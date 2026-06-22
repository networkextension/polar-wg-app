// SPDX-License-Identifier: MIT
//
// MeshClient.swift
//
// Tailscale-style join flow against a Polar wg-mac control plane:
//
//   1. user logs in (existing APIClient.login → cookie)
//   2. user enters an admin-minted token (polar_wg_…) into the join UI
//   3. app generates a Curve25519 keypair, POST /v1/register
//   4. server returns device_ip + peer list + hub info
//   5. app renders /etc/wireguard/<iface>.conf style text and persists
//      as a new ServerProfile alongside existing paste-configs
//
// Skip-login + paste-config flow is untouched — this file only adds
// the authenticated mesh-join path.

import Foundation
import CryptoKit

// MARK: - Wire types

/// Mirrors the `[Peer]` block in the rendered wg conf and matches the
/// Polar `/v1/register` response shape (doc/wg-mac-api.md §1).
struct MeshPeer: Codable {
    let pubkey: String
    let wg_ip: String?              // optional: hub entry has no /32 of its own
    let endpoint: String?
    let site_id: String?
    let hostname: String?
    let allowed_extra: [String]?
}

struct MeshHub: Codable {
    let slug: String?
    let pubkey: String
    let endpoint: String
    let wg_ip: String
}

/// Operator DNS/proxy policy pushed per-hub (wg_hubs.policy_json on the
/// control plane). v1 applies `dns`; `proxy` is decoded for v2 (iOS
/// NEProxySettings) but not yet applied. See doc/wg-dns-proxy-push-design.md.
struct MeshDNSPolicy: Codable {
    let servers: [String]?
    let match_domains: [String]?
    let search_domains: [String]?
    let mode: String?               // "plain" | "doh"
    let doh_url: String?
}

struct MeshProxyPolicy: Codable {   // v2 — decoded, not applied yet
    let http: String?
    let https: String?
    let pac_url: String?
    let match_domains: [String]?
    let bypass: [String]?
    let exclude_simple: Bool?
}

struct MeshPolicy: Codable {
    let dns: MeshDNSPolicy?
    let proxy: MeshProxyPolicy?
}

struct MeshRegisterResponse: Codable {
    let device_id: String
    let device_ip: String
    let site_id: String?
    let hub_slug: String?
    let role: String?               // "hub" | "device"
    let mesh_cidr: String?
    let hub: MeshHub?
    let peers: [MeshPeer]
    let keepalive_sec: Int?
    let refresh_sec: Int?
    let token: String?
    let token_expires: String?
    let policy: MeshPolicy?         // operator DNS/proxy push (per-hub)
}

/// What the join flow returns to the UI: a rendered conf + the metadata
/// the TunnelManager needs to store so wgctl-agent-style refresh
/// (future work) can know what token / device this profile maps to.
struct MeshJoinResult {
    let configText: String
    let deviceID: String
    let deviceIP: String
    let token: String
    let role: String
    let hubSlug: String?
    let siteID: String?
    let serverURL: String
    let pubkey: String              // for display; private key embedded in configText
}

// MARK: - Client

enum MeshClientError: Error {
    case badServerURL
    case http(Int, String)
    case decode(String)
    case keygen(String)
}

@MainActor
final class MeshClient {

    private let session = URLSession.shared
    private let serverURL: URL
    // Privileges: we use ephemeral cookies bound to this app process —
    // login flow elsewhere already populated URLSession.shared with the
    // dock session cookie. /v1/register itself is open (bearer token in
    // body), so this is forward-compatible if dock later requires the
    // user to be logged in for /v1/register too.
    init(serverURL: URL) {
        self.serverURL = serverURL
    }

    static func from(serverString raw: String) throws -> MeshClient {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let scheme = url.scheme,
              scheme == "https" || scheme == "http" else {
            throw MeshClientError.badServerURL
        }
        return MeshClient(serverURL: url)
    }

    // MARK: keypair

    /// Generate a fresh Curve25519 keypair. WireGuard uses raw 32-byte
    /// little-endian X25519, which is exactly what CryptoKit emits.
    static func newKeypair() -> (privateKeyB64: String, publicKeyB64: String) {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let pub = priv.publicKey
        let privB64 = priv.rawRepresentation.base64EncodedString()
        let pubB64 = pub.rawRepresentation.base64EncodedString()
        return (privB64, pubB64)
    }

    // MARK: register

    /// POST /v1/register. Returns the parsed response; caller renders conf.
    func register(token: String,
                  pubkey: String,
                  hostname: String,
                  wgListen: Int,
                  lanAddrs: [(iface: String, cidr: String)],
                  agentVer: String) async throws -> MeshRegisterResponse {
        var req = URLRequest(url: serverURL.appendingPathComponent("/v1/register"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let lanJSON: [[String: String]] = lanAddrs.map { ["iface": $0.iface, "cidr": $0.cidr] }
        let body: [String: Any] = [
            "token":     token,
            "pubkey":    pubkey,
            "hostname":  hostname,
            "os":        "ios",
            "arch":      "arm64",
            "agent_ver": agentVer,
            "lan_addrs": lanJSON,
            "wg_listen": wgListen,
            "site_slug": ""
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw MeshClientError.http(0, "no http response")
        }
        if !(200..<300).contains(http.statusCode) {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw MeshClientError.http(http.statusCode, body)
        }
        do {
            return try JSONDecoder().decode(MeshRegisterResponse.self, from: data)
        } catch {
            throw MeshClientError.decode(String(describing: error))
        }
    }

    // MARK: heartbeat / leave

    /// Best-effort heartbeat (admin UI "last seen"). Returns true on 200.
    func heartbeat(deviceID: String, token: String,
                   wgEndpoint: String?,
                   stats: (rx: Int, tx: Int, lastHandshakeSec: Int)?) async -> Bool {
        var req = URLRequest(url: serverURL.appendingPathComponent("/v1/heartbeat"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue(deviceID, forHTTPHeaderField: "X-Device-Id")
        var body: [String: Any] = [:]
        if let wgEndpoint { body["wg_endpoint"] = wgEndpoint }
        if let s = stats {
            body["stats"] = [
                "rx_bytes": s.rx, "tx_bytes": s.tx,
                "last_handshake_sec": s.lastHandshakeSec,
            ]
        }
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        do {
            let (_, response) = try await session.data(for: req)
            return (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
        } catch {
            return false
        }
    }

    /// Voluntary deregister. Best-effort; server may already have us gone.
    func leave(deviceID: String, token: String) async {
        var req = URLRequest(url: serverURL.appendingPathComponent("/v1/leave"))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue(deviceID, forHTTPHeaderField: "X-Device-Id")
        _ = try? await session.data(for: req)
    }
}

// MARK: - conf rendering

enum MeshConfRenderer {
    /// Render a wg-quick style conf from server response + locally-held
    /// private key. Address uses /24 (matches mesh_cidr style so kernel
    /// installs a route covering all peers); a /32 would isolate.
    static func render(response: MeshRegisterResponse,
                       privateKeyB64: String,
                       listenPort: Int) -> String {
        var lines: [String] = []
        let prefix = response.role == "hub" ? 24 : 24   // both use /24 today
        lines.append("[Interface]")
        lines.append("PrivateKey = \(privateKeyB64)")
        lines.append("Address    = \(response.device_ip)/\(prefix)")
        lines.append("ListenPort = \(listenPort)")
        lines.append("")

        let keepalive = response.keepalive_sec ?? 25
        for p in response.peers {
            guard !p.pubkey.isEmpty else { continue }
            var aips: [String] = []
            if let ip = p.wg_ip, !ip.isEmpty {
                aips.append(ip.contains("/") ? ip : "\(ip)/32")
            }
            if let extras = p.allowed_extra { aips.append(contentsOf: extras) }
            guard !aips.isEmpty else { continue }
            lines.append("[Peer]")
            lines.append("PublicKey  = \(p.pubkey)")
            if let endpoint = p.endpoint, !endpoint.isEmpty {
                lines.append("Endpoint   = \(endpoint)")
            }
            lines.append("AllowedIPs = \(aips.joined(separator: ", "))")
            if keepalive > 0 {
                lines.append("PersistentKeepalive = \(keepalive)")
            }
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - LAN address harvest

#if canImport(Darwin)
import Darwin

/// Walk getifaddrs() and emit (iface, ip/prefix) for every IPv4 address
/// that isn't loopback / link-local. Reported back to server for site
/// allocation (same-LAN devices land in the same site).
enum LANAddrs {
    static func enumerate() -> [(iface: String, cidr: String)] {
        var addrs: [(String, String)] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return [] }
        defer { freeifaddrs(ifaddr) }
        var ptr = ifaddr
        while let cur = ptr {
            defer { ptr = cur.pointee.ifa_next }
            let flags = Int32(cur.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let sa = cur.pointee.ifa_addr,
                  sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            var ipBytes = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            getnameinfo(sa, socklen_t(sa.pointee.sa_len),
                        &ipBytes, socklen_t(ipBytes.count),
                        nil, 0, NI_NUMERICHOST)
            let ip = String(cString: ipBytes)
            if ip.hasPrefix("127.") || ip.hasPrefix("169.254.") { continue }
            // netmask → CIDR prefix
            var prefix = 24
            if let nm = cur.pointee.ifa_netmask {
                nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr in
                    var bits = UInt32(0)
                    bits = ptr.pointee.sin_addr.s_addr.bigEndian
                    var count = 0
                    while bits != 0 { count += Int(bits & 1); bits >>= 1 }
                    prefix = count
                }
            }
            let iface = String(cString: cur.pointee.ifa_name)
            addrs.append((iface, "\(ip)/\(prefix)"))
        }
        return addrs
    }
}
#else
enum LANAddrs {
    static func enumerate() -> [(iface: String, cidr: String)] { [] }
}
#endif
