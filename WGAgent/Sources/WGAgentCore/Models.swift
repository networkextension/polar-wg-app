import Foundation

// Wire + on-disk models. Decoding is deliberately lenient where the fleet is
// already inconsistent (see DeviceState.listen) and strict nowhere it matters.

public enum Role: String, Sendable, Codable {
    case device
    case hub
}

/// `/etc/wgctl/<iface>.json` — one file per mesh membership.
public struct DeviceState: Sendable, Equatable {
    public var server: String
    public var deviceID: String
    public var token: String
    public var role: Role
    public var wgListen: Int
    /// Interface name. Authoritative source is the *filename*, not this field;
    /// `load(from:)` fills it in from the path.
    public var iface: String

    public init(server: String, deviceID: String, token: String,
                role: Role = .device, wgListen: Int = 1632, iface: String) {
        self.server = server
        self.deviceID = deviceID
        self.token = token
        self.role = role
        self.wgListen = wgListen
        self.iface = iface
    }
}

extension DeviceState: Decodable {
    private enum Key: String, CodingKey {
        case server, device_id, token, role, wg_listen, listen, iface
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        // Trailing slash must go or every URL we build gets a double slash.
        server = (try c.decodeIfPresent(String.self, forKey: .server) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "/+$", with: "", options: .regularExpression)
        deviceID = try c.decodeIfPresent(String.self, forKey: .device_id) ?? ""
        token = try c.decodeIfPresent(String.self, forKey: .token) ?? ""
        role = (try? c.decodeIfPresent(Role.self, forKey: .role)) .flatMap { $0 } ?? .device
        // join-linux.sh writes "listen"; every other joiner writes "wg_listen".
        // Reading only one pinned half the fleet to the default port.
        wgListen = try c.decodeIfPresent(Int.self, forKey: .wg_listen)
            ?? c.decodeIfPresent(Int.self, forKey: .listen)
            ?? 1632
        iface = try c.decodeIfPresent(String.self, forKey: .iface) ?? ""
    }
}

extension DeviceState {
    /// True when the agent has enough to talk to the control plane at all.
    public var isUsable: Bool {
        !server.isEmpty && !deviceID.isEmpty && !token.isEmpty
    }
}

// MARK: - /v1/peers and /v1/hub/peers

public struct PeerEntry: Sendable, Decodable, Equatable {
    public var pubkey: String
    public var wgIP: String?
    public var endpoint: String?
    public var allowedExtra: [String]

    private enum Key: String, CodingKey {
        case pubkey, wg_ip, endpoint, allowed_extra
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        pubkey = try c.decodeIfPresent(String.self, forKey: .pubkey) ?? ""
        wgIP = try c.decodeIfPresent(String.self, forKey: .wg_ip)
        endpoint = try c.decodeIfPresent(String.self, forKey: .endpoint)
        allowedExtra = try c.decodeIfPresent([String].self, forKey: .allowed_extra) ?? []
    }

    public init(pubkey: String, wgIP: String? = nil, endpoint: String? = nil,
                allowedExtra: [String] = []) {
        self.pubkey = pubkey
        self.wgIP = wgIP
        self.endpoint = endpoint
        self.allowedExtra = allowedExtra
    }

    /// AllowedIPs for this peer. `/v1/peers` returns a bare address while
    /// `/v1/hub/peers` already returns a CIDR, so only add /32 when absent.
    public var allowedIPs: [String] {
        var out: [String] = []
        if let ip = wgIP, !ip.isEmpty {
            out.append(ip.contains("/") ? ip : ip + "/32")
        }
        out.append(contentsOf: allowedExtra)
        return out
    }
}

public struct PeersResponse: Sendable, Decodable {
    public var notModified: Bool
    public var rev: String?
    public var peers: [PeerEntry]
    public var keepaliveSec: Int?
    public var deviceIP: String?
    public var advertisedRoutes: [String]

    private enum Key: String, CodingKey {
        case not_modified, rev, peers, keepalive_sec, device_ip, advertised_routes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        notModified = try c.decodeIfPresent(Bool.self, forKey: .not_modified) ?? false
        rev = try c.decodeIfPresent(String.self, forKey: .rev)
        peers = try c.decodeIfPresent([PeerEntry].self, forKey: .peers) ?? []
        keepaliveSec = try c.decodeIfPresent(Int.self, forKey: .keepalive_sec)
        deviceIP = try c.decodeIfPresent(String.self, forKey: .device_ip)
        advertisedRoutes = try c.decodeIfPresent([String].self, forKey: .advertised_routes) ?? []
    }
}

// MARK: - POST /v1/heartbeat

public struct LanAddr: Sendable, Codable, Equatable {
    public var iface: String
    public var cidr: String

    public init(iface: String, cidr: String) {
        self.iface = iface
        self.cidr = cidr
    }
}

/// Aggregate transfer stats across all peers of one interface.
public struct WGStats: Sendable, Codable, Equatable {
    public var rxBytes: Int
    public var txBytes: Int
    /// *Minimum* handshake age across peers — i.e. the freshest one.
    public var lastHandshakeSec: Int

    private enum Key: String, CodingKey {
        case rx_bytes, tx_bytes, last_handshake_sec
    }

    public init(rxBytes: Int, txBytes: Int, lastHandshakeSec: Int) {
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.lastHandshakeSec = lastHandshakeSec
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        rxBytes = try c.decodeIfPresent(Int.self, forKey: .rx_bytes) ?? 0
        txBytes = try c.decodeIfPresent(Int.self, forKey: .tx_bytes) ?? 0
        lastHandshakeSec = try c.decodeIfPresent(Int.self, forKey: .last_handshake_sec) ?? 0
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(rxBytes, forKey: .rx_bytes)
        try c.encode(txBytes, forKey: .tx_bytes)
        try c.encode(lastHandshakeSec, forKey: .last_handshake_sec)
    }
}

/// The heartbeat body.
///
/// Only these three fields exist because they are the only three the control
/// plane actually decodes — `wgHeartbeatRequest` in polar-wg has no `status`
/// member, so the whole v2 status block (peers[], peer_count, os, arch,
/// agent_ver, uptime_sec) was being computed, serialized and then dropped on
/// the floor by every agent in the fleet. The admin peer roster comes from a
/// separate hub-local `wg_peer_status` sampler instead. See §6.4 of
/// doc/wg-agent-swift-design.md.
public struct HeartbeatBody: Sendable, Codable, Equatable {
    public var lanAddrs: [LanAddr]
    /// Public egress IP + listen port, or "" when unknown. Empty is meaningful:
    /// the server keeps the previous value rather than overwriting it.
    public var wgEndpoint: String
    public var stats: WGStats

    private enum Key: String, CodingKey {
        case lan_addrs, wg_endpoint, stats
    }

    public init(lanAddrs: [LanAddr], wgEndpoint: String, stats: WGStats) {
        self.lanAddrs = lanAddrs
        self.wgEndpoint = wgEndpoint
        self.stats = stats
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        lanAddrs = try c.decodeIfPresent([LanAddr].self, forKey: .lan_addrs) ?? []
        wgEndpoint = try c.decodeIfPresent(String.self, forKey: .wg_endpoint) ?? ""
        stats = try c.decode(WGStats.self, forKey: .stats)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(lanAddrs, forKey: .lan_addrs)
        try c.encode(wgEndpoint, forKey: .wg_endpoint)
        try c.encode(stats, forKey: .stats)
    }
}

/// One peer as read back from the local WireGuard implementation.
public struct PeerStatus: Sendable, Equatable {
    public var pubkey: String
    public var endpoint: String?
    public var allowedIPs: [String]
    /// nil = never handshook.
    public var lastHandshakeSec: Int?
    public var rxBytes: Int
    public var txBytes: Int

    public init(pubkey: String, endpoint: String? = nil, allowedIPs: [String] = [],
                lastHandshakeSec: Int? = nil, rxBytes: Int = 0, txBytes: Int = 0) {
        self.pubkey = pubkey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.lastHandshakeSec = lastHandshakeSec
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }

    /// 180 s ≈ 7× the 25 s PersistentKeepalive.
    public static let onlineWindowSec = 180

    public var isOnline: Bool {
        guard let age = lastHandshakeSec else { return false }
        return age < Self.onlineWindowSec
    }
}

extension Array where Element == PeerStatus {
    /// Aggregate for the heartbeat: summed traffic, freshest handshake.
    public func aggregate() -> WGStats {
        let ages = compactMap(\.lastHandshakeSec)
        return WGStats(
            rxBytes: reduce(0) { $0 + $1.rxBytes },
            txBytes: reduce(0) { $0 + $1.txBytes },
            lastHandshakeSec: ages.min() ?? 0
        )
    }
}
