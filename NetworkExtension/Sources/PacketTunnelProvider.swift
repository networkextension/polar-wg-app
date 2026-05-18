// SPDX-License-Identifier: MIT
//
// PacketTunnelProvider.swift
//
// Reference NetworkExtension PacketTunnelProvider subclass that hosts
// the I/O-agnostic `wg_session` C library. Drop this file into the
// Extension target of an Xcode project, link against the WireGuardCore
// xcframework (built via scripts/build-xcframework.sh), and wire up a
// minimal host app that saves an NETunnelProviderManager pointing at
// this extension. See NE_INTEGRATION.md for the full setup walkthrough.
//
// Data flow:
//
//   NEPacketTunnelFlow.readPackets      ┐
//                                       ├── Swift ──► wg_session_handle_tun
//                                       │              ▼
//                                       │         (encap) ──► send_udp callback
//                                       │                     ▼
//                                       │              NWUDPSession.writeDatagram
//                                       │
//   NWUDPSession.setReadHandler ────────┘
//                                       ├── Swift ──► wg_session_handle_udp
//                                       │              ▼
//                                       │         (decap) ──► deliver_ip callback
//                                       │                     ▼
//                                       │              packetFlow.writePackets
//
// A DispatchSourceTimer ticks the session once per second to drive
// handshake retransmit, proactive rekey, and persistent-keepalive.

import Foundation
import NetworkExtension
import os.log
import WireGuardCore
import Darwin

private let log = OSLog(subsystem: "com.example.wireguard", category: "tunnel")

public final class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - State

    private var session: OpaquePointer?        // wg_session_t *
    private var udpSession: NWUDPSession?
    private var tickTimer: DispatchSourceTimer?
    private var peerHost: NWHostEndpoint?       // current UDP destination
    private var routeDebugInfo: String = "(route debug not initialized)"
    private var selectedEndpointDebug: String = "(none)"
    private var selectedLocalBindDebug: String = "(auto)"

    private enum RouteMode: String {
        case full
        case split

        var displayName: String {
            switch self {
            case .full: return "full"
            case .split: return "split"
            }
        }
    }

    // MARK: - Lifecycle

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // 1. Read the wg-quick config text from the provider configuration.
        //    The host app stores it as NETunnelProviderProtocol.providerConfiguration["config"].
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configText = proto.providerConfiguration?["config"] as? String else {
            completionHandler(ProviderError.missingConfig)
            return
        }
        let routeMode: RouteMode = {
            if let raw = proto.providerConfiguration?["routeMode"] as? String,
               let mode = RouteMode(rawValue: raw) {
                return mode
            }
            return .full
        }()
        let splitInjectedRoutes = proto.providerConfiguration?["splitInjectedRoutes"] as? String ?? ""
        let dnsMode: String = proto.providerConfiguration?["dnsMode"] as? String ?? "plain"

        // 2. Build the C session with callbacks pointing back at self.
        //    We pass an unretained Unmanaged<PacketTunnelProvider> as the
        //    user_ctx so the C side can call back into Swift cheaply.
        //    The wg_session_callbacks struct is imported by Swift as a
        //    POD with all four fields required at init time.
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        let callbacks = wg_session_callbacks(
            send_udp:   sendUDPCallback,
            deliver_ip: deliverIPCallback,
            log_line:   logCallback,
            user_ctx:   ctx
        )

        let configBytes = configText.utf8CString
        let handle: OpaquePointer? = configBytes.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return nil }
            return wg_session_create(base, buf.count - 1, callbacks)
        }
        guard let session = handle else {
            completionHandler(ProviderError.sessionCreateFailed)
            return
        }
        self.session = session

        // 3. Build NEPacketTunnelNetworkSettings from the session's
        //    introspection API: interface addresses, peer allowed-ips.
        let settings = buildNetworkSettings(
            for: session,
            configText: configText,
            routeMode: routeMode,
            dnsMode: dnsMode,
            splitInjectedRoutes: splitInjectedRoutes
        )

        // 4. Hand the settings to the system. Once this completes,
        //    packetFlow is ready and we can start the read loops.
        setTunnelNetworkSettings(settings) { [weak self] err in
            guard let self = self else { return }
            if let err = err {
                os_log("setTunnelNetworkSettings failed: %{public}@",
                       log: log, type: .error, String(describing: err))
                completionHandler(err)
                return
            }

            // 5. Open a UDP session to the first peer's endpoint.
            if let endpoint = self.firstPeerEndpoint(for: session)
                ?? self.firstPeerEndpointFromConfig(configText) {
                self.peerHost = endpoint
                self.selectedEndpointDebug = "\(endpoint.hostname):\(endpoint.port)"
                let localBind = self.localBindEndpointIfSameSubnet(peerEndpoint: endpoint)
                if let localBind {
                    self.selectedLocalBindDebug = "\(localBind.hostname):\(localBind.port)"
                } else {
                    self.selectedLocalBindDebug = "(none)"
                }
                self.udpSession = self.createUDPSession(to: endpoint, from: localBind)
                self.attachUDPReadHandler()
            } else {
                self.selectedEndpointDebug = "(none)"
                self.selectedLocalBindDebug = "(none)"
            }

            // 6. Start reading from the tunnel packetFlow.
            self.startPacketFlowLoop()

            // 7. Kick an immediate handshake if we have an endpoint, then
            //    arm the 1-sec tick timer.
            _ = wg_session_kick(session)
            self.startTickTimer()

            completionHandler(nil)
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        tickTimer?.cancel()
        tickTimer = nil
        udpSession?.cancel()
        udpSession = nil
        if let s = session {
            wg_session_destroy(s)
            session = nil
        }
        completionHandler()
    }

    // MARK: - Host app ↔ extension messaging (wg UAPI transport)
    //
    // The host app calls NETunnelProviderSession.sendProviderMessage(_:)
    // with a small request envelope; we route it to the right wg_session
    // UAPI call and hand back the response. This is the NE-native
    // equivalent of the unix-socket UAPI that wg(8) speaks on other
    // platforms — same text wire format, different transport.
    //
    // Request format: the first line is "get=1" or "set=1" (matching
    // the WireGuard cross-platform UAPI spec), followed by the same
    // key=value body that a unix-socket client would send. Response is
    // the canonical UAPI GET text (for get), or "errno=0\n\n" for a
    // successful set.
    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let request = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        // Dispatch on the first non-empty line.
        let firstLine = request.split(whereSeparator: { $0 == "\n" }).first ?? ""
        let response = dispatchUAPIRequest(firstLine: String(firstLine),
                                           body: request)
        completionHandler?(response.data(using: .utf8))
    }

    private func dispatchUAPIRequest(firstLine: String, body: String) -> String {
        guard let session = session else {
            return "errno=19\n\n"   // ENODEV — no active session
        }
        if firstLine == "get=1" {
            // Size first, then fill.
            let need = Int(wg_session_get_uapi(session, nil, 0))
            guard need > 0 else { return "errno=5\n\n" }  // EIO
            var buf = [CChar](repeating: 0, count: need + 1)
            buf.withUnsafeMutableBufferPointer { p in
                _ = wg_session_get_uapi(session, p.baseAddress, p.count)
            }
            let uapi = String(cString: buf)
            return uapi + routeDebugInfo + renderLiveDebug(for: session) + "\n"
        }
        if firstLine == "set=1" {
            // Forward the entire request body into the C parser. The
            // wg_session_set_uapi spec is a strict subset of upstream:
            // existing peers can have their endpoint, persistent
            // keepalive, and allowed-ips updated; private_key,
            // listen_port, replace_peers, peer add/remove are rejected.
            let bytes = Array(body.utf8)
            let rc: Int32 = bytes.withUnsafeBufferPointer { buf in
                guard let base = buf.baseAddress else { return -1 }
                return wg_session_set_uapi(session, base, buf.count)
            }
            if rc == 0 { return "errno=0\n\n" }
            return "errno=1\n\n"    // EPERM — request rejected
        }
        return "errno=22\n\n"        // EINVAL — unknown request
    }

    // MARK: - NE plumbing

    private func buildNetworkSettings(
        for session: OpaquePointer,
        configText: String,
        routeMode: RouteMode,
        dnsMode: String,
        splitInjectedRoutes: String
    ) -> NEPacketTunnelNetworkSettings {
        // Tunnel remote address — cosmetic, shown in System Settings → VPN.
        // Pull it from the first peer's endpoint via the wg_session
        // introspection API, which is now the canonical source of truth
        // (parsed from the config + resolved via getaddrinfo at create time).
        let configEndpointHost = firstEndpointHost(from: configText)
        let remote = peerEndpoint(session: session, index: 0)?.hostname
            ?? configEndpointHost
            ?? "0.0.0.0"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)

        // ── Interface addresses ──────────────────────────────────────────
        var v4Addrs: [String] = []
        var v4Masks: [String] = []
        var v6Addrs: [String] = []
        var v6Prefix: [NSNumber] = []
        var v4IfacePrefix: [Int] = []   // held so we can auto-add the
                                        // interface subnet to includedRoutes

        var addrBuf = [CChar](repeating: 0, count: 64)
        let n = wg_session_iface_addr_count(session)
        for i in 0..<n {
            var prefix: Int32 = 0
            var family: Int32 = 0
            let rc = addrBuf.withUnsafeMutableBufferPointer { ptr in
                wg_session_iface_addr_get(session, i, ptr.baseAddress, &prefix, &family)
            }
            guard rc == 0 else { continue }
            let addr = String(cString: addrBuf)
            if family == AF_INET {
                v4Addrs.append(addr)
                v4Masks.append(prefixLengthToSubnetMask(Int(prefix)))
                v4IfacePrefix.append(Int(prefix))
            } else if family == AF_INET6 {
                v6Addrs.append(addr)
                v6Prefix.append(NSNumber(value: prefix))
            }
        }

        // ── includedRoutes: from every peer's AllowedIPs ─────────────────
        // ── excludedRoutes: every peer's outer endpoint /32|/128, so the
        //    extension's own UDP to the peer does NOT loop back through
        //    utun and get dropped. This is the classic NE packet-tunnel
        //    trap: includedRoutes=0.0.0.0/0 without excluding the peer
        //    endpoint means the kernel routes the outer wireguard UDP
        //    through the same utun we're implementing, and the handshake
        //    silently never completes. tx_bytes=0 / rx_bytes=0 /
        //    last_handshake_time_sec=0 is the smoking gun.
        var included4: [NEIPv4Route] = []
        var excluded4: [NEIPv4Route] = []
        var included6: [NEIPv6Route] = []
        var excluded6: [NEIPv6Route] = []

        let peerCount = Int(wg_session_peer_count(session))
        for p in 0..<peerCount {
            let aipCount = Int(wg_session_peer_allowed_count(session, Int32(p)))
            for a in 0..<aipCount {
                var cidrBuf = [CChar](repeating: 0, count: 64)
                var prefix: Int32 = 0
                var family: Int32 = 0
                let rc = cidrBuf.withUnsafeMutableBufferPointer { ptr in
                    wg_session_peer_allowed_get(session, Int32(p), Int32(a),
                                                ptr.baseAddress, &prefix, &family)
                }
                guard rc == 0 else { continue }
                let addr = String(cString: cidrBuf)
                if family == AF_INET {
                    if prefix == 0 {
                        if routeMode == .full {
                            included4.append(NEIPv4Route.default())
                        }
                    } else {
                        included4.append(NEIPv4Route(
                            destinationAddress: addr,
                            subnetMask: prefixLengthToSubnetMask(Int(prefix))
                        ))
                    }
                } else if family == AF_INET6 {
                    if prefix == 0 {
                        if routeMode == .full {
                            included6.append(NEIPv6Route.default())
                        }
                    } else {
                        included6.append(NEIPv6Route(
                            destinationAddress: addr,
                            networkPrefixLength: NSNumber(value: prefix)
                        ))
                    }
                }
            }

            // Peer endpoint → excludedRoutes
            if routeMode == .full, let ep = peerEndpoint(session: session, index: p) {
                let host = resolvedIPAddress(for: ep.hostname) ?? ep.hostname
                if isIPv6Literal(host) {
                    excluded6.append(NEIPv6Route(
                        destinationAddress: host,
                        networkPrefixLength: 128
                    ))
                } else if isIPv4Literal(host) {
                    excluded4.append(NEIPv4Route(
                        destinationAddress: host,
                        subnetMask: "255.255.255.255"
                    ))
                }
            }
        }

        if routeMode == .split {
            let injected = parseInjectedCIDRs(splitInjectedRoutes)
            for cidr in injected {
                if cidr.family == AF_INET {
                    included4.append(NEIPv4Route(
                        destinationAddress: cidr.address,
                        subnetMask: prefixLengthToSubnetMask(cidr.prefix)
                    ))
                } else if cidr.family == AF_INET6 {
                    included6.append(NEIPv6Route(
                        destinationAddress: cidr.address,
                        networkPrefixLength: NSNumber(value: cidr.prefix)
                    ))
                }
            }
        }

        // Fallback: if endpoint introspection did not yield exclusions, parse
        // endpoint host from config text to avoid endpoint-via-utun loops.
        if routeMode == .full, excluded4.isEmpty && excluded6.isEmpty, let endpointHost = configEndpointHost {
            let host = resolvedIPAddress(for: endpointHost) ?? endpointHost
            if isIPv6Literal(host) {
                excluded6.append(NEIPv6Route(
                    destinationAddress: host,
                    networkPrefixLength: 128
                ))
            } else if isIPv4Literal(host) {
                excluded4.append(NEIPv4Route(
                    destinationAddress: host,
                    subnetMask: "255.255.255.255"
                ))
            }
        }

        // Exclude the ACTUAL local physical network subnets so LAN access
        // (printers, file shares, other devices on the same Wi-Fi/Ethernet)
        // stays reachable without going through the tunnel. We detect these
        // dynamically via getifaddrs() instead of blanket-excluding all of
        // RFC1918, because blanket exclusion would also exclude the tunnel's
        // OWN subnet (e.g. 10.88.0.0/24) which must go through utun.
        //
        // Also exclude link-local (169.254.0.0/16) since it's never tunneled.
        if routeMode == .full {
            let localNets = localPhysicalSubnets()
            for (netAddr, netMask) in localNets {
                excluded4.append(NEIPv4Route(
                    destinationAddress: netAddr,
                    subnetMask: netMask
                ))
            }
            // Link-local is always excluded.
            excluded4.append(NEIPv4Route(
                destinationAddress: "169.254.0.0",
                subnetMask: "255.255.0.0"
            ))
        }

        // Belt and braces: add the interface subnets themselves to
        // includedRoutes so `ping 10.88.0.1` when Address=10.88.0.2/24
        // definitely resolves through utun, even if a downstream
        // AllowedIPs list is narrower than the interface subnet.
        for (i, addr) in v4Addrs.enumerated() {
            let prefix = v4IfacePrefix[i]
            if let net = networkAddress(of: addr, prefixLength: prefix) {
                included4.append(NEIPv4Route(
                    destinationAddress: net,
                    subnetMask: prefixLengthToSubnetMask(prefix)
                ))
            }
        }

        included4 = dedupeIPv4Routes(included4)
        excluded4 = dedupeIPv4Routes(excluded4)
        included6 = dedupeIPv6Routes(included6)
        excluded6 = dedupeIPv6Routes(excluded6)

        if !v4Addrs.isEmpty {
            let s4 = NEIPv4Settings(addresses: v4Addrs, subnetMasks: v4Masks)
            if routeMode == .full {
                s4.includedRoutes = included4.isEmpty ? [NEIPv4Route.default()] : included4
                s4.excludedRoutes = excluded4
            } else {
                s4.includedRoutes = included4
                s4.excludedRoutes = []
            }
            settings.ipv4Settings = s4
        }
        if !v6Addrs.isEmpty {
            let s6 = NEIPv6Settings(addresses: v6Addrs, networkPrefixLengths: v6Prefix)
            if routeMode == .full {
                s6.includedRoutes = included6.isEmpty ? [NEIPv6Route.default()] : included6
                s6.excludedRoutes = excluded6
            } else {
                s6.includedRoutes = included6
                s6.excludedRoutes = []
            }
            settings.ipv6Settings = s6
        }

        // MTU matches wg_core: 1420 gives us 60 bytes of outer overhead headroom.
        settings.mtu = 1420

        // DNS mode (user choice via UI):
        //   "system" → no override, use device default
        //   "plain"  → plain DNS from the config's "DNS = ..." line
        //   "doh"    → DNS-over-HTTPS via Cloudflare (1.1.1.1)
        switch dnsMode {
        case "system":
            break  // no DNSSettings → system default
        case "doh":
            let doh = NEDNSOverHTTPSSettings(servers: ["1.1.1.1", "1.0.0.1"])
            doh.serverURL = URL(string: "https://cloudflare-dns.com/dns-query")
            settings.dnsSettings = doh
        default: // "plain"
            let dnsServers = parseDNSFromConfig(configText)
            if !dnsServers.isEmpty {
                settings.dnsSettings = NEDNSSettings(servers: dnsServers)
            }
        }
        routeDebugInfo = renderRouteDebug(
            mode: routeMode,
            tunnelRemote: remote,
            included4: included4,
            excluded4: excluded4,
            included6: included6,
            excluded6: excluded6,
            splitInjectedRoutes: splitInjectedRoutes
        )
        return settings
    }

    /// Read peer `i`'s current endpoint out of the wg_session and return
    /// it as an NWHostEndpoint. Returns nil if the peer is responder-only
    /// (has not roamed yet) or `i` is out of range.
    private func peerEndpoint(session: OpaquePointer, index: Int) -> NWHostEndpoint? {
        var addrBuf = [CChar](repeating: 0, count: 80)
        var port: UInt16 = 0
        let rc = addrBuf.withUnsafeMutableBufferPointer { ptr in
            wg_session_peer_endpoint(session, Int32(index), ptr.baseAddress, &port)
        }
        guard rc == 0 else { return nil }
        let host = String(cString: addrBuf)
        return NWHostEndpoint(hostname: host, port: String(port))
    }

    private func firstPeerEndpoint(for session: OpaquePointer) -> NWHostEndpoint? {
        peerEndpoint(session: session, index: 0)
    }

    private func firstPeerEndpointFromConfig(_ configText: String) -> NWHostEndpoint? {
        for line in configText.split(whereSeparator: \.isNewline) {
            let raw = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !raw.isEmpty, !raw.hasPrefix("#"), !raw.hasPrefix(";") else { continue }
            let lower = raw.lowercased()
            guard lower.hasPrefix("endpoint") else { continue }
            guard let eq = raw.firstIndex(of: "=") else { continue }
            let rhs = raw[raw.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            guard let parsed = parseEndpoint(rhs) else { continue }
            return NWHostEndpoint(hostname: parsed.host, port: parsed.port)
        }
        return nil
    }

    private func attachUDPReadHandler() {
        udpSession?.setReadHandler({ [weak self] datagrams, error in
            guard let self = self, let datagrams = datagrams else { return }
            guard let session = self.session else { return }
            for d in datagrams {
                d.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else { return }
                    if var peerAddr = self.makeSockaddrFromCurrentEndpoint() {
                        _ = withUnsafeMutablePointer(to: &peerAddr.storage) { storagePtr in
                            storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                                wg_session_handle_udp(
                                    session,
                                    base.assumingMemoryBound(to: UInt8.self),
                                    d.count,
                                    saPtr,
                                    peerAddr.length
                                )
                            }
                        }
                    } else {
                        // Last-resort fallback when current endpoint cannot be
                        // represented (should be rare).
                        var addr = sockaddr_in()
                        addr.sin_family = sa_family_t(AF_INET)
                        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                        _ = wg_session_handle_udp(
                            session,
                            base.assumingMemoryBound(to: UInt8.self),
                            d.count,
                            withUnsafePointer(to: &addr) {
                                UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self)
                            },
                            socklen_t(MemoryLayout<sockaddr_in>.size)
                        )
                    }
                }
            }
        }, maxDatagrams: 64)
    }

    private func startPacketFlowLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, let session = self.session else { return }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else { return }
                    _ = wg_session_handle_tun(
                        session,
                        base.assumingMemoryBound(to: UInt8.self),
                        packet.count
                    )
                }
            }
            self.startPacketFlowLoop()
        }
    }

    private func startTickTimer() {
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        t.schedule(deadline: .now() + 1, repeating: 1.0)
        t.setEventHandler { [weak self] in
            guard let self = self, let session = self.session else { return }
            wg_session_tick(session)
        }
        t.resume()
        tickTimer = t
    }

    // MARK: - C callback shims
    //
    // These are free functions (can't be Swift methods because C can't
    // take @convention(c) closures that capture state). They recover
    // `self` from the user_ctx pointer the session was created with.

    fileprivate func writeDatagram(_ bytes: UnsafePointer<UInt8>, length: Int) {
        guard let udpSession = udpSession else {
            os_log("udp write dropped: udpSession is nil", log: log, type: .error)
            return
        }
        let data = Data(bytes: bytes, count: length)
        udpSession.writeDatagram(data) { err in
            if let err = err {
                os_log("udp write error: %{public}@", log: log, type: .error,
                       String(describing: err))
            }
        }
    }

    fileprivate func writeInnerPacket(_ bytes: UnsafePointer<UInt8>, length: Int) {
        let data = Data(bytes: bytes, count: length)
        let version = (data.first ?? 0) >> 4
        let family = NSNumber(value: version == 6 ? AF_INET6 : AF_INET)
        packetFlow.writePackets([data], withProtocols: [family])
    }

    fileprivate func emitLog(_ msg: String) {
        os_log("%{public}@", log: log, type: .info, msg)
    }

    private func makeSockaddrFromCurrentEndpoint() -> (storage: sockaddr_storage, length: socklen_t)? {
        guard let endpoint = peerHost else { return nil }
        guard let port = UInt16(endpoint.port) else { return nil }

        let host = resolvedIPAddress(for: endpoint.hostname) ?? endpoint.hostname
        if isIPv4Literal(host) {
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            sin.sin_port = port.bigEndian
            guard host.withCString({ inet_pton(AF_INET, $0, &sin.sin_addr) }) == 1 else {
                return nil
            }
            var storage = sockaddr_storage()
            withUnsafeMutablePointer(to: &storage) { dst in
                dst.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee = sin }
            }
            return (storage, socklen_t(MemoryLayout<sockaddr_in>.size))
        }

        if isIPv6Literal(host) {
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            sin6.sin6_port = port.bigEndian
            guard host.withCString({ inet_pton(AF_INET6, $0, &sin6.sin6_addr) }) == 1 else {
                return nil
            }
            var storage = sockaddr_storage()
            withUnsafeMutablePointer(to: &storage) { dst in
                dst.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee = sin6 }
            }
            return (storage, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }

        return nil
    }

    private func isIPv4Literal(_ host: String) -> Bool {
        var addr = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &addr) == 1 }
    }

    private func isIPv6Literal(_ host: String) -> Bool {
        var addr = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }

    private func resolvedIPAddress(for host: String) -> String? {
        let normalized = normalizeEndpointHost(host)
        if isIPv4Literal(normalized) || isIPv6Literal(normalized) {
            return normalized
        }
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: IPPROTO_UDP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(normalized, nil, &hints, &result)
        guard rc == 0, let first = result else { return nil }
        defer { freeaddrinfo(first) }

        var nameBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let ni = getnameinfo(
            first.pointee.ai_addr,
            first.pointee.ai_addrlen,
            &nameBuf,
            socklen_t(nameBuf.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard ni == 0 else { return nil }
        return String(cString: nameBuf)
    }

    private func firstEndpointHost(from configText: String) -> String? {
        for line in configText.split(whereSeparator: \.isNewline) {
            let raw = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !raw.isEmpty, !raw.hasPrefix("#"), !raw.hasPrefix(";") else { continue }
            let lower = raw.lowercased()
            guard lower.hasPrefix("endpoint") else { continue }
            guard let eq = raw.firstIndex(of: "=") else { continue }
            let rhs = raw[raw.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            let host = normalizeEndpointHost(rhs)
            if !host.isEmpty { return host }
        }
        return nil
    }

    private func normalizeEndpointHost(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("["),
           let close = trimmed.firstIndex(of: "]") {
            return String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
        }
        // IPv4 / hostname with :port.
        if let colon = trimmed.lastIndex(of: ":"), !trimmed.contains("]"), !trimmed[..<colon].contains(":") {
            return String(trimmed[..<colon])
        }
        return trimmed
    }

    private func parseEndpoint(_ value: String) -> (host: String, port: String)? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if trimmed.hasPrefix("["),
           let close = trimmed.firstIndex(of: "]"),
           close < trimmed.endIndex {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let rest = trimmed[trimmed.index(after: close)...]
            if rest.hasPrefix(":") {
                let port = String(rest.dropFirst())
                if !host.isEmpty, !port.isEmpty { return (host, port) }
            }
            return nil
        }

        if let colon = trimmed.lastIndex(of: ":"),
           !trimmed[..<colon].contains(":"),
           colon < trimmed.endIndex {
            let host = String(trimmed[..<colon])
            let port = String(trimmed[trimmed.index(after: colon)...])
            if !host.isEmpty, !port.isEmpty { return (host, port) }
        }
        return nil
    }

    /// Parse "DNS = 1.1.1.1, 1.0.0.1" from a wg-quick config text.
    /// Returns an array of IP strings, empty if no DNS line found.
    private func parseDNSFromConfig(_ config: String) -> [String] {
        var inInterface = false
        for line in config.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("[interface]") {
                inInterface = true; continue
            }
            if trimmed.hasPrefix("[") {
                inInterface = false; continue
            }
            if inInterface, trimmed.lowercased().hasPrefix("dns") {
                let parts = trimmed.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { continue }
                return parts[1]
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
        }
        return []
    }

    /// Enumerate all physical (non-loopback, non-utun) IPv4 interfaces
    /// and return their network address + subnet mask. Used to build
    /// excludedRoutes so the local LAN stays reachable in full-tunnel mode
    /// WITHOUT blanket-excluding all of RFC1918 (which would break the
    /// tunnel's own subnet if it's in a private range like 10.88.0.0/24).
    private func localPhysicalSubnets() -> [(address: String, mask: String)] {
        var result: [(String, String)] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return result }
        defer { freeifaddrs(first) }

        var seen = Set<String>()  // dedup by "net/mask"
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let ifa = current.pointee
            let name = String(cString: ifa.ifa_name)
            cursor = ifa.ifa_next

            // Skip loopback, utun (our tunnel), and awdl/llw (Apple Wireless)
            if name == "lo0" || name.hasPrefix("utun") ||
               name.hasPrefix("awdl") || name.hasPrefix("llw") { continue }
            guard let addrPtr = ifa.ifa_addr, let maskPtr = ifa.ifa_netmask else { continue }
            guard Int32(addrPtr.pointee.sa_family) == AF_INET,
                  Int32(maskPtr.pointee.sa_family) == AF_INET else { continue }

            let sin = withUnsafePointer(to: addrPtr.pointee) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }
            let msk = withUnsafePointer(to: maskPtr.pointee) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }

            let localIP = UInt32(bigEndian: sin.sin_addr.s_addr)
            let mask    = UInt32(bigEndian: msk.sin_addr.s_addr)
            guard mask != 0 else { continue }

            let net = localIP & mask

            // Convert back to dotted strings.
            var netAddr = in_addr(s_addr: UInt32(bigEndian: net))
            var maskAddr = in_addr(s_addr: msk.sin_addr.s_addr)
            var netBuf  = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var maskBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &netAddr, &netBuf, socklen_t(INET_ADDRSTRLEN)) != nil,
                  inet_ntop(AF_INET, &maskAddr, &maskBuf, socklen_t(INET_ADDRSTRLEN)) != nil
            else { continue }

            let netStr  = String(cString: netBuf)
            let maskStr = String(cString: maskBuf)
            let key = "\(netStr)/\(maskStr)"
            if seen.contains(key) { continue }
            seen.insert(key)

            result.append((netStr, maskStr))
        }
        return result
    }

    private func localBindEndpointIfSameSubnet(peerEndpoint: NWHostEndpoint) -> NWHostEndpoint? {
        guard let peerIP = resolvedIPAddress(for: peerEndpoint.hostname),
              isIPv4Literal(peerIP) else {
            return nil
        }
        guard let chosen = firstLocalIPv4InSameSubnet(as: peerIP) else {
            return nil
        }
        return NWHostEndpoint(hostname: chosen, port: "0")
    }

    private func firstLocalIPv4InSameSubnet(as peerIP: String) -> String? {
        var peerAddr = in_addr()
        guard peerIP.withCString({ inet_pton(AF_INET, $0, &peerAddr) }) == 1 else {
            return nil
        }
        let peer = UInt32(bigEndian: peerAddr.s_addr)

        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let ifa = current.pointee
            let name = String(cString: ifa.ifa_name)
            cursor = ifa.ifa_next

            // Avoid loopback and utun addresses.
            if name == "lo0" || name.hasPrefix("utun") { continue }
            guard let addrPtr = ifa.ifa_addr, let maskPtr = ifa.ifa_netmask else { continue }
            guard Int32(addrPtr.pointee.sa_family) == AF_INET,
                  Int32(maskPtr.pointee.sa_family) == AF_INET else { continue }

            let sin = withUnsafePointer(to: addrPtr.pointee) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }
            let msk = withUnsafePointer(to: maskPtr.pointee) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }

            let local = UInt32(bigEndian: sin.sin_addr.s_addr)
            let mask = UInt32(bigEndian: msk.sin_addr.s_addr)
            guard mask != 0 else { continue }

            if (local & mask) == (peer & mask) {
                var ip = sin.sin_addr
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &ip, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buf)
                }
            }
        }
        return nil
    }

    private func renderRouteDebug(
        mode: RouteMode,
        tunnelRemote: String,
        included4: [NEIPv4Route],
        excluded4: [NEIPv4Route],
        included6: [NEIPv6Route],
        excluded6: [NEIPv6Route],
        splitInjectedRoutes: String
    ) -> String {
        let inc4 = included4.map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" }.prefix(12)
        let exc4 = excluded4.map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" }.prefix(12)
        let inc6 = included6.map { "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)" }.prefix(12)
        let exc6 = excluded6.map { "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)" }.prefix(12)
        let injected = parseInjectedCIDRs(splitInjectedRoutes).map { "\($0.address)/\($0.prefix)" }

        return """

        route_mode=\(mode.displayName)
        tunnel_remote=\(tunnelRemote)
        included_v4_count=\(included4.count)
        excluded_v4_count=\(excluded4.count)
        included_v6_count=\(included6.count)
        excluded_v6_count=\(excluded6.count)
        included_v4=\(inc4.joined(separator: ","))
        excluded_v4=\(exc4.joined(separator: ","))
        included_v6=\(inc6.joined(separator: ","))
        excluded_v6=\(exc6.joined(separator: ","))
        injected_route_count=\(injected.count)
        injected_routes=\(injected.joined(separator: ","))
        """
    }

    private func renderLiveDebug(for session: OpaquePointer) -> String {
        let livePeer = peerHost?.hostname ?? "(none)"
        let liveSessionEndpoint: String = {
            if let ep = firstPeerEndpoint(for: session) {
                return "\(ep.hostname):\(ep.port)"
            }
            return "(none)"
        }()
        let hasUdp = udpSession == nil ? "nil" : "active"

        return """

        live_peer_host=\(livePeer)
        live_session_endpoint=\(liveSessionEndpoint)
        selected_endpoint=\(selectedEndpointDebug)
        selected_local_bind=\(selectedLocalBindDebug)
        udp_session=\(hasUdp)
        """
    }

    // MARK: - Errors

    enum ProviderError: LocalizedError {
        case missingConfig
        case sessionCreateFailed
        var errorDescription: String? {
            switch self {
            case .missingConfig:      return "provider configuration missing 'config' key"
            case .sessionCreateFailed: return "wg_session_create returned NULL"
            }
        }
    }
}

// MARK: - C callback trampolines

private func sendUDPCallback(
    _ ctx: UnsafeMutableRawPointer?,
    _ bytes: UnsafePointer<UInt8>?,
    _ len: Int,
    _ to: UnsafePointer<sockaddr>?,
    _ toLen: socklen_t
) {
    guard let ctx = ctx, let bytes = bytes else { return }
    let provider = Unmanaged<PacketTunnelProvider>
        .fromOpaque(ctx).takeUnretainedValue()
    provider.writeDatagram(bytes, length: len)
}

private func deliverIPCallback(
    _ ctx: UnsafeMutableRawPointer?,
    _ bytes: UnsafePointer<UInt8>?,
    _ len: Int
) {
    guard let ctx = ctx, let bytes = bytes else { return }
    let provider = Unmanaged<PacketTunnelProvider>
        .fromOpaque(ctx).takeUnretainedValue()
    provider.writeInnerPacket(bytes, length: len)
}

private func logCallback(
    _ ctx: UnsafeMutableRawPointer?,
    _ msg: UnsafePointer<CChar>?
) {
    guard let ctx = ctx, let msg = msg else { return }
    let provider = Unmanaged<PacketTunnelProvider>
        .fromOpaque(ctx).takeUnretainedValue()
    provider.emitLog(String(cString: msg))
}

// MARK: - Helpers

private func prefixLengthToSubnetMask(_ prefix: Int) -> String {
    let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
    return String(
        format: "%u.%u.%u.%u",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >>  8) & 0xff,
         mask        & 0xff
    )
}

private func networkAddress(of address: String, prefixLength: Int) -> String? {
    guard (0...32).contains(prefixLength) else { return nil }
    var rawAddr = in_addr()
    let parsed = address.withCString { inet_pton(AF_INET, $0, &rawAddr) }
    guard parsed == 1 else { return nil }

    let hostOrder = UInt32(bigEndian: rawAddr.s_addr)
    let mask: UInt32 = prefixLength == 0 ? 0 : (UInt32.max << (32 - prefixLength))
    let netOrder = (hostOrder & mask).bigEndian

    var netAddr = in_addr(s_addr: netOrder)
    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &netAddr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
    return String(cString: buf)
}

private func parseInjectedCIDRs(_ text: String) -> [(family: Int32, address: String, prefix: Int)] {
    text
        .split { $0 == "\n" || $0 == "," || $0 == ";" || $0 == " " || $0 == "\t" }
        .compactMap { token -> (Int32, String, Int)? in
            let part = token.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !part.isEmpty else { return nil }
            guard let slash = part.lastIndex(of: "/") else { return nil }
            let addr = String(part[..<slash])
            let prefixText = String(part[part.index(after: slash)...])
            guard let prefix = Int(prefixText) else { return nil }

            var v4 = in_addr()
            if addr.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1, (0...32).contains(prefix) {
                return (AF_INET, addr, prefix)
            }

            var v6 = in6_addr()
            if addr.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1, (0...128).contains(prefix) {
                return (AF_INET6, addr, prefix)
            }
            return nil
        }
}

private func dedupeIPv4Routes(_ routes: [NEIPv4Route]) -> [NEIPv4Route] {
    var seen = Set<String>()
    var result: [NEIPv4Route] = []
    for route in routes {
        let key = "\(route.destinationAddress)/\(route.destinationSubnetMask)"
        if seen.insert(key).inserted {
            result.append(route)
        }
    }
    return result
}

private func dedupeIPv6Routes(_ routes: [NEIPv6Route]) -> [NEIPv6Route] {
    var seen = Set<String>()
    var result: [NEIPv6Route] = []
    for route in routes {
        let key = "\(route.destinationAddress)/\(route.destinationNetworkPrefixLength)"
        if seen.insert(key).inserted {
            result.append(route)
        }
    }
    return result
}
