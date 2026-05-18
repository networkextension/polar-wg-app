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

private let log = OSLog(subsystem: "com.example.wireguard", category: "tunnel")

public final class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - State

    private var session: OpaquePointer?        // wg_session_t *
    private var udpSession: NWUDPSession?
    private var tickTimer: DispatchSourceTimer?
    private var peerHost: NWHostEndpoint?       // current UDP destination

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

        // 2. Build the C session with callbacks pointing back at self.
        //    We pass an unretained Unmanaged<PacketTunnelProvider> as the
        //    user_ctx so the C side can call back into Swift cheaply.
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        var callbacks = wg_session_callbacks()
        callbacks.user_ctx = ctx
        callbacks.send_udp = sendUDPCallback
        callbacks.deliver_ip = deliverIPCallback
        callbacks.log_line = logCallback

        let configBytes = configText.utf8CString
        let handle = configBytes.withUnsafeBufferPointer { buf -> OpaquePointer? in
            guard let base = buf.baseAddress else { return nil }
            return wg_session_create(base, buf.count - 1, callbacks)
                .map { OpaquePointer($0) }
        }
        guard let session = handle else {
            completionHandler(ProviderError.sessionCreateFailed)
            return
        }
        self.session = session

        // 3. Build NEPacketTunnelNetworkSettings from the session's
        //    introspection API: interface addresses, peer allowed-ips.
        let settings = buildNetworkSettings(for: session)

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
            if let endpoint = self.firstPeerEndpoint(for: session) {
                self.peerHost = endpoint
                self.udpSession = self.createUDPSession(to: endpoint, from: nil)
                self.attachUDPReadHandler()
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
            return String(cString: buf)
        }
        if firstLine == "set=1" {
            // SET side not implemented yet — return EPERM so the caller
            // can tell it's a "capability missing" vs. a "request bad".
            // Full implementation requires runtime mutation hooks in
            // wg_session which is the next PR.
            return "errno=1\n\n"    // EPERM
        }
        return "errno=22\n\n"        // EINVAL — unknown request
    }

    // MARK: - NE plumbing

    private func buildNetworkSettings(for session: OpaquePointer) -> NEPacketTunnelNetworkSettings {
        // Tunnel remote address is cosmetic for wg; use the first peer endpoint
        // if available, otherwise "0.0.0.0".
        let remote = firstPeerEndpoint(for: session)?.hostname ?? "0.0.0.0"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)

        // Interface addresses.
        var v4Addrs: [String] = []
        var v4Masks: [String] = []
        var v6Addrs: [String] = []
        var v6Prefix: [NSNumber] = []

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
            } else if family == AF_INET6 {
                v6Addrs.append(addr)
                v6Prefix.append(NSNumber(value: prefix))
            }
        }
        if !v4Addrs.isEmpty {
            settings.ipv4Settings = NEIPv4Settings(addresses: v4Addrs, subnetMasks: v4Masks)
            settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        }
        if !v6Addrs.isEmpty {
            settings.ipv6Settings = NEIPv6Settings(addresses: v6Addrs, networkPrefixLengths: v6Prefix)
            settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        }

        // MTU matches wg_core: 1420 gives us 60 bytes of outer overhead headroom.
        settings.mtu = 1420
        return settings
    }

    private func firstPeerEndpoint(for session: OpaquePointer) -> NWHostEndpoint? {
        // wg_session does not currently expose the endpoint host/port back
        // to Swift (it only carries resolved sockaddr inside). For the
        // MVP, the caller passes the endpoint via providerConfiguration
        // separately. This helper exists as a hook for when we add a
        // peer-endpoint getter to the C API.
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let ep = proto.providerConfiguration?["endpoint"] as? String else {
            return nil
        }
        let parts = ep.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return nil }
        return NWHostEndpoint(hostname: parts[0], port: parts[1])
    }

    private func attachUDPReadHandler() {
        udpSession?.setReadHandler({ [weak self] datagrams, error in
            guard let self = self, let datagrams = datagrams else { return }
            guard let session = self.session else { return }
            for d in datagrams {
                d.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else { return }
                    // We don't have a sockaddr from NWUDPSession; synthesize
                    // one from the current endpoint so wgs_handle_udp has
                    // something for roaming bookkeeping.
                    var addr = self.makeSockaddrFromCurrentEndpoint()
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

    private func writeDatagram(_ bytes: UnsafePointer<UInt8>, length: Int) {
        let data = Data(bytes: bytes, count: length)
        udpSession?.writeDatagram(data) { err in
            if let err = err {
                os_log("udp write error: %{public}@", log: log, type: .error,
                       String(describing: err))
            }
        }
    }

    private func writeInnerPacket(_ bytes: UnsafePointer<UInt8>, length: Int) {
        let data = Data(bytes: bytes, count: length)
        let version = (data.first ?? 0) >> 4
        let family = NSNumber(value: version == 6 ? AF_INET6 : AF_INET)
        packetFlow.writePackets([data], withProtocols: [family])
    }

    private func emitLog(_ msg: String) {
        os_log("%{public}@", log: log, type: .info, msg)
    }

    private func makeSockaddrFromCurrentEndpoint() -> sockaddr_in {
        // Placeholder: fill in from the NWUDPSession's currentPath.remoteEndpoint
        // when available. For the MVP this is a zeroed struct — the C library
        // uses it only for roaming bookkeeping, so a bogus value just means
        // the peer endpoint won't update from recvfrom.
        var sin = sockaddr_in()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        return sin
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
