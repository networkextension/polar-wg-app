import Foundation

/// One interface's live state as read back from the local WireGuard.
public struct WGDumpResult: Sendable, Equatable {
    /// Kernel device, e.g. "utun0". nil when not running.
    public var interfaceName: String?
    /// Config name, e.g. "wgc0". This is the one to key on.
    public var logicalName: String?
    public var isRunning: Bool
    public var peers: [PeerStatus]

    public init(interfaceName: String? = nil, logicalName: String? = nil,
                isRunning: Bool = true, peers: [PeerStatus] = []) {
        self.interfaceName = interfaceName
        self.logicalName = logicalName
        self.isRunning = isRunning
        self.peers = peers
    }
}

/// Parsers for the two status formats we have to read.
///
/// Deliberately hand-rolled rather than regex-based: this has to compile
/// against the musl static SDK where the less-travelled Foundation paths are
/// the ones that break, and the grammars are small enough that scanning is
/// clearer than a pattern anyway.
public enum WGDump {

    // MARK: - wg_core's text dump (macOS / iOS)

    /// Parse the snapshot served by `wg_core` on
    /// `/var/run/wireguard/<iface>.sock` (and printed by `wgctl show`).
    ///
    /// Format notes that cost us a production bug: wg_core prints
    /// `peer #0: <key>`, NOT upstream wg's `peer: <key>`. The shell agent
    /// matched only the latter, so it never entered a peer block and every
    /// macOS host reported zero traffic and a zero handshake age forever.
    /// Both spellings are accepted here.
    public static func parseCoreText(_ text: String) -> WGDumpResult {
        var result = WGDumpResult()
        var current: PeerStatus?

        func flush() {
            if let p = current, !p.pubkey.isEmpty { result.peers.append(p) }
            current = nil
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }

            if line.hasPrefix("interface:") {
                flush()
                let rest = value(after: "interface:", in: line)
                // `wgctl show` synthesizes these two instead of dumping; they
                // never come off the socket.
                if rest.contains("(not running)") || rest.contains("(stale pid file") {
                    result.isRunning = false
                    result.interfaceName = firstToken(rest)
                } else {
                    result.interfaceName = rest.isEmpty ? nil : rest
                }
                continue
            }
            if line.hasPrefix("logical:") {
                result.logicalName = value(after: "logical:", in: line)
                continue
            }
            // Must be tested before "peer" prefixes so the count line isn't
            // mistaken for a peer header.
            if line.hasPrefix("peers:") { continue }

            if line.hasPrefix("peer #") || line.hasPrefix("peer:") {
                flush()
                guard let colon = line.firstIndex(of: ":") else { continue }
                let key = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                current = PeerStatus(pubkey: key)
                continue
            }

            guard current != nil else { continue }

            if line.hasPrefix("endpoint:") {
                let v = value(after: "endpoint:", in: line)
                current?.endpoint = (v == "(none)" || v.isEmpty) ? nil : v
            } else if line.hasPrefix("allowed ips:") {
                let v = value(after: "allowed ips:", in: line)
                current?.allowedIPs = (v == "(none)") ? [] :
                    v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                     .filter { !$0.isEmpty }
            } else if line.hasPrefix("latest handshake:") {
                current?.lastHandshakeSec = parseAge(value(after: "latest handshake:", in: line))
            } else if line.hasPrefix("transfer:") {
                let (rx, tx) = parseTransfer(value(after: "transfer:", in: line))
                current?.rxBytes = rx
                current?.txBytes = tx
            }
            // `packets:`, `persistent keepalive:` and `handshake state:` carry
            // nothing the control plane consumes. Note keepalive is emitted
            // only when pk_sec > 0, so its absence is not an error.
        }
        flush()
        return result
    }

    // MARK: - `wg show <iface> dump` (Linux / FreeBSD)

    /// Parse the TAB-separated dump from wireguard-tools.
    ///
    /// Line 0 is the interface (privkey, pubkey, listen-port, fwmark); every
    /// later line is a peer: pubkey, psk, endpoint, allowed-ips,
    /// latest-handshake, rx, tx, keepalive.
    ///
    /// `latestHandshake` here is an absolute unix timestamp (0 = never), unlike
    /// wg_core's already-relative age — hence the `now` parameter.
    public static func parseWGDump(_ text: String, now: Int) -> WGDumpResult {
        var result = WGDumpResult()
        var isFirst = true

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if rawLine.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            if isFirst {
                isFirst = false
                continue
            }
            let f = rawLine.split(separator: "\t", omittingEmptySubsequences: false)
                .map(String.init)
            guard f.count >= 8, !f[0].isEmpty else { continue }

            var peer = PeerStatus(pubkey: f[0])
            peer.endpoint = (f[2] == "(none)" || f[2].isEmpty) ? nil : f[2]
            if f[3] != "(none)" && !f[3].isEmpty {
                peer.allowedIPs = f[3].split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
            if let stamp = Int(f[4]), stamp > 0 {
                peer.lastHandshakeSec = max(0, now - stamp)
            }
            peer.rxBytes = Int(f[5]) ?? 0
            peer.txBytes = Int(f[6]) ?? 0
            result.peers.append(peer)
        }
        result.isRunning = !isFirst
        return result
    }

    // MARK: - Field scanners

    private static func value(after prefix: String, in line: String) -> String {
        String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
    }

    private static func firstToken(_ s: String) -> String? {
        s.split(separator: " ").first.map(String.init)
    }

    /// "never" | "9 seconds ago" | "2 minutes, 9 seconds ago" | "3 hours, 4 minutes ago"
    ///
    /// wg_core emits no days tier and always pluralizes, but singular and
    /// `days` are accepted so the same parser survives a format change.
    static func parseAge(_ s: String) -> Int? {
        let body = s.hasSuffix(" ago") ? String(s.dropLast(4)) : s
        if body == "never" || body.isEmpty { return nil }

        var total = 0
        var sawUnit = false
        for chunk in body.split(separator: ",") {
            let parts = chunk.trimmingCharacters(in: .whitespaces).split(separator: " ")
            guard parts.count == 2, let n = Int(parts[0]) else { continue }
            let unit = parts[1].hasSuffix("s") ? String(parts[1].dropLast()) : String(parts[1])
            let scale: Int
            switch unit {
            case "second": scale = 1
            case "minute": scale = 60
            case "hour":   scale = 3600
            case "day":    scale = 86400
            default: continue
            }
            total += n * scale
            sawUnit = true
        }
        return sawUnit ? total : nil
    }

    /// "168 B received, 1.42 KiB sent"
    ///
    /// wg_core prints an integer below 1 KiB and exactly two decimals above it,
    /// and has no TiB tier (5 TiB shows as "5120.00 GiB"). TiB is accepted
    /// anyway since upstream wg does emit it.
    static func parseTransfer(_ s: String) -> (rx: Int, tx: Int) {
        guard let sep = s.range(of: " received,") else { return (0, 0) }
        let rxPart = String(s[s.startIndex..<sep.lowerBound])
        var txPart = String(s[sep.upperBound...]).trimmingCharacters(in: .whitespaces)
        if txPart.hasSuffix(" sent") { txPart = String(txPart.dropLast(5)) }
        return (parseBytes(rxPart), parseBytes(txPart))
    }

    static func parseBytes(_ s: String) -> Int {
        let parts = s.trimmingCharacters(in: .whitespaces).split(separator: " ")
        guard parts.count == 2, let n = Double(parts[0]) else { return 0 }
        let scale: Double
        switch parts[1] {
        case "B":   scale = 1
        case "KiB": scale = 1024
        case "MiB": scale = 1024 * 1024
        case "GiB": scale = 1024 * 1024 * 1024
        case "TiB": scale = 1024 * 1024 * 1024 * 1024
        default: return 0
        }
        return Int(n * scale)
    }
}
