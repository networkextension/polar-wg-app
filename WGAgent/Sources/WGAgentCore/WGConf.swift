import Foundation

/// A `key = value` line we don't manage but must not destroy.
public struct WGKeyValue: Sendable, Equatable {
    public var key: String
    public var value: String

    public init(key: String, value: String) {
        self.key = key
        self.value = value
    }
}

public struct WGInterfaceSection: Sendable, Equatable {
    public var privateKey: String
    public var address: String
    public var listenPort: String
    /// Everything else the operator put in `[Interface]` — MTU, Table, DNS,
    /// PostUp, … The shell agents silently dropped these on every re-render;
    /// we carry them through in file order instead.
    public var extras: [WGKeyValue]

    public init(privateKey: String, address: String, listenPort: String,
                extras: [WGKeyValue] = []) {
        self.privateKey = privateKey
        self.address = address
        self.listenPort = listenPort
        self.extras = extras
    }
}

public struct WGPeerSection: Sendable, Equatable {
    public var publicKey: String
    public var endpoint: String?
    public var allowedIPs: [String]
    public var keepalive: Int?

    public init(publicKey: String, endpoint: String? = nil,
                allowedIPs: [String] = [], keepalive: Int? = nil) {
        self.publicKey = publicKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.keepalive = keepalive
    }
}

public struct WGConfig: Sendable, Equatable {
    public var interface: WGInterfaceSection
    public var peers: [WGPeerSection]

    public init(interface: WGInterfaceSection, peers: [WGPeerSection]) {
        self.interface = interface
        self.peers = peers
    }
}

// MARK: - Parsing

extension WGConfig {
    public static func parse(_ text: String) -> WGConfig? {
        enum Section { case none, interface, peer }
        var section = Section.none

        var priv = "", addr = "", listen = ""
        var extras: [WGKeyValue] = []
        var peers: [WGPeerSection] = []
        var cur: WGPeerSection?

        func flushPeer() {
            if let p = cur, !p.publicKey.isEmpty { peers.append(p) }
            cur = nil
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            if line.hasPrefix("[") {
                let name = line.lowercased()
                if name.hasPrefix("[interface]") {
                    flushPeer()
                    section = .interface
                } else if name.hasPrefix("[peer]") {
                    flushPeer()
                    section = .peer
                    cur = WGPeerSection(publicKey: "")
                } else {
                    flushPeer()
                    section = .none
                }
                continue
            }

            // Split on the FIRST '=' only: base64 keys contain '=' padding.
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            switch section {
            case .interface:
                switch key.lowercased() {
                case "privatekey": priv = value
                case "address": addr = value
                case "listenport": listen = value
                default: extras.append(WGKeyValue(key: key, value: value))
                }
            case .peer:
                switch key.lowercased() {
                case "publickey": cur?.publicKey = value
                case "endpoint": cur?.endpoint = value.isEmpty ? nil : value
                case "allowedips":
                    cur?.allowedIPs = value.split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                case "persistentkeepalive": cur?.keepalive = Int(value)
                default: break
                }
            case .none:
                continue
            }
        }
        flushPeer()

        guard !priv.isEmpty else { return nil }
        return WGConfig(
            interface: WGInterfaceSection(privateKey: priv, address: addr,
                                          listenPort: listen, extras: extras),
            peers: peers)
    }
}

// MARK: - Rendering

extension WGConfig {
    /// Deterministic render: peers sorted by public key so an unchanged mesh
    /// always produces the same bytes.
    public func render() -> String {
        var out = "[Interface]\n"
        out += "PrivateKey = \(interface.privateKey)\n"
        out += "Address    = \(interface.address)\n"
        out += "ListenPort = \(interface.listenPort)\n"
        for kv in interface.extras {
            out += "\(kv.key) = \(kv.value)\n"
        }
        out += "\n"

        for peer in peers.sorted(by: { $0.publicKey < $1.publicKey }) {
            out += "[Peer]\n"
            out += "PublicKey  = \(peer.publicKey)\n"
            if let ep = peer.endpoint, !ep.isEmpty {
                out += "Endpoint   = \(ep)\n"
            }
            out += "AllowedIPs = \(peer.allowedIPs.joined(separator: ", "))\n"
            if let ka = peer.keepalive, ka > 0 {
                out += "PersistentKeepalive = \(ka)\n"
            }
            out += "\n"
        }
        return out
    }
}

// MARK: - Semantic comparison

extension WGPeerSection {
    /// Order-insensitive identity used for change detection.
    fileprivate var semanticKey: String {
        let ips = allowedIPs.sorted().joined(separator: ",")
        return "\(publicKey)|\(endpoint ?? "")|\(ips)|\(keepalive ?? 0)"
    }
}

extension WGConfig {
    /// True when the two configs mean the same thing.
    ///
    /// Deliberately NOT a byte comparison. The shell agents diffed the rendered
    /// file with `cmp`, which made the column padding (`PrivateKey `,
    /// `Address    `, …) load-bearing: any formatting drift read as "changed"
    /// and kickstarted the tunnel once a minute, forever. Comparing meaning
    /// instead makes the shell→Swift cutover a no-op on every host whose mesh
    /// did not actually change.
    public func semanticallyEquals(_ other: WGConfig) -> Bool {
        guard interface.privateKey == other.interface.privateKey,
              interface.address == other.interface.address,
              interface.listenPort == other.interface.listenPort
        else { return false }

        let mine = Set(interface.extras.map { "\($0.key.lowercased())=\($0.value)" })
        let theirs = Set(other.interface.extras.map { "\($0.key.lowercased())=\($0.value)" })
        guard mine == theirs else { return false }

        return Set(peers.map(\.semanticKey)) == Set(other.peers.map(\.semanticKey))
    }

    /// Every AllowedIPs CIDR across all peers.
    public var routeSet: Set<String> {
        Set(peers.flatMap(\.allowedIPs))
    }

    /// Routes decide the reload strategy: an unchanged route set can be applied
    /// with `wg syncconf` (no tunnel drop), a changed one needs a full restart.
    public func routesDiffer(from other: WGConfig) -> Bool {
        routeSet != other.routeSet
    }
}

// MARK: - Building a config from a control-plane response

extension WGConfig {
    /// Merge a `/v1/peers` response into the interface we already have on disk.
    ///
    /// Returns nil when there is no usable local `[Interface]` — never render a
    /// config without a private key, or we would install an empty file and
    /// then restart the tunnel into it.
    public static func build(existing: WGConfig?,
                             response: PeersResponse,
                             fallbackDeviceIP: String? = nil,
                             fallbackListenPort: Int) -> WGConfig? {
        guard let existing, !existing.interface.privateKey.isEmpty else { return nil }

        var iface = existing.interface
        if iface.address.isEmpty, let ip = fallbackDeviceIP ?? response.deviceIP, !ip.isEmpty {
            // /24, not /32: a /32 silently breaks mesh routing even with a
            // healthy handshake.
            iface.address = ip.contains("/") ? ip : ip + "/24"
        }
        if iface.listenPort.isEmpty {
            iface.listenPort = String(fallbackListenPort)
        }

        let keepalive = response.keepaliveSec ?? 25
        let peers: [WGPeerSection] = response.peers.compactMap { entry in
            guard !entry.pubkey.isEmpty else { return nil }
            let ips = entry.allowedIPs
            guard !ips.isEmpty else { return nil }
            return WGPeerSection(publicKey: entry.pubkey,
                                 endpoint: entry.endpoint?.isEmpty == true ? nil : entry.endpoint,
                                 allowedIPs: ips,
                                 keepalive: keepalive > 0 ? keepalive : nil)
        }
        return WGConfig(interface: iface, peers: peers)
    }
}
