import Foundation
import WGAgentCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Bringing a tunnel back after the peer endpoint moved, or after it went dead.
public protocol TunnelRedialer: Sendable {
    /// Re-point `iface` at `endpoint` (a `host:port`, host possibly a name).
    /// Returns true when the action was issued successfully.
    func redial(iface: String, peerPublicKey: String, endpoint: String) -> Bool
}

/// Linux / FreeBSD: kernel WireGuard can re-resolve a peer endpoint in place.
///
/// `wg set <iface> peer <pub> endpoint <host>:<port>` re-runs the lookup and
/// swaps the destination without dropping the interface, so routes stay put and
/// nothing else notices. Strongly preferred over a full `wg-quick down/up`.
public struct WGSetRedialer: TunnelRedialer {
    private let runner: ProcessRunner
    private let wgPath: String

    public init(runner: ProcessRunner,
                wgPath: String = toolPath(["/usr/bin/wg", "/usr/local/bin/wg"])) {
        self.runner = runner
        self.wgPath = wgPath
    }

    public func redial(iface: String, peerPublicKey: String, endpoint: String) -> Bool {
        guard !wgPath.isEmpty, !peerPublicKey.isEmpty, !endpoint.isEmpty else { return false }
        let (code, _) = runner.run(wgPath, ["set", iface, "peer", peerPublicKey,
                                            "endpoint", endpoint])
        return code == 0
    }
}

/// macOS / iOS: `wg_core` reads its config only at startup and has no
/// equivalent of `wg set`, so the only way to re-resolve is to restart it.
///
/// `kickstart -k` rather than bootout+bootstrap: the job's `ThrottleInterval`
/// is 10 s, and tearing the job down and back up stacks that throttle instead
/// of just restarting the process.
public struct LaunchdRedialer: TunnelRedialer {
    private let runner: ProcessRunner
    private let launchctlPath: String

    public init(runner: ProcessRunner, launchctlPath: String = "/bin/launchctl") {
        self.runner = runner
        self.launchctlPath = launchctlPath
    }

    public func redial(iface: String, peerPublicKey: String, endpoint: String) -> Bool {
        let (code, _) = runner.run(launchctlPath,
                                   ["kickstart", "-k", "system/com.wireguard.wg-mac.\(iface)"])
        return code == 0
    }
}

/// Remembers when each interface was last re-dialled, so the cooldown in
/// `EndpointWatch` survives the process exiting between ticks.
///
/// The agent is a one-shot: it runs, reconciles, exits, and the scheduler
/// starts it again a minute later. An in-memory timestamp would be forgotten
/// every tick and the cooldown would never apply.
public struct RedialJournal {
    public let directory: String

    public init(directory: String = "/var/run/wireguard") {
        self.directory = directory
    }

    private func path(for iface: String) -> String {
        "\(directory)/\(iface).redial"
    }

    public func secondsSinceLastRedial(iface: String, now: Date = Date()) -> Int? {
        guard let text = try? String(contentsOfFile: path(for: iface), encoding: .utf8),
              let stamp = Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        let delta = Int(now.timeIntervalSince1970) - stamp
        return delta >= 0 ? delta : nil
    }

    public func recordRedial(iface: String, now: Date = Date()) {
        let stamp = String(Int(now.timeIntervalSince1970))
        let tmp = path(for: iface) + ".tmp"
        guard (try? stamp.write(toFile: tmp, atomically: false, encoding: .utf8)) != nil else {
            return
        }
        // Rename so a reader never sees a half-written stamp.
        rename(tmp, path(for: iface))
    }

    public func clear(iface: String) {
        unlink(path(for: iface))
    }
}

/// Ties the pieces together: look at what the tunnel is doing, ask DNS what the
/// endpoint should be now, and re-dial if they disagree.
public struct EndpointReconciler {
    private let redialer: TunnelRedialer
    private let journal: RedialJournal
    private let config: EndpointWatch.Config

    public init(redialer: TunnelRedialer,
                journal: RedialJournal = RedialJournal(),
                config: EndpointWatch.Config = .init()) {
        self.redialer = redialer
        self.journal = journal
        self.config = config
    }

    public struct Outcome: Sendable, Equatable {
        public var verdict: EndpointWatch.Verdict
        public var redialed: Bool
    }

    /// - Parameters:
    ///   - configuredEndpoint: the conf's `Endpoint` for this peer.
    ///   - status: what the data plane currently reports for that peer.
    public func reconcile(iface: String,
                          peerPublicKey: String,
                          configuredEndpoint: String?,
                          status: PeerStatus?,
                          now: Date = Date()) -> Outcome {
        let resolved: [String] = {
            guard let text = configuredEndpoint,
                  let endpoint = Endpoint(text),
                  !endpoint.isLiteralAddress
            else { return [] }
            return Resolver.addresses(for: endpoint.host)
        }()

        let verdict = EndpointWatch.evaluate(
            configured: configuredEndpoint,
            inUse: status?.endpoint,
            resolved: resolved,
            handshakeAgeSec: status?.lastHandshakeSec,
            secondsSinceLastRedial: journal.secondsSinceLastRedial(iface: iface, now: now),
            config: config)

        guard verdict.requiresRedial, let endpoint = configuredEndpoint else {
            return Outcome(verdict: verdict, redialed: false)
        }

        let ok = redialer.redial(iface: iface, peerPublicKey: peerPublicKey, endpoint: endpoint)
        if ok { journal.recordRedial(iface: iface, now: now) }
        return Outcome(verdict: verdict, redialed: ok)
    }
}
