import Foundation

/// A `host:port` endpoint, with IPv6 brackets handled.
public struct Endpoint: Sendable, Equatable {
    public var host: String
    public var port: Int?

    public init(host: String, port: Int? = nil) {
        self.host = host
        self.port = port
    }

    /// Parses "1.2.3.4:1632", "[fd00::1]:1632", "zen.4950.store:1632".
    public init?(_ text: String) {
        let s = text.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return nil }

        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            port = rest.hasPrefix(":") ? Int(rest.dropFirst()) : nil
        } else if let colon = s.lastIndex(of: ":"),
                  s.firstIndex(of: ":") == colon {
            // Exactly one colon: host:port.
            host = String(s[s.startIndex..<colon])
            port = Int(s[s.index(after: colon)...])
        } else {
            // No colon, or many (a bare IPv6 literal).
            host = s
            port = nil
        }
        if host.isEmpty { return nil }
    }

    /// True when `host` is already an address, so there is nothing to resolve.
    public var isLiteralAddress: Bool {
        if host.contains(":") { return true }                 // IPv6 literal
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            !p.isEmpty && p.allSatisfy(\.isNumber) && (Int(p) ?? 256) <= 255
        }
    }
}

/// Decides whether a tunnel needs re-dialling.
///
/// The failure this exists for: a peer endpoint is configured as a DNS name,
/// the home modem gets a new public IP, dynamic DNS updates within seconds —
/// and the tunnel stays broken anyway, because WireGuard resolves the endpoint
/// once at load and then keeps sending to the dead address forever. Nothing
/// times it out and nothing retries the lookup. The whole mesh silently falls
/// off the hub until a human restarts each client.
///
/// So the agent has to notice. It compares the address the data plane is
/// actually sending to against what DNS says now, and treats a mismatch as a
/// re-dial trigger. Handshake staleness is the backstop for every other cause.
///
/// Pure decision function: the caller supplies the DNS answer and the observed
/// state, which is what makes each rule testable without a network.
public enum EndpointWatch {

    public struct Config: Sendable, Equatable {
        /// Don't re-dial more often than this. A re-dial costs a handshake and,
        /// on macOS, a launchd throttle window; hammering it turns a transient
        /// outage into a permanent flap.
        public var cooldownSec: Int
        /// Handshake age past which the tunnel is presumed dead.
        /// 180 s ≈ 7× the 25 s keepalive.
        public var stalenessSec: Int

        public init(cooldownSec: Int = 300, stalenessSec: Int = 180) {
            self.cooldownSec = cooldownSec
            self.stalenessSec = stalenessSec
        }
    }

    public enum Verdict: Sendable, Equatable {
        /// Nothing to do.
        case healthy
        /// DNS moved out from under the live tunnel — the headline case.
        case endpointDrifted(inUse: String, resolved: [String])
        /// Not obviously a DNS problem, but no handshake in far too long.
        case handshakeStale(ageSec: Int?)
        /// Action is warranted but we re-dialled too recently.
        case cooling(secondsRemaining: Int)
        /// Not enough information to judge; explicitly do nothing.
        case indeterminate(reason: String)
    }

    /// - Parameters:
    ///   - configured: the `Endpoint` line from the conf (may be a hostname).
    ///   - inUse: what the data plane reports it is sending to (always literal).
    ///   - resolved: current DNS answer for the configured host. Empty means
    ///     the lookup failed — which must NOT be read as drift.
    ///   - handshakeAgeSec: nil = never handshook.
    ///   - secondsSinceLastRedial: nil = we have never re-dialled.
    public static func evaluate(
        configured: String?,
        inUse: String?,
        resolved: [String],
        handshakeAgeSec: Int?,
        secondsSinceLastRedial: Int?,
        config: Config = Config()
    ) -> Verdict {
        let verdict = diagnose(configured: configured, inUse: inUse, resolved: resolved,
                               handshakeAgeSec: handshakeAgeSec, config: config)
        guard verdict != .healthy else { return .healthy }
        if case .indeterminate = verdict { return verdict }

        // Something is wrong, but respect the cooldown so a re-dial that hasn't
        // had time to take effect isn't immediately repeated.
        if let since = secondsSinceLastRedial, since < config.cooldownSec {
            return .cooling(secondsRemaining: config.cooldownSec - since)
        }
        return verdict
    }

    private static func diagnose(
        configured: String?,
        inUse: String?,
        resolved: [String],
        handshakeAgeSec: Int?,
        config: Config
    ) -> Verdict {
        // Rule 1 — the endpoint moved.
        if let configuredText = configured,
           let endpoint = Endpoint(configuredText),
           !endpoint.isLiteralAddress,
           !resolved.isEmpty,
           let inUseText = inUse,
           let inUseEndpoint = Endpoint(inUseText) {
            if !resolved.contains(inUseEndpoint.host) {
                return .endpointDrifted(inUse: inUseEndpoint.host, resolved: resolved)
            }
            // DNS and the data plane agree; a stale handshake now means
            // something else is wrong, so fall through to rule 2.
        }

        // Rule 2 — no recent handshake, whatever the cause.
        guard let age = handshakeAgeSec else {
            // Never handshook. Only actionable once the peer is dialable at
            // all; with no endpoint there is nothing a re-dial would fix.
            if inUse == nil || inUse?.isEmpty == true {
                return .indeterminate(reason: "no endpoint yet")
            }
            return .handshakeStale(ageSec: nil)
        }
        if age > config.stalenessSec {
            return .handshakeStale(ageSec: age)
        }
        return .healthy
    }
}

extension EndpointWatch.Verdict {
    /// Whether the agent should act on this verdict.
    public var requiresRedial: Bool {
        switch self {
        case .endpointDrifted, .handshakeStale: return true
        case .healthy, .cooling, .indeterminate: return false
        }
    }

    /// One-line reason for the log — the operator needs to know *why* a tunnel
    /// was restarted, not just that it was.
    public var logReason: String {
        switch self {
        case .healthy:
            return "healthy"
        case .endpointDrifted(let inUse, let resolved):
            return "endpoint drifted: sending to \(inUse), DNS now \(resolved.joined(separator: ","))"
        case .handshakeStale(let age):
            return "handshake stale: \(age.map { "\($0)s" } ?? "never")"
        case .cooling(let remaining):
            return "redial needed but cooling down (\(remaining)s left)"
        case .indeterminate(let reason):
            return "indeterminate: \(reason)"
        }
    }
}
