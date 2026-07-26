import Foundation

/// Cache policy for the device's own public egress IP.
///
/// Why this is asked of an outside service at all: `wg_endpoint` is documented
/// as the "public observed peer", but every agent derived it from the default
/// NIC's own address — which behind NAT is an RFC1918 address and never the
/// egress IP. So the control plane could not see a device's egress change, ever.
/// The address is only knowable from outside, so we ask.
///
/// Why it is cached: ifconfig.co asks for at most one request per minute per
/// source IP, and every device behind one NAT shares that budget. A 60 s
/// heartbeat probing every tick would get itself rate-limited.
///
/// Pure policy, no I/O — the caller does the fetch. That keeps the TTL, the
/// backoff and the stale-fallback behaviour testable without a network.
public enum PublicIPCache {

    public struct Config: Sendable, Equatable {
        /// How long an answer stays fresh.
        public var ttlSec: Int
        /// After a total lookup failure, retry this soon instead of waiting out
        /// the whole TTL.
        public var retrySec: Int

        public init(ttlSec: Int = 900, retrySec: Int = 120) {
            self.ttlSec = ttlSec
            self.retrySec = retrySec
        }
    }

    /// On-disk entry: `"<unix-stamp> <ip>"`.
    ///
    /// Same one-line format the shell agent uses, deliberately: during the
    /// migration both implementations can share `/etc/wgctl/public_ip` without
    /// either invalidating the other's work.
    public struct Entry: Sendable, Equatable {
        public var stamp: Int
        public var ip: String

        public init(stamp: Int, ip: String) {
            self.stamp = stamp
            self.ip = ip
        }

        public init?(serialized: String) {
            let parts = serialized.split(separator: " ", omittingEmptySubsequences: true)
            guard let first = parts.first, let stamp = Int(first) else { return nil }
            self.stamp = stamp
            self.ip = parts.count > 1 ? String(parts[1]) : ""
        }

        public var serialized: String { "\(stamp) \(ip)\n" }
    }

    public enum Decision: Sendable, Equatable {
        /// Still fresh — don't spend a request.
        case useCached(String)
        /// Go ask. `previous` is what we'd fall back to if the probe fails.
        case probe(previous: String?)
    }

    public static func decide(entry: Entry?, now: Int, config: Config = Config()) -> Decision {
        guard let entry, !entry.ip.isEmpty else { return .probe(previous: nil) }
        if now - entry.stamp < config.ttlSec {
            return .useCached(entry.ip)
        }
        return .probe(previous: entry.ip)
    }

    /// What to persist and report once a probe has been attempted.
    ///
    /// - Parameter fetched: the probe result, or nil when every source failed.
    public static func resolve(fetched: String?, previous: String?, now: Int,
                               config: Config = Config())
        -> (entry: Entry, reported: String?, changedFrom: String?) {

        if let fetched, isIPv4(fetched) {
            let changed = (previous != nil && previous != fetched) ? previous : nil
            return (Entry(stamp: now, ip: fetched), fetched, changed)
        }

        // Every source failed. Keep serving the last known address — a slightly
        // old IP beats none — but back-date the stamp so the next attempt comes
        // in `retrySec` rather than a full TTL later.
        let backdated = now - config.ttlSec + config.retrySec
        return (Entry(stamp: backdated, ip: previous ?? ""), previous, nil)
    }

    public static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            !p.isEmpty && p.count <= 3 && p.allSatisfy(\.isNumber) && (Int(p) ?? 256) <= 255
        }
    }

    /// Assemble the value the heartbeat reports.
    ///
    /// Empty when the address is unknown, and that emptiness is load-bearing:
    /// the control plane keeps the previously stored endpoint when this field
    /// is blank, whereas the `":<port>"` a failed lookup used to produce
    /// overwrote a good value with junk.
    public static func wgEndpoint(ip: String?, listenPort: Int) -> String {
        guard let ip, !ip.isEmpty else { return "" }
        return "\(ip):\(listenPort)"
    }
}
