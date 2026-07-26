import Foundation
import WGAgentCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Fetches this host's public address from an outside echo service.
public protocol PublicIPFetcher: Sendable {
    /// Returns the body of a successful GET, or nil on any failure.
    func fetch(url: String, timeoutSec: Int) -> String?
}

/// Echo lookup via a `curl` subprocess.
///
/// An interim implementation: once the libcurl-backed `HTTPTransport` lands
/// this becomes a one-line swap, because the policy in `PublicIPCache` and the
/// probe below never touch the transport directly.
public struct CurlPublicIPFetcher: PublicIPFetcher {
    private let runner: ProcessRunner
    private let curlPath: String

    public init(runner: ProcessRunner,
                curlPath: String = toolPath(["/usr/bin/curl", "/usr/local/bin/curl"])) {
        self.runner = runner
        self.curlPath = curlPath
    }

    public func fetch(url: String, timeoutSec: Int) -> String? {
        guard !curlPath.isEmpty else { return nil }
        // -4: the answer has to be the IPv4 egress, and wg_endpoint is
        // "host:port" with no brackets, so a v6 reply would be unusable anyway.
        // --noproxy: a dead login-environment proxy must not silently redirect
        // this into reporting the proxy's address as ours.
        let (code, out) = runner.run(curlPath, [
            "-4", "-fsS", "--noproxy", "*",
            "--connect-timeout", "3", "--max-time", "\(timeoutSec)",
            url,
        ])
        guard code == 0 else { return nil }
        let text = out.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }
}

/// Discovers and caches the device's public egress IP.
///
/// This is the half of remote-IP awareness that faces the control plane: the
/// agent already re-dials when the *hub's* address moves (see `EndpointWatch`),
/// and this makes the device's *own* egress change visible in the admin view
/// instead of reporting a NAT-private address forever.
public struct PublicIPProbe {
    private let fetcher: PublicIPFetcher
    private let cachePath: String
    private let urls: [String]
    private let config: PublicIPCache.Config
    private let timeoutSec: Int

    /// ifconfig.co first, ifconfig.me as backup. api.ipify.org is deliberately
    /// absent: it is unreachable from the networks this fleet lives on.
    public static let defaultURLs = [
        "https://ifconfig.co/ip",
        "https://ifconfig.me/ip",
    ]

    public init(fetcher: PublicIPFetcher,
                cachePath: String = "/etc/wgctl/public_ip",
                urls: [String] = defaultURLs,
                config: PublicIPCache.Config = .init(),
                timeoutSec: Int = 5) {
        self.fetcher = fetcher
        self.cachePath = cachePath
        self.urls = urls
        self.config = config
        self.timeoutSec = timeoutSec
    }

    public struct Result: Sendable, Equatable {
        public var ip: String?
        /// Set only when this probe observed a change, for the log line.
        public var changedFrom: String?
        /// True when the answer came from cache and no request was made.
        public var fromCache: Bool
    }

    public func currentIP(now: Date = Date()) -> Result {
        let nowSec = Int(now.timeIntervalSince1970)
        let entry = readEntry()

        switch PublicIPCache.decide(entry: entry, now: nowSec, config: config) {
        case .useCached(let ip):
            return Result(ip: ip, changedFrom: nil, fromCache: true)

        case .probe(let previous):
            var fetched: String?
            for url in urls {
                if let candidate = fetcher.fetch(url: url, timeoutSec: timeoutSec),
                   PublicIPCache.isIPv4(candidate) {
                    fetched = candidate
                    break
                }
            }
            let outcome = PublicIPCache.resolve(fetched: fetched, previous: previous,
                                                now: nowSec, config: config)
            writeEntry(outcome.entry)
            return Result(ip: outcome.reported, changedFrom: outcome.changedFrom,
                          fromCache: false)
        }
    }

    /// The `wg_endpoint` value for the heartbeat, "" when unknown.
    public func wgEndpoint(listenPort: Int, now: Date = Date()) -> String {
        PublicIPCache.wgEndpoint(ip: currentIP(now: now).ip, listenPort: listenPort)
    }

    // MARK: - Store

    private func readEntry() -> PublicIPCache.Entry? {
        guard let text = try? String(contentsOfFile: cachePath, encoding: .utf8) else { return nil }
        return PublicIPCache.Entry(serialized: text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func writeEntry(_ entry: PublicIPCache.Entry) {
        let tmp = cachePath + ".tmp"
        guard (try? entry.serialized.write(toFile: tmp, atomically: false, encoding: .utf8)) != nil
        else { return }
        chmod(tmp, 0o600)
        rename(tmp, cachePath)
    }
}
