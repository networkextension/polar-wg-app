import XCTest
import WGAgentCore
@testable import WGPlatform

/// These exercise the real syscalls — that is the point. The POSIX layer is
/// exactly where the previous implementation's bugs lived, so mocking it would
/// test nothing worth testing.
final class POSIXProcessRunnerTests: XCTestCase {

    private var scratch: String!

    override func setUp() {
        super.setUp()
        scratch = NSTemporaryDirectory() + "wgagent-test-\(getpid())"
        try? FileManager.default.createDirectory(atPath: scratch,
                                                 withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: scratch)
        super.tearDown()
    }

    private func runner(env: [String: String] = [:]) -> POSIXProcessRunner {
        POSIXProcessRunner(scratchDir: scratch, extraEnvironment: env)
    }

    func testCapturesStdout() {
        let (code, out) = runner().run("/bin/echo", ["hello", "world"])
        XCTAssertEqual(code, 0)
        XCTAssertEqual(out.trimmingCharacters(in: .whitespacesAndNewlines), "hello world")
    }

    func testCapturesStderrToo() {
        let (code, out) = runner().run("/bin/sh", ["-c", "echo oops >&2"])
        XCTAssertEqual(code, 0)
        XCTAssertTrue(out.contains("oops"))
    }

    func testReportsNonZeroExitCode() {
        let (code, _) = runner().run("/bin/sh", ["-c", "exit 7"])
        XCTAssertEqual(code, 7)
    }

    /// A signalled child reports 128+signal, the way a shell does.
    func testReportsSignalDeath() {
        let (code, _) = runner().run("/bin/sh", ["-c", "kill -TERM $$"])
        XCTAssertEqual(code, 128 + SIGTERM)
    }

    func testMissingBinaryFailsWithoutCrashing() {
        let (code, out) = runner().run("/nonexistent/binary", [])
        XCTAssertEqual(code, -1)
        XCTAssertTrue(out.isEmpty)
    }

    func testExtraEnvironmentReachesTheChild() {
        let (_, out) = runner(env: ["SSL_CERT_FILE": "/tmp/probe.pem"])
            .run("/bin/sh", ["-c", "printf %s \"$SSL_CERT_FILE\""])
        XCTAssertEqual(out, "/tmp/probe.pem")
    }

    /// Our own stdio must survive being borrowed for output capture.
    func testParentStdioIsRestored() {
        let before = (dup(1), dup(2))
        defer { close(before.0); close(before.1) }
        _ = runner().run("/bin/echo", ["x"])
        XCTAssertEqual(fcntl(1, F_GETFD) >= 0, true)
        XCTAssertEqual(fcntl(2, F_GETFD) >= 0, true)
    }

    func testDoesNotLeaveScratchFilesBehind() throws {
        _ = runner().run("/bin/echo", ["x"])
        let left = try FileManager.default.contentsOfDirectory(atPath: scratch)
        XCTAssertTrue(left.isEmpty, "leftover: \(left)")
    }
}

final class ToolPathTests: XCTestCase {

    func testPicksTheFirstExecutableThatExists() {
        XCTAssertEqual(toolPath(["/nonexistent/wg", "/bin/sh"]), "/bin/sh")
    }

    func testFallsBackToTheFirstCandidateWhenNoneExist() {
        XCTAssertEqual(toolPath(["/usr/bin/wg", "/usr/local/bin/wg"]), "/usr/bin/wg")
    }

    func testEmptyCandidatesGiveEmptyString() {
        XCTAssertEqual(toolPath([]), "")
    }
}

final class FileLockTests: XCTestCase {

    private var path: String!

    override func setUp() {
        super.setUp()
        path = NSTemporaryDirectory() + "wgagent-lock-\(getpid())"
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: path)
        super.tearDown()
    }

    func testSecondAcquisitionIsRefusedWhileHeld() {
        let first = FileLock(path: path)
        XCTAssertNotNil(first)
        XCTAssertNil(FileLock(path: path), "an overlapping run must bail, not proceed")
        withExtendedLifetime(first) {}
    }

    func testLockIsReleasedOnDeinit() {
        do {
            let first = FileLock(path: path)
            XCTAssertNotNil(first)
        }
        XCTAssertNotNil(FileLock(path: path))
    }
}

final class HostFactsTests: XCTestCase {

    func testOSAndArchAreNormalized() {
        let os = HostFacts.osName()
        XCTAssertFalse(os.isEmpty)
        XCTAssertEqual(os, os.lowercased())
        XCTAssertTrue(["amd64", "arm64"].contains(HostFacts.arch()),
                      "unexpected arch \(HostFacts.arch())")
    }

    func testUptimeIsPositive() throws {
        let up = try XCTUnwrap(HostFacts.uptimeSec())
        XCTAssertGreaterThan(up, 0)
    }

    func testLanAddrsSkipLoopbackAndMeshAndTunnels() {
        let addrs = HostFacts.lanAddrs()
        for a in addrs {
            XCTAssertFalse(a.cidr.hasPrefix("127."), "loopback leaked: \(a)")
            XCTAssertFalse(a.cidr.hasPrefix("169.254."), "link-local leaked: \(a)")
            XCTAssertFalse(a.cidr.hasPrefix("10.88."), "mesh address leaked: \(a)")
            XCTAssertFalse(a.iface.hasPrefix("utun"), "tunnel leaked: \(a)")
            XCTAssertFalse(a.iface.hasPrefix("lo"), "loopback iface leaked: \(a)")
        }
    }

    func testLanAddrsAreWellFormedCIDRs() {
        for a in HostFacts.lanAddrs() {
            let parts = a.cidr.split(separator: "/")
            XCTAssertEqual(parts.count, 2, "not a CIDR: \(a.cidr)")
            let bits = Int(parts[1]) ?? -1
            XCTAssertTrue((0...32).contains(bits), "bad prefix length in \(a.cidr)")
            XCTAssertEqual(parts[0].split(separator: ".").count, 4, "bad address in \(a.cidr)")
        }
    }

    /// A caller can widen the filter; the mesh exclusion is only a default.
    func testExclusionsAreConfigurable() {
        let all = HostFacts.lanAddrs(excludingPrefixes: [], excludingInterfacePrefixes: [])
        XCTAssertTrue(all.contains { $0.cidr.hasPrefix("127.") },
                      "loopback should appear when nothing is excluded")
    }
}

final class StatusSocketTests: XCTestCase {

    func testConnectingToAMissingSocketFails() {
        XCTAssertThrowsError(try StatusSocket.read(path: "/nonexistent/wgc0.sock")) { error in
            guard case StatusSocket.Failure.connectFailed = error else {
                return XCTFail("expected connectFailed, got \(error)")
            }
        }
    }

    func testOverlongPathIsRejectedBeforeSyscall() {
        let tooLong = "/" + String(repeating: "a", count: 200)
        XCTAssertThrowsError(try StatusSocket.read(path: tooLong)) { error in
            XCTAssertEqual(error as? StatusSocket.Failure, .pathTooLong)
        }
    }
}

final class ResolverTests: XCTestCase {

    func testResolvesLoopback() {
        XCTAssertTrue(Resolver.addresses(for: "localhost").contains { $0 == "127.0.0.1" || $0 == "::1" })
    }

    func testResolvesLiteralToItself() {
        XCTAssertEqual(Resolver.addresses(for: "58.37.118.81"), ["58.37.118.81"])
    }

    /// Empty means "no information" — the caller must not read it as drift.
    func testUnresolvableHostGivesEmpty() {
        XCTAssertTrue(Resolver.addresses(for: "no-such-host.invalid").isEmpty)
    }

    func testEmptyHostGivesEmpty() {
        XCTAssertTrue(Resolver.addresses(for: "").isEmpty)
    }

    func testDeduplicatesAcrossSocktypes() {
        // getaddrinfo returns one entry per socktype; we ask for DGRAM only and
        // de-dupe, so a single-A-record host must yield exactly one answer.
        XCTAssertEqual(Resolver.addresses(for: "localhost", family: AF_INET), ["127.0.0.1"])
    }

    /// The real hub name this fleet dials. Skipped when the network is down —
    /// the point is the shape of the answer, not that DNS is reachable in CI.
    func testResolvesTheRealHubName() throws {
        let addrs = Resolver.addresses(for: "zen.4950.store", family: AF_INET)
        try XCTSkipIf(addrs.isEmpty, "no DNS available")
        for a in addrs {
            XCTAssertEqual(a.split(separator: ".").count, 4, "expected IPv4, got \(a)")
        }
    }
}

final class RedialJournalTests: XCTestCase {

    private var dir: String!
    private var journal: RedialJournal!

    override func setUp() {
        super.setUp()
        dir = NSTemporaryDirectory() + "wgagent-journal-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        journal = RedialJournal(directory: dir)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: dir)
        super.tearDown()
    }

    func testUnknownInterfaceHasNoHistory() {
        XCTAssertNil(journal.secondsSinceLastRedial(iface: "wgc0"))
    }

    /// The agent exits between ticks, so the cooldown has to live on disk.
    func testRecordSurvivesForLaterReads() {
        let t = Date()
        journal.recordRedial(iface: "wgc0", now: t)
        XCTAssertEqual(journal.secondsSinceLastRedial(iface: "wgc0", now: t), 0)
        XCTAssertEqual(journal.secondsSinceLastRedial(iface: "wgc0", now: t.addingTimeInterval(90)), 90)
    }

    func testInterfacesAreIndependent() {
        journal.recordRedial(iface: "wgc0")
        XCTAssertNil(journal.secondsSinceLastRedial(iface: "wgc1"))
    }

    func testClearForgetsTheStamp() {
        journal.recordRedial(iface: "wgc0")
        journal.clear(iface: "wgc0")
        XCTAssertNil(journal.secondsSinceLastRedial(iface: "wgc0"))
    }

    /// A clock that jumped backwards must not produce a negative cooldown.
    func testBackwardsClockIsIgnored() {
        let t = Date()
        journal.recordRedial(iface: "wgc0", now: t)
        XCTAssertNil(journal.secondsSinceLastRedial(iface: "wgc0", now: t.addingTimeInterval(-60)))
    }
}

final class EndpointReconcilerTests: XCTestCase {

    /// Records what it was asked to do instead of touching a real tunnel.
    private final class SpyRedialer: TunnelRedialer, @unchecked Sendable {
        var calls: [(iface: String, key: String, endpoint: String)] = []
        var succeed = true
        func redial(iface: String, peerPublicKey: String, endpoint: String) -> Bool {
            calls.append((iface, peerPublicKey, endpoint))
            return succeed
        }
    }

    private var dir: String!

    override func setUp() {
        super.setUp()
        dir = NSTemporaryDirectory() + "wgagent-recon-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: dir)
        super.tearDown()
    }

    private func makeReconciler(_ spy: SpyRedialer) -> EndpointReconciler {
        EndpointReconciler(redialer: spy, journal: RedialJournal(directory: dir))
    }

    func testHealthyTunnelIsLeftAlone() {
        let spy = SpyRedialer()
        let status = PeerStatus(pubkey: "K", endpoint: "127.0.0.1:1632", lastHandshakeSec: 10)
        let out = makeReconciler(spy).reconcile(iface: "wgc0", peerPublicKey: "K",
                                                configuredEndpoint: "localhost:1632",
                                                status: status)
        XCTAssertEqual(out.verdict, .healthy)
        XCTAssertFalse(out.redialed)
        XCTAssertTrue(spy.calls.isEmpty)
    }

    /// localhost resolves to 127.0.0.1, so a peer stuck on 10.9.9.9 is drift.
    func testDriftTriggersRedialAndIsRecorded() {
        let spy = SpyRedialer()
        let reconciler = makeReconciler(spy)
        let status = PeerStatus(pubkey: "K", endpoint: "10.9.9.9:1632", lastHandshakeSec: 5)

        let out = reconciler.reconcile(iface: "wgc0", peerPublicKey: "K",
                                       configuredEndpoint: "localhost:1632", status: status)
        XCTAssertTrue(out.verdict.requiresRedial, "got \(out.verdict)")
        XCTAssertTrue(out.redialed)
        XCTAssertEqual(spy.calls.count, 1)
        XCTAssertEqual(spy.calls.first?.endpoint, "localhost:1632")

        // Second pass within the cooldown must not act again.
        let again = reconciler.reconcile(iface: "wgc0", peerPublicKey: "K",
                                         configuredEndpoint: "localhost:1632", status: status)
        XCTAssertFalse(again.redialed)
        XCTAssertEqual(spy.calls.count, 1, "cooldown must survive across reconciles")
    }

    /// A failed re-dial must not be journalled, or the cooldown would lock out
    /// the retry that might have worked.
    func testFailedRedialIsNotJournalled() {
        let spy = SpyRedialer()
        spy.succeed = false
        let reconciler = makeReconciler(spy)
        let status = PeerStatus(pubkey: "K", endpoint: "10.9.9.9:1632", lastHandshakeSec: 5)

        let first = reconciler.reconcile(iface: "wgc0", peerPublicKey: "K",
                                         configuredEndpoint: "localhost:1632", status: status)
        XCTAssertFalse(first.redialed)
        _ = reconciler.reconcile(iface: "wgc0", peerPublicKey: "K",
                                 configuredEndpoint: "localhost:1632", status: status)
        XCTAssertEqual(spy.calls.count, 2, "a failed attempt must be retried next tick")
    }

    func testStaleHandshakeAloneTriggersRedial() {
        let spy = SpyRedialer()
        let status = PeerStatus(pubkey: "K", endpoint: "127.0.0.1:1632", lastHandshakeSec: 9999)
        let out = makeReconciler(spy).reconcile(iface: "wgc0", peerPublicKey: "K",
                                                configuredEndpoint: "localhost:1632",
                                                status: status)
        XCTAssertEqual(out.verdict, .handshakeStale(ageSec: 9999))
        XCTAssertTrue(out.redialed)
    }
}

final class PublicIPProbeTests: XCTestCase {

    /// Answers from a script instead of the network, and counts requests —
    /// the rate-limit budget is the whole reason this thing caches.
    private final class StubFetcher: PublicIPFetcher, @unchecked Sendable {
        var answers: [String: String?] = [:]
        var requests: [String] = []
        func fetch(url: String, timeoutSec: Int) -> String? {
            requests.append(url)
            return answers[url] ?? nil
        }
    }

    private var cachePath: String!

    override func setUp() {
        super.setUp()
        cachePath = NSTemporaryDirectory() + "wgagent-pubip-\(getpid())"
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: cachePath)
        super.tearDown()
    }

    private func probe(_ fetcher: PublicIPFetcher,
                       urls: [String] = ["primary", "backup"]) -> PublicIPProbe {
        PublicIPProbe(fetcher: fetcher, cachePath: cachePath, urls: urls,
                      config: .init(ttlSec: 900, retrySec: 120))
    }

    func testFetchesAndPersists() {
        let f = StubFetcher()
        f.answers["primary"] = "119.54.154.116"
        let r = probe(f).currentIP()
        XCTAssertEqual(r.ip, "119.54.154.116")
        XCTAssertFalse(r.fromCache)
        XCTAssertTrue(FileManager.default.fileExists(atPath: cachePath))
    }

    /// A second call inside the TTL must not spend a request.
    func testSecondCallInsideTTLUsesTheCache() {
        let f = StubFetcher()
        f.answers["primary"] = "119.54.154.116"
        let p = probe(f)
        _ = p.currentIP()
        let second = p.currentIP()
        XCTAssertEqual(second.ip, "119.54.154.116")
        XCTAssertTrue(second.fromCache)
        XCTAssertEqual(f.requests.count, 1, "cache must protect the rate-limit budget")
    }

    func testCacheExpiryTriggersAFreshRequest() {
        let f = StubFetcher()
        f.answers["primary"] = "1.1.1.1"
        let p = probe(f)
        let t0 = Date()
        _ = p.currentIP(now: t0)

        f.answers["primary"] = "2.2.2.2"
        let later = p.currentIP(now: t0.addingTimeInterval(901))
        XCTAssertEqual(later.ip, "2.2.2.2")
        XCTAssertEqual(later.changedFrom, "1.1.1.1", "a change must be reportable")
        XCTAssertEqual(f.requests.count, 2)
    }

    func testFallsBackToTheSecondSource() {
        let f = StubFetcher()
        f.answers["primary"] = nil
        f.answers["backup"] = "9.9.9.9"
        XCTAssertEqual(probe(f).currentIP().ip, "9.9.9.9")
        XCTAssertEqual(f.requests, ["primary", "backup"])
    }

    func testStopsAtTheFirstUsableAnswer() {
        let f = StubFetcher()
        f.answers["primary"] = "9.9.9.9"
        _ = probe(f).currentIP()
        XCTAssertEqual(f.requests, ["primary"], "backup must not be spent needlessly")
    }

    /// Rate-limit pages and error bodies are not addresses.
    func testNonAddressResponseIsRejectedAndFallsThrough() {
        let f = StubFetcher()
        f.answers["primary"] = "rate limit exceeded"
        f.answers["backup"] = "9.9.9.9"
        XCTAssertEqual(probe(f).currentIP().ip, "9.9.9.9")
    }

    func testTotalFailureWithNoHistoryReportsNothing() {
        let f = StubFetcher()
        XCTAssertNil(probe(f).currentIP().ip)
    }

    /// Offline must not blank out a known-good endpoint.
    func testTotalFailureKeepsServingTheStaleAddress() {
        let f = StubFetcher()
        f.answers["primary"] = "1.1.1.1"
        let p = probe(f)
        let t0 = Date()
        _ = p.currentIP(now: t0)

        f.answers["primary"] = nil
        f.answers["backup"] = nil
        let offline = p.currentIP(now: t0.addingTimeInterval(901))
        XCTAssertEqual(offline.ip, "1.1.1.1", "stale beats nothing")
    }

    func testEndpointStringUsesTheListenPort() {
        let f = StubFetcher()
        f.answers["primary"] = "119.54.154.116"
        XCTAssertEqual(probe(f).wgEndpoint(listenPort: 51820), "119.54.154.116:51820")
    }

    func testEndpointIsBlankWhenUnknown() {
        XCTAssertEqual(probe(StubFetcher()).wgEndpoint(listenPort: 51820), "",
                       "blank tells the server to keep what it has")
    }

    /// The shell agent writes the same one-line format; both must interoperate
    /// while the fleet is half-migrated.
    func testReadsACacheFileWrittenByTheShellAgent() throws {
        let stamp = Int(Date().timeIntervalSince1970)
        try "\(stamp) 203.0.113.9\n".write(toFile: cachePath, atomically: true, encoding: .utf8)
        let f = StubFetcher()
        let r = probe(f).currentIP()
        XCTAssertEqual(r.ip, "203.0.113.9")
        XCTAssertTrue(r.fromCache)
        XCTAssertTrue(f.requests.isEmpty)
    }

    func testWrittenCacheIsShellReadable() throws {
        let f = StubFetcher()
        f.answers["primary"] = "203.0.113.9"
        _ = probe(f).currentIP()
        let text = try String(contentsOfFile: cachePath, encoding: .utf8)
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        XCTAssertEqual(parts.count, 2)
        XCTAssertNotNil(Int(parts[0]))
        XCTAssertEqual(String(parts[1]), "203.0.113.9")
    }
}

final class CABundleTests: XCTestCase {

    func testLocateFindsABundleOrHonestlyReturnsNil() {
        if let found = CABundle.locate() {
            XCTAssertTrue(FileManager.default.fileExists(atPath: found))
        }
    }

    func testCandidateListCoversTheKnownPlatforms() {
        XCTAssertTrue(CABundle.candidates.contains("/etc/ssl/cert.pem"))              // macOS/FreeBSD
        XCTAssertTrue(CABundle.candidates.contains("/etc/ssl/certs/ca-certificates.crt")) // Debian
        XCTAssertTrue(CABundle.candidates.contains("/usr/local/share/certs/ca-root-nss.crt")) // FreeBSD ports
    }
}
