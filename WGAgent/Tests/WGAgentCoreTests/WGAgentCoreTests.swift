import XCTest
@testable import WGAgentCore

// MARK: - State decoding

final class DeviceStateTests: XCTestCase {

    private func decode(_ json: String) throws -> DeviceState {
        try JSONDecoder().decode(DeviceState.self, from: Data(json.utf8))
    }

    func testAcceptsWGListenKey() throws {
        let s = try decode(#"{"server":"https://a.b","device_id":"d","token":"t","wg_listen":1632}"#)
        XCTAssertEqual(s.wgListen, 1632)
    }

    /// join-linux.sh writes "listen"; reading only "wg_listen" pinned those
    /// hosts to the default port no matter what they actually listen on.
    func testAcceptsLegacyListenKey() throws {
        let s = try decode(#"{"server":"https://a.b","device_id":"d","token":"t","listen":51820}"#)
        XCTAssertEqual(s.wgListen, 51820)
    }

    func testWGListenWinsOverListen() throws {
        let s = try decode(#"{"server":"https://a.b","device_id":"d","token":"t","wg_listen":1632,"listen":9}"#)
        XCTAssertEqual(s.wgListen, 1632)
    }

    func testStripsTrailingSlashFromServer() throws {
        let s = try decode(#"{"server":"https://a.b:2443/","device_id":"d","token":"t"}"#)
        XCTAssertEqual(s.server, "https://a.b:2443")
    }

    func testUnusableWithoutCredentials() throws {
        let s = try decode(#"{"server":"https://a.b","device_id":"","token":"t"}"#)
        XCTAssertFalse(s.isUsable)
    }

    func testDefaultsRoleToDevice() throws {
        let s = try decode(#"{"server":"https://a.b","device_id":"d","token":"t"}"#)
        XCTAssertEqual(s.role, .device)
    }
}

// MARK: - Peer AllowedIPs normalization

final class PeerEntryTests: XCTestCase {

    /// /v1/peers returns a bare address, /v1/hub/peers returns a CIDR.
    func testBareAddressGetsSlash32() {
        let p = PeerEntry(pubkey: "K", wgIP: "10.88.0.3")
        XCTAssertEqual(p.allowedIPs, ["10.88.0.3/32"])
    }

    func testExistingPrefixIsNotDoubled() {
        let p = PeerEntry(pubkey: "K", wgIP: "10.88.1.2/32")
        XCTAssertEqual(p.allowedIPs, ["10.88.1.2/32"])
    }

    func testAllowedExtraIsAppended() {
        let p = PeerEntry(pubkey: "K", wgIP: "10.88.0.1", allowedExtra: ["10.88.0.0/24"])
        XCTAssertEqual(p.allowedIPs, ["10.88.0.1/32", "10.88.0.0/24"])
    }
}

// MARK: - Conf parse / render / compare

final class WGConfTests: XCTestCase {

    private let sample = """
    [Interface]
    PrivateKey = qqoVKFw1R5l6vrD3Zy3YEYVyvqTXk+y5p5iSqoxRlUc=
    Address    = 10.88.0.14/24
    ListenPort = 51820

    [Peer]
    PublicKey  = UOQJgjBEzvSFRSjwIxEENgQbPjIP0+fKXqqSxJCyxTQ=
    Endpoint   = zen.4950.store:1632
    AllowedIPs = 10.88.0.1/32, 10.88.0.0/24
    PersistentKeepalive = 25

    """

    /// Base64 keys carry '=' padding; splitting on the last '=' corrupts them.
    func testSplitsOnFirstEqualsSoBase64PaddingSurvives() throws {
        let c = try XCTUnwrap(WGConfig.parse(sample))
        XCTAssertEqual(c.interface.privateKey, "qqoVKFw1R5l6vrD3Zy3YEYVyvqTXk+y5p5iSqoxRlUc=")
        XCTAssertEqual(c.peers.first?.publicKey, "UOQJgjBEzvSFRSjwIxEENgQbPjIP0+fKXqqSxJCyxTQ=")
    }

    func testParsesPeerFields() throws {
        let c = try XCTUnwrap(WGConfig.parse(sample))
        let p = try XCTUnwrap(c.peers.first)
        XCTAssertEqual(p.endpoint, "zen.4950.store:1632")
        XCTAssertEqual(p.allowedIPs, ["10.88.0.1/32", "10.88.0.0/24"])
        XCTAssertEqual(p.keepalive, 25)
    }

    func testRoundTripsThroughRender() throws {
        let c = try XCTUnwrap(WGConfig.parse(sample))
        let again = try XCTUnwrap(WGConfig.parse(c.render()))
        XCTAssertTrue(c.semanticallyEquals(again))
    }

    func testRefusesConfigWithoutPrivateKey() {
        XCTAssertNil(WGConfig.parse("[Interface]\nAddress = 10.88.0.1/24\n"))
    }

    /// Operator-added keys used to be silently dropped on every re-render.
    func testPreservesUnmanagedInterfaceKeys() throws {
        let text = sample.replacingOccurrences(
            of: "ListenPort = 51820",
            with: "ListenPort = 51820\nMTU = 1380\nTable = off")
        let c = try XCTUnwrap(WGConfig.parse(text))
        XCTAssertEqual(c.interface.extras.map(\.key), ["MTU", "Table"])
        XCTAssertTrue(c.render().contains("MTU = 1380"))
        XCTAssertTrue(c.render().contains("Table = off"))
    }

    /// The whole reason for semantic comparison: formatting must not read as a
    /// change, or the tunnel restarts once a minute forever.
    func testWhitespaceAndPaddingAreNotAChange() throws {
        let a = try XCTUnwrap(WGConfig.parse(sample))
        let reflowed = sample
            .replacingOccurrences(of: "Address    =", with: "Address =")
            .replacingOccurrences(of: "PublicKey  =", with: "PublicKey=")
        let b = try XCTUnwrap(WGConfig.parse(reflowed))
        XCTAssertTrue(a.semanticallyEquals(b))
    }

    func testPeerOrderIsNotAChange() throws {
        let iface = WGInterfaceSection(privateKey: "P", address: "10.88.0.1/24", listenPort: "1632")
        let p1 = WGPeerSection(publicKey: "AAA", allowedIPs: ["10.88.0.2/32"])
        let p2 = WGPeerSection(publicKey: "BBB", allowedIPs: ["10.88.0.3/32"])
        XCTAssertTrue(WGConfig(interface: iface, peers: [p1, p2])
            .semanticallyEquals(WGConfig(interface: iface, peers: [p2, p1])))
    }

    func testRenderIsDeterministicallySorted() {
        let iface = WGInterfaceSection(privateKey: "P", address: "10.88.0.1/24", listenPort: "1632")
        let p1 = WGPeerSection(publicKey: "ZZZ", allowedIPs: ["10.88.0.2/32"])
        let p2 = WGPeerSection(publicKey: "AAA", allowedIPs: ["10.88.0.3/32"])
        let out = WGConfig(interface: iface, peers: [p1, p2]).render()
        let zIdx = try! XCTUnwrap(out.range(of: "ZZZ")).lowerBound
        let aIdx = try! XCTUnwrap(out.range(of: "AAA")).lowerBound
        XCTAssertLessThan(aIdx, zIdx)
    }

    func testRealChangeIsDetected() throws {
        let a = try XCTUnwrap(WGConfig.parse(sample))
        var b = a
        b.peers[0].endpoint = "1.2.3.4:1632"
        XCTAssertFalse(a.semanticallyEquals(b))
    }

    func testRoutesDifferOnlyWhenAllowedIPsChange() throws {
        let a = try XCTUnwrap(WGConfig.parse(sample))
        var endpointOnly = a
        endpointOnly.peers[0].endpoint = "5.6.7.8:1632"
        XCTAssertFalse(a.routesDiffer(from: endpointOnly), "endpoint move must stay a syncconf")

        var routeChange = a
        routeChange.peers[0].allowedIPs.append("192.168.11.0/24")
        XCTAssertTrue(a.routesDiffer(from: routeChange), "new CIDR needs a full reload")
    }
}

// MARK: - Building from a control-plane response

final class WGConfigBuildTests: XCTestCase {

    private func response(_ json: String) throws -> PeersResponse {
        try JSONDecoder().decode(PeersResponse.self, from: Data(json.utf8))
    }

    private let existing = WGConfig(
        interface: WGInterfaceSection(privateKey: "PRIV", address: "10.88.0.14/24", listenPort: "51820"),
        peers: [])

    func testMergesPeersOntoLocalInterface() throws {
        let r = try response(#"""
        {"peers":[{"pubkey":"K1","wg_ip":"10.88.0.1","endpoint":"h:1632","allowed_extra":["10.88.0.0/24"]}],
         "keepalive_sec":25}
        """#)
        let c = try XCTUnwrap(WGConfig.build(existing: existing, response: r, fallbackListenPort: 1632))
        XCTAssertEqual(c.interface.privateKey, "PRIV")
        XCTAssertEqual(c.peers.count, 1)
        XCTAssertEqual(c.peers[0].allowedIPs, ["10.88.0.1/32", "10.88.0.0/24"])
        XCTAssertEqual(c.peers[0].keepalive, 25)
    }

    /// Never install a conf with no private key and then restart into it.
    func testRefusesToBuildWithoutExistingInterface() throws {
        let r = try response(#"{"peers":[{"pubkey":"K1","wg_ip":"10.88.0.1"}]}"#)
        XCTAssertNil(WGConfig.build(existing: nil, response: r, fallbackListenPort: 1632))
    }

    func testSkipsPeersWithNoUsableAllowedIPs() throws {
        let r = try response(#"{"peers":[{"pubkey":"K1"},{"pubkey":"","wg_ip":"10.88.0.2"}]}"#)
        let c = try XCTUnwrap(WGConfig.build(existing: existing, response: r, fallbackListenPort: 1632))
        XCTAssertTrue(c.peers.isEmpty)
    }

    /// A /32 here silently breaks routing even with a healthy handshake.
    func testFallbackAddressUsesMeshPrefixNotSlash32() throws {
        let bare = WGConfig(
            interface: WGInterfaceSection(privateKey: "PRIV", address: "", listenPort: ""),
            peers: [])
        let r = try response(#"{"device_ip":"10.88.0.14","peers":[]}"#)
        let c = try XCTUnwrap(WGConfig.build(existing: bare, response: r, fallbackListenPort: 1632))
        XCTAssertEqual(c.interface.address, "10.88.0.14/24")
        XCTAssertEqual(c.interface.listenPort, "1632")
    }

    func testNotModifiedDecodes() throws {
        let r = try response(#"{"not_modified":true}"#)
        XCTAssertTrue(r.notModified)
        XCTAssertTrue(r.peers.isEmpty)
    }
}

// MARK: - Long-poll degradation guarantees

final class LongPollPlannerTests: XCTestCase {

    private func planner(_ now: Int = 0) -> LongPollPlanner {
        LongPollPlanner(config: .init(budget: 55, wait: 45, minReturn: 5, floor: 10), startTime: now)
    }

    /// The probe must not ask the server to hold: we don't yet know it can.
    func testProbeFetchesWithoutWait() {
        var p = planner()
        XCTAssertEqual(p.next(now: 0), .fetch(wait: 0))
    }

    /// Guarantee 1 — a server with no `rev` gets exactly one fetch per run.
    func testLegacyServerStopsAfterOneFetch() {
        var p = planner()
        XCTAssertEqual(p.next(now: 0), .fetch(wait: 0))
        p.record(outcome: .unchanged, elapsed: 0, rev: nil, now: 1)
        XCTAssertEqual(p.next(now: 1), .stop(.noRevSupport))
    }

    /// Guarantee 2 — has `rev` but returns instantly ⇒ it ignores ?wait.
    func testServerIgnoringWaitFallsBackToSingleFetch() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 1)
        XCTAssertEqual(p.next(now: 1), .fetch(wait: 45))      // trial
        p.record(outcome: .unchanged, elapsed: 1, rev: "r1", now: 2)
        XCTAssertEqual(p.next(now: 2), .stop(.waitIgnored(elapsed: 1)))
    }

    /// Guarantee 3 — a real long-poll keeps going until the budget runs out.
    func testConfirmedLongPollLoopsUntilBudget() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 1)
        _ = p.next(now: 1)
        p.record(outcome: .notModified, elapsed: 45, rev: "r1", now: 46)
        // 9 s left: still fetches, but only asks for what remains.
        XCTAssertEqual(p.next(now: 46), .fetch(wait: 9))
        p.record(outcome: .notModified, elapsed: 9, rev: "r1", now: 55)
        XCTAssertEqual(p.next(now: 55), .stop(.budgetExhausted))
    }

    /// Guarantee 4 — a misbehaving instant-return server must not hot-loop.
    func testInstantUnchangedInLongPollSleepsFloor() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 1)
        _ = p.next(now: 1)
        p.record(outcome: .notModified, elapsed: 5, rev: "r1", now: 6)
        _ = p.next(now: 6)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 7)
        XCTAssertEqual(p.next(now: 7), .sleep(seconds: 10))
        XCTAssertEqual(p.next(now: 17), .fetch(wait: 38))
    }

    func testInstantUnchangedNearDeadlineStopsInsteadOfSleeping() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 1)
        _ = p.next(now: 1)
        p.record(outcome: .notModified, elapsed: 44, rev: "r1", now: 45)
        _ = p.next(now: 45)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 50)  // 5s left < floor
        XCTAssertEqual(p.next(now: 50), .stop(.budgetExhausted))
    }

    /// Guarantee 5 — never hammer a server that just failed.
    func testErrorStopsImmediately() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .error, elapsed: 1, rev: nil, now: 1)
        XCTAssertEqual(p.next(now: 1), .stop(.transportError))
    }

    /// An applied change still long-polls; it must not be treated as a stop.
    func testAppliedInLongPollContinues() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "r1", now: 1)
        _ = p.next(now: 1)
        p.record(outcome: .notModified, elapsed: 10, rev: "r1", now: 11)
        _ = p.next(now: 11)
        p.record(outcome: .applied, elapsed: 1, rev: "r2", now: 12)
        XCTAssertEqual(p.next(now: 12), .fetch(wait: 43))
        XCTAssertEqual(p.rev, "r2")
    }

    func testRevIsTrackedAndSanitized() {
        var p = planner()
        _ = p.next(now: 0)
        p.record(outcome: .unchanged, elapsed: 0, rev: "abc/123 x", now: 1)
        XCTAssertEqual(p.rev, "abc/123 x")
        XCTAssertEqual(LongPollPlanner.sanitize(rev: "abc/123 x"), "abc-123-x")
    }

    func testExhaustedBudgetStopsBeforeAnyFetch() {
        var p = planner()
        XCTAssertEqual(p.next(now: 55), .stop(.budgetExhausted))
    }
}

// MARK: - Status dump parsing

final class WGCoreDumpTests: XCTestCase {

    /// Captured verbatim from a live wg_core on the iPhone (2026-07-26).
    private let realDump = """
    interface: utun0
      logical: wgc0
      peers: 1

    peer #0: UOQJgjBEzvSFRSjwIxEENgQbPjIP0+fKXqqSxJCyxTQ=
      endpoint: 58.37.118.81:1632
      allowed ips: 10.88.0.1/32, 10.88.0.0/24
      latest handshake: 2 minutes, 9 seconds ago
      transfer: 168 B received, 168 B sent
      packets: rx=2 tx=2  rx_dropped_aips=0
      persistent keepalive: every 25 seconds
      handshake state: idle

    """

    /// The regression that made every macOS host report zeroes: wg_core prints
    /// `peer #0:` while the old parser only matched `peer:`.
    func testParsesRealWGCoreDump() throws {
        let r = WGDump.parseCoreText(realDump)
        XCTAssertEqual(r.interfaceName, "utun0")
        XCTAssertEqual(r.logicalName, "wgc0")
        XCTAssertTrue(r.isRunning)
        XCTAssertEqual(r.peers.count, 1)

        let p = try XCTUnwrap(r.peers.first)
        XCTAssertEqual(p.pubkey, "UOQJgjBEzvSFRSjwIxEENgQbPjIP0+fKXqqSxJCyxTQ=")
        XCTAssertEqual(p.endpoint, "58.37.118.81:1632")
        XCTAssertEqual(p.allowedIPs, ["10.88.0.1/32", "10.88.0.0/24"])
        XCTAssertEqual(p.lastHandshakeSec, 129)
        XCTAssertEqual(p.rxBytes, 168)
        XCTAssertEqual(p.txBytes, 168)
        XCTAssertTrue(p.isOnline)
    }

    func testRealDumpProducesNonZeroStats() {
        let s = WGDump.parseCoreText(realDump).peers.aggregate()
        XCTAssertEqual(s, WGStats(rxBytes: 168, txBytes: 168, lastHandshakeSec: 129))
    }

    /// `peers: 1` must not be mistaken for a peer header.
    func testPeerCountLineIsNotAPeer() {
        XCTAssertEqual(WGDump.parseCoreText("interface: utun0\n  peers: 0\n").peers.count, 0)
    }

    /// Upstream wireguard-tools spells it without the index.
    func testAcceptsUpstreamPeerSpelling() {
        let r = WGDump.parseCoreText("interface: wg0\npeer: ABC=\n  transfer: 1.00 KiB received, 0 B sent\n")
        XCTAssertEqual(r.peers.first?.pubkey, "ABC=")
        XCTAssertEqual(r.peers.first?.rxBytes, 1024)
    }

    func testNeverHandshakenPeerHasNilAge() {
        let r = WGDump.parseCoreText("interface: utun0\npeer #0: K=\n  latest handshake: never\n")
        XCTAssertNil(r.peers.first?.lastHandshakeSec)
        XCTAssertFalse(r.peers[0].isOnline)
    }

    func testHandlesMissingKeepaliveAndNoneValues() {
        let r = WGDump.parseCoreText("""
        interface: utun0
        peer #0: K=
          endpoint: (none)
          allowed ips: (none)
          latest handshake: never
          transfer: 0 B received, 0 B sent
          handshake state: pending (attempt 3, sent 12s ago)
        """)
        let p = r.peers[0]
        XCTAssertNil(p.endpoint)
        XCTAssertTrue(p.allowedIPs.isEmpty)
        XCTAssertEqual(p.rxBytes, 0)
    }

    /// `wgctl show` synthesizes these lines; they never come off the socket.
    func testDetectsNotRunningInterface() {
        let r = WGDump.parseCoreText("interface: wgc0  (not running)\n")
        XCTAssertFalse(r.isRunning)
        XCTAssertTrue(r.peers.isEmpty)
    }

    func testDetectsStalePidFile() {
        XCTAssertFalse(WGDump.parseCoreText("interface: wgc0  (stale pid file: 42)\n").isRunning)
    }

    func testMultiplePeersAreAllCaptured() {
        let r = WGDump.parseCoreText("""
        interface: utun3
          logical: wgc0
          peers: 2

        peer #0: AAA=
          transfer: 1.00 KiB received, 2.00 KiB sent
          latest handshake: 10 seconds ago

        peer #1: BBB=
          transfer: 1.00 MiB received, 0 B sent
          latest handshake: 3 hours, 4 minutes ago

        """)
        XCTAssertEqual(r.peers.map(\.pubkey), ["AAA=", "BBB="])
        XCTAssertEqual(r.peers[1].rxBytes, 1024 * 1024)
        XCTAssertEqual(r.peers[1].lastHandshakeSec, 3 * 3600 + 4 * 60)
        XCTAssertEqual(r.peers.aggregate().lastHandshakeSec, 10, "aggregate takes the freshest")
    }

    // Unit scanners

    func testByteUnits() {
        XCTAssertEqual(WGDump.parseBytes("0 B"), 0)
        XCTAssertEqual(WGDump.parseBytes("912 B"), 912)
        XCTAssertEqual(WGDump.parseBytes("1.42 KiB"), 1454)
        XCTAssertEqual(WGDump.parseBytes("2.00 MiB"), 2 * 1024 * 1024)
        XCTAssertEqual(WGDump.parseBytes("1.00 GiB"), 1024 * 1024 * 1024)
        XCTAssertEqual(WGDump.parseBytes("garbage"), 0)
    }

    func testAgeShapes() {
        XCTAssertNil(WGDump.parseAge("never"))
        XCTAssertEqual(WGDump.parseAge("0 seconds ago"), 0)
        XCTAssertEqual(WGDump.parseAge("9 seconds ago"), 9)
        XCTAssertEqual(WGDump.parseAge("2 minutes, 9 seconds ago"), 129)
        XCTAssertEqual(WGDump.parseAge("3 hours, 4 minutes ago"), 11040)
        XCTAssertEqual(WGDump.parseAge("1 day, 1 hour ago"), 90000, "singular must parse too")
    }
}

final class WGShowDumpTests: XCTestCase {

    /// TAB-separated; line 0 is the interface, not a peer.
    private let dump = [
        "PRIVKEY\tIFPUB\t1632\toff",
        "AAA=\t(none)\t1.2.3.4:1632\t10.88.0.1/32,10.88.0.0/24\t1700000000\t9000\t8000\t25",
        "BBB=\t(none)\t(none)\t(none)\t0\t0\t0\toff",
    ].joined(separator: "\n")

    func testSkipsInterfaceLineAndParsesPeers() throws {
        let r = WGDump.parseWGDump(dump, now: 1700000011)
        XCTAssertEqual(r.peers.count, 2)

        let a = try XCTUnwrap(r.peers.first)
        XCTAssertEqual(a.pubkey, "AAA=")
        XCTAssertEqual(a.endpoint, "1.2.3.4:1632")
        XCTAssertEqual(a.allowedIPs, ["10.88.0.1/32", "10.88.0.0/24"])
        XCTAssertEqual(a.lastHandshakeSec, 11, "epoch must be converted to an age")
        XCTAssertEqual(a.rxBytes, 9000)
        XCTAssertEqual(a.txBytes, 8000)
        XCTAssertTrue(a.isOnline)
    }

    func testZeroTimestampMeansNeverHandshaken() {
        let r = WGDump.parseWGDump(dump, now: 1700000011)
        XCTAssertNil(r.peers[1].lastHandshakeSec)
        XCTAssertNil(r.peers[1].endpoint)
        XCTAssertTrue(r.peers[1].allowedIPs.isEmpty)
        XCTAssertFalse(r.peers[1].isOnline)
    }

    func testEmptyDumpMeansNotRunning() {
        let r = WGDump.parseWGDump("", now: 0)
        XCTAssertFalse(r.isRunning)
        XCTAssertTrue(r.peers.isEmpty)
    }

    func testShortLinesAreIgnored() {
        let r = WGDump.parseWGDump("IF\tPUB\t1632\toff\nBROKEN\tROW\n", now: 0)
        XCTAssertTrue(r.peers.isEmpty)
    }
}

// MARK: - Endpoint parsing

final class EndpointTests: XCTestCase {

    func testParsesHostPort() throws {
        let e = try XCTUnwrap(Endpoint("zen.4950.store:1632"))
        XCTAssertEqual(e.host, "zen.4950.store")
        XCTAssertEqual(e.port, 1632)
        XCTAssertFalse(e.isLiteralAddress)
    }

    func testParsesIPv4Literal() throws {
        let e = try XCTUnwrap(Endpoint("58.37.118.81:1632"))
        XCTAssertEqual(e.host, "58.37.118.81")
        XCTAssertTrue(e.isLiteralAddress, "a literal has nothing to re-resolve")
    }

    func testParsesBracketedIPv6() throws {
        let e = try XCTUnwrap(Endpoint("[fd00::1]:1632"))
        XCTAssertEqual(e.host, "fd00::1")
        XCTAssertEqual(e.port, 1632)
        XCTAssertTrue(e.isLiteralAddress)
    }

    func testRejectsEmpty() {
        XCTAssertNil(Endpoint(""))
        XCTAssertNil(Endpoint("   "))
    }

    func testHostnameThatLooksNumericIsStillAHostname() {
        XCTAssertFalse(Endpoint("999.999.999.999:1")!.isLiteralAddress)
        XCTAssertFalse(Endpoint("1.2.3:1")!.isLiteralAddress)
    }
}

// MARK: - Endpoint drift detection

final class EndpointWatchTests: XCTestCase {

    private let cfg = EndpointWatch.Config(cooldownSec: 300, stalenessSec: 180)

    private func evaluate(configured: String? = "zen.4950.store:1632",
                          inUse: String? = "58.37.118.81:1632",
                          resolved: [String] = ["58.37.118.81"],
                          age: Int? = 30,
                          sinceRedial: Int? = nil) -> EndpointWatch.Verdict {
        EndpointWatch.evaluate(configured: configured, inUse: inUse, resolved: resolved,
                               handshakeAgeSec: age, secondsSinceLastRedial: sinceRedial,
                               config: cfg)
    }

    func testAgreementIsHealthy() {
        XCTAssertEqual(evaluate(), .healthy)
        XCTAssertFalse(evaluate().requiresRedial)
    }

    /// The headline case: the modem got a new IP, DNS followed, the data plane
    /// did not.
    func testDetectsEndpointDrift() {
        let v = evaluate(inUse: "58.37.118.151:1632", resolved: ["58.37.118.81"])
        XCTAssertEqual(v, .endpointDrifted(inUse: "58.37.118.151", resolved: ["58.37.118.81"]))
        XCTAssertTrue(v.requiresRedial)
    }

    /// Drift is actionable even while the handshake still looks recent — the
    /// keypair age lags the outage.
    func testDriftWinsOverAFreshLookingHandshake() {
        XCTAssertTrue(evaluate(inUse: "1.2.3.4:1632", resolved: ["58.37.118.81"], age: 1)
            .requiresRedial)
    }

    /// A DNS blip must never be read as drift.
    func testFailedLookupIsNotDrift() {
        XCTAssertEqual(evaluate(resolved: []), .healthy)
    }

    func testMultipleARecordsAreAllAcceptable() {
        XCTAssertEqual(evaluate(inUse: "1.2.3.4:1632", resolved: ["9.9.9.9", "1.2.3.4"]), .healthy)
    }

    /// A literal endpoint can't drift; only staleness applies.
    func testLiteralEndpointIsNeverDrift() {
        XCTAssertEqual(evaluate(configured: "1.2.3.4:1632", inUse: "5.6.7.8:1632",
                                resolved: ["1.2.3.4"]), .healthy)
    }

    func testStaleHandshakeTriggersRedial() {
        XCTAssertEqual(evaluate(age: 181), .handshakeStale(ageSec: 181))
        XCTAssertEqual(evaluate(age: 180), .healthy, "boundary is exclusive")
    }

    func testNeverHandshakenWithAnEndpointIsStale() {
        XCTAssertEqual(evaluate(age: nil), .handshakeStale(ageSec: nil))
    }

    /// With no endpoint at all there is nothing a re-dial would fix.
    func testNeverHandshakenWithoutEndpointIsIndeterminate() {
        let v = evaluate(inUse: nil, age: nil)
        XCTAssertFalse(v.requiresRedial)
        if case .indeterminate = v {} else { XCTFail("expected indeterminate, got \(v)") }
    }

    /// Re-dialling every tick would turn one outage into a permanent flap.
    func testCooldownSuppressesRepeatRedial() {
        let v = evaluate(inUse: "9.9.9.9:1632", resolved: ["58.37.118.81"], sinceRedial: 60)
        XCTAssertEqual(v, .cooling(secondsRemaining: 240))
        XCTAssertFalse(v.requiresRedial)
    }

    func testCooldownExpiryAllowsAnotherRedial() {
        XCTAssertTrue(evaluate(inUse: "9.9.9.9:1632", resolved: ["58.37.118.81"], sinceRedial: 300)
            .requiresRedial)
    }

    /// A healthy tunnel is never suppressed by the cooldown.
    func testCooldownDoesNotMaskHealth() {
        XCTAssertEqual(evaluate(sinceRedial: 5), .healthy)
    }

    func testLogReasonNamesTheCause() {
        let v = evaluate(inUse: "58.37.118.151:1632", resolved: ["58.37.118.81"])
        XCTAssertTrue(v.logReason.contains("58.37.118.151"))
        XCTAssertTrue(v.logReason.contains("58.37.118.81"))
    }
}

// MARK: - Public egress IP cache policy

final class PublicIPCacheTests: XCTestCase {

    private let cfg = PublicIPCache.Config(ttlSec: 900, retrySec: 120)

    func testFreshEntryIsServedWithoutARequest() {
        let e = PublicIPCache.Entry(stamp: 1000, ip: "119.54.154.116")
        XCTAssertEqual(PublicIPCache.decide(entry: e, now: 1899, config: cfg),
                       .useCached("119.54.154.116"))
    }

    func testExpiredEntryTriggersAProbeButRemembersThePrevious() {
        let e = PublicIPCache.Entry(stamp: 1000, ip: "119.54.154.116")
        XCTAssertEqual(PublicIPCache.decide(entry: e, now: 1900, config: cfg),
                       .probe(previous: "119.54.154.116"))
    }

    func testNoEntryProbes() {
        XCTAssertEqual(PublicIPCache.decide(entry: nil, now: 5, config: cfg),
                       .probe(previous: nil))
    }

    func testEntryWithEmptyIPProbes() {
        let e = PublicIPCache.Entry(stamp: 999999, ip: "")
        XCTAssertEqual(PublicIPCache.decide(entry: e, now: 999999, config: cfg),
                       .probe(previous: nil))
    }

    func testSuccessfulProbeIsStoredAndReported() {
        let r = PublicIPCache.resolve(fetched: "1.2.3.4", previous: nil, now: 500, config: cfg)
        XCTAssertEqual(r.entry, PublicIPCache.Entry(stamp: 500, ip: "1.2.3.4"))
        XCTAssertEqual(r.reported, "1.2.3.4")
        XCTAssertNil(r.changedFrom)
    }

    func testChangeIsSurfacedForTheLog() {
        let r = PublicIPCache.resolve(fetched: "5.6.7.8", previous: "1.2.3.4", now: 500, config: cfg)
        XCTAssertEqual(r.changedFrom, "1.2.3.4")
        XCTAssertEqual(r.reported, "5.6.7.8")
    }

    func testUnchangedAddressIsNotReportedAsAChange() {
        let r = PublicIPCache.resolve(fetched: "1.2.3.4", previous: "1.2.3.4", now: 500, config: cfg)
        XCTAssertNil(r.changedFrom)
    }

    /// Stale beats nothing — a blip must not blank out a known-good endpoint.
    func testTotalFailureKeepsServingThePreviousAddress() {
        let r = PublicIPCache.resolve(fetched: nil, previous: "1.2.3.4", now: 5000, config: cfg)
        XCTAssertEqual(r.reported, "1.2.3.4")
        XCTAssertEqual(r.entry.ip, "1.2.3.4")
    }

    /// …but retry in 120 s, not in a full TTL.
    func testFailureBackdatesTheStampToShortenTheRetry() {
        let r = PublicIPCache.resolve(fetched: nil, previous: "1.2.3.4", now: 5000, config: cfg)
        XCTAssertEqual(r.entry.stamp, 5000 - 900 + 120)
        XCTAssertEqual(PublicIPCache.decide(entry: r.entry, now: 5000 + 120, config: cfg),
                       .probe(previous: "1.2.3.4"))
        XCTAssertEqual(PublicIPCache.decide(entry: r.entry, now: 5000 + 119, config: cfg),
                       .useCached("1.2.3.4"))
    }

    func testGarbageResponseIsTreatedAsFailure() {
        let r = PublicIPCache.resolve(fetched: "<html>rate limited</html>", previous: "1.2.3.4",
                                      now: 5000, config: cfg)
        XCTAssertEqual(r.reported, "1.2.3.4")
    }

    func testIPv4Validation() {
        XCTAssertTrue(PublicIPCache.isIPv4("119.54.154.116"))
        XCTAssertTrue(PublicIPCache.isIPv4("0.0.0.0"))
        XCTAssertFalse(PublicIPCache.isIPv4("256.1.1.1"))
        XCTAssertFalse(PublicIPCache.isIPv4("1.2.3"))
        XCTAssertFalse(PublicIPCache.isIPv4("1.2.3.4.5"))
        XCTAssertFalse(PublicIPCache.isIPv4("fd00::1"))
        XCTAssertFalse(PublicIPCache.isIPv4(""))
        XCTAssertFalse(PublicIPCache.isIPv4("1.2.3.x"))
    }

    // On-disk format is shared with the shell agent during migration.

    func testEntryRoundTrip() throws {
        let e = try XCTUnwrap(PublicIPCache.Entry(serialized: "1785000000 119.54.154.116"))
        XCTAssertEqual(e.stamp, 1785000000)
        XCTAssertEqual(e.ip, "119.54.154.116")
        XCTAssertEqual(e.serialized, "1785000000 119.54.154.116\n")
    }

    func testEntryToleratesAMissingAddress() throws {
        let e = try XCTUnwrap(PublicIPCache.Entry(serialized: "1785000000"))
        XCTAssertEqual(e.ip, "")
    }

    func testEntryRejectsGarbage() {
        XCTAssertNil(PublicIPCache.Entry(serialized: "not-a-stamp 1.2.3.4"))
        XCTAssertNil(PublicIPCache.Entry(serialized: ""))
    }

    /// Empty is load-bearing: the server keeps its stored endpoint when this
    /// field is blank, so a failed lookup must not send ":51820".
    func testEndpointIsBlankWhenTheAddressIsUnknown() {
        XCTAssertEqual(PublicIPCache.wgEndpoint(ip: nil, listenPort: 51820), "")
        XCTAssertEqual(PublicIPCache.wgEndpoint(ip: "", listenPort: 51820), "")
        XCTAssertEqual(PublicIPCache.wgEndpoint(ip: "1.2.3.4", listenPort: 51820), "1.2.3.4:51820")
    }
}

// MARK: - Heartbeat aggregation

final class HeartbeatTests: XCTestCase {

    func testAggregateSumsTrafficAndTakesFreshestHandshake() {
        let peers = [
            PeerStatus(pubkey: "A", lastHandshakeSec: 120, rxBytes: 100, txBytes: 10),
            PeerStatus(pubkey: "B", lastHandshakeSec: 11, rxBytes: 50, txBytes: 5),
            PeerStatus(pubkey: "C", lastHandshakeSec: nil),
        ]
        let s = peers.aggregate()
        XCTAssertEqual(s.rxBytes, 150)
        XCTAssertEqual(s.txBytes, 15)
        XCTAssertEqual(s.lastHandshakeSec, 11)
    }

    func testAggregateOfNoPeersIsZero() {
        XCTAssertEqual([PeerStatus]().aggregate(), WGStats(rxBytes: 0, txBytes: 0, lastHandshakeSec: 0))
    }

    func testOnlineWindow() {
        XCTAssertTrue(PeerStatus(pubkey: "A", lastHandshakeSec: 179).isOnline)
        XCTAssertFalse(PeerStatus(pubkey: "A", lastHandshakeSec: 180).isOnline)
        XCTAssertFalse(PeerStatus(pubkey: "A", lastHandshakeSec: nil).isOnline)
    }

    /// Only the three fields the control plane actually decodes.
    func testHeartbeatEncodesOnlyConsumedFields() throws {
        let body = HeartbeatBody(
            lanAddrs: [LanAddr(iface: "en0", cidr: "192.168.0.110/24")],
            wgEndpoint: "119.54.154.116:51820",
            stats: WGStats(rxBytes: 168, txBytes: 168, lastHandshakeSec: 29))
        let data = try JSONEncoder().encode(body)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(obj.keys), ["lan_addrs", "wg_endpoint", "stats"])
    }

    /// Empty is load-bearing: the server keeps the last known endpoint when
    /// this field is blank, so a failed lookup must not send junk.
    func testEmptyEndpointSurvivesEncoding() throws {
        let body = HeartbeatBody(lanAddrs: [], wgEndpoint: "",
                                 stats: WGStats(rxBytes: 0, txBytes: 0, lastHandshakeSec: 0))
        let data = try JSONEncoder().encode(body)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["wg_endpoint"] as? String, "")
    }
}
