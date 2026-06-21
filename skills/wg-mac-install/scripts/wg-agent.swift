// wg-agent (Swift) — native reconciler for wg-mac memberships. FreeBSD + Linux.
//
// Swift port of skills/wg-mac-install/scripts/wg-agent.sh, with no shell/python
// dependency: HTTP via URLSession, JSON via Foundation, and the wireguard tools
// invoked by absolute path. Per /etc/wgctl/<iface>.json it:
//   1. POST /v1/heartbeat   (v2 status block from `wg show <iface> dump`)
//   2. on 401 invalid-token → self-evict THIS iface (wg-quick down + cleanup)
//   3. GET /v1/peers (or /v1/hub/peers for role=hub)
//   4. re-render the wg-quick conf; if it changed, sync (peers) or reload (routes)
//
// Cross-platform (wg-quick / wireguard-tools on FreeBSD + Linux; no systemd reqd).
// Build:
//   FreeBSD:  . ~/swift632-env.sh && swiftc -O wg-agent.swift -o wg-agent
//   Linux:    swiftc -O -static-stdlib wg-agent.swift -o wg-agent
//             (CI builds the Linux amd64 binary — see .github/workflows/wg-agent-linux.yml)
// Run as root, e.g. from cron or an rc.d/systemd unit every 60s.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Glibc)
import Glibc   // getuid / setenv / getenv on Linux
#endif

// ── paths ───────────────────────────────────────────────────────────────────
func toolPath(_ candidates: [String]) -> String {
    for c in candidates where FileManager.default.fileExists(atPath: c) { return c }
    return candidates.first ?? ""
}

#if os(Linux)
let CONFDIR = "/etc/wireguard"
let OS_NAME = "linux"
#else
let CONFDIR = "/usr/local/etc/wireguard"   // FreeBSD (and other BSD)
let OS_NAME = "freebsd"
#endif
let STATE_DIR = "/etc/wgctl"
let RUNDIR    = "/var/run/wireguard"
let LOG_PATH  = "/var/log/wg-agent.log"
let AGENT_VER = "wg-agent-swift-1"

// resolve per-platform install locations (FreeBSD /usr/local/bin, Linux /usr/bin)
let WG       = toolPath(["/usr/bin/wg", "/usr/local/bin/wg"])
let WGQUICK  = toolPath(["/usr/bin/wg-quick", "/usr/local/bin/wg-quick"])
let IP       = toolPath(["/usr/sbin/ip", "/sbin/ip", "/bin/ip"])   // Linux lan_addrs
let IFCONFIG = toolPath(["/sbin/ifconfig", "/usr/sbin/ifconfig"])  // FreeBSD lan_addrs
let SYSCTL   = toolPath(["/sbin/sysctl", "/usr/sbin/sysctl"])
let UNAME    = toolPath(["/usr/bin/uname", "/bin/uname"])
let CURL     = toolPath(["/usr/bin/curl", "/usr/local/bin/curl"])

// hub-role egress NAT (packet filter): masquerade this whole mesh supernet out the
// uplink when the platform opens egress here. Source is the broad CGNAT supernet,
// NOT the advertised CIDRs — the kernel routes only what an opted-in spoke pushes.
let MESH_SUPERNET = ProcessInfo.processInfo.environment["WGCTL_MESH_SUPERNET"] ?? "100.64.0.0/10"
let IPTABLES = toolPath(["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"])  // Linux
let PFCTL    = toolPath(["/sbin/pfctl"])                                                 // FreeBSD pf
let ROUTE    = toolPath(["/sbin/route"])                                                 // default-route iface

// ── helpers ─────────────────────────────────────────────────────────────────
func logLine(_ s: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    let line = "\(ts) \(s)\n"
    if let fh = FileHandle(forWritingAtPath: LOG_PATH) {
        fh.seekToEndOfFile(); fh.write(line.data(using: .utf8)!); try? fh.close()
    } else {
        try? line.data(using: .utf8)!.write(to: URL(fileURLWithPath: LOG_PATH))
    }
}

@discardableResult
func run(_ path: String, _ args: [String]) -> (code: Int32, out: String) {
    // posix_spawn + waitpid (a real blocking syscall: the thread SLEEPS, 0% CPU)
    // instead of Foundation.Process, whose Pipe/dispatch I/O busy-polls to ~100%
    // CPU on FreeBSD while a slow child runs (curl on a timeout pegged the box).
    // Capture output by briefly pointing our own fd 1/2 at a temp file — avoids
    // posix_spawn_file_actions_t, whose type differs Linux↔FreeBSD.
    let outPath = "\(RUNDIR)/.run.\(getpid()).out"
    var argv: [UnsafeMutablePointer<CChar>?] = ([path] + args).map { strdup($0) }
    argv.append(nil)
    defer { for p in argv { free(p) } }
    let saved1 = dup(1), saved2 = dup(2)
    let fd = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
    if fd >= 0 { dup2(fd, 1); dup2(fd, 2); close(fd) }
    var pid: pid_t = 0
    let spawnRC = posix_spawn(&pid, path, nil, nil, argv, environ)
    if saved1 >= 0 { dup2(saved1, 1); close(saved1) }
    if saved2 >= 0 { dup2(saved2, 2); close(saved2) }
    if spawnRC != 0 { try? FileManager.default.removeItem(atPath: outPath); return (-1, "") }
    var status: Int32 = 0
    while waitpid(pid, &status, 0) < 0 && errno == EINTR { }
    let out = (try? String(contentsOfFile: outPath, encoding: .utf8)) ?? ""
    try? FileManager.default.removeItem(atPath: outPath)
    let code: Int32 = (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
    return (code, out)
}

// Synchronous HTTP via curl (NOT URLSession). FoundationNetworking's event loop
// busy-spins to ~200% CPU on FreeBSD/Linux when a request to an unreachable
// control plane hangs — that pegged dpaa2 and starved its sshd. curl uses a
// proper poll and returns cleanly on --max-time. curl is a binary, not a shell
// (still "脱离 sh"). --noproxy bypasses any (dead) proxy; the CP cert is a real
// Let's Encrypt one so curl's default CA verification passes (no -k needed).
func http(_ urlStr: String, method: String = "GET", token: String, deviceID: String,
          body: Data? = nil, timeout: TimeInterval = 10) -> (code: Int, body: Data?) {
    var args = ["-sS", "--noproxy", "*", "--max-time", "\(Int(timeout))",
                "-w", "\n%{http_code}",
                "-H", "Authorization: Bearer \(token)",
                "-H", "X-Device-Id: \(deviceID)"]
    if method != "GET" { args += ["-X", method] }
    var bodyTmp: String? = nil
    if let body = body {
        let tmp = "\(RUNDIR)/.http-body.\(getpid())"
        if (try? body.write(to: URL(fileURLWithPath: tmp))) != nil {
            bodyTmp = tmp
            args += ["-H", "Content-Type: application/json", "--data-binary", "@\(tmp)"]
        }
    }
    args.append(urlStr)
    let (rc, out) = run(CURL, args)
    if let tmp = bodyTmp { try? FileManager.default.removeItem(atPath: tmp) }
    // curl appends "\n<http_code>" after the body; split on the last newline.
    guard let nl = out.lastIndex(of: "\n") else {
        logLine("http \(method) \(urlStr) failed: curl rc=\(rc) (no response)")
        return (0, nil)
    }
    let code = Int(out[out.index(after: nl)...].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
    if code == 0 { logLine("http \(method) \(urlStr) failed: curl rc=\(rc)") }
    return (code, String(out[..<nl]).data(using: .utf8))
}

func uptimeSec() -> Int? {
#if os(Linux)
    // Linux: /proc/uptime → "12345.67 6789.01"
    if let s = try? String(contentsOfFile: "/proc/uptime", encoding: .utf8),
       let first = s.split(separator: " ").first, let secs = Double(first) {
        return Int(secs)
    }
    return nil
#else
    // FreeBSD: sysctl -n kern.boottime → "{ sec = N, usec = ... }"
    let (_, o) = run(SYSCTL, ["-n", "kern.boottime"])
    if let r = o.range(of: "sec = ") {
        let rest = o[r.upperBound...]
        let num = rest.prefix { $0.isNumber }
        if let boot = Int(num) { return max(0, Int(Date().timeIntervalSince1970) - boot) }
    }
    return nil
#endif
}

// ── membership state ────────────────────────────────────────────────────────
struct Membership: Codable {
    let server: String?
    let device_id: String?
    let token: String?
    let role: String?
    let wg_listen: Int?
}

struct PeerEntry: Codable {
    let pubkey: String?
    let wg_ip: String?
    let endpoint: String?
    let allowed_extra: [String]?
}
struct PeerResponse: Codable {
    let peers: [PeerEntry]?
    let device_ip: String?
    let keepalive_sec: Int?
    let rev: String?
    let not_modified: Bool?
    let advertised_routes: [String]?   // hub-only; non-empty == egress opened here
}

// ── lan_addrs + public-endpoint guess ────────────────────────────────────────
func lanAddrs() -> (lan: [[String: String]], pubIP: String) {
    var lan: [[String: String]] = []
#if os(Linux)
    // `ip -o -4 addr show` → "2: eth0    inet 10.0.0.5/24 brd ... scope global eth0"
    let (_, out) = run(IP, ["-o", "-4", "addr", "show"])
    for raw in out.split(separator: "\n") {
        let f = raw.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard f.count > 1, let ii = f.firstIndex(of: "inet"), ii + 1 < f.count else { continue }
        let cidr = f[ii + 1]                                   // X.X.X.X/bits
        let ip = cidr.split(separator: "/").first.map(String.init) ?? ""
        if ip.hasPrefix("127.") || ip.hasPrefix("169.254.") || ip.hasPrefix("10.88.") { continue }
        lan.append(["iface": f[1], "cidr": cidr])
    }
#else
    // FreeBSD ifconfig: "<iface>:" headers, "inet X netmask 0xFFFFFFFF ..."
    let (_, out) = run(IFCONFIG, [])
    var cur = ""
    for raw in out.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = String(raw)
        if let m = line.range(of: #"^[a-z][a-z0-9]+:"#, options: .regularExpression) {
            cur = String(line[m].dropLast()); continue
        }
        if let r = line.range(of: #"inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-fA-F]+)"#,
                              options: .regularExpression) {
            let seg = String(line[r])
            let parts = seg.split(separator: " ")
            guard parts.count >= 4 else { continue }
            let ip = String(parts[1])
            if ip.hasPrefix("127.") || ip.hasPrefix("169.254.") || ip.hasPrefix("10.88.") { continue }
            let hexMask = String(parts[3].dropFirst(2))
            let bits = (UInt32(hexMask, radix: 16) ?? 0).nonzeroBitCount
            lan.append(["iface": cur, "cidr": "\(ip)/\(bits)"])
        }
    }
#endif
    let pubIP = lan.first?["cidr"]?.split(separator: "/").first.map(String.init) ?? ""
    return (lan, pubIP)
}

// ── parse `wg show <iface> dump` into peer status ───────────────────────────
func peerStatus(iface: String) -> (peers: [[String: Any]], dumpNonEmpty: Bool) {
    let (_, dump) = run(WG, ["show", iface, "dump"])
    let now = Int(Date().timeIntervalSince1970)
    var peers: [[String: Any]] = []
    let lines = dump.split(separator: "\n", omittingEmptySubsequences: true)
    for (i, l) in lines.enumerated() {
        if i == 0 { continue }                         // interface line
        let f = l.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        if f.count < 8 { continue }
        let pub = f[0], ep = f[2], aips = f[3], lhsRaw = f[4], rx = f[5], tx = f[6]
        let lhs = Int(lhsRaw) ?? 0
        let age: Int? = lhs == 0 ? nil : max(0, now - lhs)
        var wgip: String? = nil
        if !aips.isEmpty, aips != "(none)" {
            wgip = aips.split(separator: ",").first?.trimmingCharacters(in: .whitespaces)
                       .split(separator: "/").first.map(String.init)
        }
        peers.append([
            "pubkey": pub,
            "wg_ip": wgip as Any,
            "endpoint": ep == "(none)" ? NSNull() : ep,
            "last_handshake_sec": age as Any,
            "rx_bytes": Int(rx) ?? 0,
            "tx_bytes": Int(tx) ?? 0,
            "online": (age != nil && age! < 180),
        ])
    }
    return (peers, !dump.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
}

func heartbeatBody(iface: String, role: String, wgListen: Int) -> Data? {
    let (peers, ifaceUp) = peerStatus(iface: iface)
    let ages = peers.compactMap { $0["last_handshake_sec"] as? Int }
    let stats: [String: Any] = [
        "rx_bytes": peers.reduce(0) { $0 + (($1["rx_bytes"] as? Int) ?? 0) },
        "tx_bytes": peers.reduce(0) { $0 + (($1["tx_bytes"] as? Int) ?? 0) },
        "last_handshake_sec": ages.min() ?? 0,
    ]
    let (lan, pubIP) = lanAddrs()
    let onlineCount = peers.filter { ($0["online"] as? Bool) == true }.count
    var status: [String: Any] = [
        "schema": 1, "role": role, "os": OS_NAME,
        "arch": run(UNAME, ["-m"]).out.trimmingCharacters(in: .whitespacesAndNewlines),
        "agent_ver": AGENT_VER, "iface": iface, "iface_up": ifaceUp,
        "wg_listen": wgListen, "peer_count": peers.count,
        "peers_online": onlineCount, "peers": peers,
    ]
    if let up = uptimeSec() { status["uptime_sec"] = up }
    let payload: [String: Any] = [
        "lan_addrs": lan,
        "wg_endpoint": pubIP.isEmpty ? "" : "\(pubIP):\(wgListen)",
        "stats": stats,
        "status": status,
    ]
    return try? JSONSerialization.data(withJSONObject: payload)
}

// ── render wg-quick conf from a peer response (preserving local [Interface]) ─
func renderConf(iface: String, resp: PeerResponse) -> String? {
    let confPath = "\(CONFDIR)/\(iface).conf"
    var priv = "", addr = "", listen = ""
    guard let existing = try? String(contentsOfFile: confPath, encoding: .utf8) else { return nil }
    for line in existing.split(separator: "\n") {
        let s = line.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("PrivateKey"), let v = s.split(separator: "=", maxSplits: 1).last { priv = v.trimmingCharacters(in: .whitespaces) }
        else if s.hasPrefix("Address"), let v = s.split(separator: "=", maxSplits: 1).last { addr = v.trimmingCharacters(in: .whitespaces) }
        else if s.hasPrefix("ListenPort"), let v = s.split(separator: "=", maxSplits: 1).last { listen = v.trimmingCharacters(in: .whitespaces) }
    }
    if priv.isEmpty { return nil }
    var lines = ["[Interface]", "PrivateKey = \(priv)",
                 "Address    = \(addr.isEmpty ? (resp.device_ip ?? "") + "/24" : addr)",
                 "ListenPort = \(listen.isEmpty ? "1632" : listen)", ""]
    let ka = resp.keepalive_sec ?? 25
    for p in (resp.peers ?? []).sorted(by: { ($0.pubkey ?? "") < ($1.pubkey ?? "") }) {
        guard let pk = p.pubkey, !pk.isEmpty else { continue }
        var aips: [String] = []
        if let w = p.wg_ip, !w.isEmpty { aips.append(w.contains("/") ? w : "\(w)/32") }
        aips.append(contentsOf: p.allowed_extra ?? [])
        if aips.isEmpty { continue }
        lines.append("[Peer]")
        lines.append("PublicKey  = \(pk)")
        if let ep = p.endpoint, !ep.isEmpty { lines.append("Endpoint   = \(ep)") }
        lines.append("AllowedIPs = \(aips.joined(separator: ", "))")
        if ka > 0 { lines.append("PersistentKeepalive = \(ka)") }
        lines.append("")
    }
    return lines.joined(separator: "\n")
}

func reloadIface(_ iface: String) {
    _ = run(WGQUICK, ["down", iface])
    _ = run(WGQUICK, ["up", iface])
}

// the set of AllowedIPs CIDRs across all peers — changing this set means the
// system routing table must change (full reload); peers/endpoints alone don't.
func allowedIPsSet(_ conf: String) -> Set<String> {
    var s = Set<String>()
    for line in conf.split(separator: "\n") {
        let t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("AllowedIPs"), let v = t.split(separator: "=", maxSplits: 1).last {
            for cidr in v.split(separator: ",") { s.insert(cidr.trimmingCharacters(in: .whitespaces)) }
        }
    }
    return s
}

// non-disruptive peer/endpoint update: wg syncconf reprograms the running
// interface without tearing it down (no tunnel drop, no route flap). wg-quick
// strip drops wg-quick-only keys (Address/DNS/PostUp) syncconf rejects.
func syncIface(_ iface: String) {
    let confPath = "\(CONFDIR)/\(iface).conf"
    let (sc, stripped) = run(WGQUICK, ["strip", confPath])
    if sc == 0, !stripped.isEmpty {
        let tmp = "\(RUNDIR)/\(iface).sync.conf"
        if (try? stripped.write(toFile: tmp, atomically: true, encoding: .utf8)) != nil {
            let (rc, _) = run(WG, ["syncconf", iface, tmp])
            try? FileManager.default.removeItem(atPath: tmp)
            if rc == 0 { return }
        }
    }
    logLine("[\(iface)] syncconf failed; full reload")
    reloadIface(iface)
}

// ── hub-role egress NAT / packet-filter control ─────────────────────────────
// Converge the masquerade rule to the desired state on every full hub poll
// (cheap + idempotent). enable == the /v1/hub/peers response advertised egress.
func applyEgressNAT(iface: String, enable: Bool) {
#if os(Linux)
    applyEgressNATLinux(iface: iface, enable: enable)
#else
    applyEgressNATFreeBSD(iface: iface, enable: enable)
#endif
}

// parse the egress/default-route interface name from a `<cmd>` output.
// Linux `ip route get 1.1.1.1` → "... dev eth0 ..."; FreeBSD `route -n get
// default` → a "interface: em0" line.
func egressInterface() -> String {
#if os(Linux)
    let (_, out) = run(IP, ["route", "get", "1.1.1.1"])
    let toks = out.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
    if let i = toks.firstIndex(of: "dev"), i + 1 < toks.count { return toks[i + 1] }
    return ""
#else
    let (_, out) = run(ROUTE, ["-n", "get", "default"])
    for line in out.split(separator: "\n") {
        let t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("interface:") {
            return t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
        }
    }
    return ""
#endif
}

#if os(Linux)
// Direct port of wg-agent.sh apply_egress_nat: iptables MASQUERADE, check-before-act.
func applyEgressNATLinux(iface: String, enable: Bool) {
    guard FileManager.default.fileExists(atPath: IPTABLES) else {
        if enable { logLine("[\(iface)] egress: iptables not found") }; return
    }
    let egif = egressInterface()
    guard !egif.isEmpty else {
        if enable { logLine("[\(iface)] egress: no default-route iface") }; return
    }
    let rule = ["-t", "nat", "POSTROUTING", "-s", MESH_SUPERNET, "-o", egif, "-j", "MASQUERADE"]
    let present = run(IPTABLES, ["-C"] + rule).code == 0
    if enable {
        // ip forwarding (only when enabling); /proc rejects atomic temp-rename
        let cur = (try? String(contentsOfFile: "/proc/sys/net/ipv4/ip_forward", encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if cur != "1" { try? "1\n".write(toFile: "/proc/sys/net/ipv4/ip_forward", atomically: false, encoding: .utf8) }
        if !present, run(IPTABLES, ["-A"] + rule).code == 0 {
            logLine("[\(iface)] egress NAT on: \(MESH_SUPERNET) -> \(egif)")
        }
    } else if present, run(IPTABLES, ["-D"] + rule).code == 0 {
        logLine("[\(iface)] egress NAT off")
    }
}
#else
// FreeBSD pf: the agent fully owns /etc/pf.conf on a hub. Write a minimal ruleset
// holding just the egress nat rule (no anchor needed — the rule is in the main
// ruleset directly), enable pf if disabled, persist via rc.conf. Idempotent:
// only reload when the file content changes.
func applyEgressNATFreeBSD(iface: String, enable: Bool) {
    guard FileManager.default.fileExists(atPath: PFCTL) else {
        if enable { logLine("[\(iface)] egress: pfctl not found") }; return
    }
    let pfConf = "/etc/pf.conf"
    let cur = (try? String(contentsOfFile: pfConf, encoding: .utf8)) ?? ""
    let marker = "# wg-agent egress NAT"
    if enable {
        let egif = egressInterface()
        guard !egif.isEmpty else { logLine("[\(iface)] egress: no default-route iface"); return }
        _ = run(SYSCTL, ["net.inet.ip.forwarding=1"])
        let desired = "\(marker)\nnat on \(egif) inet from \(MESH_SUPERNET) -> (\(egif))\n"
        if cur != desired {
            do {
                try desired.write(toFile: pfConf, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pfConf)
                let rc = run(PFCTL, ["-f", pfConf]).code
                if rc == 0 { logLine("[\(iface)] egress NAT on: \(MESH_SUPERNET) -> \(egif) (pf)") }
                else { logLine("[\(iface)] egress: pfctl -f failed rc=\(rc)") }
            } catch { logLine("[\(iface)] egress: write pf.conf failed: \(error)") }
        }
        // enable pf only if disabled — NEVER -E (ref-count leak over polls)
        if run(PFCTL, ["-s", "info"]).out.contains("Status: Disabled") { _ = run(PFCTL, ["-e"]) }
        // boot persistence (idempotent)
        _ = run("/usr/sbin/sysrc", ["pf_enable=YES", "gateway_enable=YES", "pf_rules=/etc/pf.conf"])
    } else if cur.contains(marker) {
        // teardown: empty ruleset, keep pf enabled (no NAT)
        try? "\(marker)\n# (egress withdrawn)\n".write(toFile: pfConf, atomically: true, encoding: .utf8)
        _ = run(PFCTL, ["-f", pfConf])
        logLine("[\(iface)] egress NAT off")
    }
}
#endif

func evictIface(iface: String, statePath: String) {
    logLine("[\(iface)] EVICT: server rejected token")
    _ = run(WGQUICK, ["down", iface])
    try? FileManager.default.removeItem(atPath: "\(CONFDIR)/\(iface).conf")
    try? FileManager.default.removeItem(atPath: statePath)
    try? FileManager.default.removeItem(atPath: "\(RUNDIR)/\(iface).rev")
}

// ── per-iface reconcile ─────────────────────────────────────────────────────
func processIface(statePath: String) {
    let iface = (statePath as NSString).lastPathComponent.replacingOccurrences(of: ".json", with: "")
    guard let data = FileManager.default.contents(atPath: statePath),
          let m = try? JSONDecoder().decode(Membership.self, from: data),
          let server = m.server?.trimmingCharacters(in: CharacterSet(charactersIn: "/")),
          let deviceID = m.device_id, let token = m.token,
          !server.isEmpty, !deviceID.isEmpty, !token.isEmpty else {
        logLine("[\(iface)] state incomplete; skip"); return
    }
    let role = m.role ?? "device"
    let wgListen = m.wg_listen ?? 1632

    // 1. heartbeat
    if let body = heartbeatBody(iface: iface, role: role, wgListen: wgListen) {
        let (code, respData) = http("\(server)/v1/heartbeat", method: "POST",
                                    token: token, deviceID: deviceID, body: body)
        let txt = respData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        if code != 200 { logLine("[\(iface)] heartbeat HTTP \(code): \(txt.prefix(160))") }
        // 2. eviction policy
        if code == 401, ["invalid device token", "token expired", "token does not match"].contains(where: { txt.contains($0) }) {
            evictIface(iface: iface, statePath: statePath); return
        }
    }

    // 3. peer refresh (single immediate fetch — long-poll is a follow-up)
    let peerURL = role == "hub" ? "\(server)/v1/hub/peers" : "\(server)/v1/peers"
    let (pcode, pdata) = http(peerURL, token: token, deviceID: deviceID)
    guard pcode == 200, let pdata = pdata else { logLine("[\(iface)] peers HTTP \(pcode)"); return }
    guard let resp = try? JSONDecoder().decode(PeerResponse.self, from: pdata) else {
        logLine("[\(iface)] peers: bad JSON"); return
    }
    if resp.not_modified == true { return }
    if getenv("WG_AGENT_DEBUG") != nil {
        logLine("[\(iface)] OK heartbeat+peers 200 rev=\(resp.rev ?? "-") peers=\(resp.peers?.count ?? 0)")
    }

    // hub-role egress NAT: non-empty advertised_routes == platform opened egress
    // here → converge the packet-filter rule (before render so a render failure
    // can't skip the NAT reconcile).
    if role == "hub" {
        applyEgressNAT(iface: iface, enable: resp.advertised_routes?.isEmpty == false)
    }

    // 4. render + sync/reload if changed
    guard let newConf = renderConf(iface: iface, resp: resp) else { return }
    let confPath = "\(CONFDIR)/\(iface).conf"
    let oldConf = (try? String(contentsOfFile: confPath, encoding: .utf8)) ?? ""
    if newConf != oldConf {
        do {
            try newConf.write(toFile: confPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: confPath)
            if allowedIPsSet(newConf) == allowedIPsSet(oldConf) {
                logLine("[\(iface)] peers changed; syncconf (non-disruptive)")
                syncIface(iface)
            } else {
                logLine("[\(iface)] routes changed; full reload")
                reloadIface(iface)
            }
        } catch { logLine("[\(iface)] write conf failed: \(error)") }
    }
}

// ── main ────────────────────────────────────────────────────────────────────
guard getuid() == 0 else { FileHandle.standardError.write("wg-agent: must run as root\n".data(using: .utf8)!); exit(1) }
try? FileManager.default.createDirectory(atPath: RUNDIR, withIntermediateDirectories: true)
// single-instance guard: a run that wedges (e.g. a network hang) must NOT let the
// next cron tick pile up another — that avalanched to 98 stuck procs once. Hold an
// flock for our lifetime; if another instance holds it, bail immediately.
let lockFD = open("\(RUNDIR)/wg-agent.lock", O_CREAT | O_RDWR, 0o600)
if lockFD >= 0, flock(lockFD, LOCK_EX | LOCK_NB) != 0 { exit(0) }
// hard watchdog: never outlive the cron interval whatever hangs (URLSession worker,
// a wedged subprocess pipe, …). Force-exit after 50s; flock then frees for next run.
Thread.detachNewThread {
    Thread.sleep(forTimeInterval: 50)
    FileHandle.standardError.write("wg-agent: watchdog 50s — force exit\n".data(using: .utf8)!)
    exit(2)
}
// URLSession's TLS (OpenSSL on FreeBSD, libcurl on Linux) may need an explicit
// CA bundle path or HTTPS fails validation silently (→ HTTP 0). Self-set so the
// binary works with no external env. (Linux libcurl usually finds it anyway.)
if getenv("SSL_CERT_FILE") == nil {
    for p in ["/etc/ssl/cert.pem",                       // FreeBSD
              "/etc/ssl/certs/ca-certificates.crt",      // Debian/Ubuntu
              "/etc/pki/tls/certs/ca-bundle.crt",        // RHEL/Fedora
              "/usr/local/etc/ssl/cert.pem",
              "/usr/local/share/certs/ca-root-nss.crt"]
    where FileManager.default.fileExists(atPath: p) { setenv("SSL_CERT_FILE", p, 1); break }
}
try? FileManager.default.createDirectory(atPath: RUNDIR, withIntermediateDirectories: true)
let states = (try? FileManager.default.contentsOfDirectory(atPath: STATE_DIR))?
    .filter { $0.hasSuffix(".json") }.map { "\(STATE_DIR)/\($0)" } ?? []
if states.isEmpty { logLine("no memberships in \(STATE_DIR); no-op") }
for s in states { processIface(statePath: s) }
exit(0)   // force clean exit past any lingering URLSession worker threads
