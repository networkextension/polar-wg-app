import Foundation
import WGAgentCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Host facts collected by syscall rather than by shelling out.
///
/// The shell agents forked `ifconfig`/`ip`/`route`/`uname`/`sysctl` and then a
/// whole `python3` just to assemble JSON, once per interface per minute. All of
/// that is `getifaddrs(3)`, `uname(2)` and one file read.
public enum HostFacts {

    // MARK: - os / arch

    public static func osName() -> String {
        var u = utsname()
        guard uname(&u) == 0 else { return "unknown" }
        return cString(&u.sysname).lowercased()
    }

    /// Normalized the way the control plane expects: amd64 / arm64.
    public static func arch() -> String {
        var u = utsname()
        guard uname(&u) == 0 else { return "unknown" }
        let raw = cString(&u.machine)
        switch raw {
        case "x86_64", "amd64": return "amd64"
        case "arm64", "aarch64": return "arm64"
        default: return raw
        }
    }

    private static func cString<T>(_ field: inout T) -> String {
        withUnsafePointer(to: &field) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) {
                String(cString: $0)
            }
        }
    }

    // MARK: - uptime

    /// Seconds since boot, or nil when it can't be determined.
    public static func uptimeSec(now: Date = Date()) -> Int? {
        #if os(Linux) || os(Android)
        guard let text = try? String(contentsOfFile: "/proc/uptime", encoding: .utf8),
              let first = text.split(separator: " ").first,
              let secs = Double(first)
        else { return nil }
        return Int(secs)
        #else
        var mib = [CTL_KERN, KERN_BOOTTIME]
        var boot = timeval()
        var size = MemoryLayout<timeval>.stride
        guard sysctl(&mib, 2, &boot, &size, nil, 0) == 0, boot.tv_sec > 0 else { return nil }
        let up = Int(now.timeIntervalSince1970) - Int(boot.tv_sec)
        return up > 0 ? up : nil
        #endif
    }

    // MARK: - lan_addrs

    /// Address families we never report as a LAN.
    ///
    /// The mesh ranges are excluded because reporting our own overlay address
    /// back to the control plane confuses its site detection.
    public static let defaultExcludedPrefixes = ["127.", "169.254.", "10.88.", "100.64."]

    /// IPv4 addresses of real interfaces, as `{iface, cidr}`.
    public static func lanAddrs(
        excludingPrefixes excluded: [String] = defaultExcludedPrefixes,
        excludingInterfacePrefixes ifacePrefixes: [String] = ["lo", "wg", "utun"]
    ) -> [LanAddr] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var out: [LanAddr] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }

            guard let addr = entry.pointee.ifa_addr,
                  addr.pointee.sa_family == sa_family_t(AF_INET)
            else { continue }

            let name = String(cString: entry.pointee.ifa_name)
            if ifacePrefixes.contains(where: { name.hasPrefix($0) }) { continue }

            let ip = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                ipv4String($0.pointee.sin_addr)
            }
            if ip.isEmpty || excluded.contains(where: { ip.hasPrefix($0) }) { continue }

            var bits = 32
            if let mask = entry.pointee.ifa_netmask,
               mask.pointee.sa_family == sa_family_t(AF_INET) {
                bits = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    prefixLength($0.pointee.sin_addr)
                }
            }
            out.append(LanAddr(iface: name, cidr: "\(ip)/\(bits)"))
        }
        return out
    }

    private static func ipv4String(_ addr: in_addr) -> String {
        var a = addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return "" }
        return String(cString: buf)
    }

    private static func prefixLength(_ mask: in_addr) -> Int {
        // s_addr is network byte order; popcount is order-independent.
        UInt32(mask.s_addr).nonzeroBitCount
    }
}
