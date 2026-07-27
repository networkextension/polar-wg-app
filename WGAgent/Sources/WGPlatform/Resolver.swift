import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Hostname → addresses, via `getaddrinfo(3)`.
///
/// This is the other half of endpoint-drift detection: WireGuard resolves a
/// peer endpoint once and never again, so the agent has to do the lookup that
/// the data plane won't.
///
/// An empty result means the lookup failed and callers must treat it as "no
/// information", never as "the endpoint moved" — a DNS blip must not be able to
/// tear down a working tunnel.
public enum Resolver {

    public static func addresses(for host: String, family: Int32 = AF_UNSPEC) -> [String] {
        guard !host.isEmpty else { return [] }

        var hints = addrinfo()
        hints.ai_family = family
        #if canImport(Glibc)
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #else
        hints.ai_socktype = SOCK_DGRAM
        #endif

        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let head = result else { return [] }
        defer { freeaddrinfo(head) }

        var out: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = head
        while let entry = cursor {
            defer { cursor = entry.pointee.ai_next }
            guard let addr = entry.pointee.ai_addr else { continue }

            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let rc = getnameinfo(addr, entry.pointee.ai_addrlen,
                                 &buf, socklen_t(NI_MAXHOST),
                                 nil, 0, NI_NUMERICHOST)
            guard rc == 0 else { continue }
            let text = String(cString: buf)
            // getaddrinfo commonly returns the same address once per socktype.
            if !text.isEmpty && !out.contains(text) { out.append(text) }
        }
        return out
    }
}
