import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Advisory whole-process lock, held for the lifetime of the value.
///
/// cron can overlap where launchd and systemd timers do not, and an overlapping
/// fleet of agents is how a control-plane outage once turned into 98 stuck
/// processes and load 114 on one box.
public final class FileLock {
    private let fd: Int32

    /// Returns nil when another instance already holds the lock.
    public init?(path: String) {
        let fd = open(path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return nil }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            return nil
        }
        self.fd = fd
    }

    deinit {
        flock(fd, LOCK_UN)
        close(fd)
    }
}

/// Hard deadline for the whole process.
///
/// Implemented with `alarm(2)` + a signal handler rather than a sleeping
/// watchdog thread on purpose: the incident that motivated a watchdog was a
/// busy-spin that saturated the CPU, and under saturation a thread waiting on
/// `Thread.sleep` can miss its own deadline. `alarm` is kernel-driven, and
/// `_exit` is one of the few async-signal-safe things a handler may call.
///
/// This is the last line of defence, not the first — the first is choosing
/// I/O primitives that don't spin.
public enum Watchdog {
    /// Force-exit with status 2 after `seconds`, whatever the process is doing.
    public static func arm(seconds: UInt32) {
        signal(SIGALRM) { _ in _exit(2) }
        alarm(seconds)
    }

    public static func disarm() {
        alarm(0)
        signal(SIGALRM, SIG_DFL)
    }
}

/// Reads a one-shot status dump from a `wg_core` unix socket.
///
/// Protocol, from `wg_core.c`: connect, send nothing, read until EOF, server
/// closes. One dump per connection, and the server serves at most one accept
/// per select tick on the data-plane thread — so poll serially, never fan out,
/// and always drain promptly, because a client that stalls mid-read stalls the
/// tunnel.
///
/// The socket is mode 0600 in a 0700 directory: root only.
public enum StatusSocket {

    public enum Failure: Error, Equatable {
        case cannotCreateSocket(errno: Int32)
        case pathTooLong
        case connectFailed(errno: Int32)
    }

    public static func read(path: String, bufferSize: Int = 4096) throws -> String {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard path.utf8.count < capacity else { throw Failure.pathTooLong }

        withUnsafeMutablePointer(to: &addr.sun_path) { tuplePtr in
            tuplePtr.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                for (i, byte) in path.utf8.enumerated() { dst[i] = CChar(bitPattern: byte) }
                dst[path.utf8.count] = 0
            }
        }

        let fd = socket(AF_UNIX, sockStreamType, 0)
        guard fd >= 0 else { throw Failure.cannotCreateSocket(errno: errno) }
        defer { close(fd) }

        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw Failure.connectFailed(errno: errno) }

        var data = Data()
        var buf = [UInt8](repeating: 0, count: bufferSize)
        while true {
            let n = Foundation.read(fd, &buf, bufferSize)
            if n > 0 {
                data.append(contentsOf: buf[0..<n])
            } else if n < 0 && errno == EINTR {
                continue
            } else {
                break
            }
        }
        return String(decoding: data, as: UTF8.self)
    }

    // glibc types SOCK_STREAM as the __socket_type enum; Darwin and musl
    // already give us an Int32.
    #if canImport(Glibc)
    private static let sockStreamType = Int32(SOCK_STREAM.rawValue)
    #else
    private static let sockStreamType = SOCK_STREAM
    #endif
}

/// Locates the CA bundle for child processes that do TLS.
///
/// FreeBSD's OpenSSL build finds no bundle by default, and the failure mode is
/// a silent `HTTP 0` rather than a certificate error — so probe explicitly and
/// pass the answer down rather than hoping the environment is right.
public enum CABundle {
    public static let candidates = [
        "/etc/ssl/cert.pem",                        // macOS, FreeBSD base
        "/etc/ssl/certs/ca-certificates.crt",       // Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",         // RHEL/Fedora
        "/usr/local/etc/ssl/cert.pem",              // FreeBSD ports
        "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD ca_root_nss
    ]

    public static func locate() -> String? {
        if let set = ProcessInfo.processInfo.environment["SSL_CERT_FILE"], !set.isEmpty {
            return set
        }
        return candidates.first { access($0, R_OK) == 0 }
    }
}
