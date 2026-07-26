import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

public protocol ProcessRunner: Sendable {
    func run(_ path: String, _ args: [String]) -> (code: Int32, out: String)
}

/// Subprocess execution via `posix_spawn` + a blocking `waitpid`.
///
/// NOT `Foundation.Process`. On FreeBSD (and to a lesser degree Linux),
/// corelibs-foundation's `Pipe` / dispatch I/O busy-polls to ~100% CPU while a
/// slow child runs — a `curl` sitting on its timeout was enough to peg the
/// dpaa2 box and starve its sshd. `waitpid` is a real blocking syscall: the
/// thread sleeps at 0% CPU.
///
/// It also fixes a hang the Pipe version had: reading a pipe to EOF waits for
/// every process holding the write end, and `wg-quick` backgrounds a route
/// monitor that keeps it open forever. `waitpid` waits for the direct child
/// only.
///
/// Output is captured by briefly pointing our own fd 1/2 at a temp file rather
/// than using `posix_spawn_file_actions_t`, whose layout differs between Linux
/// and FreeBSD and cannot be written portably in Swift.
public struct POSIXProcessRunner: ProcessRunner {
    /// Directory for the transient capture file. Must exist and be writable.
    public let scratchDir: String
    /// Extra variables handed to children on top of our own environment.
    /// FreeBSD needs `SSL_CERT_FILE` here or a child curl's TLS validation
    /// fails with no useful diagnostic.
    public let extraEnvironment: [String: String]

    public init(scratchDir: String = "/var/run/wireguard",
                extraEnvironment: [String: String] = [:]) {
        self.scratchDir = scratchDir
        self.extraEnvironment = extraEnvironment
    }

    public func run(_ path: String, _ args: [String]) -> (code: Int32, out: String) {
        let outPath = "\(scratchDir)/.run.\(getpid()).out"

        var argv: [UnsafeMutablePointer<CChar>?] = ([path] + args).map { strdup($0) }
        argv.append(nil)
        defer { for p in argv { free(p) } }

        // Build envp ourselves rather than reaching for the global `environ`,
        // which Swift does not expose uniformly across Darwin and Linux.
        var env = ProcessInfo.processInfo.environment
        env.merge(extraEnvironment) { _, new in new }
        var envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") }
        envp.append(nil)
        defer { for p in envp { free(p) } }

        let saved1 = dup(1), saved2 = dup(2)
        let fd = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd >= 0 {
            dup2(fd, 1)
            dup2(fd, 2)
            close(fd)
        }

        var pid: pid_t = 0
        let spawnRC = posix_spawn(&pid, path, nil, nil, argv, envp)

        // Restore our own stdio before doing anything that might log.
        if saved1 >= 0 { dup2(saved1, 1); close(saved1) }
        if saved2 >= 0 { dup2(saved2, 2); close(saved2) }

        if spawnRC != 0 {
            unlink(outPath)
            return (-1, "")
        }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}

        let out = (try? String(contentsOfFile: outPath, encoding: .utf8)) ?? ""
        unlink(outPath)

        // Decode wait(2) status the same way a shell reports it.
        let code: Int32 = (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        return (code, out)
    }
}

/// Resolve a tool by trying absolute paths in order.
///
/// Never search `PATH`: FreeBSD puts wireguard-tools in /usr/local/bin while
/// Linux uses /usr/bin, and a daemon started by launchd/cron has whatever PATH
/// the scheduler felt like giving it.
public func toolPath(_ candidates: [String]) -> String {
    for c in candidates where access(c, X_OK) == 0 { return c }
    return candidates.first ?? ""
}
