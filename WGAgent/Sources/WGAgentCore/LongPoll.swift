import Foundation

/// Bounded long-poll driver for `/v1/peers` (and `/v1/hub/peers`).
///
/// One agent invocation gets a wall-clock budget and then exits, so the
/// scheduler (launchd `StartInterval`, a systemd timer, cron) relaunches it.
/// `budget` must stay below that interval or two agents overlap.
///
/// The point of the state machine is that the *same* code has to behave
/// against three kinds of server: one that has no `rev` cursor at all, one
/// that has `rev` but ignores `?wait`, and one that genuinely holds the
/// connection open. It discovers which it is talking to and degrades, without
/// ever busy-looping.
///
/// This is a pure decision function — no clock, no I/O. The caller supplies
/// `now` and reports what happened, which is what makes every degradation path
/// testable.
public struct LongPollPlanner: Sendable {

    public struct Config: Sendable, Equatable {
        /// Total wall-clock budget for one invocation.
        public var budget: Int
        /// What we ask the server to hold the connection for.
        public var wait: Int
        /// A response faster than this means the server did not actually hold it.
        public var minReturn: Int
        /// Anti-busy-loop floor between attempts.
        public var floor: Int

        public init(budget: Int = 55, wait: Int = 45, minReturn: Int = 5, floor: Int = 10) {
            self.budget = budget
            self.wait = wait
            self.minReturn = minReturn
            self.floor = floor
        }
    }

    public enum Outcome: Sendable, Equatable {
        /// 200 with a body, and we changed the config.
        case applied
        /// 200 with a body, nothing to do.
        case unchanged
        /// The server held the connection and reported no change.
        case notModified
        /// Transport failure or non-200. Never retried within this invocation.
        case error
    }

    public enum Stop: Sendable, Equatable {
        case budgetExhausted
        /// Non-200 or transport failure — the next scheduler tick retries.
        case transportError
        /// Server returned no `rev`: it predates long-poll. Plain polling.
        case noRevSupport
        /// Server has `rev` but returned immediately: it ignores `?wait`.
        case waitIgnored(elapsed: Int)
    }

    public enum Action: Sendable, Equatable {
        /// Issue the request. `wait == 0` means no `?wait` parameter.
        case fetch(wait: Int)
        /// Back off before the next attempt.
        case sleep(seconds: Int)
        case stop(Stop)
    }

    private enum Mode { case probe, trial, longPoll }

    public let config: Config
    private let deadline: Int
    private var mode: Mode = .probe
    private var pendingSleep: Int?
    private var stopped: Stop?

    /// Cursor echoed back to the server on the next request.
    public private(set) var rev: String?

    public init(config: Config = Config(), startTime: Int, rev: String? = nil) {
        self.config = config
        self.deadline = startTime + config.budget
        self.rev = rev
    }

    /// What to do at `now`.
    public mutating func next(now: Int) -> Action {
        if let stopped { return .stop(stopped) }

        if let sleepFor = pendingSleep {
            pendingSleep = nil
            return .sleep(seconds: sleepFor)
        }

        let remaining = deadline - now
        if remaining <= 1 {
            stopped = .budgetExhausted
            return .stop(.budgetExhausted)
        }

        // Probe goes out without ?wait — we don't yet know if the server
        // supports holding, and a legacy server would just block us pointlessly.
        guard mode != .probe else { return .fetch(wait: 0) }

        let waitFor = min(config.wait, remaining)
        if waitFor < 1 {
            stopped = .budgetExhausted
            return .stop(.budgetExhausted)
        }
        return .fetch(wait: waitFor)
    }

    /// Report the result of the fetch that `next` asked for.
    public mutating func record(outcome: Outcome, elapsed: Int, rev newRev: String?, now: Int) {
        if let newRev, !newRev.isEmpty {
            rev = newRev
        }

        switch outcome {
        case .error:
            // Don't hammer a server that just failed; the next tick retries.
            stopped = .transportError

        case .notModified:
            // Only a server that actually held the connection can say this.
            mode = .longPoll

        case .applied, .unchanged:
            switch mode {
            case .probe:
                if newRev?.isEmpty ?? true {
                    stopped = .noRevSupport
                } else {
                    mode = .trial
                }

            case .trial:
                if elapsed >= config.minReturn {
                    mode = .longPoll
                } else {
                    stopped = .waitIgnored(elapsed: elapsed)
                }

            case .longPoll:
                // A server that claims to long-poll but returns instantly with
                // an unchanged body would spin us; floor the retry rate.
                if elapsed < config.minReturn && outcome == .unchanged {
                    if deadline - now <= config.floor {
                        stopped = .budgetExhausted
                    } else {
                        pendingSleep = config.floor
                    }
                }
            }
        }
    }

    /// `rev` sanitized for use in a query string.
    ///
    /// Matches the shell agents byte-for-byte (`sed 's/[^A-Za-z0-9._-]/-/g'`)
    /// rather than percent-encoding, because the server has only ever been fed
    /// the sanitized form; switching to correct encoding would hand it a cursor
    /// it has never seen.
    public static func sanitize(rev: String) -> String {
        String(rev.map { ch in
            let ok = ch.isASCII && (ch.isLetter || ch.isNumber || ch == "." || ch == "_" || ch == "-")
            return ok ? ch : "-"
        })
    }
}
