import Dispatch
import Foundation

/// Runs a child process so that interrupting Liter8 also stops what Liter8
/// started.
///
/// Foundation spawns with `POSIX_SPAWN_SETPGROUP`, so every child becomes a
/// process-group leader in a group of its own. Ctrl-C signals only the
/// terminal's foreground process group, which contains Liter8 and not the
/// child. The observed result is that Liter8 exits immediately while the Python
/// helper, and whatever it had spawned in turn, keep running with no owner:
///
///     parent (liter8)  pid 72221  pgid 72044   <- foreground group, gets SIGINT
///     child  (python)  pid 72222  pgid 72222   <- never sees it
///
/// That is how an aborted restore left `idevicerestore` still streaming to a
/// device in DFU with nothing left to stop it.
///
/// The signal is forwarded to the child's whole group rather than its pid,
/// because the tools that matter are grandchildren: Python spawns
/// `idevicerestore`, `irecovery` and `7zz`, and they inherit its group. Killing
/// only the Python process would orphan those in turn, which is the same bug
/// one level down.
public enum InterruptibleProcess: Sendable {
    /// How long a child gets to exit on SIGTERM before it is killed.
    ///
    /// Long enough for Python to run its own cleanup and for a USB tool to
    /// close its handle, short enough that a second Ctrl-C is not needed.
    private static let graceSeconds = 5.0

    /// Supervise `process` for the duration of `body`.
    ///
    /// For callers that cannot use `run` because they drive their own wait, for
    /// example to print progress while the child works. `body` is responsible
    /// for starting the process and waiting for it.
    public static func supervising<T>(_ process: Process, _ body: () throws -> T) rethrows -> T {
        let restore = beginSupervising(process)
        defer { restore() }
        return try body()
    }

    /// Start `process`, forward interrupts to it, and wait for it to exit.
    ///
    /// Restores the previous signal disposition before returning, so a caller
    /// that runs several children in sequence is unaffected by this one.
    public static func run(_ process: Process, foregroundTerminal: Bool = false) throws {
        try supervising(process) {
            try process.run()
            let restoreTerminal = foregroundTerminal
                ? foregroundTerminalForChild(process)
                : nil
            defer { restoreTerminal?() }
            process.waitUntilExit()
        }
    }

    private static func foregroundTerminalForChild(_ process: Process) -> (() -> Void)? {
        let descriptor = STDIN_FILENO
        guard isatty(descriptor) != 0 else { return nil }
        let originalGroup = tcgetpgrp(descriptor)
        let childGroup = process.processIdentifier
        guard originalGroup > 0,
              originalGroup == getpgrp(),
              childGroup > 0,
              getpgid(childGroup) == childGroup else { return nil }

        let previousTTOU = signal(SIGTTOU, SIG_IGN)
        let foregrounded = tcsetpgrp(descriptor, childGroup) == 0
        signal(SIGTTOU, previousTTOU)
        guard foregrounded else { return nil }

        return {
            let previousTTOU = signal(SIGTTOU, SIG_IGN)
            _ = tcsetpgrp(descriptor, originalGroup)
            signal(SIGTTOU, previousTTOU)
        }
    }

    /// Begin supervising and return a closure that stops doing so.
    ///
    /// The caller must invoke the returned closure, normally from a `defer`.
    /// Prefer `run` or `supervising` where the control flow allows it.
    public static func beginSupervising(_ process: Process) -> () -> Void {
        // Ignore the default disposition first. Without this the process dies
        // on SIGINT before any handler observes it, which is the current
        // behaviour being fixed. DispatchSourceSignal observes the signal
        // independently of the disposition, so ignoring here loses nothing.
        let previousINT = signal(SIGINT, SIG_IGN)
        let previousTERM = signal(SIGTERM, SIG_IGN)

        let queue = DispatchQueue(label: "liter8.child-signals")
        // A signal handler must be async-signal-safe; a Dispatch source runs
        // the handler on a normal queue instead, so ordinary code is allowed.
        let sources = [SIGINT, SIGTERM].map { number -> DispatchSourceSignal in
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { terminateGroup(of: process) }
            source.resume()
            return source
        }

        return {
            sources.forEach { $0.cancel() }
            signal(SIGINT, previousINT)
            signal(SIGTERM, previousTERM)
        }
    }

    /// Ask the child's process group to stop, then insist.
    private static func terminateGroup(of process: Process) {
        let identifier = process.processIdentifier
        // Both signals are ignored while a child is supervised, so a signal
        // arriving before the child exists, or after it has already gone, must
        // still stop Liter8. Otherwise ignoring them would make Ctrl-C do
        // nothing at all during setup, which is worse than the bug being fixed.
        guard identifier > 0, process.isRunning else {
            exit(130)
        }

        FileHandle.standardError.write(Data(
            "\ninterrupted: stopping the running helper and its tools...\n".utf8
        ))

        // Negative pid addresses the process group. The child is its own group
        // leader, so its pid is also its group id.
        kill(-identifier, SIGTERM)

        // Give it the grace period on a queue rather than blocking, so the
        // waitUntilExit below can still observe a clean exit.
        DispatchQueue.global().asyncAfter(deadline: .now() + graceSeconds) {
            guard process.isRunning else { return }
            FileHandle.standardError.write(Data(
                "helper did not exit after \(Int(graceSeconds))s, killing it\n".utf8
            ))
            kill(-identifier, SIGKILL)
        }
    }
}
