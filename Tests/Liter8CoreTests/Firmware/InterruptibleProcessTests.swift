import Foundation
import XCTest
@testable import Liter8Core

/// The bug these cover: Foundation spawns children into their own process
/// group, so Ctrl-C reached Liter8 and never reached the Python helper or the
/// restore tools it had started. A unit test cannot press Ctrl-C, so these
/// reproduce the shape instead: spawn a child that spawns a grandchild, signal
/// the way the supervisor does, and check what is left running.
final class InterruptibleProcessTests: XCTestCase {
    /// The property the whole fix depends on.
    ///
    /// If Foundation ever stopped putting children in their own group, the
    /// supervisor's `kill(-pid)` would address Liter8's own group instead and
    /// would take down the terminal's foreground job. Better to fail here than
    /// to discover that during a restore.
    func testFoundationPutsChildrenInTheirOwnProcessGroup() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "sleep 30"]
        try process.run()
        defer { process.terminate() }

        let childPID = process.processIdentifier
        XCTAssertGreaterThan(childPID, 0)
        // getpgid on the child returns its group. Equal to its own pid means it
        // leads a group, which is what makes kill(-pid) address exactly the
        // child and its descendants.
        XCTAssertEqual(getpgid(childPID), childPID,
                       "kill(-pid) only targets the child's own tree while this holds")
        XCTAssertNotEqual(getpgid(childPID), getpgrp(),
                          "child shares Liter8's group, so Ctrl-C would already reach it")
    }

    /// A grandchild must not survive the child being signalled.
    ///
    /// This is the actual failure that was observed: Python died, or was never
    /// signalled, and `idevicerestore` kept streaming to a device in DFU.
    func testSignallingTheGroupStopsGrandchildren() throws {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-grandchild-\(UUID().uuidString)")

        // The child backgrounds a grandchild that would create the marker in
        // two seconds, then waits. Killing only the child would leave the
        // grandchild alive and the marker would appear anyway.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "sh -c 'sleep 2; touch \(marker.path)' & sleep 30"]
        try process.run()

        // Let the grandchild exist before signalling.
        Thread.sleep(forTimeInterval: 0.3)
        let group = process.processIdentifier
        XCTAssertEqual(kill(-group, SIGKILL), 0, "signalling the group must succeed")
        process.waitUntilExit()

        // Well past when the grandchild would have fired.
        Thread.sleep(forTimeInterval: 2.5)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: marker.path),
            "grandchild outlived the group signal; this is the orphaned-tool bug"
        )
        try? FileManager.default.removeItem(at: marker)
    }

    /// Supervision must leave the process's own signal handling as it found it.
    ///
    /// The supervisor ignores SIGINT and SIGTERM while a child runs. If it did
    /// not restore them, the first supervised child would silently make Liter8
    /// immune to Ctrl-C for the rest of the run.
    func testSignalDispositionIsRestoredAfterwards() throws {
        let before = signal(SIGINT, SIG_DFL)
        signal(SIGINT, before)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "exit 0"]
        try InterruptibleProcess.run(process)

        let after = signal(SIGINT, SIG_DFL)
        signal(SIGINT, after)
        XCTAssertEqual(
            unsafeBitCast(before, to: UInt.self),
            unsafeBitCast(after, to: UInt.self),
            "SIGINT disposition leaked; Liter8 would stop responding to Ctrl-C"
        )
    }

    /// `run` must still behave like the plain call it replaced.
    func testRunWaitsAndReportsTheChildStatus() throws {
        let success = Process()
        success.executableURL = URL(fileURLWithPath: "/bin/sh")
        success.arguments = ["-c", "exit 0"]
        try InterruptibleProcess.run(success)
        XCTAssertFalse(success.isRunning)
        XCTAssertEqual(success.terminationStatus, 0)

        let failure = Process()
        failure.executableURL = URL(fileURLWithPath: "/bin/sh")
        failure.arguments = ["-c", "exit 7"]
        try InterruptibleProcess.run(failure)
        XCTAssertEqual(failure.terminationStatus, 7,
                       "callers guard on this status, so it must survive supervision")
    }

    /// Several supervised children in sequence must not accumulate handlers.
    func testRepeatedSupervisionStaysBalanced() throws {
        for _ in 0..<5 {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", "exit 0"]
            try InterruptibleProcess.run(process)
        }
        let after = signal(SIGINT, SIG_DFL)
        signal(SIGINT, after)
        XCTAssertNotEqual(unsafeBitCast(after, to: UInt.self),
                          unsafeBitCast(SIG_IGN, to: UInt.self),
                          "SIGINT left ignored after repeated supervision")
    }
}
