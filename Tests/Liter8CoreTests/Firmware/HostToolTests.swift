import Foundation
import XCTest
@testable import Liter8Core

/// The point of `HostTool` is that it works on both Homebrew prefixes, so the
/// tests put a synthetic directory on `PATH` rather than relying on whatever
/// this machine happens to have installed.
final class HostToolTests: XCTestCase {
    private var directory: URL!
    private var originalPath: String!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("liter8-hosttool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        originalPath = ProcessInfo.processInfo.environment["PATH"] ?? ""
        setenv("PATH", "\(directory.path):\(originalPath!)", 1)
    }

    override func tearDownWithError() throws {
        setenv("PATH", originalPath, 1)
        try? FileManager.default.removeItem(at: directory)
    }

    @discardableResult
    private func makeExecutable(_ name: String, mode: Int = 0o755) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try Data("#!/bin/sh\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    func testLocateFindsAnExecutableOnThePath() throws {
        let expected = try makeExecutable("liter8-fake-tool")
        XCTAssertEqual(HostTool.locate("liter8-fake-tool")?.path, expected.path)
    }

    func testLocateReturnsNilForAMissingTool() {
        XCTAssertNil(HostTool.locate("liter8-tool-that-does-not-exist"))
    }

    /// A readable but non-executable file is not a usable tool. Returning it
    /// would turn a clear "not found" into a confusing exec failure later.
    func testLocateIgnoresANonExecutableFile() throws {
        try makeExecutable("liter8-not-executable", mode: 0o644)
        XCTAssertNil(HostTool.locate("liter8-not-executable"))
    }

    func testEarlierPathEntriesWin() throws {
        // `ls` certainly exists in a system directory already.
        let shadow = try makeExecutable("ls")
        XCTAssertEqual(HostTool.locate("ls")?.path, shadow.path)
    }

    /// Both Homebrew prefixes are searched even when PATH mentions neither,
    /// which is the Intel/Apple Silicon portability the type exists for.
    func testSearchPathAlwaysIncludesBothHomebrewPrefixes() {
        setenv("PATH", "/usr/bin", 1)
        let path = HostTool.searchPath()
        XCTAssertTrue(path.contains("/opt/homebrew/bin"))
        XCTAssertTrue(path.contains("/usr/local/bin"))
    }

    func testSearchPathDoesNotRepeatADirectory() {
        setenv("PATH", "/usr/local/bin:/usr/bin:/usr/local/bin", 1)
        XCTAssertEqual(HostTool.searchPath().filter { $0 == "/usr/local/bin" }.count, 1)
    }

    func testRequireNamesTheToolAndHowToInstallIt() {
        XCTAssertThrowsError(
            try HostTool.require("liter8-tool-that-does-not-exist", installHint: "brew install nothing")
        ) { error in
            let text = String(describing: error)
            XCTAssertTrue(text.contains("liter8-tool-that-does-not-exist"), text)
            XCTAssertTrue(text.contains("brew install nothing"), text)
            XCTAssertTrue(text.contains("searched:"), text)
        }
    }

    /// A tool known under several names resolves on any of them, which is why
    /// `timeout` and Homebrew's `gtimeout` share one entry.
    func testAToolResolvesByItsSecondNameWhenTheFirstIsAbsent() throws {
        let present = try makeExecutable("liter8-second-name")
        let tool = Preflight.Tool(
            names: ["liter8-absent-name", "liter8-second-name"],
            stage: .build,
            purpose: "test",
            installHint: "test"
        )
        XCTAssertEqual(tool.resolve()?.path, present.path)
    }

    /// A tool nobody has must come back unresolved rather than throwing, so
    /// one report can list every problem instead of stopping at the first.
    func testAnAbsentToolResolvesToNilInsteadOfThrowing() {
        let absent = Preflight.Tool(
            names: ["liter8-tool-that-does-not-exist"],
            stage: .build,
            purpose: "test",
            installHint: "test"
        )
        XCTAssertNil(absent.resolve())
        XCTAssertFalse(Preflight.Result(tool: absent, resolved: absent.resolve()).isSatisfied)
    }

    /// Every entry needs an install hint, because the report prints it as the
    /// only guidance an operator gets for a missing tool.
    func testEveryPreflightToolIsFullyDescribed() {
        for tool in Preflight.tools {
            XCTAssertFalse(tool.names.isEmpty, "\(tool.purpose) has no names")
            XCTAssertFalse(tool.purpose.isEmpty, "\(tool.names) has no purpose")
            XCTAssertFalse(tool.installHint.isEmpty, "\(tool.names) has no install hint")
        }
    }

    /// A binary that exists and is executable but cannot be launched, which is
    /// what a Homebrew copy becomes when an upgrade moves its dylibs, must be
    /// skipped so resolution keeps looking.
    func testLocateCanRequireThatTheToolActuallyRuns() throws {
        let broken = try makeExecutable("liter8-broken-tool")
        try Data("#!/nonexistent/interpreter\n".utf8).write(to: broken)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: broken.path
        )
        // Present on disk either way.
        XCTAssertEqual(HostTool.locate("liter8-broken-tool")?.path, broken.path)
        // But refused when the caller needs something it can launch.
        XCTAssertNil(HostTool.locate("liter8-broken-tool", requiringRunnable: true))
    }

    /// The scripts die on these by name, so the report has to cover them.
    func testPreflightCoversTheToolsTheDeviceScriptsRequire() {
        let covered = Set(Preflight.tools.flatMap(\.names))
        for required in ["iproxy", "zstd", "gtar", "usbliter8ctl", "7zz", "ipsw", "aea"] {
            XCTAssertTrue(covered.contains(required), "preflight does not check \(required)")
        }
    }
}
