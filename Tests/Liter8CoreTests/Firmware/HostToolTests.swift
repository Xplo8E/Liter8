import Foundation
import XCTest
@testable import Liter8Core

/// The point of `HostTool` is that it works on both Homebrew prefixes, so the
/// tests use a synthetic directory rather than whatever this machine installed.
final class HostToolTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("liter8-hosttool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeExecutable(_ name: String, mode: Int = 0o755) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try Data("#!/bin/sh\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    func testLocateFindsAnExecutableInAnExtraDirectory() throws {
        let expected = try makeExecutable("liter8-fake-tool")
        let found = HostTool.locate("liter8-fake-tool", extraDirectories: [directory.path])
        XCTAssertEqual(found?.path, expected.path)
    }

    func testLocateReturnsNilForAMissingTool() {
        XCTAssertNil(HostTool.locate("liter8-tool-that-does-not-exist"))
    }

    /// A readable but non-executable file is not a usable tool. Returning it
    /// would turn a clear "not found" into a confusing exec failure later.
    func testLocateIgnoresANonExecutableFile() throws {
        _ = try makeExecutable("liter8-not-executable", mode: 0o644)
        XCTAssertNil(
            HostTool.locate("liter8-not-executable", extraDirectories: [directory.path])
        )
    }

    func testExtraDirectoriesWinOverTheRestOfThePath() throws {
        // `ls` certainly exists in a system directory already.
        let shadow = try makeExecutable("ls")
        XCTAssertEqual(
            HostTool.locate("ls", extraDirectories: [directory.path])?.path,
            shadow.path
        )
    }

    /// Both Homebrew prefixes are searched even when PATH mentions neither,
    /// which is the Intel/Apple Silicon portability the type exists for.
    func testSearchPathAlwaysIncludesBothHomebrewPrefixes() {
        let path = HostTool.searchPath()
        XCTAssertTrue(path.contains("/opt/homebrew/bin"))
        XCTAssertTrue(path.contains("/usr/local/bin"))
    }

    func testSearchPathDoesNotRepeatADirectory() {
        let path = HostTool.searchPath(extraDirectories: ["/usr/local/bin"])
        XCTAssertEqual(path.filter { $0 == "/usr/local/bin" }.count, 1)
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

    /// A tool known under several names resolves when any one of them is present.
    func testPreflightAcceptsAnAlternativeToolName() throws {
        let timeoutTool = Preflight.tools.first { $0.names.contains("gtimeout") }
        XCTAssertEqual(timeoutTool?.names, ["timeout", "gtimeout"])
    }

    func testPreflightReportsAMissingToolRatherThanThrowing() {
        let results = Preflight.run(stages: [.build], extraDirectories: [directory.path])
        XCTAssertFalse(results.isEmpty)
        XCTAssertEqual(results.map(\.tool.stage).filter { $0 != .build }.count, 0)
    }
}
