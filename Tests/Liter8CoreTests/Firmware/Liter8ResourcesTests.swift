import Foundation
import Testing
@testable import Liter8Core

@Suite("Liter8Resources")
struct Liter8ResourcesTests {
    @Test func explicitResourceDirectoryWins() throws {
        let root = try temporaryResourceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let resources = try Liter8Resources.resolve(
            executable: URL(fileURLWithPath: "/unrelated/bin/liter8"),
            environment: ["LITER8_RESOURCE_DIR": root.path]
        )

        #expect(resources.base == root.standardizedFileURL)
    }

    @Test func commandLineOverrideBeatsEnvironment() throws {
        let selected = try temporaryResourceRoot()
        let environmentRoot = try temporaryResourceRoot()
        defer {
            try? FileManager.default.removeItem(at: selected)
            try? FileManager.default.removeItem(at: environmentRoot)
        }

        let resources = try Liter8Resources.resolve(
            override: selected,
            executable: URL(fileURLWithPath: "/unrelated/bin/liter8"),
            environment: ["LITER8_RESOURCE_DIR": environmentRoot.path]
        )

        #expect(resources.base == selected.standardizedFileURL)
    }

    @Test func resolvesConventionalInstalledLayout() throws {
        let prefix = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-prefix-\(UUID().uuidString)", isDirectory: true)
        let resourcesRoot = prefix.appendingPathComponent("share/liter8", isDirectory: true)
        try createResourceRoot(at: resourcesRoot)
        defer { try? FileManager.default.removeItem(at: prefix) }

        let resources = try Liter8Resources.resolve(
            executable: prefix.appendingPathComponent("bin/liter8"),
            environment: [:]
        )

        #expect(resources.base == resourcesRoot.standardizedFileURL)
    }

    @Test func walksUpFromSwiftBuildDirectory() throws {
        let root = try temporaryResourceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent(".build/arm64-apple-macosx/debug/liter8")

        let resources = try Liter8Resources.resolve(executable: executable, environment: [:])

        #expect(resources.base == root.standardizedFileURL)
    }

    @Test func rejectsIncompleteOverride() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-incomplete-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(throws: PatchfinderError.self) {
            try Liter8Resources.resolve(
                executable: URL(fileURLWithPath: "/unrelated/liter8"),
                environment: ["LITER8_RESOURCE_DIR": root.path]
            )
        }
    }

    private func temporaryResourceRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-resources-\(UUID().uuidString)", isDirectory: true)
        try createResourceRoot(at: root)
        return root
    }

    private func createResourceRoot(at root: URL) throws {
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("scripts", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("pyimg4\n".utf8).write(to: root.appendingPathComponent("requirements.txt"))
    }
}
