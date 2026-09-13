import Foundation
import Testing
@testable import Liter8Core

@Suite("Liter8PythonRuntime")
struct Liter8PythonRuntimeTests {
    @Test func explicitPythonBeatsEnvironment() throws {
        let selected = try temporaryExecutable(named: "selected-python")
        let environmentPython = try temporaryExecutable(named: "environment-python")
        defer {
            try? FileManager.default.removeItem(at: selected.deletingLastPathComponent())
            try? FileManager.default.removeItem(at: environmentPython.deletingLastPathComponent())
        }

        let resources = Liter8Resources(base: selected.deletingLastPathComponent())
        let resolved = try Liter8PythonRuntime.executable(
            explicit: selected.path,
            resources: resources,
            environment: ["LITER8_PYTHON": environmentPython.path]
        )

        #expect(resolved == selected.standardizedFileURL)
    }

    @Test func managedVenvHonorsEnvironmentOverride() {
        let expected = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-managed-\(UUID().uuidString)", isDirectory: true)
        let resolved = Liter8PythonRuntime.managedVenvDirectory(
            environment: ["LITER8_VENV_DIR": expected.path]
        )

        #expect(resolved == expected.standardizedFileURL)
    }

    @Test func provisionsAnIsolatedManagedVenv() throws {
        let host = URL(fileURLWithPath: "/opt/homebrew/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: host.path) else { return }
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-venv-test-\(UUID().uuidString)", isDirectory: true)
        let resourcesRoot = root.appendingPathComponent("resources", isDirectory: true)
        let managed = root.appendingPathComponent("managed", isDirectory: true)
        try FileManager.default.createDirectory(at: resourcesRoot, withIntermediateDirectories: true)
        try Data("# no packages required\n".utf8).write(
            to: resourcesRoot.appendingPathComponent("requirements.txt")
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let python = try Liter8PythonRuntime.executable(
            explicit: nil,
            resources: Liter8Resources(base: resourcesRoot),
            environment: [
                "LITER8_HOST_PYTHON": host.path,
                "LITER8_VENV_DIR": managed.path,
            ]
        )

        #expect(FileManager.default.isExecutableFile(atPath: python.path))
        #expect(python.path == managed.appendingPathComponent("bin/python3").path)
        #expect(FileManager.default.fileExists(
            atPath: managed.appendingPathComponent(".liter8-requirements.sha256").path
        ))
    }

    private func temporaryExecutable(named name: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-python-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let executable = directory.appendingPathComponent(name)
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o755))],
            ofItemAtPath: executable.path
        )
        return executable
    }
}
