import CryptoKit
import Foundation

/// Resolves or provisions the isolated Python used by Liter8 workflows.
///
/// An explicit interpreter is always respected. Normal installations use a
/// managed venv under `~/.liter8`, while source checkouts may provide `.venv`
/// for a fast development loop. Nothing is installed into the host Python.
public enum Liter8PythonRuntime {
    private static let requirementsMarker = ".liter8-requirements.sha256"
    // Confirm this interpreter really belongs to a virtual environment. The
    // workflow currently has no third-party Python imports because IMG4 is
    // handled in Swift, but keeping the isolation now avoids global installs
    // when orchestration dependencies are added later.
    private static let importProbe = "import sys; assert sys.prefix != sys.base_prefix"

    public static func executable(
        explicit: String?,
        resources: Liter8Resources,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> URL {
        if let explicit, !explicit.isEmpty {
            return try requireExecutable(URL(fileURLWithPath: explicit), label: "--python")
        }
        if let override = environment["LITER8_PYTHON"], !override.isEmpty {
            return try requireExecutable(URL(fileURLWithPath: override), label: "LITER8_PYTHON")
        }

        let expectedMarker = try requirementsDigest(resources.requirementsFile)
        let developmentDirectory = resources.developmentVenvDirectory
        let developmentPython = developmentDirectory.appendingPathComponent("bin/python3")
        let developmentMarker = developmentDirectory.appendingPathComponent(requirementsMarker)
        // A venv can be isolated but stale. Once device transport added PyUSB,
        // accepting any old .venv would make usbliter8ctl fail only after the
        // phone had already entered a new USB state.
        if pythonIsUsable(developmentPython),
           (try? String(contentsOf: developmentMarker, encoding: .utf8)) == expectedMarker {
            return developmentPython
        }

        let managedDirectory = managedVenvDirectory(environment: environment)
        let managedPython = managedDirectory.appendingPathComponent("bin/python3")
        let marker = managedDirectory.appendingPathComponent(requirementsMarker)
        if pythonIsUsable(managedPython),
           (try? String(contentsOf: marker, encoding: .utf8)) == expectedMarker {
            return managedPython
        }

        return try provision(
            at: managedDirectory,
            requirements: resources.requirementsFile,
            marker: expectedMarker,
            environment: environment
        )
    }

    public static func managedVenvDirectory(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL {
        if let override = environment["LITER8_VENV_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true).standardizedFileURL
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".liter8/venv", isDirectory: true)
    }

    private static func provision(
        at destination: URL,
        requirements: URL,
        marker: String,
        environment: [String: String]
    ) throws -> URL {
        let fileManager = FileManager.default
        let parent = destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)

        let staging = parent.appendingPathComponent(
            ".venv-staging-\(UUID().uuidString)",
            isDirectory: true
        )
        let previous = parent.appendingPathComponent(
            ".venv-previous-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            try? fileManager.removeItem(at: staging)
            try? fileManager.removeItem(at: previous)
        }

        let hostPython = try hostPython(environment: environment)
        print("provisioning Liter8 Python environment: \(destination.path)")
        try run(hostPython, ["-m", "venv", staging.path])

        let python = staging.appendingPathComponent("bin/python3")
        try run(python, ["-m", "pip", "install", "-r", requirements.path])
        guard pythonIsUsable(python) else {
            throw PatchfinderError.invalidFixture(
                "the new Liter8 virtual environment failed its isolation check"
            )
        }
        try marker.write(
            to: staging.appendingPathComponent(requirementsMarker),
            atomically: true,
            encoding: .utf8
        )

        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.moveItem(at: destination, to: previous)
        }
        do {
            try fileManager.moveItem(at: staging, to: destination)
        } catch {
            if fileManager.fileExists(atPath: previous.path),
               !fileManager.fileExists(atPath: destination.path) {
                try? fileManager.moveItem(at: previous, to: destination)
            }
            throw error
        }
        try? fileManager.removeItem(at: previous)
        return destination.appendingPathComponent("bin/python3")
    }

    private static func hostPython(environment: [String: String]) throws -> URL {
        var candidates: [URL] = []
        if let explicit = environment["LITER8_HOST_PYTHON"], !explicit.isEmpty {
            candidates.append(URL(fileURLWithPath: explicit))
        }
        candidates += [
            URL(fileURLWithPath: "/opt/homebrew/bin/python3"),
            URL(fileURLWithPath: "/usr/local/bin/python3"),
            URL(fileURLWithPath: "/usr/bin/python3"),
        ]

        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        throw PatchfinderError.invalidFixture(
            "no host python3 was found; install Python or set LITER8_HOST_PYTHON"
        )
    }

    private static func pythonIsUsable(_ python: URL) -> Bool {
        guard FileManager.default.isExecutableFile(atPath: python.path) else { return false }
        let process = Process()
        process.executableURL = python
        process.arguments = ["-c", importProbe]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationReason == .exit && process.terminationStatus == 0
        } catch {
            return false
        }
    }

    private static func requireExecutable(_ url: URL, label: String) throws -> URL {
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            throw PatchfinderError.invalidFixture("\(label) is not executable: \(url.path)")
        }
        return url.standardizedFileURL
    }

    private static func requirementsDigest(_ requirements: URL) throws -> String {
        let data = try Data(contentsOf: requirements)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func run(_ executable: URL, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw PatchfinderError.invalidFixture(
                "\(executable.lastPathComponent) exited with status \(process.terminationStatus)"
            )
        }
    }
}
