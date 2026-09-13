import Foundation

/// Locates the non-Swift files shipped with Liter8.
///
/// Firmware outputs belong in `--work-dir`; scripts, requirements and host
/// tools belong beside the Liter8 installation. Keeping those roots separate
/// lets the CLI run from any current directory without copying its own source
/// files into every extracted IPSW.
public struct Liter8Resources: Sendable {
    public let base: URL

    public init(base: URL) {
        self.base = base.standardizedFileURL
    }

    public var scriptsDirectory: URL { base.appendingPathComponent("scripts", isDirectory: true) }
    public var toolsDirectory: URL { base.appendingPathComponent("tools", isDirectory: true) }
    public var payloadsDirectory: URL { base.appendingPathComponent("payloads", isDirectory: true) }
    public var deviceDirectory: URL { base.appendingPathComponent("device", isDirectory: true) }
    public var requirementsFile: URL { base.appendingPathComponent("requirements.txt") }
    public var developmentVenvDirectory: URL { base.appendingPathComponent(".venv", isDirectory: true) }

    /// Resolve resources in the same order an operator would expect:
    /// explicit override, installed layout, then a source checkout containing
    /// the running `.build/.../liter8` executable.
    public static func resolve(
        override: URL? = nil,
        executable: URL? = nil,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> Liter8Resources {
        if let override {
            return try validated(override)
        }
        if let override = environment["LITER8_RESOURCE_DIR"], !override.isEmpty {
            return try validated(URL(fileURLWithPath: override, isDirectory: true))
        }

        let executable = (executable ?? runningExecutable()).resolvingSymlinksInPath()
        let executableDirectory = executable.deletingLastPathComponent()

        // Application bundles keep immutable runtime files in Contents/Resources.
        if executableDirectory.lastPathComponent == "MacOS",
           executableDirectory.deletingLastPathComponent().lastPathComponent == "Contents" {
            let resources = executableDirectory.deletingLastPathComponent()
                .appendingPathComponent("Resources", isDirectory: true)
            if isValidBase(resources) { return Liter8Resources(base: resources) }
        }

        // A conventional command-line installation uses:
        //   <prefix>/bin/liter8
        //   <prefix>/share/liter8/{scripts,requirements.txt}
        if executableDirectory.lastPathComponent == "bin" {
            let installed = executableDirectory.deletingLastPathComponent()
                .appendingPathComponent("share/liter8", isDirectory: true)
            if isValidBase(installed) { return Liter8Resources(base: installed) }
        }

        // Development binaries live below `.build`. Walk from the real binary,
        // not argv[0] or cwd, so PATH and symlink launches remain deterministic.
        var candidate = executableDirectory
        for _ in 0..<8 {
            if isValidBase(candidate) { return Liter8Resources(base: candidate) }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }

        throw PatchfinderError.invalidFixture(
            "could not locate Liter8 resources; set LITER8_RESOURCE_DIR to the directory containing scripts/ and requirements.txt"
        )
    }

    private static func runningExecutable() -> URL {
        if let executable = Bundle.main.executableURL { return executable }
        return URL(fileURLWithPath: CommandLine.arguments[0])
    }

    private static func validated(_ base: URL) throws -> Liter8Resources {
        guard isValidBase(base) else {
            throw PatchfinderError.invalidFixture(
                "invalid Liter8 resource directory: \(base.path); expected scripts/ and requirements.txt"
            )
        }
        return Liter8Resources(base: base)
    }

    private static func isValidBase(_ base: URL) -> Bool {
        var isDirectory: ObjCBool = false
        let scripts = base.appendingPathComponent("scripts", isDirectory: true)
        return FileManager.default.fileExists(atPath: scripts.path, isDirectory: &isDirectory)
            && isDirectory.boolValue
            && FileManager.default.fileExists(
                atPath: base.appendingPathComponent("requirements.txt").path
            )
    }
}
