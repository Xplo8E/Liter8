import Foundation

/// Locate host command-line tools without assuming where Homebrew put them.
///
/// Homebrew installs to `/opt/homebrew` on Apple Silicon and `/usr/local` on
/// Intel, so a hardcoded prefix works on exactly one of the two machines this
/// project runs on. Resolution therefore walks `PATH` first and falls back to
/// both prefixes, which also covers a login shell whose `PATH` the workflow
/// did not inherit.
enum HostTool {
    /// Checked after `PATH` so an operator's own build still wins.
    static let homebrewBinaryDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    /// Liter8's own `tools/`, resolved once.
    ///
    /// `FirmwareScriptRunner` already prepends this for the Python helpers, so
    /// including it here keeps Swift-side lookups agreeing with what the
    /// workflow actually runs. Without it `usbliter8ctl` and `gtar` read as
    /// missing on a checkout that has them.
    private static let bundledToolsDirectory: String? =
        try? Liter8Resources.resolve().toolsDirectory.path

    /// Every directory searched, in order, with duplicates removed.
    static func searchPath() -> [String] {
        let fromEnvironment = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
            .filter { !$0.isEmpty }
        // PATH first, then Liter8's own tools/, matching how the device
        // scripts resolve: a native install wins, the bundled copy is the
        // fallback. Tools that exist only in tools/ are still found.
        let candidates = fromEnvironment
            + [bundledToolsDirectory].compactMap { $0 }
            + homebrewBinaryDirectories
        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }

    /// `isExecutableFile` only reads the permission bit, so it answers yes for
    /// a binary of the wrong architecture and for one whose dynamic libraries
    /// have moved. `runnable` lets a caller skip those and keep looking, which
    /// is what the device scripts do when a Homebrew copy stops loading.
    static func locate(_ name: String, requiringRunnable runnable: Bool = false) -> URL? {
        let fileManager = FileManager.default
        for directory in searchPath() {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(name)
            guard fileManager.isExecutableFile(atPath: candidate.path) else { continue }
            if !runnable || canExecute(candidate) { return candidate }
        }
        return nil
    }

    /// Can this binary be launched at all on this host?
    ///
    /// Only the spawn is checked. The exit status is ignored because a tool is
    /// free to fail on no arguments, and `ldid` prints its banner and exits 1.
    private static func canExecute(_ executable: URL) -> Bool {
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--version"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return false
        }
        process.waitUntilExit()
        // A dyld or exec failure kills the child with a signal rather than
        // letting it exit, which is how "Bad CPU type" and a missing dylib
        // both present.
        return process.terminationReason == .exit
    }

    /// Same as `locate`, but fails with the install hint and the directories
    /// that were actually searched, so a missing tool is self-diagnosing.
    static func require(_ name: String, installHint: String) throws -> URL {
        guard let found = locate(name) else {
            throw PatchfinderError.invalidFixture(
                """
                required host tool not found: \(name)
                  install it with: \(installHint)
                  searched: \(searchPath().joined(separator: ", "))
                """
            )
        }
        return found
    }
}
