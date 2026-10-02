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
        let candidates = [bundledToolsDirectory].compactMap { $0 }
            + fromEnvironment
            + homebrewBinaryDirectories
        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }

    static func locate(_ name: String) -> URL? {
        let fileManager = FileManager.default
        for directory in searchPath() {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(name)
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
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
