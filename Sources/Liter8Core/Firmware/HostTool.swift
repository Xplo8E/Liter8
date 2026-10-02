import Foundation

/// Locate host command-line tools without assuming where Homebrew put them.
///
/// Homebrew installs to `/opt/homebrew` on Apple Silicon and `/usr/local` on
/// Intel, so a hardcoded prefix works on exactly one of the two machines this
/// project runs on. Resolution therefore walks `PATH` first and falls back to
/// both prefixes, which also covers a login shell whose `PATH` the workflow
/// did not inherit.
public enum HostTool {
    /// Checked after `PATH` so an operator's own build still wins.
    static let homebrewBinaryDirectories = ["/opt/homebrew/bin", "/usr/local/bin"]

    /// Every directory searched, in order, with duplicates removed.
    ///
    /// `extraDirectories` go first so a caller can include Liter8's bundled
    /// `tools/`, which the workflow prepends to `PATH` for its Python helpers
    /// but which is not on the CLI process's own `PATH`.
    public static func searchPath(extraDirectories: [String] = []) -> [String] {
        let fromEnvironment = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
            .filter { !$0.isEmpty }
        var seen = Set<String>()
        return (extraDirectories + fromEnvironment + homebrewBinaryDirectories)
            .filter { seen.insert($0).inserted }
    }

    /// First executable named `name` on the search path, or nil.
    public static func locate(_ name: String, extraDirectories: [String] = []) -> URL? {
        let fileManager = FileManager.default
        for directory in searchPath(extraDirectories: extraDirectories) {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(name)
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    /// Same as `locate`, but fails with the install hint and the directories
    /// that were actually searched, so a missing tool is self-diagnosing.
    public static func require(_ name: String, installHint: String) throws -> URL {
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
