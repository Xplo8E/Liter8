import Foundation

/// Resolve every host tool the workflow needs, before any of it runs.
///
/// Without this the tools are discovered one at a time, mid-workflow, so a
/// missing `gtar` surfaces only once SSHRD is being built and a missing
/// `usbliter8ctl` only once the phone is already in DFU. The restore stage
/// erases the device, so finding out late is expensive.
public enum Preflight {
    public enum Stage: String, CaseIterable, Sendable {
        /// Needed to turn an IPSW into patched artifacts.
        case build
        /// Needed only once a phone is attached.
        case device
    }

    public struct Tool: Sendable {
        public let names: [String]
        public let stage: Stage
        public let purpose: String
        public let installHint: String

        /// Several names means the tool is known under any of them, Homebrew's
        /// `gtimeout` and GNU's `timeout` being the same program.
        init(_ names: [String], _ stage: Stage, _ purpose: String, _ installHint: String) {
            self.names = names
            self.stage = stage
            self.purpose = purpose
            self.installHint = installHint
        }
    }

    public struct Result: Sendable {
        public let tool: Tool
        public let resolved: URL?

        public var isSatisfied: Bool { resolved != nil }
    }

    /// Every externally installed tool the workflow shells out to.
    ///
    /// macOS system binaries such as `hdiutil`, `codesign` and `unzip` are not
    /// listed: they ship with the OS at a fixed path and cannot go missing
    /// without the host being broken in ways this check cannot help with.
    public static let tools: [Tool] = [
        Tool(["7zz"], .build,
             "IPSW extraction",
             "brew install sevenzip"),
        Tool(["ipsw"], .build,
             "firmware component handling",
             "brew install blacktop/tap/ipsw"),
        Tool(["aea"], .build,
             "decrypting the Apple Encrypted Archive root filesystem",
             "ships with macOS 14 and later"),
        Tool(["gtar"], .build,
             "SSHRD payload extraction with GNU semantics",
             "brew install gnu-tar"),
        Tool(["ldid", "ldid_macosx_arm64"], .build,
             "re-signing patched device binaries",
             "bundled in tools/, or brew install ldid"),
        Tool(["usbliter8ctl"], .device,
             "the raw iBSS handoff over USB",
             "bundled in tools/, needs PyUSB"),
        Tool(["timeout", "gtimeout"], .device,
             "bounding device commands that can hang",
             "brew install coreutils"),
    ]

    /// Resolve every tool for the given stages, in declaration order.
    ///
    /// `extraDirectories` must include Liter8's bundled `tools/`, otherwise
    /// tools that ship with the repository are reported missing.
    public static func run(
        stages: Set<Stage> = Set(Stage.allCases),
        extraDirectories: [String] = []
    ) -> [Result] {
        tools
            .filter { stages.contains($0.stage) }
            .map { tool in
                let resolved = tool.names.lazy
                    .compactMap { HostTool.locate($0, extraDirectories: extraDirectories) }
                    .first
                return Result(tool: tool, resolved: resolved)
            }
    }
}
