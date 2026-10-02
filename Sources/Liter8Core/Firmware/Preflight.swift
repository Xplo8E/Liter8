import Foundation

/// Resolve every host tool the workflow needs, before any of it runs.
///
/// Without this the tools are discovered one at a time, mid-workflow, so a
/// missing `gtar` surfaces only once SSHRD is being built and a missing
/// `iproxy` only once the phone is waiting on the other end of a forward. The
/// restore stage erases the device, so finding out late is expensive.
public enum Preflight {
    public enum Stage: String, CaseIterable, Sendable {
        /// Needed to turn an IPSW into patched artifacts.
        case build
        /// Needed once the workflow starts talking to a phone.
        case device
    }

    public struct Tool: Sendable {
        /// Any one of these resolving is enough. Homebrew's `gtimeout` and
        /// GNU's `timeout` are the same program under two names.
        public let names: [String]
        public let stage: Stage
        public let purpose: String
        public let installHint: String

        /// The first of `names` present on this host, or nil.
        func resolve() -> URL? {
            names.lazy.compactMap(HostTool.locate).first
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
    /// `irecovery` is also absent, because it is supplied per command with
    /// `--irecovery` rather than found on the path.
    public static let tools: [Tool] = [
        Tool(
            names: ["7zz"],
            stage: .build,
            purpose: "IPSW extraction",
            installHint: "brew install sevenzip"
        ),
        Tool(
            names: ["ipsw"],
            stage: .build,
            purpose: "firmware component handling",
            installHint: "brew install blacktop/tap/ipsw"
        ),
        Tool(
            names: ["gtar"],
            stage: .build,
            purpose: "SSHRD payload extraction with GNU semantics",
            installHint: "brew install gnu-tar"
        ),
        Tool(
            names: ["ldid", "ldid_macosx_arm64"],
            stage: .build,
            purpose: "re-signing patched device binaries",
            installHint: "bundled in tools/, or brew install ldid"
        ),
        Tool(
            names: ["aea"],
            stage: .device,
            purpose: "decrypting the root filesystem for fw prepare-rootfs",
            installHint: "ships with macOS 14 and later"
        ),
        Tool(
            names: ["usbliter8ctl"],
            stage: .device,
            purpose: "the raw iBSS handoff over USB",
            installHint: "bundled in tools/, needs PyUSB"
        ),
        Tool(
            names: ["iproxy"],
            stage: .device,
            purpose: "forwarding SSH to the phone for bootstrap, provision and finalize",
            installHint: "brew install libimobiledevice"
        ),
        Tool(
            names: ["zstd"],
            stage: .device,
            purpose: "unpacking the Procursus bootstrap archive",
            installHint: "brew install zstd"
        ),
        Tool(
            names: ["timeout", "gtimeout"],
            stage: .device,
            purpose: "bounding device commands that can hang",
            installHint: "brew install coreutils"
        ),
    ]

    /// Resolve every tool for the given stages, in declaration order.
    public static func run(stages: Set<Stage> = Set(Stage.allCases)) -> [Result] {
        tools
            .filter { stages.contains($0.stage) }
            .map { Result(tool: $0, resolved: $0.resolve()) }
    }
}
