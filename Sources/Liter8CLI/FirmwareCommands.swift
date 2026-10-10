import ArgumentParser
import Foundation
import Liter8Core

// Each firmware action is its own command declaring only the options it accepts.
// That replaces the old pile of "--x is only valid for y" guards: an option that
// does not apply is now rejected by the parser and absent from that action's
// help, rather than accepted and then refused at runtime.

/// Options shared by every firmware action.
struct FirmwareCommonOptions: ParsableArguments {
    @Option(
        name: .customLong("work-dir"),
        help: ArgumentHelp(
            "Firmware work directory. Defaults to $WORK_DIR, then the current directory.",
            valueName: "directory"
        )
    )
    var workDirectory: String?

    @Option(
        name: .customLong("board"),
        help: ArgumentHelp(
            "Board to use when one IPSW supports several, for example d421ap or d431ap.",
            valueName: "device-class"
        )
    )
    var board: String?

    @Flag(
        name: .customLong("experimental"),
        help: "Opt in to a firmware workflow that still needs device validation."
    )
    var experimental = false

    /// Command line first, then `WORK_DIR` for shell automation, then the current
    /// directory as the zero-configuration interactive default.
    var workDirectoryURL: URL {
        let path = workDirectory
            ?? ProcessInfo.processInfo.environment["WORK_DIR"]
            ?? FileManager.default.currentDirectoryPath
        return URL(fileURLWithPath: path).standardizedFileURL
    }
}

/// Options accepted by every action that runs against an already-prepared work
/// directory, which is everything except `prepare`.
struct FirmwarePreparedOptions: ParsableArguments {
    @Option(
        name: .customLong("python"),
        help: ArgumentHelp("Python executable for the bundled workflow scripts.", valueName: "executable")
    )
    var python: String?

    @Option(
        name: .customLong("resource-dir"),
        help: ArgumentHelp("Liter8 resource directory.", valueName: "directory")
    )
    var resourceDirectory: String?

    var resourceDirectoryURL: URL? {
        resourceDirectory.map {
            URL(fileURLWithPath: $0, isDirectory: true).standardizedFileURL
        }
    }
}

/// `--serial`, for the three actions that bake a boot-argument literal into an
/// artifact. Accepting it elsewhere would look like it had an effect.
struct SerialConsoleOption: ParsableArguments {
    @Flag(
        name: .customLong("serial"),
        help: """
        Add serial=3 to the boot arguments of the artifact being built. Off by \
        default: it moves the kernel console to the UART and the device screen \
        stops showing the verbose boot log.
        """
    )
    var serialConsole = false

    var environment: [String: String] {
        serialConsole ? [SerialConsole.environmentKey: "1"] : [:]
    }
}

struct APDemotionOption: ParsableArguments {
    @Flag(
        name: .customLong("demote-ap"),
        help: """
        DOES NOT BOOT, kept for research only. Makes the device claim a demoted \
        application processor so libFDR skips its SEP-attested sik check and \
        baseband calibration can unseal. Measured on n104ap 24B5099f: panics in \
        early kernel init with an LLC PIO error before the OS version is even \
        published. Faking one term of a security state the driver stack reads as \
        a consistent set does not work. See docs/design/BASEBAND_AND_CELLULAR.md.
        """
    )
    var demoteAP = false

    var environment: [String: String] {
        demoteAP ? [APDemotion.environmentKey: "1"] : [:]
    }
}

/// Shared execution path for the prepared actions.
func runPreparedFirmwareAction(
    _ action: String,
    common: FirmwareCommonOptions,
    prepared: FirmwarePreparedOptions,
    ticket: URL? = nil,
    sshrdPayload: String? = nil,
    environment: [String: String] = [:]
) throws {
    try FirmwareWorkflowRunner.runPreparedAction(
        action,
        workDirectory: common.workDirectoryURL,
        python: prepared.python,
        resourceDirectory: prepared.resourceDirectoryURL,
        ticket: ticket,
        sshrdPayload: sshrdPayload.map {
            URL(fileURLWithPath: $0).standardizedFileURL
        },
        includeExperimental: common.experimental,
        board: common.board,
        workflowEnvironment: environment
    )
}

/// Resolve the APTicket for the two actions that need one.
///
/// Deliberately never names `fw restore-cfw`: an erase restore is one way to
/// obtain a ticket, not a prerequisite for either action, and `get-rd` in
/// particular runs over an already installed OS.
func resolveAPTicket(
    explicit: String?,
    action: String,
    workDirectory: URL
) throws -> URL {
    let candidate = explicit.map { URL(fileURLWithPath: $0).standardizedFileURL }
        ?? workDirectory.appendingPathComponent("apticket.im4m")
    guard FileManager.default.fileExists(atPath: candidate.path) else {
        let detail = explicit == nil
            ? "pass --ticket <apticket.im4m>, or place one at \(candidate.path)"
            : "no APTicket at \(candidate.path)"
        throw PatchfinderError.invalidFixture(
            "fw \(action) needs an APTicket: \(detail). An erase restore is "
                + "one way to obtain one, not a prerequisite"
        )
    }
    return candidate
}

struct Firmware: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fw",
        abstract: "Firmware preparation and the device workflow.",
        discussion: """
        Runs in this order for a fresh device: prepare, make-cfw, restore-cfw, \
        get-rd, boot-rd, provision, get-boot, boot, finalize. `liter8 fw actions` \
        lists the action names a script can pass.
        """,
        subcommands: [
            Actions.self,
            Prepare.self,
            PrepareRootfs.self,
            UnmountRootfs.self,
            MakeCFW.self,
            CaptureTicket.self,
            GetRD.self,
            GetBoot.self,
            VerifyCFW.self,
            RestoreCFW.self,
            BootRD.self,
            Boot.self,
            Bootstrap.self,
            Provision.self,
            Finalize.self,
            SetupShell.self,
            SetupDebugger.self,
        ]
    )

    struct Actions: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List the firmware action names, one per line."
        )

        func run() throws {
            FirmwareWorkflowRunner.actionNames.forEach { print($0) }
        }
    }

    struct Prepare: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Extract an IPSW into a work directory.",
            discussion: """
            Accepts only --file, --work-dir, --board and --experimental. The other \
            firmware options apply to an already-prepared work directory.
            """
        )

        @Option(
            name: .customLong("file"),
            help: ArgumentHelp("IPSW to prepare. Defaults to $IPSW_FILE.", valueName: "firmware.ipsw")
        )
        var file: String?

        @OptionGroup var common: FirmwareCommonOptions

        func run() throws {
            // An explicit option always wins. The environment fallback is useful
            // for scripts and CI without making an ambiguous directory scan part
            // of firmware selection.
            guard let file = file ?? ProcessInfo.processInfo.environment["IPSW_FILE"],
                  !file.isEmpty else {
                throw PatchfinderError.invalidFixture(
                    "fw prepare requires --file <firmware.ipsw> or IPSW_FILE"
                )
            }
            try FirmwareWorkflowRunner.run(
                file: URL(fileURLWithPath: file).standardizedFileURL,
                workDirectory: common.workDirectoryURL,
                includeExperimental: common.experimental,
                board: common.board
            )
        }
    }

    struct PrepareRootfs: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "prepare-rootfs",
            abstract: "Decrypt and mount the root filesystem image."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            try runPreparedFirmwareAction("prepare-rootfs", common: common, prepared: prepared)
        }
    }

    struct UnmountRootfs: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "unmount-rootfs",
            abstract: "Unmount the root filesystem image."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            try runPreparedFirmwareAction("unmount-rootfs", common: common, prepared: prepared)
        }
    }

    struct MakeCFW: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "make-cfw",
            abstract: "Patch the extracted firmware into a custom IPSW."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var serial: SerialConsoleOption

        func run() throws {
            try runPreparedFirmwareAction(
                "make-cfw", common: common, prepared: prepared,
                environment: serial.environment
            )
        }
    }

    struct CaptureTicket: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "capture-ticket",
            abstract: "Capture the device's APTicket during a restore."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            try runPreparedFirmwareAction("capture-ticket", common: common, prepared: prepared)
        }
    }

    struct GetRD: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get-rd",
            abstract: "Build the signed SSH ramdisk boot set."
        )

        @Option(
            name: .customLong("ticket"),
            help: ArgumentHelp(
                "APTicket to sign with. Defaults to apticket.im4m in the work directory.",
                valueName: "apticket.im4m"
            )
        )
        var ticket: String?

        @Option(
            name: .customLong("sshrd-payload"),
            help: ArgumentHelp("SSH payload archive to place in the ramdisk.", valueName: "ssh.tar.gz")
        )
        var sshrdPayload: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var serial: SerialConsoleOption

        func run() throws {
            let resolved = try resolveAPTicket(
                explicit: ticket, action: "get-rd", workDirectory: common.workDirectoryURL
            )
            try runPreparedFirmwareAction(
                "get-rd", common: common, prepared: prepared,
                ticket: resolved, sshrdPayload: sshrdPayload,
                environment: serial.environment
            )
        }
    }

    struct GetBoot: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get-boot",
            abstract: "Build the signed normal-boot artifact set."
        )

        @Option(
            name: .customLong("ticket"),
            help: ArgumentHelp(
                "APTicket to sign with. Defaults to apticket.im4m in the work directory.",
                valueName: "apticket.im4m"
            )
        )
        var ticket: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var serial: SerialConsoleOption
        @OptionGroup var demotion: APDemotionOption

        func run() throws {
            let resolved = try resolveAPTicket(
                explicit: ticket, action: "get-boot", workDirectory: common.workDirectoryURL
            )
            // get-boot builds the normal-boot iBoot and DeviceTree, which is
            // where both halves of the demotion claim live.
            try runPreparedFirmwareAction(
                "get-boot", common: common, prepared: prepared,
                ticket: resolved,
                environment: serial.environment.merging(demotion.environment) { _, new in new }
            )
        }
    }

    struct VerifyCFW: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "verify-cfw",
            abstract: "Re-verify the patched artifacts in the work directory."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            try runPreparedFirmwareAction("verify-cfw", common: common, prepared: prepared)
        }
    }

    struct RestoreCFW: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "restore-cfw",
            abstract: "Erase-restore the device with the custom IPSW."
        )

        @Option(
            name: .customLong("idevicerestore"),
            help: ArgumentHelp("idevicerestore executable to use.", valueName: "executable")
        )
        var idevicerestore: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            var environment: [String: String] = [:]
            if let idevicerestore {
                environment["LITER8_IDEVICERESTORE"] = idevicerestore
            }
            try runPreparedFirmwareAction(
                "restore-cfw", common: common, prepared: prepared, environment: environment
            )
        }
    }

    struct BootRD: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "boot-rd",
            abstract: "Boot the SSH ramdisk over the tethered transport."
        )

        @Option(
            name: .customLong("irecovery"),
            help: ArgumentHelp("irecovery executable to use.", valueName: "executable")
        )
        var irecovery: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            var environment: [String: String] = [:]
            if let irecovery { environment["LITER8_IRECOVERY"] = irecovery }
            try runPreparedFirmwareAction(
                "boot-rd", common: common, prepared: prepared, environment: environment
            )
        }
    }

    struct Boot: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Boot the device normally with the patched firmware."
        )

        @Option(
            name: .customLong("irecovery"),
            help: ArgumentHelp("irecovery executable to use.", valueName: "executable")
        )
        var irecovery: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions

        func run() throws {
            var environment: [String: String] = [:]
            if let irecovery { environment["LITER8_IRECOVERY"] = irecovery }
            try runPreparedFirmwareAction(
                "boot", common: common, prepared: prepared, environment: environment
            )
        }
    }

    /// `--check` reports state without changing the device.
    struct CheckOnlyOption: ParsableArguments {
        @Flag(
            name: .customLong("check"),
            help: "Report what this stage would do, and change nothing."
        )
        var checkOnly = false

        var environment: [String: String] {
            checkOnly ? ["LITER8_CHECK_ONLY": "1"] : [:]
        }
    }

    struct Bootstrap: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Extract the rootless Procursus bootstrap."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var check: CheckOnlyOption

        func run() throws {
            try runPreparedFirmwareAction(
                "bootstrap", common: common, prepared: prepared, environment: check.environment
            )
        }
    }

    struct Provision: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Provision the mounted root filesystem from SSHRD."
        )

        @Option(
            name: .customLong("rootfs"),
            help: ArgumentHelp(
                "Mounted root filesystem to provision. Normally recorded by prepare-rootfs.",
                valueName: "directory"
            )
        )
        var rootfs: String?

        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var check: CheckOnlyOption

        func run() throws {
            var environment = check.environment
            if let rootfs { environment["IPSW_ROOT"] = rootfs }
            try runPreparedFirmwareAction(
                "provision", common: common, prepared: prepared, environment: environment
            )
        }
    }

    struct Finalize: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Finish the bootstrap after the first normal boot."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var check: CheckOnlyOption

        func run() throws {
            try runPreparedFirmwareAction(
                "finalize", common: common, prepared: prepared, environment: check.environment
            )
        }
    }

    struct SetupShell: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "setup-shell",
            abstract: "Make the device's SSH shell usable."
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var check: CheckOnlyOption

        func run() throws {
            try runPreparedFirmwareAction(
                "setup-shell", common: common, prepared: prepared, environment: check.environment
            )
        }
    }

    struct SetupDebugger: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "setup-debugger",
            abstract: "Install debugserver and the TrollStore helper.",
            discussion: """
            Optional, and not part of the jailbreak. The device needs internet, \
            because apt resolves the dependencies there. Use `breakpoint set -H` \
            once installed: software breakpoints are silently dropped on this \
            platform. See docs/design/DEBUGGING_PLATFORM_DAEMONS.md.
            """
        )
        @OptionGroup var common: FirmwareCommonOptions
        @OptionGroup var prepared: FirmwarePreparedOptions
        @OptionGroup var check: CheckOnlyOption

        func run() throws {
            try runPreparedFirmwareAction(
                "setup-debugger", common: common, prepared: prepared, environment: check.environment
            )
        }
    }
}
