import Darwin
import Foundation
import Liter8Core

/// Runs Liter8's bundled firmware workflow scripts under a Swift-owned entry point.
///
/// The Python scripts still contain valuable, device-tested orchestration for
/// copying firmware, signing IMG4s and modifying the restore ramdisk. Swift
/// marks the child environment with its own executable path; the tiny bridge
/// beside this executable then sends every binary patch request back to Swift.
/// Python therefore remains a workflow helper, not an offset resolver.
enum FirmwareScriptRunner {
    private static let scripts = [
        "boot": "device_boot.py",
        "boot-rd": "device_boot.py",
        "bootstrap": "device_provision.py",
        "capture-ticket": "capture_ticket.py",
        "finalize": "device_provision.py",
        "make-cfw": "make_cfw.py",
        "prepare-rootfs": "rootfs.py",
        "get-boot": "get_boot.py",
        "get-rd": "get_rd.py",
        "restore-cfw": "restore_cfw.py",
        "provision": "device_provision.py",
        "setup-shell": "device_provision.py",
        "unmount-rootfs": "rootfs.py",
        "verify-cfw": "verify_cfw.py",
    ]

    static var actionNames: [String] { scripts.keys.sorted() }

    static func run(
        action: String,
        workDirectory: URL,
        python: String?,
        resourceDirectory: URL? = nil,
        ipswSource: URL? = nil,
        contextFile: URL? = nil,
        ticket: URL? = nil,
        sshrdPayload: URL? = nil,
        workflowEnvironment: [String: String] = [:]
    ) throws {
        guard let scriptName = scripts[action] else {
            throw PatchfinderError.invalidFixture(
                "unknown firmware workflow action \(action); expected \(actionNames.joined(separator: ", "))"
            )
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(
            atPath: workDirectory.path,
            isDirectory: &isDirectory
        ), isDirectory.boolValue else {
            throw PatchfinderError.invalidFixture(
                "firmware work directory does not exist: \(workDirectory.path)"
            )
        }

        // Scripts are immutable application resources. Never load executable
        // code from an extracted IPSW or operator-selected output directory.
        let resources = try Liter8Resources.resolve(override: resourceDirectory)
        let script = resources.scriptsDirectory.appendingPathComponent(scriptName)
        guard FileManager.default.fileExists(atPath: script.path) else {
            throw PatchfinderError.invalidFixture(
                "firmware workflow script is missing: \(script.path)"
            )
        }

        let interpreter = try Liter8PythonRuntime.executable(
            explicit: python,
            resources: resources
        )
        let process = Process()
        process.executableURL = interpreter
        process.arguments = [script.path]

        process.currentDirectoryURL = workDirectory
        var environment = ProcessInfo.processInfo.environment
        // Python patch tables call back into this exact Liter8 executable for
        // binary patching, so the workflow never depends on PATH or a stale build.
        environment["LITER8_SELF"] = try currentExecutable().path
        environment["LITER8_RESOURCE_DIR"] = resources.base.path
        environment["LITER8_FW_ACTION"] = action
        // Bundled helper tools and the selected venv win over unrelated host
        // installations while ordinary system directories remain available.
        let toolPaths = [
            interpreter.deletingLastPathComponent().path,
            resources.toolsDirectory.path,
        ]
        environment["PATH"] = (toolPaths + [environment["PATH"] ?? ""]) .joined(separator: ":")
        if let ipswSource {
            // The manifest above was validated from this exact tree. Override a
            // stale caller value so Python cannot quietly copy another IPSW via
            // its legacy IPSW_SRC escape hatch.
            environment["IPSW_SRC"] = ipswSource.path
        }
        if let contextFile {
            environment["LITER8_CONTEXT"] = contextFile.path
        }
        if let ticket {
            guard FileManager.default.fileExists(atPath: ticket.path) else {
                throw PatchfinderError.invalidFixture("AP ticket does not exist: \(ticket.path)")
            }
            environment["LITER8_AP_TICKET"] = ticket.path
        }
        if let sshrdPayload {
            guard FileManager.default.fileExists(atPath: sshrdPayload.path) else {
                throw PatchfinderError.invalidFixture(
                    "SSHRD payload does not exist: \(sshrdPayload.path)"
                )
            }
            environment["LITER8_SSHRD_PAYLOAD"] = sshrdPayload.path
        }
        // Device actions have a few transport-specific settings. Keep them in
        // the child environment so the generic Python helpers remain callable
        // from the same Swift-owned workflow boundary as artifact builders.
        for (name, value) in workflowEnvironment {
            environment[name] = value
        }
        process.environment = environment

        // Inherit the terminal handles. Python progress and the records printed
        // by the Swift callback appear immediately instead of at process exit.
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError

        print("firmware workflow: \(action)")
        print("  work directory: \(workDirectory.path)")
        print("  resources: \(resources.base.path)")
        print("  python: \(interpreter.path)")
        print("  helper: \(scriptName)")
        fflush(stdout)

        try process.run()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw PatchfinderError.invalidFixture(
                "\(scriptName) exited with status \(process.terminationStatus)"
            )
        }
    }

    /// Resolve the executable itself rather than trusting argv[0] to remain
    /// relative after Python changes or inspects its working directory.
    private static func currentExecutable() throws -> URL {
        if let executable = Bundle.main.executableURL {
            return executable.resolvingSymlinksInPath()
        }
        let argument = URL(fileURLWithPath: CommandLine.arguments[0])
        return argument.absoluteURL.resolvingSymlinksInPath()
    }
}
