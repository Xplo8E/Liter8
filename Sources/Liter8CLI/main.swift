import Darwin
import Foundation
import Liter8Core

private func usage() -> Never {
    FileHandle.standardError.write(Data("""
    usage:
      liter8 resolve <component> <plan> <input> [options]
      liter8 apply <component> <plan> <input> <output> [options]
      liter8 fw <actions|prepare|prepare-rootfs|unmount-rootfs|make-cfw|capture-ticket|get-rd|get-boot|verify-cfw|restore-cfw|boot-rd|boot|bootstrap|provision|finalize|setup-shell> [options]
      liter8 profile <binary>
      liter8 profiles
      liter8 fixture <component> <plan> <input> <manifest.json>
          --device <name> --board <board> --build <build>
          --component-name <component> [--boot-args <literal>]
      liter8 inspect <binary> segments
      liter8 inspect <binary> strings <text>
      liter8 inspect <binary> objc-methods <selector> [words]
      liter8 inspect <binary> <xrefs|func|calls> <offset>
      liter8 inspect <binary> dis <offset> [words]
      liter8 inspect <binary> pattern <word[/mask]> ...
      liter8 inspect <binary> pattern-at <offset> <word[/mask]> ...
      liter8 verify <manifest.json> <binary>
      liter8 im4p <info|extract|repack> ...
      liter8 img4 create <input.im4p> <ticket.im4m> <output.img4> [--fourcc <type>]
      liter8 setup [--resource-dir <directory>]

    components and plans:
      iboot       ibss-validate, ibss-bootargs, ibss-normal, ibss-restore,
                  ibss-ramdisk, ibss-skip-display-init,
                  ibec-ignore-pinot-failure, ibec-force-pinot-id
      kernel      restore, boot-policy, aks, sep-silence, sep,
                  credential-manager, sandbox, boot, boot-public, diagnostic
      txm         restore, boot
      userland    restored-fdr, asr, coreauthd, ctkd, mobileactivationd
      devicetree  restore, normal

    options:
      --json  --boot-args <literal>  --pinot-id <value>
      --file <firmware.ipsw>  --work-dir <directory>  --python <executable>
      --experimental  opt in to a firmware workflow that still needs device validation
      --resource-dir <directory>  --ticket <apticket.im4m>
      --sshrd-payload <ssh.tar.gz>
      --irecovery <custom-irecovery>  --idevicerestore <executable>
      --rootfs <mounted-root-filesystem>  --check
      --records-out <records.json>  write records from the same apply operation

    """.utf8))
    exit(2)
}

private struct ResolverOptions {
    var bootArguments: String?
    var panelID: UInt32?
    var json = false
    var recordsOutput: URL?
}

/// Keep the public CLI small while retaining descriptive internal resolver
/// names and fixture IDs. Adding a plan is one table entry, not another command
/// parser branch or usage line.
private let resolverGroups: [String: [String: String]] = [
    "iboot": [
        "ibss-validate": IBSSValidateResolver.name,
        "ibss-bootargs": IBSSBootArgsResolver.name,
        "ibss-normal": IBSSNormalResolver.name,
        "ibss-restore": IBSSRestoreResolver.name,
        "ibss-ramdisk": IBSSRamdiskResolver.name,
        "ibss-skip-display-init": IBSSSkipDisplayInitResolver.name,
        "ibec-ignore-pinot-failure": IBECPinotIgnoreFailureResolver.name,
        "ibec-force-pinot-id": IBECPinotForceIDResolver.name,
    ],
    "kernel": [
        "restore": KernelRestoreResolver.name,
        "boot-policy": KernelBootPolicyResolver.name,
        "aks": KernelAKSResolver.name,
        "sep-silence": KernelSEPSilenceResolver.name,
        "sep": KernelSEPResolver.name,
        "credential-manager": KernelCredentialManagerResolver.name,
        "sandbox": KernelSandboxResolver.name,
        "boot": KernelBootResolver.name,
        // Keep the public CLI spelling stable while the Swift type describes
        // the plan's real cross-build compatibility contract.
        "boot-public": KernelBootCompatibilityResolver.name,
        "diagnostic": KernelDiagnosticResolver.name,
    ],
    "txm": [
        "restore": TXMRestoreResolver.name,
        "boot": TXMBootResolver.name,
    ],
    "userland": [
        "restored-fdr": RestoredExternalResolver.name,
        "asr": ASRSignatureResolver.name,
        "coreauthd": CoreAuthDResolver.name,
        "ctkd": CTKDResolver.name,
        "mobileactivationd": MobileActivationDResolver.name,
    ],
    "devicetree": [
        "restore": DeviceTreePatchPlan.restore.rawValue,
        "normal": DeviceTreePatchPlan.normal.rawValue,
    ],
]

private func resolverName(component: String, plan: String) -> String? {
    resolverGroups[component]?[plan]
}

/// Parse only the two resolver options we currently support. Keeping this tiny
/// avoids hiding patch semantics behind a command framework while the research
/// interface is still changing.
private func parseResolverOptions(
    _ arguments: ArraySlice<String>,
    allowJSON: Bool,
    allowRecordsOutput: Bool = false
) -> ResolverOptions {
    var options = ResolverOptions()
    var index = arguments.startIndex
    while index < arguments.endIndex {
        switch arguments[index] {
        case "--json" where allowJSON:
            options.json = true
            index += 1
        case "--boot-args":
            let valueIndex = arguments.index(after: index)
            guard valueIndex < arguments.endIndex else { usage() }
            options.bootArguments = arguments[valueIndex]
            index = arguments.index(after: valueIndex)
        case "--pinot-id":
            let valueIndex = arguments.index(after: index)
            guard valueIndex < arguments.endIndex else { usage() }
            let text = arguments[valueIndex]
            let value: UInt32?
            if text.hasPrefix("0x") || text.hasPrefix("0X") {
                value = UInt32(text.dropFirst(2), radix: 16)
            } else {
                value = UInt32(text, radix: 10)
            }
            guard let value else { usage() }
            options.panelID = value
            index = arguments.index(after: valueIndex)
        case "--records-out" where allowRecordsOutput:
            let valueIndex = arguments.index(after: index)
            guard valueIndex < arguments.endIndex else { usage() }
            options.recordsOutput = URL(fileURLWithPath: arguments[valueIndex])
                .standardizedFileURL
            index = arguments.index(after: valueIndex)
        default:
            usage()
        }
    }
    return options
}

/// Dispatch a named semantic resolver. The known-offset fixture registry lives
/// elsewhere and is intentionally not reachable from this function.
private func resolveRecords(
    named name: String,
    in image: BinaryImage,
    options: ResolverOptions
) throws -> [PatchRecord] {
    switch name {
    case IBSSValidateResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBSSValidateResolver().resolve(in: image)
    case IBSSBootArgsResolver.name:
        guard options.panelID == nil else { usage() }
        return try IBSSBootArgsResolver(
            bootArguments: options.bootArguments ?? IBSSBootArgsResolver.normalBootArguments
        ).resolve(in: image)
    case IBSSNormalResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBSSNormalResolver().resolve(in: image)
    case IBSSRestoreResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBSSRestoreResolver().resolve(in: image)
    case IBSSRamdiskResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBSSRamdiskResolver().resolve(in: image)
    case RestoredExternalResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try RestoredExternalResolver().resolve(in: image)
    case ASRSignatureResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try ASRSignatureResolver().resolve(in: image)
    case TXMRestoreResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try TXMRestoreResolver().resolve(in: image)
    case TXMBootResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try TXMBootResolver().resolve(in: image)
    case CoreAuthDResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try CoreAuthDResolver().resolve(in: image)
    case CTKDResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try CTKDResolver().resolve(in: image)
    case MobileActivationDResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try MobileActivationDResolver().resolve(in: image)
    case IBSSSkipDisplayInitResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBSSSkipDisplayInitResolver().resolve(in: image)
    case IBECPinotIgnoreFailureResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try IBECPinotIgnoreFailureResolver().resolve(in: image)
    case IBECPinotForceIDResolver.name:
        guard options.bootArguments == nil, let panelID = options.panelID else { usage() }
        return try IBECPinotForceIDResolver(panelID: panelID).resolve(in: image)
    case KernelRestoreResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelRestoreResolver().resolve(in: image)
    case KernelBootPolicyResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelBootPolicyResolver().resolve(in: image)
    case KernelAKSResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelAKSResolver().resolve(in: image)
    case KernelSEPSilenceResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelSEPSilenceResolver().resolve(in: image)
    case KernelSEPResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelSEPResolver().resolve(in: image)
    case KernelCredentialManagerResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelCredentialManagerResolver().resolve(in: image)
    case KernelSandboxResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelSandboxResolver().resolve(in: image)
    case KernelBootResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelBootResolver().resolve(in: image)
    case KernelBootCompatibilityResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelBootCompatibilityResolver().resolve(in: image)
    case KernelDiagnosticResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelDiagnosticResolver().resolve(in: image)
    default:
        usage()
    }
}

/// Accept `0x`-prefixed and decimal literals alike. Research notes quote file
/// offsets in hexadecimal, while some tables carry plain decimal.
private func parseNumber(_ text: String) -> UInt64? {
    if text.hasPrefix("0x") || text.hasPrefix("0X") {
        return UInt64(text.dropFirst(2), radix: 16)
    }
    return UInt64(text, radix: 10)
}

private func hex(_ value: UInt64) -> String { String(format: "0x%llx", value) }

/// Parse `<word>` or `<word>/<mask>` signature arguments. A bare word is
/// compared in full, which is how a freshly transcribed reference signature
/// behaves before any field is deliberately relaxed.
private func parseMaskedWords(_ arguments: [String]) -> (values: [UInt32], masks: [UInt32])? {
    var values: [UInt32] = []
    var masks: [UInt32] = []
    for argument in arguments {
        let parts = argument.split(separator: "/", maxSplits: 1)
        guard let rawWord = parseNumber(String(parts[0])) else { return nil }
        var mask = UInt32.max
        if parts.count > 1 {
            guard let rawMask = parseNumber(String(parts[1])) else { return nil }
            mask = UInt32(truncatingIfNeeded: rawMask)
        }
        values.append(UInt32(truncatingIfNeeded: rawWord) & mask)
        masks.append(mask)
    }
    return (values, masks)
}

private func printRecords(_ records: [PatchRecord], json: Bool) throws {
    if json {
        print(String(decoding: try encodedRecords(records), as: UTF8.self), terminator: "")
    } else {
        for record in records {
            print(String(
                format: "%@ %@: 0x%llx %@ -> %@",
                record.component,
                record.id,
                record.offset,
                record.originalBytes.hexadecimalString,
                record.replacementBytes.hexadecimalString
            ))
        }
    }
}

/// Encode the stable machine-readable record format used by `resolve --json`
/// and `apply --records-out`. Keeping one encoder prevents the workflow's
/// evidence file from drifting away from the interactive resolver output.
private func encodedRecords(_ records: [PatchRecord]) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    var data = try encoder.encode(records)
    data.append(0x0A)
    return data
}

private func deviceTreePlan(named name: String) -> DeviceTreePatchPlan? {
    DeviceTreePatchPlan(rawValue: name)
}

private func printDeviceTreeChanges(_ changes: [DeviceTreeChange]) {
    for change in changes {
        print("devicetree \(change.operation): \(change.path) [\(change.disposition.rawValue)]")
    }
}

/// Print profile selection before a potentially long kernel scan. This goes to
/// stderr so `--json` keeps stdout machine-readable. Unlike resolved records,
/// this write happens before scanning, so terminal users immediately see what
/// the tool selected instead of staring at a silent process.
private func reportProfile(
    for image: BinaryImage,
    resolver: String,
    handle: FileHandle = .standardError
) {
    guard resolver.hasPrefix("kernel-") else { return }
    guard let profile = KernelResolverProfileRegistry.detect(in: image) else {
        handle.write(Data("firmware profile: unidentified\n".utf8))
        return
    }

    var lines = [
        "firmware profile: \(profile.id)",
        "  iOS/build: \(profile.productVersion) (\(profile.build))",
        "  boards: \(profile.boards.joined(separator: ", "))",
        "  component: \(profile.component)",
    ]
    if let variants = profile.variants(for: resolver) {
        lines.append("  signature variant: \(variants.signature) [\(variants.support.rawValue)]")
        lines.append("  payload variant: \(variants.payload)")
    } else {
        // Most kernel plans discover their sites from semantic anchors and
        // validate the original instructions before patching. They therefore
        // do not need a firmware-specific signature/payload variant entry.
        lines.append("  variant selection: generic semantic resolver")
    }
    handle.write(Data((lines.joined(separator: "\n") + "\n").utf8))
}

private func printProfile(_ profile: KernelResolverProfile) {
    print("\(profile.id): iOS \(profile.productVersion), build \(profile.build)")
    print("  boards: \(profile.boards.joined(separator: ", "))")
    print("  component: \(profile.component)")
    for resolver in profile.resolverVariants.keys.sorted() {
        guard let variants = profile.resolverVariants[resolver] else { continue }
        print("  \(resolver): signatures=\(variants.signature), payload=\(variants.payload), status=\(variants.support.rawValue)")
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let command = arguments.first else { usage() }

    switch command {
    case "setup":
        var resourceDirectory: URL?
        if arguments.count == 3, arguments[1] == "--resource-dir" {
            resourceDirectory = URL(
                fileURLWithPath: arguments[2],
                isDirectory: true
            ).standardizedFileURL
        } else if arguments.count != 1 {
            usage()
        }
        let resources = try Liter8Resources.resolve(override: resourceDirectory)
        let python = try Liter8PythonRuntime.executable(
            explicit: nil,
            resources: resources
        )
        print("Liter8 resources: \(resources.base.path)")
        print("Liter8 Python: \(python.path)")

    case "fw":
        guard arguments.count >= 2 else { usage() }
        let action = arguments[1]
        if action == "actions" {
            guard arguments.count == 2 else { usage() }
            FirmwareWorkflowRunner.actionNames.forEach { print($0) }
            break
        }
        guard FirmwareWorkflowRunner.actionNames.contains(action) else { usage() }

        var fileArgument: String?
        var workDirectoryArgument: String?
        var python: String?
        var resourceDirectoryArgument: String?
        var ticketArgument: String?
        var sshrdPayloadArgument: String?
        var irecoveryArgument: String?
        var idevicerestoreArgument: String?
        var rootfsArgument: String?
        var checkOnly = false
        var includeExperimental = false
        var index = 2
        while index < arguments.count {
            if arguments[index] == "--check" {
                checkOnly = true
                index += 1
                continue
            }
            if arguments[index] == "--experimental" {
                includeExperimental = true
                index += 1
                continue
            }
            guard index + 1 < arguments.count else { usage() }
            switch arguments[index] {
            case "--file":
                fileArgument = arguments[index + 1]
            case "--work-dir":
                workDirectoryArgument = arguments[index + 1]
            case "--python":
                python = arguments[index + 1]
            case "--resource-dir":
                resourceDirectoryArgument = arguments[index + 1]
            case "--ticket":
                ticketArgument = arguments[index + 1]
            case "--sshrd-payload":
                sshrdPayloadArgument = arguments[index + 1]
            case "--irecovery":
                irecoveryArgument = arguments[index + 1]
            case "--idevicerestore":
                idevicerestoreArgument = arguments[index + 1]
            case "--rootfs":
                rootfsArgument = arguments[index + 1]
            default:
                usage()
            }
            index += 2
        }

        // Command-line input is the most explicit choice. WORK_DIR keeps shell
        // automation readable, while the current directory remains the useful
        // zero-configuration default for an interactive run.
        let workDirectory = workDirectoryArgument
            ?? ProcessInfo.processInfo.environment["WORK_DIR"]
            ?? FileManager.default.currentDirectoryPath
        let workDirectoryURL = URL(fileURLWithPath: workDirectory).standardizedFileURL
        if action == "prepare" {
            guard python == nil,
                  resourceDirectoryArgument == nil,
                  ticketArgument == nil,
                  sshrdPayloadArgument == nil,
                  irecoveryArgument == nil,
                  idevicerestoreArgument == nil,
                  rootfsArgument == nil,
                  !checkOnly else {
                throw PatchfinderError.invalidFixture(
                    "fw prepare accepts only --file, --work-dir and --experimental"
                )
            }
            // An explicit option always wins. The environment fallback is useful
            // for scripts and CI without making an ambiguous directory scan part
            // of firmware selection.
            guard let file = fileArgument ?? ProcessInfo.processInfo.environment["IPSW_FILE"],
                  !file.isEmpty else {
                throw PatchfinderError.invalidFixture(
                    "fw prepare requires --file <firmware.ipsw> or IPSW_FILE"
                )
            }
            try FirmwareWorkflowRunner.run(
                file: URL(fileURLWithPath: file).standardizedFileURL,
                workDirectory: workDirectoryURL,
                includeExperimental: includeExperimental
            )
        } else {
            guard fileArgument == nil else { usage() }
            let ticketActions: Set<String> = ["get-boot", "get-rd"]
            guard ticketArgument == nil || ticketActions.contains(action) else {
                throw PatchfinderError.invalidFixture(
                    "--ticket is only valid for fw get-boot and fw get-rd"
                )
            }
            let selectedTicket: URL?
            if ticketActions.contains(action) {
                let candidate = ticketArgument.map {
                    URL(fileURLWithPath: $0).standardizedFileURL
                } ?? workDirectoryURL.appendingPathComponent("apticket.im4m")
                guard FileManager.default.fileExists(atPath: candidate.path) else {
                    throw PatchfinderError.invalidFixture(
                        "fw \(action) needs \(candidate.path); run fw restore-cfw or fw capture-ticket first"
                    )
                }
                selectedTicket = candidate
            } else {
                selectedTicket = nil
            }
            guard sshrdPayloadArgument == nil || action == "get-rd" else {
                throw PatchfinderError.invalidFixture(
                    "--sshrd-payload is only valid for fw get-rd"
                )
            }
            let bootActions: Set<String> = ["boot", "boot-rd"]
            guard irecoveryArgument == nil || bootActions.contains(action) else {
                throw PatchfinderError.invalidFixture(
                    "--irecovery is only valid for fw boot and fw boot-rd"
                )
            }
            guard idevicerestoreArgument == nil || action == "restore-cfw" else {
                throw PatchfinderError.invalidFixture(
                    "--idevicerestore is only valid for fw restore-cfw"
                )
            }
            let provisioningActions: Set<String> = ["bootstrap", "provision", "finalize", "setup-shell"]
            guard rootfsArgument == nil || action == "provision" else {
                throw PatchfinderError.invalidFixture(
                    "--rootfs is only valid for fw provision"
                )
            }
            guard !checkOnly || provisioningActions.contains(action) else {
                throw PatchfinderError.invalidFixture(
                    "--check is only valid for bootstrap, provision, finalize and setup-shell"
                )
            }
            var workflowEnvironment: [String: String] = [:]
            if let irecoveryArgument {
                workflowEnvironment["LITER8_IRECOVERY"] = irecoveryArgument
            }
            if let idevicerestoreArgument {
                workflowEnvironment["LITER8_IDEVICERESTORE"] = idevicerestoreArgument
            }
            if let rootfsArgument {
                workflowEnvironment["IPSW_ROOT"] = rootfsArgument
            }
            if checkOnly {
                workflowEnvironment["LITER8_CHECK_ONLY"] = "1"
            }
            try FirmwareWorkflowRunner.runPreparedAction(
                action,
                workDirectory: workDirectoryURL,
                python: python,
                resourceDirectory: resourceDirectoryArgument.map {
                    URL(fileURLWithPath: $0, isDirectory: true).standardizedFileURL
                },
                ticket: selectedTicket,
                sshrdPayload: sshrdPayloadArgument.map {
                    URL(fileURLWithPath: $0).standardizedFileURL
                },
                includeExperimental: includeExperimental,
                workflowEnvironment: workflowEnvironment
            )
        }

    case "resolve":
        guard arguments.count >= 4,
              let resolver = resolverName(component: arguments[1], plan: arguments[2]) else {
            usage()
        }
        let options = parseResolverOptions(arguments.dropFirst(4), allowJSON: true)
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: arguments[3]))
        if let plan = deviceTreePlan(named: resolver) {
            guard !options.json, options.bootArguments == nil, options.panelID == nil else { usage() }
            try artifact.requireIM4PFourCC("dtre")
            let result = try DeviceTreePatcher.patch(artifact.payload, plan: plan)
            printDeviceTreeChanges(result.changes)
            print("payload size: \(artifact.payload.count) -> \(result.data.count) (\(result.data.count - artifact.payload.count >= 0 ? "+" : "")\(result.data.count - artifact.payload.count))")
            break
        }
        let image = BinaryImage(data: artifact.payload)
        reportProfile(for: image, resolver: resolver)
        let records = try resolveRecords(named: resolver, in: image, options: options)
        try printRecords(records, json: options.json)

    case "profile":
        guard arguments.count == 2 else { usage() }
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: arguments[1]))
        let image = BinaryImage(data: artifact.payload)
        guard let profile = KernelResolverProfileRegistry.detect(in: image) else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: "profile",
                profile: "unidentified",
                variant: "none"
            )
        }
        printProfile(profile)

    case "profiles":
        guard arguments.count == 1 else { usage() }
        for (index, profile) in KernelResolverProfileRegistry.profiles.enumerated() {
            if index > 0 { print("") }
            printProfile(profile)
        }

    case "fixture":
        // Emit an exact-build oracle for one resolver.
        //
        // The manifest has to bind the clean input hash, every resolved record,
        // and the complete patched-output hash. Producing that by hand invites
        // transcription errors in exactly the values a fixture exists to pin,
        // so it is generated from the same resolver and the same
        // GuardedPatchApplier the CLI uses everywhere else. Firmware identity
        // stays explicit: a fixture asserts which build it describes, and
        // guessing that would defeat the point.
        guard arguments.count >= 5,
              let resolver = resolverName(component: arguments[1], plan: arguments[2]) else {
            usage()
        }
        let inputURL = URL(fileURLWithPath: arguments[3]).standardizedFileURL
        let outputURL = URL(fileURLWithPath: arguments[4]).standardizedFileURL

        var device: String?
        var board: String?
        var build: String?
        var componentName: String?
        var index = 5
        var passthrough: [String] = []
        while index < arguments.count {
            guard index + 1 < arguments.count else { usage() }
            switch arguments[index] {
            case "--device": device = arguments[index + 1]
            case "--board": board = arguments[index + 1]
            case "--build": build = arguments[index + 1]
            case "--component-name": componentName = arguments[index + 1]
            case "--boot-args", "--pinot-id":
                passthrough.append(arguments[index])
                passthrough.append(arguments[index + 1])
            default: usage()
            }
            index += 2
        }
        guard let device, let board, let build, let componentName else {
            throw PatchfinderError.invalidFixture(
                "fixture requires --device, --board, --build and --component-name"
            )
        }

        let artifact = try FirmwareArtifact(contentsOf: inputURL)
        let image = BinaryImage(data: artifact.payload)
        let options = parseResolverOptions(passthrough[...], allowJSON: false)
        let records = try resolveRecords(named: resolver, in: image, options: options)
        let patched = try GuardedPatchApplier.apply(records, to: image)

        let manifest = FixtureManifest(
            resolver: resolver,
            target: .init(device: device, board: board, build: build, component: componentName),
            expectedSize: image.count,
            sha256: FixtureManifest.digest(of: image.data),
            expectedPatches: records.map {
                .init(
                    id: $0.id,
                    offset: $0.offset,
                    originalBytes: $0.originalBytes.hexadecimalString,
                    replacementBytes: $0.replacementBytes.hexadecimalString
                )
            },
            expectedOutputSHA256: FixtureManifest.digest(of: patched.data)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        var json = try encoder.encode(manifest)
        json.append(0x0A)
        try json.write(to: outputURL, options: .atomic)

        // Read it straight back through the same oracle the tests use. A
        // manifest that cannot verify its own binary is worse than none.
        let written = try FixtureManifest.load(from: outputURL)
        let verified = try written.verify(binaryAt: inputURL)
        print("\(resolver): \(verified.count) records")
        print("  input  \(manifest.sha256)")
        print("  output \(manifest.expectedOutputSHA256 ?? "-")")
        print("wrote \(outputURL.path)")

    case "inspect":
        guard arguments.count >= 3 else { usage() }
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: arguments[1]))
        let inspector = try BinaryInspector(image: BinaryImage(data: artifact.payload))
        let query = arguments[2]
        let parameters = Array(arguments.dropFirst(3))

        switch query {
        case "segments":
            guard parameters.isEmpty else { usage() }
            inspector.segmentReport().forEach { print($0) }

        case "objc-methods":
            guard let selector = parameters.first, parameters.count <= 2 else { usage() }
            let words = parameters.count > 1 ? Int(parameters[1]) ?? 2 : 2
            let methods = try inspector.objcMethods(named: selector, words: words)
            print("implementations: \(methods.count)")
            methods.forEach { print("  \($0)") }

        case "strings":
            guard let text = parameters.first, parameters.count == 1 else { usage() }
            let occurrences = inspector.stringOccurrences(text)
            print("occurrences: \(occurrences.count)")
            occurrences.forEach { print("  \($0)") }

        case "xrefs":
            guard parameters.count == 1, let offset = parseNumber(parameters[0]) else { usage() }
            let references = try inspector.references(toFileOffset: offset)
            print("adrp+add references: \(references.count)")
            references.forEach { print("  \($0)") }

        case "func":
            guard parameters.count == 1, let offset = parseNumber(parameters[0]) else { usage() }
            guard let start = inspector.functionStart(beforeOrAt: offset) else {
                print("no enclosing arm64e prologue within 0x4000 bytes")
                break
            }
            let end = inspector.nextFunctionStart(after: start)
            print("start \(hex(start))  end \(hex(end))  words \((end - start) / 4)")

        case "calls":
            guard parameters.count == 1, let offset = parseNumber(parameters[0]) else { usage() }
            let targets = try inspector.directCallTargets(inFunctionContaining: offset)
            print("distinct direct call targets: \(targets.count)")
            targets.forEach { print("  \(hex($0))") }

        case "dis":
            guard let offset = parseNumber(parameters.first ?? "") else { usage() }
            let words = parameters.count > 1 ? Int(parameters[1]) ?? 16 : 16
            try inspector.disassembly(at: offset, words: words).forEach { print($0) }

        case "pattern":
            guard !parameters.isEmpty, let signature = parseMaskedWords(parameters) else { usage() }
            let hits = try inspector.patternMatches(
                values: signature.values,
                masks: signature.masks
            )
            print("matches: \(hits.count)")
            hits.forEach { print("  \(hex($0))") }

        case "pattern-at":
            // Report which words of a signature survive at one candidate, so a
            // drifted function reveals the single instruction that changed.
            guard parameters.count >= 2,
                  let offset = parseNumber(parameters[0]),
                  let signature = parseMaskedWords(Array(parameters.dropFirst()))
            else { usage() }
            try inspector.patternWordReport(
                values: signature.values,
                masks: signature.masks,
                at: offset
            ).forEach { print($0) }

        default:
            usage()
        }

    case "verify":
        guard arguments.count == 3 else { usage() }
        let manifest = try FixtureManifest.load(from: URL(fileURLWithPath: arguments[1]))
        let records = try manifest.verify(binaryAt: URL(fileURLWithPath: arguments[2]))
        try printRecords(records, json: false)

    case "im4p":
        guard arguments.count >= 3 else { usage() }
        let operation = arguments[1]
        let inputURL = URL(fileURLWithPath: arguments[2]).standardizedFileURL
        let artifact = try FirmwareArtifact(contentsOf: inputURL)
        guard artifact.kind == .im4p else {
            throw PatchfinderError.invalidFirmwareContainer("\(inputURL.lastPathComponent) is not an IM4P")
        }

        switch operation {
        case "info":
            guard arguments.count == 3 else { usage() }
            print("type: IM4P")
            print("fourcc: \(artifact.fourcc ?? "unknown")")
            print("description: \(artifact.containerDescription ?? "")")
            print("payload size: \(artifact.payload.count)")

        case "extract":
            guard arguments.count == 4 else { usage() }
            let outputURL = URL(fileURLWithPath: arguments[3]).standardizedFileURL
            guard inputURL != outputURL else {
                throw PatchfinderError.invalidFirmwareContainer("input and output paths must differ")
            }
            try artifact.payload.write(to: outputURL, options: .atomic)
            print("extracted \(artifact.fourcc ?? "IM4P") payload (\(artifact.payload.count) bytes)")
            print("wrote \(outputURL.path)")

        case "repack":
            guard arguments.count == 5 else { usage() }
            let payloadURL = URL(fileURLWithPath: arguments[3]).standardizedFileURL
            let outputURL = URL(fileURLWithPath: arguments[4]).standardizedFileURL
            guard outputURL != inputURL, outputURL != payloadURL else {
                throw PatchfinderError.invalidFirmwareContainer("output must differ from both inputs")
            }
            let payload = try Data(contentsOf: payloadURL, options: [.mappedIfSafe])
            let output = try artifact.encoded(replacingPayloadWith: payload)
            try output.write(to: outputURL, options: .atomic)

            // Re-open our own result and compare the extracted payload. This
            // catches DER-length or PAYP mistakes before reporting success.
            let roundTrip = try FirmwareArtifact(data: output)
            guard roundTrip.kind == .im4p, roundTrip.payload == payload else {
                throw PatchfinderError.invalidFirmwareContainer("repacked payload failed round-trip verification")
            }
            print("repacked \(artifact.fourcc ?? "IM4P") and verified \(payload.count)-byte payload")
            print("wrote \(outputURL.path)")

        default:
            usage()
        }

    case "img4":
        guard arguments.count == 5 || arguments.count == 7,
              arguments[1] == "create" else { usage() }
        var fourcc: String?
        if arguments.count == 7 {
            guard arguments[5] == "--fourcc" else { usage() }
            fourcc = arguments[6]
        }
        let input = URL(fileURLWithPath: arguments[2]).standardizedFileURL
        let ticket = URL(fileURLWithPath: arguments[3]).standardizedFileURL
        let output = URL(fileURLWithPath: arguments[4]).standardizedFileURL
        let data = try IMG4Signing.create(
            im4pData: Data(contentsOf: input),
            im4mData: Data(contentsOf: ticket),
            fourcc: fourcc
        )
        try data.write(to: output, options: .atomic)
        print("created and verified ticket-bearing IMG4: \(output.path)")

    case "apply":
        guard arguments.count >= 5,
              let resolver = resolverName(component: arguments[1], plan: arguments[2]) else {
            usage()
        }
        let options = parseResolverOptions(
            arguments.dropFirst(5),
            allowJSON: false,
            allowRecordsOutput: true
        )
        let inputURL = URL(fileURLWithPath: arguments[3]).standardizedFileURL
        let outputURL = URL(fileURLWithPath: arguments[4]).standardizedFileURL
        guard inputURL != outputURL else {
            throw PatchfinderError.invalidFixture("input and output paths must differ")
        }
        if let recordsOutput = options.recordsOutput {
            guard recordsOutput != inputURL, recordsOutput != outputURL else {
                throw PatchfinderError.invalidFixture(
                    "records output must differ from artifact input and output"
                )
            }
        }

        let artifact = try FirmwareArtifact(contentsOf: inputURL)
        if let plan = deviceTreePlan(named: resolver) {
            guard options.bootArguments == nil,
                  options.panelID == nil,
                  options.recordsOutput == nil else { usage() }
            try artifact.requireIM4PFourCC("dtre")
            let result = try DeviceTreePatcher.patch(artifact.payload, plan: plan)
            let output = try artifact.encoded(replacingPayloadWith: result.data)
            try output.write(to: outputURL, options: .atomic)
            printDeviceTreeChanges(result.changes)
            print("payload size: \(artifact.payload.count) -> \(result.data.count) (\(result.data.count - artifact.payload.count >= 0 ? "+" : "")\(result.data.count - artifact.payload.count))")
            print("wrote \(outputURL.path)")
            break
        }

        let image = BinaryImage(data: artifact.payload)
        reportProfile(for: image, resolver: resolver)
        let records = try resolveRecords(named: resolver, in: image, options: options)
        let result = try GuardedPatchApplier.apply(records, to: image)
        let output = try artifact.encoded(replacingPayloadWith: result.data)

        // Atomic replacement protects an existing output path from a partial
        // write. The input artifact is never modified in place.
        try output.write(to: outputURL, options: .atomic)
        if let recordsOutput = options.recordsOutput {
            // Publish evidence only after the patched artifact is complete.
            // A resolution, pre-image, encoding or artifact-write failure
            // therefore cannot leave records claiming a successful output.
            try encodedRecords(records).write(to: recordsOutput, options: .atomic)
        }
        try printRecords(records, json: false)
        print("wrote \(outputURL.path)")

    default:
        usage()
    }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
