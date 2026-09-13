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
      --resource-dir <directory>  --ticket <apticket.im4m>
      --sshrd-payload <ssh.tar.gz>
      --irecovery <custom-irecovery>  --idevicerestore <executable>
      --rootfs <mounted-root-filesystem>  --check

    """.utf8))
    exit(2)
}

private struct ResolverOptions {
    var bootArguments: String?
    var panelID: UInt32?
    var json = false
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
        "boot-public": KernelBootPublicBeta4Resolver.name,
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
private func parseResolverOptions(_ arguments: ArraySlice<String>, allowJSON: Bool) -> ResolverOptions {
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
    case KernelBootPublicBeta4Resolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelBootPublicBeta4Resolver().resolve(in: image)
    case KernelDiagnosticResolver.name:
        guard options.bootArguments == nil, options.panelID == nil else { usage() }
        return try KernelDiagnosticResolver().resolve(in: image)
    default:
        usage()
    }
}

private func printRecords(_ records: [PatchRecord], json: Bool) throws {
    if json {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(records), as: UTF8.self))
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
    guard let profile = FirmwareProfileRegistry.detect(in: image) else {
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

private func printProfile(_ profile: FirmwareProfile) {
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
        var index = 2
        while index < arguments.count {
            if arguments[index] == "--check" {
                checkOnly = true
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
                    "fw prepare accepts only --file and --work-dir"
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
                workDirectory: workDirectoryURL
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
        guard let profile = FirmwareProfileRegistry.detect(in: image) else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: "profile",
                profile: "unidentified",
                variant: "none"
            )
        }
        printProfile(profile)

    case "profiles":
        guard arguments.count == 1 else { usage() }
        for (index, profile) in FirmwareProfileRegistry.profiles.enumerated() {
            if index > 0 { print("") }
            printProfile(profile)
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
        let options = parseResolverOptions(arguments.dropFirst(5), allowJSON: false)
        let inputURL = URL(fileURLWithPath: arguments[3]).standardizedFileURL
        let outputURL = URL(fileURLWithPath: arguments[4]).standardizedFileURL
        guard inputURL != outputURL else {
            throw PatchfinderError.invalidFixture("input and output paths must differ")
        }

        let artifact = try FirmwareArtifact(contentsOf: inputURL)
        if let plan = deviceTreePlan(named: resolver) {
            guard options.bootArguments == nil, options.panelID == nil else { usage() }
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
        try printRecords(records, json: false)
        print("wrote \(outputURL.path)")

    default:
        usage()
    }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
