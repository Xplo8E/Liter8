import ArgumentParser
import Darwin
import Foundation
import Liter8Core

struct ResolverOptions {
    var bootArguments: String?
    var panelID: UInt32?
    var json = false
    var recordsOutput: URL?

    /// Most resolvers take neither `--boot-args` nor `--pinot-id`. Rejecting them
    /// by name beats the old behaviour of reprinting the whole global usage block,
    /// which never said which option was the problem.
    func requireNoTuning(resolver: String) throws {
        guard bootArguments == nil, panelID == nil else {
            throw ValidationError(
                "\(resolver) accepts neither --boot-args nor --pinot-id"
            )
        }
    }
}

/// Keep the public CLI small while retaining descriptive internal resolver
/// names and fixture IDs. Adding a plan is one table entry, not another command
/// parser branch or usage line.
let resolverGroups: [String: [String: String]] = [
    "iboot": [
        "ibss-validate": IBSSValidateResolver.name,
        "ibss-bootargs": IBSSBootArgsResolver.name,
        "ibss-normal": IBSSNormalResolver.name,
        "ibss-restore": IBSSRestoreResolver.name,
        "ibec-restore": IBECRestoreResolver.name,
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
        "valeria": KernelValeriaResolver.name,
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

func resolverName(component: String, plan: String) -> String? {
    resolverGroups[component]?[plan]
}

/// Parse only the two resolver options we currently support. Keeping this tiny
/// avoids hiding patch semantics behind a command framework while the research
/// interface is still changing.
/// `--pinot-id` accepts decimal or `0x`-prefixed hex, which ArgumentParser cannot
/// express with a plain `UInt32` option.
struct PanelID: ExpressibleByArgument {
    let value: UInt32

    init?(argument: String) {
        let parsed: UInt32? = argument.hasPrefix("0x") || argument.hasPrefix("0X")
            ? UInt32(argument.dropFirst(2), radix: 16)
            : UInt32(argument, radix: 10)
        guard let parsed else { return nil }
        value = parsed
    }
}

/// `--boot-args` and `--pinot-id`, shared by the commands that run a resolver.
/// Which resolvers actually accept them is enforced in `resolveRecords`.
struct ResolverTuningOptions: ParsableArguments {
    @Option(
        name: .customLong("boot-args"),
        help: ArgumentHelp(
            "Boot-argument literal, for the iBoot boot-args resolver.",
            valueName: "literal"
        )
    )
    var bootArguments: String?

    @Option(
        name: .customLong("pinot-id"),
        help: ArgumentHelp(
            "Display panel ID, decimal or 0x hex, for ibec-force-pinot-id.",
            valueName: "value"
        )
    )
    var panelID: PanelID?

    var resolverOptions: ResolverOptions {
        ResolverOptions(bootArguments: bootArguments, panelID: panelID?.value)
    }
}

/// Dispatch a named semantic resolver. The known-offset fixture registry lives
/// elsewhere and is intentionally not reachable from this function.
func resolveRecords(
    named name: String,
    in image: BinaryImage,
    options: ResolverOptions
) throws -> [PatchRecord] {
    switch name {
    case IBSSValidateResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBSSValidateResolver().resolve(in: image)
    case IBSSBootArgsResolver.name:
        guard options.panelID == nil else {
            throw ValidationError("\(name) accepts --boot-args but not --pinot-id")
        }
        return try IBSSBootArgsResolver(
            bootArguments: options.bootArguments ?? IBSSBootArgsResolver.normalBootArguments
        ).resolve(in: image)
    case IBSSNormalResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBSSNormalResolver().resolve(in: image)
    case IBSSRestoreResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBSSRestoreResolver().resolve(in: image)
    case IBECRestoreResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBECRestoreResolver().resolve(in: image)
    case IBSSRamdiskResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBSSRamdiskResolver().resolve(in: image)
    case RestoredExternalResolver.name:
        try options.requireNoTuning(resolver: name)
        return try RestoredExternalResolver().resolve(in: image)
    case ASRSignatureResolver.name:
        try options.requireNoTuning(resolver: name)
        return try ASRSignatureResolver().resolve(in: image)
    case TXMRestoreResolver.name:
        try options.requireNoTuning(resolver: name)
        return try TXMRestoreResolver().resolve(in: image)
    case TXMBootResolver.name:
        try options.requireNoTuning(resolver: name)
        return try TXMBootResolver().resolve(in: image)
    case CoreAuthDResolver.name:
        try options.requireNoTuning(resolver: name)
        return try CoreAuthDResolver().resolve(in: image)
    case CTKDResolver.name:
        try options.requireNoTuning(resolver: name)
        return try CTKDResolver().resolve(in: image)
    case MobileActivationDResolver.name:
        try options.requireNoTuning(resolver: name)
        return try MobileActivationDResolver().resolve(in: image)
    case IBSSSkipDisplayInitResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBSSSkipDisplayInitResolver().resolve(in: image)
    case IBECPinotIgnoreFailureResolver.name:
        try options.requireNoTuning(resolver: name)
        return try IBECPinotIgnoreFailureResolver().resolve(in: image)
    case IBECPinotForceIDResolver.name:
        guard options.bootArguments == nil else {
            throw ValidationError("\(name) does not accept --boot-args")
        }
        guard let panelID = options.panelID else {
            throw ValidationError("\(name) requires --pinot-id <value>")
        }
        return try IBECPinotForceIDResolver(panelID: panelID).resolve(in: image)
    case KernelRestoreResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelRestoreResolver().resolve(in: image)
    case KernelBootPolicyResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelBootPolicyResolver().resolve(in: image)
    case KernelAKSResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelAKSResolver().resolve(in: image)
    case KernelSEPSilenceResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelSEPSilenceResolver().resolve(in: image)
    case KernelSEPResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelSEPResolver().resolve(in: image)
    case KernelCredentialManagerResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelCredentialManagerResolver().resolve(in: image)
    case KernelSandboxResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelSandboxResolver().resolve(in: image)
    case KernelValeriaResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelValeriaResolver().resolve(in: image)
    case KernelBootResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelBootResolver().resolve(in: image)
    case KernelBootCompatibilityResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelBootCompatibilityResolver().resolve(in: image)
    case KernelDiagnosticResolver.name:
        try options.requireNoTuning(resolver: name)
        return try KernelDiagnosticResolver().resolve(in: image)
    default:
        throw ValidationError("unknown resolver: \(name)")
    }
}

/// Accept `0x`-prefixed and decimal literals alike. Research notes quote file
/// offsets in hexadecimal, while some tables carry plain decimal.
func parseNumber(_ text: String) -> UInt64? {
    if text.hasPrefix("0x") || text.hasPrefix("0X") {
        return UInt64(text.dropFirst(2), radix: 16)
    }
    return UInt64(text, radix: 10)
}

func hex(_ value: UInt64) -> String { String(format: "0x%llx", value) }

/// Parse `<word>` or `<word>/<mask>` signature arguments. A bare word is
/// compared in full, which is how a freshly transcribed reference signature
/// behaves before any field is deliberately relaxed.
func parseMaskedWords(_ arguments: [String]) -> (values: [UInt32], masks: [UInt32])? {
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

func printRecords(_ records: [PatchRecord], json: Bool) throws {
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
func encodedRecords(_ records: [PatchRecord]) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    var data = try encoder.encode(records)
    data.append(0x0A)
    return data
}

func deviceTreePlan(named name: String) -> DeviceTreePatchPlan? {
    DeviceTreePatchPlan(rawValue: name)
}

func printDeviceTreeChanges(_ changes: [DeviceTreeChange]) {
    for change in changes {
        print("devicetree \(change.operation): \(change.path) [\(change.disposition.rawValue)]")
    }
}

/// Print profile selection before a potentially long kernel scan. This goes to
/// stderr so `--json` keeps stdout machine-readable. Unlike resolved records,
/// this write happens before scanning, so terminal users immediately see what
/// the tool selected instead of staring at a silent process.
func reportProfile(
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
        // Plural when a fingerprint covers several Apple build IDs: the
        // kernelcache cannot say which of them this artifact is.
        "  iOS/build\(profile.builds.count == 1 ? "" : "s"): \(profile.productVersion) "
            + "(\(profile.builds.joined(separator: ", ")))",
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

func printProfile(_ profile: KernelResolverProfile) {
    let buildLabel = profile.builds.count == 1 ? "build" : "builds"
    print("\(profile.id): iOS \(profile.productVersion), \(buildLabel) \(profile.builds.joined(separator: ", "))")
    print("  boards: \(profile.boards.joined(separator: ", "))")
    print("  component: \(profile.component)")
    for resolver in profile.resolverVariants.keys.sorted() {
        guard let variants = profile.resolverVariants[resolver] else { continue }
        print("  \(resolver): signatures=\(variants.signature), payload=\(variants.payload), status=\(variants.support.rawValue)")
    }
}
