import ArgumentParser
import Foundation
import Liter8Core

/// `<component> <plan>` stays a pair of positional arguments backed by
/// `resolverGroups`, rather than becoming one Swift type per resolver. The table
/// is the public surface, and adding a plan should remain one table entry.
private func requireResolver(component: String, plan: String) throws -> String {
    guard let resolver = resolverName(component: component, plan: plan) else {
        let plans = resolverGroups[component]?.keys.sorted().joined(separator: ", ")
        if let plans {
            throw ValidationError("unknown plan '\(plan)' for \(component). Plans: \(plans)")
        }
        let components = resolverGroups.keys.sorted().joined(separator: ", ")
        throw ValidationError("unknown component '\(component)'. Components: \(components)")
    }
    return resolver
}

private let componentDiscussion = """
COMPONENTS AND PLANS:
  iboot       ibss-validate, ibss-bootargs, ibss-normal, ibss-restore,
              ibec-restore, ibss-ramdisk, ibss-skip-display-init,
              ibec-ignore-pinot-failure, ibec-force-pinot-id
  kernel      restore, boot-policy, aks, sep-silence, sep,
              credential-manager, sandbox, valeria, boot, boot-public,
              diagnostic
  txm         restore, boot
  userland    restored-fdr, asr, coreauthd, ctkd, mobileactivationd, commcenter
  devicetree  restore, normal
"""

struct Resolve: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Resolve patch sites in a binary and print them, changing nothing.",
        discussion: componentDiscussion
    )

    @Argument(help: ArgumentHelp("Firmware component.", valueName: "component"))
    var component: String

    @Argument(help: ArgumentHelp("Patch plan for that component.", valueName: "plan"))
    var plan: String

    @Argument(help: ArgumentHelp("IM4P or raw payload to read.", valueName: "input"))
    var input: String

    @Flag(name: .customLong("json"), help: "Emit records as JSON.")
    var json = false

    @OptionGroup var tuning: ResolverTuningOptions

    // Validated here rather than in run() so an unknown component or plan is
    // reported against `liter8 resolve`, not against the root command.
    func validate() throws {
        _ = try requireResolver(component: component, plan: plan)
    }

    func run() throws {
        let resolver = try requireResolver(component: component, plan: plan)
        var options = tuning.resolverOptions
        options.json = json
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: input))

        if let plan = deviceTreePlan(named: resolver) {
            guard !json else {
                throw ValidationError("devicetree plans do not support --json")
            }
            try options.requireNoTuning(resolver: resolver)
            try artifact.requireIM4PFourCC("dtre")
            let result = try DeviceTreePatcher.patch(artifact.payload, plan: plan)
            printDeviceTreeChanges(result.changes)
            let delta = result.data.count - artifact.payload.count
            print("payload size: \(artifact.payload.count) -> \(result.data.count) (\(delta >= 0 ? "+" : "")\(delta))")
            return
        }

        let image = BinaryImage(data: artifact.payload)
        reportProfile(for: image, resolver: resolver)
        let records = try resolveRecords(named: resolver, in: image, options: options)
        try printRecords(records, json: json)
    }
}

struct Apply: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Resolve patch sites and write a patched artifact.",
        discussion: componentDiscussion + """


        The input is never modified in place, and the output is written atomically.
        """
    )

    @Argument(help: ArgumentHelp("Firmware component.", valueName: "component"))
    var component: String

    @Argument(help: ArgumentHelp("Patch plan for that component.", valueName: "plan"))
    var plan: String

    @Argument(help: ArgumentHelp("IM4P or raw payload to read.", valueName: "input"))
    var input: String

    @Argument(help: ArgumentHelp("Patched artifact to write.", valueName: "output"))
    var output: String

    @Option(
        name: .customLong("records-out"),
        help: ArgumentHelp("Also write the records from this same apply.", valueName: "records.json")
    )
    var recordsOut: String?

    @OptionGroup var tuning: ResolverTuningOptions

    func validate() throws {
        _ = try requireResolver(component: component, plan: plan)
    }

    func run() throws {
        let resolver = try requireResolver(component: component, plan: plan)
        var options = tuning.resolverOptions
        options.recordsOutput = recordsOut.map {
            URL(fileURLWithPath: $0).standardizedFileURL
        }

        let inputURL = URL(fileURLWithPath: input).standardizedFileURL
        let outputURL = URL(fileURLWithPath: output).standardizedFileURL
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
            try options.requireNoTuning(resolver: resolver)
            guard options.recordsOutput == nil else {
                throw ValidationError("devicetree plans do not support --records-out")
            }
            try artifact.requireIM4PFourCC("dtre")
            let result = try DeviceTreePatcher.patch(artifact.payload, plan: plan)
            let encoded = try artifact.encoded(replacingPayloadWith: result.data)
            try encoded.write(to: outputURL, options: .atomic)
            printDeviceTreeChanges(result.changes)
            let delta = result.data.count - artifact.payload.count
            print("payload size: \(artifact.payload.count) -> \(result.data.count) (\(delta >= 0 ? "+" : "")\(delta))")
            print("wrote \(outputURL.path)")
            return
        }

        let image = BinaryImage(data: artifact.payload)
        reportProfile(for: image, resolver: resolver)
        let records = try resolveRecords(named: resolver, in: image, options: options)
        let result = try GuardedPatchApplier.apply(records, to: image)
        let encoded = try artifact.encoded(replacingPayloadWith: result.data)

        // Atomic replacement protects an existing output path from a partial
        // write. The input artifact is never modified in place.
        try encoded.write(to: outputURL, options: .atomic)
        if let recordsOutput = options.recordsOutput {
            // Publish evidence only after the patched artifact is complete. A
            // resolution, pre-image, encoding or artifact-write failure therefore
            // cannot leave records claiming a successful output.
            try encodedRecords(records).write(to: recordsOutput, options: .atomic)
        }
        try printRecords(records, json: false)
        print("wrote \(outputURL.path)")
    }
}

struct Fixture: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Write an exact-build fixture manifest for one resolver.",
        discussion: """
        The manifest binds the clean input hash, every resolved record, and the \
        patched-output hash. It is generated from the same resolver and the same \
        GuardedPatchApplier the rest of the CLI uses, then read straight back and \
        verified, because a manifest that cannot verify its own binary is worse \
        than none. Firmware identity stays explicit: a fixture asserts which build \
        it describes rather than guessing.
        """
    )

    @Argument(help: ArgumentHelp("Firmware component.", valueName: "component"))
    var component: String

    @Argument(help: ArgumentHelp("Patch plan for that component.", valueName: "plan"))
    var plan: String

    @Argument(help: ArgumentHelp("Clean input binary to pin.", valueName: "input"))
    var input: String

    @Argument(help: ArgumentHelp("Manifest to write.", valueName: "manifest.json"))
    var manifest: String

    @Option(name: .customLong("device"), help: ArgumentHelp("Device the fixture describes.", valueName: "name"))
    var device: String

    @Option(name: .customLong("board"), help: ArgumentHelp("Board the fixture describes.", valueName: "board"))
    var board: String

    @Option(name: .customLong("build"), help: ArgumentHelp("Build the fixture describes.", valueName: "build"))
    var build: String

    @Option(
        name: .customLong("component-name"),
        help: ArgumentHelp("Component filename inside that build.", valueName: "component")
    )
    var componentName: String

    @OptionGroup var tuning: ResolverTuningOptions

    func validate() throws {
        _ = try requireResolver(component: component, plan: plan)
    }

    func run() throws {
        let resolver = try requireResolver(component: component, plan: plan)
        let inputURL = URL(fileURLWithPath: input).standardizedFileURL
        let outputURL = URL(fileURLWithPath: manifest).standardizedFileURL

        let artifact = try FirmwareArtifact(contentsOf: inputURL)
        let image = BinaryImage(data: artifact.payload)
        let records = try resolveRecords(
            named: resolver, in: image, options: tuning.resolverOptions
        )
        let patched = try GuardedPatchApplier.apply(records, to: image)

        let built = FixtureManifest(
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
        var json = try encoder.encode(built)
        json.append(0x0A)
        try json.write(to: outputURL, options: .atomic)

        let written = try FixtureManifest.load(from: outputURL)
        let verified = try written.verify(binaryAt: inputURL)
        print("\(resolver): \(verified.count) records")
        print("  input  \(built.sha256)")
        print("  output \(built.expectedOutputSHA256 ?? "-")")
        print("wrote \(outputURL.path)")
    }
}

struct Verify: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Verify a binary against a fixture manifest."
    )

    @Argument(help: ArgumentHelp("Manifest to verify against.", valueName: "manifest.json"))
    var manifest: String

    @Argument(help: ArgumentHelp("Binary to check.", valueName: "binary"))
    var binary: String

    func run() throws {
        let loaded = try FixtureManifest.load(from: URL(fileURLWithPath: manifest))
        let records = try loaded.verify(binaryAt: URL(fileURLWithPath: binary))
        try printRecords(records, json: false)
    }
}
