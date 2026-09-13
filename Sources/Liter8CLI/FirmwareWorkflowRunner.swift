import Darwin
import Foundation
import Liter8Core

/// Owns the `fw prepare` host workflow.
///
/// Swift inspects the IPSW, chooses a reviewed profile, and streams the archive
/// into a staging directory. Python is used only by later build orchestration.
enum FirmwareWorkflowRunner {
    static var actionNames: [String] {
        (["prepare"] + FirmwareScriptRunner.actionNames).sorted()
    }

    static func run(
        file: URL,
        workDirectory: URL
    ) throws {
        let identity = try IPSWManifestInspector.inspect(ipsw: file)
        guard let profile = IPSWWorkflowRegistry.profile(for: identity) else {
            let devices = identity.productTypes.joined(separator: ", ")
            let boards = Set(identity.buildIdentities.map(\.deviceClass)).sorted()
                .joined(separator: ", ")
            throw PatchfinderError.invalidFixture(
                "fw prepare does not support iOS \(identity.productVersion) "
                    + "(\(identity.build)) for \(devices) / \(boards)"
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

        print("firmware profile: \(profile.id)")
        print("  iOS/build: \(identity.productVersion) (\(identity.build))")
        print("  device/board: \(profile.productType) / \(profile.deviceClass)")
        print("  IPSW: \(file.path)")
        print("  work directory: \(workDirectory.path)")
        fflush(stdout)

        let fileManager = FileManager.default
        let extracted = workDirectory.appendingPathComponent(profile.extractedDirectoryName)
        let marker = extracted.appendingPathComponent(".extract-complete")

        if fileManager.fileExists(atPath: marker.path) {
            try verify(profile: profile, in: extracted)
            try IPSWUnzip.verifyExtractedTree(file, at: extracted)
            print("already extracted and verified: \(extracted.path)")
            return
        }
        guard !fileManager.fileExists(atPath: extracted.path) else {
            throw PatchfinderError.invalidFixture(
                "incomplete firmware directory already exists: \(extracted.path); move or remove it before retrying"
            )
        }

        if let staleStaging = try fileManager.contentsOfDirectory(atPath: workDirectory.path)
            .first(where: { $0.hasPrefix(".liter8-extract-") }) {
            throw PatchfinderError.invalidFixture(
                "stale Liter8 extraction found at \(workDirectory.appendingPathComponent(staleStaging).path); move or remove it before retrying"
            )
        }

        // A deterministic name prevents repeated interrupted runs from filling
        // the volume with abandoned UUID directories. The final rename remains
        // atomic because staging and output live on the same filesystem.
        let staging = workDirectory.appendingPathComponent(".liter8-extract-\(profile.id)")
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: false)
        defer { try? fileManager.removeItem(at: staging) }

        print("extracting with /opt/homebrew/bin/7zz ...")
        fflush(stdout)
        try IPSWUnzip.extract(file, to: staging)
        try verify(profile: profile, in: staging)
        try Data().write(to: staging.appendingPathComponent(".extract-complete"))
        try fileManager.moveItem(at: staging, to: extracted)
        print("verified extracted firmware: \(extracted.path)")
    }

    private static func verify(profile: IPSWWorkflowProfile, in directory: URL) throws {
        let manifest = directory.appendingPathComponent("BuildManifest.plist")
        let identity = try IPSWManifestInspector.parse(Data(contentsOf: manifest))
        guard profile.supports(identity) else {
            throw PatchfinderError.fixtureMismatch(
                "extracted BuildManifest does not match the selected firmware profile"
            )
        }
    }

    /// Run a post-extraction action against the same working directory used by
    /// `fw prepare`. Every invocation revalidates the extracted manifest, so a
    /// copied or stale directory cannot silently select the wrong scripts.
    static func runPreparedAction(
        _ action: String,
        workDirectory: URL,
        python: String?,
        resourceDirectory: URL?,
        ticket: URL?,
        sshrdPayload: URL?,
        workflowEnvironment: [String: String] = [:]
    ) throws {
        let matches = try IPSWWorkflowRegistry.profiles.compactMap { profile -> IPSWWorkflowProfile? in
            let manifest = workDirectory
                .appendingPathComponent(profile.extractedDirectoryName)
                .appendingPathComponent("BuildManifest.plist")
            guard FileManager.default.fileExists(atPath: manifest.path) else { return nil }
            let identity = try IPSWManifestInspector.parse(Data(contentsOf: manifest))
            return profile.supports(identity) ? profile : nil
        }

        guard matches.count == 1, let profile = matches.first else {
            let reason = matches.isEmpty
                ? "no supported extracted IPSW was found"
                : "more than one supported extracted IPSW was found"
            throw PatchfinderError.invalidFixture(
                "\(reason) in \(workDirectory.path); run fw prepare in this work directory first"
            )
        }

        print("firmware profile: \(profile.id)")
        print("  iOS/build: \(profile.productVersion) (\(profile.build))")
        print("  device/board: \(profile.productType) / \(profile.deviceClass)")
        fflush(stdout)
        let sourceRoot = workDirectory.appendingPathComponent(profile.extractedDirectoryName)
        let context = try FirmwareWorkflowContext.load(
            profile: profile,
            sourceRoot: sourceRoot
        )
        // `--work-dir` already names Liter8's mutable workspace. Do not append
        // another `.liter8` here: callers commonly pass `--work-dir .liter8`,
        // and doing so would silently create the confusing `.liter8/.liter8`.
        let contextFile = workDirectory.appendingPathComponent("context.json")
        try context.write(to: contextFile)
        var selectedEnvironment = workflowEnvironment
        if action == "provision" || action == "prepare-rootfs" {
            guard let launchdSHA256 = profile.launchdSHA256 else {
                throw PatchfinderError.invalidFixture(
                    "firmware profile \(profile.id) has no reviewed launchd identity"
                )
            }
            selectedEnvironment["LITER8_LAUNCHD_SHA"] = launchdSHA256
        }
        try FirmwareScriptRunner.run(
            action: action,
            workDirectory: workDirectory,
            python: python,
            resourceDirectory: resourceDirectory,
            ipswSource: sourceRoot,
            contextFile: contextFile,
            ticket: ticket,
            sshrdPayload: sshrdPayload,
            workflowEnvironment: selectedEnvironment
        )
    }
}
