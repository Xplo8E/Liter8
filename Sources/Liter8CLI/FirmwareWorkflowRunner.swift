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
        workDirectory: URL,
        includeExperimental: Bool,
        board: String?
    ) throws {
        let identity = try IPSWManifestInspector.inspect(ipsw: file)
        // Refuse an ambiguous IPSW even here, where extraction itself is safe.
        // The directory it would create is named after whichever profile won,
        // and a later device stage reading that name has no way to know the
        // choice was arbitrary.
        let anyBoard = DeviceWorkflowRegistry.matchingProfiles(
            for: identity,
            includeExperimental: true
        )
        let forThisBoard = board.map { named in
            anyBoard.filter { $0.deviceClass == named }
        } ?? anyBoard
        if forThisBoard.count > 1 {
            throw PatchfinderError.invalidFixture(
                DeviceWorkflowRegistry.ambiguityMessage(forThisBoard)
            )
        }
        // A --board that matched nothing on an IPSW Liter8 does know is a typo.
        // Extracting anyway would look like success.
        if let board, forThisBoard.isEmpty, !anyBoard.isEmpty {
            throw PatchfinderError.invalidFixture(
                DeviceWorkflowRegistry.unknownBoardMessage(board, offered: anyBoard)
            )
        }
        let profile = DeviceWorkflowRegistry.profile(
            for: identity,
            includeExperimental: includeExperimental,
            board: board
        )

        // Extraction is a local unzip: it never contacts a device, so having a
        // reviewed workflow profile is not a precondition for it. Requiring one
        // here blocked research on any new build, which is the moment the tool
        // is most useful, and forced the components to be unzipped by hand
        // instead.
        //
        // Device safety is unaffected. Every action that can reach hardware
        // goes through runPreparedAction, which performs its own independent
        // profile lookup against the extracted BuildManifest and refuses when
        // there is no match. Ungating this path cannot make an unvalidated
        // build restorable.
        //
        // One refusal is kept: a profile that exists but is being withheld for
        // review is a decision the caller can opt into, and silently extracting
        // would hide that from them.
        if profile == nil,
           let candidate = DeviceWorkflowRegistry.profile(
               for: identity,
               includeExperimental: true,
               board: board
           ), candidate.validationState == .experimental {
            throw PatchfinderError.invalidFixture(
                "firmware profile \(candidate.id) is experimental; rerun with --experimental"
            )
        }

        // Profiles name their output directory after the IPSW, so an unprofiled
        // build follows the same convention rather than inventing a second one.
        let extractedName = profile?.extractedDirectoryName
            ?? file.deletingPathExtension().lastPathComponent

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(
            atPath: workDirectory.path,
            isDirectory: &isDirectory
        ), isDirectory.boolValue else {
            throw PatchfinderError.invalidFixture(
                "firmware work directory does not exist: \(workDirectory.path)"
            )
        }

        if let profile {
            print("firmware profile: \(profile.id)")
            if profile.validationState == .experimental {
                print("  validation: EXPERIMENTAL, not promoted to reviewed")
            }
            print("  device/board: \(profile.productType) / \(profile.deviceClass)")
        } else {
            let devices = identity.productTypes.joined(separator: ", ")
            let boards = Set(identity.buildIdentities.map(\.deviceClass)).sorted()
                .joined(separator: ", ")
            print("firmware profile: none for this build")
            print("  EXTRACTION ONLY. No reviewed workflow profile exists, so every device action (make-cfw, restore-cfw, boot, provision) will refuse.")
            print("  device/board: \(devices) / \(boards)")
        }
        print("  iOS/build: \(identity.productVersion) (\(identity.build))")
        print("  IPSW: \(file.path)")
        print("  work directory: \(workDirectory.path)")
        fflush(stdout)

        let fileManager = FileManager.default
        let extracted = workDirectory.appendingPathComponent(extractedName)
        let marker = extracted.appendingPathComponent(".extract-complete")

        if fileManager.fileExists(atPath: marker.path) {
            try verify(profile: profile, expecting: identity, in: extracted)
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
        let staging = workDirectory
            .appendingPathComponent(".liter8-extract-\(profile?.id ?? extractedName)")
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: false)
        defer { try? fileManager.removeItem(at: staging) }

        print("extracting with \(try IPSWUnzip.sevenZipExecutable().path) ...")
        fflush(stdout)
        try IPSWUnzip.extract(file, to: staging)
        try verify(profile: profile, expecting: identity, in: staging)
        try Data().write(to: staging.appendingPathComponent(".extract-complete"))
        try fileManager.moveItem(at: staging, to: extracted)
        print("verified extracted firmware: \(extracted.path)")
    }

    /// Confirm an extracted tree is the firmware it claims to be.
    ///
    /// With a profile the check is that the profile still supports what landed.
    /// Without one there is nothing to match against, so it falls back to the
    /// weaker but still meaningful question: is this the archive the caller
    /// pointed at? That is what catches a stale or swapped directory being
    /// silently reused, which is the failure the marker file would otherwise
    /// hide.
    private static func verify(
        profile: DeviceWorkflowProfile?,
        expecting source: IPSWIdentity,
        in directory: URL
    ) throws {
        let manifest = directory.appendingPathComponent("BuildManifest.plist")
        let identity = try IPSWManifestInspector.parse(Data(contentsOf: manifest))

        guard let profile else {
            guard identity.build == source.build,
                  identity.productVersion == source.productVersion
            else {
                throw PatchfinderError.fixtureMismatch(
                    "extracted BuildManifest is iOS \(identity.productVersion) (\(identity.build)), "
                        + "but the IPSW is iOS \(source.productVersion) (\(source.build))"
                )
            }
            return
        }

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
        includeExperimental: Bool,
        board: String?,
        workflowEnvironment: [String: String] = [:]
    ) throws {
        // Scan the work directory once, then narrow. Keeping the unnarrowed
        // list lets the failure path name the boards this IPSW does offer
        // without reading every BuildManifest a second time.
        let onDisk = try DeviceWorkflowRegistry.profiles.compactMap { profile -> DeviceWorkflowProfile? in
            let manifest = workDirectory
                .appendingPathComponent(profile.extractedDirectoryName)
                .appendingPathComponent("BuildManifest.plist")
            guard FileManager.default.fileExists(atPath: manifest.path) else { return nil }
            let identity = try IPSWManifestInspector.parse(Data(contentsOf: manifest))
            return profile.supports(identity) ? profile : nil
        }
        let allMatches = board == nil ? onDisk : onDisk.filter { $0.deviceClass == board }
        if !includeExperimental,
           let candidate = allMatches.first(where: { $0.validationState == .experimental }) {
            throw PatchfinderError.invalidFixture(
                "firmware profile \(candidate.id) is experimental; rerun with --experimental"
            )
        }
        let matches = allMatches.filter {
            $0.validationState == .reviewed || includeExperimental
        }

        // Several matches is not a work-directory problem, so it does not get
        // work-directory advice. One IPSW that supports two boards matches two
        // profiles, and only the operator knows which phone is attached.
        guard matches.count == 1, let profile = matches.first else {
            guard matches.isEmpty else {
                throw PatchfinderError.invalidFixture(
                    DeviceWorkflowRegistry.ambiguityMessage(matches)
                )
            }
            // A --board nobody matched is a typo far more often than a missing
            // profile, so say which boards were on offer instead of sending
            // the operator to go write one.
            if let board, !onDisk.isEmpty {
                throw PatchfinderError.invalidFixture(
                    DeviceWorkflowRegistry.unknownBoardMessage(board, offered: onDisk)
                )
            }
            throw PatchfinderError.invalidFixture(
                """
                no supported extracted IPSW was found in \(workDirectory.path); \
                prepare a supported IPSW or add an exact device workflow profile
                """
            )
        }

        print("firmware profile: \(profile.id)")
        if profile.validationState == .experimental {
            print("  validation: EXPERIMENTAL, not promoted to reviewed")
        }
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
            selectedEnvironment["LITER8_LAUNCHD_CACHE_SHA"] = profile.launchdCacheSHA256
            selectedEnvironment["LITER8_LAUNCHD_CACHE_DAEMONS"] = String(
                profile.launchdCacheDaemonCount
            )
            selectedEnvironment["LITER8_SETUP_METHODS"] = String(
                profile.setupControllerMethodCount
            )
        }
        if profile.validationState == .experimental {
            selectedEnvironment["LITER8_EXPERIMENTAL_WORKFLOW"] = "1"
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
