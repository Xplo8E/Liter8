import Foundation

/// The firmware identity Apple records in the IPSW's top-level
/// `BuildManifest.plist`.
///
/// Filenames are only labels and can be renamed. These fields are signed build
/// metadata, so workflow selection must use them instead of guessing from the
/// archive name.
public struct IPSWIdentity: Equatable, Sendable {
    public struct BuildIdentity: Equatable, Sendable {
        public let deviceClass: String
        public let chipID: UInt64?
        public let boardID: UInt64?

        public init(deviceClass: String, chipID: UInt64?, boardID: UInt64?) {
            self.deviceClass = deviceClass
            self.chipID = chipID
            self.boardID = boardID
        }
    }

    public let productVersion: String
    public let build: String
    public let productTypes: [String]
    public let buildIdentities: [BuildIdentity]

    public init(
        productVersion: String,
        build: String,
        productTypes: [String],
        buildIdentities: [BuildIdentity]
    ) {
        self.productVersion = productVersion
        self.build = build
        self.productTypes = productTypes
        self.buildIdentities = buildIdentities
    }
}

/// Reads just `BuildManifest.plist` from an IPSW and converts the small set of
/// fields needed for safe workflow selection.
public enum IPSWManifestInspector {
    /// Inspecting one ZIP member avoids extracting a multi-gigabyte IPSW before
    /// we know that this patcher supports its device and build.
    public static func inspect(ipsw url: URL) throws -> IPSWIdentity {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw PatchfinderError.invalidFixture("IPSW does not exist: \(url.path)")
        }
        return try parse(IPSWUnzip.read("BuildManifest.plist", from: url))
    }

    /// This entry point is public so tests can exercise plist parsing without
    /// manufacturing a giant IPSW fixture.
    public static func parse(_ data: Data) throws -> IPSWIdentity {
        let object = try PropertyListSerialization.propertyList(from: data, format: nil)
        guard let plist = object as? [String: Any] else {
            throw PatchfinderError.invalidFixture("BuildManifest.plist is not a dictionary")
        }

        guard let productVersion = plist["ProductVersion"] as? String,
              let build = plist["ProductBuildVersion"] as? String,
              let productTypes = plist["SupportedProductTypes"] as? [String],
              let rawIdentities = plist["BuildIdentities"] as? [[String: Any]] else {
            throw PatchfinderError.invalidFixture(
                "BuildManifest.plist is missing product, build, device, or identity metadata"
            )
        }

        let identities = rawIdentities.compactMap { identity -> IPSWIdentity.BuildIdentity? in
            guard let info = identity["Info"] as? [String: Any],
                  let deviceClass = info["DeviceClass"] as? String else {
                return nil
            }
            return IPSWIdentity.BuildIdentity(
                deviceClass: deviceClass,
                chipID: integer(identity["ApChipID"]),
                boardID: integer(identity["ApBoardID"])
            )
        }

        guard !identities.isEmpty else {
            throw PatchfinderError.invalidFixture(
                "BuildManifest.plist contains no usable BuildIdentities"
            )
        }
        return IPSWIdentity(
            productVersion: productVersion,
            build: build,
            productTypes: productTypes,
            buildIdentities: identities
        )
    }

    /// Apple plists have represented these identifiers as hexadecimal strings
    /// and as integer objects across different tooling. Accept both forms but
    /// reject anything else instead of silently treating it as zero.
    private static func integer(_ value: Any?) -> UInt64? {
        if let number = value as? NSNumber {
            return number.uint64Value
        }
        guard let text = value as? String else { return nil }
        if text.hasPrefix("0x") || text.hasPrefix("0X") {
            return UInt64(text.dropFirst(2), radix: 16)
        }
        return UInt64(text, radix: 10)
    }
}

/// Extra iBSS operations selected by hardware policy rather than by the boot
/// mode itself.
///
/// Keep these values equal to the public CLI plan spellings. Swift writes them
/// into the workflow context, and Python only executes the reviewed selection.
public enum DeviceIBSSAdditionalPlan: String, Codable, Equatable, Sendable {
    /// Let iBEC own the display handoff on n104. Applying this operation to
    /// iBEC as well would suppress the LCD initialization the device needs.
    case skipDisplayInitialization = "ibss-skip-display-init"
}

/// Hardware-selected additions to the otherwise generic boot recipes.
///
/// Normal boot and SSHRD are separate because a future board may need the
/// display handoff workaround in only one path. An explicit empty array means
/// that the profile was reviewed and intentionally needs no extra operation.
public struct DeviceBootPlan: Codable, Equatable, Sendable {
    public let normalIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan]
    public let restoreIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan]
    /// Re-encode patched IM4P payloads in their shipped compression instead
    /// of uncompressed. n104 boots uncompressed images; the j171aap iBoot
    /// rejects them and only accepts restricted LZFSE (see FirmwareArtifact).
    public let preservesIM4PCompression: Bool
    /// Send StaticTrustCache instead of RestoreTrustCache on normal boot.
    /// n104 boots both modes with the restore cache; j171aap's normal boot
    /// needs the System-volume cache. SSHRD always uses the restore cache.
    public let normalBootUsesStaticTrustCache: Bool
    /// Whether this exact device profile supports `fw get-boot --tfp0`.
    public let supportsTFP0KernelTaskPort: Bool
    /// Passthrough firmware this board legitimately does not ship.
    ///
    /// Empty is the safe default and the state of every profile registered
    /// here: a component absent from an identity that should carry it is a
    /// manifest we do not understand, and the boot set must fail rather than
    /// quietly send an incomplete chain. j171aap is the known exception, being
    /// A12/PPL with no SPTM and therefore none of SPTM, PMP or WCH, and it
    /// states that itself rather than the selection inferring it from which
    /// components happen to be present.
    public let optionalPassthroughFirmware: [String]

    public init(
        normalIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan],
        restoreIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan],
        preservesIM4PCompression: Bool = false,
        normalBootUsesStaticTrustCache: Bool = false,
        supportsTFP0KernelTaskPort: Bool = false,
        optionalPassthroughFirmware: [String] = []
    ) {
        self.normalIBSSAdditionalPlans = normalIBSSAdditionalPlans
        self.restoreIBSSAdditionalPlans = restoreIBSSAdditionalPlans
        self.preservesIM4PCompression = preservesIM4PCompression
        self.normalBootUsesStaticTrustCache = normalBootUsesStaticTrustCache
        self.supportsTFP0KernelTaskPort = supportsTFP0KernelTaskPort
        self.optionalPassthroughFirmware = optionalPassthroughFirmware
    }
}

/// A reviewed host workflow for one exact firmware identity.
///
/// The profile names the output directory, but never supplies patch offsets.
/// Binary offsets remain the responsibility of semantic resolvers.
public struct DeviceWorkflowProfile: Equatable, Sendable {
    public enum ValidationState: String, Equatable, Sendable {
        /// Completed the full restore, provisioning and repeat-boot validation.
        case reviewed
        /// Exact-build data is present, but the device workflow is still under test.
        case experimental
    }

    public let id: String
    public let productVersion: String
    public let build: String
    public let productType: String
    public let deviceClass: String
    public let chipID: UInt64
    public let boardID: UInt64
    public let extractedDirectoryName: String
    public let validationState: ValidationState
    /// SHA-256 of stock `/sbin/launchd` accepted by device provisioning.
    /// This belongs to the exact firmware profile, beside the identity that
    /// selected it, rather than inside a generic Python or shell workflow.
    public let launchdSHA256: String?
    /// SHA-256 and pristine job count of `/System/Library/xpc/launchd.plist`.
    /// Both are build-specific even though the two jobs Liter8 adds are generic.
    public let launchdCacheSHA256: String
    public let launchdCacheDaemonCount: Int
    /// Number of class-owned `controllerNeedsToRun` implementations expected in
    /// Setup.app. This is a guard against silently broadening a behavioural patch.
    public let setupControllerMethodCount: Int
    /// Board-specific additions to the generic normal and SSHRD boot recipes.
    /// Keeping this in the exact workflow profile prevents Python from
    /// silently applying an n104 workaround to every future device.
    public let bootPlan: DeviceBootPlan

    public func supports(_ identity: IPSWIdentity) -> Bool {
        guard identity.productVersion == productVersion,
              identity.build == build,
              identity.productTypes.contains(productType) else {
            return false
        }
        return identity.buildIdentities.contains {
            $0.deviceClass == deviceClass && $0.chipID == chipID && $0.boardID == boardID
        }
    }
}

public enum DeviceWorkflowRegistry {
    public static let profiles = [
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24A5390f",
            productVersion: "27.0",
            build: "24A5390f",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.0_24A5390f_Restore",
            validationState: .reviewed,
            launchdSHA256: "9ff28152483244a34cb43cd3541511f6989636e6814611c573b21b2ee43d70f7",
            launchdCacheSHA256: "ff609d743eb0cb4ed013443ea4195e8e9daf4af71f59e5a1ea8a19b2abc3a5ba",
            launchdCacheDaemonCount: 731,
            setupControllerMethodCount: 65,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
            )
        ),
        // Device-validated on an iPhone 11 after an erase restore: CFW restore,
        // SSHRD provisioning, normal boot, repeat boot, Procursus finalization,
        // Dropbear, persona 99, icon token and PosterBoard repair all passed.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24A435",
            productVersion: "27.0",
            build: "24A435",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.0_24A435_Restore",
            validationState: .reviewed,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "752739f8224b016b5cee1b37a985995ffcfc1d6f12569fd2191ba5b4a9119c6a",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // Device-validated on an iPhone 11: erase restore, normal boot, repeat
        // boot and bootstrap all passed. Repeat boot is called out separately
        // because a first boot that works and a second that does not is a
        // failure mode this device has produced before, and it is the
        // difference between "it booted" and reviewed.
        //
        // Finalization, Dropbear, persona 99, icon token and PosterBoard repair
        // are recorded on the 24A435 entry but have not been exercised here, so
        // they are deliberately not claimed.
        //
        // Every value below was read from this build rather than carried over:
        // 27.2 ships a different XNU, its own AppleCredentialManager signature
        // family, an iBSS whose boot-argument padding moved off a page
        // boundary, and a Setup with one fewer pane controller (65, not 66).
        // The method used to measure them reproduces 24A435's recorded values
        // exactly, which is why these are trusted.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B5084k",
            productVersion: "27.2",
            build: "24B5084k",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2_24B5084k_Restore",
            validationState: .reviewed,
            launchdSHA256: "b2445ebe4ead365eabe6214f7f7a75e107a3ebd5c92b683058dab1eee1432a55",
            launchdCacheSHA256: "1babf8e67f857f2ffd4d037d9fb84ff80dd71427679e764bb61734deedbeedc9",
            launchdCacheDaemonCount: 733,
            setupControllerMethodCount: 65,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iOS 27.2 beta 2. Every plan resolves and all four oracles below were
        // measured from this build's own root filesystem, but no restore or
        // boot has been attempted on it yet, so this entry does not carry the
        // device-run record the 24A435 and 24B5084k entries do.
        //
        // The daemon count and Setup controller count happen to match beta 1
        // exactly. That is a measurement, not an assumption: the two digests
        // above them differ, so the images are not the same and the counts were
        // read rather than carried across.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B5089g",
            productVersion: "27.2",
            build: "24B5089g",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2_24B5089g_Restore",
            validationState: .reviewed,
            launchdSHA256: "05339fedc5f34c31704b2ed4e92e2e7e92f1bf1ef401c04ac5389f62b07e4490",
            launchdCacheSHA256: "bc13dfbacf37af78be13353fcea82a3f7b0780788a00b9d09f88982113bc0098",
            launchdCacheDaemonCount: 733,
            setupControllerMethodCount: 65,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iOS 27.2 beta 3, device-validated on an iPhone 11: erase restore and
        // normal boot both passed. All four oracles were measured from this
        // build's own root filesystem by `survey --guards`. The daemon count is
        // 732, one fewer than both earlier 27.2 seeds, which is a read value
        // rather than a carried one.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B5099f",
            productVersion: "27.2",
            build: "24B5099f",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2_24B5099f_Restore",
            validationState: .reviewed,
            launchdSHA256: "addb9ccb1b5650116ab5da59d1a53dc3f54e6a2a29cdcafa036c0c2376cd5ca2",
            launchdCacheSHA256: "9fd8a69b3f0a364e5e599ccc5601cb21f101786cbc3e802438fa4bf297d296aa",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 65,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iOS 27.2 beta 4, device-validated on an iPhone 11: erase restore, SSHRD
        // provisioning, normal boot, repeat boot, finalization and setup-debugger
        // passed. Guards measured from this build's own rootfs with `survey
        // --guards`: one more launch daemon (733) and one fewer Setup controller
        // method (64) than beta 3. One userspace restart of unknown cause was seen
        // during the first boot and did not recur on the repeat boot. The boot
        // plan is n104's display behaviour, the same as beta 3.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B5110a",
            productVersion: "27.2",
            build: "24B5110a",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2_24B5110a_Restore",
            validationState: .reviewed,
            launchdSHA256: "6a4626353d59d94b8d9e8ba179ccde8707d83473c2919ce8fd16175105a47647",
            launchdCacheSHA256: "40352a92f70de21e2f0dc8547606a033feeddf941b504bc236156e6fda57d37f",
            launchdCacheDaemonCount: 733,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iOS 27.2, the release build. Device-validated on an iPhone 11 on
        // 2026-10-31: erase restore, SSHRD provisioning, normal boot, repeat
        // boot, Procursus finalization and setup-debugger all passed.
        //
        // Repeat boot is recorded separately because a first boot that works
        // and a second that does not is a failure mode this device has
        // produced before. The evidence is /var/mobile/jbboot.log, which the
        // per-boot job appends to and which lives on the Data volume the erase
        // restore wiped: it carries two `=== jbboot start ===` blocks, and the
        // second adds `injection enabled for this boot` and a SpringBoard
        // restart so its tweaks load. The booted kernel reports
        // xnu-13432.42.3~28/PATCHED_ARM64_T8030, which is both this profile's
        // fingerprint and proof the kernel identity records applied.
        //
        // `finalize --check` reported complete on both boots: root SSH,
        // per-device Dropbear host keys, bootstrap shells, ElleKit 1.2, the
        // re-sign hook with every TweakInject dylib ad-hoc signed, injection
        // auto-enable, the one-time System application registration, persona
        // 99, the icon read token and a running PosterBoard repair watcher.
        //
        // All four oracles were measured from this build's own root filesystem
        // with `survey --guards`. The daemon count is 732, one fewer than beta
        // 4's 733 and equal to beta 3's; the Setup controller count matches
        // beta 4 at 64. Both are read values: the two digests differ from
        // every other entry, so the images are not the same and the counts
        // were not carried across.
        //
        // Not exercised, and deliberately not claimed: the on-screen verbose
        // boot log. Both the restore and normal-boot artifacts for this run
        // were built with `--serial`, so the console was on the UART by
        // design. The boot plan is n104's display behaviour and the device
        // reached SpringBoard, but the on-screen log path itself was not
        // observed on this build. SEP, cellular data, Apple services and
        // MobileBackup2 remain the project-wide gaps they are elsewhere.
        //
        // One observation left unexplained: load average ran 129-295 in the
        // first two minutes after boot and still fluctuated 15-43 after two
        // and a half hours of uptime, while every one of 421 processes read
        // 0.0% CPU and SpringBoard stayed up. Nothing was spinning, so this is
        // recorded rather than diagnosed.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B119",
            productVersion: "27.2",
            build: "24B119",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2_24B119_Restore",
            validationState: .reviewed,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "7e241a31f72fdd6026c156180b9c43fc415a8fcd897c6b9399b75844fbeb42c6",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iOS 27.0.1, device-validated on an iPhone 11: erase restore, SSHRD
        // provisioning, normal boot, repeat boot, Procursus finalization,
        // Dropbear, persona 99, icon token and PosterBoard repair all passed.
        // Repeat boot is recorded separately on purpose, because a first boot
        // that works and a second that does not is a failure mode this device
        // has produced before, and it is the difference between "it booted" and
        // reviewed.
        //
        // This build shares the 24A435 kernel profile, and the measurement
        // behind that is recorded beside the profile in FirmwareProfile.swift:
        // every artifact Liter8 patches is byte-identical to 24A437 apart from
        // kernelcache metadata outside any executable segment, and all 501
        // kernel records land on identical offsets with identical original
        // bytes. Resolution was checked before the device run rather than
        // inferred from it: `survey` reported 20 plans resolved and 0 failed,
        // `acm-probe` against ios27-24A435-acm-v1 reported the usual 24/26
        // exact matches, and the five userland plans resolved 5/1/1/2/5.
        //
        // All four oracles below were measured from this build's own root
        // filesystem, with the method first checked against 24A435, where it
        // reproduces the recorded launchd digest and 66 Setup controllers
        // exactly. launchd, Setup, mobileactivationd, coreauthd, ctkd, asr and
        // restored_external are byte-identical to 24A437; only
        // /System/Library/xpc/launchd.plist changed, and its 729 daemons were
        // counted from this image rather than carried across.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24A446",
            productVersion: "27.0.1",
            build: "24A446",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.0.1_24A446_Restore",
            validationState: .reviewed,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "5e0c65cf8ee4e6551325afdc4c283c350281d98e14f67b45bc55acfa536ae6e1",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // Same IPSW as the D431 entry below, so the guards are shared: one root
        // filesystem for both boards. They are copied, not measured here, and
        // the cache hash fails closed if that ever stops being true.
        DeviceWorkflowProfile(
            id: "iphone12,3-d421ap-24A446",
            productVersion: "27.0.1",
            build: "24A446",
            productType: "iPhone12,3",
            deviceClass: "d421ap",
            chipID: 0x8030,
            boardID: 0x06,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.0.1_24A446_Restore",
            validationState: .experimental,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "d207fd6fc7ab9bfb77455aa9e8e7da2c0db94519243862154e63b1839aaf7762",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // D431 booted on hardware; SEP and repeat-boot stability remain unresolved.
        DeviceWorkflowProfile(
            id: "iphone12,5-d431ap-24A446",
            productVersion: "27.0.1",
            build: "24A446",
            productType: "iPhone12,5",
            deviceClass: "d431ap",
            chipID: 0x8030,
            boardID: 0x02,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.0.1_24A446_Restore",
            validationState: .experimental,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "d207fd6fc7ab9bfb77455aa9e8e7da2c0db94519243862154e63b1839aaf7762",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // iPhone 11 Pro and Pro Max on 27.0, resolver-verified, no device run
        // on either board. The guards are identical because the IPSW ships one
        // root filesystem for both; they were measured from it, not carried
        // over from n104. Empty boot plans follow the d431 24A446 entry above
        // rather than any 24A437 measurement.
        DeviceWorkflowProfile(
            id: "iphone12,3-d421ap-24A437",
            productVersion: "27.0",
            build: "24A437",
            productType: "iPhone12,3",
            deviceClass: "d421ap",
            chipID: 0x8030,
            boardID: 0x06,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.0_24A437_Restore",
            validationState: .experimental,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "d763c9c0a7c6581cce5296cfa8e2ad7e1d5e9e389aca4b3343021dcc86c57c98",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        DeviceWorkflowProfile(
            id: "iphone12,5-d431ap-24A437",
            productVersion: "27.0",
            build: "24A437",
            productType: "iPhone12,5",
            deviceClass: "d431ap",
            chipID: 0x8030,
            boardID: 0x02,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.0_24A437_Restore",
            validationState: .experimental,
            launchdSHA256: "c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b",
            launchdCacheSHA256: "d763c9c0a7c6581cce5296cfa8e2ad7e1d5e9e389aca4b3343021dcc86c57c98",
            launchdCacheDaemonCount: 729,
            setupControllerMethodCount: 66,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // iPhone 11 Pro and Pro Max on 27.2, resolver-verified and measured,
        // with no device run on either board. Nothing here was carried over
        // from the n104 24B119 entry.
        //
        // What was exercised, all on the host: `fw prepare` on the
        // iPhone12,3/iPhone12,5 24B119 IPSW, `survey` on the extracted tree,
        // every iBoot plan resolved against each board's *own* iBSS and iBEC
        // rather than only the d421 pair `survey` happens to pick, `acm-probe`,
        // `survey --guards` for the four oracles below, and `fw make-cfw` for
        // each board, each reporting six verified restore artifacts. Every
        // plan resolves with the record count this build produces on n104, on
        // both boards, with one deliberate exception recorded below.
        //
        // The two make-cfw runs cross-check each other: `kernel-restore` and
        // `txm-restore` come out byte-identical because both boards share one
        // kernelcache and one TXM, while iBSS, iBEC and DeviceTree differ
        // because each board ships its own. They need one work directory each,
        // since `prepare_cfw` refuses a CFW built for another profile ID.
        //
        // All six userland plans resolve against this IPSW's own binaries, and
        // none of them is per-board. `restored-fdr` (1) and `asr` (1) come
        // from the restore ramdisk and were resolved by both make-cfw runs at
        // identical offsets, because one ramdisk serves both boards.
        // `coreauthd` (1), `ctkd` (2), `mobileactivationd` (5) and
        // `commcenter` (3) live in the AEA rootfs, which make-cfw never opens,
        // so they were resolved separately against the mounted root
        // filesystem. Resolved only: `fw provision`, which is what applies
        // them, was not run.
        //
        // Those four rootfs binaries are byte-identical to the ones in the
        // iPhone12,1 24B119 rootfs, and every record lands on the same offset
        // with the same id. The two IPSWs do ship different OS volumes, which
        // Apple names RaveB24B119.N104OS and RaveB24B119.D421D431OS, and
        // /System/Library/xpc/launchd.plist differs between them exactly as
        // the two profiles' `launchdCacheSHA256` values record. So the volumes
        // are genuinely different images that happen to carry the same
        // userland executables, not one image reused.
        //
        // `devicetree` is resolved separately too, for both plans and both
        // boards, because `survey` sweeps only iboot/txm/kernel and make-cfw
        // reaches `restore` alone. The three boards ship genuinely different
        // trees (237068, 240096 and n104's 234920 bytes) and all three take
        // the same edits: `normal` removes content-protect, adds
        // no-effaceable-storage and boot-ios-diagnostics and updates
        // ephemeral-storage for +44 bytes, `restore` removes content-protect
        // for -36.
        //
        // That completes the plan surface: every plan `fw get-rd` and
        // `fw get-boot` would apply (ibss-ramdisk/ibss-normal on both iBSS and
        // the raw iBEC, txm restore/boot, devicetree restore/normal, kernel
        // restore and a boot plan) now resolves on each board's own
        // components. Neither phase was run, because both need an APTicket and
        // that comes from the phone, not the IPSW. What is missing there is a
        // signature, not a patch.
        //
        // What was not exercised, and is therefore not claimed: nothing past
        // make-cfw. No APTicket, no erase restore, no SSHRD, no provisioning,
        // no boot, no repeat boot, no finalization. A verified restore
        // artifact set is four levels short of a booting phone, and nobody
        // owns an 11 Pro or Pro Max to close that gap. SEP, cellular data,
        // Apple services and MobileBackup2 remain the project-wide gaps they
        // are on n104.
        //
        // The guards come from this IPSW's own root filesystem. One rootfs
        // (141-09290-215.dmg.aea) serves both boards, so the two entries share
        // all four values by construction and the IPSW is what makes that
        // true, not a copy between entries. `launchdSHA256` equals n104's
        // because /sbin/launchd is byte-identical across the boards; the
        // daemon count of 732 and the Setup count of 64 equal n104's as read
        // values, not carry-overs, and `launchdCacheSHA256` differs from
        // n104's, which is what proves these were measured from a different
        // image.
        //
        // `ibec-ignore-pinot-failure` resolves on n104 and finds nothing here.
        // That is correct: Pinot is the iPhone 11 LCD driver and these boards
        // carry a Summit OLED controller, so the hardware the plan patches is
        // absent. See `IBECPinotDriver`. It is a diagnostic reached only
        // through `resolve`, `apply`, `survey` and the fixture manifest; no
        // boot or restore artifact path uses it, so no device action loses a
        // patch on these boards.
        //
        // Empty boot plans follow the d421/d431 24A446 and 24A437 entries
        // above. `skipDisplayInitialization` is n104's display behaviour and
        // `ibss-skip-display-init` does resolve on both Pro boards, but
        // whether either needs it is a question only the hardware answers, and
        // applying an n104 workaround to a board that was never measured is
        // exactly what DeviceBootPlan exists to prevent. tfp0 is off for the
        // same reason: the plan resolves on this kernelcache, but the libkrw
        // runtime evidence under docs/runs is n104-only.
        //
        // `preservesIM4PCompression` is left at its uncompressed default, as
        // on the 24A437 and 24A446 Pro entries. That is an inference from the
        // shared SoC, not a measurement: these boards are T8030 like n104, so
        // their iBoot is expected to accept uncompressed payloads the way
        // n104's does and unlike j171aap's. It is the first thing to suspect
        // if a Pro board ever rejects the boot chain outright, and the
        // discriminating test is one `fw boot` attempt with this flipped.
        DeviceWorkflowProfile(
            id: "iphone12,3-d421ap-24B119",
            productVersion: "27.2",
            build: "24B119",
            productType: "iPhone12,3",
            deviceClass: "d421ap",
            chipID: 0x8030,
            boardID: 0x06,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.2_24B119_Restore",
            validationState: .experimental,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "7c9724d4e2e0de815b1f676d975c5ead2480bbc13d147a17a04b2abdc7f4e465",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        DeviceWorkflowProfile(
            id: "iphone12,5-d431ap-24B119",
            productVersion: "27.2",
            build: "24B119",
            productType: "iPhone12,5",
            deviceClass: "d431ap",
            chipID: 0x8030,
            boardID: 0x02,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.2_24B119_Restore",
            validationState: .experimental,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "7c9724d4e2e0de815b1f676d975c5ead2480bbc13d147a17a04b2abdc7f4e465",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // 27.3 beta 1, resolver-verified, measured, and device-validated on an
        // iPhone 11 on 2026-11-09: erase restore, SSHRD provisioning, normal
        // boot, repeat boot, Procursus finalization and setup-debugger all
        // passed. The Pro boards below have had no device run.
        //
        // What was exercised on the host, before the device run: `fw prepare`
        // on both shipped IPSWs, `survey` (0 failed) on both extracted trees,
        // `acm-probe` of ios273b1-24C5037i-acm-v1 against both kernelcaches
        // (24/26 exact on each, only the two scored entries ambiguous),
        // `devicetree` for both plans on all three boards (the trees are the
        // same sizes as 24B119's, 234920/237068/240096 bytes, and take the
        // same +44/-36 edits), `asr` (1) and `restored-fdr` (1) against this
        // build's own restore ramdisk, and `coreauthd` (1), `ctkd` (2),
        // `mobileactivationd` (5) and `commcenter` (3) against each board's
        // mounted root filesystem. Every rootfs userland record lands on the
        // same offset in both volumes, because the executables are
        // byte-identical across the boards - the volumes are nevertheless
        // different images, which the two differing `launchdCacheSHA256`
        // values record.
        //
        // The four oracles were measured with commands validated first
        // against 24B119, where they reproduced that build's recorded
        // launchd digest, cache digest, 732-daemon count and 64 Setup
        // methods exactly. On this build they read 737 daemons (+5 over
        // 24B119, the first movement of that count since beta 1 of 27.2 hit
        // 733) and 64 Setup methods, unchanged. Both digests differ from
        // every other entry.
        //
        // The OS volumes are named RaveCSeed24C5037i.N104DeveloperOS and
        // RaveCSeed24C5037i.D421D431DeveloperOS. Prior builds shipped
        // plain `...N104OS`. The device run answered the open question: the
        // Developer image name is cosmetic. The restore, both boots and
        // provisioning behaved exactly as on prior builds' plain N104OS
        // volumes.
        //
        // Repeat boot is recorded separately because a first boot that works
        // and a second that does not is a failure mode this device has
        // produced before. The evidence is /var/mobile/jbboot.log on the
        // Data volume the erase restore wiped: it carries two
        // `=== jbboot start ===` blocks, and the second adds injection
        // auto-enable and a SpringBoard restart so its tweaks load. The
        // booted kernel reports xnu-13432.60.57~17/PATCHED_ARM64_T8030,
        // which is both this profile's fingerprint and proof the kernel
        // identity records applied on this build.
        //
        // `finalize --check` reported complete on both boots: root SSH,
        // per-device Dropbear host keys, bootstrap shells, ElleKit 1.2, the
        // re-sign hook, injection auto-enable, the one-time System
        // application registration, persona 99, the icon read token and a
        // running PosterBoard repair watcher. First-boot load average ran
        // 283-338 in the first minutes - the same boot impulse earlier
        // builds showed - and settled to 2.5 after 51 minutes of uptime.
        //
        // tfp0 has runtime evidence on this build (2026-11-10, two boots of
        // the same artifact set): task_for_pid(0) returns a usable kernel
        // task port, the slide cave reports the live slide to the kernel task
        // alone while self and launchd keep their real dyld info, a kernel-map
        // scratch allocation round-trips write and read exactly, and the
        // boot-jit exception-port byte reads back patched at slide+unslid in
        // __DATA_CONST. Slides 0x45418000 and 0x44174000 across the two boots
        // show the shim reads the live global. One 27.3-specific finding,
        // recorded in docs/runs/IOS_273_24C5037i_TFP0.md: mach_vm_read over
        // execute-only kernel text freezes the machine - only data-region
        // readback is safe, unlike 27.2.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24C5037i",
            productVersion: "27.3",
            build: "24C5037i",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.3_24C5037i_Restore",
            validationState: .reviewed,
            launchdSHA256: "4e338d7aef1a1f77572dec5ef14eb64987080b1d22f5e0a580536cfd645bd078",
            launchdCacheSHA256: "0396c1683b660728c24b16ab599989d9a87b1ac4d12cd9273dfe1efcc7ac9e75",
            launchdCacheDaemonCount: 737,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        DeviceWorkflowProfile(
            id: "iphone12,3-d421ap-24C5037i",
            productVersion: "27.3",
            build: "24C5037i",
            productType: "iPhone12,3",
            deviceClass: "d421ap",
            chipID: 0x8030,
            boardID: 0x06,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.3_24C5037i_Restore",
            validationState: .experimental,
            launchdSHA256: "4e338d7aef1a1f77572dec5ef14eb64987080b1d22f5e0a580536cfd645bd078",
            launchdCacheSHA256: "369991684c9173cfd3be3b3c27aea2f0214a60cc038591b92cddca06e88802fe",
            launchdCacheDaemonCount: 737,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        DeviceWorkflowProfile(
            id: "iphone12,5-d431ap-24C5037i",
            productVersion: "27.3",
            build: "24C5037i",
            productType: "iPhone12,5",
            deviceClass: "d431ap",
            chipID: 0x8030,
            boardID: 0x02,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.3_24C5037i_Restore",
            validationState: .experimental,
            launchdSHA256: "4e338d7aef1a1f77572dec5ef14eb64987080b1d22f5e0a580536cfd645bd078",
            launchdCacheSHA256: "369991684c9173cfd3be3b3c27aea2f0214a60cc038591b92cddca06e88802fe",
            launchdCacheDaemonCount: 737,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // iOS 27.2.1, device-validated on an iPhone 11 (2026-11-14): erase
        // restore, SSHRD provisioning, normal boot, repeat boot, finalize and
        // setup-debugger all passed, 268 apps registered and visible on both
        // boots. A 24B119 point release sharing its kernel profile and tfp0
        // evidence; the launchd digest reproduces 24B119's, the cache digest
        // is new.
        DeviceWorkflowProfile(
            id: "iphone12,1-n104ap-24B156",
            productVersion: "27.2.1",
            build: "24B156",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.2.1_24B156_Restore",
            validationState: .reviewed,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "a07c37e3ffa51167cc43c1212008a25cb650c964bafaf281a298e5c01d9f597d",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [.skipDisplayInitialization],
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization],
                supportsTFP0KernelTaskPort: true
            )
        ),
        // iPhone 11 Pro on 27.2.1, measured, no device run. One rootfs serves
        // both boards, so these guards are shared with the d431 entry below;
        // the cache digest differs from n104's.
        DeviceWorkflowProfile(
            id: "iphone12,3-d421ap-24B156",
            productVersion: "27.2.1",
            build: "24B156",
            productType: "iPhone12,3",
            deviceClass: "d421ap",
            chipID: 0x8030,
            boardID: 0x06,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.2.1_24B156_Restore",
            validationState: .experimental,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "6f354c7a3e47c45ac08b59c38b97193d1a261e05944f9bfa4ca406663dc7a0cf",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
        // Same IPSW as the d421 entry above: one rootfs serves both boards,
        // so the guards are copied, not measured here, and the cache hash
        // fails closed if that ever stops being true.
        DeviceWorkflowProfile(
            id: "iphone12,5-d431ap-24B156",
            productVersion: "27.2.1",
            build: "24B156",
            productType: "iPhone12,5",
            deviceClass: "d431ap",
            chipID: 0x8030,
            boardID: 0x02,
            extractedDirectoryName: "iPhone12,3,iPhone12,5_27.2.1_24B156_Restore",
            validationState: .experimental,
            launchdSHA256: "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3",
            launchdCacheSHA256: "6f354c7a3e47c45ac08b59c38b97193d1a261e05944f9bfa4ca406663dc7a0cf",
            launchdCacheDaemonCount: 732,
            setupControllerMethodCount: 64,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),
    ]

    /// Every profile this IPSW could be restored with.
    ///
    /// A dual-device IPSW lists both boards, so several profiles match and the
    /// archive cannot say which phone is attached. `board` is how the operator
    /// resolves that.
    public static func matchingProfiles(
        for identity: IPSWIdentity,
        includeExperimental: Bool = false,
        board: String? = nil
    ) -> [DeviceWorkflowProfile] {
        profiles.filter {
            $0.supports(identity)
                && ($0.validationState == .reviewed || includeExperimental)
                && (board == nil || $0.deviceClass == board)
        }
    }

    /// The single profile for this IPSW, or nil when none or several match.
    /// Use `matchingProfiles` to tell those two cases apart.
    public static func profile(
        for identity: IPSWIdentity,
        includeExperimental: Bool = false,
        board: String? = nil
    ) -> DeviceWorkflowProfile? {
        let matches = matchingProfiles(
            for: identity,
            includeExperimental: includeExperimental,
            board: board
        )
        return matches.count == 1 ? matches[0] : nil
    }

    /// Shared so `prepare` and the device stages word this the same way.
    public static func ambiguityMessage(
        _ matches: [DeviceWorkflowProfile]
    ) -> String {
        """
        this IPSW supports several boards and Liter8 cannot tell which \
        phone you are using: \(boardList(matches)). Rerun with --board <device-class>
        """
    }

    /// For a `--board` that matched nothing while the IPSW itself is known.
    public static func unknownBoardMessage(
        _ board: String,
        offered: [DeviceWorkflowProfile]
    ) -> String {
        "no profile for --board \(board); this IPSW supports \(boardList(offered))"
    }

    private static func boardList(_ profiles: [DeviceWorkflowProfile]) -> String {
        Set(profiles.map(\.deviceClass)).sorted().joined(separator: ", ")
    }
}
