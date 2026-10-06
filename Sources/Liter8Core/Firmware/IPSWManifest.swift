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
public enum DeviceBootTrustCache: String, Codable, Equatable, Sendable {
    case restore = "RestoreTrustCache"
    case `static` = "StaticTrustCache"
}

public struct DeviceBootPlan: Codable, Equatable, Sendable {
    /// Required semantic components, not a best-effort filter of the manifest.
    /// Missing firmware must fail before a boot set is built or uploaded.
    public static let defaultFirmwareComponents = [
        "RestoreLogo", "ANE", "AOP", "AVE", "Ap,SecurePageTableMonitor",
        "GFX", "ISP", "PMP", "SIO", "WCHFirmwareUpdater", "SEP",
    ]
    public let firmwareComponents: [String]
    public let normalTrustCache: DeviceBootTrustCache
    public let normalIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan]
    public let restoreIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan]

    public init(
        normalIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan],
        restoreIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan],
        firmwareComponents: [String] = DeviceBootPlan.defaultFirmwareComponents,
        normalTrustCache: DeviceBootTrustCache = .restore
    ) {
        self.firmwareComponents = firmwareComponents
        self.normalTrustCache = normalTrustCache
        self.normalIBSSAdditionalPlans = normalIBSSAdditionalPlans
        self.restoreIBSSAdditionalPlans = restoreIBSSAdditionalPlans
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
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
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
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
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
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
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
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
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
                restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
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
        // iPad 8 Wi-Fi, 23H30. Guards measured from 141-38001-023.dmg.
        // Restore and SSHRD passed in the recorded run; normal boot,
        // finalization and repeat boot are unverified. Keep experimental.
        // No n104 display workaround, SPTM/TXM, PMP or WCH on this identity.
        // See docs/plans/IPAD8_26_7_1_PORT.md and the device runbook.
        DeviceWorkflowProfile(
            id: "ipad11,6-j171aap-23H30",
            productVersion: "26.7.1",
            build: "23H30",
            productType: "iPad11,6",
            deviceClass: "j171aap",
            chipID: 0x8020,
            boardID: 0x24,
            extractedDirectoryName: "iPad11,6_26.7.1_23H30_Restore",
            validationState: .experimental,
            launchdSHA256: "1b37dae048542729a622a1a3f4b77ec8829d32e918f0d6a0c0c037f32d9e84b1",
            launchdCacheSHA256: "af9183685525a0833fea7a16c7a81b3f85e14372ea33d49f3e1ec6ab1a90ca4f",
            launchdCacheDaemonCount: 672,
            setupControllerMethodCount: 58,
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: [],
                firmwareComponents: [
                    "RestoreLogo", "ANE", "AOP", "AVE", "GFX", "ISP", "SIO", "SEP",
                ],
                normalTrustCache: .static
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
