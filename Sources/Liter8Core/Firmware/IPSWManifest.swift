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

    public init(
        normalIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan],
        restoreIBSSAdditionalPlans: [DeviceIBSSAdditionalPlan]
    ) {
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
    ]

    public static func profile(
        for identity: IPSWIdentity,
        includeExperimental: Bool = false
    ) -> DeviceWorkflowProfile? {
        profiles.first {
            $0.supports(identity)
                && ($0.validationState == .reviewed || includeExperimental)
        }
    }
}
