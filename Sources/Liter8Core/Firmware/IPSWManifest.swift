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

/// A reviewed host workflow for one exact firmware identity.
///
/// The profile names the output directory, but never supplies patch offsets.
/// Binary offsets remain the responsibility of semantic resolvers.
public struct IPSWWorkflowProfile: Equatable, Sendable {
    public let id: String
    public let productVersion: String
    public let build: String
    public let productType: String
    public let deviceClass: String
    public let chipID: UInt64
    public let boardID: UInt64
    public let extractedDirectoryName: String
    /// SHA-256 of stock `/sbin/launchd` accepted by device provisioning.
    /// This belongs to the exact firmware profile, beside the identity that
    /// selected it, rather than inside a generic Python or shell workflow.
    public let launchdSHA256: String?

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

public enum IPSWWorkflowRegistry {
    public static let profiles = [
        IPSWWorkflowProfile(
            id: "iphone12,1-n104ap-24A5390f",
            productVersion: "27.0",
            build: "24A5390f",
            productType: "iPhone12,1",
            deviceClass: "n104ap",
            chipID: 0x8030,
            boardID: 0x04,
            extractedDirectoryName: "iPhone12,1_27.0_24A5390f_Restore",
            launchdSHA256: "9ff28152483244a34cb43cd3541511f6989636e6814611c573b21b2ee43d70f7"
        ),
    ]

    public static func profile(for identity: IPSWIdentity) -> IPSWWorkflowProfile? {
        profiles.first { $0.supports(identity) }
    }
}
