import Foundation

/// BuildManifest-derived input shared with the generic Python workflow.
///
/// Python receives semantic component names such as `iBSS` and
/// `RestoreKernelCache`; it never guesses board-specific filenames. Binary
/// signatures and replacement instructions remain exclusively in Swift.
public struct FirmwareWorkflowContext: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schema: Int
    public let profileID: String
    public let productVersion: String
    public let build: String
    public let productType: String
    public let deviceClass: String
    public let variant: String
    public let sourceRoot: String
    public let components: [String: String]

    /// Select the normal developer erase identity for the profile's hardware.
    /// Research and upgrade identities often point at different iBoot or
    /// ramdisk artifacts, so silently taking the first manifest entry is unsafe.
    public static func load(
        profile: IPSWWorkflowProfile,
        sourceRoot: URL
    ) throws -> FirmwareWorkflowContext {
        let manifestURL = sourceRoot.appendingPathComponent("BuildManifest.plist")
        let object = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: manifestURL),
            format: nil
        )
        guard let plist = object as? [String: Any],
              let identities = plist["BuildIdentities"] as? [[String: Any]] else {
            throw PatchfinderError.invalidFixture(
                "BuildManifest.plist contains no build identities"
            )
        }

        let hardwareMatches = identities.filter { identity in
            guard let info = identity["Info"] as? [String: Any] else { return false }
            return info["DeviceClass"] as? String == profile.deviceClass
                && integer(identity["ApChipID"]) == profile.chipID
                && integer(identity["ApBoardID"]) == profile.boardID
        }
        let eraseMatches = hardwareMatches.filter { identity in
            guard let info = identity["Info"] as? [String: Any],
                  let variant = info["Variant"] as? String else { return false }
            let normalized = variant.lowercased()
            return normalized.contains("erase install") && !normalized.contains("research")
        }
        guard eraseMatches.count == 1, let selected = eraseMatches.first,
              let info = selected["Info"] as? [String: Any],
              let variant = info["Variant"] as? String,
              let manifest = selected["Manifest"] as? [String: Any] else {
            throw PatchfinderError.invalidFixture(
                "expected exactly one non-research erase identity for \(profile.deviceClass); found \(eraseMatches.count)"
            )
        }

        var components: [String: String] = [:]
        for (name, rawEntry) in manifest {
            guard let entry = rawEntry as? [String: Any],
                  let componentInfo = entry["Info"] as? [String: Any],
                  let path = componentInfo["Path"] as? String else { continue }
            try validateRelativeComponentPath(path, name: name)
            components[name] = path
        }

        let required = ["iBSS", "iBEC", "RestoreDeviceTree", "RestoreKernelCache", "RestoreRamDisk"]
        let missing = required.filter { components[$0] == nil }
        guard missing.isEmpty else {
            throw PatchfinderError.invalidFixture(
                "selected BuildManifest identity is missing components: \(missing.joined(separator: ", "))"
            )
        }

        return FirmwareWorkflowContext(
            schema: schemaVersion,
            profileID: profile.id,
            productVersion: profile.productVersion,
            build: profile.build,
            productType: profile.productType,
            deviceClass: profile.deviceClass,
            variant: variant,
            sourceRoot: sourceRoot.standardizedFileURL.path,
            components: components
        )
    }

    /// Write atomically so an interrupted command cannot leave Python with a
    /// truncated or half-updated component map.
    public func write(to url: URL) throws {
        let data = try JSONEncoder.liter8.encode(self)
        try data.write(to: url, options: .atomic)
    }

    private static func validateRelativeComponentPath(_ path: String, name: String) throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.contains("\\"),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw PatchfinderError.invalidFixture(
                "BuildManifest component \(name) has unsafe path: \(path)"
            )
        }
    }

    private static func integer(_ value: Any?) -> UInt64? {
        if let number = value as? NSNumber { return number.uint64Value }
        guard let text = value as? String else { return nil }
        if text.hasPrefix("0x") || text.hasPrefix("0X") {
            return UInt64(text.dropFirst(2), radix: 16)
        }
        return UInt64(text, radix: 10)
    }
}

private extension JSONEncoder {
    static var liter8: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}
