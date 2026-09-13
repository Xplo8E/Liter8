import Foundation

public struct PatchRecord: Codable, Equatable, Sendable {
    public let id: String
    public let component: String
    public let offset: UInt64
    public let originalBytes: Data
    public let replacementBytes: Data
    public let summary: String
    public let evidence: [String]

    /// Build an arbitrary byte patch. This is used for strings and shellcode as
    /// well as instructions; original and replacement lengths must match so a
    /// patch cannot silently move data or change the firmware container layout.
    public init(
        id: String,
        component: String,
        offset: UInt64,
        originalBytes: Data,
        replacementBytes: Data,
        summary: String,
        evidence: [String]
    ) {
        self.id = id
        self.component = component
        self.offset = offset
        self.originalBytes = originalBytes
        self.replacementBytes = replacementBytes
        self.summary = summary
        self.evidence = evidence
    }

    /// Convenience initializer for the common one-instruction ARM64 patch.
    public init(
        id: String,
        component: String,
        offset: UInt64,
        original: UInt32,
        replacement: UInt32,
        summary: String,
        evidence: [String]
    ) {
        var original = original.littleEndian
        var replacement = replacement.littleEndian
        self.init(
            id: id,
            component: component,
            offset: offset,
            originalBytes: withUnsafeBytes(of: &original) { Data($0) },
            replacementBytes: withUnsafeBytes(of: &replacement) { Data($0) },
            summary: summary,
            evidence: evidence
        )
    }

    public var originalWord: UInt32? {
        guard originalBytes.count == 4 else { return nil }
        return originalBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
    }

    public var replacementWord: UInt32? {
        guard replacementBytes.count == 4 else { return nil }
        return replacementBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
    }

    private enum CodingKeys: String, CodingKey {
        case id, component, offset, originalBytes, replacementBytes, summary, evidence
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        component = try values.decode(String.self, forKey: .component)
        offset = try values.decode(UInt64.self, forKey: .offset)
        summary = try values.decode(String.self, forKey: .summary)
        evidence = try values.decode([String].self, forKey: .evidence)

        let originalHex = try values.decode(String.self, forKey: .originalBytes)
        let replacementHex = try values.decode(String.self, forKey: .replacementBytes)
        guard let original = Data(hexadecimalString: originalHex),
              let replacement = Data(hexadecimalString: replacementHex)
        else {
            throw DecodingError.dataCorruptedError(
                forKey: .originalBytes,
                in: values,
                debugDescription: "patch bytes must be even-length hexadecimal strings"
            )
        }
        originalBytes = original
        replacementBytes = replacement
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(component, forKey: .component)
        try values.encode(offset, forKey: .offset)
        try values.encode(originalBytes.hexadecimalString, forKey: .originalBytes)
        try values.encode(replacementBytes.hexadecimalString, forKey: .replacementBytes)
        try values.encode(summary, forKey: .summary)
        try values.encode(evidence, forKey: .evidence)
    }
}
