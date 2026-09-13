import Foundation

/// Makes `-[TKSEPKeyServer serverAttributesOfKey:error:]` return nil without
/// entering the unavailable SEP-backed implementation.
public struct CTKDResolver: Sendable {
    public static let name = "ctkd"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let metadata = try ObjCMetadata(image: image)
        let methods = try metadata.methods(named: "serverAttributesOfKey:error:")
        guard let method = methods.only else {
            if methods.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(
                Self.name,
                offsets: methods.map(\.implementationOffset)
            )
        }

        let entry = method.implementationOffset
        let landingPad = try image.readUInt32(at: entry)
        let stackFrame = try image.readUInt32(at: entry + 4)

        // PACIBSP identifies a real arm64e function entry. Requiring the word
        // before it to be RETAB and the next word to allocate a stack frame
        // prevents a coincidental relative-method decode from becoming a patch.
        guard entry >= 4,
              try image.readUInt32(at: entry - 4) == 0xD65F_0FFF, // RETAB
              landingPad == 0xD503_237F, // PACIBSP
              stackFrame & 0xFFC0_03FF == 0xD100_03FF // SUB SP,SP,#imm
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "resolved method does not have the expected arm64e entry frame"
            )
        }

        let evidence = [
            "unique Objective-C selector serverAttributesOfKey:error:",
            "relative method entry at \(method.entryOffset.hex) resolves to \(entry.hex)",
            "RETAB / PACIBSP / SUB SP,SP entry boundary",
        ]
        return [
            PatchRecord(
                id: "ctkd.sep-key-server.return-nil",
                component: "ctkd",
                offset: entry,
                original: landingPad,
                replacement: ARM64.movX0Zero,
                summary: "Return nil from serverAttributesOfKey:error:",
                evidence: evidence
            ),
            PatchRecord(
                id: "ctkd.sep-key-server.return",
                component: "ctkd",
                offset: entry + 4,
                original: stackFrame,
                replacement: ARM64.ret,
                summary: "Return before entering the SEP-backed method body",
                evidence: evidence
            ),
        ]
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
