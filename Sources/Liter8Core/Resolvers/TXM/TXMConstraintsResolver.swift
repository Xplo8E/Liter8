import Foundation

/// Resolves the three TXM signature-constraint branches used by both restore
/// and normal boot.
///
/// Two distinct checks live close together:
///
/// - a six-entry entitlement loop returns `0x00NN30A2` when restricted
///   task-port/debugger entitlements are present;
/// - `validateConstraintsSignatureType` constructs `0x000130A1` on its error
///   path. Two branches skip over the benign `MOV W0,#0xA1; B epilogue` path.
///
/// They have separate anchors and are resolved independently so a future build
/// cannot lose one check while accidentally satisfying the other.
public struct TXMConstraintsResolver: Sendable {
    public static let name = "txm-constraints"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let entitlementBranch = try findRestrictedEntitlementBranch(
            in: image,
            ranges: layout.executableFileRanges
        )
        let signatureBranches = try findSignatureTypeBranches(in: image)

        return [
            PatchRecord(
                id: "txm.constraints.restricted-entitlements",
                component: "TXM",
                offset: entitlementBranch,
                original: try image.readUInt32(at: entitlementBranch),
                replacement: ARM64.nop,
                summary: "Do not reject the six restricted task-port entitlements",
                evidence: [
                    "unique six-entry loop with TST W0,#0xff00",
                    "loop advances table pointer by 8 until 0x30 bytes",
                    "selected B.EQ returns the per-entry 0x00NN30A2 error",
                ]
            ),
            PatchRecord(
                id: "txm.constraints.signature-type-range",
                component: "TXM",
                offset: signatureBranches.rangeBranch,
                original: try image.readUInt32(at: signatureBranches.rangeBranch),
                replacement: ARM64.nop,
                summary: "Keep validateConstraintsSignatureType on its benign path",
                evidence: signatureBranches.evidence
            ),
            PatchRecord(
                id: "txm.constraints.signature-type-null",
                component: "TXM",
                offset: signatureBranches.nullBranch,
                original: try image.readUInt32(at: signatureBranches.nullBranch),
                replacement: ARM64.nop,
                summary: "Do not skip to the 0x000130A1 error construction",
                evidence: signatureBranches.evidence
            ),
        ]
    }

    private func findRestrictedEntitlementBranch(
        in image: BinaryImage,
        ranges: [Range<UInt64>]
    ) throws -> UInt64 {
        var candidates: [UInt64] = []
        for range in ranges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 24 <= range.upperBound {
                let test = try image.readUInt32(at: offset)
                let branch = try image.readUInt32(at: offset + 4)
                let addStatus = try image.readUInt32(at: offset + 8)
                let addIndex = try image.readUInt32(at: offset + 12)
                let compareEnd = try image.readUInt32(at: offset + 16)
                let loopBranch = try image.readUInt32(at: offset + 20)

                guard test == 0x7218_1C1F, // TST W0,#0xff00
                      branch & 0xFF00_001F == 0x5400_0000, // B.EQ
                      addStatus == 0x1140_4273, // ADD W19,W19,#0x10,LSL#12
                      addIndex == 0x9100_22B5, // ADD X21,X21,#8
                      compareEnd == 0xF100_C2BF, // CMP X21,#0x30
                      loopBranch & 0xFF00_001F == 0x5400_0001, // B.NE
                      let exitTarget = ARM64.conditionalTarget(instruction: branch, at: offset + 4),
                      let loopTarget = ARM64.conditionalTarget(instruction: loopBranch, at: offset + 20),
                      exitTarget < offset, loopTarget < offset
                else {
                    offset += 4
                    continue
                }
                candidates.append(offset + 4)
                offset += 4
            }
        }
        guard let candidate = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) entitlement loop") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) entitlement loop",
                offsets: candidates
            )
        }
        return candidate
    }

    private func findSignatureTypeBranches(in image: BinaryImage) throws -> SignatureBranches {
        // 0x000130A1 is assembled in two instructions. That exact pair is a
        // stronger anchor than either nearby conditional branch.
        let errorAnchor = words([0x5286_1420, 0x72A0_0020])
        let anchors = image.findAll(errorAnchor)
        guard let anchor = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor("TXM status 0x000130A1") }
            throw PatchfinderError.ambiguousAnchor("TXM status 0x000130A1", count: anchors.count)
        }
        guard anchor >= 0x2C else {
            throw PatchfinderError.noCandidate("\(Self.name) signature-type context")
        }

        let rangeBranch = anchor - 0x2C
        let nullBranch = anchor - 0x24
        let compare = try image.readUInt32(at: rangeBranch - 4)
        let range = try image.readUInt32(at: rangeBranch)
        let load = try image.readUInt32(at: rangeBranch + 4)
        let null = try image.readUInt32(at: nullBranch)
        let benignResult = try image.readUInt32(at: nullBranch + 4)

        guard compare == 0x7100_1A7F, // CMP W19,#6
              range & 0xFF00_001F == 0x5400_0003, // B.LO
              load == 0xF940_06A9, // LDR X9,[X21,#8]
              null & 0xFF00_001F == 0xB400_0009, // CBZ X9
              benignResult == 0x5280_1420 // MOV W0,#0xA1
        else {
            throw PatchfinderError.noCandidate("\(Self.name) signature-type control flow")
        }

        return SignatureBranches(
            rangeBranch: rangeBranch,
            nullBranch: nullBranch,
            evidence: [
                "unique MOV/MOVK construction of error 0x000130A1 at \(anchor.hex)",
                "B.LO and CBZ X9 skip the benign MOV W0,#0xA1 path",
                "fall-through branches directly to the epilogue before error construction",
            ]
        )
    }

    private func words(_ values: [UInt32]) -> Data {
        var result = Data()
        for var value in values.map(\.littleEndian) {
            withUnsafeBytes(of: &value) { result.append(contentsOf: $0) }
        }
        return result
    }
}

private struct SignatureBranches {
    let rangeBranch: UInt64
    let nullBranch: UInt64
    let evidence: [String]
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
