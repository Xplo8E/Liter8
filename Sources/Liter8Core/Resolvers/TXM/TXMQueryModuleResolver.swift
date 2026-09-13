import Foundation

/// Finds the three TXM trust-cache comparisons used by `queryModule`.
///
/// TXM compares two 20-byte truncated CDHashes like this:
///
///     MOV X0, hashFromSignature
///     MOV X1, hashFromTrustCache
///     MOV W2, #0x14
///     BL  memcmp                 <- replace with MOV X0,#0
///     CBZ W0, hashesMatch
///
/// There is a fourth `MOV W2,#0x14; BL memcmp` in beta 4, but it loads its
/// arguments differently and follows the call with `CMP W0,#0`. Requiring the
/// complete five-instruction shape is what excludes it; we never patch "the
/// first three" merely because that happens to match the current layout.
public struct TXMQueryModuleResolver: Sendable {
    public static let name = "txm-query-module"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        var candidates: [(offset: UInt64, callTarget: UInt64)] = []

        for range in layout.executableFileRanges {
            var callOffset = ((range.lowerBound + 12) + 3) & ~UInt64(3)
            while callOffset + 8 <= range.upperBound {
                let moveX0 = try image.readUInt32(at: callOffset - 12)
                let moveX1 = try image.readUInt32(at: callOffset - 8)
                let length = try image.readUInt32(at: callOffset - 4)
                let call = try image.readUInt32(at: callOffset)
                let resultBranch = try image.readUInt32(at: callOffset + 4)

                // MOV Xd,Xm is the ORR alias with XZR as the first source. The
                // masks retain destination X0/X1 but allow the source registers
                // to differ between the three inlined queryModule paths.
                guard moveX0 & 0xFFE0_FFFF == 0xAA00_03E0, // MOV X0,Xn
                      moveX1 & 0xFFE0_FFFF == 0xAA00_03E1, // MOV X1,Xn
                      length == 0x5280_0282, // MOV W2,#0x14
                      resultBranch & 0xFF00_001F == 0x3400_0000, // CBZ W0
                      let pc = layout.virtualAddress(forFileOffset: callOffset),
                      let target = ARM64.branchLinkTarget(instruction: call, at: pc)
                else {
                    callOffset += 4
                    continue
                }
                candidates.append((callOffset, target))
                callOffset += 4
            }
        }

        guard candidates.count == 3 else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(
                Self.name,
                offsets: candidates.map(\.offset)
            )
        }
        guard Set(candidates.map(\.callTarget)).count == 1 else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "the three CDHash comparisons do not call one shared memcmp"
            )
        }

        return try candidates.sorted { $0.offset < $1.offset }.enumerated().map { index, candidate in
            PatchRecord(
                id: "txm.query-module.\(index)",
                component: "TXM",
                offset: candidate.offset,
                original: try image.readUInt32(at: candidate.offset),
                replacement: ARM64.movX0Zero,
                summary: "Make queryModule CDHash comparison \(index) report equality",
                evidence: [
                    "MOV X0,Xn / MOV X1,Xn / MOV W2,#0x14 / BL / CBZ W0",
                    "all three selected calls target one memcmp implementation",
                    "fourth 20-byte comparison rejected because it uses CMP after BL",
                ]
            )
        }
    }
}
