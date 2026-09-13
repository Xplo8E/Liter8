import Foundation

/// Finds the digest-mismatch branch in `/usr/sbin/asr` by following the real
/// error-reporting call chain.
///
/// The anchor string is deliberately far from the patch site:
///
///     CBNZ W0, failureBlock       <- patch this
///       ...
///     failureBlock: BL reporter
///       ...
///     reporter: "Image failed signature verification."
///
/// Three conditional branches reach the reporter's caller block in beta 4.
/// Only the signature check is `CBNZ W0` immediately after a BL (the `memcmp`).
/// This distinction prevents the old b3 offset mistake of NOPing the call itself.
public struct ASRSignatureResolver: Sendable {
    public static let name = "asr-signature"
    private static let anchor = "Image failed signature verification."

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let anchors = image.findAll(utf8: Self.anchor, nulTerminated: true)
        guard let anchorOffset = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }

        let references = try layout.adrpAddReferences(toFileOffset: anchorOffset)
        guard let reference = references.only else {
            if references.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) reporter xref") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) reporter xref",
                offsets: references.map(\.adrpOffset)
            )
        }

        let reporterEntry = try findFunctionEntry(before: reference.adrpOffset, in: image)
        let callers = try findCallers(of: reporterEntry, layout: layout)
        guard !callers.isEmpty else {
            throw PatchfinderError.noCandidate("\(Self.name) reporter callers")
        }

        var candidates: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                let branch = try image.readUInt32(at: offset)

                // CBNZ W0 is the comparison-result gate. Requiring W0 and the
                // immediately preceding BL excludes two other branches which
                // happen to enter the same error block for unrelated reasons.
                guard branch & 0xFF00_001F == 0x3500_0000, // CBNZ W0,<target>
                      offset >= 4,
                      ARM64.branchLinkTarget(
                          instruction: try image.readUInt32(at: offset - 4),
                          at: offset - 4
                      ) != nil,
                      let target = ARM64.conditionalTarget(instruction: branch, at: offset),
                      callers.contains(where: { caller in
                          target >= caller - 0x20 && target <= caller
                      })
                else {
                    offset += 4
                    continue
                }
                candidates.append(offset)
                offset += 4
            }
        }

        guard let patchOffset = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }

        return [PatchRecord(
            id: "asr.signature-mismatch-branch",
            component: "asr",
            offset: patchOffset,
            original: try image.readUInt32(at: patchOffset),
            replacement: ARM64.nop,
            summary: "Do not enter the image-signature failure block after memcmp",
            evidence: [
                "unique signature-failure string at \(anchorOffset.hex)",
                "reporter function begins at \(reporterEntry.hex)",
                "reporter callers: \(callers.map(\.hex).joined(separator: ", "))",
                "unique CBNZ W0 into caller block immediately follows a BL",
            ]
        )]
    }

    private func findFunctionEntry(before offset: UInt64, in image: BinaryImage) throws -> UInt64 {
        var cursor = offset
        while cursor >= 4 {
            cursor -= 4
            if ARM64.isReturn(try image.readUInt32(at: cursor)) {
                return cursor + 4
            }
        }
        throw PatchfinderError.noCandidate("\(Self.name) reporter function boundary")
    }

    private func findCallers(of targetOffset: UInt64, layout: MachOLayout) throws -> [UInt64] {
        guard let targetAddress = layout.virtualAddress(forFileOffset: targetOffset) else {
            throw PatchfinderError.invalidFixture("reporter entry is outside mapped segments")
        }
        var callers: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                let instruction = try layout.image.readUInt32(at: offset)
                if let pc = layout.virtualAddress(forFileOffset: offset),
                   ARM64.branchLinkTarget(instruction: instruction, at: pc) == targetAddress
                {
                    callers.append(offset)
                }
                offset += 4
            }
        }
        return callers
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
