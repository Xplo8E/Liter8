import Foundation

/// Resolves the four conditional branches that enter known SSV/data-protection
/// panic blocks.
///
/// These are not ordinary "find these four opcodes" patches. The useful shape
/// survives link-layout changes:
///
///     conditional branch -----> cold error block
///                                    |
///                                    +-- ADRP + ADD x0, panic format string
///                                    +-- BL _panic
///
/// Apple sometimes puts a distinctive phrase in the middle of a longer format
/// string. Code references the beginning of that C string, not necessarily the
/// first letter of our phrase, so resolution deliberately walks back to the
/// preceding NUL byte before asking for ADRP+ADD references.
struct KernelPanicResolver: Sendable {
    private let anchors: [(id: String, text: String)] = [
        ("root-snapshot", "Failed to find the root snapshot"),
        ("seal-broken", "root volume seal is broken"),
        ("rootvp-authentication", "rootvp not authenticated after mounting"),
        ("unencrypted-data-volume", "unencrypted data volume is not allowed"),
    ]

    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        return try anchors.map { anchor in
            let substrings = image.findAll(utf8: anchor.text, nulTerminated: false)
            guard let substringOffset = substrings.only else {
                if substrings.isEmpty { throw PatchfinderError.missingAnchor(anchor.text) }
                throw PatchfinderError.ambiguousAnchor(anchor.text, count: substrings.count)
            }
            let stringOffset = containingCStringStart(
                beforeOrAt: substringOffset,
                in: image
            )
            let references = try layout.adrpAddReferences(toFileOffset: stringOffset)
            guard let reference = references.only else {
                if references.count > 1 {
                    throw PatchfinderError.ambiguousCandidate(
                        "kernel panic xref: \(anchor.text)",
                        offsets: references.map(\.adrpOffset)
                    )
                }
                throw PatchfinderError.noCandidate("kernel panic xref: \(anchor.text)")
            }

            // A panic guard targets the beginning of the cold block. The
            // string materialization follows shortly afterwards. There can be
            // other conditionals entering the same block, so choose the target
            // with the smallest gap to the ADRP. That discriminator reproduced
            // all four known beta-2 sites and is independently checked against
            // the beta-4 fixture below.
            var branches: [(offset: UInt64, target: UInt64)] = []
            let targetFloor = reference.adrpOffset - min(reference.adrpOffset, 0x40)
            for range in layout.executableFileRanges {
                var offset = (range.lowerBound + 3) & ~UInt64(3)
                while offset + 4 <= range.upperBound {
                    let instruction = try image.readUInt32(at: offset)
                    guard let sourceAddress = layout.virtualAddress(forFileOffset: offset),
                          let targetAddress = ARM64.anyConditionalTarget(
                            instruction: instruction,
                            at: sourceAddress
                          ),
                          let targetOffset = layout.fileOffset(forVirtualAddress: targetAddress),
                          targetOffset >= targetFloor,
                          targetOffset <= reference.adrpOffset
                    else {
                        offset += 4
                        continue
                    }
                    branches.append((offset, targetOffset))
                    offset += 4
                }
            }

            let nearestGap = branches.map { reference.adrpOffset - $0.target }.min()
            let nearest = branches.filter { reference.adrpOffset - $0.target == nearestGap }
            guard let branch = nearest.only else {
                if nearest.isEmpty { throw PatchfinderError.noCandidate("kernel panic: \(anchor.text)") }
                throw PatchfinderError.ambiguousCandidate(
                    "kernel panic: \(anchor.text)",
                    offsets: nearest.map(\.offset)
                )
            }
            return PatchRecord(
                id: "kernel.panic.\(anchor.id)",
                component: "kernelcache",
                offset: branch.offset,
                original: try image.readUInt32(at: branch.offset),
                replacement: ARM64.nop,
                summary: "Do not enter the \(anchor.id) panic block",
                evidence: [
                    "unique diagnostic phrase: \(anchor.text)",
                    "unique ADRP+ADD reference to its containing C string",
                    "conditional target is uniquely closest to that xref within the 0x40-byte panic-block window",
                ]
            )
        }
    }

    /// Return the byte after the NUL terminating the previous C string.
    /// If the phrase begins at file offset zero, zero is already the start.
    private func containingCStringStart(beforeOrAt offset: UInt64, in image: BinaryImage) -> UInt64 {
        var cursor = Int(offset)
        while cursor > 0, image.data[cursor - 1] != 0 {
            cursor -= 1
        }
        return UInt64(cursor)
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
