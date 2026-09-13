import Foundation

/// The small normal-boot policy family that is independent of SEP and MACF:
/// two persona rejection branches and the USB restore-mode predicate.
///
/// This is deliberately separate from `KernelRestoreResolver`. A restore or
/// ramdisk boot already has `rd=md0`, so forcing restore mode there is redundant,
/// while the persona override is needed only by normal userland package tools.
public struct KernelBootPolicyResolver: Sendable {
    public static let name = "kernel-boot-policy"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        return try personaGuards(in: image, layout: layout)
            + restoreModeStub(in: image, layout: layout)
    }

    // MARK: - spawn_validate_persona

    /// Find the narrow non-root UID/GID rejection at the end of
    /// `spawn_validate_persona`.
    ///
    /// Source-level shape:
    ///
    ///     load sibling field at +0x18; CBZ continue
    ///     load persona UID at +0x08; CBZ deny
    ///     load persona GID at +0x0c; CBZ deny
    ///     fallthrough: result = 0
    ///     deny:        result = 1
    ///
    /// Both patched branches must test the register just loaded, use the same
    /// base object, and land on the same `mov wN,#1` deny block. This avoids
    /// turning a generic pair of nearby CBZ instructions into a patch.
    private func personaGuards(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        var matches: [(uid: UInt64, gid: UInt64)] = []

        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 24 <= range.upperBound {
                let siblingLoad = try image.readUInt32(at: offset)
                let siblingBranch = try image.readUInt32(at: offset + 4)
                let uidLoad = try image.readUInt32(at: offset + 8)
                let uidBranch = try image.readUInt32(at: offset + 12)
                let gidLoad = try image.readUInt32(at: offset + 16)
                let gidBranch = try image.readUInt32(at: offset + 20)

                guard let sibling = decodeLDRWUnsigned(siblingLoad), sibling.byteOffset == 0x18,
                      isCBZW(siblingBranch, register: sibling.destination),
                      let uid = decodeLDRWUnsigned(uidLoad), uid.byteOffset == 0x08,
                      let gid = decodeLDRWUnsigned(gidLoad), gid.byteOffset == 0x0C,
                      uid.base == gid.base,
                      isCBZW(uidBranch, register: uid.destination),
                      isCBZW(gidBranch, register: gid.destination),
                      let uidAddress = layout.virtualAddress(forFileOffset: offset + 12),
                      let gidAddress = layout.virtualAddress(forFileOffset: offset + 20),
                      let uidTargetAddress = ARM64.conditionalTarget(
                        instruction: uidBranch,
                        at: uidAddress
                      ),
                      let gidTargetAddress = ARM64.conditionalTarget(
                        instruction: gidBranch,
                        at: gidAddress
                      ),
                      uidTargetAddress == gidTargetAddress,
                      let denyOffset = layout.fileOffset(forVirtualAddress: uidTargetAddress),
                      denyOffset + 4 <= UInt64(image.count)
                else {
                    offset += 4
                    continue
                }

                // The fallthrough accepts the request with result zero; the
                // common branch target rejects it with result one. Require the
                // same destination register so the CFG meaning is explicit.
                let accept = try image.readUInt32(at: offset + 24)
                let deny = try image.readUInt32(at: denyOffset)
                let resultRegister = accept & 0x1F
                guard accept & 0xFFFF_FFE0 == 0x5280_0000, // MOV Wn,#0
                      deny == 0x5280_0020 | resultRegister // MOV Wn,#1
                else {
                    offset += 4
                    continue
                }

                matches.append((offset + 12, offset + 20))
                offset += 4
            }
        }

        guard let match = matches.only else {
            if matches.isEmpty { throw PatchfinderError.noCandidate("spawn_validate_persona sibling guards") }
            throw PatchfinderError.ambiguousCandidate(
                "spawn_validate_persona sibling guards",
                offsets: matches.flatMap { [$0.uid, $0.gid] }
            )
        }
        return try [
            wordPatch(
                id: "kernel.persona.uid-zero",
                offset: match.uid,
                replacement: ARM64.nop,
                summary: "Allow the persona UID override to be zero",
                evidence: [
                    "LDR Wn,[persona,#8] followed by CBZ Wn",
                    "UID and GID branches share the same result-one deny block",
                ],
                image: image
            ),
            wordPatch(
                id: "kernel.persona.gid-zero",
                offset: match.gid,
                replacement: ARM64.nop,
                summary: "Allow the persona GID override to be zero",
                evidence: [
                    "LDR Wn,[persona,#0xc] followed by CBZ Wn",
                    "fallthrough writes result zero while the shared target writes result one",
                ],
                image: image
            ),
        ]
    }

    // MARK: - isDeviceInRestoreMode

    /// Locate the restore-mode predicate through the `rd`/`rootdev` boot-arg
    /// cluster and its two sibling `PE_parse_boot_argn` calls.
    ///
    /// Searching for the two letters "rd" alone would be garbage: the
    /// kernelcache contains many such substrings. The surrounding string
    /// cluster identifies the correct literal, and the call/data-flow checks
    /// identify which of its xrefs is the actual boolean predicate.
    private func restoreModeStub(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        let prefix = "1211111212221212111111111111111111111"
        let cluster = Data((prefix + "\0rd\0rootdev\0-restore\0%02X").utf8)
        let clusters = image.findAll(cluster)
        guard let clusterOffset = clusters.only else {
            if clusters.isEmpty { throw PatchfinderError.missingAnchor("rd/rootdev boot-argument cluster") }
            throw PatchfinderError.ambiguousAnchor("rd/rootdev boot-argument cluster", count: clusters.count)
        }
        let rdOffset = clusterOffset + UInt64(prefix.utf8.count + 1)
        let references = try layout.adrpAddReferences(toFileOffset: rdOffset)
        var candidates: [UInt64] = []

        for reference in references {
            guard let firstCall = try parseBootArgumentCall(
                afterAdd: reference.addOffset,
                in: image,
                layout: layout
            ),
            let functionStart = try? nearestPACIBSP(
                beforeOrAt: reference.adrpOffset,
                maximumDistance: 0x100,
                in: image,
                layout: layout
            ),
            functionStart >= 4,
            try image.readUInt32(at: functionStart - 4) == 0xD65F_0FFF // RETAB
            else { continue }

            // The predicate parses both `rd` and `rootdev` into the same local
            // buffer using the same helper. A lone boot-arg parser elsewhere
            // in the kernel therefore cannot satisfy this check.
            var foundSibling = false
            var cursor = firstCall + 4
            let limit = min(reference.addOffset + 0x40, UInt64(image.count) - 16)
            while cursor <= limit {
                if isADRPX0(try image.readUInt32(at: cursor)),
                   isADDX0X0(try image.readUInt32(at: cursor + 4)),
                   let siblingCall = try parseBootArgumentCall(
                    afterAdd: cursor + 4,
                    in: image,
                    layout: layout
                   ),
                   try directCallTarget(at: siblingCall, in: image, layout: layout)
                    == directCallTarget(at: firstCall, in: image, layout: layout)
                {
                    foundSibling = true
                    break
                }
                cursor += 4
            }
            if foundSibling { candidates.append(functionStart) }
        }

        let uniqueCandidates = Array(Set(candidates)).sorted()
        guard let start = uniqueCandidates.only else {
            if uniqueCandidates.isEmpty { throw PatchfinderError.noCandidate("isDeviceInRestoreMode") }
            throw PatchfinderError.ambiguousCandidate("isDeviceInRestoreMode", offsets: uniqueCandidates)
        }
        return try [
            wordPatch(
                id: "kernel.usb.restore-mode-result",
                offset: start,
                replacement: ARM64.movX0One,
                summary: "Report restore mode to the USB Restricted Mode policy",
                evidence: [
                    "unique rd/rootdev/-restore boot-argument string cluster",
                    "function owns sibling rd and rootdev parser calls to the same helper",
                    "arm64e entry follows RETAB",
                ],
                image: image
            ),
            wordPatch(
                id: "kernel.usb.restore-mode-return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return the forced restore-mode result",
                evidence: ["paired entry-point stub"],
                image: image
            ),
        ]
    }

    /// Validate `ADD materialized-string; MOV X1,SP; MOV W2,#0x20; BL parser`
    /// and return the BL file offset.
    private func parseBootArgumentCall(
        afterAdd addOffset: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64? {
        guard addOffset + 16 <= UInt64(image.count),
              try image.readUInt32(at: addOffset + 4) == 0x9100_03E1, // MOV X1,SP
              try image.readUInt32(at: addOffset + 8) == 0x5280_0402, // MOV W2,#0x20
              try directCallTarget(at: addOffset + 12, in: image, layout: layout) != nil
        else { return nil }
        return addOffset + 12
    }

    private func nearestPACIBSP(
        beforeOrAt offset: UInt64,
        maximumDistance: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64 {
        guard let range = layout.executableFileRanges.first(where: { $0.contains(offset) }) else {
            throw PatchfinderError.noCandidate("executable range for boot-argument xref")
        }
        let floor = max(range.lowerBound, offset - min(maximumDistance, offset - range.lowerBound))
        var cursor = offset & ~UInt64(3)
        while cursor >= floor + 4 {
            if try image.readUInt32(at: cursor) == 0xD503_237F { return cursor } // PACIBSP
            cursor -= 4
        }
        throw PatchfinderError.noCandidate("PACIBSP before boot-argument xref")
    }

    private func directCallTarget(
        at offset: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64? {
        guard let sourceAddress = layout.virtualAddress(forFileOffset: offset),
              let targetAddress = ARM64.branchLinkTarget(
                instruction: try image.readUInt32(at: offset),
                at: sourceAddress
              )
        else { return nil }
        return layout.fileOffset(forVirtualAddress: targetAddress)
    }

    private func decodeLDRWUnsigned(_ instruction: UInt32) -> (destination: UInt32, base: UInt32, byteOffset: UInt32)? {
        guard instruction & 0xFFC0_0000 == 0xB940_0000 else { return nil } // LDR Wt,[Xn,#imm]
        return (
            destination: instruction & 0x1F,
            base: (instruction >> 5) & 0x1F,
            byteOffset: ((instruction >> 10) & 0xFFF) * 4
        )
    }

    private func isCBZW(_ instruction: UInt32, register: UInt32) -> Bool {
        instruction & 0xFF00_001F == 0x3400_0000 | register // CBZ Wregister,<target>
    }

    private func isADRPX0(_ instruction: UInt32) -> Bool {
        instruction & 0x9F00_001F == 0x9000_0000 // ADRP X0,<page>
    }

    private func isADDX0X0(_ instruction: UInt32) -> Bool {
        instruction & 0xFFC0_03FF == 0x9100_0000 // ADD X0,X0,#imm
    }

    private func wordPatch(
        id: String,
        offset: UInt64,
        replacement: UInt32,
        summary: String,
        evidence: [String],
        image: BinaryImage
    ) throws -> PatchRecord {
        PatchRecord(
            id: id,
            component: "kernelcache",
            offset: offset,
            original: try image.readUInt32(at: offset),
            replacement: replacement,
            summary: summary,
            evidence: evidence
        )
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
