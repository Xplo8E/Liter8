import Foundation

/// Profile-gated kernel patches for libkrw's tfp0 backend.
struct KernelTFP0Resolver: Sendable {
    static let variantKey = "kernel-tfp0"
    static let signatureID = "ios27-24A435-tfp0-v2"
    static let payloadID = "task-for-pid-zero-slide-v2"

    private static let slideFormat = "KernelCache slide: 0x%016lx\n"
    private static let slideRecordID = "kernel.tfp0.dyld-info-slide"
    // LDR X8,[X20,#0x3e0]; STR X8,[X22]; LDR X8,[X20,#0x3e8].
    private static let slideOriginal = instructionData([
        0xF941_F288, 0xF900_02C8, 0xF941_F688,
    ])

    // The count checks and final +8 store identify TASK_DYLD_INFO. The three
    // result instructions are ignored so clean and already-patched input match.
    private static let taskDyldInfoPattern = MaskedInstructionPattern(
        name: "TASK_DYLD_INFO result construction",
        referenceWords: [
            0xB940_02A8, 0x7100_111F, 0x5400_1A83,
            0xF941_F288, 0xF900_02C8, 0xF941_F688,
            0xF900_06C8, 0xB940_02A8, 0x7100_151F, 0x5400_24C3,
        ],
        allowDataLayoutDrift: true,
        ignoring: [3, 4, 5]
    )

    private struct Site: Sendable {
        let id: String
        let summary: String
        let name: String
        let words: [UInt32]
        let patchIndex: Int
        let replacement: UInt32
        let allowDataLayoutDrift: Bool
    }

    private static let sites = [
        // CMP X0,X9 becomes CMP XZR,XZR, forcing the success condition.
        Site(
            id: "kernel.tfp0.task-conversion",
            summary: "Make the task-conversion success edge unconditional",
            name: "tfp0 task conversion",
            words: [
                0xAA00_03E8, 0xAA13_03E0, 0x3400_0268, 0x5280_0008,
                0xEB01_001F, 0x5400_0240, 0xB0FE_D5A9, 0xF945_3129,
                0xEB09_001F, 0x5400_01C0, 0xEB09_003F, 0x5400_0160,
            ],
            patchIndex: 8,
            replacement: 0xEB1F_03FF,
            allowDataLayoutDrift: true
        ),
        // CBZ W23,reject becomes NOP, so PID 0 reaches task_for_pid().
        Site(
            id: "kernel.tfp0.pid-zero",
            summary: "Let task_for_pid continue when PID is zero",
            name: "tfp0 PID-zero gate",
            words: [
                0x9101_C3FD, 0xAA00_03E8, 0xB940_0000, 0xB940_0917,
                0xF940_0913, 0xB900_1FFF, 0xA900_FFFF, 0xF900_03FF,
                0x3400_07F7, 0x5280_0001, 0x5280_0002, 0x5280_0003,
                0xD280_0004, 0x9400_0000, 0xB400_0720, 0xAA00_03F4,
            ],
            patchIndex: 8,
            replacement: ARM64.nop,
            allowDataLayoutDrift: false
        ),
        // B.NE allowed becomes an unconditional B to the same target.
        Site(
            id: "kernel.tfp0.kernel-map",
            summary: "Skip the userspace kernel_pmap panic",
            name: "tfp0 kernel-map panic",
            words: [
                0xF2E4_A191, 0xDAC1_1A30, 0xAA10_03F1, 0xDAC1_47F1,
                0xEB11_021F, 0x5400_0040, 0xD438_8E40, 0xB000_59A8,
                0x9122_4108, 0xEB08_021F, 0x5400_0141, 0x5281_6C08,
            ],
            patchIndex: 10,
            replacement: 0x1400_000A,
            allowDataLayoutDrift: true
        ),
    ]

    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        let profile = KernelResolverProfileRegistry.detect(in: image)
        guard let variant = profile?.variants(for: variantKey),
              variant.support == .supported,
              variant.signature == signatureID,
              variant.payload == payloadID
        else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: variantKey,
                profile: profile?.id ?? "unidentified",
                variant: "unregistered"
            )
        }
        return try Self().resolve(in: image)
    }

    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let records = try Self.sites.map { site in
            precondition(site.words.indices.contains(site.patchIndex))
            let pattern = MaskedInstructionPattern(
                name: site.name,
                referenceWords: site.words,
                allowDataLayoutDrift: site.allowDataLayoutDrift,
                ignoring: [site.patchIndex]
            )
            let start = try pattern.uniqueMatch(in: image, layout: layout)
            let offset = start + UInt64(site.patchIndex * 4)
            let original = site.words[site.patchIndex]
            let current = try image.readUInt32(at: offset)
            guard current == original || current == site.replacement else {
                throw PatchfinderError.invalidPatch(
                    id: site.id,
                    reason: "unexpected instruction at \(offset.hex)"
                )
            }
            return PatchRecord(
                id: site.id,
                component: "kernelcache",
                offset: offset,
                original: original,
                replacement: site.replacement,
                summary: site.summary,
                evidence: ["unique \(pattern.name) instruction sequence"]
            )
        }
        return records + [try slideRecord(in: image, layout: layout)]
    }

    private func slideRecord(in image: BinaryImage, layout: MachOLayout) throws -> PatchRecord {
        let slide = try kernelSlideGlobal(in: image, layout: layout)
        let sequence = try Self.taskDyldInfoPattern.uniqueMatch(in: image, layout: layout)
        let site = sequence + 12
        let finalStore = try image.readUInt32(at: site + 12)

        guard finalStore & 0xFFC0_0000 == 0xF900_0000,
              Self.unsignedByteOffset(finalStore) == 8
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "TASK_DYLD_INFO second field is not a 64-bit +8 store"
            )
        }

        let valueRegister = finalStore & 0x1F
        let outputRegister = (finalStore >> 5) & 0x1F
        guard valueRegister != 31,
              outputRegister != 31,
              slide.isMultiple(of: 8),
              let siteAddress = layout.virtualAddress(forFileOffset: site),
              let page = ARM64.encodeADRP(
                register: valueRegister,
                instructionOffset: siteAddress,
                target: slide
              )
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "cannot encode the TASK_DYLD_INFO slide transport"
            )
        }

        // ADRP Xv,slide@page; LDR Xv,[Xv,#pageoff]; STR XZR,[Xout].
        let scaledOffset = UInt32(slide & 0xFFF) / 8
        let load = 0xF940_0000 | (scaledOffset << 10)
            | (valueRegister << 5) | valueRegister
        let clearAddress = 0xF900_001F | (outputRegister << 5)
        let replacement = Self.instructionData([page, load, clearAddress])
        let current = try image.bytes(at: site, count: replacement.count)
        guard current == Self.slideOriginal || current == replacement else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "unexpected TASK_DYLD_INFO result construction"
            )
        }

        return PatchRecord(
            id: Self.slideRecordID,
            component: "kernelcache",
            offset: site,
            originalBytes: Self.slideOriginal,
            replacementBytes: replacement,
            summary: "Return vm_kernel_slide through TASK_DYLD_INFO for libkrw0-tfp0",
            evidence: [
                "unique TASK_DYLD_INFO result construction",
                "vm_kernel_slide recovered from the unique kernel slide log call",
            ]
        )
    }

    private func kernelSlideGlobal(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        let string = try unique(
            image.findAll(utf8: Self.slideFormat, nulTerminated: true),
            named: Self.slideFormat
        )
        let reference = try unique(
            try layout.adrpAddReferences(toFileOffset: string),
            named: "kernel slide format reference"
        )
        guard reference.adrpOffset >= 12,
              try image.readUInt32(at: reference.adrpOffset) & 0x1F == 0,
              ARM64.branchLinkTarget(
                instruction: try image.readUInt32(at: reference.addOffset + 4),
                at: reference.addOffset + 4
              ) != nil
        else {
            throw PatchfinderError.noCandidate("kernel slide formatter X0 argument")
        }

        // The log argument is loaded from vm_kernel_slide and spilled before
        // X0 is filled with the format-string address.
        let pageOffset = reference.adrpOffset - 12
        let page = try image.readUInt32(at: pageOffset)
        let load = try image.readUInt32(at: pageOffset + 4)
        let spill = try image.readUInt32(at: pageOffset + 8)
        let pageRegister = page & 0x1F
        let valueRegister = load & 0x1F
        guard page & 0x9F00_0000 == 0x9000_0000,
              pageRegister != 31,
              load & 0xFFC0_0000 == 0xF940_0000,
              valueRegister != 31,
              (load >> 5) & 0x1F == pageRegister,
              spill & 0xFFC0_0000 == 0xF900_0000,
              spill & 0x1F == valueRegister,
              (spill >> 5) & 0x1F == 31,
              let pageAddress = layout.virtualAddress(forFileOffset: pageOffset)
        else {
            throw PatchfinderError.noCandidate("vm_kernel_slide formatter argument load")
        }

        let address = ARM64.adrpTarget(instruction: page, at: pageAddress)
            &+ UInt64(Self.unsignedByteOffset(load))
        guard let fileOffset = layout.fileOffset(forVirtualAddress: address),
              layout.segments.contains(where: {
                $0.fileRange.contains(fileOffset) && !$0.isExecutable
              })
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "vm_kernel_slide does not resolve to mapped data"
            )
        }
        return address
    }

    private func unique<T>(_ values: [T], named name: String) throws -> T {
        guard values.count == 1 else {
            if values.isEmpty { throw PatchfinderError.missingAnchor(name) }
            throw PatchfinderError.ambiguousAnchor(name, count: values.count)
        }
        return values[0]
    }

    private static func unsignedByteOffset(_ instruction: UInt32) -> UInt32 {
        ((instruction >> 10) & 0xFFF) * 8
    }

    private static func instructionData(_ words: [UInt32]) -> Data {
        Data(words.flatMap { word in
            withUnsafeBytes(of: word.littleEndian, Array.init)
        })
    }
}
