import Foundation

/// Profile-gated kernel patches for libkrw's tfp0 backend.
struct KernelTFP0Resolver: Sendable {
    static let variantKey = "kernel-tfp0"
    static let signatureID = "ios27-tfp0-v2"
    static let payloadID = "task-for-pid-zero-slide-v3"

    private static let slideFormat = "KernelCache slide: 0x%016lx\n"
    private static let slideRecordID = "kernel.tfp0.dyld-info-slide"
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
        return records + (try scopedSlideRecords(in: image, layout: layout))
    }

    private static let scopedSlideRecordID = "kernel.tfp0.dyld-info-slide-scoped"
    private static let caveRecordID = "kernel.tfp0.dyld-info-cave"
    private static let shimWords = 14
    // LDR X8,[X20,#0x3e0]; STR X8,[X22]; LDR X8,[X20,#0x3e8]; STR X8,[X22,#8].
    private static let stockDyldInfoWords: [UInt32] = [
        0xF941_F288, 0xF900_02C8, 0xF941_F688, 0xF900_06C8,
    ]

    /// Return the slide only when the queried task is the kernel task.
    ///
    /// The shipped slide patch rewrites the shared TASK_DYLD_INFO result path
    /// without testing which task was asked about, so every task loses its real
    /// dyld info. This routes the site through a cave that compares the task in
    /// X20 against `kernel_task` and replays the four displaced instructions
    /// unchanged for everyone else.
    private func scopedSlideRecords(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> [PatchRecord] {
        let slide = try kernelSlideGlobal(in: image, layout: layout)
        let kernelTask = try kernelTaskGlobal(in: image, layout: layout)
        let sequence = try Self.taskDyldInfoPattern.uniqueMatch(in: image, layout: layout)
        let site = sequence + 12
        let cave = try resolveCave(in: image, layout: layout, patchedSite: site)

        // The four instructions the stock path needs. A clean image holds all
        // four; an already-patched one holds our branch in the first slot and
        // keeps the other three, so accept that state and replay the constant.
        let live = try (0..<4).map { try image.readUInt32(at: site + UInt64($0 * 4)) }
        let stock = Self.stockDyldInfoWords
        let outputRegister = (stock[3] >> 5) & 0x1F
        let clean = live == stock
        // Decode in virtual-address space, the same space the branch was
        // encoded in, then map back to compare file offsets.
        let liveBranchTarget = layout.virtualAddress(forFileOffset: site)
            .flatMap { ARM64.directBranchTarget(instruction: live[0], at: $0) }
            .flatMap { layout.fileOffset(forVirtualAddress: $0) }
        let applied = Array(live[1...]) == Array(stock[1...]) && liveBranchTarget == cave
        guard clean || applied, outputRegister != 31 else {
            throw PatchfinderError.invalidPatch(
                id: Self.caveRecordID,
                reason: "unexpected TASK_DYLD_INFO result construction"
            )
        }

        guard let siteAddress = layout.virtualAddress(forFileOffset: site),
              let caveAddress = layout.virtualAddress(forFileOffset: cave),
              let branchToCave = ARM64.encodeDirectBranch(
                link: false, instructionOffset: siteAddress, target: caveAddress
              ),
              let kernelTaskPage = ARM64.encodeADRP(
                register: 8, instructionOffset: caveAddress, target: kernelTask
              ),
              let slidePage = ARM64.encodeADRP(
                register: 8, instructionOffset: caveAddress + 16, target: slide
              ),
              // Both tails rejoin the stock dispatch after the fourth word.
              let kernelReturn = ARM64.encodeDirectBranch(
                link: false, instructionOffset: caveAddress + 32, target: siteAddress + 16
              ),
              let stockReturn = ARM64.encodeDirectBranch(
                link: false, instructionOffset: caveAddress + 52, target: siteAddress + 16
              ),
              slide.isMultiple(of: 8), kernelTask.isMultiple(of: 8)
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.caveRecordID,
                reason: "cannot encode the scoped TASK_DYLD_INFO shim"
            )
        }

        let shim: [UInt32] = [
            kernelTaskPage,                                   // ADRP X8,kernel_task@page
            0xF940_0108 | ((UInt32(kernelTask & 0xFFF) / 8) << 10),  // LDR X8,[X8,#off]
            0xEB08_029F,                                      // CMP X20,X8
            0x5400_00C1,                                      // B.NE stock (+6 words)
            slidePage,                                        // ADRP X8,vm_kernel_slide@page
            0xF940_0108 | ((UInt32(slide & 0xFFF) / 8) << 10),       // LDR X8,[X8,#off]
            0xF900_001F | (outputRegister << 5),              // STR XZR,[Xout]
            stock[3],                                         // STR X8,[Xout,#8] - the slide
            kernelReturn,                                     // B back past the fourth word
            stock[0], stock[1], stock[2], stock[3],           // stock path, replayed verbatim
            stockReturn,                                      // B back past the fourth word
        ]

        let shimBytes = Self.instructionData(shim)
        let blank = Data(repeating: 0, count: shimBytes.count)
        let currentCave = try image.bytes(at: cave, count: shimBytes.count)
        guard currentCave == blank || currentCave == shimBytes else {
            throw PatchfinderError.invalidPatch(
                id: Self.caveRecordID,
                reason: "tfp0 cave at \(cave.hex) is neither clean padding nor this shim"
            )
        }

        return [
            PatchRecord(
                id: Self.caveRecordID,
                component: "kernelcache",
                offset: cave,
                originalBytes: blank,
                replacementBytes: shimBytes,
                summary: "kernel_task-scoped TASK_DYLD_INFO slide shim",
                evidence: [
                    "zero-filled executable padding after the Sandbox and Valeria reservations",
                    "kernel_task recovered from the unique task-conversion ADRP/LDR pair",
                    "vm_kernel_slide recovered from the unique kernel slide log call",
                ]
            ),
            PatchRecord(
                id: Self.scopedSlideRecordID,
                component: "kernelcache",
                offset: site,
                original: stock[0],
                replacement: branchToCave,
                summary: "Route TASK_DYLD_INFO through the kernel_task-scoped slide shim",
                evidence: ["unique TASK_DYLD_INFO result construction"]
            ),
        ]
    }

    /// `kernel_task`, taken from the ADRP/LDR pair the task-conversion site
    /// already uses to load it.
    private func kernelTaskGlobal(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        guard let site = Self.sites.first(where: { $0.id == "kernel.tfp0.task-conversion" })
        else { throw PatchfinderError.missingAnchor("task-conversion site") }

        let pattern = MaskedInstructionPattern(
            name: site.name,
            referenceWords: site.words,
            allowDataLayoutDrift: site.allowDataLayoutDrift,
            ignoring: [site.patchIndex]
        )
        let start = try pattern.uniqueMatch(in: image, layout: layout)
        let pageOffset = start + 24
        let page = try image.readUInt32(at: pageOffset)
        let load = try image.readUInt32(at: pageOffset + 4)

        guard page & 0x9F00_0000 == 0x9000_0000,
              load & 0xFFC0_0000 == 0xF940_0000,
              (load >> 5) & 0x1F == page & 0x1F,
              let pageAddress = layout.virtualAddress(forFileOffset: pageOffset)
        else {
            throw PatchfinderError.noCandidate("kernel_task ADRP/LDR pair")
        }

        let address = ARM64.adrpTarget(instruction: page, at: pageAddress)
            &+ UInt64(Self.unsignedByteOffset(load))
        guard let fileOffset = layout.fileOffset(forVirtualAddress: address),
              layout.segments.contains(where: {
                $0.fileRange.contains(fileOffset) && !$0.isExecutable
              })
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.caveRecordID,
                reason: "kernel_task does not resolve to mapped data"
            )
        }
        return address
    }

    /// Executable padding after the words KernelSandboxResolver and
    /// KernelValeriaResolver already own, so the three shims never overlap.
    private func resolveCave(
        in image: BinaryImage,
        layout: MachOLayout,
        patchedSite: UInt64
    ) throws -> UInt64 {
        // Mirrors KernelValeriaResolver's reservations. A committed version
        // would share one owner for this padding instead of restating it.
        let predecessor = MaskedInstructionPattern(
            name: "completed function before shared kernel executable padding",
            values: [0xF940_07EF, 0xF82D_798F, 0x1400_0000, 0x9100_43FF, 0xD65F_03C0],
            masks:  [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFC00_0000, 0xFFFF_FFFF, 0xFFFF_FFFF]
        )
        let sandboxReservedWords = 33
        let valeriaReservedWords = 14

        let tail = try predecessor.uniqueMatch(in: image, layout: layout)
        let sandboxCave = tail + UInt64(predecessor.values.count * 4)
        let cave = sandboxCave
            + UInt64(sandboxReservedWords * 4)
            + UInt64(valeriaReservedWords * 4)
        let caveRange = cave..<(cave + UInt64(Self.shimWords * 4))

        guard layout.executableFileRanges.contains(where: {
            $0.lowerBound <= caveRange.lowerBound && $0.upperBound >= caveRange.upperBound
        }) else {
            throw PatchfinderError.noCandidate("file-backed executable tfp0 cave")
        }
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                if offset == patchedSite { offset += 4; continue }
                let instruction = try image.readUInt32(at: offset)
                if let sourceAddress = layout.virtualAddress(forFileOffset: offset),
                   let targetAddress = ARM64.directBranchTarget(
                    instruction: instruction, at: sourceAddress
                   ),
                   let target = layout.fileOffset(forVirtualAddress: targetAddress),
                   caveRange.contains(target)
                {
                    throw PatchfinderError.invalidFixture(
                        "direct branch at \(offset.hex) targets the proposed tfp0 cave"
                    )
                }
                offset += 4
            }
        }
        return cave
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
