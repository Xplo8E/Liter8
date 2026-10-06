import Foundation

/// Reclaims an inactive Valeria callback owner at selector-8 registration.
///
/// Forced USB re-enumeration can leave the old `audiomxd` user client retained
/// at provider offset `0xd0`. The replacement `airplayd` selector-8 call then
/// reaches the class-command registration action and returns `kIOReturnBusy`.
/// That action already runs on the provider command gate, so it is the first
/// race-safe point that observes both the stale owner and the replacement.
///
/// The shim preserves stock behavior for a null or live owner. It invokes the
/// provider's existing direct clear routine only when the retained owner's
/// verified `IOService::getState()` word at offset `0x48` has
/// `kIOServiceInactiveState` (bit zero) set. Control then resumes at the stock
/// null-owner branch, which retains and installs the new user client.
public struct KernelValeriaResolver: Sendable {
    public static let name = "kernel-valeria"

    public init() {}

    /// Preserve upstream's repair on existing/unknown inputs. Omit it only
    /// when an exact detected profile explicitly selects the older public plan.
    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        if KernelResolverProfileRegistry.detect(in: image)?.includesValeriaRepair == false {
            return []
        }
        return try Self().resolve(in: image)
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let ownerLoad = try Self.classCommandRegistrationOwnerCheck.uniqueMatch(
            in: image,
            layout: layout
        )
        let directClear = try resolveDirectClear(in: image, layout: layout)
        let cave = try resolveCave(in: image, layout: layout)
        let shim = try buildRegistrationShim(
            at: cave,
            directClear: directClear,
            layout: layout
        )
        let redirectedOwnerLoad = try encodeBranch(
            link: true,
            from: ownerLoad,
            to: cave,
            layout: layout,
            description: "Valeria selector-8 owner load to inactive-owner shim"
        )

        var patches = [try valeriaPatch(
            id: "kernel.valeria.class-command-registration.inactive-owner-check",
            offset: ownerLoad,
            replacement: redirectedOwnerLoad,
            summary: "Reclaim only an inactive Valeria callback owner before selector-8 registration",
            evidence: [
                "Wi-Fi LLDB recorded selector 8 returning kIOReturnBusy on the first airplayd setup",
                "the retained owner is inactive while the replacement registers on the provider command gate",
            ],
            image: image
        )]

        for (index, item) in shim.enumerated() {
            patches.append(try valeriaPatch(
                id: "kernel.valeria.registration-shim.\(index)",
                offset: cave + UInt64(index * 4),
                replacement: item.word,
                summary: "Valeria inactive-owner registration shim: \(item.summary)",
                evidence: [
                    "reserved executable padding after the scoped Sandbox shim",
                    "the shim runs inside the stock selector-8 command-gate action",
                ],
                image: image
            ))
        }
        return patches
    }

    private func resolveDirectClear(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        do {
            return try Self.directClear.uniqueMatch(in: image, layout: layout)
        } catch PatchfinderError.noCandidate {
            // iOS 27 beta 4 predates the BTI landing pad added to this kext's
            // function entries. The body and ownership semantics are the same.
            return try Self.legacyDirectClear.uniqueMatch(in: image, layout: layout)
        }
    }

    /// The public compatibility plan does not use the scoped Sandbox shim, but
    /// the complete plan does. Reserve its 33 words and place this independent
    /// registration shim immediately after them so both plans compose without
    /// overlapping records.
    private func resolveCave(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64 {
        let tail = try Self.cavePredecessor.uniqueMatch(in: image, layout: layout)
        let sandboxCave = tail + UInt64(Self.cavePredecessor.values.count * 4)
        let cave = sandboxCave + UInt64(Self.sandboxReservedWords * 4)
        let completeRange = sandboxCave..<(cave
            + UInt64(Self.registrationShimTemplate.count * 4))
        let caveRange = cave..<completeRange.upperBound

        guard layout.executableFileRanges.contains(where: {
            $0.lowerBound <= completeRange.lowerBound && $0.upperBound >= completeRange.upperBound
        }) else {
            throw PatchfinderError.noCandidate("file-backed executable Valeria cave")
        }
        guard try image.bytes(
            at: completeRange.lowerBound,
            count: Int(completeRange.upperBound - completeRange.lowerBound)
        ).allSatisfy({ $0 == 0 }) else {
            throw PatchfinderError.noCandidate("zero-filled Valeria cave after Sandbox reservation")
        }

        // A direct branch into these words means the padding is not actually
        // unclaimed. Decode in virtual-address space because this shim calls
        // from a fileset kext into padding owned by the kernel Mach-O.
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                let instruction = try image.readUInt32(at: offset)
                if let sourceAddress = layout.virtualAddress(forFileOffset: offset),
                   let targetAddress = ARM64.directBranchTarget(
                    instruction: instruction,
                    at: sourceAddress
                   ),
                   let target = layout.fileOffset(forVirtualAddress: targetAddress),
                   caveRange.contains(target)
                {
                    throw PatchfinderError.invalidFixture(
                        "direct branch at \(offset.hex) targets the proposed Valeria cave"
                    )
                }
                offset += 4
            }
        }

        // Kernel collections encode authenticated pointer targets in the low
        // word as file offsets. Reject a pre-existing pointer into our range.
        var pointerOffset: UInt64 = 0
        while pointerOffset + 8 <= UInt64(image.count) {
            let pointer = try image.readUInt64(at: pointerOffset)
            let target = UInt64(UInt32(truncatingIfNeeded: pointer))
            if pointer >> 32 != 0, caveRange.contains(target) {
                throw PatchfinderError.invalidFixture(
                    "chained pointer at \(pointerOffset.hex) targets the proposed Valeria cave"
                )
            }
            pointerOffset += 8
        }
        return cave
    }

    private func buildRegistrationShim(
        at cave: UInt64,
        directClear: UInt64,
        layout: MachOLayout
    ) throws -> [(word: UInt32, summary: String)] {
        var shim = Self.registrationShimTemplate
        shim[9].word = try encodeBranch(
            link: true,
            from: cave + 36,
            to: directClear,
            layout: layout,
            description: "Valeria inactive callback-owner clear"
        )
        return shim
    }

    private func encodeBranch(
        link: Bool,
        from source: UInt64,
        to target: UInt64,
        layout: MachOLayout,
        description: String
    ) throws -> UInt32 {
        guard let sourceAddress = layout.virtualAddress(forFileOffset: source),
              let targetAddress = layout.virtualAddress(forFileOffset: target),
              let encoded = ARM64.encodeDirectBranch(
                link: link,
                instructionOffset: sourceAddress,
                target: targetAddress
              )
        else {
            throw PatchfinderError.noCandidate(description)
        }
        return encoded
    }
}

private extension KernelValeriaResolver {
    // Selector 8 reaches the provider's +0x5c0 command-gate action. Its tail
    // differs from the adjacent message-callback action by storing X20 in the
    // second callback slot, which makes this owner check unique. PAC
    // discriminator immediates may drift between linked collections.
    static let classCommandRegistrationOwnerCheck = MaskedInstructionPattern(
        name: "IOUSBDeviceInterface class-command callback owner check",
        values: [
            0xF940_6A68, 0xB400_0008, 0x1100_4C00, 0x1400_0000,
            0xF900_6A61, 0xF940_0030, 0xAA01_03F1, 0xF2E0_0011,
            0xDAC1_1A30, 0xF842_0E08, 0xAA01_03E0, 0xF2E0_0010,
            0xD73F_0910, 0x5280_0000, 0xA90D_D27F, 0xA941_7BFD,
            0xA8C2_4FF4, 0xD65F_0FFF,
        ],
        masks: [
            0xFFFF_FFFF, 0xFF00_001F, 0xFFFF_FFFF, 0xFC00_0000,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFE0_001F,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFE0_001F,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
            0xFFFF_FFFF, 0xFFFF_FFFF,
        ]
    )

    // BTI C; PACIBSP; save X20/X19 and FP/LR; establish FP; preserve provider;
    // load provider->_callbackOwner from +0xd0; skip release when null.
    static let directClear = MaskedInstructionPattern(
        name: "IOUSBDeviceInterface direct callback owner clear",
        values: [
            0xD503_245F, 0xD503_237F, 0xA9BE_4FF4, 0xA901_7BFD,
            0x9100_43FD, 0xAA00_03F3, 0xF940_6800, 0xB400_0000,
            0, 0, 0, 0, 0, 0, 0,
            0xA90D_7E7F, 0xF900_727F, 0x5280_0000,
        ],
        masks: [
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFF00_001F,
            0, 0, 0, 0, 0, 0, 0,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        ]
    )

    static let legacyDirectClear = MaskedInstructionPattern(
        name: "IOUSBDeviceInterface legacy direct callback owner clear",
        values: [
            0xD503_237F, 0xA9BE_4FF4, 0xA901_7BFD,
            0x9100_43FD, 0xAA00_03F3, 0xF940_6800, 0xB400_0000,
            0, 0, 0, 0, 0, 0, 0,
            0xA90D_7E7F, 0xF900_727F, 0x5280_0000,
        ],
        masks: [
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFF00_001F,
            0, 0, 0, 0, 0, 0, 0,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        ]
    )

    // Same reviewed function tail used to allocate the scoped Sandbox shim.
    // Its 33 words remain exclusively owned by KernelSandboxResolver.
    static let cavePredecessor = MaskedInstructionPattern(
        name: "completed function before shared kernel executable padding",
        values: [0xF940_07EF, 0xF82D_798F, 0x1400_0000, 0x9100_43FF, 0xD65F_03C0],
        masks:  [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFC00_0000, 0xFFFF_FFFF, 0xFFFF_FFFF]
    )

    static let sandboxReservedWords = 33

    // The patched instruction originally loads callbackOwner into X8. The shim
    // reproduces that result for null and live owners. For an inactive owner,
    // it clears the retained owner while already on the provider command gate,
    // restores the replacement user client in X1, and returns X8 == 0 so the
    // existing CBZ enters the stock registration path.
    static let registrationShimTemplate: [(word: UInt32, summary: String)] = [
        (0xD503_245F, "BTI C - indirect-call landing pad"),
        (0xD503_237F, "PACIBSP - sign LR before making nested calls"),
        (0xA9BF_7BF5, "STP X21,LR,[SP,#-0x10]! - preserve client and signed return"),
        (0xAA01_03F5, "MOV X21,X1 - retain the replacement user client"),
        (0xF940_6A68, "LDR X8,[X19,#0xd0] - reproduce the displaced owner load"),
        (0xB400_00C8, "CBZ X8,restore - preserve the stock null-owner path"),
        (0xB940_4909, "LDR W9,[X8,#0x48] - read the exact IOService state word"),
        (0x3600_0089, "TBZ W9,#0,restore - keep a live owner busy"),
        (0xAA13_03E0, "MOV X0,X19 - pass the provider to direct clear"),
        (0, "BL direct-clear - release and zero the inactive owner"),
        (0xAA1F_03E8, "MOV X8,XZR - enter the stock registration branch"),
        (0xAA15_03E1, "MOV X1,X21 - restore the replacement user client"),
        (0xA8C1_7BF5, "LDP X21,LR,[SP],#0x10 - restore state and signed return"),
        (0xD65F_0FFF, "RETAB - authenticated return to selector-8 registration"),
    ]
}

private func valeriaPatch(
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
