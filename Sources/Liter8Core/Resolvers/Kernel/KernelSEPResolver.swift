import Foundation

/// The 22 AKS patches shared by normal and diagnostic kernels.
///
/// This group prevents the dead SEP from leaving keybag initialization stuck.
/// It includes a guarded selector-7 implementation that writes a coherent
/// `noPin | beenUnlocked` state instead of returning fake success with an
/// untouched output buffer.
public struct KernelAKSResolver: Sendable {
    public static let name = "kernel-aks"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let startCall = try Self.aksStartCall.uniqueMatch(in: image, layout: layout)
        let externalMethod = try Self.externalMethod.uniqueMatch(in: image, layout: layout)
        let logCall = try Self.externalMethodLog.uniqueMatch(in: image, layout: layout)

        var patches: [PatchRecord] = [
            try wordPatch(
                id: "kernel.aks.start.sep-call",
                offset: startCall,
                replacement: ARM64.nop,
                summary: "Skip the SEP-dependent call in AKSUserClient::start",
                evidence: ["unique relocation-masked AKS start-call body"],
                image: image
            ),
        ]

        // Keep the PACIBSP entry at +0 intact. Indirect virtual dispatch may
        // land there, and both exit paths below use RETAB, so replacing the
        // signing instruction would break the return-address pairing.
        let shimWords: [(UInt32, String)] = [
            (0x7100_1C3F, "CMP W1,#7 - recognize selector 7"),
            (0x5400_01C1, "B.NE success - other selectors keep the existing success path"),
            (0xB400_01E2, "CBZ X2,badArgument - reject a null arguments pointer"),
            (0xF940_1048, "LDR X8,[X2,#0x20] - load scalarInput"),
            (0xB400_01A8, "CBZ X8,badArgument - reject a null scalarInput"),
            (0xB940_2848, "LDR W8,[X2,#0x28] - load scalarInputCount"),
            (0x7100_051F, "CMP W8,#1 - require one scalar input"),
            (0x5400_0141, "B.NE badArgument - reject an input-count mismatch"),
            (0xF940_2449, "LDR X9,[X2,#0x48] - load scalarOutput"),
            (0xB400_0109, "CBZ X9,badArgument - reject a null scalarOutput"),
            (0xB940_5048, "LDR W8,[X2,#0x50] - load scalarOutputCount"),
            (0x7100_051F, "CMP W8,#1 - require one scalar output"),
            (0x5400_00A1, "B.NE badArgument - reject an output-count mismatch"),
            (0xD280_00C8, "MOV X8,#6 - synthesize noPin plus beenUnlocked"),
            (0xF900_0128, "STR X8,[X9] - write the synthesized scalar output"),
            (0xD280_0000, "MOV X0,#0 - return KERN_SUCCESS"),
            (0xD65F_0FFF, "RETAB - authenticated return from the success path"),
            (0x5280_5840, "MOV W0,#0x2c2 - low half of kIOReturnBadArgument"),
            (0x72BC_0000, "MOVK W0,#0xe000,LSL#16 - finish kIOReturnBadArgument"),
            (0xD65F_0FFF, "RETAB - authenticated return from the rejection path"),
        ]
        for (index, item) in shimWords.enumerated() {
            patches.append(try wordPatch(
                id: "kernel.aks.external-method.selector7.\(index)",
                offset: externalMethod + 4 + UInt64(index * 4),
                replacement: item.0,
                summary: "Selector-7 shim: \(item.1)",
                evidence: [
                    "unique relocation-masked AKSUserClient::externalMethod prologue",
                    "IOExternalMethodArguments LP64 offsets validated by the native selector-7 path",
                    "entry PACIBSP is deliberately preserved",
                ],
                image: image
            ))
        }
        patches.append(try wordPatch(
            id: "kernel.aks.external-method.log-call",
            offset: logCall,
            replacement: ARM64.nop,
            summary: "Silence the now-unreachable externalMethod IOLog call",
            evidence: ["unique relocation-masked IOLog call sequence in the AKS external method"],
            image: image
        ))
        return patches
    }
}

/// Ten additional SEP failure-silencing records used by the normal-boot plan.
/// Diagnostic kernels intentionally omit these so an unhandled SEP failure can
/// still panic and leave a useful crash report.
public struct KernelSEPSilenceResolver: Sendable {
    public static let name = "kernel-sep-silence"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let panicCheck = try KernelAKSResolver.sepPanicCheck.uniqueMatch(in: image, layout: layout)
        let didTimeout = try KernelAKSResolver.didTimeout.uniqueMatch(in: image, layout: layout)
        let powerNotification = try powerChangeNotification(in: image, layout: layout)
        let setPowerA = try KernelAKSResolver.setPowerA.uniqueMatch(in: image, layout: layout)
        let notifyActive = try KernelAKSResolver.notifyActive.uniqueMatch(in: image, layout: layout)
        let setPowerB = try KernelAKSResolver.setPowerB.uniqueMatch(in: image, layout: layout)
        let reseed = try KernelAKSResolver.prngReseed.uniqueMatch(in: image, layout: layout)

        var patches: [PatchRecord] = []
        for (id, start, summary) in [
            ("panic-check", panicCheck, "Return success from sepPanicCheck"),
            ("did-timeout", didTimeout, "Report that the SEP command did not time out"),
            ("power-notification", powerNotification, "Return success from the paging-off notification handler"),
        ] {
            patches.append(try wordPatch(
                id: "kernel.sep.\(id).result",
                offset: start,
                replacement: ARM64.movX0Zero,
                summary: summary,
                evidence: ["semantic SEP function entry resolved without a target offset"],
                image: image
            ))
            patches.append(try wordPatch(
                id: "kernel.sep.\(id).return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return the forced SEP result",
                evidence: ["paired entry-point stub"],
                image: image
            ))
        }
        for (id, offset, summary) in [
            ("set-power-a", setPowerA, "Do not enter the first setPowerState SEP failure path"),
            ("notify-active", notifyActive, "Do not enter the notifyOSActiveGated SEP failure path"),
            ("set-power-b", setPowerB, "Do not enter the second setPowerState SEP failure path"),
            ("prng-reseed", reseed, "Do not enter the PRNG reseed failure path"),
        ] {
            patches.append(try wordPatch(
                id: "kernel.sep.\(id)",
                offset: offset,
                replacement: ARM64.nop,
                summary: summary,
                evidence: ["unique relocation-masked local failure-path sequence"],
                image: image
            ))
        }
        return patches
    }

    /// This function changed its stack frame between beta 2 and beta 4, so a
    /// masked signature correctly refuses it. Its diagnostic literal is a much
    /// stronger anchor and has exactly one executable reference.
    private func powerChangeNotification(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        let phrase = "AppleSEPManager: Received Paging off notification"
        let strings = image.findAll(utf8: phrase)
        guard let stringOffset = strings.only else {
            if strings.isEmpty { throw PatchfinderError.missingAnchor(phrase) }
            throw PatchfinderError.ambiguousAnchor(phrase, count: strings.count)
        }
        let references = try layout.adrpAddReferences(toFileOffset: stringOffset)
        guard let reference = references.only else {
            if references.isEmpty { throw PatchfinderError.noCandidate("SEP paging-off diagnostic xref") }
            throw PatchfinderError.ambiguousCandidate(
                "SEP paging-off diagnostic xref",
                offsets: references.map(\.adrpOffset)
            )
        }
        guard let range = layout.executableFileRanges.first(where: { $0.contains(reference.adrpOffset) }) else {
            throw PatchfinderError.noCandidate("SEP paging-off executable range")
        }
        let floor = max(range.lowerBound, reference.adrpOffset - min(0x4000, reference.adrpOffset - range.lowerBound))
        var cursor = reference.adrpOffset & ~UInt64(3)
        while cursor >= floor + 4 {
            if try image.readUInt32(at: cursor) == 0xD503_237F { return cursor } // PACIBSP
            cursor -= 4
        }
        throw PatchfinderError.noCandidate("SEP paging-off containing function")
    }
}

/// Complete 32-record normal-boot SEP plan.
public struct KernelSEPResolver: Sendable {
    public static let name = "kernel-sep"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelAKSResolver().resolve(in: image)
            + KernelSEPSilenceResolver().resolve(in: image)
    }
}

// MARK: - Relocation-masked semantic patterns

private extension KernelAKSResolver {
    // Each value array below is a reference ARM64 instruction sequence. Branch
    // destinations and other build-dependent fields are cleared by the paired
    // mask array: a 1 bit must match, while a 0 bit is deliberately ignored.
    // Therefore the mask words are bitfields, not executable opcodes.

    // PACIBSP; save X20/X19 and FP/LR; establish FP; MOV X19,X0;
    // LDR X0,[X0,#0x108]; CBZ X0,<target>; BL <target>; CBNZ W0,<target>;
    // restore FP/LR and X20/X19; RETAB.
    static let sepPanicCheck = pattern(
        "sepPanicCheck",
        [0xD503237F, 0xA9BE4FF4, 0xA9017BFD, 0x910043FD, 0xAA0003F3, 0xF9408400, 0xB4000000, 0x94000000, 0x35000000, 0xA9417BFD, 0xA8C24FF4, 0xD65F0FFF],
        [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]
    )

    // PACIBSP; allocate 0x30-byte frame; save X20/X19 and FP/LR;
    // establish FP; MOV X8,X0; LDR W9,[X8,#0xdc]!; SUB W10,W9,#7.
    static let didTimeout = pattern(
        "AppleSEPManager::_didTimeout",
        [0xD503237F, 0xD100C3FF, 0xA9014FF4, 0xA9027BFD, 0x910083FD, 0xAA0003E8, 0xB84DCD09, 0x51001D2A],
        Array(repeating: 0xFFFF_FFFF, count: 8)
    )

    // BLRAA X8,X16; LDRH W8,[X19,#0xf0]; TBNZ W8,#4,<target>;
    // LDR X0,[X19,#0xd8]; CBZ X0,<target>; BL <target>;
    // LDRH W8,[X19,#0xf0]; ORR W9,W8,#0x10.
    static let aksStartCall = pattern(
        "AKSUserClient::start SEP call",
        [0xD73F0910, 0x7941E268, 0x37200008, 0xF9406E60, 0xB4000000, 0x94000000, 0x7941E268, 0x321C0109],
        [0xFFFFFFFF, 0xFFFFFFFF, 0xFFF8001F, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF]
    )

    // PACIBSP; allocate 0x1a0-byte frame; save X28..X19 and FP/LR;
    // establish FP; MOV X21,X2; MOV X20,X1; MOV X22,X0.
    static let externalMethod = pattern(
        "AKSUserClient::externalMethod",
        [0xD503237F, 0xD10683FF, 0xA9146FFC, 0xA91567FA, 0xA9165FF8, 0xA91757F6, 0xA9184FF4, 0xA9197BFD, 0x910643FD, 0xAA0203F5, 0xAA0103F4, 0xAA0003F6],
        Array(repeating: 0xFFFF_FFFF, count: 12)
    )

    // BL <target>; LDR W8,[X25]; TST W8,#0xfffffff7; B.EQ <target>;
    // BL <target>; SXTW X3,W0; MOV X8,X21; SXTW X4,W8.
    static let externalMethodLog = pattern(
        "AKSUserClient::externalMethod IOLog call",
        [0x94000000, 0xB9400328, 0x721C791F, 0x54000000, 0x94000000, 0x93407C03, 0xAA1503E8, 0x93407D04],
        [0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]
    )

    // CBZ X0,<target>; LDRB W8,[X19,#0xcc]; TBZ W8,#0,<target>;
    // MOV X0,X19; MOV W1,#15000; BL <target>; BL <target>;
    // LDRB W8,[X19,#0xa5a].
    static let setPowerA = pattern(
        "AppleSEPManager::_setPowerState first failure gate",
        [0xB4000000, 0x39433268, 0x36000008, 0xAA1303E0, 0x52875301, 0x94000000, 0x94000000, 0x39696A68],
        [0xFF00001F, 0xFFFFFFFF, 0xFFF8001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFC000000, 0xFFFFFFFF]
    )

    // CBZ X0,<target>; MOV X0,X20; MOV W1,#15000; BL <target>;
    // BL <target>; LDR W8,[X20,#0xc8]; CMP W8,#2; B.NE <target>.
    static let notifyActive = pattern(
        "AppleSEPManager::_notifyOSActiveGated failure gate",
        [0xB4000000, 0xAA1403E0, 0x52875301, 0x94000000, 0x94000000, 0xB940CA88, 0x7100091F, 0x54000001],
        [0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F]
    )

    // CBZ X0,<target>; MOV X0,X19; MOV W1,#15000; BL <target>;
    // CBZ X0,<target>; MOV X0,X19; MOV W1,#1; BL <target>.
    static let setPowerB = pattern(
        "AppleSEPManager::_setPowerState second failure gate",
        [0xB4000000, 0xAA1303E0, 0x52875301, 0x94000000, 0xB4000000, 0xAA1303E0, 0x52800021, 0x94000000],
        [0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000]
    )

    // B.EQ <target>; MOV W0,#1000; BL <target>; ADD W21,W21,#1;
    // MOV X0,X19; BL <target>; TBZ W0,#0,<target>; LDP FP,LR,[SP,#0x30].
    static let prngReseed = pattern(
        "AppleSEPManager PRNG reseed failure gate",
        [0x54000000, 0x52807D00, 0x94000000, 0x110006B5, 0xAA1303E0, 0x94000000, 0x36000000, 0xA9437BFD],
        [0xFF00001F, 0xFFFFFFFF, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFFF8001F, 0xFFFFFFFF]
    )

    static func pattern(_ name: String, _ values: [UInt32], _ masks: [UInt32]) -> MaskedInstructionPattern {
        MaskedInstructionPattern(name: name, values: values, masks: masks)
    }
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

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
