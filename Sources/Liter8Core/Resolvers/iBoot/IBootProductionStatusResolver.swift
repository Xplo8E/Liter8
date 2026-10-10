import Foundation

/// Stops iBoot publishing `/chosen/effective-production-status-ap`, leaving the
/// DeviceTree's own value of 0 in place.
///
/// This exists only to reach one gate. `libFDR.dylib` will not unseal the factory
/// baseband calibration blob (`bbcl`) because the FDR instance identity is a SEP
/// key attestation (`aks_sik_attest`) that a Liter8 device cannot reproduce, so
/// `calib.nvm` is never written and the modem runs uncalibrated. The same library
/// skips that check outright when `AMFDRIsNonDefaultDemotionState` is true, which
/// is three MobileGestalt reads and no SEP call:
///
///     CertificateSecurityMode && EffectiveSecurityModeSEP && !EffectiveProductionStatusAp
///
/// Those answers come from `/chosen`. On n104ap `certificate-security-mode`
/// already reads 1, `effective-security-mode-sep` is handled by the DeviceTree
/// plan, and this resolver supplies the third term.
///
/// Why suppress the publish rather than rewrite a value: every one of these six
/// properties is **zero in the DeviceTree image** and iBoot overwrites them at boot
/// from the chip's real fusing state. Patching the DeviceTree alone is therefore
/// inert, which was measured. But the publish is conditional, so declining to
/// publish leaves the template's 0 intact — exactly how
/// `effective-security-mode-sep` already reads 0 on a stock boot, because iBoot
/// never writes that one at all.
///
/// The local shape is a per-property publish sequence:
///
///     ADRP X8, name@page
///     ADD  X8, X8, name@pageoff          ; "effective-production-status-ap"
///     STP  X8, X8, [SP,#imm]
///     ADD  X8, X8, #len
///     BL   <evaluate>
///     TBZ  W0, #0, <next property>       ; low bit clear means "do not publish"
///
/// Turning that TBZ into an unconditional branch to its own target makes the
/// decision permanent. The branch target is taken from the instruction being
/// replaced rather than computed, so a build whose layout shifts cannot be
/// mispatched silently.
public struct IBootProductionStatusResolver: Sendable {
    public static let name = "iboot-production-status"
    private static let anchor = "effective-production-status-ap"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let anchors = image.findAll(utf8: Self.anchor, nulTerminated: true)
        guard let stringOffset = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }

        let references = try ARM64.adrpAddReferences(
            in: image,
            to: stringOffset,
            maximumInstructionGap: 2
        )
        guard let reference = references.only else {
            if references.isEmpty {
                throw PatchfinderError.noCandidate("\(Self.name) string xref")
            }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) string xref",
                offsets: references.map(\.adrpOffset)
            )
        }

        // The publish sequence is fixed-length from the ADD that completes the
        // name pointer, so validate every instruction rather than just the TBZ.
        let addOffset = reference.addOffset
        guard addOffset + 20 <= UInt64(image.count) else {
            throw PatchfinderError.noCandidate("\(Self.name) truncated publish sequence")
        }
        let store = try image.readUInt32(at: addOffset + 4)
        let length = try image.readUInt32(at: addOffset + 8)
        let call = try image.readUInt32(at: addOffset + 12)
        let branchOffset = addOffset + 16
        let branch = try image.readUInt32(at: branchOffset)

        // STP X8,X8,[SP,#imm] with imm free: the name pointer is stored twice.
        guard store & 0xFFC0_7FFF == 0xA900_23E8,
              // ADD X8,X8,#len
              length & 0xFFC0_03FF == 0x9100_0108,
              // BL <evaluate>
              call & 0xFC00_0000 == 0x9400_0000,
              // TBZ W0,#0,<target>
              branch & 0xFFF8_001F == 0x3600_0000,
              let target = ARM64.testBranchTarget(instruction: branch, at: branchOffset)
        else {
            throw PatchfinderError.noCandidate("\(Self.name) publish sequence shape")
        }

        guard let replacement = ARM64.encodeDirectBranch(
            link: false,
            instructionOffset: branchOffset,
            target: target
        ) else {
            throw PatchfinderError.invalidFixture(
                "\(Self.name): TBZ target cannot be reached by an unconditional branch"
            )
        }

        return [PatchRecord(
            id: "iboot.chosen.suppress-production-status-ap",
            component: "iBoot",
            offset: branchOffset,
            original: branch,
            replacement: replacement,
            summary: "Never publish /chosen/effective-production-status-ap",
            evidence: [
                "unique effective-production-status-ap string at \(stringOffset.hex)",
                "unique ADRP+ADD reference at \(reference.adrpOffset.hex)",
                "STP X8,X8,[SP] / ADD X8,#len / BL / TBZ W0,#0 publish shape",
                "branch target \(target.hex) taken from the replaced TBZ",
            ]
        )]
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
