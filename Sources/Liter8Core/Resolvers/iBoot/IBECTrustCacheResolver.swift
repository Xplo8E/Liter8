import Foundation

/// Lets iBEC accept a second trust cache of a type it already holds, as the
/// 26.7.1 iBoot did.
///
/// Why: on a normal `bootx` with no RestoreTrustCache loaded, iBoot reads the
/// StaticTrustCache from storage itself and adds it to its trust cache list.
/// Liter8's normal boot has already sent the same StaticTrustCache over USB
/// (`firmware`), so the list then holds two `trst` entries. iBoot 26.7.1
/// (23H30) appends both. iBoot 26.7.2 (23H128) added a check to the add
/// routine that walks the list, compares each entry's stored type with the
/// incoming one, and fails with 0x400d000c on a match, so `bootx` returns to
/// Recovery and the kernel never starts. SSHRD is unaffected: it sends
/// RestoreTrustCache, which suppresses the storage load.
///
/// The patch replaces that one `B.EQ` with `NOP`, restoring the 26.7.1
/// behaviour. Measured on iPad11,6: the 23H128 system boots with the 23H30
/// iBoot, which is exactly this behaviour with two identical StaticTrustCache
/// entries. Every other check in the routine (type allowlist, list bounds,
/// pointer integrity) is left as it is.
///
/// Apply to iBEC only, and only where a profile selects it: iBSS never runs
/// `bootx`, and the payloads are byte-identical, so the plan name is the
/// boundary, as for `ibss-skip-display-init`.
public struct IBECAllowDuplicateTrustCacheResolver: Sendable {
    public static let name = "ibec-allow-duplicate-trust-cache"

    public init() {}

    /// `MOVZ W8,#0x7363` / `MOVK W8,#0x7274,LSL #16`: W8 = 'rtsc', the
    /// RestoreTrustCache fourcc the add routine compares the incoming type with.
    private static let movzRTSCLow: UInt32 = 0x528E_6C68
    private static let movkRTSCHigh: UInt32 = 0x72AE_4E88

    /// How far past the type check the duplicate-type loop may start, and how
    /// far into its failure block the error code may sit. Both are measured
    /// from 23H128 (17 and 9 instructions) with headroom; neither is an offset.
    private static let loopWindow = 64
    private static let failureWindow = 24

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        var candidates: [UInt64] = []
        var offset: UInt64 = 0
        let end = UInt64(image.count) & ~3
        while offset + 12 <= end {
            defer { offset += 4 }
            guard try image.readUInt32(at: offset) == Self.movzRTSCLow,
                  try image.readUInt32(at: offset + 4) == Self.movkRTSCHigh
            else { continue }
            // CMP Wtype, W8 (SUBS WZR, Wtype, W8): fixed bits 0x6B08_001F,
            // Rn = the register carrying the incoming fourcc.
            let compare = try image.readUInt32(at: offset + 8)
            guard compare & 0xFFFF_FC1F == 0x6B08_001F else { continue }
            let typeRegister = (compare >> 5) & 31

            var cursor = offset + 12
            let limit = min(end, offset + 12 + UInt64(Self.loopWindow * 4))
            while cursor + 12 <= limit {
                defer { cursor += 4 }
                // LDR Wt,[Xn,#imm]: the entry's stored type (32-bit, scaled
                // unsigned offset; 0xB940_0000 with Rt, Rn and imm12 variable).
                let load = try image.readUInt32(at: cursor)
                guard load & 0xFFC0_0000 == 0xB940_0000 else { continue }
                let loaded = load & 31
                // CMP Wt, Wtype (SUBS WZR, Wt, Wtype).
                let expectedCompare = 0x6B00_001F | (typeRegister << 16) | (loaded << 5)
                guard try image.readUInt32(at: cursor + 4) == expectedCompare else { continue }
                // B.EQ <failure>: cond field 0 (EQ), bit 4 clear.
                let branchOffset = cursor + 8
                let branch = try image.readUInt32(at: branchOffset)
                guard branch & 0xFF00_001F == 0x5400_0000,
                      let failure = ARM64.conditionalTarget(instruction: branch, at: branchOffset),
                      failure > branchOffset,
                      try failsWithDuplicateTypeError(at: failure, in: image)
                else { continue }
                candidates.append(branchOffset)
            }
        }

        guard candidates.count == 1, let branchOffset = candidates.first else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }
        return [PatchRecord(
            id: "ibec.trust-cache.allow-duplicate-type",
            component: "iBEC",
            offset: branchOffset,
            original: try image.readUInt32(at: branchOffset),
            replacement: ARM64.nop,
            summary: "Accept a second trust cache of an already loaded type, as iBoot 26.7.1 did",
            evidence: [
                "trust cache add routine compares the incoming type with 'rtsc'",
                "loop loads each entry's stored type and compares it with the incoming type",
                "B.EQ target returns error 0x400d000c and -1 (duplicate type)",
            ]
        )]
    }

    /// The failure block builds 0x400d000c as `MOVZ Wx,#6; MOVK Wx,#0x400d,
    /// LSL #16; ADD W0,Wx,#6` and then returns `MOV W0,#-1`. Requiring both
    /// pins the branch to the duplicate-type exit rather than another failure
    /// in the same routine.
    private func failsWithDuplicateTypeError(at start: UInt64, in image: BinaryImage) throws -> Bool {
        let limit = min(UInt64(image.count) & ~3, start + UInt64(Self.failureWindow * 4))
        var cursor = start
        var sawErrorCode = false
        while cursor + 4 <= limit {
            let word = try image.readUInt32(at: cursor)
            if !sawErrorCode, cursor + 12 <= limit, word & 0xFFFF_FFE0 == 0x5280_00C0 {
                let register = word & 31
                let high = try image.readUInt32(at: cursor + 4)
                let add = try image.readUInt32(at: cursor + 8)
                if high == 0x72A8_01A0 | register,
                   add == 0x1100_1800 | (register << 5) {
                    sawErrorCode = true
                    cursor += 12
                    continue
                }
            }
            if sawErrorCode, word == 0x1280_0000 { return true } // MOV W0,#-1
            cursor += 4
        }
        return false
    }
}
