import Foundation

/// T8020 enforces executable trust in PPL as well as AMFI. The AMFI query
/// stub alone does not give an ad-hoc binary a PPL code-signing trust level.
public struct KernelPPLTrustCacheResolver: Sendable {
    public static let name = "kernel-ppl-trust-cache"
    public init() {}

    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        guard KernelResolverProfileRegistry.detect(in: image)?.variants(for: name) != nil else {
            return []
        }
        return try Self().resolve(in: image)
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let profile = KernelResolverProfileRegistry.detect(in: image)
        guard let variant = profile?.variants(for: Self.name),
              variant.support == .supported,
              variant.signature == "t8020-loaded-trust-cache-v1",
              variant.payload == "loaded-trust-cache-true-v1" else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: Self.name, profile: profile?.id ?? "unidentified", variant: "unregistered"
            )
        }
        let layout = try MachOLayout(image: image)
        // Copy all 20 CDHash bytes into a local buffer, query loadable trust
        // caches (type 2), convert KERN_SUCCESS into a boolean. Keep the query,
        // stack canary, authenticated frame and return intact.
        let entry = try KernelPPLTrustCacheSignatures.loadedTrustCacheV1.uniqueMatch(in: image, layout: layout)
        guard let entryVA = layout.virtualAddress(forFileOffset: entry) else {
            throw PatchfinderError.noCandidate("mapped PPL trust-cache entry")
        }
        // BL helper; TBZ W0,#0,+12; MOV W8,#9; B <success>.
        // The false path skips the trust-level assignment; the true path
        // produces PMAP_CS_IN_LOADED_TRUST_CACHE. Keep branch polarity and
        // registers fixed while allowing only the final B destination to drift.
        // Independently verify the caller gives success trust level 9
        // (PMAP_CS_IN_LOADED_TRUST_CACHE), not a different trust decision.
        var callers: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 16 <= range.upperBound {
                if let address = layout.virtualAddress(forFileOffset: offset),
                   ARM64.branchLinkTarget(instruction: try image.readUInt32(at: offset), at: address) == entryVA,
                   try image.readUInt32(at: offset + 4) == 0x36000060,
                   try image.readUInt32(at: offset + 8) == 0x52800128,
                   try image.readUInt32(at: offset + 12) & 0xfc000000 == 0x14000000 {
                    callers.append(offset)
                }
                offset += 4
            }
        }
        guard callers.count == 1 else {
            throw PatchfinderError.ambiguousCandidate("PPL trust-level-9 caller", offsets: callers)
        }
        let offset = entry + 17 * 4
        return [PatchRecord(
            id: "kernel.ppl.loaded-trust-cache-result", component: "kernelcache",
            offset: offset, original: try image.readUInt32(at: offset), replacement: ARM64.movW0One,
            summary: "Accept the loaded trust-cache decision in T8020 PPL",
            evidence: [
                "unique complete CDHash-copy/type-2-query/stack-canary function",
                "unique direct caller maps true to trust level 9",
                "only CSET W0,EQ changes; query, frame and RETAB remain intact",
            ]
        )]
    }
}
