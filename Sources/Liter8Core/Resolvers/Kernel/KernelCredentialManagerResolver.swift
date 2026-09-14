import Foundation

/// Resolves the 26 AppleCredentialManager entry points patched by the normal
/// boot kernel plan. Every resolved function becomes `mov w0, #0; ret`, for a
/// total of 52 guarded patch records.
///
/// There are deliberately two resolution paths:
///
/// 1. Twenty-two bodies retain a unique relocation-masked instruction shape.
/// 2. Four bodies changed enough that exact matching would be dishonest. Their
///    real function entries are ranked inside the interval established by the
///    exact functions immediately around them.
///
/// The known beta-4 offsets live only in the fixture. Nothing below can fall
/// back to one of those offsets when semantic resolution fails.
public struct KernelCredentialManagerResolver: Sendable {
    public static let name = "kernel-credential-manager"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        guard let profile = KernelResolverProfileRegistry.detect(in: image) else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: Self.name,
                profile: "unidentified",
                variant: "none"
            )
        }
        guard let selected = profile.variants(for: Self.name) else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: Self.name,
                profile: profile.id,
                variant: "unregistered"
            )
        }
        guard selected.support == .supported,
              let signatures = KernelCredentialManagerSignatures.variant(named: selected.signature),
              let payload = KernelCredentialManagerPayloads.payload(named: selected.payload)
        else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: Self.name,
                profile: profile.id,
                variant: selected.signature
            )
        }

        let layout = try MachOLayout(image: image)
        let functions = signatures.functions
        var resolved: [Int: UInt64] = [:]

        // Resolve the strict signatures first. Besides being independently
        // useful evidence, they become the ordering rails for the four bodies
        // whose internal implementation drifted.
        for (index, descriptor) in functions.enumerated() where !descriptor.needsScoring {
            resolved[index] = try descriptor.pattern.uniqueMatch(in: image, layout: layout)
        }

        for (index, descriptor) in functions.enumerated() where descriptor.needsScoring {
            let previous = resolved[index - 1]
            let next = resolved[index + 1]
            resolved[index] = try scoredFunctionEntry(
                descriptor: descriptor,
                after: previous,
                before: next,
                image: image,
                layout: layout
            )
        }

        let ordered = try functions.indices.map { index -> UInt64 in
            guard let offset = resolved[index] else {
                throw PatchfinderError.noCandidate(functions[index].name)
            }
            return offset
        }
        guard zip(ordered, ordered.dropFirst()).allSatisfy({ $0.0 < $0.1 }) else {
            throw PatchfinderError.invalidFixture(
                "AppleCredentialManager functions did not resolve in reference order"
            )
        }

        var patches: [PatchRecord] = []
        for (descriptor, entry) in zip(functions, ordered) {
            let method = descriptor.needsScoring
                ? "neighbor-bounded 32-word similarity"
                : "unique relocation-masked function body"
            // Ten of these methods have no direct branch reference at all on RC
            // 24A435 and are reached only through a taken address, so the stub
            // starts after any BTI C landing pad rather than on top of it.
            let start = ARM64.stubStart(atEntry: entry, in: image)
            patches.append(try credentialPatch(
                id: "kernel.credential-manager.\(descriptor.id).result",
                offset: start,
                replacement: payload.result,
                summary: "Return success from \(descriptor.name)",
                evidence: [method, "genuine PACIBSP or BTI C function entry"],
                image: image
            ))
            patches.append(try credentialPatch(
                id: "kernel.credential-manager.\(descriptor.id).return",
                offset: start + 4,
                replacement: payload.returnInstruction,
                summary: "Return the forced AppleCredentialManager result",
                evidence: ["paired entry-point stub"],
                image: image
            ))
        }
        return patches
    }

    /// Rank genuine arm64e function entries in a semantically bounded window.
    /// A candidate must match at least 23 of 32 masked words, and it must lead
    /// the runner-up by at least five words. These integer rules reproduce the
    /// reviewed beta-4 evidence without fragile floating-point percentages.
    private func scoredFunctionEntry(
        descriptor: KernelFunctionSignatureDescriptor,
        after lowerNeighbor: UInt64?,
        before upperNeighbor: UInt64?,
        image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64 {
        guard let lowerNeighbor else {
            throw PatchfinderError.noCandidate("lower neighbor for \(descriptor.name)")
        }
        let signatureBytes = UInt64(descriptor.pattern.values.count * 4)
        var scores: [(matches: Int, offset: UInt64)] = []

        for range in layout.executableFileRanges {
            let lower = max(range.lowerBound, lowerNeighbor + 4)
            let upper = min(range.upperBound, upperNeighbor ?? range.upperBound)
            guard upper > lower, upper - lower >= signatureBytes else { continue }

            var offset = (lower + 3) & ~UInt64(3)
            while offset + signatureBytes <= upper {
                let first = try image.readUInt32(at: offset)
                // PACIBSP is the normal arm64e entry. One ACM leaf begins with
                // BTI C instead, so both are accepted and everything else is
                // excluded before the more expensive 32-word comparison.
                if first == 0xD503_237F || first == 0xD503_245F { // PACIBSP or BTI C
                    scores.append((
                        try descriptor.pattern.matchingWordCount(in: image, at: offset),
                        offset
                    ))
                }
                offset += 4
            }
        }

        scores.sort {
            $0.matches == $1.matches ? $0.offset < $1.offset : $0.matches > $1.matches
        }
        guard let best = scores.first, best.matches >= 23 else {
            throw PatchfinderError.noCandidate(
                "\(descriptor.name) similarity entry (best \(scores.first?.matches ?? 0)/32)"
            )
        }
        if scores.count > 1, best.matches - scores[1].matches < 5 {
            throw PatchfinderError.ambiguousCandidate(
                "\(descriptor.name) similarity entry",
                offsets: Array(scores.prefix(5).map(\.offset))
            )
        }
        return best.offset
    }
}

private func credentialPatch(
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
