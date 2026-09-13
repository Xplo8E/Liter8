import Foundation

/// Marks the two kernel version strings without changing their size or any
/// Mach-O layout. This is cosmetic but operationally useful: `uname` can prove
/// that the booted kernel came from the patched artifact.
struct KernelIdentityResolver: Sendable {
    static let original = "/RELEASE_ARM64_T8030"
    static let replacement = "/PATCHED_ARM64_T8030"

    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let sites = image.findAll(utf8: Self.original, nulTerminated: false)
        guard sites.count == 2 else {
            if sites.isEmpty { throw PatchfinderError.missingAnchor(Self.original) }
            throw PatchfinderError.ambiguousAnchor(Self.original, count: sites.count)
        }
        let original = Data(Self.original.utf8)
        let replacement = Data(Self.replacement.utf8)
        return sites.sorted().enumerated().map { index, offset in
            PatchRecord(
                id: "kernel.identity.\(index)",
                component: "kernelcache",
                offset: offset,
                originalBytes: original,
                replacementBytes: replacement,
                summary: "Mark kernel version string \(index) as patched",
                evidence: [
                    "exact same-length RELEASE_ARM64_T8030 string",
                    "exactly two occurrences in the pristine kernelcache",
                    "replacement does not move data or alter container layout",
                ]
            )
        }
    }
}
