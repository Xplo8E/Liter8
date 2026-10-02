import Foundation

/// Marks the two kernel version strings without changing their size or any
/// Mach-O layout. This is cosmetic but operationally useful: `uname` can prove
/// that the booted kernel came from the patched artifact.
///
/// The version string embeds a `/RELEASE_ARM64_<PLATFORM>` token: `T8030` on
/// the A13 (n104), `T8020` on the A12 (j171a), and so on. The SoC suffix is
/// read from the binary rather than hard-coded, because the patch itself is
/// platform-independent: it rewrites the seven-character `RELEASE` to
/// `PATCHED`, which is the same length for every platform and moves no data.
/// Hard-coding `T8030` here was the sole reason the kernel `restore`, `boot`,
/// `boot-public` and `diagnostic` plans could not even begin resolving against
/// a T8020 kernelcache.
struct KernelIdentityResolver: Sendable {
    static let prefix = "/RELEASE_ARM64_"
    static let patchedPrefix = "/PATCHED_ARM64_"

    /// Longest plausible SoC token after the prefix (e.g. `T8030`, `T8020`,
    /// `T8101`). A bound keeps the forward scan from running off a corrupt
    /// string into unrelated data.
    private static let maxPlatformLength = 16

    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let sites = image.findAll(utf8: Self.prefix, nulTerminated: false)
        guard sites.count == 2 else {
            if sites.isEmpty { throw PatchfinderError.missingAnchor(Self.prefix) }
            throw PatchfinderError.ambiguousAnchor(Self.prefix, count: sites.count)
        }

        // Both occurrences are copies of one version string, so they must carry
        // the same SoC token. Deriving it from each site and requiring equality
        // rejects a binary whose two copies disagree, which would mean the
        // anchor landed on something other than the paired version strings.
        let platforms = try sites.map { try Self.platformToken(in: image, prefixOffset: $0) }
        guard let platform = platforms.first, platforms.allSatisfy({ $0 == platform }) else {
            throw PatchfinderError.ambiguousAnchor(Self.prefix, count: sites.count)
        }

        let original = Data((Self.prefix + platform).utf8)
        let replacement = Data((Self.patchedPrefix + platform).utf8)
        return sites.sorted().enumerated().map { index, offset in
            PatchRecord(
                id: "kernel.identity.\(index)",
                component: "kernelcache",
                offset: offset,
                originalBytes: original,
                replacementBytes: replacement,
                summary: "Mark kernel version string \(index) (\(platform)) as patched",
                evidence: [
                    "exact same-length RELEASE_ARM64_\(platform) string",
                    "exactly two occurrences in the pristine kernelcache",
                    "SoC token read from the binary, not assumed",
                    "replacement does not move data or alter container layout",
                ]
            )
        }
    }

    /// Read the `[A-Za-z0-9]` SoC token that follows the prefix, stopping at the
    /// first byte that cannot belong to a platform name (the trailing NUL in a
    /// real kernelcache). An empty token means the anchor did not land on a
    /// version string.
    private static func platformToken(in image: BinaryImage, prefixOffset: UInt64) throws -> String {
        let start = prefixOffset + UInt64(Data(prefix.utf8).count)
        let available = min(maxPlatformLength, max(0, image.count - Int(start)))
        let window = try image.bytes(at: start, count: available)
        var token: [UInt8] = []
        for byte in window {
            let isAlnum = (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x61 && byte <= 0x7A)
            if isAlnum { token.append(byte) } else { break }
        }
        guard !token.isEmpty else {
            throw PatchfinderError.missingAnchor(prefix)
        }
        return String(decoding: token, as: UTF8.self)
    }
}
