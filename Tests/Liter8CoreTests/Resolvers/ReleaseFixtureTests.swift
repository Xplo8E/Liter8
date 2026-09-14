import Foundation
import XCTest
@testable import Liter8Core

/// Exact-build oracles for iOS 27 RC `24A435` on iPhone 11 / n104ap.
///
/// Every manifest binds the clean input SHA-256, each resolved offset with its
/// original and replacement bytes, and the SHA-256 of the complete patched
/// output. Verifying one therefore checks three separate things: that the
/// resolver still selects the same site, that the site still contains the bytes
/// it was recorded with, and that nothing was written outside the declared
/// ranges.
///
/// These scan real firmware, so they sit in the same slow tier as
/// `KernelFixtureTests` and are skipped by `make test`. Run them with
/// `make test-fixtures`. Apple binaries stay out of the repository: point the
/// suite at a local tree with
/// `LITER8_FIXTURE_ROOT=/path/to/private/research make test-fixtures`.
final class ReleaseFixtureTests: XCTestCase {
    private var packageRoot: URL { liter8PackageRoot(from: #filePath) }

    private func binary(_ name: String) -> URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/24A435/\(name)")
    }

    private func manifest(_ name: String) throws -> FixtureManifest {
        try FixtureManifest.load(
            from: packageRoot.appendingPathComponent("fixtures/24A435/n104ap/\(name)")
        )
    }

    /// fixture file, binary under `offsets/24A435/`, expected record count.
    private static let fixtures: [(String, String, Int)] = [
        ("ibss-n104-24A435.json", "iBSS.n104.RELEASE.bin", 2),
        ("ibss-restore-n104-24A435.json", "iBSS.n104.RELEASE.bin", 5),
        ("ibss-ramdisk-n104-24A435.json", "iBSS.n104.RELEASE.bin", 5),
        ("ibss-normal-n104-24A435.json", "iBSS.n104.RELEASE.bin", 5),
        ("ibss-skip-display-n104-24A435.json", "iBSS.n104.RELEASE.bin", 1),
        ("ibec-ignore-pinot-n104-24A435.json", "iBSS.n104.RELEASE.bin", 1),
        ("txm-restore-n104-24A435.json", "txm.iphoneos.release.bin", 6),
        ("txm-boot-n104-24A435.json", "txm.iphoneos.release.bin", 9),
        ("kernel-restore-n104-24A435.json", "kernelcache.release.iphone12b.bin", 20),
        ("kernel-boot-policy-n104-24A435.json", "kernelcache.release.iphone12b.bin", 4),
        ("kernel-sep-n104-24A435.json", "kernelcache.release.iphone12b.bin", 32),
        ("kernel-sandbox-n104-24A435.json", "kernelcache.release.iphone12b.bin", 46),
        ("kernel-credential-manager-n104-24A435.json", "kernelcache.release.iphone12b.bin", 52),
        ("restored-external-n104-24A435.json", "restored_external", 1),
        ("asr-n104-24A435.json", "asr", 1),
        ("coreauthd-n104-24A435.json", "coreauthd", 1),
        ("ctkd-n104-24A435.json", "ctkd", 2),
        ("mobileactivationd-n104-24A435.json", "mobileactivationd", 5),
    ]

    func testEveryReleaseFixtureRediscoversItsSitesAndOutput() throws {
        var checked = 0
        for (fixture, binaryName, expected) in Self.fixtures {
            let url = binary(binaryName)
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw XCTSkip("local 24A435 fixture binary \(binaryName) is absent")
            }
            let records = try manifest(fixture).verify(binaryAt: url)
            XCTAssertEqual(records.count, expected, "\(fixture) record count")
            checked += records.count
        }
        XCTAssertEqual(checked, 198, "every release record must be covered")
    }

    /// The two builds must describe the same operations.
    ///
    /// A release manifest that quietly dropped or gained a record would still
    /// verify on its own binary, so compare the sets rather than only the
    /// counts. Offsets and bytes are deliberately not compared: those are
    /// expected to move, and pinning them here would recreate the fixed-offset
    /// tables the resolvers exist to replace.
    func testReleaseAndBeta4FixturesDescribeTheSameOperations() throws {
        let releaseRoot = packageRoot.appendingPathComponent("fixtures/24A435/n104ap")
        let betaRoot = packageRoot.appendingPathComponent("fixtures/24A5390f/n104ap")
        let fileManager = FileManager.default

        let releaseFiles = try fileManager.contentsOfDirectory(atPath: releaseRoot.path)
            .filter { $0.hasSuffix(".json") }
        let betaFiles = try fileManager.contentsOfDirectory(atPath: betaRoot.path)
            .filter { $0.hasSuffix(".json") }
        XCTAssertEqual(releaseFiles.count, betaFiles.count)

        var betaByResolver: [String: FixtureManifest] = [:]
        for file in betaFiles {
            let loaded = try FixtureManifest.load(from: betaRoot.appendingPathComponent(file))
            betaByResolver[loaded.resolver] = loaded
        }

        for file in releaseFiles {
            let release = try FixtureManifest.load(from: releaseRoot.appendingPathComponent(file))
            let beta = try XCTUnwrap(
                betaByResolver[release.resolver],
                "no beta-4 fixture for resolver \(release.resolver)"
            )
            XCTAssertEqual(release.target.build, "24A435")
            XCTAssertEqual(release.target.board, beta.target.board)
            XCTAssertEqual(release.target.component, beta.target.component)
            XCTAssertEqual(
                release.expectedPatches.map(\.id).sorted(),
                beta.expectedPatches.map(\.id).sorted(),
                "\(release.resolver) must cover the same patch ids on both builds"
            )
            XCTAssertNotNil(
                release.expectedOutputSHA256,
                "\(release.resolver) must pin a complete output hash"
            )
            XCTAssertNotEqual(
                release.sha256, beta.sha256,
                "\(release.resolver) release input must not be the beta-4 binary"
            )
        }
    }
}
