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

    /// These manifests pin the **default** boot-argument literals, so the suite
    /// must not inherit `--serial` from whoever ran it. A developer with
    /// `LITER8_SERIAL=1` exported would otherwise see every iBoot fixture fail
    /// for a reason that has nothing to do with their change.
    override func setUp() {
        super.setUp()
        unsetenv(SerialConsole.environmentKey)
    }

    private func binary(_ name: String, build: String = "24A435") -> URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/\(build)/\(name)")
    }

    private func manifest(_ name: String, build: String = "24A435") throws -> FixtureManifest {
        try FixtureManifest.load(
            from: packageRoot.appendingPathComponent("fixtures/\(build)/n104ap/\(name)")
        )
    }

    /// fixture file, binary under `offsets/24A435/`, expected record count.
    private static let fixtures: [(String, String, Int)] = [
        ("ibss-n104-24A435.json", "iBSS.n104.RELEASE.bin", 2),
        ("ibss-restore-n104-24A435.json", "iBSS.n104.RELEASE.bin", 5),
        ("ibec-restore-n104-24A435.json", "iBSS.n104.RELEASE.bin", 6),
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
        ("kernel-valeria-n104-24A435.json", "kernelcache.release.iphone12b.bin", 15),
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
        XCTAssertEqual(checked, 219, "every release record must be covered")
    }

    /// The same oracles for `24A437`, the shipping build of the same kernel.
    ///
    /// These are not redundant with the `24A435` set even though every resolved
    /// offset matches: the inputs are different files. `restored_external` and
    /// `asr` genuinely differ between the two builds, so verifying both is what
    /// proves the resolvers tracked the change rather than that the bytes never
    /// moved.
    func testEveryStableFixtureRediscoversItsSitesAndOutput() throws {
        var checked = 0
        for (fixture, binaryName, expected) in Self.fixtures {
            let stableFixture = fixture.replacingOccurrences(of: "24A435", with: "24A437")
            let url = binary(binaryName, build: "24A437")
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw XCTSkip("local 24A437 fixture binary \(binaryName) is absent")
            }
            let records = try manifest(stableFixture, build: "24A437").verify(binaryAt: url)
            XCTAssertEqual(records.count, expected, "\(stableFixture) record count")
            checked += records.count
        }
        XCTAssertEqual(checked, 219, "every stable record must be covered")
    }

    /// The same oracles for iOS 27.2 `24B5084k`.
    ///
    /// Unlike `24A437`, this build is not a rebuild of `24A435`: it carries a
    /// different XNU, its own AppleCredentialManager signature family, and an
    /// iBSS whose boot-argument padding moved off a page boundary. Every one of
    /// the 219 records still resolve, so this suite is what would catch a
    /// resolver being quietly narrowed to fit one of the three builds.
    func testEveryTwoSevenTwoFixtureRediscoversItsSitesAndOutput() throws {
        var checked = 0
        for (fixture, binaryName, expected) in Self.fixtures {
            let name = fixture.replacingOccurrences(of: "24A435", with: "24B5084k")
            let url = binary(binaryName, build: "24B5084k")
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw XCTSkip("local 24B5084k fixture binary \(binaryName) is absent")
            }
            let records = try manifest(name, build: "24B5084k").verify(binaryAt: url)
            XCTAssertEqual(records.count, expected, "\(name) record count")
            checked += records.count
        }
        XCTAssertEqual(checked, 219, "every 27.2 record must be covered")
    }

    func testTFP0ResolverMatchesEverySupportedKernel() throws {
        let cases: [(build: String, offsets: [UInt64], slide: String)] = [
            ("24A435", [0x31B6640, 0x36BF37C, 0x31B7FA8, 0x32003F8], "68d3feb008b547f9df0200f9"),
            ("24A446", [0x31B6640, 0x36BF37C, 0x31B7FA8, 0x32003F8], "68d3feb008b547f9df0200f9"),
            ("24B5084k", [0x32EB87C, 0x37FA368, 0x32ED1E4, 0x3335880], "88cbfeb008a540f9df0200f9"),
            ("24B5089g", [0x32EF810, 0x37FEA40, 0x32F1178, 0x333981C], "68cbfeb008a540f9df0200f9"),
            ("24B5099f", [0x3207830, 0x3716BA8, 0x3209198, 0x3251854], "88d1feb0089140f9df0200f9"),
            ("24B5110a", [0x320B830, 0x371AE48, 0x320D198, 0x3255854], "68d1feb0089140f9df0200f9"),
            ("24B119", [0x31F28D4, 0x36FE7AC, 0x31F423C, 0x323C784], "e8d1fed0085940f9df0200f9"),
        ]
        let available = cases.filter {
            let url = binary("kernelcache.release.iphone12b.bin", build: $0.build)
            return FileManager.default.fileExists(atPath: url.path)
        }
        if available.isEmpty { throw XCTSkip("local tfp0 kernel fixtures are absent") }

        for (build, offsets, slide) in available {
            let url = binary("kernelcache.release.iphone12b.bin", build: build)
            let image = try BinaryImage(contentsOf: url)
            let records = try KernelTFP0Resolver.requiredRecords(in: image)
            XCTAssertEqual(records.map(\.offset), offsets, build)
            XCTAssertEqual(
                records.prefix(3).compactMap(\.replacementWord),
                [0xEB1F03FF, ARM64.nop, 0x1400000A],
                build
            )
            XCTAssertEqual(records.last?.replacementBytes.hexadecimalString, slide, build)
            if build == "24A435" || build == "24A446" {
                try manifest("kernel-tfp0-n104-\(build).json", build: build)
                    .verify(resolved: records, in: image)
            }

            let first = try GuardedPatchApplier.apply(records, to: image)
            let patched = BinaryImage(data: first.data)
            let secondRecords = try KernelTFP0Resolver.requiredRecords(in: patched)
            XCTAssertEqual(secondRecords, records, build)
            let second = try GuardedPatchApplier.apply(secondRecords, to: patched)
            XCTAssertTrue(second.dispositions.values.allSatisfy { $0 == .alreadyApplied }, build)
            XCTAssertEqual(second.data, first.data, build)
        }
    }

    func testTFP0SlideResolverRejectsDamagedPreimage() throws {
        let url = binary("kernelcache.release.iphone12b.bin", build: "24A446")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local 24A446 kernelcache fixture is absent")
        }
        let clean = try BinaryImage(contentsOf: url)
        var damagedPreimage = clean.data
        var nop = ARM64.nop.littleEndian
        withUnsafeBytes(of: &nop) { bytes in
            damagedPreimage.replaceSubrange(0x32003F8..<(0x32003F8 + 4), with: bytes)
        }
        XCTAssertThrowsError(
            try KernelTFP0Resolver.requiredRecords(in: BinaryImage(data: damagedPreimage))
        ) { error in
            guard case let PatchfinderError.invalidPatch(id, _) = error else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertEqual(id, "kernel.tfp0.dyld-info-slide")
        }
    }

    /// 27.2 must describe the same operations as the release builds.
    ///
    /// This is the comparison that matters most of the three, because 27.2
    /// genuinely differs: if a resolver silently stopped covering a site on the
    /// newer kernel, the record count alone could still look plausible while the
    /// patch id set had changed.
    func testTwoSevenTwoAndReleaseFixturesDescribeTheSameOperations() throws {
        for (fixture, _, _) in Self.fixtures {
            let name = fixture.replacingOccurrences(of: "24A435", with: "24B5084k")
            let release = try manifest(fixture)
            let newer = try manifest(name, build: "24B5084k")

            XCTAssertEqual(newer.target.build, "24B5084k")
            XCTAssertEqual(newer.target.board, release.target.board)
            XCTAssertEqual(newer.resolver, release.resolver)
            XCTAssertEqual(
                newer.expectedPatches.map(\.id).sorted(),
                release.expectedPatches.map(\.id).sorted(),
                "\(newer.resolver) must cover the same patch ids on 27.2"
            )
            XCTAssertNotNil(newer.expectedOutputSHA256)
            // Every 27.2 input really is a different file. 24A437 shipped some
            // components byte-identical to 24A435, so that build deliberately
            // does not assert this; asserting it here is what proves these
            // manifests were generated from 27.2 and not copied.
            XCTAssertNotEqual(
                newer.sha256, release.sha256,
                "\(newer.resolver) 27.2 input must not be the 24A435 binary"
            )
        }
    }

    /// `24A437` must describe the same operations as `24A435`, on its own bytes.
    ///
    /// Comparing patch IDs rather than offsets is deliberate. These two builds
    /// agree on every offset today, so pinning offsets here would assert a
    /// coincidence of this build pair rather than anything about the resolvers.
    ///
    /// Note what is deliberately *not* asserted: the beta-4 comparison requires
    /// the two inputs to have different digests, and that check would be wrong
    /// here. Apple shipped `24A437` with a byte-identical iBSS/iBEC, TXM and
    /// SPTM, so those manifests legitimately record the same `sha256` as
    /// `24A435`. Only the kernelcache and the two ramdisk binaries differ.
    func testStableAndReleaseFixturesDescribeTheSameOperations() throws {
        for (fixture, _, _) in Self.fixtures {
            let stableFixture = fixture.replacingOccurrences(of: "24A435", with: "24A437")
            let release = try manifest(fixture)
            let stable = try manifest(stableFixture, build: "24A437")

            XCTAssertEqual(stable.target.build, "24A437")
            XCTAssertEqual(stable.target.board, release.target.board)
            XCTAssertEqual(stable.target.component, release.target.component)
            XCTAssertEqual(stable.resolver, release.resolver)
            XCTAssertEqual(
                stable.expectedPatches.map(\.id).sorted(),
                release.expectedPatches.map(\.id).sorted(),
                "\(stable.resolver) must cover the same patch ids on both builds"
            )
            XCTAssertNotNil(
                stable.expectedOutputSHA256,
                "\(stable.resolver) must pin a complete output hash"
            )
        }
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
            .filter { $0.hasSuffix(".json") && !$0.hasPrefix("kernel-tfp0-") }
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
