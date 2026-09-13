import Foundation
import XCTest
@testable import Liter8Core

final class UserlandResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private func binary(_ name: String) -> URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/userland/\(name)")
    }

    func testObjectiveCResolversRediscoverBeta4Sites() throws {
        let coreauthd = binary("coreauthd")
        let mobileactivationd = binary("mobileactivationd")
        let ctkd = binary("ctkd")
        for url in [coreauthd, mobileactivationd, ctkd]
            where !FileManager.default.fileExists(atPath: url.path) {
            throw XCTSkip("local beta-4 userland fixtures are absent")
        }

        XCTAssertEqual(
            try CoreAuthDResolver().resolve(in: BinaryImage(contentsOf: coreauthd)).map(\.offset),
            [0x95C0]
        )
        XCTAssertEqual(
            try MobileActivationDResolver()
                .resolve(in: BinaryImage(contentsOf: mobileactivationd))
                .map(\.offset),
            [0x2EC2D8, 0x329B60, 0x329BC0, 0x329BC4, 0x329BC8]
        )
        XCTAssertEqual(
            try CTKDResolver().resolve(in: BinaryImage(contentsOf: ctkd)).map(\.offset),
            [0x1B38, 0x1B3C]
        )
    }

    func testUserlandManifestsMatchCompletePythonOutputs() throws {
        let fixtures = [
            ("coreauthd-n104-24A5390f.json", "coreauthd", 1),
            ("mobileactivationd-n104-24A5390f.json", "mobileactivationd", 5),
            ("ctkd-n104-24A5390f.json", "ctkd", 2),
        ]
        for (fixture, binaryName, patchCount) in fixtures {
            let binaryURL = binary(binaryName)
            guard FileManager.default.fileExists(atPath: binaryURL.path) else {
                throw XCTSkip("local beta-4 userland fixture \(binaryName) is absent")
            }
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent("fixtures/24A5390f/n104ap/\(fixture)")
            )

            // The output digest was produced independently by apply_patches.py.
            // This catches any write outside the individually asserted records.
            XCTAssertEqual(try manifest.verify(binaryAt: binaryURL).count, patchCount)
        }
    }
}
