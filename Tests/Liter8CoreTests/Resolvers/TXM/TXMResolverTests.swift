import Foundation
import XCTest
@testable import Liter8Core

final class TXMResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var beta4TXM: URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/txm/txm_b4_n104.raw")
    }

    override func setUpWithError() throws {
        guard FileManager.default.fileExists(atPath: beta4TXM.path) else {
            throw XCTSkip("local beta-4 TXM fixture is absent")
        }
    }

    func testQueryModuleResolverSelectsThreeCDHashComparisons() throws {
        let records = try TXMQueryModuleResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(records.map(\.offset), [0x39E28, 0x39F90, 0x3A124])
        XCTAssertEqual(records.compactMap(\.replacementWord), Array(repeating: 0xD2800000, count: 3))
    }

    func testConstraintResolverSelectsBothIndependentChecks() throws {
        let records = try TXMConstraintsResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(Set(records.map(\.offset)), Set([0x3F624, 0x3F690, 0x3F698]))
    }

    func testBootStateResolverLinksBothFunctionsThroughSharedState() throws {
        let records = try TXMBootStateResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(Set(records.map(\.offset)), Set([0x2BCD4, 0x2BCD8, 0x2BA58]))
    }

    func testTXMPlanManifestsVerifyCompleteOutputs() throws {
        let cases = [
            ("fixtures/24A5390f/n104ap/txm-restore-n104-24A5390f.json", 6),
            ("fixtures/24A5390f/n104ap/txm-boot-n104-24A5390f.json", 9),
        ]
        for (manifestPath, expectedCount) in cases {
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent(manifestPath)
            )
            XCTAssertEqual(
                try manifest.verify(binaryAt: beta4TXM).count,
                expectedCount,
                manifestPath
            )
        }
    }
}
