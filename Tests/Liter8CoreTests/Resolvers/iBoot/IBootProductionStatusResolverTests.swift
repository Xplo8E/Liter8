import Foundation
import XCTest
@testable import Liter8Core

final class IBootProductionStatusResolverTests: XCTestCase {
    private var beta4IBSS: URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/ibss/iBSS.raw")
    }

    func testResolvesTheConditionalPublishAndKeepsItsOwnTarget() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let records = try IBootProductionStatusResolver().resolve(in: image)

        XCTAssertEqual(records.count, 1)
        guard let record = records.first,
              let original = record.originalWord,
              let replacement = record.replacementWord else {
            return XCTFail("resolver produced no decodable record")
        }
        XCTAssertEqual(record.id, "iboot.chosen.suppress-production-status-ap")

        // The original must be TBZ W0,#0 and the replacement an unconditional
        // branch to that same target. Asserting the relationship rather than a
        // fixed offset is the point: a build whose layout moved must still
        // produce a self-consistent patch or fail outright.
        XCTAssertEqual(original & 0xFFF8_001F, 0x3600_0000, "original is not TBZ W0,#0")
        XCTAssertEqual(replacement & 0xFC00_0000, 0x1400_0000, "replacement is not B")
        let originalTarget = ARM64.testBranchTarget(instruction: original, at: record.offset)
        let patchedTarget = ARM64.directBranchTarget(instruction: replacement, at: record.offset)
        XCTAssertNotNil(originalTarget)
        XCTAssertEqual(originalTarget, patchedTarget, "branch target changed")
    }

    func testMissingAnchorDoesNotFallBackToAKnownOffset() throws {
        // Large enough to contain the real 24B5099f site, so a pass proves there
        // is no hidden fixed-offset fallback.
        let image = BinaryImage(data: Data(repeating: 0, count: 0x30000))
        XCTAssertThrowsError(try IBootProductionStatusResolver().resolve(in: image))
    }

    func testNormalPlanOmitsTheRecordUnlessRequested() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        XCTAssertNil(ProcessInfo.processInfo.environment[APDemotion.environmentKey])

        let records = try IBSSNormalResolver().resolve(in: image)
        XCTAssertFalse(
            records.contains { $0.id == "iboot.chosen.suppress-production-status-ap" },
            "demotion record leaked into the default normal plan"
        )
    }
}
