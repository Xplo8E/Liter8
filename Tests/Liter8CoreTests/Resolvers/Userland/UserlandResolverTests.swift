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

extension UserlandResolverTests {
    /// The activation gate is located from the error string rather than from a
    /// recorded offset, so this pins the whole chain: unique literal, unique
    /// ADRP+ADD reference, the `MOVN W8,#2` failure-block entry, and the one
    /// `TBZ W0,#0` into it that follows an authenticated indirect call.
    ///
    /// 24B5099f rather than the beta-4 fixtures above because that is the build
    /// the site was read on, and the binary is 40 MB of Apple code that is
    /// never committed, so the test skips where it is absent.
    ///
    /// Run this one with `swift test -c release`. Both gates are anchored on a
    /// string literal, so each costs one ADRP+ADD scan of every executable byte
    /// in a 40 MB binary, and a debug build of that scan takes tens of minutes
    /// where release takes seconds. It skips by default, so a normal `swift
    /// test` is unaffected.
    func testCommCenterDataActivationResolvesTheActivationGate() throws {
        let commcenter = binary("CommCenter-24B5099f")
        guard FileManager.default.fileExists(atPath: commcenter.path) else {
            throw XCTSkip("local 24B5099f CommCenter fixture is absent")
        }

        let records = try CommCenterDataActivationResolver()
            .resolve(in: BinaryImage(contentsOf: commcenter))

        XCTAssertEqual(records.count, 2)

        // The outer gate, in canActivateWithoutOverrides. B.NE in, and an
        // unconditional B to that same branch's own target out. Asserting the
        // replacement word and not just the offset is what would catch the
        // displacement being recomputed against the wrong PC.
        let context = try XCTUnwrap(
            records.first { $0.id == "commcenter.data-connection.context-index" }
        )
        XCTAssertEqual(context.offset, 0x92394)
        XCTAssertEqual(context.component, "CommCenter")
        XCTAssertEqual(context.originalWord, 0x5400_0201)
        XCTAssertEqual(context.replacementWord, 0x1400_0010)

        // The inner gate, in canActivateDataSettings. TBZ W0,#0 in, NOP out.
        // Asserting the original guards against the resolver drifting onto some
        // other branch that happens to match.
        let activation = try XCTUnwrap(
            records.first { $0.id == "commcenter.data-settings.activation-status" }
        )
        XCTAssertEqual(activation.offset, 0x936E8)
        XCTAssertEqual(activation.component, "CommCenter")
        XCTAssertEqual(activation.originalWord, 0x3600_0460)
        XCTAssertEqual(activation.replacementWord, ARM64.nop)
    }
}
