import Foundation
import XCTest
@testable import Liter8Core

/// The 23H128 iBEC duplicate-trust-cache check. Synthetic images carry the
/// same instruction shapes as the 23H128 add routine; the real payloads come
/// from LITER8_FIXTURE_ROOT/offsets/<build>/iBEC.raw.
final class IBECTrustCacheResolverTests: XCTestCase {
    private let nop: UInt32 = 0xD503_201F

    /// Words of the 23H128 routine that matter, with NOP filler in between.
    /// Returns the image and the offset of the B.EQ the resolver must find.
    private func routine(
        typeRegister: UInt32 = 20,
        loopCompareRegister: UInt32? = nil,
        errorLow: UInt32 = 0x5280_00C8,     // MOV W8,#6
        errorAdd: UInt32 = 0x1100_1900,     // ADD W0,W8,#6 -> 0x400d000c
        returnsMinusOne: Bool = true,
        copies: Int = 1
    ) -> (BinaryImage, [UInt64]) {
        var words: [UInt32] = []
        var branches: [UInt64] = []
        for _ in 0..<copies {
            words += [0xD503_237F] // PACIBSP
            words += [0x528E_6C68, 0x72AE_4E88] // W8 = 'rtsc'
            words += [0x6B08_001F | (typeRegister << 5)] // CMP Wtype,W8
            words += Array(repeating: nop, count: 20)
            words += [0xB940_6808] // LDR W8,[X0,#0x68]
            let other = loopCompareRegister ?? typeRegister
            words += [0x6B00_001F | (other << 16) | (8 << 5)] // CMP W8,Wtype
            let branchIndex = words.count
            words += [0] // B.EQ, patched below
            words += Array(repeating: nop, count: 6)
            let failureIndex = words.count
            words[branchIndex] = 0x5400_0000 | (UInt32(failureIndex - branchIndex) << 5)
            branches.append(UInt64(branchIndex * 4))
            words += [0x5280_0BC8] // MOV W8,#0x5e (log line)
            words += Array(repeating: nop, count: 8)
            words += [errorLow, 0x72A8_01A8, errorAdd] // MOVZ/MOVK W8; ADD W0,W8,#6
            words += [0x9400_0000] // BL error recorder
            words += [returnsMinusOne ? 0x1280_0000 : 0x5280_0000]
            words += Array(repeating: nop, count: 4)
        }
        var data = Data()
        for word in words { withUnsafeBytes(of: word.littleEndian) { data.append(contentsOf: $0) } }
        return (BinaryImage(data: data), branches)
    }

    func testFindsTheDuplicateTypeBranchAndReplacesItWithNOP() throws {
        let (image, branches) = routine()
        let records = try IBECAllowDuplicateTrustCacheResolver().resolve(in: image)
        XCTAssertEqual(records.map(\.offset), branches)
        XCTAssertEqual(records.first?.replacementWord, nop)
        XCTAssertEqual(records.first?.originalWord, try image.readUInt32(at: branches[0]))
    }

    func testRejectsABranchToAnotherFailure() {
        // 0x400d0006 (no ADD #6) is the routine's unsupported-type exit, not
        // the duplicate-type one.
        let (wrongCode, _) = routine(errorAdd: 0x2A08_03E0) // MOV W0,W8
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: wrongCode))
        let (noReturn, _) = routine(returnsMinusOne: false)
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: noReturn))
        let (wrongLow, _) = routine(errorLow: 0x5280_00E8) // MOV W8,#7
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: wrongLow))
    }

    func testRequiresTheLoopToCompareWithTheIncomingType() {
        let (image, _) = routine(typeRegister: 20, loopCompareRegister: 19)
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: image))
    }

    func testRefusesTwoCandidates() {
        let (image, _) = routine(copies: 2)
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: image)) { error in
            guard case PatchfinderError.ambiguousCandidate = error else {
                return XCTFail("expected ambiguousCandidate, got \(error)")
            }
        }
    }

    func testAlreadyAppliedPatchIsAcceptedAndNotRediscovered() throws {
        let (image, _) = routine()
        let records = try IBECAllowDuplicateTrustCacheResolver().resolve(in: image)
        let patched = BinaryImage(data: try GuardedPatchApplier.apply(records, to: image).data)
        // The guarded applier accepts the exact replacement again...
        XCTAssertEqual(try GuardedPatchApplier.apply(records, to: patched).data, patched.data)
        // ...and the patched routine no longer has a duplicate-type branch.
        XCTAssertThrowsError(try IBECAllowDuplicateTrustCacheResolver().resolve(in: patched))
    }

    // MARK: real payloads

    private func payload(_ build: String) -> URL {
        liter8PrivateFixtureRoot(from: #filePath).appendingPathComponent("offsets/\(build)/iBEC.raw")
    }

    func test23H128IBECHasExactlyTheMeasuredSite() throws {
        let url = payload("23H128")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local 23H128 iBEC is absent")
        }
        let records = try IBECAllowDuplicateTrustCacheResolver().resolve(in: BinaryImage(contentsOf: url))
        XCTAssertEqual(records.map(\.offset), [0xB07E4])
        XCTAssertEqual(records.first?.originalWord, 0x5400_0A80) // B.EQ +0x150
        let manifest = try FixtureManifest.load(from: liter8PackageRoot(from: #filePath)
            .appendingPathComponent("fixtures/23H128/j171aap/ibec-trust-cache-j171aap-23H128.json"))
        XCTAssertEqual(try manifest.verify(binaryAt: url).count, 1)
    }

    /// 26.7.1 has no duplicate-type check, so the plan must not find one there:
    /// the 23H30 profile does not select it, and this keeps it honest.
    func test23H30IBECHasNoDuplicateTypeCheck() throws {
        let url = payload("23H30")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local 23H30 iBEC is absent")
        }
        XCTAssertThrowsError(
            try IBECAllowDuplicateTrustCacheResolver().resolve(in: BinaryImage(contentsOf: url))
        ) { error in
            guard case PatchfinderError.noCandidate = error else {
                return XCTFail("expected noCandidate, got \(error)")
            }
        }
    }

    func testOnlyThe23H128ProfileSelectsThePlan() {
        for profile in DeviceWorkflowRegistry.profiles {
            let expected: [DeviceIBECAdditionalPlan] =
                profile.id == "ipad11,6-j171aap-23H128" ? [.allowDuplicateTrustCache] : []
            XCTAssertEqual(profile.bootPlan.normalIBECAdditionalPlans, expected, profile.id)
        }
        XCTAssertEqual(DeviceIBECAdditionalPlan.allowDuplicateTrustCache.rawValue,
                       IBECAllowDuplicateTrustCacheResolver.name)
    }
}
