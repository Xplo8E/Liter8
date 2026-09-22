import Foundation
import XCTest
@testable import Liter8Core

/// Coverage for page-tail slot selection.
///
/// The slot is chosen by identifying the section-tail padding — the uniquely
/// largest zero run ending on a 4 KiB boundary — and only then placing the
/// literal inside it. Selecting by "which runs happen to fit this literal" is
/// what made this resolver unstable: a fixed 16-byte alignment excluded the
/// runner-up run only by arithmetic accident, so relaxing the alignment to fit
/// RC's shorter run silently admitted a second candidate and broke the restore
/// plan on both builds.
final class IBSSBootArgsSlotTests: XCTestCase {
    private let resolver = IBSSBootArgsResolver()

    /// A payload whose zero runs are exactly the ones described, each ending on
    /// a page boundary, with non-zero filler everywhere else.
    private func payload(pages: Int, runs: [(endPage: Int, length: Int)]) -> BinaryImage {
        var bytes = [UInt8](repeating: 0xAA, count: pages * 0x1000)
        for run in runs {
            let end = run.endPage * 0x1000
            for index in (end - run.length)..<end { bytes[index] = 0 }
        }
        return BinaryImage(data: Data(bytes))
    }

    private func length(_ literal: String) -> Int { literal.utf8.count + 1 }

    private let restore = "-v wdt=-1 rd=md0 -restore"
    private let sshrd = "rd=md0 -v wdt=-1 debug=0x2014e backlight-level=1024"
    private let normal = "-v debug=0x2014e launchd_unsecure_cache=1 wdt=-1 backlight-level=1024"

    // MARK: - Run identification

    func testOnlyRunsEndingOnAPageBoundaryAreConsidered() {
        // A 300-byte zero run in the middle of a page is ordinary zero-filled
        // data, not section-tail padding.
        var bytes = [UInt8](repeating: 0xAA, count: 8 * 0x1000)
        for index in 0x1800..<0x1900 { bytes[index] = 0 }
        XCTAssertTrue(resolver.pageTailRuns(in: BinaryImage(data: Data(bytes))).isEmpty)
    }

    func testRunsAreOrderedLargestFirst() {
        let image = payload(pages: 8, runs: [(3, 35), (6, 476)])
        let runs = resolver.pageTailRuns(in: image)
        XCTAssertEqual(runs.count, 2)
        XCTAssertEqual(runs[0].end - runs[0].start, 476)
        XCTAssertEqual(runs[1].end - runs[1].start, 35)
    }

    // MARK: - Dominance

    func testRunnerUpRunIsNotAdmittedForAShortLiteral() {
        // Mirrors both real payloads: one dominant run plus a 35-byte runner-up
        // that can also hold the 26-byte restore literal. Before selection was
        // tied to the dominant run this produced two candidates and failed the
        // whole restore plan with an ambiguity error.
        let image = payload(pages: 8, runs: [(3, 476), (6, 35)])
        let slots = resolver.findPageTailSlots(in: image, requiredLength: length(restore))
        XCTAssertEqual(slots.count, 1)
        XCTAssertEqual(slots.first?.runEnd, 0x3000)
    }

    func testEveryLiteralLengthSelectsTheSameDominantRun() {
        let image = payload(pages: 8, runs: [(3, 476), (6, 35)])
        for literal in [restore, sshrd, normal] {
            let slots = resolver.findPageTailSlots(in: image, requiredLength: length(literal))
            XCTAssertEqual(slots.count, 1, "literal length must not change which run is chosen")
            XCTAssertEqual(slots.first?.runEnd, 0x3000)
        }
    }

    func testTwoEquallyLargestRunsAreRefusedRatherThanGuessed() {
        let image = payload(pages: 8, runs: [(3, 128), (6, 128)])
        XCTAssertTrue(resolver.findPageTailSlots(in: image, requiredLength: length(restore)).isEmpty)
    }

    /// Ambiguity must refuse even though a fallback exists.
    ///
    /// The alignment-padding fallback was added for iOS 27.2, whose page-tail
    /// runs are all under twelve bytes. It must not rescue the case above: two
    /// equally good page-tail runs is a deliberate refusal, and reaching the
    /// fallback there would convert it into a guess made on different grounds.
    /// The first version of that fallback did exactly this.
    func testFallbackDoesNotRescueAnAmbiguousPageTailChoice() {
        // Both page-tail runs fit the literal, and a large aligned-padding run
        // exists elsewhere that the fallback would happily take.
        var data = payload(pages: 8, runs: [(3, 128), (6, 128)]).data
        data.replaceSubrange(0x1000 - 300..<0x1000 - 100, with: Data(repeating: 0, count: 200))
        XCTAssertTrue(
            resolver.findPageTailSlots(in: BinaryImage(data: data),
                                       requiredLength: length(restore)).isEmpty,
            "an ambiguous page-tail choice must refuse, not fall through"
        )
    }

    /// The fallback engages when every page-tail run is too small to be used.
    ///
    /// This is the iOS 27.2 shape: the device tree grew by 2048 bytes, so the
    /// padding that 24A435 used still exists at the same size but now ends
    /// 2048-aligned rather than 4096-aligned.
    func testFallbackSelectsAlignmentPaddingWhenNoPageTailRunFits() {
        var data = Data(repeating: 0xAA, count: 0x8000)
        // Page-tail runs exist but are far too short for any literal.
        data.replaceSubrange(0x3000 - 8..<0x3000, with: Data(repeating: 0, count: 8))
        // 79 bytes of padding ending 2048-aligned, exactly 27.2's shape.
        data.replaceSubrange(0x5800 - 79..<0x5800, with: Data(repeating: 0, count: 79))

        let slots = resolver.findPageTailSlots(
            in: BinaryImage(data: data),
            requiredLength: length(restore)
        )
        XCTAssertEqual(slots.count, 1)
        XCTAssertEqual(slots.first?.runEnd, 0x5800)
        XCTAssertEqual(slots.first?.endAlignment, 2048)
    }

    // MARK: - Placement inside the chosen run

    func testWidestAlignmentIsPreferredWhenTheRunHasRoom() {
        // Beta 4's run is 476 bytes, so the 16-byte-aligned position fits every
        // literal and the historical slot is preserved.
        let image = payload(pages: 8, runs: [(3, 476)])
        let runStart = UInt64(0x3000 - 476)
        for literal in [restore, sshrd, normal] {
            let slot = try? XCTUnwrap(
                resolver.findPageTailSlots(in: image, requiredLength: length(literal)).first
            )
            XCTAssertEqual(slot?.writeOffset, (runStart + 8 + 15) & ~15)
        }
    }

    func testAlignmentNarrowsOnlyWhenTheRunDemandsIt() {
        // RC's run is 79 bytes against a 70-byte literal. No 16-, 8- or
        // 4-byte-aligned position fits after the 8-byte guard, so placement
        // must narrow rather than fail.
        let image = payload(pages: 8, runs: [(3, 79)])
        let need = length(normal)
        let slot = resolver.findPageTailSlots(in: image, requiredLength: need).first
        let runStart = UInt64(0x3000 - 79)
        XCTAssertNotNil(slot)
        XCTAssertGreaterThanOrEqual(slot!.writeOffset, runStart + 8, "the guard gap is never traded away")
        XCTAssertLessThanOrEqual(
            slot!.writeOffset + UInt64(need), 0x3000,
            "the NUL-terminated literal must end inside the run"
        )
        XCTAssertNotEqual(slot!.writeOffset % 16, 0, "this run cannot satisfy 16-byte alignment")
    }

    func testGuardGapIsNeverTradedAwayToMakeALiteralFit() {
        // The run has exactly enough bytes for the literal but not for the
        // literal plus the guard. It must be refused, not squeezed.
        let need = length(restore)
        let image = payload(pages: 8, runs: [(3, need + 4)])
        XCTAssertTrue(resolver.findPageTailSlots(in: image, requiredLength: need).isEmpty)
    }

    func testALiteralLargerThanTheRunIsRefused() {
        let image = payload(pages: 8, runs: [(3, 32)])
        XCTAssertTrue(resolver.findPageTailSlots(in: image, requiredLength: 64).isEmpty)
    }

    func testNoPageTailRunAtAllIsRefused() {
        let bytes = [UInt8](repeating: 0xAA, count: 8 * 0x1000)
        let slots = resolver.findPageTailSlots(
            in: BinaryImage(data: Data(bytes)),
            requiredLength: length(restore)
        )
        XCTAssertTrue(slots.isEmpty)
    }
}
