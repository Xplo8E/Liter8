import Foundation
import XCTest
@testable import Liter8Core

/// Unit coverage for the primitives iOS 27 RC `24A435` broke.
///
/// These build synthetic images instead of reading firmware, so they run
/// everywhere and pin the *rule*, not one build's offsets. Each case names the
/// concrete regression it exists to catch.
final class ARM64BoundaryTests: XCTestCase {
    private let pacibsp: UInt32 = 0xD503_237F
    private let btiC: UInt32 = 0xD503_245F
    private let nop: UInt32 = 0xD503_201F

    // MARK: - Fixtures

    /// A single-segment executable Mach-O whose `__TEXT_EXEC` contents are the
    /// supplied words. File offset and virtual address are deliberately
    /// different so an accidental conflation of the two cannot pass.
    private func image(words: [UInt32], textFileOffset: UInt64 = 0x4000) -> BinaryImage {
        var data = Data(count: Int(textFileOffset))

        data.replaceSubrange(0..<4, with: withUnsafeBytes(of: UInt32(0xFEED_FACF).littleEndian, Array.init))
        data.replaceSubrange(16..<20, with: withUnsafeBytes(of: UInt32(1).littleEndian, Array.init))

        var command = Data()
        func append<T: FixedWidthInteger>(_ value: T) {
            command.append(contentsOf: withUnsafeBytes(of: value.littleEndian, Array.init))
        }
        append(UInt32(0x19))                                   // LC_SEGMENT_64
        append(UInt32(72))                                     // cmdsize
        command.append(Data("__TEXT_EXEC".utf8))
        command.append(Data(count: 16 - "__TEXT_EXEC".utf8.count))
        append(UInt64(0xFFFF_FFF0_0814_8000))                  // vmaddr
        append(UInt64(words.count * 4))                        // vmsize
        append(textFileOffset)                                 // fileoff
        append(UInt64(words.count * 4))                        // filesize
        append(UInt32(5))                                      // maxprot  r-x
        append(UInt32(5))                                      // initprot r-x
        append(UInt32(0))                                      // nsects
        append(UInt32(0))                                      // flags
        data.replaceSubrange(32..<(32 + command.count), with: command)

        for word in words {
            data.append(contentsOf: withUnsafeBytes(of: word.littleEndian, Array.init))
        }
        return BinaryImage(data: data)
    }

    private func layout(_ image: BinaryImage) throws -> MachOLayout {
        try MachOLayout(image: image)
    }

    // MARK: - BTI boundary detection

    func testFunctionEntryReturnsLandingPadWhenPresent() throws {
        // bti c ; pacibsp ; nop
        let img = image(words: [btiC, pacibsp, nop])
        let prologue: UInt64 = 0x4004
        XCTAssertEqual(ARM64.functionEntry(forPrologue: prologue, in: img), 0x4000)
    }

    func testFunctionEntryIsUnchangedWithoutLandingPad() throws {
        // nop ; pacibsp ; nop  -- the beta-4 24A5390f shape
        let img = image(words: [nop, pacibsp, nop])
        let prologue: UInt64 = 0x4004
        XCTAssertEqual(ARM64.functionEntry(forPrologue: prologue, in: img), prologue)
    }

    func testFunctionStartReturnsCallTargetNotPrologue() throws {
        let img = image(words: [btiC, pacibsp, nop, nop, nop])
        let found = ARM64.functionStart(beforeOrAt: 0x4010, in: img, layout: try layout(img))
        // 0x4000 is the BTI, which is what a BL targets. Returning 0x4004 would
        // make a `functionStart - 4` predecessor check read the pad instead of
        // the previous function's terminator, which is what silently rejected
        // all three isDeviceInRestoreMode candidates on RC.
        XCTAssertEqual(found, 0x4000)
    }

    func testNextFunctionStartDoesNotReportOwnPrologue() throws {
        // One BTI'd function followed by a second one.
        let img = image(words: [btiC, pacibsp, nop, nop, btiC, pacibsp, nop])
        let next = ARM64.nextFunctionStart(after: 0x4000, in: img, layout: try layout(img))
        // Returning 0x4004 -- this function's own PACIBSP -- collapses every
        // callee scan window to nothing. That was the AMFI postValidation bug.
        XCTAssertNotEqual(next, 0x4004)
        XCTAssertEqual(next, 0x4010)
    }

    func testNextFunctionStartStillWorksWithoutLandingPads() throws {
        let img = image(words: [pacibsp, nop, nop, nop, pacibsp, nop])
        let next = ARM64.nextFunctionStart(after: 0x4000, in: img, layout: try layout(img))
        XCTAssertEqual(next, 0x4010)
    }

    func testNextFunctionStartIsBoundedWhenNoFurtherFunctionExists() throws {
        let img = image(words: [btiC, pacibsp, nop, nop])
        let next = ARM64.nextFunctionStart(after: 0x4000, in: img, layout: try layout(img))
        XCTAssertEqual(next, 0x4010) // segment end, not a spurious hit
    }

    // MARK: - stubStart

    func testStubStartSkipsLandingPadSoIndirectBranchesStayLegal() throws {
        let img = image(words: [btiC, pacibsp, nop])
        // Ten AppleCredentialManager methods on RC have zero direct branch
        // references and are reached only through a taken address. Writing the
        // two-word stub at the entry would remove their only legal target.
        XCTAssertEqual(ARM64.stubStart(atEntry: 0x4000, in: img), 0x4004)
    }

    func testStubStartIsIdentityWithoutLandingPad() throws {
        let img = image(words: [pacibsp, nop, nop])
        XCTAssertEqual(ARM64.stubStart(atEntry: 0x4000, in: img), 0x4000)
    }

    func testBareBTIStartingAPACLessLeafIsNotTreatedAsAPad() throws {
        // bti c ; cbz x1, <end> ; mov w0, #0 -- the shape of
        // performLoggingLevelQueryGated. Here the BTI is the function's own
        // first instruction, not a pad in front of a prologue. Skipping it
        // would shift the two-word stub into the body and, on beta 4, break
        // byte-for-byte agreement with the independent Python reference.
        let cbz: UInt32 = 0xB400_00C1
        let movW0Zero: UInt32 = 0x5280_0000
        let img = image(words: [btiC, cbz, movW0Zero, nop])
        XCTAssertEqual(ARM64.stubStart(atEntry: 0x4000, in: img), 0x4000)
    }

    func testPadIsOnlyRecognisedInFrontOfAPrologue() throws {
        let padded = image(words: [btiC, pacibsp, nop])
        let bare = image(words: [btiC, nop, nop])
        XCTAssertEqual(ARM64.stubStart(atEntry: 0x4000, in: padded), 0x4004)
        XCTAssertEqual(ARM64.stubStart(atEntry: 0x4000, in: bare), 0x4000)
    }

    func testStubStartAndFunctionEntryAgreeOnPadlessBuilds() throws {
        // On beta 4 the two questions have the same answer, which is why that
        // build is unaffected by either change.
        let img = image(words: [nop, pacibsp, nop])
        let entry = ARM64.functionEntry(forPrologue: 0x4004, in: img)
        XCTAssertEqual(entry, 0x4004)
        XCTAssertEqual(ARM64.stubStart(atEntry: entry, in: img), entry)
    }
}

/// `allowDataLayoutDrift` must tolerate a global moving between builds without
/// tolerating a different instruction.
final class MaskedInstructionPatternDriftTests: XCTestCase {
    // adrp x8, <page> ; add x8, x8, #0x1f0 ; ldp x9, x8, [x8]
    private let beta4 = [UInt32(0xB0FE_C908), 0x9107_C108, 0xA940_2109]
    // The same three instructions in RC, with the global on another page and at
    // another in-page offset: adrp x8, <other page> ; add x8, x8, #0xd0 ; ldp.
    private let release = [UInt32(0xD0FE_CCA8), 0x9103_4108, 0xA940_2109]

    private func image(_ words: [UInt32]) -> BinaryImage {
        var data = Data()
        for word in words {
            data.append(contentsOf: withUnsafeBytes(of: word.littleEndian, Array.init))
        }
        return BinaryImage(data: data)
    }

    func testAddImmediateDriftIsToleratedWhenDriftIsAllowed() throws {
        let pattern = MaskedInstructionPattern(
            name: "current_thread_ro global",
            referenceWords: beta4,
            allowDataLayoutDrift: true
        )
        XCTAssertTrue(try pattern.matches(in: image(release), at: 0))
        XCTAssertTrue(try pattern.matches(in: image(beta4), at: 0))
    }

    func testAddImmediateDriftIsRejectedWhenDriftIsNotAllowed() throws {
        let pattern = MaskedInstructionPattern(
            name: "current_thread_ro global",
            referenceWords: beta4,
            allowDataLayoutDrift: false
        )
        XCTAssertFalse(try pattern.matches(in: image(release), at: 0))
        XCTAssertTrue(try pattern.matches(in: image(beta4), at: 0))
    }

    func testDriftDoesNotTolerateADifferentRegister() throws {
        // add x9, x8, #0xd0 -- destination register changed, not just the
        // offset. Relaxing this would stop the signature describing a shape.
        let wrongRegister = [UInt32(0xD0FE_CCA8), 0x9103_4109, 0xA940_2109]
        let pattern = MaskedInstructionPattern(
            name: "current_thread_ro global",
            referenceWords: beta4,
            allowDataLayoutDrift: true
        )
        XCTAssertFalse(try pattern.matches(in: image(wrongRegister), at: 0))
    }

    func testDriftDoesNotTolerateAShiftedAdd() throws {
        // add x8, x8, #0xd0, lsl #12 -- the sh bit is part of the opcode field
        // the mask keeps, so a shifted ADD must not satisfy an unshifted one.
        let shifted = [UInt32(0xD0FE_CCA8), 0x9143_4108, 0xA940_2109]
        let pattern = MaskedInstructionPattern(
            name: "current_thread_ro global",
            referenceWords: beta4,
            allowDataLayoutDrift: true
        )
        XCTAssertFalse(try pattern.matches(in: image(shifted), at: 0))
    }
}

/// The post-validation compare is the one patch whose replacement depends on
/// which way the build's branch falls.
final class AMFIPostValidationPolarityTests: XCTestCase {
    private func image(_ words: [UInt32]) -> BinaryImage {
        var data = Data()
        for word in words {
            data.append(contentsOf: withUnsafeBytes(of: word.littleEndian, Array.init))
        }
        return BinaryImage(data: data)
    }

    func testBeta4ShapeForcesTheComparisonEqual() throws {
        // Fallthrough after the B.NE is the accept path: an authenticated vtable
        // dispatch. ldr x16,[x25]; mov x17,x25; movk; autda; mov x17,#0x138; add
        let accept: [UInt32] = [
            0x5400_0561,                                    // b.ne <reject>
            0xF940_0330, 0xAA19_03F1, 0xF2F9_B431,
            0xDAC1_1A30, 0xD280_2711, 0x8B11_0210,
        ]
        let img = image(accept)
        XCTAssertFalse(try KernelAMFIResolver.fallthroughBuildsDiagnostic(after: 0, in: img))

        let replacement = try KernelAMFIResolver.postValidationReplacement(
            compare: 0x7100_081F,            // cmp w0, #2
            rejectsOnFallthrough: false
        )
        XCTAssertEqual(replacement, 0x6B00_001F) // cmp w0, w0 -- Z always set
    }

    func testReleaseShapeForcesTheComparisonUnequal() throws {
        // Fallthrough after the B.NE is the reject path: store, materialize a
        // format string, branch to the shared logging tail.
        let reject: [UInt32] = [
            0x5400_00A1,                                    // b.ne <accept>
            0xF900_03F6,                                    // str x22,[sp]
            0xB0FF_3A43,                                    // adrp x3, <page>
            0x9126_C463,                                    // add  x3, x3, #0x9b1
            0x1400_002A,                                    // b    <tail>
            0xF940_0330, 0xAA19_03F1,
        ]
        let img = image(reject)
        XCTAssertTrue(try KernelAMFIResolver.fallthroughBuildsDiagnostic(after: 0, in: img))

        let replacement = try KernelAMFIResolver.postValidationReplacement(
            compare: 0x7100_041F,            // cmp w0, #1
            rejectsOnFallthrough: true
        )
        // cmp wzr, #1 -- 0 minus 1 leaves Z clear, so the B.NE always fires.
        XCTAssertEqual(replacement, 0x7100_07FF)
        XCTAssertEqual(replacement >> 5 & 0x1F, 31, "Rn must become the zero register")
        XCTAssertEqual(replacement >> 10 & 0xFFF, 1, "the immediate must be preserved")
    }

    func testBeta4ReplacementAppliedToTheReleaseShapeWouldInvertThePatch() throws {
        // Guards the actual hazard: beta 4's word sets Z, so the B.NE is never
        // taken. On RC the fallthrough is the rejection block, so reusing it
        // would refuse every binary rather than accept them.
        let beta4Replacement = try KernelAMFIResolver.postValidationReplacement(
            compare: 0x7100_081F,
            rejectsOnFallthrough: false
        )
        let releaseReplacement = try KernelAMFIResolver.postValidationReplacement(
            compare: 0x7100_041F,
            rejectsOnFallthrough: true
        )
        XCTAssertNotEqual(beta4Replacement, releaseReplacement)
    }

    func testZeroImmediateCannotBeForcedUnequal() throws {
        // cmp w0, #0 has no CMP WZR form that is guaranteed unequal, so this
        // must fail loudly rather than emit a word that does nothing.
        XCTAssertThrowsError(
            try KernelAMFIResolver.postValidationReplacement(
                compare: 0x7100_001F,
                rejectsOnFallthrough: true
            )
        )
    }
}
