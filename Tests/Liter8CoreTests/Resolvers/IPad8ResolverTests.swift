import Foundation
import XCTest
@testable import Liter8Core

final class IPad8ResolverTests: XCTestCase {
    func testIdentityPreservesEachPlatformAndRejectsInconsistentCopies() throws {
        for platform in ["T8020", "T8030"] {
            let source = Data(("/RELEASE_ARM64_\(platform)\0padding/RELEASE_ARM64_\(platform)\0").utf8)
            let image = BinaryImage(data: source)
            let records = try KernelIdentityResolver().resolve(in: image)
            let result = try GuardedPatchApplier.apply(records, to: image)
            XCTAssertEqual(result.data, Data(("/PATCHED_ARM64_\(platform)\0padding/PATCHED_ARM64_\(platform)\0").utf8))
            XCTAssertEqual(result.data.count, source.count)
        }
        for source in [
            "/RELEASE_ARM64_T8020\0/RELEASE_ARM64_T8030\0",
            "/RELEASE_ARM64_T8020\0",
            "/RELEASE_ARM64_T8020\0/RELEASE_ARM64_T8020\0/RELEASE_ARM64_T8020\0",
            "/RELEASE_ARM64_\0/RELEASE_ARM64_\0",
            "/RELEASE_ARM64_T8020\0/RELEASE_ARM64_T8020",
        ] {
            XCTAssertThrowsError(try KernelIdentityResolver().resolve(in: BinaryImage(data: Data(source.utf8))))
        }
    }

    func testValeriaOmissionRequiresTheExactExperimentalKernelProfile() throws {
        let ipad = try XCTUnwrap(KernelResolverProfileRegistry.profiles.first { $0.covers(build: "23H30") })
        XCTAssertTrue(try KernelValeriaResolver.requiredRecords(
            in: BinaryImage(data: Data((ipad.embeddedFingerprint + "\0").utf8))
        ).isEmpty)
        // Unknown inputs must still attempt the upstream resolver and reject
        // absent semantic evidence instead of silently omitting the repair.
        XCTAssertThrowsError(try KernelValeriaResolver.requiredRecords(in: BinaryImage(data: Data())))
        XCTAssertThrowsError(try KernelPPLTrustCacheResolver().resolve(in: BinaryImage(data: Data())))
    }

    func testBootArgumentsAcceptSPAndFramePointerStackBuffers() throws {
        for destination: UInt32 in [0x9100_03E0, 0xD100_03A0] {
            let image = try bootArgsImage(destinations: [destination])
            let records = try IBSSBootArgsResolver(bootArguments: "-v").resolve(in: image)
            XCTAssertEqual(records.count, 3)
            XCTAssertEqual(records[0].offset, 0x100)
            _ = try GuardedPatchApplier.apply(records, to: image)
        }
    }

    func testBootArgumentsRejectDuplicateCallsWrongDestinationAndWrongCapacity() throws {
        let ambiguous = try bootArgsImage(destinations: [0x9100_03E0, 0xD100_03A0])
        XCTAssertThrowsError(try IBSSBootArgsResolver().resolve(in: ambiguous))
        let wrongDestination = try bootArgsImage(destinations: [0xD100_0380]) // SUB X0,X28,#0
        XCTAssertThrowsError(try IBSSBootArgsResolver().resolve(in: wrongDestination))
        var wrongCapacity = try bootArgsImage(destinations: [0xD100_03A0]).data
        write(0x5280_4001, to: &wrongCapacity, at: 0x10C) // MOV W1,#0x200
        XCTAssertThrowsError(try IBSSBootArgsResolver().resolve(in: BinaryImage(data: wrongCapacity)))
    }

    private func bootArgsImage(destinations: [UInt32]) throws -> BinaryImage {
        var data = Data(repeating: 0xAA, count: 0x4000)
        data.replaceSubrange(0x2E00..<0x3000, with: Data(repeating: 0, count: 0x200))
        data.replaceSubrange(0x5FF..<0x603, with: Data([0, 0x25, 0x73, 0])) // isolated %s
        for (index, destination) in destinations.enumerated() {
            let offset = UInt64(0x100 + index * 0x80)
            let words = [
                try XCTUnwrap(ARM64.encodeADRP(register: 2, instructionOffset: offset, target: 0x600)),
                try XCTUnwrap(ARM64.encodeAddImmediate(destination: 2, source: 2, immediate: 0x600)),
                destination,
                UInt32(0x5280_8001), // MOV W1,#0x400
                try XCTUnwrap(ARM64.encodeDirectBranch(link: true, instructionOffset: offset + 16, target: 0x900)),
            ]
            for (wordIndex, word) in words.enumerated() {
                write(word, to: &data, at: Int(offset) + wordIndex * 4)
            }
        }
        return BinaryImage(data: data)
    }

    private func write(_ word: UInt32, to data: inout Data, at offset: Int) {
        var encoded = word.littleEndian
        withUnsafeBytes(of: &encoded) { data.replaceSubrange(offset..<(offset + 4), with: $0) }
    }
}
