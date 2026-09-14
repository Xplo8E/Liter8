import Foundation
import XCTest
@testable import Liter8Core

final class BinaryImageTests: XCTestCase {
    func testIntegerReadsAreLittleEndianAndMayBeUnaligned() throws {
        let image = BinaryImage(data: Data([0xAA, 0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90]))

        XCTAssertEqual(try image.readUInt32(at: 1), 0x1234_5678)
        XCTAssertEqual(try image.readUInt64(at: 1), 0x90AB_CDEF_1234_5678)
    }

    func testIntegerReadsAcceptTheLastCompleteWord() throws {
        let image = BinaryImage(data: Data([0x78, 0x56, 0x34, 0x12]))

        XCTAssertEqual(try image.readUInt32(at: 0), 0x1234_5678)
    }

    func testIntegerReadsRejectTruncatedAndOversizedOffsets() {
        let image = BinaryImage(data: Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try image.readUInt32(at: 5))
        XCTAssertThrowsError(try image.readUInt64(at: 1))
        XCTAssertThrowsError(try image.readUInt32(at: UInt64.max))
    }
}
