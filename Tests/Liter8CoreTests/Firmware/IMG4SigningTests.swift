import Foundation
import Testing
@testable import Liter8Core

@Suite("IMG4Signing")
struct IMG4SigningTests {
    @Test func wrapsAndRetagsIM4PWithTicket() throws {
        let im4p = Data([
            0x30, 0x17,
            0x16, 0x04, 0x49, 0x4d, 0x34, 0x50, // "IM4P"
            0x16, 0x04, 0x69, 0x62, 0x65, 0x63, // "ibec"
            0x16, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
            0x04, 0x03, 0x61, 0x62, 0x63,       // payload "abc"
        ])
        let im4m = Data([
            0x30, 0x09,
            0x16, 0x04, 0x49, 0x4d, 0x34, 0x4d, // "IM4M"
            0x02, 0x01, 0x00,
        ])

        let output = try IMG4Signing.create(
            im4pData: im4p,
            im4mData: im4m,
            fourcc: "rkrn"
        )

        #expect(output.starts(with: [0x30]))
        #expect(output.range(of: Data("IMG4".utf8)) != nil)
        #expect(output.range(of: Data("rkrn".utf8)) != nil)
        #expect(output.range(of: Data("IM4M".utf8)) != nil)
    }

    @Test func rejectsNonFourCCOverride() {
        #expect(throws: Error.self) {
            try IMG4Signing.create(
                im4pData: Data(),
                im4mData: Data(),
                fourcc: "kernel"
            )
        }
    }
}
