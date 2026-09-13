import Foundation
import Img4tool

/// Identifies whether an input was a bare component payload or an IM4P.
public enum FirmwareArtifactKind: String, Sendable {
    case raw
    case im4p
}

/// A component payload together with the container needed to rebuild it.
///
/// Resolvers intentionally operate only on `payload`, so their offsets remain
/// offsets in the decompressed firmware component. When an IM4P was supplied,
/// `encoded(replacingPayloadWith:)` wraps the patched bytes back into a fresh
/// IM4P carrying the original fourcc and description.
public struct FirmwareArtifact: Sendable {
    public let kind: FirmwareArtifactKind
    public let payload: Data
    public let fourcc: String?
    public let containerDescription: String?

    private let originalIM4P: IM4P?

    public init(data: Data) throws {
        if let im4p = try? IM4P(data) {
            kind = .im4p
            // The vendor can return an uncompressed DER OCTET STRING as a
            // Data slice whose startIndex is the offset inside the container.
            // Materialize a fresh zero-based Data value before handing it to
            // parsers and resolvers, all of which use payload-relative offsets.
            payload = Data(try im4p.payload())
            fourcc = im4p.fourcc
            containerDescription = im4p.description
            originalIM4P = im4p
        } else {
            kind = .raw
            payload = data
            fourcc = nil
            containerDescription = nil
            originalIM4P = nil
        }
    }

    public init(contentsOf url: URL) throws {
        try self.init(data: Data(contentsOf: url, options: [.mappedIfSafe]))
    }

    /// Rebuild the input representation around a replacement payload.
    /// Bare inputs stay bare; IM4P inputs stay IM4P.
    public func encoded(replacingPayloadWith replacement: Data) throws -> Data {
        guard let originalIM4P else { return replacement }

        // The reviewed beta-4 tooling writes patched firmware components back
        // uncompressed. We preserve the semantic container identity and, for
        // kernel/TXM images, the PAYP metadata tail used by the boot chain.
        let rebuilt = try IM4P(
            fourcc: originalIM4P.fourcc,
            description: originalIM4P.description,
            payload: replacement
        )
        guard Self.paypFourCCs.contains(originalIM4P.fourcc) else {
            return rebuilt.data
        }
        return try Self.appendPAYPIfPresent(from: originalIM4P.data, to: rebuilt.data)
    }

    /// DeviceTree commands must not silently accept a different kind of IM4P.
    /// Raw payloads have no container tag, so their structural parser remains
    /// the identity check in that mode.
    public func requireIM4PFourCC(_ expected: String) throws {
        guard kind == .im4p else { return }
        guard fourcc == expected else {
            throw PatchfinderError.invalidFirmwareContainer(
                "expected IM4P fourcc \(expected), found \(fourcc ?? "unknown")"
            )
        }
    }

    private static let paypFourCCs: Set<String> = ["krnl", "rkrn", "trxm"]

    /// libimg4 rebuilds the DER sequence itself. PAYP is an Apple extension
    /// appended after the ordinary IM4P children, so copy it from the shipped
    /// container and grow the outer DER length to include it.
    private static func appendPAYPIfPresent(from original: Data, to rebuilt: Data) throws -> Data {
        let marker = Data("PAYP".utf8)
        guard let markerRange = original.range(of: marker, options: .backwards),
              markerRange.lowerBound >= 10
        else {
            return rebuilt
        }

        let tail = original[(markerRange.lowerBound - 10)..<original.endIndex]
        var output = rebuilt
        try updateTopLevelDERLength(of: &output, adding: tail.count)
        output.append(tail)
        return output
    }

    private static func updateTopLevelDERLength(of data: inout Data, adding extraBytes: Int) throws {
        guard data.count >= 2, data[0] == 0x30 else {
            throw PatchfinderError.invalidFirmwareContainer("rebuilt IM4P has no DER sequence")
        }

        let firstLengthByte = data[1]
        let lengthRange: Range<Int>
        let oldLength: Int
        if firstLengthByte & 0x80 == 0 {
            lengthRange = 1..<2
            oldLength = Int(firstLengthByte)
        } else {
            let byteCount = Int(firstLengthByte & 0x7f)
            guard byteCount > 0, 2 + byteCount <= data.count else {
                throw PatchfinderError.invalidFirmwareContainer("malformed outer DER length")
            }
            lengthRange = 1..<(2 + byteCount)
            oldLength = data[2..<(2 + byteCount)].reduce(0) { ($0 << 8) | Int($1) }
        }
        data.replaceSubrange(lengthRange, with: derLength(oldLength + extraBytes))
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }

        var remaining = length
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.append(UInt8(remaining & 0xff))
            remaining >>= 8
        }
        bytes.reverse()
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
