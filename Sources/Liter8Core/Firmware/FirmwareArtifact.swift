import Compression
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

        // Preserve the original compression format and its DER metadata. This
        // keeps a T8020 kernel in the representation expected by its boot chain;
        // ticket validation is a separate check performed by iBEC.
        let compression = try Self.compressionMode(of: originalIM4P.data)
        let rebuilt: IM4P
        if compression == "lzfse" {
            rebuilt = try Self.ibootLZFSEContainer(originalIM4P, payload: replacement)
        } else {
            rebuilt = try IM4P(
                fourcc: originalIM4P.fourcc,
                description: originalIM4P.description,
                payload: replacement,
                compression: compression
            )
        }
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

    /// iBoot uses the restricted LZFSE decoder (0x891). A stream produced by
    /// COMPRESSION_LZFSE (0x801) can round-trip on macOS yet fail in iBoot with
    /// error 0x40040028. Keep this firmware policy here, outside the pinned
    /// general-purpose IMG4 dependency. There is deliberately no 0x801 fallback.
    private static func ibootLZFSEContainer(_ original: IM4P, payload: Data) throws -> IM4P {
        guard !payload.isEmpty else {
            throw PatchfinderError.invalidFirmwareContainer("cannot compress an empty firmware payload")
        }
        let algorithm = compression_algorithm(rawValue: 0x891)
        let capacity = max(payload.count + payload.count / 8 + 1024, 4096)
        var compressed = Data(count: capacity)
        let size = compressed.withUnsafeMutableBytes { destination in
            payload.withUnsafeBytes { source in
                compression_encode_buffer(
                    destination.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    source.bindMemory(to: UInt8.self).baseAddress!, payload.count,
                    nil, algorithm
                )
            }
        }
        guard size > 0 else {
            throw PatchfinderError.invalidFirmwareContainer("iBoot-compatible LZFSE compression failed")
        }
        compressed.count = size

        // Use the device's decoder variant, with an extra byte to detect a
        // stream that would otherwise be silently truncated to the buffer size.
        var decoded = Data(count: payload.count + 1)
        let decodedCapacity = decoded.count
        let decodedSize = decoded.withUnsafeMutableBytes { destination in
            compressed.withUnsafeBytes { source in
                compression_decode_buffer(
                    destination.bindMemory(to: UInt8.self).baseAddress!, decodedCapacity,
                    source.bindMemory(to: UInt8.self).baseAddress!, compressed.count,
                    nil, algorithm
                )
            }
        }
        guard decodedSize == payload.count, decoded.prefix(decodedSize) == payload else {
            throw PatchfinderError.invalidFirmwareContainer("iBoot LZFSE verification failed")
        }

        var container = try IM4P(
            fourcc: original.fourcc, description: original.description,
            payload: compressed
        ).data
        // IM4P compression descriptor: SEQUENCE { INTEGER 1, INTEGER size }.
        var sizeBytes = withUnsafeBytes(of: UInt64(payload.count).bigEndian) { Data($0) }
        while sizeBytes.count > 1, sizeBytes.first == 0 { sizeBytes.removeFirst() }
        if sizeBytes.first! & 0x80 != 0 { sizeBytes.insert(0, at: 0) }
        let fields = Data([0x02, 0x01, 0x01, 0x02]) + derLength(sizeBytes.count) + sizeBytes
        let descriptor = Data([0x30]) + derLength(fields.count) + fields
        try updateTopLevelDERLength(of: &container, adding: descriptor.count)
        container.append(descriptor)
        return try IM4P(container)
    }

    /// libimg4 rebuilds the DER sequence itself. Copy the complete PAYP DER
    /// child from the shipped container; searching ten bytes before its text
    /// marker borrowed two bytes of compression metadata on the T8020 kernel.
    private static func appendPAYPIfPresent(from original: Data, to rebuilt: Data) throws -> Data {
        let children = try topLevelChildren(in: original)
        guard let payp = children.dropFirst(4).first(where: { field in
            original[field.lowerBound] == 0xA0
                && original[field].range(of: Data("PAYP".utf8)) != nil
        }) else {
            return rebuilt
        }

        let tail = original[payp]
        var output = rebuilt
        try updateTopLevelDERLength(of: &output, adding: tail.count)
        output.append(tail)
        return output
    }

    private static func compressionMode(of original: Data) throws -> String? {
        let children = try topLevelChildren(in: original)
        guard children.count >= 4, original[children[3].lowerBound] == 0x04 else {
            throw PatchfinderError.invalidFirmwareContainer("IM4P has no payload OCTET STRING")
        }
        let payload = try derValueRange(in: original, at: children[3].lowerBound)
        if original[payload].starts(with: Data("bvx2".utf8)) { return "lzfse" }
        if original[payload].starts(with: Data("complzss".utf8)) { return "lzss" }
        return nil
    }

    private static func topLevelChildren(in data: Data) throws -> [Range<Int>] {
        guard data.count >= 2, data[0] == 0x30 else {
            throw PatchfinderError.invalidFirmwareContainer("IM4P has no DER sequence")
        }
        let body = try derValueRange(in: data, at: 0)
        guard body.upperBound == data.count else {
            throw PatchfinderError.invalidFirmwareContainer("IM4P has trailing DER data")
        }
        var fields: [Range<Int>] = []
        var cursor = body.lowerBound
        while cursor < body.upperBound {
            let value = try derValueRange(in: data, at: cursor)
            fields.append(cursor..<value.upperBound)
            cursor = value.upperBound
        }
        return fields
    }

    private static func derValueRange(in data: Data, at offset: Int) throws -> Range<Int> {
        guard offset >= 0, offset + 2 <= data.count else {
            throw PatchfinderError.invalidFirmwareContainer("truncated DER field")
        }
        let first = data[offset + 1]
        let header: Int
        let length: Int
        if first < 0x80 {
            header = 2
            length = Int(first)
        } else {
            let count = Int(first & 0x7F)
            guard count > 0, count <= 4, offset + 2 + count <= data.count else {
                throw PatchfinderError.invalidFirmwareContainer("malformed DER field length")
            }
            header = 2 + count
            length = data[(offset + 2)..<(offset + header)].reduce(0) { ($0 << 8) | Int($1) }
        }
        guard length <= data.count - offset - header else {
            throw PatchfinderError.invalidFirmwareContainer("DER field exceeds IM4P")
        }
        return (offset + header)..<(offset + header + length)
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
