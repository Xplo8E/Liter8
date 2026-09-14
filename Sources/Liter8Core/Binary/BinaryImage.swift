import Foundation

public struct BinaryImage: Sendable {
    public let data: Data

    public init(data: Data) {
        self.data = data
    }

    public init(contentsOf url: URL) throws {
        self.data = try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    public var count: Int { data.count }

    public func bytes(at offset: UInt64, count: Int) throws -> Data {
        let start = try checkedStart(offset: offset, length: count)
        return data.subdata(in: start..<(start + count))
    }

    public func readUInt32(at offset: UInt64) throws -> UInt32 {
        let start = try checkedStart(offset: offset, length: MemoryLayout<UInt32>.size)

        // Resolver hot loops perform millions of word reads. Loading directly
        // from the immutable backing buffer avoids allocating a four-byte Data
        // value for every instruction while remaining safe for unaligned file
        // offsets such as packed Mach-O data.
        return data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: start, as: UInt32.self))
        }
    }

    public func readUInt64(at offset: UInt64) throws -> UInt64 {
        let start = try checkedStart(offset: offset, length: MemoryLayout<UInt64>.size)

        // As above, read in place instead of manufacturing an eight-byte Data
        // object on every pointer or Mach-O field access.
        return data.withUnsafeBytes { raw in
            UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: start, as: UInt64.self))
        }
    }

    /// Validate a file range before entering an unsafe buffer closure.
    /// Returning an `Int` only after the UInt64 arithmetic is proven in-bounds
    /// also prevents a hostile offset from overflowing during conversion.
    private func checkedStart(offset: UInt64, length: Int) throws -> Int {
        guard length >= 0,
              offset <= UInt64(data.count),
              UInt64(length) <= UInt64(data.count) - offset
        else {
            throw PatchfinderError.outOfBounds(offset: offset, length: length)
        }
        return Int(offset)
    }

    public func findAll(_ needle: Data) -> [UInt64] {
        guard !needle.isEmpty, needle.count <= data.count else { return [] }

        var matches: [UInt64] = []
        var cursor = data.startIndex
        while cursor <= data.endIndex - needle.count,
              let range = data.range(of: needle, options: [], in: cursor..<data.endIndex)
        {
            matches.append(UInt64(range.lowerBound))
            cursor = range.lowerBound + 1
        }
        return matches
    }

    public func findAll(utf8 string: String, nulTerminated: Bool = false) -> [UInt64] {
        var needle = Data(string.utf8)
        if nulTerminated { needle.append(0) }
        return findAll(needle)
    }
}
