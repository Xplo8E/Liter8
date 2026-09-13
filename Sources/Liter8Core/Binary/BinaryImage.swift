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
        guard count >= 0,
              offset <= UInt64(data.count),
              UInt64(count) <= UInt64(data.count) - offset
        else {
            throw PatchfinderError.outOfBounds(offset: offset, length: count)
        }
        let start = Int(offset)
        return data.subdata(in: start..<(start + count))
    }

    public func readUInt32(at offset: UInt64) throws -> UInt32 {
        let value = try bytes(at: offset, count: 4)
        return value.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(as: UInt32.self))
        }
    }

    public func readUInt64(at offset: UInt64) throws -> UInt64 {
        let value = try bytes(at: offset, count: 8)
        return value.withUnsafeBytes { raw in
            UInt64(littleEndian: raw.loadUnaligned(as: UInt64.self))
        }
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
