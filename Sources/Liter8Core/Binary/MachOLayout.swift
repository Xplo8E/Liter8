import Foundation

/// The small subset of `segment_command_64` needed by a patchfinder.
/// We intentionally do not build a general Mach-O library here: the resolver
/// needs only trustworthy file-offset/virtual-address conversion and executable
/// scan ranges. More format support should be added only when a fixture needs it.
struct MachOSegment: Sendable {
    let name: String
    let virtualAddress: UInt64
    let virtualSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
    let initialProtection: UInt32

    var fileRange: Range<UInt64> { fileOffset..<(fileOffset + fileSize) }
    var isExecutable: Bool { initialProtection & 0x4 != 0 }
}

/// A section is the narrowest useful unit for Objective-C metadata. Keeping
/// its segment name avoids confusing identically named sections such as
/// `__TEXT,__const` and `__DATA_CONST,__const`.
struct MachOSection: Sendable {
    let segmentName: String
    let name: String
    let virtualAddress: UInt64
    let size: UInt64
    let fileOffset: UInt64

    var fileRange: Range<UInt64> { fileOffset..<(fileOffset + size) }
}

/// Address map for a thin, little-endian, 64-bit Mach-O payload.
///
/// Why this exists: ADRP encodes a displacement from the instruction's virtual
/// page, not from its location in the file. In `asr`, for example, file offset
/// `0xa98` maps to virtual address `0x100000a98`. A raw offset-only decoder can
/// accidentally work when source and target share a segment, then fail as soon
/// as a reference crosses segments. Every Mach-O resolver goes through this map.
struct MachOLayout: Sendable {
    static let magic64: UInt32 = 0xFEED_FACF
    static let segment64: UInt32 = 0x19

    let image: BinaryImage
    let segments: [MachOSegment]
    let sections: [MachOSection]

    init(image: BinaryImage) throws {
        guard try image.readUInt32(at: 0) == Self.magic64 else {
            throw PatchfinderError.invalidFixture("expected thin little-endian Mach-O 64 payload")
        }

        let commandCount = Int(try image.readUInt32(at: 16))
        var commandOffset: UInt64 = 32
        var parsed: [MachOSegment] = []
        var parsedSections: [MachOSection] = []

        for _ in 0..<commandCount {
            let command = try image.readUInt32(at: commandOffset)
            let commandSize = UInt64(try image.readUInt32(at: commandOffset + 4))
            guard commandSize >= 8,
                  commandOffset + commandSize <= UInt64(image.count)
            else {
                throw PatchfinderError.invalidFixture("malformed Mach-O load command")
            }

            if command == Self.segment64 {
                guard commandSize >= 72 else {
                    throw PatchfinderError.invalidFixture("short LC_SEGMENT_64 command")
                }
                let rawName = try image.bytes(at: commandOffset + 8, count: 16)
                let name = String(
                    decoding: rawName.prefix { $0 != 0 },
                    as: UTF8.self
                )
                let segment = MachOSegment(
                    name: name,
                    virtualAddress: try image.readUInt64(at: commandOffset + 24),
                    virtualSize: try image.readUInt64(at: commandOffset + 32),
                    fileOffset: try image.readUInt64(at: commandOffset + 40),
                    fileSize: try image.readUInt64(at: commandOffset + 48),
                    initialProtection: try image.readUInt32(at: commandOffset + 60)
                )
                guard segment.fileOffset + segment.fileSize <= UInt64(image.count) else {
                    throw PatchfinderError.invalidFixture("segment \(name) extends past end of file")
                }
                parsed.append(segment)

                let sectionCount = Int(try image.readUInt32(at: commandOffset + 64))
                guard 72 + sectionCount * 80 <= Int(commandSize) else {
                    throw PatchfinderError.invalidFixture("section table exceeds LC_SEGMENT_64")
                }
                for index in 0..<sectionCount {
                    let sectionOffset = commandOffset + 72 + UInt64(index * 80)
                    let rawSectionName = try image.bytes(at: sectionOffset, count: 16)
                    let rawSegmentName = try image.bytes(at: sectionOffset + 16, count: 16)
                    let section = MachOSection(
                        segmentName: String(
                            decoding: rawSegmentName.prefix { $0 != 0 },
                            as: UTF8.self
                        ),
                        name: String(
                            decoding: rawSectionName.prefix { $0 != 0 },
                            as: UTF8.self
                        ),
                        virtualAddress: try image.readUInt64(at: sectionOffset + 32),
                        size: try image.readUInt64(at: sectionOffset + 40),
                        fileOffset: UInt64(try image.readUInt32(at: sectionOffset + 48))
                    )
                    // Zero-fill sections have virtual size but no bytes in the
                    // file. They are valid Mach-O metadata, just unusable for
                    // a static patchfinder, so retain only file-backed ranges.
                    if section.fileOffset + section.size <= UInt64(image.count) {
                        parsedSections.append(section)
                    }
                }
            }
            commandOffset += commandSize
        }

        guard !parsed.isEmpty else {
            throw PatchfinderError.invalidFixture("Mach-O contains no LC_SEGMENT_64 commands")
        }
        segments = parsed
        sections = parsedSections
        self.image = image
    }

    var executableFileRanges: [Range<UInt64>] {
        segments.filter(\.isExecutable).map(\.fileRange)
    }

    func virtualAddress(forFileOffset offset: UInt64) -> UInt64? {
        guard let segment = segments.first(where: { $0.fileRange.contains(offset) }) else {
            return nil
        }
        return segment.virtualAddress + (offset - segment.fileOffset)
    }

    func fileOffset(forVirtualAddress address: UInt64) -> UInt64? {
        guard let segment = segments.first(where: {
            address >= $0.virtualAddress && address < $0.virtualAddress + $0.fileSize
        }) else { return nil }
        return segment.fileOffset + (address - segment.virtualAddress)
    }

    func section(segment: String? = nil, named name: String) -> MachOSection? {
        sections.first { section in
            section.name == name && (segment == nil || section.segmentName == segment)
        }
    }

    /// Resolve code references to a concrete byte location using Mach-O virtual
    /// addresses while returning file offsets suitable for patch records.
    func adrpAddReferences(toFileOffset targetOffset: UInt64) throws -> [ADRPAddReference] {
        guard let targetAddress = virtualAddress(forFileOffset: targetOffset) else {
            throw PatchfinderError.invalidFixture(
                "target file offset \(targetOffset.hex) is outside mapped segments"
            )
        }
        return try ARM64.adrpAddReferences(
            in: image,
            to: targetAddress,
            scanRanges: executableFileRanges,
            addressForFileOffset: { offset in
                // The scan ranges above contain only mapped executable bytes.
                // Falling back would hide a malformed map, so retain the
                // impossible value and let the reference fail to match.
                virtualAddress(forFileOffset: offset) ?? UInt64.max
            }
        )
    }
}
