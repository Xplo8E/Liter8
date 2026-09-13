import Foundation

public enum PatchfinderError: Error, Equatable, CustomStringConvertible {
    case outOfBounds(offset: UInt64, length: Int)
    case missingAnchor(String)
    case ambiguousAnchor(String, count: Int)
    case noCandidate(String)
    case ambiguousCandidate(String, offsets: [UInt64])
    case invalidFixture(String)
    case fixtureMismatch(String)
    case invalidPatch(id: String, reason: String)
    case overlappingPatches(offset: UInt64)
    case preimageMismatch(id: String, offset: UInt64, expected: Data, found: Data)
    case disassemblyFailed(offset: UInt64, length: Int)
    case unsupportedFirmwareProfile(resolver: String, profile: String, variant: String)
    case invalidDeviceTree(String)
    case deviceTreeVerificationFailed(String)
    case invalidFirmwareContainer(String)

    public var description: String {
        switch self {
        case let .outOfBounds(offset, length):
            "read outside image at \(offset.hex), length \(length)"
        case let .missingAnchor(anchor):
            "missing anchor: \(anchor)"
        case let .ambiguousAnchor(anchor, count):
            "ambiguous anchor \(anchor): \(count) matches"
        case let .noCandidate(name):
            "resolver produced no candidate: \(name)"
        case let .ambiguousCandidate(name, offsets):
            "resolver produced \(offsets.count) candidates for \(name): \(offsets.map(\.hex).joined(separator: ", "))"
        case let .invalidFixture(message):
            "invalid fixture: \(message)"
        case let .fixtureMismatch(message):
            "fixture mismatch: \(message)"
        case let .invalidPatch(id, reason):
            "invalid patch \(id): \(reason)"
        case let .overlappingPatches(offset):
            "multiple patches overlap at \(offset.hex)"
        case let .preimageMismatch(id, offset, expected, found):
            "\(id) at \(offset.hex): expected \(expected.hexadecimalString), found \(found.hexadecimalString)"
        case let .disassemblyFailed(offset, length):
            "failed to disassemble \(length) bytes at \(offset.hex)"
        case let .unsupportedFirmwareProfile(resolver, profile, variant):
            "\(resolver) does not support firmware profile \(profile) with signature variant \(variant)"
        case let .invalidDeviceTree(message):
            "invalid DeviceTree: \(message)"
        case let .deviceTreeVerificationFailed(path):
            "DeviceTree verification failed for \(path)"
        case let .invalidFirmwareContainer(message):
            "invalid firmware container: \(message)"
        }
    }
}

extension UInt64 {
    var hex: String { String(format: "0x%llx", self) }
}

extension UInt32 {
    var hex: String { String(format: "0x%08x", self) }
}
