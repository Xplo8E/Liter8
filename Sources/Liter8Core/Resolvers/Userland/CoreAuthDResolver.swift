import Foundation

/// Skips coreauthd's call to `-[... startController]` whose completion path
/// enters the SEP-backed DTO ratchet parser.
///
/// The original beta-4 offset came from a device crash report, but crash PCs
/// are not a generalized locator. Here we resolve the `startController`
/// selector through Objective-C metadata, identify its optimized message-send
/// stub, then require exactly one direct caller in executable code. The next
/// instruction must reload X0 from `[SP,#8]`, matching the crash backtrace's
/// recorded return address and guarding against a different call to the same
/// selector in a future build.
public struct CoreAuthDResolver: Sendable {
    public static let name = "coreauthd"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let metadata = try ObjCMetadata(image: image)
        let stubs = try metadata.selectorStubs(named: "startController")
        guard let stub = stubs.only else {
            if stubs.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) selector stub") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) selector stub",
                offsets: stubs.map(\.stubOffset)
            )
        }

        var callers: [UInt64] = []
        for range in metadata.layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 8 <= range.upperBound {
                let call = try image.readUInt32(at: offset)
                guard let callAddress = metadata.layout.virtualAddress(forFileOffset: offset),
                      ARM64.branchLinkTarget(instruction: call, at: callAddress) == stub.stubAddress,
                      try image.readUInt32(at: offset + 4) == 0xF940_07E0 // LDR X0,[SP,#8]
                else {
                    offset += 4
                    continue
                }
                callers.append(offset)
                offset += 4
            }
        }

        guard let callOffset = callers.only else {
            if callers.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: callers)
        }
        return [
            PatchRecord(
                id: "coreauthd.dto-ratchet.start-controller",
                component: "coreauthd",
                offset: callOffset,
                original: try image.readUInt32(at: callOffset),
                replacement: ARM64.nop,
                summary: "Skip the SEP-dependent DTO ratchet controller startup",
                evidence: [
                    "unique startController selector and Objective-C selector reference",
                    "optimized objc_msgSend selector stub at \(stub.stubOffset.hex)",
                    "unique BL caller followed by LDR X0,[SP,#8] at crash return address",
                ]
            ),
        ]
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
