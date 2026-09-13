import Foundation

/// One Objective-C method recovered from a modern relative method list.
struct ObjCMethod: Hashable, Sendable {
    let selector: String
    let entryOffset: UInt64
    let implementationOffset: UInt64
    let implementationAddress: UInt64
}

/// An Objective-C message-send stub bound to one selector reference.
struct ObjCSelectorStub: Hashable, Sendable {
    let selectorReferenceOffset: UInt64
    let stubOffset: UInt64
    let stubAddress: UInt64
}

/// Minimal Objective-C metadata reader for Apple's arm64e executables.
///
/// We need two facts, not a full class-dump implementation:
///
/// - which implementation belongs to a named selector;
/// - which optimized `objc_msgSend$selector` stub loads that selector.
///
/// Current Apple binaries encode method fields as signed 32-bit relative
/// pointers and selector references as dyld chained rebases. Resolving both is
/// materially stronger than searching for the selector text and assuming a
/// nearby function is related to it.
struct ObjCMetadata: Sendable {
    let image: BinaryImage
    let layout: MachOLayout

    init(image: BinaryImage) throws {
        self.image = image
        self.layout = try MachOLayout(image: image)
    }

    func methods(named selector: String) throws -> [ObjCMethod] {
        guard let methodList = layout.section(segment: "__TEXT", named: "__objc_methlist") else {
            throw PatchfinderError.invalidFixture("Mach-O has no __TEXT,__objc_methlist")
        }
        let references = try selectorReferences(named: selector)
        let referenceAddresses = Set(references.compactMap { offset in
            layout.virtualAddress(forFileOffset: offset)
        })
        guard !referenceAddresses.isEmpty else {
            throw PatchfinderError.missingAnchor(selector)
        }

        var matches: [ObjCMethod] = []
        var entryOffset = (methodList.fileRange.lowerBound + 3) & ~UInt64(3)
        while entryOffset + 12 <= methodList.fileRange.upperBound {
            let nameDelta = Int32(bitPattern: try image.readUInt32(at: entryOffset))
            guard let nameFieldAddress = layout.virtualAddress(forFileOffset: entryOffset),
                  let nameTarget = adding(nameDelta, to: nameFieldAddress),
                  referenceAddresses.contains(nameTarget)
            else {
                entryOffset += 4
                continue
            }

            // The implementation displacement is relative to its own field,
            // not to the beginning of the 12-byte method entry.
            let implementationField = entryOffset + 8
            let implementationDelta = Int32(
                bitPattern: try image.readUInt32(at: implementationField)
            )
            guard let fieldAddress = layout.virtualAddress(forFileOffset: implementationField),
                  let implementationAddress = adding(implementationDelta, to: fieldAddress),
                  let implementationOffset = layout.fileOffset(
                    forVirtualAddress: implementationAddress
                  ),
                  layout.executableFileRanges.contains(where: { $0.contains(implementationOffset) })
            else {
                entryOffset += 4
                continue
            }

            matches.append(.init(
                selector: selector,
                entryOffset: entryOffset,
                implementationOffset: implementationOffset,
                implementationAddress: implementationAddress
            ))
            entryOffset += 4
        }
        return Array(Set(matches)).sorted { $0.implementationOffset < $1.implementationOffset }
    }

    func selectorStubs(named selector: String) throws -> [ObjCSelectorStub] {
        guard let stubs = layout.section(segment: "__TEXT", named: "__objc_stubs") else {
            throw PatchfinderError.invalidFixture("Mach-O has no __TEXT,__objc_stubs")
        }
        let references = try selectorReferences(named: selector)
        let referencesByAddress = Dictionary(uniqueKeysWithValues: references.compactMap { offset in
            layout.virtualAddress(forFileOffset: offset).map { ($0, offset) }
        })

        var matches: [ObjCSelectorStub] = []
        var offset = (stubs.fileRange.lowerBound + 3) & ~UInt64(3)
        while offset + 8 <= stubs.fileRange.upperBound {
            let adrp = try image.readUInt32(at: offset)
            let load = try image.readUInt32(at: offset + 4)

            // Optimized Objective-C stubs begin by loading the selector into
            // X1. Preserve the page immediate and LDR offset as wildcards, but
            // require both destination and base registers to be X1.
            guard adrp & 0x9F00_001F == 0x9000_0001, // ADRP X1,<page>
                  load & 0xFFC0_03FF == 0xF940_0021, // LDR X1,[X1,#imm]
                  let instructionAddress = layout.virtualAddress(forFileOffset: offset)
            else {
                offset += 4
                continue
            }
            let referenceAddress = ARM64.adrpTarget(
                instruction: adrp,
                at: instructionAddress
            ) + UInt64((load >> 10) & 0xFFF) * 8
            guard let referenceOffset = referencesByAddress[referenceAddress] else {
                offset += 4
                continue
            }
            matches.append(.init(
                selectorReferenceOffset: referenceOffset,
                stubOffset: offset,
                stubAddress: instructionAddress
            ))
            offset += 4
        }
        return Array(Set(matches)).sorted { $0.stubOffset < $1.stubOffset }
    }

    /// Find selector-reference slots whose chained rebase resolves to the exact
    /// selector string in `__objc_methname`.
    private func selectorReferences(named selector: String) throws -> [UInt64] {
        guard let methodNames = layout.section(segment: "__TEXT", named: "__objc_methname"),
              let selectorReferences = layout.section(segment: "__DATA", named: "__objc_selrefs")
        else {
            throw PatchfinderError.invalidFixture("Mach-O lacks Objective-C selector sections")
        }

        let stringOffsets = image.findAll(utf8: selector, nulTerminated: true)
            .filter { methodNames.fileRange.contains($0) }
        guard !stringOffsets.isEmpty else { throw PatchfinderError.missingAnchor(selector) }
        let stringAddresses = Set(stringOffsets.compactMap { offset in
            layout.virtualAddress(forFileOffset: offset)
        })
        guard stringAddresses.count == stringOffsets.count else {
            throw PatchfinderError.invalidFixture("selector string is not mapped")
        }

        var matches: [UInt64] = []
        var offset = selectorReferences.fileRange.lowerBound
        while offset + 8 <= selectorReferences.fileRange.upperBound {
            if let target = try chainedRebaseTarget(at: offset),
               stringAddresses.contains(target) {
                matches.append(offset)
            }
            offset += 8
        }
        return matches
    }

    /// Decode the rebase forms of `DYLD_CHAINED_PTR_ARM64E` used by local
    /// selector references. Bind entries are intentionally rejected: a local
    /// selector name must point back into this image, not an imported symbol.
    /// Resolve a local dyld chained rebase. Exposed inside the module because
    /// CFString objects use the same pointer format for their C-string field.
    func chainedRebaseTarget(at offset: UInt64) throws -> UInt64? {
        let raw = try image.readUInt64(at: offset)
        let isAuthenticated = raw & (UInt64(1) << 63) != 0
        let isBind = raw & (UInt64(1) << 62) != 0
        guard !isBind else { return nil }

        guard let imageBase = layout.segments
            .filter({ $0.fileSize != 0 })
            .map(\.virtualAddress)
            .min()
        else { return nil }

        // Authenticated rebases carry a 32-bit target; unauthenticated rebases
        // carry 43 target bits. `next`, diversity and high8 are deliberately
        // masked away instead of accidentally becoming part of the address.
        let target = isAuthenticated
            ? raw & 0xFFFF_FFFF
            : raw & 0x7FF_FFFF_FFFF
        let address = imageBase + target
        return layout.fileOffset(forVirtualAddress: address) == nil ? nil : address
    }

    private func adding(_ displacement: Int32, to address: UInt64) -> UInt64? {
        guard address <= UInt64(Int64.max) else { return nil }
        let result = Int64(address) + Int64(displacement)
        return result >= 0 ? UInt64(result) : nil
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
