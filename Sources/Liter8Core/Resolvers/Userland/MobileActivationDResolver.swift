import Foundation

/// Generalizes the five beta-4 mobileactivationd patches used for offline
/// activation when the research device cannot obtain normal SEP-backed state.
public struct MobileActivationDResolver: Sendable {
    public static let name = "mobileactivationd"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let metadata = try ObjCMetadata(image: image)
        let shouldHactivate = try uniqueHactivationGetter(metadata: metadata)
        let activationState = try uniqueActivationStateMethod(metadata: metadata)

        let getterPatch = try resolveHactivationGetter(
            in: image,
            method: shouldHactivate
        )
        let statePatches = try resolveActivationStateReport(
            in: image,
            metadata: metadata,
            method: activationState
        )
        return [getterPatch] + statePatches
    }

    private func uniqueHactivationGetter(metadata: ObjCMetadata) throws -> ObjCMethod {
        let methods = try metadata.methods(named: "should_hactivate")
        let getters = try methods.filter { method in
            let entry = method.implementationOffset
            guard entry + 8 <= UInt64(metadata.image.count) else { return false }
            let load = try metadata.image.readUInt32(at: entry)
            let returnInstruction = try metadata.image.readUInt32(at: entry + 4)
            return load & 0xFFC0_03FF == 0x3940_0000 // LDRB W0,[X0,#imm]
                && returnInstruction == ARM64.ret
        }
        guard let getter = getters.only else {
            if getters.isEmpty { throw PatchfinderError.noCandidate("\(Self.name).should_hactivate") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name).should_hactivate",
                offsets: getters.map(\.implementationOffset)
            )
        }
        return getter
    }

    private func uniqueActivationStateMethod(metadata: ObjCMetadata) throws -> ObjCMethod {
        let selector = "getActivationStateWithCompletionBlock:"
        let methods = try metadata.methods(named: selector)
        var matches: [ObjCMethod] = []
        for method in methods {
            // The selector also appears in a forwarding/protocol method on
            // this binary. Only MobileActivationDaemon's implementation owns
            // the data-migration gate and fallback state-load shape.
            if try findStateLoadCandidates(
                in: metadata.image,
                methodOffset: method.implementationOffset
            ).count == 1 {
                matches.append(method)
            }
        }
        guard let method = matches.only else {
            if matches.isEmpty { throw PatchfinderError.noCandidate("\(Self.name).\(selector)") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name).\(selector)",
                offsets: matches.map(\.implementationOffset)
            )
        }
        return method
    }

    private func resolveHactivationGetter(
        in image: BinaryImage,
        method: ObjCMethod
    ) throws -> PatchRecord {
        let entry = method.implementationOffset
        let load = try image.readUInt32(at: entry)

        // A synthesized BOOL getter is exactly `LDRB W0,[X0,#ivar]; RET`.
        // This validates both the return register and object base while letting
        // the ivar offset move if DeviceType's layout changes.
        guard load & 0xFFC0_03FF == 0x3940_0000, // LDRB W0,[X0,#imm]
              try image.readUInt32(at: entry + 4) == ARM64.ret
        else {
            throw PatchfinderError.invalidPatch(
                id: "\(Self.name).should_hactivate",
                reason: "selector does not resolve to a two-instruction BOOL getter"
            )
        }
        return PatchRecord(
            id: "mobileactivationd.should-hactivate",
            component: "mobileactivationd",
            offset: entry,
            original: load,
            replacement: ARM64.movW0One,
            summary: "Make DeviceType report that hactivation is enabled",
            evidence: [
                "unique Objective-C selector should_hactivate",
                "relative method entry resolves to \(entry.hex)",
                "two-instruction LDRB W0,[X0,#ivar] / RET getter",
            ]
        )
    }

    private func resolveActivationStateReport(
        in image: BinaryImage,
        metadata: ObjCMetadata,
        method: ObjCMethod
    ) throws -> [PatchRecord] {
        let activatedObject = try findConstantString("Activated", metadata: metadata)
        let candidates = try findStateLoadCandidates(
            in: image,
            methodOffset: method.implementationOffset
        )
        guard let candidate = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("\(Self.name).activation-state") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name).activation-state",
                offsets: candidates.map(\.gate)
            )
        }

        guard let adrpAddress = metadata.layout.virtualAddress(
            forFileOffset: candidate.load
        ), let replacementADRP = ARM64.encodeADRP(
            register: 0,
            instructionOffset: adrpAddress,
            target: activatedObject.address
        ), let replacementADD = ARM64.encodeAddImmediate(
            destination: 0,
            source: 0,
            immediate: UInt32(activatedObject.address & 0xFFF)
        ) else {
            throw PatchfinderError.invalidPatch(
                id: "\(Self.name).activation-state",
                reason: "Activated CFString cannot be encoded as ADRP+ADD X0"
            )
        }

        let evidence = [
            "unique getActivationStateWithCompletionBlock: implementation at \(method.implementationOffset.hex)",
            "TBZ W22,#0 data-migration gate followed 0x60 bytes later by ADRP/ADD/LDR fallback load",
            "unique 32-byte CFString object for Activated at \(activatedObject.offset.hex)",
        ]
        return [
            PatchRecord(
                id: "mobileactivationd.activation-state.migration-gate",
                component: "mobileactivationd",
                offset: candidate.gate,
                original: try image.readUInt32(at: candidate.gate),
                replacement: ARM64.nop,
                summary: "Do not skip activation-state reporting before migration completes",
                evidence: evidence
            ),
            PatchRecord(
                id: "mobileactivationd.activation-state.adrp",
                component: "mobileactivationd",
                offset: candidate.load,
                original: try image.readUInt32(at: candidate.load),
                replacement: replacementADRP,
                summary: "Load the page containing the Activated CFString",
                evidence: evidence
            ),
            PatchRecord(
                id: "mobileactivationd.activation-state.add",
                component: "mobileactivationd",
                offset: candidate.load + 4,
                original: try image.readUInt32(at: candidate.load + 4),
                replacement: replacementADD,
                summary: "Materialize the Activated CFString address in X0",
                evidence: evidence
            ),
            PatchRecord(
                id: "mobileactivationd.activation-state.dereference",
                component: "mobileactivationd",
                offset: candidate.load + 8,
                original: try image.readUInt32(at: candidate.load + 8),
                replacement: ARM64.nop,
                summary: "Keep the CFString object address instead of dereferencing a state global",
                evidence: evidence
            ),
        ]
    }

    private func findStateLoadCandidates(
        in image: BinaryImage,
        methodOffset: UInt64
    ) throws -> [(gate: UInt64, load: UInt64)] {
        var matches: [(UInt64, UInt64)] = []
        let end = min(UInt64(image.count), methodOffset + 0x300)
        var gate = methodOffset
        while gate + 0x6C <= end {
            let branch = try image.readUInt32(at: gate)
            let loadOffset = gate + 0x60
            let adrp = try image.readUInt32(at: loadOffset)
            let add = try image.readUInt32(at: loadOffset + 4)
            let load = try image.readUInt32(at: loadOffset + 8)

            guard branch & 0xFFF8_001F == 0x3600_0016, // TBZ W22,#0,<target>
                  adrp & 0x9F00_001F == 0x9000_0008,   // ADRP X8,<page>
                  add & 0xFFC0_03FF == 0x9100_0108,    // ADD X8,X8,#imm
                  load & 0xFFC0_03FF == 0xF940_0100    // LDR X0,[X8,#imm]
            else {
                gate += 4
                continue
            }
            matches.append((gate, loadOffset))
            gate += 4
        }
        return matches
    }

    private func findConstantString(
        _ text: String,
        metadata: ObjCMetadata
    ) throws -> (offset: UInt64, address: UInt64) {
        guard let strings = metadata.layout.section(segment: "__TEXT", named: "__cstring"),
              let constants = metadata.layout.section(segment: "__DATA_CONST", named: "__cfstring")
        else {
            throw PatchfinderError.invalidFixture("Mach-O lacks CFString backing sections")
        }
        let cStrings = metadata.image.findAll(utf8: text, nulTerminated: true)
            .filter { strings.fileRange.contains($0) }
        guard !cStrings.isEmpty else { throw PatchfinderError.missingAnchor(text) }
        let cStringAddresses = Set(cStrings.compactMap { offset in
            metadata.layout.virtualAddress(forFileOffset: offset)
        })

        var matches: [(UInt64, UInt64)] = []
        var offset = constants.fileRange.lowerBound
        while offset + 32 <= constants.fileRange.upperBound {
            let length = try metadata.image.readUInt64(at: offset + 24)
            if length == UInt64(text.utf8.count),
               let backingAddress = try metadata.chainedRebaseTarget(at: offset + 16),
               cStringAddresses.contains(backingAddress),
               let address = metadata.layout.virtualAddress(forFileOffset: offset) {
                matches.append((offset, address))
            }
            offset += 32
        }
        guard let match = matches.only else {
            if matches.isEmpty { throw PatchfinderError.noCandidate("CFString \(text)") }
            throw PatchfinderError.ambiguousCandidate(
                "CFString \(text)",
                offsets: matches.map(\.0)
            )
        }
        return match
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
