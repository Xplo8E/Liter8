import Foundation

/// The two DeviceTree plans used by the beta-4 boot flows.
///
/// The SSH ramdisk only needs content protection removed. Normal boot also
/// carries the three state properties used by the AKS/diagnostic workarounds.
public enum DeviceTreePatchPlan: String, CaseIterable, Sendable {
    case restore = "devicetree-restore"
    case normal = "devicetree-normal"
}

public enum DeviceTreeChangeDisposition: String, Sendable {
    case removed
    case updated
    case added
    case alreadyApplied = "already-applied"
}

/// A human-readable structural change. DeviceTree edits can change the file
/// length, so representing them as fixed-offset ``PatchRecord`` values would
/// be misleading. Paths and property names are the stable semantic identity.
public struct DeviceTreeChange: Equatable, Sendable {
    public let operation: String
    public let path: String
    public let disposition: DeviceTreeChangeDisposition
}

public struct DeviceTreePatchResult: Sendable {
    public let data: Data
    public let changes: [DeviceTreeChange]
}

/// Parser and guarded structural patcher for Apple's flattened DeviceTree.
///
/// On disk, every node contains a property count, child count, properties,
/// then recursively encoded children. A property has a 32-byte name, a u32
/// length whose high bit is a placeholder flag, and a four-byte-aligned value.
/// We retain the original name bytes, flags and padding so a parse/serialize
/// round trip is byte-identical before any edits are made.
public enum DeviceTreePatcher {
    private static let propertyNameSize = 32
    private static let placeholderFlag: UInt32 = 0x8000_0000

    private enum Operation {
        case remove(nodePath: String, property: String)
        case set(nodePath: String, property: String, value: Data)

        var path: String {
            switch self {
            case let .remove(nodePath, property), let .set(nodePath, property, _):
                return nodePath + "/" + property
            }
        }

        var name: String {
            switch self {
            case .remove: "del-prop"
            case .set: "set-prop"
            }
        }
    }

    /// A property is a reference type because patch operations mutate the
    /// parsed tree in place before the entire payload is serialized once.
    private final class Property {
        let nameBytes: Data
        var rawLength: UInt32
        var value: Data
        var padding: Data

        init(nameBytes: Data, rawLength: UInt32, value: Data, padding: Data) {
            self.nameBytes = nameBytes
            self.rawLength = rawLength
            self.value = value
            self.padding = padding
        }

        var name: String {
            let end = nameBytes.firstIndex(of: 0) ?? nameBytes.endIndex
            return String(decoding: nameBytes[..<end], as: UTF8.self)
        }

        var flags: UInt32 { rawLength & DeviceTreePatcher.placeholderFlag }

        func replaceValue(_ newValue: Data) {
            value = newValue
            rawLength = flags | UInt32(newValue.count)
            padding = Data(repeating: 0, count: DeviceTreePatcher.alignedSize(newValue.count) - newValue.count)
        }

        static func make(name: String, value: Data) throws -> Property {
            let encoded = Data(name.utf8)
            guard encoded.count < DeviceTreePatcher.propertyNameSize else {
                throw PatchfinderError.invalidDeviceTree("property name is too long: \(name)")
            }
            var nameBytes = encoded
            nameBytes.append(Data(repeating: 0, count: DeviceTreePatcher.propertyNameSize - encoded.count))
            return Property(
                nameBytes: nameBytes,
                rawLength: UInt32(value.count),
                value: value,
                padding: Data(repeating: 0, count: DeviceTreePatcher.alignedSize(value.count) - value.count)
            )
        }
    }

    private final class Node {
        var properties: [Property] = []
        var children: [Node] = []

        var name: String {
            guard let property = properties.first(where: { $0.name == "name" }) else { return "" }
            let end = property.value.firstIndex(of: 0) ?? property.value.endIndex
            return String(decoding: property.value[..<end], as: UTF8.self)
        }
    }

    /// Apply one named plan and immediately re-parse the output to prove the
    /// requested end state survived serialization.
    public static func patch(_ data: Data, plan: DeviceTreePatchPlan) throws -> DeviceTreePatchResult {
        let root = try parsePayload(data)

        // Refuse format quirks before editing. Otherwise a serializer bug could
        // silently become part of a supposedly successful firmware patch.
        guard serialize(root) == data else {
            throw PatchfinderError.invalidDeviceTree("lossless parse/serialize round trip failed")
        }

        var changes: [DeviceTreeChange] = []
        for operation in operations(for: plan) {
            changes.append(try apply(operation, to: root))
        }

        let output = serialize(root)
        try verify(output, plan: plan)
        return DeviceTreePatchResult(data: output, changes: changes)
    }

    /// Verify a previously patched DeviceTree without modifying it.
    public static func verify(_ data: Data, plan: DeviceTreePatchPlan) throws {
        let root = try parsePayload(data)
        for operation in operations(for: plan) {
            switch operation {
            case let .remove(nodePath, propertyName):
                let node = try resolveNode(root, path: nodePath)
                guard node.properties.allSatisfy({ $0.name != propertyName }) else {
                    throw PatchfinderError.deviceTreeVerificationFailed(operation.path)
                }
            case let .set(nodePath, propertyName, expectedValue):
                let node = try resolveNode(root, path: nodePath)
                guard node.properties.first(where: { $0.name == propertyName })?.value == expectedValue else {
                    throw PatchfinderError.deviceTreeVerificationFailed(operation.path)
                }
            }
        }
    }

    private static func operations(for plan: DeviceTreePatchPlan) -> [Operation] {
        var operations: [Operation] = [
            // Without SEP, the research build cannot provide an encrypted data
            // volume. Removing this property matches the existing Python/QEMU
            // path and prevents the boot flow from demanding one.
            .remove(nodePath: "/defaults", property: "content-protect"),
        ]

        if plan == .normal {
            operations += [
                // Tell AppleKeyStore that effaceable storage is unavailable.
                .set(nodePath: "/defaults", property: "no-effaceable-storage", value: littleEndianOne),

                // Preserve the beta-4 normal-boot behavior inherited from the
                // QEMU t8030 DeviceTree patch set.
                .set(nodePath: "/product", property: "boot-ios-diagnostics", value: littleEndianOne),

                // The beta-2 flow set this separately. Keeping it in the named
                // normal plan prevents a stale SSHRD DeviceTree being reused.
                .set(nodePath: "/chosen", property: "ephemeral-storage", value: littleEndianOne),
            ]
        }
        return operations
    }

    private static var littleEndianOne: Data {
        var value = UInt32(1).littleEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    private static func apply(_ operation: Operation, to root: Node) throws -> DeviceTreeChange {
        switch operation {
        case let .remove(nodePath, propertyName):
            let node = try resolveNode(root, path: nodePath)
            guard let index = node.properties.firstIndex(where: { $0.name == propertyName }) else {
                return DeviceTreeChange(
                    operation: operation.name,
                    path: operation.path,
                    disposition: .alreadyApplied
                )
            }
            node.properties.remove(at: index)
            return DeviceTreeChange(operation: operation.name, path: operation.path, disposition: .removed)

        case let .set(nodePath, propertyName, value):
            let node = try resolveNode(root, path: nodePath)
            if let property = node.properties.first(where: { $0.name == propertyName }) {
                guard property.value != value else {
                    return DeviceTreeChange(
                        operation: operation.name,
                        path: operation.path,
                        disposition: .alreadyApplied
                    )
                }
                property.replaceValue(value)
                return DeviceTreeChange(operation: operation.name, path: operation.path, disposition: .updated)
            }

            node.properties.append(try Property.make(name: propertyName, value: value))
            return DeviceTreeChange(operation: operation.name, path: operation.path, disposition: .added)
        }
    }

    // MARK: - Parser

    private static func alignedSize(_ size: Int) -> Int { (size + 3) & ~3 }

    private static func parsePayload(_ data: Data) throws -> Node {
        let (root, end) = try parseNode(data, offset: 0)
        guard end == data.count else {
            throw PatchfinderError.invalidDeviceTree("\(data.count - end) trailing bytes after root node")
        }
        return root
    }

    private static func parseNode(_ data: Data, offset: Int) throws -> (Node, Int) {
        guard offset >= 0, offset + 8 <= data.count else {
            throw PatchfinderError.invalidDeviceTree("truncated node header at 0x\(String(offset, radix: 16))")
        }

        let propertyCount = Int(readUInt32(data, at: offset))
        let childCount = Int(readUInt32(data, at: offset + 4))
        var cursor = offset + 8
        let node = Node()

        for _ in 0..<propertyCount {
            guard cursor + propertyNameSize + 4 <= data.count else {
                throw PatchfinderError.invalidDeviceTree("truncated property header at 0x\(String(cursor, radix: 16))")
            }

            let name = data.subdata(in: cursor..<(cursor + propertyNameSize))
            let rawLength = readUInt32(data, at: cursor + propertyNameSize)
            let valueLength = Int(rawLength & ~placeholderFlag)
            let valueStart = cursor + propertyNameSize + 4
            let paddedLength = alignedSize(valueLength)
            guard valueLength >= 0, valueStart + paddedLength <= data.count else {
                throw PatchfinderError.invalidDeviceTree("truncated property value at 0x\(String(valueStart, radix: 16))")
            }

            node.properties.append(Property(
                nameBytes: name,
                rawLength: rawLength,
                value: data.subdata(in: valueStart..<(valueStart + valueLength)),
                padding: data.subdata(in: (valueStart + valueLength)..<(valueStart + paddedLength))
            ))
            cursor = valueStart + paddedLength
        }

        for _ in 0..<childCount {
            let (child, end) = try parseNode(data, offset: cursor)
            node.children.append(child)
            cursor = end
        }
        return (node, cursor)
    }

    private static func serialize(_ node: Node) -> Data {
        var output = Data()
        appendUInt32(UInt32(node.properties.count), to: &output)
        appendUInt32(UInt32(node.children.count), to: &output)

        for property in node.properties {
            output.append(property.nameBytes)
            appendUInt32(property.rawLength, to: &output)
            output.append(property.value)
            output.append(property.padding)
        }
        for child in node.children {
            output.append(serialize(child))
        }
        return output
    }

    private static func resolveNode(_ root: Node, path: String) throws -> Node {
        var node = root
        for component in path.split(separator: "/").map(String.init) {
            guard let child = node.children.first(where: { $0.name == component }) else {
                throw PatchfinderError.invalidDeviceTree("missing node \(path) at component \(component)")
            }
            node = child
        }
        return node
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
        }
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }
}
