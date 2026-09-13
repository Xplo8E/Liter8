import Foundation

public extension Data {
    /// Lowercase hexadecimal representation used by manifests and CLI output.
    /// Firmware patches are easier to audit as instruction bytes than as the
    /// Base64 strings synthesized by Foundation's default `Data` encoding.
    var hexadecimalString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Decode an even-length hexadecimal string without accepting separators.
    /// Keeping the format strict makes fixture diffs unambiguous.
    init?(hexadecimalString: String) {
        guard hexadecimalString.count.isMultiple(of: 2) else { return nil }

        var decoded = Data(capacity: hexadecimalString.count / 2)
        var cursor = hexadecimalString.startIndex
        while cursor < hexadecimalString.endIndex {
            let next = hexadecimalString.index(cursor, offsetBy: 2)
            guard let byte = UInt8(hexadecimalString[cursor..<next], radix: 16) else {
                return nil
            }
            decoded.append(byte)
            cursor = next
        }
        self = decoded
    }
}
