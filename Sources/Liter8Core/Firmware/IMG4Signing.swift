import Foundation
import Img4tool

/// Creates a ticket-bearing IMG4 entirely in Swift.
///
/// The ticket is an IM4M obtained for the connected device. This operation
/// embeds it; it does not forge, alter, or re-sign Apple's manifest.
public enum IMG4Signing {
    public static func create(
        im4pData: Data,
        im4mData: Data,
        fourcc: String? = nil
    ) throws -> Data {
        let original = try IM4P(im4pData)
        let payload: IM4P
        if let fourcc {
            guard fourcc.utf8.count == 4 else {
                throw PatchfinderError.invalidFirmwareContainer(
                    "IMG4 fourcc must contain exactly four UTF-8 bytes"
                )
            }
            payload = try original.renamed(to: fourcc)
        } else {
            payload = original
        }
        let manifest = try IM4M(im4mData)
        let output = try IMG4(im4p: payload, im4m: manifest)

        // Parse the result before returning it. This catches a malformed vendor
        // encoding immediately, before a boot workflow sends it to a device.
        let verified = try IMG4(output.data)
        guard try verified.im4p().data == payload.data,
              try verified.im4m().data == manifest.data else {
            throw PatchfinderError.invalidFirmwareContainer(
                "IMG4 failed payload/manifest round-trip verification"
            )
        }
        return output.data
    }

    /// Read the IM4M back out of a ticket-bearing IMG4.
    ///
    /// Recovering the restore-bound APTicket from the device's own
    /// `sep-firmware.img4` used to run `img4tool -e -m`, which is an arm64-only
    /// bundled binary and so could not run on an Intel Mac. The vendored
    /// container code already parses this during `create`'s round-trip check.
    public static func extractManifest(from img4Data: Data) throws -> Data {
        // `im4m()` constructs an IM4M, so malformed manifest bytes throw there
        // rather than reaching a device.
        let manifest = try IMG4(img4Data).im4m().data
        guard !manifest.isEmpty else {
            throw PatchfinderError.invalidFirmwareContainer(
                "IMG4 contains no IM4M manifest"
            )
        }
        return manifest
    }
}
