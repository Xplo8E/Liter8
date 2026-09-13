import Foundation

/// Replacement programs used by the AppleCredentialManager patch family.
///
/// Keeping these words away from locator signatures makes the compatibility
/// rule explicit: beta 2 and beta 4 use different offsets but the same two-word
/// behavior. A future build gets a new payload only if its entry ABI or desired
/// behavior changes.
struct KernelCredentialManagerPayload: Sendable {
    let id: String
    let result: UInt32
    let returnInstruction: UInt32
}

enum KernelCredentialManagerPayloads {
    static let returnSuccessV1 = KernelCredentialManagerPayload(
        id: "acm-return-success-v1",
        result: ARM64.movW0Zero,
        returnInstruction: ARM64.ret
    )

    static func payload(named id: String) -> KernelCredentialManagerPayload? {
        switch id {
        case returnSuccessV1.id: return returnSuccessV1
        default: return nil
        }
    }
}
