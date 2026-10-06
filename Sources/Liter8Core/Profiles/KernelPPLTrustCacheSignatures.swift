import Foundation

/// Signature data for the profile-selected T8020 loaded-trust-cache decision.
enum KernelPPLTrustCacheSignatures {
    // PACIBSP; stack frame/canary; copy all 20 CDHash bytes; query type 2;
    // CMP W0,#0 / CSET W0,EQ; verify canary; restore frame and RETAB.
    // Page addresses and direct branch displacements may move; register,
    // copy width, type constant, result condition and frame words stay fixed.
    static let loadedTrustCacheV1 = MaskedInstructionPattern(name: "PPL loaded trust-cache helper", referenceWords: [
        0xd503237f, 0xd100c3ff, 0xa9027bfd, 0x910083fd,
        0x90000008, 0x91000108, 0xf9400108, 0xf81f83a8,
        0x3dc00000, 0x3d8003e0, 0xb9401008, 0xb90013e8,
        0x910003e1, 0x52800040, 0xd2800002, 0x94000000,
        0x7100001f, 0x1a9f17e0,
        0xf85f83a8, 0x90000009, 0x91000129, 0xf9400129,
        0xeb08013f, 0x54000081, 0xa9427bfd, 0x9100c3ff, 0xd65f0fff,
    ])
}
