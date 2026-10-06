import Foundation

/// One named function shape inside an AppleCredentialManager signature set.
///
/// The words are locator evidence, not bytes that will be written. Branch
/// destinations, ADRP pages, and object-field offsets are masked by
/// `MaskedInstructionPattern` before scanning a different firmware.
struct KernelFunctionSignatureDescriptor: Sendable {
    let id: String
    let name: String
    let pattern: MaskedInstructionPattern
    let needsScoring: Bool

    init(_ name: String, words: String, needsScoring: Bool = false) {
        self.id = name
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
            .replacingOccurrences(of: "_", with: "-")
            .replacingOccurrences(of: " ", with: "-")
            .lowercased()
        self.name = name
        self.pattern = MaskedInstructionPattern(
            name: "AppleCredentialManager::\(name)",
            referenceWords: Self.referenceWords(words),
            allowDataLayoutDrift: true
        )
        self.needsScoring = needsScoring
    }

    /// Parse disassembler words stored in host-readable instruction order.
    /// A malformed checked-in signature is a programming error, not a bad
    /// firmware input, so fail immediately during construction.
    private static func referenceWords(_ text: String) -> [UInt32] {
        text.split { $0.isWhitespace }.map { token in
            guard let word = UInt32(token, radix: 16) else {
                preconditionFailure("invalid reference instruction: \(token)")
            }
            return word
        }
    }
}

struct KernelCredentialManagerSignatureVariant: Sendable {
    let id: String
    let functions: [KernelFunctionSignatureDescriptor]
    let requiresReferenceOrder: Bool
    let preserveBareBTI: Bool

    init(
        id: String,
        functions: [KernelFunctionSignatureDescriptor],
        requiresReferenceOrder: Bool = true,
        preserveBareBTI: Bool = false
    ) {
        self.id = id
        self.functions = functions
        self.requiresReferenceOrder = requiresReferenceOrder
        self.preserveBareBTI = preserveBareBTI
    }
}

/// Build-family-specific locator data for AppleCredentialManager.
///
/// Beta 2 and beta 4 share one variant because masked matching proved their
/// function shapes compatible. Release build 24A435 gets its own, because iOS 27
/// RC enabled BTI for the kernelcache and every method in this class gained a
/// landing pad. The families stay separate rather than being merged behind a
/// looser mask: a shared variant would let one build's shapes silently stand in
/// for the other's.
enum KernelCredentialManagerSignatures {
    static let earlyBetaV1 = KernelCredentialManagerSignatureVariant(
        id: "ios27-early-beta-acm-v1",
        functions: [
            // pacibsp; sub sp, sp, #64; stp x29, x30, [sp, #48]; add x29, sp, #48; ldr x0, [x0, #152]
            //   ldr x16, [x0]; mov x17, x0; movk x17, #52641, lsl #48; autda x16, x17; ldr x9, [x16, #232]!
            //   mov x8, x16; adrp x16, #20480
            .init("sepManagerMatchedThreadCallHandler", words: "d503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 b0000030"),
            // pacibsp; sub sp, sp, #96; stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x4, #52; ldr w8, [x4]
            //   stur w8, [x29, #-32]; ldr x8, [x4, #8]; stur x8, [x29, #-28]; sturb wzr, [x29, #-20]
            //   stur xzr, [x29, #-11]; stur xzr, [x29, #-19]; sub x4, x29, #32; bl #216
            //   ldp x29, x30, [sp, #80]; add sp, sp, #96
            .init("callPlatformFunction", words: "d503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf f81ed3bf d10083a4 94000036 a9457bfd 910183ff"),
            // pacibsp; sub sp, sp, #96; stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x4, #56; ldr w8, [x4]
            //   stur w8, [x29, #-32]; ldur x8, [x4, #4]; stur x8, [x29, #-28]; ldrb w8, [x4, #12]
            //   sturb w8, [x29, #-20]; stur xzr, [x29, #-11]; stur xzr, [x29, #-19]; sub x4, x29, #32; bl #80
            //   ldp x29, x30, [sp, #80]
            .init("cmdContextV2", words: "d503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 f81f53bf f81ed3bf d10083a4 94000014 a9457bfd"),
            // pacibsp; sub sp, sp, #144; stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]
            //   stp x20, x19, [sp, #112]; stp x29, x30, [sp, #128]; add x29, sp, #128; cbz x4, #172
            //   mov x23, x4; mov x19, x3; mov x20, x2; mov x21, x1; mov x22, x0; bl #-76632; mov x24, x0
            //   ldrb w1, [x23, #12]
            .init("cmdContextV3", words: "d503237f d10243ff a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd b4000564 aa0403f7 aa0303f3 aa0203f4 aa0103f5 aa0003f6 97ffb52a aa0003f8 394032e1"),
            // pacibsp; sub sp, sp, #336; stp x28, x27, [sp, #240]; stp x26, x25, [sp, #256]
            //   stp x24, x23, [sp, #272]; stp x22, x21, [sp, #288]; stp x20, x19, [sp, #304]
            //   stp x29, x30, [sp, #320]; add x29, sp, #320; mov x27, x4; mov x21, x3; mov x25, x2; mov x28, x1
            //   mov x22, x0; movi v0.2d, #0000000000000000; stp q0, q0, [x29, #-128]
            .init("performCommandGated", words: "d503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403fb aa0303f5 aa0203f9 aa0103fc aa0003f6 6f00e400 ad3c03a0"),
            // pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
            //   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
            //   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x21, x5; mov x22, x4; mov x23, x3; mov x24, x2
            //   mov x20, x1; mov x19, x0; adrp x26, #31965184
            .init("_performKernelControl", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 aa0303f7 aa0203f8 aa0103f4 aa0003f3 9000f3fa"),
            // pacibsp; sub sp, sp, #176; stp x28, x27, [sp, #80]; stp x26, x25, [sp, #96]
            //   stp x24, x23, [sp, #112]; stp x22, x21, [sp, #128]; stp x20, x19, [sp, #144]
            //   stp x29, x30, [sp, #160]; add x29, sp, #160; mov x24, x6; mov x25, x5; mov x20, x4; mov x23, x3
            //   mov x19, x2; mov x21, x1; mov x22, x0
            .init("_performCommand", words: "d503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6"),
            // pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
            //   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x21, #31965184
            //   ldrb w8, [x21, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
            //   ldr x16, [x19]; mov x17, x19
            .init("processSCRDResponsePayload", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f3f5 3968a2a8 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1"),
            // pacibsp; sub sp, sp, #80; stp x20, x19, [sp, #48]; stp x29, x30, [sp, #64]; add x29, sp, #64
            //   mov x19, x0; mov w1, #0; bl #15120; ldr x0, [x19, #280]; ldr x16, [x0]; mov x17, x0
            //   movk x17, #52641, lsl #48; autda x16, x17; ldr x8, [x16, #176]!; movk x16, #39702, lsl #48
            //   blraa x8, x16
            .init("scheduleDblClickDeferredAck", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000ec4 f9408e60 f9400010 aa0003f1 f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910"),

            // These bodies retain strong similarity across beta 2 and beta 4,
            // but not an honest exact signature. Neighboring exact functions
            // bound the search before the resolver scores their first 32 words.
            // pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
            //   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x22, #31961088
            //   ldrb w8, [x22, #2600]; adrp x21, #-27676672; add x21, x21, #1671; cmp w8, #10; b.hi #84
            //   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
            //   autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19; mov x1, #0
            //   movk x16, #3228, lsl #48; blraa x8, x16; b #12; adrp x0, #-27680768; add x0, x0, #1331
            //   stp x0, x21, [sp]; adrp x0, #-27746304
            .init("updateAnalytics", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 f000f3d6 3968a2c8 f0ff2cd5 911a1eb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2cc0 9114cc00 a90057e0 d0ff2c40", needsScoring: true),
            // pacibsp; sub sp, sp, #128; stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]
            //   stp x29, x30, [sp, #112]; add x29, sp, #112; mov x19, x0; adrp x20, #31961088
            //   ldrb w8, [x20, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
            //   ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
            .init("performSCRDInitialization", words: "d503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 f000f3d4 3968a288 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431"),
            // pacibsp; sub sp, sp, #272; stp x28, x27, [sp, #176]; stp x26, x25, [sp, #192]
            //   stp x24, x23, [sp, #208]; stp x22, x21, [sp, #224]; stp x20, x19, [sp, #240]
            //   stp x29, x30, [sp, #256]; add x29, sp, #256; mov x28, x7; str x6, [sp, #104]; mov x22, x5
            //   mov x21, x4; mov x24, x3; mov x25, x2; mov x20, x1; mov x19, x0; stur x4, [x29, #-96]
            //   adrp x8, #31961088; ldrb w8, [x8, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]
            //   tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48; autda x16, x17
            //   mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19
            .init("sendSEPCommand", words: "d503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc f90037e6 aa0503f6 aa0403f5 aa0303f8 aa0203f9 aa0103f4 aa0003f3 f81a03a4 f000f3c8 3968a108 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0", needsScoring: true),
            // pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
            //   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
            //   mov x19, x1; mov x20, x0; adrp x8, #-19030016; ldr x8, [x8, #3704]; ldr x1, [x8]; mov x0, x19
            //   bl #62088; cbz x0, #712
            .init("_setPropertiesGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 d0ff6ec8 f9473d08 f9400101 aa1303e0 94003ca2 b4001640"),
            // pacibsp; sub sp, sp, #80; stp x20, x19, [sp, #48]; stp x29, x30, [sp, #64]; add x29, sp, #64
            //   cbz x1, #76; mov x19, x1; stp xzr, xzr, [sp]; mov w1, #2; mov w2, #0; mov x3, #0; mov x4, #0
            //   mov x5, #0; mov x6, #0; mov w7, #1; bl #-3700
            .init("performDoubleClickQueryGated", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 d2800004 d2800005 d2800006 52800027 97fffc63"),
            // bti c; cbz x1, #24; mov w0, #0; adrp x8, #31956992; ldrb w8, [x8, #2600]; str x8, [x1]; ret
            //   pacibsp; sub sp, sp, #64; stp x29, x30, [sp, #48]
            .init("performLoggingLevelQueryGated", words: "d503245f b40000c1 52800000 d000f3c8 3968a108 f9000028 d65f03c0 d503237f d10103ff a9037bfd"),
            // pacibsp; sub sp, sp, #112; stp x24, x23, [sp, #48]; stp x22, x21, [sp, #64]
            //   stp x20, x19, [sp, #80]; stp x29, x30, [sp, #96]; add x29, sp, #96; mov x19, x2; mov x21, x1
            //   mov x20, x0; adrp x23, #31956992; ldrb w8, [x23, #2600]
            .init("lockItem", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 d000f3d7 3968a2e8"),
            // pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
            //   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x22, #31956992
            //   ldrb w8, [x22, #2600]; adrp x21, #-27684864; add x21, x21, #3492; cmp w8, #10; b.hi #84
            //   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
            //   autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19; mov x1, #0
            //   movk x16, #3228, lsl #48; blraa x8, x16; b #12; adrp x0, #-27684864; add x0, x0, #1331
            //   stp x0, x21, [sp]; adrp x0, #-27750400
            .init("unlockItem", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f3d6 3968a2c8 b0ff2cd5 913692b5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2cc0 9114cc00 a90057e0 b0ff2c40", needsScoring: true),
            // pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
            //   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
            //   mov x20, x1; mov x19, x0; ldr x24, [x2]; lsr x25, x24, #32; adrp x23, #31956992
            //   ldrb w8, [x23, #2600]; lsr w21, w24, #16; adrp x22, #-27684864
            .init("handleSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 d360ff19 d000f3d7 3968a2e8 53107f15 b0ff2cd6"),
            // pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
            //   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x2; mov x19, x1; mov x21, x0
            //   ldr x0, [x0, #328]; cbnz x0, #20; mov x0, x21; bl #2220; ldr x0, [x21, #328]; cbz x0, #236
            //   ldr x16, [x0]
            .init("readFromSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a400 b50000a0 aa1503e0 9400022b f940a6a0 b4000760 f9400010"),
            // pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
            //   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
            //   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x20, x5; mov x21, x4; mov x22, x3; mov x23, x2
            //   mov x24, x1; mov x19, x0; adrp x28, #31952896
            .init("writeToSEPBuffer", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f8 aa0003f3 b000f3dc"),
            // pacibsp; sub sp, sp, #144; stp x26, x25, [sp, #64]; stp x24, x23, [sp, #80]
            //   stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]; stp x29, x30, [sp, #128]; add x29, sp, #128
            //   mov x23, x4; mov x21, x3; mov x22, x2; mov x20, x1; mov x19, x0; adrp x25, #31952896
            //   ldrb w8, [x25, #2600]; cmp w8, #10
            .init("sendSEPMessage", words: "d503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 b000f3d9 3968a328 7100291f"),
            // pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
            //   stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x1, #280; mov x19, x2; mov x20, x1
            //   ldr x16, [x1]; mov x17, x1; movk x17, #52641, lsl #48; autda x16, x17; ldr x8, [x16, #120]!
            //   mov x0, x1; movk x16, #5079, lsl #48
            .init("clearSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0"),
            // pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
            //   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
            //   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x19, x0; adrp x27, #31952896
            //   ldrb w8, [x27, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
            .init("getSEPEndpoint", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f3db 3968a368 7100291f 540002e8 39423268 360001a8"),
            // pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
            //   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
            //   mov x19, x0; adrp x25, #31948800; ldrb w8, [x25, #2600]; cmp w8, #40; b.hi #92
            //   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]
            .init("powerOffActionGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f3d9 3968a328 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
            //   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
            //   mov x19, x0; adrp x8, #31948800; ldrb w8, [x8, #2600]; cmp w8, #40; b.hi #92
            //   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]
            .init("sepManagerMatchedGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f3c8 3968a108 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // pacibsp; sub sp, sp, #112; stp x24, x23, [sp, #48]; stp x22, x21, [sp, #64]
            //   stp x20, x19, [sp, #80]; stp x29, x30, [sp, #96]; add x29, sp, #96; mov x20, x1; mov x19, x0
            //   adrp x24, #31899648; ldrb w8, [x24, #2600]; adrp x23, #-27742208; add x23, x23, #3303
            //   cmp w8, #40; b.hi #56; ldrb w8, [x19, #140]; tbz w8, #0, #116; bl #-48444
            //   movk x17, #52641, lsl #48; autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]
            //   mov x0, x19; mov x1, #0; movk x16, #3228, lsl #48; blraa x8, x16; b #76; cbnz x20, #100
            //   mov w8, #1709; adrp x9, #-27742208; add x9, x9, #1651
            .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f378 3968a308 f0ff2c57 91339ef7 7100a11f 540001c8 39423268 360003a8 97ffd0b1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000013 b5000334 5280d5a8 f0ff2c49 9119cd29", needsScoring: true),
        ]
    )

    /// Release build 24A435 (iOS 27 RC).
    ///
    /// Recovered from `com.apple.driver.AppleSEPCredentialManager:__text` in the
    /// RC kernelcache. All 26 methods keep beta 4's relative order, which is the
    /// cross-check that the set is the same set and not 26 coincidences.
    ///
    /// Every RC method carries a `BTI C` landing pad. These words start at the
    /// `PACIBSP` that follows it, except `performLoggingLevelQueryGated`, whose
    /// entry is the pad itself on both builds. The stub write is placed with
    /// `ARM64.stubStart` so no pad is overwritten: ten of these methods have zero
    /// direct branch references and are reached only through a taken address.
    static let release24A435V1 = KernelCredentialManagerSignatureVariant(
        id: "ios27-24A435-acm-v1",
        functions: [
            // RC file offset 0x20bfd50; 11/12 words identical to beta 4.
            .init("sepManagerMatchedThreadCallHandler", words: "d503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 d0000030"),
            // RC file offset 0x20c0434; 15/16 words identical to beta 4.
            .init("callPlatformFunction", words: "d503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf f81ed3bf d10083a4 94000037 a9457bfd 910183ff"),
            // RC file offset 0x20c04bc; 16/16 words identical to beta 4.
            .init("cmdContextV2", words: "d503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 f81f53bf f81ed3bf d10083a4 94000014 a9457bfd"),
            // RC file offset 0x20c0548; 15/16 words identical to beta 4.
            .init("cmdContextV3", words: "d503237f d10243ff a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd b4000564 aa0403f7 aa0303f3 aa0203f4 aa0103f5 aa0003f6 97ffb3eb aa0003f8 394032e1"),
            // RC file offset 0x20c0824; 12/16 words identical to beta 4.
            .init("performCommandGated", words: "d503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0"),
            // RC file offset 0x20c1314; 15/16 words identical to beta 4.
            .init("_performKernelControl", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 aa0303f7 aa0203f8 aa0103f4 aa0003f3 d000f29a"),
            // RC file offset 0x20c16d4; 16/16 words identical to beta 4.
            .init("_performCommand", words: "d503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6"),
            // RC file offset 0x20c1900; 14/16 words identical to beta 4.
            .init("processSCRDResponsePayload", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f295 3964e2a8 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1"),
            // RC file offset 0x20c1b30; 15/16 words identical to beta 4.
            .init("scheduleDblClickDeferredAck", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910"),
            // RC file offset 0x20c1c54; 25/32 words identical to beta 4.
            .init("updateAnalytics", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f296 3964e2c8 b0ff2f95 9106ceb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 f0ff2f60 913b9800 a90057e0 f0ff2ee0", needsScoring: true),
            // RC file offset 0x20c1dbc; 14/16 words identical to beta 4.
            .init("performSCRDInitialization", words: "d503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f294 3964e288 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431"),
            // RC file offset 0x20c2084; 27/32 words identical to beta 4.
            .init("sendSEPCommand", words: "d503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 b000f29b 3964e368 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0", needsScoring: true),
            // RC file offset 0x20c2b00; 13/16 words identical to beta 4.
            .init("_setPropertiesGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 90ff7028 f9443908 f9400101 aa1303e0 94003dca b4001640"),
            // RC file offset 0x20c2f8c; 15/16 words identical to beta 4.
            .init("performDoubleClickQueryGated", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 d2800004 d2800005 d2800006 52800027 97fffc2e"),
            // RC file offset 0x20c307c; 8/10 words identical to beta 4.
            .init("performLoggingLevelQueryGated", words: "d503245f b40000c1 52800000 9000f288 3964e108 f9000028 d65f03c0 d503237f d10103ff a9037bfd"),
            // RC file offset 0x20c34b8; 10/12 words identical to beta 4.
            .init("lockItem", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 9000f297 3964e2e8"),
            // RC file offset 0x20c36e8; 25/32 words identical to beta 4.
            .init("unlockItem", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f296 3964e2c8 d0ff2f75 912172b5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2f60 913b9800 a90057e0 b0ff2ee0", needsScoring: true),
            // RC file offset 0x20c3bac; 13/16 words identical to beta 4.
            .init("handleSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 d360ff19 9000f297 3964e2e8 53107f15 d0ff2f76"),
            // RC file offset 0x20c3e98; 13/16 words identical to beta 4.
            .init("readFromSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 aa1503e0 9400022e f940aaa0 b4000760 f9400010"),
            // RC file offset 0x20c3ffc; 15/16 words identical to beta 4.
            .init("writeToSEPBuffer", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f8 aa0003f3 f000f27c"),
            // RC file offset 0x20c43a8; 14/16 words identical to beta 4.
            .init("sendSEPMessage", words: "d503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 f000f279 3964e328 7100291f"),
            // RC file offset 0x20c45e4; 16/16 words identical to beta 4.
            .init("clearSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0"),
            // RC file offset 0x20c4784; 14/16 words identical to beta 4.
            .init("getSEPEndpoint", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 f000f27b 3964e368 7100291f 540002e8 39423268 360001a8"),
            // RC file offset 0x20c53d0; 14/16 words identical to beta 4.
            .init("powerOffActionGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f279 3964e328 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // RC file offset 0x20c5688; 14/16 words identical to beta 4.
            .init("sepManagerMatchedGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f268 3964e108 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // RC file offset 0x20d1b2c; 19/32 words identical to beta 4.
            .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 d000f217 3964e2e8 90ff2f16 911aded6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 f0ff2e60 91325400", needsScoring: true),
        ]
    )

    /// iOS 27.2 `24B5084k`, recovered from the same class in that kernelcache.
    ///
    /// This family is close to `release24A435V1` rather than a rewrite: probing
    /// 24A435's shapes against 27.2 matched 23 of 26 outright, and the two that
    /// came back ambiguous are the scored entries that are ambiguous on 24A435
    /// too. Only `cmdContextV3` actually changed, gaining a callee-saved pair
    /// (`stp x26, x25`) and a frame of 0xa0 instead of 0x80, which shifts every
    /// following instruction by one slot.
    ///
    /// The words are nevertheless re-recorded from 27.2 rather than shared with
    /// the 24A435 variant. Reusing them would work today and would mean a later
    /// build could match one family's shapes while claiming the other's, which
    /// is the confusion these families exist to prevent.
    ///
    /// Method order is identical to 24A435, and the offsets increase
    /// monotonically through the class. `updateAnalytics` and `unlockItem` are
    /// located positionally, and their intervals hold the same candidate
    /// entries at the same deltas from their neighbours as on 24A435
    /// (`0x230, 0x3a0, 0x4c8, 0x5f0` after `lockItem` on both), which is the
    /// cross-check that the ordering rails still describe the same class.
    static let release24B5084kV1 = KernelCredentialManagerSignatureVariant(
        id: "ios272-24B5084k-acm-v1",
        functions: [
            // 27.2 file offset 0x217a600
            .init("sepManagerMatchedThreadCallHandler", words: "d503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 b0000030"),
            // 27.2 file offset 0x217ace4
            .init("callPlatformFunction", words: "d503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf f81ed3bf d10083a4 94000037 a9457bfd 910183ff"),
            // 27.2 file offset 0x217ad6c
            .init("cmdContextV2", words: "d503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 f81f53bf f81ed3bf d10083a4 94000014 a9457bfd"),
            // 27.2 file offset 0x217adf8
            .init("cmdContextV3", words: "d503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9"),
            // 27.2 file offset 0x217b190
            .init("performCommandGated", words: "d503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0"),
            // 27.2 file offset 0x217bc80
            .init("_performKernelControl", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 aa0303f7 aa0203f8 aa0103f4 aa0003f3 d000f71a"),
            // 27.2 file offset 0x217c040
            .init("_performCommand", words: "d503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6"),
            // 27.2 file offset 0x217c26c
            .init("processSCRDResponsePayload", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 b000f715 394902a8 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1"),
            // 27.2 file offset 0x217c49c
            .init("scheduleDblClickDeferredAck", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910"),
            // 27.2 file offset 0x217c5c0
            .init("updateAnalytics", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 b000f716 394902c8 f0ff2a55 913e5ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2a40 91321800 a90057e0 d0ff29c0", needsScoring: true),
            // 27.2 file offset 0x217c728
            .init("performSCRDInitialization", words: "d503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f714 39490288 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431"),
            // 27.2 file offset 0x217c9f0
            .init("sendSEPCommand", words: "d503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 b000f71b 39490368 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0", needsScoring: true),
            // 27.2 file offset 0x217d46c
            .init("_setPropertiesGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 b0ff6ca8 f947a108 f9400101 aa1303e0 94003dca b4001640"),
            // 27.2 file offset 0x217d8f8
            .init("performDoubleClickQueryGated", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 d2800004 d2800005 d2800006 52800027 97fffc2e"),
            // 27.2 file offset 0x217d9e8
            .init("performLoggingLevelQueryGated", words: "d503245f b40000c1 52800000 9000f708 39490108 f9000028 d65f03c0 d503237f d10103ff a9037bfd"),
            // 27.2 file offset 0x217de24
            .init("lockItem", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 9000f717 394902e8"),
            // 27.2 file offset 0x217e054
            .init("unlockItem", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 f000f6f6 394902c8 b0ff2a55 9118feb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 90ff2a40 91321800 a90057e0 90ff29c0", needsScoring: true),
            // 27.2 file offset 0x217e518
            .init("handleSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 d360ff19 f000f6f7 394902e8 53107f15 b0ff2a56"),
            // 27.2 file offset 0x217e804
            .init("readFromSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 aa1503e0 9400022e f940aaa0 b4000760 f9400010"),
            // 27.2 file offset 0x217e968
            .init("writeToSEPBuffer", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f8 aa0003f3 f000f6fc"),
            // 27.2 file offset 0x217ed14
            .init("sendSEPMessage", words: "d503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 f000f6f9 39490328 7100291f"),
            // 27.2 file offset 0x217ef50
            .init("clearSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0"),
            // 27.2 file offset 0x217f0f0
            .init("getSEPEndpoint", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 d000f6fb 39490368 7100291f 540002e8 39423268 360001a8"),
            // 27.2 file offset 0x217fd3c
            .init("powerOffActionGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f6f9 39490328 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // 27.2 file offset 0x217fff4
            .init("sepManagerMatchedGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f6e8 39490108 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // 27.2 file offset 0x218c498
            .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 b000f697 394902e8 f0ff29d6 91126ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 d0ff2940 91271400", needsScoring: true),
        ]
    )

    /// iOS 27.2 beta 2 `24B5089g`.
    ///
    /// Shape-identical to beta 1: probing `release24B5084kV1` against this
    /// kernelcache matches all twenty-six, with the same two positionally
    /// scored entries ambiguous as on every other build. No method body
    /// changed between the two seeds.
    ///
    /// It still gets its own family rather than reusing beta 1's. Matching is
    /// not the same as being the same bytes: fifteen of the twenty-four exact
    /// entries differ from beta 1's recorded words in ADRP pages, branch
    /// displacements and load immediates, which `allowDataLayoutDrift` masks.
    /// Sharing would therefore record one seed's addresses as if they were the
    /// other's, and the masking that makes it work would be hiding the
    /// difference rather than accounting for it.
    ///
    /// `updateAnalytics` and `unlockItem` are located positionally and their
    /// candidate entries sit at the same deltas from their neighbours as on
    /// beta 1 (0x124, and 0x230/0x3a0/0x4c8/0x5f0 after `lockItem`).
    static let release24B5089gV1 = KernelCredentialManagerSignatureVariant(
        id: "ios272b2-24B5089g-acm-v1",
        functions: [
            // beta 2 file offset 0x217bfc0
            .init("sepManagerMatchedThreadCallHandler", words: "d503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 d0000030"),
            // beta 2 file offset 0x217c6a4
            .init("callPlatformFunction", words: "d503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf f81ed3bf d10083a4 94000037 a9457bfd 910183ff"),
            // beta 2 file offset 0x217c72c
            .init("cmdContextV2", words: "d503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 f81f53bf f81ed3bf d10083a4 94000014 a9457bfd"),
            // beta 2 file offset 0x217c7b8
            .init("cmdContextV3", words: "d503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9"),
            // beta 2 file offset 0x217cb50
            .init("performCommandGated", words: "d503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0"),
            // beta 2 file offset 0x217d640
            .init("_performKernelControl", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 aa0303f7 aa0203f8 aa0103f4 aa0003f3 9000f73a"),
            // beta 2 file offset 0x217da00
            .init("_performCommand", words: "d503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6"),
            // beta 2 file offset 0x217dc2c
            .init("processSCRDResponsePayload", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f735 3948c2a8 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1"),
            // beta 2 file offset 0x217de5c
            .init("scheduleDblClickDeferredAck", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910"),
            // beta 2 file offset 0x217df80
            .init("updateAnalytics", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f736 3948c2c8 f0ff2a55 91301ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2a40 9123d800 a90057e0 d0ff29c0", needsScoring: true),
            // beta 2 file offset 0x217e0e8
            .init("performSCRDInitialization", words: "d503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 f000f714 3948c288 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431"),
            // beta 2 file offset 0x217e3b0
            .init("sendSEPCommand", words: "d503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 f000f71b 3948c368 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0", needsScoring: true),
            // beta 2 file offset 0x217ee2c
            .init("_setPropertiesGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 90ff6ca8 f947d508 f9400101 aa1303e0 94003dca b4001640"),
            // beta 2 file offset 0x217f2b8
            .init("performDoubleClickQueryGated", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 d2800004 d2800005 d2800006 52800027 97fffc2e"),
            // beta 2 file offset 0x217f3a8
            .init("performLoggingLevelQueryGated", words: "d503245f b40000c1 52800000 d000f708 3948c108 f9000028 d65f03c0 d503237f d10103ff a9037bfd"),
            // beta 2 file offset 0x217f7e4
            .init("lockItem", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 d000f717 3948c2e8"),
            // beta 2 file offset 0x217fa14
            .init("unlockItem", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f716 3948c2c8 b0ff2a55 910abeb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 90ff2a40 9123d800 a90057e0 90ff29c0", needsScoring: true),
            // beta 2 file offset 0x217fed8
            .init("handleSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 d360ff19 d000f717 3948c2e8 53107f15 b0ff2a56"),
            // beta 2 file offset 0x21801c4
            .init("readFromSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 aa1503e0 9400022e f940aaa0 b4000760 f9400010"),
            // beta 2 file offset 0x2180328
            .init("writeToSEPBuffer", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f8 aa0003f3 b000f71c"),
            // beta 2 file offset 0x21806d4
            .init("sendSEPMessage", words: "d503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 b000f719 3948c328 7100291f"),
            // beta 2 file offset 0x2180910
            .init("clearSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0"),
            // beta 2 file offset 0x2180ab0
            .init("getSEPEndpoint", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f71b 3948c368 7100291f 540002e8 39423268 360001a8"),
            // beta 2 file offset 0x21816fc
            .init("powerOffActionGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f719 3948c328 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // beta 2 file offset 0x21819b4
            .init("sepManagerMatchedGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f708 3948c108 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // beta 2 file offset 0x218de58
            .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f6b7 3948c2e8 f0ff29d6 91042ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 d0ff2940 9118d400", needsScoring: true),
        ]
    )

    /// iPad 8 A12 / T8020, iPadOS 26.7.1 23H30.
    /// Reuse the unchanged 24A435 shapes and replace eight drifted entries.
    /// The command/context call graph and setPowerStateGated diagnostic xref
    /// are recorded in docs/plans/IPAD8_26_7_1_PORT.md.
    /// updateAnalytics aliases unlockItem under the old signature; exclude it
    /// rather than patching the same entry twice. All 25 entries must be unique.
    /// setPowerStateGated moved beyond the old roster, so only this variant
    /// relaxes reference ordering. The PAC-less logging leaf keeps its BTI.
    static let release23H30V1 = KernelCredentialManagerSignatureVariant(
        id: "ios26-23H30-acm-v1",
        functions: release24A435V1.functions.filter { $0.name != "updateAnalytics" }.map { descriptor in
            switch descriptor.name {
            // PACIBSP; 0x60-byte frame; preserve x0...x6 before checking the
            // command type and tail-calling one of the context handlers.
            case "callPlatformFunction":
                return .init("callPlatformFunction", words: "d503237f d10183ff a90167fa a9025ff8 a90357f6 a9044ff4 a9057bfd 910143fd aa0603f3 aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f9 aa0003f8 d000dd88")
            // PACIBSP; x4 points to a V2 context: 32-bit command at +0,
            // pointer at +8, and a cleared byte in the stack copy at +12.
            case "cmdContextV2":
                return .init("cmdContextV2", words: "d503237f d101c3ff a90457f6 a9054ff4 a9067bfd 910183fd b4000484 aa0303f3 aa0203f4 aa0103f5 aa0003f6 b9400088 b90033e8 f9400488 f80343e8 3900f3ff")
            // PACIBSP; x4 points to a V3 context. Its byte at +12 is passed
            // to the common context helper before scheduling the same callback.
            case "cmdContextV3":
                return .init("cmdContextV3", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd b40004a4 aa0403f3 aa0303f4 aa0203f5 aa0103f6 aa0003f7 39403081 94000033 f9404ee0")
            // PACIBSP; 0xd0-byte frame, save x0...x4; the large gated body
            // directly calls _performKernelControl at 0x1b21244.
            case "performCommandGated":
                return .init("performCommandGated", words: "d503237f d10343ff a9076ffc a90867fa a9095ff8 a90a57f6 a90b4ff4 a90c7bfd 910303fd aa0403f4 aa0303f5 aa0203f8 aa0103f6 aa0003f3 b9006bff f90033ff")
            // PACIBSP; self-only entry checks the ACM state, then calls the
            // eight-argument command implementation below.
            case "performSCRDInitialization":
                return .init("performSCRDInitialization", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0003f3 b000dd95 394022a8 b0ff5254 91017a94 7100291f 540002a8 39423268 360001a8 f9400270")
            // PACIBSP; 0x110-byte frame saves x0...x7 and calls both the SEP
            // buffer writer and the message sender later in the body.
            case "sendSEPCommand":
                return .init("sendSEPCommand", words: "d503237f d10443ff 6d0a23e9 a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f9 aa0503f6 aa0403f5 aa0303f8 f90043e2 aa0103f4 aa0003f3 f81903a4 b000dd88 39402108 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208")
            // PACIBSP; five-argument message path uses getSEPEndpoint and
            // follows writeToSEPBuffer in this class's code layout.
            case "sendSEPMessage":
                return .init("sendSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 f90017ff f000dd79 39402328")
            // PACIBSP; preserves self and x1 power state. Later in this body,
            // ADRP/ADD names the setPowerStateGated diagnostic string.
            case "setPowerStateGated":
                return .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 b000dd18 39402308 b0ff51d7 9108eef7 7100a11f 540001c8 39423268 360003a8 97ffd0f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000013 b5000334 5280ce68 90ff51c9 9130fd29")
            default:
                return descriptor
            }
        },
        requiresReferenceOrder: false,
        preserveBareBTI: true
    )

    /// iOS 27.2 beta 3 `24B5099f`.
    ///
    /// Shape-identical to beta 2, and to beta 1 before it: probing
    /// `release24B5089gV1` against this kernelcache matches all twenty-six,
    /// with the usual two positionally scored entries ambiguous. No method
    /// body changed across the three seeds.
    ///
    /// Recorded as its own family for the same reason beta 2 was. Fifteen of
    /// the twenty-four exact entries differ from beta 2's recorded words in
    /// ADRP pages, branch displacements and load immediates, all masked by
    /// `allowDataLayoutDrift`. Reusing beta 2's entry would file one seed's
    /// addresses under the other's name.
    ///
    /// `updateAnalytics` and `unlockItem` are located positionally, at the
    /// same deltas from their neighbours as on both earlier seeds (0x124
    /// after `scheduleDblClickDeferredAck`, 0x230 after `lockItem`).
    static let release24B5099fV1 = KernelCredentialManagerSignatureVariant(
        id: "ios272b3-24B5099f-acm-v1",
        functions: [
            // beta 3 file offset 0x21015b0
            .init("sepManagerMatchedThreadCallHandler", words: "d503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 b0000030"),
            // beta 3 file offset 0x2101c94
            .init("callPlatformFunction", words: "d503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf f81ed3bf d10083a4 94000037 a9457bfd 910183ff"),
            // beta 3 file offset 0x2101d1c
            .init("cmdContextV2", words: "d503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 f81f53bf f81ed3bf d10083a4 94000014 a9457bfd"),
            // beta 3 file offset 0x2101da8
            .init("cmdContextV3", words: "d503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9"),
            // beta 3 file offset 0x2102140
            .init("performCommandGated", words: "d503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0"),
            // beta 3 file offset 0x2102c30
            .init("_performKernelControl", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 aa0303f7 aa0203f8 aa0103f4 aa0003f3 b000f39a"),
            // beta 3 file offset 0x2102ff0
            .init("_performCommand", words: "d503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6"),
            // beta 3 file offset 0x210321c
            .init("processSCRDResponsePayload", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f395 3971c2a8 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1"),
            // beta 3 file offset 0x210344c
            .init("scheduleDblClickDeferredAck", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910"),
            // beta 3 file offset 0x2103570
            .init("updateAnalytics", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f396 3971c2c8 d0ff2dd5 912b1ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2dc0 911ed800 a90057e0 b0ff2d40", needsScoring: true),
            // beta 3 file offset 0x21036d8
            .init("performSCRDInitialization", words: "d503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f394 3971c288 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431"),
            // beta 3 file offset 0x21039a0
            .init("sendSEPCommand", words: "d503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 9000f39b 3971c368 7100291f 540002e8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0", needsScoring: true),
            // beta 3 file offset 0x210441c
            .init("_setPropertiesGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 f0ff6ea8 f946ad08 f9400101 aa1303e0 94003dca b4001640"),
            // beta 3 file offset 0x21048a8
            .init("performDoubleClickQueryGated", words: "d503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 d2800004 d2800005 d2800006 52800027 97fffc2e"),
            // beta 3 file offset 0x2104998
            .init("performLoggingLevelQueryGated", words: "d503245f b40000c1 52800000 f000f368 3971c108 f9000028 d65f03c0 d503237f d10103ff a9037bfd"),
            // beta 3 file offset 0x2104dd4
            .init("lockItem", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 f000f377 3971c2e8"),
            // beta 3 file offset 0x2105004
            .init("unlockItem", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f376 3971c2c8 90ff2dd5 9105beb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 f0ff2da0 911ed800 a90057e0 f0ff2d20", needsScoring: true),
            // beta 3 file offset 0x21054c8
            .init("handleSEPMessage", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 d360ff19 d000f377 3971c2e8 53107f15 90ff2dd6"),
            // beta 3 file offset 0x21057b4
            .init("readFromSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 aa1503e0 9400022e f940aaa0 b4000760 f9400010"),
            // beta 3 file offset 0x2105918
            .init("writeToSEPBuffer", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 aa0303f6 aa0203f7 aa0103f8 aa0003f3 d000f37c"),
            // beta 3 file offset 0x2105cc4
            .init("sendSEPMessage", words: "d503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 aa0103f4 aa0003f3 d000f379 3971c328 7100291f"),
            // beta 3 file offset 0x2105f00
            .init("clearSEPBuffer", words: "d503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0"),
            // beta 3 file offset 0x21060a0
            .init("getSEPEndpoint", words: "d503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f37b 3971c368 7100291f 540002e8 39423268 360001a8"),
            // beta 3 file offset 0x2106cec
            .init("powerOffActionGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f379 3971c328 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // beta 3 file offset 0x2106fa4
            .init("sepManagerMatchedGated", words: "d503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f368 3971c108 7100a11f 540002e8 39423268 360001a8 f9400270"),
            // beta 3 file offset 0x2113448
            .init("setPowerStateGated", words: "d503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f317 3971c2e8 b0ff2d56 913f2ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 b0ff2cc0 9113d400", needsScoring: true),
        ]
    )

    static func variant(named id: String) -> KernelCredentialManagerSignatureVariant? {
        switch id {
        case earlyBetaV1.id: return earlyBetaV1
        case release24A435V1.id: return release24A435V1
        case release24B5084kV1.id: return release24B5084kV1
        case release24B5089gV1.id: return release24B5089gV1
        case release23H30V1.id: return release23H30V1
        case release24B5099fV1.id: return release24B5099fV1
        default: return nil
        }
    }
}
