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
}

/// Build-family-specific locator data for AppleCredentialManager.
///
/// Beta 2 and beta 4 share this variant because masked matching proved their
/// function shapes compatible. Release build 24A435 is intentionally absent:
/// its dedicated profile remains `pending-research` until those bodies are
/// reversed and reviewed.
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

    static func variant(named id: String) -> KernelCredentialManagerSignatureVariant? {
        switch id {
        case earlyBetaV1.id: return earlyBetaV1
        default: return nil
        }
    }
}
