import Foundation

/// Whether the normal-boot artifacts should make the device report a demoted
/// application processor.
///
/// Exists for exactly one purpose: baseband calibration. `libFDR.dylib` refuses to
/// unseal the factory `bbcl` blob because the FDR instance identity is a SEP key
/// attestation (`aks_sik_attest`) a Liter8 device cannot reproduce, so `calib.nvm`
/// is never written and the modem runs uncalibrated. `libFDR` skips that check when
/// `AMFDRIsNonDefaultDemotionState` holds, which is three MobileGestalt reads and no
/// SEP call:
///
///     CertificateSecurityMode && EffectiveSecurityModeSEP && !EffectiveProductionStatusAp
///
/// On n104ap `certificate-security-mode` already reads 1, so two terms remain and
/// they need different levers, because iBoot overwrites most of `/chosen` at boot
/// from the chip's real fusing state while leaving others alone:
///
/// - `effective-security-mode-sep` is never written by iBoot, so the DeviceTree
///   plan sets it to 1 and the value survives.
/// - `effective-production-status-ap` *is* written by iBoot, so
///   `IBootProductionStatusResolver` suppresses the publish and the DeviceTree's
///   own 0 survives.
///
/// Off by default, and it must stay that way. These are the device's advertised
/// security state, read by far more than AMFDR, and no boot has been shown to
/// survive the claim on a production-fused part. See
/// docs/design/BASEBAND_AND_CELLULAR.md.
///
/// Read on each access rather than cached, so a test that sets the variable does
/// not depend on whether some earlier code already looked.
public enum APDemotion: Sendable {
    /// The environment variable `--demote-ap` sets.
    public static let environmentKey = "LITER8_DEMOTE_AP"

    public static var isRequested: Bool {
        ProcessInfo.processInfo.environment[environmentKey] == "1"
    }
}
