import Foundation

/// Whether the boot-argument literals should route the kernel console to the
/// serial port.
///
/// Off by default, because `serial=3` moves the console to the UART and the
/// device stops drawing the verbose boot log on its own screen. Anyone without
/// a serial cable would be left with no log at all, which is the opposite of
/// what `-v` is in these literals for.
///
/// The choice has to be made when the artifact is built, not when it boots: the
/// literal is written into iBSS and iBEC by `fw make-cfw`, `fw get-rd` and
/// `fw get-boot`, so changing it afterwards means rebuilding and reflashing.
/// Those three commands take `--serial`, which arrives here as an environment
/// variable rather than being threaded through the Python workflow, the same way
/// the identity oracles and `--irecovery` already reach the scripts.
///
/// Read on each access rather than cached, so a test or a caller that sets the
/// variable does not depend on whether some earlier code already looked.
public enum SerialConsole: Sendable {
    /// The environment variable `--serial` sets.
    public static let environmentKey = "LITER8_SERIAL"

    /// `serial=3` is output plus input. The value is fixed rather than
    /// caller-supplied: these literals are size-constrained and a free-form
    /// value would be one more thing that can silently overflow the slot.
    public static let argument = "serial=3"

    public static var isRequested: Bool {
        ProcessInfo.processInfo.environment[environmentKey] == "1"
    }

    /// Append `serial=3` to a base literal when requested.
    ///
    /// Returns the base unchanged when it is not, so the default literals stay
    /// exactly what they were before serial support existed.
    public static func applied(to base: String) -> String {
        isRequested ? "\(base) \(argument)" : base
    }
}
