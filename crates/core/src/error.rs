//! Error type shared across the whole emulator.
//!
//! Hand-written rather than derived so that the domain crate keeps its
//! promise of zero dependencies (no `thiserror`).

use core::fmt;

/// Convenient result alias used throughout the workspace.
pub type Result<T> = core::result::Result<T, EmuError>;

/// Every failure the emulator can surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmuError {
    /// A memory access touched an address that is not mapped.
    Unmapped { addr: u64, len: usize },
    /// A memory access violated the permissions of its region
    /// (e.g. writing to read-only, or executing non-executable memory).
    Permission { addr: u64, needed: &'static str },
    /// Two mapped regions would overlap.
    Overlap { addr: u64, len: u64 },
    /// The decoder met bytes it does not understand.
    Decode { rip: u64, opcode: String },
    /// A structurally valid instruction that the interpreter has not (yet)
    /// been taught to execute.
    Unsupported(String),
    /// The input was not a PE image we can load.
    InvalidPe(String),
    /// An emulated OS service failed.
    Os(String),
    /// Host-side I/O failure while reading the executable etc.
    Io(String),
    /// A runtime fault wrapped with a full human-readable diagnostic `report`
    /// (register dump, faulting bytes, rip trail) while **preserving** the
    /// structured `cause`. Keeping the cause is what lets callers still tell
    /// *what* faulted after the report is attached — e.g. the opcode-miss
    /// telemetry keys off an [`EmuError::Decode`] inside it (roadmap P0.5).
    Fault { report: String, cause: Box<EmuError> },
}

impl EmuError {
    /// The underlying structured error, unwrapping any [`EmuError::Fault`]
    /// diagnostic wrapper (recursively). Returns `self` for non-fault errors.
    /// Match on this instead of the raw error when you care about the *kind* of
    /// failure rather than its rendered report.
    pub fn cause(&self) -> &EmuError {
        match self {
            EmuError::Fault { cause, .. } => cause.cause(),
            other => other,
        }
    }
}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmuError::Unmapped { addr, len } => {
                write!(f, "unmapped memory access at {addr:#018x} ({len} bytes)")
            }
            EmuError::Permission { addr, needed } => {
                write!(f, "permission fault at {addr:#018x}: {needed} access denied")
            }
            EmuError::Overlap { addr, len } => {
                write!(f, "region overlap at {addr:#018x} ({len} bytes)")
            }
            EmuError::Decode { rip, opcode } => {
                write!(f, "cannot decode instruction at {rip:#018x}: {opcode}")
            }
            EmuError::Unsupported(what) => write!(f, "unsupported: {what}"),
            EmuError::InvalidPe(why) => write!(f, "invalid PE image: {why}"),
            EmuError::Os(why) => write!(f, "emulated OS error: {why}"),
            EmuError::Io(why) => write!(f, "io error: {why}"),
            // The report already opens with the cause's own message, so render
            // it verbatim — the structured cause is for programmatic callers.
            EmuError::Fault { report, .. } => write!(f, "{report}"),
        }
    }
}

impl std::error::Error for EmuError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cause_unwraps_nested_faults() {
        let decode = EmuError::Decode { rip: 0x1400, opcode: "0xd9".into() };
        // A fault wrapping the decode error still reports the structured cause.
        let faulted = EmuError::Fault { report: "big diagnostic".into(), cause: Box::new(decode.clone()) };
        assert_eq!(faulted.cause(), &decode);
        // Nested wrappers unwrap all the way down.
        let double = EmuError::Fault { report: "outer".into(), cause: Box::new(faulted) };
        assert_eq!(double.cause(), &decode);
        // A non-fault error is its own cause.
        assert_eq!(decode.cause(), &decode);
    }

    #[test]
    fn fault_display_is_just_the_report() {
        let e = EmuError::Fault {
            report: "cannot decode instruction at 0x1400: 0xd9\n  faulted after 0 instructions".into(),
            cause: Box::new(EmuError::Decode { rip: 0x1400, opcode: "0xd9".into() }),
        };
        assert!(e.to_string().starts_with("cannot decode instruction"));
        assert!(!e.to_string().contains("emulated OS error"));
    }
}
