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
        }
    }
}

impl std::error::Error for EmuError {}
