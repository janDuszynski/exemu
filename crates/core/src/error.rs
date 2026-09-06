use core::fmt;

pub type Result<T> = core::result::Result<T, EmuError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmuError {
    Unmapped { addr: u64, len: usize },
    Permission { addr: u64, needed: &'static str },
    Overlap { addr: u64, len: u64 },
    Decode { rip: u64, opcode: String },
    Unsupported(String),
    InvalidPe(String),
    Os(String),
    Io(String),
    Fault { report: String, cause: Box<EmuError> },
}

impl EmuError {
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
        let faulted = EmuError::Fault { report: "big diagnostic".into(), cause: Box::new(decode.clone()) };
        assert_eq!(faulted.cause(), &decode);
        let double = EmuError::Fault { report: "outer".into(), cause: Box::new(faulted) };
        assert_eq!(double.cause(), &decode);
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
