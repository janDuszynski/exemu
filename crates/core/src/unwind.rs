//! x64 unwind metadata — the parsed `.pdata`/`.xdata` function table
//! (roadmap P4.1).
//!
//! Every non-leaf x64 function carries a `RUNTIME_FUNCTION` record in the
//! exception data directory pointing at an `UNWIND_INFO` blob that describes
//! its prolog: which nonvolatile registers were pushed/saved where, how much
//! stack was allocated, and whether a frame pointer was established. Walking
//! these codes *backwards* recovers the caller's RSP and nonvolatile registers
//! from any rip inside the function — the foundation of SEH and C++ exception
//! dispatch (roadmap P4.2/P4.3).
//!
//! This module is the byte-order-neutral domain model; `exemu-loader` parses
//! the on-disk structures into it.

/// One entry of the function table: a function's rip extent plus its fully
/// parsed unwind description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindEntry {
    /// RVA of the first byte of the function (or chained-range fragment).
    pub begin_rva: u32,
    /// RVA one past the last byte of the range (exclusive).
    pub end_rva: u32,
    pub info: UnwindInfo,
}

/// A parsed `UNWIND_INFO` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    /// Format version (1 or 2).
    pub version: u8,
    /// `UNW_FLAG_EHANDLER` — `handler_rva` participates in exception search.
    pub has_exception_handler: bool,
    /// `UNW_FLAG_UHANDLER` — `handler_rva` participates in unwinding.
    pub has_termination_handler: bool,
    /// Length of the function prolog in bytes.
    pub prolog_size: u8,
    /// The established frame-pointer register (x64 register number), if any.
    pub frame_register: Option<u8>,
    /// Offset from RSP applied when the frame register was established
    /// (already scaled ×16; meaningful only with `frame_register`).
    pub frame_offset: u16,
    /// Prolog unwind operations, ordered by descending `prolog_offset`
    /// (the on-disk order — the order they must be undone in).
    pub codes: Vec<UnwindCode>,
    /// RVA of the language-specific handler (`__C_specific_handler`,
    /// `__CxxFrameHandler3/4`, …) when either handler flag is set.
    pub handler_rva: Option<u32>,
    /// `UNW_FLAG_CHAININFO` — the primary entry this fragment continues
    /// (its codes apply after ours when unwinding).
    pub chained: Option<Box<UnwindEntry>>,
}

/// One prolog unwind operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    /// Offset of the end of the instruction this op describes, from the start
    /// of the prolog. Ops with `prolog_offset > (rip - begin)` haven't
    /// executed yet at that rip and are skipped when unwinding.
    pub prolog_offset: u8,
    pub op: UnwindOp,
}

/// The unwind operation kinds (`UWOP_*`), with their operands decoded and
/// scale factors already applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindOp {
    /// `UWOP_PUSH_NONVOL` — the prolog pushed this register.
    PushNonvolatile { reg: u8 },
    /// `UWOP_ALLOC_SMALL` / `UWOP_ALLOC_LARGE` — the prolog subtracted
    /// `size` bytes from RSP (size already unscaled).
    Alloc { size: u32 },
    /// `UWOP_SET_FPREG` — the prolog set the frame register to
    /// `RSP + frame_offset` (see [`UnwindInfo`]).
    SetFrameRegister,
    /// `UWOP_SAVE_NONVOL(_FAR)` — register saved with `mov` at
    /// `RSP + offset` (offset already unscaled).
    SaveNonvolatile { reg: u8, offset: u32 },
    /// `UWOP_SAVE_XMM128(_FAR)` — XMM register saved at `RSP + offset`.
    SaveXmm128 { reg: u8, offset: u32 },
    /// `UWOP_PUSH_MACHFRAME` — a hardware exception frame was pushed.
    PushMachineFrame { with_error_code: bool },
    /// `UWOP_EPILOG` (version 2) — epilog-location metadata; irrelevant to
    /// frame recovery, kept raw for completeness.
    Epilog { raw: u16 },
}

/// Look up the [`UnwindEntry`] covering `rva` in a function table sorted by
/// `begin_rva` (as [`crate::PeImage`] stores it). Binary search; `end_rva`
/// is exclusive, matching `RtlLookupFunctionEntry`.
pub fn lookup(table: &[UnwindEntry], rva: u32) -> Option<&UnwindEntry> {
    let idx = table.partition_point(|e| e.begin_rva <= rva);
    let e = table.get(idx.checked_sub(1)?)?;
    (rva < e.end_rva).then_some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(begin: u32, end: u32) -> UnwindEntry {
        UnwindEntry {
            begin_rva: begin,
            end_rva: end,
            info: UnwindInfo {
                version: 1,
                has_exception_handler: false,
                has_termination_handler: false,
                prolog_size: 0,
                frame_register: None,
                frame_offset: 0,
                codes: Vec::new(),
                handler_rva: None,
                chained: None,
            },
        }
    }

    #[test]
    fn lookup_finds_covering_entry() {
        let table = vec![entry(0x1000, 0x1050), entry(0x1050, 0x10a0), entry(0x2000, 0x2010)];
        assert_eq!(lookup(&table, 0x1000).unwrap().begin_rva, 0x1000);
        assert_eq!(lookup(&table, 0x104f).unwrap().begin_rva, 0x1000);
        // end_rva is exclusive — 0x1050 belongs to the *next* function.
        assert_eq!(lookup(&table, 0x1050).unwrap().begin_rva, 0x1050);
        assert_eq!(lookup(&table, 0x2005).unwrap().begin_rva, 0x2000);
    }

    #[test]
    fn lookup_misses_outside_any_range() {
        let table = vec![entry(0x1000, 0x1050), entry(0x2000, 0x2010)];
        assert!(lookup(&table, 0x0fff).is_none()); // before the first
        assert!(lookup(&table, 0x1234).is_none()); // in the gap
        assert!(lookup(&table, 0x2010).is_none()); // exactly at an exclusive end
        assert!(lookup(&[], 0x1000).is_none());
    }
}
