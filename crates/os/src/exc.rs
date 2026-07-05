//! Native x64 exception surface (roadmap P4.3): the `CONTEXT` record
//! marshalling and the `Rtl*` entry points the guest's statically-linked
//! frame handlers call.
//!
//! In a statically-linked MSVC binary the *language* handlers
//! (`__C_specific_handler`, `__CxxFrameHandler3/4`) are guest code. The NT
//! runtime underneath them is what exemu must provide: capture/restore a
//! `CONTEXT`, look up a function's unwind entry, virtually unwind a frame,
//! and drive the search/unwind dispatch loop (`RaiseException`/`RtlUnwindEx`).
//! This module holds the machine-level pieces; [`crate::WinOs`] wires them to
//! the API dispatch and the re-entrant guest-call machinery.

use exemu_core::{CpuState, Memory, Result};

/// Total size of an x64 `CONTEXT` structure (`sizeof(CONTEXT)`), what callers
/// reserve on the stack and what `RtlCaptureContext` fills. Used by exception
/// dispatch (roadmap P4.3c) to carve a CONTEXT for `RaiseException`.
#[allow(dead_code)]
pub(crate) const CONTEXT_SIZE: u64 = 0x4d0;

// Field offsets within CONTEXT (winnt.h, AMD64). Only the ones we model.
const OFF_CONTEXT_FLAGS: u64 = 0x30;
const OFF_MXCSR: u64 = 0x34;
const OFF_EFLAGS: u64 = 0x44;
/// The 16 GP registers are contiguous from 0x78 in exactly x86-64 encoding
/// order (Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8..R15) — the same order
/// as [`exemu_core::Reg`], so `gpr[i]` maps to `OFF_GPR + i*8`.
const OFF_GPR: u64 = 0x78;
const OFF_RIP: u64 = 0xf8;
/// Xmm0 within the embedded XSAVE/legacy area; Xmm0..Xmm15 step by 16.
const OFF_XMM0: u64 = 0x1a0;

/// `CONTEXT.ContextFlags` bits we honour. The CRT sets `CONTEXT_ALL`; we
/// always marshal the full integer + control + XMM state regardless, so the
/// flags are written for the guest's benefit but not gated on.
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
const CONTEXT_ALL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

/// Write `state` into a guest `CONTEXT` at `addr` (integer + control + XMM).
pub(crate) fn write_context(mem: &mut dyn Memory, addr: u64, state: &CpuState) -> Result<()> {
    mem.write_u32(addr + OFF_CONTEXT_FLAGS, CONTEXT_ALL)?;
    mem.write_u32(addr + OFF_MXCSR, 0x1f80)?; // default MXCSR
    mem.write_u32(addr + OFF_EFLAGS, state.rflags as u32)?;
    for (i, &v) in state.gpr.iter().enumerate() {
        mem.write_u64(addr + OFF_GPR + i as u64 * 8, v)?;
    }
    mem.write_u64(addr + OFF_RIP, state.rip)?;
    for (i, &v) in state.xmm.iter().enumerate() {
        mem.write(addr + OFF_XMM0 + i as u64 * 16, &v.to_le_bytes())?;
    }
    Ok(())
}

/// Read a guest `CONTEXT` at `addr` into a fresh [`CpuState`]. The reserved
/// upper flag bits are normalized so the result is a legal RFLAGS value.
pub(crate) fn read_context(mem: &dyn Memory, addr: u64) -> Result<CpuState> {
    let mut s = CpuState::new();
    for i in 0..16 {
        s.gpr[i] = mem.read_u64(addr + OFF_GPR + i as u64 * 8)?;
    }
    s.rip = mem.read_u64(addr + OFF_RIP)?;
    let eflags = mem.read_u32(addr + OFF_EFLAGS)? as u64;
    s.rflags = (eflags & !exemu_core::flags::RESERVED_ONE) | exemu_core::flags::RESERVED_ONE;
    for i in 0..16 {
        let mut b = [0u8; 16];
        mem.read(addr + OFF_XMM0 + i as u64 * 16, &mut b)?;
        s.xmm[i] = u128::from_le_bytes(b);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Flat(Vec<u8>);
    impl Memory for Flat {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let o = addr as usize;
            buf.copy_from_slice(&self.0[o..o + buf.len()]);
            Ok(())
        }
        fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let o = addr as usize;
            self.0[o..o + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn context_round_trips_all_state() {
        let mut mem = Flat(vec![0u8; 0x1000]);
        let mut s = CpuState::new();
        for i in 0..16 {
            s.gpr[i] = 0x1000 + i as u64;
            s.xmm[i] = (i as u128) << 64 | 0xdead_beef;
        }
        s.rip = 0x1_4000_1234;
        s.set_rsp(0x8_0000);
        s.rflags = exemu_core::flags::RESERVED_ONE | exemu_core::flags::CF | exemu_core::flags::ZF;

        write_context(&mut mem, 0x100, &s).unwrap();
        let back = read_context(&mem, 0x100).unwrap();

        assert_eq!(back.gpr, s.gpr);
        assert_eq!(back.xmm, s.xmm);
        assert_eq!(back.rip, s.rip);
        assert_eq!(back.rsp(), 0x8_0000);
        assert_eq!(back.rflags & 0xffff_ffff, s.rflags & 0xffff_ffff);
    }

    #[test]
    fn context_places_rsp_and_rip_at_abi_offsets() {
        // Guard the fixed offsets a guest handler depends on: Rsp at +0x98,
        // Rip at +0xf8.
        let mut mem = Flat(vec![0u8; 0x1000]);
        let mut s = CpuState::new();
        s.set_rsp(0xAAAA);
        s.rip = 0xBBBB;
        write_context(&mut mem, 0, &s).unwrap();
        assert_eq!(mem.read_u64(0x98).unwrap(), 0xAAAA);
        assert_eq!(mem.read_u64(0xf8).unwrap(), 0xBBBB);
    }
}
