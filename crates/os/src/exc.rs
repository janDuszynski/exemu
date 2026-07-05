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
/// reserve on the stack and what `RtlCaptureContext` fills.
pub(crate) const CONTEXT_SIZE: u64 = 0x4d0;

// ---- EXCEPTION_RECORD (x64) -------------------------------------------------

/// `sizeof(EXCEPTION_RECORD)` — header (0x20) + 15 information slots.
pub(crate) const EXCEPTION_RECORD_SIZE: u64 = 0x20 + 15 * 8;
const ER_CODE: u64 = 0x00;
const ER_FLAGS: u64 = 0x04;
const ER_NESTED: u64 = 0x08;
const ER_ADDRESS: u64 = 0x10;
const ER_NUM_PARAMS: u64 = 0x18;
const ER_INFO: u64 = 0x20;

/// `EXCEPTION_RECORD.ExceptionFlags` bit: set while running the unwind phase.
pub(crate) const EXCEPTION_UNWINDING: u32 = 0x2;

/// The MSVC C++ exception code (`'msc' | 0xE0000000`), recognized for tracing.
pub(crate) const STATUS_CXX_EXCEPTION: u32 = 0xE06D_7363;

/// `EXCEPTION_DISPOSITION`: a search-phase handler that returns this wants the
/// faulting instruction re-executed (it fixed up the state).
pub(crate) const EXCEPTION_CONTINUE_EXECUTION: u64 = 0;

/// Write an `EXCEPTION_RECORD` at `addr`. `params` are the
/// `ExceptionInformation` slots (truncated to 15).
pub(crate) fn write_exception_record(
    mem: &mut dyn Memory,
    addr: u64,
    code: u32,
    flags: u32,
    address: u64,
    params: &[u64],
) -> Result<()> {
    mem.write_u32(addr + ER_CODE, code)?;
    mem.write_u32(addr + ER_FLAGS, flags)?;
    mem.write_u64(addr + ER_NESTED, 0)?;
    mem.write_u64(addr + ER_ADDRESS, address)?;
    let n = params.len().min(15);
    mem.write_u32(addr + ER_NUM_PARAMS, n as u32)?;
    for (i, &p) in params.iter().take(15).enumerate() {
        mem.write_u64(addr + ER_INFO + i as u64 * 8, p)?;
    }
    Ok(())
}

/// Overwrite just the `ExceptionFlags` field (search ↔ unwind phase toggling).
pub(crate) fn set_record_flags(mem: &mut dyn Memory, addr: u64, flags: u32) -> Result<()> {
    mem.write_u32(addr + ER_FLAGS, flags)
}

pub(crate) fn record_flags(mem: &dyn Memory, addr: u64) -> Result<u32> {
    mem.read_u32(addr + ER_FLAGS)
}

// ---- DISPATCHER_CONTEXT (x64) ----------------------------------------------

/// `sizeof(DISPATCHER_CONTEXT)` (through ScopeIndex + padding).
pub(crate) const DISPATCHER_CONTEXT_SIZE: u64 = 0x50;

/// The fields a language handler reads from its `DISPATCHER_CONTEXT`.
pub(crate) struct DispatcherContext {
    pub control_pc: u64,
    pub image_base: u64,
    pub function_entry: u64,
    pub establisher_frame: u64,
    pub target_ip: u64,
    pub context_record: u64,
    pub language_handler: u64,
    pub handler_data: u64,
}

/// Write a `DISPATCHER_CONTEXT` at `addr` (HistoryTable/ScopeIndex zeroed).
pub(crate) fn write_dispatcher_context(
    mem: &mut dyn Memory,
    addr: u64,
    d: &DispatcherContext,
) -> Result<()> {
    mem.write_u64(addr, d.control_pc)?;
    mem.write_u64(addr + 0x08, d.image_base)?;
    mem.write_u64(addr + 0x10, d.function_entry)?;
    mem.write_u64(addr + 0x18, d.establisher_frame)?;
    mem.write_u64(addr + 0x20, d.target_ip)?;
    mem.write_u64(addr + 0x28, d.context_record)?;
    mem.write_u64(addr + 0x30, d.language_handler)?;
    mem.write_u64(addr + 0x38, d.handler_data)?;
    mem.write_u64(addr + 0x40, 0)?; // HistoryTable
    mem.write_u64(addr + 0x48, 0)?; // ScopeIndex + Fill0
    Ok(())
}

/// Which phase of dispatch a [`DispatchFrame`] is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// `RaiseException` search: offer each frame's handler the exception.
    Search,
    /// `RtlUnwindEx` unwind: run each frame's termination handler up to the
    /// target frame, then transfer control to `target_ip`.
    Unwind,
}

/// One in-flight exception dispatch (roadmap P4.3c). Threaded through the
/// exception driver thunk exactly like [`crate::api::CbFrame`], so guest
/// language handlers run re-entrantly and we resume the walk when they return.
pub(crate) struct DispatchFrame {
    pub phase: Phase,
    /// Guest `EXCEPTION_RECORD` pointer.
    pub record: u64,
    /// The original exception context (passed to handlers as `ContextRecord`).
    pub orig_context: u64,
    /// The working context, progressively unwound frame by frame.
    pub work_context: u64,
    /// Scratch `DISPATCHER_CONTEXT` reused across this dispatch's handler calls.
    pub dispatcher: u64,
    /// Stack pointer used as the base for each re-entrant handler call.
    pub final_rsp: u64,
    /// Scratch per-frame context handed to a handler as
    /// `DISPATCHER_CONTEXT.ContextRecord` (the frame's own, pre-unwind state).
    pub frame_context: u64,
    /// Unwind phase: stop when a frame's establisher frame reaches this, then
    /// resume at `target_ip` with `return_value` in RAX.
    pub target_frame: u64,
    pub target_ip: u64,
    pub return_value: u64,
}

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

// ---- the dispatch state machine (methods on WinOs) --------------------------

use crate::api::Outcome;
use crate::WinOs;
use exemu_core::{HandlerType, Reg};

/// Walk-length guard: a corrupt frame chain must not loop forever.
const MAX_DISPATCH_FRAMES: u32 = 4096;

impl WinOs {
    /// `RaiseException` / `RtlRaiseException` — begin exception dispatch
    /// (roadmap P4.3c). Builds the `EXCEPTION_RECORD`, captures the raising
    /// context, and drives the search phase over the guest frames.
    pub(crate) fn raise_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as u32;
        let flags = self.arg(cpu, mem, 1)? as u32;
        let nparams = self.arg(cpu, mem, 2)? as usize;
        let args_ptr = self.arg(cpu, mem, 3)?;

        // The exception address is RaiseException's caller (return address).
        let ret_addr = mem.read_u64(cpu.rsp())?;
        let final_rsp = cpu.rsp() + 8;

        let mut params = Vec::new();
        if args_ptr != 0 {
            for i in 0..nparams.min(15) {
                params.push(mem.read_u64(args_ptr + i as u64 * 8)?);
            }
        }

        let Some((record, orig_context, work_context, frame_context, dispatcher)) =
            self.alloc_dispatch_buffers()
        else {
            return Err(exemu_core::EmuError::Os("out of heap for exception dispatch".into()));
        };

        // Capture the raising context: RIP at the raise site, RSP post-return.
        let mut snap = cpu.clone();
        snap.rip = ret_addr;
        snap.set_rsp(final_rsp);
        write_context(mem, orig_context, &snap)?;
        write_context(mem, work_context, &snap)?;
        write_exception_record(mem, record, code, flags, ret_addr, &params)?;

        if self.cfg.trace {
            let kind = if code == STATUS_CXX_EXCEPTION { " (C++ throw)" } else { "" };
            eprintln!("[exemu] RaiseException code={code:#x}{kind} flags={flags:#x} at {ret_addr:#x}");
        }

        self.exc_stack.push(DispatchFrame {
            phase: Phase::Search,
            record,
            orig_context,
            work_context,
            dispatcher,
            frame_context,
            final_rsp,
            target_frame: 0,
            target_ip: 0,
            return_value: 0,
        });
        self.pump_dispatch(cpu, mem)
    }

    /// `RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
    /// ContextRecord, HistoryTable)` — a language handler calls this to unwind
    /// the stack to a catch. Runs each intervening frame's termination handler,
    /// then transfers control to `TargetIp`.
    pub(crate) fn rtl_unwind_ex(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let target_frame = self.arg(cpu, mem, 0)?;
        let target_ip = self.arg(cpu, mem, 1)?;
        let record = self.arg(cpu, mem, 2)?;
        let return_value = self.arg(cpu, mem, 3)?;
        let ctx_in = self.arg(cpu, mem, 4)?;

        let final_rsp = cpu.rsp() + 8;

        let Some((_r, orig_context, work_context, frame_context, dispatcher)) =
            self.alloc_dispatch_buffers()
        else {
            return Err(exemu_core::EmuError::Os("out of heap for unwind".into()));
        };
        // Seed the working context from the caller-supplied ContextRecord (the
        // point unwinding starts from); keep the record it handed us.
        let start = if ctx_in != 0 { read_context(mem, ctx_in)? } else { cpu.clone() };
        write_context(mem, work_context, &start)?;
        write_context(mem, orig_context, &start)?;
        let record = if record != 0 { record } else { self.exc_stack.last().map(|f| f.record).unwrap_or(0) };

        if self.cfg.trace {
            eprintln!("[exemu] RtlUnwindEx → frame {target_frame:#x} ip {target_ip:#x}");
        }

        self.exc_stack.push(DispatchFrame {
            phase: Phase::Unwind,
            record,
            orig_context,
            work_context,
            dispatcher,
            frame_context,
            final_rsp,
            target_frame,
            target_ip,
            return_value,
        });
        self.pump_dispatch(cpu, mem)
    }

    /// A guest exception/termination handler returned to the driver thunk:
    /// inspect its disposition and continue the walk.
    pub(crate) fn exc_advance(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let Some(frame) = self.exc_stack.last() else {
            // No active dispatch (defensive): just resume.
            return Ok(Outcome::Return(0));
        };
        // In the search phase a handler that wants to catch never returns here
        // (it calls RtlUnwindEx, which transfers control). A return means either
        // "continue searching" (the common case) or "continue execution" — the
        // handler fixed up state and wants the faulting instruction retried. In
        // the unwind phase a termination handler just falls through.
        let disposition = cpu.reg(Reg::Rax);
        if frame.phase == Phase::Search && disposition == EXCEPTION_CONTINUE_EXECUTION {
            let resume = read_context(mem, frame.orig_context)?;
            *cpu = resume;
            self.exc_stack.clear();
            return Ok(Outcome::Resume);
        }
        self.pump_dispatch(cpu, mem)
    }

    /// Advance the top dispatch until a handler is invoked (returns
    /// [`Outcome::Resume`]), control transfers to a catch, or the walk ends.
    fn pump_dispatch(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let image_base = self.cfg.image_base;
        for _ in 0..MAX_DISPATCH_FRAMES {
            let frame = self.exc_stack.last().expect("pump_dispatch without a frame");
            let (phase, work, record, dispatcher, frame_ctx, orig_ctx) = (
                frame.phase,
                frame.work_context,
                frame.record,
                frame.dispatcher,
                frame.frame_context,
                frame.orig_context,
            );
            let (target_frame, target_ip, return_value, handler_base) =
                (frame.target_frame, frame.target_ip, frame.return_value, frame.final_rsp);

            let mut state = read_context(mem, work)?;
            let control_pc = state.rip;

            // Off the top of the guest stack (into the OS thunk region or null):
            // no more guest frames to consider.
            if control_pc == 0 || control_pc >= self.cfg.api_base {
                return self.finish_dispatch(cpu, mem);
            }

            let entry = control_pc
                .checked_sub(image_base)
                .and_then(|off| u32::try_from(off).ok())
                .and_then(|rva| exemu_core::unwind::lookup(&self.function_table, rva));
            let Some(_entry) = entry else {
                // Leaf frame: pop the return address and keep walking.
                let ret = mem.read_u64(state.rsp())?;
                state.rip = ret;
                state.set_rsp(state.rsp() + 8);
                write_context(mem, work, &state)?;
                continue;
            };

            // Unwind this frame to the caller, learning its establisher frame
            // and (phase-filtered) language handler.
            let ht = match phase {
                Phase::Search => HandlerType::EXCEPTION,
                Phase::Unwind => HandlerType::UNWIND,
            };
            let pre_unwind = state.clone();
            let mut caller = state;
            let fu = exemu_core::unwind::virtual_unwind_typed(
                &self.function_table,
                image_base,
                &mut caller,
                mem,
                ht,
            )?;

            // Unwind phase: reaching the target frame ends the unwind — resume
            // there instead of running its handler.
            if phase == Phase::Unwind && fu.establisher_frame == target_frame {
                return self.transfer_to_target(cpu, mem, &pre_unwind, target_ip, return_value);
            }

            // Advance the working context to the caller before (possibly)
            // running this frame's handler, so a "continue" resumes correctly.
            write_context(mem, work, &caller)?;

            let Some(handler_rva) = fu.handler_rva else {
                continue; // no handler on this frame
            };
            let handler = image_base + handler_rva as u64;

            // Present the pre-unwind frame state as DISPATCHER_CONTEXT.ContextRecord.
            write_context(mem, frame_ctx, &pre_unwind)?;
            let flags = match phase {
                Phase::Search => record_flags(mem, record)? & !EXCEPTION_UNWINDING,
                Phase::Unwind => record_flags(mem, record)? | EXCEPTION_UNWINDING,
            };
            set_record_flags(mem, record, flags)?;
            let function_entry = _entry.record_rva as u64 + image_base;
            let handler_data =
                fu.handler_data_rva.map(|r| image_base + r as u64).unwrap_or(0);
            write_dispatcher_context(
                mem,
                dispatcher,
                &DispatcherContext {
                    control_pc,
                    image_base,
                    function_entry,
                    establisher_frame: fu.establisher_frame,
                    target_ip: if phase == Phase::Unwind { target_ip } else { 0 },
                    context_record: frame_ctx,
                    language_handler: handler,
                    handler_data,
                },
            )?;

            // Call handler(record, establisher_frame, context, dispatcher).
            let args = [record, fu.establisher_frame, orig_ctx, dispatcher];
            self.setup_call_args(cpu, mem, handler, &args, self.exc_driver, handler_base)?;
            return Ok(Outcome::Resume);
        }
        // Frame budget exhausted — treat as unhandled.
        self.finish_dispatch(cpu, mem)
    }

    /// Transfer control to a catch/continuation: restore `ctx` (with RIP =
    /// `target_ip`, RAX = `return_value`) onto the CPU and drop this dispatch.
    fn transfer_to_target(
        &mut self,
        cpu: &mut CpuState,
        _mem: &mut dyn Memory,
        ctx: &CpuState,
        target_ip: u64,
        return_value: u64,
    ) -> Result<Outcome> {
        let mut resume = ctx.clone();
        resume.rip = target_ip;
        resume.set_reg(Reg::Rax, return_value);
        *cpu = resume;
        // A catch was reached: the whole logical exception is resolved, so
        // discard any dispatch frames still on the stack (the orphaned search
        // frame the handler unwound out of).
        self.exc_stack.clear();
        if self.cfg.trace {
            eprintln!("[exemu] exception handled → resume at {target_ip:#x}");
        }
        Ok(Outcome::Resume)
    }

    /// No frame handled the exception: this is `std::terminate`-equivalent.
    /// Terminate the process with the exception code as the exit status.
    fn finish_dispatch(&mut self, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let frame = self.exc_stack.pop();
        self.exc_stack.clear();
        let phase = frame.as_ref().map(|f| f.phase).unwrap_or(Phase::Search);
        if phase == Phase::Unwind {
            // An unwind that ran off the top without reaching its target frame:
            // the target is unreachable. Terminate rather than run wild.
            eprintln!("[exemu] RtlUnwindEx: target frame not found — terminating");
            return Ok(Outcome::Exit(1));
        }
        let code = frame.map(|f| mem.read_u32(f.record).unwrap_or(0)).unwrap_or(0);
        eprintln!(
            "[exemu] unhandled exception {code:#010x} — terminating (no guest handler caught it)"
        );
        // Windows returns the exception code as the process exit code.
        Ok(Outcome::Exit(code as i32))
    }

    /// Allocate the five guest buffers a dispatch needs (record, orig/work/
    /// frame contexts, dispatcher). Returns `None` if the heap is exhausted.
    fn alloc_dispatch_buffers(&mut self) -> Option<(u64, u64, u64, u64, u64)> {
        let record = self.heap_alloc(EXCEPTION_RECORD_SIZE);
        let orig = self.heap_alloc(CONTEXT_SIZE);
        let work = self.heap_alloc(CONTEXT_SIZE);
        let frame = self.heap_alloc(CONTEXT_SIZE);
        let disp = self.heap_alloc(DISPATCHER_CONTEXT_SIZE);
        if [record, orig, work, frame, disp].contains(&0) {
            return None;
        }
        Some((record, orig, work, frame, disp))
    }
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
