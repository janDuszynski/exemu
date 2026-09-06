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

/// `KiUserExceptionDispatcher` — ntdll's user-mode entry the kernel transfers a
/// hardware/software exception to (roadmap W3.3). The prologue reads its two
/// arguments straight off the stack it is entered on: `mov rdx, rsp`
/// (ContextRecord) and `lea rcx, [rsp+0x4F0]` (ExceptionRecord), i.e. it is
/// entered with **RSP pointing at the CONTEXT** and **no return address pushed**,
/// then tail-calls `RtlDispatchException`. Recovered from the pinned Wine 11.0
/// `ntdll.dll` disassembly (permitted guest analysis); cross-checked BY NAME at
/// the wire site when the symbol is exported (roadmap W3.3).
pub const RVA_KI_USER_EXCEPTION_DISPATCHER: u64 = 0x10a30;

/// Bytes of guest stack the `KiUserExceptionDispatcher` frame occupies:
/// `CONTEXT` (0x4D0) + `CONTEXT_EX` (0x18) + `EXCEPTION_RECORD` (0x98) + the
/// machine frame (0x28), rounded to the 16-byte alignment the frame is built at.
///
/// The same constant is baked into `wow64.dll!Wow64PrepareForException`, which
/// copies `max(0x5C0, CONTEXT_EX.Legacy.Length)` bytes when it has to move this
/// frame off a 32-bit stack — so the two agree by construction, not by luck
/// (`crates/app/tests/wow64_abi.rs::wow64_prepare_for_exception_moves_the_5c0_byte_frame`).
pub const EXC_FRAME_BYTES: u64 = 0x5C0;

/// Which machine mode the faulting instruction was executing in when the
/// exception was taken (roadmap W5.9).
///
/// This decides the `CONTEXT.SegCs` the kernel-side frame carries, and that one
/// selector is what routes the whole WoW64 exception path: the 64-bit
/// `KiUserExceptionDispatcher` hands every exception to
/// `wow64.dll!Wow64PrepareForException`, whose first act is
/// `mov ax, cs; cmp word ptr [ctx+0x38], ax`. Equal → the fault was 64-bit and
/// the frame already lives on the 64-bit stack; different → the fault was
/// **32-bit guest code**, so it moves the frame to the 64-bit stack (`r14`) and
/// calls `wow64cpu!BTCpuResetToConsistentState`, which is what eventually
/// reaches `ntdll32!KiUserExceptionDispatcher`.
/// The exception being delivered: what it is, where it happened, its
/// `ExceptionInformation` words, and which CPU mode faulted.
///
/// These four travel together everywhere — they are one description of one
/// trap, and passing them separately pushed [`WinOs::deliver_hw_exception`]
/// past a readable argument count.
#[derive(Debug, Clone, Copy)]
pub struct Trap<'a> {
    /// NTSTATUS-shaped exception code, e.g. `0xC0000005` for an access violation.
    pub code: u32,
    /// `EXCEPTION_RECORD.ExceptionAddress`.
    pub address: u64,
    /// `ExceptionInformation[]` — for an AV, `[access_kind, faulting_address]`.
    pub info: &'a [u64],
    /// The mode the CPU was in when it faulted. This is *not* cosmetic: it
    /// selects the `CONTEXT.SegCs` the frame carries, which is the single field
    /// `wow64!Wow64PrepareForException` tests to decide whether it is looking at
    /// a 32-bit guest's fault.
    pub mode: TrapMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrapMode {
    /// 64-bit long mode — `SegCs` = [`exemu_cpu_sel::CS64`].
    #[default]
    Long,
    /// 32-bit compatibility mode (a WoW64 guest) — `SegCs` = `CS32`.
    Compat32,
}

/// The flat selectors exemu's CPU reports for `mov r/m16, Sreg`. They are
/// re-exported here because a `CONTEXT` captured by the *kernel* side must agree
/// with what the guest would see from its own `mov ax, cs` — `wow64.dll`
/// compares the two directly.
pub mod exemu_cpu_sel {
    /// 64-bit code selector (GDT index 6).
    pub const CS64: u16 = 0x33;
    /// 32-bit code selector (GDT index 4).
    pub const CS32: u16 = 0x23;
    /// Flat data/stack selector (GDT index 5) — ES/SS/DS/FS/GS in both modes.
    pub const DATA: u16 = 0x2b;
}

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

// ---- the last resort: an exception nothing handled (roadmap W5.12) ----------

/// SSDT index of `NtRaiseException` (`ZwRaiseException`), recovered from the
/// pinned guest `ntdll.dll` stub at RVA 0x10310, whose body is
/// `mov r10,rcx; mov eax,0xcf; …; syscall` (the same U9 recovery every other
/// index in this crate comes from).
pub(crate) const SSDT_NT_RAISE_EXCEPTION: u32 = 0xCF;

/// `STATUS_SUCCESS`, the NTSTATUS a service that never actually returns to its
/// caller still has to hand the dispatcher.
const STATUS_SUCCESS_NT: u32 = 0x0000_0000;
/// `STATUS_NOT_IMPLEMENTED`, for a raise exemu genuinely cannot service.
const STATUS_NOT_IMPLEMENTED_NT: u32 = 0xC000_0002;

/// SSDT thunk: `NtRaiseException(ExceptionRecord, ContextRecord, FirstChance)`.
pub(crate) fn ssdt_nt_raise_exception(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_raise_exception(cpu, mem)
}

/// An exception the guest could not handle, on its way to killing the process.
///
/// This is the *original* exception — the access violation, not whatever the
/// guest's dispatcher did afterwards while giving up on it. Naming the original
/// is the whole point: Wine's `KiUserExceptionDispatcher` executes an `int3`
/// when `dispatch_exception` returns, and reporting *that* `STATUS_BREAKPOINT`
/// tells a reader nothing about why the process died.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnhandledException {
    /// `EXCEPTION_RECORD.ExceptionCode` of the original exception.
    pub code: u32,
    /// `EXCEPTION_RECORD.ExceptionAddress` of the original exception.
    pub address: u64,
    /// How exemu established that nothing handled it — the sentence a fault
    /// report appends so the reader knows whether the guest said so itself
    /// (the last-resort syscall) or exemu had to bound a loop.
    pub how: &'static str,
}

impl UnhandledException {
    /// The guest's own last-resort path: its `dispatch_exception` found no
    /// handler and asked the kernel to finish the process off, exactly as a
    /// real NT kernel is asked to.
    pub const LAST_RESORT: &'static str =
        "the guest's own exception dispatcher found no handler and asked the kernel to \
         terminate the process (NtRaiseException, FirstChance = FALSE)";
    /// exemu bounded a re-delivery loop: the same exception kept coming back at
    /// the same instruction with no `NtContinue` in between.
    pub const RE_DELIVERY_BOUND: &'static str =
        "exemu stopped re-delivering it: the guest never resumed from it, so nothing \
         handled it";
}

/// The chain of exceptions the guest is currently failing to resolve, and the
/// bound that stops exemu re-delivering one for ever (roadmap W5.12).
///
/// **Why a bound exists at all.** Wine's `KiUserExceptionDispatcher`
/// (`ntdll` RVA 0x10a30) ends `call dispatch_exception; int3` — the `int3` at
/// RVA 0x10a5a is unreachable in a working system, because every exit from
/// `dispatch_exception` is a no-return call: `NtContinue` when a handler
/// resolved it, `RtlRaiseStatus` on an error status, and a tail
/// `jmp NtRaiseException(rec, ctx, FirstChance = FALSE)` on
/// `STATUS_UNHANDLED_EXCEPTION`. When exemu answered that last syscall with
/// `STATUS_NOT_IMPLEMENTED` the call *returned*, the `int3` executed, exemu
/// delivered the resulting `STATUS_BREAKPOINT` to the same dispatcher, and the
/// process span for ever — measured as one `0xC0000005` followed by
/// `0x80000003 at ntdll+0x10a5b` without end. [`WinOs::nt_raise_exception`]
/// fixes the cause; this bounds every other shape of the same loop.
///
/// **Why `NtContinue` is the reset.** Every way a Wine guest *successfully*
/// finishes with an exception passes through it: `dispatch_exception` calls
/// `NtContinue` directly when a handler returned `STATUS_SUCCESS`, and a catch
/// reached through `RtlUnwindEx` → `RtlRestoreContext` ends in a tail
/// `jmp NtContinue` (both read off the pinned `ntdll.dll`). So "deliveries
/// since the last `NtContinue`" is exactly "exceptions the guest has not got
/// out from under", and a guest that handles a million exceptions never
/// approaches the bound.
#[derive(Debug, Default, Clone)]
pub(crate) struct ExcChain {
    /// The exception that opened the still-unresolved chain — what a fault
    /// report must name.
    first: Option<(u32, u64)>,
    /// The most recent `(code, address, faulting rip)` delivered.
    last: Option<(u32, u64, u64)>,
    /// How many times in a row that exact triple has been delivered.
    repeats: u32,
    /// Deliveries in this chain, of any shape.
    depth: u32,
}

/// How many times the *identical* `(code, address, rip)` may be delivered
/// before exemu calls it a loop. Two is a legal retry (a handler that fixed the
/// state up and let the instruction fault again once); a third with nothing
/// resumed in between is not progress.
const MAX_IDENTICAL_DELIVERIES: u32 = 3;

/// How many exceptions of *any* shape may be delivered without one `NtContinue`
/// in between. This catches a loop that alternates between two or more faults,
/// which the identical-triple counter alone cannot see. Deliberately far above
/// anything a working dispatch does: a resolved exception resets the chain, so
/// this only counts exceptions the guest never got out from under.
const MAX_CHAIN_DELIVERIES: u32 = 32;

impl ExcChain {
    /// Record one delivery. Returns `Some(UnhandledException)` — naming the
    /// exception that *opened* the chain — when the bound says the guest is
    /// never going to handle this.
    fn note_delivery(&mut self, code: u32, address: u64, rip: u64) -> Option<UnhandledException> {
        if self.first.is_none() {
            self.first = Some((code, address));
        }
        if self.last == Some((code, address, rip)) {
            self.repeats += 1;
        } else {
            self.last = Some((code, address, rip));
            self.repeats = 1;
        }
        self.depth += 1;
        if self.repeats >= MAX_IDENTICAL_DELIVERIES || self.depth > MAX_CHAIN_DELIVERIES {
            let (code, address) = self.first.unwrap_or((code, address));
            return Some(UnhandledException {
                code,
                address,
                how: UnhandledException::RE_DELIVERY_BOUND,
            });
        }
        None
    }

    /// The guest resumed (`NtContinue`): whatever was being dispatched is over.
    fn clear(&mut self) {
        *self = Self::default();
    }
}

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
/// `CONTEXT.SegCs` — six `WORD` selectors run CS, DS, ES, FS, GS, SS.
///
/// Load-bearing, and recovered from both sides: `wow64.dll` reads `[ctx+0x38]`
/// in `Wow64PrepareForException` and `wow64cpu!BTCpuResetToConsistentState`
/// copies `[ctx+0x38]`→`WOW64_CONTEXT.SegCs`, `[ctx+0x3a]`→`SegDs`,
/// `[ctx+0x3c]`→`SegEs` and `[ctx+0x42]`→`SegSs` (it takes FS/GS from its own
/// cached slots instead).
const OFF_SEG_CS: u64 = 0x38;
const OFF_SEG_DS: u64 = 0x3a;
const OFF_SEG_ES: u64 = 0x3c;
const OFF_SEG_FS: u64 = 0x3e;
const OFF_SEG_GS: u64 = 0x40;
const OFF_SEG_SS: u64 = 0x42;
/// `CONTEXT_SEGMENTS` — set when the six selectors above are meaningful.
const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x4;

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

    /// Deliver a hardware/software CPU fault to the guest the way the NT kernel
    /// does (roadmap W3.3): build the `KiUserExceptionDispatcher` stack frame on
    /// the guest stack and seat the CPU on ntdll's dispatcher, so Wine's own
    /// `RtlDispatchException` (real guest code, walking .pdata/.xdata) runs. A
    /// handled exception returns through `NtContinue` (the CONTEXT this builds is
    /// exactly what `nt_continue` consumes); an unhandled one runs off to
    /// `NtTerminateProcess`.
    ///
    /// `cpu.rip` must already hold the *reported* faulting RIP the CONTEXT should
    /// carry (for `#BP` the caller advances it past the `int3`; see the run-loop
    /// classifier). The stack layout, from `new_rsp = (old_rsp - 0x5C0) & !0xF`:
    ///
    /// ```text
    ///   +0x000  CONTEXT              (0x4D0)  write_context(cpu)  — RSP the dispatcher reads
    ///   +0x4D0  CONTEXT_EX           (0x18)   zero-filled (never inspected)
    ///   +0x4F0  EXCEPTION_RECORD     (0x98)   code / address / info
    ///   +0x590  machine frame        (0x28)   RIP / CS / RFLAGS / OldRSP / SS
    /// ```
    ///
    /// No return address is pushed: the dispatcher expects `RSP → CONTEXT` and
    /// does `mov rdx,rsp; lea rcx,[rsp+0x4F0]`.
    ///
    /// **`mode` = [`TrapMode::Compat32`] is the WoW64 case (roadmap W5.9)** and it
    /// is *the same frame*, built on the guest's **32-bit** stack, entered in
    /// 64-bit mode — which is what the NT kernel does for a 32-bit user-mode
    /// fault. Nothing else changes here, because everything downstream is Wine's
    /// own code and it keys entirely off `CONTEXT.SegCs`:
    ///
    /// ```text
    ///   ntdll64!KiUserExceptionDispatcher (rva 0x10a30)
    ///     → wow64!Wow64PrepareForException(rec, ctx)          rva 0x1598
    ///         ctx->SegCs != cs  →  move all 0x5C0 bytes to the 64-bit stack (r14)
    ///       → wow64cpu!BTCpuResetToConsistentState(&ptrs)     rva 0x1590
    ///           RtlWow64SetThreadContext(-2, ctx32-from-ctx64)   ← the guest's real trap state
    ///           ctx->Rip = wow64cpu+0x1110 (the BOP return handler)
    ///           ctx->Rsp = ctx->R14; ctx->SegCs = 0x33            ← now unwindable
    ///     → ntdll64!RtlDispatchException walks that into wow64's simulate loop
    ///       → its handler (wow64 rva 0x1564) calls
    ///         wow64!Wow64PassExceptionToGuest(&ptrs)          rva 0x2d10
    ///           narrows the record to a 32-bit EXCEPTION_RECORD, builds the
    ///           32-bit dispatcher frame on the guest's own stack and
    ///           BTCpuSetContext()s Eip = ntdll32!KiUserExceptionDispatcher
    ///       → unwinds to `for(;;) pBTCpuSimulate();` (wow64 rva 0x155c)
    ///         which re-enters the guest — inside its own dispatcher.
    /// ```
    ///
    /// So exemu's whole job is this frame plus the mode switch; it marshals no
    /// context and knows nothing about the 32-bit dispatcher. The caller is
    /// responsible for putting the CPU in 64-bit mode (this layer only sees a
    /// [`CpuState`], which carries no mode).
    pub fn deliver_hw_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        ntdll_base: u64,
        trap: Trap<'_>,
    ) -> Result<()> {
        let Trap { code, address, info, mode } = trap;
        let old_rsp = cpu.rsp();
        // A guest whose stack pointer is below the frame size (a corrupt or
        // mode-confused state — e.g. a 32-bit `esp` after a mis-taken WoW64
        // transition) has nowhere to put the dispatcher frame. Report it as an
        // OS error rather than wrapping the subtraction (which panicked in debug
        // builds and silently built the frame at a wild address in release).
        let Some(new_rsp) = old_rsp.checked_sub(EXC_FRAME_BYTES) else {
            return Err(exemu_core::EmuError::Os(format!(
                "cannot deliver exception {code:#x}: rsp {old_rsp:#x} is below the \
                 {EXC_FRAME_BYTES:#x}-byte KiUserExceptionDispatcher frame"
            )));
        };
        let new_rsp = new_rsp & !0xF;
        let fault_rip = cpu.rip;
        let rflags = cpu.rflags;

        // CONTEXT @ +0x000 — snapshot the faulting register file (cpu.rip is the
        // reported faulting RIP; write_context lays Rsp@+0x98 = old_rsp,
        // Rip@+0xf8 = fault_rip).
        write_context(mem, new_rsp, cpu)?;

        // …and the six selectors, which `write_context` leaves alone because the
        // CPU keeps no selector state. A zero `SegCs` here is not a harmless
        // omission on the WoW64 path: it is the field `Wow64PrepareForException`
        // tests, so leaving it zero would classify every 64-bit fault in a WoW64
        // process as a 32-bit one.
        let cs = match mode {
            TrapMode::Long => exemu_cpu_sel::CS64,
            TrapMode::Compat32 => exemu_cpu_sel::CS32,
        };
        mem.write_u16(new_rsp + OFF_SEG_CS, cs)?;
        for off in [OFF_SEG_DS, OFF_SEG_ES, OFF_SEG_FS, OFF_SEG_GS, OFF_SEG_SS] {
            mem.write_u16(new_rsp + off, exemu_cpu_sel::DATA)?;
        }
        mem.write_u32(new_rsp + OFF_CONTEXT_FLAGS, CONTEXT_ALL | CONTEXT_SEGMENTS)?;

        // CONTEXT_EX @ +0x4D0 (0x18): zeroed. `Wow64PrepareForException` reads
        // `Legacy.Length` at +0x4D4 and copies `max(0x5C0, that)` bytes, so zero
        // means "exactly this frame" — which is the truth.
        for i in 0..3u64 {
            mem.write_u64(new_rsp + 0x4D0 + i * 8, 0)?;
        }

        // EXCEPTION_RECORD @ +0x4F0: ExceptionFlags = 0 (search phase).
        write_exception_record(mem, new_rsp + 0x4F0, code, 0, address, info)?;

        // Machine frame @ +0x590 — the trap frame the kernel synthesizes.
        // `BTCpuResetToConsistentState` rewrites this frame's RIP/RSP in place
        // (`rec + 0xa7 & !0xf` is exactly `new_rsp + 0x590`), so its position
        // relative to the EXCEPTION_RECORD is load-bearing, not decorative.
        mem.write_u64(new_rsp + 0x590, fault_rip)?; // RIP
        mem.write_u64(new_rsp + 0x598, cs as u64)?; // CS (0x33 long / 0x23 compat)
        mem.write_u64(new_rsp + 0x5A0, rflags)?; // RFLAGS
        mem.write_u64(new_rsp + 0x5A8, old_rsp)?; // OldRSP (== new_rsp + 0x5A8)
        mem.write_u64(new_rsp + 0x5B0, exemu_cpu_sel::DATA as u64)?; // SS

        // Seat the CPU on the dispatcher with RSP → CONTEXT, no return address.
        cpu.set_rsp(new_rsp);
        cpu.rip = ntdll_base + RVA_KI_USER_EXCEPTION_DISPATCHER;
        Ok(())
    }

    /// Record that `(code, address)` is being delivered to the guest's
    /// dispatcher from `rip`, and say whether the delivery may go ahead.
    ///
    /// `Ok(())` — deliver it. `Err(UnhandledException)` — the re-delivery bound
    /// says the guest is never going to handle this one; the caller must stop
    /// the process and report the returned (original) exception. See
    /// [`ExcChain`] for what the bound is and why `NtContinue` resets it.
    pub fn note_exception_delivery(
        &mut self,
        code: u32,
        address: u64,
        rip: u64,
    ) -> std::result::Result<(), UnhandledException> {
        match self.exc_chain.note_delivery(code, address, rip) {
            Some(u) => {
                self.unhandled_exception = Some(u.clone());
                Err(u)
            }
            None => Ok(()),
        }
    }

    /// The guest resumed out of an exception (`NtContinue`): the dispatch chain
    /// is resolved, so the re-delivery bound starts again from zero.
    pub(crate) fn note_exception_resumed(&mut self) {
        self.exc_chain.clear();
    }

    /// Take the exception that killed the process, if one did. Set either by
    /// the guest's own last-resort [`WinOs::nt_raise_exception`] or by the
    /// re-delivery bound; the run loop turns it into a fault report naming the
    /// *original* exception instead of a bare exit status.
    pub fn take_unhandled_exception(&mut self) -> Option<UnhandledException> {
        self.unhandled_exception.take()
    }

    /// `NtRaiseException(ExceptionRecord = R10, ContextRecord = RDX,
    /// FirstChance = R8)` (roadmap W5.12) — the syscall the guest's own
    /// exception dispatcher hands an exception back to the kernel through.
    ///
    /// Recovered from the pinned Wine 11.0 `ntdll.dll`, which reaches it from
    /// exactly two places:
    ///
    /// ```text
    ///   dispatch_exception (rva 0x479b0), tail:
    ///     call call_function_handlers          ; walk the guest's frames
    ///     STATUS_SUCCESS               -> call NtContinue(ctx, FALSE)      (no return)
    ///     STATUS_UNHANDLED_EXCEPTION   -> jmp  NtRaiseException(rec, ctx, FALSE)
    ///     anything else                -> call RtlRaiseStatus(status)      (no return)
    ///
    ///   RtlRaiseException (rva 0x10b84):
    ///     if (!PEB->BeingDebugged) call dispatch_exception(rec, ctx)
    ///     call NtRaiseException(rec, ctx, TRUE)
    ///     call RtlRaiseStatus(status)
    /// ```
    ///
    /// **`FirstChance = FALSE` must not return.** It is the last resort: the
    /// frame walk found nothing, and in NT the kernel ends the process with the
    /// exception code (Wine's unix side does the same, after its
    /// `err:seh:` report). exemu ends the run the same way, and remembers the
    /// record so the fault reporter names the *original* exception.
    ///
    /// Letting it return is what made an unhandled fault spin for ever:
    /// `KiUserExceptionDispatcher` is `call dispatch_exception; int3`, so the
    /// return runs the `int3` at rva 0x10a5a, exemu delivered the resulting
    /// `STATUS_BREAKPOINT` to the same dispatcher, and around it went.
    ///
    /// **`FirstChance = TRUE`** is a request to re-enter user mode at
    /// `KiUserExceptionDispatcher` with this record and context — so restore the
    /// context the caller captured and build the dispatcher frame on it, which
    /// is precisely [`WinOs::deliver_hw_exception`]. Like `NtContinue` it does
    /// not return to its caller, so the dispatcher's phase-4 restore is skipped.
    pub(crate) fn nt_raise_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        let rec = self.syscall_arg(cpu, mem, 0)?;
        let ctx = self.syscall_arg(cpu, mem, 1)?;
        let first_chance = self.syscall_arg(cpu, mem, 2)? & 0xff != 0;
        if rec == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let (Ok(code), Ok(address)) = (mem.read_u32(rec + ER_CODE), mem.read_u64(rec + ER_ADDRESS))
        else {
            return Ok(STATUS_ACCESS_VIOLATION);
        };

        if !first_chance {
            // The guest gave up on it. Terminate with the exception code — what
            // NT does — and keep the record for the fault report.
            self.unhandled_exception = Some(UnhandledException {
                code,
                address,
                how: UnhandledException::LAST_RESORT,
            });
            self.exc_chain.clear();
            self.pending_syscall_exit = Some(code as i32);
            return Ok(STATUS_SUCCESS_NT);
        }

        // First chance: re-enter user mode at the dispatcher with this record.
        let Some(ntdll) = self.module_base("ntdll.dll") else {
            // No Wine ntdll is mapped, so there is no dispatcher to enter. Say
            // so rather than pretending the exception was raised.
            return Ok(STATUS_NOT_IMPLEMENTED_NT);
        };
        let nparams = mem.read_u32(rec + ER_NUM_PARAMS).unwrap_or(0).min(15) as u64;
        let mut info = Vec::with_capacity(nparams as usize);
        for i in 0..nparams {
            info.push(mem.read_u64(rec + ER_INFO + i * 8).unwrap_or(0));
        }
        // Restore the context the raiser captured, the way NtContinue does:
        // the architectural registers only, so this thread's segment bases
        // (which no CONTEXT carries) keep pointing at its own TEB.
        if ctx != 0 {
            if let Ok(restored) = read_context(mem, ctx) {
                cpu.gpr = restored.gpr;
                cpu.xmm = restored.xmm;
                cpu.rip = restored.rip;
                cpu.rflags = restored.rflags;
            }
        }
        if let Err(u) = self.note_exception_delivery(code, address, cpu.rip) {
            self.pending_syscall_exit = Some(u.code as i32);
            return Ok(STATUS_SUCCESS_NT);
        }
        let trap = Trap { code, address, info: &info, mode: TrapMode::Long };
        if self.deliver_hw_exception(cpu, mem, ntdll, trap).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // Resume where the frame put us, not where the syscall came from.
        self.syscall_resume_as_is = true;
        Ok(STATUS_SUCCESS_NT)
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
