//! Process bootstrap — the `LdrInitializeThunk` handoff (roadmap W3.1).
//!
//! Wine's PE `ntdll` boots a thread through a fixed sequence, verified against
//! the pinned Wine 11.0 `ntdll.dll` (`example_exe/wine-dlls/x86_64-windows/`):
//!
//! ```text
//! LdrInitializeThunk(rcx = &CONTEXT)          @ RVA 0x155c0
//!   push rbx; sub rsp,0x30; lea rdx,[rcx+0x80] (= &CONTEXT.Rcx); mov rbx,rcx
//!   call loader_init                          @ 0x54430  (loads kernel32, …)
//!   mov rcx,rbx; call signal_start_thread     @ 0x10d2c  (= RtlUserThreadStart+0x18)
//!     …; mov rcx,rbx; mov edx,1; call ZwContinue(context, TRUE)  @ 0xf190
//!
//! ZwContinue == NtContinue @ 0xf190, SSDT index 0x43, stub `mov r10,rcx`:
//!   NtContinue(ctx = R10, test_alert = RDX) — load the guest CONTEXT into the
//!   register file and resume at CONTEXT.Rip on CONTEXT.Rsp.
//!
//! RtlUserThreadStart(rcx = EntryPoint, rdx = Arg)  @ RVA 0x10d14
//!   mov r8,rdx; mov rdx,rcx; xor rcx,rcx; call [pBaseThreadInitThunk @ 0x73500]
//! ```
//!
//! So the CONTEXT the bootstrap builds for a fresh thread has **Rip =
//! `RtlUserThreadStart`**, **Rcx = EntryPoint**, **Rdx = Arg**, and a valid Rsp
//! — `signal_start_thread`'s `ZwContinue(context, TRUE)` restores it, landing on
//! `RtlUserThreadStart`, which forwards `(EntryPoint, Arg)` through
//! `BaseThreadInitThunk` to the guest's real entry.
//!
//! **Clean-room note (Class B).** The RVAs, the register conventions, and the
//! SSDT index above were recovered from the pinned guest binary's disassembly
//! (permitted guest analysis) + public `winnt.h` CONTEXT layout. No Wine `.c`
//! was read.

use exemu_core::{CpuState, Memory, Reg, Result};

use crate::exc;
use crate::WinOs;

// ---- ntdll entry-point RVAs (pinned Wine 11.0 ntdll.dll) --------------------

/// `LdrInitializeThunk` — the initial thread entry. Called with `RCX =
/// &CONTEXT`; drives `loader_init` then `signal_start_thread → ZwContinue`.
pub const RVA_LDR_INITIALIZE_THUNK: u64 = 0x155c0;
/// `RtlUserThreadStart(EntryPoint, Arg)` — where `ZwContinue` lands the fresh
/// thread; forwards `(EntryPoint, Arg)` through `BaseThreadInitThunk`.
pub const RVA_RTL_USER_THREAD_START: u64 = 0x10d14;

/// `STATUS_SUCCESS` — `NtContinue` never actually returns it to the guest (it
/// resumes into the restored CONTEXT), but the dispatcher needs a status value.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_ACCESS_VIOLATION` — a `NtContinue` with a NULL / unreadable CONTEXT.
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// SSDT index of `NtContinue` (`ZwContinue`), recovered from the pinned guest
/// `ntdll.dll` stub's `mov eax,0x43` (`ZwContinue` @ RVA 0xf190; U9).
pub(crate) const SSDT_NT_CONTINUE: u32 = 0x43;

/// SSDT thunk: `NtContinue(ContextRecord, TestAlert)`.
pub(crate) fn ssdt_nt_continue(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_continue(cpu, mem)
}

impl WinOs {
    /// `NtContinue(ContextRecord = R10, TestAlert = RDX)` (roadmap W3.1).
    ///
    /// Loads the guest `CONTEXT` at `R10` into the live register file and
    /// resumes execution at `CONTEXT.Rip` on `CONTEXT.Rsp` — the load-bearing
    /// syscall the `RtlUserThreadStart → signal_start_thread → ZwContinue`
    /// bootstrap (and every handled hardware exception, W3.3) hands off through.
    ///
    /// Unlike a normal `Nt*` service this does **not** return to the caller: the
    /// saved `syscall_frame` belongs to `signal_start_thread`, which is being
    /// abandoned. It sets [`WinOs::syscall_resume_as_is`] so the dispatcher's
    /// phase-4 restore is skipped and the guest resumes exactly at the restored
    /// CONTEXT (the same "handler installed the resume state" contract W2.9's
    /// self-terminate and W2.12's blocking waits use).
    ///
    /// The current thread's segment bases (`gs_base`/`fs_base`, per-thread since
    /// W2.9) are preserved — `CONTEXT` carries no segment bases, and clobbering
    /// them would repoint `gs:` off this thread's TEB.
    pub(crate) fn nt_continue(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let ctx = self.syscall_arg(cpu, mem, 0)?; // R10 = ContextRecord
        if ctx == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // Read the CONTEXT into a fresh state, then splice its architectural
        // fields onto the live cpu, preserving the per-thread segment bases and
        // the AVX-upper / x87 state the CONTEXT layout we marshal does not span.
        let restored = match exc::read_context(mem, ctx) {
            Ok(s) => s,
            Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
        };
        cpu.gpr = restored.gpr;
        cpu.xmm = restored.xmm;
        cpu.rip = restored.rip;
        cpu.rflags = restored.rflags;
        // Skip the dispatcher's restore/return: resume the guest as we left it,
        // on CONTEXT.Rip / CONTEXT.Rsp (already loaded via gpr[Rsp]).
        self.syscall_resume_as_is = true;
        Ok(STATUS_SUCCESS)
    }

    /// Build the initial-thread bootstrap for a fresh process the way Wine's
    /// ntdll expects, and seat the CPU on it (roadmap W3.1).
    ///
    /// Constructs a guest `CONTEXT` for `RtlUserThreadStart(entry, arg)` — `Rip
    /// = ntdll_base + RtlUserThreadStart`, `Rcx = entry`, `Rdx = arg`, `Rsp =
    /// stack_top`, and a legal RFLAGS — parks it in guest memory (a scratch
    /// heap allocation), then seats the CPU at `ntdll_base + LdrInitializeThunk`
    /// with `RCX = &CONTEXT`, exactly the state Wine's Unix loader leaves a new
    /// thread in before jumping to the PE entry.
    ///
    /// `ProcessParameters` (PEB+0x20 → a minimal `RTL_USER_PROCESS_PARAMETERS`
    /// with a readable ImagePathName/CommandLine, and its Environment at +0x80)
    /// is already materialized by [`WinOs::init_ldr`] → `seed_peb`; this only
    /// builds the CONTEXT + entry handoff.
    ///
    /// Returns the guest address of the built CONTEXT (the value placed in RCX),
    /// or `None` if the heap is exhausted. **Not** taken by the existing corpus:
    /// 7z/tcc keep the direct `rip = entry` path (`start_process`); the app only
    /// calls this once a Wine `ntdll` image is mapped (W3.2).
    pub fn bootstrap_via_ldr_init(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        ntdll_base: u64,
        entry: u64,
        arg: u64,
        stack_top: u64,
    ) -> Result<Option<u64>> {
        // Scratch CONTEXT in the heap arena (stable for the life of the boot;
        // RtlUserThreadStart re-establishes its own frame from Rsp).
        let ctx = self.heap_alloc(exc::CONTEXT_SIZE);
        if ctx == 0 {
            return Ok(None);
        }

        // A CONTEXT positioned for RtlUserThreadStart(entry, arg). Start from a
        // clean state so every field marshals a defined value, then set the
        // control/argument registers the handoff reads.
        let mut boot = CpuState::new();
        boot.rip = ntdll_base + RVA_RTL_USER_THREAD_START;
        boot.set_reg(Reg::Rcx, entry); // RtlUserThreadStart arg0 = EntryPoint
        boot.set_reg(Reg::Rdx, arg); // RtlUserThreadStart arg1 = Arg
        // 16-byte aligned, one shadow-space below the top, as a `call` would
        // leave it before RtlUserThreadStart's own `sub rsp,0x28`.
        boot.set_rsp(stack_top & !0xf);
        exc::write_context(mem, ctx, &boot)?;

        // Seat the initial thread at LdrInitializeThunk with RCX = &CONTEXT.
        cpu.rip = ntdll_base + RVA_LDR_INITIALIZE_THUNK;
        cpu.set_reg(Reg::Rcx, ctx);
        Ok(Some(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::{flags, Exit};
    use exemu_memory::VirtualMemory;

    // CONTEXT field offsets (winnt.h AMD64) the builder must place.
    const CTX_CONTEXT_FLAGS: u64 = 0x30;
    const CTX_RCX: u64 = 0x80;
    const CTX_RDX: u64 = 0x88;
    const CTX_RSP: u64 = 0x98;
    const CTX_RIP: u64 = 0xf8;

    const TEB: u64 = 0x7fff_0000_0000;
    const HEAP: u64 = 0x2_0000_0000;
    const STACK_TOP: u64 = 0x10_0000_1000;

    fn os_mem() -> (WinOs, VirtualMemory) {
        let mut mem = VirtualMemory::new();
        mem.map(exemu_core::Region::new("teb", TEB, 0x2000, exemu_core::Perm::RW)).unwrap();
        mem.map(exemu_core::Region::new("heap", HEAP, 0x10000, exemu_core::Perm::RW)).unwrap();
        mem.map(exemu_core::Region::new("scratch", 0x5000_0000, 0x4000, exemu_core::Perm::RW)).unwrap();
        let os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            teb_base: TEB,
            heap_base: HEAP,
            heap_size: 0x10000,
            ..WinConfig::default()
        });
        (os, mem)
    }

    /// NtContinue loads the CONTEXT into the register file and resumes at
    /// CONTEXT.Rip / CONTEXT.Rsp (the load-bearing bootstrap handoff).
    #[test]
    fn nt_continue_loads_context_and_resumes() {
        let (mut os, mut mem) = os_mem();
        let ctx = 0x5000_0000u64;

        // A CONTEXT with distinctive integer/control state.
        let mut want = CpuState::new();
        want.set_reg(Reg::Rbx, 0xB16B_00B5);
        want.set_reg(Reg::Rsi, 0x5151_5151);
        want.set_reg(Reg::Rcx, 0x00C0_FFEE);
        want.rip = 0x1_4000_1234;
        want.set_rsp(0x10_0000_0FF0);
        want.rflags = flags::RESERVED_ONE | flags::CF | flags::ZF;
        exc::write_context(&mut mem, ctx, &want).unwrap();

        // Model the CPU state after the SYSCALL side-effects for `NtContinue`:
        // arg0 (ContextRecord) has been moved into R10 by the stub's `mov r10,rcx`.
        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;
        cpu.fs_base = TEB;
        cpu.set_reg(Reg::R10, ctx);
        cpu.set_reg(Reg::Rcx, 0xDEAD); // return rip the frame would restore — ignored
        cpu.set_reg(Reg::R11, cpu.rflags);
        cpu.set_rsp(0x10_0000_2000);

        let exit = os.dispatch_syscall(SSDT_NT_CONTINUE, &mut cpu, &mut mem).unwrap();
        assert_eq!(exit, Exit::Continue);
        assert_eq!(cpu.rip, want.rip, "resumed at CONTEXT.Rip");
        assert_eq!(cpu.rsp(), want.rsp(), "resumed on CONTEXT.Rsp");
        assert_eq!(cpu.reg(Reg::Rbx), 0xB16B_00B5, "Rbx loaded from CONTEXT");
        assert_eq!(cpu.reg(Reg::Rsi), 0x5151_5151, "Rsi loaded from CONTEXT");
        assert_eq!(cpu.reg(Reg::Rcx), 0x00C0_FFEE, "Rcx loaded (NOT the frame's return rip)");
        assert_eq!(cpu.rflags & flags::CF, flags::CF, "RFLAGS.CF loaded from CONTEXT");
        assert_eq!(cpu.gs_base, TEB, "segment bases preserved across NtContinue");
        assert_eq!(cpu.fs_base, TEB, "segment bases preserved across NtContinue");
    }

    /// NtContinue(NULL) is a clean STATUS_ACCESS_VIOLATION, not a fault, and it
    /// does NOT signal resume-as-is (the caller stays where it was).
    #[test]
    fn nt_continue_null_context_is_access_violation() {
        let (mut os, mut mem) = os_mem();
        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;
        cpu.set_reg(Reg::R10, 0);
        cpu.set_reg(Reg::Rcx, 0x1234);
        cpu.set_reg(Reg::R11, cpu.rflags);
        cpu.set_rsp(0x10_0000_2000);
        os.dispatch_syscall(SSDT_NT_CONTINUE, &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::Rax), STATUS_ACCESS_VIOLATION as u64);
        assert_eq!(cpu.rip, 0x1234, "returned to the frame's rip (RCX), not resumed");
    }

    /// The bootstrap builder produces a RtlUserThreadStart-ready CONTEXT and
    /// seats the CPU at LdrInitializeThunk with RCX = &CONTEXT.
    #[test]
    fn bootstrap_builds_context_and_seats_ldr_init() {
        let (mut os, mut mem) = os_mem();
        let ntdll_base = 0x6_0000_0000u64;
        let entry = 0x1_4000_5000u64;
        let arg = 0xABCD;
        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;

        let ctx = os
            .bootstrap_via_ldr_init(&mut cpu, &mut mem, ntdll_base, entry, arg, STACK_TOP)
            .unwrap()
            .expect("heap had room for the CONTEXT");

        // The CPU is seated at LdrInitializeThunk with RCX = &CONTEXT.
        assert_eq!(cpu.rip, ntdll_base + RVA_LDR_INITIALIZE_THUNK, "rip = LdrInitializeThunk");
        assert_eq!(cpu.reg(Reg::Rcx), ctx, "RCX = &CONTEXT");

        // The CONTEXT is positioned for RtlUserThreadStart(entry, arg).
        assert_ne!(mem.read_u32(ctx + CTX_CONTEXT_FLAGS).unwrap(), 0, "ContextFlags set");
        assert_eq!(mem.read_u64(ctx + CTX_RIP).unwrap(), ntdll_base + RVA_RTL_USER_THREAD_START);
        assert_eq!(mem.read_u64(ctx + CTX_RCX).unwrap(), entry, "CONTEXT.Rcx = EntryPoint");
        assert_eq!(mem.read_u64(ctx + CTX_RDX).unwrap(), arg, "CONTEXT.Rdx = Arg");
        let rsp = mem.read_u64(ctx + CTX_RSP).unwrap();
        assert_eq!(rsp & 0xf, 0, "CONTEXT.Rsp 16-byte aligned");
        assert!(rsp <= STACK_TOP && rsp > STACK_TOP - 0x1000, "CONTEXT.Rsp near the stack top");
    }
}
