//! The NT-syscall dispatcher — exemu's Unix side of Wine's PE→Unix boundary
//! (roadmap W2.3).
//!
//! Wine's PE `ntdll.dll` reaches the "unix side" for `Nt*` services through a
//! raw `SYSCALL` (`0F 05`): the stub does `mov r10,rcx; mov eax,N; syscall;
//! ret`, so the SSDT index `N` is in EAX and arg0 has been moved into R10
//! (SYSCALL clobbers RCX with the return address). The CPU (`crates/cpu`)
//! executes the `SYSCALL`, applies the hardware side-effects (return `rip`→RCX,
//! RFLAGS→R11, `rip` past the instruction), and hands us the index through
//! [`crate::Hooks::syscall`].
//!
//! This module implements the ARM64EC-shaped context-switch seam that a real
//! kernel entry performs, modelled over exemu's native (Rust) `Nt*` handlers:
//!
//! 1. **Save** the Windows context into the per-thread `syscall_frame` — the
//!    non-volatile set the Win64/SysV ABI requires a callee to preserve
//!    (RBX, RBP, RSI, RDI, RSP, R12–R15, XMM6–XMM15), plus the return `rip`
//!    (RCX) and flags (R11), so the guest resumes exactly where it left off.
//! 2. **Switch** to a dedicated unix stack (RSP moves off the guest stack for
//!    the duration of the handler, exactly as the real syscall entry does).
//! 3. **Index** the SSDT and **call** the native handler. The handler runs on
//!    the volatile set (RAX, RCX, RDX, R8–R11, XMM0–5 may be clobbered) and
//!    returns an NTSTATUS.
//! 4. **Restore** the non-volatile set from the frame and **return** to the
//!    guest: `rip`←saved RCX, RFLAGS←saved R11, RAX←NTSTATUS.
//!
//! **Clean-room note (Class B).** The register save-set and SYSCALL semantics
//! derive from the public x64 ABI documentation and public `winnt.h`; the
//! `Nt*` contracts from public `unixlib.h` / `winternl.h`. The `syscall_frame`
//! *field layout used here is exemu's own* (a valid re-mapping): W2.1–W2.3
//! deliberately do **not** depend on Wine's private field order. The real TEB
//! offset of the `syscall_frame` pointer and its exact field order are open
//! item **U7**, to be recovered from the pinned guest binary's
//! `KiUserExceptionDispatcher`; the concrete SSDT index→`Nt*` map is open item
//! **U9**, recovered from the `mov eax,N` immediates in the pinned stubs. Both
//! are stubbed here — no Wine `.c` implementation was read.

use exemu_core::{flags, CpuState, Exit, Memory, Reg, Result};

use crate::WinOs;

/// `STATUS_NOT_IMPLEMENTED` — returned for an SSDT slot that has no handler yet
/// (each `Nt*` group fills its slots in W2.6+). Public ntstatus value.
pub(crate) const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// Number of ntdll SSDT slots. Wine's native x64 ntdll exposes a few hundred
/// `Nt*` services; 0x400 comfortably covers the index range without depending
/// on the exact count (open item U9).
const SSDT_LEN: usize = 0x400;

/// Number of win32k (USER/GDI) SSDT slots. win32u's stubs use indices
/// 0x1084–0x1601; after masking off the `0x1000` table selector the *effective*
/// index runs 0x84–0x601, so 0x700 slots comfortably cover it (roadmap W4.1).
const WIN32K_LEN: usize = 0x700;

/// The table selector bit in an SSDT index: the win32k (USER/GDI) table is
/// selected when it is set (win32u indices 0x1084–0x1601 all carry it), the
/// ntdll table otherwise (no ntdll index reaches 0x1000). This is Windows' own
/// USER/GDI table selector, reused here as the routing discriminator so the
/// existing raw-`SYSCALL` CPU path delivers both tables with no CPU change
/// (roadmap W4.1). See [`WinOs::dispatch_syscall`].
pub(crate) const WIN32K_TABLE_BIT: u32 = 0x1000;

/// Bytes reserved for the dispatcher's dedicated unix stack. A native handler
/// runs on the host, so this only has to be large enough for any guest memory
/// a handler scratches through a switched RSP; a few pages are ample.
const UNIX_STACK_SIZE: u64 = 0x4000;

/// The app maps a 0x2000-byte TEB region per thread. The frame is parked in the
/// tail of that region, clear of the TEB struct proper (inline TLS slots reach
/// ~0x1838), so it never collides with fields the guest reads through `gs:`.
const TEB_REGION_SIZE: u64 = 0x2000;

/// A native `Nt*` handler. It runs with arguments already in the ABI registers
/// (arg0 in R10, arg1 RDX, arg2 R8, arg3 R9; args 5+ live on the *guest* stack,
/// read via [`WinOs::syscall_arg`]) and returns an NTSTATUS to place in RAX.
///
/// The handler operates directly on the live [`CpuState`] and [`Memory`]; the
/// dispatcher has already saved the non-volatile set, so a handler may clobber
/// the volatile registers freely — they are the syscall's scratch set.
pub type SyscallHandler = fn(&mut WinOs, &mut CpuState, &mut dyn Memory) -> Result<u32>;

/// Internal alias kept for brevity within this module.
type Handler = SyscallHandler;

/// The System Service Descriptor Table: index → native handler. Slots default
/// to [`Ssdt::unimplemented`], which returns `STATUS_NOT_IMPLEMENTED`; the
/// `Nt*` groups (W2.6+) install real handlers with [`Ssdt::set`].
pub(crate) struct Ssdt {
    handlers: Vec<Handler>,
    /// Which slots something has actually claimed. Kept beside `handlers`
    /// because a slot's *identity* cannot be recovered from the function pointer
    /// without comparing addresses, and this is what lets the `EXEMU_W32K_TRACE`
    /// transcript mark an index `<UNSERVICED>` — which is how the missing
    /// primitive behind a stuck control gets found (roadmap W6.2).
    claimed: Vec<bool>,
}

impl Ssdt {
    /// The ntdll service table (index → `Nt*` handler), [`SSDT_LEN`] slots.
    pub(crate) fn new() -> Self {
        Ssdt {
            handlers: vec![Ssdt::unimplemented as Handler; SSDT_LEN],
            claimed: vec![false; SSDT_LEN],
        }
    }

    /// The win32k (USER/GDI) service table, [`WIN32K_LEN`] slots, indexed by the
    /// *masked* index (`index & !WIN32K_TABLE_BIT`). Slots default to the same
    /// `unimplemented` stub until [`crate::win32k`] installs the W4.1 skeleton.
    pub(crate) fn new_win32k() -> Self {
        Ssdt {
            handlers: vec![Ssdt::unimplemented as Handler; WIN32K_LEN],
            claimed: vec![false; WIN32K_LEN],
        }
    }

    /// Install `handler` at SSDT `index`. Used by each `Nt*` group (W2.6+) to
    /// claim its slots. Out-of-range indices are ignored (they can never be
    /// dispatched anyway).
    pub(crate) fn set(&mut self, index: u32, handler: Handler) {
        if let Some(slot) = self.handlers.get_mut(index as usize) {
            *slot = handler;
            self.claimed[index as usize] = true;
        }
    }

    /// Install `handler` at `index` **without** claiming the slot — the blanket
    /// "honest stub" fill win32k lays down over its whole index range before
    /// overriding the serviced slots. Leaving these unclaimed is the whole point:
    /// it is what makes [`Ssdt::implemented`] mean "someone wrote a handler for
    /// this" rather than "the range was filled".
    pub(crate) fn set_stub(&mut self, index: u32, handler: Handler) {
        if let Some(slot) = self.handlers.get_mut(index as usize) {
            *slot = handler;
        }
    }

    /// Whether anything has claimed `index`. Only the trace consults this.
    pub(crate) fn implemented(&self, index: u32) -> bool {
        self.claimed.get(index as usize).copied().unwrap_or(false)
    }

    /// The handler for an SSDT slot with no implementation yet.
    fn unimplemented(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
        Ok(STATUS_NOT_IMPLEMENTED)
    }

    /// Look up the handler for `index`, or the unimplemented stub if the index
    /// is out of range.
    fn handler(&self, index: u32) -> Handler {
        self.handlers
            .get(index as usize)
            .copied()
            .unwrap_or(Ssdt::unimplemented as Handler)
    }
}

/// exemu's own `syscall_frame` field layout (see the module note: this is a
/// deliberate re-mapping, **not** Wine's private order — U7). One record laid
/// down in the tail of the TEB region while a handler runs; the CPU state is
/// reconstructed from it on return so the guest resumes with every non-volatile
/// register and its flags intact.
mod frame {
    /// Total frame size: 11 control/GPR slots + 10 XMM slots (16 bytes each).
    pub const SIZE: u64 = 0x140;

    // 8-byte GPR / control slots.
    pub const RBX: u64 = 0x00;
    pub const RBP: u64 = 0x08;
    pub const RSI: u64 = 0x10;
    pub const RDI: u64 = 0x18;
    pub const RSP: u64 = 0x20;
    pub const R12: u64 = 0x28;
    pub const R13: u64 = 0x30;
    pub const R14: u64 = 0x38;
    pub const R15: u64 = 0x40;
    pub const RIP: u64 = 0x48; // return address (from RCX)
    pub const FLAGS: u64 = 0x50; // saved RFLAGS (from R11)

    // 16-byte XMM slots (XMM6..=XMM15), the non-volatile vector set.
    pub const XMM_BASE: u64 = 0x60;
    /// First non-volatile XMM register number (XMM0–5 are volatile).
    pub const XMM_FIRST: u8 = 6;
    /// Last non-volatile XMM register number.
    pub const XMM_LAST: u8 = 15;
}

/// `EXEMU_W32K_TRACE` — log every win32u (`NtUser*`/`NtGdi*`) index as it is
/// dispatched, on stderr as `[w32k] 0xIDX`.
///
/// This exists because the win32u boundary is the one place exemu can *observe*
/// what Wine's user32/gdi32 actually ask the kernel side for: which primitive a
/// real control paints with is recovered by reading this trace, not guessed. Off
/// unless the variable is set, and read once.
fn win32k_trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("EXEMU_W32K_TRACE").is_some())
}

/// The saved Windows context. When a TEB exists the frame lives in guest memory
/// (`Teb`), which is the design's "build it in the TEB" path; host-only unit
/// tests with no TEB fall back to a `Host` snapshot so the save/restore
/// round-trip still holds. Either way the *same* non-volatile set is preserved.
enum SavedContext {
    /// Frame parked at this guest address in the tail of the TEB region.
    Teb(u64),
    /// No TEB: keep the non-volatiles host-side (boxed — the vector set makes
    /// this variant large). Fields mirror the frame.
    Host(Box<HostContext>),
}

/// The host-side snapshot backing [`SavedContext::Host`].
struct HostContext {
    gpr: [u64; 9], // RBX,RBP,RSI,RDI,RSP,R12,R13,R14,R15
    rip: u64,
    flags: u64,
    xmm: [u128; 10], // XMM6..=XMM15
}

impl WinOs {
    /// Integer/pointer argument `i` (0-based) of the current NT syscall, per the
    /// x64 syscall ABI: arg0 in **R10** (the stub's `mov r10,rcx` — RCX itself
    /// now holds the return address), arg1 RDX, arg2 R8, arg3 R9, and args 5+
    /// on the guest stack above the shadow space at `[guest_rsp + 0x28 +
    /// (i-4)*8]`.
    ///
    /// Handlers run *after* the unix-stack switch, so stack args are read
    /// relative to [`WinOs::syscall_guest_rsp`] — the guest RSP captured at
    /// syscall entry — not the live (switched) RSP.
    #[allow(dead_code)] // first users are the Nt* handlers in W2.6.
    pub(crate) fn syscall_arg(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u64> {
        Ok(match i {
            0 => cpu.reg(Reg::R10),
            1 => cpu.reg(Reg::Rdx),
            2 => cpu.reg(Reg::R8),
            3 => cpu.reg(Reg::R9),
            n => mem.read_u64(self.syscall_guest_rsp + 0x28 + (n as u64 - 4) * 8)?,
        })
    }

    /// Argument `i` of the current NT syscall as a **32-bit** value — for every
    /// parameter the NT prototype declares `ULONG`, `BOOLEAN` or an enum.
    ///
    /// This is not cosmetic truncation. A stack argument occupies a full 8-byte
    /// slot, but a caller storing a 32-bit value writes only the low half and
    /// **leaves the upper half holding whatever was on its stack**. Wine's own
    /// `kernelbase!FindNextFileW` does exactly that for four of
    /// `NtQueryDirectoryFile`'s arguments —
    /// `mov dword ptr [rsp+0x30], eax` (Length),
    /// `mov dword ptr [rsp+0x38], 0x3f` (FileInformationClass),
    /// `mov dword ptr [rsp+0x40], 0` (ReturnSingleEntry) and
    /// `mov dword ptr [rsp+0x50], 0` (RestartScan) — so a handler reading those
    /// slots with [`WinOs::syscall_arg`] sees values like `0x2_0000_003f` for a
    /// class of `3f` and `0x10_0000_0272` for a length of `0x272`. Measured, not
    /// theorised: those are real values off the shell-link gate's run.
    ///
    /// The consequences are silent and shaped like guest bugs — a class
    /// comparison that never matches, a `BOOLEAN` that reads true when the guest
    /// passed zero. Register-passed arguments (`i < 4`) have the same rule: the
    /// caller may have set only the 32-bit half.
    pub(crate) fn syscall_arg_u32(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u32> {
        Ok(self.syscall_arg(cpu, mem, i)? as u32)
    }

    /// Lazily reserve the dispatcher's dedicated unix stack and return the
    /// initial (top) RSP. Allocated 16-byte aligned; grows down. Returns 0 (and
    /// the dispatcher then keeps the guest stack) if the arena is exhausted —
    /// the save/restore round-trip is still correct, only the stack switch is
    /// skipped.
    fn ensure_unix_stack(&mut self, mem: &mut dyn Memory) -> u64 {
        if self.unix_stack_top != 0 {
            return self.unix_stack_top;
        }
        if let Some(base) =
            self.map_anywhere(mem, UNIX_STACK_SIZE, exemu_core::Perm::RW, "unix-stack")
        {
            // Top of the region, 16-byte aligned, one slot below the ceiling so
            // a handler's push never runs off the mapped end.
            self.unix_stack_top = (base + UNIX_STACK_SIZE - 0x10) & !0xf;
        }
        self.unix_stack_top
    }

    /// Guest address of the current thread's `syscall_frame`, or `None` when
    /// there is no TEB. The frame sits in the last [`frame::SIZE`] bytes of the
    /// running thread's TEB region so it never overlaps the TEB struct proper.
    /// Follows the *current thread's* TEB (roadmap W2.9): each thread parks its
    /// frame in its own TEB, so concurrent Wine threads never share one frame.
    fn frame_base(&self) -> Option<u64> {
        let teb = self.current_thread_teb();
        (teb != 0).then(|| teb + TEB_REGION_SIZE - frame::SIZE)
    }

    /// Phase 1 — save the non-volatile Windows context. Writes it into the TEB
    /// frame when a TEB exists, else keeps a host-side snapshot.
    fn save_context(&self, cpu: &CpuState, mem: &mut dyn Memory) -> Result<SavedContext> {
        if let Some(base) = self.frame_base() {
            mem.write_u64(base + frame::RBX, cpu.reg(Reg::Rbx))?;
            mem.write_u64(base + frame::RBP, cpu.reg(Reg::Rbp))?;
            mem.write_u64(base + frame::RSI, cpu.reg(Reg::Rsi))?;
            mem.write_u64(base + frame::RDI, cpu.reg(Reg::Rdi))?;
            mem.write_u64(base + frame::RSP, cpu.rsp())?;
            mem.write_u64(base + frame::R12, cpu.reg(Reg::R12))?;
            mem.write_u64(base + frame::R13, cpu.reg(Reg::R13))?;
            mem.write_u64(base + frame::R14, cpu.reg(Reg::R14))?;
            mem.write_u64(base + frame::R15, cpu.reg(Reg::R15))?;
            mem.write_u64(base + frame::RIP, cpu.reg(Reg::Rcx))?;
            mem.write_u64(base + frame::FLAGS, cpu.reg(Reg::R11))?;
            for n in frame::XMM_FIRST..=frame::XMM_LAST {
                let off = frame::XMM_BASE + (n - frame::XMM_FIRST) as u64 * 16;
                let v = cpu.xmm(n);
                mem.write_u64(base + off, v as u64)?;
                mem.write_u64(base + off + 8, (v >> 64) as u64)?;
            }
            Ok(SavedContext::Teb(base))
        } else {
            let mut xmm = [0u128; 10];
            for (slot, n) in xmm.iter_mut().zip(frame::XMM_FIRST..=frame::XMM_LAST) {
                *slot = cpu.xmm(n);
            }
            Ok(SavedContext::Host(Box::new(HostContext {
                gpr: [
                    cpu.reg(Reg::Rbx),
                    cpu.reg(Reg::Rbp),
                    cpu.reg(Reg::Rsi),
                    cpu.reg(Reg::Rdi),
                    cpu.rsp(),
                    cpu.reg(Reg::R12),
                    cpu.reg(Reg::R13),
                    cpu.reg(Reg::R14),
                    cpu.reg(Reg::R15),
                ],
                rip: cpu.reg(Reg::Rcx),
                flags: cpu.reg(Reg::R11),
                xmm,
            })))
        }
    }

    /// Phase 4 — restore the non-volatile set from the saved context and set up
    /// the guest return: `rip`←saved return address, RFLAGS←saved flags
    /// (restoring the guest's DF wholesale), RSP←saved guest RSP. RAX is *not*
    /// touched here — the caller places the handler's NTSTATUS there.
    fn restore_context(
        &self,
        cpu: &mut CpuState,
        mem: &dyn Memory,
        saved: &SavedContext,
    ) -> Result<()> {
        let non_vol = |cpu: &mut CpuState, gpr: [u64; 9]| {
            cpu.set_reg(Reg::Rbx, gpr[0]);
            cpu.set_reg(Reg::Rbp, gpr[1]);
            cpu.set_reg(Reg::Rsi, gpr[2]);
            cpu.set_reg(Reg::Rdi, gpr[3]);
            cpu.set_rsp(gpr[4]);
            cpu.set_reg(Reg::R12, gpr[5]);
            cpu.set_reg(Reg::R13, gpr[6]);
            cpu.set_reg(Reg::R14, gpr[7]);
            cpu.set_reg(Reg::R15, gpr[8]);
        };
        match saved {
            SavedContext::Teb(base) => {
                let base = *base;
                let gpr = [
                    mem.read_u64(base + frame::RBX)?,
                    mem.read_u64(base + frame::RBP)?,
                    mem.read_u64(base + frame::RSI)?,
                    mem.read_u64(base + frame::RDI)?,
                    mem.read_u64(base + frame::RSP)?,
                    mem.read_u64(base + frame::R12)?,
                    mem.read_u64(base + frame::R13)?,
                    mem.read_u64(base + frame::R14)?,
                    mem.read_u64(base + frame::R15)?,
                ];
                non_vol(cpu, gpr);
                cpu.rip = mem.read_u64(base + frame::RIP)?;
                cpu.rflags = mem.read_u64(base + frame::FLAGS)?;
                for n in frame::XMM_FIRST..=frame::XMM_LAST {
                    let off = frame::XMM_BASE + (n - frame::XMM_FIRST) as u64 * 16;
                    let lo = mem.read_u64(base + off)? as u128;
                    let hi = mem.read_u64(base + off + 8)? as u128;
                    cpu.set_xmm_keep_upper(n, lo | (hi << 64));
                }
            }
            SavedContext::Host(h) => {
                non_vol(cpu, h.gpr);
                cpu.rip = h.rip;
                cpu.rflags = h.flags;
                for (v, n) in h.xmm.iter().zip(frame::XMM_FIRST..=frame::XMM_LAST) {
                    cpu.set_xmm_keep_upper(n, *v);
                }
            }
        }
        Ok(())
    }

    /// Install a native handler at SSDT `index`. Each `Nt*` group (W2.6+)
    /// registers its slots this way; also the entry point through which the
    /// DLL-smoke harness / tests drive a chosen index end-to-end.
    pub fn set_syscall_handler(&mut self, index: u32, handler: SyscallHandler) {
        self.ssdt.set(index, handler);
    }

    /// Install a native handler at a **win32k** (USER/GDI) SSDT index (roadmap
    /// W4.1). The index is the raw win32u immediate (0x1084–0x1601, carrying the
    /// [`WIN32K_TABLE_BIT`]); the table stores it masked, exactly as
    /// [`WinOs::dispatch_syscall`] looks it up. The `crate::win32k` module's
    /// [`crate::win32k::register`] uses this to claim its skeleton slots; the
    /// same entry point the win32k routing test drives an index through.
    pub fn set_win32k_handler(&mut self, index: u32, handler: SyscallHandler) {
        self.win32k.set(index & !WIN32K_TABLE_BIT, handler);
    }

    /// As [`WinOs::set_win32k_handler`], but for the blanket range fill: the slot
    /// gets the handler and stays **unclaimed**, so an `EXEMU_W32K_TRACE`
    /// transcript still marks it `<UNSERVICED>` (roadmap W6.2).
    pub fn set_win32k_stub(&mut self, index: u32, handler: SyscallHandler) {
        self.win32k.set_stub(index & !WIN32K_TABLE_BIT, handler);
    }

    /// Return a full 64-bit value from the running syscall (roadmap W4.8).
    ///
    /// The SSDT handler signature returns a `u32` NTSTATUS, which is right for
    /// almost everything — but a handful of win32k services hand back real
    /// pointers (`GetWindowLongPtr` returning a control's instance data, its
    /// `Set` counterpart returning the previous one). Truncating those to 32 bits
    /// would hand the guest a pointer that faults on first use. A handler calls
    /// this and then returns any status; the dispatcher's ordinary context
    /// restore still runs, and RAX ends up holding `value`.
    pub(crate) fn return_u64_from_syscall(&mut self, value: u64) {
        self.syscall_result64 = Some(value);
    }

    /// Test-only: publish the guest RSP a native `Nt*` handler reads stack args
    /// relative to, without driving a full `SYSCALL` through the interpreter.
    #[cfg(test)]
    pub(crate) fn set_syscall_guest_rsp_for_test(&mut self, rsp: u64) {
        self.syscall_guest_rsp = rsp;
    }

    /// Full NT-syscall dispatch (see the module note for the four phases).
    pub(crate) fn dispatch_syscall(
        &mut self,
        index: u32,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Exit> {
        // Capture the guest RSP before any switch and publish it so `Nt*`
        // handlers read stack args (5+) relative to it via `syscall_arg`.
        self.syscall_guest_rsp = cpu.rsp();
        // Cleared per dispatch; a handler that switches threads itself (e.g.
        // NtTerminateThread on self) sets it to skip the restore/return below.
        self.syscall_resume_as_is = false;
        // Cleared per dispatch; NtTerminateProcess on the current process sets it
        // so the dispatcher yields Exit::ProcessExit below.
        self.pending_syscall_exit = None;
        // Cleared per dispatch; a handler returning a value too wide for the u32
        // NTSTATUS (a pointer from GetWindowLongPtr, say) sets it via
        // `return_u64_from_syscall` and the restore below honours it.
        self.syscall_result64 = None;

        // Ensure the seam itself doesn't run the host handler with DF set: the
        // guest may have left DF=1, but the native handlers assume forward
        // string ops. The guest's DF is restored wholesale via RFLAGS on return
        // (from the saved R11), so clearing it here is invisible to the guest.
        cpu.rflags &= !flags::DF;

        // Table split (roadmap W4.1): the win32k (USER/GDI) table is selected by
        // the `0x1000` bit — win32u's stubs use 0x1084–0x1601, ntdll's stay
        // below 0x1000 — indexed by the masked index. Both tables share the
        // identical save-context / unix-stack / restore seam below; only the
        // handler lookup differs. Resolved *before* the frame save so the switch
        // is untouched.
        let handler = if index & WIN32K_TABLE_BIT != 0 {
            if win32k_trace() {
                // Registers are still the guest's here (the frame save and the
                // unix-stack switch happen below), so arg0..2 read straight out.
                let masked = index & !WIN32K_TABLE_BIT;
                let mark = if self.win32k.implemented(masked) { "" } else { "  <UNSERVICED>" };
                eprintln!(
                    "[w32k] {index:#06x} {:#x} {:#x} {:#x}{mark}",
                    cpu.reg(Reg::R10),
                    cpu.reg(Reg::Rdx),
                    cpu.reg(Reg::R8)
                );
            }
            self.win32k.handler(index & !WIN32K_TABLE_BIT)
        } else {
            self.ssdt.handler(index)
        };

        // Phase 1: save the non-volatile context.
        let saved = self.save_context(cpu, mem)?;

        // Phase 2: switch to the unix stack for the duration of the handler.
        let unix_top = self.ensure_unix_stack(mem);
        if unix_top != 0 {
            cpu.set_rsp(unix_top);
        }

        // Phase 3: run the native handler resolved from the selected table.
        let status = handler(self, cpu, mem)?;

        // NtTerminateProcess on the current process asked to end the whole
        // process: yield the exit code to the run loop. The guest context is
        // being torn down, so no restore/return is performed (roadmap W3.2).
        if let Some(code) = self.pending_syscall_exit.take() {
            return Ok(Exit::ProcessExit(code));
        }

        // A handler that switched the running thread (e.g. NtTerminateThread on
        // the current thread) has already installed the guest resume state — the
        // saved frame belongs to the *terminated* thread, so restoring it would
        // clobber the newly-activated thread. Resume exactly as the handler left
        // things instead (roadmap W2.9).
        if self.syscall_resume_as_is {
            return Ok(Exit::Continue);
        }

        // Phase 4: restore the non-volatile set, then return the NTSTATUS — or
        // the full 64-bit result a handler seated instead (roadmap W4.8).
        self.restore_context(cpu, mem, &saved)?;
        let result = self.syscall_result64.take().unwrap_or(status as u64);
        cpu.set_reg(Reg::Rax, result);

        // Resume the guest at the restored `rip` (the saved return address).
        Ok(Exit::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_memory::VirtualMemory;

    fn clobber(_os: &mut WinOs, cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
        // Trash every non-volatile the dispatcher promised to preserve, plus a
        // volatile that must survive to the caller.
        for r in [Reg::Rbx, Reg::Rbp, Reg::Rsi, Reg::Rdi, Reg::R12, Reg::R13, Reg::R14, Reg::R15] {
            cpu.set_reg(r, 0xDEAD);
        }
        for n in 6u8..=15 {
            cpu.set_xmm_keep_upper(n, 0xDEAD);
        }
        cpu.set_reg(Reg::R8, 0x5A5A); // volatile → passes through
        Ok(0x1234_5678)
    }

    /// The host-fallback save/restore path (no TEB) preserves the non-volatile
    /// set and returns to RCX with the NTSTATUS, exactly like the TEB path.
    #[test]
    fn host_fallback_roundtrip_preserves_nonvolatiles() {
        let mut mem = VirtualMemory::new();
        let mut os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            teb_base: 0, // force the host-side snapshot branch
            ..WinConfig::default()
        });
        os.set_syscall_handler(7, clobber);

        let mut cpu = CpuState::default();
        // Model the state right after the CPU applied the SYSCALL side-effects.
        let ret = 0x0000_0000_0040_1234;
        cpu.set_reg(Reg::Rcx, ret); // return rip
        cpu.set_reg(Reg::R11, cpu.rflags | flags::DF); // saved flags (DF set)
        cpu.set_rsp(0x0000_0010_0000_1000);
        cpu.set_reg(Reg::Rbx, 0xB16B_00B5);
        cpu.set_reg(Reg::Rbp, 0x0BADF00D);
        cpu.set_xmm_keep_upper(6, 0xCAFE);
        cpu.set_reg(Reg::R8, 0); // will be clobbered by the handler
        let rsp_before = cpu.rsp();

        let exit = os.dispatch_syscall(7, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));

        assert_eq!(cpu.reg(Reg::Rax), 0x1234_5678, "NTSTATUS in RAX");
        assert_eq!(cpu.reg(Reg::Rbx), 0xB16B_00B5, "RBX restored");
        assert_eq!(cpu.reg(Reg::Rbp), 0x0BADF00D, "RBP restored");
        assert_eq!(cpu.xmm(6), 0xCAFE, "XMM6 restored");
        assert_eq!(cpu.reg(Reg::R8), 0x5A5A, "R8 (volatile) passes through");
        assert_eq!(cpu.rsp(), rsp_before, "guest RSP restored");
        assert_eq!(cpu.rip, ret, "resumes at the return address (saved RCX)");
        assert!(cpu.rflags & flags::DF != 0, "guest DF restored from saved R11");
    }

    /// An SSDT index with no installed handler returns STATUS_NOT_IMPLEMENTED
    /// (each Nt* group fills its slot in W2.6+).
    #[test]
    fn unimplemented_index_returns_not_implemented() {
        let mut mem = VirtualMemory::new();
        let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_rsp(0x1_0000);
        os.dispatch_syscall(0x123, &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::Rax), STATUS_NOT_IMPLEMENTED as u64);
    }

    /// The `<UNSERVICED>` signal the `EXEMU_W32K_TRACE` transcript carries
    /// (roadmap W6.2), at its source.
    ///
    /// win32k fills its **whole** index range with an honest-zero stub before
    /// overriding the slots it really services, so "does this index have a
    /// handler installed" cannot tell the two apart — every index does. What the
    /// trace needs is "did anyone *write* a handler for this", which is what
    /// [`Ssdt::set`] records and [`Ssdt::set_stub`] deliberately does not. This
    /// is the difference that makes an `EXEMU_W32K_TRACE` transcript name the
    /// next missing primitive instead of listing every call the guest makes.
    #[test]
    fn only_a_claimed_slot_counts_as_serviced() {
        fn answer(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
            Ok(0)
        }
        let mut t = Ssdt::new_win32k();
        // The blanket fill: every slot gets the stub, and none is claimed.
        for i in 0..8 {
            t.set_stub(i, answer);
        }
        assert!(!t.implemented(3), "the blanket fill does not make a slot serviced");
        // …then one real handler is written over it.
        t.set(3, answer);
        assert!(t.implemented(3), "a written handler is serviced");
        assert!(!t.implemented(4), "and its neighbour still is not");
        // Out of range is not serviced either (and does not panic).
        assert!(!t.implemented(WIN32K_LEN as u32 + 1));
    }
}
