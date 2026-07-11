//! The interception seam between the CPU and the emulated operating system.
//!
//! When the guest calls an imported function (say `kernel32!WriteFile`),
//! there is no real DLL behind it. The loader instead points the import
//! table at synthetic "thunk" addresses. Before executing the instruction
//! at `rip`, the interpreter asks its [`Hooks`] whether that address is one
//! of those thunks; if so the OS layer services the call natively and
//! returns to the caller, and the interpreter never decodes anything there.

use crate::cpu::{CpuState, Exit};
use crate::memory::Memory;
use crate::Result;

/// Implemented by the OS layer (`exemu-os`). Kept in the domain so the
/// interpreter can depend on the abstraction rather than the implementation.
pub trait Hooks {
    /// Called with the current instruction pointer *before* the interpreter
    /// decodes anything.
    ///
    /// * `Ok(None)` — not intercepted; the interpreter should decode and run
    ///   the instruction at `rip` normally.
    /// * `Ok(Some(exit))` — the call was serviced (registers/memory may have
    ///   been mutated and `rip` advanced past the thunk). The interpreter
    ///   propagates `exit`.
    fn intercept(
        &mut self,
        rip: u64,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Option<Exit>>;

    /// Called when the guest executes a native `SYSCALL` (`0F 05`). This is the
    /// NT-syscall seam: Wine's PE ntdll `Nt*` stubs issue a raw `SYSCALL` whose
    /// `eax` holds the SSDT index (`index` here); the OS layer indexes the
    /// service table and runs the native handler (roadmap W2.2/W2.3).
    ///
    /// By the time this is called the interpreter has already applied the
    /// hardware side-effects: return `rip` is in `rcx`, `rflags` is in `r11`,
    /// and `cpu.rip` points at the instruction *after* the `SYSCALL`. The
    /// handler reads its arguments from `r10`/`rdx`/`r8`/`r9` (+ the stack for
    /// args 5+), writes its NTSTATUS to `rax`, and returns an [`Exit`] (normally
    /// [`Exit::Continue`], which resumes the guest at `rcx`).
    ///
    /// The default surfaces the syscall unserviced so a bare CPU (with no OS)
    /// still terminates cleanly rather than silently swallowing it.
    fn syscall(&mut self, index: u32, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<Exit> {
        let _ = index;
        Ok(Exit::Interrupt(0x80))
    }
}

/// A no-op hook, handy for tests that run raw machine code with no OS.
pub struct NoHooks;

impl Hooks for NoHooks {
    fn intercept(&mut self, _: u64, _: &mut CpuState, _: &mut dyn Memory) -> Result<Option<Exit>> {
        Ok(None)
    }
}
