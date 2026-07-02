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
}

/// A no-op hook, handy for tests that run raw machine code with no OS.
pub struct NoHooks;

impl Hooks for NoHooks {
    fn intercept(&mut self, _: u64, _: &mut CpuState, _: &mut dyn Memory) -> Result<Option<Exit>> {
        Ok(None)
    }
}
