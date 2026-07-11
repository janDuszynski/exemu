//! The `__wine_unix_call` fast path + `NtQueryVirtualMemory(MemoryWineUnixFuncs)`
//! (roadmap W2.4).
//!
//! Wine's PE `ntdll.dll` reaches the "unix side" through **two** call
//! mechanisms (plus one IPC). One is the heavyweight NT syscall — a raw
//! `SYSCALL` routed through the SSDT dispatcher ([`crate::syscall`], W2.2/W2.3).
//! The other, implemented here, is the lighter **`__wine_unix_call`** path a PE
//! DLL uses to call its paired unixlib:
//!
//! ```text
//! NTSTATUS __wine_unix_call(unixlib_handle_t handle, unsigned int code, void *args);
//! ```
//!
//! * `handle` selects *which* unixlib (a per-DLL opaque token);
//! * `code` indexes that unixlib's ordered function table;
//! * `args` is one pointer to a packed argument block the entry reads from guest
//!   memory as its own typed struct.
//!
//! On native x64 the PE side reaches `__wine_unix_call` through an **indirect
//! call** to the `__wine_unix_call_dispatcher` pointer that the unix side of
//! ntdll fills in at load. The observed guest ABI (recovered from the pinned
//! `ntdll.dll`'s `__wine_unix_*` stubs — clean-room-permitted guest-binary
//! analysis) is: **RCX = handle, EDX = code, R8 = args pointer**, NTSTATUS
//! returned in RAX, an ordinary `call` (return address on the stack).
//!
//! exemu has **no `.so` files** — the "unix side" of every builtin is native
//! Rust. So there is nothing to `dlsym`: [`WinOs`] keeps a Rust
//! [`Unixlib`] registry ([`WinOs::unixlibs`]) and the `handle` is simply the
//! index into it (a valid Class-B re-mapping of the `.so` pointer per the W2
//! design). A PE DLL obtains its handle by querying
//! `NtQueryVirtualMemory(GetCurrentProcess(), module_base, MemoryWineUnixFuncs,
//! &handle, …)`, which resolves `module_base` to its registered unixlib and
//! writes back the opaque index.
//!
//! **Fast path — deliberately not the SSDT.** `__wine_unix_call` is an ordinary
//! intercepted call ([`crate::Hooks::intercept`], no new trait variant): it runs
//! on the current guest stack with the live [`CpuState`], with no
//! `KUSER_SHARED_DATA.SystemCall` check, no dispatcher page, and no syscall-frame
//! save into the TEB. The three-arg marshalled ABI sidesteps the SSDT indexing
//! and context switch entirely — that is why it is the "fast path".
//!
//! **Clean-room note (Class B).** The `__wine_unix_call` signature and the
//! `MemoryWineUnixFuncs` query contract derive from the public `unixlib.h` /
//! `winternl.h` interface definitions and Wine's *published* PE→Unix
//! architecture; the register ABI and the `NtQueryVirtualMemory` SSDT index
//! (`0x23`) were recovered from the pinned guest binary's stubs. No Wine `.c`
//! implementation was read; the Rust registry mapping is original.

use exemu_core::{CpuState, Memory, Reg, Result};

use crate::WinOs;

/// `MEMORY_INFORMATION_CLASS::MemoryWineUnixFuncs` — Wine's private memory-query
/// class through which a PE DLL fetches its unixlib handle. Public Wine
/// interface value (`winternl.h` extension range: `1000` == the first Wine
/// class).
pub(crate) const MEMORY_WINE_UNIX_FUNCS: u32 = 1000;

/// SSDT index of `NtQueryVirtualMemory`, recovered from the pinned guest
/// `ntdll.dll` stub (`mov eax, 0x23`). The full memory-query behavior lands in
/// W2.6; W2.4 installs only the `MemoryWineUnixFuncs` arm so a PE DLL can obtain
/// its unixlib handle.
pub(crate) const SSDT_NT_QUERY_VIRTUAL_MEMORY: u32 = 0x23;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_INVALID_PARAMETER` — bad handle / code / unknown info class.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_INVALID_ADDRESS` — the queried base is not a registered unixlib
/// module.
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;

/// One native unixlib entry: it receives the packed `args` pointer (read from
/// guest memory as its own typed struct) and returns an NTSTATUS. It runs on the
/// live [`CpuState`]/[`Memory`], the same fast-path context as the caller.
pub type UnixEntry = fn(&mut WinOs, &mut CpuState, &mut dyn Memory, args: u64) -> Result<u32>;

/// A registered unixlib: a fixed, ordered function table. The index into the
/// table is the `code` a PE DLL passes to `__wine_unix_call`; the table's order
/// is therefore the load-bearing contract (W2.5 fills ntdll's full 8-entry
/// order).
pub struct Unixlib {
    /// Diagnostics-only name (e.g. `"ntdll"`).
    pub name: &'static str,
    /// The ordered entry table; `code` indexes it directly.
    pub table: &'static [UnixEntry],
}

/// W2.4 placeholder ntdll unixlib table. W2.5 replaces this with the fixed
/// 8-entry contract (`load_so_dll`, `unwind_builtin_dll`, `wine_dbg_write`,
/// `wine_server_call`, `server_fd_to_handle`, `server_handle_to_fd`, `spawnvp`,
/// `system_time_precise`). For now entry 0 is a live handler so the fast path is
/// end-to-end testable; every other index is [`ntdll_unimplemented`].
static NTDLL_UNIXLIB: &[UnixEntry] = &[ntdll_probe];

/// The W2.4 stand-in for ntdll unixlib entry 0. It reads a `u64` from the packed
/// `args` block and returns it (mod 2^32) as the NTSTATUS, proving the marshalled
/// three-arg ABI round-trips: the guest's `code`/`args` reached a Rust handler
/// and its result flowed back to RAX. Replaced by the real entries in W2.5.
fn ntdll_probe(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args == 0 {
        return Ok(STATUS_SUCCESS);
    }
    Ok(mem.read_u64(args)? as u32)
}

/// Handler for an unimplemented ntdll unixlib slot (used once W2.5 installs the
/// full table for indices with no behavior yet).
#[allow(dead_code)] // first user is the W2.5 8-entry table.
pub(crate) fn ntdll_unimplemented(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
    _args: u64,
) -> Result<u32> {
    Ok(crate::syscall::STATUS_NOT_IMPLEMENTED)
}

impl WinOs {
    /// Register `lib` for `module_base` and return its opaque `unixlib_handle_t`
    /// (the index into [`WinOs::unixlibs`]). A PE DLL then discovers this handle
    /// via `NtQueryVirtualMemory(module_base, MemoryWineUnixFuncs, …)`. Called
    /// once per builtin at load; re-registering the same base returns the
    /// existing handle.
    pub fn register_unixlib(&mut self, module_base: u64, lib: Unixlib) -> u64 {
        if let Some(&h) = self.unixlib_of_module.get(&module_base) {
            return h;
        }
        let handle = self.unixlibs.len() as u64;
        self.unixlibs.push(lib);
        self.unixlib_of_module.insert(module_base, handle);
        handle
    }

    /// Register the ntdll unixlib against `ntdll_base`. Called by the loader when
    /// the PE `ntdll.dll` is mapped (W2.5+/W2.16 harness); the returned handle is
    /// what `MemoryWineUnixFuncs` reports for ntdll's own image base.
    pub fn register_ntdll_unixlib(&mut self, ntdll_base: u64) -> u64 {
        self.register_unixlib(
            ntdll_base,
            Unixlib { name: "ntdll", table: NTDLL_UNIXLIB },
        )
    }

    /// The unixlib handle registered for `module_base`, if any. Backs the
    /// `MemoryWineUnixFuncs` query arm.
    pub(crate) fn unixlib_handle_of(&self, module_base: u64) -> Option<u64> {
        self.unixlib_of_module.get(&module_base).copied()
    }

    /// The `__wine_unix_call` fast path: dispatch `code` in `unixlibs[handle]`
    /// with the packed `args` pointer. Returns the entry's NTSTATUS, or
    /// `STATUS_INVALID_PARAMETER` for an out-of-range handle or code (so a
    /// mis-marshalled call degrades to a clean status rather than a fault).
    pub(crate) fn dispatch_unix_call(
        &mut self,
        handle: u64,
        code: u32,
        args: u64,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let Some(entry) = self
            .unixlibs
            .get(handle as usize)
            .and_then(|lib| lib.table.get(code as usize))
            .copied()
        else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        entry(self, cpu, mem, args)
    }

    /// Intercept handler for the `__wine_unix_call` thunk (the target the loader
    /// stores in `__wine_unix_call_dispatcher`). Reads the guest ABI —
    /// RCX = handle, EDX = code, R8 = args pointer — dispatches, and leaves the
    /// NTSTATUS in RAX. The intercept seam (`Hooks::intercept`) performs the
    /// `ret` afterwards; this is a plain native call, not a syscall.
    pub(crate) fn wine_unix_call(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = cpu.reg(Reg::Rcx);
        let code = cpu.reg(Reg::Rdx) as u32;
        let args = cpu.reg(Reg::R8);
        self.dispatch_unix_call(handle, code, args, cpu, mem)
    }

    /// The `MemoryWineUnixFuncs` arm of `NtQueryVirtualMemory`
    /// (`NtQueryVirtualMemory(process, base_address, MemoryWineUnixFuncs,
    /// buffer, length, return_length)`). Resolves `base_address` to its
    /// registered unixlib and writes the opaque `unixlib_handle_t` into
    /// `buffer`. Other info classes are W2.6.
    ///
    /// SSDT arg order (x64 syscall ABI): arg0=R10 process handle (ignored — the
    /// current-process pseudo-handle at the gate), arg1=base_address,
    /// arg2=info_class, arg3=buffer, arg4=length, arg5=return_length.
    pub(crate) fn nt_query_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_address = self.syscall_arg(cpu, mem, 1)?;
        let info_class = self.syscall_arg(cpu, mem, 2)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let return_length = self.syscall_arg(cpu, mem, 5)?;

        if info_class != MEMORY_WINE_UNIX_FUNCS {
            // Other memory-info classes (MemoryBasicInformation, …) land in W2.6.
            return Ok(STATUS_INVALID_PARAMETER);
        }

        // The out buffer is a `unixlib_handle_t` (pointer-sized on the wire).
        if buffer == 0 || length < 8 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(handle) = self.unixlib_handle_of(base_address) else {
            return Ok(STATUS_INVALID_ADDRESS);
        };
        mem.write_u64(buffer, handle)?;
        if return_length != 0 {
            mem.write_u64(return_length, 8)?;
        }
        Ok(STATUS_SUCCESS)
    }
}

/// The SSDT-shaped thunk for `NtQueryVirtualMemory` (index
/// [`SSDT_NT_QUERY_VIRTUAL_MEMORY`]). Installed into the dispatcher's service
/// table so a raw guest `SYSCALL 0x23` reaches [`WinOs::nt_query_virtual_memory`]
/// through the full save/switch/restore path. W2.6 broadens it to the other
/// info classes.
pub(crate) fn ssdt_nt_query_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_virtual_memory(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::Exit;
    use exemu_memory::VirtualMemory;

    fn os64() -> WinOs {
        WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() })
    }

    /// A PE DLL obtains its unixlib array via the `MemoryWineUnixFuncs` query,
    /// then calls entry 0 through the `__wine_unix_call` fast path and gets the
    /// Rust handler's result (the W2.4 de-risk).
    #[test]
    fn query_then_call_entry0() {
        let mut mem = VirtualMemory::new();
        // Scratch page for the query out-buffer + the packed args block.
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();

        let mut os = os64();
        let ntdll_base = 0x7f00_0000;
        let expected_handle = os.register_ntdll_unixlib(ntdll_base);

        // --- 1. NtQueryVirtualMemory(MemoryWineUnixFuncs) → the handle. ---
        // Drive the SSDT arg registers directly (arg0=R10 … arg3=R8, arg4/5 on
        // the guest stack, read relative to the captured guest RSP).
        let out_buf = 0x2_0100;
        let ret_len = 0x2_0108;
        cpu_query(&mut os, &mut mem, ntdll_base, out_buf, ret_len);
        let handle = mem.read_u64(out_buf).unwrap();
        assert_eq!(handle, expected_handle, "query returns the registered handle");
        assert_eq!(mem.read_u64(ret_len).unwrap(), 8, "return_length written");

        // --- 2. __wine_unix_call(handle, 0, args) → the Rust handler result. ---
        let args = 0x2_0200;
        mem.write_u64(args, 0x1234_5678).unwrap();
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rcx, handle); // handle
        cpu.set_reg(Reg::Rdx, 0); // code 0
        cpu.set_reg(Reg::R8, args); // args ptr
        let status = os.wine_unix_call(&mut cpu, &mut mem).unwrap();
        assert_eq!(status, 0x1234_5678, "entry 0 returned its Rust-computed result");
    }

    /// Drive `nt_query_virtual_memory` with the SSDT ABI set up: process handle
    /// in R10, base in RDX, class in R8, buffer in R9, length + return_length on
    /// the guest stack. `syscall_guest_rsp` must point at that stack.
    fn cpu_query(os: &mut WinOs, mem: &mut VirtualMemory, base: u64, out_buf: u64, ret_len: u64) {
        // A tiny guest stack holding args 4 (length) and 5 (return_length).
        let gsp = 0x2_0800;
        mem.write_u64(gsp + 0x28, 8).unwrap(); // arg4: length
        mem.write_u64(gsp + 0x30, ret_len).unwrap(); // arg5: return_length ptr
        os.set_syscall_guest_rsp_for_test(gsp);

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, 0xFFFF_FFFF_FFFF_FFFF); // process = current pseudo-handle
        cpu.set_reg(Reg::Rdx, base); // arg1: base_address
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64); // arg2: info_class
        cpu.set_reg(Reg::R9, out_buf); // arg3: buffer
        let status = os.nt_query_virtual_memory(&mut cpu, mem).unwrap();
        assert_eq!(status, STATUS_SUCCESS);
    }

    /// An unknown handle or code degrades to STATUS_INVALID_PARAMETER, not a
    /// fault (a mis-marshalled fast-path call must stay recoverable).
    #[test]
    fn bad_handle_or_code_is_invalid_parameter() {
        let mut mem = VirtualMemory::new();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        let mut cpu = CpuState::default();
        // Out-of-range handle.
        assert_eq!(os.dispatch_unix_call(h + 99, 0, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
        // Valid handle, out-of-range code.
        assert_eq!(os.dispatch_unix_call(h, 999, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    /// The query rejects an unregistered base and an unknown info class.
    #[test]
    fn query_rejects_bad_base_and_class() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.register_ntdll_unixlib(0x7f00_0000);
        os.set_syscall_guest_rsp_for_test(0x2_0800);

        // Unregistered base → STATUS_INVALID_ADDRESS.
        let mut cpu = CpuState::default();
        mem.write_u64(0x2_0800 + 0x28, 8).unwrap();
        mem.write_u64(0x2_0800 + 0x30, 0).unwrap();
        cpu.set_reg(Reg::Rdx, 0xdead_0000); // unregistered base
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64);
        cpu.set_reg(Reg::R9, 0x2_0100);
        assert_eq!(os.nt_query_virtual_memory(&mut cpu, &mut mem).unwrap(), STATUS_INVALID_ADDRESS);

        // Unknown info class → STATUS_INVALID_PARAMETER (W2.6 handles the rest).
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rdx, 0x7f00_0000);
        cpu.set_reg(Reg::R8, 0); // MemoryBasicInformation, not ours yet
        cpu.set_reg(Reg::R9, 0x2_0100);
        assert_eq!(os.nt_query_virtual_memory(&mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    /// The SSDT-registered `NtQueryVirtualMemory` handler is reachable through
    /// the dispatcher and answers the `MemoryWineUnixFuncs` class end-to-end.
    #[test]
    fn ssdt_slot_answers_query() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        os.set_syscall_handler(SSDT_NT_QUERY_VIRTUAL_MEMORY, ssdt_nt_query_virtual_memory);

        // Guest stack for args 4/5 lives below the region the dispatcher's unix
        // stack switch will move RSP to; the handler reads args relative to the
        // captured guest RSP, which the dispatcher records for us.
        let gsp = 0x2_0800;
        mem.write_u64(gsp + 0x28, 8).unwrap();
        mem.write_u64(gsp + 0x30, 0).unwrap();

        let mut cpu = CpuState::default();
        cpu.set_rsp(gsp);
        cpu.set_reg(Reg::Rcx, 0x4000); // SYSCALL return rip (saved by the seam)
        cpu.set_reg(Reg::R10, 0xFFFF_FFFF_FFFF_FFFF);
        cpu.set_reg(Reg::Rdx, base);
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64);
        cpu.set_reg(Reg::R9, 0x2_0100);

        let exit = os.dispatch_syscall(SSDT_NT_QUERY_VIRTUAL_MEMORY, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64, "NTSTATUS in RAX");
        assert_eq!(mem.read_u64(0x2_0100).unwrap(), h, "handle written to out-buffer");
    }
}
