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
/// `STATUS_UNSUCCESSFUL` — generic "no result" (entry 1 has nothing to unwind).
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// `STATUS_INVALID_PARAMETER` — bad handle / code / unknown info class.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_INVALID_ADDRESS` — the queried base is not a registered unixlib
/// module.
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
/// `STATUS_DLL_NOT_FOUND` — `load_so_dll` for a `.so` that does not exist in
/// exemu's all-native-builtin personality.
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
/// `STATUS_NOT_IMPLEMENTED` — re-exported from [`crate::syscall`] for the
/// unixlib stubs (`wine_server_call` until W2.11, `server_*_to_*`, `spawnvp`).
use crate::syscall::STATUS_NOT_IMPLEMENTED;

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

/// The fixed **8-entry** ntdll unixlib table (roadmap W2.5). The order is the
/// load-bearing contract — it is the `code` a PE `Nt*`/`Rtl*` stub passes to
/// `__wine_unix_call` — and matches Wine 11.0's `enum ntdll_unix_funcs`
/// (`dlls/ntdll/unixlib.h`), each index CONFIRMED against the pinned guest
/// `ntdll.dll`'s `__wine_unix_call_dispatcher` call sites (the `mov edx,N`
/// immediate): `RtlGetSystemTimePrecise` → code 7, the `__wine_dbg_write` stub
/// → code 2, the wineserver path → code 3, etc.
///
/// ```text
/// 0 load_so_dll            1 unwind_builtin_dll     2 wine_dbg_write
/// 3 wine_server_call       4 server_fd_to_handle    5 server_handle_to_fd
/// 6 spawnvp                7 system_time_precise
/// ```
///
/// Entries ntdll init actually drives are live ([`system_time_precise`],
/// [`wine_dbg_write`], [`wine_server_call`] routed to the object manager — a
/// stub until W2.11); the rest are honest stubs that return a clean NTSTATUS so
/// walking the whole table never faults (the W2.5 de-risk).
static NTDLL_UNIXLIB: &[UnixEntry] = &[
    load_so_dll,          // 0
    unwind_builtin_dll,   // 1
    wine_dbg_write,       // 2
    wine_server_call,     // 3
    server_fd_to_handle,  // 4
    server_handle_to_fd,  // 5
    spawnvp,              // 6
    system_time_precise,  // 7
];

/// `unixlib_handle_t` code for `wine_server_call` (ntdll unixlib entry 3).
/// Used by the [`crate::syscall`] `Nt*` sync handlers (W2.12) to route into the
/// wineserver from the SSDT side, so the wire opcode lives in exactly one place.
#[allow(dead_code)] // first consumer is the W2.12 Nt* sync handlers.
pub(crate) const NTDLL_WINE_SERVER_CALL: u32 = 3;

/// Entry 0 — `load_so_dll(params)`. On real Wine this `dlopen`s a native `.so`
/// builtin (e.g. `winex11.drv`). exemu has no `.so`s — every builtin is native
/// Rust registered up front via [`WinOs::register_unixlib`] — so there is
/// nothing to load. Returning `STATUS_DLL_NOT_FOUND` is the honest answer for a
/// `.so` that does not exist in this personality; the PE loader falls back to
/// the PE image, which is exactly what we want.
fn load_so_dll(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_DLL_NOT_FOUND)
}

/// Entry 1 — `unwind_builtin_dll(params)`. Drives host (libunwind) DWARF unwind
/// through a native builtin's frames during exception dispatch. exemu's builtins
/// are Rust with no guest-visible DWARF frames to walk, so there is nothing to
/// unwind here: report "no more frames" cleanly. (Guest PE unwind is the SEH /
/// `.pdata` path, handled elsewhere — not this entry.)
fn unwind_builtin_dll(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_UNSUCCESSFUL)
}

/// Entry 2 — `wine_dbg_write(params)`. The `params` block is
/// `{ const char *str; SIZE_T len; }` (confirmed from the pinned
/// `__wine_dbg_write` stub: it stores the caller's string pointer at `rsp+0x20`
/// and the length at `rsp+0x28`, then passes `r8 = rsp+0x20`, `edx = 2`). Copy
/// the bytes out of guest memory to the host trace sink and return the number of
/// bytes written (Wine's `write()`-shaped return).
fn wine_dbg_write(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args == 0 {
        return Ok(0);
    }
    let str_ptr = mem.read_u64(args)?;
    let len = mem.read_u64(args + 8)? as usize;
    if str_ptr == 0 || len == 0 {
        return Ok(0);
    }
    // Bound the copy so a mis-marshalled length can't allocate unboundedly.
    let n = len.min(0x1_0000);
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = mem.read_u8(str_ptr + i as u64)?;
    }
    os.wine_dbg_sink(&buf);
    Ok(n as u32)
}

/// Entry 3 — `wine_server_call(params)`. `params` is a pointer to the guest's
/// `__server_request_info`; the call routes into exemu's in-process object
/// manager (the wineserver equivalent, [`crate::server`], W2.11) and the
/// NTSTATUS lands back in the request's `reply_header.error`. The live
/// [`CpuState`] is threaded through so a `select` that must wait can drive the
/// scheduler (`block_and_switch`) for REAL cross-thread blocking.
fn wine_server_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.wine_server_call(args, cpu, mem)
}

/// Entry 4 — `server_fd_to_handle(params)`. Wraps a host unix fd as a server
/// object handle (used for `NtCreateFile` of already-open fds, sockets, etc.).
/// No host-fd passing exists in exemu's in-process model yet; report the clean
/// "not supported here" status until the fs/section work needs it.
fn server_fd_to_handle(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

/// Entry 5 — `server_handle_to_fd(params)`. The inverse of entry 4: unwraps a
/// server object handle to a host unix fd. Same in-process-model gap; honest
/// stub until a caller (real file/socket I/O) needs it.
fn server_handle_to_fd(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

/// Entry 6 — `spawnvp(params)`. Wine uses this to launch a host helper process
/// (e.g. the `wineserver` binary, or a native tool). exemu is self-contained and
/// spawns no host processes, so this is unsupported by design.
fn spawnvp(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

/// Entry 7 — `system_time_precise(params)`. `params` points at a single
/// `LONGLONG` output (confirmed from `RtlGetSystemTimePrecise`: it passes
/// `r8 = &out`, `edx = 7`, then reads the `LONGLONG` back from `[r8]`). Write the
/// current wall-clock time as a FILETIME (100-ns ticks since 1601), the same
/// host clock `os/time.rs` reports, and return success.
fn system_time_precise(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        mem.write_u64(args, crate::time::filetime_now())?;
    }
    Ok(STATUS_SUCCESS)
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

    /// The host trace sink for `wine_dbg_write` (ntdll unixlib entry 2). Wine's
    /// `TRACE`/`FIXME`/`ERR` channels funnel their formatted bytes here. Emit to
    /// host stderr when tracing is enabled; otherwise swallow them (a chatty
    /// guest must not spam a non-trace run). The bytes are already
    /// caller-formatted; we do not re-interpret them.
    pub(crate) fn wine_dbg_sink(&mut self, bytes: &[u8]) {
        if self.cfg.trace {
            eprint!("[wine] {}", String::from_utf8_lossy(bytes));
        }
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
        // Only a `wine_server_call` select may leave this set; clear it for
        // every dispatch so an entry that never touches it (e.g. a call made by
        // the thread switched in after a block) cannot observe a stale value.
        self.unix_call_blocked = false;
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
        let info_class = self.syscall_arg(cpu, mem, 2)? as u32;

        // `MemoryBasicInformation` (class 0, the `VirtualQuery` payload) is
        // served by the VM manager (roadmap W2.6); `MemoryWineUnixFuncs` (below)
        // resolves a module's unixlib handle (roadmap W2.4). Any other class is
        // not implemented yet.
        match info_class {
            MEMORY_WINE_UNIX_FUNCS => {}
            crate::vm::MEMORY_BASIC_INFORMATION => return self.nt_query_virtual_memory_basic(cpu, mem),
            _ => return Ok(STATUS_INVALID_PARAMETER),
        }

        let base_address = self.syscall_arg(cpu, mem, 1)?;
        let buffer = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let return_length = self.syscall_arg(cpu, mem, 5)?;

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
    /// then calls a live entry (7, `system_time_precise`) through the
    /// `__wine_unix_call` fast path and gets the Rust handler's result (the
    /// W2.4/W2.5 de-risk: query → dispatch → result round-trips).
    #[test]
    fn query_then_call_system_time_precise() {
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

        // --- 2. __wine_unix_call(handle, 7, &out) → the clock, exactly as
        // RtlGetSystemTimePrecise drives it (edx=7, r8=&out LONGLONG). ---
        let host_before = crate::time::filetime_now();
        let args = 0x2_0200;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rcx, handle); // handle
        cpu.set_reg(Reg::Rdx, 7); // code 7 = system_time_precise
        cpu.set_reg(Reg::R8, args); // args = &out
        let status = os.wine_unix_call(&mut cpu, &mut mem).unwrap();
        let host_after = crate::time::filetime_now();
        assert_eq!(status, STATUS_SUCCESS, "system_time_precise succeeded");
        let precise = mem.read_u64(args).unwrap();
        assert!(
            (host_before..=host_after).contains(&precise),
            "system_time_precise {precise} within host clock bracket [{host_before}, {host_after}]",
        );
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
        // Valid handle, out-of-range code (table has exactly 8 entries).
        assert_eq!(os.dispatch_unix_call(h, 8, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
        assert_eq!(os.dispatch_unix_call(h, 999, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    /// The W2.5 de-risk: ntdll init walks **all 8** unixlib entries without
    /// faulting, and each returns a clean NTSTATUS. Live entries (2/3/7) do their
    /// real work; the rest are honest stubs. Codes 0..8 all dispatch; code 8 is
    /// past the end and must degrade to STATUS_INVALID_PARAMETER.
    #[test]
    fn all_eight_entries_walk_without_faulting() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x3_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        let mut cpu = CpuState::default();

        // Args block: for wine_dbg_write (2) it's {str, len}; for
        // system_time_precise (7) it's a LONGLONG out slot. Both fit here.
        let msg = 0x3_0100;
        mem.write(msg, b"hi").unwrap();
        let dbg_args = 0x3_0200;
        mem.write_u64(dbg_args, msg).unwrap(); // str
        mem.write_u64(dbg_args + 8, 2).unwrap(); // len
        let time_args = 0x3_0300;
        // For wine_server_call (3): a zeroed __server_request_info — opcode 0 is
        // outside the W2.11 subset, so the live decoder (crate::server) answers
        // the default arm's clean STATUS_NOT_IMPLEMENTED.
        let srv_req = 0x3_0400;

        let expected = [
            (0u32, STATUS_DLL_NOT_FOUND, 0u64),   // load_so_dll
            (1, STATUS_UNSUCCESSFUL, 0),          // unwind_builtin_dll
            (2, 2, dbg_args),                     // wine_dbg_write → bytes written
            (3, STATUS_NOT_IMPLEMENTED, srv_req), // wine_server_call: unknown opcode → default arm
            (4, STATUS_NOT_IMPLEMENTED, 0),       // server_fd_to_handle
            (5, STATUS_NOT_IMPLEMENTED, 0),       // server_handle_to_fd
            (6, STATUS_NOT_IMPLEMENTED, 0),       // spawnvp
            (7, STATUS_SUCCESS, time_args),       // system_time_precise
        ];
        for (code, want, args) in expected {
            let got = os.dispatch_unix_call(h, code, args, &mut cpu, &mut mem).unwrap();
            assert_eq!(got, want, "entry {code} returned an unexpected NTSTATUS");
        }
        // Entry 7 actually wrote the clock.
        assert!(mem.read_u64(time_args).unwrap() > 0, "system_time_precise wrote a nonzero FILETIME");
        // Past-the-end code degrades, never faults.
        assert_eq!(os.dispatch_unix_call(h, 8, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
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
