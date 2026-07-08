//! # exemu-os — the emulated Windows userland
//!
//! This crate stands in for `kernel32.dll` (and friends). There are no real
//! Windows DLLs in the address space; instead every imported symbol is
//! assigned a unique *thunk address* by [`WinOs::resolve_import`]. The
//! application writes that address into the guest's Import Address Table.
//!
//! When the guest `call`s through the IAT and `rip` lands on a thunk, the
//! interpreter asks us — via the [`Hooks`] trait — to service it. We read
//! the arguments per the Windows x64 calling convention, run the call
//! natively on the host, put the result in `rax`, and simulate the `ret`
//! back to the caller. The guest never executes a single instruction of the
//! "DLL".
//!
//! The layer depends only on the domain (`exemu-core`); the concrete memory
//! mapping of thunks, PEB/TEB and the heap arena is arranged by the
//! application, which passes us the relevant addresses in [`WinConfig`].

#![forbid(unsafe_code)]

mod api;
mod dll;
mod exc;
mod fs;
mod gdi;
mod vm;

use std::collections::HashMap;

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Reg, Result};

pub use api::Api;

/// Addresses and sizes the application hands us so the emulated OS knows
/// where its thunks, heap and process strings live.
#[derive(Debug, Clone)]
pub struct WinConfig {
    /// Base of the synthetic region where API thunk addresses are handed out.
    pub api_base: u64,
    /// Bump-allocated heap arena `[heap_base, heap_base + heap_size)`.
    pub heap_base: u64,
    pub heap_size: u64,
    /// Reported by `GetModuleHandle(NULL)`.
    pub image_base: u64,
    /// Pointer to the ASCII / UTF-16 command line (mapped by the app).
    pub cmdline_ptr_a: u64,
    pub cmdline_ptr_w: u64,
    /// If true, guest console output is echoed to the host stdout/stderr in
    /// addition to being captured. Tests set this false.
    pub echo: bool,
    /// If true, unimplemented API calls are logged to the host stderr.
    pub trace: bool,
    /// Target bitness: true for x86-64 (System V-ish register args), false
    /// for 32-bit x86 (stdcall/cdecl stack args, callee cleanup).
    pub is_64bit: bool,
    /// Host directory that roots the guest filesystem. Empty disables file
    /// I/O (operations then fail as they did before).
    pub sandbox: String,
    /// The guest path of the running module, reported by GetModuleFileNameW.
    pub module_path_w: String,
    /// RWX arena where dynamically loaded DLLs are mapped
    /// `[dll_base, dll_base + dll_size)`.
    pub dll_base: u64,
    pub dll_size: u64,
    /// Base of the address window from which `VirtualAlloc(NULL, …)` hands out
    /// fresh reservations (the VM manager bumps upward from here, skipping any
    /// region already mapped). Must be clear of every other region above.
    pub valloc_base: u64,
}

impl Default for WinConfig {
    fn default() -> Self {
        WinConfig {
            api_base: 0x0000_7EFF_0000_0000,
            heap_base: 0x0000_0002_0000_0000,
            heap_size: 0x0400_0000, // 64 MiB
            image_base: 0x1_4000_0000,
            cmdline_ptr_a: 0,
            cmdline_ptr_w: 0,
            echo: true,
            trace: false,
            is_64bit: true,
            sandbox: String::new(),
            module_path_w: "C:\\program.exe".into(),
            dll_base: 0x0000_0006_0000_0000,
            dll_size: 0x0800_0000, // 128 MiB
            valloc_base: 0x0000_0040_0000_0000, // 256 GiB: between stack and thunks
        }
    }
}

/// The emulated Windows OS: thunk registry, process state and API impls.
pub struct WinOs {
    cfg: WinConfig,
    /// thunk address → which API it stands for.
    thunks: HashMap<u64, Api>,
    /// (dll, symbol) → thunk address, so repeated imports share one thunk.
    interned: HashMap<(String, String), u64>,
    next_thunk: u64,
    heap_next: u64,
    /// Per-allocation size map: guest ptr → allocated byte count (size.max(1)).
    /// Populated by every heap_alloc call; used by HeapReAlloc to copy only the
    /// min(old_size, new_size) bytes and by HeapFree for last-block reclaim.
    heap_sizes: HashMap<u64, u64>,
    last_error: u32,

    /// The `VirtualAlloc` family's reservations (sorted by base). Each entry
    /// tracks the nominal `PAGE_*` protection and commit state so `VirtualQuery`
    /// and `VirtualProtect` report honest values even though the backing memory
    /// is mapped permissively (RWX) — see [`crate::vm`].
    vm_allocs: Vec<vm::VmAlloc>,
    /// Bump hint for the next `VirtualAlloc(NULL, …)` reservation.
    valloc_next: u64,

    /// Thunk address whose interception drives sequential `_initterm`
    /// callbacks (see [`api::InittermFrame`]).
    initterm_driver: u64,
    /// Active `_initterm` invocations (a stack, since a constructor may
    /// itself trigger another `_initterm`).
    initterm_stack: Vec<api::InittermFrame>,

    /// Thunk that drives general guest callbacks (window/dialog procs).
    cb_driver: u64,
    /// Active guest-callback sequences (see [`api::CbFrame`]).
    cb_stack: Vec<api::CbFrame>,
    /// Dialog-control text by control id (single active dialog assumed),
    /// stored as UTF-16 code units. Backs Get/SetDlgItemTextW & WM_GET/SETTEXT.
    controls: std::collections::HashMap<u32, Vec<u16>>,
    /// Remaining `WM_NULL` iterations `GetMessageW`/`PeekMessageW` will hand a
    /// message-loop before reporting `WM_QUIT`, so deferred-work loops run.
    msg_pumps: u32,

    /// The windowing backend (NoGui = headless auto-drive).
    gui: Box<dyn exemu_core::Gui>,
    /// Dialog templates parsed from the image, by resource id.
    dialogs: std::collections::HashMap<u32, exemu_core::DialogTemplate>,
    /// The active dialog's procedure and window handle (when a real window is
    /// shown), and whether the guest posted a quit.
    dlgproc: u64,
    dialog_hwnd: u64,
    quit_posted: bool,
    /// Set by EndDialog to terminate an active modal dialog loop (the value
    /// is what DialogBoxParam returns).
    dialog_result: Option<u64>,
    /// Progress-bar state by control id: (min, max, pos).
    progress: std::collections::HashMap<u32, (i64, i64, i64)>,
    /// Custom (CreateWindowEx) window + GDI state.
    gdi: gdi::Gdi,
    /// Dynamically loaded DLLs (LoadLibrary/GetProcAddress).
    dll: dll::Loader,

    /// Open guest file handles → host file objects.
    files: std::collections::HashMap<u64, fs::OpenFile>,
    /// Open directory-enumeration handles (FindFirstFileW / FindNextFileW).
    find_handles: std::collections::HashMap<u64, fs::FindState>,
    next_handle: u64,
    /// Monotonic source of unique temp-file numbers.
    temp_counter: u32,
    /// Writable backing cells for the CRT global-accessor family (`__p__fmode`
    /// etc.), one per distinct name, allocated lazily from the heap arena.
    crt_globals: std::collections::HashMap<String, u64>,

    /// Process environment (ordered `name=value` pairs), seeded with a
    /// plausible Windows environment. Backs the `GetEnvironmentStrings*`,
    /// `GetEnvironmentVariable*`, `SetEnvironmentVariable*` and
    /// `ExpandEnvironmentStrings*` families. Kept ordered so successive
    /// `GetEnvironmentStrings` calls are stable and match `Set` insertions.
    env: Vec<(String, String)>,

    /// Thread-Local Storage slots (`TlsAlloc` family). `Some(v)` = allocated,
    /// holding value `v`; `None` = free. Single-threaded, so one global vector.
    tls_slots: Vec<Option<u64>>,
    /// Fiber-Local Storage slots (`FlsAlloc` family) — the same model, in a
    /// separate namespace. The MSVC CRT keeps its per-thread data pointer here.
    fls_slots: Vec<Option<u64>>,

    /// In-memory registry hive: full canonical key path → value map.
    /// Value map: value name → (REG_* type, raw bytes). The default value
    /// for a key uses the empty string as its name.
    reg_hive: HashMap<String, HashMap<String, (u32, Vec<u8>)>>,
    /// Open registry handles (HKEY values allocated by RegCreateKeyExW /
    /// RegOpenKeyExW) → the canonical key path they refer to.
    reg_handles: HashMap<u64, String>,

    /// Captured console output (also echoed to the host when `cfg.echo`).
    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,

    /// The image's x64 unwind function table (sorted by begin RVA), used by
    /// `RtlLookupFunctionEntry`/`RtlVirtualUnwind`/exception dispatch. Empty
    /// for 32-bit images. See [`crate::exc`].
    function_table: Vec<exemu_core::UnwindEntry>,
    /// Thunk that drives re-entrant exception-handler calls (roadmap P4.3c).
    exc_driver: u64,
    /// Active exception dispatches (a stack: a handler can raise again).
    exc_stack: Vec<exc::DispatchFrame>,
    /// The filter installed by `SetUnhandledExceptionFilter`, or 0.
    unhandled_filter: u64,
}

// Sentinel handle values returned by GetStdHandle and understood by WriteFile.
const HANDLE_STDIN: u64 = 0x0C;
const HANDLE_STDOUT: u64 = 0x10;
const HANDLE_STDERR: u64 = 0x14;
const HANDLE_PROCESS_HEAP: u64 = 0x00AB_0000;

impl WinOs {
    pub fn new(cfg: WinConfig) -> Self {
        let (api_base, heap_base, valloc_base) = (cfg.api_base, cfg.heap_base, cfg.valloc_base);
        let mut os = WinOs {
            cfg,
            thunks: HashMap::new(),
            interned: HashMap::new(),
            next_thunk: api_base,
            heap_next: heap_base,
            heap_sizes: HashMap::new(),
            last_error: 0,
            vm_allocs: Vec::new(),
            valloc_next: valloc_base,
            initterm_driver: 0,
            initterm_stack: Vec::new(),
            cb_driver: 0,
            cb_stack: Vec::new(),
            controls: std::collections::HashMap::new(),
            msg_pumps: 8,
            gui: Box::new(exemu_core::NoGui),
            dialogs: std::collections::HashMap::new(),
            dlgproc: 0,
            dialog_hwnd: 0,
            quit_posted: false,
            dialog_result: None,
            progress: std::collections::HashMap::new(),
            gdi: gdi::Gdi::default(),
            dll: dll::Loader::default(),
            files: std::collections::HashMap::new(),
            find_handles: std::collections::HashMap::new(),
            next_handle: 0x0000_1000,
            temp_counter: 0,
            crt_globals: std::collections::HashMap::new(),
            env: default_environment(),
            tls_slots: Vec::new(),
            fls_slots: Vec::new(),
            reg_hive: HashMap::new(),
            reg_handles: HashMap::new(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            function_table: Vec::new(),
            exc_driver: 0,
            exc_stack: Vec::new(),
            unhandled_filter: 0,
        };
        // Reserve the driver thunks up front so their addresses are stable.
        os.initterm_driver = os.alloc_thunk(Api::InittermDriver);
        os.cb_driver = os.alloc_thunk(Api::CallbackDriver);
        os.exc_driver = os.alloc_thunk(Api::ExceptionDriver);
        os
    }

    /// Hand the emulated OS the image's parsed x64 unwind table so the native
    /// `Rtl*` exception APIs and exception dispatch can walk guest frames
    /// (roadmap P4.3). No-op for 32-bit images (the table is empty).
    pub fn set_unwind_table(&mut self, table: Vec<exemu_core::UnwindEntry>) {
        self.function_table = table;
    }

    /// The image's unwind function table (for the app's fault-report backtrace).
    pub fn unwind_table(&self) -> &[exemu_core::UnwindEntry] {
        &self.function_table
    }

    /// Install a windowing backend and the image's dialog templates. With a
    /// real backend, `CreateDialogParamW` shows a window and the message loop
    /// blocks on user input instead of auto-driving the Install button.
    pub fn set_gui(
        &mut self,
        gui: Box<dyn exemu_core::Gui>,
        dialogs: std::collections::HashMap<u32, exemu_core::DialogTemplate>,
    ) {
        self.gui = gui;
        self.dialogs = dialogs;
    }

    /// Whether a real (non-headless) window backend is installed and showing.
    fn gui_active(&self) -> bool {
        self.gui.is_open()
    }

    /// Allocate a fresh thunk address bound to `api`.
    fn alloc_thunk(&mut self, api: Api) -> u64 {
        let addr = self.next_thunk;
        self.next_thunk += 8;
        self.thunks.insert(addr, api);
        addr
    }

    /// Assign (or reuse) a thunk address for an imported symbol. The returned
    /// address is what the loader writes into the IAT slot.
    pub fn resolve_import(&mut self, dll: &str, symbol: &ImportSymbol) -> u64 {
        let name = match symbol {
            ImportSymbol::Named(n) => n.clone(),
            ImportSymbol::Ordinal(o) => format!("#ord{o}"),
        };
        let key = (dll.to_string(), name.clone());
        if let Some(&addr) = self.interned.get(&key) {
            return addr;
        }
        let addr = self.next_thunk;
        self.next_thunk += 8;
        let api = Api::classify(dll, &name);
        self.thunks.insert(addr, api);
        self.interned.insert(key, addr);
        addr
    }

    /// Allocate the sentinel "return address" placed beneath the entry point.
    /// When the guest's entry function `ret`s to it, the process terminates
    /// with the code in EAX.
    pub fn exit_thunk(&mut self) -> u64 {
        self.alloc_thunk(Api::ReturnExit)
    }

    /// Range `[start, end)` of assigned thunk addresses, so the application
    /// can (optionally) reserve it in the memory map.
    pub fn thunk_range(&self) -> (u64, u64) {
        (self.cfg.api_base, self.next_thunk)
    }

    /// Reverse-lookup: which imported `dll!symbol` a thunk address belongs to.
    /// Used to produce a precise diagnostic when the guest dereferences an
    /// import thunk as data (i.e. the symbol was a data export, not a
    /// function).
    pub fn symbol_for_thunk(&self, addr: u64) -> Option<String> {
        self.interned
            .iter()
            .find(|(_, &a)| a == addr)
            .map(|((dll, name), _)| format!("{dll}!{name}"))
    }

    /// Captured standard output produced by the guest.
    pub fn captured_stdout(&self) -> &[u8] {
        &self.stdout_buf
    }
    /// Captured standard error produced by the guest.
    pub fn captured_stderr(&self) -> &[u8] {
        &self.stderr_buf
    }

    // ---- calling-convention helpers --------------------------------------

    /// Integer/pointer argument `i` (0-based) at API entry.
    ///
    /// * x86-64: RCX/RDX/R8/R9, then the stack above the 32-byte shadow space.
    /// * x86-32: all arguments are 4-byte stack slots at `[esp+4 + i*4]`
    ///   (`[esp]` is the return address). This holds for both stdcall and
    ///   cdecl — they differ only in who cleans up.
    fn arg(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u64> {
        if self.cfg.is_64bit {
            Ok(match i {
                0 => cpu.reg(Reg::Rcx),
                1 => cpu.reg(Reg::Rdx),
                2 => cpu.reg(Reg::R8),
                3 => cpu.reg(Reg::R9),
                n => mem.read_u64(cpu.rsp() + 0x28 + (n as u64 - 4) * 8)?,
            })
        } else {
            Ok(mem.read_u32(cpu.rsp() + 4 + (i as u64) * 4)? as u64)
        }
    }

    /// Read a pointer-sized value (4 bytes in 32-bit mode, 8 in 64-bit).
    pub(crate) fn read_ptr(&self, mem: &dyn Memory, addr: u64) -> Result<u64> {
        if self.cfg.is_64bit {
            mem.read_u64(addr)
        } else {
            Ok(mem.read_u32(addr)? as u64)
        }
    }

    /// Write a pointer-sized value (4 bytes in 32-bit mode, 8 in 64-bit).
    pub(crate) fn write_ptr(&self, mem: &mut dyn Memory, addr: u64, val: u64) -> Result<()> {
        if self.cfg.is_64bit {
            mem.write_u64(addr, val)
        } else {
            mem.write_u32(addr, val as u32)
        }
    }

    /// Simulate the callee's `ret`: pop the return address into `rip`, and in
    /// 32-bit mode additionally clean `stack_args * 4` bytes off the stack for
    /// stdcall functions (the Win32 default). 64-bit callers clean their own.
    fn ret(&self, cpu: &mut CpuState, mem: &dyn Memory, stack_args: u32) -> Result<()> {
        let sp = cpu.rsp();
        if self.cfg.is_64bit {
            cpu.rip = mem.read_u64(sp)?;
            cpu.set_rsp(sp + 8);
        } else {
            cpu.rip = mem.read_u32(sp)? as u64;
            cpu.set_rsp((sp + 4 + stack_args as u64 * 4) & 0xFFFF_FFFF);
        }
        Ok(())
    }

    /// Append console output, echoing to the host if configured.
    fn emit(&mut self, is_err: bool, bytes: &[u8]) {
        use std::io::Write;
        if is_err {
            self.stderr_buf.extend_from_slice(bytes);
        } else {
            self.stdout_buf.extend_from_slice(bytes);
        }
        if self.cfg.echo {
            if is_err {
                let _ = std::io::stderr().write_all(bytes);
            } else {
                let _ = std::io::stdout().write_all(bytes);
            }
        }
    }

    /// Bump-allocate `size` bytes from the heap arena (always zero-filled,
    /// since the arena is mapped zeroed and never reused). Returns 0 (and
    /// sets ERROR_NOT_ENOUGH_MEMORY) when the arena is exhausted.
    ///
    /// Records the allocation in `heap_sizes` so that `HeapReAlloc` can copy
    /// only the exact old block size, and `HeapFree` can reclaim the last block.
    fn heap_alloc(&mut self, size: u64) -> u64 {
        let align = 16u64;
        let ptr = (self.heap_next + align - 1) & !(align - 1);
        let stored = size.max(1);
        let end = ptr.checked_add(stored);
        match end {
            Some(end) if end <= self.cfg.heap_base + self.cfg.heap_size => {
                self.heap_next = end;
                self.heap_sizes.insert(ptr, stored);
                ptr
            }
            _ => {
                self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                0
            }
        }
    }

    /// Address of the writable cell backing a CRT global accessor such as
    /// `__p__fmode`. The C runtime startup does `*__p__fmode() = _fmode;`, so
    /// the accessor must hand back a real, writable pointer — returning 0
    /// (the old stub behaviour) makes the guest store through null. Cells are
    /// pointer-sized, zero-initialised, and stable for the life of the process.
    /// `_acmdln`/`_wcmdln` are seeded so `__getmainargs` sees the command line.
    pub(crate) fn crt_global(&mut self, mem: &mut dyn Memory, name: &str) -> Result<u64> {
        if let Some(&cell) = self.crt_globals.get(name) {
            return Ok(cell);
        }
        let cell = self.heap_alloc(8);
        // Seed the command-line accessors; the rest keep their zero default,
        // which is the correct initial value for _fmode/_commode/argc/etc.
        let seed = match name {
            "__p__acmdln" => self.cfg.cmdline_ptr_a,
            "__p__wcmdln" => self.cfg.cmdline_ptr_w,
            _ => 0,
        };
        if seed != 0 && cell != 0 {
            if self.cfg.is_64bit {
                mem.write_u64(cell, seed)?;
            } else {
                mem.write_u32(cell, seed as u32)?;
            }
        }
        self.crt_globals.insert(name.to_string(), cell);
        Ok(cell)
    }

    // ---- Thread/Fiber Local Storage --------------------------------------
    // Fiber slots share this implementation (we run single-threaded); the
    // `fiber` flag only selects which of the two independent slot vectors is
    // used, matching Windows' separate TLS and FLS index namespaces.

    fn tls_store(&mut self, fiber: bool) -> &mut Vec<Option<u64>> {
        if fiber {
            &mut self.fls_slots
        } else {
            &mut self.tls_slots
        }
    }

    /// Reserve a slot and return its index (never the out-of-indexes sentinel,
    /// since the vector grows on demand). A fresh slot reads back as NULL.
    fn tls_alloc(&mut self, fiber: bool) -> u64 {
        let slots = self.tls_store(fiber);
        let idx = match slots.iter().position(Option::is_none) {
            Some(i) => i,
            None => {
                slots.push(None);
                slots.len() - 1
            }
        };
        slots[idx] = Some(0);
        idx as u64
    }

    /// Store a value in a slot. Returns whether it succeeded (always true for a
    /// valid index; the vector is grown so an in-range index never fails).
    fn tls_set(&mut self, fiber: bool, index: u64, value: u64) -> bool {
        let i = index as usize;
        let slots = self.tls_store(fiber);
        if i >= slots.len() {
            slots.resize(i + 1, None);
        }
        slots[i] = Some(value);
        true
    }

    /// Read a slot's value (NULL for an unset or out-of-range index).
    fn tls_get(&self, fiber: bool, index: u64) -> u64 {
        let slots = if fiber { &self.fls_slots } else { &self.tls_slots };
        slots.get(index as usize).copied().flatten().unwrap_or(0)
    }

    /// Release a slot. Always reports success.
    fn tls_free(&mut self, fiber: bool, index: u64) -> bool {
        let slots = self.tls_store(fiber);
        if let Some(slot) = slots.get_mut(index as usize) {
            *slot = None;
        }
        true
    }

    // ---- in-memory registry hive ----------------------------------------

    /// Map a predefined HKEY constant to its canonical root name string.
    fn reg_hkey_root(hkey: u64) -> Option<&'static str> {
        match hkey {
            0x8000_0000 => Some("HKCR"),
            0x8000_0001 => Some("HKCU"),
            0x8000_0002 => Some("HKLM"),
            0x8000_0003 => Some("HKU"),
            0x8000_0005 => Some("HKCC"),
            _ => None,
        }
    }

    /// Resolve any open HKEY (predefined root or allocated handle) to its
    /// canonical key-path string. Returns `None` for an unknown handle
    /// (the caller should return ERROR_INVALID_HANDLE = 6).
    pub(crate) fn reg_resolve(&self, hkey: u64) -> Option<String> {
        if let Some(root) = Self::reg_hkey_root(hkey) {
            return Some(root.to_string());
        }
        self.reg_handles.get(&hkey).cloned()
    }

    // ---- environment -----------------------------------------------------

    /// Look up an environment variable (case-insensitive, as on Windows).
    pub(crate) fn env_get(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Set (or, with `None`, remove) an environment variable, case-insensitively.
    pub(crate) fn env_set(&mut self, name: &str, value: Option<&str>) {
        let pos = self.env.iter().position(|(k, _)| k.eq_ignore_ascii_case(name));
        match (pos, value) {
            (Some(i), Some(v)) => self.env[i].1 = v.to_string(),
            (Some(i), None) => {
                self.env.remove(i);
            }
            (None, Some(v)) => self.env.push((name.to_string(), v.to_string())),
            (None, None) => {}
        }
    }

    /// The environment block as `name=value\0…\0\0` code units (UTF-16).
    pub(crate) fn env_block_utf16(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for (k, v) in &self.env {
            out.extend(k.encode_utf16());
            out.push(b'=' as u16);
            out.extend(v.encode_utf16());
            out.push(0);
        }
        out.push(0); // the block's final terminator
        out
    }

    /// Expand `%VAR%` references in `src`. Unknown variables are left verbatim
    /// (including the surrounding `%`), matching Windows' behavior. A lone `%`
    /// with no closing `%` is emitted as-is.
    pub(crate) fn expand_env(&self, src: &str) -> String {
        let mut out = String::new();
        let mut rest = src;
        while let Some(open) = rest.find('%') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            match after.find('%') {
                Some(close) => {
                    let name = &after[..close];
                    match self.env_get(name) {
                        Some(v) => out.push_str(v),
                        None => {
                            // Leave the token untouched: %NAME%.
                            out.push('%');
                            out.push_str(name);
                            out.push('%');
                        }
                    }
                    rest = &after[close + 1..];
                }
                None => {
                    // No closing '%': emit the remainder literally.
                    out.push('%');
                    out.push_str(after);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// The environment block as `name=value\0…\0\0` bytes (ANSI).
    pub(crate) fn env_block_ansi(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.env {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(0);
        }
        out.push(0);
        out
    }
}

/// A plausible Windows environment so the C runtime's environment setup
/// succeeds and programs that read `PATH`/`TEMP`/`USERPROFILE`/etc. behave.
/// `C:` maps into the sandbox, so these are consistent with the guest
/// filesystem the emulator presents.
fn default_environment() -> Vec<(String, String)> {
    [
        ("ALLUSERSPROFILE", "C:\\ProgramData"),
        ("APPDATA", "C:\\Users\\exemu\\AppData\\Roaming"),
        ("CommonProgramFiles", "C:\\Program Files\\Common Files"),
        ("COMPUTERNAME", "EXEMU"),
        ("ComSpec", "C:\\Windows\\system32\\cmd.exe"),
        ("HOMEDRIVE", "C:"),
        ("HOMEPATH", "\\Users\\exemu"),
        ("LOCALAPPDATA", "C:\\Users\\exemu\\AppData\\Local"),
        ("NUMBER_OF_PROCESSORS", "8"),
        ("OS", "Windows_NT"),
        ("Path", "C:\\Windows;C:\\Windows\\system32;C:\\Windows\\System32\\Wbem"),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.JS"),
        ("PROCESSOR_ARCHITECTURE", "AMD64"),
        ("ProgramData", "C:\\ProgramData"),
        ("ProgramFiles", "C:\\Program Files"),
        ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        ("SystemDrive", "C:"),
        ("SystemRoot", "C:\\Windows"),
        ("TEMP", "C:\\Temp"),
        ("TMP", "C:\\Temp"),
        ("USERDOMAIN", "EXEMU"),
        ("USERNAME", "exemu"),
        ("USERPROFILE", "C:\\Users\\exemu"),
        ("windir", "C:\\Windows"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

impl Hooks for WinOs {
    fn intercept(&mut self, rip: u64, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Option<Exit>> {
        let Some(api) = self.thunks.get(&rip).cloned() else {
            return Ok(None);
        };
        if self.cfg.trace && !matches!(api, Api::CallbackDriver | Api::InittermDriver) {
            eprintln!("[exemu] call {api:?}  (thunk {rip:#x})");
        }
        let argc = api.argc();
        match self.dispatch(&api, cpu, mem)? {
            api::Outcome::Return(value) => {
                if self.cfg.is_64bit {
                    cpu.set_reg(Reg::Rax, value);
                } else {
                    cpu.gpr_write(0, 4, value); // eax, upper 32 zeroed
                }
                self.ret(cpu, mem, argc)?;
                Ok(Some(Exit::Continue))
            }
            api::Outcome::Exit(code) => Ok(Some(Exit::ProcessExit(code))),
            // The handler has already set rip/rsp (e.g. it is driving a
            // re-entrant guest call); just keep executing.
            api::Outcome::Resume => Ok(Some(Exit::Continue)),
        }
    }
}
