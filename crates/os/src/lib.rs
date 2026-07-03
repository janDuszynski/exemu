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
mod fs;

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
    last_error: u32,

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
    /// Progress-bar state by control id: (min, max, pos).
    progress: std::collections::HashMap<u32, (i64, i64, i64)>,

    /// Open guest file handles → host file objects.
    files: std::collections::HashMap<u64, fs::OpenFile>,
    next_handle: u64,
    /// Monotonic source of unique temp-file numbers.
    temp_counter: u32,

    /// Captured console output (also echoed to the host when `cfg.echo`).
    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,
}

// Sentinel handle values returned by GetStdHandle and understood by WriteFile.
const HANDLE_STDIN: u64 = 0x0C;
const HANDLE_STDOUT: u64 = 0x10;
const HANDLE_STDERR: u64 = 0x14;
const HANDLE_PROCESS_HEAP: u64 = 0x00AB_0000;

impl WinOs {
    pub fn new(cfg: WinConfig) -> Self {
        let (api_base, heap_base) = (cfg.api_base, cfg.heap_base);
        let mut os = WinOs {
            cfg,
            thunks: HashMap::new(),
            interned: HashMap::new(),
            next_thunk: api_base,
            heap_next: heap_base,
            last_error: 0,
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
            progress: std::collections::HashMap::new(),
            files: std::collections::HashMap::new(),
            next_handle: 0x0000_1000,
            temp_counter: 0,
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
        };
        // Reserve the driver thunks up front so their addresses are stable.
        os.initterm_driver = os.alloc_thunk(Api::InittermDriver);
        os.cb_driver = os.alloc_thunk(Api::CallbackDriver);
        os
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
    fn heap_alloc(&mut self, size: u64) -> u64 {
        let align = 16u64;
        let ptr = (self.heap_next + align - 1) & !(align - 1);
        let end = ptr.checked_add(size.max(1));
        match end {
            Some(end) if end <= self.cfg.heap_base + self.cfg.heap_size => {
                self.heap_next = end;
                ptr
            }
            _ => {
                self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                0
            }
        }
    }
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
