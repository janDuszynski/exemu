//! # exemu-app — the application layer
//!
//! This is the use-case layer that ties the infrastructure together. It:
//!
//! 1. parses the PE with `exemu-loader`,
//! 2. builds the process address space in `exemu-memory` (headers, sections,
//!    stack, a TEB/PEB pair behind `gs:`, a heap arena and the command line),
//! 3. resolves imports into OS thunks and patches the IAT,
//! 4. runs the `exemu-cpu` interpreter against the `exemu-os` hooks until the
//!    process exits.
//!
//! It owns the memory-layout policy (where the stack, heap and thunks live)
//! so the inner layers stay policy-free.

#![forbid(unsafe_code)]

pub mod gui_sample;
pub mod sample;

use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{Cpu, EmuError, Exit, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32, GS_BASE};
use exemu_loader as loader;
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// ---- Address-space layout policy -------------------------------------------

const PAGE: u64 = 0x1000;
// The x64 TEB is ~0x1838 bytes; its inline `TlsSlots[64]` array sits at offset
// 0x1480 and `TlsExpansionSlots` at 0x1780. Compilers inline TLS access as a
// direct `gs:[0x1480 + i*8]` load/store, so the region must span past those —
// 0x1000 is not enough. 0x2000 covers the whole struct and abuts the PEB
// (placed at `teb_base + 0x2000`) without overlapping it.
const TEB_SIZE: u64 = 0x2000;
const ENV_SIZE: u64 = 0x1000;
const API_SIZE: u64 = 0x0010_0000; // 1 MiB → 128k import slots

/// `KUSER_SHARED_DATA` — the read-only page the kernel maps at a fixed virtual
/// address in every process (32- and 64-bit alike). Wine's PE ntdll and the C
/// runtime read time/tick fields directly out of it and consult the
/// `SystemCall` selector at `+0x308` to decide between the `SYSCALL` and legacy
/// `int 2Eh` syscall entry shapes. exemu seeds the modern 64-bit fields and
/// sets `SystemCall` nonzero to steer the guest onto the `SYSCALL` path the
/// dispatcher (roadmap W2.2/W2.3) will implement. Sits ~16 MiB above the 32-bit
/// TEB/PEB (which end ~0x7EFD_3000), so there is no collision with either
/// bitness's layout (roadmap W2.1).
const KUSER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
/// The synthesized syscall-dispatcher landing page, reserved one page above
/// `KUSER_SHARED_DATA`. Native x64 Wine stubs issue a raw `SYSCALL` rather than
/// calling this page, but wow64/ARM64EC-shaped stubs route through a fixed low
/// page here; we reserve it now so that path has somewhere to land later.
const KUSER_DISPATCHER_PAGE: u64 = 0x7ffe_1000;

/// `KUSER_SHARED_DATA` field offsets we seed (public winnt/ntddk layout).
const KUSER_INTERRUPT_TIME: u64 = 0x008; // KSYSTEM_TIME (Low/High/High2)
const KUSER_SYSTEM_TIME: u64 = 0x014; // KSYSTEM_TIME (Low/High/High2)
const KUSER_SYSTEM_CALL: u64 = 0x308; // ULONG syscall-entry selector
const KUSER_TICK_COUNT: u64 = 0x320; // KSYSTEM_TIME TickCount

/// Where the various regions live, chosen per bitness so 32-bit processes
/// stay entirely within the low 4 GiB.
struct Layout {
    stack_base: u64,
    stack_size: u64,
    heap_base: u64,
    heap_size: u64,
    api_base: u64,
    dll_base: u64,
    dll_size: u64,
    env_base: u64,
    teb_base: u64,
    peb_addr: u64,
    // TEB/PEB field offsets (they differ between the 32- and 64-bit structs).
    teb_self: u64,
    teb_peb: u64,
    teb_stack_base: u64,
    teb_stack_limit: u64,
    peb_image_base: u64,
    /// Offset of the `Ldr` (`PEB_LDR_DATA*`) field within the PEB — 0x18 for
    /// 64-bit, 0x0C for 32-bit (public winternl.h layout). The loader stores
    /// the `PEB_LDR_DATA` pointer here (roadmap W0.6).
    peb_ldr_off: u64,
    /// Offset of the `LoaderLock` (`PRTL_CRITICAL_SECTION`) field within the
    /// PEB — 0x110 for 64-bit, 0xA0 for 32-bit (public winnt PEB layout). The
    /// loader stores a real critical section pointer here (roadmap W0.7).
    peb_loaderlock_off: u64,
    /// Address window the VirtualAlloc manager grows from (roadmap P3.2).
    valloc_base: u64,
}

impl Layout {
    fn for_bits(is_64bit: bool) -> Layout {
        if is_64bit {
            Layout {
                stack_base: 0x0000_0010_0000_0000,
                stack_size: 0x0020_0000, // 2 MiB
                heap_base: 0x0000_0002_0000_0000,
                heap_size: 0x0400_0000, // 64 MiB
                api_base: 0x0000_7EFF_0000_0000,
                dll_base: 0x0000_0006_0000_0000,
                dll_size: 0x0800_0000, // 128 MiB
                env_base: 0x0000_0000_5000_0000,
                teb_base: GS_BASE,
                peb_addr: GS_BASE + 0x2000,
                teb_self: 0x30,
                teb_peb: 0x60,
                teb_stack_base: 0x08,
                teb_stack_limit: 0x10,
                peb_image_base: 0x10,
                peb_ldr_off: 0x18,
                peb_loaderlock_off: 0x110,
                valloc_base: 0x0000_0040_0000_0000, // 256 GiB, between stack and thunks
            }
        } else {
            // Everything below 4 GiB, clear of a typical image at 0x400000+.
            Layout {
                stack_base: 0x0018_0000,
                stack_size: 0x0020_0000, // 2 MiB, top at 0x0038_0000 (below image)
                heap_base: 0x1000_0000,
                heap_size: 0x0400_0000, // 64 MiB
                api_base: 0x7000_0000,
                dll_base: 0x2000_0000,
                dll_size: 0x0400_0000, // 64 MiB (below the 4 GiB ceiling)
                env_base: 0x0010_0000,
                teb_base: FS_BASE_32,
                peb_addr: FS_BASE_32 + 0x2000,
                teb_self: 0x18,  // NT_TIB.Self
                teb_peb: 0x30,   // ProcessEnvironmentBlock
                teb_stack_base: 0x04,
                teb_stack_limit: 0x08,
                peb_image_base: 0x08,
                peb_ldr_off: 0x0c,
                peb_loaderlock_off: 0xa0,
                valloc_base: 0x3000_0000, // between the DLL arena and the thunks
            }
        }
    }
}

/// Options controlling a run.
pub struct RunConfig {
    /// Command-line arguments (arg0 should be the program name).
    pub args: Vec<String>,
    /// Echo guest console output to the host stdio.
    pub echo: bool,
    /// Log unimplemented API calls.
    pub trace: bool,
    /// Safety cap on executed instructions (0 = unlimited).
    pub max_steps: u64,
    /// Render dialogs in a real window and let the user drive them, instead
    /// of headlessly auto-clicking the default button.
    pub gui: bool,
    /// Override the address the main image is mapped at. `None` uses the PE's
    /// preferred `ImageBase`; `Some(base)` maps the image there instead and
    /// applies its base relocations (`.reloc`) with the resulting load delta.
    /// The image must carry a relocation table for a non-preferred base to work.
    pub load_base: Option<u64>,
    /// Boot the real Wine PE DLL set (ntdll/kernel32/kernelbase/ucrtbase) from
    /// this directory instead of the emulated-DLL thunks, handing off through
    /// `LdrInitializeThunk` (roadmap W3). `None` keeps the emulated path. Takes
    /// precedence over the `EXEMU_WINE_BOOT`/`EXEMU_WINE_DLLS` env opt-in, so a
    /// caller (e.g. the W3 gate test) can request the Wine boot hermetically
    /// without touching process-global env vars.
    pub wine_boot_dir: Option<String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        // High enough for a real installer's decompression (7-Zip needs
        // ~500M) while still bounding a runaway loop.
        RunConfig {
            args: vec!["program.exe".into()],
            echo: true,
            trace: false,
            max_steps: 2_000_000_000,
            gui: false,
            load_base: None,
            wine_boot_dir: None,
        }
    }
}

/// The result of running a program to completion.
pub struct RunResult {
    pub exit_code: i32,
    pub steps: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Host directory rooting the guest filesystem (where files the program
    /// created — e.g. an installer's extracted files — actually landed).
    pub sandbox: String,
}

/// A loaded, ready-to-run process.
/// The source of a run-loop exception the W3.3 bridge classifies: either a CPU
/// interrupt vector (`Exit::Interrupt(n)` — #DE=0, #BP=3) or a structured
/// [`EmuError`] (an access violation from a memory fault).
enum ExcSource<'a> {
    Interrupt(u8),
    Error(&'a EmuError),
}

pub struct Process {
    mem: VirtualMemory,
    cpu: Interpreter,
    os: WinOs,
    sandbox: String,
    entry: u64,
    max_steps: u64,
    /// Image base, kept for virtual unwinding in the fault reporter (the
    /// unwind table itself is owned by the OS layer — see `os.unwind_table`).
    image_base: u64,
    /// Nesting depth of the hardware→software exception bridge (roadmap W3.3):
    /// how many guest faults are currently being dispatched through
    /// `KiUserExceptionDispatcher` without an intervening `NtContinue`. A fault
    /// that occurs while already inside the dispatcher (a corrupt/double fault)
    /// must NOT be re-delivered forever — past a small bound the bridge gives up
    /// and falls through to the fault reporter. Reset to 0 whenever `NtContinue`
    /// resumes the guest (a handled exception).
    exc_depth: u32,
}

impl Process {
    /// Parse and lay out `pe_bytes` into a runnable process.
    pub fn load(pe_bytes: &[u8], cfg: &RunConfig) -> Result<Process> {
        let mut image = loader::parse(pe_bytes)?;
        let mut mem = VirtualMemory::new();

        // --- Choose a load base and relocate if it differs from preferred --
        // `cfg.load_base` lets a caller deliberately map the image away from
        // its preferred `ImageBase` (exercising the relocation path even for an
        // .exe that would otherwise always land at its preferred address). When
        // it moves, apply the base relocations to the section bytes *before*
        // mapping, then treat the requested base as the image base everywhere.
        let preferred_base = image.image_base;
        let base = cfg.load_base.unwrap_or(preferred_base);
        if base != preferred_base {
            if image.relocations.is_empty() {
                return Err(EmuError::InvalidPe(format!(
                    "cannot load image at non-preferred base {base:#x}: no relocation table \
                     (preferred base {preferred_base:#x})"
                )));
            }
            loader::apply_relocations(&mut image.sections, &image.relocations, preferred_base, base)?;
            // Patch the header copy's ImageBase field so a guest that reads its
            // own PE header sees where it was actually loaded, and rebase the
            // parsed image so entry_va()/imports/unwind all use the real base.
            patch_header_image_base(&mut image.headers, image.is_64bit, base);
            image.image_base = base;
        }

        let hdr_len = align_up(image.size_of_headers as u64, PAGE).max(PAGE);
        // Writable: packers (UPX etc.) reconstruct headers/import tables in
        // place at the image base as they unpack.
        mem.map_with_data("headers", base, hdr_len, &image.headers, Perm::RWX)?;

        for s in &image.sections {
            let addr = base + s.rva as u64;
            let size = align_up((s.virtual_size as u64).max(s.data.len() as u64), PAGE).max(PAGE);
            // Map every section read/write/execute. Real-world installers and
            // packers routinely execute code they generate or unpack into
            // "data" sections (and write to "code" sections), which a strict
            // DEP model would fault. Running arbitrary binaries matters more
            // here than reproducing page-permission enforcement.
            let mut perm = Perm::RWX;
            let _ = (s.writable, s.executable); // characteristics kept for `info`
            perm = perm.union(if s.readable { Perm::READ } else { Perm::NONE });
            mem.map_with_data(section_name(&s.name), addr, size, &s.data, perm)?;
        }

        let lay = Layout::for_bits(image.is_64bit);
        let ptr_size = if image.is_64bit { 8 } else { 4 };

        // --- Stack --------------------------------------------------------
        mem.map(Region::new("stack", lay.stack_base, lay.stack_size, Perm::RW))?;

        // --- Heap arena (bump-allocated by the OS layer) ------------------
        mem.map(Region::new("heap", lay.heap_base, lay.heap_size, Perm::RW))?;

        // --- DLL arena (RWX: LoadLibrary maps plugin DLLs here and the
        //     interpreter executes their code) ------------------------------
        mem.map(Region::new("dlls", lay.dll_base, lay.dll_size, Perm::RWX))?;

        // --- TEB / PEB behind fs:(32-bit) or gs:(64-bit) ------------------
        mem.map(Region::new("teb", lay.teb_base, TEB_SIZE, Perm::RW))?;
        mem.map(Region::new("peb", align_down(lay.peb_addr, PAGE), PAGE, Perm::RW))?;
        let stack_top = lay.stack_base + lay.stack_size;
        let write_ptr = |mem: &mut VirtualMemory, addr: u64, val: u64| -> Result<()> {
            mem.poke(addr, &val.to_le_bytes()[..ptr_size])
        };
        write_ptr(&mut mem, lay.teb_base + lay.teb_self, lay.teb_base)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_peb, lay.peb_addr)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_base, stack_top)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_limit, lay.stack_base)?;
        write_ptr(&mut mem, lay.peb_addr + lay.peb_image_base, base)?;

        // --- KUSER_SHARED_DATA @ 0x7ffe0000 + dispatcher landing page -----
        // Fixed-address kernel page every process reads directly; also reserves
        // the syscall-dispatcher landing page one page above it (roadmap W2.1).
        map_kuser_shared_data(&mut mem)?;

        // --- Command line (ASCII + UTF-16) in the env region --------------
        mem.map(Region::new("env", lay.env_base, ENV_SIZE, Perm::RW))?;
        let cmdline = build_cmdline(&cfg.args);
        let cmd_a = lay.env_base;
        let mut ascii = cmdline.clone().into_bytes();
        ascii.push(0);
        mem.poke(cmd_a, &ascii)?;
        let cmd_w = lay.env_base + 0x400;
        let mut wide: Vec<u8> = Vec::new();
        for u in cmdline.encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        mem.poke(cmd_w, &wide)?;

        // --- Sandbox directory rooting the guest filesystem ---------------
        let sandbox = std::env::temp_dir().join("exemu-sandbox");
        let _ = std::fs::create_dir_all(&sandbox);
        // Ensure the guest `C:\` drive root exists as a real directory so opening
        // it as the working directory succeeds (Wine's `loader_init` opens
        // `C:\` early; a missing dir logged "could not open working directory").
        // The `C\windows\system32` chain gives the DLL-search redirect a real
        // parent so a missing DLL resolves to OBJECT_NAME_NOT_FOUND (not
        // OBJECT_PATH_NOT_FOUND), matching what Wine's search loop expects.
        let _ = std::fs::create_dir_all(sandbox.join("C").join("windows").join("system32"));
        // Guest module path (basename only) and its sandbox location. We copy
        // the executable itself into the sandbox so a program that opens its
        // own file (e.g. a self-extracting installer reading an appended
        // archive) finds the real bytes.
        let module_name = cfg
            .args
            .first()
            .map(|s| s.rsplit(['/', '\\']).next().unwrap_or(s).to_string())
            .unwrap_or_else(|| "program.exe".into());
        let module_path_w = format!("C:\\{module_name}");
        let host_exe = sandbox.join("C").join(&module_name);
        if let Some(p) = host_exe.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&host_exe, pe_bytes);

        // --- Wine-boot opt-in (roadmap W3.2) ------------------------------
        // `EXEMU_WINE_BOOT` selects the experimental path that boots the real
        // Wine PE core (ntdll→kernelbase→kernel32→ucrtbase) as guest images and
        // hands off through `LdrInitializeThunk`, instead of the emulated-DLL
        // thunks. Off by default so the corpus is byte-for-byte unaffected while
        // the boot path (W3.3 exc bridge, W3.4 console) is still being built. The
        // DLL directory defaults to the pinned prefix but is overridable via
        // `EXEMU_WINE_DLLS`; `wine_dll_dir` stays `None` unless the opt-in is set
        // AND the directory exists, so `load_wine_core` only ever runs on request.
        let wine_dll_dir = if let Some(dir) = cfg.wine_boot_dir.clone() {
            // Explicit request (e.g. the W3 gate test) — hermetic, no env vars.
            if std::path::Path::new(&dir).is_dir() {
                Some(dir)
            } else {
                None
            }
        } else if std::env::var_os("EXEMU_WINE_BOOT").is_some() {
            let dir = std::env::var("EXEMU_WINE_DLLS")
                .unwrap_or_else(|_| "example_exe/wine-dlls/x86_64-windows".to_string());
            if std::path::Path::new(&dir).is_dir() {
                Some(dir)
            } else {
                None
            }
        } else {
            None
        };

        // --- The OS layer and import resolution ---------------------------
        let mut os = WinOs::new(WinConfig {
            api_base: lay.api_base,
            heap_base: lay.heap_base,
            heap_size: lay.heap_size,
            image_base: base,
            cmdline_ptr_a: cmd_a,
            cmdline_ptr_w: cmd_w,
            echo: cfg.echo,
            trace: cfg.trace,
            is_64bit: image.is_64bit,
            sandbox: sandbox.to_string_lossy().into_owned(),
            module_path_w,
            dll_base: lay.dll_base,
            dll_size: lay.dll_size,
            valloc_base: lay.valloc_base,
            peb_addr: lay.peb_addr,
            teb_base: lay.teb_base,
            peb_ldr_off: lay.peb_ldr_off,
            peb_loaderlock_off: lay.peb_loaderlock_off,
            image_size: align_up(image.size_of_image as u64, PAGE).max(PAGE),
            image_entry: image.entry_va(),
            image_name: module_name.clone(),
            wine_dll_dir,
        });

        // Map the thunk region as real read/write memory. Function imports
        // are intercepted on *execution* (rip match) before any fetch, so
        // they never touch this backing store; but *data* imports — a DLL
        // exporting a variable, common in the C runtime — are dereferenced as
        // memory, and land here instead of faulting. Known CRT data globals
        // are seeded below; the rest default to zero (their normal initial
        // value).
        // Hand the OS layer the unwind table so its native Rtl* exception
        // APIs and dispatch can walk guest frames (roadmap P4.3).
        os.set_unwind_table(image.function_table.clone());

        // Complete the main thread's Wine-walkable TEB (roadmap W2.9/W2.10). The
        // app seeded Self/PEB/StackBase/StackLimit above; this fills every field
        // Wine's ntdll dereferences (NtTib.ExceptionList, ClientId,
        // ThreadLocalStoragePointer, StaticUnicodeString,
        // CountOfOwnedCriticalSections, DeallocationStack, TlsExpansionSlots).
        // Spawned threads get their own seeded TEB in
        // `NtCreateThreadEx`/`CreateThread`. The rest of the PEB (OS version
        // block, NtGlobalFlag, SessionId, ProcessParameters) is seeded by
        // `init_ldr` below, alongside PEB.Ldr.
        os.seed_main_teb(&mut mem, lay.stack_base, stack_top)?;

        mem.map(Region::new("imports", lay.api_base, API_SIZE, Perm::RW))?;

        for imp in &image.imports {
            // Bind to a co-loaded guest module's real export when one is
            // present (forwarders chased); otherwise this returns an OS thunk.
            // At initial process load no plugins are mapped yet, so the main
            // exe's imports of system DLLs all resolve to thunks as before — but
            // routing through the same seam keeps inter-module resolution
            // uniform for images loaded alongside it (roadmap W0.4).
            let addr = os.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.poke(base + imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
            if let exemu_core::ImportSymbol::Named(name) = &imp.symbol {
                if let Some(value) = data_import_seed(name, cmd_a, cmd_w) {
                    mem.poke(addr, &value.to_le_bytes()[..ptr_size])?;
                }
            }
        }

        // --- TLS: allocate the slot index and register callbacks ----------
        // The Windows loader allocates a per-module TLS index, writes it to the
        // image's `AddressOfIndex`, lays down the initialization template, and
        // runs the TLS callbacks (`DLL_PROCESS_ATTACH`) before the entry point
        // (roadmap W0.3). The parsed TLS `AddressOfIndex`/template addresses are
        // preferred-base virtual addresses, so shift them by the load delta when
        // the image was relocated; the callback list is stored as image-base
        // RVAs and is already base-independent.
        let mut tls_callbacks: Vec<u64> = Vec::new();
        if let Some(tls) = &image.tls {
            let delta = base.wrapping_sub(preferred_base);
            // Allocate a TLS index and publish it at AddressOfIndex.
            if tls.address_of_index != 0 {
                let idx = os.alloc_tls_index();
                let index_va = tls.address_of_index.wrapping_add(delta);
                mem.poke(index_va, &idx.to_le_bytes()[..4])?;
            }
            // Lay the initialization template down at [Start, End) so the main
            // thread's TLS data begins from the linker's initialized image.
            if !tls.raw_template.is_empty() {
                let start_va = tls.start_address_of_raw_data.wrapping_add(delta);
                mem.poke(start_va, &tls.raw_template)?;
            }
            tls_callbacks = tls.callback_rvas.iter().map(|&rva| base + rva as u64).collect();
        }
        os.set_tls_callbacks(tls_callbacks);

        // --- PEB.Ldr module lists -----------------------------------------
        // Build the PEB_LDR_DATA + LDR_DATA_TABLE_ENTRY doubly-linked lists in
        // guest memory and thread the main image on as the first module, so a
        // guest that walks its own loader list (anti-debug, GetModuleHandle by
        // walk) sees the same modules the OS APIs report (roadmap W0.6).
        os.init_ldr(&mut mem)?;

        // --- Optional GUI backend -----------------------------------------
        // EXEMU_GUI_SHOT=<dir> selects the offscreen PNG renderer (for
        // headless testing); otherwise a live minifb window.
        if cfg.gui {
            let dialogs = loader::parse_dialogs(pe_bytes);
            let gui: Box<dyn exemu_core::Gui> = match std::env::var_os("EXEMU_GUI_SHOT") {
                Some(dir) => Box::new(exemu_gui::OffscreenGui::new(std::path::PathBuf::from(dir))),
                None => Box::new(exemu_gui::MinifbGui::new()),
            };
            os.set_gui(gui, dialogs);
        }

        // --- Initial CPU state --------------------------------------------
        let mut cpu = Interpreter::with_bits(if image.is_64bit { Bits::B64 } else { Bits::B32 });
        // Align the stack, then push the sentinel return address so the entry
        // sees the stack exactly as a real `call entry` would leave it.
        let exit_thunk = os.exit_thunk();
        let rsp = if image.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 8;
            mem.write_u64(sp, exit_thunk)?;
            sp
        } else {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 4;
            mem.write_u32(sp, exit_thunk as u32)?;
            sp
        };
        cpu.state_mut().set_rsp(rsp);
        // Seat the initial rip. When the image has TLS callbacks, they run with
        // `DLL_PROCESS_ATTACH` before the entry point (roadmap W0.3); otherwise
        // this is just `rip = entry`.
        os.start_process(cpu.state_mut(), &mut mem, image.entry_va())?;

        // --- Wine PE core boot (roadmap W3.2, opt-in) ---------------------
        // When `EXEMU_WINE_BOOT` gated `wine_dll_dir` on above, map the four Wine
        // core DLLs as real guest images (relocated + inter-bound), then re-seat
        // the initial thread at ntdll's `LdrInitializeThunk` with a CONTEXT for
        // `RtlUserThreadStart(entry, 0)` — Wine's own loader_init then loads the
        // rest and runs the DllMains before reaching the exe entry. This
        // OVERRIDES the `start_process` seating above. When `wine_dll_dir` is
        // `None` (the default / files absent), `load_wine_core` returns `None`
        // and every binary keeps the emulated-DLL path, unchanged.
        //
        // NOTE (deferred, W3.3+): the LdrInitializeThunk handoff drives Wine's
        // loader_init, which needs the hardware→software exception bridge (W3.3)
        // and the console stdio bridge (W3.4) to boot to a console main. W3.2
        // proves the *load* (map+relocate+inter-bind+Ldr+fault-free DllMains via
        // the intermediate test); the handoff is wired here behind the same
        // opt-in but not exercised by the default corpus or the standing gates.
        if image.is_64bit {
            if let Some(ntdll_base) = os.load_wine_core(&mut mem)? {
                // Wine reaches its debug scratch regions VERY early in
                // `loader_init` via TRACE macros. Seed them as zeroed pages so
                // TRACE is a safe no-op (boot-path only; the emulated corpus
                // never runs this code).
                map_wine_debug_pages(&mut mem, lay.teb_base, lay.peb_addr)?;
                // Steer ntdll's stubs onto the bare `syscall` route into the
                // W2.3 dispatcher: SystemCall selector = 0 (the app's default
                // seed is 1, the dispatcher-page shape). Poke bypasses the
                // READ-only perm on KUSER_SHARED_DATA.
                mem.poke(
                    KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL,
                    &0u32.to_le_bytes(),
                )?;
                // Cross-check the LdrInitializeThunk entry BY NAME from ntdll's
                // parsed export table against the RVA `bootstrap_via_ldr_init`
                // seats (W3.1's `RVA_LDR_INITIALIZE_THUNK`), so a pinned-binary
                // RVA drift is caught loudly rather than seating a wrong rip.
                if let Some(ldr_init_va) = os.ntdll_export("LdrInitializeThunk") {
                    let seated = ntdll_base + exemu_os::RVA_LDR_INITIALIZE_THUNK;
                    if ldr_init_va != seated {
                        return Err(EmuError::Os(format!(
                            "ntdll LdrInitializeThunk export {ldr_init_va:#x} != \
                             bootstrap-seated {seated:#x} (pinned-binary RVA drift)"
                        )));
                    }
                }
                let entry = image.entry_va();
                os.bootstrap_via_ldr_init(
                    cpu.state_mut(),
                    &mut mem,
                    ntdll_base,
                    entry,
                    0, // Arg: none for a process's initial thread
                    stack_top,
                )?;
            }
        }

        Ok(Process {
            mem,
            cpu,
            os,
            sandbox: sandbox.to_string_lossy().into_owned(),
            entry: image.entry_va(),
            max_steps: cfg.max_steps,
            image_base: base,
            exc_depth: 0,
        })
    }

    /// The entry-point virtual address.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Read a byte of guest memory (for tests/tools inspecting the loaded image).
    pub fn peek_u8(&self, addr: u64) -> Result<u8> {
        self.mem.read_u8(addr)
    }

    /// Read a little-endian `u32` of guest memory (for tests/tools).
    pub fn peek_u32(&self, addr: u64) -> Result<u32> {
        self.mem.read_u32(addr)
    }

    /// Run until the process exits (or the step cap / a fault is hit).
    pub fn run(mut self) -> Result<RunResult> {
        let mut steps: u64 = 0;
        // Rolling window of the most recent instruction pointers, for the
        // fault report (helps trace how a bad jump was reached).
        const TAIL: usize = 24;
        let mut recent: std::collections::VecDeque<u64> = std::collections::VecDeque::with_capacity(TAIL + 1);
        let exit_code = loop {
            if self.max_steps != 0 && steps >= self.max_steps {
                let tail: Vec<u64> = recent.iter().copied().collect();
                return Err(self.fault(
                    EmuError::Os(format!("instruction budget exhausted after {steps} steps")),
                    steps,
                    &tail,
                ));
            }
            recent.push_back(self.cpu.state().rip);
            if recent.len() > TAIL {
                recent.pop_front();
            }

            let step_rip = self.cpu.state().rip;
            let outcome = self.cpu.step(&mut self.mem, &mut self.os);
            let tail = || recent.iter().copied().collect::<Vec<_>>();
            match outcome {
                Ok(Exit::Continue) => {
                    steps += 1;
                    // Guest made forward progress off the exception-dispatcher
                    // entry — a subsequent, unrelated fault is a fresh delivery.
                    // (A tight fault-at-entry loop never reaches here off-entry,
                    // so its depth climbs to the bail-out bound; W3.3.)
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                Ok(Exit::ProcessExit(code)) => break code,
                Ok(Exit::Halted) => break 0,
                Ok(Exit::Interrupt(n)) => {
                    // Hardware→software exception bridge (roadmap W3.3): on the
                    // Wine-boot path a bridgeable CPU exception (#DE/#BP) becomes
                    // a guest EXCEPTION_RECORD delivered via
                    // KiUserExceptionDispatcher instead of terminating here.
                    if self.try_deliver_hw_exception(ExcSource::Interrupt(n))? {
                        continue;
                    }
                    return Err(self.fault(EmuError::Os(format!("unhandled interrupt {n:#x}")), steps, &tail()));
                }
                // A native SYSCALL is serviced inside `Cpu::step` (the OS layer's
                // syscall seam, roadmap W2.2); an unserviced one surfaces here as
                // `Interrupt(0x80)` from the default hook, not as `Syscall`.
                Ok(Exit::Syscall(index)) => {
                    return Err(self.fault(
                        EmuError::Os(format!("SYSCALL {index:#x} escaped the dispatcher")),
                        steps,
                        &tail(),
                    ));
                }
                Err(e) => {
                    if self.try_deliver_hw_exception(ExcSource::Error(&e))? {
                        continue;
                    }
                    return Err(self.fault(e, steps, &tail()));
                }
            }
        };

        Ok(RunResult {
            exit_code,
            steps,
            stdout: self.os.captured_stdout().to_vec(),
            stderr: self.os.captured_stderr().to_vec(),
            sandbox: self.sandbox.clone(),
        })
    }

    /// Is `rip` the `KiUserExceptionDispatcher` entry of the loaded Wine ntdll?
    /// Used by the W3.3 recursion guard to tell "still faulting at the dispatcher
    /// entry" (an infinite re-delivery loop) from real forward progress.
    fn at_exc_dispatcher(&self, rip: u64) -> bool {
        self.os
            .module_base("ntdll.dll")
            .is_some_and(|b| rip == b + exemu_os::RVA_KI_USER_EXCEPTION_DISPATCHER)
    }

    /// The hardware→software exception bridge (roadmap W3.3). If `src` is a
    /// bridgeable CPU exception *and* the Wine core is mapped (so a guest
    /// `RtlDispatchException` exists to run), build the `KiUserExceptionDispatcher`
    /// frame and seat the CPU on it, returning `Ok(true)` — the caller `continue`s
    /// the run loop and the guest dispatches the exception, resuming through
    /// `NtContinue` if handled. Returns `Ok(false)` when the exception should keep
    /// the existing fault-reporter path (no Wine core / non-bridgeable source /
    /// recursion bound hit).
    fn try_deliver_hw_exception(&mut self, src: ExcSource<'_>) -> Result<bool> {
        // Guard: only on the Wine-boot path (real ntdll mapped). The emulated
        // corpus keeps its fault reporter, unchanged.
        let Some(ntdll_base) = self.os.module_base("ntdll.dll") else {
            return Ok(false);
        };
        // Recursion guard: a fault while already dispatching (esp. a repeated
        // fault at the dispatcher entry) must not re-deliver forever.
        const MAX_EXC_DEPTH: u32 = 8;
        if self.exc_depth >= MAX_EXC_DEPTH {
            return Ok(false);
        }

        // Classify into (ExceptionCode, ExceptionAddress, ExceptionInformation).
        // Only genuine CPU exceptions bridge; decoder/OS gaps stay on the fault
        // reporter so they surface as real emulator bugs.
        let cpu = self.cpu.state();
        let (code, address, info): (u32, u64, Vec<u64>) = match src {
            // #DE — integer divide error (div_op divisor==0 / signed overflow).
            ExcSource::Interrupt(0) => (0xC000_0094, cpu.rip, Vec::new()),
            // #BP — int3 (0xCC). Windows reports the address *after* the byte and
            // the delivered CONTEXT.Rip is fault+1; the interpreter left rip AT
            // the 0xCC (unlike `int n`/0xCD, which advances), so bump it.
            ExcSource::Interrupt(3) => (0x8000_0003, cpu.rip.wrapping_add(1), Vec::new()),
            // Access violation. info = [rw, faulting-address]; rw: 0=read, 1=write,
            // 8=execute (DEP). Unmapped carries no access kind → default read.
            ExcSource::Error(e) => match e.cause() {
                EmuError::Permission { addr, needed } => {
                    let rw = match *needed {
                        "write" => 1u64,
                        "execute" => 8u64,
                        _ => 0u64,
                    };
                    (0xC000_0005, *addr, vec![rw, *addr])
                }
                EmuError::Unmapped { addr, .. } => (0xC000_0005, *addr, vec![0, *addr]),
                // Decoder gaps (Decode/Unsupported, incl. UD2), OS-service and
                // other errors are NOT masked as guest #UD/exceptions.
                _ => return Ok(false),
            },
            // Any other interrupt vector (int n, #GP synthesis, …) isn't bridged.
            ExcSource::Interrupt(_) => return Ok(false),
        };

        // For #BP the reported/CONTEXT Rip is fault+1: advance the live rip so
        // write_context captures it (address already computed as rip+1 above).
        if let ExcSource::Interrupt(3) = src {
            let rip = self.cpu.state().rip;
            self.cpu.state_mut().rip = rip.wrapping_add(1);
        }

        self.os.deliver_hw_exception(
            self.cpu.state_mut(),
            &mut self.mem,
            ntdll_base,
            code,
            address,
            &info,
        )?;
        self.exc_depth += 1;
        Ok(true)
    }

    /// Wrap a fault with a diagnostic snapshot: the faulting instruction
    /// pointer, the bytes there (if fetchable), and the register file. This
    /// turns an opaque "unmapped memory access" into an actionable location.
    fn fault(&self, err: EmuError, steps: u64, recent: &[u64]) -> EmuError {
        use std::fmt::Write;
        let s = self.cpu.state();
        let mut o = String::new();
        let _ = writeln!(o, "{err}");

        // If the fault touched an import thunk, the guest is treating an
        // imported *function* slot as data — the tell-tale of a data export
        // (very common in the MSVCRT C runtime, e.g. _fmode/_commode).
        if let EmuError::Unmapped { addr, .. } = &err {
            let (lo, hi) = self.os.thunk_range();
            if *addr >= lo && *addr < hi {
                let sym = self.os.symbol_for_thunk(*addr).unwrap_or_else(|| "<unknown import>".into());
                let _ = writeln!(
                    o,
                    "  note: {addr:#018x} is the import thunk for {sym}.\n\
                     \x20       the guest is dereferencing it as data, so {sym} is a *data* export,\n\
                     \x20       not a function. exemu resolves imports as call targets only; data\n\
                     \x20       imports (common in msvcrt/UCRT startup) are not supported."
                );
            }
        }

        let _ = writeln!(o, "  faulted after {steps} instructions");
        let _ = writeln!(
            o,
            "  rip={:#018x}  rsp={:#018x}  rbp={:#018x}  rflags={:#06x}",
            s.rip,
            s.rsp(),
            s.reg(exemu_core::Reg::Rbp),
            s.rflags
        );
        for row in s.gpr.chunks(4).enumerate() {
            let (r, regs) = row;
            let _ = write!(o, "  ");
            for (i, v) in regs.iter().enumerate() {
                let name = exemu_core::Reg::NAMES[r * 4 + i];
                let _ = write!(o, "{name:>3}={v:#018x}  ");
            }
            o.push('\n');
        }
        // Instruction bytes at rip, if the page is executable/readable.
        let mut buf = [0u8; 16];
        match self.mem.fetch(s.rip, &mut buf) {
            Ok(()) => {
                let _ = write!(o, "  bytes @ rip:");
                for b in buf {
                    let _ = write!(o, " {b:02x}");
                }
            }
            Err(_) => {
                let _ = write!(o, "  (cannot fetch instruction bytes at rip — page not mapped/executable)");
            }
        }
        if !recent.is_empty() {
            let _ = write!(o, "\n  recent rip trail (oldest→newest):");
            for r in recent {
                let _ = write!(o, " {r:#x}");
            }
        }
        // Call stack via the x64 unwind tables (roadmap P4.2) — turns the
        // faulting rip into the chain of callers that led there.
        let function_table = self.os.unwind_table();
        if !function_table.is_empty() {
            let frames = exemu_core::unwind::backtrace(
                function_table,
                self.image_base,
                s,
                &self.mem,
                24,
            );
            if !frames.is_empty() {
                let _ = write!(o, "\n  call stack (virtual unwind, innermost first): {:#x}", s.rip);
                for f in &frames {
                    let _ = write!(o, " ← {f:#x}");
                }
            }
        }
        // Keep the structured `err` as the cause so callers can still classify
        // the fault (e.g. decode-miss telemetry, roadmap P0.5) — the report is
        // only the human-facing rendering.
        EmuError::Fault { report: o, cause: Box::new(err) }
    }
}

/// Convenience: load and run in one call.
pub fn load_and_run(pe_bytes: &[u8], cfg: RunConfig) -> Result<RunResult> {
    Process::load(pe_bytes, &cfg)?.run()
}

// ---- helpers ---------------------------------------------------------------

/// Map `KUSER_SHARED_DATA` at its fixed virtual address and seed the modern
/// 64-bit fields the guest reads directly, plus reserve the syscall-dispatcher
/// landing page one page above it (roadmap W2.1).
///
/// The `SystemTime`/`InterruptTime`/`TickCount` fields are point-in-time
/// snapshots taken at process load; they are not driven forward here (the
/// clock-backed `Nt*`/Win32 time APIs remain authoritative). `SystemCall` is
/// set nonzero so the guest selects the `SYSCALL` entry shape the dispatcher
/// will implement, rather than the legacy `int 2Eh` path.
fn map_kuser_shared_data(mem: &mut VirtualMemory) -> Result<()> {
    // Two contiguous pages: KUSER_SHARED_DATA itself and the reserved
    // dispatcher landing page directly above it.
    mem.map(Region::new(
        "kuser_shared_data",
        KUSER_SHARED_DATA_BASE,
        PAGE,
        Perm::READ,
    ))?;
    mem.map(Region::new(
        "kuser_dispatcher",
        KUSER_DISPATCHER_PAGE,
        PAGE,
        Perm::RWX,
    ))?;

    // Seed the time fields as KSYSTEM_TIME triples (LowPart, High1Time,
    // High2Time) so a guest reading either half sees a consistent value.
    let now_100ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let system_time = (now_100ns.as_secs() + KUSER_FILETIME_EPOCH_DIFF_SECS) * 10_000_000
        + now_100ns.subsec_nanos() as u64 / 100;
    let write_ksystem_time = |mem: &mut VirtualMemory, off: u64, val: u64| -> Result<()> {
        let low = (val & 0xFFFF_FFFF) as u32;
        let high = (val >> 32) as u32;
        mem.poke(KUSER_SHARED_DATA_BASE + off, &low.to_le_bytes())?;
        mem.poke(KUSER_SHARED_DATA_BASE + off + 4, &high.to_le_bytes())?; // High1Time
        mem.poke(KUSER_SHARED_DATA_BASE + off + 8, &high.to_le_bytes()) // High2Time
    };
    write_ksystem_time(mem, KUSER_SYSTEM_TIME, system_time)?;
    // InterruptTime/TickCount both count from boot; we anchor them at 0 (a
    // freshly booted system) — they advance via the clock-backed time APIs.
    write_ksystem_time(mem, KUSER_INTERRUPT_TIME, 0)?;
    write_ksystem_time(mem, KUSER_TICK_COUNT, 0)?;

    // SystemCall selector: nonzero ⇒ altered view (steer onto the SYSCALL path).
    mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &1u32.to_le_bytes())?;
    Ok(())
}

/// Map the zeroed scratch pages Wine's ntdll touches through its debug (TRACE)
/// machinery during `loader_init`, so those reads/writes don't fault. Only used
/// on the `EXEMU_WINE_BOOT` path; the emulated corpus never runs this.
///
/// Both regions are fixed offsets Wine hard-codes (confirmed from the pinned
/// `ntdll.dll` disassembly), and both sit in the currently-unmapped gap between
/// the single-page PEB (at `teb_base + 0x2000`) and the DLL arena:
///
/// - **`TEB + 0x3000`** — `__wine_dbg_strdup` (RVA 0x3f3c0) keeps a per-thread
///   debug-string ring buffer here: a `u32` write position at `TEB+0x3000` and
///   the ring bytes from `TEB+0x3008`, both bounded to `0x3fc`. A zeroed page
///   (position 0, empty ring) is a valid empty starting state.
/// - **`PEB + 0x2000`** — `__wine_dbg_get_channel_flags` reads the per-process
///   `__wine_debug_options` array here. A zero default entry (empty name) means
///   zero configured channels, so the lookup returns the default (all-off) flags
///   — the correct behaviour with no `WINEDEBUG` set.
///
/// Per-thread note: the `TEB+0x3000` ring is relative to *each* thread's TEB.
/// This seeds the main thread; spawned Wine threads (NtCreateThreadEx) need the
/// same page relative to their own TEB — a follow-up for when the Wine boot
/// spawns threads (the boot is single-threaded through `loader_init` today).
fn map_wine_debug_pages(mem: &mut VirtualMemory, teb_base: u64, peb_addr: u64) -> Result<()> {
    // TEB+0x3000 ring lands in [teb_base+0x3000, teb_base+0x4000); with the PEB
    // one page at teb_base+0x2000 and the dbgopts page at peb_addr+0x2000 (=
    // teb_base+0x4000), this gap is guaranteed unmapped.
    mem.map(Region::new("wine-dbgstr", teb_base + 0x3000, PAGE, Perm::RW))?;
    mem.map(Region::new("wine-dbgopts", peb_addr + 0x2000, PAGE, Perm::RW))?;
    Ok(())
}

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch, for
/// converting the host clock into `KUSER_SHARED_DATA.SystemTime` units.
const KUSER_FILETIME_EPOCH_DIFF_SECS: u64 = 11_644_473_600;

#[inline]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

#[inline]
fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

/// Rewrite the `ImageBase` field in a copy of the PE headers so a guest that
/// walks its own header (via `PEB.ImageBaseAddress`) sees the address it was
/// actually loaded at. The field is a QWORD at `opt+24` in PE32+ and a DWORD at
/// `opt+28` in PE32, where `opt` is the start of the optional header. Any header
/// too short to contain the field is left untouched (best-effort).
fn patch_header_image_base(headers: &mut [u8], is_64bit: bool, base: u64) {
    let read_u32 = |h: &[u8], at: usize| -> Option<u32> {
        h.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(pe_off) = read_u32(headers, 0x3C).map(|v| v as usize) else { return };
    let opt = pe_off + 4 + 20; // PE signature (4) + COFF header (20)
    if is_64bit {
        if let Some(dst) = headers.get_mut(opt + 24..opt + 32) {
            dst.copy_from_slice(&base.to_le_bytes());
        }
    } else if let Some(dst) = headers.get_mut(opt + 28..opt + 32) {
        dst.copy_from_slice(&(base as u32).to_le_bytes());
    }
}

fn section_name(raw: &str) -> String {
    if raw.is_empty() {
        "section".to_string()
    } else {
        raw.to_string()
    }
}

/// Initial value for a known imported *data* symbol (a variable exported by
/// a DLL). Returns `None` for symbols that should keep their zero default.
fn data_import_seed(name: &str, cmd_a: u64, cmd_w: u64) -> Option<u64> {
    match name {
        // The C runtime's cached command-line pointers.
        "_acmdln" => Some(cmd_a),
        "_wcmdln" => Some(cmd_w),
        // _fmode (text/binary), _commode (commit mode), environ pointers,
        // etc. all correctly default to 0, which the zeroed mapping provides.
        _ => None,
    }
}

/// Build a Windows-style command line from argv, quoting args with spaces.
fn build_cmdline(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kuser_shared_data_fields_readable() {
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem).expect("map KUSER_SHARED_DATA");

        // The page is mapped at the fixed kernel address.
        assert_eq!(KUSER_SHARED_DATA_BASE, 0x7ffe_0000);

        // SystemCall @ +0x308 is nonzero: the guest picks the SYSCALL path.
        let system_call = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL)
            .expect("read SystemCall");
        assert_ne!(system_call, 0, "SystemCall selector must be nonzero");

        // SystemTime @ +0x14 was seeded from the host clock (well past the
        // FILETIME epoch), so its high dword is nonzero.
        let system_time_high = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 4)
            .expect("read SystemTime.High1Time");
        assert_ne!(system_time_high, 0, "SystemTime should be a real clock value");
        // KSYSTEM_TIME is written as a consistent High1/High2 pair.
        let system_time_high2 = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 8)
            .expect("read SystemTime.High2Time");
        assert_eq!(system_time_high, system_time_high2);

        // InterruptTime @ +0x08 and TickCount @ +0x320 are readable (anchored 0).
        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_INTERRUPT_TIME)
                .expect("read InterruptTime"),
            0
        );
        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT)
                .expect("read TickCount"),
            0
        );

        // The dispatcher landing page one page above is reserved and mapped.
        assert_eq!(KUSER_DISPATCHER_PAGE, KUSER_SHARED_DATA_BASE + PAGE);
        mem.read_u8(KUSER_DISPATCHER_PAGE)
            .expect("dispatcher landing page is mapped");
    }

    #[test]
    fn wine_debug_pages_are_mapped_and_writable() {
        // Real 64-bit layout: TEB at GS_BASE, PEB one page above at +0x2000.
        let teb_base = GS_BASE;
        let peb_addr = GS_BASE + 0x2000;
        let mut mem = VirtualMemory::new();
        // Both maps must succeed without overlapping each other (VirtualMemory
        // rejects overlapping regions), proving the gap layout holds.
        map_wine_debug_pages(&mut mem, teb_base, peb_addr).expect("map wine debug pages");

        // The debug-string ring: a u32 position counter at TEB+0x3000 and ring
        // bytes from TEB+0x3008 — exactly what __wine_dbg_strdup reads/writes.
        mem.poke(teb_base + 0x3000, &7u32.to_le_bytes())
            .expect("write ring position");
        assert_eq!(
            mem.read_u32(teb_base + 0x3000).expect("read ring position"),
            7
        );
        mem.poke(teb_base + 0x3008, b"x").expect("write ring byte");
        // The far end of the ring (bounded to 0x3fc from +0x3008) is still in-page.
        mem.read_u8(teb_base + 0x3008 + 0x3fc)
            .expect("ring tail is mapped");

        // The __wine_debug_options page at PEB+0x2000 defaults to all zero.
        assert_eq!(
            mem.read_u32(peb_addr + 0x2000)
                .expect("read debug-options page"),
            0
        );
    }
}
