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

pub mod audio_sample;
pub mod cab;
pub mod cab_sample;
pub mod comctl_sample;
pub mod gui_sample;
pub mod sample;
pub mod shell_link_sample;
pub mod shell_sample;
pub mod socket_sample;
pub mod wow64_boot;
pub mod wow64_sample;
pub mod spawn;
pub mod spawn_sample;

use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{Cpu, EmuError, Exit, GuestClock, Memory, Perm, Region, Result};
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
/// Windows never maps the first 64 KiB of the address space — it is the
/// "null-pointer guard region", reserved precisely so that a dereference
/// through a NULL pointer (plus any plausible struct-field offset) faults
/// instead of silently reading whatever is there. exemu keeps the same
/// invariant, so a faulting address below this is a NULL dereference and can be
/// reported as one. See the null-deref note in [`Process::fault_report`].
const NULL_GUARD: u64 = 0x1_0000;

const KUSER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
/// The synthesized syscall-dispatcher landing page, reserved one page above
/// `KUSER_SHARED_DATA`. Native x64 Wine stubs issue a raw `SYSCALL` rather than
/// calling this page, but wow64/ARM64EC-shaped stubs route through a fixed low
/// page here; we reserve it now so that path has somewhere to land later.
const KUSER_DISPATCHER_PAGE: u64 = 0x7ffe_1000;

/// `KUSER_SHARED_DATA` field offsets we seed (public winnt/ntddk layout).
const KUSER_TICK_COUNT_MULTIPLIER: u64 = 0x004; // ULONG, ms = TickCount * mul >> 24
const KUSER_INTERRUPT_TIME: u64 = 0x008; // KSYSTEM_TIME (Low/High/High2)
const KUSER_SYSTEM_TIME: u64 = 0x014; // KSYSTEM_TIME (Low/High/High2)
const KUSER_SYSTEM_CALL: u64 = 0x308; // ULONG syscall-entry selector
const KUSER_TICK_COUNT: u64 = 0x320; // KSYSTEM_TIME TickCount

/// The clock-interrupt period `KUSER_SHARED_DATA.TickCount` counts in, in 100-ns
/// units: 15.625 ms, the standard Windows default `KeMaximumIncrement`.
const KUSER_TICK_PERIOD_100NS: u64 = 156_250;

/// `KUSER_SHARED_DATA.TickCountMultiplier` — the scale a guest applies to turn
/// `TickCount` into milliseconds (`ms = TickCount * multiplier >> 24`). For a
/// 15.625 ms tick that is `15.625 * 2^24` = 0x0FA0_0000, the value real Windows
/// publishes. Seeded on both clock paths: it is a *constant*, and leaving it 0
/// (as exemu did) makes a guest's inline `GetTickCount` compute 0 forever.
const KUSER_TICK_COUNT_MULTIPLIER_VALUE: u32 = 0x0FA0_0000;

/// How often the run loop refreshes the `KUSER_SHARED_DATA` time fields from the
/// virtual clock, in retired instructions.
///
/// Those fields are read by a **plain memory load** — a guest's inline
/// `GetTickCount`/`NtGetTickCount` never issues a syscall — so there is nothing
/// to intercept and the only way to virtualise them is to write them from
/// outside on a schedule. The schedule must be a function of the instruction
/// count, not of host time, or it reintroduces exactly the nondeterminism this
/// is here to remove. 65,536 instructions is 6.55 ms of virtual time: finer than
/// the 15.625 ms tick the fields are quantised to anyway, so the guest cannot
/// tell it apart from a continuously-running clock, and cheap enough (three
/// pokes per 65,536 instructions) to be invisible in the run loop.
const KUSER_REFRESH_INSTRUCTIONS: u64 = 65_536;

/// Size of the block JIT's W^X code buffer (roadmap W8). 32 MiB holds tens of
/// thousands of blocks; when it fills, the engine drops everything and starts
/// again rather than degrading to the interpreter forever.
const JIT_CODE_BYTES: usize = 32 << 20;

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

    /// The layout of a **WoW64** process (roadmap W5.4): a 32-bit guest running
    /// on Wine's 64-bit PE set.
    ///
    /// It is the *64-bit* layout — because that is what the process is: a 64-bit
    /// NT process whose kernel-facing structures (PEB64, TEB64, the NT-syscall
    /// frame, every `Nt*` handler) are 64-bit — with one change: the TEB pair is
    /// moved **below 4 GiB**. `TEB64.WowTebOffset` is a signed 32-bit delta to
    /// TEB32, and 32-bit guest code must be able to hold a TEB32 pointer, so the
    /// two TEBs must sit adjacently in the low 4 GiB (`exemu_os::wow64`'s
    /// `link_teb32` refuses anything else rather than truncating).
    ///
    /// The 32-bit half of the address space — the guest image, its stack, the
    /// 32-bit `ntdll` and `wow64cpu.dll` — is placed by [`wow64_boot`].
    fn for_wow64() -> Layout {
        Layout {
            teb_base: wow64_boot::WOW64_TEB64,
            peb_addr: wow64_boot::WOW64_PEB64,
            ..Layout::for_bits(true)
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
    /// Optional W4.2 display driver to inject before the guest starts running.
    /// `None` keeps the default [`exemu_core::NoDriver`] (all-no-ops), which is
    /// correct for console and emulated-corpus runs. Gate tests inject a
    /// [`exemu_gui::RecordingDriver`] here; future CLI code injects the Cocoa
    /// driver when `--gui` is combined with `--wine-boot`.
    pub driver: Option<Box<dyn exemu_core::UserDriver>>,
    /// Optional W7.2 host audio backend to inject before the guest starts.
    /// `None` keeps the default [`exemu_core::NoAudio`] (accept-and-drop), which
    /// is correct for every run that is not about audio and for a machine with
    /// no audio device. The W7.2 gate injects a recording sink here; the CLI
    /// injects the CoreAudio backend.
    pub audio_sink: Option<Box<dyn exemu_core::AudioSink>>,
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
    /// Which WoW64 bring-up a 32-bit guest on the Wine set takes (roadmap
    /// W5.7). The default is [`wow64_boot::Bringup::WineLoader`]: the process is
    /// handed to `wow64!Wow64LdrpInitialize`, so Wine's own i386 loader binds
    /// the guest's whole import graph — what a real application needs.
    /// [`wow64_boot::Bringup::Direct`] is the shorter chain that skips the
    /// 32-bit loader entirely. Ignored for anything that is not a WoW64 boot.
    pub wow64_bringup: wow64_boot::Bringup,
    /// The main→interpreter input channel (roadmap W4.5c). `Some` on the live
    /// Cocoa path: native window events (close → `WM_QUIT`) reach the guest's
    /// message pump, so `NtUserGetMessage` blocks until the user acts instead of
    /// quitting at once. `None` everywhere else (unchanged behaviour).
    pub input: Option<std::sync::mpsc::Receiver<exemu_core::InputEvent>>,
    /// Root the guest filesystem here instead of the shared
    /// `$TMPDIR/exemu-sandbox`.
    ///
    /// **Why this exists.** The shared sandbox **persists and accumulates across
    /// runs and across test binaries**, and guests observe it: an installer
    /// enumerates what it finds, and shell code checks whether a folder exists.
    /// So a run's behaviour — including its exact instruction count — depends on
    /// what previous runs left behind. That has bitten twice: the corpus pins
    /// were mis-measured against a dirty sandbox (see `corpus.toml`), and
    /// `shell_gate` produced a false failure because a leftover 7-Zip install
    /// already contained one of the folders under test.
    ///
    /// A test that pins behaviour should therefore set this to a private
    /// directory. The W9.6 corpus runner achieves the same isolation from the
    /// outside by spawning a child process with its own `TMPDIR`; this field is
    /// the in-process equivalent, and unlike an env var it is not racy when
    /// cargo runs test threads in parallel.
    ///
    /// `None` keeps the shared sandbox, which is right for real CLI runs — a
    /// user expects `exemu run` to write where the last one did.
    pub sandbox_root: Option<std::path::PathBuf>,
    /// Virtualise the guest clock (roadmap W9.6): drive `RDTSC`, `GetTickCount`,
    /// `QueryPerformanceCounter`, `NtQuerySystemTime` and `KUSER_SHARED_DATA`
    /// from the retired-instruction count instead of the host clock, so a run
    /// replays with the **exact same instruction count** every time.
    ///
    /// `false` (the default) keeps the host clock and the behaviour that
    /// shipped before, byte for byte. Like [`RunConfig::wine_boot_dir`] this
    /// takes precedence over the `EXEMU_VIRTUAL_CLOCK` env opt-in, so a test or
    /// the corpus gate can request it hermetically without touching
    /// process-global env vars.
    pub virtual_clock: bool,
    /// Use this **verbatim** as the guest command line instead of joining
    /// [`RunConfig::args`] (roadmap W3.5). A child process's command line was
    /// already built by its parent — re-joining an argv would re-quote it — so
    /// the spawner passes the parent's string straight through.
    pub command_line: Option<String>,
    /// Seed the guest environment with these `name=value` pairs instead of the
    /// OS layer's default set (roadmap W3.5). A child inherits the environment
    /// block its parent handed to `NtCreateUserProcess`; empty keeps the default.
    pub environment: Vec<(String, String)>,
    /// How deep this process sits in the spawn chain: 0 for a run started from
    /// the CLI or a test, `parent + 1` for a child. Bounds runaway recursion
    /// (see [`crate::spawn::MAX_SPAWN_DEPTH`]).
    pub spawn_depth: u32,
    /// Run guest code through the **block JIT** (roadmap W8) instead of the
    /// interpreter wherever it can, falling back to the interpreter for every
    /// instruction the JIT declines.
    ///
    /// `false` (the default) is the interpreter-only path that every pin in
    /// `corpus.toml` was measured against, and stays so until the JIT has been
    /// through more than the W8.3 opcode slice. The JIT is required to be
    /// bit-for-bit identical to the interpreter (`crates/oracle`'s W8.7
    /// differential), so turning it on must change *nothing* observable — which
    /// is exactly what makes an A/B of the same corpus run a meaningful test:
    /// same exit code, same artifacts, same instruction count, less wall time.
    /// Also settable with `EXEMU_JIT=1`.
    pub jit: bool,
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
            wow64_bringup: wow64_boot::Bringup::default(),
            driver: None,
            audio_sink: None,
            input: None,
            sandbox_root: None,
            virtual_clock: false,
            command_line: None,
            environment: Vec::new(),
            spawn_depth: 0,
            jit: false,
        }
    }
}

/// What the block JIT did during a run (roadmap W8) — reported rather than
/// claimed, so "how much of this workload actually ran as native code?" has a
/// measured answer.
#[derive(Clone, Debug, Default)]
pub struct JitReport {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    /// Guest instructions executed as native ARM64.
    pub insns_executed: u64,
    /// Blocks that ended by rewinding onto a faulting access.
    pub faults: u64,
    /// Addresses where nothing could be compiled (the interpreter took them).
    pub not_compiled: u64,
    /// Whole-cache invalidations caused by guest code changing (W1.7 seam).
    pub flushes: u64,
    /// High-water mark of emitted native code, in bytes.
    pub code_bytes: usize,
    /// The opcodes that most often stopped a block, `(opcode | 0x100 for the
    /// 0F map, count)`, most frequent first — the to-do list for W8.4+.
    pub declined: Vec<(u16, u64)>,
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
    /// How many child processes the program successfully created (roadmap W3.5).
    /// Monotonic, so a per-exe probe can state "this binary never reached child
    /// creation" as a measurement rather than an inference.
    pub children_created: u32,
    /// Block-JIT statistics, when the run used it (roadmap W8).
    pub jit: Option<JitReport>,
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
    /// The process clock (roadmap W9.6) — the same handle the interpreter and
    /// the OS layer hold. The run loop reads it to refresh `KUSER_SHARED_DATA`.
    clock: GuestClock,
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
    /// The WoW64 process model, when this is a 32-bit guest on Wine's 64-bit PE
    /// set (roadmap W5.4). `None` on every other path.
    wow64: Option<wow64_boot::Wow64Boot>,
    /// The block JIT (roadmap W8), when `RunConfig::jit` asked for it and the
    /// platform has a W^X backend. `None` everywhere else — and `None` is the
    /// default, so the interpreter path is untouched.
    jit: Option<exemu_jit::Jit>,
}

impl Process {
    /// Parse and lay out `pe_bytes` into a runnable process.
    ///
    /// `cfg` is taken by mutable reference so the optional
    /// [`RunConfig::driver`] slot can be moved out (a `Box<dyn …>` cannot be
    /// cloned). All other fields are read-only; callers that do not use the
    /// driver slot are unaffected.
    pub fn load(pe_bytes: &[u8], cfg: &mut RunConfig) -> Result<Process> {
        let mut image = loader::parse(pe_bytes)?;
        let mut mem = VirtualMemory::new();

        // --- The process clock (roadmap W9.6, opt-in) ---------------------
        // One handle, shared by the interpreter (RDTSC), the OS layer (every
        // Win32/NT time API) and this run loop (the KUSER_SHARED_DATA refresh),
        // so the guest sees a single consistent notion of "now". Explicit config
        // wins; otherwise `EXEMU_VIRTUAL_CLOCK` (any non-empty value that is not
        // "0") opts in, matching how `EXEMU_WINE_BOOT` is done. Default: host
        // clock, i.e. exactly the behaviour that shipped before.
        let clock = GuestClock::new(cfg.virtual_clock || env_opt_in("EXEMU_VIRTUAL_CLOCK"));

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

        // --- Wine-boot opt-in (roadmap W3.2) ------------------------------
        // `EXEMU_WINE_BOOT` selects the experimental path that boots the real
        // Wine PE core (ntdll→kernelbase→kernel32→ucrtbase) as guest images and
        // hands off through `LdrInitializeThunk`, instead of the emulated-DLL
        // thunks. Off by default so the corpus is byte-for-byte unaffected while
        // the boot path (W3.3 exc bridge, W3.4 console) is still being built. The
        // DLL directory defaults to the pinned prefix but is overridable via
        // `EXEMU_WINE_DLLS`; `wine_dll_dir` stays `None` unless the opt-in is set
        // AND the directory exists, so `load_wine_core` only ever runs on request.
        //
        // Resolved *before* the address-space layout because a 32-bit image on
        // this path is not a 32-bit process at all — it is a **WoW64** process
        // (roadmap W5.4), whose layout is the 64-bit one with a 32-bit view laid
        // over it.
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

        // A 32-bit image + the Wine PE set = a WoW64 boot, provided the pinned
        // prefix carries **both** halves (the 64-bit thunk DLLs and the 32-bit
        // ntdll). A partial prefix falls back to the ordinary 32-bit path rather
        // than half-booting WoW64.
        let wow64_dir32 = wine_dll_dir
            .as_ref()
            .map(|d| wow64_boot::sibling_i386_dir(std::path::Path::new(d)));
        let is_wow64 = !image.is_64bit
            && match (&wine_dll_dir, &wow64_dir32) {
                (Some(d64), Some(d32)) => wow64_boot::Wow64Dirs {
                    dir64: std::path::Path::new(d64),
                    dir32: d32,
                }
                .complete(),
                _ => false,
            };

        let lay = if is_wow64 {
            Layout::for_wow64()
        } else {
            Layout::for_bits(image.is_64bit)
        };
        // Width of a pointer **in the image's own structures** (its IAT slots),
        // and of a pointer in the *process*'s NT structures — which differ under
        // WoW64: a PE32 guest inside a 64-bit NT process.
        let ptr_size = if image.is_64bit { 8 } else { 4 };
        let proc_is_64 = image.is_64bit || is_wow64;
        let proc_ptr_size = if proc_is_64 { 8 } else { 4 };

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
            mem.poke(addr, &val.to_le_bytes()[..proc_ptr_size])
        };
        write_ptr(&mut mem, lay.teb_base + lay.teb_self, lay.teb_base)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_peb, lay.peb_addr)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_base, stack_top)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_limit, lay.stack_base)?;
        write_ptr(&mut mem, lay.peb_addr + lay.peb_image_base, base)?;

        // --- KUSER_SHARED_DATA @ 0x7ffe0000 + dispatcher landing page -----
        // Fixed-address kernel page every process reads directly; also reserves
        // the syscall-dispatcher landing page one page above it (roadmap W2.1).
        map_kuser_shared_data(&mut mem, &clock)?;

        // --- Command line (ASCII + UTF-16) in the env region --------------
        // A child process (roadmap W3.5) arrives with the command line its
        // parent already built, so it is used verbatim; everything else joins
        // argv. Either way it is bounded to the region: the ASCII copy has
        // 0x400 bytes and the UTF-16 copy the rest of the page, and a command
        // line that overran them would corrupt whatever follows.
        mem.map(Region::new("env", lay.env_base, ENV_SIZE, Perm::RW))?;
        let cmdline = truncate_cmdline(
            cfg.command_line.clone().unwrap_or_else(|| build_cmdline(&cfg.args)),
        );
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
        let sandbox = cfg
            .sandbox_root
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("exemu-sandbox"));
        let _ = std::fs::create_dir_all(&sandbox);
        // Ensure the guest `C:\` drive root exists as a real directory so opening
        // it as the working directory succeeds (Wine's `loader_init` opens
        // `C:\` early; a missing dir logged "could not open working directory").
        // The `C\windows\system32` chain gives the DLL-search redirect a real
        // parent so a missing DLL resolves to OBJECT_NAME_NOT_FOUND (not
        // OBJECT_PATH_NOT_FOUND), matching what Wine's search loop expects.
        let _ = std::fs::create_dir_all(sandbox.join("C").join("windows").join("system32"));
        // The user-profile tree, the way a real Wine prefix is *created* with it
        // (that is what `wineboot` does on first run). exemu previously booted
        // Wine's DLLs against a sandbox holding only `C:\windows\system32`, and
        // shell code distinguishes "folder exists" from "folder is nameable" —
        // `SHGetFolderPath` without `CSIDL_FLAG_CREATE` reports failure for an
        // absent directory even while filling in the path. Cheap (a few dozen
        // `mkdir -p`), and it makes the guest's view of its own profile real.
        for guest in exemu_os::folders::all_guest_dirs() {
            let mut host = sandbox.clone();
            for comp in guest.split('\\') {
                match comp {
                    "" | "." | ".." => {}
                    c if c.ends_with(':') => host.push(&c[..c.len() - 1]),
                    c => host.push(c),
                }
            }
            let _ = std::fs::create_dir_all(&host);
        }
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

        // exemu's own audio driver PE (roadmap W7.2). Wine's `*.drv` audio
        // drivers ship no usable PE half — the pinned `winealsa.drv` and
        // `winepulse.drv` are byte-identical, export-less stubs — so exemu
        // supplies its own `winecoreaudio.drv` and pairs the CoreAudio unixlib
        // with it. It goes into the sandbox's `system32`, which the DLL-search
        // redirect consults *before* the pinned prefix, so
        // `mmdevapi!load_driver`'s `LoadLibraryW` finds it. Written only on a
        // Wine boot: nothing on the emulated path loads it.
        if wine_dll_dir.is_some() {
            let drv = sandbox
                .join("C")
                .join("windows")
                .join("system32")
                .join(exemu_os::audio::DRIVER_MODULE);
            let _ = std::fs::write(drv, exemu_os::audio::driver_stub_pe());
        }

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
            // A WoW64 process **is** a 64-bit NT process: its PEB/TEB, its
            // NT-syscall frame and every `Nt*` handler are 64-bit. Only the
            // guest image and the 32-bit view laid over it are 32-bit, and those
            // reach the kernel exclusively through wow64.dll's 64-bit thunks.
            is_64bit: proc_is_64,
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
            wine_dll_dir: wine_dll_dir.clone(),
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

        // --- Child processes (roadmap W3.5) --------------------------------
        // The OS layer owns `NtCreateUserProcess`, the process objects and the
        // handle semantics; *running* a second guest image needs this crate, so
        // it is injected the same way the display driver is. A child inherits
        // this run's sandbox, Wine prefix and budget, and its environment is the
        // block its parent handed over.
        os.set_environment(cfg.environment.clone());
        os.set_spawn_depth(cfg.spawn_depth);
        os.set_process_spawner(Box::new(spawn::AppSpawner::new(cfg, sandbox.clone())));

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

        // Under WoW64 the guest's imports are bound later, against the **32-bit**
        // `ntdll` (`wow64_boot::bind_guest_imports`): resolving them here would
        // write 64-bit thunk (or 64-bit ntdll) addresses into 4-byte IAT slots.
        for imp in image.imports.iter().filter(|_| !is_wow64) {
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

        // --- Optional W4.2 display driver ---------------------------------
        // Injected by tests (RecordingDriver) or future CLI code (CocoaDriver).
        // Default is NoDriver (all-no-ops), correct for the emulated path.
        if let Some(d) = cfg.driver.take() {
            os.set_driver(d);
        }
        // --- Optional W7.2 host audio backend -----------------------------
        if let Some(sink) = cfg.audio_sink.take() {
            os.set_audio_sink(sink);
        }
        // --- Optional W4.5c input channel (native window → guest pump) ------
        if let Some(rx) = cfg.input.take() {
            os.set_input(rx);
        }

        // --- Initial CPU state --------------------------------------------
        let mut cpu = Interpreter::with_bits(if image.is_64bit { Bits::B64 } else { Bits::B32 });
        // --- The block JIT (roadmap W8), opt-in ---------------------------
        // A JIT that cannot be created is never a correctness problem: the run
        // loop simply stays on the interpreter, so a platform without a W^X
        // backend (or a hardened-runtime build missing the JIT entitlement)
        // degrades in speed and nothing else.
        let want_jit = cfg.jit || std::env::var("EXEMU_JIT").is_ok_and(|v| v != "0");
        let jit = if want_jit {
            match exemu_jit::Jit::new(JIT_CODE_BYTES) {
                Ok(j) => Some(j),
                Err(e) => {
                    eprintln!("[exemu] JIT unavailable, running on the interpreter: {e}");
                    None
                }
            }
        } else {
            None
        };
        // Both halves of the emulator share the one clock handle (W9.6).
        cpu.set_clock(clock.clone());
        os.set_clock(clock.clone());
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
        // When `EXEMU_WINE_BOOT` gated `wine_dll_dir` on above, pre-map **ntdll
        // only** as a real guest image (the running image Wine never re-maps),
        // then re-seat the initial thread at ntdll's `LdrInitializeThunk` with a
        // CONTEXT for `RtlUserThreadStart(entry, 0)` — Wine's own loader_init
        // then loads kernelbase/kernel32/ucrtbase itself from the same prefix and
        // runs the DllMains before reaching the exe entry (phase iv trim: exemu
        // no longer double-maps those three). This OVERRIDES the `start_process`
        // seating above. When `wine_dll_dir` is `None` (the default / files
        // absent), `load_wine_core` returns `None` and every binary keeps the
        // emulated-DLL path, unchanged.
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

        // --- WoW64 boot (roadmap W5.4/W5.1) -------------------------------
        // A 32-bit guest on the Wine set. exemu builds the WoW64 process — the
        // module set, the dual TEB/PEB, the CPU-reserved area — and then hands
        // control to Wine's own binary translator through a 64-bit bring-up
        // trampoline. Everything past that hand-off is Wine's code.
        let mut wow64 = None;
        if is_wow64 {
            let Some(ntdll_base) = os.load_wine_core(&mut mem)? else {
                return Err(EmuError::Os(
                    "WoW64 boot: the 64-bit Wine core would not load from the pinned prefix".into(),
                ));
            };
            map_wine_debug_pages(&mut mem, lay.teb_base, lay.peb_addr)?;
            // Steer the 64-bit ntdll stubs onto the bare `syscall` route into
            // the W2.3 dispatcher (as on the W3 boot path).
            mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes())?;

            let dir64 = wine_dll_dir.clone().unwrap_or_default();
            let dir32 = wow64_dir32.clone().unwrap_or_default();
            let dirs = wow64_boot::Wow64Dirs {
                dir64: std::path::Path::new(&dir64),
                dir32: &dir32,
            };
            let ntdll64_bytes = std::fs::read(dirs.dir64.join("ntdll.dll"))
                .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot re-read ntdll.dll: {e}")))?;
            let ntdll64 = exemu_os::wow64::image_view(&ntdll64_bytes, ntdll_base)?;

            let boot = wow64_boot::build(&mut mem, &dirs, &ntdll64, base)?;
            // Who binds the guest's IAT depends on the bring-up. Under
            // `WineLoader` **Wine's own i386 loader does** — that is the point
            // of running it — so exemu must leave the slots alone. Under
            // `Direct` there is no 32-bit loader at all, so exemu binds what it
            // can against the 32-bit `ntdll` and refuses the boot if the program
            // needs anything else, rather than leaving null IAT slots that fault
            // later with no explanation.
            if cfg.wow64_bringup == wow64_boot::Bringup::Direct {
                let (bound, missing) =
                    wow64_boot::bind_guest_imports(&mut mem, base, &image.imports, &boot)?;
                if !missing.is_empty() {
                    return Err(EmuError::Os(format!(
                        "WoW64 boot (direct bring-up): {} guest import(s) unresolved against the \
                         32-bit Wine set — this program needs the Wine-loader bring-up: {}",
                        missing.len(),
                        missing.join(", ")
                    )));
                }
                let _ = bound;
            }

            // `PEB32.ProcessParameters`. Wine's i386 `loader_init` dereferences
            // it in its first few hundred instructions
            // (`init_user_process_params`, ntdll32 rva 0x4fc00), so the 32-bit
            // block has to exist before the guest half starts — the kernel's
            // job, and the same one exemu already does for PEB64.
            let pp32 = os
                .build_wow64_process_parameters(&mut mem, wow64_boot::WOW64_PARAMS, wow64_boot::WOW64_PARAMS_SIZE)?
                .ok_or_else(|| {
                    EmuError::Os("WoW64 boot: the 32-bit process-parameter arena is too small".into())
                })?;
            mem.write_u32(boot.peb32 + exemu_os::wow64::peb32::PROCESS_PARAMETERS, pp32 as u32)?;

            // The process is a WoW64 one: publish its 32-bit PEB so
            // `NtQueryInformationProcess(ProcessWow64Information)` and the
            // architecture report answer the way `wow64.dll`'s process init
            // needs them to (roadmap W5.6).
            os.set_wow64_peb32(boot.peb32);
            // exemu mapped `wow64cpu`/`wow64win` itself (Wine's 64-bit
            // `loader_init` never ran on this path), so the loader entry points
            // `wow64.dll` uses to reach them answer out of exemu's own table.
            os.register_wow64_module("wow64cpu.dll", boot.wow64cpu.base);
            os.register_wow64_module("wow64win.dll", boot.wow64win.base);

            // The 32-bit ntdll's own unixlib handle (roadmap W5.3). A 32-bit
            // `__wine_unix_call` reaches the *same* 64-bit dispatcher as a
            // 64-bit one — `wow64cpu`'s BOP handler (rva 0x1255) just
            // zero-extends the guest's 32-bit `args` pointer into `r8d` — so the
            // handle is the only thing that says "this block is 32-bit wide".
            // Publishing it is the unix side's job, which is exemu's role here.
            let h32 = os.register_ntdll32_unixlib(boot.ntdll32.base);
            if let Some(slot) = boot.ntdll32.export("__wine_unixlib_handle") {
                mem.write_u64(slot, h32)?;
            }

            // `BTCpuProcessInit` calls `ntdll!LdrGetDllHandle` to find the
            // 64-bit ntdll, and `wow64.dll`'s process init calls
            // `LdrGetDllHandle` + `LdrLoadDll` to reach ntdll / wow64cpu /
            // wow64win. Wine's own loader entry points walk a module hash table
            // only its `loader_init` fills, which this boot deliberately does
            // not run — so those slots bind to exemu's native loader queries
            // instead (see `Api::LdrGetDllHandle` / `Api::LdrLoadDll`). Every
            // other import either DLL uses is Wine's real 64-bit ntdll code.
            let native = |os: &mut exemu_os::WinOs, sym: &str| {
                os.resolve_import("ntdll.dll", &exemu_core::ImportSymbol::Named(sym.into()))
            };
            let (ldr_get, ldr_load) = (native(&mut os, "LdrGetDllHandle"), native(&mut os, "LdrLoadDll"));
            for img in [&boot.wow64cpu, &boot.wow64] {
                for (iat_rva, _dll, sym) in &img.imports {
                    let addr = match sym.as_str() {
                        "LdrGetDllHandle" => ldr_get,
                        "LdrLoadDll" => ldr_load,
                        _ => continue,
                    };
                    mem.write_u64(img.base + *iat_rva as u64, addr)?;
                }
            }

            match cfg.wow64_bringup {
                wow64_boot::Bringup::Direct => {
                    wow64_boot::seat_direct(&mut cpu, &mut mem, &boot, image.entry_va(), stack_top)?
                }
                wow64_boot::Bringup::WineLoader => wow64_boot::seat_wine_loader(
                    &mut cpu,
                    &mut mem,
                    &boot,
                    &ntdll64,
                    lay.peb_addr,
                    image.entry_va(),
                    stack_top,
                )?,
            }
            wow64 = Some(boot);
        }

        Ok(Process {
            mem,
            cpu,
            os,
            clock,
            sandbox: sandbox.to_string_lossy().into_owned(),
            entry: image.entry_va(),
            max_steps: cfg.max_steps,
            image_base: base,
            exc_depth: 0,
            wow64,
            jit,
        })
    }

    /// The WoW64 process model this boot built, when the image is a 32-bit guest
    /// running on Wine's 64-bit PE set (roadmap W5.4). `None` on every other
    /// path. Gate tests read the module bases and the TEB/PEB pair out of it.
    pub fn wow64(&self) -> Option<&wow64_boot::Wow64Boot> {
        self.wow64.as_ref()
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

    /// Read-only view of the process address space (for tests/tools inspecting
    /// the built process before or after a run).
    pub fn memory(&self) -> &dyn Memory {
        &self.mem
    }

    /// The address the main image was mapped at.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Step the CPU until `rip == target`, at most `max_steps` instructions,
    /// returning how many ran.
    ///
    /// The bounded counterpart of [`Process::run`]: it stops *at* a chosen
    /// instruction instead of at process exit, which is how a gate can assert on
    /// the state a multi-stage bootstrap leaves behind at one of its stages (the
    /// WoW64 bring-up publishes the BOP before it enters the guest — roadmap
    /// W5.1). Faults surface exactly as in `run`.
    pub fn run_until_rip(&mut self, target: u64, max_steps: u64) -> Result<u64> {
        let mut steps = 0u64;
        while self.cpu.state().rip != target {
            if steps >= max_steps {
                return Err(EmuError::Os(format!(
                    "run_until_rip({target:#x}): not reached within {max_steps} steps (rip {:#x})",
                    self.cpu.state().rip
                )));
            }
            match self.cpu.step(&mut self.mem, &mut self.os)? {
                Exit::Continue => steps += 1,
                other => {
                    return Err(EmuError::Os(format!(
                        "run_until_rip({target:#x}): process left the run loop with {other:?} after {steps} steps"
                    )))
                }
            }
        }
        Ok(steps)
    }

    /// Run until the process exits (or the step cap / a fault is hit).
    pub fn run(mut self) -> Result<RunResult> {
        self.run_borrowed()
    }

    /// [`Process::run`] without consuming the process, so a caller can inspect
    /// guest memory afterwards.
    pub fn run_borrowed(&mut self) -> Result<RunResult> {
        let mut steps: u64 = 0;
        // `KUSER_SHARED_DATA`'s time fields are read by a plain guest load, so
        // the only way to virtualise them is to write them from out here on a
        // schedule keyed to the instruction count (roadmap W9.6). Off entirely
        // on the host-clock path, where the page keeps its load-time snapshot.
        let refresh_kuser = self.clock.is_virtual();
        let mut next_kuser_refresh = KUSER_REFRESH_INSTRUCTIONS;
        // Rolling window of the most recent instruction pointers, for the
        // fault report (helps trace how a bad jump was reached). With the JIT
        // on, this records block entries rather than every instruction.
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
            // --- The block JIT (roadmap W8), when it is switched on --------
            //
            // A compiled block runs many guest instructions per call, so
            // everything the loop does per instruction has to be reconciled:
            // the step count and the clock advance by the number the block
            // retired, and the KUSER refresh compares against a threshold
            // instead of testing a modulus that a multi-instruction jump can
            // step over. On the interpreter path the threshold test fires at
            // exactly the same instructions the modulus did.
            //
            // The JIT can never swallow an API thunk: thunks live in the
            // `imports` region, which is mapped RW (never executable), so
            // `Memory::fetch` refuses and the block is not compiled — the
            // interpreter takes that address and `Hooks::intercept` fires as
            // usual.
            if let Some(jit) = self.jit.as_mut() {
                // The mode is the CPU's *current* one, not the image's: a WoW64
                // process runs 32- and 64-bit code in one address space and the
                // same bytes decode differently in each (roadmap W5.2).
                let mode = match self.cpu.bits() {
                    Bits::B64 => exemu_jit::Mode::Long,
                    Bits::B32 => exemu_jit::Mode::Protected,
                };
                let ran = jit.run(self.cpu.state_mut(), &mut self.mem, mode);
                let insns = match ran {
                    exemu_jit::Run::NotCompiled => 0,
                    exemu_jit::Run::Executed { insns } | exemu_jit::Run::Faulted { insns } => insns,
                };
                if insns != 0 {
                    self.clock.retire(insns as u64);
                    steps += insns as u64;
                    // The OS layer counts instructions to drive timeslice
                    // preemption, and a compiled block bypasses the per-
                    // instruction `intercept` that does the counting — so tell
                    // it how many ran. Without this the JIT would change guest
                    // *scheduling*, not just speed.
                    exemu_core::Hooks::retire(
                        &mut self.os,
                        insns as u64,
                        self.cpu.state_mut(),
                        &mut self.mem,
                    )?;
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                // `Executed` leaves `rip` on the next block, so go round again.
                // `Faulted` rewound onto the instruction whose access failed and
                // changed nothing for it: fall through and let the interpreter
                // execute exactly that instruction, which raises the real error
                // (and leaves whatever partial state the interpreter would).
                if matches!(ran, exemu_jit::Run::Executed { .. }) {
                    continue;
                }
            }
            let outcome = self.cpu.step(&mut self.mem, &mut self.os);
            let tail = || recent.iter().copied().collect::<Vec<_>>();
            match outcome {
                Ok(Exit::Continue) => {
                    steps += 1;
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
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
                    if self.try_deliver_hw_exception(ExcSource::Interrupt(n), steps, &tail())? {
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
                    if self.try_deliver_hw_exception(ExcSource::Error(&e), steps, &tail())? {
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
            children_created: self.os.children_created(),
            jit: self.jit_report(),
        })
    }

    /// What the JIT did, if this process had one (roadmap W8).
    pub fn jit_report(&self) -> Option<JitReport> {
        let jit = self.jit.as_ref()?;
        let s = jit.stats();
        Some(JitReport {
            blocks_compiled: s.blocks_compiled,
            blocks_executed: s.blocks_executed,
            insns_executed: s.insns_executed,
            faults: s.faults,
            not_compiled: s.not_compiled,
            flushes: s.flushes,
            code_bytes: s.peak_code_bytes.max(jit.code_bytes()),
            declined: s.top_declined(16),
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
    fn try_deliver_hw_exception(&mut self, src: ExcSource<'_>, steps: u64, recent: &[u64]) -> Result<bool> {
        // Guard: only on the Wine-boot path (real ntdll mapped). The emulated
        // corpus keeps its fault reporter, unchanged.
        let Some(ntdll_base) = self.os.module_base("ntdll.dll") else {
            return Ok(false);
        };
        // A fault in **32-bit** WoW64 guest code cannot be delivered here: this
        // path builds a 64-bit `CONTEXT` and seats rip on the *64-bit* ntdll's
        // `KiUserExceptionDispatcher`, which a CPU in 32-bit mode truncates to a
        // 32-bit address and then faults on again (roadmap W5.7). Wine routes it
        // instead through `wow64.dll!Wow64PassExceptionToGuest` →
        // `ntdll32!KiUserExceptionDispatcher`, which exemu does not drive yet —
        // so decline, and let the fault reporter say where the guest really
        // stopped. Pinned as `wow64_32bit_exception_is_not_delivered_to_the_guest`.
        if self.wow64.is_some() && self.cpu.bits() == Bits::B32 {
            return Ok(false);
        }
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

        // Two levels of fault visibility, because a bridged exception is
        // *delivered to the guest* and so the emulator normally says nothing —
        // right when the guest handles it, useless when it does not (the process
        // just dies with 0xC0000005 and no clue where).
        //
        // `EXEMU_FAULT_TRACE` is the compact one-liner: code, address, rip, the
        // module the rip lands in, and the bytes there.
        if std::env::var_os("EXEMU_FAULT_TRACE").is_some() {
            let rip = self.cpu.state().rip;
            let mut bytes = [0u8; 16];
            let _ = self.mem.read(rip, &mut bytes);
            eprintln!(
                "[exc] code={code:#x} at={address:#x} rip={rip:#x} {} bytes={bytes:02x?}",
                self.os.module_for_addr(rip).unwrap_or_default()
            );
        }

        // `EXEMU_DBG` is the full, module-attributed fault report at the point of
        // delivery — what makes an access violation inside Wine's own code
        // diagnosable at all.
        if std::env::var_os("EXEMU_DBG").is_some() {
            eprintln!(
                "[exemu] delivering exception {code:#010x} to the guest, faulting address {}
{}",
                self.addr_note(address),
                self.fault_report(
                    &format!("guest exception {code:#010x} (address {address:#x})"),
                    None,
                    steps,
                    recent,
                ),
            );
        }

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
        let report = self.fault_report(&err.to_string(), Some(&err), steps, recent);
        // Keep the structured `err` as the cause so callers can still classify
        // the fault (e.g. decode-miss telemetry, roadmap P0.5) — the report is
        // only the human-facing rendering.
        EmuError::Fault { report, cause: Box::new(err) }
    }

    /// Render `addr` as `0x… (module+0xrva)` when it lands in a loaded guest
    /// image. A raw address is unactionable; `shell32.dll+0x39600` can be fed
    /// straight to a disassembler over the pinned binary.
    fn addr_note(&self, addr: u64) -> String {
        match self.os.module_at(addr) {
            Some((name, rva)) => format!("{addr:#x} ({name}+{rva:#x})"),
            None => format!("{addr:#x}"),
        }
    }

    /// The body of [`Self::fault`], reusable for a fault that is *not* fatal —
    /// notably an access violation that the W3.3 bridge is about to hand to the
    /// guest, where the emulator would otherwise print nothing at all.
    fn fault_report(&self, headline: &str, err: Option<&EmuError>, steps: u64, recent: &[u64]) -> String {
        use std::fmt::Write;
        let s = self.cpu.state();
        let mut o = String::new();
        let _ = writeln!(o, "{headline}");

        // If the fault touched an import thunk, the guest is treating an
        // imported *function* slot as data — the tell-tale of a data export
        // (very common in the MSVCRT C runtime, e.g. _fmode/_commode).
        if let Some(EmuError::Unmapped { addr, .. }) = &err {
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

        // The commonest failure shape exemu has: a stubbed API returns 0, the
        // guest keeps it as a pointer or a function pointer, and faults an
        // arbitrary distance later. The fault itself says nothing about where
        // the zero came from — so name the suspects.
        //
        // The tell is that the address involved is NULL plus at most a small
        // struct-field offset: `rip = 0` for a call through a NULL function
        // pointer, or a faulting address inside the never-mapped low guard
        // region for a load/store through a NULL base. Real code never has a
        // legitimate address there.
        let null_deref = s.rip < NULL_GUARD
            || matches!(
                err,
                Some(EmuError::Unmapped { addr, .. } | EmuError::Permission { addr, .. }) if *addr < NULL_GUARD
            );
        if null_deref {
            let suspects = self.os.zero_returning_stubs();
            let _ = writeln!(
                o,
                "  note: this is a NULL dereference (address below {NULL_GUARD:#x} — a null pointer\n\
                 \x20       plus at most a struct-field offset), which in exemu almost always means\n\
                 \x20       an unimplemented API returned 0 and the guest kept it as a pointer."
            );
            if suspects.is_empty() {
                let _ = writeln!(
                    o,
                    "  note: no unimplemented Win32 stub has returned 0 in this run, so the NULL\n\
                     \x20       came from somewhere else — guest logic, or a *implemented* API\n\
                     \x20       returning the wrong thing."
                );
            } else {
                let _ = writeln!(
                    o,
                    "  suspects (unimplemented stubs that returned 0, most recent first): {}",
                    suspects.join(", ")
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
        if self.os.module_at(s.rip).is_some() {
            let _ = writeln!(o, "  rip is {}", self.addr_note(s.rip));
        }
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
            // The same trail, module-attributed: the raw addresses show *how*
            // the guest got here, the names show *whose* code it is. Skipped
            // entirely when nothing resolves — a row of "?" is pure noise.
            if recent.iter().any(|r| self.os.module_at(*r).is_some()) {
                let _ = write!(o, "\n  recent rip trail (named):");
                for r in recent {
                    let _ = write!(o, " {}", self.os.describe_addr(*r));
                }
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
                let _ = write!(o, "\n  call stack (virtual unwind, innermost first): {}", self.addr_note(s.rip));
                for f in &frames {
                    let _ = write!(o, " ← {}", self.addr_note(*f));
                }
            }
        }
        let modules = self.os.loaded_modules();
        if !modules.is_empty() {
            let _ = write!(o, "\n  loaded modules:");
            for (name, base, size) in &modules {
                let _ = write!(o, " {name}@{base:#x}+{size:#x}");
            }
        }
        o.push('\n');
        o
    }
}

/// Convenience: load and run in one call.
pub fn load_and_run(pe_bytes: &[u8], cfg: RunConfig) -> Result<RunResult> {
    let mut cfg = cfg;
    Process::load(pe_bytes, &mut cfg)?.run()
}

// ---- helpers ---------------------------------------------------------------

/// Map `KUSER_SHARED_DATA` at its fixed virtual address and seed the modern
/// 64-bit fields the guest reads directly, plus reserve the syscall-dispatcher
/// landing page one page above it (roadmap W2.1).
///
/// `SystemCall` is set nonzero so the guest selects the `SYSCALL` entry shape
/// the dispatcher will implement, rather than the legacy `int 2Eh` path.
/// `TickCountMultiplier` gets its real Windows value on both paths — it is a
/// constant, and 0 would make a guest's inline `GetTickCount` compute 0 forever.
///
/// The `SystemTime`/`InterruptTime`/`TickCount` fields depend on `clock`:
///
/// * **Host clock** — point-in-time snapshots taken at process load, exactly as
///   before: `SystemTime` from the host, `InterruptTime`/`TickCount` anchored at
///   0. They are not driven forward (the clock-backed `Nt*`/Win32 time APIs
///   remain authoritative). Keeping the page frozen here is what makes the
///   default path byte-identical.
/// * **Virtual clock (W9.6)** — seeded from the virtual clock at instruction 0
///   and then refreshed by the run loop every
///   [`KUSER_REFRESH_INSTRUCTIONS`] instructions ([`refresh_kuser_time`]), which
///   is the only way to virtualise a field the guest reads by plain load.
fn map_kuser_shared_data(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
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

    if clock.is_virtual() {
        refresh_kuser_time(mem, clock)?;
    } else {
        // Seed the time fields as KSYSTEM_TIME triples (LowPart, High1Time,
        // High2Time) so a guest reading either half sees a consistent value.
        let now_100ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let system_time = (now_100ns.as_secs() + KUSER_FILETIME_EPOCH_DIFF_SECS) * 10_000_000
            + now_100ns.subsec_nanos() as u64 / 100;
        write_ksystem_time(mem, KUSER_SYSTEM_TIME, system_time)?;
        // InterruptTime/TickCount both count from boot; we anchor them at 0 (a
        // freshly booted system) — they advance via the clock-backed time APIs.
        write_ksystem_time(mem, KUSER_INTERRUPT_TIME, 0)?;
        write_ksystem_time(mem, KUSER_TICK_COUNT, 0)?;
    }

    mem.poke(
        KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER,
        &KUSER_TICK_COUNT_MULTIPLIER_VALUE.to_le_bytes(),
    )?;
    // SystemCall selector: nonzero ⇒ altered view (steer onto the SYSCALL path).
    mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &1u32.to_le_bytes())?;
    Ok(())
}

/// Write one `KSYSTEM_TIME` triple (LowPart, High1Time, High2Time) so a guest
/// that reads the halves separately and re-checks `High2Time` sees a consistent
/// value. `poke` bypasses the page's guest-READ-only permission.
fn write_ksystem_time(mem: &mut VirtualMemory, off: u64, val: u64) -> Result<()> {
    let low = (val & 0xFFFF_FFFF) as u32;
    let high = (val >> 32) as u32;
    mem.poke(KUSER_SHARED_DATA_BASE + off, &low.to_le_bytes())?;
    mem.poke(KUSER_SHARED_DATA_BASE + off + 4, &high.to_le_bytes())?; // High1Time
    mem.poke(KUSER_SHARED_DATA_BASE + off + 8, &high.to_le_bytes()) // High2Time
}

/// Drive `KUSER_SHARED_DATA`'s three time fields forward from the virtual clock
/// (roadmap W9.6). Called at load and then every [`KUSER_REFRESH_INSTRUCTIONS`]
/// retired instructions by [`Process::run`].
///
/// * `SystemTime` — the virtual wall clock as a FILETIME.
/// * `InterruptTime` — 100-ns units since (virtual) boot, i.e. the monotonic
///   virtual time itself; the process start *is* the boot for our purposes.
/// * `TickCount` — the same time expressed in 15.625 ms clock interrupts, which
///   is the unit a guest converts with `TickCountMultiplier`.
fn refresh_kuser_time(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
    let Some(monotonic) = clock.monotonic_100ns() else { return Ok(()) };
    let Some(filetime) = clock.filetime() else { return Ok(()) };
    write_ksystem_time(mem, KUSER_SYSTEM_TIME, filetime)?;
    write_ksystem_time(mem, KUSER_INTERRUPT_TIME, monotonic)?;
    write_ksystem_time(mem, KUSER_TICK_COUNT, monotonic / KUSER_TICK_PERIOD_100NS)
}

/// An `EXEMU_*` boolean env opt-in: set and not `0`/empty.
fn env_opt_in(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !v.is_empty() && v != "0",
        Err(_) => false,
    }
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

/// Longest command line the `env` region can hold, in **UTF-8 bytes**. The
/// ASCII copy sits at `env_base` with 0x400 bytes to itself and the UTF-16 copy
/// at `env_base+0x400` with the remaining 0xC00 of the 0x1000-byte region.
/// Bounding the UTF-8 length bounds both: the ASCII copy is exactly that many
/// bytes plus a NUL (≤ 0x400), and a string's UTF-16 encoding is never more than
/// twice its UTF-8 length (≤ 0x7E0 + 2 ≤ 0xC00).
const CMDLINE_MAX_BYTES: usize = 0x3F0;

/// Clamp a command line to what the `env` region can hold, on a character
/// boundary. A parent-supplied command line (roadmap W3.5) is arbitrary guest
/// data; truncating it loses arguments, which is visible and debuggable, where
/// overrunning the region would silently corrupt whatever is mapped after it.
fn truncate_cmdline(mut cmdline: String) -> String {
    if cmdline.len() > CMDLINE_MAX_BYTES {
        let mut end = CMDLINE_MAX_BYTES;
        while end > 0 && !cmdline.is_char_boundary(end) {
            end -= 1;
        }
        cmdline.truncate(end);
    }
    cmdline
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
        map_kuser_shared_data(&mut mem, &GuestClock::host()).expect("map KUSER_SHARED_DATA");

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

        // TickCountMultiplier is the real Windows constant on BOTH clock paths —
        // 0 would make a guest's inline GetTickCount compute 0 forever.
        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER)
                .expect("read TickCountMultiplier"),
            KUSER_TICK_COUNT_MULTIPLIER_VALUE
        );
    }

    /// `KUSER_SHARED_DATA` is the one time source with no call to intercept —
    /// the guest reads it with a plain load. Under the virtual clock (roadmap
    /// W9.6) it must therefore be *written* from the instruction counter, both
    /// at load and as the run proceeds, and never from the host.
    #[test]
    fn kuser_time_fields_track_the_virtual_clock() {
        let read_ksystem_time = |mem: &VirtualMemory, off: u64| -> u64 {
            let lo = mem.read_u32(KUSER_SHARED_DATA_BASE + off).unwrap() as u64;
            let hi = mem.read_u32(KUSER_SHARED_DATA_BASE + off + 4).unwrap() as u64;
            (hi << 32) | lo
        };

        let clock = GuestClock::virtualized();
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem, &clock).expect("map KUSER_SHARED_DATA");

        // At instruction 0 the machine has just booted: no uptime, and a wall
        // clock sitting exactly on the fixed epoch.
        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 0);
        assert_eq!(read_ksystem_time(&mem, KUSER_TICK_COUNT), 0);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME,
            "the wall clock starts at the fixed virtual epoch, not at the host's now"
        );

        // Retire one virtual second (10M instructions) and refresh.
        for _ in 0..exemu_core::VIRTUAL_INSTRUCTIONS_PER_SECOND {
            clock.retire_one();
        }
        refresh_kuser_time(&mut mem, &clock).expect("refresh");
        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 10_000_000);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME + 10_000_000
        );
        // TickCount counts 15.625 ms clock interrupts, so one second is 64 of
        // them — and `ms = TickCount * TickCountMultiplier >> 24` recovers 1000.
        let ticks = read_ksystem_time(&mem, KUSER_TICK_COUNT);
        assert_eq!(ticks, 64);
        let ms = (ticks * u64::from(KUSER_TICK_COUNT_MULTIPLIER_VALUE)) >> 24;
        assert_eq!(ms, 1_000, "the guest's own tick→ms conversion agrees");
    }

    /// A parent-supplied command line (roadmap W3.5) is arbitrary guest data, so
    /// it is clamped to what the `env` region can hold — on a character boundary,
    /// and by **bytes**, because the ASCII copy is UTF-8 and a multi-byte
    /// character would otherwise let a "short enough" string overrun the region.
    #[test]
    fn a_long_command_line_is_clamped_to_the_env_region() {
        assert_eq!(truncate_cmdline("short".into()), "short");

        let long = "a".repeat(CMDLINE_MAX_BYTES * 3);
        let cut = truncate_cmdline(long);
        assert_eq!(cut.len(), CMDLINE_MAX_BYTES);

        // Multi-byte characters: the cut lands on a boundary and never exceeds
        // the byte budget, so both the UTF-8 and UTF-16 copies stay in region.
        let wide = "é".repeat(CMDLINE_MAX_BYTES); // 2 bytes each
        let cut = truncate_cmdline(wide);
        assert!(cut.len() <= CMDLINE_MAX_BYTES, "{} bytes", cut.len());
        assert!(cut.chars().all(|c| c == 'é'), "cut on a character boundary");
        // The UTF-16 copy has 0xC00 bytes; twice the UTF-8 bound fits.
        let utf16_bytes = cut.encode_utf16().count() * 2 + 2;
        assert!(utf16_bytes <= 0xC00, "{utf16_bytes} UTF-16 bytes");
        // …and the ASCII copy has 0x400, which must hold the bytes *and* a NUL.
        assert!(cut.len() < 0x400, "{} bytes + NUL", cut.len());
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
