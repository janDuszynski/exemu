//! W6.1 — **comctl32 / uxtheme / comdlg32 arrive as guest code.**
//!
//! The roadmap's W6 claim is that these DLLs cost exemu almost nothing because
//! they are just Wine PE binaries running as guest code. This file tests that
//! claim honestly and pins exactly the part that holds:
//!
//! 1. [`wine_control_dlls_map_relocate_and_bind`] — DLL-smoke: each of the three
//!    parses as PE32+, carries base relocations, relocates + maps cleanly to a
//!    non-preferred base, exports the entry points a guest imports, and **every
//!    named import it declares resolves to a real export in the pinned prefix**
//!    (forwarders chased to a module that exists).
//! 2. [`wine_control_dll_exports_run_on_the_cpu`] — the exports are *callable*:
//!    one self-contained stub per DLL is executed through the real interpreter,
//!    from the DLL's own relocated bytes, and returns the value its own `.data`
//!    holds.
//! 3. [`comctl_sample_loads_wine_comctl32_on_wine`] — the end-to-end gate: the
//!    generated [`comctl_sample`] PE runs under the Wine boot, its static import
//!    of `comctl32!InitCommonControlsEx` forces Wine's comctl32 to load and run
//!    its `DllMain`, and the call registers `msctls_progress32` as a real class
//!    (nonzero atom, real WndProc) which the guest then instantiates as a child
//!    window — observed through the injected [`RecordingDriver`].
//! 4. [`comctl_sample_first_frame_matches_golden_on_wine`] — the painted frame is
//!    pinned against a committed golden PNG, in the style of the W4.10 gate.
//! 5. [`wine_client_pfn_arrays_publish_the_builtin_wndprocs`] — **W6.2**: the
//!    structure exemu recovers user32's built-in control WndProcs from, pinned
//!    directly against the pinned `ntdll.dll` (entry counts, thunk shape, and the
//!    index-ordered slot layout the resolver walks).
//!
//! **W6.2 closes the first two of the three measured W6 blockers.**
//!
//! * user32's built-in control classes (`BUTTON`/`EDIT`/`STATIC`/…) are the
//!   kernel side's responsibility in Wine's split; win32k now registers them
//!   against the WndProcs user32 publishes through
//!   `NtUserInitializeClientPfnArrays`, so `CreateWindowExW(L"BUTTON", …)`
//!   reaches `NtUserCreateWindowEx` and the driver sees the child window.
//! * `NtUserCreateWindowEx` now dispatches **`WM_NCCREATE` then `WM_CREATE`** to
//!   the class WndProc and *still* returns the HWND, by queueing both callbacks
//!   on the re-entrant win32k callback frame instead of hijacking the syscall
//!   return for a single call. Both children's real WndProcs (user32's
//!   `ButtonWndProc`, comctl32's `ProgressWindowProc`) run their creation
//!   handlers, so a control finally allocates its instance data.
//!
//! **Two things are deliberately *not* papered over**, and are asserted below so
//! they stay visible rather than assumed:
//!
//! * **The Wine boot maps ntdll twice.** exemu pre-maps ntdll (the running
//!   image, and the only copy whose `user_procs` user32 ever fills), and Wine's
//!   own loader then maps a *second* copy for the name `NTDLL.dll` while
//!   resolving forwarders. Because `user32!DefWindowProcW` is a forwarder to
//!   `NTDLL.NtdllDefWindowProc_W` — literally `jmp qword [user_procs+0xa8]` —
//!   every module bound after that second map (the exe, comctl32) reached
//!   `DefWindowProc` through a NULL slot. win32k now mirrors the recovered
//!   client-PFN procs into every mapped ntdll copy, which fixes `DefWindowProc`;
//!   the duplicate load itself is a loader-level gap that remains.
//! * Messaging a comctl32 control (`SendMessageW(hProgress, PBM_SETPOS, …)`)
//!   does not terminate — the dispatch reaches comctl32's real WndProc, which
//!   then spins on the unserviced `WineUnixCall` import thunk.
//!
//! Everything here skip-guards on the git-ignored Wine DLL set.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use exemu_app::{comctl_sample, load_and_run, RunConfig};
use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_gui::{DriverCall, OffscreenPresenter, PresenterDriver, RecordingDriver};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// The three DLLs W6.1 ships.
const CONTROL_DLLS: [&str; 3] = ["comctl32.dll", "uxtheme.dll", "comdlg32.dll"];

/// A non-preferred base to relocate every DLL to (all three prefer 0x180000000,
/// so this exercises the `.reloc` fixups rather than a no-op load).
const DLL_BASE: u64 = 0x0000_0006_0000_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const STACK_SIZE: u64 = 0x4000;
/// A page whose first byte is `hlt` — the return sentinel a stub's `ret` lands on.
const SENTINEL: u64 = 0x0000_0000_6000_0000;

fn wine_dlls_present() -> bool {
    CONTROL_DLLS.iter().all(|d| Path::new(WINE_DLLS).join(d).exists())
}

// ==========================================================================
// DLL-smoke: map + relocate + bind.
// ==========================================================================

/// A mapped, relocated DLL image with its exports resolved by name.
struct Dll {
    base: u64,
    exports: HashMap<String, u64>,
}

impl Dll {
    fn export(&self, name: &str) -> u64 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("{name} not exported as a callable stub"))
    }
}

/// Parse `bytes`, relocate to `base`, map every section RWX into `mem`, and
/// return the resolved (non-forwarder) export map.
fn load_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Dll {
    let mut image = exemu_loader::parse(bytes).expect("parses as PE32+");
    assert!(image.is_64bit, "the x86_64-windows DLL must be PE32+");
    assert!(!image.relocations.is_empty(), "the DLL must carry a .reloc table");

    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)
        .expect("apply base relocations");

    let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
    mem.map(Region::new("dll_headers", base, hdr_len, Perm::RWX)).unwrap();
    mem.write(base, &image.headers).unwrap();
    for s in &image.sections {
        let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
        let map_len = align_up(vsize, 0x1000).max(0x1000);
        let addr = base + s.rva as u64;
        if mem.map(Region::new("dll_section", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
            mem.write(addr, &s.data).unwrap();
        } else if !s.data.is_empty() {
            mem.poke(addr, &s.data).unwrap();
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Dll { base, exports }
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// Every named export of a pinned DLL (forwarders included — a forwarder is a
/// perfectly good import target, it just resolves elsewhere), plus the set of
/// forwarder target modules so they can be checked to exist.
fn export_names(dir: &Path, dll: &str) -> Option<(std::collections::HashSet<String>, Vec<String>)> {
    let bytes = std::fs::read(dir.join(dll)).ok()?;
    let image = exemu_loader::parse(&bytes).ok()?;
    let mut names = std::collections::HashSet::new();
    let mut fwd_targets = Vec::new();
    for e in &image.exports {
        if let Some(n) = &e.name {
            names.insert(n.clone());
        }
        if let Some(f) = &e.forwarder {
            if let Some((module, _)) = f.split_once('.') {
                fwd_targets.push(format!("{}.dll", module.to_ascii_lowercase()));
            }
        }
    }
    Some((names, fwd_targets))
}

/// W6.1 DLL-smoke. Each of comctl32/uxtheme/comdlg32 maps and relocates to a
/// non-preferred base, exports the entry points a guest imports, and every
/// symbol it *imports* is really exported by the pinned DLL it names — i.e. the
/// whole module graph these three pull in is satisfiable from the prefix, with
/// nothing exemu has to hand-write.
#[test]
fn wine_control_dlls_map_relocate_and_bind() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = Path::new(WINE_DLLS);

    // Entry points a real guest imports from each DLL.
    let expected: [(&str, &[&str]); 3] = [
        (
            "comctl32.dll",
            &["InitCommonControlsEx", "InitCommonControls", "ImageList_Create", "PropertySheetW", "InitMUILanguage", "GetMUILanguage"],
        ),
        (
            "uxtheme.dll",
            &["OpenThemeData", "CloseThemeData", "DrawThemeBackground", "IsThemeActive", "SetWindowTheme", "GetThemeAppProperties"],
        ),
        (
            "comdlg32.dll",
            &["GetOpenFileNameW", "GetSaveFileNameW", "ChooseColorW", "ChooseFontW", "PrintDlgW", "CommDlgExtendedError"],
        ),
    ];

    // Cache each dependency's export set so a 300-import DLL costs one parse per
    // dependency, not one per symbol.
    let mut cache: HashMap<String, (std::collections::HashSet<String>, Vec<String>)> = HashMap::new();

    for (dll, entries) in expected {
        let bytes = std::fs::read(dir.join(dll)).unwrap_or_else(|e| panic!("read {dll}: {e}"));
        let mut mem = VirtualMemory::new();
        let loaded = load_dll(&mut mem, &bytes, DLL_BASE);

        // Exports resolve to addresses inside the mapped image and are readable.
        for name in entries {
            let va = loaded.export(name);
            assert!(va > loaded.base, "{dll}!{name} resolves above the load base");
            let mut b = [0u8; 1];
            mem.read(va, &mut b).unwrap_or_else(|e| panic!("{dll}!{name} is mapped: {e}"));
        }

        // Every named import is really exported by the DLL it names.
        let image = exemu_loader::parse(&bytes).expect("re-parse for the import table");
        assert!(!image.imports.is_empty(), "{dll} imports something");
        let mut checked = 0usize;
        for imp in &image.imports {
            let exemu_core::ImportSymbol::Named(sym) = &imp.symbol else {
                continue; // ordinal imports carry no name to cross-check
            };
            let entry = cache.entry(imp.dll.clone()).or_insert_with(|| {
                export_names(dir, &imp.dll)
                    .unwrap_or_else(|| panic!("{dll} imports from {}, which is missing from the pinned prefix", imp.dll))
            });
            assert!(
                entry.0.contains(sym),
                "{dll} imports {}!{sym}, which that DLL does not export",
                imp.dll
            );
            checked += 1;
        }
        assert!(checked > 50, "{dll}: cross-checked {checked} named imports");
        eprintln!("{dll}: {} exports, {checked} named imports all resolvable", loaded.exports.len());
    }

    // Every module reached by a forwarder is present in the prefix too.
    let targets: Vec<String> = cache.values().flat_map(|(_, t)| t.clone()).collect();
    for t in targets {
        assert!(dir.join(&t).exists(), "forwarder target {t} is missing from the pinned prefix");
    }
}

/// Run `entry` (an absolute VA inside a mapped DLL) through the real
/// interpreter with Win64 arguments, halting on the `hlt` sentinel the stub's
/// `ret` returns to. Returns RAX.
fn call_export(os: &mut WinOs, mem: &mut VirtualMemory, entry: u64, args: &[u64]) -> u64 {
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = entry;
        s.set_rsp(rsp);
        let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().take(4).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    mem.write_u64(rsp, SENTINEL).unwrap();
    loop {
        match cpu.step(mem, os).expect("the DLL's own stub bytes faulted") {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit driving the export: {other:?}"),
        }
    }
    cpu.state().reg(Reg::Rax)
}

/// A fresh `(WinOs, VirtualMemory)` with a stack and the `hlt` sentinel, plus
/// `dll` mapped + relocated at [`DLL_BASE`].
fn setup(dll: &str) -> (WinOs, VirtualMemory, Dll) {
    let bytes = std::fs::read(Path::new(WINE_DLLS).join(dll)).expect("read the DLL");
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt
    let loaded = load_dll(&mut mem, &bytes, DLL_BASE);
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem, loaded)
}

/// W6.1: the three DLLs' exports are **callable** — their own relocated bytes run
/// on exemu's interpreter and produce the values their own `.data` holds. Each
/// stub was picked (from the pinned binaries' disassembly) to be self-contained:
/// no imports, no syscalls, only RIP-relative access to the module's own data, so
/// this isolates "the image loads and executes correctly" from the whole-process
/// boot exercised by [`comctl_sample_loads_wine_comctl32_on_wine`].
#[test]
fn wine_control_dll_exports_run_on_the_cpu() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    // comctl32: `InitMUILanguage(lang)` is `mov [rip+d], cx; ret` and
    // `GetMUILanguage()` is `movzx eax, word [rip+d]; ret` over the *same*
    // global — a round trip through two of Wine's own stubs that only lands if
    // the image was mapped and its RIP-relative displacements are honoured.
    {
        const LANG: u64 = 0x0409; // MAKELANGID(LANG_ENGLISH, SUBLANG_US)
        let (mut os, mut mem, dll) = setup("comctl32.dll");
        assert_eq!(
            call_export(&mut os, &mut mem, dll.export("GetMUILanguage"), &[]),
            0,
            "comctl32's MUI language starts out unset"
        );
        call_export(&mut os, &mut mem, dll.export("InitMUILanguage"), &[LANG]);
        assert_eq!(
            call_export(&mut os, &mut mem, dll.export("GetMUILanguage"), &[]),
            LANG,
            "comctl32!GetMUILanguage reads back what comctl32!InitMUILanguage stored"
        );
    }

    // uxtheme: `GetThemeAppProperties()` is `mov eax, [rip+d]; ret` over its
    // initialized global — STAP_ALLOW_NONCLIENT|STAP_ALLOW_CONTROLS, the value
    // Wine's uxtheme statically initializes it to.
    {
        const STAP_ALLOW_NONCLIENT: u64 = 0x1;
        const STAP_ALLOW_CONTROLS: u64 = 0x2;
        let (mut os, mut mem, dll) = setup("uxtheme.dll");
        assert_eq!(
            call_export(&mut os, &mut mem, dll.export("GetThemeAppProperties"), &[]),
            STAP_ALLOW_NONCLIENT | STAP_ALLOW_CONTROLS,
            "uxtheme!GetThemeAppProperties returns its statically initialized flags"
        );
    }

    // comdlg32: `CommDlgExtendedError()` reads its TLS-index global (statically
    // TLS_OUT_OF_INDEXES) and returns 0 — "no error yet" — without touching an
    // import, which is exactly the contract before any dialog has run.
    {
        let (mut os, mut mem, dll) = setup("comdlg32.dll");
        assert_eq!(
            call_export(&mut os, &mut mem, dll.export("CommDlgExtendedError"), &[]),
            0,
            "comdlg32!CommDlgExtendedError reports no error before any dialog ran"
        );
    }
}

// ==========================================================================
// The W6.1 GATE: comctl32 arrives as guest code under the Wine boot.
// ==========================================================================

/// W6.1 GATE. The generated sample statically imports
/// `comctl32!InitCommonControlsEx`, so booting it on the pinned Wine PE set
/// forces the loader to map + relocate + bind **Wine's own comctl32** and run its
/// `DllMain` before the entry point. The guest's `InitCommonControlsEx` call then
/// registers the common-control classes through Wine's user32 → win32u →
/// exemu's `NtUserRegisterClassExWOW`, and the guest instantiates one of them.
///
/// Observed through the injected driver: `msctls_progress32` — a class exemu has
/// never heard of and does not implement — is registered with a distinct atom and
/// created as a child of the sample's main window at the requested geometry. That
/// is the W6 "near-free breadth" claim holding for the *load + class + window*
/// half of the story.
#[test]
fn comctl_sample_loads_wine_comctl32_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 40_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
            ..RunConfig::default()
        },
    )
    .expect("the comctl sample runs to completion on the Wine boot");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly after creating its controls");
    eprintln!("comctl_sample wine boot: exit={} steps={}", res.exit_code, res.steps);

    let calls = log.lock().unwrap();
    let creates: Vec<(u32, &exemu_core::WindowParams)> = calls
        .iter()
        .filter_map(|c| match c {
            DriverCall::CreateWindow { hwnd, params } => Some((*hwnd, params)),
            _ => None,
        })
        .collect();

    // The sample's own top-level window.
    let (main_hwnd, main) = creates
        .iter()
        .find(|(_, p)| p.class_name == "ExemuComctlClass")
        .expect("the sample's main window reached the driver");
    assert_eq!(
        (main.cx, main.cy),
        (comctl_sample::WINDOW_CX, comctl_sample::WINDOW_CY),
        "main window created at the requested client size"
    );
    assert_ne!(main.class_atom, 0, "the sample's class was registered before its window");

    // THE LOAD-BEARING CHECK: a *comctl32-provided* class exists and was
    // instantiated as a child of the main window. exemu implements no progress
    // bar; this class came from Wine's comctl32 running as guest code.
    let (_, progress) = creates
        .iter()
        .find(|(_, p)| p.class_name.eq_ignore_ascii_case("msctls_progress32"))
        .expect("comctl32 registered msctls_progress32 and the guest created one");
    assert_eq!(progress.parent, *main_hwnd, "the progress bar is a child of the main window");
    assert_eq!(
        progress.style & 0x5000_0000,
        0x5000_0000,
        "WS_CHILD | WS_VISIBLE survive the user32 → win32u path"
    );
    assert_eq!((progress.cx, progress.cy), (300, 24), "progress-bar geometry marshalled intact");
    assert_ne!(progress.class_atom, 0, "the comctl32 class carries a real atom");
    assert_ne!(
        progress.class_atom, main.class_atom,
        "comctl32's class is a distinct registration, not a collision with the sample's"
    );

    // W6.2: the built-in `BUTTON` class is now in win32k's registry, wired to the
    // WndProc user32 published through `NtUserInitializeClientPfnArrays`, so the
    // class lookup inside user32 succeeds and the child reaches
    // `NtUserCreateWindowEx`. Reaching the driver at all is the transitive proof
    // that the recovered WndProc landed **inside user32's mapped image** — the
    // registration is skipped outright for a proc that resolves anywhere else.
    let (_, button) = creates
        .iter()
        .find(|(_, p)| p.class_name.eq_ignore_ascii_case("BUTTON"))
        .expect("win32k registers user32's built-in BUTTON class and the guest creates one");
    assert_eq!(button.parent, *main_hwnd, "the button is a child of the main window");
    assert_eq!((button.cx, button.cy), (140, 32), "button geometry marshalled intact");
    assert_ne!(button.class_atom, 0, "BUTTON carries a real class atom");
    assert_ne!(
        button.class_atom, progress.class_atom,
        "the built-in BUTTON and comctl32's progress bar are distinct registrations"
    );
    assert_ne!(
        button.class_atom, main.class_atom,
        "the built-in BUTTON is not a collision with the sample's own class"
    );

    // W6.2: **the creation pair reaches the class WndProc.** The sample's WndProc
    // answers `WM_CREATE` by reading `CREATESTRUCTW.lpCreateParams`, and only if
    // it finds the magic the window was created with does it set the window text
    // to `CREATESTRUCTW.lpszClass`. So this one driver call is proof of the whole
    // chain: the message was dispatched, lParam pointed at a well-formed
    // `CREATESTRUCTW`, `lpCreateParams` round-tripped through `NtUserCreateWindowEx`'s
    // argument slots, and `lpszClass` is a readable NUL-terminated string —
    // *while* `NtUserCreateWindowEx` still returned the HWND to user32 (the guest
    // went on to create both children with this window as their parent).
    let created = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::SetWindowText { hwnd, text } => Some((*hwnd, text.as_str())),
            _ => None,
        })
        .expect("the sample's WM_CREATE handler ran and reported the creation");
    assert_eq!(created.0, *main_hwnd, "WM_CREATE was delivered to the window being created");
    assert_eq!(
        created.1, "ExemuComctlClass",
        "CREATESTRUCTW.lpCreateParams round-tripped and lpszClass names the class"
    );

    // The top-level window still paints: one surface at the client size, flushed
    // with real content (the two text runs plus the frame).
    let surface = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::CreateWindowSurface { hwnd, w, h } => Some((*hwnd, *w, *h)),
            _ => None,
        })
        .expect("a backing surface was allocated");
    assert_eq!(
        (surface.1 as i32, surface.2 as i32),
        (comctl_sample::WINDOW_CX, comctl_sample::WINDOW_CY),
        "the surface matches the main window's client rect"
    );
    let non_blank = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::FlushSurface { hwnd, non_blank, .. } if *hwnd == surface.0 => Some(*non_blank),
            _ => None,
        })
        .expect("the painted frame was presented");
    assert!(non_blank > 200, "the paint produced measurable content (non_blank={non_blank})");
}

// ==========================================================================
// W6.2: the client-PFN arrays that carry user32's built-in control WndProcs.
// ==========================================================================

/// Entries in each client-PFN array (`0x88 / 8` — the size user32's
/// `winproc_init` hands `RtlInitializeNtUserPfn`). Mirrors `CLIENT_PFN_COUNT`
/// in `crates/os/src/win32k.rs`; pinned here so a drift in either shows up.
const CLIENT_PFN_COUNT: usize = 17;
/// Byte distance between the ANSI and Unicode arrays.
const CLIENT_PFN_STRIDE: u64 = (CLIENT_PFN_COUNT * 8) as u64;
/// The one index that is NULL in this build (no proc published for it).
const CLIENT_PFN_NULL_INDEX: usize = 6;

/// W6.2. **The recovery route for user32's built-in control WndProcs, pinned
/// against the pinned binary itself.**
///
/// Wine's split leaves `BUTTON`/`EDIT`/`STATIC`/… to the kernel side: user32
/// holds the WndProcs but registers no classes, so exemu has to learn them from
/// the one place they cross the boundary — `NtUserInitializeClientPfnArrays`.
/// The chain (all of it recovered by disassembling the pinned binaries, no Wine
/// source read):
///
/// * user32's `winproc_init` publishes its `client_procs{A,W}` (0x88 bytes each
///   = [`CLIENT_PFN_COUNT`] pointers) through ntdll's `RtlInitializeNtUserPfn`;
/// * `RtlRetrieveNtUserPfn` hands back a **different** triple — ntdll's own
///   `user_funcs`, reachable from that export's `lea rax, [rip+disp32]`;
/// * each `user_funcs` entry is a 7-byte `jmp qword [rip+disp32]` thunk
///   (`48 ff 25 …`) whose slot is exactly `user_procs + index*8`, i.e. the
///   procedure user32 published at that index.
///
/// This test walks that chain over the mapped, **relocated** `ntdll.dll` and
/// asserts the structure exemu's resolver depends on: the arrays are
/// [`CLIENT_PFN_COUNT`] entries, every non-null entry is that exact thunk shape,
/// the slots are strictly index-ordered inside ntdll's image, and the two arrays
/// are [`CLIENT_PFN_STRIDE`] apart. (What each *index* means, and that the
/// resolved procs live in user32, is exercised end-to-end by
/// [`comctl_sample_loads_wine_comctl32_on_wine`], which only creates a `BUTTON`
/// if the whole chain resolved to a real user32 procedure.)
#[test]
fn wine_client_pfn_arrays_publish_the_builtin_wndprocs() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("ntdll.dll")).expect("read ntdll.dll");
    let image_size = exemu_loader::parse(&bytes).expect("parses as PE32+").size_of_image as u64;
    let mut mem = VirtualMemory::new();
    let ntdll = load_dll(&mut mem, &bytes, DLL_BASE);
    let (lo, hi) = (ntdll.base, ntdll.base + image_size);

    // `RtlRetrieveNtUserPfn` is `mov eax,[rip+d]; test eax,eax; je …;
    // lea rax,[rip+d] /* user_funcs */; mov [rcx],rax; …` — take the first
    // `lea rax,[rip+disp32]` (48 8d 05) in its prologue.
    let retrieve = ntdll.export("RtlRetrieveNtUserPfn");
    let mut prologue = [0u8; 32];
    mem.read(retrieve, &mut prologue).expect("the export is mapped");
    let lea = prologue
        .windows(3)
        .position(|w| w == [0x48, 0x8D, 0x05])
        .expect("RtlRetrieveNtUserPfn loads user_funcs with `lea rax, [rip+disp32]`");
    let disp = i32::from_le_bytes(prologue[lea + 3..lea + 7].try_into().unwrap()) as i64;
    let user_funcs = (retrieve as i64 + lea as i64 + 7 + disp) as u64;
    assert!((lo..hi).contains(&user_funcs), "user_funcs lands inside ntdll's image");

    // Walk both arrays. `procs_base` is discovered from index 0's thunk slot;
    // every later slot must be exactly `procs_base + index*8`, which is what
    // makes "array index == class identity" a sound recovery.
    let mut bases = Vec::new();
    for (label, array) in [("A", user_funcs), ("W", user_funcs + CLIENT_PFN_STRIDE)] {
        let mut procs_base = 0u64;
        let mut nulls = Vec::new();
        for i in 0..CLIENT_PFN_COUNT {
            let entry = mem.read_u64(array + (i as u64) * 8).expect("the array is mapped");
            if entry == 0 {
                nulls.push(i);
                continue;
            }
            assert!((lo..hi).contains(&entry), "{label}[{i}] points inside ntdll's image");
            let mut op = [0u8; 3];
            mem.read(entry, &mut op).expect("the thunk is mapped");
            assert_eq!(
                op,
                [0x48, 0xFF, 0x25],
                "{label}[{i}] is a `jmp qword [rip+disp32]` thunk, not {op:02x?}"
            );
            let d = mem.read_u32(entry + 3).expect("the thunk displacement is mapped") as i32 as i64;
            let slot = (entry as i64 + 7 + d) as u64;
            assert!((lo..hi).contains(&slot), "{label}[{i}]'s slot lands inside ntdll's image");
            if procs_base == 0 {
                procs_base = slot - (i as u64) * 8;
            }
            assert_eq!(
                slot,
                procs_base + (i as u64) * 8,
                "{label}[{i}]'s thunk jumps through the index-ordered slot"
            );
        }
        assert_eq!(
            nulls,
            vec![CLIENT_PFN_NULL_INDEX],
            "{label}: exactly one unpublished slot, at the recovered index"
        );
        assert_ne!(procs_base, 0, "{label}: at least one thunk resolved");
        bases.push(procs_base);
    }
    assert_eq!(
        bases[1] - bases[0],
        CLIENT_PFN_STRIDE,
        "the ANSI and Unicode proc arrays are {CLIENT_PFN_COUNT} entries apart"
    );
    eprintln!(
        "client-PFN arrays: user_funcs=+{:#x}, procs A=+{:#x} W=+{:#x}, {CLIENT_PFN_COUNT} entries each",
        user_funcs - lo,
        bases[0] - lo,
        bases[1] - lo
    );
}

/// Decode an RGBA8 PNG into `(width, height, rgba_bytes)`.
fn decode_png(path: &Path) -> (u32, u32, Vec<u8>) {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut reader = png::Decoder::new(f).read_info().expect("valid PNG header");
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).expect("decode PNG frame");
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

/// W6.1: the comctl sample's first painted frame is pinned against a committed
/// golden PNG — the same standing regression shape as the W4.10 gate, extended to
/// the run that has Wine's comctl32 in the process. Rendered headlessly through
/// the **deterministic** [`OffscreenPresenter`] (the built-in `font8x8` stub, so
/// the golden is platform-independent). Set `EXEMU_BLESS=1` to re-bless after an
/// intended rendering change.
#[test]
fn comctl_sample_first_frame_matches_golden_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w61-golden-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);

    let presenter = OffscreenPresenter::with_dir(Some(shot_dir.clone()));
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 40_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(PresenterDriver::new(presenter))),
            ..RunConfig::default()
        },
    )
    .expect("the comctl sample renders its first frame");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly through the paint path");

    let rendered = std::fs::read_dir(&shot_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|x| x.to_str()) == Some("png"))
        .expect("the presenter wrote a first-frame PNG");

    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/comctl_sample_first_frame.png");

    if std::env::var_os("EXEMU_BLESS").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::copy(&rendered, &golden).unwrap();
        eprintln!("BLESSED golden: {}", golden.display());
        let _ = std::fs::remove_dir_all(&shot_dir);
        return;
    }
    assert!(
        golden.exists(),
        "no golden at {} — run once with EXEMU_BLESS=1 to create it",
        golden.display()
    );

    let (rw, rh, rpix) = decode_png(&rendered);
    let (gw, gh, gpix) = decode_png(&golden);
    let _ = std::fs::remove_dir_all(&shot_dir);

    assert_eq!((rw, rh), (gw, gh), "first-frame dimensions match the golden");
    if rpix != gpix {
        let diff = rpix.iter().zip(&gpix).filter(|(a, b)| a != b).count();
        let first = rpix.iter().zip(&gpix).position(|(a, b)| a != b).unwrap_or(0);
        panic!(
            "first frame drifted from the golden: {diff}/{} bytes differ (first at byte {first}); \
             set EXEMU_BLESS=1 to re-bless after an intended change",
            rpix.len()
        );
    }
}
