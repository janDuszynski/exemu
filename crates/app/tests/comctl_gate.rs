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
//! 6. [`comctl_children_paint_into_the_parent_surface_on_wine`] — **W4.8**: the
//!    controls are *painted*, by their own code, into the top-level window's
//!    surface.
//! 7. [`comctl_painted_controls_match_golden_on_wine`] — that frame pinned
//!    pixel-for-pixel.
//! 8. [`messaging_a_comctl32_control_terminates_on_wine`] — `SendMessageW` to a
//!    comctl32 control returns.
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
//! **W4.8 closes the third, and the child-window painting gap with it.**
//!
//! * `SendMessageW(hProgress, PBM_SETRANGE/PBM_SETPOS, …)` now returns. The
//!   recorded diagnosis — "it spins on an unserviced `WineUnixCall` import
//!   thunk" — was **wrong, and falsifiable straight from the pinned binary**:
//!   `comctl32.dll` imports no `__wine_unix_call` and no `NtQueryVirtualMemory`
//!   at all, so it has no unix half to pair (that shape is real for `ws2_32`,
//!   not here). The actual cause was the NULL `DefWindowProcW` forwarder slot,
//!   fixed in W6.2.
//! * Child windows paint. win32k gives a backing surface to the **top-level
//!   ancestor only** and binds a child's DC to it with an origin offset and a
//!   clip rect, which is what Wine's gdi32 expects — it applies no coordinate
//!   transform client-side at all.
//!
//! **One thing is deliberately *not* papered over**, and stays recorded here:
//! **the Wine boot maps ntdll twice.** exemu pre-maps ntdll (the running image,
//! and the only copy whose `user_procs` user32 ever fills), and Wine's own loader
//! then maps a *second* copy for the name `NTDLL.dll` while resolving
//! forwarders. Because `user32!DefWindowProcW` is a forwarder to
//! `NTDLL.NtdllDefWindowProc_W` — literally `jmp qword [user_procs+0xa8]` —
//! every module bound after that second map (the exe, comctl32) reached
//! `DefWindowProc` through a NULL slot. win32k mirrors the recovered client-PFN
//! procs into every mapped ntdll copy, which fixes `DefWindowProc`; the
//! duplicate load itself is a loader-level gap that remains.
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

// ==========================================================================
// W4.8: the two W6-measured gaps, closed and pinned.
// ==========================================================================

/// A [`RunConfig`] whose message pump is **deterministic and headless**.
///
/// `NtUserGetMessage` only runs its real pump when an input channel is attached
/// — without one it answers `WM_QUIT` at once and no `WM_PAINT` is ever
/// synthesized. Attaching a channel whose sender is dropped immediately gives
/// the pump exactly what a golden gate needs: it drains input (a disconnected
/// host counts as "close", so a `WM_QUIT` is armed), synthesizes one `WM_PAINT`
/// per window still owing one — parent first, then each child — and only then
/// delivers the `WM_QUIT` that ends the loop. No threads, no timing, no AppKit.
fn pumped_run_config(driver: Box<dyn exemu_core::UserDriver>) -> RunConfig {
    input_run_config(driver, Vec::new())
}

/// The same, with `events` queued on the channel ahead of the run. The pump
/// drains them into its raw-input queue, delivers every message the windows
/// already owe (the `WM_PAINT`s), then routes the events — and only once both
/// are exhausted does the dropped sender become the `WM_QUIT` that ends the
/// loop. So a click injected here lands **after** the controls have painted
/// themselves, exactly as a click on a live window would.
fn input_run_config(
    driver: Box<dyn exemu_core::UserDriver>,
    events: Vec<exemu_core::InputEvent>,
) -> RunConfig {
    let (tx, rx) = std::sync::mpsc::channel::<exemu_core::InputEvent>();
    for ev in events {
        tx.send(ev).expect("the receiver is alive");
    }
    drop(tx);
    RunConfig {
        echo: false,
        max_steps: 60_000_000,
        wine_boot_dir: Some(WINE_DLLS.to_string()),
        driver: Some(driver),
        input: Some(rx),
        ..RunConfig::default()
    }
}

/// **W4.8 gate — Wine's own controls are PAINTED, not merely created.**
///
/// The W6.1 measurement recorded that child windows never paint: win32k gave a
/// backing surface to *top-level* windows only, so a control had nowhere to put
/// pixels and no `WM_PAINT` route. This test is the closed form of that gap.
///
/// With the pump running, each of the three windows is handed a `WM_PAINT`.
/// The two children are Wine's own code — user32's `ButtonWndProc` and
/// comctl32's `ProgressWindowProc` — and they paint through `BeginPaint` into a
/// DC that win32k binds to **the top-level window's** surface with the child's
/// origin and clip rect. The assertions read the presented frame back and look
/// for ink inside each control's rect: exemu draws nothing there itself, so any
/// non-background pixel in those rects came from Wine's control code.
#[test]
fn comctl_children_paint_into_the_parent_surface_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        pumped_run_config(Box::new(RecordingDriver::with_inner(
            Arc::clone(&log),
            Box::new(FrameCapture { frames: Arc::clone(&frames) }),
        ))),
    )
    .expect("the comctl sample runs its pump to completion on the Wine boot");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly through the message pump");
    eprintln!("comctl_sample pumped: exit={} steps={}", res.exit_code, res.steps);

    let calls = log.lock().unwrap();
    let hwnd_of = |class: &str| -> u32 {
        calls
            .iter()
            .find_map(|c| match c {
                DriverCall::CreateWindow { hwnd, params } if params.class_name.eq_ignore_ascii_case(class) => {
                    Some(*hwnd)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("no window of class {class} reached the driver"))
    };
    let main_hwnd = hwnd_of("ExemuComctlClass");

    // THE STRUCTURAL CLAIM: exactly one surface exists and it belongs to the
    // top-level window. A child getting its own surface would show up here.
    let surfaces: Vec<(u32, u32, u32)> = calls
        .iter()
        .filter_map(|c| match c {
            DriverCall::CreateWindowSurface { hwnd, w, h } => Some((*hwnd, *w, *h)),
            _ => None,
        })
        .collect();
    assert_eq!(
        surfaces.len(),
        1,
        "one surface for the whole window tree — children render into their ancestor's, \
         got {surfaces:?}"
    );
    assert_eq!(surfaces[0].0, main_hwnd, "the surface belongs to the top-level window");
    assert_eq!(
        (surfaces[0].1 as i32, surfaces[0].2 as i32),
        (comctl_sample::WINDOW_CX, comctl_sample::WINDOW_CY),
        "the one surface is the top-level client rect"
    );
    // Every presented frame is the parent's surface, children included.
    assert!(
        calls
            .iter()
            .filter(|c| matches!(c, DriverCall::FlushSurface { .. }))
            .all(|c| matches!(c, DriverCall::FlushSurface { hwnd, .. } if *hwnd == main_hwnd)),
        "a child presents its ancestor's composed surface, never one of its own"
    );
    drop(calls);

    // THE PIXEL CLAIM: read the last presented frame and require ink inside each
    // control's rect. The sample paints only its two text lines (y≈16 and y≈44)
    // and one frame rectangle (12,84)-(500,180); both control rects sit *below*
    // that frame, so nothing the sample itself draws can reach them.
    let frames = frames.lock().unwrap();
    let (pixels, w, h) = frames.last().expect("at least one frame was presented").clone();
    assert_eq!(
        (w as i32, h as i32),
        (comctl_sample::WINDOW_CX, comctl_sample::WINDOW_CY),
        "the presented frame is the top-level client rect"
    );

    for (label, rect) in [
        ("BUTTON", comctl_sample::BUTTON_RECT),
        ("msctls_progress32", comctl_sample::PROGRESS_RECT),
    ] {
        let ink = ink_in_rect(&pixels, w, h, rect);
        assert!(
            ink > 0,
            "{label} at {rect:?} is blank — Wine's control code drew nothing into the \
             parent surface (child windows are not painting)"
        );
        eprintln!("{label} rect {rect:?}: {ink} non-background pixels");
    }

    // The BUTTON drew its own **label**, not just its background. user32's
    // `ButtonWndProc` reads the window text through `NtUserInternalGetWindowText`,
    // measures it (`NtGdiGetTextExtentExW`) and draws it (`NtGdiExtTextOutW`) —
    // so black pixels strictly inside the button's border are glyphs. A blank
    // button would be a uniform fill with a frame and score zero here.
    let b = comctl_sample::BUTTON_RECT;
    let interior = [b[0] + 3, b[1] + 3, b[2] - 6, b[3] - 6];
    let glyphs = pixels_matching(&pixels, w, h, interior, |px| px[0] < 0x40 && px[1] < 0x40 && px[2] < 0x40);
    assert!(
        glyphs > 20,
        "the BUTTON's own label is missing — only {glyphs} dark pixels inside {interior:?}"
    );
    eprintln!("BUTTON label: {glyphs} glyph pixels inside {interior:?}");

    // The progress bar shows the **position the guest set**. It was told
    // `PBM_SETRANGE(0, 100)` then `PBM_SETPOS(60)`, so its filled part must cover
    // clearly more than a third and clearly less than all of the bar — a control
    // that ignored the message would be empty, and one that ignored the range
    // would be full.
    // Blue-dominant, whatever the exact shade: the bar's filled chunks are the
    // only blue thing on a white/grey frame. (`px` is BGRA, so `px[0]` is blue.)
    let p = comctl_sample::PROGRESS_RECT;
    let filled = pixels_matching(&pixels, w, h, p, |px| {
        px[0] as i32 > px[1] as i32 + 0x40 && px[0] as i32 > px[2] as i32 + 0x40
    });
    let total = (p[2] * p[3]) as f32;
    let frac = filled as f32 / total;
    assert!(
        (0.35..0.85).contains(&frac),
        "the progress bar is {:.0}% filled; it was set to {}% of its range",
        frac * 100.0,
        comctl_sample::PROGRESS_POS
    );
    eprintln!("progress bar: {filled} filled px ({:.0}% of the bar)", frac * 100.0);

    // And nothing leaked outside: the strip between the two controls belongs to
    // neither, so the clip rects held.
    let gap = [
        comctl_sample::BUTTON_RECT[0] + comctl_sample::BUTTON_RECT[2] + 2,
        comctl_sample::BUTTON_RECT[1],
        comctl_sample::PROGRESS_RECT[0] - comctl_sample::BUTTON_RECT[0] - comctl_sample::BUTTON_RECT[2] - 4,
        comctl_sample::BUTTON_RECT[3],
    ];
    assert_eq!(
        ink_in_rect(&pixels, w, h, gap),
        0,
        "a control painted outside its own rect at {gap:?} — the DC clip rect is not holding"
    );
}

/// **THE INTERACTION GATE — a click reaches Wine's own `ButtonWndProc`.**
///
/// W4.8 painted the controls but left input routing pinned to the first shown
/// top-level window, so a click never got near a child. This drives a real
/// press-and-release at the `BUTTON`'s coordinates and requires the two things
/// only Wine's own control code can produce.
///
/// **1. The parent is notified.** Nothing in exemu knows what a button is. For
/// the sample's WndProc to see a `WM_COMMAND`, user32's `ButtonWndProc` had to
/// run the whole documented sequence: take the capture and push itself on
/// `WM_LBUTTONDOWN`, and on `WM_LBUTTONUP` un-push, check the release point
/// against `GetClientRect`, `ReleaseCapture`, read its control id back out of
/// `GWLP_ID`, ask `GetParent`, and `SendMessageW(parent, WM_COMMAND, id, hwnd)`.
/// The handler answers by setting the window text of the HWND it was handed in
/// **lParam** — so the recorded `SetWindowText` naming the *button* proves the
/// notification carried the button's real handle, and the id filter proves it
/// carried the right `wParam`.
///
/// **2. It repaints itself pressed.** `ButtonWndProc` answers its own
/// `BM_SETSTATE` by taking a DC (`NtUserGetDC`) and painting immediately, so the
/// button's pixels inside the parent's surface must change while the button is
/// down and change **back** when it comes up. Both frames are captured; the
/// assertion is that the pressed rendering differs from the released one and the
/// released one recurs afterwards.
///
/// A click delivered to the top-level window instead of the button — the
/// pre-routing behaviour — fails both halves.
#[test]
fn clicking_the_button_reaches_wine_button_wndproc_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};

    // The centre of the BUTTON, in the top-level window's client coordinates —
    // which is exemu's screen space (the surface is the client area).
    let b = comctl_sample::BUTTON_RECT;
    let (cx, cy) = (b[0] + b[2] / 2, b[1] + b[3] / 2);

    let log = Arc::new(Mutex::new(Vec::new()));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        input_run_config(
            Box::new(RecordingDriver::with_inner(
                Arc::clone(&log),
                Box::new(FrameCapture { frames: Arc::clone(&frames) }),
            )),
            vec![
                InputEvent::MouseButton { button: MouseButton::Left, down: true, x: cx, y: cy },
                InputEvent::MouseButton { button: MouseButton::Left, down: false, x: cx, y: cy },
            ],
        ),
    )
    .expect("the comctl sample runs its pump to completion with a click injected");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly after the click");
    eprintln!("comctl_sample clicked: exit={} steps={}", res.exit_code, res.steps);

    let calls = log.lock().unwrap();
    let button_hwnd = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::CreateWindow { hwnd, params }
                if params.class_name.eq_ignore_ascii_case("BUTTON") =>
            {
                Some(*hwnd)
            }
            _ => None,
        })
        .expect("the BUTTON child was created");

    // 1. THE NOTIFICATION.
    let notified = calls.iter().any(|c| matches!(
        c,
        DriverCall::SetWindowText { hwnd, text }
            if *hwnd == button_hwnd && text == comctl_sample::CLICKED_TEXT
    ));
    assert!(
        notified,
        "no WM_COMMAND/BN_CLICKED reached the parent: the click never got to \
         Wine's ButtonWndProc (control id {}, button hwnd {button_hwnd:#x})",
        comctl_sample::ID_BUTTON
    );
    drop(calls);

    // 2. THE PRESSED REPAINT. Collapse the presented frames to the successive
    // *distinct* renderings of the button's own rect; the button must have
    // changed and changed back.
    let frames = frames.lock().unwrap();
    let mut renderings: Vec<Vec<u8>> = Vec::new();
    for (pixels, w, h) in frames.iter() {
        let r = rect_pixels(pixels, *w, *h, b);
        if renderings.last() != Some(&r) {
            renderings.push(r);
        }
    }
    eprintln!("button rect renderings across {} frames: {}", frames.len(), renderings.len());
    assert!(
        renderings.len() >= 3,
        "the button never changed appearance: {} distinct renderings of {b:?}",
        renderings.len()
    );
    let last = renderings.last().unwrap();
    let pressed = &renderings[renderings.len() - 2];
    let before = &renderings[renderings.len() - 3];
    assert_ne!(
        pressed, last,
        "the button's pressed and released renderings are identical — BM_SETSTATE painted nothing"
    );
    assert_eq!(
        before, last,
        "the button did not return to its released appearance after the button-up"
    );
    let changed = pressed.iter().zip(last).filter(|(a, b)| a != b).count();
    eprintln!("pressed vs released: {changed}/{} bytes differ in {b:?}", last.len());
    assert!(changed > 100, "only {changed} bytes changed while the button was down");

    // 3. WHAT changed: the classic Win95 edge swap. A raised push button has a
    //    white (`COLOR_BTNHIGHLIGHT`) inner edge along its top-left and the near
    //    black `COLOR_3DDKSHADOW` along its bottom-right; pushed, the highlight
    //    is replaced by `COLOR_BTNSHADOW` grey and the dark edge goes. exemu
    //    supplies the palette through `GetSysColor`, but *which colour goes on
    //    which edge in which state* is Wine's `UITOOLS95_DFC_ButtonPush` and
    //    nothing else.
    let px = |v: &Vec<u8>, x: i32, y: i32| {
        let off = ((y * b[2] + x) * 4) as usize;
        [v[off], v[off + 1], v[off + 2]]
    };
    const BTNHIGHLIGHT: [u8; 3] = [0xFF, 0xFF, 0xFF];
    const BTNSHADOW: [u8; 3] = [0x80, 0x80, 0x80];
    const DKSHADOW: [u8; 3] = [0x00, 0x00, 0x00];
    let (rx, ry) = (b[2] - 2, b[3] - 2);
    assert_eq!(px(last, 1, 1), BTNHIGHLIGHT, "released: the top-left inner edge is the highlight");
    assert_eq!(px(pressed, 1, 1), BTNSHADOW, "pressed: the highlight becomes the shadow grey");
    assert_eq!(px(last, rx, ry), DKSHADOW, "released: the bottom-right edge is the dark shadow");
    assert_eq!(px(pressed, rx, ry), BTNSHADOW, "pressed: the dark bottom-right edge lifts");
}

/// **Keyboard focus: space activates the focused button.**
///
/// The other half of input routing. `ButtonWndProc` calls `NtUserSetFocus` on
/// itself when it is pressed, so after a click the keyboard belongs to the
/// *child*, not to the top-level window — and Wine's button answers `VK_SPACE`
/// by pushing itself on the key-down and running the whole click-notification
/// path on the key-up (its `WM_KEYUP` arm jumps straight into the
/// `WM_LBUTTONUP` one, skipping only the point-in-rect test).
///
/// Each notification makes the sample's WndProc set the button's text once, so
/// the driver log counts them: a click alone gives one, a click followed by a
/// space gives **two**. If keys still went to the top-level window — the
/// pre-routing behaviour — the second never happens.
#[test]
fn space_activates_the_focused_button_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};
    /// `VK_SPACE`.
    const VK_SPACE: u32 = 0x20;

    let b = comctl_sample::BUTTON_RECT;
    let (cx, cy) = (b[0] + b[2] / 2, b[1] + b[3] / 2);
    let notifications = |events: Vec<InputEvent>| -> usize {
        let log = Arc::new(Mutex::new(Vec::new()));
        let exe = comctl_sample::build();
        let res =
            load_and_run(&exe, input_run_config(Box::new(RecordingDriver::new(Arc::clone(&log))), events))
                .expect("the comctl sample runs its pump to completion");
        assert_eq!(res.exit_code, 0, "the guest exits cleanly");
        let calls = log.lock().unwrap();
        calls
            .iter()
            .filter(|c| matches!(
                c,
                DriverCall::SetWindowText { text, .. } if text == comctl_sample::CLICKED_TEXT
            ))
            .count()
    };

    let click = vec![
        InputEvent::MouseButton { button: MouseButton::Left, down: true, x: cx, y: cy },
        InputEvent::MouseButton { button: MouseButton::Left, down: false, x: cx, y: cy },
    ];
    let mut click_then_space = click.clone();
    click_then_space.push(InputEvent::Key { vk: VK_SPACE, down: true });
    click_then_space.push(InputEvent::Key { vk: VK_SPACE, down: false });

    assert_eq!(notifications(click), 1, "the click alone notifies once");
    assert_eq!(
        notifications(click_then_space),
        2,
        "VK_SPACE after the click did not reach the focused BUTTON — the keyboard is \
         still going to the top-level window"
    );
}

/// **The pressed button, pinned pixel-for-pixel.**
///
/// The companion golden to [`comctl_painted_controls_match_golden_on_wine`],
/// for the *interactive* state: the frame Wine's `ButtonWndProc` paints while
/// the button is held down. Rendered headlessly through the deterministic
/// [`OffscreenPresenter`] (the built-in `font8x8` stub, so the golden is
/// platform-independent). The pressed frame is found by its own content — the
/// first flush whose button top-left inner pixel is the shadow grey rather than
/// the highlight — so the pin does not depend on how many frames the pump
/// happens to present.
///
/// Set `EXEMU_BLESS=1` to re-bless after an intended rendering change.
#[test]
fn the_pressed_button_matches_golden_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};

    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w48-pressed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);

    let b = comctl_sample::BUTTON_RECT;
    let (cx, cy) = (b[0] + b[2] / 2, b[1] + b[3] / 2);
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        input_run_config(
            Box::new(PresenterDriver::new(OffscreenPresenter::with_dir(Some(shot_dir.clone())))),
            vec![
                InputEvent::MouseButton { button: MouseButton::Left, down: true, x: cx, y: cy },
                InputEvent::MouseButton { button: MouseButton::Left, down: false, x: cx, y: cy },
            ],
        ),
    )
    .expect("the comctl sample paints its pressed button");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly through the click");

    let mut frames: Vec<_> = std::fs::read_dir(&shot_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("png"))
        .collect();
    frames.sort();
    // The pressed frame identifies itself: `COLOR_BTNSHADOW` where the raised
    // button has `COLOR_BTNHIGHLIGHT`.
    let rendered = frames
        .iter()
        .find(|p| {
            let (w, _, px) = decode_png(p);
            let off = (((b[1] + 1) as usize) * w as usize + (b[0] + 1) as usize) * 4;
            px[off..off + 3] == [0x80, 0x80, 0x80]
        })
        .expect("one presented frame has the button pushed in")
        .clone();

    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/comctl_button_pressed.png");
    if std::env::var_os("EXEMU_BLESS").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::copy(&rendered, &golden).unwrap();
        eprintln!("BLESSED golden: {} (from {})", golden.display(), rendered.display());
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
    assert_eq!((rw, rh), (gw, gh), "pressed-frame dimensions match the golden");
    if rpix != gpix {
        let diff = rpix.iter().zip(&gpix).filter(|(a, b)| a != b).count();
        let first = rpix.iter().zip(&gpix).position(|(a, b)| a != b).unwrap_or(0);
        panic!(
            "the pressed button drifted from the golden: {diff}/{} bytes differ \
             (first at byte {first}); set EXEMU_BLESS=1 to re-bless after an intended change",
            rpix.len()
        );
    }
}

/// **The other half of the routing claim: a click that misses the button must
/// not press it.**
///
/// The pre-routing behaviour sent every mouse event to the first shown top-level
/// window; a hit test that always answered "the button", or one that ignored the
/// point, would pass [`clicking_the_button_reaches_wine_button_wndproc_on_wine`]
/// just as well. This clicks the *progress bar* instead — a real child, with a
/// real WndProc, that has no notion of `BN_CLICKED` — and requires silence.
#[test]
fn a_click_that_misses_the_button_notifies_nobody_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};

    let p = comctl_sample::PROGRESS_RECT;
    let (cx, cy) = (p[0] + p[2] / 2, p[1] + p[3] / 2);
    let log = Arc::new(Mutex::new(Vec::new()));
    let exe = comctl_sample::build();
    let res = load_and_run(
        &exe,
        input_run_config(
            Box::new(RecordingDriver::new(Arc::clone(&log))),
            vec![
                InputEvent::MouseButton { button: MouseButton::Left, down: true, x: cx, y: cy },
                InputEvent::MouseButton { button: MouseButton::Left, down: false, x: cx, y: cy },
            ],
        ),
    )
    .expect("the comctl sample survives a click on the progress bar");
    assert_eq!(res.exit_code, 0, "clicking a control that ignores clicks is harmless");

    let calls = log.lock().unwrap();
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            DriverCall::SetWindowText { text, .. } if text == comctl_sample::CLICKED_TEXT
        )),
        "a click at {cx},{cy} — inside the progress bar, outside the button — still \
         reached the BUTTON: the hit test is not using the point"
    );
}

/// The `[B, G, R, A]` bytes inside `rect` of a top-down BGRA32 frame, row-major.
fn rect_pixels(pixels: &[u8], w: u32, h: u32, rect: [i32; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    for y in rect[1].max(0)..(rect[1] + rect[3]).min(h as i32) {
        for x in rect[0].max(0)..(rect[0] + rect[2]).min(w as i32) {
            let off = (y as usize * w as usize + x as usize) * 4;
            out.extend_from_slice(&pixels[off..off + 4]);
        }
    }
    out
}

/// **W4.8 gate — a control's WndProc runs to completion.**
///
/// The other W6.1-measured gap: `SendMessageW` to a comctl32 control did not
/// terminate. (The recorded diagnosis, "it spins on an unserviced
/// `WineUnixCall` import thunk", is falsifiable straight from the pinned binary
/// and is **false** — `comctl32.dll` imports no `__wine_unix_call` and no
/// `NtQueryVirtualMemory` at all, so it has no unix half to pair; that shape is
/// real for `ws2_32`, not here. The true cause was a null `DefWindowProcW`
/// forwarder slot, fixed in W6.2.)
///
/// The sample now sends `PBM_SETRANGE` then `PBM_SETPOS` to the progress bar and
/// keeps running afterwards. That it reaches `ExitProcess` at all is the proof:
/// a spinning WndProc would burn the step budget instead. The step count is
/// pinned with generous headroom so a regression that reintroduces an unbounded
/// loop fails loudly rather than merely getting slower.
#[test]
fn messaging_a_comctl32_control_terminates_on_wine() {
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
    .expect("the sample reaches ExitProcess after messaging the progress bar");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly after SendMessageW to the control");
    assert!(
        res.steps < 30_000_000,
        "messaging the control cost {} instructions — that is the spin, not a WndProc call",
        res.steps
    );
    eprintln!("comctl_sample SendMessageW gate: exit=0 steps={}", res.steps);

    // The messages went to a real comctl32 control, not a dropped handle.
    let calls = log.lock().unwrap();
    assert!(
        calls.iter().any(|c| matches!(
            c,
            DriverCall::CreateWindow { params, .. } if params.class_name.eq_ignore_ascii_case("msctls_progress32")
        )),
        "the progress bar the messages target was created by comctl32"
    );
}

/// **W4.8 golden gate — the painted controls, pinned pixel-for-pixel.**
///
/// The companion to [`comctl_children_paint_into_the_parent_surface_on_wine`]:
/// that one proves *something* was drawn inside each control's rect, this one
/// pins *what*, in the W4.10 style. The frame is rendered headlessly through the
/// deterministic [`OffscreenPresenter`] (the built-in `font8x8` stub rather than
/// CoreText, so the golden is platform-independent) and compared on decoded
/// pixels. Every pixel inside the two control rects comes from Wine's own
/// `ButtonWndProc` / `ProgressWindowProc`, so a drift here is a change in how
/// exemu services their GDI calls.
///
/// Set `EXEMU_BLESS=1` to re-bless after an intended rendering change.
#[test]
fn comctl_painted_controls_match_golden_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w48-golden-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);

    let presenter = OffscreenPresenter::with_dir(Some(shot_dir.clone()));
    let exe = comctl_sample::build();
    let res = load_and_run(&exe, pumped_run_config(Box::new(PresenterDriver::new(presenter))))
        .expect("the comctl sample paints its controls");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly through the paint path");

    // The pump paints parent then each child, so the *last* frame is the one
    // with every control on it.
    let mut frames: Vec<_> = std::fs::read_dir(&shot_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("png"))
        .collect();
    frames.sort();
    let rendered = frames.last().expect("the presenter wrote frames").clone();

    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/comctl_painted_controls.png");

    if std::env::var_os("EXEMU_BLESS").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::copy(&rendered, &golden).unwrap();
        eprintln!("BLESSED golden: {} (from {})", golden.display(), rendered.display());
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

    assert_eq!((rw, rh), (gw, gh), "painted-frame dimensions match the golden");
    if rpix != gpix {
        let diff = rpix.iter().zip(&gpix).filter(|(a, b)| a != b).count();
        let first = rpix.iter().zip(&gpix).position(|(a, b)| a != b).unwrap_or(0);
        panic!(
            "the painted controls drifted from the golden: {diff}/{} bytes differ \
             (first at byte {first}); set EXEMU_BLESS=1 to re-bless after an intended change",
            rpix.len()
        );
    }
}

/// A [`exemu_core::UserDriver`] that keeps every presented frame's pixels, so a
/// gate can assert on what was actually drawn. `RecordingDriver` deliberately
/// stores only a cheap `non_blank` count; this is its pixel-keeping companion,
/// used as the inner driver.
struct FrameCapture {
    frames: Arc<Mutex<Vec<Frame>>>,
}

/// One presented frame: top-down BGRA32 pixels plus its dimensions.
type Frame = (Vec<u8>, u32, u32);

impl exemu_core::UserDriver for FrameCapture {
    fn flush_surface(&mut self, _hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        if let Ok(mut f) = self.frames.lock() {
            f.push((pixels.to_vec(), w, h));
        }
    }
}

/// Count pixels inside `rect` (`[x, y, cx, cy]`) of a top-down BGRA32 frame that
/// are **not** the surface's background white — i.e. ink somebody drew there.
/// Out-of-frame parts of the rect are skipped rather than counted.
fn ink_in_rect(pixels: &[u8], w: u32, h: u32, rect: [i32; 4]) -> u32 {
    pixels_matching(pixels, w, h, rect, |px| px != [0xFF, 0xFF, 0xFF])
}

/// Count pixels inside `rect` (`[x, y, cx, cy]`) of a top-down BGRA32 frame whose
/// `[B, G, R]` bytes satisfy `pred`. Out-of-frame parts of the rect are skipped.
fn pixels_matching(
    pixels: &[u8],
    w: u32,
    h: u32,
    rect: [i32; 4],
    pred: impl Fn([u8; 3]) -> bool,
) -> u32 {
    let mut n = 0;
    for y in rect[1].max(0)..(rect[1] + rect[3]).min(h as i32) {
        for x in rect[0].max(0)..(rect[0] + rect[2]).min(w as i32) {
            let off = (y as usize * w as usize + x as usize) * 4;
            if pred([pixels[off], pixels[off + 1], pixels[off + 2]]) {
                n += 1;
            }
        }
    }
    n
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
