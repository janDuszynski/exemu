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

const CONTROL_DLLS: [&str; 3] = ["comctl32.dll", "uxtheme.dll", "comdlg32.dll"];

const DLL_BASE: u64 = 0x0000_0006_0000_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const STACK_SIZE: u64 = 0x4000;
const SENTINEL: u64 = 0x0000_0000_6000_0000;

fn wine_dlls_present() -> bool {
    CONTROL_DLLS.iter().all(|d| Path::new(WINE_DLLS).join(d).exists())
}

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

#[test]
fn wine_control_dlls_map_relocate_and_bind() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = Path::new(WINE_DLLS);

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

    let mut cache: HashMap<String, (std::collections::HashSet<String>, Vec<String>)> = HashMap::new();

    for (dll, entries) in expected {
        let bytes = std::fs::read(dir.join(dll)).unwrap_or_else(|e| panic!("read {dll}: {e}"));
        let mut mem = VirtualMemory::new();
        let loaded = load_dll(&mut mem, &bytes, DLL_BASE);

        for name in entries {
            let va = loaded.export(name);
            assert!(va > loaded.base, "{dll}!{name} resolves above the load base");
            let mut b = [0u8; 1];
            mem.read(va, &mut b).unwrap_or_else(|e| panic!("{dll}!{name} is mapped: {e}"));
        }

        let image = exemu_loader::parse(&bytes).expect("re-parse for the import table");
        assert!(!image.imports.is_empty(), "{dll} imports something");
        let mut checked = 0usize;
        for imp in &image.imports {
            let exemu_core::ImportSymbol::Named(sym) = &imp.symbol else {
                continue;
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

    let targets: Vec<String> = cache.values().flat_map(|(_, t)| t.clone()).collect();
    for t in targets {
        assert!(dir.join(&t).exists(), "forwarder target {t} is missing from the pinned prefix");
    }
}

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

fn setup(dll: &str) -> (WinOs, VirtualMemory, Dll) {
    let bytes = std::fs::read(Path::new(WINE_DLLS).join(dll)).expect("read the DLL");
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap();
    let loaded = load_dll(&mut mem, &bytes, DLL_BASE);
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem, loaded)
}

#[test]
fn wine_control_dll_exports_run_on_the_cpu() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }

    {
        const LANG: u64 = 0x0409;
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

    {
        let (mut os, mut mem, dll) = setup("comdlg32.dll");
        assert_eq!(
            call_export(&mut os, &mut mem, dll.export("CommDlgExtendedError"), &[]),
            0,
            "comdlg32!CommDlgExtendedError reports no error before any dialog ran"
        );
    }
}

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

const CLIENT_PFN_COUNT: usize = 17;
const CLIENT_PFN_STRIDE: u64 = (CLIENT_PFN_COUNT * 8) as u64;
const CLIENT_PFN_NULL_INDEX: usize = 6;

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

fn pumped_run_config(driver: Box<dyn exemu_core::UserDriver>) -> RunConfig {
    input_run_config(driver, Vec::new())
}

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
    assert!(
        calls
            .iter()
            .filter(|c| matches!(c, DriverCall::FlushSurface { .. }))
            .all(|c| matches!(c, DriverCall::FlushSurface { hwnd, .. } if *hwnd == main_hwnd)),
        "a child presents its ancestor's composed surface, never one of its own"
    );
    drop(calls);

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

    let b = comctl_sample::BUTTON_RECT;
    let interior = [b[0] + 3, b[1] + 3, b[2] - 6, b[3] - 6];
    let glyphs = pixels_matching(&pixels, w, h, interior, |px| px[0] < 0x40 && px[1] < 0x40 && px[2] < 0x40);
    assert!(
        glyphs > 20,
        "the BUTTON's own label is missing — only {glyphs} dark pixels inside {interior:?}"
    );
    eprintln!("BUTTON label: {glyphs} glyph pixels inside {interior:?}");

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

#[test]
fn clicking_the_button_reaches_wine_button_wndproc_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};

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

#[test]
fn space_activates_the_focused_button_on_wine() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} control DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    use exemu_core::{InputEvent, MouseButton};
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

    let calls = log.lock().unwrap();
    assert!(
        calls.iter().any(|c| matches!(
            c,
            DriverCall::CreateWindow { params, .. } if params.class_name.eq_ignore_ascii_case("msctls_progress32")
        )),
        "the progress bar the messages target was created by comctl32"
    );
}

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

struct FrameCapture {
    frames: Arc<Mutex<Vec<Frame>>>,
}

type Frame = (Vec<u8>, u32, u32);

impl exemu_core::UserDriver for FrameCapture {
    fn flush_surface(&mut self, _hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        if let Ok(mut f) = self.frames.lock() {
            f.push((pixels.to_vec(), w, h));
        }
    }
}

fn ink_in_rect(pixels: &[u8], w: u32, h: u32, rect: [i32; 4]) -> u32 {
    pixels_matching(pixels, w, h, rect, |px| px != [0xFF, 0xFF, 0xFF])
}

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

fn decode_png(path: &Path) -> (u32, u32, Vec<u8>) {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut reader = png::Decoder::new(f).read_info().expect("valid PNG header");
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).expect("decode PNG frame");
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

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
