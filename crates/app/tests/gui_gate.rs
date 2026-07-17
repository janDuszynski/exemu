//! W4 boot-progress gates under the Wine boot.
//!
//! * W4.1: a GUI `.exe` gets **past** the win32k SSDT boundary. Before W4.1,
//!   Wine's user32/gdi32 null-deref the unserviced `NtUser*/NtGdi*` results
//!   (fault ~3.37M instr); the win32k skeleton (nonzero class ATOM, HWND/HDC
//!   handles, 96 DPI, empty message queue) lets them proceed.
//! * W4.2: the win32k object model marshals the real `CreateWindowEx` /
//!   `ShowWindow` arguments out of guest memory and pushes them through the
//!   injected [`exemu_core::UserDriver`] — a `RecordingDriver` observes the
//!   window the guest actually asked for (class, title, geometry, SW_ cmd).
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;
use std::sync::{Arc, Mutex};

use exemu_app::{gui_sample, load_and_run, RunConfig};
use exemu_gui::{DriverCall, OffscreenPresenter, PresenterDriver, RecordingDriver};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

#[test]
fn gui_sample_passes_win32k_skeleton_on_wine() {
    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = gui_sample::build();
    let r = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    );

    // Before W4.1, Wine's user32/gdi32 null-deref the unserviced `NtUser*/NtGdi*`
    // results and the run FAULTS in the win32k layer. With the skeleton second
    // SSDT table, the GUI sample runs its RegisterClass → CreateWindow →
    // ShowWindow → message loop to completion and exits cleanly (GetMessage
    // returns WM_QUIT for now — the real native-event pump is W4.5).
    let res = r.expect("gui_sample should run past the win32k boundary, not fault");
    eprintln!(
        "gui_sample wine boot: exit={} steps={}",
        res.exit_code, res.steps
    );
    assert_eq!(
        res.exit_code, 0,
        "GUI sample exits cleanly on Wine's user32/gdi32 + the win32k skeleton"
    );
    assert!(
        res.steps > 1_000_000,
        "the full user32/gdi32/win32u boot ran ({} steps)",
        res.steps
    );
}

#[test]
fn gui_sample_drives_the_user_driver_on_wine() {
    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let exe = gui_sample::build();
    let r = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
            ..RunConfig::default()
        },
    );
    let res = r.expect("gui_sample should run to completion with a driver injected");
    assert_eq!(res.exit_code, 0, "GUI sample exits cleanly with the RecordingDriver");

    // The win32k handlers must marshal the guest's actual CreateWindowExW
    // arguments (through Wine's user32 → win32u syscall path) and hand them to
    // the driver: gui_sample asks for "ExemuWindowClass" / "exemu — real GUI
    // window" at (120, 120) 480×260 with WS_OVERLAPPEDWINDOW, then SW_SHOW=5.
    let calls = log.lock().unwrap();
    let create = calls
        .iter()
        .position(|c| matches!(c, DriverCall::CreateWindow { .. }))
        .expect("driver saw a CreateWindow call");
    let DriverCall::CreateWindow { hwnd, params } = &calls[create] else {
        unreachable!()
    };
    assert_eq!(params.class_name, "ExemuWindowClass");
    assert_eq!(params.title, "exemu — real GUI window");
    assert_eq!(
        (params.x, params.y, params.cx, params.cy),
        (120, 120, 480, 260),
        "geometry marshalled from the guest's CreateWindowExW stack args"
    );
    assert_eq!(
        params.style & 0x00CF_0000,
        0x00CF_0000,
        "WS_OVERLAPPEDWINDOW bits survive the user32 → win32u path"
    );
    assert_ne!(params.class_atom, 0, "class was registered before the window was created");

    let show = calls
        .iter()
        .position(|c| matches!(c, DriverCall::ShowWindow { hwnd: h, cmd: 5 } if h == hwnd))
        .expect("driver saw ShowWindow(SW_SHOW) for the created hwnd");
    assert!(show > create, "ShowWindow arrives after CreateWindow");
}

#[test]
fn gui_sample_paints_and_presents_a_surface_on_wine() {
    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    // A unique PNG output directory under the OS temp dir, so PNG presence is a
    // deterministic assertion without touching the EXEMU_GUI_SHOT env var.
    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w43-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);

    // Compose the scaffold's drivers: record every UserDriver call for
    // assertions *and* forward to a PresenterDriver that writes each flushed
    // frame to a PNG in `shot_dir`.
    let log = Arc::new(Mutex::new(Vec::new()));
    let presenter = OffscreenPresenter::with_dir(Some(shot_dir.clone()));
    let driver = RecordingDriver::with_inner(
        Arc::clone(&log),
        Box::new(PresenterDriver::new(presenter)),
    );

    let exe = gui_sample::build();
    let r = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(driver)),
            ..RunConfig::default()
        },
    );
    let res = r.expect("gui_sample should run to completion with the surface/present driver");
    assert_eq!(res.exit_code, 0, "GUI sample exits cleanly through the paint path");

    let calls = log.lock().unwrap();

    // The surface is created for the gui_sample window at its 480×260 client
    // rect (the geometry gui_sample asks CreateWindowExW for).
    let surface = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::CreateWindowSurface { hwnd, w, h } => Some((*hwnd, *w, *h)),
            _ => None,
        })
        .expect("driver saw CreateWindowSurface");
    assert_eq!(
        (surface.1, surface.2),
        (480, 260),
        "surface allocated at the window's 480×260 client rect"
    );

    // At least one FlushSurface presents those dims with real drawn content:
    // both the TextOutW glyphs and the Rectangle frame paint black on the white
    // surface, so non_blank easily clears 200 pixels.
    let flush = calls
        .iter()
        .find_map(|c| match c {
            DriverCall::FlushSurface { hwnd, w, h, non_blank }
                if *hwnd == surface.0 && *w == 480 && *h == 260 =>
            {
                Some(*non_blank)
            }
            _ => None,
        })
        .expect("driver saw a FlushSurface for the 480×260 window surface");
    eprintln!(
        "gui_sample W4.3 present: exit={} steps={} flush 480×260 non_blank={flush}",
        res.exit_code, res.steps
    );
    assert!(
        flush > 200,
        "the text + rectangle frame paint measurable content (non_blank={flush})"
    );

    // The OffscreenPresenter wrote at least one non-empty PNG for the frame.
    let mut png_ok = false;
    if let Ok(entries) = std::fs::read_dir(&shot_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("png")
                && std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false)
            {
                png_ok = true;
                break;
            }
        }
    }
    assert!(png_ok, "a non-empty PNG frame was written to {}", shot_dir.display());

    let _ = std::fs::remove_dir_all(&shot_dir);
}
