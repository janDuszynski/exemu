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
use exemu_gui::{DriverCall, RecordingDriver};

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
