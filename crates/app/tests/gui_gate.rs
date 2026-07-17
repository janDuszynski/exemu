//! W4.1 boot-progress (roadmap W4.1): a GUI `.exe` gets **past** the win32k SSDT
//! boundary under the Wine boot. Before W4.1, Wine's user32/gdi32 null-deref the
//! unserviced `NtUser*/NtGdi*` results (fault ~3.37M instr); the win32k skeleton
//! (nonzero class ATOM, HWND/HDC handles, 96 DPI, empty message queue) lets them
//! proceed. No window is rendered yet (that is W4.2+); this only proves the
//! second SSDT table + skeleton stop the null-deref.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;

use exemu_app::{gui_sample, load_and_run, RunConfig};

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
