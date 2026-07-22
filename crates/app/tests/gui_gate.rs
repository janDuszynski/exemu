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

/// W4.5: the guest drives native windows across the interpreter/main thread
/// split. The interpreter runs on a spawned thread with a `CocoaPresenter`
/// whose window commands flow over an mpsc channel; here the *test* thread
/// stands in for the main-thread window host and drains that channel (real
/// AppKit is unavailable off the process main thread, so this proves the
/// plumbing — thread split + channel + clean exit, no deadlock — while the
/// live NSWindow rendering is covered by `exemu cocoa-demo` / `run --gui
/// --wine-boot`). Blocking `rx.iter()` returns only once the interpreter
/// finishes and drops its sender, so a hang here would fail as a timeout.
#[cfg(target_os = "macos")]
#[test]
fn gui_sample_drives_windows_across_the_thread_split_on_wine() {
    use exemu_gui::{CocoaPresenter, WindowCommand};

    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let exe = gui_sample::build();
    let interp = std::thread::spawn(move || {
        load_and_run(
            &exe,
            RunConfig {
                echo: false,
                max_steps: 20_000_000,
                wine_boot_dir: Some(WINE_DLLS.to_string()),
                driver: Some(Box::new(CocoaPresenter::with_channel(tx))),
                ..RunConfig::default()
            },
        )
    });

    // Stand in for the main-thread window host: collect the whole stream.
    let cmds: Vec<WindowCommand> = rx.iter().collect();

    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample runs to completion across the thread split");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly on the split path");

    // A top-level window was created and at least one real frame presented.
    assert!(
        cmds.iter().any(|c| matches!(c, WindowCommand::Create { .. })),
        "the guest's CreateWindowEx reached the main-thread host as a Create command"
    );
    let present = cmds
        .iter()
        .find_map(|c| match c {
            WindowCommand::Present { w, h, bgra, .. } => Some((*w, *h, bgra.clone())),
            _ => None,
        })
        .expect("at least one Present command crossed the channel");
    assert_eq!((present.0, present.1), (480, 260), "presented the 480×260 client surface");
    assert_eq!(present.2.len(), 480 * 260 * 4, "BGRA frame is fully populated");
    assert!(
        present.2.iter().any(|&b| b != 0xFF),
        "the text + rectangle paint non-white pixels into the presented frame"
    );
}

/// W4.5c: with the native input channel attached, a live window **stays up** —
/// the guest parks in `NtUserGetMessage` instead of quitting, and only exits
/// once the window is closed. Proves the blocking, non-spinning pump and the
/// main→interp close→WM_QUIT path (no real AppKit needed: the test stands in for
/// the host, driving the input channel directly).
#[cfg(target_os = "macos")]
#[test]
fn gui_sample_window_stays_live_until_close_on_wine() {
    use exemu_core::InputEvent;
    use exemu_gui::{CocoaPresenter, WindowCommand};
    use std::sync::mpsc::TryRecvError;
    use std::time::{Duration, Instant};

    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let exe = gui_sample::build();
    let interp = std::thread::spawn(move || {
        load_and_run(
            &exe,
            RunConfig {
                echo: false,
                max_steps: 20_000_000,
                wine_boot_dir: Some(WINE_DLLS.to_string()),
                driver: Some(Box::new(CocoaPresenter::with_channel(cmd_tx))),
                input: Some(input_rx),
                ..RunConfig::default()
            },
        )
    });

    // Wait until the window has been shown (a Present crossed the channel).
    // Do NOT drain-to-completion: the guest will not exit on its own — it parks
    // in GetMessage waiting for input.
    let mut saw_present = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !saw_present && Instant::now() < deadline {
        match cmd_rx.try_recv() {
            Ok(WindowCommand::Present { .. }) => saw_present = true,
            Ok(_) => {}
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryRecvError::Disconnected) => break,
        }
    }
    assert!(saw_present, "the guest presented its window before we intervened");

    // The window stays live: the guest is parked in NtUserGetMessage, not exited.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !interp.is_finished(),
        "GetMessage blocks (the window stays live) instead of quitting immediately"
    );

    // Close it: the pump wakes, delivers WM_QUIT, and the guest exits cleanly.
    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits once its window is closed");
    assert_eq!(res.exit_code, 0, "closing the window quits the guest cleanly");
}

/// W4.6: a synthesized WM_PAINT is dispatched to the guest's WndProc, which
/// repaints. The interpreter runs on a spawned thread; the test stands in for
/// the host. gui_sample paints once directly after ShowWindow (present #1), then
/// its message loop's GetMessage synthesizes a WM_PAINT for the shown window,
/// DispatchMessage invokes the WndProc, whose WM_PAINT arm BeginPaint/Rectangle/
/// TextOut/EndPaints — present #2. Seeing a *second* present proves the WndProc
/// dispatch (the direct-call kernel-callback path) actually ran the guest proc.
#[cfg(target_os = "macos")]
#[test]
fn gui_sample_wm_paint_reaches_the_wndproc_on_wine() {
    use exemu_core::InputEvent;
    use exemu_gui::{CocoaPresenter, WindowCommand};
    use std::sync::mpsc::TryRecvError;
    use std::time::{Duration, Instant};

    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let exe = gui_sample::build();
    let interp = std::thread::spawn(move || {
        load_and_run(
            &exe,
            RunConfig {
                echo: false,
                max_steps: 20_000_000,
                wine_boot_dir: Some(WINE_DLLS.to_string()),
                driver: Some(Box::new(CocoaPresenter::with_channel(cmd_tx))),
                input: Some(input_rx),
                ..RunConfig::default()
            },
        )
    });

    // Count presents until the WM_PAINT repaint (#2) has crossed the channel.
    let mut presents = 0;
    let deadline = Instant::now() + Duration::from_secs(25);
    while presents < 2 && Instant::now() < deadline {
        match cmd_rx.try_recv() {
            Ok(WindowCommand::Present { .. }) => presents += 1,
            Ok(_) => {}
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryRecvError::Disconnected) => break, // guest exited/crashed early
        }
    }
    assert!(
        presents >= 2,
        "the WM_PAINT WndProc dispatch produced a second present (saw {presents})"
    );

    // Close the window; the guest exits cleanly through the (now real) pump.
    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits after the WM_PAINT dispatch and close");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly");
}

/// W4.6: a native mouse click is translated into a `WM_LBUTTONDOWN`, delivered
/// to the guest's WndProc, which repaints. After the initial frames (direct
/// paint + synthesized WM_PAINT), an injected [`InputEvent::MouseButton`] is
/// posted by the pump as `WM_LBUTTONDOWN` to the shown window; DispatchMessage
/// routes it to the WndProc's click arm (GetDC → Rectangle → ReleaseDC), a
/// further present. Seeing a *third* present proves native input reaches the
/// guest procedure — the reverse (host→guest) half of the message path.
#[cfg(target_os = "macos")]
#[test]
fn gui_sample_click_repaints_via_the_wndproc_on_wine() {
    use exemu_core::{InputEvent, MouseButton};
    use exemu_gui::{CocoaPresenter, WindowCommand};
    use std::sync::mpsc::TryRecvError;
    use std::time::{Duration, Instant};

    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let exe = gui_sample::build();
    let interp = std::thread::spawn(move || {
        load_and_run(
            &exe,
            RunConfig {
                echo: false,
                max_steps: 20_000_000,
                wine_boot_dir: Some(WINE_DLLS.to_string()),
                driver: Some(Box::new(CocoaPresenter::with_channel(cmd_tx))),
                input: Some(input_rx),
                ..RunConfig::default()
            },
        )
    });

    // Count presents, injecting a click once the initial frames (#1 direct
    // paint, #2 synthesized WM_PAINT) have arrived; the click drives present #3.
    let mut presents = 0;
    let mut clicked = false;
    let deadline = Instant::now() + Duration::from_secs(25);
    while presents < 3 && Instant::now() < deadline {
        match cmd_rx.try_recv() {
            Ok(WindowCommand::Present { .. }) => {
                presents += 1;
                if presents >= 2 && !clicked {
                    input_tx
                        .send(InputEvent::MouseButton { button: MouseButton::Left, down: true, x: 40, y: 40 })
                        .expect("the interpreter is still listening for input");
                    clicked = true;
                }
            }
            Ok(_) => {}
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryRecvError::Disconnected) => break, // guest exited/crashed early
        }
    }
    assert!(
        presents >= 3,
        "the injected WM_LBUTTONDOWN reached the WndProc and repainted (saw {presents} presents)"
    );

    // Close the window; the guest exits cleanly.
    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits after the click repaint and close");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly");
}
