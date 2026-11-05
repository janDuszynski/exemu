use std::path::Path;
use std::sync::{Arc, Mutex};

use exemu_app::{gdi_sample, gui_sample, load_and_run, RunConfig};
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

    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w43-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);

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

    let cmds: Vec<WindowCommand> = rx.iter().collect();

    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample runs to completion across the thread split");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly on the split path");

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

#[cfg(target_os = "macos")]
#[test]
fn gui_sample_window_stays_live_until_close_on_wine() {
    use exemu_core::InputEvent;
    use exemu_gui::{CocoaPresenter, WindowCommand};
    use std::sync::mpsc::RecvTimeoutError;
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

    let deadline = Instant::now() + Duration::from_secs(90);
    let saw_present = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break false;
        }
        match cmd_rx.recv_timeout(left) {
            Ok(WindowCommand::Present { .. }) => break true,
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => break false,
            Err(RecvTimeoutError::Disconnected) => {
                let why = interp
                    .join()
                    .map(|r| match r {
                        Ok(run) => format!("it exited with code {}", run.exit_code),
                        Err(e) => format!("it failed: {e}"),
                    })
                    .unwrap_or_else(|_| "the interpreter thread panicked".to_string());
                panic!("the guest never presented a window — {why}");
            }
        }
    };
    assert!(saw_present, "the guest did not present a window within 90 s (it is still running)");

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !interp.is_finished(),
        "GetMessage blocks (the window stays live) instead of quitting immediately"
    );

    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits once its window is closed");
    assert_eq!(res.exit_code, 0, "closing the window quits the guest cleanly");
}

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

    let mut presents = 0;
    let deadline = Instant::now() + Duration::from_secs(25);
    while presents < 2 && Instant::now() < deadline {
        match cmd_rx.try_recv() {
            Ok(WindowCommand::Present { .. }) => presents += 1,
            Ok(_) => {}
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryRecvError::Disconnected) => break,
        }
    }
    assert!(
        presents >= 2,
        "the WM_PAINT WndProc dispatch produced a second present (saw {presents})"
    );

    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits after the WM_PAINT dispatch and close");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly");
}

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

    const CLICK_X: i32 = 150;
    const CLICK_Y: i32 = 90;

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

    let mut presents = 0;
    let mut clicked = false;
    let mut click_frame: Option<(u32, Vec<u8>)> = None;
    let deadline = Instant::now() + Duration::from_secs(25);
    while presents < 3 && Instant::now() < deadline {
        match cmd_rx.try_recv() {
            Ok(WindowCommand::Present { w, bgra, .. }) => {
                presents += 1;
                if presents >= 2 && !clicked {
                    input_tx
                        .send(InputEvent::MouseButton { hwnd: 0, button: MouseButton::Left, down: true, x: CLICK_X, y: CLICK_Y })
                        .expect("the interpreter is still listening for input");
                    clicked = true;
                }
                if presents == 3 {
                    click_frame = Some((w, bgra));
                }
            }
            Ok(_) => {}
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryRecvError::Disconnected) => break,
        }
    }
    assert!(
        presents >= 3,
        "the injected WM_LBUTTONDOWN reached the WndProc and repainted (saw {presents} presents)"
    );

    let (w, bgra) = click_frame.expect("captured the click repaint frame");
    let dark = |x: u32, y: u32| {
        let o = ((y * w + x) * 4) as usize;
        bgra[o] < 64 && bgra[o + 1] < 64 && bgra[o + 2] < 64
    };
    assert!(dark(CLICK_X as u32, 220), "the click rect's left edge tracks cursor.x={CLICK_X}");
    assert!(dark(440, CLICK_Y as u32), "the click rect's top edge tracks cursor.y={CLICK_Y}");

    input_tx.send(InputEvent::Close).expect("the interpreter is still listening for input");
    let res = interp
        .join()
        .expect("interpreter thread panicked")
        .expect("gui_sample exits after the click repaint and close");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly");
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
fn gui_sample_first_frame_matches_golden_on_wine() {
    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let shot_dir = std::env::temp_dir().join(format!(
        "exemu-w410-golden-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&shot_dir);
    let presenter = OffscreenPresenter::with_dir(Some(shot_dir.clone()));
    let exe = gui_sample::build();
    let res = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(PresenterDriver::new(presenter))),
            ..RunConfig::default()
        },
    )
    .expect("gui_sample renders its first frame");
    assert_eq!(res.exit_code, 0, "the guest exits cleanly through the paint path");

    let rendered = std::fs::read_dir(&shot_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|x| x.to_str()) == Some("png"))
        .expect("the presenter wrote a first-frame PNG");

    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/gui_sample_first_frame.png");

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

#[test]
fn gdi_sample_blits_stretches_and_reads_back_exact_pixels_on_wine() {
    if !Path::new(WINE_DLLS).join("win32u.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/win32u.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let exe = gdi_sample::build();
    let res = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 60_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
            ..RunConfig::default()
        },
    )
    .expect("gdi_sample should run to completion");

    let wrong: Vec<_> = gdi_sample::READBACKS
        .iter()
        .enumerate()
        .filter(|(i, _)| (res.exit_code as u32) >> i & 1 == 1)
        .map(|(_, (x, y, want))| format!("({x},{y}) wanted COLORREF {want:#08x}"))
        .collect();
    assert!(wrong.is_empty(), "GetPixel through Wine's gdi32 disagreed at: {wrong:?}");
    assert_eq!(res.exit_code, 0);

    let calls = log.lock().unwrap();
    let non_blank = calls
        .iter()
        .rev()
        .find_map(|c| match c {
            DriverCall::FlushSurface { w, h, non_blank, .. }
                if (*w, *h) == gdi_sample::WINDOW_SIZE =>
            {
                Some(*non_blank)
            }
            _ => None,
        })
        .expect("the window surface was presented after the drawing");
    assert_eq!(
        non_blank,
        gdi_sample::NON_WHITE_PIXELS,
        "the presented frame holds exactly the union of the blits, the DIBs, the line and the tiles"
    );
}
