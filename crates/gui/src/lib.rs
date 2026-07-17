//! Windowing backends for Windows dialogs.
//!
//! * [`MinifbGui`] — a live, clickable window (minifb + a bitmap font).
//! * [`OffscreenGui`] — renders to PNG files and auto-drives the default
//!   button, so the whole GUI pipeline (parsing → rendering → click →
//!   extraction) can be exercised and *seen* headlessly.
//!
//! Both share [`render::Renderer`]; they differ only in where pixels go and
//! where input comes from.
//!
//! W4.2 additions (driver/presenter split):
//!
//! * [`Presenter`] — the surface/present half of a display driver.
//! * [`OffscreenPresenter`] — writes BGRA frames to PNG files under
//!   `EXEMU_GUI_SHOT` when set, otherwise just counts frames; runs on the
//!   interpreter thread, no AppKit.
//! * [`RecordingDriver`] — implements [`exemu_core::UserDriver`] and records
//!   every call into a shared log for gate tests.

mod render;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use exemu_core::gui::{ControlKind, DialogTemplate, Gui, GuiEvent};
use exemu_core::{UserDriver, WindowParams};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window, WindowOptions};

use render::Renderer;

/// Promote this (terminal-launched) process to a foreground GUI app so its
/// window actually appears and can receive keyboard/mouse focus. Without
/// this, a minifb window on macOS is created but stays invisible/unfocusable
/// and `is_open()` reports false. No-op off macOS.
#[cfg(target_os = "macos")]
fn become_foreground_app() {
    #[repr(C)]
    struct ProcessSerialNumber {
        high: u32,
        low: u32,
    }
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn TransformProcessType(psn: *const ProcessSerialNumber, state: u32) -> i32;
        fn SetFrontProcess(psn: *const ProcessSerialNumber) -> i16;
    }
    const K_CURRENT_PROCESS: u32 = 2;
    const K_TO_FOREGROUND: u32 = 1;
    let psn = ProcessSerialNumber { high: 0, low: K_CURRENT_PROCESS };
    // Safe: simple, idempotent Carbon calls with a stack-local PSN. Promote
    // the process to a foreground app and bring it to the front so the window
    // is visible and can take keyboard/mouse focus.
    unsafe {
        TransformProcessType(&psn, K_TO_FOREGROUND);
        SetFrontProcess(&psn);
    }
}

#[cfg(not(target_os = "macos"))]
fn become_foreground_app() {}

fn default_button(tpl: &DialogTemplate) -> u32 {
    tpl.controls
        .iter()
        .find(|c| matches!(c.kind, ControlKind::Button { default: true }))
        .map(|c| c.id)
        .unwrap_or(1)
}

fn button_label(tpl: Option<&DialogTemplate>, id: u32) -> String {
    tpl.and_then(|t| t.controls.iter().find(|c| c.id == id))
        .map(|c| c.text.replace('&', ""))
        .unwrap_or_else(|| id.to_string())
}

fn seed_texts(tpl: &DialogTemplate) -> HashMap<u32, String> {
    tpl.controls
        .iter()
        .filter(|c| !c.text.is_empty())
        .map(|c| (c.id, c.text.clone()))
        .collect()
}

// ============================ live window ==================================

/// A real, clickable window backed by minifb.
pub struct MinifbGui {
    window: Option<Window>,
    r: Renderer,
    tpl: Option<DialogTemplate>,
    texts: HashMap<u32, String>,
    default_id: u32,
    prev_down: bool,
    /// Input is ignored for this many initial pump iterations, so the
    /// keystroke that launched the program isn't taken as a button press.
    warmup: u32,
    /// Buttons already activated — greyed and non-clickable (one-shot), so a
    /// second click can't re-trigger the action while it runs.
    disabled: HashSet<u32>,
    /// True when showing a custom (GDI-drawn) window rather than a dialog.
    custom: bool,
}

impl Default for MinifbGui {
    fn default() -> Self {
        Self::new()
    }
}

impl MinifbGui {
    pub fn new() -> Self {
        MinifbGui {
            window: None,
            r: Renderer::new(1, 1),
            tpl: None,
            texts: HashMap::new(),
            default_id: 1,
            prev_down: false,
            warmup: 0,
            disabled: HashSet::new(),
            custom: false,
        }
    }

    /// Input pump for a custom (GDI-drawn) window: returns a client-area
    /// mouse press or the window-close event; painting is driven by the OS
    /// layer's WM_PAINT.
    fn pump_custom(&mut self, block: bool) -> Option<GuiEvent> {
        loop {
            if !self.window.as_ref().map(|w| w.is_open()).unwrap_or(false) {
                return Some(GuiEvent::Close);
            }
            self.repaint();
            let (down, pos) = self
                .window
                .as_mut()
                .map(|w| (w.get_mouse_down(MouseButton::Left), w.get_mouse_pos(MouseMode::Clamp).unwrap_or((0.0, 0.0))))
                .unwrap_or((false, (0.0, 0.0)));
            let pressed = down && !self.prev_down;
            self.prev_down = down;
            if self.warmup > 0 {
                self.warmup -= 1;
            } else if pressed {
                return Some(GuiEvent::MouseDown(pos.0 as i32, pos.1 as i32));
            }
            if !block {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
    }

    fn repaint(&mut self) {
        // A custom window keeps whatever the guest's GDI drew; only dialogs
        // are re-composited from their template here.
        if !self.custom {
            if let Some(tpl) = &self.tpl {
                self.r.paint(tpl, &self.texts, &self.disabled);
            }
        }
        let (w, h) = (self.r.w, self.r.h);
        if let Some(win) = self.window.as_mut() {
            let _ = win.update_with_buffer(&self.r.buf, w, h);
        }
    }
}

impl Gui for MinifbGui {
    fn open(&mut self, tpl: &DialogTemplate) {
        let (w, h) = Renderer::size_for(tpl);
        let title = if tpl.title.is_empty() { "exemu" } else { &tpl.title };
        // `topmost` keeps the window in front of the launching terminal — on
        // macOS a normal CLI-owned window otherwise opens hidden behind it.
        let opts = WindowOptions { resize: false, topmost: true, ..WindowOptions::default() };
        self.window = Window::new(title, w, h, opts).ok();
        // Activate AFTER creating the window, so minifb's own NSApplication
        // setup doesn't override the foreground promotion.
        become_foreground_app();
        self.r = Renderer::new(w, h);
        self.texts = seed_texts(tpl);
        self.default_id = default_button(tpl);
        self.tpl = Some(tpl.clone());
        self.prev_down = false;
        self.warmup = 40; // ~0.3s of ignored input
        self.disabled.clear();
        self.custom = false;
        self.repaint();
        let is_open = self.window.as_ref().map(|w| w.is_open()).unwrap_or(false);
        let label = tpl
            .controls
            .iter()
            .find(|c| c.id == self.default_id)
            .map(|c| c.text.replace('&', ""))
            .unwrap_or_else(|| "OK".into());
        eprintln!(
            "[exemu-gui] window \"{title}\": created={} open={is_open} — click it, then press Enter to {label} (Esc cancels)",
            self.window.is_some()
        );
        self.repaint();
    }

    fn set_text(&mut self, id: u32, text: &str) {
        self.texts.insert(id, text.to_string());
        self.repaint();
    }

    fn get_text(&self, id: u32) -> Option<String> {
        self.texts.get(&id).cloned()
    }

    fn open_window(&mut self, title: &str, w: u32, h: u32) {
        let (w, h) = ((w as usize).clamp(120, 1600), (h as usize).clamp(80, 1000));
        let opts = WindowOptions { resize: false, topmost: true, ..WindowOptions::default() };
        self.window = Window::new(title, w, h, opts).ok();
        become_foreground_app();
        self.r = Renderer::new(w, h);
        self.r.apply(&exemu_core::DrawOp::Clear(0x00C0_C0C0));
        self.custom = true;
        self.prev_down = false;
        self.warmup = 20;
        self.tpl = None;
        eprintln!("[exemu-gui] custom window \"{title}\" {w}x{h} — GDI-drawn; close it to continue");
        self.repaint();
    }

    fn draw(&mut self, op: &exemu_core::DrawOp) {
        self.r.apply(op);
    }

    fn present(&mut self) {
        self.repaint();
    }

    fn client_size(&self) -> Option<(u32, u32)> {
        if self.custom {
            Some((self.r.w as u32, self.r.h as u32))
        } else {
            None
        }
    }

    fn pump(&mut self, block: bool) -> Option<GuiEvent> {
        if self.custom {
            return self.pump_custom(block);
        }
        let mut iter = 0u32;
        loop {
            let win_open = self.window.as_ref().map(|w| w.is_open()).unwrap_or(false);
            if !win_open {
                eprintln!("[exemu-gui] window was closed");
                return Some(GuiEvent::Close);
            }
            self.repaint();

            // Read input state.
            let (active, enter, esc, down, pos) = self
                .window
                .as_mut()
                .map(|w| {
                    (
                        w.is_active(),
                        w.is_key_pressed(Key::Enter, KeyRepeat::No) || w.is_key_pressed(Key::NumPadEnter, KeyRepeat::No),
                        w.is_key_pressed(Key::Escape, KeyRepeat::No),
                        w.get_mouse_down(MouseButton::Left),
                        w.get_mouse_pos(MouseMode::Clamp).unwrap_or((0.0, 0.0)),
                    )
                })
                .unwrap_or((false, false, false, false, (0.0, 0.0)));

            // Report the first couple of iterations and any input, always, so
            // the behavior is visible without needing an env var.
            iter += 1;
            let pressed = down && !self.prev_down;
            self.prev_down = down;
            if iter <= 2 || enter || esc || pressed {
                eprintln!(
                    "[exemu-gui] pump: active={active} enter={enter} esc={esc} click={pressed}@({},{}) warmup={}",
                    pos.0 as i32, pos.1 as i32, self.warmup
                );
            }

            if self.warmup > 0 {
                self.warmup -= 1;
            } else {
                // Each activation is one-shot: disable the button so the
                // action can't be re-triggered while it runs.
                if enter && !self.disabled.contains(&self.default_id) {
                    self.disabled.insert(self.default_id);
                    self.repaint();
                    eprintln!("[exemu-gui] Enter -> \"{}\" (working…)", button_label(self.tpl.as_ref(), self.default_id));
                    return Some(GuiEvent::Command(self.default_id));
                }
                if esc {
                    return Some(GuiEvent::Command(2));
                }
                if pressed {
                    if let Some(id) = self.r.hit_test(pos.0 as usize, pos.1 as usize) {
                        self.disabled.insert(id);
                        self.repaint();
                        eprintln!("[exemu-gui] clicked \"{}\" (working…)", button_label(self.tpl.as_ref(), id));
                        return Some(GuiEvent::Command(id));
                    }
                }
            }

            if !block {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
    }

    fn is_open(&self) -> bool {
        // "A window exists" — the interactive path stays engaged while the
        // window is alive; the user actually closing it is detected inside
        // `pump` (which returns `Close`) and by `close()`.
        self.window.is_some()
    }

    fn close(&mut self) {
        self.window = None;
        self.tpl = None;
    }
}

// ============================ offscreen (PNG) ==============================

/// A headless backend that renders dialog states to PNG files and auto-drives
/// the default button, so the pipeline can be verified without a display.
/// Enabled by pointing `EXEMU_GUI_SHOT` at an output directory.
pub struct OffscreenGui {
    dir: PathBuf,
    r: Renderer,
    tpl: Option<DialogTemplate>,
    texts: HashMap<u32, String>,
    default_id: u32,
    shot: u32,
    set_calls: u32,
    clicked: bool,
    open: bool,
    custom: bool,
}

impl OffscreenGui {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        OffscreenGui {
            dir,
            r: Renderer::new(1, 1),
            tpl: None,
            texts: HashMap::new(),
            default_id: 1,
            shot: 0,
            set_calls: 0,
            clicked: false,
            open: false,
            custom: false,
        }
    }

    fn snapshot(&mut self, tag: &str) {
        // Dialogs are composited from their template; custom windows keep
        // whatever the guest's GDI drew.
        if !self.custom {
            let Some(tpl) = self.tpl.clone() else { return };
            self.r.paint(&tpl, &self.texts, &HashSet::new());
        }
        let kind = if self.custom { "window" } else { "dialog" };
        let path = self.dir.join(format!("{kind}-{:02}-{tag}.png", self.shot));
        self.shot += 1;
        if let Ok(file) = std::fs::File::create(&path) {
            let mut enc = png::Encoder::new(std::io::BufWriter::new(file), self.r.w as u32, self.r.h as u32);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            if let Ok(mut w) = enc.write_header() {
                let _ = w.write_image_data(&self.r.to_rgba());
            }
            eprintln!("[exemu-gui] wrote {}", path.display());
        }
    }
}

impl Gui for OffscreenGui {
    fn open(&mut self, tpl: &DialogTemplate) {
        let (w, h) = Renderer::size_for(tpl);
        self.r = Renderer::new(w, h);
        self.texts = seed_texts(tpl);
        self.default_id = default_button(tpl);
        self.tpl = Some(tpl.clone());
        self.clicked = false;
        self.open = true;
        self.custom = false;
        self.snapshot("open");
    }

    fn open_window(&mut self, _title: &str, w: u32, h: u32) {
        let (w, h) = ((w as usize).clamp(120, 1600), (h as usize).clamp(80, 1000));
        self.r = Renderer::new(w, h);
        self.r.apply(&exemu_core::DrawOp::Clear(0x00C0_C0C0));
        self.custom = true;
        self.open = true;
        self.clicked = false;
    }

    fn draw(&mut self, op: &exemu_core::DrawOp) {
        self.r.apply(op);
    }

    fn present(&mut self) {
        if self.custom {
            self.snapshot("paint");
        }
    }

    fn client_size(&self) -> Option<(u32, u32)> {
        self.custom.then_some((self.r.w as u32, self.r.h as u32))
    }

    fn set_text(&mut self, id: u32, text: &str) {
        self.texts.insert(id, text.to_string());
        // Throttle: capture the first change and then every ~25th (progress
        // updates fire constantly), to keep a handful of frames.
        self.set_calls += 1;
        if self.set_calls <= 1 || self.set_calls % 25 == 0 {
            self.snapshot("frame");
        }
    }

    fn get_text(&self, id: u32) -> Option<String> {
        self.texts.get(&id).cloned()
    }

    fn pump(&mut self, block: bool) -> Option<GuiEvent> {
        if !self.open {
            return Some(GuiEvent::Close);
        }
        // Custom windows: they've painted; end the loop.
        if self.custom {
            return Some(GuiEvent::Close);
        }
        if block {
            if !self.clicked {
                // Auto-"click" the default (Install) button once.
                self.clicked = true;
                self.snapshot("click");
                return Some(GuiEvent::Command(self.default_id));
            }
            // Nothing more to do; end the loop.
            return Some(GuiEvent::Close);
        }
        None
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn close(&mut self) {
        self.open = false;
        self.tpl = None;
    }
}

// ============================ W4.2: Presenter trait ==========================

/// The surface/present half of a display driver (W4.2).
///
/// A [`Presenter`] owns per-HWND backing stores and knows how to flush pixels
/// from them to the screen (or to a file, for the headless path). The window
/// management half is covered by [`exemu_core::UserDriver`].
///
/// Only the surface operations needed for `OffscreenPresenter` are specified
/// here; W4.3 grows the trait as the live Cocoa path is added.
pub trait Presenter: Send {
    /// Allocate a backing surface for `hwnd` of the given pixel dimensions.
    ///
    /// The surface is top-down BGRA32 (`stride = width * 4`), matching the
    /// DIB format Windows GDI writes into. Replaces any existing surface for
    /// `hwnd`.
    fn create_surface(&mut self, hwnd: u32, width: u32, height: u32) {
        let _ = (hwnd, width, height);
    }

    /// Release the backing surface for `hwnd`.
    fn destroy_surface(&mut self, hwnd: u32) {
        let _ = hwnd;
    }

    /// Flush `pixels` (top-down BGRA32, `width * height * 4` bytes) to the
    /// presentation target for `hwnd`.
    ///
    /// For `OffscreenPresenter` this writes a PNG to the configured output
    /// directory (or increments the frame counter when no directory is set).
    /// For the live Cocoa path (W4.4) it uploads the texture and presents.
    fn flush(&mut self, hwnd: u32, pixels: &[u8], width: u32, height: u32) {
        let _ = (hwnd, pixels, width, height);
    }
}

// ============================ W4.2: OffscreenPresenter =======================

/// A headless presenter that writes each flushed frame to a PNG file under the
/// directory named by `EXEMU_GUI_SHOT`, or just counts frames when the variable
/// is not set.
///
/// Runs entirely on the interpreter thread — no AppKit, no channels. This is
/// the de-risk path for W4.1–W4.3 and the standing CI golden-frame gate
/// (W4.10).
pub struct OffscreenPresenter {
    /// Output directory (from `EXEMU_GUI_SHOT`), or `None` for count-only mode.
    dir: Option<PathBuf>,
    /// Total frames flushed across all HWNDs since construction.
    frame_count: u64,
}

impl OffscreenPresenter {
    /// Build a presenter. If `EXEMU_GUI_SHOT` names a directory, PNGs are
    /// written there; otherwise every `flush` just increments `frame_count`.
    pub fn new() -> Self {
        let dir = std::env::var_os("EXEMU_GUI_SHOT").map(|v| {
            let p = PathBuf::from(v);
            let _ = std::fs::create_dir_all(&p);
            p
        });
        OffscreenPresenter { dir, frame_count: 0 }
    }

    /// Total frames flushed (useful for assertions in tests).
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }
}

impl Default for OffscreenPresenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Presenter for OffscreenPresenter {
    fn flush(&mut self, hwnd: u32, pixels: &[u8], width: u32, height: u32) {
        self.frame_count += 1;
        let Some(dir) = &self.dir else { return };
        let path = dir.join(format!("hwnd{hwnd:08x}-frame{:04}.png", self.frame_count));
        if let Ok(file) = std::fs::File::create(&path) {
            let mut enc = png::Encoder::new(std::io::BufWriter::new(file), width, height);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            if let Ok(mut w) = enc.write_header() {
                let _ = w.write_image_data(pixels);
            }
            eprintln!("[exemu-gui] presenter: wrote {}", path.display());
        }
    }
}

// ============================ W4.2: RecordingDriver ==========================

/// A single recorded call to the [`UserDriver`] interface.
///
/// The gate test for W4.2 injects a [`RecordingDriver`], runs a headless
/// guest up to `CreateWindowEx` + `ShowWindow`, and asserts that the expected
/// calls appear in the log (in order, or as a set — the test's choice).
#[derive(Debug, Clone)]
pub enum DriverCall {
    CreateWindow { hwnd: u32, params: WindowParams },
    DestroyWindow { hwnd: u32 },
    WindowPosChanging { hwnd: u32 },
    WindowPosChanged { hwnd: u32, rect: [i32; 4] },
    ShowWindow { hwnd: u32, cmd: i32 },
    SetParent { hwnd: u32, parent: u32 },
    SetWindowRgn { hwnd: u32, rgn_hwnd: u32 },
    SetWindowText { hwnd: u32, text: String },
}

/// A [`UserDriver`] that records every call into a shared log.
///
/// Clone the [`Arc`] before injecting to keep a handle for post-run
/// assertions:
///
/// ```rust,ignore
/// let log = Arc::new(Mutex::new(Vec::new()));
/// let driver = RecordingDriver::new(Arc::clone(&log));
/// cfg.driver = Some(Box::new(driver));
/// // … run …
/// assert!(log.lock().unwrap().iter().any(|c| matches!(c, DriverCall::ShowWindow { .. })));
/// ```
pub struct RecordingDriver {
    log: Arc<Mutex<Vec<DriverCall>>>,
}

impl RecordingDriver {
    /// Construct a recording driver backed by the given shared log.
    pub fn new(log: Arc<Mutex<Vec<DriverCall>>>) -> Self {
        RecordingDriver { log }
    }

    /// Push one call record, silently discarding any poisoning.
    fn push(&self, call: DriverCall) {
        if let Ok(mut guard) = self.log.lock() {
            guard.push(call);
        }
    }
}

impl UserDriver for RecordingDriver {
    fn create_window(&mut self, hwnd: u32, params: &WindowParams) {
        self.push(DriverCall::CreateWindow { hwnd, params: params.clone() });
    }

    fn destroy_window(&mut self, hwnd: u32) {
        self.push(DriverCall::DestroyWindow { hwnd });
    }

    fn window_pos_changing(&mut self, hwnd: u32) {
        self.push(DriverCall::WindowPosChanging { hwnd });
    }

    fn window_pos_changed(&mut self, hwnd: u32, rect: [i32; 4]) {
        self.push(DriverCall::WindowPosChanged { hwnd, rect });
    }

    fn show_window(&mut self, hwnd: u32, cmd: i32) {
        self.push(DriverCall::ShowWindow { hwnd, cmd });
    }

    fn set_parent(&mut self, hwnd: u32, parent: u32) {
        self.push(DriverCall::SetParent { hwnd, parent });
    }

    fn set_window_rgn(&mut self, hwnd: u32, rgn_hwnd: u32) {
        self.push(DriverCall::SetWindowRgn { hwnd, rgn_hwnd });
    }

    fn set_window_text(&mut self, hwnd: u32, text: &str) {
        self.push(DriverCall::SetWindowText { hwnd, text: text.to_string() });
    }
}
