//! Windowing backends for Windows dialogs.
//!
//! * [`MinifbGui`] — a live, clickable window (minifb + a bitmap font).
//! * [`OffscreenGui`] — renders to PNG files and auto-drives the default
//!   button, so the whole GUI pipeline (parsing → rendering → click →
//!   extraction) can be exercised and *seen* headlessly.
//!
//! Both share [`render::Renderer`]; they differ only in where pixels go and
//! where input comes from.

mod render;

use std::collections::HashMap;
use std::path::PathBuf;

use exemu_core::gui::{ControlKind, DialogTemplate, Gui, GuiEvent};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window, WindowOptions};

use render::Renderer;

fn default_button(tpl: &DialogTemplate) -> u32 {
    tpl.controls
        .iter()
        .find(|c| matches!(c.kind, ControlKind::Button { default: true }))
        .map(|c| c.id)
        .unwrap_or(1)
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
        }
    }

    fn repaint(&mut self) {
        if let Some(tpl) = &self.tpl {
            self.r.paint(tpl, &self.texts);
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
        let opts = WindowOptions { resize: false, ..WindowOptions::default() };
        self.window = Window::new(title, w, h, opts).ok();
        self.r = Renderer::new(w, h);
        self.texts = seed_texts(tpl);
        self.default_id = default_button(tpl);
        self.tpl = Some(tpl.clone());
        self.prev_down = false;
        if self.window.is_some() {
            let label = tpl
                .controls
                .iter()
                .find(|c| c.id == self.default_id)
                .map(|c| c.text.replace('&', ""))
                .unwrap_or_else(|| "OK".into());
            eprintln!("[exemu-gui] window \"{title}\" is open — click it, then press Enter to {label} (Esc = cancel)");
        }
        self.repaint();
    }

    fn set_text(&mut self, id: u32, text: &str) {
        self.texts.insert(id, text.to_string());
        self.repaint();
    }

    fn get_text(&self, id: u32) -> Option<String> {
        self.texts.get(&id).cloned()
    }

    fn pump(&mut self, block: bool) -> Option<GuiEvent> {
        let debug = std::env::var_os("EXEMU_GUI_DEBUG").is_some();
        let mut ticks = 0u32;
        loop {
            if !self.window.as_ref().map(|w| w.is_open()).unwrap_or(false) {
                return Some(GuiEvent::Close);
            }
            self.repaint();

            // Every ~0.5s, report focus + mouse so we can see if the window is
            // even receiving events on this machine.
            if debug {
                ticks += 1;
                if ticks % 60 == 1 {
                    if let Some(w) = self.window.as_mut() {
                        let active = w.is_active();
                        let mp = w.get_mouse_pos(MouseMode::Pass);
                        eprintln!("[exemu-gui] focus(active)={active} mouse={mp:?} — click the window, then press Enter");
                    }
                }
            }

            if let Some(w) = self.window.as_ref() {
                if w.is_key_pressed(Key::Enter, KeyRepeat::No) || w.is_key_pressed(Key::NumPadEnter, KeyRepeat::No) {
                    if debug {
                        eprintln!("[exemu-gui] Enter -> default button id={}", self.default_id);
                    }
                    return Some(GuiEvent::Command(self.default_id));
                }
                if w.is_key_pressed(Key::Escape, KeyRepeat::No) {
                    return Some(GuiEvent::Command(2));
                }
            }

            let (down, pos) = self
                .window
                .as_ref()
                .map(|w| (w.get_mouse_down(MouseButton::Left), w.get_mouse_pos(MouseMode::Clamp).unwrap_or((0.0, 0.0))))
                .unwrap_or((false, (0.0, 0.0)));
            let pressed = down && !self.prev_down;
            self.prev_down = down;
            if pressed {
                let (mx, my) = (pos.0 as usize, pos.1 as usize);
                let hit = self.r.hit_test(mx, my);
                if debug {
                    eprintln!("[exemu-gui] click ({mx},{my}) win {}x{} -> {hit:?}", self.r.w, self.r.h);
                }
                if let Some(id) = hit {
                    return Some(GuiEvent::Command(id));
                }
            }

            if !block {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
    }

    fn is_open(&self) -> bool {
        self.window.as_ref().map(|w| w.is_open()).unwrap_or(false)
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
    clicked: bool,
    open: bool,
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
            clicked: false,
            open: false,
        }
    }

    fn snapshot(&mut self, tag: &str) {
        let Some(tpl) = self.tpl.clone() else { return };
        self.r.paint(&tpl, &self.texts);
        let path = self.dir.join(format!("dialog-{:02}-{tag}.png", self.shot));
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
        self.snapshot("open");
    }

    fn set_text(&mut self, id: u32, text: &str) {
        self.texts.insert(id, text.to_string());
        self.snapshot("settext");
    }

    fn get_text(&self, id: u32) -> Option<String> {
        self.texts.get(&id).cloned()
    }

    fn pump(&mut self, block: bool) -> Option<GuiEvent> {
        if !self.open {
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
