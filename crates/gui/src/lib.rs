//! A real window for Windows dialogs, drawn into a software framebuffer with
//! [`minifb`]. It renders the standard dialog controls (buttons, edits,
//! statics, checkboxes, a progress bar) from a parsed [`DialogTemplate`],
//! hit-tests mouse clicks into `WM_COMMAND`s, and reports the window-close box.
//!
//! It deliberately does *not* try to be pixel-accurate to Windows — it aims
//! to be a recognizable, clickable rendering of the dialog so a user can
//! drive an installer. Text is an 8x8 bitmap font.

use std::collections::HashMap;

use exemu_core::gui::{Control, ControlKind, DialogTemplate, Gui, GuiEvent};
use font8x8::UnicodeFonts;
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window, WindowOptions};

// Dialog-unit → pixel scale (approximate MS Shell Dlg base units).
const SX: f32 = 1.75;
const SY: f32 = 1.8;
const PAD: usize = 8;

// Colors (0x00RRGGBB).
const C_BG: u32 = 0x00F0_F0F0;
const C_TEXT: u32 = 0x0000_0000;
const C_WHITE: u32 = 0x00FF_FFFF;
const C_BTN: u32 = 0x00E1_E1E1;
const C_BORDER: u32 = 0x00A0_A0A0;
const C_DKBORDER: u32 = 0x0050_5050;
const C_PROGRESS: u32 = 0x0006_B025;

struct Rect {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

impl Rect {
    fn contains(&self, px: usize, py: usize) -> bool {
        px >= self.x && px < self.x + self.w && py >= self.y && py < self.y + self.h
    }
}

/// The minifb renderer.
pub struct MinifbGui {
    window: Option<Window>,
    buf: Vec<u32>,
    w: usize,
    h: usize,
    tpl: Option<DialogTemplate>,
    texts: HashMap<u32, String>,
    /// Clickable control hit rectangles in pixels.
    hits: Vec<(u32, Rect)>,
    prev_down: bool,
    /// The default (IDOK) button id, activated by Enter.
    default_id: u32,
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
            buf: Vec::new(),
            w: 0,
            h: 0,
            tpl: None,
            texts: HashMap::new(),
            hits: Vec::new(),
            prev_down: false,
            default_id: 1,
        }
    }

    fn du_to_px(&self, control: &Control) -> Rect {
        Rect {
            x: PAD + (control.x as f32 * SX) as usize,
            y: PAD + (control.y as f32 * SY) as usize,
            w: (control.cx as f32 * SX) as usize,
            h: (control.cy as f32 * SY) as usize,
        }
    }

    // ---- drawing primitives ----------------------------------------------

    fn px(&mut self, x: usize, y: usize, c: u32) {
        if x < self.w && y < self.h {
            self.buf[y * self.w + x] = c;
        }
    }

    fn fill(&mut self, r: &Rect, c: u32) {
        for y in r.y..(r.y + r.h).min(self.h) {
            for x in r.x..(r.x + r.w).min(self.w) {
                self.buf[y * self.w + x] = c;
            }
        }
    }

    fn frame(&mut self, r: &Rect, c: u32) {
        for x in r.x..(r.x + r.w) {
            self.px(x, r.y, c);
            self.px(x, r.y + r.h.saturating_sub(1), c);
        }
        for y in r.y..(r.y + r.h) {
            self.px(r.x, y, c);
            self.px(r.x + r.w.saturating_sub(1), y, c);
        }
    }

    fn glyph(&mut self, ch: char, x: usize, y: usize, c: u32) {
        if let Some(rows) = font8x8::BASIC_FONTS.get(ch) {
            for (ry, bits) in rows.iter().enumerate() {
                for rx in 0..8 {
                    if bits & (1 << rx) != 0 {
                        self.px(x + rx, y + ry, c);
                    }
                }
            }
        }
    }

    fn text(&mut self, s: &str, x: usize, y: usize, c: u32) {
        let mut cx = x;
        for ch in s.chars() {
            if cx + 8 > self.w {
                break;
            }
            self.glyph(ch, cx, y, c);
            cx += 8;
        }
    }

    fn text_centered(&mut self, s: &str, r: &Rect, c: u32) {
        let tw = s.chars().count() * 8;
        let tx = r.x + r.w.saturating_sub(tw) / 2;
        let ty = r.y + r.h.saturating_sub(8) / 2;
        self.text(s, tx, ty, c);
    }

    fn render(&mut self) {
        let Some(tpl) = self.tpl.clone() else { return };
        for px in self.buf.iter_mut() {
            *px = C_BG;
        }
        self.hits.clear();
        for ctl in &tpl.controls {
            let r = self.du_to_px(ctl);
            let text = self.texts.get(&ctl.id).cloned().unwrap_or_else(|| ctl.text.clone());
            match ctl.kind {
                ControlKind::Static => {
                    self.text(&text, r.x, r.y + 2, C_TEXT);
                }
                ControlKind::Edit => {
                    self.fill(&r, C_WHITE);
                    self.frame(&r, C_BORDER);
                    self.text(&text, r.x + 3, r.y + r.h.saturating_sub(8) / 2, C_TEXT);
                }
                ControlKind::Button { default } => {
                    self.fill(&r, C_BTN);
                    self.frame(&r, if default { C_DKBORDER } else { C_BORDER });
                    if default {
                        let inner =
                            Rect { x: r.x + 1, y: r.y + 1, w: r.w.saturating_sub(2), h: r.h.saturating_sub(2) };
                        self.frame(&inner, C_DKBORDER);
                    }
                    self.text_centered(&text, &r, C_TEXT);
                    self.hits.push((ctl.id, r));
                }
                ControlKind::Check => {
                    let box_r = Rect { x: r.x, y: r.y + r.h.saturating_sub(12) / 2, w: 12, h: 12 };
                    self.fill(&box_r, C_WHITE);
                    self.frame(&box_r, C_BORDER);
                    self.text(&text, r.x + 16, r.y + r.h.saturating_sub(8) / 2, C_TEXT);
                    self.hits.push((ctl.id, r));
                }
                ControlKind::Progress => {
                    self.fill(&r, C_WHITE);
                    self.frame(&r, C_BORDER);
                    // Draw fill proportional to text "percent" if it parses.
                    if let Ok(p) = text.trim_end_matches('%').parse::<u32>() {
                        let fw = (r.w.saturating_sub(2)) * (p.min(100) as usize) / 100;
                        let bar = Rect { x: r.x + 1, y: r.y + 1, w: fw, h: r.h.saturating_sub(2) };
                        self.fill(&bar, C_PROGRESS);
                    }
                }
                ControlKind::Other => {
                    self.frame(&r, C_BORDER);
                    self.text(&text, r.x + 2, r.y + 2, C_TEXT);
                }
            }
        }
    }

    fn refresh(&mut self) {
        self.render();
        let (w, h) = (self.w, self.h);
        if let Some(win) = self.window.as_mut() {
            let _ = win.update_with_buffer(&self.buf, w, h);
        }
    }
}

impl Gui for MinifbGui {
    fn open(&mut self, tpl: &DialogTemplate) {
        let w = (PAD * 2) + (tpl.cx as f32 * SX) as usize;
        let h = (PAD * 2) + (tpl.cy as f32 * SY) as usize;
        let (w, h) = (w.clamp(240, 1200), h.clamp(120, 900));
        let title = if tpl.title.is_empty() { "exemu" } else { &tpl.title };
        let window = Window::new(title, w, h, WindowOptions::default()).ok();
        self.window = window;
        self.buf = vec![C_BG; w * h];
        self.w = w;
        self.h = h;
        self.texts.clear();
        for c in &tpl.controls {
            if !c.text.is_empty() {
                self.texts.insert(c.id, c.text.clone());
            }
        }
        self.default_id = tpl
            .controls
            .iter()
            .find(|c| matches!(c.kind, ControlKind::Button { default: true }))
            .map(|c| c.id)
            .unwrap_or(1);
        self.tpl = Some(tpl.clone());
        self.prev_down = false;
        if self.window.is_some() {
            eprintln!(
                "[exemu-gui] window \"{}\" — click a button, or press Enter to {} / Esc to cancel",
                tpl.title,
                tpl.controls
                    .iter()
                    .find(|c| c.id == self.default_id)
                    .map(|c| c.text.replace('&', ""))
                    .unwrap_or_else(|| "OK".into()),
            );
        }
        self.refresh();
    }

    fn set_text(&mut self, id: u32, text: &str) {
        self.texts.insert(id, text.to_string());
        self.refresh();
    }

    fn get_text(&self, id: u32) -> Option<String> {
        self.texts.get(&id).cloned()
    }

    fn pump(&mut self, block: bool) -> Option<GuiEvent> {
        let debug = std::env::var_os("EXEMU_GUI_DEBUG").is_some();
        loop {
            let open = self.window.as_ref().map(|w| w.is_open()).unwrap_or(false);
            if !open {
                return Some(GuiEvent::Close);
            }
            // Process OS events + redraw first, THEN read the fresh input.
            self.refresh();

            // Keyboard: Enter activates the default button, Esc cancels — a
            // reliable path that avoids any mouse-coordinate quirks.
            if let Some(w) = self.window.as_ref() {
                if w.is_key_pressed(Key::Enter, KeyRepeat::No)
                    || w.is_key_pressed(Key::NumPadEnter, KeyRepeat::No)
                {
                    if debug {
                        eprintln!("[exemu-gui] Enter -> default button id={}", self.default_id);
                    }
                    return Some(GuiEvent::Command(self.default_id));
                }
                if w.is_key_pressed(Key::Escape, KeyRepeat::No) {
                    return Some(GuiEvent::Command(2)); // IDCANCEL
                }
            }

            let (down, pos) = self
                .window
                .as_ref()
                .map(|w| {
                    (
                        w.get_mouse_down(MouseButton::Left),
                        w.get_mouse_pos(MouseMode::Clamp).unwrap_or((0.0, 0.0)),
                    )
                })
                .unwrap_or((false, (0.0, 0.0)));

            // Fire on the press edge — a physical press is held long enough
            // across polls to be caught, unlike a fast release.
            let pressed = down && !self.prev_down;
            self.prev_down = down;
            if pressed {
                let (mx, my) = (pos.0 as usize, pos.1 as usize);
                let hit = self.hits.iter().find(|(_, r)| r.contains(mx, my)).map(|(id, _)| *id);
                if debug {
                    eprintln!(
                        "[exemu-gui] click at ({mx},{my}) win {}x{} -> {}",
                        self.w,
                        self.h,
                        match hit {
                            Some(id) => format!("control id={id}"),
                            None => {
                                let rects: Vec<_> = self
                                    .hits
                                    .iter()
                                    .map(|(id, r)| format!("{id}:[{},{} {}x{}]", r.x, r.y, r.w, r.h))
                                    .collect();
                                format!("no control (buttons: {})", rects.join(" "))
                            }
                        }
                    );
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
