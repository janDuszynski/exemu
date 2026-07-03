//! Window-independent dialog rendering into a 32-bit software framebuffer.
//! Shared by the live [`crate::MinifbGui`] window and the offscreen
//! [`crate::OffscreenGui`] (which saves PNGs for headless testing).

use std::collections::{HashMap, HashSet};

use exemu_core::gui::{Control, ControlKind, DialogTemplate};
use font8x8::UnicodeFonts;

// Dialog-unit → pixel scale (approximate MS Shell Dlg base units).
pub const SX: f32 = 1.75;
pub const SY: f32 = 1.8;
pub const PAD: usize = 8;

const C_BG: u32 = 0x00F0_F0F0;
const C_TEXT: u32 = 0x0000_0000;
const C_GRAY_TEXT: u32 = 0x00A0_A0A0;
const C_WHITE: u32 = 0x00FF_FFFF;
const C_BTN: u32 = 0x00E1_E1E1;
const C_BTN_DIS: u32 = 0x00D0_D0D0;
const C_BORDER: u32 = 0x00A0_A0A0;
const C_DKBORDER: u32 = 0x0050_5050;
const C_PROGRESS: u32 = 0x0006_B025;

/// Extra pixels added around a button's clickable area, so a near-miss still
/// registers.
const HIT_PAD: usize = 5;

#[derive(Clone)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl Rect {
    pub fn contains(&self, px: usize, py: usize) -> bool {
        px >= self.x && px < self.x + self.w && py >= self.y && py < self.y + self.h
    }
}

/// A framebuffer plus the geometry needed to draw a dialog and hit-test it.
pub struct Renderer {
    pub buf: Vec<u32>,
    pub w: usize,
    pub h: usize,
    /// Clickable control hit rectangles in pixels, refreshed on each paint.
    pub hits: Vec<(u32, Rect)>,
}

impl Renderer {
    /// Pixel size for a dialog of `cx` x `cy` dialog units, clamped sanely.
    pub fn size_for(tpl: &DialogTemplate) -> (usize, usize) {
        let w = (PAD * 2) + (tpl.cx as f32 * SX) as usize;
        let h = (PAD * 2) + (tpl.cy as f32 * SY) as usize;
        (w.clamp(240, 1200), h.clamp(120, 900))
    }

    pub fn new(w: usize, h: usize) -> Self {
        Renderer { buf: vec![C_BG; w * h], w, h, hits: Vec::new() }
    }

    fn du_to_px(&self, c: &Control) -> Rect {
        Rect {
            x: PAD + (c.x as f32 * SX) as usize,
            y: PAD + (c.y as f32 * SY) as usize,
            w: (c.cx as f32 * SX) as usize,
            h: (c.cy as f32 * SY) as usize,
        }
    }

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

    /// Paint the whole dialog from `tpl` + current `texts`, refreshing `hits`.
    /// Controls in `disabled` are greyed and not clickable.
    pub fn paint(&mut self, tpl: &DialogTemplate, texts: &HashMap<u32, String>, disabled: &HashSet<u32>) {
        for px in self.buf.iter_mut() {
            *px = C_BG;
        }
        self.hits.clear();
        for ctl in &tpl.controls {
            let r = self.du_to_px(ctl);
            let text = texts.get(&ctl.id).cloned().unwrap_or_else(|| ctl.text.clone());
            let off = disabled.contains(&ctl.id);
            let push_hit = |hits: &mut Vec<(u32, Rect)>, id: u32, r: &Rect| {
                hits.push((
                    id,
                    Rect {
                        x: r.x.saturating_sub(HIT_PAD),
                        y: r.y.saturating_sub(HIT_PAD),
                        w: r.w + 2 * HIT_PAD,
                        h: r.h + 2 * HIT_PAD,
                    },
                ));
            };
            match ctl.kind {
                ControlKind::Static => self.text(&text, r.x, r.y + 2, C_TEXT),
                ControlKind::Edit => {
                    self.fill(&r, C_WHITE);
                    self.frame(&r, C_BORDER);
                    self.text(&text, r.x + 3, r.y + r.h.saturating_sub(8) / 2, C_TEXT);
                }
                ControlKind::Button { default } => {
                    self.fill(&r, if off { C_BTN_DIS } else { C_BTN });
                    self.frame(&r, if default && !off { C_DKBORDER } else { C_BORDER });
                    if default && !off {
                        let inner = Rect { x: r.x + 1, y: r.y + 1, w: r.w.saturating_sub(2), h: r.h.saturating_sub(2) };
                        self.frame(&inner, C_DKBORDER);
                    }
                    // Drop the '&' accelerator marker for display.
                    self.text_centered(&text.replace('&', ""), &r, if off { C_GRAY_TEXT } else { C_TEXT });
                    if !off {
                        push_hit(&mut self.hits, ctl.id, &r);
                    }
                }
                ControlKind::Check => {
                    let box_r = Rect { x: r.x, y: r.y + r.h.saturating_sub(12) / 2, w: 12, h: 12 };
                    self.fill(&box_r, C_WHITE);
                    self.frame(&box_r, C_BORDER);
                    self.text(&text, r.x + 16, r.y + r.h.saturating_sub(8) / 2, if off { C_GRAY_TEXT } else { C_TEXT });
                    if !off {
                        push_hit(&mut self.hits, ctl.id, &r);
                    }
                }
                ControlKind::Progress => {
                    self.fill(&r, C_WHITE);
                    self.frame(&r, C_BORDER);
                    if let Ok(p) = text.trim_end_matches('%').parse::<u32>() {
                        let fw = r.w.saturating_sub(2) * (p.min(100) as usize) / 100;
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

    pub fn hit_test(&self, x: usize, y: usize) -> Option<u32> {
        self.hits.iter().find(|(_, r)| r.contains(x, y)).map(|(id, _)| *id)
    }

    /// Apply one emulated-GDI drawing op to the framebuffer (for custom
    /// windows). Negative coordinates are clamped into the buffer.
    pub fn apply(&mut self, op: &exemu_core::DrawOp) {
        use exemu_core::DrawOp::*;
        let clamp = |v: i32| v.max(0) as usize;
        let rect = |x: i32, y: i32, w: i32, h: i32| Rect {
            x: clamp(x),
            y: clamp(y),
            w: w.max(0) as usize,
            h: h.max(0) as usize,
        };
        match op {
            Clear(c) => self.buf.iter_mut().for_each(|p| *p = *c),
            FillRect { x, y, w, h, color } => self.fill(&rect(*x, *y, *w, *h), *color),
            FrameRect { x, y, w, h, color } => self.frame(&rect(*x, *y, *w, *h), *color),
            Text { x, y, text, color } => self.text(text, clamp(*x), clamp(*y), *color),
            Line { x0, y0, x1, y1, color } => self.line(*x0, *y0, *x1, *y1, *color),
            Pixel { x, y, color } => self.px(clamp(*x), clamp(*y), *color),
        }
    }

    fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {
        // Bresenham.
        let (mut x0, mut y0) = (x0, y0);
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            if x0 >= 0 && y0 >= 0 {
                self.px(x0 as usize, y0 as usize, color);
            }
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    /// The framebuffer as tightly-packed RGBA bytes (for PNG output).
    pub fn to_rgba(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.w * self.h * 4);
        for &p in &self.buf {
            out.push((p >> 16) as u8);
            out.push((p >> 8) as u8);
            out.push(p as u8);
            out.push(0xff);
        }
        out
    }
}
