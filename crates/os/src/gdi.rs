use std::collections::HashMap;

use exemu_core::{DrawOp, Memory, Result};

use crate::WinOs;

pub const HWND_CUSTOM: u64 = 0x00C1_0000;
const HDC_HANDLE: u64 = 0x00DC_0001;

pub const WM_CREATE: u64 = 0x0001;
pub const WM_PAINT: u64 = 0x000F;
pub const WM_DESTROY: u64 = 0x0002;
pub const WM_LBUTTONDOWN: u64 = 0x0201;
pub const WM_CLOSE: u64 = 0x0010;

pub const WM_KEYDOWN: u64 = 0x0100;
pub const WM_KEYUP: u64 = 0x0101;
pub const WM_MOUSEMOVE: u64 = 0x0200;
pub const WM_LBUTTONUP: u64 = 0x0202;
pub const WM_RBUTTONDOWN: u64 = 0x0204;
pub const WM_RBUTTONUP: u64 = 0x0205;
pub const MK_LBUTTON: u64 = 0x0001;
pub const MK_RBUTTON: u64 = 0x0002;

#[derive(Default)]
pub(crate) struct Window {
    pub class: String,
    pub wndproc: u64,
    pub style: u32,
    pub ex_style: u32,
    pub rect: (i32, i32, i32, i32),
    pub parent: u64,
    pub title: Vec<u16>,
    pub userdata: u64,
    pub longs: HashMap<i32, u64>,
    pub props: HashMap<String, u64>,
    pub visible: bool,
    pub paint_pending: bool,
    pub update_rect: (i32, i32, i32, i32),
}

#[derive(Clone, Default)]
pub(crate) struct LogFont {
    pub height: i32,
    pub weight: i32,
    pub italic: bool,
    pub face: String,
}

pub(crate) enum GdiObject {
    Pen(u32),
    Brush(u32),
    Font(LogFont),
}

#[derive(Clone, Default)]
struct DcState {
    text_color: u32,
    pen_color: u32,
    brush_color: u32,
    bk_color: u32,
    bk_mode: u32,
    cur: (i32, i32),
    cur_pen: u64,
    cur_brush: u64,
    cur_font: u64,
}

#[derive(Default)]
pub(crate) struct Gdi {
    pub active: bool,
    pub wndproc: u64,
    pub classes: HashMap<String, u64>,
    pub paint_pending: bool,

    pub windows: HashMap<u64, Window>,
    pub next_hwnd: u64,
    pub active_hwnd: u64,
    pub focus_hwnd: u64,
    pub capture_hwnd: u64,

    pub objects: HashMap<u64, GdiObject>,
    pub next_handle: u64,
    pub text_color: u32,
    pub pen_color: u32,
    pub brush_color: u32,
    pub bk_color: u32,
    pub bk_mode: u32,
    pub cur: (i32, i32),
    pub cur_pen: u64,
    pub cur_brush: u64,
    pub cur_font: u64,
    dc_stack: Vec<DcState>,
}

fn union(a: (i32, i32, i32, i32), b: (i32, i32, i32, i32)) -> (i32, i32, i32, i32) {
    (a.0.min(b.0), a.1.min(b.1), a.2.max(b.2), a.3.max(b.3))
}

fn colorref_to_rgb(c: u32) -> u32 {
    let r = c & 0xff;
    let g = (c >> 8) & 0xff;
    let b = (c >> 16) & 0xff;
    (r << 16) | (g << 8) | b
}

impl WinOs {
    fn read_rect(mem: &dyn Memory, p: u64) -> Result<(i32, i32, i32, i32)> {
        Ok((
            mem.read_u32(p)? as i32,
            mem.read_u32(p + 4)? as i32,
            mem.read_u32(p + 8)? as i32,
            mem.read_u32(p + 12)? as i32,
        ))
    }

    fn alloc_obj(&mut self, obj: GdiObject) -> u64 {
        if self.gdi.next_handle == 0 {
            self.gdi.next_handle = 0x00E0_0000;
        }
        let h = self.gdi.next_handle;
        self.gdi.next_handle += 8;
        self.gdi.objects.insert(h, obj);
        h
    }

    pub(crate) fn register_class(&mut self, mem: &dyn Memory, wc: u64, is_ex: bool) -> Result<u64> {
        let (proc_off, name_off) = match (self.cfg.is_64bit, is_ex) {
            (true, _) => (8, 64),
            (false, false) => (4, 36),
            (false, true) => (8, 40),
        };
        let read_ptr = |off: u64| -> Result<u64> {
            if self.cfg.is_64bit {
                mem.read_u64(wc + off)
            } else {
                Ok(mem.read_u32(wc + off)? as u64)
            }
        };
        let wndproc = read_ptr(proc_off)?;
        let name_ptr = read_ptr(name_off)?;
        let name = crate::api::read_wstr(mem, name_ptr)?;
        self.gdi.classes.insert(name, wndproc);
        Ok(0xC0DE)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_window(
        &mut self,
        mem: &dyn Memory,
        class_name_ptr: u64,
        window_name_ptr: u64,
        style: u32,
        ex_style: u32,
        x: i32,
        y: i32,
        width: i64,
        height: i64,
        parent: u64,
    ) -> Result<u64> {
        let class = crate::api::read_wstr(mem, class_name_ptr)?;
        let Some(&wndproc) = self.gdi.classes.get(&class) else {
            return Ok(crate::api::FAKE_HANDLE);
        };
        let title_units = crate::api::read_wstr_units(mem, window_name_ptr).unwrap_or_default();
        let title = String::from_utf16_lossy(&title_units);
        let w = if width <= 0 || width == 0x8000_0000 { 640 } else { width } as u32;
        let h = if height <= 0 || height == 0x8000_0000 { 480 } else { height } as u32;

        let hwnd = self.alloc_hwnd();
        self.gdi.windows.insert(
            hwnd,
            Window {
                class,
                wndproc,
                style,
                ex_style,
                rect: (x, y, w as i32, h as i32),
                parent,
                title: title_units,
                userdata: 0,
                longs: HashMap::new(),
                props: HashMap::new(),
                visible: false,
                paint_pending: true,
                update_rect: (0, 0, w as i32, h as i32),
            },
        );

        self.gui.open_window(&title, w, h);
        self.gdi.active = true;
        self.gdi.active_hwnd = hwnd;
        self.gdi.wndproc = wndproc;
        self.gdi.paint_pending = true;
        self.gdi.text_color = 0x0000_0000;
        self.gdi.pen_color = 0x0000_0000;
        self.gdi.brush_color = 0x00FF_FFFF;
        Ok(hwnd)
    }

    fn alloc_hwnd(&mut self) -> u64 {
        if self.gdi.next_hwnd == 0 {
            self.gdi.next_hwnd = HWND_CUSTOM;
        }
        let h = self.gdi.next_hwnd;
        self.gdi.next_hwnd += 0x10;
        h
    }

    pub(crate) fn is_custom_window(&self) -> bool {
        self.gdi.active && self.gui.is_open()
    }

    fn window_client(&self, hwnd: u64) -> (i32, i32) {
        self.gdi
            .windows
            .get(&hwnd)
            .map(|w| (w.rect.2, w.rect.3))
            .or_else(|| self.gui.client_size().map(|(w, h)| (w as i32, h as i32)))
            .unwrap_or((640, 480))
    }

    fn update_region(&self, hwnd: u64) -> (bool, (i32, i32, i32, i32)) {
        if let Some(w) = self.gdi.windows.get(&hwnd) {
            (w.paint_pending, w.update_rect)
        } else {
            let (cw, ch) = self.window_client(hwnd);
            (self.gdi.paint_pending, (0, 0, cw, ch))
        }
    }

    pub(crate) fn begin_paint(&mut self, mem: &mut dyn Memory, hwnd: u64, paintstruct: u64) -> Result<u64> {
        let (cw, ch) = self.window_client(hwnd);
        let (pending, rect) = self.update_region(hwnd);
        let rc = if pending { rect } else { (0, 0, cw, ch) };
        if paintstruct != 0 {
            for i in 0..72u64 {
                mem.write_u8(paintstruct + i, 0)?;
            }
            mem.write_u64(paintstruct, HDC_HANDLE)?;
            mem.write_u32(paintstruct + 8, 1)?;
            mem.write_u32(paintstruct + 12, rc.0 as u32)?;
            mem.write_u32(paintstruct + 16, rc.1 as u32)?;
            mem.write_u32(paintstruct + 20, rc.2 as u32)?;
            mem.write_u32(paintstruct + 24, rc.3 as u32)?;
        }
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.paint_pending = false;
            w.update_rect = (0, 0, 0, 0);
        }
        self.gdi.paint_pending = false;
        Ok(HDC_HANDLE)
    }

    pub(crate) fn end_paint(&mut self) {
        self.gui.present();
    }

    pub(crate) fn get_dc(&mut self, _hwnd: u64) -> u64 {
        HDC_HANDLE
    }

    pub(crate) fn invalidate_rect(&mut self, mem: &dyn Memory, hwnd: u64, lprect: u64) -> Result<u64> {
        let (cw, ch) = self.window_client(hwnd);
        let rect = if lprect != 0 { Self::read_rect(mem, lprect)? } else { (0, 0, cw, ch) };
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.update_rect = if w.paint_pending { union(w.update_rect, rect) } else { rect };
            w.paint_pending = true;
        } else {
            self.gdi.paint_pending = true;
        }
        Ok(1)
    }

    pub(crate) fn validate_rect(&mut self, hwnd: u64) -> u64 {
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.paint_pending = false;
            w.update_rect = (0, 0, 0, 0);
        }
        self.gdi.paint_pending = false;
        1
    }

    pub(crate) fn get_update_rect(&mut self, mem: &mut dyn Memory, hwnd: u64, lprect: u64) -> Result<u64> {
        let (pending, rect) = self.update_region(hwnd);
        let r = if pending { rect } else { (0, 0, 0, 0) };
        if lprect != 0 {
            mem.write_u32(lprect, r.0 as u32)?;
            mem.write_u32(lprect + 4, r.1 as u32)?;
            mem.write_u32(lprect + 8, r.2 as u32)?;
            mem.write_u32(lprect + 12, r.3 as u32)?;
        }
        Ok(pending as u64)
    }

    pub(crate) fn create_solid_brush(&mut self, colorref: u32) -> u64 {
        self.alloc_obj(GdiObject::Brush(colorref_to_rgb(colorref)))
    }

    pub(crate) fn create_pen(&mut self, colorref: u32) -> u64 {
        self.alloc_obj(GdiObject::Pen(colorref_to_rgb(colorref)))
    }

    pub(crate) fn create_font_indirect(&mut self, mem: &dyn Memory, lplf: u64) -> Result<u64> {
        let height = mem.read_u32(lplf)? as i32;
        let weight = mem.read_u32(lplf + 16)? as i32;
        let italic = mem.read_u8(lplf + 20)? != 0;
        let face = crate::api::read_wstr(mem, lplf + 28).unwrap_or_default();
        Ok(self.alloc_obj(GdiObject::Font(LogFont { height, weight, italic, face })))
    }

    pub(crate) fn get_object(&self, mem: &mut dyn Memory, hobj: u64, cb: u64, out: u64, wide: bool) -> Result<u64> {
        let Some(GdiObject::Font(lf)) = self.gdi.objects.get(&hobj) else {
            return Ok(0);
        };
        let (height, weight, italic, face) = (lf.height, lf.weight, lf.italic, lf.face.clone());
        let size: u64 = if wide { 92 } else { 60 };
        if out != 0 && cb >= 28 {
            for i in 0..size.min(cb) {
                mem.write_u8(out + i, 0)?;
            }
            mem.write_u32(out, height as u32)?;
            mem.write_u32(out + 16, weight as u32)?;
            mem.write_u8(out + 20, u8::from(italic))?;
            if wide {
                WinOs::write_wstr(mem, out + 28, &face, 32)?;
            } else {
                crate::api::write_astr(mem, out + 28, &face, 32)?;
            }
        }
        Ok(size)
    }

    pub(crate) fn get_stock_object(&mut self, index: u64) -> u64 {
        let obj = match index {
            0 => GdiObject::Brush(0x00FF_FFFF),
            1 => GdiObject::Brush(0x00C0_C0C0),
            2 => GdiObject::Brush(0x0080_8080),
            4 => GdiObject::Brush(0x0000_0000),
            5 => GdiObject::Brush(0x00FF_FFFF),
            7 => GdiObject::Pen(0x0000_0000),
            8 => GdiObject::Pen(0x00FF_FFFF),
            10..=17 => GdiObject::Font(LogFont::default()),
            _ => GdiObject::Brush(0x0000_0000),
        };
        self.alloc_obj(obj)
    }

    pub(crate) fn select_object(&mut self, obj: u64) -> u64 {
        match self.gdi.objects.get(&obj) {
            Some(GdiObject::Pen(c)) => {
                let (c, prev) = (*c, self.gdi.cur_pen);
                self.gdi.pen_color = c;
                self.gdi.cur_pen = obj;
                prev
            }
            Some(GdiObject::Brush(c)) => {
                let (c, prev) = (*c, self.gdi.cur_brush);
                self.gdi.brush_color = c;
                self.gdi.cur_brush = obj;
                prev
            }
            Some(GdiObject::Font(_)) => {
                let prev = self.gdi.cur_font;
                self.gdi.cur_font = obj;
                prev
            }
            None => 0,
        }
    }

    pub(crate) fn save_dc(&mut self) -> u64 {
        let g = &self.gdi;
        let state = DcState {
            text_color: g.text_color,
            pen_color: g.pen_color,
            brush_color: g.brush_color,
            bk_color: g.bk_color,
            bk_mode: g.bk_mode,
            cur: g.cur,
            cur_pen: g.cur_pen,
            cur_brush: g.cur_brush,
            cur_font: g.cur_font,
        };
        self.gdi.dc_stack.push(state);
        self.gdi.dc_stack.len() as u64
    }

    pub(crate) fn restore_dc(&mut self, level: i64) -> u64 {
        let depth = self.gdi.dc_stack.len() as i64;
        let target = if level < 0 { depth + level } else { level - 1 };
        if target < 0 || target >= depth {
            return 0;
        }
        self.gdi.dc_stack.truncate(target as usize + 1);
        let Some(s) = self.gdi.dc_stack.pop() else { return 0 };
        self.gdi.text_color = s.text_color;
        self.gdi.pen_color = s.pen_color;
        self.gdi.brush_color = s.brush_color;
        self.gdi.bk_color = s.bk_color;
        self.gdi.bk_mode = s.bk_mode;
        self.gdi.cur = s.cur;
        self.gdi.cur_pen = s.cur_pen;
        self.gdi.cur_brush = s.cur_brush;
        self.gdi.cur_font = s.cur_font;
        1
    }

    pub(crate) fn set_text_color(&mut self, colorref: u32) -> u64 {
        let prev = self.gdi.text_color;
        self.gdi.text_color = colorref_to_rgb(colorref);
        prev as u64
    }

    pub(crate) fn set_bk_color(&mut self, colorref: u32) -> u64 {
        let prev = self.gdi.bk_color;
        self.gdi.bk_color = colorref_to_rgb(colorref);
        prev as u64
    }

    pub(crate) fn set_bk_mode(&mut self, mode: u32) -> u64 {
        let prev = self.gdi.bk_mode;
        self.gdi.bk_mode = mode;
        prev as u64
    }

    pub(crate) fn gdi_fill_rect(&mut self, mem: &dyn Memory, rect: u64, brush: u64) -> Result<()> {
        let (l, t, r, b) = Self::read_rect(mem, rect)?;
        let color = match self.gdi.objects.get(&brush) {
            Some(GdiObject::Brush(c)) => *c,
            _ => self.gdi.brush_color,
        };
        self.gui.draw(&DrawOp::FillRect { x: l, y: t, w: r - l, h: b - t, color });
        Ok(())
    }

    pub(crate) fn gdi_rectangle(&mut self, l: i32, t: i32, r: i32, b: i32) {
        self.gui.draw(&DrawOp::FillRect { x: l, y: t, w: r - l, h: b - t, color: self.gdi.brush_color });
        self.gui.draw(&DrawOp::FrameRect { x: l, y: t, w: r - l, h: b - t, color: self.gdi.pen_color });
    }

    pub(crate) fn gdi_text_out(&mut self, x: i32, y: i32, text: &str) {
        self.gui.draw(&DrawOp::Text { x, y, text: text.to_string(), color: self.gdi.text_color });
    }

    pub(crate) fn gdi_line_to(&mut self, x: i32, y: i32) {
        let (x0, y0) = self.gdi.cur;
        self.gui.draw(&DrawOp::Line { x0, y0, x1: x, y1: y, color: self.gdi.pen_color });
        self.gdi.cur = (x, y);
    }

    pub(crate) fn gdi_move_to(&mut self, x: i32, y: i32) {
        self.gdi.cur = (x, y);
    }

    pub(crate) fn gdi_set_pixel(&mut self, x: i32, y: i32, colorref: u32) {
        self.gui.draw(&DrawOp::Pixel { x, y, color: colorref_to_rgb(colorref) });
    }
}
