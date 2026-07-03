//! A minimal, generic Win32 window + GDI layer.
//!
//! Enough of `RegisterClass`/`CreateWindowEx`, the message loop, and the GDI
//! drawing primitives that an app which paints its own window (rather than
//! using a dialog template) actually renders. Drawing is translated into
//! [`DrawOp`]s and handed to the GUI backend's framebuffer.
//!
//! This is a small subset — it covers solid fills, framed rectangles, text,
//! lines and pixels with the current pen/brush/text colors. It is not GDI+,
//! not DirectX, and not pixel-accurate to Windows.

use std::collections::HashMap;

use exemu_core::{DrawOp, Memory, Result};

use crate::WinOs;

/// Synthetic handle bases.
pub const HWND_CUSTOM: u64 = 0x00C1_0000;
const HDC_HANDLE: u64 = 0x00DC_0001;

/// Window-message ids used here.
pub const WM_CREATE: u64 = 0x0001;
pub const WM_PAINT: u64 = 0x000F;
pub const WM_DESTROY: u64 = 0x0002;
pub const WM_LBUTTONDOWN: u64 = 0x0201;
pub const WM_CLOSE: u64 = 0x0010;

/// Custom-window + GDI state.
#[derive(Default)]
pub(crate) struct Gdi {
    /// A custom window is shown (drives GetMessage/DispatchMessage routing).
    pub active: bool,
    /// The window's WndProc.
    pub wndproc: u64,
    /// Registered window classes: class name → WndProc.
    pub classes: HashMap<String, u64>,
    /// A WM_PAINT is due.
    pub paint_pending: bool,

    /// GDI object handle → packed 0x00RRGGBB color.
    pub objects: HashMap<u64, u32>,
    pub next_handle: u64,
    pub text_color: u32,
    pub pen_color: u32,
    pub brush_color: u32,
    pub cur: (i32, i32),
}

/// Convert a Win32 COLORREF (0x00BBGGRR) to packed 0x00RRGGBB.
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

    fn alloc_gdi(&mut self, color: u32) -> u64 {
        if self.gdi.next_handle == 0 {
            self.gdi.next_handle = 0x00E0_0000;
        }
        let h = self.gdi.next_handle;
        self.gdi.next_handle += 8;
        self.gdi.objects.insert(h, color);
        h
    }

    // ---- window class + creation -----------------------------------------

    /// RegisterClass(Ex)W: record the class's WndProc by name. Field offsets
    /// of `lpfnWndProc` and `lpszClassName` in WNDCLASS(EX)W depend on bitness
    /// (and, in 32-bit, on the leading `cbSize` of the EX form).
    pub(crate) fn register_class(&mut self, mem: &dyn Memory, wc: u64, is_ex: bool) -> Result<u64> {
        let (proc_off, name_off) = match (self.cfg.is_64bit, is_ex) {
            (true, _) => (8, 64),      // x64: same for W and EX
            (false, false) => (4, 36), // WNDCLASSW (x86)
            (false, true) => (8, 40),  // WNDCLASSEXW (x86)
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
        Ok(0xC0DE) // a non-zero ATOM
    }

    /// CreateWindowExW: if the class has a registered WndProc, open a real
    /// window and remember its proc. Returns the window handle.
    pub(crate) fn create_window(
        &mut self,
        mem: &dyn Memory,
        class_name_ptr: u64,
        window_name_ptr: u64,
        width: i64,
        height: i64,
    ) -> Result<u64> {
        let class = crate::api::read_wstr(mem, class_name_ptr)?;
        let Some(&wndproc) = self.gdi.classes.get(&class) else {
            // Unknown class → just a fake handle (child controls etc.).
            return Ok(crate::api::FAKE_HANDLE);
        };
        let title = crate::api::read_wstr(mem, window_name_ptr).unwrap_or_default();
        // CW_USEDEFAULT (0x80000000) → a sensible default size.
        let w = if width <= 0 || width == 0x8000_0000 { 640 } else { width } as u32;
        let h = if height <= 0 || height == 0x8000_0000 { 480 } else { height } as u32;
        self.gui.open_window(&title, w, h);
        self.gdi.active = true;
        self.gdi.wndproc = wndproc;
        self.gdi.paint_pending = true;
        self.gdi.text_color = 0x0000_0000;
        self.gdi.pen_color = 0x0000_0000;
        self.gdi.brush_color = 0x00FF_FFFF;
        Ok(HWND_CUSTOM)
    }

    pub(crate) fn is_custom_window(&self) -> bool {
        self.gdi.active && self.gui.is_open()
    }

    // ---- device contexts + painting --------------------------------------

    pub(crate) fn begin_paint(&mut self, mem: &mut dyn Memory, paintstruct: u64) -> Result<u64> {
        // PAINTSTRUCT: hdc @0, fErase @8, rcPaint @12.. — write hdc, zero rest.
        if paintstruct != 0 {
            for i in 0..64u64 {
                mem.write_u8(paintstruct + i, 0)?;
            }
            mem.write_u64(paintstruct, HDC_HANDLE)?;
        }
        Ok(HDC_HANDLE)
    }

    pub(crate) fn end_paint(&mut self) {
        self.gui.present();
    }

    pub(crate) fn get_client_rect(&self, mem: &mut dyn Memory, lprect: u64) -> Result<()> {
        let (w, h) = self.gui.client_size().unwrap_or((640, 480));
        if lprect != 0 {
            mem.write_u32(lprect, 0)?;
            mem.write_u32(lprect + 4, 0)?;
            mem.write_u32(lprect + 8, w)?;
            mem.write_u32(lprect + 12, h)?;
        }
        Ok(())
    }

    // ---- GDI object management -------------------------------------------

    pub(crate) fn create_solid_brush(&mut self, colorref: u32) -> u64 {
        self.alloc_gdi(colorref_to_rgb(colorref))
    }

    /// CreatePen(style, width, colorref) — we only track the color.
    pub(crate) fn create_pen(&mut self, colorref: u32) -> u64 {
        self.alloc_gdi(colorref_to_rgb(colorref))
    }

    /// GetStockObject: map the common stock objects to colors.
    pub(crate) fn get_stock_object(&mut self, index: u64) -> u64 {
        let color = match index {
            0 => 0x00FF_FFFF, // WHITE_BRUSH
            1 => 0x00C0_C0C0, // LTGRAY_BRUSH
            2 => 0x0080_8080, // GRAY_BRUSH
            4 => 0x0000_0000, // BLACK_BRUSH
            5 => 0x00FF_FFFF, // NULL_BRUSH (treat as white)
            7 => 0x0000_0000, // BLACK_PEN
            8 => 0x00FF_FFFF, // WHITE_PEN
            _ => 0x0000_0000,
        };
        self.alloc_gdi(color)
    }

    /// SelectObject: adopt the object's color as the current pen/brush/text.
    /// We can't tell pen from brush from the handle alone, so update all —
    /// callers select one right before using it, which is good enough here.
    pub(crate) fn select_object(&mut self, obj: u64) -> u64 {
        if let Some(&color) = self.gdi.objects.get(&obj) {
            self.gdi.pen_color = color;
            self.gdi.brush_color = color;
        }
        obj
    }

    pub(crate) fn set_text_color(&mut self, colorref: u32) -> u64 {
        let prev = self.gdi.text_color;
        self.gdi.text_color = colorref_to_rgb(colorref);
        prev as u64
    }

    // ---- GDI drawing → DrawOps -------------------------------------------

    pub(crate) fn gdi_fill_rect(&mut self, mem: &dyn Memory, rect: u64, brush: u64) -> Result<()> {
        let (l, t, r, b) = Self::read_rect(mem, rect)?;
        let color = self.gdi.objects.get(&brush).copied().unwrap_or(self.gdi.brush_color);
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
