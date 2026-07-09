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

/// A real Win32 window object (roadmap P5a.2). Keyed by its HWND in
/// [`Gdi::windows`], so guest code that stores an HWND and later queries it
/// (`GetWindowLongPtr`, `GetProp`, `IsWindow`, subclassing) sees consistent
/// per-window state instead of a single shared fake.
#[derive(Default)]
pub(crate) struct Window {
    pub class: String,
    pub wndproc: u64,
    pub style: u32,
    pub ex_style: u32,
    /// Screen rectangle as (x, y, width, height).
    pub rect: (i32, i32, i32, i32),
    pub parent: u64,
    pub title: Vec<u16>,
    /// GWLP_USERDATA.
    pub userdata: u64,
    /// Extra window-long slots (`cbWndExtra` bytes / non-standard GWL indices)
    /// keyed by byte offset, so `Get/SetWindowLongPtr` round-trips arbitrary
    /// per-window data (dialog/control frameworks stash state here).
    pub longs: HashMap<i32, u64>,
    /// SetProp/GetProp store (property name → handle value).
    pub props: HashMap<String, u64>,
    pub visible: bool,
    /// A `WM_PAINT` is owed for this window (roadmap P5a.4).
    pub paint_pending: bool,
    /// The accumulated invalid rectangle (left, top, right, bottom).
    pub update_rect: (i32, i32, i32, i32),
}

/// Custom-window + GDI state.
#[derive(Default)]
pub(crate) struct Gdi {
    /// A custom window is shown (drives GetMessage/DispatchMessage routing).
    pub active: bool,
    /// The top-level window's WndProc (legacy single-window rendering path).
    pub wndproc: u64,
    /// Registered window classes: class name → WndProc.
    pub classes: HashMap<String, u64>,
    /// A WM_PAINT is due.
    pub paint_pending: bool,

    /// Real window objects by HWND (roadmap P5a.2).
    pub windows: HashMap<u64, Window>,
    /// Monotonic HWND allocator (lazily seeded to [`HWND_CUSTOM`]).
    pub next_hwnd: u64,
    /// The top-level window shown by the GUI backend (target of WM_PAINT/input).
    pub active_hwnd: u64,
    /// The window with keyboard focus (`SetFocus`/`GetFocus`), roadmap P5a.3.
    pub focus_hwnd: u64,
    /// The window that has captured the mouse (`SetCapture`/`GetCapture`).
    pub capture_hwnd: u64,

    /// GDI object handle → packed 0x00RRGGBB color.
    pub objects: HashMap<u64, u32>,
    pub next_handle: u64,
    pub text_color: u32,
    pub pen_color: u32,
    pub brush_color: u32,
    pub cur: (i32, i32),
}

/// Union of two rectangles (left, top, right, bottom).
fn union(a: (i32, i32, i32, i32), b: (i32, i32, i32, i32)) -> (i32, i32, i32, i32) {
    (a.0.min(b.0), a.1.min(b.1), a.2.max(b.2), a.3.max(b.3))
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

    /// CreateWindowExW: if the class has a registered WndProc, allocate a real
    /// window object (roadmap P5a.2), open the GUI window, and return the real
    /// HWND. Unknown classes (child controls etc.) yield a fake handle.
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
            // Unknown class → just a fake handle (child controls etc.).
            return Ok(crate::api::FAKE_HANDLE);
        };
        let title_units = crate::api::read_wstr_units(mem, window_name_ptr).unwrap_or_default();
        let title = String::from_utf16_lossy(&title_units);
        // CW_USEDEFAULT (0x80000000) → a sensible default size.
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
                paint_pending: true, // a fresh window owes its first WM_PAINT
                update_rect: (0, 0, w as i32, h as i32),
            },
        );

        // The first top-level window drives the (single-window) GUI backend.
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

    /// Allocate a fresh, distinct HWND value.
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

    // ---- device contexts + painting (roadmap P5a.4) ----------------------

    /// A window's client size `(w, h)` (falls back to the GUI backend's size,
    /// then 640×480, for dialog/unknown HWNDs).
    fn window_client(&self, hwnd: u64) -> (i32, i32) {
        self.gdi
            .windows
            .get(&hwnd)
            .map(|w| (w.rect.2, w.rect.3))
            .or_else(|| self.gui.client_size().map(|(w, h)| (w as i32, h as i32)))
            .unwrap_or((640, 480))
    }

    /// The pending invalid rectangle for `hwnd` (or the whole client if none).
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
        // PAINTSTRUCT (x64): hdc @0, fErase @8, rcPaint @12 (l,t,r,b), rest 0.
        if paintstruct != 0 {
            for i in 0..72u64 {
                mem.write_u8(paintstruct + i, 0)?;
            }
            mem.write_u64(paintstruct, HDC_HANDLE)?;
            mem.write_u32(paintstruct + 8, 1)?; // fErase = TRUE
            mem.write_u32(paintstruct + 12, rc.0 as u32)?;
            mem.write_u32(paintstruct + 16, rc.1 as u32)?;
            mem.write_u32(paintstruct + 20, rc.2 as u32)?;
            mem.write_u32(paintstruct + 24, rc.3 as u32)?;
        }
        // The paint is now being serviced.
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

    /// GetDC(hWnd)/GetWindowDC → the (currently single) device context.
    pub(crate) fn get_dc(&mut self, _hwnd: u64) -> u64 {
        HDC_HANDLE
    }

    /// InvalidateRect(hWnd, lpRect, bErase): mark a region as needing repaint.
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

    /// ValidateRect(hWnd, lpRect): clear the pending paint (whole-window; partial
    /// subtraction is not modelled).
    pub(crate) fn validate_rect(&mut self, hwnd: u64) -> u64 {
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.paint_pending = false;
            w.update_rect = (0, 0, 0, 0);
        }
        self.gdi.paint_pending = false;
        1
    }

    /// GetUpdateRect(hWnd, lpRect, bErase) → TRUE if a paint is pending.
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
