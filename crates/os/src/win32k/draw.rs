use std::borrow::Cow;

use exemu_core::{CpuState, Memory, Result};

use super::{
    alloc_gdi_object, alloc_memory_dc, colorref_to_bgra, gdi_client_object, gdi_type,
    read_unicode_string, Bitmap, DC_ATTR_BK_COLOR, DC_ATTR_TEXT_COLOR, NT_GDI_CREATE_PEN,
    NT_GDI_PAT_BLT, NT_GDI_SELECT_PEN, SURFACE_BPP,
};
use crate::gdi_draw::{
    self as g, Blit, Brush, DibInfo, PixelFormat, Pixmap, Rect, SrcSpec, MAX_PIXELS,
};
use crate::WinOs;

pub(super) const NT_GDI_BIT_BLT: u32 = 0x1097;
pub(super) const NT_GDI_STRETCH_BLT: u32 = 0x128f;
pub(super) const NT_GDI_GET_PIXEL: u32 = 0x1217;
pub(super) const NT_GDI_SET_DIBITS_TO_DEVICE: u32 = 0x1278;
pub(super) const NT_GDI_STRETCH_DIBITS: u32 = 0x1290;
pub(super) const NT_GDI_MOVE_TO: u32 = 0x1243;
pub(super) const NT_GDI_LINE_TO: u32 = 0x123a;
pub(super) const NT_GDI_CREATE_PATTERN_BRUSH: u32 = 0x10b9;
pub(super) const NT_GDI_OPEN_DCW: u32 = 0x1246;

const SRCCOPY: u32 = 0x00CC_0020;
const DIB_RGB_COLORS: u32 = 0;
const DIB_MAX_BYTES: u64 = MAX_PIXELS * 4;
const BITFIELDS_MASKS_BYTES: usize = 12;
const DIB_INFO_HEADER_SIZE: usize = 40;
const DIB_COMPRESSION_OFF: usize = 16;
const PS_STYLE_MASK: u32 = 0xF;
const PS_NULL: u32 = 5;
const PEN_SLOT_WHITE: u32 = 0x26;
const PEN_SLOT_BLACK: u32 = 0x27;
const PEN_SLOT_NULL: u32 = 0x28;
const MAX_PATTERN_PIXELS: u64 = 1 << 20;
const BLACK_RGB: u32 = 0;
const POINT_SIZE: u64 = 8;
const GDI_FAIL: u32 = 0;
const CLR_INVALID: u32 = 0xFFFF_FFFF;
const COLORREF_MASK: u32 = 0x00FF_FFFF;
const WHITE_RGB: u32 = 0x00FF_FFFF;

#[derive(Clone, Copy)]
struct Pen {
    style: u32,
    color: u32,
}

struct PatternBrush {
    pix: Pixmap,
    mono: bool,
}

#[derive(Default)]
pub(super) struct DrawState {
    formats: Vec<(u32, PixelFormat)>,
    pens: Vec<(u32, Pen)>,
    patterns: Vec<(u32, PatternBrush)>,
}

fn stock_pen_handle(slot: u32) -> u32 {
    ((gdi_type::PEN as u32) << 16) | slot
}

impl DrawState {
    pub(super) fn forget(&mut self, handle: u32) {
        self.formats.retain(|(h, _)| *h != handle);
        self.pens.retain(|(h, _)| *h != handle);
        self.patterns.retain(|(h, _)| *h != handle);
    }

    fn pen(&self, handle: u32) -> Option<Pen> {
        if let Some((_, p)) = self.pens.iter().find(|(h, _)| *h == handle) {
            return Some(*p);
        }
        let solid = |color| Some(Pen { style: 0, color });
        match handle {
            h if h == stock_pen_handle(PEN_SLOT_WHITE) => solid(WHITE_RGB),
            h if h == stock_pen_handle(PEN_SLOT_BLACK) => solid(BLACK_RGB),
            h if h == stock_pen_handle(PEN_SLOT_NULL) => Some(Pen { style: PS_NULL, color: 0 }),
            _ => None,
        }
    }

    fn format(&self, handle: u32) -> Option<&PixelFormat> {
        self.formats.iter().find(|(h, _)| *h == handle).map(|(_, f)| f)
    }
}

struct Image {
    base: u64,
    w: i32,
    h: i32,
    stride: usize,
    top_down: bool,
    format: PixelFormat,
}

impl Image {
    fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.w, self.h)
    }

    fn row_addr(&self, y: i32) -> u64 {
        let row = if self.top_down { y } else { self.h - 1 - y };
        self.base + row as u64 * self.stride as u64
    }

    fn byte_span(&self, x0: i32, n: i32) -> (usize, usize) {
        let bpp = self.format.bpp as usize;
        let lo = x0 as usize * bpp / 8;
        let hi = ((x0 + n) as usize * bpp).div_ceil(8);
        (lo, hi.min(self.stride))
    }

    fn load(&self, mem: &dyn Memory, rect: Rect) -> Result<Pixmap> {
        let rect = rect.intersect(&self.bounds());
        let mut pix = Pixmap::new(rect, 0);
        if rect.is_empty() {
            return Ok(pix);
        }
        let (lo, hi) = self.byte_span(rect.l, rect.width());
        let mut row = vec![0u8; self.stride];
        for y in rect.t..rect.b {
            mem.read(self.row_addr(y) + lo as u64, &mut row[lo..hi])?;
            g::decode_row(&self.format, &row, rect.l as usize, pix.row_mut(y));
        }
        Ok(pix)
    }

    fn store(&self, mem: &mut dyn Memory, pix: &Pixmap) -> Result<()> {
        let rect = pix.rect.intersect(&self.bounds());
        if rect.is_empty() {
            return Ok(());
        }
        let (lo, hi) = self.byte_span(rect.l, rect.width());
        let mut row = vec![0u8; self.stride];
        for y in rect.t..rect.b {
            let addr = self.row_addr(y) + lo as u64;
            mem.read(addr, &mut row[lo..hi])?;
            g::encode_row(&self.format, &mut row, rect.l as usize, pix.row(y));
            mem.write(addr, &row[lo..hi])?;
        }
        Ok(())
    }
}

struct Canvas {
    image: Image,
    org: (i32, i32),
    clip: Rect,
    mono_ddb: bool,
}

fn default_format(bpp: u32) -> PixelFormat {
    let palette = match bpp {
        1 => g::mono_palette(),
        4 | 8 => {
            let n = 1u32 << bpp;
            (0..n)
                .map(|i| {
                    let v = i * 255 / (n - 1);
                    v << 16 | v << 8 | v
                })
                .collect()
        }
        _ => Vec::new(),
    };
    PixelFormat { bpp, palette, masks: None }
}

fn bitmap_image(os: &WinOs, handle: u32, b: &Bitmap) -> Option<Image> {
    if !g::bpp_supported(b.bpp) || b.w <= 0 || b.h <= 0 {
        return None;
    }
    let format = os
        .win32k_state
        .draw
        .format(handle)
        .cloned()
        .unwrap_or_else(|| default_format(b.bpp));
    Some(Image {
        base: b.bits,
        w: b.w,
        h: b.h,
        stride: b.stride as usize,
        top_down: b.top_down,
        format,
    })
}

fn canvas(os: &WinOs, hdc: u32) -> Option<Canvas> {
    let dc = os.win32k_state.dc(hdc)?;
    if dc.hwnd == 0 {
        let b = os.win32k_state.bitmap(dc.bitmap)?;
        let image = bitmap_image(os, dc.bitmap, &b)?;
        let mono_ddb = b.bpp == 1 && os.win32k_state.draw.format(dc.bitmap).is_none();
        let clip = image.bounds();
        return Some(Canvas { image, org: (0, 0), clip, mono_ddb });
    }
    let owner = os.win32k_state.surface_owner(dc.hwnd);
    let s = os.win32k_state.window(owner)?.surface?;
    let image = Image {
        base: s.base,
        w: s.w as i32,
        h: s.h as i32,
        stride: s.w as usize * 4,
        top_down: true,
        format: PixelFormat { bpp: SURFACE_BPP, palette: Vec::new(), masks: None },
    };
    let clip = Rect::new(dc.clip[0], dc.clip[1], dc.clip[2], dc.clip[3]).intersect(&image.bounds());
    Some(Canvas { image, org: dc.org, clip, mono_ddb: false })
}

fn dc_colors(os: &WinOs, mem: &dyn Memory, hdc: u32) -> (u32, u32) {
    let read = |off, default| {
        gdi_client_object(os, mem, hdc)
            .and_then(|obj| mem.read_u32(obj + off).ok())
            .unwrap_or(default)
    };
    (
        colorref_to_bgra(read(DC_ATTR_TEXT_COLOR, 0)),
        colorref_to_bgra(read(DC_ATTR_BK_COLOR, WHITE_RGB)),
    )
}

fn resolve_brush(os: &WinOs, mem: &dyn Memory, hdc: u32) -> Option<Brush> {
    let handle = os.win32k_state.dc(hdc).map_or(0, |d| d.brush);
    if handle == 0 {
        return Some(Brush::Solid(colorref_to_bgra(WHITE_RGB)));
    }
    if let Some((_, pattern)) = os.win32k_state.draw.patterns.iter().find(|(h, _)| *h == handle) {
        let mut pix = pattern.pix.clone();
        if pattern.mono {
            let (text, bk) = dc_colors(os, mem, hdc);
            recolor_mono(&mut pix, text, bk);
        }
        return Some(Brush::Pattern(pix));
    }
    if let Some((_, color)) = os.win32k_state.brushes.iter().find(|(h, _)| *h == handle) {
        return Some(Brush::Solid(colorref_to_bgra(*color)));
    }
    None
}

enum SrcData<'a> {
    Canvas(&'a Canvas),
    Pixels(&'a Pixmap),
}

struct SrcRef<'a> {
    data: SrcData<'a>,
    rect: Rect,
}

struct Transfer<'a> {
    dest: Rect,
    src: Option<SrcRef<'a>>,
    flip: (bool, bool),
    rop: u32,
}

fn transfer(
    os: &WinOs,
    mem: &mut dyn Memory,
    hdc: u32,
    dst: &Canvas,
    t: &Transfer,
) -> Result<bool> {
    let visible = t.dest.intersect(&dst.clip);
    if visible.is_empty() {
        return Ok(true);
    }
    if visible.area() > MAX_PIXELS {
        return Ok(false);
    }
    let brush = if g::rop_uses_pattern(t.rop) {
        match resolve_brush(os, mem, hdc) {
            Some(b) => b,
            None => return Ok(true),
        }
    } else {
        Brush::Solid(0)
    };
    let src_pix: Option<Cow<Pixmap>> = if g::rop_uses_source(t.rop) {
        let Some(src) = &t.src else { return Ok(false) };
        Some(match &src.data {
            SrcData::Pixels(p) => Cow::Borrowed(*p),
            SrcData::Canvas(c) => {
                let unscaled = t.dest.width() == src.rect.width()
                    && t.dest.height() == src.rect.height()
                    && t.flip == (false, false);
                let needed = if unscaled {
                    visible.offset(src.rect.l - t.dest.l, src.rect.t - t.dest.t)
                } else {
                    src.rect
                }
                .intersect(&c.image.bounds());
                if needed.area() > MAX_PIXELS {
                    return Ok(false);
                }
                let mut pix = c.image.load(mem, needed)?;
                if c.mono_ddb {
                    let (text, bk) = dc_colors(os, mem, hdc);
                    recolor_mono(&mut pix, text, bk);
                }
                Cow::Owned(pix)
            }
        })
    } else {
        None
    };
    let mut dpix = dst.image.load(mem, visible)?;
    let spec = Blit {
        dest: t.dest,
        src: match (&src_pix, &t.src) {
            (Some(pix), Some(src)) => Some(SrcSpec { pix: pix.as_ref(), rect: src.rect }),
            _ => None,
        },
        flip_x: t.flip.0,
        flip_y: t.flip.1,
        rop: t.rop,
        brush: &brush,
        brush_org: dst.org,
    };
    g::blit(&mut dpix, &spec);
    dst.image.store(mem, &dpix)?;
    Ok(true)
}

fn recolor_mono(pix: &mut Pixmap, text: u32, bk: u32) {
    let rect = pix.rect;
    for y in rect.t..rect.b {
        for v in pix.row_mut(y) {
            *v = if *v & COLORREF_MASK == 0 { text } else { bk };
        }
    }
}

fn dest_rect(dst: &Canvas, x: i32, y: i32, w: i32, h: i32) -> Rect {
    Rect::from_extent(x, y, w, h).offset(dst.org.0, dst.org.1)
}

fn src_rect(src: &Canvas, x: i32, y: i32, w: i32, h: i32) -> Rect {
    Rect::from_extent(x, y, w, h).offset(src.org.0, src.org.1)
}

pub(super) fn nt_gdi_bit_blt(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let dst_dc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let w = os.syscall_arg_u32(cpu, mem, 3)? as i32;
    let h = os.syscall_arg_u32(cpu, mem, 4)? as i32;
    let src_dc = os.syscall_arg_u32(cpu, mem, 5)?;
    let sx = os.syscall_arg_u32(cpu, mem, 6)? as i32;
    let sy = os.syscall_arg_u32(cpu, mem, 7)? as i32;
    let rop = os.syscall_arg_u32(cpu, mem, 8)?;
    blt(os, mem, dst_dc, (x, y, w, h), src_dc, (sx, sy, w, h), rop)
}

pub(super) fn nt_gdi_stretch_blt(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let dst_dc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let w = os.syscall_arg_u32(cpu, mem, 3)? as i32;
    let h = os.syscall_arg_u32(cpu, mem, 4)? as i32;
    let src_dc = os.syscall_arg_u32(cpu, mem, 5)?;
    let sx = os.syscall_arg_u32(cpu, mem, 6)? as i32;
    let sy = os.syscall_arg_u32(cpu, mem, 7)? as i32;
    let sw = os.syscall_arg_u32(cpu, mem, 8)? as i32;
    let sh = os.syscall_arg_u32(cpu, mem, 9)? as i32;
    let rop = os.syscall_arg_u32(cpu, mem, 10)?;
    blt(os, mem, dst_dc, (x, y, w, h), src_dc, (sx, sy, sw, sh), rop)
}

fn blt(
    os: &WinOs,
    mem: &mut dyn Memory,
    dst_dc: u32,
    dst: (i32, i32, i32, i32),
    src_dc: u32,
    src: (i32, i32, i32, i32),
    rop: u32,
) -> Result<u32> {
    let Some(dcanvas) = canvas(os, dst_dc) else { return Ok(GDI_FAIL) };
    let scanvas = if g::rop_uses_source(rop) {
        match canvas(os, src_dc) {
            Some(c) => Some(c),
            None => return Ok(GDI_FAIL),
        }
    } else {
        None
    };
    let flip = ((dst.2 < 0) != (src.2 < 0), (dst.3 < 0) != (src.3 < 0));
    let t = Transfer {
        dest: dest_rect(&dcanvas, dst.0, dst.1, dst.2, dst.3),
        src: scanvas
            .as_ref()
            .map(|c| SrcRef {
            data: SrcData::Canvas(c),
            rect: src_rect(c, src.0, src.1, src.2, src.3),
        }),
        flip,
        rop,
    };
    Ok(u32::from(transfer(os, mem, dst_dc, &dcanvas, &t)?))
}

pub(super) fn nt_gdi_pat_blt(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let w = os.syscall_arg_u32(cpu, mem, 3)? as i32;
    let h = os.syscall_arg_u32(cpu, mem, 4)? as i32;
    let rop = os.syscall_arg_u32(cpu, mem, 5)?;
    if g::rop_uses_source(rop) {
        return Ok(GDI_FAIL);
    }
    let Some(dcanvas) = canvas(os, hdc) else { return Ok(GDI_FAIL) };
    let t = Transfer { dest: dest_rect(&dcanvas, x, y, w, h), src: None, flip: (false, false), rop };
    Ok(u32::from(transfer(os, mem, hdc, &dcanvas, &t)?))
}

pub(super) fn nt_gdi_get_pixel(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let Some(c) = canvas(os, hdc) else { return Ok(CLR_INVALID) };
    let rect = Rect::from_extent(x, y, 1, 1).offset(c.org.0, c.org.1);
    if rect.intersect(&c.clip).is_empty() {
        return Ok(CLR_INVALID);
    }
    let pix = c.image.load(mem, rect)?;
    let v = pix.get(rect.l, rect.t).unwrap_or(0);
    Ok(((v & 0xFF) << 16) | (v & 0xFF00) | ((v >> 16) & 0xFF))
}

fn read_dib_info(mem: &dyn Memory, bmi: u64) -> Option<DibInfo> {
    let mut first = [0u8; 4];
    mem.read(bmi, &mut first).ok()?;
    let header = g::dib_header_size(u32::from_le_bytes(first))?;
    let mut buf = vec![0u8; header];
    mem.read(bmi, &mut buf).ok()?;
    let compression = buf
        .get(DIB_COMPRESSION_OFF..DIB_COMPRESSION_OFF + 4)
        .map_or(g::BI_RGB, |c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
    if header == DIB_INFO_HEADER_SIZE && compression == g::BI_BITFIELDS {
        buf.resize(header + BITFIELDS_MASKS_BYTES, 0);
        mem.read(bmi + header as u64, &mut buf[header..]).ok()?;
    }
    let total = DibInfo::parse(&buf)?.total_header_len();
    if total > buf.len() {
        let have = buf.len();
        buf.resize(total, 0);
        mem.read(bmi + have as u64, &mut buf[have..]).ok()?;
    }
    DibInfo::parse(&buf)
}

fn read_dib_bits(mem: &dyn Memory, info: &DibInfo, bits: u64, rows: u32) -> Option<Vec<u8>> {
    let len = (info.stride() as u64).checked_mul(rows as u64)?;
    if len > DIB_MAX_BYTES {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    mem.read(bits, &mut buf).ok()?;
    Some(buf)
}

fn dib_usable(info: &DibInfo, usage: u32) -> bool {
    info.decodable() && (info.bpp > 8 || usage == DIB_RGB_COLORS)
}

pub(super) fn record_dib_format(os: &mut WinOs, mem: &dyn Memory, handle: u32, bmi: u64) {
    if let Some(info) = read_dib_info(mem, bmi).filter(|i| g::bpp_supported(i.bpp)) {
        os.win32k_state.draw.formats.push((handle, info.format));
    }
}

pub(super) fn nt_gdi_set_dibits_to_device(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let cx = os.syscall_arg_u32(cpu, mem, 3)?;
    let cy = os.syscall_arg_u32(cpu, mem, 4)?;
    let limit = g::COORD_LIMIT;
    let xs = (os.syscall_arg_u32(cpu, mem, 5)? as i32).clamp(-limit, limit);
    let ys = (os.syscall_arg_u32(cpu, mem, 6)? as i32).clamp(-limit, limit);
    let start = os.syscall_arg_u32(cpu, mem, 7)?;
    let lines = os.syscall_arg_u32(cpu, mem, 8)?;
    let bits = os.syscall_arg(cpu, mem, 9)?;
    let bmi = os.syscall_arg(cpu, mem, 10)?;
    let usage = os.syscall_arg_u32(cpu, mem, 11)?;
    if bits == 0 || bmi == 0 || cx > limit as u32 || cy > limit as u32 {
        return Ok(GDI_FAIL);
    }
    let Some(info) = read_dib_info(mem, bmi).filter(|i| dib_usable(i, usage)) else {
        return Ok(GDI_FAIL);
    };
    let rows = lines.min((info.height as u32).saturating_sub(start));
    let Some(buf) = read_dib_bits(mem, &info, bits, rows) else { return Ok(GDI_FAIL) };
    let Some(scans) = g::decode_scans(&info, &buf, start, rows) else { return Ok(GDI_FAIL) };
    let Some(dcanvas) = canvas(os, hdc) else { return Ok(GDI_FAIL) };
    let (cx, cy) = (cx as i32, cy as i32);
    let visual = g::visual_source(&info, &scans, xs, ys, cx, cy);
    let t = Transfer {
        dest: dest_rect(&dcanvas, x, y, cx, cy),
        src: Some(SrcRef {
            data: SrcData::Pixels(&visual),
            rect: Rect::from_extent(xs, 0, cx, cy),
        }),
        flip: (false, false),
        rop: SRCCOPY,
    };
    if !transfer(os, mem, hdc, &dcanvas, &t)? {
        return Ok(GDI_FAIL);
    }
    Ok(rows)
}

pub(super) fn nt_gdi_stretch_dibits(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let cx = os.syscall_arg_u32(cpu, mem, 3)? as i32;
    let cy = os.syscall_arg_u32(cpu, mem, 4)? as i32;
    let xs = os.syscall_arg_u32(cpu, mem, 5)? as i32;
    let ys = os.syscall_arg_u32(cpu, mem, 6)? as i32;
    let cxs = os.syscall_arg_u32(cpu, mem, 7)? as i32;
    let cys = os.syscall_arg_u32(cpu, mem, 8)? as i32;
    let bits = os.syscall_arg(cpu, mem, 9)?;
    let bmi = os.syscall_arg(cpu, mem, 10)?;
    let usage = os.syscall_arg_u32(cpu, mem, 11)?;
    let rop = os.syscall_arg_u32(cpu, mem, 12)?;
    if bits == 0 || bmi == 0 {
        return Ok(GDI_FAIL);
    }
    let Some(info) = read_dib_info(mem, bmi).filter(|i| dib_usable(i, usage)) else {
        return Ok(GDI_FAIL);
    };
    let rows = info.height as u32;
    let Some(buf) = read_dib_bits(mem, &info, bits, rows) else { return Ok(GDI_FAIL) };
    let Some(scans) = g::decode_scans(&info, &buf, 0, rows) else { return Ok(GDI_FAIL) };
    let Some(dcanvas) = canvas(os, hdc) else { return Ok(GDI_FAIL) };
    let srect = Rect::from_extent(xs, ys, cxs, cys);
    let visual = g::visual_source(&info, &scans, srect.l, srect.t, srect.width(), srect.height());
    let t = Transfer {
        dest: dest_rect(&dcanvas, x, y, cx, cy),
        src: Some(SrcRef {
            data: SrcData::Pixels(&visual),
            rect: Rect::new(srect.l, 0, srect.r, srect.height()),
        }),
        flip: ((cx < 0) != (cxs < 0), (cy < 0) != (cys < 0)),
        rop,
    };
    if !transfer(os, mem, hdc, &dcanvas, &t)? {
        return Ok(GDI_FAIL);
    }
    Ok(srect.height() as u32)
}

pub(super) fn nt_gdi_create_pen(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let style = os.syscall_arg_u32(cpu, mem, 0)?;
    let color = os.syscall_arg_u32(cpu, mem, 2)?;
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::PEN)? else { return Ok(GDI_FAIL) };
    let pen = Pen { style: style & PS_STYLE_MASK, color };
    os.win32k_state.draw.pens.push((handle, pen));
    Ok(handle)
}

pub(super) fn nt_gdi_select_pen(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let pen = os.syscall_arg_u32(cpu, mem, 1)?;
    if os.win32k_state.draw.pen(pen).is_none() {
        return Ok(GDI_FAIL);
    }
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(GDI_FAIL);
    };
    let previous = std::mem::replace(&mut dc.pen, pen);
    Ok(if previous == 0 { stock_pen_handle(PEN_SLOT_BLACK) } else { previous })
}

pub(super) fn nt_gdi_move_to(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let out = os.syscall_arg(cpu, mem, 3)?;
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(GDI_FAIL);
    };
    let previous = std::mem::replace(&mut dc.pos, (x, y));
    if out != 0 {
        let mut point = [0u8; POINT_SIZE as usize];
        point[..4].copy_from_slice(&previous.0.to_le_bytes());
        point[4..].copy_from_slice(&previous.1.to_le_bytes());
        if mem.write(out, &point).is_err() {
            return Ok(GDI_FAIL);
        }
    }
    Ok(1)
}

pub(super) fn nt_gdi_line_to(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg_u32(cpu, mem, 0)?;
    let limit = g::COORD_LIMIT;
    let x = (os.syscall_arg_u32(cpu, mem, 1)? as i32).clamp(-limit, limit);
    let y = (os.syscall_arg_u32(cpu, mem, 2)? as i32).clamp(-limit, limit);
    let Some(dcanvas) = canvas(os, hdc) else { return Ok(GDI_FAIL) };
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(GDI_FAIL);
    };
    let (from, pen_handle) = (dc.pos, dc.pen);
    dc.pos = (x, y);
    let pen = os.win32k_state.draw.pen(pen_handle).unwrap_or(Pen { style: 0, color: BLACK_RGB });
    if pen.style == PS_NULL {
        return Ok(1);
    }
    let (ox, oy) = dcanvas.org;
    let from = (from.0.clamp(-limit, limit) + ox, from.1.clamp(-limit, limit) + oy);
    let points: Vec<(i32, i32)> = g::Bresenham::new(from.0, from.1, x + ox, y + oy)
        .filter(|(px, py)| dcanvas.clip.contains(*px, *py))
        .collect();
    let (Some(l), Some(t)) = (
        points.iter().map(|p| p.0).min(),
        points.iter().map(|p| p.1).min(),
    ) else {
        return Ok(1);
    };
    let r = points.iter().map(|p| p.0).max().unwrap_or(l) + 1;
    let b = points.iter().map(|p| p.1).max().unwrap_or(t) + 1;
    let bbox = Rect::new(l, t, r, b);
    if bbox.area() > MAX_PIXELS {
        return Ok(GDI_FAIL);
    }
    let mut pix = dcanvas.image.load(mem, bbox)?;
    let color = colorref_to_bgra(pen.color);
    for (px, py) in points {
        let alpha = pix.get(px, py).unwrap_or(0) & 0xFF00_0000;
        pix.set(px, py, alpha | (color & 0x00FF_FFFF));
    }
    dcanvas.image.store(mem, &pix)?;
    Ok(1)
}

pub(super) fn nt_gdi_create_pattern_brush(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hbm = os.syscall_arg_u32(cpu, mem, 0)?;
    let Some(b) = os.win32k_state.bitmap(hbm) else { return Ok(GDI_FAIL) };
    let Some(image) = bitmap_image(os, hbm, &b) else { return Ok(GDI_FAIL) };
    if image.bounds().area() > MAX_PATTERN_PIXELS {
        return Ok(GDI_FAIL);
    }
    let pix = image.load(mem, image.bounds())?;
    let mono = b.bpp == 1 && os.win32k_state.draw.format(hbm).is_none();
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::BRUSH)? else {
        return Ok(GDI_FAIL);
    };
    os.win32k_state.draw.patterns.push((handle, PatternBrush { pix, mono }));
    Ok(handle)
}

pub(super) fn nt_gdi_open_dcw(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let device = os.syscall_arg(cpu, mem, 0)?;
    let is_display = os.syscall_arg_u32(cpu, mem, 4)? != 0;
    let name = if device == 0 { String::new() } else { read_unicode_string(mem, device).unwrap_or_default() };
    if !is_display && !name.to_ascii_uppercase().contains("DISPLAY") {
        return Ok(GDI_FAIL);
    }
    alloc_memory_dc(os, mem)
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_GDI_BIT_BLT, nt_gdi_bit_blt);
    os.set_win32k_handler(NT_GDI_STRETCH_BLT, nt_gdi_stretch_blt);
    os.set_win32k_handler(NT_GDI_PAT_BLT, nt_gdi_pat_blt);
    os.set_win32k_handler(NT_GDI_GET_PIXEL, nt_gdi_get_pixel);
    os.set_win32k_handler(NT_GDI_SET_DIBITS_TO_DEVICE, nt_gdi_set_dibits_to_device);
    os.set_win32k_handler(NT_GDI_STRETCH_DIBITS, nt_gdi_stretch_dibits);
    os.set_win32k_handler(NT_GDI_CREATE_PEN, nt_gdi_create_pen);
    os.set_win32k_handler(NT_GDI_SELECT_PEN, nt_gdi_select_pen);
    os.set_win32k_handler(NT_GDI_MOVE_TO, nt_gdi_move_to);
    os.set_win32k_handler(NT_GDI_LINE_TO, nt_gdi_line_to);
    os.set_win32k_handler(NT_GDI_CREATE_PATTERN_BRUSH, nt_gdi_create_pattern_brush);
    os.set_win32k_handler(NT_GDI_OPEN_DCW, nt_gdi_open_dcw);
}

#[cfg(test)]
mod tests {
    use exemu_core::{Perm, Reg, Region};
    use exemu_memory::VirtualMemory;

    use super::*;
    use crate::win32k::{alloc_bitmap, alloc_brush, alloc_memory_dc, nt_gdi_select_bitmap, nt_gdi_select_brush};

    const PEB: u64 = 0x7F00_0000;
    const STACK: u64 = 0x10_8000;
    const SRCCOPY: u64 = 0x00CC_0020;
    const SRCINVERT: u64 = 0x0066_0046;
    const PATCOPY: u64 = 0x00F0_0021;
    const DSTINVERT: u64 = 0x0055_0009;
    const BLACKNESS: u64 = 0x0000_0042;

    fn harness() -> (WinOs, VirtualMemory) {
        let mut os =
            WinOs::new(crate::WinConfig { is_64bit: true, peb_addr: PEB, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", 0x10_0000, 0x20_000, Perm::RW)).unwrap();
        os.set_syscall_guest_rsp_for_test(STACK);
        (os, mem)
    }

    fn call(
        f: fn(&mut WinOs, &mut CpuState, &mut dyn Memory) -> Result<u32>,
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        args: &[u64],
    ) -> u32 {
        let mut cpu = CpuState::default();
        for (i, a) in args.iter().enumerate() {
            match i {
                0 => cpu.set_reg(Reg::R10, *a),
                1 => cpu.set_reg(Reg::Rdx, *a),
                2 => cpu.set_reg(Reg::R8, *a),
                3 => cpu.set_reg(Reg::R9, *a),
                n => mem.write_u64(STACK + 0x28 + (n as u64 - 4) * 8, *a).unwrap(),
            }
        }
        f(os, &mut cpu, mem).unwrap()
    }

    fn dc_with_bitmap(os: &mut WinOs, mem: &mut VirtualMemory, w: i32, h: i32, bpp: u32, top_down: bool) -> (u32, u32) {
        let hdc = alloc_memory_dc(os, mem).unwrap();
        let hbm = alloc_bitmap(os, mem, w, h, 1, bpp, top_down).unwrap();
        assert_ne!(hbm, 0);
        call(nt_gdi_select_bitmap, os, mem, &[hdc as u64, hbm as u64]);
        (hdc, hbm)
    }

    fn put(mem: &mut VirtualMemory, os: &WinOs, hbm: u32, x: i32, y: i32, bgra: u32) {
        let b = os.win32k_state.bitmap(hbm).unwrap();
        let row = if b.top_down { y } else { b.h - 1 - y };
        let at = b.bits + row as u64 * b.stride as u64 + x as u64 * 4;
        mem.write_u32(at, bgra).unwrap();
    }

    fn pixel(mem: &VirtualMemory, os: &WinOs, hbm: u32, x: i32, y: i32) -> u32 {
        let b = os.win32k_state.bitmap(hbm).unwrap();
        let row = if b.top_down { y } else { b.h - 1 - y };
        mem.read_u32(b.bits + row as u64 * b.stride as u64 + x as u64 * 4).unwrap()
    }

    #[test]
    fn bitblt_copies_between_two_memory_dcs_including_a_bottom_up_one() {
        let (mut os, mut mem) = harness();
        let (src, sbm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
        let (dst, dbm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, false);
        for y in 0..4 {
            for x in 0..4 {
                put(&mut mem, &os, sbm, x, y, 0xFF00_0000 | (y as u32) << 8 | x as u32);
            }
        }
        let ok = call(nt_gdi_bit_blt, &mut os, &mut mem, &[dst as u64, 1, 1, 3, 3, src as u64, 0, 0, SRCCOPY]);
        assert_eq!(ok, 1);
        assert_eq!(pixel(&mem, &os, dbm, 1, 1) & 0xFF_FFFF, 0x0000);
        assert_eq!(pixel(&mem, &os, dbm, 3, 2) & 0xFF_FFFF, 0x0102);
        assert_eq!(pixel(&mem, &os, dbm, 3, 3) & 0xFF_FFFF, 0x0202);
        assert_eq!(pixel(&mem, &os, dbm, 0, 0), 0, "outside the copied rectangle is untouched");
    }

    #[test]
    fn bitblt_without_a_source_dc_fails_for_a_source_rop_and_works_for_blackness() {
        let (mut os, mut mem) = harness();
        let (dst, dbm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        put(&mut mem, &os, dbm, 0, 0, 0xFFAB_CDEF);
        assert_eq!(call(nt_gdi_bit_blt, &mut os, &mut mem, &[dst as u64, 0, 0, 2, 2, 0, 0, 0, SRCCOPY]), 0);
        assert_eq!(pixel(&mem, &os, dbm, 0, 0), 0xFFAB_CDEF);
        assert_eq!(call(nt_gdi_bit_blt, &mut os, &mut mem, &[dst as u64, 0, 0, 2, 2, 0, 0, 0, BLACKNESS]), 1);
        assert_eq!(pixel(&mem, &os, dbm, 0, 0), 0xFF00_0000);
    }

    #[test]
    fn bitblt_onto_its_own_bitmap_with_overlap_moves_like_memmove() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 8, 1, 32, true);
        for x in 0..8 {
            put(&mut mem, &os, bm, x, 0, 0xFF00_0000 | x as u32 + 1);
        }
        call(nt_gdi_bit_blt, &mut os, &mut mem, &[dc as u64, 2, 0, 6, 1, dc as u64, 0, 0, SRCCOPY]);
        let row: Vec<u32> = (0..8).map(|x| pixel(&mem, &os, bm, x, 0) & 0xFF).collect();
        assert_eq!(row, [1, 2, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn dstinvert_and_srcinvert_flip_bits_in_place() {
        let (mut os, mut mem) = harness();
        let (a, abm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 32, true);
        let (b, bbm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 32, true);
        put(&mut mem, &os, abm, 0, 0, 0xFF12_3456);
        put(&mut mem, &os, bbm, 0, 0, 0xFFFF_0000);
        call(nt_gdi_bit_blt, &mut os, &mut mem, &[a as u64, 0, 0, 1, 1, b as u64, 0, 0, SRCINVERT]);
        assert_eq!(pixel(&mem, &os, abm, 0, 0), 0xFFED_3456);
        call(nt_gdi_bit_blt, &mut os, &mut mem, &[a as u64, 0, 0, 1, 1, 0, 0, 0, DSTINVERT]);
        assert_eq!(pixel(&mem, &os, abm, 0, 0), 0xFF12_CBA9);
    }

    #[test]
    fn patblt_and_bitblt_patcopy_fill_with_the_selected_solid_brush() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
        let brush = alloc_brush(&mut os, &mut mem, 0x00_33_22_11).unwrap();
        call(nt_gdi_select_brush, &mut os, &mut mem, &[dc as u64, brush as u64]);
        assert_eq!(call(nt_gdi_pat_blt, &mut os, &mut mem, &[dc as u64, 1, 1, 2, 2, PATCOPY]), 1);
        assert_eq!(pixel(&mem, &os, bm, 1, 1), 0x0011_2233);
        assert_eq!(pixel(&mem, &os, bm, 0, 0), 0);
        call(nt_gdi_bit_blt, &mut os, &mut mem, &[dc as u64, 0, 0, 1, 1, 0, 0, 0, PATCOPY]);
        assert_eq!(pixel(&mem, &os, bm, 0, 0) & 0xFF_FFFF, 0x1122_33);
    }

    #[test]
    fn get_pixel_returns_a_colorref_and_clr_invalid_outside() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, false);
        put(&mut mem, &os, bm, 1, 0, 0xFF11_2233);
        assert_eq!(call(nt_gdi_get_pixel, &mut os, &mut mem, &[dc as u64, 1, 0]), 0x0033_2211);
        assert_eq!(call(nt_gdi_get_pixel, &mut os, &mut mem, &[dc as u64, 2, 0]), CLR_INVALID);
        assert_eq!(call(nt_gdi_get_pixel, &mut os, &mut mem, &[dc as u64, 0, u64::from(u32::MAX)]), CLR_INVALID);
        assert_eq!(call(nt_gdi_get_pixel, &mut os, &mut mem, &[0, 0, 0]), CLR_INVALID);
    }

    #[test]
    fn stretchblt_doubles_a_bitmap_nearest_neighbour_and_mirrors_on_a_negative_width() {
        let (mut os, mut mem) = harness();
        let (src, sbm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 32, true);
        let (dst, dbm) = dc_with_bitmap(&mut os, &mut mem, 4, 1, 32, true);
        put(&mut mem, &os, sbm, 0, 0, 0xFF00_00AA);
        put(&mut mem, &os, sbm, 1, 0, 0xFF00_00BB);
        let args = [dst as u64, 0, 0, 4, 1, src as u64, 0, 0, 2, 1, SRCCOPY];
        assert_eq!(call(nt_gdi_stretch_blt, &mut os, &mut mem, &args), 1);
        let row: Vec<u32> = (0..4).map(|x| pixel(&mem, &os, dbm, x, 0) & 0xFF).collect();
        assert_eq!(row, [0xAA, 0xAA, 0xBB, 0xBB]);
        let mirrored = [dst as u64, 4, 0, (-4i32) as u32 as u64, 1, src as u64, 0, 0, 2, 1, SRCCOPY];
        call(nt_gdi_stretch_blt, &mut os, &mut mem, &mirrored);
        let row: Vec<u32> = (0..4).map(|x| pixel(&mem, &os, dbm, x, 0) & 0xFF).collect();
        assert_eq!(row, [0xBB, 0xBB, 0xAA, 0xAA]);
    }

    #[test]
    fn a_monochrome_bitmap_blits_in_the_destination_text_and_background_colours() {
        let (mut os, mut mem) = harness();
        let (src, sbm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 1, true);
        let (dst, dbm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 32, true);
        let b = os.win32k_state.bitmap(sbm).unwrap();
        mem.write_u8(b.bits, 0b0100_0000).unwrap();
        assert_eq!(call(nt_gdi_bit_blt, &mut os, &mut mem, &[dst as u64, 0, 0, 2, 1, src as u64, 0, 0, SRCCOPY]), 1);
        assert_eq!(pixel(&mem, &os, dbm, 0, 0) & 0xFF_FFFF, 0, "a 0 bit takes the text colour, black by default");
        assert_eq!(pixel(&mem, &os, dbm, 1, 0) & 0xFF_FFFF, 0xFF_FFFF, "a 1 bit takes the background colour");
    }

    #[test]
    fn nothing_is_drawn_to_a_dc_without_a_bitmap_and_giant_rects_do_not_allocate() {
        let (mut os, mut mem) = harness();
        let bare = alloc_memory_dc(&mut os, &mut mem).unwrap();
        assert_eq!(call(nt_gdi_bit_blt, &mut os, &mut mem, &[bare as u64, 0, 0, 1, 1, 0, 0, 0, BLACKNESS]), 0);
        let (dc, _) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
        let huge = [dc as u64, 0x8000_0000, 0x8000_0000, 0x7FFF_FFFF, 0x7FFF_FFFF, 0, 0, 0, BLACKNESS];
        assert_eq!(call(nt_gdi_bit_blt, &mut os, &mut mem, &huge), 1);
    }

    const BMI: u64 = 0x11_0000;
    const BITS: u64 = 0x11_4000;
    const RED: u32 = 0x00FF_0000;
    const GREEN: u32 = 0x0000_FF00;
    const BLUE: u32 = 0x0000_00FF;
    const WHITE: u32 = 0x00FF_FFFF;

    fn write_bmi(mem: &mut VirtualMemory, width: i32, height: i32, bpp: u16, palette: &[u32]) {
        let mut h = vec![0u8; 40];
        h[0..4].copy_from_slice(&40u32.to_le_bytes());
        h[4..8].copy_from_slice(&width.to_le_bytes());
        h[8..12].copy_from_slice(&height.to_le_bytes());
        h[12..14].copy_from_slice(&1u16.to_le_bytes());
        h[14..16].copy_from_slice(&bpp.to_le_bytes());
        h[32..36].copy_from_slice(&(palette.len() as u32).to_le_bytes());
        for c in palette {
            h.extend_from_slice(&[*c as u8, (*c >> 8) as u8, (*c >> 16) as u8, 0]);
        }
        mem.write(BMI, &h).unwrap();
    }

    fn rgb(mem: &VirtualMemory, os: &WinOs, hbm: u32, x: i32, y: i32) -> u32 {
        pixel(mem, os, hbm, x, y) & 0xFF_FFFF
    }

    fn setdib(
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        hdc: u32,
        dest: (i32, i32, u32, u32),
        src: (i32, i32),
        scans: (u32, u32),
        usage: u64,
    ) -> u32 {
        let a = [
            hdc as u64,
            dest.0 as u32 as u64,
            dest.1 as u32 as u64,
            dest.2 as u64,
            dest.3 as u64,
            src.0 as u32 as u64,
            src.1 as u32 as u64,
            scans.0 as u64,
            scans.1 as u64,
            BITS,
            BMI,
            usage,
        ];
        call(nt_gdi_set_dibits_to_device, os, mem, &a)
    }

    fn fill_four(mem: &mut VirtualMemory, values: [u32; 4]) {
        for (i, v) in values.iter().enumerate() {
            mem.write_u32(BITS + i as u64 * 4, *v).unwrap();
        }
    }

    #[test]
    fn set_dibits_places_a_bottom_up_dib_with_its_last_scanline_on_top() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
        write_bmi(&mut mem, 2, 2, 32, &[]);
        fill_four(&mut mem, [RED, GREEN, BLUE, WHITE]);
        assert_eq!(setdib(&mut os, &mut mem, dc, (1, 1, 2, 2), (0, 0), (0, 2), 0), 2);
        assert_eq!(rgb(&mem, &os, bm, 1, 1), BLUE);
        assert_eq!(rgb(&mem, &os, bm, 2, 1), WHITE);
        assert_eq!(rgb(&mem, &os, bm, 1, 2), RED);
        assert_eq!(rgb(&mem, &os, bm, 2, 2), GREEN);
        assert_eq!(pixel(&mem, &os, bm, 0, 0), 0);
        assert_eq!(pixel(&mem, &os, bm, 3, 3), 0);
    }

    #[test]
    fn set_dibits_keeps_a_top_down_dib_upright() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        write_bmi(&mut mem, 2, -2, 32, &[]);
        fill_four(&mut mem, [RED, GREEN, BLUE, WHITE]);
        setdib(&mut os, &mut mem, dc, (0, 0, 2, 2), (0, 0), (0, 2), 0);
        assert_eq!(rgb(&mem, &os, bm, 0, 0), RED);
        assert_eq!(rgb(&mem, &os, bm, 1, 1), WHITE);
    }

    #[test]
    fn set_dibits_decodes_every_depth_to_the_same_four_colours() {
        let palette = [RED, GREEN, BLUE, WHITE];
        let cases: [(u16, Vec<u32>, Vec<u8>); 5] = [
            (4, palette.to_vec(), vec![0x01, 0x23, 0, 0]),
            (8, palette.to_vec(), vec![0, 1, 2, 3]),
            (
                16,
                vec![],
                [0x7C00u16, 0x03E0, 0x001F, 0x7FFF].iter().flat_map(|v| v.to_le_bytes()).collect(),
            ),
            (24, vec![], vec![0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 0, 0, 0, 0]),
            (32, vec![], palette.iter().flat_map(|v| v.to_le_bytes()).collect()),
        ];
        for (bpp, pal, bytes) in cases {
            let (mut os, mut mem) = harness();
            let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 1, 32, true);
            write_bmi(&mut mem, 4, 1, bpp, &pal);
            mem.write(BITS, &bytes).unwrap();
            assert_eq!(setdib(&mut os, &mut mem, dc, (0, 0, 4, 1), (0, 0), (0, 1), 0), 1, "{bpp} bpp");
            let got: Vec<u32> = (0..4).map(|x| rgb(&mem, &os, bm, x, 0)).collect();
            assert_eq!(got, palette, "{bpp} bpp");
        }
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 1, 32, true);
        write_bmi(&mut mem, 4, 1, 1, &[0, WHITE]);
        mem.write(BITS, &[0b1010_0000, 0, 0, 0]).unwrap();
        setdib(&mut os, &mut mem, dc, (0, 0, 4, 1), (0, 0), (0, 1), 0);
        let got: Vec<u32> = (0..4).map(|x| rgb(&mem, &os, bm, x, 0)).collect();
        assert_eq!(got, [WHITE, 0, WHITE, 0]);
    }

    #[test]
    fn set_dibits_clips_at_every_destination_edge_and_honours_the_source_origin() {
        for (dx, dy) in [(-1, 0), (3, 0), (0, -1), (0, 3), (-1, -1), (3, 3)] {
            let (mut os, mut mem) = harness();
            let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
            write_bmi(&mut mem, 2, -2, 32, &[]);
            fill_four(&mut mem, [0xFF00_0001, 0xFF00_0002, 0xFF00_0003, 0xFF00_0004]);
            assert_eq!(setdib(&mut os, &mut mem, dc, (dx, dy, 2, 2), (0, 0), (0, 2), 0), 2);
            for y in 0..4 {
                for x in 0..4 {
                    let (sx, sy) = (x - dx, y - dy);
                    let inside = (0..2).contains(&sx) && (0..2).contains(&sy);
                    let want = if inside { (sy * 2 + sx + 1) as u32 } else { 0 };
                    assert_eq!(rgb(&mem, &os, bm, x, y), want, "dest ({dx},{dy}) pixel ({x},{y})");
                }
            }
        }
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        write_bmi(&mut mem, 2, -2, 32, &[]);
        fill_four(&mut mem, [1, 2, 3, 4]);
        setdib(&mut os, &mut mem, dc, (0, 0, 1, 1), (1, 1), (0, 2), 0);
        assert_eq!(rgb(&mem, &os, bm, 0, 0), 4);
    }

    #[test]
    fn set_dibits_draws_only_the_scanlines_the_buffer_holds() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 1, 4, 32, true);
        write_bmi(&mut mem, 1, 4, 32, &[]);
        mem.write_u32(BITS, 0xFF00_00AA).unwrap();
        mem.write_u32(BITS + 4, 0xFF00_00BB).unwrap();
        assert_eq!(setdib(&mut os, &mut mem, dc, (0, 0, 1, 4), (0, 0), (1, 2), 0), 2);
        let col: Vec<u32> = (0..4).map(|y| rgb(&mem, &os, bm, 0, y)).collect();
        assert_eq!(col, [0, 0xBB, 0xAA, 0]);
    }

    #[test]
    fn set_dibits_refuses_bad_input_without_drawing() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        write_bmi(&mut mem, 2, 2, 32, &[]);
        fill_four(&mut mem, [WHITE; 4]);
        let unmapped = [dc as u64, 0, 0, 2, 2, 0, 0, 0, 2, 0x5000_0000, BMI, 0];
        assert_eq!(call(nt_gdi_set_dibits_to_device, &mut os, &mut mem, &unmapped), 0);
        let no_bmi = [dc as u64, 0, 0, 2, 2, 0, 0, 0, 2, BITS, 0x5000_0000, 0];
        assert_eq!(call(nt_gdi_set_dibits_to_device, &mut os, &mut mem, &no_bmi), 0);
        write_bmi(&mut mem, 2, 2, 8, &[RED, GREEN]);
        assert_eq!(setdib(&mut os, &mut mem, dc, (0, 0, 2, 2), (0, 0), (0, 2), 1), 0);
        write_bmi(&mut mem, 2, 2, 32, &[]);
        assert_eq!(setdib(&mut os, &mut mem, 0, (0, 0, 2, 2), (0, 0), (0, 2), 0), 0);
        assert_eq!(pixel(&mem, &os, bm, 0, 0), 0);
    }

    #[test]
    fn a_dib_section_remembers_its_colour_table_for_later_blits() {
        let (mut os, mut mem) = harness();
        write_bmi(&mut mem, 2, 1, 8, &[GREEN, BLUE]);
        let bits_out = 0x11_8000u64;
        let args = [0, 0, 0, BMI, 0, 0, 0, 0, bits_out];
        let hbm = call(crate::win32k::nt_gdi_create_dib_section, &mut os, &mut mem, &args);
        assert_ne!(hbm, 0);
        let bits = mem.read_u64(bits_out).unwrap();
        mem.write(bits, &[1, 0, 0, 0]).unwrap();
        let src = alloc_memory_dc(&mut os, &mut mem).unwrap();
        call(nt_gdi_select_bitmap, &mut os, &mut mem, &[src as u64, hbm as u64]);
        let (dst, dbm) = dc_with_bitmap(&mut os, &mut mem, 2, 1, 32, true);
        call(nt_gdi_bit_blt, &mut os, &mut mem, &[dst as u64, 0, 0, 2, 1, src as u64, 0, 0, SRCCOPY]);
        assert_eq!(rgb(&mem, &os, dbm, 0, 0), BLUE);
        assert_eq!(rgb(&mem, &os, dbm, 1, 0), GREEN);
    }

    fn stretchdib(
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        hdc: u32,
        dest: (i32, i32, i32, i32),
        src: (i32, i32, i32, i32),
        rop: u64,
    ) -> u32 {
        let a = [
            hdc as u64,
            dest.0 as u32 as u64,
            dest.1 as u32 as u64,
            dest.2 as u32 as u64,
            dest.3 as u32 as u64,
            src.0 as u32 as u64,
            src.1 as u32 as u64,
            src.2 as u32 as u64,
            src.3 as u32 as u64,
            BITS,
            BMI,
            0,
            rop,
        ];
        call(nt_gdi_stretch_dibits, os, mem, &a)
    }

    #[test]
    fn stretch_dibits_scales_nearest_and_flips_on_a_negative_destination_height() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 4, 32, true);
        write_bmi(&mut mem, 2, 2, 32, &[]);
        fill_four(&mut mem, [RED, GREEN, BLUE, WHITE]);
        assert_eq!(stretchdib(&mut os, &mut mem, dc, (0, 0, 4, 4), (0, 0, 2, 2), SRCCOPY), 2);
        let col = |os: &WinOs, mem: &VirtualMemory, x| -> Vec<u32> {
            (0..4).map(|y| rgb(mem, os, bm, x, y)).collect()
        };
        assert_eq!(col(&os, &mem, 0), [BLUE, BLUE, RED, RED]);
        assert_eq!(col(&os, &mem, 3), [WHITE, WHITE, GREEN, GREEN]);
        stretchdib(&mut os, &mut mem, dc, (0, 4, 4, -4), (0, 0, 2, 2), SRCCOPY);
        assert_eq!(col(&os, &mem, 0), [RED, RED, BLUE, BLUE]);
    }

    #[test]
    fn stretch_dibits_honours_a_rop_that_ignores_the_source() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        write_bmi(&mut mem, 1, 1, 32, &[]);
        fill_four(&mut mem, [WHITE, 0, 0, 0]);
        stretchdib(&mut os, &mut mem, dc, (0, 0, 2, 2), (0, 0, 1, 1), SRCCOPY);
        assert_eq!(rgb(&mem, &os, bm, 1, 1), WHITE);
        stretchdib(&mut os, &mut mem, dc, (0, 0, 2, 2), (0, 0, 1, 1), BLACKNESS);
        assert_eq!(rgb(&mem, &os, bm, 1, 1), 0);
    }

    fn create_pen(os: &mut WinOs, mem: &mut VirtualMemory, style: u64, color: u64) -> u32 {
        call(nt_gdi_create_pen, os, mem, &[style, 1, color, 0])
    }

    fn row_rgb(mem: &VirtualMemory, os: &WinOs, hbm: u32, y: i32, w: i32) -> Vec<u32> {
        (0..w).map(|x| rgb(mem, os, hbm, x, y)).collect()
    }

    #[test]
    fn line_to_draws_from_the_current_position_with_the_selected_pen_and_skips_the_last_pixel() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 6, 3, 32, true);
        let pen = create_pen(&mut os, &mut mem, 0, 0x0033_2211);
        assert_ne!(pen, 0);
        let stock = call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, pen as u64]);
        assert_eq!(stock, stock_pen_handle(PEN_SLOT_BLACK), "a fresh DC holds BLACK_PEN");
        assert_eq!(call(nt_gdi_move_to, &mut os, &mut mem, &[dc as u64, 1, 1, 0]), 1);
        assert_eq!(call(nt_gdi_line_to, &mut os, &mut mem, &[dc as u64, 5, 1]), 1);
        assert_eq!(row_rgb(&mem, &os, bm, 1, 6), [0, 0x112233, 0x112233, 0x112233, 0x112233, 0]);
        assert_eq!(call(nt_gdi_line_to, &mut os, &mut mem, &[dc as u64, 5, 3]), 1);
        assert_eq!(rgb(&mem, &os, bm, 5, 1), 0x112233, "the next segment starts at the previous end");
        assert_eq!(rgb(&mem, &os, bm, 5, 2), 0x112233, "x = 5 down to the excluded row 3");
        assert_eq!(rgb(&mem, &os, bm, 4, 2), 0);
        let out = 0x11_C000u64;
        call(nt_gdi_move_to, &mut os, &mut mem, &[dc as u64, 0, 0, out]);
        assert_eq!((mem.read_u32(out).unwrap(), mem.read_u32(out + 4).unwrap()), (5, 3));
    }

    #[test]
    fn line_to_clips_to_the_bitmap_and_a_null_pen_only_moves() {
        let (mut os, mut mem) = harness();
        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 1, 32, true);
        let pen = create_pen(&mut os, &mut mem, 0, 0x00FF_FFFF);
        call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, pen as u64]);
        call(nt_gdi_move_to, &mut os, &mut mem, &[dc as u64, (-3i32) as u32 as u64, 0, 0]);
        assert_eq!(call(nt_gdi_line_to, &mut os, &mut mem, &[dc as u64, 100, 0]), 1);
        assert_eq!(row_rgb(&mem, &os, bm, 0, 4), [WHITE; 4]);

        call(nt_gdi_bit_blt, &mut os, &mut mem, &[dc as u64, 0, 0, 4, 1, 0, 0, 0, BLACKNESS]);
        let null_pen = create_pen(&mut os, &mut mem, 5, 0x00FF_FFFF);
        call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, null_pen as u64]);
        call(nt_gdi_move_to, &mut os, &mut mem, &[dc as u64, 0, 0, 0]);
        call(nt_gdi_line_to, &mut os, &mut mem, &[dc as u64, 3, 0]);
        assert_eq!(row_rgb(&mem, &os, bm, 0, 4), [0; 4]);
        let giant = [dc as u64, 0, 0, 0, 0];
        call(nt_gdi_move_to, &mut os, &mut mem, &giant);
        assert_eq!(call(nt_gdi_line_to, &mut os, &mut mem, &[dc as u64, 0x7FFF_FFFF, 0x7FFF_FFFF]), 1);
    }

    #[test]
    fn select_pen_rejects_an_unknown_handle_and_returns_the_previous_pen() {
        let (mut os, mut mem) = harness();
        let (dc, _) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        assert_eq!(call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, 0x0030_0999]), 0);
        let a = create_pen(&mut os, &mut mem, 0, 1);
        let b = create_pen(&mut os, &mut mem, 0, 2);
        call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, a as u64]);
        assert_eq!(call(nt_gdi_select_pen, &mut os, &mut mem, &[dc as u64, b as u64]), a);
    }

    #[test]
    fn a_pattern_brush_built_from_a_bitmap_tiles_through_patblt() {
        let (mut os, mut mem) = harness();
        let (_, tile) = dc_with_bitmap(&mut os, &mut mem, 2, 2, 32, true);
        put(&mut mem, &os, tile, 0, 0, 0xFF00_0001);
        put(&mut mem, &os, tile, 1, 0, 0xFF00_0002);
        put(&mut mem, &os, tile, 0, 1, 0xFF00_0003);
        put(&mut mem, &os, tile, 1, 1, 0xFF00_0004);
        let brush = call(nt_gdi_create_pattern_brush, &mut os, &mut mem, &[tile as u64, 0, 0]);
        assert_ne!(brush, 0);
        assert_eq!(brush >> 16, gdi_type::BRUSH as u32);
        put(&mut mem, &os, tile, 0, 0, 0xFFFF_FFFF);

        let (dc, bm) = dc_with_bitmap(&mut os, &mut mem, 4, 2, 32, true);
        call(nt_gdi_select_brush, &mut os, &mut mem, &[dc as u64, brush as u64]);
        assert_eq!(call(nt_gdi_pat_blt, &mut os, &mut mem, &[dc as u64, 0, 0, 4, 2, PATCOPY]), 1);
        assert_eq!(row_rgb(&mem, &os, bm, 0, 4), [1, 2, 1, 2], "the brush kept its own copy");
        assert_eq!(row_rgb(&mem, &os, bm, 1, 4), [3, 4, 3, 4]);
    }

    #[test]
    fn open_dcw_answers_a_dc_for_display_and_refuses_other_devices() {
        let (mut os, mut mem) = harness();
        let name = 0x11_D000u64;
        let text: Vec<u16> = "DISPLAY".encode_utf16().chain([0]).collect();
        let buf = name + 0x20;
        for (i, u) in text.iter().enumerate() {
            mem.write_u16(buf + i as u64 * 2, *u).unwrap();
        }
        mem.write_u16(name, 14).unwrap();
        mem.write_u16(name + 2, 16).unwrap();
        mem.write_u64(name + 8, buf).unwrap();
        let hdc = call(nt_gdi_open_dcw, &mut os, &mut mem, &[name, 0, 0, 0, 0, 0, 0, 0]);
        assert_ne!(hdc, 0);
        assert_eq!(hdc >> 16, gdi_type::DC as u32);
        assert!(os.win32k_state.dc(hdc).is_some());

        let text: Vec<u16> = "EPSON".encode_utf16().chain([0]).collect();
        for (i, u) in text.iter().enumerate() {
            mem.write_u16(buf + i as u64 * 2, *u).unwrap();
        }
        mem.write_u16(name, 10).unwrap();
        assert_eq!(call(nt_gdi_open_dcw, &mut os, &mut mem, &[name, 0, 0, 0, 0, 0, 0, 0]), 0);
        assert_ne!(call(nt_gdi_open_dcw, &mut os, &mut mem, &[name, 0, 0, 0, 1, 0, 0, 0]), 0);
    }
}
