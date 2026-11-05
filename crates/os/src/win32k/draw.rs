use exemu_core::{CpuState, Memory, Result};

use super::{
    colorref_to_bgra, gdi_client_object, Bitmap, DC_ATTR_BK_COLOR, DC_ATTR_TEXT_COLOR,
    NT_GDI_PAT_BLT, SURFACE_BPP,
};
use crate::gdi_draw::{
    self as g, Blit, Brush, PixelFormat, Pixmap, Rect, SrcSpec, MAX_PIXELS,
};
use crate::WinOs;

pub(super) const NT_GDI_BIT_BLT: u32 = 0x1097;
pub(super) const NT_GDI_STRETCH_BLT: u32 = 0x128f;
pub(super) const NT_GDI_GET_PIXEL: u32 = 0x1217;

const GDI_FAIL: u32 = 0;
const CLR_INVALID: u32 = 0xFFFF_FFFF;
const COLORREF_MASK: u32 = 0x00FF_FFFF;
const WHITE_RGB: u32 = 0x00FF_FFFF;

#[derive(Default)]
pub(super) struct DrawState {
    formats: Vec<(u32, PixelFormat)>,
}

impl DrawState {
    pub(super) fn forget(&mut self, handle: u32) {
        self.formats.retain(|(h, _)| *h != handle);
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

fn resolve_brush(os: &WinOs, hdc: u32) -> Option<Brush> {
    let handle = os.win32k_state.dc(hdc).map_or(0, |d| d.brush);
    if handle == 0 {
        return Some(Brush::Solid(colorref_to_bgra(WHITE_RGB)));
    }
    if let Some((_, color)) = os.win32k_state.brushes.iter().find(|(h, _)| *h == handle) {
        return Some(Brush::Solid(colorref_to_bgra(*color)));
    }
    None
}

struct SrcRef<'a> {
    canvas: &'a Canvas,
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
        match resolve_brush(os, hdc) {
            Some(b) => b,
            None => return Ok(true),
        }
    } else {
        Brush::Solid(0)
    };
    let src_pix = if g::rop_uses_source(t.rop) {
        let Some(src) = &t.src else { return Ok(false) };
        let unscaled = t.dest.width() == src.rect.width()
            && t.dest.height() == src.rect.height()
            && t.flip == (false, false);
        let needed = if unscaled {
            visible.offset(src.rect.l - t.dest.l, src.rect.t - t.dest.t)
        } else {
            src.rect
        }
        .intersect(&src.canvas.image.bounds());
        if needed.area() > MAX_PIXELS {
            return Ok(false);
        }
        let mut pix = src.canvas.image.load(mem, needed)?;
        if src.canvas.mono_ddb {
            let (text, bk) = dc_colors(os, mem, hdc);
            recolor_mono(&mut pix, text, bk);
        }
        Some(pix)
    } else {
        None
    };
    let mut dpix = dst.image.load(mem, visible)?;
    let spec = Blit {
        dest: t.dest,
        src: match (&src_pix, &t.src) {
            (Some(pix), Some(src)) => Some(SrcSpec { pix, rect: src.rect }),
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
            .map(|c| SrcRef { canvas: c, rect: src_rect(c, src.0, src.1, src.2, src.3) }),
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

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_GDI_BIT_BLT, nt_gdi_bit_blt);
    os.set_win32k_handler(NT_GDI_STRETCH_BLT, nt_gdi_stretch_blt);
    os.set_win32k_handler(NT_GDI_PAT_BLT, nt_gdi_pat_blt);
    os.set_win32k_handler(NT_GDI_GET_PIXEL, nt_gdi_get_pixel);
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
}
