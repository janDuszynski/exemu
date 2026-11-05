pub(crate) const COORD_LIMIT: i32 = 1 << 28;
pub(crate) const MAX_PIXELS: u64 = 1 << 24;

pub(crate) const BI_RGB: u32 = 0;
pub(crate) const BI_BITFIELDS: u32 = 3;

const ALPHA_MASK: u32 = 0xFF00_0000;
const RGB_MASK: u32 = 0x00FF_FFFF;
const CORE_HEADER_SIZE: usize = 12;
const INFO_HEADER_SIZE: usize = 40;
const RGBQUAD_SIZE: usize = 4;
const RGBTRIPLE_SIZE: usize = 3;
const BITFIELDS_MASKS_SIZE: usize = 12;
const DEFAULT_555_MASKS: [u32; 3] = [0x7C00, 0x03E0, 0x001F];
const DEFAULT_32_MASKS: [u32; 3] = [0x00FF_0000, 0x0000_FF00, 0x0000_00FF];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rect {
    pub l: i32,
    pub t: i32,
    pub r: i32,
    pub b: i32,
}

impl Rect {
    pub(crate) fn new(l: i32, t: i32, r: i32, b: i32) -> Rect {
        Rect { l, t, r, b }
    }

    pub(crate) fn from_extent(x: i32, y: i32, w: i32, h: i32) -> Rect {
        let clamp = |v: i32| v.clamp(-COORD_LIMIT, COORD_LIMIT);
        let (x, y) = (clamp(x), clamp(y));
        let (x2, y2) = (clamp(x.saturating_add(w)), clamp(y.saturating_add(h)));
        Rect { l: x.min(x2), t: y.min(y2), r: x.max(x2), b: y.max(y2) }
    }

    pub(crate) fn width(&self) -> i32 {
        (self.r - self.l).max(0)
    }

    pub(crate) fn height(&self) -> i32 {
        (self.b - self.t).max(0)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.r <= self.l || self.b <= self.t
    }

    pub(crate) fn intersect(&self, o: &Rect) -> Rect {
        Rect { l: self.l.max(o.l), t: self.t.max(o.t), r: self.r.min(o.r), b: self.b.min(o.b) }
    }

    pub(crate) fn offset(&self, dx: i32, dy: i32) -> Rect {
        Rect { l: self.l + dx, t: self.t + dy, r: self.r + dx, b: self.b + dy }
    }

    pub(crate) fn area(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            self.width() as u64 * self.height() as u64
        }
    }

    pub(crate) fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.l && x < self.r && y >= self.t && y < self.b
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pixmap {
    pub rect: Rect,
    px: Vec<u32>,
}

impl Pixmap {
    pub(crate) fn new(rect: Rect, fill: u32) -> Pixmap {
        let rect = if rect.is_empty() { Rect::new(rect.l, rect.t, rect.l, rect.t) } else { rect };
        let n = rect.width() as usize * rect.height() as usize;
        Pixmap { rect, px: vec![fill; n] }
    }

    pub(crate) fn get(&self, x: i32, y: i32) -> Option<u32> {
        if !self.rect.contains(x, y) {
            return None;
        }
        self.px.get(self.index(x, y)).copied()
    }

    pub(crate) fn set(&mut self, x: i32, y: i32, v: u32) {
        if self.rect.contains(x, y) {
            let i = self.index(x, y);
            if let Some(slot) = self.px.get_mut(i) {
                *slot = v;
            }
        }
    }

    fn index(&self, x: i32, y: i32) -> usize {
        (y - self.rect.t) as usize * self.rect.width() as usize + (x - self.rect.l) as usize
    }

    pub(crate) fn row_mut(&mut self, y: i32) -> &mut [u32] {
        let w = self.rect.width() as usize;
        if !(self.rect.t..self.rect.b).contains(&y) {
            return &mut [];
        }
        let start = (y - self.rect.t) as usize * w;
        &mut self.px[start..start + w]
    }

    pub(crate) fn row(&self, y: i32) -> &[u32] {
        let w = self.rect.width() as usize;
        if !(self.rect.t..self.rect.b).contains(&y) {
            return &[];
        }
        let start = (y - self.rect.t) as usize * w;
        &self.px[start..start + w]
    }

    pub(crate) fn crop(&self, r: Rect) -> Pixmap {
        let r = r.intersect(&self.rect);
        let mut out = Pixmap::new(r, 0);
        for y in r.t..r.b {
            for x in r.l..r.r {
                if let Some(v) = self.get(x, y) {
                    out.set(x, y, v);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Brush {
    Solid(u32),
    Pattern(Pixmap),
}

impl Brush {
    pub(crate) fn at(&self, x: i32, y: i32, org: (i32, i32)) -> u32 {
        match self {
            Brush::Solid(c) => *c,
            Brush::Pattern(p) => {
                let (w, h) = (p.rect.width().max(1), p.rect.height().max(1));
                let px = (x - org.0).rem_euclid(w) + p.rect.l;
                let py = (y - org.1).rem_euclid(h) + p.rect.t;
                p.get(px, py).unwrap_or(0)
            }
        }
    }
}

pub(crate) fn rop_index(rop: u32) -> u8 {
    (rop >> 16) as u8
}

pub(crate) fn rop_uses_source(rop: u32) -> bool {
    let i = rop_index(rop);
    ((i >> 2) & 0x33) != (i & 0x33)
}

pub(crate) fn rop_uses_pattern(rop: u32) -> bool {
    let i = rop_index(rop);
    ((i >> 4) & 0x0F) != (i & 0x0F)
}

pub(crate) fn apply_rop3(rop: u32, s: u32, d: u32, p: u32) -> u32 {
    let idx = rop_index(rop);
    let mut out = 0u32;
    for term in 0..8u32 {
        if idx >> term & 1 == 0 {
            continue;
        }
        let pick = |v: u32, bit: u32| if term >> bit & 1 == 1 { v } else { !v };
        out |= pick(p, 2) & pick(s, 1) & pick(d, 0);
    }
    out & RGB_MASK
}

pub(crate) struct SrcSpec<'a> {
    pub pix: &'a Pixmap,
    pub rect: Rect,
}

pub(crate) struct Blit<'a> {
    pub dest: Rect,
    pub src: Option<SrcSpec<'a>>,
    pub flip_x: bool,
    pub flip_y: bool,
    pub rop: u32,
    pub brush: &'a Brush,
    pub brush_org: (i32, i32),
}

fn scale_index(i: i64, dest_len: i64, src_len: i64, flip: bool) -> i64 {
    let i = if flip { dest_len - 1 - i } else { i };
    ((2 * i + 1) * src_len) / (2 * dest_len)
}

pub(crate) fn blit(dst: &mut Pixmap, spec: &Blit) -> u64 {
    let area = spec.dest.intersect(&dst.rect);
    if area.is_empty() || spec.dest.is_empty() {
        return 0;
    }
    let needs_source = rop_uses_source(spec.rop);
    let needs_pattern = rop_uses_pattern(spec.rop);
    let (dw, dh) = (spec.dest.width() as i64, spec.dest.height() as i64);
    let mut written = 0;
    for y in area.t..area.b {
        for x in area.l..area.r {
            let s = if needs_source {
                let Some(src) = &spec.src else { return written };
                if src.rect.is_empty() {
                    return written;
                }
                let sx = src.rect.l as i64
                    + scale_index((x - spec.dest.l) as i64, dw, src.rect.width() as i64, spec.flip_x);
                let sy = src.rect.t as i64
                    + scale_index((y - spec.dest.t) as i64, dh, src.rect.height() as i64, spec.flip_y);
                let (Ok(sx), Ok(sy)) = (i32::try_from(sx), i32::try_from(sy)) else { continue };
                match src.pix.get(sx, sy) {
                    Some(v) => v,
                    None => continue,
                }
            } else {
                0
            };
            let p = if needs_pattern { spec.brush.at(x, y, spec.brush_org) } else { 0 };
            let d = dst.get(x, y).unwrap_or(0);
            dst.set(x, y, (d & ALPHA_MASK) | apply_rop3(spec.rop, s, d, p));
            written += 1;
        }
    }
    written
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Line {
    x0: i64,
    y0: i64,
    sx: i64,
    sy: i64,
    major: i64,
    minor: i64,
    shallow: bool,
}

impl Line {
    pub(crate) fn new(x0: i64, y0: i64, x1: i64, y1: i64) -> Line {
        let (dx, dy) = ((x1 - x0).abs(), (y1 - y0).abs());
        Line {
            x0,
            y0,
            sx: if x0 < x1 { 1 } else { -1 },
            sy: if y0 < y1 { 1 } else { -1 },
            major: dx.max(dy),
            minor: dx.min(dy),
            shallow: dx >= dy,
        }
    }

    fn minor_offset(&self, k: i64) -> i64 {
        let (k, major, minor) = (k as i128, self.major as i128, self.minor as i128);
        ((2 * minor * k + major) / (2 * major)) as i64
    }

    fn at(&self, k: i64) -> (i64, i64) {
        let off = self.minor_offset(k);
        if self.shallow {
            (self.x0 + self.sx * k, self.y0 + self.sy * off)
        } else {
            (self.x0 + self.sx * off, self.y0 + self.sy * k)
        }
    }

    pub(crate) fn pixels(&self, clip: Rect) -> impl Iterator<Item = (i32, i32)> + '_ {
        let (lo, hi) = self.visible_steps(clip);
        (lo..hi).map(|k| {
            let (x, y) = self.at(k);
            (x as i32, y as i32)
        })
    }

    fn visible_steps(&self, clip: Rect) -> (i64, i64) {
        if self.major == 0 || clip.is_empty() {
            return (0, 0);
        }
        let (major_range, minor_range, start, step) = if self.shallow {
            ((clip.l as i64, clip.r as i64), (clip.t as i64, clip.b as i64), self.x0, self.sx)
        } else {
            ((clip.t as i64, clip.b as i64), (clip.l as i64, clip.r as i64), self.y0, self.sy)
        };
        let (mut lo, mut hi) = if step > 0 {
            (major_range.0 - start, major_range.1 - start)
        } else {
            (start - major_range.1 + 1, start - major_range.0 + 1)
        };
        lo = lo.max(0);
        hi = hi.min(self.major);
        if lo >= hi {
            return (0, 0);
        }
        let (minor_start, minor_step) = if self.shallow { (self.y0, self.sy) } else { (self.x0, self.sx) };
        let minor_at = |k: i64| minor_start + minor_step * self.minor_offset(k);
        let first = |range: (i64, i64), reached: &dyn Fn(i64) -> bool| -> i64 {
            let (mut a, mut b) = range;
            while a < b {
                let mid = a + (b - a) / 2;
                if reached(mid) {
                    b = mid;
                } else {
                    a = mid + 1;
                }
            }
            a
        };
        let (from, to) = if minor_step > 0 {
            (
                first((lo, hi), &|k| minor_at(k) >= minor_range.0),
                first((lo, hi), &|k| minor_at(k) >= minor_range.1),
            )
        } else {
            (
                first((lo, hi), &|k| minor_at(k) < minor_range.1),
                first((lo, hi), &|k| minor_at(k) < minor_range.0),
            )
        };
        (from, to.max(from))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PixelFormat {
    pub bpp: u32,
    pub palette: Vec<u32>,
    pub masks: Option<[u32; 3]>,
}

pub(crate) fn bpp_supported(bpp: u32) -> bool {
    matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32)
}

pub(crate) fn row_stride(width: u32, bpp: u32) -> usize {
    (width as usize * bpp as usize).div_ceil(32) * 4
}

pub(crate) fn mono_palette() -> Vec<u32> {
    vec![0, RGB_MASK]
}

fn mask_shift(mask: u32) -> (u32, u32) {
    if mask == 0 {
        return (0, 0);
    }
    let shift = mask.trailing_zeros();
    let bits = (mask >> shift).trailing_ones();
    (shift, bits)
}

fn extract_channel(v: u32, mask: u32) -> u32 {
    let (shift, bits) = mask_shift(mask);
    if bits == 0 {
        return 0;
    }
    let raw = (v & mask) >> shift;
    if bits >= 8 {
        raw >> (bits - 8)
    } else {
        raw * 255 / ((1 << bits) - 1)
    }
}

fn insert_channel(v8: u32, mask: u32) -> u32 {
    let (shift, bits) = mask_shift(mask);
    if bits == 0 {
        return 0;
    }
    let raw = if bits >= 8 { v8 << (bits - 8) } else { v8 >> (8 - bits) };
    (raw << shift) & mask
}

fn rgb_from_masked(v: u32, m: &[u32; 3]) -> u32 {
    (extract_channel(v, m[0]) << 16) | (extract_channel(v, m[1]) << 8) | extract_channel(v, m[2])
}

fn masked_from_rgb(rgb: u32, m: &[u32; 3]) -> u32 {
    insert_channel((rgb >> 16) & 0xFF, m[0])
        | insert_channel((rgb >> 8) & 0xFF, m[1])
        | insert_channel(rgb & 0xFF, m[2])
}

fn nearest_palette_index(palette: &[u32], rgb: u32) -> usize {
    let channel = |v: u32, s: u32| ((v >> s) & 0xFF) as i64;
    palette
        .iter()
        .enumerate()
        .min_by_key(|(_, c)| {
            [16u32, 8, 0]
                .iter()
                .map(|s| (channel(**c, *s) - channel(rgb, *s)).pow(2))
                .sum::<i64>()
        })
        .map_or(0, |(i, _)| i)
}

pub(crate) fn decode_row(f: &PixelFormat, row: &[u8], x0: usize, out: &mut [u32]) {
    let byte = |i: usize| row.get(i).copied().unwrap_or(0);
    let masks16 = f.masks.unwrap_or(DEFAULT_555_MASKS);
    let masks32 = f.masks.unwrap_or(DEFAULT_32_MASKS);
    for (k, slot) in out.iter_mut().enumerate() {
        let x = x0 + k;
        let rgb = match f.bpp {
            32 => {
                let v = u32::from_le_bytes([byte(x * 4), byte(x * 4 + 1), byte(x * 4 + 2), byte(x * 4 + 3)]);
                rgb_from_masked(v, &masks32)
            }
            24 => (byte(x * 3 + 2) as u32) << 16 | (byte(x * 3 + 1) as u32) << 8 | byte(x * 3) as u32,
            16 => {
                let v = u16::from_le_bytes([byte(x * 2), byte(x * 2 + 1)]) as u32;
                rgb_from_masked(v, &masks16)
            }
            8 => f.palette.get(byte(x) as usize).copied().unwrap_or(0) & RGB_MASK,
            4 => {
                let b = byte(x / 2);
                let idx = if x % 2 == 0 { b >> 4 } else { b & 0xF };
                f.palette.get(idx as usize).copied().unwrap_or(0) & RGB_MASK
            }
            1 => {
                let idx = byte(x / 8) >> (7 - x % 8) & 1;
                f.palette.get(idx as usize).copied().unwrap_or(0) & RGB_MASK
            }
            _ => 0,
        };
        *slot = ALPHA_MASK | rgb;
    }
}

pub(crate) fn encode_row(f: &PixelFormat, row: &mut [u8], x0: usize, src: &[u32]) {
    let masks16 = f.masks.unwrap_or(DEFAULT_555_MASKS);
    let masks32 = f.masks.unwrap_or(DEFAULT_32_MASKS);
    for (k, v) in src.iter().enumerate() {
        let x = x0 + k;
        let rgb = v & RGB_MASK;
        match f.bpp {
            32 => {
                let at = x * 4;
                if let Some(cell) = row.get_mut(at..at + 4) {
                    let prev = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]);
                    let keep = !(masks32[0] | masks32[1] | masks32[2]);
                    let out = (prev & keep) | masked_from_rgb(rgb, &masks32);
                    cell.copy_from_slice(&out.to_le_bytes());
                }
            }
            24 => {
                let at = x * 3;
                if let Some(cell) = row.get_mut(at..at + 3) {
                    cell.copy_from_slice(&[rgb as u8, (rgb >> 8) as u8, (rgb >> 16) as u8]);
                }
            }
            16 => {
                let at = x * 2;
                if let Some(cell) = row.get_mut(at..at + 2) {
                    cell.copy_from_slice(&(masked_from_rgb(rgb, &masks16) as u16).to_le_bytes());
                }
            }
            8 => {
                if let Some(cell) = row.get_mut(x) {
                    *cell = nearest_palette_index(&f.palette, rgb) as u8;
                }
            }
            4 => {
                if let Some(cell) = row.get_mut(x / 2) {
                    let idx = nearest_palette_index(&f.palette, rgb) as u8 & 0xF;
                    *cell = if x % 2 == 0 { (*cell & 0x0F) | (idx << 4) } else { (*cell & 0xF0) | idx };
                }
            }
            1 => {
                if let Some(cell) = row.get_mut(x / 8) {
                    let bit = 0x80u8 >> (x % 8);
                    if nearest_palette_index(&f.palette, rgb) != 0 {
                        *cell |= bit;
                    } else {
                        *cell &= !bit;
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DibInfo {
    pub width: i32,
    pub height: i32,
    pub top_down: bool,
    pub bpp: u32,
    pub compression: u32,
    pub format: PixelFormat,
    pub header_size: usize,
    pub colors_len: usize,
    pub image_size: u32,
}

impl DibInfo {
    pub(crate) fn stride(&self) -> usize {
        row_stride(self.width.max(0) as u32, self.bpp)
    }

    pub(crate) fn decodable(&self) -> bool {
        self.width > 0
            && self.height > 0
            && bpp_supported(self.bpp)
            && matches!(self.compression, BI_RGB | BI_BITFIELDS)
            && (self.compression == BI_RGB || matches!(self.bpp, 16 | 32))
    }

    pub(crate) fn total_header_len(&self) -> usize {
        self.header_size + self.colors_len
    }
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn dib_header_size(first_dword: u32) -> Option<usize> {
    let n = first_dword as usize;
    (n == CORE_HEADER_SIZE || (n >= INFO_HEADER_SIZE && n <= 256)).then_some(n)
}

impl DibInfo {
    pub(crate) fn parse(b: &[u8]) -> Option<DibInfo> {
        let header_size = dib_header_size(le_u32(b, 0)?)?;
        if header_size == CORE_HEADER_SIZE {
            let width = le_u16(b, 4)? as i32;
            let height = le_u16(b, 6)? as i32;
            let bpp = le_u16(b, 10)? as u32;
            let colors = if bpp <= 8 { 1usize << bpp } else { 0 };
            let palette = read_palette(b, header_size, colors, RGBTRIPLE_SIZE);
            return Some(DibInfo {
                width,
                height,
                top_down: false,
                bpp,
                compression: BI_RGB,
                format: PixelFormat { bpp, palette, masks: None },
                header_size,
                colors_len: colors * RGBTRIPLE_SIZE,
                image_size: 0,
            });
        }
        let width = le_u32(b, 4)? as i32;
        let raw_height = le_u32(b, 8)? as i32;
        let bpp = le_u16(b, 14)? as u32;
        let compression = le_u32(b, 16)?;
        let image_size = le_u32(b, 20)?;
        let clr_used = le_u32(b, 32)? as usize;
        let mut masks = None;
        let mut table_at = header_size;
        if compression == BI_BITFIELDS {
            if header_size == INFO_HEADER_SIZE {
                masks = Some([le_u32(b, 40)?, le_u32(b, 44)?, le_u32(b, 48)?]);
                table_at += BITFIELDS_MASKS_SIZE;
            } else {
                masks = Some([le_u32(b, 40)?, le_u32(b, 44)?, le_u32(b, 48)?]);
            }
        }
        let colors = if bpp <= 8 {
            let full = 1usize << bpp;
            if clr_used == 0 || clr_used > full { full } else { clr_used }
        } else {
            0
        };
        let palette = read_palette(b, table_at, colors, RGBQUAD_SIZE);
        Some(DibInfo {
            width,
            height: raw_height.checked_abs().unwrap_or(0),
            top_down: raw_height < 0,
            bpp,
            compression,
            format: PixelFormat { bpp, palette, masks },
            header_size,
            colors_len: table_at - header_size + colors * RGBQUAD_SIZE,
            image_size,
        })
    }
}

fn read_palette(b: &[u8], at: usize, colors: usize, entry: usize) -> Vec<u32> {
    (0..colors)
        .map(|i| {
            let o = at + i * entry;
            match b.get(o..o + 3) {
                Some(c) => (c[2] as u32) << 16 | (c[1] as u32) << 8 | c[0] as u32,
                None => 0,
            }
        })
        .collect()
}

pub(crate) fn decode_scans(info: &DibInfo, bits: &[u8], startscan: u32, lines: u32) -> Option<Pixmap> {
    if !info.decodable() {
        return None;
    }
    let stride = info.stride();
    let available = if stride == 0 { 0 } else { bits.len() / stride };
    let start = (startscan as usize).min(info.height as usize);
    let count = (lines as usize).min(available).min(info.height as usize - start);
    let rect = Rect::new(0, start as i32, info.width, (start + count) as i32);
    if rect.area() > MAX_PIXELS {
        return None;
    }
    let mut pix = Pixmap::new(rect, 0);
    for k in 0..count {
        let row = &bits[k * stride..(k + 1) * stride];
        decode_row(&info.format, row, 0, pix.row_mut((start + k) as i32));
    }
    Some(pix)
}

pub(crate) fn visual_source(info: &DibInfo, scans: &Pixmap, src_x: i32, src_y: i32, cx: i32, cy: i32) -> Pixmap {
    let rect = Rect::new(src_x, 0, src_x.saturating_add(cx.max(0)), cy.max(0));
    let mut out = Pixmap::new(rect.intersect(&Rect::new(0, 0, info.width, cy.max(0))), 0);
    let mut kept_rows: Vec<i32> = Vec::new();
    for j in 0..cy.max(0) {
        let scan = if info.top_down { src_y as i64 + j as i64 } else { src_y as i64 + (cy - 1 - j) as i64 };
        let Ok(scan) = i32::try_from(scan) else { continue };
        if scan < scans.rect.t || scan >= scans.rect.b {
            continue;
        }
        kept_rows.push(j);
        for x in out.rect.l..out.rect.r {
            if let Some(v) = scans.get(x, scan) {
                out.set(x, j, v);
            }
        }
    }
    if kept_rows.is_empty() {
        return Pixmap::new(Rect::new(0, 0, 0, 0), 0);
    }
    let (lo, hi) = (kept_rows[0], kept_rows[kept_rows.len() - 1] + 1);
    out.crop(Rect::new(out.rect.l, lo, out.rect.r, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BI_RLE8: u32 = 1;
    const SRCCOPY: u32 = 0x00CC_0020;
    const SRCPAINT: u32 = 0x00EE_0086;
    const SRCAND: u32 = 0x0088_00C6;
    const SRCINVERT: u32 = 0x0066_0046;
    const NOTSRCCOPY: u32 = 0x0033_0008;
    const DSTINVERT: u32 = 0x0055_0009;
    const PATCOPY: u32 = 0x00F0_0021;
    const PATINVERT: u32 = 0x005A_0049;
    const MERGECOPY: u32 = 0x00C0_00CA;
    const BLACKNESS: u32 = 0x0000_0042;
    const WHITENESS: u32 = 0x00FF_0062;

    const S: u32 = 0x00F0_C060;
    const D: u32 = 0x003C_5AA5;
    const P: u32 = 0x00FF_0F33;

    fn one(rop: u32) -> u32 {
        apply_rop3(rop, S, D, P)
    }

    #[test]
    fn every_common_rop_matches_its_boolean_definition() {
        assert_eq!(one(SRCCOPY), S);
        assert_eq!(one(SRCPAINT), S | D);
        assert_eq!(one(SRCAND), S & D);
        assert_eq!(one(SRCINVERT), S ^ D);
        assert_eq!(one(NOTSRCCOPY), !S & RGB_MASK);
        assert_eq!(one(DSTINVERT), !D & RGB_MASK);
        assert_eq!(one(PATCOPY), P);
        assert_eq!(one(PATINVERT), P ^ D);
        assert_eq!(one(MERGECOPY), P & S);
        assert_eq!(one(BLACKNESS), 0);
        assert_eq!(one(WHITENESS), RGB_MASK);
    }

    #[test]
    fn rop_source_and_pattern_use_follow_the_ternary_index() {
        for rop in [SRCCOPY, SRCPAINT, SRCAND, SRCINVERT, NOTSRCCOPY, MERGECOPY] {
            assert!(rop_uses_source(rop), "{rop:#x}");
        }
        for rop in [PATCOPY, PATINVERT, DSTINVERT, BLACKNESS, WHITENESS] {
            assert!(!rop_uses_source(rop), "{rop:#x}");
        }
        for rop in [PATCOPY, PATINVERT, MERGECOPY] {
            assert!(rop_uses_pattern(rop), "{rop:#x}");
        }
        for rop in [SRCCOPY, SRCINVERT, DSTINVERT, BLACKNESS, WHITENESS] {
            assert!(!rop_uses_pattern(rop), "{rop:#x}");
        }
    }

    fn ramp(rect: Rect) -> Pixmap {
        let mut p = Pixmap::new(rect, 0);
        for y in rect.t..rect.b {
            for x in rect.l..rect.r {
                p.set(x, y, ALPHA_MASK | ((x as u32 & 0xFF) << 8) | (y as u32 & 0xFF));
            }
        }
        p
    }

    fn solid() -> Brush {
        Brush::Solid(0)
    }

    fn copy_spec<'a>(dest: Rect, src: &'a Pixmap, src_rect: Rect, brush: &'a Brush) -> Blit<'a> {
        Blit {
            dest,
            src: Some(SrcSpec { pix: src, rect: src_rect }),
            flip_x: false,
            flip_y: false,
            rop: SRCCOPY,
            brush,
            brush_org: (0, 0),
        }
    }

    #[test]
    fn srccopy_moves_pixels_and_clips_at_every_destination_edge() {
        let src = ramp(Rect::new(0, 0, 4, 4));
        let brush = solid();
        for (dx, dy) in [(-2, 0), (6, 0), (0, -2), (0, 6), (-2, -2), (6, 6)] {
            let mut dst = Pixmap::new(Rect::new(0, 0, 8, 8), 0xFF00_0000);
            let dest = Rect::new(dx, dy, dx + 4, dy + 4);
            let n = blit(&mut dst, &copy_spec(dest, &src, Rect::new(0, 0, 4, 4), &brush));
            let inside = dest.intersect(&dst.rect);
            assert_eq!(n, inside.area(), "({dx},{dy})");
            for y in 0..8 {
                for x in 0..8 {
                    let want = if inside.contains(x, y) {
                        src.get(x - dx, y - dy).unwrap()
                    } else {
                        0xFF00_0000
                    };
                    assert_eq!(dst.get(x, y), Some(want), "({dx},{dy}) at ({x},{y})");
                }
            }
        }
    }

    #[test]
    fn a_source_pixel_outside_the_source_pixmap_is_not_drawn() {
        let src = ramp(Rect::new(0, 0, 2, 2));
        let brush = solid();
        let mut dst = Pixmap::new(Rect::new(0, 0, 4, 4), 0xFF11_1111);
        blit(&mut dst, &copy_spec(Rect::new(0, 0, 4, 4), &src, Rect::new(0, 0, 4, 4), &brush));
        assert_eq!(dst.get(1, 1), src.get(1, 1));
        assert_eq!(dst.get(3, 3), Some(0xFF11_1111));
    }

    #[test]
    fn overlapping_copy_in_one_surface_behaves_like_memmove() {
        for (dx, dy) in [(1, 0), (-1, 0), (0, 1), (0, -1), (2, 2), (-2, -2)] {
            let mut surf = ramp(Rect::new(0, 0, 8, 8));
            let before = surf.clone();
            let src_rect = Rect::new(2, 2, 6, 6);
            let snapshot = surf.crop(src_rect);
            let brush = solid();
            blit(&mut surf, &copy_spec(src_rect.offset(dx, dy), &snapshot, src_rect, &brush));
            for y in 0..8 {
                for x in 0..8 {
                    let moved = src_rect.offset(dx, dy);
                    let want = if moved.contains(x, y) {
                        before.get(x - dx, y - dy).unwrap()
                    } else {
                        before.get(x, y).unwrap()
                    };
                    assert_eq!(surf.get(x, y), Some(want), "shift ({dx},{dy}) at ({x},{y})");
                }
            }
        }
    }

    #[test]
    fn the_destination_alpha_survives_every_rop() {
        let mut dst = Pixmap::new(Rect::new(0, 0, 1, 1), 0x7A12_3456);
        let brush = Brush::Solid(0x00FF_FFFF);
        blit(
            &mut dst,
            &Blit {
                dest: Rect::new(0, 0, 1, 1),
                src: None,
                flip_x: false,
                flip_y: false,
                rop: PATCOPY,
                brush: &brush,
                brush_org: (0, 0),
            },
        );
        assert_eq!(dst.get(0, 0), Some(0x7AFF_FFFF));
    }

    #[test]
    fn pattern_brushes_tile_from_the_brush_origin() {
        let mut tile = Pixmap::new(Rect::new(0, 0, 2, 2), 0);
        tile.set(0, 0, 1);
        tile.set(1, 0, 2);
        tile.set(0, 1, 3);
        tile.set(1, 1, 4);
        let brush = Brush::Pattern(tile);
        let mut dst = Pixmap::new(Rect::new(0, 0, 4, 4), ALPHA_MASK);
        blit(
            &mut dst,
            &Blit {
                dest: Rect::new(0, 0, 4, 4),
                src: None,
                flip_x: false,
                flip_y: false,
                rop: PATCOPY,
                brush: &brush,
                brush_org: (1, 0),
            },
        );
        let row0: Vec<u32> = (0..4).map(|x| dst.get(x, 0).unwrap() & RGB_MASK).collect();
        let row1: Vec<u32> = (0..4).map(|x| dst.get(x, 1).unwrap() & RGB_MASK).collect();
        assert_eq!(row0, [2, 1, 2, 1]);
        assert_eq!(row1, [4, 3, 4, 3]);
    }

    #[test]
    fn stretching_samples_nearest_and_flips_on_opposite_signs() {
        let mut src = Pixmap::new(Rect::new(0, 0, 2, 1), 0);
        src.set(0, 0, 0xFF00_00AA);
        src.set(1, 0, 0xFF00_00BB);
        let brush = solid();
        let mut dst = Pixmap::new(Rect::new(0, 0, 4, 1), 0);
        blit(&mut dst, &copy_spec(Rect::new(0, 0, 4, 1), &src, Rect::new(0, 0, 2, 1), &brush));
        let row: Vec<u32> = (0..4).map(|x| dst.get(x, 0).unwrap() & 0xFF).collect();
        assert_eq!(row, [0xAA, 0xAA, 0xBB, 0xBB]);

        let mut spec = copy_spec(Rect::new(0, 0, 4, 1), &src, Rect::new(0, 0, 2, 1), &brush);
        spec.flip_x = true;
        blit(&mut dst, &spec);
        let row: Vec<u32> = (0..4).map(|x| dst.get(x, 0).unwrap() & 0xFF).collect();
        assert_eq!(row, [0xBB, 0xBB, 0xAA, 0xAA]);

        let mut shrink = Pixmap::new(Rect::new(0, 0, 1, 1), 0);
        blit(&mut shrink, &copy_spec(Rect::new(0, 0, 1, 1), &dst, Rect::new(0, 0, 4, 1), &brush));
        assert_eq!(shrink.get(0, 0).unwrap() & 0xFF, 0xAA);
    }

    #[test]
    fn extents_with_negative_size_order_into_the_rect_before_them() {
        assert_eq!(Rect::from_extent(10, 10, -4, 3), Rect::new(6, 10, 10, 13));
        let huge = Rect::from_extent(i32::MIN, i32::MIN, i32::MAX, i32::MAX);
        assert!(huge.width() >= 0 && huge.height() >= 0);
    }

    const WIDE_OPEN: Rect = Rect { l: -1000, t: -1000, r: 1000, b: 1000 };

    fn line_pixels(x0: i64, y0: i64, x1: i64, y1: i64, clip: Rect) -> Vec<(i32, i32)> {
        Line::new(x0, y0, x1, y1).pixels(clip).collect()
    }

    fn reference_line(x0: i64, y0: i64, x1: i64, y1: i64) -> Vec<(i32, i32)> {
        let (dx, dy) = ((x1 - x0).abs(), -(y1 - y0).abs());
        let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });
        let (mut x, mut y, mut err) = (x0, y0, dx + dy);
        let mut out = Vec::new();
        for _ in 0..dx.max(-dy) {
            out.push((x as i32, y as i32));
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
        out
    }

    #[test]
    fn the_last_pixel_of_a_line_is_excluded() {
        assert_eq!(line_pixels(0, 0, 5, 0, WIDE_OPEN), [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)]);
        assert_eq!(line_pixels(0, 0, 3, 3, WIDE_OPEN), [(0, 0), (1, 1), (2, 2)]);
        assert_eq!(line_pixels(2, 4, 2, 1, WIDE_OPEN), [(2, 4), (2, 3), (2, 2)]);
        assert_eq!(
            line_pixels(0, 0, 5, 2, WIDE_OPEN),
            [(0, 0), (1, 0), (2, 1), (3, 1), (4, 2)]
        );
        assert!(line_pixels(3, 3, 3, 3, WIDE_OPEN).is_empty());
    }

    #[test]
    fn the_closed_form_line_is_the_stepping_line_in_every_direction() {
        for x0 in -5..=5 {
            for y0 in -5..=5 {
                for x1 in -5..=5 {
                    for y1 in -5..=5 {
                        assert_eq!(
                            line_pixels(x0, y0, x1, y1, WIDE_OPEN),
                            reference_line(x0, y0, x1, y1),
                            "({x0},{y0})->({x1},{y1})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn clipping_a_line_keeps_exactly_the_pixels_the_whole_line_has_inside() {
        let clip = Rect::new(-2, -3, 4, 3);
        for (x0, y0, x1, y1) in [
            (-9, -7, 11, 6),
            (11, 6, -9, -7),
            (-9, 0, 9, 1),
            (0, -9, 1, 9),
            (9, 9, -9, -9),
            (-9, 2, 9, 2),
            (1, -9, 1, 9),
            (-30, -4, 30, 5),
        ] {
            let want: Vec<_> = reference_line(x0, y0, x1, y1)
                .into_iter()
                .filter(|(x, y)| clip.contains(*x, *y))
                .collect();
            assert!(!want.is_empty(), "({x0},{y0})->({x1},{y1}) must cross the clip");
            assert_eq!(line_pixels(x0, y0, x1, y1, clip), want, "({x0},{y0})->({x1},{y1})");
        }
    }

    #[test]
    fn a_line_with_extreme_endpoints_costs_only_its_visible_pixels() {
        let (lo, hi) = (i32::MIN as i64, i32::MAX as i64);
        let surface = Rect::new(0, 0, 8, 8);
        assert_eq!(
            line_pixels(lo, 3, hi, 3, surface),
            (0..8).map(|x| (x, 3)).collect::<Vec<_>>(),
            "a horizontal line across the whole i32 range draws its crossing of the surface"
        );
        assert_eq!(
            line_pixels(2, hi, 2, lo, surface),
            (0..8).rev().map(|y| (2, y)).collect::<Vec<_>>()
        );
        let diag = line_pixels(lo, lo, hi, hi, surface);
        assert_eq!(diag, (0..8).map(|v| (v, v)).collect::<Vec<_>>());
        assert!(line_pixels(lo, lo, hi, lo, surface).is_empty(), "above the surface");
        assert!(line_pixels(lo, 100, hi, 101, surface).is_empty(), "below the surface");
        assert!(line_pixels(100, lo, 101, hi, surface).is_empty(), "right of the surface");
        assert!(line_pixels(lo, lo, lo + 5, lo + 5, surface).is_empty(), "wholly outside");
        assert!(line_pixels(lo, lo, hi, hi, Rect::new(0, 0, 0, 0)).is_empty());
    }

    fn info_bytes(width: i32, height: i32, bpp: u16, compression: u32, clr_used: u32) -> Vec<u8> {
        let mut h = vec![0u8; INFO_HEADER_SIZE];
        h[0..4].copy_from_slice(&40u32.to_le_bytes());
        h[4..8].copy_from_slice(&width.to_le_bytes());
        h[8..12].copy_from_slice(&height.to_le_bytes());
        h[12..14].copy_from_slice(&1u16.to_le_bytes());
        h[14..16].copy_from_slice(&bpp.to_le_bytes());
        h[16..20].copy_from_slice(&compression.to_le_bytes());
        h[32..36].copy_from_slice(&clr_used.to_le_bytes());
        h
    }

    fn with_palette(mut h: Vec<u8>, colors: &[u32]) -> Vec<u8> {
        for c in colors {
            h.extend_from_slice(&[*c as u8, (*c >> 8) as u8, (*c >> 16) as u8, 0]);
        }
        h
    }

    fn decode_all(info: &DibInfo, bits: &[u8]) -> Pixmap {
        decode_scans(info, bits, 0, info.height as u32).unwrap()
    }

    fn rgb_at(p: &Pixmap, x: i32, y: i32) -> u32 {
        p.get(x, y).unwrap() & RGB_MASK
    }

    #[test]
    fn a_32bpp_bottom_up_dib_has_its_first_scanline_at_the_bottom() {
        let h = info_bytes(2, 2, 32, BI_RGB, 0);
        let info = DibInfo::parse(&h).unwrap();
        assert!(!info.top_down);
        let bits: Vec<u8> = [0x11u32, 0x22, 0x33, 0x44].iter().flat_map(|v| v.to_le_bytes()).collect();
        let scans = decode_all(&info, &bits);
        let vis = visual_source(&info, &scans, 0, 0, 2, 2);
        assert_eq!(rgb_at(&vis, 0, 0), 0x33);
        assert_eq!(rgb_at(&vis, 1, 0), 0x44);
        assert_eq!(rgb_at(&vis, 0, 1), 0x11);
        assert_eq!(rgb_at(&vis, 1, 1), 0x22);
    }

    #[test]
    fn a_top_down_dib_keeps_its_first_scanline_on_top() {
        let h = info_bytes(2, -2, 32, BI_RGB, 0);
        let info = DibInfo::parse(&h).unwrap();
        assert!(info.top_down);
        let bits: Vec<u8> = [0x11u32, 0x22, 0x33, 0x44].iter().flat_map(|v| v.to_le_bytes()).collect();
        let scans = decode_all(&info, &bits);
        let vis = visual_source(&info, &scans, 0, 0, 2, 2);
        assert_eq!(rgb_at(&vis, 0, 0), 0x11);
        assert_eq!(rgb_at(&vis, 1, 1), 0x44);
    }

    #[test]
    fn every_bit_depth_decodes_to_the_same_known_pixels() {
        let red = 0x00FF_0000;
        let green = 0x0000_FF00;
        let blue = 0x0000_00FF;
        let white = RGB_MASK;
        let want = [red, green, blue, white];

        let pal1 = [0x0000_00, white];
        let h1 = with_palette(info_bytes(4, 1, 1, BI_RGB, 2), &pal1);
        let i1 = DibInfo::parse(&h1).unwrap();
        let p1 = decode_all(&i1, &[0b1010_0000, 0, 0, 0]);
        assert_eq!((0..4).map(|x| rgb_at(&p1, x, 0)).collect::<Vec<_>>(), [white, 0, white, 0]);

        let pal4 = [red, green, blue, white];
        let h4 = with_palette(info_bytes(4, 1, 4, BI_RGB, 4), &pal4);
        let i4 = DibInfo::parse(&h4).unwrap();
        let p4 = decode_all(&i4, &[0x01, 0x23, 0, 0]);
        assert_eq!((0..4).map(|x| rgb_at(&p4, x, 0)).collect::<Vec<_>>(), want);

        let h8 = with_palette(info_bytes(4, 1, 8, BI_RGB, 4), &pal4);
        let i8 = DibInfo::parse(&h8).unwrap();
        let p8 = decode_all(&i8, &[3, 2, 1, 0]);
        assert_eq!((0..4).map(|x| rgb_at(&p8, x, 0)).collect::<Vec<_>>(), [white, blue, green, red]);

        let h16 = info_bytes(4, 1, 16, BI_RGB, 0);
        let i16 = DibInfo::parse(&h16).unwrap();
        let px16: Vec<u8> = [0x7C00u16, 0x03E0, 0x001F, 0x7FFF].iter().flat_map(|v| v.to_le_bytes()).collect();
        let p16 = decode_all(&i16, &px16);
        assert_eq!((0..4).map(|x| rgb_at(&p16, x, 0)).collect::<Vec<_>>(), want);

        let h24 = info_bytes(4, 1, 24, BI_RGB, 0);
        let i24 = DibInfo::parse(&h24).unwrap();
        let px24 = [0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 0, 0, 0, 0];
        let p24 = decode_all(&i24, &px24);
        assert_eq!((0..4).map(|x| rgb_at(&p24, x, 0)).collect::<Vec<_>>(), want);

        let h32 = info_bytes(4, 1, 32, BI_RGB, 0);
        let i32_ = DibInfo::parse(&h32).unwrap();
        let px32: Vec<u8> = want.iter().flat_map(|v| (v | 0x7700_0000u32).to_le_bytes()).collect();
        let p32 = decode_all(&i32_, &px32);
        assert_eq!((0..4).map(|x| rgb_at(&p32, x, 0)).collect::<Vec<_>>(), want);
        assert_eq!(p32.get(0, 0).unwrap() >> 24, 0xFF);
    }

    #[test]
    fn bitfields_16bpp_decodes_as_565() {
        let mut h = info_bytes(1, 1, 16, BI_BITFIELDS, 0);
        for m in [0xF800u32, 0x07E0, 0x001F] {
            h.extend_from_slice(&m.to_le_bytes());
        }
        let info = DibInfo::parse(&h).unwrap();
        assert!(info.decodable());
        assert_eq!(info.total_header_len(), 52);
        let p = decode_all(&info, &[0xE0, 0x07, 0, 0]);
        assert_eq!(rgb_at(&p, 0, 0), 0x0000_FF00);
    }

    #[test]
    fn rle_dibs_are_declared_undecodable() {
        let h = with_palette(info_bytes(4, 1, 8, BI_RLE8, 0), &[0; 256]);
        let info = DibInfo::parse(&h).unwrap();
        assert!(!info.decodable());
        assert!(decode_scans(&info, &[0; 8], 0, 1).is_none());
    }

    #[test]
    fn a_missing_colour_count_means_the_full_table_and_a_core_header_uses_triples() {
        let h = with_palette(info_bytes(2, 1, 4, BI_RGB, 0), &[0; 16]);
        let info = DibInfo::parse(&h).unwrap();
        assert_eq!(info.format.palette.len(), 16);
        assert_eq!(info.total_header_len(), 40 + 64);

        let mut core = vec![0u8; CORE_HEADER_SIZE];
        core[0..4].copy_from_slice(&12u32.to_le_bytes());
        core[4..6].copy_from_slice(&2u16.to_le_bytes());
        core[6..8].copy_from_slice(&1u16.to_le_bytes());
        core[8..10].copy_from_slice(&1u16.to_le_bytes());
        core[10..12].copy_from_slice(&1u16.to_le_bytes());
        core.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        let info = DibInfo::parse(&core).unwrap();
        assert_eq!(info.format.palette, [0x030201, 0x060504]);
        assert_eq!(info.total_header_len(), 12 + 6);
    }

    #[test]
    fn scanlines_outside_startscan_and_lines_are_not_sourced() {
        let h = info_bytes(1, 4, 32, BI_RGB, 0);
        let info = DibInfo::parse(&h).unwrap();
        let bits: Vec<u8> = [0xAAu32, 0xBB].iter().flat_map(|v| v.to_le_bytes()).collect();
        let scans = decode_scans(&info, &bits, 1, 2).unwrap();
        assert_eq!(scans.rect, Rect::new(0, 1, 1, 3));
        let vis = visual_source(&info, &scans, 0, 0, 1, 4);
        assert_eq!(vis.rect, Rect::new(0, 1, 1, 3));
        assert_eq!(rgb_at(&vis, 0, 1), 0xBB);
        assert_eq!(rgb_at(&vis, 0, 2), 0xAA);
    }

    #[test]
    fn a_short_bit_buffer_yields_only_the_full_rows_it_holds() {
        let h = info_bytes(2, 3, 32, BI_RGB, 0);
        let info = DibInfo::parse(&h).unwrap();
        let scans = decode_scans(&info, &[0; 12], 0, 3).unwrap();
        assert_eq!(scans.rect.height(), 1);
    }

    #[test]
    fn encoding_then_decoding_round_trips_each_depth() {
        let want = [0x00FF_0000u32, 0x0000_FF00, 0x0000_00FF, RGB_MASK, 0];
        let pal4 = vec![0, 0x00FF_0000, 0x0000_FF00, 0x0000_00FF, RGB_MASK];
        for (bpp, palette) in [(32u32, vec![]), (24, vec![]), (16, vec![]), (8, pal4.clone()), (4, pal4.clone()), (1, mono_palette())] {
            let f = PixelFormat { bpp, palette, masks: None };
            let mut row = vec![0u8; row_stride(5, bpp)];
            let src: Vec<u32> = if bpp == 1 { vec![RGB_MASK, 0, RGB_MASK, 0, RGB_MASK] } else { want.to_vec() };
            encode_row(&f, &mut row, 0, &src);
            let mut back = [0u32; 5];
            decode_row(&f, &row, 0, &mut back);
            let got: Vec<u32> = back.iter().map(|v| v & RGB_MASK).collect();
            let expect: Vec<u32> = src.iter().map(|v| v & RGB_MASK).collect();
            assert_eq!(got, expect, "{bpp} bpp");
        }
    }

    #[test]
    fn encoding_into_32bpp_keeps_the_unused_byte() {
        let f = PixelFormat { bpp: 32, palette: vec![], masks: None };
        let mut row = [0x00, 0x00, 0x00, 0x5A];
        encode_row(&f, &mut row, 0, &[0x0011_2233]);
        assert_eq!(row, [0x33, 0x22, 0x11, 0x5A]);
    }

    #[test]
    fn decoding_a_row_reads_zero_past_the_buffer() {
        let f = PixelFormat { bpp: 24, palette: vec![], masks: None };
        let mut out = [0u32; 2];
        decode_row(&f, &[1, 2, 3], 0, &mut out);
        assert_eq!(out[0] & RGB_MASK, 0x030201);
        assert_eq!(out[1] & RGB_MASK, 0);
    }
}
