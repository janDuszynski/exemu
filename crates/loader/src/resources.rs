//! Minimal PE resource parsing: extract `RT_DIALOG` templates so the GUI can
//! render them. Best-effort — any malformed input yields no dialogs rather
//! than an error, since rendering is optional.

use std::collections::HashMap;

use exemu_core::gui::{Control, ControlKind, DialogTemplate};

use crate::reader::Reader;

const RT_DIALOG: u32 = 5;

/// Parse all dialog templates in `bytes`, keyed by their (integer) resource id.
pub fn parse_dialogs(bytes: &[u8]) -> HashMap<u32, DialogTemplate> {
    try_parse(bytes).unwrap_or_default()
}

fn try_parse(bytes: &[u8]) -> Option<HashMap<u32, DialogTemplate>> {
    let r = Reader::new(bytes);
    let pe = r.u32(0x3c).ok()? as usize;
    let coff = pe + 4;
    let opt = coff + 20;
    let magic = r.u16(opt).ok()?;
    let is64 = magic == 0x20b;
    let num_sections = r.u16(coff + 2).ok()? as usize;
    let opt_size = r.u16(coff + 16).ok()? as usize;

    // Resource data directory (index 2).
    let dd = opt + if is64 { 112 } else { 96 };
    let res_rva = r.u32(dd + 2 * 8).ok()?;
    if res_rva == 0 {
        return None;
    }

    // Section table for RVA → file offset.
    let sec_table = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let vsize = r.u32(s + 8).ok()?;
        let va = r.u32(s + 12).ok()?;
        let rawsz = r.u32(s + 16).ok()?;
        let rawp = r.u32(s + 20).ok()?;
        sections.push((va, vsize.max(rawsz), rawp));
    }
    let rva2off = |rva: u32| -> Option<usize> {
        for &(va, size, rawp) in &sections {
            if rva >= va && rva < va + size {
                return Some((rawp + (rva - va)) as usize);
            }
        }
        None
    };

    let res_base = rva2off(res_rva)?;
    let mut out = HashMap::new();

    // Level 0: resource types. Find RT_DIALOG.
    for (type_id, sub_off, is_dir) in dir_entries(&r, res_base)? {
        if type_id != RT_DIALOG || !is_dir {
            continue;
        }
        // Level 1: names/ids of dialogs.
        for (dlg_id, name_off, name_is_dir) in dir_entries(&r, res_base + sub_off)? {
            if !name_is_dir {
                continue;
            }
            // Level 2: languages → data entry.
            for (_lang, data_off, data_is_dir) in dir_entries(&r, res_base + name_off)? {
                if data_is_dir {
                    continue;
                }
                let de = res_base + data_off;
                let data_rva = r.u32(de).ok()?;
                let size = r.u32(de + 4).ok()? as usize;
                let doff = rva2off(data_rva)?;
                if let Some(tpl) = parse_dialog(&bytes[doff..(doff + size).min(bytes.len())]) {
                    out.insert(dlg_id, tpl);
                }
            }
        }
    }
    Some(out)
}

/// Read the entries of one IMAGE_RESOURCE_DIRECTORY at `off`. Returns
/// `(NameOrId, offset-relative-to-res-base, is_subdirectory)`.
fn dir_entries(r: &Reader, off: usize) -> Option<Vec<(u32, usize, bool)>> {
    let n_named = r.u16(off + 12).ok()? as usize;
    let n_id = r.u16(off + 14).ok()? as usize;
    let mut v = Vec::with_capacity(n_named + n_id);
    let mut e = off + 16;
    for _ in 0..(n_named + n_id) {
        let name = r.u32(e).ok()?;
        let offset = r.u32(e + 4).ok()?;
        let is_dir = offset & 0x8000_0000 != 0;
        v.push((name, (offset & 0x7fff_ffff) as usize, is_dir));
        e += 8;
    }
    Some(v)
}

/// A byte cursor over a dialog template blob.
struct Cur<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cur<'a> {
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([*self.b.get(self.o).unwrap_or(&0), *self.b.get(self.o + 1).unwrap_or(&0)]);
        self.o += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let lo = self.u16() as u32;
        let hi = self.u16() as u32;
        lo | (hi << 16)
    }
    fn i16(&mut self) -> i16 {
        self.u16() as i16
    }
    fn peek16(&self) -> u16 {
        u16::from_le_bytes([*self.b.get(self.o).unwrap_or(&0), *self.b.get(self.o + 1).unwrap_or(&0)])
    }
    fn align_dword(&mut self) {
        self.o = (self.o + 3) & !3;
    }
    /// Read a menu/class/title field: 0x0000 = none, 0xFFFF + ordinal, else
    /// a NUL-terminated wide string. Returns the string (empty for ordinals).
    fn sz_or_ord(&mut self) -> String {
        match self.peek16() {
            0x0000 => {
                self.o += 2;
                String::new()
            }
            0xFFFF => {
                self.o += 4; // 0xFFFF + ordinal
                String::new()
            }
            _ => self.wstr(),
        }
    }
    fn wstr(&mut self) -> String {
        let mut units = Vec::new();
        loop {
            let w = self.u16();
            if w == 0 {
                break;
            }
            units.push(w);
        }
        String::from_utf16_lossy(&units)
    }
}

fn parse_dialog(b: &[u8]) -> Option<DialogTemplate> {
    let mut c = Cur { b, o: 0 };
    let ex = c.peek16() == 0xFFFF;

    // Header (fields read strictly in order — no fixed offsets).
    let style;
    let count;
    let (cx, cy);
    if ex {
        c.u16(); // dlgVer
        c.u16(); // signature (0xFFFF)
        c.u32(); // helpID
        c.u32(); // exStyle
        style = c.u32();
        count = c.u16();
        c.i16(); // x
        c.i16(); // y
        cx = c.u16();
        cy = c.u16();
    } else {
        style = c.u32();
        c.u32(); // exStyle
        count = c.u16();
        c.i16(); // x
        c.i16(); // y
        cx = c.u16();
        cy = c.u16();
    }

    c.sz_or_ord(); // menu
    c.sz_or_ord(); // window class
    let title = c.sz_or_ord(); // title
    // DS_SETFONT (0x40): pointsize (+weight/italic/charset for EX) + typeface.
    if style & 0x40 != 0 {
        if ex {
            c.o += 6;
        } else {
            c.o += 2;
        }
        c.wstr();
    }

    let mut controls = Vec::with_capacity(count as usize);
    for _ in 0..count {
        c.align_dword();
        let ctl_style;
        let (x, y, cw, ch);
        let id;
        if ex {
            c.u32(); // helpID
            c.u32(); // exStyle
            ctl_style = c.u32();
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u32();
        } else {
            ctl_style = c.u32();
            c.u32(); // exStyle
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u16() as u32;
        }

        // class: ordinal (0xFFFF + u16) or wide string.
        let class_ord;
        let class_name;
        if c.peek16() == 0xFFFF {
            c.o += 2;
            class_ord = c.u16();
            class_name = String::new();
        } else {
            class_ord = 0;
            class_name = c.wstr();
        }
        let text = if c.peek16() == 0xFFFF {
            c.o += 4;
            String::new()
        } else {
            c.wstr()
        };
        let extra = c.u16() as usize; // creation-data byte count
        c.o += extra;

        let kind = classify_control(class_ord, &class_name, ctl_style);
        controls.push(Control { id, kind, text, x, y, cx: cw, cy: ch });
    }

    Some(DialogTemplate { title, cx, cy, controls })
}

fn classify_control(class_ord: u16, class_name: &str, style: u32) -> ControlKind {
    let lname = class_name.to_ascii_lowercase();
    if class_ord == 0x0080 || lname == "button" {
        let bs = style & 0xf;
        // BS_CHECKBOX=2, BS_AUTOCHECKBOX=3, BS_RADIOBUTTON=4, BS_AUTORADIO=9
        if matches!(bs, 2 | 3 | 4 | 5 | 6 | 9) {
            ControlKind::Check
        } else {
            // BS_DEFPUSHBUTTON = 1
            ControlKind::Button { default: bs == 1 }
        }
    } else if class_ord == 0x0081 || lname == "edit" {
        ControlKind::Edit
    } else if class_ord == 0x0082 || lname == "static" {
        ControlKind::Static
    } else if lname.contains("progress") {
        ControlKind::Progress
    } else {
        ControlKind::Other
    }
}
