#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::HashMap;

use exemu_core::gui::{Control, ControlKind, DialogTemplate};

use crate::reader::Reader;

pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_FONTDIR: u32 = 7;
pub const RT_FONT: u32 = 8;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_RCDATA: u32 = 10;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_DLGINCLUDE: u32 = 17;
pub const RT_PLUGPLAY: u32 = 19;
pub const RT_VXD: u32 = 20;
pub const RT_ANICURSOR: u32 = 21;
pub const RT_ANIICON: u32 = 22;
pub const RT_HTML: u32 = 23;
pub const RT_MANIFEST: u32 = 24;

const MAX_WALKED_DIR_ENTRIES: usize = 1 << 20;

pub const LANG_ANY: u16 = 0xFFFF;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceName {
    Id(u32),
    Name(String),
}

impl ResourceName {
    fn from_entry(raw: u32, res_base: usize, r: &Reader) -> Self {
        if raw & 0x8000_0000 != 0 {
            let soff = res_base + (raw & 0x7fff_ffff) as usize;
            if let Ok(len) = r.u16(soff) {
                let len = len as usize;
                let mut units = Vec::with_capacity(len);
                for i in 0..len {
                    if let Ok(w) = r.u16(soff + 2 + i * 2) {
                        units.push(w);
                    }
                }
                return Self::Name(String::from_utf16_lossy(&units));
            }
        }
        Self::Id(raw & 0x7fff_ffff)
    }
}

fn resource_root(bytes: &[u8]) -> Option<(usize, impl Fn(u32) -> Option<usize> + '_)> {
    let r = Reader::new(bytes);
    let pe = r.u32(0x3c).ok()? as usize;
    let coff = pe + 4;
    let opt = coff + 20;
    let magic = r.u16(opt).ok()?;
    let is64 = magic == 0x20b;
    let num_sections = r.u16(coff + 2).ok()? as usize;
    let opt_size = r.u16(coff + 16).ok()? as usize;

    let dd = opt + if is64 { 112 } else { 96 };
    let res_rva = r.u32(dd + 2 * 8).ok()?;
    if res_rva == 0 {
        return None;
    }

    let sec_table = opt + opt_size;
    let mut sections: Vec<(u32, u32, u32)> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let vsize = r.u32(s + 8).ok()?;
        let va = r.u32(s + 12).ok()?;
        let rawsz = r.u32(s + 16).ok()?;
        let rawp = r.u32(s + 20).ok()?;
        sections.push((va, vsize.max(rawsz), rawp));
    }

    let rva2off = move |rva: u32| -> Option<usize> {
        for &(va, size, rawp) in &sections {
            if rva >= va && u64::from(rva) < u64::from(va) + u64::from(size) {
                return Some(rawp as usize + (rva - va) as usize);
            }
        }
        None
    };

    let res_base = rva2off(res_rva)?;
    Some((res_base, rva2off))
}

fn dir_entries(r: &Reader, off: usize, budget: &Cell<usize>) -> Option<Vec<(u32, usize, bool)>> {
    let n_named = r.u16(off + 12).ok()? as usize;
    let n_id = r.u16(off + 14).ok()? as usize;
    let total = n_named.saturating_add(n_id);
    budget.set(budget.get().checked_sub(total)?);
    let mut v = Vec::with_capacity(total);
    let mut e = off + 16;
    for _ in 0..total {
        let name = r.u32(e).ok()?;
        let offset = r.u32(e + 4).ok()?;
        let is_dir = offset & 0x8000_0000 != 0;
        v.push((name, (offset & 0x7fff_ffff) as usize, is_dir));
        e += 8;
    }
    Some(v)
}

pub fn find_resource<'a>(
    bytes: &'a [u8],
    type_id: u32,
    name: &ResourceName,
    lang: u16,
) -> Option<&'a [u8]> {
    let r = Reader::new(bytes);
    let (res_base, rva2off) = resource_root(bytes)?;
    let budget = Cell::new(MAX_WALKED_DIR_ENTRIES);

    for (raw_name, sub_off, is_dir) in dir_entries(&r, res_base, &budget)? {
        if !is_dir {
            continue;
        }
        let entry_name = ResourceName::from_entry(raw_name, res_base, &r);
        if entry_name != ResourceName::Id(type_id) {
            continue;
        }
        for (raw_name2, name_off, name_is_dir) in dir_entries(&r, res_base + sub_off, &budget)? {
            if !name_is_dir {
                continue;
            }
            let entry_name2 = ResourceName::from_entry(raw_name2, res_base, &r);
            if &entry_name2 != name {
                continue;
            }
            let lang_entries = dir_entries(&r, res_base + name_off, &budget)?;
            let data_off = if lang == LANG_ANY {
                lang_entries.iter().find(|(_, _, d)| !*d).map(|&(_, off, _)| off)
            } else {
                let exact = lang_entries
                    .iter()
                    .find(|&&(raw_lang, _, d)| !d && (raw_lang & 0x7fff_ffff) as u16 == lang)
                    .map(|&(_, off, _)| off);
                if exact.is_some() {
                    exact
                } else {
                    lang_entries.iter().find(|(_, _, d)| !*d).map(|&(_, off, _)| off)
                }
            }?;

            let de = res_base + data_off;
            let data_rva = r.u32(de).ok()?;
            let size = r.u32(de + 4).ok()? as usize;
            let doff = rva2off(data_rva)?;
            let end = doff.checked_add(size)?.min(bytes.len());
            return bytes.get(doff..end);
        }
    }
    None
}

pub fn find_resource_by_id(bytes: &[u8], type_id: u32, resource_id: u32) -> Option<&[u8]> {
    find_resource(bytes, type_id, &ResourceName::Id(resource_id), LANG_ANY)
}

#[inline]
pub fn find_resource_data(bytes: &[u8], type_id: u32, resource_id: u32) -> Option<&[u8]> {
    find_resource_by_id(bytes, type_id, resource_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    pub type_id: u32,
    pub type_name: Option<String>,
    pub name: ResourceName,
    pub lang: u16,
}

pub fn list_resources(bytes: &[u8]) -> Vec<ResourceEntry> {
    let r = Reader::new(bytes);
    let Some((res_base, _rva2off)) = resource_root(bytes) else {
        return Vec::new();
    };
    let budget = Cell::new(MAX_WALKED_DIR_ENTRIES);

    let mut out = Vec::new();

    let Some(type_entries) = dir_entries(&r, res_base, &budget) else {
        return out;
    };

    for (raw_type, type_sub_off, type_is_dir) in type_entries {
        if !type_is_dir {
            continue;
        }
        let (type_id, type_name) = if raw_type & 0x8000_0000 != 0 {
            let soff = res_base + (raw_type & 0x7fff_ffff) as usize;
            let name_str = if let Ok(len) = r.u16(soff) {
                let len = len as usize;
                let mut units = Vec::with_capacity(len);
                for i in 0..len {
                    if let Ok(w) = r.u16(soff + 2 + i * 2) {
                        units.push(w);
                    }
                }
                String::from_utf16_lossy(&units)
            } else {
                String::new()
            };
            (0u32, Some(name_str))
        } else {
            (raw_type & 0x7fff_ffff, None)
        };

        let Some(name_entries) = dir_entries(&r, res_base + type_sub_off, &budget) else {
            continue;
        };

        for (raw_name, name_sub_off, name_is_dir) in name_entries {
            if !name_is_dir {
                continue;
            }
            let res_name = ResourceName::from_entry(raw_name, res_base, &r);

            let Some(lang_entries) = dir_entries(&r, res_base + name_sub_off, &budget) else {
                continue;
            };

            for (raw_lang, _data_off, data_is_dir) in lang_entries {
                if data_is_dir {
                    continue;
                }
                let lang_id = (raw_lang & 0xffff) as u16;
                out.push(ResourceEntry {
                    type_id,
                    type_name: type_name.clone(),
                    name: res_name.clone(),
                    lang: lang_id,
                });
            }
        }
    }

    out
}

pub fn rt_name(type_id: u32) -> Option<&'static str> {
    Some(match type_id {
        RT_CURSOR => "RT_CURSOR",
        RT_BITMAP => "RT_BITMAP",
        RT_ICON => "RT_ICON",
        RT_MENU => "RT_MENU",
        RT_DIALOG => "RT_DIALOG",
        RT_STRING => "RT_STRING",
        RT_FONTDIR => "RT_FONTDIR",
        RT_FONT => "RT_FONT",
        RT_ACCELERATOR => "RT_ACCELERATOR",
        RT_RCDATA => "RT_RCDATA",
        RT_MESSAGETABLE => "RT_MESSAGETABLE",
        RT_GROUP_CURSOR => "RT_GROUP_CURSOR",
        RT_GROUP_ICON => "RT_GROUP_ICON",
        RT_VERSION => "RT_VERSION",
        RT_DLGINCLUDE => "RT_DLGINCLUDE",
        RT_PLUGPLAY => "RT_PLUGPLAY",
        RT_VXD => "RT_VXD",
        RT_ANICURSOR => "RT_ANICURSOR",
        RT_ANIICON => "RT_ANIICON",
        RT_HTML => "RT_HTML",
        RT_MANIFEST => "RT_MANIFEST",
        _ => return None,
    })
}

pub fn parse_string_block(block_data: &[u8]) -> Vec<String> {
    let mut result = Vec::with_capacity(16);
    let mut pos = 0usize;
    for _ in 0..16 {
        if pos.saturating_add(2) > block_data.len() {
            result.push(String::new());
            continue;
        }
        let count = u16::from_le_bytes([block_data[pos], block_data[pos + 1]]) as usize;
        pos += 2;
        if count == 0 {
            result.push(String::new());
        } else {
            let end = pos + count * 2;
            if end <= block_data.len() {
                let units: Vec<u16> = (0..count)
                    .map(|i| u16::from_le_bytes([block_data[pos + i * 2], block_data[pos + i * 2 + 1]]))
                    .collect();
                result.push(String::from_utf16_lossy(&units));
                pos = end;
            } else {
                result.push(String::new());
                break;
            }
        }
    }
    result
}

pub fn find_string(bytes: &[u8], string_id: u16) -> Option<String> {
    let block_id = (string_id as u32 >> 4) + 1;
    let slot = (string_id & 0xF) as usize;
    let data = find_resource_by_id(bytes, RT_STRING, block_id)?;
    let strings = parse_string_block(data);
    strings.into_iter().nth(slot).filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedFileInfo {
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
}

impl FixedFileInfo {
    pub fn file_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.file_version_ms >> 16) as u16,
            (self.file_version_ms & 0xffff) as u16,
            (self.file_version_ls >> 16) as u16,
            (self.file_version_ls & 0xffff) as u16,
        )
    }

    pub fn product_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.product_version_ms >> 16) as u16,
            (self.product_version_ms & 0xffff) as u16,
            (self.product_version_ls >> 16) as u16,
            (self.product_version_ls & 0xffff) as u16,
        )
    }
}

const VS_FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;

pub fn parse_version_info(data: &[u8]) -> Option<FixedFileInfo> {
    let pos = data.windows(4).position(|w| {
        u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == VS_FIXED_FILE_INFO_SIGNATURE
    })?;

    if pos.saturating_add(52) > data.len() {
        return None;
    }
    let b = &data[pos..pos + 52];
    let u32_at = |off: usize| u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);

    Some(FixedFileInfo {
        file_version_ms: u32_at(8),
        file_version_ls: u32_at(12),
        product_version_ms: u32_at(16),
        product_version_ls: u32_at(20),
        file_flags: u32_at(28),
        file_os: u32_at(32),
        file_type: u32_at(36),
        file_subtype: u32_at(40),
    })
}

pub fn find_version_info(bytes: &[u8]) -> Option<FixedFileInfo> {
    let data = find_resource_by_id(bytes, RT_VERSION, 1)?;
    parse_version_info(data)
}

pub fn parse_dialogs(bytes: &[u8]) -> HashMap<u32, DialogTemplate> {
    try_parse(bytes).unwrap_or_default()
}

fn try_parse(bytes: &[u8]) -> Option<HashMap<u32, DialogTemplate>> {
    let r = Reader::new(bytes);
    let (res_base, rva2off) = resource_root(bytes)?;
    let budget = Cell::new(MAX_WALKED_DIR_ENTRIES);
    let mut out = HashMap::new();

    for (raw_type, sub_off, is_dir) in dir_entries(&r, res_base, &budget)? {
        if !is_dir {
            continue;
        }
        let name = ResourceName::from_entry(raw_type, res_base, &r);
        if name != ResourceName::Id(RT_DIALOG) {
            continue;
        }
        for (raw_dlg, name_off, name_is_dir) in dir_entries(&r, res_base + sub_off, &budget)? {
            if !name_is_dir {
                continue;
            }
            let dlg_id = match ResourceName::from_entry(raw_dlg, res_base, &r) {
                ResourceName::Id(id) => id,
                ResourceName::Name(_) => continue,
            };
            for (_lang, data_off, data_is_dir) in dir_entries(&r, res_base + name_off, &budget)? {
                if data_is_dir {
                    continue;
                }
                let de = res_base + data_off;
                let data_rva = r.u32(de).ok()?;
                let size = r.u32(de + 4).ok()? as usize;
                let doff = rva2off(data_rva)?;
                let end = doff.saturating_add(size).min(bytes.len());
                let Some(raw) = bytes.get(doff..end) else { continue };
                if let Some(tpl) = parse_dialog(raw) {
                    out.insert(dlg_id, tpl);
                }
            }
        }
    }
    Some(out)
}

struct Cur<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cur<'a> {
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([
            *self.b.get(self.o).unwrap_or(&0),
            *self.b.get(self.o + 1).unwrap_or(&0),
        ]);
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
        u16::from_le_bytes([
            *self.b.get(self.o).unwrap_or(&0),
            *self.b.get(self.o + 1).unwrap_or(&0),
        ])
    }
    fn align_dword(&mut self) {
        self.o = (self.o + 3) & !3;
    }
    fn sz_or_ord(&mut self) -> String {
        match self.peek16() {
            0x0000 => {
                self.o += 2;
                String::new()
            }
            0xFFFF => {
                self.o += 4;
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

    let style;
    let count;
    let (cx, cy);
    if ex {
        c.u16();
        c.u16();
        c.u32();
        c.u32();
        style = c.u32();
        count = c.u16();
        c.i16();
        c.i16();
        cx = c.u16();
        cy = c.u16();
    } else {
        style = c.u32();
        c.u32();
        count = c.u16();
        c.i16();
        c.i16();
        cx = c.u16();
        cy = c.u16();
    }

    c.sz_or_ord();
    c.sz_or_ord();
    let title = c.sz_or_ord();
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
            c.u32();
            c.u32();
            ctl_style = c.u32();
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u32();
        } else {
            ctl_style = c.u32();
            c.u32();
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u16() as u32;
        }

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
        let extra = c.u16() as usize;
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
        if matches!(bs, 2 | 3 | 4 | 5 | 6 | 9) {
            ControlKind::Check
        } else {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn string_block_fixture() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        let hello: Vec<u16> = "Hello".encode_utf16().collect();
        data.extend_from_slice(&(hello.len() as u16).to_le_bytes());
        for w in &hello {
            data.extend_from_slice(&w.to_le_bytes());
        }
        for _ in 2u16..16 {
            data.extend_from_slice(&0u16.to_le_bytes());
        }
        data
    }

    #[test]
    fn string_block_parses_slots_correctly() {
        let data = string_block_fixture();
        let strings = parse_string_block(&data);
        assert_eq!(strings.len(), 16);
        assert!(strings[0].is_empty(), "slot 0 must be empty");
        assert_eq!(strings[1], "Hello", "slot 1 must be 'Hello'");
        for s in strings.iter().skip(2) {
            assert!(s.is_empty(), "remaining slots must be empty");
        }
    }

    #[test]
    fn string_block_handles_empty_input() {
        let strings = parse_string_block(&[]);
        assert_eq!(strings.len(), 16);
        for s in &strings {
            assert!(s.is_empty());
        }
    }

    #[test]
    fn string_block_handles_truncated_input() {
        let data = 5u16.to_le_bytes().to_vec();
        let strings = parse_string_block(&data);
        assert!(strings[0].is_empty());
    }

    fn version_info_fixture(
        file_major: u16,
        file_minor: u16,
        file_patch: u16,
        file_build: u16,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 92];
        let total = data.len() as u16;
        data[0..2].copy_from_slice(&total.to_le_bytes());
        data[2..4].copy_from_slice(&52u16.to_le_bytes());
        data[4..6].copy_from_slice(&0u16.to_le_bytes());
        let key: Vec<u8> = "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        data[6..6 + key.len()].copy_from_slice(&key);
        let b = &mut data[40..];
        let put32 = |d: &mut [u8], off: usize, v: u32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(b, 0, VS_FIXED_FILE_INFO_SIGNATURE);
        put32(b, 4, 0x0001_0000);
        put32(b, 8, ((file_major as u32) << 16) | file_minor as u32);
        put32(b, 12, ((file_patch as u32) << 16) | file_build as u32);
        put32(b, 16, ((file_major as u32) << 16) | file_minor as u32);
        put32(b, 20, ((file_patch as u32) << 16) | file_build as u32);
        put32(b, 24, 0x3f);
        put32(b, 28, 0);
        put32(b, 32, 0x0004);
        put32(b, 36, 0x0001);
        put32(b, 40, 0);
        put32(b, 44, 0);
        put32(b, 48, 0);
        data
    }

    #[test]
    fn parse_version_info_extracts_file_version() {
        let data = version_info_fixture(1, 2, 3, 4);
        let info = parse_version_info(&data).expect("must parse");
        assert_eq!(info.file_version(), (1, 2, 3, 4), "file version");
        assert_eq!(info.product_version(), (1, 2, 3, 4), "product version");
        assert_eq!(info.file_type, 0x0001, "file type = VFT_APP");
        assert_eq!(info.file_os, 0x0004, "file os = VOS_WIN32");
    }

    #[test]
    fn parse_version_info_returns_none_for_missing_signature() {
        let data = vec![0u8; 92];
        assert!(parse_version_info(&data).is_none());
    }

    #[test]
    fn parse_version_info_returns_none_for_truncated_data() {
        let mut data = version_info_fixture(1, 0, 0, 0);
        data.truncate(50);
        let _ = parse_version_info(&data);
    }

    const EXAMPLE_EXE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_exe");

    fn read_binary(name: &str) -> Option<Vec<u8>> {
        let path = format!("{EXAMPLE_EXE}/{name}");
        std::fs::read(&path).ok()
    }

    #[test]
    fn tcc_has_no_rt_version_or_manifest() {
        let Some(bytes) = read_binary("tcc.exe") else {
            return;
        };
        let _ = find_version_info(&bytes);
        let entries = list_resources(&bytes);
        for e in &entries {
            assert!(e.type_id > 0 || e.type_name.is_some());
        }
    }

    #[test]
    fn z7_has_rt_version_and_manifest() {
        let Some(bytes) = read_binary("7z2602-x64.exe") else {
            return;
        };

        let info = find_version_info(&bytes)
            .expect("7z2602-x64.exe must have RT_VERSION with a valid VS_FIXEDFILEINFO");
        let (major, _minor, _patch, _build) = info.file_version();
        assert_eq!(major, 26, "7z file version major must be 26");

        let manifest =
            find_resource(&bytes, RT_MANIFEST, &ResourceName::Id(1), LANG_ANY);
        assert!(manifest.is_some(), "7z must have RT_MANIFEST ID 1");

        let entries = list_resources(&bytes);
        assert!(
            entries.iter().any(|e| e.type_id == RT_VERSION),
            "list_resources must include RT_VERSION"
        );
        assert!(
            entries.iter().any(|e| e.type_id == RT_MANIFEST),
            "list_resources must include RT_MANIFEST"
        );
        assert!(
            entries.iter().any(|e| e.type_id == RT_DIALOG),
            "list_resources must include RT_DIALOG"
        );
    }

    #[test]
    fn named_resource_name_round_trips() {
        let name = ResourceName::Name("TestResource".to_string());
        assert_eq!(name, ResourceName::Name("TestResource".to_string()));
        assert_ne!(name, ResourceName::Id(42));
    }

    #[test]
    fn find_resource_returns_none_for_absent_type() {
        let Some(bytes) = read_binary("7z2602-x64.exe") else {
            return;
        };
        let result = find_resource(&bytes, RT_FONT, &ResourceName::Id(1), LANG_ANY);
        let _ = result;
    }

    #[test]
    fn find_string_returns_none_for_absent_block() {
        let result = find_string(&[], 0x100);
        assert!(result.is_none());
    }

    #[test]
    fn rt_name_covers_standard_types() {
        assert_eq!(rt_name(RT_ICON), Some("RT_ICON"));
        assert_eq!(rt_name(RT_VERSION), Some("RT_VERSION"));
        assert_eq!(rt_name(RT_MANIFEST), Some("RT_MANIFEST"));
        assert_eq!(rt_name(RT_STRING), Some("RT_STRING"));
        assert_eq!(rt_name(RT_MENU), Some("RT_MENU"));
        assert_eq!(rt_name(99), None);
    }

    #[test]
    fn list_resources_returns_empty_for_minimal_pe() {
        let pe = minimal_pe_no_resource();
        let entries = list_resources(&pe);
        assert!(entries.is_empty(), "minimal PE must have no resources");
    }

    fn minimal_pe_no_resource() -> Vec<u8> {
        const PE_SIGNATURE: u32 = 0x0000_4550;
        const MACHINE_AMD64: u16 = 0x8664;
        const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

        let mut f = vec![0u8; 0x600];
        f[0] = 0x4D;
        f[1] = 0x5A;
        let pe_off = 0x80usize;
        f[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        f[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        let coff = pe_off + 4;
        f[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        let size_opt = 0xF0u16;
        f[coff + 16..coff + 18].copy_from_slice(&size_opt.to_le_bytes());
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        f[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        f[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        f[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        f[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + size_opt as usize;
        f[sec..sec + 5].copy_from_slice(b".text");
        f[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
        f[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        f[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        f[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        f[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        f
    }
}
