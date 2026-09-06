use exemu_core::{CpuState, Memory, Perm, Reg, Result};

use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

pub(crate) const SSDT_NT_GET_NLS_SECTION_PTR: u32 = 0x9b;
pub(crate) const SSDT_NT_INITIALIZE_NLS_FILES: u32 = 0x9e;

const SYSTEM_LCID: u32 = 0x0000_0409;

const CP_UTF8: u16 = 0xFDE9;

const HDR_LOCALE_TABLE_OFF: usize = 0x10;
const HDR_CHARMAPS_OFF: usize = 0x14;
const HDR_GEO_OFF: usize = 0x18;

const LT_NB_LCIDS: usize = 0x1e;
const LT_STRIDE: usize = 0x22;
const LT_LOCALES_OFF: usize = 0x24;
const LT_LCNAMES_SIZE: usize = 0x28;
const LT_LCIDS_OFF: usize = 0x2c;
const LT_LCNAMES_OFF: usize = 0x30;
const LT_STRINGS_OFF: usize = 0x40;

const LCID_ENTRY_LEN: usize = 8;

const REC_LEN: usize = 0x130;
const REC_LCID: usize = 0x08;
const REC_FLAG_18: usize = 0x18;
const REC_ACP: usize = 0x6e;
const REC_OEMCP: usize = 0x70;
const REC_NAME_STR: usize = 0x124;

fn build_locale_nls() -> Vec<u8> {
    const HDR: usize = 0x00;
    const LOCALE_TABLE: usize = 0x80;
    const LCIDS: usize = 0x200;
    const LCNAMES: usize = 0x240;
    const STRINGS: usize = 0x280;
    const RECORDS: usize = 0x300;
    const CHARMAPS: usize = 0x300 + REC_LEN;
    const GEO: usize = CHARMAPS + 0x40;

    let total = GEO + 0x80;
    let mut b = vec![0u8; total];

    let put16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());

    put32(&mut b, HDR + HDR_LOCALE_TABLE_OFF, LOCALE_TABLE as u32);
    put32(&mut b, HDR + HDR_CHARMAPS_OFF, CHARMAPS as u32);
    put32(&mut b, HDR + HDR_GEO_OFF, GEO as u32);

    put16(&mut b, LOCALE_TABLE + LT_NB_LCIDS, 1);
    put16(&mut b, LOCALE_TABLE + LT_STRIDE, REC_LEN as u16);
    put32(&mut b, LOCALE_TABLE + LT_LOCALES_OFF, (RECORDS - LOCALE_TABLE) as u32);
    put16(&mut b, LOCALE_TABLE + LT_LCNAMES_SIZE, 1);
    put32(&mut b, LOCALE_TABLE + LT_LCIDS_OFF, (LCIDS - LOCALE_TABLE) as u32);
    put32(&mut b, LOCALE_TABLE + LT_LCNAMES_OFF, (LCNAMES - LOCALE_TABLE) as u32);
    put32(&mut b, LOCALE_TABLE + LT_STRINGS_OFF, (STRINGS - LOCALE_TABLE) as u32);

    put32(&mut b, LCIDS, SYSTEM_LCID);
    put16(&mut b, LCIDS + 0x04, 0);
    put16(&mut b, LCIDS + 0x06, 0);

    put16(&mut b, RECORDS + REC_LCID, SYSTEM_LCID as u16);
    put16(&mut b, RECORDS + REC_FLAG_18, 1);
    put16(&mut b, RECORDS + REC_ACP, CP_UTF8);
    put16(&mut b, RECORDS + REC_OEMCP, CP_UTF8);
    put32(&mut b, RECORDS + REC_NAME_STR, 0);

    let _ = CHARMAPS;

    let _ = GEO;
    let _ = LCID_ENTRY_LEN;

    b
}

fn build_sort_nls() -> Vec<u8> {
    const DIR: usize = 0x00;
    const KEYS: usize = 0x80;
    let total = KEYS + 0x200;
    let mut b = vec![0u8; total];
    let put32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());

    put32(&mut b, DIR, KEYS as u32);
    put32(&mut b, DIR + 0x4, KEYS as u32);
    put32(&mut b, DIR + 0x8, KEYS as u32);
    put32(&mut b, DIR + 0xc, KEYS as u32);

    b
}

fn build_opaque_nls() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0x00..0x02].copy_from_slice(&CP_HEADER_WORDS.to_le_bytes());
    b[0x02..0x04].copy_from_slice(&CP_UTF8.to_le_bytes());
    b
}

pub(crate) const NLS_SECTION_CODEPAGE: u32 = 0xB;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

const CP_HEADER_WORDS: u16 = 0x000D;

const UNI_DEFAULT: u16 = 0xFFFD;

const MB_DEFAULT: u8 = b'?';

fn sbcs_map(cp: u32) -> Option<[u16; 256]> {
    let mut m = [UNI_DEFAULT; 256];
    for (b, slot) in m.iter_mut().enumerate().take(0x80) {
        *slot = b as u16;
    }
    match cp {
        20127 => {}
        28591 => {
            for (b, slot) in m.iter_mut().enumerate().skip(0x80) {
                *slot = b as u16;
            }
        }
        1252 => {
            for (b, slot) in m.iter_mut().enumerate().skip(0x80) {
                *slot = b as u16;
            }
            const C1: [u16; 32] = [
                0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
                0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
                0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
                0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
            ];
            m[0x80..0xA0].copy_from_slice(&C1);
        }
        _ => return None,
    }
    Some(m)
}

fn build_sbcs_codepage_nls(cp: u32, map: &[u16; 256]) -> Vec<u8> {
    const BODY: usize = 2 * CP_HEADER_WORDS as usize;
    const WC_OFFSET: u16 = 256 + 1 + 1;
    const WCT: usize = 2 + 2 * WC_OFFSET as usize;

    let mut b = vec![0u8; BODY + WCT + 0x1_0000];
    let put16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());

    put16(&mut b, 0x00, CP_HEADER_WORDS);
    put16(&mut b, 0x02, cp as u16);
    put16(&mut b, 0x04, 1);
    put16(&mut b, 0x06, MB_DEFAULT as u16);
    put16(&mut b, 0x08, UNI_DEFAULT);
    put16(&mut b, 0x0a, MB_DEFAULT as u16);
    put16(&mut b, 0x0c, UNI_DEFAULT);

    put16(&mut b, BODY, WC_OFFSET);
    for (byte, &wc) in map.iter().enumerate() {
        put16(&mut b, BODY + 2 + byte * 2, wc);
    }

    let wct = BODY + WCT;
    b[wct..wct + 0x1_0000].fill(MB_DEFAULT);
    for (byte, &wc) in map.iter().enumerate().rev() {
        if wc != UNI_DEFAULT {
            b[wct + wc as usize] = byte as u8;
        }
    }
    b
}

pub(crate) fn sbcs_decode(cp: u32, bytes: &[u8]) -> Option<Vec<u16>> {
    let map = sbcs_map(cp)?;
    Some(bytes.iter().map(|&b| map[b as usize]).collect())
}

pub(crate) fn sbcs_encode(cp: u32, units: &[u16]) -> Option<(Vec<u8>, bool)> {
    let map = sbcs_map(cp)?;
    let mut used_default = false;
    let bytes = units
        .iter()
        .map(|&wc| match map.iter().position(|&m| m == wc && m != UNI_DEFAULT) {
            Some(b) => b as u8,
            None => {
                used_default = true;
                MB_DEFAULT
            }
        })
        .collect();
    Some((bytes, used_default))
}

fn build_codepage_nls(cp: u32) -> Option<Vec<u8>> {
    if cp == CP_UTF8 as u32 {
        return Some(build_opaque_nls());
    }
    sbcs_map(cp).map(|m| build_sbcs_codepage_nls(cp, &m))
}

pub(crate) const NLS_SECTION_CASEMAP: u32 = 0xA;

const CASE_BLOCK: usize = 16;

fn build_casemap_nls() -> Vec<u8> {
    let upper = build_case_table(|c| c.to_uppercase());
    let lower = build_case_table(|c| c.to_lowercase());
    assert!(upper.len() <= u16::MAX as usize, "upcase table fits its WORD length field");

    let mut b = Vec::with_capacity(4 + (upper.len() + lower.len()) * 2);
    b.extend_from_slice(&((2 + upper.len() + lower.len()) as u16).to_le_bytes());
    b.extend_from_slice(&(upper.len() as u16).to_le_bytes());
    for w in upper.iter().chain(lower.iter()) {
        b.extend_from_slice(&w.to_le_bytes());
    }
    b
}

fn build_case_table<I: Iterator<Item = char>>(f: impl Fn(char) -> I) -> Vec<u16> {
    let delta = |ch: u16| -> u16 {
        let Some(c) = char::from_u32(ch as u32) else { return 0 };
        let mut it = f(c);
        match (it.next(), it.next()) {
            (Some(m), None) => u16::try_from(m as u32).map(|m| m.wrapping_sub(ch)).unwrap_or(0),
            _ => 0,
        }
    };

    let mut l3_blocks: Vec<[u16; CASE_BLOCK]> = Vec::new();
    let mut l3_of_row: Vec<usize> = Vec::with_capacity(0x1000);
    for row in 0..0x1000u32 {
        let mut block = [0u16; CASE_BLOCK];
        for (i, slot) in block.iter_mut().enumerate() {
            *slot = delta((row * CASE_BLOCK as u32 + i as u32) as u16);
        }
        l3_of_row.push(match l3_blocks.iter().position(|b| *b == block) {
            Some(i) => i,
            None => {
                l3_blocks.push(block);
                l3_blocks.len() - 1
            }
        });
    }

    let mut l2_blocks: Vec<[usize; CASE_BLOCK]> = Vec::new();
    let mut l2_of_page: Vec<usize> = Vec::with_capacity(0x100);
    for page in 0..0x100usize {
        let mut block = [0usize; CASE_BLOCK];
        for (i, slot) in block.iter_mut().enumerate() {
            *slot = l3_of_row[page * CASE_BLOCK + i];
        }
        l2_of_page.push(match l2_blocks.iter().position(|b| *b == block) {
            Some(i) => i,
            None => {
                l2_blocks.push(block);
                l2_blocks.len() - 1
            }
        });
    }

    let l2_base = 0x100;
    let l3_base = l2_base + l2_blocks.len() * CASE_BLOCK;
    let total = l3_base + l3_blocks.len() * CASE_BLOCK;
    assert!(total <= 0x8000, "case table indices stay positive as signed 32-bit");

    let mut t = vec![0u16; total];
    for (page, &b) in l2_of_page.iter().enumerate() {
        t[page] = (l2_base + b * CASE_BLOCK) as u16;
    }
    for (i, block) in l2_blocks.iter().enumerate() {
        for (j, &l3) in block.iter().enumerate() {
            t[l2_base + i * CASE_BLOCK + j] = (l3_base + l3 * CASE_BLOCK) as u16;
        }
    }
    for (i, block) in l3_blocks.iter().enumerate() {
        t[l3_base + i * CASE_BLOCK..l3_base + (i + 1) * CASE_BLOCK].copy_from_slice(block);
    }
    t
}

fn nls_trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("EXEMU_NLS_TRACE").is_some())
}

impl WinOs {
    fn map_nls_blob(&mut self, mem: &mut dyn Memory, blob: &[u8], name: &str) -> u64 {
        let size = (blob.len() as u64 + 0xfff) & !0xfff;
        let placed = if self.wow64_peb32 != 0 {
            self.map_anywhere_low(mem, size, Perm::RW, name)
        } else {
            self.map_anywhere(mem, size, Perm::RW, name)
        };
        match placed {
            Some(base) => match mem.write(base, blob) {
                Ok(()) => base,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    fn nt_initialize_nls_files(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let base_out = cpu.reg(Reg::R10);
        let lcid_out = cpu.reg(Reg::Rdx);
        let size_out = cpu.reg(Reg::R8);

        let (base, size) = match self.nls_locale_base {
            Some(pair) => pair,
            None => {
                let blob = build_locale_nls();
                let base = self.map_nls_blob(mem, &blob, "nls-locale");
                if base == 0 {
                    return Ok(STATUS_NO_MEMORY);
                }
                let pair = (base, blob.len() as u64);
                self.nls_locale_base = Some(pair);
                pair
            }
        };

        if base_out != 0 {
            mem.write_u64(base_out, base)?;
        }
        if lcid_out != 0 {
            mem.write_u32(lcid_out, SYSTEM_LCID)?;
        }
        if size_out != 0 {
            mem.write_u64(size_out, size)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn nt_get_nls_section_ptr(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let sec_type = cpu.reg(Reg::R10) as u32;
        let sec_id = cpu.reg(Reg::Rdx) as u32;
        let base_out = cpu.reg(Reg::R9);
        let size_out = self.syscall_arg(cpu, mem, 4)?;
        if nls_trace() {
            eprintln!("[nls] NtGetNlsSectionPtr type={sec_type} id={sec_id}");
        }

        let cached = self
            .nls_section_bases
            .iter()
            .find(|(t, i, _, _)| *t == sec_type && *i == sec_id)
            .copied();
        let (base, size) = match cached {
            Some((_, _, b, s)) => (b, s),
            None => {
                let blob = match sec_type {
                    9 => build_sort_nls(),
                    NLS_SECTION_CASEMAP => build_casemap_nls(),
                    NLS_SECTION_CODEPAGE => match build_codepage_nls(sec_id) {
                        Some(b) => b,
                        None => return Ok(STATUS_OBJECT_NAME_NOT_FOUND),
                    },
                    _ => build_opaque_nls(),
                };
                let base = self.map_nls_blob(mem, &blob, "nls-section");
                if base == 0 {
                    return Ok(STATUS_NO_MEMORY);
                }
                let size = blob.len() as u64;
                self.nls_section_bases.push((sec_type, sec_id, base, size));
                (base, size)
            }
        };

        if base_out != 0 {
            mem.write_u64(base_out, base)?;
        }
        if size_out != 0 {
            mem.write_u64(size_out, size)?;
        }
        Ok(STATUS_SUCCESS)
    }
}

pub(crate) fn ssdt_nt_initialize_nls_files(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_initialize_nls_files(cpu, mem)
}

pub(crate) fn ssdt_nt_get_nls_section_ptr(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_get_nls_section_ptr(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::Exit;
    use exemu_memory::VirtualMemory;

    fn os64() -> WinOs {
        WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() })
    }

    fn rd32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn rd16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }

    fn guest_lookup(t: &[u16], ch: u16) -> u16 {
        let l2 = t[(ch >> 8) as usize] as usize;
        let l3 = t[l2 + ((ch >> 4) & 0xF) as usize] as usize;
        ch.wrapping_add(t[l3 + (ch & 0xF) as usize])
    }

    fn case_tables(b: &[u8]) -> (Vec<u16>, Vec<u16>) {
        let words: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let up_len = words[1] as usize;
        (words[2..2 + up_len].to_vec(), words[2 + up_len..].to_vec())
    }

    #[test]
    fn casemap_section_upcases_and_downcases_the_whole_bmp() {
        let b = build_casemap_nls();
        let (up, down) = case_tables(&b);
        assert_eq!(rd16(&b, 0), (2 + up.len() + down.len()) as u16, "self-describing WORD count");
        assert_eq!(rd16(&b, 2), up.len() as u16, "upcase length is what ntdll splits on");

        assert_eq!(guest_lookup(&up, b'n' as u16), b'N' as u16);
        assert_eq!(guest_lookup(&down, b'N' as u16), b'n' as u16);

        let simple = |c: char, f: fn(char) -> Box<dyn Iterator<Item = char>>| -> Option<u16> {
            let mut it = f(c);
            match (it.next(), it.next()) {
                (Some(m), None) => u16::try_from(m as u32).ok(),
                _ => None,
            }
        };
        let mut mapped = 0usize;
        for ch in 0..=u16::MAX {
            let Some(c) = char::from_u32(ch as u32) else {
                assert_eq!(guest_lookup(&up, ch), ch, "unpaired surrogate {ch:#x} unchanged");
                continue;
            };
            let want_up = simple(c, |c| Box::new(c.to_uppercase())).unwrap_or(ch);
            let want_down = simple(c, |c| Box::new(c.to_lowercase())).unwrap_or(ch);
            assert_eq!(guest_lookup(&up, ch), want_up, "upcase {ch:#x}");
            assert_eq!(guest_lookup(&down, ch), want_down, "downcase {ch:#x}");
            if want_up != ch {
                mapped += 1;
            }
        }
        assert!(mapped > 1000, "only {mapped} characters upcase — the table is degenerate");
    }

    #[test]
    fn casemap_section_stays_compact() {
        let b = build_casemap_nls();
        let (up, down) = case_tables(&b);
        for t in [&up, &down] {
            assert!(t.len() <= 0x8000, "table length {} keeps indices positive", t.len());
            assert!(t.len() >= 0x100 + CASE_BLOCK, "at least level 1 plus one block");
        }
        assert!(b.len() < 64 * 1024, "the whole section is a few KiB, got {}", b.len());
    }

    #[test]
    fn locale_nls_header_is_walkable() {
        let b = build_locale_nls();

        let lt = rd32(&b, HDR_LOCALE_TABLE_OFF) as usize;
        assert!(lt < b.len(), "locale-table offset in-bounds");

        let count = rd16(&b, lt + LT_NB_LCIDS);
        assert_eq!(count, 1, "exactly one locale entry");
        let lcids = lt + rd32(&b, lt + LT_LCIDS_OFF) as usize;
        assert!(lcids + LCID_ENTRY_LEN <= b.len(), "LCID index in-bounds");
        let strings = lt + rd32(&b, lt + LT_STRINGS_OFF) as usize;
        assert!(strings < b.len(), "strings block in-bounds");

        assert_eq!(rd32(&b, lcids), SYSTEM_LCID, "index holds LCID 0x409");
        let idx = rd16(&b, lcids + 4) as usize;
        let stride = rd16(&b, lt + LT_STRIDE) as usize;
        let rec = lt + rd32(&b, lt + LT_LOCALES_OFF) as usize + idx * stride;
        assert!(rec + REC_LEN <= b.len(), "resolved record in-bounds");

        assert_eq!(rd16(&b, rec + REC_ACP), CP_UTF8, "ANSI cp = UTF-8");
        assert_eq!(rd16(&b, rec + REC_OEMCP), CP_UTF8, "OEM cp = UTF-8");
        assert_ne!(rd16(&b, rec + REC_FLAG_18), 0, "validate-locale success flag");
    }

    #[test]
    fn opaque_section_marks_utf8() {
        let b = build_opaque_nls();
        assert_eq!(rd16(&b, 0x02), CP_UTF8, "CodePage field = 65001 (UTF-8)");
    }

    struct CpTable {
        code_page: u16,
        max_char_size: u16,
        default_char: u16,
        uni_default_char: u16,
        dbcs_code_page: u16,
        multi_byte: usize,
        wide_char: usize,
    }

    impl CpTable {
        fn parse(b: &[u8]) -> CpTable {
            let hdr_words = rd16(b, 0x00) as usize;
            let body = 2 * hdr_words;
            let wc_offset = rd16(b, body) as usize;
            let multi_byte = body + 2;
            let wide_char = body + 2 + 2 * wc_offset;
            let ranges = if rd16(b, body + 0x202) != 0 { body + 0x404 } else { body + 0x204 };
            let dbcs_code_page = u16::from(rd16(b, ranges) != 0);
            CpTable {
                code_page: rd16(b, 0x02),
                max_char_size: rd16(b, 0x04),
                default_char: rd16(b, 0x06),
                uni_default_char: rd16(b, 0x08),
                dbcs_code_page,
                multi_byte,
                wide_char,
            }
        }

        fn to_unicode(&self, b: &[u8], byte: u8) -> u16 {
            rd16(b, self.multi_byte + byte as usize * 2)
        }

        fn to_multi_byte(&self, b: &[u8], wc: u16) -> u8 {
            b[self.wide_char + wc as usize]
        }
    }

    #[test]
    fn supported_codepages_carry_a_real_single_byte_table() {
        for cp in [20127u32, 28591, 1252] {
            let b = build_codepage_nls(cp).unwrap_or_else(|| panic!("cp {cp} is supported"));
            let t = CpTable::parse(&b);
            assert_eq!(t.code_page, cp as u16, "cp {cp}: reports its own id, not 65001");
            assert_eq!(t.max_char_size, 1, "cp {cp}: single byte");
            assert_eq!(t.dbcs_code_page, 0, "cp {cp}: no DBCS ranges");
            assert_eq!(t.uni_default_char, UNI_DEFAULT, "cp {cp}: UniDefaultChar");
            assert_eq!(t.default_char, MB_DEFAULT as u16, "cp {cp}: DefaultChar '?'");
            assert!(t.multi_byte + 512 <= b.len(), "cp {cp}: MultiByteTable in-bounds");
            assert!(t.wide_char + 0x1_0000 <= b.len(), "cp {cp}: WideCharTable in-bounds");
            for byte in 0..=0x7Fu8 {
                assert_eq!(t.to_unicode(&b, byte), byte as u16, "cp {cp}: {byte:#04x} → itself");
                assert_eq!(t.to_multi_byte(&b, byte as u16), byte, "cp {cp}: and back");
            }
        }
    }

    #[test]
    fn cp20127_round_trips_256_bytes_the_way_the_crt_checks() {
        let b = build_codepage_nls(20127).expect("20127 is supported");
        let t = CpTable::parse(&b);

        let wide: Vec<u16> = (0..=255u8).map(|byte| t.to_unicode(&b, byte)).collect();
        assert_eq!(wide.len(), 256, "MultiByteToWideChar(20127, …, 256) → 256 WCHARs");
        let back: Vec<u8> = wide.iter().map(|&wc| t.to_multi_byte(&b, wc)).collect();
        assert_eq!(back.len(), 256, "WideCharToMultiByte(20127, …, 256) → 256 bytes");

        for byte in 0..=0x7Fu8 {
            assert_eq!(back[byte as usize], byte, "{byte:#04x} survives the round trip");
        }
        for byte in 0x80..=0xFFu8 {
            assert_eq!(wide[byte as usize], UNI_DEFAULT, "{byte:#04x} is undefined in US-ASCII");
            assert_eq!(back[byte as usize], MB_DEFAULT, "…and encodes back as DefaultChar");
        }
    }

    #[test]
    fn latin1_codepages_are_bijections() {
        for cp in [28591u32, 1252] {
            let b = build_codepage_nls(cp).unwrap_or_else(|| panic!("cp {cp} is supported"));
            let t = CpTable::parse(&b);
            for byte in 0..=255u8 {
                let wc = t.to_unicode(&b, byte);
                assert_ne!(wc, UNI_DEFAULT, "cp {cp}: {byte:#04x} is defined");
                assert_eq!(t.to_multi_byte(&b, wc), byte, "cp {cp}: {byte:#04x} round-trips");
            }
        }
        let iso = build_codepage_nls(28591).unwrap();
        let win = build_codepage_nls(1252).unwrap();
        let (ti, tw) = (CpTable::parse(&iso), CpTable::parse(&win));
        assert_eq!(ti.to_unicode(&iso, 0x80), 0x0080, "ISO 8859-1 keeps the C1 controls");
        assert_eq!(tw.to_unicode(&win, 0x80), 0x20AC, "1252 puts € at 0x80");
        assert_eq!(tw.to_unicode(&win, 0x92), 0x2019, "…and a right single quote at 0x92");
        assert_eq!(tw.to_multi_byte(&win, 0x20AC), 0x80, "…which encodes back");
        for byte in 0..=0x7Fu8 {
            assert_eq!(ti.to_unicode(&iso, byte), tw.to_unicode(&win, byte), "ASCII agrees");
        }
        for byte in 0xA0..=0xFFu8 {
            assert_eq!(ti.to_unicode(&iso, byte), tw.to_unicode(&win, byte), "Latin-1 agrees");
        }
    }

    #[test]
    fn the_emulated_thunks_and_the_guest_section_agree() {
        for cp in [20127u32, 28591, 1252] {
            let b = build_codepage_nls(cp).unwrap();
            let t = CpTable::parse(&b);
            let bytes: Vec<u8> = (0..=255u8).collect();

            let decoded = sbcs_decode(cp, &bytes).unwrap_or_else(|| panic!("cp {cp} decodes"));
            let via_section: Vec<u16> = bytes.iter().map(|&x| t.to_unicode(&b, x)).collect();
            assert_eq!(decoded, via_section, "cp {cp}: byte → wide agrees");

            let (encoded, lossy) = sbcs_encode(cp, &decoded).unwrap();
            let back: Vec<u8> = decoded.iter().map(|&wc| t.to_multi_byte(&b, wc)).collect();
            assert_eq!(encoded, back, "cp {cp}: wide → byte agrees");
            assert_eq!(lossy, cp == 20127, "only US-ASCII has characters it cannot encode");

            let (enc, lossy) = sbcs_encode(cp, &[0x4E2D]).unwrap();
            assert_eq!(enc, vec![MB_DEFAULT], "cp {cp}: an unencodable char → '?'");
            assert!(lossy, "cp {cp}: …and lpUsedDefaultChar is set");
        }
        assert!(sbcs_encode(932, &[0x41]).is_none(), "an unsupported codepage is refused here too");
        assert!(sbcs_decode(932, &[0x41]).is_none(), "…in both directions");
    }

    #[test]
    fn unsupported_codepages_are_refused_rather_than_faked() {
        for cp in [932u32, 936, 949, 950, 1361, 437, 850, 1251, 65000, 1200, 1201, 0] {
            assert!(build_codepage_nls(cp).is_none(), "cp {cp} is refused, not synthesized");
        }
        let utf8 = build_codepage_nls(CP_UTF8 as u32).expect("UTF-8 is answered");
        assert_eq!(rd16(&utf8, 0x02), CP_UTF8, "…as the short-path marker");
    }

    #[test]
    fn ssdt_initialize_nls_files_maps_and_reports() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_INITIALIZE_NLS_FILES, ssdt_nt_initialize_nls_files);

        let base_out = 0x2_0100u64;
        let lcid_out = 0x2_0108u64;
        let size_out = 0x2_0110u64;

        let mut cpu = CpuState::default();
        cpu.set_rsp(0x2_0800);
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_reg(Reg::R10, base_out);
        cpu.set_reg(Reg::Rdx, lcid_out);
        cpu.set_reg(Reg::R8, size_out);

        let exit = os.dispatch_syscall(SSDT_NT_INITIALIZE_NLS_FILES, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64, "NTSTATUS in RAX");

        let base = mem.read_u64(base_out).unwrap();
        assert_ne!(base, 0, "a non-null NLS base was returned");
        assert_eq!(mem.read_u32(lcid_out).unwrap(), SYSTEM_LCID, "system LCID reported");
        assert_ne!(mem.read_u64(size_out).unwrap(), 0, "mapping size reported");

        let lt = base + mem.read_u32(base + HDR_LOCALE_TABLE_OFF as u64).unwrap() as u64;
        let lcids = lt + mem.read_u32(lt + LT_LCIDS_OFF as u64).unwrap() as u64;
        assert_eq!(mem.read_u32(lcids).unwrap(), SYSTEM_LCID, "walkable to LCID 0x409");

        let mut cpu2 = CpuState::default();
        cpu2.set_rsp(0x2_0800);
        cpu2.set_reg(Reg::Rcx, 0x4000);
        cpu2.set_reg(Reg::R10, base_out);
        cpu2.set_reg(Reg::Rdx, lcid_out);
        cpu2.set_reg(Reg::R8, size_out);
        os.dispatch_syscall(SSDT_NT_INITIALIZE_NLS_FILES, &mut cpu2, &mut mem).unwrap();
        assert_eq!(mem.read_u64(base_out).unwrap(), base, "cached base is stable");
    }

    #[test]
    fn ssdt_get_nls_section_ptr_keys_codepages_by_id() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_GET_NLS_SECTION_PTR, ssdt_nt_get_nls_section_ptr);

        let base_out = 0x2_0100u64;
        let size_out = 0x2_0200u64;
        let gsp = 0x2_0800u64;
        mem.write_u64(gsp + 0x28, size_out).unwrap();

        let get = |os: &mut WinOs, mem: &mut VirtualMemory, ty: u64, id: u64| -> (u64, u64) {
            mem.write_u64(base_out, 0).unwrap();
            let mut cpu = CpuState::default();
            cpu.set_rsp(gsp);
            cpu.set_reg(Reg::Rcx, 0x4000);
            cpu.set_reg(Reg::R10, ty);
            cpu.set_reg(Reg::Rdx, id);
            cpu.set_reg(Reg::R8, 0);
            cpu.set_reg(Reg::R9, base_out);
            os.dispatch_syscall(SSDT_NT_GET_NLS_SECTION_PTR, &mut cpu, mem).unwrap();
            (cpu.reg(Reg::Rax), mem.read_u64(base_out).unwrap())
        };

        let (st_ascii, ascii) = get(&mut os, &mut mem, 0xb, 20127);
        assert_eq!(st_ascii, STATUS_SUCCESS as u64, "20127 is supported");
        let (st_1252, win1252) = get(&mut os, &mut mem, 0xb, 1252);
        assert_eq!(st_1252, STATUS_SUCCESS as u64, "1252 is supported");
        assert_ne!(ascii, win1252, "one section per codepage, not per type");
        assert_eq!(mem.read_u16(ascii + 0x02).unwrap(), 20127, "the 20127 section says 20127");
        assert_eq!(mem.read_u16(win1252 + 0x02).unwrap(), 1252, "and the 1252 one says 1252");

        assert_eq!(get(&mut os, &mut mem, 0xb, 20127).1, ascii, "cached per codepage");

        let (st, base) = get(&mut os, &mut mem, 0xb, 932);
        assert_eq!(st, STATUS_OBJECT_NAME_NOT_FOUND as u64, "Shift-JIS is refused cleanly");
        assert_eq!(base, 0, "…and no section pointer is handed out");
    }

    #[test]
    fn ssdt_get_nls_section_ptr_maps_section() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_GET_NLS_SECTION_PTR, ssdt_nt_get_nls_section_ptr);

        let base_out = 0x2_0100u64;
        let size_out = 0x2_0200u64;
        let gsp = 0x2_0800u64;
        mem.write_u64(gsp + 0x28, size_out).unwrap();

        let mut cpu = CpuState::default();
        cpu.set_rsp(gsp);
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_reg(Reg::R10, 0xc);
        cpu.set_reg(Reg::Rdx, 1);
        cpu.set_reg(Reg::R8, 0);
        cpu.set_reg(Reg::R9, base_out);

        let exit = os.dispatch_syscall(SSDT_NT_GET_NLS_SECTION_PTR, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64);

        let base = mem.read_u64(base_out).unwrap();
        assert_ne!(base, 0, "a non-null section base was returned");
        assert_ne!(mem.read_u64(size_out).unwrap(), 0, "section size reported");
        assert_eq!(mem.read_u16(base + 0x02).unwrap(), CP_UTF8, "opaque UTF-8-marked section");
    }
}
