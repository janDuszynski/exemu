const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 96 + 16 * 8;

pub const GUI_OK_EXIT: i32 = 71;
pub const GUI_FAIL_NO_HWND_EXIT: i32 = 72;
pub const GUI_FAIL_MESSAGES_EXIT: i32 = 73;
pub const GUI_FAIL_CREATESTRUCT_EXIT: i32 = 74;
pub const GUI_FAIL_LRESULT_EXIT: i32 = 75;
pub const GUI_FAIL_NO_ATOM_EXIT: i32 = 76;

pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_PROBE: u32 = 0x8000;
pub const PROBE_LRESULT: u32 = 0x5EED_1234;
pub const WINDOW_STYLE: u32 = 0x00CF_0000;
pub const CREATESTRUCT32_STYLE: u32 = 0x20;

pub mod seen {
    pub const NCCREATE: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const PROBE: u32 = 4;
    pub const ALL: u32 = NCCREATE | CREATE | PROBE;
}

pub mod data {
    pub const SEEN: u32 = 0x00;
    pub const PROC_HWND: u32 = 0x04;
    pub const CS_PTR: u32 = 0x08;
    pub const CS_STYLE: u32 = 0x0c;
    pub const HWND: u32 = 0x10;
    pub const SEND_RESULT: u32 = 0x14;
    pub const ATOM: u32 = 0x18;
    pub const ESP_BEFORE: u32 = 0x1c;
    pub const ESP_AFTER: u32 = 0x20;
    pub const WNDCLASS: u32 = 0x40;
    pub const LEN: u32 = 0x80;
}

pub const fn data_va(off: u32) -> u64 {
    (IMAGE_BASE + DATA_RVA + off) as u64
}

const IMPORTS: [(&str, &[&str]); 2] =
    [("user32.dll", &["RegisterClassW", "CreateWindowExW", "SendMessageW", "DefWindowProcW"]), ("ntdll.dll", &["NtTerminateProcess"])];

const I_REGISTER_CLASS: u32 = 0;
const I_CREATE_WINDOW: u32 = 1;
const I_SEND_MESSAGE: u32 = 2;
const I_DEF_WINDOW_PROC: u32 = 3;
const I_TERMINATE: u32 = 4;

pub fn build() -> Vec<u8> {
    let ndlls = IMPORTS.len() as u32;
    let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
    let import_dir_size = (ndlls + 1) * 20;
    let ilt_off = import_dir_size;
    let thunks: u32 = nfuncs + ndlls;
    let iat_off = ilt_off + thunks * 4;
    debug_assert_eq!(iat_off, self::iat_off(), "iat_off() must match the emitted layout");

    let mut pos = iat_off + thunks * 4;
    let mut ibn_rva = Vec::new();
    for (_, funcs) in IMPORTS {
        for n in funcs {
            pos = align_up_u32(pos, 2);
            ibn_rva.push(RDATA_RVA + pos);
            pos += 2 + n.len() as u32 + 1;
        }
    }
    let mut dll_rva = Vec::new();
    for (dll, _) in IMPORTS {
        pos = align_up_u32(pos, 2);
        dll_rva.push(RDATA_RVA + pos);
        pos += dll.len() as u32 + 1;
    }
    pos = align_up_u32(pos, 2);
    let class_rva = RDATA_RVA + pos;
    let class_name: Vec<u8> = wide("ExemuW510Class");
    pos += class_name.len() as u32;
    let title_rva = RDATA_RVA + pos;
    let title: Vec<u8> = wide("W5.10");
    pos += title.len() as u32;

    let mut rd = vec![0u8; pos as usize];
    let mut thunk = 0u32;
    let mut fi = 0usize;
    for (di, (dll, funcs)) in IMPORTS.iter().enumerate() {
        let d = di * 20;
        put_u32(&mut rd, d, RDATA_RVA + ilt_off + thunk * 4);
        put_u32(&mut rd, d + 12, dll_rva[di]);
        put_u32(&mut rd, d + 16, RDATA_RVA + iat_off + thunk * 4);
        for _ in *funcs {
            put_u32(&mut rd, (ilt_off + thunk * 4) as usize, ibn_rva[fi]);
            put_u32(&mut rd, (iat_off + thunk * 4) as usize, ibn_rva[fi]);
            thunk += 1;
            fi += 1;
        }
        thunk += 1;
        let o = (dll_rva[di] - RDATA_RVA) as usize;
        rd[o..o + dll.len()].copy_from_slice(dll.as_bytes());
    }
    let mut fi = 0usize;
    for (_, funcs) in IMPORTS {
        for n in funcs {
            let off = (ibn_rva[fi] - RDATA_RVA) as usize;
            rd[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
            fi += 1;
        }
    }
    let o = (class_rva - RDATA_RVA) as usize;
    rd[o..o + class_name.len()].copy_from_slice(&class_name);
    let o = (title_rva - RDATA_RVA) as usize;
    rd[o..o + title.len()].copy_from_slice(&title);

    let iat = |i: u32| {
        let mut slot = 0u32;
        let mut seen = 0u32;
        for (_, funcs) in IMPORTS {
            for _ in funcs {
                if seen == i {
                    return IMAGE_BASE + RDATA_RVA + iat_off + slot * 4;
                }
                seen += 1;
                slot += 1;
            }
            slot += 1;
        }
        unreachable!()
    };

    let text = build_text(&iat, IMAGE_BASE + class_rva, IMAGE_BASE + title_rva);

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rd.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x014C);
    put_u16(&mut f, coff + 2, 3);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0102);

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA + data::LEN, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x10B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA);
    put_u32(&mut f, opt + 20, TEXT_RVA);
    put_u32(&mut f, opt + 24, RDATA_RVA);
    put_u32(&mut f, opt + 28, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 2);
    put_u32(&mut f, opt + 72, 0x10_0000);
    put_u32(&mut f, opt + 76, 0x1000);
    put_u32(&mut f, opt + 80, 0x10_0000);
    put_u32(&mut f, opt + 84, 0x1000);
    put_u32(&mut f, opt + 92, 16);

    let dir = |i: usize| opt + 96 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA);
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + iat_off);
    put_u32(&mut f, dir(12) + 4, thunks * 4);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", rd.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", data::LEN, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

fn iat_off() -> u32 {
    let ndlls = IMPORTS.len() as u32;
    let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
    (ndlls + 1) * 20 + (nfuncs + ndlls) * 4
}

fn wide(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0]);
    v
}

fn build_text(iat: &dyn Fn(u32) -> u32, class_va: u32, title_va: u32) -> Vec<u8> {
    let cell = |off: u32| IMAGE_BASE + DATA_RVA + off;
    let wc = cell(data::WNDCLASS);
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);

    let wndproc_off = c.len();
    c.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]);

    c.extend_from_slice(&[0x3D]);
    c.extend_from_slice(&WM_NCCREATE.to_le_bytes());
    let jne_nc = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    emit_or_cell(&mut c, cell(data::SEEN), seen::NCCREATE);
    c.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x04]);
    c.extend_from_slice(&[0x89, 0x0D]);
    c.extend_from_slice(&cell(data::PROC_HWND).to_le_bytes());
    c.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]);
    c.extend_from_slice(&[0x89, 0x0D]);
    c.extend_from_slice(&cell(data::CS_PTR).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC9]);
    let jz_nocs = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    c.extend_from_slice(&[0x8B, 0x91]);
    c.extend_from_slice(&CREATESTRUCT32_STYLE.to_le_bytes());
    c.extend_from_slice(&[0x89, 0x15]);
    c.extend_from_slice(&cell(data::CS_STYLE).to_le_bytes());
    patch_rel8(&mut c, jz_nocs);
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xC2, 0x10, 0x00]);
    patch_rel32(&mut c, jne_nc);

    c.extend_from_slice(&[0x3D]);
    c.extend_from_slice(&WM_CREATE.to_le_bytes());
    let jne_cr = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    emit_or_cell(&mut c, cell(data::SEEN), seen::CREATE);
    c.extend_from_slice(&[0x31, 0xC0]);
    c.extend_from_slice(&[0xC2, 0x10, 0x00]);
    patch_rel32(&mut c, jne_cr);

    c.extend_from_slice(&[0x3D]);
    c.extend_from_slice(&WM_PROBE.to_le_bytes());
    let jne_pr = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    emit_or_cell(&mut c, cell(data::SEEN), seen::PROBE);
    c.extend_from_slice(&[0xB8]);
    c.extend_from_slice(&PROBE_LRESULT.to_le_bytes());
    c.extend_from_slice(&[0xC2, 0x10, 0x00]);
    patch_rel32(&mut c, jne_pr);

    c.extend_from_slice(&[0xFF, 0x25]);
    c.extend_from_slice(&iat(I_DEF_WINDOW_PROC).to_le_bytes());

    let main_off = c.len();
    let disp = (main_off - 5) as u32;
    c[1..5].copy_from_slice(&disp.to_le_bytes());
    let wndproc_va = IMAGE_BASE + TEXT_RVA + wndproc_off as u32;

    c.extend_from_slice(&[0x89, 0x25]);
    c.extend_from_slice(&cell(data::ESP_BEFORE).to_le_bytes());
    emit_store_imm(&mut c, wc + 0x04, wndproc_va);
    emit_store_imm(&mut c, wc + 0x10, IMAGE_BASE);
    emit_store_imm(&mut c, wc + 0x24, class_va);

    c.push(0x68);
    c.extend_from_slice(&wc.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_REGISTER_CLASS).to_le_bytes());
    c.push(0xA3);
    c.extend_from_slice(&cell(data::ATOM).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC0]);
    let jnz_atom = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_NO_ATOM_EXIT as u32);
    patch_rel8(&mut c, jnz_atom);

    for imm in [0u32, IMAGE_BASE, 0, 0, 120, 200, 20, 10, WINDOW_STYLE, title_va, class_va, 0] {
        c.push(0x68);
        c.extend_from_slice(&imm.to_le_bytes());
    }
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_CREATE_WINDOW).to_le_bytes());
    c.push(0xA3);
    c.extend_from_slice(&cell(data::HWND).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC0]);
    let jnz_hwnd = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_NO_HWND_EXIT as u32);
    patch_rel8(&mut c, jnz_hwnd);

    for imm in [0x2222u32, 0x1111, WM_PROBE] {
        c.push(0x68);
        c.extend_from_slice(&imm.to_le_bytes());
    }
    c.push(0x50);
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_SEND_MESSAGE).to_le_bytes());
    c.push(0xA3);
    c.extend_from_slice(&cell(data::SEND_RESULT).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x25]);
    c.extend_from_slice(&cell(data::ESP_AFTER).to_le_bytes());

    emit_cmp_cell(&mut c, cell(data::SEEN), seen::ALL);
    let je_seen = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_MESSAGES_EXIT as u32);
    patch_rel8(&mut c, je_seen);

    emit_cmp_cell(&mut c, cell(data::CS_STYLE), WINDOW_STYLE);
    let je_style = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_CREATESTRUCT_EXIT as u32);
    patch_rel8(&mut c, je_style);

    emit_cmp_cell(&mut c, cell(data::SEND_RESULT), PROBE_LRESULT);
    let je_res = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_LRESULT_EXIT as u32);
    patch_rel8(&mut c, je_res);

    emit_exit(&mut c, iat(I_TERMINATE), GUI_OK_EXIT as u32);
    c.push(0xF4);
    c
}

fn emit_or_cell(c: &mut Vec<u8>, at: u32, v: u32) {
    c.extend_from_slice(&[0x81, 0x0D]);
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&v.to_le_bytes());
}

fn emit_store_imm(c: &mut Vec<u8>, at: u32, v: u32) {
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&v.to_le_bytes());
}

fn emit_cmp_cell(c: &mut Vec<u8>, at: u32, v: u32) {
    c.push(0xA1);
    c.extend_from_slice(&at.to_le_bytes());
    c.push(0x3D);
    c.extend_from_slice(&v.to_le_bytes());
}

fn emit_exit(c: &mut Vec<u8>, iat_terminate: u32, code: u32) {
    c.push(0x68);
    c.extend_from_slice(&code.to_le_bytes());
    c.push(0x68);
    c.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat_terminate.to_le_bytes());
}

fn patch_rel8(c: &mut [u8], at: usize) {
    let disp = c.len() - (at + 2);
    assert!(disp < 128, "wow64 gui sample: rel8 branch out of range ({disp})");
    c[at + 1] = disp as u8;
}

fn patch_rel32(c: &mut [u8], at: usize) {
    let disp = (c.len() - (at + 6)) as u32;
    c[at + 2..at + 6].copy_from_slice(&disp.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_section(f: &mut [u8], at: usize, name: &[u8], vsize: u32, vaddr: u32, raw_size: u32, raw_ptr: u32, chars: u32) {
    f[at..at + name.len()].copy_from_slice(name);
    put_u32(f, at + 8, vsize);
    put_u32(f, at + 12, vaddr);
    put_u32(f, at + 16, raw_size);
    put_u32(f, at + 20, raw_ptr);
    put_u32(f, at + 36, chars);
}

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn align_up_u32(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sample_is_a_pe32_importing_user32_and_ntdll() {
        let bytes = build();
        let img = exemu_loader::parse(&bytes).expect("the sample parses");
        assert!(!img.is_64bit, "a WoW64 guest is a PE32");
        let mut named: Vec<String> = img
            .imports
            .iter()
            .filter_map(|i| match &i.symbol {
                exemu_core::ImportSymbol::Named(n) => Some(format!("{}!{n}", i.dll.to_ascii_lowercase())),
                exemu_core::ImportSymbol::Ordinal(_) => None,
            })
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                "ntdll.dll!NtTerminateProcess",
                "user32.dll!CreateWindowExW",
                "user32.dll!DefWindowProcW",
                "user32.dll!RegisterClassW",
                "user32.dll!SendMessageW",
            ],
        );
        let mut slots: Vec<u32> = img.imports.iter().map(|i| i.iat_rva).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), 5, "five distinct IAT slots");
    }
}
