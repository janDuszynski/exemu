use super::{
    align_up, align_up_u32, filter_blob, jcc_near, patch_near, put_u16, put_u32, wide, write_section,
    DEF_EXT, INITIAL_DIR, MAX_PATH, OPEN_FLAGS, OPEN_TITLE, SAVE_FILE_NAME, SAVE_FLAGS, SAVE_PAYLOAD,
    SAVE_TITLE,
};

const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 96 + 16 * 8;

pub const OPENFILENAMEW32_SIZE: u32 = 0x58;

mod ofn {
    pub const STRUCT_SIZE: u32 = 0x00;
    pub const LPSTR_FILTER: u32 = 0x0c;
    pub const LPSTR_FILE: u32 = 0x1c;
    pub const N_MAX_FILE: u32 = 0x20;
    pub const LPSTR_INITIAL_DIR: u32 = 0x2c;
    pub const LPSTR_TITLE: u32 = 0x30;
    pub const FLAGS: u32 = 0x34;
    pub const LPSTR_DEF_EXT: u32 = 0x3c;
}

pub mod data {
    pub const OPEN_RET: u32 = 0x00;
    pub const OPEN_ERR: u32 = 0x04;
    pub const SAVE_RET: u32 = 0x08;
    pub const SAVE_ERR: u32 = 0x0c;
    pub const READ_COUNT: u32 = 0x10;
    pub const WROTE: u32 = 0x14;
    pub const OPEN_HANDLE: u32 = 0x18;
    pub const SAVE_HANDLE: u32 = 0x1c;
    pub const OFN: u32 = 0x40;
    pub const OPEN_BUF: u32 = 0x100;
    pub const SAVE_BUF: u32 = 0x310;
    pub const READ_BUF: u32 = 0x520;
    pub const READ_BUF_LEN: u32 = 0x40;
    pub const LEN: u32 = 0x580;
}

const _: () = assert!(data::OFN + OPENFILENAMEW32_SIZE <= data::OPEN_BUF);
const _: () = assert!(data::OPEN_BUF + MAX_PATH * 2 <= data::SAVE_BUF);
const _: () = assert!(data::SAVE_BUF + MAX_PATH * 2 <= data::READ_BUF);
const _: () = assert!(data::READ_BUF + data::READ_BUF_LEN <= data::LEN);

pub const fn data_va(off: u32) -> u64 {
    (IMAGE_BASE + DATA_RVA + off) as u64
}

const fn dva(off: u32) -> u32 {
    IMAGE_BASE + DATA_RVA + off
}

const IMPORTS: [(&str, &[&str]); 2] = [
    ("comdlg32.dll", &["GetOpenFileNameW", "GetSaveFileNameW", "CommDlgExtendedError"]),
    ("kernel32.dll", &["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess"]),
];

const WIDE_STRINGS: [&str; 5] = [INITIAL_DIR, OPEN_TITLE, SAVE_TITLE, DEF_EXT, SAVE_FILE_NAME];

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;

struct Layout {
    rdata: Vec<u8>,
    import_dir_size: u32,
    iat_off: u32,
    iat_len: u32,
    iat: Vec<(&'static str, u32)>,
    strings: Vec<u32>,
    filter_va: u32,
    payload_va: u32,
}

impl Layout {
    fn build() -> Layout {
        let ndlls = IMPORTS.len() as u32;
        let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
        let import_dir_size = (ndlls + 1) * 20;
        let ilt_off = import_dir_size;
        let thunks = nfuncs + ndlls;
        let iat_off = ilt_off + thunks * 4;

        let mut pos = iat_off + thunks * 4;
        let mut ibn = Vec::new();
        for (_, funcs) in IMPORTS {
            for n in funcs {
                pos = align_up_u32(pos, 2);
                ibn.push(pos);
                pos += 2 + n.len() as u32 + 1;
            }
        }
        let mut dll_off = Vec::new();
        for (dll, _) in IMPORTS {
            dll_off.push(pos);
            pos += dll.len() as u32 + 1;
        }
        pos = align_up_u32(pos, 2);
        let mut string_off = Vec::new();
        for s in WIDE_STRINGS {
            string_off.push(pos);
            pos += wide(s).len() as u32;
        }
        let filter = filter_blob();
        let filter_off = pos;
        pos += filter.len() as u32;
        let payload_off = pos;
        pos += SAVE_PAYLOAD.len() as u32;

        let mut rd = vec![0u8; pos as usize];
        let mut iat = Vec::new();
        let (mut thunk, mut fi) = (0u32, 0usize);
        for (di, (dll, funcs)) in IMPORTS.iter().enumerate() {
            let d = di * 20;
            put_u32(&mut rd, d, RDATA_RVA + ilt_off + thunk * 4);
            put_u32(&mut rd, d + 12, RDATA_RVA + dll_off[di]);
            put_u32(&mut rd, d + 16, RDATA_RVA + iat_off + thunk * 4);
            for n in *funcs {
                put_u32(&mut rd, (ilt_off + thunk * 4) as usize, RDATA_RVA + ibn[fi]);
                put_u32(&mut rd, (iat_off + thunk * 4) as usize, RDATA_RVA + ibn[fi]);
                let at = ibn[fi] as usize + 2;
                rd[at..at + n.len()].copy_from_slice(n.as_bytes());
                iat.push((*n, IMAGE_BASE + RDATA_RVA + iat_off + thunk * 4));
                thunk += 1;
                fi += 1;
            }
            thunk += 1;
            let o = dll_off[di] as usize;
            rd[o..o + dll.len()].copy_from_slice(dll.as_bytes());
        }
        for (s, off) in WIDE_STRINGS.iter().zip(&string_off) {
            let w = wide(s);
            rd[*off as usize..*off as usize + w.len()].copy_from_slice(&w);
        }
        rd[filter_off as usize..filter_off as usize + filter.len()].copy_from_slice(&filter);
        let p = payload_off as usize;
        rd[p..p + SAVE_PAYLOAD.len()].copy_from_slice(SAVE_PAYLOAD.as_bytes());

        let va = |off: u32| IMAGE_BASE + RDATA_RVA + off;
        Layout {
            rdata: rd,
            import_dir_size,
            iat_off,
            iat_len: thunks * 4,
            iat,
            strings: string_off.into_iter().map(va).collect(),
            filter_va: va(filter_off),
            payload_va: va(payload_off),
        }
    }

    fn slot(&self, name: &str) -> u32 {
        self.iat.iter().find(|(n, _)| *n == name).map(|(_, va)| *va).expect("import present")
    }

    fn wstr(&self, s: &str) -> u32 {
        let i = WIDE_STRINGS.iter().position(|w| *w == s).expect("wide string present");
        self.strings[i]
    }
}

pub fn build() -> Vec<u8> {
    let l = Layout::build();
    let text = build_text(&l);

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(l.rdata.len(), FILE_ALIGN as usize);
    let mut f = vec![0u8; rdata_ptr + rdata_raw];
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
    put_u32(&mut f, opt + 56, align_up_u32(DATA_RVA + data::LEN, SECTION_ALIGN));
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3);
    put_u32(&mut f, opt + 72, 0x10_0000);
    put_u32(&mut f, opt + 76, 0x1000);
    put_u32(&mut f, opt + 80, 0x10_0000);
    put_u32(&mut f, opt + 84, 0x1000);
    put_u32(&mut f, opt + 92, 16);

    let dir = |i: usize| opt + 96 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA);
    put_u32(&mut f, dir(1) + 4, l.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + l.iat_off);
    put_u32(&mut f, dir(12) + 4, l.iat_len);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", l.rdata.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", data::LEN, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + l.rdata.len()].copy_from_slice(&l.rdata);
    f
}

fn build_text(l: &Layout) -> Vec<u8> {
    let mut c = Vec::new();

    emit_ofn(&mut c, l, data::OPEN_BUF, OPEN_TITLE, OPEN_FLAGS);
    mov_abs_imm32(&mut c, dva(data::OPEN_BUF), 0);
    emit_dialog_call(&mut c, l, "GetOpenFileNameW", data::OPEN_RET, data::OPEN_ERR);
    emit_create_file(&mut c, l, data::OPEN_BUF, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, data::OPEN_HANDLE);
    let skip_read = jcc_near(&mut c, 0x84);
    push_imm(&mut c, 0);
    push_imm(&mut c, dva(data::READ_COUNT));
    push_imm(&mut c, data::READ_BUF_LEN - 1);
    push_imm(&mut c, dva(data::READ_BUF));
    c.push(0x50);
    call_abs(&mut c, l.slot("ReadFile"));
    push_abs(&mut c, dva(data::OPEN_HANDLE));
    call_abs(&mut c, l.slot("CloseHandle"));
    patch_near(&mut c, skip_read);

    let name = wide(SAVE_FILE_NAME);
    c.push(0xBE);
    c.extend_from_slice(&l.wstr(SAVE_FILE_NAME).to_le_bytes());
    c.push(0xBF);
    c.extend_from_slice(&dva(data::SAVE_BUF).to_le_bytes());
    c.push(0xB9);
    c.extend_from_slice(&(name.len() as u32).to_le_bytes());
    c.extend_from_slice(&[0xFC, 0xF3, 0xA4]);
    emit_ofn(&mut c, l, data::SAVE_BUF, SAVE_TITLE, SAVE_FLAGS);
    emit_dialog_call(&mut c, l, "GetSaveFileNameW", data::SAVE_RET, data::SAVE_ERR);
    emit_create_file(&mut c, l, data::SAVE_BUF, GENERIC_WRITE, 0, CREATE_ALWAYS, data::SAVE_HANDLE);
    let skip_write = jcc_near(&mut c, 0x84);
    push_imm(&mut c, 0);
    push_imm(&mut c, dva(data::WROTE));
    push_imm(&mut c, SAVE_PAYLOAD.len() as u32);
    push_imm(&mut c, l.payload_va);
    c.push(0x50);
    call_abs(&mut c, l.slot("WriteFile"));
    push_abs(&mut c, dva(data::SAVE_HANDLE));
    call_abs(&mut c, l.slot("CloseHandle"));
    patch_near(&mut c, skip_write);

    push_imm(&mut c, 0);
    call_abs(&mut c, l.slot("ExitProcess"));
    c.push(0xCC);
    c
}

fn emit_ofn(c: &mut Vec<u8>, l: &Layout, file_buf: u32, title: &str, flags: u32) {
    let at = |off: u32| dva(data::OFN + off);
    for off in (0..OPENFILENAMEW32_SIZE).step_by(4) {
        mov_abs_imm32(c, at(off), 0);
    }
    mov_abs_imm32(c, at(ofn::STRUCT_SIZE), OPENFILENAMEW32_SIZE);
    mov_abs_imm32(c, at(ofn::LPSTR_FILTER), l.filter_va);
    mov_abs_imm32(c, at(ofn::LPSTR_FILE), dva(file_buf));
    mov_abs_imm32(c, at(ofn::N_MAX_FILE), MAX_PATH);
    mov_abs_imm32(c, at(ofn::LPSTR_INITIAL_DIR), l.wstr(INITIAL_DIR));
    mov_abs_imm32(c, at(ofn::LPSTR_TITLE), l.wstr(title));
    mov_abs_imm32(c, at(ofn::FLAGS), flags);
    mov_abs_imm32(c, at(ofn::LPSTR_DEF_EXT), l.wstr(DEF_EXT));
}

fn emit_dialog_call(c: &mut Vec<u8>, l: &Layout, func: &str, ret: u32, err: u32) {
    push_imm(c, dva(data::OFN));
    call_abs(c, l.slot(func));
    store_eax(c, dva(ret));
    call_abs(c, l.slot("CommDlgExtendedError"));
    store_eax(c, dva(err));
}

fn emit_create_file(c: &mut Vec<u8>, l: &Layout, path: u32, access: u32, share: u32, disposition: u32, handle: u32) {
    push_imm(c, 0);
    push_imm(c, 0);
    push_imm(c, disposition);
    push_imm(c, 0);
    push_imm(c, share);
    push_imm(c, access);
    push_imm(c, dva(path));
    call_abs(c, l.slot("CreateFileW"));
    store_eax(c, dva(handle));
    c.extend_from_slice(&[0x83, 0xF8, 0xFF]);
}

fn mov_abs_imm32(c: &mut Vec<u8>, va: u32, imm: u32) {
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&va.to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

fn push_imm(c: &mut Vec<u8>, imm: u32) {
    c.push(0x68);
    c.extend_from_slice(&imm.to_le_bytes());
}

fn push_abs(c: &mut Vec<u8>, va: u32) {
    c.extend_from_slice(&[0xFF, 0x35]);
    c.extend_from_slice(&va.to_le_bytes());
}

fn call_abs(c: &mut Vec<u8>, va: u32) {
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&va.to_le_bytes());
}

fn store_eax(c: &mut Vec<u8>, va: u32) {
    c.push(0xA3);
    c.extend_from_slice(&va.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wow64_sample_is_a_pe32_importing_comdlg32() {
        let exe = build();
        let image = exemu_loader::parse(&exe).expect("parses as PE32");
        assert!(!image.is_64bit);
        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        for (dll, funcs) in IMPORTS {
            for f in funcs {
                assert!(has(dll, f), "imports {dll}!{f}");
            }
        }
    }
}
