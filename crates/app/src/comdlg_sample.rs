pub mod wow64;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const MAX_PATH: u32 = 260;

pub const OPENFILENAMEW_SIZE: u32 = 0x98;

const OFN_STRUCT_SIZE: u32 = 0x00;
const OFN_HWND_OWNER: u32 = 0x08;
const OFN_LPSTR_FILTER: u32 = 0x18;
const OFN_LPSTR_FILE: u32 = 0x30;
const OFN_N_MAX_FILE: u32 = 0x38;
const OFN_LPSTR_INITIAL_DIR: u32 = 0x50;
const OFN_LPSTR_TITLE: u32 = 0x58;
const OFN_FLAGS: u32 = 0x60;
const OFN_LPSTR_DEF_EXT: u32 = 0x68;

const OPEN_FLAGS: u32 = 0x0000_1000 | 0x0000_0800 | 0x0008_0000 | 0x0000_0008 | 0x0000_0004;
const SAVE_FLAGS: u32 = 0x0000_0002 | 0x0000_0800 | 0x0008_0000 | 0x0000_0008 | 0x0000_0004;

pub const INITIAL_DIR: &str = r"C:\Users\exemu\Documents";
pub const PICK_FILE_NAME: &str = "exemu-pick.txt";
pub const SAVE_FILE_NAME: &str = "exemu-saved.txt";

pub const SAVE_PAYLOAD: &str = "exemu-comdlg-wrote-this";

pub const OPEN_TITLE: &str = "exemu — pick a file to open";
pub const SAVE_TITLE: &str = "exemu — pick where to save";

const FILTER_PARTS: [&str; 4] = ["Text files", "*.txt", "All files", "*.*"];
const DEF_EXT: &str = "txt";

const RBUF_LEN: u32 = 64;

pub const TAG_OPEN: &str = "OPEN";
pub const TAG_READ: &str = "READ";
pub const TAG_SAVE: &str = "SAVE";
pub const TAG_WROTE: &str = "WROTE";
pub const TAG_OPEN_ERR: &str = "OPENERR";
pub const TAG_SAVE_ERR: &str = "SAVEERR";
pub const TAG_OPEN_RET: &str = "OPENRET";
pub const TAG_SAVE_RET: &str = "SAVERET";
pub const TAG_BAD_SIZE: &str = "BADSIZE";

pub const BAD_STRUCT_SIZE: u32 = 0x99;
pub const CDERR_STRUCTSIZE: u32 = 1;
pub const CDERR_FINDRESFAILURE: u32 = 6;
pub const CDERR_LOADRESFAILURE: u32 = 7;

pub fn build() -> Vec<u8> {
    let r = Rdata::build();
    let text = build_text(&r);

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(r.bytes.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);

    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, 3);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022);

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA + r.data_len, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA);
    put_u32(&mut f, opt + 20, TEXT_RVA);
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3);
    put_u64(&mut f, opt + 72, 0x10_0000);
    put_u64(&mut f, opt + 80, 0x1000);
    put_u64(&mut f, opt + 88, 0x10_0000);
    put_u64(&mut f, opt + 96, 0x1000);
    put_u32(&mut f, opt + 108, 16);

    let dir = |i: usize| opt + 112 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA + r.import_dir_off);
    put_u32(&mut f, dir(1) + 4, r.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + r.iat_off);
    put_u32(&mut f, dir(12) + 4, r.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", r.bytes.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", r.data_len, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + r.bytes.len()].copy_from_slice(&r.bytes);
    f
}

fn import_plan() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "comdlg32.dll",
            vec!["GetOpenFileNameW", "GetSaveFileNameW", "CommDlgExtendedError"],
        ),
        (
            "kernel32.dll",
            vec![
                "GetStdHandle",
                "WriteFile",
                "CreateFileW",
                "ReadFile",
                "CloseHandle",
                "ExitProcess",
            ],
        ),
    ]
}

const TAGS: [&str; 9] = [
    TAG_OPEN,
    TAG_READ,
    TAG_SAVE,
    TAG_WROTE,
    TAG_OPEN_ERR,
    TAG_SAVE_ERR,
    TAG_BAD_SIZE,
    TAG_OPEN_RET,
    TAG_SAVE_RET,
];

const WIDE_STRINGS: [&str; 5] =
    [INITIAL_DIR, OPEN_TITLE, SAVE_TITLE, DEF_EXT, SAVE_FILE_NAME];

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat: std::collections::HashMap<String, u32>,
    tag_rva: Vec<u32>,
    tag_len: Vec<u32>,
    strings: Vec<u32>,
    filter_rva: u32,
    payload_rva: u32,
    payload_len: u32,
    ofn_rva: u32,
    open_buf_rva: u32,
    save_buf_rva: u32,
    abuf_rva: u32,
    rbuf_rva: u32,
    counted_rva: u32,
    written_rva: u32,
    ret_rva: u32,
    data_len: u32,
}

impl Rdata {
    fn build() -> Rdata {
        let plan = import_plan();
        let n_dlls = plan.len();

        let import_dir_off = 0u32;
        let import_dir_size = ((n_dlls + 1) * 20) as u32;
        let thunks_qwords: usize = plan.iter().map(|(_, fs)| fs.len() + 1).sum();
        let ilt_off = import_dir_off + import_dir_size;
        let ilt_size = (thunks_qwords * 8) as u32;
        let iat_off = ilt_off + ilt_size;
        let iat_size = ilt_size;

        let mut pos = iat_off + iat_size;

        let mut ibn_rva: Vec<u32> = Vec::new();
        for (_, funcs) in &plan {
            for f in funcs {
                pos = align_up_u32(pos, 2);
                ibn_rva.push(RDATA_RVA + pos);
                pos += 2 + f.len() as u32 + 1;
            }
        }
        let mut dll_name_rva: Vec<u32> = Vec::new();
        for (dll, _) in &plan {
            dll_name_rva.push(RDATA_RVA + pos);
            pos += dll.len() as u32 + 1;
        }
        let mut tag_rva = Vec::new();
        let mut tag_len = Vec::new();
        for tag in TAGS {
            tag_rva.push(RDATA_RVA + pos);
            let n = tag.len() as u32 + 1;
            tag_len.push(n);
            pos += n;
        }
        let payload_rva = RDATA_RVA + pos;
        let payload_len = SAVE_PAYLOAD.len() as u32;
        pos += payload_len;

        pos = align_up_u32(pos, 2);
        let mut strings: Vec<u32> = Vec::new();
        for s in WIDE_STRINGS {
            strings.push(RDATA_RVA + pos);
            pos += wide(s).len() as u32;
        }
        let filter_rva = RDATA_RVA + pos;
        let filter = filter_blob();
        pos += filter.len() as u32;

        let mut b = vec![0u8; pos as usize];

        let mut iat = std::collections::HashMap::new();
        let mut ilt_cursor = ilt_off;
        let mut iat_cursor = iat_off;
        let mut ibn_i = 0usize;
        for (d, (_dll, funcs)) in plan.iter().enumerate() {
            let desc = import_dir_off as usize + d * 20;
            put_u32(&mut b, desc, ilt_cursor + RDATA_RVA);
            put_u32(&mut b, desc + 12, dll_name_rva[d]);
            put_u32(&mut b, desc + 16, iat_cursor + RDATA_RVA);
            for f in funcs {
                let rva = ibn_rva[ibn_i];
                put_u64(&mut b, ilt_cursor as usize, rva as u64);
                put_u64(&mut b, iat_cursor as usize, rva as u64);
                iat.insert((*f).to_string(), iat_cursor + RDATA_RVA);
                ilt_cursor += 8;
                iat_cursor += 8;
                ibn_i += 1;
            }
            ilt_cursor += 8;
            iat_cursor += 8;
        }

        ibn_i = 0;
        for (_, funcs) in &plan {
            for f in funcs {
                let off = (ibn_rva[ibn_i] - RDATA_RVA) as usize;
                b[off + 2..off + 2 + f.len()].copy_from_slice(f.as_bytes());
                ibn_i += 1;
            }
        }
        for (d, (dll, _)) in plan.iter().enumerate() {
            let off = (dll_name_rva[d] - RDATA_RVA) as usize;
            b[off..off + dll.len()].copy_from_slice(dll.as_bytes());
        }
        for (i, tag) in TAGS.iter().enumerate() {
            let off = (tag_rva[i] - RDATA_RVA) as usize;
            b[off..off + tag.len()].copy_from_slice(tag.as_bytes());
            b[off + tag.len()] = b'=';
        }
        let off = (payload_rva - RDATA_RVA) as usize;
        b[off..off + SAVE_PAYLOAD.len()].copy_from_slice(SAVE_PAYLOAD.as_bytes());
        for (rva, s) in strings.iter().zip(WIDE_STRINGS) {
            let off = (*rva - RDATA_RVA) as usize;
            let w = wide(s);
            b[off..off + w.len()].copy_from_slice(&w);
        }
        let off = (filter_rva - RDATA_RVA) as usize;
        b[off..off + filter.len()].copy_from_slice(&filter);

        let ofn_rva = DATA_RVA;
        let open_buf_rva = ofn_rva + OPENFILENAMEW_SIZE + 8;
        let save_buf_rva = open_buf_rva + MAX_PATH * 2 + 8;
        let abuf_rva = save_buf_rva + MAX_PATH * 2 + 8;
        let rbuf_rva = abuf_rva + MAX_PATH * 2 + 8;
        let counted_rva = align_up_u32(rbuf_rva + RBUF_LEN + 8, 8);
        let written_rva = counted_rva + 8;
        let ret_rva = written_rva + 8;
        let data_len = ret_rva + 8 - DATA_RVA;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            tag_rva,
            tag_len,
            strings,
            filter_rva,
            payload_rva,
            payload_len,
            ofn_rva,
            open_buf_rva,
            save_buf_rva,
            abuf_rva,
            rbuf_rva,
            counted_rva,
            written_rva,
            ret_rva,
            data_len,
        }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }

    fn wstr(&self, s: &str) -> u32 {
        let i = WIDE_STRINGS.iter().position(|w| *w == s).expect("wide string present");
        self.strings[i]
    }

    fn tag(&self, t: &str) -> (u32, u32) {
        let i = TAGS.iter().position(|x| *x == t).expect("tag present");
        (self.tag_rva[i], self.tag_len[i])
    }
}

fn wide(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

fn filter_blob() -> Vec<u8> {
    let mut v = Vec::new();
    for p in FILTER_PARTS {
        v.extend_from_slice(&wide(p));
    }
    v.extend_from_slice(&[0, 0]);
    v
}

const FRAME: u32 = 0x38;

fn build_text(r: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME as u8]);
    c.extend_from_slice(&[0x45, 0x31, 0xED]);
    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    emit_open_leg(&mut c, r);
    emit_save_leg(&mut c, r);
    emit_bad_size_leg(&mut c, r);

    c.extend_from_slice(&[0x44, 0x89, 0xE9]);
    rip(&mut c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC);
    c
}

fn emit_ofn_common(c: &mut Vec<u8>, r: &Rdata, file_buf_rva: u32, title: &str, flags: u32) {
    let mut off = 0u32;
    while off < OPENFILENAMEW_SIZE {
        mov_mem_imm64(c, r.ofn_rva + off, 0);
        off += 8;
    }
    mov_mem_imm32(c, r.ofn_rva + OFN_STRUCT_SIZE, OPENFILENAMEW_SIZE as i32);
    mov_mem_imm64(c, r.ofn_rva + OFN_HWND_OWNER, 0);
    lea_rax(c, r.filter_rva);
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_FILTER);
    lea_rax(c, file_buf_rva);
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_FILE);
    mov_mem_imm32(c, r.ofn_rva + OFN_N_MAX_FILE, MAX_PATH as i32);
    lea_rax(c, r.wstr(INITIAL_DIR));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_INITIAL_DIR);
    lea_rax(c, r.wstr(title));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_TITLE);
    mov_mem_imm32(c, r.ofn_rva + OFN_FLAGS, flags as i32);
    lea_rax(c, r.wstr(DEF_EXT));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_DEF_EXT);
}

fn emit_open_leg(c: &mut Vec<u8>, r: &Rdata) {
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.open_buf_rva, 0);
    emit_ofn_common(c, r, r.open_buf_rva, OPEN_TITLE, OPEN_FLAGS);

    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva);
    rip(c, &[0xFF, 0x15], r.slot("GetOpenFileNameW"));
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    rip(c, &[0x89, 0x05], r.ret_rva);

    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva);

    let (tag, len) = r.tag(TAG_OPEN_RET);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.ret_rva);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_OPEN);
    emit_tag(c, r, tag, len);
    emit_squeeze_w(c, r.open_buf_rva);
    emit_count_empty(c);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_OPEN_ERR);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);

    rip(c, &[0x48, 0x8D, 0x0D], r.open_buf_rva);
    c.push(0xBA);
    c.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    stack_arg_imm(c, 0x20, 3);
    stack_arg_imm(c, 0x28, 0);
    stack_arg_imm(c, 0x30, 0);
    rip(c, &[0xFF, 0x15], r.slot("CreateFileW"));
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);

    rip_imm8(c, &[0xC6, 0x05], r.rbuf_rva, 0);
    mov_mem_imm32(c, r.counted_rva, 0);

    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0xFF]);
    let jne_fix = jcc_near(c, 0x85);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    let jmp_fix = jmp_near(c);
    patch_near(c, jne_fix);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0x48, 0x8D, 0x15], r.rbuf_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&RBUF_LEN.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.counted_rva);
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("ReadFile"));
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    rip(c, &[0x48, 0x8D, 0x05], r.rbuf_rva);
    rip(c, &[0x8B, 0x0D], r.counted_rva);
    c.extend_from_slice(&[0xC6, 0x04, 0x08, 0x00]);
    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));
    patch_near(c, jmp_fix);

    let (tag, len) = r.tag(TAG_READ);
    emit_tag(c, r, tag, len);
    emit_copy_az(c, r.rbuf_rva);
    emit_count_empty(c);
    emit_flush(c, r);
}

fn emit_save_leg(c: &mut Vec<u8>, r: &Rdata) {
    emit_copy_wz(c, r.wstr(SAVE_FILE_NAME), r.save_buf_rva);
    emit_ofn_common(c, r, r.save_buf_rva, SAVE_TITLE, SAVE_FLAGS);

    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva);
    rip(c, &[0xFF, 0x15], r.slot("GetSaveFileNameW"));
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    rip(c, &[0x89, 0x05], r.ret_rva);

    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva);

    let (tag, len) = r.tag(TAG_SAVE_RET);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.ret_rva);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_SAVE);
    emit_tag(c, r, tag, len);
    emit_squeeze_w(c, r.save_buf_rva);
    emit_count_empty(c);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_SAVE_ERR);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);

    rip(c, &[0x48, 0x8D, 0x0D], r.save_buf_rva);
    c.push(0xBA);
    c.extend_from_slice(&0x4000_0000u32.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    stack_arg_imm(c, 0x20, 2);
    stack_arg_imm(c, 0x28, 0);
    stack_arg_imm(c, 0x30, 0);
    rip(c, &[0xFF, 0x15], r.slot("CreateFileW"));
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);

    mov_mem_imm32(c, r.counted_rva, 0);
    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0xFF]);
    let jne_fix = jcc_near(c, 0x85);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    let jmp_fix = jmp_near(c);
    patch_near(c, jne_fix);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0x48, 0x8D, 0x15], r.payload_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.payload_len.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.counted_rva);
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));
    patch_near(c, jmp_fix);

    let (tag, len) = r.tag(TAG_WROTE);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);
}

fn emit_bad_size_leg(c: &mut Vec<u8>, r: &Rdata) {
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.open_buf_rva, 0);
    emit_ofn_common(c, r, r.open_buf_rva, OPEN_TITLE, OPEN_FLAGS);
    mov_mem_imm32(c, r.ofn_rva + OFN_STRUCT_SIZE, BAD_STRUCT_SIZE as i32);

    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva);
    rip(c, &[0xFF, 0x15], r.slot("GetOpenFileNameW"));
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x74, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);

    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva);

    let (tag, len) = r.tag(TAG_BAD_SIZE);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);
}

fn emit_tag(c: &mut Vec<u8>, r: &Rdata, tag_rva: u32, tag_len: u32) {
    rip(c, &[0x4C, 0x8D, 0x35], r.abuf_rva);
    rip(c, &[0x48, 0x8D, 0x3D], tag_rva);
    c.push(0xB9);
    c.extend_from_slice(&tag_len.to_le_bytes());
    let top = c.len();
    c.extend_from_slice(&[0x8A, 0x07]);
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0xFF, 0xC9]);
    jmp_short_back(c, 0x75, top);
}

fn emit_squeeze_w(c: &mut Vec<u8>, buf_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], buf_rva);
    c.extend_from_slice(&[0x45, 0x31, 0xFF]);
    let top = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]);
    c.extend_from_slice(&[0x66, 0x85, 0xC0]);
    c.extend_from_slice(&[0x74, 0x00]);
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]);
    c.extend_from_slice(&[0x41, 0xB7, 0x01]);
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

fn emit_copy_az(c: &mut Vec<u8>, buf_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], buf_rva);
    c.extend_from_slice(&[0x45, 0x31, 0xFF]);
    let top = c.len();
    c.extend_from_slice(&[0x8A, 0x07]);
    c.extend_from_slice(&[0x84, 0xC0]);
    c.extend_from_slice(&[0x74, 0x00]);
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    c.extend_from_slice(&[0x41, 0xB7, 0x01]);
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

fn emit_decimal(c: &mut Vec<u8>, count_rva: u32) {
    rip(c, &[0x8B, 0x05], count_rva);
    c.extend_from_slice(&[0x41, 0xB7, 0x01]);
    c.extend_from_slice(&[0x48, 0x8D, 0x7C, 0x24, 0x18]);
    c.extend_from_slice(&[0xB9, 0x0A, 0x00, 0x00, 0x00]);
    let top = c.len();
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0xF7, 0xF1]);
    c.extend_from_slice(&[0x80, 0xC2, 0x30]);
    c.extend_from_slice(&[0x48, 0xFF, 0xCF]);
    c.extend_from_slice(&[0x88, 0x17]);
    c.extend_from_slice(&[0x85, 0xC0]);
    jmp_short_back(c, 0x75, top);
    let copy = c.len();
    c.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x18]);
    c.extend_from_slice(&[0x48, 0x39, 0xC7]);
    c.extend_from_slice(&[0x74, 0x00]);
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x8A, 0x07]);
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    jmp_short_back(c, 0xEB, copy);
    patch_short(c, done_fix);
}

fn emit_count_empty(c: &mut Vec<u8>) {
    c.extend_from_slice(&[0x45, 0x84, 0xFF]);
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
}

fn emit_flush(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x41, 0xC6, 0x06, 0x0A]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x4C, 0x89, 0xF0]);
    rip(c, &[0x48, 0x8D, 0x15], r.abuf_rva);
    c.extend_from_slice(&[0x48, 0x29, 0xD0]);
    c.extend_from_slice(&[0x41, 0x89, 0xC0]);
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva);
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

fn emit_copy_wz(c: &mut Vec<u8>, src_rva: u32, dst_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], src_rva);
    rip(c, &[0x48, 0x8D, 0x15], dst_rva);
    let top = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]);
    c.extend_from_slice(&[0x66, 0x89, 0x02]);
    c.extend_from_slice(&[0x66, 0x85, 0xC0]);
    c.extend_from_slice(&[0x74, 0x00]);
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]);
    c.extend_from_slice(&[0x48, 0x83, 0xC2, 0x02]);
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

fn rip_imm8(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u8) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 1;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.push(imm);
}

fn rip_imm16(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u16) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 2;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

fn rip_imm32(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: i32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

fn mov_mem_imm64(c: &mut Vec<u8>, target_rva: u32, imm: i32) {
    rip_imm32(c, &[0x48, 0xC7, 0x05], target_rva, imm);
}
fn mov_mem_imm32(c: &mut Vec<u8>, target_rva: u32, imm: i32) {
    rip_imm32(c, &[0xC7, 0x05], target_rva, imm);
}
fn mov_mem_rax(c: &mut Vec<u8>, target_rva: u32) {
    rip(c, &[0x48, 0x89, 0x05], target_rva);
}
fn lea_rax(c: &mut Vec<u8>, target_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x05], target_rva);
}
fn stack_arg_imm(c: &mut Vec<u8>, disp: u8, imm: i32) {
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, disp]);
    c.extend_from_slice(&imm.to_le_bytes());
}

fn jcc_near(c: &mut Vec<u8>, cc: u8) -> usize {
    c.extend_from_slice(&[0x0F, cc]);
    let at = c.len();
    c.extend_from_slice(&[0, 0, 0, 0]);
    at
}
fn jmp_near(c: &mut Vec<u8>) -> usize {
    c.push(0xE9);
    let at = c.len();
    c.extend_from_slice(&[0, 0, 0, 0]);
    at
}
fn patch_near(c: &mut [u8], at: usize) {
    let rel = c.len() as i32 - (at as i32 + 4);
    c[at..at + 4].copy_from_slice(&rel.to_le_bytes());
}
fn patch_short(c: &mut [u8], at: usize) {
    let rel = c.len() as i64 - (at as i64 + 1);
    c[at] = (rel as i8) as u8;
}
fn jmp_short_back(c: &mut Vec<u8>, op: u8, target: usize) {
    c.extend_from_slice(&[op, 0x00]);
    let end = c.len();
    c[end - 1] = ((target as i64 - end as i64) as i8) as u8;
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
fn put_u64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
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
    fn comdlg_sample_is_a_pe_importing_comdlg32() {
        let exe = build();
        let image = exemu_loader::parse(&exe).expect("parses as PE32+");
        assert!(image.is_64bit);
        assert_eq!(image.subsystem, 3, "console subsystem");

        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        assert!(has("comdlg32.dll", "GetOpenFileNameW"), "imports comdlg32!GetOpenFileNameW");
        assert!(has("comdlg32.dll", "GetSaveFileNameW"), "imports comdlg32!GetSaveFileNameW");
        assert!(has("kernel32.dll", "CreateFileW"), "opens the path it is handed");
        assert!(has("kernel32.dll", "ReadFile"));
        assert!(has("kernel32.dll", "WriteFile"));

        for s in [OPEN_TITLE, SAVE_TITLE, INITIAL_DIR] {
            let needle = wide(s);
            assert!(
                exe.windows(needle.len()).any(|w| w == needle),
                "the wide string {s:?} is in the image"
            );
        }
        for tag in TAGS {
            let needle = format!("{tag}=");
            assert!(
                exe.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "the {tag} tag is in the image"
            );
        }
    }

    #[test]
    fn openfilenamew_is_152_bytes_on_x64() {
        assert_eq!(OPENFILENAMEW_SIZE, 152);
    }
}
