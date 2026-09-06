use crate::cab;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const TEXT_MAX: usize = (RDATA_RVA - TEXT_RVA) as usize;

pub const CAB_OK_EXIT: i32 = 66;

pub const CAB_FILE_NAME: &str = "test.cab";

pub const OK_MESSAGE: &str = "CAB OK\n";
pub const FAIL_MESSAGE: &str = "CAB FAIL\n";

pub const LABEL_FDICREATE: &str = "FDICREATE=";
pub const LABEL_SETID: &str = "SETID=";
pub const LABEL_CFILES: &str = "CFILES=";
pub const LABEL_FDICOPY: &str = "FDICOPY=";
pub const LABEL_NAME: &str = "NAME=";
pub const LABEL_LEN: &str = "LEN=";
pub const LABEL_DATA: &str = "DATA=";

const LABELS: [&str; 7] = [
    LABEL_FDICREATE,
    LABEL_SETID,
    LABEL_CFILES,
    LABEL_FDICOPY,
    LABEL_NAME,
    LABEL_LEN,
    LABEL_DATA,
];

const OUT_CAP: u32 = 0x8000;

const HEAP_CAP: u32 = 0x40_0000;

pub fn build(name: &str, payload: &[u8]) -> Vec<u8> {
    let cab_bytes = cab::build_cab(name, payload);
    let (rdata, syms) = build_rdata(&cab_bytes, name, payload);
    let (text, entry_off) = build_text(&syms);
    assert!(
        text.len() <= TEXT_MAX,
        ".text ({} bytes) outgrew the {TEXT_MAX}-byte gap to .rdata",
        text.len()
    );

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rdata.len(), FILE_ALIGN as usize);
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
    let image_size = align_up_u32(syms.data_rva + syms.data_len, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA + entry_off);
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
    put_u32(&mut f, dir(1), RDATA_RVA + syms.import_dir_off);
    put_u32(&mut f, dir(1) + 4, syms.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + syms.iat_off);
    put_u32(&mut f, dir(12) + 4, syms.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", rdata.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", syms.data_len, syms.data_rva, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rdata.len()].copy_from_slice(&rdata);
    f
}

struct Syms {
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,

    iat_fdi_create: u32,
    iat_fdi_is_cabinet: u32,
    iat_fdi_copy: u32,
    iat_fdi_destroy: u32,
    iat_get_std_handle: u32,
    iat_write_file: u32,
    iat_exit_process: u32,

    cab_rva: u32,
    cab_len: u32,
    cabname_rva: u32,
    cabpath_rva: u32,
    payload_rva: u32,
    payload_len: u32,
    aname_rva: u32,
    aname_len: u32,
    nl_rva: u32,
    label_rva: [u32; 7],
    ok_rva: u32,
    fail_rva: u32,

    data_rva: u32,
    data_len: u32,
    cab_pos_rva: u32,
    out_len_rva: u32,
    heap_ptr_rva: u32,
    name_len_rva: u32,
    written_rva: u32,
    fdici_rva: u32,
    hexbuf_rva: u32,
    namebuf_rva: u32,
    erf_rva: u32,
    out_buf_rva: u32,
    heap_arena_rva: u32,
    heap_end_rva: u32,
}

fn import_plan() -> [(&'static str, &'static [&'static str]); 2] {
    [
        (
            "cabinet.dll",
            &["FDICreate", "FDIIsCabinet", "FDICopy", "FDIDestroy"],
        ),
        (
            "kernel32.dll",
            &["GetStdHandle", "WriteFile", "ExitProcess"],
        ),
    ]
}

fn build_rdata(cab_bytes: &[u8], name: &str, payload: &[u8]) -> (Vec<u8>, Syms) {
    let plan = import_plan();
    let n_dlls = plan.len();

    let import_dir_off = 0u32;
    let import_dir_size = ((n_dlls + 1) * 20) as u32;
    let thunk_qwords: usize = plan.iter().map(|(_, fs)| fs.len() + 1).sum();
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = (thunk_qwords * 8) as u32;
    let iat_off = ilt_off + ilt_size;
    let iat_size = ilt_size;

    let mut pos = iat_off + iat_size;

    let mut ibn_rva: Vec<u32> = Vec::new();
    for (_, funcs) in &plan {
        for f in *funcs {
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

    let cabname_rva = RDATA_RVA + pos;
    pos += CAB_FILE_NAME.len() as u32 + 1;
    let cabpath_rva = RDATA_RVA + pos;
    pos += 1;
    let nl_rva = RDATA_RVA + pos;
    pos += 1;
    let mut label_rva = [0u32; 7];
    for (i, l) in LABELS.iter().enumerate() {
        label_rva[i] = RDATA_RVA + pos;
        pos += l.len() as u32;
    }
    let ok_rva = RDATA_RVA + pos;
    pos += OK_MESSAGE.len() as u32;
    let fail_rva = RDATA_RVA + pos;
    pos += FAIL_MESSAGE.len() as u32;
    let aname_rva = RDATA_RVA + pos;
    pos += name.len() as u32;
    let payload_rva = RDATA_RVA + pos;
    pos += payload.len() as u32;

    pos = align_up_u32(pos, 16);
    let cab_rva = RDATA_RVA + pos;
    pos += cab_bytes.len() as u32;

    let mut b = vec![0u8; pos as usize];

    let mut iat_slots: Vec<u32> = Vec::new();
    let mut ilt_cursor = ilt_off;
    let mut iat_cursor = iat_off;
    let mut ibn_i = 0usize;
    for (d, (_dll, funcs)) in plan.iter().enumerate() {
        let desc = import_dir_off as usize + d * 20;
        put_u32(&mut b, desc, ilt_cursor + RDATA_RVA);
        put_u32(&mut b, desc + 12, dll_name_rva[d]);
        put_u32(&mut b, desc + 16, iat_cursor + RDATA_RVA);
        for _ in *funcs {
            let rva = ibn_rva[ibn_i];
            put_u64(&mut b, ilt_cursor as usize, rva as u64);
            put_u64(&mut b, iat_cursor as usize, rva as u64);
            iat_slots.push(iat_cursor + RDATA_RVA);
            ilt_cursor += 8;
            iat_cursor += 8;
            ibn_i += 1;
        }
        ilt_cursor += 8;
        iat_cursor += 8;
    }

    ibn_i = 0;
    for (_, funcs) in &plan {
        for f in *funcs {
            let off = (ibn_rva[ibn_i] - RDATA_RVA) as usize;
            b[off + 2..off + 2 + f.len()].copy_from_slice(f.as_bytes());
            ibn_i += 1;
        }
    }
    for (d, (dll, _)) in plan.iter().enumerate() {
        let off = (dll_name_rva[d] - RDATA_RVA) as usize;
        b[off..off + dll.len()].copy_from_slice(dll.as_bytes());
    }

    let put = |b: &mut Vec<u8>, rva: u32, bytes: &[u8]| {
        let off = (rva - RDATA_RVA) as usize;
        b[off..off + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut b, cabname_rva, CAB_FILE_NAME.as_bytes());
    put(&mut b, nl_rva, b"\n");
    for (i, l) in LABELS.iter().enumerate() {
        put(&mut b, label_rva[i], l.as_bytes());
    }
    put(&mut b, ok_rva, OK_MESSAGE.as_bytes());
    put(&mut b, fail_rva, FAIL_MESSAGE.as_bytes());
    put(&mut b, aname_rva, name.as_bytes());
    put(&mut b, payload_rva, payload);
    put(&mut b, cab_rva, cab_bytes);

    let data_rva = align_up_u32(RDATA_RVA + pos, SECTION_ALIGN);
    let mut d = data_rva;
    let cell = |n: u32, dp: &mut u32| -> u32 {
        let r = *dp;
        *dp += n;
        r
    };
    let cab_pos_rva = cell(8, &mut d);
    let out_len_rva = cell(8, &mut d);
    let heap_ptr_rva = cell(8, &mut d);
    let name_len_rva = cell(8, &mut d);
    let written_rva = cell(8, &mut d);
    let fdici_rva = cell(32, &mut d);
    let hexbuf_rva = cell(32, &mut d);
    let namebuf_rva = cell(128, &mut d);
    let erf_rva = cell(16, &mut d);
    let out_buf_rva = cell(OUT_CAP, &mut d);
    d = align_up_u32(d, 16);
    let heap_arena_rva = cell(HEAP_CAP, &mut d);
    let heap_end_rva = d;
    let data_len = d - data_rva;

    let syms = Syms {
        import_dir_off,
        import_dir_size,
        iat_off,
        iat_size,
        iat_fdi_create: iat_slots[0],
        iat_fdi_is_cabinet: iat_slots[1],
        iat_fdi_copy: iat_slots[2],
        iat_fdi_destroy: iat_slots[3],
        iat_get_std_handle: iat_slots[4],
        iat_write_file: iat_slots[5],
        iat_exit_process: iat_slots[6],
        cab_rva,
        cab_len: cab_bytes.len() as u32,
        cabname_rva,
        cabpath_rva,
        payload_rva,
        payload_len: payload.len() as u32,
        aname_rva,
        aname_len: name.len() as u32,
        nl_rva,
        label_rva,
        ok_rva,
        fail_rva,
        data_rva,
        data_len,
        cab_pos_rva,
        out_len_rva,
        heap_ptr_rva,
        name_len_rva,
        written_rva,
        fdici_rva,
        hexbuf_rva,
        namebuf_rva,
        erf_rva,
        out_buf_rva,
        heap_arena_rva,
        heap_end_rva,
    };
    (b, syms)
}

#[derive(Clone, Copy)]
struct Callbacks {
    alloc: u32,
    free: u32,
    open: u32,
    read: u32,
    write: u32,
    close: u32,
    seek: u32,
    notify: u32,
}

fn build_text(s: &Syms) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();

    let alloc = c.len() as u32;
    emit_alloc(&mut c, s);
    let free = c.len() as u32;
    c.push(0xC3);
    let open = c.len() as u32;
    emit_open(&mut c, s);
    let read = c.len() as u32;
    emit_read(&mut c, s);
    let write = c.len() as u32;
    emit_write_cb(&mut c, s);
    let close = c.len() as u32;
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
    let seek = c.len() as u32;
    emit_seek(&mut c, s);
    let notify = c.len() as u32;
    emit_notify(&mut c, s);
    let cb = Callbacks { alloc, free, open, read, write, close, seek, notify };

    let entry_off = c.len() as u32;
    emit_entry(&mut c, s, &cb);
    (c, entry_off)
}

fn emit_alloc(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x89, 0xC8]);
    c.extend_from_slice(&[0x48, 0x83, 0xC0, 0x0F]);
    c.extend_from_slice(&[0x48, 0x83, 0xE0, 0xF0]);
    rip(c, &[0x48, 0x8B, 0x0D], s.heap_ptr_rva);
    c.extend_from_slice(&[0x48, 0x89, 0xCA]);
    c.extend_from_slice(&[0x48, 0x01, 0xC2]);
    rip(c, &[0x4C, 0x8D, 0x05], s.heap_end_rva);
    c.extend_from_slice(&[0x4C, 0x39, 0xC2]);
    let ja_oom = jcc8(c, 0x77);
    rip(c, &[0x48, 0x89, 0x15], s.heap_ptr_rva);
    c.extend_from_slice(&[0x48, 0x89, 0xC8]);
    c.push(0xC3);
    patch8(c, ja_oom);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
}

fn emit_open(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x31, 0xC0]);
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva);
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    c.push(0xC3);
}

fn emit_read(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x48, 0x83, 0xF9, 0x01]);
    let jne_zero = jcc8(c, 0x75);
    c.extend_from_slice(&[0x45, 0x89, 0xC1]);
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva);
    c.extend_from_slice(&[0x41, 0xBA]);
    c.extend_from_slice(&s.cab_len.to_le_bytes());
    c.extend_from_slice(&[0x4C, 0x39, 0xD0]);
    let jae_zero = jcc8(c, 0x73);
    c.extend_from_slice(&[0x49, 0x29, 0xC2]);
    c.extend_from_slice(&[0x4D, 0x39, 0xD1]);
    let jbe_clamped = jcc8(c, 0x76);
    c.extend_from_slice(&[0x4D, 0x89, 0xD1]);
    patch8(c, jbe_clamped);
    rip(c, &[0x4C, 0x8D, 0x1D], s.cab_rva);
    c.extend_from_slice(&[0x49, 0x01, 0xC3]);
    emit_copy_loop(c, CopyDir::R11ToRdx);
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva);
    c.extend_from_slice(&[0x4C, 0x01, 0xC8]);
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva);
    c.extend_from_slice(&[0x4C, 0x89, 0xC8]);
    c.push(0xC3);
    patch8(c, jne_zero);
    patch8(c, jae_zero);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
}

fn emit_write_cb(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x45, 0x89, 0xC1]);
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva);
    c.extend_from_slice(&[0x41, 0xBA]);
    c.extend_from_slice(&OUT_CAP.to_le_bytes());
    c.extend_from_slice(&[0x4C, 0x39, 0xD0]);
    let jae_zero = jcc8(c, 0x73);
    c.extend_from_slice(&[0x49, 0x29, 0xC2]);
    c.extend_from_slice(&[0x4D, 0x39, 0xD1]);
    let jbe_clamped = jcc8(c, 0x76);
    c.extend_from_slice(&[0x4D, 0x89, 0xD1]);
    patch8(c, jbe_clamped);
    rip(c, &[0x4C, 0x8D, 0x1D], s.out_buf_rva);
    c.extend_from_slice(&[0x49, 0x01, 0xC3]);
    emit_copy_loop(c, CopyDir::RdxToR11);
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva);
    c.extend_from_slice(&[0x4C, 0x01, 0xC8]);
    rip(c, &[0x48, 0x89, 0x05], s.out_len_rva);
    c.extend_from_slice(&[0x4C, 0x89, 0xC8]);
    c.push(0xC3);
    patch8(c, jae_zero);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
}

fn emit_seek(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x48, 0x83, 0xF9, 0x01]);
    let jne_other = jcc8(c, 0x75);
    c.extend_from_slice(&[0x48, 0x63, 0xD2]);
    c.extend_from_slice(&[0x41, 0x83, 0xF8, 0x01]);
    let je_cur = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0x83, 0xF8, 0x02]);
    let je_end = jcc8(c, 0x74);
    c.extend_from_slice(&[0x48, 0x89, 0xD0]);
    let jmp_store_a = jcc8(c, 0xEB);
    patch8(c, je_cur);
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva);
    c.extend_from_slice(&[0x48, 0x01, 0xD0]);
    let jmp_store_b = jcc8(c, 0xEB);
    patch8(c, je_end);
    c.push(0xB8);
    c.extend_from_slice(&s.cab_len.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x01, 0xD0]);
    patch8(c, jmp_store_a);
    patch8(c, jmp_store_b);
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva);
    c.push(0xC3);
    patch8(c, jne_other);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
}

fn emit_notify(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x83, 0xF9, 0x02]);
    let je_copy = jcc8(c, 0x74);
    c.extend_from_slice(&[0x83, 0xF9, 0x03]);
    let je_close = jcc8(c, 0x74);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
    patch8(c, je_close);
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    patch8(c, je_copy);
    c.extend_from_slice(&[0x48, 0x8B, 0x42, 0x08]);
    rip(c, &[0x4C, 0x8D, 0x05], s.namebuf_rva);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    c.extend_from_slice(&[0x41, 0xBB, 0x40, 0x00, 0x00, 0x00]);
    let loop_top = c.len();
    c.extend_from_slice(&[0x8A, 0x10]);
    c.extend_from_slice(&[0x41, 0x88, 0x10]);
    c.extend_from_slice(&[0x84, 0xD2]);
    let je_done = jcc8(c, 0x74);
    c.extend_from_slice(&[0x48, 0xFF, 0xC0]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC1]);
    c.extend_from_slice(&[0x49, 0xFF, 0xCB]);
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, loop_top);
    patch8(c, je_done);
    rip(c, &[0x4C, 0x89, 0x0D], s.name_len_rva);
    c.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00]);
    c.push(0xC3);
}

enum CopyDir {
    R11ToRdx,
    RdxToR11,
}

fn emit_copy_loop(c: &mut Vec<u8>, dir: CopyDir) {
    c.extend_from_slice(&[0x4D, 0x31, 0xD2]);
    let top = c.len();
    c.extend_from_slice(&[0x4D, 0x39, 0xCA]);
    let jae_done = jcc8(c, 0x73);
    match dir {
        CopyDir::R11ToRdx => {
            c.extend_from_slice(&[0x43, 0x8A, 0x04, 0x13]);
            c.extend_from_slice(&[0x42, 0x88, 0x04, 0x12]);
        }
        CopyDir::RdxToR11 => {
            c.extend_from_slice(&[0x42, 0x8A, 0x04, 0x12]);
            c.extend_from_slice(&[0x43, 0x88, 0x04, 0x13]);
        }
    }
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]);
    let jmp_top = jcc8(c, 0xEB);
    back8(c, jmp_top, top);
    patch8(c, jae_done);
}

fn emit_entry(c: &mut Vec<u8>, s: &Syms, cb: &Callbacks) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x68]);
    c.extend_from_slice(&[0x45, 0x31, 0xED]);

    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(c, &[0xFF, 0x15], s.iat_get_std_handle);
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    rip(c, &[0x48, 0x8D, 0x05], s.heap_arena_rva);
    rip(c, &[0x48, 0x89, 0x05], s.heap_ptr_rva);

    rip(c, &[0x48, 0x8D, 0x0D], TEXT_RVA + cb.alloc);
    rip(c, &[0x48, 0x8D, 0x15], TEXT_RVA + cb.free);
    rip(c, &[0x4C, 0x8D, 0x05], TEXT_RVA + cb.open);
    rip(c, &[0x4C, 0x8D, 0x0D], TEXT_RVA + cb.read);
    stack_arg_lea(c, 0x20, TEXT_RVA + cb.write);
    stack_arg_lea(c, 0x28, TEXT_RVA + cb.close);
    stack_arg_lea(c, 0x30, TEXT_RVA + cb.seek);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
    stack_arg_lea(c, 0x40, s.erf_rva);
    rip(c, &[0xFF, 0x15], s.iat_fdi_create);
    c.extend_from_slice(&[0x49, 0x89, 0xC4]);
    print_hex64(c, s, 0);

    c.extend_from_slice(&[0x4D, 0x85, 0xE4]);
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    let jnz_have = c.len() - 4;
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);
    let jmp_report = c.len() - 4;
    patch32(c, jnz_have);

    c.extend_from_slice(&[0x4C, 0x89, 0xE1]);
    c.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    rip(c, &[0x4C, 0x8D, 0x05], s.fdici_rva);
    rip(c, &[0xFF, 0x15], s.iat_fdi_is_cabinet);
    rip(c, &[0x0F, 0xB7, 0x05], s.fdici_rva + 8);
    print_hex64(c, s, 1);
    rip(c, &[0x0F, 0xB7, 0x05], s.fdici_rva + 6);
    print_hex64(c, s, 2);

    c.extend_from_slice(&[0x4C, 0x89, 0xE1]);
    rip(c, &[0x48, 0x8D, 0x15], s.cabname_rva);
    rip(c, &[0x4C, 0x8D, 0x05], s.cabpath_rva);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    stack_arg_lea(c, 0x20, TEXT_RVA + cb.notify);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0, 0, 0, 0]);
    rip(c, &[0xFF, 0x15], s.iat_fdi_copy);
    c.extend_from_slice(&[0x49, 0x89, 0xC6]);
    print_hex64(c, s, 3);

    write_str(c, s, s.label_rva[4], Len::Imm(LABEL_NAME.len() as u32));
    write_str(c, s, s.namebuf_rva, Len::MemU32(s.name_len_rva));
    write_str(c, s, s.nl_rva, Len::Imm(1));
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva);
    print_hex64(c, s, 5);
    write_str(c, s, s.label_rva[6], Len::Imm(LABEL_DATA.len() as u32));
    write_str(c, s, s.out_buf_rva, Len::MemU32(s.out_len_rva));
    write_str(c, s, s.nl_rva, Len::Imm(1));

    c.extend_from_slice(&[0x4C, 0x89, 0xE1]);
    rip(c, &[0xFF, 0x15], s.iat_fdi_destroy);

    c.extend_from_slice(&[0x4D, 0x85, 0xF6]);
    fail_if(c, 0x75);
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva);
    c.extend_from_slice(&[0x48, 0x3D]);
    c.extend_from_slice(&s.payload_len.to_le_bytes());
    fail_if(c, 0x74);
    rip(c, &[0x48, 0x8B, 0x05], s.name_len_rva);
    c.extend_from_slice(&[0x48, 0x3D]);
    c.extend_from_slice(&s.aname_len.to_le_bytes());
    fail_if(c, 0x74);
    emit_memcmp(c, s.out_buf_rva, s.payload_rva, s.payload_len);
    emit_memcmp(c, s.namebuf_rva, s.aname_rva, s.aname_len);

    patch32(c, jmp_report);
    c.extend_from_slice(&[0x45, 0x85, 0xED]);
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    let jnz_fail = c.len() - 4;
    write_str(c, s, s.ok_rva, Len::Imm(OK_MESSAGE.len() as u32));
    c.push(0xB9);
    c.extend_from_slice(&(CAB_OK_EXIT as u32).to_le_bytes());
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);
    let jmp_exit = c.len() - 4;
    patch32(c, jnz_fail);
    write_str(c, s, s.fail_rva, Len::Imm(FAIL_MESSAGE.len() as u32));
    c.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
    patch32(c, jmp_exit);
    rip(c, &[0xFF, 0x15], s.iat_exit_process);
    c.push(0xCC);
}

fn fail_if(c: &mut Vec<u8>, cc: u8) {
    c.extend_from_slice(&[cc, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
}

fn emit_memcmp(c: &mut Vec<u8>, a_rva: u32, b_rva: u32, len: u32) {
    if len == 0 {
        return;
    }
    rip(c, &[0x4C, 0x8D, 0x05], a_rva);
    rip(c, &[0x4C, 0x8D, 0x0D], b_rva);
    c.push(0xB9);
    c.extend_from_slice(&len.to_le_bytes());
    let top = c.len();
    c.extend_from_slice(&[0x41, 0x8A, 0x00]);
    c.extend_from_slice(&[0x41, 0x3A, 0x01]);
    let jne_bad = jcc8(c, 0x75);
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC1]);
    c.extend_from_slice(&[0xFF, 0xC9]);
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, top);
    let jmp_done = jcc8(c, 0xEB);
    patch8(c, jne_bad);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    patch8(c, jmp_done);
}

enum Len {
    Imm(u32),
    MemU32(u32),
}

fn write_str(c: &mut Vec<u8>, s: &Syms, buf_rva: u32, len: Len) {
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x48, 0x8D, 0x15], buf_rva);
    match len {
        Len::Imm(n) => {
            c.extend_from_slice(&[0x41, 0xB8]);
            c.extend_from_slice(&n.to_le_bytes());
        }
        Len::MemU32(rva) => rip(c, &[0x44, 0x8B, 0x05], rva),
    }
    rip(c, &[0x4C, 0x8D, 0x0D], s.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    rip(c, &[0xFF, 0x15], s.iat_write_file);
}

fn print_hex64(c: &mut Vec<u8>, s: &Syms, label: usize) {
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);
    write_str(c, s, s.label_rva[label], Len::Imm(LABELS[label].len() as u32));
    rip(c, &[0x48, 0x8D, 0x3D], s.hexbuf_rva);
    c.extend_from_slice(&[0x48, 0x89, 0xD8]);
    c.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]);
    let top = c.len();
    c.extend_from_slice(&[0x48, 0xC1, 0xC0, 0x04]);
    c.extend_from_slice(&[0x89, 0xC2]);
    c.extend_from_slice(&[0x83, 0xE2, 0x0F]);
    c.extend_from_slice(&[0x80, 0xC2, 0x30]);
    c.extend_from_slice(&[0x80, 0xFA, 0x39]);
    c.extend_from_slice(&[0x76, 0x03]);
    c.extend_from_slice(&[0x80, 0xC2, 0x27]);
    c.extend_from_slice(&[0x88, 0x17]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    c.extend_from_slice(&[0xFF, 0xC9]);
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, top);
    c.extend_from_slice(&[0xC6, 0x07, 0x0A]);
    write_str(c, s, s.hexbuf_rva, Len::Imm(17));
    c.extend_from_slice(&[0x48, 0x89, 0xD8]);
}

fn stack_arg_lea(c: &mut Vec<u8>, off: u8, target_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x05], target_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, off]);
}

fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

fn jcc8(c: &mut Vec<u8>, opcode: u8) -> usize {
    c.extend_from_slice(&[opcode, 0x00]);
    c.len() - 1
}

fn patch8(c: &mut [u8], site: usize) {
    let rel = c.len() as i64 - (site as i64 + 1);
    assert!((-128..=127).contains(&rel), "short jump out of range: {rel}");
    c[site] = rel as i8 as u8;
}

fn back8(c: &mut [u8], site: usize, target: usize) {
    let rel = target as i64 - (site as i64 + 1);
    assert!((-128..=127).contains(&rel), "short back-jump out of range: {rel}");
    c[site] = rel as i8 as u8;
}

fn patch32(c: &mut [u8], site: usize) {
    let rel = (c.len() as i64 - (site as i64 + 4)) as i32;
    c[site..site + 4].copy_from_slice(&rel.to_le_bytes());
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
    fn cab_sample_is_a_pe_importing_the_fdi_entry_points() {
        let exe = build("hello.txt", b"exemu W6.5 payload");
        let image = exemu_loader::parse(&exe).expect("parses as PE32+");
        assert!(image.is_64bit);
        assert_eq!(image.subsystem, 3, "console subsystem");

        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        for sym in ["FDICreate", "FDIIsCabinet", "FDICopy", "FDIDestroy"] {
            assert!(has("cabinet.dll", sym), "imports cabinet.dll!{sym}");
        }
        assert!(has("kernel32.dll", "WriteFile"));
        assert!(has("kernel32.dll", "ExitProcess"));
    }

    #[test]
    fn the_generated_cabinet_travels_inside_the_image() {
        let payload = b"exemu W6.5 cabinet payload";
        let exe = build("hello.txt", payload);
        let cab_bytes = cab::build_cab("hello.txt", payload);

        assert!(
            exe.windows(cab_bytes.len()).any(|w| w == cab_bytes),
            "the generated cabinet is embedded in .rdata"
        );
        assert!(exe.windows(payload.len()).any(|w| w == payload));
    }

    #[test]
    fn the_entry_point_follows_the_callbacks_inside_text() {
        let payload = b"abc";
        let (_, syms) = build_rdata(&cab::build_cab("a.txt", payload), "a.txt", payload);
        let (text, entry_off) = build_text(&syms);

        assert!(entry_off > 0, "the callbacks come first");
        assert!((entry_off as usize) < text.len());
        assert!(text.len() <= TEXT_MAX, "the .text fits below .rdata");

        let exe = build("a.txt", payload);
        let image = exemu_loader::parse(&exe).expect("parses");
        assert_eq!(
            image.entry_va(),
            IMAGE_BASE + (TEXT_RVA + entry_off) as u64,
            "AddressOfEntryPoint names the entry, not a callback"
        );
    }

    #[test]
    fn the_sections_do_not_overlap() {
        let payload = b"x";
        let (rdata, syms) = build_rdata(&cab::build_cab("a", payload), "a", payload);
        assert!(RDATA_RVA + rdata.len() as u32 <= syms.data_rva, ".rdata ends below .data");
        assert_eq!(syms.data_rva % SECTION_ALIGN, 0, ".data is page-aligned");
        assert_eq!(syms.heap_end_rva - syms.heap_arena_rva, HEAP_CAP);
        assert!(syms.out_buf_rva + OUT_CAP <= syms.heap_arena_rva, "the buffers are disjoint");
    }
}
