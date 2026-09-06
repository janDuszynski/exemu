const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const PE_OFF: usize = 0x40;

pub const SAMPLE_MESSAGE: &str =
    "Hello from exemu! This Windows x64 .exe is running on Apple Silicon.\n";

pub const SAMPLE_SSE_PREFIX: &str = "SSE2 check: trunc((1.5 + 2.25) * 2.0) = ";

const SSE_CONSTS: [f64; 3] = [1.5, 2.25, 2.0];

pub fn build() -> Vec<u8> {
    let rdata = Rdata::build();
    let text = build_text(&rdata);

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rdata.bytes.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];

    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);

    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, 2);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022);

    let opt = coff + 20;
    let image_size = align_up_u32(RDATA_RVA + rdata.bytes.len() as u32, SECTION_ALIGN);
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
    put_u32(&mut f, dir(1), RDATA_RVA + rdata.import_dir_off);
    put_u32(&mut f, dir(1) + 4, rdata.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + rdata.iat_off);
    put_u32(&mut f, dir(12) + 4, rdata.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rdata.bytes.len() as u32,
        vaddr: RDATA_RVA,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rdata.bytes.len()].copy_from_slice(&rdata.bytes);

    f
}

const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

pub const TLS_SENTINEL: u8 = 0x2A;

pub fn build_with_tls() -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    const RDATA_RVA_L: u32 = 0x2000;
    const DATA_RVA_L: u32 = 0x3000;

    let sentinel_rva = DATA_RVA_L;
    let tls_index_rva = DATA_RVA_L + 8;
    let tls_tmpl_rva = DATA_RVA_L + 0x10;
    let tls_tmpl_len = 8u32;

    let import_dir_off = 0u32;
    let import_dir_size = 2 * 20u32;
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = 2 * 8u32;
    let iat_off = ilt_off + ilt_size;
    let iat_size = ilt_size;
    let mut pos = iat_off + iat_size;
    pos = align_up_u32(pos, 2);
    let ibn_off = pos;
    let ibn_name = b"ExitProcess";
    pos += 2 + ibn_name.len() as u32 + 1;
    let dllname_off = pos;
    let dllname = b"kernel32.dll\0";
    pos += dllname.len() as u32;
    pos = align_up_u32(pos, 8);
    let tls_dir_off = pos;
    let tls_dir_size = 40u32;
    pos += tls_dir_size;
    let tls_cb_off = pos;
    pos += 16;

    let iat_exit_process_rva = RDATA_RVA_L + iat_off;

    let mut rd = vec![0u8; pos as usize];
    put_u32(&mut rd, import_dir_off as usize, RDATA_RVA_L + ilt_off);
    put_u32(&mut rd, import_dir_off as usize + 12, RDATA_RVA_L + dllname_off);
    put_u32(&mut rd, import_dir_off as usize + 16, RDATA_RVA_L + iat_off);
    put_u64(&mut rd, ilt_off as usize, (RDATA_RVA_L + ibn_off) as u64);
    put_u64(&mut rd, iat_off as usize, (RDATA_RVA_L + ibn_off) as u64);
    let ibn = ibn_off as usize;
    rd[ibn + 2..ibn + 2 + ibn_name.len()].copy_from_slice(ibn_name);
    let dn = dllname_off as usize;
    rd[dn..dn + dllname.len()].copy_from_slice(dllname);

    let td = tls_dir_off as usize;
    put_u64(&mut rd, td, IMAGE_BASE + tls_tmpl_rva as u64);
    put_u64(&mut rd, td + 8, IMAGE_BASE + (tls_tmpl_rva + tls_tmpl_len) as u64);
    put_u64(&mut rd, td + 16, IMAGE_BASE + tls_index_rva as u64);
    put_u64(&mut rd, td + 24, IMAGE_BASE + (RDATA_RVA_L + tls_cb_off) as u64);
    put_u64(&mut rd, tls_cb_off as usize, IMAGE_BASE + (TEXT_RVA_L + TLS_CB_OFF) as u64);

    let text = build_tls_text(sentinel_rva, iat_exit_process_rva);

    let data_len = (tls_tmpl_rva + tls_tmpl_len - DATA_RVA_L) as usize;
    let mut data = vec![0u8; data_len];
    let tmpl_start = (tls_tmpl_rva - DATA_RVA_L) as usize;
    for j in 0..tls_tmpl_len as usize {
        data[tmpl_start + j] = 0xB0u8.wrapping_add(j as u8);
    }

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rd.len(), FILE_ALIGN as usize);
    let data_ptr = rdata_ptr + rdata_raw;
    let data_raw = align_up(data.len(), FILE_ALIGN as usize);
    let file_len = data_ptr + data_raw;

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
    let image_size = align_up_u32(DATA_RVA_L + data.len() as u32, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 16, TEXT_RVA_L + ENTRY_OFF);
    put_u32(&mut f, opt + 20, TEXT_RVA_L);
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
    put_u32(&mut f, dir(1), RDATA_RVA_L + import_dir_off);
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(9), RDATA_RVA_L + tls_dir_off);
    put_u32(&mut f, dir(9) + 4, tls_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA_L + iat_off);
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA_L,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA_L,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    });
    write_section(&mut f, sec + 80, SecHeader {
        name: b".data",
        vsize: data.len() as u32,
        vaddr: DATA_RVA_L,
        raw_size: data_raw as u32,
        raw_ptr: data_ptr as u32,
        chars: 0xC000_0040,
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f[data_ptr..data_ptr + data.len()].copy_from_slice(&data);
    f
}

const TLS_CB_OFF: u32 = 0x00;
const ENTRY_OFF: u32 = 0x20;

fn build_tls_text(sentinel_rva: u32, iat_exit_process_rva: u32) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0xC6, 0x05]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 1;
    let disp = sentinel_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    c.push(TLS_SENTINEL);
    c.push(0xC3);

    while c.len() < ENTRY_OFF as usize {
        c.push(0xCC);
    }

    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    c.extend_from_slice(&[0x0F, 0xB6, 0x0D]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = sentinel_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    c.extend_from_slice(&[0xFF, 0x15]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = iat_exit_process_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    c.push(0xCC);
    c
}

pub const FILEIO_PAYLOAD: &[u8] = b"exemu-w3-gate-payload";

pub const FILEIO_GUEST_PATH: &str = "C:\\wine-gate.txt";

pub const FILEIO_OK_EXIT: i32 = 42;

pub fn build_console_fileio() -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    const RDATA_RVA_L: u32 = 0x2000;
    const DATA_RVA_L: u32 = 0x3000;

    let payload_len = FILEIO_PAYLOAD.len() as u32;

    let readbuf_rva = DATA_RVA_L;
    let written_rva = align_up_u32(readbuf_rva + payload_len, 8);
    let nread_rva = written_rva + 8;
    let data_len = (nread_rva + 8 - DATA_RVA_L) as usize;

    let names = [
        "CreateFileA",
        "WriteFile",
        "ReadFile",
        "CloseHandle",
        "GetStdHandle",
        "ExitProcess",
    ];
    let import_dir_off = 0u32;
    let import_dir_size = 2 * 20;
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = (names.len() as u32 + 1) * 8;
    let iat_off = ilt_off + ilt_size;
    let iat_size = ilt_size;

    let mut pos = iat_off + iat_size;

    let mut ibn_rva = Vec::new();
    for n in &names {
        pos = align_up_u32(pos, 2);
        ibn_rva.push(RDATA_RVA_L + pos);
        pos += 2 + n.len() as u32 + 1;
    }
    pos = align_up_u32(pos, 2);
    let dllname_rva = RDATA_RVA_L + pos;
    let dllname = b"kernel32.dll\0";
    pos += dllname.len() as u32;

    let fname = b"C:\\wine-gate.txt\0";
    let fname_rva = RDATA_RVA_L + pos;
    pos += fname.len() as u32;
    let payload_rva = RDATA_RVA_L + pos;
    pos += payload_len;
    let ok_rva = RDATA_RVA_L + pos;
    let ok_msg = b"OK\n";
    pos += ok_msg.len() as u32;
    let fail_rva = RDATA_RVA_L + pos;
    let fail_msg = b"FAIL\n";
    pos += fail_msg.len() as u32;

    let iat = |i: u32| RDATA_RVA_L + iat_off + i * 8;
    let iat_create_file = iat(0);
    let iat_write_file = iat(1);
    let iat_read_file = iat(2);
    let iat_close_handle = iat(3);
    let iat_get_std_handle = iat(4);
    let iat_exit_process = iat(5);

    let mut rd = vec![0u8; pos as usize];
    put_u32(&mut rd, import_dir_off as usize, RDATA_RVA_L + ilt_off);
    put_u32(&mut rd, import_dir_off as usize + 12, dllname_rva);
    put_u32(&mut rd, import_dir_off as usize + 16, RDATA_RVA_L + iat_off);
    for (i, &rva) in ibn_rva.iter().enumerate() {
        put_u64(&mut rd, ilt_off as usize + i * 8, rva as u64);
        put_u64(&mut rd, iat_off as usize + i * 8, rva as u64);
    }
    for (i, n) in names.iter().enumerate() {
        let off = (ibn_rva[i] - RDATA_RVA_L) as usize;
        rd[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
    }
    let doff = (dllname_rva - RDATA_RVA_L) as usize;
    rd[doff..doff + dllname.len()].copy_from_slice(dllname);
    let foff = (fname_rva - RDATA_RVA_L) as usize;
    rd[foff..foff + fname.len()].copy_from_slice(fname);
    let poff = (payload_rva - RDATA_RVA_L) as usize;
    rd[poff..poff + FILEIO_PAYLOAD.len()].copy_from_slice(FILEIO_PAYLOAD);
    let okoff = (ok_rva - RDATA_RVA_L) as usize;
    rd[okoff..okoff + ok_msg.len()].copy_from_slice(ok_msg);
    let failoff = (fail_rva - RDATA_RVA_L) as usize;
    rd[failoff..failoff + fail_msg.len()].copy_from_slice(fail_msg);

    let text = build_fileio_text(FileioSyms {
        iat_create_file,
        iat_write_file,
        iat_read_file,
        iat_close_handle,
        iat_get_std_handle,
        iat_exit_process,
        fname_rva,
        payload_rva,
        readbuf_rva,
        written_rva,
        nread_rva,
        ok_rva,
        fail_rva,
        payload_len,
    });

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
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, 3);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022);

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA_L + data_len as u32, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA_L);
    put_u32(&mut f, opt + 20, TEXT_RVA_L);
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
    put_u32(&mut f, dir(1), RDATA_RVA_L + import_dir_off);
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA_L + iat_off);
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA_L,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA_L,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    });
    write_section(&mut f, sec + 80, SecHeader {
        name: b".data",
        vsize: data_len as u32,
        vaddr: DATA_RVA_L,
        raw_size: 0,
        raw_ptr: 0,
        chars: 0xC000_0080,
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

struct FileioSyms {
    iat_create_file: u32,
    iat_write_file: u32,
    iat_read_file: u32,
    iat_close_handle: u32,
    iat_get_std_handle: u32,
    iat_exit_process: u32,
    fname_rva: u32,
    payload_rva: u32,
    readbuf_rva: u32,
    written_rva: u32,
    nread_rva: u32,
    ok_rva: u32,
    fail_rva: u32,
    payload_len: u32,
}

fn build_fileio_text(s: FileioSyms) -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    let mut c: Vec<u8> = Vec::new();

    fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
        c.extend_from_slice(prefix);
        let next_rva = TEXT_RVA_L as i64 + c.len() as i64 + 4;
        let disp = target_rva as i64 - next_rva;
        c.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]);

    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], s.iat_get_std_handle);
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    rip(&mut c, &[0x48, 0x8D, 0x0D], s.fname_rva);
    c.extend_from_slice(&[0xBA]);
    c.extend_from_slice(&0x4000_0000u32.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_create_file);
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(&mut c, &[0x48, 0x8D, 0x15], s.payload_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&s.payload_len.to_le_bytes());
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_write_file);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(&mut c, &[0xFF, 0x15], s.iat_close_handle);

    rip(&mut c, &[0x48, 0x8D, 0x0D], s.fname_rva);
    c.extend_from_slice(&[0xBA]);
    c.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_create_file);
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(&mut c, &[0x48, 0x8D, 0x15], s.readbuf_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&s.payload_len.to_le_bytes());
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.nread_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_read_file);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(&mut c, &[0xFF, 0x15], s.iat_close_handle);

    c.extend_from_slice(&[0x41, 0xBC, 0x2A, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x48, 0x8D, 0x3D], s.payload_rva);
    rip(&mut c, &[0x4C, 0x8D, 0x05], s.readbuf_rva);
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&s.payload_len.to_le_bytes());
    let loop_start = c.len();
    c.extend_from_slice(&[0x8A, 0x07]);
    c.extend_from_slice(&[0x41, 0x3A, 0x00]);
    c.extend_from_slice(&[0x75, 0x00]);
    let jne_fixup = c.len() - 1;
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]);
    c.extend_from_slice(&[0xFF, 0xC9]);
    c.extend_from_slice(&[0x75, 0x00]);
    let jnz_fixup = c.len() - 1;
    let after_loop = c.len();
    c[jnz_fixup] = ((loop_start as i64 - after_loop as i64) as i8) as u8;
    c.extend_from_slice(&[0xEB, 0x00]);
    let jmp_fixup = c.len() - 1;
    let mismatch_at = c.len();
    c.extend_from_slice(&[0x41, 0xBC, 0x01, 0x00, 0x00, 0x00]);
    let report_at = c.len();
    c[jne_fixup] = ((mismatch_at as i64 - (jne_fixup as i64 + 1)) as i8) as u8;
    c[jmp_fixup] = ((report_at as i64 - (jmp_fixup as i64 + 1)) as i8) as u8;

    c.extend_from_slice(&[0x41, 0x83, 0xFC, 0x2A]);
    c.extend_from_slice(&[0x75, 0x00]);
    let jne_fail_fixup = c.len() - 1;
    rip(&mut c, &[0x48, 0x8D, 0x15], s.ok_rva);
    c.extend_from_slice(&[0x41, 0xB8, 0x03, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xEB, 0x00]);
    let jmp_write_fixup = c.len() - 1;
    let fail_msg_at = c.len();
    c[jne_fail_fixup] = ((fail_msg_at as i64 - (jne_fail_fixup as i64 + 1)) as i8) as u8;
    rip(&mut c, &[0x48, 0x8D, 0x15], s.fail_rva);
    c.extend_from_slice(&[0x41, 0xB8, 0x05, 0x00, 0x00, 0x00]);
    let write_msg_at = c.len();
    c[jmp_write_fixup] = ((write_msg_at as i64 - (jmp_write_fixup as i64 + 1)) as i8) as u8;
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_write_file);

    c.extend_from_slice(&[0x44, 0x89, 0xE1]);
    rip(&mut c, &[0xFF, 0x15], s.iat_exit_process);
    c.push(0xCC);
    c
}

pub const COM_CLSID_STRING: &str = "{00000303-0000-0000-C000-000000000046}";

pub const COM_CLSID_BYTES: [u8; 16] = [
    0x03, 0x03, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub const COM_IID_IUNKNOWN_BYTES: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub const COM_INPROC_SERVER: &str = "ole32.dll";

pub const COM_OK_EXIT: i32 = 55;

pub const COM_OK_MESSAGE: &str = "COM OK\n";
pub const COM_FAIL_MESSAGE: &str = "COM FAIL\n";

pub const COM_LABEL_INIT: &str = "CoInitializeEx=";
pub const COM_LABEL_HR: &str = "CoCreateInstance=";
pub const COM_LABEL_REFS: &str = "AddRef=";

pub fn build_com() -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    const RDATA_RVA_L: u32 = 0x2000;
    const DATA_RVA_L: u32 = 0x3000;

    let punk_rva = DATA_RVA_L;
    let written_rva = DATA_RVA_L + 8;
    let hexbuf_rva = DATA_RVA_L + 0x10;
    let data_len = 0x20u32;

    let ole_names = ["CoInitializeEx", "CoCreateInstance", "CoUninitialize"];
    let k32_names = ["GetStdHandle", "WriteFile", "ExitProcess"];

    let import_dir_off = 0u32;
    let import_dir_size = 3 * 20u32;
    let thunks_ole = (ole_names.len() as u32 + 1) * 8;
    let thunks_k32 = (k32_names.len() as u32 + 1) * 8;
    let ilt_ole_off = import_dir_off + import_dir_size;
    let ilt_k32_off = ilt_ole_off + thunks_ole;
    let iat_ole_off = ilt_k32_off + thunks_k32;
    let iat_k32_off = iat_ole_off + thunks_ole;
    let iat_size = thunks_ole + thunks_k32;
    let mut pos = iat_k32_off + thunks_k32;

    let mut ibn_rva: Vec<u32> = Vec::new();
    for n in ole_names.iter().chain(k32_names.iter()) {
        pos = align_up_u32(pos, 2);
        ibn_rva.push(RDATA_RVA_L + pos);
        pos += 2 + n.len() as u32 + 1;
    }
    pos = align_up_u32(pos, 2);
    let ole_dllname_rva = RDATA_RVA_L + pos;
    let ole_dllname = b"ole32.dll\0";
    pos += ole_dllname.len() as u32;
    let k32_dllname_rva = RDATA_RVA_L + pos;
    let k32_dllname = b"kernel32.dll\0";
    pos += k32_dllname.len() as u32;

    pos = align_up_u32(pos, 16);
    let clsid_rva = RDATA_RVA_L + pos;
    pos += 16;
    let iid_rva = RDATA_RVA_L + pos;
    pos += 16;

    let strings: [&str; 5] = [
        COM_LABEL_INIT,
        COM_LABEL_HR,
        COM_LABEL_REFS,
        COM_OK_MESSAGE,
        COM_FAIL_MESSAGE,
    ];
    let mut str_rva = [0u32; 5];
    for (i, s) in strings.iter().enumerate() {
        str_rva[i] = RDATA_RVA_L + pos;
        pos += s.len() as u32;
    }

    let mut rd = vec![0u8; pos as usize];
    for (i, (dllname_rva, (ilt, iat))) in [
        (ole_dllname_rva, (ilt_ole_off, iat_ole_off)),
        (k32_dllname_rva, (ilt_k32_off, iat_k32_off)),
    ]
    .iter()
    .enumerate()
    {
        let d = import_dir_off as usize + i * 20;
        put_u32(&mut rd, d, RDATA_RVA_L + ilt);
        put_u32(&mut rd, d + 12, *dllname_rva);
        put_u32(&mut rd, d + 16, RDATA_RVA_L + iat);
    }
    for (i, &rva) in ibn_rva.iter().enumerate() {
        let (ilt, iat, slot) = if i < ole_names.len() {
            (ilt_ole_off, iat_ole_off, i)
        } else {
            (ilt_k32_off, iat_k32_off, i - ole_names.len())
        };
        put_u64(&mut rd, ilt as usize + slot * 8, rva as u64);
        put_u64(&mut rd, iat as usize + slot * 8, rva as u64);
    }
    for (i, n) in ole_names.iter().chain(k32_names.iter()).enumerate() {
        let off = (ibn_rva[i] - RDATA_RVA_L) as usize;
        rd[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
    }
    let o = (ole_dllname_rva - RDATA_RVA_L) as usize;
    rd[o..o + ole_dllname.len()].copy_from_slice(ole_dllname);
    let o = (k32_dllname_rva - RDATA_RVA_L) as usize;
    rd[o..o + k32_dllname.len()].copy_from_slice(k32_dllname);
    let o = (clsid_rva - RDATA_RVA_L) as usize;
    rd[o..o + 16].copy_from_slice(&COM_CLSID_BYTES);
    let o = (iid_rva - RDATA_RVA_L) as usize;
    rd[o..o + 16].copy_from_slice(&COM_IID_IUNKNOWN_BYTES);
    for (i, s) in strings.iter().enumerate() {
        let off = (str_rva[i] - RDATA_RVA_L) as usize;
        rd[off..off + s.len()].copy_from_slice(s.as_bytes());
    }

    let iat_slot = |base: u32, i: u32| RDATA_RVA_L + base + i * 8;
    let text = build_com_text(ComSyms {
        iat_co_initialize_ex: iat_slot(iat_ole_off, 0),
        iat_co_create_instance: iat_slot(iat_ole_off, 1),
        iat_co_uninitialize: iat_slot(iat_ole_off, 2),
        iat_get_std_handle: iat_slot(iat_k32_off, 0),
        iat_write_file: iat_slot(iat_k32_off, 1),
        iat_exit_process: iat_slot(iat_k32_off, 2),
        clsid_rva,
        iid_rva,
        punk_rva,
        written_rva,
        hexbuf_rva,
        label_init_rva: str_rva[0],
        label_hr_rva: str_rva[1],
        label_refs_rva: str_rva[2],
        ok_rva: str_rva[3],
        fail_rva: str_rva[4],
    });

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
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, 3);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022);

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA_L + data_len, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA_L);
    put_u32(&mut f, opt + 20, TEXT_RVA_L);
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
    put_u32(&mut f, dir(1), RDATA_RVA_L + import_dir_off);
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA_L + iat_ole_off);
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA_L,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA_L,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    });
    write_section(&mut f, sec + 80, SecHeader {
        name: b".data",
        vsize: data_len,
        vaddr: DATA_RVA_L,
        raw_size: 0,
        raw_ptr: 0,
        chars: 0xC000_0080,
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

struct ComSyms {
    iat_co_initialize_ex: u32,
    iat_co_create_instance: u32,
    iat_co_uninitialize: u32,
    iat_get_std_handle: u32,
    iat_write_file: u32,
    iat_exit_process: u32,
    clsid_rva: u32,
    iid_rva: u32,
    punk_rva: u32,
    written_rva: u32,
    hexbuf_rva: u32,
    label_init_rva: u32,
    label_hr_rva: u32,
    label_refs_rva: u32,
    ok_rva: u32,
    fail_rva: u32,
}

fn build_com_text(s: ComSyms) -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    let mut c: Vec<u8> = Vec::new();

    fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
        c.extend_from_slice(prefix);
        let next_rva = TEXT_RVA_L as i64 + c.len() as i64 + 4;
        let disp = target_rva as i64 - next_rva;
        c.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    fn write_str(c: &mut Vec<u8>, s: &ComSyms, buf_rva: u32, len: u32) {
        c.extend_from_slice(&[0x48, 0x89, 0xF1]);
        rip(c, &[0x48, 0x8D, 0x15], buf_rva);
        c.extend_from_slice(&[0x41, 0xB8]);
        c.extend_from_slice(&len.to_le_bytes());
        rip(c, &[0x4C, 0x8D, 0x0D], s.written_rva);
        c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
        rip(c, &[0xFF, 0x15], s.iat_write_file);
    }

    fn print_hex(c: &mut Vec<u8>, s: &ComSyms, label_rva: u32, label_len: u32) {
        c.extend_from_slice(&[0x89, 0xC3]);
        write_str(c, s, label_rva, label_len);
        rip(c, &[0x48, 0x8D, 0x3D], s.hexbuf_rva);
        c.extend_from_slice(&[0x89, 0xD8]);
        c.extend_from_slice(&[0xB9, 0x08, 0x00, 0x00, 0x00]);
        let loop_start = c.len();
        c.extend_from_slice(&[0xC1, 0xC0, 0x04]);
        c.extend_from_slice(&[0x89, 0xC2]);
        c.extend_from_slice(&[0x83, 0xE2, 0x0F]);
        c.extend_from_slice(&[0x80, 0xC2, 0x30]);
        c.extend_from_slice(&[0x80, 0xFA, 0x39]);
        c.extend_from_slice(&[0x76, 0x03]);
        c.extend_from_slice(&[0x80, 0xC2, 0x27]);
        c.extend_from_slice(&[0x88, 0x17]);
        c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
        c.extend_from_slice(&[0xFF, 0xC9]);
        c.extend_from_slice(&[0x75, 0x00]);
        let back = c.len();
        c[back - 1] = ((loop_start as i64 - back as i64) as i8) as u8;
        c.extend_from_slice(&[0xC6, 0x07, 0x0A]);
        write_str(c, s, s.hexbuf_rva, 9);
        c.extend_from_slice(&[0x89, 0xD8]);
    }

    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x68]);

    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], s.iat_get_std_handle);
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    c.extend_from_slice(&[0x31, 0xC9]);
    c.extend_from_slice(&[0x31, 0xD2]);
    rip(&mut c, &[0xFF, 0x15], s.iat_co_initialize_ex);
    print_hex(&mut c, &s, s.label_init_rva, COM_LABEL_INIT.len() as u32);

    rip(&mut c, &[0x48, 0x8D, 0x0D], s.clsid_rva);
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.iid_rva);
    rip(&mut c, &[0x48, 0x8D, 0x05], s.punk_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    rip(&mut c, &[0xFF, 0x15], s.iat_co_create_instance);
    c.extend_from_slice(&[0x41, 0x89, 0xC4]);
    print_hex(&mut c, &s, s.label_hr_rva, COM_LABEL_HR.len() as u32);

    c.extend_from_slice(&[0x45, 0x31, 0xF6]);
    c.extend_from_slice(&[0x45, 0x85, 0xE4]);
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    let jne_fail = c.len() - 4;
    rip(&mut c, &[0x48, 0x8B, 0x0D], s.punk_rva);
    c.extend_from_slice(&[0x48, 0x85, 0xC9]);
    c.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]);
    let je_fail = c.len() - 4;

    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    c.extend_from_slice(&[0xFF, 0x50, 0x08]);
    c.extend_from_slice(&[0x41, 0x89, 0xC6]);
    c.extend_from_slice(&[0x44, 0x89, 0xF0]);
    print_hex(&mut c, &s, s.label_refs_rva, COM_LABEL_REFS.len() as u32);

    for _ in 0..2 {
        rip(&mut c, &[0x48, 0x8B, 0x0D], s.punk_rva);
        c.extend_from_slice(&[0x48, 0x8B, 0x01]);
        c.extend_from_slice(&[0xFF, 0x50, 0x10]);
    }
    rip(&mut c, &[0xFF, 0x15], s.iat_co_uninitialize);

    c.extend_from_slice(&[0x41, 0x83, 0xFE, 0x02]);
    c.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]);
    let jb_fail = c.len() - 4;

    c.extend_from_slice(&[0x41, 0xBD]);
    c.extend_from_slice(&(COM_OK_EXIT as u32).to_le_bytes());
    write_str(&mut c, &s, s.ok_rva, COM_OK_MESSAGE.len() as u32);
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);
    let jmp_exit = c.len() - 4;

    let fail_at = c.len();
    for site in [jne_fail, je_fail, jb_fail] {
        let rel = (fail_at as i64 - (site as i64 + 4)) as i32;
        c[site..site + 4].copy_from_slice(&rel.to_le_bytes());
    }
    c.extend_from_slice(&[0x41, 0xBD, 0x01, 0x00, 0x00, 0x00]);
    write_str(&mut c, &s, s.fail_rva, COM_FAIL_MESSAGE.len() as u32);

    let exit_at = c.len();
    let rel = (exit_at as i64 - (jmp_exit as i64 + 4)) as i32;
    c[jmp_exit..jmp_exit + 4].copy_from_slice(&rel.to_le_bytes());
    c.extend_from_slice(&[0x44, 0x89, 0xE9]);
    rip(&mut c, &[0xFF, 0x15], s.iat_exit_process);
    c.push(0xCC);
    c
}

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat_get_std_handle: u32,
    iat_write_file: u32,
    iat_exit_process: u32,
    msg1_rva: u32,
    msg2_rva: u32,
    const_rva: [u32; 3],
}

impl Rdata {
    fn build() -> Rdata {
        let names = ["GetStdHandle", "WriteFile", "ExitProcess"];

        let import_dir_off = 0u32;
        let import_dir_size = 2 * 20;
        let ilt_off = import_dir_off + import_dir_size;
        let ilt_size = (names.len() as u32 + 1) * 8;
        let iat_off = ilt_off + ilt_size;
        let iat_size = ilt_size;

        let mut pos = iat_off + iat_size;

        let mut ibn_rva = Vec::new();
        for n in &names {
            pos = align_up_u32(pos, 2);
            ibn_rva.push(RDATA_RVA + pos);
            pos += 2 + n.len() as u32 + 1;
        }
        pos = align_up_u32(pos, 2);
        let dllname_rva = RDATA_RVA + pos;
        let dllname = b"kernel32.dll\0";
        pos += dllname.len() as u32;

        pos = align_up_u32(pos, 4);
        let msg1_rva = RDATA_RVA + pos;
        pos += SAMPLE_MESSAGE.len() as u32;
        let msg2_rva = RDATA_RVA + pos;
        pos += SAMPLE_SSE_PREFIX.len() as u32;

        pos = align_up_u32(pos, 8);
        let mut const_rva = [0u32; 3];
        for slot in &mut const_rva {
            *slot = RDATA_RVA + pos;
            pos += 8;
        }

        let mut b = vec![0u8; pos as usize];

        put_u32(&mut b, import_dir_off as usize, ilt_off + RDATA_RVA);
        put_u32(&mut b, import_dir_off as usize + 12, dllname_rva);
        put_u32(&mut b, import_dir_off as usize + 16, iat_off + RDATA_RVA);

        for (i, &rva) in ibn_rva.iter().enumerate() {
            put_u64(&mut b, (ilt_off as usize) + i * 8, rva as u64);
            put_u64(&mut b, (iat_off as usize) + i * 8, rva as u64);
        }

        for (i, n) in names.iter().enumerate() {
            let off = (ibn_rva[i] - RDATA_RVA) as usize;
            b[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
        }

        let doff = (dllname_rva - RDATA_RVA) as usize;
        b[doff..doff + dllname.len()].copy_from_slice(dllname);
        let m1 = (msg1_rva - RDATA_RVA) as usize;
        b[m1..m1 + SAMPLE_MESSAGE.len()].copy_from_slice(SAMPLE_MESSAGE.as_bytes());
        let m2 = (msg2_rva - RDATA_RVA) as usize;
        b[m2..m2 + SAMPLE_SSE_PREFIX.len()].copy_from_slice(SAMPLE_SSE_PREFIX.as_bytes());
        for (i, c) in SSE_CONSTS.iter().enumerate() {
            let off = (const_rva[i] - RDATA_RVA) as usize;
            b[off..off + 8].copy_from_slice(&c.to_bits().to_le_bytes());
        }

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat_get_std_handle: iat_off + RDATA_RVA,
            iat_write_file: iat_off + RDATA_RVA + 8,
            iat_exit_process: iat_off + RDATA_RVA + 16,
            msg1_rva,
            msg2_rva,
            const_rva,
        }
    }
}

fn build_text(rdata: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    emit_rip(&mut c, &[0xFF, 0x15], rdata.iat_get_std_handle);
    c.extend_from_slice(&[0x48, 0x89, 0xC3]);

    emit_write(&mut c, rdata, LenSrc::Rva(rdata.msg1_rva, SAMPLE_MESSAGE.len() as u32));

    emit_rip(&mut c, &[0xF2, 0x0F, 0x10, 0x05], rdata.const_rva[0]);
    emit_rip(&mut c, &[0xF2, 0x0F, 0x58, 0x05], rdata.const_rva[1]);
    emit_rip(&mut c, &[0xF2, 0x0F, 0x59, 0x05], rdata.const_rva[2]);
    c.extend_from_slice(&[0xF2, 0x0F, 0x2C, 0xC0]);

    c.extend_from_slice(&[0x04, 0x30]);
    c.extend_from_slice(&[0x88, 0x44, 0x24, 0x30]);
    c.extend_from_slice(&[0xC6, 0x44, 0x24, 0x31, 0x0A]);

    emit_write(&mut c, rdata, LenSrc::Rva(rdata.msg2_rva, SAMPLE_SSE_PREFIX.len() as u32));

    emit_write(&mut c, rdata, LenSrc::Stack);

    c.extend_from_slice(&[0x31, 0xC9]);
    emit_rip(&mut c, &[0xFF, 0x15], rdata.iat_exit_process);
    c.push(0xCC);

    c
}

enum LenSrc {
    Rva(u32, u32),
    Stack,
}

fn emit_write(c: &mut Vec<u8>, rdata: &Rdata, src: LenSrc) {
    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let len = match src {
        LenSrc::Rva(rva, len) => {
            emit_rip(c, &[0x48, 0x8D, 0x15], rva);
            len
        }
        LenSrc::Stack => {
            c.extend_from_slice(&[0x48, 0x8D, 0x54, 0x24, 0x30]);
            2
        }
    };
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&len.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    emit_rip(c, &[0xFF, 0x15], rdata.iat_write_file);
}

fn emit_rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = target_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
}

struct SecHeader<'a> {
    name: &'a [u8],
    vsize: u32,
    vaddr: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
}

fn write_section(f: &mut [u8], at: usize, s: SecHeader) {
    f[at..at + s.name.len()].copy_from_slice(s.name);
    put_u32(f, at + 8, s.vsize);
    put_u32(f, at + 12, s.vaddr);
    put_u32(f, at + 16, s.raw_size);
    put_u32(f, at + 20, s.raw_ptr);
    put_u32(f, at + 36, s.chars);
}

#[inline]
fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}
#[inline]
fn align_up_u32(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}
