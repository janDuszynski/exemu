const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const TEXT_MAX: usize = (RDATA_RVA - TEXT_RVA) as usize;

pub const CHILD_EXIT: i32 = 91;
pub const PARENT_OK_EXIT: i32 = 76;

pub const CHILD_MESSAGE: &str = "CHILD: exemu W3.5 — this line came from a second guest process\n";

pub const OK_MESSAGE: &str = "SPAWN OK\n";
pub const FAIL_MESSAGE: &str = "SPAWN FAIL\n";

pub const LABEL_CREATED: &str = "CREATED=";
pub const LABEL_PID: &str = "PID=";
pub const LABEL_WAIT: &str = "WAIT=";
pub const LABEL_GETEXIT: &str = "GETEXIT=";
pub const LABEL_CHILDEXIT: &str = "CHILDEXIT=";

const LABELS: [&str; 5] = [LABEL_CREATED, LABEL_PID, LABEL_WAIT, LABEL_GETEXIT, LABEL_CHILDEXIT];

const STD_OUTPUT_HANDLE: i32 = -11;
const SIZEOF_STARTUPINFOW: u32 = 0x68;
const LINE_CAP: u32 = 256;

pub fn build_child() -> Vec<u8> {
    let r = Rdata::build(Role::Child { child_path: String::new() });
    let (text, entry_off) = build_child_text(&r);
    assemble(&r, &text, entry_off)
}

pub fn build_parent(child_path: &str) -> Vec<u8> {
    let r = Rdata::build(Role::Parent { child_path: child_path.to_string() });
    let (text, entry_off) = build_parent_text(&r);
    assemble(&r, &text, entry_off)
}

enum Role {
    Child { child_path: String },
    Parent { child_path: String },
}

impl Role {
    fn is_parent(&self) -> bool {
        matches!(self, Role::Parent { .. })
    }
    fn child_path(&self) -> &str {
        match self {
            Role::Child { child_path } | Role::Parent { child_path } => child_path,
        }
    }
}

fn assemble(r: &Rdata, text: &[u8], entry_off: u32) -> Vec<u8> {
    assert!(
        text.len() <= TEXT_MAX,
        ".text ({} bytes) outgrew the {TEXT_MAX}-byte gap to .rdata",
        text.len()
    );

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
    let image_size = align_up_u32(r.data_rva + r.data_len, SECTION_ALIGN);
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
    put_u32(&mut f, dir(1), RDATA_RVA + r.import_dir_off);
    put_u32(&mut f, dir(1) + 4, r.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + r.iat_off);
    put_u32(&mut f, dir(12) + 4, r.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", r.bytes.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", r.data_len, r.data_rva, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(text);
    f[rdata_ptr..rdata_ptr + r.bytes.len()].copy_from_slice(&r.bytes);
    f
}

fn import_plan(role: &Role) -> Vec<(&'static str, Vec<&'static str>)> {
    let mut funcs = vec!["GetStdHandle", "WriteFile", "ExitProcess"];
    if role.is_parent() {
        funcs.extend_from_slice(&[
            "CreateProcessW",
            "WaitForSingleObject",
            "GetExitCodeProcess",
            "CloseHandle",
        ]);
    }
    vec![("kernel32.dll", funcs)]
}

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat: std::collections::HashMap<String, u32>,

    label_rva: [u32; 5],
    label_len: [u32; 5],
    ok_rva: u32,
    fail_rva: u32,
    message_rva: u32,
    message_len: u32,
    child_path_rva: u32,
    child_path_bytes: u32,

    data_rva: u32,
    cmdline_rva: u32,
    startup_rva: u32,
    procinfo_rva: u32,
    exitcode_rva: u32,
    line_rva: u32,
    written_rva: u32,
    data_len: u32,
}

impl Rdata {
    fn build(role: Role) -> Rdata {
        let plan = import_plan(&role);
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

        let mut label_rva = [0u32; 5];
        let mut label_len = [0u32; 5];
        for (i, l) in LABELS.iter().enumerate() {
            label_rva[i] = RDATA_RVA + pos;
            label_len[i] = l.len() as u32;
            pos += l.len() as u32;
        }
        let ok_rva = RDATA_RVA + pos;
        pos += OK_MESSAGE.len() as u32;
        let fail_rva = RDATA_RVA + pos;
        pos += FAIL_MESSAGE.len() as u32;
        let message_rva = RDATA_RVA + pos;
        let message_len = CHILD_MESSAGE.len() as u32;
        pos += message_len;

        pos = align_up_u32(pos, 2);
        let child_path_rva = RDATA_RVA + pos;
        let child_path_bytes = (role.child_path().encode_utf16().count() as u32 + 1) * 2;
        pos += child_path_bytes;

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

        let put = |b: &mut Vec<u8>, rva: u32, bytes: &[u8]| {
            let off = (rva - RDATA_RVA) as usize;
            b[off..off + bytes.len()].copy_from_slice(bytes);
        };
        for (i, l) in LABELS.iter().enumerate() {
            put(&mut b, label_rva[i], l.as_bytes());
        }
        put(&mut b, ok_rva, OK_MESSAGE.as_bytes());
        put(&mut b, fail_rva, FAIL_MESSAGE.as_bytes());
        put(&mut b, message_rva, CHILD_MESSAGE.as_bytes());
        let mut wide: Vec<u8> = Vec::new();
        for u in role.child_path().encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        put(&mut b, child_path_rva, &wide);

        let data_rva = align_up_u32(RDATA_RVA + pos, SECTION_ALIGN);
        let mut d = data_rva;
        let mut cell = |n: u32| -> u32 {
            let r = d;
            d += align_up_u32(n, 8);
            r
        };
        let cmdline_rva = cell(child_path_bytes.max(8) + 8);
        let startup_rva = cell(SIZEOF_STARTUPINFOW + 8);
        let procinfo_rva = cell(0x20);
        let exitcode_rva = cell(8);
        let line_rva = cell(LINE_CAP);
        let written_rva = cell(16);
        let data_len = d - data_rva;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            label_rva,
            label_len,
            ok_rva,
            fail_rva,
            message_rva,
            message_len,
            child_path_rva,
            child_path_bytes,
            data_rva,
            cmdline_rva,
            startup_rva,
            procinfo_rva,
            exitcode_rva,
            line_rva,
            written_rva,
            data_len,
        }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }
}

const FRAME: u8 = 0x58;
const HELPER_FRAME: u8 = 0x38;

fn build_child_text(r: &Rdata) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();
    let puts = c.len() as u32;
    emit_puts(&mut c, r);
    let entry_off = c.len() as u32;
    emit_child_entry(&mut c, r, puts);
    (c, entry_off)
}

fn build_parent_text(r: &Rdata) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();
    let report = c.len() as u32;
    emit_report(&mut c, r);
    let puts = c.len() as u32;
    emit_puts(&mut c, r);
    let entry_off = c.len() as u32;
    emit_parent_entry(&mut c, r, report, puts);
    (c, entry_off)
}

fn emit_child_entry(c: &mut Vec<u8>, r: &Rdata, puts: u32) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, HELPER_FRAME]);
    c.push(0xB9);
    c.extend_from_slice(&STD_OUTPUT_HANDLE.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);
    rip(c, &[0x48, 0x8D, 0x15], r.message_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.message_len.to_le_bytes());
    call_rel(c, puts);
    c.push(0xB9);
    c.extend_from_slice(&CHILD_EXIT.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC);
}

fn emit_parent_entry(c: &mut Vec<u8>, r: &Rdata, report: u32, puts: u32) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME]);
    c.extend_from_slice(&[0x45, 0x31, 0xE4]);

    c.push(0xB9);
    c.extend_from_slice(&STD_OUTPUT_HANDLE.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    rip(c, &[0x4C, 0x8D, 0x15], r.cmdline_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.child_path_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.child_path_bytes.to_le_bytes());
    emit_copy_loop(c);

    rip(c, &[0x48, 0x8D, 0x05], r.startup_rva);
    c.extend_from_slice(&[0xC7, 0x00]);
    c.extend_from_slice(&SIZEOF_STARTUPINFOW.to_le_bytes());

    rip(c, &[0x48, 0x8D, 0x0D], r.child_path_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.cmdline_rva);
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    store_imm64(c, 0x20, 1);
    store_imm64(c, 0x28, 0);
    store_imm64(c, 0x30, 0);
    store_imm64(c, 0x38, 0);
    rip(c, &[0x48, 0x8D, 0x05], r.startup_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x40]);
    rip(c, &[0x48, 0x8D, 0x05], r.procinfo_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x48]);
    rip(c, &[0xFF, 0x15], r.slot("CreateProcessW"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]);
    emit_report_call(c, r, report, 0);

    c.extend_from_slice(&[0x45, 0x85, 0xED]);
    let created = jcc8(c, 0x75);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    let to_verdict = jmp32(c);
    patch8(c, created);

    rip(c, &[0x48, 0x8D, 0x05], r.procinfo_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x18]);
    c.extend_from_slice(&[0x4C, 0x8B, 0x70, 0x08]);
    c.extend_from_slice(&[0x44, 0x8B, 0x68, 0x10]);
    emit_report_call(c, r, report, 1);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    c.push(0xBA);
    c.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("WaitForSingleObject"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]);
    emit_report_call(c, r, report, 2);
    c.extend_from_slice(&[0x45, 0x85, 0xED]);
    let waited = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    patch8(c, waited);

    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0x48, 0x8D, 0x15], r.exitcode_rva);
    rip(c, &[0xFF, 0x15], r.slot("GetExitCodeProcess"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]);
    emit_report_call(c, r, report, 3);
    c.extend_from_slice(&[0x45, 0x85, 0xED]);
    let got = jcc8(c, 0x75);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    patch8(c, got);

    rip(c, &[0x48, 0x8D, 0x05], r.exitcode_rva);
    c.extend_from_slice(&[0x44, 0x8B, 0x28]);
    emit_report_call(c, r, report, 4);
    c.extend_from_slice(&[0x41, 0x81, 0xFD]);
    c.extend_from_slice(&CHILD_EXIT.to_le_bytes());
    let code_ok = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    patch8(c, code_ok);

    c.extend_from_slice(&[0x4C, 0x89, 0xF1]);
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xD9]);
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));

    patch32(c, to_verdict);
    c.extend_from_slice(&[0x45, 0x85, 0xE4]);
    let failed = jcc8(c, 0x75);
    rip(c, &[0x48, 0x8D, 0x15], r.ok_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(OK_MESSAGE.len() as u32).to_le_bytes());
    call_rel(c, puts);
    c.push(0xB9);
    c.extend_from_slice(&PARENT_OK_EXIT.to_le_bytes());
    let exit = jcc8(c, 0xEB);
    patch8(c, failed);
    rip(c, &[0x48, 0x8D, 0x15], r.fail_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(FAIL_MESSAGE.len() as u32).to_le_bytes());
    call_rel(c, puts);
    c.extend_from_slice(&[0x44, 0x89, 0xE1]);
    patch8(c, exit);
    rip(c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC);
}

fn emit_report(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, HELPER_FRAME]);
    c.extend_from_slice(&[0x49, 0x89, 0xCB]);
    rip(c, &[0x4C, 0x8D, 0x15], r.line_rva);
    emit_copy_loop(c);

    c.extend_from_slice(&[0x41, 0xB9, 0x10, 0x00, 0x00, 0x00]);
    let hex_top = c.len();
    c.extend_from_slice(&[0x4C, 0x89, 0xD8]);
    c.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x3C]);
    c.extend_from_slice(&[0x83, 0xE0, 0x0F]);
    c.extend_from_slice(&[0x3C, 0x0A]);
    let jb_digit = jcc8(c, 0x72);
    c.extend_from_slice(&[0x04, 0x57]);
    let jmp_put = jcc8(c, 0xEB);
    patch8(c, jb_digit);
    c.extend_from_slice(&[0x04, 0x30]);
    patch8(c, jmp_put);
    c.extend_from_slice(&[0x41, 0x88, 0x02]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]);
    c.extend_from_slice(&[0x49, 0xC1, 0xE3, 0x04]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC9]);
    jmp_back(c, 0x75, hex_top);

    emit_flush_line(c, r);
    c.extend_from_slice(&[0x48, 0x83, 0xC4, HELPER_FRAME]);
    c.push(0xC3);
}

fn emit_puts(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, HELPER_FRAME]);
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
    c.extend_from_slice(&[0x48, 0x83, 0xC4, HELPER_FRAME]);
    c.push(0xC3);
}

fn emit_copy_loop(c: &mut Vec<u8>) {
    let top = c.len();
    c.extend_from_slice(&[0x45, 0x85, 0xC0]);
    let jz_done = jcc8(c, 0x74);
    c.extend_from_slice(&[0x8A, 0x02]);
    c.extend_from_slice(&[0x41, 0x88, 0x02]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC2]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC8]);
    jmp_back(c, 0xEB, top);
    patch8(c, jz_done);
}

fn emit_flush_line(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x41, 0xC6, 0x02, 0x0A]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]);
    rip(c, &[0x48, 0x8D, 0x15], r.line_rva);
    c.extend_from_slice(&[0x4C, 0x89, 0xD0]);
    c.extend_from_slice(&[0x48, 0x29, 0xD0]);
    c.extend_from_slice(&[0x41, 0x89, 0xC0]);
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

fn emit_report_call(c: &mut Vec<u8>, r: &Rdata, report: u32, i: usize) {
    c.extend_from_slice(&[0x44, 0x89, 0xE9]);
    rip(c, &[0x48, 0x8D, 0x15], r.label_rva[i]);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.label_len[i].to_le_bytes());
    call_rel(c, report);
}

fn store_imm64(c: &mut Vec<u8>, disp: u8, imm: i32) {
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, disp]);
    c.extend_from_slice(&imm.to_le_bytes());
}

fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

fn call_rel(c: &mut Vec<u8>, target_off: u32) {
    c.push(0xE8);
    let next = c.len() as i64 + 4;
    c.extend_from_slice(&((target_off as i64 - next) as i32).to_le_bytes());
}

fn jcc8(c: &mut Vec<u8>, op: u8) -> usize {
    c.push(op);
    c.push(0);
    c.len() - 1
}

fn patch8(c: &mut [u8], at: usize) {
    let rel = c.len() as i64 - (at as i64 + 1);
    assert!((-128..=127).contains(&rel), "short jump out of range ({rel})");
    c[at] = rel as i8 as u8;
}

fn jmp32(c: &mut Vec<u8>) -> usize {
    c.push(0xE9);
    let at = c.len();
    c.extend_from_slice(&0i32.to_le_bytes());
    at
}

fn patch32(c: &mut [u8], at: usize) {
    let rel = (c.len() as i64 - (at as i64 + 4)) as i32;
    c[at..at + 4].copy_from_slice(&rel.to_le_bytes());
}

fn jmp_back(c: &mut Vec<u8>, op: u8, target: usize) {
    c.push(op);
    c.push(0);
    let at = c.len() - 1;
    let rel = target as i64 - c.len() as i64;
    assert!((-128..=127).contains(&rel), "short jump out of range ({rel})");
    c[at] = rel as i8 as u8;
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
    fn the_pair_are_pes_importing_the_process_api() {
        let child = build_child();
        let parent = build_parent("C:\\exemu-child.exe");
        for exe in [&child, &parent] {
            let image = exemu_loader::parse(exe).expect("parses as PE32+");
            assert!(image.is_64bit);
            assert_eq!(image.subsystem, 3, "console subsystem");
        }
        let image = exemu_loader::parse(&parent).unwrap();
        let has = |sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case("kernel32.dll")
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        for sym in [
            "CreateProcessW",
            "WaitForSingleObject",
            "GetExitCodeProcess",
            "CloseHandle",
            "GetStdHandle",
            "WriteFile",
            "ExitProcess",
        ] {
            assert!(has(sym), "the parent imports kernel32!{sym}");
        }
        let child_image = exemu_loader::parse(&child).unwrap();
        assert!(
            !child_image.imports.iter().any(|i| matches!(
                &i.symbol,
                exemu_core::ImportSymbol::Named(n) if n == "CreateProcessW"
            )),
            "the child must not import CreateProcessW"
        );
    }

    #[test]
    fn the_child_path_is_embedded_as_utf16() {
        let parent = build_parent("C:\\exemu-child.exe");
        let mut wide: Vec<u8> = Vec::new();
        for u in "C:\\exemu-child.exe".encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        assert!(
            parent.windows(wide.len()).any(|w| w == wide),
            "the UTF-16 child path is in the parent image"
        );
    }

    #[test]
    fn the_reported_labels_are_embedded() {
        let parent = build_parent("C:\\x.exe");
        for l in LABELS {
            assert!(parent.windows(l.len()).any(|w| w == l.as_bytes()), "{l} is in the image");
        }
        assert!(parent.windows(OK_MESSAGE.len()).any(|w| w == OK_MESSAGE.as_bytes()));
        assert!(parent.windows(FAIL_MESSAGE.len()).any(|w| w == FAIL_MESSAGE.as_bytes()));
        let child = build_child();
        assert!(child.windows(CHILD_MESSAGE.len()).any(|w| w == CHILD_MESSAGE.as_bytes()));
    }
}
