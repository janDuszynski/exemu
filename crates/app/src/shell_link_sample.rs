use std::collections::HashMap;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const MAX_PATH: u32 = 260;

pub const CLSID_SHELL_LINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
pub const IID_ISHELL_LINK_W: [u8; 16] = [
    0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub const IID_IPERSIST_FILE: [u8; 16] = [
    0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub const LABELS: [&str; 7] =
    ["COINIT=", "CREATE=", "GETPATH=", "SETPATH=", "GETPATH2=", "QIPERSIST=", "SAVE="];
pub const PATH_TAG: &str = "PATH=";
pub const PATH2_TAG: &str = "PATH2=";

pub const TARGET_PATH: &str = "C:\\Windows\\system32\\notepad.exe";

pub const LNK_PATH: &str =
    "C:\\Users\\exemu\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\exemu Test.lnk";

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
        ("ole32.dll", vec!["CoInitializeEx", "CoCreateInstance", "CoUninitialize"]),
        ("kernel32.dll", vec!["GetStdHandle", "WriteFile", "ExitProcess"]),
    ]
}

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat: HashMap<String, u32>,
    clsid_shelllink_rva: u32,
    iid_shelllinkw_rva: u32,
    iid_persistfile_rva: u32,
    label_rva: [u32; 7],
    label_len: [u32; 7],
    path_tag_rva: u32,
    path_tag_len: u32,
    path2_tag_rva: u32,
    path2_tag_len: u32,
    target_w_rva: u32,
    lnk_w_rva: u32,
    punk_shelllink_rva: u32,
    punk_persistfile_rva: u32,
    wbuf_getpath_rva: u32,
    abuf_rva: u32,
    written_rva: u32,
    hexbuf_rva: u32,
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

        pos = align_up_u32(pos, 16);
        let clsid_shelllink_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_shelllinkw_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_persistfile_rva = RDATA_RVA + pos;
        pos += 16;

        let mut label_rva = [0u32; 7];
        let mut label_len = [0u32; 7];
        for (i, s) in LABELS.iter().enumerate() {
            label_rva[i] = RDATA_RVA + pos;
            label_len[i] = s.len() as u32;
            pos += s.len() as u32;
        }
        let path_tag_rva = RDATA_RVA + pos;
        let path_tag_len = PATH_TAG.len() as u32;
        pos += path_tag_len;
        let path2_tag_rva = RDATA_RVA + pos;
        let path2_tag_len = PATH2_TAG.len() as u32;
        pos += path2_tag_len;

        pos = align_up_u32(pos, 2);
        let target_w_rva = RDATA_RVA + pos;
        pos += (TARGET_PATH.chars().count() as u32 + 1) * 2;
        let lnk_w_rva = RDATA_RVA + pos;
        pos += (LNK_PATH.chars().count() as u32 + 1) * 2;

        let mut b = vec![0u8; pos as usize];

        let mut iat = HashMap::new();
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
        for (rva, guid) in [
            (clsid_shelllink_rva, &CLSID_SHELL_LINK),
            (iid_shelllinkw_rva, &IID_ISHELL_LINK_W),
            (iid_persistfile_rva, &IID_IPERSIST_FILE),
        ] {
            let off = (rva - RDATA_RVA) as usize;
            b[off..off + 16].copy_from_slice(guid);
        }
        for (i, s) in LABELS.iter().enumerate() {
            let off = (label_rva[i] - RDATA_RVA) as usize;
            b[off..off + s.len()].copy_from_slice(s.as_bytes());
        }
        for (rva, tag) in [(path_tag_rva, PATH_TAG), (path2_tag_rva, PATH2_TAG)] {
            let off = (rva - RDATA_RVA) as usize;
            b[off..off + tag.len()].copy_from_slice(tag.as_bytes());
        }
        put_utf16(&mut b, (target_w_rva - RDATA_RVA) as usize, TARGET_PATH);
        put_utf16(&mut b, (lnk_w_rva - RDATA_RVA) as usize, LNK_PATH);

        let punk_shelllink_rva = DATA_RVA;
        let punk_persistfile_rva = punk_shelllink_rva + 8;
        let wbuf_getpath_rva = punk_persistfile_rva + 8;
        let abuf_rva = wbuf_getpath_rva + MAX_PATH * 2 + 8;
        let written_rva = align_up_u32(abuf_rva + MAX_PATH + 16, 8);
        let hexbuf_rva = written_rva + 8;
        let data_len = hexbuf_rva + 16 - DATA_RVA;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            clsid_shelllink_rva,
            iid_shelllinkw_rva,
            iid_persistfile_rva,
            label_rva,
            label_len,
            path_tag_rva,
            path_tag_len,
            path2_tag_rva,
            path2_tag_len,
            target_w_rva,
            lnk_w_rva,
            punk_shelllink_rva,
            punk_persistfile_rva,
            wbuf_getpath_rva,
            abuf_rva,
            written_rva,
            hexbuf_rva,
            data_len,
        }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }
}

const FRAME: u32 = 0x38;

const VT_QUERY_INTERFACE: u32 = 0x00;
const VT_RELEASE: u32 = 0x10;
const VT_SLW_GET_PATH: u32 = 0x18;
const VT_SLW_SET_PATH: u32 = 0xA0;
const VT_PF_SAVE: u32 = 0x30;

fn build_text(r: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME as u8]);

    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    c.extend_from_slice(&[0x45, 0x31, 0xED]);

    c.extend_from_slice(&[0x31, 0xC9]);
    c.extend_from_slice(&[0xBA, 0x02, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], r.slot("CoInitializeEx"));
    print_hex(&mut c, r, 0);
    fail_unless_zero(&mut c);

    rip(&mut c, &[0x48, 0x8D, 0x0D], r.clsid_shelllink_rva);
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x4C, 0x8D, 0x0D], r.iid_shelllinkw_rva);
    rip(&mut c, &[0x48, 0x8D, 0x05], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    rip(&mut c, &[0xFF, 0x15], r.slot("CoCreateInstance"));
    print_hex(&mut c, r, 1);
    fail_unless_zero(&mut c);

    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x85, 0xC9]);
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    let jne_have_sl = c.len() - 4;
    c.extend_from_slice(&[0x41, 0x83, 0xC5, 5]);
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);
    let jmp_after_sl = c.len() - 4;

    let have_sl = c.len();
    patch_rel32(&mut c, jne_have_sl, have_sl);

    rip_imm16(&mut c, &[0x66, 0xC7, 0x05], r.wbuf_getpath_rva, 0);
    rip(&mut c, &[0x48, 0x8D, 0x15], r.wbuf_getpath_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&MAX_PATH.to_le_bytes());
    c.extend_from_slice(&[0x4D, 0x31, 0xC9]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_SLW_GET_PATH);
    print_hex(&mut c, r, 2);
    c.extend_from_slice(&[0x83, 0xF8, 0x01]);
    c.extend_from_slice(&[0x76, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);

    emit_report(&mut c, r.path_tag_rva, r.path_tag_len, r.wbuf_getpath_rva, r.abuf_rva, r.written_rva, r.slot("WriteFile"));

    rip(&mut c, &[0x48, 0x8D, 0x15], r.target_w_rva);
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_SLW_SET_PATH);
    print_hex(&mut c, r, 3);
    fail_unless_zero(&mut c);

    rip_imm16(&mut c, &[0x66, 0xC7, 0x05], r.wbuf_getpath_rva, 0);
    rip(&mut c, &[0x48, 0x8D, 0x15], r.wbuf_getpath_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&MAX_PATH.to_le_bytes());
    c.extend_from_slice(&[0x4D, 0x31, 0xC9]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_SLW_GET_PATH);
    print_hex(&mut c, r, 4);
    fail_unless_zero(&mut c);
    emit_report(&mut c, r.path2_tag_rva, r.path2_tag_len, r.wbuf_getpath_rva, r.abuf_rva, r.written_rva, r.slot("WriteFile"));

    rip(&mut c, &[0x48, 0x8D, 0x15], r.iid_persistfile_rva);
    rip(&mut c, &[0x4C, 0x8D, 0x05], r.punk_persistfile_rva);
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_QUERY_INTERFACE);
    print_hex(&mut c, r, 5);
    fail_unless_zero(&mut c);

    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_persistfile_rva);
    c.extend_from_slice(&[0x48, 0x85, 0xC9]);
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    let jne_have_pf = c.len() - 4;
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]);
    let jmp_after_pf = c.len() - 4;
    let have_pf = c.len();
    patch_rel32(&mut c, jne_have_pf, have_pf);

    rip(&mut c, &[0x48, 0x8D, 0x15], r.lnk_w_rva);
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_persistfile_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_PF_SAVE);
    print_hex(&mut c, r, 6);
    fail_unless_zero(&mut c);

    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_persistfile_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_RELEASE);

    let after_pf = c.len();
    patch_rel32(&mut c, jmp_after_pf, after_pf);

    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_RELEASE);

    let after_sl = c.len();
    patch_rel32(&mut c, jmp_after_sl, after_sl);

    rip(&mut c, &[0xFF, 0x15], r.slot("CoUninitialize"));

    c.extend_from_slice(&[0x44, 0x89, 0xE9]);
    rip(&mut c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC);
    c
}

fn call_vtbl(c: &mut Vec<u8>, offset: u32) {
    if offset == 0 {
        c.extend_from_slice(&[0xFF, 0x10]);
    } else if offset < 0x80 {
        c.extend_from_slice(&[0xFF, 0x50, offset as u8]);
    } else {
        c.extend_from_slice(&[0xFF, 0x90]);
        c.extend_from_slice(&offset.to_le_bytes());
    }
}

fn fail_unless_zero(c: &mut Vec<u8>) {
    c.extend_from_slice(&[0x85, 0xC0]);
    c.extend_from_slice(&[0x74, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
}

fn patch_rel32(c: &mut [u8], site: usize, target: usize) {
    let rel = (target as i64 - (site as i64 + 4)) as i32;
    c[site..site + 4].copy_from_slice(&rel.to_le_bytes());
}

fn print_hex(c: &mut Vec<u8>, r: &Rdata, label_index: usize) {
    c.extend_from_slice(&[0x89, 0xC3]);
    write_str(c, r, r.label_rva[label_index], r.label_len[label_index]);
    rip(c, &[0x48, 0x8D, 0x3D], r.hexbuf_rva);
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
    write_str(c, r, r.hexbuf_rva, 9);
    c.extend_from_slice(&[0x89, 0xD8]);
}

fn write_str(c: &mut Vec<u8>, r: &Rdata, buf_rva: u32, len: u32) {
    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x48, 0x8D, 0x15], buf_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&len.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

#[allow(clippy::too_many_arguments)]
fn emit_report(c: &mut Vec<u8>, tag_rva: u32, tag_len: u32, wbuf_rva: u32, abuf_rva: u32, written_rva: u32, iat_write_file: u32) {
    rip(c, &[0x4C, 0x8D, 0x35], abuf_rva);
    rip(c, &[0x48, 0x8D, 0x3D], tag_rva);
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&tag_len.to_le_bytes());
    let tag_loop = c.len();
    c.extend_from_slice(&[0x8A, 0x07]);
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0xFF, 0xC9]);
    c.extend_from_slice(&[0x75, 0x00]);
    let at = c.len();
    let fix = at - 1;
    c[fix] = ((tag_loop as i64 - at as i64) as i8) as u8;

    rip(c, &[0x48, 0x8D, 0x3D], wbuf_rva);
    let sq_loop = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]);
    c.extend_from_slice(&[0x66, 0x85, 0xC0]);
    c.extend_from_slice(&[0x74, 0x00]);
    let sq_done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]);
    c.extend_from_slice(&[0xEB, 0x00]);
    let back = c.len();
    c[back - 1] = ((sq_loop as i64 - back as i64) as i8) as u8;
    let sq_done = c.len();
    c[sq_done_fix] = ((sq_done as i64 - (sq_done_fix as i64 + 1)) as i8) as u8;

    c.extend_from_slice(&[0x41, 0xC6, 0x06, 0x0A]);
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]);
    c.extend_from_slice(&[0x4C, 0x89, 0xF0]);
    rip(c, &[0x48, 0x8D, 0x15], abuf_rva);
    c.extend_from_slice(&[0x48, 0x29, 0xD0]);
    c.extend_from_slice(&[0x41, 0x89, 0xC0]);

    c.extend_from_slice(&[0x48, 0x89, 0xF1]);
    rip(c, &[0x4C, 0x8D, 0x0D], written_rva);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(c, &[0xFF, 0x15], iat_write_file);
}

fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

fn rip_imm16(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u16) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 2;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
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
fn put_utf16(f: &mut [u8], at: usize, s: &str) {
    let mut o = at;
    for u in s.encode_utf16() {
        put_u16(f, o, u);
        o += 2;
    }
    put_u16(f, o, 0);
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
    fn shell_link_sample_is_a_pe_importing_ole32() {
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
        for sym in ["CoInitializeEx", "CoCreateInstance", "CoUninitialize"] {
            assert!(has("ole32.dll", sym), "imports ole32!{sym}");
        }
        for sym in ["GetStdHandle", "WriteFile", "ExitProcess"] {
            assert!(has("kernel32.dll", sym), "imports kernel32!{sym}");
        }

        for label in LABELS {
            assert!(
                exe.windows(label.len()).any(|w| w == label.as_bytes()),
                "the {label} tag is in the image"
            );
        }
        assert!(exe.windows(CLSID_SHELL_LINK.len()).any(|w| w == CLSID_SHELL_LINK), "CLSID_ShellLink bytes present");
        assert!(exe.windows(IID_ISHELL_LINK_W.len()).any(|w| w == IID_ISHELL_LINK_W), "IID_IShellLinkW bytes present");
    }
}
