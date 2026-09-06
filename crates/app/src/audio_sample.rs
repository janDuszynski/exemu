const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const TEXT_MAX: usize = (RDATA_RVA - TEXT_RVA) as usize;

pub const AUDIO_OK_EXIT: i32 = 76;

pub const OK_MESSAGE: &str = "AUDIO OK\n";
pub const FAIL_MESSAGE: &str = "AUDIO FAIL\n";

pub const LABEL_COINIT: &str = "COINIT=";
pub const LABEL_ENUM: &str = "ENUM=";
pub const LABEL_DEVICE: &str = "DEVICE=";
pub const LABEL_CLIENT: &str = "CLIENT=";
pub const LABEL_MIXFMT: &str = "MIXFMT=";
pub const LABEL_CHANNELS: &str = "CHANNELS=";
pub const LABEL_RATE: &str = "RATE=";
pub const LABEL_BITS: &str = "BITS=";
pub const LABEL_INIT: &str = "INIT=";
pub const LABEL_BUFFER: &str = "BUFFER=";
pub const LABEL_FRAMES: &str = "FRAMES=";
pub const LABEL_RENDER: &str = "RENDER=";
pub const LABEL_GETBUF: &str = "GETBUF=";
pub const LABEL_RELBUF: &str = "RELBUF=";
pub const LABEL_START: &str = "START=";
pub const LABEL_PADDING: &str = "PADDING=";
pub const LABEL_STOP: &str = "STOP=";

const LABELS: [&str; 17] = [
    LABEL_COINIT,
    LABEL_ENUM,
    LABEL_DEVICE,
    LABEL_CLIENT,
    LABEL_MIXFMT,
    LABEL_CHANNELS,
    LABEL_RATE,
    LABEL_BITS,
    LABEL_INIT,
    LABEL_BUFFER,
    LABEL_FRAMES,
    LABEL_RENDER,
    LABEL_GETBUF,
    LABEL_RELBUF,
    LABEL_START,
    LABEL_PADDING,
    LABEL_STOP,
];

const I_COINIT: usize = 0;
const I_ENUM: usize = 1;
const I_DEVICE: usize = 2;
const I_CLIENT: usize = 3;
const I_MIXFMT: usize = 4;
const I_CHANNELS: usize = 5;
const I_RATE: usize = 6;
const I_BITS: usize = 7;
const I_INIT: usize = 8;
const I_BUFFER: usize = 9;
const I_FRAMES: usize = 10;
const I_RENDER: usize = 11;
const I_GETBUF: usize = 12;
const I_RELBUF: usize = 13;
const I_START: usize = 14;
const I_PADDING: usize = 15;
const I_STOP: usize = 16;

pub const CLSID_MM_DEVICE_ENUMERATOR: [u8; 16] = [
    0x95, 0x03, 0xDE, 0xBC, 0x2F, 0xE5, 0x7C, 0x46, 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E,
];
pub const IID_IMM_DEVICE_ENUMERATOR: [u8; 16] = [
    0xD2, 0x64, 0x56, 0xA9, 0x14, 0x96, 0x35, 0x4F, 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6,
];
pub const IID_IAUDIO_CLIENT: [u8; 16] = [
    0x4C, 0xAD, 0xB9, 0x1C, 0xFA, 0xDB, 0x32, 0x4C, 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2,
];
pub const IID_IAUDIO_RENDER_CLIENT: [u8; 16] = [
    0xFC, 0xAC, 0x94, 0xF2, 0x46, 0x31, 0x83, 0x44, 0xA7, 0xBF, 0xAD, 0xDC, 0xA7, 0xC2, 0x60, 0xE2,
];

const V_GET_DEFAULT_ENDPOINT: u8 = 0x20;
const V_ACTIVATE: u8 = 0x18;
const V_INITIALIZE: u8 = 0x18;
const V_GET_BUFFER_SIZE: u8 = 0x20;
const V_GET_CURRENT_PADDING: u8 = 0x30;
const V_GET_MIX_FORMAT: u8 = 0x40;
const V_START: u8 = 0x50;
const V_STOP: u8 = 0x58;
const V_GET_SERVICE: u8 = 0x70;
const V_GET_BUFFER: u8 = 0x18;
const V_RELEASE_BUFFER: u8 = 0x20;

const COINIT_APARTMENTTHREADED: u32 = 2;
const CLSCTX_ALL: u32 = 0x17;
const SHARE_SHARED: u32 = 0;
const BUFFER_DURATION: u64 = 2_000_000;

pub const PATTERN_FRAMES: u32 = 4800;
pub const PATTERN_FRAME_BYTES: u32 = 8;
pub const PATTERN_LEN: u32 = PATTERN_FRAMES * PATTERN_FRAME_BYTES;

pub fn pattern() -> Vec<u8> {
    let mut out = Vec::with_capacity(PATTERN_LEN as usize);
    for i in 0..PATTERN_FRAMES {
        let t = i as f32 / 48_000.0;
        let env = (t / 0.01).min(1.0).min((0.1 - t) / 0.01).max(0.0);
        let s = (t * 480.0 * std::f32::consts::TAU).sin() * 0.25 * env;
        out.extend_from_slice(&s.to_le_bytes());
        out.extend_from_slice(&(-s).to_le_bytes());
    }
    out
}

const LINE_CAP: u32 = 64;

pub fn build() -> Vec<u8> {
    let r = Rdata::build();
    let (text, entry_off) = build_text(&r);
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
    iat: std::collections::HashMap<String, u32>,

    clsid_enum_rva: u32,
    iid_enum_rva: u32,
    iid_client_rva: u32,
    iid_render_rva: u32,
    pattern_rva: u32,
    label_rva: [u32; LABELS.len()],
    label_len: [u32; LABELS.len()],
    ok_rva: u32,
    fail_rva: u32,

    data_rva: u32,
    penum_rva: u32,
    pdev_rva: u32,
    pclient_rva: u32,
    prender_rva: u32,
    pwfx_rva: u32,
    pdata_rva: u32,
    frames_rva: u32,
    padding_rva: u32,
    line_rva: u32,
    written_rva: u32,
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

        pos = align_up_u32(pos, 8);
        let clsid_enum_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_enum_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_client_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_render_rva = RDATA_RVA + pos;
        pos += 16;

        let mut label_rva = [0u32; LABELS.len()];
        let mut label_len = [0u32; LABELS.len()];
        for (i, l) in LABELS.iter().enumerate() {
            label_rva[i] = RDATA_RVA + pos;
            label_len[i] = l.len() as u32;
            pos += l.len() as u32;
        }
        let ok_rva = RDATA_RVA + pos;
        pos += OK_MESSAGE.len() as u32;
        let fail_rva = RDATA_RVA + pos;
        pos += FAIL_MESSAGE.len() as u32;
        pos = align_up_u32(pos, 4);
        let pattern_rva = RDATA_RVA + pos;
        pos += PATTERN_LEN;

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
        put(&mut b, clsid_enum_rva, &CLSID_MM_DEVICE_ENUMERATOR);
        put(&mut b, iid_enum_rva, &IID_IMM_DEVICE_ENUMERATOR);
        put(&mut b, iid_client_rva, &IID_IAUDIO_CLIENT);
        put(&mut b, iid_render_rva, &IID_IAUDIO_RENDER_CLIENT);
        for (i, l) in LABELS.iter().enumerate() {
            put(&mut b, label_rva[i], l.as_bytes());
        }
        put(&mut b, ok_rva, OK_MESSAGE.as_bytes());
        put(&mut b, fail_rva, FAIL_MESSAGE.as_bytes());
        put(&mut b, pattern_rva, &pattern());

        let data_rva = align_up_u32(RDATA_RVA + pos, SECTION_ALIGN);
        let mut d = data_rva;
        let mut cell = |n: u32| -> u32 {
            let r = d;
            d += n;
            r
        };
        let penum_rva = cell(8);
        let pdev_rva = cell(8);
        let pclient_rva = cell(8);
        let prender_rva = cell(8);
        let pwfx_rva = cell(8);
        let pdata_rva = cell(8);
        let frames_rva = cell(8);
        let padding_rva = cell(8);
        let written_rva = cell(16);
        let line_rva = cell(LINE_CAP);
        let data_len = d - data_rva;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            clsid_enum_rva,
            iid_enum_rva,
            iid_client_rva,
            iid_render_rva,
            pattern_rva,
            label_rva,
            label_len,
            ok_rva,
            fail_rva,
            data_rva,
            penum_rva,
            pdev_rva,
            pclient_rva,
            prender_rva,
            pwfx_rva,
            pdata_rva,
            frames_rva,
            padding_rva,
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

fn build_text(r: &Rdata) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();
    let report = c.len() as u32;
    emit_report(&mut c, r);
    let puts = c.len() as u32;
    emit_puts(&mut c, r);
    let entry_off = c.len() as u32;
    emit_entry(&mut c, r, report, puts);
    (c, entry_off)
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

fn emit_entry(c: &mut Vec<u8>, r: &Rdata, report: u32, puts: u32) {
    let mut bails: Vec<usize> = Vec::new();

    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME]);
    c.extend_from_slice(&[0x45, 0x31, 0xE4]);

    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    c.extend_from_slice(&[0x31, 0xC9]);
    c.push(0xBA);
    c.extend_from_slice(&COINIT_APARTMENTTHREADED.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("CoInitializeEx"));
    emit_hr(c, r, report, I_COINIT, &mut bails);

    rip(c, &[0x48, 0x8D, 0x0D], r.clsid_enum_rva);
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&CLSCTX_ALL.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.iid_enum_rva);
    rip(c, &[0x48, 0x8D, 0x05], r.penum_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    rip(c, &[0xFF, 0x15], r.slot("CoCreateInstance"));
    emit_hr(c, r, report, I_ENUM, &mut bails);
    emit_require_ptr(c, r, r.penum_rva, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.penum_rva);
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    rip(c, &[0x4C, 0x8D, 0x0D], r.pdev_rva);
    emit_vcall(c, V_GET_DEFAULT_ENDPOINT);
    emit_hr(c, r, report, I_DEVICE, &mut bails);
    emit_require_ptr(c, r, r.pdev_rva, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.pdev_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.iid_client_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&CLSCTX_ALL.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);
    rip(c, &[0x48, 0x8D, 0x05], r.pclient_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    emit_vcall(c, V_ACTIVATE);
    emit_hr(c, r, report, I_CLIENT, &mut bails);
    emit_require_ptr(c, r, r.pclient_rva, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.pwfx_rva);
    emit_vcall(c, V_GET_MIX_FORMAT);
    emit_hr(c, r, report, I_MIXFMT, &mut bails);
    emit_require_ptr(c, r, r.pwfx_rva, &mut bails);

    for (off, movzx, label) in [(2u8, true, I_CHANNELS), (4, false, I_RATE), (14, true, I_BITS)] {
        rip(c, &[0x48, 0x8B, 0x05], r.pwfx_rva);
        if movzx {
            c.extend_from_slice(&[0x0F, 0xB7, 0x48, off]);
        } else {
            c.extend_from_slice(&[0x8B, 0x48, off]);
        }
        emit_label_and_call(c, r, report, label);
    }

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    c.push(0xBA);
    c.extend_from_slice(&SHARE_SHARED.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    c.extend_from_slice(&[0x49, 0xB9]);
    c.extend_from_slice(&BUFFER_DURATION.to_le_bytes());
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    rip(c, &[0x48, 0x8B, 0x05], r.pwfx_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0, 0, 0, 0]);
    emit_vcall(c, V_INITIALIZE);
    emit_hr(c, r, report, I_INIT, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.frames_rva);
    emit_vcall(c, V_GET_BUFFER_SIZE);
    emit_hr(c, r, report, I_BUFFER, &mut bails);
    rip(c, &[0x8B, 0x0D], r.frames_rva);
    emit_label_and_call(c, r, report, I_FRAMES);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.iid_render_rva);
    rip(c, &[0x4C, 0x8D, 0x05], r.prender_rva);
    emit_vcall(c, V_GET_SERVICE);
    emit_hr(c, r, report, I_RENDER, &mut bails);
    emit_require_ptr(c, r, r.prender_rva, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.prender_rva);
    c.push(0xBA);
    c.extend_from_slice(&PATTERN_FRAMES.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x05], r.pdata_rva);
    emit_vcall(c, V_GET_BUFFER);
    emit_hr(c, r, report, I_GETBUF, &mut bails);
    emit_require_ptr(c, r, r.pdata_rva, &mut bails);

    rip(c, &[0x4C, 0x8B, 0x15], r.pdata_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.pattern_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&PATTERN_LEN.to_le_bytes());
    emit_copy_loop(c);

    rip(c, &[0x48, 0x8B, 0x0D], r.prender_rva);
    c.push(0xBA);
    c.extend_from_slice(&PATTERN_FRAMES.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC0]);
    emit_vcall(c, V_RELEASE_BUFFER);
    emit_hr(c, r, report, I_RELBUF, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    emit_vcall(c, V_START);
    emit_hr(c, r, report, I_START, &mut bails);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    rip(c, &[0x48, 0x8D, 0x15], r.padding_rva);
    emit_vcall(c, V_GET_CURRENT_PADDING);
    c.extend_from_slice(&[0x49, 0x89, 0xC5]);
    rip(c, &[0x8B, 0x0D], r.padding_rva);
    emit_label_and_call(c, r, report, I_PADDING);

    rip(c, &[0x48, 0x8B, 0x0D], r.pclient_rva);
    emit_vcall(c, V_STOP);
    emit_hr(c, r, report, I_STOP, &mut bails);

    for at in bails {
        patch32(c, at);
    }
    c.extend_from_slice(&[0x45, 0x85, 0xE4]);
    let failed = jcc8(c, 0x75);
    rip(c, &[0x48, 0x8D, 0x15], r.ok_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(OK_MESSAGE.len() as u32).to_le_bytes());
    call_rel(c, puts);
    c.push(0xB9);
    c.extend_from_slice(&AUDIO_OK_EXIT.to_le_bytes());
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

fn emit_vcall(c: &mut Vec<u8>, slot: u8) {
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    c.extend_from_slice(&[0xFF, 0x50, slot]);
}

fn emit_hr(c: &mut Vec<u8>, r: &Rdata, report: u32, label: usize, bails: &mut Vec<usize>) {
    c.extend_from_slice(&[0x49, 0x89, 0xC5]);
    c.extend_from_slice(&[0x44, 0x89, 0xE9]);
    emit_label_and_call(c, r, report, label);
    c.extend_from_slice(&[0x45, 0x85, 0xED]);
    let ok = jcc8(c, 0x79);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    bails.push(jmp32(c));
    patch8(c, ok);
}

fn emit_require_ptr(c: &mut Vec<u8>, _r: &Rdata, cell_rva: u32, bails: &mut Vec<usize>) {
    rip(c, &[0x48, 0x8B, 0x05], cell_rva);
    c.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let ok = jcc8(c, 0x75);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    bails.push(jmp32(c));
    patch8(c, ok);
}

fn emit_label_and_call(c: &mut Vec<u8>, r: &Rdata, report: u32, i: usize) {
    rip(c, &[0x48, 0x8D, 0x15], r.label_rva[i]);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.label_len[i].to_le_bytes());
    call_rel(c, report);
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
    c.extend_from_slice(&[0, 0, 0, 0]);
    c.len() - 4
}

fn patch32(c: &mut [u8], at: usize) {
    let rel = c.len() as i64 - (at as i64 + 4);
    let bytes = (rel as i32).to_le_bytes();
    c[at..at + 4].copy_from_slice(&bytes);
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
    fn audio_sample_is_a_pe_importing_only_com_and_the_console() {
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
        assert!(has("kernel32.dll", "WriteFile"));
        assert!(has("kernel32.dll", "ExitProcess"));
        let dlls: std::collections::BTreeSet<String> =
            image.imports.iter().map(|i| i.dll.to_ascii_lowercase()).collect();
        assert_eq!(
            dlls,
            ["kernel32.dll".to_string(), "ole32.dll".to_string()].into_iter().collect(),
            "no audio DLL is imported by name"
        );
    }

    #[test]
    fn the_guids_and_the_pcm_pattern_are_embedded() {
        let exe = build();
        for guid in [
            &CLSID_MM_DEVICE_ENUMERATOR,
            &IID_IMM_DEVICE_ENUMERATOR,
            &IID_IAUDIO_CLIENT,
            &IID_IAUDIO_RENDER_CLIENT,
        ] {
            assert!(exe.windows(16).any(|w| w == guid), "{guid:02x?} is in the image");
        }
        let pcm = pattern();
        assert_eq!(pcm.len(), PATTERN_LEN as usize);
        assert!(exe.windows(pcm.len()).any(|w| w == pcm), "the PCM pattern is in the image");
        for l in LABELS.iter() {
            assert!(exe.windows(l.len()).any(|w| w == l.as_bytes()), "{l} is in the image");
        }
    }

    #[test]
    fn the_embedded_clsid_matches_the_registry_seed() {
        let text = exemu_os::audio::CLSID_MM_DEVICE_ENUMERATOR;
        let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let raw: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let mut want = Vec::new();
        want.extend(raw[..4].iter().rev());
        want.extend(raw[4..6].iter().rev());
        want.extend(raw[6..8].iter().rev());
        want.extend_from_slice(&raw[8..]);
        assert_eq!(want, CLSID_MM_DEVICE_ENUMERATOR);
    }
}
