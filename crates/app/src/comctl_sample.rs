use std::collections::HashMap;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const CLASS_NAME: &str = "ExemuComctlClass";
const WINDOW_TITLE: &str = "exemu — Wine common controls";
const BUTTON_CLASS: &str = "BUTTON";
const BUTTON_TEXT: &str = "Push me";
const PROGRESS_CLASS: &str = "msctls_progress32";
const PAINT_LINE1: &str = "Wine comctl32 controls under exemu.";
const PAINT_LINE2: &str = "InitCommonControlsEx + BUTTON + progress bar.";

pub const WINDOW_CX: i32 = 520;
pub const WINDOW_CY: i32 = 300;

pub const BUTTON_RECT: [i32; 4] = [24, 200, 140, 32];
pub const PROGRESS_RECT: [i32; 4] = [184, 204, 300, 24];

const ICC_FLAGS: i32 = 0x0000_00FF | 0x0000_4000;

pub const ID_BUTTON: i32 = 100;
const ID_PROGRESS: i32 = 101;

const PBM_SETRANGE: u32 = 0x0400 + 1;
const PBM_SETPOS: u32 = 0x0400 + 2;
const PROGRESS_RANGE: u32 = 100 << 16;
pub const PROGRESS_POS: u32 = 60;

pub const CREATE_PARAM_MAGIC: i32 = 0x5A5A_1234;

const CS_LP_CREATE_PARAMS: i8 = 0x00;
const CS_LPSZ_CLASS: i8 = 0x40;

const WM_CREATE: i32 = 0x0001;
const WM_NCCREATE: i32 = 0x0081;
const WM_COMMAND: i32 = 0x0111;

pub const CLICKED_TEXT: &str = "Clicked!";

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
    put_u16(&mut f, coff + 2, 2);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022);

    let opt = coff + 20;
    let image_size = align_up_u32(RDATA_RVA + r.bytes.len() as u32, SECTION_ALIGN);
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
    put_u16(&mut f, opt + 68, 2);
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

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + r.bytes.len()].copy_from_slice(&r.bytes);
    f
}

fn import_plan() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "user32.dll",
            vec![
                "RegisterClassW",
                "CreateWindowExW",
                "ShowWindow",
                "GetMessageW",
                "DispatchMessageW",
                "DefWindowProcW",
                "BeginPaint",
                "EndPaint",
                "PostQuitMessage",
                "GetDC",
                "ReleaseDC",
                "SendMessageW",
                "SetWindowTextW",
            ],
        ),
        ("gdi32.dll", vec!["TextOutW", "Rectangle"]),
        ("comctl32.dll", vec!["InitCommonControlsEx"]),
        ("kernel32.dll", vec!["ExitProcess"]),
    ]
}

const WIDE_STRINGS: [&str; 8] = [
    CLASS_NAME,
    WINDOW_TITLE,
    BUTTON_CLASS,
    BUTTON_TEXT,
    PROGRESS_CLASS,
    PAINT_LINE1,
    PAINT_LINE2,
    CLICKED_TEXT,
];

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat: HashMap<String, u32>,
    strings: Vec<u32>,
}

impl Rdata {
    fn build() -> Rdata {
        let plan = import_plan();
        let n_dlls = plan.len();
        let total_funcs: usize = plan.iter().map(|(_, fs)| fs.len()).sum();

        let import_dir_off = 0u32;
        let import_dir_size = ((n_dlls + 1) * 20) as u32;
        let thunks_qwords: usize = plan.iter().map(|(_, fs)| fs.len() + 1).sum();
        let ilt_off = import_dir_off + import_dir_size;
        let ilt_size = (thunks_qwords * 8) as u32;
        let iat_off = ilt_off + ilt_size;
        let iat_size = ilt_size;

        let mut pos = iat_off + iat_size;

        let mut ibn_rva: Vec<u32> = Vec::with_capacity(total_funcs);
        for (_, funcs) in &plan {
            for f in funcs {
                pos = align_up_u32(pos, 2);
                ibn_rva.push(RDATA_RVA + pos);
                pos += 2 + f.len() as u32 + 1;
            }
        }
        let mut dll_name_rva: Vec<u32> = Vec::with_capacity(n_dlls);
        for (dll, _) in &plan {
            dll_name_rva.push(RDATA_RVA + pos);
            pos += dll.len() as u32 + 1;
        }
        pos = align_up_u32(pos, 2);
        let mut strings: Vec<u32> = Vec::with_capacity(WIDE_STRINGS.len());
        for s in WIDE_STRINGS {
            strings.push(RDATA_RVA + pos);
            pos += wide(s).len() as u32;
        }

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
        for (rva, s) in strings.iter().zip(WIDE_STRINGS) {
            let off = (*rva - RDATA_RVA) as usize;
            let w = wide(s);
            b[off..off + w.len()].copy_from_slice(&w);
        }

        Rdata { bytes: b, import_dir_off, import_dir_size, iat_off, iat_size, iat, strings }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }

    fn wstr(&self, s: &str) -> u32 {
        let i = WIDE_STRINGS.iter().position(|w| *w == s).expect("wide string present");
        self.strings[i]
    }
}

fn wide(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

fn wlen(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

const FRAME: u32 = 0x108;
const WC: i32 = 0x60;
const MSG: i32 = 0xB0;
const ICC: i32 = 0xE0;
const H_BUTTON: i32 = 0xE8;
const H_PROGRESS: i32 = 0xF0;
const SCRATCH: i32 = 0xF8;

const WC_WNDPROC: i32 = 0x08;
const WC_CLASSNAME: i32 = 0x40;
const WC_SIZE: i32 = 0x48;

const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const WS_CHILD_VISIBLE: u32 = 0x5000_0000;
const WS_CHILD_BUTTON: u32 = 0x5000_0001;

fn build_text(r: &Rdata) -> Vec<u8> {
    let mut a = Asm::new();

    a.sub_rsp(FRAME);

    a.mov_at_rsp_imm32(ICC, 8);
    a.mov_at_rsp_imm32(ICC + 4, ICC_FLAGS);
    a.lea_rsp(RCX, ICC);
    a.call_iat(r.slot("InitCommonControlsEx"));

    let mut off = WC;
    while off < WC + WC_SIZE {
        a.mov_at_rsp_imm(off, 0);
        off += 8;
    }
    a.lea_label(RAX, "wndproc");
    a.mov_at_rsp_reg(WC + WC_WNDPROC, RAX);
    a.lea_rip(RAX, r.wstr(CLASS_NAME));
    a.mov_at_rsp_reg(WC + WC_CLASSNAME, RAX);
    a.lea_rsp(RCX, WC);
    a.call_iat(r.slot("RegisterClassW"));

    a.xor32(RCX);
    a.lea_rip(RDX, r.wstr(CLASS_NAME));
    a.lea_rip(R8, r.wstr(WINDOW_TITLE));
    a.mov32(R9, WS_OVERLAPPEDWINDOW);
    a.mov_at_rsp_imm(0x20, 120);
    a.mov_at_rsp_imm(0x28, 120);
    a.mov_at_rsp_imm(0x30, WINDOW_CX);
    a.mov_at_rsp_imm(0x38, WINDOW_CY);
    a.mov_at_rsp_imm(0x40, 0);
    a.mov_at_rsp_imm(0x48, 0);
    a.mov_at_rsp_imm(0x50, 0);
    a.mov_at_rsp_imm(0x58, CREATE_PARAM_MAGIC);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_reg_reg(RBX, RAX);

    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 5);
    a.call_iat(r.slot("ShowWindow"));

    a.xor32(RCX);
    a.lea_rip(RDX, r.wstr(BUTTON_CLASS));
    a.lea_rip(R8, r.wstr(BUTTON_TEXT));
    a.mov32(R9, WS_CHILD_BUTTON);
    a.mov_at_rsp_imm(0x20, BUTTON_RECT[0]);
    a.mov_at_rsp_imm(0x28, BUTTON_RECT[1]);
    a.mov_at_rsp_imm(0x30, BUTTON_RECT[2]);
    a.mov_at_rsp_imm(0x38, BUTTON_RECT[3]);
    a.mov_at_rsp_reg(0x40, RBX);
    a.mov_at_rsp_imm(0x48, ID_BUTTON);
    a.mov_at_rsp_imm(0x50, 0);
    a.mov_at_rsp_imm(0x58, 0);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_at_rsp_reg(H_BUTTON, RAX);

    a.xor32(RCX);
    a.lea_rip(RDX, r.wstr(PROGRESS_CLASS));
    a.xor32(R8);
    a.mov32(R9, WS_CHILD_VISIBLE);
    a.mov_at_rsp_imm(0x20, PROGRESS_RECT[0]);
    a.mov_at_rsp_imm(0x28, PROGRESS_RECT[1]);
    a.mov_at_rsp_imm(0x30, PROGRESS_RECT[2]);
    a.mov_at_rsp_imm(0x38, PROGRESS_RECT[3]);
    a.mov_at_rsp_reg(0x40, RBX);
    a.mov_at_rsp_imm(0x48, ID_PROGRESS);
    a.mov_at_rsp_imm(0x50, 0);
    a.mov_at_rsp_imm(0x58, 0);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_at_rsp_reg(H_PROGRESS, RAX);

    a.mov_reg_at_rsp(RCX, H_PROGRESS);
    a.mov32(RDX, PBM_SETRANGE);
    a.xor32(R8);
    a.mov32(R9, PROGRESS_RANGE);
    a.call_iat(r.slot("SendMessageW"));
    a.mov_reg_at_rsp(RCX, H_PROGRESS);
    a.mov32(RDX, PBM_SETPOS);
    a.mov32(R8, PROGRESS_POS);
    a.xor32(R9);
    a.call_iat(r.slot("SendMessageW"));

    a.mov_reg_reg(RCX, RBX);
    a.call_iat(r.slot("GetDC"));
    a.mov_at_rsp_reg(SCRATCH, RAX);
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 16);
    a.mov32(R8, 16);
    a.lea_rip(R9, r.wstr(PAINT_LINE1));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    a.mov_reg_at_rsp(RCX, SCRATCH);
    a.mov32(RDX, 16);
    a.mov32(R8, 44);
    a.lea_rip(R9, r.wstr(PAINT_LINE2));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE2) as i32);
    a.call_iat(r.slot("TextOutW"));
    a.mov_reg_at_rsp(RCX, SCRATCH);
    a.mov32(RDX, 12);
    a.mov32(R8, 84);
    a.mov32(R9, 500);
    a.mov_at_rsp_imm(0x20, 180);
    a.call_iat(r.slot("Rectangle"));
    a.mov_reg_reg(RCX, RBX);
    a.mov_reg_at_rsp(RDX, SCRATCH);
    a.call_iat(r.slot("ReleaseDC"));

    a.label("loop");
    a.lea_rsp(RCX, MSG);
    a.xor32(RDX);
    a.xor32(R8);
    a.xor32(R9);
    a.call_iat(r.slot("GetMessageW"));
    a.test_eax();
    a.je("end");
    a.lea_rsp(RCX, MSG);
    a.call_iat(r.slot("DispatchMessageW"));
    a.jmp("loop");
    a.label("end");
    a.xor32(RCX);
    a.call_iat(r.slot("ExitProcess"));
    a.int3();

    const WP_FRAME: u32 = 0xC8;
    const WP_PS: i32 = 0x30;
    const WP_HWND: i32 = 0x80;
    const WP_HDC: i32 = 0x88;
    a.label("wndproc");
    a.sub_rsp(WP_FRAME);
    a.mov_at_rsp_reg(WP_HWND, RCX);
    a.cmp_rdx_imm8(0x0F);
    a.je("paint");
    a.cmp_rdx_imm8(0x02);
    a.je("destroy");
    a.cmp_rdx_imm32(WM_NCCREATE);
    a.je("nccreate");
    a.cmp_rdx_imm32(WM_CREATE);
    a.je("create");
    a.cmp_rdx_imm32(WM_COMMAND);
    a.je("command");
    a.call_iat(r.slot("DefWindowProcW"));
    a.jmp("wp_ret");

    a.label("command");
    a.cmp_r8_imm32(ID_BUTTON);
    a.jne("command_done");
    a.mov_reg_reg(RCX, R9);
    a.lea_rip(RDX, r.wstr(CLICKED_TEXT));
    a.call_iat(r.slot("SetWindowTextW"));
    a.label("command_done");
    a.xor32(RAX);
    a.jmp("wp_ret");

    a.label("nccreate");
    a.mov32(RAX, 1);
    a.jmp("wp_ret");

    a.label("create");
    a.cmp_at_r9_imm32(CS_LP_CREATE_PARAMS, CREATE_PARAM_MAGIC);
    a.jne("create_done");
    a.mov_rdx_at_r9(CS_LPSZ_CLASS);
    a.mov_reg_at_rsp(RCX, WP_HWND);
    a.call_iat(r.slot("SetWindowTextW"));
    a.label("create_done");
    a.xor32(RAX);
    a.jmp("wp_ret");

    a.label("destroy");
    a.xor32(RCX);
    a.call_iat(r.slot("PostQuitMessage"));
    a.xor32(RAX);
    a.jmp("wp_ret");

    a.label("paint");
    a.mov_reg_at_rsp(RCX, WP_HWND);
    a.lea_rsp(RDX, WP_PS);
    a.call_iat(r.slot("BeginPaint"));
    a.mov_at_rsp_reg(WP_HDC, RAX);
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 12);
    a.mov32(R8, 84);
    a.mov32(R9, 500);
    a.mov_at_rsp_imm(0x20, 180);
    a.call_iat(r.slot("Rectangle"));
    a.mov_reg_at_rsp(RCX, WP_HDC);
    a.mov32(RDX, 16);
    a.mov32(R8, 16);
    a.lea_rip(R9, r.wstr(PAINT_LINE1));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    a.mov_reg_at_rsp(RCX, WP_HDC);
    a.mov32(RDX, 16);
    a.mov32(R8, 44);
    a.lea_rip(R9, r.wstr(PAINT_LINE2));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE2) as i32);
    a.call_iat(r.slot("TextOutW"));
    a.mov_reg_at_rsp(RCX, WP_HWND);
    a.lea_rsp(RDX, WP_PS);
    a.call_iat(r.slot("EndPaint"));
    a.xor32(RAX);

    a.label("wp_ret");
    a.add_rsp(WP_FRAME);
    a.ret();

    a.finish()
}

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const R8: u8 = 8;
const R9: u8 = 9;

struct Asm {
    code: Vec<u8>,
    labels: HashMap<String, usize>,
    fixups: Vec<(usize, String)>,
}

impl Asm {
    fn new() -> Asm {
        Asm { code: Vec::new(), labels: HashMap::new(), fixups: Vec::new() }
    }

    fn label(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.code.len());
    }

    fn modrm_rsp(&mut self, reg: u8, disp: i32) {
        let reg = reg & 7;
        if (-128..=127).contains(&disp) {
            self.code.push(0x40 | (reg << 3) | 0x04);
            self.code.push(0x24);
            self.code.push(disp as u8);
        } else {
            self.code.push(0x80 | (reg << 3) | 0x04);
            self.code.push(0x24);
            self.code.extend_from_slice(&disp.to_le_bytes());
        }
    }

    fn rex(&mut self, r: u8) {
        let mut rex = 0x48;
        if r >= 8 {
            rex |= 0x04;
        }
        self.code.push(rex);
    }

    fn sub_rsp(&mut self, n: u32) {
        self.code.extend_from_slice(&[0x48, 0x81, 0xEC]);
        self.code.extend_from_slice(&n.to_le_bytes());
    }
    fn add_rsp(&mut self, n: u32) {
        self.code.extend_from_slice(&[0x48, 0x81, 0xC4]);
        self.code.extend_from_slice(&n.to_le_bytes());
    }

    fn mov_at_rsp_reg(&mut self, disp: i32, reg: u8) {
        self.rex(reg);
        self.code.push(0x89);
        self.modrm_rsp(reg, disp);
    }
    fn mov_reg_at_rsp(&mut self, reg: u8, disp: i32) {
        self.rex(reg);
        self.code.push(0x8B);
        self.modrm_rsp(reg, disp);
    }
    fn lea_rsp(&mut self, reg: u8, disp: i32) {
        self.rex(reg);
        self.code.push(0x8D);
        self.modrm_rsp(reg, disp);
    }
    fn mov_at_rsp_imm(&mut self, disp: i32, imm: i32) {
        self.code.extend_from_slice(&[0x48, 0xC7]);
        self.modrm_rsp(0, disp);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    fn mov_at_rsp_imm32(&mut self, disp: i32, imm: i32) {
        self.code.push(0xC7);
        self.modrm_rsp(0, disp);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    fn mov_reg_reg(&mut self, dst: u8, src: u8) {
        let mut rex = 0x48;
        if src >= 8 {
            rex |= 0x04;
        }
        if dst >= 8 {
            rex |= 0x01;
        }
        self.code.push(rex);
        self.code.push(0x89);
        self.code.push(0xC0 | ((src & 7) << 3) | (dst & 7));
    }

    fn mov32(&mut self, reg: u8, imm: u32) {
        if reg >= 8 {
            self.code.push(0x41);
        }
        self.code.push(0xB8 | (reg & 7));
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    fn xor32(&mut self, reg: u8) {
        if reg >= 8 {
            self.code.push(0x45);
        }
        self.code.push(0x31);
        self.code.push(0xC0 | ((reg & 7) << 3) | (reg & 7));
    }

    fn test_eax(&mut self) {
        self.code.extend_from_slice(&[0x85, 0xC0]);
    }
    fn cmp_rdx_imm8(&mut self, imm: i8) {
        self.code.extend_from_slice(&[0x48, 0x83, 0xFA, imm as u8]);
    }
    fn cmp_rdx_imm32(&mut self, imm: i32) {
        self.code.extend_from_slice(&[0x48, 0x81, 0xFA]);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    fn cmp_r8_imm32(&mut self, imm: i32) {
        self.code.extend_from_slice(&[0x49, 0x81, 0xF8]);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    fn cmp_at_r9_imm32(&mut self, disp: i8, imm: i32) {
        self.code.extend_from_slice(&[0x49, 0x81, 0x79, disp as u8]);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    fn mov_rdx_at_r9(&mut self, disp: i8) {
        self.code.extend_from_slice(&[0x49, 0x8B, 0x51, disp as u8]);
    }
    fn int3(&mut self) {
        self.code.push(0xCC);
    }
    fn ret(&mut self) {
        self.code.push(0xC3);
    }

    fn je(&mut self, label: &str) {
        self.code.extend_from_slice(&[0x0F, 0x84]);
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }
    fn jne(&mut self, label: &str) {
        self.code.extend_from_slice(&[0x0F, 0x85]);
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }
    fn jmp(&mut self, label: &str) {
        self.code.push(0xE9);
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }
    fn lea_label(&mut self, reg: u8, label: &str) {
        self.rex(reg);
        self.code.push(0x8D);
        self.code.push(0x05 | ((reg & 7) << 3));
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }

    fn lea_rip(&mut self, reg: u8, target_rva: u32) {
        self.rex(reg);
        self.code.push(0x8D);
        self.code.push(0x05 | ((reg & 7) << 3));
        let next = TEXT_RVA as i64 + self.code.len() as i64 + 4;
        let disp = target_rva as i64 - next;
        self.code.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    fn call_iat(&mut self, slot_rva: u32) {
        self.code.extend_from_slice(&[0xFF, 0x15]);
        let next = TEXT_RVA as i64 + self.code.len() as i64 + 4;
        let disp = slot_rva as i64 - next;
        self.code.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        for (pos, label) in &self.fixups {
            let target = *self.labels.get(label).unwrap_or_else(|| panic!("label {label}"));
            let rel = target as i32 - (*pos as i32 + 4);
            self.code[*pos..*pos + 4].copy_from_slice(&rel.to_le_bytes());
        }
        self.code
    }
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
    fn comctl_sample_is_a_pe_importing_comctl32() {
        let exe = build();
        let image = exemu_loader::parse(&exe).expect("parses as PE32+");
        assert!(image.is_64bit);

        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        assert!(has("comctl32.dll", "InitCommonControlsEx"), "imports comctl32!InitCommonControlsEx");
        assert!(has("user32.dll", "CreateWindowExW"));
        assert!(has("user32.dll", "SendMessageW"));
        assert!(has("gdi32.dll", "Rectangle"));

        let needle = wide(PROGRESS_CLASS);
        assert!(
            exe.windows(needle.len()).any(|w| w == needle),
            "the msctls_progress32 class name is in the image"
        );
    }
}
