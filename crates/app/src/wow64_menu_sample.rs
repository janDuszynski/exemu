const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 96 + 16 * 8;

pub const MENU_OK_EXIT: i32 = 81;
pub const MENU_FAIL_NO_HWND_EXIT: i32 = 82;
pub const MENU_FAIL_NO_ATOM_EXIT: i32 = 83;

pub const WM_COMMAND: u32 = 0x0111;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WINDOW_STYLE: u32 = 0x00CF_0000;

pub const OBJID_MENU: u32 = 0xFFFF_FFFD;
pub const MENU_BAR_INFO_CB_SIZE: u32 = 0x20;
pub const SM_CYMENU: u32 = 15;
pub const WINDOW_X: u32 = 10;
pub const WINDOW_Y: u32 = 20;
pub const WINDOW_W: u32 = 200;
pub const WINDOW_H: u32 = 120;

pub mod menubarinfo32 {
    pub const RC_BAR: u32 = 0x04;
    pub const HMENU: u32 = 0x14;
    pub const HWND_MENU: u32 = 0x18;
    pub const FLAGS: u32 = 0x1c;
}

pub const MF_BYCOMMAND: u32 = 0x0000;
pub const MF_GRAYED: u32 = 0x0001;
pub const MF_CHECKED: u32 = 0x0008;
pub const MF_STRING: u32 = 0x0000;

pub const VK_F5: u32 = 0x74;
pub const VK_F6: u32 = 0x75;
pub const FVIRTKEY: u32 = 0x01;
pub const FLAST: u32 = 0x80;
pub const ACCEL_COMMAND: u32 = 0x77;
pub const NEW_ID: u32 = 100;
pub const OPEN_ID: u32 = 101;
pub const MISSING_ID: u32 = 999;

pub mod data {
    pub const COMMANDS: u32 = 0x00;
    pub const LAST_WPARAM: u32 = 0x04;
    pub const LAST_HWND: u32 = 0x08;
    pub const HWND: u32 = 0x0c;
    pub const HMENU: u32 = 0x10;
    pub const GET_MENU: u32 = 0x14;
    pub const CHECK_FIRST: u32 = 0x18;
    pub const CHECK_SECOND: u32 = 0x1c;
    pub const ENABLE_FIRST: u32 = 0x20;
    pub const ENABLE_SECOND: u32 = 0x24;
    pub const STATE_AFTER: u32 = 0x28;
    pub const COUNT_BEFORE: u32 = 0x2c;
    pub const HACCEL: u32 = 0x30;
    pub const TRANSLATE_HIT: u32 = 0x34;
    pub const TRANSLATE_MISS: u32 = 0x38;
    pub const COMMANDS_AFTER_HIT: u32 = 0x3c;
    pub const DESTROY_ACCEL: u32 = 0x40;
    pub const CHECK_MISSING: u32 = 0x44;
    pub const DELETE_RESULT: u32 = 0x48;
    pub const COUNT_AFTER_DELETE: u32 = 0x4c;
    pub const COMMANDS_AFTER_MISS: u32 = 0x50;
    pub const TRANSLATE_AFTER_DESTROY: u32 = 0x54;
    pub const ACCEL_TABLE: u32 = 0x60;
    pub const MSG_HIT: u32 = 0x80;
    pub const MSG_MISS: u32 = 0xc0;
    pub const WNDCLASS: u32 = 0x100;
    pub const CLIENT_BEFORE: u32 = 0x200;
    pub const CLIENT_AFTER: u32 = 0x210;
    pub const WINDOW_RECT: u32 = 0x220;
    pub const ITEM0_RECT: u32 = 0x230;
    pub const ITEM1_RECT: u32 = 0x240;
    pub const BAR_INFO: u32 = 0x250;
    pub const BAR_INFO_ITEM1: u32 = 0x270;
    pub const ITEM0_OK: u32 = 0x290;
    pub const ITEM1_OK: u32 = 0x294;
    pub const ITEM_BEYOND_OK: u32 = 0x298;
    pub const BAR_INFO_OK: u32 = 0x29c;
    pub const BAR_INFO_ITEM1_OK: u32 = 0x2a0;
    pub const BAR_INFO_BEYOND_OK: u32 = 0x2a4;
    pub const SYSTEM_MENU_HEIGHT: u32 = 0x2a8;
    pub const BEYOND_RECT: u32 = 0x2b0;
    pub const BEYOND_INFO: u32 = 0x2c0;
    pub const LEN: u32 = 0x300;
}

mod wndclassw {
    pub const WNDPROC: u32 = 0x04;
    pub const INSTANCE: u32 = 0x10;
    pub const BACKGROUND: u32 = 0x1c;
    pub const CLASS_NAME: u32 = 0x24;
}

mod msg32 {
    pub const HWND: u32 = 0x00;
    pub const MESSAGE: u32 = 0x04;
    pub const WPARAM: u32 = 0x08;
}

pub const fn data_va(off: u32) -> u64 {
    (IMAGE_BASE + DATA_RVA + off) as u64
}

const IMPORTS: [(&str, &[&str]); 2] = [
    (
        "user32.dll",
        &[
            "RegisterClassW",
            "CreateWindowExW",
            "DefWindowProcW",
            "CreateMenu",
            "AppendMenuW",
            "SetMenu",
            "GetMenu",
            "CheckMenuItem",
            "EnableMenuItem",
            "GetMenuState",
            "GetMenuItemCount",
            "DeleteMenu",
            "CreateAcceleratorTableW",
            "TranslateAcceleratorW",
            "DestroyAcceleratorTable",
            "GetClientRect",
            "GetWindowRect",
            "GetMenuItemRect",
            "GetMenuBarInfo",
            "GetSystemMetrics",
        ],
    ),
    ("ntdll.dll", &["NtTerminateProcess"]),
];

const I_REGISTER_CLASS: u32 = 0;
const I_CREATE_WINDOW: u32 = 1;
const I_DEF_WINDOW_PROC: u32 = 2;
const I_CREATE_MENU: u32 = 3;
const I_APPEND_MENU: u32 = 4;
const I_SET_MENU: u32 = 5;
const I_GET_MENU: u32 = 6;
const I_CHECK_MENU_ITEM: u32 = 7;
const I_ENABLE_MENU_ITEM: u32 = 8;
const I_GET_MENU_STATE: u32 = 9;
const I_GET_MENU_ITEM_COUNT: u32 = 10;
const I_DELETE_MENU: u32 = 11;
const I_CREATE_ACCEL: u32 = 12;
const I_TRANSLATE_ACCEL: u32 = 13;
const I_DESTROY_ACCEL: u32 = 14;
const I_GET_CLIENT_RECT: u32 = 15;
const I_GET_WINDOW_RECT: u32 = 16;
const I_GET_MENU_ITEM_RECT: u32 = 17;
const I_GET_MENU_BAR_INFO: u32 = 18;
const I_GET_SYSTEM_METRICS: u32 = 19;
const I_TERMINATE: u32 = 20;

struct Strings {
    class_va: u32,
    one_va: u32,
    two_va: u32,
}

pub fn build() -> Vec<u8> {
    let ndlls = IMPORTS.len() as u32;
    let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
    let import_dir_size = (ndlls + 1) * 20;
    let ilt_off = import_dir_size;
    let thunks: u32 = nfuncs + ndlls;
    let iat_off = ilt_off + thunks * 4;

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
    let mut wide_rva = Vec::new();
    let wides = [wide("ExemuMenuClass"), wide("&New"), wide("&Open")];
    for w in &wides {
        pos = align_up_u32(pos, 2);
        wide_rva.push(RDATA_RVA + pos);
        pos += w.len() as u32;
    }

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
    for (rva, w) in wide_rva.iter().zip(&wides) {
        let o = (rva - RDATA_RVA) as usize;
        rd[o..o + w.len()].copy_from_slice(w);
    }

    let iat = |i: u32| IMAGE_BASE + RDATA_RVA + iat_off + i * 4 + iat_gap(i);
    let strings = Strings {
        class_va: IMAGE_BASE + wide_rva[0],
        one_va: IMAGE_BASE + wide_rva[1],
        two_va: IMAGE_BASE + wide_rva[2],
    };
    let text = build_text(&iat, &strings);

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
    let text_header = SectionHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    };
    let rdata_header = SectionHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    };
    let data_header = SectionHeader {
        name: b".data",
        vsize: data::LEN,
        vaddr: DATA_RVA,
        raw_size: 0,
        raw_ptr: 0,
        chars: 0xC000_0080,
    };
    write_section(&mut f, sec, text_header);
    write_section(&mut f, sec + 40, rdata_header);
    write_section(&mut f, sec + 80, data_header);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

fn iat_gap(index: u32) -> u32 {
    let user32_count = IMPORTS[0].1.len() as u32;
    if index >= user32_count {
        4
    } else {
        0
    }
}

fn wide(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0]);
    v
}

struct Asm {
    code: Vec<u8>,
}

impl Asm {
    fn push_imm(&mut self, v: u32) {
        self.code.push(0x68);
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn push_cell(&mut self, at: u32) {
        self.code.extend_from_slice(&[0xFF, 0x35]);
        self.code.extend_from_slice(&at.to_le_bytes());
    }

    fn call_iat(&mut self, slot: u32) {
        self.code.extend_from_slice(&[0xFF, 0x15]);
        self.code.extend_from_slice(&slot.to_le_bytes());
    }

    fn jmp_iat(&mut self, slot: u32) {
        self.code.extend_from_slice(&[0xFF, 0x25]);
        self.code.extend_from_slice(&slot.to_le_bytes());
    }

    fn store_eax(&mut self, at: u32) {
        self.code.push(0xA3);
        self.code.extend_from_slice(&at.to_le_bytes());
    }

    fn store_imm(&mut self, at: u32, v: u32) {
        self.code.extend_from_slice(&[0xC7, 0x05]);
        self.code.extend_from_slice(&at.to_le_bytes());
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn load_eax(&mut self, at: u32) {
        self.code.push(0xA1);
        self.code.extend_from_slice(&at.to_le_bytes());
    }

    fn inc_cell(&mut self, at: u32) {
        self.code.extend_from_slice(&[0x83, 0x05]);
        self.code.extend_from_slice(&at.to_le_bytes());
        self.code.push(1);
    }

    fn exit(&mut self, slot: u32, code: u32) {
        self.push_imm(code);
        self.push_imm(0xFFFF_FFFF);
        self.call_iat(slot);
    }

    fn jnz_over(&mut self, body: impl FnOnce(&mut Asm)) {
        self.code.extend_from_slice(&[0x85, 0xC0, 0x75, 0x00]);
        let at = self.code.len() - 1;
        body(self);
        let disp = self.code.len() - (at + 1);
        assert!(disp < 128, "menu sample: rel8 branch out of range ({disp})");
        self.code[at] = disp as u8;
    }
}

fn build_text(iat: &dyn Fn(u32) -> u32, strings: &Strings) -> Vec<u8> {
    let cell = |off: u32| IMAGE_BASE + DATA_RVA + off;
    let mut a = Asm { code: vec![0xE9, 0, 0, 0, 0] };

    let wndproc_off = a.code.len();
    a.code.extend_from_slice(&[0x81, 0x7C, 0x24, 0x08]);
    a.code.extend_from_slice(&WM_COMMAND.to_le_bytes());
    a.code.extend_from_slice(&[0x75, 0x00]);
    let jne_default = a.code.len() - 1;
    a.inc_cell(cell(data::COMMANDS));
    a.code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x0C]);
    a.store_eax(cell(data::LAST_WPARAM));
    a.code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]);
    a.store_eax(cell(data::LAST_HWND));
    a.code.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x10, 0x00]);
    let disp = a.code.len() - (jne_default + 1);
    a.code[jne_default] = disp as u8;
    a.jmp_iat(iat(I_DEF_WINDOW_PROC));

    let main_off = a.code.len();
    let disp = (main_off - 5) as u32;
    a.code[1..5].copy_from_slice(&disp.to_le_bytes());
    let wndproc_va = IMAGE_BASE + TEXT_RVA + wndproc_off as u32;

    let wc = cell(data::WNDCLASS);
    for (off, v) in [
        (wndclassw::WNDPROC, wndproc_va),
        (wndclassw::INSTANCE, IMAGE_BASE),
        (wndclassw::BACKGROUND, 6),
        (wndclassw::CLASS_NAME, strings.class_va),
    ] {
        a.store_imm(wc + off, v);
    }
    a.push_imm(wc);
    a.call_iat(iat(I_REGISTER_CLASS));
    a.jnz_over(|a| a.exit(iat(I_TERMINATE), MENU_FAIL_NO_ATOM_EXIT as u32));

    for imm in [0u32, IMAGE_BASE, 0, 0, 120, 200, 20, 10, WINDOW_STYLE, strings.one_va, strings.class_va, 0] {
        a.push_imm(imm);
    }
    a.call_iat(iat(I_CREATE_WINDOW));
    a.store_eax(cell(data::HWND));
    a.jnz_over(|a| a.exit(iat(I_TERMINATE), MENU_FAIL_NO_HWND_EXIT as u32));

    a.call_iat(iat(I_CREATE_MENU));
    a.store_eax(cell(data::HMENU));
    for (id, text) in [(NEW_ID, strings.one_va), (OPEN_ID, strings.two_va)] {
        a.push_imm(text);
        a.push_imm(id);
        a.push_imm(MF_STRING);
        a.push_cell(cell(data::HMENU));
        a.call_iat(iat(I_APPEND_MENU));
    }
    a.push_cell(cell(data::HMENU));
    a.call_iat(iat(I_GET_MENU_ITEM_COUNT));
    a.store_eax(cell(data::COUNT_BEFORE));

    let rect_call = |a: &mut Asm, slot: u32, out: u32| {
        a.push_imm(cell(out));
        a.push_cell(cell(data::HWND));
        a.call_iat(iat(slot));
    };
    rect_call(&mut a, I_GET_CLIENT_RECT, data::CLIENT_BEFORE);
    a.push_cell(cell(data::HMENU));
    a.push_cell(cell(data::HWND));
    a.call_iat(iat(I_SET_MENU));
    a.push_cell(cell(data::HWND));
    a.call_iat(iat(I_GET_MENU));
    a.store_eax(cell(data::GET_MENU));
    rect_call(&mut a, I_GET_CLIENT_RECT, data::CLIENT_AFTER);
    rect_call(&mut a, I_GET_WINDOW_RECT, data::WINDOW_RECT);
    a.push_imm(SM_CYMENU);
    a.call_iat(iat(I_GET_SYSTEM_METRICS));
    a.store_eax(cell(data::SYSTEM_MENU_HEIGHT));

    let item_rect = |a: &mut Asm, pos: u32, out: u32, ok: u32| {
        a.push_imm(cell(out));
        a.push_imm(pos);
        a.push_cell(cell(data::HMENU));
        a.push_cell(cell(data::HWND));
        a.call_iat(iat(I_GET_MENU_ITEM_RECT));
        a.store_eax(cell(ok));
    };
    item_rect(&mut a, 0, data::ITEM0_RECT, data::ITEM0_OK);
    item_rect(&mut a, 1, data::ITEM1_RECT, data::ITEM1_OK);
    item_rect(&mut a, 2, data::BEYOND_RECT, data::ITEM_BEYOND_OK);

    let bar_info = |a: &mut Asm, item: u32, out: u32, ok: u32| {
        a.store_imm(cell(out), MENU_BAR_INFO_CB_SIZE);
        a.push_imm(cell(out));
        a.push_imm(item);
        a.push_imm(OBJID_MENU);
        a.push_cell(cell(data::HWND));
        a.call_iat(iat(I_GET_MENU_BAR_INFO));
        a.store_eax(cell(ok));
    };
    bar_info(&mut a, 0, data::BAR_INFO, data::BAR_INFO_OK);
    bar_info(&mut a, 1, data::BAR_INFO_ITEM1, data::BAR_INFO_ITEM1_OK);
    bar_info(&mut a, 3, data::BEYOND_INFO, data::BAR_INFO_BEYOND_OK);

    let menu_call = |a: &mut Asm, slot: u32, id: u32, flags: u32| {
        a.push_imm(flags);
        a.push_imm(id);
        a.push_cell(cell(data::HMENU));
        a.call_iat(iat(slot));
    };
    menu_call(&mut a, I_CHECK_MENU_ITEM, NEW_ID, MF_BYCOMMAND | MF_CHECKED);
    a.store_eax(cell(data::CHECK_FIRST));
    menu_call(&mut a, I_CHECK_MENU_ITEM, NEW_ID, MF_BYCOMMAND | MF_CHECKED);
    a.store_eax(cell(data::CHECK_SECOND));
    menu_call(&mut a, I_CHECK_MENU_ITEM, MISSING_ID, MF_BYCOMMAND | MF_CHECKED);
    a.store_eax(cell(data::CHECK_MISSING));
    menu_call(&mut a, I_ENABLE_MENU_ITEM, OPEN_ID, MF_GRAYED);
    a.store_eax(cell(data::ENABLE_FIRST));
    menu_call(&mut a, I_ENABLE_MENU_ITEM, OPEN_ID, MF_BYCOMMAND);
    a.store_eax(cell(data::ENABLE_SECOND));
    menu_call(&mut a, I_GET_MENU_STATE, NEW_ID, MF_BYCOMMAND);
    a.store_eax(cell(data::STATE_AFTER));
    menu_call(&mut a, I_DELETE_MENU, OPEN_ID, MF_BYCOMMAND);
    a.store_eax(cell(data::DELETE_RESULT));
    a.push_cell(cell(data::HMENU));
    a.call_iat(iat(I_GET_MENU_ITEM_COUNT));
    a.store_eax(cell(data::COUNT_AFTER_DELETE));

    let table = cell(data::ACCEL_TABLE);
    a.store_imm(table, FVIRTKEY | FLAST | (VK_F5 << 16));
    a.store_imm(table + 4, ACCEL_COMMAND);
    a.push_imm(1);
    a.push_imm(table);
    a.call_iat(iat(I_CREATE_ACCEL));
    a.store_eax(cell(data::HACCEL));

    for (msg, key) in [(data::MSG_HIT, VK_F5), (data::MSG_MISS, VK_F6)] {
        a.store_imm(cell(msg) + msg32::MESSAGE, WM_KEYDOWN);
        a.store_imm(cell(msg) + msg32::WPARAM, key);
        a.load_eax(cell(data::HWND));
        a.store_eax(cell(msg) + msg32::HWND);
    }
    let translate = |a: &mut Asm, msg: u32| {
        a.push_imm(cell(msg));
        a.push_cell(cell(data::HACCEL));
        a.push_cell(cell(data::HWND));
        a.call_iat(iat(I_TRANSLATE_ACCEL));
    };
    translate(&mut a, data::MSG_HIT);
    a.store_eax(cell(data::TRANSLATE_HIT));
    a.load_eax(cell(data::COMMANDS));
    a.store_eax(cell(data::COMMANDS_AFTER_HIT));
    translate(&mut a, data::MSG_MISS);
    a.store_eax(cell(data::TRANSLATE_MISS));
    a.load_eax(cell(data::COMMANDS));
    a.store_eax(cell(data::COMMANDS_AFTER_MISS));

    a.push_cell(cell(data::HACCEL));
    a.call_iat(iat(I_DESTROY_ACCEL));
    a.store_eax(cell(data::DESTROY_ACCEL));
    translate(&mut a, data::MSG_HIT);
    a.store_eax(cell(data::TRANSLATE_AFTER_DESTROY));

    a.exit(iat(I_TERMINATE), MENU_OK_EXIT as u32);
    a.code.push(0xF4);
    a.code
}

struct SectionHeader<'a> {
    name: &'a [u8],
    vsize: u32,
    vaddr: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
}

fn write_section(f: &mut [u8], at: usize, h: SectionHeader) {
    f[at..at + h.name.len()].copy_from_slice(h.name);
    put_u32(f, at + 8, h.vsize);
    put_u32(f, at + 12, h.vaddr);
    put_u32(f, at + 16, h.raw_size);
    put_u32(f, at + 20, h.raw_ptr);
    put_u32(f, at + 36, h.chars);
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
    fn the_sample_is_a_pe32_importing_the_menu_api_from_user32() {
        let bytes = build();
        let img = exemu_loader::parse(&bytes).expect("the sample parses");
        assert!(!img.is_64bit, "a WoW64 guest is a PE32");
        let named: Vec<String> = img
            .imports
            .iter()
            .filter_map(|i| match &i.symbol {
                exemu_core::ImportSymbol::Named(n) => Some(format!("{}!{n}", i.dll.to_ascii_lowercase())),
                exemu_core::ImportSymbol::Ordinal(_) => None,
            })
            .collect();
        let expected: usize = IMPORTS.iter().map(|(_, f)| f.len()).sum();
        assert_eq!(named.len(), expected);
        for name in ["user32.dll!SetMenu", "user32.dll!TranslateAcceleratorW", "user32.dll!CheckMenuItem"] {
            assert!(named.iter().any(|n| n == name), "{name} imported");
        }
        let mut slots: Vec<u32> = img.imports.iter().map(|i| i.iat_rva).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), expected, "every import has its own IAT slot");
    }
}
