//! Generates a tiny but real **GUI** PE: it registers a window class, creates
//! a custom (non-dialog) window, shows it, paints its client area with the
//! emulated GDI (a framed rectangle + a line of text via a direct
//! GetDC→TextOutW→Rectangle→ReleaseDC), then runs a message loop. It is the
//! counterpart to [`crate::sample`], exercising the `CreateWindowEx` + GDI
//! surface/present path rather than a console.
//!
//! The direct paint after `ShowWindow` is the honest W4.3 gate: it renders the
//! first frame without a message pump. With a live input channel (W4.6), the
//! message loop's `GetMessage` synthesizes an initial `WM_PAINT` for the shown
//! window and `DispatchMessageW` routes it through `NtUserDispatchMessage` into
//! the `WM_PAINT` arm of `wndproc` below, which repaints via BeginPaint →
//! Rectangle → TextOutW → EndPaint (a second present). Without an input channel
//! `GetMessage` returns `WM_QUIT` immediately and only the direct paint runs —
//! either way the surface/present pipeline is fully exercised, so both stay green.
//!
//! The code is hand-assembled x86-64 with a small local assembler (`Asm`) so
//! branch targets and RIP-relative references stay correct.

use std::collections::HashMap;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

const CLASS_NAME: &str = "ExemuWindowClass";
const WINDOW_TITLE: &str = "exemu — real GUI window";
const PAINT_LINE1: &str = "Hello from a real GUI window!";
const PAINT_LINE2: &str = "Drawn by exemu's emulated Win32 GDI.";

/// Build the GUI sample executable.
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
    put_u16(&mut f, opt + 68, 2); // Subsystem = WINDOWS_GUI
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

/// The imports, grouped by DLL and in IAT order.
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
            ],
        ),
        ("gdi32.dll", vec!["TextOutW", "Rectangle"]),
        ("kernel32.dll", vec!["ExitProcess"]),
    ]
}

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    /// Import name → its IAT slot RVA.
    iat: HashMap<String, u32>,
    /// Wide-string RVAs.
    class_name: u32,
    window_title: u32,
    line1: u32,
    line2: u32,
}

impl Rdata {
    fn build() -> Rdata {
        let plan = import_plan();
        let n_dlls = plan.len();
        let total_funcs: usize = plan.iter().map(|(_, fs)| fs.len()).sum();

        // Layout within .rdata.
        let import_dir_off = 0u32;
        let import_dir_size = ((n_dlls + 1) * 20) as u32;
        // Each DLL gets an ILT and IAT of (funcs+1) qwords.
        let thunks_qwords: usize = plan.iter().map(|(_, fs)| fs.len() + 1).sum();
        let ilt_off = import_dir_off + import_dir_size;
        let ilt_size = (thunks_qwords * 8) as u32;
        let iat_off = ilt_off + ilt_size;
        let iat_size = ilt_size;

        let mut pos = iat_off + iat_size;

        // IMAGE_IMPORT_BY_NAME blobs (hint u16 + asciiz).
        let mut ibn_rva: Vec<u32> = Vec::with_capacity(total_funcs);
        for (_, funcs) in &plan {
            for f in funcs {
                pos = align_up_u32(pos, 2);
                ibn_rva.push(RDATA_RVA + pos);
                pos += 2 + f.len() as u32 + 1;
            }
        }
        // DLL name strings.
        let mut dll_name_rva: Vec<u32> = Vec::with_capacity(n_dlls);
        for (dll, _) in &plan {
            dll_name_rva.push(RDATA_RVA + pos);
            pos += dll.len() as u32 + 1;
        }
        // Wide strings.
        let wide = |s: &str| -> Vec<u8> {
            let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            v.extend_from_slice(&[0, 0]);
            v
        };
        pos = align_up_u32(pos, 2);
        let class_name = RDATA_RVA + pos;
        pos += wide(CLASS_NAME).len() as u32;
        let window_title = RDATA_RVA + pos;
        pos += wide(WINDOW_TITLE).len() as u32;
        let line1 = RDATA_RVA + pos;
        pos += wide(PAINT_LINE1).len() as u32;
        let line2 = RDATA_RVA + pos;
        pos += wide(PAINT_LINE2).len() as u32;

        let mut b = vec![0u8; pos as usize];

        // Import descriptors + ILT/IAT + IBN.
        let mut iat = HashMap::new();
        let mut ilt_cursor = ilt_off;
        let mut iat_cursor = iat_off;
        let mut ibn_i = 0usize;
        for (d, (_dll, funcs)) in plan.iter().enumerate() {
            let desc = import_dir_off as usize + d * 20;
            put_u32(&mut b, desc, ilt_cursor + RDATA_RVA); // OriginalFirstThunk
            put_u32(&mut b, desc + 12, dll_name_rva[d]); // Name
            put_u32(&mut b, desc + 16, iat_cursor + RDATA_RVA); // FirstThunk
            for f in funcs {
                let rva = ibn_rva[ibn_i];
                put_u64(&mut b, ilt_cursor as usize, rva as u64);
                put_u64(&mut b, iat_cursor as usize, rva as u64);
                iat.insert((*f).to_string(), iat_cursor + RDATA_RVA);
                ilt_cursor += 8;
                iat_cursor += 8;
                ibn_i += 1;
            }
            // Null-terminate this DLL's ILT/IAT.
            ilt_cursor += 8;
            iat_cursor += 8;
        }
        // Descriptor terminator is already zero.

        // IBN blobs.
        ibn_i = 0;
        for (_, funcs) in &plan {
            for f in funcs {
                let off = (ibn_rva[ibn_i] - RDATA_RVA) as usize;
                b[off + 2..off + 2 + f.len()].copy_from_slice(f.as_bytes());
                ibn_i += 1;
            }
        }
        // DLL names.
        for (d, (dll, _)) in plan.iter().enumerate() {
            let off = (dll_name_rva[d] - RDATA_RVA) as usize;
            b[off..off + dll.len()].copy_from_slice(dll.as_bytes());
        }
        // Wide strings.
        for (rva, s) in [(class_name, CLASS_NAME), (window_title, WINDOW_TITLE), (line1, PAINT_LINE1), (line2, PAINT_LINE2)] {
            let off = (rva - RDATA_RVA) as usize;
            let w = wide(s);
            b[off..off + w.len()].copy_from_slice(&w);
        }

        Rdata { bytes: b, import_dir_off, import_dir_size, iat_off, iat_size, iat, class_name, window_title, line1, line2 }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }
}

/// UTF-16 code-unit count including the terminating NUL — the `c` count that
/// TextOutW would use is the visible length, which we pass explicitly.
fn wlen(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

fn build_text(r: &Rdata) -> Vec<u8> {
    let mut a = Asm::new();

    // ---- entry / WinMain --------------------------------------------------
    // Frame: [0x00..0x60] shadow + outgoing stack args (CreateWindowEx),
    //        [0x60..0xB0] WNDCLASSW, [0xB0..0xE0] MSG.
    a.sub_rsp(0xE8);
    a.lea_label(RAX, "wndproc");
    a.mov_at_rsp_reg(0x68, RAX); // wc.lpfnWndProc  (0x60 + 8)
    a.lea_rip(RAX, r.class_name);
    a.mov_at_rsp_reg(0xA0, RAX); // wc.lpszClassName (0x60 + 0x40)
    a.lea_rsp(RCX, 0x60); // &wc
    a.call_iat(r.slot("RegisterClassW"));

    a.xor32(RCX); // exStyle
    a.lea_rip(RDX, r.class_name);
    a.lea_rip(R8, r.window_title);
    a.mov32(R9, 0x00CF_0000); // WS_OVERLAPPEDWINDOW
    a.mov_at_rsp_imm(0x20, 120); // X
    a.mov_at_rsp_imm(0x28, 120); // Y
    a.mov_at_rsp_imm(0x30, 480); // nWidth
    a.mov_at_rsp_imm(0x38, 260); // nHeight
    a.mov_at_rsp_imm(0x40, 0); // hWndParent
    a.mov_at_rsp_imm(0x48, 0); // hMenu
    a.mov_at_rsp_imm(0x50, 0); // hInstance
    a.mov_at_rsp_imm(0x58, 0); // lpParam
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_reg_reg(RBX, RAX); // save hwnd

    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 5); // SW_SHOW
    a.call_iat(r.slot("ShowWindow"));

    // ---- direct paint (W4.3) ----------------------------------------------
    // The WndProc paint code below only runs on a WM_PAINT the message loop
    // never delivers in this build (GetMessage returns WM_QUIT immediately;
    // callback delivery is W4.6). To exercise the *surface/present* pipeline
    // now, paint the client area directly here: GetDC → TextOutW → Rectangle →
    // ReleaseDC. hwnd is live in RBX; the WNDCLASS scratch at [rsp+0x60] is free
    // after RegisterClassW so it stashes the hdc; [rsp+0x20] is the 5th-arg home
    // slot for the count/bottom.
    a.mov_reg_reg(RCX, RBX); // hwnd
    a.call_iat(r.slot("GetDC"));
    a.mov_at_rsp_reg(0x60, RAX); // save hdc
    // TextOutW(hdc, 12, 12, line1, wlen(PAINT_LINE1))
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 12);
    a.mov32(R8, 12);
    a.lea_rip(R9, r.line1);
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    // Rectangle(hdc, 8, 8, 200, 60)
    a.mov_reg_at_rsp(RCX, 0x60);
    a.mov32(RDX, 8);
    a.mov32(R8, 8);
    a.mov32(R9, 200);
    a.mov_at_rsp_imm(0x20, 60);
    a.call_iat(r.slot("Rectangle"));
    // ReleaseDC(hwnd, hdc) — the present point for the direct paint.
    a.mov_reg_reg(RCX, RBX);
    a.mov_reg_at_rsp(RDX, 0x60);
    a.call_iat(r.slot("ReleaseDC"));

    a.label("loop");
    a.lea_rsp(RCX, 0xB0); // &msg
    a.xor32(RDX);
    a.xor32(R8);
    a.xor32(R9);
    a.call_iat(r.slot("GetMessageW"));
    a.test_eax();
    a.je("end");
    a.lea_rsp(RCX, 0xB0);
    a.call_iat(r.slot("DispatchMessageW"));
    a.jmp("loop");
    a.label("end");
    a.xor32(RCX);
    a.call_iat(r.slot("ExitProcess"));
    a.int3();

    // ---- wndproc(hwnd=rcx, msg=rdx, wparam=r8, lparam=r9) -----------------
    // Frame: [0x00..0x20] shadow + 5th-arg slot at 0x20, ps @0x30, hwnd@0x70,
    //        hdc@0x78.
    a.label("wndproc");
    a.sub_rsp(0x88);
    a.mov_at_rsp_reg(0x70, RCX); // save hwnd
    a.cmp_rdx_imm8(0x0F); // WM_PAINT
    a.je("paint");
    a.cmp_rdx_imm8(0x02); // WM_DESTROY
    a.je("destroy");
    // default: DefWindowProcW(hwnd,msg,wparam,lparam) — regs already set.
    a.call_iat(r.slot("DefWindowProcW"));
    a.jmp("wp_ret");

    a.label("destroy");
    a.xor32(RCX);
    a.call_iat(r.slot("PostQuitMessage"));
    a.xor32(RAX);
    a.jmp("wp_ret");

    a.label("paint");
    a.mov_reg_at_rsp(RCX, 0x70); // hwnd
    a.lea_rsp(RDX, 0x30); // &ps
    a.call_iat(r.slot("BeginPaint"));
    a.mov_at_rsp_reg(0x78, RAX); // save hdc
    // Rectangle(hdc, 30, 40, 450, 210)
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 30);
    a.mov32(R8, 40);
    a.mov32(R9, 450);
    a.mov_at_rsp_imm(0x20, 210);
    a.call_iat(r.slot("Rectangle"));
    // TextOutW(hdc, 60, 80, line1, wlen)
    a.mov_reg_at_rsp(RCX, 0x78);
    a.mov32(RDX, 60);
    a.mov32(R8, 80);
    a.lea_rip(R9, r.line1);
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    // TextOutW(hdc, 60, 130, line2, wlen)
    a.mov_reg_at_rsp(RCX, 0x78);
    a.mov32(RDX, 60);
    a.mov32(R8, 130);
    a.lea_rip(R9, r.line2);
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE2) as i32);
    a.call_iat(r.slot("TextOutW"));
    // EndPaint(hwnd, &ps)
    a.mov_reg_at_rsp(RCX, 0x70);
    a.lea_rsp(RDX, 0x30);
    a.call_iat(r.slot("EndPaint"));
    a.xor32(RAX);

    a.label("wp_ret");
    a.add_rsp(0x88);
    a.ret();

    a.finish()
}

// ============================ mini assembler ==============================

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const R8: u8 = 8;
const R9: u8 = 9;

struct Asm {
    code: Vec<u8>,
    labels: HashMap<String, usize>,
    /// (position of rel32 field, target label) for .text-internal references.
    fixups: Vec<(usize, String)>,
}

impl Asm {
    fn new() -> Asm {
        Asm { code: Vec::new(), labels: HashMap::new(), fixups: Vec::new() }
    }

    fn label(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.code.len());
    }

    /// Emit `[rsp+disp]` addressing (SIB, base=rsp) after the opcode; `reg` is
    /// the ModRM.reg field.
    fn modrm_rsp(&mut self, reg: u8, disp: i32) {
        let reg = reg & 7;
        if (-128..=127).contains(&disp) {
            self.code.push(0x40 | (reg << 3) | 0x04); // mod=01, rm=100
            self.code.push(0x24); // SIB: base=rsp, no index
            self.code.push(disp as u8);
        } else {
            self.code.push(0x80 | (reg << 3) | 0x04); // mod=10
            self.code.push(0x24);
            self.code.extend_from_slice(&disp.to_le_bytes());
        }
    }

    fn rex(&mut self, r: u8, b: u8) {
        // REX.W + optional REX.R (reg>=8) + REX.B (base/rm>=8).
        let mut rex = 0x48;
        if r >= 8 {
            rex |= 0x04;
        }
        if b >= 8 {
            rex |= 0x01;
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
        self.rex(reg, RBX /* rsp base doesn't set REX.B */);
        self.code.push(0x89);
        self.modrm_rsp(reg, disp);
    }
    fn mov_reg_at_rsp(&mut self, reg: u8, disp: i32) {
        self.rex(reg, RBX);
        self.code.push(0x8B);
        self.modrm_rsp(reg, disp);
    }
    fn lea_rsp(&mut self, reg: u8, disp: i32) {
        self.rex(reg, RBX);
        self.code.push(0x8D);
        self.modrm_rsp(reg, disp);
    }
    fn mov_at_rsp_imm(&mut self, disp: i32, imm: i32) {
        self.code.extend_from_slice(&[0x48, 0xC7]);
        self.modrm_rsp(0, disp);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    fn mov_reg_reg(&mut self, dst: u8, src: u8) {
        // mov dst, src  (REX.W 89 /r, reg=src, rm=dst)
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
    fn jmp(&mut self, label: &str) {
        self.code.push(0xE9);
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }
    fn lea_label(&mut self, reg: u8, label: &str) {
        self.rex(reg, RBX);
        self.code.push(0x8D);
        self.code.push(0x05 | ((reg & 7) << 3)); // mod=00, rm=101 (RIP)
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }

    /// `lea reg, [rip+disp]` to an absolute .rdata RVA (known now).
    fn lea_rip(&mut self, reg: u8, target_rva: u32) {
        self.rex(reg, RBX);
        self.code.push(0x8D);
        self.code.push(0x05 | ((reg & 7) << 3));
        let next = TEXT_RVA as i64 + self.code.len() as i64 + 4;
        let disp = target_rva as i64 - next;
        self.code.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    /// `call [rip+disp]` to an IAT slot (known now).
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

// ---- byte helpers (mirrors sample.rs) --------------------------------------

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
