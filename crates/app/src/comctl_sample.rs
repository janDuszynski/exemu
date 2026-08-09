//! Generates a **common-controls** GUI PE — the roadmap W6.1 proof binary.
//!
//! Unlike [`crate::gui_sample`] (which only needs `user32`/`gdi32`), this one
//! imports **`comctl32.dll`**, calls `InitCommonControlsEx`, and then creates
//! two child controls of its main window — a `BUTTON` (a user32 built-in) and a
//! `msctls_progress32` progress bar (registered by comctl32) — before painting
//! its client area and pumping messages.
//!
//! Under the Wine boot every one of those calls is **guest PE code**: the
//! `comctl32.dll` the loader maps is Wine's own binary, its `DllMain` runs, and
//! `InitCommonControlsEx` registers the control classes through Wine's user32 →
//! `win32u` → exemu's `NtUserRegisterClassExWOW`. The W6 claim ("these DLLs cost
//! exemu almost nothing because they are just guest code") is exactly what this
//! binary exists to test.
//!
//! **What this binary actually reaches today** (measured — see
//! `tests/comctl_gate.rs`): Wine's comctl32 loads, `InitCommonControlsEx`
//! succeeds, `msctls_progress32` is registered as a real class with a real
//! WndProc, the progress-bar child window is created with the right parent /
//! geometry / style, and (since W6.2) the built-in `BUTTON` child is created too
//! and **all three windows receive `WM_NCCREATE` + `WM_CREATE`** — the sample's
//! own WndProc proves it by reading its `CREATESTRUCTW` back. One gap is pinned
//! in the code below: sending a message to a comctl32 control does not
//! terminate.
//!
//! The code is hand-assembled x86-64 with a small local assembler (`Asm`), the
//! same shape [`crate::gui_sample`] and [`crate::sample`] use, so branch targets
//! and RIP-relative references stay correct.

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
/// The `BUTTON` class is a user32 built-in; `msctls_progress32` is registered by
/// comctl32's `InitCommonControlsEx` (`ICC_PROGRESS_CLASS`).
const BUTTON_CLASS: &str = "BUTTON";
const BUTTON_TEXT: &str = "Push me";
const PROGRESS_CLASS: &str = "msctls_progress32";
const PAINT_LINE1: &str = "Wine comctl32 controls under exemu.";
const PAINT_LINE2: &str = "InitCommonControlsEx + BUTTON + progress bar.";

/// Client geometry of the main window — the surface the presenter flushes.
pub const WINDOW_CX: i32 = 520;
pub const WINDOW_CY: i32 = 300;

/// `INITCOMMONCONTROLSEX.dwICC` — `ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES`:
/// the progress bar, toolbar/statusbar/trackbar/tooltip, tab, updown, listview,
/// treeview, hotkey and animate classes plus the user32 standard set.
const ICC_FLAGS: i32 = 0x0000_00FF | 0x0000_4000;

/// The two child-control IDs (the `hMenu` argument of `CreateWindowExW`).
const ID_BUTTON: i32 = 100;
const ID_PROGRESS: i32 = 101;

/// The `lpParam` the main window is created with, and therefore the value its
/// `WM_CREATE` must find in `CREATESTRUCTW.lpCreateParams` (roadmap W6.2). The
/// WndProc only reports the creation if this round-trips, so the gate's
/// observation is proof the struct — not just the message — arrived intact.
pub const CREATE_PARAM_MAGIC: i32 = 0x5A5A_1234;

// --- CREATESTRUCTW (64-bit) field offsets the WndProc reads ------------------
/// `lpCreateParams` — the `lpParam` passed to `CreateWindowExW`.
const CS_LP_CREATE_PARAMS: i8 = 0x00;
/// `lpszClass` — the class name, as a NUL-terminated `LPCWSTR`.
const CS_LPSZ_CLASS: i8 = 0x40;

// --- window messages the sample's WndProc handles ---------------------------
const WM_CREATE: i32 = 0x0001;
const WM_NCCREATE: i32 = 0x0081;


/// Build the common-controls sample executable.
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

/// The imports, grouped by DLL and in IAT order. `comctl32.dll` is the point of
/// the exercise: a static import forces the loader to map + relocate + bind
/// Wine's comctl32 and run its `DllMain` before the entry point.
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

/// The wide strings the sample references, in `.rdata` order.
const WIDE_STRINGS: [&str; 7] = [
    CLASS_NAME,
    WINDOW_TITLE,
    BUTTON_CLASS,
    BUTTON_TEXT,
    PROGRESS_CLASS,
    PAINT_LINE1,
    PAINT_LINE2,
];

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    /// Import name → its IAT slot RVA.
    iat: HashMap<String, u32>,
    /// Wide-string RVAs, parallel to [`WIDE_STRINGS`].
    strings: Vec<u32>,
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
        pos = align_up_u32(pos, 2);
        let mut strings: Vec<u32> = Vec::with_capacity(WIDE_STRINGS.len());
        for s in WIDE_STRINGS {
            strings.push(RDATA_RVA + pos);
            pos += wide(s).len() as u32;
        }

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

    /// RVA of one of the [`WIDE_STRINGS`], by value.
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

/// UTF-16 code-unit count excluding the terminator — the `c` argument `TextOutW`
/// takes.
fn wlen(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

// ---- WinMain frame layout ---------------------------------------------------
// [0x00..0x60] shadow + outgoing stack args (CreateWindowExW takes 12)
// [0x60..0xA8] WNDCLASSW (0x48 bytes, explicitly zeroed)
// [0xB0..0xE0] MSG
// [0xE0..0xE8] INITCOMMONCONTROLSEX { DWORD dwSize; DWORD dwICC; }
// [0xE8]       hButton   [0xF0] hProgress   [0xF8] scratch (hdc)
const FRAME: u32 = 0x108;
const WC: i32 = 0x60;
const MSG: i32 = 0xB0;
const ICC: i32 = 0xE0;
const H_BUTTON: i32 = 0xE8;
const H_PROGRESS: i32 = 0xF0;
const SCRATCH: i32 = 0xF8;

// WNDCLASSW field offsets (64-bit).
const WC_WNDPROC: i32 = 0x08;
const WC_CLASSNAME: i32 = 0x40;
const WC_SIZE: i32 = 0x48;

const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
/// `WS_CHILD | WS_VISIBLE`.
const WS_CHILD_VISIBLE: u32 = 0x5000_0000;
/// `WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON`.
const WS_CHILD_BUTTON: u32 = 0x5000_0001;

fn build_text(r: &Rdata) -> Vec<u8> {
    let mut a = Asm::new();

    // ---- entry / WinMain --------------------------------------------------
    a.sub_rsp(FRAME);

    // InitCommonControlsEx(&icc) — the first call into Wine's comctl32, which
    // registers the common-control window classes.
    a.mov_at_rsp_imm32(ICC, 8); // dwSize = sizeof(INITCOMMONCONTROLSEX)
    a.mov_at_rsp_imm32(ICC + 4, ICC_FLAGS); // dwICC
    a.lea_rsp(RCX, ICC);
    a.call_iat(r.slot("InitCommonControlsEx"));

    // WNDCLASSW: zero the whole struct, then fill lpfnWndProc + lpszClassName.
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

    // The main window.
    a.xor32(RCX); // exStyle
    a.lea_rip(RDX, r.wstr(CLASS_NAME));
    a.lea_rip(R8, r.wstr(WINDOW_TITLE));
    a.mov32(R9, WS_OVERLAPPEDWINDOW);
    a.mov_at_rsp_imm(0x20, 120); // X
    a.mov_at_rsp_imm(0x28, 120); // Y
    a.mov_at_rsp_imm(0x30, WINDOW_CX); // nWidth
    a.mov_at_rsp_imm(0x38, WINDOW_CY); // nHeight
    a.mov_at_rsp_imm(0x40, 0); // hWndParent
    a.mov_at_rsp_imm(0x48, 0); // hMenu
    a.mov_at_rsp_imm(0x50, 0); // hInstance
    // lpParam: the WM_CREATE proof value (roadmap W6.2) — the WndProc reports the
    // creation only if it reads this back out of CREATESTRUCTW.lpCreateParams.
    a.mov_at_rsp_imm(0x58, CREATE_PARAM_MAGIC);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_reg_reg(RBX, RAX); // save hwnd

    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 5); // SW_SHOW
    a.call_iat(r.slot("ShowWindow"));

    // ---- the common controls ----------------------------------------------
    // A BUTTON child (user32's *built-in* control class). Wine's user32 leaves
    // the built-in control classes (BUTTON/EDIT/STATIC/…) to the kernel side;
    // since W6.2 exemu's win32k pre-registers them against the WndProcs user32
    // publishes through `NtUserInitializeClientPfnArrays`, so this reaches
    // `NtUserCreateWindowEx` and the driver sees a real child window.
    a.xor32(RCX);
    a.lea_rip(RDX, r.wstr(BUTTON_CLASS));
    a.lea_rip(R8, r.wstr(BUTTON_TEXT));
    a.mov32(R9, WS_CHILD_BUTTON);
    a.mov_at_rsp_imm(0x20, 24); // X
    a.mov_at_rsp_imm(0x28, 200); // Y
    a.mov_at_rsp_imm(0x30, 140); // nWidth
    a.mov_at_rsp_imm(0x38, 32); // nHeight
    a.mov_at_rsp_reg(0x40, RBX); // hWndParent
    a.mov_at_rsp_imm(0x48, ID_BUTTON); // hMenu = control id
    a.mov_at_rsp_imm(0x50, 0);
    a.mov_at_rsp_imm(0x58, 0);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_at_rsp_reg(H_BUTTON, RAX);

    // A msctls_progress32 child — the comctl32-registered control.
    a.xor32(RCX);
    a.lea_rip(RDX, r.wstr(PROGRESS_CLASS));
    a.xor32(R8); // no window text
    a.mov32(R9, WS_CHILD_VISIBLE);
    a.mov_at_rsp_imm(0x20, 184); // X
    a.mov_at_rsp_imm(0x28, 204); // Y
    a.mov_at_rsp_imm(0x30, 300); // nWidth
    a.mov_at_rsp_imm(0x38, 24); // nHeight
    a.mov_at_rsp_reg(0x40, RBX); // hWndParent
    a.mov_at_rsp_imm(0x48, ID_PROGRESS); // hMenu = control id
    a.mov_at_rsp_imm(0x50, 0);
    a.mov_at_rsp_imm(0x58, 0);
    a.call_iat(r.slot("CreateWindowExW"));
    a.mov_at_rsp_reg(H_PROGRESS, RAX);

    // NOTE (verified W6.1 blocker): driving the progress bar with
    // `SendMessageW(hProgress, PBM_SETRANGE/PBM_SETPOS, …)` does **not**
    // terminate today. The message reaches `NtUserMessageCall`, which dispatches
    // to comctl32's real control WndProc; that path then spins forever calling
    // the unserviced `WineUnixCall` import thunk (observed: >400M instructions,
    // an endless `[exemu] call WineUnixCall` trace). So the sample creates the
    // control but does not message it; `SendMessageW` stays imported so the
    // binary keeps the shape a real app has.

    // ---- direct paint ------------------------------------------------------
    // As in gui_sample: paint once without waiting for a message pump, so the
    // surface/present pipeline is exercised even with no input channel attached.
    a.mov_reg_reg(RCX, RBX); // hwnd
    a.call_iat(r.slot("GetDC"));
    a.mov_at_rsp_reg(SCRATCH, RAX);
    // TextOutW(hdc, 16, 16, line1, wlen)
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 16);
    a.mov32(R8, 16);
    a.lea_rip(R9, r.wstr(PAINT_LINE1));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    // TextOutW(hdc, 16, 44, line2, wlen)
    a.mov_reg_at_rsp(RCX, SCRATCH);
    a.mov32(RDX, 16);
    a.mov32(R8, 44);
    a.lea_rip(R9, r.wstr(PAINT_LINE2));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE2) as i32);
    a.call_iat(r.slot("TextOutW"));
    // Rectangle(hdc, 12, 84, 500, 180) — a frame around the control strip.
    a.mov_reg_at_rsp(RCX, SCRATCH);
    a.mov32(RDX, 12);
    a.mov32(R8, 84);
    a.mov32(R9, 500);
    a.mov_at_rsp_imm(0x20, 180);
    a.call_iat(r.slot("Rectangle"));
    // ReleaseDC(hwnd, hdc) — the present point.
    a.mov_reg_reg(RCX, RBX);
    a.mov_reg_at_rsp(RDX, SCRATCH);
    a.call_iat(r.slot("ReleaseDC"));

    // ---- message loop ------------------------------------------------------
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

    // ---- wndproc(hwnd=rcx, msg=rdx, wparam=r8, lparam=r9) -----------------
    // Frame: [0x00..0x20] shadow + 5th-arg slot at 0x20, PAINTSTRUCT @0x30
    //        (72 bytes → 0x30..0x78), hwnd@0x80, hdc@0x88.
    const WP_FRAME: u32 = 0xC8;
    const WP_PS: i32 = 0x30;
    const WP_HWND: i32 = 0x80;
    const WP_HDC: i32 = 0x88;
    a.label("wndproc");
    a.sub_rsp(WP_FRAME);
    a.mov_at_rsp_reg(WP_HWND, RCX);
    a.cmp_rdx_imm8(0x0F); // WM_PAINT
    a.je("paint");
    a.cmp_rdx_imm8(0x02); // WM_DESTROY
    a.je("destroy");
    a.cmp_rdx_imm32(WM_NCCREATE);
    a.je("nccreate");
    a.cmp_rdx_imm32(WM_CREATE);
    a.je("create");
    a.call_iat(r.slot("DefWindowProcW"));
    a.jmp("wp_ret");

    // WM_NCCREATE → TRUE ("keep creating me"), the documented contract. Handled
    // here rather than deferred to DefWindowProcW **on purpose**: under the
    // current Wine boot `user32!DefWindowProcW` forwards to
    // `NTDLL.NtdllDefWindowProc_W`, which resolves into a *second*, dead ntdll
    // image (see the module note in `tests/comctl_gate.rs`) and tail-jumps
    // through a null slot. Every real WndProc handles its own WM_NCCREATE /
    // WM_CREATE anyway, so this is ordinary Win32 code, not a workaround shape.
    a.label("nccreate");
    a.mov32(RAX, 1);
    a.jmp("wp_ret");

    // WM_CREATE → read CREATESTRUCTW.lpCreateParams (r9 = lParam); only if it
    // carries the magic the window was created with does the WndProc report the
    // creation, by setting the window text to CREATESTRUCTW.lpszClass. That one
    // driver call is the gate's evidence that the whole struct arrived intact.
    a.label("create");
    a.cmp_at_r9_imm32(CS_LP_CREATE_PARAMS, CREATE_PARAM_MAGIC);
    a.jne("create_done");
    a.mov_rdx_at_r9(CS_LPSZ_CLASS); // lpszClass
    a.mov_reg_at_rsp(RCX, WP_HWND);
    a.call_iat(r.slot("SetWindowTextW"));
    a.label("create_done");
    a.xor32(RAX); // WM_CREATE: 0 = continue creation
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
    // Rectangle(hdc, 12, 84, 500, 180)
    a.mov_reg_reg(RCX, RAX);
    a.mov32(RDX, 12);
    a.mov32(R8, 84);
    a.mov32(R9, 500);
    a.mov_at_rsp_imm(0x20, 180);
    a.call_iat(r.slot("Rectangle"));
    // TextOutW(hdc, 16, 16, line1, wlen)
    a.mov_reg_at_rsp(RCX, WP_HDC);
    a.mov32(RDX, 16);
    a.mov32(R8, 16);
    a.lea_rip(R9, r.wstr(PAINT_LINE1));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE1) as i32);
    a.call_iat(r.slot("TextOutW"));
    // TextOutW(hdc, 16, 44, line2, wlen)
    a.mov_reg_at_rsp(RCX, WP_HDC);
    a.mov32(RDX, 16);
    a.mov32(R8, 44);
    a.lea_rip(R9, r.wstr(PAINT_LINE2));
    a.mov_at_rsp_imm(0x20, wlen(PAINT_LINE2) as i32);
    a.call_iat(r.slot("TextOutW"));
    // EndPaint(hwnd, &ps)
    a.mov_reg_at_rsp(RCX, WP_HWND);
    a.lea_rsp(RDX, WP_PS);
    a.call_iat(r.slot("EndPaint"));
    a.xor32(RAX);

    a.label("wp_ret");
    a.add_rsp(WP_FRAME);
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

    fn rex(&mut self, r: u8) {
        // REX.W + optional REX.R (reg>=8). The rsp base never needs REX.B.
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
    /// `mov qword [rsp+disp], imm32` (sign-extended).
    fn mov_at_rsp_imm(&mut self, disp: i32, imm: i32) {
        self.code.extend_from_slice(&[0x48, 0xC7]);
        self.modrm_rsp(0, disp);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    /// `mov dword [rsp+disp], imm32` — the DWORD fields of INITCOMMONCONTROLSEX.
    fn mov_at_rsp_imm32(&mut self, disp: i32, imm: i32) {
        self.code.push(0xC7);
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
    /// `cmp rdx, imm32` — the message ids above 0x7F (`WM_NCCREATE` = 0x81).
    fn cmp_rdx_imm32(&mut self, imm: i32) {
        self.code.extend_from_slice(&[0x48, 0x81, 0xFA]);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    /// `cmp qword [r9+disp8], imm32` — test a field of the `CREATESTRUCTW` lParam.
    fn cmp_at_r9_imm32(&mut self, disp: i8, imm: i32) {
        self.code.extend_from_slice(&[0x49, 0x81, 0x79, disp as u8]);
        self.code.extend_from_slice(&imm.to_le_bytes());
    }
    /// `mov rdx, qword [r9+disp8]` — load a `CREATESTRUCTW` field into an arg.
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
        self.code.push(0x05 | ((reg & 7) << 3)); // mod=00, rm=101 (RIP)
        self.fixups.push((self.code.len(), label.to_string()));
        self.code.extend_from_slice(&[0, 0, 0, 0]);
    }

    /// `lea reg, [rip+disp]` to an absolute .rdata RVA (known now).
    fn lea_rip(&mut self, reg: u8, target_rva: u32) {
        self.rex(reg);
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

// ---- byte helpers (mirrors gui_sample.rs) -----------------------------------

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

    /// The generated image is a PE32+ GUI executable that statically imports
    /// `comctl32!InitCommonControlsEx` plus the two control class names — the
    /// shape the W6.1 gate depends on.
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

        // The control class names travel in .rdata as UTF-16.
        let needle = wide(PROGRESS_CLASS);
        assert!(
            exe.windows(needle.len()).any(|w| w == needle),
            "the msctls_progress32 class name is in the image"
        );
    }
}
