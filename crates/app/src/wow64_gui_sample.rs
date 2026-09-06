//! Generates the **WoW64 client-callback** proof binary — a **PE32** program
//! that registers a window class whose procedure is its own 32-bit code, creates
//! the window, and checks what that procedure was told (roadmap W5.10).
//!
//! This is the positive gate for the one path exemu's win32k could not take in a
//! WoW64 process. Every hop after the guest's `call [IAT]` belongs to Wine or to
//! exemu's kernel side — nothing here is synthesized:
//!
//! ```text
//!   <guest>.exe (PE32)  call [IAT]
//!     → user32(i386)!CreateWindowExW  → win32u(i386) → the wow64cpu BOP
//!     → wow64.dll → wow64win!wow64_NtUserCreateWindowEx → win32u(x64) → SYSCALL
//!     → exemu's win32k: NtUserCreateWindowEx
//!         …which owes the window WM_NCCREATE/WM_CREATE, so instead of
//!           returning it resumes user mode at
//!     → ntdll!KiUserCallbackDispatcher (id = NtUserCallWinProc)
//!     → wow64win!user_callbacks[4] → wow64!Wow64KiUserCallbackDispatcher
//!     → BTCpuSimulate → ntdll32!KiUserCallbackDispatcher
//!     → user32(i386)!User32CallWinProc → call_window_proc
//!     → **the guest's own WndProc, in 32-bit mode, stdcall**
//!     → ntdll32!NtCallbackReturn → the BOP → wow64.dll slot 5 → longjmp
//!     → the 64-bit NtCallbackReturn → exemu resumes NtUserCreateWindowEx
//! ```
//!
//! What the guest checks, and why each check is load-bearing:
//!
//! 1. **`WM_NCCREATE` and `WM_CREATE` both arrive.** Before W5.10 neither did:
//!    exemu declined the callback rather than run 32-bit bytes in long mode.
//! 2. **The `WM_NCCREATE` `lParam` is a usable 32-bit `CREATESTRUCTW`.** The
//!    procedure reads `style` back out of it at the **32-bit** offset `0x20`. A
//!    struct parked on the process's 64-bit stack (`0x10_0000_0000`) would
//!    arrive truncated, and a 64-bit layout would put `style` at `0x30`.
//! 3. **A `SendMessageW` LRESULT makes the whole round trip.** The procedure
//!    answers a private message with [`PROBE_LRESULT`]; the guest compares what
//!    `SendMessageW` returned. That value travels
//!    WndProc → `NtCallbackReturn` → exemu's kernel → back out through
//!    `wow64win` — so it is proof the *return* half works, not just the call.
//! 4. **`esp` is unchanged across the whole sequence**, i.e. every `stdcall`
//!    frame the kernel built was popped by the callee that was handed it.
//!
//! The exit code says which check failed, so a partial run is diagnosable
//! without a debugger.

const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 96 + 16 * 8;

/// Exit code when every check held.
pub const GUI_OK_EXIT: i32 = 71;
/// `CreateWindowExW` returned NULL.
pub const GUI_FAIL_NO_HWND_EXIT: i32 = 72;
/// The window procedure did not see both creation messages (and the private
/// probe). The mask it *did* see is in [`data::SEEN`].
pub const GUI_FAIL_MESSAGES_EXIT: i32 = 73;
/// The `WM_NCCREATE` `lParam` did not carry the style the guest asked for at the
/// 32-bit `CREATESTRUCTW` offset.
pub const GUI_FAIL_CREATESTRUCT_EXIT: i32 = 74;
/// `SendMessageW` did not return what the window procedure returned.
pub const GUI_FAIL_LRESULT_EXIT: i32 = 75;
/// `RegisterClassW` returned a zero ATOM.
pub const GUI_FAIL_NO_ATOM_EXIT: i32 = 76;

/// `WM_NCCREATE`.
pub const WM_NCCREATE: u32 = 0x0081;
/// `WM_CREATE`.
pub const WM_CREATE: u32 = 0x0001;
/// The private message the guest sends itself to measure the return path
/// (`WM_APP`).
pub const WM_PROBE: u32 = 0x8000;
/// What the window procedure answers [`WM_PROBE`] with. Positive as an `i32`, so
/// the sign-extension `wow64win` performs on the way back is not what carries it.
pub const PROBE_LRESULT: u32 = 0x5EED_1234;
/// The window style the guest asks for, and reads back out of the
/// `CREATESTRUCTW` its procedure is handed. `WS_OVERLAPPEDWINDOW`.
pub const WINDOW_STYLE: u32 = 0x00CF_0000;
/// `CREATESTRUCTW.style` on **32-bit** (it is at `0x30` on 64-bit — reading the
/// right one is half the point of this binary).
pub const CREATESTRUCT32_STYLE: u32 = 0x20;

/// Bits [`data::SEEN`] accumulates, one per message the procedure was handed.
pub mod seen {
    /// `WM_NCCREATE` arrived.
    pub const NCCREATE: u32 = 1;
    /// `WM_CREATE` arrived.
    pub const CREATE: u32 = 2;
    /// The private probe arrived.
    pub const PROBE: u32 = 4;
    /// All three.
    pub const ALL: u32 = NCCREATE | CREATE | PROBE;
}

/// `.data` offsets (from [`DATA_RVA`]) the gate reads back out of guest memory.
pub mod data {
    /// Bitmask of [`super::seen`] bits.
    pub const SEEN: u32 = 0x00;
    /// The `hwnd` the window procedure was handed on `WM_NCCREATE`.
    pub const PROC_HWND: u32 = 0x04;
    /// The `WM_NCCREATE` `lParam` — the `CREATESTRUCTW` pointer.
    pub const CS_PTR: u32 = 0x08;
    /// `style` read back out of that struct at the 32-bit offset.
    pub const CS_STYLE: u32 = 0x0c;
    /// The `HWND` `CreateWindowExW` returned.
    pub const HWND: u32 = 0x10;
    /// What `SendMessageW` returned.
    pub const SEND_RESULT: u32 = 0x14;
    /// The ATOM `RegisterClassW` returned.
    pub const ATOM: u32 = 0x18;
    /// `esp` before `RegisterClassW` and after `SendMessageW` — equal iff every
    /// `stdcall` frame unwound.
    pub const ESP_BEFORE: u32 = 0x1c;
    /// …and after.
    pub const ESP_AFTER: u32 = 0x20;
    /// The `WNDCLASSW` the guest fills in place (32-bit layout, 0x28 bytes).
    pub const WNDCLASS: u32 = 0x40;
    /// Total bytes of `.data`.
    pub const LEN: u32 = 0x80;
}

/// Absolute VA of a `.data` cell in the built image.
pub const fn data_va(off: u32) -> u64 {
    (IMAGE_BASE + DATA_RVA + off) as u64
}

/// The imports, in IAT order. Two DLLs: the window API the guest drives, and the
/// one `Nt*` it needs to report an exit code.
const IMPORTS: [(&str, &[&str]); 2] =
    [("user32.dll", &["RegisterClassW", "CreateWindowExW", "SendMessageW", "DefWindowProcW"]), ("ntdll.dll", &["NtTerminateProcess"])];

/// IAT slot indices, in the order [`IMPORTS`] lists them.
const I_REGISTER_CLASS: u32 = 0;
const I_CREATE_WINDOW: u32 = 1;
const I_SEND_MESSAGE: u32 = 2;
const I_DEF_WINDOW_PROC: u32 = 3;
const I_TERMINATE: u32 = 4;

/// Build the PE32 WoW64 client-callback sample.
pub fn build() -> Vec<u8> {
    // --- .rdata: import descriptors + ILT/IAT + name blobs ----------------
    let ndlls = IMPORTS.len() as u32;
    let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
    let import_dir_size = (ndlls + 1) * 20;
    let ilt_off = import_dir_size;
    // One null-terminated thunk array per DLL, laid out back to back.
    let thunks: u32 = nfuncs + ndlls;
    let iat_off = ilt_off + thunks * 4;
    debug_assert_eq!(iat_off, self::iat_off(), "iat_off() must match the emitted layout");

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
    pos = align_up_u32(pos, 2);
    let class_rva = RDATA_RVA + pos;
    let class_name: Vec<u8> = wide("ExemuW510Class");
    pos += class_name.len() as u32;
    let title_rva = RDATA_RVA + pos;
    let title: Vec<u8> = wide("W5.10");
    pos += title.len() as u32;

    let mut rd = vec![0u8; pos as usize];
    let mut thunk = 0u32;
    let mut fi = 0usize;
    for (di, (dll, funcs)) in IMPORTS.iter().enumerate() {
        let d = di * 20;
        put_u32(&mut rd, d, RDATA_RVA + ilt_off + thunk * 4); // OriginalFirstThunk
        put_u32(&mut rd, d + 12, dll_rva[di]); // Name
        put_u32(&mut rd, d + 16, RDATA_RVA + iat_off + thunk * 4); // FirstThunk
        for _ in *funcs {
            put_u32(&mut rd, (ilt_off + thunk * 4) as usize, ibn_rva[fi]);
            put_u32(&mut rd, (iat_off + thunk * 4) as usize, ibn_rva[fi]);
            thunk += 1;
            fi += 1;
        }
        thunk += 1; // the array's null terminator
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
    let o = (class_rva - RDATA_RVA) as usize;
    rd[o..o + class_name.len()].copy_from_slice(&class_name);
    let o = (title_rva - RDATA_RVA) as usize;
    rd[o..o + title.len()].copy_from_slice(&title);

    // Note the ILT/IAT hole for each DLL's terminator: `iat(i)` must skip it.
    let iat = |i: u32| {
        let mut slot = 0u32;
        let mut seen = 0u32;
        for (_, funcs) in IMPORTS {
            for _ in funcs {
                if seen == i {
                    return IMAGE_BASE + RDATA_RVA + iat_off + slot * 4;
                }
                seen += 1;
                slot += 1;
            }
            slot += 1;
        }
        unreachable!()
    };

    let text = build_text(&iat, IMAGE_BASE + class_rva, IMAGE_BASE + title_rva);

    // --- assemble the file ------------------------------------------------
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
    put_u16(&mut f, coff, 0x014C); // IMAGE_FILE_MACHINE_I386
    put_u16(&mut f, coff + 2, 3);
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA + data::LEN, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x10B); // PE32
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA);
    put_u32(&mut f, opt + 24, RDATA_RVA);
    put_u32(&mut f, opt + 28, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 2); // WINDOWS_GUI
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
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", rd.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", data::LEN, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

/// Offset of the IAT within `.rdata`.
fn iat_off() -> u32 {
    let ndlls = IMPORTS.len() as u32;
    let nfuncs: u32 = IMPORTS.iter().map(|(_, f)| f.len() as u32).sum();
    (ndlls + 1) * 20 + (nfuncs + ndlls) * 4
}

/// UTF-16LE, NUL-terminated.
fn wide(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0]);
    v
}

/// The 32-bit `.text`: the window procedure first (so its VA is known before
/// the entry point that registers it), then the program.
fn build_text(iat: &dyn Fn(u32) -> u32, class_va: u32, title_va: u32) -> Vec<u8> {
    let cell = |off: u32| IMAGE_BASE + DATA_RVA + off;
    let wc = cell(data::WNDCLASS);
    let mut c: Vec<u8> = Vec::new();

    // --- The entry point has to be first: it is `AddressOfEntryPoint`. Jump
    //     over the procedure so the procedure's VA is a fixed offset from it.
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp rel32 → main (patched below)

    // --- LRESULT CALLBACK WndProc(hwnd, msg, wParam, lParam) --------------
    // stdcall: [esp+4]=hwnd [esp+8]=msg [esp+0xc]=wParam [esp+0x10]=lParam.
    let wndproc_off = c.len();
    c.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]); // mov eax, [esp+8]   (msg)

    // if (msg == WM_NCCREATE) { seen |= 1; record hwnd + lParam + style; return 1 }
    c.extend_from_slice(&[0x3D]); // cmp eax, imm32
    c.extend_from_slice(&WM_NCCREATE.to_le_bytes());
    let jne_nc = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne rel32
    emit_or_cell(&mut c, cell(data::SEEN), seen::NCCREATE);
    c.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x04]); // mov ecx, [esp+4]   (hwnd)
    c.extend_from_slice(&[0x89, 0x0D]); // mov [PROC_HWND], ecx
    c.extend_from_slice(&cell(data::PROC_HWND).to_le_bytes());
    c.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]); // mov ecx, [esp+0x10] (lParam)
    c.extend_from_slice(&[0x89, 0x0D]); // mov [CS_PTR], ecx
    c.extend_from_slice(&cell(data::CS_PTR).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    let jz_nocs = c.len();
    c.extend_from_slice(&[0x74, 0x00]); // jz → skip the struct read
    c.extend_from_slice(&[0x8B, 0x91]); // mov edx, [ecx + CREATESTRUCT32_STYLE]
    c.extend_from_slice(&CREATESTRUCT32_STYLE.to_le_bytes());
    c.extend_from_slice(&[0x89, 0x15]); // mov [CS_STYLE], edx
    c.extend_from_slice(&cell(data::CS_STYLE).to_le_bytes());
    patch_rel8(&mut c, jz_nocs);
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1 (TRUE)
    c.extend_from_slice(&[0xC2, 0x10, 0x00]); // ret 0x10
    patch_rel32(&mut c, jne_nc);

    // if (msg == WM_CREATE) { seen |= 2; return 0 }
    c.extend_from_slice(&[0x3D]);
    c.extend_from_slice(&WM_CREATE.to_le_bytes());
    let jne_cr = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    emit_or_cell(&mut c, cell(data::SEEN), seen::CREATE);
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0xC2, 0x10, 0x00]); // ret 0x10
    patch_rel32(&mut c, jne_cr);

    // if (msg == WM_PROBE) { seen |= 4; return PROBE_LRESULT }
    c.extend_from_slice(&[0x3D]);
    c.extend_from_slice(&WM_PROBE.to_le_bytes());
    let jne_pr = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
    emit_or_cell(&mut c, cell(data::SEEN), seen::PROBE);
    c.extend_from_slice(&[0xB8]); // mov eax, imm32
    c.extend_from_slice(&PROBE_LRESULT.to_le_bytes());
    c.extend_from_slice(&[0xC2, 0x10, 0x00]); // ret 0x10
    patch_rel32(&mut c, jne_pr);

    // Everything else: tail-jump to DefWindowProcW with the frame untouched —
    // the same shape Wine's own window procedures use.
    c.extend_from_slice(&[0xFF, 0x25]);
    c.extend_from_slice(&iat(I_DEF_WINDOW_PROC).to_le_bytes());

    // --- main -------------------------------------------------------------
    let main_off = c.len();
    let disp = (main_off - 5) as u32;
    c[1..5].copy_from_slice(&disp.to_le_bytes());
    let wndproc_va = IMAGE_BASE + TEXT_RVA + wndproc_off as u32;

    c.extend_from_slice(&[0x89, 0x25]); // mov [ESP_BEFORE], esp
    c.extend_from_slice(&cell(data::ESP_BEFORE).to_le_bytes());
    // WNDCLASSW: lpfnWndProc, hInstance, lpszClassName. The rest stays zero.
    emit_store_imm(&mut c, wc + 0x04, wndproc_va);
    emit_store_imm(&mut c, wc + 0x10, IMAGE_BASE);
    emit_store_imm(&mut c, wc + 0x24, class_va);

    // RegisterClassW(&wc)
    c.push(0x68);
    c.extend_from_slice(&wc.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_REGISTER_CLASS).to_le_bytes());
    c.push(0xA3); // mov [ATOM], eax
    c.extend_from_slice(&cell(data::ATOM).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    let jnz_atom = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_NO_ATOM_EXIT as u32);
    patch_rel8(&mut c, jnz_atom);

    // CreateWindowExW(0, class, title, WINDOW_STYLE, 10, 20, 200, 120,
    //                 NULL, NULL, IMAGE_BASE, NULL) — 12 args, right to left.
    for imm in [0u32, IMAGE_BASE, 0, 0, 120, 200, 20, 10, WINDOW_STYLE, title_va, class_va, 0] {
        c.push(0x68);
        c.extend_from_slice(&imm.to_le_bytes());
    }
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_CREATE_WINDOW).to_le_bytes());
    c.push(0xA3); // mov [HWND], eax
    c.extend_from_slice(&cell(data::HWND).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC0]);
    let jnz_hwnd = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_NO_HWND_EXIT as u32);
    patch_rel8(&mut c, jnz_hwnd);

    // SendMessageW(hwnd, WM_PROBE, 0x1111, 0x2222)
    for imm in [0x2222u32, 0x1111, WM_PROBE] {
        c.push(0x68);
        c.extend_from_slice(&imm.to_le_bytes());
    }
    c.push(0x50); // push eax (hwnd)
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat(I_SEND_MESSAGE).to_le_bytes());
    c.push(0xA3); // mov [SEND_RESULT], eax
    c.extend_from_slice(&cell(data::SEND_RESULT).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x25]); // mov [ESP_AFTER], esp
    c.extend_from_slice(&cell(data::ESP_AFTER).to_le_bytes());

    // if (seen != ALL) exit(GUI_FAIL_MESSAGES_EXIT)
    emit_cmp_cell(&mut c, cell(data::SEEN), seen::ALL);
    let je_seen = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_MESSAGES_EXIT as u32);
    patch_rel8(&mut c, je_seen);

    // if (cs_style != WINDOW_STYLE) exit(GUI_FAIL_CREATESTRUCT_EXIT)
    emit_cmp_cell(&mut c, cell(data::CS_STYLE), WINDOW_STYLE);
    let je_style = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_CREATESTRUCT_EXIT as u32);
    patch_rel8(&mut c, je_style);

    // if (send_result != PROBE_LRESULT) exit(GUI_FAIL_LRESULT_EXIT)
    emit_cmp_cell(&mut c, cell(data::SEND_RESULT), PROBE_LRESULT);
    let je_res = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat(I_TERMINATE), GUI_FAIL_LRESULT_EXIT as u32);
    patch_rel8(&mut c, je_res);

    emit_exit(&mut c, iat(I_TERMINATE), GUI_OK_EXIT as u32);
    c.push(0xF4); // hlt — NtTerminateProcess does not return
    c
}

/// `or dword ptr [abs32], imm32`.
fn emit_or_cell(c: &mut Vec<u8>, at: u32, v: u32) {
    c.extend_from_slice(&[0x81, 0x0D]);
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&v.to_le_bytes());
}

/// `mov dword ptr [abs32], imm32`.
fn emit_store_imm(c: &mut Vec<u8>, at: u32, v: u32) {
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&v.to_le_bytes());
}

/// `mov eax,[abs32]; cmp eax, imm32`.
fn emit_cmp_cell(c: &mut Vec<u8>, at: u32, v: u32) {
    c.push(0xA1);
    c.extend_from_slice(&at.to_le_bytes());
    c.push(0x3D);
    c.extend_from_slice(&v.to_le_bytes());
}

/// `NtTerminateProcess(NtCurrentProcess, code)` — stdcall, 2 arguments.
fn emit_exit(c: &mut Vec<u8>, iat_terminate: u32, code: u32) {
    c.push(0x68);
    c.extend_from_slice(&code.to_le_bytes());
    c.push(0x68);
    c.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat_terminate.to_le_bytes());
}

fn patch_rel8(c: &mut [u8], at: usize) {
    let disp = c.len() - (at + 2);
    assert!(disp < 128, "wow64 gui sample: rel8 branch out of range ({disp})");
    c[at + 1] = disp as u8;
}

fn patch_rel32(c: &mut [u8], at: usize) {
    let disp = (c.len() - (at + 6)) as u32;
    c[at + 2..at + 6].copy_from_slice(&disp.to_le_bytes());
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

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn align_up_u32(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The built image parses as a PE32 whose imports name both DLLs and every
    /// function, and whose entry point is the jump over the window procedure.
    #[test]
    fn the_sample_is_a_pe32_importing_user32_and_ntdll() {
        let bytes = build();
        let img = exemu_loader::parse(&bytes).expect("the sample parses");
        assert!(!img.is_64bit, "a WoW64 guest is a PE32");
        let mut named: Vec<String> = img
            .imports
            .iter()
            .filter_map(|i| match &i.symbol {
                exemu_core::ImportSymbol::Named(n) => Some(format!("{}!{n}", i.dll.to_ascii_lowercase())),
                exemu_core::ImportSymbol::Ordinal(_) => None,
            })
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                "ntdll.dll!NtTerminateProcess",
                "user32.dll!CreateWindowExW",
                "user32.dll!DefWindowProcW",
                "user32.dll!RegisterClassW",
                "user32.dll!SendMessageW",
            ],
        );
        // Each IAT slot is distinct — the per-DLL terminator must not alias one.
        let mut slots: Vec<u32> = img.imports.iter().map(|i| i.iat_rva).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), 5, "five distinct IAT slots");
    }
}
