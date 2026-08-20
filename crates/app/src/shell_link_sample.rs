//! Generates the **IShellLink-through-COM** console PE — the roadmap W6.6
//! stretch goal.
//!
//! `CLSID_ShellLink` / `IID_IShellLinkW` are public, decades-stable Microsoft
//! constants (`shobjidl_core.h`), independently cross-checked against
//! Microsoft's own docs and multiple public reference implementations — not
//! recovered from the pinned binary. What *is* specific to this prefix, and is
//! the actual claim under test, is that `CoCreateInstance(&CLSID_ShellLink, …)`
//! resolves through exemu's registry to **`shell32.dll` itself**
//! (`exemu_os::reg`'s seed for it) — the same in-proc-server mechanism
//! W6.3/W6.4 already proved for ole32's moniker classes — and that the
//! returned vtable really is Wine's own `IShellLinkW` implementation: the
//! `GetPath` call below is a **guest indirect call through a vtable Wine
//! populated**, on guest memory, with no native COM in exemu.
//!
//! What the generated program does:
//!
//! 1. `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`;
//! 2. `CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
//!    &IID_IShellLinkW, &pShellLink)`;
//! 3. `pShellLink->GetPath(buf, MAX_PATH, NULL, 0)` — a vtable call at slot 3
//!    (`IShellLinkW`'s own first slot, past the 3 `IUnknown` ones) on a
//!    pristine, never-`SetPath`'d object. Per Microsoft's own documented
//!    contract ("if the operation is successful but no path is retrieved, it
//!    returns `S_FALSE`") the correct answer is `S_FALSE` with an empty
//!    string — and that is exactly, bit-for-bit, what Wine's shell32 returns.
//!    A wrong vtable slot would not coincidentally reproduce a specific
//!    documented HRESULT; getting *this exact* answer is what makes the call
//!    a real proof rather than "some function got called";
//! 4. `Release`s the interface and `CoUninitialize`s.
//!
//! Every HRESULT is printed as an 8-hex-digit line (`<LABEL>=<hex>\n`) so a
//! run that stops short is diagnosable from stdout alone. The exit code is the
//! count of the 3 steps above that did not hold (`CoInitializeEx`/
//! `CoCreateInstance` must return `S_OK`; `GetPath` must return `S_OK` *or*
//! `S_FALSE`, both documented non-error outcomes) — 0 means every step held. A
//! guarded pointer is never dereferenced when NULL: a failed `CoCreateInstance`
//! skips `GetPath` (counted as a failure) rather than faulting the interpreter
//! on a NULL vtable call.
//!
//! # What this sample deliberately does *not* attempt
//!
//! An earlier version of this sample went further — `SetPath`, then
//! `QueryInterface(IID_IPersistFile)`, then `IPersistFile::Save` to write a
//! real `.lnk` into the sandboxed `CSIDL_PROGRAMS` folder (the "7-Zip
//! start-menu-shortcut pin"). **`SetPath` crashes the guest process**: Wine's
//! own crash reporter (visible on stderr under `--trace`) names it exactly —
//! `Unhandled page fault on read access to 00000000000000BC` — a **NULL
//! pointer plus a small struct-field offset**, the same failure class
//! `knowledge/known-issues.know` already documents ("a stubbed Win32 API
//! returns 0/NULL, the guest stores it as a pointer, and faults later when it
//! dereferences it"). This was isolated methodically, not guessed: the
//! `GetPath` slot (0x18) was proven correct and callable (§3 above); a sweep
//! of the vtable's neighbouring slots (0x90/0x98/0xA0/0xA8/0xB0) showed 0xA0
//! ("SetPath", the last of `IShellLinkW`'s 21 slots) holds a plausible,
//! same-image function pointer immediately followed by the vtable's true end
//! (0xA8/0xB0 both `NULL`) — confirming the *offset* is right; and the
//! `pszFile` argument was echoed back byte-for-byte correct before the call.
//! The crash is therefore **inside Wine's real `SetPath`**, hitting some
//! *other*, not-yet-identified exemu stub that returns `NULL` where Wine
//! expects a valid pointer — a genuine, separate gap, out of scope for W6.6
//! (known folders). Worth its own investigation; not this one.
//!
//! The layout code mirrors [`crate::shell_sample`] and the COM section of
//! [`crate::sample`] (hand-assembled, RIP-relative displacements patched from
//! known RVAs).

use std::collections::HashMap;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// `IShellLinkW::GetPath` writes at most `MAX_PATH` code units.
const MAX_PATH: u32 = 260;

/// `CLSID_ShellLink` = `{00021401-0000-0000-C000-000000000046}`, in the byte
/// order a guest passes (Data1/2/3 little-endian, Data4 as declared).
pub const CLSID_SHELL_LINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
/// `IID_IShellLinkW` = `{000214F9-0000-0000-C000-000000000046}`.
pub const IID_ISHELL_LINK_W: [u8; 16] = [
    0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// The 3 counted steps, in order — the sample's exit code is how many of
/// these did not hold.
pub const LABELS: [&str; 3] = ["COINIT=", "CREATE=", "GETPATH="];
/// The tag the (expected-empty) `GetPath` result is printed under.
pub const PATH_TAG: &str = "PATH=";

/// Build the IShellLink-through-COM sample executable.
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
    put_u16(&mut f, coff, 0x8664); // Machine = AMD64
    put_u16(&mut f, coff + 2, 3); // NumberOfSections
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022); // EXECUTABLE | LARGE_ADDRESS_AWARE

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA + r.data_len, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA); // BaseOfCode
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3); // Subsystem = CONSOLE
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
    // `.data` is BSS-style: virtual scratch only, no bytes on disk.
    write_section(&mut f, sec + 80, b".data", r.data_len, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + r.bytes.len()].copy_from_slice(&r.bytes);
    f
}

/// The imports, grouped by DLL and in IAT order.
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
    /// RVA + byte length (including `=`) of each of [`LABELS`], in order.
    label_rva: [u32; 3],
    label_len: [u32; 3],
    path_tag_rva: u32,
    path_tag_len: u32,
    // --- `.data` (BSS) scratch, laid out by `Rdata::build` -----------------
    punk_shelllink_rva: u32,
    /// `IShellLinkW::GetPath`'s output buffer (UTF-16, `MAX_PATH` code units).
    wbuf_getpath_rva: u32,
    /// ASCII line buffer the squeezed `GetPath` result is built in.
    abuf_rva: u32,
    /// `WriteFile`'s `lpNumberOfBytesWritten` slot.
    written_rva: u32,
    /// 8 hex digits + `'\n'`, filled by `print_hex`.
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

        // IMAGE_IMPORT_BY_NAME blobs (hint u16 + asciiz).
        let mut ibn_rva: Vec<u32> = Vec::new();
        for (_, funcs) in &plan {
            for f in funcs {
                pos = align_up_u32(pos, 2);
                ibn_rva.push(RDATA_RVA + pos);
                pos += 2 + f.len() as u32 + 1;
            }
        }
        // DLL name strings.
        let mut dll_name_rva: Vec<u32> = Vec::new();
        for (dll, _) in &plan {
            dll_name_rva.push(RDATA_RVA + pos);
            pos += dll.len() as u32 + 1;
        }

        // The two GUIDs, 16-byte aligned.
        pos = align_up_u32(pos, 16);
        let clsid_shelllink_rva = RDATA_RVA + pos;
        pos += 16;
        let iid_shelllinkw_rva = RDATA_RVA + pos;
        pos += 16;

        // The 3 step labels.
        let mut label_rva = [0u32; 3];
        let mut label_len = [0u32; 3];
        for (i, s) in LABELS.iter().enumerate() {
            label_rva[i] = RDATA_RVA + pos;
            label_len[i] = s.len() as u32;
            pos += s.len() as u32;
        }
        let path_tag_rva = RDATA_RVA + pos;
        let path_tag_len = PATH_TAG.len() as u32;
        pos += path_tag_len;

        let mut b = vec![0u8; pos as usize];

        // Import descriptors + ILT/IAT.
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
            ilt_cursor += 8; // null-terminate this DLL's ILT/IAT
            iat_cursor += 8;
        }

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
        // GUIDs.
        for (rva, guid) in [(clsid_shelllink_rva, &CLSID_SHELL_LINK), (iid_shelllinkw_rva, &IID_ISHELL_LINK_W)] {
            let off = (rva - RDATA_RVA) as usize;
            b[off..off + 16].copy_from_slice(guid);
        }
        // Labels.
        for (i, s) in LABELS.iter().enumerate() {
            let off = (label_rva[i] - RDATA_RVA) as usize;
            b[off..off + s.len()].copy_from_slice(s.as_bytes());
        }
        let off = (path_tag_rva - RDATA_RVA) as usize;
        b[off..off + PATH_TAG.len()].copy_from_slice(PATH_TAG.as_bytes());

        // `.data` (BSS) scratch layout.
        let punk_shelllink_rva = DATA_RVA;
        let wbuf_getpath_rva = punk_shelllink_rva + 8;
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
            label_rva,
            label_len,
            path_tag_rva,
            path_tag_len,
            punk_shelllink_rva,
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

// ---- frame layout -----------------------------------------------------------
// [0x00..0x20] shadow space
// [0x20..0x30] outgoing 5th/6th stack args
const FRAME: u32 = 0x38;

// ---- COM vtable slot byte offsets (public, documented — shobjidl_core.h /
// unknwn.h; NOT recovered from the binary) -----------------------------------
const VT_RELEASE: u32 = 0x10; // IUnknown, slot 2
const VT_SLW_GET_PATH: u32 = 0x18; // IShellLinkW, slot 3

/// Emit the sample's `.text`.
///
/// Register usage across calls (all Win64 non-volatile, so they survive the
/// calls into Wine's ole32/combase/shell32): `rsi` = cached stdout handle,
/// `r13d` = running count of the 3 steps that did not hold.
fn build_text(r: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // sub rsp, FRAME
    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME as u8]);

    // rsi = GetStdHandle(STD_OUTPUT_HANDLE = -11)
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]); // mov rsi, rax

    // xor r13d, r13d  (failure count)
    c.extend_from_slice(&[0x45, 0x31, 0xED]);

    // --- CoInitializeEx(NULL, COINIT_APARTMENTTHREADED = 2) ---------------
    c.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx
    c.extend_from_slice(&[0xBA, 0x02, 0x00, 0x00, 0x00]); // mov edx, 2
    rip(&mut c, &[0xFF, 0x15], r.slot("CoInitializeEx"));
    print_hex(&mut c, r, 0);
    fail_unless_zero(&mut c);

    // --- CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER=1, ---
    //     &IID_IShellLinkW, &punk_shelllink)
    rip(&mut c, &[0x48, 0x8D, 0x0D], r.clsid_shelllink_rva); // lea rcx, [rip+clsid]
    c.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]); // mov r8d, 1
    rip(&mut c, &[0x4C, 0x8D, 0x0D], r.iid_shelllinkw_rva); // lea r9, [rip+iid]
    rip(&mut c, &[0x48, 0x8D, 0x05], r.punk_shelllink_rva); // lea rax, [rip+punk_sl]
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    rip(&mut c, &[0xFF, 0x15], r.slot("CoCreateInstance"));
    print_hex(&mut c, r, 1);
    fail_unless_zero(&mut c);

    // --- guard: only touch the object if CoCreateInstance really produced ---
    //     a non-NULL pointer (independent of the HRESULT check above — a
    //     NULL vtable call would fault the interpreter, not fail cleanly).
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva); // mov rcx, [rip+punk_sl]
    c.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne HAVE_SL
    let jne_have_sl = c.len() - 4;
    // No object: GETPATH (1 step) skipped.
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp AFTER_SL
    let jmp_after_sl = c.len() - 4;

    let have_sl = c.len();
    patch_rel32(&mut c, jne_have_sl, have_sl);

    // --- GetPath(this, wbuf_getpath, MAX_PATH, NULL, fFlags=0) on the -----
    //     pristine (never-`SetPath`'d) object.
    // Clear the first code unit so a callee that leaves the buffer untouched
    // is observable as an empty string.
    rip_imm16(&mut c, &[0x66, 0xC7, 0x05], r.wbuf_getpath_rva, 0);
    rip(&mut c, &[0x48, 0x8D, 0x15], r.wbuf_getpath_rva); // lea rdx, [rip+wbuf_getpath]
    c.extend_from_slice(&[0x41, 0xB8]); // mov r8d, MAX_PATH
    c.extend_from_slice(&MAX_PATH.to_le_bytes());
    c.extend_from_slice(&[0x4D, 0x31, 0xC9]); // xor r9, r9
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva); // mov rcx, [rip+punk_sl]
    c.extend_from_slice(&[0x48, 0x8B, 0x01]); // mov rax, [rcx]  (vtbl)
    call_vtbl(&mut c, VT_SLW_GET_PATH);
    print_hex(&mut c, r, 2);
    // S_OK (0) or S_FALSE (1) are both documented non-error outcomes for
    // GetPath on a link with no target: `cmp eax,1; jbe ok; inc r13d`.
    c.extend_from_slice(&[0x83, 0xF8, 0x01]); // cmp eax, 1
    c.extend_from_slice(&[0x76, 0x03]); // jbe +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    // Report "PATH=<squeezed wbuf_getpath>\n" (expected empty).
    emit_report(&mut c, r.path_tag_rva, r.path_tag_len, r.wbuf_getpath_rva, r.abuf_rva, r.written_rva, r.slot("WriteFile"));

    // Release(punk_shelllink)
    rip(&mut c, &[0x48, 0x8B, 0x0D], r.punk_shelllink_rva);
    c.extend_from_slice(&[0x48, 0x8B, 0x01]);
    call_vtbl(&mut c, VT_RELEASE);

    let after_sl = c.len();
    patch_rel32(&mut c, jmp_after_sl, after_sl);

    // CoUninitialize()
    rip(&mut c, &[0xFF, 0x15], r.slot("CoUninitialize"));

    // ExitProcess(r13d) — the failure count.
    c.extend_from_slice(&[0x44, 0x89, 0xE9]); // mov ecx, r13d
    rip(&mut c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC); // int3 (unreached)
    c
}

/// `call [rax+offset]` — a COM vtable call. `rax` must already hold the
/// vtable pointer. Picks the disp8 encoding when it fits, else disp32
/// (verified against both forms live — see the module doc's account of the
/// `SetPath` investigation).
fn call_vtbl(c: &mut Vec<u8>, offset: u32) {
    if offset == 0 {
        c.extend_from_slice(&[0xFF, 0x10]); // call [rax]
    } else if offset < 0x80 {
        c.extend_from_slice(&[0xFF, 0x50, offset as u8]); // call [rax+disp8]
    } else {
        c.extend_from_slice(&[0xFF, 0x90]); // call [rax+disp32]
        c.extend_from_slice(&offset.to_le_bytes());
    }
}

/// `test eax,eax; je +6; inc r13d` — count a non-`S_OK` result as a failure
/// without disturbing `eax`.
fn fail_unless_zero(c: &mut Vec<u8>) {
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x74, 0x03]); // je +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
}

/// Patch a 4-byte relative displacement at `site` (the offset of the first
/// displacement byte) so it lands on `target` — both measured from the start
/// of `.text`, matching how `rel32` is defined (relative to the *end* of the
/// 4-byte field, i.e. `site + 4`).
fn patch_rel32(c: &mut [u8], site: usize, target: usize) {
    let rel = (target as i64 - (site as i64 + 4)) as i32;
    c[site..site + 4].copy_from_slice(&rel.to_le_bytes());
}

/// Print `<label>` then `eax` as 8 hex digits + `'\n'`. `eax` is preserved.
/// `label_index` selects the entry of [`LABELS`] via `r.label_rva`/`label_len`.
fn print_hex(c: &mut Vec<u8>, r: &Rdata, label_index: usize) {
    c.extend_from_slice(&[0x89, 0xC3]); // mov ebx, eax  (save the value)
    write_str(c, r, r.label_rva[label_index], r.label_len[label_index]);
    rip(c, &[0x48, 0x8D, 0x3D], r.hexbuf_rva); // lea rdi, [rip+hexbuf]
    c.extend_from_slice(&[0x89, 0xD8]); // mov eax, ebx
    c.extend_from_slice(&[0xB9, 0x08, 0x00, 0x00, 0x00]); // mov ecx, 8
    let loop_start = c.len();
    c.extend_from_slice(&[0xC1, 0xC0, 0x04]); // rol eax, 4
    c.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
    c.extend_from_slice(&[0x83, 0xE2, 0x0F]); // and edx, 0xF
    c.extend_from_slice(&[0x80, 0xC2, 0x30]); // add dl, '0'
    c.extend_from_slice(&[0x80, 0xFA, 0x39]); // cmp dl, '9'
    c.extend_from_slice(&[0x76, 0x03]); // jbe +3 (skip the a-f fixup)
    c.extend_from_slice(&[0x80, 0xC2, 0x27]); // add dl, 'a'-'0'-10
    c.extend_from_slice(&[0x88, 0x17]); // mov [rdi], dl
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    c.extend_from_slice(&[0x75, 0x00]); // jnz .loop
    let back = c.len();
    c[back - 1] = ((loop_start as i64 - back as i64) as i8) as u8;
    c.extend_from_slice(&[0xC6, 0x07, 0x0A]); // mov byte [rdi], '\n'
    write_str(c, r, r.hexbuf_rva, 9);
    c.extend_from_slice(&[0x89, 0xD8]); // mov eax, ebx  (restore)
}

/// `WriteFile(rsi, [rip+buf_rva], len, &r.written_rva, NULL)`.
fn write_str(c: &mut Vec<u8>, r: &Rdata, buf_rva: u32, len: u32) {
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x48, 0x8D, 0x15], buf_rva); // lea rdx, [rip+buf]
    c.extend_from_slice(&[0x41, 0xB8]); // mov r8d, len
    c.extend_from_slice(&len.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

/// Emit `"<tag>" + squeeze(wbuf) + "\n"` into `abuf` and `WriteFile` it to
/// stdout (`rsi`). The UTF-16 `wbuf` is squeezed to ASCII by keeping each code
/// unit's low byte — adequate for the pure-ASCII paths this sample exercises.
#[allow(clippy::too_many_arguments)]
fn emit_report(c: &mut Vec<u8>, tag_rva: u32, tag_len: u32, wbuf_rva: u32, abuf_rva: u32, written_rva: u32, iat_write_file: u32) {
    // r14 = abuf ; rdi = tag ; ecx = tag_len — copy the prefix.
    rip(c, &[0x4C, 0x8D, 0x35], abuf_rva); // lea r14, [rip+abuf]
    rip(c, &[0x48, 0x8D, 0x3D], tag_rva); // lea rdi, [rip+tag]
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&tag_len.to_le_bytes()); // mov ecx, tag_len
    let tag_loop = c.len();
    c.extend_from_slice(&[0x8A, 0x07]); // mov al, [rdi]
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    c.extend_from_slice(&[0x75, 0x00]); // jnz tag_loop
    let at = c.len();
    let fix = at - 1;
    c[fix] = ((tag_loop as i64 - at as i64) as i8) as u8;

    // Squeeze the UTF-16 path into ASCII: rdi = wbuf; while (u16 != 0) copy
    // the low byte.
    rip(c, &[0x48, 0x8D, 0x3D], wbuf_rva); // lea rdi, [rip+wbuf]
    let sq_loop = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]); // mov ax, [rdi]
    c.extend_from_slice(&[0x66, 0x85, 0xC0]); // test ax, ax
    c.extend_from_slice(&[0x74, 0x00]); // je sq_done
    let sq_done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]); // add rdi, 2
    c.extend_from_slice(&[0xEB, 0x00]); // jmp sq_loop
    let back = c.len();
    c[back - 1] = ((sq_loop as i64 - back as i64) as i8) as u8;
    let sq_done = c.len();
    c[sq_done_fix] = ((sq_done as i64 - (sq_done_fix as i64 + 1)) as i8) as u8;

    // Terminate the line with '\n' and compute the length in r8d.
    c.extend_from_slice(&[0x41, 0xC6, 0x06, 0x0A]); // mov byte [r14], '\n'
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x4C, 0x89, 0xF0]); // mov rax, r14
    rip(c, &[0x48, 0x8D, 0x15], abuf_rva); // lea rdx, [rip+abuf]
    c.extend_from_slice(&[0x48, 0x29, 0xD0]); // sub rax, rdx
    c.extend_from_slice(&[0x41, 0x89, 0xC0]); // mov r8d, eax

    // WriteFile(stdout, abuf, len, &written, NULL)
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x4C, 0x8D, 0x0D], written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], iat_write_file);
}

/// Emit an instruction ending in a RIP-relative `disp32`.
fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

/// Emit a RIP-relative instruction with a trailing `imm16` (the displacement
/// is measured from the end of the *whole* instruction, immediate included).
fn rip_imm16(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u16) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 2;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

// ---- byte helpers -----------------------------------------------------------

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

    /// The generated image is a PE32+ console executable that statically
    /// imports exactly the ole32/kernel32 entry points the sample needs, and
    /// every GUID/label the gate greps for travels in `.rdata`.
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
