//! Generates the **common-dialog** console PE — the roadmap W6.2 proof binary.
//!
//! The produced `.exe` statically imports `comdlg32.dll!GetOpenFileNameW` and
//! `comdlg32.dll!GetSaveFileNameW`. The static import is the point: it forces
//! the loader to map + relocate + bind **Wine's own comdlg32** (and its whole
//! dependency graph — comctl32, shell32, shlwapi, ole32, …) and run their
//! `DllMain`s before the entry point, so the call below is guest PE code from
//! the pinned prefix.
//!
//! What it does:
//!
//! 1. fills an `OPENFILENAMEW` (`lStructSize` = 152, the x64 size) pointing at a
//!    `MAX_PATH` wide buffer in `.data`, with a filter, an initial directory and
//!    a title;
//! 2. calls `GetOpenFileNameW`, and prints `"OPEN=<path>"` — the returned path,
//!    squeezed from UTF-16 to ASCII in-line so the binary needs no
//!    `WideCharToMultiByte` import (one less thing that could service the test
//!    instead of the dialog);
//! 3. **opens the path it was handed** with `CreateFileW`/`ReadFile` and prints
//!    `"READ=<first bytes>"`. This is the part that makes the result meaningful:
//!    a bridge that returns a plausible-looking string but not a path the guest's
//!    own filesystem view can resolve fails here;
//! 4. repeats the same shape for `GetSaveFileNameW`, printing `"SAVE=<path>"`
//!    and then **creating and writing** that file (`"WROTE=<n>"`), so the save
//!    side is proven writable rather than merely returned.
//!
//! The exit code is the failure count, so `0` means every leg worked. On the
//! **emulated** path exemu has no `GetOpenFileNameW` at all — it is an
//! unimplemented import that returns 0 (`FALSE`) without touching the buffer —
//! so the sample prints an empty path and exits non-zero. That control is what
//! gives a pass its meaning.
//!
//! The layout code mirrors [`crate::shell_sample`] (hand-assembled, RIP-relative
//! displacements patched from known RVAs).

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// `GetOpenFileNameW` writes at most `MAX_PATH` code units into `lpstrFile`.
const MAX_PATH: u32 = 260;

/// `sizeof(OPENFILENAMEW)` on x86-64 — the value `lStructSize` must carry, and
/// what every implementation version-checks against.
pub const OPENFILENAMEW_SIZE: u32 = 0x98;

// --- OPENFILENAMEW field offsets (x86-64), from `commdlg.h` ------------------
const OFN_STRUCT_SIZE: u32 = 0x00;
const OFN_HWND_OWNER: u32 = 0x08;
const OFN_LPSTR_FILTER: u32 = 0x18;
const OFN_LPSTR_FILE: u32 = 0x30;
const OFN_N_MAX_FILE: u32 = 0x38;
const OFN_LPSTR_INITIAL_DIR: u32 = 0x50;
const OFN_LPSTR_TITLE: u32 = 0x58;
const OFN_FLAGS: u32 = 0x60;
const OFN_LPSTR_DEF_EXT: u32 = 0x68;

/// `OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR |
/// OFN_HIDEREADONLY` — the flag set an ordinary "open a document" call uses.
const OPEN_FLAGS: u32 = 0x0000_1000 | 0x0000_0800 | 0x0008_0000 | 0x0000_0008 | 0x0000_0004;
/// `OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR |
/// OFN_HIDEREADONLY` — the save-side equivalent.
const SAVE_FLAGS: u32 = 0x0000_0002 | 0x0000_0800 | 0x0008_0000 | 0x0000_0008 | 0x0000_0004;

/// The directory the sample points both dialogs at. The gate seeds
/// [`PICK_FILE_NAME`] here before the run.
pub const INITIAL_DIR: &str = r"C:\Users\exemu\Documents";
/// The file the gate seeds in [`INITIAL_DIR`], and the name the open dialog is
/// expected to come back with.
pub const PICK_FILE_NAME: &str = "exemu-pick.txt";
/// The name the sample proposes to the save dialog (`lpstrFile` is seeded with
/// it, exactly as a real app pre-fills the file-name box).
pub const SAVE_FILE_NAME: &str = "exemu-saved.txt";

/// The bytes the sample writes through the save-dialog path. The gate reads them
/// back off the host filesystem, which is what proves the returned save path is
/// a real, writable location in the guest's view *and* lands in the sandbox.
pub const SAVE_PAYLOAD: &str = "exemu-comdlg-wrote-this";

/// The dialog captions. A driver-level bridge keys off these, and the gate
/// checks the native panel was asked for the right one.
pub const OPEN_TITLE: &str = "exemu — pick a file to open";
pub const SAVE_TITLE: &str = "exemu — pick where to save";

/// The `lpstrFilter` pair list: `"Text files\0*.txt\0All files\0*.*\0\0"`.
const FILTER_PARTS: [&str; 4] = ["Text files", "*.txt", "All files", "*.*"];
/// `lpstrDefExt` — the extension appended when the user types a bare name.
const DEF_EXT: &str = "txt";

/// How many bytes of the opened file the sample reads back and reports.
const RBUF_LEN: u32 = 64;

/// The report tags, in the order the sample prints them.
pub const TAG_OPEN: &str = "OPEN";
pub const TAG_READ: &str = "READ";
pub const TAG_SAVE: &str = "SAVE";
pub const TAG_WROTE: &str = "WROTE";
/// `CommDlgExtendedError()` after each dialog call — 0 when the user simply
/// cancelled, a `CDERR_*`/`FNERR_*` code when the dialog itself failed. Printed
/// unconditionally so a failing run says *why* rather than only *that*.
pub const TAG_OPEN_ERR: &str = "OPENERR";
pub const TAG_SAVE_ERR: &str = "SAVEERR";
/// `CommDlgExtendedError()` after a **deliberately malformed** call — see
/// [`BAD_STRUCT_SIZE`]. This leg does not affect the exit code; it exists so a
/// gate can attribute the result to Wine's own validator rather than to exemu.
pub const TAG_BAD_SIZE: &str = "BADSIZE";

/// An `lStructSize` no implementation accepts.
///
/// Recovered by disassembling the pinned `comdlg32.dll` (`GetOpenFileNameW`,
/// `.text$GetOpenFileNameW`): the prologue reads `lStructSize`, masks off bit 4
/// (`and eax, ~0x10`) and requires the result to equal `0x88` — i.e. it accepts
/// exactly `0x88` (the pre-Win2000 `OPENFILENAME`) and `0x98` (the current one),
/// and on anything else calls `COMDLG32_SetCommDlgExtendedError(1)` =
/// `CDERR_STRUCTSIZE` and returns FALSE. `0x99` masks to `0x89`, so it is
/// rejected. **exemu implements no part of this**, so a `1` coming back is a
/// value only Wine's own code can have produced.
pub const BAD_STRUCT_SIZE: u32 = 0x99;
/// `CDERR_STRUCTSIZE` — what [`BAD_STRUCT_SIZE`] must produce on the Wine path.
pub const CDERR_STRUCTSIZE: u32 = 1;
/// `CDERR_FINDRESFAILURE` / `CDERR_LOADRESFAILURE` — the two codes Wine's
/// `GetFileName95` sets when it cannot find or lock **its own** dialog-template
/// resource. Neither may appear on a healthy run: seeing them would mean the
/// resource half of "comdlg32 arrives as guest code" had regressed.
pub const CDERR_FINDRESFAILURE: u32 = 6;
pub const CDERR_LOADRESFAILURE: u32 = 7;

/// Build the common-dialog sample executable.
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

/// The imports, grouped by DLL and in IAT order. `comdlg32.dll` is the point of
/// the exercise.
fn import_plan() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "comdlg32.dll",
            vec!["GetOpenFileNameW", "GetSaveFileNameW", "CommDlgExtendedError"],
        ),
        (
            "kernel32.dll",
            vec![
                "GetStdHandle",
                "WriteFile",
                "CreateFileW",
                "ReadFile",
                "CloseHandle",
                "ExitProcess",
            ],
        ),
    ]
}

/// The ASCII report tags, in `.rdata` order.
const TAGS: [&str; 7] =
    [TAG_OPEN, TAG_READ, TAG_SAVE, TAG_WROTE, TAG_OPEN_ERR, TAG_SAVE_ERR, TAG_BAD_SIZE];

/// The wide strings the sample references, in `.rdata` order.
const WIDE_STRINGS: [&str; 5] =
    [INITIAL_DIR, OPEN_TITLE, SAVE_TITLE, DEF_EXT, SAVE_FILE_NAME];

struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    iat: std::collections::HashMap<String, u32>,
    /// RVA of the `"<tag>="` ASCII prefix for each entry of [`TAGS`].
    tag_rva: Vec<u32>,
    /// Byte length of each tag prefix (including the `=`).
    tag_len: Vec<u32>,
    /// Wide-string RVAs, parallel to [`WIDE_STRINGS`].
    strings: Vec<u32>,
    /// The double-NUL-terminated `lpstrFilter` pair list.
    filter_rva: u32,
    /// The ASCII payload the save leg writes, and its length.
    payload_rva: u32,
    payload_len: u32,
    // --- `.data` (BSS) scratch, laid out by `Rdata::build` -----------------
    /// The `OPENFILENAMEW` both calls are made through.
    ofn_rva: u32,
    /// `lpstrFile` for the open leg.
    open_buf_rva: u32,
    /// `lpstrFile` for the save leg.
    save_buf_rva: u32,
    /// ASCII line buffer the squeezed path plus `'\n'` is built in.
    abuf_rva: u32,
    /// The bytes read back out of the opened file.
    rbuf_rva: u32,
    /// `ReadFile`/`WriteFile`'s `lpNumberOfBytes*` slot.
    counted_rva: u32,
    /// `WriteFile`'s `lpNumberOfBytesWritten` slot for the stdout reports.
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
        // `"<tag>="` ASCII prefixes.
        let mut tag_rva = Vec::new();
        let mut tag_len = Vec::new();
        for tag in TAGS {
            tag_rva.push(RDATA_RVA + pos);
            let n = tag.len() as u32 + 1;
            tag_len.push(n);
            pos += n;
        }
        // The ASCII payload the save leg writes.
        let payload_rva = RDATA_RVA + pos;
        let payload_len = SAVE_PAYLOAD.len() as u32;
        pos += payload_len;

        // Wide strings.
        pos = align_up_u32(pos, 2);
        let mut strings: Vec<u32> = Vec::new();
        for s in WIDE_STRINGS {
            strings.push(RDATA_RVA + pos);
            pos += wide(s).len() as u32;
        }
        // The filter pair list: each part NUL-terminated, then one more NUL.
        let filter_rva = RDATA_RVA + pos;
        let filter = filter_blob();
        pos += filter.len() as u32;

        let mut b = vec![0u8; pos as usize];

        // Import descriptors + ILT/IAT.
        let mut iat = std::collections::HashMap::new();
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
        // Tag prefixes (`"NAME="`).
        for (i, tag) in TAGS.iter().enumerate() {
            let off = (tag_rva[i] - RDATA_RVA) as usize;
            b[off..off + tag.len()].copy_from_slice(tag.as_bytes());
            b[off + tag.len()] = b'=';
        }
        // The save payload.
        let off = (payload_rva - RDATA_RVA) as usize;
        b[off..off + SAVE_PAYLOAD.len()].copy_from_slice(SAVE_PAYLOAD.as_bytes());
        // Wide strings.
        for (rva, s) in strings.iter().zip(WIDE_STRINGS) {
            let off = (*rva - RDATA_RVA) as usize;
            let w = wide(s);
            b[off..off + w.len()].copy_from_slice(&w);
        }
        // The filter list.
        let off = (filter_rva - RDATA_RVA) as usize;
        b[off..off + filter.len()].copy_from_slice(&filter);

        // `.data` (BSS) scratch layout.
        let ofn_rva = DATA_RVA;
        let open_buf_rva = ofn_rva + OPENFILENAMEW_SIZE + 8;
        let save_buf_rva = open_buf_rva + MAX_PATH * 2 + 8;
        let abuf_rva = save_buf_rva + MAX_PATH * 2 + 8;
        let rbuf_rva = abuf_rva + MAX_PATH * 2 + 8;
        let counted_rva = align_up_u32(rbuf_rva + RBUF_LEN + 8, 8);
        let written_rva = counted_rva + 8;
        let data_len = written_rva + 8 - DATA_RVA;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            tag_rva,
            tag_len,
            strings,
            filter_rva,
            payload_rva,
            payload_len,
            ofn_rva,
            open_buf_rva,
            save_buf_rva,
            abuf_rva,
            rbuf_rva,
            counted_rva,
            written_rva,
            data_len,
        }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }

    /// RVA of one of the [`WIDE_STRINGS`], by value.
    fn wstr(&self, s: &str) -> u32 {
        let i = WIDE_STRINGS.iter().position(|w| *w == s).expect("wide string present");
        self.strings[i]
    }

    /// RVA + length of one of the [`TAGS`] prefixes, by value.
    fn tag(&self, t: &str) -> (u32, u32) {
        let i = TAGS.iter().position(|x| *x == t).expect("tag present");
        (self.tag_rva[i], self.tag_len[i])
    }
}

fn wide(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// `"Text files\0*.txt\0All files\0*.*\0\0"` as UTF-16LE.
fn filter_blob() -> Vec<u8> {
    let mut v = Vec::new();
    for p in FILTER_PARTS {
        v.extend_from_slice(&wide(p));
    }
    v.extend_from_slice(&[0, 0]); // the list terminator
    v
}

// ---- frame layout -----------------------------------------------------------
// [0x00..0x20] shadow space
// [0x20..0x38] outgoing 5th/6th/7th stack args (`CreateFileW` takes 7)
// `FRAME % 16 == 8`, so `rsp` is 16-byte aligned at every `call`.
const FRAME: u32 = 0x38;

/// Emit the sample's `.text`.
///
/// Register usage across calls (all Win64 non-volatile, so they survive the
/// calls into Wine's DLLs): `rsi` = cached stdout handle, `rbx` = the file
/// handle under test, `r13d` = failure count, `r14` = the ASCII line buffer's
/// write cursor, `r15b` = "the last reported string was non-empty".
fn build_text(r: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // sub rsp, FRAME
    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME as u8]);
    // xor r13d, r13d  (failure count)
    c.extend_from_slice(&[0x45, 0x31, 0xED]);
    // mov ecx, -11 (STD_OUTPUT_HANDLE) ; call [GetStdHandle] ; mov rsi, rax
    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    emit_open_leg(&mut c, r);
    emit_save_leg(&mut c, r);
    emit_bad_size_leg(&mut c, r);

    // ExitProcess(r13d) — the failure count.
    c.extend_from_slice(&[0x44, 0x89, 0xE9]); // mov ecx, r13d
    rip(&mut c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC); // int3 (unreached)
    c
}

/// Zero the whole `OPENFILENAMEW` and fill the fields both legs share.
fn emit_ofn_common(c: &mut Vec<u8>, r: &Rdata, file_buf_rva: u32, title: &str, flags: u32) {
    let mut off = 0u32;
    while off < OPENFILENAMEW_SIZE {
        mov_mem_imm64(c, r.ofn_rva + off, 0);
        off += 8;
    }
    mov_mem_imm32(c, r.ofn_rva + OFN_STRUCT_SIZE, OPENFILENAMEW_SIZE as i32);
    mov_mem_imm64(c, r.ofn_rva + OFN_HWND_OWNER, 0);
    lea_rax(c, r.filter_rva);
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_FILTER);
    lea_rax(c, file_buf_rva);
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_FILE);
    mov_mem_imm32(c, r.ofn_rva + OFN_N_MAX_FILE, MAX_PATH as i32);
    lea_rax(c, r.wstr(INITIAL_DIR));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_INITIAL_DIR);
    lea_rax(c, r.wstr(title));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_TITLE);
    mov_mem_imm32(c, r.ofn_rva + OFN_FLAGS, flags as i32);
    lea_rax(c, r.wstr(DEF_EXT));
    mov_mem_rax(c, r.ofn_rva + OFN_LPSTR_DEF_EXT);
}

/// `GetOpenFileNameW` → report the path → open it and report its first bytes.
fn emit_open_leg(c: &mut Vec<u8>, r: &Rdata) {
    // The buffer starts empty: `lpstrFile` doubles as the *initial* file name,
    // and an empty one is what an app with nothing pre-selected passes.
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.open_buf_rva, 0);
    emit_ofn_common(c, r, r.open_buf_rva, OPEN_TITLE, OPEN_FLAGS);

    // GetOpenFileNameW(&ofn)
    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva); // lea rcx, [rip+ofn]
    rip(c, &[0xFF, 0x15], r.slot("GetOpenFileNameW"));
    // FALSE (the user cancelled, or nothing serviced the call) is a failure.
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x75, 0x03]); // jne +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    // Stash `CommDlgExtendedError()` before anything else can disturb it.
    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva); // mov [rip+counted], eax

    let (tag, len) = r.tag(TAG_OPEN);
    emit_tag(c, r, tag, len);
    emit_squeeze_w(c, r.open_buf_rva);
    emit_count_empty(c);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_OPEN_ERR);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);

    // CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
    rip(c, &[0x48, 0x8D, 0x0D], r.open_buf_rva); // lea rcx, [rip+open_buf]
    c.push(0xBA);
    c.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // mov edx, GENERIC_READ
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]); // mov r8d, FILE_SHARE_READ
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
    stack_arg_imm(c, 0x20, 3); // OPEN_EXISTING
    stack_arg_imm(c, 0x28, 0); // dwFlagsAndAttributes
    stack_arg_imm(c, 0x30, 0); // hTemplateFile
    rip(c, &[0xFF, 0x15], r.slot("CreateFileW"));
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax

    // The read buffer starts NUL so a failed read reports an empty string.
    rip_imm8(c, &[0xC6, 0x05], r.rbuf_rva, 0);
    mov_mem_imm32(c, r.counted_rva, 0);

    // if (h == INVALID_HANDLE_VALUE) { failures++; } else { ReadFile; CloseHandle; }
    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0xFF]); // cmp rax, -1
    let jne_fix = jcc_near(c, 0x85); // jne have_handle
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    let jmp_fix = jmp_near(c); // jmp read_done
    patch_near(c, jne_fix);

    // ReadFile(h, rbuf, RBUF_LEN, &counted, NULL)
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0x48, 0x8D, 0x15], r.rbuf_rva); // lea rdx, [rip+rbuf]
    c.extend_from_slice(&[0x41, 0xB8]); // mov r8d, RBUF_LEN
    c.extend_from_slice(&RBUF_LEN.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.counted_rva); // lea r9, [rip+counted]
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("ReadFile"));
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x75, 0x03]); // jne +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    // NUL-terminate what was read: rbuf[counted] = 0.
    rip(c, &[0x48, 0x8D, 0x05], r.rbuf_rva); // lea rax, [rip+rbuf]
    rip(c, &[0x8B, 0x0D], r.counted_rva); // mov ecx, [rip+counted]
    c.extend_from_slice(&[0xC6, 0x04, 0x08, 0x00]); // mov byte [rax+rcx], 0
    // CloseHandle(h)
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));
    patch_near(c, jmp_fix);

    let (tag, len) = r.tag(TAG_READ);
    emit_tag(c, r, tag, len);
    emit_copy_az(c, r.rbuf_rva);
    emit_count_empty(c);
    emit_flush(c, r);
}

/// `GetSaveFileNameW` → report the path → create it and write the payload.
fn emit_save_leg(c: &mut Vec<u8>, r: &Rdata) {
    // Pre-fill the file-name box, exactly as an app proposing a name does.
    emit_copy_wz(c, r.wstr(SAVE_FILE_NAME), r.save_buf_rva);
    emit_ofn_common(c, r, r.save_buf_rva, SAVE_TITLE, SAVE_FLAGS);

    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva); // lea rcx, [rip+ofn]
    rip(c, &[0xFF, 0x15], r.slot("GetSaveFileNameW"));
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x75, 0x03]); // jne +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva); // mov [rip+counted], eax

    let (tag, len) = r.tag(TAG_SAVE);
    emit_tag(c, r, tag, len);
    emit_squeeze_w(c, r.save_buf_rva);
    emit_count_empty(c);
    emit_flush(c, r);

    let (tag, len) = r.tag(TAG_SAVE_ERR);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);

    // CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)
    rip(c, &[0x48, 0x8D, 0x0D], r.save_buf_rva);
    c.push(0xBA);
    c.extend_from_slice(&0x4000_0000u32.to_le_bytes()); // GENERIC_WRITE
    c.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
    stack_arg_imm(c, 0x20, 2); // CREATE_ALWAYS
    stack_arg_imm(c, 0x28, 0);
    stack_arg_imm(c, 0x30, 0);
    rip(c, &[0xFF, 0x15], r.slot("CreateFileW"));
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax

    mov_mem_imm32(c, r.counted_rva, 0);
    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0xFF]); // cmp rax, -1
    let jne_fix = jcc_near(c, 0x85);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    let jmp_fix = jmp_near(c);
    patch_near(c, jne_fix);

    // WriteFile(h, payload, payload_len, &counted, NULL)
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0x48, 0x8D, 0x15], r.payload_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.payload_len.to_le_bytes());
    rip(c, &[0x4C, 0x8D, 0x0D], r.counted_rva);
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x75, 0x03]);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0xFF, 0x15], r.slot("CloseHandle"));
    patch_near(c, jmp_fix);

    // "WROTE=<n>" as a one-or-two digit decimal, so a short write is visible.
    let (tag, len) = r.tag(TAG_WROTE);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);
}

/// The attribution leg: one more `GetOpenFileNameW`, identical except for a
/// **deliberately invalid** `lStructSize` ([`BAD_STRUCT_SIZE`]). It must come
/// back FALSE with `CommDlgExtendedError() == CDERR_STRUCTSIZE`, a value only
/// the real validator inside Wine's comdlg32 produces — exemu has no
/// `OPENFILENAMEW` validator anywhere. The exit code deliberately ignores this
/// leg (FALSE is the *expected* answer here); the printed code is the evidence.
fn emit_bad_size_leg(c: &mut Vec<u8>, r: &Rdata) {
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.open_buf_rva, 0);
    emit_ofn_common(c, r, r.open_buf_rva, OPEN_TITLE, OPEN_FLAGS);
    mov_mem_imm32(c, r.ofn_rva + OFN_STRUCT_SIZE, BAD_STRUCT_SIZE as i32);

    rip(c, &[0x48, 0x8D, 0x0D], r.ofn_rva); // lea rcx, [rip+ofn]
    rip(c, &[0xFF, 0x15], r.slot("GetOpenFileNameW"));
    // A TRUE here would mean *nothing* validated the struct — a real failure.
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x74, 0x03]); // je +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    rip(c, &[0xFF, 0x15], r.slot("CommDlgExtendedError"));
    rip(c, &[0x89, 0x05], r.counted_rva); // mov [rip+counted], eax

    let (tag, len) = r.tag(TAG_BAD_SIZE);
    emit_tag(c, r, tag, len);
    emit_decimal(c, r.counted_rva);
    emit_flush(c, r);
}

// ---- report emitters --------------------------------------------------------

/// `r14 = abuf`, then copy the `"<tag>="` prefix into it.
fn emit_tag(c: &mut Vec<u8>, r: &Rdata, tag_rva: u32, tag_len: u32) {
    rip(c, &[0x4C, 0x8D, 0x35], r.abuf_rva); // lea r14, [rip+abuf]
    rip(c, &[0x48, 0x8D, 0x3D], tag_rva); // lea rdi, [rip+tag]
    c.push(0xB9);
    c.extend_from_slice(&tag_len.to_le_bytes()); // mov ecx, tag_len
    let top = c.len();
    c.extend_from_slice(&[0x8A, 0x07]); // mov al, [rdi]
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    jmp_short_back(c, 0x75, top); // jnz top
}

/// Append a NUL-terminated UTF-16 string at `buf_rva`, squeezed to ASCII.
/// `r15b` records whether any code unit was copied.
fn emit_squeeze_w(c: &mut Vec<u8>, buf_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], buf_rva); // lea rdi, [rip+buf]
    c.extend_from_slice(&[0x45, 0x31, 0xFF]); // xor r15d, r15d
    let top = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]); // mov ax, [rdi]
    c.extend_from_slice(&[0x66, 0x85, 0xC0]); // test ax, ax
    c.extend_from_slice(&[0x74, 0x00]); // je done
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]); // add rdi, 2
    c.extend_from_slice(&[0x41, 0xB7, 0x01]); // mov r15b, 1
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

/// Append a NUL-terminated ASCII string at `buf_rva`. `r15b` as above.
fn emit_copy_az(c: &mut Vec<u8>, buf_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], buf_rva); // lea rdi, [rip+buf]
    c.extend_from_slice(&[0x45, 0x31, 0xFF]); // xor r15d, r15d
    let top = c.len();
    c.extend_from_slice(&[0x8A, 0x07]); // mov al, [rdi]
    c.extend_from_slice(&[0x84, 0xC0]); // test al, al
    c.extend_from_slice(&[0x74, 0x00]); // je done
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0x41, 0xB7, 0x01]); // mov r15b, 1
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

/// Append the decimal digits of the DWORD at `count_rva` (0–999 is plenty).
/// Always writes at least one digit, so `r15b` is set unconditionally.
fn emit_decimal(c: &mut Vec<u8>, count_rva: u32) {
    // eax = count; write digits into a 3-byte scratch on the stack, backwards.
    rip(c, &[0x8B, 0x05], count_rva); // mov eax, [rip+count]
    c.extend_from_slice(&[0x41, 0xB7, 0x01]); // mov r15b, 1
    // rdi = rsp+0x18 (inside the shadow space, unused between calls); write down.
    c.extend_from_slice(&[0x48, 0x8D, 0x7C, 0x24, 0x18]); // lea rdi, [rsp+0x18]
    c.extend_from_slice(&[0xB9, 0x0A, 0x00, 0x00, 0x00]); // mov ecx, 10
    let top = c.len();
    c.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    c.extend_from_slice(&[0xF7, 0xF1]); // div ecx
    c.extend_from_slice(&[0x80, 0xC2, 0x30]); // add dl, '0'
    c.extend_from_slice(&[0x48, 0xFF, 0xCF]); // dec rdi
    c.extend_from_slice(&[0x88, 0x17]); // mov [rdi], dl
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    jmp_short_back(c, 0x75, top); // jnz top
    // Copy [rdi .. rsp+0x18) into the line buffer.
    let copy = c.len();
    c.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x18]); // lea rax, [rsp+0x18]
    c.extend_from_slice(&[0x48, 0x39, 0xC7]); // cmp rdi, rax
    c.extend_from_slice(&[0x74, 0x00]); // je done
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x8A, 0x07]); // mov al, [rdi]
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    jmp_short_back(c, 0xEB, copy);
    patch_short(c, done_fix);
}

/// An empty reported string counts as a failure (`r15b == 0`).
fn emit_count_empty(c: &mut Vec<u8>) {
    c.extend_from_slice(&[0x45, 0x84, 0xFF]); // test r15b, r15b
    c.extend_from_slice(&[0x75, 0x03]); // jnz +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
}

/// Terminate the line and `WriteFile` it to stdout.
fn emit_flush(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x41, 0xC6, 0x06, 0x0A]); // mov byte [r14], '\n'
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x4C, 0x89, 0xF0]); // mov rax, r14
    rip(c, &[0x48, 0x8D, 0x15], r.abuf_rva); // lea rdx, [rip+abuf]
    c.extend_from_slice(&[0x48, 0x29, 0xD0]); // sub rax, rdx
    c.extend_from_slice(&[0x41, 0x89, 0xC0]); // mov r8d, eax
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva); // lea r9, [rip+written]
    stack_arg_imm(c, 0x20, 0);
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

/// Copy a NUL-terminated UTF-16 string from `src_rva` to `dst_rva`.
fn emit_copy_wz(c: &mut Vec<u8>, src_rva: u32, dst_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x3D], src_rva); // lea rdi, [rip+src]
    rip(c, &[0x48, 0x8D, 0x15], dst_rva); // lea rdx, [rip+dst]
    let top = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]); // mov ax, [rdi]
    c.extend_from_slice(&[0x66, 0x89, 0x02]); // mov [rdx], ax
    c.extend_from_slice(&[0x66, 0x85, 0xC0]); // test ax, ax
    c.extend_from_slice(&[0x74, 0x00]); // je done
    let done_fix = c.len() - 1;
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]); // add rdi, 2
    c.extend_from_slice(&[0x48, 0x83, 0xC2, 0x02]); // add rdx, 2
    jmp_short_back(c, 0xEB, top);
    patch_short(c, done_fix);
}

// ---- instruction helpers ----------------------------------------------------

/// Emit an instruction ending in a RIP-relative `disp32`.
fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

/// Emit a RIP-relative instruction with a trailing `imm8`.
fn rip_imm8(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u8) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 1;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.push(imm);
}

/// Emit a RIP-relative instruction with a trailing `imm16` (the displacement is
/// measured from the end of the *whole* instruction, immediate included).
fn rip_imm16(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: u16) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 2;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

/// Emit a RIP-relative instruction with a trailing `imm32`.
fn rip_imm32(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32, imm: i32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
    c.extend_from_slice(&imm.to_le_bytes());
}

/// `mov qword [rip+target], imm32` (sign-extended).
fn mov_mem_imm64(c: &mut Vec<u8>, target_rva: u32, imm: i32) {
    rip_imm32(c, &[0x48, 0xC7, 0x05], target_rva, imm);
}
/// `mov dword [rip+target], imm32`.
fn mov_mem_imm32(c: &mut Vec<u8>, target_rva: u32, imm: i32) {
    rip_imm32(c, &[0xC7, 0x05], target_rva, imm);
}
/// `mov qword [rip+target], rax`.
fn mov_mem_rax(c: &mut Vec<u8>, target_rva: u32) {
    rip(c, &[0x48, 0x89, 0x05], target_rva);
}
/// `lea rax, [rip+target]`.
fn lea_rax(c: &mut Vec<u8>, target_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x05], target_rva);
}
/// `mov qword [rsp+disp8], imm32` — one outgoing stack argument.
fn stack_arg_imm(c: &mut Vec<u8>, disp: u8, imm: i32) {
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, disp]);
    c.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `jcc rel32` with a placeholder; returns the fixup position.
fn jcc_near(c: &mut Vec<u8>, cc: u8) -> usize {
    c.extend_from_slice(&[0x0F, cc]);
    let at = c.len();
    c.extend_from_slice(&[0, 0, 0, 0]);
    at
}
/// Emit `jmp rel32` with a placeholder; returns the fixup position.
fn jmp_near(c: &mut Vec<u8>) -> usize {
    c.push(0xE9);
    let at = c.len();
    c.extend_from_slice(&[0, 0, 0, 0]);
    at
}
/// Point a forward `rel32` placeholder at the current position.
fn patch_near(c: &mut [u8], at: usize) {
    let rel = c.len() as i32 - (at as i32 + 4);
    c[at..at + 4].copy_from_slice(&rel.to_le_bytes());
}
/// Point a forward `rel8` placeholder (the byte at `at`) at the current position.
fn patch_short(c: &mut [u8], at: usize) {
    let rel = c.len() as i64 - (at as i64 + 1);
    c[at] = (rel as i8) as u8;
}
/// Emit a backward short jump (`op` = `0xEB` for `jmp`, `0x75` for `jnz`).
fn jmp_short_back(c: &mut Vec<u8>, op: u8, target: usize) {
    c.extend_from_slice(&[op, 0x00]);
    let end = c.len();
    c[end - 1] = ((target as i64 - end as i64) as i8) as u8;
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

    /// The generated image is a PE32+ console executable that statically imports
    /// `comdlg32!GetOpenFileNameW`/`GetSaveFileNameW` — the shape the W6.2 gate
    /// depends on (the static import is what forces Wine's comdlg32 to load).
    #[test]
    fn comdlg_sample_is_a_pe_importing_comdlg32() {
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
        assert!(has("comdlg32.dll", "GetOpenFileNameW"), "imports comdlg32!GetOpenFileNameW");
        assert!(has("comdlg32.dll", "GetSaveFileNameW"), "imports comdlg32!GetSaveFileNameW");
        assert!(has("kernel32.dll", "CreateFileW"), "opens the path it is handed");
        assert!(has("kernel32.dll", "ReadFile"));
        assert!(has("kernel32.dll", "WriteFile"));

        // The dialog titles a bridge keys off travel in `.rdata` as UTF-16.
        for s in [OPEN_TITLE, SAVE_TITLE, INITIAL_DIR] {
            let needle = wide(s);
            assert!(
                exe.windows(needle.len()).any(|w| w == needle),
                "the wide string {s:?} is in the image"
            );
        }
        // Every tag the gate greps for travels as ASCII.
        for tag in TAGS {
            let needle = format!("{tag}=");
            assert!(
                exe.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "the {tag} tag is in the image"
            );
        }
    }

    /// `lStructSize` must be the x64 `sizeof(OPENFILENAMEW)`; every real
    /// implementation rejects anything else, so pin the constant.
    #[test]
    fn openfilenamew_is_152_bytes_on_x64() {
        assert_eq!(OPENFILENAMEW_SIZE, 152);
    }
}
