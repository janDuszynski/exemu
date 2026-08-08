//! Generates the **known-folder** console PE — the roadmap W6.6 proof binary.
//!
//! The produced `.exe` statically imports `shell32.dll!SHGetFolderPathW` and
//! `shlwapi.dll!PathBuildRootW`. The static imports are the point: they force
//! the loader to map + relocate + bind **Wine's own shell32 and shlwapi** and run
//! their `DllMain`s before the entry point, so every call below is guest PE code
//! from the pinned prefix — exemu contributes only the sandbox the resolved paths
//! land in (see `exemu_os::folders`).
//!
//! What it does, for each CSIDL in [`CSIDLS`]:
//!
//! 1. `SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, buf)`;
//! 2. writes `"<tag>=<path>\n"` to stdout, squeezing the UTF-16 result to ASCII
//!    in-line (so the binary needs no `WideCharToMultiByte` import — one less
//!    thing that could service the test instead of Wine);
//! 3. counts a failure when the HRESULT is non-zero **or** the returned string is
//!    empty.
//!
//! Then it calls `shlwapi!PathBuildRootW(buf, 2)` — which is shlwapi's *own*
//! local code, not one of the many Wine-11 shlwapi exports that tail-jump into
//! `kernelbase` — and prints `"ROOT=C:\"`.
//!
//! The exit code is the failure count, so `0` means every folder resolved. On the
//! **emulated** path `shell32!SHGetFolderPathW` is an unimplemented thunk that
//! returns 0 (`S_OK`) without touching the buffer, so every line comes out empty
//! and the program exits non-zero: that is the control the W6.6 gate uses, so a
//! pass can only be attributed to Wine's shell32.
//!
//! The layout code mirrors [`crate::sample`] (hand-assembled, RIP-relative
//! displacements patched from known RVAs).

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// `SHGetFolderPathW` writes at most `MAX_PATH` code units.
const MAX_PATH: u32 = 260;

/// The known folders the sample resolves, as `(tag, CSIDL)`.
///
/// `CSIDL_FLAG_CREATE` (0x8000) is deliberately **not** set: the gate wants to
/// prove the folders already exist in the sandbox because exemu seeded them, not
/// that shell32 created them on demand.
pub const CSIDLS: [(&str, u32); 6] = [
    ("APPDATA", 0x001a),        // CSIDL_APPDATA
    ("LOCALAPPDATA", 0x001c),   // CSIDL_LOCAL_APPDATA
    ("PERSONAL", 0x0005),       // CSIDL_PERSONAL   (Documents)
    ("DESKTOP", 0x0010),        // CSIDL_DESKTOPDIRECTORY
    ("PROGRAMS", 0x0002),       // CSIDL_PROGRAMS   (Start Menu\Programs)
    ("COMMONPROGRAMS", 0x0017), // CSIDL_COMMON_PROGRAMS
];

/// The tag printed for the `shlwapi!PathBuildRootW` result.
pub const ROOT_TAG: &str = "ROOT";

/// Drive index handed to `PathBuildRootW` (0 = A:, so 2 = C:).
const ROOT_DRIVE: u32 = 2;

/// Build the known-folder sample executable.
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
        ("shell32.dll", vec!["SHGetFolderPathW"]),
        ("shlwapi.dll", vec!["PathBuildRootW"]),
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
    /// RVA of the `"<tag>="` ASCII prefix for each entry of [`CSIDLS`].
    tag_rva: Vec<u32>,
    /// Byte length of each tag prefix (including the `=`).
    tag_len: Vec<u32>,
    /// RVA + length of the `"ROOT="` prefix.
    root_tag_rva: u32,
    root_tag_len: u32,
    // --- `.data` (BSS) scratch, laid out by `Rdata::build` -----------------
    /// UTF-16 buffer `SHGetFolderPathW`/`PathBuildRootW` write into.
    wbuf_rva: u32,
    /// ASCII line buffer the squeezed path plus `'\n'` is built in.
    abuf_rva: u32,
    /// `WriteFile`'s `lpNumberOfBytesWritten` slot.
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
        for (tag, _) in CSIDLS {
            tag_rva.push(RDATA_RVA + pos);
            let n = tag.len() as u32 + 1;
            tag_len.push(n);
            pos += n;
        }
        let root_tag_rva = RDATA_RVA + pos;
        let root_tag_len = ROOT_TAG.len() as u32 + 1;
        pos += root_tag_len;

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
        for (i, (tag, _)) in CSIDLS.iter().enumerate() {
            let off = (tag_rva[i] - RDATA_RVA) as usize;
            b[off..off + tag.len()].copy_from_slice(tag.as_bytes());
            b[off + tag.len()] = b'=';
        }
        let off = (root_tag_rva - RDATA_RVA) as usize;
        b[off..off + ROOT_TAG.len()].copy_from_slice(ROOT_TAG.as_bytes());
        b[off + ROOT_TAG.len()] = b'=';

        // `.data` (BSS) scratch layout.
        let wbuf_rva = DATA_RVA;
        let abuf_rva = wbuf_rva + MAX_PATH * 2 + 8;
        let written_rva = align_up_u32(abuf_rva + MAX_PATH + 8, 8);
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
            root_tag_rva,
            root_tag_len,
            wbuf_rva,
            abuf_rva,
            written_rva,
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

/// Emit the sample's `.text`.
///
/// Register usage across calls (all Win64 non-volatile, so they survive the
/// calls into Wine's DLLs): `rsi` = cached stdout handle, `r13d` = failure
/// count, `r14` = the ASCII line buffer's write cursor.
fn build_text(r: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // sub rsp, FRAME
    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME as u8]);
    // xor r13d, r13d  (failure count)
    c.extend_from_slice(&[0x45, 0x31, 0xED]);
    // mov ecx, -11 (STD_OUTPUT_HANDLE) ; call [GetStdHandle] ; mov rsi, rax
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(&mut c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]);

    for (i, (_, csidl)) in CSIDLS.iter().enumerate() {
        emit_folder(&mut c, r, i, *csidl);
    }
    emit_root(&mut c, r);

    // ExitProcess(r13d) — the failure count.
    c.extend_from_slice(&[0x44, 0x89, 0xE9]); // mov ecx, r13d
    rip(&mut c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC); // int3 (unreached)
    c
}

/// One `SHGetFolderPathW` call plus its `"<tag>=<path>\n"` report.
fn emit_folder(c: &mut Vec<u8>, r: &Rdata, i: usize, csidl: u32) {
    // Clear the first code unit so a callee that leaves the buffer untouched is
    // observable as an empty string (this is what makes the emulated control
    // fail loudly instead of printing stale bytes).
    // mov word [rip+wbuf], 0
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.wbuf_rva, 0);

    // SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT=0, wbuf)
    c.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx      (hwnd)
    c.extend_from_slice(&[0xBA]); // mov edx, csidl
    c.extend_from_slice(&csidl.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d  (hToken)
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d  (dwFlags)
    rip(c, &[0x48, 0x8D, 0x05], r.wbuf_rva); // lea rax, [rip+wbuf]
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    rip(c, &[0xFF, 0x15], r.slot("SHGetFolderPathW"));
    // A non-zero HRESULT is a failure.
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x74, 0x03]); // je +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    emit_report(c, r, r.tag_rva[i], r.tag_len[i], true);
}

/// The `shlwapi!PathBuildRootW` call plus its `"ROOT=C:\"` report.
fn emit_root(c: &mut Vec<u8>, r: &Rdata) {
    rip_imm16(c, &[0x66, 0xC7, 0x05], r.wbuf_rva, 0);
    // PathBuildRootW(wbuf, ROOT_DRIVE)
    rip(c, &[0x48, 0x8D, 0x0D], r.wbuf_rva); // lea rcx, [rip+wbuf]
    c.extend_from_slice(&[0xBA]);
    c.extend_from_slice(&ROOT_DRIVE.to_le_bytes()); // mov edx, drive
    rip(c, &[0xFF, 0x15], r.slot("PathBuildRootW"));
    // It returns the buffer; a NULL return is a failure.
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x75, 0x03]); // jne +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d

    emit_report(c, r, r.root_tag_rva, r.root_tag_len, false);
}

/// Emit `"<tag>" + squeeze(wbuf) + "\n"` into the ASCII buffer and `WriteFile`
/// it to stdout. When `count_empty` is set, an empty `wbuf` also bumps the
/// failure count — the check that makes "the API returned S_OK but wrote
/// nothing" (the emulated stub's behaviour) a hard failure.
fn emit_report(c: &mut Vec<u8>, r: &Rdata, tag_rva: u32, tag_len: u32, count_empty: bool) {
    // r14 = abuf ; rdi = tag ; ecx = tag_len — copy the prefix.
    rip(c, &[0x4C, 0x8D, 0x35], r.abuf_rva); // lea r14, [rip+abuf]
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

    // Squeeze the UTF-16 path into ASCII: rdi = wbuf; while (u16 != 0) copy low
    // byte. `r15b` records whether any code unit was copied.
    rip(c, &[0x48, 0x8D, 0x3D], r.wbuf_rva); // lea rdi, [rip+wbuf]
    c.extend_from_slice(&[0x45, 0x31, 0xFF]); // xor r15d, r15d
    let sq_loop = c.len();
    c.extend_from_slice(&[0x66, 0x8B, 0x07]); // mov ax, [rdi]
    c.extend_from_slice(&[0x66, 0x85, 0xC0]); // test ax, ax
    c.extend_from_slice(&[0x74, 0x00]); // je sq_done
    let sq_done_fix = c.len() - 1;
    c.extend_from_slice(&[0x41, 0x88, 0x06]); // mov [r14], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x48, 0x83, 0xC7, 0x02]); // add rdi, 2
    c.extend_from_slice(&[0x41, 0xB7, 0x01]); // mov r15b, 1
    c.extend_from_slice(&[0xEB, 0x00]); // jmp sq_loop
    let back = c.len();
    c[back - 1] = ((sq_loop as i64 - back as i64) as i8) as u8;
    let sq_done = c.len();
    c[sq_done_fix] = ((sq_done as i64 - (sq_done_fix as i64 + 1)) as i8) as u8;

    if count_empty {
        // An empty result is a failure too: test r15b, r15b ; jnz +3 ; inc r13d
        c.extend_from_slice(&[0x45, 0x84, 0xFF]);
        c.extend_from_slice(&[0x75, 0x03]);
        c.extend_from_slice(&[0x41, 0xFF, 0xC5]);
    }

    // Terminate the line with '\n' and compute the length in r8d.
    c.extend_from_slice(&[0x41, 0xC6, 0x06, 0x0A]); // mov byte [r14], '\n'
    c.extend_from_slice(&[0x49, 0xFF, 0xC6]); // inc r14
    c.extend_from_slice(&[0x4C, 0x89, 0xF0]); // mov rax, r14
    rip(c, &[0x48, 0x8D, 0x15], r.abuf_rva); // lea rdx, [rip+abuf]
    c.extend_from_slice(&[0x48, 0x29, 0xD0]); // sub rax, rdx
    c.extend_from_slice(&[0x41, 0x89, 0xC0]); // mov r8d, eax

    // WriteFile(stdout, abuf, len, &written, NULL)
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

/// Emit an instruction ending in a RIP-relative `disp32`.
fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

/// Emit a RIP-relative instruction with a trailing `imm16` (the displacement is
/// measured from the end of the *whole* instruction, immediate included).
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

    /// The generated image is a PE32+ console executable that statically imports
    /// `shell32!SHGetFolderPathW` and `shlwapi!PathBuildRootW` — the shape the
    /// W6.6 gate depends on (the static imports are what force Wine's shell32 and
    /// shlwapi to load).
    #[test]
    fn shell_sample_is_a_pe_importing_shell32_and_shlwapi() {
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
        assert!(has("shell32.dll", "SHGetFolderPathW"), "imports shell32!SHGetFolderPathW");
        assert!(has("shlwapi.dll", "PathBuildRootW"), "imports shlwapi!PathBuildRootW");
        assert!(has("kernel32.dll", "WriteFile"));
        assert!(has("kernel32.dll", "ExitProcess"));

        // Every tag the gate greps for travels in `.rdata`.
        for (tag, _) in CSIDLS {
            let needle = format!("{tag}=");
            assert!(
                exe.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "the {tag} tag is in the image"
            );
        }
    }
}
