//! A self-contained generator for a minimal, *real* 64-bit PE executable.
//!
//! The produced `.exe` is a valid Windows console program: it imports
//! `GetStdHandle`, `WriteFile` and `ExitProcess` from `kernel32.dll`, writes
//! a line to standard output and exits with code 0. It exists so the
//! emulator can be exercised end to end without needing a Windows toolchain,
//! and so the loader/CPU/OS pipeline has a known-good input.
//!
//! Everything is laid out programmatically and RIP-relative displacements in
//! the code are patched once the section RVAs are known, so there are no
//! hand-computed magic offsets.

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const PE_OFF: usize = 0x40;

/// The message the sample program prints.
pub const SAMPLE_MESSAGE: &str =
    "Hello from exemu! This Windows x64 .exe is running on Apple Silicon.\n";

/// Build the bytes of the sample `.exe`.
pub fn build() -> Vec<u8> {
    let rdata = Rdata::build();
    let text = build_text(&rdata);

    // File layout: [headers | .text | .rdata], each raw-part file-aligned.
    let headers_raw = FILE_ALIGN as usize; // 0x200 is plenty for our headers
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rdata.bytes.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];

    // ---- DOS header --------------------------------------------------------
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32); // e_lfanew

    // ---- PE signature + COFF file header -----------------------------------
    put_u32(&mut f, PE_OFF, 0x0000_4550); // "PE\0\0"
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664); // Machine = AMD64
    put_u16(&mut f, coff + 2, 2); // NumberOfSections
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16); // SizeOfOptionalHeader
    put_u16(&mut f, coff + 18, 0x0022); // Characteristics: EXECUTABLE | LARGE_ADDRESS_AWARE

    // ---- Optional header (PE32+) -------------------------------------------
    let opt = coff + 20;
    let image_size = align_up_u32(RDATA_RVA + rdata.bytes.len() as u32, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B); // Magic = PE32+
    f[opt + 2] = 14; // MajorLinkerVersion
    put_u32(&mut f, opt + 4, text_raw as u32); // SizeOfCode
    put_u32(&mut f, opt + 8, rdata_raw as u32); // SizeOfInitializedData
    put_u32(&mut f, opt + 16, TEXT_RVA); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA); // BaseOfCode
    put_u64(&mut f, opt + 24, IMAGE_BASE); // ImageBase
    put_u32(&mut f, opt + 32, SECTION_ALIGN); // SectionAlignment
    put_u32(&mut f, opt + 36, FILE_ALIGN); // FileAlignment
    put_u16(&mut f, opt + 40, 6); // MajorOperatingSystemVersion
    put_u16(&mut f, opt + 48, 6); // MajorSubsystemVersion
    put_u32(&mut f, opt + 56, image_size); // SizeOfImage
    put_u32(&mut f, opt + 60, headers_raw as u32); // SizeOfHeaders
    put_u16(&mut f, opt + 68, 3); // Subsystem = CONSOLE
    put_u64(&mut f, opt + 72, 0x10_0000); // SizeOfStackReserve
    put_u64(&mut f, opt + 80, 0x1000); // SizeOfStackCommit
    put_u64(&mut f, opt + 88, 0x10_0000); // SizeOfHeapReserve
    put_u64(&mut f, opt + 96, 0x1000); // SizeOfHeapCommit
    put_u32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes

    // Data directories: [1] = Import, [12] = IAT.
    let dir = |i: usize| opt + 112 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA + rdata.import_dir_off); // Import table RVA
    put_u32(&mut f, dir(1) + 4, rdata.import_dir_size); // Import table size
    put_u32(&mut f, dir(12), RDATA_RVA + rdata.iat_off); // IAT RVA
    put_u32(&mut f, dir(12) + 4, rdata.iat_size); // IAT size

    // ---- Section table -----------------------------------------------------
    let sec = opt + OPT_HEADER_SIZE;
    // 0x60000020 = CODE | EXECUTE | READ ; 0x40000040 = INITIALIZED_DATA | READ
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020,
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rdata.bytes.len() as u32,
        vaddr: RDATA_RVA,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040,
    });

    // ---- Section bodies ----------------------------------------------------
    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rdata.bytes.len()].copy_from_slice(&rdata.bytes);

    f
}

// The optional header is the fixed 112-byte part plus 16 data directories.
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// The `.rdata` blob: imports (descriptor table, ILT, IAT, name table),
/// the DLL name and the message, with the RVAs the code and headers need.
struct Rdata {
    bytes: Vec<u8>,
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,
    // IAT slot RVAs (absolute, i.e. RDATA_RVA + offset) for the three imports.
    iat_get_std_handle: u32,
    iat_write_file: u32,
    iat_exit_process: u32,
    msg_rva: u32,
}

impl Rdata {
    fn build() -> Rdata {
        // Imported names, in IAT order.
        let names = ["GetStdHandle", "WriteFile", "ExitProcess"];

        // Plan offsets within .rdata.
        let import_dir_off = 0u32;
        let import_dir_size = 2 * 20; // one descriptor + null terminator
        let ilt_off = import_dir_off + import_dir_size;
        let ilt_size = (names.len() as u32 + 1) * 8;
        let iat_off = ilt_off + ilt_size;
        let iat_size = ilt_size;

        let mut pos = iat_off + iat_size;

        // IMAGE_IMPORT_BY_NAME blobs (hint u16 + asciiz), 2-byte aligned.
        let mut ibn_rva = Vec::new();
        for n in &names {
            pos = align_up_u32(pos, 2);
            ibn_rva.push(RDATA_RVA + pos);
            pos += 2 + n.len() as u32 + 1;
        }
        pos = align_up_u32(pos, 2);
        let dllname_rva = RDATA_RVA + pos;
        let dllname = b"kernel32.dll\0";
        pos += dllname.len() as u32;

        pos = align_up_u32(pos, 4);
        let msg_rva = RDATA_RVA + pos;
        pos += SAMPLE_MESSAGE.len() as u32;

        // Now emit the bytes.
        let mut b = vec![0u8; pos as usize];

        // Import descriptor for kernel32.
        put_u32(&mut b, import_dir_off as usize, ilt_off + RDATA_RVA); // OriginalFirstThunk (ILT)
        put_u32(&mut b, import_dir_off as usize + 12, dllname_rva); // Name
        put_u32(&mut b, import_dir_off as usize + 16, iat_off + RDATA_RVA); // FirstThunk (IAT)
        // descriptor[1] is already all-zero (terminator).

        // ILT and IAT: identical arrays of RVAs to the IBN blobs.
        for (i, &rva) in ibn_rva.iter().enumerate() {
            put_u64(&mut b, (ilt_off as usize) + i * 8, rva as u64);
            put_u64(&mut b, (iat_off as usize) + i * 8, rva as u64);
        }

        // IBN blobs.
        for (i, n) in names.iter().enumerate() {
            let off = (ibn_rva[i] - RDATA_RVA) as usize;
            // hint stays 0
            b[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
        }

        // DLL name and message.
        let doff = (dllname_rva - RDATA_RVA) as usize;
        b[doff..doff + dllname.len()].copy_from_slice(dllname);
        let moff = (msg_rva - RDATA_RVA) as usize;
        b[moff..moff + SAMPLE_MESSAGE.len()].copy_from_slice(SAMPLE_MESSAGE.as_bytes());

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat_get_std_handle: iat_off + RDATA_RVA,
            iat_write_file: iat_off + RDATA_RVA + 8,
            iat_exit_process: iat_off + RDATA_RVA + 16,
            msg_rva,
        }
    }
}

/// Emit the `.text` machine code, patching RIP-relative displacements to the
/// IAT slots and the message using their now-known RVAs.
fn build_text(rdata: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // sub rsp, 0x28    (shadow space + alignment; also holds the 5th arg)
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov ecx, -11     (STD_OUTPUT_HANDLE)
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());

    // call [rip+GetStdHandle]
    emit_rip_call(&mut c, rdata.iat_get_std_handle);

    // mov rcx, rax     (hFile = returned handle)
    c.extend_from_slice(&[0x48, 0x89, 0xC1]);

    // lea rdx, [rip+msg]
    emit_rip_lea_rdx(&mut c, rdata.msg_rva);

    // mov r8d, len     (nNumberOfBytesToWrite)
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(SAMPLE_MESSAGE.len() as u32).to_le_bytes());

    // xor r9d, r9d     (lpNumberOfBytesWritten = NULL)
    c.extend_from_slice(&[0x45, 0x31, 0xC9]);

    // mov qword [rsp+0x20], 0   (lpOverlapped = NULL, the 5th argument slot)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);

    // call [rip+WriteFile]
    emit_rip_call(&mut c, rdata.iat_write_file);

    // xor ecx, ecx     (uExitCode = 0)
    c.extend_from_slice(&[0x31, 0xC9]);

    // call [rip+ExitProcess]
    emit_rip_call(&mut c, rdata.iat_exit_process);

    // int3             (should be unreachable)
    c.push(0xCC);

    c
}

/// `FF 15 <disp32>` — call qword ptr [rip + disp]. `target_rva` is the IAT
/// slot; disp is relative to the end of this 6-byte instruction.
fn emit_rip_call(c: &mut Vec<u8>, target_rva: u32) {
    c.extend_from_slice(&[0xFF, 0x15]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = target_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
}

/// `48 8D 15 <disp32>` — lea rdx, [rip + disp].
fn emit_rip_lea_rdx(c: &mut Vec<u8>, target_rva: u32) {
    c.extend_from_slice(&[0x48, 0x8D, 0x15]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = target_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
}

// ---- byte-level helpers ----------------------------------------------------

/// The fields of an `IMAGE_SECTION_HEADER` the sample needs to set.
struct SecHeader<'a> {
    name: &'a [u8],
    vsize: u32,
    vaddr: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
}

fn write_section(f: &mut [u8], at: usize, s: SecHeader) {
    f[at..at + s.name.len()].copy_from_slice(s.name);
    put_u32(f, at + 8, s.vsize);
    put_u32(f, at + 12, s.vaddr);
    put_u32(f, at + 16, s.raw_size);
    put_u32(f, at + 20, s.raw_ptr);
    put_u32(f, at + 36, s.chars);
}

#[inline]
fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}
#[inline]
fn align_up_u32(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}
