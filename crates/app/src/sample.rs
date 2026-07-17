//! A self-contained generator for a minimal, *real* 64-bit PE executable.
//!
//! The produced `.exe` is a valid Windows console program: it imports
//! `GetStdHandle`, `WriteFile` and `ExitProcess` from `kernel32.dll`, prints
//! a greeting, then does a little **SSE2 double-precision arithmetic**
//! (`(1.5 + 2.25) * 2.0`, truncated to `7`) and prints the result, and exits
//! with code 0. It exists so the emulator can be exercised end to end without
//! needing a Windows toolchain, and so the loader/CPU/OS/SSE pipeline has a
//! known-good input.
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

/// The greeting the sample program prints first.
pub const SAMPLE_MESSAGE: &str =
    "Hello from exemu! This Windows x64 .exe is running on Apple Silicon.\n";

/// The prefix printed before the SSE-computed number (a single ASCII digit
/// plus newline follows it at run time).
pub const SAMPLE_SSE_PREFIX: &str = "SSE2 check: trunc((1.5 + 2.25) * 2.0) = ";

/// The three `double` constants the sample loads into XMM registers.
const SSE_CONSTS: [f64; 3] = [1.5, 2.25, 2.0];

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

/// The sentinel byte a TLS `DLL_PROCESS_ATTACH` callback writes, which the
/// entry point then reads and reports as the process exit code — proving the
/// callback fired before the entry point ran (roadmap W0.3).
pub const TLS_SENTINEL: u8 = 0x2A;

/// Build a minimal, *real* 64-bit PE with a load-time TLS callback.
///
/// The image's `IMAGE_TLS_DIRECTORY` names one callback that stores
/// [`TLS_SENTINEL`] into a `.data` cell. The entry point reads that cell and
/// exits with its value: if the loader ran the callback before entry (as the
/// PE spec requires) the process exits `TLS_SENTINEL`; otherwise it exits `0`.
/// The directory also carries a non-empty initialization template and an
/// `AddressOfIndex` slot so the loader's index-publish + template-copy paths
/// are exercised end to end.
pub fn build_with_tls() -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    const RDATA_RVA_L: u32 = 0x2000;
    const DATA_RVA_L: u32 = 0x3000;

    // --- .data layout: sentinel byte, TLS index slot, template ------------
    let sentinel_rva = DATA_RVA_L; // 1 byte
    let tls_index_rva = DATA_RVA_L + 8; // DWORD (8-aligned)
    let tls_tmpl_rva = DATA_RVA_L + 0x10; // 8-byte init template
    let tls_tmpl_len = 8u32;

    // --- .rdata layout: imports + TLS directory + callback array ----------
    // Imports: a single kernel32!ExitProcess.
    let import_dir_off = 0u32;
    let import_dir_size = 2 * 20u32; // one descriptor + null terminator
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = 2 * 8u32; // one entry + null
    let iat_off = ilt_off + ilt_size;
    let iat_size = ilt_size;
    let mut pos = iat_off + iat_size;
    // IMAGE_IMPORT_BY_NAME for ExitProcess.
    pos = align_up_u32(pos, 2);
    let ibn_off = pos;
    let ibn_name = b"ExitProcess";
    pos += 2 + ibn_name.len() as u32 + 1;
    let dllname_off = pos;
    let dllname = b"kernel32.dll\0";
    pos += dllname.len() as u32;
    // TLS directory (40 bytes, 8-aligned) then the callback array [cb, 0].
    pos = align_up_u32(pos, 8);
    let tls_dir_off = pos;
    let tls_dir_size = 40u32;
    pos += tls_dir_size;
    let tls_cb_off = pos;
    pos += 16; // [callback VA, 0]

    let iat_exit_process_rva = RDATA_RVA_L + iat_off;

    let mut rd = vec![0u8; pos as usize];
    // Import descriptor for kernel32: OriginalFirstThunk / Name / FirstThunk.
    put_u32(&mut rd, import_dir_off as usize, RDATA_RVA_L + ilt_off);
    put_u32(&mut rd, import_dir_off as usize + 12, RDATA_RVA_L + dllname_off);
    put_u32(&mut rd, import_dir_off as usize + 16, RDATA_RVA_L + iat_off);
    // ILT and IAT both point at the IBN blob.
    put_u64(&mut rd, ilt_off as usize, (RDATA_RVA_L + ibn_off) as u64);
    put_u64(&mut rd, iat_off as usize, (RDATA_RVA_L + ibn_off) as u64);
    // IBN: hint (0) + name.
    let ibn = ibn_off as usize;
    rd[ibn + 2..ibn + 2 + ibn_name.len()].copy_from_slice(ibn_name);
    let dn = dllname_off as usize;
    rd[dn..dn + dllname.len()].copy_from_slice(dllname);

    // TLS directory: addresses are preferred-base VAs.
    let td = tls_dir_off as usize;
    put_u64(&mut rd, td, IMAGE_BASE + tls_tmpl_rva as u64); // StartAddressOfRawData
    put_u64(&mut rd, td + 8, IMAGE_BASE + (tls_tmpl_rva + tls_tmpl_len) as u64); // End
    put_u64(&mut rd, td + 16, IMAGE_BASE + tls_index_rva as u64); // AddressOfIndex
    put_u64(&mut rd, td + 24, IMAGE_BASE + (RDATA_RVA_L + tls_cb_off) as u64); // AddressOfCallBacks
    // SizeOfZeroFill (0) and Characteristics (0) stay zero.
    // Callback array: [callback VA, 0].
    put_u64(&mut rd, tls_cb_off as usize, IMAGE_BASE + (TEXT_RVA_L + TLS_CB_OFF) as u64);

    // --- .text: the TLS callback and the entry point ----------------------
    // Callback lives at TEXT_RVA + TLS_CB_OFF, entry at TEXT_RVA + ENTRY_OFF.
    let text = build_tls_text(sentinel_rva, iat_exit_process_rva);

    // --- .data body: the template bytes (a recognizable pattern) ----------
    let data_len = (tls_tmpl_rva + tls_tmpl_len - DATA_RVA_L) as usize;
    let mut data = vec![0u8; data_len];
    let tmpl_start = (tls_tmpl_rva - DATA_RVA_L) as usize;
    for j in 0..tls_tmpl_len as usize {
        data[tmpl_start + j] = 0xB0u8.wrapping_add(j as u8);
    }

    // --- Assemble the file ------------------------------------------------
    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rd.len(), FILE_ALIGN as usize);
    let data_ptr = rdata_ptr + rdata_raw;
    let data_raw = align_up(data.len(), FILE_ALIGN as usize);
    let file_len = data_ptr + data_raw;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664); // AMD64
    put_u16(&mut f, coff + 2, 3); // 3 sections
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022); // EXECUTABLE | LARGE_ADDRESS_AWARE

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA_L + data.len() as u32, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 16, TEXT_RVA_L + ENTRY_OFF); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA_L); // BaseOfCode
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3); // CONSOLE
    put_u64(&mut f, opt + 72, 0x10_0000);
    put_u64(&mut f, opt + 80, 0x1000);
    put_u64(&mut f, opt + 88, 0x10_0000);
    put_u64(&mut f, opt + 96, 0x1000);
    put_u32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes

    let dir = |i: usize| opt + 112 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA_L + import_dir_off); // Import table
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(9), RDATA_RVA_L + tls_dir_off); // TLS directory
    put_u32(&mut f, dir(9) + 4, tls_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA_L + iat_off); // IAT
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA_L,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020, // CODE | EXECUTE | READ
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA_L,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040, // INITIALIZED_DATA | READ
    });
    write_section(&mut f, sec + 80, SecHeader {
        name: b".data",
        vsize: data.len() as u32,
        vaddr: DATA_RVA_L,
        raw_size: data_raw as u32,
        raw_ptr: data_ptr as u32,
        chars: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f[data_ptr..data_ptr + data.len()].copy_from_slice(&data);
    f
}

// Fixed offsets within the TLS fixture's `.text` (see `build_tls_text`).
const TLS_CB_OFF: u32 = 0x00; // the callback comes first
const ENTRY_OFF: u32 = 0x20; // the entry point follows, at a fixed offset

/// Emit the TLS fixture's `.text`: a callback that stores [`TLS_SENTINEL`] into
/// the `.data` sentinel cell, then the entry point that reads that cell and
/// exits with its value. Both use RIP-relative addressing patched from RVAs.
fn build_tls_text(sentinel_rva: u32, iat_exit_process_rva: u32) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // _tls_cb @ TLS_CB_OFF: mov byte [rip+sentinel], TLS_SENTINEL ; ret
    // Encoding: C6 05 <disp32> <imm8>. disp is from end of instruction (after imm8).
    c.extend_from_slice(&[0xC6, 0x05]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4 + 1; // +disp32 +imm8
    let disp = sentinel_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    c.push(TLS_SENTINEL);
    c.push(0xC3); // ret

    // Pad to ENTRY_OFF.
    while c.len() < ENTRY_OFF as usize {
        c.push(0xCC);
    }

    // _entry @ ENTRY_OFF:
    //   sub rsp, 0x28              (shadow space + alignment)
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    //   movzx ecx, byte [rip+sentinel]   ; 0F B6 0D <disp32>
    c.extend_from_slice(&[0x0F, 0xB6, 0x0D]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = sentinel_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    //   call [rip+ExitProcess]     ; FF 15 <disp32>
    c.extend_from_slice(&[0xFF, 0x15]);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    let disp = iat_exit_process_rva as i64 - next_rva;
    c.extend_from_slice(&(disp as i32).to_le_bytes());
    c.push(0xCC); // int3 (unreached)
    c
}

/// The fixed ASCII payload the file-I/O sample writes and reads back.
pub const FILEIO_PAYLOAD: &[u8] = b"exemu-w3-gate-payload";

/// The guest path the file-I/O sample creates (maps to `<sandbox>/C/wine-gate.txt`).
pub const FILEIO_GUEST_PATH: &str = "C:\\wine-gate.txt";

/// The exit code the file-I/O sample returns when the round-trip matched.
pub const FILEIO_OK_EXIT: i32 = 42;

/// Build a 64-bit PE32+ AMD64 console program that exercises the file-I/O
/// round-trip end to end (roadmap W3.7).
///
/// It imports `CreateFileA`, `WriteFile`, `ReadFile`, `CloseHandle`,
/// `GetStdHandle` and `ExitProcess` from `kernel32.dll` **by name**, so on the
/// Wine-boot path Wine's loader re-binds them to its own kernel32 (whose
/// `CreateFileA` → `NtCreateFile` etc. run through exemu's NT syscalls), and on
/// the emulated path exemu's own kernel32 thunks service them.
///
/// The entry:
///   1. `CreateFileA(FILEIO_GUEST_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
///      FILE_ATTRIBUTE_NORMAL, NULL)` → hFile.
///   2. `WriteFile(hFile, FILEIO_PAYLOAD, len, &written, NULL)`.
///   3. `CloseHandle(hFile)`.
///   4. `CreateFileA(FILEIO_GUEST_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
///      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)` → hRead.
///   5. `ReadFile(hRead, readbuf, len, &read, NULL)`; `CloseHandle(hRead)`.
///   6. Byte-compare `readbuf` to the payload; write `"OK\n"` (match) or
///      `"FAIL\n"` (mismatch) to `GetStdHandle(STD_OUTPUT_HANDLE)`.
///   7. `ExitProcess(FILEIO_OK_EXIT)` on match, else `ExitProcess(1)` — a
///      distinct non-zero code proving exit-code propagation.
pub fn build_console_fileio() -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    const RDATA_RVA_L: u32 = 0x2000;
    const DATA_RVA_L: u32 = 0x3000;

    let payload_len = FILEIO_PAYLOAD.len() as u32;

    // --- .data layout (RW scratch): read buffer + the two byte-count DWORDs ---
    let readbuf_rva = DATA_RVA_L; // payload_len bytes
    let written_rva = align_up_u32(readbuf_rva + payload_len, 8); // DWORD out-param
    let nread_rva = written_rva + 8; // DWORD out-param
    let data_len = (nread_rva + 8 - DATA_RVA_L) as usize;

    // --- .rdata layout: imports (6 by name) + strings ---------------------
    let names = [
        "CreateFileA",
        "WriteFile",
        "ReadFile",
        "CloseHandle",
        "GetStdHandle",
        "ExitProcess",
    ];
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
        ibn_rva.push(RDATA_RVA_L + pos);
        pos += 2 + n.len() as u32 + 1;
    }
    pos = align_up_u32(pos, 2);
    let dllname_rva = RDATA_RVA_L + pos;
    let dllname = b"kernel32.dll\0";
    pos += dllname.len() as u32;

    // Strings: filename (asciiz), payload, "OK\n", "FAIL\n".
    let fname = b"C:\\wine-gate.txt\0";
    let fname_rva = RDATA_RVA_L + pos;
    pos += fname.len() as u32;
    let payload_rva = RDATA_RVA_L + pos;
    pos += payload_len;
    let ok_rva = RDATA_RVA_L + pos;
    let ok_msg = b"OK\n";
    pos += ok_msg.len() as u32;
    let fail_rva = RDATA_RVA_L + pos;
    let fail_msg = b"FAIL\n";
    pos += fail_msg.len() as u32;

    // IAT slot RVAs, in `names` order.
    let iat = |i: u32| RDATA_RVA_L + iat_off + i * 8;
    let iat_create_file = iat(0);
    let iat_write_file = iat(1);
    let iat_read_file = iat(2);
    let iat_close_handle = iat(3);
    let iat_get_std_handle = iat(4);
    let iat_exit_process = iat(5);

    // --- emit .rdata bytes ------------------------------------------------
    let mut rd = vec![0u8; pos as usize];
    put_u32(&mut rd, import_dir_off as usize, RDATA_RVA_L + ilt_off); // OriginalFirstThunk
    put_u32(&mut rd, import_dir_off as usize + 12, dllname_rva); // Name
    put_u32(&mut rd, import_dir_off as usize + 16, RDATA_RVA_L + iat_off); // FirstThunk
    for (i, &rva) in ibn_rva.iter().enumerate() {
        put_u64(&mut rd, ilt_off as usize + i * 8, rva as u64);
        put_u64(&mut rd, iat_off as usize + i * 8, rva as u64);
    }
    for (i, n) in names.iter().enumerate() {
        let off = (ibn_rva[i] - RDATA_RVA_L) as usize;
        rd[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
    }
    let doff = (dllname_rva - RDATA_RVA_L) as usize;
    rd[doff..doff + dllname.len()].copy_from_slice(dllname);
    let foff = (fname_rva - RDATA_RVA_L) as usize;
    rd[foff..foff + fname.len()].copy_from_slice(fname);
    let poff = (payload_rva - RDATA_RVA_L) as usize;
    rd[poff..poff + FILEIO_PAYLOAD.len()].copy_from_slice(FILEIO_PAYLOAD);
    let okoff = (ok_rva - RDATA_RVA_L) as usize;
    rd[okoff..okoff + ok_msg.len()].copy_from_slice(ok_msg);
    let failoff = (fail_rva - RDATA_RVA_L) as usize;
    rd[failoff..failoff + fail_msg.len()].copy_from_slice(fail_msg);

    // --- .text ------------------------------------------------------------
    let text = build_fileio_text(FileioSyms {
        iat_create_file,
        iat_write_file,
        iat_read_file,
        iat_close_handle,
        iat_get_std_handle,
        iat_exit_process,
        fname_rva,
        payload_rva,
        readbuf_rva,
        written_rva,
        nread_rva,
        ok_rva,
        fail_rva,
        payload_len,
    });

    // --- assemble the file ------------------------------------------------
    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rd.len(), FILE_ALIGN as usize);
    // .data is BSS-style: zero VirtualSize, no raw bytes on disk (SizeOfRawData 0),
    // so the loader zero-fills the read buffer + count slots.
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664); // AMD64
    put_u16(&mut f, coff + 2, 3); // 3 sections
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0022); // EXECUTABLE | LARGE_ADDRESS_AWARE

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA_L + data_len as u32, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32); // SizeOfCode
    put_u32(&mut f, opt + 8, rdata_raw as u32); // SizeOfInitializedData
    put_u32(&mut f, opt + 16, TEXT_RVA_L); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA_L); // BaseOfCode
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3); // CONSOLE
    put_u64(&mut f, opt + 72, 0x10_0000);
    put_u64(&mut f, opt + 80, 0x1000);
    put_u64(&mut f, opt + 88, 0x10_0000);
    put_u64(&mut f, opt + 96, 0x1000);
    put_u32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes

    let dir = |i: usize| opt + 112 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA_L + import_dir_off); // Import table
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA_L + iat_off); // IAT
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, SecHeader {
        name: b".text",
        vsize: text.len() as u32,
        vaddr: TEXT_RVA_L,
        raw_size: text_raw as u32,
        raw_ptr: text_ptr as u32,
        chars: 0x6000_0020, // CODE | EXECUTE | READ
    });
    write_section(&mut f, sec + 40, SecHeader {
        name: b".rdata",
        vsize: rd.len() as u32,
        vaddr: RDATA_RVA_L,
        raw_size: rdata_raw as u32,
        raw_ptr: rdata_ptr as u32,
        chars: 0x4000_0040, // INITIALIZED_DATA | READ
    });
    // .data: BSS — VirtualSize covers the scratch region, but no file bytes.
    write_section(&mut f, sec + 80, SecHeader {
        name: b".data",
        vsize: data_len as u32,
        vaddr: DATA_RVA_L,
        raw_size: 0,
        raw_ptr: 0,
        chars: 0xC000_0080, // UNINITIALIZED_DATA | READ | WRITE
    });

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

/// RVAs the file-I/O sample's `.text` needs (IAT slots + data/string RVAs).
struct FileioSyms {
    iat_create_file: u32,
    iat_write_file: u32,
    iat_read_file: u32,
    iat_close_handle: u32,
    iat_get_std_handle: u32,
    iat_exit_process: u32,
    fname_rva: u32,
    payload_rva: u32,
    readbuf_rva: u32,
    written_rva: u32,
    nread_rva: u32,
    ok_rva: u32,
    fail_rva: u32,
    payload_len: u32,
}

/// Emit the file-I/O sample's `.text`. RIP-relative displacements are patched
/// from the known RVAs. Register conventions: `rsi` holds the cached stdout
/// handle (nonvolatile, set once), `rbx` holds the current file handle, and
/// `r12d` holds the pending exit code across the final `WriteFile` (both
/// nonvolatile per the Win64 ABI, so they survive the calls into kernel32).
fn build_fileio_text(s: FileioSyms) -> Vec<u8> {
    const TEXT_RVA_L: u32 = 0x1000;
    let mut c: Vec<u8> = Vec::new();

    // RIP-relative emit local to this function's `.text` base.
    fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
        c.extend_from_slice(prefix);
        let next_rva = TEXT_RVA_L as i64 + c.len() as i64 + 4;
        let disp = target_rva as i64 - next_rva;
        c.extend_from_slice(&(disp as i32).to_le_bytes());
    }

    // sub rsp, 0x48  (shadow 0x20 + stack args at +0x20..+0x38 + 16-byte align)
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]);

    // --- rsi = GetStdHandle(STD_OUTPUT_HANDLE = -11) ---
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes()); // mov ecx, -11
    rip(&mut c, &[0xFF, 0x15], s.iat_get_std_handle); // call [GetStdHandle]
    c.extend_from_slice(&[0x48, 0x89, 0xC6]); // mov rsi, rax

    // --- rbx = CreateFileA(fname, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    //                       FILE_ATTRIBUTE_NORMAL, NULL) ---
    rip(&mut c, &[0x48, 0x8D, 0x0D], s.fname_rva); // lea rcx, [rip+fname]
    c.extend_from_slice(&[0xBA]);
    c.extend_from_slice(&0x4000_0000u32.to_le_bytes()); // mov edx, GENERIC_WRITE
    c.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d  (share = 0)
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d  (sa = NULL)
    // mov dword [rsp+0x20], 2 (CREATE_ALWAYS)
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00]);
    // mov dword [rsp+0x28], 0x80 (FILE_ATTRIBUTE_NORMAL)
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]);
    // mov qword [rsp+0x30], 0 (template NULL)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_create_file); // call [CreateFileA]
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax (hFile)

    // --- WriteFile(hFile, payload, len, &written, NULL) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(&mut c, &[0x48, 0x8D, 0x15], s.payload_rva); // lea rdx, [rip+payload]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&s.payload_len.to_le_bytes()); // mov r8d, len
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.written_rva); // lea r9, [rip+written]
    // mov qword [rsp+0x20], 0 (overlapped NULL)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_write_file); // call [WriteFile]

    // --- CloseHandle(hFile) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(&mut c, &[0xFF, 0x15], s.iat_close_handle); // call [CloseHandle]

    // --- rbx = CreateFileA(fname, GENERIC_READ, FILE_SHARE_READ, NULL,
    //                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) ---
    rip(&mut c, &[0x48, 0x8D, 0x0D], s.fname_rva); // lea rcx, [rip+fname]
    c.extend_from_slice(&[0xBA]);
    c.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // mov edx, GENERIC_READ
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]); // mov r8d, 1 (FILE_SHARE_READ)
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
    // mov dword [rsp+0x20], 3 (OPEN_EXISTING)
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00]);
    // mov dword [rsp+0x28], 0x80
    c.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]);
    // mov qword [rsp+0x30], 0
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]);
    rip(&mut c, &[0xFF, 0x15], s.iat_create_file); // call [CreateFileA]
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax (hRead)

    // --- ReadFile(hRead, readbuf, len, &nread, NULL) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(&mut c, &[0x48, 0x8D, 0x15], s.readbuf_rva); // lea rdx, [rip+readbuf]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&s.payload_len.to_le_bytes()); // mov r8d, len
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.nread_rva); // lea r9, [rip+nread]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov [rsp+0x20], 0
    rip(&mut c, &[0xFF, 0x15], s.iat_read_file); // call [ReadFile]

    // --- CloseHandle(hRead) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(&mut c, &[0xFF, 0x15], s.iat_close_handle); // call [CloseHandle]

    // --- byte-compare readbuf vs payload → r12d = 42 (match) or 1 (mismatch) ---
    c.extend_from_slice(&[0x41, 0xBC, 0x2A, 0x00, 0x00, 0x00]); // mov r12d, 42
    rip(&mut c, &[0x48, 0x8D, 0x3D], s.payload_rva); // lea rdi, [rip+payload]
    rip(&mut c, &[0x4C, 0x8D, 0x05], s.readbuf_rva); // lea r8, [rip+readbuf]
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&s.payload_len.to_le_bytes()); // mov ecx, len
    // .loop:  (len >= 1 always)
    let loop_start = c.len();
    c.extend_from_slice(&[0x8A, 0x07]); // mov al, [rdi]
    c.extend_from_slice(&[0x41, 0x3A, 0x00]); // cmp al, [r8]
    // jne .mismatch (short) — patched below
    c.extend_from_slice(&[0x75, 0x00]);
    let jne_fixup = c.len() - 1;
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]); // inc r8
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    // jnz .loop (short, backward)
    c.extend_from_slice(&[0x75, 0x00]);
    let jnz_fixup = c.len() - 1;
    let after_loop = c.len();
    c[jnz_fixup] = ((loop_start as i64 - after_loop as i64) as i8) as u8;
    // jmp .report (short) — skip the mismatch setter
    c.extend_from_slice(&[0xEB, 0x00]);
    let jmp_fixup = c.len() - 1;
    let mismatch_at = c.len();
    // .mismatch: mov r12d, 1
    c.extend_from_slice(&[0x41, 0xBC, 0x01, 0x00, 0x00, 0x00]);
    let report_at = c.len();
    // patch the two forward jumps.
    c[jne_fixup] = ((mismatch_at as i64 - (jne_fixup as i64 + 1)) as i8) as u8;
    c[jmp_fixup] = ((report_at as i64 - (jmp_fixup as i64 + 1)) as i8) as u8;

    // .report: choose message by r12d, then WriteFile(stdout, msg, len, &written, NULL)
    c.extend_from_slice(&[0x41, 0x83, 0xFC, 0x2A]); // cmp r12d, 42
    // jne .fail_msg (short) — patched below
    c.extend_from_slice(&[0x75, 0x00]);
    let jne_fail_fixup = c.len() - 1;
    // OK branch: lea rdx, [rip+ok] ; mov r8d, 3 ; jmp .write_msg
    rip(&mut c, &[0x48, 0x8D, 0x15], s.ok_rva);
    c.extend_from_slice(&[0x41, 0xB8, 0x03, 0x00, 0x00, 0x00]); // mov r8d, 3
    c.extend_from_slice(&[0xEB, 0x00]); // jmp .write_msg
    let jmp_write_fixup = c.len() - 1;
    let fail_msg_at = c.len();
    c[jne_fail_fixup] = ((fail_msg_at as i64 - (jne_fail_fixup as i64 + 1)) as i8) as u8;
    // .fail_msg: lea rdx, [rip+fail] ; mov r8d, 5
    rip(&mut c, &[0x48, 0x8D, 0x15], s.fail_rva);
    c.extend_from_slice(&[0x41, 0xB8, 0x05, 0x00, 0x00, 0x00]); // mov r8d, 5
    let write_msg_at = c.len();
    c[jmp_write_fixup] = ((write_msg_at as i64 - (jmp_write_fixup as i64 + 1)) as i8) as u8;
    // .write_msg:
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi (stdout)
    rip(&mut c, &[0x4C, 0x8D, 0x0D], s.written_rva); // lea r9, [rip+written] (reuse slot)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov [rsp+0x20], 0
    rip(&mut c, &[0xFF, 0x15], s.iat_write_file); // call [WriteFile]

    // --- ExitProcess(r12d) ---
    c.extend_from_slice(&[0x44, 0x89, 0xE1]); // mov ecx, r12d
    rip(&mut c, &[0xFF, 0x15], s.iat_exit_process); // call [ExitProcess]
    c.push(0xCC); // int3 (unreached)
    c
}

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
    msg1_rva: u32,
    msg2_rva: u32,
    /// RVAs of the three `double` constants.
    const_rva: [u32; 3],
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
        let msg1_rva = RDATA_RVA + pos;
        pos += SAMPLE_MESSAGE.len() as u32;
        let msg2_rva = RDATA_RVA + pos;
        pos += SAMPLE_SSE_PREFIX.len() as u32;

        // The double constants, 8-byte aligned so aligned loads would work too.
        pos = align_up_u32(pos, 8);
        let mut const_rva = [0u32; 3];
        for slot in &mut const_rva {
            *slot = RDATA_RVA + pos;
            pos += 8;
        }

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

        // DLL name, messages and constants.
        let doff = (dllname_rva - RDATA_RVA) as usize;
        b[doff..doff + dllname.len()].copy_from_slice(dllname);
        let m1 = (msg1_rva - RDATA_RVA) as usize;
        b[m1..m1 + SAMPLE_MESSAGE.len()].copy_from_slice(SAMPLE_MESSAGE.as_bytes());
        let m2 = (msg2_rva - RDATA_RVA) as usize;
        b[m2..m2 + SAMPLE_SSE_PREFIX.len()].copy_from_slice(SAMPLE_SSE_PREFIX.as_bytes());
        for (i, c) in SSE_CONSTS.iter().enumerate() {
            let off = (const_rva[i] - RDATA_RVA) as usize;
            b[off..off + 8].copy_from_slice(&c.to_bits().to_le_bytes());
        }

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat_get_std_handle: iat_off + RDATA_RVA,
            iat_write_file: iat_off + RDATA_RVA + 8,
            iat_exit_process: iat_off + RDATA_RVA + 16,
            msg1_rva,
            msg2_rva,
            const_rva,
        }
    }
}

/// Emit the `.text` machine code, patching RIP-relative displacements to the
/// IAT slots, the messages and the float constants using their known RVAs.
///
/// Register usage: `rbx` holds the cached stdout handle; a 2-byte scratch
/// buffer for the computed digit + newline lives at `[rsp+0x30]`.
fn build_text(rdata: &Rdata) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    // sub rsp, 0x38   (shadow space, the 5th-arg slot at +0x20, scratch at +0x30)
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    // mov ecx, -11 (STD_OUTPUT_HANDLE) ; call GetStdHandle ; mov rbx, rax
    c.extend_from_slice(&[0xB9]);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    emit_rip(&mut c, &[0xFF, 0x15], rdata.iat_get_std_handle); // call [GetStdHandle]
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax  (save handle)

    // --- WriteFile(stdout, msg1, len1, NULL, NULL) ---
    emit_write(&mut c, rdata, LenSrc::Rva(rdata.msg1_rva, SAMPLE_MESSAGE.len() as u32));

    // --- SSE2: xmm0 = (1.5 + 2.25) * 2.0 = 7.5 ; eax = (int)7.5 = 7 ---
    emit_rip(&mut c, &[0xF2, 0x0F, 0x10, 0x05], rdata.const_rva[0]); // movsd xmm0, [1.5]
    emit_rip(&mut c, &[0xF2, 0x0F, 0x58, 0x05], rdata.const_rva[1]); // addsd xmm0, [2.25]
    emit_rip(&mut c, &[0xF2, 0x0F, 0x59, 0x05], rdata.const_rva[2]); // mulsd xmm0, [2.0]
    c.extend_from_slice(&[0xF2, 0x0F, 0x2C, 0xC0]); // cvttsd2si eax, xmm0

    // --- turn the result into ASCII "<digit>\n" at [rsp+0x30] ---
    c.extend_from_slice(&[0x04, 0x30]); // add al, '0'
    c.extend_from_slice(&[0x88, 0x44, 0x24, 0x30]); // mov [rsp+0x30], al
    c.extend_from_slice(&[0xC6, 0x44, 0x24, 0x31, 0x0A]); // mov byte [rsp+0x31], '\n'

    // --- WriteFile(stdout, msg2 prefix, len2, NULL, NULL) ---
    emit_write(&mut c, rdata, LenSrc::Rva(rdata.msg2_rva, SAMPLE_SSE_PREFIX.len() as u32));

    // --- WriteFile(stdout, [rsp+0x30], 2, NULL, NULL) — the computed digit ---
    emit_write(&mut c, rdata, LenSrc::Stack);

    // xor ecx, ecx ; call ExitProcess ; int3
    c.extend_from_slice(&[0x31, 0xC9]);
    emit_rip(&mut c, &[0xFF, 0x15], rdata.iat_exit_process);
    c.push(0xCC);

    c
}

/// Where a WriteFile call gets its buffer/length from.
enum LenSrc {
    /// A string constant in `.rdata`: (buffer RVA, length).
    Rva(u32, u32),
    /// The 2-byte scratch buffer at `[rsp+0x30]`.
    Stack,
}

/// Emit a `WriteFile(rbx, buf, len, NULL, NULL)` call sequence.
fn emit_write(c: &mut Vec<u8>, rdata: &Rdata, src: LenSrc) {
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx (hFile)
    let len = match src {
        LenSrc::Rva(rva, len) => {
            emit_rip(c, &[0x48, 0x8D, 0x15], rva); // lea rdx, [rip+buf]
            len
        }
        LenSrc::Stack => {
            c.extend_from_slice(&[0x48, 0x8D, 0x54, 0x24, 0x30]); // lea rdx, [rsp+0x30]
            2
        }
    };
    c.extend_from_slice(&[0x41, 0xB8]); // mov r8d, len
    c.extend_from_slice(&len.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (lpNumberOfBytesWritten)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    emit_rip(c, &[0xFF, 0x15], rdata.iat_write_file); // call [WriteFile]
}

/// Emit an instruction ending in a RIP-relative `disp32`: the fixed
/// `prefix` bytes (opcode + ModRM with mod=00,rm=101), then the displacement
/// from the end of the instruction to `target_rva`.
fn emit_rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
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
