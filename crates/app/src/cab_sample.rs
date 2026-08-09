//! Generates the **CAB-extraction** console PE — the roadmap W6.5 proof binary.
//!
//! The produced `.exe` statically imports `cabinet.dll!FDICreate` / `FDIIsCabinet`
//! / `FDICopy` / `FDIDestroy`, so under the Wine boot the loader must map,
//! relocate, bind and `DllMain` **Wine's own cabinet.dll** before the entry point
//! runs. exemu implements no cabinet decoder of any kind (see [`crate::cab`],
//! which only *writes* archives), so every byte that comes out of the archive
//! came out of Wine's code.
//!
//! # Why this sample is the interesting one
//!
//! `FDI` is a **callback** API: `FDICreate` takes seven caller-supplied function
//! pointers (alloc/free/open/read/write/close/seek) and `FDICopy` takes a
//! notification callback. So the extraction is not "guest calls DLL"; it is
//!
//! ```text
//!   guest .text ──FDICopy──▶ Wine cabinet.dll ──pfnread/pfnwrite/pfnseek──▶ guest .text
//! ```
//!
//! — Wine's guest code calling back **into the emulated program's own code**,
//! repeatedly, across a Win64 ABI boundary the interpreter has to get exactly
//! right (argument registers, volatile/non-volatile split, return values). The
//! callbacks below therefore touch only volatile registers (`rax`, `rcx`, `rdx`,
//! `r8`–`r11`) and never `rbx`/`rsi`/`rdi`/`r12`–`r15`, which the entry point
//! keeps live across the call into Wine.
//!
//! # The guest-side "filesystem"
//!
//! There is none — deliberately. The callbacks serve the archive straight out of
//! the image's own `.rdata` and collect the extracted bytes into a `.data`
//! buffer, so the round-trip involves no file I/O, no `kernel32` file API and no
//! sandbox: nothing but Wine's decoder and the guest's memory. Handle `1` is the
//! cabinet (read/seek); the notification callback hands `FDI` handle `2` for the
//! file being extracted (write only). `pfnalloc` is a bump allocator over a
//! `.data` arena.
//!
//! # What it prints
//!
//! Every step reports on stdout so a run that stops short is diagnosable without
//! a debugger:
//!
//! ```text
//! FDICREATE=<16 hex>     the HFDI (zero ⇒ FDICreate failed)
//! SETID=<16 hex>         FDIIsCabinet's view of our CFHEADER.setID
//! CFILES=<16 hex>        …and its cFiles
//! FDICOPY=<16 hex>       the FDICopy BOOL
//! NAME=<archived name>   psz1 from the fdintCOPY_FILE notification
//! LEN=<16 hex>           bytes the write callback collected
//! DATA=<extracted bytes>
//! CAB OK | CAB FAIL
//! ```
//!
//! The exit code is [`CAB_OK_EXIT`] only when `FDICopy` returned TRUE **and** the
//! collected bytes and the archived name both match what the generator put in.
//! On the **emulated** path exemu has no cabinet.dll at all, so `FDICreate` is an
//! unimplemented thunk returning 0, the sample reports `CAB FAIL` and exits 1 —
//! that is the control the W6.5 gate uses.
//!
//! The layout code mirrors [`crate::sample`] and [`crate::shell_sample`]
//! (hand-assembled, RIP-relative displacements patched from known RVAs).

use crate::cab;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
/// `.rdata` starts two pages up, so the hand-assembled `.text` (callbacks +
/// entry, ~1.5 KiB) has room to grow without colliding with it.
const RDATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// Ceiling on the hand-assembled `.text`, i.e. the gap to `.rdata`.
const TEXT_MAX: usize = (RDATA_RVA - TEXT_RVA) as usize;

/// The exit code the sample returns when the extraction round-tripped.
pub const CAB_OK_EXIT: i32 = 66;

/// The cabinet name the sample hands `FDICopy` (and that `FDI` then passes to
/// the guest's `pfnopen`). No file of this name exists anywhere — the open
/// callback serves the archive out of `.rdata` regardless of the name.
pub const CAB_FILE_NAME: &str = "test.cab";

/// The line printed when every check held.
pub const OK_MESSAGE: &str = "CAB OK\n";
/// The line printed when any check failed.
pub const FAIL_MESSAGE: &str = "CAB FAIL\n";

/// Labels printed before each result, in emission order.
pub const LABEL_FDICREATE: &str = "FDICREATE=";
pub const LABEL_SETID: &str = "SETID=";
pub const LABEL_CFILES: &str = "CFILES=";
pub const LABEL_FDICOPY: &str = "FDICOPY=";
pub const LABEL_NAME: &str = "NAME=";
pub const LABEL_LEN: &str = "LEN=";
pub const LABEL_DATA: &str = "DATA=";

const LABELS: [&str; 7] = [
    LABEL_FDICREATE,
    LABEL_SETID,
    LABEL_CFILES,
    LABEL_FDICOPY,
    LABEL_NAME,
    LABEL_LEN,
    LABEL_DATA,
];

/// Capacity of the `.data` buffer the write callback collects into. One stored
/// `CFDATA` block is at most 0x8000 bytes, so this can never truncate a cabinet
/// [`crate::cab::build_cab`] produced.
const OUT_CAP: u32 = 0x8000;

/// Size of the bump-allocation arena `pfnalloc` hands out of. Wine's `FDI`
/// allocates its context plus one decompression state; 4 MiB is far more than
/// either needs and costs nothing on disk (`.data` is BSS).
const HEAP_CAP: u32 = 0x40_0000;

/// Build the CAB-extraction sample.
///
/// `name` is the archived name and `payload` the file contents; the cabinet is
/// generated with [`crate::cab::build_cab`] and embedded in the image's
/// `.rdata`, and the same two values are embedded again as the expected result
/// so the **guest itself** verifies the round-trip.
///
/// # Panics
///
/// If `payload` does not fit one `CFDATA` block (see
/// [`crate::cab::build_cab`]), or if the generated `.text` outgrows the gap to
/// `.rdata`.
pub fn build(name: &str, payload: &[u8]) -> Vec<u8> {
    let cab_bytes = cab::build_cab(name, payload);
    let (rdata, syms) = build_rdata(&cab_bytes, name, payload);
    let (text, entry_off) = build_text(&syms);
    assert!(
        text.len() <= TEXT_MAX,
        ".text ({} bytes) outgrew the {TEXT_MAX}-byte gap to .rdata",
        text.len()
    );

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rdata.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw; // `.data` is BSS — no bytes on disk

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
    let image_size = align_up_u32(syms.data_rva + syms.data_len, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32);
    put_u32(&mut f, opt + 8, rdata_raw as u32);
    put_u32(&mut f, opt + 16, TEXT_RVA + entry_off); // AddressOfEntryPoint
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
    put_u32(&mut f, dir(1), RDATA_RVA + syms.import_dir_off);
    put_u32(&mut f, dir(1) + 4, syms.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + syms.iat_off);
    put_u32(&mut f, dir(12) + 4, syms.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", rdata.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    // `.data` is BSS: virtual scratch only (the 4 MiB arena costs no file bytes).
    write_section(&mut f, sec + 80, b".data", syms.data_len, syms.data_rva, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rdata.len()].copy_from_slice(&rdata);
    f
}

// ==========================================================================
// Layout
// ==========================================================================

/// Every RVA the hand-assembled `.text` refers to.
struct Syms {
    import_dir_off: u32,
    import_dir_size: u32,
    iat_off: u32,
    iat_size: u32,

    // --- IAT slots -------------------------------------------------------
    iat_fdi_create: u32,
    iat_fdi_is_cabinet: u32,
    iat_fdi_copy: u32,
    iat_fdi_destroy: u32,
    iat_get_std_handle: u32,
    iat_write_file: u32,
    iat_exit_process: u32,

    // --- `.rdata` --------------------------------------------------------
    /// The generated cabinet, verbatim.
    cab_rva: u32,
    cab_len: u32,
    /// `"test.cab\0"` and the empty cab path, both handed to `FDICopy`.
    cabname_rva: u32,
    cabpath_rva: u32,
    /// The expected extraction result, for the guest's own comparison.
    payload_rva: u32,
    payload_len: u32,
    /// The expected archived name (no NUL; the length is known).
    aname_rva: u32,
    aname_len: u32,
    nl_rva: u32,
    label_rva: [u32; 7],
    ok_rva: u32,
    fail_rva: u32,

    // --- `.data` (BSS) ---------------------------------------------------
    data_rva: u32,
    data_len: u32,
    cab_pos_rva: u32,
    out_len_rva: u32,
    heap_ptr_rva: u32,
    name_len_rva: u32,
    written_rva: u32,
    fdici_rva: u32,
    hexbuf_rva: u32,
    namebuf_rva: u32,
    erf_rva: u32,
    out_buf_rva: u32,
    heap_arena_rva: u32,
    heap_end_rva: u32,
}

/// The imports, grouped by DLL and in IAT order.
fn import_plan() -> [(&'static str, &'static [&'static str]); 2] {
    [
        (
            "cabinet.dll",
            &["FDICreate", "FDIIsCabinet", "FDICopy", "FDIDestroy"],
        ),
        (
            "kernel32.dll",
            &["GetStdHandle", "WriteFile", "ExitProcess"],
        ),
    ]
}

fn build_rdata(cab_bytes: &[u8], name: &str, payload: &[u8]) -> (Vec<u8>, Syms) {
    let plan = import_plan();
    let n_dlls = plan.len();

    let import_dir_off = 0u32;
    let import_dir_size = ((n_dlls + 1) * 20) as u32;
    let thunk_qwords: usize = plan.iter().map(|(_, fs)| fs.len() + 1).sum();
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = (thunk_qwords * 8) as u32;
    let iat_off = ilt_off + ilt_size;
    let iat_size = ilt_size;

    let mut pos = iat_off + iat_size;

    // IMAGE_IMPORT_BY_NAME blobs (hint u16 + asciiz).
    let mut ibn_rva: Vec<u32> = Vec::new();
    for (_, funcs) in &plan {
        for f in *funcs {
            pos = align_up_u32(pos, 2);
            ibn_rva.push(RDATA_RVA + pos);
            pos += 2 + f.len() as u32 + 1;
        }
    }
    let mut dll_name_rva: Vec<u32> = Vec::new();
    for (dll, _) in &plan {
        dll_name_rva.push(RDATA_RVA + pos);
        pos += dll.len() as u32 + 1;
    }

    // Strings.
    let cabname_rva = RDATA_RVA + pos;
    pos += CAB_FILE_NAME.len() as u32 + 1;
    let cabpath_rva = RDATA_RVA + pos;
    pos += 1; // the empty string ""
    let nl_rva = RDATA_RVA + pos;
    pos += 1;
    let mut label_rva = [0u32; 7];
    for (i, l) in LABELS.iter().enumerate() {
        label_rva[i] = RDATA_RVA + pos;
        pos += l.len() as u32;
    }
    let ok_rva = RDATA_RVA + pos;
    pos += OK_MESSAGE.len() as u32;
    let fail_rva = RDATA_RVA + pos;
    pos += FAIL_MESSAGE.len() as u32;
    let aname_rva = RDATA_RVA + pos;
    pos += name.len() as u32;
    let payload_rva = RDATA_RVA + pos;
    pos += payload.len() as u32;

    // The archive itself, last so its offset is easy to eyeball in a hex dump.
    pos = align_up_u32(pos, 16);
    let cab_rva = RDATA_RVA + pos;
    pos += cab_bytes.len() as u32;

    // ---- emit --------------------------------------------------------------
    let mut b = vec![0u8; pos as usize];

    let mut iat_slots: Vec<u32> = Vec::new();
    let mut ilt_cursor = ilt_off;
    let mut iat_cursor = iat_off;
    let mut ibn_i = 0usize;
    for (d, (_dll, funcs)) in plan.iter().enumerate() {
        let desc = import_dir_off as usize + d * 20;
        put_u32(&mut b, desc, ilt_cursor + RDATA_RVA); // OriginalFirstThunk
        put_u32(&mut b, desc + 12, dll_name_rva[d]); // Name
        put_u32(&mut b, desc + 16, iat_cursor + RDATA_RVA); // FirstThunk
        for _ in *funcs {
            let rva = ibn_rva[ibn_i];
            put_u64(&mut b, ilt_cursor as usize, rva as u64);
            put_u64(&mut b, iat_cursor as usize, rva as u64);
            iat_slots.push(iat_cursor + RDATA_RVA);
            ilt_cursor += 8;
            iat_cursor += 8;
            ibn_i += 1;
        }
        ilt_cursor += 8; // null-terminate this DLL's ILT/IAT
        iat_cursor += 8;
    }

    ibn_i = 0;
    for (_, funcs) in &plan {
        for f in *funcs {
            let off = (ibn_rva[ibn_i] - RDATA_RVA) as usize;
            b[off + 2..off + 2 + f.len()].copy_from_slice(f.as_bytes());
            ibn_i += 1;
        }
    }
    for (d, (dll, _)) in plan.iter().enumerate() {
        let off = (dll_name_rva[d] - RDATA_RVA) as usize;
        b[off..off + dll.len()].copy_from_slice(dll.as_bytes());
    }

    let put = |b: &mut Vec<u8>, rva: u32, bytes: &[u8]| {
        let off = (rva - RDATA_RVA) as usize;
        b[off..off + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut b, cabname_rva, CAB_FILE_NAME.as_bytes());
    // cabpath stays the zero byte already there (the empty string).
    put(&mut b, nl_rva, b"\n");
    for (i, l) in LABELS.iter().enumerate() {
        put(&mut b, label_rva[i], l.as_bytes());
    }
    put(&mut b, ok_rva, OK_MESSAGE.as_bytes());
    put(&mut b, fail_rva, FAIL_MESSAGE.as_bytes());
    put(&mut b, aname_rva, name.as_bytes());
    put(&mut b, payload_rva, payload);
    put(&mut b, cab_rva, cab_bytes);

    // ---- `.data` (BSS) layout ---------------------------------------------
    let data_rva = align_up_u32(RDATA_RVA + pos, SECTION_ALIGN);
    let mut d = data_rva;
    let cell = |n: u32, dp: &mut u32| -> u32 {
        let r = *dp;
        *dp += n;
        r
    };
    let cab_pos_rva = cell(8, &mut d);
    let out_len_rva = cell(8, &mut d);
    let heap_ptr_rva = cell(8, &mut d);
    let name_len_rva = cell(8, &mut d);
    let written_rva = cell(8, &mut d);
    let fdici_rva = cell(32, &mut d); // FDICABINETINFO is 24 bytes
    let hexbuf_rva = cell(32, &mut d); // 16 digits + '\n'
    let namebuf_rva = cell(128, &mut d);
    let erf_rva = cell(16, &mut d); // ERF is 3 ints
    let out_buf_rva = cell(OUT_CAP, &mut d);
    d = align_up_u32(d, 16);
    let heap_arena_rva = cell(HEAP_CAP, &mut d);
    let heap_end_rva = d;
    let data_len = d - data_rva;

    let syms = Syms {
        import_dir_off,
        import_dir_size,
        iat_off,
        iat_size,
        iat_fdi_create: iat_slots[0],
        iat_fdi_is_cabinet: iat_slots[1],
        iat_fdi_copy: iat_slots[2],
        iat_fdi_destroy: iat_slots[3],
        iat_get_std_handle: iat_slots[4],
        iat_write_file: iat_slots[5],
        iat_exit_process: iat_slots[6],
        cab_rva,
        cab_len: cab_bytes.len() as u32,
        cabname_rva,
        cabpath_rva,
        payload_rva,
        payload_len: payload.len() as u32,
        aname_rva,
        aname_len: name.len() as u32,
        nl_rva,
        label_rva,
        ok_rva,
        fail_rva,
        data_rva,
        data_len,
        cab_pos_rva,
        out_len_rva,
        heap_ptr_rva,
        name_len_rva,
        written_rva,
        fdici_rva,
        hexbuf_rva,
        namebuf_rva,
        erf_rva,
        out_buf_rva,
        heap_arena_rva,
        heap_end_rva,
    };
    (b, syms)
}

// ==========================================================================
// Code generation
// ==========================================================================

/// `.text` offsets of the eight callbacks, recorded as they are emitted.
#[derive(Clone, Copy)]
struct Callbacks {
    alloc: u32,
    free: u32,
    open: u32,
    read: u32,
    write: u32,
    close: u32,
    seek: u32,
    notify: u32,
}

/// Emit `.text`: the eight `FDI` callbacks first (at known offsets), then the
/// entry point. Returns the code and the entry's offset within `.text`.
fn build_text(s: &Syms) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();

    let alloc = c.len() as u32;
    emit_alloc(&mut c, s);
    let free = c.len() as u32;
    c.push(0xC3); // free: nothing to do — the arena is never reclaimed
    let open = c.len() as u32;
    emit_open(&mut c, s);
    let read = c.len() as u32;
    emit_read(&mut c, s);
    let write = c.len() as u32;
    emit_write_cb(&mut c, s);
    let close = c.len() as u32;
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]); // close: xor eax, eax ; ret
    let seek = c.len() as u32;
    emit_seek(&mut c, s);
    let notify = c.len() as u32;
    emit_notify(&mut c, s);
    let cb = Callbacks { alloc, free, open, read, write, close, seek, notify };

    let entry_off = c.len() as u32;
    emit_entry(&mut c, s, &cb);
    (c, entry_off)
}

// ---- callbacks --------------------------------------------------------------
//
// Win64 ABI: args in rcx/rdx/r8/r9, result in rax. None of these calls anything,
// so no frame is set up; none touches a non-volatile register, so the entry
// point's cached stdout handle / counters survive the whole of `FDICopy`.

/// `void *pfnalloc(ULONG cb)` — bump-allocate from the `.data` arena.
fn emit_alloc(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x89, 0xC8]); // mov eax, ecx          (zero-extend cb)
    c.extend_from_slice(&[0x48, 0x83, 0xC0, 0x0F]); // add rax, 15
    c.extend_from_slice(&[0x48, 0x83, 0xE0, 0xF0]); // and rax, -16
    rip(c, &[0x48, 0x8B, 0x0D], s.heap_ptr_rva); // mov rcx, [rip+heap_ptr]
    c.extend_from_slice(&[0x48, 0x89, 0xCA]); // mov rdx, rcx
    c.extend_from_slice(&[0x48, 0x01, 0xC2]); // add rdx, rax
    rip(c, &[0x4C, 0x8D, 0x05], s.heap_end_rva); // lea r8, [rip+heap_end]
    c.extend_from_slice(&[0x4C, 0x39, 0xC2]); // cmp rdx, r8
    let ja_oom = jcc8(c, 0x77); // ja .oom
    rip(c, &[0x48, 0x89, 0x15], s.heap_ptr_rva); // mov [rip+heap_ptr], rdx
    c.extend_from_slice(&[0x48, 0x89, 0xC8]); // mov rax, rcx
    c.push(0xC3); // ret
    // .oom:
    patch8(c, ja_oom);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax, eax ; ret
}

/// `INT_PTR pfnopen(char *name, int oflag, int pmode)` — hand back handle 1 (the
/// embedded cabinet) and rewind. The name is ignored on purpose: the archive
/// lives in `.rdata`, not in any filesystem.
fn emit_open(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva); // mov [rip+cab_pos], rax
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    c.push(0xC3);
}

/// `UINT pfnread(INT_PTR hf, void *pv, UINT cb)` — serve the cabinet out of
/// `.rdata`, clamped at end-of-archive (a short read is how `FDI` sees EOF).
fn emit_read(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x48, 0x83, 0xF9, 0x01]); // cmp rcx, 1
    let jne_zero = jcc8(c, 0x75); // jne .zero
    c.extend_from_slice(&[0x45, 0x89, 0xC1]); // mov r9d, r8d     (requested)
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva); // mov rax, [rip+cab_pos]
    c.extend_from_slice(&[0x41, 0xBA]); // mov r10d, cab_len
    c.extend_from_slice(&s.cab_len.to_le_bytes());
    c.extend_from_slice(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
    let jae_zero = jcc8(c, 0x73); // jae .zero  (at or past EOF)
    c.extend_from_slice(&[0x49, 0x29, 0xC2]); // sub r10, rax     (remaining)
    c.extend_from_slice(&[0x4D, 0x39, 0xD1]); // cmp r9, r10
    let jbe_clamped = jcc8(c, 0x76); // jbe .clamped
    c.extend_from_slice(&[0x4D, 0x89, 0xD1]); // mov r9, r10
    patch8(c, jbe_clamped);
    rip(c, &[0x4C, 0x8D, 0x1D], s.cab_rva); // lea r11, [rip+cab]
    c.extend_from_slice(&[0x49, 0x01, 0xC3]); // add r11, rax
    emit_copy_loop(c, CopyDir::R11ToRdx);
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva); // mov rax, [rip+cab_pos]
    c.extend_from_slice(&[0x4C, 0x01, 0xC8]); // add rax, r9
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva); // mov [rip+cab_pos], rax
    c.extend_from_slice(&[0x4C, 0x89, 0xC8]); // mov rax, r9
    c.push(0xC3);
    // .zero:
    patch8(c, jne_zero);
    patch8(c, jae_zero);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax, eax ; ret
}

/// `UINT pfnwrite(INT_PTR hf, void *pv, UINT cb)` — append to the `.data`
/// collection buffer. Returns the number of bytes actually stored, so a
/// truncation surfaces to `FDI` as a write error rather than a silent pass.
fn emit_write_cb(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x45, 0x89, 0xC1]); // mov r9d, r8d
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva); // mov rax, [rip+out_len]
    c.extend_from_slice(&[0x41, 0xBA]); // mov r10d, OUT_CAP
    c.extend_from_slice(&OUT_CAP.to_le_bytes());
    c.extend_from_slice(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
    let jae_zero = jcc8(c, 0x73); // jae .zero (full)
    c.extend_from_slice(&[0x49, 0x29, 0xC2]); // sub r10, rax   (room)
    c.extend_from_slice(&[0x4D, 0x39, 0xD1]); // cmp r9, r10
    let jbe_clamped = jcc8(c, 0x76); // jbe .clamped
    c.extend_from_slice(&[0x4D, 0x89, 0xD1]); // mov r9, r10
    patch8(c, jbe_clamped);
    rip(c, &[0x4C, 0x8D, 0x1D], s.out_buf_rva); // lea r11, [rip+out_buf]
    c.extend_from_slice(&[0x49, 0x01, 0xC3]); // add r11, rax
    emit_copy_loop(c, CopyDir::RdxToR11);
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva); // mov rax, [rip+out_len]
    c.extend_from_slice(&[0x4C, 0x01, 0xC8]); // add rax, r9
    rip(c, &[0x48, 0x89, 0x05], s.out_len_rva); // mov [rip+out_len], rax
    c.extend_from_slice(&[0x4C, 0x89, 0xC8]); // mov rax, r9
    c.push(0xC3);
    // .zero:
    patch8(c, jae_zero);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax, eax ; ret
}

/// `long pfnseek(INT_PTR hf, long dist, int seektype)` — reposition the cabinet
/// cursor and return the new absolute offset.
fn emit_seek(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x48, 0x83, 0xF9, 0x01]); // cmp rcx, 1
    let jne_other = jcc8(c, 0x75); // jne .other
    c.extend_from_slice(&[0x48, 0x63, 0xD2]); // movsxd rdx, edx
    c.extend_from_slice(&[0x41, 0x83, 0xF8, 0x01]); // cmp r8d, 1 (SEEK_CUR)
    let je_cur = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0x83, 0xF8, 0x02]); // cmp r8d, 2 (SEEK_END)
    let je_end = jcc8(c, 0x74);
    c.extend_from_slice(&[0x48, 0x89, 0xD0]); // mov rax, rdx   (SEEK_SET)
    let jmp_store_a = jcc8(c, 0xEB);
    // .cur:
    patch8(c, je_cur);
    rip(c, &[0x48, 0x8B, 0x05], s.cab_pos_rva); // mov rax, [rip+cab_pos]
    c.extend_from_slice(&[0x48, 0x01, 0xD0]); // add rax, rdx
    let jmp_store_b = jcc8(c, 0xEB);
    // .end:
    patch8(c, je_end);
    c.push(0xB8); // mov eax, cab_len
    c.extend_from_slice(&s.cab_len.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x01, 0xD0]); // add rax, rdx
    // .store:
    patch8(c, jmp_store_a);
    patch8(c, jmp_store_b);
    rip(c, &[0x48, 0x89, 0x05], s.cab_pos_rva); // mov [rip+cab_pos], rax
    c.push(0xC3);
    // .other: the output "file" is append-only; report offset 0.
    patch8(c, jne_other);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]);
}

/// `INT_PTR pfnfdin(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin)`.
///
/// `fdintCOPY_FILE` (2) is the one that matters: it copies the archived name out
/// of `pfdin->psz1` (offset +8) and returns handle 2, which is what makes `FDI`
/// stream the file's bytes through `pfnwrite`. `fdintCLOSE_FILE_INFO` (3) must
/// return TRUE; every other notification is declined with 0.
fn emit_notify(c: &mut Vec<u8>, s: &Syms) {
    c.extend_from_slice(&[0x83, 0xF9, 0x02]); // cmp ecx, 2
    let je_copy = jcc8(c, 0x74);
    c.extend_from_slice(&[0x83, 0xF9, 0x03]); // cmp ecx, 3
    let je_close = jcc8(c, 0x74);
    c.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax, eax ; ret
    // .close:
    patch8(c, je_close);
    c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax, 1 ; ret
    // .copy:
    patch8(c, je_copy);
    c.extend_from_slice(&[0x48, 0x8B, 0x42, 0x08]); // mov rax, [rdx+8]   (psz1)
    rip(c, &[0x4C, 0x8D, 0x05], s.namebuf_rva); // lea r8, [rip+namebuf]
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d       (length)
    c.extend_from_slice(&[0x41, 0xBB, 0x40, 0x00, 0x00, 0x00]); // mov r11d, 64 (cap)
    let loop_top = c.len();
    c.extend_from_slice(&[0x8A, 0x10]); // mov dl, [rax]
    c.extend_from_slice(&[0x41, 0x88, 0x10]); // mov [r8], dl
    c.extend_from_slice(&[0x84, 0xD2]); // test dl, dl
    let je_done = jcc8(c, 0x74);
    c.extend_from_slice(&[0x48, 0xFF, 0xC0]); // inc rax
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]); // inc r8
    c.extend_from_slice(&[0x49, 0xFF, 0xC1]); // inc r9
    c.extend_from_slice(&[0x49, 0xFF, 0xCB]); // dec r11
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, loop_top);
    // .done:
    patch8(c, je_done);
    rip(c, &[0x4C, 0x89, 0x0D], s.name_len_rva); // mov [rip+name_len], r9
    c.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00]); // mov eax, 2 (our handle)
    c.push(0xC3);
}

/// Which way [`emit_copy_loop`] moves bytes; both forms copy `r9` bytes using
/// `r10` as the index and `al` as the shuttle.
enum CopyDir {
    /// `[rdx + i] <- [r11 + i]` — cabinet bytes into `FDI`'s buffer.
    R11ToRdx,
    /// `[r11 + i] <- [rdx + i]` — `FDI`'s bytes into the collection buffer.
    RdxToR11,
}

fn emit_copy_loop(c: &mut Vec<u8>, dir: CopyDir) {
    c.extend_from_slice(&[0x4D, 0x31, 0xD2]); // xor r10, r10
    let top = c.len();
    c.extend_from_slice(&[0x4D, 0x39, 0xCA]); // cmp r10, r9
    let jae_done = jcc8(c, 0x73);
    match dir {
        CopyDir::R11ToRdx => {
            c.extend_from_slice(&[0x43, 0x8A, 0x04, 0x13]); // mov al, [r11+r10]
            c.extend_from_slice(&[0x42, 0x88, 0x04, 0x12]); // mov [rdx+r10], al
        }
        CopyDir::RdxToR11 => {
            c.extend_from_slice(&[0x42, 0x8A, 0x04, 0x12]); // mov al, [rdx+r10]
            c.extend_from_slice(&[0x43, 0x88, 0x04, 0x13]); // mov [r11+r10], al
        }
    }
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]); // inc r10
    let jmp_top = jcc8(c, 0xEB);
    back8(c, jmp_top, top);
    patch8(c, jae_done);
}

// ---- the entry point --------------------------------------------------------

/// Emit the entry point.
///
/// Non-volatile register conventions (they survive every call into Wine's
/// cabinet.dll): `rsi` = cached stdout handle, `r12` = the `HFDI`, `r13d` = the
/// failure count, `r14` = `FDICopy`'s return, `rbx` = the hex printer's scratch.
fn emit_entry(c: &mut Vec<u8>, s: &Syms, cb: &Callbacks) {
    // sub rsp, 0x68 — shadow space plus the 5th..9th argument slots at
    // [rsp+0x20..0x48], leaving rsp 16-byte aligned at every call site.
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x68]);
    c.extend_from_slice(&[0x45, 0x31, 0xED]); // xor r13d, r13d

    // rsi = GetStdHandle(STD_OUTPUT_HANDLE)
    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(c, &[0xFF, 0x15], s.iat_get_std_handle);
    c.extend_from_slice(&[0x48, 0x89, 0xC6]); // mov rsi, rax

    // heap_ptr = &heap_arena
    rip(c, &[0x48, 0x8D, 0x05], s.heap_arena_rva); // lea rax, [rip+arena]
    rip(c, &[0x48, 0x89, 0x05], s.heap_ptr_rva); // mov [rip+heap_ptr], rax

    // --- FDICreate(alloc, free, open, read, write, close, seek, -1, &erf) ---
    rip(c, &[0x48, 0x8D, 0x0D], TEXT_RVA + cb.alloc); // lea rcx
    rip(c, &[0x48, 0x8D, 0x15], TEXT_RVA + cb.free); // lea rdx
    rip(c, &[0x4C, 0x8D, 0x05], TEXT_RVA + cb.open); // lea r8
    rip(c, &[0x4C, 0x8D, 0x0D], TEXT_RVA + cb.read); // lea r9
    stack_arg_lea(c, 0x20, TEXT_RVA + cb.write);
    stack_arg_lea(c, 0x28, TEXT_RVA + cb.close);
    stack_arg_lea(c, 0x30, TEXT_RVA + cb.seek);
    // cpuType = cpuUNKNOWN (-1)
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
    stack_arg_lea(c, 0x40, s.erf_rva);
    rip(c, &[0xFF, 0x15], s.iat_fdi_create);
    c.extend_from_slice(&[0x49, 0x89, 0xC4]); // mov r12, rax
    print_hex64(c, s, 0);

    // if (!hfdi) { failures++; goto report; }
    c.extend_from_slice(&[0x4D, 0x85, 0xE4]); // test r12, r12
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jnz .have_fdi
    let jnz_have = c.len() - 4;
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp .report
    let jmp_report = c.len() - 4;
    patch32(c, jnz_have);

    // --- FDIIsCabinet(hfdi, 1, &fdici) — does Wine parse our CFHEADER? ---
    c.extend_from_slice(&[0x4C, 0x89, 0xE1]); // mov rcx, r12
    c.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1
    rip(c, &[0x4C, 0x8D, 0x05], s.fdici_rva); // lea r8, [rip+fdici]
    rip(c, &[0xFF, 0x15], s.iat_fdi_is_cabinet);
    rip(c, &[0x0F, 0xB7, 0x05], s.fdici_rva + 8); // movzx eax, word [setID]
    print_hex64(c, s, 1);
    rip(c, &[0x0F, 0xB7, 0x05], s.fdici_rva + 6); // movzx eax, word [cFiles]
    print_hex64(c, s, 2);

    // --- FDICopy(hfdi, "test.cab", "", 0, notify, NULL, NULL) ---
    c.extend_from_slice(&[0x4C, 0x89, 0xE1]); // mov rcx, r12
    rip(c, &[0x48, 0x8D, 0x15], s.cabname_rva); // lea rdx, [rip+cabname]
    rip(c, &[0x4C, 0x8D, 0x05], s.cabpath_rva); // lea r8, [rip+cabpath]
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d  (flags)
    stack_arg_lea(c, 0x20, TEXT_RVA + cb.notify);
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]); // decrypt = NULL
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0, 0, 0, 0]); // pvUser = NULL
    rip(c, &[0xFF, 0x15], s.iat_fdi_copy);
    c.extend_from_slice(&[0x49, 0x89, 0xC6]); // mov r14, rax
    print_hex64(c, s, 3);

    // --- report what came back ------------------------------------------
    write_str(c, s, s.label_rva[4], Len::Imm(LABEL_NAME.len() as u32));
    write_str(c, s, s.namebuf_rva, Len::MemU32(s.name_len_rva));
    write_str(c, s, s.nl_rva, Len::Imm(1));
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva); // mov rax, [rip+out_len]
    print_hex64(c, s, 5);
    write_str(c, s, s.label_rva[6], Len::Imm(LABEL_DATA.len() as u32));
    write_str(c, s, s.out_buf_rva, Len::MemU32(s.out_len_rva));
    write_str(c, s, s.nl_rva, Len::Imm(1));

    // --- FDIDestroy(hfdi) -------------------------------------------------
    c.extend_from_slice(&[0x4C, 0x89, 0xE1]); // mov rcx, r12
    rip(c, &[0xFF, 0x15], s.iat_fdi_destroy);

    // --- the checks -------------------------------------------------------
    // FDICopy returned TRUE
    c.extend_from_slice(&[0x4D, 0x85, 0xF6]); // test r14, r14
    fail_if(c, 0x75); // jnz over the increment
    // out_len == payload_len
    rip(c, &[0x48, 0x8B, 0x05], s.out_len_rva); // mov rax, [rip+out_len]
    c.extend_from_slice(&[0x48, 0x3D]); // cmp rax, imm32
    c.extend_from_slice(&s.payload_len.to_le_bytes());
    fail_if(c, 0x74); // je over the increment
    // name_len == aname_len
    rip(c, &[0x48, 0x8B, 0x05], s.name_len_rva); // mov rax, [rip+name_len]
    c.extend_from_slice(&[0x48, 0x3D]);
    c.extend_from_slice(&s.aname_len.to_le_bytes());
    fail_if(c, 0x74);
    // the bytes themselves
    emit_memcmp(c, s.out_buf_rva, s.payload_rva, s.payload_len);
    emit_memcmp(c, s.namebuf_rva, s.aname_rva, s.aname_len);

    // --- .report ----------------------------------------------------------
    patch32(c, jmp_report);
    c.extend_from_slice(&[0x45, 0x85, 0xED]); // test r13d, r13d
    c.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jnz .fail
    let jnz_fail = c.len() - 4;
    write_str(c, s, s.ok_rva, Len::Imm(OK_MESSAGE.len() as u32));
    c.push(0xB9); // mov ecx, CAB_OK_EXIT
    c.extend_from_slice(&(CAB_OK_EXIT as u32).to_le_bytes());
    c.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp .exit
    let jmp_exit = c.len() - 4;
    // .fail:
    patch32(c, jnz_fail);
    write_str(c, s, s.fail_rva, Len::Imm(FAIL_MESSAGE.len() as u32));
    c.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx, 1
    // .exit:
    patch32(c, jmp_exit);
    rip(c, &[0xFF, 0x15], s.iat_exit_process);
    c.push(0xCC); // int3 (unreached)
}

/// `jcc` over `inc r13d`: emit the two-byte conditional that skips the failure
/// counter when the preceding comparison said "good".
fn fail_if(c: &mut Vec<u8>, cc: u8) {
    c.extend_from_slice(&[cc, 0x03]); // jcc +3
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
}

/// Compare `len` bytes at two RVAs, bumping the failure count on any difference.
/// Uses only `rax`/`rcx`/`r8`/`r9`, so the entry's live non-volatiles are safe.
fn emit_memcmp(c: &mut Vec<u8>, a_rva: u32, b_rva: u32, len: u32) {
    if len == 0 {
        return;
    }
    rip(c, &[0x4C, 0x8D, 0x05], a_rva); // lea r8, [rip+a]
    rip(c, &[0x4C, 0x8D, 0x0D], b_rva); // lea r9, [rip+b]
    c.push(0xB9); // mov ecx, len
    c.extend_from_slice(&len.to_le_bytes());
    let top = c.len();
    c.extend_from_slice(&[0x41, 0x8A, 0x00]); // mov al, [r8]
    c.extend_from_slice(&[0x41, 0x3A, 0x01]); // cmp al, [r9]
    let jne_bad = jcc8(c, 0x75);
    c.extend_from_slice(&[0x49, 0xFF, 0xC0]); // inc r8
    c.extend_from_slice(&[0x49, 0xFF, 0xC1]); // inc r9
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, top);
    let jmp_done = jcc8(c, 0xEB);
    // .bad:
    patch8(c, jne_bad);
    c.extend_from_slice(&[0x41, 0xFF, 0xC5]); // inc r13d
    patch8(c, jmp_done);
}

/// Where a `WriteFile` call gets its length.
enum Len {
    /// A compile-time constant.
    Imm(u32),
    /// A `u32` read out of `.data` at run time (`out_len`, `name_len`).
    MemU32(u32),
}

/// `WriteFile(stdout, buf, len, &written, NULL)`.
fn write_str(c: &mut Vec<u8>, s: &Syms, buf_rva: u32, len: Len) {
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x48, 0x8D, 0x15], buf_rva); // lea rdx, [rip+buf]
    match len {
        Len::Imm(n) => {
            c.extend_from_slice(&[0x41, 0xB8]); // mov r8d, n
            c.extend_from_slice(&n.to_le_bytes());
        }
        Len::MemU32(rva) => rip(c, &[0x44, 0x8B, 0x05], rva), // mov r8d, [rip+rva]
    }
    rip(c, &[0x4C, 0x8D, 0x0D], s.written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]); // mov [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], s.iat_write_file);
}

/// Print `LABELS[label]` then `rax` as 16 hex digits and a newline. `rax` is
/// clobbered; the value is parked in `rbx` (non-volatile) across the WriteFiles.
fn print_hex64(c: &mut Vec<u8>, s: &Syms, label: usize) {
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
    write_str(c, s, s.label_rva[label], Len::Imm(LABELS[label].len() as u32));
    rip(c, &[0x48, 0x8D, 0x3D], s.hexbuf_rva); // lea rdi, [rip+hexbuf]
    c.extend_from_slice(&[0x48, 0x89, 0xD8]); // mov rax, rbx
    c.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]); // mov ecx, 16
    let top = c.len();
    c.extend_from_slice(&[0x48, 0xC1, 0xC0, 0x04]); // rol rax, 4
    c.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
    c.extend_from_slice(&[0x83, 0xE2, 0x0F]); // and edx, 0xF
    c.extend_from_slice(&[0x80, 0xC2, 0x30]); // add dl, '0'
    c.extend_from_slice(&[0x80, 0xFA, 0x39]); // cmp dl, '9'
    c.extend_from_slice(&[0x76, 0x03]); // jbe +3
    c.extend_from_slice(&[0x80, 0xC2, 0x27]); // add dl, 'a'-'0'-10
    c.extend_from_slice(&[0x88, 0x17]); // mov [rdi], dl
    c.extend_from_slice(&[0x48, 0xFF, 0xC7]); // inc rdi
    c.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let jnz_top = jcc8(c, 0x75);
    back8(c, jnz_top, top);
    c.extend_from_slice(&[0xC6, 0x07, 0x0A]); // mov byte [rdi], '\n'
    write_str(c, s, s.hexbuf_rva, Len::Imm(17));
    c.extend_from_slice(&[0x48, 0x89, 0xD8]); // mov rax, rbx
}

/// `lea rax, [rip+target] ; mov [rsp+off], rax` — one outgoing stack argument.
fn stack_arg_lea(c: &mut Vec<u8>, off: u8, target_rva: u32) {
    rip(c, &[0x48, 0x8D, 0x05], target_rva);
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, off]);
}

// ---- encoding helpers -------------------------------------------------------

/// Emit an instruction ending in a RIP-relative `disp32`.
fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

/// Emit a short jump with a placeholder displacement; returns the index of the
/// displacement byte, for [`patch8`]/[`back8`].
fn jcc8(c: &mut Vec<u8>, opcode: u8) -> usize {
    c.extend_from_slice(&[opcode, 0x00]);
    c.len() - 1
}

/// Point a short jump emitted by [`jcc8`] at the current end of the buffer.
fn patch8(c: &mut [u8], site: usize) {
    let rel = c.len() as i64 - (site as i64 + 1);
    assert!((-128..=127).contains(&rel), "short jump out of range: {rel}");
    c[site] = rel as i8 as u8;
}

/// Point a short jump emitted by [`jcc8`] backwards at `target`.
fn back8(c: &mut [u8], site: usize, target: usize) {
    let rel = target as i64 - (site as i64 + 1);
    assert!((-128..=127).contains(&rel), "short back-jump out of range: {rel}");
    c[site] = rel as i8 as u8;
}

/// Point a near jump (`rel32` placeholder at `site`) at the current end.
fn patch32(c: &mut [u8], site: usize) {
    let rel = (c.len() as i64 - (site as i64 + 4)) as i32;
    c[site..site + 4].copy_from_slice(&rel.to_le_bytes());
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
    /// the four `FDI` entry points — the static imports are what force Wine's
    /// cabinet.dll to load, so the gate depends on this shape.
    #[test]
    fn cab_sample_is_a_pe_importing_the_fdi_entry_points() {
        let exe = build("hello.txt", b"exemu W6.5 payload");
        let image = exemu_loader::parse(&exe).expect("parses as PE32+");
        assert!(image.is_64bit);
        assert_eq!(image.subsystem, 3, "console subsystem");

        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        for sym in ["FDICreate", "FDIIsCabinet", "FDICopy", "FDIDestroy"] {
            assert!(has("cabinet.dll", sym), "imports cabinet.dll!{sym}");
        }
        assert!(has("kernel32.dll", "WriteFile"));
        assert!(has("kernel32.dll", "ExitProcess"));
    }

    /// The archive the guest serves through its read callback is the very one
    /// [`crate::cab::build_cab`] produced — embedded verbatim, so the test's
    /// expectation and the guest's input cannot drift apart.
    #[test]
    fn the_generated_cabinet_travels_inside_the_image() {
        let payload = b"exemu W6.5 cabinet payload";
        let exe = build("hello.txt", payload);
        let cab_bytes = cab::build_cab("hello.txt", payload);

        assert!(
            exe.windows(cab_bytes.len()).any(|w| w == cab_bytes),
            "the generated cabinet is embedded in .rdata"
        );
        // …and so is the expected result the guest compares against.
        assert!(exe.windows(payload.len()).any(|w| w == payload));
    }

    /// The entry point sits inside `.text`, past every callback: a regression
    /// that seated the entry on a callback would "run" and silently do nothing.
    #[test]
    fn the_entry_point_follows_the_callbacks_inside_text() {
        let payload = b"abc";
        let (_, syms) = build_rdata(&cab::build_cab("a.txt", payload), "a.txt", payload);
        let (text, entry_off) = build_text(&syms);

        // The eight callbacks are emitted before the entry, so the entry offset
        // must be past all of them — and inside the emitted code.
        assert!(entry_off > 0, "the callbacks come first");
        assert!((entry_off as usize) < text.len());
        assert!(text.len() <= TEXT_MAX, "the .text fits below .rdata");

        let exe = build("a.txt", payload);
        let image = exemu_loader::parse(&exe).expect("parses");
        assert_eq!(
            image.entry_va(),
            IMAGE_BASE + (TEXT_RVA + entry_off) as u64,
            "AddressOfEntryPoint names the entry, not a callback"
        );
    }

    /// `.text`, `.rdata` and the BSS arena occupy disjoint virtual ranges, and
    /// the arena is big enough to be worth calling an arena.
    #[test]
    fn the_sections_do_not_overlap() {
        let payload = b"x";
        let (rdata, syms) = build_rdata(&cab::build_cab("a", payload), "a", payload);
        assert!(RDATA_RVA + rdata.len() as u32 <= syms.data_rva, ".rdata ends below .data");
        assert_eq!(syms.data_rva % SECTION_ALIGN, 0, ".data is page-aligned");
        assert_eq!(syms.heap_end_rva - syms.heap_arena_rva, HEAP_CAP);
        assert!(syms.out_buf_rva + OUT_CAP <= syms.heap_arena_rva, "the buffers are disjoint");
    }
}
