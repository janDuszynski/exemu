//! Generates the **sockets** console PE — the roadmap W7.1 proof binary.
//!
//! The produced `.exe` statically imports `ws2_32.dll!WSAStartup` / `socket` /
//! `connect` / `send` / `recv` / `closesocket` / `WSACleanup`, so under the Wine
//! boot the loader must map, relocate, bind and `DllMain` **Wine's own
//! ws2_32.dll** before the entry point runs, and every socket call below is
//! Wine's guest code. exemu contributes only what Wine's ws2_32 asks the kernel
//! for: `NtOpenFile` on `\Device\Afd` and `NtDeviceIoControlFile` (see
//! `exemu_os::net`).
//!
//! What it does:
//!
//! 1. `WSAStartup(MAKEWORD(2,2), &wsadata)`;
//! 2. `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`;
//! 3. `connect` to `127.0.0.1:<port>` — the port is baked into `.rdata` by
//!    [`build`], because the gate binds an **ephemeral** loopback port and only
//!    knows which one after the fact;
//! 4. `send` the request, `recv` the reply;
//! 5. compare the reply, byte for byte, against the expected bytes also baked
//!    into `.rdata` — so the **guest itself** verifies the round trip;
//! 6. `closesocket`, `WSACleanup`, and exit with [`SOCKET_OK_EXIT`] when every
//!    check held.
//!
//! What it prints (so a run that stops short is diagnosable without a debugger):
//!
//! ```text
//! STARTUP=<16 hex>   WSAStartup's return (0 = success)
//! SOCKET=<16 hex>    the SOCKET (0 or ~0 ⇒ socket() failed)
//! CONNECT=<16 hex>   connect's return (0 = success)
//! SENT=<16 hex>      bytes send() reported
//! RECVD=<16 hex>     bytes recv() reported
//! DATA=<reply bytes>
//! SOCKET OK | SOCKET FAIL
//! ```
//!
//! On the **emulated** path exemu has no ws2_32 of any kind, so every import is
//! an unimplemented thunk returning 0: `socket()` hands back 0, which the sample
//! rejects as an invalid SOCKET, and `send`/`recv` report 0 bytes. It prints
//! `SOCKET FAIL` and exits non-zero — that is the control the W7.1 gate uses, and
//! it is what makes a pass on the Wine path attributable to Wine's ws2_32 plus
//! exemu's AFD backend and nothing else.
//!
//! The layout code mirrors [`crate::shell_sample`] and [`crate::cab_sample`]
//! (hand-assembled, RIP-relative displacements patched from known RVAs).

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
const OPT_HEADER_SIZE: usize = 112 + 16 * 8;

/// Ceiling on the hand-assembled `.text`, i.e. the gap to `.rdata`.
const TEXT_MAX: usize = (RDATA_RVA - TEXT_RVA) as usize;

/// The exit code the sample returns when the whole exchange round-tripped.
pub const SOCKET_OK_EXIT: i32 = 74;

/// The line printed when every check held.
pub const OK_MESSAGE: &str = "SOCKET OK\n";
/// The line printed when any check failed.
pub const FAIL_MESSAGE: &str = "SOCKET FAIL\n";

pub const LABEL_STARTUP: &str = "STARTUP=";
pub const LABEL_SOCKET: &str = "SOCKET=";
pub const LABEL_CONNECT: &str = "CONNECT=";
pub const LABEL_SENT: &str = "SENT=";
pub const LABEL_RECVD: &str = "RECVD=";
pub const LABEL_DATA: &str = "DATA=";

const LABELS: [&str; 5] = [LABEL_STARTUP, LABEL_SOCKET, LABEL_CONNECT, LABEL_SENT, LABEL_RECVD];

/// `MAKEWORD(2, 2)` — the Winsock version every modern program requests.
const WSA_VERSION: u32 = 0x0202;
/// Public winsock2.h.
const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const IPPROTO_TCP: u32 = 6;

/// Capacity of the receive buffer, and the clamp applied to `recv`'s return
/// before it is used as a length — `recv` reports `SOCKET_ERROR` (-1) on
/// failure, and an unclamped -1 would drive the print loop off the end of the
/// image.
const RECV_CAP: u32 = 512;
/// `WSADATA` is 408 bytes on x64; round up.
const WSADATA_LEN: u32 = 512;
/// The ASCII line buffer: the longest line is `"DATA="` + the reply.
const LINE_CAP: u32 = RECV_CAP + 64;

/// Build the socket sample.
///
/// `port` is the **host** TCP port on `127.0.0.1` the guest dials; the gate
/// binds an ephemeral listener first and passes the port it was given, which is
/// what keeps the test hermetic. `request` is what the guest sends and `reply`
/// what it must receive back — both are embedded, and the guest compares the
/// reply itself.
///
/// # Panics
///
/// If `reply` does not fit [`RECV_CAP`], or the generated `.text` outgrows the
/// gap to `.rdata`.
pub fn build(port: u16, request: &[u8], reply: &[u8]) -> Vec<u8> {
    assert!(reply.len() <= RECV_CAP as usize, "the reply must fit the receive buffer");
    let r = Rdata::build(port, request, reply);
    let (text, entry_off) = build_text(&r);
    assert!(
        text.len() <= TEXT_MAX,
        ".text ({} bytes) outgrew the {TEXT_MAX}-byte gap to .rdata",
        text.len()
    );

    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(r.bytes.len(), FILE_ALIGN as usize);
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
    let image_size = align_up_u32(r.data_rva + r.data_len, SECTION_ALIGN);
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
    put_u32(&mut f, dir(1), RDATA_RVA + r.import_dir_off);
    put_u32(&mut f, dir(1) + 4, r.import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + r.iat_off);
    put_u32(&mut f, dir(12) + 4, r.iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", r.bytes.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    write_section(&mut f, sec + 80, b".data", r.data_len, r.data_rva, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + r.bytes.len()].copy_from_slice(&r.bytes);
    f
}

/// The imports, grouped by DLL and in IAT order.
fn import_plan() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "ws2_32.dll",
            vec!["WSAStartup", "socket", "connect", "send", "recv", "closesocket", "WSACleanup"],
        ),
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

    /// The ready-made `sockaddr_in` for `127.0.0.1:<port>`.
    sockaddr_rva: u32,
    /// The bytes the guest sends, and their length.
    request_rva: u32,
    request_len: u32,
    /// The bytes it must receive, for the guest's own comparison.
    reply_rva: u32,
    reply_len: u32,
    /// `"<label>"` prefixes, in [`LABELS`] order, then `DATA=`.
    label_rva: [u32; 5],
    label_len: [u32; 5],
    data_label_rva: u32,
    data_label_len: u32,
    ok_rva: u32,
    fail_rva: u32,

    // --- `.data` (BSS) -----------------------------------------------------
    data_rva: u32,
    wsadata_rva: u32,
    recvbuf_rva: u32,
    line_rva: u32,
    written_rva: u32,
    data_len: u32,
}

impl Rdata {
    fn build(port: u16, request: &[u8], reply: &[u8]) -> Rdata {
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

        let mut ibn_rva: Vec<u32> = Vec::new();
        for (_, funcs) in &plan {
            for f in funcs {
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

        // The `sockaddr_in`, laid out here rather than assembled at runtime:
        // `{u16 sin_family; u16 sin_port (network order); u8 sin_addr[4]; u8 pad[8]}`.
        pos = align_up_u32(pos, 4);
        let sockaddr_rva = RDATA_RVA + pos;
        pos += 16;

        let mut label_rva = [0u32; 5];
        let mut label_len = [0u32; 5];
        for (i, l) in LABELS.iter().enumerate() {
            label_rva[i] = RDATA_RVA + pos;
            label_len[i] = l.len() as u32;
            pos += l.len() as u32;
        }
        let data_label_rva = RDATA_RVA + pos;
        let data_label_len = LABEL_DATA.len() as u32;
        pos += data_label_len;
        let ok_rva = RDATA_RVA + pos;
        pos += OK_MESSAGE.len() as u32;
        let fail_rva = RDATA_RVA + pos;
        pos += FAIL_MESSAGE.len() as u32;
        let request_rva = RDATA_RVA + pos;
        pos += request.len() as u32;
        let reply_rva = RDATA_RVA + pos;
        pos += reply.len() as u32;

        let mut b = vec![0u8; pos as usize];

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
            ilt_cursor += 8;
            iat_cursor += 8;
        }

        ibn_i = 0;
        for (_, funcs) in &plan {
            for f in funcs {
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
        // sockaddr_in { AF_INET, htons(port), 127.0.0.1, 0… }
        let mut sa = Vec::with_capacity(16);
        sa.extend_from_slice(&(AF_INET as u16).to_le_bytes());
        sa.extend_from_slice(&port.to_be_bytes()); // network order
        sa.extend_from_slice(&[127, 0, 0, 1]);
        sa.extend_from_slice(&[0u8; 8]);
        put(&mut b, sockaddr_rva, &sa);

        for (i, l) in LABELS.iter().enumerate() {
            put(&mut b, label_rva[i], l.as_bytes());
        }
        put(&mut b, data_label_rva, LABEL_DATA.as_bytes());
        put(&mut b, ok_rva, OK_MESSAGE.as_bytes());
        put(&mut b, fail_rva, FAIL_MESSAGE.as_bytes());
        put(&mut b, request_rva, request);
        put(&mut b, reply_rva, reply);

        // `.data` (BSS) layout.
        let data_rva = align_up_u32(RDATA_RVA + pos, SECTION_ALIGN);
        let mut d = data_rva;
        let mut cell = |n: u32| -> u32 {
            let r = d;
            d += n;
            r
        };
        let wsadata_rva = cell(WSADATA_LEN);
        let recvbuf_rva = cell(RECV_CAP + 16);
        let line_rva = cell(LINE_CAP);
        let written_rva = cell(16);
        let data_len = d - data_rva;

        Rdata {
            bytes: b,
            import_dir_off,
            import_dir_size,
            iat_off,
            iat_size,
            iat,
            sockaddr_rva,
            request_rva,
            request_len: request.len() as u32,
            reply_rva,
            reply_len: reply.len() as u32,
            label_rva,
            label_len,
            data_label_rva,
            data_label_len,
            ok_rva,
            fail_rva,
            data_rva,
            wsadata_rva,
            recvbuf_rva,
            line_rva,
            written_rva,
            data_len,
        }
    }

    fn slot(&self, name: &str) -> u32 {
        *self.iat.get(name).expect("import present")
    }
}

// ==========================================================================
// Code generation
// ==========================================================================
//
// Register usage across the calls into Wine (all Win64 non-volatile, so they
// survive ws2_32's own code):
//   rsi  cached stdout handle
//   rbx  the SOCKET
//   r12d failure count (the exit code's basis)
//   r13  the last call's return value
//   r15d the clamped received length
//
// [rsp+0x00..0x20] shadow space, [rsp+0x20] the outgoing 5th argument.
const FRAME: u8 = 0x48;
/// The frame the two leaf helpers set up for their own `WriteFile` call.
const HELPER_FRAME: u8 = 0x38;

/// Emit `.text`: the two output helpers at known offsets, then the entry point.
fn build_text(r: &Rdata) -> (Vec<u8>, u32) {
    let mut c: Vec<u8> = Vec::new();
    let report = c.len() as u32;
    emit_report(&mut c, r);
    let puts = c.len() as u32;
    emit_puts(&mut c, r);
    let entry_off = c.len() as u32;
    emit_entry(&mut c, r, report, puts);
    (c, entry_off)
}

/// `report(rcx = value, rdx = label, r8d = label length)` — print
/// `"<label><16 hex>\n"`. Touches only volatile registers plus the frame, so the
/// caller's cached handle, socket and counters survive.
fn emit_report(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, HELPER_FRAME]); // sub rsp, HELPER_FRAME
    c.extend_from_slice(&[0x49, 0x89, 0xCB]); // mov r11, rcx      (value)
    rip(c, &[0x4C, 0x8D, 0x15], r.line_rva); // lea r10, [rip+line]
    emit_copy_loop(c); // label → line

    c.extend_from_slice(&[0x41, 0xB9, 0x10, 0x00, 0x00, 0x00]); // mov r9d, 16
    let hex_top = c.len();
    c.extend_from_slice(&[0x4C, 0x89, 0xD8]); // mov rax, r11
    c.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x3C]); // shr rax, 60
    c.extend_from_slice(&[0x83, 0xE0, 0x0F]); // and eax, 0x0f
    c.extend_from_slice(&[0x3C, 0x0A]); // cmp al, 10
    let jb_digit = jcc8(c, 0x72); // jb .digit
    c.extend_from_slice(&[0x04, 0x57]); // add al, 'a'-10
    let jmp_put = jcc8(c, 0xEB);
    patch8(c, jb_digit);
    c.extend_from_slice(&[0x04, 0x30]); // add al, '0'
    patch8(c, jmp_put);
    c.extend_from_slice(&[0x41, 0x88, 0x02]); // mov [r10], al
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]); // inc r10
    c.extend_from_slice(&[0x49, 0xC1, 0xE3, 0x04]); // shl r11, 4
    c.extend_from_slice(&[0x41, 0xFF, 0xC9]); // dec r9d
    jmp_back(c, 0x75, hex_top); // jnz .hex

    emit_flush_line(c, r);
    c.extend_from_slice(&[0x48, 0x83, 0xC4, HELPER_FRAME]); // add rsp, HELPER_FRAME
    c.push(0xC3);
}

/// `puts(rdx = bytes, r8d = length)` — write them to stdout verbatim.
fn emit_puts(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, HELPER_FRAME]);
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi   (stdout)
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]); // mov qword [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
    c.extend_from_slice(&[0x48, 0x83, 0xC4, HELPER_FRAME]);
    c.push(0xC3);
}

/// Copy `r8d` bytes from `[rdx]` to `[r10]`, advancing both. The one loop shape
/// this file needs.
fn emit_copy_loop(c: &mut Vec<u8>) {
    let top = c.len();
    c.extend_from_slice(&[0x45, 0x85, 0xC0]); // test r8d, r8d
    let jz_done = jcc8(c, 0x74);
    c.extend_from_slice(&[0x8A, 0x02]); // mov al, [rdx]
    c.extend_from_slice(&[0x41, 0x88, 0x02]); // mov [r10], al
    c.extend_from_slice(&[0x48, 0xFF, 0xC2]); // inc rdx
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]); // inc r10
    c.extend_from_slice(&[0x41, 0xFF, 0xC8]); // dec r8d
    jmp_back(c, 0xEB, top);
    patch8(c, jz_done);
}

/// Terminate the line at `[r10]` with `'\n'` and `WriteFile` it. Assumes the
/// caller already set up [`HELPER_FRAME`].
fn emit_flush_line(c: &mut Vec<u8>, r: &Rdata) {
    c.extend_from_slice(&[0x41, 0xC6, 0x02, 0x0A]); // mov byte [r10], '\n'
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]); // inc r10
    rip(c, &[0x48, 0x8D, 0x15], r.line_rva); // lea rdx, [rip+line]
    c.extend_from_slice(&[0x4C, 0x89, 0xD0]); // mov rax, r10
    c.extend_from_slice(&[0x48, 0x29, 0xD0]); // sub rax, rdx
    c.extend_from_slice(&[0x41, 0x89, 0xC0]); // mov r8d, eax
    c.extend_from_slice(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
    rip(c, &[0x4C, 0x8D, 0x0D], r.written_rva); // lea r9, [rip+written]
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]); // mov qword [rsp+0x20], 0
    rip(c, &[0xFF, 0x15], r.slot("WriteFile"));
}

/// The entry point: the whole exchange, with a report after every step.
fn emit_entry(c: &mut Vec<u8>, r: &Rdata, report: u32, puts: u32) {
    c.extend_from_slice(&[0x48, 0x83, 0xEC, FRAME]); // sub rsp, FRAME
    c.extend_from_slice(&[0x45, 0x31, 0xE4]); // xor r12d, r12d   (failures)

    // rsi = GetStdHandle(STD_OUTPUT_HANDLE)
    c.push(0xB9);
    c.extend_from_slice(&(-11i32).to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("GetStdHandle"));
    c.extend_from_slice(&[0x48, 0x89, 0xC6]); // mov rsi, rax

    // --- WSAStartup(MAKEWORD(2,2), &wsadata) ---
    c.push(0xB9);
    c.extend_from_slice(&WSA_VERSION.to_le_bytes());
    rip(c, &[0x48, 0x8D, 0x15], r.wsadata_rva); // lea rdx, [rip+wsadata]
    rip(c, &[0xFF, 0x15], r.slot("WSAStartup"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax
    emit_report_call(c, r, report, 0, true);
    // A non-zero return is a failure.
    c.extend_from_slice(&[0x45, 0x85, 0xED]); // test r13d, r13d
    let ok = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]); // inc r12d
    patch8(c, ok);

    // --- socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) ---
    c.push(0xB9);
    c.extend_from_slice(&AF_INET.to_le_bytes());
    c.push(0xBA);
    c.extend_from_slice(&SOCK_STREAM.to_le_bytes());
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&IPPROTO_TCP.to_le_bytes());
    rip(c, &[0xFF, 0x15], r.slot("socket"));
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
    // report the SOCKET itself (all 64 bits).
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    emit_label_and_call(c, r, report, 1);
    // INVALID_SOCKET is ~0; a zero handle means nothing serviced the call at all
    // (the emulated path's unimplemented thunk) — both are failures.
    c.extend_from_slice(&[0x48, 0x83, 0xFB, 0xFF]); // cmp rbx, -1
    let not_invalid = jcc8(c, 0x75);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]); // inc r12d
    patch8(c, not_invalid);
    c.extend_from_slice(&[0x48, 0x85, 0xDB]); // test rbx, rbx
    let not_null = jcc8(c, 0x75);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]); // inc r12d
    patch8(c, not_null);

    // --- connect(s, &sockaddr, 16) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0x48, 0x8D, 0x15], r.sockaddr_rva); // lea rdx, [rip+sockaddr]
    c.extend_from_slice(&[0x41, 0xB8, 0x10, 0x00, 0x00, 0x00]); // mov r8d, 16
    rip(c, &[0xFF, 0x15], r.slot("connect"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax
    emit_report_call(c, r, report, 2, true);
    c.extend_from_slice(&[0x45, 0x85, 0xED]); // test r13d, r13d
    let ok = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    patch8(c, ok);

    // --- send(s, request, len, 0) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0x48, 0x8D, 0x15], r.request_rva); // lea rdx, [rip+request]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.request_len.to_le_bytes()); // mov r8d, len
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
    rip(c, &[0xFF, 0x15], r.slot("send"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax
    emit_report_call(c, r, report, 3, true);
    // Anything but the full length is a failure.
    c.extend_from_slice(&[0x41, 0x81, 0xFD]); // cmp r13d, imm32
    c.extend_from_slice(&r.request_len.to_le_bytes());
    let ok = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]);
    patch8(c, ok);

    // --- recv(s, recvbuf, RECV_CAP, 0) ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0x48, 0x8D, 0x15], r.recvbuf_rva); // lea rdx, [rip+recvbuf]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&RECV_CAP.to_le_bytes());
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
    rip(c, &[0xFF, 0x15], r.slot("recv"));
    c.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax
    emit_report_call(c, r, report, 4, true);

    // r15d = min(r13d, RECV_CAP) — `recv` returns -1 on failure, and an
    // unclamped length would walk the print loop off the end of the image.
    c.extend_from_slice(&[0x41, 0x81, 0xFD]); // cmp r13d, RECV_CAP
    c.extend_from_slice(&RECV_CAP.to_le_bytes());
    let in_range = jcc8(c, 0x76); // jbe
    c.extend_from_slice(&[0x45, 0x31, 0xED]); // xor r13d, r13d
    patch8(c, in_range);
    c.extend_from_slice(&[0x45, 0x89, 0xEF]); // mov r15d, r13d

    // --- the guest's own verification: length, then bytes ---
    c.extend_from_slice(&[0x41, 0x81, 0xFF]); // cmp r15d, reply_len
    c.extend_from_slice(&r.reply_len.to_le_bytes());
    let len_ok = jcc8(c, 0x74);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]); // inc r12d
    let skip_compare = jcc8(c, 0xEB);
    patch8(c, len_ok);
    rip(c, &[0x48, 0x8D, 0x0D], r.recvbuf_rva); // lea rcx, [rip+recvbuf]
    rip(c, &[0x48, 0x8D, 0x15], r.reply_rva); // lea rdx, [rip+reply]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.reply_len.to_le_bytes()); // mov r8d, reply_len
    let cmp_top = c.len();
    c.extend_from_slice(&[0x45, 0x85, 0xC0]); // test r8d, r8d
    let all_matched = jcc8(c, 0x74);
    c.extend_from_slice(&[0x8A, 0x01]); // mov al, [rcx]
    c.extend_from_slice(&[0x3A, 0x02]); // cmp al, [rdx]
    let differs = jcc8(c, 0x75);
    c.extend_from_slice(&[0x48, 0xFF, 0xC1]); // inc rcx
    c.extend_from_slice(&[0x48, 0xFF, 0xC2]); // inc rdx
    c.extend_from_slice(&[0x41, 0xFF, 0xC8]); // dec r8d
    jmp_back(c, 0xEB, cmp_top);
    patch8(c, differs);
    c.extend_from_slice(&[0x41, 0xFF, 0xC4]); // inc r12d
    patch8(c, all_matched);
    patch8(c, skip_compare);

    // --- print "DATA=<bytes>\n" ---
    rip(c, &[0x4C, 0x8D, 0x15], r.line_rva); // lea r10, [rip+line]
    rip(c, &[0x48, 0x8D, 0x15], r.data_label_rva); // lea rdx, [rip+"DATA="]
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.data_label_len.to_le_bytes());
    emit_copy_loop(c);
    rip(c, &[0x48, 0x8D, 0x15], r.recvbuf_rva); // lea rdx, [rip+recvbuf]
    c.extend_from_slice(&[0x45, 0x89, 0xF8]); // mov r8d, r15d
    emit_copy_loop(c);
    c.extend_from_slice(&[0x41, 0xC6, 0x02, 0x0A]); // mov byte [r10], '\n'
    c.extend_from_slice(&[0x49, 0xFF, 0xC2]); // inc r10
    rip(c, &[0x48, 0x8D, 0x15], r.line_rva); // lea rdx, [rip+line]
    c.extend_from_slice(&[0x4C, 0x89, 0xD0]); // mov rax, r10
    c.extend_from_slice(&[0x48, 0x29, 0xD0]); // sub rax, rdx
    c.extend_from_slice(&[0x41, 0x89, 0xC0]); // mov r8d, eax
    call_rel(c, puts);

    // --- closesocket(s) ; WSACleanup() ---
    c.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    rip(c, &[0xFF, 0x15], r.slot("closesocket"));
    rip(c, &[0xFF, 0x15], r.slot("WSACleanup"));

    // --- the verdict ---
    c.extend_from_slice(&[0x45, 0x85, 0xE4]); // test r12d, r12d
    let failed = jcc8(c, 0x75);
    rip(c, &[0x48, 0x8D, 0x15], r.ok_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(OK_MESSAGE.len() as u32).to_le_bytes());
    call_rel(c, puts);
    c.push(0xB9);
    c.extend_from_slice(&SOCKET_OK_EXIT.to_le_bytes()); // mov ecx, SOCKET_OK_EXIT
    let exit = jcc8(c, 0xEB);
    patch8(c, failed);
    rip(c, &[0x48, 0x8D, 0x15], r.fail_rva);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&(FAIL_MESSAGE.len() as u32).to_le_bytes());
    call_rel(c, puts);
    c.extend_from_slice(&[0x44, 0x89, 0xE1]); // mov ecx, r12d  (the failure count)
    patch8(c, exit);
    rip(c, &[0xFF, 0x15], r.slot("ExitProcess"));
    c.push(0xCC); // int3 (unreached)
}

/// `mov ecx, r13d` (zero-extended) then `report(value, label[i])`.
fn emit_report_call(c: &mut Vec<u8>, r: &Rdata, report: u32, i: usize, from_r13: bool) {
    if from_r13 {
        c.extend_from_slice(&[0x44, 0x89, 0xE9]); // mov ecx, r13d
    }
    emit_label_and_call(c, r, report, i);
}

/// Load `label[i]` into `rdx`/`r8d` and call `report`. `rcx` is already set.
fn emit_label_and_call(c: &mut Vec<u8>, r: &Rdata, report: u32, i: usize) {
    rip(c, &[0x48, 0x8D, 0x15], r.label_rva[i]);
    c.extend_from_slice(&[0x41, 0xB8]);
    c.extend_from_slice(&r.label_len[i].to_le_bytes());
    call_rel(c, report);
}

// ---- encoding helpers -------------------------------------------------------

/// Emit an instruction ending in a RIP-relative `disp32`.
fn rip(c: &mut Vec<u8>, prefix: &[u8], target_rva: u32) {
    c.extend_from_slice(prefix);
    let next_rva = TEXT_RVA as i64 + c.len() as i64 + 4;
    c.extend_from_slice(&((target_rva as i64 - next_rva) as i32).to_le_bytes());
}

/// `call rel32` to a `.text` offset.
fn call_rel(c: &mut Vec<u8>, target_off: u32) {
    c.push(0xE8);
    let next = c.len() as i64 + 4;
    c.extend_from_slice(&((target_off as i64 - next) as i32).to_le_bytes());
}

/// Emit a short jump with a placeholder displacement; returns the byte to patch.
fn jcc8(c: &mut Vec<u8>, op: u8) -> usize {
    c.push(op);
    c.push(0);
    c.len() - 1
}

/// Point a placeholder emitted by [`jcc8`] at the current position.
fn patch8(c: &mut [u8], at: usize) {
    let rel = c.len() as i64 - (at as i64 + 1);
    assert!((-128..=127).contains(&rel), "short jump out of range ({rel})");
    c[at] = rel as i8 as u8;
}

/// Emit a short jump backwards to an already-emitted position.
fn jmp_back(c: &mut Vec<u8>, op: u8, target: usize) {
    c.push(op);
    c.push(0);
    let at = c.len() - 1;
    let rel = target as i64 - c.len() as i64;
    assert!((-128..=127).contains(&rel), "short jump out of range ({rel})");
    c[at] = rel as i8 as u8;
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

    /// The generated image is a PE32+ console executable statically importing
    /// the ws2_32 entry points the W7.1 gate depends on — the static imports are
    /// what force Wine's ws2_32 to load before the entry point runs.
    #[test]
    fn socket_sample_is_a_pe_importing_ws2_32() {
        let exe = build(4242, b"ping", b"pong");
        let image = exemu_loader::parse(&exe).expect("parses as PE32+");
        assert!(image.is_64bit);
        assert_eq!(image.subsystem, 3, "console subsystem");

        let has = |dll: &str, sym: &str| {
            image.imports.iter().any(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == sym)
            })
        };
        for sym in ["WSAStartup", "socket", "connect", "send", "recv", "closesocket", "WSACleanup"] {
            assert!(has("ws2_32.dll", sym), "imports ws2_32!{sym}");
        }
        assert!(has("kernel32.dll", "WriteFile"));
        assert!(has("kernel32.dll", "ExitProcess"));
    }

    /// The dialled port is baked into a real `sockaddr_in` in `.rdata`: family
    /// `AF_INET`, the port in **network** order, and `127.0.0.1`. A byte-order
    /// slip here would connect somewhere else entirely, so it is pinned.
    #[test]
    fn the_embedded_sockaddr_is_loopback_on_the_requested_port() {
        let exe = build(0xBEEF, b"x", b"y");
        let want = [
            2, 0, // AF_INET, little-endian
            0xBE, 0xEF, // port, network order
            127, 0, 0, 1, // 127.0.0.1
            0, 0, 0, 0, 0, 0, 0, 0, // sin_zero
        ];
        assert!(
            exe.windows(want.len()).any(|w| w == want),
            "the sockaddr_in for 127.0.0.1:0xBEEF is in the image"
        );
    }

    /// Every label the gate greps for travels in `.rdata`, and the request and
    /// reply the guest compares against are embedded verbatim.
    #[test]
    fn the_reported_labels_and_payloads_are_embedded() {
        let request = b"the request bytes";
        let reply = b"the reply bytes";
        let exe = build(1, request, reply);
        for l in LABELS.iter().chain([&LABEL_DATA]) {
            assert!(exe.windows(l.len()).any(|w| w == l.as_bytes()), "{l} is in the image");
        }
        assert!(exe.windows(request.len()).any(|w| w == request));
        assert!(exe.windows(reply.len()).any(|w| w == reply));
        assert!(exe.windows(OK_MESSAGE.len()).any(|w| w == OK_MESSAGE.as_bytes()));
        assert!(exe.windows(FAIL_MESSAGE.len()).any(|w| w == FAIL_MESSAGE.as_bytes()));
    }
}
