//! W7.1 — **the `\Device\Afd` boundary, re-derived from the pinned binaries**.
//!
//! Before exemu implements a single socket it has to know, exactly, what Wine's
//! `ws2_32.dll` *asks the kernel for*. This test recovers that surface from the
//! bytes of `example_exe/wine-dlls/x86_64-windows/{ws2_32,ntdll}.dll` on every
//! run and asserts it against the constants in [`exemu_os::net`]. A guessed
//! IOCTL code, a wrong structure offset or a drifted SSDT index fails **here**,
//! loudly, instead of turning into a silent wrong answer three layers down —
//! which is the classic failure mode for a boundary nobody re-derived.
//!
//! What it establishes, all from the binary:
//!
//! 1. `NtDeviceIoControlFile`'s SSDT index, read from ntdll's own
//!    `mov r10,rcx; mov eax,N` stub (the method every other `Nt*` group here
//!    used).
//! 2. A `SOCKET` is an NT file handle: `WSASocketW` opens `\Device\Afd` through
//!    `NtOpenFile` with `DesiredAccess = 0xC0100000` and an `OBJECT_ATTRIBUTES`
//!    whose `UNICODE_STRING` is `{Length 0x16, MaximumLength 0x18}`.
//! 3. Every socket operation is one syscall — `NtDeviceIoControlFile` — with an
//!    AFD control code. The codes, their input/output buffer sizes, and which
//!    exported entry point issues each are all read back out of `.text`.
//! 4. AFD's control-code encoding shifts the device type by **12**, not the 16
//!    of `CTL_CODE`.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::BTreeMap;

use exemu_core::ImportSymbol;
use exemu_os::net;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

// ---------------------------------------------------------------------------
// Byte-level recovery helpers
// ---------------------------------------------------------------------------

/// One recovered `NtDeviceIoControlFile` call site.
#[derive(Debug, Clone, Copy)]
struct CallSite {
    /// RVA of the `call qword [rip+…]` itself.
    call_rva: u32,
    /// RVA of the enclosing `.pdata` function.
    func_rva: u32,
    /// The `IoControlCode` immediate (arg5, `[rsp+0x28]`).
    ioctl: Option<u32>,
    /// `InputBufferLength` (arg7, `[rsp+0x38]`).
    in_len: Option<u32>,
    /// `OutputBufferLength` (arg9, `[rsp+0x48]`).
    out_len: Option<u32>,
}

/// `mov dword ptr [rsp+disp8], imm32` — `C7 44 24 <disp8> <imm32>`. The three
/// stack slots that matter are the Win64 outgoing-argument slots for args 5, 7
/// and 9 of `NtDeviceIoControlFile`.
fn stack_store(code: &[u8], i: usize) -> Option<(u8, u32)> {
    if i + 8 > code.len() || code[i] != 0xC7 || code[i + 1] != 0x44 || code[i + 2] != 0x24 {
        return None;
    }
    let imm = u32::from_le_bytes(code[i + 4..i + 8].try_into().unwrap());
    Some((code[i + 3], imm))
}

/// `call qword ptr [rip+disp32]` — `FF 15 <disp32>`; returns the RVA the
/// displacement resolves to (the IAT slot).
fn rip_call_target(code: &[u8], i: usize, text_rva: u32) -> Option<u32> {
    if i + 6 > code.len() || code[i] != 0xFF || code[i + 1] != 0x15 {
        return None;
    }
    let disp = i32::from_le_bytes(code[i + 2..i + 6].try_into().unwrap());
    let next = text_rva as i64 + i as i64 + 6;
    u32::try_from(next + disp as i64).ok()
}

/// Walk one `.pdata` function's bytes forward, remembering the most recent
/// immediate stored into each outgoing-argument stack slot, and record every
/// call through `iat_rva`. This is the same "what was in the argument slot when
/// the call happened" reading a disassembler gives, done on raw bytes so the
/// test carries no decoder of its own.
fn scan_function(code: &[u8], text_rva: u32, func: (u32, u32), iat_rva: u32, out: &mut Vec<CallSite>) {
    let (begin, end) = func;
    let (Some(lo), Some(hi)) = (
        begin.checked_sub(text_rva).map(|o| o as usize),
        end.checked_sub(text_rva).map(|o| o as usize),
    ) else {
        return;
    };
    if lo >= code.len() {
        return;
    }
    let hi = hi.min(code.len());
    let mut slots: BTreeMap<u8, u32> = BTreeMap::new();
    let mut i = lo;
    while i < hi {
        if let Some((disp, imm)) = stack_store(code, i) {
            slots.insert(disp, imm);
            i += 8;
            continue;
        }
        if rip_call_target(code, i, text_rva) == Some(iat_rva) {
            out.push(CallSite {
                call_rva: text_rva + i as u32,
                func_rva: begin,
                ioctl: slots.get(&0x28).copied(),
                in_len: slots.get(&0x38).copied(),
                out_len: slots.get(&0x48).copied(),
            });
            i += 6;
            continue;
        }
        i += 1;
    }
}

/// The single direct `call rel32` (`E8`) inside `[begin, end)`, as an RVA.
/// `recv`/`send` are thin wrappers over one shared core, and this is how the
/// test follows them there without assuming the core's address.
fn only_direct_call(code: &[u8], text_rva: u32, begin: u32, end: u32) -> Option<u32> {
    let lo = (begin - text_rva) as usize;
    let hi = ((end - text_rva) as usize).min(code.len());
    let mut found = None;
    let mut i = lo;
    while i + 5 <= hi {
        if code[i] == 0xE8 {
            let rel = i32::from_le_bytes(code[i + 1..i + 5].try_into().unwrap());
            let target = text_rva as i64 + i as i64 + 5 + rel as i64;
            if found.is_some() {
                return None; // more than one: the caller's assumption is wrong
            }
            found = u32::try_from(target).ok();
            i += 5;
            continue;
        }
        i += 1;
    }
    found
}

/// Whether `needle` occurs within `[begin, end)` of `.text`.
fn contains_in(code: &[u8], text_rva: u32, begin: u32, end: u32, needle: &[u8]) -> bool {
    let lo = (begin - text_rva) as usize;
    let hi = ((end - text_rva) as usize).min(code.len());
    code[lo..hi].windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The recovery
// ---------------------------------------------------------------------------

/// Everything the scan recovers, in one place so each assertion below reads as
/// a statement about the pinned binary.
struct Afd {
    /// `.text` bytes and the RVA they start at.
    code: Vec<u8>,
    text_rva: u32,
    /// `.pdata` function ranges, sorted.
    funcs: Vec<(u32, u32)>,
    /// Exported name → RVA.
    exports: BTreeMap<String, u32>,
    /// Every `NtDeviceIoControlFile` call site.
    sites: Vec<CallSite>,
    /// IAT slot RVAs for the three `Nt*` imports the socket path uses.
    iat_open_file: u32,
}

impl Afd {
    fn recover() -> Option<Afd> {
        let path = std::path::Path::new(WINE_DLLS).join("ws2_32.dll");
        let bytes = std::fs::read(path).ok()?;
        let image = exemu_loader::parse(&bytes).expect("ws2_32.dll parses as PE32+");
        assert!(image.is_64bit, "the pinned ws2_32.dll must be PE32+");

        let text = image
            .sections
            .iter()
            .find(|s| s.name == ".text" && s.executable)
            .expect("ws2_32.dll has an executable .text");

        let iat = |sym: &str| -> u32 {
            image
                .imports
                .iter()
                .find(|i| {
                    i.dll.eq_ignore_ascii_case("ntdll.dll")
                        && matches!(&i.symbol, ImportSymbol::Named(n) if n == sym)
                })
                .unwrap_or_else(|| panic!("ws2_32.dll imports ntdll!{sym}"))
                .iat_rva
        };
        let iat_ioctl = iat("NtDeviceIoControlFile");
        let iat_open_file = iat("NtOpenFile");

        let mut funcs: Vec<(u32, u32)> = image
            .function_table
            .iter()
            .map(|f| (f.begin_rva, f.end_rva))
            .collect();
        funcs.sort_unstable();
        assert!(!funcs.is_empty(), "ws2_32.dll carries a .pdata function table");

        let mut sites = Vec::new();
        for f in &funcs {
            scan_function(&text.data, text.rva, *f, iat_ioctl, &mut sites);
        }

        let exports = image
            .exports
            .iter()
            .filter(|e| e.forwarder.is_none())
            .filter_map(|e| e.name.clone().map(|n| (n, e.rva)))
            .collect();

        Some(Afd {
            code: text.data.clone(),
            text_rva: text.rva,
            funcs,
            exports,
            sites,
            iat_open_file,
        })
    }

    fn export(&self, name: &str) -> u32 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("ws2_32.dll exports {name}"))
    }

    /// The `.pdata` range containing `rva`.
    fn func_of(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{rva:#x} lies in a .pdata function"))
    }

    /// The call sites inside the function that begins exactly at `func_rva`.
    fn sites_in(&self, func_rva: u32) -> Vec<CallSite> {
        self.sites.iter().copied().filter(|s| s.func_rva == func_rva).collect()
    }

    /// The one `NtDeviceIoControlFile` call the named export issues directly.
    fn site_of_export(&self, name: &str) -> CallSite {
        let rva = self.export(name);
        let sites = self.sites_in(rva);
        assert_eq!(
            sites.len(),
            1,
            "{name} should issue exactly one NtDeviceIoControlFile; got {sites:#x?}"
        );
        sites[0]
    }
}

fn skip() -> bool {
    if std::path::Path::new(WINE_DLLS).join("ws2_32.dll").exists() {
        return false;
    }
    eprintln!("SKIP: {WINE_DLLS}/ws2_32.dll not present (the Wine DLL set is git-ignored)");
    true
}

// ---------------------------------------------------------------------------
// 1. The syscall itself
// ---------------------------------------------------------------------------

/// `NtDeviceIoControlFile`'s SSDT index, read out of the pinned ntdll's own
/// stub. Every socket operation Wine performs arrives through this one index,
/// so a drift here silently routes the whole networking boundary to
/// `STATUS_NOT_IMPLEMENTED`.
#[test]
fn nt_device_io_control_file_ssdt_index_comes_from_the_pinned_ntdll() {
    if skip() {
        return;
    }
    let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join("ntdll.dll")).expect("read ntdll.dll");
    let image = exemu_loader::parse(&bytes).expect("ntdll.dll parses");
    let ex = image
        .exports
        .iter()
        .find(|e| e.name.as_deref() == Some("NtDeviceIoControlFile"))
        .expect("ntdll exports NtDeviceIoControlFile");
    let text = image
        .sections
        .iter()
        .find(|s| ex.rva >= s.rva && ex.rva < s.rva + s.virtual_size)
        .expect("the stub lies in a section");
    let off = (ex.rva - text.rva) as usize;
    let stub = &text.data[off..off + 8];

    // `4C 8B D1` = mov r10, rcx ; `B8 imm32` = mov eax, N.
    assert_eq!(&stub[..4], &[0x4C, 0x8B, 0xD1, 0xB8], "not a syscall stub: {stub:02x?}");
    let index = u32::from_le_bytes(stub[4..8].try_into().unwrap());
    assert_eq!(
        index,
        net::SSDT_NT_DEVICE_IO_CONTROL_FILE,
        "the pinned ntdll's NtDeviceIoControlFile stub says index {index:#x}"
    );
}

// ---------------------------------------------------------------------------
// 2. A SOCKET is an NT file handle on \Device\Afd
// ---------------------------------------------------------------------------

/// `WSASocketW` opens `\Device\Afd`: the device name travels as UTF-16 in
/// `.rdata`, described by a `UNICODE_STRING` whose `{Length, MaximumLength}`
/// pair is stored as one immediate, and `NtOpenFile` is asked for
/// `GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE`.
#[test]
fn a_socket_is_an_nt_handle_opened_on_the_afd_device() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();
    let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join("ws2_32.dll")).unwrap();

    // The device name, verbatim, as the UTF-16 the UNICODE_STRING points at.
    let utf16: Vec<u8> = net::AFD_DEVICE_NAME
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert!(
        bytes.windows(utf16.len()).any(|w| w == utf16),
        "L\"{}\" is in the image",
        net::AFD_DEVICE_NAME
    );

    let (begin, end) = afd.func_of(afd.export("WSASocketW"));

    // UNICODE_STRING { USHORT Length; USHORT MaximumLength; } stored as one
    // dword: Length = 2 * 11 = 0x16 bytes, MaximumLength = 0x18 (room for the
    // NUL). Both follow from the name, which is what makes this a check and not
    // a transcription.
    let len = (net::AFD_DEVICE_NAME.encode_utf16().count() * 2) as u16;
    assert_eq!(len, 0x16);
    let ustr = u32::from(len) | (u32::from(len + 2) << 16);
    let mut found_ustr = false;
    for disp in 0u8..=0xFF {
        let needle = [&[0xC7u8, 0x44, 0x24, disp][..], &ustr.to_le_bytes()[..]].concat();
        if contains_in(&afd.code, afd.text_rva, begin, end, &needle) {
            found_ustr = true;
            break;
        }
    }
    assert!(
        found_ustr,
        "WSASocketW should build a UNICODE_STRING{{{len:#x}, {:#x}}} for {}",
        len + 2,
        net::AFD_DEVICE_NAME
    );

    // mov edx, 0xC0100000 — NtOpenFile's DesiredAccess, in the argument
    // register, inside WSASocketW's own body.
    let access = [&[0xBAu8][..], &net::AFD_DESIRED_ACCESS.to_le_bytes()[..]].concat();
    assert!(
        contains_in(&afd.code, afd.text_rva, begin, end, &access),
        "WSASocketW asks NtOpenFile for DesiredAccess {:#x}",
        net::AFD_DESIRED_ACCESS
    );

    // …and it really is NtOpenFile that is called there.
    let mut calls_open = false;
    let mut i = (begin - afd.text_rva) as usize;
    let hi = ((end - afd.text_rva) as usize).min(afd.code.len());
    while i < hi {
        if rip_call_target(&afd.code, i, afd.text_rva) == Some(afd.iat_open_file) {
            calls_open = true;
            break;
        }
        i += 1;
    }
    assert!(calls_open, "WSASocketW calls ntdll!NtOpenFile");
}

// ---------------------------------------------------------------------------
// 3. The IOCTL map
// ---------------------------------------------------------------------------

/// Every socket operation is `NtDeviceIoControlFile` with an AFD control code.
/// Each row below is read out of the named export's own body: the immediate in
/// the `IoControlCode` argument slot at the call, plus the fixed-size input and
/// output lengths where the code uses them.
#[test]
fn the_afd_ioctl_map_matches_what_ws2_32_issues() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();

    // (export, expected ioctl, expected InputBufferLength, expected OutputBufferLength)
    let rows: &[(&str, u32, Option<u32>, Option<u32>)] = &[
        ("WSASocketW", net::IOCTL_AFD_WINE_CREATE, Some(net::CREATE_PARAMS_LEN), Some(0)),
        ("listen", net::IOCTL_AFD_START_LISTEN, Some(net::LISTEN_PARAMS_LEN), Some(0)),
        ("accept", net::IOCTL_AFD_WINE_ACCEPT, Some(0), Some(net::ACCEPT_OUT_LEN)),
        ("shutdown", net::IOCTL_AFD_WINE_SHUTDOWN, Some(net::SHUTDOWN_PARAMS_LEN), Some(0)),
        ("connect", net::IOCTL_AFD_WINE_CONNECT, None, Some(0)),
        ("bind", net::IOCTL_AFD_BIND, None, None),
        ("getsockname", net::IOCTL_AFD_GET_SOCK_NAME, Some(0), None),
        ("getpeername", net::IOCTL_AFD_WINE_GET_PEER_NAME, Some(0), None),
        ("select", net::IOCTL_AFD_SELECT, None, None),
        ("WSAPoll", net::IOCTL_AFD_SELECT, None, None),
        ("WSAEventSelect", net::IOCTL_AFD_EVENT_SELECT, Some(0x10), Some(0)),
        ("WSAEnumNetworkEvents", net::IOCTL_AFD_ENUM_NETWORK_EVENTS, Some(0), Some(0x38)),
        ("WSAAsyncSelect", net::IOCTL_AFD_WINE_ASYNC_SELECT, Some(0x10), Some(0)),
    ];

    for (name, ioctl, in_len, out_len) in rows {
        let site = afd.site_of_export(name);
        assert_eq!(
            site.ioctl,
            Some(*ioctl),
            "{name} at {:#x} issues {:#x?}, expected {ioctl:#x}",
            site.call_rva,
            site.ioctl
        );
        if let Some(want) = in_len {
            assert_eq!(site.in_len, Some(*want), "{name} InputBufferLength");
        }
        if let Some(want) = out_len {
            assert_eq!(site.out_len, Some(*want), "{name} OutputBufferLength");
        }
    }
}

/// `recv` and `send` are one-line wrappers over a shared core; following their
/// single direct call finds the request the whole receive/send family issues,
/// and its fixed 0x30 / 0x20-byte parameter block.
#[test]
fn the_send_and_receive_cores_carry_the_recovered_parameter_blocks() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();

    for (name, ioctl, params_len) in [
        ("recv", net::IOCTL_AFD_WINE_RECVMSG, net::RECVMSG_PARAMS_LEN),
        ("send", net::IOCTL_AFD_WINE_SENDMSG, net::SENDMSG_PARAMS_LEN),
    ] {
        let (begin, end) = afd.func_of(afd.export(name));
        let core = only_direct_call(&afd.code, afd.text_rva, begin, end)
            .unwrap_or_else(|| panic!("{name} should tail into exactly one shared core"));
        let sites = afd.sites_in(core);
        let hit = sites
            .iter()
            .find(|s| s.ioctl == Some(ioctl))
            .unwrap_or_else(|| panic!("{name}'s core {core:#x} should issue {ioctl:#x}; got {sites:#x?}"));
        assert_eq!(
            hit.in_len,
            Some(params_len),
            "{name}'s parameter block is {params_len:#x} bytes"
        );
    }
}

/// Wine's ws2_32 issues control codes in **two** encodings, and mixing them up
/// yields plausible-looking but wrong codes for every operation. The classic
/// AFD operations shift `FILE_DEVICE_NETWORK` by 12 (`0x0001_2xxx`); the
/// operations Wine adds for itself use the ordinary `CTL_CODE`'s 16
/// (`0x0012_0xxx`). Each recovered code must decode under exactly one of them,
/// and the split must fall on the operation number 200.
#[test]
fn recovered_control_codes_use_both_afd_encodings_split_at_operation_200() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();
    let mut checked = 0usize;
    // Only the codes this module claims: a byte scan can also pick up an
    // immediate that is not a control code at all in a call site whose code
    // came from a register, and those must not be asserted as facts.
    let known = [
        net::IOCTL_AFD_BIND,
        net::IOCTL_AFD_START_LISTEN,
        net::IOCTL_AFD_SELECT,
        net::IOCTL_AFD_GET_SOCK_NAME,
        net::IOCTL_AFD_EVENT_SELECT,
        net::IOCTL_AFD_ENUM_NETWORK_EVENTS,
        net::IOCTL_AFD_WINE_CREATE,
        net::IOCTL_AFD_WINE_ACCEPT,
        net::IOCTL_AFD_WINE_OP_202,
        net::IOCTL_AFD_WINE_CONNECT,
        net::IOCTL_AFD_WINE_SHUTDOWN,
        net::IOCTL_AFD_WINE_RECVMSG,
        net::IOCTL_AFD_WINE_SENDMSG,
        net::IOCTL_AFD_WINE_OP_207,
        net::IOCTL_AFD_WINE_OP_210,
        net::IOCTL_AFD_WINE_ASYNC_SELECT,
        net::IOCTL_AFD_WINE_GET_PEER_NAME,
        net::IOCTL_AFD_WINE_OP_217,
        net::IOCTL_AFD_WINE_GET_SOCKET_INFO,
    ];
    for site in &afd.sites {
        let Some(code) = site.ioctl else { continue };
        if !known.contains(&code) {
            continue;
        }
        checked += 1;
        let method = code & 3;
        assert!(
            method == net::METHOD_BUFFERED || method == net::METHOD_NEITHER,
            "{code:#x} uses transfer method {method}"
        );
        if code >> 16 == net::FILE_DEVICE_NETWORK {
            // Wine's own operations: plain CTL_CODE, FILE_ANY_ACCESS.
            let op = (code >> 2) & 0xFFF;
            assert!(op >= 200, "{code:#x} is CTL_CODE-encoded but op {op} < 200");
            assert_eq!(net::ctl_code(op, method), code, "at {:#x}", site.call_rva);
        } else {
            // The operations Windows' own AFD defines: the 12-bit device shift.
            assert_eq!(
                code >> 12,
                net::FILE_DEVICE_NETWORK,
                "{code:#x} at {:#x} decodes under neither AFD encoding",
                site.call_rva
            );
            let op = (code >> 2) & 0x3FF;
            assert!(op < 200, "{code:#x} is AFD-encoded but op {op} >= 200");
            assert_eq!(net::afd_control_code(op, method), code, "at {:#x}", site.call_rva);
        }
    }
    // The scan must actually have found the surface, not silently nothing.
    assert!(checked >= 15, "only {checked} recognised AFD call sites — the scan found too little");

    // The whole recovered set, for the record.
    let mut by_code: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for s in &afd.sites {
        if let Some(c) = s.ioctl {
            by_code.entry(c).or_default().push(s.call_rva);
        }
    }
    eprintln!("recovered AFD control codes → call-site RVAs: {by_code:#x?}");
}

/// The one operation exemu could most easily get wrong by assumption: the
/// accepted socket comes back as a **4-byte handle in the output buffer**, not
/// as a return value or through the `IO_STATUS_BLOCK`.
#[test]
fn accept_returns_the_new_socket_through_a_four_byte_output_buffer() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();
    let site = afd.site_of_export("accept");
    assert_eq!(site.ioctl, Some(net::IOCTL_AFD_WINE_ACCEPT));
    assert_eq!(site.in_len, Some(0), "accept sends no input");
    assert_eq!(site.out_len, Some(net::ACCEPT_OUT_LEN), "…and reads back 4 bytes");
}
