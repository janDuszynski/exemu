use std::collections::BTreeMap;

use exemu_core::ImportSymbol;
use exemu_os::net;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

#[derive(Debug, Clone, Copy)]
struct CallSite {
    call_rva: u32,
    func_rva: u32,
    ioctl: Option<u32>,
    in_len: Option<u32>,
    out_len: Option<u32>,
}

fn stack_store(code: &[u8], i: usize) -> Option<(u8, u32)> {
    if i + 8 > code.len() || code[i] != 0xC7 || code[i + 1] != 0x44 || code[i + 2] != 0x24 {
        return None;
    }
    let imm = u32::from_le_bytes(code[i + 4..i + 8].try_into().unwrap());
    Some((code[i + 3], imm))
}

fn rip_call_target(code: &[u8], i: usize, text_rva: u32) -> Option<u32> {
    if i + 6 > code.len() || code[i] != 0xFF || code[i + 1] != 0x15 {
        return None;
    }
    let disp = i32::from_le_bytes(code[i + 2..i + 6].try_into().unwrap());
    let next = text_rva as i64 + i as i64 + 6;
    u32::try_from(next + disp as i64).ok()
}

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
                return None;
            }
            found = u32::try_from(target).ok();
            i += 5;
            continue;
        }
        i += 1;
    }
    found
}

fn contains_in(code: &[u8], text_rva: u32, begin: u32, end: u32, needle: &[u8]) -> bool {
    let lo = (begin - text_rva) as usize;
    let hi = ((end - text_rva) as usize).min(code.len());
    code[lo..hi].windows(needle.len()).any(|w| w == needle)
}

struct Afd {
    code: Vec<u8>,
    text_rva: u32,
    funcs: Vec<(u32, u32)>,
    exports: BTreeMap<String, u32>,
    sites: Vec<CallSite>,
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

    fn func_of(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{rva:#x} lies in a .pdata function"))
    }

    fn sites_in(&self, func_rva: u32) -> Vec<CallSite> {
        self.sites.iter().copied().filter(|s| s.func_rva == func_rva).collect()
    }

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

    assert_eq!(&stub[..4], &[0x4C, 0x8B, 0xD1, 0xB8], "not a syscall stub: {stub:02x?}");
    let index = u32::from_le_bytes(stub[4..8].try_into().unwrap());
    assert_eq!(
        index,
        net::SSDT_NT_DEVICE_IO_CONTROL_FILE,
        "the pinned ntdll's NtDeviceIoControlFile stub says index {index:#x}"
    );
}

#[test]
fn a_socket_is_an_nt_handle_opened_on_the_afd_device() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();
    let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join("ws2_32.dll")).unwrap();

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

    let access = [&[0xBAu8][..], &net::AFD_DESIRED_ACCESS.to_le_bytes()[..]].concat();
    assert!(
        contains_in(&afd.code, afd.text_rva, begin, end, &access),
        "WSASocketW asks NtOpenFile for DesiredAccess {:#x}",
        net::AFD_DESIRED_ACCESS
    );

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

#[test]
fn the_afd_ioctl_map_matches_what_ws2_32_issues() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();

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

#[test]
fn recovered_control_codes_use_both_afd_encodings_split_at_operation_200() {
    if skip() {
        return;
    }
    let afd = Afd::recover().unwrap();
    let mut checked = 0usize;
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
            let op = (code >> 2) & 0xFFF;
            assert!(op >= 200, "{code:#x} is CTL_CODE-encoded but op {op} < 200");
            assert_eq!(net::ctl_code(op, method), code, "at {:#x}", site.call_rva);
        } else {
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
    assert!(checked >= 15, "only {checked} recognised AFD call sites — the scan found too little");

    let mut by_code: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for s in &afd.sites {
        if let Some(c) = s.ioctl {
            by_code.entry(c).or_default().push(s.call_rva);
        }
    }
    eprintln!("recovered AFD control codes → call-site RVAs: {by_code:#x?}");
}

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
