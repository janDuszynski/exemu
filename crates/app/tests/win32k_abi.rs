use std::collections::BTreeMap;

use exemu_core::ImportSymbol;
use exemu_os::win32k_abi as abi;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    ["win32u.dll", "user32.dll", "gdi32.dll"]
        .iter()
        .all(|d| std::path::Path::new(WINE_DLLS).join(d).exists())
}

struct Dll {
    name: &'static str,
    code: Vec<u8>,
    text_rva: u32,
    funcs: Vec<(u32, u32)>,
    exports: BTreeMap<String, u32>,
    symbols: BTreeMap<String, u32>,
    imports: BTreeMap<u32, String>,
}

impl Dll {
    fn load(name: &'static str) -> Dll {
        let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        let image = exemu_loader::parse(&bytes).unwrap_or_else(|e| panic!("{name} parses: {e}"));
        assert!(image.is_64bit, "the pinned {name} must be PE32+");
        let text = image
            .sections
            .iter()
            .find(|s| s.name == ".text" && s.executable)
            .unwrap_or_else(|| panic!("{name} has an executable .text"));
        let mut funcs: Vec<(u32, u32)> =
            image.function_table.iter().map(|f| (f.begin_rva, f.end_rva)).collect();
        funcs.sort_unstable();
        assert!(!funcs.is_empty(), "{name} carries a .pdata function table");
        Dll {
            name,
            code: text.data.clone(),
            text_rva: text.rva,
            funcs,
            symbols: coff_symbols(&bytes),
            exports: image
                .exports
                .iter()
                .filter(|e| e.forwarder.is_none())
                .filter_map(|e| e.name.clone().map(|n| (n, e.rva)))
                .collect(),
            imports: image
                .imports
                .iter()
                .filter_map(|i| match &i.symbol {
                    ImportSymbol::Named(n) => Some((i.iat_rva, format!("{}!{n}", i.dll))),
                    _ => None,
                })
                .collect(),
        }
    }

    fn export(&self, sym: &str) -> u32 {
        *self
            .exports
            .get(sym)
            .unwrap_or_else(|| panic!("{} exports {sym}", self.name))
    }

    fn code_rva(&self, sym: &str) -> u32 {
        self.exports
            .get(sym)
            .or_else(|| self.symbols.get(sym))
            .copied()
            .unwrap_or_else(|| panic!("{} has neither an export nor a symbol for {sym}", self.name))
    }

    fn iat(&self, sym: &str) -> u32 {
        *self
            .imports
            .iter()
            .find(|(_, n)| n.rsplit('!').next() == Some(sym))
            .unwrap_or_else(|| panic!("{} imports {sym}", self.name))
            .0
    }

    fn slice(&self, begin: u32, end: u32) -> &[u8] {
        let lo = begin.saturating_sub(self.text_rva) as usize;
        let hi = (end.saturating_sub(self.text_rva) as usize).min(self.code.len());
        if lo >= hi {
            return &[];
        }
        &self.code[lo..hi]
    }

    fn func_at(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{}: no .pdata entry covers {rva:#x}", self.name))
    }
}

fn mov_reg_imm32(code: &[u8], i: usize) -> Option<(u8, u32, usize)> {
    let (base, rex_b) = if code.get(i)? & 0xF8 == 0x40 {
        (i + 1, code[i] & 1)
    } else {
        (i, 0)
    };
    let op = *code.get(base)?;
    if (op == 0x31 || op == 0x33) && base + 2 <= code.len() {
        let modrm = code[base + 1];
        let (reg, rm) = ((modrm >> 3) & 7, modrm & 7);
        if modrm >> 6 == 3 && reg == rm {
            return Some((reg | (rex_b << 3), 0, base + 2 - i));
        }
    }
    if !(0xB8..=0xBF).contains(&op) || base + 5 > code.len() {
        return None;
    }
    let imm = u32::from_le_bytes(code[base + 1..base + 5].try_into().ok()?);
    Some(((op - 0xB8) | (rex_b << 3), imm, base + 5 - i))
}

fn mov_stack_imm32(code: &[u8], i: usize) -> Option<(u8, u32, usize)> {
    if i + 8 > code.len() || code[i] != 0xC7 || code[i + 1] != 0x44 || code[i + 2] != 0x24 {
        return None;
    }
    let disp = code[i + 3];
    let imm = u32::from_le_bytes(code[i + 4..i + 8].try_into().ok()?);
    Some((disp, imm, 8))
}

fn stack_imm_at_call(dll: &Dll, begin: u32, end: u32, iat_slot: u32, slot: u8) -> Option<u32> {
    let body = dll.slice(begin, end);
    let mut last: BTreeMap<u8, u32> = BTreeMap::new();
    let mut i = 0usize;
    while i < body.len() {
        let at = begin + i as u32;
        if let Some((disp, imm, len)) = mov_stack_imm32(body, i) {
            last.insert(disp, imm);
            i += len;
            continue;
        }
        if rip_indirect(body, i, dll.text_rva, at) == Some(iat_slot) {
            return last.get(&slot).copied();
        }
        i += 1;
    }
    None
}

fn stack_imms_at_calls(dll: &Dll, begin: u32, end: u32, iat_slot: u32, slot: u8) -> Vec<u32> {
    let body = dll.slice(begin, end);
    let mut last: BTreeMap<u8, u32> = BTreeMap::new();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let at = begin + i as u32;
        if let Some((disp, imm, len)) = mov_stack_imm32(body, i) {
            last.insert(disp, imm);
            i += len;
            continue;
        }
        if rip_indirect(body, i, dll.text_rva, at) == Some(iat_slot) {
            if let Some(v) = last.get(&slot) {
                out.push(*v);
            }
        }
        i += 1;
    }
    out
}

const MESSAGE_CALL_TYPE_SLOT: u8 = 0x28;

const MESSAGE_CALL_CALLERS: [&str; 5] =
    ["user32.dll", "imm32.dll", "wintab32.dll", "wow64win.dll", "explorer.exe"];

fn message_call_dlls_present() -> bool {
    MESSAGE_CALL_CALLERS.iter().all(|d| std::path::Path::new(WINE_DLLS).join(d).exists())
}

fn message_call_space() -> Vec<u64> {
    abi::MESSAGE_CALL_TYPES
        .iter()
        .map(|(_, _, t)| *t)
        .chain([abi::MESSAGE_CALL_DISPATCH, abi::MESSAGE_CALL_DRIVER_307])
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn direct_calls(dll: &Dll, begin: u32, end: u32) -> Vec<u32> {
    let body = dll.slice(begin, end);
    let mut out = Vec::new();
    for i in 0..body.len().saturating_sub(5) {
        if body[i] != 0xE8 {
            continue;
        }
        let rel = i32::from_le_bytes(body[i + 1..i + 5].try_into().unwrap()) as i64;
        let at = begin as i64 + i as i64 + 5 + rel;
        if let Ok(t) = u32::try_from(at) {
            if dll.funcs.binary_search_by_key(&t, |(b, _)| *b).is_ok() {
                out.push(t);
            }
        }
    }
    out
}

fn first_rip_indirect(dll: &Dll, rva: u32, len: u32) -> Option<u32> {
    let body = dll.slice(rva, rva + len);
    (0..body.len()).find_map(|i| rip_indirect(body, i, dll.text_rva, rva + i as u32))
}

fn coff_symbols(bytes: &[u8]) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let coff = lfanew + 4;
    let nsec = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let ptr_sym = u32::from_le_bytes(bytes[coff + 8..coff + 12].try_into().unwrap()) as usize;
    let n_sym = u32::from_le_bytes(bytes[coff + 12..coff + 16].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap()) as usize;
    if ptr_sym == 0 || n_sym == 0 {
        return out;
    }
    let sec_hdrs = coff + 20 + opt_size;
    let sec_rva: Vec<u32> = (0..nsec)
        .map(|i| {
            let o = sec_hdrs + 40 * i + 12;
            u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap())
        })
        .collect();
    let strtab = ptr_sym + n_sym * 18;
    let mut i = 0usize;
    while i < n_sym {
        let e = ptr_sym + i * 18;
        if e + 18 > bytes.len() {
            break;
        }
        let value = u32::from_le_bytes(bytes[e + 8..e + 12].try_into().unwrap());
        let secnum = i16::from_le_bytes(bytes[e + 12..e + 14].try_into().unwrap());
        let naux = bytes[e + 17] as usize;
        let name = if bytes[e..e + 4] == [0, 0, 0, 0] {
            let off = strtab + u32::from_le_bytes(bytes[e + 4..e + 8].try_into().unwrap()) as usize;
            let end = bytes[off..].iter().position(|b| *b == 0).map(|p| off + p).unwrap_or(off);
            String::from_utf8_lossy(&bytes[off..end]).into_owned()
        } else {
            let raw = &bytes[e..e + 8];
            let end = raw.iter().position(|b| *b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        if secnum >= 1 && (secnum as usize) <= nsec {
            out.entry(name).or_insert(sec_rva[secnum as usize - 1] + value);
        }
        i += 1 + naux;
    }
    out
}

fn rip_indirect(code: &[u8], i: usize, text_rva: u32, at: u32) -> Option<u32> {
    if i + 6 > code.len() || code[i] != 0xFF || (code[i + 1] != 0x15 && code[i + 1] != 0x25) {
        return None;
    }
    let _ = text_rva;
    let disp = i32::from_le_bytes(code[i + 2..i + 6].try_into().ok()?);
    u32::try_from(at as i64 + 6 + disp as i64).ok()
}

fn selector_at_call(dll: &Dll, export: &str, iat_slot: u32, reg: u8) -> Option<u32> {
    let rva = dll.code_rva(export);
    let (begin, end) = dll.func_at(rva);
    let body = dll.slice(begin, end);
    let mut last: BTreeMap<u8, u32> = BTreeMap::new();
    let mut i = 0usize;
    while i < body.len() {
        let at = begin + i as u32;
        if let Some((r, imm, len)) = mov_reg_imm32(body, i) {
            last.insert(r, imm);
            i += len;
            continue;
        }
        if rip_indirect(body, i, dll.text_rva, at) == Some(iat_slot) {
            return last.get(&reg).copied();
        }
        i += 1;
    }
    None
}

fn selectors_via_parked_rdi(dll: &Dll, sym: &str, iat_slot: u32) -> Vec<u32> {
    let (begin, end) = dll.func_at(dll.code_rva(sym));
    let body = dll.slice(begin, end);
    let mut last: BTreeMap<u8, u32> = BTreeMap::new();
    let mut parked = false;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < body.len() {
        let at = begin + i as u32;
        if body[i..].starts_with(&[0x48, 0x8B, 0x3D]) && i + 7 <= body.len() {
            let disp = i32::from_le_bytes(body[i + 3..i + 7].try_into().unwrap());
            parked = u32::try_from(at as i64 + 7 + disp as i64) == Ok(iat_slot);
            i += 7;
            continue;
        }
        if let Some((r, imm, len)) = mov_reg_imm32(body, i) {
            last.insert(r, imm);
            i += len;
            continue;
        }
        if parked && body[i] == 0xFF && body[i + 1] == 0xD7 {
            out.push(last.get(&8).copied().unwrap_or(u32::MAX));
            i += 2;
            continue;
        }
        i += 1;
    }
    out
}

fn contains(dll: &Dll, begin: u32, end: u32, needle: &[u8]) -> bool {
    dll.slice(begin, end).windows(needle.len()).any(|w| w == needle)
}

fn immediates(dll: &Dll, export: &str) -> Vec<u32> {
    let (begin, end) = dll.func_at(dll.export(export));
    let body = dll.slice(begin, end);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        if let Some((_, imm, len)) = mov_reg_imm32(body, i) {
            out.push(imm);
            i += len;
            continue;
        }
        i += 1;
    }
    out
}

#[test]
fn win32u_syscall_indices_match_the_pinned_stubs() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let win32u = Dll::load("win32u.dll");
    for (name, expected) in abi::SYSCALLS {
        let rva = win32u.export(name);
        let stub = win32u.slice(rva, rva + 24);
        let idx = stub
            .iter()
            .position(|b| *b == 0xB8)
            .map(|p| u32::from_le_bytes(stub[p + 1..p + 5].try_into().unwrap()))
            .unwrap_or_else(|| panic!("win32u!{name} is not a `mov eax, imm32` syscall stub"));
        assert_eq!(
            idx, expected,
            "win32u!{name} is index {idx:#x} in the pinned build, exemu registers {expected:#x}"
        );
        assert_ne!(idx & 0x1000, 0, "win32u!{name} ({idx:#x}) carries the win32k table bit");
    }
    eprintln!("win32u: {} indices re-derived by export name", abi::SYSCALLS.len());
}

#[test]
fn nt_user_call_selectors_match_the_pinned_user32_wrappers() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");

    const EDX: u8 = 2;
    const R8D: u8 = 8;

    let hwnd = user32.iat("NtUserCallHwnd");
    for (export, expected) in abi::CALL_HWND {
        let got = selector_at_call(&user32, export, hwnd, EDX)
            .unwrap_or_else(|| panic!("user32!{export} reaches NtUserCallHwnd with an immediate"));
        assert_eq!(
            got as u64, expected,
            "user32!{export} passes NtUserCallHwnd selector {got:#x}, exemu maps {expected:#x}"
        );
    }

    let hwnd_param = user32.iat("NtUserCallHwndParam");
    for (export, expected) in abi::CALL_HWND_PARAM {
        let got = selector_at_call(&user32, export, hwnd_param, R8D).unwrap_or_else(|| {
            panic!("user32!{export} reaches NtUserCallHwndParam with an immediate")
        });
        assert_eq!(
            got as u64, expected,
            "user32!{export} passes NtUserCallHwndParam selector {got:#x}, exemu maps {expected:#x}"
        );
    }

    let one_param = user32.iat("NtUserCallOneParam");
    for (export, expected) in abi::CALL_ONE_PARAM {
        let got = selector_at_call(&user32, export, one_param, EDX).unwrap_or_else(|| {
            panic!("user32!{export} reaches NtUserCallOneParam with an immediate")
        });
        assert_eq!(
            got as u64, expected,
            "user32!{export} passes NtUserCallOneParam selector {got:#x}, exemu maps {expected:#x}"
        );
    }

    for (label, set) in [
        ("NtUserCallHwnd", abi::CALL_HWND.iter().map(|(_, c)| *c).collect::<Vec<_>>()),
        ("NtUserCallHwndParam", abi::CALL_HWND_PARAM.iter().map(|(_, c)| *c).collect()),
        ("NtUserCallOneParam", abi::CALL_ONE_PARAM.iter().map(|(_, c)| *c).collect()),
    ] {
        let mut sorted = set.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), set.len(), "{label}: two operations share a selector");
    }
}

#[test]
fn get_dialog_proc_is_selector_zero_of_nt_user_call_two_param() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let two = user32.iat("NtUserCallTwoParam");
    let got = selectors_via_parked_rdi(&user32, "SetWindowLongPtrA", two);
    let want: Vec<u32> =
        abi::CALL_TWO_PARAM_VIA_SET_WINDOW_LONG_PTR_A.iter().map(|(_, c)| *c as u32).collect();
    assert_eq!(
        got, want,
        "user32!SetWindowLongPtrA's NtUserCallTwoParam selectors are {got:?}, exemu maps {want:?}"
    );
}

#[test]
fn get_window_long_selector_is_pinned_by_is_iconic() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let hwnd_param = user32.iat("NtUserCallHwndParam");
    let (begin, end) = user32.func_at(user32.export("IsIconic"));

    assert!(
        contains(&user32, begin, end, &[0x48, 0xC7, 0xC2, 0xF0, 0xFF, 0xFF, 0xFF]),
        "user32!IsIconic asks for GWL_STYLE (-16)"
    );
    let selector = selector_at_call(&user32, "IsIconic", hwnd_param, 8)
        .expect("user32!IsIconic reaches NtUserCallHwndParam with an immediate selector");
    assert_eq!(
        selector, 0x0a,
        "IsIconic reads GWL_STYLE through NtUserCallHwndParam selector {selector:#x}"
    );
    assert!(
        contains(&user32, begin, end, &[0xC1, 0xE8, 0x1D]),
        "user32!IsIconic extracts WS_MINIMIZE (bit 29) from the returned long"
    );
    let ptr_a = abi::CALL_HWND_PARAM.iter().find(|(n, _)| *n == "GetWindowLongPtrA").unwrap().1;
    let ptr_w = abi::CALL_HWND_PARAM.iter().find(|(n, _)| *n == "GetWindowLongPtrW").unwrap().1;
    assert_eq!((ptr_a, ptr_w), (0x0b, 0x0c), "the Ptr variants follow GetWindowLong");
}

#[test]
fn get_client_rect_param_is_a_rect_pointer_plus_dpi() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let (begin, end) = user32.func_at(user32.export("GetClientRect"));
    assert!(
        contains(&user32, begin, end, &[0x48, 0x89, 0x74, 0x24, 0x20]),
        "GetClientRect stores the caller's RECT* at [rsp+0x20] (offset 0 of the block)"
    );
    assert!(
        contains(&user32, begin, end, &[0x89, 0x44, 0x24, 0x28]),
        "GetClientRect stores the DPI context at [rsp+0x28] (offset 8 of the block)"
    );
    assert!(
        contains(&user32, begin, end, &[0x48, 0x8D, 0x54, 0x24, 0x20]),
        "GetClientRect passes `lea rdx, [rsp+0x20]` — the block, not the RECT"
    );
}

#[test]
fn window_from_point_and_capture_are_bare_kernel_calls() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");

    let (begin, end) = user32.func_at(user32.export("WindowFromPoint"));
    assert!(
        end - begin < 0x40,
        "user32!WindowFromPoint is a handful of instructions, not a tree walk ({} bytes)",
        end - begin
    );
    assert!(
        contains(&user32, begin, end, &[0x48, 0xC1, 0xE8, 0x20]),
        "WindowFromPoint unpacks the by-value POINT with `shr rax, 0x20`"
    );
    let target = first_rip_indirect(&user32, begin, end - begin)
        .expect("WindowFromPoint tail-jumps an import");
    assert_eq!(
        user32.imports.get(&target).map(String::as_str),
        Some("win32u.dll!NtUserWindowFromPoint"),
        "…and that import is NtUserWindowFromPoint"
    );
    assert!(
        contains(&user32, end - 7, end, &[0x48, 0xFF, 0x25]),
        "WindowFromPoint ends in the tail-jump — the whole hit test is the kernel's"
    );

    for (export, import) in [
        ("SetCapture", "win32u.dll!NtUserSetCapture"),
        ("ReleaseCapture", "win32u.dll!NtUserReleaseCapture"),
        ("SetFocus", "win32u.dll!NtUserSetFocus"),
    ] {
        let rva = user32.export(export);
        let target =
            first_rip_indirect(&user32, rva, 0x20).unwrap_or_else(|| panic!("{export} branches"));
        assert_eq!(
            user32.imports.get(&target).map(String::as_str),
            Some(import),
            "user32!{export} is a bare thunk to {import}"
        );
    }
}

#[test]
fn thread_state_indices_match_the_pinned_user32_wrappers() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let iat = user32.iat("NtUserGetThreadState");
    const ECX: u8 = 1;
    for (export, expected) in abi::THREAD_STATE {
        let got = selector_at_call(&user32, export, iat, ECX)
            .unwrap_or_else(|| panic!("user32!{export} reaches NtUserGetThreadState"));
        assert_eq!(
            got as u64, expected,
            "user32!{export} asks for thread-state index {got}, exemu maps {expected}"
        );
    }
}

#[test]
fn message_call_types_match_the_pinned_callers() {
    if !wine_dlls_present() || !message_call_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");

    for (dll, routine, expected) in abi::MESSAGE_CALL_TYPES {
        let d = Dll::load(dll);
        let iat = d.iat("NtUserMessageCall");
        let (begin, end) = d.func_at(d.code_rva(routine));
        let got = stack_imm_at_call(&d, begin, end, iat, MESSAGE_CALL_TYPE_SLOT)
            .unwrap_or_else(|| panic!("{dll}!{routine} reaches NtUserMessageCall with a type"));
        assert_eq!(
            got as u64, expected,
            "{dll}!{routine} passes NtUserMessageCall type {got:#x}, exemu maps {expected:#x}"
        );
    }

    let iat = user32.iat("NtUserMessageCall");
    let (db, de) = user32.func_at(user32.export("DispatchMessageW"));
    let dispatch_type = direct_calls(&user32, db, de)
        .into_iter()
        .filter_map(|t| {
            let (b, e) = user32.func_at(t);
            stack_imm_at_call(&user32, b, e, iat, MESSAGE_CALL_TYPE_SLOT)
        })
        .next()
        .expect("DispatchMessageW calls a helper that issues NtUserMessageCall");
    assert_eq!(
        dispatch_type as u64,
        abi::MESSAGE_CALL_DISPATCH,
        "DispatchMessageW's helper passes type {dispatch_type:#x}, exemu maps {:#x}",
        abi::MESSAGE_CALL_DISPATCH
    );

    for t in message_call_space() {
        let n = [
            abi::MESSAGE_CALL_SENDS.contains(&t),
            abi::MESSAGE_CALL_KERNEL_PROCS.contains(&t),
            abi::MESSAGE_CALL_NOT_A_MESSAGE.contains(&t),
            t == abi::MESSAGE_CALL_DISPATCH,
            t == abi::MESSAGE_CALL_CALL_WINDOW_PROC,
        ]
        .iter()
        .filter(|b| **b)
        .count();
        assert_eq!(n, 1, "NtUserMessageCall type {t:#x} has {n} dispositions, not one");
    }
}

#[test]
fn the_pinned_binaries_issue_no_message_call_type_exemu_does_not_know() {
    if !wine_dlls_present() || !message_call_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let known = message_call_space();
    let mut seen: Vec<(String, u32)> = Vec::new();
    for dll in MESSAGE_CALL_CALLERS {
        let d = Dll::load(dll);
        let iat = d.iat("NtUserMessageCall");
        for (begin, end) in d.funcs.clone() {
            for imm in stack_imms_at_calls(&d, begin, end, iat, MESSAGE_CALL_TYPE_SLOT) {
                seen.push((format!("{dll}+{begin:#x}"), imm));
            }
        }
    }
    assert!(
        seen.len() >= abi::MESSAGE_CALL_TYPES.len(),
        "the sweep found only {} call sites — it is not finding the stores",
        seen.len()
    );
    for (site, imm) in &seen {
        assert!(
            known.contains(&(*imm as u64)),
            "{site} issues NtUserMessageCall type {imm:#x}, which exemu does not name"
        );
    }
    let issued: std::collections::BTreeSet<u64> = seen.iter().map(|(_, i)| *i as u64).collect();
    for t in known {
        assert!(
            issued.contains(&t) || t == abi::MESSAGE_CALL_DISPATCH,
            "exemu names NtUserMessageCall type {t:#x}, which no pinned binary issues"
        );
    }
}

#[test]
fn def_window_proc_forwards_the_hit_test_and_trusts_call_hwnd_0x10() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let (begin, end) = user32.func_at(user32.code_rva("DefWindowProcW"));

    let hit = abi::WM_NCHITTEST;
    for cmp in [
        [0x81, 0xFE].as_slice(),
        [0x81, 0xFA].as_slice(),
    ] {
        let mut needle = cmp.to_vec();
        needle.extend_from_slice(&hit.to_le_bytes());
        assert!(
            !contains(&user32, begin, end, &needle),
            "user32!DefWindowProcW has a WM_NCHITTEST ({hit:#x}) arm after all"
        );
    }
    assert!(
        !user32.exports.keys().any(|k| k.contains("HandleNCHitTest")),
        "user32 exports a non-client hit-test helper — the default may not be the kernel's"
    );

    let iat = user32.iat("NtUserMessageCall");
    let ty = stack_imm_at_call(&user32, begin, end, iat, 0x28)
        .expect("DefWindowProcW reaches NtUserMessageCall");
    let expected =
        abi::MESSAGE_CALL_TYPES.iter().find(|(_, n, _)| *n == "DefWindowProcW").unwrap().2;
    assert_eq!(ty as u64, expected, "DefWindowProcW forwards with type {ty:#x}");

    let call_hwnd = user32.iat("NtUserCallHwnd");
    const EDX: u8 = 2;
    let helper = *direct_calls(&user32, begin, end).first().expect("DefWindowProcW calls a helper");
    let (hb, he) = user32.func_at(helper);
    let code = {
        let body = user32.slice(hb, he);
        let mut last: BTreeMap<u8, u32> = BTreeMap::new();
        let mut i = 0usize;
        let mut found = None;
        while i < body.len() {
            let at = hb + i as u32;
            if let Some((r, imm, len)) = mov_reg_imm32(body, i) {
                last.insert(r, imm);
                i += len;
                continue;
            }
            if rip_indirect(body, i, user32.text_rva, at) == Some(call_hwnd) {
                found = last.get(&EDX).copied();
                break;
            }
            i += 1;
        }
        found.expect("DefWindowProcW's first helper issues NtUserCallHwnd with an immediate")
    };
    let self_thread =
        abi::CALL_HWND.iter().find(|(n, _)| *n == "SetWindowTextW").expect("selector recorded").1;
    assert_eq!(
        code as u64, self_thread,
        "DefWindowProcW's helper asks NtUserCallHwnd code {code:#x}; exemu answers {self_thread:#x} \
         with the HWND"
    );
    assert!(
        contains(&user32, begin, end, &[0x48, 0x89, 0xC3]),
        "DefWindowProcW keeps that result as the window handle (`mov rbx, rax`)"
    );
}

#[test]
fn gdi_handle_type_lives_in_the_generation_word() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");
    let (begin, end) = gdi32.func_at(gdi32.export("SelectObject"));

    assert!(
        contains(&gdi32, begin, end, &[0x48, 0x8B, 0x81, 0xF8, 0x00, 0x00, 0x00]),
        "SelectObject reads the handle table from PEB+{:#x}",
        abi::GDI_PEB_TABLE_PTR_OFF
    );
    assert!(
        contains(&gdi32, begin, end, &[0x48, 0x8D, 0x14, 0x40])
            || contains(&gdi32, begin, end, &[0x48, 0x8D, 0x04, 0x40]),
        "SelectObject scales the slot index by 3 (× 8 = {} bytes per entry)",
        abi::GDI_ENTRY_SIZE
    );
    assert!(
        contains(&gdi32, begin, end, &[0x80, 0x78, 0x0E, 0x00]),
        "SelectObject tests the in-use byte at entry+{:#x}",
        abi::GDI_ENTRY_TYPE_OFF
    );
    assert!(
        contains(&gdi32, begin, end, &[0x66, 0x39, 0x50, 0x0C]),
        "SelectObject compares the generation word at entry+{:#x} with handle>>16",
        abi::GDI_ENTRY_GENERATION_OFF
    );
    assert!(
        contains(&gdi32, begin, end, &[0x0F, 0xB6, 0x40, 0x0C]),
        "SelectObject reads the object type from the LOW BYTE of entry+{:#x}",
        abi::GDI_ENTRY_GENERATION_OFF
    );
    assert!(
        contains(&gdi32, begin, end, &[0x83, 0xE0, 0x7F])
            && contains(&gdi32, begin, end, &[0xC1, 0xE0, 0x10]),
        "SelectObject masks that byte to 7 bits and shifts it to bits 16..22"
    );
    let expected_cmp = (abi::GDI_TYPE_BRUSH as u32) << 16;
    let mut cmp = [0u8; 5];
    cmp[0] = 0x3D;
    cmp[1..].copy_from_slice(&expected_cmp.to_le_bytes());
    assert!(
        contains(&gdi32, begin, end, &cmp),
        "SelectObject compares the type against {expected_cmp:#x} (exemu's brush type \
         {:#x} << 16) before calling NtGdiSelectBrush",
        abi::GDI_TYPE_BRUSH
    );
}

#[test]
fn stock_object_slots_are_fixed_and_an_empty_one_traps() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");
    let get_stock = gdi32.export("GetStockObject");
    let (begin, end) = gdi32.func_at(get_stock);

    let body = gdi32.slice(begin, end);
    let win32u_slots: Vec<u32> = gdi32
        .imports
        .iter()
        .filter(|(_, n)| n.to_ascii_lowercase().starts_with("win32u"))
        .map(|(r, _)| *r)
        .collect();
    let mut i = 0usize;
    while i + 6 <= body.len() {
        if let Some(slot) = rip_indirect(body, i, gdi32.text_rva, begin + i as u32) {
            assert!(
                !win32u_slots.contains(&slot),
                "GetStockObject issues a win32u syscall — the fixed-slot model is wrong"
            );
        }
        i += 1;
    }

    let base = u8::try_from(abi::STOCK_SLOT_BASE).expect("stock slot base is a byte");
    assert!(
        contains(&gdi32, begin, end, &[0x83, 0xC1, base]),
        "GetStockObject maps index -> index + {:#x}",
        abi::STOCK_SLOT_BASE
    );
    assert!(
        contains(&gdi32, begin, end, &[0x80, 0x7A, 0x0E, 0x00]),
        "GetStockObject tests the in-use byte at entry+{:#x}",
        abi::GDI_ENTRY_TYPE_OFF
    );

    let published: Vec<u64> = abi::stock_slots().iter().map(|(s, _)| *s).collect();
    let imms = immediates(&gdi32, "GetStockObject");
    let dpi_slots: Vec<u32> = imms
        .iter()
        .copied()
        .filter(|v| (abi::STOCK_SLOT_BASE as u32..=abi::STOCK_SLOT_LAST as u32).contains(v))
        .collect();
    assert!(
        dpi_slots.len() >= 6,
        "GetStockObject's DPI-variant font slots are literal immediates, found {dpi_slots:?}"
    );
    for s in &dpi_slots {
        assert!(
            published.contains(&(*s as u64)),
            "GetStockObject can return slot {s:#x}, which exemu does not publish"
        );
    }

    let mut sorted = published.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), published.len(), "two stock objects share a slot");
    for s in &published {
        assert!(
            (abi::STOCK_SLOT_BASE..=abi::STOCK_SLOT_LAST).contains(s),
            "stock slot {s:#x} is outside the recovered range"
        );
    }
    eprintln!(
        "GetStockObject: base {:#x}, {} slots published, DPI variants {dpi_slots:?}",
        abi::STOCK_SLOT_BASE,
        published.len()
    );
}

#[test]
fn dc_attr_offsets_match_the_pinned_gdi32_accessors() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");

    for (export, off) in abi::DC_ATTR {
        let (begin, end) = gdi32.func_at(gdi32.export(export));
        let off8 = u8::try_from(off).expect("DC_ATTR offsets fit a disp8");
        let found = (0u8..8).any(|reg| contains(&gdi32, begin, end, &[0x8B, 0x40 | (reg << 3), off8]));
        assert!(
            found,
            "gdi32!{export} does not read the DC object at +{off:#x} — exemu's DC_ATTR \
             layout has drifted from the pinned build"
        );
    }
    let (begin, end) = gdi32.func_at(gdi32.export("GetDCOrgEx"));
    let org_x = abi::DC_ATTR.iter().find(|(n, _)| *n == "GetDCOrgEx").unwrap().1;
    let org_y = u8::try_from(org_x + 4).unwrap();
    assert!(
        (0u8..8).any(|reg| contains(&gdi32, begin, end, &[0x8B, 0x40 | (reg << 3), org_y])),
        "GetDCOrgEx reads the origin's y at +{org_y:#x}, immediately after x"
    );
    let body = gdi32.slice(begin, end);
    let win32u_slots: Vec<u32> = gdi32
        .imports
        .iter()
        .filter(|(_, n)| n.to_ascii_lowercase().starts_with("win32u"))
        .map(|(r, _)| *r)
        .collect();
    for i in 0..body.len().saturating_sub(6) {
        if let Some(slot) = rip_indirect(body, i, gdi32.text_rva, begin + i as u32) {
            assert!(
                !win32u_slots.contains(&slot),
                "GetDCOrgEx issues a syscall — the origin is not purely a shared-object read"
            );
        }
    }
}

#[test]
fn dc_dword_selectors_match_the_pinned_gdi32_setters() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");
    let iat = gdi32.iat("NtGdiGetAndSetDCDword");
    const EDX: u8 = 2;
    for (export, expected) in abi::DC_DWORD {
        let got = selector_at_call(&gdi32, export, iat, EDX).unwrap_or_else(|| {
            panic!("gdi32!{export} reaches NtGdiGetAndSetDCDword with an immediate selector")
        });
        assert_eq!(
            got as u64, expected,
            "gdi32!{export} passes selector {got:#x}, exemu maps {expected:#x}"
        );
    }
}

#[test]
fn fill_rect_lowers_to_select_brush_plus_patblt() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let (begin, end) = user32.func_at(user32.export("FillRect"));

    assert!(
        contains(&user32, begin, end, &[0xC7, 0x44, 0x24, 0x28, 0x21, 0x00, 0xF0, 0x00]),
        "user32!FillRect issues PatBlt with PATCOPY (0x00f00021)"
    );
    let pat_blt = user32.iat("PatBlt");
    let body = user32.slice(begin, end);
    let calls_patblt = (0..body.len().saturating_sub(6))
        .any(|i| rip_indirect(body, i, user32.text_rva, begin + i as u32) == Some(pat_blt));
    assert!(calls_patblt, "user32!FillRect calls gdi32!PatBlt");
    let win32u = Dll::load("win32u.dll");
    assert!(
        !win32u.exports.keys().any(|k| k.contains("FillRect")),
        "win32u exports no FillRect: the SelectBrush+PatBlt lowering is the only path"
    );
}
