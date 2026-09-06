//! W4.8 — **the win32u / GDI boundary, re-derived from the pinned binaries.**
//!
//! Everything exemu's win32k layer knows about Wine's USER/GDI split is a number
//! it read out of a binary once: a syscall index, a fan-in call selector, a field
//! offset in the DC object gdi32 shares with the kernel, a fixed handle-table
//! slot a stock object must live in. None of it is documented anywhere. This test
//! recovers each of those from the bytes of
//! `example_exe/wine-dlls/x86_64-windows/{win32u,user32,gdi32}.dll` on **every
//! run** and asserts it against the constants in [`exemu_os::win32k_abi`] — the
//! same constants the handlers use, not a mirrored copy.
//!
//! A Wine bump that renumbers a syscall, a `NtUserCall*` selector or a DC_ATTR
//! field therefore fails **here**, by name, instead of turning into a control
//! that silently paints nothing. It is the `afd_abi.rs` treatment for the GUI
//! boundary.
//!
//! What it establishes, all from the binary:
//!
//! 1. Every win32u index exemu services is the `mov eax, imm32` immediate in
//!    that export's own stub.
//! 2. The `NtUserCall{Hwnd,HwndParam,OneParam}` **call-number enums** — user32's
//!    thin wrapper for each public API loads the selector as an immediate into
//!    the trailing argument register straight before the win32u thunk.
//! 3. `GetClientRect`'s parameter block is `{ RECT *rect; DWORD dpi_ctx; }`.
//! 4. A GDI handle is `(type << 16) | slot`, and gdi32 recovers the type from
//!    the **low byte of the handle-table entry's generation word** — the rule
//!    that makes brushes and pens work.
//! 5. `GetStockObject` reads fixed slots directly and **executes `ud2`** on an
//!    empty one, so those slots must be published.
//! 6. The DC_ATTR offsets exemu writes (origin) and reads (text colour).
//! 7. **Hit-testing, capture and focus belong to the kernel side.**
//!    `user32!WindowFromPoint` is four instructions ending in a tail-jump;
//!    `SetCapture`/`ReleaseCapture`/`SetFocus` are bare thunks; and
//!    `GetFocus`/`GetActiveWindow`/`GetCapture` are the three
//!    `NtUserGetThreadState` indices.
//! 8. **`NtUserMessageCall` is a family selected by its `type` argument** — the
//!    `mov dword ptr [rsp+0x28], imm32` each user32 wrapper issues, including
//!    the internal `dispatch_message` behind `DispatchMessageW`. That the slot
//!    is written as a *dword* is itself load-bearing: the upper half is stale.
//! 9. **`DefWindowProc` is that syscall and nothing else** — no `WM_NCHITTEST`
//!    arm anywhere in user32 — and the handle it forwards is whatever
//!    `NtUserCallHwnd` code 0x10 returned, which therefore has to be the HWND.
//!
//! Where a routine has no export of its own (`DefWindowProcW`'s export is a
//! forwarder into ntdll), it is reached through the **COFF symbol table** the
//! pinned DLLs ship.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::BTreeMap;

use exemu_core::ImportSymbol;
use exemu_os::win32k_abi as abi;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    ["win32u.dll", "user32.dll", "gdi32.dll"]
        .iter()
        .all(|d| std::path::Path::new(WINE_DLLS).join(d).exists())
}

// ---------------------------------------------------------------------------
// A mapped pinned DLL, with the pieces every recovery below needs.
// ---------------------------------------------------------------------------

struct Dll {
    name: &'static str,
    /// `.text` bytes and the RVA they start at.
    code: Vec<u8>,
    text_rva: u32,
    /// `.pdata` function ranges, sorted.
    funcs: Vec<(u32, u32)>,
    /// Exported name → RVA (forwarders excluded).
    exports: BTreeMap<String, u32>,
    /// COFF symbol name → RVA — the only route to a routine whose export is a
    /// forwarder (`DefWindowProcW`).
    symbols: BTreeMap<String, u32>,
    /// `dll!Symbol` → IAT slot RVA, for annotating indirect calls.
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

    /// The RVA of a routine's *code*: its export when it has one, otherwise its
    /// COFF symbol (a forwarded export like `DefWindowProcW` has no export RVA).
    fn code_rva(&self, sym: &str) -> u32 {
        self.exports
            .get(sym)
            .or_else(|| self.symbols.get(sym))
            .copied()
            .unwrap_or_else(|| panic!("{} has neither an export nor a symbol for {sym}", self.name))
    }

    /// The IAT slot RVA of an imported symbol, matched on the bare name.
    fn iat(&self, sym: &str) -> u32 {
        *self
            .imports
            .iter()
            .find(|(_, n)| n.rsplit('!').next() == Some(sym))
            .unwrap_or_else(|| panic!("{} imports {sym}", self.name))
            .0
    }

    /// Bytes of `[begin, end)`, clamped to `.text`.
    fn slice(&self, begin: u32, end: u32) -> &[u8] {
        let lo = begin.saturating_sub(self.text_rva) as usize;
        let hi = (end.saturating_sub(self.text_rva) as usize).min(self.code.len());
        if lo >= hi {
            return &[];
        }
        &self.code[lo..hi]
    }

    /// The `.pdata` range containing `rva`.
    fn func_at(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{}: no .pdata entry covers {rva:#x}", self.name))
    }
}

// ---------------------------------------------------------------------------
// Byte-level readers (no decoder — the same "what was in the register when the
// call happened" reading a disassembler gives, done on raw bytes).
// ---------------------------------------------------------------------------

/// `mov <reg32>, imm32` (the `B8+rd` short form) **or** `xor <reg32>, <same>` —
/// which is how a wrapper passing selector 0 spells it (`user32!GetFocus` is
/// `xor ecx, ecx`). Returns `(reg, value, length)` with `reg` in the 0..7
/// encoding; a REX.B prefix bumps it to 8..15.
fn mov_reg_imm32(code: &[u8], i: usize) -> Option<(u8, u32, usize)> {
    let (base, rex_b) = if code.get(i)? & 0xF8 == 0x40 {
        (i + 1, code[i] & 1)
    } else {
        (i, 0)
    };
    let op = *code.get(base)?;
    // `xor r32, r32` — 31 /r (or 33 /r) with mod=11 and reg == rm.
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

/// `mov dword ptr [rsp+disp8], imm32` — `C7 44 24 disp8 imm32`. The form every
/// user32 wrapper uses to fill `NtUserMessageCall`'s stack arguments, and the
/// reason those slots must be read as **dwords**: the upper half of the qword is
/// never written.
fn mov_stack_imm32(code: &[u8], i: usize) -> Option<(u8, u32, usize)> {
    if i + 8 > code.len() || code[i] != 0xC7 || code[i + 1] != 0x44 || code[i + 2] != 0x24 {
        return None;
    }
    let disp = code[i + 3];
    let imm = u32::from_le_bytes(code[i + 4..i + 8].try_into().ok()?);
    Some((disp, imm, 8))
}

/// The immediate a function stores at `[rsp+slot]` before its first call/jmp
/// through `iat_slot` — how `NtUserMessageCall`'s `type` argument is recovered.
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

/// Every immediate standing at `[rsp+slot]` at each call/jmp through
/// `iat_slot` in `[begin, end)` — [`stack_imm_at_call`] without the "first one
/// only", so a routine that issues two different `NtUserMessageCall` types
/// (`user32!bcast_childwindow`, `user32!post_dde_message`) reports both.
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

/// `NtUserMessageCall`'s 6th argument — the first stack slot past the shadow
/// space plus one (the `type`).
const MESSAGE_CALL_TYPE_SLOT: u8 = 0x28;

/// Every pinned PE that imports `NtUserMessageCall`. `wow64win.dll` is in the
/// list because its 32→64 thunk is the only evidence for type `0x307`.
const MESSAGE_CALL_CALLERS: [&str; 5] =
    ["user32.dll", "imm32.dll", "wintab32.dll", "wow64win.dll", "explorer.exe"];

fn message_call_dlls_present() -> bool {
    MESSAGE_CALL_CALLERS.iter().all(|d| std::path::Path::new(WINE_DLLS).join(d).exists())
}

/// Every `NtUserMessageCall` type exemu names, from the ABI table plus the two
/// members that table cannot key by caller.
fn message_call_space() -> Vec<u64> {
    abi::MESSAGE_CALL_TYPES
        .iter()
        .map(|(_, _, t)| *t)
        .chain([abi::MESSAGE_CALL_DISPATCH, abi::MESSAGE_CALL_DRIVER_307])
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Targets of the `call rel32`s (`E8`) inside `[begin, end)`, in order. A bare
/// byte scan finds `E8` bytes that are really immediates, so only targets that
/// land exactly on a `.pdata` function start are kept.
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

/// The first `jmp qword [rip+disp32]` / `call qword [rip+disp32]` target inside a
/// short export body (used for the bare-thunk wrappers, which carry no `.pdata`
/// entry of their own).
fn first_rip_indirect(dll: &Dll, rva: u32, len: u32) -> Option<u32> {
    let body = dll.slice(rva, rva + len);
    (0..body.len()).find_map(|i| rip_indirect(body, i, dll.text_rva, rva + i as u32))
}

/// The pinned DLLs ship a **COFF symbol table**, which is the only way to reach a
/// routine that is not exported under its own name. `user32!DefWindowProcW` is
/// exactly that case: the export is a *forwarder* to `NTDLL.NtdllDefWindowProc_W`
/// (which jumps back through the client-PFN slot), so the code has to be found by
/// symbol. Returns `name -> RVA` for every symbol that belongs to a section.
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

/// `call/jmp qword ptr [rip+disp32]` (`FF 15` / `FF 25`) → the IAT slot RVA.
fn rip_indirect(code: &[u8], i: usize, text_rva: u32, at: u32) -> Option<u32> {
    if i + 6 > code.len() || code[i] != 0xFF || (code[i + 1] != 0x15 && code[i + 1] != 0x25) {
        return None;
    }
    let _ = text_rva;
    let disp = i32::from_le_bytes(code[i + 2..i + 6].try_into().ok()?);
    u32::try_from(at as i64 + 6 + disp as i64).ok()
}

/// The selector immediate a `user32` wrapper hands one of the `NtUserCall*`
/// multiplexers: walk the exported function forward remembering the last
/// `mov <reg>, imm32` per register, and read `reg` at the first call/jmp through
/// `iat_slot`.
///
/// `reg` is the x86-64 register number of the multiplexer's trailing argument:
/// `ecx`(1) for `NtUserCallNoParam`, `edx`(2) for the one-argument families,
/// `r8d`(8) for the two-argument ones.
fn selector_at_call(dll: &Dll, export: &str, iat_slot: u32, reg: u8) -> Option<u32> {
    let rva = dll.export(export);
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

/// Whether `needle` occurs anywhere in `[begin, end)`.
fn contains(dll: &Dll, begin: u32, end: u32, needle: &[u8]) -> bool {
    dll.slice(begin, end).windows(needle.len()).any(|w| w == needle)
}

/// Every `mov <reg32>, imm32` immediate inside an exported function, in order.
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

// ---------------------------------------------------------------------------
// 1. win32u syscall indices
// ---------------------------------------------------------------------------

/// Every win32u index exemu services is the `mov eax, imm32` immediate in that
/// export's own stub (`mov r10,rcx; mov eax,IDX; test …; syscall`). Recovering
/// them *by export name* is what makes a Wine bump that renumbers the table an
/// immediate, named failure instead of a wrong-handler dispatch.
#[test]
fn win32u_syscall_indices_match_the_pinned_stubs() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let win32u = Dll::load("win32u.dll");
    for (name, expected) in abi::SYSCALLS {
        let rva = win32u.export(name);
        // The stub is 3 bytes of `mov r10,rcx` then `mov eax,imm32`; read the
        // first `B8` immediate in its opening bytes rather than assuming the
        // exact prologue.
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
        // Every win32u index carries the 0x1000 table-selector bit that routes
        // it to exemu's second SSDT.
        assert_ne!(idx & 0x1000, 0, "win32u!{name} ({idx:#x}) carries the win32k table bit");
    }
    eprintln!("win32u: {} indices re-derived by export name", abi::SYSCALLS.len());
}

// ---------------------------------------------------------------------------
// 2. The NtUserCall* fan-in enums
// ---------------------------------------------------------------------------

/// The call-number enums are not public anywhere. They are recovered from
/// user32's thin wrappers: each public API loads its selector as an immediate
/// into the multiplexer's trailing argument register right before the win32u
/// thunk, e.g. `user32!GetClientRect` does `mov r8d, 0xe; call NtUserCallHwndParam`.
#[test]
fn nt_user_call_selectors_match_the_pinned_user32_wrappers() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");

    // Register numbers of each multiplexer's trailing (selector) argument.
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

    // The four selectors are distinct *within* each multiplexer — the property
    // that makes "one index, many operations" decodable at all.
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

/// `GetWindowLong` and `GetWindowLongPtr{A,W}` are three *different* selectors of
/// the same multiplexer, and `IsIconic` is what pins the first one's meaning: it
/// asks for `GWL_STYLE` (`mov rdx, -16`) with selector `0xa` and then tests
/// `WS_MINIMIZE` in the answer, which is only sensible if `0xa` reads a window
/// long. exemu services all three the same way, so this asserts the shape rather
/// than trusting the name.
#[test]
fn get_window_long_selector_is_pinned_by_is_iconic() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let hwnd_param = user32.iat("NtUserCallHwndParam");
    let (begin, end) = user32.func_at(user32.export("IsIconic"));

    // `mov rdx, 0xfffffffffffffff0` — GWL_STYLE as a sign-extended imm32.
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
    // `shr eax, 0x1d; and eax, 1` — bit 29, i.e. WS_MINIMIZE (0x20000000). This
    // is what proves the selector returns the *style*, not something else.
    assert!(
        contains(&user32, begin, end, &[0xC1, 0xE8, 0x1D]),
        "user32!IsIconic extracts WS_MINIMIZE (bit 29) from the returned long"
    );
    // …and the three window-long selectors are consecutive and distinct.
    let ptr_a = abi::CALL_HWND_PARAM.iter().find(|(n, _)| *n == "GetWindowLongPtrA").unwrap().1;
    let ptr_w = abi::CALL_HWND_PARAM.iter().find(|(n, _)| *n == "GetWindowLongPtrW").unwrap().1;
    assert_eq!((ptr_a, ptr_w), (0x0b, 0x0c), "the Ptr variants follow GetWindowLong");
}

/// `GetClientRect`'s `param` is a pointer to `{ RECT *rect; DWORD dpi_ctx; }`,
/// not to the RECT itself — a distinction that silently writes a rect into the
/// wrong place if you get it backwards. user32 builds that block on its own
/// stack: the caller's `RECT*` (arrived in `rdx`, saved to `rsi`) is stored at
/// `[rsp+0x20]`, the DPI-awareness context at `[rsp+0x28]`, and `lea rdx,
/// [rsp+0x20]` is what the syscall receives.
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

// ---------------------------------------------------------------------------
// 2b. Input routing: who hit-tests, and the message-call family
// ---------------------------------------------------------------------------

/// **Hit-testing is the kernel side's job, and the binary is what says so.**
///
/// `user32!WindowFromPoint` is *four instructions*: unpack the by-value `POINT`
/// (x stays in the low half of `rcx`, y is shifted out into `edx`) and tail-jump
/// `NtUserWindowFromPoint`. There is no window-tree walk, no Z-order, no clip
/// arithmetic on the user side at all — so all of it has to live in exemu's
/// win32k. The same holds for the capture and the focus: `SetCapture`,
/// `ReleaseCapture` and `SetFocus` are bare thunks.
#[test]
fn window_from_point_and_capture_are_bare_kernel_calls() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");

    // `WindowFromPoint` reaches the syscall and nothing else.
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
    // …and it is the function's *last* instruction (`48 FF 25 disp32`, 7 bytes),
    // so nothing else runs: no helper, no tree walk, no clip arithmetic.
    assert!(
        contains(&user32, end - 7, end, &[0x48, 0xFF, 0x25]),
        "WindowFromPoint ends in the tail-jump — the whole hit test is the kernel's"
    );

    // The capture/focus setters are bare thunks: the first indirect branch in
    // the export's bytes is the win32u entry of the same name.
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

/// `GetFocus` / `GetActiveWindow` / `GetCapture` are one-line wrappers that load
/// index 0 / 1 / 2 and tail-jump `NtUserGetThreadState` — which is where those
/// three index values come from. (`GetFocus` spells its zero `xor ecx, ecx`.)
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

/// **`NtUserMessageCall` is a whole family behind one index**, and the `type`
/// argument in its 6th slot is what selects the member. Each caller stores that
/// type as a `mov dword ptr [rsp+0x28], imm32` right before the syscall —
/// including `DefWindowProcW`, which *is* nothing but this call.
///
/// The `dword` matters as much as the value: the upper half of the qword slot is
/// never written, so a handler that reads the argument 64 bits wide picks up the
/// previous frame's bytes.
///
/// The family is **not** all sends. `SPY_EnterMessage`/`SPY_ExitMessage` bracket
/// every message user32 delivers, `SPY_GetMsgName` is a string query, and the
/// IME / systray / tablet / DDE members are not message deliveries at all — so
/// each is pinned here by the routine that issues it, which is what lets
/// `nt_user_message_call` dispatch on an allow-list instead of guessing.
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

    // The dispatch type has no exported wrapper: `DispatchMessageW` tail-calls an
    // internal `dispatch_message`, and that is where 0x3001 lives. Follow the
    // call rather than trusting the number.
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

    // Each type gets exactly one disposition — the property that makes
    // dispatching on it sound. A member in two lists, or in none, is a bug in
    // exemu's table rather than in the binary.
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

/// **Nothing outside exemu's table reaches the syscall.** The per-routine pins
/// above prove each named type is right; this proves the *set* is complete, by
/// sweeping every `.pdata` function of every pinned PE that imports
/// `NtUserMessageCall` and collecting the immediate stored at the type slot
/// before each call site.
///
/// `wow64win!wow64_NtUserMessageCall` is swept for the same reason and is the
/// only evidence for one member: type `0x307` has no caller anywhere in the
/// pinned PE set, and would otherwise be invisible.
///
/// A Wine bump that adds a member fails here — which matters because an
/// unrecognised type is answered with a zero, not dispatched to a WndProc, so
/// without this test a new member would silently stop working instead of
/// silently recursing.
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
    // Every type exemu names, except the two the sweep cannot see, is actually
    // issued: `DISPATCH_MESSAGE`'s caller is reached above, and `0x307` has no
    // caller at all outside wow64win's thunk (which the sweep does cover).
    let issued: std::collections::BTreeSet<u64> = seen.iter().map(|(_, i)| *i as u64).collect();
    for t in known {
        assert!(
            issued.contains(&t) || t == abi::MESSAGE_CALL_DISPATCH,
            "exemu names NtUserMessageCall type {t:#x}, which no pinned binary issues"
        );
    }
}

/// **`DefWindowProc` is the kernel's, hit test included.**
///
/// The pinned `user32!DefWindowProcW` handles a handful of IME/syscommand
/// messages and forwards everything else to `NtUserMessageCall` — it never
/// compares the message against `WM_NCHITTEST`, and user32 exports no
/// `NC_HandleNCHitTest`-shaped helper it could delegate to. So the default hit
/// test has to be answered on the kernel side, which is what exemu's
/// `def_window_proc` does.
///
/// It also pins the trap that made this invisible: the handle
/// `DefWindowProcW` passes on is **whatever `NtUserCallHwnd` code 0x10 returned**
/// (`call WIN_IsCurrentProcess; mov rbx, rax`), so that code must answer the
/// HWND, not a boolean.
#[test]
fn def_window_proc_forwards_the_hit_test_and_trusts_call_hwnd_0x10() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let (begin, end) = user32.func_at(user32.code_rva("DefWindowProcW"));

    // No WM_NCHITTEST arm: the message id never appears as a comparison
    // immediate anywhere in the body.
    let hit = abi::WM_NCHITTEST;
    for cmp in [
        [0x81, 0xFE].as_slice(), // cmp esi, imm32
        [0x81, 0xFA].as_slice(), // cmp edx, imm32
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

    // It forwards through NtUserMessageCall with the DefWindowProc type.
    let iat = user32.iat("NtUserMessageCall");
    let ty = stack_imm_at_call(&user32, begin, end, iat, 0x28)
        .expect("DefWindowProcW reaches NtUserMessageCall");
    let expected =
        abi::MESSAGE_CALL_TYPES.iter().find(|(_, n, _)| *n == "DefWindowProcW").unwrap().2;
    assert_eq!(ty as u64, expected, "DefWindowProcW forwards with type {ty:#x}");

    // The handle it forwards is the result of `NtUserCallHwnd(hwnd, 0x10)`:
    // its first direct call is a helper that issues exactly that, and the
    // instruction that follows the call is `mov rbx, rax`.
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

// ---------------------------------------------------------------------------
// 3. The GDI handle encoding and the stock-object slots
// ---------------------------------------------------------------------------

/// **A GDI handle is `(type << 16) | slot`, and the type is the low byte of the
/// handle-table entry's generation word.**
///
/// This is the rule that unblocks brushes and pens: `gdi32!SelectObject` walks
/// `PEB[0xF8] + (handle & 0xFFFF) * 24`, checks the in-use byte, checks
/// `word[entry+0x0C] == handle >> 16`, then computes
/// `(byte[entry+0x0C] & 0x7f) << 16` and dispatches on it — `0x100000` to
/// `NtGdiSelectBrush`. A brush handle therefore *must* be `0x0010_0000 | slot`
/// with `0x0010` in the entry's generation word; anything else is rejected.
#[test]
fn gdi_handle_type_lives_in_the_generation_word() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");
    let (begin, end) = gdi32.func_at(gdi32.export("SelectObject"));

    // `mov rax, [rcx+0xf8]` — the handle table read out of the PEB.
    assert!(
        contains(&gdi32, begin, end, &[0x48, 0x8B, 0x81, 0xF8, 0x00, 0x00, 0x00]),
        "SelectObject reads the handle table from PEB+{:#x}",
        abi::GDI_PEB_TABLE_PTR_OFF
    );
    // `lea rdx,[rax+rax*2]` then `lea rax,[rax+rdx*8]` — index * 3 * 8 = *24.
    assert!(
        contains(&gdi32, begin, end, &[0x48, 0x8D, 0x14, 0x40])
            || contains(&gdi32, begin, end, &[0x48, 0x8D, 0x04, 0x40]),
        "SelectObject scales the slot index by 3 (× 8 = {} bytes per entry)",
        abi::GDI_ENTRY_SIZE
    );
    // `cmp byte ptr [rax+0xe], 0` — the in-use byte.
    assert!(
        contains(&gdi32, begin, end, &[0x80, 0x78, 0x0E, 0x00]),
        "SelectObject tests the in-use byte at entry+{:#x}",
        abi::GDI_ENTRY_TYPE_OFF
    );
    // `cmp word ptr [rax+0xc], dx` — generation == handle >> 16.
    assert!(
        contains(&gdi32, begin, end, &[0x66, 0x39, 0x50, 0x0C]),
        "SelectObject compares the generation word at entry+{:#x} with handle>>16",
        abi::GDI_ENTRY_GENERATION_OFF
    );
    // `movzx eax, byte [rax+0xc]; and eax,0x7f; shl eax,0x10` — the type.
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
    // …and dispatches `brush_type << 16` to NtGdiSelectBrush.
    let expected_cmp = (abi::GDI_TYPE_BRUSH as u32) << 16;
    let mut cmp = [0u8; 5];
    cmp[0] = 0x3D; // cmp eax, imm32
    cmp[1..].copy_from_slice(&expected_cmp.to_le_bytes());
    assert!(
        contains(&gdi32, begin, end, &cmp),
        "SelectObject compares the type against {expected_cmp:#x} (exemu's brush type \
         {:#x} << 16) before calling NtGdiSelectBrush",
        abi::GDI_TYPE_BRUSH
    );
}

/// **`GetStockObject` reads fixed handle-table slots and traps on an empty one.**
///
/// It issues no syscall at all: it maps the index to a slot, reads
/// `PEB[0xF8] + slot*24` and — the load-bearing part — branches to a `ud2` when
/// the entry's in-use byte is zero. A win32k that leaves the stock slots empty
/// does not return NULL, it **crashes** the first Wine control that asks for a
/// stock brush while painting. This asserts both the slot arithmetic exemu
/// publishes against and the fact that the trap is really there.
#[test]
fn stock_object_slots_are_fixed_and_an_empty_one_traps() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let gdi32 = Dll::load("gdi32.dll");
    let get_stock = gdi32.export("GetStockObject");
    let (begin, end) = gdi32.func_at(get_stock);

    // No syscall: GetStockObject reaches no win32u import at all.
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

    // `add ecx, 0x20` — the plain mapping `slot = index + STOCK_SLOT_BASE`.
    let base = u8::try_from(abi::STOCK_SLOT_BASE).expect("stock slot base is a byte");
    assert!(
        contains(&gdi32, begin, end, &[0x83, 0xC1, base]),
        "GetStockObject maps index -> index + {:#x}",
        abi::STOCK_SLOT_BASE
    );
    // `cmp byte ptr [rdx+0xe], 0` then a branch into a block ending in `ud2`.
    assert!(
        contains(&gdi32, begin, end, &[0x80, 0x7A, 0x0E, 0x00]),
        "GetStockObject tests the in-use byte at entry+{:#x}",
        abi::GDI_ENTRY_TYPE_OFF
    );

    // The DPI-variant font slots appear as literal immediates in the body. Each
    // of them must be one exemu publishes, or a control asking for that font
    // reads an empty slot and executes the trap.
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

    // Every published slot is inside the recovered range, and no two collide.
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

// ---------------------------------------------------------------------------
// 4. DC_ATTR — the DC object gdi32 and the kernel share
// ---------------------------------------------------------------------------

/// The DC origin, text colour and background colour live at fixed offsets in the
/// user-mode DC object, and gdi32 reads them **without a syscall** — so exemu has
/// to write them there. `GetDCOrgEx` in particular reads `+0x48`/`+0x4c` and
/// nothing in gdi32 ever writes them, which is what makes the DC origin the
/// kernel side's job (and therefore why a child control's DC needs its offset
/// published, roadmap W4.8).
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
        // `mov e?x, dword ptr [rax+disp8]` — ModRM 0x40|reg|rm=0 (rax).
        let found = (0u8..8).any(|reg| contains(&gdi32, begin, end, &[0x8B, 0x40 | (reg << 3), off8]));
        assert!(
            found,
            "gdi32!{export} does not read the DC object at +{off:#x} — exemu's DC_ATTR \
             layout has drifted from the pinned build"
        );
    }
    // The y half of the origin is the dword right after the x half.
    let (begin, end) = gdi32.func_at(gdi32.export("GetDCOrgEx"));
    let org_x = abi::DC_ATTR.iter().find(|(n, _)| *n == "GetDCOrgEx").unwrap().1;
    let org_y = u8::try_from(org_x + 4).unwrap();
    assert!(
        (0u8..8).any(|reg| contains(&gdi32, begin, end, &[0x8B, 0x40 | (reg << 3), org_y])),
        "GetDCOrgEx reads the origin's y at +{org_y:#x}, immediately after x"
    );
    // And GetDCOrgEx issues no syscall: the origin only ever comes from the
    // shared DC object, i.e. from whatever the kernel side put there.
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

/// `SetTextColor` / `SetBkColor` are **not** plain client-side stores: they go
/// through `NtGdiGetAndSetDCDword` with a selector immediate. Those selectors are
/// what exemu's handler dispatches on.
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

/// `user32!FillRect` — the call every themeless control paints with — lowers to
/// `SelectObject(brush)` + `PatBlt(PATCOPY)` + `SelectObject(previous)`, which is
/// why exemu services exactly those three and not a `FillRect` syscall (there
/// isn't one).
#[test]
fn fill_rect_lowers_to_select_brush_plus_patblt() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load("user32.dll");
    let (begin, end) = user32.func_at(user32.export("FillRect"));

    // `mov dword ptr [rsp+0x28], 0x00f00021` — PATCOPY in the 6th argument slot.
    assert!(
        contains(&user32, begin, end, &[0xC7, 0x44, 0x24, 0x28, 0x21, 0x00, 0xF0, 0x00]),
        "user32!FillRect issues PatBlt with PATCOPY (0x00f00021)"
    );
    // It calls gdi32!PatBlt, not any win32u entry point directly.
    let pat_blt = user32.iat("PatBlt");
    let body = user32.slice(begin, end);
    let calls_patblt = (0..body.len().saturating_sub(6))
        .any(|i| rip_indirect(body, i, user32.text_rva, begin + i as u32) == Some(pat_blt));
    assert!(calls_patblt, "user32!FillRect calls gdi32!PatBlt");
    // And there is no `FillRect` in win32u at all — the brush+blt pair is the
    // whole lowering.
    let win32u = Dll::load("win32u.dll");
    assert!(
        !win32u.exports.keys().any(|k| k.contains("FillRect")),
        "win32u exports no FillRect: the SelectBrush+PatBlt lowering is the only path"
    );
}
