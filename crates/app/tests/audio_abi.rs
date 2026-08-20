//! W7.2 — **the mmdevapi driver unixlib, re-derived from the pinned binaries**.
//!
//! Before exemu plays a single sample it has to know, exactly, what Wine's audio
//! stack *asks its driver for*. This test recovers that surface from the bytes
//! of `example_exe/wine-dlls/x86_64-windows/{winealsa,winepulse}.drv` and
//! `mmdevapi.dll` on every run and asserts it against the constants in
//! [`exemu_os::audio`]. A guessed code index or a wrong structure offset fails
//! **here**, loudly, instead of turning into silence three layers down.
//!
//! What it establishes, all from the binary:
//!
//! 1. Wine's `*.drv` audio drivers carry **no PE half worth the name**:
//!    `winealsa.drv` and `winepulse.drv` are byte-identical, export nothing, and
//!    import exactly `kernel32!DisableThreadLibraryCalls`. Nothing about the
//!    interface is ALSA- or PulseAudio-specific, because nothing about the
//!    interface is in them at all.
//! 2. **`mmdevapi.dll` is the PE half** — the only audio DLL in the prefix that
//!    imports the unixlib bootstrap trio.
//! 3. `mmdevapi!load_driver` builds `L"wine" + name + L".drv"`, `LoadLibraryW`s
//!    it, and asks `NtQueryVirtualMemory(…, MemoryWineUnixFuncs, …, 8, …)` for
//!    that module's unixlib handle — the exact handshake exemu answers.
//! 4. The **complete code table**: every `call [__wine_unix_call_dispatcher]` in
//!    mmdevapi's `.text`, the `mov edx, imm` code in its argument slot, and the
//!    name of the enclosing function read out of mmdevapi's own **COFF symbol
//!    table**. The codes are a dense 0..=36.
//! 5. The **argument-structure offsets** exemu marshals, re-derived from the
//!    `lea r8, [rsp+disp]` that forms each call's `args` pointer and the
//!    `[rsp+disp8]` stores and loads around it.
//!
//! No disassembler: the scans are raw byte patterns, the same technique
//! `afd_abi.rs` uses.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::{BTreeMap, BTreeSet};

use exemu_core::ImportSymbol;
use exemu_os::audio;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn dll(name: &str) -> std::path::PathBuf {
    std::path::Path::new(WINE_DLLS).join(name)
}

fn skip() -> bool {
    if dll("mmdevapi.dll").exists() && dll("winealsa.drv").exists() {
        return false;
    }
    eprintln!("SKIP: {WINE_DLLS} audio DLLs not present (the Wine DLL set is git-ignored)");
    true
}

// ---------------------------------------------------------------------------
// Byte-level recovery helpers
// ---------------------------------------------------------------------------

/// `call qword ptr [rip+disp32]` — `FF 15 <disp32>`; the RVA it resolves to.
fn rip_call(code: &[u8], text_rva: u32, i: usize) -> Option<u32> {
    if i + 6 > code.len() || code[i] != 0xFF || code[i + 1] != 0x15 {
        return None;
    }
    let disp = i32::from_le_bytes(code[i + 2..i + 6].try_into().unwrap());
    u32::try_from(text_rva as i64 + i as i64 + 6 + disp as i64).ok()
}

/// `mov <reg>, qword ptr [rip+disp32]` / `lea` — the RVA of the operand, for
/// the `48 8B ?? ...` and `48 8D ?? ...` forms with a `rip` base (`modrm.rm`
/// = 5, `mod` = 0).
fn rip_operand(code: &[u8], text_rva: u32, i: usize, op: u8) -> Option<u32> {
    if i + 7 > code.len() || code[i] & 0xF8 != 0x48 || code[i + 1] != op {
        return None;
    }
    if code[i + 2] & 0xC7 != 0x05 {
        return None;
    }
    let disp = i32::from_le_bytes(code[i + 3..i + 7].try_into().unwrap());
    u32::try_from(text_rva as i64 + i as i64 + 7 + disp as i64).ok()
}

/// UTF-16LE bytes of `s`, without a terminator — for searching an image.
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// One recovered dispatcher call site.
#[derive(Debug, Clone, Copy)]
struct Site {
    /// RVA of the `call` itself.
    call_rva: u32,
    /// RVA of the enclosing `.pdata` function.
    func_rva: u32,
    /// The `code` argument (`mov edx, imm32` / `xor edx, edx`).
    code: Option<u32>,
    /// `[rsp+disp]` the `args` pointer was `lea`'d from, or `None` when the
    /// call passes `args = NULL` (`xor r8d, r8d`).
    args_disp: Option<u32>,
    /// Whether `args` was explicitly NULL.
    args_null: bool,
}

/// The recovered picture of `mmdevapi.dll`.
struct Mmdevapi {
    code: Vec<u8>,
    text_rva: u32,
    /// `.data` section bytes and RVA (the dispatcher pointer lives there).
    data: Vec<u8>,
    data_rva: u32,
    funcs: Vec<(u32, u32)>,
    /// COFF symbol name → RVA, and the reverse for the ones in `.text`.
    sym: BTreeMap<String, u32>,
    sym_at: BTreeMap<u32, String>,
    sites: Vec<Site>,
    /// The whole file, for literal searches.
    bytes: Vec<u8>,
    image: exemu_core::PeImage,
}

impl Mmdevapi {
    fn recover() -> Mmdevapi {
        let bytes = std::fs::read(dll("mmdevapi.dll")).expect("read mmdevapi.dll");
        let image = exemu_loader::parse(&bytes).expect("mmdevapi.dll parses as PE32+");
        assert!(image.is_64bit, "the pinned mmdevapi.dll must be PE32+");

        let text = image
            .sections
            .iter()
            .find(|s| s.name == ".text" && s.executable)
            .expect("mmdevapi.dll has an executable .text");
        let data = image
            .sections
            .iter()
            .find(|s| s.name == ".data")
            .expect("mmdevapi.dll has a .data");

        let mut funcs: Vec<(u32, u32)> = image.function_table.iter().map(|f| (f.begin_rva, f.end_rva)).collect();
        funcs.sort_unstable();
        assert!(!funcs.is_empty(), "mmdevapi.dll carries a .pdata function table");

        let (sym, sym_at) = coff_symbols(&bytes, &image);
        assert!(
            sym.len() > 1000,
            "mingw keeps mmdevapi's COFF symbol table; got {} symbols",
            sym.len()
        );

        let dispatcher = *sym
            .get("__wine_unix_call_dispatcher")
            .expect("mmdevapi names its own __wine_unix_call_dispatcher slot");

        let sites = scan_dispatcher_calls(&text.data, text.rva, &funcs, dispatcher);

        Mmdevapi {
            code: text.data.clone(),
            text_rva: text.rva,
            data: data.data.clone(),
            data_rva: data.rva,
            funcs,
            sym,
            sym_at,
            sites,
            bytes,
            image,
        }
    }

    fn sym(&self, name: &str) -> u32 {
        *self
            .sym
            .get(name)
            .unwrap_or_else(|| panic!("mmdevapi.dll's COFF symbol table names {name}"))
    }

    fn func_of(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{rva:#x} lies in a .pdata function"))
    }

    /// The call site issuing `code` from the function named `func`.
    fn site(&self, func: &str, code: u32) -> Site {
        let (begin, _) = self.func_of(self.sym(func));
        let hits: Vec<Site> = self
            .sites
            .iter()
            .copied()
            .filter(|s| s.func_rva == begin && s.code == Some(code))
            .collect();
        assert!(
            !hits.is_empty(),
            "{func} should issue unixlib code {code}; it issues {:?}",
            self.sites
                .iter()
                .filter(|s| s.func_rva == begin)
                .map(|s| s.code)
                .collect::<Vec<_>>()
        );
        hits[0]
    }

    /// The IAT slot RVA of an imported symbol.
    fn iat(&self, dll_name: &str, symbol: &str) -> u32 {
        self.image
            .imports
            .iter()
            .find(|i| {
                i.dll.eq_ignore_ascii_case(dll_name)
                    && matches!(&i.symbol, ImportSymbol::Named(n) if n == symbol)
            })
            .unwrap_or_else(|| panic!("mmdevapi.dll imports {dll_name}!{symbol}"))
            .iat_rva
    }

    /// Whether `needle` occurs in `[begin, end)` of `.text`.
    fn contains(&self, begin: u32, end: u32, needle: &[u8]) -> bool {
        let lo = (begin - self.text_rva) as usize;
        let hi = ((end - self.text_rva) as usize).min(self.code.len());
        lo < hi && self.code[lo..hi].windows(needle.len()).any(|w| w == needle)
    }

    /// Whether the function containing `rva` calls `iat_rva`.
    fn calls(&self, func_begin: u32, func_end: u32, iat_rva: u32) -> bool {
        let lo = (func_begin - self.text_rva) as usize;
        let hi = ((func_end - self.text_rva) as usize).min(self.code.len());
        (lo..hi).any(|i| rip_call(&self.code, self.text_rva, i) == Some(iat_rva))
    }

    /// Whether the function *hoists* `iat_rva` into a register
    /// (`mov r64, qword ptr [rip+disp32]`) and calls it indirectly — what gcc
    /// does for an import used inside a loop, and what `load_driver_devices`
    /// does with `malloc`/`free`.
    fn loads_iat(&self, func_begin: u32, func_end: u32, iat_rva: u32) -> bool {
        let lo = (func_begin - self.text_rva) as usize;
        let hi = ((func_end - self.text_rva) as usize).min(self.code.len());
        (lo..hi).any(|i| rip_operand(&self.code, self.text_rva, i, 0x8B) == Some(iat_rva))
    }

    /// The `disp8` of the first `mov eax, dword ptr [rsp+disp8]`
    /// (`8B 44 24 disp8`) at or after `from`, bounded by the function end. This
    /// is how mmdevapi reads an `HRESULT` back out of an argument block, so the
    /// answer minus the block's base is the result field's offset.
    fn first_result_load(&self, from: u32, end: u32) -> u32 {
        let lo = (from - self.text_rva) as usize;
        let hi = ((end - self.text_rva) as usize).min(self.code.len());
        let mut i = lo;
        while i + 4 <= hi {
            if self.code[i] == 0x8B && self.code[i + 1] == 0x44 && self.code[i + 2] == 0x24 {
                return self.code[i + 3] as u32;
            }
            i += 1;
        }
        panic!("no `mov eax, [rsp+disp8]` after {from:#x}");
    }
}

/// Parse the COFF symbol table mingw leaves in the shipped image: 18-byte
/// records at `PointerToSymbolTable`, names either inline (8 bytes) or an offset
/// into the string table that follows.
fn coff_symbols(bytes: &[u8], image: &exemu_core::PeImage) -> (BTreeMap<String, u32>, BTreeMap<u32, String>) {
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let symptr = u32::from_le_bytes(bytes[pe_off + 12..pe_off + 16].try_into().unwrap()) as usize;
    let nsyms = u32::from_le_bytes(bytes[pe_off + 16..pe_off + 20].try_into().unwrap()) as usize;
    let mut by_name = BTreeMap::new();
    let mut by_rva: BTreeMap<u32, String> = BTreeMap::new();
    if symptr == 0 || nsyms == 0 {
        return (by_name, by_rva);
    }
    let strtab = &bytes[symptr + 18 * nsyms..];
    let mut i = 0usize;
    while i < nsyms {
        let e = &bytes[symptr + 18 * i..symptr + 18 * i + 18];
        let name = if e[..4] == [0, 0, 0, 0] {
            let off = u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize;
            let end = strtab[off..].iter().position(|b| *b == 0).unwrap_or(0) + off;
            String::from_utf8_lossy(&strtab[off..end]).into_owned()
        } else {
            let end = e[..8].iter().position(|b| *b == 0).unwrap_or(8);
            String::from_utf8_lossy(&e[..end]).into_owned()
        };
        let value = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let secnum = i16::from_le_bytes(e[12..14].try_into().unwrap());
        let naux = e[17] as usize;
        if secnum >= 1 && (secnum as usize) <= image.sections.len() {
            let rva = image.sections[secnum as usize - 1].rva + value;
            by_name.entry(name.clone()).or_insert(rva);
            by_rva.entry(rva).or_insert(name);
        }
        i += 1 + naux;
    }
    (by_name, by_rva)
}

/// Walk each `.pdata` function's bytes forward, remembering the most recent
/// `mov edx, imm32` / `xor edx, edx` (the unixlib `code`) and the most recent
/// `lea r8, [rsp+disp]` / `xor r8d, r8d` (the `args` pointer), and record every
/// call through the dispatcher slot. Same "what was in the argument register
/// when the call happened" reading a disassembler gives, done on raw bytes so
/// the test carries no decoder of its own.
fn scan_dispatcher_calls(code: &[u8], text_rva: u32, funcs: &[(u32, u32)], dispatcher: u32) -> Vec<Site> {
    let mut out = Vec::new();
    for &(begin, end) in funcs {
        let Some(lo) = begin.checked_sub(text_rva).map(|o| o as usize) else {
            continue;
        };
        if lo >= code.len() {
            continue;
        }
        let hi = ((end - text_rva) as usize).min(code.len());
        let mut edx: Option<u32> = None;
        let mut args: Option<u32> = None;
        let mut args_null = false;
        let mut i = lo;
        while i < hi {
            // mov edx, imm32
            if code[i] == 0xBA && i + 5 <= hi {
                edx = Some(u32::from_le_bytes(code[i + 1..i + 5].try_into().unwrap()));
                i += 5;
                continue;
            }
            // xor edx, edx
            if i + 2 <= hi && code[i] == 0x31 && code[i + 1] == 0xD2 {
                edx = Some(0);
                i += 2;
                continue;
            }
            // lea r8, [rsp+disp8]
            if i + 5 <= hi && code[i..i + 4] == [0x4C, 0x8D, 0x44, 0x24] {
                args = Some(code[i + 4] as u32);
                args_null = false;
                i += 5;
                continue;
            }
            // lea r8, [rsp+disp32]
            if i + 8 <= hi && code[i..i + 4] == [0x4C, 0x8D, 0x84, 0x24] {
                args = Some(u32::from_le_bytes(code[i + 4..i + 8].try_into().unwrap()));
                args_null = false;
                i += 8;
                continue;
            }
            // xor r8d, r8d
            if i + 3 <= hi && code[i..i + 3] == [0x45, 0x31, 0xC0] {
                args = None;
                args_null = true;
                i += 3;
                continue;
            }
            if rip_call(code, text_rva, i) == Some(dispatcher) {
                out.push(Site {
                    call_rva: text_rva + i as u32,
                    func_rva: begin,
                    code: edx,
                    args_disp: args,
                    args_null,
                });
                edx = None;
                i += 6;
                continue;
            }
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. Wine's `*.drv` audio drivers have no PE half
// ---------------------------------------------------------------------------

/// The finding that decides the whole shape of W7.2: the pinned prefix's audio
/// drivers are **not** ALSA-specific PE halves that exemu would have to be
/// compatible with. They are the *same stub*, byte for byte, with no exports and
/// a `DllMain` whose only import is `DisableThreadLibraryCalls`.
#[test]
fn the_audio_drv_modules_are_identical_export_less_stubs() {
    if skip() {
        return;
    }
    let alsa = std::fs::read(dll("winealsa.drv")).expect("read winealsa.drv");
    let pulse = std::fs::read(dll("winepulse.drv")).expect("read winepulse.drv");
    assert_eq!(
        alsa, pulse,
        "winealsa.drv and winepulse.drv must be byte-identical — that is what makes \
         the driver interface generic rather than backend-specific"
    );

    let image = exemu_loader::parse(&alsa).expect("winealsa.drv parses as PE");
    assert!(image.is_64bit);
    assert!(
        image.exports.is_empty(),
        "the driver stub exports nothing: {:?}",
        image.exports.iter().filter_map(|e| e.name.clone()).collect::<Vec<_>>()
    );
    assert_eq!(
        image.dll_name, None,
        "…and therefore has no export directory to be identified by, which is why \
         exemu generates its own {} instead of pairing with this one",
        audio::DRIVER_MODULE
    );
    let imports: Vec<String> = image
        .imports
        .iter()
        .map(|i| match &i.symbol {
            ImportSymbol::Named(n) => format!("{}!{n}", i.dll.to_ascii_lowercase()),
            ImportSymbol::Ordinal(o) => format!("{}!#{o}", i.dll.to_ascii_lowercase()),
        })
        .collect();
    assert_eq!(
        imports,
        vec!["kernel32.dll!DisableThreadLibraryCalls".to_string()],
        "the whole driver PE is a DllMain that disables thread notifications"
    );
    let text = image.sections.iter().find(|s| s.name == ".text").expect(".text");
    assert!(
        text.virtual_size < 0x200,
        ".text is {:#x} bytes — there is no audio code in this image at all",
        text.virtual_size
    );
}

// ---------------------------------------------------------------------------
// 2. mmdevapi is the PE half
// ---------------------------------------------------------------------------

/// Exactly one audio DLL in the prefix imports the unixlib bootstrap trio. That
/// is the module exemu must answer, and everything above it (`winmm`'s waveOut,
/// `dsound`, `xaudio2`) reaches the driver through its COM surface as guest
/// code, never through this boundary.
#[test]
fn mmdevapi_is_the_only_audio_dll_that_asks_for_a_unix_side() {
    if skip() {
        return;
    }
    const TRIO: [&str; 3] = ["NtQueryVirtualMemory", "LdrGetDllHandle", "RtlFindExportedRoutineByName"];
    let has_trio = |name: &str| -> Option<bool> {
        let bytes = std::fs::read(dll(name)).ok()?;
        let image = exemu_loader::parse(&bytes).ok()?;
        let named: BTreeSet<String> = image
            .imports
            .iter()
            .filter(|i| i.dll.eq_ignore_ascii_case("ntdll.dll"))
            .filter_map(|i| match &i.symbol {
                ImportSymbol::Named(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        Some(TRIO.iter().all(|s| named.contains(*s)))
    };

    assert_eq!(has_trio("mmdevapi.dll"), Some(true), "mmdevapi.dll is the PE half");
    for other in ["winmm.dll", "dsound.dll", "xaudio2_8.dll", "mciwave.dll", "msacm32.dll", "midimap.dll"] {
        if let Some(yes) = has_trio(other) {
            assert!(!yes, "{other} should reach the driver through mmdevapi, not its own unixlib");
        }
    }
}

/// The PE-side bootstrap: `__wine_unix_call_dispatcher` starts as a pointer to a
/// self-installing trampoline that resolves the real dispatcher out of
/// `ntdll.dll` by name. Verifying it matters because it is the mechanism exemu's
/// boot already wires (`RVA_WINE_UNIX_CALL_DISPATCHER`) — mmdevapi reaching
/// exemu at all depends on it.
#[test]
fn the_dispatcher_slot_bootstraps_itself_out_of_ntdll() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let slot = m.sym("__wine_unix_call_dispatcher");
    let off = (slot - m.data_rva) as usize;
    let initial = u64::from_le_bytes(m.data[off..off + 8].try_into().unwrap());
    let init_rva = (initial - m.image.image_base) as u32;
    assert_eq!(
        m.sym_at.get(&init_rva).map(String::as_str),
        Some("unix_call_init"),
        "the slot should start pointing at the self-installing trampoline"
    );

    let (begin, end) = m.func_of(init_rva);
    assert!(
        m.calls(begin, end, m.iat("ntdll.dll", "LdrGetDllHandle")),
        "unix_call_init looks ntdll up"
    );
    assert!(
        m.calls(begin, end, m.iat("ntdll.dll", "RtlFindExportedRoutineByName")),
        "…and finds the dispatcher there by name"
    );
    // UNICODE_STRING{ Length = 2*9, MaximumLength = 2*10 } for L"ntdll.dll",
    // stored as one dword immediate — derived from the name, not transcribed.
    let ustr = 0x12u32 | (0x14u32 << 16);
    assert!(
        m.contains(begin, end, &[&[0xC7u8, 0x44, 0x24][..], &[0x30], &ustr.to_le_bytes()[..]].concat())
            || m.contains(begin, end, &ustr.to_le_bytes()),
        "unix_call_init builds a UNICODE_STRING for L\"ntdll.dll\""
    );
    // The symbol it asks for, verbatim, in .rdata.
    let needle = b"__wine_unix_call_dispatcher\0";
    assert!(
        m.bytes.windows(needle.len()).any(|w| w == needle),
        "the symbol name travels as an ASCII literal"
    );
}

// ---------------------------------------------------------------------------
// 3. load_driver — how a driver is found and paired
// ---------------------------------------------------------------------------

/// `load_driver` is the entire handshake exemu answers. Everything asserted here
/// is what makes exemu's own generated `winecoreaudio.drv` reachable: the module
/// name is built from the registry list with mmdevapi's own `L"wine%s.drv"`, and
/// the unixlib handle comes from `MemoryWineUnixFuncs` on that module.
#[test]
fn load_driver_builds_the_module_name_and_queries_memory_wine_unix_funcs() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let (begin, end) = m.func_of(m.sym("load_driver"));

    for part in [audio::DRIVER_MODULE_PREFIX, audio::DRIVER_MODULE_SUFFIX] {
        let lit = utf16(part);
        assert!(
            m.bytes.windows(lit.len()).any(|w| w == lit),
            "L\"{part}\" is in mmdevapi's .rdata — load_driver concatenates the two \
             around the driver name"
        );
    }

    assert!(
        m.calls(begin, end, m.iat("kernel32.dll", "LoadLibraryW")),
        "load_driver LoadLibraryW's the module it just named"
    );
    assert!(
        m.calls(begin, end, m.iat("ntdll.dll", "NtQueryVirtualMemory")),
        "…then asks that module for its unixlib handle"
    );
    // mov r8d, 1000 — MemoryWineUnixFuncs, in NtQueryVirtualMemory's third
    // argument register, inside load_driver's own body.
    assert!(
        m.contains(begin, end, &[&[0x41u8, 0xB8][..], &1000u32.to_le_bytes()[..]].concat()),
        "the info class is MemoryWineUnixFuncs (1000)"
    );
    // mov qword [rsp+0x20], 8 — the buffer length: one unixlib_handle_t.
    assert!(
        m.contains(begin, end, &[0x48, 0xC7, 0x44, 0x24, 0x20, 0x08, 0x00, 0x00, 0x00]),
        "…and it asks for exactly 8 bytes"
    );

    // The first thing it does with the handle is code 0 with args = NULL,
    // and the probe that follows is code 27.
    let attach = m.site("load_driver", audio::CODE_PROCESS_ATTACH);
    assert!(attach.args_null, "process_attach takes no arguments");
    let probe = m.site("load_driver", audio::CODE_TEST_CONNECT);
    assert!(
        probe.call_rva > attach.call_rva,
        "test_connect follows process_attach"
    );
    // The priority slot is pre-seeded with `Neutral` before the probe.
    let base = probe.args_disp.expect("test_connect passes an args pointer");
    let seed = [
        &[0xC7u8, 0x44, 0x24][..],
        &[(base + audio::TEST_CONNECT_PRIORITY as u32) as u8],
        &audio::PRIORITY_NEUTRAL.to_le_bytes()[..],
    ]
    .concat();
    assert!(
        m.contains(begin, end, &seed),
        "test_connect's priority field sits at +{:#x} and is pre-seeded with {}",
        audio::TEST_CONNECT_PRIORITY,
        audio::PRIORITY_NEUTRAL
    );
}

/// The driver-selection inputs, verbatim from mmdevapi's `.rdata`: the registry
/// key `init_driver` opens, and the fallback list it uses when the value is
/// absent. `coreaudio` being in that list is why exemu needs no patch to be
/// selected — it only has to seed the registry value and provide the module.
#[test]
fn the_driver_registry_key_and_default_list_are_mmdevapis_own_literals() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    for lit in [audio::DRIVER_KEY, audio::DRIVER_DEFAULT_LIST] {
        let needle = utf16(lit);
        assert!(
            m.bytes.windows(needle.len()).any(|w| w == needle),
            "L\"{lit}\" is a literal in the pinned mmdevapi.dll"
        );
    }
    assert!(
        audio::DRIVER_DEFAULT_LIST.split(',').any(|d| d == audio::DRIVER_NAME),
        "exemu's driver name must be one mmdevapi already tries"
    );
    assert_eq!(
        format!(
            "{}{}{}",
            audio::DRIVER_MODULE_PREFIX,
            audio::DRIVER_NAME,
            audio::DRIVER_MODULE_SUFFIX
        ),
        audio::DRIVER_MODULE
    );
}

// ---------------------------------------------------------------------------
// 4. The code table
// ---------------------------------------------------------------------------

/// The complete unixlib contract, recovered exhaustively: every dispatcher call
/// site in mmdevapi's `.text`, its code, and the name of the function issuing it
/// from mmdevapi's own COFF symbol table. A drift in any index — the classic way
/// to get a unixlib silently wrong — fails here.
#[test]
fn the_driver_unixlib_table_is_a_dense_zero_to_thirtysix() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();

    // Each row: the code, and a function that must issue it.
    let rows: &[(u32, &str)] = &[
        (audio::CODE_PROCESS_ATTACH, "load_driver"),
        (audio::CODE_PROCESS_DETACH, "DllMain"),
        (audio::CODE_MAIN_LOOP, "main_loop_func"),
        (audio::CODE_GET_ENDPOINT_IDS, "load_driver_devices"),
        (audio::CODE_CREATE_STREAM, "stream_init"),
        (audio::CODE_RELEASE_STREAM, "stream_release"),
        (audio::CODE_START, "client_Start"),
        (audio::CODE_STOP, "client_Stop"),
        (audio::CODE_RESET, "client_Reset"),
        (audio::CODE_TIMER_LOOP, "timer_loop_func"),
        (audio::CODE_GET_RENDER_BUFFER, "render_GetBuffer"),
        (audio::CODE_RELEASE_RENDER_BUFFER, "render_ReleaseBuffer"),
        (audio::CODE_GET_CAPTURE_BUFFER, "capture_GetBuffer"),
        (audio::CODE_RELEASE_CAPTURE_BUFFER, "capture_ReleaseBuffer"),
        (audio::CODE_IS_FORMAT_SUPPORTED, "client_IsFormatSupported"),
        (audio::CODE_GET_LOOPBACK_CAPTURE_DEVICE, "stream_init"),
        (audio::CODE_GET_MIX_FORMAT, "client_GetMixFormat"),
        (audio::CODE_GET_DEVICE_PERIOD, "client_GetDevicePeriod"),
        (audio::CODE_GET_BUFFER_SIZE, "client_GetBufferSize"),
        (audio::CODE_GET_LATENCY, "client_GetStreamLatency"),
        (audio::CODE_GET_CURRENT_PADDING, "client_GetCurrentPadding"),
        (audio::CODE_GET_NEXT_PACKET_SIZE, "capture_GetNextPacketSize"),
        (audio::CODE_GET_FREQUENCY, "clock_GetFrequency"),
        (audio::CODE_GET_POSITION, "clock_GetPosition"),
        (audio::CODE_SET_VOLUMES, "set_stream_volumes"),
        (audio::CODE_SET_EVENT_HANDLE, "client_SetEventHandle"),
        (audio::CODE_SET_SAMPLE_RATE, "AudioClockAdjustment_SetSampleRate"),
        (audio::CODE_TEST_CONNECT, "load_driver"),
        (audio::CODE_IS_STARTED, "control_GetState"),
        (audio::CODE_GET_PROP_VALUE, "set_driver_prop_value"),
        (audio::CODE_MIDI_DRIVER_NAME, "init_driver"),
        (audio::CODE_MIDI_INIT, "DriverProc"),
        (audio::CODE_MIDI_RELEASE, "DriverProc"),
        (audio::CODE_MIDI_OUT_MESSAGE, "modMessage"),
        (audio::CODE_MIDI_IN_MESSAGE, "midMessage"),
        (audio::CODE_MIDI_NOTIFY_WAIT, "notify_thread"),
        (audio::CODE_AUX_MESSAGE, "auxMessage"),
    ];
    assert_eq!(rows.len(), audio::UNIXLIB_ENTRIES, "one row per table entry");

    for (code, func) in rows {
        let site = m.site(func, *code);
        assert_eq!(site.code, Some(*code));
    }

    // …and nothing outside 0..=36 is ever issued, which is what makes a
    // 37-entry table complete rather than merely sufficient.
    let issued: BTreeSet<u32> = m.sites.iter().filter_map(|s| s.code).collect();
    assert_eq!(
        issued,
        (0..audio::UNIXLIB_ENTRIES as u32).collect::<BTreeSet<u32>>(),
        "the codes mmdevapi issues are exactly 0..={}",
        audio::UNIXLIB_ENTRIES - 1
    );
    assert!(
        m.sites.iter().all(|s| s.code.is_some()),
        "every dispatcher call site's code was recovered ({} sites)",
        m.sites.len()
    );
    eprintln!("recovered {} dispatcher call sites, codes 0..=36", m.sites.len());
}

// ---------------------------------------------------------------------------
// 5. Argument-structure offsets
// ---------------------------------------------------------------------------

/// Where each answer lands. The `HRESULT` field is the one exemu writes on every
/// path, so getting its offset wrong turns a working backend into a caller that
/// reads back garbage. Each row is re-derived: find the call, take the
/// `lea r8, [rsp+base]` that formed its `args`, then the first
/// `mov eax, [rsp+disp]` after it — the difference is the offset.
#[test]
fn the_result_field_offsets_are_where_mmdevapi_reads_them_back() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let rows: &[(&str, u32, u64)] = &[
        ("client_GetBufferSize", audio::CODE_GET_BUFFER_SIZE, audio::STREAM_OUT_RESULT),
        ("client_GetCurrentPadding", audio::CODE_GET_CURRENT_PADDING, audio::STREAM_OUT_RESULT),
        ("client_GetStreamLatency", audio::CODE_GET_LATENCY, audio::STREAM_OUT_RESULT),
        ("clock_GetFrequency", audio::CODE_GET_FREQUENCY, audio::STREAM_OUT_RESULT),
        ("capture_GetNextPacketSize", audio::CODE_GET_NEXT_PACKET_SIZE, audio::STREAM_OUT_RESULT),
        ("client_Start", audio::CODE_START, audio::STREAM_ONLY_RESULT),
        ("client_Stop", audio::CODE_STOP, audio::STREAM_ONLY_RESULT),
        ("client_Reset", audio::CODE_RESET, audio::STREAM_ONLY_RESULT),
        ("render_GetBuffer", audio::CODE_GET_RENDER_BUFFER, audio::RENDER_GET_RESULT),
        ("render_ReleaseBuffer", audio::CODE_RELEASE_RENDER_BUFFER, audio::RENDER_REL_RESULT),
        ("client_GetMixFormat", audio::CODE_GET_MIX_FORMAT, audio::MIX_FMT_RESULT),
        ("client_GetDevicePeriod", audio::CODE_GET_DEVICE_PERIOD, audio::PERIOD_RESULT),
        ("client_IsFormatSupported", audio::CODE_IS_FORMAT_SUPPORTED, audio::FMT_SUPPORTED_RESULT),
        ("clock_GetPosition", audio::CODE_GET_POSITION, audio::POSITION_RESULT),
        ("stream_release", audio::CODE_RELEASE_STREAM, audio::RELEASE_STREAM_RESULT),
        ("client_SetEventHandle", audio::CODE_SET_EVENT_HANDLE, audio::EVENT_RESULT),
    ];
    for (func, code, want) in rows {
        let site = m.site(func, *code);
        let (_, end) = m.func_of(site.call_rva);
        let base = site.args_disp.unwrap_or_else(|| panic!("{func} passes an args pointer"));
        let load = m.first_result_load(site.call_rva, end);
        assert_eq!(
            u64::from(load - base),
            *want,
            "{func}: args at [rsp+{base:#x}], HRESULT read from [rsp+{load:#x}]"
        );
    }
}

/// The input fields on the render hot path, recovered from the stores that
/// precede each call. These are the offsets exemu reads the frame counts and the
/// `BYTE**` out-pointer from — the difference between playing a buffer and
/// scribbling somewhere else.
#[test]
fn the_render_path_input_offsets_are_where_mmdevapi_writes_them() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();

    // render_GetBuffer: `mov [rsp+base+8], edi` (frames),
    //                   `mov [rsp+base+0x10], rbx` (the BYTE** out).
    let get = m.site("render_GetBuffer", audio::CODE_GET_RENDER_BUFFER);
    let (gb, ge) = m.func_of(get.call_rva);
    let base = get.args_disp.unwrap();
    assert!(
        m.contains(gb, ge, &[0x89, 0x7C, 0x24, (base + audio::RENDER_GET_FRAMES as u32) as u8]),
        "get_render_buffer's frame count sits at +{:#x}",
        audio::RENDER_GET_FRAMES
    );
    assert!(
        m.contains(gb, ge, &[0x48, 0x89, 0x5C, 0x24, (base + audio::RENDER_GET_DATA as u32) as u8]),
        "…and the BYTE** out-pointer at +{:#x}",
        audio::RENDER_GET_DATA
    );

    // render_ReleaseBuffer: `mov [rsp+base+8], edi` (frames written),
    //                       `mov [rsp+base+0xc], esi` (flags).
    let rel = m.site("render_ReleaseBuffer", audio::CODE_RELEASE_RENDER_BUFFER);
    let (rb, re) = m.func_of(rel.call_rva);
    let rbase = rel.args_disp.unwrap();
    assert!(
        m.contains(rb, re, &[0x89, 0x7C, 0x24, (rbase + audio::RENDER_REL_FRAMES as u32) as u8]),
        "release_render_buffer's written-frame count sits at +{:#x}",
        audio::RENDER_REL_FRAMES
    );
    assert!(
        m.contains(rb, re, &[0x89, 0x74, 0x24, (rbase + audio::RENDER_REL_FLAGS as u32) as u8]),
        "…and its flags at +{:#x}",
        audio::RENDER_REL_FLAGS
    );

    // The `{stream, HRESULT, T *out}` family writes its out-pointer at +0x10.
    for func in [
        "client_GetBufferSize",
        "client_GetCurrentPadding",
        "client_GetStreamLatency",
        "clock_GetFrequency",
    ] {
        let site = m.sites.iter().find(|s| s.func_rva == m.func_of(m.sym(func)).0).unwrap();
        let (b, e) = m.func_of(site.call_rva);
        let base = site.args_disp.unwrap();
        // The register carrying the caller's out-pointer differs (rbx or rsi);
        // the *slot* it lands in is the fact under test.
        let disp = (base + audio::STREAM_OUT_PTR as u32) as u8;
        assert!(
            m.contains(b, e, &[0x48, 0x89, 0x5C, 0x24, disp]) || m.contains(b, e, &[0x48, 0x89, 0x74, 0x24, disp]),
            "{func}'s out-pointer sits at +{:#x}",
            audio::STREAM_OUT_PTR
        );
    }
}

/// `get_mix_format`'s reply block is a `CoTaskMemAlloc(0x28)` — exactly
/// `sizeof(WAVEFORMATEXTENSIBLE)`. That single immediate is what fixes the shape
/// of the format exemu must write, and it is read straight out of the caller.
#[test]
fn get_mix_format_allocates_exactly_a_waveformatextensible() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let (begin, end) = m.func_of(m.sym("client_GetMixFormat"));
    assert!(
        m.calls(begin, end, m.iat("ole32.dll", "CoTaskMemAlloc")),
        "client_GetMixFormat allocates the block it hands the driver"
    );
    // mov ecx, 0x28
    assert!(
        m.contains(begin, end, &[&[0xB9u8][..], &audio::WAVEFORMATEXTENSIBLE_LEN.to_le_bytes()[..]].concat()),
        "…of {} bytes",
        audio::WAVEFORMATEXTENSIBLE_LEN
    );
}

/// `get_endpoint_ids`'s overflow protocol. mmdevapi loops on
/// `HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)`, growing the buffer each
/// time, so exemu must answer with that exact HRESULT rather than a generic
/// failure — otherwise enumeration stops with zero endpoints.
#[test]
fn get_endpoint_ids_retries_on_the_insufficient_buffer_hresult() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let (begin, end) = m.func_of(m.sym("load_driver_devices"));
    // cmp eax, 0x8007007A
    assert!(
        m.contains(
            begin,
            end,
            &[&[0x3Du8][..], &audio::HRESULT_ERROR_INSUFFICIENT_BUFFER.to_le_bytes()[..]].concat()
        ),
        "load_driver_devices retries on {:#x}",
        audio::HRESULT_ERROR_INSUFFICIENT_BUFFER
    );
    assert!(
        m.loads_iat(begin, end, m.iat("ucrtbase.dll", "malloc")),
        "…after growing the buffer"
    );
    // Each endpoint entry is a pair of u32 offsets: `mov ebx,[rax]` then
    // `mov eax,[rax+4]`, both added to the buffer base.
    assert!(
        m.contains(begin, end, &[0x8B, 0x18, 0x8B, 0x40, audio::ENDPOINT_ID_OFF as u8]),
        "an endpoint entry is {{name@+{:#x}, id@+{:#x}}}",
        audio::ENDPOINT_NAME_OFF,
        audio::ENDPOINT_ID_OFF
    );
    // …and `lea rax, [rdx + rsi*8]` indexes them, which fixes the stride.
    assert!(
        m.contains(begin, end, &[0x48, 0x8D, 0x04, 0xF2]),
        "…with a stride of {}",
        audio::ENDPOINT_STRIDE
    );
}

/// `mmdevapi!get_device_guid` widens the endpoint **id** with
/// `MultiByteToWideChar`, which is how we know the id is a `char` string while
/// the friendly name is `WCHAR` — a detail that would otherwise be a coin flip,
/// and one exemu's endpoint table depends on.
#[test]
fn the_endpoint_id_is_a_char_string_and_the_name_is_wide() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let (begin, end) = m.func_of(m.sym("get_device_guid"));
    assert!(
        m.calls(begin, end, m.iat("kernel32.dll", "MultiByteToWideChar")),
        "get_device_guid widens the id it was handed — so the id is multibyte"
    );
    // The friendly name goes to MMDevice_Create untouched, and the registry key
    // it builds is a wide format string.
    let fmt = utf16("Software\\Wine\\Drivers\\%s\\devices\\%u,");
    assert!(
        m.bytes.windows(fmt.len()).any(|w| w == fmt),
        "the per-device registry path is a wide literal"
    );
    // get_device_name_from_guid hands the id back with _strdup — a char* API.
    let (nb, ne) = m.func_of(m.sym("get_device_name_from_guid"));
    assert!(
        m.calls(nb, ne, m.iat("ucrtbase.dll", "_strdup")),
        "…and it comes back through _strdup, not _wcsdup"
    );
}

/// `client_GetDevicePeriod` clamps whatever the driver reports up to 10 ms.
/// Recovered because it tells exemu that reporting a *smaller* default period
/// achieves nothing, and pins the units as 100 ns.
#[test]
fn mmdevapi_clamps_the_default_period_to_ten_milliseconds() {
    if skip() {
        return;
    }
    let m = Mmdevapi::recover();
    let (begin, end) = m.func_of(m.sym("client_GetDevicePeriod"));
    // mov edx, 0x186A0 ; cmp rax, rdx ; cmovl rax, rdx
    assert!(
        m.contains(begin, end, &[&[0xBAu8][..], &(audio::DEFAULT_PERIOD as u32).to_le_bytes()[..]].concat()),
        "the floor is {} in 100 ns units (10 ms)",
        audio::DEFAULT_PERIOD
    );
    const { assert!(audio::MIN_PERIOD < audio::DEFAULT_PERIOD) };
}
