//! W6.4 — **Wine's debug-channel mechanism, re-derived from the pinned
//! binaries.**
//!
//! Everything `exemu_os::winedebug` knows about how a Wine builtin decides
//! whether a `TRACE()` prints is a number read out of a binary: two
//! PEB-relative offsets that are *different for the two bitnesses*, a 16-byte
//! record layout, a sentinel bit, a class bit order, and a default flags byte.
//! None of it is documented anywhere except the `wine(1)` description of
//! `WINEDEBUG`'s syntax. This test recovers each of them from
//! `example_exe/wine-dlls/{x86_64,i386}-windows/{ntdll,user32}.dll` on **every
//! run** and asserts it against the constants the boot really uses.
//!
//! It exists because getting any of them wrong is silent. A wrong PEB offset
//! makes ntdll resolve every channel out of whatever memory happens to be
//! there — which is exactly the bug this test was written for: the WoW64
//! layout used to put the CPU-reserved area at `PEB32 + 0x1000`, so the 32-bit
//! builtins read their channel flags out of the live 32-bit register save area.
//! Nothing crashes; the process merely logs, or does not, at random.
//!
//! What it establishes, all from the bytes:
//!
//! 1. `ntdll!__wine_dbg_get_channel_flags` opens with a **sign test** on the
//!    channel's first byte — which is what makes `0x80` the "unresolved"
//!    sentinel rather than a fifth class.
//! 2. Its slow half reads the option array at **`PEB + 0x2000`** in the 64-bit
//!    build and **`PEB + 0x1000`** in the 32-bit one, and indexes it with a
//!    `shl 4` — the 16-byte record.
//! 3. A shipped channel object really is `{ 0xff, "name" }`: every
//!    `__wine_dbch_*` in user32's data starts with the sentinel.
//! 4. The class bit order is `fixme, err, warn, trace`, and the default with no
//!    `WINEDEBUG` set is `err+fixme` — both read out of the *fallback* resolver
//!    every builtin carries for the case where ntdll's export is unreachable.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::BTreeMap;

use exemu_os::winedebug;

const WINE64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE32: &str = "../../example_exe/wine-dlls/i386-windows";

fn present() -> bool {
    [
        std::path::Path::new(WINE64).join("ntdll.dll"),
        std::path::Path::new(WINE64).join("user32.dll"),
        std::path::Path::new(WINE32).join("ntdll.dll"),
        std::path::Path::new(WINE32).join("user32.dll"),
    ]
    .iter()
    .all(|p| p.exists())
}

// ---------------------------------------------------------------------------
// A pinned DLL, with the two views this file needs: bytes at an RVA (the
// channel records live in `.data`, not `.text`) and the COFF symbol table (the
// routines involved are internal, not exported).
// ---------------------------------------------------------------------------

struct Dll {
    name: String,
    image: exemu_core::PeImage,
    symbols: BTreeMap<String, u32>,
}

impl Dll {
    fn load(dir: &str, name: &str) -> Dll {
        let path = std::path::Path::new(dir).join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let image = exemu_loader::parse(&bytes).unwrap_or_else(|e| panic!("{name} parses: {e}"));
        Dll { name: format!("{name} ({dir})"), symbols: coff_symbols(&bytes), image }
    }

    /// Bytes of `[rva, rva+len)` from whichever section covers them.
    fn at(&self, rva: u32, len: usize) -> &[u8] {
        for s in &self.image.sections {
            let end = s.rva + s.data.len() as u32;
            if rva >= s.rva && rva + len as u32 <= end {
                let off = (rva - s.rva) as usize;
                return &s.data[off..off + len];
            }
        }
        panic!("{}: no section covers {rva:#x}..+{len:#x}", self.name)
    }

    fn export(&self, sym: &str) -> u32 {
        self.image
            .exports
            .iter()
            .find(|e| e.name.as_deref() == Some(sym) && e.forwarder.is_none())
            .unwrap_or_else(|| panic!("{} exports {sym}", self.name))
            .rva
    }

    /// A COFF symbol by name. The i386 build decorates cdecl symbols with a
    /// leading underscore the x86-64 one does not, so both spellings are tried.
    fn symbol(&self, sym: &str) -> u32 {
        self.symbols
            .get(sym)
            .or_else(|| self.symbols.get(&format!("_{sym}")))
            .copied()
            .unwrap_or_else(|| panic!("{} has a COFF symbol for {sym}", self.name))
    }
}

/// The COFF symbol table the pinned (MinGW-built) DLLs ship — the only route to
/// an internal routine like `fallback__wine_dbg_get_channel_flags` or a data
/// object like `__wine_dbch_win`. Returns name → RVA.
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

/// Bytes to scan for a routine that carries no `.pdata` bound (the i386 build
/// has none at all). Comfortably longer than any routine read here.
const SCAN: usize = 0x400;

/// Every `lea <reg>, [<reg>+disp32]` in `code` — the addressing form both
/// `ntdll`s use to turn the PEB into the option array. `mod=10` with `rm != 4`
/// (no SIB byte) is what separates it from the `[base+index+disp]` forms in the
/// same function.
fn lea_disp32(code: &[u8], long_mode: bool) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 7 <= code.len() {
        let mut j = i;
        if long_mode && code[j] & 0xF0 == 0x40 {
            j += 1; // REX
        } else if long_mode {
            i += 1;
            continue;
        }
        if code.get(j) != Some(&0x8D) || j + 6 > code.len() {
            i += 1;
            continue;
        }
        let modrm = code[j + 1];
        if modrm >> 6 == 2 && modrm & 7 != 4 {
            out.push(u32::from_le_bytes(code[j + 2..j + 6].try_into().unwrap()));
        }
        i += 1;
    }
    out
}

/// **The sentinel, and the two PEB offsets.**
///
/// `__wine_dbg_get_channel_flags(channel)` opens `movzbl (chan),eax; test al,al;
/// jns <return>` — the *sign* of the flags byte is what says "not resolved
/// yet", which is what makes `0x80` [`winedebug::UNRESOLVED`] rather than a
/// fifth class. Everything past the `jns` is the slow half, and that is where
/// the option array's address is computed off the PEB — at a **different offset
/// in each build**, which is the whole reason this test exists.
#[test]
fn the_option_array_offsets_come_from_each_ntdll() {
    if !present() {
        eprintln!("SKIP: {WINE64} / {WINE32} not present (Wine DLL set is git-ignored)");
        return;
    }
    for (dir, long_mode, expected) in [
        (WINE64, true, winedebug::OPTIONS_OFF_64),
        (WINE32, false, winedebug::OPTIONS_OFF_32),
    ] {
        let ntdll = Dll::load(dir, "ntdll.dll");
        let entry = ntdll.export("__wine_dbg_get_channel_flags");
        // `movzbl (chan), <r32>` (0F B6 /r) then `test al,al` (84 C0) then a
        // `jns` — the fast path, in whichever registers the build chose. The
        // 32-bit build reaches the channel through its frame pointer first, so
        // the sequence is looked for in a window rather than at the entry.
        let head = ntdll.at(entry, 32);
        let seq = head
            .windows(6)
            .position(|w| w[0] == 0x0F && w[1] == 0xB6 && w[3] == 0x84 && w[4] == 0xC0 && w[5] == 0x79)
            .unwrap_or_else(|| {
                panic!("{}: the fast path is a sign test on the flags byte", ntdll.name)
            });
        assert!(seq < 16, "{}: …and it is the first thing the routine does", ntdll.name);
        assert_eq!(
            winedebug::UNRESOLVED, 0x80,
            "a `jns` on the flags byte makes bit 7, and only bit 7, the sentinel"
        );

        // The slow half is the routine the `jns` falls through to. It is a
        // separate `.part.0` function reached by a near jump; take the whole
        // window from the export and let the scan find the `lea`.
        let body = ntdll.at(entry, SCAN);
        let leas = lea_disp32(body, long_mode);
        assert!(
            leas.contains(&(expected as u32)),
            "{}: the option array is at PEB+{:#x}, exemu maps PEB+{expected:#x} (found {:#x?})",
            ntdll.name,
            leas.first().copied().unwrap_or(0),
            leas
        );
        // The record stride: the index is scaled by `shl 4`.
        let shl4 = if long_mode { &[0x48u8, 0xC1, 0xE2, 0x04][..] } else { &[0xC1, 0xE2, 0x04][..] };
        assert!(
            body.windows(shl4.len()).any(|w| w == shl4),
            "{}: the array is indexed with a shift-by-4, i.e. a 16-byte record",
            ntdll.name
        );
        assert_eq!(winedebug::OPTION_SIZE, 16);
    }

    assert_ne!(
        winedebug::OPTIONS_OFF_32, winedebug::OPTIONS_OFF_64,
        "the two builds disagree on this offset — mirroring one onto the other is the bug"
    );
}

/// **A channel ships unresolved.** Every `__wine_dbch_*` object in user32's data
/// is `{ 0xff, "<name>" }` — 16 bytes, flags first, a NUL-terminated name in the
/// remaining 15. So the "channels are off unless switched on" reading of these
/// binaries is wrong: until something resolves the byte, every class reads on.
#[test]
fn a_shipped_channel_carries_the_unresolved_sentinel() {
    if !present() {
        eprintln!("SKIP: {WINE64} / {WINE32} not present (Wine DLL set is git-ignored)");
        return;
    }
    for dir in [WINE64, WINE32] {
        let user32 = Dll::load(dir, "user32.dll");
        let channels: Vec<(String, u32)> = user32
            .symbols
            .iter()
            .filter(|(n, _)| n.trim_start_matches('_').starts_with("wine_dbch_"))
            .map(|(n, r)| (n.trim_start_matches('_').to_string(), *r))
            .collect();
        assert!(channels.len() > 10, "{}: found {} channels", user32.name, channels.len());
        for (sym, rva) in &channels {
            let rec = user32.at(*rva, winedebug::OPTION_SIZE as usize);
            assert_eq!(
                rec[0], 0xff,
                "{}: {sym} ships flags {:#04x}, not the unresolved sentinel",
                user32.name, rec[0]
            );
            let name_end = rec[1..].iter().position(|b| *b == 0).unwrap_or(15);
            let name = std::str::from_utf8(&rec[1..1 + name_end]).expect("an ASCII channel name");
            assert_eq!(
                format!("wine_dbch_{name}"),
                *sym,
                "{}: the record's name is the symbol's suffix",
                user32.name
            );
            assert!(
                name.len() <= winedebug::OPTION_NAME_MAX,
                "{}: {name} needs {} bytes, the record holds {}",
                user32.name,
                name.len(),
                winedebug::OPTION_NAME_MAX
            );
        }
    }
}

/// **The class bit order, and the default with no `WINEDEBUG`.**
///
/// Both are read out of `fallback__wine_dbg_get_channel_flags` — the resolver
/// every builtin carries for the case where ntdll's export cannot be found. It
/// matches the spec against a table of class names (`mov <table>(,%edi,4),%eax`)
/// and, when nothing matches, answers a `default_flags` byte
/// (`movzbl <default>,%eax`). Both operands are absolute 32-bit addresses in the
/// i386 build, so both are readable straight out of the image.
#[test]
fn the_class_order_and_the_default_come_from_the_builtins_own_parser() {
    if !present() {
        eprintln!("SKIP: {WINE64} / {WINE32} not present (Wine DLL set is git-ignored)");
        return;
    }
    let user32 = Dll::load(WINE32, "user32.dll");
    let base = user32.image.image_base as u32;
    let body = user32.at(user32.symbol("fallback__wine_dbg_get_channel_flags"), SCAN);

    // `mov <abs32>(,%edi,4), %eax` — 8B 04 BD <abs32>: the class-name table.
    let table = body
        .windows(7)
        .find(|w| w[..3] == [0x8B, 0x04, 0xBD])
        .map(|w| u32::from_le_bytes(w[3..7].try_into().unwrap()))
        .expect("the parser indexes a class-name table");
    let names: Vec<String> = (0..winedebug::CLASSES.len())
        .map(|i| {
            let p = u32::from_le_bytes(user32.at(table - base + 4 * i as u32, 4).try_into().unwrap());
            let raw = user32.at(p - base, 16);
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).into_owned()
        })
        .collect();
    assert_eq!(
        names,
        winedebug::CLASSES,
        "the class bit order is the table's order — bit N is CLASSES[N]"
    );

    // `movzbl <abs32>, %eax` — 0F B6 05 <abs32>: the default-flags byte.
    let default_at = body
        .windows(7)
        .find(|w| w[..3] == [0x0F, 0xB6, 0x05])
        .map(|w| u32::from_le_bytes(w[3..7].try_into().unwrap()))
        .expect("the parser falls back to a default-flags byte");
    let shipped = user32.at(default_at - base, 1)[0];
    assert_eq!(
        shipped,
        winedebug::DEFAULT_FLAGS,
        "the pinned build's default is {shipped:#04x} (err+fixme), exemu boots with {:#04x}",
        winedebug::DEFAULT_FLAGS
    );
    assert_eq!(shipped & (1 << 3), 0, "trace is OFF in a default Wine process");
    assert_eq!(shipped & (1 << 2), 0, "warn is OFF in a default Wine process");
    assert_ne!(shipped & (1 << 1), 0, "err is ON in a default Wine process");
    assert_ne!(shipped & 1, 0, "fixme is ON in a default Wine process");
}

/// **The per-thread string ring, likewise per bitness.** `__wine_dbg_strdup`
/// keeps its ring at a fixed TEB offset — `+0x3000` in the 64-bit build,
/// `+0x1000` in the 32-bit one — and both bound it to `0x3fc`, which is the
/// number the layout has to leave room for.
#[test]
fn the_debug_string_ring_offsets_come_from_each_ntdll() {
    if !present() {
        eprintln!("SKIP: {WINE64} / {WINE32} not present (Wine DLL set is git-ignored)");
        return;
    }
    for (dir, off) in
        [(WINE64, winedebug::STRDUP_RING_OFF_64), (WINE32, winedebug::STRDUP_RING_OFF_32)]
    {
        let ntdll = Dll::load(dir, "ntdll.dll");
        let body = ntdll.at(ntdll.export("__wine_dbg_strdup"), SCAN);
        // The ring position is read at `[teb + off]` and the bytes start 8
        // further on; both appear as plain 32-bit displacements in the body.
        let has = |v: u32| body.windows(4).any(|w| u32::from_le_bytes(w.try_into().unwrap()) == v);
        assert!(has(off as u32), "{}: the ring position is at TEB+{off:#x}", ntdll.name);
        assert!(has(off as u32 + 8), "{}: the ring bytes start at TEB+{:#x}", ntdll.name, off + 8);
        assert!(has(0x3fc), "{}: the ring is bounded to 0x3fc", ntdll.name);
        assert_eq!(winedebug::STRDUP_RING_SIZE, 8 + 0x3fc);
    }
}

/// **The `wine_dbg_write` params block ends in a 32-bit length**, and reading it
/// as a qword is a live bug: both pinned callers fill the block with a `movq`
/// for the string pointer and a `movl` for the length, and neither writes the
/// slot's upper half — it keeps whatever the frame's uninitialised stack held.
///
/// `ntdll!__wine_dbg_write` (the ABI's own producer) is
/// `movq %rcx,0x20(%rsp)` / `movl %edx,0x28(%rsp)` / `lea r8,[rsp+0x20]`, and
/// `__wine_dbg_output` builds the same block the same way. exemu's unixlib
/// entry 2 has to read the length narrow or a stale upper half sends it walking
/// off the mapped page — which is exactly what happened the moment the debug
/// channels started emitting.
#[test]
fn the_debug_write_params_block_carries_a_dword_length() {
    if !present() {
        eprintln!("SKIP: {WINE64} not present (Wine DLL set is git-ignored)");
        return;
    }
    let ntdll = Dll::load(WINE64, "ntdll.dll");
    let body = ntdll.at(ntdll.export("__wine_dbg_write"), 0x40);
    // `movq <r64>, 0x20(%rsp)` — REX.W 89 /r, modrm mod=01 rm=100 (SIB), disp8.
    assert!(
        body.windows(5).any(|w| w[0] & 0xF8 == 0x48
            && w[1] == 0x89
            && w[2] & 0xC7 == 0x44
            && w[3] == 0x24
            && w[4] == 0x20),
        "the string pointer goes into the block as a qword at +0x00"
    );
    // `movl <r32>, 0x28(%rsp)` — **no REX.W**: the length field is 4 bytes.
    let movl = body
        .windows(4)
        .position(|w| w[0] == 0x89 && w[1] & 0xC7 == 0x44 && w[2] == 0x24 && w[3] == 0x28)
        .expect("the length goes into the block at +0x08");
    assert!(
        movl == 0 || body[movl - 1] & 0xF8 != 0x48,
        "the length store carries a REX.W — it would be a qword after all"
    );
    // …and nothing initialises the slot's upper half.
    assert!(
        !body
            .windows(4)
            .any(|w| w[0] == 0xC7 && w[1] & 0xC7 == 0x44 && w[2] == 0x24 && w[3] == 0x2C),
        "the upper half of the length slot is written after all"
    );
}
