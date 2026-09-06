//! The NLS **codepage-section ABI**, re-derived from the pinned Wine binaries
//! on every run (roadmap W6.x / W3.2).
//!
//! `crates/os/src/nls.rs` synthesizes a codepage table — a `C_#####.nls` image —
//! for the guest, because the pinned `wine-stable-amd64` prefix ships the
//! binaries but not the arch-independent `.nls` data files. Every offset in that
//! synthesized image is dictated by three functions in the pinned `ntdll.dll`
//! which parse and index it. If a Wine refresh changed any of them, the
//! synthesized table would go silently wrong — text would convert to the wrong
//! bytes rather than fail — so the constants `nls.rs` builds against are
//! recovered here from the binaries themselves and asserted, in the style of
//! `crates/app/tests/win32k_abi.rs`.
//!
//! What is pinned:
//!
//! * `RtlInitCodePageTable` — the header field offsets, the `CP_UTF8` short
//!   path, and the three body offsets (`+0x202` glyph flag, `+0x204` DBCS
//!   ranges, `+0x404` past a glyph table) that place the two tables.
//! * `RtlUnicodeToCustomCPN` — `WideCharTable` at `CPTABLEINFO+0x28`, selected
//!   by `DBCSCodePage` at `+0x0c`, and **byte**-indexed by the whole `WCHAR` on
//!   the single-byte arm.
//! * `RtlCustomCPToUnicodeN` — `MultiByteTable` at `CPTABLEINFO+0x20`, **word**-
//!   indexed by the byte.
//! * `msvcrt` — that 20127 is the codepage the C runtime names for its default
//!   single-byte locale, which is why it is the one codepage every Wine-booted
//!   guest asks for.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    Path::new(WINE_DLLS).join("ntdll.dll").exists()
        && Path::new(WINE_DLLS).join("msvcrt.dll").exists()
}

/// Bytes of the named export's code, up to `len`, or `None` if it is missing or
/// a forwarder.
fn export_bytes(bytes: &[u8], name: &str, len: usize) -> Option<Vec<u8>> {
    let image = exemu_loader::parse(bytes).ok()?;
    let rva = image
        .exports
        .iter()
        .find(|e| e.name.as_deref() == Some(name) && e.forwarder.is_none())?
        .rva;
    for s in &image.sections {
        let end = s.rva + s.data.len() as u32;
        if rva >= s.rva && rva < end {
            let off = (rva - s.rva) as usize;
            return Some(s.data[off..(off + len).min(s.data.len())].to_vec());
        }
    }
    None
}

/// Index of the first occurrence of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

fn ntdll() -> Vec<u8> {
    std::fs::read(Path::new(WINE_DLLS).join("ntdll.dll")).expect("read the pinned ntdll")
}

/// `RtlInitCodePageTable(USHORT *ptr, CPTABLEINFO *info)` decides the whole
/// section layout. Every constant `build_sbcs_codepage_nls` writes comes from
/// this function, so read them back out of it.
#[test]
fn rtl_init_code_page_table_dictates_the_section_layout() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlInitCodePageTable", 0x120)
        .expect("ntdll exports RtlInitCodePageTable as code");

    // --- the header ---
    // `movzwl 0x2(%rcx),%edx` then `cmpw $0xfde9,%dx`: the CodePage field is at
    // +0x02, and 65001 short-paths onto a built-in UTF-8 CPTABLEINFO without
    // another byte being read. That is the *only* reason a marker section works,
    // and why it can never stand in for a real codepage.
    let cp_field = find(&code, &[0x0F, 0xB7, 0x51, 0x02]).expect("CodePage read from +0x02");
    let utf8_cmp = find(&code, &[0x66, 0x81, 0xFA, 0xE9, 0xFD]).expect("compared with 0xFDE9");
    assert!(cp_field < utf8_cmp, "the field is read before it is compared");

    // `movzwl (%rcx),%r8d` then `leaq (%rcx,%rdx,2),%rdx`: HeaderSize is at
    // +0x00 and counts WORDs — the table body starts 2*HeaderSize bytes in.
    assert!(contains(&code, &[0x44, 0x0F, 0xB7, 0x01]), "HeaderSize read from +0x00");
    assert!(contains(&code, &[0x48, 0x8D, 0x14, 0x51]), "body = ptr + 2 * HeaderSize");

    // The remaining header fields, copied one WORD at a time into CPTABLEINFO:
    // MaximumCharacterSize +0x04, DefaultChar +0x06, UniDefaultChar +0x08,
    // TransDefaultChar +0x0a, TransUniDefaultChar +0x0c, then LeadByte[12] as a
    // qword at +0x0e and a dword at +0x16 — i.e. the header ends at +0x1a, which
    // is exactly 0x0d WORDs.
    for (src, dst) in [(0x04u8, 0x02u8), (0x06, 0x04), (0x08, 0x06), (0x0a, 0x08), (0x0c, 0x0a)] {
        assert!(contains(&code, &[0x0F, 0xB7, 0x51, src]), "header WORD read from +{src:#04x}");
        assert!(contains(&code, &[0x66, 0x89, 0x50, dst]), "…stored at CPTABLEINFO+{dst:#04x}");
    }
    assert!(contains(&code, &[0x48, 0x8B, 0x51, 0x0E]), "LeadByte[12] starts at +0x0e");
    assert!(contains(&code, &[0x8B, 0x51, 0x16]), "…and runs to +0x1a (0x0d WORDs)");

    // --- the body ---
    // `leaq 0x2(%rcx,%rcx),%rcx` with rcx = word[body]: WideCharTable is
    // body + 2 + 2*wc_offset, and MultiByteTable is body + 2 — both written to
    // CPTABLEINFO+0x20/+0x28 by one `movups %xmm0,0x20(%rax)`.
    assert!(contains(&code, &[0x48, 0x8D, 0x4C, 0x09, 0x02]), "WideCharTable = body+2+2*W");
    assert!(contains(&code, &[0x0F, 0x11, 0x40, 0x20]), "…stored as the pair at +0x20/+0x28");

    // `cmpw $0x0,0x202(%rdx)`: the WORD just past the 256-WORD MultiByteTable is
    // the glyph-table flag; zero → DBCS ranges at body+0x204, non-zero → a
    // 256-WORD glyph table intervenes and they sit at body+0x404.
    assert!(contains(&code, &[0x66, 0x83, 0xBA, 0x02, 0x02, 0x00, 0x00, 0x00]), "glyph flag @+0x202");
    assert!(contains(&code, &[0x48, 0x8D, 0x8A, 0x04, 0x02, 0x00, 0x00]), "no glyphs → +0x204");
    assert!(contains(&code, &[0x48, 0x8D, 0x8A, 0x04, 0x04, 0x00, 0x00]), "glyphs → +0x404");
    assert!(contains(&code, &[0x48, 0x89, 0x48, 0x30]), "DBCSRanges stored at +0x30");
    // A non-zero first range word is what makes DBCSCodePage (+0x0c) non-zero,
    // i.e. what a synthesized single-byte table must leave at zero.
    assert!(contains(&code, &[0x66, 0x83, 0x39, 0x00]), "first range word tested");
    assert!(contains(&code, &[0x66, 0x44, 0x89, 0x40, 0x0C]), "…and sets DBCSCodePage at +0x0c");
}

/// `RtlUnicodeToCustomCPN` — the wide→multibyte direction. Its single-byte arm
/// is what fixes the `WideCharTable` as a flat 64 KiB **byte** table.
#[test]
fn unicode_to_custom_cp_indexes_a_flat_byte_wide_char_table() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlUnicodeToCustomCPN", 0xa0)
        .expect("ntdll exports RtlUnicodeToCustomCPN as code");

    // `movq 0x28(%rcx),%rsi` — WideCharTable — and `cmpw $0x0,0xc(%rcx)`, the
    // DBCSCodePage test that picks the arm.
    assert!(contains(&code, &[0x48, 0x8B, 0x71, 0x28]), "WideCharTable from CPTABLEINFO+0x28");
    let dbcs = find(&code, &[0x66, 0x83, 0x79, 0x0C, 0x00]).expect("DBCSCodePage tested at +0x0c");

    // Single-byte arm: `movzwl (%rdx),%ecx` then `movzbl (%rsi,%rcx),%ecx` — one
    // BYTE per WCHAR, so the table is 0x10000 bytes and covers the whole BMP.
    let sbcs = find(&code, &[0x0F, 0xB6, 0x0C, 0x0E]).expect("SBCS arm: byte[WideCharTable + wc]");
    assert!(dbcs < sbcs, "the DBCS test selects the arm");
    // The DBCS arm reads the same table two bytes wide, which is what a stray
    // non-zero DBCS-ranges word would switch a synthesized SBCS table into.
    assert!(contains(&code, &[0x0F, 0xB7, 0x0C, 0x4E]), "DBCS arm: word[WideCharTable + wc*2]");
}

/// `RtlCustomCPToUnicodeN` — the multibyte→wide direction. Its single-byte arm
/// fixes `MultiByteTable` as 256 **WORD**s.
#[test]
fn custom_cp_to_unicode_indexes_a_256_word_multi_byte_table() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlCustomCPToUnicodeN", 0xf0)
        .expect("ntdll exports RtlCustomCPToUnicodeN as code");

    // `movq 0x38(%rsi),%rbx` — DBCSOffsets — is tested for NULL to pick the arm;
    // a synthesized SBCS table leaves it NULL by carrying no DBCS ranges.
    assert!(contains(&code, &[0x48, 0x8B, 0x5E, 0x38]), "DBCSOffsets from CPTABLEINFO+0x38");
    assert!(contains(&code, &[0x48, 0x85, 0xDB]), "…tested for NULL");
    // Single-byte arm: `movq 0x20(%rsi),%r10` then `movzwl (%r10,%r11,2),%r10d`.
    assert!(contains(&code, &[0x4C, 0x8B, 0x56, 0x20]), "MultiByteTable from CPTABLEINFO+0x20");
    assert!(contains(&code, &[0x47, 0x0F, 0xB7, 0x14, 0x5A]), "word[MultiByteTable + b*2]");
}

/// **Why 20127 is the codepage that matters.** The measured surface (an
/// `EXEMU_NLS_TRACE` over both WoW64 corpus boots) is one codepage section, id
/// 20127, requested six times — and this is where it comes from: `msvcrt` names
/// codepage 20127 for the C runtime's default single-byte locale, and converts
/// all 256 byte values through both directions to build its multibyte tables.
///
/// Pinning the constant here means the number `nls.rs` supports and the code
/// that asks for it are checked against each other, not against a memory of
/// `mbctype.h`.
#[test]
fn msvcrt_names_codepage_20127_for_its_default_single_byte_locale() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("msvcrt.dll")).expect("read msvcrt");
    let image = exemu_loader::parse(&bytes).expect("msvcrt parses as a PE");

    // `mov edi,0x4e9f` / `mov esi,0x4e9f` — 20127 loaded as an immediate in
    // msvcrt's own code (create_mbcinfo's `_MB_CP_SBCS` arm).
    let text = image
        .sections
        .iter()
        .find(|s| s.name.starts_with(".text"))
        .expect("msvcrt has a .text section");
    let imm = 20127u32.to_le_bytes();
    let loads = [0xBFu8, 0xBE, 0xB8, 0xBB, 0xB9, 0xBA] // mov edi/esi/eax/ebx/ecx/edx, imm32
        .iter()
        .filter(|op| {
            let mut pat = vec![**op];
            pat.extend_from_slice(&imm);
            contains(&text.data, &pat)
        })
        .count();
    assert!(loads >= 1, "msvcrt loads the immediate 20127 (0x4e9f) in its own code");

    // …and it converts through the two APIs whose failure the bug showed up in.
    let named: Vec<&str> = image
        .imports
        .iter()
        .map(|i| &i.symbol)
        .filter_map(|s| match s {
            exemu_core::ImportSymbol::Named(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    for api in ["MultiByteToWideChar", "WideCharToMultiByte", "GetCPInfo"] {
        assert!(named.contains(&api), "msvcrt imports {api}");
    }
}
