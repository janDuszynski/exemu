use std::path::Path;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    Path::new(WINE_DLLS).join("ntdll.dll").exists()
        && Path::new(WINE_DLLS).join("msvcrt.dll").exists()
}

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

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

fn ntdll() -> Vec<u8> {
    std::fs::read(Path::new(WINE_DLLS).join("ntdll.dll")).expect("read the pinned ntdll")
}

#[test]
fn rtl_init_code_page_table_dictates_the_section_layout() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlInitCodePageTable", 0x120)
        .expect("ntdll exports RtlInitCodePageTable as code");

    let cp_field = find(&code, &[0x0F, 0xB7, 0x51, 0x02]).expect("CodePage read from +0x02");
    let utf8_cmp = find(&code, &[0x66, 0x81, 0xFA, 0xE9, 0xFD]).expect("compared with 0xFDE9");
    assert!(cp_field < utf8_cmp, "the field is read before it is compared");

    assert!(contains(&code, &[0x44, 0x0F, 0xB7, 0x01]), "HeaderSize read from +0x00");
    assert!(contains(&code, &[0x48, 0x8D, 0x14, 0x51]), "body = ptr + 2 * HeaderSize");

    for (src, dst) in [(0x04u8, 0x02u8), (0x06, 0x04), (0x08, 0x06), (0x0a, 0x08), (0x0c, 0x0a)] {
        assert!(contains(&code, &[0x0F, 0xB7, 0x51, src]), "header WORD read from +{src:#04x}");
        assert!(contains(&code, &[0x66, 0x89, 0x50, dst]), "…stored at CPTABLEINFO+{dst:#04x}");
    }
    assert!(contains(&code, &[0x48, 0x8B, 0x51, 0x0E]), "LeadByte[12] starts at +0x0e");
    assert!(contains(&code, &[0x8B, 0x51, 0x16]), "…and runs to +0x1a (0x0d WORDs)");

    assert!(contains(&code, &[0x48, 0x8D, 0x4C, 0x09, 0x02]), "WideCharTable = body+2+2*W");
    assert!(contains(&code, &[0x0F, 0x11, 0x40, 0x20]), "…stored as the pair at +0x20/+0x28");

    assert!(contains(&code, &[0x66, 0x83, 0xBA, 0x02, 0x02, 0x00, 0x00, 0x00]), "glyph flag @+0x202");
    assert!(contains(&code, &[0x48, 0x8D, 0x8A, 0x04, 0x02, 0x00, 0x00]), "no glyphs → +0x204");
    assert!(contains(&code, &[0x48, 0x8D, 0x8A, 0x04, 0x04, 0x00, 0x00]), "glyphs → +0x404");
    assert!(contains(&code, &[0x48, 0x89, 0x48, 0x30]), "DBCSRanges stored at +0x30");
    assert!(contains(&code, &[0x66, 0x83, 0x39, 0x00]), "first range word tested");
    assert!(contains(&code, &[0x66, 0x44, 0x89, 0x40, 0x0C]), "…and sets DBCSCodePage at +0x0c");
}

#[test]
fn unicode_to_custom_cp_indexes_a_flat_byte_wide_char_table() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlUnicodeToCustomCPN", 0xa0)
        .expect("ntdll exports RtlUnicodeToCustomCPN as code");

    assert!(contains(&code, &[0x48, 0x8B, 0x71, 0x28]), "WideCharTable from CPTABLEINFO+0x28");
    let dbcs = find(&code, &[0x66, 0x83, 0x79, 0x0C, 0x00]).expect("DBCSCodePage tested at +0x0c");

    let sbcs = find(&code, &[0x0F, 0xB6, 0x0C, 0x0E]).expect("SBCS arm: byte[WideCharTable + wc]");
    assert!(dbcs < sbcs, "the DBCS test selects the arm");
    assert!(contains(&code, &[0x0F, 0xB7, 0x0C, 0x4E]), "DBCS arm: word[WideCharTable + wc*2]");
}

#[test]
fn custom_cp_to_unicode_indexes_a_256_word_multi_byte_table() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let code = export_bytes(&ntdll(), "RtlCustomCPToUnicodeN", 0xf0)
        .expect("ntdll exports RtlCustomCPToUnicodeN as code");

    assert!(contains(&code, &[0x48, 0x8B, 0x5E, 0x38]), "DBCSOffsets from CPTABLEINFO+0x38");
    assert!(contains(&code, &[0x48, 0x85, 0xDB]), "…tested for NULL");
    assert!(contains(&code, &[0x4C, 0x8B, 0x56, 0x20]), "MultiByteTable from CPTABLEINFO+0x20");
    assert!(contains(&code, &[0x47, 0x0F, 0xB7, 0x14, 0x5A]), "word[MultiByteTable + b*2]");
}

#[test]
fn msvcrt_names_codepage_20127_for_its_default_single_byte_locale() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("msvcrt.dll")).expect("read msvcrt");
    let image = exemu_loader::parse(&bytes).expect("msvcrt parses as a PE");

    let text = image
        .sections
        .iter()
        .find(|s| s.name.starts_with(".text"))
        .expect("msvcrt has a .text section");
    let imm = 20127u32.to_le_bytes();
    let loads = [0xBFu8, 0xBE, 0xB8, 0xBB, 0xB9, 0xBA]
        .iter()
        .filter(|op| {
            let mut pat = vec![**op];
            pat.extend_from_slice(&imm);
            contains(&text.data, &pat)
        })
        .count();
    assert!(loads >= 1, "msvcrt loads the immediate 20127 (0x4e9f) in its own code");

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
