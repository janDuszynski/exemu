//! 32-bit PE (PE32, `IMAGE_FILE_MACHINE_I386`) parsing — the loader half of the
//! WoW64 path (roadmap W5). A 32-bit guest image reads its image base, entry, and
//! stack from *different* optional-header offsets than a PE32+ image (base@28 vs
//! @24, dirs@92/96 vs @108/112); this pins those so the loader keeps handling the
//! majority-32-bit corpus (SteamSetup, Firefox, tcc) that WoW64 runs.

use exemu_loader::parse;

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Assemble a minimal but valid PE32 (32-bit) image: MZ + PE headers, a PE32
/// optional header (magic 0x10B), and one `.text` section.
fn build_pe32() -> Vec<u8> {
    const IMAGE_BASE: u32 = 0x0040_0000;
    const ENTRY_RVA: u32 = 0x1000;
    const TEXT_RVA: u32 = 0x1000;
    const TEXT_RAW: u32 = 0x200; // file offset of section data
    const OPT_SIZE: usize = 96 + 16 * 8; // standard PE32 optional header

    let coff = 0x40 + 4; // e_lfanew=0x40, then "PE\0\0"
    let opt = coff + 20;
    let sec_table = opt + OPT_SIZE;
    let file_len = (TEXT_RAW + 0x200) as usize;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, 0x40); // e_lfanew
    put_u32(&mut f, 0x40, 0x0000_4550); // "PE\0\0"

    // COFF header.
    put_u16(&mut f, coff, 0x014C); // Machine = i386
    put_u16(&mut f, coff + 2, 1); // NumberOfSections
    put_u16(&mut f, coff + 16, OPT_SIZE as u16); // SizeOfOptionalHeader
    put_u16(&mut f, coff + 18, 0x0102); // Characteristics: EXECUTABLE | 32BIT_MACHINE

    // Optional header (PE32).
    put_u16(&mut f, opt, 0x010B); // Magic = PE32
    put_u32(&mut f, opt + 16, ENTRY_RVA); // AddressOfEntryPoint
    put_u32(&mut f, opt + 28, IMAGE_BASE); // ImageBase (PE32: @28, not @24)
    put_u32(&mut f, opt + 32, 0x1000); // SectionAlignment
    put_u32(&mut f, opt + 36, 0x200); // FileAlignment
    put_u32(&mut f, opt + 56, 0x2000); // SizeOfImage
    put_u32(&mut f, opt + 60, 0x200); // SizeOfHeaders
    put_u16(&mut f, opt + 68, 3); // Subsystem = CONSOLE
    put_u32(&mut f, opt + 72, 0x10_0000); // SizeOfStackReserve (PE32: @72)
    put_u32(&mut f, opt + 92, 16); // NumberOfRvaAndSizes (PE32: @92)

    // One .text section: a 3-byte body (mov eax, 0 / ret would do; content is
    // irrelevant to parsing, only the mapping is).
    f[sec_table..sec_table + 5].copy_from_slice(b".text");
    put_u32(&mut f, sec_table + 8, 0x10); // VirtualSize
    put_u32(&mut f, sec_table + 12, TEXT_RVA); // VirtualAddress
    put_u32(&mut f, sec_table + 16, 0x200); // SizeOfRawData
    put_u32(&mut f, sec_table + 20, TEXT_RAW); // PointerToRawData
    put_u32(&mut f, sec_table + 36, 0x6000_0020); // CODE | EXECUTE | READ
    f[TEXT_RAW as usize] = 0xC3; // ret

    f
}

#[test]
fn parses_a_32bit_pe32_image() {
    let bytes = build_pe32();
    let image = parse(&bytes).expect("a valid PE32 image parses");

    assert!(!image.is_64bit, "PE32 magic 0x10B is a 32-bit image");
    assert_eq!(image.image_base, 0x0040_0000, "32-bit image base read from opt+28");
    assert_eq!(image.entry_rva, 0x1000, "entry point RVA");
    assert_eq!(image.stack_reserve, 0x10_0000, "stack reserve read from opt+72 (PE32 layout)");
    assert_eq!(image.subsystem, 3, "console subsystem");
    assert_eq!(image.sections.len(), 1, "one section");
    assert_eq!(image.sections[0].rva, 0x1000, ".text mapped at its RVA");
    assert_eq!(image.sections[0].data.first().copied(), Some(0xC3), ".text body loaded");
}

#[test]
fn rejects_a_non_pe_blob() {
    assert!(parse(b"not a PE at all, just some bytes here padding padding").is_err());
}
