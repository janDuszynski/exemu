use exemu_loader::parse;

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn build_pe32() -> Vec<u8> {
    const IMAGE_BASE: u32 = 0x0040_0000;
    const ENTRY_RVA: u32 = 0x1000;
    const TEXT_RVA: u32 = 0x1000;
    const TEXT_RAW: u32 = 0x200;
    const OPT_SIZE: usize = 96 + 16 * 8;

    let coff = 0x40 + 4;
    let opt = coff + 20;
    let sec_table = opt + OPT_SIZE;
    let file_len = (TEXT_RAW + 0x200) as usize;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, 0x40);
    put_u32(&mut f, 0x40, 0x0000_4550);

    put_u16(&mut f, coff, 0x014C);
    put_u16(&mut f, coff + 2, 1);
    put_u16(&mut f, coff + 16, OPT_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0102);

    put_u16(&mut f, opt, 0x010B);
    put_u32(&mut f, opt + 16, ENTRY_RVA);
    put_u32(&mut f, opt + 28, IMAGE_BASE);
    put_u32(&mut f, opt + 32, 0x1000);
    put_u32(&mut f, opt + 36, 0x200);
    put_u32(&mut f, opt + 56, 0x2000);
    put_u32(&mut f, opt + 60, 0x200);
    put_u16(&mut f, opt + 68, 3);
    put_u32(&mut f, opt + 72, 0x10_0000);
    put_u32(&mut f, opt + 92, 16);

    f[sec_table..sec_table + 5].copy_from_slice(b".text");
    put_u32(&mut f, sec_table + 8, 0x10);
    put_u32(&mut f, sec_table + 12, TEXT_RVA);
    put_u32(&mut f, sec_table + 16, 0x200);
    put_u32(&mut f, sec_table + 20, TEXT_RAW);
    put_u32(&mut f, sec_table + 36, 0x6000_0020);
    f[TEXT_RAW as usize] = 0xC3;

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
