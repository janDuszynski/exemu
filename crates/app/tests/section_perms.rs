//! A PE section is mapped with the permissions its own
//! `IMAGE_SECTION_HEADER.Characteristics` asks for — not `RWX` (roadmap W9.5).
//!
//! exemu used to map every section (and the header page) read/write/execute on
//! the theory that running arbitrary binaries mattered more than reproducing
//! DEP. The measurement that retired that theory is in this file's sibling
//! assertions: the two self-modifying guests in the corpus — the UPX-packed
//! Firefox stub, which decompresses over its own image and jumps into it —
//! **mark their own sections `MEM_WRITE|MEM_EXECUTE`**, so an honest mapping
//! hands them exactly the `RWX` they asked for, while an ordinary MSVC image
//! stops being a `W^X` hole.
//!
//! The one deliberate departure, pinned here so it stays visible rather than
//! becoming folklore: the section carrying the **import address table** is
//! mapped writable even when the linker marked it read-only, because on the
//! Wine path the code that binds imports is *guest* code and exemu's
//! `NtProtectVirtualMemory` is nominal — it records the requested `PAGE_*` for
//! `VirtualQuery` and never changes a real permission.

use exemu_app::{sample, Process, RunConfig};
use exemu_core::Perm;

fn silent_cfg() -> RunConfig {
    RunConfig { echo: false, trace: false, ..RunConfig::default() }
}

/// The permission of the region containing `addr`, or `None` if `addr` is in a
/// free gap. `Memory::next_region` returns the first region whose end is above
/// `addr`, so a base at or below `addr` means it is the containing one.
fn perm_at(proc: &Process, addr: u64) -> Option<Perm> {
    match proc.memory().next_region(addr) {
        Some((base, _, perm)) if base <= addr => Some(perm),
        _ => None,
    }
}

fn perm_of(proc: &Process, addr: u64, what: &str) -> Perm {
    perm_at(proc, addr).unwrap_or_else(|| panic!("{what} at {addr:#x} is not mapped"))
}

#[test]
fn a_code_section_is_not_writable_and_a_data_section_is_not_executable() {
    // `build_with_tls` is the three-section fixture: `.text` CODE|EXECUTE|READ,
    // `.rdata` INITIALIZED_DATA|READ, `.data` INITIALIZED_DATA|READ|WRITE.
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).expect("fixture parses");
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let base = image.image_base;

    let text = image.sections.iter().find(|s| s.name == ".text").expect(".text");
    let data = image.sections.iter().find(|s| s.name == ".data").expect(".data");
    assert!(text.executable && !text.writable, "fixture .text must be r-x on disk");
    assert!(data.writable && !data.executable, "fixture .data must be rw- on disk");

    let text_perm = perm_of(&proc, base + text.rva as u64, ".text");
    assert!(text_perm.contains(Perm::EXEC), ".text must stay executable");
    assert!(text_perm.contains(Perm::READ), ".text must stay readable");
    assert!(!text_perm.contains(Perm::WRITE), ".text must NOT be writable (W^X)");

    let data_perm = perm_of(&proc, base + data.rva as u64, ".data");
    assert!(data_perm.contains(Perm::READ) && data_perm.contains(Perm::WRITE));
    assert!(!data_perm.contains(Perm::EXEC), ".data must NOT be executable (DEP)");
}

#[test]
fn the_header_page_is_writable_but_not_executable() {
    // Writable because packers reconstruct headers/import tables in place at
    // the image base; never executable, because no section covers
    // `SizeOfHeaders`, so nothing a linker emitted can be fetched from there.
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).expect("fixture parses");
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let perm = perm_of(&proc, image.image_base, "headers");
    assert!(perm.contains(Perm::READ) && perm.contains(Perm::WRITE));
    assert!(!perm.contains(Perm::EXEC), "the PE header page must not be executable");
}

#[test]
fn the_section_carrying_the_iat_stays_writable() {
    // The documented carve-out. The fixture's IAT lives in `.rdata`, which the
    // linker marked read-only; a guest loader binding those slots must be able
    // to store into them, and `NtProtectVirtualMemory` cannot yet grant that.
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).expect("fixture parses");
    let iat_rva = image.imports.first().expect("fixture imports something").iat_rva;
    let owner = image
        .sections
        .iter()
        .find(|s| iat_rva >= s.rva && iat_rva < s.rva + s.virtual_size.max(1))
        .expect("some section owns the IAT");
    assert!(!owner.writable, "the fixture's IAT section must be read-only on disk");

    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let perm = perm_of(&proc, image.image_base + iat_rva as u64, "the IAT section");
    assert!(perm.contains(Perm::WRITE), "the IAT section must be mapped writable");
    assert!(!perm.contains(Perm::EXEC), "…but not executable");
}

/// The corpus's self-modifying guest, and the reason an honest mapping does not
/// break it: UPX marks its own sections writable *and* executable, so mapping
/// from the characteristics hands the stub exactly the pages it asked for.
///
/// Skip-guarded on the git-ignored corpus, like every other test that needs a
/// real third-party binary.
#[test]
fn a_upx_packed_guest_still_gets_rwx_because_it_asked_for_it() {
    let path = std::path::Path::new("../../example_exe/Firefox Installer.exe");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let image = exemu_loader::parse(&bytes).expect("UPX image parses");
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let mut checked = 0;
    for s in image.sections.iter().filter(|s| s.name.starts_with("UPX")) {
        assert!(s.writable && s.executable, "{} should be rwx on disk", s.name);
        let perm = perm_of(&proc, image.image_base + s.rva as u64, &s.name);
        assert_eq!(perm, Perm::RWX, "{} must stay RWX", s.name);
        checked += 1;
    }
    assert!(checked >= 2, "expected the UPX0/UPX1 pair, saw {checked}");
}

/// A real MSVC image: everything that is not code stops being executable, and
/// the read-only sections that do **not** carry the IAT stay read-only.
#[test]
fn a_real_msvc_image_maps_pdata_and_rsrc_read_only() {
    let path = std::path::Path::new("../../example_exe/7z2602-x64.exe");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let image = exemu_loader::parse(&bytes).expect("7-Zip parses");
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let base = image.image_base;
    for name in [".pdata", ".rsrc"] {
        let s = image.sections.iter().find(|s| s.name == name).expect(name);
        let perm = perm_of(&proc, base + s.rva as u64, name);
        assert_eq!(perm, Perm::READ, "{name} must be mapped read-only");
    }
    let text = image.sections.iter().find(|s| s.name == ".text").expect(".text");
    assert_eq!(perm_of(&proc, base + text.rva as u64, ".text"), Perm::RX);
}
