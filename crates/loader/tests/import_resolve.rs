//! End-to-end forwarder resolution pin (roadmap W0.4).
//!
//! The classic loader trap is *forwarder-as-RVA corruption*: an export whose
//! address RVA lands inside the export directory is not code but a
//! `"DLL.func"` string, and mistaking one for the other silently corrupts a
//! resolved import. This test builds the canonical minimal fixture —
//!
//!   * **a.dll** exports `f` as real code,
//!   * **b.dll** forwards `g → A.f` (its `g` export's RVA points at an ASCIIZ
//!     `"A.f"` inside b.dll's export directory),
//!   * an **exe** imports `b.dll!g`,
//!
//! — parses all three through the real [`exemu_loader::parse`], and drives the
//! real resolver end to end: importing `b.dll!g` must land on a.dll's actual
//! code address, proving the forwarder string was parsed (not treated as a
//! code RVA) and chased across modules.

use std::collections::HashMap;

use exemu_core::{Export, ImportSymbol};
use exemu_loader::{resolve_import, LoadedModule, ModuleSet, Resolved};

// ---- tiny byte helpers -----------------------------------------------------

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

const IMAGE_BASE: u64 = 0x1_8000_0000;
const PE_OFF: usize = 0x80;
const OPT_HDR_SIZE: usize = 112 + 16 * 8;
const SEC_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;

/// A named export: either real code at `rva` or a forwarder to `"DLL.sym"`.
enum ExportSpec {
    Code { name: &'static str, ordinal_bias: u32, rva_off: u32 },
    Forward { name: &'static str, ordinal_bias: u32, target: &'static str },
}

/// Build a minimal PE32+ DLL exporting the given symbols. The export directory
/// (and any forwarder strings, which live *inside* it) sit in a single
/// `.edata` section at RVA 0x1000. Ordinal base is 1; each spec's
/// `ordinal_bias` is its index-from-base.
fn build_dll(dll_name: &str, exports: &[ExportSpec]) -> Vec<u8> {
    const EDATA_RVA: u32 = 0x1000;

    // Plan the export directory's contents inside .edata.
    //   +0x00  IMAGE_EXPORT_DIRECTORY (40 bytes)
    //   then: EAT, name-pointer table, ordinal table, name strings,
    //         dll name, and forwarder strings (all inside the dir range).
    let n = exports.len() as u32;
    let dir_off = 0u32;
    let eat_off = dir_off + 40;
    let names_off = eat_off + n * 4;
    let ords_off = names_off + n * 4;
    let mut pos = ords_off + n * 2;

    // Emit the export-name strings and record their RVAs.
    let mut name_rvas = Vec::new();
    for e in exports {
        let name = match e {
            ExportSpec::Code { name, .. } | ExportSpec::Forward { name, .. } => *name,
        };
        name_rvas.push(EDATA_RVA + pos);
        // asciiz
        pos += name.len() as u32 + 1;
    }
    // DLL name string.
    let dllname_rva = EDATA_RVA + pos;
    pos += dll_name.len() as u32 + 1;
    // Forwarder strings.
    let mut fwd_rvas: HashMap<usize, u32> = HashMap::new();
    for (i, e) in exports.iter().enumerate() {
        if let ExportSpec::Forward { target, .. } = e {
            fwd_rvas.insert(i, EDATA_RVA + pos);
            pos += target.len() as u32 + 1;
        }
    }
    // `pos` is a section offset (dir starts at offset 0); it is the total length.
    let edata_len = pos;
    let export_dir_size = edata_len; // the whole section IS the directory range

    // Now write the .edata bytes.
    let mut ed = vec![0u8; edata_len as usize];
    // IMAGE_EXPORT_DIRECTORY.
    put_u32(&mut ed, dir_off as usize + 12, dllname_rva); // Name
    put_u32(&mut ed, dir_off as usize + 16, 1); // Base (ordinal base)
    put_u32(&mut ed, dir_off as usize + 20, n); // NumberOfFunctions
    put_u32(&mut ed, dir_off as usize + 24, n); // NumberOfNames
    put_u32(&mut ed, dir_off as usize + 28, EDATA_RVA + eat_off); // AddressOfFunctions
    put_u32(&mut ed, dir_off as usize + 32, EDATA_RVA + names_off); // AddressOfNames
    put_u32(&mut ed, dir_off as usize + 36, EDATA_RVA + ords_off); // AddressOfNameOrdinals

    for (i, e) in exports.iter().enumerate() {
        let eat = eat_off as usize + i * 4;
        let names = names_off as usize + i * 4;
        let ords = ords_off as usize + i * 2;
        match e {
            ExportSpec::Code { ordinal_bias, rva_off, .. } => {
                // A real code RVA (outside the export directory).
                put_u32(&mut ed, eat, *rva_off);
                let _ = ordinal_bias;
            }
            ExportSpec::Forward { ordinal_bias, .. } => {
                // The EAT entry points at the forwarder string (inside the dir).
                put_u32(&mut ed, eat, fwd_rvas[&i]);
                let _ = ordinal_bias;
            }
        }
        put_u32(&mut ed, names, name_rvas[i]);
        put_u16(&mut ed, ords, i as u16); // index into the EAT
    }
    // Export-name strings.
    for (i, e) in exports.iter().enumerate() {
        let name = match e {
            ExportSpec::Code { name, .. } | ExportSpec::Forward { name, .. } => *name,
        };
        let off = (name_rvas[i] - EDATA_RVA) as usize;
        ed[off..off + name.len()].copy_from_slice(name.as_bytes());
    }
    // DLL name.
    let dn = (dllname_rva - EDATA_RVA) as usize;
    ed[dn..dn + dll_name.len()].copy_from_slice(dll_name.as_bytes());
    // Forwarder strings.
    for (i, e) in exports.iter().enumerate() {
        if let ExportSpec::Forward { target, .. } = e {
            let off = (fwd_rvas[&i] - EDATA_RVA) as usize;
            ed[off..off + target.len()].copy_from_slice(target.as_bytes());
        }
    }

    assemble_pe(
        /*is_dll=*/ true,
        &[Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 }],
        /*export_dir=*/ Some((EDATA_RVA, export_dir_size)),
        /*import_dir=*/ None,
        /*entry_rva=*/ 0,
    )
}

/// Build a minimal exe importing `b.dll!g` (a single by-name import), so the
/// resolver has a real parsed [`ImportSymbol`] to chase.
fn build_exe_importing(dll: &str, sym: &str) -> Vec<u8> {
    const IDATA_RVA: u32 = 0x1000;
    // .idata layout: descriptor(20)+null(20), ILT(8)+null(8), IAT(8)+null(8),
    // IMAGE_IMPORT_BY_NAME{hint(2)+name+0}, dll name+0.
    let desc_off = 0u32;
    let ilt_off = 40u32;
    let iat_off = ilt_off + 16;
    let mut pos = iat_off + 16;
    let ibn_off = pos;
    pos += 2 + sym.len() as u32 + 1;
    let dllname_off = pos;
    pos += dll.len() as u32 + 1;
    let len = pos;

    let mut d = vec![0u8; len as usize];
    put_u32(&mut d, desc_off as usize, IDATA_RVA + ilt_off); // OriginalFirstThunk
    put_u32(&mut d, desc_off as usize + 12, IDATA_RVA + dllname_off); // Name
    put_u32(&mut d, desc_off as usize + 16, IDATA_RVA + iat_off); // FirstThunk
    put_u64(&mut d, ilt_off as usize, (IDATA_RVA + ibn_off) as u64);
    put_u64(&mut d, iat_off as usize, (IDATA_RVA + ibn_off) as u64);
    let ibn = ibn_off as usize;
    d[ibn + 2..ibn + 2 + sym.len()].copy_from_slice(sym.as_bytes());
    let dn = dllname_off as usize;
    d[dn..dn + dll.len()].copy_from_slice(dll.as_bytes());

    assemble_pe(
        false,
        &[Sec { name: b".idata", rva: IDATA_RVA, data: &d, chars: 0x4000_0040 }],
        None,
        Some((IDATA_RVA + desc_off, 40)),
        0,
    )
}

struct Sec<'a> {
    name: &'a [u8],
    rva: u32,
    data: &'a [u8],
    chars: u32,
}

fn align_up(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

/// Assemble a PE32+ file from a set of sections, wiring the export/import data
/// directories when given.
fn assemble_pe(
    is_dll: bool,
    secs: &[Sec],
    export_dir: Option<(u32, u32)>,
    import_dir: Option<(u32, u32)>,
    entry_rva: u32,
) -> Vec<u8> {
    // File layout: headers (0x200) then each section's raw bytes file-aligned.
    let headers_raw = FILE_ALIGN;
    let mut raw_ptr = headers_raw;
    let mut placed: Vec<(u32, u32)> = Vec::new(); // (raw_ptr, raw_size) per section
    for s in secs {
        let raw_size = align_up(s.data.len() as u32, FILE_ALIGN);
        placed.push((raw_ptr, raw_size));
        raw_ptr += raw_size;
    }
    let file_len = raw_ptr as usize;
    let mut f = vec![0u8; file_len];

    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664); // AMD64
    put_u16(&mut f, coff + 2, secs.len() as u16);
    put_u16(&mut f, coff + 16, OPT_HDR_SIZE as u16);
    let chars = if is_dll { 0x2022 } else { 0x0022 }; // + DLL bit for a DLL
    put_u16(&mut f, coff + 18, chars);

    let opt = coff + 20;
    let last = secs.last().unwrap();
    let image_size = align_up(last.rva + last.data.len() as u32, SEC_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    put_u32(&mut f, opt + 16, entry_rva); // AddressOfEntryPoint
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SEC_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw);
    put_u16(&mut f, opt + 68, 3); // CONSOLE
    put_u32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes

    let dir = |i: usize| opt + 112 + i * 8;
    if let Some((rva, size)) = export_dir {
        put_u32(&mut f, dir(0), rva);
        put_u32(&mut f, dir(0) + 4, size);
    }
    if let Some((rva, size)) = import_dir {
        put_u32(&mut f, dir(1), rva);
        put_u32(&mut f, dir(1) + 4, size);
    }

    // Section table + bodies.
    let sec_tbl = opt + OPT_HDR_SIZE;
    for (i, s) in secs.iter().enumerate() {
        let at = sec_tbl + i * 40;
        f[at..at + s.name.len()].copy_from_slice(s.name);
        put_u32(&mut f, at + 8, s.data.len() as u32); // VirtualSize
        put_u32(&mut f, at + 12, s.rva); // VirtualAddress
        let (rp, rs) = placed[i];
        put_u32(&mut f, at + 16, rs); // SizeOfRawData
        put_u32(&mut f, at + 20, rp); // PointerToRawData
        put_u32(&mut f, at + 36, s.chars);
        f[rp as usize..rp as usize + s.data.len()].copy_from_slice(s.data);
    }
    f
}

/// A parsed-image module set backing the resolver.
struct Images {
    map: HashMap<String, (u64, Vec<Export>)>,
}
impl ModuleSet for Images {
    fn module(&self, dll: &str) -> Option<LoadedModule<'_>> {
        self.map.get(dll).map(|(base, exports)| LoadedModule { base: *base, exports })
    }
}

#[test]
fn two_dll_forwarder_resolves_end_to_end() {
    // a.dll: f is real code at RVA 0x2000.
    let a = exemu_loader::parse(&build_dll(
        "a.dll",
        &[ExportSpec::Code { name: "f", ordinal_bias: 0, rva_off: 0x2000 }],
    ))
    .expect("a.dll parses");
    // Forwarder detection sanity: a.f is *not* a forwarder.
    let af = a.exports.iter().find(|e| e.name.as_deref() == Some("f")).unwrap();
    assert!(af.forwarder.is_none());
    assert_eq!(af.rva, 0x2000);

    // b.dll: g forwards to A.f.
    let b = exemu_loader::parse(&build_dll(
        "b.dll",
        &[ExportSpec::Forward { name: "g", ordinal_bias: 0, target: "A.f" }],
    ))
    .expect("b.dll parses");
    // The classic trap: g's EAT entry must have been read as a forwarder
    // string, not mistaken for a code RVA.
    let bg = b.exports.iter().find(|e| e.name.as_deref() == Some("g")).unwrap();
    assert_eq!(bg.forwarder.as_deref(), Some("A.f"));

    // exe: imports b.dll!g. Confirm the import parsed.
    let exe = exemu_loader::parse(&build_exe_importing("b.dll", "g")).expect("exe parses");
    assert_eq!(exe.imports.len(), 1);
    assert_eq!(exe.imports[0].dll, "b.dll");
    assert_eq!(exe.imports[0].symbol, ImportSymbol::Named("g".into()));

    // Load a.dll and b.dll at distinct bases and resolve the exe's import.
    let a_base = 0x1000_0000u64;
    let b_base = 0x2000_0000u64;
    let mut map = HashMap::new();
    map.insert("a.dll".to_string(), (a_base, a.exports.clone()));
    map.insert("b.dll".to_string(), (b_base, b.exports.clone()));
    let images = Images { map };

    let imp = &exe.imports[0];
    let r = resolve_import(&images, &imp.dll, &imp.symbol);
    // b.g → a.f, whose real code lives at a_base + 0x2000.
    assert_eq!(r, Resolved::GuestCode(a_base + 0x2000));
}

#[test]
fn forwarder_to_system_dll_falls_back_to_thunk() {
    // b.dll forwards g → kernel32.foo; kernel32 is not a loaded guest image,
    // so resolution must fall back (the OS layer then hands out a thunk).
    let b = exemu_loader::parse(&build_dll(
        "b.dll",
        &[ExportSpec::Forward { name: "g", ordinal_bias: 0, target: "KERNEL32.foo" }],
    ))
    .unwrap();
    let bg = b.exports.iter().find(|e| e.name.as_deref() == Some("g")).unwrap();
    assert_eq!(bg.forwarder.as_deref(), Some("KERNEL32.foo"));

    let mut map = HashMap::new();
    map.insert("b.dll".to_string(), (0x2000_0000u64, b.exports.clone()));
    let images = Images { map };
    assert_eq!(
        resolve_import(&images, "b.dll", &ImportSymbol::Named("g".into())),
        Resolved::Fallback
    );
}
