use std::collections::HashMap;

use exemu_core::{Export, ImportSymbol};
use exemu_loader::{resolve_import, LoadedModule, ModuleSet, Resolved};

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

enum ExportSpec {
    Code { name: &'static str, ordinal_bias: u32, rva_off: u32 },
    Forward { name: &'static str, ordinal_bias: u32, target: &'static str },
}

fn build_dll(dll_name: &str, exports: &[ExportSpec]) -> Vec<u8> {
    const EDATA_RVA: u32 = 0x1000;

    let n = exports.len() as u32;
    let dir_off = 0u32;
    let eat_off = dir_off + 40;
    let names_off = eat_off + n * 4;
    let ords_off = names_off + n * 4;
    let mut pos = ords_off + n * 2;

    let mut name_rvas = Vec::new();
    for e in exports {
        let name = match e {
            ExportSpec::Code { name, .. } | ExportSpec::Forward { name, .. } => *name,
        };
        name_rvas.push(EDATA_RVA + pos);
        pos += name.len() as u32 + 1;
    }
    let dllname_rva = EDATA_RVA + pos;
    pos += dll_name.len() as u32 + 1;
    let mut fwd_rvas: HashMap<usize, u32> = HashMap::new();
    for (i, e) in exports.iter().enumerate() {
        if let ExportSpec::Forward { target, .. } = e {
            fwd_rvas.insert(i, EDATA_RVA + pos);
            pos += target.len() as u32 + 1;
        }
    }
    let edata_len = pos;
    let export_dir_size = edata_len;

    let mut ed = vec![0u8; edata_len as usize];
    put_u32(&mut ed, dir_off as usize + 12, dllname_rva);
    put_u32(&mut ed, dir_off as usize + 16, 1);
    put_u32(&mut ed, dir_off as usize + 20, n);
    put_u32(&mut ed, dir_off as usize + 24, n);
    put_u32(&mut ed, dir_off as usize + 28, EDATA_RVA + eat_off);
    put_u32(&mut ed, dir_off as usize + 32, EDATA_RVA + names_off);
    put_u32(&mut ed, dir_off as usize + 36, EDATA_RVA + ords_off);

    for (i, e) in exports.iter().enumerate() {
        let eat = eat_off as usize + i * 4;
        let names = names_off as usize + i * 4;
        let ords = ords_off as usize + i * 2;
        match e {
            ExportSpec::Code { ordinal_bias, rva_off, .. } => {
                put_u32(&mut ed, eat, *rva_off);
                let _ = ordinal_bias;
            }
            ExportSpec::Forward { ordinal_bias, .. } => {
                put_u32(&mut ed, eat, fwd_rvas[&i]);
                let _ = ordinal_bias;
            }
        }
        put_u32(&mut ed, names, name_rvas[i]);
        put_u16(&mut ed, ords, i as u16);
    }
    for (i, e) in exports.iter().enumerate() {
        let name = match e {
            ExportSpec::Code { name, .. } | ExportSpec::Forward { name, .. } => *name,
        };
        let off = (name_rvas[i] - EDATA_RVA) as usize;
        ed[off..off + name.len()].copy_from_slice(name.as_bytes());
    }
    let dn = (dllname_rva - EDATA_RVA) as usize;
    ed[dn..dn + dll_name.len()].copy_from_slice(dll_name.as_bytes());
    for (i, e) in exports.iter().enumerate() {
        if let ExportSpec::Forward { target, .. } = e {
            let off = (fwd_rvas[&i] - EDATA_RVA) as usize;
            ed[off..off + target.len()].copy_from_slice(target.as_bytes());
        }
    }

    assemble_pe(
         true,
        &[Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 }],
         Some((EDATA_RVA, export_dir_size)),
         None,
         0,
    )
}

fn build_exe_importing(dll: &str, sym: &str) -> Vec<u8> {
    const IDATA_RVA: u32 = 0x1000;
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
    put_u32(&mut d, desc_off as usize, IDATA_RVA + ilt_off);
    put_u32(&mut d, desc_off as usize + 12, IDATA_RVA + dllname_off);
    put_u32(&mut d, desc_off as usize + 16, IDATA_RVA + iat_off);
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

fn assemble_pe(
    is_dll: bool,
    secs: &[Sec],
    export_dir: Option<(u32, u32)>,
    import_dir: Option<(u32, u32)>,
    entry_rva: u32,
) -> Vec<u8> {
    let headers_raw = FILE_ALIGN;
    let mut raw_ptr = headers_raw;
    let mut placed: Vec<(u32, u32)> = Vec::new();
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
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, secs.len() as u16);
    put_u16(&mut f, coff + 16, OPT_HDR_SIZE as u16);
    let chars = if is_dll { 0x2022 } else { 0x0022 };
    put_u16(&mut f, coff + 18, chars);

    let opt = coff + 20;
    let last = secs.last().unwrap();
    let image_size = align_up(last.rva + last.data.len() as u32, SEC_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    put_u32(&mut f, opt + 16, entry_rva);
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SEC_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw);
    put_u16(&mut f, opt + 68, 3);
    put_u32(&mut f, opt + 108, 16);

    let dir = |i: usize| opt + 112 + i * 8;
    if let Some((rva, size)) = export_dir {
        put_u32(&mut f, dir(0), rva);
        put_u32(&mut f, dir(0) + 4, size);
    }
    if let Some((rva, size)) = import_dir {
        put_u32(&mut f, dir(1), rva);
        put_u32(&mut f, dir(1) + 4, size);
    }

    let sec_tbl = opt + OPT_HDR_SIZE;
    for (i, s) in secs.iter().enumerate() {
        let at = sec_tbl + i * 40;
        f[at..at + s.name.len()].copy_from_slice(s.name);
        put_u32(&mut f, at + 8, s.data.len() as u32);
        put_u32(&mut f, at + 12, s.rva);
        let (rp, rs) = placed[i];
        put_u32(&mut f, at + 16, rs);
        put_u32(&mut f, at + 20, rp);
        put_u32(&mut f, at + 36, s.chars);
        f[rp as usize..rp as usize + s.data.len()].copy_from_slice(s.data);
    }
    f
}

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
    let a = exemu_loader::parse(&build_dll(
        "a.dll",
        &[ExportSpec::Code { name: "f", ordinal_bias: 0, rva_off: 0x2000 }],
    ))
    .expect("a.dll parses");
    let af = a.exports.iter().find(|e| e.name.as_deref() == Some("f")).unwrap();
    assert!(af.forwarder.is_none());
    assert_eq!(af.rva, 0x2000);

    let b = exemu_loader::parse(&build_dll(
        "b.dll",
        &[ExportSpec::Forward { name: "g", ordinal_bias: 0, target: "A.f" }],
    ))
    .expect("b.dll parses");
    let bg = b.exports.iter().find(|e| e.name.as_deref() == Some("g")).unwrap();
    assert_eq!(bg.forwarder.as_deref(), Some("A.f"));

    let exe = exemu_loader::parse(&build_exe_importing("b.dll", "g")).expect("exe parses");
    assert_eq!(exe.imports.len(), 1);
    assert_eq!(exe.imports[0].dll, "b.dll");
    assert_eq!(exe.imports[0].symbol, ImportSymbol::Named("g".into()));

    let a_base = 0x1000_0000u64;
    let b_base = 0x2000_0000u64;
    let mut map = HashMap::new();
    map.insert("a.dll".to_string(), (a_base, a.exports.clone()));
    map.insert("b.dll".to_string(), (b_base, b.exports.clone()));
    let images = Images { map };

    let imp = &exe.imports[0];
    let r = resolve_import(&images, &imp.dll, &imp.symbol);
    assert_eq!(r, Resolved::GuestCode(a_base + 0x2000));
}

#[test]
fn forwarder_to_system_dll_falls_back_to_thunk() {
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
