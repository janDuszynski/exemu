use std::collections::HashMap;

use exemu_core::{Memory, Perm, Result};

pub struct Wow64Image {
    pub base: u64,
    pub size: u64,
    pub exports: HashMap<String, u64>,
    pub imports: Vec<(u32, String, String)>,
    pub entry: u64,
}

impl Wow64Image {
    pub fn export(&self, name: &str) -> Option<u64> {
        self.exports.get(name).copied()
    }
}

pub fn map_image(mem: &mut dyn Memory, bytes: &[u8], base: u64, name: &str) -> Result<Wow64Image> {
    let mut image = exemu_loader::parse(bytes)?;
    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)?;

    let size = align_up_page((image.size_of_image as u64).max(0x1000));
    mem.map_fixed(base, size, Perm::RWX, name)?;
    mem.write(base, &image.headers)?;
    for s in &image.sections {
        if !s.data.is_empty() {
            mem.write(base + s.rva as u64, &s.data)?;
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(n) = &e.name {
            exports.insert(n.clone(), base + e.rva as u64);
        }
    }
    let imports = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();

    Ok(Wow64Image {
        base,
        size,
        exports,
        imports,
        entry: if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 },
    })
}

pub fn image_view(bytes: &[u8], base: u64) -> Result<Wow64Image> {
    let image = exemu_loader::parse(bytes)?;
    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(n) = &e.name {
            exports.insert(n.clone(), base + e.rva as u64);
        }
    }
    let imports = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    Ok(Wow64Image {
        base,
        size: align_up_page((image.size_of_image as u64).max(0x1000)),
        exports,
        imports,
        entry: if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 },
    })
}

pub fn bind_imports(mem: &mut dyn Memory, image: &Wow64Image, providers: &[&Wow64Image], ptr_size: u8) -> Result<usize> {
    let mut bound = 0;
    for (iat_rva, _dll, sym) in &image.imports {
        for p in providers {
            if let Some(addr) = p.export(sym) {
                mem.write(image.base + *iat_rva as u64, &addr.to_le_bytes()[..ptr_size as usize])?;
                bound += 1;
                break;
            }
        }
    }
    Ok(bound)
}

#[inline]
fn align_up_page(v: u64) -> u64 {
    (v + 0xfff) & !0xfff
}
