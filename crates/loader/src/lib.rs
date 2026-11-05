#![forbid(unsafe_code)]

mod api_set;
mod image_loader;
mod manifest;
mod reader;
mod reloc;
mod resolve;
mod resources;
mod unwind;

pub use api_set::resolve as resolve_api_set;
pub use image_loader::PeImageLoader;
pub use manifest::parse_from_pe_resources as parse_activation_context;
pub use manifest::parse_from_external_manifest as parse_activation_context_from_manifest;
pub use reloc::apply as apply_relocations;
pub use resolve::{resolve as resolve_import, LoadedModule, ModuleSet, Resolved};
pub use resources::{
    find_resource, find_resource_by_id, find_string, find_version_info, list_resources,
    parse_dialogs, parse_string_block, parse_version_info, rt_name, FixedFileInfo, ResourceEntry,
    ResourceName, LANG_ANY, RT_ACCELERATOR, RT_ANIICON, RT_ANICURSOR, RT_BITMAP, RT_CURSOR,
    RT_DIALOG, RT_DLGINCLUDE, RT_FONT, RT_FONTDIR, RT_GROUP_CURSOR, RT_GROUP_ICON, RT_HTML,
    RT_ICON, RT_MANIFEST, RT_MENU, RT_MESSAGETABLE, RT_PLUGPLAY, RT_RCDATA, RT_STRING,
    RT_VERSION, RT_VXD,
};

use exemu_core::{EmuError, Export, Import, ImportSymbol, PeImage, Reloc, Result, Section, Tls};
use reader::Reader;

const DOS_MAGIC: u16 = 0x5A4D;
const PE_SIGNATURE: u32 = 0x0000_4550;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_I386: u16 = 0x014c;
const OPT_MAGIC_PE32: u16 = 0x10B;
const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

const E_LFANEW_OFFSET: usize = 0x3C;

const OPT_ENTRY: usize = 16;
const OPT_SIZE_OF_IMAGE: usize = 56;
const OPT_SIZE_OF_HEADERS: usize = 60;
const OPT_SUBSYSTEM: usize = 68;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_DELAY_IMPORT: usize = 13;

const SCN_CNT_UNINIT_DATA: u32 = 0x0000_0080;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const SECTION_HEADER_SIZE: usize = 40;

pub fn parse(bytes: &[u8]) -> Result<PeImage> {
    let r = Reader::new(bytes);

    if r.u16(0)? != DOS_MAGIC {
        return Err(EmuError::InvalidPe("missing 'MZ' DOS signature".into()));
    }
    let pe_off = r.u32(E_LFANEW_OFFSET)? as usize;

    if r.u32(pe_off)? != PE_SIGNATURE {
        return Err(EmuError::InvalidPe("missing 'PE\\0\\0' signature".into()));
    }
    let coff = pe_off + 4;
    let machine = r.u16(coff)?;
    if machine != MACHINE_AMD64 && machine != MACHINE_I386 {
        return Err(EmuError::InvalidPe(format!(
            "unsupported machine {machine:#06x} (only x86-64 and 32-bit x86 are supported)"
        )));
    }
    let num_sections = r.u16(coff + 2)? as usize;
    let size_opt_header = r.u16(coff + 16)? as usize;

    let opt = coff + 20;
    let magic = r.u16(opt)?;
    let is_64bit = match magic {
        OPT_MAGIC_PE32PLUS => true,
        OPT_MAGIC_PE32 => false,
        other => {
            return Err(EmuError::InvalidPe(format!("unknown optional-header magic {other:#06x}")))
        }
    };

    let entry_rva = r.u32(opt + OPT_ENTRY)?;
    let size_of_image = r.u32(opt + OPT_SIZE_OF_IMAGE)?;
    let size_of_headers = r.u32(opt + OPT_SIZE_OF_HEADERS)?;
    let subsystem = r.u16(opt + OPT_SUBSYSTEM)?;
    let (image_base, stack_reserve, num_dirs_off, data_dirs_off) = if is_64bit {
        (r.u64(opt + 24)?, r.u64(opt + 72)?, 108usize, 112usize)
    } else {
        (r.u32(opt + 28)? as u64, r.u32(opt + 72)? as u64, 92usize, 96usize)
    };
    let num_dirs = r.u32(opt + num_dirs_off)? as usize;

    let dir = |i: usize| -> Result<(u32, u32)> {
        if num_dirs > i {
            let b = opt + data_dirs_off + i * 8;
            Ok((r.u32(b)?, r.u32(b + 4)?))
        } else {
            Ok((0, 0))
        }
    };
    let (import_dir_rva, import_dir_size) = dir(DIR_IMPORT)?;
    let (export_dir_rva, export_dir_size) = dir(DIR_EXPORT)?;
    let (exc_dir_rva, exc_dir_size) = dir(DIR_EXCEPTION)?;
    let (reloc_dir_rva, reloc_dir_size) = dir(DIR_BASERELOC)?;
    let (tls_dir_rva, _tls_dir_size) = dir(DIR_TLS)?;
    let (delay_dir_rva, delay_dir_size) = dir(DIR_DELAY_IMPORT)?;

    let sec_table = opt + size_opt_header;
    let headers = (0..num_sections)
        .map(|i| SectionHeader::read(&r, sec_table + i * SECTION_HEADER_SIZE))
        .collect::<Result<Vec<_>>>()?;
    let raw_limits = raw_copy_limits(&headers)?;
    let mut sections = Vec::with_capacity(num_sections);
    for (h, limit) in headers.into_iter().zip(raw_limits) {
        let data = if h.size_raw == 0 || h.chars & SCN_CNT_UNINIT_DATA != 0 {
            Vec::new()
        } else {
            let avail = r.len().saturating_sub(h.ptr_raw).min(h.size_raw).min(limit);
            r.bytes(h.ptr_raw, avail)?
        };

        sections.push(Section {
            name: h.name,
            rva: h.rva,
            virtual_size: h.virtual_size,
            data,
            readable: h.chars & SCN_MEM_READ != 0,
            writable: h.chars & SCN_MEM_WRITE != 0,
            executable: h.chars & SCN_MEM_EXECUTE != 0,
        });
    }

    let mut imports = if import_dir_rva != 0 && import_dir_size != 0 {
        parse_imports(&sections, import_dir_rva, is_64bit)?
    } else {
        Vec::new()
    };

    if delay_dir_rva != 0 && delay_dir_size != 0 {
        if let Ok(mut delay) = parse_delay_imports(&sections, delay_dir_rva, image_base, is_64bit) {
            imports.append(&mut delay);
        }
    }

    let (exports, dll_name) = if export_dir_rva != 0 && export_dir_size != 0 {
        parse_exports(&sections, export_dir_rva, export_dir_size).unwrap_or_default()
    } else {
        (Vec::new(), None)
    };

    let relocations = if reloc_dir_rva != 0 && reloc_dir_size != 0 {
        parse_relocs(&sections, reloc_dir_rva, reloc_dir_size).unwrap_or_default()
    } else {
        Vec::new()
    };

    let tls = if tls_dir_rva != 0 {
        parse_tls(&sections, tls_dir_rva, image_base, is_64bit).ok()
    } else {
        None
    };

    let function_table = if is_64bit && exc_dir_rva != 0 && exc_dir_size != 0 {
        unwind::parse_function_table(&sections, exc_dir_rva, exc_dir_size)
    } else {
        Vec::new()
    };

    let headers = r.bytes(0, (size_of_headers as usize).min(r.len()))?;

    let activation_context = manifest::parse_from_pe_resources(bytes);

    Ok(PeImage {
        is_64bit,
        image_base,
        entry_rva,
        size_of_image,
        size_of_headers,
        subsystem,
        stack_reserve,
        sections,
        imports,
        exports,
        relocations,
        tls,
        dll_name,
        headers,
        function_table,
        activation_context,
    })
}

struct SectionHeader {
    name: String,
    virtual_size: u32,
    rva: u32,
    size_raw: usize,
    ptr_raw: usize,
    chars: u32,
}

impl SectionHeader {
    fn read(r: &Reader, at: usize) -> Result<SectionHeader> {
        let raw_name = r.bytes(at, 8)?;
        let name_len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        Ok(SectionHeader {
            name: String::from_utf8_lossy(&raw_name[..name_len]).into_owned(),
            virtual_size: r.u32(at + 8)?,
            rva: r.u32(at + 12)?,
            size_raw: r.u32(at + 16)? as usize,
            ptr_raw: r.u32(at + 20)? as usize,
            chars: r.u32(at + 36)?,
        })
    }

    fn virtual_span(&self) -> u64 {
        if self.virtual_size != 0 {
            u64::from(self.virtual_size)
        } else {
            self.size_raw as u64
        }
    }

    fn virtual_end(&self) -> u64 {
        u64::from(self.rva) + self.virtual_span()
    }
}

fn raw_copy_limits(headers: &[SectionHeader]) -> Result<Vec<usize>> {
    let mut by_rva: Vec<usize> = (0..headers.len()).collect();
    by_rva.sort_by_key(|&i| (headers[i].rva, headers[i].virtual_span()));
    let mut limits = vec![usize::MAX; headers.len()];
    for pair in by_rva.windows(2) {
        let (cur, next) = (&headers[pair[0]], &headers[pair[1]]);
        if cur.virtual_end() > u64::from(next.rva) {
            return Err(EmuError::InvalidPe(format!(
                "section {:?} at rva {:#x} overlaps section {:?} at rva {:#x}",
                cur.name, cur.rva, next.name, next.rva
            )));
        }
        limits[pair[0]] = (next.rva - cur.rva) as usize;
    }
    Ok(limits)
}

fn parse_exports(
    sections: &[Section],
    dir_rva: u32,
    dir_size: u32,
) -> Result<(Vec<Export>, Option<String>)> {
    let ordinal_base = slice_u32(sections, dir_rva.wrapping_add(16))?;
    let num_funcs = slice_u32(sections, dir_rva.wrapping_add(20))?;
    let num_names = slice_u32(sections, dir_rva.wrapping_add(24))?;
    let funcs_rva = slice_u32(sections, dir_rva.wrapping_add(28))?;
    let names_rva = slice_u32(sections, dir_rva.wrapping_add(32))?;
    let ords_rva = slice_u32(sections, dir_rva.wrapping_add(36))?;
    let name_ptr = slice_u32(sections, dir_rva.wrapping_add(12))?;
    let dll_name = if name_ptr != 0 { cstr_at_rva(sections, name_ptr).ok() } else { None };

    let dir_end = dir_rva.saturating_add(dir_size);

    let mut names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    for i in 0..num_names {
        let name_rva = slice_u32(sections, names_rva.wrapping_add(i.wrapping_mul(4)))?;
        let ord_index = slice_u16(sections, ords_rva.wrapping_add(i.wrapping_mul(2)))? as u32;
        if let Ok(nm) = cstr_at_rva(sections, name_rva) {
            names.insert(ord_index, nm);
        }
    }

    let mut exports = Vec::new();
    for i in 0..num_funcs {
        let func_rva = slice_u32(sections, funcs_rva.wrapping_add(i.wrapping_mul(4)))?;
        if func_rva == 0 {
            continue;
        }
        let forwarder = if func_rva >= dir_rva && func_rva < dir_end {
            cstr_at_rva(sections, func_rva).ok()
        } else {
            None
        };
        exports.push(Export {
            name: names.get(&i).cloned(),
            ordinal: ordinal_base.wrapping_add(i) as u16,
            rva: func_rva,
            forwarder,
        });
    }
    Ok((exports, dll_name))
}

fn parse_relocs(sections: &[Section], dir_rva: u32, dir_size: u32) -> Result<Vec<Reloc>> {
    let mut relocs = Vec::new();
    let mut off = 0u32;
    while off.checked_add(8).is_some_and(|end| end <= dir_size) {
        let page_rva = slice_u32(sections, dir_rva.wrapping_add(off))?;
        let block_size = slice_u32(sections, dir_rva.wrapping_add(off).wrapping_add(4))?;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for e in 0..entries {
            let v = slice_u16(sections, dir_rva.wrapping_add(off).wrapping_add(8).wrapping_add(e.wrapping_mul(2)))?;
            let kind = (v >> 12) as u8;
            let word_off = (v & 0x0FFF) as u32;
            if kind != 0 {
                relocs.push(Reloc { rva: page_rva.wrapping_add(word_off), kind });
            }
        }
        off = off.saturating_add(block_size);
    }
    Ok(relocs)
}

fn parse_tls(sections: &[Section], dir_rva: u32, image_base: u64, is_64bit: bool) -> Result<Tls> {
    let ptr = |rva: u32| -> Result<u64> {
        if is_64bit {
            slice_u64(sections, rva)
        } else {
            slice_u32(sections, rva).map(u64::from)
        }
    };
    let p: u32 = if is_64bit { 8 } else { 4 };

    let start_address_of_raw_data = ptr(dir_rva)?;
    let end_address_of_raw_data = ptr(dir_rva.wrapping_add(p))?;
    let address_of_index = ptr(dir_rva.wrapping_add(2 * p))?;
    let address_of_callbacks = ptr(dir_rva.wrapping_add(3 * p))?;
    let size_of_zero_fill = slice_u32(sections, dir_rva.wrapping_add(4 * p))?;
    let characteristics = slice_u32(sections, dir_rva.wrapping_add(4 * p + 4))?;

    let va_to_rva = |va: u64| -> Option<u32> {
        if va == 0 {
            return None;
        }
        va.checked_sub(image_base).and_then(|off| u32::try_from(off).ok())
    };

    let raw_template = match (va_to_rva(start_address_of_raw_data), end_address_of_raw_data) {
        (Some(start_rva), end) if end > start_address_of_raw_data => {
            let len = (end - start_address_of_raw_data) as usize;
            let mut buf = Vec::new();
            let mut ok = true;
            for i in 0..len {
                match slice_u8(sections, start_rva.wrapping_add(i as u32)) {
                    Ok(b) => buf.push(b),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok { buf } else { Vec::new() }
        }
        _ => Vec::new(),
    };

    let mut callback_rvas = Vec::new();
    if let Some(mut arr_rva) = va_to_rva(address_of_callbacks) {
        while let Ok(cb_va) = ptr(arr_rva) {
            if cb_va == 0 {
                break;
            }
            match va_to_rva(cb_va) {
                Some(rva) => callback_rvas.push(rva),
                None => break,
            }
            arr_rva = arr_rva.wrapping_add(p);
        }
    }

    Ok(Tls {
        start_address_of_raw_data,
        end_address_of_raw_data,
        address_of_index,
        address_of_callbacks,
        size_of_zero_fill,
        characteristics,
        raw_template,
        callback_rvas,
    })
}

fn read_at_rva(sections: &[Section], rva: u32) -> Option<(&Section, usize)> {
    for s in sections {
        let vsize = s.virtual_size.max(s.data.len() as u32);
        if rva >= s.rva && u64::from(rva) < u64::from(s.rva) + u64::from(vsize) {
            return Some((s, (rva - s.rva) as usize));
        }
    }
    None
}

pub(crate) fn slice_u8(sections: &[Section], rva: u32) -> Result<u8> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    s.data
        .get(off)
        .copied()
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))
}

pub(crate) fn slice_u16(sections: &[Section], rva: u32) -> Result<u16> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    let b = s
        .data
        .get(off..off.saturating_add(2))
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn slice_u32(sections: &[Section], rva: u32) -> Result<u32> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    let b = s
        .data
        .get(off..off.saturating_add(4))
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn slice_u64(sections: &[Section], rva: u32) -> Result<u64> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    let b = s
        .data
        .get(off..off.saturating_add(8))
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Ok(u64::from_le_bytes(arr))
}

fn cstr_at_rva(sections: &[Section], rva: u32) -> Result<String> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("string rva {rva:#x} not in any section")))?;
    let tail = s
        .data
        .get(off..)
        .ok_or_else(|| EmuError::InvalidPe(format!("string rva {rva:#x} past section data")))?;
    let len = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..len]).into_owned())
}

fn parse_imports(sections: &[Section], dir_rva: u32, is_64bit: bool) -> Result<Vec<Import>> {
    let mut imports = Vec::new();
    let thunk_size = if is_64bit { 8 } else { 4 };
    let ordinal_flag: u64 = if is_64bit { 1 << 63 } else { 1 << 31 };

    let read_thunk = |sections: &[Section], rva: u32| -> Result<u64> {
        if is_64bit {
            slice_u64(sections, rva)
        } else {
            slice_u32(sections, rva).map(|v| v as u64)
        }
    };

    let mut desc = dir_rva;
    loop {
        let orig_first_thunk = slice_u32(sections, desc)?;
        let name_rva = slice_u32(sections, desc.wrapping_add(12))?;
        let first_thunk = slice_u32(sections, desc.wrapping_add(16))?;

        if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll = cstr_at_rva(sections, name_rva)?.to_ascii_lowercase();

        let lookup = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };

        let mut i = 0u32;
        loop {
            let thunk = read_thunk(sections, lookup.wrapping_add(i.wrapping_mul(thunk_size)))?;
            if thunk == 0 {
                break;
            }
            let iat_rva = first_thunk.wrapping_add(i.wrapping_mul(thunk_size));
            let symbol = if thunk & ordinal_flag != 0 {
                ImportSymbol::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                let by_name_rva = (thunk & 0x7FFF_FFFF) as u32;
                ImportSymbol::Named(cstr_at_rva(sections, by_name_rva.wrapping_add(2))?)
            };
            imports.push(Import { dll: dll.clone(), symbol, iat_rva });
            i += 1;
        }

        desc = desc.wrapping_add(20);
    }

    Ok(imports)
}

fn parse_delay_imports(
    sections: &[Section],
    dir_rva: u32,
    image_base: u64,
    is_64bit: bool,
) -> Result<Vec<Import>> {
    let mut imports = Vec::new();
    let thunk_size = if is_64bit { 8 } else { 4 };
    let ordinal_flag: u64 = if is_64bit { 1 << 63 } else { 1 << 31 };

    let read_thunk = |sections: &[Section], rva: u32| -> Result<u64> {
        if is_64bit {
            slice_u64(sections, rva)
        } else {
            slice_u32(sections, rva).map(|v| v as u64)
        }
    };

    let mut desc = dir_rva;
    loop {
        let attributes = slice_u32(sections, desc)?;
        let name_field = slice_u32(sections, desc.wrapping_add(4))?;
        let iat_field = slice_u32(sections, desc.wrapping_add(12))?;
        let int_field = slice_u32(sections, desc.wrapping_add(16))?;

        if attributes == 0 && name_field == 0 && iat_field == 0 && int_field == 0 {
            break;
        }

        let rva_based = attributes & 1 != 0;
        let to_rva = |field: u32| -> u32 {
            if rva_based {
                field
            } else {
                (field as u64).wrapping_sub(image_base) as u32
            }
        };

        let name_rva = to_rva(name_field);
        let iat_rva0 = to_rva(iat_field);
        let int_rva0 = to_rva(int_field);

        let Ok(dll) = cstr_at_rva(sections, name_rva).map(|s| s.to_ascii_lowercase()) else {
            desc = desc.wrapping_add(32);
            continue;
        };

        let mut i = 0u32;
        while let Ok(thunk) = read_thunk(sections, int_rva0.wrapping_add(i.wrapping_mul(thunk_size))) {
            if thunk == 0 {
                break;
            }
            let iat_rva = iat_rva0.wrapping_add(i.wrapping_mul(thunk_size));
            let symbol = if thunk & ordinal_flag != 0 {
                ImportSymbol::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                let by_name_rva = (thunk & 0x7FFF_FFFF) as u32;
                match cstr_at_rva(sections, by_name_rva.wrapping_add(2)) {
                    Ok(name) => ImportSymbol::Named(name),
                    Err(_) => break,
                }
            };
            imports.push(Import { dll: dll.clone(), symbol, iat_rva });
            i += 1;
        }

        desc = desc.wrapping_add(32);
    }

    Ok(imports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(matches!(parse(b"not an exe at all"), Err(EmuError::InvalidPe(_))));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse(&[]).is_err());
    }

    fn tls_fixture_64(image_base: u64) -> (Vec<Section>, u32) {
        const SEC_RVA: u32 = 0x1000;
        const DIR_OFF: usize = 0x00;
        const CB_ARR_OFF: usize = 0x40;
        const TMPL_OFF: usize = 0x60;
        const TMPL_LEN: usize = 4;

        let tmpl_rva = SEC_RVA + TMPL_OFF as u32;
        let cb_arr_rva = SEC_RVA + CB_ARR_OFF as u32;
        let cb_target_rva = 0x2345u32;

        let tmpl_va = image_base + tmpl_rva as u64;
        let cb_arr_va = image_base + cb_arr_rva as u64;
        let cb_va = image_base + cb_target_rva as u64;
        let index_va = image_base + 0x3000;

        let mut data = vec![0u8; 0x80];
        data[DIR_OFF..DIR_OFF + 8].copy_from_slice(&tmpl_va.to_le_bytes());
        data[DIR_OFF + 8..DIR_OFF + 16]
            .copy_from_slice(&(tmpl_va + TMPL_LEN as u64).to_le_bytes());
        data[DIR_OFF + 16..DIR_OFF + 24].copy_from_slice(&index_va.to_le_bytes());
        data[DIR_OFF + 24..DIR_OFF + 32].copy_from_slice(&cb_arr_va.to_le_bytes());
        data[DIR_OFF + 32..DIR_OFF + 36].copy_from_slice(&0x100u32.to_le_bytes());
        data[DIR_OFF + 36..DIR_OFF + 40].copy_from_slice(&0x0030_0000u32.to_le_bytes());

        data[CB_ARR_OFF..CB_ARR_OFF + 8].copy_from_slice(&cb_va.to_le_bytes());
        data[CB_ARR_OFF + 8..CB_ARR_OFF + 16].copy_from_slice(&0u64.to_le_bytes());

        data[TMPL_OFF..TMPL_OFF + TMPL_LEN].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let sections = vec![Section {
            name: ".tls".into(),
            rva: SEC_RVA,
            virtual_size: 0x80,
            data,
            readable: true,
            writable: true,
            executable: false,
        }];
        (sections, SEC_RVA + DIR_OFF as u32)
    }

    #[test]
    fn tls_directory_64_parses_fields_template_and_callback() {
        let image_base = 0x1_4000_0000u64;
        let (sections, dir_rva) = tls_fixture_64(image_base);
        let tls = parse_tls(&sections, dir_rva, image_base, true).unwrap();

        assert_eq!(tls.start_address_of_raw_data, image_base + 0x1060);
        assert_eq!(tls.end_address_of_raw_data, image_base + 0x1064);
        assert_eq!(tls.address_of_index, image_base + 0x3000);
        assert_eq!(tls.address_of_callbacks, image_base + 0x1040);
        assert_eq!(tls.size_of_zero_fill, 0x100);
        assert_eq!(tls.characteristics, 0x0030_0000);

        assert_eq!(tls.raw_template, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(tls.callback_rvas, vec![0x2345]);
    }

    #[test]
    fn tls_directory_32_uses_4byte_pointers() {
        const SEC_RVA: u32 = 0x1000;
        let image_base = 0x0040_0000u64;
        let tmpl_rva = SEC_RVA + 0x60;
        let cb_arr_rva = SEC_RVA + 0x40;
        let cb_target_rva = 0x1234u32;

        let mut data = vec![0u8; 0x80];
        let put32 = |d: &mut [u8], off: usize, v: u32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut data, 0x00, (image_base as u32) + tmpl_rva);
        put32(&mut data, 0x04, (image_base as u32) + tmpl_rva + 4);
        put32(&mut data, 0x08, (image_base as u32) + 0x3000);
        put32(&mut data, 0x0C, (image_base as u32) + cb_arr_rva);
        put32(&mut data, 0x10, 0x40);
        put32(&mut data, 0x14, 0x00A0_0000);
        put32(&mut data, 0x40, (image_base as u32) + cb_target_rva);
        put32(&mut data, 0x44, 0);
        data[0x60..0x64].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let sections = vec![Section {
            name: ".tls".into(),
            rva: SEC_RVA,
            virtual_size: 0x80,
            data,
            readable: true,
            writable: true,
            executable: false,
        }];

        let tls = parse_tls(&sections, SEC_RVA, image_base, false).unwrap();
        assert_eq!(tls.start_address_of_raw_data, image_base + 0x1060);
        assert_eq!(tls.end_address_of_raw_data, image_base + 0x1064);
        assert_eq!(tls.address_of_index, image_base + 0x3000);
        assert_eq!(tls.address_of_callbacks, image_base + 0x1040);
        assert_eq!(tls.size_of_zero_fill, 0x40);
        assert_eq!(tls.characteristics, 0x00A0_0000);
        assert_eq!(tls.raw_template, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(tls.callback_rvas, vec![0x1234]);
    }

    #[test]
    fn tls_empty_callback_array_yields_no_callbacks() {
        const SEC_RVA: u32 = 0x1000;
        let image_base = 0x1_4000_0000u64;
        let cb_arr_rva = SEC_RVA + 0x40;
        let mut data = vec![0u8; 0x80];
        data[24..32].copy_from_slice(&(image_base + cb_arr_rva as u64).to_le_bytes());
        let sections = vec![Section {
            name: ".tls".into(),
            rva: SEC_RVA,
            virtual_size: 0x80,
            data,
            readable: true,
            writable: true,
            executable: false,
        }];
        let tls = parse_tls(&sections, SEC_RVA, image_base, true).unwrap();
        assert!(tls.callback_rvas.is_empty());
        assert!(tls.raw_template.is_empty());
    }

    #[test]
    fn no_tls_directory_leaves_tls_none() {
        let bytes = minimal_pe_no_tls();
        let img = parse(&bytes).expect("minimal PE should parse");
        assert!(img.tls.is_none());
    }

    fn minimal_pe_no_tls() -> Vec<u8> {
        let mut f = vec![0u8; 0x600];
        f[0] = 0x4D;
        f[1] = 0x5A;
        let pe_off = 0x80usize;
        f[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(pe_off as u32).to_le_bytes());
        f[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        let coff = pe_off + 4;
        f[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        let size_opt = 0xF0u16;
        f[coff + 16..coff + 18].copy_from_slice(&size_opt.to_le_bytes());
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        f[opt + OPT_ENTRY..opt + OPT_ENTRY + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        f[opt + OPT_SIZE_OF_IMAGE..opt + OPT_SIZE_OF_IMAGE + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        f[opt + OPT_SIZE_OF_HEADERS..opt + OPT_SIZE_OF_HEADERS + 4]
            .copy_from_slice(&0x400u32.to_le_bytes());
        f[opt + OPT_SUBSYSTEM..opt + OPT_SUBSYSTEM + 2].copy_from_slice(&3u16.to_le_bytes());
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + size_opt as usize;
        f[sec..sec + 5].copy_from_slice(b".text");
        f[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
        f[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        f[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        f[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        f[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        f
    }

    fn ordinal_thunk_64(ord: u16) -> u64 {
        (1u64 << 63) | ord as u64
    }

    #[test]
    fn delay_import_rva_based_parses_name_and_ordinal() {
        const RVA: u32 = 0x1000;
        let desc_off = 0usize;
        let int_off = 0x40usize;
        let iat_off = 0x58usize;
        let ibn_off = 0x70usize;
        let dll_off = 0x80usize;

        let mut d = vec![0u8; 0x100];
        d[desc_off..desc_off + 4].copy_from_slice(&1u32.to_le_bytes());
        d[desc_off + 4..desc_off + 8].copy_from_slice(&(RVA + dll_off as u32).to_le_bytes());
        d[desc_off + 12..desc_off + 16].copy_from_slice(&(RVA + iat_off as u32).to_le_bytes());
        d[desc_off + 16..desc_off + 20].copy_from_slice(&(RVA + int_off as u32).to_le_bytes());

        d[int_off..int_off + 8].copy_from_slice(&((RVA + ibn_off as u32) as u64).to_le_bytes());
        d[int_off + 8..int_off + 16].copy_from_slice(&ordinal_thunk_64(1).to_le_bytes());

        d[ibn_off + 2..ibn_off + 2 + 5].copy_from_slice(b"Sleep");
        d[dll_off..dll_off + 12].copy_from_slice(b"kernel32.dll");

        let sections = vec![Section {
            name: ".didat".into(),
            rva: RVA,
            virtual_size: 0x100,
            data: d,
            readable: true,
            writable: true,
            executable: false,
        }];

        let imports = parse_delay_imports(&sections, RVA, 0x1_4000_0000, true).unwrap();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].dll, "kernel32.dll");
        assert_eq!(imports[0].symbol, ImportSymbol::Named("Sleep".into()));
        assert_eq!(imports[0].iat_rva, RVA + iat_off as u32);
        assert_eq!(imports[1].symbol, ImportSymbol::Ordinal(1));
        assert_eq!(imports[1].iat_rva, RVA + iat_off as u32 + 8);
    }

    #[test]
    fn import_by_ordinal_sets_ordinal_symbol() {
        const RVA: u32 = 0x1000;
        let ilt_off = 40usize;
        let iat_off = ilt_off + 16;
        let dll_off = iat_off + 16;
        let mut d = vec![0u8; 0x80];
        put_le32(&mut d, 0, RVA + ilt_off as u32);
        put_le32(&mut d, 12, RVA + dll_off as u32);
        put_le32(&mut d, 16, RVA + iat_off as u32);
        d[ilt_off..ilt_off + 8].copy_from_slice(&ordinal_thunk_64(7).to_le_bytes());
        d[dll_off..dll_off + 5].copy_from_slice(b"a.dll");

        let sections = vec![Section {
            name: ".idata".into(),
            rva: RVA,
            virtual_size: 0x80,
            data: d,
            readable: true,
            writable: true,
            executable: false,
        }];
        let imports = parse_imports(&sections, RVA, true).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "a.dll");
        assert_eq!(imports[0].symbol, ImportSymbol::Ordinal(7));
        assert_eq!(imports[0].iat_rva, RVA + iat_off as u32);
    }

    fn one_section(rva: u32, virtual_size: u32, data: Vec<u8>) -> Vec<Section> {
        vec![Section {
            name: ".t".into(),
            rva,
            virtual_size,
            data,
            readable: true,
            writable: false,
            executable: false,
        }]
    }

    #[test]
    fn string_rva_in_the_zero_filled_tail_is_an_error() {
        let sections = one_section(0x1000, 0x1000, vec![b'a'; 0x10]);
        assert!(cstr_at_rva(&sections, 0x1800).is_err());
    }

    #[test]
    fn rva_arithmetic_at_the_top_of_the_address_space_does_not_panic() {
        let sections = one_section(u32::MAX - 0x10, 0x100, vec![0; 0x10]);
        assert!(slice_u32(&sections, u32::MAX - 2).is_err());
        assert!(parse_exports(&sections, u32::MAX - 0x10, 0x100).is_err());
        assert!(parse_relocs(&sections, u32::MAX - 0x10, u32::MAX).is_ok());
    }

    const TEST_SEC_TABLE: usize = 0x80 + 4 + 20 + 0xF0;

    fn pe_with_sections(
        count: u16,
        file_len: usize,
        header: impl Fn(usize) -> (u32, u32, u32, u32),
    ) -> Vec<u8> {
        let mut f = minimal_pe_no_tls();
        f.resize(file_len.max(TEST_SEC_TABLE + usize::from(count) * SECTION_HEADER_SIZE), 0);
        f[0x80 + 4 + 2..0x80 + 4 + 4].copy_from_slice(&count.to_le_bytes());
        let template = f[TEST_SEC_TABLE..TEST_SEC_TABLE + SECTION_HEADER_SIZE].to_vec();
        for i in 0..usize::from(count) {
            let s = TEST_SEC_TABLE + i * SECTION_HEADER_SIZE;
            f[s..s + SECTION_HEADER_SIZE].copy_from_slice(&template);
            let (rva, virtual_size, size_raw, ptr_raw) = header(i);
            put_le32(&mut f, s + 8, virtual_size);
            put_le32(&mut f, s + 12, rva);
            put_le32(&mut f, s + 16, size_raw);
            put_le32(&mut f, s + 20, ptr_raw);
        }
        f
    }

    #[test]
    fn sections_sharing_raw_data_load() {
        let len = 0x600u32;
        let f = pe_with_sections(2, len as usize, |i| (0x1000 * (i as u32 + 1), 0x1000, len, 0));
        let pe = parse(&f).expect("two sections over the same file bytes are a valid image");
        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.sections[0].data, f);
        assert_eq!(pe.sections[1].data, f);
    }

    #[test]
    fn a_mutated_section_count_over_one_virtual_range_is_refused() {
        let f = pe_with_sections(1000, 0x10000, |_| (0x1000, 0x1000, 0x10000, 0));
        match parse(&f) {
            Err(EmuError::InvalidPe(why)) => assert!(why.contains("overlaps"), "{why}"),
            other => panic!("expected an overlap refusal, got {:?}", other.map(|p| p.sections.len())),
        }
    }

    #[test]
    fn section_raw_data_stops_at_the_next_section() {
        let len = 0x4000u32;
        let f = pe_with_sections(64, len as usize, |i| (0x1000 * (i as u32 + 1), 0x10, len, 0));
        let pe = parse(&f).expect("ascending sections with small virtual sizes are a valid layout");
        let (last, rest) = pe.sections.split_last().unwrap();
        assert!(rest.iter().all(|s| s.data.len() == 0x1000));
        assert_eq!(last.data.len(), len as usize);
        let copied: usize = pe.sections.iter().map(|s| s.data.len()).sum();
        assert_eq!(copied, 63 * 0x1000 + len as usize);
    }

    fn put_le32(d: &mut [u8], off: usize, v: u32) {
        d[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}
