//! # exemu-loader — PE64 parsing
//!
//! Turns the raw bytes of a Windows `.exe` into a [`PeImage`] the rest of
//! the emulator can map and run. Only the 64-bit PE32+ format is supported
//! (which is what x86-64 executables use).
//!
//! The parser is intentionally strict about the few fields it relies on and
//! forgiving about the rest: it validates the magic numbers and machine
//! type, then extracts sections and the import table. It does not process
//! relocations — images are mapped at their preferred `ImageBase`.

#![forbid(unsafe_code)]

mod reader;
mod resources;

pub use resources::parse_dialogs;

use exemu_core::{EmuError, Import, ImportSymbol, PeImage, Result, Section};
use reader::Reader;

// --- On-disk constants -------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_I386: u16 = 0x014c;
const OPT_MAGIC_PE32: u16 = 0x10B;
const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

const E_LFANEW_OFFSET: usize = 0x3C;

// Optional-header field offsets that are identical in PE32 and PE32+.
const OPT_ENTRY: usize = 16;
const OPT_SIZE_OF_IMAGE: usize = 56;
const OPT_SIZE_OF_HEADERS: usize = 60;
const OPT_SUBSYSTEM: usize = 68;

// Data-directory indices.
const DIR_IMPORT: usize = 1;

// Section characteristics bits.
const SCN_CNT_UNINIT_DATA: u32 = 0x0000_0080;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Parse a PE executable (PE32 or PE32+) from its raw bytes.
pub fn parse(bytes: &[u8]) -> Result<PeImage> {
    let r = Reader::new(bytes);

    // ---- DOS header ------------------------------------------------------
    if r.u16(0)? != DOS_MAGIC {
        return Err(EmuError::InvalidPe("missing 'MZ' DOS signature".into()));
    }
    let pe_off = r.u32(E_LFANEW_OFFSET)? as usize;

    // ---- PE / COFF header ------------------------------------------------
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

    // ---- Optional header (PE32 or PE32+) ---------------------------------
    // The two formats share the standard fields but differ in where the
    // image base and the 64-bit-vs-32-bit quadword fields sit.
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
    // Fields at 56/60/68 are identically placed in both formats; the image
    // base, stack reserve and directory table are not.
    let size_of_image = r.u32(opt + OPT_SIZE_OF_IMAGE)?;
    let size_of_headers = r.u32(opt + OPT_SIZE_OF_HEADERS)?;
    let subsystem = r.u16(opt + OPT_SUBSYSTEM)?;
    let (image_base, stack_reserve, num_dirs_off, data_dirs_off) = if is_64bit {
        (r.u64(opt + 24)?, r.u64(opt + 72)?, 108usize, 112usize)
    } else {
        (r.u32(opt + 28)? as u64, r.u32(opt + 72)? as u64, 92usize, 96usize)
    };
    let num_dirs = r.u32(opt + num_dirs_off)? as usize;

    // Import data directory (may be absent).
    let (import_dir_rva, import_dir_size) = if num_dirs > DIR_IMPORT {
        let base = opt + data_dirs_off + DIR_IMPORT * 8;
        (r.u32(base)?, r.u32(base + 4)?)
    } else {
        (0, 0)
    };

    // ---- Section table ---------------------------------------------------
    let sec_table = opt + size_opt_header;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let name = {
            let raw = r.bytes(s, 8)?;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        let virtual_size = r.u32(s + 8)?;
        let rva = r.u32(s + 12)?;
        let size_raw = r.u32(s + 16)? as usize;
        let ptr_raw = r.u32(s + 20)? as usize;
        let chars = r.u32(s + 36)?;

        let data = if size_raw == 0 || chars & SCN_CNT_UNINIT_DATA != 0 {
            Vec::new()
        } else {
            // Clamp to the file end; some linkers pad SizeOfRawData beyond EOF.
            let avail = r.len().saturating_sub(ptr_raw).min(size_raw);
            r.bytes(ptr_raw, avail)?
        };

        sections.push(Section {
            name,
            rva,
            virtual_size,
            data,
            readable: chars & SCN_MEM_READ != 0,
            writable: chars & SCN_MEM_WRITE != 0,
            executable: chars & SCN_MEM_EXECUTE != 0,
        });
    }

    // ---- Imports ---------------------------------------------------------
    let imports = if import_dir_rva != 0 && import_dir_size != 0 {
        parse_imports(&sections, import_dir_rva, is_64bit)?
    } else {
        Vec::new()
    };

    let headers = r.bytes(0, (size_of_headers as usize).min(r.len()))?;

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
        headers,
    })
}

/// Read bytes living at a given RVA out of whichever section contains it.
/// Returns the containing section plus the intra-section offset so callers
/// can slice `section.data`.
fn read_at_rva(sections: &[Section], rva: u32) -> Option<(&Section, usize)> {
    for s in sections {
        let vsize = s.virtual_size.max(s.data.len() as u32);
        if rva >= s.rva && rva < s.rva + vsize {
            return Some((s, (rva - s.rva) as usize));
        }
    }
    None
}

fn slice_u32(sections: &[Section], rva: u32) -> Result<u32> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    let b = s
        .data
        .get(off..off + 4)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn slice_u64(sections: &[Section], rva: u32) -> Result<u64> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} not in any section")))?;
    let b = s
        .data
        .get(off..off + 8)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Ok(u64::from_le_bytes(arr))
}

fn cstr_at_rva(sections: &[Section], rva: u32) -> Result<String> {
    let (s, off) = read_at_rva(sections, rva)
        .ok_or_else(|| EmuError::InvalidPe(format!("string rva {rva:#x} not in any section")))?;
    let end = s.data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(s.data.len());
    Ok(String::from_utf8_lossy(&s.data[off..end]).into_owned())
}

/// Walk the import directory, producing one [`Import`] per symbol with the
/// RVA of the IAT slot that must be patched at load time. Thunk entries are
/// 8 bytes for PE32+ and 4 bytes for PE32.
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
        let name_rva = slice_u32(sections, desc + 12)?;
        let first_thunk = slice_u32(sections, desc + 16)?;

        // An all-zero descriptor terminates the array.
        if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll = cstr_at_rva(sections, name_rva)?.to_ascii_lowercase();

        // Prefer the Import Lookup Table; fall back to the IAT if absent.
        let lookup = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };

        let mut i = 0u32;
        loop {
            let thunk = read_thunk(sections, lookup + i * thunk_size)?;
            if thunk == 0 {
                break;
            }
            let iat_rva = first_thunk + i * thunk_size;
            let symbol = if thunk & ordinal_flag != 0 {
                ImportSymbol::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                let by_name_rva = (thunk & 0x7FFF_FFFF) as u32;
                // IMAGE_IMPORT_BY_NAME = { Hint: u16, Name: asciiz }
                ImportSymbol::Named(cstr_at_rva(sections, by_name_rva + 2)?)
            };
            imports.push(Import { dll: dll.clone(), symbol, iat_rva });
            i += 1;
        }

        desc += 20;
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
}
