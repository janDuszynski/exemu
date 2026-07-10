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
mod reloc;
mod resources;
mod unwind;

pub use reloc::apply as apply_relocations;
pub use resources::parse_dialogs;

use exemu_core::{EmuError, Export, Import, ImportSymbol, PeImage, Reloc, Result, Section, Tls};
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
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;

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

    // Data directories (each may be absent).
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

    // ---- Exports (DLLs) --------------------------------------------------
    let (exports, dll_name) = if export_dir_rva != 0 && export_dir_size != 0 {
        parse_exports(&sections, export_dir_rva).unwrap_or_default()
    } else {
        (Vec::new(), None)
    };

    // ---- Base relocations ------------------------------------------------
    let relocations = if reloc_dir_rva != 0 && reloc_dir_size != 0 {
        parse_relocs(&sections, reloc_dir_rva, reloc_dir_size).unwrap_or_default()
    } else {
        Vec::new()
    };

    // ---- Thread-local storage directory ----------------------------------
    // A missing directory is the common case (most images have no static
    // TLS). A present-but-corrupt directory is tolerated (best-effort parse)
    // rather than failing the whole load — the template/callbacks simply come
    // back empty, matching the "no TLS" behaviour.
    let tls = if tls_dir_rva != 0 {
        parse_tls(&sections, tls_dir_rva, image_base, is_64bit).ok()
    } else {
        None
    };

    // ---- x64 exception function table (.pdata/.xdata) ---------------------
    // 32-bit x86 uses the fs:[0] SEH chain instead; its directory 3 (when
    // present at all) holds a different format, so parse only for PE32+.
    let function_table = if is_64bit && exc_dir_rva != 0 && exc_dir_size != 0 {
        unwind::parse_function_table(&sections, exc_dir_rva, exc_dir_size)
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
        exports,
        relocations,
        tls,
        dll_name,
        headers,
        function_table,
    })
}

/// Parse the export directory into a flat list of exports (resolving name and
/// ordinal tables) plus the module's own name.
fn parse_exports(sections: &[Section], dir_rva: u32) -> Result<(Vec<Export>, Option<String>)> {
    let ordinal_base = slice_u32(sections, dir_rva + 16)?;
    let num_funcs = slice_u32(sections, dir_rva + 20)?;
    let num_names = slice_u32(sections, dir_rva + 24)?;
    let funcs_rva = slice_u32(sections, dir_rva + 28)?;
    let names_rva = slice_u32(sections, dir_rva + 32)?;
    let ords_rva = slice_u32(sections, dir_rva + 36)?;
    let name_ptr = slice_u32(sections, dir_rva + 12)?;
    let dll_name = if name_ptr != 0 { cstr_at_rva(sections, name_ptr).ok() } else { None };

    // Map each function index → its exported name (if any).
    let mut names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    for i in 0..num_names {
        let name_rva = slice_u32(sections, names_rva + i * 4)?;
        let ord_index = slice_u16(sections, ords_rva + i * 2)? as u32; // index into funcs
        if let Ok(nm) = cstr_at_rva(sections, name_rva) {
            names.insert(ord_index, nm);
        }
    }

    let mut exports = Vec::new();
    for i in 0..num_funcs {
        let func_rva = slice_u32(sections, funcs_rva + i * 4)?;
        if func_rva == 0 {
            continue; // empty slot
        }
        exports.push(Export {
            name: names.get(&i).cloned(),
            ordinal: (ordinal_base + i) as u16,
            rva: func_rva,
        });
    }
    Ok((exports, dll_name))
}

/// Parse the base-relocation blocks into a flat list of fixups.
fn parse_relocs(sections: &[Section], dir_rva: u32, dir_size: u32) -> Result<Vec<Reloc>> {
    let mut relocs = Vec::new();
    let mut off = 0u32;
    while off + 8 <= dir_size {
        let page_rva = slice_u32(sections, dir_rva + off)?;
        let block_size = slice_u32(sections, dir_rva + off + 4)?;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for e in 0..entries {
            let v = slice_u16(sections, dir_rva + off + 8 + e * 2)?;
            let kind = (v >> 12) as u8;
            let word_off = (v & 0x0FFF) as u32;
            if kind != 0 {
                // Skip IMAGE_REL_BASED_ABSOLUTE (0), a padding no-op.
                relocs.push(Reloc { rva: page_rva + word_off, kind });
            }
        }
        off += block_size;
    }
    Ok(relocs)
}

/// Parse the `IMAGE_TLS_DIRECTORY` (32-bit or 64-bit form) at `dir_rva`.
///
/// Layout (per the PE/COFF spec's `.tls` section / public `winnt.h`), where
/// each pointer field is 4 bytes for PE32 and 8 bytes for PE32+:
///
/// ```text
///   +0   StartAddressOfRawData   (VA)
///   + p   EndAddressOfRawData     (VA)
///   +2p  AddressOfIndex          (VA)
///   +3p  AddressOfCallBacks      (VA of null-terminated VA array)
///   +4p  SizeOfZeroFill          (DWORD)
///   +4p+4 Characteristics        (DWORD)
/// ```
///
/// The four address fields are **virtual addresses** (`image_base + rva`), so
/// this converts each back to an RVA (by subtracting `image_base`) before
/// reading the referenced bytes out of the sections. The initialization
/// template `[Start, End)` is copied out, and the `AddressOfCallBacks` array
/// is walked to its null terminator, each entry recorded as an `image_base`
/// relative RVA.
fn parse_tls(sections: &[Section], dir_rva: u32, image_base: u64, is_64bit: bool) -> Result<Tls> {
    // Read one pointer-sized field (4 bytes on PE32, 8 on PE32+).
    let ptr = |rva: u32| -> Result<u64> {
        if is_64bit {
            slice_u64(sections, rva)
        } else {
            slice_u32(sections, rva).map(u64::from)
        }
    };
    let p: u32 = if is_64bit { 8 } else { 4 };

    let start_address_of_raw_data = ptr(dir_rva)?;
    let end_address_of_raw_data = ptr(dir_rva + p)?;
    let address_of_index = ptr(dir_rva + 2 * p)?;
    let address_of_callbacks = ptr(dir_rva + 3 * p)?;
    let size_of_zero_fill = slice_u32(sections, dir_rva + 4 * p)?;
    let characteristics = slice_u32(sections, dir_rva + 4 * p + 4)?;

    // Convert a stored VA to an image-relative RVA, if it falls at or above
    // the preferred base. VAs below the base (or a zero VA) yield None.
    let va_to_rva = |va: u64| -> Option<u32> {
        if va == 0 {
            return None;
        }
        va.checked_sub(image_base).and_then(|off| u32::try_from(off).ok())
    };

    // Copy the raw initialization template out of [Start, End).
    let raw_template = match (va_to_rva(start_address_of_raw_data), end_address_of_raw_data) {
        (Some(start_rva), end) if end > start_address_of_raw_data => {
            let len = (end - start_address_of_raw_data) as usize;
            let mut buf = Vec::with_capacity(len);
            let mut ok = true;
            for i in 0..len {
                match slice_u8(sections, start_rva + i as u32) {
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

    // Walk the null-terminated array of callback VAs.
    let mut callback_rvas = Vec::new();
    if let Some(mut arr_rva) = va_to_rva(address_of_callbacks) {
        // Stop on a read error (corrupt/truncated array) or the null
        // terminator, keeping whatever was collected so far.
        while let Ok(cb_va) = ptr(arr_rva) {
            if cb_va == 0 {
                break; // null terminator
            }
            match va_to_rva(cb_va) {
                Some(rva) => callback_rvas.push(rva),
                None => break, // implausible callback VA — stop
            }
            arr_rva += p;
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
        .get(off..off + 2)
        .ok_or_else(|| EmuError::InvalidPe(format!("rva {rva:#x} past section data")))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn slice_u32(sections: &[Section], rva: u32) -> Result<u32> {
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

    /// Build one `.tls`-like section at `rva` holding a 64-bit
    /// `IMAGE_TLS_DIRECTORY`, a one-entry (+ null) callback array, and a small
    /// initialization template, all laid out at hand so the byte offsets are
    /// unambiguous. Returns the section and the directory RVA.
    fn tls_fixture_64(image_base: u64) -> (Vec<Section>, u32) {
        // Section starts at RVA 0x1000. Layout inside its data:
        //   +0x00  TLS directory (40 bytes)
        //   +0x40  callback array: [cb_va, 0]  (16 bytes)
        //   +0x60  template bytes  (4 bytes: DE AD BE EF)
        const SEC_RVA: u32 = 0x1000;
        const DIR_OFF: usize = 0x00;
        const CB_ARR_OFF: usize = 0x40;
        const TMPL_OFF: usize = 0x60;
        const TMPL_LEN: usize = 4;

        let tmpl_rva = SEC_RVA + TMPL_OFF as u32;
        let cb_arr_rva = SEC_RVA + CB_ARR_OFF as u32;
        let cb_target_rva = 0x2345u32; // where the callback function "lives"

        let tmpl_va = image_base + tmpl_rva as u64;
        let cb_arr_va = image_base + cb_arr_rva as u64;
        let cb_va = image_base + cb_target_rva as u64;
        let index_va = image_base + 0x3000; // arbitrary AddressOfIndex

        let mut data = vec![0u8; 0x80];
        // TLS directory (PE32+ pointers are 8 bytes each).
        data[DIR_OFF..DIR_OFF + 8].copy_from_slice(&tmpl_va.to_le_bytes()); // Start
        data[DIR_OFF + 8..DIR_OFF + 16]
            .copy_from_slice(&(tmpl_va + TMPL_LEN as u64).to_le_bytes()); // End
        data[DIR_OFF + 16..DIR_OFF + 24].copy_from_slice(&index_va.to_le_bytes()); // AddressOfIndex
        data[DIR_OFF + 24..DIR_OFF + 32].copy_from_slice(&cb_arr_va.to_le_bytes()); // AddressOfCallBacks
        data[DIR_OFF + 32..DIR_OFF + 36].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfZeroFill
        data[DIR_OFF + 36..DIR_OFF + 40].copy_from_slice(&0x0030_0000u32.to_le_bytes()); // Characteristics (align)

        // Callback array: one real callback then the null terminator.
        data[CB_ARR_OFF..CB_ARR_OFF + 8].copy_from_slice(&cb_va.to_le_bytes());
        data[CB_ARR_OFF + 8..CB_ARR_OFF + 16].copy_from_slice(&0u64.to_le_bytes());

        // Template contents.
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

        // Field VAs are recorded verbatim.
        assert_eq!(tls.start_address_of_raw_data, image_base + 0x1060);
        assert_eq!(tls.end_address_of_raw_data, image_base + 0x1064);
        assert_eq!(tls.address_of_index, image_base + 0x3000);
        assert_eq!(tls.address_of_callbacks, image_base + 0x1040);
        assert_eq!(tls.size_of_zero_fill, 0x100);
        assert_eq!(tls.characteristics, 0x0030_0000);

        // Template copied out of [Start, End).
        assert_eq!(tls.raw_template, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // Exactly one callback, recorded as an image_base-relative RVA (the
        // null terminator is dropped).
        assert_eq!(tls.callback_rvas, vec![0x2345]);
    }

    #[test]
    fn tls_directory_32_uses_4byte_pointers() {
        // Same shape, but a 32-bit directory: pointers are 4 bytes wide, so
        // SizeOfZeroFill/Characteristics land at +16/+20.
        const SEC_RVA: u32 = 0x1000;
        let image_base = 0x0040_0000u64;
        let tmpl_rva = SEC_RVA + 0x60;
        let cb_arr_rva = SEC_RVA + 0x40;
        let cb_target_rva = 0x1234u32;

        let mut data = vec![0u8; 0x80];
        let put32 = |d: &mut [u8], off: usize, v: u32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        // Directory (4-byte VAs — image_base 0x400000 fits in 32 bits).
        put32(&mut data, 0x00, (image_base as u32) + tmpl_rva); // Start
        put32(&mut data, 0x04, (image_base as u32) + tmpl_rva + 4); // End
        put32(&mut data, 0x08, (image_base as u32) + 0x3000); // AddressOfIndex
        put32(&mut data, 0x0C, (image_base as u32) + cb_arr_rva); // AddressOfCallBacks
        put32(&mut data, 0x10, 0x40); // SizeOfZeroFill
        put32(&mut data, 0x14, 0x00A0_0000); // Characteristics
        // Callback array (4-byte entries): one callback + null.
        put32(&mut data, 0x40, (image_base as u32) + cb_target_rva);
        put32(&mut data, 0x44, 0);
        // Template.
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
        // AddressOfCallBacks points straight at a null terminator.
        const SEC_RVA: u32 = 0x1000;
        let image_base = 0x1_4000_0000u64;
        let cb_arr_rva = SEC_RVA + 0x40;
        let mut data = vec![0u8; 0x80];
        // Zero template (Start == End == 0), index 0, callbacks -> empty array.
        data[24..32].copy_from_slice(&(image_base + cb_arr_rva as u64).to_le_bytes());
        // The array's first (and only) entry is the null terminator (already 0).
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
        // A full hand-built minimal PE32+ with no TLS data directory must
        // parse with `tls == None`.
        let bytes = minimal_pe_no_tls();
        let img = parse(&bytes).expect("minimal PE should parse");
        assert!(img.tls.is_none());
    }

    /// A minimal valid PE32+ image with two sections and no data directories
    /// populated — used to prove the absence of a TLS directory yields `None`.
    fn minimal_pe_no_tls() -> Vec<u8> {
        // 0x400 headers + one 0x200 section body is plenty.
        let mut f = vec![0u8; 0x600];
        // DOS header.
        f[0] = 0x4D;
        f[1] = 0x5A; // "MZ"
        let pe_off = 0x80usize;
        f[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(pe_off as u32).to_le_bytes());
        // PE signature.
        f[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        let coff = pe_off + 4;
        f[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes()); // Machine
        f[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        let size_opt = 0xF0u16; // room for 16 data dirs
        f[coff + 16..coff + 18].copy_from_slice(&size_opt.to_le_bytes()); // SizeOfOptionalHeader
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes()); // magic
        f[opt + OPT_ENTRY..opt + OPT_ENTRY + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
        f[opt + OPT_SIZE_OF_IMAGE..opt + OPT_SIZE_OF_IMAGE + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        f[opt + OPT_SIZE_OF_HEADERS..opt + OPT_SIZE_OF_HEADERS + 4]
            .copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        f[opt + OPT_SUBSYSTEM..opt + OPT_SUBSYSTEM + 2].copy_from_slice(&3u16.to_le_bytes()); // console
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // All 16 data directories left zero (no TLS, no imports, etc.).

        // Section table (immediately after the optional header).
        let sec = opt + size_opt as usize;
        f[sec..sec + 5].copy_from_slice(b".text");
        f[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        f[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        f[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        f[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        f[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ
        f
    }
}
