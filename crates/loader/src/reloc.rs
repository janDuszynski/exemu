//! Base-relocation application (PE `.reloc` / `IMAGE_DIRECTORY_ENTRY_BASERELOC`).
//!
//! The [`parse`](crate::parse) step already turns the relocation blocks into a
//! flat [`Reloc`] list (page-RVA + type per fixup). This module *applies* those
//! fixups: when an image is mapped at a load address other than its preferred
//! `ImageBase`, every absolute address baked into the image must be shifted by
//! the **load delta** = `actual_base - preferred_base`.
//!
//! Only the two fixup types x86/x86-64 PE images actually emit are handled:
//!
//! * `IMAGE_REL_BASED_HIGHLOW` (3): add the low 32 bits of the delta to the
//!   32-bit little-endian word at the target (used by PE32 images).
//! * `IMAGE_REL_BASED_DIR64` (10): add the full 64-bit delta to the 64-bit
//!   little-endian word at the target (used by PE32+ images).
//!
//! `IMAGE_REL_BASED_ABSOLUTE` (0) is padding and is already dropped during
//! parsing, so it never reaches this code. Any other type is rejected — silently
//! ignoring it would leave a half-relocated image, which is worse than failing.
//!
//! Semantics are derived from the public PE/COFF specification (§"The .reloc
//! Section" / "Base Relocation Types").

use exemu_core::{EmuError, Reloc, Result, Section};

/// `IMAGE_REL_BASED_HIGHLOW` — 32-bit field.
const REL_HIGHLOW: u8 = 3;
/// `IMAGE_REL_BASED_DIR64` — 64-bit field.
const REL_DIR64: u8 = 10;

/// Apply base relocations to `sections`, patching absolute addresses in place
/// so the image is correct when loaded at `actual_base` instead of
/// `preferred_base`.
///
/// A zero delta is a no-op fast path (the image loaded at its preferred base),
/// but the fixups are still validated so a corrupt `.reloc` is caught either
/// way. Each patched word is read from and written back into the containing
/// section's `data`, which the caller subsequently maps into guest memory.
pub fn apply(
    sections: &mut [Section],
    relocations: &[Reloc],
    preferred_base: u64,
    actual_base: u64,
) -> Result<()> {
    let delta = actual_base.wrapping_sub(preferred_base);
    for r in relocations {
        match r.kind {
            REL_HIGHLOW => {
                let old = read_u32(sections, r.rva)?;
                // The low 32 bits of the delta, added with 32-bit wraparound.
                let new = old.wrapping_add(delta as u32);
                write_u32(sections, r.rva, new)?;
            }
            REL_DIR64 => {
                let old = read_u64(sections, r.rva)?;
                let new = old.wrapping_add(delta);
                write_u64(sections, r.rva, new)?;
            }
            other => {
                return Err(EmuError::InvalidPe(format!(
                    "unsupported base-relocation type {other} at rva {:#x}",
                    r.rva
                )));
            }
        }
    }
    Ok(())
}

/// Locate the mutable slice of length `len` at `rva` inside whichever section
/// contains it. A fixup that straddles a section boundary (or runs past the
/// backing `data`) is a malformed `.reloc` and is rejected.
fn slice_mut(sections: &mut [Section], rva: u32, len: usize) -> Result<&mut [u8]> {
    for s in sections.iter_mut() {
        let vsize = s.virtual_size.max(s.data.len() as u32);
        if rva >= s.rva && rva < s.rva + vsize {
            let off = (rva - s.rva) as usize;
            return s.data.get_mut(off..off + len).ok_or_else(|| {
                EmuError::InvalidPe(format!("relocation at rva {rva:#x} past section data"))
            });
        }
    }
    Err(EmuError::InvalidPe(format!("relocation rva {rva:#x} not in any section")))
}

fn read_u32(sections: &[Section], rva: u32) -> Result<u32> {
    // Reuse the shared bounds-checked reader in the parent module.
    crate::slice_u32(sections, rva)
}

fn read_u64(sections: &[Section], rva: u32) -> Result<u64> {
    let b = slice_ref(sections, rva, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Ok(u64::from_le_bytes(arr))
}

/// Immutable counterpart of [`slice_mut`], for reading the field before patching.
fn slice_ref(sections: &[Section], rva: u32, len: usize) -> Result<&[u8]> {
    for s in sections.iter() {
        let vsize = s.virtual_size.max(s.data.len() as u32);
        if rva >= s.rva && rva < s.rva + vsize {
            let off = (rva - s.rva) as usize;
            return s.data.get(off..off + len).ok_or_else(|| {
                EmuError::InvalidPe(format!("relocation at rva {rva:#x} past section data"))
            });
        }
    }
    Err(EmuError::InvalidPe(format!("relocation rva {rva:#x} not in any section")))
}

fn write_u32(sections: &mut [Section], rva: u32, v: u32) -> Result<()> {
    let dst = slice_mut(sections, rva, 4)?;
    dst.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u64(sections: &mut [Section], rva: u32, v: u64) -> Result<()> {
    let dst = slice_mut(sections, rva, 8)?;
    dst.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One section starting at RVA 0x1000 with a known byte pattern holding two
    /// absolute pointers: a DIR64 at +0x10 and a HIGHLOW at +0x20.
    fn fixture() -> Vec<Section> {
        let mut data = vec![0u8; 0x40];
        // DIR64 field at offset 0x10: preferred absolute 0x1_4000_1234.
        data[0x10..0x18].copy_from_slice(&0x0000_0001_4000_1234u64.to_le_bytes());
        // HIGHLOW field at offset 0x20: preferred absolute 0x0040_5678.
        data[0x20..0x24].copy_from_slice(&0x0040_5678u32.to_le_bytes());
        vec![Section {
            name: ".data".into(),
            rva: 0x1000,
            virtual_size: 0x40,
            data,
            readable: true,
            writable: true,
            executable: false,
        }]
    }

    #[test]
    fn dir64_and_highlow_exact_byte_diff() {
        let mut sections = fixture();
        let relocs = vec![
            Reloc { rva: 0x1010, kind: REL_DIR64 },
            Reloc { rva: 0x1020, kind: REL_HIGHLOW },
        ];
        // Preferred base 0x1_4000_0000, load 0x60_0000 higher.
        let preferred = 0x0000_0001_4000_0000u64;
        let actual = 0x0000_0001_4060_0000u64;
        let delta = actual - preferred; // 0x60_0000
        apply(&mut sections, &relocs, preferred, actual).unwrap();

        let d = &sections[0].data;
        // DIR64: 0x1_4000_1234 + 0x60_0000 = 0x1_4060_1234.
        assert_eq!(
            &d[0x10..0x18],
            &0x0000_0001_4060_1234u64.to_le_bytes(),
            "DIR64 word must be shifted by the full 64-bit delta"
        );
        // Hand-computed byte layout, little-endian: 34 12 60 40 01 00 00 00.
        assert_eq!(&d[0x10..0x18], &[0x34, 0x12, 0x60, 0x40, 0x01, 0x00, 0x00, 0x00]);

        // HIGHLOW: 0x0040_5678 + (delta as u32 = 0x60_0000) = 0x00A0_5678.
        assert_eq!(
            &d[0x20..0x24],
            &0x00A0_5678u32.to_le_bytes(),
            "HIGHLOW word must be shifted by the low 32 bits of the delta"
        );
        assert_eq!(&d[0x20..0x24], &[0x78, 0x56, 0xA0, 0x00]);

        // Untouched padding stays zero.
        assert!(d[0x00..0x10].iter().all(|&b| b == 0));
        assert!(d[0x18..0x20].iter().all(|&b| b == 0));
        assert!(d[0x24..0x40].iter().all(|&b| b == 0));
        let _ = delta;
    }

    #[test]
    fn zero_delta_is_identity() {
        let mut sections = fixture();
        let before = sections[0].data.clone();
        let relocs = vec![
            Reloc { rva: 0x1010, kind: REL_DIR64 },
            Reloc { rva: 0x1020, kind: REL_HIGHLOW },
        ];
        apply(&mut sections, &relocs, 0x1_4000_0000, 0x1_4000_0000).unwrap();
        assert_eq!(sections[0].data, before, "loading at the preferred base changes nothing");
    }

    #[test]
    fn negative_delta_wraps_correctly() {
        // Load 0x1000 *below* the preferred base: the pointers must decrease.
        let mut sections = fixture();
        let relocs = vec![
            Reloc { rva: 0x1010, kind: REL_DIR64 },
            Reloc { rva: 0x1020, kind: REL_HIGHLOW },
        ];
        apply(&mut sections, &relocs, 0x1_4000_0000, 0x1_3FFF_F000).unwrap();
        let d = &sections[0].data;
        // 0x1_4000_1234 - 0x1000 = 0x1_4000_0234.
        assert_eq!(&d[0x10..0x18], &0x0000_0001_4000_0234u64.to_le_bytes());
        // 0x0040_5678 - 0x1000 = 0x0040_4678.
        assert_eq!(&d[0x20..0x24], &0x0040_4678u32.to_le_bytes());
    }

    #[test]
    fn unknown_type_rejected() {
        let mut sections = fixture();
        let relocs = vec![Reloc { rva: 0x1010, kind: 1 /* HIGH */ }];
        assert!(matches!(apply(&mut sections, &relocs, 0, 0x1000), Err(EmuError::InvalidPe(_))));
    }
}
