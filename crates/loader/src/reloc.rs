use exemu_core::{EmuError, Reloc, Result, Section};

const REL_HIGHLOW: u8 = 3;
const REL_DIR64: u8 = 10;

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
    crate::slice_u32(sections, rva)
}

fn read_u64(sections: &[Section], rva: u32) -> Result<u64> {
    let b = slice_ref(sections, rva, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Ok(u64::from_le_bytes(arr))
}

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

    fn fixture() -> Vec<Section> {
        let mut data = vec![0u8; 0x40];
        data[0x10..0x18].copy_from_slice(&0x0000_0001_4000_1234u64.to_le_bytes());
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
        let preferred = 0x0000_0001_4000_0000u64;
        let actual = 0x0000_0001_4060_0000u64;
        let delta = actual - preferred;
        apply(&mut sections, &relocs, preferred, actual).unwrap();

        let d = &sections[0].data;
        assert_eq!(
            &d[0x10..0x18],
            &0x0000_0001_4060_1234u64.to_le_bytes(),
            "DIR64 word must be shifted by the full 64-bit delta"
        );
        assert_eq!(&d[0x10..0x18], &[0x34, 0x12, 0x60, 0x40, 0x01, 0x00, 0x00, 0x00]);

        assert_eq!(
            &d[0x20..0x24],
            &0x00A0_5678u32.to_le_bytes(),
            "HIGHLOW word must be shifted by the low 32 bits of the delta"
        );
        assert_eq!(&d[0x20..0x24], &[0x78, 0x56, 0xA0, 0x00]);

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
        let mut sections = fixture();
        let relocs = vec![
            Reloc { rva: 0x1010, kind: REL_DIR64 },
            Reloc { rva: 0x1020, kind: REL_HIGHLOW },
        ];
        apply(&mut sections, &relocs, 0x1_4000_0000, 0x1_3FFF_F000).unwrap();
        let d = &sections[0].data;
        assert_eq!(&d[0x10..0x18], &0x0000_0001_4000_0234u64.to_le_bytes());
        assert_eq!(&d[0x20..0x24], &0x0040_4678u32.to_le_bytes());
    }

    #[test]
    fn unknown_type_rejected() {
        let mut sections = fixture();
        let relocs = vec![Reloc { rva: 0x1010, kind: 1  }];
        assert!(matches!(apply(&mut sections, &relocs, 0, 0x1000), Err(EmuError::InvalidPe(_))));
    }
}
