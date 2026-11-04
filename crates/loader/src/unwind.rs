use exemu_core::{EmuError, Result, Section, UnwindCode, UnwindEntry, UnwindInfo, UnwindOp};

use crate::{slice_u16, slice_u32, slice_u8};

const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

const MAX_CHAIN_DEPTH: u8 = 8;

pub(crate) fn parse_function_table(
    sections: &[Section],
    dir_rva: u32,
    dir_size: u32,
) -> Vec<UnwindEntry> {
    let mut table = Vec::new();
    let readable_end = sections
        .iter()
        .map(|s| u64::from(s.rva) + s.data.len() as u64)
        .max()
        .unwrap_or(0);
    let readable = readable_end.saturating_sub(u64::from(dir_rva)) / 12;
    let count = (dir_size / 12).min(u32::try_from(readable).unwrap_or(u32::MAX));
    for i in 0..count {
        let rec = dir_rva.wrapping_add(i * 12);
        let Ok(entry) = parse_runtime_function(sections, rec, 0) else { continue };
        let Some(entry) = entry else { continue };
        table.push(entry);
    }
    table.sort_by_key(|e| e.begin_rva);
    table
}

fn parse_runtime_function(
    sections: &[Section],
    rec_rva: u32,
    depth: u8,
) -> Result<Option<UnwindEntry>> {
    let begin_rva = slice_u32(sections, rec_rva)?;
    let end_rva = slice_u32(sections, rec_rva.wrapping_add(4))?;
    let unwind_rva = slice_u32(sections, rec_rva.wrapping_add(8))?;
    if begin_rva == 0 && end_rva == 0 {
        return Ok(None);
    }
    if end_rva <= begin_rva {
        return Err(EmuError::InvalidPe(format!(
            "RUNTIME_FUNCTION with empty range {begin_rva:#x}..{end_rva:#x}"
        )));
    }
    let info = parse_unwind_info(sections, unwind_rva, depth)?;
    Ok(Some(UnwindEntry { begin_rva, end_rva, record_rva: rec_rva, info }))
}

fn parse_unwind_info(sections: &[Section], rva: u32, depth: u8) -> Result<UnwindInfo> {
    let b0 = slice_u8(sections, rva)?;
    let version = b0 & 0x7;
    let flags = b0 >> 3;
    if version != 1 && version != 2 {
        return Err(EmuError::InvalidPe(format!("UNWIND_INFO version {version}")));
    }
    let prolog_size = slice_u8(sections, rva.wrapping_add(1))?;
    let count = slice_u8(sections, rva.wrapping_add(2))?;
    let b3 = slice_u8(sections, rva.wrapping_add(3))?;
    let frame_register = match b3 & 0xF {
        0 => None,
        r => Some(r),
    };
    let frame_offset = ((b3 >> 4) as u16) * 16;

    let slots_base = rva.wrapping_add(4);
    let slot = |i: u32| -> Result<(u8, u8, u8)> {
        let lo = slice_u8(sections, slots_base.wrapping_add(i * 2))?;
        let hi = slice_u8(sections, slots_base.wrapping_add(i * 2 + 1))?;
        Ok((lo, hi & 0xF, hi >> 4))
    };
    let next_u16 = |i: u32| slice_u16(sections, slots_base.wrapping_add(i * 2));
    let next_u32 = |i: u32| slice_u32(sections, slots_base.wrapping_add(i * 2));

    let mut codes = Vec::new();
    let mut i = 0u32;
    while i < count as u32 {
        let (prolog_offset, op, op_info) = slot(i)?;
        let (op, used) = match op {
            0 => (UnwindOp::PushNonvolatile { reg: op_info }, 1),
            1 => match op_info {
                0 => (UnwindOp::Alloc { size: next_u16(i + 1)? as u32 * 8 }, 2),
                1 => (UnwindOp::Alloc { size: next_u32(i + 1)? }, 3),
                other => {
                    return Err(EmuError::InvalidPe(format!("ALLOC_LARGE op_info {other}")))
                }
            },
            2 => (UnwindOp::Alloc { size: op_info as u32 * 8 + 8 }, 1),
            3 => (UnwindOp::SetFrameRegister, 1),
            4 => (
                UnwindOp::SaveNonvolatile { reg: op_info, offset: next_u16(i + 1)? as u32 * 8 },
                2,
            ),
            5 => (UnwindOp::SaveNonvolatile { reg: op_info, offset: next_u32(i + 1)? }, 3),
            6 if version == 2 => {
                let raw = next_u16(i)?;
                (UnwindOp::Epilog { raw }, 1)
            }
            8 => (
                UnwindOp::SaveXmm128 { reg: op_info, offset: next_u16(i + 1)? as u32 * 16 },
                2,
            ),
            9 => (UnwindOp::SaveXmm128 { reg: op_info, offset: next_u32(i + 1)? }, 3),
            10 => (UnwindOp::PushMachineFrame { with_error_code: op_info == 1 }, 1),
            other => {
                return Err(EmuError::InvalidPe(format!("unwind op {other}")));
            }
        };
        codes.push(UnwindCode { prolog_offset, op });
        i += used;
    }
    if i > count as u32 {
        return Err(EmuError::InvalidPe("unwind codes overrun their count".into()));
    }

    let after_codes = slots_base.wrapping_add(2 * ((count as u32 + 1) & !1));

    let mut handler_rva = None;
    let mut handler_data_rva = None;
    let mut chained = None;
    if flags & UNW_FLAG_CHAININFO != 0 {
        if depth >= MAX_CHAIN_DEPTH {
            return Err(EmuError::InvalidPe("chained unwind info nested too deep".into()));
        }
        match parse_runtime_function(sections, after_codes, depth + 1)? {
            Some(e) => chained = Some(Box::new(e)),
            None => return Err(EmuError::InvalidPe("chained RUNTIME_FUNCTION is zero".into())),
        }
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        handler_rva = Some(slice_u32(sections, after_codes)?);
        handler_data_rva = Some(after_codes.wrapping_add(4));
    }

    Ok(UnwindInfo {
        version,
        has_exception_handler: flags & UNW_FLAG_EHANDLER != 0,
        has_termination_handler: flags & UNW_FLAG_UHANDLER != 0,
        prolog_size,
        frame_register,
        frame_offset,
        codes,
        handler_rva,
        handler_data_rva,
        chained,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(data: Vec<u8>) -> Vec<Section> {
        vec![Section {
            name: ".rdata".into(),
            rva: 0x1000,
            virtual_size: data.len() as u32,
            data,
            readable: true,
            writable: false,
            executable: false,
        }]
    }

    fn rt_func(begin: u32, end: u32, unwind: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&begin.to_le_bytes());
        v.extend_from_slice(&end.to_le_bytes());
        v.extend_from_slice(&unwind.to_le_bytes());
        v
    }

    #[test]
    fn parses_typical_prolog() {
        let mut data = rt_func(0x2000, 0x2080, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[
            0x01,
            0x05,
            0x02,
            0x00,
            0x05, 0x42,
            0x01, 0x50,
        ]);

        let table = parse_function_table(&sec(data), 0x1000, 12);
        assert_eq!(table.len(), 1);
        let e = &table[0];
        assert_eq!((e.begin_rva, e.end_rva), (0x2000, 0x2080));
        assert_eq!(e.info.version, 1);
        assert_eq!(e.info.prolog_size, 5);
        assert_eq!(e.info.frame_register, None);
        assert_eq!(e.info.handler_rva, None);
        assert_eq!(
            e.info.codes,
            vec![
                UnwindCode { prolog_offset: 5, op: UnwindOp::Alloc { size: 0x28 } },
                UnwindCode { prolog_offset: 1, op: UnwindOp::PushNonvolatile { reg: 5 } },
            ]
        );
    }

    #[test]
    fn parses_frame_pointer_and_large_allocs() {
        let mut data = rt_func(0x3000, 0x3100, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[
            0x01,
            0x20,
            0x0a,
            0x25,
            0x20, 0x03,
            0x1c, 0x01, 0x00, 0x10,
            0x18, 0x11, 0x78, 0x56, 0x34, 0x12,
            0x10, 0x34, 0x08, 0x00,
            0x08, 0x68, 0x02, 0x00,
        ]);
        let table = parse_function_table(&sec(data), 0x1000, 12);
        assert_eq!(table.len(), 1);
        let info = &table[0].info;
        assert_eq!(info.frame_register, Some(5));
        assert_eq!(info.frame_offset, 32);
        assert_eq!(
            info.codes,
            vec![
                UnwindCode { prolog_offset: 0x20, op: UnwindOp::SetFrameRegister },
                UnwindCode { prolog_offset: 0x1c, op: UnwindOp::Alloc { size: 0x8000 } },
                UnwindCode { prolog_offset: 0x18, op: UnwindOp::Alloc { size: 0x12345678 } },
                UnwindCode {
                    prolog_offset: 0x10,
                    op: UnwindOp::SaveNonvolatile { reg: 3, offset: 0x40 }
                },
                UnwindCode {
                    prolog_offset: 0x08,
                    op: UnwindOp::SaveXmm128 { reg: 6, offset: 0x20 }
                },
            ]
        );
    }

    #[test]
    fn parses_handler_after_odd_code_count_padding() {
        let mut data = rt_func(0x4000, 0x4040, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[
            0x09,
            0x04, 0x01, 0x00,
            0x01, 0x30,
            0x00, 0x00,
            0x99, 0x51, 0x00, 0x00,
        ]);
        let table = parse_function_table(&sec(data), 0x1000, 12);
        assert_eq!(table.len(), 1);
        let info = &table[0].info;
        assert!(info.has_exception_handler);
        assert!(!info.has_termination_handler);
        assert_eq!(info.handler_rva, Some(0x5199));
        assert_eq!(info.handler_data_rva, Some(0x101c));
        assert_eq!(table[0].record_rva, 0x1000);
    }

    #[test]
    fn parses_chained_info() {
        let mut data = rt_func(0x5040, 0x5080, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&rt_func(0x5000, 0x5040, 0x1030));
        data.resize(0x30, 0);
        data.extend_from_slice(&[0x01, 0x02, 0x01, 0x00, 0x02, 0x70, 0x00, 0x00]);

        let table = parse_function_table(&sec(data), 0x1000, 12);
        assert_eq!(table.len(), 1);
        let info = &table[0].info;
        let chained = info.chained.as_ref().expect("chained entry parsed");
        assert_eq!((chained.begin_rva, chained.end_rva), (0x5000, 0x5040));
        assert_eq!(
            chained.info.codes,
            vec![UnwindCode { prolog_offset: 2, op: UnwindOp::PushNonvolatile { reg: 7 } }]
        );
    }

    #[test]
    fn skips_bad_entries_keeps_good_ones_and_sorts() {
        let mut data = Vec::new();
        data.extend_from_slice(&rt_func(0x7000, 0x7010, 0x1040));
        data.extend_from_slice(&rt_func(0x6000, 0x6010, 0xdead_0000));
        data.extend_from_slice(&rt_func(0x5000, 0x5010, 0x1040));
        data.resize(0x40, 0);
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let table = parse_function_table(&sec(data), 0x1000, 36);
        let begins: Vec<u32> = table.iter().map(|e| e.begin_rva).collect();
        assert_eq!(begins, vec![0x5000, 0x7000]);
    }

    #[test]
    fn ignores_zero_padding_records() {
        let mut data = rt_func(0x2000, 0x2010, 0x1020);
        data.extend_from_slice(&rt_func(0, 0, 0));
        data.resize(0x20, 0);
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let table = parse_function_table(&sec(data), 0x1000, 24);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn rejects_unknown_ops_and_overruns() {
        let mut data = rt_func(0x2000, 0x2010, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[0x01, 0x02, 0x01, 0x00, 0x01, 0x07]);
        assert!(parse_function_table(&sec(data.clone()), 0x1000, 12).is_empty());

        let mut data = rt_func(0x2000, 0x2010, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[0x01, 0x02, 0x01, 0x00, 0x01, 0x34, 0x08, 0x00]);
        assert!(parse_function_table(&sec(data), 0x1000, 12).is_empty());
    }

    #[test]
    fn push_machframe_and_epilog_v2() {
        let mut data = rt_func(0x2000, 0x2010, 0x1010);
        data.resize(0x10, 0);
        data.extend_from_slice(&[
            0x02,
            0x00, 0x02, 0x00,
            0x05, 0x16,
            0x00, 0x1a,
        ]);
        let table = parse_function_table(&sec(data), 0x1000, 12);
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].info.codes[0].op, UnwindOp::Epilog { raw: 0x1605 });
        assert_eq!(
            table[0].info.codes[1].op,
            UnwindOp::PushMachineFrame { with_error_code: true }
        );
    }
}
