#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindEntry {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub record_rva: u32,
    pub info: UnwindInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    pub has_exception_handler: bool,
    pub has_termination_handler: bool,
    pub prolog_size: u8,
    pub frame_register: Option<u8>,
    pub frame_offset: u16,
    pub codes: Vec<UnwindCode>,
    pub handler_rva: Option<u32>,
    pub handler_data_rva: Option<u32>,
    pub chained: Option<Box<UnwindEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    pub prolog_offset: u8,
    pub op: UnwindOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindOp {
    PushNonvolatile { reg: u8 },
    Alloc { size: u32 },
    SetFrameRegister,
    SaveNonvolatile { reg: u8, offset: u32 },
    SaveXmm128 { reg: u8, offset: u32 },
    PushMachineFrame { with_error_code: bool },
    Epilog { raw: u16 },
}

pub fn lookup(table: &[UnwindEntry], rva: u32) -> Option<&UnwindEntry> {
    let idx = table.partition_point(|e| e.begin_rva <= rva);
    let e = table.get(idx.checked_sub(1)?)?;
    (rva < e.end_rva).then_some(e)
}

use crate::cpu::CpuState;
use crate::memory::Memory;
use crate::Result;

pub fn virtual_unwind<M: Memory + ?Sized>(
    table: &[UnwindEntry],
    image_base: u64,
    ctx: &mut CpuState,
    mem: &M,
) -> Result<()> {
    virtual_unwind_frame(table, image_base, ctx, mem).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameUnwind {
    pub establisher_frame: u64,
    pub handler_rva: Option<u32>,
    pub handler_data_rva: Option<u32>,
    pub is_leaf_or_epilog: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerType(pub u32);

impl HandlerType {
    pub const NONE: HandlerType = HandlerType(0);
    pub const EXCEPTION: HandlerType = HandlerType(1);
    pub const UNWIND: HandlerType = HandlerType(2);
}

pub fn virtual_unwind_frame<M: Memory + ?Sized>(
    table: &[UnwindEntry],
    image_base: u64,
    ctx: &mut CpuState,
    mem: &M,
) -> Result<FrameUnwind> {
    virtual_unwind_typed(table, image_base, ctx, mem, HandlerType::EXCEPTION)
}

pub fn virtual_unwind_typed<M: Memory + ?Sized>(
    table: &[UnwindEntry],
    image_base: u64,
    ctx: &mut CpuState,
    mem: &M,
    handler_type: HandlerType,
) -> Result<FrameUnwind> {
    let rva = match ctx.rip.checked_sub(image_base) {
        Some(off) if u32::try_from(off).is_ok() => off as u32,
        _ => {
            pop_return_address(ctx, mem)?;
            return Ok(FrameUnwind { establisher_frame: ctx.rsp(), is_leaf_or_epilog: true, ..Default::default() });
        }
    };
    let Some(entry) = lookup(table, rva) else {
        pop_return_address(ctx, mem)?;
        return Ok(FrameUnwind { establisher_frame: ctx.rsp(), is_leaf_or_epilog: true, ..Default::default() });
    };

    if try_simulate_epilog(entry, image_base, ctx, mem)? {
        return Ok(FrameUnwind { establisher_frame: ctx.rsp(), is_leaf_or_epilog: true, ..Default::default() });
    }

    let offset_in_func = rva - entry.begin_rva;
    let opts_in = match handler_type {
        HandlerType::EXCEPTION => entry.info.has_exception_handler,
        HandlerType::UNWIND => entry.info.has_termination_handler,
        _ => false,
    };
    let handler_rva = opts_in.then_some(entry.info.handler_rva).flatten();
    let handler_data_rva = opts_in.then_some(entry.info.handler_data_rva).flatten();
    let mut establisher_frame = ctx.rsp();

    let mut machine_frame = false;
    let mut cur = entry;
    let mut first = true;
    loop {
        let info = &cur.info;
        let frame = match info.frame_register {
            Some(fr) => ctx.gpr[fr as usize & 0xf].wrapping_sub(info.frame_offset as u64),
            None => ctx.rsp(),
        };
        if first {
            establisher_frame = frame;
        }
        for code in &info.codes {
            if first && u32::from(code.prolog_offset) > offset_in_func {
                continue;
            }
            match code.op {
                UnwindOp::PushNonvolatile { reg } => {
                    ctx.gpr[reg as usize & 0xf] = mem.read_u64(ctx.rsp())?;
                    ctx.set_rsp(ctx.rsp().wrapping_add(8));
                }
                UnwindOp::Alloc { size } => {
                    ctx.set_rsp(ctx.rsp().wrapping_add(size as u64));
                }
                UnwindOp::SetFrameRegister => {
                    ctx.set_rsp(frame);
                }
                UnwindOp::SaveNonvolatile { reg, offset } => {
                    ctx.gpr[reg as usize & 0xf] =
                        mem.read_u64(frame.wrapping_add(offset as u64))?;
                }
                UnwindOp::SaveXmm128 { reg, offset } => {
                    let mut b = [0u8; 16];
                    mem.read(frame.wrapping_add(offset as u64), &mut b)?;
                    ctx.xmm[reg as usize & 0xf] = u128::from_le_bytes(b);
                }
                UnwindOp::PushMachineFrame { with_error_code } => {
                    let base = ctx.rsp().wrapping_add(if with_error_code { 8 } else { 0 });
                    ctx.rip = mem.read_u64(base)?;
                    ctx.set_rsp(mem.read_u64(base.wrapping_add(24))?);
                    machine_frame = true;
                }
                UnwindOp::Epilog { .. } => {}
            }
        }
        match &info.chained {
            Some(parent) => {
                cur = parent;
                first = false;
            }
            None => break,
        }
    }

    if !machine_frame {
        pop_return_address(ctx, mem)?;
    }
    Ok(FrameUnwind { establisher_frame, handler_rva, handler_data_rva, is_leaf_or_epilog: false })
}

fn pop_return_address<M: Memory + ?Sized>(ctx: &mut CpuState, mem: &M) -> Result<()> {
    ctx.rip = mem.read_u64(ctx.rsp())?;
    ctx.set_rsp(ctx.rsp().wrapping_add(8));
    Ok(())
}

fn try_simulate_epilog<M: Memory + ?Sized>(
    entry: &UnwindEntry,
    image_base: u64,
    ctx: &mut CpuState,
    mem: &M,
) -> Result<bool> {
    enum EpiOp {
        AddRsp(u64),
        LeaRsp { reg: u8, disp: i32 },
        Pop(u8),
    }

    let func_begin = image_base + entry.begin_rva as u64;
    let func_end = image_base + entry.end_rva as u64;
    let mut ops: Vec<EpiOp> = Vec::new();
    let mut pc = ctx.rip;

    let byte = |at: u64| mem.read_u8(at);

    let b0 = match byte(pc) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if b0 == 0x48 || b0 == 0x49 {
        match byte(pc + 1) {
            Ok(0x83) if b0 == 0x48 && byte(pc + 2) == Ok(0xC4) => {
                let imm = byte(pc + 3)? as i8 as i64;
                ops.push(EpiOp::AddRsp(imm as u64));
                pc += 4;
            }
            Ok(0x81) if b0 == 0x48 && byte(pc + 2) == Ok(0xC4) => {
                let imm = mem.read_u32(pc + 3)? as i32 as i64;
                ops.push(EpiOp::AddRsp(imm as u64));
                pc += 7;
            }
            Ok(0x8D) => {
                let modrm = byte(pc + 2)?;
                let md = modrm >> 6;
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                if reg != 4 || rm == 4 || (md != 1 && md != 2) {
                    return Ok(false);
                }
                let fp = if b0 == 0x49 { rm + 8 } else { rm };
                let (disp, len) = if md == 1 {
                    (byte(pc + 3)? as i8 as i32, 4u64)
                } else {
                    (mem.read_u32(pc + 3)? as i32, 7u64)
                };
                ops.push(EpiOp::LeaRsp { reg: fp, disp });
                pc += len;
            }
            _ => {}
        }
    }

    let terminator_ok = loop {
        let b = match byte(pc) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        match b {
            0x58..=0x5F => {
                ops.push(EpiOp::Pop(b - 0x58));
                pc += 1;
            }
            0x41 => match byte(pc + 1) {
                Ok(p @ 0x58..=0x5F) => {
                    ops.push(EpiOp::Pop(p - 0x58 + 8));
                    pc += 2;
                }
                _ => return Ok(false),
            },
            0xC3 => break true,
            0xC2 => break true,
            0xF3 if byte(pc + 1) == Ok(0xC3) => break true,
            0xEB => {
                let rel = byte(pc + 1)? as i8 as i64;
                let target = (pc + 2).wrapping_add(rel as u64);
                break !(func_begin..func_end).contains(&target);
            }
            0xE9 => {
                let rel = mem.read_u32(pc + 1)? as i32 as i64;
                let target = (pc + 5).wrapping_add(rel as u64);
                break !(func_begin..func_end).contains(&target);
            }
            0xFF if byte(pc + 1).is_ok_and(|m| m & 0x38 == 0x20) => break true,
            _ => return Ok(false),
        }
    };
    if !terminator_ok {
        return Ok(false);
    }

    for op in &ops {
        match *op {
            EpiOp::AddRsp(v) => ctx.set_rsp(ctx.rsp().wrapping_add(v)),
            EpiOp::LeaRsp { reg, disp } => {
                ctx.set_rsp(ctx.gpr[reg as usize & 0xf].wrapping_add(disp as i64 as u64))
            }
            EpiOp::Pop(reg) => {
                ctx.gpr[reg as usize & 0xf] = mem.read_u64(ctx.rsp())?;
                ctx.set_rsp(ctx.rsp().wrapping_add(8));
            }
        }
    }
    pop_return_address(ctx, mem)?;
    Ok(true)
}

pub fn backtrace<M: Memory + ?Sized>(
    table: &[UnwindEntry],
    image_base: u64,
    ctx: &CpuState,
    mem: &M,
    max: usize,
) -> Vec<u64> {
    let mut walk = ctx.clone();
    let mut frames = Vec::new();
    while frames.len() < max {
        let prev_rsp = walk.rsp();
        let prev_rip = walk.rip;
        if virtual_unwind(table, image_base, &mut walk, mem).is_err() {
            break;
        }
        if walk.rip == 0 || walk.rip == prev_rip || walk.rsp() <= prev_rsp {
            break;
        }
        frames.push(walk.rip);
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(begin: u32, end: u32) -> UnwindEntry {
        UnwindEntry {
            begin_rva: begin,
            end_rva: end,
            record_rva: 0,
            info: UnwindInfo {
                version: 1,
                has_exception_handler: false,
                has_termination_handler: false,
                prolog_size: 0,
                frame_register: None,
                frame_offset: 0,
                codes: Vec::new(),
                handler_rva: None,
                handler_data_rva: None,
                chained: None,
            },
        }
    }

    #[test]
    fn lookup_finds_covering_entry() {
        let table = vec![entry(0x1000, 0x1050), entry(0x1050, 0x10a0), entry(0x2000, 0x2010)];
        assert_eq!(lookup(&table, 0x1000).unwrap().begin_rva, 0x1000);
        assert_eq!(lookup(&table, 0x104f).unwrap().begin_rva, 0x1000);
        assert_eq!(lookup(&table, 0x1050).unwrap().begin_rva, 0x1050);
        assert_eq!(lookup(&table, 0x2005).unwrap().begin_rva, 0x2000);
    }

    #[test]
    fn lookup_misses_outside_any_range() {
        let table = vec![entry(0x1000, 0x1050), entry(0x2000, 0x2010)];
        assert!(lookup(&table, 0x0fff).is_none());
        assert!(lookup(&table, 0x1234).is_none());
        assert!(lookup(&table, 0x2010).is_none());
        assert!(lookup(&[], 0x1000).is_none());
    }

    const BASE: u64 = 0x1_4000_0000;

    struct FlatMem {
        org: u64,
        bytes: Vec<u8>,
    }

    impl FlatMem {
        fn new(org: u64, size: usize) -> Self {
            FlatMem { org, bytes: vec![0; size] }
        }

        fn put64(&mut self, addr: u64, v: u64) {
            let o = (addr - self.org) as usize;
            self.bytes[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }

        fn put(&mut self, addr: u64, data: &[u8]) {
            let o = (addr - self.org) as usize;
            self.bytes[o..o + data.len()].copy_from_slice(data);
        }
    }

    impl Memory for FlatMem {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let o = addr
                .checked_sub(self.org)
                .filter(|&o| o as usize + buf.len() <= self.bytes.len())
                .ok_or(crate::EmuError::Unmapped { addr, len: buf.len() })?
                as usize;
            buf.copy_from_slice(&self.bytes[o..o + buf.len()]);
            Ok(())
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let o = addr
                .checked_sub(self.org)
                .filter(|&o| o as usize + data.len() <= self.bytes.len())
                .ok_or(crate::EmuError::Unmapped { addr, len: data.len() })?
                as usize;
            self.bytes[o..o + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    fn code(prolog_offset: u8, op: UnwindOp) -> UnwindCode {
        UnwindCode { prolog_offset, op }
    }

    fn entry_with(begin: u32, end: u32, prolog: u8, codes: Vec<UnwindCode>) -> UnwindEntry {
        let mut e = entry(begin, end);
        e.info.prolog_size = prolog;
        e.info.codes = codes;
        e
    }

    #[test]
    fn unwind_leaf_pops_return_address() {
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8010, 0x1400_1234);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x5000;
        ctx.set_rsp(0x8010);
        virtual_unwind(&[], BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.rip, 0x1400_1234);
        assert_eq!(ctx.rsp(), 0x8018);
    }

    #[test]
    fn unwind_typical_frame() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![
                code(5, UnwindOp::Alloc { size: 0x28 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        )];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8028, 0xBBBB_0005);
        mem.put64(0x8030, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[5], 0xBBBB_0005);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), 0x8038);
    }

    #[test]
    fn unwind_mid_prolog_skips_unexecuted_codes() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![
                code(5, UnwindOp::Alloc { size: 0x28 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        )];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8000, 0xBBBB_0005);
        mem.put64(0x8008, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1001;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[5], 0xBBBB_0005);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), 0x8010);
    }

    #[test]
    fn unwind_frame_register_ignores_moved_rsp() {
        let mut e = entry_with(
            0x1000,
            0x1080,
            8,
            vec![
                code(8, UnwindOp::SetFrameRegister),
                code(4, UnwindOp::Alloc { size: 0x40 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        );
        e.info.frame_register = Some(5);
        e.info.frame_offset = 0x20;
        let table = vec![e];

        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8040, 0xBBBB_0005);
        mem.put64(0x8048, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x7000_0000);
        ctx.gpr[5] = 0x8000 + 0x20;
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[5], 0xBBBB_0005);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), 0x8050);
    }

    #[test]
    fn unwind_save_nonvol_and_xmm_restore_from_frame() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            12,
            vec![
                code(12, UnwindOp::SaveXmm128 { reg: 6, offset: 0x20 }),
                code(9, UnwindOp::SaveNonvolatile { reg: 3, offset: 0x10 }),
                code(5, UnwindOp::Alloc { size: 0x38 }),
                code(1, UnwindOp::PushNonvolatile { reg: 7 }),
            ],
        )];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8010, 0xBBBB_0003);
        mem.put(0x8020, &0xAAAA_BBBB_CCCC_DDDD_1111_2222_3333_4444u128.to_le_bytes());
        mem.put64(0x8038, 0xBBBB_0007);
        mem.put64(0x8040, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[3], 0xBBBB_0003);
        assert_eq!(ctx.xmm[6], 0xAAAA_BBBB_CCCC_DDDD_1111_2222_3333_4444);
        assert_eq!(ctx.gpr[7], 0xBBBB_0007);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), 0x8048);
    }

    #[test]
    fn unwind_chained_applies_parent_codes_fully() {
        let mut frag = entry_with(0x1040, 0x1080, 0, vec![]);
        frag.info.chained = Some(Box::new(entry_with(
            0x1000,
            0x1040,
            2,
            vec![code(2, UnwindOp::PushNonvolatile { reg: 3 })],
        )));
        let table = vec![frag];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8000, 0xBBBB_0003);
        mem.put64(0x8008, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[3], 0xBBBB_0003);
        assert_eq!(ctx.rip, BASE + 0x2000);
    }

    #[test]
    fn unwind_machine_frame() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            0,
            vec![code(0, UnwindOp::PushMachineFrame { with_error_code: false })],
        )];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8000, BASE + 0x3000);
        mem.put64(0x8018, 0x9000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1010;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.rip, BASE + 0x3000);
        assert_eq!(ctx.rsp(), 0x9000);
    }

    #[test]
    fn unwind_inside_epilog_simulates_remaining_instructions() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![
                code(5, UnwindOp::Alloc { size: 0x28 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        )];
        let mut cmem = FlatMem::new(BASE + 0x1000, 0x100);
        cmem.put(BASE + 0x1070, &[0x5D, 0xC3]);
        let stack = BASE + 0x1000 + 0x80;
        cmem.put64(stack, 0xBBBB_0005);
        cmem.put64(stack + 8, BASE + 0x2000);

        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1070;
        ctx.set_rsp(stack);
        virtual_unwind(&table, BASE, &mut ctx, &cmem).unwrap();
        assert_eq!(ctx.gpr[5], 0xBBBB_0005);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), stack + 16);
    }

    #[test]
    fn unwind_rejects_fake_epilog_jmp_inside_function() {
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![code(1, UnwindOp::PushNonvolatile { reg: 3 })],
        )];
        let mut cmem = FlatMem::new(BASE + 0x1000, 0x100);
        cmem.put(BASE + 0x1040, &[0x48, 0x83, 0xC4, 0x28, 0xEB, 0xD0]);
        let stack = BASE + 0x1000 + 0x80;
        cmem.put64(stack, 0xBBBB_0003);
        cmem.put64(stack + 8, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(stack);
        virtual_unwind(&table, BASE, &mut ctx, &cmem).unwrap();
        assert_eq!(ctx.gpr[3], 0xBBBB_0003);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), stack + 16);
    }

    #[test]
    fn unwind_frame_reports_handler_and_establisher() {
        let mut e = entry_with(
            0x1000,
            0x1080,
            5,
            vec![
                code(5, UnwindOp::Alloc { size: 0x28 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        );
        e.info.has_exception_handler = true;
        e.info.handler_rva = Some(0x9000);
        e.info.handler_data_rva = Some(0x9100);
        let table = vec![e];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8028, 0xBBBB_0005);
        mem.put64(0x8030, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        let fu = virtual_unwind_frame(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(fu.handler_rva, Some(0x9000));
        assert_eq!(fu.handler_data_rva, Some(0x9100));
        assert_eq!(fu.establisher_frame, 0x8000);
        assert!(!fu.is_leaf_or_epilog);
        assert_eq!(ctx.rip, BASE + 0x2000);
    }

    #[test]
    fn unwind_frame_hides_handler_for_wrong_phase() {
        let mut e = entry_with(0x1000, 0x1080, 2, vec![code(2, UnwindOp::PushNonvolatile { reg: 3 })]);
        e.info.has_exception_handler = true;
        e.info.handler_rva = Some(0x9000);
        let table = vec![e];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8000, 0xBBBB_0003);
        mem.put64(0x8008, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        let fu = virtual_unwind_typed(&table, BASE, &mut ctx, &mem, HandlerType::UNWIND).unwrap();
        assert_eq!(fu.handler_rva, None);
    }

    #[test]
    fn unwind_frame_leaf_flagged() {
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8000, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x5000;
        ctx.set_rsp(0x8000);
        let fu = virtual_unwind_frame(&[], BASE, &mut ctx, &mem).unwrap();
        assert!(fu.is_leaf_or_epilog);
        assert_eq!(fu.handler_rva, None);
    }

    #[test]
    fn backtrace_walks_nested_frames() {
        let table = vec![
            entry_with(0x1000, 0x1080, 4, vec![code(4, UnwindOp::Alloc { size: 0x18 })]),
            entry_with(0x3000, 0x3080, 2, vec![code(2, UnwindOp::PushNonvolatile { reg: 5 })]),
        ];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8018, BASE + 0x3030);
        mem.put64(0x8020, 0xBBBB_0005);
        mem.put64(0x8028, BASE + 0x9999);
        mem.put64(0x8030, 0);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        let frames = backtrace(&table, BASE, &ctx, &mem, 16);
        assert_eq!(frames, vec![BASE + 0x3030, BASE + 0x9999]);
    }
}
