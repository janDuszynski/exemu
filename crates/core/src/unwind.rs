//! x64 unwind metadata — the parsed `.pdata`/`.xdata` function table
//! (roadmap P4.1).
//!
//! Every non-leaf x64 function carries a `RUNTIME_FUNCTION` record in the
//! exception data directory pointing at an `UNWIND_INFO` blob that describes
//! its prolog: which nonvolatile registers were pushed/saved where, how much
//! stack was allocated, and whether a frame pointer was established. Walking
//! these codes *backwards* recovers the caller's RSP and nonvolatile registers
//! from any rip inside the function — the foundation of SEH and C++ exception
//! dispatch (roadmap P4.2/P4.3).
//!
//! This module is the byte-order-neutral domain model; `exemu-loader` parses
//! the on-disk structures into it.

/// One entry of the function table: a function's rip extent plus its fully
/// parsed unwind description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindEntry {
    /// RVA of the first byte of the function (or chained-range fragment).
    pub begin_rva: u32,
    /// RVA one past the last byte of the range (exclusive).
    pub end_rva: u32,
    pub info: UnwindInfo,
}

/// A parsed `UNWIND_INFO` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    /// Format version (1 or 2).
    pub version: u8,
    /// `UNW_FLAG_EHANDLER` — `handler_rva` participates in exception search.
    pub has_exception_handler: bool,
    /// `UNW_FLAG_UHANDLER` — `handler_rva` participates in unwinding.
    pub has_termination_handler: bool,
    /// Length of the function prolog in bytes.
    pub prolog_size: u8,
    /// The established frame-pointer register (x64 register number), if any.
    pub frame_register: Option<u8>,
    /// Offset from RSP applied when the frame register was established
    /// (already scaled ×16; meaningful only with `frame_register`).
    pub frame_offset: u16,
    /// Prolog unwind operations, ordered by descending `prolog_offset`
    /// (the on-disk order — the order they must be undone in).
    pub codes: Vec<UnwindCode>,
    /// RVA of the language-specific handler (`__C_specific_handler`,
    /// `__CxxFrameHandler3/4`, …) when either handler flag is set.
    pub handler_rva: Option<u32>,
    /// `UNW_FLAG_CHAININFO` — the primary entry this fragment continues
    /// (its codes apply after ours when unwinding).
    pub chained: Option<Box<UnwindEntry>>,
}

/// One prolog unwind operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    /// Offset of the end of the instruction this op describes, from the start
    /// of the prolog. Ops with `prolog_offset > (rip - begin)` haven't
    /// executed yet at that rip and are skipped when unwinding.
    pub prolog_offset: u8,
    pub op: UnwindOp,
}

/// The unwind operation kinds (`UWOP_*`), with their operands decoded and
/// scale factors already applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindOp {
    /// `UWOP_PUSH_NONVOL` — the prolog pushed this register.
    PushNonvolatile { reg: u8 },
    /// `UWOP_ALLOC_SMALL` / `UWOP_ALLOC_LARGE` — the prolog subtracted
    /// `size` bytes from RSP (size already unscaled).
    Alloc { size: u32 },
    /// `UWOP_SET_FPREG` — the prolog set the frame register to
    /// `RSP + frame_offset` (see [`UnwindInfo`]).
    SetFrameRegister,
    /// `UWOP_SAVE_NONVOL(_FAR)` — register saved with `mov` at
    /// `RSP + offset` (offset already unscaled).
    SaveNonvolatile { reg: u8, offset: u32 },
    /// `UWOP_SAVE_XMM128(_FAR)` — XMM register saved at `RSP + offset`.
    SaveXmm128 { reg: u8, offset: u32 },
    /// `UWOP_PUSH_MACHFRAME` — a hardware exception frame was pushed.
    PushMachineFrame { with_error_code: bool },
    /// `UWOP_EPILOG` (version 2) — epilog-location metadata; irrelevant to
    /// frame recovery, kept raw for completeness.
    Epilog { raw: u16 },
}

/// Look up the [`UnwindEntry`] covering `rva` in a function table sorted by
/// `begin_rva` (as [`crate::PeImage`] stores it). Binary search; `end_rva`
/// is exclusive, matching `RtlLookupFunctionEntry`.
pub fn lookup(table: &[UnwindEntry], rva: u32) -> Option<&UnwindEntry> {
    let idx = table.partition_point(|e| e.begin_rva <= rva);
    let e = table.get(idx.checked_sub(1)?)?;
    (rva < e.end_rva).then_some(e)
}

// ---- virtual unwind (roadmap P4.2) ------------------------------------------

use crate::cpu::CpuState;
use crate::memory::Memory;
use crate::Result;

/// Virtually unwind **one frame**: rewrite `ctx` (RSP, RIP, and any saved
/// nonvolatile GP/XMM registers) from the callee's state to its caller's —
/// the emulator's `RtlVirtualUnwind`.
///
/// - If no table entry covers `ctx.rip`, the function is a leaf (or the rip
///   is outside the image, e.g. an API thunk): the return address is on top
///   of the stack.
/// - If `ctx.rip` is inside an epilog, the remaining epilog instructions are
///   simulated forward (the prolog codes would double-count what the epilog
///   already undid).
/// - Otherwise the prolog's unwind codes are applied in reverse, skipping
///   codes whose instruction hasn't executed yet at `ctx.rip`, then any
///   chained (primary) entries' codes in full.
///
/// After a successful return, `ctx.rip` is the caller's resume address
/// (0 typically means the frame chain is exhausted — the caller of this
/// function decides when to stop walking).
pub fn virtual_unwind<M: Memory + ?Sized>(
    table: &[UnwindEntry],
    image_base: u64,
    ctx: &mut CpuState,
    mem: &M,
) -> Result<()> {
    let rva = match ctx.rip.checked_sub(image_base) {
        Some(off) if u32::try_from(off).is_ok() => off as u32,
        _ => return pop_return_address(ctx, mem), // outside the image → leaf rules
    };
    let Some(entry) = lookup(table, rva) else {
        return pop_return_address(ctx, mem); // leaf function: no frame to undo
    };

    // Unwinding from within an epilog: part of the frame is already torn
    // down, so simulate the remaining epilog instructions instead.
    if try_simulate_epilog(entry, image_base, ctx, mem)? {
        return Ok(());
    }

    let offset_in_func = rva - entry.begin_rva;
    let mut machine_frame = false;
    let mut cur = entry;
    let mut first = true;
    loop {
        let info = &cur.info;
        // The frame base: RSP as it stood when the prolog completed. With a
        // frame register established it is recovered from that register, so
        // frames using `alloca` (where RSP has moved since) still unwind.
        let frame = match info.frame_register {
            Some(fr) => ctx.gpr[fr as usize & 0xf].wrapping_sub(info.frame_offset as u64),
            None => ctx.rsp(),
        };
        for code in &info.codes {
            // Prolog codes that haven't executed yet at this rip are skipped —
            // only for the entry actually containing rip; a chained (primary)
            // entry's prolog has fully executed by definition.
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
                    // Undo `lea fp, [rsp+off]`: RSP at that point was `frame`.
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
                    // [rsp(+8 with an error code)] = RIP, +24 from there = RSP.
                    let base = ctx.rsp().wrapping_add(if with_error_code { 8 } else { 0 });
                    ctx.rip = mem.read_u64(base)?;
                    ctx.set_rsp(mem.read_u64(base.wrapping_add(24))?);
                    machine_frame = true;
                }
                UnwindOp::Epilog { .. } => {} // location metadata only
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

    if machine_frame {
        Ok(()) // the machine frame already supplied RIP and RSP
    } else {
        pop_return_address(ctx, mem)
    }
}

fn pop_return_address<M: Memory + ?Sized>(ctx: &mut CpuState, mem: &M) -> Result<()> {
    ctx.rip = mem.read_u64(ctx.rsp())?;
    ctx.set_rsp(ctx.rsp().wrapping_add(8));
    Ok(())
}

/// If `ctx.rip` sits inside a legal x64 epilog of `entry`'s range, simulate
/// the remaining epilog instructions (`add rsp` / `lea rsp` / `pop` / `ret`
/// or tail `jmp`) against `ctx` and return `Ok(true)`.
///
/// The scan is strict: every instruction from rip to the terminator must be
/// one of the canonical epilog forms, otherwise this is not an epilog and the
/// prolog unwind codes apply (`Ok(false)`).
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

    // A one-instruction lookahead buffer; epilog instructions are ≤ 8 bytes.
    let byte = |at: u64| mem.read_u8(at);

    // Optional first instruction: the stack-frame release.
    let b0 = match byte(pc) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if b0 == 0x48 || b0 == 0x49 {
        match byte(pc + 1) {
            // add rsp, imm8 / imm32 (REX.W 83 /0 ib | 81 /0 id, modrm C4)
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
            // lea rsp, [fp ± disp8/disp32] (REX.W(±B) 8D, mod 01/10, reg=rsp)
            Ok(0x8D) => {
                let modrm = byte(pc + 2)?;
                let md = modrm >> 6;
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                // reg must be RSP; rm=100 needs a SIB byte — not epilog form.
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
            _ => {} // fall through — maybe the epilog starts at the pops
        }
    }

    // Pops, then a terminator.
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
            0xC3 => break true,                              // ret
            0xC2 => break true,                              // ret imm16
            0xF3 if byte(pc + 1) == Ok(0xC3) => break true,  // rep ret
            0xEB => {
                // jmp rel8 — a tail call only if it leaves the function.
                let rel = byte(pc + 1)? as i8 as i64;
                let target = (pc + 2).wrapping_add(rel as u64);
                break !(func_begin..func_end).contains(&target);
            }
            0xE9 => {
                let rel = mem.read_u32(pc + 1)? as i32 as i64;
                let target = (pc + 5).wrapping_add(rel as u64);
                break !(func_begin..func_end).contains(&target);
            }
            0xFF if byte(pc + 1).is_ok_and(|m| m & 0x38 == 0x20) => break true, // jmp r/m64
            _ => return Ok(false),
        }
    };
    if !terminator_ok {
        return Ok(false);
    }

    // It is an epilog — commit the simulation.
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
    // Whether the epilog ends in `ret` or tail-`jmp`s elsewhere, the caller's
    // return address is now on top of the stack.
    pop_return_address(ctx, mem)?;
    Ok(true)
}

/// Walk the frame chain from `ctx` and return the caller rips, outermost
/// last — the fault reporter's call stack. Best-effort: stops at the first
/// unreadable frame, a null/self rip, a non-increasing RSP, or `max` frames.
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
        // Terminate on a dead end or on state that stopped making progress
        // (a corrupt frame would otherwise loop forever).
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
            info: UnwindInfo {
                version: 1,
                has_exception_handler: false,
                has_termination_handler: false,
                prolog_size: 0,
                frame_register: None,
                frame_offset: 0,
                codes: Vec::new(),
                handler_rva: None,
                chained: None,
            },
        }
    }

    #[test]
    fn lookup_finds_covering_entry() {
        let table = vec![entry(0x1000, 0x1050), entry(0x1050, 0x10a0), entry(0x2000, 0x2010)];
        assert_eq!(lookup(&table, 0x1000).unwrap().begin_rva, 0x1000);
        assert_eq!(lookup(&table, 0x104f).unwrap().begin_rva, 0x1000);
        // end_rva is exclusive — 0x1050 belongs to the *next* function.
        assert_eq!(lookup(&table, 0x1050).unwrap().begin_rva, 0x1050);
        assert_eq!(lookup(&table, 0x2005).unwrap().begin_rva, 0x2000);
    }

    #[test]
    fn lookup_misses_outside_any_range() {
        let table = vec![entry(0x1000, 0x1050), entry(0x2000, 0x2010)];
        assert!(lookup(&table, 0x0fff).is_none()); // before the first
        assert!(lookup(&table, 0x1234).is_none()); // in the gap
        assert!(lookup(&table, 0x2010).is_none()); // exactly at an exclusive end
        assert!(lookup(&[], 0x1000).is_none());
    }

    // ---- virtual unwind -----------------------------------------------------

    const BASE: u64 = 0x1_4000_0000;

    /// Flat little test memory: one RW span starting at `org`.
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
        mem.put64(0x8010, 0x1400_1234); // return address on top of stack
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x5000; // no table entry covers it
        ctx.set_rsp(0x8010);
        virtual_unwind(&[], BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.rip, 0x1400_1234);
        assert_eq!(ctx.rsp(), 0x8018);
    }

    #[test]
    fn unwind_typical_frame() {
        // prolog: push rbp (offset 1); sub rsp, 0x28 (offset 5).
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
        mem.put64(0x8028, 0xBBBB_0005); // saved rbp above the 0x28 alloc
        mem.put64(0x8030, BASE + 0x2000); // return address
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040; // mid-body
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
        mem.put64(0x8000, 0xBBBB_0005); // saved rbp — the sub hasn't run yet
        mem.put64(0x8008, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1001; // right after the push, before the sub
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        assert_eq!(ctx.gpr[5], 0xBBBB_0005);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), 0x8010);
    }

    #[test]
    fn unwind_frame_register_ignores_moved_rsp() {
        // prolog: push rbp; sub rsp,0x40; lea rbp,[rsp+0x20] — then the body
        // does an alloca, so RSP is garbage and only RBP can anchor the frame.
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
        mem.put64(0x8040, 0xBBBB_0005); // saved rbp above the 0x40 alloc
        mem.put64(0x8048, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x7000_0000); // alloca moved RSP somewhere unrelated
        ctx.gpr[5] = 0x8000 + 0x20; // rbp = post-alloc rsp + 0x20
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
        mem.put64(0x8010, 0xBBBB_0003); // rbx saved at frame+0x10
        mem.put(0x8020, &0xAAAA_BBBB_CCCC_DDDD_1111_2222_3333_4444u128.to_le_bytes());
        mem.put64(0x8038, 0xBBBB_0007); // rdi pushed above the alloc
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
        // A fragment (no codes of its own) chained to a primary that pushed rbx.
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
        // rip is at the very start of the fragment: offset 0. The parent's
        // push (prolog_offset 2 > 0) must apply anyway.
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
        mem.put64(0x8000, BASE + 0x3000); // interrupted RIP
        mem.put64(0x8018, 0x9000); // interrupted RSP
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1010;
        ctx.set_rsp(0x8000);
        virtual_unwind(&table, BASE, &mut ctx, &mem).unwrap();
        // The machine frame supplies rip/rsp directly — no extra pop.
        assert_eq!(ctx.rip, BASE + 0x3000);
        assert_eq!(ctx.rsp(), 0x9000);
    }

    #[test]
    fn unwind_inside_epilog_simulates_remaining_instructions() {
        // Function with codes [alloc 0x28, push rbp]. rip sits in the epilog
        // *after* `add rsp,0x28` already ran: only `pop rbp; ret` remain.
        // Replaying the prolog codes would add 0x28 again — the epilog
        // simulation must win.
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![
                code(5, UnwindOp::Alloc { size: 0x28 }),
                code(1, UnwindOp::PushNonvolatile { reg: 5 }),
            ],
        )];
        // The epilog scan reads code bytes through the same Memory as the
        // stack, so put both in one flat span based near the function.
        let mut cmem = FlatMem::new(BASE + 0x1000, 0x100);
        cmem.put(BASE + 0x1070, &[0x5D, 0xC3]); // pop rbp; ret
        let stack = BASE + 0x1000 + 0x80;
        cmem.put64(stack, 0xBBBB_0005); // saved rbp
        cmem.put64(stack + 8, BASE + 0x2000); // return address

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
        // `add rsp,0x28; jmp -0x20` — the jmp stays inside the function, so
        // this is a loop, not an epilog; the unwind codes must be used.
        let table = vec![entry_with(
            0x1000,
            0x1080,
            5,
            vec![code(1, UnwindOp::PushNonvolatile { reg: 3 })],
        )];
        let mut cmem = FlatMem::new(BASE + 0x1000, 0x100);
        cmem.put(BASE + 0x1040, &[0x48, 0x83, 0xC4, 0x28, 0xEB, 0xD0]); // jmp back
        let stack = BASE + 0x1000 + 0x80;
        cmem.put64(stack, 0xBBBB_0003); // saved rbx (per the unwind code)
        cmem.put64(stack + 8, BASE + 0x2000);
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(stack);
        virtual_unwind(&table, BASE, &mut ctx, &cmem).unwrap();
        // Codes path: pop rbx then return address — NOT rsp+0x28.
        assert_eq!(ctx.gpr[3], 0xBBBB_0003);
        assert_eq!(ctx.rip, BASE + 0x2000);
        assert_eq!(ctx.rsp(), stack + 16);
    }

    #[test]
    fn backtrace_walks_nested_frames() {
        // outer (0x3000, pushes rbp) calls inner (0x1000, alloc 0x18).
        let table = vec![
            entry_with(0x1000, 0x1080, 4, vec![code(4, UnwindOp::Alloc { size: 0x18 })]),
            entry_with(0x3000, 0x3080, 2, vec![code(2, UnwindOp::PushNonvolatile { reg: 5 })]),
        ];
        let mut mem = FlatMem::new(0x8000, 0x100);
        mem.put64(0x8018, BASE + 0x3030); // inner's return into outer
        mem.put64(0x8020, 0xBBBB_0005); // outer's saved rbp
        mem.put64(0x8028, BASE + 0x9999); // outer's return (outside the table → leaf)
        mem.put64(0x8030, 0); // chain ends
        let mut ctx = CpuState::new();
        ctx.rip = BASE + 0x1040;
        ctx.set_rsp(0x8000);
        let frames = backtrace(&table, BASE, &ctx, &mem, 16);
        assert_eq!(frames, vec![BASE + 0x3030, BASE + 0x9999]);
    }
}
