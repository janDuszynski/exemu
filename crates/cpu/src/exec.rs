//! The instruction dispatch: `execute_one` fetches, decodes and runs a
//! single instruction. Split out from `lib.rs` purely for length.
//!
//! Control-flow instructions set `rip` themselves and `return`. Every other
//! instruction falls out of the `match`, after which the shared tail sets
//! `rip` to the first byte past the instruction.

use super::*;
use crate::alu::{self, Shift};
use exemu_core::cpu::flags;

/// Which of the four CPUID output registers a feature bit lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuidReg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

impl CpuidReg {
    /// Select this register's value from a `(eax, ebx, ecx, edx)` CPUID result.
    #[inline]
    pub fn pick(self, r: (u32, u32, u32, u32)) -> u32 {
        match self {
            CpuidReg::Eax => r.0,
            CpuidReg::Ebx => r.1,
            CpuidReg::Ecx => r.2,
            CpuidReg::Edx => r.3,
        }
    }
}

/// One advertised CPUID feature bit paired with a representative instruction
/// that exercises it. Used by the "advertised ⊆ implemented" invariant test to
/// prove every reported capability is one the decoder actually understands.
#[derive(Debug, Clone, Copy)]
pub struct CpuidFeature {
    pub leaf: u32,
    pub sub: u32,
    pub reg: CpuidReg,
    pub bit: u8,
    pub name: &'static str,
    /// A 64-bit encoding of an instruction that uses the feature.
    pub probe: &'static [u8],
}

impl Interpreter {
    pub(crate) fn execute_one(&mut self, mem: &mut dyn Memory) -> Result<Exit> {
        let start = self.state.rip;
        let mut ctx = Ctx {
            pfx: Prefixes::default(),
            cur: start,
            reg: 0,
            rm: Rm::Reg(0),
            bits: self.bits,
            u8_at_op: 0,
        };

        self.read_prefixes(&mut ctx, mem)?;
        let opcode = ctx.u8(mem)?;

        // The regular ALU opcodes 0x00..=0x3D share one handler.
        if opcode < 0x40 && (opcode & 7) < 6 {
            self.alu_regular(&mut ctx, mem, opcode)?;
            self.state.rip = ctx.cur & self.addr_mask();
            return Ok(Exit::Continue);
        }

        match opcode {
            // ---- INC/DEC r32 (32-bit mode only; REX otherwise) ----------
            0x40..=0x4F => {
                let r = opcode & 7;
                let size = Self::opsize(&ctx);
                let v = self.state.gpr_read(r, size);
                let res = if opcode < 0x48 {
                    alu::inc(&mut self.state, v, size)
                } else {
                    alu::dec(&mut self.state, v, size)
                };
                self.state.gpr_write(r, size, res);
            }

            // ---- PUSH/POP r64/r32 ---------------------------------------
            0x50..=0x57 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let v = self.state.gpr[r as usize];
                self.push_stack(mem, v)?;
            }
            0x58..=0x5F => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let v = self.pop_stack(mem)?;
                self.state.gpr[r as usize] = v & self.addr_mask();
            }

            // ---- PUSHA / POPA (32-bit only) -----------------------------
            0x60 => {
                let esp = self.state.rsp();
                for r in [0u8, 1, 2, 3] {
                    let v = self.state.gpr_read(r, 4);
                    self.push_stack(mem, v)?;
                }
                self.push_stack(mem, esp)?; // original esp
                for r in [5u8, 6, 7] {
                    let v = self.state.gpr_read(r, 4);
                    self.push_stack(mem, v)?;
                }
            }
            0x61 => {
                for r in [7u8, 6, 5] {
                    let v = self.pop_stack(mem)?;
                    self.state.gpr_write(r, 4, v);
                }
                let _esp = self.pop_stack(mem)?; // discard saved esp
                for r in [3u8, 2, 1, 0] {
                    let v = self.pop_stack(mem)?;
                    self.state.gpr_write(r, 4, v);
                }
            }

            0x68 => {
                let imm = alu::sext(ctx.u32(mem)? as u64, 4);
                self.push_stack(mem, imm)?;
            }
            0x6A => {
                let imm = alu::sext(ctx.u8(mem)? as u64, 1);
                self.push_stack(mem, imm)?;
            }

            // ---- MOVSXD r64, r/m32 --------------------------------------
            0x63 => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.read_rm(&ctx, &*mem, 4)?;
                let size = Self::opsize(&ctx);
                self.write_reg_field(&ctx, size, alu::sext(v, 4) & alu::mask(size));
            }

            // ---- IMUL r, r/m, imm ---------------------------------------
            0x69 | 0x6B => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx);
                let imm = if opcode == 0x6B {
                    alu::sext(ctx.u8(mem)? as u64, 1)
                } else {
                    self.imm_z(&mut ctx, mem, size)?
                };
                let src = self.read_rm(&ctx, &*mem, size)?;
                let r = self.imul_trunc(src, imm, size);
                self.write_reg_field(&ctx, size, r);
            }

            // ---- Jcc rel8 ------------------------------------------------
            0x70..=0x7F => {
                let rel = ctx.u8(mem)? as i8 as i64;
                let taken = self.cond(opcode & 0xF);
                self.state.rip = if taken { ctx.cur.wrapping_add(rel as u64) } else { ctx.cur };
                return Ok(Exit::Continue);
            }

            // ---- Group 1: r/m, imm --------------------------------------
            0x80 | 0x81 | 0x83 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x80 { 1 } else { Self::opsize(&ctx) };
                let op = ctx.reg & 7;
                let imm = match opcode {
                    0x80 => ctx.u8(mem)? as u64,
                    0x81 => self.imm_z(&mut ctx, mem, size)?,
                    _ => alu::sext(ctx.u8(mem)? as u64, 1) & alu::mask(size),
                };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let r = self.do_alu(op, a, imm, size);
                if op != 7 {
                    self.write_rm(&ctx, mem, size, r)?;
                }
            }

            // ---- TEST r/m, r --------------------------------------------
            0x84 | 0x85 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x84 { 1 } else { Self::opsize(&ctx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                alu::logic(&mut self.state, a & b, size);
            }

            // ---- XCHG r/m, r --------------------------------------------
            0x86 | 0x87 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x86 { 1 } else { Self::opsize(&ctx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                self.write_rm(&ctx, mem, size, b)?;
                self.write_reg_field(&ctx, size, a);
            }

            // ---- MOV r/m<->r --------------------------------------------
            0x88 | 0x89 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x88 { 1 } else { Self::opsize(&ctx) };
                let v = self.read_reg_field(&ctx, size);
                self.write_rm(&ctx, mem, size, v)?;
            }
            0x8A | 0x8B => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x8A { 1 } else { Self::opsize(&ctx) };
                let v = self.read_rm(&ctx, &*mem, size)?;
                self.write_reg_field(&ctx, size, v);
            }

            // ---- MOV Sreg, r/m16 / MOV r/m16, Sreg ----------------------
            // Segment-register moves. exemu is flat-model: segment *selectors*
            // don't affect execution (ES/DS/SS bases are 0; the FS/GS *bases* are
            // managed via the TEB setup / WRFSBASE, not derived from the loaded
            // selector), so a load (`mov ds,eax`; wow64cpu's iretq path uses these)
            // just consumes its 16-bit operand, and a store yields 0. The mode
            // switch that WoW64 needs rides the CS *selector* through the far
            // jmp / iretq handlers, not these moves.
            0x8C => {
                self.read_modrm(&mut ctx, mem)?;
                self.write_rm(&ctx, mem, 2, 0)?; // no meaningful selector in flat mode
            }
            0x8E => {
                self.read_modrm(&mut ctx, mem)?;
                let _selector = self.read_rm(&ctx, &*mem, 2)?; // loaded, then ignored
            }

            // ---- LEA r, m -----------------------------------------------
            0x8D => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx);
                let addr = ctx.rm_addr();
                self.write_reg_field(&ctx, size, addr);
            }

            // ---- POP r/m (group 1A) -------------------------------------
            0x8F => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.pop_stack(mem)?;
                let w = self.stack_width();
                self.write_rm(&ctx, mem, w, v)?;
            }

            // ---- XCHG rAX, r / NOP / PAUSE ------------------------------
            0x90..=0x97 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                if r != 0 {
                    let size = Self::opsize(&ctx);
                    let a = self.state.gpr_read(0, size);
                    let b = self.state.gpr_read(r, size);
                    self.state.gpr_write(0, size, b);
                    self.state.gpr_write(r, size, a);
                }
                // r == 0 → plain NOP.  F3 90 (PAUSE) intentionally takes this
                // same path: PAUSE is a no-op hint with no architectural side
                // effects, so no separate handling is needed or desirable.
            }

            // ---- CWDE/CDQE and CDQ/CQO ----------------------------------
            0x98 => {
                if ctx.pfx.w() {
                    let v = alu::sext(self.state.gpr_read(0, 4), 4);
                    self.state.set_reg(exemu_core::Reg::Rax, v);
                } else if ctx.pfx.p66 {
                    let v = alu::sext(self.state.gpr_read(0, 1), 1);
                    self.state.gpr_write(0, 2, v);
                } else {
                    let v = alu::sext(self.state.gpr_read(0, 2), 2);
                    self.state.gpr_write(0, 4, v);
                }
            }
            0x99 => {
                let size = Self::opsize(&ctx);
                let a = self.state.gpr_read(0, size);
                let hi = if a & alu::sign_bit(size) != 0 { alu::mask(size) } else { 0 };
                self.state.gpr_write(2, size, hi);
            }

            // ---- PUSHF / POPF -------------------------------------------
            0x9C => {
                let flags = self.state.rflags;
                self.push_stack(mem, flags)?;
            }
            0x9D => {
                let v = self.pop_stack(mem)?;
                // Keep the reserved bit set; ignore privileged/high bits.
                self.state.rflags = (v & 0x0000_0000_00FC_FFD5) | flags::RESERVED_ONE;
            }

            // ---- TEST AL/eAX, imm ---------------------------------------
            0xA8 => {
                let imm = ctx.u8(mem)? as u64;
                let a = self.state.gpr_read(0, 1);
                alu::logic(&mut self.state, a & imm, 1);
            }
            0xA9 => {
                let size = Self::opsize(&ctx);
                let imm = self.imm_z(&mut ctx, mem, size)?;
                let a = self.state.gpr_read(0, size);
                alu::logic(&mut self.state, a & imm, size);
            }

            // ---- MOV AL/eAX <-> moffs (absolute address) ----------------
            0xA0..=0xA3 => {
                // The offset is an address-size immediate (4 or 8 bytes).
                let mut addr = if ctx.bits == Bits::B64 { ctx.u64(mem)? } else { ctx.u32(mem)? as u64 };
                if ctx.pfx.seg == 0x64 {
                    addr = addr.wrapping_add(if ctx.bits == Bits::B64 { FS_BASE } else { FS_BASE_32 });
                } else if ctx.pfx.seg == 0x65 {
                    addr = addr.wrapping_add(GS_BASE);
                }
                addr &= self.addr_mask();
                let size = if opcode & 1 == 0 { 1 } else { Self::opsize(&ctx) };
                match opcode {
                    0xA0 | 0xA1 => {
                        let v = mem.read_uint(addr, size)?;
                        self.state.gpr_write(0, size, v);
                    }
                    _ => {
                        let v = self.state.gpr_read(0, size);
                        mem.write_uint(addr, size, v)?;
                    }
                }
            }

            // ---- String ops: MOVS / STOS / CMPS / LODS / SCAS -----------
            0xA4 | 0xA5 => {
                let size = if opcode == 0xA4 { 1 } else { Self::opsize(&ctx) };
                self.string_movs(mem, &ctx, size)?;
            }
            0xAA | 0xAB => {
                let size = if opcode == 0xAA { 1 } else { Self::opsize(&ctx) };
                self.string_stos(mem, &ctx, size)?;
            }
            0xA6 | 0xA7 => {
                let size = if opcode == 0xA6 { 1 } else { Self::opsize(&ctx) };
                self.string_cmps(mem, &ctx, size)?;
            }
            0xAC | 0xAD => {
                let size = if opcode == 0xAC { 1 } else { Self::opsize(&ctx) };
                self.string_lods(mem, &ctx, size)?;
            }
            0xAE | 0xAF => {
                let size = if opcode == 0xAE { 1 } else { Self::opsize(&ctx) };
                self.string_scas(mem, &ctx, size)?;
            }

            // ---- MOV r8, imm8 -------------------------------------------
            0xB0..=0xB7 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let imm = ctx.u8(mem)? as u64;
                self.write_gpr(r, 1, ctx.pfx.has_rex, imm);
            }
            // ---- MOV r32/r64, imm --------------------------------------
            0xB8..=0xBF => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                if ctx.pfx.w() {
                    let imm = ctx.u64(mem)?;
                    self.state.gpr[r as usize] = imm;
                } else if ctx.pfx.p66 {
                    let imm = ctx.u16(mem)? as u64;
                    self.state.gpr_write(r, 2, imm);
                } else {
                    let imm = ctx.u32(mem)? as u64;
                    self.state.gpr_write(r, 4, imm); // zero-extends to 64
                }
            }

            // ---- Group 2 shifts -----------------------------------------
            0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode & 1 == 0 { 1 } else { Self::opsize(&ctx) };
                let kind = Shift::from_reg(ctx.reg);
                let count = match opcode {
                    0xC0 | 0xC1 => ctx.u8(mem)? as u64,
                    0xD0 | 0xD1 => 1,
                    _ => self.state.gpr_read(1, 1), // CL
                };
                let v = self.read_rm(&ctx, &*mem, size)?;
                let r = alu::shift(&mut self.state, kind, v, count, size);
                self.write_rm(&ctx, mem, size, r)?;
            }

            // ---- RET -----------------------------------------------------
            0xC2 => {
                let extra = ctx.u16(mem)? as u64;
                let ret = self.pop_stack(mem)?;
                self.state.set_rsp(self.state.rsp().wrapping_add(extra));
                self.state.rip = ret;
                return Ok(Exit::Continue);
            }
            0xC3 => {
                let ret = self.pop_stack(mem)?;
                self.state.rip = ret;
                return Ok(Exit::Continue);
            }

            // ---- MOV r/m, imm (group 11) --------------------------------
            0xC6 => {
                self.read_modrm(&mut ctx, mem)?;
                let imm = ctx.u8(mem)? as u64;
                self.write_rm(&ctx, mem, 1, imm)?;
            }
            0xC7 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx);
                let imm = self.imm_z(&mut ctx, mem, size)?;
                self.write_rm(&ctx, mem, size, imm)?;
            }

            // ---- LEAVE ---------------------------------------------------
            0xC9 => {
                let bp = self.state.reg(exemu_core::Reg::Rbp);
                self.state.set_rsp(bp);
                let v = self.pop_stack(mem)?;
                self.state.set_reg(exemu_core::Reg::Rbp, v);
            }

            // ---- INT3 / INT imm8 ----------------------------------------
            0xCC => return Ok(Exit::Interrupt(3)),
            0xCD => {
                let n = ctx.u8(mem)?;
                self.state.rip = ctx.cur;
                return Ok(Exit::Interrupt(n));
            }

            // ---- IRET / IRETQ -------------------------------------------
            // Interrupt return. exemu has no GDT/IDT and models Wine's flat
            // WoW64 selectors, so `iretq` doubles as the full-context mode
            // switch `wow64cpu!BTCpuSimulate` uses on its resume path (roadmap
            // W5.2): pop RIP, CS, RFLAGS, RSP, SS — the popped CS selector picks
            // the operating mode (0x33 → 64-bit long, else 32-bit compat). Stack
            // slots are the operand width (8 with REX.W = iretq, else 4).
            0xCF => {
                let sp = self.state.rsp();
                let (rip, cs, rflags, new_rsp) = if ctx.pfx.w() {
                    (mem.read_u64(sp)?, mem.read_u64(sp + 8)?, mem.read_u64(sp + 16)?, mem.read_u64(sp + 24)?)
                } else {
                    (
                        mem.read_u32(sp)? as u64,
                        mem.read_u32(sp + 4)? as u64,
                        mem.read_u32(sp + 8)? as u64,
                        mem.read_u32(sp + 12)? as u64,
                    )
                };
                self.bits = if cs & 0xFFF8 == 0x30 { Bits::B64 } else { Bits::B32 };
                self.state.rflags = (rflags & 0x0000_0000_00FC_FFD5) | flags::RESERVED_ONE;
                self.state.set_rsp(new_rsp & self.addr_mask());
                self.state.rip = rip & self.addr_mask();
                return Ok(Exit::Continue);
            }

            // ---- LOOP / LOOPE / LOOPNE / JECXZ --------------------------
            0xE0..=0xE3 => {
                let rel = ctx.u8(mem)? as i8 as i64;
                let target = ctx.cur.wrapping_add(rel as u64) & self.addr_mask();
                let csize: u8 = if ctx.bits == Bits::B64 { 8 } else { 4 };
                let taken = if opcode == 0xE3 {
                    // JECXZ/JRCXZ: branch if the count is zero (no decrement).
                    self.state.gpr_read(1, csize) == 0
                } else {
                    // Decrement the count *without* touching flags; the
                    // LOOPE/LOOPNE condition tests the pre-existing ZF.
                    let cmask = alu::mask(csize);
                    let c = self.state.gpr_read(1, csize).wrapping_sub(1) & cmask;
                    self.state.gpr_write(1, csize, c);
                    let nonzero = c != 0;
                    match opcode {
                        0xE0 => nonzero && !self.state.flag(flags::ZF), // LOOPNE
                        0xE1 => nonzero && self.state.flag(flags::ZF),  // LOOPE
                        _ => nonzero,                                   // LOOP
                    }
                };
                self.state.rip = if taken { target } else { ctx.cur & self.addr_mask() };
                return Ok(Exit::Continue);
            }

            // ---- CALL rel32 / JMP rel32 / JMP rel8 ----------------------
            0xE8 => {
                let rel = ctx.u32(mem)? as i32 as i64;
                let ret = ctx.cur;
                self.push_stack(mem, ret)?;
                self.state.rip = ret.wrapping_add(rel as u64);
                return Ok(Exit::Continue);
            }
            0xE9 => {
                let rel = ctx.u32(mem)? as i32 as i64;
                self.state.rip = ctx.cur.wrapping_add(rel as u64);
                return Ok(Exit::Continue);
            }
            0xEB => {
                let rel = ctx.u8(mem)? as i8 as i64;
                self.state.rip = ctx.cur.wrapping_add(rel as u64);
                return Ok(Exit::Continue);
            }

            // ---- HLT -----------------------------------------------------
            0xF4 => return Ok(Exit::Halted),

            // ---- Group 3: F6/F7 -----------------------------------------
            0xF6 | 0xF7 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0xF6 { 1 } else { Self::opsize(&ctx) };
                match ctx.reg & 7 {
                    0 | 1 => {
                        let imm = if size == 1 {
                            ctx.u8(mem)? as u64
                        } else {
                            self.imm_z(&mut ctx, mem, size)?
                        };
                        let a = self.read_rm(&ctx, &*mem, size)?;
                        alu::logic(&mut self.state, a & imm, size);
                    }
                    2 => {
                        let v = self.read_rm(&ctx, &*mem, size)?;
                        self.write_rm(&ctx, mem, size, !v)?;
                    }
                    3 => {
                        let v = self.read_rm(&ctx, &*mem, size)?;
                        let r = alu::sub(&mut self.state, 0, v, 0, size);
                        self.write_rm(&ctx, mem, size, r)?;
                    }
                    4 => self.mul_op(mem, &ctx, size, false)?,
                    5 => self.mul_op(mem, &ctx, size, true)?,
                    6 => {
                        if let Some(e) = self.div_op(mem, &ctx, size, false)? {
                            return Ok(e);
                        }
                    }
                    _ => {
                        if let Some(e) = self.div_op(mem, &ctx, size, true)? {
                            return Ok(e);
                        }
                    }
                }
            }

            // ---- Flag ops ------------------------------------------------
            0xF8 => self.state.set_flag(flags::CF, false),
            0xF9 => self.state.set_flag(flags::CF, true),
            0xFA => self.state.set_flag(flags::IF, false),
            0xFB => self.state.set_flag(flags::IF, true),
            0xFC => self.state.set_flag(flags::DF, false),
            0xFD => self.state.set_flag(flags::DF, true),

            // ---- Group 4: INC/DEC r/m8 ----------------------------------
            0xFE => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.read_rm(&ctx, &*mem, 1)?;
                let r = if ctx.reg & 7 == 0 {
                    alu::inc(&mut self.state, v, 1)
                } else {
                    alu::dec(&mut self.state, v, 1)
                };
                self.write_rm(&ctx, mem, 1, r)?;
            }

            // ---- Group 5: INC/DEC/CALL/JMP/PUSH r/m ---------------------
            0xFF => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx);
                match ctx.reg & 7 {
                    0 => {
                        let v = self.read_rm(&ctx, &*mem, size)?;
                        let r = alu::inc(&mut self.state, v, size);
                        self.write_rm(&ctx, mem, size, r)?;
                    }
                    1 => {
                        let v = self.read_rm(&ctx, &*mem, size)?;
                        let r = alu::dec(&mut self.state, v, size);
                        self.write_rm(&ctx, mem, size, r)?;
                    }
                    2 => {
                        // CALL r/m (indirect, pointer-width operand)
                        let w = self.stack_width();
                        let target = self.read_rm(&ctx, &*mem, w)?;
                        let ret = ctx.cur;
                        self.push_stack(mem, ret)?;
                        self.state.rip = target & self.addr_mask();
                        return Ok(Exit::Continue);
                    }
                    4 => {
                        // JMP r/m (indirect)
                        let w = self.stack_width();
                        let target = self.read_rm(&ctx, &*mem, w)?;
                        self.state.rip = target & self.addr_mask();
                        return Ok(Exit::Continue);
                    }
                    5 => {
                        // JMP m16:32 / m16:64 — far *indirect* jump. exemu has no
                        // GDT; it models the flat WoW64 selectors, so the loaded CS
                        // selector picks the operating mode (index 6 / 0x33 →
                        // 64-bit long mode, else → 32-bit compat). This is the
                        // `Wow64Transition` CS-based mode switch (roadmap W5.2): the
                        // guest reads `[offset, selector]` from memory, and the
                        // mode change reinterprets the width of everything after.
                        // A far jump requires a memory operand.
                        let Rm::Mem { .. } = ctx.rm else {
                            return Err(EmuError::Unsupported(format!(
                                "far JMP with register operand at {start:#x}"
                            )));
                        };
                        let addr = ctx.rm_addr();
                        let offset = match size {
                            8 => mem.read_u64(addr)?,
                            _ => mem.read_u32(addr)? as u64,
                        };
                        let selector = mem.read_u16(addr + size as u64)?;
                        self.bits = if selector & 0xFFF8 == 0x30 { Bits::B64 } else { Bits::B32 };
                        self.state.rip = offset & self.addr_mask();
                        return Ok(Exit::Continue);
                    }
                    6 => {
                        let w = self.stack_width();
                        let v = self.read_rm(&ctx, &*mem, w)?;
                        self.push_stack(mem, v)?;
                    }
                    other => {
                        return Err(EmuError::Unsupported(format!("group5 /{other} at {start:#x}")));
                    }
                }
            }

            // ---- x87 FPU escapes ----------------------------------------
            0xD8..=0xDF => {
                self.exec_x87(&mut ctx, mem, opcode)?;
            }

            // ---- FWAIT / WAIT: no pending unmasked FP exceptions here ----
            0x9B => {}

            // ---- VEX prefixes (AVX/AVX2) --------------------------------
            // 0xC4 = 3-byte VEX, 0xC5 = 2-byte VEX. In 64-bit mode these bytes
            // are *always* VEX (LES/LDS are invalid in long mode). In 32-bit
            // mode they are LES/LDS unless the following byte's top two bits are
            // 11b, exactly how a real CPU disambiguates the encoding.
            0xC4 | 0xC5 => {
                let two_byte = opcode == 0xC5;
                if ctx.bits == Bits::B32 {
                    let peek = mem.read_u8(ctx.cur)?;
                    if peek >> 6 != 0b11 {
                        return Err(EmuError::Unsupported(format!("LES/LDS at {start:#x}")));
                    }
                }
                self.exec_vex(&mut ctx, mem, two_byte)?;
            }

            // ---- Two-byte opcodes ---------------------------------------
            0x0F => {
                let op2 = ctx.u8(mem)?;
                if let Some(exit) = self.exec_0f(&mut ctx, mem, op2, start)? {
                    return Ok(exit);
                }
            }

            other => {
                return Err(EmuError::Decode {
                    rip: start,
                    opcode: format!("{other:#04x}"),
                });
            }
        }

        self.state.rip = ctx.cur & self.addr_mask();
        Ok(Exit::Continue)
    }

    /// The `0x00..=0x3D` ALU family, driven by opcode high bits (operation)
    /// and low bits (operand form).
    fn alu_regular(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, opcode: u8) -> Result<()> {
        let op = opcode >> 3;
        let form = opcode & 7;
        let size = if form % 2 == 0 && form != 5 { 1 } else { Self::opsize(ctx) };
        match form {
            0 | 1 => {
                self.read_modrm(ctx, mem)?;
                let b = self.read_reg_field(ctx, size);
                let a = self.read_rm(ctx, &*mem, size)?;
                let r = self.do_alu(op, a, b, size);
                if op != 7 {
                    self.write_rm(ctx, mem, size, r)?;
                }
            }
            2 | 3 => {
                self.read_modrm(ctx, mem)?;
                let a = self.read_reg_field(ctx, size);
                let b = self.read_rm(ctx, &*mem, size)?;
                let r = self.do_alu(op, a, b, size);
                if op != 7 {
                    self.write_reg_field(ctx, size, r);
                }
            }
            4 => {
                let imm = ctx.u8(mem)? as u64;
                let a = self.state.gpr_read(0, 1);
                let r = self.do_alu(op, a, imm, 1);
                if op != 7 {
                    self.state.gpr_write(0, 1, r);
                }
            }
            _ => {
                // form 5: eAX, immZ
                let imm = self.imm_z(ctx, mem, size)?;
                let a = self.state.gpr_read(0, size);
                let r = self.do_alu(op, a, imm, size);
                if op != 7 {
                    self.state.gpr_write(0, size, r);
                }
            }
        }
        Ok(())
    }

    /// Apply one of the eight basic ALU operations, returning the result
    /// (for CMP the original `a` is returned and no write should occur).
    fn do_alu(&mut self, op: u8, a: u64, b: u64, size: u8) -> u64 {
        match op {
            0 => alu::add(&mut self.state, a, b, 0, size),
            1 => alu::logic(&mut self.state, a | b, size),
            2 => {
                let c = self.state.flag(flags::CF) as u64;
                alu::add(&mut self.state, a, b, c, size)
            }
            3 => {
                let c = self.state.flag(flags::CF) as u64;
                alu::sub(&mut self.state, a, b, c, size)
            }
            4 => alu::logic(&mut self.state, a & b, size),
            5 => alu::sub(&mut self.state, a, b, 0, size),
            6 => alu::logic(&mut self.state, a ^ b, size),
            _ => {
                alu::sub(&mut self.state, a, b, 0, size);
                a
            }
        }
    }

    /// Two-operand signed multiply truncated to `size`, setting CF/OF on
    /// overflow.
    fn imul_trunc(&mut self, a: u64, b: u64, size: u8) -> u64 {
        let prod = (alu::sext(a, size) as i64 as i128) * (alu::sext(b, size) as i64 as i128);
        let res = (prod as u64) & alu::mask(size);
        let overflow = (alu::sext(res, size) as i64 as i128) != prod;
        self.state.set_flag(flags::CF, overflow);
        self.state.set_flag(flags::OF, overflow);
        res
    }

    /// One-operand MUL/IMUL producing a double-width result in rDX:rAX (or AX
    /// for byte operands).
    fn mul_op(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8, signed: bool) -> Result<()> {
        let src = self.read_rm(ctx, &*mem, size)?;
        let a = self.state.gpr_read(0, size);
        let (lo, hi, flag) = if signed {
            let prod = (alu::sext(a, size) as i64 as i128) * (alu::sext(src, size) as i64 as i128);
            let lo = (prod as u64) & alu::mask(size);
            let hi = ((prod >> (size * 8)) as u64) & alu::mask(size);
            (lo, hi, (alu::sext(lo, size) as i64 as i128) != prod)
        } else {
            let prod = (a as u128) * (src as u128);
            let lo = (prod as u64) & alu::mask(size);
            let hi = ((prod >> (size * 8)) as u64) & alu::mask(size);
            (lo, hi, hi != 0)
        };
        if size == 1 {
            self.state.gpr_write(0, 2, lo | (hi << 8));
        } else {
            self.state.gpr_write(0, size, lo);
            self.state.gpr_write(2, size, hi);
        }
        self.state.set_flag(flags::CF, flag);
        self.state.set_flag(flags::OF, flag);
        Ok(())
    }

    /// One-operand DIV/IDIV. Returns `Some(Interrupt(0))` on divide error.
    fn div_op(
        &mut self,
        mem: &mut dyn Memory,
        ctx: &Ctx,
        size: u8,
        signed: bool,
    ) -> Result<Option<Exit>> {
        let divisor = self.read_rm(ctx, &*mem, size)?;
        if divisor == 0 {
            return Ok(Some(Exit::Interrupt(0)));
        }

        if size == 1 {
            let num = self.state.gpr_read(0, 2);
            let (q, r) = if signed {
                let n = num as i16;
                let d = divisor as u8 as i8 as i16;
                (n / d, n % d)
            } else {
                let n = num;
                let d = divisor & 0xff;
                ((n / d) as i16, (n % d) as i16)
            };
            if signed && !(-128..=127).contains(&q) {
                return Ok(Some(Exit::Interrupt(0)));
            }
            self.state.gpr_write(0, 1, q as u64);
            self.state.gpr_write_high8(0, r as u64);
            return Ok(None);
        }

        let lo = self.state.gpr_read(0, size);
        let hi = self.state.gpr_read(2, size);
        let bits = size as u32 * 8;
        if signed {
            let num = ((hi as i128) << bits) | (lo as i128 & (alu::mask(size) as i128));
            // sign-extend the assembled two's-complement value
            let num = (num << (128 - 2 * bits)) >> (128 - 2 * bits);
            let d = alu::sext(divisor, size) as i64 as i128;
            let q = num / d;
            let r = num % d;
            self.state.gpr_write(0, size, q as u64);
            self.state.gpr_write(2, size, r as u64);
        } else {
            let num = ((hi as u128) << bits) | (lo as u128);
            let d = divisor as u128;
            let q = num / d;
            let r = num % d;
            self.state.gpr_write(0, size, q as u64);
            self.state.gpr_write(2, size, r as u64);
        }
        Ok(None)
    }

    /// STOS[B/W/D/Q] with optional REP: store rAX to [rdi], advance rdi by
    /// ±size per the direction flag.
    fn string_stos(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8) -> Result<()> {
        let step = if self.state.flag(flags::DF) { (size as u64).wrapping_neg() } else { size as u64 };
        let val = self.state.gpr_read(0, size);
        let mut count = if ctx.pfx.rep != 0 { self.state.reg(exemu_core::Reg::Rcx) } else { 1 };
        while count > 0 {
            let di = self.state.reg(exemu_core::Reg::Rdi);
            mem.write_uint(di, size, val)?;
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step));
            count -= 1;
        }
        if ctx.pfx.rep != 0 {
            self.state.set_reg(exemu_core::Reg::Rcx, 0);
        }
        Ok(())
    }

    /// MOVS[B/W/D/Q] with optional REP: copy [rsi] → [rdi], advance both.
    fn string_movs(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8) -> Result<()> {
        let step = if self.state.flag(flags::DF) { (size as u64).wrapping_neg() } else { size as u64 };
        let mut count = if ctx.pfx.rep != 0 { self.state.reg(exemu_core::Reg::Rcx) } else { 1 };
        while count > 0 {
            let si = self.state.reg(exemu_core::Reg::Rsi);
            let di = self.state.reg(exemu_core::Reg::Rdi);
            let v = mem.read_uint(si, size)?;
            mem.write_uint(di, size, v)?;
            self.state.set_reg(exemu_core::Reg::Rsi, si.wrapping_add(step));
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step));
            count -= 1;
        }
        if ctx.pfx.rep != 0 {
            self.state.set_reg(exemu_core::Reg::Rcx, 0);
        }
        Ok(())
    }

    /// SCAS[B/W/D/Q]: compare the accumulator with `[rdi]`, advance rdi.
    /// With REPE/REPNE, repeat while the count is non-zero and ZF matches.
    fn string_scas(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8) -> Result<()> {
        let step = if self.state.flag(flags::DF) { (size as u64).wrapping_neg() } else { size as u64 };
        let acc = self.state.gpr_read(0, size);
        let rep = ctx.pfx.rep;
        loop {
            if rep != 0 && self.state.reg(exemu_core::Reg::Rcx) == 0 {
                break;
            }
            let di = self.state.reg(exemu_core::Reg::Rdi);
            let v = mem.read_uint(di, size)?;
            alu::sub(&mut self.state, acc, v, 0, size); // CMP acc, [rdi]
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step) & self.addr_mask());
            if rep == 0 || self.rep_string_break(rep) {
                break;
            }
        }
        Ok(())
    }

    /// CMPS[B/W/D/Q]: compare `[rsi]` with `[rdi]`, advance both.
    fn string_cmps(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8) -> Result<()> {
        let step = if self.state.flag(flags::DF) { (size as u64).wrapping_neg() } else { size as u64 };
        let rep = ctx.pfx.rep;
        loop {
            if rep != 0 && self.state.reg(exemu_core::Reg::Rcx) == 0 {
                break;
            }
            let si = self.state.reg(exemu_core::Reg::Rsi);
            let di = self.state.reg(exemu_core::Reg::Rdi);
            let a = mem.read_uint(si, size)?;
            let b = mem.read_uint(di, size)?;
            alu::sub(&mut self.state, a, b, 0, size); // CMP [rsi], [rdi]
            self.state.set_reg(exemu_core::Reg::Rsi, si.wrapping_add(step) & self.addr_mask());
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step) & self.addr_mask());
            if rep == 0 || self.rep_string_break(rep) {
                break;
            }
        }
        Ok(())
    }

    /// LODS[B/W/D/Q]: load `[rsi]` into the accumulator, advance rsi.
    fn string_lods(&mut self, mem: &mut dyn Memory, ctx: &Ctx, size: u8) -> Result<()> {
        let step = if self.state.flag(flags::DF) { (size as u64).wrapping_neg() } else { size as u64 };
        let mut count = if ctx.pfx.rep != 0 { self.state.reg(exemu_core::Reg::Rcx) } else { 1 };
        while count > 0 {
            let si = self.state.reg(exemu_core::Reg::Rsi);
            let v = mem.read_uint(si, size)?;
            self.state.gpr_write(0, size, v);
            self.state.set_reg(exemu_core::Reg::Rsi, si.wrapping_add(step) & self.addr_mask());
            count -= 1;
        }
        if ctx.pfx.rep != 0 {
            self.state.set_reg(exemu_core::Reg::Rcx, 0);
        }
        Ok(())
    }

    /// BT/BTS/BTR/BTC: test bit `idx` of the r/m operand into CF, then set,
    /// reset or complement it. `op2` selects the variant.
    fn bit_op(&mut self, ctx: &Ctx, mem: &mut dyn Memory, op2: u8, size: u8, idx: u64) -> Result<()> {
        let modify = |v: u64, bit: u32| -> u64 {
            match op2 {
                0xAB => v | (1u64 << bit),  // BTS
                0xB3 => v & !(1u64 << bit), // BTR
                0xBB => v ^ (1u64 << bit),  // BTC
                _ => v,                     // BT
            }
        };
        match ctx.rm {
            Rm::Reg(i) => {
                let bit = (idx % (size as u64 * 8)) as u32;
                let val = self.state.gpr_read(i, size);
                self.state.set_flag(flags::CF, (val >> bit) & 1 != 0);
                if op2 != 0xA3 {
                    self.state.gpr_write(i, size, modify(val, bit));
                }
            }
            Rm::Mem { .. } => {
                let base = ctx.rm_addr();
                let addr = (base as i64 + (idx as i64).div_euclid(8)) as u64 & self.addr_mask();
                let bit = (idx & 7) as u32;
                let byte = mem.read_u8(addr)?;
                self.state.set_flag(flags::CF, (byte >> bit) & 1 != 0);
                if op2 != 0xA3 {
                    mem.write_u8(addr, modify(byte as u64, bit) as u8)?;
                }
            }
        }
        Ok(())
    }

    /// Decrement the count and evaluate the REPE/REPNE termination condition
    /// for CMPS/SCAS. Returns true when the repetition should stop.
    fn rep_string_break(&mut self, rep: u8) -> bool {
        let c = self.state.reg(exemu_core::Reg::Rcx).wrapping_sub(1) & self.addr_mask();
        self.state.set_reg(exemu_core::Reg::Rcx, c);
        let zf = self.state.flag(flags::ZF);
        // REPE (F3): stop when ZF==0. REPNE (F2): stop when ZF==1.
        c == 0 || (rep == 0xF3 && !zf) || (rep == 0xF2 && zf)
    }

    /// `CPUID`: report only the features the interpreter actually implements.
    ///
    /// Honesty matters: MSVC/GCC CRTs branch on these bits to pick a `memcpy`/
    /// `memset`/`strlen` variant. Advertising AVX we cannot execute makes the
    /// CRT jump straight into a VEX-encoded loop and fault; advertising the
    /// SSE-family baseline we *do* support steers it onto code we can run.
    fn cpuid(&mut self) {
        let leaf = self.state.gpr_read(0, 4) as u32;
        let subleaf = self.state.gpr_read(1, 4) as u32;
        let (eax, ebx, ecx, edx) = Self::cpuid_leaf(leaf, subleaf);
        self.state.gpr_write(0, 4, eax as u64);
        self.state.gpr_write(3, 4, ebx as u64);
        self.state.gpr_write(1, 4, ecx as u64);
        self.state.gpr_write(2, 4, edx as u64);
    }

    /// Pure CPUID: `(leaf, subleaf) -> (EAX, EBX, ECX, EDX)`. Kept
    /// side-effect-free so the "advertised ⊆ implemented" invariant test can
    /// enumerate every reported feature bit and cross-check it against the
    /// decoder's actual capability table without hand-assembling `0F A2`.
    ///
    /// **Honesty invariant:** every feature bit set here MUST have its
    /// instruction(s) implemented and oracle-clean. See [`Self::CPUID_FEATURES`]
    /// for the machine-checkable bit→instruction map that guards this.
    pub fn cpuid_leaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        // Brand string returned by extended leaves 0x8000_0002..=0x8000_0004.
        const BRAND: &[u8; 48] = b"exemu virtual x86-64 CPU\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let brand_word = |i: usize| -> u32 {
            u32::from_le_bytes([BRAND[i], BRAND[i + 1], BRAND[i + 2], BRAND[i + 3]])
        };
        match leaf {
            // Standard: max leaf + "GenuineIntel" so feature detection that
            // keys off the vendor takes its Intel path (all we implement is
            // Intel-compatible). Max standard leaf is 0xD (XSAVE enumeration).
            0x0 => (0xD, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
            // Family/model/stepping + feature flags. ECX/EDX enumerate ONLY
            // implemented features. The interpreter covers the one-byte SSE/
            // SSE2 map plus POPCNT and the full three-byte 0F 38 / 0F 3A
            // SSSE3/SSE4.1/SSE4.2 family (roadmap W1.4), all oracle-clean, so
            // those bits are now advertised. AVX/XSAVE-compacted/MMX/AES: absent.
            0x1 => {
                // POPCNT (ECX.23) is a discrete feature bit. SSSE3 (ECX.9),
                // SSE4.1 (ECX.19) and SSE4.2 (ECX.20) are advertised now that the
                // 0F 38 / 0F 3A escapes (PSHUFB…PALIGNR, PTEST, ROUND*, PMULLD,
                // PCMPxSTRx, CRC32, …) are implemented and oracle-clean vs the
                // differential reference. XSAVE (ECX.26) + OSXSAVE (ECX.27) are
                // advertised because the full FXSAVE/XSAVE/XGETBV/XSETBV state is
                // implemented; a guest may XGETBV(XCR0) and see exactly the
                // x87+SSE components (0x3) the interpreter can restore.
                let ecx: u32 = (1 << 9)    // SSSE3
                    | (1 << 13)            // CMPXCHG16B (CX16) — roadmap W1.6
                    | (1 << 19)            // SSE4.1
                    | (1 << 20)            // SSE4.2
                    | (1 << 23)            // POPCNT
                    | (1 << 26)            // XSAVE
                    | (1 << 27)            // OSXSAVE (XCR0 accessible / CR4.OSXSAVE = 1)
                    | (1 << 28)            // AVX (VEX-encoded 256-bit float/int — roadmap W1.5)
                    | (1 << 29); // F16C (VCVTPH2PS/VCVTPS2PH — roadmap W1.6)
                let edx: u32 = 1        // FPU (bit 0; guaranteed in long mode)
                    | (1 << 4)          // TSC
                    | (1 << 15)         // CMOV
                    | (1 << 23)         // MMX (bare-form MMX + EMMS — roadmap W1.6)
                    | (1 << 24)         // FXSR
                    | (1 << 25)         // SSE
                    | (1 << 26); // SSE2
                (0x0003_06c3, 0x0001_0800, ecx, edx)
            }
            // Structured extended features. Sub-leaf 0 EBX enumerates: BMI1
            // (bit 3 — ANDN/BEXTR/BLSR/BLSMSK/BLSI, roadmap W1.6), AVX2 (bit 5),
            // BMI2 (bit 8 — MULX/PDEP/PEXT/BZHI/RORX/SARX/SHLX/SHRX, W1.6) and
            // ADX (bit 19 — ADCX/ADOX, W1.6). All are implemented in vex.rs /
            // exec.rs and oracle-verified. No AVX-512. EAX = max sub-leaf = 0.
            0x7 => match subleaf {
                0 => (0, (1 << 3) | (1 << 5) | (1 << 8) | (1 << 19), 0, 0),
                _ => (0, 0, 0, 0),
            },
            // XSAVE feature enumeration. Sub-leaf in ECX selects the view:
            //   ECX==0: EAX/EDX = XCR0 valid-bit mask (x87+SSE = 0x3), EBX = size
            //           of the XSAVE area for the *enabled* features in XCR0,
            //           ECX = maximum XSAVE area size for all supported features.
            //   ECX==1: XSAVE extended features (XSAVEOPT/XSAVEC/XGETBV1/XSAVES);
            //           none implemented ⇒ all zero.
            //   ECX>=2: per-component enumeration; none beyond x87+SSE ⇒ zero.
            // The x87+SSE standard area is the 512-byte legacy region plus the
            // 64-byte XSAVE header = 576 bytes.
            // With the AVX component (XCR0 bit 2) enabled, the standard XSAVE
            // area is the 512-byte legacy region + 64-byte header + 256-byte YMM
            // upper-half component = 832 bytes. Sub-leaf 2 enumerates the AVX
            // component itself: EAX = size (256), EBX = offset (576).
            0xD => match subleaf {
                0 => (XCR0_SUPPORTED as u32, 832, 832, (XCR0_SUPPORTED >> 32) as u32),
                2 => (256, 576, 0, 0),
                _ => (0, 0, 0, 0),
            },
            // Extended: max extended leaf. We implement the extended feature leaf
            // (0x8000_0001) and the three brand-string leaves, so the highest
            // extended leaf we answer honestly is 0x8000_0004.
            0x8000_0000 => (0x8000_0004, 0, 0, 0),
            // Extended features: LZCNT/ABM (ECX bit 5), SYSCALL (EDX bit 11),
            // RDTSCP (EDX bit 27, implemented since P1.8) and Long Mode
            // (EDX bit 29) — all implemented.
            0x8000_0001 => (0u32, 0, 1 << 5, (1 << 11) | (1 << 27) | (1 << 29)),
            0x8000_0002 => (brand_word(0), brand_word(4), brand_word(8), brand_word(12)),
            0x8000_0003 => (brand_word(16), brand_word(20), brand_word(24), brand_word(28)),
            0x8000_0004 => (brand_word(32), brand_word(36), brand_word(40), brand_word(44)),
            _ => (0, 0, 0, 0),
        }
    }

    /// The machine-checkable "advertised ⊆ implemented" table.
    ///
    /// Every capability **feature bit** the interpreter advertises through
    /// [`Self::cpuid_leaf`] appears here paired with a representative instruction
    /// that exercises it. The invariant test ([`cpu/tests/cpuid.rs`]) executes
    /// each `probe` and asserts the interpreter neither [`EmuError::Decode`]s nor
    /// [`EmuError::Unsupported`]s it, then cross-checks that **every** advertised
    /// feature-flag bit in the guarded words is covered by an entry — so a future
    /// step cannot flip a CPUID bit on (SSSE3/SSE4/AVX/BMI in W1.4–W1.6) without
    /// also landing its decoder support and adding its probe here. The words it
    /// guards are the pure feature-flag registers: leaf 1 ECX/EDX, leaf 7.0
    /// EBX/ECX/EDX, and leaf 0x8000_0001 ECX/EDX. (Structural fields — max-leaf,
    /// vendor, family, XSAVE sizes, brand string — are not feature flags and are
    /// excluded from the coverage cross-check.)
    ///
    /// `probe` is a **64-bit** encoding; the invariant test runs it in long mode.
    pub const CPUID_FEATURES: &'static [CpuidFeature] = &[
        // ---- leaf 1, EDX -----------------------------------------------------
        // bit 0: FPU (x87). FNINIT.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 0, name: "x87", probe: &[0x9B, 0xDB, 0xE3] },
        // bit 4: TSC. RDTSC.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 4, name: "tsc", probe: &[0x0F, 0x31] },
        // bit 15: CMOV. CMOVE r32, r/m32.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 15, name: "cmov", probe: &[0x0F, 0x44, 0xC1] },
        // bit 24: FXSR. FXSAVE [rax] (needs a mapped operand — the probe maps it).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 24, name: "fxsr", probe: &[0x0F, 0xAE, 0x00] },
        // bit 25: SSE. MOVAPS xmm0, xmm1.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 25, name: "sse", probe: &[0x0F, 0x28, 0xC1] },
        // bit 23: MMX. PXOR mm0, mm0 (bare 0F EF, no mandatory prefix).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 23, name: "mmx", probe: &[0x0F, 0xEF, 0xC0] },
        // bit 26: SSE2. MOVAPD xmm0, xmm1 (66 0F 28).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 26, name: "sse2", probe: &[0x66, 0x0F, 0x28, 0xC1] },
        // ---- leaf 1, ECX -----------------------------------------------------
        // bit 9: SSSE3. PSHUFB xmm0, xmm1 (66 0F 38 00).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 9, name: "ssse3", probe: &[0x66, 0x0F, 0x38, 0x00, 0xC1] },
        // bit 13: CMPXCHG16B (CX16). REX.W 0F C7 /1 [rax] (the probe maps [rax],
        // aligned to 16 bytes; a mismatch just clears ZF and loads RDX:RAX).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 13, name: "cx16", probe: &[0x48, 0x0F, 0xC7, 0x08] },
        // bit 19: SSE4.1. PMULLD xmm0, xmm1 (66 0F 38 40).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 19, name: "sse4.1", probe: &[0x66, 0x0F, 0x38, 0x40, 0xC1] },
        // bit 20: SSE4.2. PCMPISTRI xmm0, xmm1, 0 (66 0F 3A 63 /r ib) — the
        // string-compare family + CRC32; this probe exercises the 0F 3A escape.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 20, name: "sse4.2", probe: &[0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x00] },
        // bit 23: POPCNT. POPCNT r32, r/m32 (F3 0F B8).
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 23, name: "popcnt", probe: &[0xF3, 0x0F, 0xB8, 0xC1] },
        // bit 26: XSAVE. XSAVE [rax] (0F AE /4) — the probe maps the operand.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 26, name: "xsave", probe: &[0x0F, 0xAE, 0x20] },
        // bit 27: OSXSAVE. XGETBV (0F 01 D0) reads XCR0 — the OS-enabled path.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 27, name: "osxsave", probe: &[0x0F, 0x01, 0xD0] },
        // bit 28: AVX. VXORPS xmm0, xmm0, xmm0 (VEX.128 NP 0F 57) — a VEX-encoded
        // float op. Its decode proves the 0xC5 VEX prefix + 0F map are handled.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 28, name: "avx", probe: &[0xC5, 0xF8, 0x57, 0xC0] },
        // bit 29: F16C. VCVTPH2PS xmm0, xmm1 (VEX.128.66.0F38.W0 13) — roadmap W1.6.
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 29, name: "f16c", probe: &[0xC4, 0xE2, 0x79, 0x13, 0xC1] },
        // ---- leaf 7.0, EBX ---------------------------------------------------
        // bit 3: BMI1. ANDN eax, ebx, ecx (VEX.NDS.LZ.0F38.W0 F2) — roadmap W1.6.
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 3, name: "bmi1", probe: &[0xC4, 0xE2, 0x60, 0xF2, 0xC1] },
        // bit 5: AVX2. VPADDD ymm0, ymm0, ymm0 (VEX.256 66 0F FE) — a 256-bit
        // integer op, proving the AVX2 lane-wise integer surface decodes.
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 5, name: "avx2", probe: &[0xC5, 0xFD, 0xFE, 0xC0] },
        // bit 8: BMI2. MULX eax, ebx, ecx (VEX.NDD.LZ.F2.0F38.W0 F6) — roadmap W1.6.
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 8, name: "bmi2", probe: &[0xC4, 0xE2, 0x63, 0xF6, 0xC1] },
        // bit 19: ADX. ADCX eax, ecx (66 0F38 F6) — roadmap W1.6.
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 19, name: "adx", probe: &[0x66, 0x0F, 0x38, 0xF6, 0xC1] },
        // ---- leaf 0x8000_0001, ECX ------------------------------------------
        // bit 5: LZCNT/ABM. LZCNT r32, r/m32 (F3 0F BD).
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Ecx, bit: 5, name: "lzcnt", probe: &[0xF3, 0x0F, 0xBD, 0xC1] },
        // ---- leaf 0x8000_0001, EDX ------------------------------------------
        // bit 11: SYSCALL. (Routed to the syscall layer, not #UD — a decode of
        // the two SYSCALL bytes must not fault at the decoder.)
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 11, name: "syscall", probe: &[0x0F, 0x05] },
        // bit 27: RDTSCP (0F 01 F9) — implemented since P1.8 (EDX:EAX = TSC,
        // ECX = IA32_TSC_AUX = 0).
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 27, name: "rdtscp", probe: &[0x0F, 0x01, 0xF9] },
        // bit 29: Long Mode. CDQE (REX.W 98) is a 64-bit-only encoding.
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 29, name: "long-mode", probe: &[0x48, 0x98] },
    ];

    /// The set of CPUID (leaf, sub, register) words that are **feature-flag
    /// words** whose every advertised bit must be covered by [`Self::CPUID_FEATURES`].
    /// Pairs with the table above so the invariant test can prove *completeness*
    /// (no advertised bit is un-probed) as well as *soundness* (every probe
    /// decodes). Leaf 7.0's EBX/ECX/EDX are here too: exemu advertises none, so
    /// the "all bits covered" check is trivially satisfied and stays that way
    /// until a future step both flips a bit and adds its probe.
    pub const CPUID_FEATURE_WORDS: &'static [(u32, u32, CpuidReg)] = &[
        (1, 0, CpuidReg::Ecx),
        (1, 0, CpuidReg::Edx),
        (7, 0, CpuidReg::Ebx),
        (7, 0, CpuidReg::Ecx),
        (7, 0, CpuidReg::Edx),
        (0x8000_0001, 0, CpuidReg::Ecx),
        (0x8000_0001, 0, CpuidReg::Edx),
    ];

    /// Build the 512-byte FXSAVE / XSAVE legacy area from the current x87 + SSE
    /// state, per the Intel SDM "FXSAVE Area" layout:
    ///
    /// | off | field            | off | field                     |
    /// |-----|------------------|-----|---------------------------|
    /// | 0   | FCW (2)          | 24  | MXCSR (4)                 |
    /// | 2   | FSW (2)          | 28  | MXCSR_MASK (4)            |
    /// | 4   | abridged FTW (1) | 32  | ST0..ST7, 16 bytes each   |
    /// | 6   | FOP (2)          | 160 | XMM0..XMM15, 16 bytes each|
    /// | 8   | FIP (4 or 8)     |     |                           |
    /// | 16  | FDP (4 or 8)     |     |                           |
    ///
    /// `rexw` selects the 64-bit-pointer form (FXSAVE64), where FIP occupies
    /// bytes 8..16 and FDP bytes 16..24; the 32-bit form stores FIP at 8..12,
    /// FCS at 12..14, FDP at 16..20, FDS at 20..22 (the two-word "pointer +
    /// selector" packing). ST registers are stored as their raw 80 bits in the
    /// low 10 bytes of each 16-byte slot **ST-relative to TOP** (ST0 first).
    fn build_fxsave_area(&self, rexw: bool) -> [u8; 512] {
        let x = &self.state.x87;
        let mut buf = [0u8; 512];
        buf[0..2].copy_from_slice(&x.cw.to_le_bytes());
        buf[2..4].copy_from_slice(&x.sw.to_le_bytes());
        buf[4] = abridged_ftw(x.tw); // FTW: 1 bit per physical register
        // buf[5] reserved
        buf[6..8].copy_from_slice(&x.fop.to_le_bytes());
        if rexw {
            buf[8..16].copy_from_slice(&x.fip.to_le_bytes());
            buf[16..24].copy_from_slice(&x.fdp.to_le_bytes());
        } else {
            buf[8..12].copy_from_slice(&(x.fip as u32).to_le_bytes());
            buf[12..14].copy_from_slice(&x.fcs.to_le_bytes());
            buf[16..20].copy_from_slice(&(x.fdp as u32).to_le_bytes());
            buf[20..22].copy_from_slice(&x.fds.to_le_bytes());
        }
        buf[24..28].copy_from_slice(&self.mxcsr.to_le_bytes());
        buf[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());
        // ST registers, ST-relative (ST0 = physical TOP), 10 raw bytes each.
        for i in 0..8u8 {
            let v = x.st[x.phys(i)];
            let off = 32 + i as usize * 16;
            buf[off..off + 10].copy_from_slice(&v.to_le_bytes()[..10]);
        }
        // XMM registers. In 64-bit mode all 16 are saved; in 32-bit mode only
        // XMM0..7 exist, so XMM8..15 (offset 288..416) is left as the zeroed
        // reserved region — hardware leaves it undefined there.
        let nxmm = match self.bits {
            Bits::B64 => 16,
            Bits::B32 => 8,
        };
        for (i, r) in self.state.xmm.iter().take(nxmm).enumerate() {
            let off = 160 + i * 16;
            buf[off..off + 16].copy_from_slice(&r.to_le_bytes());
        }
        buf
    }

    /// Restore x87 + SSE state from a 512-byte FXSAVE area (the inverse of
    /// [`Self::build_fxsave_area`]). The abridged FTW is expanded back to the
    /// full 2-bit-per-register tag word by classifying each restored 80-bit
    /// register, exactly as real hardware does on FXRSTOR.
    fn restore_fxsave_area(&mut self, buf: &[u8; 512], rexw: bool) {
        self.restore_x87_component(buf, rexw);
        self.mxcsr = u32::from_le_bytes(buf[24..28].try_into().unwrap()) & MXCSR_MASK;
        self.restore_xmm_component(buf);
    }

    /// Restore the x87 slice (FCW/FSW/abridged-FTW/FOP/FIP/FDP + ST0–7) from a
    /// 512-byte area. Sets `sw` first so `phys()` reflects the restored TOP, then
    /// expands the abridged FTW back to the full tag word by classifying each
    /// loaded 80-bit register, exactly as hardware does.
    fn restore_x87_component(&mut self, buf: &[u8; 512], rexw: bool) {
        let ftw_abridged = buf[4];
        self.state.x87.sw = u16::from_le_bytes([buf[2], buf[3]]);
        self.state.x87.cw = u16::from_le_bytes([buf[0], buf[1]]);
        self.state.x87.fop = u16::from_le_bytes([buf[6], buf[7]]);
        if rexw {
            self.state.x87.fip = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            self.state.x87.fcs = 0;
            self.state.x87.fdp = u64::from_le_bytes(buf[16..24].try_into().unwrap());
            self.state.x87.fds = 0;
        } else {
            self.state.x87.fip = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as u64;
            self.state.x87.fcs = u16::from_le_bytes([buf[12], buf[13]]);
            self.state.x87.fdp = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as u64;
            self.state.x87.fds = u16::from_le_bytes([buf[20], buf[21]]);
        }
        let mut full_tw: u16 = 0;
        for i in 0..8u8 {
            let off = 32 + i as usize * 16;
            let mut b = [0u8; 16];
            b[..10].copy_from_slice(&buf[off..off + 10]);
            let v = u128::from_le_bytes(b) & ((1u128 << 80) - 1);
            let phys = self.state.x87.phys(i);
            self.state.x87.st[phys] = v;
            // Expand the abridged bit: 0 ⇒ empty (0b11); 1 ⇒ classify the value.
            let tag = if ftw_abridged & (1 << phys) == 0 { 0b11 } else { full_tag(v) };
            full_tw |= (tag & 0b11) << (phys as u16 * 2);
        }
        self.state.x87.tw = full_tw;
    }

    /// Restore the XMM registers from a 512-byte area (offset 160, 16 bytes
    /// each). 64-bit mode restores XMM0–15; 32-bit mode restores only XMM0–7
    /// (XMM8–15 do not exist there and are left unchanged).
    fn restore_xmm_component(&mut self, buf: &[u8; 512]) {
        let nxmm = match self.bits {
            Bits::B64 => 16,
            Bits::B32 => 8,
        };
        for i in 0..nxmm {
            let off = 160 + i * 16;
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[off..off + 16]);
            self.state.xmm[i] = u128::from_le_bytes(b);
        }
    }

    /// Write the AVX state component (YMM upper 128 bits, `ymm0_hi..ymm15_hi`)
    /// to the extended XSAVE area at offset 576 — 16 bytes per register, in
    /// register-number order. 32-bit mode saves only the eight low registers.
    fn write_avx_component(&self, mem: &mut dyn Memory, addr: u64) -> Result<()> {
        let n = match self.bits {
            Bits::B64 => 16,
            Bits::B32 => 8,
        };
        for i in 0..n {
            mem.write(addr + 576 + (i as u64) * 16, &self.state.ymm_hi[i].to_le_bytes())?;
        }
        Ok(())
    }

    /// Restore the AVX state component from offset 576 (inverse of
    /// [`Self::write_avx_component`]).
    fn read_avx_component(&mut self, mem: &dyn Memory, addr: u64) -> Result<()> {
        let n = match self.bits {
            Bits::B64 => 16,
            Bits::B32 => 8,
        };
        for i in 0..n {
            let mut b = [0u8; 16];
            mem.read(addr + 576 + (i as u64) * 16, &mut b)?;
            self.state.ymm_hi[i] = u128::from_le_bytes(b);
        }
        Ok(())
    }

    /// The requested-feature bitmap for an XSAVE/XRSTOR: `(EDX:EAX) AND XCR0`,
    /// intersected with the components the interpreter implements.
    fn xsave_rfbm(&self) -> u64 {
        let eax = self.state.gpr_read(0, 4);
        let edx = self.state.gpr_read(2, 4);
        ((edx << 32) | eax) & self.xcr0 & XCR0_SUPPORTED
    }

    /// Apply an XRSTOR: for each requested component, restore it from `area` if
    /// its `xstate_bv` bit is set, otherwise reset it to its INIT configuration.
    fn xrstor_apply(&mut self, area: &[u8; 512], rfbm: u64, xstate_bv: u64, rexw: bool) {
        // x87 component (bit 0): restore from memory, or reset to the FNINIT
        // state (control words reset, registers zeroed) if not in XSTATE_BV.
        if rfbm & 1 != 0 {
            if xstate_bv & 1 != 0 {
                self.restore_x87_component(area, rexw);
            } else {
                self.state.x87 = exemu_core::X87::new();
            }
        }
        // SSE component (bit 1): the XMM registers *and* MXCSR. Per the SDM,
        // MXCSR is always loaded from the area when RFBM[1] is set (regardless
        // of XSTATE_BV[1]); the XMM registers are loaded only if XSTATE_BV[1] is
        // set, else reset to zero.
        if rfbm & 2 != 0 {
            self.mxcsr = u32::from_le_bytes(area[24..28].try_into().unwrap()) & MXCSR_MASK;
            if xstate_bv & 2 != 0 {
                self.restore_xmm_component(area);
            } else {
                self.state.xmm = [0u128; 16];
            }
        }
    }

    /// Two-byte (0x0F) opcode group. Returns `Some(exit)` only for the rare
    /// arms that divert control flow; otherwise `None` and the caller's tail
    /// advances `rip`.
    fn exec_0f(
        &mut self,
        ctx: &mut Ctx,
        mem: &mut dyn Memory,
        op2: u8,
        start: u64,
    ) -> Result<Option<Exit>> {
        // Bare-form (no 66/F3/F2 mandatory prefix) MMX ops alias onto the x87
        // register file — they must NOT be treated as 128-bit XMM. Route them to
        // the MMX unit before the SSE dispatch below. (The `66`/`F3`/`F2` forms
        // of the same opcodes are SSE and fall through to `exec_sse`.)
        let no_mandatory = ctx.pfx.rep == 0 && !ctx.pfx.p66;
        if no_mandatory && crate::mmx::is_mmx(op2) {
            self.exec_mmx(ctx, mem, op2)?;
            return Ok(None);
        }
        // EMMS (0F 77, no prefix): clear the x87/MMX tag word to all-empty. The
        // `66`/VEX form of 0F 77 is VZEROUPPER/VZEROALL (handled by the VEX path).
        if op2 == 0x77 && no_mandatory {
            self.state.x87.emms();
            return Ok(None);
        }
        // The SSE/SSE2 family (two-byte opcodes with a mandatory prefix) is
        // handled by its own unit.
        if crate::sse::is_sse(op2) {
            self.exec_sse(ctx, mem, op2)?;
            return Ok(None);
        }
        match op2 {
            // SYSCALL (0F 05) — apply the hardware side-effects here and hand
            // the SSDT index (eax) to the OS layer's syscall seam (roadmap
            // W2.2). Hardware: RIP of the next instruction → RCX, RFLAGS → R11,
            // RIP ← the SYSCALL target (here: past the instruction; the OS
            // dispatcher runs natively). Nothing is pushed to the guest stack.
            0x05 => {
                let ret_rip = ctx.cur;
                self.state.set_reg(exemu_core::Reg::Rcx, ret_rip);
                self.state.set_reg(exemu_core::Reg::R11, self.state.rflags);
                self.state.rip = ret_rip;
                let index = self.state.gpr_read(exemu_core::Reg::Rax as u8, 4) as u32;
                return Ok(Some(Exit::Syscall(index)));
            }
            // UD2
            0x0B => return Err(EmuError::Unsupported(format!("ud2 at {start:#x}"))),

            // endbr64 / multi-byte NOP: consume ModRM, do nothing.
            0x1E | 0x1F => {
                self.read_modrm(ctx, mem)?;
            }

            // CPUID: report an honest feature set (only what we execute).
            0xA2 => self.cpuid(),
            // RDTSC: return the monotonic counter in EDX:EAX and advance it.
            0x31 => {
                let t = self.tsc;
                self.tsc = self.tsc.wrapping_add(64);
                self.state.gpr_write(0, 4, t & 0xffff_ffff);
                self.state.gpr_write(2, 4, t >> 32);
            }

            // 0F 01 /sub — RDTSCP (sub-byte 0xF9) and system instructions.
            // Only RDTSCP is implemented; all other sub-encodings (SGDT, SIDT,
            // LGDT, LIDT, SMSW, LMSW, INVLPG, SWAPGS, …) are rejected cleanly
            // rather than silently no-op'd.
            0x01 => {
                let sub = ctx.u8(mem)?;
                match sub {
                    // RDTSCP (0F 01 F9): EDX:EAX = TSC (identical to RDTSC
                    // semantics — monotonic, wrapping_add(64) each call), and
                    // ECX = IA32_TSC_AUX = 0 (processor id; 0 is correct for
                    // the single-vCPU model).  No flags are touched.
                    0xF9 => {
                        let t = self.tsc;
                        self.tsc = self.tsc.wrapping_add(64);
                        self.state.gpr_write(0, 4, t & 0xffff_ffff); // EAX = TSC[31:0]
                        self.state.gpr_write(2, 4, t >> 32); // EDX = TSC[63:32]
                        self.state.gpr_write(1, 4, 0); // ECX = IA32_TSC_AUX (processor 0)
                    }
                    // XGETBV (0F 01 D0): read the extended-control register
                    // selected by ECX into EDX:EAX. Only XCR0 (ECX==0) exists.
                    0xD0 => {
                        let ecx = self.state.gpr_read(1, 4);
                        // ECX != 0 selects a non-existent XCR ⇒ #GP on hardware;
                        // Wine only ever reads XCR0, so report 0 for anything else
                        // rather than faulting.
                        let val = if ecx == 0 { self.xcr0 } else { 0 };
                        self.state.gpr_write(0, 4, val & 0xffff_ffff);
                        self.state.gpr_write(2, 4, val >> 32);
                    }
                    // XSETBV (0F 01 D1): write EDX:EAX to the XCR selected by ECX.
                    // Only XCR0 exists, bit 0 (x87) is mandatory, and only bits
                    // the interpreter implements may be enabled.
                    0xD1 => {
                        let ecx = self.state.gpr_read(1, 4);
                        if ecx == 0 {
                            let eax = self.state.gpr_read(0, 4);
                            let edx = self.state.gpr_read(2, 4);
                            let requested = (edx << 32) | eax;
                            // Silently clamp to the supported set (bit 0 forced on).
                            self.xcr0 = (requested & XCR0_SUPPORTED) | 1;
                        }
                    }
                    other => {
                        return Err(EmuError::Unsupported(format!(
                            "0f 01 {other:#04x} at {start:#x}"
                        )));
                    }
                }
            }

            // 0F AE group 15: FXSAVE/FXRSTOR (/0,/1), LDMXCSR/STMXCSR (/2,/3),
            // XSAVE/XRSTOR (/4,/5 memory form), and the register-form memory
            // fences LFENCE (/5)/MFENCE (/6)/SFENCE (/7) + CLFLUSH (/7 memory).
            0xAE => {
                self.read_modrm(ctx, mem)?;
                let digit = ctx.reg & 7;
                let is_mem = matches!(ctx.rm, Rm::Mem { .. });
                // Register-form /5,/6,/7 are the fences (LFENCE/MFENCE/SFENCE),
                // single-threaded ⇒ no-ops. Memory-form /6 (CLFLUSH) is also a
                // no-op. Memory-form /4 (XSAVE) and /5 (XRSTOR) are handled below.
                if !is_mem && digit >= 5 {
                    return Ok(None);
                }
                if is_mem && (digit == 6 || digit == 7) {
                    return Ok(None); // CLFLUSH / CLFLUSHOPT: no-op
                }
                let addr = ctx.rm_addr();
                let rexw = ctx.pfx.w();
                match digit {
                    // FXSAVE / FXSAVE64 (REX.W): write the full 512-byte area.
                    0 => {
                        let buf = self.build_fxsave_area(rexw);
                        mem.write(addr, &buf)?;
                    }
                    // FXRSTOR / FXRSTOR64: load the full 512-byte area.
                    1 => {
                        let mut buf = [0u8; 512];
                        mem.read(addr, &mut buf)?;
                        self.restore_fxsave_area(&buf, rexw);
                    }
                    // LDMXCSR / STMXCSR: load/store the 32-bit control word.
                    2 => self.mxcsr = mem.read_u32(addr)? & MXCSR_MASK,
                    3 => mem.write_u32(addr, self.mxcsr)?,
                    // XSAVE / XSAVE64: standard form. The state to save is
                    // (EDX:EAX requested-feature-mask) AND XCR0; only the x87
                    // (bit 0) and SSE (bit 1) components are implemented.
                    4 => {
                        let rfbm = self.xsave_rfbm();
                        let buf = self.build_fxsave_area(rexw);
                        mem.write(addr, &buf)?;
                        // XSAVE header: standard form writes only the 8-byte
                        // XSTATE_BV at offset 512, updating exactly the bits in
                        // RFBM and preserving the rest (SDM: "XSTATE_BV[i] is set
                        // to modified value only for i in RFBM; other bits keep
                        // their prior value"). The standard form always writes
                        // the x87+SSE FXSAVE sub-area, so both are marked in-use.
                        // XCOMP_BV (offset 520) and the reserved header bytes are
                        // left untouched, matching hardware's standard form.
                        //
                        // AVX component (bit 2): when requested, the YMM upper
                        // halves are written at offset 576 (the extended state
                        // area — 16 bytes per register). It is marked in-use in
                        // XSTATE_BV only if any upper half is non-zero (the
                        // "init optimization" is not modelled, so we simply
                        // reflect whether the component was written).
                        if rfbm & 4 != 0 {
                            self.write_avx_component(mem, addr)?;
                        }
                        let old_bv = mem.read_u64(addr + 512)?;
                        let new_bv = (old_bv & !rfbm) | (rfbm & XCR0_SUPPORTED);
                        mem.write_u64(addr + 512, new_bv)?;
                    }
                    // XRSTOR / XRSTOR64: standard form. Restore each requested
                    // component from memory if its XSTATE_BV bit is set, else
                    // reset it to its INIT value (x87 → FNINIT, SSE → zeroed).
                    5 => {
                        let rfbm = self.xsave_rfbm();
                        let mut area = [0u8; 512];
                        mem.read(addr, &mut area)?;
                        let xstate_bv = mem.read_u64(addr + 512)?;
                        self.xrstor_apply(&area, rfbm, xstate_bv, rexw);
                        // AVX component (bit 2): restore the YMM upper halves from
                        // offset 576 if present in XSTATE_BV, else INIT (zeroed).
                        if rfbm & 4 != 0 {
                            if xstate_bv & 4 != 0 {
                                self.read_avx_component(mem, addr)?;
                            } else {
                                self.state.ymm_hi = [0u128; 16];
                            }
                        }
                    }
                    _ => {
                        return Err(EmuError::Unsupported(format!(
                            "0f ae /{digit} at {start:#x}"
                        )))
                    }
                }
            }

            // CMOVcc r, r/m
            0x40..=0x4F => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let v = self.read_rm(ctx, &*mem, size)?;
                // The destination is written unconditionally: on a taken move
                // with the source, otherwise with its own current value. That
                // matters in 64-bit mode, where a 32-bit write zero-extends the
                // upper half even when the condition is *not* met.
                let keep = self.read_reg_field(ctx, size);
                let val = if self.cond(op2 & 0xF) { v } else { keep };
                self.write_reg_field(ctx, size, val);
            }

            // Jcc rel32
            0x80..=0x8F => {
                let rel = ctx.u32(mem)? as i32 as i64;
                let taken = self.cond(op2 & 0xF);
                self.state.rip = if taken { ctx.cur.wrapping_add(rel as u64) } else { ctx.cur };
                return Ok(Some(Exit::Continue));
            }

            // SETcc r/m8
            0x90..=0x9F => {
                self.read_modrm(ctx, mem)?;
                let v = self.cond(op2 & 0xF) as u64;
                self.write_rm(ctx, mem, 1, v)?;
            }

            // IMUL r, r/m
            0xAF => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let a = self.read_reg_field(ctx, size);
                let b = self.read_rm(ctx, &*mem, size)?;
                let r = self.imul_trunc(a, b, size);
                self.write_reg_field(ctx, size, r);
            }

            // MOVZX / MOVSX
            0xB6 | 0xB7 => {
                self.read_modrm(ctx, mem)?;
                let src_size = if op2 == 0xB6 { 1 } else { 2 };
                let dst = Self::opsize(ctx);
                let v = self.read_rm(ctx, &*mem, src_size)?;
                self.write_reg_field(ctx, dst, v & alu::mask(src_size));
            }
            0xBE | 0xBF => {
                self.read_modrm(ctx, mem)?;
                let src_size = if op2 == 0xBE { 1 } else { 2 };
                let dst = Self::opsize(ctx);
                let v = self.read_rm(ctx, &*mem, src_size)?;
                self.write_reg_field(ctx, dst, alu::sext(v, src_size) & alu::mask(dst));
            }

            // ---- SHLD / SHRD --------------------------------------------
            0xA4 | 0xA5 | 0xAC | 0xAD => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let count = if op2 & 1 == 0 { ctx.u8(mem)? as u64 } else { self.state.gpr_read(1, 1) };
                let dst = self.read_rm(ctx, &*mem, size)?;
                let src = self.read_reg_field(ctx, size);
                let r = if op2 < 0xAC {
                    alu::shld(&mut self.state, dst, src, count, size)
                } else {
                    alu::shrd(&mut self.state, dst, src, count, size)
                };
                self.write_rm(ctx, mem, size, r)?;
            }

            // ---- BT / BTS / BTR / BTC (reg bit index) -------------------
            0xA3 | 0xAB | 0xB3 | 0xBB => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let idx = self.read_reg_field(ctx, size);
                self.bit_op(ctx, mem, op2, size, idx)?;
            }
            // ---- Group 8: BT/BTS/BTR/BTC r/m, imm8 ----------------------
            0xBA => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let idx = ctx.u8(mem)? as u64;
                let sub = match ctx.reg & 7 {
                    4 => 0xA3, // BT
                    5 => 0xAB, // BTS
                    6 => 0xB3, // BTR
                    _ => 0xBB, // BTC
                };
                self.bit_op(ctx, mem, sub, size, idx)?;
            }

            // ---- BSF / BSR, or (with F3) TZCNT / LZCNT ------------------
            //
            // BMI1's TZCNT/LZCNT reuse the BSF/BSR opcodes under a mandatory
            // F3 prefix. On a CPU without BMI1 the F3 is ignored and these
            // decode as BSF/BSR — but modern compilers emit them unconditionally
            // and rely on the distinct zero-input result (operand width, not
            // "undefined") and on CF, so we honour the prefix.
            0xBC | 0xBD => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let bits = size as u32 * 8;
                let v = self.read_rm(ctx, &*mem, size)? & alu::mask(size);
                if ctx.pfx.rep == 0xF3 {
                    // TZCNT (BC) / LZCNT (BD).
                    let cnt = if v == 0 {
                        bits
                    } else if op2 == 0xBC {
                        v.trailing_zeros()
                    } else {
                        v.leading_zeros() - (64 - bits)
                    };
                    self.write_reg_field(ctx, size, cnt as u64);
                    self.state.set_flag(flags::CF, v == 0);
                    self.state.set_flag(flags::ZF, cnt == 0);
                    for f in [flags::OF, flags::SF, flags::AF, flags::PF] {
                        self.state.set_flag(f, false);
                    }
                } else if v == 0 {
                    // BSF/BSR of 0: ZF set, destination undefined (left as-is).
                    self.state.set_flag(flags::ZF, true);
                } else {
                    self.state.set_flag(flags::ZF, false);
                    let idx = if op2 == 0xBC { v.trailing_zeros() } else { 63 - v.leading_zeros() };
                    self.write_reg_field(ctx, size, idx as u64);
                }
            }

            // ---- POPCNT (F3 0F B8) --------------------------------------
            0xB8 if ctx.pfx.rep == 0xF3 => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let v = self.read_rm(ctx, &*mem, size)? & alu::mask(size);
                self.write_reg_field(ctx, size, v.count_ones() as u64);
                self.state.set_flag(flags::ZF, v == 0);
                for f in [flags::CF, flags::OF, flags::SF, flags::AF, flags::PF] {
                    self.state.set_flag(f, false);
                }
            }

            // ---- BSWAP r32/r64 ------------------------------------------
            0xC8..=0xCF => {
                let r = (op2 & 7) | (ctx.pfx.b() << 3);
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.state.gpr_read(r, size);
                let swapped = if size == 8 { v.swap_bytes() } else { (v as u32).swap_bytes() as u64 };
                self.state.gpr_write(r, size, swapped);
            }

            // ---- XADD ---------------------------------------------------
            // LOCK-atomic invariant (roadmap W2.15): the memory operand is read
            // exactly once (`read_rm`) and written exactly once (`write_rm`)
            // with no block/yield point between, so under the cooperative
            // scheduler `lock xadd` is one indivisible read-modify-write.
            0xC0 | 0xC1 => {
                self.read_modrm(ctx, mem)?;
                let size = if op2 == 0xC0 { 1 } else { Self::opsize(ctx) };
                let dst = self.read_rm(ctx, &*mem, size)?;
                let src = self.read_reg_field(ctx, size);
                let sum = alu::add(&mut self.state, dst, src, 0, size);
                self.write_reg_field(ctx, size, dst);
                self.write_rm(ctx, mem, size, sum)?;
            }
            // ---- CMPXCHG ------------------------------------------------
            // LOCK-atomic invariant (roadmap W2.15): the destination is read
            // once and written once with no intervening block/yield point, so
            // `lock cmpxchg` is one indivisible compare-and-swap under the
            // cooperative scheduler — the CAS-increment pin test in
            // crates/os/tests relies on this holding for every guest thread.
            0xB0 | 0xB1 => {
                self.read_modrm(ctx, mem)?;
                let size = if op2 == 0xB0 { 1 } else { Self::opsize(ctx) };
                let dst = self.read_rm(ctx, &*mem, size)?;
                let acc = self.state.gpr_read(0, size);
                alu::sub(&mut self.state, acc, dst, 0, size); // sets ZF on equality
                let equal = self.state.flag(flags::ZF);
                // Read the source before touching the accumulator (they may
                // alias). x86 CMPXCHG always writes *both* the accumulator (with
                // the old destination) and the destination (with the source when
                // equal, else with itself) — so 32-bit forms zero-extend the
                // upper half of each register regardless of the branch taken.
                let store = if equal { self.read_reg_field(ctx, size) } else { dst };
                self.state.gpr_write(0, size, dst);
                self.write_rm(ctx, mem, size, store)?;
            }

            // ---- Group 9: CMPXCHG8B / CMPXCHG16B (0F C7 /1) -------------
            // /1 memory form: 8-byte compare-exchange (EDX:EAX vs m64, store
            // ECX:EBX) or, with REX.W, 16-byte (RDX:RAX vs m128, store RCX:RBX).
            // Only ZF is affected. CMPXCHG16B requires 16-byte alignment (#GP
            // otherwise). Wine 11.0 ntdll uses CMPXCHG16B 5×.
            0xC7 => {
                self.read_modrm(ctx, mem)?;
                let digit = ctx.reg & 7;
                if digit != 1 {
                    return Err(EmuError::Unsupported(format!("0f c7 /{digit} at {start:#x}")));
                }
                let addr = match ctx.rm {
                    Rm::Mem { .. } => ctx.rm_addr(),
                    Rm::Reg(_) => return Err(EmuError::Unsupported(format!("cmpxchg8b/16b reg-form at {start:#x}"))),
                };
                if ctx.pfx.w() {
                    // CMPXCHG16B: 16-byte alignment required — #GP(0) otherwise,
                    // surfaced as the general-protection interrupt vector.
                    if addr & 0xF != 0 {
                        self.state.rip = ctx.cur & self.addr_mask();
                        return Ok(Some(Exit::Interrupt(13)));
                    }
                    let lo = mem.read_u64(addr)?;
                    let hi = mem.read_u64(addr.wrapping_add(8))?;
                    let rax = self.state.gpr_read(0, 8);
                    let rdx = self.state.gpr_read(2, 8);
                    if lo == rax && hi == rdx {
                        self.state.set_flag(flags::ZF, true);
                        let rbx = self.state.gpr_read(3, 8);
                        let rcx = self.state.gpr_read(1, 8);
                        mem.write_u64(addr, rbx)?;
                        mem.write_u64(addr.wrapping_add(8), rcx)?;
                    } else {
                        self.state.set_flag(flags::ZF, false);
                        self.state.gpr_write(0, 8, lo); // RAX = mem low
                        self.state.gpr_write(2, 8, hi); // RDX = mem high
                    }
                } else {
                    // CMPXCHG8B: 64-bit compare-exchange (default in 32-bit mode).
                    let val = mem.read_u64(addr)?;
                    let eax = self.state.gpr_read(0, 4);
                    let edx = self.state.gpr_read(2, 4);
                    let cmp = (edx << 32) | eax;
                    if val == cmp {
                        self.state.set_flag(flags::ZF, true);
                        let ebx = self.state.gpr_read(3, 4);
                        let ecx = self.state.gpr_read(1, 4);
                        mem.write_u64(addr, (ecx << 32) | ebx)?;
                    } else {
                        self.state.set_flag(flags::ZF, false);
                        self.state.gpr_write(0, 4, val & 0xffff_ffff); // EAX = mem[31:0]
                        self.state.gpr_write(2, 4, val >> 32); // EDX = mem[63:32]
                    }
                }
            }

            // ---- Three-byte 0F 38 escape --------------------------------
            // MOVBE (F0/F1 without F2) is the one GP-register op here; the F2
            // F0/F1 forms are CRC32, and the rest of the map is the SSSE3 /
            // SSE4.1 / SSE4.2 packed family, routed to the SSE unit.
            0x38 => {
                let op3 = ctx.u8(mem)?;
                match op3 {
                    // MOVBE — load (F0) / store (F1) with byte reversal. Under
                    // an F2 prefix these two opcodes encode CRC32 instead, which
                    // the SSE unit handles.
                    0xF0 | 0xF1 if ctx.pfx.rep != 0xF2 => {
                        self.read_modrm(ctx, mem)?;
                        let size = Self::opsize(ctx);
                        let bswap = |v: u64| match size {
                            2 => (v as u16).swap_bytes() as u64,
                            4 => (v as u32).swap_bytes() as u64,
                            _ => v.swap_bytes(),
                        };
                        if op3 == 0xF0 {
                            let v = self.read_rm(ctx, &*mem, size)?;
                            self.write_reg_field(ctx, size, bswap(v));
                        } else {
                            let v = self.read_reg_field(ctx, size);
                            self.write_rm(ctx, mem, size, bswap(v))?;
                        }
                    }
                    // ADCX (66 0F38 F6) / ADOX (F3 0F38 F6). These are the ADX
                    // extension's flag-isolated add-with-carry ops: ADCX uses and
                    // updates ONLY CF; ADOX uses and updates ONLY OF. Every other
                    // status flag is left untouched — that's the whole point (two
                    // independent carry chains for big-integer multiply). The F2
                    // form of 0F38 F6 is MULX (VEX-only, handled in vex.rs); the
                    // no-prefix legacy form is invalid.
                    0xF6 if ctx.pfx.p66 || ctx.pfx.rep == 0xF3 => {
                        self.read_modrm(ctx, mem)?;
                        let size = if ctx.pfx.w() { 8 } else { 4 };
                        let m = alu::mask(size);
                        let dst = self.read_reg_field(ctx, size) & m;
                        let src = self.read_rm(ctx, &*mem, size)? & m;
                        let use_of = ctx.pfx.rep == 0xF3; // ADOX
                        let carry_in = if use_of {
                            self.state.flag(flags::OF) as u128
                        } else {
                            self.state.flag(flags::CF) as u128
                        };
                        let full = dst as u128 + src as u128 + carry_in;
                        let res = (full as u64) & m;
                        let carry_out = (full >> (size * 8)) & 1 != 0;
                        self.write_reg_field(ctx, size, res);
                        // Update only the isolated flag; preserve all others.
                        self.state.set_flag(if use_of { flags::OF } else { flags::CF }, carry_out);
                    }
                    _ => self.exec_sse_0f38(ctx, mem, op3)?,
                }
            }

            // ---- Three-byte 0F 3A escape (SSSE3/SSE4 imm8 ops) ----------
            0x3A => {
                let op3 = ctx.u8(mem)?;
                self.exec_sse_0f3a(ctx, mem, op3)?;
            }

            other => {
                return Err(EmuError::Decode {
                    rip: start,
                    opcode: format!("0f {other:#04x}"),
                });
            }
        }
        Ok(None)
    }
}

/// Compress the full 2-bit-per-register x87 tag word into the 1-bit-per-register
/// **abridged** form stored in the FXSAVE area (byte 4): bit *j* is 0 when
/// physical register *j* is empty (full tag `0b11`), 1 otherwise. This is the
/// exact encoding real hardware writes — FXSAVE never records the fine-grained
/// zero/special/valid distinction, only empty-vs-not.
fn abridged_ftw(full: u16) -> u8 {
    let mut out = 0u8;
    for j in 0..8 {
        let tag = (full >> (j * 2)) & 0b11;
        if tag != 0b11 {
            out |= 1 << j;
        }
    }
    out
}

/// Classify an 80-bit register value into its full 2-bit x87 tag (valid / zero /
/// special). Used by FXRSTOR to expand the abridged FTW back to the tag word,
/// exactly as hardware does: a non-empty register's tag is recomputed from its
/// stored bit pattern.
fn full_tag(v: u128) -> u16 {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    let integer_bit = signif & 0x8000_0000_0000_0000 != 0;
    if exp == 0 && signif == 0 {
        0b01 // zero
    } else if exp == 0x7fff || (exp == 0 && signif != 0) || (exp != 0 && !integer_bit) {
        0b10 // special (NaN/Inf/denormal/unnormal)
    } else {
        0b00 // valid
    }
}
