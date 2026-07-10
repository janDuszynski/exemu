//! The instruction dispatch: `execute_one` fetches, decodes and runs a
//! single instruction. Split out from `lib.rs` purely for length.
//!
//! Control-flow instructions set `rip` themselves and `return`. Every other
//! instruction falls out of the `match`, after which the shared tail sets
//! `rip` to the first byte past the instruction.

use super::*;
use crate::alu::{self, Shift};
use exemu_core::cpu::flags;

impl Interpreter {
    pub(crate) fn execute_one(&mut self, mem: &mut dyn Memory) -> Result<Exit> {
        let start = self.state.rip;
        let mut ctx = Ctx {
            pfx: Prefixes::default(),
            cur: start,
            reg: 0,
            rm: Rm::Reg(0),
            bits: self.bits,
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
        // Brand string returned by extended leaves 0x8000_0002..=0x8000_0004.
        const BRAND: &[u8; 48] = b"exemu virtual x86-64 CPU\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let brand_word = |i: usize| -> u32 {
            u32::from_le_bytes([BRAND[i], BRAND[i + 1], BRAND[i + 2], BRAND[i + 3]])
        };
        let (eax, ebx, ecx, edx) = match leaf {
            // Standard: max leaf + "GenuineIntel" so feature detection that
            // keys off the vendor takes its Intel path (all we implement is
            // Intel-compatible).
            0x0 => (0x7, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
            // Family/model/stepping + feature flags. ECX/EDX enumerate ONLY
            // implemented features. The interpreter covers the one-byte SSE/
            // SSE2 map plus POPCNT; the three-byte 0F 38 / 0F 3A escapes that
            // carry SSSE3/SSE4.1/SSE4.2 are NOT decoded, so those bits are
            // withheld (advertising them would steer the CRT into pshufb /
            // pcmpistri / crc32 we cannot execute). AVX/XSAVE/MMX/AES: absent.
            0x1 => {
                // POPCNT (ECX.23) is a discrete feature bit, valid to report
                // without SSE4.2 (ECX.20), which we do not implement.
                let ecx: u32 = 1 << 23; // POPCNT
                let edx: u32 = 1        // FPU (bit 0; guaranteed in long mode)
                    | (1 << 4)          // TSC
                    | (1 << 15)         // CMOV
                    | (1 << 24)         // FXSR
                    | (1 << 25)         // SSE
                    | (1 << 26); // SSE2
                (0x0003_06c3, 0x0001_0800, ecx, edx)
            }
            // Structured extended features. All zero: no BMI1/BMI2/AVX2/AVX-512
            // (we have TZCNT/LZCNT but not the rest of BMI1, so we do not claim
            // the BMI1 bit).
            0x7 => (0, 0, 0, 0),
            // Extended: max extended leaf.
            0x8000_0000 => (0x8000_0004, 0, 0, 0),
            // Extended features: LZCNT/ABM (ECX bit 5), SYSCALL (EDX bit 11)
            // and Long Mode (EDX bit 29) — all implemented.
            0x8000_0001 => (0u32, 0, 1 << 5, (1 << 11) | (1 << 29)),
            0x8000_0002 => (brand_word(0), brand_word(4), brand_word(8), brand_word(12)),
            0x8000_0003 => (brand_word(16), brand_word(20), brand_word(24), brand_word(28)),
            0x8000_0004 => (brand_word(32), brand_word(36), brand_word(40), brand_word(44)),
            _ => (0, 0, 0, 0),
        };
        self.state.gpr_write(0, 4, eax as u64);
        self.state.gpr_write(3, 4, ebx as u64);
        self.state.gpr_write(1, 4, ecx as u64);
        self.state.gpr_write(2, 4, edx as u64);
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
        // The SSE/SSE2 family (two-byte opcodes with a mandatory prefix) is
        // handled by its own unit.
        if crate::sse::is_sse(op2) {
            self.exec_sse(ctx, mem, op2)?;
            return Ok(None);
        }
        match op2 {
            // SYSCALL — surfaced as a distinguished interrupt for the OS loop.
            0x05 => {
                self.state.rip = ctx.cur;
                return Ok(Some(Exit::Interrupt(0x80)));
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
                    other => {
                        return Err(EmuError::Unsupported(format!(
                            "0f 01 {other:#04x} at {start:#x}"
                        )));
                    }
                }
            }

            // 0F AE group 15: FXSAVE/FXRSTOR (/0,/1), LDMXCSR/STMXCSR (/2,/3),
            // and the memory fences LFENCE/MFENCE/SFENCE + CLFLUSH (/5,/6,/7).
            0xAE => {
                self.read_modrm(ctx, mem)?;
                let digit = ctx.reg & 7;
                // Fences and CLFLUSH: single-threaded, so no-ops (ModRM consumed).
                if digit >= 5 {
                    return Ok(None);
                }
                let addr = ctx.rm_addr();
                match digit {
                    // FXSAVE: 512-byte area. We model MXCSR (off 24) + MXCSR_MASK
                    // (off 28) + XMM0..15 (off 160, 16 bytes each); the x87 area
                    // is zeroed (no x87 state yet).
                    0 => {
                        let mut buf = [0u8; 512];
                        buf[24..28].copy_from_slice(&self.mxcsr.to_le_bytes());
                        buf[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());
                        for i in 0..16 {
                            let off = 160 + i * 16;
                            buf[off..off + 16].copy_from_slice(&self.state.xmm[i].to_le_bytes());
                        }
                        mem.write(addr, &buf)?;
                    }
                    // FXRSTOR: restore MXCSR + XMM from the 512-byte area.
                    1 => {
                        let mut buf = [0u8; 512];
                        mem.read(addr, &mut buf)?;
                        self.mxcsr =
                            u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]) & MXCSR_MASK;
                        for i in 0..16 {
                            let off = 160 + i * 16;
                            let mut b = [0u8; 16];
                            b.copy_from_slice(&buf[off..off + 16]);
                            self.state.xmm[i] = u128::from_le_bytes(b);
                        }
                    }
                    // LDMXCSR / STMXCSR: load/store the 32-bit control word.
                    2 => self.mxcsr = mem.read_u32(addr)? & MXCSR_MASK,
                    3 => mem.write_u32(addr, self.mxcsr)?,
                    _ => {
                        return Err(EmuError::Unsupported(format!(
                            "0f ae /{digit} (xsave) at {start:#x}"
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

            // ---- Three-byte 0F 38 escape --------------------------------
            // Only MOVBE is decoded here for now; this arm is also the future
            // home of the SSSE3 / SSE4 instructions (pshufb, pcmpistri, …),
            // which is why CPUID withholds those feature bits until they land.
            0x38 => {
                let op3 = ctx.u8(mem)?;
                match op3 {
                    // MOVBE — load (F0) / store (F1) with byte reversal. Under
                    // an F2 prefix these encode CRC32, which we do not
                    // implement, so exclude that case.
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
                    other => {
                        return Err(EmuError::Decode {
                            rip: start,
                            opcode: format!("0f 38 {other:#04x}"),
                        });
                    }
                }
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
