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
        };

        self.read_prefixes(&mut ctx, mem)?;
        let opcode = ctx.u8(mem)?;

        // The regular ALU opcodes 0x00..=0x3D share one handler.
        if opcode < 0x40 && (opcode & 7) < 6 {
            self.alu_regular(&mut ctx, mem, opcode)?;
            self.state.rip = ctx.cur;
            return Ok(Exit::Continue);
        }

        match opcode {
            // ---- PUSH/POP r64 -------------------------------------------
            0x50..=0x57 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let v = self.state.gpr[r as usize];
                self.push64(mem, v)?;
            }
            0x58..=0x5F => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let v = self.pop64(mem)?;
                self.state.gpr[r as usize] = v;
            }

            0x68 => {
                let imm = alu::sext(ctx.u32(mem)? as u64, 4);
                self.push64(mem, imm)?;
            }
            0x6A => {
                let imm = alu::sext(ctx.u8(mem)? as u64, 1);
                self.push64(mem, imm)?;
            }

            // ---- MOVSXD r64, r/m32 --------------------------------------
            0x63 => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.read_rm(&ctx, &*mem, 4)?;
                let size = Self::opsize(&ctx.pfx);
                self.write_reg_field(&ctx, size, alu::sext(v, 4) & alu::mask(size));
            }

            // ---- IMUL r, r/m, imm ---------------------------------------
            0x69 | 0x6B => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx.pfx);
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
                let size = if opcode == 0x80 { 1 } else { Self::opsize(&ctx.pfx) };
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
                let size = if opcode == 0x84 { 1 } else { Self::opsize(&ctx.pfx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                alu::logic(&mut self.state, a & b, size);
            }

            // ---- XCHG r/m, r --------------------------------------------
            0x86 | 0x87 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x86 { 1 } else { Self::opsize(&ctx.pfx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                self.write_rm(&ctx, mem, size, b)?;
                self.write_reg_field(&ctx, size, a);
            }

            // ---- MOV r/m<->r --------------------------------------------
            0x88 | 0x89 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x88 { 1 } else { Self::opsize(&ctx.pfx) };
                let v = self.read_reg_field(&ctx, size);
                self.write_rm(&ctx, mem, size, v)?;
            }
            0x8A | 0x8B => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x8A { 1 } else { Self::opsize(&ctx.pfx) };
                let v = self.read_rm(&ctx, &*mem, size)?;
                self.write_reg_field(&ctx, size, v);
            }

            // ---- LEA r, m -----------------------------------------------
            0x8D => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx.pfx);
                let addr = ctx.rm_addr();
                self.write_reg_field(&ctx, size, addr);
            }

            // ---- POP r/m (group 1A) -------------------------------------
            0x8F => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.pop64(mem)?;
                self.write_rm(&ctx, mem, 8, v)?;
            }

            // ---- XCHG rAX, r / NOP / PAUSE ------------------------------
            0x90..=0x97 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                if r != 0 {
                    let size = Self::opsize(&ctx.pfx);
                    let a = self.state.gpr_read(0, size);
                    let b = self.state.gpr_read(r, size);
                    self.state.gpr_write(0, size, b);
                    self.state.gpr_write(r, size, a);
                }
                // r == 0 → plain NOP (also PAUSE when preceded by F3).
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
                let size = Self::opsize(&ctx.pfx);
                let a = self.state.gpr_read(0, size);
                let hi = if a & alu::sign_bit(size) != 0 { alu::mask(size) } else { 0 };
                self.state.gpr_write(2, size, hi);
            }

            // ---- TEST AL/eAX, imm ---------------------------------------
            0xA8 => {
                let imm = ctx.u8(mem)? as u64;
                let a = self.state.gpr_read(0, 1);
                alu::logic(&mut self.state, a & imm, 1);
            }
            0xA9 => {
                let size = Self::opsize(&ctx.pfx);
                let imm = self.imm_z(&mut ctx, mem, size)?;
                let a = self.state.gpr_read(0, size);
                alu::logic(&mut self.state, a & imm, size);
            }

            // ---- String ops: MOVS / STOS (with optional REP) ------------
            0xA4 | 0xA5 => {
                let size = if opcode == 0xA4 { 1 } else { Self::opsize(&ctx.pfx) };
                self.string_movs(mem, &ctx, size)?;
            }
            0xAA | 0xAB => {
                let size = if opcode == 0xAA { 1 } else { Self::opsize(&ctx.pfx) };
                self.string_stos(mem, &ctx, size)?;
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
                let size = if opcode & 1 == 0 { 1 } else { Self::opsize(&ctx.pfx) };
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
                let ret = self.pop64(mem)?;
                self.state.set_rsp(self.state.rsp().wrapping_add(extra));
                self.state.rip = ret;
                return Ok(Exit::Continue);
            }
            0xC3 => {
                let ret = self.pop64(mem)?;
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
                let size = Self::opsize(&ctx.pfx);
                let imm = self.imm_z(&mut ctx, mem, size)?;
                self.write_rm(&ctx, mem, size, imm)?;
            }

            // ---- LEAVE ---------------------------------------------------
            0xC9 => {
                let bp = self.state.reg(exemu_core::Reg::Rbp);
                self.state.set_rsp(bp);
                let v = self.pop64(mem)?;
                self.state.set_reg(exemu_core::Reg::Rbp, v);
            }

            // ---- INT3 / INT imm8 ----------------------------------------
            0xCC => return Ok(Exit::Interrupt(3)),
            0xCD => {
                let n = ctx.u8(mem)?;
                self.state.rip = ctx.cur;
                return Ok(Exit::Interrupt(n));
            }

            // ---- CALL rel32 / JMP rel32 / JMP rel8 ----------------------
            0xE8 => {
                let rel = ctx.u32(mem)? as i32 as i64;
                let ret = ctx.cur;
                self.push64(mem, ret)?;
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
                let size = if opcode == 0xF6 { 1 } else { Self::opsize(&ctx.pfx) };
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
                let size = Self::opsize(&ctx.pfx);
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
                        // CALL r/m64
                        let target = self.read_rm(&ctx, &*mem, 8)?;
                        let ret = ctx.cur;
                        self.push64(mem, ret)?;
                        self.state.rip = target;
                        return Ok(Exit::Continue);
                    }
                    4 => {
                        // JMP r/m64
                        let target = self.read_rm(&ctx, &*mem, 8)?;
                        self.state.rip = target;
                        return Ok(Exit::Continue);
                    }
                    6 => {
                        let v = self.read_rm(&ctx, &*mem, 8)?;
                        self.push64(mem, v)?;
                    }
                    other => {
                        return Err(EmuError::Unsupported(format!("group5 /{other} at {start:#x}")));
                    }
                }
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

        self.state.rip = ctx.cur;
        Ok(Exit::Continue)
    }

    /// The `0x00..=0x3D` ALU family, driven by opcode high bits (operation)
    /// and low bits (operand form).
    fn alu_regular(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, opcode: u8) -> Result<()> {
        let op = opcode >> 3;
        let form = opcode & 7;
        let size = if form % 2 == 0 && form != 5 { 1 } else { Self::opsize(&ctx.pfx) };
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
        let prod = (alu::sext(a, size) as i128) * (alu::sext(b, size) as i128);
        let res = (prod as u64) & alu::mask(size);
        let overflow = (alu::sext(res, size) as i128) != prod;
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
            let prod = (alu::sext(a, size) as i128) * (alu::sext(src, size) as i128);
            let lo = (prod as u64) & alu::mask(size);
            let hi = ((prod >> (size * 8)) as u64) & alu::mask(size);
            (lo, hi, (alu::sext(lo, size) as i128) != prod)
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
            let d = alu::sext(divisor, size) as i128;
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

            // CPUID / RDTSC: minimal stubs (report nothing).
            0xA2 => {
                for r in [0usize, 1, 2, 3] {
                    self.state.gpr_write(r as u8, 4, 0);
                }
            }
            0x31 => {
                self.state.gpr_write(0, 4, 0);
                self.state.gpr_write(2, 4, 0);
            }

            // CMOVcc r, r/m
            0x40..=0x4F => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(&ctx.pfx);
                let v = self.read_rm(ctx, &*mem, size)?;
                if self.cond(op2 & 0xF) {
                    self.write_reg_field(ctx, size, v);
                }
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
                let size = Self::opsize(&ctx.pfx);
                let a = self.read_reg_field(ctx, size);
                let b = self.read_rm(ctx, &*mem, size)?;
                let r = self.imul_trunc(a, b, size);
                self.write_reg_field(ctx, size, r);
            }

            // MOVZX / MOVSX
            0xB6 | 0xB7 => {
                self.read_modrm(ctx, mem)?;
                let src_size = if op2 == 0xB6 { 1 } else { 2 };
                let dst = Self::opsize(&ctx.pfx);
                let v = self.read_rm(ctx, &*mem, src_size)?;
                self.write_reg_field(ctx, dst, v & alu::mask(src_size));
            }
            0xBE | 0xBF => {
                self.read_modrm(ctx, mem)?;
                let src_size = if op2 == 0xBE { 1 } else { 2 };
                let dst = Self::opsize(&ctx.pfx);
                let v = self.read_rm(ctx, &*mem, src_size)?;
                self.write_reg_field(ctx, dst, alu::sext(v, src_size) & alu::mask(dst));
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
