use super::*;
use crate::alu::{self, Shift};
use exemu_core::cpu::flags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuidReg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

impl CpuidReg {
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

#[derive(Debug, Clone, Copy)]
pub struct CpuidFeature {
    pub leaf: u32,
    pub sub: u32,
    pub reg: CpuidReg,
    pub bit: u8,
    pub name: &'static str,
    pub probe: &'static [u8],
}

impl Interpreter {
    #[inline]
    pub(crate) fn segment_selector(&self, idx: u8) -> u16 {
        match idx {
            1 => match self.bits {
                Bits::B64 => SEL_CS64,
                Bits::B32 => SEL_CS32,
            },
            _ => SEL_DATA,
        }
    }

    pub(crate) fn execute_one(&mut self, mem: &mut dyn Memory) -> Result<Exit> {
        let start = self.state.rip;
        let (ibuf, ibuf_n) = Ctx::prefetch(&*mem, start);
        let mut ctx = Ctx {
            pfx: Prefixes::default(),
            cur: start,
            reg: 0,
            rm: Rm::Reg(0),
            bits: self.bits,
            u8_at_op: 0,
            ibuf,
            ibuf_base: start,
            ibuf_n,
        };

        self.read_prefixes(&mut ctx, mem)?;
        let opcode = ctx.u8(mem)?;

        #[cfg(feature = "profile")]
        if opcode != 0x0F {
            let greg = if crate::profile::is_group(opcode, false) {
                ctx.peek().map_or(0, |m| (m >> 3) & 7)
            } else {
                0
            };
            crate::profile::record(opcode, false, ctx.pfx.w(), ctx.pfx.p66, greg);
        }

        if opcode < 0x40 && (opcode & 7) < 6 {
            self.alu_regular(&mut ctx, mem, opcode)?;
            self.state.rip = ctx.cur & self.addr_mask();
            return Ok(Exit::Continue);
        }

        match opcode {
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

            0x60 => {
                let esp = self.state.rsp();
                for r in [0u8, 1, 2, 3] {
                    let v = self.state.gpr_read(r, 4);
                    self.push_stack(mem, v)?;
                }
                self.push_stack(mem, esp)?;
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
                let _esp = self.pop_stack(mem)?;
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

            0x63 => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.read_rm(&ctx, &*mem, 4)?;
                let size = Self::opsize(&ctx);
                self.write_reg_field(&ctx, size, alu::sext(v, 4) & alu::mask(size));
            }

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

            0x70..=0x7F => {
                let rel = ctx.u8(mem)? as i8 as i64;
                let taken = self.cond(opcode & 0xF);
                let target = if taken { ctx.cur.wrapping_add(rel as u64) } else { ctx.cur };
                self.state.rip = target & self.addr_mask();
                return Ok(Exit::Continue);
            }

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

            0x84 | 0x85 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x84 { 1 } else { Self::opsize(&ctx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                alu::logic(&mut self.state, a & b, size);
            }

            0x86 | 0x87 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode == 0x86 { 1 } else { Self::opsize(&ctx) };
                let a = self.read_rm(&ctx, &*mem, size)?;
                let b = self.read_reg_field(&ctx, size);
                self.write_rm(&ctx, mem, size, b)?;
                self.write_reg_field(&ctx, size, a);
            }

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

            0x8C => {
                self.read_modrm(&mut ctx, mem)?;
                let sel = self.segment_selector(ctx.reg & 7) as u64;
                self.write_rm(&ctx, mem, 2, sel)?;
            }
            0x8E => {
                self.read_modrm(&mut ctx, mem)?;
                let _selector = self.read_rm(&ctx, &*mem, 2)?;
            }

            0x8D => {
                self.read_modrm(&mut ctx, mem)?;
                let size = Self::opsize(&ctx);
                let addr = ctx.rm_addr();
                self.write_reg_field(&ctx, size, addr);
            }

            0x8F => {
                self.read_modrm(&mut ctx, mem)?;
                let v = self.pop_stack(mem)?;
                let w = self.stack_width();
                self.write_rm(&ctx, mem, w, v)?;
            }

            0x90..=0x97 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                if r != 0 {
                    let size = Self::opsize(&ctx);
                    let a = self.state.gpr_read(0, size);
                    let b = self.state.gpr_read(r, size);
                    self.state.gpr_write(0, size, b);
                    self.state.gpr_write(r, size, a);
                }
            }

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

            0x9C => {
                let flags = self.state.rflags;
                self.push_stack(mem, flags)?;
            }
            0x9D => {
                let v = self.pop_stack(mem)?;
                self.state.rflags = (v & 0x0000_0000_00FC_FFD5) | flags::RESERVED_ONE;
            }

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

            0xA0..=0xA3 => {
                let mut addr = if ctx.bits == Bits::B64 { ctx.u64(mem)? } else { ctx.u32(mem)? as u64 };
                if ctx.pfx.seg == 0x64 {
                    addr = addr.wrapping_add(self.fs_base(ctx.bits));
                } else if ctx.pfx.seg == 0x65 {
                    addr = addr.wrapping_add(self.state.gs_base);
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

            0xB0..=0xB7 => {
                let r = (opcode & 7) | (ctx.pfx.b() << 3);
                let imm = ctx.u8(mem)? as u64;
                self.write_gpr(r, 1, ctx.pfx.has_rex, imm);
            }
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
                    self.state.gpr_write(r, 4, imm);
                }
            }

            0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => {
                self.read_modrm(&mut ctx, mem)?;
                let size = if opcode & 1 == 0 { 1 } else { Self::opsize(&ctx) };
                let kind = Shift::from_reg(ctx.reg);
                let count = match opcode {
                    0xC0 | 0xC1 => ctx.u8(mem)? as u64,
                    0xD0 | 0xD1 => 1,
                    _ => self.state.gpr_read(1, 1),
                };
                let v = self.read_rm(&ctx, &*mem, size)?;
                let r = alu::shift(&mut self.state, kind, v, count, size);
                self.write_rm(&ctx, mem, size, r)?;
            }

            0xC2 => {
                let extra = ctx.u16(mem)? as u64;
                let ret = self.pop_stack(mem)?;
                self.state.set_rsp(self.state.rsp().wrapping_add(extra) & self.addr_mask());
                self.state.rip = ret;
                return Ok(Exit::Continue);
            }
            0xC3 => {
                let ret = self.pop_stack(mem)?;
                self.state.rip = ret;
                return Ok(Exit::Continue);
            }

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

            0xC9 => {
                let bp = self.state.reg(exemu_core::Reg::Rbp);
                self.state.set_rsp(bp);
                let v = self.pop_stack(mem)?;
                self.state.set_reg(exemu_core::Reg::Rbp, v);
            }

            0xCC => return Ok(Exit::Interrupt(3)),
            0xCD => {
                let n = ctx.u8(mem)?;
                self.state.rip = ctx.cur;
                return Ok(Exit::Interrupt(n));
            }

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

            0xE0..=0xE3 => {
                let rel = ctx.u8(mem)? as i8 as i64;
                let target = ctx.cur.wrapping_add(rel as u64) & self.addr_mask();
                let csize: u8 = if ctx.bits == Bits::B64 { 8 } else { 4 };
                let taken = if opcode == 0xE3 {
                    self.state.gpr_read(1, csize) == 0
                } else {
                    let cmask = alu::mask(csize);
                    let c = self.state.gpr_read(1, csize).wrapping_sub(1) & cmask;
                    self.state.gpr_write(1, csize, c);
                    let nonzero = c != 0;
                    match opcode {
                        0xE0 => nonzero && !self.state.flag(flags::ZF),
                        0xE1 => nonzero && self.state.flag(flags::ZF),
                        _ => nonzero,
                    }
                };
                self.state.rip = if taken { target } else { ctx.cur & self.addr_mask() };
                return Ok(Exit::Continue);
            }

            0xE8 => {
                let rel = ctx.u32(mem)? as i32 as i64;
                let ret = ctx.cur;
                self.push_stack(mem, ret)?;
                self.state.rip = ret.wrapping_add(rel as u64) & self.addr_mask();
                return Ok(Exit::Continue);
            }
            0xE9 => {
                let rel = ctx.u32(mem)? as i32 as i64;
                self.state.rip = ctx.cur.wrapping_add(rel as u64) & self.addr_mask();
                return Ok(Exit::Continue);
            }
            0xEB => {
                let rel = ctx.u8(mem)? as i8 as i64;
                self.state.rip = ctx.cur.wrapping_add(rel as u64) & self.addr_mask();
                return Ok(Exit::Continue);
            }

            0xF4 => return Ok(Exit::Halted),

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

            0xF8 => self.state.set_flag(flags::CF, false),
            0xF9 => self.state.set_flag(flags::CF, true),
            0xFA => self.state.set_flag(flags::IF, false),
            0xFB => self.state.set_flag(flags::IF, true),
            0xFC => self.state.set_flag(flags::DF, false),
            0xFD => self.state.set_flag(flags::DF, true),

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
                        let w = self.stack_width();
                        let target = self.read_rm(&ctx, &*mem, w)?;
                        let ret = ctx.cur;
                        self.push_stack(mem, ret)?;
                        self.state.rip = target & self.addr_mask();
                        return Ok(Exit::Continue);
                    }
                    4 => {
                        let w = self.stack_width();
                        let target = self.read_rm(&ctx, &*mem, w)?;
                        self.state.rip = target & self.addr_mask();
                        return Ok(Exit::Continue);
                    }
                    5 => {
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

            0xD8..=0xDF => {
                self.exec_x87(&mut ctx, mem, opcode)?;
            }

            0x9B => {}

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

    fn imul_trunc(&mut self, a: u64, b: u64, size: u8) -> u64 {
        let prod = (alu::sext(a, size) as i64 as i128) * (alu::sext(b, size) as i64 as i128);
        let res = (prod as u64) & alu::mask(size);
        let overflow = (alu::sext(res, size) as i64 as i128) != prod;
        self.state.set_flag(flags::CF, overflow);
        self.state.set_flag(flags::OF, overflow);
        res
    }

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
            alu::sub(&mut self.state, acc, v, 0, size);
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step) & self.addr_mask());
            if rep == 0 || self.rep_string_break(rep) {
                break;
            }
        }
        Ok(())
    }

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
            alu::sub(&mut self.state, a, b, 0, size);
            self.state.set_reg(exemu_core::Reg::Rsi, si.wrapping_add(step) & self.addr_mask());
            self.state.set_reg(exemu_core::Reg::Rdi, di.wrapping_add(step) & self.addr_mask());
            if rep == 0 || self.rep_string_break(rep) {
                break;
            }
        }
        Ok(())
    }

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

    fn bit_op(&mut self, ctx: &Ctx, mem: &mut dyn Memory, op2: u8, size: u8, idx: u64) -> Result<()> {
        let modify = |v: u64, bit: u32| -> u64 {
            match op2 {
                0xAB => v | (1u64 << bit),
                0xB3 => v & !(1u64 << bit),
                0xBB => v ^ (1u64 << bit),
                _ => v,
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

    fn rep_string_break(&mut self, rep: u8) -> bool {
        let c = self.state.reg(exemu_core::Reg::Rcx).wrapping_sub(1) & self.addr_mask();
        self.state.set_reg(exemu_core::Reg::Rcx, c);
        let zf = self.state.flag(flags::ZF);
        c == 0 || (rep == 0xF3 && !zf) || (rep == 0xF2 && zf)
    }

    fn cpuid(&mut self) {
        let leaf = self.state.gpr_read(0, 4) as u32;
        let subleaf = self.state.gpr_read(1, 4) as u32;
        let (eax, ebx, ecx, edx) = Self::cpuid_leaf(leaf, subleaf);
        self.state.gpr_write(0, 4, eax as u64);
        self.state.gpr_write(3, 4, ebx as u64);
        self.state.gpr_write(1, 4, ecx as u64);
        self.state.gpr_write(2, 4, edx as u64);
    }

    pub fn cpuid_leaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        const BRAND: &[u8; 48] = b"exemu virtual x86-64 CPU\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let brand_word = |i: usize| -> u32 {
            u32::from_le_bytes([BRAND[i], BRAND[i + 1], BRAND[i + 2], BRAND[i + 3]])
        };
        match leaf {
            0x0 => (0xD, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
            0x1 => {
                let ecx: u32 = (1 << 9)
                    | (1 << 13)
                    | (1 << 19)
                    | (1 << 20)
                    | (1 << 23)
                    | (1 << 26)
                    | (1 << 27)
                    | (1 << 28)
                    | (1 << 29);
                let edx: u32 = 1
                    | (1 << 4)
                    | (1 << 15)
                    | (1 << 23)
                    | (1 << 24)
                    | (1 << 25)
                    | (1 << 26);
                (0x0003_06c3, 0x0001_0800, ecx, edx)
            }
            0x7 => match subleaf {
                0 => (0, (1 << 3) | (1 << 5) | (1 << 8) | (1 << 19), 0, 0),
                _ => (0, 0, 0, 0),
            },
            0xD => match subleaf {
                0 => (XCR0_SUPPORTED as u32, 832, 832, (XCR0_SUPPORTED >> 32) as u32),
                2 => (256, 576, 0, 0),
                _ => (0, 0, 0, 0),
            },
            0x8000_0000 => (0x8000_0004, 0, 0, 0),
            0x8000_0001 => (0u32, 0, 1 << 5, (1 << 11) | (1 << 27) | (1 << 29)),
            0x8000_0002 => (brand_word(0), brand_word(4), brand_word(8), brand_word(12)),
            0x8000_0003 => (brand_word(16), brand_word(20), brand_word(24), brand_word(28)),
            0x8000_0004 => (brand_word(32), brand_word(36), brand_word(40), brand_word(44)),
            _ => (0, 0, 0, 0),
        }
    }

    pub const CPUID_FEATURES: &'static [CpuidFeature] = &[
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 0, name: "x87", probe: &[0x9B, 0xDB, 0xE3] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 4, name: "tsc", probe: &[0x0F, 0x31] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 15, name: "cmov", probe: &[0x0F, 0x44, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 24, name: "fxsr", probe: &[0x0F, 0xAE, 0x00] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 25, name: "sse", probe: &[0x0F, 0x28, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 23, name: "mmx", probe: &[0x0F, 0xEF, 0xC0] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Edx, bit: 26, name: "sse2", probe: &[0x66, 0x0F, 0x28, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 9, name: "ssse3", probe: &[0x66, 0x0F, 0x38, 0x00, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 13, name: "cx16", probe: &[0x48, 0x0F, 0xC7, 0x08] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 19, name: "sse4.1", probe: &[0x66, 0x0F, 0x38, 0x40, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 20, name: "sse4.2", probe: &[0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x00] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 23, name: "popcnt", probe: &[0xF3, 0x0F, 0xB8, 0xC1] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 26, name: "xsave", probe: &[0x0F, 0xAE, 0x20] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 27, name: "osxsave", probe: &[0x0F, 0x01, 0xD0] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 28, name: "avx", probe: &[0xC5, 0xF8, 0x57, 0xC0] },
        CpuidFeature { leaf: 1, sub: 0, reg: CpuidReg::Ecx, bit: 29, name: "f16c", probe: &[0xC4, 0xE2, 0x79, 0x13, 0xC1] },
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 3, name: "bmi1", probe: &[0xC4, 0xE2, 0x60, 0xF2, 0xC1] },
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 5, name: "avx2", probe: &[0xC5, 0xFD, 0xFE, 0xC0] },
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 8, name: "bmi2", probe: &[0xC4, 0xE2, 0x63, 0xF6, 0xC1] },
        CpuidFeature { leaf: 7, sub: 0, reg: CpuidReg::Ebx, bit: 19, name: "adx", probe: &[0x66, 0x0F, 0x38, 0xF6, 0xC1] },
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Ecx, bit: 5, name: "lzcnt", probe: &[0xF3, 0x0F, 0xBD, 0xC1] },
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 11, name: "syscall", probe: &[0x0F, 0x05] },
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 27, name: "rdtscp", probe: &[0x0F, 0x01, 0xF9] },
        CpuidFeature { leaf: 0x8000_0001, sub: 0, reg: CpuidReg::Edx, bit: 29, name: "long-mode", probe: &[0x48, 0x98] },
    ];

    pub const CPUID_FEATURE_WORDS: &'static [(u32, u32, CpuidReg)] = &[
        (1, 0, CpuidReg::Ecx),
        (1, 0, CpuidReg::Edx),
        (7, 0, CpuidReg::Ebx),
        (7, 0, CpuidReg::Ecx),
        (7, 0, CpuidReg::Edx),
        (0x8000_0001, 0, CpuidReg::Ecx),
        (0x8000_0001, 0, CpuidReg::Edx),
    ];

    fn build_fxsave_area(&self, rexw: bool) -> [u8; 512] {
        let x = &self.state.x87;
        let mut buf = [0u8; 512];
        buf[0..2].copy_from_slice(&x.cw.to_le_bytes());
        buf[2..4].copy_from_slice(&x.sw.to_le_bytes());
        buf[4] = abridged_ftw(x.tw);
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
        for i in 0..8u8 {
            let v = x.st[x.phys(i)];
            let off = 32 + i as usize * 16;
            buf[off..off + 10].copy_from_slice(&v.to_le_bytes()[..10]);
        }
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

    fn restore_fxsave_area(&mut self, buf: &[u8; 512], rexw: bool) {
        self.restore_x87_component(buf, rexw);
        self.mxcsr = u32::from_le_bytes(buf[24..28].try_into().unwrap()) & MXCSR_MASK;
        self.restore_xmm_component(buf);
    }

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
            let tag = if ftw_abridged & (1 << phys) == 0 { 0b11 } else { full_tag(v) };
            full_tw |= (tag & 0b11) << (phys as u16 * 2);
        }
        self.state.x87.tw = full_tw;
    }

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

    fn xsave_rfbm(&self) -> u64 {
        let eax = self.state.gpr_read(0, 4);
        let edx = self.state.gpr_read(2, 4);
        ((edx << 32) | eax) & self.xcr0 & XCR0_SUPPORTED
    }

    fn xrstor_apply(&mut self, area: &[u8; 512], rfbm: u64, xstate_bv: u64, rexw: bool) {
        if rfbm & 1 != 0 {
            if xstate_bv & 1 != 0 {
                self.restore_x87_component(area, rexw);
            } else {
                self.state.x87 = exemu_core::X87::new();
            }
        }
        if rfbm & 2 != 0 {
            self.mxcsr = u32::from_le_bytes(area[24..28].try_into().unwrap()) & MXCSR_MASK;
            if xstate_bv & 2 != 0 {
                self.restore_xmm_component(area);
            } else {
                self.state.xmm = [0u128; 16];
            }
        }
    }

    fn exec_0f(
        &mut self,
        ctx: &mut Ctx,
        mem: &mut dyn Memory,
        op2: u8,
        start: u64,
    ) -> Result<Option<Exit>> {
        #[cfg(feature = "profile")]
        {
            let greg = if crate::profile::is_group(op2, true) {
                ctx.peek().map_or(0, |m| (m >> 3) & 7)
            } else {
                0
            };
            crate::profile::record(op2, true, ctx.pfx.w(), ctx.pfx.p66, greg);
        }
        let no_mandatory = ctx.pfx.rep == 0 && !ctx.pfx.p66;
        if no_mandatory && crate::mmx::is_mmx(op2) {
            self.exec_mmx(ctx, mem, op2)?;
            return Ok(None);
        }
        if op2 == 0x77 && no_mandatory {
            self.state.x87.emms();
            return Ok(None);
        }
        if crate::sse::is_sse(op2) {
            self.exec_sse(ctx, mem, op2)?;
            return Ok(None);
        }
        match op2 {
            0x05 => {
                let ret_rip = ctx.cur;
                self.state.set_reg(exemu_core::Reg::Rcx, ret_rip);
                self.state.set_reg(exemu_core::Reg::R11, self.state.rflags);
                self.state.rip = ret_rip;
                let index = self.state.gpr_read(exemu_core::Reg::Rax as u8, 4) as u32;
                return Ok(Some(Exit::Syscall(index)));
            }
            0x0B => return Err(EmuError::Unsupported(format!("ud2 at {start:#x}"))),

            0x1E | 0x1F => {
                self.read_modrm(ctx, mem)?;
            }

            0xA2 => self.cpuid(),
            0x31 => {
                let t = self.read_tsc();
                self.state.gpr_write(0, 4, t & 0xffff_ffff);
                self.state.gpr_write(2, 4, t >> 32);
            }

            0x01 => {
                let sub = ctx.u8(mem)?;
                match sub {
                    0xF9 => {
                        let t = self.read_tsc();
                        self.state.gpr_write(0, 4, t & 0xffff_ffff);
                        self.state.gpr_write(2, 4, t >> 32);
                        self.state.gpr_write(1, 4, 0);
                    }
                    0xD0 => {
                        let ecx = self.state.gpr_read(1, 4);
                        let val = if ecx == 0 { self.xcr0 } else { 0 };
                        self.state.gpr_write(0, 4, val & 0xffff_ffff);
                        self.state.gpr_write(2, 4, val >> 32);
                    }
                    0xD1 => {
                        let ecx = self.state.gpr_read(1, 4);
                        if ecx == 0 {
                            let eax = self.state.gpr_read(0, 4);
                            let edx = self.state.gpr_read(2, 4);
                            let requested = (edx << 32) | eax;
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

            0xAE => {
                self.read_modrm(ctx, mem)?;
                let digit = ctx.reg & 7;
                let is_mem = matches!(ctx.rm, Rm::Mem { .. });
                if !is_mem && digit >= 5 {
                    return Ok(None);
                }
                if is_mem && (digit == 6 || digit == 7) {
                    return Ok(None);
                }
                let addr = ctx.rm_addr();
                let rexw = ctx.pfx.w();
                match digit {
                    0 => {
                        let buf = self.build_fxsave_area(rexw);
                        mem.write(addr, &buf)?;
                    }
                    1 => {
                        let mut buf = [0u8; 512];
                        mem.read(addr, &mut buf)?;
                        self.restore_fxsave_area(&buf, rexw);
                    }
                    2 => self.mxcsr = mem.read_u32(addr)? & MXCSR_MASK,
                    3 => mem.write_u32(addr, self.mxcsr)?,
                    4 => {
                        let rfbm = self.xsave_rfbm();
                        let buf = self.build_fxsave_area(rexw);
                        mem.write(addr, &buf)?;
                        if rfbm & 4 != 0 {
                            self.write_avx_component(mem, addr)?;
                        }
                        let old_bv = mem.read_u64(addr + 512)?;
                        let new_bv = (old_bv & !rfbm) | (rfbm & XCR0_SUPPORTED);
                        mem.write_u64(addr + 512, new_bv)?;
                    }
                    5 => {
                        let rfbm = self.xsave_rfbm();
                        let mut area = [0u8; 512];
                        mem.read(addr, &mut area)?;
                        let xstate_bv = mem.read_u64(addr + 512)?;
                        self.xrstor_apply(&area, rfbm, xstate_bv, rexw);
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

            0x40..=0x4F => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let v = self.read_rm(ctx, &*mem, size)?;
                let keep = self.read_reg_field(ctx, size);
                let val = if self.cond(op2 & 0xF) { v } else { keep };
                self.write_reg_field(ctx, size, val);
            }

            0x80..=0x8F => {
                let rel = ctx.u32(mem)? as i32 as i64;
                let taken = self.cond(op2 & 0xF);
                let target = if taken { ctx.cur.wrapping_add(rel as u64) } else { ctx.cur };
                self.state.rip = target & self.addr_mask();
                return Ok(Some(Exit::Continue));
            }

            0x90..=0x9F => {
                self.read_modrm(ctx, mem)?;
                let v = self.cond(op2 & 0xF) as u64;
                self.write_rm(ctx, mem, 1, v)?;
            }

            0xAF => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let a = self.read_reg_field(ctx, size);
                let b = self.read_rm(ctx, &*mem, size)?;
                let r = self.imul_trunc(a, b, size);
                self.write_reg_field(ctx, size, r);
            }

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

            0xA3 | 0xAB | 0xB3 | 0xBB => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let idx = self.read_reg_field(ctx, size);
                self.bit_op(ctx, mem, op2, size, idx)?;
            }
            0xBA => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let idx = ctx.u8(mem)? as u64;
                let sub = match ctx.reg & 7 {
                    4 => 0xA3,
                    5 => 0xAB,
                    6 => 0xB3,
                    _ => 0xBB,
                };
                self.bit_op(ctx, mem, sub, size, idx)?;
            }

            0xBC | 0xBD => {
                self.read_modrm(ctx, mem)?;
                let size = Self::opsize(ctx);
                let bits = size as u32 * 8;
                let v = self.read_rm(ctx, &*mem, size)? & alu::mask(size);
                if ctx.pfx.rep == 0xF3 {
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
                    self.state.set_flag(flags::ZF, true);
                } else {
                    self.state.set_flag(flags::ZF, false);
                    let idx = if op2 == 0xBC { v.trailing_zeros() } else { 63 - v.leading_zeros() };
                    self.write_reg_field(ctx, size, idx as u64);
                }
            }

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

            0xC8..=0xCF => {
                let r = (op2 & 7) | (ctx.pfx.b() << 3);
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.state.gpr_read(r, size);
                let swapped = if size == 8 { v.swap_bytes() } else { (v as u32).swap_bytes() as u64 };
                self.state.gpr_write(r, size, swapped);
            }

            0xC0 | 0xC1 => {
                self.read_modrm(ctx, mem)?;
                let size = if op2 == 0xC0 { 1 } else { Self::opsize(ctx) };
                let dst = self.read_rm(ctx, &*mem, size)?;
                let src = self.read_reg_field(ctx, size);
                let sum = alu::add(&mut self.state, dst, src, 0, size);
                self.write_reg_field(ctx, size, dst);
                self.write_rm(ctx, mem, size, sum)?;
            }
            0xB0 | 0xB1 => {
                self.read_modrm(ctx, mem)?;
                let size = if op2 == 0xB0 { 1 } else { Self::opsize(ctx) };
                let dst = self.read_rm(ctx, &*mem, size)?;
                let acc = self.state.gpr_read(0, size);
                alu::sub(&mut self.state, acc, dst, 0, size);
                let equal = self.state.flag(flags::ZF);
                let store = if equal { self.read_reg_field(ctx, size) } else { dst };
                self.state.gpr_write(0, size, dst);
                self.write_rm(ctx, mem, size, store)?;
            }

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
                        self.state.gpr_write(0, 8, lo);
                        self.state.gpr_write(2, 8, hi);
                    }
                } else {
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
                        self.state.gpr_write(0, 4, val & 0xffff_ffff);
                        self.state.gpr_write(2, 4, val >> 32);
                    }
                }
            }

            0x38 => {
                let op3 = ctx.u8(mem)?;
                match op3 {
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
                    0xF6 if ctx.pfx.p66 || ctx.pfx.rep == 0xF3 => {
                        self.read_modrm(ctx, mem)?;
                        let size = if ctx.pfx.w() { 8 } else { 4 };
                        let m = alu::mask(size);
                        let dst = self.read_reg_field(ctx, size) & m;
                        let src = self.read_rm(ctx, &*mem, size)? & m;
                        let use_of = ctx.pfx.rep == 0xF3;
                        let carry_in = if use_of {
                            self.state.flag(flags::OF) as u128
                        } else {
                            self.state.flag(flags::CF) as u128
                        };
                        let full = dst as u128 + src as u128 + carry_in;
                        let res = (full as u64) & m;
                        let carry_out = (full >> (size * 8)) & 1 != 0;
                        self.write_reg_field(ctx, size, res);
                        self.state.set_flag(if use_of { flags::OF } else { flags::CF }, carry_out);
                    }
                    _ => self.exec_sse_0f38(ctx, mem, op3)?,
                }
            }

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

fn full_tag(v: u128) -> u16 {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    let integer_bit = signif & 0x8000_0000_0000_0000 != 0;
    if exp == 0 && signif == 0 {
        0b01
    } else if exp == 0x7fff || (exp == 0 && signif != 0) || (exp != 0 && !integer_bit) {
        0b10
    } else {
        0b00
    }
}
