use super::*;
use crate::alu;
use exemu_core::cpu::flags;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sse {
    Ps,
    Pd,
    Ss,
    Sd,
}

pub(crate) const LOW64: u128 = 0xFFFF_FFFF_FFFF_FFFF;
pub(crate) const LOW32: u128 = 0xFFFF_FFFF;

pub(crate) fn is_sse(op2: u8) -> bool {
    matches!(op2,
        0x10..=0x17 | 0x28..=0x2F | 0x50..=0x5F |
        0x60..=0x76 | 0x7E | 0x7F |
        0xC2 | 0xC4 | 0xC5 | 0xC6 | 0xD0..=0xFE)
}

impl Interpreter {
    fn sse_kind(ctx: &Ctx) -> Sse {
        if ctx.pfx.rep == 0xF3 {
            Sse::Ss
        } else if ctx.pfx.rep == 0xF2 {
            Sse::Sd
        } else if ctx.pfx.p66 {
            Sse::Pd
        } else {
            Sse::Ps
        }
    }

    fn xmm(&self, i: u8) -> u128 {
        self.state.xmm[i as usize & 0xf]
    }
    fn set_xmm(&mut self, i: u8, v: u128) {
        self.state.xmm[i as usize & 0xf] = v;
    }

    fn sse_rm(&self, ctx: &Ctx, mem: &dyn Memory, n: usize) -> Result<u128> {
        match ctx.rm {
            Rm::Reg(i) => Ok(self.xmm(i)),
            Rm::Mem { .. } => {
                let mut buf = [0u8; 16];
                mem.read(ctx.rm_addr(), &mut buf[..n])?;
                Ok(u128::from_le_bytes(buf))
            }
        }
    }

    fn sse_store_full(&mut self, ctx: &Ctx, mem: &mut dyn Memory, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.set_xmm(i, val);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()),
        }
    }

    fn sse_store_low(&mut self, ctx: &Ctx, mem: &mut dyn Memory, n: usize, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                let mask = low_mask(n);
                let cur = self.xmm(i);
                self.set_xmm(i, (cur & !mask) | (val & mask));
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()[..n]),
        }
    }

    pub(crate) fn exec_sse(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op2: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        let kind = Self::sse_kind(ctx);
        let reg = ctx.reg;

        match op2 {
            0x10 => match kind {
                Sse::Ps | Sse::Pd => {
                    let v = self.sse_rm(ctx, mem, 16)?;
                    self.set_xmm(reg, v);
                }
                Sse::Ss => self.mov_scalar_load(ctx, mem, reg, 4)?,
                Sse::Sd => self.mov_scalar_load(ctx, mem, reg, 8)?,
            },
            0x11 => match kind {
                Sse::Ps | Sse::Pd => {
                    let v = self.xmm(reg);
                    self.sse_store_full(ctx, mem, v)?;
                }
                Sse::Ss => {
                    let v = self.xmm(reg);
                    self.sse_store_low(ctx, mem, 4, v)?;
                }
                Sse::Sd => {
                    let v = self.xmm(reg);
                    self.sse_store_low(ctx, mem, 8, v)?;
                }
            },

            0x12 => {
                let v = match ctx.rm {
                    Rm::Reg(i) => (self.xmm(reg) & !LOW64) | (self.xmm(i) >> 64),
                    Rm::Mem { .. } => (self.xmm(reg) & !LOW64) | (self.sse_rm(ctx, mem, 8)? & LOW64),
                };
                self.set_xmm(reg, v);
            }
            0x13 => {
                let v = self.xmm(reg) & LOW64;
                self.sse_store_low(ctx, mem, 8, v)?;
            }
            0x16 => {
                let v = match ctx.rm {
                    Rm::Reg(i) => (self.xmm(reg) & LOW64) | (self.xmm(i) << 64),
                    Rm::Mem { .. } => (self.xmm(reg) & LOW64) | (self.sse_rm(ctx, mem, 8)? << 64),
                };
                self.set_xmm(reg, v);
            }
            0x17 => {
                let v = self.xmm(reg) >> 64;
                self.sse_store_low(ctx, mem, 8, v)?;
            }

            0x28 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }
            0x29 => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            0x2A => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let src = alu::sext(self.read_rm(ctx, &*mem, size)?, size) as i64;
                match kind {
                    Sse::Sd => {
                        let bits = (src as f64).to_bits() as u128;
                        self.set_xmm(reg, (self.xmm(reg) & !LOW64) | bits);
                    }
                    _ => {
                        let bits = (src as f32).to_bits() as u128;
                        self.set_xmm(reg, (self.xmm(reg) & !LOW32) | bits);
                    }
                }
            }
            0x2C | 0x2D => {
                let truncate = op2 == 0x2C;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let val = self.sse_rm(ctx, mem, 8)?;
                let f = if kind == Sse::Sd {
                    f64::from_bits((val & LOW64) as u64)
                } else {
                    f32::from_bits((val & LOW32) as u32) as f64
                };
                let out = cvt_f_to_int(f, truncate, size);
                self.write_reg_field(ctx, size, out);
            }
            0x2E | 0x2F => {
                let (a, b) = if kind == Sse::Pd {
                    (
                        f64::from_bits((self.xmm(reg) & LOW64) as u64),
                        f64::from_bits((self.sse_rm(ctx, mem, 8)? & LOW64) as u64),
                    )
                } else {
                    (
                        f32::from_bits((self.xmm(reg) & LOW32) as u32) as f64,
                        f32::from_bits((self.sse_rm(ctx, mem, 4)? & LOW32) as u32) as f64,
                    )
                };
                self.set_compare_flags(a, b);
            }

            0x50 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                let mask = match kind {
                    Sse::Ps => {
                        ((v >> 31) & 1) | ((v >> 62) & 2) | ((v >> 93) & 4) | ((v >> 124) & 8)
                    }
                    Sse::Pd => ((v >> 63) & 1) | ((v >> 126) & 2),
                    _ => return unsupported(op2, ctx, "movmsk ss/sd"),
                } as u64;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, mask);
            }

            0x51 => self.sse_unary(ctx, mem, kind, f64::sqrt)?,

            0x54 => self.sse_logic(ctx, mem, |a, b| a & b)?,
            0x55 => self.sse_logic(ctx, mem, |a, b| !a & b)?,
            0x56 => self.sse_logic(ctx, mem, |a, b| a | b)?,
            0x57 => self.sse_logic(ctx, mem, |a, b| a ^ b)?,

            0x58 => self.sse_arith(ctx, mem, kind, |a, b| a + b)?,
            0x59 => self.sse_arith(ctx, mem, kind, |a, b| a * b)?,
            0x5C => self.sse_arith(ctx, mem, kind, |a, b| a - b)?,
            0x5D => self.sse_arith(ctx, mem, kind, |a, b| if a < b { a } else { b })?,
            0x5E => self.sse_arith(ctx, mem, kind, |a, b| a / b)?,
            0x5F => self.sse_arith(ctx, mem, kind, |a, b| if a > b { a } else { b })?,

            0x5A => match kind {
                Sse::Sd => {
                    let f = f64::from_bits((self.sse_rm(ctx, mem, 8)? & LOW64) as u64) as f32;
                    let bits = f.to_bits() as u128;
                    self.set_xmm(reg, (self.xmm(reg) & !LOW32) | bits);
                }
                Sse::Ss => {
                    let f = f32::from_bits((self.sse_rm(ctx, mem, 4)? & LOW32) as u32) as f64;
                    let bits = f.to_bits() as u128;
                    self.set_xmm(reg, (self.xmm(reg) & !LOW64) | bits);
                }
                _ => return unsupported(op2, ctx, "cvtps2pd/cvtpd2ps"),
            },

            0x5B => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let out = match kind {
                    Sse::Ps => cvtdq2ps(src),
                    Sse::Pd => cvtps2dq(src, false),
                    Sse::Ss => cvtps2dq(src, true),
                    Sse::Sd => return unsupported(op2, ctx, "cvt 5b/f2"),
                };
                self.set_xmm(reg, out);
            }

            0xF0 => {
                if kind != Sse::Sd {
                    return unsupported(op2, ctx, "0f f0");
                }
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }

            0x6E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let src = self.read_rm(ctx, &*mem, size)? as u128;
                self.set_xmm(reg, src);
            }
            0x6F => {
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }
            0x7E => match kind {
                Sse::Ss => {
                    let v = self.sse_rm(ctx, mem, 8)? & LOW64;
                    self.set_xmm(reg, v);
                }
                _ => {
                    let size = if ctx.pfx.w() { 8 } else { 4 };
                    let v = self.xmm(reg) as u64;
                    self.write_rm(ctx, mem, size, v)?;
                }
            },
            0x7F => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            0xD6 => {
                let v = self.xmm(reg) & LOW64;
                match ctx.rm {
                    Rm::Reg(i) => self.set_xmm(i, v),
                    Rm::Mem { .. } => mem.write(ctx.rm_addr(), &v.to_le_bytes()[..8])?,
                }
            }

            0xDB => self.sse_logic(ctx, mem, |a, b| a & b)?,
            0xDF => self.sse_logic(ctx, mem, |a, b| !a & b)?,
            0xEB => self.sse_logic(ctx, mem, |a, b| a | b)?,
            0xEF => self.sse_logic(ctx, mem, |a, b| a ^ b)?,

            0x2B | 0xE7 => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            0x60 | 0x61 | 0x62 | 0x6C => {
                let esz = [1usize, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8][(op2 - 0x60) as usize];
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, punpck(a, b, esz, false));
            }
            0x68 | 0x69 | 0x6A | 0x6D => {
                let esz = [1usize, 2, 4, 0, 0, 8][(op2 - 0x68) as usize];
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, punpck(a, b, esz, true));
            }

            0x74..=0x76 => {
                let esz = 1usize << (op2 - 0x74);
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pcmp(a, b, esz, false));
            }
            0x64..=0x66 => {
                let esz = 1usize << (op2 - 0x64);
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pcmp(a, b, esz, true));
            }

            0xFC..=0xFE => {
                let esz = 1usize << (op2 - 0xFC);
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, add_sub(a, b, esz, true));
            }
            0xD4 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, add_sub(a, b, 8, true));
            }
            0xF8..=0xFB => {
                let esz = 1usize << (op2 - 0xF8);
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, add_sub(a, b, esz, false));
            }

            0xD8 | 0xD9 | 0xDC | 0xDD | 0xE8 | 0xE9 | 0xEC | 0xED => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let esz = if op2 & 1 == 0 { 1 } else { 2 };
                let add = matches!(op2, 0xDC | 0xDD | 0xEC | 0xED);
                let signed = matches!(op2, 0xE8 | 0xE9 | 0xEC | 0xED);
                self.set_xmm(reg, add_sub_sat(a, b, esz, add, signed));
            }

            0xD5 | 0xE4 | 0xE5 | 0xF4 | 0xF5 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let out = match op2 {
                    0xD5 => pmullw(a, b),
                    0xE5 => pmulh(a, b, true),
                    0xE4 => pmulh(a, b, false),
                    0xF4 => pmuludq(a, b),
                    _ => pmaddwd(a, b),
                };
                self.set_xmm(reg, out);
            }

            0xE0 | 0xE3 | 0xF6 | 0x63 | 0x6B | 0x67 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let out = match op2 {
                    0xE0 => pavg(a, b, 1),
                    0xE3 => pavg(a, b, 2),
                    0xF6 => psadbw(a, b),
                    0x63 => pack(a, b, 2, true),
                    0x6B => pack(a, b, 4, true),
                    _ => pack(a, b, 2, false),
                };
                self.set_xmm(reg, out);
            }

            0xC5 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let imm = ctx.u8(mem)? as u32;
                let w = ((src >> ((imm & 7) * 16)) & 0xFFFF) as u64;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, w);
            }

            0xDA => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, byte_minmax(a, b, false));
            }
            0xDE => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, byte_minmax(a, b, true));
            }

            0xD7 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                let mask = pmovmskb(v) as u64;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, mask);
            }

            0x70 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let imm = ctx.u8(mem)?;
                let out = match kind {
                    Sse::Pd => pshufd(src, imm),
                    Sse::Sd => pshuflw(src, imm),
                    Sse::Ss => pshufhw(src, imm),
                    Sse::Ps => return unsupported(op2, ctx, "pshufw(mm)"),
                };
                self.set_xmm(reg, out);
            }

            0xC2 => {
                let dst = self.xmm(reg);
                let out = match kind {
                    Sse::Ps => {
                        let src = self.sse_rm(ctx, mem, 16)?;
                        let imm = ctx.u8(mem)?;
                        crate::vex::pcmp_float(dst, src, false, imm)
                    }
                    Sse::Pd => {
                        let src = self.sse_rm(ctx, mem, 16)?;
                        let imm = ctx.u8(mem)?;
                        crate::vex::pcmp_float(dst, src, true, imm)
                    }
                    Sse::Ss => {
                        let src = self.sse_rm(ctx, mem, 4)?;
                        let imm = ctx.u8(mem)?;
                        let r = crate::vex::cmp_pred_full(
                            f32::from_bits(dst as u32) as f64,
                            f32::from_bits(src as u32) as f64,
                            imm,
                        );
                        (dst & !LOW32) | (if r { LOW32 } else { 0 })
                    }
                    Sse::Sd => {
                        let src = self.sse_rm(ctx, mem, 8)?;
                        let imm = ctx.u8(mem)?;
                        let r = crate::vex::cmp_pred_full(
                            f64::from_bits(dst as u64),
                            f64::from_bits(src as u64),
                            imm,
                        );
                        (dst & !LOW64) | (if r { LOW64 } else { 0 })
                    }
                };
                self.set_xmm(reg, out);
            }

            0xC4 => {
                let word = match ctx.rm {
                    Rm::Reg(i) => self.state.gpr[i as usize & 0xf] as u16,
                    Rm::Mem { .. } => {
                        let mut b = [0u8; 2];
                        mem.read(ctx.rm_addr(), &mut b)?;
                        u16::from_le_bytes(b)
                    }
                };
                let imm = ctx.u8(mem)?;
                let lane = (imm & 7) as u128;
                let dst = self.xmm(reg);
                let mask = 0xFFFFu128 << (lane * 16);
                let out = (dst & !mask) | ((word as u128) << (lane * 16));
                self.set_xmm(reg, out);
            }

            0xC6 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let dst = self.xmm(reg);
                let imm = ctx.u8(mem)?;
                let out = if kind == Sse::Pd { shufpd(dst, src, imm) } else { shufps(dst, src, imm) };
                self.set_xmm(reg, out);
            }

            0x71..=0x73 => {
                let digit = ctx.reg & 7;
                let src = self.sse_rm(ctx, mem, 16)?;
                let imm = ctx.u8(mem)? as u64;
                let esz = match op2 {
                    0x71 => 2,
                    0x72 => 4,
                    _ => 8,
                };
                let out = match (op2, digit) {
                    (_, 2) => shift_r(src, esz, imm, false),
                    (0x71 | 0x72, 4) => shift_r(src, esz, imm, true),
                    (_, 6) => shift_l(src, esz, imm),
                    (0x73, 3) => {
                        if imm >= 16 {
                            0
                        } else {
                            src >> (imm * 8)
                        }
                    }
                    (0x73, 7) => {
                        if imm >= 16 {
                            0
                        } else {
                            src << (imm * 8)
                        }
                    }
                    _ => return unsupported(op2, ctx, "psh-group"),
                };
                self.sse_store_full(ctx, mem, out)?;
            }

            0xD1 | 0xD2 | 0xD3 | 0xE1 | 0xE2 | 0xF1 | 0xF2 | 0xF3 => {
                let count = (self.sse_rm(ctx, mem, 16)? & LOW64) as u64;
                let dst = self.xmm(reg);
                let out = match op2 {
                    0xD1 => shift_r(dst, 2, count, false),
                    0xD2 => shift_r(dst, 4, count, false),
                    0xD3 => shift_r(dst, 8, count, false),
                    0xE1 => shift_r(dst, 2, count, true),
                    0xE2 => shift_r(dst, 4, count, true),
                    0xF1 => shift_l(dst, 2, count),
                    0xF2 => shift_l(dst, 4, count),
                    _ => shift_l(dst, 8, count),
                };
                self.set_xmm(reg, out);
            }

            other => return unsupported(other, ctx, "sse"),
        }
        Ok(())
    }

    pub(crate) fn exec_sse_0f38(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op3: u8) -> Result<()> {
        if op3 == 0xF0 || op3 == 0xF1 {
            return self.crc32(ctx, mem, op3);
        }
        self.read_modrm(ctx, mem)?;
        let reg = ctx.reg;
        match op3 {
            0x00 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pshufb(a, b));
            }
            0x01 | 0x02 | 0x03 | 0x05 | 0x06 | 0x07 => {
                let a = self.xmm(reg);
                let b = self.sse_rm(ctx, mem, 16)?;
                let esz = if op3 == 0x02 || op3 == 0x06 { 4 } else { 2 };
                let sub = matches!(op3, 0x05..=0x07);
                let sat = op3 == 0x03 || op3 == 0x07;
                let aliased = matches!(ctx.rm, Rm::Reg(i) if i == reg);
                self.set_xmm(reg, phaddsub(a, b, esz, sub, sat, aliased));
            }
            0x04 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pmaddubsw(a, b));
            }
            0x08..=0x0A => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let esz = 1usize << (op3 - 0x08);
                self.set_xmm(reg, psign(a, b, esz));
            }
            0x0B => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pmulhrsw(a, b));
            }
            0x1C..=0x1E => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let esz = 1usize << (op3 - 0x1C);
                self.set_xmm(reg, pabs(src, esz));
            }
            0x10 | 0x14 | 0x15 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let mask = self.xmm(0);
                let esz = match op3 {
                    0x10 => 1,
                    0x14 => 4,
                    _ => 8,
                };
                self.set_xmm(reg, blend_var(a, b, mask, esz));
            }
            0x17 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.state.set_flag(flags::ZF, (b & a) == 0);
                self.state.set_flag(flags::CF, (b & !a) == 0);
                for f in [flags::OF, flags::SF, flags::AF, flags::PF] {
                    self.state.set_flag(f, false);
                }
            }
            0x20..=0x25 | 0x30..=0x35 => {
                let sign = op3 < 0x30;
                let sel = op3 & 0x0F;
                let (src_sz, dst_sz) = [(1usize, 2usize), (1, 4), (1, 8), (2, 4), (2, 8), (4, 8)][sel as usize];
                let count = 16 / dst_sz;
                let src = self.sse_rm(ctx, mem, count * src_sz)?;
                self.set_xmm(reg, pmovx(src, src_sz, dst_sz, sign));
            }
            0x28 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pmuldq(a, b));
            }
            0x29 | 0x37 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pcmp(a, b, 8, op3 == 0x37));
            }
            0x2A => {
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }
            0x2B => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, packusdw(a, b));
            }
            0x38..=0x3F => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                let max = op3 >= 0x3C;
                let (esz, signed) = match op3 & 0x03 {
                    0 => (1usize, true),
                    1 => (4usize, true),
                    2 => (2usize, false),
                    _ => (4usize, false),
                };
                self.set_xmm(reg, int_minmax(a, b, esz, signed, max));
            }
            0x40 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, pmulld(a, b));
            }
            0x41 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, phminposuw(src));
            }
            other => return unsupported3(0x38, other, ctx, "sse38"),
        }
        Ok(())
    }

    pub(crate) fn exec_sse_0f3a(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op3: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        let imm = ctx.u8(mem)?;
        let reg = ctx.reg;
        match op3 {
            0x08..=0x0B => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let mode = self.round_mode(imm);
                let dst = self.xmm(reg);
                let out = match op3 {
                    0x08 => {
                        let mut o = 0u128;
                        for l in 0..4 {
                            o |= (round_f32(f32_lane(src, l), mode).to_bits() as u128) << (l * 32);
                        }
                        o
                    }
                    0x09 => {
                        let mut o = 0u128;
                        for l in 0..2 {
                            o |= (round_f64(f64_lane(src, l), mode).to_bits() as u128) << (l * 64);
                        }
                        o
                    }
                    0x0A => (dst & !LOW32) | (round_f32(f32_lane(src, 0), mode).to_bits() as u128),
                    _ => (dst & !LOW64) | (round_f64(f64_lane(src, 0), mode).to_bits() as u128),
                };
                self.set_xmm(reg, out);
            }
            0x0C..=0x0E => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let dst = self.xmm(reg);
                let esz = match op3 {
                    0x0C => 4,
                    0x0D => 8,
                    _ => 2,
                };
                self.set_xmm(reg, blend_imm(dst, src, imm, esz));
            }
            0x0F => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, palignr(a, b, imm));
            }
            0x14..=0x16 => {
                let src = self.xmm(reg);
                let (esz, cnt) = match op3 {
                    0x14 => (1usize, 16u32),
                    0x15 => (2usize, 8),
                    _ => {
                        if ctx.pfx.w() {
                            (8usize, 2)
                        } else {
                            (4usize, 4)
                        }
                    }
                };
                let idx = (imm as u32) % cnt;
                let v = ((src >> (idx * esz as u32 * 8)) & emask(esz)) as u64;
                let store_sz = match op3 {
                    0x16 => esz as u8,
                    _ => {
                        if matches!(ctx.rm, Rm::Reg(_)) {
                            if ctx.pfx.w() {
                                8
                            } else {
                                4
                            }
                        } else {
                            esz as u8
                        }
                    }
                };
                self.write_rm(ctx, mem, store_sz, v)?;
            }
            0x17 => {
                let src = self.xmm(reg);
                let idx = (imm as u32) & 3;
                let v = ((src >> (idx * 32)) & LOW32) as u64;
                let store_sz = if matches!(ctx.rm, Rm::Reg(_)) && ctx.pfx.w() { 8 } else { 4 };
                self.write_rm(ctx, mem, store_sz, v)?;
            }
            0x20 | 0x22 => {
                let (esz, cnt) = if op3 == 0x20 {
                    (1usize, 16u32)
                } else if ctx.pfx.w() {
                    (8usize, 2)
                } else {
                    (4usize, 4)
                };
                let gp = match ctx.rm {
                    Rm::Reg(i) => self.state.gpr_read(i, if esz == 8 { 8 } else { 4 }),
                    Rm::Mem { .. } => mem.read_uint(ctx.rm_addr(), esz as u8)?,
                } & (emask(esz) as u64);
                let idx = (imm as u32) % cnt;
                let mask = emask(esz) << (idx * esz as u32 * 8);
                let dst = self.xmm(reg);
                self.set_xmm(reg, (dst & !mask) | (((gp as u128) << (idx * esz as u32 * 8)) & mask));
            }
            0x21 => {
                let src_dword = match ctx.rm {
                    Rm::Reg(i) => (self.xmm(i) >> (((imm >> 6) & 3) as u32 * 32)) as u32,
                    Rm::Mem { .. } => mem.read_u32(ctx.rm_addr())?,
                };
                let dst_sel = ((imm >> 4) & 3) as u32;
                let mut dst = self.xmm(reg);
                let lane_mask = LOW32 << (dst_sel * 32);
                dst = (dst & !lane_mask) | (((src_dword as u128) << (dst_sel * 32)) & lane_mask);
                for l in 0..4 {
                    if (imm >> l) & 1 == 1 {
                        dst &= !(LOW32 << (l * 32));
                    }
                }
                self.set_xmm(reg, dst);
            }
            0x40 | 0x41 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let dst = self.xmm(reg);
                let out = if op3 == 0x40 { dpps(dst, src, imm) } else { dppd(dst, src, imm) };
                self.set_xmm(reg, out);
            }
            0x42 => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, mpsadbw(a, b, imm));
            }
            0x60..=0x63 => {
                let a = self.xmm(reg);
                let b = self.sse_rm(ctx, mem, 16)?;
                let explicit = op3 <= 0x61;
                let index = op3 & 1 == 1;
                self.pcmpstr(a, b, imm, explicit, index);
            }
            other => return unsupported3(0x3A, other, ctx, "sse3a"),
        }
        Ok(())
    }

    fn crc32(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op3: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        let src_sz: u8 = if op3 == 0xF0 { 1 } else if ctx.pfx.p66 { 2 } else if ctx.pfx.w() { 8 } else { 4 };
        let dst_sz: u8 = if ctx.pfx.w() { 8 } else { 4 };
        let src = self.read_rm(ctx, &*mem, src_sz)?;
        let mut crc = self.read_reg_field(ctx, dst_sz) as u32;
        for i in 0..src_sz {
            let byte = (src >> (i * 8)) as u8;
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
            }
        }
        self.write_reg_field(ctx, dst_sz, crc as u64);
        Ok(())
    }

    pub(crate) fn round_mode(&self, imm: u8) -> u8 {
        if imm & 0x04 != 0 {
            ((self.mxcsr >> 13) & 3) as u8
        } else {
            imm & 3
        }
    }

    fn pcmpstr(&mut self, a: u128, b: u128, imm: u8, explicit: bool, index: bool) {
        let elem_bytes = if imm & 1 == 0 { 1usize } else { 2 };
        let signed = imm & 2 != 0;
        let agg = (imm >> 2) & 3;
        let n = 16 / elem_bytes;

        let (len_a, len_b) = if explicit {
            let eax = self.state.gpr_read(0, 4) as i32;
            let edx = self.state.gpr_read(2, 4) as i32;
            let clamp = |v: i32| -> usize { (v.unsigned_abs() as usize).min(n) };
            (clamp(eax), clamp(edx))
        } else {
            (implicit_len(a, elem_bytes, n), implicit_len(b, elem_bytes, n))
        };

        let get = |v: u128, i: usize| -> i64 {
            let bits = elem_bytes * 8;
            let raw = ((v >> (i * bits)) & emask(elem_bytes)) as u64;
            if signed {
                let shift = 64 - bits;
                ((raw << shift) as i64) >> shift
            } else {
                raw as i64
            }
        };

        let raw = |i: usize, j: usize| -> bool {
            match agg {
                1 => {
                    if j & 1 == 0 {
                        get(a, j) <= get(b, i)
                    } else {
                        get(b, i) <= get(a, j)
                    }
                }
                _ => get(b, i) == get(a, j),
            }
        };
        let overridden = |i: usize, j: usize| -> bool {
            let aj = j < len_a;
            let bi = i < len_b;
            match agg {
                0 | 1 => {
                    if aj && bi {
                        raw(i, j)
                    } else {
                        false
                    }
                }
                2 => match (aj, bi) {
                    (true, true) => raw(i, j),
                    (false, false) => true,
                    _ => false,
                },
                _ => {
                    if !aj {
                        true
                    } else if !bi {
                        false
                    } else {
                        raw(i, j)
                    }
                }
            }
        };
        let mut int_res = [false; 16];
        for (i, slot) in int_res.iter_mut().enumerate().take(n) {
            *slot = match agg {
                0 => (0..n).any(|j| overridden(i, j)),
                1 => {
                    let mut hit = false;
                    let mut k = 0;
                    while k + 1 < n {
                        if overridden(i, k) && overridden(i, k + 1) {
                            hit = true;
                        }
                        k += 2;
                    }
                    hit
                }
                2 => overridden(i, i),
                _ => (0..n).all(|j| overridden(i + j, j)),
            };
        }

        let neg = (imm >> 4) & 3;
        let mut res = [false; 16];
        for i in 0..n {
            let mut r = int_res[i];
            match neg {
                1 => r = !r,
                3 => r = if i < len_b { !r } else { r },
                _ => {}
            }
            res[i] = r;
        }

        let mut mask = 0u32;
        for (i, &r) in res.iter().enumerate().take(n) {
            if r {
                mask |= 1 << i;
            }
        }

        self.state.set_flag(flags::CF, mask != 0);
        self.state.set_flag(flags::ZF, len_b < n);
        self.state.set_flag(flags::SF, len_a < n);
        self.state.set_flag(flags::OF, res[0]);
        self.state.set_flag(flags::AF, false);
        self.state.set_flag(flags::PF, false);

        if index {
            let ecx = if mask == 0 {
                n as u32
            } else if imm & 0x40 != 0 {
                31 - mask.leading_zeros()
            } else {
                mask.trailing_zeros()
            };
            self.state.gpr_write(1, 8, ecx as u64);
        } else {
            let out = if imm & 0x40 != 0 {
                let bits = elem_bytes * 8;
                let mut o = 0u128;
                for (i, &r) in res.iter().enumerate().take(n) {
                    if r {
                        o |= emask(elem_bytes) << (i * bits);
                    }
                }
                o
            } else {
                mask as u128
            };
            self.set_xmm(0, out);
        }
    }

    fn mov_scalar_load(&mut self, ctx: &Ctx, mem: &mut dyn Memory, reg: u8, n: usize) -> Result<()> {
        let mask = low_mask(n);
        match ctx.rm {
            Rm::Reg(i) => {
                let v = self.xmm(i) & mask;
                self.set_xmm(reg, (self.xmm(reg) & !mask) | v);
            }
            Rm::Mem { .. } => {
                let v = self.sse_rm(ctx, mem, n)? & mask;
                self.set_xmm(reg, v);
            }
        }
        Ok(())
    }

    fn sse_logic(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        f: impl Fn(u128, u128) -> u128,
    ) -> Result<()> {
        let a = self.xmm(ctx.reg);
        let b = self.sse_rm(ctx, mem, 16)?;
        self.set_xmm(ctx.reg, f(a, b));
        Ok(())
    }

    fn sse_arith(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        kind: Sse,
        f: impl Fn(f64, f64) -> f64,
    ) -> Result<()> {
        let reg = ctx.reg;
        let src = self.sse_rm(ctx, mem, 16)?;
        let dst = self.xmm(reg);
        let out = match kind {
            Sse::Sd => {
                let r = f(f64_lane(dst, 0), f64_lane(src, 0));
                (dst & !LOW64) | (r.to_bits() as u128)
            }
            Sse::Ss => {
                let r = f(f32_lane(dst, 0) as f64, f32_lane(src, 0) as f64) as f32;
                (dst & !LOW32) | (r.to_bits() as u128)
            }
            Sse::Pd => {
                let mut out = 0u128;
                for lane in 0..2 {
                    let r = f(f64_lane(dst, lane), f64_lane(src, lane));
                    out |= (r.to_bits() as u128) << (lane * 64);
                }
                out
            }
            Sse::Ps => {
                let mut out = 0u128;
                for lane in 0..4 {
                    let r = f(f32_lane(dst, lane) as f64, f32_lane(src, lane) as f64) as f32;
                    out |= (r.to_bits() as u128) << (lane * 32);
                }
                out
            }
        };
        self.set_xmm(reg, out);
        Ok(())
    }

    fn sse_unary(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        kind: Sse,
        f: impl Fn(f64) -> f64,
    ) -> Result<()> {
        let reg = ctx.reg;
        let src = self.sse_rm(ctx, mem, 16)?;
        let dst = self.xmm(reg);
        let out = match kind {
            Sse::Sd => (dst & !LOW64) | (f(f64_lane(src, 0)).to_bits() as u128),
            Sse::Ss => (dst & !LOW32) | ((f(f32_lane(src, 0) as f64) as f32).to_bits() as u128),
            Sse::Pd => {
                let mut o = 0u128;
                for lane in 0..2 {
                    o |= (f(f64_lane(src, lane)).to_bits() as u128) << (lane * 64);
                }
                o
            }
            Sse::Ps => {
                let mut o = 0u128;
                for lane in 0..4 {
                    o |= ((f(f32_lane(src, lane) as f64) as f32).to_bits() as u128) << (lane * 32);
                }
                o
            }
        };
        self.set_xmm(reg, out);
        Ok(())
    }

    pub(crate) fn set_compare_flags(&mut self, a: f64, b: f64) {
        let s = &mut self.state;
        s.set_flag(flags::OF, false);
        s.set_flag(flags::SF, false);
        s.set_flag(flags::AF, false);
        if a.is_nan() || b.is_nan() {
            s.set_flag(flags::ZF, true);
            s.set_flag(flags::PF, true);
            s.set_flag(flags::CF, true);
        } else {
            s.set_flag(flags::ZF, a == b);
            s.set_flag(flags::PF, false);
            s.set_flag(flags::CF, a < b);
        }
    }
}

pub(crate) fn low_mask(n: usize) -> u128 {
    if n >= 16 {
        u128::MAX
    } else {
        (1u128 << (n * 8)) - 1
    }
}

pub(crate) fn cvt_f_to_int(f: f64, truncate: bool, size: u8) -> u64 {
    let r = if truncate { f.trunc() } else { f.round_ties_even() };
    if size == 8 {
        if (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&r) {
            r as i64 as u64
        } else {
            0x8000_0000_0000_0000
        }
    } else if (-2_147_483_648.0..2_147_483_648.0).contains(&r) {
        (r as i32 as u32) as u64
    } else {
        0x8000_0000
    }
}

pub(crate) fn cvtdq2ps(v: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let x = ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 as i32;
        out |= ((x as f32).to_bits() as u128) << (i * 32);
    }
    out
}

pub(crate) fn cvtps2dq(v: u128, truncate: bool) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let r = cvt_f_to_int(f32_lane(v, i) as f64, truncate, 4) as u32;
        out |= (r as u128) << (i * 32);
    }
    out
}

pub(crate) fn f64_lane(v: u128, lane: u32) -> f64 {
    f64::from_bits((v >> (lane * 64)) as u64)
}

pub(crate) fn f32_lane(v: u128, lane: u32) -> f32 {
    f32::from_bits((v >> (lane * 32)) as u32)
}

pub(crate) fn emask(esz: usize) -> u128 {
    let bits = esz * 8;
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

pub(crate) fn punpck(a: u128, b: u128, esz: usize, high: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let half = (16 / esz) / 2;
    let base = if high { half } else { 0 };
    let mut out = 0u128;
    for i in 0..half {
        let d = (a >> ((base + i) * bits)) & mask;
        let s = (b >> ((base + i) * bits)) & mask;
        out |= d << ((2 * i) * bits);
        out |= s << ((2 * i + 1) * bits);
    }
    out
}

pub(crate) fn pcmp(a: u128, b: u128, esz: usize, gt: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let sign = 1u128 << (bits - 1);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = (a >> (i * bits)) & mask;
        let y = (b >> (i * bits)) & mask;
        let hit = if gt {
            (x ^ sign) > (y ^ sign)
        } else {
            x == y
        };
        if hit {
            out |= mask << (i * bits);
        }
    }
    out
}

pub(crate) fn add_sub(a: u128, b: u128, esz: usize, add: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = ((a >> (i * bits)) & mask) as u64;
        let y = ((b >> (i * bits)) & mask) as u64;
        let r = if add { x.wrapping_add(y) } else { x.wrapping_sub(y) } as u128;
        out |= (r & mask) << (i * bits);
    }
    out
}

pub(crate) fn add_sub_sat(a: u128, b: u128, esz: usize, add: bool, signed: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = ((a >> (i * bits)) & mask) as u64;
        let y = ((b >> (i * bits)) & mask) as u64;
        let r = if signed {
            let shift = 64 - bits;
            let sx = ((x << shift) as i64) >> shift;
            let sy = ((y << shift) as i64) >> shift;
            let v = if add { sx + sy } else { sx - sy };
            let hi = (1i64 << (bits - 1)) - 1;
            let lo = -(1i64 << (bits - 1));
            (v.clamp(lo, hi) as u64) & mask as u64
        } else if add {
            (x + y).min(mask as u64)
        } else {
            x.saturating_sub(y)
        };
        out |= (r as u128 & mask) << (i * bits);
    }
    out
}

pub(crate) fn pmullw(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..8 {
        let x = ((a >> (i * 16)) & 0xFFFF) as u32;
        let y = ((b >> (i * 16)) & 0xFFFF) as u32;
        out |= (((x * y) & 0xFFFF) as u128) << (i * 16);
    }
    out
}

pub(crate) fn pmulh(a: u128, b: u128, signed: bool) -> u128 {
    let mut out = 0u128;
    for i in 0..8 {
        let x = ((a >> (i * 16)) & 0xFFFF) as u16;
        let y = ((b >> (i * 16)) & 0xFFFF) as u16;
        let p: i64 = if signed {
            (x as i16 as i64) * (y as i16 as i64)
        } else {
            (x as i64) * (y as i64)
        };
        out |= (((p >> 16) as u128) & 0xFFFF) << (i * 16);
    }
    out
}

pub(crate) fn pmuludq(a: u128, b: u128) -> u128 {
    let a0 = (a & 0xFFFF_FFFF) as u64;
    let b0 = (b & 0xFFFF_FFFF) as u64;
    let a2 = ((a >> 64) & 0xFFFF_FFFF) as u64;
    let b2 = ((b >> 64) & 0xFFFF_FFFF) as u64;
    (a0 as u128 * b0 as u128) | ((a2 as u128 * b2 as u128) << 64)
}

pub(crate) fn pmaddwd(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let base = i * 32;
        let al = ((a >> base) & 0xFFFF) as u16 as i16 as i32;
        let ah = ((a >> (base + 16)) & 0xFFFF) as u16 as i16 as i32;
        let bl = ((b >> base) & 0xFFFF) as u16 as i16 as i32;
        let bh = ((b >> (base + 16)) & 0xFFFF) as u16 as i16 as i32;
        let s = (al * bl).wrapping_add(ah * bh);
        out |= (s as u32 as u128) << base;
    }
    out
}

pub(crate) fn pavg(a: u128, b: u128, esz: usize) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = ((a >> (i * bits)) & mask) as u64;
        let y = ((b >> (i * bits)) & mask) as u64;
        let r = (x + y + 1) >> 1;
        out |= (r as u128 & mask) << (i * bits);
    }
    out
}

pub(crate) fn psadbw(a: u128, b: u128) -> u128 {
    let mut halves = [0u128; 2];
    for (h, acc) in halves.iter_mut().enumerate() {
        let mut sum = 0u32;
        for i in 0..8 {
            let sh = (h * 8 + i) * 8;
            let x = ((a >> sh) & 0xFF) as i32;
            let y = ((b >> sh) & 0xFF) as i32;
            sum += (x - y).unsigned_abs();
        }
        *acc = sum as u128;
    }
    halves[0] | (halves[1] << 64)
}

pub(crate) fn pack(a: u128, b: u128, esz_in: usize, signed_out: bool) -> u128 {
    let bits_in = esz_in * 8;
    let bits_out = bits_in / 2;
    let mask_in = emask(esz_in);
    let mask_out = emask(esz_in / 2);
    let lanes = 16 / esz_in;
    let (lo, hi) = if signed_out {
        (-(1i64 << (bits_out - 1)), (1i64 << (bits_out - 1)) - 1)
    } else {
        (0, (1i64 << bits_out) - 1)
    };
    let mut out = 0u128;
    for (half, src) in [a, b].iter().enumerate() {
        for i in 0..lanes {
            let raw = ((src >> (i * bits_in)) & mask_in) as u64;
            let shift = 64 - bits_in;
            let v = ((raw << shift) as i64) >> shift;
            let c = (v.clamp(lo, hi) as u64) & mask_out as u64;
            out |= (c as u128) << ((half * lanes + i) * bits_out);
        }
    }
    out
}

pub(crate) fn byte_minmax(a: u128, b: u128, max: bool) -> u128 {
    let mut out = 0u128;
    for i in 0..16 {
        let x = ((a >> (i * 8)) & 0xFF) as u8;
        let y = ((b >> (i * 8)) & 0xFF) as u8;
        let r = if max { x.max(y) } else { x.min(y) } as u128;
        out |= r << (i * 8);
    }
    out
}

pub(crate) fn pmovmskb(v: u128) -> u32 {
    let mut m = 0u32;
    for i in 0..16 {
        if (v >> (i * 8 + 7)) & 1 == 1 {
            m |= 1 << i;
        }
    }
    m
}

pub(crate) fn shift_r(v: u128, esz: usize, count: u64, arith: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let sign = 1u128 << (bits - 1);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let e = (v >> (i * bits)) & mask;
        let r = if arith {
            let se = ((e ^ sign).wrapping_sub(sign)) as i128;
            let r = if count >= bits as u64 { se >> 127 } else { se >> count };
            (r as u128) & mask
        } else if count >= bits as u64 {
            0
        } else {
            e >> count
        };
        out |= r << (i * bits);
    }
    out
}

pub(crate) fn shift_l(v: u128, esz: usize, count: u64) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    if count >= bits as u64 {
        return 0;
    }
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let e = (v >> (i * bits)) & mask;
        out |= ((e << count) & mask) << (i * bits);
    }
    out
}

pub(crate) fn pshufd(src: u128, imm: u8) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let dw = (src >> (sel as u32 * 32)) & LOW32;
        out |= dw << (i * 32);
    }
    out
}

pub(crate) fn pshuflw(src: u128, imm: u8) -> u128 {
    let mut low = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let w = (src >> (sel as u32 * 16)) & 0xFFFF;
        low |= w << (i * 16);
    }
    (src & !LOW64) | (low & LOW64)
}

pub(crate) fn pshufhw(src: u128, imm: u8) -> u128 {
    let hi = src >> 64;
    let mut out = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let w = (hi >> (sel as u32 * 16)) & 0xFFFF;
        out |= w << (i * 16);
    }
    (src & LOW64) | (out << 64)
}

pub(crate) fn shufps(dst: u128, src: u128, imm: u8) -> u128 {
    let dw = |v: u128, i: u8| (v >> (i as u32 * 32)) & LOW32;
    let mut out = 0u128;
    out |= dw(dst, imm & 3);
    out |= dw(dst, (imm >> 2) & 3) << 32;
    out |= dw(src, (imm >> 4) & 3) << 64;
    out |= dw(src, (imm >> 6) & 3) << 96;
    out
}

pub(crate) fn shufpd(dst: u128, src: u128, imm: u8) -> u128 {
    let lo = if imm & 1 == 0 { dst & LOW64 } else { (dst >> 64) & LOW64 };
    let hi = if imm & 2 == 0 { src & LOW64 } else { (src >> 64) & LOW64 };
    lo | (hi << 64)
}

pub(crate) fn pshufb(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..16 {
        let ctl = ((b >> (i * 8)) & 0xFF) as u8;
        if ctl & 0x80 == 0 {
            let sel = (ctl & 0x0F) as u32;
            let byte = (a >> (sel * 8)) & 0xFF;
            out |= byte << (i * 8);
        }
    }
    out
}

pub(crate) fn phaddsub(a: u128, b: u128, esz: usize, sub: bool, sat: bool, aliased: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz) as u64;
    let lanes = 16 / esz;
    let shift = 64 - bits;
    let get = |v: u128, i: usize| -> i64 {
        let raw = ((v >> (i * bits)) & (mask as u128)) as u64;
        ((raw << shift) as i64) >> shift
    };
    let combine = |x: i64, y: i64| -> u64 {
        let mut r = if sub { x - y } else { x + y };
        if sat {
            r = r.clamp(-32768, 32767);
        }
        (r as u64) & mask
    };
    let mut d = [0u64; 8];
    for (i, slot) in d.iter_mut().enumerate().take(lanes) {
        *slot = ((a >> (i * bits)) & (mask as u128)) as u64;
    }
    let sext = |raw: u64| -> i64 { ((raw << shift) as i64) >> shift };
    let half = lanes / 2;
    for k in 0..half {
        let x = sext(d[2 * k]);
        let y = sext(d[2 * k + 1]);
        d[k] = combine(x, y);
    }
    for k in 0..half {
        let (x, y) = if aliased {
            (sext(d[2 * k]), sext(d[2 * k + 1]))
        } else {
            (get(b, 2 * k), get(b, 2 * k + 1))
        };
        d[half + k] = combine(x, y);
    }
    let mut out = 0u128;
    for (i, v) in d.iter().enumerate().take(lanes) {
        out |= ((*v as u128) & (mask as u128)) << (i * bits);
    }
    out
}

pub(crate) fn pmaddubsw(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..8 {
        let base = i * 16;
        let a0 = ((a >> base) & 0xFF) as u8 as i32;
        let a1 = ((a >> (base + 8)) & 0xFF) as u8 as i32;
        let b0 = ((b >> base) & 0xFF) as u8 as i8 as i32;
        let b1 = ((b >> (base + 8)) & 0xFF) as u8 as i8 as i32;
        let s = (a0 * b0 + a1 * b1).clamp(-32768, 32767);
        out |= ((s as u16 as u128) & 0xFFFF) << base;
    }
    out
}

pub(crate) fn psign(a: u128, b: u128, esz: usize) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let shift = 64 - bits;
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let av = ((a >> (i * bits)) & mask) as u64;
        let bv = (((((b >> (i * bits)) & mask) as u64) << shift) as i64) >> shift;
        let r = match bv.cmp(&0) {
            std::cmp::Ordering::Less => av.wrapping_neg(),
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => av,
        };
        out |= ((r as u128) & mask) << (i * bits);
    }
    out
}

pub(crate) fn pmulhrsw(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..8 {
        let x = ((a >> (i * 16)) & 0xFFFF) as u16 as i16 as i32;
        let y = ((b >> (i * 16)) & 0xFFFF) as u16 as i16 as i32;
        let r = ((((x * y) >> 14) + 1) >> 1) as i16;
        out |= ((r as u16 as u128) & 0xFFFF) << (i * 16);
    }
    out
}

pub(crate) fn pabs(v: u128, esz: usize) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let shift = 64 - bits;
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = (((((v >> (i * bits)) & mask) as u64) << shift) as i64) >> shift;
        out |= ((x.unsigned_abs() as u128) & mask) << (i * bits);
    }
    out
}

pub(crate) fn blend_var(a: u128, b: u128, mask: u128, esz: usize) -> u128 {
    let bits = esz * 8;
    let em = emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let top = (mask >> (i * bits + bits - 1)) & 1;
        let src = if top == 1 { b } else { a };
        out |= ((src >> (i * bits)) & em) << (i * bits);
    }
    out
}

pub(crate) fn blend_imm(dst: u128, src: u128, imm: u8, esz: usize) -> u128 {
    let bits = esz * 8;
    let em = emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let from_src = (imm >> i) & 1 == 1;
        let v = if from_src { src } else { dst };
        out |= ((v >> (i * bits)) & em) << (i * bits);
    }
    out
}

pub(crate) fn pmovx(src: u128, src_sz: usize, dst_sz: usize, sign: bool) -> u128 {
    let sbits = src_sz * 8;
    let dbits = dst_sz * 8;
    let smask = emask(src_sz);
    let dmask = emask(dst_sz);
    let shift = 64 - sbits;
    let count = 16 / dst_sz;
    let mut out = 0u128;
    for i in 0..count {
        let raw = ((src >> (i * sbits)) & smask) as u64;
        let ext = if sign { (((raw << shift) as i64) >> shift) as u64 } else { raw };
        out |= ((ext as u128) & dmask) << (i * dbits);
    }
    out
}

pub(crate) fn pmuldq(a: u128, b: u128) -> u128 {
    let a0 = (a & 0xFFFF_FFFF) as u32 as i32 as i64;
    let b0 = (b & 0xFFFF_FFFF) as u32 as i32 as i64;
    let a2 = ((a >> 64) & 0xFFFF_FFFF) as u32 as i32 as i64;
    let b2 = ((b >> 64) & 0xFFFF_FFFF) as u32 as i32 as i64;
    ((a0 * b0) as u64 as u128) | (((a2 * b2) as u64 as u128) << 64)
}

pub(crate) fn packusdw(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for (half, src) in [a, b].iter().enumerate() {
        for i in 0..4 {
            let v = ((src >> (i * 32)) & 0xFFFF_FFFF) as u32 as i32;
            let c = v.clamp(0, 0xFFFF) as u32 as u128;
            out |= c << ((half * 4 + i) * 16);
        }
    }
    out
}

pub(crate) fn int_minmax(a: u128, b: u128, esz: usize, signed: bool, max: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let shift = 64 - bits;
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let xr = ((a >> (i * bits)) & mask) as u64;
        let yr = ((b >> (i * bits)) & mask) as u64;
        let take_x = if signed {
            let x = ((xr << shift) as i64) >> shift;
            let y = ((yr << shift) as i64) >> shift;
            if max { x > y } else { x < y }
        } else if max {
            xr > yr
        } else {
            xr < yr
        };
        let r = if take_x { xr } else { yr };
        out |= ((r as u128) & mask) << (i * bits);
    }
    out
}

pub(crate) fn pmulld(a: u128, b: u128) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let x = ((a >> (i * 32)) & 0xFFFF_FFFF) as u32;
        let y = ((b >> (i * 32)) & 0xFFFF_FFFF) as u32;
        out |= ((x.wrapping_mul(y)) as u128) << (i * 32);
    }
    out
}

fn phminposuw(src: u128) -> u128 {
    let mut min = 0xFFFFu32;
    let mut idx = 0u32;
    for i in 0..8u32 {
        let w = ((src >> (i * 16)) & 0xFFFF) as u32;
        if w < min {
            min = w;
            idx = i;
        }
    }
    (min as u128) | ((idx as u128) << 16)
}

pub(crate) fn palignr(a: u128, b: u128, imm: u8) -> u128 {
    let n = imm as u32;
    if n >= 32 {
        return 0;
    }
    if n == 0 {
        return b;
    }
    let shift = n * 8;
    if n < 16 {
        (b >> shift) | (a << (128 - shift))
    } else {
        a >> ((n - 16) * 8)
    }
}

fn dpps(a: u128, b: u128, imm: u8) -> u128 {
    let mut sum = 0f32;
    for i in 0..4 {
        if (imm >> (4 + i)) & 1 == 1 {
            sum += f32_lane(a, i) * f32_lane(b, i);
        }
    }
    let mut out = 0u128;
    for i in 0..4 {
        let v = if (imm >> i) & 1 == 1 { sum } else { 0.0 };
        out |= (v.to_bits() as u128) << (i * 32);
    }
    out
}

fn dppd(a: u128, b: u128, imm: u8) -> u128 {
    let mut sum = 0f64;
    for i in 0..2 {
        if (imm >> (4 + i)) & 1 == 1 {
            sum += f64_lane(a, i) * f64_lane(b, i);
        }
    }
    let mut out = 0u128;
    for i in 0..2 {
        let v = if (imm >> i) & 1 == 1 { sum } else { 0.0 };
        out |= (v.to_bits() as u128) << (i * 64);
    }
    out
}

pub(crate) fn mpsadbw(a: u128, b: u128, imm: u8) -> u128 {
    let a_off = (((imm >> 2) & 1) * 4) as u32;
    let b_off = ((imm & 3) * 4) as u32;
    let abyte = |i: u32| ((a >> (i * 8)) & 0xFF) as i32;
    let bbyte = |i: u32| ((b >> (i * 8)) & 0xFF) as i32;
    let mut out = 0u128;
    for k in 0..8u32 {
        let mut sum = 0i32;
        for j in 0..4u32 {
            let av = abyte(a_off + k + j);
            let bv = bbyte(b_off + j);
            sum += (av - bv).abs();
        }
        out |= ((sum as u16 as u128) & 0xFFFF) << (k * 16);
    }
    out
}

fn implicit_len(v: u128, elem_bytes: usize, n: usize) -> usize {
    let bits = elem_bytes * 8;
    let mask = emask(elem_bytes);
    for i in 0..n {
        if (v >> (i * bits)) & mask == 0 {
            return i;
        }
    }
    n
}

pub(crate) fn round_f32(x: f32, mode: u8) -> f32 {
    match mode {
        0 => {
            let r = x.round_ties_even();
            if r == 0.0 && x.is_sign_negative() { -0.0 } else { r }
        }
        1 => x.floor(),
        2 => x.ceil(),
        _ => x.trunc(),
    }
}

pub(crate) fn round_f64(x: f64, mode: u8) -> f64 {
    match mode {
        0 => {
            let r = x.round_ties_even();
            if r == 0.0 && x.is_sign_negative() { -0.0 } else { r }
        }
        1 => x.floor(),
        2 => x.ceil(),
        _ => x.trunc(),
    }
}

fn unsupported3(esc: u8, op3: u8, ctx: &Ctx, group: &str) -> Result<()> {
    let pfx = if ctx.pfx.rep == 0xF3 {
        "f3 "
    } else if ctx.pfx.rep == 0xF2 {
        "f2 "
    } else if ctx.pfx.p66 {
        "66 "
    } else {
        ""
    };
    Err(EmuError::Unsupported(format!("{group}: {pfx}0f {esc:02x} {op3:02x}")))
}

fn unsupported(op2: u8, ctx: &Ctx, group: &str) -> Result<()> {
    let pfx = if ctx.pfx.rep == 0xF3 {
        "f3 "
    } else if ctx.pfx.rep == 0xF2 {
        "f2 "
    } else if ctx.pfx.p66 {
        "66 "
    } else {
        ""
    };
    Err(EmuError::Unsupported(format!("{group}: {pfx}0f {op2:02x}")))
}
