use super::*;
use crate::sse;
use exemu_core::cpu::flags;

#[derive(Clone, Copy)]
pub(crate) struct Vex {
    r: u8,
    x: u8,
    b: u8,
    w: bool,
    vvvv: u8,
    l: bool,
    pp: u8,
    mmmmm: u8,
}

impl Vex {
    #[inline]
    fn pd(&self) -> bool {
        self.pp == 1
    }
    #[inline]
    fn f3(&self) -> bool {
        self.pp == 2
    }
    #[inline]
    fn f2(&self) -> bool {
        self.pp == 3
    }
}

impl Interpreter {
    pub(crate) fn exec_vex(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, two_byte: bool) -> Result<()> {
        let vex = self.decode_vex(ctx, mem, two_byte)?;
        let op = ctx.u8_at_op;
        if vex.mmmmm == 1 && op == 0x77 {
            if vex.l {
                self.state.xmm = [0u128; 16];
                self.state.ymm_hi = [0u128; 16];
            } else {
                self.state.ymm_hi = [0u128; 16];
            }
            return Ok(());
        }
        self.read_modrm_vex(ctx, mem, &vex)?;
        match vex.mmmmm {
            1 => self.vex_0f(ctx, mem, &vex, op),
            2 => self.vex_0f38(ctx, mem, &vex, op),
            3 => self.vex_0f3a(ctx, mem, &vex, op),
            _ => Err(EmuError::Unsupported(format!("VEX map {} op {op:#04x}", vex.mmmmm))),
        }
    }

    fn decode_vex(&self, ctx: &mut Ctx, mem: &dyn Memory, two_byte: bool) -> Result<Vex> {
        let vex = if two_byte {
            let b1 = ctx.u8(mem)?;
            Vex {
                r: (!(b1 >> 7)) & 1,
                x: 0,
                b: 0,
                w: false,
                vvvv: (!(b1 >> 3)) & 0xF,
                l: (b1 >> 2) & 1 != 0,
                pp: b1 & 3,
                mmmmm: 1,
            }
        } else {
            let b1 = ctx.u8(mem)?;
            let b2 = ctx.u8(mem)?;
            Vex {
                r: (!(b1 >> 7)) & 1,
                x: (!(b1 >> 6)) & 1,
                b: (!(b1 >> 5)) & 1,
                w: (b2 >> 7) & 1 != 0,
                vvvv: (!(b2 >> 3)) & 0xF,
                l: (b2 >> 2) & 1 != 0,
                pp: b2 & 3,
                mmmmm: b1 & 0x1F,
            }
        };
        let mut vex = vex;
        if ctx.bits == Bits::B32 {
            vex.r = 0;
            vex.x = 0;
            vex.b = 0;
            vex.vvvv &= 7;
        }
        ctx.u8_at_op = ctx.u8(mem)?;
        Ok(vex)
    }

    fn read_modrm_vex(&self, ctx: &mut Ctx, mem: &dyn Memory, vex: &Vex) -> Result<()> {
        ctx.pfx.rex = 0x40 | ((vex.w as u8) << 3) | (vex.r << 2) | (vex.x << 1) | vex.b;
        ctx.pfx.has_rex = ctx.bits == Bits::B64;
        self.read_modrm(ctx, mem)
    }

    fn vrm128(&self, ctx: &Ctx, mem: &dyn Memory, n: usize) -> Result<u128> {
        match ctx.rm {
            Rm::Reg(i) => Ok(self.state.xmm(i)),
            Rm::Mem { .. } => {
                let mut buf = [0u8; 16];
                mem.read(ctx.rm_addr(), &mut buf[..n])?;
                Ok(u128::from_le_bytes(buf))
            }
        }
    }

    fn vrm256(&self, ctx: &Ctx, mem: &dyn Memory) -> Result<(u128, u128)> {
        match ctx.rm {
            Rm::Reg(i) => Ok((self.state.xmm(i), self.state.ymm_hi(i))),
            Rm::Mem { .. } => {
                let a = ctx.rm_addr();
                let mut buf = [0u8; 32];
                mem.read(a, &mut buf)?;
                let mut lo = [0u8; 16];
                let mut hi = [0u8; 16];
                lo.copy_from_slice(&buf[..16]);
                hi.copy_from_slice(&buf[16..]);
                Ok((u128::from_le_bytes(lo), u128::from_le_bytes(hi)))
            }
        }
    }

    fn vstore128(&mut self, ctx: &Ctx, mem: &mut dyn Memory, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.set_xmm_zero_upper(i, val);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()),
        }
    }

    fn vstore256(&mut self, ctx: &Ctx, mem: &mut dyn Memory, lo: u128, hi: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.set_ymm(i, lo, hi);
                Ok(())
            }
            Rm::Mem { .. } => {
                let mut buf = [0u8; 32];
                buf[..16].copy_from_slice(&lo.to_le_bytes());
                buf[16..].copy_from_slice(&hi.to_le_bytes());
                mem.write(ctx.rm_addr(), &buf)
            }
        }
    }

    fn vstore_low(&mut self, ctx: &Ctx, mem: &mut dyn Memory, n: usize, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                let mask = if n >= 16 { u128::MAX } else { (1u128 << (n * 8)) - 1 };
                self.state.set_xmm_zero_upper(i, val & mask);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()[..n]),
        }
    }

    #[inline]
    fn vdst(&mut self, reg: u8, l: bool, lo: u128, hi: u128) {
        if l {
            self.state.set_ymm(reg, lo, hi);
        } else {
            self.state.set_xmm_zero_upper(reg, lo);
        }
    }

    #[inline]
    fn vsrc(&self, vex: &Vex) -> (u128, u128) {
        (self.state.xmm(vex.vvvv), self.state.ymm_hi(vex.vvvv))
    }

    fn vex_0f(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            0x10 | 0x28 => {
                if vex.f3() || vex.f2() {
                    return self.vex_movss_sd(ctx, mem, vex, reg,  false);
                }
                let (lo, hi) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, lo, hi);
            }
            0x11 | 0x29 => {
                if vex.f3() || vex.f2() {
                    return self.vex_movss_sd(ctx, mem, vex, reg,  true);
                }
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                if vex.l {
                    self.vstore256(ctx, mem, lo, hi)?;
                } else {
                    self.vstore128(ctx, mem, lo)?;
                }
            }

            0x12 => {
                let dst = self.state.xmm(vex.vvvv);
                let lo = match ctx.rm {
                    Rm::Reg(i) => (dst & !sse::LOW64) | (self.state.xmm(i) >> 64),
                    Rm::Mem { .. } => (dst & !sse::LOW64) | (self.vrm128(ctx, mem, 8)? & sse::LOW64),
                };
                self.state.set_xmm_zero_upper(reg, lo);
            }
            0x13 => {
                let v = self.state.xmm(reg) & sse::LOW64;
                self.vstore_low(ctx, mem, 8, v)?;
            }
            0x16 => {
                let dst = self.state.xmm(vex.vvvv);
                let lo = match ctx.rm {
                    Rm::Reg(i) => (dst & sse::LOW64) | (self.state.xmm(i) << 64),
                    Rm::Mem { .. } => (dst & sse::LOW64) | (self.vrm128(ctx, mem, 8)? << 64),
                };
                self.state.set_xmm_zero_upper(reg, lo);
            }
            0x17 => {
                let v = self.state.xmm(reg) >> 64;
                self.vstore_low(ctx, mem, 8, v)?;
            }

            0x6F => {
                let (lo, hi) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, lo, hi);
            }
            0x7F => {
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                if vex.l {
                    self.vstore256(ctx, mem, lo, hi)?;
                } else {
                    self.vstore128(ctx, mem, lo)?;
                }
            }

            0x6E => {
                let size = if vex.w { 8 } else { 4 };
                let v = self.read_rm(ctx, &*mem, size)? as u128 & sse::low_mask(size as usize);
                self.state.set_xmm_zero_upper(reg, v);
            }
            0x7E => {
                if vex.f3() {
                    let v = self.vrm128(ctx, mem, 8)? & sse::LOW64;
                    self.state.set_xmm_zero_upper(reg, v);
                } else {
                    let size = if vex.w { 8 } else { 4 };
                    let v = self.state.xmm(reg) & sse::low_mask(size as usize);
                    self.write_rm(ctx, mem, size, v as u64)?;
                }
            }
            0xD6 => {
                let v = self.state.xmm(reg) & sse::LOW64;
                self.vstore_low(ctx, mem, 8, v)?;
            }

            0x58 => self.vex_farith(ctx, mem, vex, reg, |a, b| a + b)?,
            0x59 => self.vex_farith(ctx, mem, vex, reg, |a, b| a * b)?,
            0x5C => self.vex_farith(ctx, mem, vex, reg, |a, b| a - b)?,
            0x5D => self.vex_farith(ctx, mem, vex, reg, sse_min)?,
            0x5E => self.vex_farith(ctx, mem, vex, reg, |a, b| a / b)?,
            0x5F => self.vex_farith(ctx, mem, vex, reg, sse_max)?,
            0x51 => self.vex_funary(ctx, mem, vex, reg, f64::sqrt)?,

            0x54 => self.vex_logic(ctx, mem, vex, reg, |a, b| a & b)?,
            0x55 => self.vex_logic(ctx, mem, vex, reg, |a, b| !a & b)?,
            0x56 => self.vex_logic(ctx, mem, vex, reg, |a, b| a | b)?,
            0x57 => self.vex_logic(ctx, mem, vex, reg, |a, b| a ^ b)?,

            0x14 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, if vex.pd() { 8 } else { 4 }, false))?,
            0x15 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, if vex.pd() { 8 } else { 4 }, true))?,

            0xC6 => {
                let (sl, sh) = self.vsrc(vex);
                let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
                let imm = ctx.u8(mem)?;
                if vex.pd() {
                    self.vdst(reg, vex.l, sse::shufpd(sl, bl, imm), if vex.l { sse::shufpd(sh, bh, imm >> 2) } else { 0 });
                } else {
                    self.vdst(reg, vex.l, sse::shufps(sl, bl, imm), if vex.l { sse::shufps(sh, bh, imm) } else { 0 });
                }
            }

            0xC2 => self.vex_cmp(ctx, mem, vex, reg)?,

            0x2E | 0x2F => {
                let src = self.vrm128(ctx, mem, if vex.pd() { 8 } else { 4 })?;
                let dst = self.state.xmm(reg);
                let (a, b) = if vex.pd() {
                    (f64::from_bits(dst as u64), f64::from_bits(src as u64))
                } else {
                    (f32::from_bits(dst as u32) as f64, f32::from_bits(src as u32) as f64)
                };
                self.set_compare_flags(a, b);
            }

            0xD4 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 8, true))?,
            0xFB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 8, false))?,
            0xFC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 1, true))?,
            0xFD => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 2, true))?,
            0xFE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 4, true))?,
            0xF8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 1, false))?,
            0xF9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 2, false))?,
            0xFA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 4, false))?,
            0xDB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a & b)?,
            0xDF => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| !a & b)?,
            0xEB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a | b)?,
            0xEF => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a ^ b)?,
            0x74 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 1, false))?,
            0x75 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 2, false))?,
            0x76 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 4, false))?,
            0x64 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 1, true))?,
            0x65 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 2, true))?,
            0x66 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 4, true))?,
            0xD5 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmullw)?,
            0xE5 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pmulh(a, b, true))?,
            0xE4 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pmulh(a, b, false))?,
            0xF4 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmuludq)?,
            0xF5 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmaddwd)?,
            0xF6 => self.vex_lane_bin(ctx, mem, vex, reg, sse::psadbw)?,
            0xDC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, true, false))?,
            0xDD => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, true, false))?,
            0xEC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, true, true))?,
            0xED => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, true, true))?,
            0xD8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, false, false))?,
            0xD9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, false, false))?,
            0xE8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, false, true))?,
            0xE9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, false, true))?,
            0xDA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::byte_minmax(a, b, false))?,
            0xDE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::byte_minmax(a, b, true))?,
            0xEA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, true, false))?,
            0xEE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, true, true))?,
            0xE0 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pavg(a, b, 1))?,
            0xE3 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pavg(a, b, 2))?,

            0x60 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 1, false))?,
            0x61 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 2, false))?,
            0x62 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 4, false))?,
            0x6C => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 8, false))?,
            0x68 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 1, true))?,
            0x69 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 2, true))?,
            0x6A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 4, true))?,
            0x6D => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 8, true))?,

            0x63 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 2, true))?,
            0x6B => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 4, true))?,
            0x67 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 2, false))?,

            0x70 => {
                let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
                let imm = ctx.u8(mem)?;
                let f: fn(u128, u8) -> u128 = if vex.f2() {
                    sse::pshuflw
                } else if vex.f3() {
                    sse::pshufhw
                } else {
                    sse::pshufd
                };
                self.vdst(reg, vex.l, f(bl, imm), if vex.l { f(bh, imm) } else { 0 });
            }

            0xD7 => {
                let lo = sse::pmovmskb(self.vrm128(ctx, mem, 16)?);
                let mask = if vex.l {
                    let (_, hi) = self.vrm256(ctx, mem)?;
                    lo | (sse::pmovmskb(hi) << 16)
                } else {
                    lo
                };
                self.state.gpr_write(reg, 4, mask as u64);
            }
            0x50 => {
                let esz = if vex.pd() { 8 } else { 4 };
                let per = 16 / esz;
                let mut mask = 0u64;
                let (lo, hi) = self.vrm256_or128(ctx, mem, vex)?;
                for (half, v) in [lo, hi].into_iter().enumerate() {
                    if half == 1 && !vex.l {
                        break;
                    }
                    for i in 0..per {
                        let bit = (v >> ((i + 1) * esz * 8 - 1)) & 1;
                        mask |= (bit as u64) << (half * per + i);
                    }
                }
                self.state.gpr_write(reg, 4, mask);
            }

            0x71..=0x73 => self.vex_shift_imm(ctx, mem, vex, op)?,
            0xD1 => self.vex_shift_var(ctx, mem, vex, reg, 2, false, false)?,
            0xD2 => self.vex_shift_var(ctx, mem, vex, reg, 4, false, false)?,
            0xD3 => self.vex_shift_var(ctx, mem, vex, reg, 8, false, false)?,
            0xE1 => self.vex_shift_var(ctx, mem, vex, reg, 2, true, false)?,
            0xE2 => self.vex_shift_var(ctx, mem, vex, reg, 4, true, false)?,
            0xF1 => self.vex_shift_var(ctx, mem, vex, reg, 2, false, true)?,
            0xF2 => self.vex_shift_var(ctx, mem, vex, reg, 4, false, true)?,
            0xF3 => self.vex_shift_var(ctx, mem, vex, reg, 8, false, true)?,

            0x5B => {
                let (lo, hi) = self.vload_rm(ctx, mem, vex)?;
                let f: fn(u128) -> u128 = if vex.pd() {
                    |v| sse::cvtps2dq(v, false)
                } else if vex.f3() {
                    |v| sse::cvtps2dq(v, true)
                } else {
                    sse::cvtdq2ps
                };
                self.vdst(reg, vex.l, f(lo), if vex.l { f(hi) } else { 0 });
            }
            0x2A => {
                let size = if vex.w { 8 } else { 4 };
                let src = alu::sext(self.read_rm(ctx, &*mem, size)?, size) as i64;
                let base = self.state.xmm(vex.vvvv);
                let v = if vex.f2() {
                    (base & !sse::LOW64) | ((src as f64).to_bits() as u128)
                } else {
                    (base & !sse::LOW32) | ((src as f32).to_bits() as u128)
                };
                self.state.set_xmm_zero_upper(reg, v);
            }
            0x2C | 0x2D => {
                let truncate = op == 0x2C;
                let size = if vex.w { 8 } else { 4 };
                let src = self.vrm128(ctx, mem, 8)?;
                let f = if vex.f2() { f64::from_bits(src as u64) } else { f32::from_bits(src as u32) as f64 };
                let r = sse::cvt_f_to_int(f, truncate, size);
                self.write_reg_field(ctx, size, r);
            }
            0x5A => {
                let src = self.vrm128(ctx, mem, 8)?;
                let base = self.state.xmm(vex.vvvv);
                let v = if vex.f2() {
                    (base & !sse::LOW32) | ((f64::from_bits(src as u64) as f32).to_bits() as u128)
                } else {
                    (base & !sse::LOW64) | ((f32::from_bits(src as u32) as f64).to_bits() as u128)
                };
                self.state.set_xmm_zero_upper(reg, v);
            }

            _ => return Err(EmuError::Unsupported(format!("VEX 0F {op:#04x}"))),
        }
        Ok(())
    }

    fn vex_0f38(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            0xF2 => return self.bmi_andn(ctx, mem, vex),
            0xF3 => return self.bmi_group17(ctx, mem, vex),
            0xF5 => return self.bmi_f5(ctx, mem, vex),
            0xF6 => return self.bmi_mulx(ctx, mem, vex),
            0xF7 => return self.bmi_f7(ctx, mem, vex),
            0x13 if vex.pp == 1 => return self.vex_cvtph2ps(ctx, mem, vex, reg),
            _ => {}
        }
        match op {
            0x00 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pshufb)?,
            0x01 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, false, false, false))?,
            0x02 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 4, false, false, false))?,
            0x05 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, true, false, false))?,
            0x06 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 4, true, false, false))?,
            0x03 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, false, true, false))?,
            0x07 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, true, true, false))?,
            0x04 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmaddubsw)?,
            0x08 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 1))?,
            0x09 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 2))?,
            0x0A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 4))?,
            0x0B => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmulhrsw)?,
            0x1C => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 1))?,
            0x1D => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 2))?,
            0x1E => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 4))?,
            0x28 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmuldq)?,
            0x29 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 8, false))?,
            0x37 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 8, true))?,
            0x2B => self.vex_lane_bin(ctx, mem, vex, reg, sse::packusdw)?,
            0x40 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmulld)?,
            0x38 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 1, true, false))?,
            0x3C => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 1, true, true))?,
            0x39 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, true, false))?,
            0x3D => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, true, true))?,
            0x3A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, false, false))?,
            0x3E => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, false, true))?,
            0x3B => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, false, false))?,
            0x3F => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, false, true))?,

            0x20 => self.vex_pmovx(ctx, mem, vex, reg, 1, 2, true)?,
            0x21 => self.vex_pmovx(ctx, mem, vex, reg, 1, 4, true)?,
            0x22 => self.vex_pmovx(ctx, mem, vex, reg, 1, 8, true)?,
            0x23 => self.vex_pmovx(ctx, mem, vex, reg, 2, 4, true)?,
            0x24 => self.vex_pmovx(ctx, mem, vex, reg, 2, 8, true)?,
            0x25 => self.vex_pmovx(ctx, mem, vex, reg, 4, 8, true)?,
            0x30 => self.vex_pmovx(ctx, mem, vex, reg, 1, 2, false)?,
            0x31 => self.vex_pmovx(ctx, mem, vex, reg, 1, 4, false)?,
            0x32 => self.vex_pmovx(ctx, mem, vex, reg, 1, 8, false)?,
            0x33 => self.vex_pmovx(ctx, mem, vex, reg, 2, 4, false)?,
            0x34 => self.vex_pmovx(ctx, mem, vex, reg, 2, 8, false)?,
            0x35 => self.vex_pmovx(ctx, mem, vex, reg, 4, 8, false)?,

            0x78 => self.vex_broadcast(ctx, mem, vex, reg, 1)?,
            0x79 => self.vex_broadcast(ctx, mem, vex, reg, 2)?,
            0x58 => self.vex_broadcast(ctx, mem, vex, reg, 4)?,
            0x59 => self.vex_broadcast(ctx, mem, vex, reg, 8)?,
            0x18 => self.vex_broadcast(ctx, mem, vex, reg, 4)?,
            0x19 => self.vex_broadcast(ctx, mem, vex, reg, 8)?,

            0x17 => self.vex_ptest(ctx, mem, vex, reg)?,

            0x36 => self.vex_permd(ctx, mem, vex, reg)?,
            0x16 => self.vex_permps(ctx, mem, vex, reg)?,

            0x47 => self.vex_var_shift(ctx, mem, vex, reg, if vex.w { 8 } else { 4 }, false, true)?,
            0x45 => self.vex_var_shift(ctx, mem, vex, reg, if vex.w { 8 } else { 4 }, false, false)?,
            0x46 => self.vex_var_shift(ctx, mem, vex, reg, 4, true, false)?,

            _ => return Err(EmuError::Unsupported(format!("VEX 0F38 {op:#04x}"))),
        }
        Ok(())
    }

    fn vex_0f3a(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            0xF0 if vex.f2() => return self.bmi_rorx(ctx, mem, vex),
            0x1D if vex.pp == 1 => return self.vex_cvtps2ph(ctx, mem, vex, reg),
            _ => {}
        }
        match op {
            0x0F => {
                let imm = ctx.u8(mem)?;
                let (sl, sh) = self.vsrc(vex);
                let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, sse::palignr(sl, bl, imm), if vex.l { sse::palignr(sh, bh, imm) } else { 0 });
            }
            0x0E => self.vex_blend_imm(ctx, mem, vex, reg, 2)?,
            0x0C => self.vex_blend_imm(ctx, mem, vex, reg, 4)?,
            0x0D => self.vex_blend_imm(ctx, mem, vex, reg, 8)?,
            0x02 => self.vex_blend_imm(ctx, mem, vex, reg, 4)?,

            0x08 => self.vex_round_packed(ctx, mem, vex, reg, false)?,
            0x09 => self.vex_round_packed(ctx, mem, vex, reg, true)?,
            0x0A => self.vex_round_scalar(ctx, mem, vex, reg, false)?,
            0x0B => self.vex_round_scalar(ctx, mem, vex, reg, true)?,

            0x00 => self.vex_permq(ctx, mem, vex, reg)?,
            0x01 => self.vex_permpd(ctx, mem, vex, reg)?,

            0x39 | 0x19 => {
                let imm = ctx.u8(mem)?;
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                let sel = if imm & 1 != 0 { hi } else { lo };
                self.vstore128(ctx, mem, sel)?;
            }
            0x38 | 0x18 => {
                let imm = ctx.u8(mem)?;
                let (dl, dh) = self.vsrc(vex);
                let ins = self.vrm128(ctx, mem, 16)?;
                let (lo, hi) = if imm & 1 != 0 { (dl, ins) } else { (ins, dh) };
                self.state.set_ymm(reg, lo, hi);
            }
            0x46 | 0x06 => self.vex_perm2i128(ctx, mem, vex, reg)?,

            0x14 => self.vex_pextr(ctx, mem, vex, reg, 1)?,
            0x15 => self.vex_pextr(ctx, mem, vex, reg, 2)?,
            0x16 => self.vex_pextr(ctx, mem, vex, reg, if vex.w { 8 } else { 4 })?,
            0x20 => self.vex_pinsr(ctx, mem, vex, reg, 1)?,
            0x22 => self.vex_pinsr(ctx, mem, vex, reg, if vex.w { 8 } else { 4 })?,

            0x42 => {
                let imm = ctx.u8(mem)?;
                let (sl, _sh) = self.vsrc(vex);
                let bl = self.vrm128(ctx, mem, 16)?;
                self.state.set_xmm_zero_upper(reg, sse::mpsadbw(sl, bl, imm));
            }

            _ => return Err(EmuError::Unsupported(format!("VEX 0F3A {op:#04x}"))),
        }
        Ok(())
    }

    fn vload_rm(&self, ctx: &Ctx, mem: &dyn Memory, vex: &Vex) -> Result<(u128, u128)> {
        if vex.l {
            self.vrm256(ctx, mem)
        } else {
            Ok((self.vrm128(ctx, mem, 16)?, 0))
        }
    }

    fn vrm256_or128(&self, ctx: &Ctx, mem: &dyn Memory, vex: &Vex) -> Result<(u128, u128)> {
        self.vload_rm(ctx, mem, vex)
    }

    fn imm_after_rm(&self, ctx: &mut Ctx, mem: &dyn Memory) -> Result<u8> {
        ctx.u8(mem)
    }

    #[inline]
    fn bmi_size(vex: &Vex) -> u8 {
        if vex.w {
            8
        } else {
            4
        }
    }

    #[inline]
    fn bmi_szf(&mut self, res: u64, size: u8) {
        let sb = 1u64 << (size * 8 - 1);
        self.state.set_flag(flags::SF, res & sb != 0);
        self.state.set_flag(flags::ZF, res == 0);
        self.state.set_flag(flags::OF, false);
    }

    fn bmi_andn(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        let size = Self::bmi_size(vex);
        let vvvv = self.state.gpr_read(vex.vvvv, size);
        let src = self.read_rm(ctx, &*mem, size)?;
        let res = (!vvvv & src) & alu::mask(size);
        self.write_reg_field(ctx, size, res);
        self.state.set_flag(flags::CF, false);
        self.bmi_szf(res, size);
        Ok(())
    }

    fn bmi_group17(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        let size = Self::bmi_size(vex);
        let m = alu::mask(size);
        let src = self.read_rm(ctx, &*mem, size)? & m;
        let digit = ctx.reg & 7;
        let (res, cf) = match digit {
            1 => (src & src.wrapping_sub(1) & m, src == 0),
            2 => ((src.wrapping_sub(1) ^ src) & m, src == 0),
            3 => (src.wrapping_neg() & src & m, src != 0),
            _ => return Err(EmuError::Unsupported(format!("VEX 0F38 F3 /{digit}"))),
        };
        self.state.gpr_write(vex.vvvv, size, res);
        self.state.set_flag(flags::CF, cf);
        if digit == 2 {
            let sb = 1u64 << (size * 8 - 1);
            self.state.set_flag(flags::SF, res & sb != 0);
            self.state.set_flag(flags::ZF, false);
            self.state.set_flag(flags::OF, false);
        } else {
            self.bmi_szf(res, size);
        }
        Ok(())
    }

    fn bmi_f5(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        let size = Self::bmi_size(vex);
        let m = alu::mask(size);
        let opbits = (size * 8) as u32;
        if vex.pp == 0 {
            let src = self.read_rm(ctx, &*mem, size)? & m;
            let idx = (self.state.gpr_read(vex.vvvv, size) & 0xFF) as u32;
            let res = if idx >= opbits { src } else { src & ((1u64 << idx) - 1) };
            self.write_reg_field(ctx, size, res & m);
            self.state.set_flag(flags::CF, idx >= opbits);
            self.bmi_szf(res & m, size);
        } else if vex.pp == 2 {
            let val = self.state.gpr_read(vex.vvvv, size) & m;
            let mask = self.read_rm(ctx, &*mem, size)? & m;
            let mut res = 0u64;
            let mut k = 0;
            for i in 0..opbits {
                if (mask >> i) & 1 != 0 {
                    if (val >> i) & 1 != 0 {
                        res |= 1u64 << k;
                    }
                    k += 1;
                }
            }
            self.write_reg_field(ctx, size, res & m);
        } else if vex.pp == 3 {
            let val = self.state.gpr_read(vex.vvvv, size) & m;
            let mask = self.read_rm(ctx, &*mem, size)? & m;
            let mut res = 0u64;
            let mut k = 0;
            for i in 0..opbits {
                if (mask >> i) & 1 != 0 {
                    if (val >> k) & 1 != 0 {
                        res |= 1u64 << i;
                    }
                    k += 1;
                }
            }
            self.write_reg_field(ctx, size, res & m);
        } else {
            return Err(EmuError::Unsupported("VEX 0F38 F5 pp".into()));
        }
        Ok(())
    }

    fn bmi_mulx(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        if !vex.f2() {
            return Err(EmuError::Unsupported("VEX 0F38 F6 non-F2".into()));
        }
        let size = Self::bmi_size(vex);
        let m = alu::mask(size);
        let src = self.read_rm(ctx, &*mem, size)? & m;
        let edx = self.state.gpr_read(2, size) & m;
        let prod = (edx as u128) * (src as u128);
        let bits = (size * 8) as u32;
        let lo = (prod as u64) & m;
        let hi = ((prod >> bits) as u64) & m;
        self.state.gpr_write(vex.vvvv, size, lo);
        self.write_reg_field(ctx, size, hi);
        Ok(())
    }

    fn bmi_f7(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        let size = Self::bmi_size(vex);
        let m = alu::mask(size);
        let opbits = (size * 8) as u32;
        let src = self.read_rm(ctx, &*mem, size)? & m;
        match vex.pp {
            0 => {
                let ctrl = self.state.gpr_read(vex.vvvv, size);
                let start = (ctrl & 0xFF) as u32;
                let len = ((ctrl >> 8) & 0xFF) as u32;
                let shifted = if start >= opbits { 0 } else { src >> start };
                let res = if len >= opbits {
                    shifted & m
                } else if len == 0 {
                    0
                } else {
                    shifted & ((1u64 << len) - 1)
                };
                self.write_reg_field(ctx, size, res & m);
                self.state.set_flag(flags::ZF, res & m == 0);
                self.state.set_flag(flags::CF, false);
                self.state.set_flag(flags::OF, false);
            }
            1..=3 => {
                let cnt = (self.state.gpr_read(vex.vvvv, size) & (opbits as u64 - 1)) as u32;
                let res = match vex.pp {
                    1 => (src << cnt) & m,
                    3 => src >> cnt,
                    _ => {
                        let sb = 1u64 << (opbits - 1);
                        let sext = if src & sb != 0 { src | !m } else { src };
                        ((sext as i64) >> cnt) as u64 & m
                    }
                };
                self.write_reg_field(ctx, size, res);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn bmi_rorx(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex) -> Result<()> {
        let size = Self::bmi_size(vex);
        let m = alu::mask(size);
        let src = self.read_rm(ctx, &*mem, size)? & m;
        let imm = self.imm_after_rm(ctx, mem)? as u32;
        let opbits = (size * 8) as u32;
        let n = imm & (opbits - 1);
        let res = if n == 0 { src } else { ((src >> n) | (src << (opbits - n))) & m };
        self.write_reg_field(ctx, size, res);
        Ok(())
    }

    fn vex_cvtph2ps(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let n = if vex.l { 8 } else { 4 };
        let src = self.vrm128(ctx, mem, n * 2)?;
        let mut lo = 0u128;
        let mut hi = 0u128;
        for i in 0..n {
            let h = ((src >> (i * 16)) & 0xFFFF) as u16;
            let f = f16_to_f32(h);
            if i < 4 {
                lo |= (f as u128) << (i * 32);
            } else {
                hi |= (f as u128) << ((i - 4) * 32);
            }
        }
        if vex.l {
            self.state.set_ymm(reg, lo, hi);
        } else {
            self.state.set_xmm_zero_upper(reg, lo);
        }
        Ok(())
    }

    fn vex_cvtps2ph(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let n = if vex.l { 8 } else { 4 };
        let (sl, sh) = (self.state.xmm(reg), self.state.ymm_hi(reg));
        let imm = self.imm_after_rm(ctx, mem)?;
        let _ = imm;
        let mut packed = 0u128;
        for i in 0..n {
            let bits32 = if i < 4 { (sl >> (i * 32)) as u32 } else { (sh >> ((i - 4) * 32)) as u32 };
            let h = f32_to_f16(f32::from_bits(bits32));
            packed |= (h as u128) << (i * 16);
        }
        let nbytes = n * 2;
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.set_xmm_zero_upper(i, packed);
            }
            Rm::Mem { .. } => {
                let bytes = packed.to_le_bytes();
                mem.write(ctx.rm_addr(), &bytes[..nbytes])?;
            }
        }
        Ok(())
    }

    fn vex_lane_bin(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        f: impl Fn(u128, u128) -> u128,
    ) -> Result<()> {
        let (al, ah) = self.vsrc(vex);
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let lo = f(al, bl);
        let hi = if vex.l { f(ah, bh) } else { 0 };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    fn vex_unary_lane(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        f: impl Fn(u128) -> u128,
    ) -> Result<()> {
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let lo = f(bl);
        let hi = if vex.l { f(bh) } else { 0 };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    fn vex_logic(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        f: impl Fn(u128, u128) -> u128,
    ) -> Result<()> {
        self.vex_lane_bin(ctx, mem, vex, reg, f)
    }

    fn vex_farith(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        f: impl Fn(f64, f64) -> f64,
    ) -> Result<()> {
        let scalar = vex.f2() || vex.f3();
        let dbl = vex.pd() || vex.f2();
        let (al, ah) = self.vsrc(vex);
        let n = if scalar { if dbl { 8 } else { 4 } } else { 16 };
        let (bl, bh) = if scalar {
            (self.vrm128(ctx, mem, n)?, 0)
        } else {
            self.vload_rm(ctx, mem, vex)?
        };
        if scalar {
            let lo = if dbl {
                (al & !sse::LOW64) | (f(f64::from_bits(al as u64), f64::from_bits(bl as u64)).to_bits() as u128)
            } else {
                (al & !sse::LOW32) | ((f(f32::from_bits(al as u32) as f64, f32::from_bits(bl as u32) as f64) as f32).to_bits() as u128)
            };
            self.state.set_xmm_zero_upper(reg, lo);
        } else {
            let lo = pfloat(al, bl, dbl, &f);
            let hi = if vex.l { pfloat(ah, bh, dbl, &f) } else { 0 };
            self.vdst(reg, vex.l, lo, hi);
        }
        Ok(())
    }

    fn vex_funary(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        f: impl Fn(f64) -> f64,
    ) -> Result<()> {
        let scalar = vex.f2() || vex.f3();
        let dbl = vex.pd() || vex.f2();
        if scalar {
            let n = if dbl { 8 } else { 4 };
            let b = self.vrm128(ctx, mem, n)?;
            let base = self.state.xmm(vex.vvvv);
            let lo = if dbl {
                (base & !sse::LOW64) | (f(f64::from_bits(b as u64)).to_bits() as u128)
            } else {
                (base & !sse::LOW32) | ((f(f32::from_bits(b as u32) as f64) as f32).to_bits() as u128)
            };
            self.state.set_xmm_zero_upper(reg, lo);
        } else {
            let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
            let lo = pfloat_un(bl, dbl, &f);
            let hi = if vex.l { pfloat_un(bh, dbl, &f) } else { 0 };
            self.vdst(reg, vex.l, lo, hi);
        }
        Ok(())
    }

    fn vex_movss_sd(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        store: bool,
    ) -> Result<()> {
        let n = if vex.f2() { 8 } else { 4 };
        let mask = if n == 8 { sse::LOW64 } else { sse::LOW32 };
        if store {
            match ctx.rm {
                Rm::Reg(_) => {
                    let merged = (self.state.xmm(vex.vvvv) & !mask) | (self.state.xmm(reg) & mask);
                    self.vstore128(ctx, mem, merged)?;
                }
                Rm::Mem { .. } => {
                    let v = self.state.xmm(reg) & mask;
                    self.vstore_low(ctx, mem, n, v)?;
                }
            }
        } else {
            match ctx.rm {
                Rm::Reg(i) => {
                    let merged = (self.state.xmm(vex.vvvv) & !mask) | (self.state.xmm(i) & mask);
                    self.state.set_xmm_zero_upper(reg, merged);
                }
                Rm::Mem { .. } => {
                    let v = self.vrm128(ctx, mem, n)? & mask;
                    self.state.set_xmm_zero_upper(reg, v);
                }
            }
        }
        Ok(())
    }

    fn vex_cmp(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let scalar = vex.f2() || vex.f3();
        let dbl = vex.pd() || vex.f2();
        let (al, ah) = self.vsrc(vex);
        let (bl, bh) = if scalar {
            (self.vrm128(ctx, mem, if dbl { 8 } else { 4 })?, 0)
        } else {
            self.vload_rm(ctx, mem, vex)?
        };
        let imm = ctx.u8(mem)?;
        if scalar {
            let base = al;
            let lo = if dbl {
                let r = cmp_pred(f64::from_bits(al as u64), f64::from_bits(bl as u64), imm);
                (base & !sse::LOW64) | (if r { sse::LOW64 } else { 0 })
            } else {
                let r = cmp_pred(f32::from_bits(al as u32) as f64, f32::from_bits(bl as u32) as f64, imm);
                (base & !sse::LOW32) | (if r { sse::LOW32 } else { 0 })
            };
            self.state.set_xmm_zero_upper(reg, lo);
        } else {
            let lo = pcmp_float(al, bl, dbl, imm);
            let hi = if vex.l { pcmp_float(ah, bh, dbl, imm) } else { 0 };
            self.vdst(reg, vex.l, lo, hi);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn vex_pmovx(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        src_sz: usize,
        dst_sz: usize,
        sign: bool,
    ) -> Result<()> {
        if vex.l {
            let src = self.vrm128(ctx, mem, 16)?;
            let per_lane = 16 / dst_sz;
            let lo = pmovx_from(src, 0, per_lane, src_sz, dst_sz, sign);
            let hi = pmovx_from(src, per_lane, per_lane, src_sz, dst_sz, sign);
            self.state.set_ymm(reg, lo, hi);
        } else {
            let n = (16 / dst_sz) * src_sz;
            let src = self.vrm128(ctx, mem, n)?;
            self.state.set_xmm_zero_upper(reg, sse::pmovx(src, src_sz, dst_sz, sign));
        }
        Ok(())
    }

    fn vex_broadcast(&mut self, ctx: &Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, esz: usize) -> Result<()> {
        let src = self.vrm128(ctx, mem, esz)?;
        let elem = src & sse::emask(esz);
        let mut lane = 0u128;
        let per = 16 / esz;
        for i in 0..per {
            lane |= elem << (i * esz * 8);
        }
        self.vdst(reg, vex.l, lane, if vex.l { lane } else { 0 });
        Ok(())
    }

    fn vex_ptest(&mut self, ctx: &Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let (al, ah) = (self.state.xmm(reg), self.state.ymm_hi(reg));
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let (zf, cf) = if vex.l {
            (((al & bl) | (ah & bh)) == 0, ((!al & bl) | (!ah & bh)) == 0)
        } else {
            ((al & bl) == 0, (!al & bl) == 0)
        };
        self.state.set_flag(flags::ZF, zf);
        self.state.set_flag(flags::CF, cf);
        self.state.set_flag(flags::OF, false);
        self.state.set_flag(flags::SF, false);
        self.state.set_flag(flags::AF, false);
        self.state.set_flag(flags::PF, false);
        Ok(())
    }

    fn vex_shift_imm(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let (esz, ext) = match op {
            0x71 => (2usize, ctx.reg & 7),
            0x72 => (4usize, ctx.reg & 7),
            _ => (8usize, ctx.reg & 7),
        };
        let (sl, sh) = self.vload_rm(ctx, mem, vex)?;
        let count = ctx.u8(mem)? as u64;
        let dst = vex.vvvv;
        let f: Box<dyn Fn(u128) -> u128> = match ext {
            2 => Box::new(move |v| sse::shift_r(v, esz, count, false)),
            4 => Box::new(move |v| sse::shift_r(v, esz, count, true)),
            6 => Box::new(move |v| sse::shift_l(v, esz, count)),
            _ => return Err(EmuError::Unsupported(format!("VEX shift-imm /{ext}"))),
        };
        let lo = f(sl);
        let hi = if vex.l { f(sh) } else { 0 };
        self.vdst(dst, vex.l, lo, hi);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn vex_shift_var(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        esz: usize,
        arith: bool,
        left: bool,
    ) -> Result<()> {
        let count = (self.vrm128(ctx, mem, 16)? & sse::LOW64) as u64;
        let (dl, dh) = self.vsrc(vex);
        let apply = |v: u128| if left { sse::shift_l(v, esz, count) } else { sse::shift_r(v, esz, count, arith) };
        let lo = apply(dl);
        let hi = if vex.l { apply(dh) } else { 0 };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn vex_var_shift(
        &mut self,
        ctx: &Ctx,
        mem: &mut dyn Memory,
        vex: &Vex,
        reg: u8,
        esz: usize,
        arith: bool,
        left: bool,
    ) -> Result<()> {
        let (dl, dh) = self.vsrc(vex);
        let (cl, ch) = self.vload_rm(ctx, mem, vex)?;
        let lo = var_shift_lane(dl, cl, esz, arith, left);
        let hi = if vex.l { var_shift_lane(dh, ch, esz, arith, left) } else { 0 };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    fn vex_blend_imm(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, esz: usize) -> Result<()> {
        let (al, ah) = self.vsrc(vex);
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let imm = ctx.u8(mem)?;
        let (lo, hi) = if vex.l && esz == 4 {
            (blend_imm_wide(al, bl, imm & 0x0F, esz), blend_imm_wide(ah, bh, imm >> 4, esz))
        } else {
            (sse::blend_imm(al, bl, imm, esz), if vex.l { sse::blend_imm(ah, bh, imm, esz) } else { 0 })
        };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    fn vex_round_packed(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, dbl: bool) -> Result<()> {
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let imm = ctx.u8(mem)?;
        let mode = self.round_mode(imm);
        let f = |v: u128| round_packed(v, dbl, mode);
        let lo = f(bl);
        let hi = if vex.l { f(bh) } else { 0 };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    fn vex_round_scalar(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, dbl: bool) -> Result<()> {
        let src = self.vrm128(ctx, mem, if dbl { 8 } else { 4 })?;
        let imm = ctx.u8(mem)?;
        let mode = self.round_mode(imm);
        let base = self.state.xmm(vex.vvvv);
        let lo = if dbl {
            (base & !sse::LOW64) | ((sse::round_f64(f64::from_bits(src as u64), mode)).to_bits() as u128)
        } else {
            (base & !sse::LOW32) | ((sse::round_f32(f32::from_bits(src as u32), mode)).to_bits() as u128)
        };
        self.state.set_xmm_zero_upper(reg, lo);
        Ok(())
    }

    fn vex_permq(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, _vex: &Vex, reg: u8) -> Result<()> {
        let (sl, sh) = self.vrm256(ctx, mem)?;
        let imm = ctx.u8(mem)?;
        let q = [sl as u64, (sl >> 64) as u64, sh as u64, (sh >> 64) as u64];
        let pick = |sh2: u8| q[((imm >> (sh2 * 2)) & 3) as usize] as u128;
        let lo = pick(0) | (pick(1) << 64);
        let hi = pick(2) | (pick(3) << 64);
        self.state.set_ymm(reg, lo, hi);
        Ok(())
    }

    fn vex_permpd(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        self.vex_permq(ctx, mem, vex, reg)
    }

    fn vex_permd(&mut self, ctx: &Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let (il, ih) = self.vsrc(vex);
        let (sl, sh) = self.vrm256(ctx, mem)?;
        let s = [dwords(sl), dwords(sh)];
        let all: [u32; 8] = [s[0][0], s[0][1], s[0][2], s[0][3], s[1][0], s[1][1], s[1][2], s[1][3]];
        let idx = [dwords(il), dwords(ih)];
        let mut out = [0u32; 8];
        for (i, o) in out.iter_mut().enumerate() {
            let sel = idx[i / 4][i % 4] & 7;
            *o = all[sel as usize];
        }
        self.state.set_ymm(reg, pack_dwords(&out[..4]), pack_dwords(&out[4..]));
        Ok(())
    }

    fn vex_permps(&mut self, ctx: &Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        self.vex_permd(ctx, mem, vex, reg)
    }

    fn vex_perm2i128(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let (al, ah) = self.vsrc(vex);
        let (bl, bh) = self.vrm256(ctx, mem)?;
        let imm = ctx.u8(mem)?;
        let lanes = [al, ah, bl, bh];
        let sel = |ctrl: u8| -> u128 {
            if ctrl & 0x8 != 0 {
                0
            } else {
                lanes[(ctrl & 3) as usize]
            }
        };
        let lo = sel(imm & 0x0F);
        let hi = sel(imm >> 4);
        self.state.set_ymm(reg, lo, hi);
        Ok(())
    }

    fn vex_pextr(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, esz: usize) -> Result<()> {
        let src = self.state.xmm(reg);
        let imm = self.imm_after_rm(ctx, mem)?;
        let per = 16 / esz;
        let lane = (imm as usize) % per;
        let bits = esz * 8;
        let val = ((src >> (lane * bits)) & sse::emask(esz)) as u64;
        match ctx.rm {
            Rm::Reg(_) => {
                let wsz = if esz >= 4 { esz as u8 } else { 4 };
                self.write_rm(ctx, mem, wsz, val)?;
            }
            Rm::Mem { .. } => self.write_rm(ctx, mem, esz as u8, val)?,
        }
        let _ = vex;
        Ok(())
    }

    fn vex_pinsr(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, esz: usize) -> Result<()> {
        let src = self.read_rm(ctx, &*mem, esz as u8)?;
        let imm = self.imm_after_rm(ctx, mem)?;
        let per = 16 / esz;
        let lane = (imm as usize) % per;
        let bits = esz * 8;
        let base = self.state.xmm(vex.vvvv);
        let cleared = base & !(sse::emask(esz) << (lane * bits));
        let ins = ((src as u128) & sse::emask(esz)) << (lane * bits);
        self.state.set_xmm_zero_upper(reg, cleared | ins);
        Ok(())
    }
}

fn sse_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() || a == b {
        b
    } else if a < b {
        a
    } else {
        b
    }
}

fn sse_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() || a == b {
        b
    } else if a > b {
        a
    } else {
        b
    }
}

fn pfloat(a: u128, b: u128, dbl: bool, f: &impl Fn(f64, f64) -> f64) -> u128 {
    let mut out = 0u128;
    if dbl {
        for l in 0..2 {
            let x = f64::from_bits((a >> (l * 64)) as u64);
            let y = f64::from_bits((b >> (l * 64)) as u64);
            out |= (f(x, y).to_bits() as u128) << (l * 64);
        }
    } else {
        for l in 0..4 {
            let x = f32::from_bits((a >> (l * 32)) as u32) as f64;
            let y = f32::from_bits((b >> (l * 32)) as u32) as f64;
            out |= ((f(x, y) as f32).to_bits() as u128) << (l * 32);
        }
    }
    out
}

fn pfloat_un(a: u128, dbl: bool, f: &impl Fn(f64) -> f64) -> u128 {
    let mut out = 0u128;
    if dbl {
        for l in 0..2 {
            let x = f64::from_bits((a >> (l * 64)) as u64);
            out |= (f(x).to_bits() as u128) << (l * 64);
        }
    } else {
        for l in 0..4 {
            let x = f32::from_bits((a >> (l * 32)) as u32) as f64;
            out |= ((f(x) as f32).to_bits() as u128) << (l * 32);
        }
    }
    out
}

fn cmp_pred(a: f64, b: f64, imm: u8) -> bool {
    match imm & 0x1F {
        0x00 => a == b,
        0x01 => a < b,
        0x02 => a <= b,
        0x03 => a.is_nan() || b.is_nan(),
        0x04 => a != b || a.is_nan() || b.is_nan(),
        0x05 => a >= b || a.is_nan() || b.is_nan(),
        0x06 => a > b || a.is_nan() || b.is_nan(),
        0x07 => !a.is_nan() && !b.is_nan(),
        0x08 => a == b,
        0x09 => a < b || a.is_nan() || b.is_nan(),
        0x0A => a <= b || a.is_nan() || b.is_nan(),
        0x0B => false,
        0x0C => a != b && !a.is_nan() && !b.is_nan(),
        0x0D => a >= b,
        0x0E => a > b,
        0x0F => true,
        v => cmp_pred(a, b, v & 0x07),
    }
}

pub(crate) fn pcmp_float(a: u128, b: u128, dbl: bool, imm: u8) -> u128 {
    let mut out = 0u128;
    if dbl {
        for l in 0..2 {
            let x = f64::from_bits((a >> (l * 64)) as u64);
            let y = f64::from_bits((b >> (l * 64)) as u64);
            if cmp_pred_full(x, y, imm) {
                out |= (u64::MAX as u128) << (l * 64);
            }
        }
    } else {
        for l in 0..4 {
            let x = f32::from_bits((a >> (l * 32)) as u32) as f64;
            let y = f32::from_bits((b >> (l * 32)) as u32) as f64;
            if cmp_pred_full(x, y, imm) {
                out |= (u32::MAX as u128) << (l * 32);
            }
        }
    }
    out
}

pub(crate) fn cmp_pred_full(a: f64, b: f64, imm: u8) -> bool {
    match imm & 0x1F {
        0x08 => a == b || a.is_nan() || b.is_nan(),
        _ => cmp_pred(a, b, imm),
    }
}

fn dwords(v: u128) -> [u32; 4] {
    [v as u32, (v >> 32) as u32, (v >> 64) as u32, (v >> 96) as u32]
}

fn pack_dwords(w: &[u32]) -> u128 {
    let mut v = 0u128;
    for (i, &d) in w.iter().enumerate() {
        v |= (d as u128) << (i * 32);
    }
    v
}

fn var_shift_lane(v: u128, counts: u128, esz: usize, arith: bool, left: bool) -> u128 {
    let bits = esz * 8;
    let mask = sse::emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = (v >> (i * bits)) & mask;
        let c = ((counts >> (i * bits)) & mask) as u64;
        let r = if c >= bits as u64 {
            if arith && !left {
                if (x >> (bits - 1)) & 1 != 0 { mask } else { 0 }
            } else {
                0
            }
        } else if left {
            (x << c) & mask
        } else if arith {
            let sx = sign_extend(x, bits);
            ((sx >> c) as u128) & mask
        } else {
            x >> c
        };
        out |= r << (i * bits);
    }
    out
}

fn sign_extend(x: u128, bits: usize) -> i128 {
    let shift = 128 - bits;
    ((x << shift) as i128) >> shift
}

fn blend_imm_wide(dst: u128, src: u128, sel4: u8, esz: usize) -> u128 {
    let bits = esz * 8;
    let mask = sse::emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let take_src = (sel4 >> i) & 1 != 0;
        let v = if take_src { (src >> (i * bits)) & mask } else { (dst >> (i * bits)) & mask };
        out |= v << (i * bits);
    }
    out
}

fn round_packed(v: u128, dbl: bool, mode: u8) -> u128 {
    let mut out = 0u128;
    if dbl {
        for l in 0..2 {
            let x = f64::from_bits((v >> (l * 64)) as u64);
            out |= (sse::round_f64(x, mode).to_bits() as u128) << (l * 64);
        }
    } else {
        for l in 0..4 {
            let x = f32::from_bits((v >> (l * 32)) as u32);
            out |= (sse::round_f32(x, mode).to_bits() as u128) << (l * 32);
        }
    }
    out
}

fn pmovx_from(src: u128, start: usize, count: usize, src_sz: usize, dst_sz: usize, sign: bool) -> u128 {
    let sbits = src_sz * 8;
    let dbits = dst_sz * 8;
    let smask = sse::emask(src_sz);
    let dmask = sse::emask(dst_sz);
    let mut out = 0u128;
    for i in 0..count {
        let e = (src >> ((start + i) * sbits)) & smask;
        let widened = if sign {
            (sign_extend(e, sbits) as u128) & dmask
        } else {
            e
        };
        out |= (widened & dmask) << (i * dbits);
    }
    out
}

fn f16_to_f32(h: u16) -> u32 {
    let sign = (h as u32 & 0x8000) << 16;
    let exp = (h >> 10) & 0x1F;
    let mant = (h & 0x3FF) as u32;
    match exp {
        0 => {
            if mant == 0 {
                sign
            } else {
                let mut m = mant;
                let mut e: i32 = -1;
                while m & 0x400 == 0 {
                    m <<= 1;
                    e -= 1;
                }
                m &= 0x3FF;
                let exp32 = (127 - 15 + 1 + e) as u32;
                sign | (exp32 << 23) | (m << 13)
            }
        }
        0x1F => {
            sign | 0x7F80_0000 | (mant << 13)
        }
        _ => {
            let exp32 = (exp as i32 - 15 + 127) as u32;
            sign | (exp32 << 23) | (mant << 13)
        }
    }
}

fn f32_to_f16(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let mant = bits & 0x007F_FFFF;

    if exp == 0xFF {
        return if mant != 0 {
            sign | 0x7E00
        } else {
            sign | 0x7C00
        };
    }
    let e = exp - 127 + 15;
    if e >= 0x1F {
        return sign | 0x7C00;
    }
    if e <= 0 {
        if e < -10 {
            return sign;
        }
        let m = mant | 0x0080_0000;
        let shift = 14 - e;
        let half_shifted = m >> shift;
        let remainder = m & ((1 << shift) - 1);
        let halfway = 1u32 << (shift - 1);
        let mut r = half_shifted as u16;
        if remainder > halfway || (remainder == halfway && (half_shifted & 1) != 0) {
            r += 1;
        }
        return sign | r;
    }
    let mut half_exp = e as u16;
    let round_bits = mant & 0x1FFF;
    let mut half_mant = (mant >> 13) as u16;
    let halfway = 0x1000u32;
    if round_bits > halfway || (round_bits == halfway && (half_mant & 1) != 0) {
        half_mant += 1;
        if half_mant == 0x400 {
            half_mant = 0;
            half_exp += 1;
            if half_exp >= 0x1F {
                return sign | 0x7C00;
            }
        }
    }
    sign | (half_exp << 10) | half_mant
}
