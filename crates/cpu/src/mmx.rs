use super::*;
use crate::sse;

pub(crate) fn is_mmx(op2: u8) -> bool {
    matches!(op2,
        0x6E | 0x6F | 0x7E | 0x7F |
        0x60..=0x6B |
        0x74 | 0x75 | 0x76 |
        0x70 |
        0x71 | 0x72 | 0x73 |
        0xD1 | 0xD2 | 0xD3 | 0xE1 | 0xE2 | 0xF1 | 0xF2 | 0xF3 |
        0xD5 | 0xE4 | 0xE5 | 0xF4 | 0xF5 |
        0xD4 | 0xFB |
        0xDB | 0xDF | 0xEB | 0xEF |
        0xFC..=0xFE | 0xF8..=0xFA |
        0xDC | 0xDD | 0xD8 | 0xD9 |
        0xEC | 0xED | 0xE8 | 0xE9 |
        0xDA | 0xDE | 0xE0 | 0xE3 | 0xF6 |
        0xD7
    )
}

impl Interpreter {
    fn mmx_rm(&self, ctx: &Ctx, mem: &dyn Memory) -> Result<u64> {
        match ctx.rm {
            Rm::Reg(i) => Ok(self.state.x87.mmx(i & 7)),
            Rm::Mem { .. } => mem.read_u64(ctx.rm_addr()),
        }
    }

    fn mmx_store_rm(&mut self, ctx: &Ctx, mem: &mut dyn Memory, v: u64) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.x87.set_mmx(i & 7, v);
                Ok(())
            }
            Rm::Mem { .. } => mem.write_u64(ctx.rm_addr(), v),
        }
    }

    pub(crate) fn exec_mmx(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op2: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        let reg = ctx.reg & 7;
        let lane = |a: u64, b: u64, f: &dyn Fn(u128, u128) -> u128| -> u64 { f(a as u128, b as u128) as u64 };

        match op2 {
            0x6E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.read_rm(ctx, &*mem, size)?;
                self.state.x87.set_mmx(reg, v);
            }
            0x7E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.state.x87.mmx(reg) & mask64(size);
                self.write_rm(ctx, mem, size, v)?;
            }
            0x6F => {
                let v = self.mmx_rm(ctx, mem)?;
                self.state.x87.set_mmx(reg, v);
            }
            0x7F => {
                let v = self.state.x87.mmx(reg);
                self.mmx_store_rm(ctx, mem, v)?;
            }

            0x60 | 0x61 | 0x62 | 0x68 | 0x69 | 0x6A => {
                let esz = 1usize << (op2 & 3);
                let high = op2 >= 0x68;
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, punpck64(a, b, esz, high));
            }
            0x63 | 0x6B | 0x67 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let out = match op2 {
                    0x63 => pack64(a, b, 2, true),
                    0x6B => pack64(a, b, 4, true),
                    _ => pack64(a, b, 2, false),
                };
                self.state.x87.set_mmx(reg, out);
            }

            0xFC..=0xFE => {
                let esz = 1usize << (op2 - 0xFC);
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::add_sub(x, y, esz, true)));
            }
            0xF8..=0xFA => {
                let esz = 1usize << (op2 - 0xF8);
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::add_sub(x, y, esz, false)));
            }
            0xD4 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, a.wrapping_add(b));
            }
            0xFB => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, a.wrapping_sub(b));
            }

            0xD8 | 0xD9 | 0xDC | 0xDD | 0xE8 | 0xE9 | 0xEC | 0xED => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let esz = if op2 & 1 == 0 { 1 } else { 2 };
                let add = matches!(op2, 0xDC | 0xDD | 0xEC | 0xED);
                let signed = matches!(op2, 0xE8 | 0xE9 | 0xEC | 0xED);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::add_sub_sat(x, y, esz, add, signed)));
            }

            0xDB => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, a & b);
            }
            0xDF => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, !a & b);
            }
            0xEB => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, a | b);
            }
            0xEF => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, a ^ b);
            }

            0x74 | 0x75 | 0x76 | 0x64 | 0x65 | 0x66 => {
                let esz = 1usize << (op2 & 3);
                let gt = op2 < 0x70;
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::pcmp(x, y, esz, gt)));
            }

            0xD5 | 0xE4 | 0xE5 | 0xF4 | 0xF5 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let out = match op2 {
                    0xD5 => lane(a, b, &sse::pmullw),
                    0xE5 => lane(a, b, &|x, y| sse::pmulh(x, y, true)),
                    0xE4 => lane(a, b, &|x, y| sse::pmulh(x, y, false)),
                    0xF4 => (a as u32 as u64).wrapping_mul(b as u32 as u64),
                    _ => lane(a, b, &sse::pmaddwd),
                };
                self.state.x87.set_mmx(reg, out);
            }

            0xDA => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::byte_minmax(x, y, false)));
            }
            0xDE => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::byte_minmax(x, y, true)));
            }
            0xE0 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::pavg(x, y, 1)));
            }
            0xE3 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::pavg(x, y, 2)));
            }
            0xF6 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, psadbw64(a, b));
            }

            0xD7 => {
                let src = match ctx.rm {
                    Rm::Reg(i) => self.state.x87.mmx(i & 7),
                    Rm::Mem { .. } => return Err(EmuError::Unsupported("pmovmskb mm,m".into())),
                };
                let mut m = 0u64;
                for i in 0..8 {
                    if (src >> (i * 8 + 7)) & 1 != 0 {
                        m |= 1 << i;
                    }
                }
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, m);
            }

            0x70 => {
                let src = self.mmx_rm(ctx, mem)?;
                let imm = ctx.u8(mem)?;
                let mut out = 0u64;
                for i in 0..4 {
                    let sel = (imm >> (i * 2)) & 3;
                    let w = (src >> (sel as u64 * 16)) & 0xFFFF;
                    out |= w << (i * 16);
                }
                self.state.x87.set_mmx(reg, out);
            }

            0x71..=0x73 => {
                let digit = ctx.reg & 7;
                let src = match ctx.rm {
                    Rm::Reg(i) => self.state.x87.mmx(i & 7),
                    Rm::Mem { .. } => return Err(EmuError::Unsupported("mmx shift m64,imm".into())),
                };
                let imm = ctx.u8(mem)? as u64;
                let esz = match op2 {
                    0x71 => 2,
                    0x72 => 4,
                    _ => 8,
                };
                let out = match (op2, digit) {
                    (_, 2) => mmx_shift(src, esz, imm, ShiftKind::Srl),
                    (0x71 | 0x72, 4) => mmx_shift(src, esz, imm, ShiftKind::Sra),
                    (_, 6) => mmx_shift(src, esz, imm, ShiftKind::Sll),
                    _ => return Err(EmuError::Unsupported(format!("mmx shift-group {op2:#x}/{digit}"))),
                };
                if let Rm::Reg(i) = ctx.rm {
                    self.state.x87.set_mmx(i & 7, out);
                }
            }

            0xD1 | 0xD2 | 0xD3 | 0xE1 | 0xE2 | 0xF1 | 0xF2 | 0xF3 => {
                let count = self.mmx_rm(ctx, mem)?;
                let dst = self.state.x87.mmx(reg);
                let out = match op2 {
                    0xD1 => mmx_shift(dst, 2, count, ShiftKind::Srl),
                    0xD2 => mmx_shift(dst, 4, count, ShiftKind::Srl),
                    0xD3 => mmx_shift(dst, 8, count, ShiftKind::Srl),
                    0xE1 => mmx_shift(dst, 2, count, ShiftKind::Sra),
                    0xE2 => mmx_shift(dst, 4, count, ShiftKind::Sra),
                    0xF1 => mmx_shift(dst, 2, count, ShiftKind::Sll),
                    0xF2 => mmx_shift(dst, 4, count, ShiftKind::Sll),
                    _ => mmx_shift(dst, 8, count, ShiftKind::Sll),
                };
                self.state.x87.set_mmx(reg, out);
            }

            other => return Err(EmuError::Unsupported(format!("mmx 0f {other:#04x}"))),
        }
        Ok(())
    }
}

#[inline]
fn mask64(size: u8) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn punpck64(a: u64, b: u64, esz: usize, high: bool) -> u64 {
    let bits = esz * 8;
    let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let half = (8 / esz) / 2;
    let base = if high { half } else { 0 };
    let mut out = 0u64;
    for i in 0..half {
        let d = (a >> ((base + i) * bits)) & mask;
        let s = (b >> ((base + i) * bits)) & mask;
        out |= d << ((2 * i) * bits);
        out |= s << ((2 * i + 1) * bits);
    }
    out
}

fn pack64(a: u64, b: u64, esz_in: usize, signed_out: bool) -> u64 {
    let bits_in = esz_in * 8;
    let bits_out = bits_in / 2;
    let in_mask: u64 = if bits_in >= 64 { u64::MAX } else { (1u64 << bits_in) - 1 };
    let n = 8 / esz_in;
    let mut out = 0u64;
    let mut place = 0;
    for src in [a, b] {
        for i in 0..n {
            let raw = (src >> (i * bits_in)) & in_mask;
            let shift = 64 - bits_in;
            let sv = ((raw << shift) as i64) >> shift;
            let clamped: u64 = if signed_out {
                let hi = (1i64 << (bits_out - 1)) - 1;
                let lo = -(1i64 << (bits_out - 1));
                (sv.clamp(lo, hi) as u64) & ((1u64 << bits_out) - 1)
            } else {
                let hi = (1i64 << bits_out) - 1;
                (sv.clamp(0, hi) as u64) & ((1u64 << bits_out) - 1)
            };
            out |= clamped << (place * bits_out);
            place += 1;
        }
    }
    out
}

fn psadbw64(a: u64, b: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..8 {
        let x = ((a >> (i * 8)) & 0xFF) as i32;
        let y = ((b >> (i * 8)) & 0xFF) as i32;
        sum += (x - y).unsigned_abs() as u64;
    }
    sum
}

enum ShiftKind {
    Sll,
    Srl,
    Sra,
}

fn mmx_shift(v: u64, esz: usize, count: u64, kind: ShiftKind) -> u64 {
    let bits = (esz * 8) as u64;
    let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let mut out = 0u64;
    let lanes = 8 / esz;
    for i in 0..lanes {
        let lane = (v >> (i as u64 * bits)) & mask;
        let r = match kind {
            ShiftKind::Sll => {
                if count >= bits {
                    0
                } else {
                    (lane << count) & mask
                }
            }
            ShiftKind::Srl => {
                if count >= bits {
                    0
                } else {
                    lane >> count
                }
            }
            ShiftKind::Sra => {
                let shift = 64 - bits;
                let s = ((lane << shift) as i64) >> shift;
                let c = count.min(bits - 1);
                ((s >> c) as u64) & mask
            }
        };
        out |= r << (i as u64 * bits);
    }
    out
}
