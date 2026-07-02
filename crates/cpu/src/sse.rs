//! SSE / SSE2 support.
//!
//! MSVC-compiled code leans on the XMM registers constantly — for struct
//! copies and zeroing (`movaps`/`movups`/`movdqa`/`xorps`), and for all
//! `float`/`double` arithmetic. This module implements a practical subset:
//! the full family of 128/64/32-bit moves, the bitwise logic ops, scalar
//! and packed add/sub/mul/div/min/max/sqrt, the `comiss`/`comisd` compares
//! that feed `Jcc`, and the common int↔float conversions.
//!
//! SSE opcodes are two-byte (`0F xx`) with a *mandatory prefix* — one of
//! `66`, `F3` or `F2` (or none) — that selects the variant. Those prefixes
//! were already captured during decode, so we just read them back here.

use super::*;
use crate::alu;
use exemu_core::cpu::flags;

/// The mandatory-prefix "flavor" of an SSE opcode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sse {
    /// no prefix — packed single (`...ps`)
    Ps,
    /// `66` — packed double (`...pd`) / integer
    Pd,
    /// `F3` — scalar single (`...ss`)
    Ss,
    /// `F2` — scalar double (`...sd`)
    Sd,
}

const LOW64: u128 = 0xFFFF_FFFF_FFFF_FFFF;
const LOW32: u128 = 0xFFFF_FFFF;

/// Whether a two-byte (`0F xx`) opcode should be routed to the SSE unit.
pub(crate) fn is_sse(op2: u8) -> bool {
    matches!(op2,
        0x10..=0x17 | 0x28..=0x2F | 0x51..=0x5F |
        0x6E | 0x6F | 0x7E | 0x7F | 0xD6 | 0xDB | 0xDF | 0xEB | 0xEF)
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

    // ---- raw XMM / memory access ----------------------------------------

    fn xmm(&self, i: u8) -> u128 {
        self.state.xmm[i as usize & 0xf]
    }
    fn set_xmm(&mut self, i: u8, v: u128) {
        self.state.xmm[i as usize & 0xf] = v;
    }

    /// Read the r/m operand as a 128-bit value. For a register operand the
    /// full XMM register is returned; for memory, `n` bytes zero-extended.
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

    /// Store the full 128-bit `val` to the r/m operand (register or 16 bytes
    /// of memory).
    fn sse_store_full(&mut self, ctx: &Ctx, mem: &mut dyn Memory, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.set_xmm(i, val);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()),
        }
    }

    /// Store the low `n` bytes of `val` to the r/m operand. For a register
    /// destination the upper bits are preserved (scalar-move semantics).
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

    // ---- the dispatch ----------------------------------------------------

    pub(crate) fn exec_sse(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op2: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        let kind = Self::sse_kind(ctx);
        let reg = ctx.reg;

        match op2 {
            // ---- MOVUPS/MOVSS/MOVSD/MOVUPD (load: reg <- r/m) ------------
            0x10 => match kind {
                Sse::Ps | Sse::Pd => {
                    let v = self.sse_rm(ctx, mem, 16)?;
                    self.set_xmm(reg, v);
                }
                Sse::Ss => self.mov_scalar_load(ctx, mem, reg, 4)?,
                Sse::Sd => self.mov_scalar_load(ctx, mem, reg, 8)?,
            },
            // ---- MOVUPS/MOVSS/MOVSD/MOVUPD (store: r/m <- reg) ----------
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

            // ---- MOVLPS / MOVHLPS (load low 64) -------------------------
            0x12 => {
                let v = match ctx.rm {
                    Rm::Reg(i) => (self.xmm(reg) & !LOW64) | (self.xmm(i) >> 64), // movhlps
                    Rm::Mem { .. } => (self.xmm(reg) & !LOW64) | (self.sse_rm(ctx, mem, 8)? & LOW64),
                };
                self.set_xmm(reg, v);
            }
            // ---- MOVLPS store (low 64 -> m64) ---------------------------
            0x13 => {
                let v = self.xmm(reg) & LOW64;
                self.sse_store_low(ctx, mem, 8, v)?;
            }
            // ---- MOVHPS / MOVLHPS (load high 64) ------------------------
            0x16 => {
                let v = match ctx.rm {
                    Rm::Reg(i) => (self.xmm(reg) & LOW64) | (self.xmm(i) << 64), // movlhps
                    Rm::Mem { .. } => (self.xmm(reg) & LOW64) | (self.sse_rm(ctx, mem, 8)? << 64),
                };
                self.set_xmm(reg, v);
            }
            // ---- MOVHPS store (high 64 -> m64) --------------------------
            0x17 => {
                let v = self.xmm(reg) >> 64;
                self.sse_store_low(ctx, mem, 8, v)?;
            }

            // ---- MOVAPS / MOVAPD (load / store, full 128) ---------------
            0x28 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }
            0x29 => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            // ---- CVTSI2SS / CVTSI2SD (int -> float) ---------------------
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
            // ---- CVTTSS2SI/CVTTSD2SI (truncate) and CVTSS2SI/CVTSD2SI --
            0x2C | 0x2D => {
                let truncate = op2 == 0x2C;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let val = self.sse_rm(ctx, mem, 8)?;
                let f = if kind == Sse::Sd {
                    f64::from_bits((val & LOW64) as u64)
                } else {
                    f32::from_bits((val & LOW32) as u32) as f64
                };
                let f = if truncate { f.trunc() } else { f.round() };
                let out = if size == 8 { f as i64 as u64 } else { f as i32 as u32 as u64 };
                self.write_reg_field(ctx, size, out);
            }
            // ---- UCOMISS/UCOMISD (2E) and COMISS/COMISD (2F) -----------
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

            // ---- SQRT (51) ----------------------------------------------
            0x51 => self.sse_unary(ctx, mem, kind, f64::sqrt)?,

            // ---- Bitwise logic: ANDPS/ANDNPS/ORPS/XORPS (54-57) --------
            0x54 => self.sse_logic(ctx, mem, |a, b| a & b)?,
            0x55 => self.sse_logic(ctx, mem, |a, b| !a & b)?,
            0x56 => self.sse_logic(ctx, mem, |a, b| a | b)?,
            0x57 => self.sse_logic(ctx, mem, |a, b| a ^ b)?,

            // ---- Arithmetic: ADD/MUL/SUB/MIN/DIV/MAX (58-5F) -----------
            0x58 => self.sse_arith(ctx, mem, kind, |a, b| a + b)?,
            0x59 => self.sse_arith(ctx, mem, kind, |a, b| a * b)?,
            0x5C => self.sse_arith(ctx, mem, kind, |a, b| a - b)?,
            0x5D => self.sse_arith(ctx, mem, kind, |a, b| a.min(b))?,
            0x5E => self.sse_arith(ctx, mem, kind, |a, b| a / b)?,
            0x5F => self.sse_arith(ctx, mem, kind, |a, b| a.max(b))?,

            // ---- CVTSD2SS / CVTSS2SD (5A) -------------------------------
            0x5A => match kind {
                Sse::Sd => {
                    // double -> single
                    let f = f64::from_bits((self.sse_rm(ctx, mem, 8)? & LOW64) as u64) as f32;
                    let bits = f.to_bits() as u128;
                    self.set_xmm(reg, (self.xmm(reg) & !LOW32) | bits);
                }
                Sse::Ss => {
                    // single -> double
                    let f = f32::from_bits((self.sse_rm(ctx, mem, 4)? & LOW32) as u32) as f64;
                    let bits = f.to_bits() as u128;
                    self.set_xmm(reg, (self.xmm(reg) & !LOW64) | bits);
                }
                _ => return unsupported(op2, ctx, "cvtps2pd/cvtpd2ps"),
            },

            // ---- MOVD/MOVQ xmm, r/m (66 0F 6E) --------------------------
            0x6E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let src = self.read_rm(ctx, &*mem, size)? as u128;
                self.set_xmm(reg, src); // zero-extends into the full register
            }
            // ---- MOVDQA / MOVDQU load (66 / F3  0F 6F) ------------------
            0x6F => {
                let v = self.sse_rm(ctx, mem, 16)?;
                self.set_xmm(reg, v);
            }
            // ---- MOVD/MOVQ r/m, xmm (66 0F 7E)  &  MOVQ xmm,xmm/m64 (F3) ­
            0x7E => match kind {
                Sse::Ss => {
                    // F3 0F 7E: movq xmm, xmm/m64 (zero upper)
                    let v = self.sse_rm(ctx, mem, 8)? & LOW64;
                    self.set_xmm(reg, v);
                }
                _ => {
                    // 66 0F 7E: movd/movq r/m, xmm
                    let size = if ctx.pfx.w() { 8 } else { 4 };
                    let v = self.xmm(reg) as u64;
                    self.write_rm(ctx, mem, size, v)?;
                }
            },
            // ---- MOVDQA / MOVDQU store (66 / F3  0F 7F) -----------------
            0x7F => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            // ---- MOVQ xmm/m64, xmm (66 0F D6) ---------------------------
            0xD6 => {
                let v = self.xmm(reg) & LOW64;
                match ctx.rm {
                    Rm::Reg(i) => self.set_xmm(i, v), // zeroes upper of dest reg
                    Rm::Mem { .. } => mem.write(ctx.rm_addr(), &v.to_le_bytes()[..8])?,
                }
            }

            // ---- Integer bitwise: PAND/PANDN/POR/PXOR -------------------
            0xDB => self.sse_logic(ctx, mem, |a, b| a & b)?,
            0xDF => self.sse_logic(ctx, mem, |a, b| !a & b)?,
            0xEB => self.sse_logic(ctx, mem, |a, b| a | b)?,
            0xEF => self.sse_logic(ctx, mem, |a, b| a ^ b)?,

            other => return unsupported(other, ctx, "sse"),
        }
        Ok(())
    }

    // ---- shared operation shapes ----------------------------------------

    /// `movss`/`movsd` load: a memory source zeroes the upper bits, a
    /// register source preserves them.
    fn mov_scalar_load(&mut self, ctx: &Ctx, mem: &mut dyn Memory, reg: u8, n: usize) -> Result<()> {
        let mask = low_mask(n);
        match ctx.rm {
            Rm::Reg(i) => {
                let v = self.xmm(i) & mask;
                self.set_xmm(reg, (self.xmm(reg) & !mask) | v);
            }
            Rm::Mem { .. } => {
                let v = self.sse_rm(ctx, mem, n)? & mask;
                self.set_xmm(reg, v); // upper bits cleared
            }
        }
        Ok(())
    }

    /// 128-bit bitwise logic: `dst = f(dst, src)`.
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

    /// Scalar or packed float arithmetic `dst = f(dst, src)`.
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

    /// Unary float op applied like `sse_arith` but with one operand (`src`).
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

    /// Set ZF/PF/CF from a scalar float compare, clearing OF/SF/AF, exactly
    /// as `comiss`/`comisd` do (unordered → ZF=PF=CF=1).
    fn set_compare_flags(&mut self, a: f64, b: f64) {
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

// ---- free helpers ----------------------------------------------------------

fn low_mask(n: usize) -> u128 {
    if n >= 16 {
        u128::MAX
    } else {
        (1u128 << (n * 8)) - 1
    }
}

fn f64_lane(v: u128, lane: u32) -> f64 {
    f64::from_bits((v >> (lane * 64)) as u64)
}

fn f32_lane(v: u128, lane: u32) -> f32 {
    f32::from_bits((v >> (lane * 32)) as u32)
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
