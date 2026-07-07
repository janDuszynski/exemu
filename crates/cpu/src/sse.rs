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
///
/// The `0x60..=0x76`, `0xC6` and `0xD0..=0xFE` ranges are the MMX/SSE2 integer
/// opcodes (pack/unpack, compares, shifts, packed add/sub, shuffles). They do
/// not overlap the two-byte opcodes handled directly in `exec.rs` (`0F A2`
/// CPUID, `0F C7` CMPXCHG8B, `0F C8..CF` BSWAP, the `Jcc`/`SETcc`/`CMOVcc`
/// blocks, etc.), so routing whole ranges here is safe; anything we do not yet
/// implement falls through to a clear "unsupported" error.
pub(crate) fn is_sse(op2: u8) -> bool {
    matches!(op2,
        0x10..=0x17 | 0x28..=0x2F | 0x50..=0x5F |
        0x60..=0x76 | 0x7E | 0x7F |
        0xC6 | 0xD0..=0xFE)
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
                let out = cvt_f_to_int(f, truncate, size);
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
            // ---- MOVMSKPS / MOVMSKPD (NP/66 0F 50 /r) ------------------
            // Sign bits of the packed floats → low bits of a GP register.
            0x50 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                let mask = match kind {
                    // 4 f32 lanes: sign bits at 31/63/95/127.
                    Sse::Ps => {
                        ((v >> 31) & 1) | ((v >> 62) & 2) | ((v >> 93) & 4) | ((v >> 124) & 8)
                    }
                    // 2 f64 lanes: sign bits at 63/127.
                    Sse::Pd => ((v >> 63) & 1) | ((v >> 126) & 2),
                    // F3/F2 0F 50 are not defined encodings.
                    _ => return unsupported(op2, ctx, "movmsk ss/sd"),
                } as u64;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, mask);
            }

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
            // MIN/MAX are `(a<b)?a:b` / `(a>b)?a:b`, NOT IEEE minNum/maxNum:
            // if either operand is NaN, or they are equal (incl. ±0), the
            // *source* (b) is returned. Rust's f64::min/max instead drop NaNs.
            0x5D => self.sse_arith(ctx, mem, kind, |a, b| if a < b { a } else { b })?,
            0x5E => self.sse_arith(ctx, mem, kind, |a, b| a / b)?,
            0x5F => self.sse_arith(ctx, mem, kind, |a, b| if a > b { a } else { b })?,

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

            // ---- MOVNTPS / MOVNTDQ store (non-temporal → plain store) ---
            0x2B | 0xE7 => {
                let v = self.xmm(reg);
                self.sse_store_full(ctx, mem, v)?;
            }

            // ---- PUNPCKL{BW,WD,DQ,QDQ} / PUNPCKH… (interleave) ----------
            // The CRT's SSE2 memset broadcasts a byte across a register with
            // these, so they are on the hot path into `main`.
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

            // ---- PCMPEQ{B,W,D} / PCMPGT{B,W,D} --------------------------
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

            // ---- PADD{B,W,D} / PADDQ / PSUB{B,W,D} / PSUBQ --------------
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

            // ---- PMINUB / PMAXUB (unsigned byte min/max) ----------------
            0xDA => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, byte_minmax(a, b, false));
            }
            0xDE => {
                let (a, b) = (self.xmm(reg), self.sse_rm(ctx, mem, 16)?);
                self.set_xmm(reg, byte_minmax(a, b, true));
            }

            // ---- PMOVMSKB: gather the 16 byte sign bits into a GP reg ---
            // The workhorse of SSE2 strlen/memchr/strcmp (pcmpeqb + pmovmskb).
            0xD7 => {
                let v = self.sse_rm(ctx, mem, 16)?;
                let mask = pmovmskb(v) as u64;
                let size = if ctx.pfx.w() { 8 } else { 4 };
                self.write_reg_field(ctx, size, mask);
            }

            // ---- PSHUFD / PSHUFLW / PSHUFHW (66/F2/F3 0F 70 ib) ---------
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

            // ---- SHUFPS / SHUFPD (0F C6 ib) -----------------------------
            0xC6 => {
                let src = self.sse_rm(ctx, mem, 16)?;
                let dst = self.xmm(reg);
                let imm = ctx.u8(mem)?;
                let out = if kind == Sse::Pd { shufpd(dst, src, imm) } else { shufps(dst, src, imm) };
                self.set_xmm(reg, out);
            }

            // ---- Shift by imm8 (groups 71/72/73) ------------------------
            // reg field is the /digit; r/m is the xmm register operand.
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
                    (_, 2) => shift_r(src, esz, imm, false),  // PSRLW/D/Q
                    (0x71 | 0x72, 4) => shift_r(src, esz, imm, true), // PSRAW/D
                    (_, 6) => shift_l(src, esz, imm),         // PSLLW/D/Q
                    // PSRLDQ (whole-register byte shift): >=16 clears it. Guard
                    // the count so we never `>> 128` (which Rust masks to `>> 0`).
                    (0x73, 3) => {
                        if imm >= 16 {
                            0
                        } else {
                            src >> (imm * 8)
                        }
                    } // PSRLDQ (bytes)
                    (0x73, 7) => {
                        if imm >= 16 {
                            0
                        } else {
                            src << (imm * 8)
                        }
                    } // PSLLDQ (bytes)
                    _ => return unsupported(op2, ctx, "psh-group"),
                };
                self.sse_store_full(ctx, mem, out)?;
            }

            // ---- Shift by xmm/m128 count (variable) ---------------------
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

/// Convert a float to a signed integer of `size` bytes with x86 CVT(T)*2SI
/// semantics: round per mode (truncate → toward zero, else round-to-nearest-
/// even, matching the default MXCSR mode), and yield the "integer indefinite"
/// value (0x8000…0) when the rounded result is out of range or the input is
/// NaN — where Rust's saturating `as` cast would instead clamp or return 0.
fn cvt_f_to_int(f: f64, truncate: bool, size: u8) -> u64 {
    let r = if truncate { f.trunc() } else { f.round_ties_even() };
    if size == 8 {
        // Valid i64 targets satisfy -2^63 <= r < 2^63 (both bounds exact f64).
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

fn f64_lane(v: u128, lane: u32) -> f64 {
    f64::from_bits((v >> (lane * 64)) as u64)
}

fn f32_lane(v: u128, lane: u32) -> f32 {
    f32::from_bits((v >> (lane * 32)) as u32)
}

// ---- packed-integer element helpers ----------------------------------------

/// Element mask for an `esz`-byte lane (`esz` ∈ {1,2,4,8}).
fn emask(esz: usize) -> u128 {
    let bits = esz * 8;
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// Interleave `esz`-byte elements of `a` (dst) and `b` (src), taking the low
/// or high half — PUNPCKL*/PUNPCKH*.
fn punpck(a: u128, b: u128, esz: usize, high: bool) -> u128 {
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

/// Per-element compare: equality, or signed greater-than. Matching lanes become
/// all-ones, others zero (PCMPEQ*/PCMPGT*).
fn pcmp(a: u128, b: u128, esz: usize, gt: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let sign = 1u128 << (bits - 1);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = (a >> (i * bits)) & mask;
        let y = (b >> (i * bits)) & mask;
        let hit = if gt {
            // Signed compare: flip the sign bit so an unsigned compare orders
            // the two's-complement values correctly.
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

/// Per-element wrapping add (`sub=false`) or subtract (PADD*/PSUB*).
fn add_sub(a: u128, b: u128, esz: usize, add: bool) -> u128 {
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

/// Per-byte unsigned min (`max=false`) or max — PMINUB/PMAXUB.
fn byte_minmax(a: u128, b: u128, max: bool) -> u128 {
    let mut out = 0u128;
    for i in 0..16 {
        let x = ((a >> (i * 8)) & 0xFF) as u8;
        let y = ((b >> (i * 8)) & 0xFF) as u8;
        let r = if max { x.max(y) } else { x.min(y) } as u128;
        out |= r << (i * 8);
    }
    out
}

/// The top bit of each of the 16 bytes, packed into a 16-bit mask — PMOVMSKB.
fn pmovmskb(v: u128) -> u32 {
    let mut m = 0u32;
    for i in 0..16 {
        if (v >> (i * 8 + 7)) & 1 == 1 {
            m |= 1 << i;
        }
    }
    m
}

/// Per-element right shift, logical (`arith=false`) or arithmetic — PSRL*/PSRA*.
fn shift_r(v: u128, esz: usize, count: u64, arith: bool) -> u128 {
    let bits = esz * 8;
    let mask = emask(esz);
    let sign = 1u128 << (bits - 1);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let e = (v >> (i * bits)) & mask;
        let r = if arith {
            // Sign-extend the lane to i128, arithmetic-shift, remask.
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

/// Per-element logical left shift — PSLL*.
fn shift_l(v: u128, esz: usize, count: u64) -> u128 {
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

/// Select four dwords per `imm` from a single source — PSHUFD.
fn pshufd(src: u128, imm: u8) -> u128 {
    let mut out = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let dw = (src >> (sel as u32 * 32)) & LOW32;
        out |= dw << (i * 32);
    }
    out
}

/// Shuffle the low four words per `imm`, copying the high qword — PSHUFLW.
fn pshuflw(src: u128, imm: u8) -> u128 {
    let mut low = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let w = (src >> (sel as u32 * 16)) & 0xFFFF;
        low |= w << (i * 16);
    }
    (src & !LOW64) | (low & LOW64)
}

/// Shuffle the high four words per `imm`, copying the low qword — PSHUFHW.
fn pshufhw(src: u128, imm: u8) -> u128 {
    let hi = src >> 64;
    let mut out = 0u128;
    for i in 0..4 {
        let sel = (imm >> (i * 2)) & 3;
        let w = (hi >> (sel as u32 * 16)) & 0xFFFF;
        out |= w << (i * 16);
    }
    (src & LOW64) | (out << 64)
}

/// SHUFPS: low two dwords from `dst`, high two from `src`, per `imm`.
fn shufps(dst: u128, src: u128, imm: u8) -> u128 {
    let dw = |v: u128, i: u8| (v >> (i as u32 * 32)) & LOW32;
    let mut out = 0u128;
    out |= dw(dst, imm & 3);
    out |= dw(dst, (imm >> 2) & 3) << 32;
    out |= dw(src, (imm >> 4) & 3) << 64;
    out |= dw(src, (imm >> 6) & 3) << 96;
    out
}

/// SHUFPD: low qword from `dst`, high qword from `src`, each per one `imm` bit.
fn shufpd(dst: u128, src: u128, imm: u8) -> u128 {
    let lo = if imm & 1 == 0 { dst & LOW64 } else { (dst >> 64) & LOW64 };
    let hi = if imm & 2 == 0 { src & LOW64 } else { (src >> 64) & LOW64 };
    lo | (hi << 64)
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
