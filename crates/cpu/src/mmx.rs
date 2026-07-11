//! Bare-form (64-bit) MMX instructions.
//!
//! MMX registers `MM0..MM7` are architecturally **aliased onto the low 64 bits
//! of the x87 physical data registers** `st[0..8]` — *not* TOP-relative, but by
//! physical index (Intel SDM Vol. 1 §9.2). Writing an MMX register therefore:
//!   * stores the 64-bit result in the mantissa of the aliased x87 register,
//!   * sets bits 64:79 (the exponent+sign) to all 1s, and
//!   * marks that register **valid** in the x87 tag word.
//!
//! `EMMS` (`0F 77`) marks every register empty again (tag word `0xFFFF`). All of
//! this lives on [`exemu_core::X87`] via `mmx`/`set_mmx`/`emms`.
//!
//! These are the *bare* (no mandatory prefix) encodings that old media codecs
//! emit. The `66`-prefixed forms of the same opcodes are the SSE2 128-bit XMM
//! instructions and are handled by `sse.rs`; the `F3`/`F2` forms belong to SSE
//! as well. So this module is reached only for the no-prefix opcode space.
//!
//! Per-lane arithmetic reuses the lane-generic helpers in `sse.rs` by placing
//! the 64-bit operands in the low half of a `u128` (the upper 64 stay zero) and
//! taking the low 64 of the result — those helpers are lane-independent, so this
//! is exact. The width-sensitive ops (unpack/pack/shuffle/PSADBW) have dedicated
//! 64-bit implementations here. Semantics: Intel SDM Vol. 2 only.

use super::*;
use crate::sse;

/// The set of two-byte opcodes that, **without** a mandatory 66/F3/F2 prefix,
/// are MMX (64-bit) instructions rather than SSE. `execute_one` routes these to
/// [`Interpreter::exec_mmx`] before the SSE unit gets them.
pub(crate) fn is_mmx(op2: u8) -> bool {
    matches!(op2,
        0x6E | 0x6F | 0x7E | 0x7F |            // MOVD / MOVQ
        0x60..=0x6B |                          // PUNPCKL*/PACK*/PCMPGT (no 0x6C/D — SSE2-only PUNPCKxQDQ)
        0x74 | 0x75 | 0x76 |                   // PCMPEQ B/W/D
        0x70 |                                 // PSHUFW (imm8)
        0x71 | 0x72 | 0x73 |                   // shift-by-imm groups
        0xD1 | 0xD2 | 0xD3 | 0xE1 | 0xE2 | 0xF1 | 0xF2 | 0xF3 | // shift-by-mm
        0xD5 | 0xE4 | 0xE5 | 0xF4 | 0xF5 |     // PMULLW/HUW/HW/UDQ/MADDWD
        0xD4 | 0xFB |                          // PADDQ / PSUBQ
        0xDB | 0xDF | 0xEB | 0xEF |            // PAND/PANDN/POR/PXOR
        0xFC..=0xFE | 0xF8..=0xFA |            // PADD/PSUB B/W/D
        0xDC | 0xDD | 0xD8 | 0xD9 |            // saturating PADDUS/PSUBUS B/W
        0xEC | 0xED | 0xE8 | 0xE9 |            // saturating PADDS/PSUBS B/W
        0xDA | 0xDE | 0xE0 | 0xE3 | 0xF6 |     // PMINUB/PMAXUB/PAVGB/W/PSADBW
        0xD7                                   // PMOVMSKB (to GP reg)
    )
}

impl Interpreter {
    /// Read the MMX r/m operand as a 64-bit value (register = an MMX register,
    /// memory = 8 bytes).
    fn mmx_rm(&self, ctx: &Ctx, mem: &dyn Memory) -> Result<u64> {
        match ctx.rm {
            Rm::Reg(i) => Ok(self.state.x87.mmx(i & 7)),
            Rm::Mem { .. } => mem.read_u64(ctx.rm_addr()),
        }
    }

    /// Store a 64-bit value into the MMX r/m operand (register = MMX write with
    /// x87 aliasing side effects, memory = 8 bytes).
    fn mmx_store_rm(&mut self, ctx: &Ctx, mem: &mut dyn Memory, v: u64) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.x87.set_mmx(i & 7, v);
                Ok(())
            }
            Rm::Mem { .. } => mem.write_u64(ctx.rm_addr(), v),
        }
    }

    /// Dispatch a bare-form MMX two-byte opcode. `reg` is the destination MMX
    /// register (ModRM.reg, low 3 bits — MMX ignores REX.R/B). Called from
    /// `exec_0f` when [`is_mmx`] matched and no mandatory prefix is present.
    pub(crate) fn exec_mmx(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, op2: u8) -> Result<()> {
        self.read_modrm(ctx, mem)?;
        // MMX register numbers are 0..8; REX.R/B do not extend them.
        let reg = ctx.reg & 7;
        // Helper: apply a lane-generic `u128` op on the low 64 bits.
        let lane = |a: u64, b: u64, f: &dyn Fn(u128, u128) -> u128| -> u64 { f(a as u128, b as u128) as u64 };

        match op2 {
            // ---- MOVD mm, r/m32  (also MOVQ mm, r/m64 with REX.W) ----------
            0x6E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.read_rm(ctx, &*mem, size)?;
                self.state.x87.set_mmx(reg, v);
            }
            // ---- MOVD r/m32, mm  /  MOVQ r/m64, mm (REX.W) -----------------
            0x7E => {
                let size = if ctx.pfx.w() { 8 } else { 4 };
                let v = self.state.x87.mmx(reg) & mask64(size);
                self.write_rm(ctx, mem, size, v)?;
            }
            // ---- MOVQ mm, mm/m64 (load) -----------------------------------
            0x6F => {
                let v = self.mmx_rm(ctx, mem)?;
                self.state.x87.set_mmx(reg, v);
            }
            // ---- MOVQ mm/m64, mm (store) ----------------------------------
            0x7F => {
                let v = self.state.x87.mmx(reg);
                self.mmx_store_rm(ctx, mem, v)?;
            }

            // ---- PUNPCKL/H BW/WD/DQ (60..62, 68..6A) ----------------------
            0x60 | 0x61 | 0x62 | 0x68 | 0x69 | 0x6A => {
                let esz = 1usize << (op2 & 3); // 60->1(byte) 61->2 62->4
                let high = op2 >= 0x68;
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, punpck64(a, b, esz, high));
            }
            // ---- PACKSSWB/PACKSSDW/PACKUSWB (63/6B/67) --------------------
            0x63 | 0x6B | 0x67 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let out = match op2 {
                    0x63 => pack64(a, b, 2, true),  // PACKSSWB
                    0x6B => pack64(a, b, 4, true),  // PACKSSDW
                    _ => pack64(a, b, 2, false),    // PACKUSWB
                };
                self.state.x87.set_mmx(reg, out);
            }

            // ---- PADD/PSUB B/W/D (FC..FE, F8..FA) + PADDQ/PSUBQ (D4/FB) ---
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

            // ---- saturating PADDS/US, PSUBS/US B/W -----------------------
            0xD8 | 0xD9 | 0xDC | 0xDD | 0xE8 | 0xE9 | 0xEC | 0xED => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let esz = if op2 & 1 == 0 { 1 } else { 2 };
                let add = matches!(op2, 0xDC | 0xDD | 0xEC | 0xED);
                let signed = matches!(op2, 0xE8 | 0xE9 | 0xEC | 0xED);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::add_sub_sat(x, y, esz, add, signed)));
            }

            // ---- logic PAND/PANDN/POR/PXOR (DB/DF/EB/EF) ------------------
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

            // ---- PCMPEQ B/W/D (74/75/76), PCMPGT B/W/D (64/65/66) --------
            0x74 | 0x75 | 0x76 | 0x64 | 0x65 | 0x66 => {
                let esz = 1usize << (op2 & 3);
                let gt = op2 < 0x70;
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                self.state.x87.set_mmx(reg, lane(a, b, &|x, y| sse::pcmp(x, y, esz, gt)));
            }

            // ---- PMULLW/PMULHUW/PMULHW/PMULUDQ/PMADDWD (D5/E4/E5/F4/F5) --
            0xD5 | 0xE4 | 0xE5 | 0xF4 | 0xF5 => {
                let (a, b) = (self.state.x87.mmx(reg), self.mmx_rm(ctx, mem)?);
                let out = match op2 {
                    0xD5 => lane(a, b, &sse::pmullw),
                    0xE5 => lane(a, b, &|x, y| sse::pmulh(x, y, true)),
                    0xE4 => lane(a, b, &|x, y| sse::pmulh(x, y, false)),
                    0xF4 => (a as u32 as u64).wrapping_mul(b as u32 as u64), // PMULUDQ: one dword lane
                    _ => lane(a, b, &sse::pmaddwd),
                };
                self.state.x87.set_mmx(reg, out);
            }

            // ---- PMINUB/PMAXUB (DA/DE), PAVGB/W (E0/E3), PSADBW (F6) ------
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

            // ---- PMOVMSKB mm -> GP reg (D7) -------------------------------
            0xD7 => {
                // Register-only source (no memory form).
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

            // ---- PSHUFW mm, mm/m64, imm8 (70) ----------------------------
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

            // ---- shift by imm8 (groups 71/72/73) -------------------------
            0x71..=0x73 => {
                let digit = ctx.reg & 7;
                // The r/m must be an MMX register here (mod=11); read it, then imm8.
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
                // The r/m register (== the destination for these forms) is written.
                if let Rm::Reg(i) = ctx.rm {
                    self.state.x87.set_mmx(i & 7, out);
                }
            }

            // ---- shift by mm/m64 count (D1..D3, E1/E2, F1..F3) -----------
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

/// 64-bit MMX unpack (interleave low/high 32 bits by element size).
fn punpck64(a: u64, b: u64, esz: usize, high: bool) -> u64 {
    let bits = esz * 8;
    let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let half = (8 / esz) / 2; // number of elements taken from each source
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

/// 64-bit MMX pack: signed/unsigned-saturate `esz_in`-byte lanes of `a` (low
/// half) then `b` (high half) into half-width lanes.
fn pack64(a: u64, b: u64, esz_in: usize, signed_out: bool) -> u64 {
    let bits_in = esz_in * 8;
    let bits_out = bits_in / 2;
    let in_mask: u64 = if bits_in >= 64 { u64::MAX } else { (1u64 << bits_in) - 1 };
    let n = 8 / esz_in; // lanes per source
    let mut out = 0u64;
    let mut place = 0;
    for src in [a, b] {
        for i in 0..n {
            let raw = (src >> (i * bits_in)) & in_mask;
            // Sign-extend the input lane.
            let shift = 64 - bits_in;
            let sv = ((raw << shift) as i64) >> shift;
            let clamped: u64 = if signed_out {
                let hi = (1i64 << (bits_out - 1)) - 1;
                let lo = -(1i64 << (bits_out - 1));
                (sv.clamp(lo, hi) as u64) & ((1u64 << bits_out) - 1)
            } else {
                // PACKUSWB: signed source clamped to [0, 0xFF].
                let hi = (1i64 << bits_out) - 1;
                (sv.clamp(0, hi) as u64) & ((1u64 << bits_out) - 1)
            };
            out |= clamped << (place * bits_out);
            place += 1;
        }
    }
    out
}

/// 64-bit PSADBW: |a_byte - b_byte| summed across all 8 bytes into the low word.
fn psadbw64(a: u64, b: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..8 {
        let x = ((a >> (i * 8)) & 0xFF) as i32;
        let y = ((b >> (i * 8)) & 0xFF) as i32;
        sum += (x - y).unsigned_abs() as u64;
    }
    sum // result in the low word, rest zero
}

enum ShiftKind {
    Sll,
    Srl,
    Sra,
}

/// Per-element MMX shift. A count `>=` the element width clears (logical) or
/// fills with the sign (arithmetic), matching x86 packed-shift semantics.
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
