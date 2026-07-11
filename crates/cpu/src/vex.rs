//! AVX / AVX2 support via the VEX prefix (`0xC5` two-byte, `0xC4` three-byte).
//!
//! The VEX prefix re-encodes the SSE map with:
//!   * an inverted R/X/B (register-extension) field, so `xmm8..15` and 32-bit
//!     mode both fall out naturally,
//!   * a non-destructive third source register `vvvv` (inverted), turning the
//!     two-operand SSE `dst op= src` into `dst = vvvv op src`,
//!   * a vector-length bit `L` (0 = 128-bit `xmm`, 1 = 256-bit `ymm`),
//!   * a compressed mandatory prefix `pp` (0/66/F3/F2) and opcode-map selector
//!     `mmmmm` (1 = `0F`, 2 = `0F38`, 3 = `0F3A`).
//!
//! **The zero-upper rule.** Every VEX-encoded instruction with a 128-bit
//! destination *zeroes* the upper 128 bits of the target `ymm` register, whereas
//! the legacy (non-VEX) SSE form *preserves* them. That asymmetry is the single
//! biggest correctness trap in this decoder, so all 128-bit destination writes go
//! through [`CpuState::set_xmm_zero_upper`] and all 256-bit writes through
//! [`CpuState::set_ymm`]; the legacy SSE unit keeps using the preserve path.
//!
//! Provenance: Intel SDM Vol. 2 (VEX encoding, §2.3) and the per-instruction
//! reference pages. The differential oracle (`crates/oracle`, VEX category)
//! verifies every op here against a black-box reference, full 256-bit lanes.

use super::*;
use crate::sse;
use exemu_core::cpu::flags;

/// A decoded VEX prefix.
#[derive(Clone, Copy)]
pub(crate) struct Vex {
    /// REX-equivalent bits (already de-inverted): R/X/B extend ModRM.reg,
    /// SIB.index, ModRM.rm/base respectively; W is the operand-size/opcode bit.
    r: u8,
    x: u8,
    b: u8,
    w: bool,
    /// The non-destructive source register (already de-inverted, 0..=15).
    vvvv: u8,
    /// Vector length: false = 128-bit, true = 256-bit.
    l: bool,
    /// Compressed mandatory prefix: 0 = none, 1 = 66, 2 = F3, 3 = F2.
    pp: u8,
    /// Opcode map: 1 = 0F, 2 = 0F38, 3 = 0F3A.
    mmmmm: u8,
}

impl Vex {
    /// The SSE "flavor" implied by `pp`, reusing the legacy naming.
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
    /// Entry point from `execute_one` for a `0xC4`/`0xC5` byte. In 32-bit mode
    /// these bytes are `LES`/`LDS`; the caller only routes here when the byte
    /// that follows has ModRM.mod == 11 (a register form), matching how a real
    /// CPU disambiguates VEX from LES/LDS. `cur` points just past the `0xC4`/
    /// `0xC5` byte.
    pub(crate) fn exec_vex(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, two_byte: bool) -> Result<()> {
        let vex = self.decode_vex(ctx, mem, two_byte)?;
        let op = ctx.u8_at_op;
        // VZEROUPPER / VZEROALL (VEX.128/256 0F 77) have NO ModRM byte.
        if vex.mmmmm == 1 && op == 0x77 {
            if vex.l {
                // VZEROALL: zero the whole YMM register file.
                self.state.xmm = [0u128; 16];
                self.state.ymm_hi = [0u128; 16];
            } else {
                // VZEROUPPER: zero only the upper 128 bits of every YMM register.
                self.state.ymm_hi = [0u128; 16];
            }
            return Ok(());
        }
        // Read ModRM with the VEX-supplied R/X/B in place of REX.
        self.read_modrm_vex(ctx, mem, &vex)?;
        match vex.mmmmm {
            1 => self.vex_0f(ctx, mem, &vex, op),
            2 => self.vex_0f38(ctx, mem, &vex, op),
            3 => self.vex_0f3a(ctx, mem, &vex, op),
            _ => Err(EmuError::Unsupported(format!("VEX map {} op {op:#04x}", vex.mmmmm))),
        }
    }

    /// Consume the VEX payload byte(s) and the opcode. Stores the opcode in
    /// `ctx.u8_at_op` and leaves `ctx.cur` pointing at the ModRM byte.
    fn decode_vex(&self, ctx: &mut Ctx, mem: &dyn Memory, two_byte: bool) -> Result<Vex> {
        let vex = if two_byte {
            // 0xC5: [R vvvv L pp]. Implied W=0, mmmmm=1 (0F), X=B=0.
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
            // 0xC4: [R X B mmmmm][W vvvv L pp].
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
        // In 32-bit mode the R/X/B/vvvv high bits still decode but there are only
        // 8 architectural registers; masking keeps register indices in range.
        let mut vex = vex;
        if ctx.bits == Bits::B32 {
            vex.r = 0;
            vex.x = 0;
            vex.b = 0;
            vex.vvvv &= 7;
        }
        // Read the opcode byte and stash it.
        ctx.u8_at_op = ctx.u8(mem)?;
        Ok(vex)
    }

    /// ModRM read using the VEX R/X/B fields as the register-extension source
    /// (mirrors `read_modrm`, which uses REX). Shares the memory-operand math.
    fn read_modrm_vex(&self, ctx: &mut Ctx, mem: &dyn Memory, vex: &Vex) -> Result<()> {
        // Splice the VEX R/X/B into the prefix so the shared `read_modrm` path
        // resolves the operand identically to a REX-prefixed instruction.
        ctx.pfx.rex = 0x40 | ((vex.w as u8) << 3) | (vex.r << 2) | (vex.x << 1) | vex.b;
        ctx.pfx.has_rex = ctx.bits == Bits::B64;
        self.read_modrm(ctx, mem)
    }

    // ---- operand access --------------------------------------------------

    /// Read the r/m operand as a 128-bit value (low lane of a `ymm`, or `n`
    /// bytes from memory zero-extended).
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

    /// Read the r/m operand as a full 256-bit value `(low, high)`.
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

    /// Store a 128-bit destination: register (zero-upper) or 16 bytes of memory.
    fn vstore128(&mut self, ctx: &Ctx, mem: &mut dyn Memory, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.state.set_xmm_zero_upper(i, val);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()),
        }
    }

    /// Store a 256-bit destination: register or 32 bytes of memory.
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

    /// Store the low `n` bytes of `val` to the r/m operand (scalar VMOV store).
    fn vstore_low(&mut self, ctx: &Ctx, mem: &mut dyn Memory, n: usize, val: u128) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                // A VEX scalar store to a register zeroes the upper lanes above
                // the written bytes (128-bit dst) and the whole upper 128.
                let mask = if n >= 16 { u128::MAX } else { (1u128 << (n * 8)) - 1 };
                self.state.set_xmm_zero_upper(i, val & mask);
                Ok(())
            }
            Rm::Mem { .. } => mem.write(ctx.rm_addr(), &val.to_le_bytes()[..n]),
        }
    }

    /// Write a full 256/128-bit result to the ModRM.reg destination, applying
    /// the length-dependent zero-upper rule.
    #[inline]
    fn vdst(&mut self, reg: u8, l: bool, lo: u128, hi: u128) {
        if l {
            self.state.set_ymm(reg, lo, hi);
        } else {
            self.state.set_xmm_zero_upper(reg, lo);
        }
    }

    /// The `vvvv` source register's low/high halves.
    #[inline]
    fn vsrc(&self, vex: &Vex) -> (u128, u128) {
        (self.state.xmm(vex.vvvv), self.state.ymm_hi(vex.vvvv))
    }

    // ---- 0F map ----------------------------------------------------------

    fn vex_0f(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            // ---- VMOVUPS/VMOVUPD/VMOVAPS/VMOVAPD (aligned/unaligned load) ---
            0x10 | 0x28 => {
                if vex.f3() || vex.f2() {
                    // VMOVSS / VMOVSD.
                    return self.vex_movss_sd(ctx, mem, vex, reg, /*store=*/ false);
                }
                let (lo, hi) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, lo, hi);
            }
            // ---- VMOVUPS/VMOVUPD/VMOVAPS/VMOVAPD (store) --------------------
            0x11 | 0x29 => {
                if vex.f3() || vex.f2() {
                    return self.vex_movss_sd(ctx, mem, vex, reg, /*store=*/ true);
                }
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                if vex.l {
                    self.vstore256(ctx, mem, lo, hi)?;
                } else {
                    self.vstore128(ctx, mem, lo)?;
                }
            }

            // ---- VMOVLPS/VMOVHLPS (0x12), VMOVHPS/VMOVLHPS (0x16) ----------
            0x12 => {
                let dst = self.state.xmm(vex.vvvv);
                let lo = match ctx.rm {
                    Rm::Reg(i) => (dst & !sse::LOW64) | (self.state.xmm(i) >> 64), // VMOVHLPS
                    Rm::Mem { .. } => (dst & !sse::LOW64) | (self.vrm128(ctx, mem, 8)? & sse::LOW64), // VMOVLPS
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
                    Rm::Reg(i) => (dst & sse::LOW64) | (self.state.xmm(i) << 64), // VMOVLHPS
                    Rm::Mem { .. } => (dst & sse::LOW64) | (self.vrm128(ctx, mem, 8)? << 64), // VMOVHPS
                };
                self.state.set_xmm_zero_upper(reg, lo);
            }
            0x17 => {
                let v = self.state.xmm(reg) >> 64;
                self.vstore_low(ctx, mem, 8, v)?;
            }

            // ---- VMOVDDUP / VMOVSLDUP / VMOVSHDUP --------------------------
            // (F2 0F 12 / F3 0F 12 / F3 0F 16) — kept minimal; only the
            // common F2 VMOVDDUP is emitted by CRTs. Fall through otherwise.

            // ---- VMOVDQA / VMOVDQU (load) ---------------------------------
            0x6F => {
                let (lo, hi) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, lo, hi);
            }
            // ---- VMOVDQA / VMOVDQU (store) --------------------------------
            0x7F => {
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                if vex.l {
                    self.vstore256(ctx, mem, lo, hi)?;
                } else {
                    self.vstore128(ctx, mem, lo)?;
                }
            }

            // ---- VMOVD / VMOVQ (66 0F 6E: GP->xmm) ------------------------
            0x6E => {
                let size = if vex.w { 8 } else { 4 };
                let v = self.read_rm(ctx, &*mem, size)? as u128 & sse::low_mask(size as usize);
                self.state.set_xmm_zero_upper(reg, v);
            }
            // ---- VMOVD / VMOVQ (66 0F 7E: xmm->GP)  or F3 0F 7E VMOVQ xmm<-xmm
            0x7E => {
                if vex.f3() {
                    // VMOVQ xmm, xmm/m64: low 64 bits, zero the rest.
                    let v = self.vrm128(ctx, mem, 8)? & sse::LOW64;
                    self.state.set_xmm_zero_upper(reg, v);
                } else {
                    let size = if vex.w { 8 } else { 4 };
                    let v = self.state.xmm(reg) & sse::low_mask(size as usize);
                    self.write_rm(ctx, mem, size, v as u64)?;
                }
            }
            // ---- VMOVQ store (66 0F D6: xmm/m64 <- xmm low 64) ------------
            0xD6 => {
                let v = self.state.xmm(reg) & sse::LOW64;
                self.vstore_low(ctx, mem, 8, v)?;
            }

            // ---- packed float arithmetic ----------------------------------
            0x58 => self.vex_farith(ctx, mem, vex, reg, |a, b| a + b)?,
            0x59 => self.vex_farith(ctx, mem, vex, reg, |a, b| a * b)?,
            0x5C => self.vex_farith(ctx, mem, vex, reg, |a, b| a - b)?,
            0x5D => self.vex_farith(ctx, mem, vex, reg, sse_min)?,
            0x5E => self.vex_farith(ctx, mem, vex, reg, |a, b| a / b)?,
            0x5F => self.vex_farith(ctx, mem, vex, reg, sse_max)?,
            // VSQRT — unary.
            0x51 => self.vex_funary(ctx, mem, vex, reg, f64::sqrt)?,

            // ---- packed float logic (AND/ANDN/OR/XOR) ---------------------
            0x54 => self.vex_logic(ctx, mem, vex, reg, |a, b| a & b)?,
            0x55 => self.vex_logic(ctx, mem, vex, reg, |a, b| !a & b)?,
            0x56 => self.vex_logic(ctx, mem, vex, reg, |a, b| a | b)?,
            0x57 => self.vex_logic(ctx, mem, vex, reg, |a, b| a ^ b)?,

            // ---- VUNPCKLPS/PD (0x14), VUNPCKHPS/PD (0x15) -----------------
            0x14 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, if vex.pd() { 8 } else { 4 }, false))?,
            0x15 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, if vex.pd() { 8 } else { 4 }, true))?,

            // ---- VSHUFPS/PD (0xC6) with imm8 ------------------------------
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

            // ---- VCMPPS/PD/SS/SD (0xC2) with imm8 predicate ---------------
            0xC2 => self.vex_cmp(ctx, mem, vex, reg)?,

            // ---- VCOMISS/SD (0x2F), VUCOMISS/SD (0x2E) --------------------
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

            // ---- integer add/sub/logic/compare (AVX2, lane-wise) ----------
            0xD4 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 8, true))?, // VPADDQ
            0xFB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 8, false))?, // VPSUBQ
            0xFC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 1, true))?, // VPADDB
            0xFD => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 2, true))?, // VPADDW
            0xFE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 4, true))?, // VPADDD
            0xF8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 1, false))?, // VPSUBB
            0xF9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 2, false))?, // VPSUBW
            0xFA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub(a, b, 4, false))?, // VPSUBD
            0xDB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a & b)?,  // VPAND
            0xDF => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| !a & b)?, // VPANDN
            0xEB => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a | b)?,  // VPOR
            0xEF => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| a ^ b)?,  // VPXOR
            0x74 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 1, false))?, // VPCMPEQB
            0x75 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 2, false))?, // VPCMPEQW
            0x76 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 4, false))?, // VPCMPEQD
            0x64 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 1, true))?, // VPCMPGTB
            0x65 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 2, true))?, // VPCMPGTW
            0x66 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 4, true))?, // VPCMPGTD
            0xD5 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmullw)?, // VPMULLW
            0xE5 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pmulh(a, b, true))?, // VPMULHW
            0xE4 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pmulh(a, b, false))?, // VPMULHUW
            0xF4 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmuludq)?, // VPMULUDQ
            0xF5 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmaddwd)?, // VPMADDWD
            0xF6 => self.vex_lane_bin(ctx, mem, vex, reg, sse::psadbw)?, // VPSADBW
            0xDC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, true, false))?, // VPADDUSB
            0xDD => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, true, false))?, // VPADDUSW
            0xEC => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, true, true))?, // VPADDSB
            0xED => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, true, true))?, // VPADDSW
            0xD8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, false, false))?, // VPSUBUSB
            0xD9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, false, false))?, // VPSUBUSW
            0xE8 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 1, false, true))?, // VPSUBSB
            0xE9 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::add_sub_sat(a, b, 2, false, true))?, // VPSUBSW
            0xDA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::byte_minmax(a, b, false))?, // VPMINUB
            0xDE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::byte_minmax(a, b, true))?, // VPMAXUB
            0xEA => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, true, false))?, // VPMINSW
            0xEE => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, true, true))?, // VPMAXSW
            0xE0 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pavg(a, b, 1))?, // VPAVGB
            0xE3 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pavg(a, b, 2))?, // VPAVGW

            // ---- VPUNPCK{L,H}{BW,WD,DQ,QDQ} -------------------------------
            0x60 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 1, false))?, // VPUNPCKLBW
            0x61 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 2, false))?, // VPUNPCKLWD
            0x62 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 4, false))?, // VPUNPCKLDQ
            0x6C => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 8, false))?, // VPUNPCKLQDQ
            0x68 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 1, true))?, // VPUNPCKHBW
            0x69 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 2, true))?, // VPUNPCKHWD
            0x6A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 4, true))?, // VPUNPCKHDQ
            0x6D => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::punpck(a, b, 8, true))?, // VPUNPCKHQDQ

            // ---- VPACKSSWB/DW, VPACKUSWB (2-source pack) ------------------
            0x63 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 2, true))?, // VPACKSSWB
            0x6B => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 4, true))?, // VPACKSSDW
            0x67 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pack(a, b, 2, false))?, // VPACKUSWB

            // ---- VPSHUFD (66), VPSHUFLW (F2), VPSHUFHW (F3) with imm8 -----
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

            // ---- VPMOVMSKB (66 0F D7) -> GP -------------------------------
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
            // ---- VMOVMSKPS/PD (0F 50) -> GP -------------------------------
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

            // ---- variable/imm shifts (VPSLL/VPSRL/VPSRA) ------------------
            0x71..=0x73 => self.vex_shift_imm(ctx, mem, vex, op)?,
            0xD1 => self.vex_shift_var(ctx, mem, vex, reg, 2, false, false)?, // VPSRLW
            0xD2 => self.vex_shift_var(ctx, mem, vex, reg, 4, false, false)?, // VPSRLD
            0xD3 => self.vex_shift_var(ctx, mem, vex, reg, 8, false, false)?, // VPSRLQ
            0xE1 => self.vex_shift_var(ctx, mem, vex, reg, 2, true, false)?,  // VPSRAW
            0xE2 => self.vex_shift_var(ctx, mem, vex, reg, 4, true, false)?,  // VPSRAD
            0xF1 => self.vex_shift_var(ctx, mem, vex, reg, 2, false, true)?,  // VPSLLW
            0xF2 => self.vex_shift_var(ctx, mem, vex, reg, 4, false, true)?,  // VPSLLD
            0xF3 => self.vex_shift_var(ctx, mem, vex, reg, 8, false, true)?,  // VPSLLQ

            // ---- VCVT* (packed dq<->ps) -----------------------------------
            0x5B => {
                // 0F 5B: VCVTDQ2PS (NP), VCVTPS2DQ (66), VCVTTPS2DQ (F3).
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
            // VCVTSI2SS/SD (F3/F2 0F 2A): GP -> scalar float.
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
            // VCVT(T)SS2SI / VCVT(T)SD2SI (F3/F2 0F 2C/2D): scalar float -> GP.
            0x2C | 0x2D => {
                let truncate = op == 0x2C;
                let size = if vex.w { 8 } else { 4 };
                let src = self.vrm128(ctx, mem, 8)?;
                let f = if vex.f2() { f64::from_bits(src as u64) } else { f32::from_bits(src as u32) as f64 };
                let r = sse::cvt_f_to_int(f, truncate, size);
                self.write_reg_field(ctx, size, r);
            }
            // VCVTSS2SD / VCVTSD2SS (F3/F2 0F 5A).
            0x5A => {
                let src = self.vrm128(ctx, mem, 8)?;
                let base = self.state.xmm(vex.vvvv);
                let v = if vex.f2() {
                    // sd2ss
                    (base & !sse::LOW32) | ((f64::from_bits(src as u64) as f32).to_bits() as u128)
                } else {
                    // ss2sd
                    (base & !sse::LOW64) | ((f32::from_bits(src as u32) as f64).to_bits() as u128)
                };
                self.state.set_xmm_zero_upper(reg, v);
            }

            _ => return Err(EmuError::Unsupported(format!("VEX 0F {op:#04x}"))),
        }
        Ok(())
    }

    // ---- 0F38 map --------------------------------------------------------

    fn vex_0f38(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            0x00 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pshufb)?, // VPSHUFB
            0x01 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, false, false, false))?, // VPHADDW
            0x02 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 4, false, false, false))?, // VPHADDD
            0x05 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, true, false, false))?, // VPHSUBW
            0x06 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 4, true, false, false))?, // VPHSUBD
            0x03 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, false, true, false))?, // VPHADDSW
            0x07 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::phaddsub(a, b, 2, true, true, false))?, // VPHSUBSW
            0x04 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmaddubsw)?, // VPMADDUBSW
            0x08 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 1))?, // VPSIGNB
            0x09 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 2))?, // VPSIGNW
            0x0A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::psign(a, b, 4))?, // VPSIGND
            0x0B => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmulhrsw)?, // VPMULHRSW
            0x1C => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 1))?, // VPABSB
            0x1D => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 2))?, // VPABSW
            0x1E => self.vex_unary_lane(ctx, mem, vex, reg, |v| sse::pabs(v, 4))?, // VPABSD
            0x28 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmuldq)?, // VPMULDQ
            0x29 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 8, false))?, // VPCMPEQQ
            0x37 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::pcmp(a, b, 8, true))?, // VPCMPGTQ
            0x2B => self.vex_lane_bin(ctx, mem, vex, reg, sse::packusdw)?, // VPACKUSDW
            0x40 => self.vex_lane_bin(ctx, mem, vex, reg, sse::pmulld)?, // VPMULLD
            0x38 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 1, true, false))?, // VPMINSB
            0x3C => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 1, true, true))?, // VPMAXSB
            0x39 => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, true, false))?, // VPMINSD
            0x3D => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, true, true))?, // VPMAXSD
            0x3A => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, false, false))?, // VPMINUW
            0x3E => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 2, false, true))?, // VPMAXUW
            0x3B => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, false, false))?, // VPMINUD
            0x3F => self.vex_lane_bin(ctx, mem, vex, reg, |a, b| sse::int_minmax(a, b, 4, false, true))?, // VPMAXUD

            // ---- VPMOVSX/ZX (128-bit only src widened to dst) -------------
            0x20 => self.vex_pmovx(ctx, mem, vex, reg, 1, 2, true)?, // VPMOVSXBW
            0x21 => self.vex_pmovx(ctx, mem, vex, reg, 1, 4, true)?, // VPMOVSXBD
            0x22 => self.vex_pmovx(ctx, mem, vex, reg, 1, 8, true)?, // VPMOVSXBQ
            0x23 => self.vex_pmovx(ctx, mem, vex, reg, 2, 4, true)?, // VPMOVSXWD
            0x24 => self.vex_pmovx(ctx, mem, vex, reg, 2, 8, true)?, // VPMOVSXWQ
            0x25 => self.vex_pmovx(ctx, mem, vex, reg, 4, 8, true)?, // VPMOVSXDQ
            0x30 => self.vex_pmovx(ctx, mem, vex, reg, 1, 2, false)?, // VPMOVZXBW
            0x31 => self.vex_pmovx(ctx, mem, vex, reg, 1, 4, false)?, // VPMOVZXBD
            0x32 => self.vex_pmovx(ctx, mem, vex, reg, 1, 8, false)?, // VPMOVZXBQ
            0x33 => self.vex_pmovx(ctx, mem, vex, reg, 2, 4, false)?, // VPMOVZXWD
            0x34 => self.vex_pmovx(ctx, mem, vex, reg, 2, 8, false)?, // VPMOVZXWQ
            0x35 => self.vex_pmovx(ctx, mem, vex, reg, 4, 8, false)?, // VPMOVZXDQ

            // ---- VPBROADCASTB/W/D/Q (AVX2) --------------------------------
            0x78 => self.vex_broadcast(ctx, mem, vex, reg, 1)?, // VPBROADCASTB
            0x79 => self.vex_broadcast(ctx, mem, vex, reg, 2)?, // VPBROADCASTW
            0x58 => self.vex_broadcast(ctx, mem, vex, reg, 4)?, // VPBROADCASTD
            0x59 => self.vex_broadcast(ctx, mem, vex, reg, 8)?, // VPBROADCASTQ
            // VBROADCASTSS (4) / VBROADCASTSD (8, 256-only)
            0x18 => self.vex_broadcast(ctx, mem, vex, reg, 4)?, // VBROADCASTSS
            0x19 => self.vex_broadcast(ctx, mem, vex, reg, 8)?, // VBROADCASTSD

            // ---- VPTEST (sets flags) --------------------------------------
            0x17 => self.vex_ptest(ctx, mem, vex, reg)?,

            // ---- VINSERTI128 handled in 0F3A; VPERMD (0x36) ---------------
            0x36 => self.vex_permd(ctx, mem, vex, reg)?, // VPERMD (256-bit, dword)
            0x16 => self.vex_permps(ctx, mem, vex, reg)?, // VPERMPS

            // ---- VPSLLVD/Q, VPSRLVD/Q, VPSRAVD (per-element var shift) ----
            0x47 => self.vex_var_shift(ctx, mem, vex, reg, if vex.w { 8 } else { 4 }, false, true)?, // VPSLLV
            0x45 => self.vex_var_shift(ctx, mem, vex, reg, if vex.w { 8 } else { 4 }, false, false)?, // VPSRLV
            0x46 => self.vex_var_shift(ctx, mem, vex, reg, 4, true, false)?, // VPSRAVD

            _ => return Err(EmuError::Unsupported(format!("VEX 0F38 {op:#04x}"))),
        }
        Ok(())
    }

    // ---- 0F3A map --------------------------------------------------------

    fn vex_0f3a(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let reg = ctx.reg;
        match op {
            // ---- VPALIGNR (0x0F) ------------------------------------------
            0x0F => {
                // Read the trailing imm8 BEFORE the memory operand so a
                // RIP-relative r/m resolves against the end of the whole
                // instruction (imm included). Applies to every 0F3A form below.
                let imm = ctx.u8(mem)?;
                let (sl, sh) = self.vsrc(vex);
                let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
                self.vdst(reg, vex.l, sse::palignr(sl, bl, imm), if vex.l { sse::palignr(sh, bh, imm) } else { 0 });
            }
            // ---- VPBLENDW (0x0E), VBLENDPS (0x0C), VBLENDPD (0x0D) --------
            0x0E => self.vex_blend_imm(ctx, mem, vex, reg, 2)?,
            0x0C => self.vex_blend_imm(ctx, mem, vex, reg, 4)?,
            0x0D => self.vex_blend_imm(ctx, mem, vex, reg, 8)?,
            // ---- VPBLENDD (0x02, AVX2 dword blend) ------------------------
            0x02 => self.vex_blend_imm(ctx, mem, vex, reg, 4)?,

            // ---- VSHUFPS/PD imm variants live at C6 (0F map) --------------

            // ---- VROUNDPS/PD (0x08/0x09), VROUNDSS/SD (0x0A/0x0B) ---------
            0x08 => self.vex_round_packed(ctx, mem, vex, reg, false)?,
            0x09 => self.vex_round_packed(ctx, mem, vex, reg, true)?,
            0x0A => self.vex_round_scalar(ctx, mem, vex, reg, false)?,
            0x0B => self.vex_round_scalar(ctx, mem, vex, reg, true)?,

            // ---- VPERMQ / VPERMPD (0x00 / 0x01, 256-bit, imm8) -----------
            0x00 => self.vex_permq(ctx, mem, vex, reg)?,
            0x01 => self.vex_permpd(ctx, mem, vex, reg)?,

            // ---- VEXTRACTI128 / VEXTRACTF128 (0x39 / 0x19) ---------------
            0x39 | 0x19 => {
                let imm = ctx.u8(mem)?;
                let (lo, hi) = (self.state.xmm(reg), self.state.ymm_hi(reg));
                let sel = if imm & 1 != 0 { hi } else { lo };
                self.vstore128(ctx, mem, sel)?;
            }
            // ---- VINSERTI128 / VINSERTF128 (0x38 / 0x18) -----------------
            0x38 | 0x18 => {
                let imm = ctx.u8(mem)?;
                let (dl, dh) = self.vsrc(vex);
                let ins = self.vrm128(ctx, mem, 16)?;
                let (lo, hi) = if imm & 1 != 0 { (dl, ins) } else { (ins, dh) };
                self.state.set_ymm(reg, lo, hi);
            }
            // ---- VPERM2I128 / VPERM2F128 (0x46 / 0x06) -------------------
            0x46 | 0x06 => self.vex_perm2i128(ctx, mem, vex, reg)?,

            // ---- VPEXTRB/W/D/Q (0x14/0x15/0x16/0x22) ---------------------
            0x14 => self.vex_pextr(ctx, mem, vex, reg, 1)?,
            0x15 => self.vex_pextr(ctx, mem, vex, reg, 2)?,
            0x16 => self.vex_pextr(ctx, mem, vex, reg, if vex.w { 8 } else { 4 })?,
            // ---- VPINSRB/W/D/Q (0x20/../0x22) ----------------------------
            0x20 => self.vex_pinsr(ctx, mem, vex, reg, 1)?,
            0x22 => self.vex_pinsr(ctx, mem, vex, reg, if vex.w { 8 } else { 4 })?,

            // ---- VMPSADBW (0x42) ------------------------------------------
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

    // ---- shared op helpers ----------------------------------------------

    /// Load the r/m operand honoring the vector length (128 or 256 bits).
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

    /// Read the trailing imm8 after a ModRM+possible-memory operand (used for the
    /// 0F3A forms that touch memory then read an immediate — the immediate is
    /// after the whole operand, so this must be called after `rm_addr()` is used
    /// or the value cached first).
    fn imm_after_rm(&self, ctx: &mut Ctx, mem: &dyn Memory) -> Result<u8> {
        ctx.u8(mem)
    }

    /// `dst = f(vvvv, rm)` applied per 128-bit lane (AVX2 integer / lane-wise).
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

    /// `dst = f(rm)` applied per 128-bit lane (unary AVX2 integer).
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

    /// Packed float logic (`dst = f(vvvv, rm)` on raw bits).
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

    /// Packed/scalar float arithmetic `dst = f(vvvv, rm)`.
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
            // Scalar: operate on the low element, take the rest from vvvv (al).
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

    /// Packed/scalar float unary `dst = f(rm)` (VSQRT).
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

    /// VMOVSS / VMOVSD in the two 3-operand register forms and the 2-operand
    /// memory forms.
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
            // 0x11: r/m <- reg. Register form merges vvvv; memory form writes n.
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
            // 0x10: reg <- r/m.
            match ctx.rm {
                Rm::Reg(i) => {
                    let merged = (self.state.xmm(vex.vvvv) & !mask) | (self.state.xmm(i) & mask);
                    self.state.set_xmm_zero_upper(reg, merged);
                }
                Rm::Mem { .. } => {
                    // Memory scalar load zero-extends into the full register.
                    let v = self.vrm128(ctx, mem, n)? & mask;
                    self.state.set_xmm_zero_upper(reg, v);
                }
            }
        }
        Ok(())
    }

    /// VCMPPS/PD/SS/SD — imm8 predicate compare producing an all-ones/zero mask.
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

    /// VPMOVSX/ZX: widen the low `dst_bytes/src*count` elements of the 128-bit
    /// source. The 256-bit form reads a 128-bit source and widens into 256 bits.
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
            // 256-bit: source is 128 bits; each lane of output takes half the
            // source elements. Read the full 128-bit source.
            let src = self.vrm128(ctx, mem, 16)?;
            // Number of output elements total = 16/dst_sz * 2 lanes; but a
            // 256-bit pmovx widens (32/dst_sz) elements from the 128-bit source.
            let per_lane = 16 / dst_sz;
            let lo = pmovx_from(src, 0, per_lane, src_sz, dst_sz, sign);
            let hi = pmovx_from(src, per_lane, per_lane, src_sz, dst_sz, sign);
            self.state.set_ymm(reg, lo, hi);
        } else {
            let n = (16 / dst_sz) * src_sz; // bytes of source consumed
            let src = self.vrm128(ctx, mem, n)?;
            self.state.set_xmm_zero_upper(reg, sse::pmovx(src, src_sz, dst_sz, sign));
        }
        Ok(())
    }

    /// VPBROADCAST* / VBROADCASTSS/SD — replicate the low element of the source
    /// (register low lane, or memory) across the destination.
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

    /// VPTEST — set ZF from `dst AND src`, CF from `dst ANDN src` (per SDM).
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

    /// VPSHUFD-style imm shift group (0F 71/72/73 /reg).
    fn vex_shift_imm(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, op: u8) -> Result<()> {
        let (esz, ext) = match op {
            0x71 => (2usize, ctx.reg & 7),
            0x72 => (4usize, ctx.reg & 7),
            _ => (8usize, ctx.reg & 7),
        };
        // r/m is the source; the destination is vvvv.
        let (sl, sh) = self.vload_rm(ctx, mem, vex)?;
        let count = ctx.u8(mem)? as u64;
        let dst = vex.vvvv;
        let f: Box<dyn Fn(u128) -> u128> = match ext {
            2 => Box::new(move |v| sse::shift_r(v, esz, count, false)), // PSRL
            4 => Box::new(move |v| sse::shift_r(v, esz, count, true)),  // PSRA
            6 => Box::new(move |v| sse::shift_l(v, esz, count)),        // PSLL
            _ => return Err(EmuError::Unsupported(format!("VEX shift-imm /{ext}"))),
        };
        let lo = f(sl);
        let hi = if vex.l { f(sh) } else { 0 };
        self.vdst(dst, vex.l, lo, hi);
        Ok(())
    }

    /// VPSRLW/D/Q, VPSRAW/D, VPSLLW/D/Q — shift by the low 64 bits of the xmm
    /// r/m operand (a single scalar count broadcast to all elements).
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

    /// VPSLLVD/Q, VPSRLVD/Q, VPSRAVD — per-element variable shift (AVX2).
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

    /// VBLENDPS/PD/VPBLENDW/VPBLENDD imm8 blend.
    fn vex_blend_imm(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8, esz: usize) -> Result<()> {
        let (al, ah) = self.vsrc(vex);
        let (bl, bh) = self.vload_rm(ctx, mem, vex)?;
        let imm = ctx.u8(mem)?;
        // For a 256-bit VPBLENDD the imm8 covers all 8 dwords; VBLENDPS 8 lanes;
        // for the others the same imm8 applies to both 128-bit lanes.
        let (lo, hi) = if vex.l && esz == 4 {
            // 8 dword/float selectors across the full 256 bits.
            (blend_imm_wide(al, bl, imm & 0x0F, esz), blend_imm_wide(ah, bh, imm >> 4, esz))
        } else {
            (sse::blend_imm(al, bl, imm, esz), if vex.l { sse::blend_imm(ah, bh, imm, esz) } else { 0 })
        };
        self.vdst(reg, vex.l, lo, hi);
        Ok(())
    }

    /// VROUNDPS/PD — packed round with imm8 mode.
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

    /// VROUNDSS/SD — scalar round; upper elements from vvvv.
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

    /// VPERMQ / VPERMPD — imm8 selects each of 4 qwords from the 256-bit source.
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
        // Same lane selection as VPERMQ (both operate on 64-bit lanes).
        self.vex_permq(ctx, mem, vex, reg)
    }

    /// VPERMD — 8 dword selectors from vvvv indexing the 256-bit source.
    fn vex_permd(&mut self, ctx: &Ctx, mem: &mut dyn Memory, vex: &Vex, reg: u8) -> Result<()> {
        let (il, ih) = self.vsrc(vex); // index vector
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
        // VPERMPS has the same dword-permute semantics as VPERMD.
        self.vex_permd(ctx, mem, vex, reg)
    }

    /// VPERM2I128 / VPERM2F128 — imm8 selects a 128-bit lane per output half.
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

    /// VPEXTRB/W/D/Q — extract an element to a GP register or memory.
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

    /// VPINSRB/D/Q — insert a GP/memory element into a lane; base from vvvv.
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

// ---- free helpers ----------------------------------------------------------

fn sse_min(a: f64, b: f64) -> f64 {
    // x86 MINPS/MINPD: if either operand is NaN, or they are equal (incl. ±0),
    // return the second (src) operand.
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

/// Packed float binary op over a 128-bit lane.
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

/// Evaluate an SSE/AVX compare predicate (imm8 low 5 bits) on two f64s.
/// Only the eight legacy (VEX) predicates plus the common extended ones needed
/// by CRTs are decoded; the rest fall back to the legacy 3-bit interpretation.
fn cmp_pred(a: f64, b: f64, imm: u8) -> bool {
    match imm & 0x1F {
        0x00 => a == b,                       // EQ_OQ
        0x01 => a < b,                        // LT_OS
        0x02 => a <= b,                       // LE_OS
        0x03 => a.is_nan() || b.is_nan(),     // UNORD_Q
        0x04 => a != b || a.is_nan() || b.is_nan(), // NEQ_UQ
        0x05 => a >= b || a.is_nan() || b.is_nan(), // NLT_US = !(a<b), unordered→true
        0x06 => a > b || a.is_nan() || b.is_nan(),  // NLE_US = !(a<=b), unordered→true
        0x07 => !a.is_nan() && !b.is_nan(),   // ORD_Q
        0x08 => a == b,                       // EQ_UQ (unordered-eq): treat NaN below
        0x09 => a < b || a.is_nan() || b.is_nan(), // NGE_US = !(a>=b), unordered→true
        0x0A => a <= b || a.is_nan() || b.is_nan(), // NGT_US = !(a>b), unordered→true
        0x0B => false,                        // FALSE_OQ
        0x0C => a != b && !a.is_nan() && !b.is_nan(),  // NEQ_OQ
        0x0D => a >= b,                        // GE_OS
        0x0E => a > b,                         // GT_OS
        0x0F => true,                          // TRUE_UQ
        // Extended set (0x10..0x1F) mirror 0x00..0x0F signalling variants; the
        // ordered/unordered result is identical for quiet operands.
        v => cmp_pred(a, b, v & 0x07),
    }
}

/// The unordered-equal predicate (0x08) must be true when either is NaN.
fn pcmp_float(a: u128, b: u128, dbl: bool, imm: u8) -> u128 {
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

/// Compare predicate with correct unordered handling for the 0x08 (EQ_UQ) case.
fn cmp_pred_full(a: f64, b: f64, imm: u8) -> bool {
    match imm & 0x1F {
        0x08 => a == b || a.is_nan() || b.is_nan(), // EQ_UQ
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

/// Per-element variable shift (VPSLLV/VPSRLV/VPSRAV) over a 128-bit lane.
fn var_shift_lane(v: u128, counts: u128, esz: usize, arith: bool, left: bool) -> u128 {
    let bits = esz * 8;
    let mask = sse::emask(esz);
    let mut out = 0u128;
    for i in 0..(16 / esz) {
        let x = (v >> (i * bits)) & mask;
        let c = ((counts >> (i * bits)) & mask) as u64;
        let r = if c >= bits as u64 {
            if arith && !left {
                // arithmetic right shift by >= width → sign fill
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

/// 256-bit dword/float blend where `sel4` (4 bits) chooses per-lane src/dst.
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

/// Packed round of an f32x4 / f64x2 lane using the resolved MXCSR-style mode.
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

/// Widen `count` elements starting at element `start` of the 128-bit source.
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
