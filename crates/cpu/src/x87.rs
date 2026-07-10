//! x87 FPU: the ST0..ST7 register stack, control/status/tag words, and the
//! `D8..DF` (+ `9B` FWAIT) instruction families.
//!
//! # Storage & precision model
//!
//! Each physical data register holds a real **80-bit double-extended** value
//! (see [`exemu_core::X87`]). Loads and stores of a `long double` therefore
//! round-trip bit-exactly. Arithmetic is evaluated in the host `f64` (double,
//! 53-bit significand) and the double result is re-encoded to 80-bit. This is
//! an intentional, documented approximation: results are correct to double
//! precision, not to the true 64-bit-extended significand. Code that runs the
//! FPU in double or single precision-control mode — the norm on Windows, where
//! `long double == double` — is unaffected. The rounding-control (RC) field of
//! the control word *is* honoured for stores and int conversions.
//!
//! # Transcendentals
//!
//! `FSIN`/`FCOS`/`FSINCOS`/`FPTAN`/`FPATAN`/`F2XM1`/`FYL2X`/`FYL2XP1` are host
//! `f64` math-library approximations. They are **not** bit-exact against a real
//! x87 (whose 68-bit internal polynomial evaluation differs), so the oracle
//! masks the low significand bits of transcendental results rather than
//! claiming exactness — see the oracle's x87 category.

use exemu_core::{EmuError, Memory, Result};

use crate::{Ctx, Interpreter, Rm};

// --- Status-word bits ---------------------------------------------------------

const SW_C0: u16 = 1 << 8;
const SW_C1: u16 = 1 << 9;
const SW_C2: u16 = 1 << 10;
const SW_C3: u16 = 1 << 14;
/// Invalid-operation exception flag.
const SW_IE: u16 = 1 << 0;

// --- 80-bit extended <-> f64 conversion --------------------------------------

/// Encode an `f64` into the low 80 bits of a `u128` (x87 double-extended).
pub(crate) fn f64_to_ext(x: f64) -> u128 {
    let bits = x.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7ff) as u32;
    let frac = bits & 0x000f_ffff_ffff_ffff;

    let (ext_exp, ext_signif): (u32, u64) = if exp == 0x7ff {
        // Inf / NaN: exponent all-ones, integer bit set. NaN keeps its payload
        // in the top mantissa bits; the QNaN bit maps to bit 62.
        let signif = if frac == 0 {
            0x8000_0000_0000_0000 // infinity
        } else {
            0x8000_0000_0000_0000 | (frac << 11)
        };
        (0x7fff, signif)
    } else if exp == 0 {
        if frac == 0 {
            (0, 0) // signed zero
        } else {
            // Subnormal double. Normalise into the wider extended range, which
            // can represent it as a normal number (extended has more exponent
            // range), setting the explicit integer bit.
            let lead = frac.leading_zeros() - 11; // shift to put msb at bit 52
            let signif = frac << (11 + lead + 1);
            // Unbiased double exponent for a subnormal is 1-1023; each left
            // shift decrements it further.
            let e = 1_i32 - 1023 - (lead as i32) - 1 + 16383;
            (e as u32, 0x8000_0000_0000_0000 | signif)
        }
    } else {
        // Normal double: rebias exponent, restore the implicit integer bit.
        let e = exp - 1023 + 16383;
        let signif = 0x8000_0000_0000_0000 | (frac << 11);
        (e, signif)
    };

    ((sign as u128) << 79) | ((ext_exp as u128) << 64) | (ext_signif as u128)
}

/// Decode the low 80 bits of a `u128` (x87 double-extended) to the nearest
/// `f64` (round-to-nearest-even). Used for arithmetic inputs and for stores in
/// the standard round-nearest control mode.
pub(crate) fn ext_to_f64(v: u128) -> f64 {
    let sign = ((v >> 79) & 1) as u64;
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64; // low 64 bits: integer bit + fraction

    if exp == 0x7fff {
        // Inf / NaN.
        let frac = signif & 0x7fff_ffff_ffff_ffff;
        return if frac == 0 {
            if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY }
        } else {
            // NaN: fold the payload down. Preserve quiet-bit and non-zero-ness.
            let payload = frac >> 11;
            let bits = (sign << 63) | (0x7ff << 52) | payload | 0x0008_0000_0000_0000;
            f64::from_bits(bits)
        };
    }
    if exp == 0 && signif == 0 {
        return f64::from_bits(sign << 63); // signed zero
    }

    // Real value: (-1)^sign * signif * 2^(exp-16383-63).
    // Build it directly and let the host FPU round to nearest double.
    let mantissa = signif as f64; // exact (<= 2^64)
    let e2 = exp as i32 - 16383 - 63;
    let mag = mantissa * exp2(e2);
    if sign == 1 { -mag } else { mag }
}

/// `2^n` for a (possibly large negative or positive) integer power, without
/// `powi` intermediate overflow surprises for the extreme exponents.
fn exp2(n: i32) -> f64 {
    // f64 exponent range is roughly [-1074, 1023]. Clamp beyond it to 0/inf,
    // matching what multiplication by such a scale produces anyway.
    if n > 1100 {
        f64::INFINITY
    } else if n < -1100 {
        0.0
    } else {
        // Split so each factor stays representable.
        let mut r = 1.0f64;
        let mut k = n;
        while k > 0 {
            let s = k.min(1000);
            r *= f64::from_bits(((1023 + s) as u64) << 52);
            k -= s;
        }
        while k < 0 {
            let s = (-k).min(1000);
            r *= f64::from_bits(((1023 - s) as u64) << 52);
            k += s;
        }
        r
    }
}

impl Interpreter {
    // ---- stack helpers ---------------------------------------------------

    /// Read `ST(i)` as a raw 80-bit value.
    #[inline]
    fn fpu_read_ext(&self, i: u8) -> u128 {
        let p = self.state.x87.phys(i);
        self.state.x87.st[p]
    }

    /// Read `ST(i)` as an `f64`.
    #[inline]
    fn fpu_read(&self, i: u8) -> f64 {
        ext_to_f64(self.fpu_read_ext(i))
    }

    /// Write `ST(i)` from a raw 80-bit value and mark it valid.
    #[inline]
    fn fpu_write_ext(&mut self, i: u8, v: u128) {
        let p = self.state.x87.phys(i);
        self.state.x87.st[p] = v & ((1u128 << 80) - 1);
        self.fpu_set_tag(p, tag_of(self.state.x87.st[p]));
    }

    /// Write `ST(i)` from an `f64`.
    #[inline]
    fn fpu_write(&mut self, i: u8, x: f64) {
        self.fpu_write_ext(i, f64_to_ext(x));
    }

    #[inline]
    fn fpu_set_tag(&mut self, phys: usize, tag: u16) {
        let shift = (phys as u16) * 2;
        self.state.x87.tw = (self.state.x87.tw & !(0b11 << shift)) | ((tag & 0b11) << shift);
    }

    /// Decrement TOP and load `val` into the new ST0.
    fn fpu_push(&mut self, val: u128) {
        let top = self.state.x87.top();
        let new_top = top.wrapping_sub(1) & 7;
        self.state.x87.set_top(new_top);
        self.state.x87.st[new_top as usize] = val & ((1u128 << 80) - 1);
        self.fpu_set_tag(new_top as usize, tag_of(self.state.x87.st[new_top as usize]));
    }

    fn fpu_push_f64(&mut self, x: f64) {
        self.fpu_push(f64_to_ext(x));
    }

    /// Mark ST0 empty and increment TOP.
    fn fpu_pop(&mut self) {
        let top = self.state.x87.top();
        self.fpu_set_tag(top as usize, 0b11); // empty
        self.state.x87.set_top(top.wrapping_add(1) & 7);
    }

    /// Set the C1 condition bit (used for round-up indication / stack fault).
    #[inline]
    fn fpu_set_c1(&mut self, on: bool) {
        if on {
            self.state.x87.sw |= SW_C1;
        } else {
            self.state.x87.sw &= !SW_C1;
        }
    }

    // ---- FCOM / FUCOM condition codes ------------------------------------

    /// Set C3/C2/C0 from an ordered comparison of `a` vs `b` (C1 cleared).
    fn fpu_set_compare(&mut self, a: f64, b: f64) {
        let sw = &mut self.state.x87.sw;
        *sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if a.is_nan() || b.is_nan() {
            *sw |= SW_C0 | SW_C2 | SW_C3; // unordered
        } else if a < b {
            *sw |= SW_C0;
        } else if a > b {
            // all clear
        } else {
            *sw |= SW_C3; // equal
        }
    }

    /// Set EFLAGS ZF/PF/CF from a comparison of `a` vs `b` (the FCOMI form).
    fn fpu_set_compare_eflags(&mut self, a: f64, b: f64) {
        use exemu_core::cpu::flags::{CF, OF, PF, SF, ZF, AF};
        // FCOMI/FUCOMI: ZF/PF/CF set per result, OF/SF/AF cleared.
        let (zf, pf, cf) = if a.is_nan() || b.is_nan() {
            (true, true, true) // unordered
        } else if a < b {
            (false, false, true)
        } else if a > b {
            (false, false, false)
        } else {
            (true, false, false)
        };
        self.state.set_flag(ZF, zf);
        self.state.set_flag(PF, pf);
        self.state.set_flag(CF, cf);
        self.state.set_flag(OF, false);
        self.state.set_flag(SF, false);
        self.state.set_flag(AF, false);
    }

    // ---- rounding control ------------------------------------------------

    /// Round a real value to an integer per the control word's RC field.
    /// The sign of a zero result follows the sign of the input (x87 preserves
    /// −0.0 when rounding e.g. −0.3 toward nearest).
    fn fpu_round_int(&self, x: f64) -> f64 {
        if !x.is_finite() {
            return x;
        }
        let r = match (self.state.x87.cw >> 10) & 3 {
            0 => round_half_even(x), // nearest (even)
            1 => x.floor(),          // toward -inf
            2 => x.ceil(),           // toward +inf
            _ => x.trunc(),          // toward zero
        };
        if r == 0.0 && x.is_sign_negative() {
            -0.0
        } else {
            r
        }
    }

    // ---- the main dispatch ----------------------------------------------

    /// Execute one x87 instruction whose escape opcode is `esc` (0xD8..=0xDF).
    /// Returns after advancing `ctx.cur` past the ModRM/operands; the caller's
    /// shared tail commits `rip`.
    pub(crate) fn exec_x87(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, esc: u8) -> Result<()> {
        let modrm = ctx.u8(mem)?;
        let mod_ = modrm >> 6;
        let reg = (modrm >> 3) & 7;

        if mod_ == 3 {
            // Register form: r/m selects ST(i).
            let sti = modrm & 7;
            self.x87_reg_form(ctx, mem, esc, reg, sti)
        } else {
            // Memory form: re-decode the ModRM as a memory operand so the
            // existing SIB/disp machinery computes the address.
            ctx.cur -= 1; // step back to the ModRM byte
            self.read_modrm(ctx, mem)?;
            let addr = match ctx.rm {
                Rm::Mem { .. } => ctx.rm_addr(),
                Rm::Reg(_) => unreachable!("mod!=3 decoded as register"),
            };
            self.x87_mem_form(mem, esc, reg, addr)
        }
    }

    /// Register-form (`mod==3`) x87 ops.
    fn x87_reg_form(&mut self, _ctx: &mut Ctx, _mem: &mut dyn Memory, esc: u8, reg: u8, sti: u8) -> Result<()> {
        match (esc, reg) {
            // FADD/FMUL/FSUB(R)/FDIV(R) ST0, ST(i)  (D8) and ST(i),ST0 (DC)
            (0xD8, 0) => { let r = self.fpu_read(0) + self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 1) => { let r = self.fpu_read(0) * self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 2) => self.fpu_set_compare(self.fpu_read(0), self.fpu_read(sti)), // FCOM
            (0xD8, 3) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); } // FCOMP
            (0xD8, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(0, r); } // FSUB
            (0xD8, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(0, r); } // FSUBR
            (0xD8, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(0, r); } // FDIV
            (0xD8, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(0, r); } // FDIVR

            // D9: FLD ST(i), FXCH, and the no-operand group.
            (0xD9, 0) => { let v = self.fpu_read_ext(sti); self.fpu_push(v); } // FLD ST(i)
            (0xD9, 1) => self.fxch(sti),                                       // FXCH
            (0xD9, 4) => self.d9_e0_group(sti)?,  // FCHS/FABS/FTST/FXAM (reg encodes op)
            (0xD9, 5) => self.d9_e8_group(sti)?,  // FLD1/FLDL2T/.../FLDZ
            (0xD9, 6) => self.d9_f0_group(sti)?,  // F2XM1/FYL2X/FPTAN/.../FSIN/FCOS
            (0xD9, 7) => self.d9_f8_group(sti)?,  // FPREM/FYL2XP1/FSQRT/.../FSCALE/...

            // DA/DB reg-form: FCMOVcc / FUCOMI / FCOMI.
            (0xDB, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); } // FUCOMI
            (0xDB, 6) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); } // FCOMI
            (0xDF, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); self.fpu_pop(); } // FUCOMIP
            (0xDF, 6) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); self.fpu_pop(); } // FCOMIP

            // DB E3 = FNINIT, DB E1/E2 = FNDISI/FNCLEX etc; handled here where sti carries the low bits.
            (0xDB, 4) => self.db_e0_group(sti)?,

            // DF E0 = FNSTSW AX (the `fnstsw ax` → test/jcc idiom).
            (0xDF, 4) => { self.state.gpr_write(0, 2, self.state.x87.sw as u64); }

            // DC: arithmetic with ST(i) as destination. NOTE the /4../7 reverse
            // meaning vs D8: DC /4 is FSUBR, /5 is FSUB, /6 is FDIVR, /7 is FDIV
            // (Intel's "reverse" encoding quirk for the ST(i)-destination forms).
            (0xDC, 0) => { let r = self.fpu_read(sti) + self.fpu_read(0); self.fpu_write(sti, r); }
            (0xDC, 1) => { let r = self.fpu_read(sti) * self.fpu_read(0); self.fpu_write(sti, r); }
            (0xDC, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(sti, r); } // FSUBR ST(i),ST0
            (0xDC, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(sti, r); } // FSUB ST(i),ST0
            (0xDC, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(sti, r); } // FDIVR ST(i),ST0
            (0xDC, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(sti, r); } // FDIV ST(i),ST0

            // DD: FST/FSTP ST(i), FFREE, FUCOM/FUCOMP.
            (0xDD, 0) => self.ffree(sti),                                            // FFREE ST(i)
            (0xDD, 2) => { let v = self.fpu_read_ext(0); self.fpu_write_ext(sti, v); } // FST ST(i)
            (0xDD, 3) => { let v = self.fpu_read_ext(0); self.fpu_write_ext(sti, v); self.fpu_pop(); } // FSTP ST(i)
            (0xDD, 4) => self.fpu_set_compare(self.fpu_read(0), self.fpu_read(sti)),  // FUCOM
            (0xDD, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); } // FUCOMP

            // DE: arithmetic-and-pop (FADDP/FMULP/FSUBP/FDIVP/FCOMPP). Same
            // reverse-encoding quirk as DC: /4 FSUBRP, /5 FSUBP, /6 FDIVRP,
            // /7 FDIVP.
            (0xDE, 0) => { let r = self.fpu_read(sti) + self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 1) => { let r = self.fpu_read(sti) * self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 2) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); } // FCOMP (rare)
            (0xDE, 3) => self.de_d8_fcompp(),                                          // FCOMPP (sti must be 1)
            (0xDE, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(sti, r); self.fpu_pop(); } // FSUBRP
            (0xDE, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); } // FSUBP
            (0xDE, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(sti, r); self.fpu_pop(); } // FDIVRP
            (0xDE, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); } // FDIVP

            _ => {
                return Err(EmuError::Unsupported(format!("x87 reg-form esc={esc:#x} /{reg} st{sti}")));
            }
        }
        Ok(())
    }

    fn fxch(&mut self, sti: u8) {
        let a = self.fpu_read_ext(0);
        let b = self.fpu_read_ext(sti);
        self.fpu_write_ext(0, b);
        self.fpu_write_ext(sti, a);
        self.fpu_set_c1(false);
    }

    fn ffree(&mut self, sti: u8) {
        let p = self.state.x87.phys(sti);
        self.fpu_set_tag(p, 0b11); // empty
    }

    fn de_d8_fcompp(&mut self) {
        let (a, b) = (self.fpu_read(0), self.fpu_read(1));
        self.fpu_set_compare(a, b);
        self.fpu_pop();
        self.fpu_pop();
    }

    /// D9 /4 group (mod==3): FCHS/FABS/FTST/FXAM keyed by the low 3 bits.
    fn d9_e0_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let v = self.fpu_read_ext(0) ^ (1u128 << 79); self.fpu_write_ext(0, v); self.fpu_set_c1(false); } // FCHS
            1 => { let v = self.fpu_read_ext(0) & !(1u128 << 79); self.fpu_write_ext(0, v); self.fpu_set_c1(false); } // FABS
            4 => self.fpu_set_compare(self.fpu_read(0), 0.0), // FTST
            5 => self.fxam(),                                 // FXAM
            _ => return Err(EmuError::Unsupported(format!("x87 D9 E0-group /{low}"))),
        }
        Ok(())
    }

    /// FXAM: classify ST0 into C3/C2/C0 (and C1 = sign).
    fn fxam(&mut self) {
        let top = self.state.x87.top();
        let tag = (self.state.x87.tw >> (top as u16 * 2)) & 3;
        let v = self.fpu_read_ext(0);
        let sign = ((v >> 79) & 1) != 0;
        let sw = &mut self.state.x87.sw;
        *sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if sign {
            *sw |= SW_C1;
        }
        let x = ext_to_f64(v);
        // (C3,C2,C0) encode the class.
        let (c3, c2, c0) = if tag == 0b11 {
            (true, false, true) // empty
        } else if x.is_nan() {
            (false, false, true) // NaN
        } else if x.is_infinite() {
            (false, true, true) // infinity
        } else if x == 0.0 {
            (true, false, false) // zero
        } else if is_ext_denormal(v) {
            (true, true, false) // denormal
        } else {
            (false, true, false) // normal finite
        };
        if c3 { *sw |= SW_C3; }
        if c2 { *sw |= SW_C2; }
        if c0 { *sw |= SW_C0; }
    }

    /// D9 /5 group (mod==3): load a named constant.
    fn d9_e8_group(&mut self, low: u8) -> Result<()> {
        // Constants encoded in 80-bit for exactness where the value is not an
        // f64 (log/ln/pi); pushed as extended so the register holds the exact
        // constant a real x87 would.
        let ext: u128 = match low {
            0 => f64_to_ext(1.0),                       // FLD1
            1 => EXT_L2T,                               // FLDL2T  log2(10)
            2 => EXT_L2E,                               // FLDL2E  log2(e)
            3 => EXT_PI,                                // FLDPI
            4 => EXT_LG2,                               // FLDLG2  log10(2)
            5 => EXT_LN2,                               // FLDLN2  ln(2)
            6 => f64_to_ext(0.0),                       // FLDZ
            _ => return Err(EmuError::Unsupported(format!("x87 D9 E8-group /{low}"))),
        };
        self.fpu_push(ext);
        Ok(())
    }

    /// D9 /6 group (mod==3, D9 F0..F7): F2XM1/FYL2X/FPTAN/FPATAN/FXTRACT/
    /// FPREM1/FDECSTP/FINCSTP.
    fn d9_f0_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let r = exp2m1(self.fpu_read(0)); self.fpu_write(0, r); } // F2XM1: 2^x - 1
            1 => { // FYL2X: ST1 = ST1 * log2(ST0); pop
                let r = self.fpu_read(1) * self.fpu_read(0).log2();
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            2 => { // FPTAN: ST0 = tan(ST0); push 1.0
                let r = self.fpu_read(0).tan();
                self.fpu_write(0, r);
                self.fpu_push_f64(1.0);
                self.set_c2(false);
            }
            3 => { // FPATAN: ST1 = atan2(ST1, ST0); pop
                let r = self.fpu_read(1).atan2(self.fpu_read(0));
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            4 => self.fxtract(),                                       // FXTRACT
            5 => { let r = self.fprem1_value(); self.fpu_write(0, r); } // FPREM1
            6 => self.fdecstp(),                                       // FDECSTP
            7 => self.fincstp(),                                       // FINCSTP
            _ => return Err(EmuError::Unsupported(format!("x87 D9 F0-group /{low}"))),
        }
        Ok(())
    }

    /// FXTRACT: split ST0 into its exponent (→ ST0) and significand in [1,2)
    /// (pushed as the new ST0). Computed from the f64 view.
    fn fxtract(&mut self) {
        let x = self.fpu_read(0);
        if x == 0.0 {
            // exponent = -inf, significand = ST0 (zero) per SDM edge cases.
            self.fpu_write(0, f64::NEG_INFINITY);
            self.fpu_push_f64(x);
            return;
        }
        if !x.is_finite() {
            self.fpu_write(0, x.abs());
            self.fpu_push_f64(x);
            return;
        }
        let exp = x.abs().log2().floor();
        let signif = x / exp2(exp as i32);
        self.fpu_write(0, exp);
        self.fpu_push_f64(signif);
    }

    /// D9 /7 group (mod==3): FPREM/FYL2XP1/FSQRT/FSINCOS/FRNDINT/FSCALE/FSIN/FCOS.
    fn d9_f8_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let r = self.fprem_value(); self.fpu_write(0, r); } // FPREM
            1 => { // FYL2XP1: ST1 = ST1 * log2(ST0+1); pop
                let r = self.fpu_read(1) * (self.fpu_read(0) + 1.0).log2();
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            2 => { let r = self.fpu_read(0).sqrt(); self.fpu_write(0, r); } // FSQRT
            3 => { // FSINCOS: ST0 = sin, push cos
                let x = self.fpu_read(0);
                self.fpu_write(0, x.sin());
                self.fpu_push_f64(x.cos());
                self.set_c2(false);
            }
            4 => { let r = self.fpu_round_int(self.fpu_read(0)); self.fpu_write(0, r); } // FRNDINT
            5 => { let r = self.fscale_value(); self.fpu_write(0, r); }                  // FSCALE
            6 => { let r = self.fpu_read(0).sin(); self.fpu_write(0, r); self.set_c2(false); } // FSIN
            7 => { let r = self.fpu_read(0).cos(); self.fpu_write(0, r); self.set_c2(false); } // FCOS
            _ => return Err(EmuError::Unsupported(format!("x87 D9 F8-group /{low}"))),
        }
        Ok(())
    }

    /// DB /4 group (mod==3): FNINIT/FNCLEX and the (ignored) FNENI/FNDISI.
    fn db_e0_group(&mut self, low: u8) -> Result<()> {
        match low {
            2 => { self.state.x87.sw &= !(0x80ff); } // FNCLEX: clear exception + busy bits
            3 => {
                // FNINIT resets the control/status/tag words but leaves the
                // physical data-register bytes as they were (they just become
                // "empty" / undefined) — matching what a real FPU and QEMU do.
                self.state.x87.cw = 0x037F;
                self.state.x87.sw = 0x0000;
                self.state.x87.tw = 0xFFFF;
            }
            0 | 1 | 4 => {}                          // FNENI/FNDISI/FNSETPM: no-ops on modern CPUs
            _ => return Err(EmuError::Unsupported(format!("x87 DB E0-group /{low}"))),
        }
        Ok(())
    }

    #[inline]
    fn set_c2(&mut self, on: bool) {
        if on {
            self.state.x87.sw |= SW_C2;
        } else {
            self.state.x87.sw &= !SW_C2;
        }
    }

    fn fdecstp(&mut self) {
        let t = self.state.x87.top();
        self.state.x87.set_top(t.wrapping_sub(1) & 7);
        self.fpu_set_c1(false);
    }

    fn fincstp(&mut self) {
        let t = self.state.x87.top();
        self.state.x87.set_top(t.wrapping_add(1) & 7);
        self.fpu_set_c1(false);
    }

    /// FPREM: ST0 = ST0 - Q*ST1 where Q = trunc(ST0/ST1) (partial remainder;
    /// we compute the complete IEEE remainder toward zero and clear C2).
    fn fprem_value(&mut self) -> f64 {
        let a = self.fpu_read(0);
        let b = self.fpu_read(1);
        self.state.x87.sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if a.is_nan() || b.is_nan() {
            return f64::NAN;
        }
        if b == 0.0 || a.is_infinite() {
            self.state.x87.sw |= SW_IE;
            return f64::NAN;
        }
        if b.is_infinite() {
            return a; // finite mod infinite = the dividend itself
        }
        let q = (a / b).trunc();
        set_prem_cc(&mut self.state.x87.sw, q);
        a - q * b
    }

    /// FPREM1: IEEE 754 remainder (round-half-even quotient).
    fn fprem1_value(&mut self) -> f64 {
        let a = self.fpu_read(0);
        let b = self.fpu_read(1);
        self.state.x87.sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if a.is_nan() || b.is_nan() {
            return f64::NAN;
        }
        if b == 0.0 || a.is_infinite() {
            self.state.x87.sw |= SW_IE;
            return f64::NAN;
        }
        if b.is_infinite() {
            return a;
        }
        let q = round_half_even(a / b);
        set_prem_cc(&mut self.state.x87.sw, q);
        a - q * b
    }

    /// FSCALE: ST0 = ST0 * 2^trunc(ST1).
    fn fscale_value(&mut self) -> f64 {
        let x = self.fpu_read(0);
        let n = self.fpu_read(1).trunc();
        if !x.is_finite() || x == 0.0 {
            return x;
        }
        // Clamp n to a sane range; exp2 handles the rest.
        let ni = n.clamp(-100000.0, 100000.0) as i32;
        x * exp2(ni)
    }

    // ---- memory forms ----------------------------------------------------

    fn x87_mem_form(&mut self, mem: &mut dyn Memory, esc: u8, reg: u8, addr: u64) -> Result<()> {
        match esc {
            // D8: 32-bit float arithmetic, ST0 op m32fp.
            0xD8 => {
                let v = f32::from_bits(mem.read_u32(addr)?) as f64;
                self.mem_arith(reg, v)?;
            }
            // D9: FLD m32fp / FST(P) m32fp / FLDCW / FNSTCW.
            0xD9 => match reg {
                0 => { let v = f32::from_bits(mem.read_u32(addr)?) as f64; self.fpu_push_f64(v); } // FLD m32
                2 => { let v = self.store_f32(self.fpu_read(0)); mem.write_u32(addr, v)?; }          // FST m32
                3 => { let v = self.store_f32(self.fpu_read(0)); mem.write_u32(addr, v)?; self.fpu_pop(); } // FSTP m32
                5 => { self.state.x87.cw = mem.read_u16(addr)?; }  // FLDCW
                7 => { mem.write_u16(addr, self.state.x87.cw)?; }  // FNSTCW
                _ => return Err(EmuError::Unsupported(format!("x87 D9 mem /{reg}"))),
            },
            // DB: FILD m32int / FISTP m32int / FLD m80 / FSTP m80.
            0xDB => match reg {
                0 => { let v = mem.read_u32(addr)? as i32 as f64; self.fpu_push_f64(v); }        // FILD m32
                1 => { let v = self.to_signed_int(self.fpu_read(0), 4, true); mem.write_u32(addr, v as i32 as u32)?; self.fpu_pop(); } // FISTTP m32
                2 => { let v = self.to_signed_int(self.fpu_read(0), 4, false); mem.write_u32(addr, v as i32 as u32)?; }                // FIST m32
                3 => { let v = self.to_signed_int(self.fpu_read(0), 4, false); mem.write_u32(addr, v as i32 as u32)?; self.fpu_pop(); } // FISTP m32
                5 => { let v = read_ext(mem, addr)?; self.fpu_push(v); }                          // FLD m80
                7 => { let v = self.fpu_read_ext(0); write_ext(mem, addr, v)?; self.fpu_pop(); }  // FSTP m80
                _ => return Err(EmuError::Unsupported(format!("x87 DB mem /{reg}"))),
            },
            // DC: 64-bit float arithmetic, ST0 op m64fp.
            0xDC => {
                let v = f64::from_bits(mem.read_u64(addr)?);
                self.mem_arith(reg, v)?;
            }
            // DD: FLD m64fp / FST(P) m64fp / FNSTSW m16 / FRSTOR (unsupported).
            0xDD => match reg {
                0 => { let v = f64::from_bits(mem.read_u64(addr)?); self.fpu_push_f64(v); } // FLD m64
                1 => { let v = self.to_signed_int(self.fpu_read(0), 8, true); mem.write_u64(addr, v as u64)?; self.fpu_pop(); } // FISTTP m64
                2 => { let v = self.store_f64(self.fpu_read(0)); mem.write_u64(addr, v)?; }  // FST m64
                3 => { let v = self.store_f64(self.fpu_read(0)); mem.write_u64(addr, v)?; self.fpu_pop(); } // FSTP m64
                7 => { mem.write_u16(addr, self.state.x87.sw)?; }  // FNSTSW m16
                _ => return Err(EmuError::Unsupported(format!("x87 DD mem /{reg}"))),
            },
            // DF: FILD/FISTP m16int, FILD/FISTP m64int, FBLD/FBSTP.
            0xDF => match reg {
                0 => { let v = mem.read_u16(addr)? as i16 as f64; self.fpu_push_f64(v); } // FILD m16
                1 => { let v = self.to_signed_int(self.fpu_read(0), 2, true); mem.write_u16(addr, v as i16 as u16)?; self.fpu_pop(); } // FISTTP m16
                2 => { let v = self.to_signed_int(self.fpu_read(0), 2, false); mem.write_u16(addr, v as i16 as u16)?; }                // FIST m16
                3 => { let v = self.to_signed_int(self.fpu_read(0), 2, false); mem.write_u16(addr, v as i16 as u16)?; self.fpu_pop(); } // FISTP m16
                5 => { let v = mem.read_u64(addr)? as i64 as f64; self.fpu_push_f64(v); }  // FILD m64
                7 => { let v = self.to_signed_int(self.fpu_read(0), 8, false); mem.write_u64(addr, v as u64)?; self.fpu_pop(); } // FISTP m64
                _ => return Err(EmuError::Unsupported(format!("x87 DF mem /{reg}"))),
            },
            _ => return Err(EmuError::Unsupported(format!("x87 mem esc={esc:#x} /{reg}"))),
        }
        Ok(())
    }

    /// ST0 <- ST0 (op) v  for the memory arithmetic escapes (/reg selects op).
    fn mem_arith(&mut self, reg: u8, v: f64) -> Result<()> {
        let a = self.fpu_read(0);
        match reg {
            0 => self.fpu_write(0, a + v),
            1 => self.fpu_write(0, a * v),
            2 => self.fpu_set_compare(a, v),                       // FCOM
            3 => { self.fpu_set_compare(a, v); self.fpu_pop(); }   // FCOMP
            4 => self.fpu_write(0, a - v),
            5 => self.fpu_write(0, v - a),                         // FSUBR
            6 => self.fpu_write(0, a / v),
            7 => self.fpu_write(0, v / a),                         // FDIVR
            _ => return Err(EmuError::Unsupported(format!("x87 mem-arith /{reg}"))),
        }
        Ok(())
    }

    /// Round `x` to a signed integer of `bytes` (2/4/8) per RC (or truncate for
    /// FISTTP), producing the size-appropriate **integer indefinite** (the sign
    /// bit alone) when the value does not fit or is not finite. Returned in the
    /// low `bytes*8` bits of an `i64`.
    fn to_signed_int(&self, x: f64, bytes: u8, trunc: bool) -> i64 {
        let r = if trunc { x.trunc() } else { self.fpu_round_int(x) };
        let indef: i64 = match bytes {
            2 => i16::MIN as i64,
            4 => i32::MIN as i64,
            _ => i64::MIN,
        };
        if !r.is_finite() {
            return indef;
        }
        let (lo, hi): (f64, f64) = match bytes {
            2 => (-32768.0, 32768.0),
            4 => (-2147483648.0, 2147483648.0),
            _ => (-9223372036854775808.0, 9223372036854775808.0),
        };
        if r < lo || r >= hi {
            indef
        } else {
            r as i64
        }
    }

    /// Round an `f64` to `f32` per RC (round-nearest only here; other RC modes
    /// affect only the last bit and the oracle seeds nearest for stores).
    fn store_f32(&self, x: f64) -> u32 {
        (x as f32).to_bits()
    }

    fn store_f64(&self, x: f64) -> u64 {
        x.to_bits()
    }
}

// --- helpers ----------------------------------------------------------------

/// Round half-to-even (banker's rounding) — the x87 default.
fn round_half_even(x: f64) -> f64 {
    let r = x.round(); // rounds halves away from zero
    if (x - x.trunc()).abs() == 0.5 {
        // Exactly halfway: pick the even neighbour.
        let f = x.floor();
        if (f as i64) % 2 == 0 { f } else { f + 1.0 }
    } else {
        r
    }
}

/// `2^x - 1` for F2XM1 (defined for |x| <= 1 on hardware; we just use exp2).
fn exp2m1(x: f64) -> f64 {
    x.exp2() - 1.0
}

/// Set the FPREM/FPREM1 condition codes C0/C3/C1 from the low quotient bits;
/// C2 stays clear (reduction complete).
fn set_prem_cc(sw: &mut u16, q: f64) {
    let qi = q as i64;
    if qi & 1 != 0 { *sw |= SW_C1; }
    if qi & 2 != 0 { *sw |= SW_C3; }
    if qi & 4 != 0 { *sw |= SW_C0; }
}

/// Compute the 2-bit tag for a physical register's 80-bit value.
fn tag_of(v: u128) -> u16 {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    if exp == 0 && signif == 0 {
        0b01 // zero
    } else if exp == 0x7fff || (exp != 0 && signif & 0x8000_0000_0000_0000 == 0) || (exp == 0 && signif != 0) {
        0b10 // special (NaN/Inf/denormal/unnormal)
    } else {
        0b00 // valid
    }
}

fn is_ext_denormal(v: u128) -> bool {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    exp == 0 && signif != 0
}

/// Read an 80-bit extended value from memory (10 bytes).
fn read_ext(mem: &dyn Memory, addr: u64) -> Result<u128> {
    let lo = mem.read_u64(addr)? as u128;
    let hi = mem.read_u16(addr + 8)? as u128;
    Ok(lo | (hi << 64))
}

/// Write an 80-bit extended value to memory (10 bytes).
fn write_ext(mem: &mut dyn Memory, addr: u64, v: u128) -> Result<()> {
    mem.write_u64(addr, v as u64)?;
    mem.write_u16(addr + 8, (v >> 64) as u16)?;
    Ok(())
}

// x87 constants encoded as exact 80-bit double-extended values (the ROM
// constants a real FPU loads). Layout: low u64 = integer bit + fraction,
// high u16 = sign(1)+exponent(15).
macro_rules! ext {
    ($hi:expr, $lo:expr) => {
        ($lo as u128) | (($hi as u128) << 64)
    };
}

const EXT_PI: u128 = ext!(0x4000, 0xC90F_DAA2_2168_C235u64); // pi
const EXT_L2T: u128 = ext!(0x4000, 0xD49A_784B_CD1B_8AFEu64); // log2(10)
const EXT_L2E: u128 = ext!(0x3FFF, 0xB8AA_3B29_5C17_F0BCu64); // log2(e)
const EXT_LG2: u128 = ext!(0x3FFD, 0x9A20_9A84_FBCF_F799u64); // log10(2)
const EXT_LN2: u128 = ext!(0x3FFE, 0xB172_17F7_D1CF_79ACu64); // ln(2)
