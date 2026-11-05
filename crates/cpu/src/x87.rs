use exemu_core::{EmuError, Memory, Result};

use crate::{Ctx, Interpreter, Rm};

const SW_C0: u16 = 1 << 8;
const SW_C1: u16 = 1 << 9;
const SW_C2: u16 = 1 << 10;
const SW_C3: u16 = 1 << 14;
const SW_IE: u16 = 1 << 0;

pub(crate) fn f64_to_ext(x: f64) -> u128 {
    let bits = x.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7ff) as u32;
    let frac = bits & 0x000f_ffff_ffff_ffff;

    let (ext_exp, ext_signif): (u32, u64) = if exp == 0x7ff {
        let signif = if frac == 0 {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000_0000_0000 | (frac << 11)
        };
        (0x7fff, signif)
    } else if exp == 0 {
        if frac == 0 {
            (0, 0)
        } else {
            let lead = frac.leading_zeros() - 11;
            let signif = frac << (11 + lead + 1);
            let e = 1_i32 - 1023 - (lead as i32) - 1 + 16383;
            (e as u32, 0x8000_0000_0000_0000 | signif)
        }
    } else {
        let e = exp + (16383 - 1023);
        let signif = 0x8000_0000_0000_0000 | (frac << 11);
        (e, signif)
    };

    ((sign as u128) << 79) | ((ext_exp as u128) << 64) | (ext_signif as u128)
}

pub(crate) fn ext_to_f64(v: u128) -> f64 {
    let sign = ((v >> 79) & 1) as u64;
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;

    if exp == 0x7fff {
        let frac = signif & 0x7fff_ffff_ffff_ffff;
        return if frac == 0 {
            if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY }
        } else {
            let payload = frac >> 11;
            let bits = (sign << 63) | (0x7ff << 52) | payload | 0x0008_0000_0000_0000;
            f64::from_bits(bits)
        };
    }
    if exp == 0 && signif == 0 {
        return f64::from_bits(sign << 63);
    }

    let mantissa = signif as f64;
    let e2 = exp as i32 - 16383 - 63;
    let mag = mantissa * exp2(e2);
    if sign == 1 { -mag } else { mag }
}

fn exp2(n: i32) -> f64 {
    if n > 1100 {
        f64::INFINITY
    } else if n < -1100 {
        0.0
    } else {
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

    #[inline]
    fn fpu_read_ext(&self, i: u8) -> u128 {
        let p = self.state.x87.phys(i);
        self.state.x87.st[p]
    }

    #[inline]
    fn fpu_read(&self, i: u8) -> f64 {
        ext_to_f64(self.fpu_read_ext(i))
    }

    #[inline]
    fn fpu_write_ext(&mut self, i: u8, v: u128) {
        let p = self.state.x87.phys(i);
        self.state.x87.st[p] = v & ((1u128 << 80) - 1);
        self.fpu_set_tag(p, tag_of(self.state.x87.st[p]));
    }

    #[inline]
    fn fpu_write(&mut self, i: u8, x: f64) {
        self.fpu_write_ext(i, f64_to_ext(x));
    }

    #[inline]
    fn fpu_set_tag(&mut self, phys: usize, tag: u16) {
        let shift = (phys as u16) * 2;
        self.state.x87.tw = (self.state.x87.tw & !(0b11 << shift)) | ((tag & 0b11) << shift);
    }

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

    fn fpu_pop(&mut self) {
        let top = self.state.x87.top();
        self.fpu_set_tag(top as usize, 0b11);
        self.state.x87.set_top(top.wrapping_add(1) & 7);
    }

    #[inline]
    fn fpu_set_c1(&mut self, on: bool) {
        if on {
            self.state.x87.sw |= SW_C1;
        } else {
            self.state.x87.sw &= !SW_C1;
        }
    }

    fn fpu_set_compare(&mut self, a: f64, b: f64) {
        let sw = &mut self.state.x87.sw;
        *sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if a.is_nan() || b.is_nan() {
            *sw |= SW_C0 | SW_C2 | SW_C3;
        } else if a < b {
            *sw |= SW_C0;
        } else if a > b {
        } else {
            *sw |= SW_C3;
        }
    }

    fn fpu_set_compare_eflags(&mut self, a: f64, b: f64) {
        use exemu_core::cpu::flags::{CF, OF, PF, SF, ZF, AF};
        let (zf, pf, cf) = if a.is_nan() || b.is_nan() {
            (true, true, true)
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

    fn fpu_round_int(&self, x: f64) -> f64 {
        if !x.is_finite() {
            return x;
        }
        let r = match (self.state.x87.cw >> 10) & 3 {
            0 => round_half_even(x),
            1 => x.floor(),
            2 => x.ceil(),
            _ => x.trunc(),
        };
        if r == 0.0 && x.is_sign_negative() {
            -0.0
        } else {
            r
        }
    }

    pub(crate) fn exec_x87(&mut self, ctx: &mut Ctx, mem: &mut dyn Memory, esc: u8) -> Result<()> {
        let modrm = ctx.u8(mem)?;
        let mod_ = modrm >> 6;
        let reg = (modrm >> 3) & 7;

        if mod_ == 3 {
            let sti = modrm & 7;
            self.x87_reg_form(ctx, mem, esc, reg, sti)
        } else {
            ctx.cur -= 1;
            self.read_modrm(ctx, mem)?;
            let addr = match ctx.rm {
                Rm::Mem { .. } => ctx.rm_addr(),
                Rm::Reg(_) => unreachable!("mod!=3 decoded as register"),
            };
            self.x87_mem_form(mem, esc, reg, addr, Self::opsize(ctx) == 2)
        }
    }

    fn x87_reg_form(&mut self, _ctx: &mut Ctx, _mem: &mut dyn Memory, esc: u8, reg: u8, sti: u8) -> Result<()> {
        match (esc, reg) {
            (0xD8, 0) => { let r = self.fpu_read(0) + self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 1) => { let r = self.fpu_read(0) * self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 2) => self.fpu_set_compare(self.fpu_read(0), self.fpu_read(sti)),
            (0xD8, 3) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); }
            (0xD8, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(0, r); }
            (0xD8, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(0, r); }
            (0xD8, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(0, r); }

            (0xD9, 0) => { let v = self.fpu_read_ext(sti); self.fpu_push(v); }
            (0xD9, 1) => self.fxch(sti),
            (0xD9, 4) => self.d9_e0_group(sti)?,
            (0xD9, 5) => self.d9_e8_group(sti)?,
            (0xD9, 6) => self.d9_f0_group(sti)?,
            (0xD9, 7) => self.d9_f8_group(sti)?,

            (0xDB, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); }
            (0xDB, 6) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); }
            (0xDF, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); self.fpu_pop(); }
            (0xDF, 6) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare_eflags(a, b); self.fpu_pop(); }

            (0xDB, 4) => self.db_e0_group(sti)?,

            (0xDF, 4) => { self.state.gpr_write(0, 2, self.state.x87.sw as u64); }

            (0xDC, 0) => { let r = self.fpu_read(sti) + self.fpu_read(0); self.fpu_write(sti, r); }
            (0xDC, 1) => { let r = self.fpu_read(sti) * self.fpu_read(0); self.fpu_write(sti, r); }
            (0xDC, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(sti, r); }
            (0xDC, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(sti, r); }
            (0xDC, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(sti, r); }
            (0xDC, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(sti, r); }

            (0xDD, 0) => self.ffree(sti),
            (0xDD, 2) => { let v = self.fpu_read_ext(0); self.fpu_write_ext(sti, v); }
            (0xDD, 3) => { let v = self.fpu_read_ext(0); self.fpu_write_ext(sti, v); self.fpu_pop(); }
            (0xDD, 4) => self.fpu_set_compare(self.fpu_read(0), self.fpu_read(sti)),
            (0xDD, 5) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); }

            (0xDE, 0) => { let r = self.fpu_read(sti) + self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 1) => { let r = self.fpu_read(sti) * self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 2) => { let (a, b) = (self.fpu_read(0), self.fpu_read(sti)); self.fpu_set_compare(a, b); self.fpu_pop(); }
            (0xDE, 3) => self.de_d8_fcompp(),
            (0xDE, 4) => { let r = self.fpu_read(0) - self.fpu_read(sti); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 5) => { let r = self.fpu_read(sti) - self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 6) => { let r = self.fpu_read(0) / self.fpu_read(sti); self.fpu_write(sti, r); self.fpu_pop(); }
            (0xDE, 7) => { let r = self.fpu_read(sti) / self.fpu_read(0); self.fpu_write(sti, r); self.fpu_pop(); }

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
        self.fpu_set_tag(p, 0b11);
    }

    fn de_d8_fcompp(&mut self) {
        let (a, b) = (self.fpu_read(0), self.fpu_read(1));
        self.fpu_set_compare(a, b);
        self.fpu_pop();
        self.fpu_pop();
    }

    fn d9_e0_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let v = self.fpu_read_ext(0) ^ (1u128 << 79); self.fpu_write_ext(0, v); self.fpu_set_c1(false); }
            1 => { let v = self.fpu_read_ext(0) & !(1u128 << 79); self.fpu_write_ext(0, v); self.fpu_set_c1(false); }
            4 => self.fpu_set_compare(self.fpu_read(0), 0.0),
            5 => self.fxam(),
            _ => return Err(EmuError::Unsupported(format!("x87 D9 E0-group /{low}"))),
        }
        Ok(())
    }

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
        let (c3, c2, c0) = if tag == 0b11 {
            (true, false, true)
        } else if x.is_nan() {
            (false, false, true)
        } else if x.is_infinite() {
            (false, true, true)
        } else if x == 0.0 {
            (true, false, false)
        } else if is_ext_denormal(v) {
            (true, true, false)
        } else {
            (false, true, false)
        };
        if c3 { *sw |= SW_C3; }
        if c2 { *sw |= SW_C2; }
        if c0 { *sw |= SW_C0; }
    }

    fn d9_e8_group(&mut self, low: u8) -> Result<()> {
        let ext: u128 = match low {
            0 => f64_to_ext(1.0),
            1 => EXT_L2T,
            2 => EXT_L2E,
            3 => EXT_PI,
            4 => EXT_LG2,
            5 => EXT_LN2,
            6 => f64_to_ext(0.0),
            _ => return Err(EmuError::Unsupported(format!("x87 D9 E8-group /{low}"))),
        };
        self.fpu_push(ext);
        Ok(())
    }

    fn d9_f0_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let r = exp2m1(self.fpu_read(0)); self.fpu_write(0, r); }
            1 => {
                let r = self.fpu_read(1) * self.fpu_read(0).log2();
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            2 => {
                let r = self.fpu_read(0).tan();
                self.fpu_write(0, r);
                self.fpu_push_f64(1.0);
                self.set_c2(false);
            }
            3 => {
                let r = self.fpu_read(1).atan2(self.fpu_read(0));
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            4 => self.fxtract(),
            5 => { let r = self.fprem1_value(); self.fpu_write(0, r); }
            6 => self.fdecstp(),
            7 => self.fincstp(),
            _ => return Err(EmuError::Unsupported(format!("x87 D9 F0-group /{low}"))),
        }
        Ok(())
    }

    fn fxtract(&mut self) {
        let x = self.fpu_read(0);
        if x == 0.0 {
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

    fn d9_f8_group(&mut self, low: u8) -> Result<()> {
        match low {
            0 => { let r = self.fprem_value(); self.fpu_write(0, r); }
            1 => {
                let r = self.fpu_read(1) * (self.fpu_read(0) + 1.0).log2();
                self.fpu_write(1, r);
                self.fpu_pop();
            }
            2 => { let r = self.fpu_read(0).sqrt(); self.fpu_write(0, r); }
            3 => {
                let x = self.fpu_read(0);
                self.fpu_write(0, x.sin());
                self.fpu_push_f64(x.cos());
                self.set_c2(false);
            }
            4 => { let r = self.fpu_round_int(self.fpu_read(0)); self.fpu_write(0, r); }
            5 => { let r = self.fscale_value(); self.fpu_write(0, r); }
            6 => { let r = self.fpu_read(0).sin(); self.fpu_write(0, r); self.set_c2(false); }
            7 => { let r = self.fpu_read(0).cos(); self.fpu_write(0, r); self.set_c2(false); }
            _ => return Err(EmuError::Unsupported(format!("x87 D9 F8-group /{low}"))),
        }
        Ok(())
    }

    fn db_e0_group(&mut self, low: u8) -> Result<()> {
        match low {
            2 => { self.state.x87.sw &= !(0x80ff); }
            3 => self.fninit(),
            0 | 1 | 4 => {}
            _ => return Err(EmuError::Unsupported(format!("x87 DB E0-group /{low}"))),
        }
        Ok(())
    }

    fn fninit(&mut self) {
        self.state.x87.cw = 0x037F;
        self.state.x87.sw = 0x0000;
        self.state.x87.tw = 0xFFFF;
    }

    fn saved_tag_word(&self) -> u16 {
        let x = &self.state.x87;
        let mut out = 0u16;
        for phys in 0..8usize {
            let tag = if (x.tw >> (phys * 2)) & 0b11 == 0b11 { 0b11 } else { tag_of(x.st[phys]) };
            out |= tag << (phys * 2);
        }
        out
    }

    fn fnstenv(&self, mem: &mut dyn Memory, addr: u64, env16: bool) -> Result<()> {
        let x = &self.state.x87;
        let tw = self.saved_tag_word();
        if env16 {
            mem.write_u16(addr, x.cw)?;
            mem.write_u16(addr + 2, x.sw)?;
            mem.write_u16(addr + 4, tw)?;
            mem.write_u16(addr + 6, x.fip as u16)?;
            mem.write_u16(addr + 8, x.fcs)?;
            mem.write_u16(addr + 10, x.fdp as u16)?;
            mem.write_u16(addr + 12, x.fds)?;
        } else {
            mem.write_u32(addr, u32::from(x.cw))?;
            mem.write_u32(addr + 4, u32::from(x.sw))?;
            mem.write_u32(addr + 8, u32::from(tw))?;
            mem.write_u32(addr + 12, x.fip as u32)?;
            mem.write_u32(addr + 16, u32::from(x.fcs) | (u32::from(x.fop & 0x7FF) << 16))?;
            mem.write_u32(addr + 20, x.fdp as u32)?;
            mem.write_u32(addr + 24, u32::from(x.fds))?;
        }
        Ok(())
    }

    fn fldenv(&mut self, mem: &mut dyn Memory, addr: u64, env16: bool) -> Result<()> {
        if env16 {
            let cw = mem.read_u16(addr)?;
            let sw = mem.read_u16(addr + 2)?;
            let tw = mem.read_u16(addr + 4)?;
            let ip = mem.read_u16(addr + 6)?;
            let cs = mem.read_u16(addr + 8)?;
            let dp = mem.read_u16(addr + 10)?;
            let ds = mem.read_u16(addr + 12)?;
            let x = &mut self.state.x87;
            x.cw = cw;
            x.sw = sw;
            x.tw = tw;
            x.fip = u64::from(ip);
            x.fcs = cs;
            x.fdp = u64::from(dp);
            x.fds = ds;
        } else {
            let cw = mem.read_u16(addr)?;
            let sw = mem.read_u16(addr + 4)?;
            let tw = mem.read_u16(addr + 8)?;
            let ip = mem.read_u32(addr + 12)?;
            let csop = mem.read_u32(addr + 16)?;
            let dp = mem.read_u32(addr + 20)?;
            let ds = mem.read_u16(addr + 24)?;
            let x = &mut self.state.x87;
            x.cw = cw;
            x.sw = sw;
            x.tw = tw;
            x.fip = u64::from(ip);
            x.fcs = csop as u16;
            x.fop = ((csop >> 16) & 0x7FF) as u16;
            x.fdp = u64::from(dp);
            x.fds = ds;
        }
        Ok(())
    }

    fn fnsave(&mut self, mem: &mut dyn Memory, addr: u64, env16: bool) -> Result<()> {
        self.fnstenv(mem, addr, env16)?;
        let regs = addr + if env16 { 14 } else { 28 };
        for i in 0..8u8 {
            let v = self.fpu_read_ext(i);
            write_ext(mem, regs + u64::from(i) * 10, v)?;
        }
        self.fninit();
        Ok(())
    }

    fn frstor(&mut self, mem: &mut dyn Memory, addr: u64, env16: bool) -> Result<()> {
        self.fldenv(mem, addr, env16)?;
        let regs = addr + if env16 { 14 } else { 28 };
        for i in 0..8u8 {
            let v = read_ext(mem, regs + u64::from(i) * 10)?;
            let p = self.state.x87.phys(i);
            self.state.x87.st[p] = v;
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
            return a;
        }
        let q = (a / b).trunc();
        set_prem_cc(&mut self.state.x87.sw, q);
        a - q * b
    }

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

    fn fscale_value(&mut self) -> f64 {
        let x = self.fpu_read(0);
        let n = self.fpu_read(1).trunc();
        if !x.is_finite() || x == 0.0 {
            return x;
        }
        let ni = n.clamp(-100000.0, 100000.0) as i32;
        x * exp2(ni)
    }

    fn x87_mem_form(&mut self, mem: &mut dyn Memory, esc: u8, reg: u8, addr: u64, env16: bool) -> Result<()> {
        match esc {
            0xD8 => {
                let v = f32::from_bits(mem.read_u32(addr)?) as f64;
                self.mem_arith(reg, v)?;
            }
            0xD9 => match reg {
                0 => { let v = f32::from_bits(mem.read_u32(addr)?) as f64; self.fpu_push_f64(v); }
                2 => { let v = self.store_f32(self.fpu_read(0)); mem.write_u32(addr, v)?; }
                3 => { let v = self.store_f32(self.fpu_read(0)); mem.write_u32(addr, v)?; self.fpu_pop(); }
                4 => self.fldenv(mem, addr, env16)?,
                5 => { self.state.x87.cw = mem.read_u16(addr)?; }
                6 => self.fnstenv(mem, addr, env16)?,
                7 => { mem.write_u16(addr, self.state.x87.cw)?; }
                _ => return Err(EmuError::Unsupported(format!("x87 D9 mem /{reg}"))),
            },
            0xDB => match reg {
                0 => { let v = mem.read_u32(addr)? as i32 as f64; self.fpu_push_f64(v); }
                1 => { let v = self.to_signed_int(self.fpu_read(0), 4, true); mem.write_u32(addr, v as i32 as u32)?; self.fpu_pop(); }
                2 => { let v = self.to_signed_int(self.fpu_read(0), 4, false); mem.write_u32(addr, v as i32 as u32)?; }
                3 => { let v = self.to_signed_int(self.fpu_read(0), 4, false); mem.write_u32(addr, v as i32 as u32)?; self.fpu_pop(); }
                5 => { let v = read_ext(mem, addr)?; self.fpu_push(v); }
                7 => { let v = self.fpu_read_ext(0); write_ext(mem, addr, v)?; self.fpu_pop(); }
                _ => return Err(EmuError::Unsupported(format!("x87 DB mem /{reg}"))),
            },
            0xDC => {
                let v = f64::from_bits(mem.read_u64(addr)?);
                self.mem_arith(reg, v)?;
            }
            0xDD => match reg {
                0 => { let v = f64::from_bits(mem.read_u64(addr)?); self.fpu_push_f64(v); }
                1 => { let v = self.to_signed_int(self.fpu_read(0), 8, true); mem.write_u64(addr, v as u64)?; self.fpu_pop(); }
                2 => { let v = self.store_f64(self.fpu_read(0)); mem.write_u64(addr, v)?; }
                3 => { let v = self.store_f64(self.fpu_read(0)); mem.write_u64(addr, v)?; self.fpu_pop(); }
                4 => self.frstor(mem, addr, env16)?,
                6 => self.fnsave(mem, addr, env16)?,
                7 => { mem.write_u16(addr, self.state.x87.sw)?; }
                _ => return Err(EmuError::Unsupported(format!("x87 DD mem /{reg}"))),
            },
            0xDF => match reg {
                0 => { let v = mem.read_u16(addr)? as i16 as f64; self.fpu_push_f64(v); }
                1 => { let v = self.to_signed_int(self.fpu_read(0), 2, true); mem.write_u16(addr, v as i16 as u16)?; self.fpu_pop(); }
                2 => { let v = self.to_signed_int(self.fpu_read(0), 2, false); mem.write_u16(addr, v as i16 as u16)?; }
                3 => { let v = self.to_signed_int(self.fpu_read(0), 2, false); mem.write_u16(addr, v as i16 as u16)?; self.fpu_pop(); }
                5 => { let v = mem.read_u64(addr)? as i64 as f64; self.fpu_push_f64(v); }
                7 => { let v = self.to_signed_int(self.fpu_read(0), 8, false); mem.write_u64(addr, v as u64)?; self.fpu_pop(); }
                _ => return Err(EmuError::Unsupported(format!("x87 DF mem /{reg}"))),
            },
            _ => return Err(EmuError::Unsupported(format!("x87 mem esc={esc:#x} /{reg}"))),
        }
        Ok(())
    }

    fn mem_arith(&mut self, reg: u8, v: f64) -> Result<()> {
        let a = self.fpu_read(0);
        match reg {
            0 => self.fpu_write(0, a + v),
            1 => self.fpu_write(0, a * v),
            2 => self.fpu_set_compare(a, v),
            3 => { self.fpu_set_compare(a, v); self.fpu_pop(); }
            4 => self.fpu_write(0, a - v),
            5 => self.fpu_write(0, v - a),
            6 => self.fpu_write(0, a / v),
            7 => self.fpu_write(0, v / a),
            _ => return Err(EmuError::Unsupported(format!("x87 mem-arith /{reg}"))),
        }
        Ok(())
    }

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

    fn store_f32(&self, x: f64) -> u32 {
        (x as f32).to_bits()
    }

    fn store_f64(&self, x: f64) -> u64 {
        x.to_bits()
    }
}

fn round_half_even(x: f64) -> f64 {
    let r = x.round();
    if (x - x.trunc()).abs() == 0.5 {
        let f = x.floor();
        if (f as i64) % 2 == 0 { f } else { f + 1.0 }
    } else {
        r
    }
}

fn exp2m1(x: f64) -> f64 {
    x.exp2() - 1.0
}

fn set_prem_cc(sw: &mut u16, q: f64) {
    let qi = q as i64;
    if qi & 1 != 0 { *sw |= SW_C1; }
    if qi & 2 != 0 { *sw |= SW_C3; }
    if qi & 4 != 0 { *sw |= SW_C0; }
}

fn tag_of(v: u128) -> u16 {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    if exp == 0 && signif == 0 {
        0b01
    } else if exp == 0x7fff || (exp != 0 && signif & 0x8000_0000_0000_0000 == 0) || (exp == 0 && signif != 0) {
        0b10
    } else {
        0b00
    }
}

fn is_ext_denormal(v: u128) -> bool {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    exp == 0 && signif != 0
}

fn read_ext(mem: &dyn Memory, addr: u64) -> Result<u128> {
    let lo = mem.read_u64(addr)? as u128;
    let hi = mem.read_u16(addr + 8)? as u128;
    Ok(lo | (hi << 64))
}

fn write_ext(mem: &mut dyn Memory, addr: u64, v: u128) -> Result<()> {
    mem.write_u64(addr, v as u64)?;
    mem.write_u16(addr + 8, (v >> 64) as u16)?;
    Ok(())
}

macro_rules! ext {
    ($hi:expr, $lo:expr) => {
        ($lo as u128) | (($hi as u128) << 64)
    };
}

const EXT_PI: u128 = ext!(0x4000, 0xC90F_DAA2_2168_C235u64);
const EXT_L2T: u128 = ext!(0x4000, 0xD49A_784B_CD1B_8AFEu64);
const EXT_L2E: u128 = ext!(0x3FFF, 0xB8AA_3B29_5C17_F0BCu64);
const EXT_LG2: u128 = ext!(0x3FFD, 0x9A20_9A84_FBCF_F799u64);
const EXT_LN2: u128 = ext!(0x3FFE, 0xB172_17F7_D1CF_79ACu64);
