pub const ZR: u32 = 31;
pub const SP: u32 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Cond {
    Eq = 0,
    Ne = 1,
    Cs = 2,
    Cc = 3,
    Mi = 4,
    Pl = 5,
    Vs = 6,
    Vc = 7,
    Hi = 8,
    Ls = 9,
    Ge = 10,
    Lt = 11,
    Gt = 12,
    Le = 13,
    Al = 14,
}

impl Cond {
    pub fn invert(self) -> Cond {
        match self {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Cs => Cond::Cc,
            Cond::Cc => Cond::Cs,
            Cond::Mi => Cond::Pl,
            Cond::Pl => Cond::Mi,
            Cond::Vs => Cond::Vc,
            Cond::Vc => Cond::Vs,
            Cond::Hi => Cond::Ls,
            Cond::Ls => Cond::Hi,
            Cond::Ge => Cond::Lt,
            Cond::Lt => Cond::Ge,
            Cond::Gt => Cond::Le,
            Cond::Le => Cond::Gt,
            Cond::Al => Cond::Al,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Label(usize);

#[derive(Default, Clone)]
pub struct Asm {
    words: Vec<u32>,
}

impl Asm {
    pub fn new() -> Asm {
        Asm { words: Vec::new() }
    }

    pub fn words(&self) -> &[u32] {
        &self.words
    }

    pub fn into_words(self) -> Vec<u32> {
        self.words
    }

    pub fn words_mut(&mut self) -> &mut [u32] {
        &mut self.words
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    #[inline]
    pub fn emit(&mut self, w: u32) {
        self.words.push(w);
    }

    pub fn movz(&mut self, sf64: bool, rd: u32, imm16: u16, hw: u32) {
        debug_assert!(hw < if sf64 { 4 } else { 2 });
        self.emit(
            (sf64 as u32) << 31 | 0b10_100101 << 23 | (hw & 3) << 21 | (imm16 as u32) << 5 | rd,
        );
    }

    pub fn movn(&mut self, sf64: bool, rd: u32, imm16: u16, hw: u32) {
        self.emit(
            (sf64 as u32) << 31 | 0b00_100101 << 23 | (hw & 3) << 21 | (imm16 as u32) << 5 | rd,
        );
    }

    pub fn movk(&mut self, sf64: bool, rd: u32, imm16: u16, hw: u32) {
        self.emit(
            (sf64 as u32) << 31 | 0b11_100101 << 23 | (hw & 3) << 21 | (imm16 as u32) << 5 | rd,
        );
    }

    pub fn mov_imm64(&mut self, rd: u32, value: u64) {
        let hw = |i: u32| ((value >> (16 * i)) & 0xffff) as u16;
        let inv = !value;
        let inv_hw = |i: u32| ((inv >> (16 * i)) & 0xffff) as u16;
        let nz = (0..4).filter(|&i| hw(i) != 0).count();
        let nz_inv = (0..4).filter(|&i| inv_hw(i) != 0).count();
        if nz == 0 {
            self.movz(true, rd, 0, 0);
            return;
        }
        if nz_inv <= nz {
            let first = (0..4).find(|&i| inv_hw(i) != 0).unwrap_or(0);
            self.movn(true, rd, inv_hw(first), first);
            for i in 0..4 {
                if i != first && inv_hw(i) != 0 {
                    self.movk(true, rd, hw(i), i);
                }
            }
        } else {
            let first = (0..4).find(|&i| hw(i) != 0).unwrap();
            self.movz(true, rd, hw(first), first);
            for i in 0..4 {
                if i != first && hw(i) != 0 {
                    self.movk(true, rd, hw(i), i);
                }
            }
        }
    }

    pub fn mov_reg(&mut self, sf64: bool, rd: u32, rn: u32) {
        self.orr_reg(sf64, rd, ZR, rn, 0);
    }

    pub fn ldr(&mut self, size: u8, rt: u32, rn: u32, off: u32) {
        let (base, scale) = match size {
            1 => (0x3940_0000u32, 0),
            2 => (0x7940_0000, 1),
            4 => (0xB940_0000, 2),
            _ => (0xF940_0000, 3),
        };
        debug_assert_eq!(off & ((1 << scale) - 1), 0, "unaligned ldr offset");
        let imm12 = off >> scale;
        debug_assert!(imm12 < 4096, "ldr offset out of range");
        self.emit(base | (imm12 & 0xfff) << 10 | rn << 5 | rt);
    }

    pub fn ldrb_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0x3860_6800 | rm << 16 | rn << 5 | rt);
    }

    pub fn ldr_reg(&mut self, size: u8, rt: u32, rn: u32, rm: u32) {
        let base: u32 = match size {
            1 => 0x3860_6800,
            2 => 0x7860_6800,
            4 => 0xB860_6800,
            _ => 0xF860_6800,
        };
        self.emit(base | rm << 16 | rn << 5 | rt);
    }

    pub fn str_reg(&mut self, size: u8, rt: u32, rn: u32, rm: u32) {
        let base: u32 = match size {
            1 => 0x3820_6800,
            2 => 0x7820_6800,
            4 => 0xB820_6800,
            _ => 0xF820_6800,
        };
        self.emit(base | rm << 16 | rn << 5 | rt);
    }

    pub fn str_reg_lsl3(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xF820_7800 | rm << 16 | rn << 5 | rt);
    }

    pub fn str(&mut self, size: u8, rt: u32, rn: u32, off: u32) {
        let (base, scale) = match size {
            1 => (0x3900_0000u32, 0),
            2 => (0x7900_0000, 1),
            4 => (0xB900_0000, 2),
            _ => (0xF900_0000, 3),
        };
        debug_assert_eq!(off & ((1 << scale) - 1), 0, "unaligned str offset");
        let imm12 = off >> scale;
        debug_assert!(imm12 < 4096, "str offset out of range");
        self.emit(base | (imm12 & 0xfff) << 10 | rn << 5 | rt);
    }

    pub fn stp_pre(&mut self, rt1: u32, rt2: u32, rn: u32, off: i32) {
        debug_assert_eq!(off % 8, 0);
        let imm7 = ((off / 8) as u32) & 0x7f;
        self.emit(0xA980_0000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt1);
    }

    pub fn ldp_post(&mut self, rt1: u32, rt2: u32, rn: u32, off: i32) {
        debug_assert_eq!(off % 8, 0);
        let imm7 = ((off / 8) as u32) & 0x7f;
        self.emit(0xA8C0_0000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt1);
    }

    pub fn stp(&mut self, rt1: u32, rt2: u32, rn: u32, off: i32) {
        debug_assert_eq!(off % 8, 0);
        let imm7 = ((off / 8) as u32) & 0x7f;
        self.emit(0xA900_0000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt1);
    }

    pub fn ldp(&mut self, rt1: u32, rt2: u32, rn: u32, off: i32) {
        debug_assert_eq!(off % 8, 0);
        let imm7 = ((off / 8) as u32) & 0x7f;
        self.emit(0xA940_0000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt1);
    }

    fn addsub_reg(&mut self, base: u32, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.emit((sf64 as u32) << 31 | base | rm << 16 | (lsl & 0x3f) << 10 | rn << 5 | rd);
    }

    pub fn add_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.addsub_reg(0x0B00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn adds_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.addsub_reg(0x2B00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn sub_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.addsub_reg(0x4B00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn subs_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.addsub_reg(0x6B00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn cmp_reg(&mut self, sf64: bool, rn: u32, rm: u32) {
        self.subs_reg(sf64, ZR, rn, rm, 0);
    }
    pub fn cmp_reg_asr(&mut self, sf64: bool, rn: u32, rm: u32, sh: u32) {
        self.emit(
            (sf64 as u32) << 31 | 0x6B00_0000 | 0b10 << 22 | rm << 16 | (sh & 0x3f) << 10 | rn << 5
                | ZR,
        );
    }
    pub fn cmp_reg_lsr(&mut self, sf64: bool, rn: u32, rm: u32, sh: u32) {
        self.emit(
            (sf64 as u32) << 31 | 0x6B00_0000 | 0b01 << 22 | rm << 16 | (sh & 0x3f) << 10 | rn << 5
                | ZR,
        );
    }
    pub fn adcs_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x3A00_0000 | rm << 16 | rn << 5 | rd);
    }
    pub fn sbcs_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x7A00_0000 | rm << 16 | rn << 5 | rd);
    }

    fn addsub_imm(&mut self, base: u32, sf64: bool, rd: u32, rn: u32, imm12: u32, sh12: bool) {
        debug_assert!(imm12 < 4096);
        self.emit(
            (sf64 as u32) << 31 | base | (sh12 as u32) << 22 | (imm12 & 0xfff) << 10 | rn << 5 | rd,
        );
    }

    pub fn add_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm12: u32, sh12: bool) {
        self.addsub_imm(0x1100_0000, sf64, rd, rn, imm12, sh12);
    }
    pub fn sub_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm12: u32, sh12: bool) {
        self.addsub_imm(0x5100_0000, sf64, rd, rn, imm12, sh12);
    }
    pub fn subs_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm12: u32, sh12: bool) {
        self.addsub_imm(0x7100_0000, sf64, rd, rn, imm12, sh12);
    }

    fn logic_reg(&mut self, base: u32, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.emit((sf64 as u32) << 31 | base | rm << 16 | (lsl & 0x3f) << 10 | rn << 5 | rd);
    }

    pub fn and_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x0A00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn orr_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x2A00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn eor_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x4A00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn ands_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x6A00_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn bic_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x0A20_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn orn_reg(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, lsl: u32) {
        self.logic_reg(0x2A20_0000, sf64, rd, rn, rm, lsl);
    }
    pub fn mvn(&mut self, sf64: bool, rd: u32, rm: u32) {
        self.orn_reg(sf64, rd, ZR, rm, 0);
    }
    pub fn neg(&mut self, sf64: bool, rd: u32, rm: u32) {
        self.sub_reg(sf64, rd, ZR, rm, 0);
    }

    #[must_use]
    pub fn and_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm: u64) -> bool {
        self.logic_imm(0x1200_0000, sf64, rd, rn, imm)
    }
    #[must_use]
    pub fn orr_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm: u64) -> bool {
        self.logic_imm(0x3200_0000, sf64, rd, rn, imm)
    }
    #[must_use]
    pub fn eor_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm: u64) -> bool {
        self.logic_imm(0x5200_0000, sf64, rd, rn, imm)
    }
    #[must_use]
    pub fn ands_imm(&mut self, sf64: bool, rd: u32, rn: u32, imm: u64) -> bool {
        self.logic_imm(0x7200_0000, sf64, rd, rn, imm)
    }

    fn logic_imm(&mut self, base: u32, sf64: bool, rd: u32, rn: u32, imm: u64) -> bool {
        match encode_bitmask(imm, sf64) {
            Some((n, immr, imms)) => {
                self.emit(
                    (sf64 as u32) << 31 | base | n << 22 | immr << 16 | imms << 10 | rn << 5 | rd,
                );
                true
            }
            None => false,
        }
    }

    fn bfm_family(&mut self, base: u32, sf64: bool, rd: u32, rn: u32, immr: u32, imms: u32) {
        let n = sf64 as u32;
        self.emit(
            (sf64 as u32) << 31 | base | n << 22 | (immr & 0x3f) << 16 | (imms & 0x3f) << 10
                | rn << 5
                | rd,
        );
    }

    pub fn ubfm(&mut self, sf64: bool, rd: u32, rn: u32, immr: u32, imms: u32) {
        self.bfm_family(0x5300_0000, sf64, rd, rn, immr, imms);
    }
    pub fn sbfm(&mut self, sf64: bool, rd: u32, rn: u32, immr: u32, imms: u32) {
        self.bfm_family(0x1300_0000, sf64, rd, rn, immr, imms);
    }
    pub fn bfm(&mut self, sf64: bool, rd: u32, rn: u32, immr: u32, imms: u32) {
        self.bfm_family(0x3300_0000, sf64, rd, rn, immr, imms);
    }

    pub fn lsl_imm(&mut self, sf64: bool, rd: u32, rn: u32, sh: u32) {
        let w = if sf64 { 64 } else { 32 };
        if sh == 0 {
            self.mov_reg(sf64, rd, rn);
            return;
        }
        self.ubfm(sf64, rd, rn, (w - sh) % w, w - 1 - sh);
    }
    pub fn lsr_imm(&mut self, sf64: bool, rd: u32, rn: u32, sh: u32) {
        let w = if sf64 { 64 } else { 32 };
        if sh == 0 {
            self.mov_reg(sf64, rd, rn);
            return;
        }
        self.ubfm(sf64, rd, rn, sh, w - 1);
    }
    pub fn asr_imm(&mut self, sf64: bool, rd: u32, rn: u32, sh: u32) {
        let w = if sf64 { 64 } else { 32 };
        self.sbfm(sf64, rd, rn, sh, w - 1);
    }
    pub fn ubfx(&mut self, sf64: bool, rd: u32, rn: u32, lsb: u32, width: u32) {
        self.ubfm(sf64, rd, rn, lsb, lsb + width - 1);
    }
    pub fn sbfx(&mut self, sf64: bool, rd: u32, rn: u32, lsb: u32, width: u32) {
        self.sbfm(sf64, rd, rn, lsb, lsb + width - 1);
    }
    pub fn bfi(&mut self, sf64: bool, rd: u32, rn: u32, lsb: u32, width: u32) {
        let w = if sf64 { 64 } else { 32 };
        self.bfm(sf64, rd, rn, (w - lsb) % w, width - 1);
    }
    pub fn sxtw(&mut self, rd: u32, rn: u32) {
        self.sbfm(true, rd, rn, 0, 31);
    }

    pub fn lslv(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x1AC0_2000 | rm << 16 | rn << 5 | rd);
    }
    pub fn lsrv(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x1AC0_2400 | rm << 16 | rn << 5 | rd);
    }
    pub fn asrv(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x1AC0_2800 | rm << 16 | rn << 5 | rd);
    }
    pub fn rorv(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x1AC0_2C00 | rm << 16 | rn << 5 | rd);
    }

    pub fn mul(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32) {
        self.emit((sf64 as u32) << 31 | 0x1B00_7C00 | rm << 16 | rn << 5 | rd);
    }
    pub fn smulh(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9B40_7C00 | rm << 16 | rn << 5 | rd);
    }
    pub fn umulh(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9BC0_7C00 | rm << 16 | rn << 5 | rd);
    }

    pub fn csel(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, cond: Cond) {
        self.emit(
            (sf64 as u32) << 31 | 0x1A80_0000 | rm << 16 | (cond as u32) << 12 | rn << 5 | rd,
        );
    }
    pub fn csinc(&mut self, sf64: bool, rd: u32, rn: u32, rm: u32, cond: Cond) {
        self.emit(
            (sf64 as u32) << 31 | 0x1A80_0400 | rm << 16 | (cond as u32) << 12 | rn << 5 | rd,
        );
    }
    pub fn cset(&mut self, sf64: bool, rd: u32, cond: Cond) {
        self.csinc(sf64, rd, ZR, ZR, cond.invert());
    }

    pub fn ret(&mut self) {
        self.emit(0xD65F_03C0);
    }
    pub fn blr(&mut self, rn: u32) {
        self.emit(0xD63F_0000 | rn << 5);
    }
    pub fn br(&mut self, rn: u32) {
        self.emit(0xD61F_0000 | rn << 5);
    }

    pub fn nop(&mut self) {
        self.emit(0xD503_201F);
    }

    pub fn b_forward(&mut self) -> Label {
        let at = self.words.len();
        self.emit(0x1400_0000);
        Label(at)
    }

    pub fn b_cond_forward(&mut self, cond: Cond) -> Label {
        let at = self.words.len();
        self.emit(0x5400_0000 | cond as u32);
        Label(at)
    }

    pub fn cbnz_forward(&mut self, sf64: bool, rt: u32) -> Label {
        let at = self.words.len();
        self.emit((sf64 as u32) << 31 | 0x3500_0000 | rt);
        Label(at)
    }

    pub fn cbz_forward(&mut self, sf64: bool, rt: u32) -> Label {
        let at = self.words.len();
        self.emit((sf64 as u32) << 31 | 0x3400_0000 | rt);
        Label(at)
    }

    pub fn tbnz_forward(&mut self, rt: u32, bit: u32) -> Label {
        let at = self.words.len();
        self.emit(0x3700_0000 | (bit & 0x1f) << 19 | (bit >> 5) << 31 | rt);
        Label(at)
    }

    pub fn tbz_forward(&mut self, rt: u32, bit: u32) -> Label {
        let at = self.words.len();
        self.emit(0x3600_0000 | (bit & 0x1f) << 19 | (bit >> 5) << 31 | rt);
        Label(at)
    }

    pub fn bind(&mut self, label: Label) {
        let target = self.words.len();
        let delta = (target - label.0) as u32;
        let w = self.words[label.0];
        if w & 0xFC00_0000 == 0x1400_0000 {
            debug_assert!(delta < (1 << 25));
            self.words[label.0] = 0x1400_0000 | (delta & 0x03FF_FFFF);
        } else if w & 0x7E00_0000 == 0x3600_0000 {
            debug_assert!(delta < (1 << 13));
            self.words[label.0] = (w & !0x0007_FFE0) | ((delta & 0x3FFF) << 5);
        } else {
            debug_assert!(delta < (1 << 18));
            self.words[label.0] = (w & !0x00FF_FFE0) | ((delta & 0x7FFFF) << 5);
        }
    }
}

pub fn decode_bitmask(n: u32, immr: u32, imms: u32, is64: bool) -> Option<u64> {
    let width: u32 = if is64 { 64 } else { 32 };
    if !is64 && n == 1 {
        return None;
    }
    let x = (n << 6) | ((!imms) & 0x3f);
    if x == 0 {
        return None;
    }
    let len = 31 - x.leading_zeros();
    if len < 1 {
        return None;
    }
    let esize = 1u32 << len;
    if esize > width {
        return None;
    }
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let esize_mask: u64 = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let welem: u64 = if s + 1 == 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let w = welem & esize_mask;
    let rotated = ((w >> r) | (w << ((esize - r) % esize))) & esize_mask;
    let mut out = 0u64;
    let mut i = 0;
    while i < width {
        out |= rotated << i;
        i += esize;
    }
    if !is64 {
        out &= 0xffff_ffff;
    }
    Some(out)
}

#[inline]
fn is_shifted_mask(x: u64) -> bool {
    if x == 0 {
        return false;
    }
    let t = x >> x.trailing_zeros();
    t.count_ones() == 64 - t.leading_zeros()
}

pub fn encode_bitmask(value: u64, is64: bool) -> Option<(u32, u32, u32)> {
    let width: u32 = if is64 { 64 } else { 32 };
    let all: u64 = if is64 { u64::MAX } else { 0xffff_ffff };
    let value = value & all;
    if value == 0 || value == all {
        return None;
    }

    let mut size = width;
    loop {
        size /= 2;
        let mask = (1u64 << size) - 1;
        if (value & mask) != ((value >> size) & mask) {
            size *= 2;
            break;
        }
        if size <= 2 {
            break;
        }
    }
    let esize_mask: u64 = if size == 64 { u64::MAX } else { (1u64 << size) - 1 };
    let mut elem = value & esize_mask;

    let (rot, ones) = if is_shifted_mask(elem) {
        let i = elem.trailing_zeros();
        (i, (elem >> i).trailing_ones())
    } else {
        elem |= !esize_mask;
        if !is_shifted_mask(!elem) {
            return None;
        }
        let clo = (!elem).leading_zeros();
        let ones = (clo + elem.trailing_ones()).checked_sub(64 - size)?;
        (64 - clo, ones)
    };
    if ones == 0 || ones >= size || rot >= size {
        return None;
    }

    let immr = (size - rot) & (size - 1);
    let nimms = (!(size - 1) << 1) | (ones - 1);
    let n = ((nimms >> 6) & 1) ^ 1;
    let imms = nimms & 0x3f;

    if decode_bitmask(n, immr, imms, is64) == Some(value) {
        Some((n, immr, imms))
    } else {
        None
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::buffer::CodeBuffer;

    fn run2(body: impl FnOnce(&mut Asm), a: u64, b: u64) -> u64 {
        let mut asm = Asm::new();
        body(&mut asm);
        asm.ret();
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let code = buf.push(asm.words()).unwrap();
        // SAFETY: the block was just assembled with the AAPCS64 signature below
        let f: extern "C" fn(u64, u64) -> u64 = unsafe { code.as_fn() };
        f(a, b)
    }

    #[test]
    fn br_jumps_to_the_address_in_a_register() {
        let mut tail = Asm::new();
        tail.mov_imm64(0, 42);
        tail.ret();
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let target = buf.push(tail.words()).unwrap();
        let mut head = Asm::new();
        head.mov_imm64(0, 7);
        head.br(1);
        let entry = buf.push(head.words()).unwrap();
        // SAFETY: both streams were just assembled for this signature and the
        let got = unsafe {
            let f: extern "C" fn(u64, u64) -> u64 = entry.as_fn();
            f(0, target.addr() as u64)
        };
        assert_eq!(got, 42, "br did not reach the second stream");
    }

    #[test]
    fn str_reg_lsl3_indexes_a_slot_array() {
        let mut slots = [0u64; 4];
        let mut asm = Asm::new();
        asm.mov_imm64(3, 0xABCD);
        asm.mov_imm64(2, 2);
        asm.str_reg_lsl3(3, 1, 2);
        asm.mov_imm64(0, 0);
        asm.ret();
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let code = buf.push(asm.words()).unwrap();
        // SAFETY: as `run2` — the stream was just assembled for this signature,
        unsafe {
            let f: extern "C" fn(u64, u64) -> u64 = code.as_fn();
            f(0, slots.as_mut_ptr() as u64);
        }
        assert_eq!(slots, [0, 0, 0xABCD, 0], "the scaled index landed wrong");
    }

    #[test]
    fn mov_imm64_covers_every_shape() {
        for v in [
            0u64,
            1,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1234_5678_9abc_def0,
            u64::MAX,
            u64::MAX - 3,
            0xffff_0000_ffff_0000,
            (-4096i64) as u64,
        ] {
            let got = run2(|a| a.mov_imm64(0, v), 0, 0);
            assert_eq!(got, v, "mov_imm64 {v:#x}");
        }
    }

    #[test]
    fn arithmetic_and_flags() {
        assert_eq!(run2(|a| a.add_reg(true, 0, 0, 1, 0), 7, 35), 42);
        assert_eq!(run2(|a| a.sub_reg(true, 0, 0, 1, 0), 50, 8), 42);
        assert_eq!(run2(|a| a.add_reg(true, 0, 0, 1, 3), 2, 5), 42);
        assert_eq!(run2(|a| a.add_reg(false, 0, 0, 1, 0), 0xffff_ffff, 2), 1, "32-bit wraps");
        assert_eq!(run2(|a| a.mul(true, 0, 0, 1), 6, 7), 42);
        assert_eq!(run2(|a| a.umulh(0, 0, 1), u64::MAX, 4), 3);
        assert_eq!(run2(|a| a.smulh(0, 0, 1), (-1i64) as u64, 4), u64::MAX);
        assert_eq!(run2(|a| a.neg(true, 0, 0), 42, 0), (-42i64) as u64);
        assert_eq!(run2(|a| a.mvn(true, 0, 0), 0, 0), u64::MAX);
    }

    #[test]
    fn cset_reads_the_flags_the_x86_lowering_needs() {
        let carry = |x: u64, y: u64| {
            run2(
                |a| {
                    a.adds_reg(true, 2, 0, 1, 0);
                    a.cset(true, 0, Cond::Cs);
                },
                x,
                y,
            )
        };
        assert_eq!(carry(u64::MAX, 1), 1);
        assert_eq!(carry(1, 1), 0);
        let borrow = |x: u64, y: u64| {
            run2(
                |a| {
                    a.subs_reg(true, 2, 0, 1, 0);
                    a.cset(true, 0, Cond::Cc);
                },
                x,
                y,
            )
        };
        assert_eq!(borrow(1, 2), 1);
        assert_eq!(borrow(2, 1), 0);
        let ovf = |x: u64, y: u64| {
            run2(
                |a| {
                    a.adds_reg(true, 2, 0, 1, 0);
                    a.cset(true, 0, Cond::Vs);
                },
                x,
                y,
            )
        };
        assert_eq!(ovf(i64::MAX as u64, 1), 1);
        assert_eq!(ovf(1, 1), 0);
    }

    #[test]
    fn shifts_and_bitfields() {
        assert_eq!(run2(|a| a.lsl_imm(true, 0, 0, 8), 1, 0), 0x100);
        assert_eq!(run2(|a| a.lsr_imm(true, 0, 0, 8), 0x1234, 0), 0x12);
        assert_eq!(run2(|a| a.asr_imm(true, 0, 0, 4), (-256i64) as u64, 0), (-16i64) as u64);
        assert_eq!(run2(|a| a.ubfx(true, 0, 0, 4, 8), 0x00ab_cdef, 0), 0xde);
        assert_eq!(run2(|a| a.sbfx(true, 0, 0, 0, 8), 0xff, 0), u64::MAX);
        assert_eq!(run2(|a| a.sxtw(0, 0), 0xffff_ffff, 0), u64::MAX);
        assert_eq!(run2(|a| a.lslv(true, 0, 0, 1), 1, 12), 0x1000);
        assert_eq!(run2(|a| a.lsrv(true, 0, 0, 1), 0x1000, 12), 1);
        assert_eq!(run2(|a| a.asrv(true, 0, 0, 1), (-4096i64) as u64, 12), (-1i64) as u64);
        assert_eq!(run2(|a| a.rorv(true, 0, 0, 1), 1, 1), 0x8000_0000_0000_0000);
        assert_eq!(run2(|a| a.bfi(true, 0, 1, 8, 8), 0xffff, 0), 0x00ff);
    }

    #[test]
    fn cmp_folds_a_logical_shift_right_into_its_second_operand() {
        let eq = |a: u64, b: u64| {
            run2(
                |asm| {
                    asm.cmp_reg_lsr(true, 0, 1, 12);
                    asm.cset(true, 0, Cond::Eq);
                },
                a,
                b,
            )
        };
        assert_eq!(eq(0x9, 0x9123), 1, "x0 == x1 >> 12");
        assert_eq!(eq(0x9, 0xa123), 0);
        assert_eq!(eq(0x9123, 0x9123), 0, "the shift is not optional");
        assert_eq!(eq(0x000f_ffff_ffff_ffff, u64::MAX), 1);
        assert_eq!(eq(u64::MAX, u64::MAX), 0);
    }

    #[test]
    fn register_offset_loads_and_stores_address_base_plus_offset() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as u64;
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(run2(|a| a.ldr_reg(1, 0, 0, 1), base, 5), 5);
        assert_eq!(run2(|a| a.ldr_reg(2, 0, 0, 1), base, 5), 0x0605);
        assert_eq!(run2(|a| a.ldr_reg(4, 0, 0, 1), base, 5), 0x0807_0605);
        assert_eq!(run2(|a| a.ldr_reg(8, 0, 0, 1), base, 5), 0x0c0b_0a09_0807_0605);
        assert_eq!(run2(|a| a.ldr_reg(4, 0, 0, 1), base, 3), 0x0605_0403);

        let mut out = [0u8; 16];
        let ob = out.as_mut_ptr() as u64;
        run2(
            |a| {
                a.mov_imm64(2, 0xdead_beef_cafe_1122);
                a.str_reg(1, 2, 0, 1);
                a.str_reg(2, 2, 0, 1);
            },
            ob,
            3,
        );
        assert_eq!(u16::from_le_bytes([out[3], out[4]]), 0x1122);
        run2(|a| a.str_reg(8, 1, 0, 1), ob, 0);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0);
    }

    #[test]
    fn logical_immediates_round_trip() {
        for v in [0xffu64, 0xffff, 0xffff_ffff, 0x5555_5555_5555_5555, 0xf0f0_f0f0_f0f0_f0f0, 0x10] {
            let (n, immr, imms) = encode_bitmask(v, true).unwrap_or_else(|| panic!("{v:#x}"));
            assert_eq!(decode_bitmask(n, immr, imms, true), Some(v));
            assert_eq!(run2(|a| assert!(a.and_imm(true, 0, 0, v)), u64::MAX, 0), v);
        }
        assert_eq!(encode_bitmask(0x8D5, true), None);
        assert_eq!(encode_bitmask(0, true), None);
        assert_eq!(encode_bitmask(u64::MAX, true), None);
    }

    #[test]
    fn every_encodable_value_is_found_by_the_closed_form() {
        for is64 in [false, true] {
            let mut seen = 0u32;
            for n in 0..2u32 {
                for immr in 0..64u32 {
                    for imms in 0..64u32 {
                        let Some(v) = decode_bitmask(n, immr, imms, is64) else { continue };
                        seen += 1;
                        let got = encode_bitmask(v, is64)
                            .unwrap_or_else(|| panic!("{v:#x} (is64={is64}) lost"));
                        assert_eq!(
                            decode_bitmask(got.0, got.1, got.2, is64),
                            Some(v),
                            "{v:#x} (is64={is64}) encoded as {got:?}"
                        );
                    }
                }
            }
            assert!(seen > 3000, "only {seen} encodable triples for is64={is64}");
        }
    }

    #[test]
    fn the_closed_form_declines_exactly_what_no_triple_encodes() {
        let mut encodable = std::collections::HashSet::new();
        for n in 0..2u32 {
            for immr in 0..64u32 {
                for imms in 0..64u32 {
                    if let Some(v) = decode_bitmask(n, immr, imms, true) {
                        encodable.insert(v);
                    }
                }
            }
        }
        let mut vals: Vec<u64> = (0..=0x3ffu64).collect();
        for b in 0..64 {
            vals.push(1u64 << b);
            vals.push(!(1u64 << b));
            vals.push((1u64 << b).wrapping_sub(1));
            vals.push(0x8D5u64 << (b % 32));
        }
        vals.extend([0xffff_ffffu64, 0xffff_ffff_ffff_ff00, 0x0f0f_0f0f_0f0f_0f0f, 0xdead_beef]);
        for v in vals {
            assert_eq!(
                encode_bitmask(v, true).is_some(),
                encodable.contains(&v),
                "{v:#x} disagrees with the decoder's own reachable set"
            );
        }
    }

    #[test]
    fn loads_stores_and_branches() {
        let mut scratch = [0u64; 4];
        let ptr = scratch.as_mut_ptr() as u64;
        run2(
            |a| {
                a.mov_imm64(2, 0xdead_beef_cafe_0011);
                a.str(1, 2, 0, 0);
                a.str(2, 2, 0, 8);
                a.str(4, 2, 0, 16);
                a.str(8, 2, 0, 24);
            },
            ptr,
            0,
        );
        assert_eq!(scratch[0], 0x11);
        assert_eq!(scratch[1], 0x0011);
        assert_eq!(scratch[2], 0xcafe_0011);
        assert_eq!(scratch[3], 0xdead_beef_cafe_0011);
        assert_eq!(run2(|a| a.ldr(8, 0, 0, 24), ptr, 0), 0xdead_beef_cafe_0011);
        assert_eq!(run2(|a| a.ldr(1, 0, 0, 0), ptr, 0), 0x11);
        assert_eq!(run2(|a| a.ldr(2, 0, 0, 8), ptr, 0), 0x11);
        assert_eq!(run2(|a| a.ldr(4, 0, 0, 16), ptr, 0), 0xcafe_0011);

        let eq = |x: u64, y: u64| {
            run2(
                |a| {
                    a.cmp_reg(true, 0, 1);
                    let l = a.b_cond_forward(Cond::Ne);
                    a.mov_imm64(0, 1);
                    a.ret();
                    a.bind(l);
                    a.mov_imm64(0, 2);
                },
                x,
                y,
            )
        };
        assert_eq!(eq(5, 5), 1);
        assert_eq!(eq(5, 6), 2);

        let nz = |x: u64| {
            run2(
                |a| {
                    let l = a.cbnz_forward(true, 0);
                    a.mov_imm64(0, 100);
                    let done = a.b_forward();
                    a.bind(l);
                    a.mov_imm64(0, 200);
                    a.bind(done);
                },
                x,
                0,
            )
        };
        assert_eq!(nz(0), 100);
        assert_eq!(nz(7), 200);
    }

    #[test]
    fn frame_save_restore() {
        let mut asm = Asm::new();
        asm.stp_pre(19, 20, SP, -16);
        asm.mov_imm64(19, 0xdead);
        asm.mov_imm64(20, 0xbeef);
        asm.add_reg(true, 0, 19, 20, 0);
        asm.ldp_post(19, 20, SP, 16);
        asm.ret();
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let code = buf.push(asm.words()).unwrap();
        // SAFETY: assembled just above with this exact signature.
        let f: extern "C" fn() -> u64 = unsafe { code.as_fn() };
        assert_eq!(f(), 0xdead + 0xbeef);
    }
}
