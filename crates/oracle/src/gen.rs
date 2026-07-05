//! Instruction generator for the differential oracle.
//!
//! Every trial is a single x86 instruction whose operands are registers and
//! immediates only (ModRM mod=3) — no memory, no control flow — so the two
//! engines can be compared purely on register/flag effects without a shared
//! address space or fault model. The generator focuses on the integer ALU,
//! shift/rotate, multiply/divide and bit families: exactly the arithmetic the
//! LZMA/NSIS decompressor that trips the SteamSetup fault leans on.
//!
//! Each [`Trial`] carries a **defined-flags mask** — the status flags the
//! instruction architecturally defines for the operands chosen — so the diff
//! never trips over a flag x86 leaves *undefined* (e.g. SF/ZF after `mul`, or
//! `OF` after a multi-bit shift), which exemu and Unicorn may set differently
//! yet both be correct.

use crate::rng::Rng;
use exemu_core::cpu::flags::{AF, CF, DF, OF, PF, RESERVED_ONE, SF, ZF};
use exemu_cpu::Bits;

const ARITH: u64 = CF | PF | AF | ZF | SF | OF;
const LOGIC: u64 = CF | PF | ZF | SF | OF; // AND/OR/XOR leave AF undefined
const INCDEC: u64 = PF | AF | ZF | SF | OF; // INC/DEC preserve CF
const MULF: u64 = CF | OF; // MUL/IMUL define only CF/OF

/// A seeded architectural state shared by both engines for one trial.
#[derive(Clone)]
pub struct Seed {
    pub gpr: [u64; 16],
    pub rflags: u64,
}

/// One generated instruction plus the policy for comparing its result.
pub struct Trial {
    pub bytes: Vec<u8>,
    /// Status flags this instruction defines for the chosen operands.
    pub defined_flags: u64,
    /// Bitmask of GPR indices whose post-value is architecturally undefined
    /// (e.g. BSF/BSR destination when the source is zero).
    pub skip_reg: u16,
    pub label: String,
}

#[inline]
fn wmask(w: u8) -> u64 {
    match w {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

#[inline]
fn sign_bit(w: u8) -> u64 {
    1u64 << (w * 8 - 1)
}

#[inline]
fn modrm_reg(reg: u8, rm: u8) -> u8 {
    0xC0 | ((reg & 7) << 3) | (rm & 7)
}

/// Emit the legacy/REX prefixes for an operand `width` (and an optional F3).
fn prefixes(b: &mut Vec<u8>, width: u8, f3: bool) {
    if f3 {
        b.push(0xF3);
    }
    if width == 2 {
        b.push(0x66);
    }
    if width == 8 {
        b.push(0x48); // REX.W (no B/R/X → registers 0..7 only)
    }
}

fn emit_imm(b: &mut Vec<u8>, val: u64, nbytes: usize) {
    for i in 0..nbytes {
        b.push((val >> (8 * i)) as u8);
    }
}

/// Random operand width 1/2/4 (and 8 in 64-bit).
fn w124(rng: &mut Rng, bits: Bits) -> u8 {
    match rng.below(if bits == Bits::B64 { 4 } else { 3 }) {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Random operand width 2/4 (and 8 in 64-bit) — for ops with no byte form.
fn w24(rng: &mut Rng, bits: Bits) -> u8 {
    match rng.below(if bits == Bits::B64 { 3 } else { 2 }) {
        0 => 2,
        1 => 4,
        _ => 8,
    }
}

/// Random operand width 4 (and 8 in 64-bit).
fn w48(rng: &mut Rng, bits: Bits) -> u8 {
    if bits == Bits::B64 && rng.boolean() {
        8
    } else {
        4
    }
}

fn alu_defined(op: u8) -> u64 {
    match op {
        1 | 4 | 6 => LOGIC, // OR / AND / XOR
        _ => ARITH,         // ADD ADC SBB SUB CMP
    }
}

const ALU_MNEM: [&str; 8] = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];

/// Build one trial, possibly adjusting `seed` (only the DIV/IDIV family does,
/// to keep the quotient in range so the trial tests division math rather than
/// the #DE-on-overflow fault path).
pub fn build(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    match rng.below(26) {
        0 => alu_rr(rng, bits),
        1 => alu_imm(rng, bits),
        2 => shift_imm(rng, bits, seed),
        3 => shift_cl(rng, bits, seed),
        4 => shld_shrd(rng, bits, seed),
        5 => mul_one(rng, bits),
        6 => imul2(rng, bits),
        7 => imul3(rng, bits),
        8 => div_op(rng, bits, seed),
        9 => incdec(rng, bits),
        10 => neg(rng, bits),
        11 => not(rng, bits),
        12 => test_rr(rng, bits),
        13 => bt_reg(rng, bits, seed),
        14 => bt_imm(rng, bits),
        15 => bsf_bsr(rng, bits, seed),
        16 => tzcnt_lzcnt(rng, bits),
        17 => popcnt(rng, bits),
        18 => movzx_movsx(rng, bits),
        19 => setcc(rng),
        20 => cmovcc(rng, bits),
        21 => bswap(rng, bits),
        22 => xadd(rng, bits),
        23 => cmpxchg(rng, bits),
        24 => xchg(rng, bits),
        _ => cdq_cwde(rng, bits),
    }
}

fn alu_rr(rng: &mut Rng, bits: Bits) -> Trial {
    let op = rng.below(8) as u8;
    let byte = rng.boolean();
    let dir = rng.boolean(); // false: rm,r  true: r,rm
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let opcode = (op << 3) | ((dir as u8) << 1) | (!byte as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(opcode);
    b.push(modrm_reg(reg, rm));
    Trial {
        bytes: b,
        defined_flags: alu_defined(op),
        skip_reg: 0,
        label: format!("{} w{} {}", ALU_MNEM[op as usize], width, if dir { "r,rm" } else { "rm,r" }),
    }
}

fn alu_imm(rng: &mut Rng, bits: Bits) -> Trial {
    let op = rng.below(8) as u8;
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    let imm = rng.operand();
    if width == 1 {
        b.push(0x80);
        b.push(modrm_reg(op, rm));
        emit_imm(&mut b, imm, 1);
    } else if rng.boolean() {
        // 0x83: imm8 sign-extended.
        b.push(0x83);
        b.push(modrm_reg(op, rm));
        emit_imm(&mut b, imm, 1);
    } else {
        // 0x81: immZ (imm16 for w2, imm32 for w4/w8).
        b.push(0x81);
        b.push(modrm_reg(op, rm));
        emit_imm(&mut b, imm, if width == 2 { 2 } else { 4 });
    }
    Trial { bytes: b, defined_flags: alu_defined(op), skip_reg: 0, label: format!("{} w{} rm,imm", ALU_MNEM[op as usize], width) }
}

const SH_MNEM: [&str; 8] = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"];

/// Defined status flags for a shift/rotate given its kind (/reg) and the
/// already-masked count.
fn shift_defined(reg: u8, masked: u32) -> u64 {
    if masked == 0 {
        return 0;
    }
    let of = if masked == 1 { OF } else { 0 };
    match reg & 7 {
        4..=7 => CF | SF | ZF | PF | of, // SHL/SHR/SAL/SAR
        _ => CF | of,                    // ROL/ROR/RCL/RCR
    }
}

fn shift_imm(rng: &mut Rng, bits: Bits, _seed: &mut Seed) -> Trial {
    let width = w124(rng, bits);
    let reg = rng.below(8) as u8; // /reg selects the shift kind
    let rm = rng.below(8) as u8;
    let wb = (width as u32) * 8;
    let count = rng.below(wb + 1); // 0..=width_bits: always in the defined region
    let cmask = if width == 8 { 0x3f } else { 0x1f };
    let masked = count & cmask;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xC0 } else { 0xC1 });
    b.push(modrm_reg(reg, rm));
    emit_imm(&mut b, count as u64, 1);
    Trial { bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, label: format!("{} w{} imm={}", SH_MNEM[(reg & 7) as usize], width, count) }
}

fn shift_cl(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // Restrict to 32/64-bit so the masked CL count (0..31/63) never exceeds the
    // operand width — keeping CF/result out of the undefined >width region.
    let width = w48(rng, bits);
    let reg = rng.below(8) as u8;
    let rm = rng.below(8) as u8;
    let cl = (seed.gpr[1] & 0xff) as u32;
    let masked = cl & if width == 8 { 0x3f } else { 0x1f };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0xD3);
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, label: format!("{} w{} cl(={})", SH_MNEM[(reg & 7) as usize], width, cl & 0xff) }
}

fn shld_shrd(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let width = w48(rng, bits);
    let is_shrd = rng.boolean();
    let cl_form = rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg=src, rm=dst
    let wb = (width as u32) * 8;
    let cmask = if width == 8 { 0x3f } else { 0x1f };
    let (op2, count, count_label) = if cl_form {
        let cl = (seed.gpr[1] & 0xff) as u32;
        (if is_shrd { 0xAD } else { 0xA5 }, cl & cmask, format!("cl(={})", cl & 0xff))
    } else {
        let c = rng.below(wb + 1);
        (if is_shrd { 0xAC } else { 0xA4 }, c & cmask, format!("imm={c}"))
    };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(op2);
    b.push(modrm_reg(reg, rm));
    if op2 == 0xA4 || op2 == 0xAC {
        emit_imm(&mut b, count as u64, 1);
    }
    let defined = if count == 0 { 0 } else { CF | SF | ZF | PF };
    Trial { bytes: b, defined_flags: defined, skip_reg: 0, label: format!("{} w{} {}", if is_shrd { "shrd" } else { "shld" }, width, count_label) }
}

fn mul_one(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let signed = rng.boolean();
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(if signed { 5 } else { 4 }, rm));
    Trial { bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("{} w{} (one-op)", if signed { "imul" } else { "mul" }, width) }
}

fn imul2(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(0xAF);
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("imul2 w{width}") }
}

fn imul3(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm8 = rng.boolean();
    let imm = rng.operand();
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if imm8 { 0x6B } else { 0x69 });
    b.push(modrm_reg(reg, rm));
    emit_imm(&mut b, imm, if imm8 { 1 } else if width == 2 { 2 } else { 4 });
    Trial { bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("imul3 w{width} {}", if imm8 { "imm8" } else { "immZ" }) }
}

fn div_op(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // Widths 2/4/8 only. Set up EDX:EAX so the quotient always fits (no #DE),
    // which isolates the division arithmetic from the overflow fault path.
    let width = w24(rng, bits);
    let signed = rng.boolean();
    // Divisor register: avoid EAX(0)/EDX(2), which hold the dividend.
    let choices = [1u8, 3, 4, 5, 6, 7];
    let rm = *rng.pick(&choices);
    let m = wmask(width);
    // Ensure a non-zero divisor.
    if seed.gpr[rm as usize] & m == 0 {
        seed.gpr[rm as usize] = (seed.gpr[rm as usize] & !m) | 1;
    }
    if signed {
        // Avoid divisor == -1 (INT_MIN / -1 overflows).
        if (seed.gpr[rm as usize] & m) == m {
            seed.gpr[rm as usize] = (seed.gpr[rm as usize] & !m) | 1;
        }
        // EDX = sign extension of EAX across the width.
        let hi = if seed.gpr[0] & sign_bit(width) != 0 { m } else { 0 };
        seed.gpr[2] = (seed.gpr[2] & !m) | hi;
    } else {
        // EDX high part = 0 → dividend is just EAX, quotient always fits.
        seed.gpr[2] &= !m;
    }
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0xF7);
    b.push(modrm_reg(if signed { 7 } else { 6 }, rm));
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} w{width}", if signed { "idiv" } else { "div" }) }
}

fn incdec(rng: &mut Rng, bits: Bits) -> Trial {
    let dec = rng.boolean();
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    if bits == Bits::B32 && width == 4 && rng.boolean() {
        // Short 0x40..0x4F form (32-bit only).
        b.push(if dec { 0x48 + rm } else { 0x40 + rm });
    } else {
        prefixes(&mut b, width, false);
        b.push(if width == 1 { 0xFE } else { 0xFF });
        b.push(modrm_reg(if dec { 1 } else { 0 }, rm));
    }
    Trial { bytes: b, defined_flags: INCDEC, skip_reg: 0, label: format!("{} w{width}", if dec { "dec" } else { "inc" }) }
}

fn neg(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(3, rm));
    Trial { bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("neg w{width}") }
}

fn not(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(2, rm));
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("not w{width}") }
}

fn test_rr(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0x84 } else { 0x85 });
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: LOGIC, skip_reg: 0, label: format!("test w{width}") }
}

const BT_MNEM: [(&str, u8); 4] = [("bt", 0xA3), ("bts", 0xAB), ("btr", 0xB3), ("btc", 0xBB)];

fn bt_reg(rng: &mut Rng, bits: Bits, _seed: &mut Seed) -> Trial {
    let width = w24(rng, bits);
    let (name, op2) = BT_MNEM[rng.below(4) as usize];
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(op2);
    b.push(modrm_reg(reg, rm)); // reg = bit index, rm = bit base register
    Trial { bytes: b, defined_flags: CF, skip_reg: 0, label: format!("{name} w{width} (reg)") }
}

fn bt_imm(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let sub = rng.below(4) as u8; // 0=bt 1=bts 2=btr 3=btc → /4../7
    let rm = rng.below(8) as u8;
    let idx = rng.below((width as u32) * 8); // in-range bit index
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(0xBA);
    b.push(modrm_reg(4 + sub, rm));
    emit_imm(&mut b, idx as u64, 1);
    Trial { bytes: b, defined_flags: CF, skip_reg: 0, label: format!("{} w{width} imm={idx}", ["bt", "bts", "btr", "btc"][sub as usize]) }
}

fn bsf_bsr(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let width = w24(rng, bits);
    let bsr = rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let src_zero = seed.gpr[rm as usize] & wmask(width) == 0;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(if bsr { 0xBD } else { 0xBC });
    b.push(modrm_reg(reg, rm));
    // When the source is zero the destination is architecturally undefined.
    let skip = if src_zero { 1u16 << (reg & 7) } else { 0 };
    Trial { bytes: b, defined_flags: ZF, skip_reg: skip, label: format!("{} w{width}{}", if bsr { "bsr" } else { "bsf" }, if src_zero { " (src=0)" } else { "" }) }
}

fn tzcnt_lzcnt(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let lz = rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, true); // F3 mandatory prefix
    b.push(0x0F);
    b.push(if lz { 0xBD } else { 0xBC });
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: CF | ZF, skip_reg: 0, label: format!("{} w{width}", if lz { "lzcnt" } else { "tzcnt" }) }
}

fn popcnt(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, true);
    b.push(0x0F);
    b.push(0xB8);
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: CF | OF | SF | ZF | AF | PF, skip_reg: 0, label: format!("popcnt w{width}") }
}

fn movzx_movsx(rng: &mut Rng, bits: Bits) -> Trial {
    // MOVSXD (0x63) in 64-bit occasionally.
    if bits == Bits::B64 && rng.below(4) == 0 {
        let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
        let b = vec![0x48, 0x63, modrm_reg(reg, rm)];
        return Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: "movsxd r64,rm32".into() };
    }
    let src = if rng.boolean() { 1 } else { 2 };
    // Destination wider than source.
    let dst = if src == 1 { *rng.pick(if bits == Bits::B64 { &[2u8, 4, 8][..] } else { &[2u8, 4][..] }) } else if bits == Bits::B64 { *rng.pick(&[4u8, 8]) } else { 4 };
    let signed = rng.boolean();
    let op2 = match (src, signed) {
        (1, false) => 0xB6,
        (2, false) => 0xB7,
        (1, true) => 0xBE,
        _ => 0xBF,
    };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, dst, false); // width prefixes follow the destination size
    b.push(0x0F);
    b.push(op2);
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} dst{dst}<-src{src}", if signed { "movsx" } else { "movzx" }) }
}

const CC: [&str; 16] = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

fn setcc(rng: &mut Rng) -> Trial {
    let cc = rng.below(16) as u8;
    let rm = rng.below(8) as u8;
    let b = vec![0x0F, 0x90 + cc, modrm_reg(0, rm)];
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("set{}", CC[cc as usize]) }
}

fn cmovcc(rng: &mut Rng, bits: Bits) -> Trial {
    let cc = rng.below(16) as u8;
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(0x40 + cc);
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("cmov{} w{width}", CC[cc as usize]) }
}

fn bswap(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w48(rng, bits);
    let reg = rng.below(8) as u8;
    let mut b = Vec::new();
    if width == 8 {
        b.push(0x48);
    }
    b.push(0x0F);
    b.push(0xC8 + reg);
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("bswap w{width}") }
}

fn xadd(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(if byte { 0xC0 } else { 0xC1 });
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("xadd w{width}") }
}

fn cmpxchg(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(if byte { 0xB0 } else { 0xB1 });
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("cmpxchg w{width}") }
}

fn xchg(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0x86 } else { 0x87 });
    b.push(modrm_reg(reg, rm));
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("xchg w{width}") }
}

fn cdq_cwde(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w48(rng, bits); // CWDE/CDQE via 0x98, CDQ/CQO via 0x99
    let cdq = rng.boolean();
    let mut b = Vec::new();
    if width == 8 {
        b.push(0x48);
    } else if width == 2 {
        b.push(0x66);
    }
    b.push(if cdq { 0x99 } else { 0x98 });
    Trial { bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} w{width}", if cdq { "cdq/cqo" } else { "cwde/cdqe" }) }
}

/// Build a fully random seed: interesting GPR values and random status flags.
pub fn seed(rng: &mut Rng) -> Seed {
    let mut gpr = [0u64; 16];
    for g in gpr.iter_mut() {
        *g = rng.operand();
    }
    let mut rflags = RESERVED_ONE;
    for f in [CF, PF, AF, ZF, SF, OF, DF] {
        if rng.boolean() {
            rflags |= f;
        }
    }
    Seed { gpr, rflags }
}
