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

/// A guest data region both engines map identically, so instructions with a
/// memory operand (and the REP string ops) can be diffed on their memory
/// effects — the "touched pages" half of the P0.1 oracle spec.
pub const DATA_BASE: u64 = 0x0001_0000;
pub const DATA_LEN: usize = 0x1000;
/// The middle of the data region; memory operands are based here so a small
/// displacement always lands inside the mapping.
const DATA_MID: u64 = DATA_BASE + (DATA_LEN as u64) / 2;

/// A seeded architectural state shared by both engines for one trial.
#[derive(Clone)]
pub struct Seed {
    pub gpr: [u64; 16],
    pub rflags: u64,
    /// Initial XMM register file (xmm0..xmm15).
    pub xmm: [u128; 16],
    /// Initial contents of the shared data region at [`DATA_BASE`].
    pub data: Vec<u8>,
    /// Initial x87 physical data registers (80-bit each, low 80 bits used).
    /// Always seeded with TOP=0 so physical index == ST-relative index, which
    /// makes seeding Unicorn's TOP-relative `ST0..ST7` unambiguous.
    pub st: [u128; 8],
    /// Initial x87 control word (default: double-precision, round-nearest).
    pub cw: u16,
    /// Initial x87 status word (TOP always 0 at seed time).
    pub sw: u16,
    /// Initial x87 tag word.
    pub tw: u16,
}

/// One generated instruction plus the policy for comparing its result.
pub struct Trial {
    pub bytes: Vec<u8>,
    /// Status flags this instruction defines for the chosen operands.
    pub defined_flags: u64,
    /// Bitmask of GPR indices whose post-value is architecturally undefined
    /// (e.g. BSF/BSR destination when the source is zero).
    pub skip_reg: u16,
    /// XMM comparison policy: 0 = bit-exact; 4 = f32 lanes NaN-aware; 8 = f64
    /// lanes NaN-aware (a lane that is NaN in both engines counts as equal,
    /// since x86 and the host FPU may pick different NaN payloads).
    pub xmm_nan: u8,
    /// When true, the x87 register stack + status/control words are compared
    /// (this is an x87 trial). Non-x87 trials leave the FPU untouched.
    pub fpu: bool,
    /// Bitmask of ST *physical* registers whose 80-bit value is architecturally
    /// approximate (transcendentals) — compared NaN-aware and to a tolerance
    /// rather than bit-exact, or skipped entirely.
    pub fpu_approx: u8,
    /// Status-word bits to compare for this trial (TOP + condition codes;
    /// exception/precision flags are excluded — exemu models them loosely).
    pub sw_mask: u16,
    pub label: String,
}

/// Status-word TOP field (bits 11..14).
pub const SW_TOP: u16 = 0x3800;
/// TOP plus the comparison condition codes C0/C2/C3 (bits 8, 10, 14). C1 is
/// excluded: it doubles as the round-up / stack-fault indicator and is left
/// *undefined* by many ops, and QEMU's choice for it differs from exemu's
/// f64 core.
pub const SW_TOP_CMP: u16 = SW_TOP | (1 << 8) | (1 << 10) | (1 << 14);

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

/// Register-index space: 0..8 in 32-bit, 0..16 in 64-bit (REX.R/B reach the
/// extended r8..r15). Both engines decode identical bytes, so this only widens
/// the exercised decode path.
#[inline]
fn nregs(bits: Bits) -> u32 {
    if bits == Bits::B64 { 16 } else { 8 }
}

/// The REX prefix byte needed to encode `reg`/`rm` (their high bit → REX.R/B)
/// with optional REX.W, or `None` when a plain (no-REX) encoding suffices.
/// Callers emit it *after* the 0x66 operand-size prefix and before the opcode.
#[inline]
fn rex_rb(reg: u8, rm: u8, w: bool) -> Option<u8> {
    let byte = 0x40 | ((w as u8) << 3) | (((reg >= 8) as u8) << 2) | ((rm >= 8) as u8);
    (byte != 0x40).then_some(byte)
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

/// Build one trial, possibly adjusting `seed`. Roughly half the trials use a
/// memory operand or a REP string op (exercising the ModRM/SIB/disp decoder and
/// the "touched pages" half of the oracle); the rest are register/immediate.
pub fn build(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    match rng.below(4) {
        0 => build_sse(rng, bits, seed),
        1 => build_mem(rng, bits, seed),
        2 => build_x87(rng, bits, seed),
        _ => build_reg(rng, bits, seed),
    }
}

/// Register/immediate-form instructions (no memory operand).
fn build_reg(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
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
    let (reg, rm) = (rng.below(nregs(bits)) as u8, rng.below(nregs(bits)) as u8);
    let opcode = (op << 3) | ((dir as u8) << 1) | (!byte as u8);
    let mut b = Vec::new();
    if width == 2 {
        b.push(0x66);
    }
    if let Some(rex) = rex_rb(reg, rm, width == 8) {
        b.push(rex);
    }
    b.push(opcode);
    b.push(modrm_reg(reg, rm));
    Trial {
        xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0,
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: alu_defined(op), skip_reg: 0, label: format!("{} w{} rm,imm", ALU_MNEM[op as usize], width) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, label: format!("{} w{} imm={}", SH_MNEM[(reg & 7) as usize], width, count) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, label: format!("{} w{} cl(={})", SH_MNEM[(reg & 7) as usize], width, cl & 0xff) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: defined, skip_reg: 0, label: format!("{} w{} {}", if is_shrd { "shrd" } else { "shld" }, width, count_label) }
}

fn mul_one(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let signed = rng.boolean();
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(if signed { 5 } else { 4 }, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("{} w{} (one-op)", if signed { "imul" } else { "mul" }, width) }
}

fn imul2(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(0xAF);
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("imul2 w{width}") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, label: format!("imul3 w{width} {}", if imm8 { "imm8" } else { "immZ" }) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} w{width}", if signed { "idiv" } else { "div" }) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: INCDEC, skip_reg: 0, label: format!("{} w{width}", if dec { "dec" } else { "inc" }) }
}

fn neg(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(3, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("neg w{width}") }
}

fn not(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(2, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("not w{width}") }
}

fn test_rr(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(nregs(bits)) as u8, rng.below(nregs(bits)) as u8);
    let mut b = Vec::new();
    if width == 2 {
        b.push(0x66);
    }
    if let Some(rex) = rex_rb(reg, rm, width == 8) {
        b.push(rex);
    }
    b.push(if byte { 0x84 } else { 0x85 });
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: LOGIC, skip_reg: 0, label: format!("test w{width}") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF, skip_reg: 0, label: format!("{name} w{width} (reg)") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF, skip_reg: 0, label: format!("{} w{width} imm={idx}", ["bt", "bts", "btr", "btc"][sub as usize]) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ZF, skip_reg: skip, label: format!("{} w{width}{}", if bsr { "bsr" } else { "bsf" }, if src_zero { " (src=0)" } else { "" }) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | ZF, skip_reg: 0, label: format!("{} w{width}", if lz { "lzcnt" } else { "tzcnt" }) }
}

fn popcnt(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, true);
    b.push(0x0F);
    b.push(0xB8);
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | OF | SF | ZF | AF | PF, skip_reg: 0, label: format!("popcnt w{width}") }
}

fn movzx_movsx(rng: &mut Rng, bits: Bits) -> Trial {
    // MOVSXD (0x63) in 64-bit occasionally.
    if bits == Bits::B64 && rng.below(4) == 0 {
        let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
        let b = vec![0x48, 0x63, modrm_reg(reg, rm)];
        return Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "movsxd r64,rm32".into() };
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} dst{dst}<-src{src}", if signed { "movsx" } else { "movzx" }) }
}

const CC: [&str; 16] = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

fn setcc(rng: &mut Rng) -> Trial {
    let cc = rng.below(16) as u8;
    let rm = rng.below(8) as u8;
    let b = vec![0x0F, 0x90 + cc, modrm_reg(0, rm)];
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("set{}", CC[cc as usize]) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("cmov{} w{width}", CC[cc as usize]) }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("bswap w{width}") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("xadd w{width}") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("cmpxchg w{width}") }
}

fn xchg(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0x86 } else { 0x87 });
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("xchg w{width}") }
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
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} w{width}", if cdq { "cdq/cqo" } else { "cwde/cdqe" }) }
}

// ---- memory-operand and string families ------------------------------------

/// Base registers safe to use at ModRM mod=01 without SIB (rm=4) or the
/// disp32 special case (rm=5): ecx, ebx, esi, edi.
const MEM_BASES: [u8; 4] = [1, 3, 6, 7];

/// Point base register `base` at the middle of the data region and return a
/// small displacement so `[base+disp]` stays inside the mapping for operands
/// up to 8 bytes.
fn point_data(seed: &mut Seed, base: u8, rng: &mut Rng) -> i8 {
    seed.gpr[base as usize] = DATA_MID;
    (rng.below(0xF0) as i32 - 0x78) as i8 // ~[-120, 119]
}

fn push_mem(b: &mut Vec<u8>, reg: u8, base: u8, disp: i8) {
    b.push(0x40 | ((reg & 7) << 3) | (base & 7)); // mod=01, r/m=base
    b.push(disp as u8);
}

fn build_mem(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    match rng.below(10) {
        0 => mem_alu(rng, bits, seed),
        1 => mem_mov(rng, bits, seed),
        2 => mem_movzx_movsx(rng, bits, seed),
        3 => mem_incdec(rng, bits, seed),
        4 => mem_neg_not(rng, bits, seed),
        5 => mem_shift(rng, bits, seed),
        6 => mem_xadd(rng, bits, seed),
        7 => mem_cmpxchg(rng, bits, seed),
        8 => mem_test(rng, bits, seed),
        _ => string_op(rng, bits, seed),
    }
}

fn mem_alu(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let op = rng.below(8) as u8;
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let dir = rng.boolean(); // false: [m],r   true: r,[m]
    let reg = rng.below(8) as u8;
    let base = *rng.pick(&MEM_BASES);
    let disp = point_data(seed, base, rng);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push((op << 3) | ((dir as u8) << 1) | (!byte as u8));
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: alu_defined(op), skip_reg: 0, label: format!("{} w{} {}", ALU_MNEM[op as usize], width, if dir { "r,[m]" } else { "[m],r" }) }
}

fn mem_mov(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let reg = rng.below(8) as u8;
    let disp = point_data(seed, base, rng);
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    let label = match rng.below(3) {
        0 => {
            b.push(if byte { 0x88 } else { 0x89 });
            push_mem(&mut b, reg, base, disp);
            format!("mov [m],r w{width}")
        }
        1 => {
            b.push(if byte { 0x8A } else { 0x8B });
            push_mem(&mut b, reg, base, disp);
            format!("mov r,[m] w{width}")
        }
        _ => {
            b.push(if byte { 0xC6 } else { 0xC7 });
            push_mem(&mut b, 0, base, disp);
            emit_imm(&mut b, rng.operand(), if byte { 1 } else if width == 2 { 2 } else { 4 });
            format!("mov [m],imm w{width}")
        }
    };
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label }
}

fn mem_movzx_movsx(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let reg = rng.below(8) as u8;
    let disp = point_data(seed, base, rng);
    let src = if rng.boolean() { 1 } else { 2 };
    let dst = if src == 1 { *rng.pick(if bits == Bits::B64 { &[2u8, 4, 8][..] } else { &[2u8, 4][..] }) } else if bits == Bits::B64 { *rng.pick(&[4u8, 8]) } else { 4 };
    let signed = rng.boolean();
    let op2 = match (src, signed) {
        (1, false) => 0xB6,
        (2, false) => 0xB7,
        (1, true) => 0xBE,
        _ => 0xBF,
    };
    let mut b = Vec::new();
    prefixes(&mut b, dst, false);
    b.push(0x0F);
    b.push(op2);
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{} dst{dst}<-[m]{src}", if signed { "movsx" } else { "movzx" }) }
}

fn mem_incdec(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let disp = point_data(seed, base, rng);
    let dec = rng.boolean();
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0xFE } else { 0xFF });
    push_mem(&mut b, if dec { 1 } else { 0 }, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: INCDEC, skip_reg: 0, label: format!("{} [m] w{width}", if dec { "dec" } else { "inc" }) }
}

fn mem_neg_not(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let disp = point_data(seed, base, rng);
    let is_neg = rng.boolean();
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0xF6 } else { 0xF7 });
    push_mem(&mut b, if is_neg { 3 } else { 2 }, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: if is_neg { ARITH } else { 0 }, skip_reg: 0, label: format!("{} [m] w{width}", if is_neg { "neg" } else { "not" }) }
}

fn mem_shift(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let disp = point_data(seed, base, rng);
    let regf = rng.below(8) as u8;
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let wb = (width as u32) * 8;
    let count = rng.below(wb + 1);
    let masked = count & if width == 8 { 0x3f } else { 0x1f };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0xC0 } else { 0xC1 });
    push_mem(&mut b, regf, base, disp);
    emit_imm(&mut b, count as u64, 1);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(regf, masked), skip_reg: 0, label: format!("{} [m] w{width} imm={count}", SH_MNEM[(regf & 7) as usize]) }
}

fn mem_xadd(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let reg = rng.below(8) as u8;
    let disp = point_data(seed, base, rng);
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(if byte { 0xC0 } else { 0xC1 });
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("xadd [m],r w{width}") }
}

fn mem_cmpxchg(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let reg = rng.below(8) as u8;
    let disp = point_data(seed, base, rng);
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(if byte { 0xB0 } else { 0xB1 });
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, label: format!("cmpxchg [m],r w{width}") }
}

fn mem_test(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    let reg = rng.below(8) as u8;
    let disp = point_data(seed, base, rng);
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0x84 } else { 0x85 });
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: LOGIC, skip_reg: 0, label: format!("test [m],r w{width}") }
}

/// REP-able string ops (MOVS/STOS/CMPS/SCAS/LODS). Pointers are placed with a
/// 32-byte headroom in the seeded DF direction so every access stays inside the
/// data region.
fn string_op(rng: &mut Rng, _bits: Bits, seed: &mut Seed) -> Trial {
    let which = rng.below(5);
    let byte = rng.boolean();
    let width = if byte { 1 } else { *rng.pick(&[2u8, 4]) };
    let rep = rng.boolean();
    let df = seed.rflags & DF != 0;
    let count = if rep { 1 + rng.below(8) as u64 } else { 1 };
    let (sp, dp) = if df { (DATA_BASE + 0xE00, DATA_BASE + 0xA00) } else { (DATA_BASE + 0x100, DATA_BASE + 0x500) };
    seed.gpr[6] = sp; // rsi
    seed.gpr[7] = dp; // rdi
    if rep {
        seed.gpr[1] = count; // rcx
    }
    let mut b = Vec::new();
    if rep {
        b.push(0xF3);
    }
    if width == 2 {
        b.push(0x66);
    }
    let (opc, mnem, defined) = match which {
        0 => (if byte { 0xA4 } else { 0xA5 }, "movs", 0),
        1 => (if byte { 0xAA } else { 0xAB }, "stos", 0),
        2 => (if byte { 0xA6 } else { 0xA7 }, "cmps", ARITH),
        3 => (if byte { 0xAE } else { 0xAF }, "scas", ARITH),
        _ => (if byte { 0xAC } else { 0xAD }, "lods", 0),
    };
    b.push(opc);
    let sz = if byte { "b" } else if width == 2 { "w" } else { "d" };
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: defined, skip_reg: 0, label: format!("{}{}{} n={}{}", if rep { "rep " } else { "" }, mnem, sz, count, if df { " df" } else { "" }) }
}

// ---- SSE / SSE2 families (register form) ------------------------------------

/// Emit the mandatory SSE prefix: 0 = none (`...ps`), 1 = `66` (`...pd`/int),
/// 2 = `F3` (`...ss`), 3 = `F2` (`...sd`); plus optional REX.W.
fn sse_prefix(b: &mut Vec<u8>, mp: u8, rexw: bool) {
    match mp {
        1 => b.push(0x66),
        2 => b.push(0xF3),
        3 => b.push(0xF2),
        _ => {}
    }
    if rexw {
        b.push(0x48);
    }
}

const KIND: [&str; 4] = ["ps", "pd", "ss", "sd"];

/// f32 lanes for `...ps`/`...ss`, f64 lanes for `...pd`/`...sd`.
fn nan_lane(mp: u8) -> u8 {
    if mp == 0 || mp == 2 {
        4
    } else {
        8
    }
}

fn build_sse(rng: &mut Rng, bits: Bits, _seed: &mut Seed) -> Trial {
    match rng.below(12) {
        0 => sse_arith(rng),
        1 => sse_sqrt(rng),
        2 => sse_logic(rng),
        3 => sse_comis(rng),
        4 => sse_cvt_i2f(rng, bits),
        5 => sse_cvt_f2i(rng, bits),
        6 => sse_cvt_f2f(rng),
        7 => sse_move(rng, bits),
        8 => sse_int(rng),
        9 => sse_shift_imm(rng),
        10 => sse_shift_var(rng),
        _ => match rng.below(5) {
            0 => sse_shuffle(rng),
            1 => sse_pmovmskb(rng, bits),
            2 => sse_movmsk(rng, bits),
            3 => sse_pextrw(rng, bits),
            _ => sse_cvt_dq(rng),
        },
    }
}

fn sse_arith(rng: &mut Rng) -> Trial {
    let (op2, name) = *rng.pick(&[(0x58u8, "add"), (0x59, "mul"), (0x5C, "sub"), (0x5D, "min"), (0x5E, "div"), (0x5F, "max")]);
    let mp = rng.below(4) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, op2, modrm_reg(d, s)]);
    Trial { xmm_nan: nan_lane(mp), fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{name}{}", KIND[mp as usize]) }
}

fn sse_sqrt(rng: &mut Rng) -> Trial {
    let mp = rng.below(4) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, 0x51, modrm_reg(d, s)]);
    Trial { xmm_nan: nan_lane(mp), fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("sqrt{}", KIND[mp as usize]) }
}

fn sse_logic(rng: &mut Rng) -> Trial {
    let (op2, name, mp) = if rng.boolean() {
        let (o, n) = *rng.pick(&[(0xDBu8, "pand"), (0xDF, "pandn"), (0xEB, "por"), (0xEF, "pxor")]);
        (o, n, 1u8)
    } else {
        let (o, n) = *rng.pick(&[(0x54u8, "andps"), (0x55, "andnps"), (0x56, "orps"), (0x57, "xorps")]);
        (o, n, rng.below(2) as u8)
    };
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, op2, modrm_reg(d, s)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: name.into() }
}

fn sse_comis(rng: &mut Rng) -> Trial {
    let op2 = if rng.boolean() { 0x2E } else { 0x2F };
    let dbl = rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, if dbl { 1 } else { 0 }, false);
    b.extend([0x0F, op2, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | PF | AF | ZF | SF | OF, skip_reg: 0, label: format!("{}comis{}", if op2 == 0x2E { "u" } else { "" }, if dbl { "d" } else { "s" }) }
}

fn sse_cvt_i2f(rng: &mut Rng, bits: Bits) -> Trial {
    let sd = rng.boolean();
    let rexw = bits == Bits::B64 && rng.boolean();
    let (d, rm) = (rng.below(8) as u8, rng.below(8) as u8); // rm = GP source
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd { 3 } else { 2 }, rexw);
    b.extend([0x0F, 0x2A, modrm_reg(d, rm)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("cvtsi2s{}{}", if sd { "d" } else { "s" }, if rexw { " r64" } else { "" }) }
}

fn sse_cvt_f2i(rng: &mut Rng, bits: Bits) -> Trial {
    let op2 = if rng.boolean() { 0x2C } else { 0x2D }; // trunc / round
    let sd = rng.boolean();
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd { 3 } else { 2 }, rexw);
    b.extend([0x0F, op2, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("cvt{}s{}2si{}", if op2 == 0x2C { "t" } else { "" }, if sd { "d" } else { "s" }, if rexw { " r64" } else { "" }) }
}

fn sse_cvt_f2f(rng: &mut Rng) -> Trial {
    let sd2ss = rng.boolean();
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd2ss { 3 } else { 2 }, false); // F2 = cvtsd2ss, F3 = cvtss2sd
    b.extend([0x0F, 0x5A, modrm_reg(d, s)]);
    Trial { xmm_nan: if sd2ss { 4 } else { 8 }, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: if sd2ss { "cvtsd2ss".into() } else { "cvtss2sd".into() } }
}

/// CVTDQ2PS (NP) / CVTPS2DQ (66) / CVTTPS2DQ (F3) — packed int32 ↔ f32.
fn sse_cvt_dq(rng: &mut Rng) -> Trial {
    let (mp, name) = *rng.pick(&[(0u8, "cvtdq2ps"), (1, "cvtps2dq"), (2, "cvttps2dq")]);
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, 0x5B, modrm_reg(d, s)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: name.into() }
}

fn sse_move(rng: &mut Rng, bits: Bits) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    match rng.below(6) {
        0 => Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x0F, 0x28, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: "movaps".into() },
        1 => Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, 0x6F, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: "movdqa".into() },
        2 => {
            let sd = rng.boolean();
            Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![if sd { 0xF2 } else { 0xF3 }, 0x0F, 0x10, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: if sd { "movsd".into() } else { "movss".into() } }
        }
        3 => {
            let rexw = bits == Bits::B64 && rng.boolean();
            let mut b = vec![0x66];
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0x6E, modrm_reg(d, s)]);
            Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "movd xmm,r".into() }
        }
        4 => {
            let rexw = bits == Bits::B64 && rng.boolean();
            let mut b = vec![0x66];
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0x7E, modrm_reg(d, s)]); // reg=xmm src, rm=GP dst
            Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "movd r,xmm".into() }
        }
        _ => Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0xF3, 0x0F, 0x7E, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: "movq xmm".into() },
    }
}

fn sse_int(rng: &mut Rng) -> Trial {
    let (op2, name) = *rng.pick(&[
        (0xFCu8, "paddb"),
        (0xFD, "paddw"),
        (0xFE, "paddd"),
        (0xD4, "paddq"),
        (0xF8, "psubb"),
        (0xF9, "psubw"),
        (0xFA, "psubd"),
        (0xFB, "psubq"),
        (0x74, "pcmpeqb"),
        (0x75, "pcmpeqw"),
        (0x76, "pcmpeqd"),
        (0x64, "pcmpgtb"),
        (0x65, "pcmpgtw"),
        (0x66, "pcmpgtd"),
        (0x60, "punpcklbw"),
        (0x61, "punpcklwd"),
        (0x62, "punpckldq"),
        (0x6C, "punpcklqdq"),
        (0x68, "punpckhbw"),
        (0x69, "punpckhwd"),
        (0x6A, "punpckhdq"),
        (0x6D, "punpckhqdq"),
        (0xDA, "pminub"),
        (0xDE, "pmaxub"),
        // saturating add/sub (signed + unsigned, byte + word)
        (0xDC, "paddusb"),
        (0xDD, "paddusw"),
        (0xD8, "psubusb"),
        (0xD9, "psubusw"),
        (0xEC, "paddsb"),
        (0xED, "paddsw"),
        (0xE8, "psubsb"),
        (0xE9, "psubsw"),
        // packed multiply
        (0xD5, "pmullw"),
        (0xE5, "pmulhw"),
        (0xE4, "pmulhuw"),
        (0xF4, "pmuludq"),
        (0xF5, "pmaddwd"),
        // average / SAD / pack-with-saturation
        (0xE0, "pavgb"),
        (0xE3, "pavgw"),
        (0xF6, "psadbw"),
        (0x63, "packsswb"),
        (0x6B, "packssdw"),
        (0x67, "packuswb"),
    ]);
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: name.into() }
}

fn sse_pmovmskb(rng: &mut Rng, bits: Bits) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = vec![0x66];
    if rexw {
        b.push(0x48);
    }
    b.extend([0x0F, 0xD7, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "pmovmskb".into() }
}

/// PEXTRW (66 0F C5 /r ib) — extract word[imm8&7] of an xmm into a GP reg.
/// Register form only.
fn sse_pextrw(rng: &mut Rng, bits: Bits) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = vec![0x66];
    if rexw {
        b.push(0x48);
    }
    b.extend([0x0F, 0xC5, modrm_reg(reg, rm), rng.below(8) as u8]);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "pextrw".into() }
}

/// MOVMSKPS (NP) / MOVMSKPD (66) — sign bits of the packed floats into a GP
/// register. Register form only (the memory form is #UD).
fn sse_movmsk(rng: &mut Rng, bits: Bits) -> Trial {
    let pd = rng.boolean();
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = Vec::new();
    if pd {
        b.push(0x66);
    }
    if rexw {
        b.push(0x48);
    }
    b.extend([0x0F, 0x50, modrm_reg(reg, rm)]);
    Trial {
        xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0,
        bytes: b,
        defined_flags: 0,
        skip_reg: 0,
        label: if pd { "movmskpd" } else { "movmskps" }.into(),
    }
}

fn sse_shift_imm(rng: &mut Rng) -> Trial {
    let op2 = *rng.pick(&[0x71u8, 0x72, 0x73]);
    let digit = if op2 == 0x73 { *rng.pick(&[2u8, 3, 6, 7]) } else { *rng.pick(&[2u8, 4, 6]) };
    let rm = rng.below(8) as u8; // xmm operand (shifted in place)
    let imm = rng.below(20) as u8;
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(digit, rm), imm], defined_flags: 0, skip_reg: 0, label: format!("psh-imm {op2:#x}/{digit} imm={imm}") }
}

fn sse_shift_var(rng: &mut Rng) -> Trial {
    let (op2, name) = *rng.pick(&[
        (0xD1u8, "psrlw"),
        (0xD2, "psrld"),
        (0xD3, "psrlq"),
        (0xE1, "psraw"),
        (0xE2, "psrad"),
        (0xF1, "psllw"),
        (0xF2, "pslld"),
        (0xF3, "psllq"),
    ]);
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, label: name.into() }
}

fn sse_shuffle(rng: &mut Rng) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.next_u32() as u8;
    if rng.boolean() {
        let mp = *rng.pick(&[1u8, 2, 3]); // pshufd(66) / pshufhw(F3) / pshuflw(F2)
        let mut b = Vec::new();
        sse_prefix(&mut b, mp, false);
        b.extend([0x0F, 0x70, modrm_reg(d, s), imm]);
        Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "pshuf".into() }
    } else {
        let mp = rng.below(2) as u8; // shufps(none) / shufpd(66)
        let mut b = Vec::new();
        sse_prefix(&mut b, mp, false);
        b.extend([0x0F, 0xC6, modrm_reg(d, s), imm]);
        Trial { xmm_nan: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, label: "shufp".into() }
    }
}

// ---- x87 FPU family ---------------------------------------------------------
//
// Every x87 trial sets `fpu: true` so the engine compares the ST stack +
// status/control words. The seed always has TOP=0 and eight f64-exact 80-bit
// registers; the control word is double-precision round-nearest so QEMU's
// 80-bit results round to double and match exemu's f64 core.

/// Write an f64-exact value into the DATA region and return the base register +
/// displacement to address it (mod=01, no SIB). `wbytes` is the operand size so
/// the whole value stays inside the mapping.
fn point_fp(seed: &mut Seed, base: u8, rng: &mut Rng, val_bytes: &[u8]) -> i8 {
    seed.gpr[base as usize] = DATA_MID;
    let disp = (rng.below(0x60) as i32 - 0x30) as i8; // ~[-48, 47]
    let addr = (DATA_MID as i64 + disp as i64 - DATA_BASE as i64) as usize;
    seed.data[addr..addr + val_bytes.len()].copy_from_slice(val_bytes);
    disp
}

fn build_x87(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    match rng.below(9) {
        0 => x87_arith_reg(rng, seed),
        1 => x87_arith_mem(rng, bits, seed),
        2 => x87_load_mem(rng, bits, seed),
        3 => x87_store_mem(rng, bits, seed),
        4 => x87_ld_const(rng, seed),
        5 => x87_compare(rng, seed),
        6 => x87_misc(rng, seed),
        7 => x87_transcendental(rng, seed),
        8 => x87_reduce(rng, seed),
        _ => x87_control(rng, bits, seed),
    }
}

/// FPREM/FPREM1/FSCALE — the two-operand ST0/ST1 reductions. Results are exact
/// doubles (remainder / multiply-by-power-of-two), so they are compared
/// bit-exactly; only TOP is checked in the status word (FPREM's C0/C1/C3
/// quotient bits are compared too via SW_TOP_CMP).
fn x87_reduce(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    // ST0 dividend, ST1 divisor / scale. Keep both f64-exact, the divisor
    // non-zero, and |dividend| >= |divisor| so the reduction takes its ordinary
    // path. (When |d| < |b| the x87 FPREM/FPREM1 completion step is
    // implementation-defined in the 0.5 < d/b < 1 sub-range — QEMU leaves d
    // unchanged there — so that sub-range is left out of the differential.)
    let divisor = *rng.pick(&[1.0f64, 2.0, 3.0, -4.0, 8.0, -16.0, 10.0, -2.0]);
    let big = *rng.pick(&[12.25f64, 100.0, 255.0, 1024.0, 37.5, -88.0, 512.0, -300.0]);
    let dividend = if big.abs() >= divisor.abs() { big } else { big * divisor };
    seed.st[0] = f64_to_ext_seed(dividend);
    seed.st[1] = f64_to_ext_seed(divisor);
    // FPREM/FPREM1 pack the low quotient bits into C0/C1/C3, but the exact
    // encoding depends on the (implementation-defined) partial-reduction step
    // count, so only TOP is compared — the *value* result is still checked
    // bit-exactly.
    let (bytes, label): (Vec<u8>, &str) = match rng.below(3) {
        0 => (vec![0xD9, 0xF8], "fprem"),
        1 => (vec![0xD9, 0xF5], "fprem1"),
        _ => (vec![0xD9, 0xFD], "fscale"),
    };
    let mask = SW_TOP;
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: mask, bytes, defined_flags: 0, skip_reg: 0, label: label.into() }
}

/// Transcendentals: FSIN/FCOS/FSINCOS/FPTAN/FPATAN/F2XM1/FYL2X/FYL2XP1. These
/// are host-math approximations that are *not* bit-exact against a real x87, so
/// every result register is compared **loosely** (equal-as-f64 or both-NaN,
/// `fpu_approx = 0xFF`) and only TOP is checked in the status word. Inputs are
/// kept in a small in-range interval so the reduction path (which sets C2) is
/// not exercised.
fn x87_transcendental(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    // Domain-safe small f64-exact operands, chosen per op so both engines stay
    // in the same well-defined branch (no NaN/inf boundary disagreements).
    let trig = [0.0f64, 0.25, 0.5, -0.5, 0.75, -0.25, 1.0, -1.0];
    let pos = [0.25f64, 0.5, 1.0, 2.0, 4.0, 0.125, 8.0, 0.75]; // > 0 (log domain)
    let unit = [0.0f64, 0.25, 0.5, -0.5, 0.75, -0.75, 1.0, -1.0]; // |x| <= 1
    let (bytes, label, st0, st1): (Vec<u8>, &str, f64, f64) = match rng.below(8) {
        0 => (vec![0xD9, 0xFE], "fsin", *rng.pick(&trig), *rng.pick(&trig)),
        1 => (vec![0xD9, 0xFF], "fcos", *rng.pick(&trig), *rng.pick(&trig)),
        2 => (vec![0xD9, 0xFB], "fsincos", *rng.pick(&trig), *rng.pick(&trig)),
        3 => (vec![0xD9, 0xF2], "fptan", *rng.pick(&trig), *rng.pick(&trig)),
        4 => (vec![0xD9, 0xF3], "fpatan", *rng.pick(&pos), *rng.pick(&pos)),
        5 => (vec![0xD9, 0xF0], "f2xm1", *rng.pick(&unit), *rng.pick(&trig)),
        6 => (vec![0xD9, 0xF1], "fyl2x", *rng.pick(&pos), *rng.pick(&pos)),
        _ => (vec![0xD9, 0xF9], "fyl2xp1", *rng.pick(&pos), *rng.pick(&pos)),
    };
    seed.st[0] = f64_to_ext_seed(st0);
    seed.st[1] = f64_to_ext_seed(st1);
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0xFF, sw_mask: SW_TOP, bytes, defined_flags: 0, skip_reg: 0, label: label.into() }
}

/// Register-form arithmetic: FADD/FMUL/FSUB(R)/FDIV(R) between ST0 and ST(i),
/// plus the FADDP/…P pop forms. Seeds a non-empty stack (TOP already 0, all
/// registers tagged valid via a full tag word).
fn x87_arith_reg(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000; // all valid — the stack is "full" of our seeded values
    let sti = rng.below(8) as u8;
    // esc D8 (ST0 dst), DC (ST(i) dst), DE (ST(i) dst then pop).
    let (esc, name_dst) = *rng.pick(&[(0xD8u8, "st0"), (0xDC, "sti"), (0xDE, "sti+pop")]);
    let reg = *rng.pick(&[0u8, 1, 4, 5, 6, 7]); // add/mul/sub/subr/div/divr
    // FCOMPP is DE D9 specifically; keep DE to arithmetic /reg here.
    let modrm = 0xC0 | (reg << 3) | sti;
    let mnem = ["fadd", "fmul", "?", "?", "fsub", "fsubr", "fdiv", "fdivr"][reg as usize];
    Trial {
        xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP,
        bytes: vec![esc, modrm], defined_flags: 0, skip_reg: 0,
        label: format!("{mnem} {name_dst} st{sti}"),
    }
}

/// Memory-form arithmetic: FADD/…/FDIVR with a 32- or 64-bit float in memory.
fn x87_arith_mem(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    let is64 = rng.boolean();
    let esc = if is64 { 0xDCu8 } else { 0xD8 };
    let reg = *rng.pick(&[0u8, 1, 4, 5, 6, 7]);
    let base = *rng.pick(&MEM_BASES);
    let v = fpu_edge_f64(rng);
    let disp = if is64 { point_fp(seed, base, rng, &v.to_bits().to_le_bytes()) } else { point_fp(seed, base, rng, &(v as f32).to_bits().to_le_bytes()) };
    let mut b = Vec::new();
    let _ = bits;
    b.push(esc);
    push_mem(&mut b, reg, base, disp);
    let mnem = ["fadd", "fmul", "?", "?", "fsub", "fsubr", "fdiv", "fdivr"][reg as usize];
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, label: format!("{mnem} m{}", if is64 { 64 } else { 32 }) }
}

/// FLD m32/m64, FILD m16/m32/m64 — push a memory value onto the stack.
fn x87_load_mem(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // Keep one free stack slot so the push doesn't overflow (harmless for us,
    // but keeps TOP arithmetic sane): mark reg 7 empty.
    seed.tw = 0xC000; // physical 7 empty, rest valid
    let base = *rng.pick(&MEM_BASES);
    let _ = bits;
    let (esc, reg, bytes, label): (u8, u8, Vec<u8>, &str) = match rng.below(5) {
        0 => { let v = fpu_edge_f64(rng); (0xD9, 0, (v as f32).to_bits().to_le_bytes().to_vec(), "fld m32") }
        1 => { let v = fpu_edge_f64(rng); (0xDD, 0, v.to_bits().to_le_bytes().to_vec(), "fld m64") }
        2 => { let v = (rng.next_u32() as i16) as i64; (0xDF, 0, (v as u16).to_le_bytes().to_vec(), "fild m16") }
        3 => { let v = rng.next_u32() as i32; (0xDB, 0, (v as u32).to_le_bytes().to_vec(), "fild m32") }
        _ => { let v = (rng.next_u32() as i32) as i64 * 1000; (0xDF, 5, (v as u64).to_le_bytes().to_vec(), "fild m64") }
    };
    let disp = point_fp(seed, base, rng, &bytes);
    let mut b = vec![esc];
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, label: label.into() }
}

/// FST/FSTP m32/m64, FIST/FISTP m16/m32/m64 — store ST0 to memory. The stored
/// bytes are diffed via the shared DATA region.
fn x87_store_mem(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    let _ = bits;
    let base = *rng.pick(&MEM_BASES);
    let (esc, reg, wbytes, label): (u8, u8, usize, &str) = match rng.below(6) {
        0 => (0xD9, 2, 4, "fst m32"),
        1 => (0xD9, 3, 4, "fstp m32"),
        2 => (0xDD, 2, 8, "fst m64"),
        3 => (0xDD, 3, 8, "fstp m64"),
        4 => (0xDF, 3, 2, "fistp m16"),
        _ => (0xDB, 3, 4, "fistp m32"),
    };
    let disp = point_fp(seed, base, rng, &vec![0u8; wbytes]);
    let mut b = vec![esc];
    push_mem(&mut b, reg, base, disp);
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, label: label.into() }
}

/// FLD1/FLDZ/FLDPI/FLDL2T/FLDL2E/FLDLG2/FLDLN2 — push a ROM constant.
fn x87_ld_const(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0xC000; // keep a free slot
    let low = *rng.pick(&[0u8, 1, 2, 3, 4, 5, 6]); // E8..EE
    let names = ["fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz"];
    // The transcendental log/ln constants are exact 80-bit ROM values, but
    // their double rounding differs from a from-scratch f64; compare the pushed
    // register loosely for the log constants, bit-exact for 1.0/0.0/pi.
    let approx = if low == 1 || low == 2 || low == 4 || low == 5 { 1u8 << 7 /*new ST0 = phys 7*/ } else { 0 };
    Trial { xmm_nan: 0, fpu: true, fpu_approx: approx, sw_mask: SW_TOP, bytes: vec![0xD9, 0xE8 + low], defined_flags: 0, skip_reg: 0, label: names[low as usize].into() }
}

/// FCOM/FCOMP/FCOMPP/FUCOM/FUCOMI/FCOMI — compares that set condition codes or
/// EFLAGS.
fn x87_compare(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    let sti = rng.below(8) as u8;
    // The x87-condition-code compares (FCOM…) set C0/C2/C3; the …I forms set
    // EFLAGS instead and leave the FPU condition codes alone.
    let (bytes, label, flags, sw_mask): (Vec<u8>, String, u64, u16) = match rng.below(6) {
        0 => (vec![0xD8, 0xD0 | sti], format!("fcom st{sti}"), 0, SW_TOP_CMP),
        1 => (vec![0xD8, 0xD8 | sti], format!("fcomp st{sti}"), 0, SW_TOP_CMP),
        2 => (vec![0xDE, 0xD9], "fcompp".into(), 0, SW_TOP_CMP),
        3 => (vec![0xDD, 0xE0 | sti], format!("fucom st{sti}"), 0, SW_TOP_CMP),
        // FCOMI/FCOMIP set ZF/PF/CF; OF/SF/AF are cleared by the SDM but QEMU
        // leaves some of them unmodified, so only the three defined bits are
        // compared.
        4 => (vec![0xDB, 0xF0 | sti], format!("fcomi st{sti}"), CF | PF | ZF, SW_TOP),
        _ => (vec![0xDF, 0xF0 | sti], format!("fcomip st{sti}"), CF | PF | ZF, SW_TOP),
    };
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask, bytes, defined_flags: flags, skip_reg: 0, label }
}

/// FXCH/FABS/FCHS/FSQRT/FRNDINT/FSCALE/FXAM/FTST/FINCSTP/FDECSTP and the pop
/// forms.
fn x87_misc(rng: &mut Rng, seed: &mut Seed) -> Trial {
    seed.tw = 0x0000;
    let sti = rng.below(8) as u8;
    // FTST/FXAM set condition codes; the rest leave only C1 (undefined) so we
    // compare TOP alone for them.
    let (bytes, label, sw_mask): (Vec<u8>, String, u16) = match rng.below(9) {
        0 => (vec![0xD9, 0xC8 | sti], format!("fxch st{sti}"), SW_TOP),
        1 => (vec![0xD9, 0xE0], "fchs".into(), SW_TOP),
        2 => (vec![0xD9, 0xE1], "fabs".into(), SW_TOP),
        3 => (vec![0xD9, 0xFA], "fsqrt".into(), SW_TOP),
        4 => (vec![0xD9, 0xFC], "frndint".into(), SW_TOP),
        5 => (vec![0xD9, 0xE4], "ftst".into(), SW_TOP_CMP),
        6 => (vec![0xD9, 0xE5], "fxam".into(), SW_TOP_CMP),
        7 => (vec![0xD9, 0xF6], "fdecstp".into(), SW_TOP),
        _ => (vec![0xD9, 0xF7], "fincstp".into(), SW_TOP),
    };
    Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask, bytes, defined_flags: 0, skip_reg: 0, label }
}

/// FNINIT / FNSTCW / FLDCW / FNSTSW (m16 and AX). Exercises the control/status
/// plumbing and the `fnstsw ax` idiom.
fn x87_control(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let _ = bits;
    match rng.below(4) {
        0 => Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: vec![0xDB, 0xE3], defined_flags: 0, skip_reg: 0, label: "fninit".into() },
        1 => {
            // FLDCW m16: load a fresh (double-precision) control word.
            let base = *rng.pick(&MEM_BASES);
            let cw: u16 = 0x027F | ((rng.below(4) as u16) << 10); // vary RC bits
            let disp = point_fp(seed, base, rng, &cw.to_le_bytes());
            let mut b = vec![0xD9];
            push_mem(&mut b, 5, base, disp);
            Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, label: "fldcw".into() }
        }
        2 => {
            // FNSTCW m16.
            seed.tw = 0x0000;
            let base = *rng.pick(&MEM_BASES);
            let disp = point_fp(seed, base, rng, &[0u8, 0]);
            let mut b = vec![0xD9];
            push_mem(&mut b, 7, base, disp);
            Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, label: "fnstcw".into() }
        }
        _ => {
            // fnstsw ax after seeding some condition codes via a compare would
            // be two instructions; here just FNSTSW AX reads the seeded SW.
            seed.tw = 0x0000;
            seed.sw = (rng.below(0x8) as u16) << 8; // seed some condition bits (TOP stays 0)
            Trial { xmm_nan: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: vec![0xDF, 0xE0], defined_flags: 0, skip_reg: 0, label: "fnstsw ax".into() }
        }
    }
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
    let mut data = vec![0u8; DATA_LEN];
    for b in data.iter_mut() {
        *b = rng.next_u32() as u8;
    }
    let mut xmm = [0u128; 16];
    for x in xmm.iter_mut() {
        *x = xmm_seed(rng);
    }
    // x87: seed each physical register with an f64-exact 80-bit value so that
    // loads/stores are exact and double-precision arithmetic matches. Control
    // word forced to double precision (PC=10b) + round-nearest so QEMU's true
    // 80-bit FPU rounds each result to double, matching exemu's f64 core.
    // TOP is 0 at seed time (physical == ST-relative).
    let mut st = [0u128; 8];
    for s in st.iter_mut() {
        *s = f64_to_ext_seed(fpu_edge_f64(rng));
    }
    let cw = 0x027F; // double precision, round-to-nearest, all masked
    Seed { gpr, rflags, xmm, data, st, cw, sw: 0x0000, tw: 0xFFFF }
}

/// Encode an `f64` into an x87 80-bit extended value (mirrors the interpreter's
/// `f64_to_ext`; the oracle keeps its own copy so it needn't peek at internals).
fn f64_to_ext_seed(x: f64) -> u128 {
    let bits = x.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7ff) as u32;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    let (ext_exp, signif): (u32, u64) = if exp == 0x7ff {
        let s = if frac == 0 { 0x8000_0000_0000_0000 } else { 0x8000_0000_0000_0000 | (frac << 11) };
        (0x7fff, s)
    } else if exp == 0 {
        (0, 0) // treat subnormal seeds as ±0 (kept out of the edge set anyway)
    } else {
        (exp - 1023 + 16383, 0x8000_0000_0000_0000 | (frac << 11))
    };
    ((sign as u128) << 79) | ((ext_exp as u128) << 64) | (signif as u128)
}

/// f64 values that are exactly representable *and* stress the FPU: small
/// integers, powers of two, ±0, ±inf, NaN, and a few "nice" fractions whose
/// double value is exact.
fn fpu_edge_f64(rng: &mut Rng) -> f64 {
    const EDGES: [f64; 20] = [
        0.0, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, 10.0, 100.0, -7.0, 256.0, -0.25, 1024.0,
        0.125, 65536.0, -1048576.0, f64::INFINITY, f64::NEG_INFINITY,
    ];
    match rng.below(3) {
        0 => EDGES[rng.below(EDGES.len() as u32) as usize],
        1 => f64::NAN,
        // A random-but-exact double: an integer scaled by a small power of two.
        _ => {
            let m = (rng.next_u32() as i64 as f64) / 16.0; // exact (÷16)
            if rng.boolean() { -m } else { m }
        }
    }
}

/// Interesting f64 lane bit patterns (±0, ±1, halves, ±inf, quiet/signaling
/// NaN, max, min-normal, denormal, pi, large magnitudes).
const F64_EDGES: [u64; 16] = [
    0x0000_0000_0000_0000, // +0.0
    0x8000_0000_0000_0000, // -0.0
    0x3FF0_0000_0000_0000, // 1.0
    0xBFF0_0000_0000_0000, // -1.0
    0x3FE0_0000_0000_0000, // 0.5
    0x4000_0000_0000_0000, // 2.0
    0x7FF0_0000_0000_0000, // +inf
    0xFFF0_0000_0000_0000, // -inf
    0x7FF8_0000_0000_0000, // qNaN
    0x7FF0_0000_0000_0001, // sNaN
    0x7FEF_FFFF_FFFF_FFFF, // f64::MAX
    0x0010_0000_0000_0000, // min normal
    0x0000_0000_0000_0001, // denormal
    0x4009_21FB_5444_2D18, // pi
    0x7E37_E43C_8800_759C, // 1e300
    0xC1E0_0000_0000_0000, // -2^31
];

/// Interesting f32 lane bit patterns.
const F32_EDGES: [u32; 15] = [
    0x0000_0000, // +0.0
    0x8000_0000, // -0.0
    0x3F80_0000, // 1.0
    0xBF80_0000, // -1.0
    0x3F00_0000, // 0.5
    0x4000_0000, // 2.0
    0x7F80_0000, // +inf
    0xFF80_0000, // -inf
    0x7FC0_0000, // qNaN
    0x7F80_0001, // sNaN
    0x7F7F_FFFF, // f32::MAX
    0x0000_0001, // denormal
    0x4049_0FDB, // pi
    0x7149_F2CA, // ~1e30
    0xF149_F2CA, // ~-1e30
];

/// A 128-bit XMM seed: a mix of fully-random bits and float-edge lanes so the
/// float ops hit NaN/inf/denormal/±0 boundaries and the integer ops see
/// arbitrary bytes.
fn xmm_seed(rng: &mut Rng) -> u128 {
    match rng.below(4) {
        0 => (rng.next_u64() as u128) | ((rng.next_u64() as u128) << 64),
        1 => {
            let lo = *rng.pick(&F64_EDGES) as u128;
            let hi = *rng.pick(&F64_EDGES) as u128;
            lo | (hi << 64)
        }
        2 => {
            let mut v = 0u128;
            for i in 0..4 {
                v |= (*rng.pick(&F32_EDGES) as u128) << (i * 32);
            }
            v
        }
        _ => {
            let lo = *rng.pick(&F64_EDGES) as u128;
            lo | ((rng.next_u64() as u128) << 64)
        }
    }
}
