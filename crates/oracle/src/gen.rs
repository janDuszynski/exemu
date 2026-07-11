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
    /// Initial XMM register file — the low 128 bits of ymm0..ymm15.
    pub xmm: [u128; 16],
    /// Initial upper 128 bits of ymm0..ymm15 (the AVX YMM_Hi state). Only the
    /// VEX category seeds these non-zero.
    pub ymm_hi: [u128; 16],
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
    /// Initial SSE control/status register (`MXCSR`).
    pub mxcsr: u32,
    /// Initial x87 last-instruction pointer/opcode/data-pointer state. Only ever
    /// non-zero for the FXSAVE/XSAVE category, where the save-area layout must
    /// round-trip these fields byte-exactly against the reference.
    pub fip: u64,
    pub fdp: u64,
    pub fop: u16,
    pub fcs: u16,
    pub fds: u16,
}

/// One generated instruction plus the policy for comparing its result.
pub struct Trial {
    pub bytes: Vec<u8>,
    /// Status flags this instruction defines for the chosen operands.
    pub defined_flags: u64,
    /// Bitmask of GPR indices whose post-value is architecturally undefined
    /// (e.g. BSF/BSR destination when the source is zero).
    pub skip_reg: u16,
    /// Bitmask of GPR indices compared under a **subset** policy rather than
    /// equality: every bit exemu sets must also be set by the reference, but the
    /// reference may set *more*. Used only by the CPUID category — exemu reports
    /// an honest *subset* of the reference CPU's feature flags (it must never
    /// advertise a bit the reference lacks, which would prove a fabricated
    /// capability), while the reference's richer QEMU feature set is expected to
    /// be a superset. Registers in this mask are excluded from the plain-equality
    /// pass; a register set in both `skip_reg` and `subset_reg` is skipped.
    pub subset_reg: u16,
    /// For `subset_reg` registers, feature bits to **exclude** from the "extra"
    /// (advertised-but-reference-lacks) check. Used only by the CPUID category
    /// for AVX (leaf1 ECX bit 28) and AVX2 (leaf7 EBX bit 5): the Unicorn/QEMU
    /// reference model executes VEX instructions but never surfaces those bits
    /// in CPUID regardless of its selected CPU model, so a plain subset check
    /// would wrongly reject exemu's *behaviorally-verified* AVX claim. The claim
    /// is proven honest independently — by the VEX category itself (every VEX op
    /// executes and matches the reference lane-for-lane) and by exemu's own
    /// machine-checkable `CPUID_FEATURES` decode-coverage table. Applied only to
    /// the register whose index is set in `subset_reg`.
    pub subset_ignore: u64,
    /// XMM comparison policy: 0 = bit-exact; 4 = f32 lanes NaN-aware; 8 = f64
    /// lanes NaN-aware (a lane that is NaN in both engines counts as equal,
    /// since x86 and the host FPU may pick different NaN payloads).
    pub xmm_nan: u8,
    /// When true, the full 256-bit YMM registers are diffed against the
    /// reference (both the low XMM half and the upper `ymm_hi` half).
    ///
    /// **Reference limitation.** The Unicorn/QEMU-TCG build this oracle links
    /// does NOT implement AVX zero-upper semantics — a VEX.128 op leaves the
    /// upper 128 bits *unchanged* — and it faults (`INSN_INVALID`) on any 256-bit
    /// (VEX.L=1) instruction. So the reference is trustworthy only for the low
    /// 128-bit lane of VEX.128 ops. The VEX category therefore keeps `ymm256`
    /// FALSE (diffing only the low lane against the reference) and instead
    /// asserts exemu's own zero-upper behavior via [`Self::assert_upper_zero`];
    /// the 256-bit lane semantics are pinned by the hand-assembled unit tests in
    /// `cpu/tests/vex.rs`. This field is retained (and available) for the day a
    /// zero-upper-correct reference is wired in.
    pub ymm256: bool,
    /// Bitmask of vector-register indices whose **upper 128 bits exemu must have
    /// zeroed** after this instruction (the VEX.128 zero-upper rule). Checked
    /// against exemu's own post-state only — not the reference — because the
    /// reference does not model zero-upper (see `ymm256`). This turns every
    /// VEX.128 trial into a zero-upper assertion on top of the low-lane diff.
    pub assert_upper_zero: u16,
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
    /// Byte offsets *within the DATA region* that are excluded from the memory
    /// diff. Used by the FXSAVE/XSAVE category for the FOP field (offset 6–7 of
    /// the save area): FOP is the opcode of the *last x87 instruction*, which is
    /// implementation-defined when no such instruction ran (modern CPUs store 0
    /// unless the last op raised an unmasked exception), so exemu and the
    /// reference legitimately differ there. Everything else in the 512/576-byte
    /// area is compared byte-exactly.
    pub skip_mem: Vec<usize>,
    pub label: String,
}

impl Default for Trial {
    /// A plain register/flag trial: bit-exact comparison, no memory/xmm/x87 diff.
    /// Builders override only the fields they care about (bytes, defined_flags,
    /// label, …), which keeps the newer categories readable.
    fn default() -> Self {
        Trial {
            bytes: Vec::new(),
            defined_flags: 0,
            skip_reg: 0,
            subset_reg: 0,
            subset_ignore: 0,
            xmm_nan: 0,
            ymm256: false,
            assert_upper_zero: 0,
            fpu: false,
            fpu_approx: 0,
            sw_mask: 0,
            skip_mem: Vec::new(),
            label: String::new(),
        }
    }
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
    match rng.below(10) {
        0 => build_sse(rng, bits, seed),
        1 => build_mem(rng, bits, seed),
        2 => build_x87(rng, bits, seed),
        3 => build_fxsave(rng, bits, seed),
        4 => build_cpuid(rng, bits, seed),
        5 => build_sse4(rng, bits, seed),
        6 => build_vex(rng, bits, seed),
        7 => build_bmi(rng, bits, seed),
        8 => build_mmx(rng, bits, seed),
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
        xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0,
        bytes: b,
        defined_flags: alu_defined(op),
        skip_reg: 0,
        subset_reg: 0, subset_ignore: 0,
        skip_mem: Vec::new(),
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: alu_defined(op), skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} rm,imm", ALU_MNEM[op as usize], width) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} imm={}", SH_MNEM[(reg & 7) as usize], width, count) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(reg, masked), skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} cl(={})", SH_MNEM[(reg & 7) as usize], width, cl & 0xff) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: defined, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} {}", if is_shrd { "shrd" } else { "shld" }, width, count_label) }
}

fn mul_one(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let signed = rng.boolean();
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(if signed { 5 } else { 4 }, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} (one-op)", if signed { "imul" } else { "mul" }, width) }
}

fn imul2(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(0x0F);
    b.push(0xAF);
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("imul2 w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: MULF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("imul3 w{width} {}", if imm8 { "imm8" } else { "immZ" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width}", if signed { "idiv" } else { "div" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: INCDEC, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width}", if dec { "dec" } else { "inc" }) }
}

fn neg(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(3, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("neg w{width}") }
}

fn not(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w124(rng, bits);
    let rm = rng.below(8) as u8;
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if width == 1 { 0xF6 } else { 0xF7 });
    b.push(modrm_reg(2, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("not w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: LOGIC, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("test w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{name} w{width} (reg)") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width} imm={idx}", ["bt", "bts", "btr", "btc"][sub as usize]) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ZF, skip_reg: skip, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width}{}", if bsr { "bsr" } else { "bsf" }, if src_zero { " (src=0)" } else { "" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | ZF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width}", if lz { "lzcnt" } else { "tzcnt" }) }
}

fn popcnt(rng: &mut Rng, bits: Bits) -> Trial {
    let width = w24(rng, bits);
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, true);
    b.push(0x0F);
    b.push(0xB8);
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | OF | SF | ZF | AF | PF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("popcnt w{width}") }
}

fn movzx_movsx(rng: &mut Rng, bits: Bits) -> Trial {
    // MOVSXD (0x63) in 64-bit occasionally.
    if bits == Bits::B64 && rng.below(4) == 0 {
        let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
        let b = vec![0x48, 0x63, modrm_reg(reg, rm)];
        return Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movsxd r64,rm32".into() };
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} dst{dst}<-src{src}", if signed { "movsx" } else { "movzx" }) }
}

const CC: [&str; 16] = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

fn setcc(rng: &mut Rng) -> Trial {
    let cc = rng.below(16) as u8;
    let rm = rng.below(8) as u8;
    let b = vec![0x0F, 0x90 + cc, modrm_reg(0, rm)];
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("set{}", CC[cc as usize]) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cmov{} w{width}", CC[cc as usize]) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("bswap w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("xadd w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cmpxchg w{width}") }
}

fn xchg(rng: &mut Rng, bits: Bits) -> Trial {
    let byte = rng.boolean();
    let width = if byte { 1 } else { w24(rng, bits) };
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    prefixes(&mut b, width, false);
    b.push(if byte { 0x86 } else { 0x87 });
    b.push(modrm_reg(reg, rm));
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("xchg w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{width}", if cdq { "cdq/cqo" } else { "cwde/cdqe" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: alu_defined(op), skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} w{} {}", ALU_MNEM[op as usize], width, if dir { "r,[m]" } else { "[m],r" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} dst{dst}<-[m]{src}", if signed { "movsx" } else { "movzx" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: INCDEC, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} [m] w{width}", if dec { "dec" } else { "inc" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: if is_neg { ARITH } else { 0 }, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} [m] w{width}", if is_neg { "neg" } else { "not" }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: shift_defined(regf, masked), skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{} [m] w{width} imm={count}", SH_MNEM[(regf & 7) as usize]) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("xadd [m],r w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: ARITH, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cmpxchg [m],r w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: LOGIC, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("test [m],r w{width}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: defined, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{}{}{} n={}{}", if rep { "rep " } else { "" }, mnem, sz, count, if df { " df" } else { "" }) }
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
        _ => match rng.below(7) {
            0 => sse_shuffle(rng),
            1 => sse_pmovmskb(rng, bits),
            2 => sse_movmsk(rng, bits),
            3 => sse_pextrw(rng, bits),
            4 => sse_cmp(rng),
            5 => sse_pinsrw(rng, bits),
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
    Trial { xmm_nan: nan_lane(mp), ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{name}{}", KIND[mp as usize]) }
}

fn sse_sqrt(rng: &mut Rng) -> Trial {
    let mp = rng.below(4) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, 0x51, modrm_reg(d, s)]);
    Trial { xmm_nan: nan_lane(mp), ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("sqrt{}", KIND[mp as usize]) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: name.into() }
}

fn sse_comis(rng: &mut Rng) -> Trial {
    let op2 = if rng.boolean() { 0x2E } else { 0x2F };
    let dbl = rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, if dbl { 1 } else { 0 }, false);
    b.extend([0x0F, op2, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | PF | AF | ZF | SF | OF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{}comis{}", if op2 == 0x2E { "u" } else { "" }, if dbl { "d" } else { "s" }) }
}

fn sse_cvt_i2f(rng: &mut Rng, bits: Bits) -> Trial {
    let sd = rng.boolean();
    let rexw = bits == Bits::B64 && rng.boolean();
    let (d, rm) = (rng.below(8) as u8, rng.below(8) as u8); // rm = GP source
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd { 3 } else { 2 }, rexw);
    b.extend([0x0F, 0x2A, modrm_reg(d, rm)]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cvtsi2s{}{}", if sd { "d" } else { "s" }, if rexw { " r64" } else { "" }) }
}

fn sse_cvt_f2i(rng: &mut Rng, bits: Bits) -> Trial {
    let op2 = if rng.boolean() { 0x2C } else { 0x2D }; // trunc / round
    let sd = rng.boolean();
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd { 3 } else { 2 }, rexw);
    b.extend([0x0F, op2, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cvt{}s{}2si{}", if op2 == 0x2C { "t" } else { "" }, if sd { "d" } else { "s" }, if rexw { " r64" } else { "" }) }
}

fn sse_cvt_f2f(rng: &mut Rng) -> Trial {
    let sd2ss = rng.boolean();
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, if sd2ss { 3 } else { 2 }, false); // F2 = cvtsd2ss, F3 = cvtss2sd
    b.extend([0x0F, 0x5A, modrm_reg(d, s)]);
    Trial { xmm_nan: if sd2ss { 4 } else { 8 }, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: if sd2ss { "cvtsd2ss".into() } else { "cvtss2sd".into() } }
}

/// CVTDQ2PS (NP) / CVTPS2DQ (66) / CVTTPS2DQ (F3) — packed int32 ↔ f32.
fn sse_cvt_dq(rng: &mut Rng) -> Trial {
    let (mp, name) = *rng.pick(&[(0u8, "cvtdq2ps"), (1, "cvtps2dq"), (2, "cvttps2dq")]);
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, 0x5B, modrm_reg(d, s)]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: name.into() }
}

fn sse_move(rng: &mut Rng, bits: Bits) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    match rng.below(6) {
        0 => Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x0F, 0x28, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movaps".into() },
        1 => Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, 0x6F, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movdqa".into() },
        2 => {
            let sd = rng.boolean();
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![if sd { 0xF2 } else { 0xF3 }, 0x0F, 0x10, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: if sd { "movsd".into() } else { "movss".into() } }
        }
        3 => {
            let rexw = bits == Bits::B64 && rng.boolean();
            let mut b = vec![0x66];
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0x6E, modrm_reg(d, s)]);
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movd xmm,r".into() }
        }
        4 => {
            let rexw = bits == Bits::B64 && rng.boolean();
            let mut b = vec![0x66];
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0x7E, modrm_reg(d, s)]); // reg=xmm src, rm=GP dst
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movd r,xmm".into() }
        }
        _ => Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0xF3, 0x0F, 0x7E, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "movq xmm".into() },
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: name.into() }
}

fn sse_pmovmskb(rng: &mut Rng, bits: Bits) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = GP dst, rm = xmm src
    let mut b = vec![0x66];
    if rexw {
        b.push(0x48);
    }
    b.extend([0x0F, 0xD7, modrm_reg(reg, rm)]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "pmovmskb".into() }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "pextrw".into() }
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
        xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0,
        bytes: b,
        defined_flags: 0,
        skip_reg: 0,
        subset_reg: 0, subset_ignore: 0,
        skip_mem: Vec::new(),
        label: if pd { "movmskpd" } else { "movmskps" }.into(),
    }
}

fn sse_shift_imm(rng: &mut Rng) -> Trial {
    let op2 = *rng.pick(&[0x71u8, 0x72, 0x73]);
    let digit = if op2 == 0x73 { *rng.pick(&[2u8, 3, 6, 7]) } else { *rng.pick(&[2u8, 4, 6]) };
    let rm = rng.below(8) as u8; // xmm operand (shifted in place)
    let imm = rng.below(20) as u8;
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(digit, rm), imm], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("psh-imm {op2:#x}/{digit} imm={imm}") }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: vec![0x66, 0x0F, op2, modrm_reg(d, s)], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: name.into() }
}

/// Legacy (non-VEX) CMPPS/CMPPD/CMPSS/CMPSD (0F C2 ib). The imm predicate is
/// restricted to the eight legacy encodings (0..7), which is all the legacy
/// (SSE1/SSE2) form can express. The result is an all-ones/zero lane mask, so
/// it is compared bit-exactly (no NaN-lane masking needed — a mask lane is
/// exactly 0 or all-ones in both engines).
fn sse_cmp(rng: &mut Rng) -> Trial {
    let mp = rng.below(4) as u8; // ps / pd / ss / sd
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.below(8) as u8; // legacy predicates 0..7
    let mut b = Vec::new();
    sse_prefix(&mut b, mp, false);
    b.extend([0x0F, 0xC2, modrm_reg(d, s), imm]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("cmp p{imm} {}", KIND[mp as usize]) }
}

/// PINSRW (66 0F C4 ib): insert a 16-bit word from a GP register into the xmm
/// lane selected by imm8[2:0].
fn sse_pinsrw(rng: &mut Rng, bits: Bits) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    let (reg, rm) = (rng.below(8) as u8, rng.below(8) as u8); // reg = xmm dst, rm = GP src
    let mut b = vec![0x66];
    if rexw {
        b.push(0x48);
    }
    b.extend([0x0F, 0xC4, modrm_reg(reg, rm), rng.below(8) as u8]);
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "pinsrw".into() }
}

fn sse_shuffle(rng: &mut Rng) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.next_u32() as u8;
    if rng.boolean() {
        let mp = *rng.pick(&[1u8, 2, 3]); // pshufd(66) / pshufhw(F3) / pshuflw(F2)
        let mut b = Vec::new();
        sse_prefix(&mut b, mp, false);
        b.extend([0x0F, 0x70, modrm_reg(d, s), imm]);
        Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "pshuf".into() }
    } else {
        let mp = rng.below(2) as u8; // shufps(none) / shufpd(66)
        let mut b = Vec::new();
        sse_prefix(&mut b, mp, false);
        b.extend([0x0F, 0xC6, modrm_reg(d, s), imm]);
        Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "shufp".into() }
    }
}

// ---- SSSE3 / SSE4.1 / SSE4.2 (three-byte 0F 38 / 0F 3A) ---------------------
//
// The whole packed family carries the mandatory `66` prefix; CRC32 carries `F2`.
// Register forms (mod=3) exercise the compute paths; a subset also generate a
// memory operand so the ModRM/SIB/disp path and RIP-independent [base+disp]
// addressing are covered. The string-compare ops (PCMPxSTRx) sweep imm8 values
// and rely on EAX/EDX (already seeded random) for the explicit-length forms.

/// Emit a ModRM addressing a `[base+disp8]` memory operand (mod=01, no SIB),
/// pointing `base` at the data region. Returns nothing; pushes the byte(s).
fn push_xmm_mem(b: &mut Vec<u8>, xmm_reg: u8, base: u8, disp: i8) {
    b.push(0x40 | ((xmm_reg & 7) << 3) | (base & 7)); // mod=01
    b.push(disp as u8);
}

fn build_sse4(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    match rng.below(10) {
        0 => sse4_38_packed(rng, seed),
        1 => sse4_pmovx(rng, seed),
        2 => sse4_ptest(rng),
        3 => sse4_round(rng),
        4 => sse4_blend_imm(rng),
        5 => sse4_palignr(rng),
        6 => sse4_extr_ins(rng, bits),
        7 => sse4_dp_mpsad(rng),
        8 => sse4_pcmpstr(rng, bits),
        _ => sse4_crc32(rng, bits),
    }
}

/// 0F 38 packed ops with no immediate (register or memory r/m).
fn sse4_38_packed(rng: &mut Rng, seed: &mut Seed) -> Trial {
    let (op3, name) = *rng.pick(&[
        (0x00u8, "pshufb"),
        (0x01, "phaddw"),
        (0x02, "phaddd"),
        (0x03, "phaddsw"),
        (0x04, "pmaddubsw"),
        (0x05, "phsubw"),
        (0x06, "phsubd"),
        (0x07, "phsubsw"),
        (0x08, "psignb"),
        (0x09, "psignw"),
        (0x0A, "psignd"),
        (0x0B, "pmulhrsw"),
        (0x1C, "pabsb"),
        (0x1D, "pabsw"),
        (0x1E, "pabsd"),
        (0x10, "pblendvb"),
        (0x14, "blendvps"),
        (0x15, "blendvpd"),
        (0x28, "pmuldq"),
        (0x29, "pcmpeqq"),
        (0x2B, "packusdw"),
        (0x37, "pcmpgtq"),
        (0x38, "pminsb"),
        (0x39, "pminsd"),
        (0x3A, "pminuw"),
        (0x3B, "pminud"),
        (0x3C, "pmaxsb"),
        (0x3D, "pmaxsd"),
        (0x3E, "pmaxuw"),
        (0x3F, "pmaxud"),
        (0x40, "pmulld"),
        (0x41, "phminposuw"),
    ]);
    let d = rng.below(8) as u8;
    let mut b = vec![0x66, 0x0F, 0x38, op3];
    // ~1/3 memory form for the plumbing coverage.
    if rng.below(3) == 0 {
        let base = *rng.pick(&MEM_BASES);
        let disp = point_data(seed, base, rng);
        push_xmm_mem(&mut b, d, base, disp);
    } else {
        let s = rng.below(8) as u8;
        b.push(modrm_reg(d, s));
    }
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: name.into() }
}

/// PMOVSX*/PMOVZX* (0F 38 20-25 / 30-35).
fn sse4_pmovx(rng: &mut Rng, seed: &mut Seed) -> Trial {
    let sel = rng.below(6) as u8;
    let zx = rng.boolean();
    let op3 = if zx { 0x30 } else { 0x20 } + sel;
    let d = rng.below(8) as u8;
    let mut b = vec![0x66, 0x0F, 0x38, op3];
    if rng.boolean() {
        let base = *rng.pick(&MEM_BASES);
        let disp = point_data(seed, base, rng);
        push_xmm_mem(&mut b, d, base, disp);
    } else {
        let s = rng.below(8) as u8;
        b.push(modrm_reg(d, s));
    }
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("pmov{}x/{sel}", if zx { "z" } else { "s" }) }
}

/// PTEST (0F 38 17) — sets ZF/CF only.
fn sse4_ptest(rng: &mut Rng) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let b = vec![0x66, 0x0F, 0x38, 0x17, modrm_reg(d, s)];
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: CF | ZF | OF | SF | AF | PF, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "ptest".into() }
}

/// ROUNDPS/PD/SS/SD (0F 3A 08-0B ib) with random imm8 (mode + MXCSR bit).
fn sse4_round(rng: &mut Rng) -> Trial {
    let op3 = 0x08u8 + rng.below(4) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    // imm[2] uses MXCSR RC; imm[1:0] a direct mode; imm[3] suppresses precision.
    let imm = rng.next_u32() as u8;
    let b = vec![0x66, 0x0F, 0x3A, op3, modrm_reg(d, s), imm];
    // Result lanes are float bit patterns; compare NaN-aware for the packed/
    // scalar forms (ps/ss = 4-lane, pd/sd = 2-lane f64).
    let nan = if op3 == 0x08 || op3 == 0x0A { 4 } else { 8 };
    Trial { xmm_nan: nan, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("round/{op3:#x} imm={imm:#x}") }
}

/// BLENDPS/BLENDPD/PBLENDW (0F 3A 0C-0E ib).
fn sse4_blend_imm(rng: &mut Rng) -> Trial {
    let op3 = 0x0Cu8 + rng.below(3) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.next_u32() as u8;
    let b = vec![0x66, 0x0F, 0x3A, op3, modrm_reg(d, s), imm];
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("blend-imm/{op3:#x}") }
}

/// PALIGNR (0F 3A 0F ib).
fn sse4_palignr(rng: &mut Rng) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = (rng.below(34)) as u8; // sweep 0..33 incl. >=16 and >=32 edges
    let b = vec![0x66, 0x0F, 0x3A, 0x0F, modrm_reg(d, s), imm];
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("palignr imm={imm}") }
}

/// PEXTR*/PINSR*/EXTRACTPS/INSERTPS (0F 3A 14-17 / 20-22 ib). Register forms.
fn sse4_extr_ins(rng: &mut Rng, bits: Bits) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    let imm = rng.next_u32() as u8;
    match rng.below(6) {
        // PEXTRB/W/D(/Q) → GP reg.
        0..=2 => {
            let op3 = [0x14u8, 0x15, 0x16][rng.below(3) as usize];
            let (xmm, gp) = (rng.below(8) as u8, rng.below(8) as u8);
            let mut b = vec![0x66];
            if rexw && op3 == 0x16 {
                b.push(0x48);
            }
            b.extend([0x0F, 0x3A, op3, modrm_reg(xmm, gp), imm]);
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("pextr/{op3:#x}") }
        }
        // EXTRACTPS xmm → GP.
        3 => {
            let (xmm, gp) = (rng.below(8) as u8, rng.below(8) as u8);
            let b = vec![0x66, 0x0F, 0x3A, 0x17, modrm_reg(xmm, gp), imm];
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "extractps".into() }
        }
        // PINSRB/D(/Q) ← GP.
        4 => {
            let (op3, q) = if rng.boolean() { (0x20u8, false) } else { (0x22u8, rexw) };
            let (xmm, gp) = (rng.below(8) as u8, rng.below(8) as u8);
            let mut b = vec![0x66];
            if q {
                b.push(0x48);
            }
            b.extend([0x0F, 0x3A, op3, modrm_reg(xmm, gp), imm]);
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("pinsr/{op3:#x}") }
        }
        // INSERTPS xmm ← xmm.
        _ => {
            let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
            let b = vec![0x66, 0x0F, 0x3A, 0x21, modrm_reg(d, s), imm];
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "insertps".into() }
        }
    }
}

/// DPPS/DPPD (0F 3A 40/41 ib) and MPSADBW (0F 3A 42 ib).
fn sse4_dp_mpsad(rng: &mut Rng) -> Trial {
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.next_u32() as u8;
    match rng.below(3) {
        0 => {
            let b = vec![0x66, 0x0F, 0x3A, 0x40, modrm_reg(d, s), imm];
            Trial { xmm_nan: 4, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "dpps".into() }
        }
        1 => {
            let b = vec![0x66, 0x0F, 0x3A, 0x41, modrm_reg(d, s), imm];
            Trial { xmm_nan: 8, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "dppd".into() }
        }
        _ => {
            let b = vec![0x66, 0x0F, 0x3A, 0x42, modrm_reg(d, s), imm];
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "mpsadbw".into() }
        }
    }
}

/// PCMPESTRM/I, PCMPISTRM/I (0F 3A 60-63 ib). Sweeps imm8 fully; sets ECX (…I)
/// or XMM0 (…M) plus all flags. EAX/EDX (explicit lengths) are the seeded GPRs.
fn sse4_pcmpstr(rng: &mut Rng, bits: Bits) -> Trial {
    let op3 = 0x60u8 + rng.below(4) as u8;
    let (d, s) = (rng.below(8) as u8, rng.below(8) as u8);
    let imm = rng.next_u32() as u8;
    // REX.W is legal but only affects the (ignored) upper bits of EAX/EDX for the
    // explicit forms; keep the plain encoding for a stable decode across engines.
    let _ = bits;
    let b = vec![0x66, 0x0F, 0x3A, op3, modrm_reg(d, s), imm];
    let index = op3 & 1 == 1;
    // …I writes ECX (reg 1); …M writes XMM0. Both write the full flag set.
    Trial {
        xmm_nan: 0, ymm256: false, assert_upper_zero: 0,
        fpu: false,
        fpu_approx: 0,
        sw_mask: 0,
        bytes: b,
        defined_flags: CF | ZF | SF | OF | AF | PF,
        skip_reg: 0,
        subset_reg: 0, subset_ignore: 0,
        skip_mem: Vec::new(),
        label: format!("pcmp{}str{} imm={imm:#x}", if op3 <= 0x61 { "e" } else { "i" }, if index { "i" } else { "m" }),
    }
}

/// CRC32 (F2 0F 38 F0/F1) — 8/16/32/64-bit source into a GP register.
fn sse4_crc32(rng: &mut Rng, bits: Bits) -> Trial {
    // F0 = 8-bit source; F1 = 16/32/64-bit source (66 → 16, REX.W → 64).
    let byte_form = rng.boolean();
    let (dst, src) = (rng.below(8) as u8, rng.below(8) as u8);
    let mut b = vec![0xF2];
    let mut label = String::from("crc32");
    if byte_form {
        b.extend([0x0F, 0x38, 0xF0, modrm_reg(dst, src)]);
        label.push_str(" r,r/m8");
    } else {
        match rng.below(if bits == Bits::B64 { 3 } else { 2 }) {
            0 => {
                b.push(0x66);
                b.extend([0x0F, 0x38, 0xF1, modrm_reg(dst, src)]);
                label.push_str(" r,r/m16");
            }
            1 => {
                b.extend([0x0F, 0x38, 0xF1, modrm_reg(dst, src)]);
                label.push_str(" r,r/m32");
            }
            _ => {
                b.push(0x48); // REX.W
                b.extend([0x0F, 0x38, 0xF1, modrm_reg(dst, src)]);
                label.push_str(" r,r/m64");
            }
        }
    }
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: mask, bytes, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: label.into() }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0xFF, sw_mask: SW_TOP, bytes, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: label.into() }
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
        xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP,
        bytes: vec![esc, modrm], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0,
        skip_mem: Vec::new(),
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: format!("{mnem} m{}", if is64 { 64 } else { 32 }) }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: label.into() }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: label.into() }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: approx, sw_mask: SW_TOP, bytes: vec![0xD9, 0xE8 + low], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: names[low as usize].into() }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask, bytes, defined_flags: flags, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label }
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
    Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask, bytes, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label }
}

/// FNINIT / FNSTCW / FLDCW / FNSTSW (m16 and AX). Exercises the control/status
/// plumbing and the `fnstsw ax` idiom.
fn x87_control(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let _ = bits;
    match rng.below(4) {
        0 => Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: vec![0xDB, 0xE3], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "fninit".into() },
        1 => {
            // FLDCW m16: load a fresh (double-precision) control word.
            let base = *rng.pick(&MEM_BASES);
            let cw: u16 = 0x027F | ((rng.below(4) as u16) << 10); // vary RC bits
            let disp = point_fp(seed, base, rng, &cw.to_le_bytes());
            let mut b = vec![0xD9];
            push_mem(&mut b, 5, base, disp);
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "fldcw".into() }
        }
        2 => {
            // FNSTCW m16.
            seed.tw = 0x0000;
            let base = *rng.pick(&MEM_BASES);
            let disp = point_fp(seed, base, rng, &[0u8, 0]);
            let mut b = vec![0xD9];
            push_mem(&mut b, 7, base, disp);
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: b, defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "fnstcw".into() }
        }
        _ => {
            // fnstsw ax after seeding some condition codes via a compare would
            // be two instructions; here just FNSTSW AX reads the seeded SW.
            seed.tw = 0x0000;
            seed.sw = (rng.below(0x8) as u16) << 8; // seed some condition bits (TOP stays 0)
            Trial { xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP, bytes: vec![0xDF, 0xE0], defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: "fnstsw ax".into() }
        }
    }
}

// ---- FXSAVE / FXRSTOR / XSAVE / XRSTOR family -------------------------------
//
// FXSAVE writes the full 512-byte legacy area; the differential engine already
// diffs the shared DATA region byte-for-byte, so an FXSAVE trial is *the*
// byte-exact save-area check the roadmap step calls for. FXRSTOR/XRSTOR load a
// pre-populated area and are diffed on the resulting register state (ST stack +
// XMM + status/control). XSAVE additionally writes the 64-byte header.

/// A 64-byte-aligned address inside the DATA region with room for a 576-byte
/// XSAVE area (512 legacy + 64 header). `DATA_BASE` (0x10000) is 64-aligned, so
/// this offset keeps the whole area inside the mapping.
const FX_AREA: u64 = DATA_BASE + 0x400;

/// Write a self-consistent 512-byte FXSAVE image into `seed.data`, built per the
/// SDM layout from f64-exact ST values and matching abridged tag bits. Used to
/// seed the memory operand for FXRSTOR/XRSTOR trials. Returns nothing; the
/// caller diffs the resulting registers.
fn fill_fxsave_image(rng: &mut Rng, seed: &mut Seed, rexw: bool) {
    let base = (FX_AREA - DATA_BASE) as usize;
    // Zero the whole 512-byte area first.
    for b in &mut seed.data[base..base + 512] {
        *b = 0;
    }
    let cw: u16 = 0x027F | ((rng.below(4) as u16) << 10); // vary RC bits
    let sw: u16 = (rng.below(0x8) as u16) << 8; // some condition codes, TOP=0
    seed.data[base..base + 2].copy_from_slice(&cw.to_le_bytes());
    seed.data[base + 2..base + 4].copy_from_slice(&sw.to_le_bytes());
    // ST registers + a consistent abridged FTW (bit set ⇔ register non-empty).
    let mut ftw: u8 = 0;
    for i in 0..8 {
        let present = rng.boolean();
        let v = if present {
            ftw |= 1 << i;
            f64_to_ext_seed(fpu_edge_f64(rng))
        } else {
            0
        };
        let off = base + 32 + i * 16;
        seed.data[off..off + 10].copy_from_slice(&v.to_le_bytes()[..10]);
    }
    seed.data[base + 4] = ftw;
    // FOP / FIP / FDP: only meaningful (non-zero) for the pointer round-trip.
    let fop = (rng.next_u32() as u16) & 0x07FF; // 11-bit opcode
    seed.data[base + 6..base + 8].copy_from_slice(&fop.to_le_bytes());
    if rexw {
        let fip = rng.operand();
        let fdp = rng.operand();
        seed.data[base + 8..base + 16].copy_from_slice(&fip.to_le_bytes());
        seed.data[base + 16..base + 24].copy_from_slice(&fdp.to_le_bytes());
    } else {
        let fip = rng.next_u32();
        let fcs = rng.next_u32() as u16;
        let fdp = rng.next_u32();
        let fds = rng.next_u32() as u16;
        seed.data[base + 8..base + 12].copy_from_slice(&fip.to_le_bytes());
        seed.data[base + 12..base + 14].copy_from_slice(&fcs.to_le_bytes());
        seed.data[base + 16..base + 20].copy_from_slice(&fdp.to_le_bytes());
        seed.data[base + 20..base + 22].copy_from_slice(&fds.to_le_bytes());
    }
    // MXCSR: reserved bits above bit 15 must be clear; keep the mask bits set so
    // no exception is unmasked when loaded.
    let mxcsr = 0x1F80 | (rng.next_u32() & 0x0000_003F);
    seed.data[base + 24..base + 28].copy_from_slice(&mxcsr.to_le_bytes());
    // MXCSR_MASK at +28 is architecturally ignored by FXRSTOR; leave it 0.
    // XMM0..15.
    for i in 0..16 {
        let off = base + 160 + i * 16;
        seed.data[off..off + 16].copy_from_slice(&xmm_seed(rng).to_le_bytes());
    }
}

/// DATA-region byte offsets excluded from the FXSAVE/XSAVE memory diff, all of
/// which are architecturally undefined or reference-uncontrollable here:
///  - **FOP** (offset 6–7): the reference derives the last-x87-opcode field
///    internally, independent of any seed, so its saved value is not
///    controllable and differs from exemu's tracked (0) FOP.
///  - the **6 reserved bytes** trailing each 10-byte ST register in its 16-byte
///    slot (offsets 32+i*16+10 .. +16): the SDM leaves these undefined and
///    implementations disagree — exemu zero-fills them while a real CPU may
///    leave the prior memory untouched.
///
/// The 10 significant bytes of every ST register, FCW/FSW/FTW, FIP/FDP (seeded
/// to 0), MXCSR/MXCSR_MASK, and the XMM registers that exist in the mode
/// (XMM0–15 in 64-bit, XMM0–7 in 32-bit) are still compared byte-exactly —
/// i.e. the entire architectural register file.
fn save_reserved_skip(bits: Bits) -> Vec<usize> {
    let base = (FX_AREA - DATA_BASE) as usize;
    let mut v = vec![base + 6, base + 7];
    for i in 0..8usize {
        let slot = base + 32 + i * 16;
        for r in 10..16 {
            v.push(slot + r);
        }
    }
    // In 32-bit mode XMM8–15 (offset 288..416) do not exist; FXSAVE leaves that
    // region undefined (exemu zero-fills it, a real CPU leaves prior memory).
    let xmm_end = if bits == Bits::B64 { 416 } else { 288 };
    // The reserved / "available for software" tail plus (in 32-bit) the absent
    // XMM8–15 region. exemu zero-fills it; a real CPU leaves prior memory.
    for off in xmm_end..512 {
        v.push(base + off);
    }
    v
}

/// Set up `[base]` to address the aligned FX area and return the base register.
fn point_fx(seed: &mut Seed, rng: &mut Rng) -> u8 {
    let base = *rng.pick(&MEM_BASES);
    seed.gpr[base as usize] = FX_AREA;
    base
}

fn build_fxsave(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let rexw = bits == Bits::B64 && rng.boolean();
    match rng.below(4) {
        // FXSAVE: seed random FPU/SSE register state, save it, diff the 512-byte
        // area byte-for-byte (via the shared DATA region).
        0 => {
            seed_fx_registers(rng, seed);
            let base = point_fx(seed, rng);
            let mut b = Vec::new();
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0xAE]);
            push_mem(&mut b, 0, base, 0); // /0 = FXSAVE, disp8=0
            Trial {
                xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b,
                defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: save_reserved_skip(bits), label: if rexw { "fxsave64".into() } else { "fxsave".into() },
            }
        }
        // FXRSTOR: pre-populate a valid image, restore it, diff the registers.
        1 => {
            fill_fxsave_image(rng, seed, rexw);
            let base = point_fx(seed, rng);
            let mut b = Vec::new();
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0xAE]);
            push_mem(&mut b, 1, base, 0); // /1 = FXRSTOR
            // The restored ST stack + status/control words are compared; the
            // full SW (incl. TOP + condition codes) is restored verbatim.
            Trial {
                xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP_CMP, bytes: b,
                defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: if rexw { "fxrstor64".into() } else { "fxrstor".into() },
            }
        }
        // XSAVE: request x87+SSE (EDX:EAX = 3), save, diff the 576-byte area.
        2 => {
            seed_fx_registers(rng, seed);
            let base = point_fx(seed, rng);
            seed.gpr[0] = 3; // EAX = requested-feature mask low = x87|SSE
            seed.gpr[2] = 0; // EDX = high
            let mut b = Vec::new();
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0xAE]);
            push_mem(&mut b, 4, base, 0); // /4 = XSAVE
            // EAX/EDX are inputs, not written; RSP-family bases excluded.
            Trial {
                xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: false, fpu_approx: 0, sw_mask: 0, bytes: b,
                defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: save_reserved_skip(bits), label: if rexw { "xsave64".into() } else { "xsave".into() },
            }
        }
        // XRSTOR: build a full XSAVE image (legacy area + header with both state
        // bits set), request x87+SSE, restore, diff the registers.
        _ => {
            fill_fxsave_image(rng, seed, rexw);
            // XSAVE header at +512: XSTATE_BV = 3 (x87+SSE present), XCOMP_BV = 0.
            let hoff = (FX_AREA - DATA_BASE) as usize + 512;
            for b in &mut seed.data[hoff..hoff + 64] {
                *b = 0;
            }
            seed.data[hoff] = 0x03; // XSTATE_BV low byte = x87|SSE
            let base = point_fx(seed, rng);
            seed.gpr[0] = 3; // EAX requested mask
            seed.gpr[2] = 0; // EDX
            let mut b = Vec::new();
            if rexw {
                b.push(0x48);
            }
            b.extend([0x0F, 0xAE]);
            push_mem(&mut b, 5, base, 0); // /5 = XRSTOR
            Trial {
                xmm_nan: 0, ymm256: false, assert_upper_zero: 0, fpu: true, fpu_approx: 0, sw_mask: SW_TOP_CMP, bytes: b,
                defined_flags: 0, skip_reg: 0, subset_reg: 0, subset_ignore: 0, skip_mem: Vec::new(), label: if rexw { "xrstor64".into() } else { "xrstor".into() },
            }
        }
    }
}

/// Seed random (but valid) x87 + SSE register state for a save trial: f64-exact
/// ST values, a matching tag word, varied control/status words, random pointer
/// state, MXCSR, and XMM registers.
fn seed_fx_registers(rng: &mut Rng, seed: &mut Seed) {
    // TOP=0 at seed time (physical == ST-relative). Randomly mark some
    // registers empty so the abridged FTW exercises both bit values.
    let mut tw: u16 = 0;
    for i in 0..8u16 {
        let present = rng.boolean();
        if present {
            seed.st[i as usize] = f64_to_ext_seed(fpu_edge_f64(rng));
            // Leave the full tag as "valid/zero/special" — Unicorn recomputes it;
            // for the abridged form only empty-vs-not matters, so 00 (valid)
            // suffices here and hardware re-derives the fine tag on save.
            tw |= 0b00 << (i * 2);
        } else {
            seed.st[i as usize] = 0;
            tw |= 0b11 << (i * 2); // empty
        }
    }
    seed.tw = tw;
    seed.cw = 0x027F | ((rng.below(4) as u16) << 10);
    seed.sw = (rng.below(0x8) as u16) << 8; // condition codes, TOP=0
    seed.mxcsr = 0x1F80 | (rng.next_u32() & 0x0000_003F);
    // The x87 environment pointers (FOP/FIP/FCS/FDP/FDS) record the *last x87
    // instruction*. No such instruction runs before this save, so their saved
    // value is implementation-defined (modern CPUs zero the deprecated FCS/FDS
    // and, with FDP_EXCPTN_ONLY, the pointers too). Seed them to 0 so both
    // engines agree on the environment block; the fields are still exercised for
    // round-trip fidelity by the cpu/tests/fxsave.rs FXRSTOR→FXSAVE pin.
    seed.fop = 0;
    seed.fip = 0;
    seed.fdp = 0;
    seed.fcs = 0;
    seed.fds = 0;
    for x in seed.xmm.iter_mut() {
        *x = xmm_seed(rng);
    }
}

// ---- CPUID leaf-fidelity family (roadmap W1.3) -----------------------------
//
// A CPUID trial is the two bytes `0F A2` with EAX (leaf) and ECX (sub-leaf)
// pre-seeded; the differential engine diffs EAX/EBX/ECX/EDX afterwards. CPUID
// honesty is a *correctness* item: if exemu advertised a feature bit the
// interpreter cannot execute, Wine's feature-detection would branch straight
// into an unimplemented path and die. So the invariant this category enforces
// is **"advertised ⊆ implementable"**, expressed against the reference CPU:
//
//   * **Structural fields that must match exactly** — the maximum-leaf values
//     and the vendor string (leaf 0 EBX/ECX/EDX = "GenuineIntel") are diffed
//     bit-exact: exemu claims Intel and QEMU's default CPU is Intel too.
//   * **Feature-flag words** (leaf 1 ECX/EDX, leaf 7 EBX/ECX/EDX, leaf
//     0x8000_0001 ECX/EDX, leaf 0xD.0 EAX = XCR0 valid-bit mask) are diffed
//     under the **subset** policy: every bit exemu sets must also be set by the
//     reference. exemu deliberately reports fewer bits (no SSSE3/SSE4/AVX/BMI
//     yet), so equality is wrong but "exemu ⊆ reference" must hold — that is
//     exactly the "never fabricate a capability" guarantee.
//   * **Fields that legitimately differ and carry no capability meaning** are
//     skipped: leaf 1 EAX (stepping) and EBX (brand index / CLFLUSH size /
//     APIC id), the extended max-leaf EAX at 0x8000_0000 (exemu implements
//     fewer extended leaves — 0x8000_0004 vs the reference's higher value) and
//     its reserved EBX/ECX/EDX, leaf 0xD's area-size EBX/ECX (feature-set
//     dependent), and the brand-string leaves 0x8000_0002..4 (cosmetic).
//
/// Register-index bits for EAX/EBX/ECX/EDX in exemu's GPR order.
const R_EAX: u16 = 1 << 0;
const R_ECX: u16 = 1 << 1;
const R_EDX: u16 = 1 << 2;
const R_EBX: u16 = 1 << 3;

fn build_cpuid(rng: &mut Rng, _bits: Bits, seed: &mut Seed) -> Trial {
    // Leaves the interpreter implements plus a couple of out-of-range probes
    // (which must return all-zero in both engines' max-leaf convention — but
    // QEMU echoes the highest leaf for out-of-range *standard* queries, so we
    // stay on defined leaves and let the sub-leaf vary).
    #[allow(clippy::type_complexity)]
    let (leaf, sub, skip, subset, ignore, label): (u32, u32, u16, u16, u64, &str) = match rng.below(7) {
        // Leaf 0: max standard leaf (EAX) + vendor (EBX/ECX/EDX) — all exact.
        0 => (0x0, 0, 0, 0, 0, "cpuid.0 maxleaf+vendor"),
        // Leaf 1: EAX stepping and EBX brand/CLFLUSH/APIC skipped; ECX/EDX
        // feature words under subset. AVX (ECX bit 28) is behaviorally verified
        // by the VEX category, so it is excluded from the "exemu advertises a bit
        // the reference lacks" check — the Unicorn reference executes VEX but
        // never surfaces AVX in CPUID.
        // F16C (ECX bit 29) is behaviorally verified by the VEX category's F16C
        // conversions and pinned in cpu/tests/vex.rs; the reference does not
        // surface it (same class as AVX), so it is excluded from the subset check.
        1 => (0x1, 0, R_EAX | R_EBX, R_ECX | R_EDX, (1 << 28) | (1 << 29), "cpuid.1 features"),
        // Leaf 7 sub-leaf 0: EAX = max sub-leaf (exact, both 0); EBX/ECX/EDX
        // structured-extended feature words under subset. AVX2 (EBX bit 5) and
        // ADX (EBX bit 19) are excluded: the reference executes ADCX/ADOX (the
        // ADX category proves this) but this QEMU model does not advertise ADX,
        // like AVX2. BMI1 (bit 3) / BMI2 (bit 8) ARE advertised by the reference,
        // so they remain under the plain subset check.
        2 => (0x7, 0, 0, R_EBX | R_ECX | R_EDX, (1 << 5) | (1 << 19), "cpuid.7.0 ext-features"),
        // Leaf 0xD sub-leaf 0: EAX = XCR0 valid-bit mask under subset. exemu now
        // reports x87|SSE|AVX (bit 2); the reference model reports only x87|SSE,
        // so the AVX component bit is excluded (behaviorally verified by the VEX
        // category's XSAVE/XRSTOR AVX-component round-trip). Area sizes EBX/ECX
        // are feature-set-dependent and skipped; EDX (high mask) exact (both 0).
        3 => (0xD, 0, R_EBX | R_ECX, R_EAX, 1 << 2, "cpuid.D.0 xsave"),
        // Extended max-leaf: EAX differs (exemu implements fewer extended
        // leaves) and the SDM leaves EBX/ECX/EDX reserved — skip all four.
        4 => (0x8000_0000, 0, R_EAX | R_EBX | R_ECX | R_EDX, 0, 0, "cpuid.8000_0000 maxext"),
        // Extended features: EAX (family) skipped, EBX reserved; ECX (LZCNT/ABM)
        // and EDX (SYSCALL/NX/LM) feature words under subset.
        5 => (0x8000_0001, 0, R_EAX | R_EBX, R_ECX | R_EDX, 0, "cpuid.8000_0001 ext-features"),
        // Brand string: cosmetic, skip all four registers (exemu's brand differs
        // from the reference's) — but the instruction must still decode/execute.
        _ => (0x8000_0002 + rng.below(3), 0, R_EAX | R_EBX | R_ECX | R_EDX, 0, 0, "cpuid.brand"),
    };
    // Seed the leaf in EAX (index 0) and sub-leaf in ECX (index 1). CPUID clears
    // no other state we compare.
    seed.gpr[0] = leaf as u64;
    seed.gpr[1] = sub as u64;
    Trial {
        xmm_nan: 0, ymm256: false, assert_upper_zero: 0,
        fpu: false,
        fpu_approx: 0,
        sw_mask: 0,
        bytes: vec![0x0F, 0xA2],
        defined_flags: 0,
        skip_reg: skip,
        subset_reg: subset,
        subset_ignore: ignore,
        skip_mem: Vec::new(),
        label: label.into(),
    }
}

// ---- AVX / AVX2 (VEX) category (roadmap W1.5) -------------------------------
//
// The VEX category verifies exemu's AVX/AVX2 op *semantics* against the Unicorn
// reference on the LOW 128-bit lane, and separately asserts exemu's own VEX.128
// zero-upper behavior. See `Trial::ymm256` for why the reference is trusted only
// for the low lane (this Unicorn build implements neither zero-upper nor 256-bit
// VEX): every trial here is therefore VEX.128 (L=0), the destination register's
// upper half is seeded with junk and asserted zero via `assert_upper_zero`, and
// the 256-bit-lane / VZEROUPPER / VZEROALL semantics are pinned by the
// hand-assembled unit tests in `cpu/tests/vex.rs`.

/// Emit a 2-byte (`0xC5`) or 3-byte (`0xC4`) VEX prefix. `reg`/`vvvv`/`rm` are
/// register indices; `mmmmm` = 1/2/3 (0F/0F38/0F3A); `pp` = 0/1/2/3
/// (none/66/F3/F2); `w` = the W bit. `l` is always false here (VEX.128). The
/// 2-byte form is used when it can encode the request (mmmmm==1, !w, rm<8);
/// `force3` forces the 3-byte form to fuzz both decoders on the same op.
#[allow(clippy::too_many_arguments)]
fn vex_prefix(b: &mut Vec<u8>, reg: u8, vvvv: u8, rm: u8, mmmmm: u8, pp: u8, w: bool, force3: bool) {
    let rbit = (reg >= 8) as u8;
    let bbit = (rm >= 8) as u8;
    let two_ok = mmmmm == 1 && !w && bbit == 0 && !force3;
    if two_ok {
        let byte1 = ((!rbit & 1) << 7) | (((!vvvv) & 0xF) << 3) | pp; // L=0
        b.push(0xC5);
        b.push(byte1);
    } else {
        let byte1 = ((!rbit & 1) << 7) | (1 << 6) | ((!bbit & 1) << 5) | (mmmmm & 0x1F);
        let byte2 = ((w as u8) << 7) | (((!vvvv) & 0xF) << 3) | pp; // L=0
        b.push(0xC4);
        b.push(byte1);
        b.push(byte2);
    }
}

/// Number of vector registers usable in this mode (16 in 64-bit, 8 in 32-bit).
#[inline]
fn nvec(bits: Bits) -> u8 {
    if bits == Bits::B64 { 16 } else { 8 }
}

fn build_vex(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // Seed the YMM upper halves with junk so the zero-upper rule is observable.
    for h in seed.ymm_hi.iter_mut() {
        *h = xmm_seed(rng);
    }
    let force3 = rng.boolean();
    // NOTE: the AVX2 register-source broadcasts (VPBROADCAST*/VBROADCASTSS),
    // per-element variable shifts (VPSLLV/VPSRLV/VPSRAV), VPBLENDD and VPERMD are
    // NOT fuzzed here — this Unicorn/TCG build faults (`INSN_INVALID`) on their
    // register-source encodings, so it cannot serve as their reference. They are
    // pinned by hand-assembled unit tests in `cpu/tests/vex.rs`.
    match rng.below(18) {
        0 => vex_float_arith(rng, bits, force3),
        1 => vex_logic(rng, bits, force3),
        2 => vex_int_bin(rng, bits, force3),
        3 => vex_move(rng, bits, force3),
        4 => vex_shuffle(rng, bits, force3),
        5 => vex_shift_imm(rng, bits, force3),
        6 => vex_shift_var(rng, bits, force3),
        7 => vex_pack_unpack(rng, bits, force3),
        8 => vex_cvt(rng, bits, force3),
        9 => vex_blend(rng, bits, force3),
        10 => vex_round(rng, bits, force3),
        11 => vex_pmovx(rng, bits, force3),
        12 => vex_ptest(rng, bits, force3),
        13 => vex_movmsk(rng, bits, force3),
        14 => vex_cmp(rng, bits, force3),
        15 => vex_scalar_arith(rng, bits, force3),
        16 => vex_movd(rng, bits, force3),
        _ => vex_int_bin(rng, bits, force3),
    }
}

/// A finished VEX trial writing a vector destination `dst` (so its upper half is
/// asserted zero) with an `xmm_nan` lane policy for the low-lane diff.
fn vex_trial(bytes: Vec<u8>, nan: u8, dst: u8, label: String) -> Trial {
    Trial {
        xmm_nan: nan,
        ymm256: false,
        assert_upper_zero: 1 << (dst & 0xf),
        fpu: false,
        fpu_approx: 0,
        sw_mask: 0,
        bytes,
        defined_flags: 0,
        skip_reg: 0,
        subset_reg: 0,
        subset_ignore: 0,
        skip_mem: Vec::new(),
        label,
    }
}

/// A VEX trial whose destination is a GP register or flags (no zero-upper
/// assertion): defined_flags carries any status-flag effect.
fn vex_trial_gp(bytes: Vec<u8>, defined_flags: u64, label: String) -> Trial {
    Trial {
        xmm_nan: 0,
        ymm256: false,
        assert_upper_zero: 0,
        fpu: false,
        fpu_approx: 0,
        sw_mask: 0,
        bytes,
        defined_flags,
        skip_reg: 0,
        subset_reg: 0,
        subset_ignore: 0,
        skip_mem: Vec::new(),
        label,
    }
}

/// Pick a `(reg, vvvv, rm)` triple for a 3-operand VEX op where **vvvv == reg**.
///
/// The Unicorn/QEMU-TCG reference this oracle links ignores the VEX `vvvv` field
/// and evaluates 3-operand VEX ops as the legacy 2-operand form `dst = dst op
/// rm` (verified empirically — `vpaddd xmm0,xmm1,xmm2` yields `xmm0 op xmm2`,
/// ignoring `xmm1`). So to diff against it we set src1 (`vvvv`) equal to the
/// destination, making the two forms coincide. exemu's *independent* vvvv decode
/// — that src1 is `vvvv`, NOT the destination — is pinned by the hand-assembled
/// unit test `vex_three_operand_nondestructive` in `cpu/tests/vex.rs`.
fn vec3(rng: &mut Rng, bits: Bits) -> (u8, u8, u8) {
    let n = nvec(bits) as u32;
    let reg = rng.below(n) as u8;
    let rm = rng.below(n) as u8;
    (reg, reg, rm)
}

/// VADD/SUB/MUL/DIV/MIN/MAX PS/PD (packed float, 3-operand).
fn vex_float_arith(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (op, name) = *rng.pick(&[(0x58u8, "add"), (0x59, "mul"), (0x5C, "sub"), (0x5D, "min"), (0x5E, "div"), (0x5F, "max")]);
    let pd = rng.boolean();
    let (reg, vvvv, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, if pd { 1 } else { 0 }, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, if pd { 8 } else { 4 }, reg, format!("v{name}p{}", if pd { "d" } else { "s" }))
}

/// VADD/SUB/MUL/DIV/MIN/MAX/SQRT SS/SD (scalar float).
fn vex_scalar_arith(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (op, name) = *rng.pick(&[(0x58u8, "add"), (0x59, "mul"), (0x5C, "sub"), (0x5D, "min"), (0x5E, "div"), (0x5F, "max"), (0x51, "sqrt")]);
    let sd = rng.boolean();
    let (reg, vvvv, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, if sd { 3 } else { 2 }, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, if sd { 8 } else { 4 }, reg, format!("v{name}s{}", if sd { "d" } else { "s" }))
}

/// VANDPS/ANDNPS/ORPS/XORPS (+ pd) and VPAND/VPANDN/VPOR/VPXOR.
fn vex_logic(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (reg, vvvv, rm) = vec3(rng, bits);
    let (op, pp, name) = if rng.boolean() {
        let (o, n) = *rng.pick(&[(0x54u8, "vandps"), (0x55, "vandnps"), (0x56, "vorps"), (0x57, "vxorps")]);
        (o, if rng.boolean() { 1 } else { 0 }, n)
    } else {
        let (o, n) = *rng.pick(&[(0xDBu8, "vpand"), (0xDF, "vpandn"), (0xEB, "vpor"), (0xEF, "vpxor")]);
        (o, 1u8, n)
    };
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, pp, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, name.into())
}

/// AVX2 integer binary ops (add/sub/cmp/mul/minmax/avg), 128-bit lane.
fn vex_int_bin(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let ops1: &[(u8, &str)] = &[
        (0xFC, "vpaddb"), (0xFD, "vpaddw"), (0xFE, "vpaddd"), (0xD4, "vpaddq"),
        (0xF8, "vpsubb"), (0xF9, "vpsubw"), (0xFA, "vpsubd"), (0xFB, "vpsubq"),
        (0x74, "vpcmpeqb"), (0x75, "vpcmpeqw"), (0x76, "vpcmpeqd"),
        (0x64, "vpcmpgtb"), (0x65, "vpcmpgtw"), (0x66, "vpcmpgtd"),
        (0xD5, "vpmullw"), (0xE5, "vpmulhw"), (0xE4, "vpmulhuw"),
        (0xF4, "vpmuludq"), (0xF5, "vpmaddwd"), (0xF6, "vpsadbw"),
        (0xDC, "vpaddusb"), (0xDD, "vpaddusw"), (0xEC, "vpaddsb"), (0xED, "vpaddsw"),
        (0xD8, "vpsubusb"), (0xD9, "vpsubusw"), (0xE8, "vpsubsb"), (0xE9, "vpsubsw"),
        (0xDA, "vpminub"), (0xDE, "vpmaxub"), (0xEA, "vpminsw"), (0xEE, "vpmaxsw"),
        (0xE0, "vpavgb"), (0xE3, "vpavgw"),
    ];
    let ops2: &[(u8, &str)] = &[
        (0x28, "vpmuldq"), (0x29, "vpcmpeqq"), (0x37, "vpcmpgtq"), (0x40, "vpmulld"),
        (0x38, "vpminsb"), (0x3C, "vpmaxsb"), (0x39, "vpminsd"), (0x3D, "vpmaxsd"),
        (0x3A, "vpminuw"), (0x3E, "vpmaxuw"), (0x3B, "vpminud"), (0x3F, "vpmaxud"),
        (0x00, "vpshufb"), (0x0B, "vpmulhrsw"), (0x04, "vpmaddubsw"),
        (0x08, "vpsignb"), (0x09, "vpsignw"), (0x0A, "vpsignd"),
        // The horizontal-add/sub ops (VPHADD*/VPHSUB*) are intentionally NOT
        // fuzzed: because the reference ignores `vvvv` and evaluates the op as
        // the legacy 2-operand `dst = dst hadd rm` in place, and this oracle must
        // set `vvvv == dst` (so the reference reads the intended src1), the
        // destination always aliases a source. That triggers the SDM's
        // sequential-write in-place hazard in the reference (the low-half write
        // overwrites a high-half source), whereas a true 3-operand VEX op writes
        // a fresh destination with no hazard. exemu is correct; the reference is
        // not, so these are pinned by the hand-assembled unit test
        // `vphaddd_no_inplace_hazard` in `cpu/tests/vex.rs` instead.
    ];
    let (reg, vvvv, rm) = vec3(rng, bits);
    let (map, op, name) = if rng.boolean() {
        let (o, n) = *rng.pick(ops2);
        (2u8, o, n)
    } else {
        let (o, n) = *rng.pick(ops1);
        (1u8, o, n)
    };
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, map, 1, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, name.into())
}

/// VMOVDQA/VMOVDQU/VMOVUPS/VMOVAPS reg<-reg (zero-upper on copy).
fn vex_move(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (reg, _v, rm) = vec3(rng, bits);
    let (pp, op, name) = *rng.pick(&[
        (1u8, 0x6Fu8, "vmovdqa"), (2, 0x6F, "vmovdqu"),
        (0, 0x28, "vmovaps"), (1, 0x28, "vmovapd"),
        (0, 0x10, "vmovups"), (1, 0x10, "vmovupd"),
    ]);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, 0xF, rm, 1, pp, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, name.into())
}

/// VMOVD/VMOVQ GP<->xmm. To-xmm zero-extends the whole ymm.
fn vex_movd(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let w = bits == Bits::B64 && rng.boolean();
    let to_gp = rng.boolean();
    let xreg = rng.below(nvec(bits) as u32) as u8;
    let gp = rng.below(if bits == Bits::B64 { 16 } else { 8 } as u32) as u8;
    let mut b = Vec::new();
    let op = if to_gp { 0x7E } else { 0x6E };
    vex_prefix(&mut b, xreg, 0xF, gp, 1, 1, w, force3);
    b.extend([op, modrm_reg(xreg, gp)]);
    let name = format!("vmov{} {}", if w { "q" } else { "d" }, if to_gp { "gp<-x" } else { "x<-gp" });
    if to_gp {
        vex_trial_gp(b, 0, name)
    } else {
        vex_trial(b, 0, xreg, name)
    }
}

/// VSHUFPS/PD (imm8) and VPSHUFD/LW/HW (imm8).
fn vex_shuffle(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let imm = rng.next_u32() as u8;
    if rng.boolean() {
        let pd = rng.boolean();
        let (reg, vvvv, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, vvvv, rm, 1, if pd { 1 } else { 0 }, false, force3);
        b.extend([0xC6, modrm_reg(reg, rm), imm]);
        vex_trial(b, 0, reg, format!("vshufp{}", if pd { "d" } else { "s" }))
    } else {
        let (pp, name) = *rng.pick(&[(1u8, "vpshufd"), (3, "vpshuflw"), (2, "vpshufhw")]);
        let (reg, _v, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, 0xF, rm, 1, pp, false, force3);
        b.extend([0x70, modrm_reg(reg, rm), imm]);
        vex_trial(b, 0, reg, name.into())
    }
}

/// VPSLLW/D/Q, VPSRLW/D/Q, VPSRAW/D by imm8 (0F 71/72/73 /reg, dst = vvvv).
fn vex_shift_imm(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let choices: &[(u8, u8, &str)] = &[
        (0x71, 2, "vpsrlw"), (0x71, 4, "vpsraw"), (0x71, 6, "vpsllw"),
        (0x72, 2, "vpsrld"), (0x72, 4, "vpsrad"), (0x72, 6, "vpslld"),
        (0x73, 2, "vpsrlq"), (0x73, 6, "vpsllq"),
    ];
    let (op, ext, name) = *rng.pick(choices);
    // dst = vvvv; source = ModRM.rm. Set dst == rm so the reference (which
    // ignores vvvv and shifts the ModRM.rm operand in place) writes the same
    // register exemu does. exemu's `dst = vvvv` decode is unit-tested separately.
    let rm = rng.below(nvec(bits) as u32) as u8;
    let count = rng.below(80) as u8;
    let mut b = Vec::new();
    vex_prefix(&mut b, ext, rm, rm, 1, 1, false, force3);
    b.extend([op, modrm_reg(ext, rm), count]);
    vex_trial(b, 0, rm, format!("{name} imm{count}"))
}

/// VPSRLW/D/Q etc. by an xmm variable count (low 64 bits scalar).
fn vex_shift_var(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let choices: &[(u8, &str)] = &[
        (0xD1, "vpsrlw"), (0xD2, "vpsrld"), (0xD3, "vpsrlq"),
        (0xE1, "vpsraw"), (0xE2, "vpsrad"),
        (0xF1, "vpsllw"), (0xF2, "vpslld"), (0xF3, "vpsllq"),
    ];
    let (op, name) = *rng.pick(choices);
    let (reg, vvvv, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, 1, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, format!("{name} var"))
}

// VPSLLV/VPSRLV/VPSRAV (per-element variable shift) and the register-source
// VPBROADCAST*/VBROADCASTSS are omitted from this category — the Unicorn/TCG
// reference faults on their register encodings (see the dispatch note). Their
// semantics are pinned by unit tests in `cpu/tests/vex.rs`.

/// VPUNPCK{L,H}*, VPACK*, VUNPCK{L,H}P{S,D}.
fn vex_pack_unpack(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let choices: &[(u8, &str)] = &[
        (0x60, "vpunpcklbw"), (0x61, "vpunpcklwd"), (0x62, "vpunpckldq"), (0x6C, "vpunpcklqdq"),
        (0x68, "vpunpckhbw"), (0x69, "vpunpckhwd"), (0x6A, "vpunpckhdq"), (0x6D, "vpunpckhqdq"),
        (0x63, "vpacksswb"), (0x6B, "vpackssdw"), (0x67, "vpackuswb"),
    ];
    let (reg, vvvv, rm) = vec3(rng, bits);
    let (pp, op, name) = if rng.below(4) == 0 {
        let hi = rng.boolean();
        let pd = rng.boolean();
        (if pd { 1u8 } else { 0 }, if hi { 0x15u8 } else { 0x14 }, if hi { "vunpckhp" } else { "vunpcklp" })
    } else {
        let (o, n) = *rng.pick(choices);
        (1u8, o, n)
    };
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, pp, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, name.into())
}

/// VCVTDQ2PS / VCVTPS2DQ / VCVTTPS2DQ, VCVTSS2SD / VCVTSD2SS.
fn vex_cvt(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    if rng.boolean() {
        let (pp, name) = *rng.pick(&[(0u8, "vcvtdq2ps"), (1, "vcvtps2dq"), (2, "vcvttps2dq")]);
        let (reg, _v, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, 0xF, rm, 1, pp, false, force3);
        b.extend([0x5B, modrm_reg(reg, rm)]);
        vex_trial(b, 0, reg, name.into())
    } else {
        let sd2ss = rng.boolean();
        let (reg, vvvv, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, vvvv, rm, 1, if sd2ss { 3 } else { 2 }, false, force3);
        b.extend([0x5A, modrm_reg(reg, rm)]);
        vex_trial(b, if sd2ss { 4 } else { 8 }, reg, if sd2ss { "vcvtsd2ss".into() } else { "vcvtss2sd".into() })
    }
}

/// VBLENDPS/PD (0F3A 0C/0D), VPBLENDW (0x0E), VPBLENDD (0x02) — imm8 blend.
fn vex_blend(rng: &mut Rng, bits: Bits, _force3: bool) -> Trial {
    // VPBLENDD (0x02) is excluded — its register form faults in the reference.
    let (op, name) = *rng.pick(&[(0x0Cu8, "vblendps"), (0x0D, "vblendpd"), (0x0E, "vpblendw")]);
    let imm = rng.next_u32() as u8;
    let (reg, vvvv, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 3, 1, false, true);
    b.extend([op, modrm_reg(reg, rm), imm]);
    vex_trial(b, 0, reg, name.into())
}

/// VROUNDPS/PD (imm8 mode) and VROUNDSS/SD.
fn vex_round(rng: &mut Rng, bits: Bits, _force3: bool) -> Trial {
    let imm = (rng.next_u32() as u8) & 0x0F;
    if rng.boolean() {
        let (op, pd) = if rng.boolean() { (0x08u8, false) } else { (0x09, true) };
        let (reg, _v, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, 0xF, rm, 3, 1, false, true);
        b.extend([op, modrm_reg(reg, rm), imm]);
        vex_trial(b, 0, reg, format!("vroundp{}", if pd { "d" } else { "s" }))
    } else {
        let (op, sd) = if rng.boolean() { (0x0Au8, false) } else { (0x0B, true) };
        let (reg, vvvv, rm) = vec3(rng, bits);
        let mut b = Vec::new();
        vex_prefix(&mut b, reg, vvvv, rm, 3, 1, false, true);
        b.extend([op, modrm_reg(reg, rm), imm]);
        vex_trial(b, 0, reg, format!("vrounds{}", if sd { "d" } else { "s" }))
    }
}

/// VPMOVSX/ZX widening (0F38 20..25 / 30..35).
fn vex_pmovx(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (op, name) = *rng.pick(&[
        (0x20u8, "vpmovsxbw"), (0x21, "vpmovsxbd"), (0x22, "vpmovsxbq"),
        (0x23, "vpmovsxwd"), (0x24, "vpmovsxwq"), (0x25, "vpmovsxdq"),
        (0x30, "vpmovzxbw"), (0x31, "vpmovzxbd"), (0x32, "vpmovzxbq"),
        (0x33, "vpmovzxwd"), (0x34, "vpmovzxwq"), (0x35, "vpmovzxdq"),
    ]);
    let (reg, _v, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, 0xF, rm, 2, 1, false, force3);
    b.extend([op, modrm_reg(reg, rm)]);
    vex_trial(b, 0, reg, name.into())
}

/// VPTEST — sets flags from AND / ANDN of the two operands (0F38 17).
fn vex_ptest(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let (reg, _v, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, 0xF, rm, 2, 1, false, force3);
    b.extend([0x17, modrm_reg(reg, rm)]);
    vex_trial_gp(b, CF | ZF | OF | SF | AF | PF, "vptest".into())
}

/// VMOVMSKPS/PD, VPMOVMSKB → GP register.
fn vex_movmsk(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let gp = rng.below(if bits == Bits::B64 { 16 } else { 8 } as u32) as u8;
    let rm = rng.below(nvec(bits) as u32) as u8;
    let (op, pp, name) = *rng.pick(&[(0x50u8, 0u8, "vmovmskps"), (0x50, 1, "vmovmskpd"), (0xD7, 1, "vpmovmskb")]);
    let mut b = Vec::new();
    vex_prefix(&mut b, gp, 0xF, rm, 1, pp, false, force3);
    b.extend([op, modrm_reg(gp, rm)]);
    vex_trial_gp(b, 0, name.into())
}

/// VCMPPS/PD/SS/SD — imm8 predicate compare producing a lane mask (0F C2).
fn vex_cmp(rng: &mut Rng, bits: Bits, force3: bool) -> Trial {
    let imm = rng.below(8) as u8; // the eight legacy predicates exemu matches exactly
    let scalar = rng.boolean();
    let dbl = rng.boolean();
    let pp = if scalar { if dbl { 3 } else { 2 } } else if dbl { 1 } else { 0 };
    let (reg, vvvv, rm) = vec3(rng, bits);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 1, pp, false, force3);
    b.extend([0xC2, modrm_reg(reg, rm), imm]);
    vex_trial(b, 0, reg, format!("vcmp p{imm} {}{}", if scalar { "s" } else { "p" }, if dbl { "d" } else { "s" }))
}

// ---- BMI1 / BMI2 / ADX / CMPXCHG (roadmap W1.6) ----------------------------
//
// BMI/ADX are general-purpose integer ops. BMI1/BMI2 are VEX-encoded (LZ, no
// vector state); ADCX/ADOX are legacy 66/F3 0F38. Several deliberately touch NO
// flags (MULX/PDEP/PEXT/RORX/SARX/SHLX/SHRX) — a flag-diff trap this category
// exercises directly. Operand width is 32-bit, plus 64-bit in long mode.

/// BMI operand width. **Reference limitation:** the linked Unicorn/QEMU-TCG
/// build ignores VEX.W for BMI GP ops in 64-bit mode — it evaluates every BMI
/// op at 64 bits regardless of W (so a W=0 op wrongly keeps the upper 32 bits
/// of the destination instead of zero-extending). To keep the reference honest
/// we therefore fuzz only the width that matches the mode: 64-bit (W=1) in long
/// mode and 32-bit in protected mode. The 32-bit-width *zero-extension* of the
/// W=0 long-mode form is pinned separately in `cpu/tests/interp.rs`.
fn bmi_w(_rng: &mut Rng, bits: Bits) -> u8 {
    if bits == Bits::B64 {
        8
    } else {
        4
    }
}

fn build_bmi(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // NOTE: ADCX/ADOX (ADX) are NOT fuzzed here — the linked Unicorn/QEMU-TCG
    // build does not implement the ADX extension (it #UDs ADCX/ADOX and never
    // advertises the leaf-7 EBX bit 19, exactly like it withholds AVX). So the
    // reference cannot serve as their oracle; ADCX/ADOX are pinned exhaustively by
    // hand-computed unit tests in cpu/tests/interp.rs instead. Same for F16C.
    match rng.below(10) {
        0 => bmi_andn(rng, bits),
        1 => bmi_bextr(rng, bits, seed),
        2 => bmi_bls(rng, bits),
        3 => bmi_mulx(rng, bits, seed),
        4 => bmi_pdep_pext(rng, bits),
        5 => bmi_bzhi(rng, bits, seed),
        6 => bmi_rorx(rng, bits),
        7 => bmi_shx(rng, bits),
        // CMPXCHG16B is REX.W-only (64-bit); in 32-bit mode fall back to
        // CMPXCHG8B (which is also the default form there).
        8 if bits == Bits::B64 => cmpxchg16b(rng, bits, seed),
        _ => cmpxchg8b(rng, bits, seed),
    }
}

/// ANDN reg, vvvv, r/m (VEX.NDS.LZ.0F38.Wx F2). Sets SF/ZF, clears CF/OF.
fn bmi_andn(rng: &mut Rng, bits: Bits) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, 0, width == 8, rng.boolean());
    b.extend([0xF2, modrm_reg(reg, rm)]);
    Trial { bytes: b, defined_flags: CF | ZF | SF | OF, label: format!("andn w{width}"), ..Default::default() }
}

/// BEXTR reg, r/m, vvvv (VEX.NDS.LZ.0F38.Wx F7, pp=none). Defines ZF; CF/OF=0;
/// SF/AF/PF undefined.
///
/// **Reference limitation:** the SDM extracts `LEN` bits starting at `START`
/// with `(1<<LEN)-1` widths up to the full operand, but this Unicorn/QEMU-TCG
/// build mis-clamps `START+LEN` beyond the operand size (dropping the top bit).
/// So the oracle constrains `START` and `LEN` to keep the extracted field inside
/// the operand (`START+LEN <= opsize`); the over-length/over-start pass-through
/// is pinned in `cpu/tests/interp.rs`.
fn bmi_bextr(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let width = bmi_w(rng, bits);
    let opbits = width as u32 * 8;
    let n = nregs(bits);
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    // Control = vvvv: start in [0, opsize], len in [0, opsize - start].
    // Cap len at opsize-1: a full-width mask (len >= opsize) is where the linked
    // QEMU/Unicorn build is wrong — it clamps and drops the top bit — while exemu
    // follows the SDM (whole shifted source passes through). That SDM-correct
    // full-width behavior is pinned in cpu/tests/interp.rs
    // (bextr_extracts_field_and_overlength_passthrough); here we keep the fuzzer
    // out of QEMU's buggy region so the diff stays meaningful.
    let start = rng.below(opbits + 1);
    let len = rng.below(opbits - start + 1).min(opbits - 1);
    seed.gpr[vvvv as usize] = (start as u64) | ((len as u64) << 8);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, 0, width == 8, rng.boolean());
    b.extend([0xF7, modrm_reg(reg, rm)]);
    // SF/AF/PF are architecturally undefined for BEXTR — diff only ZF/CF/OF.
    Trial { bytes: b, defined_flags: ZF | CF | OF, label: format!("bextr w{width}"), ..Default::default() }
}

/// BLSR/BLSMSK/BLSI dst(vvvv), r/m (VEX.NDD.LZ.0F38.Wx F3 /reg).
///
/// **Reference limitation (BLSI CF):** the SDM sets BLSI's CF to `(SRC != 0)`,
/// but this Unicorn/QEMU-TCG build reports the opposite/wrong value (a known
/// historical QEMU BLSI CF bug). So the BLSI CF is excluded from the oracle diff
/// and pinned in `cpu/tests/interp.rs`; BLSR/BLSMSK CF (also `(SRC==0)`) matches
/// the reference and stays diffed. BLSMSK forces ZF=0.
fn bmi_bls(rng: &mut Rng, bits: Bits) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let digit = 1 + rng.below(3) as u8; // /1 BLSR, /2 BLSMSK, /3 BLSI
    let (vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8);
    let mut b = Vec::new();
    // ModRM.reg = the /digit; ModRM.rm = source. reg-extension via R is unused.
    vex_prefix(&mut b, digit, vvvv, rm, 2, 0, width == 8, rng.boolean());
    b.extend([0xF3, modrm_reg(digit, rm)]);
    let (name, flags) = match digit {
        1 => ("blsr", CF | SF | OF | ZF),
        2 => ("blsmsk", CF | SF | OF | ZF),
        _ => ("blsi", SF | OF | ZF), // BLSI CF excluded (QEMU reference bug)
    };
    Trial { bytes: b, defined_flags: flags, label: format!("{name} w{width}"), ..Default::default() }
}

/// MULX dst_hi(reg), dst_lo(vvvv), r/m (VEX.NDD.LZ.F2.0F38.Wx F6). No flags.
fn bmi_mulx(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    // Seed rDX (the implicit multiplicand) with an interesting value.
    seed.gpr[2] = rng.operand();
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, 3, width == 8, rng.boolean());
    b.extend([0xF6, modrm_reg(reg, rm)]);
    Trial { bytes: b, defined_flags: 0, label: format!("mulx w{width}"), ..Default::default() }
}

/// PDEP (F2) / PEXT (F3) dst, vvvv, r/m(mask) (VEX.NDS.LZ.pp.0F38.Wx F5). No flags.
fn bmi_pdep_pext(rng: &mut Rng, bits: Bits) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let pext = rng.boolean();
    let pp = if pext { 2 } else { 3 };
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, pp, width == 8, rng.boolean());
    b.extend([0xF5, modrm_reg(reg, rm)]);
    Trial { bytes: b, defined_flags: 0, label: format!("{} w{width}", if pext { "pext" } else { "pdep" }), ..Default::default() }
}

/// BZHI dst, r/m, vvvv (VEX.NDS.LZ.0F38.Wx F5, pp=none). Defines ZF/CF/SF; OF=0.
///
/// **Reference limitation:** for a control index N >= operand size the SDM leaves
/// the source unchanged (no bits cleared, CF=1), but this Unicorn/QEMU-TCG build
/// wrongly clamps N to opsize-1 and clears the top bit. So the oracle seeds the
/// control index into `[0, opsize]` (both engines agree there); the N>=opsize
/// pass-through + CF=1 behavior is pinned in `cpu/tests/interp.rs`.
fn bmi_bzhi(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    // Constrain the control index (vvvv low byte) to [0, opsize-2]. The SDM sets
    // BZHI's CF as `N > opsize-1`, but this QEMU build's CF is off by one at the
    // N == opsize-1 boundary (it reports CF=1 there); the pass-through and the
    // exact CF boundary (N == opsize-1 → CF=0, N >= opsize → CF=1) are pinned in
    // `cpu/tests/interp.rs`.
    let idx = rng.below(width as u32 * 8 - 1) as u64;
    seed.gpr[vvvv as usize] = idx;
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, 0, width == 8, rng.boolean());
    b.extend([0xF5, modrm_reg(reg, rm)]);
    // AF/PF undefined for BZHI — diff ZF/CF/SF/OF.
    Trial { bytes: b, defined_flags: ZF | CF | SF | OF, label: format!("bzhi w{width}"), ..Default::default() }
}

/// RORX dst, r/m, imm8 (VEX.LZ.F2.0F3A.Wx F0 /r ib). No flags.
fn bmi_rorx(rng: &mut Rng, bits: Bits) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let (reg, rm) = (rng.below(n) as u8, rng.below(n) as u8);
    let imm = rng.below(256) as u8;
    let mut b = Vec::new();
    // RORX has no vvvv (encoded as 1111).
    vex_prefix(&mut b, reg, 0, rm, 3, 3, width == 8, rng.boolean());
    b.extend([0xF0, modrm_reg(reg, rm), imm]);
    Trial { bytes: b, defined_flags: 0, label: format!("rorx w{width} imm={imm}"), ..Default::default() }
}

/// SHLX (66) / SARX (F3) / SHRX (F2) dst, r/m, vvvv (VEX.LZ.pp.0F38.Wx F7). No flags.
fn bmi_shx(rng: &mut Rng, bits: Bits) -> Trial {
    let width = bmi_w(rng, bits);
    let n = nregs(bits);
    let (pp, name) = *rng.pick(&[(1u8, "shlx"), (2, "sarx"), (3, "shrx")]);
    let (reg, vvvv, rm) = (rng.below(n) as u8, rng.below(n) as u8, rng.below(n) as u8);
    let mut b = Vec::new();
    vex_prefix(&mut b, reg, vvvv, rm, 2, pp, width == 8, rng.boolean());
    b.extend([0xF7, modrm_reg(reg, rm)]);
    Trial { bytes: b, defined_flags: 0, label: format!("{name} w{width}"), ..Default::default() }
}

/// CMPXCHG16B m128 (REX.W 0F C7 /1). Diffs ZF + RAX/RDX + the 16 memory bytes.
/// The comparand (RDX:RAX) matches the seeded memory ~half the time (via a coin
/// flip that copies the memory image into the registers) so both the equal and
/// not-equal paths are exercised.
fn cmpxchg16b(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // 64-bit only (REX.W). Point a base register at a 16-byte-aligned slot.
    let base = *rng.pick(&MEM_BASES);
    // DATA_MID is 16-byte aligned (DATA_BASE + 0x800); use it directly (disp 0).
    seed.gpr[base as usize] = DATA_MID;
    let off = (DATA_MID - DATA_BASE) as usize;
    // Seed 16 bytes of memory.
    for i in 0..16 {
        seed.data[off + i] = rng.next_u32() as u8;
    }
    // Half the time, make RDX:RAX equal the memory so the exchange path fires.
    if rng.boolean() {
        let lo = u64::from_le_bytes(seed.data[off..off + 8].try_into().unwrap());
        let hi = u64::from_le_bytes(seed.data[off + 8..off + 16].try_into().unwrap());
        seed.gpr[0] = lo; // RAX
        seed.gpr[2] = hi; // RDX
    } else {
        seed.gpr[0] = rng.operand();
        seed.gpr[2] = rng.operand();
    }
    seed.gpr[3] = rng.operand(); // RBX (store low)
    seed.gpr[1] = rng.operand(); // RCX (store high)
    let mut b = Vec::new();
    b.push(0x48); // REX.W
    b.extend([0x0F, 0xC7]);
    // ModRM /1, mod=00, rm=base (base ∈ {ecx,ebx,esi,edi}, none needs SIB/disp32).
    b.push((1 << 3) | (base & 7)); // mod=00, reg=/1, rm=base
    let _ = bits;
    Trial { bytes: b, defined_flags: ZF, label: "cmpxchg16b".into(), ..Default::default() }
}

/// CMPXCHG8B m64 (0F C7 /1, no REX.W). Diffs ZF + EAX/EDX + 8 memory bytes.
fn cmpxchg8b(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    let base = *rng.pick(&MEM_BASES);
    seed.gpr[base as usize] = DATA_MID;
    let off = (DATA_MID - DATA_BASE) as usize;
    for i in 0..8 {
        seed.data[off + i] = rng.next_u32() as u8;
    }
    if rng.boolean() {
        let lo = u32::from_le_bytes(seed.data[off..off + 4].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(seed.data[off + 4..off + 8].try_into().unwrap()) as u64;
        seed.gpr[0] = lo; // EAX
        seed.gpr[2] = hi; // EDX
    } else {
        seed.gpr[0] = rng.operand();
        seed.gpr[2] = rng.operand();
    }
    seed.gpr[3] = rng.operand(); // EBX
    seed.gpr[1] = rng.operand(); // ECX
    let mut b = Vec::new();
    b.extend([0x0F, 0xC7]);
    b.push((1 << 3) | (base & 7)); // mod=00, reg=/1, rm=base
    let _ = bits;
    Trial { bytes: b, defined_flags: ZF, label: "cmpxchg8b".into(), ..Default::default() }
}

// ---- bare-form MMX (roadmap W1.6) ------------------------------------------
//
// MMX registers alias the low 64 bits of the x87 physical stack. This category
// seeds the eight `st` registers with MMX-shaped values (bits 64:79 = 0xFFFF,
// tag word all-valid) and diffs the resulting register file (bit-exact 80-bit,
// since both engines set the same exponent/sign) plus any GP destination.

/// A finished MMX trial: compare the x87 register file (fpu=true) but not the
/// status word (MMX doesn't meaningfully update TOP/condition codes here).
fn mmx_trial(bytes: Vec<u8>, label: String) -> Trial {
    Trial { bytes, fpu: true, sw_mask: 0, label, ..Default::default() }
}

fn build_mmx(rng: &mut Rng, bits: Bits, seed: &mut Seed) -> Trial {
    // Re-seed the eight physical registers as MMX values (low 64 arbitrary, high
    // 16 = 0xFFFF as a written MMX register looks), tag word all-valid so the
    // reference treats them as live MMX registers.
    for s in seed.st.iter_mut() {
        let lo = ((rng.operand() as u128) & 0xFFFF_FFFF_FFFF_FFFF) | (0xFFFFu128 << 64);
        *s = lo;
    }
    seed.tw = 0x0000; // all valid
    match rng.below(11) {
        0 => mmx_addsub(rng, bits),
        1 => mmx_addsub_sat(rng, bits),
        2 => mmx_logic(rng, bits),
        3 => mmx_cmp(rng, bits),
        4 => mmx_unpack(rng, bits),
        5 => mmx_pack(rng, bits),
        6 => mmx_mul(rng, bits),
        7 => mmx_shift(rng, bits),
        8 => mmx_pshufw(rng, bits),
        9 => mmx_movd(rng, bits, seed),
        _ => mmx_misc(rng, bits),
    }
}

/// Pick two MMX register numbers (0..8; MMX ignores REX).
fn mm2(rng: &mut Rng) -> (u8, u8) {
    (rng.below(8) as u8, rng.below(8) as u8)
}

fn mmx_addsub(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0xFCu8, 0xFD, 0xFE, 0xF8, 0xF9, 0xFA, 0xD4, 0xFB]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx padd/sub {op:#x}"))
}

fn mmx_addsub_sat(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0xD8u8, 0xD9, 0xDC, 0xDD, 0xE8, 0xE9, 0xEC, 0xED]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx padds/us {op:#x}"))
}

fn mmx_logic(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0xDBu8, 0xDF, 0xEB, 0xEF]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx logic {op:#x}"))
}

fn mmx_cmp(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0x74u8, 0x75, 0x76, 0x64, 0x65, 0x66]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx pcmp {op:#x}"))
}

fn mmx_unpack(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0x60u8, 0x61, 0x62, 0x68, 0x69, 0x6A]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx punpck {op:#x}"))
}

fn mmx_pack(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0x63u8, 0x6B, 0x67]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx pack {op:#x}"))
}

fn mmx_mul(rng: &mut Rng, _bits: Bits) -> Trial {
    let op = *rng.pick(&[0xD5u8, 0xE4, 0xE5, 0xF4, 0xF5]);
    let (reg, rm) = mm2(rng);
    mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx pmul {op:#x}"))
}

fn mmx_shift(rng: &mut Rng, _bits: Bits) -> Trial {
    if rng.boolean() {
        // shift by imm8 (groups 71/72/73).
        let op = *rng.pick(&[0x71u8, 0x72, 0x73]);
        let digit = *rng.pick(&[2u8, 4, 6]);
        // 73 /4 (PSRAQ) is invalid; keep 71/72 for /4.
        let digit = if op == 0x73 && digit == 4 { 2 } else { digit };
        let rm = rng.below(8) as u8;
        let imm = rng.below(72) as u8; // include over-shift counts
        mmx_trial(vec![0x0F, op, modrm_reg(digit, rm), imm], format!("mmx shift-imm {op:#x}/{digit}"))
    } else {
        // shift by mm count.
        let op = *rng.pick(&[0xD1u8, 0xD2, 0xD3, 0xE1, 0xE2, 0xF1, 0xF2, 0xF3]);
        let (reg, rm) = mm2(rng);
        mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx shift-mm {op:#x}"))
    }
}

fn mmx_pshufw(rng: &mut Rng, _bits: Bits) -> Trial {
    let (reg, rm) = mm2(rng);
    let imm = rng.below(256) as u8;
    mmx_trial(vec![0x0F, 0x70, modrm_reg(reg, rm), imm], format!("pshufw imm={imm}"))
}

/// MOVD/MOVQ between an MMX register and a GP register (register form). Diffs the
/// MMX register file (fpu) and, for the store direction, the GP destination.
fn mmx_movd(rng: &mut Rng, bits: Bits, _seed: &mut Seed) -> Trial {
    let store = rng.boolean(); // true: MOVD r/m, mm
    let w = bits == Bits::B64 && rng.boolean(); // REX.W → MOVQ
    let (mm, gp) = (rng.below(8) as u8, rng.below(8) as u8);
    let op = if store { 0x7E } else { 0x6E };
    let mut b = Vec::new();
    if w {
        b.push(0x48);
    }
    b.extend([0x0F, op, modrm_reg(mm, gp)]); // reg=mm, rm=gp
    mmx_trial(b, format!("{} w{}", if store { "movd r,mm" } else { "movd mm,r" }, if w { 8 } else { 4 }))
}

/// EMMS, PMOVMSKB, PMINUB/PMAXUB, PAVGB/W, PSADBW.
fn mmx_misc(rng: &mut Rng, bits: Bits) -> Trial {
    match rng.below(4) {
        0 => {
            // EMMS: clears the tag word. Both engines end with tw all-empty; the
            // fpu diff compares the st bytes (unchanged) — still exact.
            mmx_trial(vec![0x0F, 0x77], "emms".into())
        }
        1 => {
            // PMOVMSKB r32, mm — writes a GP register (diffed normally).
            let (gp, mm) = (rng.below(8) as u8, rng.below(8) as u8);
            let mut b = Vec::new();
            let _ = bits;
            b.extend([0x0F, 0xD7, modrm_reg(gp, mm)]);
            // GP destination + the (unchanged) MMX file.
            Trial { bytes: b, fpu: true, sw_mask: 0, label: "pmovmskb r,mm".into(), ..Default::default() }
        }
        2 => {
            let op = *rng.pick(&[0xDAu8, 0xDE]); // PMINUB / PMAXUB
            let (reg, rm) = mm2(rng);
            mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx pmin/max {op:#x}"))
        }
        _ => {
            let op = *rng.pick(&[0xE0u8, 0xE3, 0xF6]); // PAVGB / PAVGW / PSADBW
            let (reg, rm) = mm2(rng);
            mmx_trial(vec![0x0F, op, modrm_reg(reg, rm)], format!("mmx pavg/psad {op:#x}"))
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
    Seed {
        gpr,
        rflags,
        xmm,
        ymm_hi: [0u128; 16],
        data,
        st,
        cw,
        sw: 0x0000,
        tw: 0xFFFF,
        mxcsr: 0x1F80,
        fip: 0,
        fdp: 0,
        fop: 0,
        fcs: 0,
        fds: 0,
    }
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
