//! x87 FPU unit tests (hand-assembled bytes; 32-bit and 64-bit forms).

use exemu_core::{Cpu, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;

fn mem() -> VirtualMemory {
    let mut m = VirtualMemory::new();
    m.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    m.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    m
}

fn run(m: &mut VirtualMemory, code: &[u8], steps: usize) -> Interpreter {
    m.write(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    for _ in 0..steps {
        cpu.step(m, &mut hooks).unwrap();
    }
    cpu
}

/// FLD1 pushes 1.0; FLDZ pushes 0.0; FADD makes 1.0.
#[test]
fn fld1_fldz_fadd() {
    let mut m = mem();
    // fld1 (D9 E8); fldz (D9 EE); faddp st1,st0 (DE C1)
    let cpu = run(&mut m, &[0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xC1], 3);
    // After faddp: st0 should be 1.0. Read ST0 via its extended value.
    let x = &cpu.state().x87;
    let st0 = x.st[x.phys(0)];
    assert_eq!(exemu_cpu_ext_to_f64(st0), 1.0);
}

/// FLD m64 then FSTP m64 round-trips the exact double bits.
#[test]
fn fld_fstp_m64_roundtrip() {
    let mut m = mem();
    let v = std::f64::consts::PI;
    m.write_u64(DATA, v.to_bits()).unwrap();
    // fld qword [DATA]  = DD /0 with rip-rel? Use absolute via rax base.
    // mov rax, DATA ; fld qword [rax] ; fstp qword [rax+8]
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes()); // mov rax, DATA
    code.extend_from_slice(&[0xDD, 0x00]); // fld qword [rax]
    code.extend_from_slice(&[0xDD, 0x58, 0x08]); // fstp qword [rax+8]
    run(&mut m, &code, 3);
    assert_eq!(f64::from_bits(m.read_u64(DATA + 8).unwrap()), v);
}

/// FLD m80 / FSTP m80 preserves all 80 bits (long double fidelity).
#[test]
fn fld_fstp_m80_roundtrip() {
    let mut m = mem();
    // A non-f64-representable 80-bit value: pi as the ROM constant.
    let lo: u64 = 0xC90F_DAA2_2168_C235;
    let hi: u16 = 0x4000;
    m.write_u64(DATA, lo).unwrap();
    m.write_u16(DATA + 8, hi).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDB, 0x28]); // fld tbyte [rax]   (DB /5)
    code.extend_from_slice(&[0xDB, 0x78, 0x10]); // fstp tbyte [rax+16] (DB /7)
    run(&mut m, &code, 3);
    assert_eq!(m.read_u64(DATA + 16).unwrap(), lo);
    assert_eq!(m.read_u16(DATA + 24).unwrap(), hi);
}

/// fnstsw ax reflects the status word after a compare.
#[test]
fn fnstsw_after_fcom() {
    let mut m = mem();
    // fld1; fldz; fcompp -> compares st0(0.0) vs st1(1.0); then fnstsw ax
    // Actually push order: fld1 -> st0=1; fldz -> st0=0,st1=1. fcompp compares st0 vs st1.
    // 0.0 < 1.0 so C0 set.
    let mut code = vec![0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xD9]; // fld1;fldz;fcompp
    code.extend_from_slice(&[0xDF, 0xE0]); // fnstsw ax
    let cpu = run(&mut m, &code, 4);
    let ax = cpu.state().gpr[0] & 0xffff;
    assert_ne!(ax & (1 << 8), 0, "C0 should be set (0.0 < 1.0)");
}

/// FMUL m32 multiplies ST0 by a float in memory.
#[test]
fn fmul_m32() {
    let mut m = mem();
    m.write_u32(DATA, 3.0f32.to_bits()).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xD9, 0xE8]); // fld1  -> st0=1.0
    code.extend_from_slice(&[0xD8, 0x08]); // fmul dword [rax] (D8 /1)
    let cpu = run(&mut m, &code, 3);
    let x = &cpu.state().x87;
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(0)]), 3.0);
}

// ---- regression pins for divergences found during oracle bring-up ----------

/// Seed ST0 (physical 0, TOP=0) with an f64-exact value, then run `code`.
fn run_st0(m: &mut VirtualMemory, x: f64, code: &[u8], steps: usize) -> Interpreter {
    m.write(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().x87.tw = 0x0000;
    cpu.state_mut().x87.st[0] = f64_to_ext(x);
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    for _ in 0..steps {
        cpu.step(m, &mut hooks).unwrap();
    }
    cpu
}

fn f64_to_ext(x: f64) -> u128 {
    let bits = x.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7ff) as u32;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    let (e, s): (u32, u64) = if exp == 0 && frac == 0 {
        (0, 0)
    } else {
        ((exp as i32 - 1023 + 16383) as u32, 0x8000_0000_0000_0000 | (frac << 11))
    };
    ((sign as u128) << 79) | ((e as u128) << 64) | (s as u128)
}

/// DC/DE reverse-encoding quirk: DC /5 is FSUB (ST(i) = ST(i) − ST0), DC /4 is
/// FSUBR (ST(i) = ST0 − ST(i)). A naive decode swaps these and flips the sign.
#[test]
fn dc_fsub_fsubr_reverse_encoding() {
    let mut m = mem();
    // st0 = 10, st1 = 3.  fsubr st1,st0 (DC /4, modrm E9) -> st1 = st0 - st1 = 7
    // Build: fld1-ish via loads. Push 3.0 then 10.0 so st0=10, st1=3.
    // fld m64(3.0); fld m64(10.0) using rax base.
    m.write_u64(DATA, 3.0f64.to_bits()).unwrap();
    m.write_u64(DATA + 8, 10.0f64.to_bits()).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes()); // mov rax,DATA
    code.extend_from_slice(&[0xDD, 0x00]); // fld qword [rax]   -> st0=3
    code.extend_from_slice(&[0xDD, 0x40, 0x08]); // fld qword [rax+8] -> st0=10,st1=3
    code.extend_from_slice(&[0xDC, 0xE1]); // fsubr st1,st0 (DC /4) -> st1 = st0-st1 = 7
    let cpu = run(&mut m, &code, 4);
    let x = &cpu.state().x87;
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(1)]), 7.0, "DC /4 must be FSUBR");
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(0)]), 10.0);
}

/// FRNDINT of a small negative value rounds to −0.0 (sign preserved), not +0.0.
#[test]
fn frndint_negative_zero() {
    let mut m = mem();
    let cpu = run_st0(&mut m, -0.3, &[0xD9, 0xFC], 1); // frndint
    let x = &cpu.state().x87;
    let st0 = x.st[x.phys(0)];
    assert_eq!(st0, f64_to_ext(-0.0), "frndint(-0.3) must be -0.0");
    // -0.0 has the sign bit set (bit 79).
    assert_ne!(st0 & (1u128 << 79), 0);
}

/// FISTP m16 of an out-of-range value stores the 16-bit integer indefinite
/// (0x8000), not a truncated low word.
#[test]
fn fistp_m16_indefinite() {
    let mut m = mem();
    // st0 = 100000.0 (> i16::MAX). fistp word [rax].
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDF, 0x18]); // fistp word [rax] (DF /3)
    m.write(CODE, &code).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().x87.tw = 0x0000;
    cpu.state_mut().x87.st[0] = f64_to_ext(100000.0);
    cpu.state_mut().gpr[0] = DATA;
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    for _ in 0..2 {
        cpu.step(&mut m, &mut hooks).unwrap();
    }
    assert_eq!(m.read_u16(DATA).unwrap(), 0x8000, "m16 integer indefinite");
}

/// FNINIT resets cw/sw/tw but leaves the physical register bytes intact
/// (they become "empty"/undefined but are not zeroed).
#[test]
fn fninit_preserves_register_bytes() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().x87.st[3] = 0x4000_c90f_daa2_2168_c235; // some 80-bit value
    cpu.state_mut().x87.cw = 0x027F;
    cpu.state_mut().x87.sw = 0x3800;
    cpu.state_mut().x87.tw = 0x0000;
    cpu.state_mut().rip = CODE;
    m.write(CODE, &[0xDB, 0xE3]).unwrap(); // fninit
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let x = &cpu.state().x87;
    assert_eq!(x.cw, 0x037F);
    assert_eq!(x.sw, 0x0000);
    assert_eq!(x.tw, 0xFFFF);
    assert_eq!(x.st[3], 0x4000_c90f_daa2_2168_c235, "FNINIT must not zero data regs");
}

/// FDECSTP (D9 F6) / FINCSTP (D9 F7) decode and move TOP without faulting.
#[test]
fn fdecstp_fincstp_decode() {
    let mut m = mem();
    let cpu = run(&mut m, &[0xD9, 0xF6, 0xD9, 0xF7], 2); // fdecstp; fincstp
    assert_eq!(cpu.state().x87.top(), 0, "TOP back to 0 after dec+inc");
}

/// Regression: loading a normal `double` with magnitude below 1.0 (biased
/// exponent < 1023, e.g. 0.5 → 1022, ln2 → 1022) must not underflow the
/// double→extended exponent rebias. `f64_to_ext` computed `exp - 1023 + 16383`,
/// which underflows `u32` for any such value and panics under debug/overflow
/// checks — even though the value is a perfectly ordinary finite double. Found
/// by the W1 ntdll `.text` decode sweep. FLD then FSTP must round-trip the exact
/// bits for a range of sub-1.0 magnitudes (and their negatives).
#[test]
fn fld_fstp_sub_one_magnitude_no_exponent_underflow() {
    // Ordinary sub-1.0 magnitudes down to ~1e-300 (the class the fix covers and
    // that a modern toolchain's ntdll produces). Values within a few powers of
    // two of the f64 denormal floor exercise a *separate* store-path scaling
    // edge (documented follow-up) and are deliberately excluded here.
    for v in [0.5_f64, -0.5, std::f64::consts::LN_2, 0.75, 0.1, -0.1, 1e-300, 2.5e-200] {
        let mut m = mem();
        m.write_u64(DATA, v.to_bits()).unwrap();
        let mut code = vec![0x48, 0xB8];
        code.extend_from_slice(&DATA.to_le_bytes()); // mov rax, DATA
        code.extend_from_slice(&[0xDD, 0x00]); // fld qword [rax]
        code.extend_from_slice(&[0xDD, 0x58, 0x08]); // fstp qword [rax+8]
        run(&mut m, &code, 3);
        assert_eq!(
            f64::from_bits(m.read_u64(DATA + 8).unwrap()),
            v,
            "FLD/FSTP must round-trip {v} (magnitude < 1.0) without exponent underflow"
        );
    }
}

// Re-expose the crate's conversion for the tests via a tiny reimplementation
// mirror (the crate keeps it private). Kept minimal: normal + zero paths.
fn exemu_cpu_ext_to_f64(v: u128) -> f64 {
    let sign = ((v >> 79) & 1) as u64;
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    if exp == 0 && signif == 0 {
        return f64::from_bits(sign << 63);
    }
    let mantissa = signif as f64;
    let e2 = exp as i32 - 16383 - 63;
    let mag = mantissa * 2f64.powi(e2);
    if sign == 1 { -mag } else { mag }
}
