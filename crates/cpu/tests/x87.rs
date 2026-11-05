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

#[test]
fn fld1_fldz_fadd() {
    let mut m = mem();
    let cpu = run(&mut m, &[0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xC1], 3);
    let x = &cpu.state().x87;
    let st0 = x.st[x.phys(0)];
    assert_eq!(exemu_cpu_ext_to_f64(st0), 1.0);
}

#[test]
fn fld_fstp_m64_roundtrip() {
    let mut m = mem();
    let v = std::f64::consts::PI;
    m.write_u64(DATA, v.to_bits()).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDD, 0x00]);
    code.extend_from_slice(&[0xDD, 0x58, 0x08]);
    run(&mut m, &code, 3);
    assert_eq!(f64::from_bits(m.read_u64(DATA + 8).unwrap()), v);
}

#[test]
fn fld_fstp_m80_roundtrip() {
    let mut m = mem();
    let lo: u64 = 0xC90F_DAA2_2168_C235;
    let hi: u16 = 0x4000;
    m.write_u64(DATA, lo).unwrap();
    m.write_u16(DATA + 8, hi).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDB, 0x28]);
    code.extend_from_slice(&[0xDB, 0x78, 0x10]);
    run(&mut m, &code, 3);
    assert_eq!(m.read_u64(DATA + 16).unwrap(), lo);
    assert_eq!(m.read_u16(DATA + 24).unwrap(), hi);
}

#[test]
fn fnstsw_after_fcom() {
    let mut m = mem();
    let mut code = vec![0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xD9];
    code.extend_from_slice(&[0xDF, 0xE0]);
    let cpu = run(&mut m, &code, 4);
    let ax = cpu.state().gpr[0] & 0xffff;
    assert_ne!(ax & (1 << 8), 0, "C0 should be set (0.0 < 1.0)");
}

#[test]
fn fmul_m32() {
    let mut m = mem();
    m.write_u32(DATA, 3.0f32.to_bits()).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xD9, 0xE8]);
    code.extend_from_slice(&[0xD8, 0x08]);
    let cpu = run(&mut m, &code, 3);
    let x = &cpu.state().x87;
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(0)]), 3.0);
}

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

#[test]
fn dc_fsub_fsubr_reverse_encoding() {
    let mut m = mem();
    m.write_u64(DATA, 3.0f64.to_bits()).unwrap();
    m.write_u64(DATA + 8, 10.0f64.to_bits()).unwrap();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDD, 0x00]);
    code.extend_from_slice(&[0xDD, 0x40, 0x08]);
    code.extend_from_slice(&[0xDC, 0xE1]);
    let cpu = run(&mut m, &code, 4);
    let x = &cpu.state().x87;
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(1)]), 7.0, "DC /4 must be FSUBR");
    assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(0)]), 10.0);
}

#[test]
fn frndint_negative_zero() {
    let mut m = mem();
    let cpu = run_st0(&mut m, -0.3, &[0xD9, 0xFC], 1);
    let x = &cpu.state().x87;
    let st0 = x.st[x.phys(0)];
    assert_eq!(st0, f64_to_ext(-0.0), "frndint(-0.3) must be -0.0");
    assert_ne!(st0 & (1u128 << 79), 0);
}

#[test]
fn fistp_m16_indefinite() {
    let mut m = mem();
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0xDF, 0x18]);
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

#[test]
fn fninit_preserves_register_bytes() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().x87.st[3] = 0x4000_c90f_daa2_2168_c235;
    cpu.state_mut().x87.cw = 0x027F;
    cpu.state_mut().x87.sw = 0x3800;
    cpu.state_mut().x87.tw = 0x0000;
    cpu.state_mut().rip = CODE;
    m.write(CODE, &[0xDB, 0xE3]).unwrap();
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let x = &cpu.state().x87;
    assert_eq!(x.cw, 0x037F);
    assert_eq!(x.sw, 0x0000);
    assert_eq!(x.tw, 0xFFFF);
    assert_eq!(x.st[3], 0x4000_c90f_daa2_2168_c235, "FNINIT must not zero data regs");
}

#[test]
fn fdecstp_fincstp_decode() {
    let mut m = mem();
    let cpu = run(&mut m, &[0xD9, 0xF6, 0xD9, 0xF7], 2);
    assert_eq!(cpu.state().x87.top(), 0, "TOP back to 0 after dec+inc");
}

#[test]
fn fld_fstp_sub_one_magnitude_no_exponent_underflow() {
    for v in [0.5_f64, -0.5, std::f64::consts::LN_2, 0.75, 0.1, -0.1, 1e-300, 2.5e-200] {
        let mut m = mem();
        m.write_u64(DATA, v.to_bits()).unwrap();
        let mut code = vec![0x48, 0xB8];
        code.extend_from_slice(&DATA.to_le_bytes());
        code.extend_from_slice(&[0xDD, 0x00]);
        code.extend_from_slice(&[0xDD, 0x58, 0x08]);
        run(&mut m, &code, 3);
        assert_eq!(
            f64::from_bits(m.read_u64(DATA + 8).unwrap()),
            v,
            "FLD/FSTP must round-trip {v} (magnitude < 1.0) without exponent underflow"
        );
    }
}

fn mov_rax_data() -> Vec<u8> {
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code
}

fn two_value_stack() -> Vec<u8> {
    let mut code = mov_rax_data();
    code.extend_from_slice(&[0xD9, 0xE8, 0xD9, 0xEE]);
    code
}

#[test]
fn fnsave_32bit_layout_tag_word_and_reinit() {
    let mut m = mem();
    let mut code = two_value_stack();
    code.extend_from_slice(&[0xDD, 0x30]);
    let cpu = run(&mut m, &code, 4);
    assert_eq!(m.read_u16(DATA).unwrap(), 0x037F);
    assert_eq!(m.read_u16(DATA + 4).unwrap(), 0x3000);
    assert_eq!(m.read_u16(DATA + 8).unwrap(), 0x1FFF);
    assert_eq!(m.read_u16(DATA + 28).unwrap(), 0x0000);
    assert_eq!(m.read_u16(DATA + 28 + 10 + 8).unwrap(), 0x3FFF);
    assert_eq!(m.read_u64(DATA + 28 + 10).unwrap(), 0x8000_0000_0000_0000);
    let x = &cpu.state().x87;
    assert_eq!((x.cw, x.sw, x.tw), (0x037F, 0, 0xFFFF));
}

#[test]
fn fnsave_16bit_layout_uses_94_bytes() {
    let mut m = mem();
    m.write(DATA, &[0xAA; 128]).unwrap();
    let mut code = two_value_stack();
    code.extend_from_slice(&[0x66, 0xDD, 0x30]);
    run(&mut m, &code, 4);
    assert_eq!(m.read_u16(DATA).unwrap(), 0x037F);
    assert_eq!(m.read_u16(DATA + 2).unwrap(), 0x3000);
    assert_eq!(m.read_u16(DATA + 4).unwrap(), 0x1FFF);
    assert_eq!(m.read_u16(DATA + 14 + 10 + 8).unwrap(), 0x3FFF);
    assert_eq!(m.read_u8(DATA + 94).unwrap(), 0xAA);
    assert_eq!(m.read_u8(DATA + 93).unwrap(), 0x00);
}

#[test]
fn fnsave_frstor_round_trip_both_sizes() {
    for prefix in [&[][..], &[0x66][..]] {
        let mut m = mem();
        let mut code = two_value_stack();
        code.extend_from_slice(prefix);
        code.extend_from_slice(&[0xDD, 0x30]);
        code.extend_from_slice(prefix);
        code.extend_from_slice(&[0xDD, 0x20]);
        let cpu = run(&mut m, &code, 5);
        let x = &cpu.state().x87;
        assert_eq!(x.top(), 6);
        assert_eq!(x.sw & 0x3800, 0x3000);
        assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(0)]), 0.0);
        assert_eq!(exemu_cpu_ext_to_f64(x.st[x.phys(1)]), 1.0);
        assert_eq!(x.tw, 0x1FFF);
    }
}

#[test]
fn fnstenv_fldenv_layouts_and_registers_untouched() {
    let mut m = mem();
    m.write(DATA, &[0xAA; 64]).unwrap();
    let mut code = two_value_stack();
    code.extend_from_slice(&[0xD9, 0x30]);
    code.extend_from_slice(&[0x66, 0xD9, 0x70, 0x20]);
    let cpu = run(&mut m, &code, 5);
    assert_eq!(m.read_u16(DATA + 8).unwrap(), 0x1FFF);
    assert_eq!(m.read_u32(DATA + 4).unwrap(), 0x3000);
    assert_eq!(m.read_u16(DATA + 0x20 + 4).unwrap(), 0x1FFF);
    assert_eq!(m.read_u8(DATA + 0x20 + 14).unwrap(), 0xAA);
    assert_eq!(m.read_u8(DATA + 28).unwrap(), 0xAA);
    let x = &cpu.state().x87;
    assert_eq!(x.sw & 0x3800, 0x3000);
    assert_eq!(x.tw, 0x1FFF);
}

#[test]
fn fldenv_loads_control_status_and_tags_without_touching_registers() {
    let mut m = mem();
    m.write_u32(DATA, 0x0000_0C7F).unwrap();
    m.write_u32(DATA + 4, 0x0000_2800).unwrap();
    m.write_u32(DATA + 8, 0x0000_FFFF).unwrap();
    let mut code = mov_rax_data();
    code.extend_from_slice(&[0xD9, 0xE8, 0xD9, 0x20]);
    let cpu = run(&mut m, &code, 3);
    let x = &cpu.state().x87;
    assert_eq!((x.cw, x.sw, x.tw), (0x0C7F, 0x2800, 0xFFFF));
    assert_eq!(x.st[7], 0x3FFF_u128 << 64 | 0x8000_0000_0000_0000);
}

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
