use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;

const CODE_BASE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;

fn run_with(code: &[u8], setup: impl FnOnce(&mut Interpreter, &mut VirtualMemory)) -> (Interpreter, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1_0000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(0x9_0000);
    setup(&mut cpu, &mut mem);

    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    (cpu, mem)
}

fn f64_in(cpu: &Interpreter, xmm: usize) -> f64 {
    f64::from_bits(cpu.state().xmm[xmm] as u64)
}

#[test]
fn xorps_zeroes_register() {
    let code = [
        0x0F, 0x57, 0xC0,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 0xdead_beef_dead_beef);
    assert_eq!(cpu.state().xmm[0], 0);
}

#[test]
fn movsd_loads_and_stores() {
    let code = [
        0xF2, 0x48, 0x0F, 0x10, 0x04, 0x25,
        (DATA & 0xff) as u8, (DATA >> 8) as u8, (DATA >> 16) as u8, (DATA >> 24) as u8,
        0xF2, 0x48, 0x0F, 0x11, 0x04, 0x25,
        ((DATA + 8) & 0xff) as u8, ((DATA + 8) >> 8) as u8, ((DATA + 8) >> 16) as u8, ((DATA + 8) >> 24) as u8,
        0xF4,
    ];
    let val = std::f64::consts::PI.to_bits();
    let (_, mem) = run_with(&code, |_, mem| mem.write_u64(DATA, val).unwrap());
    assert_eq!(mem.read_u64(DATA + 8).unwrap(), val, "movsd should copy the double through xmm0");
}

#[test]
fn addsd_adds_doubles() {
    let code = [
        0xF2, 0x0F, 0x58, 0xC1,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 1.5f64.to_bits() as u128;
        cpu.state_mut().xmm[1] = 2.25f64.to_bits() as u128;
    });
    assert_eq!(f64_in(&cpu, 0), 3.75);
}

#[test]
fn mulsd_and_divsd() {
    let code = [
        0xF2, 0x0F, 0x59, 0xC1,
        0xF2, 0x0F, 0x5E, 0xC1,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 6.0f64.to_bits() as u128;
        cpu.state_mut().xmm[1] = 4.0f64.to_bits() as u128;
    });
    assert_eq!(f64_in(&cpu, 0), 6.0);
}

#[test]
fn cvtsi2sd_and_cvttsd2si_roundtrip() {
    let code = [
        0xF2, 0x48, 0x0F, 0x2A, 0xC0,
        0xF2, 0x0F, 0x58, 0xC0,
        0xF2, 0x48, 0x0F, 0x2C, 0xC8,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, 42));
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rcx), 84);
}

#[test]
fn comisd_sets_flags_for_branch() {
    let code = [
        0x66, 0x0F, 0x2F, 0xC1,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 1.0f64.to_bits() as u128;
        cpu.state_mut().xmm[1] = 2.0f64.to_bits() as u128;
    });
    use exemu_core::cpu::flags;
    assert!(cpu.state().flag(flags::CF), "1.0 < 2.0 sets CF");
    assert!(!cpu.state().flag(flags::ZF), "operands differ, ZF clear");
}

#[test]
fn movaps_moves_full_128_bits() {
    let code = [
        0x0F, 0x28, 0xC8,
        0xF4,
    ];
    let pattern = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128;
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = pattern);
    assert_eq!(cpu.state().xmm[1], pattern);
}

#[test]
fn punpcklqdq_interleaves_low_quadwords() {
    let code = [0x66, 0x0F, 0x6C, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x1111_1111_1111_1111_2222_2222_2222_2222;
        cpu.state_mut().xmm[1] = 0x3333_3333_3333_3333_4444_4444_4444_4444;
    });
    assert_eq!(cpu.state().xmm[0], 0x4444_4444_4444_4444_2222_2222_2222_2222);
}

#[test]
fn pshufd_reverses_dwords() {
    let code = [0x66, 0x0F, 0x70, 0xC1, 0x1B, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[1] = 0x0000_000D_0000_000C_0000_000B_0000_000A;
    });
    assert_eq!(cpu.state().xmm[0], 0x0000_000A_0000_000B_0000_000C_0000_000D);
}

#[test]
fn pcmpeqb_then_pmovmskb_finds_zero_bytes() {
    let code = [
        0x66, 0x0F, 0x74, 0xC1,
        0x66, 0x0F, 0xD7, 0xC0,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0xFF00;
        cpu.state_mut().xmm[1] = 0;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0xFFFD);
}

#[test]
fn movmskps_movmskpd_extract_sign_bits() {
    let v = (1u128 << 127) | (1u128 << 31);
    let (cpu, _) = run_with(&[0x0F, 0x50, 0xC0, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = v;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0b1001);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x50, 0xC0, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = v;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0b10);
}

#[test]
fn saturating_add_sub_clamps_lanes() {
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xDC, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xF0;
        cpu.state_mut().xmm[1] = 0x20;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0xFF);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xD8, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x10;
        cpu.state_mut().xmm[1] = 0x20;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x00);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xED, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x7000;
        cpu.state_mut().xmm[1] = 0x2000;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 0x7FFF);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE8, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x90;
        cpu.state_mut().xmm[1] = 0x40;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x80);
}

#[test]
fn packed_multiply_ops() {
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xD5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 3;
        cpu.state_mut().xmm[1] = 5;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 15);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x8000;
        cpu.state_mut().xmm[1] = 0x0002;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 0xFFFF);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF4, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xFFFF_FFFF;
        cpu.state_mut().xmm[1] = 0xFFFF_FFFF;
    });
    assert_eq!(cpu.state().xmm[0], 0xFFFF_FFFE_0000_0001);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = (3u128 << 16) | 2;
        cpu.state_mut().xmm[1] = (5u128 << 16) | 4;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF_FFFF, 23);
}

#[test]
fn avg_sad_pack_extract_ops() {
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE0, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xF0;
        cpu.state_mut().xmm[1] = 0x0F;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x80);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF6, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes([0x10; 16]);
        cpu.state_mut().xmm[1] = u128::from_le_bytes([0x08; 16]);
    });
    assert_eq!(cpu.state().xmm[0], (0x40u128 << 64) | 0x40);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x63, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x7FFF;
        cpu.state_mut().xmm[1] = 0x8000;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x7F);
    assert_eq!((cpu.state().xmm[0] >> 64) & 0xFF, 0x80);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xC5, 0xC0, 0x02, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xBEEFu128 << 32;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0xBEEF);
}

#[test]
fn packed_int_float_conversions() {
    let (cpu, _) = run_with(&[0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 5;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 5.0f32.to_bits());
    let (cpu, _) = run_with(&[0xF3, 0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 3.9f32.to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 3);
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 2.5f32.to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 2);
}

#[test]
fn lddqu_loads_128_from_memory() {
    let val = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
    let (cpu, _) = run_with(&[0xF2, 0x0F, 0xF0, 0x00, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        mem.write(DATA, &val.to_le_bytes()).unwrap();
    });
    assert_eq!(cpu.state().xmm[0], val);
}

#[test]
fn mxcsr_load_store_round_trips() {
    let (_, mem) = run_with(&[0x0F, 0xAE, 0x10, 0x0F, 0xAE, 0x1B, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        cpu.state_mut().set_reg(exemu_core::Reg::Rbx, DATA + 16);
        mem.write_u32(DATA, 0x9F80).unwrap();
    });
    assert_eq!(mem.read_u32(DATA + 16).unwrap(), 0x9F80);
}

#[test]
fn fxsave_fxrstor_round_trip_xmm_and_mxcsr() {
    let (_, mem) = run_with(&[0x0F, 0xAE, 0x00, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        cpu.state_mut().xmm[0] = 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00;
        let _ = mem;
    });
    let mut b = [0u8; 16];
    mem.read(DATA + 160, &mut b).unwrap();
    assert_eq!(u128::from_le_bytes(b), 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00);
    assert_eq!(mem.read_u32(DATA + 24).unwrap(), 0x1F80);

    let (cpu, mem) = run_with(&[0x0F, 0xAE, 0x08, 0x0F, 0xAE, 0x1B, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        cpu.state_mut().set_reg(exemu_core::Reg::Rbx, DATA + 512);
        mem.write_u32(DATA + 24, 0x9F80).unwrap();
        mem.write(DATA + 160, &0xCAFE_u128.to_le_bytes()).unwrap();
    });
    assert_eq!(cpu.state().xmm[0], 0xCAFE);
    assert_eq!(mem.read_u32(DATA + 512).unwrap(), 0x9F80);
}

#[test]
fn self_modifying_code_reexecutes_patched_bytes() {
    let (cpu, _) = run_with(
        &[0xC6, 0x40, 0x05, 0x42, 0xB3, 0x00, 0xF4],
        |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, CODE_BASE),
    );
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rbx) & 0xFF, 0x42);
}

#[test]
fn paddb_adds_per_byte_with_wrap() {
    let code = [0x66, 0x0F, 0xFC, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes([0xFF; 16]);
        cpu.state_mut().xmm[1] = u128::from_le_bytes([0x01; 16]);
    });
    assert_eq!(cpu.state().xmm[0], 0);
}

#[test]
fn psrldq_byte_shifts_whole_register() {
    let code = [0x66, 0x0F, 0x73, 0xD8, 0x01, 0xF4];
    let orig = 0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100u128;
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = orig);
    assert_eq!(cpu.state().xmm[0], orig >> 8);
}

#[test]
fn movd_gpr_to_xmm_and_back() {
    let code = [
        0x66, 0x0F, 0x6E, 0xC0,
        0x66, 0x0F, 0x7E, 0xC2,
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, 0xCAFE_BABE));
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rdx), 0xCAFE_BABE);
    assert_eq!(cpu.state().xmm[0], 0xCAFE_BABE);
}

fn eax(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rax) & 0xffff_ffff
}

#[test]
fn cvttsd2si_out_of_range_is_integer_indefinite() {
    let code = [0xF2, 0x0F, 0x2C, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 1e30f64.to_bits() as u128);
    assert_eq!(eax(&cpu), 0x8000_0000);
}

#[test]
fn cvtsd2si_rounds_to_nearest_even() {
    let code = [0xF2, 0x0F, 0x2D, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 2.5f64.to_bits() as u128);
    assert_eq!(eax(&cpu), 2);
}

#[test]
fn minps_returns_source_on_nan() {
    let code = [0x0F, 0x5D, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 1.0f32.to_bits() as u128;
        cpu.state_mut().xmm[1] = f32::NAN.to_bits() as u128;
    });
    let lane0 = cpu.state().xmm[0] as u32;
    assert!(f32::from_bits(lane0).is_nan(), "min(1.0, NaN) must yield the NaN source");
}

#[test]
fn minsd_returns_source_on_signed_zero() {
    let code = [0xF2, 0x0F, 0x5D, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0.0f64.to_bits() as u128;
        cpu.state_mut().xmm[1] = (-0.0f64).to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u64, 0x8000_0000_0000_0000, "min(+0,-0) = src = -0.0");
}

#[test]
fn psrldq_by_16_or_more_clears() {
    let code = [0x66, 0x0F, 0x73, 0xD8, 0x11, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = u128::MAX);
    assert_eq!(cpu.state().xmm[0], 0);
}

fn ecx(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rcx) & 0xffff_ffff
}

#[test]
fn pshufb_selects_and_zeroes() {
    let code = [0x66, 0x0F, 0x38, 0x00, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        let mut src = 0u128;
        for i in 0..16u128 {
            src |= i << (i * 8);
        }
        cpu.state_mut().xmm[0] = src;
        cpu.state_mut().xmm[1] = 0x0F << 16 | 0x80 << 8;
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r & 0xFF, 0x00, "byte0 = src[0]");
    assert_eq!((r >> 8) & 0xFF, 0x00, "byte1 control high-bit → 0");
    assert_eq!((r >> 16) & 0xFF, 0x0F, "byte2 = src[15]");
}

#[test]
fn palignr_concatenates_and_shifts() {
    let code = [0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x03, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;
        cpu.state_mut().xmm[1] = 0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100;
    });
    let expect = (0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100u128 >> 24)
        | (0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128 << (128 - 24));
    assert_eq!(cpu.state().xmm[0], expect);
}

#[test]
fn palignr_imm_ge_32_zeroes() {
    let code = [0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x20, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = u128::MAX;
        cpu.state_mut().xmm[1] = u128::MAX;
    });
    assert_eq!(cpu.state().xmm[0], 0);
}

#[test]
fn ptest_sets_zf_and_cf() {
    use exemu_core::cpu::flags;
    let code = [0x66, 0x0F, 0x38, 0x17, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F;
        cpu.state_mut().xmm[1] = 0xF0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0;
    });
    assert!(cpu.state().flag(flags::ZF), "disjoint masks → ZF");
    assert!(!cpu.state().flag(flags::CF), "xmm1 has bits outside xmm0 → CF clear");
}

#[test]
fn roundsd_honors_imm_modes() {
    let code = [0x66, 0x0F, 0x3A, 0x0B, 0xC1, 0x01, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0;
        cpu.state_mut().xmm[1] = 2.7f64.to_bits() as u128;
    });
    assert_eq!(f64_in(&cpu, 0), 2.0, "floor(2.7) = 2.0");
}

#[test]
fn roundss_nearest_even() {
    let code = [0x66, 0x0F, 0x3A, 0x0A, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0;
        cpu.state_mut().xmm[1] = 2.5f32.to_bits() as u128;
    });
    let lane0 = f32::from_bits(cpu.state().xmm[0] as u32);
    assert_eq!(lane0, 2.0, "round-nearest-even(2.5) = 2.0");
}

#[test]
fn pmulld_low_dwords() {
    let code = [0x66, 0x0F, 0x38, 0x40, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = (7u128) | (0xFFFF_FFFFu128 << 32);
        cpu.state_mut().xmm[1] = (6u128) | (2u128 << 32);
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r & 0xFFFF_FFFF, 42, "7*6");
    assert_eq!((r >> 32) & 0xFFFF_FFFF, 0xFFFF_FFFE, "0xFFFFFFFF*2 low32");
}

#[test]
fn crc32_castagnoli_byte() {
    let code = [0xF2, 0x0F, 0x38, 0xF0, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().gpr[0] = 0;
        cpu.state_mut().gpr[1] = 0xFF;
    });
    assert_eq!(eax(&cpu), 0xAD7D_5351);
}

#[test]
fn pcmpistri_flags_and_index() {
    use exemu_core::cpu::flags;
    let code = [0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes(*b"abc\0\0\0\0\0\0\0\0\0\0\0\0\0");
        cpu.state_mut().xmm[1] = u128::from_le_bytes(*b"xby\0\0\0\0\0\0\0\0\0\0\0\0\0");
    });
    assert_eq!(ecx(&cpu), 1, "first (LSB) matching position is index 1");
    assert!(cpu.state().flag(flags::CF), "a match exists → CF");
    assert!(cpu.state().flag(flags::ZF), "b has a null before the end → ZF");
    assert!(cpu.state().flag(flags::SF), "a has a null before the end → SF");
}

#[test]
fn pcmpistri_no_match_returns_16() {
    use exemu_core::cpu::flags;
    let code = [0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes(*b"abc\0\0\0\0\0\0\0\0\0\0\0\0\0");
        cpu.state_mut().xmm[1] = u128::from_le_bytes(*b"xyz\0\0\0\0\0\0\0\0\0\0\0\0\0");
    });
    assert_eq!(ecx(&cpu), 16, "no match → index = element count");
    assert!(!cpu.state().flag(flags::CF), "no match → CF clear");
}

#[test]
fn pinsrb_reads_low_byte_not_high8_alias() {
    let code = [0x66, 0x0F, 0x3A, 0x20, 0xFF, 0x0C, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[7] = 0;
        cpu.state_mut().gpr[7] = 0x7FFF_FFFF;
    });
    let byte12 = (cpu.state().xmm[7] >> (12 * 8)) & 0xFF;
    assert_eq!(byte12, 0xFF, "PINSRB inserts the register's low byte");
}

#[test]
fn mpsadbw_block_offsets_from_imm() {
    let code = [0x66, 0x0F, 0x3A, 0x42, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x00_00_00_00_00_00_00_00_00_00_00_00_04_03_02_01;
        cpu.state_mut().xmm[1] = 0x00_00_00_00_00_00_00_00_00_00_00_00_08_06_04_02;
    });
    let word0 = cpu.state().xmm[0] & 0xFFFF;
    assert_eq!(word0, 10);
}

#[test]
fn phaddw_in_place_alias_hazard() {
    let code = [0x66, 0x0F, 0x38, 0x01, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        let mut v = 0u128;
        for i in 0..8u128 {
            v |= (i + 1) << (i * 16);
        }
        cpu.state_mut().xmm[0] = v;
    });
    let w = |k: u32| ((cpu.state().xmm[0] >> (k * 16)) & 0xFFFF) as u64;
    assert_eq!((w(0), w(1), w(2), w(3)), (3, 7, 11, 15));
    assert_eq!((w(4), w(5), w(6), w(7)), (10, 26, 36, 44));
}

#[test]
fn pmovzxbw_zero_extends_low_bytes() {
    let code = [0x66, 0x0F, 0x38, 0x30, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[1] = 0xFF_80_01_00_FF_80_01_00;
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r & 0xFFFF, 0x0000, "byte 0x00 → word 0");
    assert_eq!((r >> 16) & 0xFFFF, 0x0001, "byte 0x01 → word 1");
    assert_eq!((r >> 48) & 0xFFFF, 0x00FF, "byte 0xFF → word 0x00FF (zero-ext)");
}

#[test]
fn cmpps_eq_produces_lane_mask() {
    let code = [0x0F, 0xC2, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        let a: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
        let b: [f32; 4] = [1.0, 9.0, 3.0, 9.0];
        let pack = |v: [f32; 4]| {
            (v[0].to_bits() as u128)
                | ((v[1].to_bits() as u128) << 32)
                | ((v[2].to_bits() as u128) << 64)
                | ((v[3].to_bits() as u128) << 96)
        };
        cpu.state_mut().xmm[0] = pack(a);
        cpu.state_mut().xmm[1] = pack(b);
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r as u32, 0xFFFF_FFFF, "lane0 1==1 → all ones");
    assert_eq!((r >> 32) as u32, 0, "lane1 2!=9 → zero");
    assert_eq!((r >> 64) as u32, 0xFFFF_FFFF, "lane2 3==3 → all ones");
    assert_eq!((r >> 96) as u32, 0, "lane3 4!=9 → zero");
}

#[test]
fn cmpss_scalar_preserves_upper_lanes() {
    let code = [0xF3, 0x0F, 0xC2, 0xC1, 0x01, 0xF4];
    let upper: u128 = 0xAAAA_BBBB_CCCC_DDDD_1111_2222_0000_0000;
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = upper | (1.0f32.to_bits() as u128);
        cpu.state_mut().xmm[1] = 2.0f32.to_bits() as u128;
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r as u32, 0xFFFF_FFFF, "1.0 < 2.0 → low lane all ones");
    assert_eq!(r & !0xFFFF_FFFFu128, upper, "upper 96 bits preserved");
}

#[test]
fn cmpsd_unordered_predicate() {
    let code = [0xF2, 0x0F, 0xC2, 0xC1, 0x03, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = f64::NAN.to_bits() as u128;
        cpu.state_mut().xmm[1] = 1.0f64.to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u64, u64::MAX, "NaN is unordered → all ones");
}

#[test]
fn pinsrw_inserts_word_at_selected_lane() {
    let code = [0x66, 0x0F, 0xC4, 0xC1, 0x03, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0;
        cpu.state_mut().gpr[1] = 0x1234_5678_9ABC_DEF0;
    });
    let r = cpu.state().xmm[0];
    assert_eq!((r >> 48) & 0xFFFF, 0xDEF0, "word lane 3 = low 16 bits of ecx");
    assert_eq!(r & 0xFFFF_FFFF_FFFF, 0, "other lanes untouched");
}
