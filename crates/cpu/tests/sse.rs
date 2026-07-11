//! SSE / SSE2 tests, hand-assembled the same way as the integer tests.

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
    // Preload xmm0 with junk, then xorps xmm0, xmm0 → 0.
    let code = [
        0x0F, 0x57, 0xC0, // xorps xmm0, xmm0
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 0xdead_beef_dead_beef);
    assert_eq!(cpu.state().xmm[0], 0);
}

#[test]
fn movsd_loads_and_stores() {
    // movsd xmm0, [DATA] ; movsd [DATA+8], xmm0
    let code = [
        0xF2, 0x48, 0x0F, 0x10, 0x04, 0x25, // movsd xmm0, [disp32]
        (DATA & 0xff) as u8, (DATA >> 8) as u8, (DATA >> 16) as u8, (DATA >> 24) as u8,
        0xF2, 0x48, 0x0F, 0x11, 0x04, 0x25, // movsd [disp32], xmm0
        ((DATA + 8) & 0xff) as u8, ((DATA + 8) >> 8) as u8, ((DATA + 8) >> 16) as u8, ((DATA + 8) >> 24) as u8,
        0xF4,
    ];
    let val = std::f64::consts::PI.to_bits();
    let (_, mem) = run_with(&code, |_, mem| mem.write_u64(DATA, val).unwrap());
    assert_eq!(mem.read_u64(DATA + 8).unwrap(), val, "movsd should copy the double through xmm0");
}

#[test]
fn addsd_adds_doubles() {
    // xmm0 = 1.5, xmm1 = 2.25, addsd xmm0, xmm1 → 3.75
    let code = [
        0xF2, 0x0F, 0x58, 0xC1, // addsd xmm0, xmm1
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
    // xmm0 = 6.0, xmm1 = 4.0 ; mulsd xmm0, xmm1 (=24) ; divsd xmm0, xmm1 (=6)
    let code = [
        0xF2, 0x0F, 0x59, 0xC1, // mulsd xmm0, xmm1
        0xF2, 0x0F, 0x5E, 0xC1, // divsd xmm0, xmm1
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
    // cvtsi2sd xmm0, rax (rax=42) ; addsd xmm0,xmm0 (=84) ; cvttsd2si rcx, xmm0
    let code = [
        0xF2, 0x48, 0x0F, 0x2A, 0xC0, // cvtsi2sd xmm0, rax
        0xF2, 0x0F, 0x58, 0xC0, // addsd xmm0, xmm0
        0xF2, 0x48, 0x0F, 0x2C, 0xC8, // cvttsd2si rcx, xmm0
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, 42));
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rcx), 84);
}

#[test]
fn comisd_sets_flags_for_branch() {
    // xmm0 = 1.0, xmm1 = 2.0 ; comisd xmm0, xmm1 → CF=1 (1.0 < 2.0), ZF=0
    let code = [
        0x66, 0x0F, 0x2F, 0xC1, // comisd xmm0, xmm1
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
    // movaps xmm1, xmm0 (full 128-bit copy)
    let code = [
        0x0F, 0x28, 0xC8, // movaps xmm1, xmm0
        0xF4,
    ];
    let pattern = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128;
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = pattern);
    assert_eq!(cpu.state().xmm[1], pattern);
}

#[test]
fn punpcklqdq_interleaves_low_quadwords() {
    // punpcklqdq xmm0, xmm1 → xmm0 = (xmm1.low64 << 64) | xmm0.low64.
    // The CRT's SSE2 memset broadcasts a byte across a register this way.
    let code = [0x66, 0x0F, 0x6C, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x1111_1111_1111_1111_2222_2222_2222_2222;
        cpu.state_mut().xmm[1] = 0x3333_3333_3333_3333_4444_4444_4444_4444;
    });
    assert_eq!(cpu.state().xmm[0], 0x4444_4444_4444_4444_2222_2222_2222_2222);
}

#[test]
fn pshufd_reverses_dwords() {
    // pshufd xmm0, xmm1, 0x1B  (0b00_01_10_11 selects dwords 3,2,1,0).
    let code = [0x66, 0x0F, 0x70, 0xC1, 0x1B, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[1] = 0x0000_000D_0000_000C_0000_000B_0000_000A;
    });
    assert_eq!(cpu.state().xmm[0], 0x0000_000A_0000_000B_0000_000C_0000_000D);
}

#[test]
fn pcmpeqb_then_pmovmskb_finds_zero_bytes() {
    // The SSE2 strlen idiom: pcmpeqb against zero, then gather the match mask.
    let code = [
        0x66, 0x0F, 0x74, 0xC1, // pcmpeqb xmm0, xmm1
        0x66, 0x0F, 0xD7, 0xC0, // pmovmskb eax, xmm0
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0xFF00; // byte 1 = 0xFF, every other byte 0
        cpu.state_mut().xmm[1] = 0; // compare against zero
    });
    // Every byte equals zero except byte 1 → all mask bits set but bit 1.
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0xFFFD);
}

#[test]
fn movmskps_movmskpd_extract_sign_bits() {
    // xmm0 sign bits set on f32 lane 0 (bit 31) and lane 3 (bit 127).
    let v = (1u128 << 127) | (1u128 << 31);
    // movmskps eax, xmm0 → lanes 0 and 3 → 0b1001 = 9.
    let (cpu, _) = run_with(&[0x0F, 0x50, 0xC0, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = v;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0b1001);
    // movmskpd eax, xmm0 → f64 lanes at bits 63 (clear) and 127 (set) → 0b10.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x50, 0xC0, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = v;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0b10);
}

#[test]
fn saturating_add_sub_clamps_lanes() {
    // paddusb xmm0, xmm1: 0xF0 + 0x20 clamps to 0xFF (unsigned byte).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xDC, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xF0;
        cpu.state_mut().xmm[1] = 0x20;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0xFF);
    // psubusb xmm0, xmm1: 0x10 - 0x20 clamps to 0 (no unsigned wrap).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xD8, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x10;
        cpu.state_mut().xmm[1] = 0x20;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x00);
    // paddsw xmm0, xmm1: 0x7000 + 0x2000 clamps to 0x7FFF (signed word max).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xED, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x7000;
        cpu.state_mut().xmm[1] = 0x2000;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 0x7FFF);
    // psubsb xmm0, xmm1: (-0x70) - 0x40 clamps to -128 = 0x80 (signed byte min).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE8, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x90; // -112
        cpu.state_mut().xmm[1] = 0x40; // +64
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x80);
}

#[test]
fn packed_multiply_ops() {
    // pmullw: low 16 of 3*5 = 15.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xD5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 3;
        cpu.state_mut().xmm[1] = 5;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 15);
    // pmulhw: (-32768)*2 = -65536 = 0xFFFF0000 → high word 0xFFFF (signed).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x8000;
        cpu.state_mut().xmm[1] = 0x0002;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF, 0xFFFF);
    // pmuludq: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF4, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xFFFF_FFFF;
        cpu.state_mut().xmm[1] = 0xFFFF_FFFF;
    });
    assert_eq!(cpu.state().xmm[0], 0xFFFF_FFFE_0000_0001);
    // pmaddwd: dword0 = 2*4 + 3*5 = 23.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF5, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = (3u128 << 16) | 2;
        cpu.state_mut().xmm[1] = (5u128 << 16) | 4;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFFFF_FFFF, 23);
}

#[test]
fn avg_sad_pack_extract_ops() {
    // pavgb: (0xF0 + 0x0F + 1) >> 1 = 0x80.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xE0, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xF0;
        cpu.state_mut().xmm[1] = 0x0F;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x80);
    // psadbw: all bytes |0x10-0x08| = 8, ×8 per half = 0x40 at bit 0 and bit 64.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xF6, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes([0x10; 16]);
        cpu.state_mut().xmm[1] = u128::from_le_bytes([0x08; 16]);
    });
    assert_eq!(cpu.state().xmm[0], (0x40u128 << 64) | 0x40);
    // packsswb: dst word 0x7FFF → +127 (byte 0); src word 0x8000 → -128 (byte 8).
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x63, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0x7FFF;
        cpu.state_mut().xmm[1] = 0x8000;
    });
    assert_eq!(cpu.state().xmm[0] & 0xFF, 0x7F);
    assert_eq!((cpu.state().xmm[0] >> 64) & 0xFF, 0x80);
    // pextrw eax, xmm0, 2 → word lane 2.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0xC5, 0xC0, 0x02, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[0] = 0xBEEFu128 << 32;
    });
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0xBEEF);
}

#[test]
fn packed_int_float_conversions() {
    // cvtdq2ps xmm0, xmm1: int32 5 → f32 5.0.
    let (cpu, _) = run_with(&[0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 5;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 5.0f32.to_bits());
    // cvttps2dq xmm0, xmm1: f32 3.9 truncates to 3.
    let (cpu, _) = run_with(&[0xF3, 0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 3.9f32.to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 3);
    // cvtps2dq xmm0, xmm1: f32 2.5 rounds to even → 2.
    let (cpu, _) = run_with(&[0x66, 0x0F, 0x5B, 0xC1, 0xF4], |cpu, _| {
        cpu.state_mut().xmm[1] = 2.5f32.to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u32, 2);
}

#[test]
fn lddqu_loads_128_from_memory() {
    // lddqu xmm0, [rax] with rax → the data region.
    let val = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
    let (cpu, _) = run_with(&[0xF2, 0x0F, 0xF0, 0x00, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        mem.write(DATA, &val.to_le_bytes()).unwrap();
    });
    assert_eq!(cpu.state().xmm[0], val);
}

#[test]
fn mxcsr_load_store_round_trips() {
    // ldmxcsr [rax]; stmxcsr [rbx] — the control word must survive intact.
    let (_, mem) = run_with(&[0x0F, 0xAE, 0x10, 0x0F, 0xAE, 0x1B, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        cpu.state_mut().set_reg(exemu_core::Reg::Rbx, DATA + 16);
        mem.write_u32(DATA, 0x9F80).unwrap();
    });
    assert_eq!(mem.read_u32(DATA + 16).unwrap(), 0x9F80);
}

#[test]
fn fxsave_fxrstor_round_trip_xmm_and_mxcsr() {
    // fxsave [rax]: xmm0 lands at +160, mxcsr at +24.
    let (_, mem) = run_with(&[0x0F, 0xAE, 0x00, 0xF4], |cpu, mem| {
        cpu.state_mut().set_reg(exemu_core::Reg::Rax, DATA);
        cpu.state_mut().xmm[0] = 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00;
        let _ = mem;
    });
    let mut b = [0u8; 16];
    mem.read(DATA + 160, &mut b).unwrap();
    assert_eq!(u128::from_le_bytes(b), 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00);
    assert_eq!(mem.read_u32(DATA + 24).unwrap(), 0x1F80);

    // fxrstor [rax]; stmxcsr [rbx] — reload xmm0 + mxcsr from a save area.
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
    // No decode cache (P0.6): patching a later instruction's immediate before
    // it runs must take effect. mov byte [rax+5], 0x42 patches the 0x00 imm of
    // the following `mov bl, 0x00`, so bl ends up 0x42.
    let (cpu, _) = run_with(
        &[0xC6, 0x40, 0x05, 0x42, 0xB3, 0x00, 0xF4],
        |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, CODE_BASE),
    );
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rbx) & 0xFF, 0x42);
}

#[test]
fn paddb_adds_per_byte_with_wrap() {
    // paddb xmm0, xmm1: 0xFF + 0x01 wraps to 0x00 in every byte lane.
    let code = [0x66, 0x0F, 0xFC, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = u128::from_le_bytes([0xFF; 16]);
        cpu.state_mut().xmm[1] = u128::from_le_bytes([0x01; 16]);
    });
    assert_eq!(cpu.state().xmm[0], 0);
}

#[test]
fn psrldq_byte_shifts_whole_register() {
    // psrldq xmm0, 1  (66 0F 73 /3 ib): shift the 128-bit value right one byte.
    let code = [0x66, 0x0F, 0x73, 0xD8, 0x01, 0xF4];
    let orig = 0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100u128;
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = orig);
    assert_eq!(cpu.state().xmm[0], orig >> 8);
}

#[test]
fn movd_gpr_to_xmm_and_back() {
    // movd xmm0, eax (eax=0xCAFEBABE) ; movd edx, xmm0
    let code = [
        0x66, 0x0F, 0x6E, 0xC0, // movd xmm0, eax
        0x66, 0x0F, 0x7E, 0xC2, // movd edx, xmm0
        0xF4,
    ];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().set_reg(exemu_core::Reg::Rax, 0xCAFE_BABE));
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rdx), 0xCAFE_BABE);
    assert_eq!(cpu.state().xmm[0], 0xCAFE_BABE);
}

// ---- Differential-oracle SSE regression tests (roadmap P0.4 / P1.3) --------
//
// Each encodes an exemu-vs-real-x86 divergence the P0.1 Unicorn oracle flagged.

fn eax(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rax) & 0xffff_ffff
}

#[test]
fn cvttsd2si_out_of_range_is_integer_indefinite() {
    // cvttsd2si eax, xmm0 with xmm0 = 1e30 → out of i32 range → 0x80000000
    // (x86 "integer indefinite"), NOT a saturated 0x7fffffff.
    let code = [0xF2, 0x0F, 0x2C, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 1e30f64.to_bits() as u128);
    assert_eq!(eax(&cpu), 0x8000_0000);
}

#[test]
fn cvtsd2si_rounds_to_nearest_even() {
    // cvtsd2si eax, xmm0 with xmm0 = 2.5 → 2 (banker's rounding), not 3.
    let code = [0xF2, 0x0F, 0x2D, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = 2.5f64.to_bits() as u128);
    assert_eq!(eax(&cpu), 2);
}

#[test]
fn minps_returns_source_on_nan() {
    // minps xmm0, xmm1 with xmm0 lane0 = 1.0, xmm1 lane0 = NaN.
    // x86 min is (a<b)?a:b, so the NaN source is returned (not dropped).
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
    // minsd xmm0, xmm1 with xmm0 = +0.0, xmm1 = -0.0 → -0.0 (the source),
    // since +0.0 < -0.0 is false.
    let code = [0xF2, 0x0F, 0x5D, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0.0f64.to_bits() as u128;
        cpu.state_mut().xmm[1] = (-0.0f64).to_bits() as u128;
    });
    assert_eq!(cpu.state().xmm[0] as u64, 0x8000_0000_0000_0000, "min(+0,-0) = src = -0.0");
}

#[test]
fn psrldq_by_16_or_more_clears() {
    // psrldq xmm0, 17 → 0 (all 16 bytes shifted out). The buggy `>> 128`
    // wrapped to `>> 0` and left the register unchanged.
    let code = [0x66, 0x0F, 0x73, 0xD8, 0x11, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| cpu.state_mut().xmm[0] = u128::MAX);
    assert_eq!(cpu.state().xmm[0], 0);
}

// ---- SSSE3 / SSE4.1 / SSE4.2 (0F 38 / 0F 3A) — roadmap W1.4 ---------------
//
// PSHUFB / PALIGNR / PTEST / ROUND* / PMULLD / PCMPISTRI / CRC32 plus the three
// exemu-vs-reference divergences the oracle flagged during bring-up (PINSRB's
// high-byte-alias read, MPSADBW's imm[1:0]/imm[2] block-offset swap, and the
// PHADDW in-place hazard when the source aliases the destination).

fn ecx(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rcx) & 0xffff_ffff
}

#[test]
fn pshufb_selects_and_zeroes() {
    // pshufb xmm0, xmm1. Control bytes: byte0 selects src[0], byte1 has the
    // high bit set (→ 0), byte2 selects src[15]; the rest select src[0].
    let code = [0x66, 0x0F, 0x38, 0x00, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        // src bytes: b[i] = i (so src[0]=0x00 .. src[15]=0x0F).
        let mut src = 0u128;
        for i in 0..16u128 {
            src |= i << (i * 8);
        }
        cpu.state_mut().xmm[0] = src;
        // control: byte0 = 0x00 (→ src[0]=0), byte1 = 0x80 (→ 0), byte2 = 0x0F
        // (→ src[15]=0x0F), all others 0x00.
        cpu.state_mut().xmm[1] = 0x0F << 16 | 0x80 << 8;
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r & 0xFF, 0x00, "byte0 = src[0]");
    assert_eq!((r >> 8) & 0xFF, 0x00, "byte1 control high-bit → 0");
    assert_eq!((r >> 16) & 0xFF, 0x0F, "byte2 = src[15]");
}

#[test]
fn palignr_concatenates_and_shifts() {
    // palignr xmm0, xmm1, 3 — concat (xmm0:xmm1), byte-shift right by 3.
    let code = [0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x03, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA; // high (a)
        cpu.state_mut().xmm[1] = 0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100; // low (b)
    });
    // low 13 bytes = b >> 24 bits; top 3 bytes = a's low 3 bytes.
    let expect = (0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100u128 >> 24)
        | (0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128 << (128 - 24));
    assert_eq!(cpu.state().xmm[0], expect);
}

#[test]
fn palignr_imm_ge_32_zeroes() {
    // palignr xmm0, xmm1, 32 → all zero.
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
    // ptest xmm0, xmm1. ZF = ((xmm1 & xmm0)==0); CF = ((xmm1 & ~xmm0)==0).
    let code = [0x66, 0x0F, 0x38, 0x17, 0xC1, 0xF4];
    // Case: xmm0 = 0x0F.., xmm1 = 0xF0.. → AND=0 (ZF=1); ~xmm0 & xmm1 = xmm1 (CF=0).
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F;
        cpu.state_mut().xmm[1] = 0xF0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0;
    });
    assert!(cpu.state().flag(flags::ZF), "disjoint masks → ZF");
    assert!(!cpu.state().flag(flags::CF), "xmm1 has bits outside xmm0 → CF clear");
}

#[test]
fn roundsd_honors_imm_modes() {
    // roundsd xmm0, xmm1, imm. Test floor (imm=1) of 2.7 → 2.0.
    let code = [0x66, 0x0F, 0x3A, 0x0B, 0xC1, 0x01, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0;
        cpu.state_mut().xmm[1] = 2.7f64.to_bits() as u128;
    });
    assert_eq!(f64_in(&cpu, 0), 2.0, "floor(2.7) = 2.0");
}

#[test]
fn roundss_nearest_even() {
    // roundss xmm0, xmm1, 0 (nearest-even) of 2.5 → 2.0.
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
    // pmulld xmm0, xmm1 — 4 lanes of 32x32 keeping the low 32 bits.
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
    // crc32 eax, cl (F2 0F 38 F0 /r) — CRC-32C of a single byte 0x00 into a
    // seed of 0 is 0; feed 0xFF with seed 0 to get a known nonzero value.
    let code = [0xF2, 0x0F, 0x38, 0xF0, 0xC1, 0xF4]; // crc32 eax, cl
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().gpr[0] = 0; // eax seed
        cpu.state_mut().gpr[1] = 0xFF; // cl
    });
    // CRC-32C (Castagnoli) of the single byte 0xFF with an initial CRC of 0 and
    // no final inversion is 0xAD7D5351 (independently computed reference).
    assert_eq!(eax(&cpu), 0xAD7D_5351);
}

#[test]
fn pcmpistri_flags_and_index() {
    use exemu_core::cpu::flags;
    // pcmpistri xmm0, xmm1, 0 — equal-any, unsigned bytes, implicit length,
    // least-significant index. The classic flag trap: CF set iff any match,
    // ECX = index of the first match (else 16).
    // xmm0 (the "set" a) = bytes 'a','b','c', null-terminated.
    // xmm1 (the "search" b) = 'x','b','y', null-terminated → 'b' matches at i=1.
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
    // No common byte → ECX = 16, CF = 0.
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
    // pinsrb xmm7, edi, 12 (66 0F 3A 20 /r ib). Oracle divergence: reading the
    // source as an 8-bit r/m wrongly hit the BH/DH-style high-byte alias for
    // register indices 4..8 with no REX; PINSRB must take the *low* byte of the
    // doubleword register (DIL), here 0xFF.
    let code = [0x66, 0x0F, 0x3A, 0x20, 0xFF, 0x0C, 0xF4]; // reg=7(xmm7), rm=7(edi)
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[7] = 0;
        cpu.state_mut().gpr[7] = 0x7FFF_FFFF; // edi low byte = 0xFF
    });
    let byte12 = (cpu.state().xmm[7] >> (12 * 8)) & 0xFF;
    assert_eq!(byte12, 0xFF, "PINSRB inserts the register's low byte");
}

#[test]
fn mpsadbw_block_offsets_from_imm() {
    // mpsadbw xmm0, xmm1, imm. imm[1:0] picks the 4-byte reference block in the
    // *source* (xmm1); imm[2] picks the window base in the *dest* (xmm0). The
    // oracle caught these two being swapped. With imm=0 both offsets are 0, so
    // result word0 = |a0-b0|+|a1-b1|+|a2-b2|+|a3-b3|.
    let code = [0x66, 0x0F, 0x3A, 0x42, 0xC1, 0x00, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[0] = 0x00_00_00_00_00_00_00_00_00_00_00_00_04_03_02_01;
        cpu.state_mut().xmm[1] = 0x00_00_00_00_00_00_00_00_00_00_00_00_08_06_04_02;
    });
    let word0 = cpu.state().xmm[0] & 0xFFFF;
    // |1-2|+|2-4|+|3-6|+|4-8| = 1+2+3+4 = 10.
    assert_eq!(word0, 10);
}

#[test]
fn phaddw_in_place_alias_hazard() {
    // phaddw xmm0, xmm0 — when the source aliases the destination the low half
    // is written first, so the high half's later pairs read the freshly-written
    // low words, NOT the original ones (matches the hardware/reference in-place
    // behavior the oracle pinned). Words = [1,2,3,4,5,6,7,8].
    let code = [0x66, 0x0F, 0x38, 0x01, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        let mut v = 0u128;
        for i in 0..8u128 {
            v |= (i + 1) << (i * 16);
        }
        cpu.state_mut().xmm[0] = v;
    });
    let w = |k: u32| ((cpu.state().xmm[0] >> (k * 16)) & 0xFFFF) as u64;
    // Low half: 1+2, 3+4, 5+6, 7+8 = 3,7,11,15.
    assert_eq!((w(0), w(1), w(2), w(3)), (3, 7, 11, 15));
    // High half reads the live, sequentially-updated destination. After the low
    // half d = [3,7,11,15,5,6,7,8]; then d4=d0+d1=10, d5=d2+d3=26, d6=d4+d5=36
    // (d4/d5 already overwritten this instruction), d7=d6+d7=36+8=44.
    assert_eq!((w(4), w(5), w(6), w(7)), (10, 26, 36, 44));
}

#[test]
fn pmovzxbw_zero_extends_low_bytes() {
    // pmovzxbw xmm0, xmm1 (66 0F 38 30) — low 8 bytes → 8 zero-extended words.
    let code = [0x66, 0x0F, 0x38, 0x30, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().xmm[1] = 0xFF_80_01_00_FF_80_01_00; // low 8 bytes
    });
    let r = cpu.state().xmm[0];
    assert_eq!(r & 0xFFFF, 0x0000, "byte 0x00 → word 0");
    assert_eq!((r >> 16) & 0xFFFF, 0x0001, "byte 0x01 → word 1");
    assert_eq!((r >> 48) & 0xFFFF, 0x00FF, "byte 0xFF → word 0x00FF (zero-ext)");
}
