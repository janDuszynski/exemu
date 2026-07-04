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
