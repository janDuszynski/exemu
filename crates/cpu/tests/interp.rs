use exemu_core::cpu::flags;
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;

const CODE_BASE: u64 = 0x1_0000;
const STACK_TOP: u64 = 0x9_0000;

fn run(code: &[u8]) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);

    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => return cpu,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    panic!("program did not halt within the step budget");
}

fn rax(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rax)
}
fn rbx(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rbx)
}

#[test]
fn add_two_registers() {
    let code = [
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0xB9, 0x03, 0x00, 0x00, 0x00,
        0x01, 0xC8,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 8);
}

#[test]
fn push_pop_roundtrip() {
    let code = [
        0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50,
        0x5B,
        0xF4,
    ];
    assert_eq!(rbx(&run(&code)), 0x1234);
}

#[test]
fn summation_loop() {
    let code = [
        0x31, 0xC0,
        0xB9, 0x0A, 0x00, 0x00, 0x00,
        0x01, 0xC8,
        0xFF, 0xC9,
        0x75, 0xFA,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 55);
}

#[test]
fn memory_store_and_load() {
    let code = [
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x44, 0x24, 0xF8,
        0x48, 0x8B, 0x5C, 0x24, 0xF8,
        0xF4,
    ];
    assert_eq!(rbx(&run(&code)), 0xDEAD_BEEF);
}

#[test]
fn call_and_ret() {
    let code = [
        0xE8, 0x06, 0x00, 0x00, 0x00,
        0xF4,
        0x90, 0x90, 0x90, 0x90, 0x90,
        0xB8, 0x07, 0x00, 0x00, 0x00,
        0xC3,
    ];
    assert_eq!(rax(&run(&code)), 7);
}

#[test]
fn signed_compare_setcc() {
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0x83, 0xF8, 0x01,
        0x0F, 0x9C, 0xC3,
        0x0F, 0xB6, 0xC3,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 1);
}

#[test]
fn imul_and_flags() {
    let code = [
        0xB8, 0x06, 0x00, 0x00, 0x00,
        0x6B, 0xC0, 0x07,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 42);
}

#[test]
fn div_unsigned() {
    let code = [
        0xB8, 0x64, 0x00, 0x00, 0x00,
        0x31, 0xD2,
        0xB9, 0x07, 0x00, 0x00, 0x00,
        0xF7, 0xF1,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 14);
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rdx), 2);
}

#[test]
fn shift_left_sets_result() {
    let code = [
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC1, 0xE0, 0x04,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 16);
}

#[test]
fn rep_stosb_fills_memory() {
    let stack_addr = 0x8_1000u64;
    let code = [
        0xB0, 0xAB,
        0x48, 0xBF,
        (stack_addr & 0xff) as u8,
        (stack_addr >> 8) as u8,
        (stack_addr >> 16) as u8,
        (stack_addr >> 24) as u8,
        0, 0, 0, 0,
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00,
        0xF3, 0xAA,
        0xF4,
    ];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    let mut hooks = NoHooks;
    loop {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    assert_eq!(mem.read_u32(stack_addr).unwrap(), 0xABAB_ABAB);
}

#[test]
fn shld_shifts_in_from_source() {
    let code = [
        0xB8, 0x78, 0x56, 0x34, 0x12,
        0xBB, 0xF0, 0xDE, 0xBC, 0x9A,
        0x0F, 0xA4, 0xD8, 0x08,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x3456_789A);
}

#[test]
fn bt_imm_sets_carry_and_setcc() {
    let code = [
        0xB8, 0x00, 0x01, 0x00, 0x00,
        0x0F, 0xBA, 0xE0, 0x08,
        0x0F, 0x92, 0xC3,
        0x0F, 0xB6, 0xC3,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 1);
}

#[test]
fn bsf_finds_lowest_set_bit() {
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00,
        0x0F, 0xBC, 0xC0,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 4);
}

#[test]
fn bswap_reverses_bytes() {
    let code = [
        0xB8, 0x44, 0x33, 0x22, 0x11,
        0x0F, 0xC8,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x4433_2211);
}

#[test]
fn overflow_flag_on_signed_add() {
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0x7F,
        0x83, 0xC0, 0x01,
        0xF4,
    ];
    let cpu = run(&code);
    assert!(cpu.state().flag(flags::OF), "overflow flag should be set");
    assert!(cpu.state().flag(flags::SF), "sign flag should be set");
}

#[test]
fn popcnt_counts_set_bits() {
    let code = [
        0xB8, 0x0F, 0x0F, 0x00, 0x00,
        0xF3, 0x0F, 0xB8, 0xD8,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 8);
    assert!(!cpu.state().flag(flags::ZF));
}

#[test]
fn popcnt_zero_sets_zf() {
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0xB8, 0xD8,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 0);
    assert!(cpu.state().flag(flags::ZF));
}

#[test]
fn tzcnt_trailing_zeros() {
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0xBC, 0xD8,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 4);
    assert!(!cpu.state().flag(flags::CF));
    assert!(!cpu.state().flag(flags::ZF));
}

#[test]
fn tzcnt_zero_is_width_and_sets_cf() {
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0xBC, 0xD8,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 32);
    assert!(cpu.state().flag(flags::CF));
}

#[test]
fn lzcnt_leading_zeros() {
    let code = [
        0xB8, 0xFF, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0xBD, 0xD8,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 24);
    assert!(!cpu.state().flag(flags::CF));
}

#[test]
fn bsf_without_f3_still_works() {
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00,
        0x0F, 0xBC, 0xD8,
        0xF4,
    ];
    assert_eq!(rbx(&run(&code)), 4);
}

fn rcx(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rcx)
}
fn rdx(cpu: &Interpreter) -> u64 {
    cpu.state().reg(exemu_core::Reg::Rdx)
}

#[test]
fn cpuid_vendor_string_is_intel() {
    let code = [
        0x31, 0xC0,
        0x0F, 0xA2,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu) as u32, 0x756e_6547);
    assert_eq!(rcx(&cpu) as u32, 0x6c65_746e);
    assert_eq!(rdx(&cpu) as u32, 0x4965_6e69);
    assert_eq!(rax(&cpu) as u32, 0xD);
}

#[test]
fn cpuid_advertises_sse2_ssse3_sse4_avx() {
    let code = [
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x0F, 0xA2,
        0xF4,
    ];
    let cpu = run(&code);
    let edx = rdx(&cpu) as u32;
    let ecx = rcx(&cpu) as u32;
    assert!(edx & (1 << 26) != 0, "SSE2 (EDX.26) must be set");
    assert!(edx & (1 << 25) != 0, "SSE (EDX.25) must be set");
    assert!(ecx & (1 << 23) != 0, "POPCNT (ECX.23) must be set");
    assert!(ecx & (1 << 26) != 0, "XSAVE (ECX.26) must be advertised");
    assert!(ecx & (1 << 27) != 0, "OSXSAVE (ECX.27) must be advertised");
    assert!(ecx & (1 << 9) != 0, "SSSE3 (ECX.9) must be advertised (W1.4)");
    assert!(ecx & (1 << 19) != 0, "SSE4.1 (ECX.19) must be advertised (W1.4)");
    assert!(ecx & (1 << 20) != 0, "SSE4.2 (ECX.20) must be advertised (W1.4)");
    assert!(ecx & (1 << 28) != 0, "AVX (ECX.28) must be advertised (W1.5)");
}

#[test]
fn rdtsc_is_monotonic() {
    let code = [
        0x0F, 0x31,
        0x89, 0xC1,
        0x0F, 0x31,
        0x29, 0xC8,
        0xF4,
    ];
    let cpu = run(&code);
    assert!(rax(&cpu) as u32 > 0, "TSC must advance between reads");
}

#[test]
fn rdtsc_is_exactly_reproducible_under_the_virtual_clock() {
    let code = [
        0x0F, 0x31,
        0x89, 0xC1,
        0x0F, 0x31,
        0x29, 0xC8,
        0xF4,
    ];
    let delta = |_: u32| {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
        mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
        mem.write(CODE_BASE, &code).unwrap();
        let mut cpu = Interpreter::new();
        cpu.set_clock(exemu_core::GuestClock::virtualized());
        cpu.state_mut().rip = CODE_BASE;
        cpu.state_mut().set_rsp(STACK_TOP);
        let mut hooks = NoHooks;
        loop {
            match cpu.step(&mut mem, &mut hooks).unwrap() {
                Exit::Continue => {}
                Exit::Halted => break,
                other => panic!("unexpected exit: {other:?}"),
            }
        }
        rax(&cpu) as u32
    };
    assert_eq!(delta(0), 200, "TSC delta is the instruction count, scaled");
    assert_eq!(delta(1), delta(2), "and it repeats exactly");
    assert_eq!(delta(1), 200);
}

#[test]
fn movbe_load_byteswaps_from_memory() {
    let code = [
        0xC7, 0x44, 0x24, 0xF8, 0x44, 0x33, 0x22, 0x11,
        0x0F, 0x38, 0xF0, 0x44, 0x24, 0xF8,
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x4433_2211);
}

#[test]
fn movbe_store_byteswaps_to_memory() {
    let code = [
        0xB8, 0xDD, 0xCC, 0xBB, 0xAA,
        0x0F, 0x38, 0xF1, 0x44, 0x24, 0xF8,
        0x8B, 0x5C, 0x24, 0xF8,
        0xF4,
    ];
    assert_eq!(rbx(&run(&code)) & 0xffff_ffff, 0xDDCC_BBAA);
}

fn flag(cpu: &Interpreter, mask: u64) -> bool {
    cpu.state().flag(mask)
}

#[test]
fn imul_two_op_negative_no_overflow_clears_cf_of() {
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0x0F, 0xAF, 0xC0,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 1);
    assert!(!flag(&cpu, flags::CF), "CF must be clear (no overflow)");
    assert!(!flag(&cpu, flags::OF), "OF must be clear (no overflow)");
}

#[test]
fn imul_one_op_signed_high_half() {
    let code = [
        0xB8, 0xFE, 0xFF, 0xFF, 0xFF,
        0xB9, 0x03, 0x00, 0x00, 0x00,
        0xF7, 0xE9,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0xFFFF_FFFA);
    assert_eq!(rdx(&cpu) & 0xffff_ffff, 0xFFFF_FFFF);
    assert!(!flag(&cpu, flags::CF));
    assert!(!flag(&cpu, flags::OF));
}

#[test]
fn idiv_negative_divisor() {
    let code = [
        0xB8, 0xFA, 0xFF, 0xFF, 0xFF,
        0x99,
        0xB9, 0xFD, 0xFF, 0xFF, 0xFF,
        0xF7, 0xF9,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 2);
    assert_eq!(rdx(&cpu) & 0xffff_ffff, 0);
}

#[test]
fn rcl_by_one_sets_overflow() {
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x80,
        0xD1, 0xD0,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0);
    assert!(flag(&cpu, flags::CF), "CF = old MSB = 1");
    assert!(flag(&cpu, flags::OF), "OF = MSB(result) XOR CF = 1");
}

#[test]
fn cmov_not_taken_zero_extends() {
    let code = [
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,
        0x0F, 0x42, 0xC1,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0x0000_0000_FFFF_FFFF, "upper 32 bits must be cleared");
}

#[test]
fn cmpxchg_equal_zero_extends_accumulator() {
    let code = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xB9, 0x00, 0x00, 0x00, 0x00,
        0xBA, 0x05, 0x00, 0x00, 0x00,
        0x0F, 0xB1, 0xD1,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0, "accumulator upper 32 bits must be cleared");
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 5, "destination updated on equal");
}

#[test]
fn rdtscp_ecx_zero_and_tsc_monotonic() {
    let code = [
        0x0F, 0x01, 0xF9,
        0x89, 0xC3,
        0x0F, 0x01, 0xF9,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rcx(&cpu) as u32, 0, "ECX (IA32_TSC_AUX) must be 0");
    let first_low = rbx(&cpu) as u32;
    let second_low = rax(&cpu) as u32;
    assert!(
        second_low > first_low,
        "TSC must be monotonically increasing: first={first_low} second={second_low}"
    );
    assert_eq!(cpu.state().rip, CODE_BASE + 8, "rip must advance past all 3 RDTSCP bytes");
}

#[test]
fn pause_is_nop() {
    let code = [
        0xF3, 0x90,
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0, "RAX must be unchanged by PAUSE");
    assert_eq!(rbx(&cpu), 0, "RBX must be unchanged by PAUSE");
    assert_eq!(rcx(&cpu), 0, "RCX must be unchanged by PAUSE");
    assert_eq!(rdx(&cpu), 0, "RDX must be unchanged by PAUSE");
    assert_eq!(
        cpu.state().rip,
        CODE_BASE + 2,
        "rip must advance past PAUSE (2 bytes); HLT stops without advancing rip"
    );
}

use exemu_core::Reg;

fn run_seeded(code: &[u8], regs: &[(Reg, u64)], data_at: Option<(u64, &[u8])>) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();
    if let Some((addr, bytes)) = data_at {
        mem.write(addr, bytes).unwrap();
    }
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    for (r, v) in regs {
        cpu.state_mut().set_reg(*r, *v);
    }
    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => return cpu,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    panic!("program did not halt within the step budget");
}

fn run_seeded_mem(code: &[u8], regs: &[(Reg, u64)], data_addr: u64, data: &[u8]) -> (Interpreter, Vec<u8>) {
    let mut mem = VirtualMemory::new();
    let data_base = data_addr & !0xFFF;
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.map(Region::new("data", data_base, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();
    mem.write(data_addr, data).unwrap();
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    for (r, v) in regs {
        cpu.state_mut().set_reg(*r, *v);
    }
    let mut hooks = NoHooks;
    let mut halted = false;
    for _ in 0..10_000 {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => {
                halted = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(halted, "program did not halt");
    let mut out = vec![0u8; data.len()];
    mem.read(data_addr, &mut out).unwrap();
    (cpu, out)
}

const DATA: u64 = 0x2_0000;

#[test]
fn andn_result_and_flags() {
    let code = [0xC4, 0xE2, 0x60, 0xF2, 0xCA, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rbx, 0x0F0F_0F0F), (Reg::Rdx, 0xFFFF_FFFF)], None);
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0xF0F0_F0F0);
    assert!(flag(&cpu, flags::SF), "ANDN sets SF from result msb");
    assert!(!flag(&cpu, flags::ZF), "ANDN ZF clear (result nonzero)");
    assert!(!flag(&cpu, flags::CF), "ANDN clears CF");
    assert!(!flag(&cpu, flags::OF), "ANDN clears OF");
}

#[test]
fn blsi_extracts_lowest_set_bit_and_cf() {
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xD9, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0x10);
    assert!(flag(&cpu, flags::CF), "BLSI CF = (src != 0) per SDM");
    assert!(!flag(&cpu, flags::ZF), "BLSI ZF from result");

    let cpu0 = run_seeded(&code, &[(Reg::Rcx, 0)], None);
    assert_eq!(rbx(&cpu0) & 0xffff_ffff, 0);
    assert!(!flag(&cpu0, flags::CF), "BLSI CF = 0 when src == 0");
    assert!(flag(&cpu0, flags::ZF), "BLSI ZF = 1 when result 0");
}

#[test]
fn blsr_clears_lowest_set_bit() {
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xC9, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xA0);
    assert!(!flag(&cpu, flags::CF), "BLSR CF = (src == 0) = 0 here");
}

#[test]
fn blsmsk_masks_up_to_lowest_set_bit_zf_clear() {
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xD1, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0x1F);
    assert!(!flag(&cpu, flags::ZF), "BLSMSK forces ZF = 0");
    assert!(!flag(&cpu, flags::CF), "BLSMSK CF = (src == 0) = 0 here");
}

#[test]
fn bextr_extracts_field_and_overlength_passthrough() {
    let code = [0xC4, 0xE2, 0x60, 0xF7, 0xCA, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0xDEAD_BEEF), (Reg::Rbx, 0x08_04)], None);
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0xEE);
    assert!(!flag(&cpu, flags::ZF), "BEXTR ZF from result");

    let code64 = [0xC4, 0xE2, 0xE0, 0xF7, 0xCA, 0xF4];
    let cpu64 = run_seeded(&code64, &[(Reg::Rdx, 0x8000_0000_0000_0001), (Reg::Rbx, 200 << 8)], None);
    assert_eq!(rcx(&cpu64), 0x8000_0000_0000_0001, "BEXTR len>=opsize returns full source");

    let code32 = [0xC4, 0xE2, 0x60, 0xF7, 0xCA, 0xF4];
    let cpu32 = run_seeded(&code32, &[(Reg::Rdx, 0xD445_608C), (Reg::Rbx, 32 << 8)], None);
    assert_eq!(rcx(&cpu32) & 0xffff_ffff, 0xD445_608C, "BEXTR len==opsize keeps bit 31");
}

#[test]
fn mulx_flag_preserving_and_product() {
    let code = [0xC4, 0xE2, 0x73, 0xF6, 0xDA, 0xF4];
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rdx, 0xFFFF_FFFF);
        s.rflags |= flags::CF | flags::OF | flags::SF | flags::ZF | flags::AF | flags::PF;
    }
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut hooks = NoHooks;
    loop {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0x0000_0001, "MULX low half → vvvv");
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xFFFF_FFFE, "MULX high half → reg");
    for f in [flags::CF, flags::OF, flags::SF, flags::ZF, flags::AF, flags::PF] {
        assert!(flag(&cpu, f), "MULX preserves every status flag");
    }
}

#[test]
fn pdep_pext_roundtrip() {
    let code = [0xC4, 0xE2, 0x73, 0xF5, 0xDA, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0b111), (Reg::Rdx, 0b10101)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0b10101);

    let code2 = [0xC4, 0xE2, 0x72, 0xF5, 0xDA, 0xF4];
    let cpu2 = run_seeded(&code2, &[(Reg::Rcx, 0b10101), (Reg::Rdx, 0b10101)], None);
    assert_eq!(rbx(&cpu2) & 0xffff_ffff, 0b111, "PEXT packs the 3 masked bits low");
}

#[test]
fn bzhi_zero_high_and_cf_boundary() {
    let code = [0xC4, 0xE2, 0x70, 0xF5, 0xDA, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 8)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xFF);
    assert!(!flag(&cpu, flags::CF), "BZHI CF=0 when idx <= opsize-1");

    let cpu31 = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 31)], None);
    assert_eq!(rbx(&cpu31) & 0xffff_ffff, 0x7FFF_FFFF);
    assert!(!flag(&cpu31, flags::CF), "BZHI CF=0 at idx == opsize-1 (SDM: N > opsize-1)");

    let cpu32 = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 40)], None);
    assert_eq!(rbx(&cpu32) & 0xffff_ffff, 0xFFFF_FFFF, "BZHI idx>=opsize passes source through");
    assert!(flag(&cpu32, flags::CF), "BZHI CF=1 when idx >= opsize");
}

#[test]
fn rorx_rotates_without_touching_flags() {
    let code = [0xC4, 0xE3, 0x7B, 0xF0, 0xD9, 0x04, 0xF4];
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rcx, 0x0000_000F);
        s.rflags |= flags::CF | flags::OF | flags::ZF;
    }
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut hooks = NoHooks;
    loop {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xF000_0000, "ror(0xF, 4) in 32 bits");
    assert!(flag(&cpu, flags::CF) && flag(&cpu, flags::OF) && flag(&cpu, flags::ZF), "RORX preserves all flags");
}

#[test]
fn sarx_shlx_shrx_flag_untouched() {
    let code = [0xC4, 0xE2, 0x72, 0xF7, 0xDA, 0xF4];
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0x8000_0000), (Reg::Rcx, 4)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xF800_0000, "SARX arithmetic shift keeps sign");

    let shlx = [0xC4, 0xE2, 0x71, 0xF7, 0xDA, 0xF4];
    let cpu_l = run_seeded(&shlx, &[(Reg::Rdx, 0x1), (Reg::Rcx, 5)], None);
    assert_eq!(rcx(&cpu_l) & 0xffff_ffff, 5);
    assert_eq!(rbx(&cpu_l) & 0xffff_ffff, 0x20, "SHLX shift left");
    let shrx = [0xC4, 0xE2, 0x73, 0xF7, 0xDA, 0xF4];
    let cpu_r = run_seeded(&shrx, &[(Reg::Rdx, 0x8000_0000), (Reg::Rcx, 4)], None);
    assert_eq!(rbx(&cpu_r) & 0xffff_ffff, 0x0800_0000, "SHRX logical shift right");
}

#[test]
fn bmi_32bit_result_zero_extends_upper() {
    let code = [0xC4, 0xE2, 0x60, 0xF2, 0xCA, 0xF4];
    let cpu = run_seeded(
        &code,
        &[(Reg::Rbx, 0), (Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 0xDEAD_BEEF_0000_0000)],
        None,
    );
    assert_eq!(rcx(&cpu), 0x0000_0000_FFFF_FFFF, "32-bit BMI zero-extends the upper half");
}

#[test]
fn adcx_updates_only_cf() {
    let code = [0x66, 0x0F, 0x38, 0xF6, 0xC1, 0xF4];
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rax, 0xFFFF_FFFF);
        s.set_reg(Reg::Rcx, 0);
        s.rflags |= flags::CF | flags::OF | flags::SF | flags::ZF | flags::AF | flags::PF;
    }
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut hooks = NoHooks;
    loop {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0, "ADCX result");
    assert!(flag(&cpu, flags::CF), "ADCX carry out sets CF");
    for f in [flags::OF, flags::SF, flags::ZF, flags::AF, flags::PF] {
        assert!(flag(&cpu, f), "ADCX preserves non-CF flags");
    }
}

#[test]
fn adox_updates_only_of() {
    let code = [0xF3, 0x0F, 0x38, 0xF6, 0xC1, 0xF4];
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rax, 0xFFFF_FFFF);
        s.set_reg(Reg::Rcx, 0);
        s.rflags |= flags::OF | flags::CF | flags::SF | flags::ZF | flags::AF | flags::PF;
    }
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut hooks = NoHooks;
    loop {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0, "ADOX result = 0xFFFFFFFF + OF(1)");
    assert!(flag(&cpu, flags::OF), "ADOX carry out sets OF");
    for f in [flags::CF, flags::SF, flags::ZF, flags::AF, flags::PF] {
        assert!(flag(&cpu, f), "ADOX preserves non-OF flags (incl. CF)");
    }
}

#[test]
fn cmpxchg16b_exchange_when_equal() {
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4];
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
    data[8..].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0x1111_2222_3333_4444),
            (Reg::Rdx, 0x5555_6666_7777_8888),
            (Reg::Rbx, 0xAAAA_BBBB_CCCC_DDDD),
            (Reg::Rcx, 0x0102_0304_0506_0708),
        ],
        DATA,
        &data,
    );
    assert!(flag(&cpu, flags::ZF), "CMPXCHG16B ZF=1 on match");
    assert_eq!(&out[..8], &0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes(), "low ← RBX");
    assert_eq!(&out[8..], &0x0102_0304_0506_0708u64.to_le_bytes(), "high ← RCX");
}

#[test]
fn cmpxchg16b_loads_when_not_equal() {
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4];
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    data[8..].copy_from_slice(&0x0BAD_F00D_1234_5678u64.to_le_bytes());
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0),
            (Reg::Rdx, 0),
            (Reg::Rbx, 0x9999),
            (Reg::Rcx, 0x8888),
        ],
        DATA,
        &data,
    );
    assert!(!flag(&cpu, flags::ZF), "CMPXCHG16B ZF=0 on mismatch");
    assert_eq!(rax(&cpu), 0xDEAD_BEEF_CAFE_BABE, "RAX ← mem low");
    assert_eq!(rdx(&cpu), 0x0BAD_F00D_1234_5678, "RDX ← mem high");
    assert_eq!(&out[..8], &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes(), "memory unchanged low");
    assert_eq!(&out[8..], &0x0BAD_F00D_1234_5678u64.to_le_bytes(), "memory unchanged high");
}

#[test]
fn cmpxchg16b_misaligned_faults_gp() {
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_reg(Reg::Rsi, DATA + 8);
    let mut hooks = NoHooks;
    let exit = cpu.step(&mut mem, &mut hooks).unwrap();
    assert_eq!(exit, Exit::Interrupt(13), "misaligned CMPXCHG16B raises #GP");
}

#[test]
fn cmpxchg8b_exchange_when_equal() {
    let code = [0x0F, 0xC7, 0x0E, 0xF4];
    let data = 0x1122_3344_5566_7788u64.to_le_bytes();
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0x5566_7788),
            (Reg::Rdx, 0x1122_3344),
            (Reg::Rbx, 0xAABB_CCDD),
            (Reg::Rcx, 0x0011_2233),
        ],
        DATA,
        &data,
    );
    assert!(flag(&cpu, flags::ZF), "CMPXCHG8B ZF=1 on match");
    assert_eq!(u64::from_le_bytes(out.as_slice().try_into().unwrap()), 0x0011_2233_AABB_CCDD);
}

#[test]
fn f16c_ph2ps_ps2ph_roundtrip() {
    let halfs: u64 = 0x3800_BC00_4000_3C00;
    let code = [
        0xC4, 0xE2, 0x79, 0x13, 0xC1,
        0xC4, 0xE3, 0x79, 0x1D, 0xC2, 0x00,
        0xF4,
    ];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().xmm[1] = halfs as u128;
    let mut hooks = NoHooks;
    loop {
        match cpu.step(&mut mem, &mut hooks).unwrap() {
            Exit::Continue => {}
            Exit::Halted => break,
            other => panic!("{other:?}"),
        }
    }
    let xmm0 = cpu.state().xmm[0];
    let f = |i: usize| f32::from_bits((xmm0 >> (i * 32)) as u32);
    assert_eq!(f(0), 1.0);
    assert_eq!(f(1), 2.0);
    assert_eq!(f(2), -1.0);
    assert_eq!(f(3), 0.5);
    let xmm2 = cpu.state().xmm[2];
    assert_eq!(xmm2 as u64, halfs, "VCVTPS2PH recovers the fp16 patterns");
    assert_eq!(xmm2 >> 64, 0, "VCVTPS2PH zeroes the unused upper lanes");
}

#[test]
fn mmx_write_sets_tag_valid_and_exponent_ones() {
    let code = [
        0x0F, 0x6E, 0xC0,
        0x0F, 0x7E, 0xC3,
        0xF4,
    ];
    let cpu = run_seeded(&code, &[(Reg::Rax, 0xCAFEBABE)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xCAFEBABE, "MMX movd round-trip");
    let x = &cpu.state().x87;
    assert_eq!(x.st[0] as u64, 0xCAFEBABE);
    assert_eq!((x.st[0] >> 64) & 0xFFFF, 0xFFFF, "MMX write sets exp+sign to all 1s");
    assert_eq!(x.tw & 0b11, 0, "MMX write marks the register valid in the tag word");
}

#[test]
fn emms_marks_all_registers_empty() {
    let code = [
        0x0F, 0x6E, 0xC0,
        0x0F, 0x77,
        0xF4,
    ];
    let cpu = run_seeded(&code, &[(Reg::Rax, 0x12345678)], None);
    let x = &cpu.state().x87;
    assert_eq!(x.tw, 0xFFFF, "EMMS empties the whole tag word");
    assert_eq!(x.st[0] as u64, 0x12345678, "EMMS leaves register bytes intact");
}

#[test]
fn mmx_paddb_lanes() {
    let code = [
        0x48, 0x0F, 0x6E, 0xC0,
        0x48, 0x0F, 0x6E, 0xC9,
        0x0F, 0xFC, 0xC1,
        0x48, 0x0F, 0x7E, 0xC3,
        0xF4,
    ];
    let a = 0x0102_0304_0506_0708u64;
    let b = 0x1020_3040_5060_7080u64;
    let cpu = run_seeded(&code, &[(Reg::Rax, a), (Reg::Rcx, b)], None);
    let expect = {
        let mut r = 0u64;
        for i in 0..8 {
            let x = (a >> (i * 8)) as u8;
            let y = (b >> (i * 8)) as u8;
            r |= (x.wrapping_add(y) as u64) << (i * 8);
        }
        r
    };
    assert_eq!(rbx(&cpu), expect, "PADDB byte-wise wrapping add");
}

fn run_smc(code: &[u8]) -> (Interpreter, VirtualMemory, u64, [u64; 2]) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();
    let gen0 = mem.code_generation();
    let page0 = [
        mem.code_page_generation(CODE_BASE),
        mem.code_page_generation(CODE_BASE + 0x1000),
    ];

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    (cpu, mem, gen0, page0)
}

#[test]
fn smc_write_to_own_code_then_execute_takes_effect_and_bumps_gen() {
    let code = [
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x01, 0x00,
        0xC6, 0x40, 0x0C, 0x42,
        0xB3, 0x00,
        0xF4,
    ];
    let (cpu, mem, gen0, [p0, _p1]) = run_smc(&code);
    assert_eq!(rbx(&cpu) & 0xFF, 0x42, "patched immediate must be executed");
    assert_eq!(
        mem.code_generation() - gen0,
        1,
        "exactly one store into executable memory happened in this run"
    );
    assert_eq!(
        mem.code_page_generation(CODE_BASE) - p0,
        1,
        "the patched page's generation advanced once"
    );
}

#[test]
fn smc_cross_page_write_bumps_the_target_page_not_the_writer_page() {
    let target = CODE_BASE + 0x1000 + 0x40;
    let code = [
        0x48, 0xB8,
        target as u8, (target >> 8) as u8, (target >> 16) as u8, (target >> 24) as u8,
        (target >> 32) as u8, (target >> 40) as u8, (target >> 48) as u8, (target >> 56) as u8,
        0xC6, 0x00, 0x90,
        0xF4,
    ];
    let (_, mem, gen0, [p0, p1]) = run_smc(&code);
    assert_eq!(mem.code_generation() - gen0, 1);
    assert_eq!(
        mem.code_page_generation(CODE_BASE) - p0,
        0,
        "the writer's own page was not written to during the run"
    );
    assert_eq!(
        mem.code_page_generation(CODE_BASE + 0x1000) - p1,
        1,
        "the target page's generation advanced"
    );
    assert_eq!(mem.read_u8(target).unwrap(), 0x90, "the byte landed");
}

#[test]
fn smc_rep_movs_into_code_bumps_gen_per_write() {
    let src = CODE_BASE + 0x100;
    let dst = CODE_BASE + 0x200;
    let code = [
        0x48, 0xBE, src as u8, (src >> 8) as u8, (src >> 16) as u8, (src >> 24) as u8,
        (src >> 32) as u8, (src >> 40) as u8, (src >> 48) as u8, (src >> 56) as u8,
        0x48, 0xBF, dst as u8, (dst >> 8) as u8, (dst >> 16) as u8, (dst >> 24) as u8,
        (dst >> 32) as u8, (dst >> 40) as u8, (dst >> 48) as u8, (dst >> 56) as u8,
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00,
        0xF3, 0xA4,
        0xF4,
    ];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    mem.poke(src, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    let gen0 = mem.code_generation();
    let page0 = mem.code_page_generation(dst);

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    assert_eq!(
        &[
            mem.read_u8(dst).unwrap(),
            mem.read_u8(dst + 1).unwrap(),
            mem.read_u8(dst + 2).unwrap(),
            mem.read_u8(dst + 3).unwrap(),
        ],
        &[0xAA, 0xBB, 0xCC, 0xDD],
        "REP MOVSB must copy the bytes into code"
    );
    assert_eq!(mem.code_generation() - gen0, 4);
    assert_eq!(mem.code_page_generation(dst) - page0, 4);
}

#[test]
fn syscall_routes_to_hook_with_context() {
    use exemu_core::hooks::Hooks;
    use exemu_core::{CpuState, Reg, Result};

    struct SyscallSpy {
        index: Option<u32>,
        rcx: u64,
        r11: u64,
    }
    impl Hooks for SyscallSpy {
        fn intercept(&mut self, _: u64, _: &mut CpuState, _: &mut dyn Memory) -> Result<Option<Exit>> {
            Ok(None)
        }
        fn syscall(&mut self, index: u32, cpu: &mut CpuState, _: &mut dyn Memory) -> Result<Exit> {
            self.index = Some(index);
            self.rcx = cpu.reg(Reg::Rcx);
            self.r11 = cpu.reg(Reg::R11);
            cpu.set_reg(Reg::Rax, 0xC000_0001);
            Ok(Exit::Continue)
        }
    }

    let code = [
        0x49, 0x89, 0xCA,
        0xB8, 0x42, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xF4,
    ];
    let syscall_rip = CODE_BASE + 8;
    let ret_rip = CODE_BASE + 10;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(STACK_TOP);
    cpu.state_mut().rflags |= flags::CF;
    let flags_before = cpu.state().rflags;

    let mut spy = SyscallSpy { index: None, rcx: 0, r11: 0 };
    let mut halted = false;
    for _ in 0..100 {
        if let Exit::Halted = cpu.step(&mut mem, &mut spy).unwrap() {
            halted = true;
            break;
        }
    }
    assert!(halted, "guest must reach the hlt after the syscall resumes");

    assert_eq!(spy.index, Some(0x42), "hook must receive the SSDT index (eax)");
    assert_eq!(spy.rcx, ret_rip, "SYSCALL must place the return RIP in RCX");
    assert_eq!(spy.r11, flags_before, "SYSCALL must snapshot RFLAGS into R11");
    assert_eq!(
        cpu.state().reg(Reg::R10),
        0,
        "the stub's mov r10, rcx must have executed before the syscall"
    );
    assert_eq!(cpu.state().rip, ret_rip, "guest resumed at RCX (the byte past the SYSCALL, i.e. the hlt)");
    assert_eq!(cpu.state().reg(Reg::Rax), 0xC000_0001, "handler's NTSTATUS lands in RAX");
    let _ = syscall_rip;
}

#[test]
fn gs_base_is_a_per_thread_state_value() {
    use exemu_core::Reg;

    let teb_a: u64 = 0x0000_7FFF_0000_0000;
    let teb_b: u64 = 0x0000_0033_0000_0000;

    let program: &[u8] = &[
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x65, 0x48, 0x8B, 0x4B, 0x08,
        0x65, 0x48, 0x8B, 0x13,
        0xF4,
    ];

    let run_with_teb = |teb: u64| -> (u64, u64, u64) {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
        mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
        mem.map(Region::new("teb", teb, 0x1000, Perm::RW)).unwrap();
        mem.write(CODE_BASE, program).unwrap();
        mem.write_u64(teb + 0x30, teb).unwrap();
        mem.write_u64(teb, 0xAA).unwrap();
        mem.write_u64(teb + 8, 0xBB).unwrap();

        let mut cpu = Interpreter::new();
        cpu.state_mut().rip = CODE_BASE;
        cpu.state_mut().set_rsp(STACK_TOP);
        cpu.state_mut().gs_base = teb;
        cpu.state_mut().set_reg(Reg::Rbx, 0);

        let mut hooks = NoHooks;
        for _ in 0..100 {
            if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
                break;
            }
        }
        (
            cpu.state().reg(Reg::Rax),
            cpu.state().reg(Reg::Rcx),
            cpu.state().reg(Reg::Rdx),
        )
    };

    let (a_self, a_bb, a_aa) = run_with_teb(teb_a);
    assert_eq!(a_self, teb_a, "gs:[0x30] resolves against thread A's gs base");
    assert_eq!(a_bb, 0xBB, "gs:[rbx+8] under thread A");
    assert_eq!(a_aa, 0xAA, "gs:[rbx] under thread A");

    let (b_self, _, _) = run_with_teb(teb_b);
    assert_eq!(b_self, teb_b, "the same gs:[0x30] reads thread B's TEB under B's gs base");
}

fn run_at_region_tail(code: &[u8], with_neighbour: bool) -> exemu_core::Result<Interpreter> {
    const RGN: u64 = 0x1000;
    let code_end = CODE_BASE + RGN;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, RGN, Perm::RWX)).unwrap();
    if with_neighbour {
        mem.map(Region::new("data", code_end, RGN, Perm::RW)).unwrap();
    }
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();

    let start = code_end - code.len() as u64;
    mem.write(start, code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = start;
    cpu.state_mut().set_rsp(STACK_TOP);

    let mut hooks = NoHooks;
    for _ in 0..1000 {
        match cpu.step(&mut mem, &mut hooks)? {
            Exit::Continue => {}
            Exit::Halted => return Ok(cpu),
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    panic!("program did not halt within the step budget");
}

#[test]
fn instruction_flush_against_the_end_of_a_code_region_still_executes() {
    let code = [0xB8, 0x44, 0x33, 0x22, 0x11, 0xF4];
    let cpu = run_at_region_tail(&code, false).expect("tail instruction must execute");
    assert_eq!(rax(&cpu), 0x1122_3344);

    let cpu = run_at_region_tail(&code, true).expect("tail instruction must execute");
    assert_eq!(rax(&cpu), 0x1122_3344);
}

#[test]
fn long_instruction_in_the_region_tail_decodes_correctly() {
    let code = [
        0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xF4,
    ];
    let cpu = run_at_region_tail(&code, true).expect("tail instruction must execute");
    assert_eq!(rax(&cpu), 0x0123_4567_89AB_CDEF);
}

#[test]
fn instruction_running_off_the_end_of_a_code_region_still_faults() {
    use exemu_core::EmuError;

    const RGN: u64 = 0x1000;
    let code_end = CODE_BASE + RGN;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, RGN, Perm::RWX)).unwrap();
    mem.map(Region::new("data", code_end, RGN, Perm::RW)).unwrap();
    mem.write_u64(code_end, 0xDEAD_BEEF_DEAD_BEEF).unwrap();
    mem.write(code_end - 1, &[0xB8]).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = code_end - 1;
    cpu.state_mut().set_rsp(STACK_TOP);

    let err = cpu
        .step(&mut mem, &mut NoHooks)
        .expect_err("must fault rather than execute the neighbouring region's bytes");
    assert!(
        matches!(err.cause(), EmuError::Permission { .. } | EmuError::Unmapped { .. }),
        "expected a fetch fault, got {err:?}"
    );
    assert_eq!(rax(&cpu), 0);
}
