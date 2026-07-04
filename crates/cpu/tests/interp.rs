//! Interpreter tests driven by hand-assembled x86-64 machine code.
//!
//! Each program is a byte slice loaded at `CODE_BASE`; we run it to a `hlt`
//! and assert on the resulting register state. The comments spell out the
//! encoding so the tests double as documentation of what the decoder must
//! handle.

use exemu_core::cpu::flags;
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;

const CODE_BASE: u64 = 0x1_0000;
const STACK_TOP: u64 = 0x9_0000;

/// Load `code` at `CODE_BASE`, give it a stack, and single-step until the
/// program halts (or we hit a safety cap). Returns the final interpreter.
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
    // mov eax, 5 ; mov ecx, 3 ; add eax, ecx ; hlt
    let code = [
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0xB9, 0x03, 0x00, 0x00, 0x00, // mov ecx, 3
        0x01, 0xC8, // add eax, ecx
        0xF4, // hlt
    ];
    assert_eq!(rax(&run(&code)), 8);
}

#[test]
fn push_pop_roundtrip() {
    // mov rax, 0x1234 ; push rax ; pop rbx ; hlt
    let code = [
        0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x1234
        0x50, // push rax
        0x5B, // pop rbx
        0xF4, // hlt
    ];
    assert_eq!(rbx(&run(&code)), 0x1234);
}

#[test]
fn summation_loop() {
    // xor eax,eax ; mov ecx,10 ; L: add eax,ecx ; dec ecx ; jnz L ; hlt
    let code = [
        0x31, 0xC0, // xor eax, eax
        0xB9, 0x0A, 0x00, 0x00, 0x00, // mov ecx, 10
        0x01, 0xC8, // L: add eax, ecx  (offset 7)
        0xFF, 0xC9, // dec ecx          (offset 9)
        0x75, 0xFA, // jnz L (rel8 -6, from end=13 back to offset 7)
        0xF4, // hlt
    ];
    assert_eq!(rax(&run(&code)), 55); // 10+9+...+1
}

#[test]
fn memory_store_and_load() {
    // mov rax, 0xDEADBEEF ; mov [rsp-8], rax ; mov rbx, [rsp-8] ; hlt
    let code = [
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xDEADBEEF
        0x48, 0x89, 0x44, 0x24, 0xF8, // mov [rsp-8], rax
        0x48, 0x8B, 0x5C, 0x24, 0xF8, // mov rbx, [rsp-8]
        0xF4, // hlt
    ];
    assert_eq!(rbx(&run(&code)), 0xDEAD_BEEF);
}

#[test]
fn call_and_ret() {
    // call +3 (to the mov) ; hlt ; mov eax,42 ; ret  ... but simpler:
    //   call target ; hlt ; target: mov eax, 7 ; ret
    // Layout (offsets from CODE_BASE):
    //   0: E8 06 00 00 00   call +6  -> target at 0x0B
    //   5: F4               hlt
    //   6: 90 90 90 90 90   padding (nops)  -- not reached
    //   B: B8 07 00 00 00   mov eax, 7
    //  10: C3               ret  (returns to offset 5 = hlt)
    let code = [
        0xE8, 0x06, 0x00, 0x00, 0x00, // call +6
        0xF4, // hlt
        0x90, 0x90, 0x90, 0x90, 0x90, // padding
        0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
        0xC3, // ret
    ];
    assert_eq!(rax(&run(&code)), 7);
}

#[test]
fn signed_compare_setcc() {
    // mov eax, -1 ; cmp eax, 1 ; setl bl ; movzx eax, bl ; hlt  → eax = 1
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1
        0x83, 0xF8, 0x01, // cmp eax, 1
        0x0F, 0x9C, 0xC3, // setl bl
        0x0F, 0xB6, 0xC3, // movzx eax, bl
        0xF4, // hlt
    ];
    assert_eq!(rax(&run(&code)), 1);
}

#[test]
fn imul_and_flags() {
    // mov eax, 6 ; imul eax, eax, 7 ; hlt → eax = 42
    let code = [
        0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6
        0x6B, 0xC0, 0x07, // imul eax, eax, 7
        0xF4, // hlt
    ];
    assert_eq!(rax(&run(&code)), 42);
}

#[test]
fn div_unsigned() {
    // mov eax, 100 ; xor edx,edx ; mov ecx, 7 ; div ecx ; hlt
    // → eax = 14 (quotient), edx = 2 (remainder)
    let code = [
        0xB8, 0x64, 0x00, 0x00, 0x00, // mov eax, 100
        0x31, 0xD2, // xor edx, edx
        0xB9, 0x07, 0x00, 0x00, 0x00, // mov ecx, 7
        0xF7, 0xF1, // div ecx
        0xF4, // hlt
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 14);
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rdx), 2);
}

#[test]
fn shift_left_sets_result() {
    // mov eax, 1 ; shl eax, 4 ; hlt → eax = 16
    let code = [
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xC1, 0xE0, 0x04, // shl eax, 4
        0xF4, // hlt
    ];
    assert_eq!(rax(&run(&code)), 16);
}

#[test]
fn rep_stosb_fills_memory() {
    // Fill 4 bytes at [rdi] with 0xAB using rep stosb.
    //   mov al, 0xAB ; mov rdi, STACK ; mov rcx, 4 ; rep stosb ; hlt
    let stack_addr = 0x8_1000u64;
    let code = [
        0xB0, 0xAB, // mov al, 0xAB
        0x48, 0xBF, // mov rdi, imm64
        (stack_addr & 0xff) as u8,
        (stack_addr >> 8) as u8,
        (stack_addr >> 16) as u8,
        (stack_addr >> 24) as u8,
        0, 0, 0, 0,
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xF3, 0xAA, // rep stosb
        0xF4, // hlt
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
    // mov eax,0x12345678 ; mov ebx,0x9ABCDEF0 ; shld eax,ebx,8 ; hlt
    // eax = (eax<<8) | (ebx>>24) = 0x3456789A
    let code = [
        0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0xBB, 0xF0, 0xDE, 0xBC, 0x9A, // mov ebx, 0x9ABCDEF0
        0x0F, 0xA4, 0xD8, 0x08, // shld eax, ebx, 8
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x3456_789A);
}

#[test]
fn bt_imm_sets_carry_and_setcc() {
    // mov eax,0x100 ; bt eax,8 ; setc bl ; movzx eax,bl ; hlt → eax=1
    let code = [
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x0F, 0xBA, 0xE0, 0x08, // bt eax, 8
        0x0F, 0x92, 0xC3, // setc bl
        0x0F, 0xB6, 0xC3, // movzx eax, bl
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 1);
}

#[test]
fn bsf_finds_lowest_set_bit() {
    // mov eax,0x10 ; bsf eax,eax ; hlt → eax=4
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
        0x0F, 0xBC, 0xC0, // bsf eax, eax
        0xF4,
    ];
    assert_eq!(rax(&run(&code)), 4);
}

#[test]
fn bswap_reverses_bytes() {
    // mov eax,0x11223344 ; bswap eax ; hlt → eax=0x44332211
    let code = [
        0xB8, 0x44, 0x33, 0x22, 0x11, // mov eax, 0x11223344
        0x0F, 0xC8, // bswap eax
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x4433_2211);
}

#[test]
fn overflow_flag_on_signed_add() {
    // mov eax, 0x7FFFFFFF ; add eax, 1 ; hlt → OF set, SF set
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0x7F, // mov eax, 0x7FFFFFFF
        0x83, 0xC0, 0x01, // add eax, 1
        0xF4, // hlt
    ];
    let cpu = run(&code);
    assert!(cpu.state().flag(flags::OF), "overflow flag should be set");
    assert!(cpu.state().flag(flags::SF), "sign flag should be set");
}

#[test]
fn popcnt_counts_set_bits() {
    // mov eax, 0xF0F ; popcnt ebx, eax ; hlt  → 8 set bits, ZF clear
    let code = [
        0xB8, 0x0F, 0x0F, 0x00, 0x00, // mov eax, 0x0F0F
        0xF3, 0x0F, 0xB8, 0xD8, // popcnt ebx, eax
        0xF4, // hlt
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 8);
    assert!(!cpu.state().flag(flags::ZF));
}

#[test]
fn popcnt_zero_sets_zf() {
    // mov eax, 0 ; popcnt ebx, eax ; hlt  → 0, ZF set
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0xF3, 0x0F, 0xB8, 0xD8, // popcnt ebx, eax
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 0);
    assert!(cpu.state().flag(flags::ZF));
}

#[test]
fn tzcnt_trailing_zeros() {
    // mov eax, 0x10 ; tzcnt ebx, eax ; hlt  → 4, CF clear
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
        0xF3, 0x0F, 0xBC, 0xD8, // tzcnt ebx, eax
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 4);
    assert!(!cpu.state().flag(flags::CF));
    assert!(!cpu.state().flag(flags::ZF));
}

#[test]
fn tzcnt_zero_is_width_and_sets_cf() {
    // mov eax, 0 ; tzcnt ebx, eax ; hlt  → 32 (operand width), CF set
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0xF3, 0x0F, 0xBC, 0xD8, // tzcnt ebx, eax
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 32);
    assert!(cpu.state().flag(flags::CF));
}

#[test]
fn lzcnt_leading_zeros() {
    // mov eax, 0xFF ; lzcnt ebx, eax ; hlt  → 24 (32-bit operand), CF clear
    let code = [
        0xB8, 0xFF, 0x00, 0x00, 0x00, // mov eax, 0xFF
        0xF3, 0x0F, 0xBD, 0xD8, // lzcnt ebx, eax
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu), 24);
    assert!(!cpu.state().flag(flags::CF));
}

#[test]
fn bsf_without_f3_still_works() {
    // mov eax, 0x10 ; bsf ebx, eax ; hlt  → index 4
    let code = [
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
        0x0F, 0xBC, 0xD8, // bsf ebx, eax
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
    // xor eax,eax ; cpuid ; hlt  → EBX="Genu" ECX="ntel" EDX="ineI"
    let code = [
        0x31, 0xC0, // xor eax, eax
        0x0F, 0xA2, // cpuid
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rbx(&cpu) as u32, 0x756e_6547); // "Genu"
    assert_eq!(rcx(&cpu) as u32, 0x6c65_746e); // "ntel"
    assert_eq!(rdx(&cpu) as u32, 0x4965_6e69); // "ineI"
    assert_eq!(rax(&cpu) as u32, 7); // max standard leaf
}

#[test]
fn cpuid_advertises_sse2_but_not_avx() {
    // mov eax,1 ; cpuid ; hlt
    let code = [
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x0F, 0xA2, // cpuid
        0xF4,
    ];
    let cpu = run(&code);
    let edx = rdx(&cpu) as u32;
    let ecx = rcx(&cpu) as u32;
    assert!(edx & (1 << 26) != 0, "SSE2 (EDX.26) must be set");
    assert!(edx & (1 << 25) != 0, "SSE (EDX.25) must be set");
    assert!(ecx & (1 << 23) != 0, "POPCNT (ECX.23) must be set");
    assert!(ecx & (1 << 28) == 0, "AVX (ECX.28) must NOT be advertised");
    assert!(ecx & (1 << 26) == 0, "XSAVE (ECX.26) must NOT be advertised");
    // Three-byte SSSE3/SSE4 escapes are not decoded, so those bits stay off.
    assert!(ecx & (1 << 9) == 0, "SSSE3 (ECX.9) must NOT be advertised");
    assert!(ecx & (1 << 20) == 0, "SSE4.2 (ECX.20) must NOT be advertised");
}

#[test]
fn rdtsc_is_monotonic() {
    // rdtsc ; mov ecx,eax ; rdtsc ; sub eax,ecx ; hlt  → second read > first
    let code = [
        0x0F, 0x31, // rdtsc
        0x89, 0xC1, // mov ecx, eax
        0x0F, 0x31, // rdtsc
        0x29, 0xC8, // sub eax, ecx
        0xF4,
    ];
    let cpu = run(&code);
    assert!(rax(&cpu) as u32 > 0, "TSC must advance between reads");
}

#[test]
fn movbe_load_byteswaps_from_memory() {
    // mov dword [rsp-8], 0x11223344 ; movbe eax, [rsp-8] ; hlt → 0x44332211
    let code = [
        0xC7, 0x44, 0x24, 0xF8, 0x44, 0x33, 0x22, 0x11, // mov dword [rsp-8], 0x11223344
        0x0F, 0x38, 0xF0, 0x44, 0x24, 0xF8, // movbe eax, [rsp-8]
        0xF4,
    ];
    assert_eq!(rax(&run(&code)) & 0xffff_ffff, 0x4433_2211);
}

#[test]
fn movbe_store_byteswaps_to_memory() {
    // mov eax, 0xAABBCCDD ; movbe [rsp-8], eax ; mov ebx, [rsp-8] ; hlt
    // stored bytes are reversed → reloaded value is 0xDDCCBBAA
    let code = [
        0xB8, 0xDD, 0xCC, 0xBB, 0xAA, // mov eax, 0xAABBCCDD
        0x0F, 0x38, 0xF1, 0x44, 0x24, 0xF8, // movbe [rsp-8], eax
        0x8B, 0x5C, 0x24, 0xF8, // mov ebx, [rsp-8]
        0xF4,
    ];
    assert_eq!(rbx(&run(&code)) & 0xffff_ffff, 0xDDCC_BBAA);
}
