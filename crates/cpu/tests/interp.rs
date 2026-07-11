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
    assert_eq!(rax(&cpu) as u32, 0xD); // max standard leaf (0xD = XSAVE enumeration)
}

#[test]
fn cpuid_advertises_sse2_ssse3_sse4_avx() {
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
    // XSAVE + OSXSAVE are advertised now that FXSAVE/XSAVE/XGETBV/XSETBV are
    // implemented and oracle-clean (roadmap W1.2).
    assert!(ecx & (1 << 26) != 0, "XSAVE (ECX.26) must be advertised");
    assert!(ecx & (1 << 27) != 0, "OSXSAVE (ECX.27) must be advertised");
    // The three-byte SSSE3/SSE4.1/SSE4.2 escapes are implemented and oracle-
    // clean (roadmap W1.4), so those bits are advertised. AVX (ECX.28) is ON
    // after the VEX decoder + YMM register file landed (roadmap W1.5).
    assert!(ecx & (1 << 9) != 0, "SSSE3 (ECX.9) must be advertised (W1.4)");
    assert!(ecx & (1 << 19) != 0, "SSE4.1 (ECX.19) must be advertised (W1.4)");
    assert!(ecx & (1 << 20) != 0, "SSE4.2 (ECX.20) must be advertised (W1.4)");
    assert!(ecx & (1 << 28) != 0, "AVX (ECX.28) must be advertised (W1.5)");
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

// ---- Differential-oracle regression tests (roadmap P0.4) -------------------
//
// Each of these encodes a case the P0.1 Unicorn oracle flagged as an exemu vs
// real-x86 divergence, so the fixes cannot silently regress under CI (which
// does not build the Unicorn-gated oracle itself).

fn flag(cpu: &Interpreter, mask: u64) -> bool {
    cpu.state().flag(mask)
}

#[test]
fn imul_two_op_negative_no_overflow_clears_cf_of() {
    // mov eax, -1 ; imul eax, eax ; hlt  →  (-1)*(-1) = 1, fits → CF=OF=0.
    // The sign-vs-zero-extension bug set CF/OF here (0xffffffff read as +4e9).
    let code = [
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, 0xFFFFFFFF (-1)
        0x0F, 0xAF, 0xC0, // imul eax, eax
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 1);
    assert!(!flag(&cpu, flags::CF), "CF must be clear (no overflow)");
    assert!(!flag(&cpu, flags::OF), "OF must be clear (no overflow)");
}

#[test]
fn imul_one_op_signed_high_half() {
    // mov eax, -2 ; mov ecx, 3 ; imul ecx ; hlt  →  edx:eax = -6.
    // The zero-extension bug corrupted the high half (edx) for negatives.
    let code = [
        0xB8, 0xFE, 0xFF, 0xFF, 0xFF, // mov eax, -2
        0xB9, 0x03, 0x00, 0x00, 0x00, // mov ecx, 3
        0xF7, 0xE9, // imul ecx  (F7 /5)
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0xFFFF_FFFA); // -6 low
    assert_eq!(rdx(&cpu) & 0xffff_ffff, 0xFFFF_FFFF); // -6 high (sign)
    assert!(!flag(&cpu, flags::CF));
    assert!(!flag(&cpu, flags::OF));
}

#[test]
fn idiv_negative_divisor() {
    // mov eax,-6 ; cdq ; mov ecx,-3 ; idiv ecx ; hlt  →  q=2, r=0.
    // The divisor sign-extension bug made -3 read as a huge positive.
    let code = [
        0xB8, 0xFA, 0xFF, 0xFF, 0xFF, // mov eax, -6
        0x99, // cdq (edx = sign of eax)
        0xB9, 0xFD, 0xFF, 0xFF, 0xFF, // mov ecx, -3
        0xF7, 0xF9, // idiv ecx  (F7 /7)
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 2); // quotient
    assert_eq!(rdx(&cpu) & 0xffff_ffff, 0); // remainder
}

#[test]
fn rcl_by_one_sets_overflow() {
    // mov eax, 0x80000000 ; rcl eax,1 ; hlt.  CF starts 0.
    // MSB(1) rotates into CF; result 0, CF=1, OF = MSB(res) XOR CF = 1.
    // Previously OF was left untouched (the RCL/RCR arm never set it).
    let code = [
        0xB8, 0x00, 0x00, 0x00, 0x80, // mov eax, 0x80000000
        0xD1, 0xD0, // rcl eax, 1  (D1 /2)
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0);
    assert!(flag(&cpu, flags::CF), "CF = old MSB = 1");
    assert!(flag(&cpu, flags::OF), "OF = MSB(result) XOR CF = 1");
}

#[test]
fn cmov_not_taken_zero_extends() {
    // mov rax,-1 ; cmovb eax, ecx (CF=0 → not taken) ; hlt.
    // A 32-bit CMOV zero-extends the destination even when not taken.
    let code = [
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, -1 (all ones)
        0x0F, 0x42, 0xC1, // cmovb eax, ecx
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0x0000_0000_FFFF_FFFF, "upper 32 bits must be cleared");
}

#[test]
fn cmpxchg_equal_zero_extends_accumulator() {
    // mov rax, 0x1_00000000 ; mov ecx,0 ; mov edx,5 ; cmpxchg ecx, edx ; hlt.
    // eax(low32)=0 == ecx=0 → equal → ecx=edx=5, and eax zero-extends to 0.
    let code = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, 0x100000000
        0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
        0xBA, 0x05, 0x00, 0x00, 0x00, // mov edx, 5
        0x0F, 0xB1, 0xD1, // cmpxchg ecx, edx
        0xF4,
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0, "accumulator upper 32 bits must be cleared");
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 5, "destination updated on equal");
}

#[test]
fn rdtscp_ecx_zero_and_tsc_monotonic() {
    // RDTSCP (0F 01 F9): EDX:EAX = TSC, ECX = IA32_TSC_AUX (processor id = 0).
    // Two back-to-back calls must return a strictly increasing TSC, confirming
    // that the counter advances and that all 3 encoding bytes are consumed.
    //
    // Byte layout (total 9 bytes before hlt):
    //   0F 01 F9          rdtscp          (3 bytes — low32→EAX, high32→EDX, ECX=0)
    //   89 C3             mov ebx, eax    (2 bytes — save first TSC low-32)
    //   0F 01 F9          rdtscp          (3 bytes — second read, overwrites EAX/EDX/ECX)
    //   F4                hlt             (1 byte)
    let code = [
        0x0F, 0x01, 0xF9, // rdtscp  (first read)
        0x89, 0xC3, // mov ebx, eax  (stash first low-32 in EBX)
        0x0F, 0x01, 0xF9, // rdtscp  (second read)
        0xF4, // hlt
    ];
    let cpu = run(&code);
    // ECX must be IA32_TSC_AUX = 0 (single-vCPU emulator reports processor 0).
    assert_eq!(rcx(&cpu) as u32, 0, "ECX (IA32_TSC_AUX) must be 0");
    // Second TSC low-32 must be strictly greater than the first.
    let first_low = rbx(&cpu) as u32;
    let second_low = rax(&cpu) as u32;
    assert!(
        second_low > first_low,
        "TSC must be monotonically increasing: first={first_low} second={second_low}"
    );
    // RIP must point at the hlt byte, proving all three bytes of each RDTSCP
    // were consumed.  HLT surfaces as Exit::Halted without advancing rip, so
    // rip stops at CODE_BASE + 8 (3 + 2 + 3 bytes consumed before the hlt).
    assert_eq!(cpu.state().rip, CODE_BASE + 8, "rip must advance past all 3 RDTSCP bytes");
}

#[test]
fn pause_is_nop() {
    // F3 90 = PAUSE.  PAUSE is a no-op hint with no architectural side effects;
    // it takes the r==0 NOP path in the 0x90..=0x97 arm intentionally.
    // After PAUSE + HLT the GPRs must be unchanged and rip advanced by exactly
    // 2 bytes (F3 prefix + 90 opcode) for PAUSE, plus 1 for HLT.
    //
    //   F3 90   pause   (2 bytes — rep prefix consumed, r=0 → NOP)
    //   F4      hlt     (1 byte)
    let code = [
        0xF3, 0x90, // pause
        0xF4, // hlt
    ];
    let cpu = run(&code);
    assert_eq!(rax(&cpu), 0, "RAX must be unchanged by PAUSE");
    assert_eq!(rbx(&cpu), 0, "RBX must be unchanged by PAUSE");
    assert_eq!(rcx(&cpu), 0, "RCX must be unchanged by PAUSE");
    assert_eq!(rdx(&cpu), 0, "RDX must be unchanged by PAUSE");
    // RIP must be CODE_BASE + 2: PAUSE consumed 2 bytes (F3 prefix + 90
    // opcode), then HLT at offset 2 fires without advancing rip further.
    assert_eq!(
        cpu.state().rip,
        CODE_BASE + 2,
        "rip must advance past PAUSE (2 bytes); HLT stops without advancing rip"
    );
}

// ============================================================================
// W1.6 — BMI1/BMI2/ADX/CMPXCHG16B/F16C + MMX-x87 aliasing pins.
//
// Each carries the *reason* it exists — many pin behavior where the differential
// oracle's Unicorn/QEMU-TCG reference is wrong or absent (documented per test),
// so the correct (Intel SDM) semantics cannot regress under CI even though the
// oracle can't check them.
// ============================================================================

use exemu_core::Reg;

/// Run `code` after seeding the 16 GPRs from `regs` (indexed by exemu register
/// order) and optionally seeding 16 bytes of a scratch data page at `DATA`.
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

/// Like `run_seeded` but returns both the interpreter and the final data page so
/// memory-writing ops (CMPXCHG8B/16B) can be asserted.
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

// ---- BMI1 ANDN -------------------------------------------------------------

#[test]
fn andn_result_and_flags() {
    // andn ecx, ebx, edx  (VEX.NDS.LZ.0F38.W0 F2 /r): ecx = ~ebx & edx.
    // ebx=0x0F0F0F0F, edx=0xFFFFFFFF → ~ebx&edx = 0xF0F0F0F0 (msb set → SF=1).
    let code = [0xC4, 0xE2, 0x60, 0xF2, 0xCA, 0xF4]; // vvvv=ebx(3), reg=ecx(1), rm=edx(2)
    let cpu = run_seeded(&code, &[(Reg::Rbx, 0x0F0F_0F0F), (Reg::Rdx, 0xFFFF_FFFF)], None);
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0xF0F0_F0F0);
    assert!(flag(&cpu, flags::SF), "ANDN sets SF from result msb");
    assert!(!flag(&cpu, flags::ZF), "ANDN ZF clear (result nonzero)");
    assert!(!flag(&cpu, flags::CF), "ANDN clears CF");
    assert!(!flag(&cpu, flags::OF), "ANDN clears OF");
}

// ---- BMI1 BLSI/BLSR/BLSMSK (CF pinned — QEMU BLSI CF is wrong) --------------

#[test]
fn blsi_extracts_lowest_set_bit_and_cf() {
    // blsi ebx, ecx (VEX.NDD.LZ.0F38.W0 F3 /3): ebx = (-ecx) & ecx.
    // The oracle EXCLUDES BLSI's CF because this QEMU build reports it wrong; the
    // SDM sets CF = (src != 0), pinned here.
    // ecx = 0b10110000 (0xB0) → lowest set bit = 0x10.
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xD9, 0xF4]; // vvvv=ebx(3), /3, rm=ecx(1)
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0x10);
    assert!(flag(&cpu, flags::CF), "BLSI CF = (src != 0) per SDM");
    assert!(!flag(&cpu, flags::ZF), "BLSI ZF from result");

    // src == 0 → result 0, CF = 0, ZF = 1.
    let cpu0 = run_seeded(&code, &[(Reg::Rcx, 0)], None);
    assert_eq!(rbx(&cpu0) & 0xffff_ffff, 0);
    assert!(!flag(&cpu0, flags::CF), "BLSI CF = 0 when src == 0");
    assert!(flag(&cpu0, flags::ZF), "BLSI ZF = 1 when result 0");
}

#[test]
fn blsr_clears_lowest_set_bit() {
    // blsr ebx, ecx (F3 /1): ebx = ecx & (ecx-1); CF = (ecx == 0).
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xC9, 0xF4]; // vvvv=ebx(3), /1, rm=ecx(1)
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xA0); // cleared the 0x10 bit
    assert!(!flag(&cpu, flags::CF), "BLSR CF = (src == 0) = 0 here");
}

#[test]
fn blsmsk_masks_up_to_lowest_set_bit_zf_clear() {
    // blsmsk ebx, ecx (F3 /2): ebx = (ecx-1) ^ ecx; ZF forced 0; CF=(src==0).
    let code = [0xC4, 0xE2, 0x60, 0xF3, 0xD1, 0xF4]; // vvvv=ebx(3), /2, rm=ecx(1)
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0xB0)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0x1F); // mask bits 0..=4
    assert!(!flag(&cpu, flags::ZF), "BLSMSK forces ZF = 0");
    assert!(!flag(&cpu, flags::CF), "BLSMSK CF = (src == 0) = 0 here");
}

// ---- BMI1 BEXTR (over-length pinned — QEMU mis-clamps) ----------------------

#[test]
fn bextr_extracts_field_and_overlength_passthrough() {
    // bextr ecx, edx, ebx (0F38.W0 F7): start = ebx[7:0], len = ebx[15:8].
    // edx = 0xDEADBEEF, start=4, len=8 → (edx>>4)&0xFF = 0xEE.
    let code = [0xC4, 0xE2, 0x60, 0xF7, 0xCA, 0xF4]; // reg=ecx(1), vvvv=ebx(3), rm=edx(2)
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0xDEAD_BEEF), (Reg::Rbx, 0x08_04)], None);
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0xEE);
    assert!(!flag(&cpu, flags::ZF), "BEXTR ZF from result");

    // Over-length (len >= opsize): the whole shifted source passes through — the
    // case the oracle avoids because QEMU wrongly clamps and drops the top bit.
    // 64-bit: start=0, len=200 → result = full src.
    let code64 = [0xC4, 0xE2, 0xE0, 0xF7, 0xCA, 0xF4]; // W1 (64-bit), vvvv=rbx, rm=rdx
    let cpu64 = run_seeded(&code64, &[(Reg::Rdx, 0x8000_0000_0000_0001), (Reg::Rbx, 200 << 8)], None);
    assert_eq!(rcx(&cpu64), 0x8000_0000_0000_0001, "BEXTR len>=opsize returns full source");

    // Exact boundary regression (32-bit start=0, len==opsize==32): the top bit
    // must survive — result = full 32-bit source. This is the precise case the
    // oracle found QEMU dropping bit 31 on (0xD445608C -> 0x5445608C); exemu is
    // SDM-correct. Control ebx = start(0) | len(32<<8) = 0x2000.
    let code32 = [0xC4, 0xE2, 0x60, 0xF7, 0xCA, 0xF4]; // ecx, edx, ebx (32-bit)
    let cpu32 = run_seeded(&code32, &[(Reg::Rdx, 0xD445_608C), (Reg::Rbx, 32 << 8)], None);
    assert_eq!(rcx(&cpu32) & 0xffff_ffff, 0xD445_608C, "BEXTR len==opsize keeps bit 31");
}

// ---- BMI2 MULX (flag-preserving) -------------------------------------------

#[test]
fn mulx_flag_preserving_and_product() {
    // mulx ebx, ecx, edx (VEX.NDD.LZ.F2.0F38.W0 F6): {ebx:ecx} = edx * eDX(rdx).
    // reg=ebx (high), vvvv=ecx (low), rm=edx (source); implicit multiplicand rdx.
    // rdx = 0x1_0000_0002, but 32-bit uses edx=0x2; src edx = 0x2. Wait — for a
    // 32-bit MULX the multiplicand is EDX. Set edx = 0xFFFF_FFFF (also the source
    // == rm == edx), so product = 0xFFFF_FFFF * 0xFFFF_FFFF.
    let code = [0xC4, 0xE2, 0x73, 0xF6, 0xDA, 0xF4]; // reg=ebx(3), vvvv=ecx(1), rm=edx(2)
    // Seed all arithmetic flags set so we can prove MULX preserves them.
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
    // 0xFFFF_FFFF^2 = 0xFFFF_FFFE_0000_0001 → low = 0x0000_0001, high = 0xFFFF_FFFE.
    assert_eq!(rcx(&cpu) & 0xffff_ffff, 0x0000_0001, "MULX low half → vvvv");
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xFFFF_FFFE, "MULX high half → reg");
    for f in [flags::CF, flags::OF, flags::SF, flags::ZF, flags::AF, flags::PF] {
        assert!(flag(&cpu, f), "MULX preserves every status flag");
    }
}

// ---- BMI2 PDEP / PEXT ------------------------------------------------------

#[test]
fn pdep_pext_roundtrip() {
    // pdep ebx, ecx, edx (F2.0F38.W0 F5): deposit low bits of ecx into mask edx.
    // ecx = 0b111, mask edx = 0b10101 → deposit → 0b10101.
    let code = [0xC4, 0xE2, 0x73, 0xF5, 0xDA, 0xF4]; // reg=ebx(3), vvvv=ecx(1), rm=edx(2)
    let cpu = run_seeded(&code, &[(Reg::Rcx, 0b111), (Reg::Rdx, 0b10101)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0b10101);

    // pext ebx, ecx, edx (F3.0F38.W0 F5): extract masked bits of ecx, packed low.
    let code2 = [0xC4, 0xE2, 0x72, 0xF5, 0xDA, 0xF4]; // pp=F3
    let cpu2 = run_seeded(&code2, &[(Reg::Rcx, 0b10101), (Reg::Rdx, 0b10101)], None);
    assert_eq!(rbx(&cpu2) & 0xffff_ffff, 0b111, "PEXT packs the 3 masked bits low");
}

// ---- BMI2 BZHI (CF boundary pinned — QEMU off-by-one) ----------------------

#[test]
fn bzhi_zero_high_and_cf_boundary() {
    // bzhi ebx, edx, ecx (0F38.W0 F5, pp=none): zero bits [31:idx] of edx; idx=ecx[7:0].
    // edx=0xFFFFFFFF, idx=8 → keep low 8 bits = 0xFF. CF = (idx > 31) = 0.
    let code = [0xC4, 0xE2, 0x70, 0xF5, 0xDA, 0xF4]; // reg=ebx(3), vvvv=ecx(1), rm=edx(2)
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 8)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xFF);
    assert!(!flag(&cpu, flags::CF), "BZHI CF=0 when idx <= opsize-1");

    // idx == opsize-1 (31): keep low 31 bits, CF still 0 (31 > 31 is false).
    let cpu31 = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 31)], None);
    assert_eq!(rbx(&cpu31) & 0xffff_ffff, 0x7FFF_FFFF);
    assert!(!flag(&cpu31, flags::CF), "BZHI CF=0 at idx == opsize-1 (SDM: N > opsize-1)");

    // idx >= opsize (32): pass through unchanged, CF = 1.
    let cpu32 = run_seeded(&code, &[(Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 40)], None);
    assert_eq!(rbx(&cpu32) & 0xffff_ffff, 0xFFFF_FFFF, "BZHI idx>=opsize passes source through");
    assert!(flag(&cpu32, flags::CF), "BZHI CF=1 when idx >= opsize");
}

// ---- BMI2 RORX (no flags) --------------------------------------------------

#[test]
fn rorx_rotates_without_touching_flags() {
    // rorx ebx, ecx, 4 (VEX.LZ.F2.0F3A.W0 F0 /r ib): ebx = ror(ecx, 4). No flags.
    let code = [0xC4, 0xE3, 0x7B, 0xF0, 0xD9, 0x04, 0xF4]; // reg=ebx(3), rm=ecx(1), imm=4
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

// ---- BMI2 SARX/SHLX/SHRX (flag-untouched shifts) ---------------------------

#[test]
fn sarx_shlx_shrx_flag_untouched() {
    // sarx ebx, edx, ecx (VEX.LZ.F3.0F38.W0 F7): ebx = edx >>a (ecx & 31). No flags.
    let code = [0xC4, 0xE2, 0x72, 0xF7, 0xDA, 0xF4]; // reg=ebx(3), vvvv=ecx(1), rm=edx(2)
    let cpu = run_seeded(&code, &[(Reg::Rdx, 0x8000_0000), (Reg::Rcx, 4)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xF800_0000, "SARX arithmetic shift keeps sign");

    // shlx (66), shrx (F2).
    let shlx = [0xC4, 0xE2, 0x71, 0xF7, 0xDA, 0xF4];
    let cpu_l = run_seeded(&shlx, &[(Reg::Rdx, 0x1), (Reg::Rcx, 5)], None);
    assert_eq!(rcx(&cpu_l) & 0xffff_ffff, 5); // ecx unchanged
    assert_eq!(rbx(&cpu_l) & 0xffff_ffff, 0x20, "SHLX shift left");
    let shrx = [0xC4, 0xE2, 0x73, 0xF7, 0xDA, 0xF4];
    let cpu_r = run_seeded(&shrx, &[(Reg::Rdx, 0x8000_0000), (Reg::Rcx, 4)], None);
    assert_eq!(rbx(&cpu_r) & 0xffff_ffff, 0x0800_0000, "SHRX logical shift right");
}

// ---- BMI 32-bit zero-extension (QEMU reference doesn't; SDM/exemu do) -------

#[test]
fn bmi_32bit_result_zero_extends_upper() {
    // In 64-bit mode a W0 (32-bit) BMI op MUST zero the upper 32 bits of the
    // destination — the property the oracle's Unicorn build fails to honor, so it
    // is pinned here. andn ecx, ebx, edx with a destination pre-seeded nonzero.
    let code = [0xC4, 0xE2, 0x60, 0xF2, 0xCA, 0xF4];
    let cpu = run_seeded(
        &code,
        &[(Reg::Rbx, 0), (Reg::Rdx, 0xFFFF_FFFF), (Reg::Rcx, 0xDEAD_BEEF_0000_0000)],
        None,
    );
    // ~0 & 0xFFFF_FFFF = 0xFFFF_FFFF, zero-extended → upper 32 cleared.
    assert_eq!(rcx(&cpu), 0x0000_0000_FFFF_FFFF, "32-bit BMI zero-extends the upper half");
}

// ---- ADX ADCX / ADOX (isolated-carry, flag-preserving) ---------------------

#[test]
fn adcx_updates_only_cf() {
    // adcx eax, ecx (66 0F38 F6): eax = eax + ecx + CF; only CF changes.
    // Seed OF/SF/ZF/AF/PF set, CF set; eax=0xFFFF_FFFF, ecx=1 → sum=0 with carry.
    let code = [0x66, 0x0F, 0x38, 0xF6, 0xC1, 0xF4]; // reg=eax(0), rm=ecx(1)
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rax, 0xFFFF_FFFF);
        s.set_reg(Reg::Rcx, 0);
        // CF=1 (added), and OF/SF/ZF/AF/PF all set to prove preservation.
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
    // 0xFFFF_FFFF + 0 + CF(1) = 0x1_0000_0000 → 32-bit result 0, CF out = 1.
    assert_eq!(rax(&cpu) & 0xffff_ffff, 0, "ADCX result");
    assert!(flag(&cpu, flags::CF), "ADCX carry out sets CF");
    // Every other flag preserved (they were all set).
    for f in [flags::OF, flags::SF, flags::ZF, flags::AF, flags::PF] {
        assert!(flag(&cpu, f), "ADCX preserves non-CF flags");
    }
}

#[test]
fn adox_updates_only_of() {
    // adox eax, ecx (F3 0F38 F6): eax = eax + ecx + OF; only OF changes.
    let code = [0xF3, 0x0F, 0x38, 0xF6, 0xC1, 0xF4];
    let mut cpu = Interpreter::new();
    {
        let s = cpu.state_mut();
        s.rip = CODE_BASE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rax, 0xFFFF_FFFF);
        s.set_reg(Reg::Rcx, 0);
        // OF=1 (the carry-in for ADOX). CF/SF/ZF/AF/PF set → must be preserved.
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

// ---- CMPXCHG16B (equal + not-equal + alignment #GP) ------------------------

#[test]
fn cmpxchg16b_exchange_when_equal() {
    // REX.W 0F C7 /1 [rsi]. RDX:RAX = mem → ZF=1, mem = RCX:RBX.
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4]; // /1, rm=rsi(6)
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes()); // low = RAX
    data[8..].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes()); // high = RDX
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0x1111_2222_3333_4444),
            (Reg::Rdx, 0x5555_6666_7777_8888),
            (Reg::Rbx, 0xAAAA_BBBB_CCCC_DDDD), // store low
            (Reg::Rcx, 0x0102_0304_0506_0708), // store high
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
    // Mismatch → ZF=0, RDX:RAX loaded from memory, memory unchanged.
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4];
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    data[8..].copy_from_slice(&0x0BAD_F00D_1234_5678u64.to_le_bytes());
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0), // != mem low
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
    // A non-16-byte-aligned operand must raise #GP(0) — Interrupt(13).
    let code = [0x48, 0x0F, 0xC7, 0x0E, 0xF4];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_reg(Reg::Rsi, DATA + 8); // 8-byte aligned but NOT 16
    let mut hooks = NoHooks;
    let exit = cpu.step(&mut mem, &mut hooks).unwrap();
    assert_eq!(exit, Exit::Interrupt(13), "misaligned CMPXCHG16B raises #GP");
}

// ---- CMPXCHG8B (32-bit-mode form still works in 64-bit default) -------------

#[test]
fn cmpxchg8b_exchange_when_equal() {
    // 0F C7 /1 [rsi] (no REX.W): EDX:EAX vs m64; on match ZF=1, m64 = ECX:EBX.
    let code = [0x0F, 0xC7, 0x0E, 0xF4];
    let data = 0x1122_3344_5566_7788u64.to_le_bytes(); // low32=EAX cmp, high32=EDX cmp
    let (cpu, out) = run_seeded_mem(
        &code,
        &[
            (Reg::Rsi, DATA),
            (Reg::Rax, 0x5566_7788), // EAX = mem[31:0]
            (Reg::Rdx, 0x1122_3344), // EDX = mem[63:32]
            (Reg::Rbx, 0xAABB_CCDD), // store low
            (Reg::Rcx, 0x0011_2233), // store high
        ],
        DATA,
        &data,
    );
    assert!(flag(&cpu, flags::ZF), "CMPXCHG8B ZF=1 on match");
    assert_eq!(u64::from_le_bytes(out.as_slice().try_into().unwrap()), 0x0011_2233_AABB_CCDD);
}

// ---- F16C VCVTPH2PS / VCVTPS2PH (behaviorally verified; QEMU lacks F16C) -----

#[test]
fn f16c_ph2ps_ps2ph_roundtrip() {
    // The linked Unicorn build does not implement F16C, so these are pinned here.
    // Put four fp16 values in xmm1's low 64 bits, convert up, convert back down.
    // 1.0 = 0x3C00, 2.0 = 0x4000, -1.0 = 0xBC00, 0.5 = 0x3800.
    let halfs: u64 = 0x3800_BC00_4000_3C00;
    // vcvtph2ps xmm0, xmm1 (VEX.128.66.0F38.W0 13 /r): xmm0 = 4×fp32.
    // vcvtps2ph xmm2, xmm0, 0 (VEX.128.66.0F3A.W0 1D /r ib): xmm2 = 4×fp16.
    let code = [
        0xC4, 0xE2, 0x79, 0x13, 0xC1, // vcvtph2ps xmm0, xmm1
        0xC4, 0xE3, 0x79, 0x1D, 0xC2, 0x00, // vcvtps2ph xmm2, xmm0, 0
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
    // xmm0 = the four fp32 values.
    let xmm0 = cpu.state().xmm[0];
    let f = |i: usize| f32::from_bits((xmm0 >> (i * 32)) as u32);
    assert_eq!(f(0), 1.0);
    assert_eq!(f(1), 2.0);
    assert_eq!(f(2), -1.0);
    assert_eq!(f(3), 0.5);
    // Round-trip back to fp16 recovers the exact half bit patterns (upper 64 zero).
    let xmm2 = cpu.state().xmm[2];
    assert_eq!(xmm2 as u64, halfs, "VCVTPS2PH recovers the fp16 patterns");
    assert_eq!(xmm2 >> 64, 0, "VCVTPS2PH zeroes the unused upper lanes");
}

// ---- MMX / x87 aliasing + tag-word interaction ------------------------------

#[test]
fn mmx_write_sets_tag_valid_and_exponent_ones() {
    // A bare-form MMX write aliases the low 64 bits of physical x87 register 0
    // (MM0), sets its exponent+sign bits (64:79) to all 1s, and marks it valid
    // in the tag word — the W1.1 tag-word interaction. movq mm0, mm1 after
    // seeding mm1 via movd.
    // movd mm0, eax (0F 6E C0), then read back with movd ebx, mm0 (0F 7E C3).
    let code = [
        0x0F, 0x6E, 0xC0, // movd mm0, eax
        0x0F, 0x7E, 0xC3, // movd ebx, mm0
        0xF4,
    ];
    let cpu = run_seeded(&code, &[(Reg::Rax, 0xCAFEBABE)], None);
    assert_eq!(rbx(&cpu) & 0xffff_ffff, 0xCAFEBABE, "MMX movd round-trip");
    let x = &cpu.state().x87;
    // MM0 aliases physical st[0]; its low 64 = the value, bits 64:79 = 0xFFFF.
    assert_eq!(x.st[0] as u64, 0xCAFEBABE);
    assert_eq!((x.st[0] >> 64) & 0xFFFF, 0xFFFF, "MMX write sets exp+sign to all 1s");
    // Tag word: physical register 0 marked valid (bits 0..2 == 00).
    assert_eq!(x.tw & 0b11, 0, "MMX write marks the register valid in the tag word");
}

#[test]
fn emms_marks_all_registers_empty() {
    // EMMS (0F 77) sets the tag word to 0xFFFF (all empty) without touching the
    // register contents.
    let code = [
        0x0F, 0x6E, 0xC0, // movd mm0, eax  (marks MM0 valid)
        0x0F, 0x77, // emms
        0xF4,
    ];
    let cpu = run_seeded(&code, &[(Reg::Rax, 0x12345678)], None);
    let x = &cpu.state().x87;
    assert_eq!(x.tw, 0xFFFF, "EMMS empties the whole tag word");
    // The stored value survives EMMS (only the tag word changes).
    assert_eq!(x.st[0] as u64, 0x12345678, "EMMS leaves register bytes intact");
}

#[test]
fn mmx_paddb_lanes() {
    // paddb mm0, mm1 (0F FC): byte-wise wrapping add. Seed both via movq from GP.
    // movq mm0, rax ; movq mm1, rcx ; paddb mm0, mm1 ; movq rbx, mm0.
    let code = [
        0x48, 0x0F, 0x6E, 0xC0, // movq mm0, rax  (REX.W 0F 6E)
        0x48, 0x0F, 0x6E, 0xC9, // movq mm1, rcx
        0x0F, 0xFC, 0xC1, // paddb mm0, mm1
        0x48, 0x0F, 0x7E, 0xC3, // movq rbx, mm0
        0xF4,
    ];
    // 0x01_02_03_04_05_06_07_08 + 0x10_20_30_40_50_60_70_80 (byte lanes).
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

// --- self-modifying-code detection + decode-cache invalidation (W1.7) ------
//
// The interpreter decodes fresh every step, so SMC already produces correct
// results (the P0.6 pin in sse.rs proves that). These pins prove the *seam*
// the W8 JIT will consume: a write into executable memory (a) still executes
// with the patched bytes, and (b) advances the code-generation counters so a
// cache can invalidate. Data writes must NOT advance the counters.

/// Run `code` in an RWX code region big enough to span pages, plus a stack.
/// Returns the interpreter and the memory (so a test can read the generation
/// counters). The generation is snapshotted *after* the initial code load so
/// that only the program's own writes are measured.
/// Baselines are the global code generation and the per-page generation of the
/// two code pages, captured *after* the initial code load (loading code into an
/// RWX region is itself a code write, so tests measure deltas from here).
fn run_smc(code: &[u8]) -> (Interpreter, VirtualMemory, u64, [u64; 2]) {
    let mut mem = VirtualMemory::new();
    // Two code pages so the cross-page pin has somewhere to reach.
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
    // Offsets from CODE_BASE:
    //   0x00  48 C7 C0 00 00 01 00   mov rax, 0x1_0000 (CODE_BASE)
    //   0x07  C6 40 0C 42            mov byte [rax+0x0C], 0x42
    //   0x0B  B3 00                  mov bl, 0x00   (imm8 lives at 0x0C)
    //   0x0D  F4                     hlt
    // The store patches offset 0x0C — the imm8 of `mov bl` — before it runs.
    let code = [
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x01, 0x00, // mov rax, CODE_BASE
        0xC6, 0x40, 0x0C, 0x42, // mov byte [rax+0x0C], 0x42
        0xB3, 0x00, // mov bl, 0x00  (imm8 @ 0x0C, patched above)
        0xF4, // hlt
    ];
    let (cpu, mem, gen0, [p0, _p1]) = run_smc(&code);
    assert_eq!(rbx(&cpu) & 0xFF, 0x42, "patched immediate must be executed");
    // The one self-modifying store advances the global generation by exactly 1
    // and the writer/target page's generation by exactly 1 (measured as deltas
    // from the post-load baseline, since loading the code itself is a code write).
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
    // The writer lives in page 0 (CODE_BASE); it stores into page 1
    // (CODE_BASE+0x1000), which is still executable. The seam must credit the
    // *written* page, not the page the store instruction sits in.
    let target = CODE_BASE + 0x1000 + 0x40;
    let code = [
        // mov rax, target
        0x48, 0xB8,
        target as u8, (target >> 8) as u8, (target >> 16) as u8, (target >> 24) as u8,
        (target >> 32) as u8, (target >> 40) as u8, (target >> 48) as u8, (target >> 56) as u8,
        0xC6, 0x00, 0x90, // mov byte [rax], 0x90 (NOP) into page 1
        0xF4, // hlt
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
    // REP MOVSB copying 4 bytes from a data buffer into executable memory must
    // (a) land the bytes and (b) advance the global generation once per byte
    // written (each MOVSB is a distinct 1-byte store into exec memory).
    // Source buffer at CODE_BASE+0x100 (0xAA 0xBB 0xCC 0xDD), dest CODE_BASE+0x200.
    let src = CODE_BASE + 0x100;
    let dst = CODE_BASE + 0x200;
    let code = [
        // mov rsi, src
        0x48, 0xBE, src as u8, (src >> 8) as u8, (src >> 16) as u8, (src >> 24) as u8,
        (src >> 32) as u8, (src >> 40) as u8, (src >> 48) as u8, (src >> 56) as u8,
        // mov rdi, dst
        0x48, 0xBF, dst as u8, (dst >> 8) as u8, (dst >> 16) as u8, (dst >> 24) as u8,
        (dst >> 32) as u8, (dst >> 40) as u8, (dst >> 48) as u8, (dst >> 56) as u8,
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xF3, 0xA4, // rep movsb
        0xF4, // hlt
    ];
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, &code).unwrap();
    // Seed the source with `poke` so it does not itself count as a code write —
    // we want the run's own MOVSB stores to be the only measured bumps.
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
    // 4 one-byte stores into exec memory → 4 generation bumps (deltas from the
    // post-load baseline). The source read is a read, so it does not count; the
    // poke above went through the loader path, which *does* count — but we
    // snapshot after it, so only the MOVSB stores are measured here.
    assert_eq!(mem.code_generation() - gen0, 4);
    assert_eq!(mem.code_page_generation(dst) - page0, 4);
}
