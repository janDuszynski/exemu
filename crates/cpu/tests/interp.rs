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
