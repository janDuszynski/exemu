//! 32-bit (protected-mode / IA-32) interpreter tests.
//!
//! These exercise the mode-specific decode paths: `0x40..=0x4F` as
//! `inc`/`dec` (not REX), 4-byte push/pop and call/ret, and absolute
//! `disp32` addressing instead of RIP-relative.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};

const CODE: u64 = 0x0040_0000;
const DATA: u64 = 0x0050_0000;
// Stack region is [0x10_0000, 0x11_0000); start esp at the top.
const STACK_TOP: u64 = 0x0011_0000;

fn run32(code: &[u8], setup: impl FnOnce(&mut Interpreter, &mut VirtualMemory)) -> (Interpreter, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1_0000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x0010_0000, 0x1_0000, Perm::RW)).unwrap();
    mem.write(CODE, code).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_rsp(STACK_TOP);
    setup(&mut cpu, &mut mem);

    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    (cpu, mem)
}

use exemu_memory::VirtualMemory;

fn eax(cpu: &Interpreter) -> u64 {
    cpu.state().gpr_read(0, 4)
}

#[test]
fn inc_is_not_rex_in_32bit() {
    // mov eax,5 ; mov ecx,3 ; add eax,ecx ; inc eax ; hlt  → eax = 9
    let code = [
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0xB9, 0x03, 0x00, 0x00, 0x00, // mov ecx, 3
        0x01, 0xC8, // add eax, ecx
        0x40, // inc eax  (REX in 64-bit, INC in 32-bit)
        0xF4, // hlt
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 9);
}

#[test]
fn dec_opcode_0x48() {
    // mov eax, 10 ; dec eax ; dec eax ; hlt  → eax = 8
    let code = [
        0xB8, 0x0A, 0x00, 0x00, 0x00, // mov eax, 10
        0x48, // dec eax
        0x48, // dec eax
        0xF4,
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 8);
}

#[test]
fn push_pop_is_four_bytes() {
    // push 0x1234 ; pop eax ; hlt — verify esp moved by 4, value preserved
    let code = [
        0x68, 0x34, 0x12, 0x00, 0x00, // push 0x1234
        0x58, // pop eax
        0xF4,
    ];
    let (cpu, _) = run32(&code, |_, _| {});
    assert_eq!(eax(&cpu), 0x1234);
    assert_eq!(cpu.state().rsp(), STACK_TOP, "esp should be balanced");
}

#[test]
fn call_ret_uses_4byte_return_address() {
    //   0: E8 06 00 00 00   call +6  → target at 0x0B (CODE+0xB)
    //   5: F4               hlt
    //   6: 90*5             padding
    //   B: B8 07 00 00 00   mov eax, 7
    //  10: C3               ret
    let code = [
        0xE8, 0x06, 0x00, 0x00, 0x00, 0xF4, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0x07, 0x00, 0x00,
        0x00, 0xC3,
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 7);
}

#[test]
fn absolute_disp32_addressing() {
    // In 32-bit mode `mov eax, [disp32]` is absolute, not RIP-relative.
    // mov dword [DATA], 0xCAFE ; mov eax, [DATA] ; hlt
    let d = DATA as u32;
    let code = [
        // mov dword [DATA], 0x0000CAFE  (C7 05 <disp32> <imm32>)
        0xC7, 0x05, (d & 0xff) as u8, (d >> 8) as u8, (d >> 16) as u8, (d >> 24) as u8,
        0xFE, 0xCA, 0x00, 0x00,
        // mov eax, [DATA]  (8B 05 <disp32>)
        0x8B, 0x05, (d & 0xff) as u8, (d >> 8) as u8, (d >> 16) as u8, (d >> 24) as u8,
        0xF4,
    ];
    let (cpu, _) = run32(&code, |_, _| {});
    assert_eq!(eax(&cpu), 0xCAFE);
}
