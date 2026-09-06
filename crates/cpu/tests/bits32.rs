use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};

const CODE: u64 = 0x0040_0000;
const DATA: u64 = 0x0050_0000;
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
    let code = [
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0xB9, 0x03, 0x00, 0x00, 0x00,
        0x01, 0xC8,
        0x40,
        0xF4,
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 9);
}

#[test]
fn dec_opcode_0x48() {
    let code = [
        0xB8, 0x0A, 0x00, 0x00, 0x00,
        0x48,
        0x48,
        0xF4,
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 8);
}

#[test]
fn push_pop_is_four_bytes() {
    let code = [
        0x68, 0x34, 0x12, 0x00, 0x00,
        0x58,
        0xF4,
    ];
    let (cpu, _) = run32(&code, |_, _| {});
    assert_eq!(eax(&cpu), 0x1234);
    assert_eq!(cpu.state().rsp(), STACK_TOP, "esp should be balanced");
}

#[test]
fn call_ret_uses_4byte_return_address() {
    let code = [
        0xE8, 0x06, 0x00, 0x00, 0x00, 0xF4, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0x07, 0x00, 0x00,
        0x00, 0xC3,
    ];
    assert_eq!(eax(&run32(&code, |_, _| {}).0), 7);
}

#[test]
fn absolute_disp32_addressing() {
    let d = DATA as u32;
    let code = [
        0xC7, 0x05, (d & 0xff) as u8, (d >> 8) as u8, (d >> 16) as u8, (d >> 24) as u8,
        0xFE, 0xCA, 0x00, 0x00,
        0x8B, 0x05, (d & 0xff) as u8, (d >> 8) as u8, (d >> 16) as u8, (d >> 24) as u8,
        0xF4,
    ];
    let (cpu, _) = run32(&code, |_, _| {});
    assert_eq!(eax(&cpu), 0xCAFE);
}
