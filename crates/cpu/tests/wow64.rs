//! WoW64 CS-based mode switch (roadmap W5.2).
//!
//! A far *indirect* jump (`FF /5`, `m16:32`) loads `[offset, selector]` from
//! memory. exemu has no GDT — it models Wine's flat WoW64 selectors, so the CS
//! selector alone picks the operating mode: `0x33` (GDT index 6) → 64-bit long
//! mode, `0x23` (index 4) → 32-bit compatibility mode. This is the mechanism
//! `wow64cpu!BTCpuSimulate` uses to drop from 64-bit Wine code into a 32-bit
//! guest (and back), recovered from the pinned `wow64cpu.dll`.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x0040_0000;
const DATA: u64 = 0x0050_0000;

/// A mapped interpreter in `bits` with `rip` at `CODE` and a `FF /5 [rAX]` far
/// jump (`FF 28`) whose far pointer at `DATA` is `[offset32, selector16]`.
fn far_jmp(bits: Bits, offset: u32, selector: u16) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE, &[0xFF, 0x28]).unwrap(); // jmp far [rax] / [eax]
    mem.write_u32(DATA, offset).unwrap();
    mem.write_u16(DATA + 4, selector).unwrap();

    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_reg(Reg::Rax, DATA); // the operand pointer

    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).expect("far jmp executes");
    cpu
}

#[test]
fn far_jmp_to_cs_0x33_switches_to_64bit() {
    let cpu = far_jmp(Bits::B32, 0x0000_1234, 0x33);
    assert_eq!(cpu.bits(), Bits::B64, "CS=0x33 (index 6) → 64-bit long mode");
    assert_eq!(cpu.state().rip, 0x1234, "rip = the far offset");
}

#[test]
fn far_jmp_to_cs_0x23_switches_to_32bit() {
    let cpu = far_jmp(Bits::B64, 0x0040_5678, 0x23);
    assert_eq!(cpu.bits(), Bits::B32, "CS=0x23 (index 4) → 32-bit compat mode");
    assert_eq!(cpu.state().rip, 0x0040_5678, "rip = the far offset");
}

#[test]
fn far_jmp_within_64bit_stays_64bit() {
    // A far jump that keeps CS=0x33 stays in long mode (a plain far branch).
    let cpu = far_jmp(Bits::B64, 0x0040_1000, 0x33);
    assert_eq!(cpu.bits(), Bits::B64);
    assert_eq!(cpu.state().rip, 0x0040_1000);
}

/// `iretq` is BTCpuSimulate's *other* forward path (full-context restore): it
/// pops RIP/CS/RFLAGS/RSP/SS, and the popped CS selector switches the mode.
fn iretq(cs: u64) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    let sp = 0x9000;
    mem.write(CODE, &[0x48, 0xCF]).unwrap(); // iretq (REX.W + CF)
    mem.write_u64(sp, 0x0040_1234).unwrap(); // RIP
    mem.write_u64(sp + 8, cs).unwrap(); // CS
    mem.write_u64(sp + 16, 0x202).unwrap(); // RFLAGS
    mem.write_u64(sp + 24, 0x0041_0000).unwrap(); // RSP
    mem.write_u64(sp + 32, 0x2b).unwrap(); // SS

    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_rsp(sp);
    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).expect("iretq executes");
    cpu
}

#[test]
fn iretq_to_cs_0x23_restores_32bit_context() {
    let cpu = iretq(0x23);
    assert_eq!(cpu.bits(), Bits::B32, "popped CS=0x23 → 32-bit compat mode");
    assert_eq!(cpu.state().rip, 0x0040_1234, "rip = popped RIP");
    assert_eq!(cpu.state().rsp(), 0x0041_0000, "rsp = popped RSP");
}

#[test]
fn iretq_to_cs_0x33_stays_64bit() {
    let cpu = iretq(0x33);
    assert_eq!(cpu.bits(), Bits::B64, "popped CS=0x33 → 64-bit long mode");
    assert_eq!(cpu.state().rip, 0x0040_1234);
}
