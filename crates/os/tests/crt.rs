//! Tests for the emulated C-runtime shims, driven through the public
//! `Hooks::intercept` entry point exactly as the interpreter would call it.

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const DATA: u64 = 0x4000;
const STACK: u64 = 0x9000;
const RET_ADDR: u64 = 0x1_2345;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x1000, Perm::RW)).unwrap();
    // Heap arena the OS bump-allocates from.
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        echo: false,
        ..WinConfig::default()
    });
    (os, mem)
}

/// Register a msvcrt thunk, seat a return address on the stack, then invoke
/// the API through intercept. Returns the value left in RAX.
fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str) -> u64 {
    let thunk = os.resolve_import("msvcrt.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue));
    // The shim should have `ret`ed back to the caller.
    assert_eq!(cpu.rip, RET_ADDR, "shim did not return to caller");
    assert_eq!(cpu.rsp(), STACK + 8, "stack not unwound by ret");
    cpu.reg(Reg::Rax)
}

#[test]
fn memset_fills() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, DATA); // dest
    cpu.set_reg(Reg::Rdx, 0xAB); // fill byte
    cpu.set_reg(Reg::R8, 8); // count
    let rax = call(&mut os, &mut mem, &mut cpu, "memset");
    assert_eq!(rax, DATA, "memset returns dest");
    assert_eq!(mem.read_u64(DATA).unwrap(), 0xABAB_ABAB_ABAB_ABAB);
}

#[test]
fn memcpy_copies() {
    let (mut os, mut mem) = setup();
    mem.write_u64(DATA, 0x1122_3344_5566_7788).unwrap();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, DATA + 0x100); // dest
    cpu.set_reg(Reg::Rdx, DATA); // src
    cpu.set_reg(Reg::R8, 8); // n
    let rax = call(&mut os, &mut mem, &mut cpu, "memcpy");
    assert_eq!(rax, DATA + 0x100);
    assert_eq!(mem.read_u64(DATA + 0x100).unwrap(), 0x1122_3344_5566_7788);
}

#[test]
fn strlen_counts() {
    let (mut os, mut mem) = setup();
    mem.write(DATA, b"hello\0").unwrap();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, DATA);
    let rax = call(&mut os, &mut mem, &mut cpu, "strlen");
    assert_eq!(rax, 5);
}

#[test]
fn malloc_returns_heap_pointer() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 128);
    let p = call(&mut os, &mut mem, &mut cpu, "malloc");
    assert!((0x2_0000_0000..0x2_0001_0000).contains(&p), "pointer {p:#x} not in heap arena");
    // The returned block is usable memory.
    mem.write_u64(p, 0xdead_beef).unwrap();
    assert_eq!(mem.read_u64(p).unwrap(), 0xdead_beef);
}

#[test]
fn exit_terminates_process() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 7); // exit code
    let thunk = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("exit".into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, &mut cpu, &mut mem).unwrap();
    assert_eq!(exit, Some(Exit::ProcessExit(7)));
}
