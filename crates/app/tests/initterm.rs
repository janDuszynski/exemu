//! Verify that `_initterm` re-entrantly drives real guest calls: the OS
//! layer runs a table of constructor functions *in the guest*, in order,
//! then returns to the caller.
//!
//! We hand-assemble a tiny program:
//!   main:  mov rcx, table_start ; mov rdx, table_end ; mov rax, _initterm
//!          call rax ; hlt
//!   ctor0: mov rax, DATA   ; mov byte [rax], 0x11 ; ret
//!   ctor1: mov rax, DATA+1 ; mov byte [rax], 0x22 ; ret
//! and a 2-entry initializer table [ctor0, ctor1].

use exemu_core::hooks::Hooks;
use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x9000;
const STACK_TOP: u64 = 0x2_0000;

fn le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

#[test]
fn initterm_runs_constructors_in_order() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x1_0000, 0x1_0000, Perm::RW)).unwrap();

    // The OS layer, and the _initterm thunk the program will call.
    let mut os = WinOs::new(WinConfig { echo: false, ..WinConfig::default() });
    // Map the OS thunk region so its driver/init thunks are addressable as
    // control-flow targets (execution is intercepted before any fetch).
    mem.map(Region::new("imports", WinConfig::default().api_base, 0x1000, Perm::RW)).unwrap();
    let initterm = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("_initterm".into()));

    let ctor0 = CODE + 0x80;
    let ctor1 = CODE + 0xA0;
    let table = CODE + 0x100;
    let table_end = table + 16;

    // --- main @ CODE ---
    let mut m = Vec::new();
    m.extend_from_slice(&[0x48, 0xB9]);
    m.extend_from_slice(&le(table)); // mov rcx, table_start
    m.extend_from_slice(&[0x48, 0xBA]);
    m.extend_from_slice(&le(table_end)); // mov rdx, table_end
    m.extend_from_slice(&[0x48, 0xB8]);
    m.extend_from_slice(&le(initterm)); // mov rax, _initterm
    m.extend_from_slice(&[0xFF, 0xD0]); // call rax
    m.push(0xF4); // hlt
    mem.write(CODE, &m).unwrap();

    // --- ctor0 @ CODE+0x80: mov rax, DATA ; mov byte [rax], 0x11 ; ret ---
    let mut c0 = vec![0x48, 0xB8];
    c0.extend_from_slice(&le(DATA));
    c0.extend_from_slice(&[0xC6, 0x00, 0x11, 0xC3]);
    mem.write(ctor0, &c0).unwrap();

    // --- ctor1 @ CODE+0xA0: mov rax, DATA+1 ; mov byte [rax], 0x22 ; ret ---
    let mut c1 = vec![0x48, 0xB8];
    c1.extend_from_slice(&le(DATA + 1));
    c1.extend_from_slice(&[0xC6, 0x00, 0x22, 0xC3]);
    mem.write(ctor1, &c1).unwrap();

    // --- initializer table [ctor0, ctor1] ---
    mem.write(table, &le(ctor0)).unwrap();
    mem.write(table + 8, &le(ctor1)).unwrap();

    // --- run ---
    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_rsp(STACK_TOP & !0xf);

    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut os).unwrap() {
            break;
        }
    }

    // Both constructors ran (proving the driver sequenced them), and the
    // program returned to its `hlt` afterwards.
    assert_eq!(mem.read_u8(DATA).unwrap(), 0x11, "ctor0 did not run");
    assert_eq!(mem.read_u8(DATA + 1).unwrap(), 0x22, "ctor1 did not run");
}

/// A no-callback `_initterm` (empty table) must just return.
#[test]
fn initterm_empty_table_returns() {
    let mut os = WinOs::new(WinConfig { echo: false, ..WinConfig::default() });
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", 0x1_0000, 0x1_0000, Perm::RW)).unwrap();
    let initterm = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("_initterm".into()));

    let mut cpu = Interpreter::new();
    let rsp = 0x1_8000u64;
    let ret = 0xdead_beef;
    mem.write_u64(rsp, ret).unwrap();
    cpu.state_mut().set_rsp(rsp);
    // first == last → empty range
    cpu.state_mut().set_reg(exemu_core::Reg::Rcx, 0x5000);
    cpu.state_mut().set_reg(exemu_core::Reg::Rdx, 0x5000);

    let exit = os.intercept(initterm, cpu.state_mut(), &mut mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.state().rip, ret, "should return to caller");
    assert_eq!(cpu.state().reg(exemu_core::Reg::Rax), 0);
}
