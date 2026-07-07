//! Tests for the MSVC 32-bit C++ SEH frame prolog helper (`__EH_prolog`),
//! driven through the public `Hooks::intercept` entry point exactly as the
//! interpreter would call it. See `api.rs::eh_prolog`.

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_cpu::FS_BASE_32;
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// A 32-bit stack slot `S` with room below it for the 12-byte SEH frame, and a
// TEB mapped at FS_BASE_32 whose first DWORD is the ExceptionList head (fs:[0]).
const STACK_BASE: u64 = 0x0018_0000;
const STACK_SIZE: u64 = 0x1000;
const S: u64 = 0x0018_0800; // esp at __EH_prolog entry

const RETADDR: u32 = 0x0041_2233; // return address into the caller
const SCOPETABLE: u32 = 0x0040_9000; // eax at entry (handler/scopetable ptr)
const CALLER_EBP: u32 = 0x0018_0C00; // ebp at entry
const OLD_HEAD: u32 = 0xDEAD_BEEF; // previous fs:[0] SEH frame head

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x7000_0000, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", FS_BASE_32, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x1000_0000, 0x1_0000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: false,
        api_base: 0x7000_0000,
        heap_base: 0x1000_0000,
        heap_size: 0x1_0000,
        echo: false,
        ..WinConfig::default()
    });
    (os, mem)
}

/// Seat the documented entry state and invoke `__EH_prolog` via `intercept`.
fn run_prolog(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState) {
    cpu.set_rsp(S);
    cpu.gpr_write(Reg::Rax as u8, 4, SCOPETABLE as u64); // eax = scopetable
    cpu.gpr_write(Reg::Rbp as u8, 4, CALLER_EBP as u64); // ebp = caller_ebp
    mem.write_u32(S, RETADDR).unwrap(); // [esp] = return address
    mem.write_u32(FS_BASE_32, OLD_HEAD).unwrap(); // fs:[0] = old head

    let thunk = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("_EH_prolog".into()));
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    // The handler drives rip/rsp itself and returns Resume → Continue.
    assert_eq!(exit, Some(Exit::Continue));
}

#[test]
fn eh_prolog_builds_seh_frame() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    run_prolog(&mut os, &mut mem, &mut cpu);

    // Frame written on the stack.
    assert_eq!(mem.read_u32(S - 4).unwrap(), 0xFFFF_FFFF, "trylevel = -1");
    assert_eq!(mem.read_u32(S - 8).unwrap(), SCOPETABLE, "scopetable slot");
    assert_eq!(mem.read_u32(S - 12).unwrap(), OLD_HEAD, "prev SEH head slot");
    assert_eq!(mem.read_u32(S).unwrap(), CALLER_EBP, "retaddr slot repurposed to saved ebp");

    // New linked state.
    assert_eq!(mem.read_u32(FS_BASE_32).unwrap() as u64, S - 12, "fs:[0] = S-12");
    assert_eq!(cpu.gpr_read(Reg::Rbp as u8, 4), S, "ebp = S");
    assert_eq!(cpu.rsp() & 0xFFFF_FFFF, S - 12, "esp = S-12");
    assert_eq!(cpu.rip, RETADDR as u64, "returned to caller");
    // eax must NOT be clobbered to 0 (the old no-op stub bug).
    assert_eq!(cpu.gpr_read(Reg::Rax as u8, 4), SCOPETABLE as u64, "eax preserved");
}

/// The classic `__EH_prolog` pairs with an *inline* epilog (no helper call).
/// Emulate that epilog here to prove the frame the prolog builds is a proper,
/// reversible SEH registration: it restores fs:[0], ebp and esp to the values
/// a normal ebp frame would, and returns to the function's own caller.
#[test]
fn eh_prolog_frame_round_trips_via_inline_epilog() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // The function's own return address lives at [ebp+4] == [S+4].
    const FUNC_RET: u32 = 0x0041_9ABC;
    mem.write_u32(S + 4, FUNC_RET).unwrap();

    run_prolog(&mut os, &mut mem, &mut cpu);

    // Inline epilog the compiler emits:
    //   mov ecx, [ebp-0Ch] ; mov fs:[0], ecx  (unlink SEH)
    //   mov esp, ebp                            (drop locals)
    //   pop ebp                                 (restore caller ebp)
    //   ret                                     (return to caller)
    let ebp = cpu.gpr_read(Reg::Rbp as u8, 4);
    let prev_head = mem.read_u32(ebp - 12).unwrap();
    mem.write_u32(FS_BASE_32, prev_head).unwrap();
    let mut esp = ebp;
    let saved_ebp = mem.read_u32(esp).unwrap();
    esp += 4;
    cpu.gpr_write(Reg::Rbp as u8, 4, saved_ebp as u64);
    let ret_ip = mem.read_u32(esp).unwrap();
    esp += 4;
    cpu.set_rsp(esp);
    cpu.rip = ret_ip as u64;

    // Back to the caller's original view.
    assert_eq!(mem.read_u32(FS_BASE_32).unwrap(), OLD_HEAD, "fs:[0] restored");
    assert_eq!(cpu.gpr_read(Reg::Rbp as u8, 4), CALLER_EBP as u64, "ebp restored");
    assert_eq!(cpu.rip, FUNC_RET as u64, "returned to function's caller");
    assert_eq!(cpu.rsp() & 0xFFFF_FFFF, S + 8, "esp unwound past the frame");
}
