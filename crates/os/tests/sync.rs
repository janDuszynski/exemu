//! Tests for the Win32 event/sync primitive stubs (roadmap P3.6), driven
//! through the public `Hooks::intercept` seam exactly as the interpreter
//! would. These are stubs (no real signaling state — we run single-threaded),
//! but they must (a) hand back a NON-NULL handle from CreateEvent so the guest
//! does not null-deref the result, and (b) declare the correct 32-bit stdcall
//! argc so the callee-cleans-up stack stays balanced. A regression to the old
//! argc-0 `Unsupported` stub would leak esp and return NULL — the exact fault
//! that stalled the Firefox installer.

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// A 32-bit stack, an imports (thunk) region and a heap region.
const STACK_BASE: u64 = 0x0018_0000;
const STACK_SIZE: u64 = 0x1000;
const ESP: u64 = 0x0018_0800; // esp at API entry ([esp] = return address)
const RETADDR: u32 = 0x0041_2233;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x7000_0000, 0x1000, Perm::RW)).unwrap();
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

/// Seat `name` as a kernel32 thunk, push a return address and `argc` dummy
/// stack arguments, invoke intercept, and assert stdcall stack cleanup removed
/// exactly `argc` DWORDs (proving the declared argc). Returns the value in EAX.
fn call_stdcall(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    cpu: &mut CpuState,
    name: &str,
    argc: u64,
) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(ESP);
    mem.write_u32(ESP, RETADDR).unwrap(); // [esp] = return address
    for i in 0..argc {
        mem.write_u32(ESP + 4 + i * 4, 0).unwrap(); // dummy DWORD args
    }
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "{name}: intercept should Continue");
    assert_eq!(cpu.rip, RETADDR as u64, "{name}: shim must ret to caller");
    // stdcall: callee pops the return address AND its `argc` DWORD arguments.
    assert_eq!(
        cpu.rsp() & 0xFFFF_FFFF,
        ESP + 4 + argc * 4,
        "{name}: stdcall stack cleanup must match argc {argc}"
    );
    cpu.gpr_read(Reg::Rax as u8, 4)
}

#[test]
fn create_event_returns_non_null_handle_with_argc_4() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName) — 4.
    let h_a = call_stdcall(&mut os, &mut mem, &mut cpu, "CreateEventA", 4);
    assert_ne!(h_a, 0, "CreateEventA must return a NON-NULL event handle");

    let h_w = call_stdcall(&mut os, &mut mem, &mut cpu, "CreateEventW", 4);
    assert_ne!(h_w, 0, "CreateEventW must return a NON-NULL event handle");
}

#[test]
fn set_reset_event_return_true_with_argc_1() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // SetEvent(hEvent) / ResetEvent(hEvent) — BOOL, one handle arg.
    assert_eq!(
        call_stdcall(&mut os, &mut mem, &mut cpu, "SetEvent", 1),
        1,
        "SetEvent must return TRUE"
    );
    assert_eq!(
        call_stdcall(&mut os, &mut mem, &mut cpu, "ResetEvent", 1),
        1,
        "ResetEvent must return TRUE"
    );
    assert_eq!(
        call_stdcall(&mut os, &mut mem, &mut cpu, "PulseEvent", 1),
        1,
        "PulseEvent must return TRUE"
    );
}

#[test]
fn close_handle_accepts_event_handle() {
    // Closing the event handle CreateEvent handed back must succeed (TRUE) and
    // not misroute through the file-handle path.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    let h = call_stdcall(&mut os, &mut mem, &mut cpu, "CreateEventA", 4);
    assert_ne!(h, 0);

    cpu.set_rsp(ESP);
    mem.write_u32(ESP, RETADDR).unwrap();
    mem.write_u32(ESP + 4, h as u32).unwrap();
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CloseHandle".into()));
    cpu.rip = thunk;
    os.intercept(thunk, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.gpr_read(Reg::Rax as u8, 4), 1, "CloseHandle(event) must return TRUE");
}

#[test]
fn wait_for_single_object_returns_wait_object_0() {
    // A single-threaded wait must not hang: report WAIT_OBJECT_0 (0). Also
    // proves the 2-DWORD stdcall footprint stays balanced.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    assert_eq!(
        call_stdcall(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", 2),
        0,
        "WaitForSingleObject must return WAIT_OBJECT_0"
    );
    assert_eq!(
        call_stdcall(&mut os, &mut mem, &mut cpu, "WaitForMultipleObjects", 4),
        0,
        "WaitForMultipleObjects must return WAIT_OBJECT_0"
    );
}
