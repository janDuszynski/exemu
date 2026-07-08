//! Tests for the Win32 synchronization objects (roadmap P3.6), driven through
//! the public `Hooks::intercept` seam exactly as the interpreter would.
//!
//! These now exercise *real* signaling state: events set/reset/pulse, auto- vs
//! manual-reset consumption, semaphore counts, mutex ownership, named-object
//! sharing, and `WaitForSingle/MultipleObjects` returning `WAIT_OBJECT_0` when
//! satisfied and `WAIT_TIMEOUT` (0x102) for an unsatisfiable zero-timeout wait.
//! Each call also asserts the 32-bit stdcall stack cleanup matches the declared
//! argc — a regression here leaks esp (the original Firefox-installer stall).

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const STACK_BASE: u64 = 0x0018_0000;
const STACK_SIZE: u64 = 0x1000;
const ESP: u64 = 0x0018_0800;
const RETADDR: u32 = 0x0041_2233;
const HEAP: u64 = 0x1000_0000; // scratch for arrays / out-params / names

const WAIT_OBJECT_0: u64 = 0;
const WAIT_TIMEOUT: u64 = 0x102;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x7000_0000, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", HEAP, 0x1_0000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: false,
        api_base: 0x7000_0000,
        heap_base: HEAP,
        heap_size: 0x1_0000,
        echo: false,
        ..WinConfig::default()
    });
    (os, mem)
}

/// Invoke a kernel32 API with explicit 32-bit stdcall DWORD arguments,
/// asserting the callee cleaned up exactly `args.len()` DWORDs. Returns EAX.
fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, args: &[u32]) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(ESP);
    mem.write_u32(ESP, RETADDR).unwrap();
    for (i, &a) in args.iter().enumerate() {
        mem.write_u32(ESP + 4 + i as u64 * 4, a).unwrap();
    }
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "{name}: intercept should Continue");
    assert_eq!(cpu.rip, RETADDR as u64, "{name}: must ret to caller");
    assert_eq!(
        cpu.rsp() & 0xFFFF_FFFF,
        ESP + 4 + args.len() as u64 * 4,
        "{name}: stdcall cleanup must match argc {}",
        args.len()
    );
    cpu.gpr_read(Reg::Rax as u8, 4)
}

fn put_wstr(mem: &mut VirtualMemory, addr: u64, s: &str) {
    let mut a = addr;
    for u in s.encode_utf16() {
        mem.write_u16(a, u).unwrap();
        a += 2;
    }
    mem.write_u16(a, 0).unwrap();
}

#[test]
fn create_event_returns_non_null_handle_with_argc_4() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // CreateEventA(attr, bManualReset, bInitialState, lpName).
    let h = call(&mut os, &mut mem, &mut cpu, "CreateEventA", &[0, 1, 0, 0]);
    assert_ne!(h, 0, "CreateEventA must return a NON-NULL handle");
    let h2 = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 0, 0, 0]);
    assert_ne!(h2, 0);
    assert_ne!(h, h2, "distinct anonymous events get distinct handles");
}

#[test]
fn manual_reset_event_signal_roundtrip() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // Manual-reset, initially non-signaled.
    let h = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 1, 0, 0]) as u32;

    // Unsignaled + zero timeout → WAIT_TIMEOUT.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_TIMEOUT);
    // Set → signaled; manual reset stays signaled across repeated waits.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetEvent", &[h]), 1);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    // Reset → unsignaled again.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "ResetEvent", &[h]), 1);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_TIMEOUT);
}

#[test]
fn auto_reset_event_is_consumed_by_wait() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // Auto-reset, initially signaled.
    let h = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 0, 1, 0]) as u32;
    // First wait consumes the signal; the second times out.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_TIMEOUT);
}

#[test]
fn semaphore_counts_down_and_releases() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // CreateSemaphore(attr, lInitialCount=2, lMaximumCount=4, name).
    let h = call(&mut os, &mut mem, &mut cpu, "CreateSemaphoreW", &[0, 2, 4, 0]) as u32;
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    // Count now 0 → times out.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_TIMEOUT);
    // ReleaseSemaphore(h, 1, &prev): prev count written back is 0, then wait ok.
    let prev = HEAP + 0x100;
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "ReleaseSemaphore", &[h, 1, prev as u32]), 1);
    assert_eq!(mem.read_u32(prev).unwrap(), 0, "previous count");
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
}

#[test]
fn mutex_ownership_and_release() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // CreateMutex(attr, bInitialOwner=0, name) — unowned.
    let h = call(&mut os, &mut mem, &mut cpu, "CreateMutexW", &[0, 0, 0]) as u32;
    // Acquire (owner becomes current thread), then release succeeds.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h, 0]), WAIT_OBJECT_0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "ReleaseMutex", &[h]), 1);
    // Releasing an unowned mutex fails (ERROR_NOT_OWNER → FALSE).
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "ReleaseMutex", &[h]), 0);
}

#[test]
fn wait_multiple_any_returns_first_signaled_index() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let h0 = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 1, 0, 0]) as u32; // unsignaled
    let h1 = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 1, 1, 0]) as u32; // signaled
    let arr = HEAP + 0x200;
    mem.write_u32(arr, h0).unwrap();
    mem.write_u32(arr + 4, h1).unwrap();
    // WaitForMultipleObjects(2, arr, bWaitAll=FALSE, 0) → WAIT_OBJECT_0 + 1.
    let r = call(&mut os, &mut mem, &mut cpu, "WaitForMultipleObjects", &[2, arr as u32, 0, 0]);
    assert_eq!(r, WAIT_OBJECT_0 + 1, "index of the first signaled object");
}

#[test]
fn named_event_is_shared_across_creates() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let name = HEAP + 0x300;
    put_wstr(&mut mem, name, "ExemuTestEvent");
    let h1 = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 1, 0, name as u32]);
    let h2 = call(&mut os, &mut mem, &mut cpu, "CreateEventW", &[0, 1, 0, name as u32]);
    assert_eq!(h1, h2, "same name → same underlying object handle");
    // OpenEventW(access, inherit, name) resolves the same object.
    let h3 = call(&mut os, &mut mem, &mut cpu, "OpenEventW", &[0, 0, name as u32]);
    assert_eq!(h3, h1);
    // Signaling through one handle is visible through the shared object.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetEvent", &[h1 as u32]), 1);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[h2 as u32, 0]), WAIT_OBJECT_0);
}

#[test]
fn close_handle_accepts_event_handle() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let h = call(&mut os, &mut mem, &mut cpu, "CreateEventA", &[0, 1, 0, 0]);
    assert_ne!(h, 0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "CloseHandle", &[h as u32]), 1, "CloseHandle(event) → TRUE");
}

#[test]
fn wait_on_unknown_handle_does_not_hang() {
    // A wait on a foreign/pseudo handle (e.g. the current process) must report
    // WAIT_OBJECT_0 immediately rather than block.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "WaitForSingleObject", &[0xDEAD_0000, 0]), WAIT_OBJECT_0);
}
