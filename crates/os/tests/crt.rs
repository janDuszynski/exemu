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
fn tls_alloc_set_get_roundtrip() {
    // The MSVC CRT stores its per-thread data pointer in a TLS/FLS slot; if the
    // set/get do not round-trip it aborts at startup (R6016). TlsAlloc → an
    // index, TlsSetValue stores, TlsGetValue reads the same value back.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let idx = call(&mut os, &mut mem, &mut cpu, "TlsAlloc");

    cpu.set_reg(Reg::Rcx, idx);
    cpu.set_reg(Reg::Rdx, 0xCAFE_D00D);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "TlsSetValue"), 1, "TlsSetValue must succeed");

    cpu.set_reg(Reg::Rcx, idx);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "TlsGetValue"), 0xCAFE_D00D);
}

#[test]
fn fls_alloc_set_get_roundtrip() {
    // Fiber-local storage shares the implementation; the classic MSVC CRT uses
    // FlsAlloc/FlsSetValue/FlsGetValue for the same per-thread data pointer.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let idx = call(&mut os, &mut mem, &mut cpu, "FlsAlloc");

    cpu.set_reg(Reg::Rcx, idx);
    cpu.set_reg(Reg::Rdx, 0x1234_5678);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "FlsSetValue"), 1);

    cpu.set_reg(Reg::Rcx, idx);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "FlsGetValue"), 0x1234_5678);
}

#[test]
fn get_environment_strings_is_populated() {
    // An empty environment block makes the CRT abort (R6009); ours is seeded, so
    // the block's first wide character is non-NUL.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let ptr = call(&mut os, &mut mem, &mut cpu, "GetEnvironmentStringsW");
    assert_ne!(ptr, 0);
    assert_ne!(mem.read_u16(ptr).unwrap(), 0, "environment block must not be empty");
}

#[test]
fn environment_variable_set_then_get() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    // "EXEMU_TEST" (name) and "yes" (value) as UTF-16 in guest memory.
    let name = DATA;
    let value = DATA + 0x100;
    let out = DATA + 0x200;
    for (i, u) in "EXEMU_TEST".encode_utf16().chain([0]).enumerate() {
        mem.write_u16(name + i as u64 * 2, u).unwrap();
    }
    for (i, u) in "yes".encode_utf16().chain([0]).enumerate() {
        mem.write_u16(value + i as u64 * 2, u).unwrap();
    }

    cpu.set_reg(Reg::Rcx, name);
    cpu.set_reg(Reg::Rdx, value);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetEnvironmentVariableW"), 1);

    cpu.set_reg(Reg::Rcx, name);
    cpu.set_reg(Reg::Rdx, out);
    cpu.set_reg(Reg::R8, 260); // buffer size in wide chars
    let n = call(&mut os, &mut mem, &mut cpu, "GetEnvironmentVariableW");
    assert_eq!(n, 3, "GetEnvironmentVariableW returns the length in chars");
    let read: Vec<u16> = (0..n).map(|i| mem.read_u16(out + i * 2).unwrap()).collect();
    assert_eq!(String::from_utf16(&read).unwrap(), "yes");
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

// ── Heap per-allocation size tracking (roadmap P3.3) ─────────────────────────

/// Drive a kernel32 API through intercept and return RAX, using the Windows
/// x64 calling convention (RCX, RDX, R8, R9).
fn call_k32(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    cpu: &mut CpuState,
    name: &str,
) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.rip, RET_ADDR, "{name} did not return to caller");
    assert_eq!(cpu.rsp(), STACK + 8, "{name} did not unwind stack");
    cpu.reg(Reg::Rax)
}

const HEAP: u64 = 0x00AB_0000; // HANDLE_PROCESS_HEAP sentinel

#[test]
fn heap_realloc_grow_preserves_data() {
    // HeapAlloc 0x20 bytes, fill with a pattern, HeapReAlloc to 0x40,
    // assert the first 0x20 bytes are preserved (not over-read or zeroed).
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // HeapAlloc(HEAP, 0, 0x20)
    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr, 0, "HeapAlloc must succeed");

    // Write a known byte pattern into the block.
    for i in 0..0x20u64 {
        mem.write_u8(ptr + i, (0xA0 + i) as u8).unwrap();
    }

    // HeapReAlloc(HEAP, 0, ptr, 0x40) — grow the block
    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr);
    cpu.set_reg(Reg::R9, 0x40);
    let ptr2 = call_k32(&mut os, &mut mem, &mut cpu, "HeapReAlloc");
    assert_ne!(ptr2, 0, "HeapReAlloc must succeed");

    // First 0x20 bytes must match the pattern written before.
    for i in 0..0x20u64 {
        let b = mem.read_u8(ptr2 + i).unwrap();
        assert_eq!(b, (0xA0 + i) as u8, "byte {i} mismatch after grow realloc");
    }
}

#[test]
fn heap_realloc_shrink_preserves_prefix() {
    // HeapAlloc 0x40, fill, HeapReAlloc to 0x10; first 0x10 bytes preserved.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x40);
    let ptr = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr, 0);

    for i in 0..0x40u64 {
        mem.write_u8(ptr + i, (0xC0 + i) as u8).unwrap();
    }

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr);
    cpu.set_reg(Reg::R9, 0x10);
    let ptr2 = call_k32(&mut os, &mut mem, &mut cpu, "HeapReAlloc");
    assert_ne!(ptr2, 0);

    // Only the first 0x10 bytes should have been copied (shrink).
    for i in 0..0x10u64 {
        let b = mem.read_u8(ptr2 + i).unwrap();
        assert_eq!(b, (0xC0 + i) as u8, "byte {i} mismatch after shrink realloc");
    }
}

#[test]
fn heap_free_returns_true() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x10);
    let ptr = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr, 0);

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr);
    let r = call_k32(&mut os, &mut mem, &mut cpu, "HeapFree");
    assert_eq!(r, 1, "HeapFree must return TRUE");
}

#[test]
fn heap_free_last_block_reclaim() {
    // Alloc A, free A, alloc B: B should reuse A's address (last-block reclaim).
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // Alloc A
    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr_a = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr_a, 0);

    // Free A (last block → reclaim)
    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr_a);
    let r = call_k32(&mut os, &mut mem, &mut cpu, "HeapFree");
    assert_eq!(r, 1);

    // Alloc B — must land at the same address as A
    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr_b = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_eq!(ptr_b, ptr_a, "last-block reclaim: B should reuse A's address");
}
