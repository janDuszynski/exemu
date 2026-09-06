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
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        echo: false,
        ..WinConfig::default()
    });
    (os, mem)
}

fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str) -> u64 {
    let thunk = os.resolve_import("msvcrt.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.rip, RET_ADDR, "shim did not return to caller");
    assert_eq!(cpu.rsp(), STACK + 8, "stack not unwound by ret");
    cpu.reg(Reg::Rax)
}

#[test]
fn memset_fills() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, DATA);
    cpu.set_reg(Reg::Rdx, 0xAB);
    cpu.set_reg(Reg::R8, 8);
    let rax = call(&mut os, &mut mem, &mut cpu, "memset");
    assert_eq!(rax, DATA, "memset returns dest");
    assert_eq!(mem.read_u64(DATA).unwrap(), 0xABAB_ABAB_ABAB_ABAB);
}

#[test]
fn memcpy_copies() {
    let (mut os, mut mem) = setup();
    mem.write_u64(DATA, 0x1122_3344_5566_7788).unwrap();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, DATA + 0x100);
    cpu.set_reg(Reg::Rdx, DATA);
    cpu.set_reg(Reg::R8, 8);
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
    mem.write_u64(p, 0xdead_beef).unwrap();
    assert_eq!(mem.read_u64(p).unwrap(), 0xdead_beef);
}

#[test]
fn tls_alloc_set_get_roundtrip() {
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
    cpu.set_reg(Reg::R8, 260);
    let n = call(&mut os, &mut mem, &mut cpu, "GetEnvironmentVariableW");
    assert_eq!(n, 3, "GetEnvironmentVariableW returns the length in chars");
    let read: Vec<u16> = (0..n).map(|i| mem.read_u16(out + i * 2).unwrap()).collect();
    assert_eq!(String::from_utf16(&read).unwrap(), "yes");
}

#[test]
fn exit_terminates_process() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 7);
    let thunk = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("exit".into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, &mut cpu, &mut mem).unwrap();
    assert_eq!(exit, Some(Exit::ProcessExit(7)));
}

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

const HEAP: u64 = 0x00AB_0000;

#[test]
fn heap_realloc_grow_preserves_data() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr, 0, "HeapAlloc must succeed");

    for i in 0..0x20u64 {
        mem.write_u8(ptr + i, (0xA0 + i) as u8).unwrap();
    }

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr);
    cpu.set_reg(Reg::R9, 0x40);
    let ptr2 = call_k32(&mut os, &mut mem, &mut cpu, "HeapReAlloc");
    assert_ne!(ptr2, 0, "HeapReAlloc must succeed");

    for i in 0..0x20u64 {
        let b = mem.read_u8(ptr2 + i).unwrap();
        assert_eq!(b, (0xA0 + i) as u8, "byte {i} mismatch after grow realloc");
    }
}

#[test]
fn heap_realloc_shrink_preserves_prefix() {
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
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr_a = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_ne!(ptr_a, 0);

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, ptr_a);
    let r = call_k32(&mut os, &mut mem, &mut cpu, "HeapFree");
    assert_eq!(r, 1);

    cpu.set_reg(Reg::Rcx, HEAP);
    cpu.set_reg(Reg::Rdx, 0);
    cpu.set_reg(Reg::R8, 0x20);
    let ptr_b = call_k32(&mut os, &mut mem, &mut cpu, "HeapAlloc");
    assert_eq!(ptr_b, ptr_a, "last-block reclaim: B should reuse A's address");
}
