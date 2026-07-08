//! Tests for the virtual-memory manager (roadmap P3.2): `VirtualAlloc`,
//! `VirtualFree`, `VirtualProtect` and `VirtualQuery`, driven through the
//! public `Hooks::intercept` seam exactly as the interpreter would.
//!
//! Unlike the old stubs (which handed VirtualAlloc off to the bump heap and
//! made VirtualProtect a no-op), these must return real, distinct, usable
//! regions and report honest state/protection back through VirtualQuery.

use exemu_core::{CpuState, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x2000;
const RSP: u64 = 0x0000_0010_0000_1000;
const RETADDR: u64 = 0x0000_0001_4000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000; // MBI buffer / write target

// PAGE_* protection constants.
const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE_READ: u64 = 0x20;
// flAllocationType / dwFreeType / State.
const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;
const MEM_RELEASE: u64 = 0x8000;
const STATE_COMMIT: u32 = 0x1000;
const STATE_FREE: u32 = 0x10000;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem)
}

/// Invoke a kernel32 API through intercept with up to four register arguments,
/// returning the value left in RAX.
fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, args: &[u64]) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        cpu.set_reg(regs[i], a);
    }
    cpu.rip = thunk;
    os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(cpu.rip, RETADDR, "{name}: must ret to caller");
    cpu.reg(Reg::Rax)
}

#[test]
fn alloc_write_query_protect_free_roundtrip() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();

    // Reserve+commit two pages, read/write.
    let base = call(
        &mut os,
        &mut mem,
        &mut cpu,
        "VirtualAlloc",
        &[0, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
    );
    assert_ne!(base, 0, "VirtualAlloc must return a non-null base");
    assert_eq!(base & 0xFFFF, 0, "base must be 64 KiB aligned");
    mem.write_u64(base, 0xdead_beef_cafe_babe).unwrap();
    assert_eq!(mem.read_u64(base).unwrap(), 0xdead_beef_cafe_babe);
    mem.write_u64(base + 0x1000, 1).unwrap(); // second page is real too

    // Query reports committed private RW memory grouped under `base`.
    let n = call(&mut os, &mut mem, &mut cpu, "VirtualQuery", &[base, SCRATCH, 0x30]);
    assert_eq!(n, 0x30);
    assert_eq!(mem.read_u64(SCRATCH).unwrap(), base, "BaseAddress");
    assert_eq!(mem.read_u64(SCRATCH + 0x08).unwrap(), base, "AllocationBase");
    assert_eq!(mem.read_u64(SCRATCH + 0x18).unwrap(), 0x2000, "RegionSize");
    assert_eq!(mem.read_u32(SCRATCH + 0x20).unwrap(), STATE_COMMIT, "State");
    assert_eq!(mem.read_u32(SCRATCH + 0x24).unwrap() as u64, PAGE_READWRITE, "Protect");

    // Re-protect the first page; the old protection is returned and reflected.
    let old_slot = SCRATCH + 0x200;
    let ok = call(
        &mut os,
        &mut mem,
        &mut cpu,
        "VirtualProtect",
        &[base, 0x1000, PAGE_EXECUTE_READ, old_slot],
    );
    assert_eq!(ok, 1);
    assert_eq!(mem.read_u32(old_slot).unwrap() as u64, PAGE_READWRITE, "old protect");
    call(&mut os, &mut mem, &mut cpu, "VirtualQuery", &[base, SCRATCH, 0x30]);
    assert_eq!(mem.read_u32(SCRATCH + 0x24).unwrap() as u64, PAGE_EXECUTE_READ, "new Protect");

    // Release unmaps the backing (a later access faults).
    let ok = call(&mut os, &mut mem, &mut cpu, "VirtualFree", &[base, 0, MEM_RELEASE]);
    assert_eq!(ok, 1);
    assert!(mem.read_u64(base).is_err(), "released memory must be unmapped");
}

#[test]
fn distinct_allocations_and_free_query() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();

    let a = call(&mut os, &mut mem, &mut cpu, "VirtualAlloc", &[0, 0x1000, MEM_COMMIT, PAGE_READWRITE]);
    let b = call(&mut os, &mut mem, &mut cpu, "VirtualAlloc", &[0, 0x1000, MEM_COMMIT, PAGE_READWRITE]);
    assert_ne!(a, b, "each VirtualAlloc yields a distinct region");
    assert!(b >= a + 0x1000, "regions must not overlap");

    // Query an address in a guaranteed-free hole → MEM_FREE.
    call(&mut os, &mut mem, &mut cpu, "VirtualQuery", &[0x0000_0050_0000_0000, SCRATCH, 0x30]);
    assert_eq!(mem.read_u32(SCRATCH + 0x20).unwrap(), STATE_FREE, "unmapped range is MEM_FREE");
}

#[test]
fn commit_within_reservation() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();

    // Reserve a large range, then commit a page inside it at a fixed address.
    let base = call(&mut os, &mut mem, &mut cpu, "VirtualAlloc", &[0, 0x10000, MEM_RESERVE, PAGE_READWRITE]);
    assert_ne!(base, 0);
    let committed = call(
        &mut os,
        &mut mem,
        &mut cpu,
        "VirtualAlloc",
        &[base + 0x2000, 0x1000, MEM_COMMIT, PAGE_READWRITE],
    );
    assert_eq!(committed, base + 0x2000, "commit returns the requested page base");
    // The reserved backing is usable (we back the whole reservation up front).
    mem.write_u32(base + 0x2000, 0x1234).unwrap();
    assert_eq!(mem.read_u32(base + 0x2000).unwrap(), 0x1234);
}
