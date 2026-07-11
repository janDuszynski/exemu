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

// --- W2.6: the NT memory syscalls (NtAllocate/Free/Protect/QueryVirtualMemory)
// driven end-to-end through the real interpreter + SSDT dispatcher, exactly as a
// Wine PE `Nt*` stub would (`mov r10,rcx; mov eax,N; syscall; ret`). This is the
// W2.6 de-risk: alloc → protect → query → free round-trips through the syscall
// path, with the NTSTATUS/IN-OUT-pointer ABI, not the Win32 `Virtual*` face. ---

mod nt {
    use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
    use exemu_cpu::{Bits, Interpreter, GS_BASE};
    use exemu_memory::VirtualMemory;
    use exemu_os::{WinConfig, WinOs};

    const CODE: u64 = 0x0000_0000_0040_0000;
    const STACK_TOP: u64 = 0x0000_0010_0000_1000;
    const SCRATCH: u64 = 0x0000_0000_5000_0000; // IN/OUT pointer cells + MBI buffer
    const TEB_SIZE: u64 = 0x2000;

    // SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
    const NT_ALLOCATE: u32 = 0x18;
    const NT_FREE: u32 = 0x1e;
    const NT_PROTECT: u32 = 0x50;
    const NT_QUERY: u32 = 0x23;

    const MEM_COMMIT: u64 = 0x1000;
    const MEM_RESERVE: u64 = 0x2000;
    const MEM_RELEASE: u64 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const MEMORY_BASIC_INFORMATION: u64 = 0;
    const STATE_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x0002_0000;
    const STATUS_SUCCESS: u64 = 0;

    /// Drive one raw `SYSCALL n` through the real interpreter with args already
    /// placed in the syscall ABI registers (arg0=R10, arg1=RDX, arg2=R8,
    /// arg3=R9) plus any stack args written by the caller at `[STACK_TOP+…]`.
    /// Returns the NTSTATUS left in RAX.
    fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
        // `mov rcx,arg0; mov r10,rcx; mov eax,N; syscall; hlt`.
        // (The stub's `mov r10,rcx` is what moves arg0 into R10.)
        let mut asm: Vec<u8> = Vec::new();
        asm.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
        asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
        asm.extend_from_slice(&[0x49, 0x89, 0xCA]); // mov r10, rcx
        asm.extend_from_slice(&[0xB8]); // mov eax, imm32
        asm.extend_from_slice(&index.to_le_bytes());
        asm.extend_from_slice(&[0x0F, 0x05]); // syscall
        asm.push(0xF4); // hlt
        mem.poke(CODE, &asm).unwrap();

        let mut cpu = Interpreter::with_bits(Bits::B64);
        // Point RSP a little below the top of the stack so the syscall's stack
        // args (5+) at [rsp+0x28+…] land inside the mapped stack region.
        let rsp = STACK_TOP - 0x100;
        {
            let s = cpu.state_mut();
            s.rip = CODE;
            s.set_rsp(rsp);
            let regs = [Reg::Rdx, Reg::R8, Reg::R9];
            for (i, &a) in args.iter().skip(1).take(3).enumerate() {
                s.set_reg(regs[i], a);
            }
        }
        // args 5+ live above the 32-byte shadow at [rsp+0x28+(n-4)*8].
        for (n, &a) in args.iter().enumerate().skip(4) {
            mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
        }
        loop {
            match cpu.step(mem, os).unwrap() {
                Exit::Continue => continue,
                Exit::Halted => break,
                other => panic!("unexpected exit: {other:?}"),
            }
        }
        cpu.state().reg(Reg::Rax)
    }

    fn setup() -> (WinOs, VirtualMemory) {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
        mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
        let os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
        (os, mem)
    }

    #[test]
    fn nt_alloc_protect_query_free_roundtrip() {
        let (mut os, mut mem) = setup();

        // --- NtAllocateVirtualMemory(NULL base, 0x2000, COMMIT|RESERVE, RW). ---
        // IN/OUT cells: *BaseAddress starts NULL (kernel picks), *RegionSize 0x2000.
        let base_ptr = SCRATCH;
        let size_ptr = SCRATCH + 0x10;
        mem.write_u64(base_ptr, 0).unwrap();
        mem.write_u64(size_ptr, 0x2000).unwrap();
        let st = syscall(
            &mut os,
            &mut mem,
            NT_ALLOCATE,
            &[0xFFFF_FFFF_FFFF_FFFF, base_ptr, 0, size_ptr, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE as u64],
        );
        assert_eq!(st, STATUS_SUCCESS, "NtAllocateVirtualMemory succeeds");
        let base = mem.read_u64(base_ptr).unwrap();
        assert_ne!(base, 0, "kernel wrote back a base");
        assert_eq!(base & 0xFFFF, 0, "base 64 KiB aligned");
        assert_eq!(mem.read_u64(size_ptr).unwrap(), 0x2000, "size written back");
        // Backing is real and writable.
        mem.write_u64(base, 0xdead_beef_cafe_babe).unwrap();
        assert_eq!(mem.read_u64(base).unwrap(), 0xdead_beef_cafe_babe);

        // --- NtProtectVirtualMemory(&base, &size, PAGE_EXECUTE_READ, &old). ---
        let pbase_ptr = SCRATCH + 0x20;
        let psize_ptr = SCRATCH + 0x28;
        let old_ptr = SCRATCH + 0x30;
        mem.write_u64(pbase_ptr, base).unwrap();
        mem.write_u64(psize_ptr, 0x1000).unwrap();
        let st = syscall(
            &mut os,
            &mut mem,
            NT_PROTECT,
            &[0xFFFF_FFFF_FFFF_FFFF, pbase_ptr, psize_ptr, PAGE_EXECUTE_READ as u64, old_ptr],
        );
        assert_eq!(st, STATUS_SUCCESS, "NtProtectVirtualMemory succeeds");
        assert_eq!(mem.read_u32(old_ptr).unwrap(), PAGE_READWRITE, "old protect written back");

        // --- NtQueryVirtualMemory(base, MemoryBasicInformation, &mbi, 0x30, &ret). ---
        let mbi = SCRATCH + 0x100;
        let ret_ptr = SCRATCH + 0x40;
        let st = syscall(
            &mut os,
            &mut mem,
            NT_QUERY,
            &[0xFFFF_FFFF_FFFF_FFFF, base, MEMORY_BASIC_INFORMATION, mbi, 0x30, ret_ptr],
        );
        assert_eq!(st, STATUS_SUCCESS, "NtQueryVirtualMemory succeeds");
        assert_eq!(mem.read_u64(ret_ptr).unwrap(), 0x30, "ReturnLength = sizeof(MBI)");
        assert_eq!(mem.read_u64(mbi).unwrap(), base, "MBI.BaseAddress");
        assert_eq!(mem.read_u64(mbi + 0x08).unwrap(), base, "MBI.AllocationBase");
        assert_eq!(mem.read_u64(mbi + 0x18).unwrap(), 0x2000, "MBI.RegionSize");
        assert_eq!(mem.read_u32(mbi + 0x20).unwrap(), STATE_COMMIT, "MBI.State = COMMIT");
        assert_eq!(mem.read_u32(mbi + 0x24).unwrap(), PAGE_EXECUTE_READ, "MBI.Protect (post-protect)");
        assert_eq!(mem.read_u32(mbi + 0x28).unwrap(), MEM_PRIVATE, "MBI.Type = MEM_PRIVATE");

        // --- NtFreeVirtualMemory(&base, &size, MEM_RELEASE) → unmapped. ---
        let fbase_ptr = SCRATCH + 0x50;
        let fsize_ptr = SCRATCH + 0x58;
        mem.write_u64(fbase_ptr, base).unwrap();
        mem.write_u64(fsize_ptr, 0).unwrap();
        let st = syscall(
            &mut os,
            &mut mem,
            NT_FREE,
            &[0xFFFF_FFFF_FFFF_FFFF, fbase_ptr, fsize_ptr, MEM_RELEASE],
        );
        assert_eq!(st, STATUS_SUCCESS, "NtFreeVirtualMemory succeeds");
        assert_eq!(mem.read_u64(fbase_ptr).unwrap(), base, "freed base written back");
        assert_eq!(mem.read_u64(fsize_ptr).unwrap(), 0x2000, "freed size written back");
        assert!(mem.read_u64(base).is_err(), "released memory is unmapped");
    }

    #[test]
    fn nt_allocate_null_pointers_rejected() {
        let (mut os, mut mem) = setup();
        // A NULL *BaseAddress pointer is STATUS_INVALID_PARAMETER, not a fault.
        let st = syscall(
            &mut os,
            &mut mem,
            NT_ALLOCATE,
            &[0xFFFF_FFFF_FFFF_FFFF, 0, 0, SCRATCH, MEM_COMMIT, PAGE_READWRITE as u64],
        );
        assert_eq!(st, 0xC000_000D, "NULL BaseAddress → STATUS_INVALID_PARAMETER");
    }
}
