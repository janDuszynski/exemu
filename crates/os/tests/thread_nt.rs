//! W2.9 — the NT thread/process syscalls (`NtCreateThreadEx`, `NtTerminate/
//! Suspend/ResumeThread`, `NtQueryInformationThread`) and the full per-thread
//! Wine-walkable TEB, driven end-to-end through the real interpreter + the
//! W2.3 SSDT dispatcher exactly as a Wine PE `Nt*` stub would
//! (`mov r10,rcx; mov eax,N; syscall; ret`).
//!
//! De-risk (roadmap W2.9): (1) a spawned thread's full TEB is readable without
//! faulting — every field Wine's ntdll walks off `NtCurrentTeb()` is seeded;
//! (2) each thread has its own `gs` segment base, so `gs:[…]` reads *that*
//! thread's TEB.

use exemu_core::{Cpu, CpuState, Exit, Hooks, Memory, Perm, Reg, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000; // OUT-pointer cells
const PEB: u64 = GS_BASE + 0x2000;
const TEB_SIZE: u64 = 0x2000;

// SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
const NT_CREATE_THREAD_EX: u32 = 0x85;
const NT_TERMINATE_THREAD: u32 = 0x53;
const NT_SUSPEND_THREAD: u32 = 0xf5;
const NT_RESUME_THREAD: u32 = 0x52;
const NT_QUERY_INFORMATION_THREAD: u32 = 0x25;

const STATUS_SUCCESS: u64 = 0;
const NT_CURRENT_THREAD: u64 = u64::MAX - 1;
const PROCESS_ID: u64 = 0x1000;

/// Drive one raw `SYSCALL n` through the real interpreter with args in the
/// syscall ABI registers (arg0=R10 via the stub's `mov r10,rcx`, arg1=RDX,
/// arg2=R8, arg3=R9) + any stack args at `[rsp+0x28+…]`. Returns RAX (NTSTATUS).
fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
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
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        // The running (main) thread's gs base is the main TEB.
        s.gs_base = GS_BASE;
        let regs = [Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
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
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    (os, mem)
}

/// The x64 TEB field offsets Wine walks (public winternl.h / NT_TIB layout).
mod teb {
    pub const EXCEPTION_LIST: u64 = 0x000;
    pub const STACK_BASE: u64 = 0x008;
    pub const STACK_LIMIT: u64 = 0x010;
    pub const SELF: u64 = 0x030;
    pub const CLIENT_ID_PROCESS: u64 = 0x040;
    pub const CLIENT_ID_THREAD: u64 = 0x048;
    pub const TLS_POINTER: u64 = 0x058;
    pub const PEB: u64 = 0x060;
    // The offset Wine's kernelbase `file_name_AtoW` reads as `gs:[0x30]+0x1258`
    // (roadmap W3.7): the `*A` file APIs fail before `NtCreateFile` if this is
    // wrong and MaximumLength reads back 0.
    pub const STATIC_UNICODE_STRING: u64 = 0x1258;
    pub const STATIC_UNICODE_BUFFER: u64 = 0x1268;
    pub const COUNT_OF_OWNED_CRIT_SECS: u64 = 0x6C8;
}

/// De-risk 1: `NtCreateThreadEx` spawns a thread whose **full TEB** is present
/// and walkable — every field Wine's ntdll reads off `NtCurrentTeb()` — and
/// `NtQueryInformationThread(ThreadBasicInformation)` reports it consistently.
#[test]
fn nt_create_thread_reads_full_teb() {
    let (mut os, mut mem) = setup();
    let entry = 0x0000_0000_0041_0000;
    let param = 0xCAFE_F00D;

    // NtCreateThreadEx(&h, access, objattr, proc, entry, arg, flags=0, zbits,
    //                  stack, maxstack, attrlist). arg6 flags=0 (not suspended).
    let handle_out = SCRATCH;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_THREAD_EX,
        &[handle_out, 0x1FFFFF, 0, NT_CURRENT_THREAD, entry, param, 0, 0, 0, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateThreadEx succeeds");
    let handle = mem.read_u64(handle_out).unwrap();
    assert_ne!(handle, 0, "a thread handle was written back");

    // Query the new thread's basic info to learn its TEB base (the thread runs
    // its own TEB, distinct from the main thread's).
    let tbi = SCRATCH + 0x100;
    let ret_ptr = SCRATCH + 0x40;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_INFORMATION_THREAD,
        &[handle, 0 /* ThreadBasicInformation */, tbi, 0x30, ret_ptr],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryInformationThread(basic) succeeds");
    assert_eq!(mem.read_u32(ret_ptr).unwrap(), 0x30, "ReturnLength = sizeof(TBI)");
    assert_eq!(mem.read_u32(tbi).unwrap(), 259, "ExitStatus = STILL_ACTIVE");
    let teb_base = mem.read_u64(tbi + 0x08).unwrap();
    assert_ne!(teb_base, GS_BASE, "the spawned thread has its OWN TEB, not the main TEB");
    assert_eq!(mem.read_u64(tbi + 0x10).unwrap(), PROCESS_ID, "ClientId.UniqueProcess");
    let tid = mem.read_u64(tbi + 0x18).unwrap();
    assert_ne!(tid, 0, "ClientId.UniqueThread nonzero");

    // Now walk the spawned thread's TEB directly — none of these reads faults,
    // and every field Wine's ntdll probes is populated.
    assert_eq!(mem.read_u64(teb_base + teb::SELF).unwrap(), teb_base, "NtTib.Self");
    assert_eq!(
        mem.read_u64(teb_base + teb::EXCEPTION_LIST).unwrap(),
        u64::MAX,
        "NtTib.ExceptionList = -1 sentinel (no SEH frame yet)"
    );
    assert_ne!(mem.read_u64(teb_base + teb::STACK_BASE).unwrap(), 0, "NtTib.StackBase");
    assert!(
        mem.read_u64(teb_base + teb::STACK_LIMIT).unwrap()
            < mem.read_u64(teb_base + teb::STACK_BASE).unwrap(),
        "StackLimit < StackBase"
    );
    assert_eq!(mem.read_u64(teb_base + teb::CLIENT_ID_PROCESS).unwrap(), PROCESS_ID, "ClientId.UniqueProcess");
    assert_eq!(mem.read_u64(teb_base + teb::CLIENT_ID_THREAD).unwrap(), tid, "ClientId.UniqueThread matches query");
    assert_eq!(mem.read_u64(teb_base + teb::TLS_POINTER).unwrap(), 0, "ThreadLocalStoragePointer (lazy, NULL)");
    assert_eq!(mem.read_u64(teb_base + teb::PEB).unwrap(), PEB, "ProcessEnvironmentBlock");
    // StaticUnicodeString: empty UNICODE_STRING pointing at StaticUnicodeBuffer.
    assert_eq!(mem.read_u16(teb_base + teb::STATIC_UNICODE_STRING).unwrap(), 0, "StaticUnicodeString.Length = 0");
    assert_eq!(
        mem.read_u16(teb_base + teb::STATIC_UNICODE_STRING + 2).unwrap(),
        261 * 2,
        "StaticUnicodeString.MaximumLength = 522"
    );
    assert_eq!(
        mem.read_u64(teb_base + teb::STATIC_UNICODE_STRING + 8).unwrap(),
        teb_base + teb::STATIC_UNICODE_BUFFER,
        "StaticUnicodeString.Buffer → inline StaticUnicodeBuffer"
    );
    assert_eq!(mem.read_u32(teb_base + teb::COUNT_OF_OWNED_CRIT_SECS).unwrap(), 0, "CountOfOwnedCriticalSections");

    // The per-thread Wine debug-string ring at TEB+0x3000 (a u32 write position
    // + ring bytes from +0x3008, bounded 0x3fc — `__wine_dbg_strdup` @ ntdll RVA
    // 0x3f3c0). A spawned thread's TEB region is 0x4000, so this is mapped and
    // zero-initialised, and a Wine thread that emits a TRACE won't fault here.
    assert_eq!(
        mem.read_u32(teb_base + 0x3000).unwrap(),
        0,
        "debug-string ring write-position is zero-initialised"
    );
    mem.write_u32(teb_base + 0x3000, 7).expect("debug ring position is writable");
    assert_eq!(mem.read_u32(teb_base + 0x3000).unwrap(), 7);
    mem.read_u8(teb_base + 0x3008 + 0x3fc)
        .expect("the whole debug-string ring (through +0x3fc) is mapped");
}

/// De-risk 2: each thread reads its OWN TEB through `gs:`. The spawned thread's
/// `gs` segment base is its own TEB, so running the canonical `NtCurrentTeb()`
/// idiom `mov rax, gs:[0x30]` under that thread's base reads its Self pointer,
/// while the main thread reads the main TEB — proving the per-thread `gs` base
/// threads through the CPU's SIB math (roadmap W2.9).
#[test]
fn per_thread_gs_base_selects_the_right_teb() {
    let (mut os, mut mem) = setup();
    let entry = 0x0000_0000_0041_0000;

    // Spawn a thread and learn its TEB base.
    let handle_out = SCRATCH;
    syscall(
        &mut os,
        &mut mem,
        NT_CREATE_THREAD_EX,
        &[handle_out, 0x1FFFFF, 0, NT_CURRENT_THREAD, entry, 0, 0, 0, 0, 0, 0],
    );
    let handle = mem.read_u64(handle_out).unwrap();
    let tbi = SCRATCH + 0x100;
    syscall(&mut os, &mut mem, NT_QUERY_INFORMATION_THREAD, &[handle, 0, tbi, 0x30, SCRATCH + 0x40]);
    let worker_teb = mem.read_u64(tbi + 0x08).unwrap();
    assert_ne!(worker_teb, GS_BASE);

    // Seed the main TEB's Self pointer (the app does this for the process's main
    // thread; here we stand in for it) so the main-thread read has a target.
    mem.write_u64(GS_BASE + teb::SELF, GS_BASE).unwrap();

    // `mov rax, gs:[0x30]` — read NtCurrentTeb()->Self.
    let read_self: &[u8] = &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xF4]; // + hlt
    mem.poke(CODE, read_self).unwrap();

    let run_with_gs = |mem: &mut VirtualMemory, gs: u64| -> u64 {
        let mut cpu = Interpreter::with_bits(Bits::B64);
        {
            let s = cpu.state_mut();
            s.rip = CODE;
            s.set_rsp(STACK_TOP - 0x100);
            s.gs_base = gs; // the running thread's per-thread gs base
        }
        loop {
            match cpu.step(mem, &mut NoOpHooks).unwrap() {
                Exit::Continue => continue,
                Exit::Halted => break,
                other => panic!("unexpected exit: {other:?}"),
            }
        }
        cpu.state().reg(Reg::Rax)
    };

    // Main thread's gs base → main TEB Self (GS_BASE).
    assert_eq!(run_with_gs(&mut mem, GS_BASE), GS_BASE, "main thread reads the main TEB via gs:[0x30]");
    // Worker thread's gs base → its own TEB Self.
    assert_eq!(run_with_gs(&mut mem, worker_teb), worker_teb, "worker thread reads its OWN TEB via gs:[0x30]");
}

/// A no-op `Hooks` stand-in so the pure `gs:[0x30]` read above needs no OS
/// services (no thunk lands on the running rip).
struct NoOpHooks;
impl Hooks for NoOpHooks {
    fn intercept(&mut self, _rip: u64, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<Option<Exit>> {
        Ok(None)
    }
}

/// `NtSuspendThread`/`NtResumeThread` bump and report the previous suspend
/// count; `NtTerminateThread` of another thread marks it terminated and its
/// exit code surfaces through `NtQueryInformationThread`.
#[test]
fn nt_suspend_resume_terminate_another_thread() {
    let (mut os, mut mem) = setup();
    let entry = 0x0000_0000_0041_0000;
    let handle_out = SCRATCH;
    syscall(
        &mut os,
        &mut mem,
        NT_CREATE_THREAD_EX,
        &[handle_out, 0x1FFFFF, 0, NT_CURRENT_THREAD, entry, 0, 0, 0, 0, 0, 0],
    );
    let handle = mem.read_u64(handle_out).unwrap();

    // Suspend twice: previous counts 0, then 1.
    let prev = SCRATCH + 0x40;
    assert_eq!(syscall(&mut os, &mut mem, NT_SUSPEND_THREAD, &[handle, prev]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(prev).unwrap(), 0, "first suspend: prev count 0");
    assert_eq!(syscall(&mut os, &mut mem, NT_SUSPEND_THREAD, &[handle, prev]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(prev).unwrap(), 1, "second suspend: prev count 1");
    // Resume once: previous count 2.
    assert_eq!(syscall(&mut os, &mut mem, NT_RESUME_THREAD, &[handle, prev]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(prev).unwrap(), 2, "resume: prev count 2");

    // Terminate it with exit code 7; query reports the code.
    assert_eq!(syscall(&mut os, &mut mem, NT_TERMINATE_THREAD, &[handle, 7]), STATUS_SUCCESS);
    let tbi = SCRATCH + 0x100;
    syscall(&mut os, &mut mem, NT_QUERY_INFORMATION_THREAD, &[handle, 0, tbi, 0x30, SCRATCH + 0x40]);
    assert_eq!(mem.read_u32(tbi).unwrap(), 7, "ExitStatus reports the terminate code");

    // A bad handle is rejected.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_SUSPEND_THREAD, &[0xDEAD_BEEF, prev]),
        0xC000_0008,
        "STATUS_INVALID_HANDLE for an unknown thread handle"
    );
}
