//! W2.12 — the NT sync syscalls (`NtCreateEvent`/`NtOpenEvent`/`NtSetEvent`/
//! `NtWaitForSingleObject`/`NtWaitForMultipleObjects`/`NtReleaseSemaphore`/
//! `NtCreateMutant`/`NtCreateSemaphore`), driven end-to-end through the real
//! interpreter + the W2.3 SSDT dispatcher exactly as a Wine PE `Nt*` stub would
//! (`mov r10,rcx; mov eax,N; syscall`).
//!
//! The load-bearing pins (roadmap W2.12 de-risk — the differential oracle is
//! single-stream and cannot see cross-thread behavior):
//!
//! 1. `nt_producer_consumer_event_cross_thread`: a consumer creates an
//!    auto-reset UNsignaled event, spawns a producer, and `NtWaitForSingleObject`
//!    with an infinite timeout **genuinely blocks** (rewind → switch); the
//!    producer writes a sentinel, `NtSetEvent`s via a raw SYSCALL, and exits; the
//!    consumer resumes with `STATUS_WAIT_0` and must observe the sentinel (a
//!    speculative non-blocking return would read 0). This exercises the
//!    rewind/re-execute machinery end to end.
//! 2. `nt_wait_for_multiple_wait_any_reports_index`: a wait-any over two
//!    UNsignaled events returns `STATUS_WAIT_0 + 1` after a real block when the
//!    producer signals handle index 1.

use exemu_core::{Cpu, EmuError, Exit, ImportSymbol, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
const NT_CREATE_EVENT: u32 = 0x48;
const NT_OPEN_EVENT: u32 = 0x40;
const NT_SET_EVENT: u32 = 0x0e;
const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x04;
const NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x5b;
const NT_RELEASE_SEMAPHORE: u32 = 0x0a;
const NT_CREATE_MUTANT: u32 = 0x7e;
const NT_CREATE_SEMAPHORE: u32 = 0x83;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_WAIT_0: u64 = 0x0000_0000;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u64 = 0xC000_0047;

// EVENT_TYPE / WAIT_TYPE (public winternl.h / winnt.h).
const NOTIFICATION_EVENT: u64 = 0; // manual-reset
const SYNCHRONIZATION_EVENT: u64 = 1; // auto-reset
const WAIT_ANY: u64 = 1;

// ==========================================================================
// Single-threaded harness: one raw `SYSCALL n` through the real interpreter.
// (Copied from the thread_nt.rs pattern.)
// ==========================================================================

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000; // OUT-pointer cells / objattr / names
const PEB: u64 = GS_BASE + 0x2000;
const TEB_SIZE: u64 = 0x2000;

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

/// Assemble `mov rcx,arg0; mov r10,rcx; mov eax,N; syscall; hlt`, run it on a
/// fresh interpreter over the shared `os`/`mem`, and return RAX. args 1..=3 land
/// in RDX/R8/R9; args 4+ on the guest stack at `[rsp+0x28+…]`. Panics on any
/// interpreter error (use [`try_syscall`] when an error is the expected result).
fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    try_syscall(os, mem, index, args).expect("syscall faulted")
}

/// Like [`syscall`] but surfaces an interpreter error (e.g. the honest deadlock
/// fault of an unsatisfiable infinite wait) instead of panicking.
fn try_syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> Result<u64> {
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
        s.gs_base = GS_BASE;
        let regs = [exemu_core::Reg::Rdx, exemu_core::Reg::R8, exemu_core::Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os)? {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    Ok(cpu.state().reg(exemu_core::Reg::Rax))
}

/// Lay out a named `OBJECT_ATTRIBUTES` (with its `ObjectName` UNICODE_STRING and
/// wide name buffer) in guest memory, returning the `OBJECT_ATTRIBUTES` address.
/// 64-bit layout: OBJECT_ATTRIBUTES {Length@0, RootDirectory@8, ObjectName@0x10};
/// UNICODE_STRING {Length@0, MaximumLength@2, Buffer@8}.
fn put_objattr(mem: &mut VirtualMemory, base: u64, name: &str) -> u64 {
    let objattr = base;
    let ustr = base + 0x40;
    let name_buf = base + 0x80;
    let units: Vec<u16> = name.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(name_buf + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(ustr, bytes).unwrap(); // Length
    mem.write_u16(ustr + 2, bytes).unwrap(); // MaximumLength
    mem.write_u64(ustr + 8, name_buf).unwrap(); // Buffer
    mem.write_u32(objattr, 0x30).unwrap(); // Length
    mem.write_u64(objattr + 8, 0).unwrap(); // RootDirectory
    mem.write_u64(objattr + 0x10, ustr).unwrap(); // ObjectName
    objattr
}

// ==========================================================================
// Single-threaded tests (no blocking: polls, creates, releases, bad handles).
// ==========================================================================

/// `NtCreateSemaphore` round-trips a count; `NtReleaseSemaphore` reports the
/// previous count and refuses to overflow past the maximum; a satisfied
/// zero-timeout wait consumes one unit each time until the count drains.
#[test]
fn nt_semaphore_release_and_limit() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let prev = SCRATCH + 0x40;
    let zero_timeout = SCRATCH + 0x80; // cell holds 0 → poll

    // NtCreateSemaphore(&h, access=0, objattr=0, initial=1, max=2).
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_SEMAPHORE, &[h_out, 0, 0, 1, 2]), STATUS_SUCCESS);
    let sem = mem.read_u64(h_out).unwrap();
    assert_ne!(sem, 0);

    // Release 1 → previous count 1 (count now 2 = max).
    assert_eq!(syscall(&mut os, &mut mem, NT_RELEASE_SEMAPHORE, &[sem, 1, prev]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(prev).unwrap(), 1, "PreviousCount reported");

    // Release 1 more → would push 2→3 past max 2 → SEMAPHORE_LIMIT_EXCEEDED,
    // count untouched, PreviousCount not written.
    mem.write_u32(prev, 0xDEAD).unwrap();
    assert_eq!(
        syscall(&mut os, &mut mem, NT_RELEASE_SEMAPHORE, &[sem, 1, prev]),
        STATUS_SEMAPHORE_LIMIT_EXCEEDED
    );
    assert_eq!(mem.read_u32(prev).unwrap(), 0xDEAD, "PreviousCount untouched on failure");

    // Drain the count of 2 with zero-timeout waits (each consumes one unit).
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_WAIT_0);
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_WAIT_0);
    // Now empty: a zero-timeout poll times out.
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_TIMEOUT);
}

/// `NtCreateMutant(InitialOwner=TRUE)` grants ownership to the creating thread,
/// so a subsequent wait by the same thread is satisfied immediately (recursive
/// acquire), and an unowned mutant is likewise acquirable.
#[test]
fn nt_create_mutant_initial_owner() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let zero_timeout = SCRATCH + 0x80;

    // Owned by the creator: the same thread's wait succeeds (recurses).
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_MUTANT, &[h_out, 0, 0, 1]), STATUS_SUCCESS);
    let owned = mem.read_u64(h_out).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[owned, 0, zero_timeout]), STATUS_WAIT_0);

    // Unowned: the first waiter takes ownership and is satisfied.
    let h_out2 = SCRATCH + 0x8;
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_MUTANT, &[h_out2, 0, 0, 0]), STATUS_SUCCESS);
    let free = mem.read_u64(h_out2).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[free, 0, zero_timeout]), STATUS_WAIT_0);
}

/// A zero-timeout wait on an UNsignaled auto-reset event is a poll: it reports
/// `STATUS_TIMEOUT` immediately without blocking.
#[test]
fn nt_zero_timeout_poll_times_out() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let zero_timeout = SCRATCH + 0x80;
    // auto-reset, initial UNsignaled.
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, 0, SYNCHRONIZATION_EVENT, 0]);
    let ev = mem.read_u64(h_out).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[ev, 0, zero_timeout]), STATUS_TIMEOUT);
}

/// `NtOpenEvent` resolves a name an `NtCreateEvent` planted (prefix-stripped so
/// `\BaseNamedObjects\Evt` meets the bare `Evt`), a missing name is
/// `STATUS_OBJECT_NAME_NOT_FOUND`, and the same object is reachable through the
/// Win32 `OpenEventW` seam — one shared named-object namespace.
#[test]
fn nt_open_event_by_name_and_win32_interop() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;

    // NtCreateEvent with a \BaseNamedObjects\-prefixed NT name → stored as "Evt".
    let create_attr = put_objattr(&mut mem, SCRATCH + 0x100, "\\BaseNamedObjects\\Evt");
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, create_attr, NOTIFICATION_EVENT, 1]);
    let created = mem.read_u64(h_out).unwrap();
    assert_ne!(created, 0);

    // NtOpenEvent with the bare name resolves the same object.
    let open_attr = put_objattr(&mut mem, SCRATCH + 0x300, "Evt");
    let h_out2 = SCRATCH + 0x8;
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_EVENT, &[h_out2, 0, open_attr]), STATUS_SUCCESS);
    assert_eq!(mem.read_u64(h_out2).unwrap(), created, "NtOpenEvent found the NtCreateEvent'd object");

    // A name that names nothing → OBJECT_NAME_NOT_FOUND.
    let miss_attr = put_objattr(&mut mem, SCRATCH + 0x500, "Nope");
    let h_out3 = SCRATCH + 0x10;
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_EVENT, &[h_out3, 0, miss_attr]), STATUS_OBJECT_NAME_NOT_FOUND);

    // Win32 interop: OpenEventW(access, inherit, "Evt") through the thunk seam
    // resolves the *same* object the NT syscall created.
    let name_w = SCRATCH + 0x700;
    for (i, u) in "Evt".encode_utf16().chain(std::iter::once(0)).enumerate() {
        mem.write_u16(name_w + (i as u64) * 2, u).unwrap();
    }
    let open_event_w = os.resolve_import("kernel32.dll", &ImportSymbol::Named("OpenEventW".into()));
    let win32 = call_win32_openevent(&mut os, &mut mem, open_event_w, name_w);
    assert_eq!(win32, created, "Win32 OpenEventW sees the NT-created named object");
}

/// Drive a Win32 `OpenEventW(dwDesiredAccess, bInheritHandle, lpName)` through
/// the intercept seam: RCX=access, RDX=inherit, R8=lpName; returns RAX.
fn call_win32_openevent(os: &mut WinOs, mem: &mut VirtualMemory, thunk: u64, name_w: u64) -> u64 {
    // `mov rcx,0; mov rdx,0; mov r8,name; mov rax,thunk; call rax; hlt`, with a
    // return slot on the stack for the seam's simulated `ret`.
    let mut a: Vec<u8> = Vec::new();
    a.extend_from_slice(&[0x48, 0xB9]);
    a.extend_from_slice(&0u64.to_le_bytes()); // mov rcx, 0
    a.extend_from_slice(&[0x48, 0xBA]);
    a.extend_from_slice(&0u64.to_le_bytes()); // mov rdx, 0
    a.extend_from_slice(&[0x49, 0xB8]);
    a.extend_from_slice(&name_w.to_le_bytes()); // mov r8, name_w
    a.extend_from_slice(&[0x48, 0xB8]);
    a.extend_from_slice(&thunk.to_le_bytes()); // mov rax, thunk
    a.extend_from_slice(&[0xFF, 0xD0]); // call rax
    a.push(0xF4); // hlt
    mem.poke(CODE, &a).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(STACK_TOP - 0x100);
        s.gs_base = GS_BASE;
    }
    loop {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(exemu_core::Reg::Rax)
}

/// An unknown handle is rejected by the strict NT wait/signal paths (unlike the
/// permissive Win32 face).
#[test]
fn nt_bad_handle_is_invalid_handle() {
    let (mut os, mut mem) = setup();
    let bad = 0xDEAD_BEEF;
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[bad, 0, 0]), STATUS_INVALID_HANDLE);
    assert_eq!(syscall(&mut os, &mut mem, NT_SET_EVENT, &[bad, 0]), STATUS_INVALID_HANDLE);
}

/// The honest deadlock: a single-threaded infinite wait on an UNsignaled event
/// has nobody to signal it and no timed wakeup — the NT path must NOT fabricate
/// success (design §5.4). It surfaces as an emulator fault naming the deadlock.
#[test]
fn nt_infinite_wait_single_thread_deadlocks() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    // auto-reset, initial UNsignaled.
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, 0, SYNCHRONIZATION_EVENT, 0]);
    let ev = mem.read_u64(h_out).unwrap();
    // Infinite timeout (NULL PLARGE_INTEGER = arg2 0). No other thread → deadlock.
    let err = try_syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[ev, 0, 0]).unwrap_err();
    match err.cause() {
        EmuError::Os(msg) => assert!(msg.contains("deadlock"), "fault names the deadlock: {msg}"),
        other => panic!("expected an Os deadlock fault, got {other:?}"),
    }
}

// ==========================================================================
// Cross-thread harness: a full guest with a consumer + producer thread, driven
// on ONE interpreter through the scheduler (copied from the server.rs pattern).
// The blocking wait rewinds its SYSCALL and switches; the producer signals and
// exits; the consumer's SYSCALL re-executes and completes.
// ==========================================================================

const PROG: u64 = 0x0000_0000_0040_0000; // code + cells (RWX)
const MAIN: u64 = 0x0000_0000_0040_1000;
const WORKER: u64 = 0x0000_0000_0040_1800;
const HANDLE_CELL: u64 = 0x0000_0000_0040_3000; // event/handle main → worker
const FLAG: u64 = 0x0000_0000_0040_3008; // producer sentinel
const RESULT_STATUS: u64 = 0x0000_0000_0040_3010; // the blocking wait's RAX
const RESULT_FLAG: u64 = 0x0000_0000_0040_3018; // FLAG as seen after the wait
const RESULT_POLL: u64 = 0x0000_0000_0040_3020; // trailing zero-timeout wait RAX
const OUT_HANDLE: u64 = 0x0000_0000_0040_3028; // NtCreateEvent PHANDLE out
const TIMEOUT0: u64 = 0x0000_0000_0040_3030; // a cell holding 0 (poll timeout)
const HANDLES: u64 = 0x0000_0000_0040_3040; // HANDLE[2] for wait-multiple

/// A tiny x86-64 emitter for the forms the cross-thread guests need.
struct Asm(Vec<u8>);
impl Asm {
    fn new() -> Self {
        Asm(Vec::new())
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn mov_r10_imm(&mut self, v: u64) {
        self.0.extend([0x49, 0xBA]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_edx_imm(&mut self, v: u32) {
        self.0.push(0xBA);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_r8_imm(&mut self, v: u64) {
        self.0.extend([0x49, 0xB8]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_r9d_imm(&mut self, v: u32) {
        self.0.extend([0x41, 0xB9]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_eax_imm(&mut self, v: u32) {
        self.0.push(0xB8);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_rax_imm(&mut self, v: u64) {
        self.0.extend([0x48, 0xB8]);
        self.0.extend(v.to_le_bytes());
    }
    fn syscall(&mut self) {
        self.0.extend([0x0F, 0x05]);
    }
    fn call_rax(&mut self) {
        self.0.extend([0xFF, 0xD0]);
    }
    /// `mov r10, [addr]` via r11 scratch.
    fn load_r10_from(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x4D, 0x8B, 0x13]);
    }
    /// `mov rax, [addr]` via r11 scratch.
    fn load_rax_from(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x8B, 0x03]);
    }
    /// `mov [addr], rax` via r11 scratch.
    fn store_rax_to(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x89, 0x03]);
    }
    /// `CreateThread(NULL, 0, entry, NULL, 0, NULL)` — win64 ABI, 2 stack args.
    fn create_thread(&mut self, thunk: u64, entry: u64) {
        self.raw(&[0x48, 0x83, 0xEC, 0x38]); // sub rsp, 0x38
        self.raw(&[0x31, 0xC9]); // xor ecx, ecx
        self.raw(&[0x31, 0xD2]); // xor edx, edx
        self.mov_r8_imm(entry);
        self.raw(&[0x45, 0x31, 0xC9]); // xor r9d, r9d
        self.raw(&[0x31, 0xC0]); // xor eax, eax
        self.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
        self.raw(&[0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax
        self.mov_rax_imm(thunk);
        self.call_rax();
        self.raw(&[0x48, 0x83, 0xC4, 0x38]); // add rsp, 0x38
    }
}

fn cross_thread_env() -> (WinOs, VirtualMemory, u64) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", PROG, 0x8000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    let create_thread = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    (os, mem, create_thread)
}

fn run_to_halt(os: &mut WinOs, mem: &mut VirtualMemory) {
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = MAIN;
        s.set_rsp(STACK_TOP - 0x100);
        s.gs_base = GS_BASE;
    }
    let mut halted = false;
    for _ in 0..200_000 {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => {}
            Exit::Halted => {
                halted = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(halted, "the guest never reached its hlt — a wait hung or a thread was corrupted");
}

/// De-risk 1: a consumer creates an auto-reset UNsignaled event via a raw
/// `NtCreateEvent`, spawns a producer, and blocks in `NtWaitForSingleObject`
/// (infinite timeout). The producer writes a sentinel, `NtSetEvent`s via a raw
/// SYSCALL, and exits; the consumer resumes with `STATUS_WAIT_0` and must
/// observe the sentinel — proving a REAL block → switch → signal → re-execute
/// handoff, not a speculative `WAIT_OBJECT_0`. A trailing zero-timeout poll then
/// reports `STATUS_TIMEOUT`, proving the auto-reset event was consumed.
#[test]
fn nt_producer_consumer_event_cross_thread() {
    let (mut os, mut mem, create_thread) = cross_thread_env();

    // --- consumer (main) ---
    let mut m = Asm::new();
    // NtCreateEvent(&OUT_HANDLE, 0, NULL, SynchronizationEvent, InitialState=0).
    m.mov_r10_imm(OUT_HANDLE); // arg0
    m.mov_edx_imm(0); // arg1 access
    m.mov_r8_imm(0); // arg2 objattr NULL
    m.mov_r9d_imm(SYNCHRONIZATION_EVENT as u32); // arg3 auto-reset
    // arg4 InitialState is at [rsp+0x28] = 0 (zero-filled stack).
    m.mov_eax_imm(NT_CREATE_EVENT);
    m.syscall();
    // Publish the handle to the worker and remember it locally.
    m.load_rax_from(OUT_HANDLE);
    m.store_rax_to(HANDLE_CELL);
    // Spawn the producer.
    m.create_thread(create_thread, WORKER);
    // The blocking wait: NtWaitForSingleObject(handle, alertable=0, timeout=NULL).
    m.load_r10_from(HANDLE_CELL); // arg0 = handle
    m.mov_edx_imm(0); // arg1 alertable
    m.mov_r8_imm(0); // arg2 timeout NULL → infinite
    m.mov_eax_imm(NT_WAIT_FOR_SINGLE_OBJECT);
    m.syscall();
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    // Trailing poll: the auto-reset event was consumed → STATUS_TIMEOUT.
    m.load_r10_from(HANDLE_CELL);
    m.mov_edx_imm(0);
    m.mov_r8_imm(TIMEOUT0); // *TIMEOUT0 == 0 → poll
    m.mov_eax_imm(NT_WAIT_FOR_SINGLE_OBJECT);
    m.syscall();
    m.store_rax_to(RESULT_POLL);
    m.0.push(0xF4); // hlt
    mem.write(MAIN, &m.0).unwrap();

    // --- producer (worker): sentinel first, then NtSetEvent, then exit ---
    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_r10_from(HANDLE_CELL); // arg0 = handle
    w.mov_edx_imm(0); // arg1 PreviousState NULL
    w.mov_eax_imm(NT_SET_EVENT);
    w.syscall();
    w.0.extend([0x31, 0xC0]); // xor eax, eax
    w.0.push(0xC3); // ret → thread exit
    mem.write(WORKER, &w.0).unwrap();

    run_to_halt(&mut os, &mut mem);

    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer resumed only after the producer signaled");
    assert_eq!(mem.read_u64(RESULT_STATUS).unwrap(), STATUS_WAIT_0, "blocking wait returned STATUS_WAIT_0");
    assert_eq!(mem.read_u64(RESULT_POLL).unwrap(), STATUS_TIMEOUT, "auto-reset event consumed by the wait");
}

/// De-risk 2: `NtWaitForMultipleObjects(WaitAny)` over two UNsignaled events
/// returns `STATUS_WAIT_0 + 1` after a real block when the producer signals the
/// handle at index 1 (the wait-any index reporting the W2.11 server lacks).
#[test]
fn nt_wait_for_multiple_wait_any_reports_index() {
    let (mut os, mut mem, create_thread) = cross_thread_env();
    let out0 = OUT_HANDLE;
    let out1 = OUT_HANDLE + 8;

    // --- consumer (main) ---
    let mut m = Asm::new();
    // Create two auto-reset UNsignaled events → HANDLES[0], HANDLES[1].
    for out in [out0, out1] {
        m.mov_r10_imm(out);
        m.mov_edx_imm(0);
        m.mov_r8_imm(0);
        m.mov_r9d_imm(SYNCHRONIZATION_EVENT as u32);
        m.mov_eax_imm(NT_CREATE_EVENT);
        m.syscall();
    }
    m.load_rax_from(out0);
    m.store_rax_to(HANDLES);
    m.load_rax_from(out1);
    m.store_rax_to(HANDLES + 8);
    m.store_rax_to(HANDLE_CELL); // the worker signals handle index 1
    // Spawn the producer.
    m.create_thread(create_thread, WORKER);
    // NtWaitForMultipleObjects(2, &HANDLES, WaitAny, alertable=0, timeout=NULL).
    m.mov_r10_imm(2); // arg0 count
    m.raw(&[0x48, 0xBA]); // mov rdx, imm64
    m.0.extend(HANDLES.to_le_bytes()); // arg1 &HANDLES
    m.mov_r8_imm(WAIT_ANY); // arg2 WaitType = WaitAny
    m.mov_r9d_imm(0); // arg3 alertable
    // arg4 timeout at [rsp+0x28] = 0 (NULL) → infinite (zero-filled stack).
    m.mov_eax_imm(NT_WAIT_FOR_MULTIPLE_OBJECTS);
    m.syscall();
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    m.0.push(0xF4); // hlt
    mem.write(MAIN, &m.0).unwrap();

    // --- producer: sentinel, then NtSetEvent on handle index 1, then exit ---
    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_r10_from(HANDLE_CELL);
    w.mov_edx_imm(0);
    w.mov_eax_imm(NT_SET_EVENT);
    w.syscall();
    w.0.extend([0x31, 0xC0]);
    w.0.push(0xC3);
    mem.write(WORKER, &w.0).unwrap();

    run_to_halt(&mut os, &mut mem);

    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer really blocked until the producer ran");
    assert_eq!(
        mem.read_u64(RESULT_STATUS).unwrap(),
        STATUS_WAIT_0 + 1,
        "wait-any reports the satisfied handle's index (1)"
    );
}
