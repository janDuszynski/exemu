//! W2.14 — the NT time syscalls (`NtQuerySystemTime`/`NtQueryPerformanceCounter`),
//! driven end-to-end through the real interpreter + the W2.3 SSDT dispatcher
//! exactly as a Wine PE `Nt*` stub would (`mov r10,rcx; mov eax,N; syscall`).
//!
//! De-risk (roadmap W2.14 "clock read"): `NtQuerySystemTime` returns a FILETIME
//! bracketed by the host clock taken before/after the call; `NtQueryPerformance-
//! Counter` returns a monotonically non-decreasing counter and the fixed QPC
//! frequency. (`NtGetTickCount` is not a syscall on x64 — it is an inline
//! KUSER_SHARED_DATA read — so there is no syscall path to drive here.)

use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
const NT_QUERY_SYSTEM_TIME: u32 = 0x5a;
const NT_QUERY_PERFORMANCE_COUNTER: u32 = 0x31;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;

// QueryPerformanceFrequency value (time.rs QPC_FREQ = 10 MHz).
const QPC_FREQ: u64 = 10_000_000;
const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
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

/// Assemble `mov rcx,arg0; mov r10,rcx; mov eax,N; syscall; hlt`, run it, return RAX.
fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    syscall_on(os, mem, index, args, None)
}

/// As [`syscall`], but optionally running the interpreter on `clock` so the
/// retired instructions of the stub itself advance the virtual clock — the way
/// they do inside a real run (roadmap W9.6).
fn syscall_on(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    index: u32,
    args: &[u64],
    clock: Option<&exemu_core::GuestClock>,
) -> u64 {
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
    if let Some(c) = clock {
        cpu.set_clock(c.clone());
    }
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
    loop {
        match cpu.step(mem, os).expect("syscall faulted") {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(exemu_core::Reg::Rax)
}

fn filetime_host_now() -> u64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (d.as_secs() + EPOCH_DIFF_SECS) * QPC_FREQ + d.subsec_nanos() as u64 / 100
}

#[test]
fn nt_query_system_time_matches_host_clock() {
    let (mut os, mut mem) = setup();
    let out = SCRATCH;

    let before = filetime_host_now();
    assert_eq!(syscall(&mut os, &mut mem, NT_QUERY_SYSTEM_TIME, &[out]), STATUS_SUCCESS);
    let after = filetime_host_now();

    let t = mem.read_u64(out).unwrap();
    // The reported FILETIME is bracketed by the host clock either side of the call.
    assert!(before <= t && t <= after, "system time {t} not in [{before}, {after}]");

    // NULL out-pointer → STATUS_ACCESS_VIOLATION.
    assert_eq!(syscall(&mut os, &mut mem, NT_QUERY_SYSTEM_TIME, &[0]), STATUS_ACCESS_VIOLATION);
}

#[test]
fn nt_query_performance_counter_is_monotonic_and_reports_frequency() {
    let (mut os, mut mem) = setup();
    let counter = SCRATCH;
    let freq = SCRATCH + 0x40;

    // Counter + frequency in one call.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_PERFORMANCE_COUNTER, &[counter, freq]),
        STATUS_SUCCESS
    );
    let first = mem.read_u64(counter).unwrap();
    assert_eq!(mem.read_u64(freq).unwrap(), QPC_FREQ);

    // A later call is monotonically non-decreasing.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_PERFORMANCE_COUNTER, &[counter, 0]),
        STATUS_SUCCESS
    );
    let second = mem.read_u64(counter).unwrap();
    assert!(second >= first, "counter went backwards: {second} < {first}");

    // NULL counter → STATUS_ACCESS_VIOLATION (frequency-only is not a valid call).
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_PERFORMANCE_COUNTER, &[0, freq]),
        STATUS_ACCESS_VIOLATION
    );
}

// ---- the deterministic clock (roadmap W9.6) --------------------------------

/// `NtQuerySystemTime` under the virtual clock reports the **fixed epoch plus
/// the instruction count**, not the host's now — and two runs of the identical
/// syscall sequence agree bit for bit. That equality is the property W8.7 needs:
/// a JIT can only be diffed against the interpreter if the guest's clock reads
/// are replayable.
#[test]
fn the_virtual_clock_replays_the_nt_time_syscalls_exactly() {
    let one_pass = || {
        let clock = exemu_core::GuestClock::virtualized();
        let (mut os, mut mem) = setup();
        os.set_clock(clock.clone());
        let (counter, freq) = (SCRATCH, SCRATCH + 0x40);

        assert_eq!(
            syscall_on(&mut os, &mut mem, NT_QUERY_SYSTEM_TIME, &[SCRATCH + 0x80], Some(&clock)),
            STATUS_SUCCESS
        );
        let wall = mem.read_u64(SCRATCH + 0x80).unwrap();
        assert_eq!(
            syscall_on(&mut os, &mut mem, NT_QUERY_PERFORMANCE_COUNTER, &[counter, freq], Some(&clock)),
            STATUS_SUCCESS
        );
        assert_eq!(mem.read_u64(freq).unwrap(), QPC_FREQ);
        let qpc = mem.read_u64(counter).unwrap();
        (wall, qpc, clock.instret())
    };

    let (wall_a, qpc_a, instret_a) = one_pass();
    let (wall_b, qpc_b, instret_b) = one_pass();
    assert_eq!((wall_a, qpc_a, instret_a), (wall_b, qpc_b, instret_b), "the run replays exactly");

    // The performance counter IS the instruction count (one 100-ns tick each),
    // and the wall clock is that same count offset from the fixed epoch — so
    // neither can encode anything about the host.
    assert!(qpc_a > 0 && qpc_a < instret_a, "counter is the retired count at the time of the read");
    let uptime = wall_a - exemu_core::VIRTUAL_EPOCH_FILETIME;
    assert!(
        (1..1_000).contains(&uptime),
        "a handful of instructions in, the wall clock is {uptime} × 100 ns past the fixed \
         2026-01-01 epoch — a host clock would be ~10^16 ticks past it"
    );
}

