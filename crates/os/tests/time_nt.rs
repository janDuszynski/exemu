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
