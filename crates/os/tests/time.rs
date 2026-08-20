//! Tests for the host-clock-backed time/date APIs (roadmap P3.8), driven
//! through `Hooks::intercept`. The old stubs wrote 0 for everything; these must
//! report real, advancing, plausible values.

use exemu_core::{CpuState, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const RSP: u64 = 0x0000_0010_0000_1000;
const RETADDR: u64 = 0x0000_0001_4000_1000;
const OUT: u64 = 0x0000_0000_5000_0000;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", 0x0000_0010_0000_0000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("out", OUT, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem)
}

fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, arg0: u64) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    cpu.set_reg(Reg::Rcx, arg0);
    cpu.rip = thunk;
    os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(cpu.rip, RETADDR, "{name} must ret");
    cpu.reg(Reg::Rax)
}

#[test]
fn qpf_is_fixed_and_qpc_is_monotonic() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();

    assert_eq!(call(&mut os, &mut mem, &mut cpu, "QueryPerformanceFrequency", OUT), 1);
    assert_eq!(mem.read_u64(OUT).unwrap(), 10_000_000, "QPF should be 10 MHz");

    call(&mut os, &mut mem, &mut cpu, "QueryPerformanceCounter", OUT);
    let t0 = mem.read_u64(OUT).unwrap();
    call(&mut os, &mut mem, &mut cpu, "QueryPerformanceCounter", OUT + 8);
    let t1 = mem.read_u64(OUT + 8).unwrap();
    assert!(t1 >= t0, "QPC must be monotonic non-decreasing ({t0} -> {t1})");
}

#[test]
fn tick_count_is_reasonable() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    // Milliseconds since process start: small, and non-decreasing across calls.
    let a = call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0);
    let b = call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0);
    assert!(b >= a, "GetTickCount must not go backwards");
    assert!(a < 60_000, "process is younger than a minute in-test");
}

#[test]
fn system_time_as_filetime_is_a_recent_date() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "GetSystemTimeAsFileTime", OUT);
    let ft = mem.read_u64(OUT).unwrap();
    // FILETIME for 2020-01-01 is 132223104000000000; year ~2064 is ~1.6e17.
    assert!(ft > 132_223_104_000_000_000, "FILETIME predates 2020");
    assert!(ft < 160_000_000_000_000_000, "FILETIME implausibly far in the future");
}

#[test]
fn system_time_fields_are_valid() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "GetSystemTime", OUT);
    let year = mem.read_u16(OUT).unwrap();
    let month = mem.read_u16(OUT + 2).unwrap();
    let dow = mem.read_u16(OUT + 4).unwrap();
    let day = mem.read_u16(OUT + 6).unwrap();
    let hour = mem.read_u16(OUT + 8).unwrap();
    let minute = mem.read_u16(OUT + 10).unwrap();
    let second = mem.read_u16(OUT + 12).unwrap();
    assert!((2020..2200).contains(&year), "year {year}");
    assert!((1..=12).contains(&month), "month {month}");
    assert!(dow < 7, "day-of-week {dow}");
    assert!((1..=31).contains(&day), "day {day}");
    assert!(hour < 24 && minute < 60 && second < 60, "{hour}:{minute}:{second}");
}

// ---- the deterministic clock (roadmap W9.6) --------------------------------

/// Every Win32 time API reads the SAME virtual clock, and each is exactly the
/// documented function of the retired-instruction count — 10M instructions is
/// one second, however long the host took to execute them.
#[test]
fn the_virtual_clock_drives_every_win32_time_api() {
    let clock = exemu_core::GuestClock::virtualized();
    let (mut os, mut mem) = setup();
    os.set_clock(clock.clone());
    let mut cpu = CpuState::default();

    // Retire one virtual second's worth of guest instructions.
    for _ in 0..exemu_core::VIRTUAL_INSTRUCTIONS_PER_SECOND {
        clock.retire_one();
    }

    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0), 1_000, "one virtual second");
    call(&mut os, &mut mem, &mut cpu, "QueryPerformanceCounter", OUT);
    assert_eq!(mem.read_u64(OUT).unwrap(), 10_000_000, "QPC ticks == instructions retired");
    call(&mut os, &mut mem, &mut cpu, "QueryPerformanceFrequency", OUT);
    assert_eq!(mem.read_u64(OUT).unwrap(), 10_000_000, "the QPC rate is unchanged");

    call(&mut os, &mut mem, &mut cpu, "GetSystemTimeAsFileTime", OUT);
    assert_eq!(
        mem.read_u64(OUT).unwrap(),
        exemu_core::VIRTUAL_EPOCH_FILETIME + 10_000_000,
        "the wall clock is the fixed epoch plus the elapsed virtual time"
    );

    // …and the broken-out SYSTEMTIME agrees: 2026-01-01T00:00:01Z, a Thursday.
    call(&mut os, &mut mem, &mut cpu, "GetSystemTime", OUT);
    let f = |i: u64| mem.read_u16(OUT + i * 2).unwrap();
    assert_eq!((f(0), f(1), f(3)), (2026, 1, 1), "2026-01-01");
    assert_eq!(f(2), 4, "1 January 2026 is a Thursday");
    assert_eq!((f(4), f(5), f(6), f(7)), (0, 0, 1, 0), "00:00:01.000");
}

/// The point of the exercise: replay. Two identical call sequences against two
/// fresh virtual clocks produce byte-identical answers — so a guest that
/// branches on a timestamp takes the same branch every run.
#[test]
fn the_virtual_clock_replays_exactly() {
    let one_pass = || {
        let clock = exemu_core::GuestClock::virtualized();
        let (mut os, mut mem) = setup();
        os.set_clock(clock.clone());
        let mut cpu = CpuState::default();
        let mut trace = Vec::new();
        for i in 0..8u64 {
            // A guest doing work between clock reads: the "work" is instructions.
            for _ in 0..(1_000 * (i + 1)) {
                clock.retire_one();
            }
            trace.push(call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0));
            call(&mut os, &mut mem, &mut cpu, "QueryPerformanceCounter", OUT);
            trace.push(mem.read_u64(OUT).unwrap());
            call(&mut os, &mut mem, &mut cpu, "GetSystemTimeAsFileTime", OUT);
            trace.push(mem.read_u64(OUT).unwrap());
        }
        trace
    };
    assert_eq!(one_pass(), one_pass(), "the same guest run observes the same times");
}

/// `Sleep(ms)` is a cooperative yield that costs one instruction, so without a
/// credit a `Sleep`-paced timeout loop would take 10^4 iterations per virtual
/// millisecond to escape. Crediting the interval the guest asked for keeps such
/// loops terminating — deterministically, since the interval is the guest's own
/// argument (roadmap W9.6).
#[test]
fn a_slept_interval_advances_the_virtual_clock() {
    let clock = exemu_core::GuestClock::virtualized();
    let (mut os, mut mem) = setup();
    os.set_clock(clock.clone());
    let mut cpu = CpuState::default();

    let t0 = call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0);
    call(&mut os, &mut mem, &mut cpu, "Sleep", 250);
    let t1 = call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0);
    assert_eq!(t1 - t0, 250, "the guest observes the interval it asked to sleep");

    // INFINITE names no interval, so it must not skip the clock forward.
    call(&mut os, &mut mem, &mut cpu, "Sleep", 0xFFFF_FFFF);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetTickCount", 0), t1);
}

/// The default is unchanged: the clock declines to answer and every API falls
/// back to the host, so nothing about the shipped behaviour moves.
#[test]
fn the_host_clock_stays_the_default() {
    let (mut os, mut mem) = setup();
    assert!(!os.clock().is_virtual(), "host clock unless explicitly asked for");
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "GetSystemTimeAsFileTime", OUT);
    let ft = mem.read_u64(OUT).unwrap();
    assert!(
        ft > exemu_core::VIRTUAL_EPOCH_FILETIME,
        "the default path reports the real host clock, not the virtual epoch"
    );
}
