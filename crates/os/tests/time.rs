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
