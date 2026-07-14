//! Time and date APIs backed by the host clock (roadmap P3.8).
//!
//! `GetTickCount`/`QueryPerformanceCounter` measure from the process start
//! instant (monotonic); `GetSystemTimeAsFileTime`/`GetSystemTime`/`GetLocalTime`
//! report the real wall-clock time. These were previously stubs that always
//! returned 0 — enough to null-deref-avoid, but a program computing
//! `elapsed = now - start` then dividing by it, or seeding a temp name from the
//! clock, needs real, advancing values.

use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{CpuState, Memory, Result};

use crate::api::Outcome;
use crate::WinOs;

/// The `QueryPerformanceFrequency` value we report: 10 MHz, so a performance
/// counter tick is 100 ns — matching a common Windows QPC frequency and making
/// the counter directly convertible to/from `FILETIME` units.
pub(crate) const QPC_FREQ: u64 = 10_000_000;

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

/// Current wall-clock time as a Windows FILETIME (100-ns ticks since 1601).
pub(crate) fn filetime_now() -> u64 {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (dur.as_secs() + EPOCH_DIFF_SECS) * QPC_FREQ + dur.subsec_nanos() as u64 / 100
}

/// Break a FILETIME into SYSTEMTIME fields (UTC): year, month, day, day-of-week
/// (0 = Sunday), hour, minute, second, millisecond.
fn systemtime_fields(filetime: u64) -> [u16; 8] {
    let ticks = filetime; // 100-ns units since 1601
    let secs_since_1601 = ticks / QPC_FREQ;
    let ms = ((ticks % QPC_FREQ) / 10_000) as u16;
    let secs_since_1970 = secs_since_1601 as i64 - EPOCH_DIFF_SECS as i64;
    let days = secs_since_1970.div_euclid(86_400);
    let secs_of_day = secs_since_1970.rem_euclid(86_400);
    let (hour, minute, second) = ((secs_of_day / 3600) as u16, ((secs_of_day % 3600) / 60) as u16, (secs_of_day % 60) as u16);

    // Howard Hinnant's civil-from-days (days since 1970-01-01).
    let mut z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u16; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u16; // [1, 12]
    let year = (year + i64::from(month <= 2)) as u16;

    // Day of week: 1970-01-01 was a Thursday (weekday 4, Sunday = 0).
    z = days;
    let dow = (z.rem_euclid(7) + 4).rem_euclid(7) as u16;

    [year, month, dow, day, hour, minute, second, ms]
}

impl WinOs {
    fn elapsed_100ns(&self) -> u64 {
        (self.start_time.elapsed().as_nanos() / 100) as u64
    }

    /// GetTickCount()/GetTickCount64(): milliseconds since process start.
    pub(crate) fn get_tick_count(&self) -> Result<Outcome> {
        Ok(Outcome::Return(self.start_time.elapsed().as_millis() as u64))
    }

    /// QueryPerformanceCounter(*lpPerformanceCount): 100-ns ticks since start.
    pub(crate) fn query_performance_counter(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            mem.write_u64(ptr, self.elapsed_100ns())?;
        }
        Ok(Outcome::Return(1))
    }

    /// QueryPerformanceFrequency(*lpFrequency): the fixed QPC rate.
    pub(crate) fn query_performance_frequency(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            mem.write_u64(ptr, QPC_FREQ)?;
        }
        Ok(Outcome::Return(1))
    }

    /// GetSystemTimeAsFileTime / GetSystemTimePreciseAsFileTime(*lpFileTime).
    pub(crate) fn get_system_time_as_filetime(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            mem.write_u64(ptr, filetime_now())?; // FILETIME is two DWORDs, little-endian == u64
        }
        Ok(Outcome::Return(0))
    }

    /// GetSystemTime / GetLocalTime(*lpSystemTime) — fills a SYSTEMTIME (UTC; we
    /// do not model a local timezone offset).
    pub(crate) fn get_system_time(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            let f = systemtime_fields(filetime_now());
            for (i, field) in f.iter().enumerate() {
                mem.write_u16(ptr + i as u64 * 2, *field)?;
            }
        }
        Ok(Outcome::Return(0))
    }

    // ---- NT time syscalls (roadmap W2.14) --------------------------------
    //
    // The NTSTATUS face of the same host-clock math the Win32 seam uses,
    // reached via a raw guest `SYSCALL` through the W2.3 dispatcher. Args come
    // via [`WinOs::syscall_arg`] (arg0=R10, arg1=RDX, …). Signatures are the
    // public NT headers (winternl.h / ntddk.h); no Wine `.c` read.
    //
    // `NtGetTickCount` is deliberately absent: on x64 it is NOT a syscall — the
    // pinned guest ntdll implements it inline by reading `KUSER_SHARED_DATA.
    // TickCount` (`gs`-free RIP-relative load), so there is no SSDT slot to fill.
    // Keeping that page live is the standing W2.1/W2.10 follow-up (the page is
    // guest-read-only, so it needs a permission-bypassing host writer).

    /// `NtQuerySystemTime(PLARGE_INTEGER SystemTime)` — current wall-clock time
    /// as a FILETIME (100-ns ticks since 1601). NULL out-pointer →
    /// STATUS_ACCESS_VIOLATION.
    pub(crate) fn nt_query_system_time(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let ptr = self.syscall_arg(cpu, mem, 0)?;
        if ptr == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write_u64(ptr, filetime_now())?;
        Ok(NT_STATUS_SUCCESS)
    }

    /// `NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter,
    /// PLARGE_INTEGER PerformanceFrequency OPTIONAL)` — the monotonic 100-ns
    /// counter since process start, and (if non-NULL) the fixed QPC rate. NULL
    /// counter → STATUS_ACCESS_VIOLATION.
    pub(crate) fn nt_query_performance_counter(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let counter_ptr = self.syscall_arg(cpu, mem, 0)?;
        let freq_ptr = self.syscall_arg(cpu, mem, 1)?;
        if counter_ptr == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write_u64(counter_ptr, self.elapsed_100ns())?;
        if freq_ptr != 0 {
            mem.write_u64(freq_ptr, QPC_FREQ)?;
        }
        Ok(NT_STATUS_SUCCESS)
    }
}

// NTSTATUS codes.
const NT_STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

// SSDT indices (pinned guest ntdll.dll `mov eax,N`).
pub(crate) const SSDT_NT_QUERY_PERFORMANCE_COUNTER: u32 = 0x31;
pub(crate) const SSDT_NT_QUERY_SYSTEM_TIME: u32 = 0x5a;

pub(crate) fn ssdt_nt_query_system_time(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_system_time(cpu, mem)
}
pub(crate) fn ssdt_nt_query_performance_counter(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_performance_counter(cpu, mem)
}
