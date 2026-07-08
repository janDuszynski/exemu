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
const QPC_FREQ: u64 = 10_000_000;

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

/// Current wall-clock time as a Windows FILETIME (100-ns ticks since 1601).
fn filetime_now() -> u64 {
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
}
