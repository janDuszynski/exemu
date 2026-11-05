use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{CpuState, Memory, Result};

use crate::api::Outcome;
use crate::WinOs;

pub(crate) const QPC_FREQ: u64 = exemu_core::QPC_FREQUENCY;

const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

pub(crate) fn filetime_now() -> u64 {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (dur.as_secs() + EPOCH_DIFF_SECS) * QPC_FREQ + dur.subsec_nanos() as u64 / 100
}

fn systemtime_fields(filetime: u64) -> [u16; 8] {
    let ticks = filetime;
    let secs_since_1601 = ticks / QPC_FREQ;
    let ms = ((ticks % QPC_FREQ) / 10_000) as u16;
    let secs_since_1970 = secs_since_1601 as i64 - EPOCH_DIFF_SECS as i64;
    let days = secs_since_1970.div_euclid(86_400);
    let secs_of_day = secs_since_1970.rem_euclid(86_400);
    let (hour, minute, second) = ((secs_of_day / 3600) as u16, ((secs_of_day % 3600) / 60) as u16, (secs_of_day % 60) as u16);

    let mut z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u16;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u16;
    let year = (year + i64::from(month <= 2)) as u16;

    z = days;
    let dow = (z.rem_euclid(7) + 4).rem_euclid(7) as u16;

    [year, month, dow, day, hour, minute, second, ms]
}

impl WinOs {

    pub(crate) fn filetime_now(&self) -> u64 {
        self.clock.filetime().unwrap_or_else(filetime_now)
    }

    pub(crate) fn monotonic_100ns(&self) -> u64 {
        self.clock
            .monotonic_100ns()
            .unwrap_or_else(|| (self.start_time.elapsed().as_nanos() / 100) as u64)
    }

    pub(crate) fn tick_count_ms(&self) -> u64 {
        self.clock
            .tick_count_ms()
            .unwrap_or_else(|| self.start_time.elapsed().as_millis() as u64)
    }

    pub(crate) fn get_tick_count(&self) -> Result<Outcome> {
        Ok(Outcome::Return(self.tick_count_ms()))
    }

    pub(crate) fn query_performance_counter(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            mem.write_u64(ptr, self.monotonic_100ns())?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn query_performance_frequency(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            mem.write_u64(ptr, QPC_FREQ)?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn get_system_time_as_filetime(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            let now = self.filetime_now();
            mem.write_u64(ptr, now)?;
        }
        Ok(Outcome::Return(0))
    }

    pub(crate) fn get_system_time(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let ptr = self.arg(cpu, mem, 0)?;
        if ptr != 0 {
            let f = systemtime_fields(self.filetime_now());
            for (i, field) in f.iter().enumerate() {
                mem.write_u16_at(ptr, i as u64 * 2, *field)?;
            }
        }
        Ok(Outcome::Return(0))
    }

    pub(crate) fn nt_query_system_time(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let ptr = self.syscall_arg(cpu, mem, 0)?;
        if ptr == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let now = self.filetime_now();
        mem.write_u64(ptr, now)?;
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_performance_counter(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let counter_ptr = self.syscall_arg(cpu, mem, 0)?;
        let freq_ptr = self.syscall_arg(cpu, mem, 1)?;
        if counter_ptr == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write_u64(counter_ptr, self.monotonic_100ns())?;
        if freq_ptr != 0 {
            mem.write_u64(freq_ptr, QPC_FREQ)?;
        }
        Ok(NT_STATUS_SUCCESS)
    }
}

const NT_STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

pub(crate) const SSDT_NT_QUERY_PERFORMANCE_COUNTER: u32 = 0x31;
pub(crate) const SSDT_NT_QUERY_SYSTEM_TIME: u32 = 0x5a;

pub(crate) fn ssdt_nt_query_system_time(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_system_time(cpu, mem)
}
pub(crate) fn ssdt_nt_query_performance_counter(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_performance_counter(cpu, mem)
}
