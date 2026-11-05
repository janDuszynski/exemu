use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::{GuestClock, Perm, Region, Result};
use exemu_memory::VirtualMemory;

use crate::PAGE;

pub(crate) const KUSER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER_PAGE: u64 = 0x7ffe_1000;

const KUSER_TICK_COUNT_MULTIPLIER: u64 = 0x004;
const KUSER_INTERRUPT_TIME: u64 = 0x008;
const KUSER_SYSTEM_TIME: u64 = 0x014;
pub(crate) const KUSER_SYSTEM_CALL: u64 = 0x308;
const KUSER_TICK_COUNT: u64 = 0x320;

const KUSER_TICK_PERIOD_100NS: u64 = 156_250;

const KUSER_TICK_COUNT_MULTIPLIER_VALUE: u32 = 0x0FA0_0000;

pub(crate) const KUSER_REFRESH_INSTRUCTIONS: u64 = 65_536;

pub(crate) fn map_kuser_shared_data(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
    mem.map(Region::new(
        "kuser_shared_data",
        KUSER_SHARED_DATA_BASE,
        PAGE,
        Perm::READ,
    ))?;
    mem.map(Region::new(
        "kuser_dispatcher",
        KUSER_DISPATCHER_PAGE,
        PAGE,
        Perm::RWX,
    ))?;

    if clock.is_virtual() {
        refresh_kuser_time(mem, clock)?;
    } else {
        let now_100ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let system_time = (now_100ns.as_secs() + KUSER_FILETIME_EPOCH_DIFF_SECS) * 10_000_000
            + now_100ns.subsec_nanos() as u64 / 100;
        write_ksystem_time(mem, KUSER_SYSTEM_TIME, system_time)?;
        write_ksystem_time(mem, KUSER_INTERRUPT_TIME, 0)?;
        write_ksystem_time(mem, KUSER_TICK_COUNT, 0)?;
    }

    mem.poke(
        KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER,
        &KUSER_TICK_COUNT_MULTIPLIER_VALUE.to_le_bytes(),
    )?;
    mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &1u32.to_le_bytes())?;
    Ok(())
}

fn write_ksystem_time(mem: &mut VirtualMemory, off: u64, val: u64) -> Result<()> {
    let low = (val & 0xFFFF_FFFF) as u32;
    let high = (val >> 32) as u32;
    mem.poke(KUSER_SHARED_DATA_BASE + off, &low.to_le_bytes())?;
    mem.poke(KUSER_SHARED_DATA_BASE + off + 4, &high.to_le_bytes())?;
    mem.poke(KUSER_SHARED_DATA_BASE + off + 8, &high.to_le_bytes())
}

pub(crate) fn refresh_kuser_time(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
    let Some(monotonic) = clock.monotonic_100ns() else { return Ok(()) };
    let Some(filetime) = clock.filetime() else { return Ok(()) };
    write_ksystem_time(mem, KUSER_SYSTEM_TIME, filetime)?;
    write_ksystem_time(mem, KUSER_INTERRUPT_TIME, monotonic)?;
    write_ksystem_time(mem, KUSER_TICK_COUNT, monotonic / KUSER_TICK_PERIOD_100NS)
}

const KUSER_FILETIME_EPOCH_DIFF_SECS: u64 = 11_644_473_600;

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::Memory;

    #[test]
    fn kuser_shared_data_fields_readable() {
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem, &GuestClock::host()).expect("map KUSER_SHARED_DATA");

        assert_eq!(KUSER_SHARED_DATA_BASE, 0x7ffe_0000);

        let system_call = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL)
            .expect("read SystemCall");
        assert_ne!(system_call, 0, "SystemCall selector must be nonzero");

        let system_time_high = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 4)
            .expect("read SystemTime.High1Time");
        assert_ne!(system_time_high, 0, "SystemTime should be a real clock value");
        let system_time_high2 = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 8)
            .expect("read SystemTime.High2Time");
        assert_eq!(system_time_high, system_time_high2);

        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_INTERRUPT_TIME)
                .expect("read InterruptTime"),
            0
        );
        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT)
                .expect("read TickCount"),
            0
        );

        assert_eq!(KUSER_DISPATCHER_PAGE, KUSER_SHARED_DATA_BASE + PAGE);
        mem.read_u8(KUSER_DISPATCHER_PAGE)
            .expect("dispatcher landing page is mapped");

        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER)
                .expect("read TickCountMultiplier"),
            KUSER_TICK_COUNT_MULTIPLIER_VALUE
        );
    }

    #[test]
    fn kuser_time_fields_track_the_virtual_clock() {
        let read_ksystem_time = |mem: &VirtualMemory, off: u64| -> u64 {
            let lo = mem.read_u32(KUSER_SHARED_DATA_BASE + off).unwrap() as u64;
            let hi = mem.read_u32(KUSER_SHARED_DATA_BASE + off + 4).unwrap() as u64;
            (hi << 32) | lo
        };

        let clock = GuestClock::virtualized();
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem, &clock).expect("map KUSER_SHARED_DATA");

        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 0);
        assert_eq!(read_ksystem_time(&mem, KUSER_TICK_COUNT), 0);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME,
            "the wall clock starts at the fixed virtual epoch, not at the host's now"
        );

        for _ in 0..exemu_core::VIRTUAL_INSTRUCTIONS_PER_SECOND {
            clock.retire_one();
        }
        refresh_kuser_time(&mut mem, &clock).expect("refresh");
        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 10_000_000);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME + 10_000_000
        );
        let ticks = read_ksystem_time(&mem, KUSER_TICK_COUNT);
        assert_eq!(ticks, 64);
        let ms = (ticks * u64::from(KUSER_TICK_COUNT_MULTIPLIER_VALUE)) >> 24;
        assert_eq!(ms, 1_000, "the guest's own tick→ms conversion agrees");
    }
}
