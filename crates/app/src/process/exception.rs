use exemu_core::{Cpu, EmuError, Memory, Result};
use exemu_cpu::Bits;

use crate::memory_map;

use super::Process;

pub(super) enum ExcSource<'a> {
    Interrupt(u8),
    Error(&'a EmuError),
}

impl Process {
    pub(super) fn at_exc_dispatcher(&self, rip: u64) -> bool {
        self.os
            .module_base("ntdll.dll")
            .is_some_and(|b| rip == b + exemu_os::RVA_KI_USER_EXCEPTION_DISPATCHER)
    }

    pub(super) fn try_deliver_hw_exception(&mut self, src: ExcSource<'_>, steps: u64, recent: &[u64]) -> Result<bool> {
        let Some(ntdll_base) = self.os.module_base("ntdll.dll") else {
            return Ok(false);
        };
        let mode = if self.wow64.is_some() && self.cpu.bits() == Bits::B32 {
            exemu_os::TrapMode::Compat32
        } else {
            exemu_os::TrapMode::Long
        };
        const MAX_EXC_DEPTH: u32 = 8;
        if self.exc_depth >= MAX_EXC_DEPTH {
            return Ok(false);
        }

        let cpu = self.cpu.state();
        let (code, address, info): (u32, u64, Vec<u64>) = match src {
            ExcSource::Interrupt(0) => (0xC000_0094, cpu.rip, Vec::new()),
            ExcSource::Interrupt(3) => (0x8000_0003, cpu.rip.wrapping_add(1), Vec::new()),
            ExcSource::Error(e) => match e.cause() {
                EmuError::Permission { addr, needed } => {
                    let rw = match *needed {
                        "write" => 1u64,
                        "execute" => 8u64,
                        _ => 0u64,
                    };
                    (0xC000_0005, *addr, vec![rw, *addr])
                }
                EmuError::Unmapped { addr, .. } => (0xC000_0005, *addr, vec![0, *addr]),
                _ => return Ok(false),
            },
            ExcSource::Interrupt(_) => return Ok(false),
        };

        if self.os.note_exception_delivery(code, address, cpu.rip).is_err() {
            return Ok(false);
        }

        if std::env::var_os("EXEMU_FAULT_TRACE").is_some() {
            let rip = self.cpu.state().rip;
            let mut bytes = [0u8; 16];
            let _ = self.mem.read(rip, &mut bytes);
            eprintln!(
                "[exc] code={code:#x} at={address:#x} rip={rip:#x} {} bytes={bytes:02x?}",
                self.os.module_for_addr(rip).unwrap_or_default()
            );
        }

        if std::env::var_os("EXEMU_DBG").is_some() {
            eprintln!(
                "[exemu] delivering exception {code:#010x} to the guest, faulting address {} ({})
{}",
                self.addr_note(address),
                memory_map::locate(self.mem.regions(), address),
                self.fault_report(
                    &format!("guest exception {code:#010x} (address {address:#x})"),
                    None,
                    steps,
                    recent,
                ),
            );
        }

        let rip_before = self.cpu.state().rip;
        if let ExcSource::Interrupt(3) = src {
            self.cpu.state_mut().rip = rip_before.wrapping_add(1);
        }

        if let Err(why) = self.os.deliver_hw_exception(
            self.cpu.state_mut(),
            &mut self.mem,
            ntdll_base,
            exemu_os::Trap { code, address, info: &info, mode },
        ) {
            self.cpu.state_mut().rip = rip_before;
            if std::env::var_os("EXEMU_DBG").is_some() {
                eprintln!("[exemu] could not deliver exception {code:#010x} to the guest: {why}");
            }
            return Ok(false);
        }
        if mode == exemu_os::TrapMode::Compat32 {
            self.cpu.set_bits(Bits::B64);
        }
        self.exc_depth += 1;
        Ok(true)
    }
}
