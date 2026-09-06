use crate::cpu::{CpuState, Exit};
use crate::memory::Memory;
use crate::Result;

pub trait Hooks {
    fn intercept(
        &mut self,
        rip: u64,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Option<Exit>>;

    fn syscall(&mut self, index: u32, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<Exit> {
        let _ = index;
        Ok(Exit::Interrupt(0x80))
    }

    fn retire(&mut self, n: u64, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Option<Exit>> {
        let _ = (n, cpu, mem);
        Ok(None)
    }

    fn retire_budget(&self) -> u64 {
        u64::MAX
    }
}

pub struct NoHooks;

impl Hooks for NoHooks {
    fn intercept(&mut self, _: u64, _: &mut CpuState, _: &mut dyn Memory) -> Result<Option<Exit>> {
        Ok(None)
    }
}
