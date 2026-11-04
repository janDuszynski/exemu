use exemu_core::debug::{DebugCommand, DebugControl, DebugEvent};
use exemu_core::{GuestClock, Memory, Result};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;
use exemu_os::WinOs;

use crate::config::{RunConfig, RunResult};
use crate::wow64_boot;

mod debug;
mod exception;
mod fault;
mod load;
mod run;

pub struct Process {
    mem: VirtualMemory,
    cpu: Interpreter,
    os: WinOs,
    clock: GuestClock,
    sandbox: String,
    entry: u64,
    max_steps: u64,
    image_base: u64,
    exc_depth: u32,
    wow64: Option<wow64_boot::Wow64Boot>,
    jit: Option<exemu_jit::Jit>,
    dbg: DebugControl,
    dbg_cmds: Option<std::sync::mpsc::Receiver<DebugCommand>>,
    dbg_events: Option<std::sync::mpsc::Sender<DebugEvent>>,
}

impl Process {
    pub fn wow64(&self) -> Option<&wow64_boot::Wow64Boot> {
        self.wow64.as_ref()
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn peek_u8(&self, addr: u64) -> Result<u8> {
        self.mem.read_u8(addr)
    }

    pub fn peek_u32(&self, addr: u64) -> Result<u32> {
        self.mem.read_u32(addr)
    }

    pub fn peek_u64(&self, addr: u64) -> Result<u64> {
        self.mem.read_u64(addr)
    }

    pub fn memory(&self) -> &dyn Memory {
        &self.mem
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }
}

pub fn load_and_run(pe_bytes: &[u8], cfg: RunConfig) -> Result<RunResult> {
    let mut cfg = cfg;
    Process::load(pe_bytes, &mut cfg)?.run()
}
