use exemu_core::{flags, CpuState, Exit, Memory, Reg, Result};

use crate::WinOs;

pub(crate) const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const SSDT_LEN: usize = 0x400;

const WIN32K_LEN: usize = 0x700;

pub(crate) const WIN32K_TABLE_BIT: u32 = 0x1000;

const UNIX_STACK_SIZE: u64 = 0x4000;

const TEB_REGION_SIZE: u64 = 0x2000;

pub type SyscallHandler = fn(&mut WinOs, &mut CpuState, &mut dyn Memory) -> Result<u32>;

type Handler = SyscallHandler;

pub(crate) struct Ssdt {
    handlers: Vec<Handler>,
    claimed: Vec<bool>,
}

impl Ssdt {
    pub(crate) fn new() -> Self {
        Ssdt {
            handlers: vec![Ssdt::unimplemented as Handler; SSDT_LEN],
            claimed: vec![false; SSDT_LEN],
        }
    }

    pub(crate) fn new_win32k() -> Self {
        Ssdt {
            handlers: vec![Ssdt::unimplemented as Handler; WIN32K_LEN],
            claimed: vec![false; WIN32K_LEN],
        }
    }

    pub(crate) fn set(&mut self, index: u32, handler: Handler) {
        if let Some(slot) = self.handlers.get_mut(index as usize) {
            *slot = handler;
            self.claimed[index as usize] = true;
        }
    }

    pub(crate) fn set_stub(&mut self, index: u32, handler: Handler) {
        if let Some(slot) = self.handlers.get_mut(index as usize) {
            *slot = handler;
        }
    }

    pub(crate) fn implemented(&self, index: u32) -> bool {
        self.claimed.get(index as usize).copied().unwrap_or(false)
    }

    fn unimplemented(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
        Ok(STATUS_NOT_IMPLEMENTED)
    }

    fn handler(&self, index: u32) -> Handler {
        self.handlers
            .get(index as usize)
            .copied()
            .unwrap_or(Ssdt::unimplemented as Handler)
    }
}

mod frame {
    pub const SIZE: u64 = 0x140;

    pub const RBX: u64 = 0x00;
    pub const RBP: u64 = 0x08;
    pub const RSI: u64 = 0x10;
    pub const RDI: u64 = 0x18;
    pub const RSP: u64 = 0x20;
    pub const R12: u64 = 0x28;
    pub const R13: u64 = 0x30;
    pub const R14: u64 = 0x38;
    pub const R15: u64 = 0x40;
    pub const RIP: u64 = 0x48;
    pub const FLAGS: u64 = 0x50;

    pub const XMM_BASE: u64 = 0x60;
    pub const XMM_FIRST: u8 = 6;
    pub const XMM_LAST: u8 = 15;
}

fn win32k_trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("EXEMU_W32K_TRACE").is_some())
}

enum SavedContext {
    Teb(u64),
    Host(Box<HostContext>),
}

struct HostContext {
    gpr: [u64; 9],
    rip: u64,
    flags: u64,
    xmm: [u128; 10],
}

impl WinOs {
    #[allow(dead_code)]
    pub(crate) fn syscall_arg(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u64> {
        Ok(match i {
            0 => cpu.reg(Reg::R10),
            1 => cpu.reg(Reg::Rdx),
            2 => cpu.reg(Reg::R8),
            3 => cpu.reg(Reg::R9),
            n => mem.read_u64(self.syscall_guest_rsp + 0x28 + (n as u64 - 4) * 8)?,
        })
    }

    pub(crate) fn syscall_arg_u32(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u32> {
        Ok(self.syscall_arg(cpu, mem, i)? as u32)
    }

    fn ensure_unix_stack(&mut self, mem: &mut dyn Memory) -> u64 {
        if self.unix_stack_top != 0 {
            return self.unix_stack_top;
        }
        if let Some(base) =
            self.map_anywhere(mem, UNIX_STACK_SIZE, exemu_core::Perm::RW, "unix-stack")
        {
            self.unix_stack_top = (base + UNIX_STACK_SIZE - 0x10) & !0xf;
        }
        self.unix_stack_top
    }

    fn frame_base(&self) -> Option<u64> {
        let teb = self.current_thread_teb();
        (teb != 0).then(|| teb + TEB_REGION_SIZE - frame::SIZE)
    }

    fn save_context(&self, cpu: &CpuState, mem: &mut dyn Memory) -> Result<SavedContext> {
        if let Some(base) = self.frame_base() {
            mem.write_u64(base + frame::RBX, cpu.reg(Reg::Rbx))?;
            mem.write_u64(base + frame::RBP, cpu.reg(Reg::Rbp))?;
            mem.write_u64(base + frame::RSI, cpu.reg(Reg::Rsi))?;
            mem.write_u64(base + frame::RDI, cpu.reg(Reg::Rdi))?;
            mem.write_u64(base + frame::RSP, cpu.rsp())?;
            mem.write_u64(base + frame::R12, cpu.reg(Reg::R12))?;
            mem.write_u64(base + frame::R13, cpu.reg(Reg::R13))?;
            mem.write_u64(base + frame::R14, cpu.reg(Reg::R14))?;
            mem.write_u64(base + frame::R15, cpu.reg(Reg::R15))?;
            mem.write_u64(base + frame::RIP, cpu.reg(Reg::Rcx))?;
            mem.write_u64(base + frame::FLAGS, cpu.reg(Reg::R11))?;
            for n in frame::XMM_FIRST..=frame::XMM_LAST {
                let off = frame::XMM_BASE + (n - frame::XMM_FIRST) as u64 * 16;
                let v = cpu.xmm(n);
                mem.write_u64(base + off, v as u64)?;
                mem.write_u64(base + off + 8, (v >> 64) as u64)?;
            }
            Ok(SavedContext::Teb(base))
        } else {
            let mut xmm = [0u128; 10];
            for (slot, n) in xmm.iter_mut().zip(frame::XMM_FIRST..=frame::XMM_LAST) {
                *slot = cpu.xmm(n);
            }
            Ok(SavedContext::Host(Box::new(HostContext {
                gpr: [
                    cpu.reg(Reg::Rbx),
                    cpu.reg(Reg::Rbp),
                    cpu.reg(Reg::Rsi),
                    cpu.reg(Reg::Rdi),
                    cpu.rsp(),
                    cpu.reg(Reg::R12),
                    cpu.reg(Reg::R13),
                    cpu.reg(Reg::R14),
                    cpu.reg(Reg::R15),
                ],
                rip: cpu.reg(Reg::Rcx),
                flags: cpu.reg(Reg::R11),
                xmm,
            })))
        }
    }

    fn restore_context(
        &self,
        cpu: &mut CpuState,
        mem: &dyn Memory,
        saved: &SavedContext,
    ) -> Result<()> {
        let non_vol = |cpu: &mut CpuState, gpr: [u64; 9]| {
            cpu.set_reg(Reg::Rbx, gpr[0]);
            cpu.set_reg(Reg::Rbp, gpr[1]);
            cpu.set_reg(Reg::Rsi, gpr[2]);
            cpu.set_reg(Reg::Rdi, gpr[3]);
            cpu.set_rsp(gpr[4]);
            cpu.set_reg(Reg::R12, gpr[5]);
            cpu.set_reg(Reg::R13, gpr[6]);
            cpu.set_reg(Reg::R14, gpr[7]);
            cpu.set_reg(Reg::R15, gpr[8]);
        };
        match saved {
            SavedContext::Teb(base) => {
                let base = *base;
                let gpr = [
                    mem.read_u64(base + frame::RBX)?,
                    mem.read_u64(base + frame::RBP)?,
                    mem.read_u64(base + frame::RSI)?,
                    mem.read_u64(base + frame::RDI)?,
                    mem.read_u64(base + frame::RSP)?,
                    mem.read_u64(base + frame::R12)?,
                    mem.read_u64(base + frame::R13)?,
                    mem.read_u64(base + frame::R14)?,
                    mem.read_u64(base + frame::R15)?,
                ];
                non_vol(cpu, gpr);
                cpu.rip = mem.read_u64(base + frame::RIP)?;
                cpu.rflags = mem.read_u64(base + frame::FLAGS)?;
                for n in frame::XMM_FIRST..=frame::XMM_LAST {
                    let off = frame::XMM_BASE + (n - frame::XMM_FIRST) as u64 * 16;
                    let lo = mem.read_u64(base + off)? as u128;
                    let hi = mem.read_u64(base + off + 8)? as u128;
                    cpu.set_xmm_keep_upper(n, lo | (hi << 64));
                }
            }
            SavedContext::Host(h) => {
                non_vol(cpu, h.gpr);
                cpu.rip = h.rip;
                cpu.rflags = h.flags;
                for (v, n) in h.xmm.iter().zip(frame::XMM_FIRST..=frame::XMM_LAST) {
                    cpu.set_xmm_keep_upper(n, *v);
                }
            }
        }
        Ok(())
    }

    pub fn set_syscall_handler(&mut self, index: u32, handler: SyscallHandler) {
        self.ssdt.set(index, handler);
    }

    pub fn set_win32k_handler(&mut self, index: u32, handler: SyscallHandler) {
        self.win32k.set(index & !WIN32K_TABLE_BIT, handler);
    }

    pub fn set_win32k_stub(&mut self, index: u32, handler: SyscallHandler) {
        self.win32k.set_stub(index & !WIN32K_TABLE_BIT, handler);
    }

    pub(crate) fn return_u64_from_syscall(&mut self, value: u64) {
        self.syscall_result64 = Some(value);
    }

    #[cfg(test)]
    pub(crate) fn set_syscall_guest_rsp_for_test(&mut self, rsp: u64) {
        self.syscall_guest_rsp = rsp;
    }

    pub(crate) fn dispatch_syscall(
        &mut self,
        index: u32,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Exit> {
        self.syscall_guest_rsp = cpu.rsp();
        self.syscall_resume_as_is = false;
        self.pending_syscall_exit = None;
        self.syscall_result64 = None;

        cpu.rflags &= !flags::DF;

        let handler = if index & WIN32K_TABLE_BIT != 0 {
            if win32k_trace() {
                let masked = index & !WIN32K_TABLE_BIT;
                let mark = if self.win32k.implemented(masked) { "" } else { "  <UNSERVICED>" };
                eprintln!(
                    "[w32k] {index:#06x} {:#x} {:#x} {:#x}{mark}",
                    cpu.reg(Reg::R10),
                    cpu.reg(Reg::Rdx),
                    cpu.reg(Reg::R8)
                );
            }
            self.win32k.handler(index & !WIN32K_TABLE_BIT)
        } else {
            self.ssdt.handler(index)
        };

        let saved = self.save_context(cpu, mem)?;

        let unix_top = self.ensure_unix_stack(mem);
        if unix_top != 0 {
            cpu.set_rsp(unix_top);
        }

        let status = handler(self, cpu, mem)?;

        if let Some(code) = self.pending_syscall_exit.take() {
            return Ok(Exit::ProcessExit(code));
        }

        if self.syscall_resume_as_is {
            return Ok(Exit::Continue);
        }

        self.restore_context(cpu, mem, &saved)?;
        let result = self.syscall_result64.take().unwrap_or(status as u64);
        cpu.set_reg(Reg::Rax, result);

        Ok(Exit::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_memory::VirtualMemory;

    fn clobber(_os: &mut WinOs, cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
        for r in [Reg::Rbx, Reg::Rbp, Reg::Rsi, Reg::Rdi, Reg::R12, Reg::R13, Reg::R14, Reg::R15] {
            cpu.set_reg(r, 0xDEAD);
        }
        for n in 6u8..=15 {
            cpu.set_xmm_keep_upper(n, 0xDEAD);
        }
        cpu.set_reg(Reg::R8, 0x5A5A);
        Ok(0x1234_5678)
    }

    #[test]
    fn host_fallback_roundtrip_preserves_nonvolatiles() {
        let mut mem = VirtualMemory::new();
        let mut os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            teb_base: 0,
            ..WinConfig::default()
        });
        os.set_syscall_handler(7, clobber);

        let mut cpu = CpuState::default();
        let ret = 0x0000_0000_0040_1234;
        cpu.set_reg(Reg::Rcx, ret);
        cpu.set_reg(Reg::R11, cpu.rflags | flags::DF);
        cpu.set_rsp(0x0000_0010_0000_1000);
        cpu.set_reg(Reg::Rbx, 0xB16B_00B5);
        cpu.set_reg(Reg::Rbp, 0x0BADF00D);
        cpu.set_xmm_keep_upper(6, 0xCAFE);
        cpu.set_reg(Reg::R8, 0);
        let rsp_before = cpu.rsp();

        let exit = os.dispatch_syscall(7, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));

        assert_eq!(cpu.reg(Reg::Rax), 0x1234_5678, "NTSTATUS in RAX");
        assert_eq!(cpu.reg(Reg::Rbx), 0xB16B_00B5, "RBX restored");
        assert_eq!(cpu.reg(Reg::Rbp), 0x0BADF00D, "RBP restored");
        assert_eq!(cpu.xmm(6), 0xCAFE, "XMM6 restored");
        assert_eq!(cpu.reg(Reg::R8), 0x5A5A, "R8 (volatile) passes through");
        assert_eq!(cpu.rsp(), rsp_before, "guest RSP restored");
        assert_eq!(cpu.rip, ret, "resumes at the return address (saved RCX)");
        assert!(cpu.rflags & flags::DF != 0, "guest DF restored from saved R11");
    }

    #[test]
    fn unimplemented_index_returns_not_implemented() {
        let mut mem = VirtualMemory::new();
        let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_rsp(0x1_0000);
        os.dispatch_syscall(0x123, &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::Rax), STATUS_NOT_IMPLEMENTED as u64);
    }

    #[test]
    fn only_a_claimed_slot_counts_as_serviced() {
        fn answer(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
            Ok(0)
        }
        let mut t = Ssdt::new_win32k();
        for i in 0..8 {
            t.set_stub(i, answer);
        }
        assert!(!t.implemented(3), "the blanket fill does not make a slot serviced");
        t.set(3, answer);
        assert!(t.implemented(3), "a written handler is serviced");
        assert!(!t.implemented(4), "and its neighbour still is not");
        assert!(!t.implemented(WIN32K_LEN as u32 + 1));
    }
}
