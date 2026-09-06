use exemu_core::{CpuState, Memory, Reg, Result};

use crate::exc;
use crate::WinOs;

pub const RVA_LDR_INITIALIZE_THUNK: u64 = 0x155c0;
pub const RVA_RTL_USER_THREAD_START: u64 = 0x10d14;

pub const RVA_WINE_UNIX_CALL_DISPATCHER: u64 = 0x9c058;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

pub(crate) const SSDT_NT_CONTINUE: u32 = 0x43;

pub(crate) fn ssdt_nt_continue(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_continue(cpu, mem)
}

impl WinOs {
    pub(crate) fn nt_continue(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let ctx = self.syscall_arg(cpu, mem, 0)?;
        if ctx == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let restored = match exc::read_context(mem, ctx) {
            Ok(s) => s,
            Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
        };
        cpu.gpr = restored.gpr;
        cpu.xmm = restored.xmm;
        cpu.rip = restored.rip;
        cpu.rflags = restored.rflags;
        self.note_exception_resumed();
        self.syscall_resume_as_is = true;
        Ok(STATUS_SUCCESS)
    }

    pub fn bootstrap_via_ldr_init(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        ntdll_base: u64,
        entry: u64,
        arg: u64,
        stack_top: u64,
    ) -> Result<Option<u64>> {
        let ctx = (stack_top - exc::CONTEXT_SIZE) & !0xf;

        let mut boot = CpuState::new();
        boot.rip = ntdll_base + RVA_RTL_USER_THREAD_START;
        boot.set_reg(Reg::Rcx, entry);
        boot.set_reg(Reg::Rdx, arg);
        boot.set_rsp((ctx - 0x100) & !0xf);
        exc::write_context(mem, ctx, &boot)?;

        cpu.rip = ntdll_base + RVA_LDR_INITIALIZE_THUNK;
        cpu.set_reg(Reg::Rcx, ctx);
        cpu.set_rsp((ctx - 0x100) & !0xf);
        Ok(Some(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::{flags, Exit};
    use exemu_memory::VirtualMemory;

    const CTX_CONTEXT_FLAGS: u64 = 0x30;
    const CTX_RCX: u64 = 0x80;
    const CTX_RDX: u64 = 0x88;
    const CTX_RSP: u64 = 0x98;
    const CTX_RIP: u64 = 0xf8;

    const TEB: u64 = 0x7fff_0000_0000;
    const HEAP: u64 = 0x2_0000_0000;
    const STACK_TOP: u64 = 0x10_0000_1000;

    fn os_mem() -> (WinOs, VirtualMemory) {
        let mut mem = VirtualMemory::new();
        mem.map(exemu_core::Region::new("teb", TEB, 0x2000, exemu_core::Perm::RW)).unwrap();
        mem.map(exemu_core::Region::new("heap", HEAP, 0x10000, exemu_core::Perm::RW)).unwrap();
        mem.map(exemu_core::Region::new("scratch", 0x5000_0000, 0x4000, exemu_core::Perm::RW)).unwrap();
        mem.map(exemu_core::Region::new("stack", STACK_TOP - 0x10000, 0x10000, exemu_core::Perm::RW)).unwrap();
        let os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            teb_base: TEB,
            heap_base: HEAP,
            heap_size: 0x10000,
            ..WinConfig::default()
        });
        (os, mem)
    }

    #[test]
    fn nt_continue_loads_context_and_resumes() {
        let (mut os, mut mem) = os_mem();
        let ctx = 0x5000_0000u64;

        let mut want = CpuState::new();
        want.set_reg(Reg::Rbx, 0xB16B_00B5);
        want.set_reg(Reg::Rsi, 0x5151_5151);
        want.set_reg(Reg::Rcx, 0x00C0_FFEE);
        want.rip = 0x1_4000_1234;
        want.set_rsp(0x10_0000_0FF0);
        want.rflags = flags::RESERVED_ONE | flags::CF | flags::ZF;
        exc::write_context(&mut mem, ctx, &want).unwrap();

        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;
        cpu.fs_base = TEB;
        cpu.set_reg(Reg::R10, ctx);
        cpu.set_reg(Reg::Rcx, 0xDEAD);
        cpu.set_reg(Reg::R11, cpu.rflags);
        cpu.set_rsp(0x10_0000_2000);

        let exit = os.dispatch_syscall(SSDT_NT_CONTINUE, &mut cpu, &mut mem).unwrap();
        assert_eq!(exit, Exit::Continue);
        assert_eq!(cpu.rip, want.rip, "resumed at CONTEXT.Rip");
        assert_eq!(cpu.rsp(), want.rsp(), "resumed on CONTEXT.Rsp");
        assert_eq!(cpu.reg(Reg::Rbx), 0xB16B_00B5, "Rbx loaded from CONTEXT");
        assert_eq!(cpu.reg(Reg::Rsi), 0x5151_5151, "Rsi loaded from CONTEXT");
        assert_eq!(cpu.reg(Reg::Rcx), 0x00C0_FFEE, "Rcx loaded (NOT the frame's return rip)");
        assert_eq!(cpu.rflags & flags::CF, flags::CF, "RFLAGS.CF loaded from CONTEXT");
        assert_eq!(cpu.gs_base, TEB, "segment bases preserved across NtContinue");
        assert_eq!(cpu.fs_base, TEB, "segment bases preserved across NtContinue");
    }

    #[test]
    fn nt_continue_null_context_is_access_violation() {
        let (mut os, mut mem) = os_mem();
        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;
        cpu.set_reg(Reg::R10, 0);
        cpu.set_reg(Reg::Rcx, 0x1234);
        cpu.set_reg(Reg::R11, cpu.rflags);
        cpu.set_rsp(0x10_0000_2000);
        os.dispatch_syscall(SSDT_NT_CONTINUE, &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::Rax), STATUS_ACCESS_VIOLATION as u64);
        assert_eq!(cpu.rip, 0x1234, "returned to the frame's rip (RCX), not resumed");
    }

    #[test]
    fn bootstrap_builds_context_and_seats_ldr_init() {
        let (mut os, mut mem) = os_mem();
        let ntdll_base = 0x6_0000_0000u64;
        let entry = 0x1_4000_5000u64;
        let arg = 0xABCD;
        let mut cpu = CpuState::new();
        cpu.gs_base = TEB;

        let ctx = os
            .bootstrap_via_ldr_init(&mut cpu, &mut mem, ntdll_base, entry, arg, STACK_TOP)
            .unwrap()
            .expect("heap had room for the CONTEXT");

        assert_eq!(cpu.rip, ntdll_base + RVA_LDR_INITIALIZE_THUNK, "rip = LdrInitializeThunk");
        assert_eq!(cpu.reg(Reg::Rcx), ctx, "RCX = &CONTEXT");

        assert_ne!(mem.read_u32(ctx + CTX_CONTEXT_FLAGS).unwrap(), 0, "ContextFlags set");
        assert_eq!(mem.read_u64(ctx + CTX_RIP).unwrap(), ntdll_base + RVA_RTL_USER_THREAD_START);
        assert_eq!(mem.read_u64(ctx + CTX_RCX).unwrap(), entry, "CONTEXT.Rcx = EntryPoint");
        assert_eq!(mem.read_u64(ctx + CTX_RDX).unwrap(), arg, "CONTEXT.Rdx = Arg");
        let rsp = mem.read_u64(ctx + CTX_RSP).unwrap();
        assert_eq!(rsp & 0xf, 0, "CONTEXT.Rsp 16-byte aligned");
        assert!(rsp <= STACK_TOP && rsp > STACK_TOP - 0x1000, "CONTEXT.Rsp near the stack top");
    }
}
