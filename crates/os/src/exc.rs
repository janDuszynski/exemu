use exemu_core::cpu::{SEL_CS32, SEL_CS64, SEL_DATA};
use exemu_core::{guest_addr, CpuState, Memory, Result};

pub(crate) const CONTEXT_SIZE: u64 = 0x4d0;

pub const RVA_KI_USER_EXCEPTION_DISPATCHER: u64 = 0x10a30;

pub const EXC_FRAME_BYTES: u64 = 0x5C0;

#[derive(Debug, Clone, Copy)]
pub struct Trap<'a> {
    pub code: u32,
    pub address: u64,
    pub info: &'a [u64],
    pub mode: TrapMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrapMode {
    #[default]
    Long,
    Compat32,
}

pub(crate) const EXCEPTION_RECORD_SIZE: u64 = 0x20 + 15 * 8;
const ER_CODE: u64 = 0x00;
const ER_FLAGS: u64 = 0x04;
const ER_NESTED: u64 = 0x08;
const ER_ADDRESS: u64 = 0x10;
const ER_NUM_PARAMS: u64 = 0x18;
const ER_INFO: u64 = 0x20;

pub(crate) const EXCEPTION_UNWINDING: u32 = 0x2;

pub(crate) const STATUS_CXX_EXCEPTION: u32 = 0xE06D_7363;

pub(crate) const EXCEPTION_CONTINUE_EXECUTION: u64 = 0;

pub(crate) const SSDT_NT_RAISE_EXCEPTION: u32 = 0xCF;

const STATUS_SUCCESS_NT: u32 = 0x0000_0000;
const STATUS_NOT_IMPLEMENTED_NT: u32 = 0xC000_0002;

pub(crate) fn ssdt_nt_raise_exception(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_raise_exception(cpu, mem)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnhandledException {
    pub code: u32,
    pub address: u64,
    pub how: &'static str,
}

impl UnhandledException {
    pub const LAST_RESORT: &'static str =
        "the guest's own exception dispatcher found no handler and asked the kernel to \
         terminate the process (NtRaiseException, FirstChance = FALSE)";
    pub const RE_DELIVERY_BOUND: &'static str =
        "exemu stopped re-delivering it: the guest never resumed from it, so nothing \
         handled it";
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ExcChain {
    first: Option<(u32, u64)>,
    last: Option<(u32, u64, u64)>,
    repeats: u32,
    depth: u32,
}

const MAX_IDENTICAL_DELIVERIES: u32 = 3;

const MAX_CHAIN_DELIVERIES: u32 = 32;

impl ExcChain {
    fn note_delivery(&mut self, code: u32, address: u64, rip: u64) -> Option<UnhandledException> {
        if self.first.is_none() {
            self.first = Some((code, address));
        }
        if self.last == Some((code, address, rip)) {
            self.repeats += 1;
        } else {
            self.last = Some((code, address, rip));
            self.repeats = 1;
        }
        self.depth += 1;
        if self.repeats >= MAX_IDENTICAL_DELIVERIES || self.depth > MAX_CHAIN_DELIVERIES {
            let (code, address) = self.first.unwrap_or((code, address));
            return Some(UnhandledException {
                code,
                address,
                how: UnhandledException::RE_DELIVERY_BOUND,
            });
        }
        None
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

pub(crate) fn write_exception_record(
    mem: &mut dyn Memory,
    addr: u64,
    code: u32,
    flags: u32,
    address: u64,
    params: &[u64],
) -> Result<()> {
    mem.write_u32_at(addr, ER_CODE, code)?;
    mem.write_u32_at(addr, ER_FLAGS, flags)?;
    mem.write_u64_at(addr, ER_NESTED, 0)?;
    mem.write_u64_at(addr, ER_ADDRESS, address)?;
    let n = params.len().min(15);
    mem.write_u32_at(addr, ER_NUM_PARAMS, n as u32)?;
    for (i, &p) in params.iter().take(15).enumerate() {
        mem.write_u64_at(addr, ER_INFO + i as u64 * 8, p)?;
    }
    Ok(())
}

pub(crate) fn set_record_flags(mem: &mut dyn Memory, addr: u64, flags: u32) -> Result<()> {
    mem.write_u32_at(addr, ER_FLAGS, flags)
}

pub(crate) fn record_flags(mem: &dyn Memory, addr: u64) -> Result<u32> {
    mem.read_u32_at(addr, ER_FLAGS)
}

pub(crate) const DISPATCHER_CONTEXT_SIZE: u64 = 0x50;

pub(crate) struct DispatcherContext {
    pub control_pc: u64,
    pub image_base: u64,
    pub function_entry: u64,
    pub establisher_frame: u64,
    pub target_ip: u64,
    pub context_record: u64,
    pub language_handler: u64,
    pub handler_data: u64,
}

pub(crate) fn write_dispatcher_context(
    mem: &mut dyn Memory,
    addr: u64,
    d: &DispatcherContext,
) -> Result<()> {
    mem.write_u64(addr, d.control_pc)?;
    mem.write_u64_at(addr, 0x08, d.image_base)?;
    mem.write_u64_at(addr, 0x10, d.function_entry)?;
    mem.write_u64_at(addr, 0x18, d.establisher_frame)?;
    mem.write_u64_at(addr, 0x20, d.target_ip)?;
    mem.write_u64_at(addr, 0x28, d.context_record)?;
    mem.write_u64_at(addr, 0x30, d.language_handler)?;
    mem.write_u64_at(addr, 0x38, d.handler_data)?;
    mem.write_u64_at(addr, 0x40, 0)?;
    mem.write_u64_at(addr, 0x48, 0)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Search,
    Unwind,
}

pub(crate) struct DispatchFrame {
    pub phase: Phase,
    pub record: u64,
    pub orig_context: u64,
    pub work_context: u64,
    pub dispatcher: u64,
    pub final_rsp: u64,
    pub frame_context: u64,
    pub target_frame: u64,
    pub target_ip: u64,
    pub return_value: u64,
}

const OFF_CONTEXT_FLAGS: u64 = 0x30;
const OFF_MXCSR: u64 = 0x34;
const OFF_EFLAGS: u64 = 0x44;
const OFF_GPR: u64 = 0x78;
const OFF_RIP: u64 = 0xf8;
const OFF_XMM0: u64 = 0x1a0;
const OFF_SEG_CS: u64 = 0x38;
const OFF_SEG_DS: u64 = 0x3a;
const OFF_SEG_ES: u64 = 0x3c;
const OFF_SEG_FS: u64 = 0x3e;
const OFF_SEG_GS: u64 = 0x40;
const OFF_SEG_SS: u64 = 0x42;
const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x4;

const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
const CONTEXT_ALL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

pub(crate) fn write_context(mem: &mut dyn Memory, addr: u64, state: &CpuState) -> Result<()> {
    mem.write_u32_at(addr, OFF_CONTEXT_FLAGS, CONTEXT_ALL)?;
    mem.write_u32_at(addr, OFF_MXCSR, 0x1f80)?;
    mem.write_u32_at(addr, OFF_EFLAGS, state.rflags as u32)?;
    for (i, &v) in state.gpr.iter().enumerate() {
        mem.write_u64_at(addr, OFF_GPR + i as u64 * 8, v)?;
    }
    mem.write_u64_at(addr, OFF_RIP, state.rip)?;
    for (i, &v) in state.xmm.iter().enumerate() {
        mem.write_at(addr, OFF_XMM0 + i as u64 * 16, &v.to_le_bytes())?;
    }
    Ok(())
}

pub(crate) fn read_context(mem: &dyn Memory, addr: u64) -> Result<CpuState> {
    let mut s = CpuState::new();
    for i in 0..16 {
        s.gpr[i] = mem.read_u64_at(addr, OFF_GPR + i as u64 * 8)?;
    }
    s.rip = mem.read_u64_at(addr, OFF_RIP)?;
    let eflags = mem.read_u32_at(addr, OFF_EFLAGS)? as u64;
    s.rflags = (eflags & !exemu_core::flags::RESERVED_ONE) | exemu_core::flags::RESERVED_ONE;
    for i in 0..16 {
        let mut b = [0u8; 16];
        mem.read_at(addr, OFF_XMM0 + i as u64 * 16, &mut b)?;
        s.xmm[i] = u128::from_le_bytes(b);
    }
    Ok(s)
}

use crate::api::Outcome;
use crate::WinOs;
use exemu_core::{HandlerType, Reg};

const MAX_DISPATCH_FRAMES: u32 = 4096;

impl WinOs {
    pub(crate) fn raise_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as u32;
        let flags = self.arg(cpu, mem, 1)? as u32;
        let nparams = self.arg(cpu, mem, 2)? as usize;
        let args_ptr = self.arg(cpu, mem, 3)?;

        let ret_addr = mem.read_u64(cpu.rsp())?;
        let final_rsp = cpu.rsp() + 8;

        let mut params = Vec::new();
        if args_ptr != 0 {
            for i in 0..nparams.min(15) {
                params.push(mem.read_u64_at(args_ptr, i as u64 * 8)?);
            }
        }

        let Some((record, orig_context, work_context, frame_context, dispatcher)) =
            self.alloc_dispatch_buffers()
        else {
            return Err(exemu_core::EmuError::Os("out of heap for exception dispatch".into()));
        };

        let mut snap = cpu.clone();
        snap.rip = ret_addr;
        snap.set_rsp(final_rsp);
        write_context(mem, orig_context, &snap)?;
        write_context(mem, work_context, &snap)?;
        write_exception_record(mem, record, code, flags, ret_addr, &params)?;

        if self.cfg.trace {
            let kind = if code == STATUS_CXX_EXCEPTION { " (C++ throw)" } else { "" };
            eprintln!("[exemu] RaiseException code={code:#x}{kind} flags={flags:#x} at {ret_addr:#x}");
        }

        self.exc_stack.push(DispatchFrame {
            phase: Phase::Search,
            record,
            orig_context,
            work_context,
            dispatcher,
            frame_context,
            final_rsp,
            target_frame: 0,
            target_ip: 0,
            return_value: 0,
        });
        self.pump_dispatch(cpu, mem)
    }

    pub(crate) fn rtl_unwind_ex(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let target_frame = self.arg(cpu, mem, 0)?;
        let target_ip = self.arg(cpu, mem, 1)?;
        let record = self.arg(cpu, mem, 2)?;
        let return_value = self.arg(cpu, mem, 3)?;
        let ctx_in = self.arg(cpu, mem, 4)?;

        let final_rsp = cpu.rsp() + 8;

        let Some((_r, orig_context, work_context, frame_context, dispatcher)) =
            self.alloc_dispatch_buffers()
        else {
            return Err(exemu_core::EmuError::Os("out of heap for unwind".into()));
        };
        let start = if ctx_in != 0 { read_context(mem, ctx_in)? } else { cpu.clone() };
        write_context(mem, work_context, &start)?;
        write_context(mem, orig_context, &start)?;
        let record = if record != 0 { record } else { self.exc_stack.last().map(|f| f.record).unwrap_or(0) };

        if self.cfg.trace {
            eprintln!("[exemu] RtlUnwindEx → frame {target_frame:#x} ip {target_ip:#x}");
        }

        self.exc_stack.push(DispatchFrame {
            phase: Phase::Unwind,
            record,
            orig_context,
            work_context,
            dispatcher,
            frame_context,
            final_rsp,
            target_frame,
            target_ip,
            return_value,
        });
        self.pump_dispatch(cpu, mem)
    }

    pub(crate) fn exc_advance(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let Some(frame) = self.exc_stack.last() else {
            return Ok(Outcome::Return(0));
        };
        let disposition = cpu.reg(Reg::Rax);
        if frame.phase == Phase::Search && disposition == EXCEPTION_CONTINUE_EXECUTION {
            let resume = read_context(mem, frame.orig_context)?;
            *cpu = resume;
            self.exc_stack.clear();
            return Ok(Outcome::Resume);
        }
        self.pump_dispatch(cpu, mem)
    }

    fn pump_dispatch(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let image_base = self.cfg.image_base;
        for _ in 0..MAX_DISPATCH_FRAMES {
            let frame = self.exc_stack.last().expect("pump_dispatch without a frame");
            let (phase, work, record, dispatcher, frame_ctx, orig_ctx) = (
                frame.phase,
                frame.work_context,
                frame.record,
                frame.dispatcher,
                frame.frame_context,
                frame.orig_context,
            );
            let (target_frame, target_ip, return_value, handler_base) =
                (frame.target_frame, frame.target_ip, frame.return_value, frame.final_rsp);

            let mut state = read_context(mem, work)?;
            let control_pc = state.rip;

            if control_pc == 0 || control_pc >= self.cfg.api_base {
                return self.finish_dispatch(cpu, mem);
            }

            let entry = control_pc
                .checked_sub(image_base)
                .and_then(|off| u32::try_from(off).ok())
                .and_then(|rva| exemu_core::unwind::lookup(&self.function_table, rva));
            let Some(_entry) = entry else {
                let ret = mem.read_u64(state.rsp())?;
                state.rip = ret;
                state.set_rsp(state.rsp() + 8);
                write_context(mem, work, &state)?;
                continue;
            };

            let ht = match phase {
                Phase::Search => HandlerType::EXCEPTION,
                Phase::Unwind => HandlerType::UNWIND,
            };
            let pre_unwind = state.clone();
            let mut caller = state;
            let fu = exemu_core::unwind::virtual_unwind_typed(
                &self.function_table,
                image_base,
                &mut caller,
                mem,
                ht,
            )?;

            if phase == Phase::Unwind && fu.establisher_frame == target_frame {
                return self.transfer_to_target(cpu, mem, &pre_unwind, target_ip, return_value);
            }

            write_context(mem, work, &caller)?;

            let Some(handler_rva) = fu.handler_rva else {
                continue;
            };
            let handler = image_base + handler_rva as u64;

            write_context(mem, frame_ctx, &pre_unwind)?;
            let flags = match phase {
                Phase::Search => record_flags(mem, record)? & !EXCEPTION_UNWINDING,
                Phase::Unwind => record_flags(mem, record)? | EXCEPTION_UNWINDING,
            };
            set_record_flags(mem, record, flags)?;
            let function_entry = _entry.record_rva as u64 + image_base;
            let handler_data =
                fu.handler_data_rva.map(|r| image_base + r as u64).unwrap_or(0);
            write_dispatcher_context(
                mem,
                dispatcher,
                &DispatcherContext {
                    control_pc,
                    image_base,
                    function_entry,
                    establisher_frame: fu.establisher_frame,
                    target_ip: if phase == Phase::Unwind { target_ip } else { 0 },
                    context_record: frame_ctx,
                    language_handler: handler,
                    handler_data,
                },
            )?;

            let args = [record, fu.establisher_frame, orig_ctx, dispatcher];
            self.setup_call_args(cpu, mem, handler, &args, self.exc_driver, handler_base)?;
            return Ok(Outcome::Resume);
        }
        self.finish_dispatch(cpu, mem)
    }

    fn transfer_to_target(
        &mut self,
        cpu: &mut CpuState,
        _mem: &mut dyn Memory,
        ctx: &CpuState,
        target_ip: u64,
        return_value: u64,
    ) -> Result<Outcome> {
        let mut resume = ctx.clone();
        resume.rip = target_ip;
        resume.set_reg(Reg::Rax, return_value);
        *cpu = resume;
        self.exc_stack.clear();
        if self.cfg.trace {
            eprintln!("[exemu] exception handled → resume at {target_ip:#x}");
        }
        Ok(Outcome::Resume)
    }

    fn finish_dispatch(&mut self, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let frame = self.exc_stack.pop();
        self.exc_stack.clear();
        let phase = frame.as_ref().map(|f| f.phase).unwrap_or(Phase::Search);
        if phase == Phase::Unwind {
            eprintln!("[exemu] RtlUnwindEx: target frame not found — terminating");
            return Ok(Outcome::Exit(1));
        }
        let code = frame.map(|f| mem.read_u32(f.record).unwrap_or(0)).unwrap_or(0);
        eprintln!(
            "[exemu] unhandled exception {code:#010x} — terminating (no guest handler caught it)"
        );
        Ok(Outcome::Exit(code as i32))
    }

    pub fn deliver_hw_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        ntdll_base: u64,
        trap: Trap<'_>,
    ) -> Result<()> {
        let Trap { code, address, info, mode } = trap;
        let old_rsp = cpu.rsp();
        let Some(new_rsp) = old_rsp.checked_sub(EXC_FRAME_BYTES) else {
            return Err(exemu_core::EmuError::Os(format!(
                "cannot deliver exception {code:#x}: rsp {old_rsp:#x} is below the \
                 {EXC_FRAME_BYTES:#x}-byte KiUserExceptionDispatcher frame"
            )));
        };
        let new_rsp = new_rsp & !0xF;
        let fault_rip = cpu.rip;
        let rflags = cpu.rflags;

        write_context(mem, new_rsp, cpu)?;

        let cs = match mode {
            TrapMode::Long => SEL_CS64,
            TrapMode::Compat32 => SEL_CS32,
        };
        mem.write_u16_at(new_rsp, OFF_SEG_CS, cs)?;
        for off in [OFF_SEG_DS, OFF_SEG_ES, OFF_SEG_FS, OFF_SEG_GS, OFF_SEG_SS] {
            mem.write_u16_at(new_rsp, off, SEL_DATA)?;
        }
        mem.write_u32_at(new_rsp, OFF_CONTEXT_FLAGS, CONTEXT_ALL | CONTEXT_SEGMENTS)?;

        for i in 0..3u64 {
            mem.write_u64_at(new_rsp, 0x4D0 + i * 8, 0)?;
        }

        write_exception_record(mem, guest_addr(new_rsp, 0x4F0, 0)?, code, 0, address, info)?;

        mem.write_u64_at(new_rsp, 0x590, fault_rip)?;
        mem.write_u64_at(new_rsp, 0x598, cs as u64)?;
        mem.write_u64_at(new_rsp, 0x5A0, rflags)?;
        mem.write_u64_at(new_rsp, 0x5A8, old_rsp)?;
        mem.write_u64_at(new_rsp, 0x5B0, SEL_DATA as u64)?;

        cpu.set_rsp(new_rsp);
        cpu.rip = ntdll_base + RVA_KI_USER_EXCEPTION_DISPATCHER;
        Ok(())
    }

    pub fn note_exception_delivery(
        &mut self,
        code: u32,
        address: u64,
        rip: u64,
    ) -> std::result::Result<(), UnhandledException> {
        match self.exc_chain.note_delivery(code, address, rip) {
            Some(u) => {
                self.unhandled_exception = Some(u.clone());
                Err(u)
            }
            None => Ok(()),
        }
    }

    pub(crate) fn note_exception_resumed(&mut self) {
        self.exc_chain.clear();
    }

    pub fn take_unhandled_exception(&mut self) -> Option<UnhandledException> {
        self.unhandled_exception.take()
    }

    pub(crate) fn nt_raise_exception(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        let rec = self.syscall_arg(cpu, mem, 0)?;
        let ctx = self.syscall_arg(cpu, mem, 1)?;
        let first_chance = self.syscall_arg(cpu, mem, 2)? & 0xff != 0;
        if rec == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let (Ok(code), Ok(address)) = (mem.read_u32_at(rec, ER_CODE), mem.read_u64_at(rec, ER_ADDRESS))
        else {
            return Ok(STATUS_ACCESS_VIOLATION);
        };

        if !first_chance {
            self.unhandled_exception = Some(UnhandledException {
                code,
                address,
                how: UnhandledException::LAST_RESORT,
            });
            self.exc_chain.clear();
            self.pending_syscall_exit = Some(code as i32);
            return Ok(STATUS_SUCCESS_NT);
        }

        let Some(ntdll) = self.module_base("ntdll.dll") else {
            return Ok(STATUS_NOT_IMPLEMENTED_NT);
        };
        let nparams = mem.read_u32_at(rec, ER_NUM_PARAMS).unwrap_or(0).min(15) as u64;
        let mut info = Vec::with_capacity(nparams as usize);
        for i in 0..nparams {
            info.push(mem.read_u64_at(rec, ER_INFO + i * 8).unwrap_or(0));
        }
        if ctx != 0 {
            if let Ok(restored) = read_context(mem, ctx) {
                cpu.gpr = restored.gpr;
                cpu.xmm = restored.xmm;
                cpu.rip = restored.rip;
                cpu.rflags = restored.rflags;
            }
        }
        if let Err(u) = self.note_exception_delivery(code, address, cpu.rip) {
            self.pending_syscall_exit = Some(u.code as i32);
            return Ok(STATUS_SUCCESS_NT);
        }
        let trap = Trap { code, address, info: &info, mode: TrapMode::Long };
        if self.deliver_hw_exception(cpu, mem, ntdll, trap).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        self.syscall_resume_as_is = true;
        Ok(STATUS_SUCCESS_NT)
    }

    fn alloc_dispatch_buffers(&mut self) -> Option<(u64, u64, u64, u64, u64)> {
        let record = self.heap_alloc(EXCEPTION_RECORD_SIZE);
        let orig = self.heap_alloc(CONTEXT_SIZE);
        let work = self.heap_alloc(CONTEXT_SIZE);
        let frame = self.heap_alloc(CONTEXT_SIZE);
        let disp = self.heap_alloc(DISPATCHER_CONTEXT_SIZE);
        if [record, orig, work, frame, disp].contains(&0) {
            return None;
        }
        Some((record, orig, work, frame, disp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Flat(Vec<u8>);
    impl Memory for Flat {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let o = addr as usize;
            buf.copy_from_slice(&self.0[o..o + buf.len()]);
            Ok(())
        }
        fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let o = addr as usize;
            self.0[o..o + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn context_round_trips_all_state() {
        let mut mem = Flat(vec![0u8; 0x1000]);
        let mut s = CpuState::new();
        for i in 0..16 {
            s.gpr[i] = 0x1000 + i as u64;
            s.xmm[i] = (i as u128) << 64 | 0xdead_beef;
        }
        s.rip = 0x1_4000_1234;
        s.set_rsp(0x8_0000);
        s.rflags = exemu_core::flags::RESERVED_ONE | exemu_core::flags::CF | exemu_core::flags::ZF;

        write_context(&mut mem, 0x100, &s).unwrap();
        let back = read_context(&mem, 0x100).unwrap();

        assert_eq!(back.gpr, s.gpr);
        assert_eq!(back.xmm, s.xmm);
        assert_eq!(back.rip, s.rip);
        assert_eq!(back.rsp(), 0x8_0000);
        assert_eq!(back.rflags & 0xffff_ffff, s.rflags & 0xffff_ffff);
    }

    #[test]
    fn context_places_rsp_and_rip_at_abi_offsets() {
        let mut mem = Flat(vec![0u8; 0x1000]);
        let mut s = CpuState::new();
        s.set_rsp(0xAAAA);
        s.rip = 0xBBBB;
        write_context(&mut mem, 0, &s).unwrap();
        assert_eq!(mem.read_u64(0x98).unwrap(), 0xAAAA);
        assert_eq!(mem.read_u64(0xf8).unwrap(), 0xBBBB);
    }
}
