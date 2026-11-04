use exemu_core::debug::{DebugCommand, DebugControl, DebugEvent, DebugSnapshot, StopReason, StopRequest};
use exemu_core::{Cpu, Memory};
use exemu_cpu::Bits;

use super::Process;

const JIT_EXACT_STOP_WINDOW: u64 = 128;

const DEBUG_READ_MAX: u64 = 1 << 20;

pub(super) enum DebugAction {
    Continue,
    Step,
    Detach,
    Kill,
}

impl Process {
    pub fn debug(&self) -> &DebugControl {
        &self.dbg
    }

    pub(super) fn debug_pending_stop(&self, steps: u64, step_target: u64) -> Option<StopReason> {
        if let Some((addr, kind)) = self.dbg.take_watch_hit() {
            return Some(StopReason::Watch { addr, kind });
        }
        if steps >= step_target {
            return Some(StopReason::StepComplete);
        }
        if steps >= self.dbg.break_at_step() {
            self.dbg.set_break_at_step(None);
            return Some(StopReason::StepCount { steps });
        }
        None
    }

    pub(super) fn debug_needs_interpreter(&self, stepping: bool, steps: u64) -> bool {
        stepping
            || self.dbg.break_at_step().saturating_sub(steps) <= JIT_EXACT_STOP_WINDOW
    }

    pub(super) fn debug_stop(&mut self, reason: StopReason, steps: u64, trail: &[u64]) -> DebugAction {
        let Some(cmds) = self.dbg_cmds.take() else { return DebugAction::Continue };
        let events = self.dbg_events.take();
        let action = self.debug_serve(&cmds, events.as_ref(), reason, steps, trail);
        if matches!(action, DebugAction::Detach) {
            self.debug_disarm_all();
        } else {
            self.dbg_cmds = Some(cmds);
            self.dbg_events = events;
        }
        action
    }

    fn debug_serve(
        &mut self,
        cmds: &std::sync::mpsc::Receiver<DebugCommand>,
        events: Option<&std::sync::mpsc::Sender<DebugEvent>>,
        reason: StopReason,
        steps: u64,
        trail: &[u64],
    ) -> DebugAction {
        let snapshot = self.debug_snapshot(reason, steps, trail);
        if let Some(tx) = events {
            let _ = tx.send(DebugEvent::Stopped(Box::new(snapshot)));
        }
        loop {
            let Ok(cmd) = cmds.recv() else {
                return DebugAction::Detach;
            };
            match cmd {
                DebugCommand::Resume => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Resumed);
                    }
                    return DebugAction::Continue;
                }
                DebugCommand::Step => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Resumed);
                    }
                    return DebugAction::Step;
                }
                DebugCommand::Pause => {}
                DebugCommand::ArmBreak(addr) => self.dbg.arm_break(addr),
                DebugCommand::DisarmBreak(addr) => self.dbg.disarm_break(addr),
                DebugCommand::ArmWatch { base, len, kind } => self.dbg.arm_watch(base, len, kind),
                DebugCommand::DisarmWatch(base) => self.dbg.disarm_watch(base),
                DebugCommand::BreakAtStep(n) => self.dbg.set_break_at_step(n),
                DebugCommand::ReadMemory { addr, len } => {
                    let bytes = self.debug_read(addr, len);
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Memory { addr, bytes });
                    }
                }
                DebugCommand::Disassemble { addr, .. } => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Error(format!(
                            "cannot disassemble at {addr:#x}: the decoder is not a public seam yet \
                             (roadmap W9.2). Read the bytes with ReadMemory instead."
                        )));
                    }
                }
                DebugCommand::Detach => return DebugAction::Detach,
                DebugCommand::Kill => return DebugAction::Kill,
            }
        }
    }

    fn debug_snapshot(&self, stop: StopReason, steps: u64, trail: &[u64]) -> DebugSnapshot {
        let regs = self.cpu.state().clone();
        let table = self.os.unwind_table();
        let backtrace = if table.is_empty() {
            Vec::new()
        } else {
            exemu_core::unwind::backtrace(table, self.image_base, &regs, &self.mem, 24)
        };
        DebugSnapshot {
            stop,
            steps,
            bits: match self.cpu.bits() {
                Bits::B64 => 64,
                Bits::B32 => 32,
            },
            rip_note: self.os.describe_addr(regs.rip),
            trail: trail.to_vec(),
            backtrace,
            modules: self
                .os
                .loaded_modules()
                .into_iter()
                .map(|(name, base, size)| exemu_core::ModuleInfo { name, base, size })
                .collect(),
            threads: Vec::new(),
            handles: Vec::new(),
            regions: self.mem.regions().cloned().collect(),
            regs,
        }
    }

    fn debug_read(&self, addr: u64, len: u64) -> Vec<u8> {
        let len = len.min(DEBUG_READ_MAX) as usize;
        let mut buf = vec![0u8; len];
        if self.mem.read(addr, &mut buf).is_ok() {
            return buf;
        }
        buf.clear();
        for i in 0..len as u64 {
            let mut b = [0u8; 1];
            if self.mem.read(addr.wrapping_add(i), &mut b).is_err() {
                break;
            }
            buf.push(b[0]);
        }
        buf
    }

    fn debug_disarm_all(&self) {
        for addr in self.dbg.breakpoints() {
            self.dbg.disarm_break(addr);
        }
        for w in self.dbg.watchpoints() {
            self.dbg.disarm_watch(w.base);
        }
        self.dbg.set_break_at_step(None);
        self.dbg.request(StopRequest::Run);
    }
}
