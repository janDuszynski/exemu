use exemu_core::debug::{DebugEvent, StopReason, StopRequest};
use exemu_core::{Cpu, EmuError, Exit, Result};
use exemu_cpu::Bits;

use crate::config::{JitReport, RunResult};
use crate::kuser::{refresh_kuser_time, KUSER_REFRESH_INSTRUCTIONS};

use super::debug::DebugAction;
use super::exception::ExcSource;
use super::Process;

const CHAIN_MAX_INSTRUCTIONS: u64 = 65_536;

impl Process {
    pub fn run_until_rip(&mut self, target: u64, max_steps: u64) -> Result<u64> {
        let mut steps = 0u64;
        while self.cpu.state().rip != target {
            if steps >= max_steps {
                return Err(EmuError::Os(format!(
                    "run_until_rip({target:#x}): not reached within {max_steps} steps (rip {:#x})",
                    self.cpu.state().rip
                )));
            }
            match self.cpu.step(&mut self.mem, &mut self.os)? {
                Exit::Continue => steps += 1,
                other => {
                    return Err(EmuError::Os(format!(
                        "run_until_rip({target:#x}): process left the run loop with {other:?} after {steps} steps"
                    )))
                }
            }
        }
        Ok(steps)
    }

    pub fn run(mut self) -> Result<RunResult> {
        self.run_borrowed()
    }

    pub fn run_borrowed(&mut self) -> Result<RunResult> {
        let mut steps: u64 = 0;
        let refresh_kuser = self.clock.is_virtual();
        let mut next_kuser_refresh = KUSER_REFRESH_INSTRUCTIONS;
        const TAIL: usize = 24;
        let mut recent: std::collections::VecDeque<u64> = std::collections::VecDeque::with_capacity(TAIL + 1);
        let mut debugging = self.dbg.is_attached();
        let mut stepping = false;
        let mut step_target = u64::MAX;
        let exit_code = loop {
            if self.max_steps != 0 && steps >= self.max_steps {
                let tail = self.rip_trail(&recent);
                let e = EmuError::Os(format!("instruction budget exhausted after {steps} steps"));
                return Err(self.fault_debugged(debugging, e, steps, &tail));
            }
            recent.push_back(self.cpu.state().rip);
            if recent.len() > TAIL {
                recent.pop_front();
            }

            let step_rip = self.cpu.state().rip;
            self.os.set_guest_mode32(self.cpu.bits() == Bits::B32);
            if debugging {
                let mut reason = self.debug_pending_stop(steps, step_target);
                if reason.is_none() {
                    match self.dbg.take_request() {
                        StopRequest::Pause => reason = Some(StopReason::Paused),
                        StopRequest::Step => {
                            step_target = steps + 1;
                            stepping = true;
                        }
                        StopRequest::Run => {}
                    }
                }
                if reason.is_none() && self.dbg.is_break(step_rip) {
                    reason = Some(StopReason::Breakpoint { rip: step_rip });
                }
                if let Some(reason) = reason {
                    let trail = self.rip_trail(&recent);
                    match self.debug_stop(reason, steps, &trail) {
                        DebugAction::Continue => {
                            stepping = false;
                            step_target = u64::MAX;
                        }
                        DebugAction::Step => {
                            stepping = true;
                            step_target = steps + 1;
                        }
                        DebugAction::Detach => {
                            debugging = false;
                            stepping = false;
                            step_target = u64::MAX;
                        }
                        DebugAction::Kill => {
                            return Err(EmuError::Os(format!(
                                "the debugger abandoned the run after {steps} instructions"
                            )));
                        }
                    }
                }
            }
            let interpret_only = debugging && self.debug_needs_interpreter(stepping, steps);
            if let Some(jit) = self.jit.as_mut().filter(|_| !interpret_only) {
                let mode = match self.cpu.bits() {
                    Bits::B64 => exemu_jit::Mode::Long,
                    Bits::B32 => exemu_jit::Mode::Protected,
                };
                let budget = if self.exc_depth != 0 {
                    0
                } else {
                    let mut b = CHAIN_MAX_INSTRUCTIONS;
                    b = b.min(exemu_core::Hooks::retire_budget(&self.os));
                    if refresh_kuser {
                        b = b.min(next_kuser_refresh.saturating_sub(steps));
                    }
                    if self.max_steps != 0 {
                        b = b.min(self.max_steps.saturating_sub(steps));
                    }
                    if debugging {
                        b = b.min(self.dbg.break_at_step().saturating_sub(steps));
                    }
                    b
                };
                let ran = jit.run(self.cpu.state_mut(), &mut self.mem, mode, budget);
                let insns = ran.insns();
                if insns != 0 {
                    self.clock.retire(insns as u64);
                    steps += insns as u64;
                    exemu_core::Hooks::retire(
                        &mut self.os,
                        insns as u64,
                        self.cpu.state_mut(),
                        &mut self.mem,
                    )?;
                    self.apply_thread_mode_switch();
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                if matches!(ran, exemu_jit::Run::Executed { .. }) {
                    continue;
                }
            }
            let outcome = self.cpu.step(&mut self.mem, &mut self.os);
            self.apply_thread_mode_switch();
            let tail = || self.rip_trail(&recent);
            match outcome {
                Ok(Exit::Continue) => {
                    steps += 1;
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                Ok(Exit::ProcessExit(code)) => {
                    if let Some(u) = self.os.take_unhandled_exception() {
                        let t = self.rip_trail(&recent);
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    break code;
                }
                Ok(Exit::Halted) => break 0,
                Ok(Exit::Interrupt(n)) => {
                    let t = tail();
                    if self.try_deliver_hw_exception(ExcSource::Interrupt(n), steps, &t)? {
                        continue;
                    }
                    if let Some(u) = self.os.take_unhandled_exception() {
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    let e = EmuError::Os(format!("unhandled interrupt {n:#x}"));
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
                Ok(Exit::Syscall(index)) => {
                    let t = tail();
                    let e = EmuError::Os(format!("SYSCALL {index:#x} escaped the dispatcher"));
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
                Err(e) => {
                    let t = tail();
                    if self.try_deliver_hw_exception(ExcSource::Error(&e), steps, &t)? {
                        continue;
                    }
                    if let Some(u) = self.os.take_unhandled_exception() {
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
            }
        };

        if let Some(tx) = self.dbg_events.as_ref() {
            let _ = tx.send(DebugEvent::Exited { code: exit_code, steps });
        }

        Ok(RunResult {
            exit_code,
            steps,
            stdout: self.os.captured_stdout().to_vec(),
            stderr: self.os.captured_stderr().to_vec(),
            sandbox: self.sandbox.clone(),
            children_created: self.os.children_created(),
            jit: self.jit_report(),
        })
    }

    fn rip_trail(&self, recent: &std::collections::VecDeque<u64>) -> Vec<u64> {
        match self.jit.as_ref() {
            Some(jit) => jit.recent_blocks(),
            None => recent.iter().copied().collect(),
        }
    }

    pub fn jit_report(&self) -> Option<JitReport> {
        let jit = self.jit.as_ref()?;
        let s = jit.stats();
        Some(JitReport {
            blocks_compiled: s.blocks_compiled,
            blocks_executed: s.blocks_executed,
            chains: s.chains,
            insns_executed: s.insns_executed,
            faults: s.faults,
            not_compiled: s.not_compiled,
            flushes: s.flushes,
            code_bytes: s.peak_code_bytes.max(jit.code_bytes()),
            declined: s.top_declined(16),
        })
    }

    fn apply_thread_mode_switch(&mut self) {
        if let Some(mode32) = self.os.take_thread_mode_switch() {
            self.cpu.set_bits(if mode32 { Bits::B32 } else { Bits::B64 });
        }
    }
}
