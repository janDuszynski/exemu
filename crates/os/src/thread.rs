//! A cooperative thread scheduler that lives entirely in the OS layer
//! (roadmap P3.4).
//!
//! The interpreter always runs whatever register state is in its single
//! `CpuState`; the OS layer owns a table of [`Thread`]s and, at yield points,
//! saves the running thread's state and loads another's — returning
//! [`Outcome::Resume`] so the interpreter simply keeps stepping the newly
//! installed thread. Each thread has its own stack (reserved from the
//! VirtualAlloc arena) and its own TLS/FLS values.
//!
//! Yield points: `Sleep`/`SleepEx`/`SwitchToThread` (yield, stay ready), a
//! blocking `WaitForSingle/MultipleObjects` (block until the object signals),
//! `ExitThread` / a start-routine return (terminate), and a timeslice counter
//! (preempt a CPU-bound thread). A blocked thread keeps its `rip` at the wait
//! thunk, so resuming it simply re-runs the wait — the single source of truth
//! for wait semantics stays in [`crate::sync`].

use std::collections::{HashMap, VecDeque};

use exemu_core::{CpuState, Memory, Perm, Reg, Result};

use crate::api::Outcome;
use crate::msg::PostedMsg;
use crate::sync::KObject;
use crate::WinOs;

const CREATE_SUSPENDED: u64 = 0x0000_0004;
const STILL_ACTIVE: u32 = 259;
const THREAD_STACK_SIZE: u64 = 0x0010_0000; // 1 MiB default per thread
const TIMESLICE: u64 = 50_000; // instructions between preemptive yields

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadState {
    Ready,
    Running,
    Blocked,
    Suspended,
    Terminated,
}

/// A blocked thread's wait condition — used by the scheduler to decide when the
/// thread is runnable again (the wait itself re-runs on resume).
pub(crate) struct WaitDesc {
    pub handles: Vec<u64>,
    pub all: bool,
}

/// One guest thread.
pub(crate) struct Thread {
    pub tid: u32,
    /// The thread's own `KObject::Thread` handle (0 for the main thread, which
    /// callers reach via the `GetCurrentThread` pseudo-handle instead).
    pub handle: u64,
    pub state: ThreadState,
    /// Saved register state; valid whenever the thread is not `Running`.
    pub saved: CpuState,
    pub exit_code: u32,
    /// Owned stack region `[stack_base, stack_base+stack_size)` (0 = the main
    /// thread's stack, which the application maps and owns).
    pub stack_base: u64,
    pub stack_size: u64,
    pub suspend_count: u32,
    pub wait: Option<WaitDesc>,
    tls: HashMap<u64, u64>,
    fls: HashMap<u64, u64>,
    /// This thread's Win32 message queue (roadmap P5a.1). `PostMessage`/
    /// `PostThreadMessage` enqueue here; `GetMessage`/`PeekMessage` drain it.
    pub msgs: VecDeque<PostedMsg>,
    /// A pending `WM_QUIT` exit code set by `PostQuitMessage` (delivered once the
    /// queue drains).
    pub quit_code: Option<i32>,
}

impl Thread {
    /// The main thread (index 0): already running, no owned stack.
    pub(crate) fn main(tid: u32) -> Self {
        Thread {
            tid,
            handle: 0,
            state: ThreadState::Running,
            saved: CpuState::new(),
            exit_code: STILL_ACTIVE,
            stack_base: 0,
            stack_size: 0,
            suspend_count: 0,
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
        }
    }

    /// This thread's TLS or FLS value map (mutable).
    pub(crate) fn tls_values(&mut self, fiber: bool) -> &mut HashMap<u64, u64> {
        if fiber {
            &mut self.fls
        } else {
            &mut self.tls
        }
    }

    /// This thread's TLS or FLS value map (shared).
    pub(crate) fn tls_values_ref(&self, fiber: bool) -> &HashMap<u64, u64> {
        if fiber {
            &self.fls
        } else {
            &self.tls
        }
    }
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

impl WinOs {
    // ---- scheduler core --------------------------------------------------

    /// Whether thread `i` can run now: `Ready`, or `Blocked` with a wait that
    /// is currently satisfiable.
    fn runnable(&self, i: usize) -> bool {
        let t = &self.threads[i];
        match t.state {
            ThreadState::Ready => true,
            ThreadState::Blocked => t.wait.as_ref().map_or(true, |w| self.wait_satisfiable(w, t.tid)),
            _ => false,
        }
    }

    /// Peek whether a wait descriptor is satisfied for thread `tid` (no
    /// consumption). An unknown handle counts as signaled (as the waits do).
    fn wait_satisfiable(&self, w: &WaitDesc, tid: u32) -> bool {
        let sig = |h: &u64| self.kobjects.get(h).map_or(true, |o| o.is_signaled(tid));
        if w.all {
            w.handles.iter().all(sig)
        } else {
            w.handles.iter().any(sig)
        }
    }

    /// Round-robin: the next runnable thread after the current one, if any.
    fn pick_next(&self) -> Option<usize> {
        let n = self.threads.len();
        (1..n).map(|s| (self.current + s) % n).find(|&i| self.runnable(i))
    }

    /// Install thread `next` as the running thread.
    fn activate(&mut self, cpu: &mut CpuState, next: usize) {
        *cpu = self.threads[next].saved.clone();
        self.threads[next].state = ThreadState::Running;
        self.threads[next].wait = None;
        self.current = next;
        self.current_tid = self.threads[next].tid;
        self.sched_ticks = 0;
    }

    /// Block the running thread on `desc` and switch to another runnable thread.
    /// Returns `false` (no switch) if none is runnable, so the caller can fall
    /// back to completing the wait immediately.
    pub(crate) fn block_and_switch(&mut self, cpu: &mut CpuState, desc: WaitDesc) -> bool {
        let Some(next) = self.pick_next() else { return false };
        let cur = self.current;
        self.threads[cur].saved = cpu.clone(); // rip is still at the wait thunk
        self.threads[cur].state = ThreadState::Blocked;
        self.threads[cur].wait = Some(desc);
        self.activate(cpu, next);
        true
    }

    /// Yield the running thread (it stays `Ready`, with `cpu` already holding
    /// its post-call state) to another runnable thread. Returns whether a
    /// switch happened.
    fn yield_and_switch(&mut self, cpu: &mut CpuState) -> bool {
        let Some(next) = self.pick_next() else { return false };
        let cur = self.current;
        self.threads[cur].saved = cpu.clone();
        self.threads[cur].state = ThreadState::Ready;
        self.activate(cpu, next);
        true
    }

    /// Timeslice preemption: after `TIMESLICE` instructions with more than one
    /// thread, yield so a CPU-bound thread can't starve the others. `cpu` holds
    /// the mid-code state to save. Returns whether a switch happened.
    pub(crate) fn preempt(&mut self, cpu: &mut CpuState) -> bool {
        if self.threads.len() < 2 {
            return false;
        }
        self.sched_ticks += 1;
        if self.sched_ticks < TIMESLICE {
            return false;
        }
        self.sched_ticks = 0;
        self.yield_and_switch(cpu)
    }

    fn thread_by_handle(&self, handle: u64) -> Option<usize> {
        self.threads.iter().position(|t| t.handle == handle && handle != 0)
    }

    // ---- the thread APIs -------------------------------------------------

    /// CreateThread(lpAttr, dwStackSize, lpStart, lpParam, dwFlags, lpThreadId)
    /// and `_beginthreadex` (same argument positions). Does not switch — the
    /// creating thread keeps running and the new thread starts when it yields.
    pub(crate) fn create_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let req_stack = self.arg(cpu, mem, 1)?;
        let entry = self.arg(cpu, mem, 2)?;
        let param = self.arg(cpu, mem, 3)?;
        let flags = self.arg(cpu, mem, 4)?;
        let tid_out = self.arg(cpu, mem, 5)?;

        let stack_size = align_up(req_stack.max(THREAD_STACK_SIZE), 0x1000);
        let Some(stack_base) = self.map_anywhere(mem, stack_size, Perm::RWX, "thread-stack") else {
            self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
            return Ok(Outcome::Return(0));
        };

        // Build the start state: a `call entry` frame returning to the
        // thread-exit thunk, with the parameter passed per the ABI.
        let mut st = CpuState::new();
        let stack_top = stack_base + stack_size;
        let exit_thunk = self.thread_exit_thunk;
        if self.cfg.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 8;
            mem.write_u64(sp, exit_thunk)?;
            st.set_rsp(sp);
            st.set_reg(Reg::Rcx, param);
        } else {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 4;
            mem.write_u32(sp, param as u32)?; // [esp+4] = lpParameter
            sp -= 4;
            mem.write_u32(sp, exit_thunk as u32)?; // [esp] = return address
            st.set_rsp(sp);
        }
        st.rip = entry;

        let tid = self.next_tid;
        self.next_tid += 1;
        let handle = self.alloc_khandle();
        self.kobjects.insert(handle, KObject::Thread { exited: false });
        let suspended = flags & CREATE_SUSPENDED != 0;
        self.threads.push(Thread {
            tid,
            handle,
            state: if suspended { ThreadState::Suspended } else { ThreadState::Ready },
            saved: st,
            exit_code: STILL_ACTIVE,
            stack_base,
            stack_size,
            suspend_count: u32::from(suspended),
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
        });
        if tid_out != 0 {
            mem.write_u32(tid_out, tid)?;
        }
        Ok(Outcome::Return(handle))
    }

    /// Reclaim thread `i`'s owned stack region (no-op for the main thread).
    fn free_thread_stack(&mut self, mem: &mut dyn Memory, i: usize) {
        let (base, size) = (self.threads[i].stack_base, self.threads[i].stack_size);
        if base != 0 {
            let _ = mem.unmap(base, size);
        }
    }

    /// End the running thread with `code`; both `ExitThread` and a start-routine
    /// return (via the thread-exit thunk) land here. Switches to another
    /// runnable thread, or exits the process if this was the last one.
    pub(crate) fn exit_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, code: u32) -> Result<Outcome> {
        let cur = self.current;
        self.threads[cur].state = ThreadState::Terminated;
        self.threads[cur].exit_code = code;
        let handle = self.threads[cur].handle;
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&handle) {
            *exited = true; // wake any joiner
        }
        self.free_thread_stack(mem, cur);
        match self.pick_next() {
            Some(next) => {
                self.activate(cpu, next);
                Ok(Outcome::Resume)
            }
            None => Ok(Outcome::Exit(code as i32)),
        }
    }

    /// The thread-exit thunk: a start routine returned; its return value (EAX)
    /// is the exit code.
    pub(crate) fn thread_start_returned(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = cpu.gpr_read(Reg::Rax as u8, 4) as u32;
        self.exit_thread(cpu, mem, code)
    }

    /// ExitThread(dwExitCode).
    pub(crate) fn api_exit_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as u32;
        self.exit_thread(cpu, mem, code)
    }

    /// ResumeThread(hThread) → previous suspend count (or (DWORD)-1 on error).
    pub(crate) fn resume_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let h = self.arg(cpu, mem, 0)?;
        let Some(i) = self.thread_by_handle(h) else {
            return Ok(Outcome::Return(u32::MAX as u64));
        };
        let prev = self.threads[i].suspend_count;
        if prev > 0 {
            self.threads[i].suspend_count -= 1;
            if self.threads[i].suspend_count == 0 && self.threads[i].state == ThreadState::Suspended {
                self.threads[i].state = ThreadState::Ready;
            }
        }
        Ok(Outcome::Return(prev as u64))
    }

    /// SuspendThread(hThread) → previous suspend count (or (DWORD)-1 on error).
    pub(crate) fn suspend_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let h = self.arg(cpu, mem, 0)?;
        let Some(i) = self.thread_by_handle(h) else {
            return Ok(Outcome::Return(u32::MAX as u64));
        };
        let prev = self.threads[i].suspend_count;
        self.threads[i].suspend_count += 1;
        // Suspending another (non-terminated) thread parks it until resumed.
        if i != self.current && !matches!(self.threads[i].state, ThreadState::Terminated) {
            self.threads[i].state = ThreadState::Suspended;
        }
        Ok(Outcome::Return(prev as u64))
    }

    /// TerminateThread(hThread, dwExitCode).
    pub(crate) fn terminate_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let h = self.arg(cpu, mem, 0)?;
        let code = self.arg(cpu, mem, 1)? as u32;
        let Some(i) = self.thread_by_handle(h) else {
            return Ok(Outcome::Return(0));
        };
        self.threads[i].state = ThreadState::Terminated;
        self.threads[i].exit_code = code;
        let handle = self.threads[i].handle;
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&handle) {
            *exited = true;
        }
        self.free_thread_stack(mem, i);
        if i == self.current {
            return match self.pick_next() {
                Some(next) => {
                    self.activate(cpu, next);
                    Ok(Outcome::Resume)
                }
                None => Ok(Outcome::Exit(code as i32)),
            };
        }
        Ok(Outcome::Return(1))
    }

    /// GetExitCodeThread(hThread, lpExitCode) — STILL_ACTIVE until terminated.
    pub(crate) fn get_exit_code_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let h = self.arg(cpu, mem, 0)?;
        let out = self.arg(cpu, mem, 1)?;
        let code = self.thread_by_handle(h).map_or(STILL_ACTIVE, |i| {
            if self.threads[i].state == ThreadState::Terminated {
                self.threads[i].exit_code
            } else {
                STILL_ACTIVE
            }
        });
        if out != 0 {
            mem.write_u32(out, code)?;
        }
        Ok(Outcome::Return(1))
    }

    /// Sleep(ms) / SleepEx(ms, alertable): complete the (void/DWORD) call, then
    /// yield to another runnable thread. `argc` keeps the stdcall stack balanced.
    pub(crate) fn sleep(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, argc: u32) -> Result<Outcome> {
        self.complete_and_yield(cpu, mem, 0, argc)
    }

    /// SwitchToThread() → BOOL: nonzero if it yielded to another thread.
    pub(crate) fn switch_to_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let has_other = self.pick_next().is_some();
        self.complete_and_yield(cpu, mem, u64::from(has_other), 0)
    }

    /// Complete an API returning `retval` (cleaning `argc` stack args), then
    /// yield. The current thread stays Ready and resumes after the call.
    fn complete_and_yield(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, retval: u64, argc: u32) -> Result<Outcome> {
        if self.cfg.is_64bit {
            cpu.set_reg(Reg::Rax, retval);
        } else {
            cpu.gpr_write(0, 4, retval);
        }
        self.ret(cpu, mem, argc)?;
        self.yield_and_switch(cpu);
        Ok(Outcome::Resume)
    }
}
