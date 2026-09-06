use std::collections::{HashMap, VecDeque};

use exemu_core::{CpuState, Memory, Perm, Reg, Result};

use crate::api::Outcome;
use crate::msg::PostedMsg;
use crate::sync::KObject;
use crate::WinOs;

const CREATE_SUSPENDED: u64 = 0x0000_0004;
const STILL_ACTIVE: u32 = 259;
const THREAD_STACK_SIZE: u64 = 0x0010_0000;
const TIMESLICE: u64 = 50_000;

const THREAD_TEB_SIZE: u64 = 0x4000;

const WOW64_THREAD_BLOCK: u64 = 0x8000;
const WOW64_THREAD_CPU_AREA: u64 = THREAD_TEB_SIZE + 0x2000;

mod teb64 {
    pub const NT_TIB_EXCEPTION_LIST: u64 = 0x000;
    pub const NT_TIB_STACK_BASE: u64 = 0x008;
    pub const NT_TIB_STACK_LIMIT: u64 = 0x010;
    pub const NT_TIB_SELF: u64 = 0x030;
    pub const CLIENT_ID_PROCESS: u64 = 0x040;
    pub const CLIENT_ID_THREAD: u64 = 0x048;
    pub const TLS_POINTER: u64 = 0x058;
    pub const PEB: u64 = 0x060;
    pub const STATIC_UNICODE_STRING: u64 = 0x1258;
    pub const STATIC_UNICODE_BUFFER: u64 = 0x1268;
    pub const COUNT_OF_OWNED_CRIT_SECS: u64 = 0x6C8;
    pub const TLS_EXPANSION_SLOTS: u64 = 0x1780;
    pub const DEALLOCATION_STACK: u64 = 0x1478;

    pub const ACTIVATION_CONTEXT_STACK_POINTER: u64 = 0x2c8;

    pub const ACTIVATION_CONTEXT_STACK: u64 = 0x1900;

    pub const ACTIVATION_CONTEXT_STACK_SIZE: u64 = 0x28;

    pub const STATIC_UNICODE_MAX_BYTES: u16 = 261 * 2;
}

mod teb32 {
    pub const NT_TIB_EXCEPTION_LIST: u64 = 0x000;
    pub const NT_TIB_STACK_BASE: u64 = 0x004;
    pub const NT_TIB_STACK_LIMIT: u64 = 0x008;
    pub const NT_TIB_SELF: u64 = 0x018;
    pub const CLIENT_ID_PROCESS: u64 = 0x020;
    pub const CLIENT_ID_THREAD: u64 = 0x024;
    pub const TLS_POINTER: u64 = 0x02C;
    pub const PEB: u64 = 0x030;
    pub const STATIC_UNICODE_STRING: u64 = 0x0AC;
    pub const STATIC_UNICODE_BUFFER: u64 = 0x0B4;
    pub const COUNT_OF_OWNED_CRIT_SECS: u64 = 0x38C;
    pub const TLS_EXPANSION_SLOTS: u64 = 0x0F94;
    pub const DEALLOCATION_STACK: u64 = 0x0E0C;
    pub const STATIC_UNICODE_MAX_BYTES: u16 = 261 * 2;
}

const _: () = assert!(
    teb64::ACTIVATION_CONTEXT_STACK + teb64::ACTIVATION_CONTEXT_STACK_SIZE
        <= THREAD_TEB_SIZE - 0x140,
    "ACTIVATION_CONTEXT_STACK collides with the syscall_frame tail"
);

const PROCESS_ID: u64 = crate::CURRENT_PROCESS_ID;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadState {
    Ready,
    Running,
    Blocked,
    Suspended,
    Terminated,
}

pub(crate) struct WaitDesc {
    pub handles: Vec<u64>,
    pub all: bool,
}

pub(crate) struct Thread {
    pub tid: u32,
    pub handle: u64,
    pub state: ThreadState,
    pub saved: CpuState,
    pub exit_code: u32,
    pub stack_base: u64,
    pub stack_size: u64,
    pub teb_base: u64,
    pub teb_owned: u64,
    pub suspend_count: u32,
    pub wait: Option<WaitDesc>,
    tls: HashMap<u64, u64>,
    fls: HashMap<u64, u64>,
    pub msgs: VecDeque<PostedMsg>,
    pub quit_code: Option<i32>,
    pub pending_entry: Option<(u64, u64)>,
    pub mode32: bool,
    pub wow64_block: u64,
    pub wow64_stack32: (u64, u64),
}

impl Thread {
    pub(crate) fn main(tid: u32) -> Self {
        Thread {
            tid,
            handle: 0,
            state: ThreadState::Running,
            saved: CpuState::new(),
            exit_code: STILL_ACTIVE,
            stack_base: 0,
            stack_size: 0,
            teb_base: 0,
            teb_owned: 0,
            suspend_count: 0,
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
            pending_entry: None,
            mode32: false,
            wow64_block: 0,
            wow64_stack32: (0, 0),
        }
    }

    pub(crate) fn tls_values(&mut self, fiber: bool) -> &mut HashMap<u64, u64> {
        if fiber {
            &mut self.fls
        } else {
            &mut self.tls
        }
    }

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

    fn runnable(&self, i: usize) -> bool {
        let t = &self.threads[i];
        match t.state {
            ThreadState::Ready => true,
            ThreadState::Blocked => t.wait.as_ref().map_or(true, |w| self.wait_satisfiable(w, t.tid)),
            _ => false,
        }
    }

    fn wait_satisfiable(&self, w: &WaitDesc, tid: u32) -> bool {
        let sig = |h: &u64| self.kobjects.get(h).map_or(true, |o| o.is_signaled(tid));
        if w.all {
            w.handles.iter().all(sig)
        } else {
            w.handles.iter().any(sig)
        }
    }

    fn pick_next(&self) -> Option<usize> {
        let n = self.threads.len();
        (1..n).map(|s| (self.current + s) % n).find(|&i| self.runnable(i))
    }

    fn activate(&mut self, cpu: &mut CpuState, next: usize) {
        let cur = self.current;
        self.threads[cur].mode32 = self.guest_mode32;
        self.pending_mode_switch = Some(self.threads[next].mode32);
        *cpu = self.threads[next].saved.clone();
        self.threads[next].state = ThreadState::Running;
        self.threads[next].wait = None;
        self.current = next;
        self.current_tid = self.threads[next].tid;
        self.sched_ticks = 0;
    }

    pub(crate) fn block_and_switch(&mut self, cpu: &mut CpuState, desc: WaitDesc) -> bool {
        let Some(next) = self.pick_next() else { return false };
        let cur = self.current;
        self.threads[cur].saved = cpu.clone();
        self.threads[cur].state = ThreadState::Blocked;
        self.threads[cur].wait = Some(desc);
        self.activate(cpu, next);
        true
    }

    fn yield_and_switch(&mut self, cpu: &mut CpuState) -> bool {
        let Some(next) = self.pick_next() else { return false };
        let cur = self.current;
        self.threads[cur].saved = cpu.clone();
        self.threads[cur].state = ThreadState::Ready;
        self.activate(cpu, next);
        true
    }

    pub(crate) fn preempt(&mut self, cpu: &mut CpuState) -> bool {
        self.preempt_by(cpu, 1)
    }

    pub(crate) fn ticks_left(&self) -> u64 {
        if self.threads.len() < 2 {
            u64::MAX
        } else {
            TIMESLICE.saturating_sub(self.sched_ticks)
        }
    }

    pub(crate) fn preempt_by(&mut self, cpu: &mut CpuState, n: u64) -> bool {
        if self.threads.len() < 2 {
            return false;
        }
        self.sched_ticks += n;
        if self.sched_ticks < TIMESLICE {
            return false;
        }
        self.sched_ticks = 0;
        self.yield_and_switch(cpu)
    }

    fn thread_by_handle(&self, handle: u64) -> Option<usize> {
        self.threads.iter().position(|t| t.handle == handle && handle != 0)
    }

    fn seed_teb_64(
        &self,
        mem: &mut dyn Memory,
        teb_base: u64,
        tid: u32,
        peb: u64,
        stack_top: u64,
        stack_base: u64,
    ) -> Result<()> {
        if self.cfg.is_64bit {
            let w = |mem: &mut dyn Memory, off: u64, v: u64| mem.write_u64(teb_base + off, v);
            w(mem, teb64::NT_TIB_EXCEPTION_LIST, u64::MAX)?;
            w(mem, teb64::NT_TIB_STACK_BASE, stack_top)?;
            w(mem, teb64::NT_TIB_STACK_LIMIT, stack_base)?;
            w(mem, teb64::NT_TIB_SELF, teb_base)?;
            w(mem, teb64::CLIENT_ID_PROCESS, PROCESS_ID)?;
            w(mem, teb64::CLIENT_ID_THREAD, tid as u64)?;
            w(mem, teb64::TLS_POINTER, 0)?;
            w(mem, teb64::PEB, peb)?;
            let len_maxlen = (teb64::STATIC_UNICODE_MAX_BYTES as u64) << 16;
            w(mem, teb64::STATIC_UNICODE_STRING, len_maxlen)?;
            w(mem, teb64::STATIC_UNICODE_STRING + 8, teb_base + teb64::STATIC_UNICODE_BUFFER)?;
            w(mem, teb64::COUNT_OF_OWNED_CRIT_SECS, 0)?;
            w(mem, teb64::DEALLOCATION_STACK, stack_base)?;
            w(mem, teb64::TLS_EXPANSION_SLOTS, 0)?;
            let actx = teb_base + teb64::ACTIVATION_CONTEXT_STACK;
            w(mem, teb64::ACTIVATION_CONTEXT_STACK_POINTER, actx)?;
            w(mem, teb64::ACTIVATION_CONTEXT_STACK + 0x08, actx + 0x08)?;
            w(mem, teb64::ACTIVATION_CONTEXT_STACK + 0x10, actx + 0x08)?;
        } else {
            let w4 = |mem: &mut dyn Memory, off: u64, v: u32| mem.write_u32(teb_base + off, v);
            w4(mem, teb32::NT_TIB_EXCEPTION_LIST, u32::MAX)?;
            w4(mem, teb32::NT_TIB_STACK_BASE, stack_top as u32)?;
            w4(mem, teb32::NT_TIB_STACK_LIMIT, stack_base as u32)?;
            w4(mem, teb32::NT_TIB_SELF, teb_base as u32)?;
            w4(mem, teb32::CLIENT_ID_PROCESS, PROCESS_ID as u32)?;
            w4(mem, teb32::CLIENT_ID_THREAD, tid)?;
            w4(mem, teb32::TLS_POINTER, 0)?;
            w4(mem, teb32::PEB, peb as u32)?;
            let len_maxlen = (teb32::STATIC_UNICODE_MAX_BYTES as u32) << 16;
            w4(mem, teb32::STATIC_UNICODE_STRING, len_maxlen)?;
            w4(mem, teb32::STATIC_UNICODE_STRING + 4, (teb_base + teb32::STATIC_UNICODE_BUFFER) as u32)?;
            w4(mem, teb32::COUNT_OF_OWNED_CRIT_SECS, 0)?;
            w4(mem, teb32::DEALLOCATION_STACK, stack_base as u32)?;
            w4(mem, teb32::TLS_EXPANSION_SLOTS, 0)?;
        }
        Ok(())
    }

    pub fn seed_main_teb(&self, mem: &mut dyn Memory, stack_base: u64, stack_top: u64) -> Result<()> {
        let teb = self.cfg.teb_base;
        if teb == 0 {
            return Ok(());
        }
        self.seed_teb_64(mem, teb, 0x1001 , self.cfg.peb_addr, stack_top, stack_base)
    }

    fn new_thread_teb(&mut self, mem: &mut dyn Memory, tid: u32, stack_base: u64, stack_top: u64) -> Option<u64> {
        let teb_base = self.map_anywhere(mem, THREAD_TEB_SIZE, Perm::RW, "thread-teb")?;
        self.seed_teb_64(mem, teb_base, tid, self.cfg.peb_addr, stack_top, stack_base).ok()?;
        Some(teb_base)
    }

    fn spawn_thread(
        &mut self,
        mem: &mut dyn Memory,
        req_stack: u64,
        entry: u64,
        param: u64,
        suspended: bool,
    ) -> Result<Option<(u64, u32)>> {
        let stack_size = align_up(req_stack.max(THREAD_STACK_SIZE), 0x1000);
        let Some(stack_base) = self.map_anywhere(mem, stack_size, Perm::RWX, "thread-stack") else {
            self.last_error = 8;
            return Ok(None);
        };
        let stack_top = stack_base + stack_size;

        let tid = self.next_tid;
        self.next_tid += 1;

        let Some(teb_base) = self.new_thread_teb(mem, tid, stack_base, stack_top) else {
            let _ = mem.unmap(stack_base, stack_size);
            self.last_error = 8;
            return Ok(None);
        };

        let mut st = CpuState::new();
        st.gs_base = teb_base;
        st.fs_base = teb_base;
        let exit_thunk = self.thread_exit_thunk;
        let has_tls = !self.tls_callbacks.is_empty() || !self.thread_notify_targets().is_empty();
        let mut pending_entry = None;
        if self.cfg.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            if has_tls {
                sp -= 8;
                mem.write_u64(sp, self.thread_entry_thunk)?;
                st.rip = self.thread_tls_thunk;
                pending_entry = Some((entry, param));
            } else {
                sp -= 8;
                mem.write_u64(sp, exit_thunk)?;
                st.set_reg(Reg::Rcx, param);
                st.rip = entry;
            }
            st.set_rsp(sp);
        } else {
            let mut sp = (stack_top - 0x100) & !0xf;
            if has_tls {
                sp -= 4;
                mem.write_u32(sp, self.thread_entry_thunk as u32)?;
                st.rip = self.thread_tls_thunk;
                pending_entry = Some((entry, param));
            } else {
                sp -= 4;
                mem.write_u32(sp, param as u32)?;
                sp -= 4;
                mem.write_u32(sp, exit_thunk as u32)?;
                st.rip = entry;
            }
            st.set_rsp(sp);
        }

        let handle = self.alloc_khandle();
        self.kobjects.insert(handle, KObject::Thread { exited: false });
        self.threads.push(Thread {
            tid,
            handle,
            state: if suspended { ThreadState::Suspended } else { ThreadState::Ready },
            saved: st,
            exit_code: STILL_ACTIVE,
            stack_base,
            stack_size,
            teb_base,
            teb_owned: teb_base,
            suspend_count: u32::from(suspended),
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
            pending_entry,
            mode32: !self.cfg.is_64bit,
            wow64_block: 0,
            wow64_stack32: (0, 0),
        });
        Ok(Some((handle, tid)))
    }

    fn spawn_wow64_thread(
        &mut self,
        mem: &mut dyn Memory,
        req_stack: u64,
        entry: u64,
        param: u64,
        suspended: bool,
    ) -> Result<Option<(u64, u32)>> {
        let Some(w) = self.wow64_threading else {
            return Ok(None);
        };
        let stack32_size = align_up(req_stack.max(THREAD_STACK_SIZE), 0x1000);
        let Some(stack32) = self.map_anywhere_low(mem, stack32_size, Perm::RW, "wow64-thread-stack32") else {
            self.last_error = 8;
            return Ok(None);
        };
        let Some(stack64) = self.map_anywhere(mem, THREAD_STACK_SIZE, Perm::RWX, "wow64-thread-stack64") else {
            let _ = mem.unmap(stack32, stack32_size);
            self.last_error = 8;
            return Ok(None);
        };
        let Some(block) = self.map_anywhere_low(mem, WOW64_THREAD_BLOCK, Perm::RW, "wow64-thread-teb") else {
            let _ = mem.unmap(stack32, stack32_size);
            let _ = mem.unmap(stack64, THREAD_STACK_SIZE);
            self.last_error = 8;
            return Ok(None);
        };
        let (teb64, teb32, area) = (block, block + THREAD_TEB_SIZE, block + WOW64_THREAD_CPU_AREA);

        let tid = self.next_tid;
        self.next_tid += 1;
        let stack32_top = stack32 + stack32_size;
        self.seed_teb_64(mem, teb64, tid, self.cfg.peb_addr, stack64 + THREAD_STACK_SIZE, stack64)?;
        crate::wow64::seed_teb32(mem, teb32, self.wow64_peb32, stack32, stack32_top)?;
        crate::wow64::link_teb32(mem, teb64, teb32)?;
        crate::wow64::init_cpu_area(
            mem,
            teb64,
            area,
            crate::wow64::Start32 {
                eip: w.rtl_user_thread_start32 as u32,
                esp: ((stack32_top - 0x100) & !0xf) as u32,
                eax: entry as u32,
                ebx: param as u32,
            },
        )?;

        let mut st = CpuState::new();
        st.gs_base = teb64;
        st.fs_base = teb32;
        st.set_rsp(((stack64 + THREAD_STACK_SIZE - 0x100) & !0xf) - 8);
        st.set_reg(Reg::Rcx, 0);
        st.rip = w.ldrp_initialize;

        let handle = self.alloc_khandle();
        self.kobjects.insert(handle, KObject::Thread { exited: false });
        self.threads.push(Thread {
            tid,
            handle,
            state: if suspended { ThreadState::Suspended } else { ThreadState::Ready },
            saved: st,
            exit_code: STILL_ACTIVE,
            stack_base: stack64,
            stack_size: THREAD_STACK_SIZE,
            teb_base: teb64,
            teb_owned: 0,
            mode32: false,
            wow64_block: block,
            wow64_stack32: (stack32, stack32_size),
            suspend_count: u32::from(suspended),
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
            pending_entry: None,
        });
        Ok(Some((handle, tid)))
    }

    pub(crate) fn create_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let req_stack = self.arg(cpu, mem, 1)?;
        let entry = self.arg(cpu, mem, 2)?;
        let param = self.arg(cpu, mem, 3)?;
        let flags = self.arg(cpu, mem, 4)?;
        let tid_out = self.arg(cpu, mem, 5)?;

        let suspended = flags & CREATE_SUSPENDED != 0;
        let Some((handle, tid)) = self.spawn_thread(mem, req_stack, entry, param, suspended)? else {
            return Ok(Outcome::Return(0));
        };
        if tid_out != 0 {
            mem.write_u32(tid_out, tid)?;
        }
        Ok(Outcome::Return(handle))
    }

    fn free_thread_stack(&mut self, mem: &mut dyn Memory, i: usize) {
        let (base, size) = (self.threads[i].stack_base, self.threads[i].stack_size);
        if base != 0 {
            let _ = mem.unmap(base, size);
        }
        let teb = self.threads[i].teb_owned;
        if teb != 0 {
            let _ = mem.unmap(teb, THREAD_TEB_SIZE);
        }
        let block = self.threads[i].wow64_block;
        if block != 0 {
            let _ = mem.unmap(block, WOW64_THREAD_BLOCK);
        }
        let (s32, n32) = self.threads[i].wow64_stack32;
        if s32 != 0 {
            let _ = mem.unmap(s32, n32);
        }
    }

    pub(crate) fn exit_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, code: u32) -> Result<Outcome> {
        let cur = self.current;
        self.threads[cur].state = ThreadState::Terminated;
        self.threads[cur].exit_code = code;
        let handle = self.threads[cur].handle;
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&handle) {
            *exited = true;
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

    pub(crate) fn thread_start_returned(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = cpu.gpr_read(Reg::Rax as u8, 4) as u32;
        self.exit_thread(cpu, mem, code)
    }

    pub(crate) fn thread_tls_attach(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let module = self.cfg.image_base;
        let mut calls: Vec<(u64, Vec<u64>)> = self
            .tls_callbacks
            .iter()
            .map(|&cb| (cb, vec![module, 2 , 0]))
            .collect();
        for (entry, base) in self.thread_notify_targets() {
            calls.push((entry, vec![base, 2 , 0]));
        }
        self.invoke_callbacks(cpu, mem, calls, 0, 0, false)
    }

    pub(crate) fn thread_start_entry(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let cur = self.current;
        let (entry, param) = self.threads[cur].pending_entry.take().unwrap_or((0, 0));
        let exit_thunk = self.thread_exit_thunk;
        let base = cpu.rsp();
        self.setup_call_args(cpu, mem, entry, &[param], exit_thunk, base)?;
        Ok(Outcome::Resume)
    }

    pub(crate) fn api_exit_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as u32;
        self.exit_thread(cpu, mem, code)
    }

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

    pub(crate) fn suspend_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let h = self.arg(cpu, mem, 0)?;
        let Some(i) = self.thread_by_handle(h) else {
            return Ok(Outcome::Return(u32::MAX as u64));
        };
        let prev = self.threads[i].suspend_count;
        self.threads[i].suspend_count += 1;
        if i != self.current && !matches!(self.threads[i].state, ThreadState::Terminated) {
            self.threads[i].state = ThreadState::Suspended;
        }
        Ok(Outcome::Return(prev as u64))
    }

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

    pub(crate) fn sleep(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, argc: u32) -> Result<Outcome> {
        let ms = self.arg(cpu, mem, 0)? & 0xFFFF_FFFF;
        self.clock.credit_ms(ms);
        self.complete_and_yield(cpu, mem, 0, argc)
    }

    pub(crate) fn switch_to_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let has_other = self.pick_next().is_some();
        self.complete_and_yield(cpu, mem, u64::from(has_other), 0)
    }

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

    pub(crate) fn current_thread_teb(&self) -> u64 {
        self.threads.get(self.current).map_or(0, |t| t.teb_base)
    }

    fn nt_thread_index(&self, handle: u64) -> Option<usize> {
        if handle == NT_CURRENT_THREAD {
            return Some(self.current);
        }
        self.thread_by_handle(handle)
    }

    pub(crate) fn nt_create_thread_ex(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let entry = self.syscall_arg(cpu, mem, 4)?;
        let param = self.syscall_arg(cpu, mem, 5)?;
        let create_flags = self.syscall_arg(cpu, mem, 6)?;
        let stack_size = self.syscall_arg(cpu, mem, 8)?;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let suspended = create_flags & (CREATE_SUSPENDED_NT as u64) != 0;
        let spawned = if self.is_wow64() {
            self.spawn_wow64_thread(mem, stack_size, entry, param, suspended)?
        } else {
            self.spawn_thread(mem, stack_size, entry, param, suspended)?
        };
        match spawned {
            Some((handle, _tid)) => {
                self.write_ptr(mem, handle_out, handle)?;
                Ok(STATUS_SUCCESS)
            }
            None => Ok(STATUS_NO_MEMORY),
        }
    }

    pub(crate) fn nt_terminate_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let code = self.syscall_arg(cpu, mem, 1)? as u32;
        let Some(i) = self.nt_thread_index(handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        self.threads[i].state = ThreadState::Terminated;
        self.threads[i].exit_code = code;
        let khandle = self.threads[i].handle;
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&khandle) {
            *exited = true;
        }
        self.free_thread_stack(mem, i);
        if i == self.current {
            self.syscall_resume_as_is = true;
            match self.pick_next() {
                Some(next) => {
                    self.activate(cpu, next);
                }
                None => {
                    return Ok(code);
                }
            }
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_terminate_process(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let code = self.syscall_arg(cpu, mem, 1)? as i32;
        if handle == 0 || handle == u64::MAX {
            self.pending_syscall_exit = Some(code);
            return Ok(STATUS_SUCCESS);
        }
        if self.terminate_child(handle, code as u32) {
            return Ok(STATUS_SUCCESS);
        }
        Ok(STATUS_INVALID_HANDLE)
    }

    pub(crate) fn nt_suspend_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let prev_out = self.syscall_arg(cpu, mem, 1)?;
        let Some(i) = self.nt_thread_index(handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let prev = self.threads[i].suspend_count;
        self.threads[i].suspend_count += 1;
        if i != self.current && !matches!(self.threads[i].state, ThreadState::Terminated) {
            self.threads[i].state = ThreadState::Suspended;
        }
        if prev_out != 0 {
            mem.write_u32(prev_out, prev)?;
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_resume_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let prev_out = self.syscall_arg(cpu, mem, 1)?;
        if let Some(prev) = self.resume_child_thread(handle) {
            if prev_out != 0 {
                mem.write_u32(prev_out, prev)?;
            }
            return Ok(STATUS_SUCCESS);
        }
        let Some(i) = self.nt_thread_index(handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let prev = self.threads[i].suspend_count;
        if prev > 0 {
            self.threads[i].suspend_count -= 1;
            if self.threads[i].suspend_count == 0 && self.threads[i].state == ThreadState::Suspended {
                self.threads[i].state = ThreadState::Ready;
            }
        }
        if prev_out != 0 {
            mem.write_u32(prev_out, prev)?;
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_information_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let return_length = self.syscall_arg(cpu, mem, 4)?;
        if class == THREAD_WOW64_CONTEXT {
            return self.query_wow64_context(cpu, mem, handle, buffer, length, return_length);
        }
        if class != THREAD_BASIC_INFORMATION {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        let Some(i) = self.nt_thread_index(handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let need: u64 = if self.cfg.is_64bit { 0x30 } else { 0x1C };
        if buffer == 0 || length < need {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        let (exit_status, teb, tid) = {
            let t = &self.threads[i];
            let exit = if t.state == ThreadState::Terminated { t.exit_code } else { STILL_ACTIVE };
            (exit, t.teb_base, t.tid)
        };
        if self.cfg.is_64bit {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u64(buffer + 0x08, teb)?;
            mem.write_u64(buffer + 0x10, PROCESS_ID)?;
            mem.write_u64(buffer + 0x18, tid as u64)?;
            mem.write_u64(buffer + 0x20, 1)?;
            mem.write_u32(buffer + 0x28, 0)?;
            mem.write_u32(buffer + 0x2C, 0)?;
        } else {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u32(buffer + 0x04, teb as u32)?;
            mem.write_u32(buffer + 0x08, PROCESS_ID as u32)?;
            mem.write_u32(buffer + 0x0C, tid)?;
            mem.write_u32(buffer + 0x10, 1)?;
            mem.write_u32(buffer + 0x14, 0)?;
            mem.write_u32(buffer + 0x18, 0)?;
        }
        if return_length != 0 {
            mem.write_u32(return_length, need as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn query_wow64_context(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        handle: u64,
        buffer: u64,
        length: u64,
        return_length: u64,
    ) -> Result<u32> {
        if self.nt_thread_index(handle).is_none() {
            return Ok(STATUS_INVALID_HANDLE);
        }
        if buffer == 0 || length < WOW64_CONTEXT_SIZE {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        let teb = if cpu.gs_base != 0 { cpu.gs_base } else { self.cfg.teb_base };
        let area = mem.read_u64(teb + crate::wow64::TEB_CPU_AREA_PTR_OFF)?;
        if area == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let ctx = area + crate::wow64::CPU_AREA_HEADER_LEN;
        let mut buf = vec![0u8; WOW64_CONTEXT_SIZE as usize];
        mem.read(ctx, &mut buf)?;
        mem.write(buffer, &buf)?;
        if return_length != 0 {
            mem.write_u32(return_length, WOW64_CONTEXT_SIZE as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn set_wow64_context(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, buffer: u64, length: u64) -> Result<u32> {
        if buffer == 0 || length < WOW64_CONTEXT_SIZE {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        let teb = if cpu.gs_base != 0 { cpu.gs_base } else { self.cfg.teb_base };
        let area = mem.read_u64(teb + crate::wow64::TEB_CPU_AREA_PTR_OFF)?;
        if area == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let mut buf = vec![0u8; WOW64_CONTEXT_SIZE as usize];
        mem.read(buffer, &mut buf)?;
        mem.write(area + crate::wow64::CPU_AREA_HEADER_LEN, &buf)?;
        let header = mem.read_u32(area)?;
        mem.write_u32(area, header | crate::wow64::CPU_AREA_RELOAD_BIT)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_set_information_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        if class != THREAD_WOW64_CONTEXT {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        if self.nt_thread_index(handle).is_none() {
            return Ok(STATUS_INVALID_HANDLE);
        }
        self.set_wow64_context(cpu, mem, buffer, length)
    }

    pub(crate) fn nt_query_system_information(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let class = self.syscall_arg(cpu, mem, 0)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 1)?;
        let length = self.syscall_arg(cpu, mem, 2)?;
        let return_length = self.syscall_arg(cpu, mem, 3)?;
        if class != SYSTEM_EMULATION_BASIC_INFORMATION {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        const NEED: u64 = 0x40;
        if buffer == 0 || length < NEED {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        mem.write(buffer, &[0u8; NEED as usize])?;
        mem.write_u32(buffer + 0x08, 0x1000)?;
        mem.write_u32(buffer + 0x18, 0x1_0000)?;
        mem.write_u64(buffer + 0x20, 0x1_0000)?;
        mem.write_u64(buffer + 0x28, 0x7FFF_FFFF)?;
        mem.write_u64(buffer + 0x30, 1)?;
        mem.write_u8(buffer + 0x38, 1)?;
        if return_length != 0 {
            mem.write_u32(return_length, NEED as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_system_information_ex(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        use crate::wow64::arch_entry;
        let class = self.syscall_arg(cpu, mem, 0)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let return_length = self.syscall_arg(cpu, mem, 5)?;
        if class != crate::wow64::SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        let native = arch_entry::entry(
            crate::wow64::MACHINE_AMD64,
            arch_entry::KERNEL_MODE | arch_entry::USER_MODE | arch_entry::NATIVE,
        );
        let entries: [u32; 3] = if self.wow64_peb32 != 0 {
            [
                arch_entry::entry(crate::wow64::MACHINE_I386, arch_entry::USER_MODE | arch_entry::PROCESS),
                native,
                0,
            ]
        } else {
            [
                arch_entry::entry(crate::wow64::MACHINE_AMD64, arch_entry::USER_MODE | arch_entry::PROCESS),
                native,
                0,
            ]
        };
        let need = entries.len() as u64 * 4;
        if buffer == 0 || length < need {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        for (i, e) in entries.iter().enumerate() {
            mem.write_u32(buffer + i as u64 * 4, *e)?;
        }
        if return_length != 0 {
            mem.write_u32(return_length, need as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }
}

const NT_CURRENT_THREAD: u64 = u64::MAX - 1;
const CREATE_SUSPENDED_NT: u32 = 0x0000_0001;
const THREAD_BASIC_INFORMATION: u32 = 0;
const SYSTEM_EMULATION_BASIC_INFORMATION: u32 = 0x3e;
use crate::wow64::{THREAD_WOW64_CONTEXT, WOW64_CONTEXT_SIZE};

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

pub(crate) const SSDT_NT_CREATE_THREAD_EX: u32 = 0x85;
pub(crate) const SSDT_NT_TERMINATE_THREAD: u32 = 0x53;
pub(crate) const SSDT_NT_TERMINATE_PROCESS: u32 = 0x2c;
pub(crate) const SSDT_NT_SUSPEND_THREAD: u32 = 0xf5;
pub(crate) const SSDT_NT_RESUME_THREAD: u32 = 0x52;
pub(crate) const SSDT_NT_QUERY_INFORMATION_THREAD: u32 = 0x25;
pub(crate) const SSDT_NT_QUERY_SYSTEM_INFORMATION_EX: u32 = 0xcb;
pub(crate) const SSDT_NT_QUERY_SYSTEM_INFORMATION: u32 = 0x36;
pub(crate) const SSDT_NT_SET_INFORMATION_THREAD: u32 = 0xd;

pub(crate) fn ssdt_nt_create_thread_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_thread_ex(cpu, mem)
}
pub(crate) fn ssdt_nt_terminate_thread(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_terminate_thread(cpu, mem)
}
pub(crate) fn ssdt_nt_terminate_process(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_terminate_process(cpu, mem)
}
pub(crate) fn ssdt_nt_suspend_thread(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_suspend_thread(cpu, mem)
}
pub(crate) fn ssdt_nt_resume_thread(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_resume_thread(cpu, mem)
}
pub(crate) fn ssdt_nt_query_information_thread(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_information_thread(cpu, mem)
}
pub(crate) fn ssdt_nt_set_information_thread(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_set_information_thread(cpu, mem)
}
pub(crate) fn ssdt_nt_query_system_information(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_system_information(cpu, mem)
}
pub(crate) fn ssdt_nt_query_system_information_ex(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_system_information_ex(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WinConfig, WinOs};
    use exemu_core::Region;
    use exemu_memory::VirtualMemory;

    #[test]
    fn a_spawned_threads_block_leaves_room_for_the_debug_string_ring() {
        use crate::winedebug::{STRDUP_RING_OFF_32, STRDUP_RING_OFF_64, STRDUP_RING_SIZE};
        const {
            assert!(
                STRDUP_RING_OFF_64 + STRDUP_RING_SIZE <= THREAD_TEB_SIZE,
                "a spawned thread's TEB region cannot hold its debug-string ring"
            )
        };
        let (teb64, teb32, area) = (0u64, THREAD_TEB_SIZE, WOW64_THREAD_CPU_AREA);
        assert!(
            teb64 + STRDUP_RING_OFF_64 + STRDUP_RING_SIZE <= teb32,
            "the 64-bit ring runs into TEB32"
        );
        assert!(
            teb32 + STRDUP_RING_OFF_32 + STRDUP_RING_SIZE <= area,
            "the 32-bit ring runs into the CPU-reserved area"
        );
        const {
            assert!(
                STRDUP_RING_OFF_32 + STRDUP_RING_SIZE
                    <= crate::wow64::TEB32_ACTIVATION_CONTEXT_STACK,
                "the 32-bit ring overlaps TEB32's activation-context stack"
            )
        };
        assert!(area < WOW64_THREAD_BLOCK, "the CPU-reserved area is inside the block");
    }

    fn create_thread_ex(os: &mut WinOs, mem: &mut VirtualMemory, handle_out: u64) -> u32 {
        const GUEST_RSP: u64 = 0x2_0800;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, handle_out);
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        for (i, v) in [(4u64, 0x40_1000u64), (5, 0), (6, 0), (7, 0), (8, 0x1000)] {
            mem.write_u64(GUEST_RSP + 0x28 + (i - 4) * 8, v).unwrap();
        }
        os.nt_create_thread_ex(&mut cpu, mem).unwrap()
    }

    fn os_and_mem() -> (WinOs, VirtualMemory) {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", 0x2_0000, 0x1_0000, Perm::RW)).unwrap();
        let os = WinOs::new(WinConfig {
            is_64bit: true,
            api_base: 0x7EFF_0000_0000,
            heap_base: 0x2_0000_0000,
            heap_size: 0x10_0000,
            valloc_base: 0x40_0000_0000,
            echo: false,
            ..WinConfig::default()
        });
        (os, mem)
    }

    #[test]
    fn a_wow64_process_creates_a_real_32bit_thread() {
        const OUT: u64 = 0x2_0100;
        const LDRP: u64 = 0x7_0000_2ce0;
        const START32: u64 = 0x6000_e1d0;
        const ENTRY: u64 = 0x40_1000;

        let (mut os, mut mem) = os_and_mem();
        assert_eq!(create_thread_ex(&mut os, &mut mem, OUT), STATUS_SUCCESS, "control: 64-bit");
        assert_ne!(mem.read_u64(OUT).unwrap(), 0, "the control really produced a handle");
        let plain = os.threads.last().expect("the control thread");
        assert_eq!(plain.saved.rip, ENTRY, "a plain thread starts at its own start routine");
        assert_eq!(plain.wow64_block, 0, "…and owns no WoW64 block");

        let (mut os, mut mem) = os_and_mem();
        os.set_wow64_peb32(0x7f00_8000);
        os.set_wow64_threading(crate::wow64::Wow64Threading {
            ldrp_initialize: LDRP,
            rtl_user_thread_start32: START32,
        });
        assert!(os.is_wow64());
        assert_eq!(create_thread_ex(&mut os, &mut mem, OUT), STATUS_SUCCESS);
        assert_ne!(mem.read_u64(OUT).unwrap(), 0, "a handle was written");

        let t = os.threads.last().expect("the WoW64 thread");
        assert_eq!(t.saved.rip, LDRP, "a WoW64 thread starts in wow64!Wow64LdrpInitialize");
        assert!(!t.mode32, "…and in 64-bit mode, so that entry is not truncated to 0x2ce0");

        let (teb64, teb32) = (t.saved.gs_base, t.saved.fs_base);
        assert_eq!(teb64, t.teb_base);
        assert!(teb32 <= u32::MAX as u64, "TEB32 must be 32-bit addressable");
        assert_eq!(
            crate::wow64::teb32_of(&mem, teb64).unwrap(),
            Some(teb32),
            "TEB64 + (i32)WowTebOffset resolves to this thread's TEB32",
        );
        assert_ne!(teb64, 0x7f00_0000, "…and it is this thread's own pair, not the process's");

        let (s32, n32) = t.wow64_stack32;
        assert!(s32 != 0 && s32 + n32 <= u32::MAX as u64, "32-bit stack {s32:#x}+{n32:#x} is low");
        assert_eq!(
            mem.read_u32(teb32 + crate::wow64::TEB32_STACK_BASE).unwrap() as u64,
            s32 + n32,
            "TEB32.NtTib.StackBase is that stack's top",
        );

        let area = mem.read_u64(teb64 + crate::wow64::TEB_CPU_AREA_PTR_OFF).unwrap();
        assert_ne!(area, 0, "TEB64+0x1488 points at this thread's own CPU-reserved area");
        let ctx = area + crate::wow64::CPU_AREA_HEADER_LEN;
        assert_eq!(mem.read_u32(ctx + crate::wow64::CTX_EIP).unwrap() as u64, START32);
        assert_eq!(mem.read_u32(ctx + crate::wow64::CTX_EAX).unwrap() as u64, ENTRY);
        assert_eq!(mem.read_u32(ctx + crate::wow64::CTX_SEGCS).unwrap(), crate::wow64::SEL_CS32);
        let esp = mem.read_u32(ctx + crate::wow64::CTX_ESP).unwrap() as u64;
        assert!(esp > s32 && esp <= s32 + n32, "Esp {esp:#x} is inside the 32-bit stack");

        let (mut os, mut mem) = os_and_mem();
        os.set_wow64_peb32(0x7f00_8000);
        assert_eq!(create_thread_ex(&mut os, &mut mem, OUT), STATUS_NO_MEMORY);
    }

    #[test]
    fn a_thread_switch_carries_the_cpu_mode() {
        let (mut os, mut mem) = os_and_mem();
        os.set_wow64_peb32(0x7f00_8000);
        os.set_wow64_threading(crate::wow64::Wow64Threading {
            ldrp_initialize: 0x7_0000_2ce0,
            rtl_user_thread_start32: 0x6000_e1d0,
        });
        assert_eq!(create_thread_ex(&mut os, &mut mem, 0x2_0100), STATUS_SUCCESS);

        let mut cpu = CpuState::default();
        os.set_guest_mode32(true);
        assert!(os.take_thread_mode_switch().is_none(), "no switch has happened yet");
        assert!(os.yield_and_switch(&mut cpu), "the new thread is runnable");
        assert_eq!(os.take_thread_mode_switch(), Some(false), "it resumes in long mode");
        assert!(os.take_thread_mode_switch().is_none(), "…and the request is taken once");

        os.set_guest_mode32(false);
        assert!(os.yield_and_switch(&mut cpu), "back to the main thread");
        assert_eq!(os.take_thread_mode_switch(), Some(true), "which was in 32-bit mode");
    }
}
