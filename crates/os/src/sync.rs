use exemu_core::{CpuState, EmuError, Memory, Reg, Result};

use crate::api::Outcome;
use crate::thread::WaitDesc;
use crate::WinOs;

const WAIT_OBJECT_0: u64 = 0x0000_0000;
const WAIT_TIMEOUT: u64 = 0x0000_0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Event,
    Mutex,
    Semaphore,
    Timer,
}

#[derive(Debug, Clone, Copy)]
pub enum SignalOp {
    SetEvent,
    ResetEvent,
    PulseEvent,
    ReleaseMutex,
    ReleaseSemaphore,
}

pub(crate) enum KObject {
    Event { manual_reset: bool, signaled: bool },
    Mutex { owner: Option<u32>, recursion: u32 },
    Semaphore { count: i32, max: i32 },
    Timer { manual_reset: bool, signaled: bool },
    Thread { exited: bool },
    Process { exited: bool },
}

impl KObject {
    pub(crate) fn is_signaled(&self, tid: u32) -> bool {
        match self {
            KObject::Event { signaled, .. } | KObject::Timer { signaled, .. } => *signaled,
            KObject::Semaphore { count, .. } => *count > 0,
            KObject::Mutex { owner, .. } => owner.is_none() || *owner == Some(tid),
            KObject::Thread { exited } | KObject::Process { exited } => *exited,
        }
    }

    fn acquire(&mut self, tid: u32) -> bool {
        match self {
            KObject::Event { manual_reset, signaled } | KObject::Timer { manual_reset, signaled } => {
                if *signaled {
                    if !*manual_reset {
                        *signaled = false;
                    }
                    true
                } else {
                    false
                }
            }
            KObject::Semaphore { count, .. } => {
                if *count > 0 {
                    *count -= 1;
                    true
                } else {
                    false
                }
            }
            KObject::Mutex { owner, recursion } => match owner {
                None => {
                    *owner = Some(tid);
                    *recursion = 1;
                    true
                }
                Some(o) if *o == tid => {
                    *recursion += 1;
                    true
                }
                Some(_) => false,
            },
            KObject::Thread { exited } | KObject::Process { exited } => *exited,
        }
    }
}

impl WinOs {
    fn handle_stride(&self) -> u64 {
        if self.cfg.is_64bit {
            8
        } else {
            4
        }
    }

    pub(crate) fn make_object(&mut self, kind: SyncKind, name: Option<String>, manual: bool, signaled: bool, count: i32, max: i32) -> u64 {
        if let Some(n) = &name {
            if let Some(&h) = self.named_kobjects.get(n) {
                self.set_last_error(183);
                return h;
            }
        }
        let obj = match kind {
            SyncKind::Event => KObject::Event { manual_reset: manual, signaled },
            SyncKind::Timer => KObject::Timer { manual_reset: manual, signaled },
            SyncKind::Mutex => KObject::Mutex {
                owner: if signaled { Some(self.current_tid) } else { None },
                recursion: if signaled { 1 } else { 0 },
            },
            SyncKind::Semaphore => KObject::Semaphore { count, max },
        };
        let h = self.alloc_khandle();
        self.kobjects.insert(h, obj);
        if let Some(n) = name {
            self.named_kobjects.insert(n, h);
        }
        h
    }

    fn read_name(&self, mem: &dyn Memory, ptr: u64, wide: bool) -> Result<Option<String>> {
        if ptr == 0 {
            return Ok(None);
        }
        let s = if wide {
            crate::api::read_wstr(mem, ptr)?
        } else {
            String::from_utf8_lossy(&mem.read_cstr(ptr, 512)?).into_owned()
        };
        Ok(if s.is_empty() { None } else { Some(s) })
    }

    pub(crate) fn create_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, kind: SyncKind, ex: bool, wide: bool) -> Result<Outcome> {
        self.set_last_error(0);
        let h = match (kind, ex) {
            (SyncKind::Event, false) => {
                let manual = self.arg(cpu, mem, 1)? != 0;
                let initial = self.arg(cpu, mem, 2)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, manual, initial, 0, 0)
            }
            (SyncKind::Event, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, flags & 1 != 0, flags & 2 != 0, 0, 0)
            }
            (SyncKind::Mutex, false) => {
                let owned = self.arg(cpu, mem, 1)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
                self.make_object(kind, name, false, owned, 0, 0)
            }
            (SyncKind::Mutex, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, false, flags & 1 != 0, 0, 0)
            }
            (SyncKind::Semaphore, false) => {
                let init = self.arg(cpu, mem, 1)? as i32;
                let max = self.arg(cpu, mem, 2)? as i32;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, false, false, init, max)
            }
            (SyncKind::Semaphore, true) => {
                let init = self.arg(cpu, mem, 1)? as i32;
                let max = self.arg(cpu, mem, 2)? as i32;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, false, false, init, max)
            }
            (SyncKind::Timer, false) => {
                let manual = self.arg(cpu, mem, 1)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
                self.make_object(kind, name, manual, false, 0, 0)
            }
            (SyncKind::Timer, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, flags & 2 != 0, false, 0, 0)
            }
        };
        Ok(Outcome::Return(h))
    }

    pub(crate) fn open_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
        match name.and_then(|n| self.named_kobjects.get(&n).copied()) {
            Some(h) => Ok(Outcome::Return(h)),
            None => {
                self.set_last_error(2);
                Ok(Outcome::Return(0))
            }
        }
    }

    pub(crate) fn signal_event_handle(&mut self, handle: u64) -> bool {
        match self.kobjects.get_mut(&handle) {
            Some(KObject::Event { signaled, .. } | KObject::Timer { signaled, .. }) => {
                *signaled = true;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn signal_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, op: SignalOp) -> Result<Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        let (rel_count, prev_ptr) = if matches!(op, SignalOp::ReleaseSemaphore) {
            (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)?)
        } else {
            (0, 0)
        };
        let tid = self.current_tid;
        let Some(obj) = self.kobjects.get_mut(&handle) else {
            return Ok(Outcome::Return(1));
        };
        let mut prev = 0i32;
        let ok = match (op, obj) {
            (SignalOp::SetEvent, KObject::Event { signaled, .. } | KObject::Timer { signaled, .. }) => {
                *signaled = true;
                true
            }
            (SignalOp::ResetEvent, KObject::Event { signaled, .. } | KObject::Timer { signaled, .. }) => {
                *signaled = false;
                true
            }
            (SignalOp::PulseEvent, KObject::Event { signaled, .. } | KObject::Timer { signaled, .. }) => {
                *signaled = false;
                true
            }
            (SignalOp::ReleaseMutex, KObject::Mutex { owner, recursion }) => {
                if *owner == Some(tid) {
                    *recursion = recursion.saturating_sub(1);
                    if *recursion == 0 {
                        *owner = None;
                    }
                    true
                } else {
                    false
                }
            }
            (SignalOp::ReleaseSemaphore, KObject::Semaphore { count, max }) => {
                prev = *count;
                let bump = *count + rel_count;
                if *max > 0 && bump > *max {
                    false
                } else {
                    *count = bump;
                    true
                }
            }
            _ => false,
        };
        if matches!(op, SignalOp::ReleaseSemaphore) && prev_ptr != 0 {
            mem.write_u32(prev_ptr, prev as u32)?;
        }
        Ok(Outcome::Return(ok as u64))
    }

    pub(crate) fn wait_single(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        let timeout = self.arg(cpu, mem, 1)? as u32;
        let tid = self.current_tid;
        let acquired = self.kobjects.get_mut(&handle).map_or(true, |o| o.acquire(tid));
        if acquired {
            return Ok(Outcome::Return(WAIT_OBJECT_0));
        }
        if timeout == 0 {
            return Ok(Outcome::Return(WAIT_TIMEOUT));
        }
        if self.block_and_switch(cpu, WaitDesc { handles: vec![handle], all: true }) {
            Ok(Outcome::Resume)
        } else {
            Ok(Outcome::Return(WAIT_OBJECT_0))
        }
    }

    pub(crate) fn wait_multiple(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let count = self.arg(cpu, mem, 0)? as u32;
        let arr = self.arg(cpu, mem, 1)?;
        let wait_all = self.arg(cpu, mem, 2)? != 0;
        let timeout = self.arg(cpu, mem, 3)? as u32;
        let tid = self.current_tid;
        let stride = self.handle_stride();

        let mut handles = Vec::with_capacity(count as usize);
        for i in 0..count as u64 {
            handles.push(self.read_ptr(mem, arr + i * stride)?);
        }

        let signaled = |h: &u64| self.kobjects.get(h).map_or(true, |o| o.is_signaled(tid));
        let satisfiable = if wait_all {
            handles.iter().all(signaled)
        } else {
            handles.iter().any(signaled)
        };
        if satisfiable {
            if wait_all {
                for h in &handles {
                    if let Some(o) = self.kobjects.get_mut(h) {
                        o.acquire(tid);
                    }
                }
                return Ok(Outcome::Return(WAIT_OBJECT_0));
            }
            for (i, h) in handles.iter().enumerate() {
                let acquired = self.kobjects.get_mut(h).map_or(true, |o| o.acquire(tid));
                if acquired {
                    return Ok(Outcome::Return(WAIT_OBJECT_0 + i as u64));
                }
            }
        }
        if timeout == 0 {
            return Ok(Outcome::Return(WAIT_TIMEOUT));
        }
        if self.block_and_switch(cpu, WaitDesc { handles, all: wait_all }) {
            Ok(Outcome::Resume)
        } else {
            Ok(Outcome::Return(WAIT_OBJECT_0))
        }
    }

    fn nt_object_attr_name(&self, mem: &dyn Memory, objattr: u64) -> Result<Option<String>> {
        if objattr == 0 {
            return Ok(None);
        }
        let name_ptr = mem.read_u64_at(objattr, 0x10)?;
        let Some(raw) = crate::fs::read_unicode_string(mem, name_ptr) else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Ok(None);
        }
        let stripped = crate::fs::strip_nt_prefix(&raw);
        let name = stripped.strip_prefix("\\BaseNamedObjects\\").unwrap_or(&stripped).to_string();
        Ok(if name.is_empty() { None } else { Some(name) })
    }

    pub(crate) fn nt_create_event(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let event_type = self.syscall_arg(cpu, mem, 3)? as u32;
        let initial = self.syscall_arg(cpu, mem, 4)? != 0;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let manual = event_type == NOTIFICATION_EVENT;
        let name = self.nt_object_attr_name(mem, objattr)?;
        let handle = self.make_object(SyncKind::Event, name, manual, initial, 0, 0);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_open_event(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(name) = self.nt_object_attr_name(mem, objattr)? else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        match self.named_kobjects.get(&name).copied() {
            Some(handle) => {
                self.write_ptr(mem, handle_out, handle)?;
                Ok(NT_STATUS_SUCCESS)
            }
            None => Ok(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    pub(crate) fn nt_set_event(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let prev_ptr = self.syscall_arg(cpu, mem, 1)?;
        let Some(obj) = self.kobjects.get_mut(&handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let prev = match obj {
            KObject::Event { signaled, .. } | KObject::Timer { signaled, .. } => {
                let was = *signaled;
                *signaled = true;
                was
            }
            _ => return Ok(STATUS_OBJECT_TYPE_MISMATCH),
        };
        if prev_ptr != 0 {
            mem.write_u32(prev_ptr, prev as u32)?;
        }
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_create_mutant(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let initial_owner = self.syscall_arg(cpu, mem, 3)? != 0;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let name = self.nt_object_attr_name(mem, objattr)?;
        let handle = self.make_object(SyncKind::Mutex, name, false, initial_owner, 0, 0);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_create_semaphore(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let initial = self.syscall_arg(cpu, mem, 3)? as i32;
        let max = self.syscall_arg(cpu, mem, 4)? as i32;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if max < 1 || initial < 0 || initial > max {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let name = self.nt_object_attr_name(mem, objattr)?;
        let handle = self.make_object(SyncKind::Semaphore, name, false, false, initial, max);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_release_semaphore(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let release = self.syscall_arg(cpu, mem, 1)? as i32;
        let prev_ptr = self.syscall_arg(cpu, mem, 2)?;
        let Some(obj) = self.kobjects.get_mut(&handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let KObject::Semaphore { count, max } = obj else {
            return Ok(STATUS_OBJECT_TYPE_MISMATCH);
        };
        if release < 1 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let prev = *count;
        let bump = count.checked_add(release);
        match bump {
            Some(b) if *max <= 0 || b <= *max => *count = b,
            _ => return Ok(STATUS_SEMAPHORE_LIMIT_EXCEEDED),
        }
        if prev_ptr != 0 {
            mem.write_u32(prev_ptr, prev as u32)?;
        }
        Ok(NT_STATUS_SUCCESS)
    }

    pub(crate) fn nt_wait_for_single_object(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let _alertable = self.syscall_arg(cpu, mem, 1)?;
        let timeout_ptr = self.syscall_arg(cpu, mem, 2)?;
        if !self.kobjects.contains_key(&handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let timeout = self.read_nt_timeout(mem, timeout_ptr)?;
        self.nt_wait(cpu, vec![handle], false, timeout)
    }

    pub(crate) fn nt_wait_for_multiple_objects(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let count = self.syscall_arg(cpu, mem, 0)? as u32;
        let handles_ptr = self.syscall_arg(cpu, mem, 1)?;
        let wait_type = self.syscall_arg(cpu, mem, 2)? as u32;
        let _alertable = self.syscall_arg(cpu, mem, 3)?;
        let timeout_ptr = self.syscall_arg(cpu, mem, 4)?;
        if count == 0 || count as u64 > MAXIMUM_WAIT_OBJECTS {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let all = match wait_type {
            WAIT_TYPE_ALL => true,
            WAIT_TYPE_ANY => false,
            _ => return Ok(STATUS_INVALID_PARAMETER),
        };
        let stride = self.handle_stride();
        let mut handles = Vec::with_capacity(count as usize);
        for i in 0..count as u64 {
            let h = self.read_ptr(mem, handles_ptr + i * stride)?;
            if !self.kobjects.contains_key(&h) {
                return Ok(STATUS_INVALID_HANDLE);
            }
            handles.push(h);
        }
        let timeout = self.read_nt_timeout(mem, timeout_ptr)?;
        self.nt_wait(cpu, handles, all, timeout)
    }

    fn read_nt_timeout(&self, mem: &dyn Memory, ptr: u64) -> Result<NtTimeout> {
        if ptr == 0 {
            return Ok(NtTimeout::Infinite);
        }
        Ok(if mem.read_u64(ptr)? == 0 { NtTimeout::Poll } else { NtTimeout::Finite })
    }

    fn nt_wait(&mut self, cpu: &mut CpuState, handles: Vec<u64>, all: bool, timeout: NtTimeout) -> Result<u32> {
        let tid = self.current_tid;
        if self.nt_wait_satisfiable(&handles, all, tid) {
            return Ok(self.nt_wait_acquire(&handles, all, tid));
        }
        if timeout == NtTimeout::Poll {
            return Ok(STATUS_TIMEOUT);
        }
        self.rewind_syscall(cpu);
        let infinite = timeout == NtTimeout::Infinite;
        let deadlock = format!(
            "guest deadlock: NtWaitFor{} on {handles:#x?} (wait_all={all}) with an infinite timeout, \
             but no other thread can run to signal it",
            if handles.len() == 1 { "SingleObject" } else { "MultipleObjects" },
        );
        if self.block_and_switch(cpu, WaitDesc { handles, all }) {
            self.syscall_resume_as_is = true;
            Ok(STATUS_WAIT_0)
        } else if infinite {
            Err(EmuError::Os(deadlock))
        } else {
            Ok(STATUS_TIMEOUT)
        }
    }

    fn nt_wait_satisfiable(&self, handles: &[u64], all: bool, tid: u32) -> bool {
        let sig = |h: &u64| self.kobject_is_signaled(*h, tid);
        if all {
            handles.iter().all(sig)
        } else {
            handles.iter().any(sig)
        }
    }

    fn nt_wait_acquire(&mut self, handles: &[u64], all: bool, tid: u32) -> u32 {
        if all {
            for h in handles {
                self.kobject_acquire(*h, tid);
            }
            STATUS_WAIT_0
        } else {
            for (i, h) in handles.iter().enumerate() {
                if self.kobject_acquire(*h, tid) {
                    return STATUS_WAIT_0 + i as u32;
                }
            }
            STATUS_WAIT_0
        }
    }

    pub(crate) fn rewind_syscall(&self, cpu: &mut CpuState) {
        let ret_rip = cpu.reg(Reg::Rcx);
        cpu.rip = ret_rip.wrapping_sub(SYSCALL_INSN_LEN);
        cpu.rflags = cpu.reg(Reg::R11);
        cpu.set_rsp(self.syscall_guest_rsp);
    }

    pub(crate) fn kobject_is_signaled(&self, handle: u64, tid: u32) -> bool {
        self.kobjects.get(&handle).map_or(true, |o| o.is_signaled(tid))
    }

    pub(crate) fn kobject_acquire(&mut self, handle: u64, tid: u32) -> bool {
        self.kobjects.get_mut(&handle).map_or(true, |o| o.acquire(tid))
    }

    pub(crate) fn dup_kobject_handle(&mut self, src: u64) -> Option<u64> {
        let dup = match self.kobjects.get(&src)? {
            KObject::Event { manual_reset, signaled } => KObject::Event { manual_reset: *manual_reset, signaled: *signaled },
            KObject::Timer { manual_reset, signaled } => KObject::Timer { manual_reset: *manual_reset, signaled: *signaled },
            KObject::Mutex { owner, recursion } => KObject::Mutex { owner: *owner, recursion: *recursion },
            KObject::Semaphore { count, max } => KObject::Semaphore { count: *count, max: *max },
            KObject::Thread { exited } => KObject::Thread { exited: *exited },
            KObject::Process { exited } => KObject::Process { exited: *exited },
        };
        let h = self.alloc_khandle();
        self.kobjects.insert(h, dup);
        Some(h)
    }

    #[cfg(test)]
    pub(crate) fn kobject_is_signaled_for_test(&self, handle: u64) -> bool {
        self.kobject_is_signaled(handle, self.current_tid)
    }

    #[cfg(test)]
    pub(crate) fn unix_call_blocked_for_test(&self) -> bool {
        self.unix_call_blocked
    }
}

const NT_STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_WAIT_0: u32 = 0x0000_0000;
const STATUS_TIMEOUT: u32 = 0x0000_0102;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;

const NOTIFICATION_EVENT: u32 = 0;

const WAIT_TYPE_ALL: u32 = 0;
const WAIT_TYPE_ANY: u32 = 1;

const MAXIMUM_WAIT_OBJECTS: u64 = 64;

const SYSCALL_INSN_LEN: u64 = 2;

pub(crate) const SSDT_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x04;
pub(crate) const SSDT_NT_RELEASE_SEMAPHORE: u32 = 0x0a;
pub(crate) const SSDT_NT_SET_EVENT: u32 = 0x0e;
pub(crate) const SSDT_NT_OPEN_EVENT: u32 = 0x40;
pub(crate) const SSDT_NT_CREATE_EVENT: u32 = 0x48;
pub(crate) const SSDT_NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x5b;
pub(crate) const SSDT_NT_CREATE_MUTANT: u32 = 0x7e;
pub(crate) const SSDT_NT_CREATE_SEMAPHORE: u32 = 0x83;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NtTimeout {
    Infinite,
    Poll,
    Finite,
}

pub(crate) fn ssdt_nt_create_event(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_event(cpu, mem)
}
pub(crate) fn ssdt_nt_open_event(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_event(cpu, mem)
}
pub(crate) fn ssdt_nt_set_event(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_set_event(cpu, mem)
}
pub(crate) fn ssdt_nt_create_mutant(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_mutant(cpu, mem)
}
pub(crate) fn ssdt_nt_create_semaphore(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_semaphore(cpu, mem)
}
pub(crate) fn ssdt_nt_release_semaphore(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_release_semaphore(cpu, mem)
}
pub(crate) fn ssdt_nt_wait_for_single_object(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_wait_for_single_object(cpu, mem)
}
pub(crate) fn ssdt_nt_wait_for_multiple_objects(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_wait_for_multiple_objects(cpu, mem)
}
