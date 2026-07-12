//! Kernel synchronization objects with real signaling state (roadmap P3.6).
//!
//! Events, mutexes, semaphores and waitable timers are modelled as real
//! objects in a handle table, so `SetEvent`/`ReleaseSemaphore`/`ReleaseMutex`
//! change observable state and `WaitForSingleObject`/`WaitForMultipleObjects`
//! consult and *consume* it (auto-reset events reset, semaphore counts
//! decrement, mutexes take ownership).
//!
//! Until the cooperative scheduler lands (P3.4) there is only one runnable
//! thread, so a wait on an *unsignaled* object cannot truly block: it reports
//! `WAIT_TIMEOUT` for a zero timeout and otherwise falls back to
//! `WAIT_OBJECT_0` to avoid a hang. P3.4 replaces that fallback with a real
//! yield to another ready thread.

use exemu_core::{CpuState, Memory, Result};

use crate::api::Outcome;
use crate::thread::WaitDesc;
use crate::WinOs;

// Wait return codes.
const WAIT_OBJECT_0: u64 = 0x0000_0000;
const WAIT_TIMEOUT: u64 = 0x0000_0102;

/// Which flavour of object a `Create*`/`Open*` refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Event,
    Mutex,
    Semaphore,
    Timer,
}

/// A state-changing signal operation.
#[derive(Debug, Clone, Copy)]
pub enum SignalOp {
    SetEvent,
    ResetEvent,
    PulseEvent,
    ReleaseMutex,
    ReleaseSemaphore,
}

/// A live kernel synchronization object.
pub(crate) enum KObject {
    Event { manual_reset: bool, signaled: bool },
    Mutex { owner: Option<u32>, recursion: u32 },
    Semaphore { count: i32, max: i32 },
    Timer { manual_reset: bool, signaled: bool },
    /// A thread handle (roadmap P3.4): signaled once the thread has exited, and
    /// stays signaled (manual, like a terminated-process object).
    Thread { exited: bool },
}

impl KObject {
    /// Whether a wait would be satisfied right now (without consuming), for the
    /// thread `tid` (mutexes are signaled to their current owner).
    pub(crate) fn is_signaled(&self, tid: u32) -> bool {
        match self {
            KObject::Event { signaled, .. } | KObject::Timer { signaled, .. } => *signaled,
            KObject::Semaphore { count, .. } => *count > 0,
            KObject::Mutex { owner, .. } => owner.is_none() || *owner == Some(tid),
            KObject::Thread { exited } => *exited,
        }
    }

    /// Satisfy a wait, consuming state: auto-reset events reset, semaphore
    /// counts decrement, a mutex takes/recurses ownership. Returns whether the
    /// object was signaled (and thus consumed).
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
            // A thread object is a latch: waiting on an exited thread always
            // succeeds and never consumes.
            KObject::Thread { exited } => *exited,
        }
    }
}

impl WinOs {
    /// The pointer stride of a `HANDLE` array element (32- vs 64-bit).
    fn handle_stride(&self) -> u64 {
        if self.cfg.is_64bit {
            8
        } else {
            4
        }
    }

    /// Create (or, for a named object that already exists, re-open) a
    /// synchronization object and return its handle. `initial` seeds the
    /// initial signaled/owned/count state per kind.
    pub(crate) fn make_object(&mut self, kind: SyncKind, name: Option<String>, manual: bool, signaled: bool, count: i32, max: i32) -> u64 {
        if let Some(n) = &name {
            if let Some(&h) = self.named_kobjects.get(n) {
                self.set_last_error(183); // ERROR_ALREADY_EXISTS (handle still valid)
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

    /// Read an object name argument (LPCSTR/LPCWSTR), returning `None` for a
    /// null pointer (an anonymous object).
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

    /// CreateEvent/CreateMutex/CreateSemaphore/CreateWaitableTimer (+ *Ex).
    pub(crate) fn create_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, kind: SyncKind, ex: bool, wide: bool) -> Result<Outcome> {
        self.set_last_error(0);
        let h = match (kind, ex) {
            // CreateEvent(attr, bManualReset, bInitialState, name)
            (SyncKind::Event, false) => {
                let manual = self.arg(cpu, mem, 1)? != 0;
                let initial = self.arg(cpu, mem, 2)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, manual, initial, 0, 0)
            }
            // CreateEventEx(attr, name, flags, access): flags bit0 MANUAL_RESET, bit1 INITIAL_SET
            (SyncKind::Event, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, flags & 1 != 0, flags & 2 != 0, 0, 0)
            }
            // CreateMutex(attr, bInitialOwner, name)
            (SyncKind::Mutex, false) => {
                let owned = self.arg(cpu, mem, 1)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
                self.make_object(kind, name, false, owned, 0, 0)
            }
            // CreateMutexEx(attr, name, flags, access): flags bit0 INITIAL_OWNER
            (SyncKind::Mutex, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, false, flags & 1 != 0, 0, 0)
            }
            // CreateSemaphore(attr, lInitialCount, lMaximumCount, name)
            (SyncKind::Semaphore, false) => {
                let init = self.arg(cpu, mem, 1)? as i32;
                let max = self.arg(cpu, mem, 2)? as i32;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, false, false, init, max)
            }
            // CreateSemaphoreEx(attr, init, max, name, flags, access)
            (SyncKind::Semaphore, true) => {
                let init = self.arg(cpu, mem, 1)? as i32;
                let max = self.arg(cpu, mem, 2)? as i32;
                let name = self.read_name(mem, self.arg(cpu, mem, 3)?, wide)?;
                self.make_object(kind, name, false, false, init, max)
            }
            // CreateWaitableTimer(attr, bManualReset, name)
            (SyncKind::Timer, false) => {
                let manual = self.arg(cpu, mem, 1)? != 0;
                let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
                self.make_object(kind, name, manual, false, 0, 0)
            }
            // CreateWaitableTimerEx(attr, name, flags, access): flags bit1 MANUAL_RESET
            (SyncKind::Timer, true) => {
                let name = self.read_name(mem, self.arg(cpu, mem, 1)?, wide)?;
                let flags = self.arg(cpu, mem, 2)?;
                self.make_object(kind, name, flags & 2 != 0, false, 0, 0)
            }
        };
        Ok(Outcome::Return(h))
    }

    /// OpenEvent/OpenMutex/OpenSemaphore/OpenWaitableTimer(access, inherit, name).
    pub(crate) fn open_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let name = self.read_name(mem, self.arg(cpu, mem, 2)?, wide)?;
        match name.and_then(|n| self.named_kobjects.get(&n).copied()) {
            Some(h) => Ok(Outcome::Return(h)),
            None => {
                self.set_last_error(2); // ERROR_FILE_NOT_FOUND
                Ok(Outcome::Return(0))
            }
        }
    }

    /// SetEvent/ResetEvent/PulseEvent/ReleaseMutex/ReleaseSemaphore.
    pub(crate) fn signal_sync(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, op: SignalOp) -> Result<Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        // ReleaseSemaphore(handle, lReleaseCount, lpPreviousCount).
        let (rel_count, prev_ptr) = if matches!(op, SignalOp::ReleaseSemaphore) {
            (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)?)
        } else {
            (0, 0)
        };
        let tid = self.current_tid;
        let Some(obj) = self.kobjects.get_mut(&handle) else {
            return Ok(Outcome::Return(1)); // unknown handle: report success, no-op
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
            // Pulse briefly signals; with cooperative scheduling any waiter is
            // released elsewhere, so the visible end state is unsignaled.
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
                    false // ERROR_NOT_OWNER
                }
            }
            (SignalOp::ReleaseSemaphore, KObject::Semaphore { count, max }) => {
                prev = *count;
                let bump = *count + rel_count;
                if *max > 0 && bump > *max {
                    false // would exceed the maximum
                } else {
                    *count = bump;
                    true
                }
            }
            _ => false, // op applied to the wrong object kind
        };
        if matches!(op, SignalOp::ReleaseSemaphore) && prev_ptr != 0 {
            mem.write_u32(prev_ptr, prev as u32)?;
        }
        Ok(Outcome::Return(ok as u64))
    }

    /// WaitForSingleObject(handle, ms) / WaitForSingleObjectEx(handle, ms, alertable).
    pub(crate) fn wait_single(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        let timeout = self.arg(cpu, mem, 1)? as u32;
        let tid = self.current_tid;
        // Acquire immediately if signaled (unknown handles count as signaled).
        let acquired = self.kobjects.get_mut(&handle).map_or(true, |o| o.acquire(tid));
        if acquired {
            return Ok(Outcome::Return(WAIT_OBJECT_0));
        }
        if timeout == 0 {
            return Ok(Outcome::Return(WAIT_TIMEOUT));
        }
        // Block: switch to another runnable thread. When we are scheduled again
        // (once the object is signaled) intercept re-runs this wait and it
        // acquires. If nobody else can run, fall back to WAIT_OBJECT_0 so a
        // single-threaded program does not hang.
        if self.block_and_switch(cpu, WaitDesc { handles: vec![handle], all: true }) {
            Ok(Outcome::Resume)
        } else {
            Ok(Outcome::Return(WAIT_OBJECT_0))
        }
    }

    /// WaitForMultipleObjects(count, handles, waitAll, ms) (+ Ex alertable arg).
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

        // Peek satisfiability *before* consuming, so a partial set is not
        // drained when we are going to block instead.
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

    // ---- object-manager helpers (roadmap W2.11) --------------------------
    //
    // The wineserver equivalent ([`crate::server`]) drives the *same* KObject
    // model these Win32 waits use, so these thin helpers expose signaled/acquire
    // and duplicate/close by handle to it (a duplicate is a second handle onto
    // one object in the single-process in-process model).

    /// Whether the object at `handle` is signaled for `tid` right now (unknown
    /// handle counts as signaled, matching the wait paths). Backs the server's
    /// `select` satisfiability peek.
    pub(crate) fn kobject_is_signaled(&self, handle: u64, tid: u32) -> bool {
        self.kobjects.get(&handle).map_or(true, |o| o.is_signaled(tid))
    }

    /// Satisfy a wait on `handle`, consuming state (auto-reset events reset,
    /// semaphores decrement). Returns whether it was signaled/acquired (unknown
    /// handle counts as acquired).
    pub(crate) fn kobject_acquire(&mut self, handle: u64, tid: u32) -> bool {
        self.kobjects.get_mut(&handle).map_or(true, |o| o.acquire(tid))
    }

    /// Duplicate `src` into a second handle onto the *same* object (the server
    /// `dup_handle`). Returns the new handle, or `None` if `src` is not a live
    /// kernel object. The object stays live until every naming handle is closed.
    pub(crate) fn dup_kobject_handle(&mut self, src: u64) -> Option<u64> {
        let dup = match self.kobjects.get(&src)? {
            KObject::Event { manual_reset, signaled } => KObject::Event { manual_reset: *manual_reset, signaled: *signaled },
            KObject::Timer { manual_reset, signaled } => KObject::Timer { manual_reset: *manual_reset, signaled: *signaled },
            KObject::Mutex { owner, recursion } => KObject::Mutex { owner: *owner, recursion: *recursion },
            KObject::Semaphore { count, max } => KObject::Semaphore { count: *count, max: *max },
            KObject::Thread { exited } => KObject::Thread { exited: *exited },
        };
        let h = self.alloc_khandle();
        self.kobjects.insert(h, dup);
        Some(h)
    }

    /// Test-only: whether `handle` names a signaled kernel object (from the
    /// current thread's perspective).
    #[cfg(test)]
    pub(crate) fn kobject_is_signaled_for_test(&self, handle: u64) -> bool {
        self.kobject_is_signaled(handle, self.current_tid)
    }

    /// Test-only: whether the last `wine_server_call` blocked (drove a
    /// scheduler switch) rather than completing.
    #[cfg(test)]
    pub(crate) fn unix_call_blocked_for_test(&self) -> bool {
        self.unix_call_blocked
    }
}
