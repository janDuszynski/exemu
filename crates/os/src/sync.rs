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

use exemu_core::{CpuState, EmuError, Memory, Reg, Result};

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

    // ---- NT sync syscalls (roadmap W2.12) --------------------------------
    //
    // The NTSTATUS face of the P3.6 sync objects + the P3.4 scheduler, reached
    // via a raw guest `SYSCALL` through the W2.3 dispatcher. Args come via
    // [`WinOs::syscall_arg`] (arg0=R10, arg1=RDX, arg2=R8, arg3=R9, then the
    // guest stack). Signatures are the public NT headers (winternl.h / ntifs.h /
    // phnt-style `NtCreateEvent`/`NtWaitForMultipleObjects`); no Wine `.c` read.
    //
    // These reuse the *same* `kobjects`/`named_kobjects` maps the Win32 seam and
    // the W2.11 server use, so an event created here is the same object a Win32
    // `SetEvent` or a server `select` sees. Unlike the Win32 waits, the NT waits
    // block for REAL (design §5.4): there is **no** speculative `WAIT_OBJECT_0`
    // fallback — an unsatisfiable infinite wait with nobody else runnable is a
    // genuine guest deadlock, surfaced as a fault rather than fabricated success.

    /// Read an `OBJECT_ATTRIBUTES.ObjectName` as a named-object key, or `None`
    /// for an anonymous object (NULL attributes/name or an empty name). Reuses
    /// the fs.rs UNICODE_STRING reader and strips the NT namespace prefixes
    /// (`\??\` etc.) plus a leading `\BaseNamedObjects\`, so an NT-created named
    /// object and a Win32 `CreateEventW(lpName)` object meet in one namespace.
    /// 64-bit `OBJECT_ATTRIBUTES` layout (the W2 pivot pins 64-bit ntdll):
    /// `{ ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; … }`
    /// — `ObjectName` at offset 0x10.
    fn nt_object_attr_name(&self, mem: &dyn Memory, objattr: u64) -> Result<Option<String>> {
        if objattr == 0 {
            return Ok(None);
        }
        let name_ptr = mem.read_u64(objattr + 0x10)?;
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

    /// `NtCreateEvent(*EventHandle, DesiredAccess, *ObjectAttributes, EventType,
    /// BOOLEAN InitialState)`. arg0=&EventHandle (OUT), arg2=&ObjectAttributes
    /// (optional name), arg3=EventType (`NotificationEvent`=0 → manual-reset,
    /// `SynchronizationEvent`=1 → auto-reset), arg4=InitialState.
    pub(crate) fn nt_create_event(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let event_type = self.syscall_arg(cpu, mem, 3)? as u32;
        let initial = self.syscall_arg(cpu, mem, 4)? != 0;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let manual = event_type == NOTIFICATION_EVENT; // 0 = manual, 1 = auto
        let name = self.nt_object_attr_name(mem, objattr)?;
        let handle = self.make_object(SyncKind::Event, name, manual, initial, 0, 0);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_STATUS_SUCCESS)
    }

    /// `NtOpenEvent(*EventHandle, DesiredAccess, *ObjectAttributes)`. Resolves the
    /// `ObjectAttributes.ObjectName` in the named-object namespace; a name that
    /// names no live object → `STATUS_OBJECT_NAME_NOT_FOUND`.
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

    /// `NtSetEvent(EventHandle, *PreviousState)`. Signals the event; writes the
    /// prior signaled state (0/1) through `PreviousState` when nonzero. Unknown
    /// handle → `STATUS_INVALID_HANDLE`; wrong object kind →
    /// `STATUS_OBJECT_TYPE_MISMATCH`.
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

    /// `NtCreateMutant(*MutantHandle, DesiredAccess, *ObjectAttributes, BOOLEAN
    /// InitialOwner)`. arg0=&MutantHandle (OUT), arg2=&ObjectAttributes,
    /// arg3=InitialOwner (the creating thread takes ownership when true).
    pub(crate) fn nt_create_mutant(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let initial_owner = self.syscall_arg(cpu, mem, 3)? != 0;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let name = self.nt_object_attr_name(mem, objattr)?;
        // `make_object`'s `signaled` seeds mutex ownership: owned → owner =
        // current thread, recursion = 1.
        let handle = self.make_object(SyncKind::Mutex, name, false, initial_owner, 0, 0);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_STATUS_SUCCESS)
    }

    /// `NtCreateSemaphore(*SemaphoreHandle, DesiredAccess, *ObjectAttributes,
    /// LONG InitialCount, LONG MaximumCount)`. arg3=InitialCount, arg4=Maximum
    /// Count. Rejects `MaximumCount < 1` or `InitialCount` outside `0..=Maximum`
    /// with `STATUS_INVALID_PARAMETER`.
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

    /// `NtReleaseSemaphore(SemaphoreHandle, LONG ReleaseCount, *PreviousCount)`.
    /// Raises the count by `ReleaseCount`; a release that would push the count
    /// past its maximum → `STATUS_SEMAPHORE_LIMIT_EXCEEDED` with the count left
    /// unchanged. Writes the prior count through `PreviousCount` when nonzero
    /// (only on success). Unknown handle → `STATUS_INVALID_HANDLE`; wrong kind →
    /// `STATUS_OBJECT_TYPE_MISMATCH`.
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

    /// `NtWaitForSingleObject(Handle, BOOLEAN Alertable, *Timeout)`. `Alertable`
    /// is read and ignored (design §7: no APCs). `Timeout` is a `PLARGE_INTEGER`:
    /// NULL = infinite, `*Timeout == 0` = poll, any other value = a finite wait
    /// (blocks — no timed wakeups yet). Unknown handle → `STATUS_INVALID_HANDLE`.
    /// Success → `STATUS_WAIT_0` (0).
    pub(crate) fn nt_wait_for_single_object(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let _alertable = self.syscall_arg(cpu, mem, 1)?; // read & ignored (design §7)
        let timeout_ptr = self.syscall_arg(cpu, mem, 2)?;
        if !self.kobjects.contains_key(&handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let timeout = self.read_nt_timeout(mem, timeout_ptr)?;
        self.nt_wait(cpu, vec![handle], false, timeout)
    }

    /// `NtWaitForMultipleObjects(ULONG Count, *Handles, WAIT_TYPE, BOOLEAN
    /// Alertable, *Timeout)`. `Handles` is a `Count`-long array of pointer-sized
    /// `HANDLE`s. `WAIT_TYPE` (public winnt.h `_WAIT_TYPE`): `WaitAll`=0 →
    /// wait-all, `WaitAny`=1 → wait-any (matches kernel32's
    /// `WaitForMultipleObjects(bWaitAll ? WaitAll : WaitAny)`). `Count` of 0 or
    /// `> MAXIMUM_WAIT_OBJECTS` → `STATUS_INVALID_PARAMETER`; any handle naming no
    /// live object → `STATUS_INVALID_HANDLE`. Wait-any success →
    /// `STATUS_WAIT_0 + index` of the satisfied handle.
    pub(crate) fn nt_wait_for_multiple_objects(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let count = self.syscall_arg(cpu, mem, 0)? as u32;
        let handles_ptr = self.syscall_arg(cpu, mem, 1)?;
        let wait_type = self.syscall_arg(cpu, mem, 2)? as u32;
        let _alertable = self.syscall_arg(cpu, mem, 3)?; // read & ignored
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

    /// Read a `PLARGE_INTEGER` NT wait timeout: NULL = infinite; `*p == 0` = poll
    /// (return immediately, never block); any other value = a finite timeout.
    /// There are no timed wakeups yet (design §7 / W2.11 `select`), so a finite
    /// wait blocks like an infinite one — the disposition only decides the
    /// no-runnable fallback (a finite wait times out; an infinite one deadlocks).
    fn read_nt_timeout(&self, mem: &dyn Memory, ptr: u64) -> Result<NtTimeout> {
        if ptr == 0 {
            return Ok(NtTimeout::Infinite);
        }
        Ok(if mem.read_u64(ptr)? == 0 { NtTimeout::Poll } else { NtTimeout::Finite })
    }

    /// The shared NT wait core. Peeks the handle set (no consumption); on success
    /// acquires it and returns `STATUS_WAIT_0` (+ the satisfied index for
    /// wait-any). Otherwise a poll returns `STATUS_TIMEOUT`, and a blocking wait
    /// rewinds the `SYSCALL` and switches to another runnable thread for REAL
    /// blocking (design §5). With nobody else runnable there is no timed wakeup
    /// to rescue it: a finite wait honestly times out; an infinite wait is a
    /// genuine deadlock, surfaced as a fault (design §5.4 — never fabricate
    /// success on the NT path).
    fn nt_wait(&mut self, cpu: &mut CpuState, handles: Vec<u64>, all: bool, timeout: NtTimeout) -> Result<u32> {
        let tid = self.current_tid;
        if self.nt_wait_satisfiable(&handles, all, tid) {
            return Ok(self.nt_wait_acquire(&handles, all, tid));
        }
        if timeout == NtTimeout::Poll {
            return Ok(STATUS_TIMEOUT);
        }
        // REAL blocking. Rewind so the whole SYSCALL re-executes when we are
        // rescheduled (the wait re-runs and now acquires). On the no-switch
        // fallback below this rewind is invisible: the dispatcher's phase-4
        // restore overwrites rip/rsp/rflags from the frame saved at syscall entry.
        self.rewind_syscall(cpu);
        let infinite = timeout == NtTimeout::Infinite;
        let deadlock = format!(
            "guest deadlock: NtWaitFor{} on {handles:#x?} (wait_all={all}) with an infinite timeout, \
             but no other thread can run to signal it",
            if handles.len() == 1 { "SingleObject" } else { "MultipleObjects" },
        );
        if self.block_and_switch(cpu, WaitDesc { handles, all }) {
            // Phase 4 must not restore the abandoned frame over the switched-in
            // thread; resume it exactly as `block_and_switch` left it (as W2.9's
            // self-terminate does). The returned status is ignored while blocked
            // — the blocked thread's re-run produces the real STATUS_WAIT_0.
            self.syscall_resume_as_is = true;
            Ok(STATUS_WAIT_0)
        } else if infinite {
            Err(EmuError::Os(deadlock))
        } else {
            Ok(STATUS_TIMEOUT)
        }
    }

    /// Peek whether the handle set is satisfiable for `tid` without consuming.
    fn nt_wait_satisfiable(&self, handles: &[u64], all: bool, tid: u32) -> bool {
        let sig = |h: &u64| self.kobject_is_signaled(*h, tid);
        if all {
            handles.iter().all(sig)
        } else {
            handles.iter().any(sig)
        }
    }

    /// Consume a *satisfiable* wait (peek first). Wait-all acquires every object
    /// and returns `STATUS_WAIT_0`; wait-any acquires the first signaled object
    /// and returns `STATUS_WAIT_0 + its index` (the index the caller must learn —
    /// the W2.11 `server_acquire` does not report it, so this is the NT variant).
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
            STATUS_WAIT_0 // unreachable: the set was peeked satisfiable
        }
    }

    /// Rewind the guest so the *entire* `SYSCALL` (`0F 05`) re-executes on the
    /// blocked thread's next schedule (design §5). After the CPU applied the
    /// SYSCALL side effects, RCX holds the return address just past the 2-byte
    /// instruction and R11 holds the pre-syscall RFLAGS. Setting `rip = RCX − 2`
    /// re-arms the instruction; `rflags ← R11` undoes the flags side effect so the
    /// second execution re-derives the same R11 (incl. the guest's DF); `rsp ←`
    /// the captured guest RSP steps off the dispatcher's unix stack.
    ///
    /// Re-execution invariant: the SSDT index (EAX, from the stub's `mov eax,N`)
    /// and the volatile arg registers (arg0=R10, arg1=RDX, arg2=R8, arg3=R9) are
    /// untouched by the dispatcher (it only saves/reads them and switches RSP) and
    /// by the wait handler up to this point (`syscall_arg` only *reads* them), so
    /// the re-executed `SYSCALL` re-reads identical arguments and re-dispatches to
    /// this same handler — which, now that the object is signaled, acquires and
    /// returns normally.
    fn rewind_syscall(&self, cpu: &mut CpuState) {
        let ret_rip = cpu.reg(Reg::Rcx);
        cpu.rip = ret_rip.wrapping_sub(SYSCALL_INSN_LEN);
        cpu.rflags = cpu.reg(Reg::R11);
        cpu.set_rsp(self.syscall_guest_rsp);
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

// ---- NT sync syscall status codes + constants + SSDT wiring (roadmap W2.12) --
//
// NTSTATUS values are the public ntstatus.h definitions; the SSDT indices were
// recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N` immediate
// (`example_exe/wine-dlls/x86_64-windows/ntdll.dll`; U9), never guessed. No Wine
// `.c` was read.

/// `STATUS_SUCCESS` — also the value `NtSetEvent`/`Nt*Create` return on success.
const NT_STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_WAIT_0` — a satisfied wait; wait-any adds the satisfied index.
const STATUS_WAIT_0: u32 = 0x0000_0000;
/// `STATUS_TIMEOUT` — an unsatisfied poll (or finite wait with no wakeup).
const STATUS_TIMEOUT: u32 = 0x0000_0102;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
/// `STATUS_SEMAPHORE_LIMIT_EXCEEDED` — a release would push the count past max.
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;

/// `EVENT_TYPE::NotificationEvent` (public winternl.h) — a manual-reset event.
/// `SynchronizationEvent` (=1) is auto-reset.
const NOTIFICATION_EVENT: u32 = 0;

/// `WAIT_TYPE::WaitAll` / `WaitAny` (public winnt.h `_WAIT_TYPE`). kernel32's
/// `WaitForMultipleObjects` passes `bWaitAll ? WaitAll : WaitAny`.
const WAIT_TYPE_ALL: u32 = 0;
const WAIT_TYPE_ANY: u32 = 1;

/// `MAXIMUM_WAIT_OBJECTS` (public winnt.h) — the most handles one wait carries.
const MAXIMUM_WAIT_OBJECTS: u64 = 64;

/// Length of the `SYSCALL` instruction (`0F 05`) — the rewind steps `rip` back
/// this far so the whole instruction re-executes (design §5).
const SYSCALL_INSN_LEN: u64 = 2;

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x04;
pub(crate) const SSDT_NT_RELEASE_SEMAPHORE: u32 = 0x0a;
pub(crate) const SSDT_NT_SET_EVENT: u32 = 0x0e;
pub(crate) const SSDT_NT_OPEN_EVENT: u32 = 0x40;
pub(crate) const SSDT_NT_CREATE_EVENT: u32 = 0x48;
pub(crate) const SSDT_NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x5b;
pub(crate) const SSDT_NT_CREATE_MUTANT: u32 = 0x7e;
pub(crate) const SSDT_NT_CREATE_SEMAPHORE: u32 = 0x83;

/// The three NT wait-timeout dispositions (see [`WinOs::read_nt_timeout`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum NtTimeout {
    /// NULL `PLARGE_INTEGER` — wait forever.
    Infinite,
    /// `*Timeout == 0` — return immediately without blocking.
    Poll,
    /// Any other value — a finite timeout (blocks; no timed wakeups yet).
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
