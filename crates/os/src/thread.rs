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

/// Size of a per-thread TEB region. Matches the app's main-thread TEB region:
/// the x64 TEB struct reaches ~0x1838 (its inline `TlsSlots[64]` sit at 0x1480,
/// `TlsExpansionSlots` at 0x1780), and the NT-syscall dispatcher parks this
/// thread's `syscall_frame` in the tail — 0x2000 covers both.
const THREAD_TEB_SIZE: u64 = 0x2000;

/// x64 TEB field offsets Wine's PE `ntdll` walks (public `winternl.h`/NT_TIB
/// layout; confirmed against the pinned guest binary's `gs:`-relative reads).
/// The fields [`WinOs::seed_teb_64`] populates so the ~0x1838-byte 64-bit TEB is
/// walkable without a fault (roadmap W2.9/W2.10). Every offset ntdll actually
/// *dereferences* off `gs:[0x30]` (recovered from the pinned guest binary) is
/// listed here; the rest of the region is zero-mapped, which satisfies the
/// null-checks ntdll does on the fields it does not dereference.
mod teb64 {
    pub const NT_TIB_EXCEPTION_LIST: u64 = 0x000; // NtTib.ExceptionList (-1 = end)
    pub const NT_TIB_STACK_BASE: u64 = 0x008; // NtTib.StackBase
    pub const NT_TIB_STACK_LIMIT: u64 = 0x010; // NtTib.StackLimit
    pub const NT_TIB_SELF: u64 = 0x030; // NtTib.Self → the TEB itself
    pub const CLIENT_ID_PROCESS: u64 = 0x040; // ClientId.UniqueProcess
    pub const CLIENT_ID_THREAD: u64 = 0x048; // ClientId.UniqueThread
    pub const TLS_POINTER: u64 = 0x058; // ThreadLocalStoragePointer
    pub const PEB: u64 = 0x060; // ProcessEnvironmentBlock
    // StaticUnicodeString/Buffer offsets are Wine-build-specific: the pinned
    // `kernelbase.dll` `file_name_AtoW` reads them off the TEB as `gs:[0x30]+0x1258`
    // (`RtlAnsiStringToUnicodeString(&TEB->StaticUnicodeString, ...)` then returns
    // `[+8]` = Buffer). Wine's PE TEB places StaticUnicodeString at 0x1258 (not
    // the stock-Windows 0x538); the 0xB8/0xC8 here were the 32-bit-ish offsets and
    // left the real field zeroed, so `RtlAnsiStringToUnicodeString` overflowed a
    // 0-length buffer → `file_name_AtoW` returned NULL → every `*A` file API
    // (`CreateFileA`, …) failed *before* reaching `NtCreateFile` (roadmap W3.7).
    pub const STATIC_UNICODE_STRING: u64 = 0x1258; // UNICODE_STRING {Len, MaxLen, +pad, Buffer}
    pub const STATIC_UNICODE_BUFFER: u64 = 0x1268; // WCHAR[261] backing buffer
    pub const COUNT_OF_OWNED_CRIT_SECS: u64 = 0x6C8; // CountOfOwnedCriticalSections (ULONG)
    // W2.10 completion: the pointer fields the pinned ntdll dereferences off the
    // TEB and that must therefore hold a *valid* value (not merely read 0). The
    // TEB region is freshly zero-mapped, so we write the ones with a meaningful
    // non-zero value and leave the rest reading back 0 (their correct initial
    // state — no allocated stack/expansion arrays yet).
    pub const TLS_EXPANSION_SLOTS: u64 = 0x1780; // ThreadLocalStoragePointer expansion (0 until grown)
    pub const DEALLOCATION_STACK: u64 = 0x1478; // NtTib-independent stack base for teardown

    /// `TEB.ActivationContextStackPointer` (a `PACTIVATION_CONTEXT_STACK`). Wine's
    /// ntdll dereferences this in the SxS / activation-context lookup
    /// (`RtlFindActivationContextSectionString` @ RVA 0x24180:
    /// `mov rax,gs:[0x30]; mov rax,[rax+0x2c8]; mov rcx,[rax]`) — it must point at
    /// a real (empty) `ACTIVATION_CONTEXT_STACK`, not read back 0.
    pub const ACTIVATION_CONTEXT_STACK_POINTER: u64 = 0x2c8;

    /// Offset (inside the mapped 0x2000 TEB region, in the gap between the last
    /// real TEB field at ~0x1838 and the NT-syscall `syscall_frame` parked at
    /// `0x2000 - 0x140 = 0x1ec0`) where [`WinOs::seed_teb_64`] lays an inline,
    /// per-thread `ACTIVATION_CONTEXT_STACK` and points
    /// [`ACTIVATION_CONTEXT_STACK_POINTER`] at it. Self-contained in the TEB
    /// region so every thread (main + spawned) gets its own, no arena needed.
    pub const ACTIVATION_CONTEXT_STACK: u64 = 0x1900;

    /// Size of the x64 `ACTIVATION_CONTEXT_STACK` struct (recovered from the
    /// pinned ntdll: `ActiveFrame` PVOID @0x00, `FrameListCache` LIST_ENTRY @0x08,
    /// `Flags` ULONG @0x18, `NextCookieSequenceNumber` ULONG @0x1c, `StackId`
    /// ULONG @0x20 → 0x28 rounded). `ActiveFrame = 0` (empty stack) makes every
    /// read path — `RtlFindActivationContextSectionString`,
    /// `RtlFreeActivationContextStack` — take its "no active frame" branch.
    pub const ACTIVATION_CONTEXT_STACK_SIZE: u64 = 0x28;

    /// `MaximumLength` of `StaticUnicodeString` — 261 WCHARs (the documented
    /// `STATIC_UNICODE_BUFFER_LENGTH`), in bytes.
    pub const STATIC_UNICODE_MAX_BYTES: u16 = 261 * 2;
}

/// 32-bit TEB field offsets (NT_TIB smaller-pointer layout) for the fields this
/// step seeds. The 32-bit TEB lives behind `fs:`.
mod teb32 {
    pub const NT_TIB_EXCEPTION_LIST: u64 = 0x000;
    pub const NT_TIB_STACK_BASE: u64 = 0x004;
    pub const NT_TIB_STACK_LIMIT: u64 = 0x008;
    pub const NT_TIB_SELF: u64 = 0x018;
    pub const CLIENT_ID_PROCESS: u64 = 0x020;
    pub const CLIENT_ID_THREAD: u64 = 0x024;
    pub const TLS_POINTER: u64 = 0x02C;
    pub const PEB: u64 = 0x030;
    pub const STATIC_UNICODE_STRING: u64 = 0x0AC; // {Len u16, MaxLen u16, Buffer ptr}
    pub const STATIC_UNICODE_BUFFER: u64 = 0x0B4;
    pub const COUNT_OF_OWNED_CRIT_SECS: u64 = 0x38C;
    pub const TLS_EXPANSION_SLOTS: u64 = 0x0F94; // ThreadLocalStoragePointer expansion (0 until grown)
    pub const DEALLOCATION_STACK: u64 = 0x0E0C; // stack base for teardown
    pub const STATIC_UNICODE_MAX_BYTES: u16 = 261 * 2;
}

/// Compile-time invariant: the inline `ACTIVATION_CONTEXT_STACK` seeded into the
/// TEB region must not run into the NT-syscall `syscall_frame` parked in the tail
/// of the 0x2000 TEB region (the last 0x140 bytes, i.e. from `0x2000 - 0x140 =
/// 0x1ec0`).
const _: () = assert!(
    teb64::ACTIVATION_CONTEXT_STACK + teb64::ACTIVATION_CONTEXT_STACK_SIZE
        <= THREAD_TEB_SIZE - 0x140,
    "ACTIVATION_CONTEXT_STACK collides with the syscall_frame tail"
);

/// Fixed process id reported through `ClientId.UniqueProcess` (matches
/// `GetCurrentProcessId`).
const PROCESS_ID: u64 = 0x1000;

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
    /// Base of this thread's own TEB region (the value the CPU uses as the `gs`
    /// segment base while this thread runs, so `gs:[…]` reads *this* thread's
    /// TEB — roadmap W2.9). The main thread reuses the app-mapped
    /// `cfg.teb_base`; every spawned thread gets a fresh region seeded by
    /// [`WinOs::seed_teb_64`]. The NT-syscall dispatcher also parks this thread's
    /// `syscall_frame` in the tail of this region.
    pub teb_base: u64,
    /// Owned TEB region `[teb_base, teb_base+teb_size)` to unmap on teardown
    /// (0 for the main thread, whose TEB the app owns).
    pub teb_owned: u64,
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
    /// When the image has TLS callbacks, a new thread starts at the TLS-attach
    /// driver thunk instead of its start routine; this holds the real
    /// `(start_routine, parameter)` to seat once the `DLL_THREAD_ATTACH`
    /// callbacks have run (roadmap W0.3). `None` once consumed / for the main
    /// thread.
    pub pending_entry: Option<(u64, u64)>,
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
            teb_base: 0,
            teb_owned: 0,
            suspend_count: 0,
            wait: None,
            tls: HashMap::new(),
            fls: HashMap::new(),
            msgs: VecDeque::new(),
            quit_code: None,
            pending_entry: None,
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

    // ---- per-thread TEB --------------------------------------------------

    /// Seed the complete Wine-walkable TEB at `teb_base` for a thread with id
    /// `tid`, whose `ProcessEnvironmentBlock` is `peb`, running over stack
    /// `[stack_base, stack_top)` (roadmap W2.9/W2.10).
    ///
    /// Writes every field Wine's PE `ntdll` dereferences off `NtCurrentTeb()`:
    /// `NtTib` (ExceptionList=-1 sentinel, StackBase/StackLimit, Self),
    /// `ClientId` (process/thread ids), `ThreadLocalStoragePointer`,
    /// `ProcessEnvironmentBlock`, the `StaticUnicodeString` (an empty
    /// UNICODE_STRING pointing at the inline `StaticUnicodeBuffer`),
    /// `CountOfOwnedCriticalSections`, `DeallocationStack` (the stack base used
    /// on teardown) and `TlsExpansionSlots` (0 until the expansion array is
    /// grown). The TEB region is freshly mapped RW and zero-filled, so the
    /// pointer fields not written here read back 0 — their correct initial state
    /// — which satisfies ntdll's null-checks. `peb` is passed explicitly (rather
    /// than read off `self.cfg`) so a caller can seed a TEB before the PEB
    /// address is committed to the config.
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
            w(mem, teb64::NT_TIB_EXCEPTION_LIST, u64::MAX)?; // no SEH frame yet
            w(mem, teb64::NT_TIB_STACK_BASE, stack_top)?;
            w(mem, teb64::NT_TIB_STACK_LIMIT, stack_base)?;
            w(mem, teb64::NT_TIB_SELF, teb_base)?;
            w(mem, teb64::CLIENT_ID_PROCESS, PROCESS_ID)?;
            w(mem, teb64::CLIENT_ID_THREAD, tid as u64)?;
            w(mem, teb64::TLS_POINTER, 0)?; // set up lazily by the CRT/ntdll
            w(mem, teb64::PEB, peb)?;
            // StaticUnicodeString: an empty UNICODE_STRING whose Buffer is the
            // inline StaticUnicodeBuffer (Length 0, MaximumLength 522).
            let len_maxlen = (teb64::STATIC_UNICODE_MAX_BYTES as u64) << 16; // Length=0 | MaxLen<<16
            w(mem, teb64::STATIC_UNICODE_STRING, len_maxlen)?;
            w(mem, teb64::STATIC_UNICODE_STRING + 8, teb_base + teb64::STATIC_UNICODE_BUFFER)?;
            w(mem, teb64::COUNT_OF_OWNED_CRIT_SECS, 0)?;
            w(mem, teb64::DEALLOCATION_STACK, stack_base)?;
            w(mem, teb64::TLS_EXPANSION_SLOTS, 0)?;
            // ActivationContextStackPointer: point at an inline, empty
            // ACTIVATION_CONTEXT_STACK laid in the TEB region's dead gap. The
            // region is zero-mapped, so ActiveFrame(@0x00)/Flags/StackId already
            // read 0 (the empty-stack initial state ntdll's SxS lookup expects);
            // the FrameListCache LIST_ENTRY (@0x08) is made self-referential to
            // match a live process's initial thread activation-context stack.
            let actx = teb_base + teb64::ACTIVATION_CONTEXT_STACK;
            w(mem, teb64::ACTIVATION_CONTEXT_STACK_POINTER, actx)?;
            w(mem, teb64::ACTIVATION_CONTEXT_STACK + 0x08, actx + 0x08)?; // FrameListCache.Flink → self
            w(mem, teb64::ACTIVATION_CONTEXT_STACK + 0x10, actx + 0x08)?; // FrameListCache.Blink → self
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

    /// Seed the **main thread's** full Wine-walkable TEB at `cfg.teb_base`
    /// (roadmap W2.9). The app maps the main TEB and seeds Self/PEB/StackBase/
    /// StackLimit before the OS exists; this fills the remaining fields Wine's
    /// ntdll walks (ExceptionList, ClientId, ThreadLocalStoragePointer,
    /// StaticUnicodeString, CountOfOwnedCriticalSections) so a Wine thread that
    /// reads the main thread's TEB does not fault. Idempotent with the app's
    /// seed (it rewrites the same Self/PEB/stack values). No-op without a TEB.
    pub fn seed_main_teb(&self, mem: &mut dyn Memory, stack_base: u64, stack_top: u64) -> Result<()> {
        let teb = self.cfg.teb_base;
        if teb == 0 {
            return Ok(());
        }
        self.seed_teb_64(mem, teb, 0x1001 /* main tid */, self.cfg.peb_addr, stack_top, stack_base)
    }

    /// Allocate and seed a fresh per-thread TEB region, returning its base (the
    /// thread's `gs`/`fs` segment base). Returns `None` if the arena is
    /// exhausted (the caller then fails the thread creation).
    fn new_thread_teb(&mut self, mem: &mut dyn Memory, tid: u32, stack_base: u64, stack_top: u64) -> Option<u64> {
        let teb_base = self.map_anywhere(mem, THREAD_TEB_SIZE, Perm::RW, "thread-teb")?;
        self.seed_teb_64(mem, teb_base, tid, self.cfg.peb_addr, stack_top, stack_base).ok()?;
        Some(teb_base)
    }

    // ---- the thread APIs -------------------------------------------------

    /// The shared thread-spawn core behind both `CreateThread` (Win32) and
    /// `NtCreateThreadEx` (NT). Allocates the new thread's stack **and its own
    /// per-thread TEB** (roadmap W2.9), builds its initial register state (with
    /// its `gs`/`fs` segment base pointing at that TEB), and enqueues it. Does
    /// not switch — the creating thread keeps running; the new thread starts
    /// when it yields. Returns `(handle, tid)`, or `None` if the arena is
    /// exhausted (`last_error` set to ERROR_NOT_ENOUGH_MEMORY).
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
            self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
            return Ok(None);
        };
        let stack_top = stack_base + stack_size;

        let tid = self.next_tid;
        self.next_tid += 1;

        // Each thread gets its own full Wine-walkable TEB; its base becomes the
        // thread's `gs`/`fs` segment base so `gs:[…]` reads *this* thread's TEB.
        let Some(teb_base) = self.new_thread_teb(mem, tid, stack_base, stack_top) else {
            let _ = mem.unmap(stack_base, stack_size);
            self.last_error = 8;
            return Ok(None);
        };

        // Build the start state. Normally this is a `call entry(param)` frame
        // returning to the thread-exit thunk. When the image carries TLS
        // callbacks, or any loaded DLL wants thread notifications, the thread
        // must first run each with `DLL_THREAD_ATTACH` (roadmap W0.3/W0.7): we
        // instead start it at the TLS-attach driver thunk over a stack whose top
        // is the entry-seating thunk (the callbacks' drain target), and stash
        // the real `(entry, param)` to seat afterward.
        let mut st = CpuState::new();
        // Per-thread segment bases (roadmap W2.9): the scheduler carries these
        // in the saved state, so on activation the CPU reads this thread's TEB.
        st.gs_base = teb_base;
        st.fs_base = teb_base;
        let exit_thunk = self.thread_exit_thunk;
        let has_tls = !self.tls_callbacks.is_empty() || !self.thread_notify_targets().is_empty();
        let mut pending_entry = None;
        if self.cfg.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            if has_tls {
                sp -= 8;
                mem.write_u64(sp, self.thread_entry_thunk)?; // callbacks drain here
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
                mem.write_u32(sp, self.thread_entry_thunk as u32)?; // drain target
                st.rip = self.thread_tls_thunk;
                pending_entry = Some((entry, param));
            } else {
                sp -= 4;
                mem.write_u32(sp, param as u32)?; // [esp+4] = lpParameter
                sp -= 4;
                mem.write_u32(sp, exit_thunk as u32)?; // [esp] = return address
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
        });
        Ok(Some((handle, tid)))
    }

    /// CreateThread(lpAttr, dwStackSize, lpStart, lpParam, dwFlags, lpThreadId)
    /// and `_beginthreadex` (same argument positions). Does not switch — the
    /// creating thread keeps running and the new thread starts when it yields.
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

    /// Reclaim thread `i`'s owned stack **and TEB** regions (no-op for the main
    /// thread, whose stack/TEB the app owns).
    fn free_thread_stack(&mut self, mem: &mut dyn Memory, i: usize) {
        let (base, size) = (self.threads[i].stack_base, self.threads[i].stack_size);
        if base != 0 {
            let _ = mem.unmap(base, size);
        }
        let teb = self.threads[i].teb_owned;
        if teb != 0 {
            let _ = mem.unmap(teb, THREAD_TEB_SIZE);
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

    /// A new thread's initial `rip` when the image has TLS callbacks or any
    /// loaded DLL wants thread notifications: run each with
    /// `callback(hModule, DLL_THREAD_ATTACH, NULL)` before the thread's start
    /// routine (roadmap W0.3/W0.7). The main image's TLS callbacks run first
    /// (with `hModule` = the exe), then every loaded plugin's `DllMain` that did
    /// not `DisableThreadLibraryCalls` (in initialization order, with `hModule`
    /// = that DLL's base). The thread's stack top already holds the entry-seating
    /// thunk, so the drained callback queue returns there.
    pub(crate) fn thread_tls_attach(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let module = self.cfg.image_base;
        let mut calls: Vec<(u64, Vec<u64>)> = self
            .tls_callbacks
            .iter()
            .map(|&cb| (cb, vec![module, 2 /* DLL_THREAD_ATTACH */, 0]))
            .collect();
        // Then each loaded plugin DllMain(base, DLL_THREAD_ATTACH, NULL).
        for (entry, base) in self.thread_notify_targets() {
            calls.push((entry, vec![base, 2 /* DLL_THREAD_ATTACH */, 0]));
        }
        // `invoke_callbacks` reads the drain-return address from `[rsp]` (the
        // entry-seating thunk seated by `create_thread`) and cleans up 0 args.
        self.invoke_callbacks(cpu, mem, calls, 0, 0, false)
    }

    /// The TLS-attach callbacks have drained: seat the real
    /// `start_routine(parameter)` frame (returning to the thread-exit thunk).
    pub(crate) fn thread_start_entry(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let cur = self.current;
        let (entry, param) = self.threads[cur].pending_entry.take().unwrap_or((0, 0));
        let exit_thunk = self.thread_exit_thunk;
        let base = cpu.rsp();
        self.setup_call_args(cpu, mem, entry, &[param], exit_thunk, base)?;
        Ok(Outcome::Resume)
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

    // ---- NT thread syscalls (roadmap W2.9) -------------------------------
    //
    // The NTSTATUS face of the P3.4 scheduler, reached via a raw guest
    // `SYSCALL` through the W2.3 dispatcher. Args come via `syscall_arg`
    // (arg0=R10, arg1=RDX, arg2=R8, arg3=R9, then the guest stack). Signatures
    // are from public NT headers (winternl.h / phnt-style `NtCreateThreadEx`);
    // no Wine `.c` was read.

    /// The base of the currently-running thread's TEB (its `gs`/`fs` segment
    /// base). Used by the syscall dispatcher to locate this thread's
    /// `syscall_frame` and by `NtQueryInformationThread(ThreadBasicInformation)`.
    pub(crate) fn current_thread_teb(&self) -> u64 {
        self.threads.get(self.current).map_or(0, |t| t.teb_base)
    }

    /// Resolve an NT thread handle (a real `KObject::Thread` handle, or the
    /// `NtCurrentThread` pseudo-handle `-2`) to a `threads` index.
    fn nt_thread_index(&self, handle: u64) -> Option<usize> {
        if handle == NT_CURRENT_THREAD {
            return Some(self.current);
        }
        self.thread_by_handle(handle)
    }

    /// `NtCreateThreadEx(&ThreadHandle, DesiredAccess, ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits,
    /// StackSize, MaximumStackSize, AttributeList)`.
    ///
    /// arg0=&ThreadHandle (OUT), arg4=StartRoutine, arg5=Argument,
    /// arg6=CreateFlags (bit0 = THREAD_CREATE_FLAGS_CREATE_SUSPENDED),
    /// arg8=StackSize. The desired-access mask, object attributes, target
    /// process (self only), zero-bits and attribute list are accepted and
    /// ignored — exemu hosts a single process.
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
        match self.spawn_thread(mem, stack_size, entry, param, suspended)? {
            Some((handle, _tid)) => {
                self.write_ptr(mem, handle_out, handle)?;
                Ok(STATUS_SUCCESS)
            }
            None => Ok(STATUS_NO_MEMORY),
        }
    }

    /// `NtTerminateThread(ThreadHandle, ExitStatus)`. arg0=ThreadHandle
    /// (`NtCurrentThread` = -2), arg1=ExitStatus. Terminating the current
    /// thread switches to another runnable thread (or exits the process when it
    /// was the last); the dispatcher then resumes as-is instead of returning to
    /// the dead thread.
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
            // Switch away from the terminated thread; the dispatcher must not
            // restore the dead thread's frame or return to it.
            self.syscall_resume_as_is = true;
            match self.pick_next() {
                Some(next) => {
                    self.activate(cpu, next);
                }
                None => {
                    // Last thread: end the process. The syscall hook maps this
                    // through, so set RAX for completeness and let the run loop
                    // observe the process exit on the next step. Since there is
                    // no other thread to run, park rip on the exit and rely on
                    // the process-exit path; the dispatcher returns Continue.
                    return Ok(code); // resume_as_is set: RAX carries the code
                }
            }
        }
        Ok(STATUS_SUCCESS)
    }

    /// `NtTerminateProcess(ProcessHandle, ExitStatus)`. arg0=ProcessHandle
    /// (`NtCurrentProcess` = -1, or 0 = the current process), arg1=ExitStatus.
    ///
    /// Terminating the current process ends the whole run with `ExitStatus`: the
    /// handler records the code in `pending_syscall_exit`, which the syscall
    /// dispatcher observes to yield `Exit::ProcessExit` to the run loop (the same
    /// termination `ExitProcess` reaches). A handle naming some *other* process is
    /// meaningless in exemu's single-process model and is accepted as a no-op
    /// success. This also services Wine's `loader_init` crash-cascade path, which
    /// calls `ZwTerminateProcess` after a failed `load_dll` (roadmap W3.2).
    pub(crate) fn nt_terminate_process(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let code = self.syscall_arg(cpu, mem, 1)? as i32;
        // 0 or NtCurrentProcess (-1) name the current (only) process.
        if handle == 0 || handle == u64::MAX {
            self.pending_syscall_exit = Some(code);
            return Ok(STATUS_SUCCESS);
        }
        // Any other handle: no other process exists to terminate — succeed inertly.
        Ok(STATUS_SUCCESS)
    }

    /// `NtSuspendThread(ThreadHandle, *PreviousSuspendCount)`.
    /// arg0=ThreadHandle, arg1=&PreviousSuspendCount (OUT, optional).
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

    /// `NtResumeThread(ThreadHandle, *PreviousSuspendCount)`.
    /// arg0=ThreadHandle, arg1=&PreviousSuspendCount (OUT, optional).
    pub(crate) fn nt_resume_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let prev_out = self.syscall_arg(cpu, mem, 1)?;
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

    /// `NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength, *ReturnLength)`.
    ///
    /// Serves `ThreadBasicInformation` (class 0): a `THREAD_BASIC_INFORMATION`
    /// `{ NTSTATUS ExitStatus; PVOID TebBaseAddress; CLIENT_ID ClientId;
    /// KAFFINITY AffinityMask; KPRIORITY Priority; KPRIORITY BasePriority; }`.
    /// arg0=ThreadHandle, arg1=class, arg2=buffer, arg3=length, arg4=&ReturnLength.
    pub(crate) fn nt_query_information_thread(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let return_length = self.syscall_arg(cpu, mem, 4)?;
        if class != THREAD_BASIC_INFORMATION {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        let Some(i) = self.nt_thread_index(handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        // THREAD_BASIC_INFORMATION is 0x30 bytes on x64, 0x1C on x86.
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
            mem.write_u32(buffer, exit_status)?; // ExitStatus (NTSTATUS, +pad)
            mem.write_u64(buffer + 0x08, teb)?; // TebBaseAddress
            mem.write_u64(buffer + 0x10, PROCESS_ID)?; // ClientId.UniqueProcess
            mem.write_u64(buffer + 0x18, tid as u64)?; // ClientId.UniqueThread
            mem.write_u64(buffer + 0x20, 1)?; // AffinityMask
            mem.write_u32(buffer + 0x28, 0)?; // Priority
            mem.write_u32(buffer + 0x2C, 0)?; // BasePriority
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
}

// ---- NT thread syscall status codes + SSDT wiring (roadmap W2.9) ----------

/// `NtCurrentThread` pseudo-handle (`(HANDLE)-2`).
const NT_CURRENT_THREAD: u64 = u64::MAX - 1;
/// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` for `NtCreateThreadEx.CreateFlags`.
const CREATE_SUSPENDED_NT: u32 = 0x0000_0001;
/// `ThreadBasicInformation` `THREADINFOCLASS` value.
const THREAD_BASIC_INFORMATION: u32 = 0;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_CREATE_THREAD_EX: u32 = 0x85;
pub(crate) const SSDT_NT_TERMINATE_THREAD: u32 = 0x53;
/// `NtTerminateProcess` (roadmap W3.2). Index recovered from the pinned guest
/// `ntdll.dll` stub's `mov eax,N`.
pub(crate) const SSDT_NT_TERMINATE_PROCESS: u32 = 0x2c;
pub(crate) const SSDT_NT_SUSPEND_THREAD: u32 = 0xf5;
pub(crate) const SSDT_NT_RESUME_THREAD: u32 = 0x52;
pub(crate) const SSDT_NT_QUERY_INFORMATION_THREAD: u32 = 0x25;

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
