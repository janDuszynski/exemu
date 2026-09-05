//! The debug seam — one shared handle, one injectable trace trait, plain-data
//! snapshots (roadmap W9.3, step S1 of the W9.2/W9.3 design).
//!
//! # Why this is a module and not a trait method
//!
//! The obvious place to hang a breakpoint is one of the three core traits. All
//! three are wrong, for specific reasons rather than aesthetic ones:
//!
//! * **[`Hooks`](crate::hooks::Hooks) must not.** `Hooks::intercept` is the OS
//!   thunk seam and is called *only* by the interpreter, once per instruction,
//!   before decode (`crates/cpu/src/lib.rs`, `Cpu::step`). A compiled block
//!   never calls it, and `exemu-jit` does not depend on `exemu-core`'s `Hooks`
//!   at all. A breakpoint hung there would be an **interpreter-only**
//!   breakpoint — the one disqualifying bug for a debugger that has to be
//!   believed when it says "the guest never reached this address".
//! * **[`Cpu`](crate::cpu::Cpu) must not.** The JIT is not a `Cpu` implementor;
//!   the run loop drives it *alongside* the `Cpu`, not behind it. A
//!   `Cpu::breakpoint` would burden every implementor and still not reach
//!   compiled code.
//! * **[`Memory`](crate::memory::Memory) must not** carry breakpoints. An
//!   instruction breakpoint is not a memory event, and expressing one as a
//!   guest-memory write (`INT3` patching) would bump the self-modifying-code
//!   generation counter on every arm, flush the JIT cache, and be visible to a
//!   guest that checksums itself — and the corpus's headline binary is a
//!   self-extracting installer. exemu's breakpoints are **out of band**: guest
//!   memory is never modified to arm one.
//!
//! What the domain gains instead is this module: a shared, `Arc`-backed
//! [`DebugControl`] handle built to the exact pattern
//! [`GuestClock`](crate::clock::GuestClock) already establishes, an injectable
//! [`TraceSink`] built to the [`UserDriver`](crate::driver::UserDriver) /
//! [`AudioSink`](crate::audio::AudioSink) pattern, and plain-data DTOs. Every
//! dependency arrow still points inward: `cpu → core`, `jit → core`,
//! `memory → core`, `os → core`, `app → core`, `ui → core`.
//!
//! # Attaching is free
//!
//! The whole design rests on the claim that attaching a debugger cannot perturb
//! a run — the zero-tolerance corpus is the project's strongest correctness
//! asset and a debugger that moves it by one instruction poisons every future
//! regression investigation. The claim is made *structurally* true here rather
//! than measured after the fact:
//!
//! * [`DebugControl::detached`] sets `attached` as a **plain `bool` field**, not
//!   an atomic, so a consumer hoists it into a local exactly as the run loop
//!   already hoists `GuestClock::is_virtual`, and every added site is inside an
//!   untaken branch.
//! * A detached handle is **inert**: every mutator is a no-op and every accessor
//!   reports "nothing armed". There is no state a detached handle can be put
//!   into that makes a hot-path check do more work.
//! * Attached-but-unarmed costs **one relaxed atomic load** and a compare: the
//!   64-bit Bloom filter over armed addresses is zero, so it cannot match, and
//!   the mutex behind it is never taken. That is the same "cheap exact reject
//!   before the expensive lookup" trick `WinOs::intercept` already uses on the
//!   thunk path.
//!
//! A Bloom **miss is proof of absence**; a hit is only a hint, so the mutex is a
//! confirmation step, not the mechanism. The direction that matters is the one
//! the unit tests pin: there must be **no false negatives**, because a false
//! negative is a missed breakpoint.
//!
//! # The read-only protocol
//!
//! [`DebugCommand`] deliberately has **no write variant** — no `WriteMemory`, no
//! `SetRegister`. A front-end's entire view of guest memory is `Vec<u8>` copies
//! delivered in [`DebugEvent::Memory`]. Adding a write would be a visible,
//! reviewable diff *in this file*, and these DTOs live in `core` rather than in
//! `exemu-app` precisely so a presentation crate can render a session while
//! linking neither `exemu-memory` nor `exemu-os` — which is what turns that
//! restricted dependency list into a real barrier rather than an aspiration.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use crate::cpu::CpuState;
use crate::memory::Region;

/// The value [`DebugControl::break_at_step`] reports when no instruction-count
/// breakpoint is armed. Chosen so a consumer can fold it into an existing
/// `min`-reduction over deadlines without a branch.
pub const BREAK_AT_STEP_DISABLED: u64 = u64::MAX;

/// Granularity of the watchpoint Bloom filter: one bit's worth of key per 4 KiB
/// page. The *set* is byte-exact; only the cheap reject is page-granular.
const WATCH_PAGE_SHIFT: u32 = 12;

/// Above this many pages an armed watchpoint stops contributing individual bits
/// and saturates the filter instead. Saturating keeps the "no false negatives"
/// guarantee (an all-ones filter always hits) and bounds the arm-time loop; a
/// watchpoint that large is a human decision to pay for exact checks anyway.
const WATCH_FILTER_MAX_PAGES: u64 = 4096;

/// Above this many pages an *access* stops probing individual bits and is
/// treated as a filter hit. Real accesses are at most a cache line wide; this
/// only bounds the loop against a nonsense length.
const ACCESS_PROBE_MAX_PAGES: u64 = 64;

// ---------------------------------------------------------------------------
// Small value types
// ---------------------------------------------------------------------------

/// What a watchpoint watches for, and what an access did.
///
/// The discriminants are bit flags so that "does this watchpoint cover this
/// access" is one `AND` ([`WatchKind::covers`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WatchKind {
    /// Guest reads only.
    Read = 1,
    /// Guest writes only.
    Write = 2,
    /// Either.
    ReadWrite = 3,
}

impl WatchKind {
    /// Does a watchpoint armed for `self` fire on an access of kind `access`?
    #[inline]
    pub const fn covers(self, access: WatchKind) -> bool {
        (self as u8) & (access as u8) != 0
    }

    /// The wire encoding used by the shared handle's atomics. Never `0` — that
    /// value is reserved for "no hit recorded".
    #[inline]
    const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    const fn from_u8(v: u8) -> Option<WatchKind> {
        match v {
            1 => Some(WatchKind::Read),
            2 => Some(WatchKind::Write),
            3 => Some(WatchKind::ReadWrite),
            _ => None,
        }
    }
}

/// An armed data watchpoint, as reported by [`DebugControl::watchpoints`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchpoint {
    /// First watched guest address.
    pub base: u64,
    /// Length in bytes. Never zero — a zero-length arm is ignored.
    pub len: u64,
    /// Read, write, or either.
    pub kind: WatchKind,
}

impl Watchpoint {
    /// Does `[addr, addr + len)` overlap this watchpoint's range?
    #[inline]
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let a_end = addr.saturating_add(len);
        let w_end = self.base.saturating_add(self.len);
        addr < w_end && self.base < a_end
    }
}

/// What the front-end has asked the run loop to do at its next stop point.
///
/// Written by any thread, observed by the emulator thread. Deliberately a
/// three-state atomic rather than a channel: the run loop must be able to
/// notice a pause without blocking, and a `store` cannot deadlock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StopRequest {
    /// Keep running (the default, and what a consumed request resets to).
    #[default]
    Run = 0,
    /// Stop at the next instruction boundary and park.
    Pause = 1,
    /// Execute exactly one instruction, then park again.
    Step = 2,
}

impl StopRequest {
    #[inline]
    const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    const fn from_u8(v: u8) -> StopRequest {
        match v {
            1 => StopRequest::Pause,
            2 => StopRequest::Step,
            _ => StopRequest::Run,
        }
    }
}

/// Why the emulator stopped, as carried in a [`DebugSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// A [`StopRequest::Pause`] was honoured.
    Paused,
    /// An instruction breakpoint armed at exactly `rip` was reached.
    Breakpoint {
        /// The armed address — always the address of the instruction about to
        /// execute, never a block entry.
        rip: u64,
    },
    /// A watched data access landed. Trap-after semantics: the instruction that
    /// made the access has completed.
    Watch {
        /// The watched guest address the access touched.
        addr: u64,
        /// Whether the access was a read or a write.
        kind: WatchKind,
    },
    /// A [`StopRequest::Step`] completed — exactly one instruction retired.
    StepComplete,
    /// The instruction-count breakpoint set by
    /// [`DebugControl::set_break_at_step`] was reached.
    StepCount {
        /// Retired instructions at the stop — equal to the armed count.
        steps: u64,
    },
    /// The guest faulted. `report` is the rendered fault text; the debugger is
    /// an observer here and does not own the reporter's format.
    Faulted {
        /// The fault reporter's rendered text.
        report: String,
    },
}

// ---------------------------------------------------------------------------
// DebugControl — the shared handle
// ---------------------------------------------------------------------------

/// A handle to the process's debug state. Cheap to clone — the interpreter, the
/// JIT, the memory backend, the run loop and the front-end all share one.
///
/// Built to the same shape as [`GuestClock`](crate::clock::GuestClock): an
/// `Arc<Inner>` of atomics whose mode is selected once at construction, so the
/// default (detached) path is a plain non-atomic `bool` read and every hot-path
/// accessor short-circuits on it. See the module docs for why "attaching is
/// free" is a structural property here rather than a measurement.
#[derive(Clone)]
pub struct DebugControl {
    inner: Arc<Inner>,
}

struct Inner {
    /// Selected mode. `false` (the default) means the handle is **inert**:
    /// every mutator is a no-op and every accessor reports "nothing armed", so
    /// the emulator is byte-identical to a build without a debugger.
    attached: bool,
    /// Bumped on every arm/disarm. Consumers (notably the JIT's code cache)
    /// cache it and invalidate on change.
    generation: AtomicU64,
    /// A 64-bit Bloom filter over armed instruction addresses. A miss is proof
    /// of absence and costs one relaxed load, so the mutex is never taken on
    /// the overwhelmingly common path.
    bp_filter: AtomicU64,
    /// The same, keyed by page, for watched data addresses.
    wp_filter: AtomicU64,
    /// Set by the front-end thread; observed by the run loop at its next stop
    /// point. See [`StopRequest`].
    stop_request: AtomicU8,
    /// Instruction-count breakpoint: stop when `steps == break_at_step`.
    /// [`BREAK_AT_STEP_DISABLED`] means none.
    break_at_step: AtomicU64,
    /// Recorded by the memory backend when a watched access lands; drained by
    /// the run loop after the instruction completes (trap-after semantics).
    /// Stores `addr + 1`, so `0` means "no hit".
    watch_hit: AtomicU64,
    /// The kind of the recorded hit, encoded by [`WatchKind::as_u8`]; `0` means
    /// none.
    watch_kind: AtomicU8,
    /// The authoritative sets. Only consulted after a filter hit, and only
    /// written by the front-end thread at human speed.
    sets: Mutex<Sets>,
}

#[derive(Default)]
struct Sets {
    /// Armed instruction addresses, sorted and deduplicated.
    breakpoints: Vec<u64>,
    /// Armed data watchpoints, in arm order.
    watchpoints: Vec<Watchpoint>,
}

impl Default for DebugControl {
    fn default() -> Self {
        DebugControl::detached()
    }
}

impl std::fmt::Debug for DebugControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugControl")
            .field("attached", &self.inner.attached)
            .field("generation", &self.generation())
            .field("breakpoints", &self.breakpoints())
            .field("watchpoints", &self.watchpoints())
            .field("request", &self.pending_request())
            .finish()
    }
}

impl DebugControl {
    /// The default installed everywhere today: no debugger. The handle is
    /// **inert** — arming does nothing and every accessor reports nothing
    /// armed, so no caller can put it into a state that costs the hot path
    /// anything.
    pub fn detached() -> DebugControl {
        DebugControl::with_mode(false)
    }

    /// A live debug session.
    pub fn attached() -> DebugControl {
        DebugControl::with_mode(true)
    }

    /// Select a mode by flag — `new(true)` is [`attached`](Self::attached),
    /// `new(false)` is [`detached`](Self::detached). Mirrors
    /// [`GuestClock::new`](crate::clock::GuestClock::new).
    pub fn new(attached: bool) -> DebugControl {
        DebugControl::with_mode(attached)
    }

    fn with_mode(attached: bool) -> DebugControl {
        DebugControl {
            inner: Arc::new(Inner {
                attached,
                generation: AtomicU64::new(0),
                bp_filter: AtomicU64::new(0),
                wp_filter: AtomicU64::new(0),
                stop_request: AtomicU8::new(StopRequest::Run.as_u8()),
                break_at_step: AtomicU64::new(BREAK_AT_STEP_DISABLED),
                watch_hit: AtomicU64::new(0),
                watch_kind: AtomicU8::new(0),
                sets: Mutex::new(Sets::default()),
            }),
        }
    }

    /// Is a debugger attached? A plain field read, not an atomic — hoist it
    /// into a local at the top of a loop, exactly as the run loop hoists
    /// [`GuestClock::is_virtual`](crate::clock::GuestClock::is_virtual).
    #[inline]
    pub fn is_attached(&self) -> bool {
        self.inner.attached
    }

    /// Bumped on every arm/disarm. A consumer that caches anything derived from
    /// the armed sets — the JIT's compiled blocks, above all — compares this
    /// once per block entry and invalidates on change.
    #[inline]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Relaxed)
    }

    // -- breakpoints --------------------------------------------------------

    /// Is an instruction breakpoint armed at exactly `addr`?
    ///
    /// Detached: a plain `bool` read. Attached and unarmed: one relaxed load
    /// and a compare. The mutex is taken only on a Bloom hit, and a Bloom miss
    /// is proof of absence.
    #[inline]
    pub fn is_break(&self, addr: u64) -> bool {
        if !self.inner.attached {
            return false;
        }
        let filter = self.inner.bp_filter.load(Ordering::Relaxed);
        let bits = bloom_bits(addr);
        if filter & bits != bits {
            return false;
        }
        self.sets().breakpoints.binary_search(&addr).is_ok()
    }

    /// Is *any* instruction breakpoint armed? One relaxed load.
    #[inline]
    pub fn any_breakpoints(&self) -> bool {
        self.inner.attached && self.inner.bp_filter.load(Ordering::Relaxed) != 0
    }

    /// The lowest armed breakpoint `>= start`, or `None`.
    ///
    /// Called **once per block compile**, so the JIT's inner loop needs only an
    /// integer compare against this value rather than a set lookup per
    /// instruction. `None` is naturally represented downstream as
    /// [`u64::MAX`], which no instruction can start at.
    pub fn next_break_at_or_after(&self, start: u64) -> Option<u64> {
        if !self.any_breakpoints() {
            return None;
        }
        let sets = self.sets();
        let i = sets.breakpoints.partition_point(|&a| a < start);
        sets.breakpoints.get(i).copied()
    }

    /// The armed instruction breakpoints, sorted. For a front-end to render;
    /// never on a hot path.
    pub fn breakpoints(&self) -> Vec<u64> {
        if !self.inner.attached {
            return Vec::new();
        }
        self.sets().breakpoints.clone()
    }

    /// Arm an instruction breakpoint. Idempotent; bumps
    /// [`generation`](Self::generation) only when the set actually changed.
    /// A no-op on a detached handle.
    pub fn arm_break(&self, addr: u64) {
        self.mutate(|s| match s.breakpoints.binary_search(&addr) {
            Ok(_) => false,
            Err(i) => {
                s.breakpoints.insert(i, addr);
                true
            }
        });
    }

    /// Disarm an instruction breakpoint. Idempotent. A no-op on a detached
    /// handle.
    pub fn disarm_break(&self, addr: u64) {
        self.mutate(|s| match s.breakpoints.binary_search(&addr) {
            Ok(i) => {
                s.breakpoints.remove(i);
                true
            }
            Err(_) => false,
        });
    }

    // -- watchpoints --------------------------------------------------------

    /// Is any data watchpoint armed? One relaxed load — this is what the JIT
    /// consults once per `run` to decide which memory helpers to install, so
    /// the disarmed case must not touch the mutex.
    #[inline]
    pub fn any_watchpoints(&self) -> bool {
        self.inner.attached && self.inner.wp_filter.load(Ordering::Relaxed) != 0
    }

    /// Does `[addr, addr + len)` overlap an armed watchpoint that covers an
    /// access of `kind`?
    ///
    /// Cheap reject first: page-granular Bloom probe, no lock. The confirming
    /// check against the set is byte-exact.
    #[inline]
    pub fn is_watched(&self, addr: u64, len: u64, kind: WatchKind) -> bool {
        if !self.inner.attached || len == 0 {
            return false;
        }
        let filter = self.inner.wp_filter.load(Ordering::Relaxed);
        if filter == 0 || !access_may_hit(filter, addr, len) {
            return false;
        }
        self.sets()
            .watchpoints
            .iter()
            .any(|w| w.kind.covers(kind) && w.overlaps(addr, len))
    }

    /// The armed watchpoints, in arm order. For a front-end to render.
    pub fn watchpoints(&self) -> Vec<Watchpoint> {
        if !self.inner.attached {
            return Vec::new();
        }
        self.sets().watchpoints.clone()
    }

    /// Arm a data watchpoint over `[base, base + len)`. A zero length arms
    /// nothing. A no-op on a detached handle.
    pub fn arm_watch(&self, base: u64, len: u64, kind: WatchKind) {
        if len == 0 {
            return;
        }
        self.mutate(|s| {
            s.watchpoints.push(Watchpoint { base, len, kind });
            true
        });
    }

    /// Disarm every watchpoint based at `base`. Idempotent. A no-op on a
    /// detached handle.
    pub fn disarm_watch(&self, base: u64) {
        self.mutate(|s| {
            let before = s.watchpoints.len();
            s.watchpoints.retain(|w| w.base != base);
            s.watchpoints.len() != before
        });
    }

    /// Record that a watched access landed at `addr`. Called by the memory
    /// backend; drained by the run loop after the instruction completes.
    /// Overwrites any undrained hit — the run loop drains once per instruction,
    /// so at most one instruction's worth is ever pending.
    #[inline]
    pub fn note_watch_hit(&self, addr: u64, kind: WatchKind) {
        if !self.inner.attached {
            return;
        }
        self.inner.watch_kind.store(kind.as_u8(), Ordering::Relaxed);
        self.inner
            .watch_hit
            .store(addr.wrapping_add(1), Ordering::Relaxed);
    }

    /// Take the pending watched-access hit, clearing it. `None` when there is
    /// none — one relaxed load on the common path.
    #[inline]
    pub fn take_watch_hit(&self) -> Option<(u64, WatchKind)> {
        if !self.inner.attached || self.inner.watch_hit.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let raw = self.inner.watch_hit.swap(0, Ordering::Relaxed);
        if raw == 0 {
            return None;
        }
        let kind = WatchKind::from_u8(self.inner.watch_kind.swap(0, Ordering::Relaxed))?;
        Some((raw.wrapping_sub(1), kind))
    }

    // -- stop requests and the instruction-count breakpoint ------------------

    /// Ask the emulator to run, pause or single-step. A `store`, so the calling
    /// thread can never block on the emulator — the invariant the whole
    /// AppKit-main-thread split rests on. A no-op on a detached handle.
    pub fn request(&self, r: StopRequest) {
        if !self.inner.attached {
            return;
        }
        self.inner.stop_request.store(r.as_u8(), Ordering::Relaxed);
    }

    /// Peek at the outstanding request without consuming it.
    #[inline]
    pub fn pending_request(&self) -> StopRequest {
        if !self.inner.attached {
            return StopRequest::Run;
        }
        StopRequest::from_u8(self.inner.stop_request.load(Ordering::Relaxed))
    }

    /// Take the outstanding request, resetting it to [`StopRequest::Run`]. The
    /// run loop calls this at its stop point; a request is therefore honoured
    /// exactly once.
    #[inline]
    pub fn take_request(&self) -> StopRequest {
        if !self.inner.attached {
            return StopRequest::Run;
        }
        StopRequest::from_u8(
            self.inner
                .stop_request
                .swap(StopRequest::Run.as_u8(), Ordering::Relaxed),
        )
    }

    /// Stop when exactly `steps` instructions have retired, or clear it with
    /// `None`.
    ///
    /// This is the most useful of the three breakpoint kinds for this project:
    /// combined with the deterministic virtual clock it means "re-run and stop
    /// N instructions before the fault", and it needs no JIT change at all —
    /// it is one more term in the run loop's existing `min`-reduction over
    /// instruction-denominated deadlines. A no-op on a detached handle.
    pub fn set_break_at_step(&self, steps: Option<u64>) {
        if !self.inner.attached {
            return;
        }
        self.inner
            .break_at_step
            .store(steps.unwrap_or(BREAK_AT_STEP_DISABLED), Ordering::Relaxed);
    }

    /// The armed instruction count, or [`BREAK_AT_STEP_DISABLED`] when none.
    /// Safe to fold straight into a `min` over deadlines.
    #[inline]
    pub fn break_at_step(&self) -> u64 {
        if !self.inner.attached {
            return BREAK_AT_STEP_DISABLED;
        }
        self.inner.break_at_step.load(Ordering::Relaxed)
    }

    // -- internals ----------------------------------------------------------

    /// Lock the authoritative sets. Poisoning is recovered rather than
    /// propagated: a panic while holding this lock leaves the sets structurally
    /// intact (they are two `Vec`s of plain data), and a debugger that refuses
    /// to answer because an unrelated thread panicked would be worse than one
    /// that answers from the last consistent state.
    fn sets(&self) -> std::sync::MutexGuard<'_, Sets> {
        self.inner.sets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply `f` to the sets; if it reports a change, rebuild both Bloom filters
    /// and bump the generation — all while holding the lock, so a consumer that
    /// sees a filter bit and then takes the lock cannot observe a stale set.
    fn mutate(&self, f: impl FnOnce(&mut Sets) -> bool) {
        if !self.inner.attached {
            return;
        }
        let mut sets = self.sets();
        if !f(&mut sets) {
            return;
        }
        let bp = sets.breakpoints.iter().fold(0u64, |acc, &a| acc | bloom_bits(a));
        let wp = sets.watchpoints.iter().fold(0u64, |acc, w| acc | watch_bits(w));
        self.inner.bp_filter.store(bp, Ordering::Release);
        self.inner.wp_filter.store(wp, Ordering::Release);
        self.inner.generation.fetch_add(1, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// The Bloom filter
// ---------------------------------------------------------------------------

/// SplitMix64's finalizer — a full 64-bit avalanche, so two disjoint slices of
/// the result are near-independent hash positions.
#[inline]
const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// The two filter bits a key claims. Arming ORs these in; a probe requires
/// **both** present, so a miss proves the key was never armed.
#[inline]
const fn bloom_bits(key: u64) -> u64 {
    let h = mix64(key);
    (1u64 << (h & 63)) | (1u64 << ((h >> 32) & 63))
}

/// The filter bits an armed watchpoint claims: one key per covered page, or a
/// saturated filter if it covers too many to enumerate cheaply.
fn watch_bits(w: &Watchpoint) -> u64 {
    let first = w.base >> WATCH_PAGE_SHIFT;
    let last = w.base.saturating_add(w.len - 1) >> WATCH_PAGE_SHIFT;
    if last - first >= WATCH_FILTER_MAX_PAGES {
        return u64::MAX;
    }
    (first..=last).fold(0u64, |acc, p| acc | bloom_bits(p))
}

/// Could an access of `len` bytes at `addr` touch a watched page? A `false`
/// here is proof it could not.
#[inline]
fn access_may_hit(filter: u64, addr: u64, len: u64) -> bool {
    let first = addr >> WATCH_PAGE_SHIFT;
    let last = addr.saturating_add(len - 1) >> WATCH_PAGE_SHIFT;
    if last - first >= ACCESS_PROBE_MAX_PAGES {
        return true;
    }
    (first..=last).any(|p| {
        let bits = bloom_bits(p);
        filter & bits == bits
    })
}

// ---------------------------------------------------------------------------
// TraceSink — the one new injectable trait
// ---------------------------------------------------------------------------

/// Which system-service table a syscall was dispatched through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallTable {
    /// The `Nt*` table serviced by ntdll's unix side.
    Ntdll,
    /// The `NtUser*` / `NtGdi*` table serviced by win32k.
    Win32k,
}

/// One tap for everything the guest asks the host to do.
///
/// Implemented **outside** the domain (`exemu-cli` writes stderr; a control app
/// forwards to a channel); `exemu-os` only calls it. Built to the shape of the
/// two existing injectable core traits — [`UserDriver`](crate::driver::UserDriver)
/// and [`AudioSink`](crate::audio::AudioSink) — `Send`-bounded with **every
/// method defaulted**, so adding a future tap point breaks no implementor and an
/// implementor that only wants the API log writes one method.
///
/// There are three distinct guest→host call paths in exemu, not one: import
/// thunks, the two SSDT branches, and `__wine_unix_call`. This trait is the
/// single vocabulary for all of them.
pub trait TraceSink: Send {
    /// Is anyone listening? Callers use this to skip formatting entirely — the
    /// point being that a `format!` hoisted out of a trace branch would run on
    /// every intercepted call and would be a real regression on the thunk path.
    /// [`NoTrace`] answers `false`.
    fn enabled(&self) -> bool {
        true
    }

    /// A Win32 import thunk was intercepted. `name` is the API's own name and
    /// `thunk` its address in the API region.
    fn win32_call(&mut self, _name: &str, _thunk: u64) {}

    /// A syscall was dispatched. `args` is the first four register arguments.
    fn syscall(&mut self, _table: SyscallTable, _index: u32, _args: &[u64; 4]) {}

    /// A syscall returned `status` (an `NTSTATUS`).
    fn syscall_return(&mut self, _table: SyscallTable, _index: u32, _status: u32) {}

    /// A `__wine_unix_call` crossed the PE/Unix boundary: `handle` is the
    /// unixlib handle, `code` the function ordinal, `args` the argument block.
    fn unix_call(&mut self, _handle: u64, _code: u32, _args: u64) {}

    /// Free-form diagnostic text from the emulator itself.
    fn note(&mut self, _text: &str) {}
}

/// The default sink: accepts and drops. Zero-sized, no allocation, and
/// [`enabled`](TraceSink::enabled) is `false` so callers format nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTrace;

impl TraceSink for NoTrace {
    #[inline]
    fn enabled(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// The DTOs
// ---------------------------------------------------------------------------

/// A loaded module, for the front-end's module view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// File name as the guest knows it, e.g. `ntdll.dll`.
    pub name: String,
    /// Image base in guest address space.
    pub base: u64,
    /// Mapped size in bytes.
    pub size: u64,
}

/// A guest thread, for the front-end's thread view.
///
/// Guest threads are cooperatively scheduled onto **one** host thread, so every
/// entry here is readable from the emulator thread with no locking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadInfo {
    /// Guest thread id.
    pub tid: u32,
    /// The kernel handle the guest holds for it, if any.
    pub handle: u64,
    /// Scheduler state, e.g. `"running"` / `"ready"` / `"waiting"`.
    pub state: &'static str,
    /// Saved instruction pointer (live value for the current thread).
    pub rip: u64,
    /// Saved stack pointer.
    pub rsp: u64,
    /// Base of this thread's TEB.
    pub teb_base: u64,
    /// Outstanding `SuspendThread` count.
    pub suspend_count: u32,
    /// Handles this thread is blocked on, if any.
    pub waiting_on: Vec<u64>,
    /// Is this the thread the run loop is currently executing?
    pub is_current: bool,
}

/// A kernel handle, for the front-end's handle view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleInfo {
    /// The handle value the guest holds.
    pub handle: u64,
    /// Object kind, e.g. `"file"` / `"event"` / `"key"` / `"socket"`.
    pub kind: &'static str,
    /// Kind-specific detail — a path, a name, a state.
    pub detail: String,
}

/// One disassembled instruction, as answered to
/// [`DebugCommand::Disassemble`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmLine {
    /// Guest address of the instruction.
    pub addr: u64,
    /// Its encoded bytes.
    pub bytes: Vec<u8>,
    /// Rendered text.
    pub text: String,
}

/// Everything a front-end needs to render one stop, as plain data.
///
/// Copied out on the emulator thread and sent over a channel: nothing here
/// borrows from the `Process`, which cannot cross threads at all.
#[derive(Debug, Clone)]
pub struct DebugSnapshot {
    /// Why the emulator stopped.
    pub stop: StopReason,
    /// Retired instructions — the run's clock, and the coordinate a
    /// [`StopReason::StepCount`] breakpoint is expressed in.
    pub steps: u64,
    /// The architectural register file at the stop.
    pub regs: CpuState,
    /// Guest bitness at the stop: 32 or 64. A WoW64 guest changes mode.
    pub bits: u8,
    /// Symbolic form of `regs.rip`, e.g. `"ntdll.dll+0x3f3c0"`.
    pub rip_note: String,
    /// Recent instruction (or, under the JIT, block-entry) addresses.
    pub trail: Vec<u64>,
    /// Unwound return addresses, innermost first.
    pub backtrace: Vec<u64>,
    /// Loaded modules.
    pub modules: Vec<ModuleInfo>,
    /// Guest threads.
    pub threads: Vec<ThreadInfo>,
    /// Open kernel handles.
    pub handles: Vec<HandleInfo>,
    /// Mapped guest memory. Reuses the domain's own [`Region`] rather than
    /// restating its four fields.
    pub regions: Vec<Region>,
}

/// What a front-end may ask of a running emulator.
///
/// **There is deliberately no write variant** — no `WriteMemory`, no
/// `SetRegister`. Read-only is what keeps a debugged run comparable against a
/// pinned one, and it is the first of the three barriers that stop a UI from
/// corrupting the run it is observing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommand {
    /// Stop at the next instruction boundary.
    Pause,
    /// Continue running.
    Resume,
    /// Execute exactly one instruction, then stop again.
    Step,
    /// Arm an instruction breakpoint.
    ArmBreak(u64),
    /// Disarm an instruction breakpoint.
    DisarmBreak(u64),
    /// Arm a data watchpoint.
    ArmWatch {
        /// First watched address.
        base: u64,
        /// Length in bytes.
        len: u64,
        /// Read, write or either.
        kind: WatchKind,
    },
    /// Disarm every watchpoint based at this address.
    DisarmWatch(u64),
    /// Stop after exactly this many retired instructions, or clear it.
    BreakAtStep(Option<u64>),
    /// Read guest memory through the permission-checked accessor. Answered with
    /// [`DebugEvent::Memory`].
    ReadMemory {
        /// First address to read.
        addr: u64,
        /// Number of bytes.
        len: u64,
    },
    /// Disassemble `count` instructions starting at `addr`. Answered with
    /// [`DebugEvent::Disassembly`].
    Disassemble {
        /// Where to start decoding.
        addr: u64,
        /// How many instructions.
        count: u32,
    },
    /// Detach: disarm everything and run to completion without a debugger.
    Detach,
    /// Abandon the run.
    Kill,
}

/// What a running emulator tells a front-end.
///
/// Not `PartialEq`: it carries a [`DebugSnapshot`], and a register file is not
/// a thing to compare structurally.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// The emulator stopped and is parked. Boxed because a snapshot carries a
    /// full register file and would otherwise dominate the enum's size.
    Stopped(Box<DebugSnapshot>),
    /// The emulator resumed.
    Resumed,
    /// Answer to [`DebugCommand::ReadMemory`]. `bytes` may be shorter than the
    /// request if the range ran out of mapped, readable memory.
    Memory {
        /// The address the read started at.
        addr: u64,
        /// The bytes read — a copy; the front-end never sees guest memory.
        bytes: Vec<u8>,
    },
    /// Answer to [`DebugCommand::Disassemble`].
    Disassembly {
        /// The address decoding started at.
        addr: u64,
        /// One entry per decoded instruction.
        lines: Vec<DisasmLine>,
    },
    /// The guest exited.
    Exited {
        /// Guest exit code.
        code: i32,
        /// Retired instructions at exit.
        steps: u64,
    },
    /// A command could not be served. Not fatal.
    Error(String),
}

/// The emulator-thread half of a debug session.
///
/// All three members are `Send`, which is the point: a `Process` is **not**
/// `Send` (the OS layer holds non-`Send` GUI and spawner boxes), so the
/// emulator is built inside its own thread and only these cross.
pub struct DebugSession {
    /// The shared control handle. Also cloned into the interpreter, the JIT and
    /// the memory backend.
    pub control: DebugControl,
    /// Commands from the front-end. The emulator's **only** blocking wait is a
    /// `recv` on this, taken while holding no lock.
    pub commands: Receiver<DebugCommand>,
    /// Events to the front-end.
    pub events: Sender<DebugEvent>,
}

/// The front-end half of a debug session.
///
/// A front-end must never block on the emulator: it only ever `store`s through
/// [`DebugControl`] and `try_recv`s [`events`](Self::events). That discipline,
/// not a lock ordering, is what makes the AppKit-main-thread split
/// deadlock-free.
pub struct DebugFrontEnd {
    /// The shared control handle.
    pub control: DebugControl,
    /// Commands to the emulator.
    pub commands: Sender<DebugCommand>,
    /// Events from the emulator. Drain with `try_recv`.
    pub events: Receiver<DebugEvent>,
}

impl DebugSession {
    /// Build both halves of a session over a shared `control`, wiring the two
    /// channel pairs so neither side can be constructed with the wrong
    /// direction.
    pub fn pair(control: DebugControl) -> (DebugSession, DebugFrontEnd) {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (evt_tx, evt_rx) = std::sync::mpsc::channel();
        (
            DebugSession { control: control.clone(), commands: cmd_rx, events: evt_tx },
            DebugFrontEnd { control, commands: cmd_tx, events: evt_rx },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic 64-bit PRNG so the sweeps below are reproducible without
    /// pulling a dependency into the dependency-free domain crate.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            mix64(self.0)
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn the_handle_crosses_threads() {
        assert_send_sync::<DebugControl>();
    }

    // -- the detached (default) path ----------------------------------------

    #[test]
    fn detached_is_inert_from_every_accessor() {
        let d = DebugControl::default();
        assert!(!d.is_attached());

        // Every mutator, on a handle that cannot honour them.
        d.arm_break(0x1000);
        d.arm_watch(0x2000, 8, WatchKind::ReadWrite);
        d.set_break_at_step(Some(42));
        d.request(StopRequest::Pause);
        d.note_watch_hit(0x2000, WatchKind::Write);

        assert!(!d.is_break(0x1000), "detached: no breakpoint can be armed");
        assert!(!d.any_breakpoints());
        assert_eq!(d.next_break_at_or_after(0), None);
        assert_eq!(d.breakpoints(), Vec::<u64>::new());
        assert!(!d.is_watched(0x2000, 8, WatchKind::Write));
        assert!(!d.any_watchpoints());
        assert_eq!(d.watchpoints(), Vec::new());
        assert_eq!(d.break_at_step(), BREAK_AT_STEP_DISABLED);
        assert_eq!(d.pending_request(), StopRequest::Run);
        assert_eq!(d.take_request(), StopRequest::Run);
        assert_eq!(d.take_watch_hit(), None);
        assert_eq!(d.generation(), 0, "an inert handle never invalidates a cache");
    }

    #[test]
    fn the_disabled_check_is_side_effect_free() {
        // The claim the whole design rests on: asking a detached handle
        // anything, any number of times, changes nothing an emulator can see.
        let d = DebugControl::detached();
        let before = format!("{d:?}");
        for i in 0..10_000u64 {
            assert!(!d.is_break(i.wrapping_mul(0x1f)));
            assert!(!d.is_watched(i, 8, WatchKind::Read));
            assert!(!d.any_watchpoints());
            assert!(!d.any_breakpoints());
            assert_eq!(d.break_at_step(), BREAK_AT_STEP_DISABLED);
            assert_eq!(d.take_request(), StopRequest::Run);
            assert_eq!(d.take_watch_hit(), None);
        }
        assert_eq!(d.generation(), 0);
        assert_eq!(format!("{d:?}"), before, "no observable state moved");
    }

    #[test]
    fn an_attached_but_unarmed_handle_answers_no_to_everything() {
        // The second free path: attach without arming, which is what the
        // "attach is free" corpus entry runs.
        let d = DebugControl::attached();
        assert!(d.is_attached());
        assert!(!d.any_breakpoints());
        assert!(!d.any_watchpoints());
        assert_eq!(d.generation(), 0);
        for i in 0..10_000u64 {
            assert!(!d.is_break(i.wrapping_mul(0x1f)));
            assert!(!d.is_watched(i, 8, WatchKind::Write));
        }
        assert_eq!(d.generation(), 0, "checking never arms anything");
    }

    // -- arm / disarm --------------------------------------------------------

    #[test]
    fn arming_and_disarming_a_breakpoint_round_trips() {
        let d = DebugControl::attached();
        d.arm_break(0x1400);
        assert!(d.is_break(0x1400));
        assert!(d.any_breakpoints());
        assert_eq!(d.breakpoints(), vec![0x1400]);
        assert!(!d.is_break(0x1401));

        d.disarm_break(0x1400);
        assert!(!d.is_break(0x1400));
        assert!(!d.any_breakpoints(), "the filter is rebuilt, not merely cleared");
        assert_eq!(d.breakpoints(), Vec::<u64>::new());
    }

    #[test]
    fn disarming_one_breakpoint_keeps_the_others_visible() {
        // A filter that cleared bits instead of rebuilding would lose these —
        // and a lost breakpoint is the failure mode that makes a debugger lie.
        let d = DebugControl::attached();
        let armed: Vec<u64> = (0..24).map(|i| 0x4000 + i * 0x37).collect();
        for &a in &armed {
            d.arm_break(a);
        }
        for (i, &a) in armed.iter().enumerate() {
            d.disarm_break(a);
            for &b in &armed[i + 1..] {
                assert!(d.is_break(b), "{b:#x} survived {a:#x} being disarmed");
            }
            assert!(!d.is_break(a));
        }
        assert!(!d.any_breakpoints());
    }

    #[test]
    fn arming_is_idempotent_and_the_set_stays_sorted() {
        let d = DebugControl::attached();
        for a in [0x30, 0x10, 0x20, 0x10, 0x30] {
            d.arm_break(a);
        }
        assert_eq!(d.breakpoints(), vec![0x10, 0x20, 0x30]);
        let g = d.generation();
        d.arm_break(0x20); // already armed
        d.disarm_break(0x99); // never armed
        assert_eq!(d.generation(), g, "a no-op arm must not invalidate the code cache");
    }

    #[test]
    fn the_generation_strictly_increases_across_every_real_change() {
        let d = DebugControl::attached();
        let mut seen = vec![d.generation()];
        for i in 0..16u64 {
            d.arm_break(0x8000 + i * 4);
            seen.push(d.generation());
        }
        d.arm_watch(0x9000, 16, WatchKind::Write);
        seen.push(d.generation());
        d.disarm_watch(0x9000);
        seen.push(d.generation());
        for i in 0..16u64 {
            d.disarm_break(0x8000 + i * 4);
            seen.push(d.generation());
        }
        assert!(
            seen.windows(2).all(|w| w[1] > w[0]),
            "generations must be strictly increasing: {seen:?}"
        );
    }

    #[test]
    fn next_break_at_or_after_is_the_jits_per_block_query() {
        let d = DebugControl::attached();
        assert_eq!(d.next_break_at_or_after(0), None, "unarmed: nothing to stop before");
        for a in [0x1000, 0x1004, 0x2000] {
            d.arm_break(a);
        }
        assert_eq!(d.next_break_at_or_after(0), Some(0x1000));
        assert_eq!(d.next_break_at_or_after(0x1000), Some(0x1000), "inclusive");
        assert_eq!(d.next_break_at_or_after(0x1001), Some(0x1004));
        assert_eq!(d.next_break_at_or_after(0x1005), Some(0x2000));
        assert_eq!(d.next_break_at_or_after(0x2001), None);
    }

    // -- the Bloom filter ----------------------------------------------------

    #[test]
    fn the_bloom_filter_has_no_false_negatives() {
        // A false positive costs a mutex; a false negative is a missed
        // breakpoint. Sweep 10k random sets and assert every armed address is
        // still reported armed.
        let mut rng = Rng(0x5eed_1234_9abc_def0);
        for round in 0..10_000u32 {
            let d = DebugControl::attached();
            let n = 1 + (rng.next() % 12);
            let mut armed: Vec<u64> = (0..n).map(|_| rng.next()).collect();
            armed.sort_unstable();
            armed.dedup();
            for &a in &armed {
                d.arm_break(a);
            }
            for &a in &armed {
                assert!(d.is_break(a), "round {round}: lost breakpoint {a:#x}");
                assert_eq!(d.next_break_at_or_after(a), Some(a));
            }
            // And after removing half of them, the rest are still found — the
            // case a filter that cleared bits instead of rebuilding would fail.
            let gone: Vec<u64> = armed.iter().copied().step_by(2).collect();
            let kept: Vec<u64> = armed.iter().copied().skip(1).step_by(2).collect();
            for &a in &gone {
                d.disarm_break(a);
            }
            for &a in &kept {
                assert!(d.is_break(a), "round {round}: lost survivor {a:#x}");
            }
            assert_eq!(d.breakpoints(), kept);
        }
    }

    #[test]
    fn the_watch_filter_has_no_false_negatives() {
        let mut rng = Rng(0xfeed_0f00_1122_3344);
        for round in 0..10_000u32 {
            let d = DebugControl::attached();
            let n = 1 + (rng.next() % 6);
            let mut armed = Vec::new();
            for _ in 0..n {
                // Keep the base clear of the u64 ceiling so base+len cannot wrap.
                let base = rng.next() >> 1;
                let len = 1 + (rng.next() % 4096);
                d.arm_watch(base, len, WatchKind::ReadWrite);
                armed.push((base, len));
            }
            for &(base, len) in &armed {
                assert!(
                    d.is_watched(base, 1, WatchKind::Read),
                    "round {round}: lost watch at {base:#x}"
                );
                assert!(
                    d.is_watched(base + len - 1, 1, WatchKind::Write),
                    "round {round}: lost the last byte of the watch at {base:#x}"
                );
            }
        }
    }

    #[test]
    fn a_watchpoint_spanning_more_pages_than_the_filter_holds_still_fires() {
        // The saturation path: too many pages to enumerate, so the filter goes
        // all-ones — slower, never wrong.
        let d = DebugControl::attached();
        let len = (WATCH_FILTER_MAX_PAGES + 8) << WATCH_PAGE_SHIFT;
        d.arm_watch(0x1_0000_0000, len, WatchKind::Write);
        assert!(d.any_watchpoints());
        assert!(d.is_watched(0x1_0000_0000, 4, WatchKind::Write));
        assert!(d.is_watched(0x1_0000_0000 + len - 1, 1, WatchKind::Write));
        assert!(!d.is_watched(0x1_0000_0000 + len, 1, WatchKind::Write));
    }

    // -- watchpoint semantics ------------------------------------------------

    #[test]
    fn a_watchpoint_matches_by_overlap_and_by_kind() {
        let d = DebugControl::attached();
        d.arm_watch(0x2000, 8, WatchKind::Write);

        assert!(d.is_watched(0x2000, 1, WatchKind::Write));
        assert!(d.is_watched(0x2007, 1, WatchKind::Write));
        assert!(d.is_watched(0x1ffc, 8, WatchKind::Write), "a straddling access hits");
        assert!(!d.is_watched(0x2008, 1, WatchKind::Write), "one past the end misses");
        assert!(!d.is_watched(0x1fff, 1, WatchKind::Write), "one before the start misses");
        assert!(!d.is_watched(0x2000, 1, WatchKind::Read), "a write watch ignores reads");
        assert!(!d.is_watched(0x2000, 0, WatchKind::Write), "a zero-length access hits nothing");

        d.arm_watch(0x3000, 4, WatchKind::Read);
        assert!(d.is_watched(0x3000, 4, WatchKind::Read));
        assert!(!d.is_watched(0x3000, 4, WatchKind::Write));

        d.arm_watch(0x4000, 4, WatchKind::ReadWrite);
        assert!(d.is_watched(0x4000, 4, WatchKind::Read));
        assert!(d.is_watched(0x4000, 4, WatchKind::Write));
    }

    #[test]
    fn arming_a_zero_length_watchpoint_arms_nothing() {
        let d = DebugControl::attached();
        d.arm_watch(0x2000, 0, WatchKind::ReadWrite);
        assert!(!d.any_watchpoints());
        assert_eq!(d.generation(), 0);
    }

    #[test]
    fn disarming_a_watchpoint_removes_every_range_at_that_base() {
        let d = DebugControl::attached();
        d.arm_watch(0x2000, 4, WatchKind::Read);
        d.arm_watch(0x2000, 8, WatchKind::Write);
        d.arm_watch(0x5000, 4, WatchKind::Write);
        assert_eq!(d.watchpoints().len(), 3);

        d.disarm_watch(0x2000);
        assert_eq!(d.watchpoints(), vec![Watchpoint { base: 0x5000, len: 4, kind: WatchKind::Write }]);
        assert!(!d.is_watched(0x2000, 8, WatchKind::Write));
        assert!(d.is_watched(0x5000, 1, WatchKind::Write));
    }

    #[test]
    fn a_watch_hit_is_recorded_once_and_drained_once() {
        let d = DebugControl::attached();
        assert_eq!(d.take_watch_hit(), None);
        d.note_watch_hit(0xdead_beef, WatchKind::Write);
        assert_eq!(d.take_watch_hit(), Some((0xdead_beef, WatchKind::Write)));
        assert_eq!(d.take_watch_hit(), None, "draining clears it");

        // Address 0 is a real address, not the sentinel.
        d.note_watch_hit(0, WatchKind::Read);
        assert_eq!(d.take_watch_hit(), Some((0, WatchKind::Read)));
    }

    #[test]
    fn watch_kind_covers_is_a_bit_test() {
        use WatchKind::{Read, ReadWrite, Write};
        assert!(Read.covers(Read));
        assert!(!Read.covers(Write));
        assert!(Write.covers(Write));
        assert!(!Write.covers(Read));
        assert!(ReadWrite.covers(Read));
        assert!(ReadWrite.covers(Write));
        assert!(ReadWrite.covers(ReadWrite));
    }

    // -- stop requests and the instruction-count breakpoint ------------------

    #[test]
    fn a_stop_request_is_honoured_exactly_once() {
        let d = DebugControl::attached();
        assert_eq!(d.pending_request(), StopRequest::Run);
        d.request(StopRequest::Pause);
        assert_eq!(d.pending_request(), StopRequest::Pause, "peeking does not consume");
        assert_eq!(d.take_request(), StopRequest::Pause);
        assert_eq!(d.take_request(), StopRequest::Run, "taking resets to Run");

        d.request(StopRequest::Step);
        assert_eq!(d.take_request(), StopRequest::Step);
        assert_eq!(d.pending_request(), StopRequest::Run);
    }

    #[test]
    fn the_instruction_count_breakpoint_folds_into_a_min_reduction() {
        // How a consumer uses it: one more term in the run loop's existing
        // `min` over instruction-denominated deadlines, no branch.
        let deadline = |d: &DebugControl, steps: u64, chain_cap: u64| {
            chain_cap.min(d.break_at_step().saturating_sub(steps))
        };
        let d = DebugControl::attached();
        assert_eq!(d.break_at_step(), BREAK_AT_STEP_DISABLED);
        assert_eq!(deadline(&d, 1_000, 65_536), 65_536, "disabled loses every min");

        d.set_break_at_step(Some(92_865_709));
        assert_eq!(d.break_at_step(), 92_865_709);
        assert_eq!(deadline(&d, 92_864_709, 65_536), 1_000, "the run stops on the count");
        assert_eq!(deadline(&d, 1_000, 65_536), 65_536, "…and not before");
        assert_eq!(deadline(&d, 92_865_709, 65_536), 0, "already there");

        d.set_break_at_step(None);
        assert_eq!(d.break_at_step(), BREAK_AT_STEP_DISABLED);
        assert_eq!(deadline(&d, 1_000, 65_536), 65_536);

        // A detached handle must fold into the same reduction harmlessly.
        assert_eq!(deadline(&DebugControl::detached(), 1_000, 65_536), 65_536);
    }

    // -- sharing -------------------------------------------------------------

    #[test]
    fn a_clone_shares_one_debug_state() {
        let front = DebugControl::attached();
        let emu = front.clone();
        front.arm_break(0x1234);
        front.request(StopRequest::Pause);
        front.set_break_at_step(Some(7));
        assert!(emu.is_break(0x1234), "the run loop sees what the front-end armed");
        assert_eq!(emu.take_request(), StopRequest::Pause);
        assert_eq!(emu.break_at_step(), 7);
        // …and back the other way: the emulator's drain is visible to the clone.
        emu.note_watch_hit(0x55, WatchKind::Read);
        assert_eq!(front.take_watch_hit(), Some((0x55, WatchKind::Read)));
    }

    #[test]
    fn arming_from_another_thread_is_visible_to_the_emulator() {
        let emu = DebugControl::attached();
        let front = emu.clone();
        let armer = std::thread::spawn(move || {
            for i in 0..256u64 {
                front.arm_break(0x10_0000 + i * 16);
            }
            front.request(StopRequest::Pause);
            front.generation()
        });
        let gen_after = armer.join().expect("the arming thread must not panic");
        assert_eq!(emu.generation(), gen_after);
        for i in 0..256u64 {
            assert!(emu.is_break(0x10_0000 + i * 16));
        }
        assert_eq!(emu.take_request(), StopRequest::Pause);
    }

    // -- the trace sink ------------------------------------------------------

    #[test]
    fn no_trace_accepts_everything_and_reports_disabled() {
        let mut s = NoTrace;
        assert!(!s.enabled(), "callers must be able to skip formatting entirely");
        s.win32_call("CreateFileW", 0x7000_0010);
        s.syscall(SyscallTable::Ntdll, 0x18, &[1, 2, 3, 4]);
        s.syscall_return(SyscallTable::Ntdll, 0x18, 0);
        s.syscall(SyscallTable::Win32k, 0x1000, &[0; 4]);
        s.unix_call(0x1000, 7, 0x2000);
        s.note("nothing happens");
    }

    #[test]
    fn a_trace_sink_may_override_a_single_method() {
        // The defaulted-methods property: an implementor that only wants the
        // API log writes exactly one method and still satisfies the trait.
        #[derive(Default)]
        struct ApiLog(Vec<String>);
        impl TraceSink for ApiLog {
            fn win32_call(&mut self, name: &str, _thunk: u64) {
                self.0.push(name.to_string());
            }
        }
        let mut sink: Box<dyn TraceSink> = Box::new(ApiLog::default());
        assert!(sink.enabled());
        sink.win32_call("GetProcAddress", 0);
        sink.syscall(SyscallTable::Ntdll, 1, &[0; 4]); // defaulted: drops
        sink.note("still fine");
    }

    // -- the protocol --------------------------------------------------------

    #[test]
    fn a_session_pairs_two_send_halves_over_one_control() {
        let (session, front) = DebugSession::pair(DebugControl::attached());
        assert!(session.control.is_attached() && front.control.is_attached());

        front.commands.send(DebugCommand::Pause).expect("front-end → emulator");
        front.control.arm_break(0x2000);
        assert_eq!(session.commands.try_recv(), Ok(DebugCommand::Pause));
        assert!(session.control.is_break(0x2000), "one control, two holders");

        session
            .events
            .send(DebugEvent::Memory { addr: 0x2000, bytes: vec![0x90; 4] })
            .expect("emulator → front-end");
        match front.events.try_recv() {
            Ok(DebugEvent::Memory { addr, bytes }) => {
                assert_eq!((addr, bytes), (0x2000, vec![0x90; 4]));
            }
            other => panic!("expected the memory copy back, got {other:?}"),
        }

        // Both halves must be movable to another thread — the only shape the
        // type system permits, since a Process cannot cross threads.
        let t = std::thread::spawn(move || session.control.take_request());
        assert_eq!(t.join().expect("session half is Send"), StopRequest::Run);
    }

    #[test]
    fn the_command_protocol_is_read_only() {
        // A structural reminder rather than a proof: this match is exhaustive,
        // so a future write variant cannot be added without editing this test.
        let all = [
            DebugCommand::Pause,
            DebugCommand::Resume,
            DebugCommand::Step,
            DebugCommand::ArmBreak(0),
            DebugCommand::DisarmBreak(0),
            DebugCommand::ArmWatch { base: 0, len: 1, kind: WatchKind::Write },
            DebugCommand::DisarmWatch(0),
            DebugCommand::BreakAtStep(None),
            DebugCommand::ReadMemory { addr: 0, len: 16 },
            DebugCommand::Disassemble { addr: 0, count: 4 },
            DebugCommand::Detach,
            DebugCommand::Kill,
        ];
        for c in &all {
            let writes_guest_state = match c {
                DebugCommand::Pause
                | DebugCommand::Resume
                | DebugCommand::Step
                | DebugCommand::ArmBreak(_)
                | DebugCommand::DisarmBreak(_)
                | DebugCommand::ArmWatch { .. }
                | DebugCommand::DisarmWatch(_)
                | DebugCommand::BreakAtStep(_)
                | DebugCommand::ReadMemory { .. }
                | DebugCommand::Disassemble { .. }
                | DebugCommand::Detach
                | DebugCommand::Kill => false,
            };
            assert!(!writes_guest_state, "{c:?} would give a UI a write path");
        }
    }
}
