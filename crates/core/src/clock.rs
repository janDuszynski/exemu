//! The guest clock — one choke point for every notion of "now" a guest can see
//! (roadmap W9.6 follow-up, prerequisite for the W8.7 JIT differential).
//!
//! # Why this exists
//!
//! exemu services the **real host clock**, so a guest that compares two
//! timestamps branches on how fast the host happened to be, and the same binary
//! executes a slightly different number of instructions on every run. Measured
//! through the W9.6 corpus runner (private sandbox, bare `argv[0]`, so the two
//! *other* known sources of variation are already removed): `Firefox
//! Installer.exe` repeats to ±1 instruction and `SteamSetup.exe` wandered by 189
//! instructions across two full passes. That is why the corpus tolerances are
//! **noise floors** rather than change budgets — and it is fatal for the W8.7
//! plan of diffing a JIT against the interpreter instruction-for-instruction,
//! which needs exact replay.
//!
//! # The model
//!
//! When [`GuestClock::virtualized`] is selected, time is **derived from the
//! guest's own instruction stream** and nothing else:
//!
//! ```text
//!   virtual 100-ns ticks  =  instructions retired  +  sleep credit
//! ```
//!
//! * **One retired instruction buys one 100-ns tick** — a nominal
//!   [`VIRTUAL_INSTRUCTIONS_PER_SECOND`] = 10,000,000 instructions/second
//!   machine. Three things recommend that rate:
//!   1. It is what exemu actually runs at. A release build executes 7-Zip's
//!      496,505,572 instructions in roughly a minute — order 10 MIPS. So a
//!      guest's *virtual* seconds elapse at about the rate its *real* seconds
//!      used to, and switching the clock on does not suddenly present the guest
//!      with a machine 100× faster or slower than the one it was seeing.
//!   2. It makes the unit conversions exact and inspectable: the performance
//!      counter already runs at [`QPC_FREQUENCY`] = 10 MHz, so **the virtual
//!      performance counter *is* the instruction count**, and a `FILETIME` (also
//!      100-ns units) is just the epoch plus the instruction count.
//!   3. A poll loop still terminates in a sane number of instructions: a guest
//!      spinning on `GetTickCount()` for 100 ms escapes after 10^6 instructions,
//!      not 10^8.
//! * **A blocking call is credited the time it asked to block for.** `Sleep(ms)`
//!   is a cooperative yield in exemu — it costs one instruction, not `ms` of
//!   anything — so without this a `while (GetTickCount() - t0 < 5000) Sleep(10);`
//!   loop would have to grind out 5×10^7 instructions to escape. Crediting the
//!   requested interval (see [`GuestClock::credit_ms`]) makes such a loop
//!   terminate in as many iterations as a real machine would take, and it stays
//!   deterministic because the interval comes from the guest's own argument.
//!   Both terms are therefore pure functions of the guest instruction stream,
//!   which is the property the whole exercise is for.
//! * **The wall clock is a fixed epoch plus that monotonic time**
//!   ([`VIRTUAL_EPOCH_FILETIME`], 2026-01-01T00:00:00Z). A guest that stamps a
//!   file, seeds a temp name or formats a date sees the same value every run.
//!
//! The default is [`GuestClock::host`], which keeps the existing behaviour
//! byte-for-byte: every accessor returns `None` and the caller falls back to the
//! host clock it used before. That fallback lives in the outer crates on purpose
//! — this crate performs no I/O, so the *deterministic* clock is pure arithmetic
//! here and the *host* clock stays where it always was.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The performance-counter frequency exemu reports: 10 MHz, so one tick is
/// 100 ns and the counter is directly convertible to/from `FILETIME` units.
/// Mirrored by `exemu-os`'s `QueryPerformanceFrequency`.
pub const QPC_FREQUENCY: u64 = 10_000_000;

/// Nominal instruction rate of the virtualised machine: 10 million retired
/// instructions per second, i.e. exactly one [`QPC_FREQUENCY`] tick (100 ns)
/// per instruction. See the module docs for why this rate.
pub const VIRTUAL_INSTRUCTIONS_PER_SECOND: u64 = QPC_FREQUENCY;

/// Time-stamp-counter ticks per 100-ns tick — a 1 GHz `RDTSC`. Keeping the TSC
/// a fixed multiple of the performance counter means a guest that calibrates one
/// against the other gets a self-consistent answer instead of two unrelated
/// ramps.
pub const TSC_TICKS_PER_100NS: u64 = 100;

/// The virtual wall-clock epoch as a Windows `FILETIME` (100-ns ticks since
/// 1601-01-01): **2026-01-01T00:00:00Z**.
///
/// `(11_644_473_600 + 1_767_225_600) * 10_000_000` — the 1601→1970 offset plus
/// the Unix time of 2026-01-01, in 100-ns units.
pub const VIRTUAL_EPOCH_FILETIME: u64 = 134_116_992_000_000_000;

/// `INFINITE` — the `Sleep`/wait argument meaning "no timeout". Never credited
/// as elapsed time: it does not name an interval.
const INFINITE_MS: u64 = 0xFFFF_FFFF;

/// Upper bound on the virtual time a single blocking call may be credited: one
/// minute. A guest that asks to sleep for an hour would otherwise skip the
/// wall clock an hour forward in one instruction; clamping keeps a wild argument
/// from turning into a wild timestamp while leaving every realistic
/// `Sleep`/`WaitForSingleObject` timeout credited in full.
const MAX_CREDIT_MS: u64 = 60_000;

/// A handle to the process's clock. Cheap to clone — every holder (the
/// interpreter for `RDTSC`, the OS layer for the time APIs and syscalls, the run
/// loop for the `KUSER_SHARED_DATA` refresh) shares one counter.
#[derive(Clone)]
pub struct GuestClock {
    inner: Arc<Inner>,
}

struct Inner {
    /// Selected mode. `false` (the default) means every accessor returns `None`
    /// and callers use the host clock, exactly as before this type existed.
    virtualized: bool,
    /// Instructions retired since the process started. Only advanced in
    /// virtualised mode, so the default path pays a single predictable branch.
    instret: AtomicU64,
    /// Extra 100-ns ticks granted to blocking calls (see [`GuestClock::credit_ms`]).
    credit_100ns: AtomicU64,
}

impl Default for GuestClock {
    fn default() -> Self {
        GuestClock::host()
    }
}

impl std::fmt::Debug for GuestClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestClock")
            .field("virtualized", &self.inner.virtualized)
            .field("instret", &self.instret())
            .field("credit_100ns", &self.sleep_credit_100ns())
            .finish()
    }
}

impl GuestClock {
    /// The default: guest time comes from the real host clock. Every accessor
    /// returns `None`; callers keep their existing host-clock code path.
    pub fn host() -> GuestClock {
        GuestClock {
            inner: Arc::new(Inner {
                virtualized: false,
                instret: AtomicU64::new(0),
                credit_100ns: AtomicU64::new(0),
            }),
        }
    }

    /// The deterministic clock: guest time is a pure function of the guest's own
    /// instruction stream (see the module docs).
    pub fn virtualized() -> GuestClock {
        GuestClock {
            inner: Arc::new(Inner {
                virtualized: true,
                instret: AtomicU64::new(0),
                credit_100ns: AtomicU64::new(0),
            }),
        }
    }

    /// Select a mode by flag — `virtualized(true)` / `host(false)`.
    pub fn new(virtualized: bool) -> GuestClock {
        if virtualized {
            GuestClock::virtualized()
        } else {
            GuestClock::host()
        }
    }

    /// Is guest time deterministic (rather than host-backed)?
    #[inline]
    pub fn is_virtual(&self) -> bool {
        self.inner.virtualized
    }

    /// Account one retired instruction. Called from the interpreter's step, so
    /// it is the hottest path in the emulator: in host mode it is one
    /// perfectly-predicted branch, and in virtual mode a relaxed load/store pair
    /// (never a read-modify-write — only the interpreter thread advances it).
    #[inline]
    pub fn retire_one(&self) {
        if !self.inner.virtualized {
            return;
        }
        let n = self.inner.instret.load(Ordering::Relaxed).wrapping_add(1);
        self.inner.instret.store(n, Ordering::Relaxed);
    }

    /// Instructions retired so far (always 0 in host mode — nothing counts them).
    #[inline]
    pub fn instret(&self) -> u64 {
        self.inner.instret.load(Ordering::Relaxed)
    }

    /// Virtual time credited to blocking calls so far, in 100-ns ticks.
    pub fn sleep_credit_100ns(&self) -> u64 {
        self.inner.credit_100ns.load(Ordering::Relaxed)
    }

    /// Credit a blocking call that asked to wait `ms` milliseconds.
    ///
    /// `INFINITE` credits nothing (it names no interval), and a single call is
    /// clamped to [`MAX_CREDIT_MS`]. A no-op in host mode, where the host clock
    /// already advanced on its own.
    pub fn credit_ms(&self, ms: u64) {
        if !self.inner.virtualized || ms == 0 || ms == INFINITE_MS {
            return;
        }
        let ticks = ms.min(MAX_CREDIT_MS) * (QPC_FREQUENCY / 1_000);
        let n = self.inner.credit_100ns.load(Ordering::Relaxed).wrapping_add(ticks);
        self.inner.credit_100ns.store(n, Ordering::Relaxed);
    }

    /// Monotonic virtual time since the process started, in 100-ns ticks —
    /// i.e. the value `QueryPerformanceCounter` reports. `None` in host mode.
    #[inline]
    pub fn monotonic_100ns(&self) -> Option<u64> {
        if !self.inner.virtualized {
            return None;
        }
        Some(self.instret().wrapping_add(self.sleep_credit_100ns()))
    }

    /// Monotonic virtual time in milliseconds — i.e. `GetTickCount`. `None` in
    /// host mode.
    #[inline]
    pub fn tick_count_ms(&self) -> Option<u64> {
        self.monotonic_100ns().map(|t| t / (QPC_FREQUENCY / 1_000))
    }

    /// The virtual wall clock as a Windows `FILETIME` (100-ns ticks since
    /// 1601-01-01): a fixed epoch plus the monotonic time. `None` in host mode.
    #[inline]
    pub fn filetime(&self) -> Option<u64> {
        self.monotonic_100ns().map(|t| VIRTUAL_EPOCH_FILETIME.wrapping_add(t))
    }

    /// The virtual time-stamp counter backing `RDTSC`/`RDTSCP`: a fixed 1 GHz
    /// multiple of the monotonic time. Strictly increasing between any two reads
    /// because the `RDTSC` itself retires an instruction. `None` in host mode.
    #[inline]
    pub fn tsc(&self) -> Option<u64> {
        self.monotonic_100ns().map(|t| t.wrapping_mul(TSC_TICKS_PER_100NS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_mode_defers_everything_to_the_caller() {
        let c = GuestClock::default();
        assert!(!c.is_virtual());
        c.retire_one();
        c.credit_ms(1000);
        assert_eq!(c.instret(), 0, "host mode does not count instructions");
        assert_eq!(c.monotonic_100ns(), None);
        assert_eq!(c.filetime(), None);
        assert_eq!(c.tick_count_ms(), None);
        assert_eq!(c.tsc(), None);
    }

    #[test]
    fn one_instruction_is_one_hundred_nanoseconds() {
        let c = GuestClock::virtualized();
        for _ in 0..VIRTUAL_INSTRUCTIONS_PER_SECOND {
            c.retire_one();
        }
        assert_eq!(c.instret(), 10_000_000);
        // Exactly one second of virtual time, expressed three ways.
        assert_eq!(c.monotonic_100ns(), Some(10_000_000));
        assert_eq!(c.tick_count_ms(), Some(1_000));
        assert_eq!(c.filetime(), Some(VIRTUAL_EPOCH_FILETIME + 10_000_000));
    }

    #[test]
    fn the_performance_counter_is_the_instruction_count() {
        let c = GuestClock::virtualized();
        for n in 1..=1000u64 {
            c.retire_one();
            assert_eq!(c.monotonic_100ns(), Some(n));
        }
    }

    #[test]
    fn the_clock_is_a_pure_function_of_the_stream() {
        // Two clocks driven by the same sequence of events agree exactly — the
        // property that makes a run replayable.
        let (a, b) = (GuestClock::virtualized(), GuestClock::virtualized());
        for step in 0..5_000u64 {
            a.retire_one();
            b.retire_one();
            if step % 700 == 0 {
                a.credit_ms(15);
                b.credit_ms(15);
            }
        }
        assert_eq!(a.filetime(), b.filetime());
        assert_eq!(a.tsc(), b.tsc());
        assert_eq!(a.tick_count_ms(), b.tick_count_ms());
    }

    #[test]
    fn a_sleep_is_credited_the_interval_it_asked_for() {
        let c = GuestClock::virtualized();
        c.retire_one();
        c.credit_ms(10); // 10 ms == 100,000 ticks
        assert_eq!(c.sleep_credit_100ns(), 100_000);
        assert_eq!(c.tick_count_ms(), Some(10));
        // INFINITE names no interval, so it credits nothing…
        c.credit_ms(INFINITE_MS);
        assert_eq!(c.sleep_credit_100ns(), 100_000);
        // …and a wild interval is clamped rather than skipping the wall clock.
        c.credit_ms(24 * 60 * 60 * 1000);
        assert_eq!(c.sleep_credit_100ns(), 100_000 + MAX_CREDIT_MS * 10_000);
    }

    #[test]
    fn the_tsc_advances_between_any_two_reads() {
        let c = GuestClock::virtualized();
        c.retire_one();
        let first = c.tsc().unwrap();
        c.retire_one(); // the second RDTSC is itself an instruction
        let second = c.tsc().unwrap();
        assert!(second > first, "{second} must exceed {first}");
        assert_eq!(second - first, TSC_TICKS_PER_100NS, "1 GHz against a 10 MHz QPC");
    }

    #[test]
    fn the_epoch_is_the_start_of_2026() {
        // 2026-01-01T00:00:00Z: Unix 1_767_225_600, plus the 1601→1970 offset.
        const UNIX_2026: u64 = 1_767_225_600;
        const EPOCH_DIFF: u64 = 11_644_473_600;
        assert_eq!(VIRTUAL_EPOCH_FILETIME, (UNIX_2026 + EPOCH_DIFF) * QPC_FREQUENCY);
    }

    #[test]
    fn a_clone_shares_the_counter() {
        let c = GuestClock::virtualized();
        let d = c.clone();
        c.retire_one();
        assert_eq!(d.instret(), 1, "the interpreter and the OS layer see one clock");
    }
}
