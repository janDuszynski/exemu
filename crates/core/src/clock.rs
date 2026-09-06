use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const QPC_FREQUENCY: u64 = 10_000_000;

pub const VIRTUAL_INSTRUCTIONS_PER_SECOND: u64 = QPC_FREQUENCY;

pub const TSC_TICKS_PER_100NS: u64 = 100;

pub const VIRTUAL_EPOCH_FILETIME: u64 = 134_116_992_000_000_000;

const INFINITE_MS: u64 = 0xFFFF_FFFF;

const MAX_CREDIT_MS: u64 = 60_000;

#[derive(Clone)]
pub struct GuestClock {
    inner: Arc<Inner>,
}

struct Inner {
    virtualized: bool,
    instret: AtomicU64,
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
    pub fn host() -> GuestClock {
        GuestClock {
            inner: Arc::new(Inner {
                virtualized: false,
                instret: AtomicU64::new(0),
                credit_100ns: AtomicU64::new(0),
            }),
        }
    }

    pub fn virtualized() -> GuestClock {
        GuestClock {
            inner: Arc::new(Inner {
                virtualized: true,
                instret: AtomicU64::new(0),
                credit_100ns: AtomicU64::new(0),
            }),
        }
    }

    pub fn new(virtualized: bool) -> GuestClock {
        if virtualized {
            GuestClock::virtualized()
        } else {
            GuestClock::host()
        }
    }

    #[inline]
    pub fn is_virtual(&self) -> bool {
        self.inner.virtualized
    }

    #[inline]
    pub fn retire_one(&self) {
        if !self.inner.virtualized {
            return;
        }
        let n = self.inner.instret.load(Ordering::Relaxed).wrapping_add(1);
        self.inner.instret.store(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn retire(&self, n: u64) {
        if !self.inner.virtualized || n == 0 {
            return;
        }
        let v = self.inner.instret.load(Ordering::Relaxed).wrapping_add(n);
        self.inner.instret.store(v, Ordering::Relaxed);
    }

    #[inline]
    pub fn instret(&self) -> u64 {
        self.inner.instret.load(Ordering::Relaxed)
    }

    pub fn sleep_credit_100ns(&self) -> u64 {
        self.inner.credit_100ns.load(Ordering::Relaxed)
    }

    pub fn credit_ms(&self, ms: u64) {
        if !self.inner.virtualized || ms == 0 || ms == INFINITE_MS {
            return;
        }
        let ticks = ms.min(MAX_CREDIT_MS) * (QPC_FREQUENCY / 1_000);
        let n = self.inner.credit_100ns.load(Ordering::Relaxed).wrapping_add(ticks);
        self.inner.credit_100ns.store(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn monotonic_100ns(&self) -> Option<u64> {
        if !self.inner.virtualized {
            return None;
        }
        Some(self.instret().wrapping_add(self.sleep_credit_100ns()))
    }

    #[inline]
    pub fn tick_count_ms(&self) -> Option<u64> {
        self.monotonic_100ns().map(|t| t / (QPC_FREQUENCY / 1_000))
    }

    #[inline]
    pub fn filetime(&self) -> Option<u64> {
        self.monotonic_100ns().map(|t| VIRTUAL_EPOCH_FILETIME.wrapping_add(t))
    }

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
        c.credit_ms(10);
        assert_eq!(c.sleep_credit_100ns(), 100_000);
        assert_eq!(c.tick_count_ms(), Some(10));
        c.credit_ms(INFINITE_MS);
        assert_eq!(c.sleep_credit_100ns(), 100_000);
        c.credit_ms(24 * 60 * 60 * 1000);
        assert_eq!(c.sleep_credit_100ns(), 100_000 + MAX_CREDIT_MS * 10_000);
    }

    #[test]
    fn the_tsc_advances_between_any_two_reads() {
        let c = GuestClock::virtualized();
        c.retire_one();
        let first = c.tsc().unwrap();
        c.retire_one();
        let second = c.tsc().unwrap();
        assert!(second > first, "{second} must exceed {first}");
        assert_eq!(second - first, TSC_TICKS_PER_100NS, "1 GHz against a 10 MHz QPC");
    }

    #[test]
    fn the_epoch_is_the_start_of_2026() {
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
