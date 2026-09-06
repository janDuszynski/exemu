use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use crate::cpu::CpuState;
use crate::memory::Region;

pub const BREAK_AT_STEP_DISABLED: u64 = u64::MAX;

const WATCH_PAGE_SHIFT: u32 = 12;

const WATCH_FILTER_MAX_PAGES: u64 = 4096;

const ACCESS_PROBE_MAX_PAGES: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WatchKind {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

impl WatchKind {
    #[inline]
    pub const fn covers(self, access: WatchKind) -> bool {
        (self as u8) & (access as u8) != 0
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchpoint {
    pub base: u64,
    pub len: u64,
    pub kind: WatchKind,
}

impl Watchpoint {
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StopRequest {
    #[default]
    Run = 0,
    Pause = 1,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    Paused,
    Breakpoint {
        rip: u64,
    },
    Watch {
        addr: u64,
        kind: WatchKind,
    },
    StepComplete,
    StepCount {
        steps: u64,
    },
    Faulted {
        report: String,
    },
}

#[derive(Clone)]
pub struct DebugControl {
    inner: Arc<Inner>,
}

struct Inner {
    attached: bool,
    generation: AtomicU64,
    bp_filter: AtomicU64,
    wp_filter: AtomicU64,
    stop_request: AtomicU8,
    break_at_step: AtomicU64,
    watch_hit: AtomicU64,
    watch_kind: AtomicU8,
    sets: Mutex<Sets>,
}

#[derive(Default)]
struct Sets {
    breakpoints: Vec<u64>,
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
    pub fn detached() -> DebugControl {
        DebugControl::with_mode(false)
    }

    pub fn attached() -> DebugControl {
        DebugControl::with_mode(true)
    }

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

    #[inline]
    pub fn is_attached(&self) -> bool {
        self.inner.attached
    }

    #[inline]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Relaxed)
    }

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

    #[inline]
    pub fn any_breakpoints(&self) -> bool {
        self.inner.attached && self.inner.bp_filter.load(Ordering::Relaxed) != 0
    }

    pub fn next_break_at_or_after(&self, start: u64) -> Option<u64> {
        if !self.any_breakpoints() {
            return None;
        }
        let sets = self.sets();
        let i = sets.breakpoints.partition_point(|&a| a < start);
        sets.breakpoints.get(i).copied()
    }

    pub fn breakpoints(&self) -> Vec<u64> {
        if !self.inner.attached {
            return Vec::new();
        }
        self.sets().breakpoints.clone()
    }

    pub fn arm_break(&self, addr: u64) {
        self.mutate(|s| match s.breakpoints.binary_search(&addr) {
            Ok(_) => false,
            Err(i) => {
                s.breakpoints.insert(i, addr);
                true
            }
        });
    }

    pub fn disarm_break(&self, addr: u64) {
        self.mutate(|s| match s.breakpoints.binary_search(&addr) {
            Ok(i) => {
                s.breakpoints.remove(i);
                true
            }
            Err(_) => false,
        });
    }

    #[inline]
    pub fn any_watchpoints(&self) -> bool {
        self.inner.attached && self.inner.wp_filter.load(Ordering::Relaxed) != 0
    }

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

    pub fn watchpoints(&self) -> Vec<Watchpoint> {
        if !self.inner.attached {
            return Vec::new();
        }
        self.sets().watchpoints.clone()
    }

    pub fn arm_watch(&self, base: u64, len: u64, kind: WatchKind) {
        if len == 0 {
            return;
        }
        self.mutate(|s| {
            s.watchpoints.push(Watchpoint { base, len, kind });
            true
        });
    }

    pub fn disarm_watch(&self, base: u64) {
        self.mutate(|s| {
            let before = s.watchpoints.len();
            s.watchpoints.retain(|w| w.base != base);
            s.watchpoints.len() != before
        });
    }

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

    pub fn request(&self, r: StopRequest) {
        if !self.inner.attached {
            return;
        }
        self.inner.stop_request.store(r.as_u8(), Ordering::Relaxed);
    }

    #[inline]
    pub fn pending_request(&self) -> StopRequest {
        if !self.inner.attached {
            return StopRequest::Run;
        }
        StopRequest::from_u8(self.inner.stop_request.load(Ordering::Relaxed))
    }

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

    pub fn set_break_at_step(&self, steps: Option<u64>) {
        if !self.inner.attached {
            return;
        }
        self.inner
            .break_at_step
            .store(steps.unwrap_or(BREAK_AT_STEP_DISABLED), Ordering::Relaxed);
    }

    #[inline]
    pub fn break_at_step(&self) -> u64 {
        if !self.inner.attached {
            return BREAK_AT_STEP_DISABLED;
        }
        self.inner.break_at_step.load(Ordering::Relaxed)
    }

    fn sets(&self) -> std::sync::MutexGuard<'_, Sets> {
        self.inner.sets.lock().unwrap_or_else(|e| e.into_inner())
    }

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

#[inline]
const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[inline]
const fn bloom_bits(key: u64) -> u64 {
    let h = mix64(key);
    (1u64 << (h & 63)) | (1u64 << ((h >> 32) & 63))
}

fn watch_bits(w: &Watchpoint) -> u64 {
    let first = w.base >> WATCH_PAGE_SHIFT;
    let last = w.base.saturating_add(w.len - 1) >> WATCH_PAGE_SHIFT;
    if last - first >= WATCH_FILTER_MAX_PAGES {
        return u64::MAX;
    }
    (first..=last).fold(0u64, |acc, p| acc | bloom_bits(p))
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallTable {
    Ntdll,
    Win32k,
}

pub trait TraceSink: Send {
    fn enabled(&self) -> bool {
        true
    }

    fn win32_call(&mut self, _name: &str, _thunk: u64) {}

    fn syscall(&mut self, _table: SyscallTable, _index: u32, _args: &[u64; 4]) {}

    fn syscall_return(&mut self, _table: SyscallTable, _index: u32, _status: u32) {}

    fn unix_call(&mut self, _handle: u64, _code: u32, _args: u64) {}

    fn note(&mut self, _text: &str) {}
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoTrace;

impl TraceSink for NoTrace {
    #[inline]
    fn enabled(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadInfo {
    pub tid: u32,
    pub handle: u64,
    pub state: &'static str,
    pub rip: u64,
    pub rsp: u64,
    pub teb_base: u64,
    pub suspend_count: u32,
    pub waiting_on: Vec<u64>,
    pub is_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleInfo {
    pub handle: u64,
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmLine {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct DebugSnapshot {
    pub stop: StopReason,
    pub steps: u64,
    pub regs: CpuState,
    pub bits: u8,
    pub rip_note: String,
    pub trail: Vec<u64>,
    pub backtrace: Vec<u64>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub handles: Vec<HandleInfo>,
    pub regions: Vec<Region>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommand {
    Pause,
    Resume,
    Step,
    ArmBreak(u64),
    DisarmBreak(u64),
    ArmWatch {
        base: u64,
        len: u64,
        kind: WatchKind,
    },
    DisarmWatch(u64),
    BreakAtStep(Option<u64>),
    ReadMemory {
        addr: u64,
        len: u64,
    },
    Disassemble {
        addr: u64,
        count: u32,
    },
    Detach,
    Kill,
}

#[derive(Debug, Clone)]
pub enum DebugEvent {
    Stopped(Box<DebugSnapshot>),
    Resumed,
    Memory {
        addr: u64,
        bytes: Vec<u8>,
    },
    Disassembly {
        addr: u64,
        lines: Vec<DisasmLine>,
    },
    Exited {
        code: i32,
        steps: u64,
    },
    Error(String),
}

pub struct DebugSession {
    pub control: DebugControl,
    pub commands: Receiver<DebugCommand>,
    pub events: Sender<DebugEvent>,
}

pub struct DebugFrontEnd {
    pub control: DebugControl,
    pub commands: Sender<DebugCommand>,
    pub events: Receiver<DebugEvent>,
}

impl DebugSession {
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

    #[test]
    fn detached_is_inert_from_every_accessor() {
        let d = DebugControl::default();
        assert!(!d.is_attached());

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
        d.arm_break(0x20);
        d.disarm_break(0x99);
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

    #[test]
    fn the_bloom_filter_has_no_false_negatives() {
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
        let d = DebugControl::attached();
        let len = (WATCH_FILTER_MAX_PAGES + 8) << WATCH_PAGE_SHIFT;
        d.arm_watch(0x1_0000_0000, len, WatchKind::Write);
        assert!(d.any_watchpoints());
        assert!(d.is_watched(0x1_0000_0000, 4, WatchKind::Write));
        assert!(d.is_watched(0x1_0000_0000 + len - 1, 1, WatchKind::Write));
        assert!(!d.is_watched(0x1_0000_0000 + len, 1, WatchKind::Write));
    }

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

        assert_eq!(deadline(&DebugControl::detached(), 1_000, 65_536), 65_536);
    }

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
        sink.syscall(SyscallTable::Ntdll, 1, &[0; 4]);
        sink.note("still fine");
    }

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

        let t = std::thread::spawn(move || session.control.take_request());
        assert_eq!(t.join().expect("session half is Send"), StopRequest::Run);
    }

    #[test]
    fn the_command_protocol_is_read_only() {
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
