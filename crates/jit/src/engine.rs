use std::collections::{HashMap, HashSet};

use exemu_core::cpu::CpuState;
use exemu_core::debug::DebugControl;
use exemu_core::Memory;

use crate::buffer::{BlockCode, BufferError, CodeBuffer};
use crate::compile::{Compiler, StopReason, MAX_INSNS, MAX_LINKS, RET_FAULT};
use crate::rt::{
    jit_read, jit_read_watched, jit_write, jit_write_watched, BlockCtx, LinkSlot, ReadFn, TlbEntry,
    WriteFn, CODE_PAGE_WORDS, LINK_EPOCH_DEAD, NO_SLOT, NO_SMC, PARITY, TLB_SLOTS, TRAIL,
};

pub use crate::compile::Mode;

type BlockFn = unsafe extern "C" fn(*mut CpuState, *mut u8) -> u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    Executed { insns: u32 },
    SideExit { insns: u32 },
    Faulted { insns: u32 },
    NotCompiled,
}

impl Run {
    pub fn insns(self) -> u32 {
        match self {
            Run::NotCompiled => 0,
            Run::Executed { insns } | Run::SideExit { insns } | Run::Faulted { insns } => insns,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct JitStats {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub insns_executed: u64,
    pub faults: u64,
    pub not_compiled: u64,
    pub chains: u64,
    pub links_taken: u64,
    pub links_made: u64,
    pub unlinks: u64,
    pub smc_false_hits: u64,
    pub flushes: u64,
    pub breakpoint_stops: u64,
    pub watch_stops: u64,
    pub budget_stops: u64,
    pub budget_refusals: u64,
    pub tlb_fills: u64,
    pub tlb_denied: u64,
    pub tlb_resets: u64,
    pub peak_code_bytes: usize,
    pub declined: HashMap<u16, u64>,
}

impl JitStats {
    pub fn top_declined(&self, n: usize) -> Vec<(u16, u64)> {
        let mut v: Vec<(u16, u64)> = self.declined.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(n);
        v
    }
}

struct Block {
    code: Option<BlockCode>,
    chain: u64,
    insns: u32,
    page0: u64,
    page1: u64,
    gen0: u64,
    gen1: u64,
    global_gen: u64,
}

#[derive(Clone, Copy)]
struct CacheLine {
    rip: u64,
    idx: u32,
    gen: u32,
    long: bool,
}

const LINES: usize = 8192;

fn link_blocks_for(capacity: usize) -> u32 {
    (capacity / 256).clamp(64, 1 << 16) as u32
}

pub struct Jit {
    buffer: CodeBuffer,
    blocks: Vec<Block>,
    map: HashMap<(u64, bool), u32>,
    lines: Vec<CacheLine>,
    cache_gen: u32,
    code_gen: u64,
    stats: JitStats,
    max_insns: u32,
    longest: u32,
    trail: Box<[u64]>,
    trail_at: u64,
    links: Box<[LinkSlot]>,
    link_blocks: u32,
    link_epoch: u64,
    pending: u64,
    pending_rip: u64,
    pending_long: bool,
    code_page_set: HashSet<u64>,
    code_pages: Box<[u64]>,
    tlb: Box<[TlbEntry]>,
    tlb_live: bool,
    tlb_gen: u64,
    tlb_watch: bool,
    tlb_mem: usize,
    tlb_on: bool,
    debug: Option<DebugControl>,
    debug_gen: u64,
}

impl Jit {
    pub fn new(capacity: usize) -> Result<Jit, BufferError> {
        let link_blocks = link_blocks_for(capacity);
        Ok(Jit {
            buffer: CodeBuffer::with_capacity(capacity)?,
            blocks: Vec::new(),
            map: HashMap::new(),
            lines: vec![CacheLine { rip: 0, idx: 0, gen: 0, long: false }; LINES],
            cache_gen: 1,
            code_gen: 0,
            stats: JitStats::default(),
            max_insns: MAX_INSNS,
            longest: 0,
            trail: vec![0; TRAIL].into_boxed_slice(),
            trail_at: 0,
            links: vec![LinkSlot::default(); (link_blocks * MAX_LINKS) as usize]
                .into_boxed_slice(),
            link_blocks,
            link_epoch: 1,
            pending: NO_SLOT,
            pending_rip: 0,
            pending_long: false,
            code_page_set: HashSet::new(),
            code_pages: vec![0u64; CODE_PAGE_WORDS].into_boxed_slice(),
            tlb: vec![TlbEntry::EMPTY; TLB_SLOTS].into_boxed_slice(),
            tlb_live: false,
            tlb_gen: 0,
            tlb_watch: false,
            tlb_mem: 0,
            tlb_on: true,
            debug: None,
            debug_gen: 0,
        })
    }

    pub fn stats(&self) -> &JitStats {
        &self.stats
    }

    pub fn set_tlb(&mut self, on: bool) {
        self.tlb_on = on;
        self.tlb_reset();
    }

    fn tlb_reset(&mut self) {
        self.dump_tlb_stats("reset");
        self.tlb.fill(TlbEntry::EMPTY);
        self.tlb_live = false;
        self.stats.tlb_resets += 1;
    }

    pub fn set_max_insns(&mut self, n: u32) {
        self.max_insns = n.max(1);
    }

    pub fn set_debug(&mut self, debug: DebugControl) {
        self.debug = debug.is_attached().then_some(debug);
        self.debug_gen = self.debug.as_ref().map_or(0, DebugControl::generation);
        self.flush();
        self.tlb_reset();
    }

    #[inline]
    fn stop_before(&self, rip: u64) -> u64 {
        match &self.debug {
            Some(d) => d.next_break_at_or_after(rip).unwrap_or(u64::MAX),
            None => u64::MAX,
        }
    }

    #[inline]
    fn debug_generation_check(&mut self) {
        let Some(d) = &self.debug else { return };
        let g = d.generation();
        if g != self.debug_gen {
            self.debug_gen = g;
            self.flush();
        }
    }

    pub fn code_bytes(&self) -> usize {
        self.buffer.used()
    }

    #[inline]
    fn line_of(rip: u64, long: bool) -> usize {
        (rip.wrapping_add(long as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 51) as usize
            & (LINES - 1)
    }

    fn unlink_all(&mut self) {
        self.link_epoch += 1;
        if self.link_epoch == LINK_EPOCH_DEAD {
            self.links.fill(LinkSlot::default());
            self.link_epoch = 1;
        }
        self.pending = NO_SLOT;
        self.stats.unlinks += 1;
    }

    fn flush(&mut self) {
        self.buffer.reset();
        self.blocks.clear();
        self.map.clear();
        self.longest = 0;
        self.unlink_all();
        self.code_page_set.clear();
        self.code_pages.fill(0);
        self.cache_gen = self.cache_gen.wrapping_add(1);
        if self.cache_gen == 0 {
            for l in self.lines.iter_mut() {
                l.gen = 0;
            }
            self.cache_gen = 1;
        }
        self.stats.flushes += 1;
    }

    fn note_code_page(&mut self, page: u64) {
        if self.code_page_set.insert(page) {
            let bit = crate::rt::code_page_bit(page);
            self.code_pages[(bit >> 6) as usize] |= 1 << (bit & 63);
        }
    }

    pub fn invalidate(&mut self) {
        self.flush();
        self.code_gen = 0;
        self.tlb_reset();
    }

    fn block_at<M: Memory + ?Sized>(&mut self, rip: u64, mode: Mode, mem: &M) -> u32 {
        let long = mode == Mode::Long;
        let line = Self::line_of(rip, long);
        let l = self.lines[line];
        if l.gen == self.cache_gen && l.rip == rip && l.long == long {
            return l.idx;
        }
        if let Some(&idx) = self.map.get(&(rip, long)) {
            self.lines[line] = CacheLine { rip, idx, gen: self.cache_gen, long };
            return idx;
        }
        let stop_before = self.stop_before(rip);
        let plan =
            Compiler::compile(mem, mode, rip, self.max_insns, self.slots_for(None), stop_before);
        let lo = plan.start;
        let hi = lo.saturating_add(plan.bytes);
        let page0 = lo & !(exemu_core::CODE_PAGE_SIZE - 1);
        let page1 = hi.saturating_sub(1).max(lo) & !(exemu_core::CODE_PAGE_SIZE - 1);
        let meta = (
            lo,
            hi,
            page0,
            page1,
            mem.code_page_generation(page0),
            mem.code_page_generation(page1),
            mem.code_generation(),
        );
        if let StopReason::Unsupported { opcode, rip: at, esc } = plan.stop {
            if at == rip {
                let key = opcode as u16 | if esc { 0x100 } else { 0 };
                *self.stats.declined.entry(key).or_insert(0) += 1;
            }
        }
        let mk = |code: Option<BlockCode>, chain_off: u32, insns: u32| Block {
            chain: match code {
                Some(c) => c.addr() as u64 + 4 * chain_off as u64,
                None => 0,
            },
            code,
            insns,
            page0: meta.2,
            page1: meta.3,
            gen0: meta.4,
            gen1: meta.5,
            global_gen: meta.6,
        };
        let block = if plan.insns == 0 {
            mk(None, 0, 0)
        } else {
            match self.buffer.push(&plan.code) {
                Ok(code) => {
                    self.stats.blocks_compiled += 1;
                    self.stats.peak_code_bytes = self.stats.peak_code_bytes.max(self.buffer.used());
                    mk(Some(code), plan.chain_off, plan.insns)
                }
                Err(_) => {
                    self.flush();
                    let plan = Compiler::compile(
                        mem,
                        mode,
                        rip,
                        self.max_insns,
                        self.slots_for(None),
                        stop_before,
                    );
                    match self.buffer.push(&plan.code) {
                        Ok(code) => {
                            self.stats.blocks_compiled += 1;
                            mk(Some(code), plan.chain_off, plan.insns)
                        }
                        Err(_) => mk(None, 0, 0),
                    }
                }
            }
        };
        let idx = self.blocks.len() as u32;
        if block.code.is_some() {
            self.longest = self.longest.max(block.insns);
            self.note_code_page(meta.2);
            self.note_code_page(meta.3);
        }
        self.blocks.push(block);
        self.map.insert((rip, long), idx);
        self.lines[Self::line_of(rip, long)] = CacheLine { rip, idx, gen: self.cache_gen, long };
        idx
    }

    fn slots_for(&self, idx: Option<u32>) -> Option<u32> {
        let idx = idx.unwrap_or(self.blocks.len() as u32);
        (idx < self.link_blocks).then(|| idx * MAX_LINKS)
    }

    fn validate<M: Memory + ?Sized>(&mut self, idx: usize, mem: &M) -> bool {
        let cur = mem.code_generation();
        let b = &self.blocks[idx];
        if b.global_gen == cur {
            return true;
        }
        let (p0, p1, g0, g1) = (b.page0, b.page1, b.gen0, b.gen1);
        if mem.code_page_generation(p0) == g0 && mem.code_page_generation(p1) == g1 {
            self.blocks[idx].global_gen = cur;
            return true;
        }
        false
    }

    pub fn run<M: Memory + ?Sized>(
        &mut self,
        state: &mut CpuState,
        mem: &mut M,
        mode: Mode,
        budget: u64,
    ) -> Run {
        self.stats.chains += 1;
        let long = mode == Mode::Long;
        let mem_id = std::ptr::from_mut(mem).cast::<u8>() as usize;
        let layout_gen = mem.layout_generation();
        let watching = mem.watchpoints_armed()
            || self.debug.as_ref().is_some_and(DebugControl::any_watchpoints);
        if !self.tlb_live
            || layout_gen != self.tlb_gen
            || watching != self.tlb_watch
            || mem_id != self.tlb_mem
        {
            self.tlb_reset();
            self.tlb_gen = layout_gen;
            self.tlb_watch = watching;
            self.tlb_mem = mem_id;
            self.tlb_live = true;
        }
        let tlb_on = u64::from(self.tlb_on && !watching);
        let budget = budget.min(u32::MAX as u64 - MAX_INSNS as u64);
        let debug = self.debug.clone();
        let (read, write): (ReadFn<M>, WriteFn<M>) = match &debug {
            Some(d) if d.any_watchpoints() => (jit_read_watched, jit_write_watched),
            _ => (jit_read, jit_write),
        };
        let mut retired: u64 = 0;
        loop {
            self.debug_generation_check();
            let rip = state.rip;
            self.trail[self.trail_at as usize & (TRAIL - 1)] = rip;
            self.trail_at = self.trail_at.wrapping_add(1);

            let mut idx = self.block_at(rip, mode, &*mem) as usize;
            if !self.validate(idx, &*mem) {
                self.flush();
                idx = self.block_at(rip, mode, &*mem) as usize;
            }
            let (code, chain, insns) = match &self.blocks[idx] {
                Block { code: Some(c), chain, insns, .. } => (*c, *chain, *insns),
                _ => {
                    self.pending = NO_SLOT;
                    self.stats.not_compiled += 1;
                    if retired == 0 {
                        return Run::NotCompiled;
                    }
                    return if debug.as_ref().is_some_and(|d| d.is_break(rip)) {
                        self.stats.breakpoint_stops += 1;
                        Run::Executed { insns: retired as u32 }
                    } else {
                        Run::SideExit { insns: retired as u32 }
                    };
                }
            };
            if self.pending != NO_SLOT && self.pending_long == long && self.pending_rip == rip {
                let slot = self.pending as usize;
                let fill = LinkSlot { epoch: self.link_epoch, key: rip, code: chain };
                if self.links[slot] != fill {
                    self.stats.links_made += 1;
                }
                self.links[slot] = fill;
            }
            self.pending = NO_SLOT;
            if retired + u64::from(insns) > budget {
                self.stats.budget_stops += 1;
                self.stats.budget_refusals += u64::from(retired < budget);
                return Run::SideExit { insns: retired as u32 };
            }

            let trail_before = self.trail_at;
            let (ret, ran, pending, smc, trail_at) = {
                let mut ctx = BlockCtx {
                    mem,
                    parity: PARITY.as_ptr(),
                    code_lo: 0,
                    code_hi: 0,
                    read,
                    write,
                    debug: debug.as_ref(),
                    retired,
                    link_limit: (budget + 1).saturating_sub(u64::from(self.longest)),
                    links: self.links.as_ptr(),
                    link_epoch: self.link_epoch,
                    pending: NO_SLOT,
                    trail: self.trail.as_mut_ptr(),
                    trail_at: self.trail_at,
                    smc: NO_SMC,
                    smc_hits: 0,
                    code_pages: self.code_pages.as_ptr(),
                    tlb: self.tlb.as_mut_ptr(),
                    tlb_on,
                    tlb_fills: 0,
                    tlb_denied: 0,
                    watch_stops: 0,
                };
                // SAFETY: `code` was produced by this crate's emitter for exactly
                let ret = unsafe {
                    let f: BlockFn = code.as_fn();
                    f(state as *mut CpuState, (&mut ctx as *mut BlockCtx<'_, M>).cast::<u8>())
                };
                self.stats.tlb_fills += ctx.tlb_fills;
                self.stats.tlb_denied += ctx.tlb_denied;
                self.stats.watch_stops += ctx.watch_stops;
                (ret, ctx.retired, ctx.pending, (ctx.smc, ctx.smc_hits), ctx.trail_at)
            };
            let linked = trail_at.wrapping_sub(trail_before);
            self.trail_at = trail_at;
            self.stats.links_taken += linked;
            self.stats.blocks_executed += 1 + linked;
            self.stats.insns_executed += ran - retired;
            retired = ran;
            self.pending = pending;
            self.pending_rip = state.rip;
            self.pending_long = long;
            let (smc, smc_hits) = smc;
            if smc_hits != 0 {
                let page = smc / exemu_core::CODE_PAGE_SIZE * exemu_core::CODE_PAGE_SIZE;
                if smc_hits > 1 || self.code_page_set.contains(&page) {
                    self.unlink_all();
                } else {
                    self.stats.smc_false_hits += 1;
                }
            }
            if ret & RET_FAULT != 0 {
                self.stats.faults += 1;
                return Run::Faulted { insns: retired as u32 };
            }
            if retired >= budget {
                return Run::Executed { insns: retired as u32 };
            }
        }
    }

    pub fn dump_tlb_stats(&self, tag: &str) {
        if std::env::var("EXEMU_JIT_TLB_STATS").is_err() {
            return;
        }
        let s = &self.stats;
        eprintln!(
            "[jit/tlb] {tag}: {} fills, {} denied, {} resets; {} chains, {} blocks, {} insns",
            s.tlb_fills, s.tlb_denied, s.tlb_resets, s.chains, s.blocks_executed, s.insns_executed
        );
    }

    pub fn recent_blocks(&self) -> Vec<u64> {
        let n = (self.trail_at as usize).min(TRAIL);
        (0..n)
            .map(|i| self.trail[(self.trail_at as usize + TRAIL - n + i) & (TRAIL - 1)])
            .collect()
    }
}

impl Drop for Jit {
    fn drop(&mut self) {
        self.dump_tlb_stats("final");
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use exemu_core::{Perm, Region};
    use exemu_memory::VirtualMemory;

    const DECLINED: u8 = 0xF4;

    const CODE: u64 = 0x1000;
    const DATA: u64 = 0x2000;

    fn mem_with(code: &[u8]) -> VirtualMemory {
        let mut m = VirtualMemory::new();
        m.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
        m.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
        m.poke(CODE, code).unwrap();
        m
    }

    #[test]
    fn runs_a_straight_line_block() {
        let code = [
            0xB8, 0x05, 0x00, 0x00, 0x00,
            0x83, 0xC0, 0x07,
            DECLINED,
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 2);
        assert_eq!(r, Run::Executed { insns: 2 });
        assert_eq!(st.gpr[0], 12);
        assert_eq!(st.rip, CODE + 8);
    }

    #[test]
    fn declines_what_it_cannot_prove() {
        let code = [0x0F, 0xA2];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::NotCompiled);
        assert_eq!(st.rip, CODE, "a declined block must not move rip");
    }

    #[test]
    fn a_faulting_load_rewinds_to_the_instruction() {
        let code = [
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0x8B, 0x0A,
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        st.gpr[2] = 0xDEAD_0000;
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 1000);
        assert_eq!(r, Run::Faulted { insns: 1 });
        assert_eq!(st.gpr[0], 1, "the first instruction did run");
        assert_eq!(st.rip, CODE + 5, "rip rewound to the faulting instruction");
    }

    #[test]
    fn a_taken_branch_is_compiled_and_sets_rip() {
        let code = [
            0x31, 0xC0,
            0x74, 0x02,
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 2), Run::Executed { insns: 2 });
        assert_eq!(st.rip, CODE + 6, "branch taken");
    }

    #[test]
    fn a_store_into_this_blocks_own_code_stops_the_block() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        let code = [
            0xC6, 0x04, 0x25, 0x09, 0x10, 0x00, 0x00, 0x09,
            0xB8, 0x07, 0x00, 0x00, 0x00,
            DECLINED,
        ];
        mem.poke(CODE, &code).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 1000);
        assert_eq!(r, Run::SideExit { insns: 2 });
        assert_eq!(st.rip, CODE + 13);
        assert_eq!(st.gpr[0], 9, "the instruction after the store ran from its rewritten bytes");
        assert_eq!(jit.recent_blocks()[..2], [CODE, CODE + 8], "the block stopped at the store");
    }

    #[test]
    fn a_store_into_another_block_invalidates_it() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        let a = [0xC6, 0x04, 0x25, 0x41, 0x10, 0x00, 0x00, 0x02, DECLINED];
        let b = [0xB8, 0x01, 0x00, 0x00, 0x00, DECLINED];
        mem.poke(CODE, &a).unwrap();
        mem.poke(CODE + 0x40, &b).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();

        let mut st = CpuState::new();
        st.rip = CODE + 0x40;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        assert_eq!(st.gpr[0], 1);

        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });

        let flushes = jit.stats().flushes;
        st.rip = CODE + 0x40;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        assert_eq!(st.gpr[0], 2, "block B was recompiled from the rewritten bytes");
        assert!(jit.stats().flushes > flushes, "the stale block was invalidated");
    }

    #[test]
    fn the_same_bytes_are_cached_separately_per_cpu_mode() {
        let code = [0x48, 0xFF, 0xC0, DECLINED];
        let mut mem = mem_with(&code);
        let mut jit = Jit::new(64 * 1024).unwrap();

        let mut st = CpuState::new();
        st.rip = CODE;
        st.gpr[0] = 5;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        assert_eq!(st.gpr[0], 6, "long mode: one `inc rax`");
        assert_eq!(st.rip, CODE + 3);

        st.rip = CODE;
        st.gpr[0] = 5;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Protected, 2), Run::Executed { insns: 2 });
        assert_eq!(st.gpr[0], 5, "protected mode: `dec eax` then `inc eax`");
        assert_eq!(st.rip, CODE + 3);

        st.rip = CODE;
        st.gpr[0] = 5;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        assert_eq!(st.gpr[0], 6);
        assert_eq!(jit.stats().flushes, 0, "switching modes must not flush");
    }

    #[test]
    fn a_data_store_does_not_invalidate_anything() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        mem.map(Region::new("data", DATA, 0x1000, Perm::RWX)).unwrap();
        let code = [0xC6, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x01, DECLINED];
        mem.poke(CODE, &code).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for _ in 0..8 {
            st.rip = CODE;
            assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        }
        assert_eq!(jit.stats().flushes, 0, "a data store must not invalidate the cache");
        assert_eq!(jit.stats().blocks_compiled, 1, "and the block is compiled once");
    }

    const LOAD_DATA: [u8; 8] = [0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, DECLINED];

    fn mem_two_page_data(code: &[u8], perm: Perm) -> VirtualMemory {
        let mut m = VirtualMemory::new();
        m.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
        m.map(Region::new("data", DATA, 0x2000, perm)).unwrap();
        m.poke(CODE, code).unwrap();
        m
    }

    fn mem_data_pages(code: &[u8], pages: u64) -> VirtualMemory {
        let mut m = VirtualMemory::new();
        m.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
        m.map(Region::new("data", DATA, pages * 0x1000, Perm::RW)).unwrap();
        m.poke(CODE, code).unwrap();
        m
    }

    fn load_once(jit: &mut Jit, mem: &mut VirtualMemory) -> u64 {
        let mut st = CpuState::new();
        st.rip = CODE;
        jit.run(&mut st, mem, Mode::Long, 1000);
        st.gpr[0]
    }

    #[test]
    fn remapping_a_region_at_the_same_address_does_not_reuse_its_host_pointer() {
        let mut mem = mem_two_page_data(&LOAD_DATA, Perm::RW);
        let mut jit = Jit::new(64 * 1024).unwrap();

        mem.write_u32(DATA, 0x1111_1111).unwrap();
        assert_eq!(load_once(&mut jit, &mut mem), 0x1111_1111);
        assert!(jit.stats().tlb_fills > 0, "the page must actually be cached");
        let resets = jit.stats().tlb_resets;

        for i in 0..8u32 {
            mem.unmap(DATA, 0).unwrap();
            mem.map(Region::new("data", DATA, 0x2000, Perm::RW)).unwrap();
            let v = 0x2222_0000 + i;
            mem.write_u32(DATA, v).unwrap();
            assert_eq!(load_once(&mut jit, &mut mem), v as u64, "round {i} read a stale page");
        }
        assert!(jit.stats().tlb_resets > resets, "the table was never thrown away");
    }

    #[test]
    fn making_a_region_executable_puts_its_stores_back_on_the_helper() {
        let mut mem = mem_two_page_data(
            &[0xC6, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x01, DECLINED],
            Perm::RW,
        );
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();

        let quiet = mem.code_generation();
        for _ in 0..4 {
            st.rip = CODE;
            jit.run(&mut st, &mut mem, Mode::Long, 1000);
        }
        assert!(jit.stats().tlb_fills > 0);
        assert_eq!(mem.code_generation(), quiet, "not executable, so not a code write");

        mem.protect(DATA, 0x2000, Perm::RWX).unwrap();
        let before = mem.code_generation();
        for _ in 0..4 {
            st.rip = CODE;
            jit.run(&mut st, &mut mem, Mode::Long, 1000);
        }
        assert_eq!(
            mem.code_generation(),
            before + 4,
            "every store into executable memory must reach the seam"
        );
    }

    #[test]
    fn arming_a_watchpoint_throws_the_cached_pages_away() {
        use exemu_core::debug::{DebugControl, WatchKind};
        let mut mem = mem_two_page_data(&LOAD_DATA, Perm::RW);
        let d = DebugControl::attached();
        mem.set_debug(d.clone());
        let mut jit = Jit::new(64 * 1024).unwrap();

        mem.write_u32(DATA, 0x33).unwrap();
        assert_eq!(load_once(&mut jit, &mut mem), 0x33);
        assert!(jit.stats().tlb_fills > 0, "unarmed, the page is cached");

        d.arm_watch(DATA, 4, WatchKind::Read);
        let fills = jit.stats().tlb_fills;
        let resets = jit.stats().tlb_resets;
        assert_eq!(load_once(&mut jit, &mut mem), 0x33, "still the right value");
        assert!(jit.stats().tlb_resets > resets, "arming must throw the table away");
        assert_eq!(jit.stats().tlb_fills, fills, "and nothing may be cached while armed");
        assert!(d.take_watch_hit().is_some(), "the read must have been seen");

        d.disarm_watch(DATA);
        assert_eq!(load_once(&mut jit, &mut mem), 0x33);
        assert!(jit.stats().tlb_fills > fills);
    }

    #[test]
    fn the_table_changes_nothing_a_run_can_observe() {
        let code: [u8; 26] = [
            0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
            0x01, 0x04, 0x25, 0x04, 0x20, 0x00, 0x00,
            0x89, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00,
            0x50,
            0x5B,
            0x8A, 0x0D,
            DECLINED,
        ];
        let run = |tlb_on: bool| {
            let mut mem = mem_two_page_data(&code, Perm::RW);
            mem.write_u64(DATA, 0x0000_0007_0000_0005).unwrap();
            mem.map(Region::new("stack", 0x8000, 0x4000, Perm::RW)).unwrap();
            let mut jit = Jit::new(64 * 1024).unwrap();
            jit.set_tlb(tlb_on);
            let mut st = CpuState::new();
            st.rip = CODE;
            st.gpr[4] = 0x9000;
            let mut insns = 0u64;
            for _ in 0..4 {
                st.rip = CODE;
                insns += jit.run(&mut st, &mut mem, Mode::Long, 1000).insns() as u64;
            }
            let mut data = [0u8; 32];
            mem.read(DATA, &mut data).unwrap();
            (st.gpr, st.rflags, insns, data, jit.stats().tlb_fills > 0)
        };
        let (off_gpr, off_flags, off_insns, off_data, off_cached) = run(false);
        let (on_gpr, on_flags, on_insns, on_data, on_cached) = run(true);
        assert!(!off_cached, "switched off means switched off");
        assert!(on_cached, "switched on, the pages really were cached");
        assert_eq!(on_gpr, off_gpr, "registers");
        assert_eq!(on_flags, off_flags, "flags");
        assert_eq!(on_insns, off_insns, "instructions retired");
        assert_eq!(on_data, off_data, "guest memory");
    }

    #[test]
    fn a_faulting_access_still_faults_with_a_warm_table() {
        let code: [u8; 15] = [
            0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
            0x8B, 0x1C, 0x25, 0x00, 0x60, 0x00, 0x00,
            DECLINED,
        ];
        let mut mem = mem_two_page_data(&code, Perm::RW);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for round in 0..4 {
            st.rip = CODE;
            st.gpr[3] = 0xdead;
            let r = jit.run(&mut st, &mut mem, Mode::Long, 1000);
            assert_eq!(r, Run::Faulted { insns: 1 }, "round {round}");
            assert_eq!(st.rip, CODE + 7, "rewound to the faulting instruction");
            assert_eq!(st.gpr[3], 0xdead, "nothing of it was committed");
        }
        assert!(jit.stats().tlb_fills > 0, "the mapped page was cached all along");
    }

    #[test]
    fn a_one_page_region_is_served_from_the_fast_path() {
        let code: [u8; 15] = [
            0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
            0x8B, 0x0C, 0x25, 0xFC, 0x2F, 0x00, 0x00,
            DECLINED,
        ];
        let mut mem = mem_data_pages(&code, 1);
        mem.write_u32(DATA, 0x4444_4444).unwrap();
        mem.write_u32(DATA + 0xffc, 0x5555_5555).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for _ in 0..2 {
            st.rip = CODE;
            jit.run(&mut st, &mut mem, Mode::Long, 1000);
        }
        assert_eq!(st.gpr[0], 0x4444_4444);
        assert_eq!(st.gpr[1] as u32, 0x5555_5555, "the region's last dword");
        assert_eq!(jit.stats().tlb_fills, 1, "one page, cached once and reused");
        assert_eq!(jit.stats().tlb_denied, 0);
    }

    #[test]
    fn an_access_running_off_a_cached_final_page_faults_at_its_own_instruction() {
        let code: [u8; 16] = [
            0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
            0x48, 0x8B, 0x1C, 0x25, 0xFC, 0x2F, 0x00, 0x00,
            DECLINED,
        ];
        let mut mem = mem_data_pages(&code, 1);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for round in 0..4 {
            st.rip = CODE;
            st.gpr[3] = 0xdead;
            assert_eq!(
                jit.run(&mut st, &mut mem, Mode::Long, 1000),
                Run::Faulted { insns: 1 },
                "round {round}"
            );
            assert_eq!(st.rip, CODE + 7, "rewound to the straddling load");
            assert_eq!(st.gpr[3], 0xdead, "nothing of it was committed");
        }
        assert_eq!(jit.stats().tlb_fills, 1, "the page it starts on is cached");
    }

    #[test]
    fn a_straddling_access_is_served_by_the_helper_and_reads_both_pages() {
        let code: [u8; 16] = [
            0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
            0x48, 0x8B, 0x1C, 0x25, 0xFC, 0x2F, 0x00, 0x00,
            DECLINED,
        ];
        let mut mem = mem_data_pages(&code, 2);
        mem.write_u32(DATA + 0xffc, 0xAAAA_AAAA).unwrap();
        mem.write_u32(DATA + 0x1000, 0xBBBB_BBBB).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for _ in 0..4 {
            st.rip = CODE;
            st.gpr[3] = 0;
            jit.run(&mut st, &mut mem, Mode::Long, 1000);
            assert_eq!(st.gpr[3], 0xBBBB_BBBB_AAAA_AAAA, "both halves, little-endian");
        }
        assert_eq!(jit.stats().tlb_fills, 1);
        assert_eq!(jit.stats().tlb_denied, 0);
    }

    const CHAIN: [u8; 16] = [
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0xEB, 0x00,
        0x83, 0xC0, 0x07,
        0xEB, 0x00,
        0x83, 0xC0, 0x09,
        DECLINED,
    ];

    #[test]
    fn a_chain_runs_every_block_it_can_in_one_call() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();

        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 2), Run::Executed { insns: 2 });
        assert_eq!(st.rip, CODE + 7);
        assert_eq!(jit.stats().blocks_executed, 1);

        st.rip = CODE;
        st.gpr[0] = 0;
        let chains = jit.stats().chains;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 5 });
        assert_eq!(st.gpr[0], 21, "all three blocks ran (5 + 7 + 9)");
        assert_eq!(st.rip, CODE + 15, "left sitting on the declined opcode");
        assert_eq!(jit.stats().chains, chains + 1, "three blocks, one entry");
    }

    #[test]
    fn the_block_that_would_cross_the_budget_is_left_to_the_interpreter() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 3), Run::SideExit { insns: 2 });
        assert_eq!(st.rip, CODE + 7, "stopped before the block that does not fit");
        assert_eq!(jit.stats().blocks_executed, 1);
        assert_eq!(jit.stats().budget_stops, 1);
        assert_eq!(jit.stats().budget_refusals, 1, "a block was refused with room left");
    }

    #[test]
    fn a_zero_budget_runs_nothing() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 0), Run::SideExit { insns: 0 });
        assert_eq!(st.rip, CODE);
        assert_eq!(st.gpr[0], 0);
        assert_eq!(jit.stats().budget_stops, 1);
        assert_eq!(jit.stats().budget_refusals, 0, "a zero budget refuses nothing it could have run");
    }

    #[test]
    fn a_chain_and_a_sequence_of_single_blocks_are_the_same_run() {
        let mut mem = mem_with(&CHAIN);
        let mut one = Jit::new(64 * 1024).unwrap();
        let mut many = Jit::new(64 * 1024).unwrap();
        let (mut a, mut b) = (CpuState::new(), CpuState::new());
        a.rip = CODE;
        b.rip = CODE;

        let mut stepped = 0u32;
        loop {
            match one.run(&mut a, &mut mem, Mode::Long, 2) {
                Run::Executed { insns } => stepped += insns,
                other => {
                    stepped += other.insns();
                    break;
                }
            }
        }
        let chained = many.run(&mut b, &mut mem, Mode::Long, 1000).insns();
        assert_eq!(stepped, chained, "the same instructions retired either way");
        assert_eq!(a.rip, b.rip);
        assert_eq!(a.gpr, b.gpr);
        assert_eq!(a.rflags, b.rflags);
    }

    #[test]
    fn the_trail_records_every_block_a_chain_entered() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        jit.run(&mut st, &mut mem, Mode::Long, 1000);
        assert_eq!(
            jit.recent_blocks(),
            vec![CODE, CODE + 7, CODE + 12, CODE + 15],
            "every block entry, oldest first — including the one that found nothing"
        );
    }

    #[test]
    fn the_trail_keeps_the_most_recent_entries_when_it_wraps() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for _ in 0..40 {
            st.rip = CODE;
            jit.run(&mut st, &mut mem, Mode::Long, 2);
        }
        let t = jit.recent_blocks();
        assert_eq!(t.len(), TRAIL, "the ring is full");
        assert!(t.iter().all(|&r| r == CODE), "and holds the entries, not zeroes");
    }

    const LOOP: [u8; 12] = [
        0xB9, 0x08, 0x00, 0x00, 0x00,
        0xFF, 0xC9,
        0x75, 0xFC,
        0x31, 0xC0,
        DECLINED,
    ];

    #[test]
    fn a_warm_loop_runs_every_iteration_without_returning_to_rust() {
        let mut mem = mem_with(&LOOP);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 18 });
        assert_eq!(st.gpr[1], 0, "ecx counted down to zero");

        let taken = jit.stats().links_taken;
        let entries = jit.stats().blocks_executed;
        st = CpuState::new();
        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 18 });
        assert_eq!(st.gpr[1], 0);
        assert_eq!(jit.stats().links_taken - taken, 8, "block transitions returned to Rust");
        assert_eq!(
            jit.stats().blocks_executed - entries,
            9,
            "nine block entries: one from here, eight by native link"
        );
        assert_eq!(
            jit.recent_blocks().iter().rev().take(9).copied().collect::<Vec<_>>(),
            vec![CODE + 11, CODE + 9, CODE + 5, CODE + 5, CODE + 5, CODE + 5, CODE + 5, CODE + 5, CODE + 5],
            "the trail still records blocks the caller's loop never saw"
        );
    }

    #[test]
    fn a_linked_chain_never_retires_past_its_budget() {
        let mut short = 0;
        for budget in 0..=20u64 {
            let mut mem = mem_with(&LOOP);
            let mut linked = Jit::new(64 * 1024).unwrap();
            let mut cold = Jit::new(64 * 1024).unwrap();
            let (mut a, mut b) = (CpuState::new(), CpuState::new());
            let mut warm = CpuState::new();
            warm.rip = CODE;
            linked.run(&mut warm, &mut mem, Mode::Long, 1000);
            assert!(linked.stats().links_made > 0, "the warm-up linked nothing");

            a.rip = CODE;
            b.rip = CODE;
            let taken = linked.stats().links_taken;
            let chained = linked.run(&mut a, &mut mem, Mode::Long, budget).insns();
            let stepped = cold.run(&mut b, &mut mem, Mode::Long, budget).insns();
            assert!(u64::from(chained) <= budget, "budget {budget}: retired {chained}");
            if budget >= 10 {
                assert!(linked.stats().links_taken > taken, "budget {budget}: no link was taken");
            }
            short += u64::from(u64::from(chained) < budget && chained < 18);
            assert_eq!(chained, stepped, "budget {budget}: retired a different amount");
            assert_eq!(a.rip, b.rip, "budget {budget}: stopped at a different instruction");
            assert_eq!(a.gpr, b.gpr, "budget {budget}");
            assert_eq!(a.rflags, b.rflags, "budget {budget}");
        }
        assert!(short > 0, "no budget ever ended inside a block");
    }

    #[test]
    fn a_store_into_a_linked_block_is_never_executed_stale() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        let mut a = vec![0xC6, 0x04, 0x25, 0x41, 0x10, 0x00, 0x00, 0x02];
        let jmp_at = a.len() as i32;
        a.push(0xE9);
        a.extend_from_slice(&(0x40 - (jmp_at + 5)).to_le_bytes());
        mem.poke(CODE, &a).unwrap();
        mem.poke(CODE + 0x40, &[0xB8, 0x01, 0x00, 0x00, 0x00, DECLINED]).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();

        let mut st = CpuState::new();
        st.rip = CODE;
        jit.run(&mut st, &mut mem, Mode::Long, 1000);
        assert_eq!(st.gpr[0], 2, "B already ran from the rewritten bytes");

        mem.poke(CODE + 0x40, &[0xB8, 0x01, 0x00, 0x00, 0x00, DECLINED]).unwrap();
        st = CpuState::new();
        st.rip = CODE;
        st.gpr[0] = 0xDEAD;
        jit.run(&mut st, &mut mem, Mode::Long, 1000);
        assert_eq!(st.gpr[0], 2, "the chain executed a stale copy of block B");
        assert!(jit.stats().unlinks > 0, "the store never broke the links");
    }

    const CALL_LOOP: [u8; 17] = [
        0xB9, 0x08, 0x00, 0x00, 0x00,
        0xE8, 0x06, 0x00, 0x00, 0x00,
        0xFF, 0xC9,
        0x75, 0xF7,
        DECLINED,
        0x90,
        0xC3,
    ];

    #[test]
    fn a_warm_return_reaches_its_caller_without_returning_to_rust() {
        let mut mem = mem_with(&CALL_LOOP);
        mem.map(Region::new("stack", 0x8000, 0x1000, Perm::RW)).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        st.gpr[4] = 0x8800;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 33 });
        assert_eq!(st.gpr[1], 0, "ecx counted down to zero");
        assert_eq!(st.rip, CODE + 14, "left on the declined opcode");
        assert_eq!(st.gpr[4], 0x8800, "every call was matched by its ret");

        let taken = jit.stats().links_taken;
        let chains = jit.stats().chains;
        st = CpuState::new();
        st.rip = CODE;
        st.gpr[4] = 0x8800;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 33 });
        assert_eq!(jit.stats().chains - chains, 1, "one entry into native code");
        assert_eq!(
            jit.stats().links_taken - taken,
            23,
            "every transition, the eight returns included, was a native link"
        );
    }

    #[test]
    fn a_return_to_a_new_target_misses_the_cache_and_still_lands() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
        mem.map(Region::new("stack", 0x8000, 0x1000, Perm::RW)).unwrap();
        mem.poke(CODE, &[0xC3]).unwrap();
        mem.poke(CODE + 0x40, &[0xB8, 0x07, 0x00, 0x00, 0x00, DECLINED]).unwrap();
        mem.poke(CODE + 0x80, &[0xB8, 0x09, 0x00, 0x00, 0x00, DECLINED]).unwrap();
        let mut jit = Jit::new(64 * 1024).unwrap();

        for (round, (slot, want, links)) in
            [(CODE + 0x40, 7u64, 0), (CODE + 0x40, 7, 1), (CODE + 0x80, 9, 0)].iter().enumerate()
        {
            mem.write_u64(0x8800, *slot).unwrap();
            let before = jit.stats().links_taken;
            let mut st = CpuState::new();
            st.rip = CODE;
            st.gpr[4] = 0x8800;
            jit.run(&mut st, &mut mem, Mode::Long, 1000);
            assert_eq!(st.gpr[0], *want, "round {round}: the ret to {slot:#x} ran the wrong block");
            assert_eq!(st.gpr[4], 0x8808, "round {round}: rsp moved by exactly one slot");
            assert_eq!(
                jit.stats().links_taken - before,
                *links,
                "round {round}: the cached target must be taken only when it is the one popped"
            );
        }
    }

    #[test]
    fn a_data_store_next_to_the_code_does_not_break_the_links() {
        let mut mem = mem_with(&LOOP);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        jit.run(&mut st, &mut mem, Mode::Long, 1000);
        let unlinks = jit.stats().unlinks;

        let store = [0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, DECLINED];
        mem.poke(DATA, &store).unwrap();
        mem.map(Region::new("more", DATA + 0x1000, 0x1000, Perm::RWX)).unwrap();
        mem.poke(DATA + 0x1000, &store).unwrap();
        let mut s2 = CpuState::new();
        s2.rip = DATA + 0x1000;
        jit.run(&mut s2, &mut mem, Mode::Long, 1000);
        assert_eq!(jit.stats().unlinks, unlinks, "a data store broke the links");
    }
}
