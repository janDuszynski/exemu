//! The block cache and the guest→native entry point.
//!
//! One [`Jit`] belongs to one guest thread. It owns a [`CodeBuffer`], a map from
//! guest address to compiled block, and the snapshot of
//! [`Memory::code_generation`] the cache is valid against.

use std::collections::HashMap;

use exemu_core::cpu::CpuState;
use exemu_core::Memory;

use crate::buffer::{BlockCode, BufferError, CodeBuffer};
use crate::compile::{Compiler, StopReason, MAX_INSNS, RET_FAULT};
use crate::rt::{jit_read, jit_write, BlockCtx, PARITY};

pub use crate::compile::Mode;

/// The ABI every compiled block is emitted with.
type BlockFn = unsafe extern "C" fn(*mut CpuState, *mut BlockCtx<'_>) -> u64;

/// What one [`Jit::run`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    /// `insns` guest instructions executed and the run stopped because the
    /// **budget** ran out, not because it had to. `rip` sits on a boundary the
    /// JIT could have carried on from, so the caller does its per-budget
    /// bookkeeping and comes straight back.
    Executed { insns: u32 },
    /// `insns` executed, and then the chain reached an address with no compiled
    /// block. The caller must account `insns`, then interpret **one**
    /// instruction before coming back.
    SideExit { insns: u32 },
    /// `insns` executed, then an access faulted: guest state is exactly as it
    /// was before the faulting instruction and `rip` points at it. The caller
    /// must run **one** instruction on the interpreter, which raises the real
    /// error.
    Faulted { insns: u32 },
    /// Nothing compiled at this address: the caller interprets one instruction
    /// and comes back. (`SideExit { insns: 0 }`, named separately because the
    /// caller has no accounting to do for it.)
    NotCompiled,
}

impl Run {
    /// Guest instructions this call executed natively.
    pub fn insns(self) -> u32 {
        match self {
            Run::NotCompiled => 0,
            Run::Executed { insns } | Run::SideExit { insns } | Run::Faulted { insns } => insns,
        }
    }
}

/// Counters for reporting real coverage rather than claimed coverage.
#[derive(Clone, Debug, Default)]
pub struct JitStats {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub insns_executed: u64,
    /// Times a block ended by rewinding to a faulting access.
    pub faults: u64,
    /// Times a chain ended because nothing was compiled at the address it
    /// reached (the interpreter took that instruction).
    pub not_compiled: u64,
    /// Times [`Jit::run`] was entered — the number of round trips through the
    /// caller's run loop, as opposed to `blocks_executed`, which counts blocks.
    /// Their ratio is the chain length (roadmap W8.5).
    pub chains: u64,
    /// Times the whole cache was thrown away because guest code changed.
    pub flushes: u64,
    /// High-water mark of emitted native code, in bytes. (`Jit::code_bytes`
    /// reports what is live *now*, which a flush resets.)
    pub peak_code_bytes: usize,
    /// Guest instructions the interpreter had to take because the block ended
    /// on an opcode the compiler declines, counted per first opcode byte.
    pub declined: HashMap<u16, u64>,
}

impl JitStats {
    /// The declined opcodes, most frequent first, as `(key, count)` where the
    /// key is `opcode | 0x100` for `0F`-escaped opcodes.
    pub fn top_declined(&self, n: usize) -> Vec<(u16, u64)> {
        let mut v: Vec<(u16, u64)> = self.declined.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(n);
        v
    }
}

struct Block {
    code: Option<BlockCode>,
    insns: u32,
    /// Guest address range the block was compiled from (handed to the store
    /// helper so it can spot a store into the block's own instructions).
    lo: u64,
    hi: u64,
    /// The (at most two) 4 KiB code pages the block covers, and the
    /// `Memory::code_page_generation` each had when it was compiled.
    page0: u64,
    page1: u64,
    gen0: u64,
    gen1: u64,
    /// `Memory::code_generation()` at the last moment this block was known
    /// valid. While the global counter has not moved since, no per-page check is
    /// needed at all — which is the common case, and keeps block entry to one
    /// `u64` compare.
    global_gen: u64,
}

/// Direct-mapped lookup in front of the block map: one compare on the hot path.
/// A line is live only while its `gen` matches the engine's, so a flush is O(1)
/// in the line array rather than a walk over all 8192 of them.
#[derive(Clone, Copy)]
struct CacheLine {
    rip: u64,
    idx: u32,
    gen: u32,
    long: bool,
}

const LINES: usize = 8192;

/// Block entry addresses kept for the fault reporter. A power of two so the
/// ring index is a mask.
const TRAIL: usize = 32;

pub struct Jit {
    buffer: CodeBuffer,
    blocks: Vec<Block>,
    /// Keyed by `(guest address, 64-bit mode)`. The mode is part of the key
    /// because the *same bytes* decode differently in the two modes — and a
    /// WoW64 guest really does run both, switching on every transition
    /// (roadmap W5.2). Keying them apart lets both stay cached instead of
    /// flushing on every switch.
    map: HashMap<(u64, bool), u32>,
    lines: Vec<CacheLine>,
    /// Bumped on every flush; a cache line is live only at the current value.
    cache_gen: u32,
    /// `Memory::code_generation()` the cache was built against.
    code_gen: u64,
    stats: JitStats,
    max_insns: u32,
    /// Ring of the block entry addresses most recently run, for the fault
    /// report (roadmap W8.5): with chaining, the caller's run loop sees one
    /// address per *chain*, so the history has to be kept here.
    trail: [u64; TRAIL],
    trail_at: u64,
}

impl Jit {
    /// Create a JIT with a `capacity`-byte code buffer. The guest CPU mode is
    /// passed per call to [`Jit::run`], not fixed here.
    pub fn new(capacity: usize) -> Result<Jit, BufferError> {
        Ok(Jit {
            buffer: CodeBuffer::with_capacity(capacity)?,
            blocks: Vec::new(),
            map: HashMap::new(),
            lines: vec![CacheLine { rip: 0, idx: 0, gen: 0, long: false }; LINES],
            cache_gen: 1,
            code_gen: 0,
            stats: JitStats::default(),
            max_insns: MAX_INSNS,
            trail: [0; TRAIL],
            trail_at: 0,
        })
    }

    pub fn stats(&self) -> &JitStats {
        &self.stats
    }

    /// Cap the number of guest instructions per block (the differential uses
    /// this to compile exactly one instruction at a time).
    pub fn set_max_insns(&mut self, n: u32) {
        self.max_insns = n.max(1);
    }

    /// Bytes of native code emitted so far.
    pub fn code_bytes(&self) -> usize {
        self.buffer.used()
    }

    #[inline]
    fn line_of(rip: u64, long: bool) -> usize {
        (rip.wrapping_add(long as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 51) as usize
            & (LINES - 1)
    }

    /// Throw the whole cache away. Called when guest code changed underneath it
    /// (the roadmap W1.7 seam) or when the code buffer fills up.
    fn flush(&mut self) {
        self.buffer.reset();
        self.blocks.clear();
        self.map.clear();
        self.cache_gen = self.cache_gen.wrapping_add(1);
        if self.cache_gen == 0 {
            // Only on wrap: make sure no ancient line can alias generation 0.
            for l in self.lines.iter_mut() {
                l.gen = 0;
            }
            self.cache_gen = 1;
        }
        self.stats.flushes += 1;
    }

    /// Drop every compiled block and forget which memory the cache was built
    /// against. For callers that reuse one engine across *different* guest
    /// images (the differential harness builds a fresh address space per trial).
    pub fn invalidate(&mut self) {
        self.flush();
        self.code_gen = 0;
    }

    /// Compile (or find) the block at `rip` in `mode` and return its index.
    fn block_at(&mut self, rip: u64, mode: Mode, mem: &dyn Memory) -> u32 {
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
        let plan = Compiler::compile(mem, mode, rip, self.max_insns);
        let lo = plan.start;
        let hi = plan.end_rip.max(plan.start);
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
                // Nothing compiled here at all — remember the reason so the
                // coverage report is measured rather than guessed.
                let key = opcode as u16 | if esc { 0x100 } else { 0 };
                *self.stats.declined.entry(key).or_insert(0) += 1;
            }
        }
        let mk = |code: Option<BlockCode>, insns: u32| Block {
            code,
            insns,
            lo: meta.0,
            hi: meta.1,
            page0: meta.2,
            page1: meta.3,
            gen0: meta.4,
            gen1: meta.5,
            global_gen: meta.6,
        };
        let block = if plan.insns == 0 {
            mk(None, 0)
        } else {
            match self.buffer.push(&plan.code) {
                Ok(code) => {
                    self.stats.blocks_compiled += 1;
                    self.stats.peak_code_bytes = self.stats.peak_code_bytes.max(self.buffer.used());
                    mk(Some(code), plan.insns)
                }
                Err(_) => {
                    // Out of code space: drop everything and try once more, so a
                    // long-running process recycles instead of degrading to the
                    // interpreter forever.
                    self.flush();
                    match self.buffer.push(&plan.code) {
                        Ok(code) => {
                            self.stats.blocks_compiled += 1;
                            mk(Some(code), plan.insns)
                        }
                        Err(_) => mk(None, 0),
                    }
                }
            }
        };
        let idx = self.blocks.len() as u32;
        self.blocks.push(block);
        self.map.insert((rip, long), idx);
        self.lines[Self::line_of(rip, long)] = CacheLine { rip, idx, gen: self.cache_gen, long };
        idx
    }

    /// Is the cached block still the code that is actually in guest memory?
    ///
    /// Cheap path: the global code-generation counter (roadmap W1.7) has not
    /// moved since this block was last known good, so nothing executable
    /// anywhere has changed. Otherwise fall back to the per-page generations for
    /// the pages this block covers, and — if they are unchanged — re-stamp the
    /// block so the next entry is cheap again.
    ///
    /// The distinction matters enormously in practice: exemu maps PE sections
    /// RWX, so an ordinary store into the image's `.data` bumps the *global*
    /// counter. Treating that as "code changed" throws the entire cache away on
    /// almost every store, which measured **40× slower than the interpreter** on
    /// SteamSetup (an NSIS installer that decompresses into its own image)
    /// before this check was made page-precise.
    fn validate(&mut self, idx: usize, mem: &dyn Memory) -> bool {
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

    /// Run compiled blocks from `state.rip`, one after another, until `budget`
    /// guest instructions have retired or the chain has to stop (roadmap W8.5).
    ///
    /// `mode` is the *interpreter's current* mode, not a property of the image:
    /// a WoW64 process runs 32- and 64-bit code in the same address space, and
    /// the same bytes mean different things in each.
    ///
    /// # The budget is a correctness parameter, not a tuning knob
    ///
    /// A compiled block leaves `rip` on the next block, so the JIT could in
    /// principle run forever without returning. It must not, because the caller
    /// does things *between* blocks that the guest can observe: timeslice
    /// preemption, the `KUSER_SHARED_DATA` clock refresh, the step cap. `budget`
    /// is how many instructions the caller can afford before it has to look
    /// again, and the rule this loop obeys is:
    ///
    /// > run a block, add up what it retired, and stop as soon as the running
    /// > total has **reached** the budget.
    ///
    /// It deliberately does *not* refuse to start a block that might overshoot.
    /// That is what makes chaining invisible: block-at-a-time, the caller
    /// accumulated the same per-block counts and acted at the first block
    /// boundary where the total crossed its threshold — which is exactly the
    /// boundary this loop returns on. Preemption and the clock refresh therefore
    /// fire at the same instruction they did before, and the corpus pins do not
    /// move. A `budget` of 0 or 1 means "one block", which is what the
    /// differential harness uses.
    pub fn run(&mut self, state: &mut CpuState, mem: &mut dyn Memory, mode: Mode, budget: u64) -> Run {
        self.stats.chains += 1;
        // The running total is reported in a `u32` and a block adds at most
        // `MAX_INSNS` to it, so cap the budget well clear of the edge rather
        // than trusting every caller to. `u64::MAX` — the default budget of a
        // hook with no notion of time — lands here.
        let budget = budget.min(u32::MAX as u64 - MAX_INSNS as u64);
        let mut retired: u64 = 0;
        loop {
            let rip = state.rip;
            // The block-entry trail, for the fault reporter: with chaining the
            // caller's run loop only sees one address per chain, so the JIT has
            // to keep the trail itself or a fault would come with no history of
            // how the guest got there.
            self.trail[self.trail_at as usize & (TRAIL - 1)] = rip;
            self.trail_at = self.trail_at.wrapping_add(1);

            let mut idx = self.block_at(rip, mode, &*mem) as usize;
            if !self.validate(idx, &*mem) {
                // The bytes under a cached block changed. Invalidation is still
                // whole-cache (indexing pages back to the blocks that cover them
                // is W8.5's next step); what matters here is that it now happens
                // only when guest *code* really changed.
                self.flush();
                idx = self.block_at(rip, mode, &*mem) as usize;
            }
            let (code, insns, lo, hi) = match &self.blocks[idx] {
                Block { code: Some(c), insns, lo, hi, .. } => (*c, *insns, *lo, *hi),
                _ => {
                    // Nothing here. The caller interprets this one instruction —
                    // and is told how much ran first, so it can account for it
                    // before doing so.
                    self.stats.not_compiled += 1;
                    return if retired == 0 {
                        Run::NotCompiled
                    } else {
                        Run::SideExit { insns: retired as u32 }
                    };
                }
            };
            let ret = {
                let mut ctx = BlockCtx {
                    mem,
                    parity: PARITY.as_ptr(),
                    code_lo: lo,
                    code_hi: hi,
                    read: jit_read,
                    write: jit_write,
                };
                // SAFETY: `code` was produced by this crate's emitter for exactly
                // this signature and written into `self.buffer`, which is still
                // alive and has not been reset since (a reset only happens in
                // `flush`, which needs `&mut self` and therefore cannot run while
                // this call is in progress). The block only writes through the two
                // pointers below: the `CpuState` — for which no other reference is
                // live across the call — and the `BlockCtx` on this stack frame.
                unsafe {
                    let f: BlockFn = code.as_fn();
                    f(state as *mut CpuState, &mut ctx as *mut BlockCtx)
                }
            };
            let n = (ret & 0xffff_ffff) as u32;
            debug_assert!(n <= insns, "block reported more instructions than it holds");
            self.stats.blocks_executed += 1;
            self.stats.insns_executed += n as u64;
            retired += n as u64;
            if ret & RET_FAULT != 0 {
                self.stats.faults += 1;
                return Run::Faulted { insns: retired as u32 };
            }
            if retired >= budget {
                return Run::Executed { insns: retired as u32 };
            }
        }
    }

    /// The most recent block entry addresses, oldest first — the rip trail the
    /// fault reporter prints. Chaining moves this bookkeeping in here, because
    /// the caller's loop no longer sees every block.
    pub fn recent_blocks(&self) -> Vec<u64> {
        let n = (self.trail_at as usize).min(TRAIL);
        (0..n)
            .map(|i| self.trail[(self.trail_at as usize + TRAIL - n + i) & (TRAIL - 1)])
            .collect()
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use exemu_core::{Perm, Region};
    use exemu_memory::VirtualMemory;

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
        // mov eax, 5 ; add eax, 7 ; ret. `ret` is not compiled, so it is where
        // the block stops — without a terminator the compiler would keep going
        // into whatever the rest of the page decodes as (zeros are a perfectly
        // valid `add [rax], al`).
        let code = [
            0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0x83, 0xC0, 0x07, // add eax, 7
            0xC3, // ret (declined -> ends the block)
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 1);
        assert_eq!(r, Run::Executed { insns: 2 });
        assert_eq!(st.gpr[0], 12);
        assert_eq!(st.rip, CODE + 8);
    }

    #[test]
    fn declines_what_it_cannot_prove() {
        // `cpuid` is not compiled: the block must be empty and the caller told.
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
        // mov eax, 1 ; mov ecx, [rdx] with rdx unmapped.
        let code = [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x8B, 0x0A, // mov ecx, [rdx]
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        st.gpr[2] = 0xDEAD_0000; // unmapped
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 1);
        assert_eq!(r, Run::Faulted { insns: 1 });
        assert_eq!(st.gpr[0], 1, "the first instruction did run");
        assert_eq!(st.rip, CODE + 5, "rip rewound to the faulting instruction");
    }

    #[test]
    fn a_taken_branch_is_compiled_and_sets_rip() {
        // xor eax,eax ; je +2 ; (skipped) ; ...
        let code = [
            0x31, 0xC0, // xor eax, eax  -> ZF=1
            0x74, 0x02, // je +2
        ];
        let mut mem = mem_with(&code);
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 2 });
        assert_eq!(st.rip, CODE + 6, "branch taken");
    }

    #[test]
    fn a_store_into_this_blocks_own_code_stops_the_block() {
        // The store lands in the very bytes this block was compiled from, so it
        // must commit that instruction and stop rather than run instructions
        // that may have just been rewritten underneath the compiled code.
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        let code = [
            0xC6, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, 0x90, // mov byte [0x1000], 0x90
            0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
            0xC3,
        ];
        mem.poke(CODE, &code).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem, Mode::Long, 1);
        assert_eq!(r, Run::Executed { insns: 1 }, "stopped after the self-modifying store");
        assert_eq!(st.rip, CODE + 8);
        assert_eq!(st.gpr[0], 0, "the instruction after the store did NOT run");
    }

    #[test]
    fn a_store_into_another_block_invalidates_it() {
        // Block B is cached; block A rewrites B's bytes; B must then be
        // recompiled from what is actually in guest memory.
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        // A @ CODE: mov byte [CODE+0x41], 2 ; ret
        let a = [0xC6, 0x04, 0x25, 0x41, 0x10, 0x00, 0x00, 0x02, 0xC3];
        // B @ CODE+0x40: mov eax, 1 ; ret
        let b = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
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

    /// A WoW64 guest runs 32- and 64-bit code in one address space, switching on
    /// every transition — so the block cache is keyed by mode, not just by
    /// address. These bytes mean genuinely different things in the two modes:
    /// `48 FF C0` is `inc rax` in long mode, but `dec eax` followed by
    /// `inc eax` in protected mode.
    #[test]
    fn the_same_bytes_are_cached_separately_per_cpu_mode() {
        let code = [0x48, 0xFF, 0xC0, 0xC3];
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
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Protected, 1), Run::Executed { insns: 2 });
        assert_eq!(st.gpr[0], 5, "protected mode: `dec eax` then `inc eax`");
        assert_eq!(st.rip, CODE + 3);

        // And back again, from the cache rather than a recompile.
        st.rip = CODE;
        st.gpr[0] = 5;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 1 });
        assert_eq!(st.gpr[0], 6);
        assert_eq!(jit.stats().flushes, 0, "switching modes must not flush");
    }

    #[test]
    fn a_data_store_does_not_invalidate_anything() {
        // The regression this guards: exemu maps PE sections RWX, so an ordinary
        // store into `.data` moves the *global* code-generation counter. Treating
        // that as "code changed" throws the whole cache away on nearly every
        // store — measured at 40x SLOWER than the interpreter on SteamSetup
        // before the check was made page-precise.
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        mem.map(Region::new("data", DATA, 0x1000, Perm::RWX)).unwrap();
        // mov byte [DATA], 1 ; ret
        let code = [0xC6, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x01, 0xC3];
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

    // -----------------------------------------------------------------------
    // Block chaining (roadmap W8.5)
    // -----------------------------------------------------------------------

    /// Three blocks back to back. `jmp` is a block *terminator* — it is compiled,
    /// and it ends the block — so this is 2 + 2 + 1 guest instructions in three
    /// blocks, followed by a `ret` the compiler declines.
    const CHAIN: [u8; 16] = [
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5      | block 1
        0xEB, 0x00, //                                   | jmp +0
        0x83, 0xC0, 0x07, //             add eax, 7      | block 2
        0xEB, 0x00, //                                   | jmp +0
        0x83, 0xC0, 0x09, //             add eax, 9      | block 3
        0xC3, //                         ret (declined)
    ];

    #[test]
    fn a_chain_runs_every_block_it_can_in_one_call() {
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();

        // Budget 1 is "one block", which is what the differential harness uses.
        st.rip = CODE;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1), Run::Executed { insns: 2 });
        assert_eq!(st.rip, CODE + 7);
        assert_eq!(jit.stats().blocks_executed, 1);

        // With a real budget the same three blocks run in ONE entry, and the
        // chain ends only where it must: the `ret`, which has no compiled block.
        st.rip = CODE;
        st.gpr[0] = 0;
        let chains = jit.stats().chains;
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 1000), Run::SideExit { insns: 5 });
        assert_eq!(st.gpr[0], 21, "all three blocks ran (5 + 7 + 9)");
        assert_eq!(st.rip, CODE + 15, "left sitting on the `ret`");
        assert_eq!(jit.stats().chains, chains + 1, "three blocks, one entry");
    }

    #[test]
    fn the_budget_stops_the_chain_at_the_first_boundary_that_reaches_it() {
        // The rule the whole design rests on: stop at the first block boundary
        // at which the running total has REACHED the budget — never refuse to
        // start a block because it might overshoot. Block-at-a-time, the caller
        // accumulated the same per-block counts and acted at that same boundary,
        // so preemption and the clock refresh keep firing where they did and the
        // corpus pins do not move.
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        // Blocks retire 2, 2, 1. A budget of 3 is reached by the end of block
        // two, which has by then retired 4 — the overshoot is the point.
        assert_eq!(jit.run(&mut st, &mut mem, Mode::Long, 3), Run::Executed { insns: 4 });
        assert_eq!(st.rip, CODE + 12, "stopped on a block boundary, not mid-block");
        assert_eq!(jit.stats().blocks_executed, 2);
    }

    #[test]
    fn a_chain_and_a_sequence_of_single_blocks_are_the_same_run() {
        // Chaining may change how often the caller is consulted; it may not
        // change what the guest computes, nor how many instructions it takes.
        let mut mem = mem_with(&CHAIN);
        let mut one = Jit::new(64 * 1024).unwrap();
        let mut many = Jit::new(64 * 1024).unwrap();
        let (mut a, mut b) = (CpuState::new(), CpuState::new());
        a.rip = CODE;
        b.rip = CODE;

        let mut stepped = 0u32;
        loop {
            match one.run(&mut a, &mut mem, Mode::Long, 1) {
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
        // With chaining the caller's run loop sees one address per chain, so a
        // fault report would lose the history of how the guest got there unless
        // the JIT keeps it. This is that history.
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
        // A 500M-instruction run enters hundreds of millions of blocks; the ring
        // has to hand back the *last* few in order, not the first few.
        let mut mem = mem_with(&CHAIN);
        let mut jit = Jit::new(64 * 1024).unwrap();
        let mut st = CpuState::new();
        for _ in 0..40 {
            st.rip = CODE;
            jit.run(&mut st, &mut mem, Mode::Long, 1);
        }
        let t = jit.recent_blocks();
        assert_eq!(t.len(), TRAIL, "the ring is full");
        assert!(t.iter().all(|&r| r == CODE), "and holds the entries, not zeroes");
    }
}
