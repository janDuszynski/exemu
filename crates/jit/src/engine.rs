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
    /// `insns` guest instructions executed; `rip` is correct and the caller can
    /// simply loop.
    Executed { insns: u32 },
    /// `insns` executed, then an access faulted: guest state is exactly as it
    /// was before the faulting instruction and `rip` points at it. The caller
    /// must run **one** instruction on the interpreter, which raises the real
    /// error.
    Faulted { insns: u32 },
    /// Nothing compiled at this address: the caller interprets one instruction
    /// and comes back.
    NotCompiled,
}

/// Counters for reporting real coverage rather than claimed coverage.
#[derive(Clone, Debug, Default)]
pub struct JitStats {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub insns_executed: u64,
    /// Times a block ended by rewinding to a faulting access.
    pub faults: u64,
    /// Times `run` found nothing to execute (the interpreter took the
    /// instruction).
    pub not_compiled: u64,
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
}

/// Direct-mapped lookup in front of the block map: one compare on the hot path.
/// A line is live only while its `gen` matches the engine's, so a flush is O(1)
/// in the line array rather than a walk over all 8192 of them.
#[derive(Clone, Copy)]
struct CacheLine {
    rip: u64,
    idx: u32,
    gen: u32,
}

const LINES: usize = 8192;

pub struct Jit {
    buffer: CodeBuffer,
    mode: Mode,
    blocks: Vec<Block>,
    map: HashMap<u64, u32>,
    lines: Vec<CacheLine>,
    /// Bumped on every flush; a cache line is live only at the current value.
    cache_gen: u32,
    /// `Memory::code_generation()` the cache was built against.
    code_gen: u64,
    stats: JitStats,
    max_insns: u32,
}

impl Jit {
    /// Create a JIT with a `capacity`-byte code buffer.
    pub fn new(mode: Mode, capacity: usize) -> Result<Jit, BufferError> {
        Ok(Jit {
            buffer: CodeBuffer::with_capacity(capacity)?,
            mode,
            blocks: Vec::new(),
            map: HashMap::new(),
            lines: vec![CacheLine { rip: 0, idx: 0, gen: 0 }; LINES],
            cache_gen: 1,
            code_gen: 0,
            stats: JitStats::default(),
            max_insns: MAX_INSNS,
        })
    }

    pub fn stats(&self) -> &JitStats {
        &self.stats
    }

    pub fn mode(&self) -> Mode {
        self.mode
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
    fn line_of(rip: u64) -> usize {
        (rip.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 51) as usize & (LINES - 1)
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

    /// Compile (or find) the block at `rip` and return its index.
    fn block_at(&mut self, rip: u64, mem: &dyn Memory) -> u32 {
        let line = Self::line_of(rip);
        let l = self.lines[line];
        if l.gen == self.cache_gen && l.rip == rip {
            return l.idx;
        }
        if let Some(&idx) = self.map.get(&rip) {
            self.lines[line] = CacheLine { rip, idx, gen: self.cache_gen };
            return idx;
        }
        let plan = Compiler::compile(mem, self.mode, rip, self.max_insns);
        if let StopReason::Unsupported { opcode, rip: at, esc } = plan.stop {
            if at == rip {
                // Nothing compiled here at all — remember the reason so the
                // coverage report is measured rather than guessed.
                let key = opcode as u16 | if esc { 0x100 } else { 0 };
                *self.stats.declined.entry(key).or_insert(0) += 1;
            }
        }
        let block = if plan.insns == 0 {
            Block { code: None, insns: 0 }
        } else {
            match self.buffer.push(&plan.code) {
                Ok(code) => {
                    self.stats.blocks_compiled += 1;
                    self.stats.peak_code_bytes = self.stats.peak_code_bytes.max(self.buffer.used());
                    Block { code: Some(code), insns: plan.insns }
                }
                Err(_) => {
                    // Out of code space: drop everything and try once more, so a
                    // long-running process recycles instead of degrading to the
                    // interpreter forever.
                    self.flush();
                    match self.buffer.push(&plan.code) {
                        Ok(code) => {
                            self.stats.blocks_compiled += 1;
                            Block { code: Some(code), insns: plan.insns }
                        }
                        Err(_) => Block { code: None, insns: 0 },
                    }
                }
            }
        };
        let idx = self.blocks.len() as u32;
        self.blocks.push(block);
        self.map.insert(rip, idx);
        self.lines[Self::line_of(rip)] = CacheLine { rip, idx, gen: self.cache_gen };
        idx
    }

    /// Execute the block at `state.rip`, if there is one.
    pub fn run(&mut self, state: &mut CpuState, mem: &mut dyn Memory) -> Run {
        // Guest code may have changed since the cache was built (roadmap W1.7).
        // One `u64` compare answers "did *any* executable byte change?"; a
        // change throws the cache away, which is coarse but always correct.
        // (Per-page invalidation is W8.5.)
        let gen = mem.code_generation();
        if gen != self.code_gen {
            self.flush();
            self.code_gen = gen;
        }
        let rip = state.rip;
        let idx = self.block_at(rip, &*mem) as usize;
        let (code, insns) = match &self.blocks[idx] {
            Block { code: Some(c), insns } => (*c, *insns),
            _ => {
                self.stats.not_compiled += 1;
                return Run::NotCompiled;
            }
        };
        let ret = {
            let mut ctx = BlockCtx {
                mem,
                parity: PARITY.as_ptr(),
                code_gen: gen,
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
        let retired = (ret & 0xffff_ffff) as u32;
        debug_assert!(retired <= insns, "block reported more instructions than it holds");
        self.stats.blocks_executed += 1;
        self.stats.insns_executed += retired as u64;
        if ret & RET_FAULT != 0 {
            self.stats.faults += 1;
            Run::Faulted { insns: retired }
        } else {
            Run::Executed { insns: retired }
        }
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
        let mut jit = Jit::new(Mode::Long, 64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem);
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
        let mut jit = Jit::new(Mode::Long, 64 * 1024).unwrap();
        assert_eq!(jit.run(&mut st, &mut mem), Run::NotCompiled);
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
        let mut jit = Jit::new(Mode::Long, 64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem);
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
        let mut jit = Jit::new(Mode::Long, 64 * 1024).unwrap();
        assert_eq!(jit.run(&mut st, &mut mem), Run::Executed { insns: 2 });
        assert_eq!(st.rip, CODE + 6, "branch taken");
    }

    #[test]
    fn a_store_into_code_stops_the_block() {
        // mov byte [rip-relative code page], 0x90 — the store lands in the very
        // page being executed, so the block must stop right after it rather than
        // running instructions that may have just been rewritten.
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
        let code = [
            0xC6, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, 0x90, // mov byte [0x1000], 0x90
            0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
        ];
        mem.poke(CODE, &code).unwrap();
        let mut st = CpuState::new();
        st.rip = CODE;
        let mut jit = Jit::new(Mode::Long, 64 * 1024).unwrap();
        let r = jit.run(&mut st, &mut mem);
        assert_eq!(r, Run::Executed { insns: 1 }, "stopped after the self-modifying store");
        assert_eq!(st.rip, CODE + 8);
        assert_eq!(st.gpr[0], 0, "the instruction after the store did NOT run");
        // And the next call recompiles from the modified bytes.
        let before = jit.stats().flushes;
        jit.run(&mut st, &mut mem);
        assert!(jit.stats().flushes > before, "the cache was invalidated");
    }
}
