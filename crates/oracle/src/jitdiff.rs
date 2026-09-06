//! JIT-vs-interpreter differential (roadmap W8.7).
//!
//! The Unicorn oracle answers "is the interpreter a real x86?". This answers the
//! other question, the one the JIT lives or dies by: **is the JIT the same
//! machine as the interpreter, bit for bit?** It is deliberately a *different
//! shape* of test:
//!
//! * No reference emulator, and therefore **no defined-flags policy**. Against
//!   Unicorn, flags x86 leaves architecturally undefined must be excluded from
//!   the diff because two correct CPUs may differ. Against the interpreter there
//!   is no such licence: whatever the interpreter leaves in `rflags` — including
//!   AF, including the bits x86 calls undefined — the JIT must leave too. Every
//!   bit of every GPR, `rflags`, `rip`, the vector file and every byte of guest
//!   memory is compared for equality.
//! * No GPL dependency, so it runs in the ordinary `cargo test --workspace`
//!   gate rather than behind the `unicorn` feature.
//!
//! The comparison is driven by what the JIT actually did: a block reports how
//! many guest instructions it retired, the interpreter is then stepped *exactly
//! that many times* from the identical start state, and the two architectural
//! states must be equal. Three further properties are checked on the way:
//!
//! * a block that the compiler **declines** must leave the state completely
//!   untouched (`NotCompiled` is a promise, not just a hint);
//! * a block that **faults** must have rewound onto an instruction that really
//!   does fault on the interpreter — a spurious fault would be invisible in the
//!   state diff, but it means an address computation is wrong;
//! * the interpreter must not stop early inside the window the JIT claimed.
//!
//! # Where the trial is assembled is part of the trial
//!
//! For a long time every trial was assembled at the base of a low page, which
//! made the differential structurally blind to a whole class of disagreement:
//! **the address-width rule**. In 32-bit mode every architectural address the
//! CPU produces is masked to 32 bits — `rip` after any instruction, a branch
//! target, an effective address, `esp` after a push or a pop — and in 64-bit
//! mode none of them is. A trial that never computes an address near 2^32 can
//! never tell a CPU that masks from one that does not.
//!
//! So a trial now also picks a [`Layout`]: where its code, stack and pointer
//! operands live. [`Layout::EdgeCode`] puts the code flush against the top of
//! the 32-bit address space (or above 4 GiB in long mode), so `rip` itself
//! crosses the boundary and the last instructions are fetched through the
//! compiler's short-window path; [`Layout::EdgeData`] leaves the code low but
//! puts the stack and the base pointer on the boundary, so effective addresses
//! and `esp` cross it. Alongside that the generator emits **boundary shapes** —
//! push/pop/leave, near branches, and `[rbp+disp]` accesses — because the
//! integer stream the Unicorn oracle shares contains no control flow and never
//! touches the stack.

use crate::gen::{self, Seed};
use crate::rng::Rng;
use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const PAGE: u64 = 0x1000;
/// The historical code base: a low page with nothing interesting near it.
const LOW_CODE: u64 = 0x1000;
/// A low stack, for the layouts that are not testing the stack pointer.
const LOW_STACK: u64 = 0x8000;
/// The last page below 4 GiB.
const TOP32: u64 = 0xFFFF_F000;
/// The first page above 4 GiB.
const HIGH64: u64 = 0x1_0000_0000;

/// Where a trial's code, stack and pointer operands live.
///
/// The three answers differ only near an address boundary, which is exactly
/// where a JIT and an interpreter can disagree without either looking wrong on
/// its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// Low code, low stack, low pointers. Nothing an instruction computes ever
    /// crosses a boundary — the shape every trial had before roadmap W8.7.
    Low,
    /// The code is flush against the top of the address space (32-bit) or sits
    /// above 4 GiB (64-bit), so `rip` and every branch target cross the
    /// boundary — and the trial's last instructions are fetched through the
    /// compiler's short-window path, at the tail of an executable region.
    EdgeCode,
    /// Low code, but the stack and the base pointer sit on the boundary, so
    /// effective addresses and `esp` cross it.
    EdgeData,
}

impl Layout {
    pub const ALL: [Layout; 3] = [Layout::Low, Layout::EdgeCode, Layout::EdgeData];

    /// Index into [`JitSummary::by_layout`].
    pub fn index(self) -> usize {
        match self {
            Layout::Low => 0,
            Layout::EdgeCode => 1,
            Layout::EdgeData => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Layout::Low => "low",
            Layout::EdgeCode => "edge-code",
            Layout::EdgeData => "edge-data",
        }
    }
}

/// Which layouts a run draws from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutMix {
    /// Only [`Layout::Low`] — the pre-W8.7 shape, kept so an old run can be
    /// reproduced exactly.
    Low,
    /// Only the two boundary layouts.
    Edge,
    /// Half low, a quarter each of the two boundary layouts.
    Mixed,
}

impl LayoutMix {
    fn pick(self, rng: &mut Rng) -> Layout {
        match self {
            LayoutMix::Low => Layout::Low,
            LayoutMix::Edge => {
                if rng.boolean() {
                    Layout::EdgeCode
                } else {
                    Layout::EdgeData
                }
            }
            LayoutMix::Mixed => match rng.below(4) {
                0 => Layout::EdgeCode,
                1 => Layout::EdgeData,
                _ => Layout::Low,
            },
        }
    }
}

/// The address space one trial runs in.
struct Space {
    /// `(name, base, len, perm)`, in map order.
    regions: Vec<(&'static str, u64, u64, Perm)>,
    /// Base of the region the code goes in, and its length.
    code_base: u64,
    code_len: u64,
    /// Assemble the trial flush against the *end* of the code region rather
    /// than at its base.
    flush: bool,
    /// Value seeded into `rsp`.
    sp: u64,
    /// A pointer whose `[rbp+disp8]` operands cross the boundary.
    wrap_base: u64,
    /// `rsp` a push shape installs, chosen so the push itself crosses.
    push_sp: u64,
    /// `rsp` a pop shape installs, chosen so the pop itself crosses.
    pop_sp: u64,
}

/// Extra bytes appended to the data and stack regions in a **roomy** trial.
///
/// The JIT's guest-memory TLB (roadmap W8.6) caches a page only when the whole
/// page *plus the seven bytes an 8-byte access at its last byte reaches* is
/// inside one region — so a region exactly one page long is never cached, and
/// every region in this harness was exactly one page long. The differential was
/// therefore **structurally unable to execute the fast path at all**: 2 M trials
/// of "zero divergences" said nothing whatever about it.
///
/// Rather than grow every region — which would quietly delete the fault
/// coverage the one-page regions exist for, since a push that used to run off
/// the end would now succeed — roominess is drawn per trial like the layout is.
/// Half the trials are exactly what they always were; half have the slack that
/// lets the fast path engage. Both halves are compared the same way.
const ROOM: u64 = PAGE;

fn space(layout: Layout, bits: Bits, roomy: bool) -> Space {
    let room = if roomy { ROOM } else { 0 };
    let data = (
        "data",
        gen::DATA_BASE,
        gen::DATA_LEN as u64 + room,
        Perm::RW,
    );
    // The stack grows *upward* for slack, which is fine everywhere except where
    // the region is deliberately flush against the top of the address space —
    // `EdgeData`'s, whose whole point is that a push carries past the boundary.
    // Those stay one page and stay on the helper, which is itself the right
    // answer: a fast path must not serve an access there.
    let stack_room = match (layout, bits) {
        // The only stack that cannot grow: 32-bit `EdgeData` puts it flush
        // against 2^32, which is the entire point of that layout.
        (Layout::EdgeData, Bits::B32) => 0,
        _ => room,
    };
    match (layout, bits) {
        (Layout::Low, _) => Space {
            regions: vec![
                ("code", LOW_CODE, PAGE, Perm::RWX),
                data,
                ("stack", LOW_STACK, PAGE + stack_room, Perm::RW),
            ],
            code_base: LOW_CODE,
            code_len: PAGE,
            flush: false,
            sp: LOW_STACK + PAGE / 2,
            wrap_base: LOW_STACK + PAGE / 4,
            push_sp: LOW_STACK + PAGE / 2,
            pop_sp: LOW_STACK + PAGE / 2,
        },
        // 32-bit: the code ends exactly on 2^32 and page zero is mapped, so a
        // branch that carries over lands somewhere real — and `rip` itself
        // wraps when the block runs off the end.
        (Layout::EdgeCode, Bits::B32) => Space {
            regions: vec![
                ("code", TOP32, PAGE, Perm::RWX),
                ("zero", 0, PAGE, Perm::RW),
                data,
                ("stack", LOW_STACK, PAGE + stack_room, Perm::RW),
            ],
            code_base: TOP32,
            code_len: PAGE,
            flush: true,
            sp: LOW_STACK + PAGE / 2,
            wrap_base: 0xFFFF_FFF0,
            push_sp: LOW_STACK + PAGE / 2,
            pop_sp: LOW_STACK + PAGE / 2,
        },
        // 64-bit: the code lives above 4 GiB, where the rule is the opposite —
        // a stray 32-bit mask would send `rip` into unmapped low memory. No low
        // page is mapped on purpose, so such a mask cannot go unnoticed.
        (Layout::EdgeCode, Bits::B64) => Space {
            regions: vec![
                ("code", HIGH64, PAGE, Perm::RWX),
                data,
                ("stack", HIGH64 + PAGE, PAGE + stack_room, Perm::RW),
            ],
            code_base: HIGH64,
            code_len: PAGE,
            flush: false,
            sp: HIGH64 + PAGE + PAGE / 2,
            wrap_base: HIGH64 + PAGE / 2,
            push_sp: HIGH64 + PAGE + PAGE / 2,
            pop_sp: HIGH64 + PAGE + PAGE / 2,
        },
        // 32-bit: low code, but `esp` starts *on* the boundary, so a push
        // carries below zero and a pop carries past 2^32.
        (Layout::EdgeData, Bits::B32) => Space {
            regions: vec![
                ("code", LOW_CODE, PAGE, Perm::RWX),
                ("zero", 0, PAGE, Perm::RW),
                data,
                ("stack", TOP32, PAGE, Perm::RW),
            ],
            code_base: LOW_CODE,
            code_len: PAGE,
            flush: false,
            sp: 0,
            wrap_base: 0xFFFF_FFF0,
            push_sp: 0,
            pop_sp: 0xFFFF_FFFC,
        },
        (Layout::EdgeData, Bits::B64) => Space {
            regions: vec![
                ("code", LOW_CODE, PAGE, Perm::RWX),
                data,
                ("stack", HIGH64, PAGE + stack_room, Perm::RW),
            ],
            code_base: LOW_CODE,
            code_len: PAGE,
            flush: false,
            sp: HIGH64 + PAGE / 2,
            wrap_base: HIGH64 + PAGE / 4,
            push_sp: HIGH64 + PAGE / 2,
            pop_sp: HIGH64 + PAGE / 2,
        },
    }
}

/// One trial's verdict.
pub struct JitDivergence {
    pub index: u64,
    pub label: String,
    pub bytes: Vec<u8>,
    pub reason: String,
    pub layout: Layout,
    /// Guest address the trial was assembled at.
    pub at: u64,
}

pub struct JitFuzzConfig {
    pub bits: Bits,
    pub count: u64,
    pub seed: u64,
    pub max_report: usize,
    /// Guest instructions concatenated into one block per trial.
    pub chain: u32,
    /// Which address-space layouts trials are drawn from.
    pub layouts: LayoutMix,
    /// How many times a trial's instructions are run **round a loop**, which is
    /// what makes this differential able to see native block linking at all
    /// (roadmap W8.5).
    ///
    /// At the default of 1 a trial is one straight run of one block, and the
    /// engine is held to a budget of one block — the shape this harness has
    /// always measured. Above 1 the trial ends in a `jmp` back to its own first
    /// instruction instead of a `ret`, the block cap drops to
    /// [`LAP_MAX_INSNS`] so the body becomes several blocks, and the budget
    /// allows that many passes. The first pass creates the links; every pass
    /// after it takes them, so the bytes compared against the interpreter are
    /// the ones a *linked chain* produced.
    pub laps: u32,
    /// What the debugger has armed while the trial runs (roadmap W9.3).
    pub debug: DebugMix,
}

/// The debugger dimension of a trial.
///
/// The JIT's contribution to the debugger is a **negative guarantee** — never
/// run past an armed address — and a guarantee of that shape is exactly what a
/// hand-written test set is bad at: it proves the cases someone thought of. The
/// generator already produces the instruction stream, the layouts and the fault
/// shapes, so arming one thing per trial reuses all of it and asks the question
/// against the whole corpus instead.
///
/// The property checked is stronger than "the run still agrees". For each mode
/// the expected retired count is computed **independently of the JIT** — from
/// the interpreter's own trace — and the armed run must land on exactly it.
/// A JIT that honoured breakpoints by simply refusing to compile would pass a
/// state comparison and fail this.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DebugMix {
    /// Nothing armed. The historical differential.
    #[default]
    Off,
    /// One instruction breakpoint per trial, at a boundary drawn uniformly from
    /// the trial's own executed trace — including the address one past its last
    /// instruction, where arming must change nothing.
    Break,
    /// One data watchpoint per trial, over a random sub-range of the data
    /// region, in a random direction.
    Watch,
}

impl DebugMix {
    pub fn parse(s: &str) -> Option<DebugMix> {
        match s {
            "off" | "none" => Some(DebugMix::Off),
            "break" | "bp" => Some(DebugMix::Break),
            "watch" | "wp" => Some(DebugMix::Watch),
            _ => None,
        }
    }
}

/// Guest instructions per block when [`JitFuzzConfig::laps`] is set. Small on
/// purpose: it splits a trial into several blocks, so the fallthrough edge
/// between them is linked as well as the `jmp` that closes the loop.
pub const LAP_MAX_INSNS: u32 = 3;

#[derive(Default)]
pub struct JitSummary {
    pub trials: u64,
    /// Trials where the JIT compiled and ran at least one instruction.
    pub compiled: u64,
    /// Total guest instructions executed as native code.
    pub insns: u64,
    /// Trials where nothing at the entry address could be compiled.
    pub not_compiled: u64,
    /// Trials that ended by rewinding onto a faulting access.
    pub faults: u64,
    pub divergences: u64,
    pub first: Vec<JitDivergence>,
    /// Guest instructions the interpreter had to take because the block ended.
    pub interpreted: u64,
    /// Instructions the generator emitted (the denominator for coverage).
    pub generated: u64,
    /// Block entries the JIT reached by a **native link** rather than by
    /// returning here (roadmap W8.5). Zero unless [`JitFuzzConfig::laps`] is
    /// set — a straight-line trial walks each block exactly once, so there is
    /// no second pass for a link to be taken on.
    pub links_taken: u64,
    /// First opcode byte of every block the compiler declined outright, most
    /// frequent first (`opcode | 0x100` for the `0F` map).
    pub declined_ops: Vec<(u16, u64)>,
    /// Trials, and divergences, per [`Layout`].
    pub by_layout: [u64; 3],
    pub div_by_layout: [u64; 3],
    /// Guest-memory TLB entries filled across the whole run, and fills the
    /// backend refused (roadmap W8.6).
    ///
    /// Reported because "zero divergences" says nothing at all unless the fast
    /// path was engaged: a harness whose regions are too tight to cache fills
    /// **nothing**, and then every trial exercises the helper the JIT already
    /// had. That is not a hypothetical — it is what the first version of the
    /// W8.6 differential did for two million trials.
    pub tlb_fills: u64,
    pub tlb_denied: u64,
    /// Trials where a compiled block handed control back at an armed breakpoint
    /// rather than running past it, and trials where one refused a watched
    /// access. Zero unless [`JitFuzzConfig::debug`] asked for them, and the
    /// count that says the debugger dimension did anything at all.
    pub breakpoint_stops: u64,
    pub watch_stops: u64,
    /// Guest-memory TLB entries filled **during the armed run only**, as
    /// opposed to [`tlb_fills`](JitSummary::tlb_fills), which also counts the
    /// unarmed control run each debugged trial makes first.
    ///
    /// The two together are the assertion that matters for S6: the same trials
    /// fill entries with nothing armed and fill **none** with a watchpoint
    /// armed. Either number alone would be satisfied by a harness that never
    /// engaged the fast path at all. With a *breakpoint* armed the count must
    /// stay non-zero — arming an address is not a reason to slow guest memory
    /// down.
    pub armed_tlb_fills: u64,
    /// Trials in which the armed thing was actually reached, i.e. where the
    /// expected retired count was **below** the count the same trial retired
    /// with nothing armed. The rest armed something the trial never got to,
    /// which is a real case (arming must change nothing) but not the
    /// interesting one.
    pub debug_split: u64,
}

impl JitSummary {
    /// Share of the *generated* instruction stream the JIT executed natively.
    /// The denominator is every instruction the generator emitted, so an
    /// instruction the compiler declined counts against the JIT even when the
    /// trial never reached it.
    pub fn coverage(&self) -> f64 {
        if self.generated == 0 {
            0.0
        } else {
            100.0 * self.insns as f64 / self.generated as f64
        }
    }
}

fn mode_of(bits: Bits) -> Mode {
    match bits {
        Bits::B32 => Mode::Protected,
        Bits::B64 => Mode::Long,
    }
}

// ---- boundary shapes -------------------------------------------------------
//
// The integer generator the Unicorn oracle shares emits no control flow and
// never touches the stack, because both are meaningless to a single-instruction
// differential. They are the whole point of a *block* differential, so they are
// generated here.
//
// Each shape installs the register it depends on with a `mov r, imm` of its
// own rather than trusting the seed, because the instructions generated before
// it are free to have overwritten anything.

/// `mov r, imm` at the mode's operand width: `B8+r` (32-bit) or `REX.W B8+r`.
fn mov_reg_imm(b: &mut Vec<u8>, bits: Bits, reg: u8, imm: u64) {
    match bits {
        Bits::B32 => {
            b.push(0xB8 | (reg & 7));
            b.extend_from_slice(&(imm as u32).to_le_bytes());
        }
        Bits::B64 => {
            b.push(0x48);
            b.push(0xB8 | (reg & 7));
            b.extend_from_slice(&imm.to_le_bytes());
        }
    }
}

const RSP: u8 = 4;
const RBP: u8 = 5;

/// One boundary shape: its bytes and how many guest instructions they are.
fn boundary_shape(rng: &mut Rng, bits: Bits, sp: &Space) -> (Vec<u8>, String, u64) {
    let mut b = Vec::new();
    let (label, n) = match rng.below(9) {
        // push r, from a stack pointer that makes the push cross the boundary.
        0 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            let r = rng.below(8) as u8;
            b.push(0x50 | r);
            (format!("mov esp,{:#x} ; push r{r}", sp.push_sp), 2)
        }
        // pop r, from the other side of the boundary.
        1 => {
            mov_reg_imm(&mut b, bits, RSP, sp.pop_sp);
            let r = rng.below(8) as u8;
            b.push(0x58 | r);
            (format!("mov esp,{:#x} ; pop r{r}", sp.pop_sp), 2)
        }
        // push imm8 / push imm32.
        2 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            if rng.boolean() {
                b.push(0x6A);
                b.push(rng.next_u32() as u8);
                (format!("mov esp,{:#x} ; push imm8", sp.push_sp), 2)
            } else {
                b.push(0x68);
                b.extend_from_slice(&rng.next_u32().to_le_bytes());
                (format!("mov esp,{:#x} ; push imm32", sp.push_sp), 2)
            }
        }
        // leave: rsp = rbp ; pop rbp, with rbp on the boundary.
        3 => {
            mov_reg_imm(&mut b, bits, RBP, sp.pop_sp);
            b.push(0xC9);
            (format!("mov ebp,{:#x} ; leave", sp.pop_sp), 2)
        }
        // jmp rel8 / rel32 — a block terminator, so `rip` is the whole result.
        4 => {
            if rng.boolean() {
                b.push(0xEB);
                b.push(rng.next_u32() as u8);
                ("jmp rel8".into(), 1)
            } else {
                b.push(0xE9);
                b.extend_from_slice(&rel32(rng).to_le_bytes());
                ("jmp rel32".into(), 1)
            }
        }
        // jcc rel8 / rel32 — both edges are compiled, so both are compared.
        5 => {
            let cc = rng.below(16) as u8;
            if rng.boolean() {
                b.push(0x70 | cc);
                b.push(rng.next_u32() as u8);
                (format!("j{cc:x} rel8"), 1)
            } else {
                b.push(0x0F);
                b.push(0x80 | cc);
                b.extend_from_slice(&rel32(rng).to_le_bytes());
                (format!("j{cc:x} rel32"), 1)
            }
        }
        // `call rel32 +0` — the get-EIP idiom, and the one call shape whose
        // target is the next instruction, so the trial carries on afterwards
        // instead of jumping into the middle of itself. It pushes the address
        // *after* the call, which in a flush layout is on the boundary.
        6 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            b.push(0xE8);
            b.extend_from_slice(&0u32.to_le_bytes());
            (format!("mov esp,{:#x} ; call rel32 +0", sp.push_sp), 2)
        }
        // A computed jump to the instruction after itself: take the address the
        // call just pushed, add the length of what follows, and `jmp` to it.
        // This is the shape the indirect-branch inline cache exists for — the
        // same branch going to the same place every time — and it lands on real
        // code rather than on whatever a random register holds.
        7 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            b.push(0xE8);
            b.extend_from_slice(&0u32.to_le_bytes()); // call +0: pushes `next`
            b.push(0x58); // pop rax/eax
            let wide = bits == Bits::B64;
            if wide {
                b.push(0x48);
            }
            // `add rax, imm8` then `jmp rax`: the distance from the popped
            // address to the byte after the whole sequence.
            let after = if wide { 1 + 4 + 2 } else { 1 + 3 + 2 };
            b.extend_from_slice(&[0x83, 0xC0, after]);
            b.extend_from_slice(&[0xFF, 0xE0]);
            ("call +0 ; pop rax ; add rax,n ; jmp rax".into(), 4)
        }
        // [rbp+disp8] load / store / lea, from a base on the boundary.
        8 => {
            mov_reg_imm(&mut b, bits, RBP, sp.wrap_base);
            let disp = rng.next_u32() as u8;
            let reg = rng.below(8) as u8;
            if bits == Bits::B64 && rng.boolean() {
                b.push(0x48);
            }
            let (opc, what) = match rng.below(3) {
                0 => (0x8Bu8, "mov r,[rbp+d]"),
                1 => (0x89, "mov [rbp+d],r"),
                _ => (0x8D, "lea r,[rbp+d]"),
            };
            b.push(opc);
            b.push(0x40 | ((reg & 7) << 3) | RBP); // mod=01, r/m=rbp
            b.push(disp);
            (format!("mov ebp,{:#x} ; {what}", sp.wrap_base), 2)
        }
        _ => unreachable!(),
    };
    (b, label, n)
}

/// A `rel32` biased toward values that carry an address over a boundary from
/// anywhere inside a 4 KiB code page, with the occasional huge jump.
fn rel32(rng: &mut Rng) -> i32 {
    match rng.below(4) {
        0 => rng.next_u32() as i32,
        1 => -(rng.below(0x2000) as i32),
        _ => rng.below(0x2000) as i32,
    }
}

// ---- one trial -------------------------------------------------------------

struct TrialPlan {
    bytes: Vec<u8>,
    label: String,
    seed: Seed,
    /// Guest instructions the generator emitted.
    generated: u64,
    layout: Layout,
    space: Space,
    /// Guest address the code is assembled at.
    at: u64,
}

/// Build one trial: `chain` generated instructions back to back, followed by a
/// `ret` the compiler declines so the block cannot run off into whatever the
/// rest of the page decodes as.
fn trial_at(cfg: &JitFuzzConfig, index: u64) -> TrialPlan {
    let bits = cfg.bits;
    let mut rng = Rng::for_trial(cfg.seed, index);
    let layout = cfg.layouts.pick(&mut rng);
    // Half the trials get the slack the JIT's guest-memory TLB needs before it
    // will cache a page, so the fast path is exercised; half keep the tight
    // one-page regions the fault shapes depend on. See `ROOM`.
    let sp = space(layout, bits, rng.below(2) == 0);
    let mut seed = gen::seed(&mut rng);
    let mut bytes = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut generated = 0u64;
    // Leave room for the terminator — one byte for a `ret`, five for the `jmp`
    // back that a lapped trial ends on — and, in the flush layouts, for the
    // whole block to sit inside the code region.
    let room = sp.code_len as usize - if cfg.laps > 1 { 5 } else { 1 };
    for _ in 0..cfg.chain.max(1) {
        // A boundary shape a quarter of the time. Under `Layout::Low` these are
        // still worth generating — push/pop/branch lowerings are not otherwise
        // covered by the differential at all — they simply do not cross
        // anything there.
        let (b, label, n) = if rng.below(4) == 0 {
            boundary_shape(&mut rng, bits, &sp)
        } else {
            let t = gen::build_integer(&mut rng, bits, &mut seed);
            (t.bytes, t.label, 1)
        };
        if bytes.len() + b.len() > room {
            break;
        }
        bytes.extend_from_slice(&b);
        labels.push(label);
        generated += n;
    }
    // How the trial ends. Normally with a `ret`, which the compiler declines
    // and which therefore terminates the block cleanly.
    //
    // In a flush layout, half the time, the trial instead ends **mid
    // instruction**: the `ret` is dropped and a few bytes are shaved off the
    // tail, so the last encoding runs past the end of the executable region.
    // That is the one place where the compiler's 16-byte fetch window can lie
    // to it — the wide fetch fails, the byte-at-a-time fallback stops at the
    // region's last byte, and everything after it in the window is zero. A
    // compiler that decodes those zeros runs an instruction that is not in
    // guest memory at all, while the interpreter faults fetching the very byte
    // the window could not reach. Without this the case is unreachable: a
    // trial that always ends on a whole `ret` never asks for a byte it cannot
    // have.
    if sp.flush && !bytes.is_empty() && rng.boolean() {
        let cut = (1 + rng.below(6) as usize).min(bytes.len() - 1);
        bytes.truncate(bytes.len() - cut);
    } else if cfg.laps > 1 {
        // `jmp` back to the trial's own first instruction, so the same code runs
        // several times and the block boundaries inside it are walked more than
        // once. The first pass fills the link slots; the passes after it take
        // them, which is the only way this harness gets to compare a natively
        // linked chain against the interpreter.
        let back = -((bytes.len() + 5) as i64) as i32;
        bytes.push(0xE9);
        bytes.extend_from_slice(&back.to_le_bytes());
    } else {
        bytes.push(0xC3); // ret — not compiled, so it terminates the block
    }
    // The stack pointer the trial starts on. A shape that cares installs its
    // own, but a generated instruction may use `esp` as an operand, and the
    // layout is what decides whether that is near a boundary.
    seed.gpr[RSP as usize] = sp.sp;
    let at = if sp.flush {
        sp.code_base + sp.code_len - bytes.len() as u64
    } else {
        sp.code_base
    };
    TrialPlan { bytes, label: labels.join(" ; "), seed, generated, layout, space: sp, at }
}

fn setup(bits: Bits, plan: &TrialPlan) -> Option<(VirtualMemory, Interpreter)> {
    let mut mem = VirtualMemory::new();
    for (name, base, len, perm) in &plan.space.regions {
        mem.map(Region::new(*name, *base, *len, *perm)).ok()?;
    }
    mem.poke(plan.at, &plan.bytes).ok()?;
    mem.poke(gen::DATA_BASE, &plan.seed.data).ok()?;
    let mut cpu = Interpreter::with_bits(bits);
    cpu.set_mxcsr(plan.seed.mxcsr);
    {
        let s = cpu.state_mut();
        s.gpr = plan.seed.gpr;
        s.rflags = plan.seed.rflags;
        s.xmm = plan.seed.xmm;
        s.ymm_hi = plan.seed.ymm_hi;
        s.x87.st = plan.seed.st;
        s.x87.cw = plan.seed.cw;
        s.x87.sw = plan.seed.sw;
        s.x87.tw = plan.seed.tw;
        s.rip = plan.at;
    }
    Some((mem, cpu))
}

/// Full architectural comparison — no exclusions.
fn diff_state(a: &CpuState, b: &CpuState) -> Option<String> {
    for i in 0..16 {
        if a.gpr[i] != b.gpr[i] {
            return Some(format!(
                "{} jit={:#x} interp={:#x}",
                exemu_core::Reg::NAMES[i],
                a.gpr[i],
                b.gpr[i]
            ));
        }
    }
    if a.rflags != b.rflags {
        return Some(format!(
            "rflags jit={:#x} interp={:#x} Δ={:#x}",
            a.rflags,
            b.rflags,
            a.rflags ^ b.rflags
        ));
    }
    if a.rip != b.rip {
        return Some(format!("rip jit={:#x} interp={:#x}", a.rip, b.rip));
    }
    for i in 0..16 {
        if a.xmm[i] != b.xmm[i] {
            return Some(format!("xmm{i} jit={:#034x} interp={:#034x}", a.xmm[i], b.xmm[i]));
        }
        if a.ymm_hi[i] != b.ymm_hi[i] {
            return Some(format!(
                "ymm{i}[255:128] jit={:#034x} interp={:#034x}",
                a.ymm_hi[i], b.ymm_hi[i]
            ));
        }
    }
    for i in 0..8 {
        if a.x87.st[i] != b.x87.st[i] {
            return Some(format!("st(phys {i}) jit={:#034x} interp={:#034x}", a.x87.st[i], b.x87.st[i]));
        }
    }
    None
}

fn diff_mem(a: &VirtualMemory, b: &VirtualMemory, sp: &Space) -> Option<String> {
    for (_, base, len, _) in &sp.regions {
        let len = *len as usize;
        let mut x = vec![0u8; len];
        let mut y = vec![0u8; len];
        if a.read(*base, &mut x).is_err() || b.read(*base, &mut y).is_err() {
            return Some("memory readback failed".into());
        }
        for i in 0..len {
            if x[i] != y[i] {
                return Some(format!(
                    "mem[{:#x}] jit={:#04x} interp={:#04x}",
                    base + i as u64,
                    x[i],
                    y[i]
                ));
            }
        }
    }
    None
}

/// A lapped trial (roadmap W8.5): the trial's code ends in a `jmp` back to its
/// own first instruction, so the same blocks are entered again and again, and
/// after the first pass they are entered by a **native link** — a `br` from the
/// previous block's exit, with no return to Rust in between.
///
/// The JIT side is driven exactly the way `crates/app`'s run loop drives it,
/// because that is the only way a trial gets more than a handful of laps: a
/// block that stops on an opcode the compiler declines hands that one
/// instruction to an interpreter running against the *JIT's own* memory, and
/// then the chain resumes. What comes out is a mixed native/interpreted run, and
/// it is compared against a pure interpreter run of exactly the same length.
#[allow(clippy::too_many_arguments)]
fn run_lapped(
    jit: &mut Jit,
    plan: &TrialPlan,
    laps: u32,
    mut mem_j: VirtualMemory,
    mut cpu_j: Interpreter,
    mut mem_i: VirtualMemory,
    mut cpu_i: Interpreter,
) -> (Run, Option<String>) {
    let budget = laps as u64 * (plan.generated + 1);
    let mut hooks = NoHooks;
    let mut total: u32 = 0;
    let mut last = Run::NotCompiled;
    // Did the JIT side's own interpreter stop on something other than a clean
    // `Continue`? Then it may already have changed state before it stopped — a
    // `rep stos` that faults partway has advanced `rdi` over the bytes it did
    // write — so the reference has to be given that same instruction rather than
    // left one behind it.
    let mut stopped_mid_instruction = false;
    // The two sides are compared **after every step**, not once at the end. A
    // lapped trial runs the same block many times, so a state difference
    // introduced on lap 1 would otherwise surface only as a fault several
    // instructions later, at an address that says nothing about what went wrong.
    let mut done: u32 = 0;
    fn catch_up(
        cpu_i: &mut Interpreter,
        mem_i: &mut VirtualMemory,
        done: &mut u32,
        total: u32,
    ) -> Option<String> {
        let mut hooks = NoHooks;
        while *done < total {
            match cpu_i.step(mem_i, &mut hooks) {
                Ok(Exit::Continue) => *done += 1,
                other => {
                    let rip = cpu_i.state().rip;
                    let mut w = [0u8; 16];
                    let _ = mem_i.fetch(rip, &mut w);
                    return Some(format!(
                        "interpreter stopped after {done} of {total} instructions at rip={rip:#x} [{}]: {other:?}",
                        w.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                    ));
                }
            }
        }
        None
    }
    while (total as u64) < budget {
        let left = budget - total as u64;
        // **The mode is re-read every time**, not fixed at the start of the
        // trial. A guest can change it while it runs — a far jump through a CS
        // selector is how a WoW64 process switches (roadmap W5.2), and `iret`
        // reloads CS too — and the same bytes are two different programs in the
        // two modes. The real run loop in `crates/app` re-reads it per iteration
        // for exactly this reason; a lapped trial is the first thing here that
        // calls `Jit::run` more than once, and pinning the mode made a 64-bit
        // block run for an interpreter that had switched to 32-bit.
        let mode = mode_of(cpu_j.bits());
        let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, left);
        total += run.insns();
        last = run;
        if let Some(r) = catch_up(&mut cpu_i, &mut mem_i, &mut done, total) {
            return (last, Some(r));
        }
        if let Some(r) = diff_state(cpu_j.state(), cpu_i.state()) {
            return (last, Some(r));
        }
        match run {
            // Stopped on the budget: the `while` above decides whether that is
            // the end of the trial.
            Run::Executed { .. } => {}
            // Rewound onto a faulting access. The interpreter is required to
            // fail on that same instruction below, so stop here and let the
            // comparison speak.
            Run::Faulted { .. } => break,
            // Nothing compiled at this address — the run loop's job is to
            // interpret exactly one instruction and come back.
            Run::SideExit { .. } | Run::NotCompiled => {
                match cpu_j.step(&mut mem_j, &mut hooks) {
                    Ok(Exit::Continue) => total += 1,
                    _ => {
                        stopped_mid_instruction = true;
                        break;
                    }
                }
            }
        }
    }

    if let Some(r) = catch_up(&mut cpu_i, &mut mem_i, &mut done, total) {
        return (last, Some(r));
    }
    if stopped_mid_instruction {
        // Whatever it did to the JIT side's state before it stopped, it does
        // here too — including a partial one.
        let _ = cpu_i.step(&mut mem_i, &mut hooks);
    }
    if let Some(r) = diff_state(cpu_j.state(), cpu_i.state()) {
        return (last, Some(r));
    }
    if let Some(r) = diff_mem(&mem_j, &mem_i, &plan.space) {
        return (last, Some(r));
    }
    if matches!(last, Run::Faulted { .. }) {
        if let Ok(Exit::Continue) = cpu_i.step(&mut mem_i, &mut hooks) {
            return (
                last,
                Some(format!(
                    "JIT faulted at rip={:#x} but the interpreter executed that instruction",
                    cpu_j.state().rip
                )),
            );
        }
    }
    // Report the trial as having compiled `total` instructions, so the summary's
    // coverage figure still means what it says.
    (
        match last {
            Run::Faulted { .. } => Run::Faulted { insns: total },
            Run::NotCompiled if total == 0 => Run::NotCompiled,
            _ => Run::Executed { insns: total },
        },
        None,
    )
}

/// Run one trial. Returns `(run, reason)`.
fn run_one(jit: &mut Jit, bits: Bits, plan: &TrialPlan, laps: u32) -> (Run, Option<String>) {
    let mode = mode_of(bits);
    let Some((mut mem_j, mut cpu_j)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let Some((mut mem_i, mut cpu_i)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let before = cpu_j.state().clone();

    jit.invalidate(); // fresh address space every trial
    // Budget 1 = exactly one block (roadmap W8.5). The generator emits straight
    // -line integer code, so a trial *is* one block; holding the chain loop to
    // one keeps this differential measuring the same thing it measured before
    // chaining existed — the block, not the loop around it.
    //
    // With `--laps` the trial is a loop instead, and the budget lets it round
    // that loop several times: the first pass fills the link slots and every
    // pass after it enters blocks by `br` rather than by returning here, so what
    // is compared against the interpreter is what a natively linked chain
    // computed. The budget is deliberately not a round multiple of the body —
    // it lands wherever it lands, which is also a test that the chain stops on
    // an instruction boundary the interpreter agrees with.
    if laps > 1 {
        return run_lapped(jit, plan, laps, mem_j, cpu_j, mem_i, cpu_i);
    }
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, 1);

    let retired = match run {
        Run::NotCompiled => {
            // A declined block must be a no-op, in every observable respect.
            if let Some(r) = diff_state(cpu_j.state(), &before) {
                return (run, Some(format!("declined block changed state: {r}")));
            }
            return (run, None);
        }
        Run::Executed { insns } | Run::SideExit { insns } | Run::Faulted { insns } => insns,
    };

    // Step the interpreter exactly as far as the JIT claimed to have got.
    let mut hooks = NoHooks;
    for step in 0..retired {
        match cpu_i.step(&mut mem_i, &mut hooks) {
            Ok(Exit::Continue) => {}
            other => {
                return (
                    run,
                    Some(format!(
                        "interpreter stopped after {step} of {retired} instructions: {other:?}"
                    )),
                )
            }
        }
    }

    if let Some(r) = diff_state(cpu_j.state(), cpu_i.state()) {
        return (run, Some(r));
    }
    if let Some(r) = diff_mem(&mem_j, &mem_i, &plan.space) {
        return (run, Some(r));
    }

    // A rewind must be a *real* fault: run the instruction the JIT refused and
    // require the interpreter to fail on it too. Otherwise the JIT is faulting
    // spuriously — invisible in the state diff, fatal to performance, and a
    // sign that an effective address is being computed wrongly.
    if matches!(run, Run::Faulted { .. }) {
        match cpu_i.step(&mut mem_i, &mut hooks) {
            Err(_) => {}
            Ok(Exit::Continue) => {
                return (
                    run,
                    Some(format!(
                        "JIT faulted at rip={:#x} but the interpreter executed that instruction",
                        cpu_j.state().rip
                    )),
                )
            }
            Ok(_) => {}
        }
    }
    (run, None)
}

pub fn fuzz(cfg: &JitFuzzConfig) -> Result<JitSummary, String> {
    let mut jit = Jit::new(4 << 20).map_err(|e| format!("no JIT on this platform: {e}"))?;
    if cfg.laps > 1 {
        jit.set_max_insns(LAP_MAX_INSNS);
    }
    let mut s = JitSummary::default();
    for index in 0..cfg.count {
        let plan = trial_at(cfg, index);
        s.generated += plan.generated;
        s.by_layout[plan.layout.index()] += 1;
        let (run, reason) = if cfg.debug == DebugMix::Off {
            run_one(&mut jit, cfg.bits, &plan, cfg.laps)
        } else {
            run_one_debugged(&mut jit, cfg, &plan, index, &mut s)
        };
        s.trials += 1;
        match run {
            Run::NotCompiled => {
                s.not_compiled += 1;
                s.interpreted += 1;
            }
            Run::Executed { insns } | Run::SideExit { insns } => {
                s.compiled += 1;
                s.insns += insns as u64;
            }
            Run::Faulted { insns } => {
                s.compiled += u64::from(insns > 0);
                s.insns += insns as u64;
                s.faults += 1;
                s.interpreted += 1;
            }
        }
        if let Some(reason) = reason {
            s.divergences += 1;
            s.div_by_layout[plan.layout.index()] += 1;
            if s.first.len() < cfg.max_report {
                s.first.push(JitDivergence {
                    index,
                    label: plan.label,
                    bytes: plan.bytes,
                    reason,
                    layout: plan.layout,
                    at: plan.at,
                });
            }
        }
    }
    s.declined_ops = jit.stats().top_declined(20);
    s.links_taken = jit.stats().links_taken;
    s.tlb_fills = jit.stats().tlb_fills;
    s.tlb_denied = jit.stats().tlb_denied;
    s.breakpoint_stops = jit.stats().breakpoint_stops;
    s.watch_stops = jit.stats().watch_stops;
    Ok(s)
}

/// One trial with something armed (roadmap W9.3, steps S3 and S6).
///
/// Three runs of the same trial, and the third is the one under test:
///
/// 1. **Natural.** Nothing armed, so we know how far this trial's block gets on
///    its own. Everything below is a *difference* against this, which is what
///    stops the mode from passing on trials the JIT declines outright.
/// 2. **Reference.** The interpreter walks the same trace, and — depending on
///    the mode — either records the addresses it stops at or, with the same
///    watchpoint installed on *its* memory, the first instruction at which a hit
///    is recorded. Either way the expected answer comes from the interpreter,
///    never from the JIT.
/// 3. **Armed.** The JIT, with the handle installed exactly as `crates/app`
///    installs it (on the engine *and* on the backend). Its retired count must
///    equal the expected one, and the architectural state and every byte of
///    guest memory must equal an interpreter stepped exactly that far.
fn run_one_debugged(
    jit: &mut Jit,
    cfg: &JitFuzzConfig,
    plan: &TrialPlan,
    index: u64,
    s: &mut JitSummary,
) -> (Run, Option<String>) {
    let bits = cfg.bits;
    let mode = mode_of(bits);
    let mut hooks = NoHooks;
    // A budget big enough for the whole trial, rather than the single block
    // `run_one` holds itself to. That is deliberate and it is the point of this
    // mode: the case S3 exists for is a **chain** that reaches an armed address
    // — one block at a time, the caller's loop head sees every block entry
    // anyway and there is nothing to get wrong. Both runs below use it, so
    // `natural` and the armed count are measured against the same rule.
    let budget = plan.generated + 1;

    // --- 1. the natural run -------------------------------------------------
    jit.set_debug(DebugControl::detached());
    jit.invalidate();
    let Some((mut mem_n, mut cpu_n)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let natural = jit.run(cpu_n.state_mut(), &mut mem_n, mode, budget).insns();

    // --- 2. the reference, and the expected answer --------------------------
    let Some((mut mem_r, mut cpu_r)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    // A generator stream is not a straight line — it contains branches — so an
    // address can recur, and a breakpoint stops at the *first* time it is
    // reached rather than at the draw's index.
    let dbg = DebugControl::attached();
    let mut rng = Rng::for_trial(cfg.seed ^ 0x9E37_79B9, index);
    let expected;
    match cfg.debug {
        DebugMix::Off => unreachable!("run_one handles the undebugged case"),
        DebugMix::Break => {
            let mut trace = Vec::with_capacity(natural as usize + 1);
            for _ in 0..natural {
                trace.push(cpu_r.state().rip);
                if !matches!(cpu_r.step(&mut mem_r, &mut hooks), Ok(Exit::Continue)) {
                    break;
                }
            }
            // …and the address one past the last instruction, where arming must
            // change nothing at all.
            trace.push(cpu_r.state().rip);
            let target = trace[rng.below(trace.len() as u32) as usize];
            dbg.arm_break(target);
            let first = trace.iter().position(|&a| a == target).unwrap_or(trace.len() - 1);
            expected = (first as u32).min(natural);
        }
        DebugMix::Watch => {
            // --- where to put it ------------------------------------------
            //
            // Uniformly over the 4 KiB data region is the obvious answer and it
            // is a **useless** one: a trial is eight instructions long, so a
            // random 1–8 byte range is essentially never touched and the whole
            // mode degenerates into "arming something changes nothing". (This
            // was measured, not guessed: one trial in four thousand reached
            // what it armed.)
            //
            // So the range is drawn against the trial's own behaviour. A probe
            // run watches the *entire* data region and reports the first
            // address this trial actually touches; three draws in four then
            // cover that address, and the fourth deliberately does not — which
            // keeps the "must not stop" case in the mix rather than trading one
            // blind spot for another.
            let touched = {
                let probe = DebugControl::attached();
                probe.arm_watch(gen::DATA_BASE, gen::DATA_LEN as u64, WatchKind::ReadWrite);
                let mut first = None;
                if let Some((mut mem_p, mut cpu_p)) = setup(bits, plan) {
                    mem_p.set_debug(probe.clone());
                    for _ in 0..natural {
                        let stepped = cpu_p.step(&mut mem_p, &mut hooks);
                        if let Some((addr, _)) = probe.take_watch_hit() {
                            first = Some(addr);
                            break;
                        }
                        if !matches!(stepped, Ok(Exit::Continue)) {
                            break;
                        }
                    }
                }
                first
            };
            let len = 1 + u64::from(rng.below(8));
            let base = match touched {
                Some(a) if rng.below(4) != 0 => {
                    a.saturating_sub(u64::from(rng.below(len as u32))).max(gen::DATA_BASE)
                }
                _ => gen::DATA_BASE + u64::from(rng.below(gen::DATA_LEN as u32)),
            };
            // `ReadWrite` twice, so the kind covers the access more often than
            // not while both single directions still get drawn.
            let kind = *rng.pick(&[
                WatchKind::Read,
                WatchKind::Write,
                WatchKind::ReadWrite,
                WatchKind::ReadWrite,
            ]);
            dbg.arm_watch(base, len, kind);
            mem_r.set_debug(dbg.clone());
            let mut first = natural;
            for i in 0..natural {
                let stepped = cpu_r.step(&mut mem_r, &mut hooks);
                // Checked *before* the `Continue` test: an instruction that
                // makes a watched access and then faults still made it.
                if dbg.take_watch_hit().is_some() {
                    first = i;
                    break;
                }
                if !matches!(stepped, Ok(Exit::Continue)) {
                    break;
                }
            }
            expected = first;
        }
    }
    if expected < natural {
        s.debug_split += 1;
    }

    // --- 3. the armed run ---------------------------------------------------
    jit.set_debug(dbg.clone());
    jit.invalidate();
    let Some((mut mem_j, mut cpu_j)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    // Installed on the backend too, exactly as the run loop does it: that is
    // what makes `Memory::host_span` refuse while a watchpoint is armed.
    mem_j.set_debug(dbg.clone());
    let before = cpu_j.state().clone();
    let fills_before = jit.stats().tlb_fills;
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, budget);
    s.armed_tlb_fills += jit.stats().tlb_fills - fills_before;
    let retired = run.insns();
    if retired != expected {
        return (
            run,
            Some(format!(
                "armed run retired {retired} instructions, expected {expected}                  (the same trial retires {natural} with nothing armed)"
            )),
        );
    }
    if retired == 0 {
        // Nothing ran, so nothing may have changed — the same promise a
        // declined block makes.
        if let Some(r) = diff_state(cpu_j.state(), &before) {
            return (run, Some(format!("armed block retired nothing but changed state: {r}")));
        }
        return (run, None);
    }

    let Some((mut mem_i, mut cpu_i)) = setup(bits, plan) else {
        return (run, Some("could not build the address space".into()));
    };
    for step in 0..retired {
        match cpu_i.step(&mut mem_i, &mut hooks) {
            Ok(Exit::Continue) => {}
            other => {
                return (
                    run,
                    Some(format!(
                        "interpreter stopped after {step} of {retired} instructions: {other:?}"
                    )),
                )
            }
        }
    }
    if let Some(r) = diff_state(cpu_j.state(), cpu_i.state()) {
        return (run, Some(r));
    }
    if let Some(r) = diff_mem(&mem_j, &mem_i, &plan.space) {
        return (run, Some(r));
    }
    (run, None)
}

pub fn render(d: &JitDivergence) -> String {
    let hex: Vec<String> = d.bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "  #{:<10} [{}] @ {:#x}  {}\n      [{}]\n      Δ {}",
        d.index,
        d.layout.name(),
        d.at,
        d.label,
        hex.join(" "),
        d.reason
    )
}
