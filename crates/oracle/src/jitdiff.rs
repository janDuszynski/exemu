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

fn space(layout: Layout, bits: Bits) -> Space {
    let data = (
        "data",
        gen::DATA_BASE,
        gen::DATA_LEN as u64,
        Perm::RW,
    );
    match (layout, bits) {
        (Layout::Low, _) => Space {
            regions: vec![
                ("code", LOW_CODE, PAGE, Perm::RWX),
                data,
                ("stack", LOW_STACK, PAGE, Perm::RW),
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
                ("stack", LOW_STACK, PAGE, Perm::RW),
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
                ("stack", HIGH64 + PAGE, PAGE, Perm::RW),
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
                ("stack", HIGH64, PAGE, Perm::RW),
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
}

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
    /// First opcode byte of every block the compiler declined outright, most
    /// frequent first (`opcode | 0x100` for the `0F` map).
    pub declined_ops: Vec<(u16, u64)>,
    /// Trials, and divergences, per [`Layout`].
    pub by_layout: [u64; 3],
    pub div_by_layout: [u64; 3],
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
        // [rbp+disp8] load / store / lea, from a base on the boundary.
        6..=8 => {
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
    let sp = space(layout, bits);
    let mut seed = gen::seed(&mut rng);
    let mut bytes = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut generated = 0u64;
    // Leave room for the terminating `ret` and, in the flush layouts, for the
    // whole block to sit inside the code region.
    let room = sp.code_len as usize - 1;
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

/// Run one trial. Returns `(run, reason)`.
fn run_one(jit: &mut Jit, bits: Bits, plan: &TrialPlan) -> (Run, Option<String>) {
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
    // chaining existed — the block, not the loop around it. Chaining is gated
    // instead by the parity tests in `crates/jit/tests` and by the corpus twins,
    // which are the only harnesses with real control flow in them.
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
    let mut s = JitSummary::default();
    for index in 0..cfg.count {
        let plan = trial_at(cfg, index);
        s.generated += plan.generated;
        s.by_layout[plan.layout.index()] += 1;
        let (run, reason) = run_one(&mut jit, cfg.bits, &plan);
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
    Ok(s)
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
