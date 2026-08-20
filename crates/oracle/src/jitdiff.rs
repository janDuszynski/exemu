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

use crate::gen::{self, Seed};
use crate::rng::Rng;
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const CODE_BASE: u64 = 0x1000;
const CODE_LEN: u64 = 0x1000;

/// One trial's verdict.
pub struct JitDivergence {
    pub index: u64,
    pub label: String,
    pub bytes: Vec<u8>,
    pub reason: String,
}

pub struct JitFuzzConfig {
    pub bits: Bits,
    pub count: u64,
    pub seed: u64,
    pub max_report: usize,
    /// Guest instructions concatenated into one block per trial.
    pub chain: u32,
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

/// Build one trial: `chain` generated instructions back to back, followed by a
/// `ret` the compiler declines so the block cannot run off into whatever the
/// rest of the page decodes as.
fn trial_at(bits: Bits, base_seed: u64, index: u64, chain: u32) -> (Vec<u8>, String, Seed, u64) {
    let mut rng = Rng::new(base_seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut seed = gen::seed(&mut rng);
    let mut bytes = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    for _ in 0..chain.max(1) {
        let t = gen::build_integer(&mut rng, bits, &mut seed);
        if bytes.len() + t.bytes.len() + 1 > CODE_LEN as usize {
            break;
        }
        bytes.extend_from_slice(&t.bytes);
        labels.push(t.label);
    }
    bytes.push(0xC3); // ret — not compiled, so it terminates the block
    let n = labels.len() as u64;
    (bytes, labels.join(" ; "), seed, n)
}

fn setup(bits: Bits, code: &[u8], seed: &Seed) -> Option<(VirtualMemory, Interpreter)> {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, CODE_LEN, Perm::RWX)).ok()?;
    mem.map(Region::new("data", gen::DATA_BASE, gen::DATA_LEN as u64, Perm::RW)).ok()?;
    mem.poke(CODE_BASE, code).ok()?;
    mem.poke(gen::DATA_BASE, &seed.data).ok()?;
    let mut cpu = Interpreter::with_bits(bits);
    cpu.set_mxcsr(seed.mxcsr);
    {
        let s = cpu.state_mut();
        s.gpr = seed.gpr;
        s.rflags = seed.rflags;
        s.xmm = seed.xmm;
        s.ymm_hi = seed.ymm_hi;
        s.x87.st = seed.st;
        s.x87.cw = seed.cw;
        s.x87.sw = seed.sw;
        s.x87.tw = seed.tw;
        s.rip = CODE_BASE;
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

fn diff_mem(a: &VirtualMemory, b: &VirtualMemory) -> Option<String> {
    for (base, len) in [(CODE_BASE, CODE_LEN as usize), (gen::DATA_BASE, gen::DATA_LEN)] {
        let mut x = vec![0u8; len];
        let mut y = vec![0u8; len];
        if a.read(base, &mut x).is_err() || b.read(base, &mut y).is_err() {
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

/// Run one trial. Returns `(retired, interpreted_after, reason)`.
fn run_one(jit: &mut Jit, bits: Bits, code: &[u8], seed: &Seed) -> (Run, Option<String>) {
    let mode = mode_of(bits);
    let Some((mut mem_j, mut cpu_j)) = setup(bits, code, seed) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let Some((mut mem_i, mut cpu_i)) = setup(bits, code, seed) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let before = cpu_j.state().clone();

    jit.invalidate(); // fresh address space every trial
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode);

    let retired = match run {
        Run::NotCompiled => {
            // A declined block must be a no-op, in every observable respect.
            if let Some(r) = diff_state(cpu_j.state(), &before) {
                return (run, Some(format!("declined block changed state: {r}")));
            }
            return (run, None);
        }
        Run::Executed { insns } | Run::Faulted { insns } => insns,
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
    if let Some(r) = diff_mem(&mem_j, &mem_i) {
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
        let (bytes, label, seed, generated) = trial_at(cfg.bits, cfg.seed, index, cfg.chain);
        s.generated += generated;
        let (run, reason) = run_one(&mut jit, cfg.bits, &bytes, &seed);
        s.trials += 1;
        match run {
            Run::NotCompiled => {
                s.not_compiled += 1;
                s.interpreted += 1;
            }
            Run::Executed { insns } => {
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
            if s.first.len() < cfg.max_report {
                s.first.push(JitDivergence { index, label, bytes, reason });
            }
        }
    }
    s.declined_ops = jit.stats().top_declined(20);
    Ok(s)
}

pub fn render(d: &JitDivergence) -> String {
    let hex: Vec<String> = d.bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("  #{:<10} {}\n      [{}]\n      Δ {}", d.index, d.label, hex.join(" "), d.reason)
}
