//! The differential core: seed identical state into exemu and Unicorn, run one
//! instruction in each, and diff the architectural result under the trial's
//! defined-flags policy.

use crate::gen::{self, Seed};
use crate::rng::Rng;
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

const CODE_BASE: u64 = 0x1000;

/// x86 GPR ids in exemu register-index order, per bitness.
const REGS32: [RegisterX86; 8] = [
    RegisterX86::EAX,
    RegisterX86::ECX,
    RegisterX86::EDX,
    RegisterX86::EBX,
    RegisterX86::ESP,
    RegisterX86::EBP,
    RegisterX86::ESI,
    RegisterX86::EDI,
];
const REGS64: [RegisterX86; 16] = [
    RegisterX86::RAX,
    RegisterX86::RCX,
    RegisterX86::RDX,
    RegisterX86::RBX,
    RegisterX86::RSP,
    RegisterX86::RBP,
    RegisterX86::RSI,
    RegisterX86::RDI,
    RegisterX86::R8,
    RegisterX86::R9,
    RegisterX86::R10,
    RegisterX86::R11,
    RegisterX86::R12,
    RegisterX86::R13,
    RegisterX86::R14,
    RegisterX86::R15,
];

/// The eight low XMM registers (all the generator uses; XMM8-15 need REX).
const XMMS: [RegisterX86; 8] = [
    RegisterX86::XMM0,
    RegisterX86::XMM1,
    RegisterX86::XMM2,
    RegisterX86::XMM3,
    RegisterX86::XMM4,
    RegisterX86::XMM5,
    RegisterX86::XMM6,
    RegisterX86::XMM7,
];

/// The observable result of one step.
struct Post {
    gpr: [u64; 16],
    rflags: u64,
    ip: u64,
    xmm: [u128; 16],
    data: Vec<u8>,
}

/// Per-lane XMM equality under a NaN-aware policy (`nan` = 0 bit-exact, 4 f32
/// lanes, 8 f64 lanes; a lane NaN in both engines counts as equal).
fn xmm_eq(a: u128, b: u128, nan: u8) -> bool {
    if a == b {
        return true;
    }
    match nan {
        4 => (0..4).all(|l| {
            let (x, y) = ((a >> (l * 32)) as u32, (b >> (l * 32)) as u32);
            x == y || (f32::from_bits(x).is_nan() && f32::from_bits(y).is_nan())
        }),
        8 => (0..2).all(|l| {
            let (x, y) = ((a >> (l * 64)) as u64, (b >> (l * 64)) as u64);
            x == y || (f64::from_bits(x).is_nan() && f64::from_bits(y).is_nan())
        }),
        _ => false,
    }
}

// `Post` is deliberately large (full register + XMM snapshot); it lives only
// for the span of one trial's comparison, so boxing it would just add churn.
#[allow(clippy::large_enum_variant)]
enum Outcome {
    Ok(Post),
    Fault,
}

#[inline]
fn width_mask(bits: Bits) -> u64 {
    match bits {
        Bits::B32 => 0xffff_ffff,
        Bits::B64 => u64::MAX,
    }
}

fn run_exemu(bits: Bits, code: &[u8], seed: &Seed) -> Outcome {
    let mut mem = VirtualMemory::new();
    if mem.map(Region::new("code", CODE_BASE, 0x1000, Perm::RWX)).is_err()
        || mem.map(Region::new("data", gen::DATA_BASE, gen::DATA_LEN as u64, Perm::RW)).is_err()
        || mem.write(CODE_BASE, code).is_err()
        || mem.write(gen::DATA_BASE, &seed.data).is_err()
    {
        return Outcome::Fault;
    }
    let mut cpu = Interpreter::with_bits(bits);
    {
        let s = cpu.state_mut();
        s.gpr = seed.gpr;
        s.rflags = seed.rflags;
        s.xmm = seed.xmm;
        s.rip = CODE_BASE;
    }
    let mut hooks = NoHooks;
    match cpu.step(&mut mem, &mut hooks) {
        Ok(Exit::Continue) => {
            let (gpr, rflags, ip, xmm) = {
                let s = cpu.state();
                (s.gpr, s.rflags, s.rip, s.xmm)
            };
            let mut data = vec![0u8; gen::DATA_LEN];
            if mem.read(gen::DATA_BASE, &mut data).is_err() {
                return Outcome::Fault;
            }
            Outcome::Ok(Post { gpr, rflags, ip, xmm, data })
        }
        // #DE (Interrupt(0)), Halted, ProcessExit, or a memory/decode error.
        _ => Outcome::Fault,
    }
}

fn run_unicorn(bits: Bits, code: &[u8], seed: &Seed) -> Outcome {
    let (mode, regs, ip_reg): (Mode, &[RegisterX86], RegisterX86) = match bits {
        Bits::B32 => (Mode::MODE_32, &REGS32, RegisterX86::EIP),
        Bits::B64 => (Mode::MODE_64, &REGS64, RegisterX86::RIP),
    };
    // A fresh instance per trial: overwriting code at a fixed address would
    // otherwise hit Unicorn's stale translation-block cache.
    let mut uc = match Unicorn::new(Arch::X86, mode) {
        Ok(uc) => uc,
        Err(_) => return Outcome::Fault,
    };
    let mask = width_mask(bits);
    if uc.mem_map(CODE_BASE, 0x1000, Prot::ALL).is_err()
        || uc.mem_map(gen::DATA_BASE, gen::DATA_LEN as u64, Prot::ALL).is_err()
        || uc.mem_write(CODE_BASE, code).is_err()
        || uc.mem_write(gen::DATA_BASE, &seed.data).is_err()
    {
        return Outcome::Fault;
    }
    for (i, r) in regs.iter().enumerate() {
        if uc.reg_write(*r, seed.gpr[i] & mask).is_err() {
            return Outcome::Fault;
        }
    }
    for (i, x) in XMMS.iter().enumerate() {
        if uc.reg_write_long(*x, &seed.xmm[i].to_le_bytes()).is_err() {
            return Outcome::Fault;
        }
    }
    let _ = uc.reg_write(RegisterX86::EFLAGS, seed.rflags & 0xffff_ffff);
    let _ = uc.reg_write(ip_reg, CODE_BASE);
    // Run until rip reaches the end of the instruction (count=0 = no limit), so
    // a REP string op completes all its iterations in one go — exemu executes
    // the whole REP in a single step(), and count=1 would stop Unicorn after
    // just the first iteration.
    match uc.emu_start(CODE_BASE, CODE_BASE + code.len() as u64, 0, 0) {
        Ok(()) => {
            let mut gpr = [0u64; 16];
            for (i, r) in regs.iter().enumerate() {
                gpr[i] = uc.reg_read(*r).unwrap_or(0);
            }
            let rflags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
            let ip = uc.reg_read(ip_reg).unwrap_or(0);
            let mut xmm = [0u128; 16];
            for (i, x) in XMMS.iter().enumerate() {
                if let Ok(bytes) = uc.reg_read_long(*x) {
                    if bytes.len() >= 16 {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&bytes[..16]);
                        xmm[i] = u128::from_le_bytes(a);
                    }
                }
            }
            let mut data = vec![0u8; gen::DATA_LEN];
            if uc.mem_read(gen::DATA_BASE, &mut data).is_err() {
                return Outcome::Fault;
            }
            Outcome::Ok(Post { gpr, rflags, ip, xmm, data })
        }
        Err(_) => Outcome::Fault,
    }
}

/// A single detected divergence, ready to render.
pub struct Divergence {
    pub index: u64,
    pub label: String,
    pub bytes: Vec<u8>,
    pub reason: String,
    pub exemu: String,
    pub unicorn: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn regs_str(bits: Bits, p: &Post, nreg: usize) -> String {
    let mask = width_mask(bits);
    let names = exemu_core::Reg::NAMES;
    let mut parts: Vec<String> = (0..nreg).map(|i| format!("{}={:#x}", names[i], p.gpr[i] & mask)).collect();
    parts.push(format!("flags={:#x}", p.rflags & 0xffff));
    parts.push(format!("ip={:#x}", p.ip));
    parts.join(" ")
}

/// Compare two successful steps under the trial's policy; `Some(reason)` on
/// divergence.
fn diff(bits: Bits, a: &Post, b: &Post, trial: &gen::Trial, nreg: usize) -> Option<String> {
    let mask = width_mask(bits);
    for i in 0..nreg {
        if trial.skip_reg & (1 << i) != 0 {
            continue;
        }
        if a.gpr[i] & mask != b.gpr[i] & mask {
            return Some(format!("{} exemu={:#x} unicorn={:#x}", exemu_core::Reg::NAMES[i], a.gpr[i] & mask, b.gpr[i] & mask));
        }
    }
    let fa = a.rflags & trial.defined_flags;
    let fb = b.rflags & trial.defined_flags;
    if fa != fb {
        return Some(format!("flags(defined={:#x}) exemu={:#x} unicorn={:#x} Δ={:#x}", trial.defined_flags, fa, fb, fa ^ fb));
    }
    for i in 0..8 {
        if !xmm_eq(a.xmm[i], b.xmm[i], trial.xmm_nan) {
            return Some(format!("xmm{i} exemu={:#034x} unicorn={:#034x}", a.xmm[i], b.xmm[i]));
        }
    }
    for (i, (x, y)) in a.data.iter().zip(b.data.iter()).enumerate() {
        if x != y {
            return Some(format!("mem[{:#x}] exemu={:#04x} unicorn={:#04x}", gen::DATA_BASE + i as u64, x, y));
        }
    }
    if a.ip != b.ip {
        return Some(format!("ip exemu={:#x} unicorn={:#x}", a.ip, b.ip));
    }
    None
}

/// Configuration for a fuzzing run.
pub struct FuzzConfig {
    pub bits: Bits,
    pub count: u64,
    pub seed: u64,
    pub max_report: usize,
}

/// Aggregate result of a fuzzing run.
pub struct Summary {
    pub trials: u64,
    pub divergences: u64,
    pub both_faulted: u64,
    pub one_faulted: u64,
    pub first: Vec<Divergence>,
}

/// Run one reproducible trial by global index.
fn trial_at(bits: Bits, base_seed: u64, index: u64) -> (gen::Trial, Seed) {
    // Independent, index-addressable stream so any divergence reproduces.
    let mut rng = Rng::new(base_seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut seed = gen::seed(&mut rng);
    let trial = gen::build(&mut rng, bits, &mut seed);
    (trial, seed)
}

pub fn fuzz(cfg: &FuzzConfig) -> Summary {
    let nreg = match cfg.bits {
        Bits::B32 => 8,
        Bits::B64 => 16,
    };
    let mut summary = Summary { trials: 0, divergences: 0, both_faulted: 0, one_faulted: 0, first: Vec::new() };
    for index in 0..cfg.count {
        let (trial, seed) = trial_at(cfg.bits, cfg.seed, index);
        summary.trials += 1;
        let ex = run_exemu(cfg.bits, &trial.bytes, &seed);
        let un = run_unicorn(cfg.bits, &trial.bytes, &seed);
        let divergence = match (&ex, &un) {
            (Outcome::Fault, Outcome::Fault) => {
                summary.both_faulted += 1;
                None
            }
            (Outcome::Ok(a), Outcome::Ok(b)) => diff(cfg.bits, a, b, &trial, nreg).map(|reason| {
                (reason, regs_str(cfg.bits, a, nreg), regs_str(cfg.bits, b, nreg))
            }),
            (a, b) => {
                summary.one_faulted += 1;
                let ex_s = match a {
                    Outcome::Ok(p) => regs_str(cfg.bits, p, nreg),
                    Outcome::Fault => "FAULT".into(),
                };
                let un_s = match b {
                    Outcome::Ok(p) => regs_str(cfg.bits, p, nreg),
                    Outcome::Fault => "FAULT".into(),
                };
                Some(("only one engine faulted".to_string(), ex_s, un_s))
            }
        };
        if let Some((reason, exemu, unicorn)) = divergence {
            summary.divergences += 1;
            if summary.first.len() < cfg.max_report {
                summary.first.push(Divergence { index, label: trial.label.clone(), bytes: trial.bytes.clone(), reason, exemu, unicorn });
            }
        }
    }
    summary
}

/// Render a divergence for the terminal.
pub fn render(d: &Divergence) -> String {
    format!(
        "  #{:<10} {:<22} [{}]\n      Δ {}\n      exemu:   {}\n      unicorn: {}",
        d.index,
        d.label,
        hex(&d.bytes),
        d.reason,
        d.exemu,
        d.unicorn
    )
}
