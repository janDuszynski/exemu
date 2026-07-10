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

/// The eight x87 stack registers (TOP-relative: `ST0` is the current top).
const STS: [RegisterX86; 8] = [
    RegisterX86::ST0,
    RegisterX86::ST1,
    RegisterX86::ST2,
    RegisterX86::ST3,
    RegisterX86::ST4,
    RegisterX86::ST5,
    RegisterX86::ST6,
    RegisterX86::ST7,
];

/// The eight low XMM registers (all the generator uses; XMM8-15 need REX).
const XMMS: [RegisterX86; 16] = [
    RegisterX86::XMM0,
    RegisterX86::XMM1,
    RegisterX86::XMM2,
    RegisterX86::XMM3,
    RegisterX86::XMM4,
    RegisterX86::XMM5,
    RegisterX86::XMM6,
    RegisterX86::XMM7,
    RegisterX86::XMM8,
    RegisterX86::XMM9,
    RegisterX86::XMM10,
    RegisterX86::XMM11,
    RegisterX86::XMM12,
    RegisterX86::XMM13,
    RegisterX86::XMM14,
    RegisterX86::XMM15,
];

/// The observable result of one step.
struct Post {
    gpr: [u64; 16],
    rflags: u64,
    ip: u64,
    xmm: [u128; 16],
    data: Vec<u8>,
    /// x87 physical data registers (80-bit) in ST-relative order as read out
    /// from the *final* TOP, so both engines are compared register-for-register
    /// regardless of how many pushes/pops the instruction did.
    st: [u128; 8],
    /// x87 status and control words.
    sw: u16,
    cw: u16,
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
        s.x87.st = seed.st;
        s.x87.cw = seed.cw;
        s.x87.sw = seed.sw; // TOP=0 at seed time
        s.x87.tw = seed.tw;
        s.rip = CODE_BASE;
    }
    let mut hooks = NoHooks;
    match cpu.step(&mut mem, &mut hooks) {
        Ok(Exit::Continue) => {
            let (gpr, rflags, ip, xmm, sw, cw) = {
                let s = cpu.state();
                (s.gpr, s.rflags, s.rip, s.xmm, s.x87.sw, s.x87.cw)
            };
            // Read the ST stack ST-relative to the final TOP.
            let mut st = [0u128; 8];
            {
                let x = &cpu.state().x87;
                for (i, slot) in st.iter_mut().enumerate() {
                    *slot = x.st[x.phys(i as u8)] & ((1u128 << 80) - 1);
                }
            }
            let mut data = vec![0u8; gen::DATA_LEN];
            if mem.read(gen::DATA_BASE, &mut data).is_err() {
                return Outcome::Fault;
            }
            Outcome::Ok(Post { gpr, rflags, ip, xmm, data, st, sw, cw })
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
    // xmm8..15 exist only in 64-bit mode.
    let nxmm = if bits == Bits::B64 { 16 } else { 8 };
    for (i, x) in XMMS[..nxmm].iter().enumerate() {
        if uc.reg_write_long(*x, &seed.xmm[i].to_le_bytes()).is_err() {
            return Outcome::Fault;
        }
    }
    // Seed the x87 FPU: control/status/tag words, then the eight stack
    // registers (TOP=0 at seed time, so ST(i) == seed.st[i]).
    let _ = uc.reg_write(RegisterX86::FPCW, seed.cw as u64);
    let _ = uc.reg_write(RegisterX86::FPSW, seed.sw as u64);
    let _ = uc.reg_write(RegisterX86::FPTAG, seed.tw as u64);
    for (i, r) in STS.iter().enumerate() {
        let mut bytes = [0u8; 10];
        bytes.copy_from_slice(&seed.st[i].to_le_bytes()[..10]);
        if uc.reg_write_long(*r, &bytes).is_err() {
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
            for (i, x) in XMMS[..nxmm].iter().enumerate() {
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
            // x87 stack (ST-relative to Unicorn's final TOP), status + control.
            let mut st = [0u128; 8];
            for (i, r) in STS.iter().enumerate() {
                if let Ok(bytes) = uc.reg_read_long(*r) {
                    if bytes.len() >= 10 {
                        let mut a = [0u8; 16];
                        a[..10].copy_from_slice(&bytes[..10]);
                        st[i] = u128::from_le_bytes(a);
                    }
                }
            }
            let sw = uc.reg_read(RegisterX86::FPSW).unwrap_or(0) as u16;
            let cw = uc.reg_read(RegisterX86::FPCW).unwrap_or(0) as u16;
            Outcome::Ok(Post { gpr, rflags, ip, xmm, data, st, sw, cw })
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
    // xmm8..15 exist only in 64-bit mode; compare them there too (the
    // generator now reaches them via REX.R/B).
    let nxmm = if bits == Bits::B64 { 16 } else { 8 };
    for i in 0..nxmm {
        if !xmm_eq(a.xmm[i], b.xmm[i], trial.xmm_nan) {
            return Some(format!("xmm{i} exemu={:#034x} unicorn={:#034x}", a.xmm[i], b.xmm[i]));
        }
    }
    for (i, (x, y)) in a.data.iter().zip(b.data.iter()).enumerate() {
        if x != y {
            return Some(format!("mem[{:#x}] exemu={:#04x} unicorn={:#04x}", gen::DATA_BASE + i as u64, x, y));
        }
    }
    if trial.fpu {
        if let Some(r) = diff_fpu(a, b, trial) {
            return Some(r);
        }
    }
    if a.ip != b.ip {
        return Some(format!("ip exemu={:#x} unicorn={:#x}", a.ip, b.ip));
    }
    None
}

/// x87 stack + status/control comparison (only for `trial.fpu` trials).
/// Registers flagged `fpu_approx` are compared NaN-aware and to the value they
/// represent as `f64` (transcendental/ROM-constant slop), not bit-exact.
fn diff_fpu(a: &Post, b: &Post, trial: &gen::Trial) -> Option<String> {
    for i in 0..8u8 {
        let (x, y) = (a.st[i as usize], b.st[i as usize]);
        if x == y {
            continue;
        }
        if trial.fpu_approx & (1 << i) != 0 {
            // Loose compare for transcendental results: the host math library
            // and the reference x87 agree only to a few ULP in the last
            // significand bits, so accept a small tolerance (or both NaN).
            let fx = ext80_to_f64(x);
            let fy = ext80_to_f64(y);
            if (fx.is_nan() && fy.is_nan()) || f64_within_ulps(fx, fy, 4) {
                continue;
            }
        }
        // Both-NaN (possibly different payloads) counts as equal.
        if ext80_is_nan(x) && ext80_is_nan(y) {
            continue;
        }
        return Some(format!("st{i} exemu={x:#022x} unicorn={y:#022x}"));
    }
    let sa = a.sw & trial.sw_mask;
    let sb = b.sw & trial.sw_mask;
    if sa != sb {
        return Some(format!("fpsw(mask={:#x}) exemu={:#06x} unicorn={:#06x} Δ={:#x}", trial.sw_mask, sa, sb, sa ^ sb));
    }
    if a.cw != b.cw {
        return Some(format!("fpcw exemu={:#06x} unicorn={:#06x}", a.cw, b.cw));
    }
    None
}

/// Decode a raw 80-bit extended value to the nearest f64 (for loose compares).
fn ext80_to_f64(v: u128) -> f64 {
    let sign = ((v >> 79) & 1) as u64;
    let exp = ((v >> 64) & 0x7fff) as u32;
    let signif = v as u64;
    if exp == 0x7fff {
        let frac = signif & 0x7fff_ffff_ffff_ffff;
        return if frac == 0 {
            if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY }
        } else {
            f64::NAN
        };
    }
    if exp == 0 && signif == 0 {
        return f64::from_bits(sign << 63);
    }
    let mantissa = signif as f64;
    let e2 = exp as i32 - 16383 - 63;
    let mag = mantissa * (e2 as f64).exp2();
    if sign == 1 { -mag } else { mag }
}

/// True when `a` and `b` are within `max_ulps` units-in-the-last-place of each
/// other (used only for transcendental result tolerance).
fn f64_within_ulps(a: f64, b: f64, max_ulps: u64) -> bool {
    if a == b {
        return true;
    }
    if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    let ua = a.to_bits();
    let ub = b.to_bits();
    ua.abs_diff(ub) <= max_ulps
}

fn ext80_is_nan(v: u128) -> bool {
    let exp = ((v >> 64) & 0x7fff) as u32;
    let frac = (v as u64) & 0x7fff_ffff_ffff_ffff;
    exp == 0x7fff && frac != 0
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
