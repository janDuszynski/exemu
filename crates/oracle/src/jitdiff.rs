use crate::gen::{self, Seed};
use crate::rng::Rng;
use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::compile::{Compiler, MAX_INSNS};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const PAGE: u64 = 0x1000;
const LOW_CODE: u64 = 0x1000;
const LOW_STACK: u64 = 0x8000;
const TOP32: u64 = 0xFFFF_F000;
const HIGH64: u64 = 0x1_0000_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    Low,
    EdgeCode,
    EdgeData,
}

impl Layout {
    pub const ALL: [Layout; 3] = [Layout::Low, Layout::EdgeCode, Layout::EdgeData];

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutMix {
    Low,
    Edge,
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

struct Space {
    regions: Vec<(&'static str, u64, u64, Perm)>,
    code_base: u64,
    code_len: u64,
    flush: bool,
    sp: u64,
    wrap_base: u64,
    push_sp: u64,
    pop_sp: u64,
}

const ROOM: u64 = PAGE;

fn space(layout: Layout, bits: Bits, roomy: bool) -> Space {
    let room = if roomy { ROOM } else { 0 };
    let data = (
        "data",
        gen::DATA_BASE,
        gen::DATA_LEN as u64 + room,
        Perm::RW,
    );
    let stack_room = match (layout, bits) {
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

pub struct JitDivergence {
    pub index: u64,
    pub label: String,
    pub bytes: Vec<u8>,
    pub reason: String,
    pub layout: Layout,
    pub at: u64,
}

pub struct JitFuzzConfig {
    pub bits: Bits,
    pub count: u64,
    pub seed: u64,
    pub max_report: usize,
    pub chain: u32,
    pub layouts: LayoutMix,
    pub laps: u32,
    pub debug: DebugMix,
    pub cut: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DebugMix {
    #[default]
    Off,
    Break,
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

pub const LAP_MAX_INSNS: u32 = 3;

const CUT_SALT: u64 = 0xC07_B0D6_E7;

#[derive(Default)]
pub struct JitSummary {
    pub trials: u64,
    pub compiled: u64,
    pub insns: u64,
    pub not_compiled: u64,
    pub faults: u64,
    pub divergences: u64,
    pub first: Vec<JitDivergence>,
    pub interpreted: u64,
    pub generated: u64,
    pub links_taken: u64,
    pub declined_ops: Vec<(u16, u64)>,
    pub by_layout: [u64; 3],
    pub div_by_layout: [u64; 3],
    pub tlb_fills: u64,
    pub tlb_denied: u64,
    pub breakpoint_stops: u64,
    pub watch_stops: u64,
    pub armed_tlb_fills: u64,
    pub debug_split: u64,
    pub budget_stops: u64,
}

impl JitSummary {
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

fn boundary_shape(rng: &mut Rng, bits: Bits, sp: &Space) -> (Vec<u8>, String, u64) {
    let mut b = Vec::new();
    let (label, n) = match rng.below(11) {
        0 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            let r = rng.below(8) as u8;
            b.push(0x50 | r);
            (format!("mov esp,{:#x} ; push r{r}", sp.push_sp), 2)
        }
        1 => {
            mov_reg_imm(&mut b, bits, RSP, sp.pop_sp);
            let r = rng.below(8) as u8;
            b.push(0x58 | r);
            (format!("mov esp,{:#x} ; pop r{r}", sp.pop_sp), 2)
        }
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
        3 => {
            mov_reg_imm(&mut b, bits, RBP, sp.pop_sp);
            b.push(0xC9);
            (format!("mov ebp,{:#x} ; leave", sp.pop_sp), 2)
        }
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
        6 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            b.push(0xE8);
            b.extend_from_slice(&0u32.to_le_bytes());
            (format!("mov esp,{:#x} ; call rel32 +0", sp.push_sp), 2)
        }
        7 => {
            mov_reg_imm(&mut b, bits, RSP, sp.push_sp);
            b.push(0xE8);
            b.extend_from_slice(&0u32.to_le_bytes());
            b.push(0x58);
            let wide = bits == Bits::B64;
            if wide {
                b.push(0x48);
            }
            let after = if wide { 1 + 4 + 2 } else { 1 + 3 + 2 };
            b.extend_from_slice(&[0x83, 0xC0, after]);
            b.extend_from_slice(&[0xFF, 0xE0]);
            ("call +0 ; pop rax ; add rax,n ; jmp rax".into(), 4)
        }
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
            b.push(0x40 | ((reg & 7) << 3) | RBP);
            b.push(disp);
            (format!("mov ebp,{:#x} ; {what}", sp.wrap_base), 2)
        }
        9 => {
            mov_reg_imm(&mut b, bits, RSP, sp.pop_sp);
            b.push(0xC3);
            (format!("mov esp,{:#x} ; ret", sp.pop_sp), 2)
        }
        10 => {
            mov_reg_imm(&mut b, bits, RSP, sp.pop_sp);
            let extra = rng.next_u32() as u16;
            b.push(0xC2);
            b.extend_from_slice(&extra.to_le_bytes());
            (format!("mov esp,{:#x} ; ret {extra:#x}", sp.pop_sp), 2)
        }
        _ => unreachable!(),
    };
    (b, label, n)
}

fn rel32(rng: &mut Rng) -> i32 {
    match rng.below(4) {
        0 => rng.next_u32() as i32,
        1 => -(rng.below(0x2000) as i32),
        _ => rng.below(0x2000) as i32,
    }
}

struct TrialPlan {
    bytes: Vec<u8>,
    label: String,
    seed: Seed,
    generated: u64,
    tail: u64,
    layout: Layout,
    space: Space,
    at: u64,
}

fn trial_at(cfg: &JitFuzzConfig, index: u64) -> TrialPlan {
    let bits = cfg.bits;
    let mut rng = Rng::for_trial(cfg.seed, index);
    let layout = cfg.layouts.pick(&mut rng);
    let sp = space(layout, bits, rng.below(2) == 0);
    let mut seed = gen::seed(&mut rng);
    let mut bytes = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut generated = 0u64;
    let lap_by_ret = cfg.laps > 1 && rng.boolean();
    let mov_len = match bits {
        Bits::B32 => 5,
        Bits::B64 => 10,
    };
    let tail_len = match (cfg.laps > 1, lap_by_ret) {
        (true, true) => mov_len + 2,
        (true, false) => 5,
        (false, _) => 1,
    };
    let room = sp.code_len as usize - tail_len;
    for _ in 0..cfg.chain.max(1) {
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
    let tail;
    if sp.flush && !bytes.is_empty() && rng.boolean() {
        let cut = (1 + rng.below(6) as usize).min(bytes.len() - 1);
        bytes.truncate(bytes.len() - cut);
        tail = 1;
    } else if cfg.laps > 1 && lap_by_ret {
        let top = if sp.flush {
            sp.code_base + sp.code_len - (bytes.len() + tail_len) as u64
        } else {
            sp.code_base
        };
        mov_reg_imm(&mut bytes, bits, 0, top);
        bytes.push(0x50);
        bytes.push(0xC3);
        tail = 3;
    } else if cfg.laps > 1 {
        let back = -((bytes.len() + 5) as i64) as i32;
        bytes.push(0xE9);
        bytes.extend_from_slice(&back.to_le_bytes());
        tail = 1;
    } else {
        bytes.push(0xC3);
        tail = 1;
    }
    seed.gpr[RSP as usize] = sp.sp;
    let at = if sp.flush {
        sp.code_base + sp.code_len - bytes.len() as u64
    } else {
        sp.code_base
    };
    TrialPlan { bytes, label: labels.join(" ; "), seed, generated, tail, layout, space: sp, at }
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

struct Twin {
    mem_j: VirtualMemory,
    cpu_j: Interpreter,
    mem_i: VirtualMemory,
    cpu_i: Interpreter,
}

fn run_lapped(
    jit: &mut Jit,
    plan: &TrialPlan,
    laps: u32,
    mut cuts: Option<Rng>,
    twin: Twin,
) -> (Run, Option<String>) {
    let Twin { mut mem_j, mut cpu_j, mut mem_i, mut cpu_i } = twin;
    let budget = laps as u64 * (plan.generated + plan.tail);
    let mut hooks = NoHooks;
    let mut total: u32 = 0;
    let mut last = Run::NotCompiled;
    let mut stopped_mid_instruction = false;
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
        let rest = budget - total as u64;
        let left = match cuts.as_mut() {
            Some(rng) => {
                let cut = match rng.below(4) {
                    0 => 8 + rng.below(40),
                    _ => rng.below(2 * LAP_MAX_INSNS + 2),
                };
                rest.min(u64::from(cut))
            }
            None => rest,
        };
        let mode = mode_of(cpu_j.bits());
        let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, left);
        if u64::from(run.insns()) > left {
            return (
                run,
                Some(format!(
                    "the JIT retired {} instructions against a budget of {left} at instruction {total}",
                    run.insns()
                )),
            );
        }
        total += run.insns();
        last = run;
        if let Some(r) = catch_up(&mut cpu_i, &mut mem_i, &mut done, total) {
            return (last, Some(r));
        }
        if let Some(r) = diff_state(cpu_j.state(), cpu_i.state()) {
            return (last, Some(r));
        }
        match run {
            Run::Executed { .. } => {}
            Run::Faulted { .. } => break,
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
    (
        match last {
            Run::Faulted { .. } => Run::Faulted { insns: total },
            Run::NotCompiled if total == 0 => Run::NotCompiled,
            _ => Run::Executed { insns: total },
        },
        None,
    )
}

fn run_one(jit: &mut Jit, cfg: &JitFuzzConfig, plan: &TrialPlan, index: u64) -> (Run, Option<String>) {
    let (bits, laps) = (cfg.bits, cfg.laps);
    let mode = mode_of(bits);
    let Some((mut mem_j, mut cpu_j)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let Some((mut mem_i, mut cpu_i)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let before = cpu_j.state().clone();

    jit.invalidate();
    if laps > 1 {
        let cuts = cfg.cut.then(|| Rng::for_trial(cfg.seed ^ CUT_SALT, index));
        return run_lapped(jit, plan, laps, cuts, Twin { mem_j, cpu_j, mem_i, cpu_i });
    }
    let one_block = Compiler::compile(&mem_j, mode, plan.at, MAX_INSNS, None, u64::MAX).insns;
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, u64::from(one_block));

    let retired = match run {
        Run::NotCompiled => {
            if let Some(r) = diff_state(cpu_j.state(), &before) {
                return (run, Some(format!("declined block changed state: {r}")));
            }
            return (run, None);
        }
        Run::Executed { insns } | Run::SideExit { insns } | Run::Faulted { insns } => insns,
    };

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
            run_one(&mut jit, cfg, &plan, index)
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
    s.budget_stops = jit.stats().budget_stops;
    Ok(s)
}

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
    let budget = plan.generated + plan.tail;

    jit.set_debug(DebugControl::detached());
    jit.invalidate();
    let Some((mut mem_n, mut cpu_n)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
    let natural = jit.run(cpu_n.state_mut(), &mut mem_n, mode, budget).insns();

    let Some((mut mem_r, mut cpu_r)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
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
            trace.push(cpu_r.state().rip);
            let target = trace[rng.below(trace.len() as u32) as usize];
            dbg.arm_break(target);
            let first = trace.iter().position(|&a| a == target).unwrap_or(trace.len() - 1);
            expected = (first as u32).min(natural);
        }
        DebugMix::Watch => {
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

    jit.set_debug(dbg.clone());
    jit.invalidate();
    let Some((mut mem_j, mut cpu_j)) = setup(bits, plan) else {
        return (Run::NotCompiled, Some("could not build the address space".into()));
    };
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
