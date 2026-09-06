use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const STACK: u64 = 0x3_0000;

fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn program() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&[0xB8, 0x08, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xBB, 0x01, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xBA, 0x00, 0x00, 0x02, 0x00]);
    assert_eq!(c.len(), LOOP_OFF);
    c.extend_from_slice(&[0x83, 0xC3, 0x07]);
    c.extend_from_slice(&[0xC1, 0xE3, 0x01]);
    c.extend_from_slice(&[0x89, 0x1A]);
    c.extend_from_slice(&[0x8B, 0x0A]);
    c.extend_from_slice(&[0x01, 0xCB]);
    c.extend_from_slice(&[0x83, 0xEB, 0x05]);
    c.extend_from_slice(&[0x31, 0xC9]);
    c.extend_from_slice(&[0x83, 0xC1, 0x09]);
    c.extend_from_slice(&[0x29, 0xCB]);
    c.extend_from_slice(&[0xD1, 0xEB]);
    c.extend_from_slice(&[0x81, 0xE3, 0xFF, 0xFF, 0x00, 0x00]);
    c.extend_from_slice(&[0x83, 0xCB, 0x01]);
    c.extend_from_slice(&[0x89, 0x5A, 0x04]);
    c.extend_from_slice(&[0x8B, 0x4A, 0x04]);
    c.extend_from_slice(&[0xFF, 0xC8]);
    let back = LOOP_OFF as i64 - (c.len() + 2) as i64;
    c.extend_from_slice(&[0x75, back as i8 as u8]);
    c.push(0xF4);
    assert_eq!(c.len(), PROGRAM_LEN);
    c
}

const LOOP_OFF: usize = 15;
const PROGRAM_LEN: usize = 59;

fn instruction_offsets() -> Vec<usize> {
    vec![0, 5, 10, 15, 18, 21, 23, 25, 27, 30, 32, 35, 37, 39, 45, 48, 51, 54, 56, 58]
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Stop {
    Breakpoint { rip: u64, steps: u64 },
    Watch { addr: u64, kind: WatchKind, steps: u64 },
    Halted { steps: u64 },
    Other { what: String, steps: u64 },
}

impl Stop {
    fn steps(&self) -> u64 {
        match self {
            Stop::Breakpoint { steps, .. }
            | Stop::Watch { steps, .. }
            | Stop::Halted { steps }
            | Stop::Other { steps, .. } => *steps,
        }
    }
}

#[derive(Clone, Debug)]
struct Outcome {
    stop: Stop,
    native: u64,
    breakpoint_stops: u64,
    watch_stops: u64,
    links_taken: u64,
    tlb_fills: u64,
    code_bytes: u64,
    blocks_compiled: u64,
    flushes: u64,
}

fn build(bits: Bits, code: &[u8], dbg: &DebugControl) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("data", DATA, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", STACK, 0x2000, Perm::RW)).unwrap();
    mem.poke(CODE, code).unwrap();
    mem.set_debug(dbg.clone());
    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().gpr[4] = STACK + 0x1000;
    (mem, cpu)
}

const MAX_STEPS: u64 = 100_000;

fn run_to_stop(bits: Bits, code: &[u8], dbg: &DebugControl, use_jit: bool) -> Outcome {
    let (mut mem, mut cpu) = build(bits, code, dbg);
    let mode = match bits {
        Bits::B64 => Mode::Long,
        Bits::B32 => Mode::Protected,
    };
    let mut jit = use_jit.then(|| {
        let mut j = Jit::new(1 << 20).expect("a code buffer");
        j.set_debug(dbg.clone());
        j
    });
    let mut hooks = NoHooks;
    let mut steps = 0u64;
    let stop = loop {
        if steps > MAX_STEPS {
            break Stop::Other { what: "step cap".into(), steps };
        }
        if let Some((addr, kind)) = dbg.take_watch_hit() {
            break Stop::Watch { addr, kind, steps };
        }
        let rip = cpu.state().rip;
        if dbg.is_break(rip) {
            break Stop::Breakpoint { rip, steps };
        }
        if let Some(j) = jit.as_mut() {
            let ran = j.run(cpu.state_mut(), &mut mem, mode, u64::MAX);
            steps += u64::from(ran.insns());
            if matches!(ran, Run::Executed { .. }) {
                continue;
            }
        }
        match cpu.step(&mut mem, &mut hooks) {
            Ok(Exit::Continue) => steps += 1,
            Ok(Exit::Halted) => break Stop::Halted { steps },
            other => break Stop::Other { what: format!("{other:?}"), steps },
        }
    };
    let s = jit.as_ref().map(|j| j.stats().clone());
    Outcome {
        stop,
        native: s.as_ref().map_or(0, |s| s.insns_executed),
        breakpoint_stops: s.as_ref().map_or(0, |s| s.breakpoint_stops),
        watch_stops: s.as_ref().map_or(0, |s| s.watch_stops),
        links_taken: s.as_ref().map_or(0, |s| s.links_taken),
        tlb_fills: s.as_ref().map_or(0, |s| s.tlb_fills),
        code_bytes: s.as_ref().map_or(0, |s| s.peak_code_bytes as u64),
        blocks_compiled: s.as_ref().map_or(0, |s| s.blocks_compiled),
        flushes: s.as_ref().map_or(0, |s| s.flushes),
    }
}

fn both_bitnesses() -> [Bits; 2] {
    [Bits::B64, Bits::B32]
}

#[test]
fn the_trace_this_file_sweeps_is_genuinely_compiled_and_natively_linked() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::detached();
        let jit = run_to_stop(bits, &code, &dbg, true);
        let interp = run_to_stop(bits, &code, &dbg, false);
        assert_eq!(jit.stop, interp.stop, "{bits:?}: undebugged runs must agree");
        assert!(matches!(jit.stop, Stop::Halted { .. }), "{bits:?}: {:?}", jit.stop);
        let steps = jit.stop.steps();
        assert_eq!(steps, 3 + 8 * 16, "{bits:?}: the trace is the length it is meant to be");
        assert_eq!(jit.native, steps, "{bits:?}: only `hlt` should reach the interpreter");
        assert_eq!(jit.blocks_compiled, 2, "{bits:?}");
        assert!(jit.links_taken >= 5, "{bits:?}: back edge not linked ({})", jit.links_taken);
        assert_eq!(jit.breakpoint_stops, 0, "{bits:?}: nothing was armed");
        assert_eq!(jit.watch_stops, 0, "{bits:?}: nothing was armed");
        assert!(jit.tlb_fills > 0, "{bits:?}: the guest-memory TLB filled nothing");
    }
}

#[test]
fn a_breakpoint_at_every_address_of_the_trace_stops_both_engines_identically() {
    if !jit_available() {
        return;
    }
    let code = program();
    let boundaries = instruction_offsets();
    for bits in both_bitnesses() {
        let mut stopped = 0;
        let mut ran_through = 0;
        for off in 0..PROGRAM_LEN {
            let at = CODE + off as u64;
            let dbg = DebugControl::attached();
            dbg.arm_break(at);
            let jit = run_to_stop(bits, &code, &dbg, true);
            let dbg_i = DebugControl::attached();
            dbg_i.arm_break(at);
            let interp = run_to_stop(bits, &code, &dbg_i, false);
            assert_eq!(
                jit.stop, interp.stop,
                "{bits:?}: breakpoint at {at:#x} (offset {off}) diverged"
            );
            if boundaries.contains(&off) {
                stopped += 1;
                assert_eq!(
                    jit.stop,
                    Stop::Breakpoint { rip: at, steps: jit.stop.steps() },
                    "{bits:?}: offset {off} is an instruction boundary and must stop"
                );
                if off != 0 {
                    assert!(
                        jit.native > 0,
                        "{bits:?}: offset {off} stopped without compiling anything"
                    );
                }
            } else {
                ran_through += 1;
                assert!(
                    matches!(jit.stop, Stop::Halted { .. }),
                    "{bits:?}: offset {off} is mid-instruction and must not stop: {:?}",
                    jit.stop
                );
                assert_eq!(
                    jit.native,
                    jit.stop.steps(),
                    "{bits:?}: a mid-instruction address must not split a block"
                );
            }
        }
        assert_eq!(stopped, boundaries.len(), "{bits:?}: every boundary stopped");
        assert_eq!(
            ran_through,
            PROGRAM_LEN - boundaries.len(),
            "{bits:?}: every non-boundary ran through"
        );
    }
}

#[test]
fn both_engines_agree_on_which_instruction_a_breakpoint_is() {
    if !jit_available() {
        return;
    }
    let code = program();
    let body: Vec<usize> = instruction_offsets().into_iter().filter(|o| *o >= LOOP_OFF).collect();
    for bits in both_bitnesses() {
        for (i, off) in body.iter().enumerate() {
            if *off == 58 {
                continue;
            }
            let at = CODE + *off as u64;
            let dbg = DebugControl::attached();
            dbg.arm_break(at);
            let jit = run_to_stop(bits, &code, &dbg, true);
            let dbg_i = DebugControl::attached();
            dbg_i.arm_break(at);
            let interp = run_to_stop(bits, &code, &dbg_i, false);
            let expected = 3 + i as u64;
            assert_eq!(
                jit.stop,
                Stop::Breakpoint { rip: at, steps: expected },
                "{bits:?}: {at:#x} should be instruction {expected}"
            );
            assert_eq!(interp.stop, jit.stop, "{bits:?}: {at:#x}");
        }
    }
}

#[test]
fn the_first_armed_address_reached_is_the_one_that_stops_the_run() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        dbg.arm_break(CODE + 51);
        dbg.arm_break(CODE + 21);
        let jit = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(jit.stop, Stop::Breakpoint { rip: CODE + 21, steps: 5 }, "{bits:?}");
        assert!(jit.native > 0, "{bits:?}: nothing compiled");
        let dbg = DebugControl::attached();
        dbg.arm_break(CODE + 51);
        let jit = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(jit.stop, Stop::Breakpoint { rip: CODE + 51, steps: 16 }, "{bits:?}");
    }
}

#[test]
fn arming_after_the_block_is_already_compiled_and_linked_still_stops_the_run() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        let (mut mem, mut cpu) = build(bits, &code, &dbg);
        let mode = match bits {
            Bits::B64 => Mode::Long,
            Bits::B32 => Mode::Protected,
        };
        let mut jit = Jit::new(1 << 20).unwrap();
        jit.set_debug(dbg.clone());
        let mut hooks = NoHooks;
        let warm_up = 3 + 5 * 16;
        let ran = jit.run(cpu.state_mut(), &mut mem, mode, warm_up);
        let mut steps = u64::from(ran.insns());
        assert_eq!(steps, warm_up, "{bits:?}: the warm-up chain stopped early ({ran:?})");
        let warm = jit.stats().clone();
        assert!(warm.blocks_compiled > 0, "{bits:?}: nothing compiled in the warm-up");
        assert!(warm.links_taken > 0, "{bits:?}: the back edge never linked");
        let flushes_before = warm.flushes;

        dbg.arm_break(CODE + 37);
        let armed_at_step = steps;
        let stop = loop {
            assert!(steps < MAX_STEPS, "{bits:?}: wedged");
            let rip = cpu.state().rip;
            if dbg.is_break(rip) {
                break (rip, steps);
            }
            let ran = jit.run(cpu.state_mut(), &mut mem, mode, u64::MAX);
            steps += u64::from(ran.insns());
            if matches!(ran, Run::Executed { .. }) {
                continue;
            }
            match cpu.step(&mut mem, &mut hooks) {
                Ok(Exit::Continue) => steps += 1,
                other => panic!("{bits:?}: unexpected {other:?}"),
            }
        };
        assert_eq!(stop.0, CODE + 37, "{bits:?}");
        assert!(
            stop.1 - armed_at_step < 16,
            "{bits:?}: the arm took {} instructions to land",
            stop.1 - armed_at_step
        );
        assert!(
            jit.stats().flushes > flushes_before,
            "{bits:?}: the generation change did not invalidate the cache"
        );
        assert!(
            jit.stats().breakpoint_stops > 0,
            "{bits:?}: the chain did not hand back at the armed address"
        );
    }
}

#[test]
fn disarming_puts_the_block_back() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let plain = run_to_stop(bits, &code, &DebugControl::detached(), true);
        let dbg = DebugControl::attached();
        dbg.arm_break(CODE + 37);
        dbg.disarm_break(CODE + 37);
        assert!(!dbg.any_breakpoints());
        let after = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(after.stop, plain.stop, "{bits:?}");
        assert_eq!(after.native, plain.native, "{bits:?}");
        assert_eq!(after.blocks_compiled, plain.blocks_compiled, "{bits:?}");
    }
}

#[test]
fn attaching_without_arming_emits_the_same_code_and_runs_the_same_run() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let off = run_to_stop(bits, &code, &DebugControl::detached(), true);
        let on = run_to_stop(bits, &code, &DebugControl::attached(), true);
        assert_eq!(on.stop, off.stop, "{bits:?}");
        assert_eq!(on.native, off.native, "{bits:?}");
        assert_eq!(on.blocks_compiled, off.blocks_compiled, "{bits:?}");
        assert_eq!(on.links_taken, off.links_taken, "{bits:?}");
        assert_eq!(on.tlb_fills, off.tlb_fills, "{bits:?}");
        assert_eq!(on.code_bytes, off.code_bytes, "{bits:?}: emitted code differs");
        assert_eq!(on.flushes, off.flushes, "{bits:?}");
    }
}

#[test]
fn a_watchpoint_on_every_touched_address_stops_both_engines_identically() {
    if !jit_available() {
        return;
    }
    let code = program();
    let kinds = [WatchKind::Read, WatchKind::Write, WatchKind::ReadWrite];
    for bits in both_bitnesses() {
        let mut hits = 0;
        for base in 0..12u64 {
            for len in [1u64, 2, 4] {
                for kind in kinds {
                    let arm = |d: &DebugControl| d.arm_watch(DATA + base, len, kind);
                    let dbg = DebugControl::attached();
                    arm(&dbg);
                    let jit = run_to_stop(bits, &code, &dbg, true);
                    let dbg_i = DebugControl::attached();
                    arm(&dbg_i);
                    let interp = run_to_stop(bits, &code, &dbg_i, false);
                    let what = format!("{bits:?}: watch {:#x}+{len} {kind:?}", DATA + base);
                    assert_eq!(jit.stop, interp.stop, "{what} diverged");
                    if let Stop::Watch { .. } = jit.stop {
                        hits += 1;
                        assert!(jit.native > 0, "{what}: nothing ran as native code");
                        assert!(jit.watch_stops > 0, "{what}: the block did not refuse the access");
                    } else {
                        assert!(matches!(jit.stop, Stop::Halted { .. }), "{what}: {:?}", jit.stop);
                        assert_eq!(jit.watch_stops, 0, "{what}: refused an unwatched access");
                    }
                }
            }
        }
        assert!(hits >= 20, "{bits:?}: the sweep only landed {hits} watch stops");
    }
}

#[test]
fn a_read_watch_and_a_write_watch_stop_on_different_instructions() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        dbg.arm_watch(DATA, 4, WatchKind::Write);
        let w = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(
            w.stop,
            Stop::Watch { addr: DATA, kind: WatchKind::Write, steps: 6 },
            "{bits:?}: write watch"
        );

        let dbg = DebugControl::attached();
        dbg.arm_watch(DATA, 4, WatchKind::Read);
        let r = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(
            r.stop,
            Stop::Watch { addr: DATA, kind: WatchKind::Read, steps: 7 },
            "{bits:?}: read watch"
        );
        assert!(w.native > 0 && r.native > 0, "{bits:?}: nothing compiled");
    }
}

#[test]
fn a_refused_store_has_not_landed_when_the_block_hands_back() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        dbg.arm_watch(DATA, 4, WatchKind::Write);
        let (mut mem, mut cpu) = build(bits, &code, &dbg);
        let mode = match bits {
            Bits::B64 => Mode::Long,
            Bits::B32 => Mode::Protected,
        };
        let mut jit = Jit::new(1 << 20).unwrap();
        jit.set_debug(dbg.clone());
        mem.poke(DATA, &0xDEAD_BEEFu32.to_le_bytes()).unwrap();
        let ran = jit.run(cpu.state_mut(), &mut mem, mode, u64::MAX);
        assert!(matches!(ran, Run::Faulted { .. }), "{bits:?}: expected a rewind, got {ran:?}");
        assert_eq!(jit.stats().watch_stops, 1, "{bits:?}");
        assert_eq!(
            mem.read_uint(DATA, 4).unwrap(),
            0xDEAD_BEEF,
            "{bits:?}: the refused store landed anyway"
        );
        assert_eq!(cpu.state().rip, CODE + 21, "{bits:?}: rewound to the wrong instruction");
        assert_eq!(dbg.take_watch_hit(), None, "{bits:?}: the JIT reported a hit itself");
    }
}

#[test]
fn an_armed_watchpoint_takes_the_guest_memory_tlb_out_of_the_path() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let plain = run_to_stop(bits, &code, &DebugControl::detached(), true);
        assert!(plain.tlb_fills > 0, "{bits:?}: the fast path was never engaged to begin with");

        let dbg = DebugControl::attached();
        dbg.arm_watch(DATA + 0x800, 4, WatchKind::ReadWrite);
        let armed = run_to_stop(bits, &code, &dbg, true);
        assert!(matches!(armed.stop, Stop::Halted { .. }), "{bits:?}: {:?}", armed.stop);
        assert_eq!(armed.stop.steps(), plain.stop.steps(), "{bits:?}");
        assert!(armed.native > 0, "{bits:?}: nothing compiled");
        assert_eq!(armed.tlb_fills, 0, "{bits:?}: an entry was cached while a watchpoint was armed");
        assert_eq!(armed.watch_stops, 0, "{bits:?}: refused an access outside the watched range");
    }
}

#[test]
fn the_fast_path_stays_out_of_the_way_even_if_only_the_jit_holds_the_handle() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        let (mut mem, mut cpu) = build(bits, &code, &DebugControl::detached());
        assert!(!mem.watchpoints_armed(), "{bits:?}: the backend must not be watching here");
        let mode = match bits {
            Bits::B64 => Mode::Long,
            Bits::B32 => Mode::Protected,
        };
        let mut jit = Jit::new(1 << 20).unwrap();
        jit.set_debug(dbg.clone());
        dbg.arm_watch(DATA + 4, 4, WatchKind::Write);
        let ran = jit.run(cpu.state_mut(), &mut mem, mode, u64::MAX);
        assert!(matches!(ran, Run::Faulted { .. }), "{bits:?}: got {ran:?}");
        assert_eq!(jit.stats().tlb_fills, 0, "{bits:?}: cached a page while watching");
        assert_eq!(jit.stats().watch_stops, 1, "{bits:?}");
        assert_eq!(cpu.state().rip, CODE + 48, "{bits:?}: rewound to the wrong instruction");
    }
}

#[test]
fn a_breakpoint_and_a_watchpoint_armed_together_stop_at_the_earlier_one() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let arm = |d: &DebugControl| {
            d.arm_watch(DATA, 4, WatchKind::Write);
            d.arm_break(CODE + 51);
        };
        let dbg = DebugControl::attached();
        arm(&dbg);
        let jit = run_to_stop(bits, &code, &dbg, true);
        let dbg_i = DebugControl::attached();
        arm(&dbg_i);
        let interp = run_to_stop(bits, &code, &dbg_i, false);
        assert_eq!(jit.stop, interp.stop, "{bits:?}");
        assert_eq!(
            jit.stop,
            Stop::Watch { addr: DATA, kind: WatchKind::Write, steps: 6 },
            "{bits:?}"
        );

        let arm = |d: &DebugControl| {
            d.arm_watch(DATA + 4, 4, WatchKind::Write);
            d.arm_break(CODE + 18);
        };
        let dbg = DebugControl::attached();
        arm(&dbg);
        let jit = run_to_stop(bits, &code, &dbg, true);
        let dbg_i = DebugControl::attached();
        arm(&dbg_i);
        let interp = run_to_stop(bits, &code, &dbg_i, false);
        assert_eq!(jit.stop, interp.stop, "{bits:?}");
        assert_eq!(jit.stop, Stop::Breakpoint { rip: CODE + 18, steps: 4 }, "{bits:?}");
    }
}
