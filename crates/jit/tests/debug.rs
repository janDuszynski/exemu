//! Breakpoints and watchpoints in **compiled** code (roadmap W9.3, S3 and S6).
//!
//! # What these tests have to be careful about
//!
//! The failure this file exists to catch is *not* "the debugger reports the
//! wrong thing". It is "the debugger reports nothing, because the guest was in
//! a natively linked chain that ran straight through the armed address". A test
//! that arms a breakpoint and then does not actually run compiled code proves
//! precisely nothing about that, so **every case below asserts, from the JIT's
//! own counters, how many guest instructions ran as native code before the
//! stop** — and the sweeps refuse to pass if that number is zero.
//!
//! # The loop these tests drive
//!
//! `crates/app`'s run loop is the debugger's single decision point, and it is
//! not reachable from this crate (`exemu-jit` does not depend on `exemu-app`,
//! and must not). [`run_to_stop`] below is a faithful model of it, in the
//! ordering that matters:
//!
//! 1. drain a recorded watch hit first (trap-**after**: the hit belongs to the
//!    instruction that has already completed);
//! 2. then test the address about to execute against the armed breakpoints;
//! 3. then run — the JIT if there is one, and `Run::Executed` means "come back
//!    to step 1 before anything else executes", while every other answer means
//!    "interpret exactly one instruction here".
//!
//! Every test runs the same program twice, once with a `Jit` and once without,
//! and requires the two to agree on the stop *and* on the instruction count.
//! The interpreter is the reference; the JIT is the thing under test.

use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const STACK: u64 = 0x3_0000;

/// The JIT is macOS/aarch64 only; everywhere else these tests are vacuous and
/// say so rather than passing quietly.
fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

/// A loop the compiler takes whole: sixteen integer instructions per iteration,
/// two stores and two loads among them, run eight times and then `hlt`.
///
/// Deliberate properties:
///
/// * **One block per iteration.** Sixteen instructions is well under
///   `MAX_INSNS`, so the body compiles as a single block and the back edge
///   becomes a *native link* — which is the only shape in which a chain can run
///   past an armed address without returning to Rust, and therefore the only
///   shape worth testing.
/// * **No REX-sensitive encodings.** Every instruction means the same thing in
///   32- and 64-bit mode (`ff c8` for `dec eax`, not `48`), so both bitnesses
///   run the identical bytes.
/// * **Four watchable accesses per iteration**, at two different data addresses
///   and in both directions, so a watchpoint sweep has somewhere to land.
/// * **Ends in `hlt`**, which the compiler declines — so the chain has a
///   natural end that is not a breakpoint.
fn program() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&[0xB8, 0x08, 0x00, 0x00, 0x00]); // 0:  mov eax, 8
    c.extend_from_slice(&[0xBB, 0x01, 0x00, 0x00, 0x00]); // 5:  mov ebx, 1
    c.extend_from_slice(&[0xBA, 0x00, 0x00, 0x02, 0x00]); // 10: mov edx, DATA
    assert_eq!(c.len(), LOOP_OFF);
    c.extend_from_slice(&[0x83, 0xC3, 0x07]); // 15: add ebx, 7
    c.extend_from_slice(&[0xC1, 0xE3, 0x01]); // 18: shl ebx, 1
    c.extend_from_slice(&[0x89, 0x1A]); // 21: mov [edx], ebx
    c.extend_from_slice(&[0x8B, 0x0A]); // 23: mov ecx, [edx]
    c.extend_from_slice(&[0x01, 0xCB]); // 25: add ebx, ecx
    c.extend_from_slice(&[0x83, 0xEB, 0x05]); // 27: sub ebx, 5
    c.extend_from_slice(&[0x31, 0xC9]); // 30: xor ecx, ecx
    c.extend_from_slice(&[0x83, 0xC1, 0x09]); // 32: add ecx, 9
    c.extend_from_slice(&[0x29, 0xCB]); // 35: sub ebx, ecx
    c.extend_from_slice(&[0xD1, 0xEB]); // 37: shr ebx, 1
    c.extend_from_slice(&[0x81, 0xE3, 0xFF, 0xFF, 0x00, 0x00]); // 39: and ebx, 0xffff
    c.extend_from_slice(&[0x83, 0xCB, 0x01]); // 45: or ebx, 1
    c.extend_from_slice(&[0x89, 0x5A, 0x04]); // 48: mov [edx+4], ebx
    c.extend_from_slice(&[0x8B, 0x4A, 0x04]); // 51: mov ecx, [edx+4]
    c.extend_from_slice(&[0xFF, 0xC8]); // 54: dec eax
    let back = LOOP_OFF as i64 - (c.len() + 2) as i64;
    c.extend_from_slice(&[0x75, back as i8 as u8]); // 56: jnz loop
    c.push(0xF4); // 58: hlt
    assert_eq!(c.len(), PROGRAM_LEN);
    c
}

/// Offset of the loop body's first instruction.
const LOOP_OFF: usize = 15;
/// Length of [`program`] in bytes.
const PROGRAM_LEN: usize = 59;

/// Where an instruction of [`program`] starts, in program order. Used to arm at
/// boundaries; the sweeps arm at *every* byte, boundary or not.
fn instruction_offsets() -> Vec<usize> {
    vec![0, 5, 10, 15, 18, 21, 23, 25, 27, 30, 32, 35, 37, 39, 45, 48, 51, 54, 56, 58]
}

/// How a modelled run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stop {
    /// The run-loop head found an armed breakpoint at the address about to
    /// execute, having retired `steps` instructions.
    Breakpoint { rip: u64, steps: u64 },
    /// A watched access was recorded by the instruction that just completed.
    Watch { addr: u64, kind: WatchKind, steps: u64 },
    /// The guest executed `hlt`.
    Halted { steps: u64 },
    /// Anything else — a fault, a process exit, or the harness's own cap. Kept
    /// as a string so a divergence prints something useful.
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

/// What one modelled run did, beyond where it stopped.
#[derive(Clone, Debug)]
struct Outcome {
    stop: Stop,
    /// Guest instructions executed as **native code**. Zero for an interpreter
    /// run, and the number every test below checks before believing anything
    /// else it measured.
    native: u64,
    /// Times the chain handed control back because the next address had an
    /// armed breakpoint.
    breakpoint_stops: u64,
    /// Accesses a compiled block refused because they were watched.
    watch_stops: u64,
    /// Block entries reached by a native link — the shape a breakpoint has to
    /// survive.
    links_taken: u64,
    /// Guest-memory TLB entries filled during the run.
    tlb_fills: u64,
    /// Native code emitted, at its high-water mark.
    code_bytes: u64,
    blocks_compiled: u64,
    flushes: u64,
}

fn build(bits: Bits, code: &[u8], dbg: &DebugControl) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    // Two pages, so the guest-memory TLB is willing to cache the data page:
    // it needs the whole page plus the widest access inside one region.
    mem.map(Region::new("data", DATA, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", STACK, 0x2000, Perm::RW)).unwrap();
    mem.poke(CODE, code).unwrap();
    mem.set_debug(dbg.clone());
    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().gpr[4] = STACK + 0x1000; // rsp
    (mem, cpu)
}

/// The harness's own cap, so a wedged run fails loudly instead of hanging.
const MAX_STEPS: u64 = 100_000;

/// Run `code` under `dbg` until the first debugger stop, on the JIT
/// (`use_jit`) or on the interpreter alone.
///
/// This is the model of `crates/app`'s run loop described in the module docs.
/// The two engines share every line of it except the `Jit::run` call, which is
/// the point: a divergence between them is a divergence in the JIT.
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
        // (1) trap-after: a hit belongs to the instruction that just finished.
        if let Some((addr, kind)) = dbg.take_watch_hit() {
            break Stop::Watch { addr, kind, steps };
        }
        // (2) the address about to execute.
        let rip = cpu.state().rip;
        if dbg.is_break(rip) {
            break Stop::Breakpoint { rip, steps };
        }
        // (3) run. The budget is deliberately unbounded: nothing but the JIT's
        // own rules may end a chain here, so a breakpoint that the JIT failed to
        // honour would be run straight past rather than caught by a short
        // budget the app happens to impose.
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

// ---------------------------------------------------------------------------
// The baseline: the program really is compiled, chained and linked
// ---------------------------------------------------------------------------

/// Everything below measures a *difference* against an undebugged run, so this
/// pins what that run is. If the JIT ever stopped compiling this program the
/// sweeps would still pass while proving nothing, and this is what would fail
/// instead.
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
        // Every instruction but the final `hlt` ran as native code.
        assert_eq!(jit.native, steps, "{bits:?}: only `hlt` should reach the interpreter");
        // Two blocks (the entry, which swallows the setup and the first
        // iteration, and the body the back edge re-enters) and five of the
        // eight iterations reached by a native `br`: iteration 1 runs inside
        // the entry block, 2 and 3 are entered from Rust while the two link
        // slots are being filled, and 4–8 are linked. That is the shape a
        // breakpoint has to survive, so it is asserted rather than hoped for.
        assert_eq!(jit.blocks_compiled, 2, "{bits:?}");
        assert!(jit.links_taken >= 5, "{bits:?}: back edge not linked ({})", jit.links_taken);
        assert_eq!(jit.breakpoint_stops, 0, "{bits:?}: nothing was armed");
        assert_eq!(jit.watch_stops, 0, "{bits:?}: nothing was armed");
        // The fast path is engaged: the data page is roomy enough to cache.
        assert!(jit.tlb_fills > 0, "{bits:?}: the guest-memory TLB filled nothing");
    }
}

// ---------------------------------------------------------------------------
// S3 — breakpoints
// ---------------------------------------------------------------------------

/// **The exhaustive sweep.** Arm a breakpoint at *every* byte address the
/// program occupies — instruction boundaries and the bytes in between — and
/// require the JIT-driven run and the interpreter-driven run to stop at the
/// identical `rip` having retired the identical count.
///
/// Sweeping bytes rather than boundaries is the part that costs nothing and
/// buys the other half of the property: an address that is *not* the start of an
/// instruction must not split a block, must not stop a run, and must not change
/// the step count either.
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
            // A fresh handle for the reference run: the JIT run drained its
            // own watch/stop state, and sharing one would let the two
            // interfere.
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
                // The instruction *before* the armed one must still have run as
                // native code — that is the difference between "the JIT
                // honoured the breakpoint" and "arming turned the JIT off".
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

/// The count half of the sweep above, stated the way a user would: for each of
/// the first N instructions of the trace, both engines must agree that *this*
/// address is instruction number N.
///
/// The sweep already compares whole `Stop`s, so this cannot fail on its own —
/// what it adds is the independent arithmetic. The expected count is computed
/// from the program's shape (three setup instructions, then sixteen per
/// iteration), not from either engine.
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
                continue; // `hlt`, reached after the loop rather than in it
            }
            let at = CODE + *off as u64;
            let dbg = DebugControl::attached();
            dbg.arm_break(at);
            let jit = run_to_stop(bits, &code, &dbg, true);
            let dbg_i = DebugControl::attached();
            dbg_i.arm_break(at);
            let interp = run_to_stop(bits, &code, &dbg_i, false);
            // First time round the loop: three setup instructions, then `i`.
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

/// Two breakpoints at once: the run must stop at the one the guest reaches
/// first, whichever order they were armed in. `next_break_at_or_after` returning
/// the *lowest* armed address is not the same as "the first one reached", and a
/// block that stopped at the wrong one would still look like it stopped.
#[test]
fn the_first_armed_address_reached_is_the_one_that_stops_the_run() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        // 51 is reached later in the iteration than 21, so 21 wins even though
        // both are armed and 51 is armed first.
        let dbg = DebugControl::attached();
        dbg.arm_break(CODE + 51);
        dbg.arm_break(CODE + 21);
        let jit = run_to_stop(bits, &code, &dbg, true);
        // `mov [edx], ebx` at offset 21 is the sixth instruction of the trace.
        assert_eq!(jit.stop, Stop::Breakpoint { rip: CODE + 21, steps: 5 }, "{bits:?}");
        assert!(jit.native > 0, "{bits:?}: nothing compiled");
        // And the *earlier* address, armed second, is honoured on its own.
        let dbg = DebugControl::attached();
        dbg.arm_break(CODE + 51);
        let jit = run_to_stop(bits, &code, &dbg, true);
        assert_eq!(jit.stop, Stop::Breakpoint { rip: CODE + 51, steps: 16 }, "{bits:?}");
    }
}

/// Arming *after* the blocks are compiled must take effect, and must take
/// effect on the very next chain — the block cache is keyed on
/// `DebugControl::generation()`, and this is the test that the key is actually
/// consulted rather than only documented.
///
/// This is the case a naive implementation gets wrong in the direction that
/// matters: the program is compiled and linked on the first pass, so a
/// breakpoint armed on the second would be invisible to a cache that never
/// re-examined itself.
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
        // Five iterations' worth in **one chain**, so the loop body is not only
        // compiled but has been *entered by a native link* before anything is
        // armed. The budget has to be large enough for that: a chain takes a
        // link only while its running total is still under the budget, so a
        // block-at-a-time warm-up would compile the body and never once jump
        // into it — which is the very shape the arm has to survive.
        let warm_up = 3 + 5 * 16;
        let ran = jit.run(cpu.state_mut(), &mut mem, mode, warm_up);
        let mut steps = u64::from(ran.insns());
        assert_eq!(steps, warm_up, "{bits:?}: the warm-up chain stopped early ({ran:?})");
        let warm = jit.stats().clone();
        assert!(warm.blocks_compiled > 0, "{bits:?}: nothing compiled in the warm-up");
        assert!(warm.links_taken > 0, "{bits:?}: the back edge never linked");
        let flushes_before = warm.flushes;

        // Now arm, mid-run, inside the body the chain is already looping over.
        dbg.arm_break(CODE + 37);
        let armed_at_step = steps;
        // …and carry on with an unbounded budget, so only the JIT's own rules
        // can stop the chain.
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
        // Within one iteration of arming — the tightest bound native linking
        // permits, and far tighter than "eventually".
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

/// Disarming puts the block back together: the run that follows must be the
/// undebugged run again, instruction for instruction, and must compile the
/// whole body as one block once more.
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

/// An attached-but-unarmed handle must change **nothing**: the same stop, the
/// same instruction count, the same blocks, and — the part that is easy to get
/// wrong by adding a check to the emitter rather than to the helper pointer —
/// the same number of bytes of native code.
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

// ---------------------------------------------------------------------------
// S6 — watchpoints
// ---------------------------------------------------------------------------

/// **The watchpoint sweep.** Every base address the program touches, every
/// length up to the access width, every kind: the JIT-driven run and the
/// interpreter-driven run must stop at the same instruction count and report
/// the same address and kind.
///
/// The asymmetry this exists to prove is real and is not self-evident: the
/// JIT-side check fires *before* the access (it must, so the block can rewind
/// having changed nothing), while the interpreter-side check fires *after* it.
/// They agree only because the interpreter is the one that ever performs the
/// access — the compiled block's refusal is not a report, it is a hand-over.
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
                        // Only an address the program never touches may run to
                        // completion, and then the JIT must not have refused
                        // anything at all.
                        assert!(matches!(jit.stop, Stop::Halted { .. }), "{what}: {:?}", jit.stop);
                        assert_eq!(jit.watch_stops, 0, "{what}: refused an unwatched access");
                    }
                }
            }
        }
        assert!(hits >= 20, "{bits:?}: the sweep only landed {hits} watch stops");
    }
}

/// The two accesses of one iteration, named: a store at `DATA` and a load from
/// `DATA`, four instructions apart. Arming each direction separately must stop
/// on the matching instruction and not on the other one — which is the check
/// that the JIT-side helper is testing the access *kind* and not merely the
/// address.
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
        // `mov [edx], ebx` is instruction 5 of the trace (0-based), so the stop
        // is reported after it completes: six retired.
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

/// A compiled block must not *perform* a watched store before refusing it. The
/// rewind contract says the faulting instruction changed nothing, and for a
/// store "nothing" includes guest memory — otherwise the interpreter's
/// re-execution would be the *second* write, which a guest that counts its own
/// writes would see.
///
/// Checked by watching a location the program writes a known, changing value
/// to, and reading that location out at the stop.
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
        // A value the guest never stores, so "unchanged" is unambiguous.
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
        // Nothing was recorded either: the *interpreter* records the hit, and
        // it has not run this instruction yet.
        assert_eq!(dbg.take_watch_hit(), None, "{bits:?}: the JIT reported a hit itself");
    }
}

/// The property S6 rests on, checked rather than assumed: while a watchpoint is
/// armed the guest-memory TLB fills **nothing**, so no access can be served by
/// emitted code without going through the helper that has to see it.
///
/// The first half of the assertion is what makes the second half mean anything
/// — an undebugged run of this same program must fill entries, or "no fills
/// while armed" would be true of a harness that never engaged the fast path at
/// all. (That is exactly how the W8.6 differential managed a two-million-trial
/// run that filled zero entries and proved nothing.)
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
        // A watchpoint the program never hits, so the run goes all the way to
        // `hlt` and every access it makes had the chance to be cached.
        dbg.arm_watch(DATA + 0x800, 4, WatchKind::ReadWrite);
        let armed = run_to_stop(bits, &code, &dbg, true);
        assert!(matches!(armed.stop, Stop::Halted { .. }), "{bits:?}: {:?}", armed.stop);
        assert_eq!(armed.stop.steps(), plain.stop.steps(), "{bits:?}");
        assert!(armed.native > 0, "{bits:?}: nothing compiled");
        assert_eq!(armed.tlb_fills, 0, "{bits:?}: an entry was cached while a watchpoint was armed");
        assert_eq!(armed.watch_stops, 0, "{bits:?}: refused an access outside the watched range");
    }
}

/// The same, one level down: a JIT that holds the handle while the *memory
/// backend* does not must still keep the fast path out of the way.
///
/// This is not a configuration `crates/app` produces — it installs the handle on
/// both — but it is the one where a wrong answer is **silent**, because
/// `Memory::host_span`'s own refusal is what would otherwise be doing all the
/// work. Gating the table on both views is what makes the fast path incapable
/// of hiding an access regardless of how the handle was wired.
///
/// # Why the watched address is the program's *second* one
///
/// The obvious version of this test watches `DATA`, and it is worthless: the
/// first watched access is the program's first access of any kind, so the block
/// rewinds before a single entry could have been filled and "zero fills" is
/// true of a run that never had the chance to fill one. Watching `DATA + 4`
/// instead puts two **unwatched** accesses to the same page in front of it —
/// which is precisely the shape that goes wrong without the gate: the first
/// store fills the page's write entry, and the watched store four instructions
/// later is then served inline by emitted code and never reaches the helper
/// that has to see it. Removing the gate makes this test run to completion,
/// which is what it is for.
#[test]
fn the_fast_path_stays_out_of_the_way_even_if_only_the_jit_holds_the_handle() {
    if !jit_available() {
        return;
    }
    let code = program();
    for bits in both_bitnesses() {
        let dbg = DebugControl::attached();
        // Built with a *detached* handle: the backend hands out spans freely.
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
        // Two unwatched accesses to the same page ran first, and neither was
        // allowed to cache it.
        assert_eq!(jit.stats().tlb_fills, 0, "{bits:?}: cached a page while watching");
        assert_eq!(jit.stats().watch_stops, 1, "{bits:?}");
        assert_eq!(cpu.state().rip, CODE + 48, "{bits:?}: rewound to the wrong instruction");
    }
}

/// Breakpoints and watchpoints armed together, which is how a debugger is
/// actually used. Whichever comes first in the trace must win, and the two
/// mechanisms must not mask each other: the breakpoint here sits *after* the
/// watched store, so the watch stop is the one that happens.
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

        // And the other way round: a breakpoint before the watched store.
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
