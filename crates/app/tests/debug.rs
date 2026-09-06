//! The debugger at the run loop's instruction boundary (roadmap W9.3).
//!
//! Two things are proved here, and they pull in opposite directions:
//!
//! 1. **Attaching is free.** A run with a `DebugControl` attached and nothing
//!    armed must execute the same instructions in the same order as a run with
//!    no debugger at all — asserted field by field, including every `JitReport`
//!    counter. `chains` is the load-bearing one: it is a direct readout of where
//!    the JIT's chain loop returned, so a single moved block boundary fails the
//!    test even if the instruction total coincidentally matched.
//! 2. **A stop is exact, and it is exact under both engines.** A breakpoint
//!    reports the address it was armed at, at the instruction count an
//!    independently-counted single-step trace says that address is reached at; a
//!    `Step` advances by exactly one instruction; `break_at_step(N)` stops at
//!    exactly N. Every one of those runs twice — once interpreted, once with the
//!    block JIT switched on — because a debugger that is right only on the
//!    interpreter is the disqualifying bug this design exists to avoid.
//!
//! # What "under the JIT" means for each stop kind, honestly
//!
//! The run loop is the sole decision point; the JIT's job is only to hand
//! control back often enough. Today it does that in three different ways, and
//! the tests below are written to say which is which:
//!
//! * **`break_at_step` and pause** genuinely run *with* the JIT. The chain
//!   budget already carries instruction-denominated deadlines, so the compiled
//!   path runs right up to the stop; only the last stretch before an exact count
//!   is interpreted (`JIT_EXACT_STOP_WINDOW`), which
//!   `break_at_step_keeps_the_jit_running_up_to_the_stop` measures.
//! * **A single `Step`** takes that one iteration off the JIT — one instruction
//!   is one instruction and a compiled block is many.
//! * **An armed address breakpoint or watchpoint** takes the *run* off the JIT
//!   for as long as it is armed, because the JIT cannot yet decline to chain
//!   past one. The guarantee that matters is therefore still met — a breakpoint
//!   is never missed in compiled code — and the `jit = true` half of those cases
//!   is proving exactly that: same address, same instruction count, whichever
//!   engine the caller asked for.
//!
//! # How the front-end is driven without a thread
//!
//! The real front-end lives on another thread (a `Process` is not `Send`). A
//! test does not need one: `mpsc` buffers, so the whole command script can be
//! queued *before* the run starts and the parked run loop consumes it as it
//! goes. The command `Sender` is then **dropped**, which is the safety net — an
//! unexpected extra park sees a disconnected channel, detaches, and runs to
//! completion instead of hanging the test for ever.

use exemu_app::{comdlg_sample, load_and_run, sample, JitReport, RunConfig, RunResult};
use exemu_core::debug::{
    DebugCommand, DebugControl, DebugEvent, DebugSession, DebugSnapshot, StopReason, StopRequest,
    WatchKind,
};

/// The built-in console demo: 35 instructions. Short enough that a single-step
/// trace covers a useful fraction of it.
fn short_image() -> Vec<u8> {
    sample::build()
}

/// The common-dialog demo: ~900 instructions, ~95% of them compiled. Long enough
/// that a stop can be placed with hundreds of natively-executed instructions on
/// either side of it, which is what makes the JIT half of these cases real.
fn long_image() -> Vec<u8> {
    comdlg_sample::build()
}

fn cfg(jit: bool) -> RunConfig {
    RunConfig { echo: false, trace: false, jit, virtual_clock: true, ..RunConfig::default() }
}

fn plain_run(image: &[u8], jit: bool) -> RunResult {
    load_and_run(image, cfg(jit)).expect("the undebugged run should have completed")
}

/// Everything one debugged run produced.
struct Debugged {
    result: exemu_core::Result<RunResult>,
    stops: Vec<DebugSnapshot>,
    exited: Option<(i32, u64)>,
}

impl Debugged {
    fn ok(&self) -> &RunResult {
        self.result.as_ref().expect("the debugged run should have completed")
    }
    fn first(&self) -> &DebugSnapshot {
        self.stops.first().expect("the run should have stopped at least once")
    }
}

/// Run `image` with a debugger attached: `arm` sets the session up before the
/// guest starts, `script` is queued into the command channel and consumed one
/// command per park.
fn run_debugged(
    image: &[u8],
    jit: bool,
    arm: impl FnOnce(&DebugControl),
    script: &[DebugCommand],
) -> Debugged {
    let control = DebugControl::attached();
    let (session, front) = DebugSession::pair(control.clone());
    arm(&control);
    for c in script {
        front.commands.send(c.clone()).expect("the emulator has not started yet");
    }
    // See the module docs: dropping the sender turns any unscripted park into a
    // detach-and-continue rather than a hang.
    drop(front.commands);

    let mut c = cfg(jit);
    c.debug = Some(session);
    let result = load_and_run(image, c);

    let mut stops = Vec::new();
    let mut exited = None;
    while let Ok(e) = front.events.try_recv() {
        match e {
            DebugEvent::Stopped(s) => stops.push(*s),
            DebugEvent::Exited { code, steps } => exited = Some((code, steps)),
            DebugEvent::Resumed | DebugEvent::Memory { .. } | DebugEvent::Disassembly { .. } => {}
            DebugEvent::Error(e) => panic!("the emulator reported an error: {e}"),
        }
    }
    Debugged { result, stops, exited }
}

/// Single-step the first `n` instructions of `image` and hand back the snapshot
/// at each boundary — the independently-counted reference every "exactly" below
/// is measured against. Interpreted, because the interpreter is the reference
/// the JIT is defined against.
fn trace(image: &[u8], n: usize) -> Vec<DebugSnapshot> {
    let script = vec![DebugCommand::Step; n];
    let d = run_debugged(image, false, |c| c.request(StopRequest::Pause), &script);
    assert_eq!(d.stops.len(), n + 1, "one pause at instruction 0 plus {n} single-steps");
    d.stops
}

/// The first address reached at step `k` that the guest has not already executed
/// earlier in the trace — so a breakpoint armed on it can only fire at `k`.
fn first_fresh_address(t: &[DebugSnapshot], from: usize) -> (usize, u64) {
    for k in from..t.len() {
        let rip = t[k].regs.rip;
        if !t[..k].iter().any(|s| s.regs.rip == rip) {
            return (k, rip);
        }
    }
    panic!("the trace revisits every address after step {from}");
}

fn assert_jit_reports_identical(a: &Option<JitReport>, b: &Option<JitReport>, what: &str) {
    match (a, b) {
        (Some(a), Some(b)) => {
            // The seven counters the design note names, plus the two derived
            // fields. `chains` is the sharp one: it says where the chain loop
            // returned, so a moved block boundary fails here even if the
            // instruction total coincidentally matched.
            assert_eq!(a.blocks_compiled, b.blocks_compiled, "{what}: blocks_compiled");
            assert_eq!(a.blocks_executed, b.blocks_executed, "{what}: blocks_executed");
            assert_eq!(a.chains, b.chains, "{what}: chains");
            assert_eq!(a.insns_executed, b.insns_executed, "{what}: insns_executed");
            assert_eq!(a.faults, b.faults, "{what}: faults");
            assert_eq!(a.not_compiled, b.not_compiled, "{what}: not_compiled");
            assert_eq!(a.flushes, b.flushes, "{what}: flushes");
            assert_eq!(a.code_bytes, b.code_bytes, "{what}: code_bytes");
            assert_eq!(a.declined, b.declined, "{what}: declined");
            assert!(a.insns_executed > 0, "{what}: the JIT executed nothing at all");
        }
        (None, None) => {}
        _ => panic!("{what}: one run built a JIT and the other did not"),
    }
}

// ---------------------------------------------------------------------------
// Attaching is free
// ---------------------------------------------------------------------------

/// The gate that turns "attaching the debugger is free" from a claim into a
/// test: same exit code, same **exact** instruction count, same output, and —
/// with the JIT on — every counter identical.
#[test]
fn attaching_and_arming_nothing_changes_nothing() {
    for (name, image) in [("short", short_image()), ("long", long_image())] {
        for jit in [false, true] {
            let what = format!("{name}/{}", if jit { "jit" } else { "interpreter" });
            let plain = plain_run(&image, jit);
            let d = run_debugged(&image, jit, |_| {}, &[]);
            let attached = d.ok();

            assert!(d.stops.is_empty(), "{what}: an idle debugger stopped the run");
            assert_eq!(plain.exit_code, attached.exit_code, "{what}: exit code");
            assert_eq!(
                plain.steps, attached.steps,
                "{what}: attaching moved the instruction count"
            );
            assert_eq!(plain.stdout, attached.stdout, "{what}: stdout");
            assert_eq!(plain.stderr, attached.stderr, "{what}: stderr");
            assert_eq!(
                d.exited,
                Some((attached.exit_code, attached.steps)),
                "{what}: the front-end is told how the run ended"
            );
            assert_jit_reports_identical(&plain.jit, &attached.jit, &what);
        }
    }
}

/// The same claim stated the other way round: two attached-and-idle runs of the
/// same image agree with each other as exactly as they agree with the
/// undebugged one, so the equality above is not an accident of one run.
#[test]
fn two_attached_runs_agree_with_each_other() {
    let image = long_image();
    for jit in [false, true] {
        let a = run_debugged(&image, jit, |_| {}, &[]);
        let b = run_debugged(&image, jit, |_| {}, &[]);
        assert_eq!(a.ok().steps, b.ok().steps);
        assert_eq!(a.ok().exit_code, b.ok().exit_code);
        assert_jit_reports_identical(&a.ok().jit, &b.ok().jit, "attached A/B");
    }
}

// ---------------------------------------------------------------------------
// Pause and single-step
// ---------------------------------------------------------------------------

/// A pause is honoured at the next instruction boundary, each `Step` advances by
/// exactly one instruction, and resuming afterwards reaches the same exit code
/// and the same **total** instruction count as an undebugged run — which is the
/// observable form of "single-step did not perturb the guest".
#[test]
fn pause_then_step_advances_by_exactly_one_instruction() {
    const N: usize = 12;
    let image = long_image();
    let plain = plain_run(&image, false);

    for jit in [false, true] {
        let what = if jit { "jit" } else { "interpreter" };
        let mut script = vec![DebugCommand::Step; N];
        script.push(DebugCommand::Resume);
        let d = run_debugged(&image, jit, |c| c.request(StopRequest::Pause), &script);

        assert_eq!(d.stops.len(), N + 1, "{what}: one pause plus {N} single-steps");
        assert!(
            matches!(d.stops[0].stop, StopReason::Paused),
            "{what}: the first stop is the pause, not {:?}",
            d.stops[0].stop
        );
        for (i, snap) in d.stops.iter().enumerate() {
            assert_eq!(snap.steps, i as u64, "{what}: stop {i} must be at instruction {i}");
            if i > 0 {
                assert!(
                    matches!(snap.stop, StopReason::StepComplete),
                    "{what}: stop {i} is {:?}",
                    snap.stop
                );
            }
        }
        let r = d.ok();
        assert_eq!(r.exit_code, plain.exit_code, "{what}: exit code after resuming");
        assert_eq!(
            r.steps, plain.steps,
            "{what}: stepping and resuming changed the guest's total instruction count"
        );
    }
}

/// The two engines must single-step over the *same* instruction sequence. This
/// is the direct proof that stepping is not interpreter-only: the JIT run is
/// held off the compiled path for each stepped instruction and lands on exactly
/// the same addresses.
#[test]
fn single_stepping_walks_the_same_addresses_with_and_without_the_jit() {
    const N: usize = 40;
    let image = long_image();
    let script = vec![DebugCommand::Step; N];
    let a = run_debugged(&image, false, |c| c.request(StopRequest::Pause), &script);
    let b = run_debugged(&image, true, |c| c.request(StopRequest::Pause), &script);
    let rips = |d: &Debugged| d.stops.iter().map(|s| s.regs.rip).collect::<Vec<_>>();
    assert_eq!(rips(&a), rips(&b), "the JIT stepped a different instruction sequence");
    assert_eq!(a.ok().steps, b.ok().steps);
}

/// Stepping leaves the JIT's compiled code intact: the run picks the compiled
/// path straight back up after the stepped instructions, so a session that
/// stepped a dozen instructions still finishes as native code.
#[test]
fn stepping_does_not_deoptimise_the_rest_of_the_run() {
    let image = long_image();
    let plain = plain_run(&image, true);
    let Some(reference) = plain.jit else { return };

    let mut script = vec![DebugCommand::Step; 12];
    script.push(DebugCommand::Resume);
    let d = run_debugged(&image, true, |c| c.request(StopRequest::Pause), &script);
    let stepped = d.ok().jit.as_ref().expect("the JIT should have been built");

    assert_eq!(d.ok().steps, plain.steps, "stepping changed the guest's instruction count");
    // The 12 stepped instructions are the only ones that had to be interpreted.
    assert!(
        stepped.insns_executed + 64 >= reference.insns_executed,
        "stepping cost {} natively-executed instructions, not ~12",
        reference.insns_executed.saturating_sub(stepped.insns_executed)
    );
}

/// Resuming from a stop must execute the instruction that was stopped *on*,
/// never skip it and never re-fire on it. A breakpoint on an address the guest
/// reaches once therefore stops once and the run finishes with the same count.
#[test]
fn resuming_from_a_breakpoint_does_not_wedge_or_skip() {
    let image = long_image();
    let t = trace(&image, 16);
    let (_, target) = first_fresh_address(&t, 8);
    let plain = plain_run(&image, false);

    for jit in [false, true] {
        let what = if jit { "jit" } else { "interpreter" };
        let d = run_debugged(&image, jit, |c| c.arm_break(target), &[DebugCommand::Resume]);
        let r = d.ok();
        assert_eq!(r.exit_code, plain.exit_code, "{what}: the run finished normally");
        assert_eq!(
            r.steps, plain.steps,
            "{what}: the instruction at the breakpoint was skipped or re-run"
        );
    }
}

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------

/// A breakpoint reports **exactly** the address it was armed at, at **exactly**
/// the instruction count an independently-counted single-step trace says that
/// address is reached at — under the interpreter and under the JIT alike.
#[test]
fn a_breakpoint_stops_at_exactly_its_armed_address() {
    let image = long_image();
    let t = trace(&image, 24);
    let (k, target) = first_fresh_address(&t, 8);

    for jit in [false, true] {
        let what = if jit { "jit" } else { "interpreter" };
        let d = run_debugged(&image, jit, |c| c.arm_break(target), &[DebugCommand::Resume]);
        let first = d.first();
        assert_eq!(
            first.stop,
            StopReason::Breakpoint { rip: target },
            "{what}: wrong stop reason"
        );
        assert_eq!(first.regs.rip, target, "{what}: stopped on the wrong instruction");
        assert_eq!(
            first.steps, k as u64,
            "{what}: stopped after the wrong number of instructions"
        );
    }
}

/// Every address in a trace is a valid breakpoint, not just a convenient one: a
/// breakpoint armed on the address reached at step k stops at step k, for every
/// k in the prefix that the guest does not revisit. A sweep, not a spot check —
/// an off-by-one that only showed at a block boundary would survive one sample.
#[test]
fn every_address_in_a_trace_is_an_exact_breakpoint() {
    let image = long_image();
    let t = trace(&image, 32);
    let mut checked = 0;
    for k in 1..t.len() {
        let target = t[k].regs.rip;
        if t[..k].iter().any(|s| s.regs.rip == target) {
            continue; // reached earlier: the breakpoint would fire before k
        }
        for jit in [false, true] {
            let d = run_debugged(&image, jit, |c| c.arm_break(target), &[DebugCommand::Resume]);
            let first = d.first();
            assert_eq!(
                first.stop,
                StopReason::Breakpoint { rip: target },
                "k={k} jit={jit}: wrong stop reason"
            );
            assert_eq!(first.steps, k as u64, "k={k} jit={jit}: wrong instruction count");
        }
        checked += 1;
    }
    assert!(checked >= 16, "the sweep only covered {checked} addresses");
}

/// A stop carries the state a front-end renders: the register file, the bitness,
/// a symbolic note for `rip`, the rip trail and the region map.
#[test]
fn a_stop_carries_the_state_a_front_end_renders() {
    let image = short_image();
    let t = trace(&image, 12);
    let (_, target) = first_fresh_address(&t, 6);

    let d = run_debugged(&image, false, |c| c.arm_break(target), &[DebugCommand::Resume]);
    let s = d.first();
    assert_eq!(s.bits, 64, "the console sample is a 64-bit image");
    assert_eq!(s.regs.rip, target);
    assert!(!s.rip_note.is_empty(), "rip should have a symbolic note");
    assert!(!s.regions.is_empty(), "the region map should not be empty");
    assert!(
        s.regions.iter().any(|r| r.contains(target)),
        "the instruction we stopped on should be inside a mapped region"
    );
    assert!(!s.trail.is_empty(), "the rip trail should carry some history");
}

// ---------------------------------------------------------------------------
// The instruction-count breakpoint
// ---------------------------------------------------------------------------

/// `break_at_step(N)` stops at exactly instruction N — including under the JIT,
/// whose chain loop stops at or *past* its budget and therefore has to be taken
/// off the compiled path for the last stretch. Both engines must also agree on
/// *which* instruction that is.
#[test]
fn break_at_step_stops_at_exactly_n_under_both_engines() {
    let image = long_image();
    let plain = plain_run(&image, false);
    assert!(plain.steps > 64, "the sample must be long enough to stop part-way through");

    for n in [1u64, 5, 64, 200, plain.steps / 2, plain.steps - 1] {
        let mut rip_at_n = None;
        for jit in [false, true] {
            let what = if jit { "jit" } else { "interpreter" };
            let d =
                run_debugged(&image, jit, |c| c.set_break_at_step(Some(n)), &[DebugCommand::Resume]);
            assert_eq!(d.stops.len(), 1, "{what}: n={n} should stop exactly once");
            let s = d.first();
            assert_eq!(s.stop, StopReason::StepCount { steps: n }, "{what}: n={n}");
            assert_eq!(s.steps, n, "{what}: n={n} stopped at the wrong instruction count");
            match rip_at_n {
                None => rip_at_n = Some(s.regs.rip),
                Some(rip) => assert_eq!(
                    rip, s.regs.rip,
                    "the two engines disagree about which instruction is number {n}"
                ),
            }
            assert_eq!(
                d.ok().steps,
                plain.steps,
                "{what}: n={n} — the run must complete normally after the stop"
            );
        }
    }
}

/// The instruction-count breakpoint is the one stop that runs *with* the JIT
/// rather than instead of it: it is a term of the chain budget, so only the last
/// `JIT_EXACT_STOP_WINDOW` instructions before the stop have to be interpreted.
/// This measures that, so a regression that quietly took the whole run off the
/// compiled path would be caught rather than merely still passing.
#[test]
fn break_at_step_keeps_the_jit_running_up_to_the_stop() {
    let image = long_image();
    let plain = plain_run(&image, true);
    let Some(reference) = plain.jit else { return };
    assert!(reference.insns_executed > 400, "the long sample should be mostly native");

    let n = plain.steps / 2;
    let d = run_debugged(&image, true, |c| c.set_break_at_step(Some(n)), &[DebugCommand::Resume]);
    let stopped = d.ok().jit.as_ref().expect("the JIT should have been built");
    assert_eq!(d.first().steps, n);
    let interpreted = reference.insns_executed.saturating_sub(stopped.insns_executed);
    assert!(
        interpreted < 300,
        "stopping at instruction {n} cost {interpreted} natively-executed instructions — the \
         exact-stop window should only take ~128 off the compiled path"
    );
    assert!(stopped.insns_executed > 0, "the JIT executed nothing at all");
}

/// The instruction-count breakpoint is one-shot: it must not re-fire on the very
/// next instruction and make the run unresumable.
#[test]
fn break_at_step_is_one_shot() {
    let image = long_image();
    let plain = plain_run(&image, false);
    let n = plain.steps / 2;
    let d = run_debugged(&image, false, |c| c.set_break_at_step(Some(n)), &[DebugCommand::Resume]);
    assert_eq!(d.stops.len(), 1, "a second stop means the count breakpoint stayed armed");
    assert_eq!(d.ok().steps, plain.steps);
}

// ---------------------------------------------------------------------------
// Watchpoints — the interpreter half (the memory backend records; this stops)
// ---------------------------------------------------------------------------

/// A watched write stops the run **after** the instruction that made it
/// (trap-after, matching x86 data breakpoints), reporting the address touched
/// and the kind of access.
#[test]
fn a_watched_write_stops_after_the_instruction_that_made_it() {
    let image = long_image();
    // Learn the guest's initial stack pointer by pausing at instruction 0.
    let probe = run_debugged(&image, false, |c| c.request(StopRequest::Pause), &[]);
    let rsp = probe.first().regs.rsp();
    let (base, len) = (rsp - 0x100, 0x100u64);

    let mut agreed: Option<(u64, u64)> = None;
    for jit in [false, true] {
        let what = if jit { "jit" } else { "interpreter" };
        let d = run_debugged(
            &image,
            jit,
            |c| c.arm_watch(base, len, WatchKind::Write),
            &[DebugCommand::Resume],
        );
        let s = d.first();
        let addr = match s.stop {
            StopReason::Watch { addr, kind } => {
                assert_eq!(kind, WatchKind::Write, "{what}: wrong access kind");
                assert!(
                    (base..base + len).contains(&addr),
                    "{what}: reported {addr:#x}, outside the watched range"
                );
                addr
            }
            ref other => panic!("{what}: expected a watch stop, got {other:?}"),
        };
        assert!(s.steps >= 1, "{what}: trap-after — the writing instruction has completed");
        match agreed {
            None => agreed = Some((addr, s.steps)),
            Some(prev) => assert_eq!(
                prev,
                (addr, s.steps),
                "the two engines disagree about the first watched write"
            ),
        }
    }
}

/// An armed-but-never-hit watchpoint must not stop anything, and must not change
/// what the guest does.
#[test]
fn an_unhit_watchpoint_changes_nothing() {
    let image = long_image();
    let plain = plain_run(&image, false);
    // A page the guest never touches: well above every mapped region.
    let d = run_debugged(
        &image,
        false,
        |c| c.arm_watch(0x7ff0_0000_0000, 0x1000, WatchKind::ReadWrite),
        &[],
    );
    assert!(d.stops.is_empty(), "an unhit watchpoint stopped the run");
    assert_eq!(d.ok().steps, plain.steps);
    assert_eq!(d.ok().exit_code, plain.exit_code);
}

// ---------------------------------------------------------------------------
// The command protocol
// ---------------------------------------------------------------------------

/// `ReadMemory` is answered from the emulator thread through the
/// permission-checked accessor, and the bytes match what the image holds.
#[test]
fn read_memory_is_answered_while_parked() {
    let image = short_image();
    let control = DebugControl::attached();
    let (session, front) = DebugSession::pair(control.clone());
    control.request(StopRequest::Pause);
    front.commands.send(DebugCommand::ReadMemory { addr: 0x140000000, len: 2 }).unwrap();
    front.commands.send(DebugCommand::Resume).unwrap();
    drop(front.commands);

    let mut c = cfg(false);
    c.debug = Some(session);
    load_and_run(&image, c).expect("run");

    let mut memory = None;
    while let Ok(e) = front.events.try_recv() {
        if let DebugEvent::Memory { addr, bytes } = e {
            memory = Some((addr, bytes));
        }
    }
    let (addr, got) = memory.expect("the ReadMemory command should have been answered");
    assert_eq!(addr, 0x140000000);
    assert_eq!(got, b"MZ", "the image's DOS header should be readable at its base");
}

/// A read that runs off the end of mapped memory comes back **short**, not as an
/// error, so a front-end can walk up to the edge of a region.
#[test]
fn read_memory_truncates_at_the_edge_of_mapped_memory() {
    let control = DebugControl::attached();
    let (session, front) = DebugSession::pair(control.clone());
    control.request(StopRequest::Pause);
    // Deliberately unmapped: nothing lives up here.
    front
        .commands
        .send(DebugCommand::ReadMemory { addr: 0x7ff0_0000_0000, len: 64 })
        .unwrap();
    front.commands.send(DebugCommand::Resume).unwrap();
    drop(front.commands);

    let mut c = cfg(false);
    c.debug = Some(session);
    load_and_run(&short_image(), c).expect("run");

    let mut memory = None;
    while let Ok(e) = front.events.try_recv() {
        if let DebugEvent::Memory { bytes, .. } = e {
            memory = Some(bytes);
        }
    }
    assert_eq!(
        memory.expect("answered"),
        Vec::<u8>::new(),
        "an unmapped read is empty, not an error"
    );
}

/// `Detach` disarms everything and runs to completion with no further stops.
#[test]
fn detach_disarms_and_runs_to_completion() {
    let image = long_image();
    let t = trace(&image, 16);
    let (_, target) = first_fresh_address(&t, 8);
    let plain = plain_run(&image, false);

    let d = run_debugged(&image, false, |c| c.arm_break(target), &[DebugCommand::Detach]);
    assert_eq!(d.stops.len(), 1, "detaching should stop the run exactly once");
    assert_eq!(d.ok().steps, plain.steps);
    assert_eq!(d.ok().exit_code, plain.exit_code);
}

/// `Kill` abandons the run, and says so rather than pretending the guest exited.
#[test]
fn kill_abandons_the_run() {
    let d = run_debugged(
        &short_image(),
        false,
        |c| c.request(StopRequest::Pause),
        &[DebugCommand::Kill],
    );
    let err = match d.result {
        Err(e) => e,
        Ok(r) => panic!("a killed run must not report a clean exit ({} steps)", r.steps),
    };
    assert!(err.to_string().contains("debugger abandoned"), "unexpected error text: {err}");
    assert_eq!(d.stops.len(), 1);
    assert!(d.exited.is_none(), "a killed run must not report an exit code");
}
