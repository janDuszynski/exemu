//! End-to-end A/B: the same program run on the interpreter and on the block
//! JIT must be indistinguishable (roadmap W8.3).
//!
//! The oracle differential in `crates/oracle` proves the JIT block-by-block on
//! generated instructions. This proves the *integration*: the run loop's step
//! accounting, the clock, the API-thunk boundary and the sandbox all have to
//! agree too. What is compared is everything a caller can observe — exit code,
//! **exact instruction count**, and the bytes the program printed.
//!
//! The instruction count is the sharp end of it. A JIT block retires many
//! instructions per call, so the run loop has to add exactly the number the
//! block executed; an off-by-one there would silently desynchronise the
//! deterministic clock (which is a pure function of that count) and every corpus
//! pin with it.

use exemu_app::{gui_sample, load_and_run, sample, RunConfig};

fn cfg(jit: bool) -> RunConfig {
    RunConfig { echo: false, trace: false, jit, virtual_clock: true, ..RunConfig::default() }
}

/// `Jit::new` fails on any platform without the macOS/AArch64 W^X backend, in
/// which case the run loop stays on the interpreter and the A/B is vacuous.
fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn compare(bytes: &[u8], what: &str) {
    let a = load_and_run(bytes, cfg(false)).unwrap_or_else(|e| panic!("{what} interpreted: {e}"));
    let b = load_and_run(bytes, cfg(true)).unwrap_or_else(|e| panic!("{what} jitted: {e}"));
    assert_eq!(a.exit_code, b.exit_code, "{what}: exit code");
    assert_eq!(a.steps, b.steps, "{what}: instruction count");
    assert_eq!(a.stdout, b.stdout, "{what}: stdout");
    assert_eq!(a.stderr, b.stderr, "{what}: stderr");
    if jit_available() {
        let j = b.jit.expect("the JIT should have been built");
        assert!(j.insns_executed > 0, "{what}: the JIT executed nothing at all");
        assert!(j.blocks_compiled > 0, "{what}: no blocks were compiled");
    }
}

#[test]
fn console_sample_is_identical_with_and_without_the_jit() {
    compare(&sample::build(), "console sample");
}

#[test]
fn gui_sample_is_identical_with_and_without_the_jit() {
    compare(&gui_sample::build(), "gui sample");
}

/// The JIT must be a pure accelerator: switching it on may not change what the
/// guest sees, so a second run with it on must match the first run with it on
/// *and* both interpreter runs. (This also catches a stale code cache leaking
/// across processes, since each run builds a fresh address space.)
#[test]
fn repeated_runs_agree() {
    let bytes = sample::build();
    let runs: Vec<_> = [false, true, false, true]
        .iter()
        .map(|&jit| load_and_run(&bytes, cfg(jit)).expect("sample should run"))
        .collect();
    for (i, r) in runs.iter().enumerate() {
        assert_eq!(r.steps, runs[0].steps, "run {i} executed a different number of instructions");
        assert_eq!(r.stdout, runs[0].stdout, "run {i} printed something different");
    }
}
