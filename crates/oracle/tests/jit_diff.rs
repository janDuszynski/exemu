//! The JIT-vs-interpreter differential, in the ordinary test gate (roadmap
//! W8.7).
//!
//! This is the test that decides whether the JIT may be trusted at all. It runs
//! the same generated trials the Unicorn oracle uses through both engines and
//! demands **bit-for-bit** equality of the whole architectural state — no
//! defined-flags policy, no tolerance. A divergence here is a release blocker,
//! not a warning.
//!
//! The counts are kept modest so the gate stays fast; the real volume comes from
//! `cargo run -p exemu-oracle --release -- jit --count 1M`, whose result is
//! recorded in the roadmap notes.

use exemu_cpu::Bits;
use exemu_oracle::jitdiff::{fuzz, render, JitFuzzConfig};

/// `Jit::new` fails on any platform without the macOS/AArch64 W^X backend.
fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn run(bits: Bits, count: u64, seed: u64, chain: u32) {
    if !jit_available() {
        eprintln!("skipping: no JIT backend on this platform");
        return;
    }
    let s = fuzz(&JitFuzzConfig { bits, count, seed, max_report: 8, chain })
        .expect("the JIT backend should be available here");
    for d in &s.first {
        eprintln!("{}", render(d));
    }
    assert_eq!(
        s.divergences, 0,
        "{} divergence(s) in {} trials ({} instructions natively, {:.1}% coverage)",
        s.divergences,
        s.trials,
        s.insns,
        s.coverage()
    );
    // A run that compiles nothing would pass vacuously; require real work.
    assert!(s.insns > count / 2, "only {} instructions compiled in {} trials", s.insns, s.trials);
}

#[test]
fn jit_matches_the_interpreter_64bit() {
    run(Bits::B64, 4_000, 1, 8);
}

#[test]
fn jit_matches_the_interpreter_32bit() {
    run(Bits::B32, 4_000, 1, 8);
}

/// Single-instruction blocks: every compiled opcode is exercised in isolation,
/// where a divergence points straight at one lowering rather than at a chain.
#[test]
fn jit_matches_the_interpreter_one_instruction_at_a_time() {
    run(Bits::B64, 4_000, 7, 1);
    run(Bits::B32, 4_000, 7, 1);
}

/// A second, independent seed: the generator is deterministic per (seed, index),
/// so a fixed seed can only ever explore one slice of the space.
#[test]
fn jit_matches_the_interpreter_second_seed() {
    run(Bits::B64, 4_000, 0xC0FFEE, 16);
    run(Bits::B32, 4_000, 0xC0FFEE, 16);
}
