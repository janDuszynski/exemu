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
use exemu_oracle::jitdiff::{fuzz, render, JitFuzzConfig, LayoutMix};

/// `Jit::new` fails on any platform without the macOS/AArch64 W^X backend.
fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn run_mix(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix) {
    run_laps(bits, count, seed, chain, layouts, 1);
}

fn run_laps(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix, laps: u32) {
    if !jit_available() {
        eprintln!("skipping: no JIT backend on this platform");
        return;
    }
    let s = fuzz(&JitFuzzConfig { bits, count, seed, max_report: 8, chain, layouts, laps })
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
    // Likewise for a lapped run that never actually linked anything.
    if laps > 1 {
        assert!(s.links_taken > count / 2, "only {} native links taken", s.links_taken);
    }
}

fn run(bits: Bits, count: u64, seed: u64, chain: u32) {
    run_mix(bits, count, seed, chain, LayoutMix::Mixed);
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

/// Only the boundary layouts (roadmap W8.7): every trial computes an address
/// across 2^32 (32-bit) or above 4 GiB (64-bit), which is where the JIT and the
/// interpreter can disagree about the width of an address without either
/// looking wrong on its own. The low-layout runs above cannot reach this at all.
#[test]
fn jit_matches_the_interpreter_at_the_address_boundary() {
    run_mix(Bits::B64, 4_000, 3, 8, LayoutMix::Edge);
    run_mix(Bits::B32, 4_000, 3, 8, LayoutMix::Edge);
    run_mix(Bits::B64, 4_000, 11, 1, LayoutMix::Edge);
    run_mix(Bits::B32, 4_000, 11, 1, LayoutMix::Edge);
}

/// **Natively linked chains** (roadmap W8.5). Every trial above walks each of
/// its blocks exactly once, which is precisely the case in which no link is ever
/// *taken* — the slots get filled and the trial ends. These trials end in a
/// `jmp` back to their own first instruction instead, with the block cap dropped
/// so the body is several blocks, so the second and later passes enter blocks by
/// a `br` from the previous block's exit with no Rust in between. What is
/// compared against the interpreter is then what a linked chain computed: the
/// registers, the flags, `rip`, and every byte of guest memory.
#[test]
fn jit_matches_the_interpreter_across_native_links() {
    run_laps(Bits::B64, 4_000, 21, 8, LayoutMix::Mixed, 4);
    run_laps(Bits::B32, 4_000, 21, 8, LayoutMix::Mixed, 4);
}

/// The same, at the address boundary — where a block ends on the top of the
/// address space and its successor is at a *lower* address than it started.
#[test]
fn jit_matches_the_interpreter_across_native_links_at_the_boundary() {
    run_laps(Bits::B64, 4_000, 22, 8, LayoutMix::Edge, 4);
    run_laps(Bits::B32, 4_000, 22, 8, LayoutMix::Edge, 4);
}

/// The pre-W8.7 shape, kept so an old run can still be reproduced exactly.
#[test]
fn jit_matches_the_interpreter_in_the_low_layout_only() {
    run_mix(Bits::B64, 4_000, 5, 8, LayoutMix::Low);
    run_mix(Bits::B32, 4_000, 5, 8, LayoutMix::Low);
}
