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
use exemu_oracle::jitdiff::{fuzz, render, DebugMix, JitFuzzConfig, LayoutMix};

/// `Jit::new` fails on any platform without the macOS/AArch64 W^X backend.
fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn run_mix(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix) {
    run_laps(bits, count, seed, chain, layouts, 1);
}

fn run_laps(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix, laps: u32) {
    run_debug(bits, count, seed, chain, layouts, laps, DebugMix::Off);
}

#[allow(clippy::too_many_arguments)]
fn run_debug(
    bits: Bits,
    count: u64,
    seed: u64,
    chain: u32,
    layouts: LayoutMix,
    laps: u32,
    debug: DebugMix,
) {
    if !jit_available() {
        eprintln!("skipping: no JIT backend on this platform");
        return;
    }
    let s = fuzz(&JitFuzzConfig { bits, count, seed, max_report: 8, chain, layouts, laps, debug })
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
    // …and for a run whose regions were all too tight for the guest-memory TLB
    // to cache, which would silently measure only the helper path (roadmap
    // W8.6). A watchpoint run is the exception, and deliberately so: while one
    // is armed *nothing* may be cached, which is the property S6 rests on.
    assert!(s.tlb_fills > 0, "the guest-memory TLB filled nothing in {count} trials");
    match debug {
        // The same trials, run twice: entries are filled with nothing armed
        // (asserted above) and **none** with a watchpoint armed. Neither half
        // means anything without the other.
        DebugMix::Watch => {
            assert_eq!(s.armed_tlb_fills, 0, "an entry was cached while a watchpoint was armed");
        }
        // A breakpoint is not a memory event, and must not take guest memory
        // off the fast path.
        DebugMix::Break => {
            assert!(s.armed_tlb_fills > 0, "arming a breakpoint disabled the guest-memory TLB");
            // The path S3 exists for: a chain that reached the armed address
            // and handed control back rather than interpreting through it. It
            // only happens with a budget wider than one block, which is why the
            // debugged runs get one.
            assert!(s.breakpoint_stops > 0, "no chain ever stopped at an armed address");
        }
        DebugMix::Off => {}
    }
    // A debugged run that never once reached the thing it armed would pass
    // without exercising anything.
    if debug != DebugMix::Off {
        assert!(
            s.debug_split > count / 20,
            "only {} of {count} trials reached what they armed",
            s.debug_split
        );
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

/// **Breakpoints in compiled code** (roadmap W9.3, S3). Every trial arms one
/// instruction breakpoint, drawn uniformly from the addresses that trial's own
/// interpreter trace passes through, and the JIT must retire *exactly* as many
/// instructions as the interpreter says lie before it — no more, which would be
/// a missed breakpoint, and no fewer, which would be a block split at the wrong
/// place.
///
/// The expected count is computed from the interpreter, never from the JIT, so
/// a JIT that "honoured" breakpoints by declining to compile at all would fail
/// this rather than pass it.
#[test]
fn jit_honours_a_breakpoint_at_a_random_point_of_every_trial() {
    run_debug(Bits::B64, 4_000, 31, 8, LayoutMix::Mixed, 1, DebugMix::Break);
    run_debug(Bits::B32, 4_000, 31, 8, LayoutMix::Mixed, 1, DebugMix::Break);
}

/// The same at the address boundary, where the block's own byte range wraps and
/// `stop_before` is compared against a masked `rip`.
#[test]
fn jit_honours_a_breakpoint_at_the_address_boundary() {
    run_debug(Bits::B64, 4_000, 33, 8, LayoutMix::Edge, 1, DebugMix::Break);
    run_debug(Bits::B32, 4_000, 33, 8, LayoutMix::Edge, 1, DebugMix::Break);
}

/// **Watchpoints in compiled code** (roadmap W9.3, S6). Every trial arms one
/// data watchpoint over a random sub-range of the data region, and the JIT must
/// rewind onto exactly the instruction at which the interpreter first records a
/// hit — which is the asymmetry worth testing rather than assuming, since the
/// compiled block checks *before* the access and the interpreter *after* it.
#[test]
fn jit_stops_a_compiled_block_on_a_watched_access() {
    run_debug(Bits::B64, 4_000, 41, 8, LayoutMix::Mixed, 1, DebugMix::Watch);
    run_debug(Bits::B32, 4_000, 41, 8, LayoutMix::Mixed, 1, DebugMix::Watch);
}

/// The same at the address boundary, where an access can straddle 2^32.
#[test]
fn jit_stops_a_compiled_block_on_a_watched_access_at_the_boundary() {
    run_debug(Bits::B64, 4_000, 43, 8, LayoutMix::Edge, 1, DebugMix::Watch);
    run_debug(Bits::B32, 4_000, 43, 8, LayoutMix::Edge, 1, DebugMix::Watch);
}
