use exemu_cpu::Bits;
use exemu_oracle::jitdiff::{fuzz, render, DebugMix, JitFuzzConfig, LayoutMix};

fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn run_mix(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix) {
    run_laps(bits, count, seed, chain, layouts, 1);
}

fn run_laps(bits: Bits, count: u64, seed: u64, chain: u32, layouts: LayoutMix, laps: u32) {
    run_debug(bits, count, seed, chain, layouts, laps, DebugMix::Off);
}

fn run_cut(bits: Bits, count: u64, seed: u64, layouts: LayoutMix) {
    if !jit_available() {
        eprintln!("skipping: no JIT backend on this platform");
        return;
    }
    let s = fuzz(&JitFuzzConfig {
        bits,
        count,
        seed,
        max_report: 8,
        chain: 8,
        layouts,
        laps: 4,
        debug: DebugMix::Off,
        cut: true,
    })
    .expect("the JIT backend should be available here");
    for d in &s.first {
        eprintln!("{}", render(d));
    }
    assert_eq!(s.divergences, 0, "{} divergence(s) in {} trials", s.divergences, s.trials);
    assert!(s.insns > count / 2, "only {} instructions compiled in {} trials", s.insns, s.trials);
    assert!(s.links_taken > count / 4, "only {} native links taken", s.links_taken);
    assert!(
        s.budget_refusals > count / 2,
        "only {} chains refused a block that would cross a budget with room left ({} stops in all)",
        s.budget_refusals,
        s.budget_stops
    );
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
    let s = fuzz(&JitFuzzConfig {
        bits,
        count,
        seed,
        max_report: 8,
        chain,
        layouts,
        laps,
        debug,
        cut: false,
    })
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
    assert!(s.insns > count / 2, "only {} instructions compiled in {} trials", s.insns, s.trials);
    if laps > 1 {
        assert!(s.links_taken > count / 2, "only {} native links taken", s.links_taken);
    }
    assert!(s.tlb_fills > 0, "the guest-memory TLB filled nothing in {count} trials");
    match debug {
        DebugMix::Watch => {
            assert_eq!(s.armed_tlb_fills, 0, "an entry was cached while a watchpoint was armed");
        }
        DebugMix::Break => {
            assert!(s.armed_tlb_fills > 0, "arming a breakpoint disabled the guest-memory TLB");
            assert!(s.breakpoint_stops > 0, "no chain ever stopped at an armed address");
        }
        DebugMix::Off => {}
    }
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

#[test]
fn jit_matches_the_interpreter_one_instruction_at_a_time() {
    run(Bits::B64, 4_000, 7, 1);
    run(Bits::B32, 4_000, 7, 1);
}

#[test]
fn jit_matches_the_interpreter_second_seed() {
    run(Bits::B64, 4_000, 0xC0FFEE, 16);
    run(Bits::B32, 4_000, 0xC0FFEE, 16);
}

#[test]
fn jit_matches_the_interpreter_at_the_address_boundary() {
    run_mix(Bits::B64, 4_000, 3, 8, LayoutMix::Edge);
    run_mix(Bits::B32, 4_000, 3, 8, LayoutMix::Edge);
    run_mix(Bits::B64, 4_000, 11, 1, LayoutMix::Edge);
    run_mix(Bits::B32, 4_000, 11, 1, LayoutMix::Edge);
}

#[test]
fn jit_matches_the_interpreter_across_native_links() {
    run_laps(Bits::B64, 4_000, 21, 8, LayoutMix::Mixed, 4);
    run_laps(Bits::B32, 4_000, 21, 8, LayoutMix::Mixed, 4);
}

#[test]
fn jit_matches_the_interpreter_across_native_links_at_the_boundary() {
    run_laps(Bits::B64, 4_000, 22, 8, LayoutMix::Edge, 4);
    run_laps(Bits::B32, 4_000, 22, 8, LayoutMix::Edge, 4);
}

#[test]
fn jit_never_retires_past_a_budget_that_ends_inside_a_block() {
    run_cut(Bits::B64, 4_000, 23, LayoutMix::Mixed);
    run_cut(Bits::B32, 4_000, 23, LayoutMix::Mixed);
}

#[test]
fn jit_never_retires_past_a_budget_at_the_address_boundary() {
    run_cut(Bits::B64, 4_000, 24, LayoutMix::Edge);
    run_cut(Bits::B32, 4_000, 24, LayoutMix::Edge);
}

#[test]
fn jit_matches_the_interpreter_in_the_low_layout_only() {
    run_mix(Bits::B64, 4_000, 5, 8, LayoutMix::Low);
    run_mix(Bits::B32, 4_000, 5, 8, LayoutMix::Low);
}

#[test]
fn jit_honours_a_breakpoint_at_a_random_point_of_every_trial() {
    run_debug(Bits::B64, 4_000, 31, 8, LayoutMix::Mixed, 1, DebugMix::Break);
    run_debug(Bits::B32, 4_000, 31, 8, LayoutMix::Mixed, 1, DebugMix::Break);
}

#[test]
fn jit_honours_a_breakpoint_at_the_address_boundary() {
    run_debug(Bits::B64, 4_000, 33, 8, LayoutMix::Edge, 1, DebugMix::Break);
    run_debug(Bits::B32, 4_000, 33, 8, LayoutMix::Edge, 1, DebugMix::Break);
}

#[test]
fn jit_stops_a_compiled_block_on_a_watched_access() {
    run_debug(Bits::B64, 4_000, 41, 8, LayoutMix::Mixed, 1, DebugMix::Watch);
    run_debug(Bits::B32, 4_000, 41, 8, LayoutMix::Mixed, 1, DebugMix::Watch);
}

#[test]
fn jit_stops_a_compiled_block_on_a_watched_access_at_the_boundary() {
    run_debug(Bits::B64, 4_000, 43, 8, LayoutMix::Edge, 1, DebugMix::Watch);
    run_debug(Bits::B32, 4_000, 43, 8, LayoutMix::Edge, 1, DebugMix::Watch);
}
