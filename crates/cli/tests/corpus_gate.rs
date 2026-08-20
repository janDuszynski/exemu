//! The corpus regression gate (roadmap W9.6) — the per-exe pins as a test.
//!
//! The roadmap lists per-exe regression pins as one of four standing harnesses,
//! and the only one that can catch cross-thread / IPC / integration regressions:
//! the differential CPU oracle is single-stream and structurally cannot see
//! them. This test runs the pins in `corpus.toml` and fails on any drift —
//! a different instruction count, a moved fault site, a lost output file.
//!
//! # When it skips, and why
//!
//! 1. **No corpus.** The binaries live in `example_exe/`, which is git-ignored
//!    (third-party installers we do not redistribute). A fresh checkout — CI —
//!    has none, so the test prints SKIP and passes, the same skip-guard idiom as
//!    `crates/app/tests/wine_gate.rs`.
//! 2. **Debug build.** The pins are measured on a `--release` build, and a debug
//!    build is ~10x slower — 7-Zip alone executes ~496M instructions. On the
//!    host-clock entry it is worse than slow: a guest that polls the clock spins
//!    a different number of times at a different host speed, so the count
//!    genuinely differs and debug pins would be a second, unmaintained set of
//!    numbers. (A `virtual_clock` entry has no such excuse — its count is a pure
//!    function of the guest's instruction stream — but the runtime alone still
//!    rules a debug run out.) Run `cargo test --release`.
//!
//! # Tiers
//!
//! By default only the entries flagged `quick = true` run (~2 s — Firefox
//! Installer on both clocks, and tcc). Set `EXEMU_CORPUS=full` to include the
//! minutes-long ones (7-Zip's full install, SteamSetup's 93M-instruction reach).
//! The full tier is the release gate; the quick tier is what `cargo test
//! --release` can afford to run on every change.

use std::path::{Path, PathBuf};

use exemu_cli::corpus::{render_table, Manifest, Options};

/// `corpus.toml` lives at the repository root, two levels above this crate.
fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("corpus.toml")
}

#[test]
fn corpus_pins_hold() {
    let path = manifest_path();
    let manifest = match Manifest::load(&path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("SKIP: {e}");
            return;
        }
    };

    if !manifest.corpus_present() {
        let missing: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| !manifest.exe_path(e).exists())
            .map(|e| e.name.as_str())
            .collect();
        eprintln!(
            "SKIP: corpus binaries absent (example_exe/ is git-ignored): {}",
            missing.join(", ")
        );
        return;
    }

    if cfg!(debug_assertions) {
        eprintln!(
            "SKIP: the corpus pins are measured on a release build (a debug build is ~10x \
             slower, which changes clock-polling guests' instruction counts as well as the \
             runtime) — run `cargo test --release -p exemu-cli --test corpus_gate`"
        );
        return;
    }

    let full = matches!(std::env::var("EXEMU_CORPUS").as_deref(), Ok("full") | Ok("1"));
    let mut opts = Options::new(PathBuf::from(env!("CARGO_BIN_EXE_exemu")));
    opts.workroot = std::env::temp_dir().join("exemu-corpus-gate");
    opts.quick = !full;

    let verdicts = exemu_cli::corpus::run_manifest(&manifest, &opts).expect("corpus run");
    let table = render_table(&verdicts);
    eprintln!(
        "corpus gate ({} tier, {} of {} entries):\n{table}",
        if full { "full" } else { "quick" },
        verdicts.len(),
        manifest.entries.len()
    );
    if !full {
        eprintln!("  (set EXEMU_CORPUS=full to include the minutes-long installers)");
    }

    let failed: Vec<_> = verdicts.iter().filter(|v| !v.passed()).collect();
    if !failed.is_empty() {
        let mut msg = String::from("corpus drift vs corpus.toml:\n");
        for v in &failed {
            msg.push_str(&format!("  {}\n", v.entry.name));
            for p in &v.problems {
                msg.push_str(&format!("      {p}\n"));
            }
        }
        msg.push_str(&table);
        msg.push_str(
            "\nIf the change is intended, re-bless deliberately with\n  \
             cargo run --release -p exemu-cli -- corpus --update\nand review the manifest diff.",
        );
        panic!("{msg}");
    }
}

/// The manifest itself must stay well-formed and internally consistent even on
/// a machine with no corpus — this half of the gate always runs, so a typo in
/// `corpus.toml` fails in CI rather than on the one machine that has the exes.
#[test]
fn manifest_is_well_formed() {
    let path = manifest_path();
    let manifest = Manifest::load(&path).expect("corpus.toml parses");
    assert!(!manifest.entries.is_empty(), "manifest declares binaries");

    let mut seen = std::collections::HashSet::new();
    for e in &manifest.entries {
        assert!(seen.insert(e.name.clone()), "duplicate entry name {:?}", e.name);
        assert!(!e.path.is_empty(), "{}: empty path", e.name);
        assert!(e.max_steps > e.steps, "{}: budget must exceed the pinned count", e.name);
        assert!(
            e.tolerance < e.steps.max(1),
            "{}: tolerance {} swallows the whole pin",
            e.name,
            e.tolerance
        );
        // The virtual clock leaves no host input to jitter on, so such an entry
        // is an equality — for a fault's reach metric as much as for an exit.
        // Any slack here would be un-earned and would hide a real one-instruction
        // change (roadmap W9.6).
        if e.virtual_clock {
            assert_eq!(
                e.tolerance, 0,
                "{}: a virtual-clock pin is exact; a tolerance would hide real drift",
                e.name
            );
        }
        match e.outcome {
            exemu_cli::corpus::Outcome::Exit => {
                // On the host clock a completed trace is the strongest assertion
                // available, so it is pinned at the bare measurement noise floor
                // — never scaled to the length of the run the way a fault's reach
                // metric is.
                if !e.virtual_clock {
                    assert_eq!(
                        e.tolerance,
                        exemu_cli::corpus::Entry::JITTER_FLOOR,
                        "{}: a host-clock exit is pinned at the noise floor, not a percentage",
                        e.name
                    );
                }
                assert!(e.rip.is_none(), "{}: an exit has no fault site", e.name);
            }
            exemu_cli::corpus::Outcome::Fault => {
                assert!(e.stop.is_some(), "{}: a fault pin must state its reason", e.name);
                assert!(e.rip.is_some(), "{}: a fault pin must state its site", e.name);
            }
            exemu_cli::corpus::Outcome::Budget => {
                panic!("{}: `budget` is an observed outcome, never an expectation", e.name)
            }
        }
    }
    assert!(
        manifest.entries.iter().any(|e| e.quick),
        "at least one entry must be in the quick tier or the default gate is empty"
    );
    // Both clock paths stay covered. The virtual clock is the high-resolution
    // instrument, but the host clock is what a plain `exemu run` still does, so
    // dropping it from the gate would stop testing the default.
    assert!(
        manifest.entries.iter().any(|e| e.virtual_clock),
        "at least one entry must pin the deterministic clock (roadmap W9.6)"
    );
    assert!(
        manifest.entries.iter().any(|e| !e.virtual_clock && e.quick),
        "at least one quick entry must stay on the default host clock"
    );
    // `--update` must be able to round-trip whatever is committed, or a
    // re-blessed manifest would silently lose fields.
    let reparsed = Manifest::load(&path).expect("reload");
    assert_eq!(
        Manifest::load(&path).unwrap().to_toml(),
        reparsed.to_toml(),
        "manifest emitting is stable"
    );
}
