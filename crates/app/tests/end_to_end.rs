//! End-to-end: generate a real PE, load it, and run it to completion.
//!
//! This exercises the whole stack — the PE builder, the loader, memory
//! mapping, import resolution/IAT patching, the interpreter and the OS
//! layer — with no host toolchain involved.

use exemu_app::{gui_sample, sample, load_and_run, Process, RunConfig};

fn silent_cfg() -> RunConfig {
    RunConfig { echo: false, trace: true, ..RunConfig::default() }
}

#[test]
fn sample_exe_parses() {
    let bytes = sample::build();
    // The loader accepts it and finds the three kernel32 imports.
    let image = exemu_loader::parse(&bytes).expect("sample should parse");
    assert_eq!(image.imports.len(), 3);
    assert!(image
        .imports
        .iter()
        .all(|i| i.dll == "kernel32.dll"));
    let names: Vec<_> = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    assert!(names.contains(&"GetStdHandle"));
    assert!(names.contains(&"WriteFile"));
    assert!(names.contains(&"ExitProcess"));
}

#[test]
fn sample_exe_runs_and_prints() {
    let bytes = sample::build();
    let result = load_and_run(&bytes, silent_cfg()).expect("sample should run");

    assert_eq!(result.exit_code, 0, "program should exit cleanly");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(out.starts_with(sample::SAMPLE_MESSAGE), "greeting missing; got: {out:?}");
    // The SSE2 computation (1.5 + 2.25) * 2.0 truncates to 7.
    assert!(
        out.contains(&format!("{}7", sample::SAMPLE_SSE_PREFIX)),
        "SSE result line missing; got: {out:?}"
    );
    // A tiny program should finish in well under a hundred instructions.
    assert!(result.steps < 1000, "unexpectedly many steps: {}", result.steps);
}

#[test]
fn gui_sample_parses_with_multiple_dll_imports() {
    let bytes = gui_sample::build();
    let image = exemu_loader::parse(&bytes).expect("gui sample should parse");
    let dlls: std::collections::HashSet<_> = image.imports.iter().map(|i| i.dll.as_str()).collect();
    assert!(dlls.contains("user32.dll"), "missing user32 imports");
    assert!(dlls.contains("gdi32.dll"), "missing gdi32 imports");
    assert!(dlls.contains("kernel32.dll"), "missing kernel32 imports");
    let names: Vec<_> = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    for expected in ["RegisterClassW", "CreateWindowExW", "TextOutW", "BeginPaint"] {
        assert!(names.contains(&expected), "missing import {expected}");
    }
}

#[test]
fn gui_sample_runs_to_a_clean_exit() {
    // Headless (NoGui): the window class registers, the window "creates", the
    // message loop runs and dispatches to the WndProc, and the program exits 0
    // — exercising the whole RegisterClass/CreateWindowEx/GDI path even with
    // no display attached.
    let bytes = gui_sample::build();
    let result = load_and_run(&bytes, silent_cfg()).expect("gui sample should run");
    assert_eq!(result.exit_code, 0, "gui sample should exit cleanly");
    assert!(result.steps < 1000, "unexpectedly many steps: {}", result.steps);
}

#[test]
fn entry_point_is_in_text_section() {
    let bytes = sample::build();
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    // Image base 0x140000000 + .text RVA 0x1000.
    assert_eq!(proc.entry(), 0x1_4000_1000);
}

#[test]
fn rejects_garbage() {
    let err = load_and_run(b"this is not an exe", silent_cfg());
    assert!(err.is_err());
}

#[test]
fn decode_miss_surfaces_structured_cause() {
    // A run that stops on an instruction the decoder can't handle must surface
    // a structured `EmuError::Decode` *through* the diagnostic fault wrapper, so
    // the opcode-miss telemetry (roadmap P0.5) can key off it. Regression guard:
    // the fault reporter used to collapse every error into `EmuError::Os`, which
    // silently disabled the telemetry recording.
    let mut bytes = sample::build();
    // Overwrite the entry prologue's first byte with 0xF1 (ICEBP/INT1 — an
    // opcode the interpreter does not decode) to force a decode miss at the
    // entry point. Locating the prologue by pattern keeps this robust to layout
    // changes. (x87 ESC 0xD8..0xDF is implemented — roadmap W1.1; the 0xC4/0xC5
    // VEX prefixes are implemented — roadmap W1.5 — so neither is a decode miss
    // any longer.)
    let entry_prologue = [0x48u8, 0x83, 0xEC, 0x38]; // sub rsp, 0x38
    let at = bytes
        .windows(entry_prologue.len())
        .position(|w| w == entry_prologue)
        .expect("sample entry prologue present");
    bytes[at] = 0xF1;

    let err = match load_and_run(&bytes, silent_cfg()) {
        Err(e) => e,
        Ok(_) => panic!("decode miss must fault, but the run succeeded"),
    };
    match err.cause() {
        exemu_core::EmuError::Decode { opcode, .. } => assert_eq!(opcode, "0xf1"),
        other => panic!("expected a structured Decode cause, got {other:?}"),
    }
}

/// The deterministic clock, end to end through `Process::load`/`run` (roadmap
/// W9.6): the whole wiring — the shared `GuestClock` handle reaching both the
/// interpreter and the OS layer, and the run loop's `KUSER_SHARED_DATA` refresh
/// — must leave a normal program's behaviour untouched and its instruction count
/// identical run to run.
///
/// The corpus gate is the *strong* proof of replay (496M instructions, Δ 0), but
/// it needs the git-ignored installers and skips without them. This runs on a
/// fresh checkout, so the plumbing cannot silently rot.
#[test]
fn the_virtual_clock_leaves_a_run_identical_and_repeatable() {
    let bytes = sample::build();
    let run_once = |virtual_clock: bool| {
        let cfg = RunConfig { virtual_clock, ..silent_cfg() };
        let r = load_and_run(&bytes, cfg).expect("sample should run");
        (r.exit_code, r.steps, String::from_utf8_lossy(&r.stdout).into_owned())
    };

    let host = run_once(false);
    let a = run_once(true);
    let b = run_once(true);
    let c = run_once(true);

    assert_eq!(a.0, 0, "the program still exits cleanly with the clock virtualised");
    assert_eq!(a, b, "two virtual-clock runs are identical");
    assert_eq!(b, c, "…and a third");
    assert_eq!(
        host, a,
        "the clock must not change what the program does, only where its time comes from"
    );
}
