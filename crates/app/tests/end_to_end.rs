//! End-to-end: generate a real PE, load it, and run it to completion.
//!
//! This exercises the whole stack — the PE builder, the loader, memory
//! mapping, import resolution/IAT patching, the interpreter and the OS
//! layer — with no host toolchain involved.

use exemu_app::{sample, load_and_run, Process, RunConfig};

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
fn entry_point_is_in_text_section() {
    let bytes = sample::build();
    let proc = Process::load(&bytes, &silent_cfg()).expect("load");
    // Image base 0x140000000 + .text RVA 0x1000.
    assert_eq!(proc.entry(), 0x1_4000_1000);
}

#[test]
fn rejects_garbage() {
    let err = load_and_run(b"this is not an exe", silent_cfg());
    assert!(err.is_err());
}
