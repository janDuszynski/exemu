use exemu_app::{gui_sample, sample, load_and_run, Process, RunConfig};

fn silent_cfg() -> RunConfig {
    RunConfig { echo: false, trace: true, ..RunConfig::default() }
}

#[test]
fn sample_exe_parses() {
    let bytes = sample::build();
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
    assert!(
        out.contains(&format!("{}7", sample::SAMPLE_SSE_PREFIX)),
        "SSE result line missing; got: {out:?}"
    );
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
    let bytes = gui_sample::build();
    let result = load_and_run(&bytes, silent_cfg()).expect("gui sample should run");
    assert_eq!(result.exit_code, 0, "gui sample should exit cleanly");
    assert!(result.steps < 1000, "unexpectedly many steps: {}", result.steps);
}

#[test]
fn entry_point_is_in_text_section() {
    let bytes = sample::build();
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    assert_eq!(proc.entry(), 0x1_4000_1000);
}

#[test]
fn rejects_garbage() {
    let err = load_and_run(b"this is not an exe", silent_cfg());
    assert!(err.is_err());
}

#[test]
fn decode_miss_surfaces_structured_cause() {
    let mut bytes = sample::build();
    let entry_prologue = [0x48u8, 0x83, 0xEC, 0x38];
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

#[test]
fn a_null_deref_fault_names_the_stubs_that_returned_zero() {
    const TCC: &str = "../../example_exe/tcc.exe";
    if !std::path::Path::new(TCC).exists() {
        eprintln!("SKIP: {TCC} not present (the corpus is git-ignored)");
        return;
    }
    let bytes = std::fs::read(TCC).expect("read the pinned tcc.exe");
    let dir = std::env::temp_dir().join(format!("exemu-nullref-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let outcome = load_and_run(
        &bytes,
        RunConfig {
            echo: false,
            max_steps: 100_000,
            sandbox_root: Some(dir.clone()),
            ..RunConfig::default()
        },
    );
    let Err(err) = outcome else {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("tcc.exe is expected to fault on the emulated path; it ran to completion");
    };
    let report = err.to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(report.contains("NULL dereference"), "the shape is recognised; report:\n{report}");
    for sym in ["VerifyVersionInfoW", "VerSetConditionMask"] {
        assert!(
            report.contains(sym),
            "the suspect list should name {sym} — the stub that produced this NULL; report:\n{report}"
        );
    }
    assert!(report.contains(".exe+0x"), "the rip trail is module-attributed; report:\n{report}");
    assert!(report.contains("loaded modules:"), "the report lists the mapped images; report:\n{report}");
    assert!(
        report.contains(": unmapped, between nothing and \""),
        "the faulting address is placed in the memory map, below every region; report:\n{report}"
    );
}
