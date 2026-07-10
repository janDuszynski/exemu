//! End-to-end: a TLS callback must run at process attach, *before* the entry
//! point (roadmap W0.3).
//!
//! `sample::build_with_tls` produces a real PE whose single TLS callback stores
//! `TLS_SENTINEL` into a `.data` cell; the entry point reads that cell and exits
//! with its value. If the loader fires the callback before entry (as the PE/COFF
//! spec requires) the process exits `TLS_SENTINEL`; if it does not, the cell is
//! still zero and it exits `0`. This exercises the whole stack — the loader's
//! TLS directory parse, the app's index/template seeding, and the OS layer's
//! re-entrant callback dispatch ahead of `AddressOfEntryPoint`.

use exemu_app::{load_and_run, sample, Process, RunConfig};

fn silent_cfg() -> RunConfig {
    RunConfig { echo: false, trace: false, ..RunConfig::default() }
}

#[test]
fn tls_fixture_parses_with_one_callback() {
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).expect("tls fixture should parse");
    let tls = image.tls.as_ref().expect("fixture must carry a TLS directory");
    assert_eq!(tls.callback_rvas.len(), 1, "expected exactly one TLS callback");
    // The callback is the first thing in .text (RVA 0x1000).
    assert_eq!(tls.callback_rvas[0], 0x1000);
    // A non-empty init template and a real AddressOfIndex are present.
    assert_eq!(tls.raw_template.len(), 8);
    assert_ne!(tls.address_of_index, 0);
}

#[test]
fn tls_callback_runs_before_entry_point() {
    let bytes = sample::build_with_tls();
    let result = load_and_run(&bytes, silent_cfg()).expect("tls fixture should run");
    assert_eq!(
        result.exit_code, sample::TLS_SENTINEL as i32,
        "TLS callback did not run before the entry point (sentinel not written)"
    );
    assert!(result.steps < 1000, "unexpectedly many steps: {}", result.steps);
}

#[test]
fn tls_index_is_published_and_template_copied() {
    // After load, the loader must have written the allocated TLS index to
    // AddressOfIndex and laid the init template down at [Start, End).
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).unwrap();
    let tls = image.tls.clone().unwrap();
    let proc = Process::load(&bytes, &silent_cfg()).expect("load");
    // Index slot holds 0 (the first allocated TLS index).
    let idx = proc.peek_u32(tls.address_of_index).expect("index slot mapped");
    assert_eq!(idx, 0, "loader should publish TLS index 0 at AddressOfIndex");
    // The template's first byte was copied from the image (0xB0 pattern).
    let first = proc.peek_u8(tls.start_address_of_raw_data).expect("template mapped");
    assert_eq!(first, 0xB0, "TLS init template not laid down");
}
