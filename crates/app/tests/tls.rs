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
    assert_eq!(tls.callback_rvas[0], 0x1000);
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
    let bytes = sample::build_with_tls();
    let image = exemu_loader::parse(&bytes).unwrap();
    let tls = image.tls.clone().unwrap();
    let proc = Process::load(&bytes, &mut silent_cfg()).expect("load");
    let idx = proc.peek_u32(tls.address_of_index).expect("index slot mapped");
    assert_eq!(idx, 0, "loader should publish TLS index 0 at AddressOfIndex");
    let first = proc.peek_u8(tls.start_address_of_raw_data).expect("template mapped");
    assert_eq!(first, 0xB0, "TLS init template not laid down");
}
