use std::path::Path;

use exemu_app::{load_and_run, sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";
const GREETING: &str = "Hello from exemu";

#[test]
fn console_hello_runs_on_wine_pe_kernel32() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = sample::build();

    let emulated = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    assert_eq!(emulated.exit_code, 0, "emulated exit code");
    assert!(
        String::from_utf8_lossy(&emulated.stdout).contains(GREETING),
        "emulated stdout"
    );
    assert!(
        emulated.steps < 1000,
        "emulated path is trivial, was {} steps",
        emulated.steps
    );

    let wine = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    )
    .expect("wine-boot run");

    assert_eq!(wine.exit_code, 0, "console program exit code on Wine's kernel32");
    assert!(
        String::from_utf8_lossy(&wine.stdout).contains(GREETING),
        "stdout produced through Wine's kernel32 → NtWriteFile: {:?}",
        String::from_utf8_lossy(&wine.stdout)
    );
    assert!(
        wine.steps > 100_000,
        "the full Wine PE core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}

#[test]
fn console_fileio_roundtrips_and_propagates_exit_code_on_wine() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = sample::build_console_fileio();

    let emulated = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    assert_eq!(emulated.exit_code, 42, "emulated exit code (round-trip matched)");
    assert!(
        String::from_utf8_lossy(&emulated.stdout).contains("OK"),
        "emulated stdout: {:?}",
        String::from_utf8_lossy(&emulated.stdout)
    );
    assert!(
        emulated.steps < 5000,
        "emulated path is trivial, was {} steps",
        emulated.steps
    );

    let wine = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 20_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    )
    .expect("wine-boot run");

    assert_eq!(
        wine.exit_code, 42,
        "non-zero exit code propagated through Wine's ExitProcess → NtTerminateProcess"
    );
    assert!(
        String::from_utf8_lossy(&wine.stdout).contains("OK"),
        "file-I/O round-trip reported OK through Wine's kernel32: {:?}",
        String::from_utf8_lossy(&wine.stdout)
    );
    let host_file = Path::new(&wine.sandbox).join("C").join("wine-gate.txt");
    let bytes = std::fs::read(&host_file)
        .unwrap_or_else(|e| panic!("host file {host_file:?} should exist: {e}"));
    assert_eq!(
        bytes,
        sample::FILEIO_PAYLOAD,
        "the payload Wine's NtWriteFile committed to disk"
    );
    assert!(
        wine.steps > 100_000,
        "the full Wine PE core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}
