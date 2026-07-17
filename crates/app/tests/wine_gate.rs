//! W3 GATE — a console `.exe` runs to completion on **Wine's real PE core**
//! (ntdll → kernelbase → kernel32 → ucrtbase), producing correct stdout and
//! exit code, with all kernel work serviced by exemu's NT syscalls.
//!
//! The proof binary is exemu's own generated 64-bit console sample (imports
//! `GetStdHandle`/`WriteFile`/`ExitProcess` from `kernel32.dll`, prints a
//! greeting + an SSE-computed number, exits 0). Booted with `wine_boot_dir`
//! set, exemu maps ntdll(self) + the exe, hands off through
//! `LdrInitializeThunk`, and Wine's own `loader_init`/`build_module` loads
//! kernel32/kernelbase/ucrtbase from the prefix (as real `SEC_IMAGE` sections)
//! and **re-binds the exe's imports to its own kernel32**. So the program's
//! `WriteFile` runs Wine's kernel32 → `NtWriteFile` → exemu's console bridge
//! (roadmap W3.4) → host stdio, and `ExitProcess` exits 0 — none of exemu's
//! emulated API thunks are used on this path (verified separately by `--trace`:
//! the emulated `GetStdHandle`/`WriteFile`/`ExitProcess` thunks fire on the
//! emulated path and do NOT fire on the Wine-boot path).
//!
//! Skip-guarded on the git-ignored Wine DLL set.

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

    // Control — the EMULATED path runs the same program in a handful of
    // instructions (exemu's own `WriteFile` thunk services the output), proving
    // the program itself is trivial and any large instruction count on the Wine
    // path is Wine's PE core booting, not the program.
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

    // The GATE — boot Wine's real PE core and run the same console program on it.
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
    // The full Wine PE boot (ntdll/kernel32/kernelbase/ucrtbase init) ran: orders
    // of magnitude more instructions than the emulated path's handful. A trivial
    // program taking >100k instructions can only be Wine's real core booting.
    assert!(
        wine.steps > 100_000,
        "the full Wine PE core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}

/// Broadened W3 gate (roadmap W3.7): a console `.exe` drives a full **file-I/O
/// round-trip** — `CreateFileA`/`WriteFile`/`CloseHandle` then
/// `CreateFileA`/`ReadFile`/`CloseHandle` — through Wine's real kernel32, then
/// exits with a **distinct non-zero code** proving exit-code propagation.
///
/// On the Wine-boot path the program's `CreateFileA` runs Wine's
/// kernelbase `CreateFileA` → `file_name_AtoW` (which reads the TEB
/// `StaticUnicodeString`) → `CreateFileW` → `NtCreateFile`, its `WriteFile`/
/// `ReadFile` run Wine's kernel32 → `NtWriteFile`/`NtReadFile`, and its
/// `ExitProcess(42)` runs Wine's kernel32 → `NtTerminateProcess(42)`. The bytes
/// actually land on the host under `<sandbox>/C/wine-gate.txt`, the read-back
/// matches, and the process exits 42 — end to end through Wine's PE core.
///
/// (No clean 64-bit console corpus binary exercises file I/O — tcc is 32-bit and
/// the rest GUI — so the proof binary is exemu's own generated sample.)
#[test]
fn console_fileio_roundtrips_and_propagates_exit_code_on_wine() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = sample::build_console_fileio();

    // Control — the EMULATED path runs the same program (exemu's own kernel32
    // thunks service CreateFileA/WriteFile/ReadFile/…) in a handful of
    // instructions, proving the program itself is trivial: the round-trip
    // succeeds and it exits with the distinct code 42.
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

    // The GATE — boot Wine's real PE core and run the same file-I/O program on it.
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

    // Exit-code propagation: ExitProcess(42) → Wine kernel32 → NtTerminateProcess.
    assert_eq!(
        wine.exit_code, 42,
        "non-zero exit code propagated through Wine's ExitProcess → NtTerminateProcess"
    );
    // stdout "OK" means CreateFileA + WriteFile + ReadFile all worked through Wine.
    assert!(
        String::from_utf8_lossy(&wine.stdout).contains("OK"),
        "file-I/O round-trip reported OK through Wine's kernel32: {:?}",
        String::from_utf8_lossy(&wine.stdout)
    );
    // The bytes actually landed on the host: read <sandbox>/C/wine-gate.txt.
    let host_file = Path::new(&wine.sandbox).join("C").join("wine-gate.txt");
    let bytes = std::fs::read(&host_file)
        .unwrap_or_else(|e| panic!("host file {host_file:?} should exist: {e}"));
    assert_eq!(
        bytes,
        sample::FILEIO_PAYLOAD,
        "the payload Wine's NtWriteFile committed to disk"
    );
    // The full Wine PE boot ran (orders of magnitude more than the emulated path).
    assert!(
        wine.steps > 100_000,
        "the full Wine PE core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}
