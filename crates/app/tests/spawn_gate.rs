use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, spawn_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const CHILD_GUEST_PATH: &str = "C:\\exemu-child.exe";

fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

fn sandbox_with_child(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-w35-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C")).expect("create the guest C: root");
    std::fs::write(dir.join("C").join("exemu-child.exe"), spawn_sample::build_child())
        .expect("stage the child binary in the sandbox");
    dir
}

fn assert_spawn_succeeded(stdout: &str, exit_code: i32) {
    assert_eq!(line(stdout, spawn_sample::LABEL_CREATED), "0000000000000001", "stdout:\n{stdout}");
    let pid = u64::from_str_radix(line(stdout, spawn_sample::LABEL_PID), 16).expect("PID is hex");
    assert!(pid != 0, "PROCESS_INFORMATION.dwProcessId was zero; stdout:\n{stdout}");
    assert_ne!(pid, 0x1000, "the child must not report the parent's own pid; stdout:\n{stdout}");

    assert_eq!(line(stdout, spawn_sample::LABEL_WAIT), "0000000000000000", "stdout:\n{stdout}");
    assert_eq!(line(stdout, spawn_sample::LABEL_GETEXIT), "0000000000000001", "stdout:\n{stdout}");
    assert_eq!(
        line(stdout, spawn_sample::LABEL_CHILDEXIT),
        format!("{:016x}", spawn_sample::CHILD_EXIT),
        "the child's exit code did not survive the round trip; stdout:\n{stdout}"
    );

    assert!(
        stdout.contains(spawn_sample::CHILD_MESSAGE.trim_end()),
        "the child's own output is missing; stdout:\n{stdout}"
    );
    let child_at = stdout.find(spawn_sample::CHILD_MESSAGE.trim_end()).unwrap();
    let created_at = stdout.find(spawn_sample::LABEL_CREATED).unwrap();
    assert!(
        child_at < created_at,
        "W3.5's child runs synchronously inside CreateProcessW; stdout:\n{stdout}"
    );

    assert!(stdout.contains(spawn_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(exit_code, spawn_sample::PARENT_OK_EXIT, "stdout:\n{stdout}");
}

fn assert_one_child(run: &exemu_app::RunResult) {
    assert_eq!(run.children_created, 1, "exactly one child process was created");
}

#[test]
fn parent_spawns_child_through_wine_kernel32() {
    if !Path::new(WINE_DLLS).join("kernelbase.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/kernelbase.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let sandbox = sandbox_with_child("wine");
    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(sandbox),
            ..RunConfig::default()
        },
    )
    .expect("the spawn sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("spawn sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    assert!(run.steps > 500_000, "expected a real Wine boot, got {} steps", run.steps);

    assert_spawn_succeeded(&stdout, run.exit_code);
    assert_one_child(&run);
}

#[test]
fn parent_spawns_child_on_the_emulated_path() {
    let sandbox = sandbox_with_child("emulated");
    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            sandbox_root: Some(sandbox),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("spawn sample emulated: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);
    assert_spawn_succeeded(&stdout, run.exit_code);
    assert_one_child(&run);
}

#[test]
fn a_missing_child_fails_the_create_rather_than_faking_it() {
    let dir = std::env::temp_dir().join(format!("exemu-w35-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C")).unwrap();

    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            sandbox_root: Some(dir.clone()),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();

    assert_eq!(
        line(&stdout, spawn_sample::LABEL_CREATED),
        "0000000000000000",
        "CreateProcessW must fail for a missing image; stdout:\n{stdout}"
    );
    assert!(stdout.contains(spawn_sample::FAIL_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_ne!(run.exit_code, spawn_sample::PARENT_OK_EXIT);
    assert!(
        !stdout.contains(spawn_sample::CHILD_MESSAGE.trim_end()),
        "nothing should have run; stdout:\n{stdout}"
    );
    assert_eq!(run.children_created, 0, "a refused create must leave no process behind");
    let _ = std::fs::remove_dir_all(&dir);
}

const TCMD: &str = "../../example_exe/tcmd1156x64.exe";
const STEAM: &str = "../../example_exe/SteamSetup.exe";

#[test]
fn total_commander_still_never_reaches_child_creation() {
    if !Path::new(TCMD).exists() {
        eprintln!("SKIP: {TCMD} not present (git-ignored)");
        return;
    }
    let exe = std::fs::read(TCMD).expect("read the pinned Total Commander binary");

    let run = |tag: &str, wine: Option<String>| {
        let dir = std::env::temp_dir()
            .join(format!("exemu-w35-probe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let r = load_and_run(
            &exe,
            RunConfig {
                echo: false,
                max_steps: 50_000_000,
                wine_boot_dir: wine,
                sandbox_root: Some(dir.clone()),
                ..RunConfig::default()
            },
        )
        .expect("tcmd should run to a deliberate exit, not fault");
        let _ = std::fs::remove_dir_all(&dir);
        r
    };

    let emu = run("tcmd-emu", None);
    eprintln!(
        "tcmd emulated:  exit {} after {} steps, {} children",
        emu.exit_code, emu.steps, emu.children_created
    );
    assert!(emu.steps < 100_000, "the emulated path should stop early, got {}", emu.steps);
    assert_eq!(emu.exit_code, 1, "tcmd still exits 1 on the emulated path");
    assert_eq!(emu.children_created, 0, "tcmd never reaches CreateProcess on the emulated path");

    if !Path::new(WINE_DLLS).join("kernelbase.dll").exists() {
        eprintln!("SKIP (Wine half): {WINE_DLLS} not present");
        return;
    }
    let wine = run("tcmd-wine", Some(WINE_DLLS.to_string()));
    eprintln!(
        "tcmd wine-boot: exit {} after {} steps, {} children",
        wine.exit_code, wine.steps, wine.children_created
    );
    assert!(
        wine.steps > 2_000_000 && wine.steps < 10_000_000,
        "the Wine boot should still carry tcmd into the millions, got {}",
        wine.steps
    );
    assert!(wine.steps > emu.steps * 100, "{} vs {} emulated", wine.steps, emu.steps);
    assert_eq!(wine.exit_code, 1, "tcmd still exits 1 on the Wine boot");
    assert_eq!(
        wine.children_created, 0,
        "tcmd never reaches CreateProcess on the Wine boot either — W3.5 does not \
         unblock it, and the day it does, this assertion is what says so"
    );
}

#[test]
fn steam_setup_cannot_reach_wine_child_creation_because_it_is_32_bit() {
    if !Path::new(STEAM).exists() {
        eprintln!("SKIP: {STEAM} not present (git-ignored)");
        return;
    }
    let bytes = std::fs::read(STEAM).expect("read the pinned SteamSetup binary");
    let image = exemu_loader::parse(&bytes).expect("SteamSetup parses as a PE");
    assert!(
        !image.is_64bit,
        "SteamSetup is a PE32 — if this ever becomes a 64-bit image the reasoning \
         above no longer holds"
    );
    let imports_create_process = image.imports.iter().any(|i| {
        matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n.starts_with("CreateProcess"))
    });
    assert!(
        imports_create_process,
        "SteamSetup imports CreateProcess* — the reason it is a W3.5 target at all"
    );
}
