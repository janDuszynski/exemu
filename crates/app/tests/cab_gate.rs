use std::path::{Path, PathBuf};

use exemu_app::{cab, cab_sample, load_and_run, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const TCMD: &str = "../../example_exe/tcmd1156x64.exe";

const ARCHIVED_NAME: &str = "hello.txt";
const PAYLOAD: &[u8] = b"exemu W6.5: these bytes were stored in a real MS-CAB and came back out of Wine's cabinet.dll.";

fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

#[test]
fn emulated_path_cannot_extract_a_cabinet() {
    let exe = cab_sample::build(ARCHIVED_NAME, PAYLOAD);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_ne!(run.exit_code, cab_sample::CAB_OK_EXIT, "stdout:\n{stdout}");
    assert!(
        stdout.contains(cab_sample::FAIL_MESSAGE.trim_end()),
        "the sample should report failure without a cabinet implementation; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, cab_sample::LABEL_FDICREATE),
        "0000000000000000",
        "exemu's FDICreate is an unimplemented thunk; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains(cab_sample::LABEL_FDICOPY),
        "the sample must stop at the null HFDI; stdout:\n{stdout}"
    );
}

#[test]
fn cab_sample_extracts_through_wine_cabinet() {
    if !Path::new(WINE_DLLS).join("cabinet.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/cabinet.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = cab_sample::build(ARCHIVED_NAME, PAYLOAD);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    )
    .expect("the CAB sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("cab sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    assert!(run.steps > 500_000, "expected a real Wine boot, got {} steps", run.steps);

    assert_ne!(
        line(&stdout, cab_sample::LABEL_FDICREATE),
        "0000000000000000",
        "FDICreate did not return an HFDI; stdout:\n{stdout}"
    );

    assert_eq!(
        line(&stdout, cab_sample::LABEL_SETID),
        format!("{:016x}", cab::CAB_SET_ID),
        "FDIIsCabinet's setID should be the one build_cab stamped; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, cab_sample::LABEL_CFILES),
        "0000000000000001",
        "the archive holds exactly one file; stdout:\n{stdout}"
    );

    assert_ne!(
        line(&stdout, cab_sample::LABEL_FDICOPY),
        "0000000000000000",
        "FDICopy failed; stdout:\n{stdout}"
    );
    assert_eq!(line(&stdout, cab_sample::LABEL_NAME), ARCHIVED_NAME);

    assert_eq!(
        line(&stdout, cab_sample::LABEL_LEN),
        format!("{:016x}", PAYLOAD.len()),
        "the extracted length; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, cab_sample::LABEL_DATA).as_bytes(),
        PAYLOAD,
        "the extracted bytes; stdout:\n{stdout}"
    );

    assert!(stdout.contains(cab_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(run.exit_code, cab_sample::CAB_OK_EXIT, "stdout:\n{stdout}");
}

fn prefix_without(dir: &Path, omit: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let src = std::fs::canonicalize(WINE_DLLS)?;
    for entry in std::fs::read_dir(&src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().eq_ignore_ascii_case(omit) {
            continue;
        }
        let link = dir.join(&name);
        if !link.exists() {
            std::os::unix::fs::symlink(entry.path(), link)?;
        }
    }
    assert!(!dir.join(omit).exists(), "{omit} must be absent from the mirror");
    Ok(())
}

fn run_steps(exe: &[u8], wine_dir: Option<String>, max_steps: u64) -> (i32, u64) {
    let r = load_and_run(
        exe,
        RunConfig {
            echo: false,
            max_steps,
            wine_boot_dir: wine_dir,
            ..RunConfig::default()
        },
    )
    .expect("tcmd should run to a deliberate exit, not fault");
    (r.exit_code, r.steps)
}

#[test]
fn total_commander_loads_wine_cabinet_but_still_exits_early() {
    if !Path::new(TCMD).exists() || !Path::new(WINE_DLLS).join("cabinet.dll").exists() {
        eprintln!("SKIP: {TCMD} / the Wine DLL set not present (both are git-ignored)");
        return;
    }
    let exe = std::fs::read(TCMD).expect("read the pinned Total Commander binary");

    let (emu_code, emu_steps) = run_steps(&exe, None, 5_000_000);
    eprintln!("tcmd emulated:            exit {emu_code} after {emu_steps} steps");
    assert!(emu_steps < 100_000, "the emulated path should stop early, got {emu_steps}");

    let (wine_code, wine_steps) = run_steps(&exe, Some(WINE_DLLS.to_string()), 50_000_000);
    eprintln!("tcmd wine-boot:           exit {wine_code} after {wine_steps} steps");
    assert!(
        wine_steps > 3_000_000,
        "the Wine boot should carry tcmd millions of instructions in, got {wine_steps}"
    );
    assert!(wine_steps > emu_steps * 100, "{wine_steps} vs {emu_steps} emulated");

    let mirror: PathBuf = std::env::temp_dir().join(format!("exemu-w65-nocab-{}", std::process::id()));
    prefix_without(&mirror, "cabinet.dll").expect("mirror the prefix without cabinet.dll");
    let (nocab_code, nocab_steps) = run_steps(&exe, Some(mirror.to_string_lossy().into_owned()), 50_000_000);
    let _ = std::fs::remove_dir_all(&mirror);
    eprintln!("tcmd wine-boot, no cabinet: exit {nocab_code} after {nocab_steps} steps");

    assert!(
        wine_steps > nocab_steps + 100_000,
        "removing cabinet.dll should cost real startup work: {wine_steps} with it, \
         {nocab_steps} without — if these converge, cabinet.dll is not being loaded"
    );

    assert_eq!(wine_code, 1, "tcmd still exits 1 on the Wine boot");
    assert_eq!(nocab_code, 1, "…and exits 1 without cabinet.dll too");
}
