//! W6.5 — **CAB extraction through Wine's `cabinet.dll` as guest code**.
//!
//! The proof binary ([`exemu_app::cab_sample`]) statically imports
//! `cabinet!FDICreate`/`FDIIsCabinet`/`FDICopy`/`FDIDestroy`, so under the Wine
//! boot the loader must map, relocate, bind and `DllMain` **Wine's own
//! cabinet.dll** before the entry point runs. The archive it extracts is
//! generated at test time by [`exemu_app::cab`] — a *writer* only, so exemu can
//! state what the bytes are without owning a decoder.
//!
//! Two things make the result attributable to Wine and nothing else:
//!
//! 1. **exemu has no cabinet decoder, native or emulated.** On the emulated path
//!    `FDICreate` is an unimplemented thunk returning 0, so the sample reports
//!    `CAB FAIL` and exits non-zero. That is the control below, and it is what
//!    gives the Wine result its meaning.
//! 2. **`FDI` is a callback API.** `FDICreate` takes seven guest function
//!    pointers (alloc/free/open/read/write/close/seek) and `FDICopy` a
//!    notification callback, and Wine's decoder drives the whole extraction
//!    through them. So the archive's bytes travel *out of the guest's `.rdata`,
//!    into Wine's decoder, and back into the guest's `.data`* — Wine's guest code
//!    calling back into the emulated program's own guest code across the Win64
//!    ABI, dozens of times, with no host code in the loop at all.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::{Path, PathBuf};

use exemu_app::{cab, cab_sample, load_and_run, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// The W6.5 per-exe pin: Total Commander, which loads `cabinet.dll` during
/// startup.
const TCMD: &str = "../../example_exe/tcmd1156x64.exe";

/// The archived name and contents the generated cabinet carries. The payload is
/// printable so the extracted bytes can be asserted straight out of stdout, and
/// deliberately longer than the `CFFILE`/`CFDATA` headers so a decoder that
/// merely echoed a header could not produce it.
const ARCHIVED_NAME: &str = "hello.txt";
const PAYLOAD: &[u8] = b"exemu W6.5: these bytes were stored in a real MS-CAB and came back out of Wine's cabinet.dll.";

/// Read a `LABEL=` line out of the sample's stdout.
fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

/// The control: exemu implements no cabinet API, so the sample cannot extract
/// anything and says so. Without this, a pass on the Wine path could just be an
/// exemu thunk being helpful.
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
    // Specifically: FDICreate never produced an HFDI, so nothing downstream ran.
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

/// The W6.5 gate: Wine's `cabinet.dll` extracts the generated archive, calling
/// back into the guest's own code for every byte of I/O.
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

    // Wine's cabinet stack really booted. Measured: ~813k guest instructions —
    // an order of magnitude past the emulated control (~10k), but well *below*
    // the shell32/ole32 gates' millions, because cabinet.dll's whole dependency
    // set is kernel32 + ntdll + ucrtbase. Decoding is cheap; the DLL is small.
    assert!(run.steps > 500_000, "expected a real Wine boot, got {} steps", run.steps);

    // FDICreate returned a live HFDI out of the guest's own bump allocator.
    assert_ne!(
        line(&stdout, cab_sample::LABEL_FDICREATE),
        "0000000000000000",
        "FDICreate did not return an HFDI; stdout:\n{stdout}"
    );

    // FDIIsCabinet parsed the CFHEADER this repository generated: the setID and
    // file count come straight out of `cab::build_cab`'s bytes, so matching them
    // proves Wine read *our* archive rather than reporting defaults.
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

    // FDICopy succeeded, and the notification callback got the archived name.
    assert_ne!(
        line(&stdout, cab_sample::LABEL_FDICOPY),
        "0000000000000000",
        "FDICopy failed; stdout:\n{stdout}"
    );
    assert_eq!(line(&stdout, cab_sample::LABEL_NAME), ARCHIVED_NAME);

    // THE CLAIM: the extracted bytes are the payload, byte for byte.
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

    // The guest verified the same thing itself (length, bytes and archived name)
    // and said so with its distinguishing exit code.
    assert!(stdout.contains(cab_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(run.exit_code, cab_sample::CAB_OK_EXIT, "stdout:\n{stdout}");
}

// ==========================================================================
// The W6.5 per-exe pin: Total Commander
// ==========================================================================

/// Mirror the pinned prefix into `dir` as symlinks, **omitting** `omit`.
///
/// This is the control that turns "the app ran longer" into "the app loaded
/// cabinet.dll": the two runs differ in exactly one file.
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

/// Run `exe` and return `(exit_code, steps)`, treating a fault as a failure —
/// this probe is about *where a real binary gets to*, so a fault must be loud.
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

/// W6.5's per-exe pin, asserting **what is actually true today**.
///
/// Measured by this test:
///
/// | run | instructions | exit |
/// | --- | --- | --- |
/// | emulated (no Wine) | 22,033 | 1 |
/// | Wine boot, prefix **without** cabinet.dll | 3,569,341 | 1 |
/// | Wine boot, full prefix | 4,057,410 | 1 |
///
/// The totals move a little with the command line, the build profile and what
/// exemu has seeded into the sandbox (the release CLI, with a different argv,
/// gives 25,553 / 4,082,535 / 3,542,988) — which is why every assertion below
/// is an inequality with a wide margin rather than an equality.
///
/// What that establishes:
///
/// * **`cabinet.dll` is no longer the wall.** The emulated path dies in the
///   opening ~22k instructions; under the Wine boot the same binary runs ~180x
///   further and terminates by calling `ExitProcess` itself (the innermost frame
///   is `ntdll!RtlExitUserProcess`) — not a fault, not a decoder gap, not the
///   step budget.
/// * **cabinet.dll really loads and really runs.** Deleting that one file from
///   the prefix costs half a million instructions of startup work (488k–540k
///   across the profiles measured), the same order as the whole cabinet-sample
///   boot above (~813k). A run that merely *failed* to find the DLL could not
///   spend them.
///
/// **What it does NOT establish, and this is the honest gap:** Total Commander
/// still exits 1 from its own startup path, with or without cabinet.dll. So the
/// remaining blocker is downstream of W6.5 entirely — it is not CAB support.
/// Nothing here has been forced to make the app "work"; the numbers are pinned
/// as they are so that when the real blocker is fixed, this test fails and says
/// so.
#[test]
fn total_commander_loads_wine_cabinet_but_still_exits_early() {
    if !Path::new(TCMD).exists() || !Path::new(WINE_DLLS).join("cabinet.dll").exists() {
        eprintln!("SKIP: {TCMD} / the Wine DLL set not present (both are git-ignored)");
        return;
    }
    let exe = std::fs::read(TCMD).expect("read the pinned Total Commander binary");

    // The emulated path barely starts: exemu has no cabinet.dll (nor most of
    // what this app imports), so it gives up in the opening instructions.
    let (emu_code, emu_steps) = run_steps(&exe, None, 5_000_000);
    eprintln!("tcmd emulated:            exit {emu_code} after {emu_steps} steps");
    assert!(emu_steps < 100_000, "the emulated path should stop early, got {emu_steps}");

    // The Wine boot carries it two orders of magnitude further, to a deliberate
    // exit rather than a fault.
    let (wine_code, wine_steps) = run_steps(&exe, Some(WINE_DLLS.to_string()), 50_000_000);
    eprintln!("tcmd wine-boot:           exit {wine_code} after {wine_steps} steps");
    assert!(
        wine_steps > 3_500_000,
        "the Wine boot should carry tcmd millions of instructions in, got {wine_steps}"
    );
    assert!(wine_steps > emu_steps * 100, "{wine_steps} vs {emu_steps} emulated");

    // THE DIFFERENTIAL: the same run against a prefix that differs in exactly
    // one file. If cabinet.dll were merely *present* and never loaded, removing
    // it could not change the instruction count.
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

    // THE GAP, pinned so that fixing it fails here and forces the notes to be
    // updated: the app still exits 1 from its own startup, cabinet or no
    // cabinet. Whatever blocks Total Commander is not CAB support.
    assert_eq!(wine_code, 1, "tcmd still exits 1 on the Wine boot");
    assert_eq!(nocab_code, 1, "…and exits 1 without cabinet.dll too");
}
