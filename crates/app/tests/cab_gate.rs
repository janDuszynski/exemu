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

use std::path::Path;

use exemu_app::{cab, cab_sample, load_and_run, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

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
