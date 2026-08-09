//! W6.6 — known folders through Wine's `shell32.dll` as guest code.
//!
//! The proof binary ([`exemu_app::shell_sample`]) statically imports
//! `shell32!SHGetFolderPathW` and `shlwapi!PathBuildRootW`, so under the Wine
//! boot the loader must map, relocate, bind and `DllMain` **Wine's own**
//! shell32/shlwapi before the entry point. exemu contributes only the guest
//! paths (see `exemu_os::folders`) and the sandbox they land in.
//!
//! The **emulated path is the control**: exemu has no native shell32, so
//! `SHGetFolderPathW` is an unimplemented thunk that returns `S_OK` without
//! touching the caller's buffer. Every folder line comes out empty and the
//! sample exits non-zero. A pass on the Wine path therefore cannot be
//! attributed to an exemu thunk.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;

use exemu_app::{load_and_run, shell_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// The control. exemu's own `SHGetFolderPathW` cannot fill the buffer, so the
/// sample must report failure — this is what gives the Wine result its meaning.
#[test]
fn emulated_path_cannot_resolve_known_folders() {
    let exe = shell_sample::build();
    let r = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&r.stdout).into_owned();
    assert_ne!(
        r.exit_code, 0,
        "exemu has no native shell32, so no folder can resolve; stdout:\n{stdout}"
    );
}

/// The W6.6 gate, asserting what is **actually true today** rather than a hoped-for
/// result.
///
/// Measured: Wine's shell32 boots and resolves every requested `CSIDL` to a
/// well-formed guest path (2.03M guest instructions). So the W6 "arrives free as
/// guest code" claim holds for the *resolution* itself — exemu hand-writes no
/// shell32.
///
/// Two gaps are pinned here so they stay visible rather than being discovered
/// again later:
///
/// 1. **The user component is missing.** Wine returns `C:\users\AppData\Roaming`
///    where the profile is `C:\Users\exemu`, i.e. `…\users\<user>\…` with `<user>`
///    empty. Wine's shell32 builds these from its own notion of the profile
///    directory, which exemu has not seeded — so this is an exemu gap, not a Wine
///    one, and it is what wiring `SHGetFolderPathW` to [`exemu_os::folders`]
///    (whose table already spells the full `C:\Users\exemu\…`) exists to fix.
/// 2. **Five of six calls still return a non-zero HRESULT** — because the
///    directory Wine names does not exist. The sample does not pass
///    `CSIDL_FLAG_CREATE`, so `SHGetFolderPath` reports failure for an absent
///    folder while still filling the buffer. This is now *downstream of* gap 1:
///    exemu materialises the profile tree it models (`C:\Users\exemu\…`), but
///    Wine asks about `C:\users\…`, so only `COMMONPROGRAMS` — the one path both
///    agree on (`C:\ProgramData\…`) — succeeds. Closing gap 1 should close this
///    one with it.
///
/// **Evidence that directory existence is what matters here:** materialising the
/// profile tree moved the run from 2,026,356 to 2,025,637 instructions and the
/// failure count from 6 to 5. Before that, three separate changes (the
/// `Shell Folders` keys, the HKCU namespace fix, the whole token surface) left
/// the count *byte-identical*, proving Wine never executed those paths at all.
/// The instruction count is a free oracle for "did the guest even go there".
///
/// The assertions below therefore check the property that genuinely holds — real
/// guest paths came back from Wine's own code — and pin both gaps by their
/// observable signature, so closing either one fails this test and forces the
/// documentation to be updated with it.
#[test]
fn shell_sample_resolves_known_folders_on_wine() {
    if !Path::new(WINE_DLLS).join("shell32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/shell32.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = shell_sample::build();
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    )
    .expect("the shell sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("shell sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    // Wine's shell32/shlwapi stack really booted — orders of magnitude beyond the
    // emulated control, which cannot resolve anything.
    assert!(
        run.steps > 1_000_000,
        "Wine's shell32 stack should really boot, got {} steps",
        run.steps
    );

    // THE CLAIM: every folder came back as a well-formed guest path, from Wine's
    // own code. exemu implements no shell32.
    for tag in ["APPDATA", "LOCALAPPDATA", "PERSONAL", "DESKTOP", "PROGRAMS", "COMMONPROGRAMS"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{tag}=")))
            .unwrap_or_else(|| panic!("no {tag} line in:\n{stdout}"));
        let path = &line[tag.len() + 1..];
        assert!(path.starts_with("C:\\"), "{tag} resolved to {path:?}, not a C:\\ guest path");
        assert!(path.len() > 4, "{tag} resolved to the bare drive {path:?}");
    }
    // shlwapi's own local code ran too (PathBuildRootW is not one of the Wine-11
    // exports that tail-jump into kernelbase).
    assert!(stdout.contains("ROOT=C:\\"), "shlwapi!PathBuildRootW did not run; stdout:\n{stdout}");

    // GAP 1 — the profile's user component is absent. When this stops being true,
    // this assertion fails and the doc comment above must be updated with it.
    assert!(
        stdout.contains("APPDATA=C:\\users\\AppData"),
        "GAP 1 (missing user component) appears to be FIXED — update this test and \
         the W6.6 notes. stdout:\n{stdout}"
    );

    // GAP 2 — five of six still fail because the directory Wine names does not
    // exist; only COMMONPROGRAMS (C:\ProgramData\…), the one path exemu and Wine
    // agree on, resolves. Closing gap 1 should close this with it.
    assert_eq!(
        run.exit_code, 5,
        "GAP 2 (absent directories) changed — if this dropped, gap 1 may be fixed \
         too and both notes need updating; stdout:\n{stdout}"
    );
}
