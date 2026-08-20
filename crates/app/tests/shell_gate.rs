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

use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, shell_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// A private, empty sandbox for one run.
///
/// The shared `$TMPDIR/exemu-sandbox` persists and accumulates across runs *and*
/// across test binaries, and this gate's result depends on which folders exist —
/// so sharing it makes the assertions read whatever a previous run happened to
/// leave behind. A leftover 7-Zip corpus install already contains
/// `C:\ProgramData\Microsoft\Windows\Start Menu\Programs`, which alone flips one
/// folder from failing to succeeding; that produced a false failure once already.
///
/// The name carries the pid and a counter so parallel test threads never collide.
fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-shell-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

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
            sandbox_root: Some(private_sandbox("emulated")),
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
/// **Both W6.6 gaps are now closed**, by a fix that came from somewhere else
/// entirely (roadmap W7.2). They were:
///
/// 1. **The user component was missing** — Wine returned `C:\users\AppData\Roaming`
///    where the profile is `C:\Users\exemu`, i.e. `…\users\<user>\…` with
///    `<user>` empty.
/// 2. **Five of six calls returned a non-zero HRESULT**, because the directory
///    Wine named did not exist (the sample passes no `CSIDL_FLAG_CREATE`, so
///    `SHGetFolderPath` reports failure for an absent folder while still filling
///    the buffer) — downstream of gap 1.
///
/// The cause was neither the `Shell Folders` seeds nor the folder table: it was
/// that `NtQueryInformationToken` accepted only exemu's own token pseudo-handle
/// and **rejected the constant `(HANDLE)-6`** (`NtCurrentThreadEffectiveToken`),
/// which is what ntdll's `RtlFormatCurrentUserKeyPath` uses. That made
/// `RtlOpenCurrentUser` fail, its caller proceed with an uninitialised root
/// handle, and the whole of `HKEY_CURRENT_USER` — including the `Shell Folders`
/// values exemu had carefully seeded — become unreachable from guest code. With
/// the handle accepted, Wine reads the seeded paths, every folder resolves to
/// `C:\Users\exemu\…`, the directories exemu materialises are the ones Wine
/// names, and all six calls succeed.
///
/// The lesson worth keeping: the failure looked like a *shell32* gap for three
/// separate rounds of work, and the instruction count was the tell — the
/// `Shell Folders` keys, the HKCU namespace fix and the whole token surface each
/// left the run **byte-identical**, proving Wine never executed those paths at
/// all. A change that moves nothing has fixed nothing.
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
            sandbox_root: Some(private_sandbox("wine")),
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

    // The paths are exemu's own profile, user component and all — Wine read them
    // out of the `Shell Folders` values exemu seeds under HKCU, which it can only
    // reach through a working `RtlOpenCurrentUser`.
    assert!(
        stdout.contains("APPDATA=C:\\Users\\exemu\\AppData\\Roaming"),
        "the profile's user component should be present; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("PERSONAL=C:\\Users\\exemu\\Documents"),
        "…for every folder, not just AppData; stdout:\n{stdout}"
    );

    // Every call succeeded: the directory Wine names is now the directory exemu
    // materialises, so no folder is reported absent. The exit code is the
    // sample's own failure count.
    //
    // This count is a function of **which folders exist**, so it is only
    // meaningful against a known-empty sandbox — hence `private_sandbox` above.
    // Sharing `$TMPDIR/exemu-sandbox` made it read whatever a previous run left
    // behind: a leftover 7-Zip corpus install contains
    // `C:\ProgramData\Microsoft\Windows\Start Menu\Programs`, which alone makes
    // COMMONPROGRAMS succeed and cost one engineer a false failure here.
    assert_eq!(
        run.exit_code, 0,
        "every SHGetFolderPathW should now succeed; stdout:\n{stdout}"
    );
}
