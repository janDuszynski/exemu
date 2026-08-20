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
use exemu_os::folders;

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

/// The W6.6 gate, asserting what is **actually true today**: Wine's shell32
/// resolves every requested `CSIDL` to the *correct*, fully-qualified guest
/// path, and the sample exits **0**.
///
/// Measured: **exit 0 after ~2.0M guest instructions**, e.g.
/// `APPDATA=C:\Users\exemu\AppData\Roaming` — matching
/// [`exemu_os::folders::csidl_path`] exactly, capitalisation and all.
///
/// # The two gaps this used to pin, and what actually closed them
///
/// 1. **The profile's user component was missing** —
///    `APPDATA=C:\users\AppData\Roaming` (lowercase `users`, empty `<user>`)
///    instead of `C:\Users\exemu\AppData\Roaming`. Three plausible fixes (the
///    `Shell Folders` registry keys, the HKCU/NT-namespace fold, a first cut of
///    the token surface) each left the instruction count **byte-identical**,
///    proving Wine never executed those paths at all — see
///    `crates/os/src/token.rs`'s module doc and `knowledge/known-issues.know`
///    for the full elimination trail.
///
///    The actual cause, found by disassembling the pinned `shell32.dll`
///    (`SHGetFolderPathAndSubDirW`'s per-CSIDL dispatch → the group-0 handler at
///    a fixed RVA off the DLL's own image base → its registry helper) and then
///    tracing the live syscalls it issues: that helper calls
///    `NtQueryInformationToken` on `NtCurrentThreadEffectiveToken()`
///    (`(HANDLE)-6`, sign-extended to `0xfffffffffffffffa`) to learn the
///    profile's SID **before ever opening a token handle** — a public,
///    documented NT pseudo-handle (`winternl.h`/`processthreadsapi.h`), not a
///    Wine internal. exemu's token surface recognised only the real handle
///    `NtOpenProcessToken` hands out, so this always failed with
///    `STATUS_INVALID_HANDLE`, `HKEY_CURRENT_USER` never resolved, and shell32
///    fell all the way back to `HKEY_LOCAL_MACHINE` (visible live: every
///    registry read in the trace was `HKLM\…`, never `HKCU\…`) and finally to a
///    purely computed default with no user name in it. Fixed in
///    `crates/os/src/token.rs` (`is_current_token_handle`).
/// 2. **The directory Wine named did not exist**, so `SHGetFolderPath` (called
///    without `CSIDL_FLAG_CREATE`) reported failure for 5 of 6 folders even while
///    filling the buffer. This was already known to be *downstream* of gap 1
///    (`crates/app/src/lib.rs` has materialised the full `C:\Users\exemu\…` tree
///    since the W6.6 profile-tree commit) — once Wine asks about the same
///    `C:\Users\exemu\…` tree exemu actually creates, the directories are there
///    and every call succeeds. No separate fix was needed; closing gap 1 closed
///    this one with it, exactly as predicted.
///
/// The assertions below now pin the *fixed* behaviour — exact paths, zero exit —
/// so either gap reopening (a registry/token regression, or the profile tree
/// silently no longer being materialised) fails this test loudly.
///
/// **The same defect was hit again, independently, from the audio side (roadmap
/// W7.2)** — worth recording because it shows how wide the blast radius was.
/// ntdll's own `RtlFormatCurrentUserKeyPath` asks for `TokenUser` on the same
/// `(HANDLE)-6`, so `RtlOpenCurrentUser` failed and *its* caller proceeded with
/// an **uninitialised** root handle. The whole of `HKEY_CURRENT_USER` was
/// therefore unreachable from guest code — including the `Shell Folders` values
/// exemu had carefully seeded. Wine's `mmdevapi` registers each audio endpoint's
/// GUID under HKCU, so every `IMMDevice::Activate` failed with
/// `AUDCLNT_E_DEVICE_INVALIDATED`. One rejected handle constant, two unrelated
/// subsystems broken, both silently.
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

    // THE CLAIM: every folder came back as the exact guest path `folders.rs`
    // models, from Wine's own code — not merely "a well-formed path" (the old,
    // partial pin), but the *same* path exemu's table and the seeded sandbox
    // tree agree on. Cross-checking against `folders::csidl_path` (rather than
    // hand-duplicating the strings here) means the two can never silently drift
    // apart — a table edit that stops matching what the guest resolves fails
    // both this test and `folders.rs`'s own tests.
    for (tag, csidl) in shell_sample::CSIDLS {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{tag}=")))
            .unwrap_or_else(|| panic!("no {tag} line in:\n{stdout}"));
        let path = &line[tag.len() + 1..];
        let want =
            folders::csidl_path(csidl).unwrap_or_else(|| panic!("{tag} (CSIDL {csidl:#x}) has no folders.rs entry"));
        assert_eq!(path, want, "{tag} resolved to {path:?}, expected folders.rs's {want:?}");
        // The historical bug's exact signature: a lowercase, user-less `users`
        // component. Kept as an explicit trap so a regression reads immediately
        // as "the old bug is back", not just "a string mismatch".
        assert!(!path.contains("\\users\\"), "{tag}={path:?} looks like the old empty-user-component bug");
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
