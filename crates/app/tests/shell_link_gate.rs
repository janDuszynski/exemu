//! W6.6 stretch — `IShellLink` through COM.
//!
//! See `exemu_app::shell_link_sample` for exactly what the generated program
//! does and — just as importantly — what it deliberately does not attempt
//! (`SetPath` crashes on a separate, not-yet-identified gap; the module doc
//! there has the full isolation trail).
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, shell_link_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// A private, empty sandbox for one run — see `shell_gate.rs`'s
/// `private_sandbox` for why a shared sandbox would make this fragile.
fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-shelllink-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The control. exemu's own `CoCreateInstance` is an `Unsupported` stub (see
/// `com_gate.rs`): it cannot produce a real `IShellLinkW` object, so the
/// guarded `GetPath` call is skipped and the sample reports exactly one
/// failure (`CREATE`) — never zero. This is what gives the Wine result below
/// its meaning: a pass there cannot be attributed to an exemu thunk.
#[test]
fn emulated_path_cannot_create_a_shell_link() {
    let exe = shell_link_sample::build();
    let r = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 1_000_000,
            sandbox_root: Some(private_sandbox("emulated")),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&r.stdout).into_owned();
    assert_ne!(r.exit_code, 0, "exemu has no native COM, so CoCreateInstance cannot succeed; stdout:\n{stdout}");
}

/// The W6.6 stretch gate: `CoCreateInstance(CLSID_ShellLink, IID_IShellLinkW)`
/// resolves through exemu's registry to **Wine's own shell32.dll**, and a real
/// vtable call (`GetPath`) through the returned interface returns exactly the
/// HRESULT Microsoft's own docs specify for an unset link (`S_FALSE`).
#[test]
fn shell_link_sample_creates_and_calls_getpath_on_wine() {
    if !Path::new(WINE_DLLS).join("shell32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/shell32.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = shell_link_sample::build();
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
    .expect("the shell-link sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("shell-link sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    // Wine's ole32/combase/shell32 stack really booted.
    assert!(run.steps > 1_000_000, "Wine's COM/shell32 stack should really boot, got {} steps", run.steps);

    // CoInitializeEx and CoCreateInstance both returned S_OK.
    assert!(stdout.contains("COINIT=00000000"), "stdout:\n{stdout}");
    assert!(stdout.contains("CREATE=00000000"), "CoCreateInstance(CLSID_ShellLink) should succeed; stdout:\n{stdout}");

    // GetPath, called through the vtable Wine populated, returns S_FALSE
    // (S_OK is also accepted — both are documented non-error outcomes — but
    // S_FALSE is what is actually, deterministically observed): the exact
    // documented answer for "successful call, no path retrieved".
    assert!(
        stdout.contains("GETPATH=00000000") || stdout.contains("GETPATH=00000001"),
        "GetPath should return S_OK or S_FALSE, both documented non-error results; stdout:\n{stdout}"
    );
    // The link has no target, so GetPath must not have written anything.
    assert!(stdout.contains("PATH=\n"), "GetPath on an unset link should report an empty path; stdout:\n{stdout}");

    assert_eq!(run.exit_code, 0, "every step should have held; stdout:\n{stdout}");
}
