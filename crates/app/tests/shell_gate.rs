use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, shell_sample, RunConfig};
use exemu_os::folders;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-shell-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

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

    assert!(
        run.steps > 1_000_000,
        "Wine's shell32 stack should really boot, got {} steps",
        run.steps
    );

    for (tag, csidl) in shell_sample::CSIDLS {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{tag}=")))
            .unwrap_or_else(|| panic!("no {tag} line in:\n{stdout}"));
        let path = &line[tag.len() + 1..];
        let want =
            folders::csidl_path(csidl).unwrap_or_else(|| panic!("{tag} (CSIDL {csidl:#x}) has no folders.rs entry"));
        assert_eq!(path, want, "{tag} resolved to {path:?}, expected folders.rs's {want:?}");
        assert!(!path.contains("\\users\\"), "{tag}={path:?} looks like the old empty-user-component bug");
    }
    assert!(stdout.contains("ROOT=C:\\"), "shlwapi!PathBuildRootW did not run; stdout:\n{stdout}");

    assert!(
        stdout.contains("APPDATA=C:\\Users\\exemu\\AppData\\Roaming"),
        "the profile's user component should be present; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("PERSONAL=C:\\Users\\exemu\\Documents"),
        "…for every folder, not just AppData; stdout:\n{stdout}"
    );

    assert_eq!(
        run.exit_code, 0,
        "every SHGetFolderPathW should now succeed; stdout:\n{stdout}"
    );
}
