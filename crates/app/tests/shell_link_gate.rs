use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, shell_link_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-shelllink-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn host_path(sandbox: &Path, guest: &str) -> PathBuf {
    let rest = guest.strip_prefix("C:\\").expect("a C: guest path");
    let mut p = sandbox.join("C");
    for part in rest.split('\\') {
        p = p.join(part);
    }
    p
}

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

#[test]
fn shell_link_sample_writes_a_start_menu_shortcut_on_wine() {
    if !Path::new(WINE_DLLS).join("shell32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/shell32.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let sandbox = private_sandbox("wine");
    let exe = shell_link_sample::build();
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(sandbox.clone()),
            ..RunConfig::default()
        },
    )
    .expect("the shell-link sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("shell-link sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    assert!(run.steps > 1_000_000, "Wine's COM/shell32 stack should really boot, got {} steps", run.steps);

    assert!(stdout.contains("COINIT=00000000"), "stdout:\n{stdout}");
    assert!(stdout.contains("CREATE=00000000"), "CoCreateInstance(CLSID_ShellLink) should succeed; stdout:\n{stdout}");

    assert!(
        stdout.contains("GETPATH=00000000") || stdout.contains("GETPATH=00000001"),
        "GetPath should return S_OK or S_FALSE, both documented non-error results; stdout:\n{stdout}"
    );
    assert!(stdout.contains("PATH=\n"), "GetPath on an unset link should report an empty path; stdout:\n{stdout}");

    assert!(stdout.contains("SETPATH=00000000"), "IShellLinkW::SetPath should return S_OK; stdout:\n{stdout}");
    assert!(stdout.contains("GETPATH2=00000000"), "GetPath after SetPath should return S_OK; stdout:\n{stdout}");
    assert!(
        stdout.contains(&format!("PATH2={}\n", shell_link_sample::TARGET_PATH)),
        "the link should report back exactly the target SetPath was given; stdout:\n{stdout}"
    );

    assert!(stdout.contains("QIPERSIST=00000000"), "QueryInterface(IID_IPersistFile) should succeed; stdout:\n{stdout}");
    assert!(stdout.contains("SAVE=00000000"), "IPersistFile::Save should return S_OK; stdout:\n{stdout}");
    assert_eq!(run.exit_code, 0, "every step should have held; stdout:\n{stdout}");

    let programs = exemu_os::folders::csidl_path(exemu_os::folders::csidl::PROGRAMS).expect("CSIDL_PROGRAMS is in the table");
    assert!(
        shell_link_sample::LNK_PATH.starts_with(&format!("{programs}\\")),
        "the sample writes into CSIDL_PROGRAMS ({programs}), got {}",
        shell_link_sample::LNK_PATH
    );

    let lnk = host_path(&sandbox, shell_link_sample::LNK_PATH);
    let b = std::fs::read(&lnk).unwrap_or_else(|e| panic!("no .lnk written at {}: {e}", lnk.display()));
    let u32_at = |off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;

    assert!(b.len() > 0x4C, "a shell link is at least its 0x4C-byte header, got {}", b.len());
    assert_eq!(u32_at(0), 0x4C, "MS-SHLLINK HeaderSize = 0x4C");
    assert_eq!(&b[4..20], &shell_link_sample::CLSID_SHELL_LINK, "MS-SHLLINK LinkCLSID = CLSID_ShellLink");
    let link_flags = u32_at(0x14);
    assert_ne!(link_flags & 0x02, 0, "LinkFlags.HasLinkInfo — the target is recorded ({link_flags:#x})");
    assert_eq!(u32_at(0x3C), 1, "ShowCommand = SW_SHOWNORMAL");

    assert_ne!(
        link_flags & 0x01,
        0,
        "LinkFlags.HasLinkTargetIDList — the shell-namespace walk resolved the target ({link_flags:#x})",
    );
    let idlist_size = u16::from_le_bytes(b[0x4C..0x4E].try_into().unwrap()) as usize;
    assert!(idlist_size > 0, "IDListSize");
    let idlist = &b[0x4E..0x4E + idlist_size];
    for want in ["windows", "system32", "notepad.exe"] {
        assert!(
            idlist.windows(want.len()).any(|w| w.eq_ignore_ascii_case(want.as_bytes())),
            "the PIDL names {want} — it was built by walking the sandbox with Wine's own \
             FindFirstFileW, so an empty directory enumeration cannot produce it",
        );
    }

    let li = 0x4Eusize + idlist_size;
    assert!(li + u32_at(li) <= b.len(), "LinkInfoSize fits the file");
    assert_ne!(u32_at(li + 0x08) & 0x01, 0, "LinkInfoFlags.VolumeIDAndLocalBasePath");
    let base = li + u32_at(li + 0x10);
    let end = b[base..].iter().position(|&c| c == 0).expect("LocalBasePath is NUL-terminated") + base;
    let target = std::str::from_utf8(&b[base..end]).expect("LocalBasePath is ASCII here");
    assert_eq!(target, shell_link_sample::TARGET_PATH, "the .lnk records the target SetPath was given");

    let _ = std::fs::remove_dir_all(&sandbox);
}
