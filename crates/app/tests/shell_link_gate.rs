//! W6.6 — the **start-menu shortcut**, end to end, through Wine's shell32.
//!
//! See [`exemu_app::shell_link_sample`] for exactly what the generated program
//! does — and for the account of the NLS case-table bug that made `SetPath`
//! fault at `0xBC` until it was fixed.
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

/// Map a guest `C:\…` path onto its host location under `sandbox`, the way the
/// sandbox lays the guest drive out.
fn host_path(sandbox: &Path, guest: &str) -> PathBuf {
    let rest = guest.strip_prefix("C:\\").expect("a C: guest path");
    let mut p = sandbox.join("C");
    for part in rest.split('\\') {
        p = p.join(part);
    }
    p
}

/// The control. exemu's own `CoCreateInstance` is an `Unsupported` stub (see
/// `com_gate.rs`): it cannot produce a real `IShellLinkW` object, so every
/// guarded step is skipped and the sample reports failures — never zero. This
/// is what gives the Wine result below its meaning: a pass there cannot be
/// attributed to an exemu thunk.
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

/// The W6.6 shortcut gate: `CoCreateInstance(CLSID_ShellLink, IID_IShellLinkW)`
/// resolves through exemu's registry to **Wine's own shell32.dll**, `SetPath`
/// records a target, `QueryInterface(IID_IPersistFile)` returns the object's
/// persistence interface, and `IPersistFile::Save` writes a **real `.lnk` file**
/// into the sandboxed `CSIDL_PROGRAMS` folder — which this test then reads back.
///
/// Everything above the sandbox is Wine's code: exemu implements no COM, no
/// shell namespace, and no `.lnk` serializer.
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

    // Wine's ole32/combase/shell32 stack really booted.
    assert!(run.steps > 1_000_000, "Wine's COM/shell32 stack should really boot, got {} steps", run.steps);

    // CoInitializeEx and CoCreateInstance both returned S_OK.
    assert!(stdout.contains("COINIT=00000000"), "stdout:\n{stdout}");
    assert!(stdout.contains("CREATE=00000000"), "CoCreateInstance(CLSID_ShellLink) should succeed; stdout:\n{stdout}");

    // GetPath on the pristine link returns S_FALSE — the exact HRESULT
    // Microsoft documents for "successful call, no path retrieved" — with an
    // empty buffer. (S_OK is accepted too; S_FALSE is what is observed.)
    assert!(
        stdout.contains("GETPATH=00000000") || stdout.contains("GETPATH=00000001"),
        "GetPath should return S_OK or S_FALSE, both documented non-error results; stdout:\n{stdout}"
    );
    assert!(stdout.contains("PATH=\n"), "GetPath on an unset link should report an empty path; stdout:\n{stdout}");

    // SetPath stored the target, and GetPath hands it back — the round trip is
    // what proves SetPath did something rather than merely returning S_OK.
    assert!(stdout.contains("SETPATH=00000000"), "IShellLinkW::SetPath should return S_OK; stdout:\n{stdout}");
    assert!(stdout.contains("GETPATH2=00000000"), "GetPath after SetPath should return S_OK; stdout:\n{stdout}");
    assert!(
        stdout.contains(&format!("PATH2={}\n", shell_link_sample::TARGET_PATH)),
        "the link should report back exactly the target SetPath was given; stdout:\n{stdout}"
    );

    // The same object hands out its IPersistFile, and Save writes the file.
    assert!(stdout.contains("QIPERSIST=00000000"), "QueryInterface(IID_IPersistFile) should succeed; stdout:\n{stdout}");
    assert!(stdout.contains("SAVE=00000000"), "IPersistFile::Save should return S_OK; stdout:\n{stdout}");
    assert_eq!(run.exit_code, 0, "every step should have held; stdout:\n{stdout}");

    // The shortcut path the sample hard-codes is the folder table's own
    // CSIDL_PROGRAMS, so the two cannot drift apart silently.
    let programs = exemu_os::folders::csidl_path(exemu_os::folders::csidl::PROGRAMS).expect("CSIDL_PROGRAMS is in the table");
    assert!(
        shell_link_sample::LNK_PATH.starts_with(&format!("{programs}\\")),
        "the sample writes into CSIDL_PROGRAMS ({programs}), got {}",
        shell_link_sample::LNK_PATH
    );

    // THE CLAIM: a real .lnk file exists in the sandbox, written by Wine's own
    // IPersistFile::Save. Read it back and walk it as the format Microsoft
    // publishes (MS-SHLLINK) — exemu has no .lnk serializer of any kind, so
    // every byte below came out of Wine's shell32.
    let lnk = host_path(&sandbox, shell_link_sample::LNK_PATH);
    let b = std::fs::read(&lnk).unwrap_or_else(|e| panic!("no .lnk written at {}: {e}", lnk.display()));
    let u32_at = |off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;

    // ShellLinkHeader: a fixed 0x4C bytes whose LinkCLSID is
    // {00021401-0000-0000-C000-000000000046} — the same CLSID the sample handed
    // CoCreateInstance.
    assert!(b.len() > 0x4C, "a shell link is at least its 0x4C-byte header, got {}", b.len());
    assert_eq!(u32_at(0), 0x4C, "MS-SHLLINK HeaderSize = 0x4C");
    assert_eq!(&b[4..20], &shell_link_sample::CLSID_SHELL_LINK, "MS-SHLLINK LinkCLSID = CLSID_ShellLink");
    let link_flags = u32_at(0x14);
    assert_ne!(link_flags & 0x02, 0, "LinkFlags.HasLinkInfo — the target is recorded ({link_flags:#x})");
    assert_eq!(u32_at(0x3C), 1, "ShowCommand = SW_SHOWNORMAL");

    // LinkInfo (present because HasLinkInfo is set), starting right after the
    // header. Its LocalBasePath is a NUL-terminated *ANSI* string at
    // `LinkInfo + LocalBasePathOffset`, and it must be exactly the target the
    // sample gave SetPath — a full round trip: guest string → Wine's shell link
    // object → a file on disk → back out here.
    let li = 0x4Cusize;
    assert!(li + u32_at(li) <= b.len(), "LinkInfoSize fits the file");
    assert_ne!(u32_at(li + 0x08) & 0x01, 0, "LinkInfoFlags.VolumeIDAndLocalBasePath");
    let base = li + u32_at(li + 0x10); // LocalBasePathOffset
    let end = b[base..].iter().position(|&c| c == 0).expect("LocalBasePath is NUL-terminated") + base;
    let target = std::str::from_utf8(&b[base..end]).expect("LocalBasePath is ASCII here");
    assert_eq!(target, shell_link_sample::TARGET_PATH, "the .lnk records the target SetPath was given");

    // PINNED GAP: no `LinkTargetIDList`. Real Windows also stores the target as
    // a PIDL (LinkFlags bit 0), which `SetPath` builds by walking the shell
    // namespace — `SHGetDesktopFolder` → `IShellFolder::ParseDisplayName`. That
    // walk does not produce one here, so the shortcut resolves by path only.
    // When this starts holding, this assertion fails and the docs must say so.
    assert_eq!(link_flags & 0x01, 0, "GAP (no shell-namespace PIDL) appears to be FIXED — update this test and the W6.6 notes; LinkFlags={link_flags:#x}");

    let _ = std::fs::remove_dir_all(&sandbox);
}
