//! **W5.8 — per-exe probes on the WoW64 path.**
//!
//! The two 32-bit corpus binaries booted the way a real 32-bit application has
//! to boot: as a WoW64 process on Wine's 64-bit PE set, with Wine's own i386
//! `ntdll` doing the loading (`wow64_boot::Bringup::WineLoader`, the default).
//! exemu binds **none** of their imports — Wine's 32-bit loader does, which is
//! the whole point of this path.
//!
//! Neither runs to completion, and neither is expected to. These are **honest
//! probes**, in the style of `cab_gate.rs`'s Total Commander pin: an inequality
//! with a wide margin, plus the identity assertions that carry the meaning, and
//! a doc comment naming what moves the numbers. Their value is a measured,
//! attributable starting line — so the next change can say how much further it
//! got instead of guessing.
//!
//! What moves these numbers:
//!
//! * the pinned Wine prefix (**both** halves — a refresh changes the loader
//!   itself, not just the libraries);
//! * how many NT services Wine's 32-bit loader can complete before it stops;
//! * the WoW64 file-system redirector's view of `\windows\system32`, which
//!   decides *which* DLLs the 32-bit loader is handed;
//! * the sandbox contents, because a self-extractor's own file I/O is part of
//!   the count;
//! * `max_steps` — SteamSetup is still running when its budget runs out, so its
//!   number is a floor, not a stopping point.
//!
//! Skip-guarded on the git-ignored corpus and DLL set.

use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_wow64_set() -> bool {
    wow64_boot::Wow64Dirs {
        dir64: Path::new(WINE_DLLS64),
        dir32: Path::new(WINE_DLLS32),
    }
    .complete()
}

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-w5probe-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// How far a corpus binary gets on the WoW64 path.
struct Probe {
    /// Instructions retired before it stopped.
    steps: u64,
    /// Exit code, or the fault's first line + the rip it stopped at.
    outcome: String,
    /// `PEB32.Ldr` after the run — non-zero once Wine's **32-bit** `loader_init`
    /// has published its module list, which is the single cheapest proof that
    /// the i386 loader really ran rather than the process dying before it.
    peb32_ldr: u32,
}

fn probe(path: &str, tag: &str, max_steps: u64) -> Option<Probe> {
    if !have_wow64_set() || !Path::new(path).is_file() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let mut cfg = RunConfig {
        echo: false,
        max_steps,
        args: vec![path.to_string()],
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(tag)),
        ..RunConfig::default()
    };
    let mut p = Process::load(&bytes, &mut cfg).unwrap_or_else(|e| panic!("{tag}: WoW64 boot: {e}"));
    // A WoW64 boot must actually have happened — otherwise the numbers below
    // would be measuring the emulated path by accident.
    let peb32 = p.wow64().expect("a PE32 on the Wine set must boot WoW64").peb32;
    let outcome = match p.run_borrowed() {
        Ok(r) => (r.steps, format!("exit {}", r.exit_code)),
        Err(e) => {
            let report = format!("{e}");
            let steps = report
                .split("faulted after ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let first = report.lines().next().unwrap_or("?").to_string();
            let rip = report
                .split("rip=")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("?")
                .to_string();
            (steps, format!("{first} at rip={rip}"))
        }
    };
    Some(Probe {
        steps: outcome.0,
        outcome: outcome.1,
        peb32_ldr: p.peek_u32(peb32 + exemu_os::wow64::peb32::LDR).unwrap_or(0),
    })
}

/// **`SteamSetup.exe` (32-bit NSIS) on the WoW64 path.**
///
/// Measured 2026-09-06: **7,371,260 instructions, exit code 2 — the guest's
/// own, with zero exceptions delivered.** Wine's i386 `loader_init` binds its
/// whole import graph off the pinned prefix (30 modules, `advapi32` through
/// `shfolder`) and the guest reaches exemu's win32k through `wow64win`'s
/// thunks into the 64-bit `win32u`.
///
/// **It used to fault** at 6,605,667 with a 145-deep exception cascade: exemu
/// seated combase's `OleMainThreadWndClass` procedure — 32-bit code — with the
/// CPU still in long mode (roadmap W5.10). It now declines that callback
/// instead, so the window is created and simply hears no `WM_NCCREATE`/
/// `WM_CREATE`.
///
/// It does **not** reach its nsDialogs installer; that is the W5 GUI gate,
/// still open. The exact count lives in `corpus.toml`
/// (`SteamSetup.exe (wine wow64)`, tolerance 0) measured through the corpus
/// runner's bare `argv[0]`; this probe passes the test's own long relative
/// path, which is worth ~7.6k more instructions of command-line parsing, so it
/// asserts a range rather than a second, conflicting exact number.
#[test]
fn steamsetup_wow64_probe() {
    let Some(p) = probe("../../example_exe/SteamSetup.exe", "steam", 60_000_000) else {
        eprintln!("SKIP: SteamSetup.exe or the pinned Wine WoW64 set is absent (git-ignored)");
        return;
    };
    eprintln!(
        "W5 probe — SteamSetup.exe (WoW64): {} instructions, PEB32.Ldr={:#x}, {}",
        p.steps, p.peb32_ldr, p.outcome,
    );
    assert_ne!(
        p.peb32_ldr, 0,
        "Wine's i386 loader_init published PEB32.Ldr (it really ran) — {}",
        p.outcome,
    );
    // The identity assertion, and the one that regressed for months: the run
    // ends because the guest asked it to, not because it walked off a cliff.
    assert_eq!(
        p.outcome, "exit 2",
        "SteamSetup terminates itself on the WoW64 path; a fault here means the \
         32-bit callback/thread refusals (W5.10/W5.11) stopped holding",
    );
    assert!(
        (5_000_000..20_000_000).contains(&p.steps),
        "SteamSetup should run millions of instructions on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}

/// **`Firefox Installer.exe` (32-bit UPX) on the WoW64 path.**
///
/// Measured 2026-09-06: **12,475,885 instructions, exit code 1 — the guest's
/// own.** The UPX stub self-decompresses, and the inner 7-Zip SFX runs against
/// Wine's `kernel32`/`kernelbase`/`msvcrt`/`user32` far enough to unpack
/// `C:\Temp\7zS00004040`.
///
/// **It used to fault** at 10,950,022 inside `msvcrt!__beginthreadex_trampoline`
/// on its own `push ebp`: a thread exemu spawned with a stack in the *64-bit*
/// `VirtualAlloc` arena at `0x40_0000_0000`, of which 32-bit code sees only
/// `0x0012_fef8` — unmapped. `NtCreateThreadEx` now refuses in a WoW64 process
/// (roadmap W5.11) and `_beginthreadex` takes its error path.
///
/// For scale, the same binary on the **emulated** path is pinned at 4,665,426
/// instructions and faults, so the WoW64 path gets it ~2.7x further with all of
/// the extra work being Wine's own code. Exact count: `corpus.toml`
/// (`Firefox Installer.exe (wine wow64)`, tolerance 0); see the note on the
/// SteamSetup probe above for why this one asserts a range.
#[test]
fn firefox_installer_wow64_probe() {
    let Some(p) = probe("../../example_exe/Firefox Installer.exe", "firefox", 60_000_000) else {
        eprintln!("SKIP: Firefox Installer.exe or the pinned Wine WoW64 set is absent (git-ignored)");
        return;
    };
    eprintln!(
        "W5 probe — Firefox Installer.exe (WoW64): {} instructions, PEB32.Ldr={:#x}, {}",
        p.steps, p.peb32_ldr, p.outcome,
    );
    assert_ne!(
        p.peb32_ldr, 0,
        "Wine's i386 loader_init published PEB32.Ldr (it really ran) — {}",
        p.outcome,
    );
    assert_eq!(
        p.outcome, "exit 1",
        "Firefox Installer terminates itself on the WoW64 path; a fault here means the \
         32-bit callback/thread refusals (W5.10/W5.11) stopped holding",
    );
    assert!(
        (8_000_000..25_000_000).contains(&p.steps),
        "Firefox Installer should get past its UPX stub on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}
