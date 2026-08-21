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
/// Measured 2026-08-21: **~6.6M instructions**, then a fault inside the 64-bit
/// `ntdll` with `rsp` off the bottom of the 32-bit stack.
///
/// **The previous "still running at 60M" reading was not progress.** With
/// `EXEMU_DBG=1` the run showed one real fault at ~5.0M followed by 82
/// `0x80000003` breakpoints, all at the identical address
/// `ntdll!KiUserExceptionDispatcher+0x2a` — the `int3` Wine puts *after* its
/// unreachable `call dispatch_exception`. The remaining 595M instructions were
/// that livelock, not the installer.
///
/// What moved it forward: `wow64win.dll`'s 477 `win32u.dll` imports are now
/// bound (roadmap W5.8). Before that, the first win32k call a GUI guest makes —
/// `NtUserInitializeClientPfnArrays`, from user32's own `DllMain` — jumped
/// through an unbound IAT slot into the ASCII of its own name. The visible
/// effect is the module count: the 32-bit loader now gets **30** modules in,
/// including `imm32`, `uxtheme`, `oleaut32`, `propsys` and `setupapi`, where it
/// used to stop at 20.
///
/// For scale, the same binary on the **emulated** path is pinned at 92,865,377
/// instructions and faults (`corpus.toml`) — but that is a different program:
/// there NSIS runs against exemu's hand-written Win32, here it runs against
/// Wine's. It does **not** reach its nsDialogs installer; that is the W5 gate,
/// still open.
#[test]
fn steamsetup_wow64_probe() {
    let Some(p) = probe("../../example_exe/SteamSetup.exe", "steam", 60_000_000) else {
        eprintln!("SKIP: SteamSetup.exe or the pinned Wine WoW64 set is absent (git-ignored)");
        return;
    };
    eprintln!(
        "W5.8 probe — SteamSetup.exe (WoW64): {} instructions, PEB32.Ldr={:#x}, {}",
        p.steps, p.peb32_ldr, p.outcome,
    );
    assert_ne!(
        p.peb32_ldr, 0,
        "Wine's i386 loader_init published PEB32.Ldr (it really ran) — {}",
        p.outcome,
    );
    assert!(
        p.steps > 5_000_000,
        "SteamSetup should run millions of instructions on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}

/// **`Firefox Installer.exe` (32-bit UPX) on the WoW64 path.**
///
/// Measured: **11,462,340 instructions**, then an unmapped read at `0x12fef4`
/// with `rip` at `0xcc1c70` — an address that is neither in the 32-bit `ntdll`
/// (mapped at 0x6000_0000) nor in the packed stub's own image, i.e. the UPX
/// stub has already unpacked and the *inner* program is running against
/// Wine's 32-bit DLLs.
///
/// For scale, the same binary on the **emulated** path is pinned at 4,665,426
/// instructions (`corpus.toml`) — so the WoW64 path currently gets it ~2.5×
/// further, with all of the extra work being Wine's own code.
#[test]
fn firefox_installer_wow64_probe() {
    let Some(p) = probe("../../example_exe/Firefox Installer.exe", "firefox", 60_000_000) else {
        eprintln!("SKIP: Firefox Installer.exe or the pinned Wine WoW64 set is absent (git-ignored)");
        return;
    };
    eprintln!(
        "W5.8 probe — Firefox Installer.exe (WoW64): {} instructions, PEB32.Ldr={:#x}, {}",
        p.steps, p.peb32_ldr, p.outcome,
    );
    assert_ne!(
        p.peb32_ldr, 0,
        "Wine's i386 loader_init published PEB32.Ldr (it really ran) — {}",
        p.outcome,
    );
    assert!(
        p.steps > 4_000_000,
        "Firefox Installer should get past its UPX stub on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}
