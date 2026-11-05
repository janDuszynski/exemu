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

struct Probe {
    steps: u64,
    outcome: String,
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
    assert_eq!(
        p.outcome, "exit 2",
        "SteamSetup terminates itself on the WoW64 path; a fault here means the \
         32-bit callback/thread refusals (W5.10/W5.11) stopped holding",
    );
    assert!(
        (5_000_000..60_000_000).contains(&p.steps),
        "SteamSetup should run millions of instructions on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}

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
        (8_000_000..60_000_000).contains(&p.steps),
        "Firefox Installer should get past its UPX stub on the WoW64 path; ran {} ({})",
        p.steps,
        p.outcome,
    );
}
