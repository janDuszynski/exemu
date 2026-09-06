use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, wow64_sample, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_wow64_set() -> bool {
    wow64_boot::Wow64Dirs { dir64: Path::new(WINE_DLLS64), dir32: Path::new(WINE_DLLS32) }.complete()
}

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-wow64exc-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn cfg(tag: &str) -> RunConfig {
    RunConfig {
        echo: false,
        max_steps: MAX_STEPS,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(tag)),
        ..RunConfig::default()
    }
}

const MAX_STEPS: u64 = 8_000_000;

#[test]
fn wow64_unhandled_exception_terminates_bounded_naming_the_original() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build_unhandled_fault();
    let mut proc = Process::load(&exe, &mut cfg("unhandled")).expect("WoW64 boot");
    let err = proc
        .run_borrowed()
        .err()
        .expect("a fault nothing handles must END the run, not exit it cleanly");
    let report = err.to_string();
    eprintln!("--- unhandled-exception report ---\n{report}\n---");

    let steps = steps_from(&report).expect("the fault report states the instruction count");
    assert!(
        steps < MAX_STEPS,
        "the process must terminate on the exception, not run out the {MAX_STEPS}-instruction \
         budget (stopped at {steps})",
    );
    assert!(
        !report.contains("step budget") && !report.contains("max-steps"),
        "the run must not have been cut off by the budget:\n{report}",
    );

    let lc = report.to_lowercase();
    assert!(
        lc.contains("unhandled guest exception 0xc0000005"),
        "the report must name the access violation the guest actually took:\n{report}",
    );
    assert!(
        lc.contains(&format!("{:#x}", wow64_sample::WOW64_SEH_FAULT_ADDR)),
        "the report must name the address the guest read through ({:#x}):\n{report}",
        wow64_sample::WOW64_SEH_FAULT_ADDR,
    );
    assert!(
        !lc.contains("0x80000003"),
        "STATUS_BREAKPOINT is what KiUserExceptionDispatcher's trailing int3 raises AFTER the \
         real exception was given up on — reporting it hides the cause:\n{report}",
    );

    assert_ne!(
        proc.peek_u32(wow64_sample::data_va(wow64_sample::data::SEH_HANDLED)).unwrap(),
        wow64_sample::WOW64_SEH_HANDLED,
        "no handler exists in this program, so none can have run",
    );
}

#[test]
fn wow64_guests_own_seh_handler_is_not_reached_yet() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build_seh();
    let mut proc = Process::load(&exe, &mut cfg("seh")).expect("WoW64 boot");
    let err = proc.run_borrowed().err().expect(
        "PIN: the 32-bit hand-off does not complete, so the fault reaches the last resort. If \
         this now succeeds the W5.9 follow-up landed — rewrite this test to assert \
         WOW64_SEH_OK_EXIT and the handler's recorded EXCEPTION_RECORD fields.",
    );
    let report = err.to_string();
    let lc = report.to_lowercase();

    let steps = steps_from(&report).expect("the fault report states the instruction count");
    assert!(steps < MAX_STEPS, "terminated on the exception, not on the budget (at {steps})");
    assert!(
        lc.contains("unhandled guest exception 0xc0000005")
            && lc.contains(&format!("{:#x}", wow64_sample::WOW64_SEH_FAULT_ADDR)),
        "the report names the guest's own access violation:\n{report}",
    );
    assert!(
        report.contains("NtRaiseException, FirstChance = FALSE"),
        "the last resort is reached through Wine's own dispatch_exception tail call, not through \
         exemu's re-delivery bound:\n{report}",
    );
    assert_eq!(
        proc.peek_u32(wow64_sample::data_va(wow64_sample::data::SEH_HANDLED)).unwrap(),
        0,
        "PIN (W5.9 follow-up): ntdll32!KiUserExceptionDispatcher is never entered, so the \
         guest's own fs:[0] handler does not run",
    );
}

fn steps_from(report: &str) -> Option<u64> {
    let tail = report.split("faulted after ").nth(1)?;
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    digits.replace(',', "").parse().ok()
}
