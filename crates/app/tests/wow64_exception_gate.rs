//! **W5.12 — what a 32-bit WoW64 guest's exceptions do when nothing handles
//! them**, and a pin on how far the hand-off to the guest's *own* handler gets.
//!
//! The two programs here are byte-identical apart from the `fs:[0]` frame and
//! fault at the same address on the same boot, so a difference in outcome is a
//! difference in the guest's handler and not in how exemu delivered anything.
//!
//! The chain both exercise, every hop after the first belonging to Wine:
//!
//! ```text
//!   <guest>.exe (PE32) faults
//!     → exemu builds the KiUserExceptionDispatcher frame (W5.9)
//!     → ntdll64!KiUserExceptionDispatcher (rva 0x10a30)
//!         cld; mov rax,[rip+…]        ← the Wow64PrepareForException hook cell
//!         call dispatch_exception (rva 0x479b0)
//!           call_function_handlers == STATUS_SUCCESS              → NtContinue
//!           call_function_handlers == STATUS_UNHANDLED_EXCEPTION  → jmp
//!               NtRaiseException(rec, ctx, FirstChance = FALSE)   ← the last resort
//!         int3                        ← rva 0x10a5a, unreachable in a working system
//! ```
//!
//! Skip-guarded on the git-ignored Wine DLL set (both halves).

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

/// The default boot (Wine's own i386 loader runs), with a **hard instruction
/// ceiling**.
///
/// The ceiling is load-bearing, not decoration: before W5.12 both of these
/// guests ran until the budget ran out, because
/// `ntdll!KiUserExceptionDispatcher` is `call dispatch_exception; int3` and
/// exemu answered the last-resort `NtRaiseException` with
/// `STATUS_NOT_IMPLEMENTED` — so the call returned, the `int3` executed, exemu
/// delivered the resulting `STATUS_BREAKPOINT` to the same dispatcher, and round
/// it went. `max_steps` is what tells "it terminated" from "it was cut off".
fn cfg(tag: &str) -> RunConfig {
    RunConfig {
        echo: false,
        max_steps: MAX_STEPS,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(tag)),
        ..RunConfig::default()
    }
}

/// Generous next to what either program needs (both measured just under a
/// million), and far below the 300M the loop used to burn.
const MAX_STEPS: u64 = 8_000_000;

/// **W5.12 — the standing gate: an exception nothing handles ends the process,
/// in bounded time, named by the exception that actually happened.**
///
/// Three separate things are asserted because each has been wrong:
///
/// 1. **It stops.** Not "it was cut off at `max_steps`" — the run must end
///    strictly inside the budget.
/// 2. **It says why.** The report names `0xC0000005` and the address the guest
///    read through, *not* the `STATUS_BREAKPOINT` from
///    `KiUserExceptionDispatcher`'s trailing `int3`, which is the last thing
///    that happens and tells a reader nothing about the cause.
/// 3. **It is not a silent exit.** NT gives such a process the exception code as
///    its exit status; exemu ends the run through the fault reporter instead, so
///    the module attribution and rip trail survive.
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

    // (1) It stopped on its own, not on the budget.
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

    // (2) It names the ORIGINAL exception, not the `int3` that followed it.
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

    // (3) The guest never ran past the faulting instruction.
    assert_ne!(
        proc.peek_u32(wow64_sample::data_va(wow64_sample::data::SEH_HANDLED)).unwrap(),
        wow64_sample::WOW64_SEH_HANDLED,
        "no handler exists in this program, so none can have run",
    );
}

/// **The W5.9 follow-up, PINNED AS IT ACTUALLY BEHAVES — a 32-bit guest's own
/// `fs:[0]` handler is NOT reached yet.**
///
/// The [`wow64_sample::Program::Seh`] program installs the ordinary i386 SEH
/// prologue any 1990s MSVC binary emits — push a handler, chain it through
/// `fs:[0]`, fault, and let the handler point `CONTEXT.Eip` at a recovery label.
/// It was landed as a *sample* with no test running it, and running it shows the
/// hand-off does not complete: with `EXEMU_FAULT_TRACE=1` the run delivers
/// **exactly one** exception (`code=0xc0000005 at=0xdead rip=0x401018`), the
/// **64-bit** `RtlDispatchException` finds nothing on the 64-bit stack —
/// `wow64.dll`'s `for(;;) pBTCpuSimulate();` frame and its handler are not
/// found, so `Wow64PassExceptionToGuest` never runs — and the exception goes
/// straight to the last resort. `ntdll32!KiUserExceptionDispatcher` is never
/// entered and the guest's handler never runs.
///
/// So this is a pin, not a gate. It asserts the *current* truth precisely, which
/// makes it fail the moment the 32-bit hand-off starts working — at which point
/// it should be rewritten to assert
/// [`wow64_sample::WOW64_SEH_OK_EXIT`] and the handler's recorded record fields.
///
/// What W5.12 changed here: before it, this program did not terminate at all —
/// it span in the `int3` loop until the step budget. The bound below is the
/// point of the test.
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

    // It stops, in bounded time, naming the guest's own access violation.
    let steps = steps_from(&report).expect("the fault report states the instruction count");
    assert!(steps < MAX_STEPS, "terminated on the exception, not on the budget (at {steps})");
    assert!(
        lc.contains("unhandled guest exception 0xc0000005")
            && lc.contains(&format!("{:#x}", wow64_sample::WOW64_SEH_FAULT_ADDR)),
        "the report names the guest's own access violation:\n{report}",
    );
    // And it got there the way Wine's own code gets there: the guest's dispatcher
    // asked the kernel to finish the process off, rather than exemu bounding a loop.
    assert!(
        report.contains("NtRaiseException, FirstChance = FALSE"),
        "the last resort is reached through Wine's own dispatch_exception tail call, not through \
         exemu's re-delivery bound:\n{report}",
    );
    // The pin itself: the guest's handler never ran.
    assert_eq!(
        proc.peek_u32(wow64_sample::data_va(wow64_sample::data::SEH_HANDLED)).unwrap(),
        0,
        "PIN (W5.9 follow-up): ntdll32!KiUserExceptionDispatcher is never entered, so the \
         guest's own fs:[0] handler does not run",
    );
}

/// Pull the instruction count out of a fault report's `faulted after N
/// instructions` line.
fn steps_from(report: &str) -> Option<u64> {
    let tail = report.split("faulted after ").nth(1)?;
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    digits.replace(',', "").parse().ok()
}
