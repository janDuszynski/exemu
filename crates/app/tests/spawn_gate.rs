//! W3.5 — **a child process created through Wine's own `CreateProcessW`**.
//!
//! The proof binaries ([`exemu_app::spawn_sample`]) are a pair. The parent
//! statically imports `kernel32!CreateProcessW` / `WaitForSingleObject` /
//! `GetExitCodeProcess` / `CloseHandle`, so under the Wine boot the loader must
//! map, relocate, bind and `DllMain` **Wine's own kernel32 and kernelbase**
//! before the entry point runs, and the whole creation path is then guest code:
//!
//! ```text
//! CreateProcessW → CreateProcessInternalW → RtlCreateProcessParametersEx
//!                → create_nt_process → NtCreateUserProcess → NtResumeThread
//! GetExitCodeProcess → NtQueryInformationProcess(ProcessBasicInformation)
//! ```
//!
//! exemu contributes only the NT syscalls (`exemu_os::process`) and the nested
//! run. Three things make the result attributable to that path:
//!
//! 1. **The child is a separate binary that exemu had to actually run.** Its
//!    marker line is written by *its own* `WriteFile`, in its own address space,
//!    from a `.rdata` the parent does not contain — and it lands in the parent's
//!    stdout because it inherited the parent's console.
//! 2. **The exit code is a value only the child knows.** `CHILD_EXIT` is 91:
//!    not 0, not 1, not a CRT status. Reading it back proves the value crossed
//!    from the child's `ExitProcess`, through a process object, into the
//!    parent's `GetExitCodeProcess`.
//! 3. **The emulated path is the control**, and it runs the *same* pair through
//!    exemu's own kernel32 instead of Wine's. Both paths must produce the same
//!    answer, from opposite ends of the OS layer.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::{Path, PathBuf};

use exemu_app::{load_and_run, spawn_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// Where the child lands inside the guest sandbox.
const CHILD_GUEST_PATH: &str = "C:\\exemu-child.exe";

/// Read a `LABEL=` line out of the sample's stdout.
fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

/// A private sandbox per run, so nothing a previous run left behind can change
/// what this one observes (see `RunConfig::sandbox_root`), with the child
/// already placed where the parent will ask for it. The parent cannot *create*
/// the child binary — it has no compiler — so the harness stages it, exactly as
/// a real installer would have extracted it a moment earlier.
fn sandbox_with_child(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-w35-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C")).expect("create the guest C: root");
    std::fs::write(dir.join("C").join("exemu-child.exe"), spawn_sample::build_child())
        .expect("stage the child binary in the sandbox");
    dir
}

/// Assert everything the parent reported, given its stdout and exit code. The
/// same battery runs against both paths, because both must answer identically.
fn assert_spawn_succeeded(stdout: &str, exit_code: i32) {
    // CreateProcessW returned TRUE and handed back a real pid.
    assert_eq!(line(stdout, spawn_sample::LABEL_CREATED), "0000000000000001", "stdout:\n{stdout}");
    let pid = u64::from_str_radix(line(stdout, spawn_sample::LABEL_PID), 16).expect("PID is hex");
    assert!(pid != 0, "PROCESS_INFORMATION.dwProcessId was zero; stdout:\n{stdout}");
    assert_ne!(pid, 0x1000, "the child must not report the parent's own pid; stdout:\n{stdout}");

    // The wait on the process handle reported WAIT_OBJECT_0.
    assert_eq!(line(stdout, spawn_sample::LABEL_WAIT), "0000000000000000", "stdout:\n{stdout}");
    // GetExitCodeProcess succeeded…
    assert_eq!(line(stdout, spawn_sample::LABEL_GETEXIT), "0000000000000001", "stdout:\n{stdout}");
    // …and THE CLAIM: it is the child's own exit code.
    assert_eq!(
        line(stdout, spawn_sample::LABEL_CHILDEXIT),
        format!("{:016x}", spawn_sample::CHILD_EXIT),
        "the child's exit code did not survive the round trip; stdout:\n{stdout}"
    );

    // The child really ran: its marker line came out of *its* address space and
    // into the parent's console.
    assert!(
        stdout.contains(spawn_sample::CHILD_MESSAGE.trim_end()),
        "the child's own output is missing; stdout:\n{stdout}"
    );
    // The child ran *before* the parent's first report, because the run is
    // synchronous inside CreateProcessW — pinned so that the day a scheduler
    // makes it concurrent, this line is what says so.
    let child_at = stdout.find(spawn_sample::CHILD_MESSAGE.trim_end()).unwrap();
    let created_at = stdout.find(spawn_sample::LABEL_CREATED).unwrap();
    assert!(
        child_at < created_at,
        "W3.5's child runs synchronously inside CreateProcessW; stdout:\n{stdout}"
    );

    // The guest verified the same things itself and said so.
    assert!(stdout.contains(spawn_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(exit_code, spawn_sample::PARENT_OK_EXIT, "stdout:\n{stdout}");
}

/// The W3.5 gate: Wine's own kernel32/kernelbase creates the child, exemu runs
/// it, and the parent reads its exit code back.
#[test]
fn parent_spawns_child_through_wine_kernel32() {
    if !Path::new(WINE_DLLS).join("kernelbase.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/kernelbase.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let sandbox = sandbox_with_child("wine");
    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(sandbox),
            ..RunConfig::default()
        },
    )
    .expect("the spawn sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("spawn sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    // Wine's process stack really booted: CreateProcessW pulls in the full
    // kernel32/kernelbase/ntdll set, and the child boots the same set again, so
    // the total is far past anything the emulated control spends.
    assert!(run.steps > 500_000, "expected a real Wine boot, got {} steps", run.steps);

    assert_spawn_succeeded(&stdout, run.exit_code);
}

/// The control, from the other end of the OS layer: the same pair on exemu's own
/// emulated kernel32, which reaches the same process objects through
/// `Api::CreateProcessApi` instead of `NtCreateUserProcess`. Both doors must lead
/// to the same room.
#[test]
fn parent_spawns_child_on_the_emulated_path() {
    let sandbox = sandbox_with_child("emulated");
    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            sandbox_root: Some(sandbox),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("spawn sample emulated: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);
    assert_spawn_succeeded(&stdout, run.exit_code);
}

/// The named gap, pinned so it cannot rot into a false claim: with **no child
/// binary in the sandbox** the create fails cleanly — `CreateProcessW` returns
/// FALSE — instead of handing back a handle to a process that will never exist.
#[test]
fn a_missing_child_fails_the_create_rather_than_faking_it() {
    let dir = std::env::temp_dir().join(format!("exemu-w35-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C")).unwrap();
    // Deliberately do NOT stage the child.

    let exe = spawn_sample::build_parent(CHILD_GUEST_PATH);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            sandbox_root: Some(dir.clone()),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();

    assert_eq!(
        line(&stdout, spawn_sample::LABEL_CREATED),
        "0000000000000000",
        "CreateProcessW must fail for a missing image; stdout:\n{stdout}"
    );
    assert!(stdout.contains(spawn_sample::FAIL_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_ne!(run.exit_code, spawn_sample::PARENT_OK_EXIT);
    assert!(
        !stdout.contains(spawn_sample::CHILD_MESSAGE.trim_end()),
        "nothing should have run; stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
