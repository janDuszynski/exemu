use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, wow64_sample, JitReport, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";
const MAX_STEPS: u64 = 8_000_000;

fn have_wow64_set() -> bool {
    wow64_boot::Wow64Dirs { dir64: Path::new(WINE_DLLS64), dir32: Path::new(WINE_DLLS32) }.complete()
}

fn private_sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-jitexc-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn fault_run(jit: bool) -> (String, Option<JitReport>) {
    let exe = wow64_sample::build_unhandled_fault();
    let mut cfg = RunConfig {
        echo: false,
        jit,
        virtual_clock: true,
        max_steps: MAX_STEPS,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(if jit { "jit" } else { "interp" })),
        ..RunConfig::default()
    };
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let err = proc.run_borrowed().err().expect("a fault nothing handles must end the run");
    (err.to_string(), proc.jit_report())
}

fn steps_from(report: &str) -> u64 {
    let tail = report.split("faulted after ").nth(1).expect("the report states the instruction count");
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    digits.replace(',', "").parse().expect("a count")
}

#[test]
fn a_hardware_exception_is_delivered_at_the_same_instruction_with_and_without_the_jit() {
    if !have_wow64_set() || !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        eprintln!("SKIP: needs the pinned Wine WoW64 set and the JIT backend");
        return;
    }
    let (plain, _) = fault_run(false);
    let (jitted, report) = fault_run(true);
    let report = report.expect("the JIT should have been built");
    let steps = steps_from(&jitted);
    assert!(
        report.insns_executed > steps / 2,
        "the JIT barely ran: {} of {steps} instructions",
        report.insns_executed
    );
    assert!(jitted.contains("unhandled guest exception 0xc0000005"), "{jitted}");
    assert_eq!(steps, steps_from(&plain), "the JIT run stopped at a different instruction");
}
