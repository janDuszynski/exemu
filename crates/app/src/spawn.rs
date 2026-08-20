//! The application layer's child-process runner (roadmap W3.5).
//!
//! `NtCreateUserProcess` and the emulated `CreateProcessW` both live in
//! `exemu-os`, which cannot load a PE or drive an interpreter — those are this
//! crate's job. [`AppSpawner`] is the implementation of
//! [`exemu_core::ProcessSpawner`] that closes that loop: it reads the child
//! image out of the guest sandbox, builds a **second, complete [`Process`]** —
//! its own address space, its own `WinOs`, its own interpreter — runs it to
//! completion, and reports the exit code and console output back.
//!
//! It is deliberately a small, boring adapter. Everything about *when* a child
//! runs, what handles the guest sees, and what is refused lives in
//! `exemu_os::process`; the only policy here is what a child inherits from the
//! run that created it (the same sandbox, the same Wine prefix, the same
//! instruction budget) and how deep the chain may go.

use exemu_core::{ChildProcessOutcome, ChildProcessRequest, ProcessSpawner, SpawnError};

use crate::{Process, RunConfig};

/// How many generations of children a single run may create. A guest that
/// spawns itself would otherwise recurse until the host stack gives out; four
/// is far past anything an installer does (`setup.exe` → `unpacked.exe` →
/// `msiexec` is three) and turns runaway recursion into a clean refusal.
pub const MAX_SPAWN_DEPTH: u32 = 4;

/// Runs child guest processes as nested [`Process`] instances.
pub struct AppSpawner {
    /// The sandbox the parent is rooted in — a child shares it, because a child
    /// on Windows shares its parent's filesystem.
    sandbox_root: std::path::PathBuf,
    /// The Wine PE prefix the parent booted from, if any. A child of a Wine-boot
    /// run must boot the same way or its imports would not resolve.
    wine_boot_dir: Option<String>,
    /// Instruction budget for one child run.
    max_steps: u64,
    /// Whether to log unimplemented APIs, inherited from the parent run.
    trace: bool,
}

impl AppSpawner {
    pub(crate) fn new(cfg: &RunConfig, sandbox_root: std::path::PathBuf) -> AppSpawner {
        AppSpawner {
            sandbox_root,
            wine_boot_dir: cfg.wine_boot_dir.clone(),
            max_steps: cfg.max_steps,
            trace: cfg.trace,
        }
    }
}

impl ProcessSpawner for AppSpawner {
    fn spawn(&mut self, req: &ChildProcessRequest) -> Result<ChildProcessOutcome, SpawnError> {
        if req.depth > MAX_SPAWN_DEPTH {
            return Err(SpawnError::Unsupported);
        }
        let bytes = std::fs::read(&req.image_host_path).map_err(|_| SpawnError::ImageNotFound)?;

        // argv[0] is the child's own guest path: `Process::load` derives the
        // module name (and therefore `GetModuleFileName`) from it. The command
        // line is passed whole and separately, because the parent already built
        // it and re-joining argv would re-quote it.
        let mut child_cfg = RunConfig {
            args: vec![req.image_guest_path.clone()],
            command_line: Some(req.command_line.clone()),
            environment: req.environment.clone(),
            // Captured, never echoed: the *parent* folds the child's output into
            // its own stream, so it passes through exactly one console policy.
            echo: false,
            trace: self.trace,
            max_steps: self.max_steps,
            wine_boot_dir: self.wine_boot_dir.clone(),
            sandbox_root: Some(self.sandbox_root.clone()),
            spawn_depth: req.depth,
            ..RunConfig::default()
        };

        let process = Process::load(&bytes, &mut child_cfg)
            .map_err(|e| SpawnError::InvalidImage(e.to_string()))?;
        match process.run() {
            Ok(r) => Ok(ChildProcessOutcome {
                // A guest exit code is a DWORD; the run loop carries it as i32.
                exit_code: r.exit_code as u32,
                steps: r.steps,
                stdout: r.stdout,
                stderr: r.stderr,
            }),
            // The child started and *exemu* could not finish it — a fault, or the
            // instruction budget. That is an emulator failure, not a guest exit,
            // and the OS layer turns it into a failed process plus a verbatim
            // report rather than any kind of exit code.
            Err(e) => Err(SpawnError::Faulted(e.to_string())),
        }
    }
}
