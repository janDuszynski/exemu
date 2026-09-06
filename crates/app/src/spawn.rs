use exemu_core::{ChildProcessOutcome, ChildProcessRequest, ProcessSpawner, SpawnError};

use crate::{Process, RunConfig};

pub const MAX_SPAWN_DEPTH: u32 = 4;

pub struct AppSpawner {
    sandbox_root: std::path::PathBuf,
    wine_boot_dir: Option<String>,
    max_steps: u64,
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

        let mut child_cfg = RunConfig {
            args: vec![req.image_guest_path.clone()],
            command_line: Some(req.command_line.clone()),
            environment: req.environment.clone(),
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
                exit_code: r.exit_code as u32,
                steps: r.steps,
                stdout: r.stdout,
                stderr: r.stderr,
            }),
            Err(e) => Err(SpawnError::Faulted(e.to_string())),
        }
    }
}
