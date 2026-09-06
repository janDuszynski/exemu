#[derive(Debug, Clone, Default)]
pub struct ChildProcessRequest {
    pub image_guest_path: String,
    pub image_host_path: std::path::PathBuf,
    pub command_line: String,
    pub current_directory: String,
    pub environment: Vec<(String, String)>,
    pub inherit_handles: bool,
    pub depth: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ChildProcessOutcome {
    pub exit_code: u32,
    pub steps: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SpawnError {
    Unsupported,
    ImageNotFound,
    InvalidImage(String),
    Faulted(String),
}

pub trait ProcessSpawner {
    fn spawn(&mut self, req: &ChildProcessRequest) -> Result<ChildProcessOutcome, SpawnError>;
}

pub struct NoSpawner;

impl ProcessSpawner for NoSpawner {
    fn spawn(&mut self, _req: &ChildProcessRequest) -> Result<ChildProcessOutcome, SpawnError> {
        Err(SpawnError::Unsupported)
    }
}
