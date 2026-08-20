//! The child-process seam (roadmap W3.5).
//!
//! `NtCreateUserProcess` lives in the OS layer, but *running* a second guest
//! image needs the whole application wiring — the PE loader, a fresh address
//! space, the interpreter. Those live outward of `exemu-os`, so the OS layer
//! asks for them through this trait, exactly as it asks for a window backend
//! through [`crate::UserDriver`]. `exemu-app` implements it; every other
//! consumer keeps the default [`NoSpawner`], for which child creation fails
//! with a real NTSTATUS rather than a fabricated success.
//!
//! **What the request carries, and why it is a snapshot.** Wine's kernelbase
//! builds the child's `RTL_USER_PROCESS_PARAMETERS` in the *parent's* address
//! space (`RtlCreateProcessParametersEx`) and frees it as soon as
//! `NtCreateUserProcess` returns. The OS layer therefore copies every field it
//! needs out of guest memory at create time; by the time a spawner runs, the
//! guest buffer may already be gone.

/// Everything needed to start a child guest process, copied out of the
/// caller's address space at `NtCreateUserProcess` time.
#[derive(Debug, Clone, Default)]
pub struct ChildProcessRequest {
    /// The child image's **guest** path (`C:\…`), for `GetModuleFileName` and
    /// the child's own `RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub image_guest_path: String,
    /// The same image resolved to a **host** path inside the sandbox. The OS
    /// layer owns guest→host path mapping, so it resolves this rather than
    /// leaking the sandbox layout outward.
    pub image_host_path: std::path::PathBuf,
    /// The child's full command line (argv0 included), as the parent built it.
    pub command_line: String,
    /// The child's initial current directory, as a guest path.
    pub current_directory: String,
    /// The child's environment, decoded from the parent-built environment block.
    /// Empty means "the spawner's default environment".
    pub environment: Vec<(String, String)>,
    /// Whether the creator asked for handle inheritance
    /// (`PROCESS_CREATE_FLAGS_INHERIT_HANDLES`, recovered as bit 2 of
    /// `NtCreateUserProcess`'s `ProcessFlags` — see `exemu_os::process`).
    pub inherit_handles: bool,
    /// How deep this child is in the spawn chain (0 = spawned by the top-level
    /// process). A spawner uses it to bound recursion.
    pub depth: u32,
}

/// What a completed child run reports back.
#[derive(Debug, Clone, Default)]
pub struct ChildProcessOutcome {
    /// The child's process exit code — the value the parent will read back
    /// through `GetExitCodeProcess`.
    pub exit_code: u32,
    /// Guest instructions the child executed (diagnostics only).
    pub steps: u64,
    /// Console output the child produced, so a parent that shares its console
    /// with the child sees it in its own stream.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why a child could not be created or run. Each variant maps to a distinct
/// NTSTATUS in the OS layer — none of them is a success.
#[derive(Debug, Clone)]
pub enum SpawnError {
    /// No spawner is installed (the [`NoSpawner`] default), or this build
    /// cannot host children at all.
    Unsupported,
    /// The image named by the request does not exist in the sandbox.
    ImageNotFound,
    /// The bytes exist but are not a loadable PE for this host.
    InvalidImage(String),
    /// The child started and the *emulator* failed while running it (a fault,
    /// or the instruction budget). This is an exemu defect, not a guest exit:
    /// the report is surfaced verbatim so it can never be mistaken for one.
    Faulted(String),
}

/// Runs child guest processes on behalf of `NtCreateUserProcess`.
pub trait ProcessSpawner {
    /// Run `req` to completion and report its exit code.
    ///
    /// The call is **synchronous**: it returns only once the child has exited.
    /// That is the honest shape of exemu's single-address-space model — see the
    /// module docs of `exemu_os::process` for what it does and does not buy.
    fn spawn(&mut self, req: &ChildProcessRequest) -> Result<ChildProcessOutcome, SpawnError>;
}

/// The default: exemu cannot host a child process. Every request is refused,
/// which the OS layer turns into `STATUS_NOT_SUPPORTED` — never a handle to a
/// process that does not exist.
pub struct NoSpawner;

impl ProcessSpawner for NoSpawner {
    fn spawn(&mut self, _req: &ChildProcessRequest) -> Result<ChildProcessOutcome, SpawnError> {
        Err(SpawnError::Unsupported)
    }
}
