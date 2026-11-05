use crate::wow64_boot;

pub struct RunConfig {
    pub args: Vec<String>,
    pub echo: bool,
    pub trace: bool,
    pub driver: Option<Box<dyn exemu_core::UserDriver>>,
    pub audio_sink: Option<Box<dyn exemu_core::AudioSink>>,
    pub max_steps: u64,
    pub gui: bool,
    pub load_base: Option<u64>,
    pub wine_boot_dir: Option<String>,
    pub wow64_bringup: wow64_boot::Bringup,
    pub input: Option<std::sync::mpsc::Receiver<exemu_core::InputEvent>>,
    pub sandbox_root: Option<std::path::PathBuf>,
    pub virtual_clock: bool,
    pub command_line: Option<String>,
    pub environment: Vec<(String, String)>,
    pub spawn_depth: u32,
    pub jit: bool,
    pub dpi: u32,
    pub file_dialog_pick: Option<String>,
    pub debug: Option<exemu_core::DebugSession>,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            args: vec!["program.exe".into()],
            echo: true,
            trace: false,
            max_steps: 2_000_000_000,
            gui: false,
            load_base: None,
            wine_boot_dir: None,
            wow64_bringup: wow64_boot::Bringup::default(),
            driver: None,
            audio_sink: None,
            input: None,
            sandbox_root: None,
            virtual_clock: false,
            command_line: None,
            environment: Vec::new(),
            spawn_depth: 0,
            jit: false,
            dpi: 96,
            file_dialog_pick: std::env::var("EXEMU_FILE_DIALOG_PICK").ok().filter(|s| !s.is_empty()),
            debug: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct JitReport {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub chains: u64,
    pub insns_executed: u64,
    pub faults: u64,
    pub not_compiled: u64,
    pub flushes: u64,
    pub code_bytes: usize,
    pub declined: Vec<(u16, u64)>,
}

pub struct RunResult {
    pub exit_code: i32,
    pub steps: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub sandbox: String,
    pub children_created: u32,
    pub jit: Option<JitReport>,
}
