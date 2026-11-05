#![forbid(unsafe_code)]

pub mod audio_sample;
pub mod cab;
pub mod cab_sample;
mod cmdline;
pub mod comctl_sample;
pub mod comdlg_sample;
mod config;
mod kuser;
pub mod gui_sample;
pub mod image_loader;
mod inspect;
mod memory_map;
mod process;
pub mod sample;
pub mod shell_link_sample;
pub mod shell_sample;
pub mod socket_sample;
pub mod prefix_dirs;
pub mod winsxs;
pub mod wow64_boot;
pub mod wow64_gui_sample;
pub mod wow64_image;
pub mod wow64_sample;
pub mod spawn;
pub mod spawn_sample;

pub use config::{JitReport, RunConfig, RunResult};
pub use inspect::{inspect, ImageInfo, ResourceTypeCount};
pub use process::{load_and_run, Process};

#[cfg(feature = "opcode-profile")]
pub fn opcode_profile_report(top: usize) -> String {
    exemu_cpu::profile::report(top)
}

const PAGE: u64 = 0x1000;
