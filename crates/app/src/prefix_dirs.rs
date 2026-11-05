use std::path::Path;

pub const PREFIX_DIRS: &[&str] = &[
    "Temp",
    "windows/temp",
    "ProgramData",
    "Program Files",
    "Program Files/Common Files",
    "Program Files (x86)",
    "Program Files (x86)/Common Files",
    "Users/exemu/Desktop",
    "Users/exemu/Documents",
    "Users/exemu/AppData/Local/Temp",
    "Users/exemu/AppData/Roaming",
];

pub fn stage_prefix_dirs(sandbox: &Path) {
    let drive = sandbox.join("C");
    for rel in PREFIX_DIRS {
        let _ = std::fs::create_dir_all(drive.join(rel));
    }
}
