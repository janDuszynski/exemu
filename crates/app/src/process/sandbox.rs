use std::path::PathBuf;

use crate::config::RunConfig;
use crate::{prefix_dirs, winsxs};

pub(super) fn stage(
    cfg: &RunConfig,
    pe_bytes: &[u8],
    is_64bit: bool,
    wine_dll_dir: &Option<String>,
    wow64_dir32: &Option<PathBuf>,
) -> (PathBuf, String, String) {
    let sandbox = cfg
        .sandbox_root
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("exemu-sandbox"));
    let _ = std::fs::create_dir_all(&sandbox);
    let _ = std::fs::create_dir_all(sandbox.join("C").join("windows").join("system32"));
    for guest in exemu_os::folders::all_guest_dirs() {
        let mut host = sandbox.clone();
        for comp in guest.split('\\') {
            match comp {
                "" | "." | ".." => {}
                c if c.ends_with(':') => host.push(&c[..c.len() - 1]),
                c => host.push(c),
            }
        }
        let _ = std::fs::create_dir_all(&host);
    }
    let module_name = cfg
        .args
        .first()
        .map(|s| s.rsplit(['/', '\\']).next().unwrap_or(s).to_string())
        .unwrap_or_else(|| "program.exe".into());
    let module_path_w = format!("C:\\{module_name}");
    let host_exe = sandbox.join("C").join(&module_name);
    if let Some(p) = host_exe.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let _ = std::fs::write(&host_exe, pe_bytes);

    if wine_dll_dir.is_some() {
        let drv = sandbox
            .join("C")
            .join("windows")
            .join("system32")
            .join(exemu_os::audio::DRIVER_MODULE);
        let _ = std::fs::write(drv, exemu_os::audio::driver_stub_pe());
    }

    if let Some(dir) = &wine_dll_dir {
        let prefix = match (is_64bit, wow64_dir32) {
            (false, Some(d32)) => d32.clone(),
            _ => std::path::PathBuf::from(dir),
        };
        prefix_dirs::stage_prefix_dirs(&sandbox);
        let _ = winsxs::stage_comctl6(&sandbox, &prefix, winsxs::arch_for(is_64bit));
    }

    (sandbox, module_name, module_path_w)
}
