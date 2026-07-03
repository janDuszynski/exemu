//! A minimal in-process DLL loader for `LoadLibrary` / `GetProcAddress`.
//!
//! Two kinds of module are handled:
//!
//! * **Emulated system DLLs** (kernel32, user32, gdi32, …) — we don't have
//!   their bytes, but we already service their functions via API thunks. A
//!   `LoadLibrary` of one returns a synthetic handle, and `GetProcAddress`
//!   against it hands back a thunk for the requested function (created on
//!   demand), exactly as if it had been imported statically.
//!
//! * **Plugin DLLs** (a real PE file — e.g. an NSIS `System.dll` the
//!   installer just extracted to its temp dir). We read the file, map its
//!   sections into the DLL arena, apply base relocations for the load delta,
//!   resolve its own imports to thunks, record its export table, and run
//!   `DllMain`. `GetProcAddress` then returns the guest address of an export,
//!   which the interpreter executes like any other guest code.

use std::collections::HashMap;

use exemu_core::{ImportSymbol, Memory, Result};

use crate::WinOs;

const PAGE: u64 = 0x1000;

/// System DLLs whose functions we emulate rather than load from disk.
const EMULATED: &[&str] = &[
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ole32.dll",
    "oleaut32.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "version.dll",
    "ntdll.dll",
    "msvcrt.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "setupapi.dll",
    "winmm.dll",
    "rpcrt4.dll",
    "userenv.dll",
    "psapi.dll",
    "imm32.dll",
    "gdiplus.dll",
];

#[derive(Default)]
pub(crate) struct Loader {
    /// Bump pointer into the DLL arena (0 until first use → cfg.dll_base).
    arena_next: u64,
    /// Lower-cased module base name → handle (real base or synthetic).
    by_name: HashMap<String, u64>,
    /// Real plugin base → its exports (name/ordinal → RVA within the module).
    exports: HashMap<u64, Vec<exemu_core::Export>>,
    /// Synthetic handle → emulated system DLL name.
    system: HashMap<u64, String>,
    /// Next synthetic handle for an emulated system DLL.
    next_system: u64,
    /// A freshly loaded plugin's (DllMain entry, base) awaiting invocation.
    pub(crate) pending_dllmain: Option<(u64, u64)>,
}

/// The last path component, lower-cased, with a `.dll` extension ensured.
fn base_name(path: &str) -> String {
    let last = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let mut n = last.to_ascii_lowercase();
    if !n.ends_with(".dll") && !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

impl WinOs {
    /// LoadLibrary(Ex)(A/W): return a module handle, loading a plugin DLL from
    /// the sandbox if necessary. Returns 0 on failure.
    pub(crate) fn load_library(&mut self, mem: &mut dyn Memory, path: &str) -> Result<u64> {
        if path.is_empty() {
            return Ok(self.cfg.image_base); // LoadLibrary(NULL) → the exe itself
        }
        let name = base_name(path);
        if let Some(&h) = self.dll.by_name.get(&name) {
            return Ok(h);
        }

        // Emulated system DLL → synthetic handle.
        if EMULATED.contains(&name.as_str()) {
            return Ok(self.system_handle(name));
        }

        // Plugin DLL: try to load its real bytes from the sandbox.
        match self.load_plugin(mem, path, &name) {
            Ok(Some(base)) => Ok(base),
            _ => Ok(0),
        }
    }

    /// The handle of an already-loaded (or emulated) module, without loading a
    /// plugin from disk. `GetModuleHandle` semantics: 0 if not present.
    pub(crate) fn module_handle(&mut self, path: &str) -> u64 {
        let name = base_name(path);
        if let Some(&h) = self.dll.by_name.get(&name) {
            return h;
        }
        if EMULATED.contains(&name.as_str()) {
            return self.system_handle(name);
        }
        0
    }

    /// Assign (or reuse) a synthetic handle for an emulated system DLL.
    fn system_handle(&mut self, name: String) -> u64 {
        if let Some(&h) = self.dll.by_name.get(&name) {
            return h;
        }
        if self.dll.next_system == 0 {
            self.dll.next_system = 0x00D1_0000;
        }
        let h = self.dll.next_system;
        self.dll.next_system += 0x1_0000;
        self.dll.by_name.insert(name.clone(), h);
        self.dll.system.insert(h, name);
        h
    }

    fn load_plugin(&mut self, mem: &mut dyn Memory, path: &str, name: &str) -> Result<Option<u64>> {
        let Some(host) = self.find_dll_file(path, name) else {
            return Ok(None);
        };
        let Ok(bytes) = std::fs::read(&host) else {
            return Ok(None);
        };
        let Ok(image) = exemu_loader::parse(&bytes) else {
            return Ok(None);
        };

        // Reserve arena space for the whole image.
        if self.dll.arena_next == 0 {
            self.dll.arena_next = self.cfg.dll_base;
        }
        let base = align_up(self.dll.arena_next, PAGE);
        let img_size = align_up(image.size_of_image as u64, PAGE).max(PAGE);
        if base + img_size > self.cfg.dll_base + self.cfg.dll_size {
            return Ok(None); // arena exhausted
        }
        self.dll.arena_next = base + img_size;
        let ptr_size = if self.cfg.is_64bit { 8 } else { 4 };

        // Map headers + section data (the arena is pre-zeroed, so gaps and
        // uninitialized data are already zero).
        mem.write(base, &image.headers)?;
        for s in &image.sections {
            if !s.data.is_empty() {
                mem.write(base + s.rva as u64, &s.data)?;
            }
        }

        // Apply base relocations for the load delta.
        let delta = base.wrapping_sub(image.image_base);
        if delta != 0 {
            for r in &image.relocations {
                let at = base + r.rva as u64;
                match r.kind {
                    10 => mem.write_u64(at, mem.read_u64(at)?.wrapping_add(delta))?, // DIR64
                    3 => mem.write_u32(at, (mem.read_u32(at)? as u64).wrapping_add(delta) as u32)?, // HIGHLOW
                    _ => {}
                }
            }
        }

        // Resolve the DLL's own imports to thunks and patch its IAT.
        for imp in &image.imports {
            let thunk = self.resolve_import(&imp.dll, &imp.symbol);
            mem.write(base + imp.iat_rva as u64, &thunk.to_le_bytes()[..ptr_size])?;
        }

        self.dll.exports.insert(base, image.exports.clone());
        self.dll.by_name.insert(name.to_string(), base);
        if self.cfg.trace {
            eprintln!(
                "[exemu] loaded plugin {name} at {base:#x} ({} exports, {} relocs)",
                image.exports.len(),
                image.relocations.len()
            );
        }

        // Run DllMain(base, DLL_PROCESS_ATTACH, 0) if there is an entry point
        // and it hasn't been disabled for debugging.
        let entry = if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 };
        let run_dllmain = std::env::var_os("EXEMU_NO_DLLMAIN").is_none();
        self.dll.pending_dllmain = if entry != 0 && run_dllmain { Some((entry, base)) } else { None };
        Ok(Some(base))
    }

    /// GetProcAddress(hModule, name-or-ordinal). `name_ptr` is a string
    /// pointer unless its high bits are zero and value < 0x10000 (an ordinal).
    pub(crate) fn get_proc_address(&mut self, mem: &mut dyn Memory, hmodule: u64, name_ptr: u64) -> Result<u64> {
        // Plugin export lookup.
        if let Some(exports) = self.dll.exports.get(&hmodule) {
            let by_ord = name_ptr < 0x1_0000;
            let found = if by_ord {
                exports.iter().find(|e| e.ordinal as u64 == name_ptr)
            } else {
                let want = crate::api::read_astr(mem, name_ptr)?;
                exports.iter().find(|e| e.name.as_deref() == Some(want.as_str()))
            };
            return Ok(found.map(|e| hmodule + e.rva as u64).unwrap_or(0));
        }
        // Emulated system DLL → hand out a thunk for the function.
        if let Some(dll) = self.dll.system.get(&hmodule).cloned() {
            if name_ptr < 0x1_0000 {
                return Ok(self.resolve_import(&dll, &ImportSymbol::Ordinal(name_ptr as u16)));
            }
            let name = crate::api::read_astr(mem, name_ptr)?;
            if name.is_empty() {
                return Ok(0);
            }
            let thunk = self.resolve_import(&dll, &ImportSymbol::Named(name.clone()));
            // A few CRT *data* exports are pointers a program dereferences
            // rather than calls. When one is resolved dynamically, its thunk
            // slot must hold the real value or the guest reads, e.g., a null
            // command line and faults.
            if let Some(v) = data_export_value(&self.cfg, &name) {
                self.write_ptr(mem, thunk, v)?;
            }
            return Ok(thunk);
        }
        Ok(0)
    }

    /// Locate a plugin DLL's real bytes: try the given path in the sandbox,
    /// then the same directory as the running module, then the sandbox root.
    fn find_dll_file(&self, path: &str, name: &str) -> Option<std::path::PathBuf> {
        // As given (may be a full guest path like C:\Temp\...\System.dll).
        if let Some(p) = self.host_path(path) {
            if p.is_file() {
                return Some(p);
            }
        }
        // Bare name under the sandbox's C: drive and temp locations.
        for guest in [format!("C:\\{name}"), format!("C:\\Temp\\{name}")] {
            if let Some(p) = self.host_path(&guest) {
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        // Last resort: search the sandbox tree for a matching file name.
        if !self.cfg.sandbox.is_empty() {
            return find_in_tree(std::path::Path::new(&self.cfg.sandbox), name, 0);
        }
        None
    }
}

/// Value for a known CRT *data* export (a variable a DLL exports, not a
/// function). `None` means the zero default is correct.
fn data_export_value(cfg: &crate::WinConfig, name: &str) -> Option<u64> {
    match name {
        "_acmdln" => Some(cfg.cmdline_ptr_a),
        "_wcmdln" => Some(cfg.cmdline_ptr_w),
        _ => None,
    }
}

/// Recursively search `dir` (bounded depth) for a file named `name`.
fn find_in_tree(dir: &std::path::Path, name: &str, depth: u32) -> Option<std::path::PathBuf> {
    if depth > 6 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            subdirs.push(p);
        } else if p.file_name().and_then(|n| n.to_str()).map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false) {
            return Some(p);
        }
    }
    for sd in subdirs {
        if let Some(found) = find_in_tree(&sd, name, depth + 1) {
            return Some(found);
        }
    }
    None
}
