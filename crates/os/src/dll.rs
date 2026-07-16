//! The in-process module loader for `LoadLibrary` / `GetProcAddress`, and the
//! guest-memory `PEB.Ldr` module-list materialization (roadmap W0.6).
//!
//! Three kinds of module are handled:
//!
//! * **The main image** — recorded as the first module (ref count "pinned"),
//!   so `GetModuleHandle(NULL)` and a walk of the loader lists both see it.
//!
//! * **Emulated system DLLs** (kernel32, user32, gdi32, …) — we don't have
//!   their bytes, but we already service their functions via API thunks. A
//!   `LoadLibrary` of one returns a synthetic handle, and `GetProcAddress`
//!   against it hands back a thunk for the requested function (created on
//!   demand), exactly as if it had been imported statically.
//!
//! * **Plugin DLLs** (a real PE file — a guest-bundled DLL, e.g. an NSIS
//!   `System.dll`, or one plugin's dependency `B.dll`). We read the file, map
//!   its sections into the DLL arena, apply base relocations for the load
//!   delta, **recursively load its own guest-bundled dependencies in
//!   dependency order**, resolve its imports to real guest export addresses
//!   (or thunks), record its export table, and run `DllMain`. `GetProcAddress`
//!   then returns the guest address of an export.
//!
//! Each loaded module (main image + every plugin) also gets a real
//! `LDR_DATA_TABLE_ENTRY` in guest memory, threaded onto the three
//! doubly-linked lists `PEB_LDR_DATA` heads (InLoadOrder / InMemoryOrder /
//! InInitializationOrder), so anti-debug code and a hand-rolled
//! `GetModuleHandle`-by-walk see the same list the OS APIs walk. Ref counts on
//! `LoadLibrary`/`FreeLibrary` track pinned vs. releasable modules.

use std::collections::HashMap;

use exemu_core::{CpuState, Export, ImportSymbol, Memory, Result};

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

/// A loaded plugin module (a real PE mapped into the DLL arena).
struct Module {
    /// The base name (lower-cased, `.dll`-suffixed) — the loader-list key.
    name: String,
    /// The full guest path reported in `FullDllName`.
    full_path: String,
    /// Mapped base address (== the module handle).
    base: u64,
    /// `SizeOfImage`.
    size: u64,
    /// Entry point VA (`DllMain`), or 0 when the image has none.
    entry: u64,
    /// `LoadLibrary`/`FreeLibrary` reference count. A statically-linked
    /// dependency and the main image start at 1; each explicit `LoadLibrary`
    /// increments and `FreeLibrary` decrements (we never unmap — see below).
    ref_count: u32,
    /// Guest address of this module's `LDR_DATA_TABLE_ENTRY`, once threaded
    /// onto the loader lists.
    ldr_entry: u64,
    /// Set by `DisableThreadLibraryCalls(hModule)`: this DLL opted out of
    /// `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` notifications, so a new thread
    /// must **not** call its `DllMain` with those reasons (roadmap W0.7).
    thread_calls_disabled: bool,
    /// True once this module's `DllMain(DLL_PROCESS_ATTACH)` has run and its
    /// matching `DLL_PROCESS_DETACH` has not — i.e. it is eligible for a detach
    /// notification on `FreeLibrary` ref-count-zero or process exit.
    attached: bool,
}

#[derive(Default)]
pub(crate) struct Loader {
    /// Bump pointer into the DLL arena (0 until first use → cfg.dll_base).
    arena_next: u64,
    /// Lower-cased module base name → handle (real base or synthetic).
    by_name: HashMap<String, u64>,
    /// Real plugin base → its exports (name/ordinal → RVA within the module).
    exports: HashMap<u64, Vec<Export>>,
    /// Real loaded modules (main image first), in load order. The authoritative
    /// module table backing the `PEB.Ldr` lists and ref counting.
    modules: Vec<Module>,
    /// Synthetic handle → emulated system DLL name.
    system: HashMap<u64, String>,
    /// Next synthetic handle for an emulated system DLL.
    next_system: u64,
    /// A freshly loaded plugin's (DllMain entry, base) awaiting invocation.
    /// When a `LoadLibrary` triggers a recursive dependency load, this holds
    /// the *whole chain* of (entry, base) pairs in **leaves-first** order so
    /// the caller drives each `DllMain(DLL_PROCESS_ATTACH)` in dependency order.
    pub(crate) pending_dllmain: Vec<(u64, u64)>,
    /// Guest bump pointer for `PEB_LDR_DATA` / `LDR_DATA_TABLE_ENTRY` / name
    /// buffers, carved from the top of the DLL arena downward so it never
    /// collides with a mapped image.
    ldr_arena_next: u64,
    /// Guest address of the process `PEB_LDR_DATA`, once built (0 until then).
    peb_ldr_data: u64,
    /// Recursion guard for the dependency-order loader.
    loading: Vec<String>,
    /// A module whose `DllMain(DLL_PROCESS_DETACH)` is awaiting invocation
    /// because a `FreeLibrary` dropped its ref count to zero: `(entry, base)`.
    /// The `FreeLibrary` handler drains it through the callback machinery.
    pub(crate) pending_detach: Vec<(u64, u64)>,
    /// Guest address of the process `PEB.LoaderLock` `RTL_CRITICAL_SECTION`
    /// (0 until `init_ldr` seeds it). Held during loader operations that run
    /// `DllMain` (roadmap W0.7).
    loader_lock: u64,
    /// Recursion depth of the held loader lock (its `RecursionCount`). Lets
    /// nested loader operations (a `DllMain` that itself calls `LoadLibrary`)
    /// keep the lock owned until the outermost operation completes.
    loader_lock_depth: i32,
    /// Guest address of the seeded `API_SET_NAMESPACE` (`PEB.ApiSetMap`), or 0
    /// until [`WinOs::seed_api_set_map`] runs on the Wine-boot path (roadmap
    /// W3.3). The emulated corpus never seeds it (its loader never reads
    /// `PEB.ApiSetMap`), so this stays 0 there.
    api_set_map: u64,
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

/// Resolve an API-set contract name to its host DLL and ensure a `.dll` suffix.
fn canonical_name(raw: &str) -> String {
    match exemu_loader::resolve_api_set(raw) {
        Some(host) => {
            let mut s = host.to_string();
            if !s.ends_with(".dll") {
                s.push_str(".dll");
            }
            s
        }
        None => raw.to_string(),
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

impl WinOs {
    /// LoadLibrary(Ex)(A/W): return a module handle, loading a plugin DLL (and
    /// its guest-bundled dependencies, in dependency order) from the sandbox if
    /// necessary. An already-loaded plugin has its ref count bumped. Returns 0
    /// on failure.
    pub(crate) fn load_library(&mut self, mem: &mut dyn Memory, path: &str) -> Result<u64> {
        if path.is_empty() {
            return Ok(self.cfg.image_base); // LoadLibrary(NULL) → the exe itself
        }
        // Resolve API-set contract names before any look-up so that, e.g.,
        // LoadLibrary("api-ms-win-crt-runtime-l1-1-0.dll") returns the handle
        // for ucrtbase exactly as if ucrtbase had been requested directly.
        let name = canonical_name(&base_name(path));

        if let Some(&h) = self.dll.by_name.get(&name) {
            // Already loaded: a real plugin has its ref count incremented (an
            // explicit LoadLibrary pins it); an emulated system DLL just
            // returns its synthetic handle.
            if let Some(m) = self.dll.modules.iter_mut().find(|m| m.name == name) {
                m.ref_count = m.ref_count.saturating_add(1);
            }
            return Ok(h);
        }

        // Emulated system DLL → synthetic handle.
        if EMULATED.contains(&name.as_str()) {
            return Ok(self.system_handle(name));
        }

        // Plugin DLL: load its real bytes (and dependencies) from the sandbox.
        self.dll.pending_dllmain.clear();
        match self.load_plugin(mem, path, &name) {
            Ok(Some(base)) => Ok(base),
            _ => Ok(0),
        }
    }

    /// The handle of an already-loaded (or emulated) module, without loading a
    /// plugin from disk. `GetModuleHandle` semantics: 0 if not present. The
    /// main image and every loaded plugin are visible (they walk the same
    /// module table the `PEB.Ldr` lists reflect).
    pub(crate) fn module_handle(&mut self, path: &str) -> u64 {
        let name = canonical_name(&base_name(path));
        if let Some(&h) = self.dll.by_name.get(&name) {
            return h;
        }
        if EMULATED.contains(&name.as_str()) {
            return self.system_handle(name);
        }
        0
    }

    /// `FreeLibrary(hModule)`: decrement the ref count of a loaded plugin. We
    /// never actually unmap (the DLL arena is a bump allocator and a stale
    /// mapping is harmless), but the count is tracked honestly so a program
    /// that balances Load/Free sees the module drop to zero references. When a
    /// module's count reaches zero and it was attached, its
    /// `DllMain(DLL_PROCESS_DETACH)` is queued in `pending_detach` for the
    /// caller to drive (roadmap W0.7). Returns TRUE for any recognized handle,
    /// as the real API does.
    pub(crate) fn free_library(&mut self, hmodule: u64) -> bool {
        if hmodule == self.cfg.image_base {
            return true; // the exe itself is pinned
        }
        if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == hmodule) {
            m.ref_count = m.ref_count.saturating_sub(1);
            // Ref count hit zero: run DLL_PROCESS_DETACH exactly once (only if
            // the module actually ran its process-attach and hasn't detached).
            if m.ref_count == 0 && m.attached && m.entry != 0 {
                m.attached = false;
                let (entry, base) = (m.entry, m.base);
                self.dll.pending_detach.push((entry, base));
            }
            return true;
        }
        // A synthetic emulated-DLL handle: always succeeds, nothing to free.
        self.dll.system.contains_key(&hmodule) || self.dll.by_name.values().any(|&h| h == hmodule)
    }

    /// Mark a loaded plugin as having opted out of thread-attach/-detach
    /// notifications (`DisableThreadLibraryCalls`). Returns TRUE for any real
    /// loaded module (the main image and emulated system DLLs also succeed —
    /// they never get thread notifications anyway). Returns FALSE for an
    /// unrecognized handle, matching the real API (roadmap W0.7).
    pub(crate) fn disable_thread_library_calls(&mut self, hmodule: u64) -> bool {
        if hmodule == self.cfg.image_base {
            return true;
        }
        if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == hmodule) {
            m.thread_calls_disabled = true;
            return true;
        }
        self.dll.system.contains_key(&hmodule)
    }

    /// Mark every queued module (those whose `DllMain(DLL_PROCESS_ATTACH)` is
    /// about to run) as attached, so a later `FreeLibrary`/exit fires exactly
    /// one matching `DLL_PROCESS_DETACH`. Called by the `LoadLibrary` handler
    /// right before it drives the pending attach queue.
    pub(crate) fn mark_attached(&mut self, bases: &[u64]) {
        for &b in bases {
            if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == b) {
                m.attached = true;
            }
        }
    }

    /// The `(DllMain entry, hModule)` of every loaded plugin that should receive
    /// a thread notification `reason` (`DLL_THREAD_ATTACH`=2 / `DLL_THREAD_DETACH`=3),
    /// in **initialization order** (the order they were attached). Modules that
    /// called `DisableThreadLibraryCalls`, or have no entry point, are skipped
    /// (roadmap W0.7).
    pub(crate) fn thread_notify_targets(&self) -> Vec<(u64, u64)> {
        self.dll
            .modules
            .iter()
            .filter(|m| m.entry != 0 && m.attached && !m.thread_calls_disabled)
            .map(|m| (m.entry, m.base))
            .collect()
    }

    /// The `(DllMain entry, hModule)` of every still-attached loaded plugin, in
    /// **reverse initialization order** (dependents before dependencies — the
    /// order a real loader runs `DLL_PROCESS_DETACH` at process shutdown).
    /// Marks each as detached so it is reported at most once (roadmap W0.7).
    pub(crate) fn take_process_detach_targets(&mut self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for m in self.dll.modules.iter_mut().rev() {
            if m.entry != 0 && m.attached {
                m.attached = false;
                out.push((m.entry, m.base));
            }
        }
        out
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

    /// Load a plugin DLL and, first, recursively load every guest-bundled DLL
    /// it imports (dependency-order load, leaves-first). Returns the mapped
    /// base. Each successfully loaded module (this one and each dependency) is
    /// recorded in the module table, threaded onto the `PEB.Ldr` lists, and its
    /// `DllMain` queued in `pending_dllmain` in leaves-first order.
    fn load_plugin(&mut self, mem: &mut dyn Memory, path: &str, name: &str) -> Result<Option<u64>> {
        // Cycle guard: A imports B imports A must not recurse forever.
        if self.dll.loading.iter().any(|n| n == name) {
            // Already being loaded higher in the recursion; its table entry and
            // handle are recorded before its imports are resolved (below), so
            // by the time we get here it is visible via `by_name`.
            return Ok(self.dll.by_name.get(name).copied());
        }
        let Some(host) = self.find_dll_file(path, name) else {
            return Ok(None);
        };
        let Ok(bytes) = std::fs::read(&host) else {
            return Ok(None);
        };
        let Ok(mut image) = exemu_loader::parse(&bytes) else {
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

        // Apply base relocations for the load delta *before* mapping, using the
        // same exact fixup code as the main image (DIR64 + HIGHLOW, unknown
        // types rejected). A malformed `.reloc` aborts the load rather than
        // mapping a half-relocated image.
        let preferred = image.image_base;
        if let Err(e) =
            exemu_loader::apply_relocations(&mut image.sections, &image.relocations, preferred, base)
        {
            if self.cfg.trace {
                eprintln!("[exemu] plugin {name}: bad relocations ({e}); not loading");
            }
            self.dll.arena_next = base; // release the reservation
            return Ok(None);
        }

        // Map headers + relocated section data (the arena is pre-zeroed, so gaps
        // and uninitialized data are already zero).
        mem.write(base, &image.headers)?;
        for s in &image.sections {
            if !s.data.is_empty() {
                mem.write(base + s.rva as u64, &s.data)?;
            }
        }

        // Record this module's exports/handle *before* resolving its imports or
        // recursing into dependencies, so a self-referential or mutually
        // forwarding import (and a dependency cycle) can see it too.
        self.dll.exports.insert(base, image.exports.clone());
        self.dll.by_name.insert(name.to_string(), base);
        self.dll.loading.push(name.to_string());

        // Recursively load guest-bundled dependencies *first* (dependency-order
        // load). A dependency that is an emulated system DLL, or whose file is
        // not present in the sandbox, is skipped here — its imports fall back to
        // OS thunks, exactly as before. Deduplicate so we don't reload a DLL two
        // imports name.
        let mut dep_names: Vec<String> = Vec::new();
        for imp in &image.imports {
            let dep = canonical_name(&imp.dll);
            if EMULATED.contains(&dep.as_str())
                || self.dll.by_name.contains_key(&dep)
                || dep_names.contains(&dep)
            {
                continue;
            }
            dep_names.push(dep);
        }
        for dep in dep_names {
            // Only recurse when the dependency's real bytes exist in the
            // sandbox; otherwise leave it to the thunk fallback.
            if self.find_dll_file(&dep, &dep).is_some() {
                let _ = self.load_plugin(mem, &dep, &dep)?;
            }
        }

        // Resolve this DLL's own imports and patch its IAT. Imports of another
        // co-loaded guest image bind to that image's real export address
        // (forwarders chased); imports of an emulated system DLL get a thunk.
        for imp in &image.imports {
            let addr = self.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.write(base + imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
        }
        if self.cfg.trace {
            eprintln!(
                "[exemu] loaded plugin {name} at {base:#x} ({} exports, {} relocs)",
                image.exports.len(),
                image.relocations.len()
            );
        }

        // Record the module in the table and thread its Ldr entry onto the
        // loader lists (roadmap W0.6).
        let entry = if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 };
        let full_path = host.to_string_lossy().into_owned();
        self.dll.modules.push(Module {
            name: name.to_string(),
            full_path,
            base,
            size: image.size_of_image as u64,
            entry,
            ref_count: 1,
            ldr_entry: 0,
            thread_calls_disabled: false,
            attached: false,
        });
        self.ldr_add_module(mem, self.dll.modules.len() - 1)?;

        self.dll.loading.pop();

        // Queue this module's DllMain *after* its dependencies' (they were
        // pushed by the recursive calls above), so the pending list is
        // leaves-first — the caller drives them in that order.
        let run_dllmain = std::env::var_os("EXEMU_NO_DLLMAIN").is_none();
        if entry != 0 && run_dllmain {
            self.dll.pending_dllmain.push((entry, base));
        }
        Ok(Some(base))
    }

    /// Load the pinned Wine PE core set (`ntdll → kernelbase → kernel32 →
    /// ucrtbase`) as **real guest images** from `cfg.wine_dll_dir`, returning
    /// the mapped `ntdll` base (or `None` when the directory or any of the four
    /// files is absent — the caller then keeps the emulated-DLL path).
    ///
    /// Unlike [`Self::load_library`], this deliberately **suppresses the
    /// `EMULATED` short-circuit**: ntdll/kernelbase/kernel32 are on the emulated
    /// list (their functions are otherwise serviced by API thunks), so a normal
    /// `LoadLibrary` of them returns a synthetic handle and never maps bytes.
    /// Here we map the real bytes and record each module in `by_name`/`exports`
    /// *before* loading the next, so the moment ntdll+kernelbase are present,
    /// [`Self::resolve_import_addr`] (via [`GuestModules`]) resolves kernel32's
    /// imports of them to real export addresses — the emulated intercept is
    /// bypassed structurally, not by editing the `EMULATED` list. Loading
    /// strictly in dependency order (verified from the real import tables:
    /// ntdll imports nothing; kernelbase→ntdll; kernel32→kernelbase+ntdll;
    /// ucrtbase→kernel32+ntdll) guarantees every IAT slot binds to already-mapped
    /// predecessor code (roadmap W3.2).
    ///
    /// After ntdll maps, its unixlib is registered against its real base so the
    /// `__wine_unix_call` / `MemoryWineUnixFuncs` path finds it. Each module's
    /// `DllMain` is queued in `pending_dllmain` (leaves-first) but **not driven
    /// here** — on the boot path Wine's own `loader_init` (reached once
    /// `LdrInitializeThunk` runs) drives them under the loader lock; the caller
    /// may drain them via [`Self::run_pending_dllmains`] in the intermediate test.
    pub fn load_wine_core(&mut self, mem: &mut dyn Memory) -> Result<Option<u64>> {
        let Some(dir) = self.cfg.wine_dll_dir.clone() else {
            return Ok(None);
        };
        let dir = std::path::PathBuf::from(dir);
        // The four, strictly in dependency (leaves-first) order.
        const CORE: [&str; 4] = ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll"];
        // Guard: only take this path when all four files are actually present,
        // so a partial prefix never half-loads the core set.
        let paths: Vec<std::path::PathBuf> = CORE.iter().map(|n| dir.join(n)).collect();
        if paths.iter().any(|p| !p.is_file()) {
            return Ok(None);
        }

        self.dll.pending_dllmain.clear();
        let mut ntdll_base = None;
        for (name, host) in CORE.iter().zip(paths.iter()) {
            // Already mapped (an earlier core load, or a plugin) → reuse.
            let base = if let Some(&b) = self.dll.by_name.get(*name) {
                b
            } else {
                match self.load_core_image(mem, host, name)? {
                    Some(b) => b,
                    None => return Ok(None), // a malformed image aborts the whole set
                }
            };
            if *name == "ntdll.dll" {
                ntdll_base = Some(base);
                // Wire ntdll's unixlib so the `__wine_unix_call` fast path and
                // the `MemoryWineUnixFuncs` query resolve to it (roadmap W2.4/W2.5).
                self.register_ntdll_unixlib(base);
                // Plug the `__wine_unix_call_dispatcher` global. exemu maps ntdll
                // as a standalone PE with no unix side, so this pointer (which
                // Wine's unix loader would fill) is null; every PE-side
                // `__wine_unix_call` — including the very early debug-output path
                // (`__wine_dbg_write`) reached in `loader_init` — does
                // `call [__wine_unix_call_dispatcher]`, faulting on a null call.
                // Point it at the intercepted fast-path thunk so those calls land
                // on `WinOs::wine_unix_call` (roadmap W3.2 follow-up to W2.4).
                let thunk = self.wine_unix_call_thunk();
                let ptr_size = if self.cfg.is_64bit { 8 } else { 4 };
                mem.write(
                    base + crate::RVA_WINE_UNIX_CALL_DISPATCHER,
                    &thunk.to_le_bytes()[..ptr_size],
                )?;
            }
        }
        // Seed PEB.ApiSetMap so Wine's loader_init → build_import_name (which
        // reads it for every import) doesn't fault on a null pointer (W3.3).
        // Only on this (Wine-core) path, so the emulated corpus is untouched.
        self.seed_api_set_map(mem)?;
        Ok(ntdll_base)
    }

    /// Map + relocate + inter-bind + Ldr-thread one Wine-core PE from an explicit
    /// host path, recording it as a real module. Unlike [`Self::load_plugin`] this
    /// does **not** recurse into dependencies (the caller drives the core set in
    /// dependency order) and does **not** consult `EMULATED` (the whole point of
    /// the Wine-core path). Its imports bind via [`Self::resolve_import_addr`], so
    /// any predecessor already recorded in `by_name`/`exports` resolves to real
    /// code and the rest fall back to thunks (roadmap W3.2).
    fn load_core_image(
        &mut self,
        mem: &mut dyn Memory,
        host: &std::path::Path,
        name: &str,
    ) -> Result<Option<u64>> {
        let Ok(bytes) = std::fs::read(host) else {
            return Ok(None);
        };
        let Ok(mut image) = exemu_loader::parse(&bytes) else {
            return Ok(None);
        };

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

        let preferred = image.image_base;
        if let Err(e) =
            exemu_loader::apply_relocations(&mut image.sections, &image.relocations, preferred, base)
        {
            if self.cfg.trace {
                eprintln!("[exemu] wine-core {name}: bad relocations ({e}); not loading");
            }
            self.dll.arena_next = base;
            return Ok(None);
        }

        mem.write(base, &image.headers)?;
        for s in &image.sections {
            if !s.data.is_empty() {
                mem.write(base + s.rva as u64, &s.data)?;
            }
        }

        // Record exports/handle before binding imports so a self-referential
        // import (or a later core module) sees this one immediately.
        self.dll.exports.insert(base, image.exports.clone());
        self.dll.by_name.insert(name.to_string(), base);

        // Bind this DLL's imports to already-mapped predecessor code (real
        // export addresses), thunk-falling-back for anything not yet a guest
        // image.
        for imp in &image.imports {
            let addr = self.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.write(base + imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
        }
        if self.cfg.trace {
            eprintln!(
                "[exemu] loaded wine-core {name} at {base:#x} ({} exports, {} reloc blocks)",
                image.exports.len(),
                image.relocations.len()
            );
        }

        let entry = if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 };
        let full_path = host.to_string_lossy().into_owned();
        self.dll.modules.push(Module {
            name: name.to_string(),
            full_path,
            base,
            size: image.size_of_image as u64,
            entry,
            ref_count: 1,
            ldr_entry: 0,
            thread_calls_disabled: false,
            attached: false,
        });
        self.ldr_add_module(mem, self.dll.modules.len() - 1)?;

        if entry != 0 {
            self.dll.pending_dllmain.push((entry, base));
        }
        Ok(Some(base))
    }

    /// The mapped base of a loaded guest module by lower-cased base name (e.g.
    /// `"kernel32.dll"`), or `None` if it is not a real loaded image (never
    /// loaded, or only an emulated synthetic handle). Backs the W3.2 boot wiring
    /// and its intermediate test's inter-module-binding assertions.
    pub fn module_base(&self, name: &str) -> Option<u64> {
        let &base = self.dll.by_name.get(name)?;
        // Only a real mapped image has an export table recorded; a synthetic
        // emulated-DLL handle does not (it lives in `system`, not `exports`).
        self.dll.exports.contains_key(&base).then_some(base)
    }

    /// The absolute virtual address of `symbol` in the loaded `ntdll` image,
    /// resolved **by name** from its recorded export table (never a hardcoded
    /// RVA), or `None` if ntdll is not a loaded guest image or the symbol is
    /// absent/forwarded. Used by the boot path to seat `LdrInitializeThunk`
    /// (roadmap W3.2).
    pub fn ntdll_export(&self, symbol: &str) -> Option<u64> {
        let &base = self.dll.by_name.get("ntdll.dll")?;
        let exports = self.dll.exports.get(&base)?;
        let e = exports.iter().find(|e| e.name.as_deref() == Some(symbol) && e.forwarder.is_none())?;
        Some(base + e.rva as u64)
    }

    /// Drive every queued `DllMain(base, DLL_PROCESS_ATTACH, 0)` (the
    /// `pending_dllmain` chain, leaves-first) through the re-entrant callback
    /// machinery — the same drain [`Api::LoadLibraryApi`] runs, factored out so
    /// the boot-path load can prove the Wine-core DllMains are fault-free
    /// **without** wiring the full `LdrInitializeThunk` handoff (roadmap W3.2).
    /// Marks each module attached (so a later detach fires once) and seats the
    /// callback sequence; the caller then steps the CPU until it drains. A no-op
    /// (returns the CPU unchanged) when nothing is queued.
    pub fn run_pending_dllmains(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<()> {
        let pending = std::mem::take(&mut self.dll.pending_dllmain);
        if pending.is_empty() {
            return Ok(());
        }
        let bases: Vec<u64> = pending.iter().map(|&(_, b)| b).collect();
        self.mark_attached(&bases);
        let calls: Vec<(u64, Vec<u64>)> = pending
            .into_iter()
            .map(|(entry, base)| (entry, vec![base, 1 /* DLL_PROCESS_ATTACH */, 0]))
            .collect();
        // `invoke_callbacks` reads the drain-return address from `[rsp]`; the
        // caller has seated a sentinel there. Ignore the (Resume) outcome.
        self.invoke_callbacks(cpu, mem, calls, 0, 0, false)?;
        Ok(())
    }

    /// Resolve an imported `(dll, symbol)` to the address the IAT slot should
    /// hold. When the target DLL is a **co-loaded guest image**, this returns
    /// the real code address of that export — chasing export forwarders
    /// (`KERNEL32.foo → NTDLL.bar`) recursively, cycle-guarded. Otherwise it
    /// falls back to an OS thunk (roadmap W0.4).
    pub fn resolve_import_addr(&mut self, dll: &str, symbol: &ImportSymbol) -> u64 {
        let host: &str = match exemu_loader::resolve_api_set(dll) {
            Some(h) => h,
            None => dll,
        };
        let view = GuestModules { dll: &self.dll };
        match exemu_loader::resolve_import(&view, host, symbol) {
            exemu_loader::Resolved::GuestCode(addr) => addr,
            exemu_loader::Resolved::Fallback => self.resolve_import(host, symbol),
        }
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

    // ---- PEB.Ldr materialization (roadmap W0.6) --------------------------

    /// Seed the process loader lists in guest memory: build `PEB_LDR_DATA` with
    /// three empty (self-referential) list heads, store a pointer to it at
    /// `PEB.Ldr`, then thread the main image on as the first module. Called by
    /// the app once the PEB and main image are mapped. No-op when the app did
    /// not supply a PEB address.
    pub fn init_ldr(&mut self, mem: &mut dyn Memory) -> Result<()> {
        if self.cfg.peb_addr == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        // Carve the loader structures from the top of the DLL arena downward so
        // they never collide with a plugin image mapped from the bottom up.
        if self.dll.ldr_arena_next == 0 {
            self.dll.ldr_arena_next = self.cfg.dll_base + self.cfg.dll_size;
        }

        // PEB_LDR_DATA layout (public winternl.h / ntdef):
        //   64-bit: Length u32 @0, Initialized u8 @4, SsHandle ptr @8,
        //           InLoadOrderModuleList @0x10, InMemoryOrderModuleList @0x20,
        //           InInitializationOrderModuleList @0x30. Length = 0x58.
        //   32-bit: SsHandle @8, InLoadOrder @0x0c, InMemoryOrder @0x14,
        //           InInitializationOrder @0x1c. Length = 0x30.
        let ldr_size = if self.cfg.is_64bit { 0x58 } else { 0x30 };
        let ldr = self.ldr_alloc(ldr_size);
        self.dll.peb_ldr_data = ldr;
        // Length field.
        mem.write_u32(ldr, ldr_size as u32)?;
        // Initialized = TRUE.
        mem.write_u32(ldr + 4, 1)?;
        // The three list heads start empty (Flink == Blink == head).
        for off in self.ldr_list_offsets() {
            let head = ldr + off;
            self.write_ptr(mem, head, head)?;
            self.write_ptr(mem, head + ptr, head)?;
        }
        // Publish PEB.Ldr.
        self.write_ptr(mem, self.cfg.peb_addr + self.cfg.peb_ldr_off, ldr)?;

        // Populate the rest of the PEB fields Wine's ntdll probes (roadmap
        // W2.10): the OS version block, NtGlobalFlag, SessionId, BeingDebugged,
        // and a minimal RTL_USER_PROCESS_PARAMETERS reachable via
        // PEB.ProcessParameters. ImageBaseAddress is seeded by the app.
        self.seed_peb(mem)?;

        // Seed a real PEB.LoaderLock CRITICAL_SECTION (roadmap W0.7). ntdll's
        // loader takes this lock across every module-graph mutation; a guest
        // that queries it (anti-debug, `ntdll!LdrLockLoaderLock`) must see a
        // valid, initialized RTL_CRITICAL_SECTION, and it must read as *held*
        // while a DllMain runs (a DllMain that re-enters the loader recurses on
        // it). Public winnt.h RTL_CRITICAL_SECTION layout:
        //   DebugInfo ptr @0, LockCount i32 @ptr, RecursionCount i32 @ptr+4,
        //   OwningThread ptr @ptr+8, LockSemaphore ptr @ptr+8+ptr,
        //   SpinCount usize @ptr+8+2*ptr. Size 0x28 (64) / 0x18 (32).
        let cs_size = if self.cfg.is_64bit { 0x28 } else { 0x18 };
        let cs = self.ldr_alloc(cs_size);
        self.dll.loader_lock = cs;
        // Unowned, uncontended: DebugInfo NULL, LockCount -1 (the "not locked"
        // value modern ntdll uses), RecursionCount 0, OwningThread 0.
        self.write_ptr(mem, cs, 0)?; // DebugInfo
        mem.write_u32(cs + ptr, (-1_i32) as u32)?; // LockCount
        mem.write_u32(cs + ptr + 4, 0)?; // RecursionCount
        self.write_ptr(mem, cs + ptr + 8, 0)?; // OwningThread
        self.write_ptr(mem, cs + ptr + 8 + ptr, 0)?; // LockSemaphore
        self.write_ptr(mem, cs + ptr + 8 + 2 * ptr, 0)?; // SpinCount
        if self.cfg.peb_loaderlock_off != 0 {
            self.write_ptr(mem, self.cfg.peb_addr + self.cfg.peb_loaderlock_off, cs)?;
        }

        // Thread the main image on as the first loader entry, so a walk of the
        // list starting at PEB.Ldr finds the exe just like real NT.
        let name = if self.cfg.image_name.is_empty() {
            "program.exe".to_string()
        } else {
            self.cfg.image_name.clone()
        };
        let full = self.cfg.module_path_w.clone();
        self.ldr_thread_entry(
            mem,
            self.cfg.image_base,
            self.cfg.image_size,
            self.cfg.image_entry,
            &name,
            &full,
        )?;
        Ok(())
    }

    /// Populate the PEB fields Wine's PE `ntdll` reads beyond `Ldr` +
    /// `ImageBaseAddress` (roadmap W2.10). The PEB is a freshly zero-mapped page,
    /// so any field left unwritten reads back 0 (its correct default); this
    /// writes the ones that must hold a meaningful value.
    ///
    /// Offsets are the published 64-/32-bit PEB layout. `NtGlobalFlag` @0xBC (64)
    /// is confirmed from the pinned guest `ntdll.dll` (`RtlGetNtGlobalFlags`
    /// reads `gs:[0x30]`→`[+0x60]`(PEB)→`[+0xBC]`); the OS-version block,
    /// `SessionId` and `BeingDebugged` are the documented winternl PEB fields.
    /// `ProcessParameters` points at a full `RTL_USER_PROCESS_PARAMETERS` built
    /// by [`Self::build_process_parameters`] (verified against the pinned Wine
    /// ntdll) — ImagePathName/CommandLine/CurrentDirectory/DllPath UNICODE_STRINGs,
    /// a real Environment block + EnvironmentSize, Flags=NORMALIZED.
    fn seed_peb(&mut self, mem: &mut dyn Memory) -> Result<()> {
        let peb = self.cfg.peb_addr;
        let (
            off_being_debugged,
            off_nt_global_flag,
            off_os_major,
            off_os_minor,
            off_os_build,
            off_os_platform,
            off_session_id,
            off_process_params,
        ) = if self.cfg.is_64bit {
            (0x02u64, 0xBC, 0x118, 0x11C, 0x120, 0x124, 0x2C0, 0x20)
        } else {
            // 32-bit PEB: NtGlobalFlag @0x68, version block @0xA4.., SessionId
            // @0x1D4, BeingDebugged @0x02, ProcessParameters @0x10.
            (0x02, 0x68, 0xA4, 0xA8, 0xAC, 0xB0, 0x1D4, 0x10)
        };

        // Not being debugged (a common anti-debug read).
        mem.write_u8(peb + off_being_debugged, 0)?;
        // NtGlobalFlag: 0 — no ntdll debug heap / loader-snap flags set, which is
        // what a normally-launched process sees (a nonzero value here flips ntdll
        // into debug-heap paths a bare guest cannot satisfy).
        mem.write_u32(peb + off_nt_global_flag, 0)?;
        // OS version block: report Windows 10 (10.0.19045) so version gates in the
        // guest CRT/ntdll take their modern paths. OSBuildNumber is a u16.
        mem.write_u32(peb + off_os_major, 10)?;
        mem.write_u32(peb + off_os_minor, 0)?;
        mem.write_u16(peb + off_os_build, 19045)?;
        mem.write_u32(peb + off_os_platform, 2)?; // VER_PLATFORM_WIN32_NT
        // Session 0 (the console/services session in a single-session model).
        mem.write_u32(peb + off_session_id, 0)?;

        // A full RTL_USER_PROCESS_PARAMETERS, pointed at by PEB.ProcessParameters.
        let pp = self.build_process_parameters(mem)?;
        self.write_ptr(mem, peb + off_process_params, pp)?;
        Ok(())
    }

    /// Build a full, correctly-sized `RTL_USER_PROCESS_PARAMETERS` in the loader
    /// arena and return its guest address (roadmap W3.6).
    ///
    /// **Layout is VERIFIED against the pinned Wine 11.0 `ntdll.dll`** (ImageBase
    /// 0x170000000), not merely the public winternl.h stub:
    ///   * `init_user_process_params` @ RVA 0x51d30 reads `EnvironmentSize` at
    ///     **`+0x3f0`** (u64, `movq 0x3f0(%rdx),%rsi`), the `Environment` pointer
    ///     at **`+0x80`**, and a scalar at **`+0x408`** (u32) — these three are the
    ///     deep reads that faulted the earlier 0x80-byte stub (the boot's 5743-instr
    ///     blocker was the `+0x3f0` read; the design's guess that this was
    ///     `HeapPartitionName.Buffer` was WRONG — it is `EnvironmentSize`).
    ///   * `alloc_process_params` @ RVA 0x433c0 lays the buffer area at **`+0x410`**
    ///     (`leaq 0x410(%rax),%rcx`) — so the header is exactly **0x410 bytes** —
    ///     and writes `EnvironmentSize` to `+0x3f0`, `Flags` NORMALIZED=1 to `+0x08`.
    ///   * `RtlNormalizeProcessParams` @ RVA 0x2dce0 de-normalizes the `.Buffer`
    ///     fields at **0x40,0x58,0x68,0x78,0xb8,0xc8,0xd8,0xe8** *only when
    ///     `Flags & NORMALIZED(0x1)` is clear* (it early-returns otherwise). We set
    ///     **NORMALIZED and store ABSOLUTE Buffer pointers**, so normalization is a
    ///     no-op and every buffer stays valid — matching a live process.
    ///
    /// The x86 header offsets are the public 32-bit layout (half-width scalars,
    /// UNICODE_STRINGs at 0x24/0x30/0x38/0x40, Environment @0x48, size 0x290); the
    /// Wine-boot path is x64-only, so the 32-bit shape is used only by the
    /// emulated corpus, whose CRT reads just ImagePathName/CommandLine.
    fn build_process_parameters(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        if self.cfg.is_64bit {
            self.build_process_parameters_64(mem)
        } else {
            self.build_process_parameters_32(mem)
        }
    }

    fn build_process_parameters_64(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        // Total size: the 0x410-byte header (verified) plus a small tail so the
        // `+0x408` scalar and any incidental reads land inside the allocation.
        const PP_SIZE: u64 = 0x420;
        let pp = self.ldr_alloc(PP_SIZE);
        // The arena is bump-allocated (never guaranteed zero on reuse); zero the
        // whole block so every unset tail field — HeapPartitionName region,
        // RedirectionDllName, threadpool masks, EnvironmentVersion — reads 0.
        let zero = [0u8; PP_SIZE as usize];
        mem.write(pp, &zero)?;

        // MaximumLength @0x00 / Length @0x04: the header size (public convention;
        // the guest re-derives them when it re-allocs, so exact values are inert).
        mem.write_u32(pp, PP_SIZE as u32)?;
        mem.write_u32(pp + 0x04, PP_SIZE as u32)?;
        // Flags @0x08 = NORMALIZED (0x1): our Buffer pointers below are ABSOLUTE,
        // so RtlNormalizeProcessParams must treat them as already-normalized.
        mem.write_u32(pp + 0x08, 0x1)?;
        // DebugFlags @0x0C, ConsoleFlags @0x18: 0 (default).
        // ConsoleHandle @0x10, StandardInput @0x20, StandardOutput @0x28,
        // StandardError @0x30: left 0 (the real console is wired in W3.4; a null
        // std handle is the correct "not yet a console process" value here).

        // CurrentDirectory.DosPath @0x38 (UNICODE_STRING, Handle @0x48): a real
        // "C:\" so RtlSetCurrentDirectory_U (reads Buffer @0x40) can parse it.
        let (cd_buf, cd_len) = self.ldr_write_wstr(mem, "C:\\")?;
        self.write_unicode_string(mem, pp + 0x38, cd_buf, cd_len)?;
        // DllPath @0x50: the system search path.
        let (dll_buf, dll_len) = self.ldr_write_wstr(mem, "C:\\windows\\system32")?;
        self.write_unicode_string(mem, pp + 0x50, dll_buf, dll_len)?;
        // ImagePathName @0x60 ← the module path ("C:\\…").
        let (img_buf, img_len) = self.ldr_write_wstr(mem, &self.cfg.module_path_w.clone())?;
        self.write_unicode_string(mem, pp + 0x60, img_buf, img_len)?;
        // CommandLine @0x70 ← the app's UTF-16 command line, or the module path.
        if self.cfg.cmdline_ptr_w != 0 {
            let cmd_len = wstr_byte_len(mem, self.cfg.cmdline_ptr_w)?;
            self.write_unicode_string(mem, pp + 0x70, self.cfg.cmdline_ptr_w, cmd_len)?;
        } else {
            self.write_unicode_string(mem, pp + 0x70, img_buf, img_len)?;
        }

        // Environment @0x80 + EnvironmentSize @0x3f0: a valid UTF-16
        // `name=value\0…\0\0` block. init_user_process_params memcpy's exactly
        // EnvironmentSize bytes from Environment, so the two must agree.
        let (env_buf, env_bytes) = self.write_env_block(mem)?;
        self.write_ptr(mem, pp + 0x80, env_buf)?;
        mem.write_u64(pp + 0x3f0, env_bytes)?;

        // WindowTitle @0xb0, DesktopInfo @0xc0, ShellInfo @0xd0, RuntimeData @0xe0:
        // short but valid empty UNICODE_STRINGs (Length 0, a NUL Buffer) so the
        // loader's copy of them is well-formed. **These offsets are VERIFIED from
        // init_user_process_params @ 0x51d30, which passes `leaq 0xb0/0xc0/0xd0/
        // 0xe0(%rbx)` to alloc_process_params — the design's 0xc8/0xd8/0xe8 were
        // the *Buffer* fields (struct+8), not the struct starts.** A UNICODE_STRING
        // mis-placed at 0xc8 would overwrite DesktopInfo@0xc0's Buffer and make the
        // loader memcpy from a garbage source (the 0x20000 fault seen mid-bringup).
        let (empty_buf, _) = self.ldr_write_wstr(mem, "")?;
        for off in [0xb0u64, 0xc0, 0xd0, 0xe0] {
            self.write_unicode_string(mem, pp + off, empty_buf, 0)?;
        }
        // +0x408 scalar: 0 (EnvironmentVersion / a flag — read but its value is
        // simply copied forward; 0 is the launched-process default).
        Ok(pp)
    }

    fn build_process_parameters_32(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        // 32-bit RTL_USER_PROCESS_PARAMETERS (public layout): scalars at half
        // width, UNICODE_STRINGs at CurrentDirectory 0x24, DllPath 0x30,
        // ImagePathName 0x38, CommandLine 0x40, Environment @0x48. Only the
        // emulated corpus uses this (the Wine-boot path is x64); its CRT reads
        // only ImagePathName + CommandLine, so a zero-filled 0x290-byte block
        // with those two populated is sufficient and correctly sized.
        const PP_SIZE: u64 = 0x290;
        let pp = self.ldr_alloc(PP_SIZE);
        let zero = [0u8; PP_SIZE as usize];
        mem.write(pp, &zero)?;
        mem.write_u32(pp, PP_SIZE as u32)?; // MaximumLength
        mem.write_u32(pp + 0x04, PP_SIZE as u32)?; // Length
        mem.write_u32(pp + 0x08, 0x1)?; // Flags = NORMALIZED
        let (img_buf, img_len) = self.ldr_write_wstr(mem, &self.cfg.module_path_w.clone())?;
        self.write_unicode_string(mem, pp + 0x38, img_buf, img_len)?;
        if self.cfg.cmdline_ptr_w != 0 {
            let cmd_len = wstr_byte_len(mem, self.cfg.cmdline_ptr_w)?;
            self.write_unicode_string(mem, pp + 0x40, self.cfg.cmdline_ptr_w, cmd_len)?;
        } else {
            self.write_unicode_string(mem, pp + 0x40, img_buf, img_len)?;
        }
        let (env_buf, _env_bytes) = self.write_env_block(mem)?;
        self.write_ptr(mem, pp + 0x48, env_buf)?;
        Ok(pp)
    }

    /// Write the process environment (`name=value\0…\0\0`, UTF-16) into the loader
    /// arena from `self.env`. Returns (buffer address, byte length including the
    /// double-NUL terminator) — the exact size `init_user_process_params` copies.
    fn write_env_block(&mut self, mem: &mut dyn Memory) -> Result<(u64, u64)> {
        let units = self.env_block_utf16();
        let byte_len = (units.len() * 2) as u64;
        let addr = self.ldr_alloc(byte_len.max(2));
        for (i, u) in units.iter().enumerate() {
            mem.write_u16(addr + (i * 2) as u64, *u)?;
        }
        Ok((addr, byte_len))
    }

    /// Seed a valid v6 `API_SET_NAMESPACE` in guest memory and publish it at
    /// `PEB.ApiSetMap` (x64 PEB `+0x68`, x86 PEB `+0x38` — verified from the
    /// pinned Wine `ntdll`'s `build_import_name`: `mov rax,gs:[0x30];
    /// mov rax,[rax+0x60]; mov rdi,[rax+0x68]`, roadmap W3.3).
    ///
    /// Wine's `loader_init → build_module → build_import_name` reads
    /// `PEB.ApiSetMap` for **every** imported DLL name; an unseeded (null/
    /// unmapped) pointer faults the loader. The four Wine core DLLs import each
    /// other by real name (no api-set contract), so a *valid, non-null*
    /// namespace is all the boot path needs — but we populate it (via
    /// [`crate::apiset`], reusing the W0.5 resolver's host mappings) so a guest
    /// exe that imports `api-ms-win-*` contracts gets the right host substituted.
    ///
    /// Placed on the **Wine-boot path only** (called from [`Self::load_wine_core`]),
    /// so the emulated corpus's guest image is byte-for-byte unchanged.
    pub(crate) fn seed_api_set_map(&mut self, mem: &mut dyn Memory) -> Result<()> {
        if self.cfg.peb_addr == 0 {
            return Ok(()); // no PEB (headless path with Ldr disabled)
        }
        // Idempotent: a second core load reuses the already-seeded namespace.
        if self.dll.api_set_map != 0 {
            return Ok(());
        }
        let ns = crate::apiset::build_populated_namespace();
        // Carve the blob from the loader arena (top-down, same region as the
        // PEB.Ldr structures — mapped RW on the boot path).
        let base = self.ldr_alloc(ns.bytes.len() as u64);
        mem.write(base, &ns.bytes)?;
        self.dll.api_set_map = base;
        // PEB.ApiSetMap.
        let off = if self.cfg.is_64bit { 0x68u64 } else { 0x38 };
        self.write_ptr(mem, self.cfg.peb_addr + off, base)?;
        Ok(())
    }

    /// Guest address of the seeded `API_SET_NAMESPACE` (`PEB.ApiSetMap`), or 0
    /// when it was never seeded (the emulated path). For tests/tools.
    pub fn api_set_map(&self) -> u64 {
        self.dll.api_set_map
    }

    /// Acquire the process `PEB.LoaderLock` for a loader operation, updating the
    /// guest `RTL_CRITICAL_SECTION` so a guest that reads it sees the lock held
    /// by the current thread. Recursive (a `DllMain` that re-enters the loader).
    /// A no-op when the loader lock was never seeded (headless test path).
    pub(crate) fn enter_loader_lock(&mut self, mem: &mut dyn Memory) -> Result<()> {
        let cs = self.dll.loader_lock;
        if cs == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        self.dll.loader_lock_depth += 1;
        // LockCount = -1 + threads_waiting_plus_owner; for a single-threaded
        // uncontended acquire, ntdll bumps it to 0 on the first entry.
        mem.write_u32(cs + ptr, (self.dll.loader_lock_depth - 1) as u32)?;
        mem.write_u32(cs + ptr + 4, self.dll.loader_lock_depth as u32)?; // RecursionCount
        let owner = u64::from(self.current_tid);
        self.write_ptr(mem, cs + ptr + 8, owner)?; // OwningThread
        Ok(())
    }

    /// Release one level of the loader lock acquired by [`Self::enter_loader_lock`].
    pub(crate) fn leave_loader_lock(&mut self, mem: &mut dyn Memory) -> Result<()> {
        let cs = self.dll.loader_lock;
        if cs == 0 || self.dll.loader_lock_depth == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        self.dll.loader_lock_depth -= 1;
        if self.dll.loader_lock_depth == 0 {
            mem.write_u32(cs + ptr, (-1_i32) as u32)?; // LockCount → unlocked
            mem.write_u32(cs + ptr + 4, 0)?; // RecursionCount
            self.write_ptr(mem, cs + ptr + 8, 0)?; // OwningThread cleared
        } else {
            mem.write_u32(cs + ptr, (self.dll.loader_lock_depth - 1) as u32)?;
            mem.write_u32(cs + ptr + 4, self.dll.loader_lock_depth as u32)?;
        }
        Ok(())
    }

    /// The offsets of the three `LIST_ENTRY` list heads inside `PEB_LDR_DATA`.
    fn ldr_list_offsets(&self) -> [u64; 3] {
        if self.cfg.is_64bit {
            [0x10, 0x20, 0x30]
        } else {
            [0x0c, 0x14, 0x1c]
        }
    }

    /// The offsets of the three `LIST_ENTRY` links inside `LDR_DATA_TABLE_ENTRY`
    /// (InLoadOrderLinks / InMemoryOrderLinks / InInitializationOrderLinks).
    fn ldr_entry_link_offsets(&self) -> [u64; 3] {
        if self.cfg.is_64bit {
            [0x00, 0x10, 0x20]
        } else {
            [0x00, 0x08, 0x10]
        }
    }

    /// Bump-allocate `size` bytes for a loader structure from the top of the
    /// DLL arena downward (8-byte aligned).
    fn ldr_alloc(&mut self, size: u64) -> u64 {
        let aligned = size.div_ceil(8) * 8;
        self.dll.ldr_arena_next -= aligned;
        self.dll.ldr_arena_next
    }

    /// Add the plugin module at `modules[idx]` to the loader lists.
    fn ldr_add_module(&mut self, mem: &mut dyn Memory, idx: usize) -> Result<()> {
        if self.cfg.peb_addr == 0 || self.dll.peb_ldr_data == 0 {
            return Ok(()); // Ldr not initialized (headless test path)
        }
        let m = &self.dll.modules[idx];
        let (base, size, entry) = (m.base, m.size, m.entry);
        let name = m.name.clone();
        let full = m.full_path.clone();
        let ldr_entry = self.ldr_thread_entry(mem, base, size, entry, &name, &full)?;
        self.dll.modules[idx].ldr_entry = ldr_entry;
        Ok(())
    }

    /// Allocate an `LDR_DATA_TABLE_ENTRY` for a module, populate its public
    /// fields (DllBase, EntryPoint, SizeOfImage, FullDllName, BaseDllName) and
    /// append it to the tail of all three loader lists. Returns the entry's
    /// guest address.
    fn ldr_thread_entry(
        &mut self,
        mem: &mut dyn Memory,
        base: u64,
        size: u64,
        entry: u64,
        base_name: &str,
        full_path: &str,
    ) -> Result<u64> {
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        // LDR_DATA_TABLE_ENTRY public field offsets (winternl.h / ntdef):
        //   64: DllBase 0x30, EntryPoint 0x38, SizeOfImage 0x40,
        //       FullDllName 0x48 (UNICODE_STRING), BaseDllName 0x58. Size 0x68.
        //   32: DllBase 0x18, EntryPoint 0x1c, SizeOfImage 0x20,
        //       FullDllName 0x24, BaseDllName 0x2c. Size 0x38.
        let (off_dllbase, off_entry, off_size, off_full, off_basename, entry_size) =
            if self.cfg.is_64bit {
                (0x30u64, 0x38, 0x40, 0x48, 0x58, 0x68u64)
            } else {
                (0x18, 0x1c, 0x20, 0x24, 0x2c, 0x38)
            };
        let te = self.ldr_alloc(entry_size);

        // UNICODE_STRING name buffers (NUL-terminated UTF-16, as NT keeps them).
        let full_buf = self.ldr_write_wstr(mem, full_path)?;
        let base_buf = self.ldr_write_wstr(mem, base_name)?;

        mem.write(te + off_dllbase, &base.to_le_bytes()[..ptr as usize])?;
        mem.write(te + off_entry, &entry.to_le_bytes()[..ptr as usize])?;
        mem.write(te + off_size, &size.to_le_bytes()[..ptr as usize])?;
        self.write_unicode_string(mem, te + off_full, full_buf.0, full_buf.1)?;
        self.write_unicode_string(mem, te + off_basename, base_buf.0, base_buf.1)?;

        // Append to the tail of each list. Both the entry link (in the
        // LDR_DATA_TABLE_ENTRY) and the corresponding list head are at the
        // parallel offsets in the two structs.
        let list_offs = self.ldr_list_offsets();
        let link_offs = self.ldr_entry_link_offsets();
        for (head_off, link_off) in list_offs.into_iter().zip(link_offs) {
            let head = self.dll.peb_ldr_data + head_off;
            let link = te + link_off;
            self.list_insert_tail(mem, head, link, ptr)?;
        }
        Ok(te)
    }

    /// Insert `entry` (a `LIST_ENTRY` at `link`) at the tail of the doubly
    /// linked list whose head `LIST_ENTRY` is at `head`.
    /// `head.Blink` is the current tail. Standard `InsertTailList`.
    fn list_insert_tail(&self, mem: &mut dyn Memory, head: u64, link: u64, ptr: u64) -> Result<()> {
        let blink = self.read_ptr(mem, head + ptr)?; // old tail
        // link.Flink = head; link.Blink = oldtail
        self.write_ptr(mem, link, head)?;
        self.write_ptr(mem, link + ptr, blink)?;
        // oldtail.Flink = link
        self.write_ptr(mem, blink, link)?;
        // head.Blink = link
        self.write_ptr(mem, head + ptr, link)?;
        Ok(())
    }

    /// Write a UTF-16 NUL-terminated copy of `s` into the loader arena. Returns
    /// (buffer address, byte length excluding the terminator).
    fn ldr_write_wstr(&mut self, mem: &mut dyn Memory, s: &str) -> Result<(u64, u16)> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (units.len() * 2) as u16;
        let addr = self.ldr_alloc((units.len() * 2 + 2) as u64);
        for (i, u) in units.iter().enumerate() {
            mem.write_u16(addr + (i * 2) as u64, *u)?;
        }
        mem.write_u16(addr + units.len() as u64 * 2, 0)?; // NUL terminator
        Ok((addr, byte_len))
    }

    /// Write a `UNICODE_STRING { Length, MaximumLength, Buffer }` at `at`.
    fn write_unicode_string(&self, mem: &mut dyn Memory, at: u64, buffer: u64, byte_len: u16) -> Result<()> {
        mem.write_u16(at, byte_len)?; // Length (bytes, no NUL)
        mem.write_u16(at + 2, byte_len + 2)?; // MaximumLength (incl NUL)
        // On 64-bit there is 4 bytes of padding before the 8-byte Buffer ptr.
        let buf_off = if self.cfg.is_64bit { 8 } else { 4 };
        let ptr = if self.cfg.is_64bit { 8 } else { 4 };
        mem.write(at + buf_off, &buffer.to_le_bytes()[..ptr])?;
        Ok(())
    }
}

/// A read-only view of the loaded *guest* modules for the import resolver.
/// Only real plugin images (those with an export table recorded in
/// `Loader::exports`) are visible; emulated system DLLs are deliberately absent
/// so their imports fall through to OS thunks.
struct GuestModules<'a> {
    dll: &'a Loader,
}

impl exemu_loader::ModuleSet for GuestModules<'_> {
    fn module(&self, dll: &str) -> Option<exemu_loader::LoadedModule<'_>> {
        let &base = self.dll.by_name.get(dll)?;
        let exports = self.dll.exports.get(&base)?;
        Some(exemu_loader::LoadedModule { base, exports })
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

/// Byte length (excluding the terminating NUL) of the NUL-terminated UTF-16
/// string at `addr`, for building a `UNICODE_STRING` over an already-mapped
/// buffer. Bounded so a missing terminator cannot loop forever (32 KiB covers
/// the Windows MAX_PATH-based command lines the loader deals with).
fn wstr_byte_len(mem: &dyn Memory, addr: u64) -> Result<u16> {
    let mut units = 0u64;
    while units < 0x4000 {
        if mem.read_u16(addr + units * 2)? == 0 {
            break;
        }
        units += 1;
    }
    Ok((units * 2) as u16)
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
