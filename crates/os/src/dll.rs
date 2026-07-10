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

use exemu_core::{Export, ImportSymbol, Memory, Result};

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
    /// that balances Load/Free sees the module drop to zero references. Returns
    /// TRUE for any recognized handle, as the real API does.
    pub(crate) fn free_library(&mut self, hmodule: u64) -> bool {
        if hmodule == self.cfg.image_base {
            return true; // the exe itself is pinned
        }
        if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == hmodule) {
            m.ref_count = m.ref_count.saturating_sub(1);
            return true;
        }
        // A synthetic emulated-DLL handle: always succeeds, nothing to free.
        self.dll.system.contains_key(&hmodule) || self.dll.by_name.values().any(|&h| h == hmodule)
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
