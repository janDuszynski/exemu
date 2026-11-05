use std::collections::HashMap;

use exemu_core::{guest_addr, checked_align_up, CpuState, Export, ImageLoader, ImportSymbol, Memory, ModuleExports, Result};

use crate::WinOs;

const PAGE: u64 = 0x1000;

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

struct Module {
    name: String,
    full_path: String,
    base: u64,
    size: u64,
    entry: u64,
    ref_count: u32,
    ldr_entry: u64,
    thread_calls_disabled: bool,
    attached: bool,
}

struct ImageView {
    base: u64,
    size: u64,
    name: Option<String>,
}

#[derive(Default)]
pub(crate) struct Loader {
    arena_next: u64,
    by_name: HashMap<String, u64>,
    exports: HashMap<u64, Vec<Export>>,
    modules: Vec<Module>,
    image_views: Vec<ImageView>,
    system: HashMap<u64, String>,
    next_system: u64,
    pub(crate) pending_dllmain: Vec<(u64, u64)>,
    ldr_arena_next: u64,
    peb_ldr_data: u64,
    loading: Vec<String>,
    pub(crate) pending_detach: Vec<(u64, u64)>,
    loader_lock: u64,
    loader_lock_depth: i32,
    api_set_map: u64,
}

fn base_name(path: &str) -> String {
    let last = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let mut n = last.to_ascii_lowercase();
    if !n.ends_with(".dll") && !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

fn canonical_name(images: &dyn ImageLoader, raw: &str) -> String {
    match images.api_set_host(raw) {
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

impl WinOs {
    pub fn set_image_loader(&mut self, images: Box<dyn ImageLoader>) {
        self.images = images;
    }

    pub(crate) fn load_library(&mut self, mem: &mut dyn Memory, path: &str) -> Result<u64> {
        if path.is_empty() {
            return Ok(self.cfg.image_base);
        }
        let name = canonical_name(&*self.images, &base_name(path));

        if let Some(&h) = self.dll.by_name.get(&name) {
            if let Some(m) = self.dll.modules.iter_mut().find(|m| m.name == name) {
                m.ref_count = m.ref_count.saturating_add(1);
            }
            return Ok(h);
        }

        if EMULATED.contains(&name.as_str()) {
            return Ok(self.system_handle(name));
        }

        self.dll.pending_dllmain.clear();
        match self.load_plugin(mem, path, &name) {
            Ok(Some(base)) => Ok(base),
            _ => Ok(0),
        }
    }

    pub(crate) fn module_handle(&mut self, path: &str) -> u64 {
        let name = canonical_name(&*self.images, &base_name(path));
        if let Some(&h) = self.dll.by_name.get(&name) {
            return h;
        }
        if EMULATED.contains(&name.as_str()) {
            return self.system_handle(name);
        }
        0
    }

    pub(crate) fn free_library(&mut self, hmodule: u64) -> bool {
        if hmodule == self.cfg.image_base {
            return true;
        }
        if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == hmodule) {
            m.ref_count = m.ref_count.saturating_sub(1);
            if m.ref_count == 0 && m.attached && m.entry != 0 {
                m.attached = false;
                let (entry, base) = (m.entry, m.base);
                self.dll.pending_detach.push((entry, base));
            }
            return true;
        }
        self.dll.system.contains_key(&hmodule) || self.dll.by_name.values().any(|&h| h == hmodule)
    }

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

    pub(crate) fn mark_attached(&mut self, bases: &[u64]) {
        for &b in bases {
            if let Some(m) = self.dll.modules.iter_mut().find(|m| m.base == b) {
                m.attached = true;
            }
        }
    }

    pub(crate) fn thread_notify_targets(&self) -> Vec<(u64, u64)> {
        self.dll
            .modules
            .iter()
            .filter(|m| m.entry != 0 && m.attached && !m.thread_calls_disabled)
            .map(|m| (m.entry, m.base))
            .collect()
    }

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
        if self.dll.loading.iter().any(|n| n == name) {
            return Ok(self.dll.by_name.get(name).copied());
        }
        let Some(host) = self.find_dll_file(path, name) else {
            return Ok(None);
        };
        let Ok(bytes) = std::fs::read(&host) else {
            return Ok(None);
        };
        let Ok(mut image) = self.images.parse(&bytes) else {
            return Ok(None);
        };

        if self.dll.arena_next == 0 {
            self.dll.arena_next = self.cfg.dll_base;
        }
        let (Some(base), Some(img_size)) = (
            checked_align_up(self.dll.arena_next, PAGE),
            checked_align_up(image.size_of_image as u64, PAGE),
        ) else {
            return Ok(None);
        };
        let img_size = img_size.max(PAGE);
        let arena_end = self.cfg.dll_base.saturating_add(self.cfg.dll_size);
        let Some(next) = base.checked_add(img_size).filter(|&end| end <= arena_end) else {
            return Ok(None);
        };
        self.dll.arena_next = next;
        let ptr_size = if self.cfg.is_64bit { 8 } else { 4 };

        let preferred = image.image_base;
        if let Err(e) =
            self.images.apply_relocations(&mut image.sections, &image.relocations, preferred, base)
        {
            if self.cfg.trace {
                eprintln!("[exemu] plugin {name}: bad relocations ({e}); not loading");
            }
            self.dll.arena_next = base;
            return Ok(None);
        }

        mem.write(base, &image.headers)?;
        for s in &image.sections {
            if !s.data.is_empty() {
                mem.write_at(base, s.rva as u64, &s.data)?;
            }
        }

        self.dll.exports.insert(base, image.exports.clone());
        self.dll.by_name.insert(name.to_string(), base);
        self.dll.loading.push(name.to_string());

        let mut dep_names: Vec<String> = Vec::new();
        for imp in &image.imports {
            let dep = canonical_name(&*self.images, &imp.dll);
            if EMULATED.contains(&dep.as_str())
                || self.dll.by_name.contains_key(&dep)
                || dep_names.contains(&dep)
            {
                continue;
            }
            dep_names.push(dep);
        }
        for dep in dep_names {
            if self.find_dll_file(&dep, &dep).is_some() {
                let _ = self.load_plugin(mem, &dep, &dep)?;
            }
        }

        for imp in &image.imports {
            let addr = self.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.write_at(base, imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
        }
        if self.cfg.trace {
            eprintln!(
                "[exemu] loaded plugin {name} at {base:#x} ({} exports, {} relocs)",
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

        self.dll.loading.pop();

        let run_dllmain = std::env::var_os("EXEMU_NO_DLLMAIN").is_none();
        if entry != 0 && run_dllmain {
            self.dll.pending_dllmain.push((entry, base));
        }
        Ok(Some(base))
    }

    pub fn load_wine_core(&mut self, mem: &mut dyn Memory) -> Result<Option<u64>> {
        let Some(dir) = self.cfg.wine_dll_dir.clone() else {
            return Ok(None);
        };
        let dir = std::path::PathBuf::from(dir);
        const CORE: [&str; 4] = ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll"];
        if CORE.iter().any(|n| !dir.join(n).is_file()) {
            return Ok(None);
        }

        self.dll.pending_dllmain.clear();
        let ntdll_host = dir.join("ntdll.dll");
        let base = if let Some(&b) = self.dll.by_name.get("ntdll.dll") {
            b
        } else {
            match self.load_core_image(mem, &ntdll_host, "ntdll.dll")? {
                Some(b) => b,
                None => return Ok(None),
            }
        };
        self.register_ntdll_unixlib(base);
        let thunk = self.wine_unix_call_thunk();
        let ptr_size = if self.cfg.is_64bit { 8 } else { 4 };
        mem.write(
            base + crate::RVA_WINE_UNIX_CALL_DISPATCHER,
            &thunk.to_le_bytes()[..ptr_size],
        )?;

        self.seed_api_set_map(mem)?;
        Ok(Some(base))
    }

    fn load_core_image(
        &mut self,
        mem: &mut dyn Memory,
        host: &std::path::Path,
        name: &str,
    ) -> Result<Option<u64>> {
        let Ok(bytes) = std::fs::read(host) else {
            return Ok(None);
        };
        let Ok(mut image) = self.images.parse(&bytes) else {
            return Ok(None);
        };

        if self.dll.arena_next == 0 {
            self.dll.arena_next = self.cfg.dll_base;
        }
        let (Some(base), Some(img_size)) = (
            checked_align_up(self.dll.arena_next, PAGE),
            checked_align_up(image.size_of_image as u64, PAGE),
        ) else {
            return Ok(None);
        };
        let img_size = img_size.max(PAGE);
        let arena_end = self.cfg.dll_base.saturating_add(self.cfg.dll_size);
        let Some(next) = base.checked_add(img_size).filter(|&end| end <= arena_end) else {
            return Ok(None);
        };
        self.dll.arena_next = next;
        let ptr_size = if self.cfg.is_64bit { 8 } else { 4 };

        let preferred = image.image_base;
        if let Err(e) =
            self.images.apply_relocations(&mut image.sections, &image.relocations, preferred, base)
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
                mem.write_at(base, s.rva as u64, &s.data)?;
            }
        }

        self.dll.exports.insert(base, image.exports.clone());
        self.dll.by_name.insert(name.to_string(), base);

        for imp in &image.imports {
            let addr = self.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.write_at(base, imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
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

    pub fn module_base(&self, name: &str) -> Option<u64> {
        let &base = self.dll.by_name.get(name)?;
        self.dll.exports.contains_key(&base).then_some(base)
    }

    pub fn module_for_addr(&self, addr: u64) -> Option<String> {
        if let Some(m) = self.dll.modules.iter().find(|m| addr >= m.base && addr < m.base + m.size) {
            return Some(format!("{}+{:#x}", m.name, addr - m.base));
        }
        let m = self.dll.modules.iter().filter(|m| m.base <= addr).max_by_key(|m| m.base)?;
        Some(format!("(after {}+{:#x})", m.name, addr - m.base))
    }

    pub(crate) fn record_image_view(&mut self, base: u64, size: u64, name: Option<String>) {
        self.dll.image_views.retain(|v| v.base != base);
        self.dll.image_views.push(ImageView { base, size, name });
    }

    pub(crate) fn forget_image_view(&mut self, base: u64) {
        self.dll.image_views.retain(|v| v.base != base);
    }

    pub fn module_at(&self, addr: u64) -> Option<(&str, u64)> {
        if let Some(m) = self.dll.modules.iter().find(|m| addr >= m.base && addr < m.base + m.size) {
            return Some((m.name.as_str(), addr - m.base));
        }
        if let Some(v) = self.dll.image_views.iter().find(|v| addr >= v.base && addr < v.base + v.size) {
            return Some((v.name.as_deref().unwrap_or("<unnamed image>"), addr - v.base));
        }
        let (base, size) = (self.cfg.image_base, self.cfg.image_size);
        (size != 0 && addr >= base && addr < base + size).then(|| (self.cfg.image_name.as_str(), addr - base))
    }

    pub fn loaded_modules(&self) -> Vec<(String, u64, u64)> {
        let mut v: Vec<(String, u64, u64)> = self
            .dll
            .modules
            .iter()
            .map(|m| (m.name.clone(), m.base, m.size))
            .chain(self.dll.image_views.iter().map(|i| {
                (i.name.clone().unwrap_or_else(|| "<unnamed image>".into()), i.base, i.size)
            }))
            .collect();
        if self.cfg.image_size != 0 {
            v.push((self.cfg.image_name.clone(), self.cfg.image_base, self.cfg.image_size));
        }
        v.sort_by_key(|(_, base, _)| *base);
        v.dedup_by_key(|(_, base, _)| *base);
        v
    }

    pub fn describe_addr(&self, addr: u64) -> String {
        match self.module_at(addr) {
            Some((name, rva)) => format!("{name}+{rva:#x}"),
            None => "?".to_string(),
        }
    }

    pub fn ntdll_export(&self, symbol: &str) -> Option<u64> {
        let &base = self.dll.by_name.get("ntdll.dll")?;
        let exports = self.dll.exports.get(&base)?;
        let e = exports.iter().find(|e| e.name.as_deref() == Some(symbol) && e.forwarder.is_none())?;
        Some(base + e.rva as u64)
    }

    pub fn run_pending_dllmains(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<()> {
        let pending = std::mem::take(&mut self.dll.pending_dllmain);
        if pending.is_empty() {
            return Ok(());
        }
        let bases: Vec<u64> = pending.iter().map(|&(_, b)| b).collect();
        self.mark_attached(&bases);
        let calls: Vec<(u64, Vec<u64>)> = pending
            .into_iter()
            .map(|(entry, base)| (entry, vec![base, 1 , 0]))
            .collect();
        self.invoke_callbacks(cpu, mem, calls, 0, 0, false)?;
        Ok(())
    }

    pub fn resolve_import_addr(&mut self, dll: &str, symbol: &ImportSymbol) -> u64 {
        let host: &str = match self.images.api_set_host(dll) {
            Some(h) => h,
            None => dll,
        };
        let view = GuestModules { dll: &self.dll };
        match self.images.resolve_export(&view, host, symbol) {
            Some(addr) => addr,
            None => self.resolve_import(host, symbol),
        }
    }

    pub(crate) fn get_proc_address(&mut self, mem: &mut dyn Memory, hmodule: u64, name_ptr: u64) -> Result<u64> {
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
        if let Some(dll) = self.dll.system.get(&hmodule).cloned() {
            if name_ptr < 0x1_0000 {
                return Ok(self.resolve_import(&dll, &ImportSymbol::Ordinal(name_ptr as u16)));
            }
            let name = crate::api::read_astr(mem, name_ptr)?;
            if name.is_empty() {
                return Ok(0);
            }
            let thunk = self.resolve_import(&dll, &ImportSymbol::Named(name.clone()));
            if let Some(v) = data_export_value(&self.cfg, &name) {
                self.write_ptr(mem, thunk, v)?;
            }
            return Ok(thunk);
        }
        Ok(0)
    }

    fn find_dll_file(&self, path: &str, name: &str) -> Option<std::path::PathBuf> {
        if let Some(p) = self.host_path(path) {
            if p.is_file() {
                return Some(p);
            }
        }
        for guest in [format!("C:\\{name}"), format!("C:\\Temp\\{name}")] {
            if let Some(p) = self.host_path(&guest) {
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        if !self.cfg.sandbox.is_empty() {
            return find_in_tree(std::path::Path::new(&self.cfg.sandbox), name, 0);
        }
        None
    }

    pub fn init_ldr(&mut self, mem: &mut dyn Memory) -> Result<()> {
        if self.cfg.peb_addr == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        if self.dll.ldr_arena_next == 0 {
            self.dll.ldr_arena_next = self.cfg.dll_base + self.cfg.dll_size;
        }

        let ldr_size = if self.cfg.is_64bit { 0x58 } else { 0x30 };
        let ldr = self.ldr_alloc(ldr_size);
        self.dll.peb_ldr_data = ldr;
        mem.write_u32(ldr, ldr_size as u32)?;
        mem.write_u32_at(ldr, 4, 1)?;
        for off in self.ldr_list_offsets() {
            let head = ldr + off;
            self.write_ptr(mem, head, head)?;
            self.write_ptr(mem, guest_addr(head, ptr, 0)?, head)?;
        }
        self.write_ptr(mem, guest_addr(self.cfg.peb_addr, self.cfg.peb_ldr_off, 0)?, ldr)?;

        self.seed_peb(mem)?;

        let cs_size = if self.cfg.is_64bit { 0x28 } else { 0x18 };
        let cs = self.ldr_alloc(cs_size);
        self.dll.loader_lock = cs;
        self.write_ptr(mem, cs, 0)?;
        mem.write_u32_at(cs, ptr, (-1_i32) as u32)?;
        mem.write_u32_at(cs, ptr + 4, 0)?;
        self.write_ptr(mem, guest_addr(cs, ptr + 8, 0)?, 0)?;
        self.write_ptr(mem, guest_addr(cs, ptr + 8 + ptr, 0)?, 0)?;
        self.write_ptr(mem, guest_addr(cs, ptr + 8 + 2 * ptr, 0)?, 0)?;
        if self.cfg.peb_loaderlock_off != 0 {
            self.write_ptr(mem, guest_addr(self.cfg.peb_addr, self.cfg.peb_loaderlock_off, 0)?, cs)?;
        }

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
            (0x02, 0x68, 0xA4, 0xA8, 0xAC, 0xB0, 0x1D4, 0x10)
        };

        mem.write_u8_at(peb, off_being_debugged, 0)?;
        mem.write_u32_at(peb, off_nt_global_flag, 0)?;
        mem.write_u32_at(peb, off_os_major, 10)?;
        mem.write_u32_at(peb, off_os_minor, 0)?;
        mem.write_u16_at(peb, off_os_build, 19045)?;
        mem.write_u32_at(peb, off_os_platform, 2)?;
        mem.write_u32_at(peb, off_session_id, 0)?;

        let pp = self.build_process_parameters(mem)?;
        self.write_ptr(mem, guest_addr(peb, off_process_params, 0)?, pp)?;
        Ok(())
    }

    fn build_process_parameters(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        if self.cfg.is_64bit {
            self.build_process_parameters_64(mem)
        } else {
            self.build_process_parameters_32(mem)
        }
    }

    #[cfg(test)]
    pub(crate) fn build_process_parameters_for_test(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        if self.dll.ldr_arena_next == 0 {
            self.dll.ldr_arena_next = self.cfg.dll_base + self.cfg.dll_size;
        }
        self.build_process_parameters(mem)
    }

    fn build_process_parameters_64(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        const PP_SIZE: u64 = 0x420;
        let pp = self.ldr_alloc(PP_SIZE);
        let zero = [0u8; PP_SIZE as usize];
        mem.write(pp, &zero)?;

        mem.write_u32(pp, PP_SIZE as u32)?;
        mem.write_u32_at(pp, 0x04, PP_SIZE as u32)?;
        mem.write_u32_at(pp, 0x08, 0x1)?;
        mem.write_u64_at(pp, 0x20, crate::HANDLE_STDIN)?;
        mem.write_u64_at(pp, 0x28, crate::HANDLE_STDOUT)?;
        mem.write_u64_at(pp, 0x30, crate::HANDLE_STDERR)?;

        let (cd_buf, cd_len) = self.ldr_write_wstr(mem, "C:\\")?;
        self.write_unicode_string(mem, guest_addr(pp, 0x38, 0)?, cd_buf, cd_len)?;
        let (dll_buf, dll_len) = self.ldr_write_wstr(mem, "C:\\windows\\system32")?;
        self.write_unicode_string(mem, guest_addr(pp, 0x50, 0)?, dll_buf, dll_len)?;
        let (img_buf, img_len) = self.ldr_write_wstr(mem, &self.cfg.module_path_w.clone())?;
        self.write_unicode_string(mem, guest_addr(pp, 0x60, 0)?, img_buf, img_len)?;
        if self.cfg.cmdline_ptr_w != 0 {
            let cmd_len = wstr_byte_len(mem, self.cfg.cmdline_ptr_w)?;
            self.write_unicode_string(mem, guest_addr(pp, 0x70, 0)?, self.cfg.cmdline_ptr_w, cmd_len)?;
        } else {
            self.write_unicode_string(mem, guest_addr(pp, 0x70, 0)?, img_buf, img_len)?;
        }

        let (env_buf, env_bytes) = self.write_env_block(mem)?;
        self.write_ptr(mem, guest_addr(pp, 0x80, 0)?, env_buf)?;
        mem.write_u64_at(pp, 0x3f0, env_bytes)?;

        let (empty_buf, _) = self.ldr_write_wstr(mem, "")?;
        for off in [0xb0u64, 0xc0, 0xd0, 0xe0] {
            self.write_unicode_string(mem, guest_addr(pp, off, 0)?, empty_buf, 0)?;
        }
        Ok(pp)
    }

    fn build_process_parameters_32(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        const PP_SIZE: u64 = 0x290;
        let pp = self.ldr_alloc(PP_SIZE);
        let zero = [0u8; PP_SIZE as usize];
        mem.write(pp, &zero)?;
        mem.write_u32(pp, PP_SIZE as u32)?;
        mem.write_u32_at(pp, 0x04, PP_SIZE as u32)?;
        mem.write_u32_at(pp, 0x08, 0x1)?;
        let (img_buf, img_len) = self.ldr_write_wstr(mem, &self.cfg.module_path_w.clone())?;
        self.write_unicode_string(mem, guest_addr(pp, 0x38, 0)?, img_buf, img_len)?;
        if self.cfg.cmdline_ptr_w != 0 {
            let cmd_len = wstr_byte_len(mem, self.cfg.cmdline_ptr_w)?;
            self.write_unicode_string(mem, guest_addr(pp, 0x40, 0)?, self.cfg.cmdline_ptr_w, cmd_len)?;
        } else {
            self.write_unicode_string(mem, guest_addr(pp, 0x40, 0)?, img_buf, img_len)?;
        }
        let (env_buf, _env_bytes) = self.write_env_block(mem)?;
        self.write_ptr(mem, guest_addr(pp, 0x48, 0)?, env_buf)?;
        Ok(pp)
    }

    pub fn build_wow64_process_parameters(
        &mut self,
        mem: &mut dyn Memory,
        arena: u64,
        arena_size: u64,
    ) -> Result<Option<u64>> {
        const PP32_SIZE: u64 = 0x2b0;
        const PP32_ENVIRONMENT_SIZE: u64 = 0x290;
        let mut next = arena;
        let mut alloc = |n: u64| {
            let at = next;
            next += n.div_ceil(8) * 8;
            at
        };
        let pp = alloc(PP32_SIZE);
        let img = self.cfg.module_path_w.clone();
        let img_units: Vec<u16> = img.encode_utf16().collect();
        let img_buf = alloc((img_units.len() * 2 + 2) as u64);
        let cmd_units: Vec<u16> = if self.cfg.cmdline_ptr_w != 0 {
            crate::api::read_wstr_units(mem, self.cfg.cmdline_ptr_w)?
        } else {
            img_units.clone()
        };
        let cmd_buf = alloc((cmd_units.len() * 2 + 2) as u64);
        let cur_units: Vec<u16> = "C:\\\0".encode_utf16().collect();
        let cur_buf = alloc((cur_units.len() * 2 + 2) as u64);
        let env_units = self.env_block_utf16();
        let env_buf = alloc((env_units.len() * 2) as u64);
        if next > arena + arena_size || next > u32::MAX as u64 {
            return Ok(None);
        }

        mem.write(pp, &vec![0u8; PP32_SIZE as usize])?;
        mem.write_u32(pp, PP32_SIZE as u32)?;
        mem.write_u32_at(pp, 0x04, PP32_SIZE as u32)?;
        mem.write_u32_at(pp, 0x08, 0x1)?;
        let put = |mem: &mut dyn Memory, at: u64, buf: u64, units: &[u16]| -> Result<()> {
            for (i, u) in units.iter().enumerate() {
                mem.write_u16_at(buf, (i * 2) as u64, *u)?;
            }
            mem.write_u16_at(buf, units.len() as u64 * 2, 0)?;
            let bytes = (units.len() * 2) as u16;
            mem.write_u16(at, bytes)?;
            mem.write_u16_at(at, 2, bytes + 2)?;
            mem.write_u32_at(at, 4, buf as u32)?;
            Ok(())
        };
        put(mem, pp + 0x24, cur_buf, &cur_units)?;
        put(mem, pp + 0x38, img_buf, &img_units)?;
        put(mem, pp + 0x40, cmd_buf, &cmd_units)?;
        for (i, u) in env_units.iter().enumerate() {
            mem.write_u16_at(env_buf, (i * 2) as u64, *u)?;
        }
        mem.write_u32_at(pp, 0x48, env_buf as u32)?;
        mem.write_u32_at(pp, PP32_ENVIRONMENT_SIZE, (env_units.len() * 2) as u32)?;
        Ok(Some(pp))
    }

    fn write_env_block(&mut self, mem: &mut dyn Memory) -> Result<(u64, u64)> {
        let units = self.env_block_utf16();
        let byte_len = (units.len() * 2) as u64;
        let addr = self.ldr_alloc(byte_len.max(2));
        for (i, u) in units.iter().enumerate() {
            mem.write_u16_at(addr, (i * 2) as u64, *u)?;
        }
        Ok((addr, byte_len))
    }

    pub(crate) fn seed_api_set_map(&mut self, mem: &mut dyn Memory) -> Result<()> {
        if self.cfg.peb_addr == 0 {
            return Ok(());
        }
        if self.dll.api_set_map != 0 {
            return Ok(());
        }
        let ns = crate::apiset::build_populated_namespace();
        let base = self.ldr_alloc(ns.bytes.len() as u64);
        mem.write(base, &ns.bytes)?;
        self.dll.api_set_map = base;
        let off = if self.cfg.is_64bit { 0x68u64 } else { 0x38 };
        self.write_ptr(mem, guest_addr(self.cfg.peb_addr, off, 0)?, base)?;
        Ok(())
    }

    pub fn api_set_map(&self) -> u64 {
        self.dll.api_set_map
    }

    pub(crate) fn enter_loader_lock(&mut self, mem: &mut dyn Memory) -> Result<()> {
        let cs = self.dll.loader_lock;
        if cs == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        self.dll.loader_lock_depth += 1;
        mem.write_u32_at(cs, ptr, (self.dll.loader_lock_depth - 1) as u32)?;
        mem.write_u32_at(cs, ptr + 4, self.dll.loader_lock_depth as u32)?;
        let owner = u64::from(self.current_tid);
        self.write_ptr(mem, guest_addr(cs, ptr + 8, 0)?, owner)?;
        Ok(())
    }

    pub(crate) fn leave_loader_lock(&mut self, mem: &mut dyn Memory) -> Result<()> {
        let cs = self.dll.loader_lock;
        if cs == 0 || self.dll.loader_lock_depth == 0 {
            return Ok(());
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        self.dll.loader_lock_depth -= 1;
        if self.dll.loader_lock_depth == 0 {
            mem.write_u32_at(cs, ptr, (-1_i32) as u32)?;
            mem.write_u32_at(cs, ptr + 4, 0)?;
            self.write_ptr(mem, guest_addr(cs, ptr + 8, 0)?, 0)?;
        } else {
            mem.write_u32_at(cs, ptr, (self.dll.loader_lock_depth - 1) as u32)?;
            mem.write_u32_at(cs, ptr + 4, self.dll.loader_lock_depth as u32)?;
        }
        Ok(())
    }

    fn ldr_list_offsets(&self) -> [u64; 3] {
        if self.cfg.is_64bit {
            [0x10, 0x20, 0x30]
        } else {
            [0x0c, 0x14, 0x1c]
        }
    }

    fn ldr_entry_link_offsets(&self) -> [u64; 3] {
        if self.cfg.is_64bit {
            [0x00, 0x10, 0x20]
        } else {
            [0x00, 0x08, 0x10]
        }
    }

    fn ldr_alloc(&mut self, size: u64) -> u64 {
        let aligned = size.div_ceil(8) * 8;
        self.dll.ldr_arena_next -= aligned;
        self.dll.ldr_arena_next
    }

    fn ldr_add_module(&mut self, mem: &mut dyn Memory, idx: usize) -> Result<()> {
        if self.cfg.peb_addr == 0 || self.dll.peb_ldr_data == 0 {
            return Ok(());
        }
        let m = &self.dll.modules[idx];
        let (base, size, entry) = (m.base, m.size, m.entry);
        let name = m.name.clone();
        let full = m.full_path.clone();
        let ldr_entry = self.ldr_thread_entry(mem, base, size, entry, &name, &full)?;
        self.dll.modules[idx].ldr_entry = ldr_entry;
        Ok(())
    }

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
        let (off_dllbase, off_entry, off_size, off_full, off_basename, entry_size) =
            if self.cfg.is_64bit {
                (0x30u64, 0x38, 0x40, 0x48, 0x58, 0x68u64)
            } else {
                (0x18, 0x1c, 0x20, 0x24, 0x2c, 0x38)
            };
        let te = self.ldr_alloc(entry_size);

        let full_buf = self.ldr_write_wstr(mem, full_path)?;
        let base_buf = self.ldr_write_wstr(mem, base_name)?;

        mem.write_at(te, off_dllbase, &base.to_le_bytes()[..ptr as usize])?;
        mem.write_at(te, off_entry, &entry.to_le_bytes()[..ptr as usize])?;
        mem.write_at(te, off_size, &size.to_le_bytes()[..ptr as usize])?;
        self.write_unicode_string(mem, guest_addr(te, off_full, 0)?, full_buf.0, full_buf.1)?;
        self.write_unicode_string(mem, guest_addr(te, off_basename, 0)?, base_buf.0, base_buf.1)?;

        let list_offs = self.ldr_list_offsets();
        let link_offs = self.ldr_entry_link_offsets();
        for (head_off, link_off) in list_offs.into_iter().zip(link_offs) {
            let head = self.dll.peb_ldr_data + head_off;
            let link = te + link_off;
            self.list_insert_tail(mem, head, link, ptr)?;
        }
        Ok(te)
    }

    fn list_insert_tail(&self, mem: &mut dyn Memory, head: u64, link: u64, ptr: u64) -> Result<()> {
        let blink = self.read_ptr(mem, guest_addr(head, ptr, 0)?)?;
        self.write_ptr(mem, link, head)?;
        self.write_ptr(mem, guest_addr(link, ptr, 0)?, blink)?;
        self.write_ptr(mem, blink, link)?;
        self.write_ptr(mem, guest_addr(head, ptr, 0)?, link)?;
        Ok(())
    }

    fn ldr_write_wstr(&mut self, mem: &mut dyn Memory, s: &str) -> Result<(u64, u16)> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (units.len() * 2) as u16;
        let addr = self.ldr_alloc((units.len() * 2 + 2) as u64);
        for (i, u) in units.iter().enumerate() {
            mem.write_u16_at(addr, (i * 2) as u64, *u)?;
        }
        mem.write_u16_at(addr, units.len() as u64 * 2, 0)?;
        Ok((addr, byte_len))
    }

    fn write_unicode_string(&self, mem: &mut dyn Memory, at: u64, buffer: u64, byte_len: u16) -> Result<()> {
        mem.write_u16(at, byte_len)?;
        mem.write_u16_at(at, 2, byte_len + 2)?;
        let buf_off = if self.cfg.is_64bit { 8 } else { 4 };
        let ptr = if self.cfg.is_64bit { 8 } else { 4 };
        mem.write_at(at, buf_off, &buffer.to_le_bytes()[..ptr])?;
        Ok(())
    }
}

struct GuestModules<'a> {
    dll: &'a Loader,
}

impl ModuleExports for GuestModules<'_> {
    fn module_exports(&self, dll: &str) -> Option<(u64, &[Export])> {
        let &base = self.dll.by_name.get(dll)?;
        let exports = self.dll.exports.get(&base)?;
        Some((base, exports.as_slice()))
    }
}

fn data_export_value(cfg: &crate::WinConfig, name: &str) -> Option<u64> {
    match name {
        "_acmdln" => Some(cfg.cmdline_ptr_a),
        "_wcmdln" => Some(cfg.cmdline_ptr_w),
        _ => None,
    }
}

fn wstr_byte_len(mem: &dyn Memory, addr: u64) -> Result<u16> {
    let mut units = 0u64;
    while units < 0x4000 {
        if mem.read_u16_at(addr, units * 2)? == 0 {
            break;
        }
        units += 1;
    }
    Ok((units * 2) as u16)
}

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
