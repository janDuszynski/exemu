use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use exemu_core::{CpuState, Memory, Result};

use crate::WinOs;

pub struct OpenFile {
    pub file: std::fs::File,
}

#[derive(Clone)]
pub struct FindEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub ctime: u64,
    pub atime: u64,
    pub mtime: u64,
}

pub struct FindState {
    pub entries: Vec<FindEntry>,
    pub pos: usize,
    pub wide: bool,
}

pub const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF;
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;
const CREATE_NEW: u64 = 1;
const CREATE_ALWAYS: u64 = 2;
const OPEN_EXISTING: u64 = 3;
const OPEN_ALWAYS: u64 = 4;
const TRUNCATE_EXISTING: u64 = 5;
const GENERIC_WRITE: u64 = 0x4000_0000;

impl WinOs {
    pub(crate) fn is_file_handle(&self, handle: u64) -> bool {
        self.files.contains_key(&handle)
    }

    pub(crate) fn is_std_handle(&self, handle: u64) -> bool {
        handle == crate::HANDLE_STDIN
            || handle == crate::HANDLE_STDOUT
            || handle == crate::HANDLE_STDERR
    }

    pub(crate) fn host_path(&self, guest: &str) -> Option<PathBuf> {
        if self.cfg.sandbox.is_empty() {
            return None;
        }
        let mut out = PathBuf::from(&self.cfg.sandbox);
        let cleaned = guest.trim_start_matches("\\\\?\\").replace('\\', "/");
        for comp in cleaned.split('/') {
            match comp {
                "" | "." | ".." => {}
                c if c.ends_with(':') => out.push(&c[..c.len() - 1]),
                c => out.push(c),
            }
        }
        if !out.exists() {
            if let Some(redirect) = self.wine_dll_redirect(guest) {
                return Some(redirect);
            }
        }
        Some(out)
    }

    fn wine_dll_redirect(&self, guest: &str) -> Option<PathBuf> {
        let dir = self.cfg.wine_dll_dir.as_ref()?;
        let dir = if self.wow64_peb32 != 0 {
            let sib = std::path::Path::new(dir)
                .parent()
                .map(|p| p.join("i386-windows"))
                .unwrap_or_else(|| PathBuf::from("i386-windows"));
            sib.to_string_lossy().into_owned()
        } else {
            dir.clone()
        };
        let dir = &dir;
        let cleaned = strip_nt_prefix(guest).replace('/', "\\");
        let lower = cleaned.to_ascii_lowercase();
        let (pos, mlen) = ["\\windows\\system32\\", "\\windows\\syswow64\\"]
            .iter()
            .find_map(|m| lower.find(m).map(|p| (p, m.len())))?;
        let leaf = &cleaned[pos + mlen..];
        if leaf.is_empty() || leaf.contains('\\') {
            return None;
        }
        Some(PathBuf::from(dir).join(leaf))
    }

    fn alloc_handle(&mut self, f: std::fs::File) -> u64 {
        let h = self.next_handle;
        self.next_handle += 4;
        self.files.insert(h, OpenFile { file: f });
        h
    }

    pub(crate) fn create_file(&mut self, name: &str, access: u64, disposition: u64) -> u64 {
        let Some(path) = self.host_path(name) else {
            return INVALID_HANDLE_VALUE;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        if access & GENERIC_WRITE != 0 || disposition != OPEN_EXISTING {
            opts.write(true);
        }
        match disposition {
            CREATE_NEW => {
                opts.create_new(true);
            }
            CREATE_ALWAYS => {
                opts.create(true).truncate(true);
            }
            OPEN_EXISTING => {}
            OPEN_ALWAYS => {
                opts.create(true);
            }
            TRUNCATE_EXISTING => {
                opts.truncate(true);
            }
            _ => {
                opts.create(true);
            }
        }
        match opts.open(&path) {
            Ok(f) => self.alloc_handle(f),
            Err(_) => {
                self.set_last_error(2);
                INVALID_HANDLE_VALUE
            }
        }
    }

    pub(crate) fn read_file(&mut self, handle: u64, buf: &mut [u8]) -> Option<usize> {
        let of = self.files.get_mut(&handle)?;
        Some(of.file.read(buf).unwrap_or(0))
    }

    pub(crate) fn write_file_handle(&mut self, handle: u64, data: &[u8]) -> Option<usize> {
        let of = self.files.get_mut(&handle)?;
        Some(of.file.write(data).unwrap_or(0))
    }

    pub(crate) fn close_handle(&mut self, handle: u64) -> bool {
        if self.close_socket(handle) {
            return true;
        }
        if self.kobjects.remove(&handle).is_some() {
            self.named_kobjects.retain(|_, &mut h| h != handle);
            self.forget_child_handle(handle);
            return true;
        }
        self.file_dirs.remove(&handle);
        self.find_handles.remove(&handle);
        self.files.remove(&handle).is_some()
    }

    pub(crate) fn alloc_khandle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 4;
        h
    }

    pub(crate) fn file_size(&self, handle: u64) -> Option<u64> {
        let of = self.files.get(&handle)?;
        of.file.metadata().ok().map(|m| m.len())
    }

    pub(crate) fn set_file_pointer(&mut self, handle: u64, distance: i64, method: u64) -> u64 {
        let Some(of) = self.files.get_mut(&handle) else {
            return INVALID_HANDLE_VALUE;
        };
        let seek = match method {
            0 => SeekFrom::Start(distance.max(0) as u64),
            1 => SeekFrom::Current(distance),
            _ => SeekFrom::End(distance),
        };
        of.file.seek(seek).unwrap_or(0) & 0xFFFF_FFFF
    }

    pub(crate) fn temp_file_name(&mut self, dir: &str, prefix: &str, unique: u32) -> (String, u32) {
        let u = if unique != 0 {
            unique
        } else {
            self.temp_counter += 1;
            self.temp_counter
        };
        let pfx: String = prefix.chars().take(3).collect();
        let sep = if dir.ends_with('\\') { "" } else { "\\" };
        let name = format!("{dir}{sep}{pfx}{:x}.TMP", u & 0xFFFF);
        if let Some(path) = self.host_path(&name) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::File::create(&path);
        }
        (name, u)
    }

    pub(crate) fn create_directory(&mut self, name: &str) -> bool {
        match self.host_path(name) {
            Some(p) => std::fs::create_dir_all(p).is_ok(),
            None => false,
        }
    }

    pub(crate) fn delete_file(&mut self, name: &str) -> bool {
        match self.host_path(name) {
            Some(p) => std::fs::remove_file(p).is_ok(),
            None => false,
        }
    }

    pub(crate) fn full_path_name(&self, name: &str) -> String {
        let n = name.replace('/', "\\");
        let bytes = n.as_bytes();
        let drive_qualified = bytes.len() >= 2 && bytes[1] == b':';
        if drive_qualified || n.starts_with("\\\\") {
            n
        } else if let Some(rest) = n.strip_prefix('\\') {
            format!("C:\\{}", rest.trim_start_matches('\\'))
        } else {
            format!("C:\\{n}")
        }
    }

    pub(crate) fn move_file(&mut self, src: &str, dst: &str) -> bool {
        let (Some(s), Some(d)) = (self.host_path(src), self.host_path(dst)) else {
            self.set_last_error(2);
            return false;
        };
        if let Some(parent) = d.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::rename(&s, &d).is_ok() {
            return true;
        }
        if std::fs::copy(&s, &d).is_ok() && std::fs::remove_file(&s).is_ok() {
            return true;
        }
        self.set_last_error(2);
        false
    }

    pub(crate) fn copy_file(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> bool {
        let (Some(s), Some(d)) = (self.host_path(src), self.host_path(dst)) else {
            self.set_last_error(2);
            return false;
        };
        if fail_if_exists && d.exists() {
            self.set_last_error(80);
            return false;
        }
        if let Some(parent) = d.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::copy(&s, &d).is_ok() {
            true
        } else {
            self.set_last_error(2);
            false
        }
    }

    pub(crate) fn file_attributes(&self, name: &str) -> u64 {
        match self.host_path(name).as_deref().map(Path::metadata) {
            Some(Ok(m)) if m.is_dir() => FILE_ATTRIBUTE_DIRECTORY,
            Some(Ok(_)) => FILE_ATTRIBUTE_NORMAL,
            _ => INVALID_FILE_ATTRIBUTES,
        }
    }

    pub(crate) fn write_wstr(mem: &mut dyn Memory, addr: u64, s: &str, max: usize) -> Result<u64> {
        if addr == 0 || max == 0 {
            return Ok(0);
        }
        let units: Vec<u16> = s.encode_utf16().take(max - 1).collect();
        for (i, u) in units.iter().enumerate() {
            mem.write_u16(addr + (i as u64) * 2, *u)?;
        }
        mem.write_u16(addr + (units.len() as u64) * 2, 0)?;
        Ok(units.len() as u64)
    }

    pub(crate) fn set_last_error(&mut self, code: u32) {
        self.last_error = code;
    }

    pub(crate) fn find_first_file(
        &mut self,
        mem: &mut dyn Memory,
        pattern: &str,
        data_ptr: u64,
        wide: bool,
    ) -> Result<u64> {
        let (dir, leaf) = match pattern.rfind('\\') {
            Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
            None => ("", pattern),
        };

        let Some(host_dir) = self.host_path(dir) else {
            self.set_last_error(2);
            return Ok(INVALID_HANDLE_VALUE);
        };

        let mut entries: Vec<FindEntry> = Vec::new();

        if glob_matches(leaf, ".") {
            let (ctime, atime, mtime) = std::fs::metadata(&host_dir)
                .as_ref()
                .map(metadata_times)
                .unwrap_or((0, 0, 0));
            entries.push(FindEntry {
                name: ".".to_string(),
                is_dir: true,
                size: 0,
                ctime,
                atime,
                mtime,
            });
        }

        if glob_matches(leaf, "..") {
            let (ctime, atime, mtime) = host_dir
                .parent()
                .and_then(|p| std::fs::metadata(p).ok())
                .as_ref()
                .map(metadata_times)
                .unwrap_or((0, 0, 0));
            entries.push(FindEntry {
                name: "..".to_string(),
                is_dir: true,
                size: 0,
                ctime,
                atime,
                mtime,
            });
        }

        if let Ok(iter) = std::fs::read_dir(&host_dir) {
            for de in iter.flatten() {
                let file_name = de.file_name();
                let name = file_name.to_string_lossy().into_owned();
                if glob_matches(leaf, &name) {
                    let meta = de.metadata().ok();
                    let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                    let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    let (ctime, atime, mtime) =
                        meta.as_ref().map(metadata_times).unwrap_or((0, 0, 0));
                    entries.push(FindEntry { name, is_dir, size, ctime, atime, mtime });
                }
            }
        }

        entries.sort_by(|a, b| {
            a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase())
        });

        if entries.is_empty() {
            self.set_last_error(2);
            return Ok(INVALID_HANDLE_VALUE);
        }

        write_find_data(mem, data_ptr, &entries[0], wide)?;

        let h = self.next_handle;
        self.next_handle += 4;
        self.find_handles.insert(h, FindState { entries, pos: 1, wide });

        Ok(h)
    }

    pub(crate) fn find_next_file(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        data_ptr: u64,
    ) -> Result<u64> {
        let Some(state) = self.find_handles.get_mut(&handle) else {
            self.set_last_error(18);
            return Ok(0);
        };
        if state.pos < state.entries.len() {
            let entry = state.entries[state.pos].clone();
            let wide = state.wide;
            state.pos += 1;
            write_find_data(mem, data_ptr, &entry, wide)?;
            Ok(1)
        } else {
            self.set_last_error(18);
            Ok(0)
        }
    }

    pub(crate) fn find_close(&mut self, handle: u64) -> u64 {
        self.find_handles.remove(&handle);
        1
    }
}

fn write_find_data(mem: &mut dyn Memory, ptr: u64, entry: &FindEntry, wide: bool) -> Result<()> {
    let total = if wide { 592 } else { 318 };
    mem.write(ptr, &vec![0u8; total])?;

    let attrs: u32 = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY as u32
    } else {
        FILE_ATTRIBUTE_NORMAL as u32
    };
    mem.write_u32(ptr, attrs)?;

    mem.write_u32(ptr + 4, entry.ctime as u32)?;
    mem.write_u32(ptr + 8, (entry.ctime >> 32) as u32)?;
    mem.write_u32(ptr + 12, entry.atime as u32)?;
    mem.write_u32(ptr + 16, (entry.atime >> 32) as u32)?;
    mem.write_u32(ptr + 20, entry.mtime as u32)?;
    mem.write_u32(ptr + 24, (entry.mtime >> 32) as u32)?;
    mem.write_u32(ptr + 28, (entry.size >> 32) as u32)?;
    mem.write_u32(ptr + 32, entry.size as u32)?;

    if wide {
        WinOs::write_wstr(mem, ptr + 44, &entry.name, 260)?;
    } else {
        crate::api::write_astr(mem, ptr + 44, &entry.name, 260)?;
    }
    Ok(())
}

fn metadata_times(meta: &std::fs::Metadata) -> (u64, u64, u64) {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let to_ft = |res: std::io::Result<std::time::SystemTime>| -> u64 {
        res.ok()
            .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                d.as_secs() * 10_000_000
                    + d.subsec_nanos() as u64 / 100
                    + EPOCH_DIFF
            })
            .unwrap_or(0)
    };
    (to_ft(meta.created()), to_ft(meta.accessed()), to_ft(meta.modified()))
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    let effective_pat: &str = if pattern == "*.*" { "*" } else { pattern };
    let p: Vec<char> = effective_pat.chars().map(|c| c.to_ascii_lowercase()).collect();
    let n: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    glob_ci(&p, &n)
}

fn glob_ci(p: &[char], n: &[char]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some('*') => {
            (0..=n.len()).any(|i| glob_ci(&p[1..], &n[i..]))
        }
        Some('?') => !n.is_empty() && glob_ci(&p[1..], &n[1..]),
        Some(pc) => matches!(n.first(), Some(nc) if *nc == *pc) && glob_ci(&p[1..], &n[1..]),
    }
}

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

const FILE_WRITE_DATA: u64 = 0x0000_0002;
const FILE_APPEND_DATA: u64 = 0x0000_0004;
const NT_GENERIC_WRITE: u64 = 0x4000_0000;

const FILE_SUPERSEDED: u64 = 0;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;
const FILE_OVERWRITTEN: u64 = 3;

const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;

const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;

const FILE_DEVICE_NAMED_PIPE: u32 = 0x11;

pub(crate) const SSDT_NT_CREATE_FILE: u32 = 0x55;
pub(crate) const SSDT_NT_READ_FILE: u32 = 0x06;
pub(crate) const SSDT_NT_WRITE_FILE: u32 = 0x08;
pub(crate) const SSDT_NT_QUERY_INFORMATION_FILE: u32 = 0x11;
pub(crate) const SSDT_NT_QUERY_DIRECTORY_FILE: u32 = 0x35;
pub(crate) const SSDT_NT_QUERY_VOLUME_INFORMATION_FILE: u32 = 0x49;
pub(crate) const SSDT_NT_OPEN_FILE: u32 = 0x33;
pub(crate) const SSDT_NT_QUERY_ATTRIBUTES_FILE: u32 = 0x3d;
pub(crate) const SSDT_NT_FS_CONTROL_FILE: u32 = 0x39;
pub(crate) const SSDT_NT_CLOSE: u32 = 0x0f;

const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const NT_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const NT_FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

impl WinOs {
    fn nt_object_name(&self, mem: &dyn Memory, objattr: u64) -> Option<String> {
        if objattr == 0 {
            return None;
        }
        let root_dir = mem.read_u64(objattr + 8).ok()?;
        let name_ptr = mem.read_u64(objattr + 0x10).ok()?;
        let name = read_unicode_string(mem, name_ptr)?;
        let name = strip_nt_prefix(&name);

        if root_dir != 0 && root_dir != u64::MAX {
            if let Some(base) = self.dir_handle_guest_path(root_dir) {
                let sep = if base.ends_with('\\') || name.is_empty() { "" } else { "\\" };
                return Some(format!("{base}{sep}{name}"));
            }
        }
        Some(name)
    }

    fn dir_handle_guest_path(&self, handle: u64) -> Option<String> {
        self.file_dirs.get(&handle).cloned()
    }

    pub(crate) fn nt_create_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_ptr = self.syscall_arg(cpu, mem, 0)?;
        let access = self.syscall_arg(cpu, mem, 1)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 3)?;
        let disposition = self.syscall_arg(cpu, mem, 7)? as u32;
        if handle_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(name) = self.nt_object_name(mem, objattr) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        let Some(path) = self.host_path(&name) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };

        let existed = path.exists();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let wants_write = access & (NT_GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA) != 0
            || disposition != FILE_OPEN;

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        if wants_write {
            opts.write(true);
        }
        match disposition {
            FILE_CREATE => {
                opts.create_new(true);
            }
            FILE_SUPERSEDE | FILE_OVERWRITE_IF => {
                opts.create(true).truncate(true);
            }
            FILE_OPEN => {}
            FILE_OPEN_IF => {
                opts.create(true);
            }
            FILE_OVERWRITE => {
                opts.truncate(true);
            }
            _ => {
                opts.create(true);
            }
        }

        let file = match opts.open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            Err(_) => return Ok(STATUS_OBJECT_NAME_NOT_FOUND),
        };

        let is_dir = file.metadata().map(|m| m.is_dir()).unwrap_or(false);
        let handle = self.alloc_handle(file);
        if is_dir {
            self.file_dirs.insert(handle, name.clone());
        }

        let information = match disposition {
            FILE_CREATE => FILE_CREATED,
            FILE_SUPERSEDE => FILE_SUPERSEDED,
            FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                if existed { FILE_OVERWRITTEN } else { FILE_CREATED }
            }
            FILE_OPEN_IF => {
                if existed { FILE_OPENED } else { FILE_CREATED }
            }
            _ => FILE_OPENED,
        };
        mem.write_u64(handle_ptr, handle)?;
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, information)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_open_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_ptr = self.syscall_arg(cpu, mem, 0)?;
        let access = self.syscall_arg(cpu, mem, 1)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 3)?;
        if handle_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(name) = self.nt_object_name(mem, objattr) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        if let Some(status) = self.nt_open_afd(mem, &name, handle_ptr, iosb_ptr)? {
            return Ok(status);
        }
        let Some(path) = self.host_path(&name) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if !path.exists() {
            let status = match path.parent() {
                Some(p) if !p.exists() => STATUS_OBJECT_PATH_NOT_FOUND,
                _ => STATUS_OBJECT_NAME_NOT_FOUND,
            };
            return Ok(status);
        }

        let wants_write = access & (NT_GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        if wants_write {
            opts.write(true);
        }
        let file = match opts.open(&path) {
            Ok(f) => f,
            Err(_) => match std::fs::OpenOptions::new().read(true).open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
                }
                Err(_) => return Ok(STATUS_OBJECT_NAME_NOT_FOUND),
            },
        };

        let is_dir = file.metadata().map(|m| m.is_dir()).unwrap_or(false);
        let handle = self.alloc_handle(file);
        if is_dir {
            self.file_dirs.insert(handle, name.clone());
        }
        mem.write_u64(handle_ptr, handle)?;
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, FILE_OPENED)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_attributes_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let objattr = self.syscall_arg(cpu, mem, 0)?;
        let info = self.syscall_arg(cpu, mem, 1)?;
        let Some(name) = self.nt_object_name(mem, objattr) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        let Some(path) = self.host_path(&name) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if info == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let ft = meta
            .modified()
            .ok()
            .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() * 10_000_000 + d.subsec_nanos() as u64 / 100 + FILETIME_EPOCH_DIFF)
            .unwrap_or(FILETIME_EPOCH_DIFF);
        mem.write_u64(info, ft)?;
        mem.write_u64(info + 0x08, ft)?;
        mem.write_u64(info + 0x10, ft)?;
        mem.write_u64(info + 0x18, ft)?;
        let attrs = if meta.is_dir() { NT_FILE_ATTRIBUTE_DIRECTORY } else { NT_FILE_ATTRIBUTE_NORMAL };
        mem.write_u32(info + 0x20, attrs)?;
        mem.write_u32(info + 0x24, 0)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_fs_control_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        write_iosb(mem, iosb_ptr, STATUS_NOT_IMPLEMENTED, 0)?;
        Ok(STATUS_NOT_IMPLEMENTED)
    }

    pub(crate) fn nt_close(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        if handle == u64::MAX || handle == u64::MAX - 1 {
            return Ok(STATUS_SUCCESS);
        }
        if self.is_std_handle(handle) {
            return Ok(STATUS_SUCCESS);
        }
        if self.close_handle(handle) {
            Ok(STATUS_SUCCESS)
        } else {
            Ok(STATUS_INVALID_HANDLE)
        }
    }

    pub(crate) fn nt_read_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let buffer = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg(cpu, mem, 6)? & 0xFFFF_FFFF;
        let offset_ptr = self.syscall_arg(cpu, mem, 7)?;
        if self.is_std_handle(handle) {
            write_iosb(mem, iosb_ptr, STATUS_END_OF_FILE, 0)?;
            return Ok(STATUS_END_OF_FILE);
        }
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        if offset_ptr != 0 {
            let off = mem.read_u64(offset_ptr)?;
            if (off as i64) >= 0 {
                if let Some(of) = self.files.get_mut(&handle) {
                    let _ = of.file.seek(SeekFrom::Start(off));
                }
            }
        }
        let mut buf = vec![0u8; length as usize];
        let n = self.read_file(handle, &mut buf).unwrap_or(0);
        if n != 0 {
            mem.write(buffer, &buf[..n])?;
        }
        if n == 0 && length != 0 {
            write_iosb(mem, iosb_ptr, STATUS_END_OF_FILE, 0)?;
            return Ok(STATUS_END_OF_FILE);
        }
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, n as u64)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_write_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let buffer = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg(cpu, mem, 6)? & 0xFFFF_FFFF;
        let offset_ptr = self.syscall_arg(cpu, mem, 7)?;
        if self.is_std_handle(handle) {
            let mut data = vec![0u8; length as usize];
            if length != 0 {
                mem.read(buffer, &mut data)?;
            }
            self.emit(handle == crate::HANDLE_STDERR, &data);
            write_iosb(mem, iosb_ptr, STATUS_SUCCESS, length)?;
            return Ok(STATUS_SUCCESS);
        }
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        if offset_ptr != 0 {
            let off = mem.read_u64(offset_ptr)?;
            if off == u64::MAX {
                if let Some(of) = self.files.get_mut(&handle) {
                    let _ = of.file.seek(SeekFrom::End(0));
                }
            } else if (off as i64) >= 0 {
                if let Some(of) = self.files.get_mut(&handle) {
                    let _ = of.file.seek(SeekFrom::Start(off));
                }
            }
        }
        let mut data = vec![0u8; length as usize];
        if length != 0 {
            mem.read(buffer, &mut data)?;
        }
        let n = self.write_file_handle(handle, &data).unwrap_or(0);
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, n as u64)?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_information_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 1)?;
        let info = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let class = self.syscall_arg(cpu, mem, 4)? as u32;
        if self.is_std_handle(handle) {
            return match class {
                FILE_STANDARD_INFORMATION => {
                    if length < 0x18 {
                        return Ok(STATUS_BUFFER_TOO_SMALL);
                    }
                    let zero = [0u8; 0x18];
                    mem.write(info, &zero)?;
                    mem.write_u32(info + 0x10, 1)?;
                    write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 0x18)?;
                    Ok(STATUS_SUCCESS)
                }
                FILE_POSITION_INFORMATION => {
                    if length < 8 {
                        return Ok(STATUS_BUFFER_TOO_SMALL);
                    }
                    mem.write_u64(info, 0)?;
                    write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                    Ok(STATUS_SUCCESS)
                }
                _ => {
                    write_iosb(mem, iosb_ptr, STATUS_INVALID_PARAMETER, 0)?;
                    Ok(STATUS_INVALID_PARAMETER)
                }
            };
        }
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let size = self.file_size(handle).unwrap_or(0);
        let pos = self
            .files
            .get_mut(&handle)
            .and_then(|of| of.file.stream_position().ok())
            .unwrap_or(0);

        match class {
            FILE_STANDARD_INFORMATION => {
                if length < 0x18 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, size)?;
                mem.write_u64(info + 8, size)?;
                mem.write_u32(info + 0x10, 1)?;
                mem.write_u32(info + 0x14, 0)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 0x18)?;
                Ok(STATUS_SUCCESS)
            }
            FILE_END_OF_FILE_INFORMATION => {
                if length < 8 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, size)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                Ok(STATUS_SUCCESS)
            }
            FILE_POSITION_INFORMATION => {
                if length < 8 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, pos)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                Ok(STATUS_SUCCESS)
            }
            _ => {
                write_iosb(mem, iosb_ptr, STATUS_INVALID_PARAMETER, 0)?;
                Ok(STATUS_INVALID_PARAMETER)
            }
        }
    }

    pub(crate) fn nt_query_volume_information_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 1)?;
        let info = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let class = self.syscall_arg(cpu, mem, 4)? as u32;
        if self.is_std_handle(handle) {
            return match class {
                FILE_FS_DEVICE_INFORMATION => {
                    if length < 8 {
                        return Ok(STATUS_BUFFER_TOO_SMALL);
                    }
                    mem.write_u32(info, FILE_DEVICE_NAMED_PIPE)?;
                    mem.write_u32(info + 4, 0)?;
                    write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                    Ok(STATUS_SUCCESS)
                }
                _ => {
                    write_iosb(mem, iosb_ptr, STATUS_INVALID_PARAMETER, 0)?;
                    Ok(STATUS_INVALID_PARAMETER)
                }
            };
        }
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        match class {
            FILE_FS_SIZE_INFORMATION => {
                if length < 0x18 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, 0x0010_0000)?;
                mem.write_u64(info + 8, 0x0008_0000)?;
                mem.write_u32(info + 0x10, 8)?;
                mem.write_u32(info + 0x14, 512)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 0x18)?;
                Ok(STATUS_SUCCESS)
            }
            FILE_FS_DEVICE_INFORMATION => {
                if length < 8 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u32(info, 7)?;
                mem.write_u32(info + 4, 0)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                Ok(STATUS_SUCCESS)
            }
            _ => {
                write_iosb(mem, iosb_ptr, STATUS_INVALID_PARAMETER, 0)?;
                Ok(STATUS_INVALID_PARAMETER)
            }
        }
    }

    pub(crate) fn nt_query_directory_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let info = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg_u32(cpu, mem, 6)? as u64;
        let class_id = self.syscall_arg_u32(cpu, mem, 7)? as u64;
        let name_ptr = self.syscall_arg(cpu, mem, 9)?;
        let restart = self.syscall_arg_u32(cpu, mem, 10)? != 0;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let Some(&class) = DIR_INFO_CLASSES.iter().find(|c| c.class == class_id) else {
            write_iosb(mem, iosb_ptr, STATUS_INVALID_INFO_CLASS, 0)?;
            return Ok(STATUS_INVALID_INFO_CLASS);
        };

        let pattern = if name_ptr != 0 {
            read_unicode_string(mem, name_ptr).unwrap_or_else(|| "*".to_string())
        } else {
            "*".to_string()
        };
        let pattern = if pattern.is_empty() { "*".to_string() } else { pattern };

        if restart || !self.find_handles.contains_key(&handle) {
            let Some(dir) = self.dir_handle_guest_path(handle) else {
                return Ok(STATUS_INVALID_PARAMETER);
            };
            let entries = self.collect_dir_entries(&dir, &pattern);
            self.find_handles.insert(handle, FindState { entries, pos: 0, wide: true });
        }

        let entry = {
            let state = self.find_handles.get_mut(&handle).unwrap();
            if state.pos >= state.entries.len() {
                write_iosb(mem, iosb_ptr, STATUS_NO_MORE_FILES, 0)?;
                return Ok(STATUS_NO_MORE_FILES);
            }
            let e = state.entries[state.pos].clone();
            state.pos += 1;
            e
        };

        let name_units: Vec<u16> = entry.name.encode_utf16().collect();
        let name_bytes = name_units.len() as u64 * 2;
        let need = class.name_off + name_bytes;
        if length < need {
            write_iosb(mem, iosb_ptr, STATUS_BUFFER_TOO_SMALL, 0)?;
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        write_dir_information(mem, info, class, &entry, &name_units)?;
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, need)?;
        Ok(STATUS_SUCCESS)
    }

    fn collect_dir_entries(&self, dir: &str, pattern: &str) -> Vec<FindEntry> {
        let mut entries: Vec<FindEntry> = Vec::new();
        let Some(host_dir) = self.host_path(dir) else {
            return entries;
        };
        if let Ok(iter) = std::fs::read_dir(&host_dir) {
            for de in iter.flatten() {
                let name = de.file_name().to_string_lossy().into_owned();
                if !glob_matches(pattern, &name) {
                    continue;
                }
                let meta = de.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let (ctime, atime, mtime) = meta.as_ref().map(metadata_times).unwrap_or((0, 0, 0));
                entries.push(FindEntry { name, is_dir, size, ctime, atime, mtime });
            }
        }
        entries.sort_by_key(|a| a.name.to_ascii_lowercase());
        entries
    }
}

pub(crate) fn read_unicode_string(mem: &dyn Memory, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    let length = mem.read_u16(ptr).ok()? as u64;
    let buffer = mem.read_u64(ptr + 8).ok()?;
    if buffer == 0 {
        return Some(String::new());
    }
    let units = (length / 2) as usize;
    let mut v = Vec::with_capacity(units);
    for i in 0..units {
        v.push(mem.read_u16(buffer + (i as u64) * 2).ok()?);
    }
    Some(String::from_utf16_lossy(&v))
}

pub(crate) fn strip_nt_prefix(name: &str) -> String {
    for p in ["\\??\\", "\\\\?\\", "\\DosDevices\\", "\\GLOBAL??\\"] {
        if let Some(rest) = name.strip_prefix(p) {
            return rest.to_string();
        }
    }
    name.to_string()
}

fn write_iosb(mem: &mut dyn Memory, ptr: u64, status: u32, information: u64) -> Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    mem.write_u32(ptr, status)?;
    mem.write_u32(ptr + 4, 0)?;
    mem.write_u64(ptr + 8, information)?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DirInfoClass {
    class: u64,
    name_off: u64,
}

const FILE_BOTH_DIRECTORY_INFORMATION: DirInfoClass = DirInfoClass { class: 3, name_off: 0x5E };

const FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION: DirInfoClass =
    DirInfoClass { class: 0x3F, name_off: 0x72 };

const DIR_INFO_CLASSES: [DirInfoClass; 2] =
    [FILE_BOTH_DIRECTORY_INFORMATION, FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION];

fn write_dir_information(
    mem: &mut dyn Memory,
    ptr: u64,
    class: DirInfoClass,
    entry: &FindEntry,
    name_units: &[u16],
) -> Result<()> {
    let name_bytes = name_units.len() * 2;
    let zero = vec![0u8; class.name_off as usize];
    mem.write(ptr, &zero)?;
    mem.write_u32(ptr, 0)?;
    mem.write_u64(ptr + 0x08, entry.ctime)?;
    mem.write_u64(ptr + 0x10, entry.atime)?;
    mem.write_u64(ptr + 0x18, entry.mtime)?;
    mem.write_u64(ptr + 0x20, entry.mtime)?;
    mem.write_u64(ptr + 0x28, entry.size)?;
    mem.write_u64(ptr + 0x30, entry.size)?;
    let attrs: u32 = if entry.is_dir { FILE_ATTRIBUTE_DIRECTORY as u32 } else { FILE_ATTRIBUTE_NORMAL as u32 };
    mem.write_u32(ptr + 0x38, attrs)?;
    mem.write_u32(ptr + 0x3C, name_bytes as u32)?;
    for (i, u) in name_units.iter().enumerate() {
        mem.write_u16(ptr + class.name_off + (i as u64) * 2, *u)?;
    }
    Ok(())
}

pub(crate) fn ssdt_nt_create_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_file(cpu, mem)
}

pub(crate) fn ssdt_nt_open_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_file(cpu, mem)
}

pub(crate) fn ssdt_nt_query_attributes_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_attributes_file(cpu, mem)
}

pub(crate) fn ssdt_nt_fs_control_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_fs_control_file(cpu, mem)
}

pub(crate) fn ssdt_nt_close(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_close(cpu, mem)
}

pub(crate) fn ssdt_nt_read_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_read_file(cpu, mem)
}

pub(crate) fn ssdt_nt_write_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_write_file(cpu, mem)
}

pub(crate) fn ssdt_nt_query_information_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_information_file(cpu, mem)
}

pub(crate) fn ssdt_nt_query_directory_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_directory_file(cpu, mem)
}

pub(crate) fn ssdt_nt_query_volume_information_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_volume_information_file(cpu, mem)
}
