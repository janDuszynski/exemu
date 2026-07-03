//! A host-backed guest filesystem, rooted at a sandbox directory.
//!
//! Guest Windows paths are mapped into the sandbox so that installers and
//! command-line tools can create directories, write files and read them back
//! without touching the real filesystem outside the sandbox. Everything here
//! is best-effort: unknown flags are ignored and errors surface as the
//! Windows failure values the caller expects.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use exemu_core::{Memory, Result};

use crate::WinOs;

/// An open file the guest is holding a handle to.
pub struct OpenFile {
    pub file: std::fs::File,
}

// Windows constants.
pub const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF; // (HANDLE)-1 as seen by 32-bit callers
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;
// CreateFile dwCreationDisposition
const CREATE_NEW: u64 = 1;
const CREATE_ALWAYS: u64 = 2;
const OPEN_EXISTING: u64 = 3;
const OPEN_ALWAYS: u64 = 4;
const TRUNCATE_EXISTING: u64 = 5;
// Generic access rights
const GENERIC_WRITE: u64 = 0x4000_0000;

impl WinOs {
    /// Whether a guest handle refers to an open file.
    pub(crate) fn is_file_handle(&self, handle: u64) -> bool {
        self.files.contains_key(&handle)
    }

    /// Translate a guest Windows path into a host path under the sandbox.
    /// A drive prefix (`C:`) becomes a directory named after the letter, and
    /// backslashes become path separators; `..` components are dropped so a
    /// guest cannot escape the sandbox.
    pub(crate) fn host_path(&self, guest: &str) -> Option<PathBuf> {
        if self.cfg.sandbox.is_empty() {
            return None;
        }
        let mut out = PathBuf::from(&self.cfg.sandbox);
        let cleaned = guest.trim_start_matches("\\\\?\\").replace('\\', "/");
        for comp in cleaned.split('/') {
            match comp {
                "" | "." | ".." => {}
                c if c.ends_with(':') => out.push(&c[..c.len() - 1]), // drive letter
                c => out.push(c),
            }
        }
        Some(out)
    }

    fn alloc_handle(&mut self, f: std::fs::File) -> u64 {
        let h = self.next_handle;
        self.next_handle += 4;
        self.files.insert(h, OpenFile { file: f });
        h
    }

    // ---- the file APIs ---------------------------------------------------

    /// CreateFileW(name, access, share, sa, disposition, flags, template).
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
                self.set_last_error(2); // ERROR_FILE_NOT_FOUND
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
        self.files.remove(&handle).is_some()
    }

    pub(crate) fn file_size(&self, handle: u64) -> Option<u64> {
        let of = self.files.get(&handle)?;
        of.file.metadata().ok().map(|m| m.len())
    }

    /// SetFilePointer(handle, distance, high, method) → new position (low 32).
    pub(crate) fn set_file_pointer(&mut self, handle: u64, distance: i64, method: u64) -> u64 {
        let Some(of) = self.files.get_mut(&handle) else {
            return INVALID_HANDLE_VALUE;
        };
        let seek = match method {
            0 => SeekFrom::Start(distance.max(0) as u64), // FILE_BEGIN
            1 => SeekFrom::Current(distance),             // FILE_CURRENT
            _ => SeekFrom::End(distance),                 // FILE_END
        };
        of.file.seek(seek).unwrap_or(0) & 0xFFFF_FFFF
    }

    /// GetTempFileNameW: pick a unique name in `dir` with `prefix`, create an
    /// empty file for it, and return the guest path plus the unique number.
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
        // Create an empty file so a later CreateFile(OPEN_EXISTING) succeeds.
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

    pub(crate) fn file_attributes(&self, name: &str) -> u64 {
        match self.host_path(name).as_deref().map(Path::metadata) {
            Some(Ok(m)) if m.is_dir() => FILE_ATTRIBUTE_DIRECTORY,
            Some(Ok(_)) => FILE_ATTRIBUTE_NORMAL,
            _ => INVALID_FILE_ATTRIBUTES,
        }
    }

    /// Write a UTF-16 string (with NUL) into guest memory, returning the
    /// number of code units written excluding the terminator.
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

    fn set_last_error(&mut self, code: u32) {
        self.last_error = code;
    }
}
