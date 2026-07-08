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

/// One entry collected during a directory enumeration.
#[derive(Clone)]
pub struct FindEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Creation time as FILETIME (100-ns intervals since 1601-01-01 UTC).
    pub ctime: u64,
    /// Last access time as FILETIME.
    pub atime: u64,
    /// Last write/modification time as FILETIME.
    pub mtime: u64,
}

/// State associated with an open directory-enumeration handle
/// (FindFirstFile / FindNextFile / FindClose).
pub struct FindState {
    pub entries: Vec<FindEntry>,
    pub pos: usize,
    /// Whether entries marshal as `WIN32_FIND_DATAW` (true) or …A (false); set
    /// by `FindFirstFile` and honoured by `FindNextFile` for the same handle.
    pub wide: bool,
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
        if self.kobjects.remove(&handle).is_some() {
            self.named_kobjects.retain(|_, &mut h| h != handle);
            return true;
        }
        self.files.remove(&handle).is_some()
    }

    /// Allocate a fresh, unique kernel handle value (shared monotonic space
    /// with file/find handles, so `CloseHandle` can route by lookup).
    pub(crate) fn alloc_khandle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 4;
        h
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

    /// GetFullPathName: turn a possibly-relative guest path into an absolute
    /// one. Relative names resolve against `C:\` (the sandbox root); already-
    /// absolute paths (drive-qualified or UNC) are returned normalised to
    /// backslashes. `.`/`..` collapsing is not modelled.
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

    /// MoveFile/MoveFileEx: rename within the sandbox, falling back to
    /// copy+delete across host devices.
    pub(crate) fn move_file(&mut self, src: &str, dst: &str) -> bool {
        let (Some(s), Some(d)) = (self.host_path(src), self.host_path(dst)) else {
            self.set_last_error(2); // ERROR_FILE_NOT_FOUND
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

    /// CopyFile: duplicate a sandbox file; honour `fail_if_exists`.
    pub(crate) fn copy_file(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> bool {
        let (Some(s), Some(d)) = (self.host_path(src), self.host_path(dst)) else {
            self.set_last_error(2);
            return false;
        };
        if fail_if_exists && d.exists() {
            self.set_last_error(80); // ERROR_FILE_EXISTS
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

    pub(crate) fn set_last_error(&mut self, code: u32) {
        self.last_error = code;
    }

    // ---- directory enumeration (FindFirstFileW / FindNextFileW) ----------

    /// FindFirstFileW / FindFirstFileExW: enumerate sandbox entries whose names
    /// match the wildcard `leaf` inside `dir`, write the first match into
    /// the guest `WIN32_FIND_DATAW` buffer at `data_ptr`, and return a find
    /// handle. Returns `INVALID_HANDLE_VALUE` (and sets last-error 2) when
    /// there are no matches or the directory does not exist.
    pub(crate) fn find_first_file(
        &mut self,
        mem: &mut dyn Memory,
        pattern: &str,
        data_ptr: u64,
        wide: bool,
    ) -> Result<u64> {
        // Split the guest path into a directory part and the wildcard leaf.
        let (dir, leaf) = match pattern.rfind('\\') {
            Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
            None => ("", pattern),
        };

        let Some(host_dir) = self.host_path(dir) else {
            self.set_last_error(2); // ERROR_FILE_NOT_FOUND
            return Ok(INVALID_HANDLE_VALUE);
        };

        let mut entries: Vec<FindEntry> = Vec::new();

        // Virtual "." entry — the directory itself.
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

        // Virtual ".." entry — the parent directory.
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

        // Real entries from the host directory.
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

        // Sort case-insensitively for determinism.  "." and ".." sort before
        // alphabetic names (ASCII 0x2E < 0x61) so they naturally come first.
        entries.sort_by(|a, b| {
            a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase())
        });

        if entries.is_empty() {
            self.set_last_error(2); // ERROR_FILE_NOT_FOUND
            return Ok(INVALID_HANDLE_VALUE);
        }

        // Marshal the first entry into the guest buffer.
        write_find_data(mem, data_ptr, &entries[0], wide)?;

        // Allocate a find handle from the same monotonic counter as file
        // handles (but we do NOT add it to `self.files`, so is_file_handle
        // correctly returns false for find handles).
        let h = self.next_handle;
        self.next_handle += 4;
        self.find_handles.insert(h, FindState { entries, pos: 1, wide });

        Ok(h)
    }

    /// FindNextFileW: advance to the next matching entry and marshal it.
    /// Returns TRUE (1) on success; sets last-error ERROR_NO_MORE_FILES (18)
    /// and returns FALSE (0) when the list is exhausted or the handle is unknown.
    pub(crate) fn find_next_file(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        data_ptr: u64,
    ) -> Result<u64> {
        let Some(state) = self.find_handles.get_mut(&handle) else {
            self.set_last_error(18); // ERROR_NO_MORE_FILES
            return Ok(0);
        };
        if state.pos < state.entries.len() {
            let entry = state.entries[state.pos].clone();
            let wide = state.wide;
            state.pos += 1;
            write_find_data(mem, data_ptr, &entry, wide)?;
            Ok(1)
        } else {
            self.set_last_error(18); // ERROR_NO_MORE_FILES
            Ok(0)
        }
    }

    /// FindClose: release a find handle. Always returns TRUE; lenient for
    /// unknown handles (a close after exhaustion is harmless).
    pub(crate) fn find_close(&mut self, handle: u64) -> u64 {
        self.find_handles.remove(&handle);
        1 // TRUE
    }
}

// ---- free helpers -----------------------------------------------------------

/// Write a `WIN32_FIND_DATAW`/`WIN32_FIND_DATAA` into guest memory. Fields
/// 0..44 are identical; only the trailing name arrays differ:
/// ```text
///   0  dwFileAttributes  DWORD
///   4  ftCreationTime    FILETIME (low @ 4, high @ 8)
///  12  ftLastAccessTime  FILETIME (low @12, high @16)
///  20  ftLastWriteTime   FILETIME (low @20, high @24)
///  28  nFileSizeHigh     DWORD   (high BEFORE low)
///  32  nFileSizeLow      DWORD
///  36  dwReserved0/1     DWORD × 2
///  44  cFileName          WCHAR[260] (…W, 520B) | CHAR[260] (…A, 260B)
/// tail cAlternateFileName  WCHAR[14]  (…W)       | CHAR[14]  (…A)
/// ```
/// Total size: 592 bytes (W) or 318 bytes (A).
fn write_find_data(mem: &mut dyn Memory, ptr: u64, entry: &FindEntry, wide: bool) -> Result<()> {
    let total = if wide { 592 } else { 318 };
    // Zero the whole structure first (also clears cAlternateFileName).
    mem.write(ptr, &vec![0u8; total])?;

    let attrs: u32 = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY as u32 // 0x10
    } else {
        FILE_ATTRIBUTE_NORMAL as u32 // 0x80
    };
    mem.write_u32(ptr, attrs)?;

    mem.write_u32(ptr + 4, entry.ctime as u32)?;
    mem.write_u32(ptr + 8, (entry.ctime >> 32) as u32)?;
    mem.write_u32(ptr + 12, entry.atime as u32)?;
    mem.write_u32(ptr + 16, (entry.atime >> 32) as u32)?;
    mem.write_u32(ptr + 20, entry.mtime as u32)?;
    mem.write_u32(ptr + 24, (entry.mtime >> 32) as u32)?;
    // nFileSizeHigh @ 28 (HIGH comes BEFORE low), nFileSizeLow @ 32.
    mem.write_u32(ptr + 28, (entry.size >> 32) as u32)?;
    mem.write_u32(ptr + 32, entry.size as u32)?;

    // cFileName at offset 44 (already NUL-terminated by the zero-fill).
    if wide {
        WinOs::write_wstr(mem, ptr + 44, &entry.name, 260)?;
    } else {
        crate::api::write_astr(mem, ptr + 44, &entry.name, 260)?;
    }
    Ok(())
}

/// Convert `std::fs::Metadata` timestamps to FILETIME values
/// (100-nanosecond intervals since 1601-01-01 00:00:00 UTC).
/// Returns `(ctime, atime, mtime)`. Any unavailable time becomes 0.
fn metadata_times(meta: &std::fs::Metadata) -> (u64, u64, u64) {
    /// Difference in 100-ns units between the Windows epoch (1601-01-01) and
    /// the UNIX epoch (1970-01-01): 11644473600 seconds × 10_000_000.
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

/// Case-insensitive wildcard glob: `*` matches any run of characters (including
/// empty), `?` matches exactly one character. `*.*` is treated as `*`
/// (matches everything, including names with no dot) per Windows convention.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let effective_pat: &str = if pattern == "*.*" { "*" } else { pattern };
    let p: Vec<char> = effective_pat.chars().map(|c| c.to_ascii_lowercase()).collect();
    let n: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    glob_ci(&p, &n)
}

/// Recursive case-insensitive glob core (operates on char slices that have
/// already been lower-cased).
fn glob_ci(p: &[char], n: &[char]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some('*') => {
            // '*' matches 0 or more characters from `n`.
            (0..=n.len()).any(|i| glob_ci(&p[1..], &n[i..]))
        }
        Some('?') => !n.is_empty() && glob_ci(&p[1..], &n[1..]),
        Some(pc) => matches!(n.first(), Some(nc) if *nc == *pc) && glob_ci(&p[1..], &n[1..]),
    }
}
