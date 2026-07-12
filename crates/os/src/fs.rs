//! A host-backed guest filesystem, rooted at a sandbox directory.
//!
//! Guest Windows paths are mapped into the sandbox so that installers and
//! command-line tools can create directories, write files and read them back
//! without touching the real filesystem outside the sandbox. Everything here
//! is best-effort: unknown flags are ignored and errors surface as the
//! Windows failure values the caller expects.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use exemu_core::{CpuState, Memory, Result};

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
        self.file_dirs.remove(&handle);
        self.find_handles.remove(&handle);
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

// ---------------------------------------------------------------------------
// NT file syscalls (roadmap W2.8) — the NTSTATUS / IO_STATUS_BLOCK face of the
// sandbox filesystem the Win32 `CreateFileW`/`ReadFile`/… APIs drive.
//
// Wine's PE `ntdll.dll` reaches these through a raw `SYSCALL` (the SSDT index in
// EAX, recovered from the pinned guest stubs' `mov eax,N`): NtReadFile = 0x06,
// NtWriteFile = 0x08, NtQueryInformationFile = 0x11, NtQueryDirectoryFile =
// 0x35, NtQueryVolumeInformationFile = 0x49, NtCreateFile = 0x55. The W2.3
// dispatcher has already saved the context and switched to the unix stack; each
// handler reads its arguments via [`WinOs::syscall_arg`] (arg0=R10, arg1=RDX,
// arg2=R8, arg3=R9, args 5+ on the guest stack) and returns an NTSTATUS the
// dispatcher places in RAX.
//
// The object namespace: a guest file is named by an OBJECT_ATTRIBUTES whose
// ObjectName UNICODE_STRING is an NT path like `\??\C:\dir\file`. exemu strips
// the `\??\` (DOS-device) prefix and hands the remaining `C:\…` to the P3.9
// sandbox (`host_path`). A RootDirectory handle names a base directory the
// ObjectName is relative to (used by Wine's directory-relative opens).
//
// Clean-room Class B: struct layouts (UNICODE_STRING / OBJECT_ATTRIBUTES /
// IO_STATUS_BLOCK / FILE_*_INFORMATION) are the public `winternl.h` / `ntifs.h`
// definitions; the SSDT indices come from the pinned guest binary — no Wine
// `.c` was read.

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_END_OF_FILE` — a read reached EOF with no bytes transferred.
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
/// `STATUS_NO_MORE_FILES` — a directory enumeration is exhausted.
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
/// `STATUS_INVALID_PARAMETER` — a required pointer argument was NULL, or an
/// unsupported information class was requested.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_INVALID_HANDLE` — the handle names no live file.
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// `STATUS_OBJECT_NAME_NOT_FOUND` — the named file does not exist (and the
/// disposition does not create it).
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
/// `STATUS_BUFFER_TOO_SMALL` — the caller's buffer cannot hold the fixed part
/// of the requested information class.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

// NtCreateFile `CreateDisposition` (arg — distinct from the Win32 disposition).
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

// NtCreateFile `DesiredAccess` bits we care about.
const FILE_WRITE_DATA: u64 = 0x0000_0002;
const FILE_APPEND_DATA: u64 = 0x0000_0004;
const NT_GENERIC_WRITE: u64 = 0x4000_0000; // GENERIC_WRITE

// IO_STATUS_BLOCK.Information for a create/open (the disposition that occurred).
const FILE_SUPERSEDED: u64 = 0;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;
const FILE_OVERWRITTEN: u64 = 3;

// FILE_INFORMATION_CLASS values used by NtQueryInformationFile.
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_END_OF_FILE_INFORMATION: u32 = 20; // returns std info shape for size

// FS_INFORMATION_CLASS values used by NtQueryVolumeInformationFile.
const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_CREATE_FILE: u32 = 0x55;
pub(crate) const SSDT_NT_READ_FILE: u32 = 0x06;
pub(crate) const SSDT_NT_WRITE_FILE: u32 = 0x08;
pub(crate) const SSDT_NT_QUERY_INFORMATION_FILE: u32 = 0x11;
pub(crate) const SSDT_NT_QUERY_DIRECTORY_FILE: u32 = 0x35;
pub(crate) const SSDT_NT_QUERY_VOLUME_INFORMATION_FILE: u32 = 0x49;

impl WinOs {
    /// Resolve an `OBJECT_ATTRIBUTES*` to a guest Windows path (`C:\…`), applying
    /// the DOS-device `\??\` prefix strip and any `RootDirectory` base directory.
    /// Returns `None` if the pointer is NULL or the name cannot be read.
    fn nt_object_name(&self, mem: &dyn Memory, objattr: u64) -> Option<String> {
        if objattr == 0 {
            return None;
        }
        // OBJECT_ATTRIBUTES (64-bit): Length@0, RootDirectory@8, ObjectName@0x10.
        let root_dir = mem.read_u64(objattr + 8).ok()?;
        let name_ptr = mem.read_u64(objattr + 0x10).ok()?;
        let name = read_unicode_string(mem, name_ptr)?;
        // Strip the DOS-device namespace prefix so the sandbox sees `C:\…`.
        let name = strip_nt_prefix(&name);

        // A RootDirectory handle names a base directory for a relative name. We
        // only model file handles opened over sandbox directories: recover the
        // directory's guest path and join it.
        if root_dir != 0 && root_dir != u64::MAX {
            if let Some(base) = self.dir_handle_guest_path(root_dir) {
                let sep = if base.ends_with('\\') || name.is_empty() { "" } else { "\\" };
                return Some(format!("{base}{sep}{name}"));
            }
        }
        Some(name)
    }

    /// The guest path recorded for an open directory handle (for RootDirectory-
    /// relative opens). `None` if the handle is not a tracked open directory.
    fn dir_handle_guest_path(&self, handle: u64) -> Option<String> {
        self.file_dirs.get(&handle).cloned()
    }

    /// `NtCreateFile(*FileHandle, DesiredAccess, *ObjectAttributes,
    /// *IoStatusBlock, *AllocationSize, FileAttributes, ShareAccess,
    /// CreateDisposition, CreateOptions, EaBuffer, EaLength)`.
    /// arg0=&FileHandle, arg1=DesiredAccess, arg2=&ObjectAttributes,
    /// arg3=&IoStatusBlock, arg4=&AllocationSize, arg5=FileAttributes,
    /// arg6=ShareAccess, arg7=CreateDisposition, arg8=CreateOptions.
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

        // Record whether the handle names a directory so a RootDirectory-relative
        // open (and NtQueryDirectoryFile) can resolve against it later.
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

    /// `NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
    /// Buffer, Length, *ByteOffset, Key)`. arg0=FileHandle, arg4=&IoStatusBlock,
    /// arg5=Buffer, arg6=Length, arg7=&ByteOffset.
    pub(crate) fn nt_read_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let buffer = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg(cpu, mem, 6)?;
        let offset_ptr = self.syscall_arg(cpu, mem, 7)?;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        // Honour an explicit ByteOffset (Wine passes one for synchronous reads);
        // a negative sentinel (FILE_USE_FILE_POINTER_POSITION) keeps the cursor.
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

    /// `NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
    /// Buffer, Length, *ByteOffset, Key)`. arg0=FileHandle, arg4=&IoStatusBlock,
    /// arg5=Buffer, arg6=Length, arg7=&ByteOffset.
    pub(crate) fn nt_write_file(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let buffer = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg(cpu, mem, 6)?;
        let offset_ptr = self.syscall_arg(cpu, mem, 7)?;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        if offset_ptr != 0 {
            let off = mem.read_u64(offset_ptr)?;
            // FILE_WRITE_TO_END_OF_FILE (0xFFFFFFFF_FFFFFFFF) appends; a plain
            // negative sentinel keeps the cursor; a nonneg offset seeks.
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

    /// `NtQueryInformationFile(FileHandle, *IoStatusBlock, FileInformation,
    /// Length, FileInformationClass)`. arg0=FileHandle, arg1=&IoStatusBlock,
    /// arg2=FileInformation, arg3=Length, arg4=FileInformationClass.
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
                // FILE_STANDARD_INFORMATION (0x18 bytes): AllocationSize (i64) @0,
                // EndOfFile (i64) @8, NumberOfLinks (u32) @0x10, DeletePending
                // (u8) @0x14, Directory (u8) @0x15.
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
                // FILE_END_OF_FILE_INFORMATION: EndOfFile (i64) @0.
                if length < 8 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, size)?;
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 8)?;
                Ok(STATUS_SUCCESS)
            }
            FILE_POSITION_INFORMATION => {
                // FILE_POSITION_INFORMATION: CurrentByteOffset (i64) @0.
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

    /// `NtQueryVolumeInformationFile(FileHandle, *IoStatusBlock, FsInformation,
    /// Length, FsInformationClass)`. arg0=FileHandle, arg1=&IoStatusBlock,
    /// arg2=FsInformation, arg3=Length, arg4=FsInformationClass.
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
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        match class {
            FILE_FS_SIZE_INFORMATION => {
                // FILE_FS_SIZE_INFORMATION (0x18): TotalAllocationUnits (i64) @0,
                // AvailableAllocationUnits (i64) @8, SectorsPerAllocationUnit
                // (u32) @0x10, BytesPerSector (u32) @0x14. Report a nominal large
                // volume (the sandbox is host-backed; exact figures don't matter).
                if length < 0x18 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(info, 0x0010_0000)?; // 1M units
                mem.write_u64(info + 8, 0x0008_0000)?; // 512K free
                mem.write_u32(info + 0x10, 8)?; // 8 sectors/unit
                mem.write_u32(info + 0x14, 512)?; // 512 bytes/sector
                write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 0x18)?;
                Ok(STATUS_SUCCESS)
            }
            FILE_FS_DEVICE_INFORMATION => {
                // FILE_FS_DEVICE_INFORMATION (0x08): DeviceType (u32) @0,
                // Characteristics (u32) @4. FILE_DEVICE_DISK = 7.
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

    /// `NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
    /// *IoStatusBlock, FileInformation, Length, FileInformationClass,
    /// ReturnSingleEntry, *FileName, RestartScan)`. arg0=FileHandle,
    /// arg4=&IoStatusBlock, arg5=FileInformation, arg6=Length,
    /// arg7=FileInformationClass, arg8=ReturnSingleEntry, arg9=*FileName,
    /// arg10=RestartScan.
    ///
    /// Emits **FILE_BOTH_DIR_INFORMATION** (class 3) — the class Wine's
    /// `FindFirstFile`/readdir path requests — one entry per call. The directory
    /// handle carries the enumeration cursor (a `FindState` keyed by the handle),
    /// (re)built on the first call or when `RestartScan` is set.
    pub(crate) fn nt_query_directory_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 4)?;
        let info = self.syscall_arg(cpu, mem, 5)?;
        let length = self.syscall_arg(cpu, mem, 6)?;
        let name_ptr = self.syscall_arg(cpu, mem, 9)?;
        let restart = self.syscall_arg(cpu, mem, 10)? != 0;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }

        // The wildcard (optional): a UNICODE_STRING* naming the search pattern.
        let pattern = if name_ptr != 0 {
            read_unicode_string(mem, name_ptr).unwrap_or_else(|| "*".to_string())
        } else {
            "*".to_string()
        };
        let pattern = if pattern.is_empty() { "*".to_string() } else { pattern };

        // (Re)build the enumeration cursor on the first call / RestartScan.
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
        let name_bytes = name_units.len() * 2;
        // FILE_BOTH_DIR_INFORMATION fixed part = 0x60 bytes, then the name.
        let need = 0x60 + name_bytes;
        if length < need as u64 {
            write_iosb(mem, iosb_ptr, STATUS_BUFFER_TOO_SMALL, 0)?;
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        write_both_dir_information(mem, info, &entry, &name_units)?;
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, need as u64)?;
        Ok(STATUS_SUCCESS)
    }

    /// Collect the sandbox directory entries under guest path `dir` matching the
    /// wildcard `pattern`, as `FindEntry`s (reusing the FindFirstFile machinery).
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

/// Read a `UNICODE_STRING` (64-bit layout: `USHORT Length; USHORT MaximumLength;
/// PWSTR Buffer` — Buffer at offset 8) into a `String`. `Length` is a **byte**
/// count, not units, and the buffer is not necessarily NUL-terminated.
pub(crate) fn read_unicode_string(mem: &dyn Memory, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    let length = mem.read_u16(ptr).ok()? as u64; // bytes
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

/// Strip the DOS-device / Win32 file-namespace prefix from an NT path so the
/// sandbox sees a plain `C:\…` drive path: `\??\`, `\\?\`, `\DosDevices\`.
pub(crate) fn strip_nt_prefix(name: &str) -> String {
    for p in ["\\??\\", "\\\\?\\", "\\DosDevices\\", "\\GLOBAL??\\"] {
        if let Some(rest) = name.strip_prefix(p) {
            return rest.to_string();
        }
    }
    name.to_string()
}

/// Write an `IO_STATUS_BLOCK` (64-bit: `union { NTSTATUS Status; PVOID Pointer };
/// ULONG_PTR Information` — Status@0, Information@8). NULL pointer is a no-op.
fn write_iosb(mem: &mut dyn Memory, ptr: u64, status: u32, information: u64) -> Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    mem.write_u32(ptr, status)?;
    mem.write_u32(ptr + 4, 0)?; // upper half of the Status/Pointer union
    mem.write_u64(ptr + 8, information)?;
    Ok(())
}

/// Write a `FILE_BOTH_DIR_INFORMATION` (fixed part 0x60 bytes, then the file
/// name) into guest memory for one directory entry. `NextEntryOffset` is 0
/// (single-entry-per-call model).
///
/// ```text
///   0x00 NextEntryOffset   ULONG   (0 — last/only entry)
///   0x04 FileIndex         ULONG
///   0x08 CreationTime      LARGE_INTEGER
///   0x10 LastAccessTime    LARGE_INTEGER
///   0x18 LastWriteTime     LARGE_INTEGER
///   0x20 ChangeTime        LARGE_INTEGER
///   0x28 EndOfFile         LARGE_INTEGER
///   0x30 AllocationSize    LARGE_INTEGER
///   0x38 FileAttributes    ULONG
///   0x3C FileNameLength    ULONG   (bytes)
///   0x40 EaSize            ULONG
///   0x44 ShortNameLength   CCHAR
///   0x46 ShortName         WCHAR[12] (0x18 bytes)
///   0x5E (pad to)          0x60
///   0x60 FileName          WCHAR[]
/// ```
fn write_both_dir_information(
    mem: &mut dyn Memory,
    ptr: u64,
    entry: &FindEntry,
    name_units: &[u16],
) -> Result<()> {
    let name_bytes = name_units.len() * 2;
    // Zero the fixed part (also clears ShortName and the pad).
    mem.write(ptr, &[0u8; 0x60])?;
    mem.write_u32(ptr, 0)?; // NextEntryOffset
    mem.write_u64(ptr + 0x08, entry.ctime)?;
    mem.write_u64(ptr + 0x10, entry.atime)?;
    mem.write_u64(ptr + 0x18, entry.mtime)?;
    mem.write_u64(ptr + 0x20, entry.mtime)?; // ChangeTime ≈ LastWriteTime
    mem.write_u64(ptr + 0x28, entry.size)?; // EndOfFile
    mem.write_u64(ptr + 0x30, entry.size)?; // AllocationSize
    let attrs: u32 = if entry.is_dir { FILE_ATTRIBUTE_DIRECTORY as u32 } else { FILE_ATTRIBUTE_NORMAL as u32 };
    mem.write_u32(ptr + 0x38, attrs)?;
    mem.write_u32(ptr + 0x3C, name_bytes as u32)?;
    // FileName at 0x60.
    for (i, u) in name_units.iter().enumerate() {
        mem.write_u16(ptr + 0x60 + (i as u64) * 2, *u)?;
    }
    Ok(())
}

/// SSDT thunk for `NtCreateFile` (index 0x55).
pub(crate) fn ssdt_nt_create_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_file(cpu, mem)
}

/// SSDT thunk for `NtReadFile` (index 0x06).
pub(crate) fn ssdt_nt_read_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_read_file(cpu, mem)
}

/// SSDT thunk for `NtWriteFile` (index 0x08).
pub(crate) fn ssdt_nt_write_file(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_write_file(cpu, mem)
}

/// SSDT thunk for `NtQueryInformationFile` (index 0x11).
pub(crate) fn ssdt_nt_query_information_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_information_file(cpu, mem)
}

/// SSDT thunk for `NtQueryDirectoryFile` (index 0x35).
pub(crate) fn ssdt_nt_query_directory_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_directory_file(cpu, mem)
}

/// SSDT thunk for `NtQueryVolumeInformationFile` (index 0x49).
pub(crate) fn ssdt_nt_query_volume_information_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_volume_information_file(cpu, mem)
}
