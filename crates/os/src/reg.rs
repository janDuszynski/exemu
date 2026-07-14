//! In-memory registry hive with W/A round-trip and enumeration (roadmap P3.12).
//!
//! Keys live in a flat map `full path → (value name → (REG_* type, raw bytes))`
//! (`reg_hive`), so every value type round-trips as opaque bytes. Sub-key
//! enumeration treats the flat map as a tree (a deep path implies its
//! ancestors). HKLM/HKCU are seeded with a handful of values real installers
//! probe. Persistence across runs is still a TODO.

use std::collections::BTreeSet;

use exemu_core::{CpuState, Memory, Result};

use crate::api::{read_path, write_astr, Outcome};
use crate::WinOs;

// Value types.
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
// Return codes.
const ERROR_SUCCESS: u64 = 0;
const ERROR_FILE_NOT_FOUND: u64 = 2;
const ERROR_INVALID_HANDLE: u64 = 6;
const ERROR_MORE_DATA: u64 = 234;
const ERROR_NO_MORE_ITEMS: u64 = 259;

/// Encode a REG_SZ value as UTF-16LE bytes (with terminator), as a W-query
/// caller expects.
fn sz(s: &str) -> (u32, Vec<u8>) {
    let mut b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.extend([0, 0]);
    (REG_SZ, b)
}

fn dword(v: u32) -> (u32, Vec<u8>) {
    (REG_DWORD, v.to_le_bytes().to_vec())
}

impl WinOs {
    /// Resolve `hkey` + a sub-key path into a canonical full path.
    fn reg_join(&self, hkey: u64, subkey: &str) -> Option<String> {
        let base = self.reg_resolve(hkey)?;
        Some(if subkey.is_empty() { base } else { format!("{base}\\{subkey}") })
    }

    /// The immediate sub-key names of `base` (the hive is treated as a tree, so
    /// a deep path materialises its ancestors' membership).
    fn subkeys(&self, base: &str) -> Vec<String> {
        let prefix = format!("{base}\\");
        let mut set = BTreeSet::new();
        for k in self.reg_hive.keys() {
            if let Some(rest) = k.strip_prefix(&prefix) {
                if let Some(first) = rest.split('\\').next() {
                    set.insert(first.to_string());
                }
            }
        }
        set.into_iter().collect()
    }

    /// Seed HKLM/HKCU with values installers commonly probe.
    pub(crate) fn reg_seed(&mut self) {
        // (key path, value name, (REG_* type, raw bytes)).
        type Seed<'a> = (&'a str, &'a str, (u32, Vec<u8>));
        let entries: &[Seed] = &[
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", sz("Windows 10 Pro")),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentVersion", sz("6.3")),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber", sz("19045")),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentMajorVersionNumber", dword(10)),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProgramFilesDir", sz("C:\\Program Files")),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "CommonFilesDir", sz("C:\\Program Files\\Common Files")),
            ("HKCU\\Software", "", sz("")),
        ];
        for (path, name, val) in entries {
            self.reg_hive.entry((*path).to_string()).or_default().insert((*name).to_string(), val.clone());
        }
    }

    /// RegCreateKeyEx[AW]: create or open a key; allocate a handle.
    pub(crate) fn reg_create(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let subkey = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let phk_result = self.arg(cpu, mem, 7)?;
        let lpdw_disp = self.arg(cpu, mem, 8)?;
        let Some(path) = self.reg_join(hkey, &subkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let existed = self.reg_hive.contains_key(&path);
        self.reg_hive.entry(path.clone()).or_default();
        let handle = self.alloc_khandle();
        self.reg_handles.insert(handle, path);
        if phk_result != 0 {
            self.write_ptr(mem, phk_result, handle)?;
        }
        if lpdw_disp != 0 {
            mem.write_u32(lpdw_disp, if existed { 2 } else { 1 })?; // OPENED / CREATED
        }
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegOpenKeyEx[AW]: open an existing key (no auto-create).
    pub(crate) fn reg_open(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let subkey = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let phk_result = self.arg(cpu, mem, 4)?;
        let Some(path) = self.reg_join(hkey, &subkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        // A key exists if it has its own entry or any descendant.
        let exists = self.reg_hive.contains_key(&path)
            || self.reg_hive.keys().any(|k| k.starts_with(&format!("{path}\\")));
        if !exists {
            self.last_error = ERROR_FILE_NOT_FOUND as u32;
            return Ok(Outcome::Return(ERROR_FILE_NOT_FOUND));
        }
        let handle = self.alloc_khandle();
        self.reg_handles.insert(handle, path);
        if phk_result != 0 {
            self.write_ptr(mem, phk_result, handle)?;
        }
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegSetValueEx[AW]: write a named value.
    pub(crate) fn reg_set(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let name = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let dw_type = self.arg(cpu, mem, 3)? as u32;
        let lp_data = self.arg(cpu, mem, 4)?;
        let cb_data = self.arg(cpu, mem, 5)? as usize;
        let Some(path) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let mut data = vec![0u8; cb_data];
        if lp_data != 0 && cb_data > 0 {
            mem.read(lp_data, &mut data)?;
        }
        self.reg_hive.entry(path).or_default().insert(name, (dw_type, data));
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegQueryValueEx[AW]: read a named value (with size-query protocol).
    pub(crate) fn reg_query(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let name = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let lp_type = self.arg(cpu, mem, 3)?;
        let lp_data = self.arg(cpu, mem, 4)?;
        let lpcb_data = self.arg(cpu, mem, 5)?;
        let Some(path) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let Some((ty, data)) = self.reg_hive.get(&path).and_then(|m| m.get(&name)).map(|(t, d)| (*t, d.clone())) else {
            self.last_error = ERROR_FILE_NOT_FOUND as u32;
            return Ok(Outcome::Return(ERROR_FILE_NOT_FOUND));
        };
        if lp_type != 0 {
            mem.write_u32(lp_type, ty)?;
        }
        let data_len = data.len() as u32;
        if lpcb_data == 0 {
            return Ok(Outcome::Return(ERROR_SUCCESS));
        }
        if lp_data == 0 {
            mem.write_u32(lpcb_data, data_len)?; // size query
            return Ok(Outcome::Return(ERROR_SUCCESS));
        }
        let buf_size = mem.read_u32(lpcb_data)?;
        if buf_size < data_len {
            mem.write_u32(lpcb_data, data_len)?;
            return Ok(Outcome::Return(ERROR_MORE_DATA));
        }
        mem.write(lp_data, &data)?;
        mem.write_u32(lpcb_data, data_len)?;
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegCloseKey: free an open handle (predefined roots are no-ops).
    pub(crate) fn reg_close(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        self.reg_handles.remove(&hkey);
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegDeleteValue[AW]: remove a named value.
    pub(crate) fn reg_delete_value(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let name = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let Some(path) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let removed = self.reg_hive.get_mut(&path).and_then(|m| m.remove(&name)).is_some();
        if removed {
            Ok(Outcome::Return(ERROR_SUCCESS))
        } else {
            self.last_error = ERROR_FILE_NOT_FOUND as u32;
            Ok(Outcome::Return(ERROR_FILE_NOT_FOUND))
        }
    }

    /// RegDeleteKey[Ex][AW]: remove a sub-key (and its descendants).
    pub(crate) fn reg_delete_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let subkey = read_path(mem, self.arg(cpu, mem, 1)?, wide)?;
        let Some(path) = self.reg_join(hkey, &subkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let descendants = format!("{path}\\");
        self.reg_hive.retain(|k, _| k != &path && !k.starts_with(&descendants));
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegEnumKeyEx[AW]: the `dwIndex`-th sub-key name.
    pub(crate) fn reg_enum_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let index = self.arg(cpu, mem, 1)? as usize;
        let name_ptr = self.arg(cpu, mem, 2)?;
        let cch_ptr = self.arg(cpu, mem, 3)?;
        let ft_ptr = self.arg(cpu, mem, 7)?;
        let Some(base) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let subs = self.subkeys(&base);
        let Some(name) = subs.get(index).cloned() else {
            return Ok(Outcome::Return(ERROR_NO_MORE_ITEMS));
        };
        let r = write_reg_name(mem, name_ptr, cch_ptr, &name, wide)?;
        if ft_ptr != 0 {
            mem.write_u64(ft_ptr, 0)?;
        }
        Ok(Outcome::Return(r))
    }

    /// RegEnumValue[AW]: the `dwIndex`-th value's name/type/data.
    pub(crate) fn reg_enum_value(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let index = self.arg(cpu, mem, 1)? as usize;
        let name_ptr = self.arg(cpu, mem, 2)?;
        let cch_ptr = self.arg(cpu, mem, 3)?;
        let type_ptr = self.arg(cpu, mem, 5)?;
        let data_ptr = self.arg(cpu, mem, 6)?;
        let cb_ptr = self.arg(cpu, mem, 7)?;
        let Some(path) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let mut items: Vec<(String, u32, Vec<u8>)> = match self.reg_hive.get(&path) {
            Some(m) => m.iter().map(|(k, (t, d))| (k.clone(), *t, d.clone())).collect(),
            None => Vec::new(),
        };
        items.sort_by(|a, b| a.0.cmp(&b.0));
        let Some((vname, vtype, vdata)) = items.get(index) else {
            return Ok(Outcome::Return(ERROR_NO_MORE_ITEMS));
        };
        let r = write_reg_name(mem, name_ptr, cch_ptr, vname, wide)?;
        if r != ERROR_SUCCESS {
            return Ok(Outcome::Return(r));
        }
        if type_ptr != 0 {
            mem.write_u32(type_ptr, *vtype)?;
        }
        if cb_ptr != 0 {
            let data_len = vdata.len() as u32;
            let buf_size = mem.read_u32(cb_ptr)?;
            if data_ptr == 0 {
                mem.write_u32(cb_ptr, data_len)?;
            } else if buf_size < data_len {
                mem.write_u32(cb_ptr, data_len)?;
                return Ok(Outcome::Return(ERROR_MORE_DATA));
            } else {
                mem.write(data_ptr, vdata)?;
                mem.write_u32(cb_ptr, data_len)?;
            }
        }
        Ok(Outcome::Return(ERROR_SUCCESS))
    }

    /// RegQueryInfoKey[AW]: sub-key/value counts and max name/data lengths.
    pub(crate) fn reg_query_info(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hkey = self.arg(cpu, mem, 0)?;
        let c_subkeys = self.arg(cpu, mem, 4)?;
        let c_max_subkey = self.arg(cpu, mem, 5)?;
        let c_values = self.arg(cpu, mem, 7)?;
        let c_max_vname = self.arg(cpu, mem, 8)?;
        let c_max_vlen = self.arg(cpu, mem, 9)?;
        let ft_ptr = self.arg(cpu, mem, 11)?;
        let Some(base) = self.reg_resolve(hkey) else {
            self.last_error = ERROR_INVALID_HANDLE as u32;
            return Ok(Outcome::Return(ERROR_INVALID_HANDLE));
        };
        let subs = self.subkeys(&base);
        let max_subkey = subs.iter().map(|s| s.chars().count()).max().unwrap_or(0) as u32;
        let (nvalues, max_vn, max_vl) = match self.reg_hive.get(&base) {
            Some(m) => (
                m.len() as u32,
                m.keys().map(|k| k.chars().count()).max().unwrap_or(0) as u32,
                m.values().map(|(_, d)| d.len()).max().unwrap_or(0) as u32,
            ),
            None => (0, 0, 0),
        };
        for (ptr, val) in [
            (c_subkeys, subs.len() as u32),
            (c_max_subkey, max_subkey),
            (c_values, nvalues),
            (c_max_vname, max_vn),
            (c_max_vlen, max_vl),
        ] {
            if ptr != 0 {
                mem.write_u32(ptr, val)?;
            }
        }
        if ft_ptr != 0 {
            mem.write_u64(ft_ptr, 0)?;
        }
        Ok(Outcome::Return(ERROR_SUCCESS))
    }
}

// ---- NT registry syscalls (roadmap W2.13) --------------------------------
//
// The NTSTATUS face of the same P3.12 `reg_hive`/`reg_handles` the Win32 seam
// uses, reached via a raw guest `SYSCALL` through the W2.3 dispatcher. Args come
// via [`WinOs::syscall_arg`] (arg0=R10, arg1=RDX, arg2=R8, arg3=R9, then the
// guest stack). Signatures + struct layouts are the public NT headers
// (winternl.h / wdm.h `KEY_*_INFORMATION`); no Wine `.c` read. SSDT indices were
// recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
//
// An NT-created key is the *same* object a Win32 `RegOpenKeyEx` sees: both index
// `reg_hive` by a canonical `HKLM\…`/`HKCU\…` path. The NT namespace
// (`\Registry\Machine\…`) is folded onto that convention by `map_nt_registry_root`.

// NTSTATUS codes.
const NT_SUCCESS: u32 = 0x0000_0000;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

// KEY_VALUE_INFORMATION_CLASS.
const KEY_VALUE_BASIC_INFORMATION: u64 = 0;
const KEY_VALUE_FULL_INFORMATION: u64 = 1;
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
// KEY_INFORMATION_CLASS.
const KEY_BASIC_INFORMATION: u64 = 0;
const KEY_NODE_INFORMATION: u64 = 1;
const KEY_FULL_INFORMATION: u64 = 2;
const KEY_NAME_INFORMATION: u64 = 3;

// SSDT indices (pinned guest ntdll.dll `mov eax,N`).
pub(crate) const SSDT_NT_CREATE_KEY: u32 = 0x1d;
pub(crate) const SSDT_NT_OPEN_KEY: u32 = 0x12;
pub(crate) const SSDT_NT_QUERY_VALUE_KEY: u32 = 0x17;
pub(crate) const SSDT_NT_SET_VALUE_KEY: u32 = 0x60;
pub(crate) const SSDT_NT_ENUMERATE_KEY: u32 = 0x32;
pub(crate) const SSDT_NT_QUERY_KEY: u32 = 0x16;

/// Fold an absolute NT registry path (`\Registry\Machine\SOFTWARE\…`) onto the
/// hive's `HKLM\…`/`HKU\…` convention so an NT-opened key and a Win32-opened key
/// meet in one namespace. Returns `None` for a non-`\Registry\…` path.
fn map_nt_registry_root(nt: &str) -> Option<String> {
    let trimmed = nt.trim_start_matches('\\');
    let mut parts = trimmed.splitn(3, '\\');
    let reg = parts.next()?;
    if !reg.eq_ignore_ascii_case("Registry") {
        return None;
    }
    let hive = parts.next()?;
    let rest = parts.next().unwrap_or("");
    let root = if hive.eq_ignore_ascii_case("Machine") {
        "HKLM"
    } else if hive.eq_ignore_ascii_case("User") {
        "HKU"
    } else {
        return None;
    };
    Some(if rest.is_empty() { root.to_string() } else { format!("{root}\\{rest}") })
}

/// Write `s` as UTF-16LE code units at `addr`, at most `max_bytes` bytes (no
/// terminator — the `KEY_*_INFORMATION` name/class fields are counted, not
/// NUL-terminated).
fn write_utf16_bounded(mem: &mut dyn Memory, addr: u64, s: &str, max_bytes: u64) -> Result<()> {
    let mut n = 0u64;
    for u in s.encode_utf16() {
        if n + 2 > max_bytes {
            break;
        }
        mem.write_u16(addr + n, u)?;
        n += 2;
    }
    Ok(())
}

/// UTF-16 byte length of `s` (code units × 2), as the `NameLength`/`DataLength`
/// fields of the NT key-info structures report.
fn utf16_bytes(s: &str) -> u32 {
    (s.encode_utf16().count() * 2) as u32
}

impl WinOs {
    /// Resolve an `OBJECT_ATTRIBUTES` (RootDirectory + ObjectName) into a
    /// canonical hive path. 64-bit layout (the W2 pivot pins 64-bit ntdll):
    /// `{ ULONG Length; HANDLE RootDirectory@0x08; PUNICODE_STRING ObjectName@0x10; … }`.
    /// A non-zero `RootDirectory` (a predefined root or a previously-opened key
    /// handle) makes `ObjectName` relative; otherwise `ObjectName` is an absolute
    /// `\Registry\…` path.
    fn nt_reg_resolve(&self, mem: &dyn Memory, objattr: u64) -> Option<String> {
        if objattr == 0 {
            return None;
        }
        let root_dir = mem.read_u64(objattr + 0x08).ok()?;
        let name_ptr = mem.read_u64(objattr + 0x10).ok()?;
        let name = crate::fs::read_unicode_string(mem, name_ptr).unwrap_or_default();
        if root_dir != 0 {
            let base = self.reg_resolve(root_dir)?;
            let sub = name.trim_start_matches('\\');
            Some(if sub.is_empty() { base } else { format!("{base}\\{sub}") })
        } else {
            map_nt_registry_root(&name)
        }
    }

    /// Whether `path` names a live key (its own entry or any descendant).
    fn reg_key_exists(&self, path: &str) -> bool {
        self.reg_hive.contains_key(path) || self.reg_hive.keys().any(|k| k.starts_with(&format!("{path}\\")))
    }

    /// The leaf component of a key path (`HKLM\SOFTWARE\Foo` → `Foo`).
    fn reg_leaf(path: &str) -> &str {
        path.rsplit('\\').next().unwrap_or(path)
    }

    /// `NtCreateKey(*KeyHandle, DesiredAccess, *ObjectAttributes, TitleIndex,
    /// *Class, CreateOptions, *Disposition)` — create or open a key, mint a
    /// handle, and report REG_CREATED_NEW_KEY (1) / REG_OPENED_EXISTING_KEY (2).
    pub(crate) fn nt_create_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        let disp_ptr = self.syscall_arg(cpu, mem, 6)?;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(path) = self.nt_reg_resolve(mem, objattr) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        let existed = self.reg_key_exists(&path);
        self.reg_hive.entry(path.clone()).or_default();
        let handle = self.alloc_khandle();
        self.reg_handles.insert(handle, path);
        self.write_ptr(mem, handle_out, handle)?;
        if disp_ptr != 0 {
            mem.write_u32(disp_ptr, if existed { 2 } else { 1 })?;
        }
        Ok(NT_SUCCESS)
    }

    /// `NtOpenKey(*KeyHandle, DesiredAccess, *ObjectAttributes)` — open an
    /// existing key (no auto-create). Missing key → STATUS_OBJECT_NAME_NOT_FOUND.
    pub(crate) fn nt_open_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle_out = self.syscall_arg(cpu, mem, 0)?;
        let objattr = self.syscall_arg(cpu, mem, 2)?;
        if handle_out == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(path) = self.nt_reg_resolve(mem, objattr) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        if !self.reg_key_exists(&path) {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let handle = self.alloc_khandle();
        self.reg_handles.insert(handle, path);
        self.write_ptr(mem, handle_out, handle)?;
        Ok(NT_SUCCESS)
    }

    /// `NtSetValueKey(KeyHandle, *ValueName, TitleIndex, Type, *Data, DataSize)`.
    pub(crate) fn nt_set_value_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let hkey = self.syscall_arg(cpu, mem, 0)?;
        let name_ptr = self.syscall_arg(cpu, mem, 1)?;
        let ty = self.syscall_arg(cpu, mem, 3)? as u32;
        let data_ptr = self.syscall_arg(cpu, mem, 4)?;
        let data_size = self.syscall_arg(cpu, mem, 5)? as usize;
        let Some(path) = self.reg_resolve(hkey) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let name = crate::fs::read_unicode_string(mem, name_ptr).unwrap_or_default();
        let mut data = vec![0u8; data_size];
        if data_ptr != 0 && data_size > 0 {
            mem.read(data_ptr, &mut data)?;
        }
        self.reg_hive.entry(path).or_default().insert(name, (ty, data));
        Ok(NT_SUCCESS)
    }

    /// `NtQueryValueKey(KeyHandle, *ValueName, InfoClass, *KeyValueInformation,
    /// Length, *ResultLength)` — read a named value in the Basic/Full/Partial
    /// class layout. Buffer too small for the fixed header →
    /// STATUS_BUFFER_TOO_SMALL; header fits but not the whole record →
    /// STATUS_BUFFER_OVERFLOW; `*ResultLength` always the full required size.
    pub(crate) fn nt_query_value_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let hkey = self.syscall_arg(cpu, mem, 0)?;
        let name_ptr = self.syscall_arg(cpu, mem, 1)?;
        let class = self.syscall_arg(cpu, mem, 2)?;
        let buf = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let result_len_ptr = self.syscall_arg(cpu, mem, 5)?;
        let Some(path) = self.reg_resolve(hkey) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let name = crate::fs::read_unicode_string(mem, name_ptr).unwrap_or_default();
        let Some((ty, data)) = self.reg_hive.get(&path).and_then(|m| m.get(&name)).map(|(t, d)| (*t, d.clone())) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let name_bytes = utf16_bytes(&name);
        let data_len = data.len() as u32;
        let (header, total) = match class {
            KEY_VALUE_BASIC_INFORMATION => (12u32, 12 + name_bytes),
            KEY_VALUE_FULL_INFORMATION => (20u32, 20 + name_bytes + data_len),
            KEY_VALUE_PARTIAL_INFORMATION => (12u32, 12 + data_len),
            _ => return Ok(STATUS_INVALID_PARAMETER),
        };
        if result_len_ptr != 0 {
            mem.write_u32(result_len_ptr, total)?;
        }
        if (length as u32) < header {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        match class {
            KEY_VALUE_BASIC_INFORMATION => {
                mem.write_u32(buf, 0)?; // TitleIndex
                mem.write_u32(buf + 4, ty)?;
                mem.write_u32(buf + 8, name_bytes)?;
                write_utf16_bounded(mem, buf + 12, &name, length - 12)?;
            }
            KEY_VALUE_FULL_INFORMATION => {
                mem.write_u32(buf, 0)?;
                mem.write_u32(buf + 4, ty)?;
                mem.write_u32(buf + 8, 20 + name_bytes)?; // DataOffset
                mem.write_u32(buf + 12, data_len)?;
                mem.write_u32(buf + 16, name_bytes)?;
                write_utf16_bounded(mem, buf + 20, &name, length.saturating_sub(20))?;
                let data_at = 20 + name_bytes as u64;
                if length > data_at {
                    let n = ((length - data_at) as usize).min(data.len());
                    mem.write(buf + data_at, &data[..n])?;
                }
            }
            KEY_VALUE_PARTIAL_INFORMATION => {
                mem.write_u32(buf, 0)?;
                mem.write_u32(buf + 4, ty)?;
                mem.write_u32(buf + 8, data_len)?;
                let n = ((length - 12) as usize).min(data.len());
                mem.write(buf + 12, &data[..n])?;
            }
            _ => unreachable!(),
        }
        Ok(if (length as u32) < total { STATUS_BUFFER_OVERFLOW } else { NT_SUCCESS })
    }

    /// `NtEnumerateKey(KeyHandle, Index, InfoClass, *KeyInformation, Length,
    /// *ResultLength)` — the `Index`-th sub-key in Basic/Node class layout.
    /// Index past the last sub-key → STATUS_NO_MORE_ENTRIES.
    pub(crate) fn nt_enumerate_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let hkey = self.syscall_arg(cpu, mem, 0)?;
        let index = self.syscall_arg(cpu, mem, 1)? as usize;
        let class = self.syscall_arg(cpu, mem, 2)?;
        let buf = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let result_len_ptr = self.syscall_arg(cpu, mem, 5)?;
        let Some(base) = self.reg_resolve(hkey) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let subs = self.subkeys(&base);
        let Some(name) = subs.get(index).cloned() else {
            return Ok(STATUS_NO_MORE_ENTRIES);
        };
        let name_bytes = utf16_bytes(&name);
        let (header, name_off) = match class {
            KEY_BASIC_INFORMATION => (16u32 + name_bytes, 16u64),
            KEY_NODE_INFORMATION => (24u32 + name_bytes, 24u64),
            _ => return Ok(STATUS_INVALID_PARAMETER),
        };
        if result_len_ptr != 0 {
            mem.write_u32(result_len_ptr, header)?;
        }
        if length < name_off {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let lwt = crate::time::filetime_now();
        mem.write_u64(buf, lwt)?; // LastWriteTime
        mem.write_u32(buf + 8, 0)?; // TitleIndex
        if class == KEY_NODE_INFORMATION {
            mem.write_u32(buf + 12, 0)?; // ClassOffset
            mem.write_u32(buf + 16, 0)?; // ClassLength
            mem.write_u32(buf + 20, name_bytes)?; // NameLength
        } else {
            mem.write_u32(buf + 12, name_bytes)?; // NameLength
        }
        write_utf16_bounded(mem, buf + name_off, &name, length - name_off)?;
        Ok(if length < header as u64 { STATUS_BUFFER_OVERFLOW } else { NT_SUCCESS })
    }

    /// `NtQueryKey(KeyHandle, InfoClass, *KeyInformation, Length, *ResultLength)`
    /// — info about the key itself in Basic/Node/Full/Name class layout.
    pub(crate) fn nt_query_key(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let hkey = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)?;
        let buf = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let result_len_ptr = self.syscall_arg(cpu, mem, 4)?;
        let Some(path) = self.reg_resolve(hkey) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let lwt = crate::time::filetime_now();
        match class {
            KEY_BASIC_INFORMATION | KEY_NODE_INFORMATION => {
                let name = Self::reg_leaf(&path).to_string();
                let name_bytes = utf16_bytes(&name);
                let (header, name_off) = if class == KEY_BASIC_INFORMATION {
                    (16u32 + name_bytes, 16u64)
                } else {
                    (24u32 + name_bytes, 24u64)
                };
                if result_len_ptr != 0 {
                    mem.write_u32(result_len_ptr, header)?;
                }
                if length < name_off {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(buf, lwt)?;
                mem.write_u32(buf + 8, 0)?;
                if class == KEY_NODE_INFORMATION {
                    mem.write_u32(buf + 12, 0)?;
                    mem.write_u32(buf + 16, 0)?;
                    mem.write_u32(buf + 20, name_bytes)?;
                } else {
                    mem.write_u32(buf + 12, name_bytes)?;
                }
                write_utf16_bounded(mem, buf + name_off, &name, length - name_off)?;
                Ok(if length < header as u64 { STATUS_BUFFER_OVERFLOW } else { NT_SUCCESS })
            }
            KEY_FULL_INFORMATION => {
                let subs = self.subkeys(&path);
                let max_name = subs.iter().map(|s| utf16_bytes(s)).max().unwrap_or(0);
                let (nvalues, max_vn, max_vl) = match self.reg_hive.get(&path) {
                    Some(m) => (
                        m.len() as u32,
                        m.keys().map(|k| utf16_bytes(k)).max().unwrap_or(0),
                        m.values().map(|(_, d)| d.len() as u32).max().unwrap_or(0),
                    ),
                    None => (0, 0, 0),
                };
                let header = 44u32;
                if result_len_ptr != 0 {
                    mem.write_u32(result_len_ptr, header)?;
                }
                if length < header as u64 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u64(buf, lwt)?; // LastWriteTime
                mem.write_u32(buf + 8, 0)?; // TitleIndex
                mem.write_u32(buf + 12, header)?; // ClassOffset (empty class → end)
                mem.write_u32(buf + 16, 0)?; // ClassLength
                mem.write_u32(buf + 20, subs.len() as u32)?; // SubKeys
                mem.write_u32(buf + 24, max_name)?; // MaxNameLen
                mem.write_u32(buf + 28, 0)?; // MaxClassLen
                mem.write_u32(buf + 32, nvalues)?; // Values
                mem.write_u32(buf + 36, max_vn)?; // MaxValueNameLen
                mem.write_u32(buf + 40, max_vl)?; // MaxValueDataLen
                Ok(NT_SUCCESS)
            }
            KEY_NAME_INFORMATION => {
                let name_bytes = utf16_bytes(&path);
                let header = 4u32 + name_bytes;
                if result_len_ptr != 0 {
                    mem.write_u32(result_len_ptr, header)?;
                }
                if length < 4 {
                    return Ok(STATUS_BUFFER_TOO_SMALL);
                }
                mem.write_u32(buf, name_bytes)?; // NameLength
                write_utf16_bounded(mem, buf + 4, &path, length - 4)?;
                Ok(if length < header as u64 { STATUS_BUFFER_OVERFLOW } else { NT_SUCCESS })
            }
            _ => Ok(STATUS_INVALID_PARAMETER),
        }
    }
}

pub(crate) fn ssdt_nt_create_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_create_key(cpu, mem)
}
pub(crate) fn ssdt_nt_open_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_key(cpu, mem)
}
pub(crate) fn ssdt_nt_query_value_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_value_key(cpu, mem)
}
pub(crate) fn ssdt_nt_set_value_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_set_value_key(cpu, mem)
}
pub(crate) fn ssdt_nt_enumerate_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_enumerate_key(cpu, mem)
}
pub(crate) fn ssdt_nt_query_key(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_key(cpu, mem)
}

/// Write a registry name to `name_ptr` honouring the IN/OUT char count at
/// `cch_ptr` (buffer size in → chars written out). Returns ERROR_SUCCESS, or
/// ERROR_MORE_DATA if the buffer is too small.
fn write_reg_name(mem: &mut dyn Memory, name_ptr: u64, cch_ptr: u64, name: &str, wide: bool) -> Result<u64> {
    let cap = if cch_ptr != 0 { mem.read_u32(cch_ptr)? } else { 260 };
    let nchars = name.chars().count() as u32;
    if nchars + 1 > cap {
        if cch_ptr != 0 {
            mem.write_u32(cch_ptr, nchars)?;
        }
        return Ok(ERROR_MORE_DATA);
    }
    if name_ptr != 0 {
        if wide {
            WinOs::write_wstr(mem, name_ptr, name, cap as usize)?;
        } else {
            write_astr(mem, name_ptr, name, cap as usize)?;
        }
    }
    if cch_ptr != 0 {
        mem.write_u32(cch_ptr, nchars)?;
    }
    Ok(ERROR_SUCCESS)
}
