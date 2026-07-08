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
