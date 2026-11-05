use std::io::{Seek, SeekFrom};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use exemu_core::{CpuState, Memory, Result};

use super::{
    strip_nt_prefix, write_iosb, FILETIME_EPOCH_DIFF, STATUS_ACCESS_DENIED,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_SUCCESS,
};
use crate::WinOs;

const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_DISPOSITION_INFORMATION: u32 = 13;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_ALLOCATION_INFORMATION: u32 = 19;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
const FILE_DISPOSITION_INFORMATION_EX: u32 = 64;
const FILE_RENAME_INFORMATION_EX: u32 = 65;

const FILE_BASIC_INFORMATION_SIZE: u64 = 40;
const FILE_BASIC_LAST_WRITE_TIME: u64 = 16;
const FILE_RENAME_ROOT_DIRECTORY: u64 = 8;
const FILE_RENAME_NAME_LENGTH: u64 = 0x10;
const FILE_RENAME_NAME: u64 = 0x14;
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 1;
const FILE_DISPOSITION_DELETE: u32 = 1;
const FILETIME_KEEP: u64 = u64::MAX;

const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;

impl WinOs {
    pub(crate) fn nt_set_information_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb_ptr = self.syscall_arg(cpu, mem, 1)?;
        let info = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)? & 0xFFFF_FFFF;
        let class = self.syscall_arg(cpu, mem, 4)? as u32;
        if !self.is_file_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let status = match class {
            FILE_POSITION_INFORMATION => self.set_position(mem, handle, info, length)?,
            FILE_END_OF_FILE_INFORMATION => self.set_end_of_file(mem, handle, info, length)?,
            FILE_ALLOCATION_INFORMATION => {
                if length < 8 {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    STATUS_SUCCESS
                }
            }
            FILE_DISPOSITION_INFORMATION => {
                if length < 1 {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    let delete = mem.read_u8(info)? != 0;
                    self.set_disposition(handle, delete)
                }
            }
            FILE_DISPOSITION_INFORMATION_EX => {
                if length < 4 {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    let delete = mem.read_u32(info)? & FILE_DISPOSITION_DELETE != 0;
                    self.set_disposition(handle, delete)
                }
            }
            FILE_RENAME_INFORMATION | FILE_RENAME_INFORMATION_EX => {
                let replace = if class == FILE_RENAME_INFORMATION {
                    mem.read_u8(info)? != 0
                } else {
                    mem.read_u32(info)? & FILE_RENAME_REPLACE_IF_EXISTS != 0
                };
                self.rename_open_file(mem, handle, info, length, replace)?
            }
            FILE_BASIC_INFORMATION => self.set_basic_times(mem, handle, info, length)?,
            _ => STATUS_NOT_IMPLEMENTED,
        };
        write_iosb(mem, iosb_ptr, status, 0)?;
        Ok(status)
    }

    fn set_position(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        info: u64,
        length: u64,
    ) -> Result<u32> {
        if length < 8 {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let pos = mem.read_u64(info)?;
        if (pos as i64) < 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(of) = self.files.get_mut(&handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        Ok(match of.file.seek(SeekFrom::Start(pos)) {
            Ok(_) => STATUS_SUCCESS,
            Err(_) => STATUS_ACCESS_DENIED,
        })
    }

    fn set_end_of_file(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        info: u64,
        length: u64,
    ) -> Result<u32> {
        if length < 8 {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let size = mem.read_u64(info)?;
        if (size as i64) < 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(of) = self.files.get_mut(&handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        Ok(match of.file.set_len(size) {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_ACCESS_DENIED,
        })
    }

    fn set_disposition(&mut self, handle: u64, delete: bool) -> u32 {
        let Some(of) = self.files.get_mut(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        if delete && of.path.is_dir() {
            let occupied = std::fs::read_dir(&of.path).map(|mut d| d.next().is_some());
            if occupied.unwrap_or(false) {
                return STATUS_DIRECTORY_NOT_EMPTY;
            }
        }
        of.delete_on_close = delete;
        STATUS_SUCCESS
    }

    fn rename_open_file(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        info: u64,
        length: u64,
        replace: bool,
    ) -> Result<u32> {
        if length < FILE_RENAME_NAME {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let root = mem.read_u64(info + FILE_RENAME_ROOT_DIRECTORY)?;
        let bytes = u64::from(mem.read_u32(info + FILE_RENAME_NAME_LENGTH)?);
        if FILE_RENAME_NAME + bytes > length {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let mut units = Vec::with_capacity((bytes / 2) as usize);
        for i in 0..bytes / 2 {
            units.push(mem.read_u16(info + FILE_RENAME_NAME + i * 2)?);
        }
        let name = strip_nt_prefix(&String::from_utf16_lossy(&units));
        let guest = match self.dir_handle_guest_path(root).filter(|_| root != 0) {
            Some(base) => format!("{}\\{name}", base.trim_end_matches('\\')),
            None => name,
        };
        let Some(target) = self.host_path(&guest) else {
            return Ok(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if target.parent().is_some_and(|p| !p.is_dir()) {
            return Ok(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if target.exists() {
            if !replace {
                return Ok(STATUS_OBJECT_NAME_COLLISION);
            }
            if target.is_dir() {
                return Ok(STATUS_ACCESS_DENIED);
            }
        }
        let Some(of) = self.files.get_mut(&handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        match std::fs::rename(&of.path, &target) {
            Ok(()) => {
                of.path = target;
                Ok(STATUS_SUCCESS)
            }
            Err(_) => Ok(STATUS_ACCESS_DENIED),
        }
    }

    fn set_basic_times(
        &mut self,
        mem: &mut dyn Memory,
        handle: u64,
        info: u64,
        length: u64,
    ) -> Result<u32> {
        if length < FILE_BASIC_INFORMATION_SIZE {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        let written = mem.read_u64(info + FILE_BASIC_LAST_WRITE_TIME)?;
        if written == 0 || written == FILETIME_KEEP {
            return Ok(STATUS_SUCCESS);
        }
        let Some(ticks) = written.checked_sub(FILETIME_EPOCH_DIFF) else {
            return Ok(STATUS_SUCCESS);
        };
        let when = UNIX_EPOCH + Duration::from_nanos(ticks.saturating_mul(100));
        Ok(self.set_modified_time(handle, when))
    }

    fn set_modified_time(&mut self, handle: u64, when: SystemTime) -> u32 {
        let Some(of) = self.files.get(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        match of.file.set_modified(when) {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_ACCESS_DENIED,
        }
    }
}

pub(crate) fn ssdt_nt_set_information_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_set_information_file(cpu, mem)
}
