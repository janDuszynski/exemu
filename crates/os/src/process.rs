use exemu_core::{
    ChildProcessOutcome, ChildProcessRequest, CpuState, Memory, ProcessSpawner, Result, SpawnError,
};

use crate::sync::KObject;
use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_00E4;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

pub const STILL_ACTIVE: u32 = 259;

const NT_CURRENT_PROCESS: u64 = u64::MAX;

pub const SSDT_NT_CREATE_USER_PROCESS: u32 = 0x89;
pub const SSDT_NT_QUERY_INFORMATION_PROCESS: u32 = 0x19;

pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u64 = 0x0000_0004;
pub const PROCESS_CREATE_FLAGS_SUSPENDED: u64 = 0x0000_0200;

pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u64 = 0x0000_0001;

pub mod ps_attr {
    pub const TOTAL_LENGTH: u64 = 0x00;
    pub const FIRST: u64 = 0x08;
    pub const ENTRY_SIZE: u64 = 0x20;

    pub const ATTRIBUTE: u64 = 0x00;
    pub const SIZE: u64 = 0x08;
    pub const VALUE: u64 = 0x10;
    pub const RETURN_LENGTH: u64 = 0x18;

    pub const NUMBER_MASK: u64 = 0xFFFF;
    pub const THREAD: u64 = 0x0001_0000;
    pub const INPUT: u64 = 0x0002_0000;
    pub const ADDITIVE: u64 = 0x0004_0000;

    pub const PARENT_PROCESS: u64 = 0;
    pub const DEBUG_PORT: u64 = 1;
    pub const TOKEN: u64 = 2;
    pub const CLIENT_ID: u64 = 3;
    pub const IMAGE_NAME: u64 = 5;
    pub const IMAGE_INFO: u64 = 6;
    pub const HANDLE_LIST: u64 = 11;
    pub const JOB_LIST: u64 = 19;
    pub const MACHINE_TYPE: u64 = 28;

    pub const MAX_ENTRIES: u64 = 32;
}

const IMAGE_FILE_MACHINE_AMD64: u64 = 0x8664;

pub mod pp {
    pub const CONSOLE_HANDLE: u64 = 0x10;
    pub const STD_INPUT: u64 = 0x20;
    pub const STD_OUTPUT: u64 = 0x28;
    pub const STD_ERROR: u64 = 0x30;
    pub const CURRENT_DIRECTORY: u64 = 0x38;
    pub const IMAGE_PATH_NAME: u64 = 0x60;
    pub const COMMAND_LINE: u64 = 0x70;
    pub const ENVIRONMENT: u64 = 0x80;
    pub const ENVIRONMENT_SIZE: u64 = 0x3F0;
}

const MAX_ENVIRONMENT_BYTES: u64 = 0x0010_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ChildState {
    NotStarted,
    Exited,
}

pub(crate) struct ChildProcess {
    pub pid: u32,
    pub tid: u32,
    pub process_handle: u64,
    pub thread_handle: u64,
    pub state: ChildState,
    pub exit_code: u32,
    pub suspend_count: u32,
    pub request: Option<ChildProcessRequest>,
}

impl WinOs {

    pub fn set_process_spawner(&mut self, spawner: Box<dyn ProcessSpawner>) {
        self.spawner = spawner;
    }

    pub fn set_spawn_depth(&mut self, depth: u32) {
        self.spawn_depth = depth;
    }

    fn child_by_process_handle(&self, handle: u64) -> Option<usize> {
        self.children.iter().position(|c| c.process_handle == handle)
    }

    fn child_by_thread_handle(&self, handle: u64) -> Option<usize> {
        self.children.iter().position(|c| c.thread_handle == handle)
    }

    pub(crate) fn forget_child_handle(&mut self, handle: u64) {
        if let Some(i) = self.child_by_process_handle(handle) {
            self.children[i].process_handle = 0;
        }
        if let Some(i) = self.child_by_thread_handle(handle) {
            self.children[i].thread_handle = 0;
        }
        self.children.retain(|c| c.process_handle != 0 || c.thread_handle != 0);
    }

    fn next_child_ids(&mut self) -> (u32, u32) {
        let pid = self.next_pid;
        self.next_pid += 4;
        let tid = self.next_pid;
        self.next_pid += 4;
        (pid, tid)
    }

    pub(crate) fn nt_create_user_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let process_handle_out = self.syscall_arg(cpu, mem, 0)?;
        let thread_handle_out = self.syscall_arg(cpu, mem, 1)?;
        let process_flags = self.syscall_arg(cpu, mem, 6)?;
        let _thread_flags = self.syscall_arg(cpu, mem, 7)?;
        let params = self.syscall_arg(cpu, mem, 8)?;
        let attribute_list = self.syscall_arg(cpu, mem, 10)?;

        if process_handle_out == 0 || thread_handle_out == 0 || params == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }

        let attrs = match self.read_ps_attributes(mem, attribute_list)? {
            Ok(a) => a,
            Err(status) => return Ok(status),
        };

        let inherit_handles = process_flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES != 0;
        let std_handles = [
            mem.read_u64(params + pp::STD_INPUT)?,
            mem.read_u64(params + pp::STD_OUTPUT)?,
            mem.read_u64(params + pp::STD_ERROR)?,
        ];
        for h in std_handles {
            if h == 0 || h == u64::MAX {
                continue;
            }
            if !self.is_std_handle(h) {
                return Ok(STATUS_NOT_SUPPORTED);
            }
        }

        let command_line = crate::fs::read_unicode_string(mem, params + pp::COMMAND_LINE)
            .unwrap_or_default();
        let image_from_params =
            crate::fs::read_unicode_string(mem, params + pp::IMAGE_PATH_NAME).unwrap_or_default();
        let current_directory =
            crate::fs::read_unicode_string(mem, params + pp::CURRENT_DIRECTORY).unwrap_or_default();
        let environment = self.read_environment_block(mem, params)?;

        let image_nt_path = attrs.image_name.clone().unwrap_or(image_from_params);
        if image_nt_path.is_empty() {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let image_guest_path = crate::fs::strip_nt_prefix(&image_nt_path);
        let Some(image_host_path) = self.host_path(&image_guest_path) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if !image_host_path.is_file() {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        let (pid, tid) = self.next_child_ids();
        let process_handle = self.alloc_khandle();
        let thread_handle = self.alloc_khandle();
        self.kobjects.insert(process_handle, KObject::Process { exited: false });
        self.kobjects.insert(thread_handle, KObject::Thread { exited: false });

        self.children_created += 1;
        self.children.push(ChildProcess {
            pid,
            tid,
            process_handle,
            thread_handle,
            state: ChildState::NotStarted,
            exit_code: STILL_ACTIVE,
            suspend_count: 1,
            request: Some(ChildProcessRequest {
                image_guest_path,
                image_host_path,
                command_line,
                current_directory,
                environment,
                inherit_handles,
                depth: self.spawn_depth.saturating_add(1),
            }),
        });

        self.write_ptr(mem, process_handle_out, process_handle)?;
        self.write_ptr(mem, thread_handle_out, thread_handle)?;
        if let Some(client_id) = attrs.client_id_out {
            mem.write_u64(client_id, pid as u64)?;
            mem.write_u64(client_id + 8, tid as u64)?;
        }
        if let Some((ptr, len)) = attrs.image_info_out {
            for off in (0..len).step_by(8) {
                mem.write_u64(ptr + off, 0)?;
            }
        }
        for (ptr, value) in attrs.return_lengths {
            mem.write_u64(ptr, value)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn read_environment_block(
        &self,
        mem: &dyn Memory,
        params: u64,
    ) -> Result<Vec<(String, String)>> {
        let base = mem.read_u64(params + pp::ENVIRONMENT)?;
        let size = mem.read_u64(params + pp::ENVIRONMENT_SIZE)?;
        if base == 0 || !(4..=MAX_ENVIRONMENT_BYTES).contains(&size) {
            return Ok(Vec::new());
        }
        let mut units = Vec::with_capacity((size / 2) as usize);
        for i in 0..size / 2 {
            units.push(mem.read_u16(base + i * 2)?);
        }
        let mut out = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        for u in units {
            if u == 0 {
                if cur.is_empty() {
                    break;
                }
                let s = String::from_utf16_lossy(&cur);
                if let Some(rel) = s.get(1..).and_then(|rest| rest.find('=')) {
                    let eq = rel + 1;
                    out.push((s[..eq].to_string(), s[eq + 1..].to_string()));
                }
                cur.clear();
            } else {
                cur.push(u);
            }
        }
        Ok(out)
    }

    fn read_ps_attributes(
        &self,
        mem: &dyn Memory,
        list: u64,
    ) -> Result<std::result::Result<PsAttributes, u32>> {
        let mut out = PsAttributes::default();
        if list == 0 {
            return Ok(Ok(out));
        }
        let total = mem.read_u64(list + ps_attr::TOTAL_LENGTH)?;
        if total < ps_attr::FIRST {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        let count = ((total - ps_attr::FIRST) / ps_attr::ENTRY_SIZE).min(ps_attr::MAX_ENTRIES);
        for i in 0..count {
            let e = list + ps_attr::FIRST + i * ps_attr::ENTRY_SIZE;
            let packed = mem.read_u64(e + ps_attr::ATTRIBUTE)?;
            let size = mem.read_u64(e + ps_attr::SIZE)?;
            let value = mem.read_u64(e + ps_attr::VALUE)?;
            let return_length = mem.read_u64(e + ps_attr::RETURN_LENGTH)?;
            let number = packed & ps_attr::NUMBER_MASK;
            match number {
                ps_attr::IMAGE_NAME => {
                    if value != 0 && (2..=0x1000).contains(&size) {
                        let mut units = Vec::with_capacity((size / 2) as usize);
                        for k in 0..size / 2 {
                            units.push(mem.read_u16(value + k * 2)?);
                        }
                        out.image_name = Some(String::from_utf16_lossy(&units));
                    }
                }
                ps_attr::CLIENT_ID => {
                    if value != 0 && size >= 16 {
                        out.client_id_out = Some(value);
                        if return_length != 0 {
                            out.return_lengths.push((return_length, 16));
                        }
                    }
                }
                ps_attr::IMAGE_INFO => {
                    if value != 0 && (8..=0x200).contains(&size) {
                        out.image_info_out = Some((value, size & !7));
                        if return_length != 0 {
                            out.return_lengths.push((return_length, size));
                        }
                    }
                }
                ps_attr::HANDLE_LIST => {
                    if value != 0 && size != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::DEBUG_PORT => {
                    if value != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::JOB_LIST => {
                    if value != 0 && size != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::TOKEN => {
                    if value != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::PARENT_PROCESS => {
                    if value != 0 && value != NT_CURRENT_PROCESS {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::MACHINE_TYPE if value != 0 && value != IMAGE_FILE_MACHINE_AMD64 => {
                    return Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
                }
                _ => {}
            }
        }
        Ok(Ok(out))
    }

    pub(crate) fn resume_child(&mut self, i: usize) -> u32 {
        let prev = self.children[i].suspend_count;
        if prev > 0 {
            self.children[i].suspend_count -= 1;
        }
        if self.children[i].suspend_count == 0 && self.children[i].state == ChildState::NotStarted {
            self.run_child(i);
        }
        prev
    }

    fn run_child(&mut self, i: usize) {
        let Some(req) = self.children[i].request.take() else {
            return;
        };
        let outcome = self.spawner.spawn(&req);
        let exit_code = match outcome {
            Ok(ChildProcessOutcome { exit_code, stdout, stderr, .. }) => {
                if !stdout.is_empty() {
                    self.emit_child(false, &stdout);
                }
                if !stderr.is_empty() {
                    self.emit_child(true, &stderr);
                }
                exit_code
            }
            Err(e) => {
                let note = match &e {
                    SpawnError::Unsupported => "no child-process runner is installed".to_string(),
                    SpawnError::ImageNotFound => "the child image disappeared".to_string(),
                    SpawnError::InvalidImage(m) => format!("the child image is not loadable: {m}"),
                    SpawnError::Faulted(m) => format!("exemu failed while running the child: {m}"),
                };
                self.emit_child(
                    true,
                    format!("exemu: child process {} failed — {note}\n", req.image_guest_path)
                        .as_bytes(),
                );
                self.child_failure = Some(note);
                STATUS_UNSUCCESSFUL
            }
        };
        self.children[i].state = ChildState::Exited;
        self.children[i].exit_code = exit_code;
        let (ph, th) = (self.children[i].process_handle, self.children[i].thread_handle);
        if let Some(KObject::Process { exited }) = self.kobjects.get_mut(&ph) {
            *exited = true;
        }
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&th) {
            *exited = true;
        }
    }

    fn emit_child(&mut self, is_err: bool, bytes: &[u8]) {
        self.emit_bytes(is_err, bytes);
    }

    pub fn child_failure(&self) -> Option<&str> {
        self.child_failure.as_deref()
    }

    pub(crate) fn resume_child_thread(&mut self, handle: u64) -> Option<u32> {
        let i = self.child_by_thread_handle(handle)?;
        Some(self.resume_child(i))
    }

    pub(crate) fn terminate_child(&mut self, handle: u64, code: u32) -> bool {
        let Some(i) = self.child_by_process_handle(handle) else {
            return false;
        };
        if self.children[i].state == ChildState::NotStarted {
            self.children[i].request = None;
            self.children[i].state = ChildState::Exited;
            self.children[i].exit_code = code;
            let (ph, th) = (self.children[i].process_handle, self.children[i].thread_handle);
            if let Some(KObject::Process { exited }) = self.kobjects.get_mut(&ph) {
                *exited = true;
            }
            if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&th) {
                *exited = true;
            }
        }
        true
    }

    pub(crate) fn nt_query_information_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let return_length = self.syscall_arg(cpu, mem, 4)?;

        if class == crate::wow64::PROCESS_WOW64_INFORMATION {
            let ptr: u64 = if self.cfg.is_64bit { 8 } else { 4 };
            if buffer == 0 || length < ptr {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            mem.write(buffer, &self.wow64_peb32.to_le_bytes()[..ptr as usize])?;
            if return_length != 0 {
                mem.write_u32(return_length, ptr as u32)?;
            }
            return Ok(STATUS_SUCCESS);
        }

        if class != PROCESS_BASIC_INFORMATION {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        let need: u64 = if self.cfg.is_64bit { 0x30 } else { 0x18 };
        if buffer == 0 || length < need {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        let (exit_status, peb, pid) = if handle == 0 || handle == NT_CURRENT_PROCESS {
            (STILL_ACTIVE, self.cfg.peb_addr, crate::CURRENT_PROCESS_ID)
        } else if let Some(i) = self.child_by_process_handle(handle) {
            let c = &self.children[i];
            (c.exit_code, 0, c.pid as u64)
        } else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        if self.cfg.is_64bit {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u32(buffer + 0x04, 0)?;
            mem.write_u64(buffer + 0x08, peb)?;
            mem.write_u64(buffer + 0x10, 1)?;
            mem.write_u64(buffer + 0x18, 8)?;
            mem.write_u64(buffer + 0x20, pid)?;
            mem.write_u64(buffer + 0x28, if pid == crate::CURRENT_PROCESS_ID { 0 } else { crate::CURRENT_PROCESS_ID })?;
        } else {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u32(buffer + 0x04, peb as u32)?;
            mem.write_u32(buffer + 0x08, 1)?;
            mem.write_u32(buffer + 0x0C, 8)?;
            mem.write_u32(buffer + 0x10, pid as u32)?;
            mem.write_u32(buffer + 0x14, if pid == crate::CURRENT_PROCESS_ID { 0 } else { crate::CURRENT_PROCESS_ID as u32 })?;
        }
        if return_length != 0 {
            mem.write_u32(return_length, need as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn create_child_process(
        &mut self,
        image_guest_path: &str,
        command_line: &str,
        current_directory: &str,
        inherit_handles: bool,
    ) -> std::result::Result<(u64, u64, u32, u32), u32> {
        let Some(image_host_path) = self.host_path(image_guest_path) else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if !image_host_path.is_file() {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let environment = self.env.clone();
        let (pid, tid) = self.next_child_ids();
        let process_handle = self.alloc_khandle();
        let thread_handle = self.alloc_khandle();
        self.kobjects.insert(process_handle, KObject::Process { exited: false });
        self.kobjects.insert(thread_handle, KObject::Thread { exited: false });
        self.children_created += 1;
        self.children.push(ChildProcess {
            pid,
            tid,
            process_handle,
            thread_handle,
            state: ChildState::NotStarted,
            exit_code: STILL_ACTIVE,
            suspend_count: 1,
            request: Some(ChildProcessRequest {
                image_guest_path: image_guest_path.to_string(),
                image_host_path,
                command_line: command_line.to_string(),
                current_directory: current_directory.to_string(),
                environment,
                inherit_handles,
                depth: self.spawn_depth.saturating_add(1),
            }),
        });
        let c = self.children.last().expect("just pushed");
        Ok((c.process_handle, c.thread_handle, c.pid, c.tid))
    }

    pub(crate) fn child_exit_code(&self, handle: u64) -> Option<u32> {
        self.child_by_process_handle(handle).map(|i| self.children[i].exit_code)
    }

    pub(crate) fn win32_create_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        wide: bool,
    ) -> Result<crate::api::Outcome> {
        let app_name = self.arg(cpu, mem, 0)?;
        let cmd_line = self.arg(cpu, mem, 1)?;
        let inherit = self.arg(cpu, mem, 4)? != 0;
        let flags = self.arg(cpu, mem, 5)?;
        let cur_dir = self.arg(cpu, mem, 7)?;
        let info = self.arg(cpu, mem, 9)?;

        let read = |mem: &dyn Memory, p: u64| -> Result<String> {
            if p == 0 {
                return Ok(String::new());
            }
            if wide {
                crate::api::read_wstr(mem, p)
            } else {
                Ok(String::from_utf8_lossy(&mem.read_cstr(p, 0x1000)?).into_owned())
            }
        };
        let app = read(mem, app_name)?;
        let cmd = read(mem, cmd_line)?;
        let dir = read(mem, cur_dir)?;

        let image = if !app.is_empty() { app.clone() } else { first_token(&cmd) };
        if image.is_empty() {
            self.set_last_error(ERROR_INVALID_PARAMETER);
            return Ok(crate::api::Outcome::Return(0));
        }
        let image = self.full_path_name(&image);
        let command_line = if cmd.is_empty() { image.clone() } else { cmd };
        let cwd = if dir.is_empty() { "C:\\".to_string() } else { self.full_path_name(&dir) };

        let (hprocess, hthread, pid, tid) =
            match self.create_child_process(&image, &command_line, &cwd, inherit) {
                Ok(v) => v,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => {
                    self.set_last_error(ERROR_FILE_NOT_FOUND);
                    return Ok(crate::api::Outcome::Return(0));
                }
                Err(_) => {
                    self.set_last_error(ERROR_NOT_SUPPORTED);
                    return Ok(crate::api::Outcome::Return(0));
                }
            };

        if flags & CREATE_SUSPENDED == 0 {
            if let Some(i) = self.child_by_thread_handle(hthread) {
                self.resume_child(i);
            }
        }

        if info != 0 {
            let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
            self.write_ptr(mem, info, hprocess)?;
            self.write_ptr(mem, info + ptr, hthread)?;
            mem.write_u32(info + ptr * 2, pid)?;
            mem.write_u32(info + ptr * 2 + 4, tid)?;
        }
        Ok(crate::api::Outcome::Return(1))
    }

    pub(crate) fn win32_get_exit_code_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<crate::api::Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        let out = self.arg(cpu, mem, 1)?;
        let current = handle == 0 || handle == NT_CURRENT_PROCESS || handle == 0xFFFF_FFFF;
        let code = if current {
            Some(STILL_ACTIVE)
        } else {
            self.child_exit_code(handle)
        };
        let Some(code) = code else {
            self.set_last_error(ERROR_INVALID_HANDLE);
            return Ok(crate::api::Outcome::Return(0));
        };
        if out != 0 {
            mem.write_u32(out, code)?;
        }
        Ok(crate::api::Outcome::Return(1))
    }

    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    pub fn children_created(&self) -> u32 {
        self.children_created
    }
}

const PROCESS_BASIC_INFORMATION: u32 = 0;

const CREATE_SUSPENDED: u64 = 0x0000_0004;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_SUPPORTED: u32 = 50;

fn first_token(cmd: &str) -> String {
    let cmd = cmd.trim_start();
    if let Some(rest) = cmd.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    cmd.split_whitespace().next().unwrap_or("").to_string()
}

#[derive(Default)]
struct PsAttributes {
    image_name: Option<String>,
    client_id_out: Option<u64>,
    image_info_out: Option<(u64, u64)>,
    return_lengths: Vec<(u64, u64)>,
}

pub(crate) fn ssdt_nt_create_user_process(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_create_user_process(cpu, mem)
}

pub(crate) fn ssdt_nt_query_information_process(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_information_process(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WinConfig, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT};
    use exemu_core::{Perm, Reg};
    use exemu_memory::VirtualMemory;

    struct FakeSpawner {
        exit_code: u32,
        stdout: Vec<u8>,
        seen: std::rc::Rc<std::cell::RefCell<Vec<ChildProcessRequest>>>,
    }

    impl ProcessSpawner for FakeSpawner {
        fn spawn(
            &mut self,
            req: &ChildProcessRequest,
        ) -> std::result::Result<ChildProcessOutcome, SpawnError> {
            self.seen.borrow_mut().push(req.clone());
            Ok(ChildProcessOutcome {
                exit_code: self.exit_code,
                steps: 1234,
                stdout: self.stdout.clone(),
                stderr: Vec::new(),
            })
        }
    }

    const PARAMS: u64 = 0x9_0000;
    const ATTRS: u64 = 0x9_1000;
    const SCRATCH: u64 = 0x9_2000;
    const GUEST_RSP: u64 = 0x9_3000;

    fn os64(sandbox: &std::path::Path) -> WinOs {
        WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            sandbox: sandbox.to_string_lossy().into_owned(),
            peb_addr: 0x7000_0000,
            ..WinConfig::default()
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_create(
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        image_nt_path: &str,
        command_line: &str,
        process_flags: u64,
        std_handles: [u64; 3],
        extra_attr: Option<(u64, u64, u64)>,
    ) -> u32 {
        for off in (0..0x420u64).step_by(8) {
            mem.write_u64(PARAMS + off, 0).unwrap();
        }
        mem.write_u64(PARAMS + pp::STD_INPUT, std_handles[0]).unwrap();
        mem.write_u64(PARAMS + pp::STD_OUTPUT, std_handles[1]).unwrap();
        mem.write_u64(PARAMS + pp::STD_ERROR, std_handles[2]).unwrap();
        let cmd_buf = SCRATCH + 0x200;
        write_wstr(mem, cmd_buf, command_line);
        write_unicode_string(mem, PARAMS + pp::COMMAND_LINE, cmd_buf, command_line.len() * 2);
        let cwd_buf = SCRATCH + 0x400;
        write_wstr(mem, cwd_buf, "C:\\");
        write_unicode_string(mem, PARAMS + pp::CURRENT_DIRECTORY, cwd_buf, 6);

        let name_buf = SCRATCH + 0x600;
        write_wstr(mem, name_buf, image_nt_path);
        let client_id = SCRATCH + 0x800;
        let image_info = SCRATCH + 0x900;
        let mut entries: Vec<(u64, u64, u64)> = vec![
            (ps_attr::INPUT | ps_attr::IMAGE_NAME, (image_nt_path.len() * 2) as u64, name_buf),
            (ps_attr::THREAD | ps_attr::CLIENT_ID, 0x10, client_id),
            (ps_attr::IMAGE_INFO, 0x40, image_info),
        ];
        if let Some(e) = extra_attr {
            entries.push(e);
        }
        mem.write_u64(ATTRS + ps_attr::TOTAL_LENGTH, ps_attr::FIRST + entries.len() as u64 * ps_attr::ENTRY_SIZE)
            .unwrap();
        for (i, (packed, size, value)) in entries.iter().enumerate() {
            let e = ATTRS + ps_attr::FIRST + i as u64 * ps_attr::ENTRY_SIZE;
            mem.write_u64(e + ps_attr::ATTRIBUTE, *packed).unwrap();
            mem.write_u64(e + ps_attr::SIZE, *size).unwrap();
            mem.write_u64(e + ps_attr::VALUE, *value).unwrap();
            mem.write_u64(e + ps_attr::RETURN_LENGTH, 0).unwrap();
        }

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, SCRATCH);
        cpu.set_reg(Reg::Rdx, SCRATCH + 8);
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        let stack = |mem: &mut VirtualMemory, n: u64, v: u64| {
            mem.write_u64(GUEST_RSP + 0x28 + (n - 4) * 8, v).unwrap();
        };
        stack(mem, 4, 0);
        stack(mem, 5, 0);
        stack(mem, 6, process_flags);
        stack(mem, 7, THREAD_CREATE_FLAGS_CREATE_SUSPENDED);
        stack(mem, 8, PARAMS);
        stack(mem, 9, 0xDEAD_BEEF);
        stack(mem, 10, ATTRS);
        os.nt_create_user_process(&mut cpu, mem).unwrap()
    }

    fn write_wstr(mem: &mut VirtualMemory, at: u64, s: &str) {
        let mut i = 0;
        for u in s.encode_utf16() {
            mem.write_u16(at + i, u).unwrap();
            i += 2;
        }
        mem.write_u16(at + i, 0).unwrap();
    }

    fn write_unicode_string(mem: &mut VirtualMemory, at: u64, buf: u64, len: usize) {
        mem.write_u16(at, len as u16).unwrap();
        mem.write_u16(at + 2, (len + 2) as u16).unwrap();
        mem.write_u64(at + 8, buf).unwrap();
    }

    fn fixture() -> (VirtualMemory, std::path::PathBuf) {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x9_0000, 0x8000, Perm::RW, "scratch").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "exemu-w35-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("C")).unwrap();
        std::fs::write(dir.join("C").join("child.exe"), b"MZ not really a PE").unwrap();
        (mem, dir)
    }

    #[test]
    fn create_resume_and_read_the_exit_code() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        os.set_process_spawner(Box::new(FakeSpawner {
            exit_code: 74,
            stdout: b"child said hello\n".to_vec(),
            seen: seen.clone(),
        }));

        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe --flag",
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            [HANDLE_STDIN, HANDLE_STDOUT, HANDLE_STDERR],
            None,
        );
        assert_eq!(status, STATUS_SUCCESS);

        let hprocess = mem.read_u64(SCRATCH).unwrap();
        let hthread = mem.read_u64(SCRATCH + 8).unwrap();
        assert!(hprocess != 0 && hthread != 0 && hprocess != hthread);
        let pid = mem.read_u64(SCRATCH + 0x800).unwrap();
        let tid = mem.read_u64(SCRATCH + 0x808).unwrap();
        assert!(pid != 0 && tid != 0 && pid % 4 == 0 && tid % 4 == 0, "pid {pid} tid {tid}");

        assert!(seen.borrow().is_empty(), "a suspended child must not run");
        assert!(!os.kobject_is_signaled_for_test(hprocess));
        assert!(!os.kobject_is_signaled_for_test(hthread));
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), STILL_ACTIVE);

        assert_eq!(os.resume_child_thread(hthread), Some(1));
        assert_eq!(seen.borrow().len(), 1, "resume runs the child exactly once");
        let req = seen.borrow()[0].clone();
        assert_eq!(req.image_guest_path, "C:\\child.exe");
        assert_eq!(req.command_line, "C:\\child.exe --flag");
        assert!(req.inherit_handles);

        assert!(os.kobject_is_signaled_for_test(hprocess));
        assert!(os.kobject_is_signaled_for_test(hthread));
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), 74);
        assert_eq!(
            String::from_utf8_lossy(os.captured_stdout()),
            "child said hello\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn query_exit_status(os: &mut WinOs, mem: &mut VirtualMemory, handle: u64) -> u32 {
        let buf = SCRATCH + 0xA00;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, handle);
        cpu.set_reg(Reg::Rdx, PROCESS_BASIC_INFORMATION as u64);
        cpu.set_reg(Reg::R8, buf);
        cpu.set_reg(Reg::R9, 0x30);
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        mem.write_u64(GUEST_RSP + 0x28, 0).unwrap();
        assert_eq!(os.nt_query_information_process(&mut cpu, mem).unwrap(), STATUS_SUCCESS);
        mem.read_u32(buf).unwrap()
    }

    #[test]
    fn a_missing_image_is_refused() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        os.set_process_spawner(Box::new(FakeSpawner {
            exit_code: 0,
            stdout: Vec::new(),
            seen: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        }));
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\nothing-here.exe",
            "C:\\nothing-here.exe",
            0,
            [0, 0, 0],
            None,
        );
        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(os.child_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_a_spawner_the_child_fails_loudly() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe",
            0,
            [0, 0, 0],
            None,
        );
        assert_eq!(status, STATUS_SUCCESS, "creation itself is fine");
        let hthread = mem.read_u64(SCRATCH + 8).unwrap();
        let hprocess = mem.read_u64(SCRATCH).unwrap();
        os.resume_child_thread(hthread);
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), STATUS_UNSUCCESSFUL);
        assert!(os.child_failure().unwrap().contains("no child-process runner"));
        assert!(String::from_utf8_lossy(os.captured_stderr()).contains("exemu: child process"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_scope_requests_are_refused_with_a_real_status() {
        let cases: [(u64, u64, u64, u32); 5] = [
            (ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::DEBUG_PORT, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::JOB_LIST, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::TOKEN, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::HANDLE_LIST, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (
                ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::MACHINE_TYPE,
                2,
                0x014C,
                STATUS_INVALID_IMAGE_FORMAT,
            ),
        ];
        for (packed, size, value, want) in cases {
            let (mut mem, dir) = fixture();
            let mut os = os64(&dir);
            let status = drive_create(
                &mut os,
                &mut mem,
                "\\??\\C:\\child.exe",
                "C:\\child.exe",
                0,
                [0, 0, 0],
                Some((packed, size, value)),
            );
            assert_eq!(status, want, "attribute {packed:#x} must be refused");
            assert_eq!(os.child_count(), 0, "a refused create leaves no object behind");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_redirected_std_handle_is_refused() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe",
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            [HANDLE_STDIN, 0x1000 , HANDLE_STDERR],
            None,
        );
        assert_eq!(status, STATUS_NOT_SUPPORTED);
        assert_eq!(os.child_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn params_reader_matches_the_w36_writer() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x10_0000, Perm::RW, "arena").unwrap();
        let mut os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            module_path_w: "C:\\parent.exe".into(),
            dll_base: 0x2_0000,
            dll_size: 0x10_0000,
            ..WinConfig::default()
        });
        let params = os.build_process_parameters_for_test(&mut mem).unwrap();

        assert_eq!(mem.read_u64(params + pp::STD_INPUT).unwrap(), HANDLE_STDIN);
        assert_eq!(mem.read_u64(params + pp::STD_OUTPUT).unwrap(), HANDLE_STDOUT);
        assert_eq!(mem.read_u64(params + pp::STD_ERROR).unwrap(), HANDLE_STDERR);
        assert_eq!(mem.read_u64(params + pp::CONSOLE_HANDLE).unwrap(), 0);
        assert_eq!(
            crate::fs::read_unicode_string(&mem, params + pp::IMAGE_PATH_NAME).unwrap(),
            "C:\\parent.exe"
        );
        assert_eq!(
            crate::fs::read_unicode_string(&mem, params + pp::CURRENT_DIRECTORY).unwrap(),
            "C:\\"
        );
        let env = os.read_environment_block(&mem, params).unwrap();
        let system_root = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("SystemRoot"))
            .unwrap_or_else(|| panic!("the decoded environment carries SystemRoot: {env:?}"));
        assert!(
            system_root.1.starts_with("C:"),
            "SystemRoot decoded as {:?} — a leading '=' here means the name/value \
             split ate the separator",
            system_root.1
        );
        assert!(env.iter().all(|(k, _)| !k.is_empty()), "no empty names: {env:?}");
        assert!(
            env.iter().all(|(_, v)| !v.starts_with('=')),
            "no value keeps the separator: {env:?}"
        );
    }
}
