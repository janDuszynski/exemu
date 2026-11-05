use exemu_core::{CpuState, Memory, Result};

use crate::sync::SyncKind;
use crate::thread::WaitDesc;
use crate::WinOs;

pub(crate) const SERVER_PROTOCOL_VERSION: u32 = 930;

const _: () = assert!(SERVER_PROTOCOL_VERSION == 0x3a2);

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_TIMEOUT: u32 = 0x0000_0102;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const REQ_CREATE_EVENT: u32 = 0x01;
const REQ_SELECT: u32 = 0x02;
const REQ_CLOSE_HANDLE: u32 = 0x03;
const REQ_DUP_HANDLE: u32 = 0x04;

const SELECT_WAIT: u32 = 0;
const SELECT_WAIT_ALL: u32 = 1;

#[cfg(test)]
const TIMEOUT_INFINITE: u64 = 0x7fff_ffff_ffff_ffff;

const MAXIMUM_WAIT_OBJECTS: u64 = 64;

mod info {
    pub const UNION_SIZE: u64 = 64;
    pub const DATA_COUNT: u64 = UNION_SIZE;
    pub const DATA: u64 = UNION_SIZE + 16;
}

mod req_header {
    pub const REQ: u64 = 0x00;
}

mod reply_header {
    pub const ERROR: u64 = 0x00;
    pub const REPLY_SIZE: u64 = 0x04;
}

mod body {
    pub const BASE: u64 = 12;

    pub const CREATE_EVENT_MANUAL: u64 = BASE;
    pub const CREATE_EVENT_INITIAL: u64 = BASE + 4;

    pub const SELECT_FLAGS: u64 = BASE;
    pub const SELECT_COOKIE: u64 = BASE + 8;
    pub const SELECT_TIMEOUT: u64 = BASE + 16;

    pub const CLOSE_HANDLE: u64 = BASE;

    pub const DUP_SRC_HANDLE: u64 = BASE + 4;
}

mod select_op {
    pub const OP: u64 = 0x00;
    pub const HANDLES: u64 = 0x04;
    pub const HANDLE_SIZE: u64 = 4;
}

impl WinOs {
    fn read_obj_handle(&self, mem: &dyn Memory, addr: u64) -> Result<u64> {
        Ok(mem.read_u32(addr)? as u64)
    }

    fn write_obj_handle(&self, mem: &mut dyn Memory, addr: u64, handle: u64) -> Result<()> {
        mem.write_u32(addr, handle as u32)
    }

    pub(crate) fn wine_server_call(
        &mut self,
        req: u64,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        self.unix_call_blocked = false;
        if req == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let opcode = mem.read_u32(req + req_header::REQ)?;
        let status = match opcode {
            REQ_CREATE_EVENT => self.srv_create_event(req, mem)?,
            REQ_SELECT => self.srv_select(req, cpu, mem)?,
            REQ_CLOSE_HANDLE => self.srv_close_handle(req, mem)?,
            REQ_DUP_HANDLE => self.srv_dup_handle(req, mem)?,
            _ => STATUS_NOT_IMPLEMENTED,
        };
        if !self.unix_call_blocked {
            self.write_reply_error(req, mem, status)?;
        }
        Ok(status)
    }

    fn write_reply_error(&self, req: u64, mem: &mut dyn Memory, error: u32) -> Result<()> {
        mem.write_u32(req + reply_header::ERROR, error)?;
        mem.write_u32(req + reply_header::REPLY_SIZE, 0)?;
        Ok(())
    }

    fn srv_create_event(&mut self, req: u64, mem: &mut dyn Memory) -> Result<u32> {
        let manual = mem.read_u32(req + body::CREATE_EVENT_MANUAL)? != 0;
        let initial = mem.read_u32(req + body::CREATE_EVENT_INITIAL)? != 0;
        let handle = self.make_object(mem, SyncKind::Event, None, manual, initial, (0, 0));
        self.write_obj_handle(mem, req + 8, handle)?;
        Ok(STATUS_SUCCESS)
    }

    fn srv_select(&mut self, req: u64, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let _cookie = mem.read_u64(req + body::SELECT_COOKIE)?;
        let _flags = mem.read_u32(req + body::SELECT_FLAGS)?;
        let timeout = mem.read_u64(req + body::SELECT_TIMEOUT)?;

        let data_count = mem.read_u32(req + info::DATA_COUNT)?;
        if data_count == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let iov_ptr = mem.read_u64(req + info::DATA)?;
        let iov_size = mem.read_u32(req + info::DATA + 8)? as u64;
        if iov_ptr == 0 || iov_size < select_op::HANDLES {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let op = mem.read_u32(iov_ptr + select_op::OP)?;
        let all = match op {
            SELECT_WAIT => false,
            SELECT_WAIT_ALL => true,
            _ => return Ok(STATUS_INVALID_PARAMETER),
        };
        let count = (iov_size - select_op::HANDLES) / select_op::HANDLE_SIZE;
        if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let mut handles = Vec::with_capacity(count as usize);
        for i in 0..count {
            let h = self.read_obj_handle(mem, iov_ptr + select_op::HANDLES + i * select_op::HANDLE_SIZE)?;
            handles.push(h);
        }
        self.server_select_wait(cpu, handles, all, timeout)
    }

    fn server_select_wait(&mut self, cpu: &mut CpuState, handles: Vec<u64>, all: bool, timeout: u64) -> Result<u32> {
        let tid = self.current_tid;
        let satisfied = self.server_wait_satisfiable(&handles, all, tid);
        if satisfied {
            self.server_acquire(&handles, all, tid);
            return Ok(STATUS_SUCCESS);
        }
        if timeout == 0 {
            return Ok(STATUS_TIMEOUT);
        }
        if self.block_and_switch(cpu, WaitDesc { handles, all }) {
            self.unix_call_blocked = true;
            Ok(STATUS_PENDING)
        } else {
            Ok(STATUS_SUCCESS)
        }
    }

    fn server_wait_satisfiable(&self, handles: &[u64], all: bool, tid: u32) -> bool {
        let sig = |h: &u64| self.kobject_is_signaled(*h, tid);
        if all {
            handles.iter().all(sig)
        } else {
            handles.iter().any(sig)
        }
    }

    fn server_acquire(&mut self, handles: &[u64], all: bool, tid: u32) {
        if all {
            for h in handles {
                self.kobject_acquire(*h, tid);
            }
        } else {
            for h in handles {
                if self.kobject_acquire(*h, tid) {
                    break;
                }
            }
        }
    }

    fn srv_close_handle(&mut self, req: u64, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.read_obj_handle(mem, req + body::CLOSE_HANDLE)?;
        if self.close_handle(handle) {
            Ok(STATUS_SUCCESS)
        } else {
            Ok(STATUS_INVALID_HANDLE)
        }
    }

    fn srv_dup_handle(&mut self, req: u64, mem: &mut dyn Memory) -> Result<u32> {
        let src = self.read_obj_handle(mem, req + body::DUP_SRC_HANDLE)?;
        let Some(new_handle) = self.dup_kobject_handle(src) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        self.write_obj_handle(mem, req + 8, new_handle)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_memory::VirtualMemory;

    fn os64() -> WinOs {
        WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() })
    }

    fn make_req(mem: &mut VirtualMemory, req: u64, opcode: u32) {
        mem.write_u32(req + req_header::REQ, opcode).unwrap();
    }

    #[test]
    fn protocol_version_is_pinned_930() {
        assert_eq!(SERVER_PROTOCOL_VERSION, 930);
        assert_eq!(SERVER_PROTOCOL_VERSION, 0x3a2);
    }

    #[test]
    fn create_event_through_wine_server_call() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x1000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let req = 0x5_0000;
        make_req(&mut mem, req, REQ_CREATE_EVENT);
        mem.write_u32(req + body::CREATE_EVENT_MANUAL, 1).unwrap();
        mem.write_u32(req + body::CREATE_EVENT_INITIAL, 1).unwrap();

        let status = os.wine_server_call(req, &mut CpuState::default(), &mut mem).unwrap();
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(mem.read_u32(req + reply_header::ERROR).unwrap(), STATUS_SUCCESS);
        let handle = mem.read_u32(req + 8).unwrap() as u64;
        assert!(handle != 0, "a handle was minted");
        assert!(os.kobject_is_signaled_for_test(handle));
    }

    #[test]
    fn close_handle_through_wine_server_call() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x2000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let handle = mem.read_u32(create + 8).unwrap() as u64;

        let close = 0x5_1000;
        make_req(&mut mem, close, REQ_CLOSE_HANDLE);
        os.write_obj_handle(&mut mem, close + body::CLOSE_HANDLE, handle).unwrap();
        assert_eq!(os.wine_server_call(close, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        make_req(&mut mem, close, REQ_CLOSE_HANDLE);
        assert_eq!(os.wine_server_call(close, &mut CpuState::default(), &mut mem).unwrap(), STATUS_INVALID_HANDLE);
    }

    #[test]
    fn dup_handle_through_wine_server_call() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x3000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        mem.write_u32(create + body::CREATE_EVENT_MANUAL, 1).unwrap();
        mem.write_u32(create + body::CREATE_EVENT_INITIAL, 1).unwrap();
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let h1 = mem.read_u32(create + 8).unwrap() as u64;

        let dup = 0x5_1000;
        make_req(&mut mem, dup, REQ_DUP_HANDLE);
        os.write_obj_handle(&mut mem, dup + body::DUP_SRC_HANDLE, h1).unwrap();
        assert_eq!(os.wine_server_call(dup, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        let h2 = mem.read_u32(dup + 8).unwrap() as u64;
        assert!(h2 != 0 && h2 != h1, "a distinct duplicate handle");

        let close = 0x5_2000;
        make_req(&mut mem, close, REQ_CLOSE_HANDLE);
        os.write_obj_handle(&mut mem, close + body::CLOSE_HANDLE, h1).unwrap();
        os.wine_server_call(close, &mut CpuState::default(), &mut mem).unwrap();
        assert!(os.kobject_is_signaled_for_test(h2), "duplicate survives the original's close");

        make_req(&mut mem, dup, REQ_DUP_HANDLE);
        os.write_obj_handle(&mut mem, dup + body::DUP_SRC_HANDLE, 0xdead_beef).unwrap();
        assert_eq!(os.wine_server_call(dup, &mut CpuState::default(), &mut mem).unwrap(), STATUS_INVALID_HANDLE);
    }

    #[test]
    fn select_on_signaled_event_completes() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x4000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        mem.write_u32(create + body::CREATE_EVENT_MANUAL, 1).unwrap();
        mem.write_u32(create + body::CREATE_EVENT_INITIAL, 1).unwrap();
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let handle = mem.read_u32(create + 8).unwrap() as u64;

        let sel_op = 0x5_2000;
        mem.write_u32(sel_op + select_op::OP, SELECT_WAIT).unwrap();
        os.write_obj_handle(&mut mem, sel_op + select_op::HANDLES, handle).unwrap();

        let sel = 0x5_1000;
        make_req(&mut mem, sel, REQ_SELECT);
        mem.write_u64(sel + body::SELECT_TIMEOUT, TIMEOUT_INFINITE).unwrap();
        mem.write_u32(sel + info::DATA_COUNT, 1).unwrap();
        mem.write_u64(sel + info::DATA, sel_op).unwrap();
        mem.write_u32(sel + info::DATA + 8, (select_op::HANDLES + 4) as u32).unwrap();

        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        assert_eq!(mem.read_u32(sel + reply_header::ERROR).unwrap(), STATUS_SUCCESS);
        assert!(!os.unix_call_blocked_for_test(), "did not block on a signaled object");
    }

    #[test]
    fn zero_timeout_select_polls_status_timeout() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x4000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let handle = mem.read_u32(create + 8).unwrap() as u64;

        let sel_op = 0x5_2000;
        mem.write_u32(sel_op + select_op::OP, SELECT_WAIT).unwrap();
        os.write_obj_handle(&mut mem, sel_op + select_op::HANDLES, handle).unwrap();
        let sel = 0x5_1000;
        make_req(&mut mem, sel, REQ_SELECT);
        mem.write_u32(sel + info::DATA_COUNT, 1).unwrap();
        mem.write_u64(sel + info::DATA, sel_op).unwrap();
        mem.write_u32(sel + info::DATA + 8, (select_op::HANDLES + 4) as u32).unwrap();

        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_TIMEOUT);
        assert_eq!(mem.read_u32(sel + reply_header::ERROR).unwrap(), STATUS_TIMEOUT);
        assert!(!os.unix_call_blocked_for_test(), "a poll never blocks");
    }

    #[test]
    fn select_on_unsignaled_single_thread_does_not_hang() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x4000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let handle = mem.read_u32(create + 8).unwrap() as u64;

        let sel_op = 0x5_2000;
        mem.write_u32(sel_op + select_op::OP, SELECT_WAIT).unwrap();
        os.write_obj_handle(&mut mem, sel_op + select_op::HANDLES, handle).unwrap();
        let sel = 0x5_1000;
        make_req(&mut mem, sel, REQ_SELECT);
        mem.write_u64(sel + body::SELECT_TIMEOUT, TIMEOUT_INFINITE).unwrap();
        mem.write_u32(sel + info::DATA_COUNT, 1).unwrap();
        mem.write_u64(sel + info::DATA, sel_op).unwrap();
        mem.write_u32(sel + info::DATA + 8, (select_op::HANDLES + 4) as u32).unwrap();

        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        assert!(!os.unix_call_blocked_for_test());
    }
}
