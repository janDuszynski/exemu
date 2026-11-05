use super::*;
use crate::sync::KObject;

pub(super) const EVENT_SELECT_PARAMS_LEN: u64 = 0x10;
const EVENT_SELECT_MASK_OFF: u64 = 8;
const ENUM_EVENTS_OUT_LEN: u64 = 0x38;
const ENUM_STATUS_OFF: u64 = 4;
const AFD_POLL_BIT_CONNECT_ERR: u32 = 8;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub(super) const RECV_REARMED: u32 = AFD_POLL_READ | AFD_POLL_ACCEPT;
const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

pub(super) struct EventSelect {
    pub handle: u64,
    pub mask: u32,
}

impl WinOs {
    pub(super) fn afd_event_select(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < EVENT_SELECT_PARAMS_LEN || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_BUFFER_TOO_SMALL, 0));
        }
        let event = mem.read_u64(req.in_buf)?;
        let mask = mem.read_u32(req.in_buf + EVENT_SELECT_MASK_OFF)?;
        if mask != 0 && !matches!(self.kobjects.get(&event), Some(KObject::Event { .. })) {
            return Ok(OpResult::Done(STATUS_INVALID_HANDLE, 0));
        }
        let sock = self.socket_mut(req.handle);
        if mask == 0 {
            sock.event = None;
            return Ok(OK);
        }
        sock.event = Some(EventSelect { handle: event, mask });
        sock.nonblocking = true;
        sock.write_armed = true;
        self.signal_socket_event(req.handle);
        Ok(OK)
    }

    pub(super) fn afd_enum_network_events(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.out_len < ENUM_EVENTS_OUT_LEN || req.out_buf == 0 {
            return Ok(OpResult::Done(STATUS_BUFFER_TOO_SMALL, 0));
        }
        let fired = self.socket_events(req.handle);
        let sock = self.socket_mut(req.handle);
        let connect_status = sock.connect_error;
        if fired & AFD_POLL_WRITE != 0 {
            sock.write_armed = false;
        }
        sock.read_masked |= fired & RECV_REARMED;
        if fired & (AFD_POLL_CONNECT | AFD_POLL_CONNECT_ERR) != 0 {
            sock.connect_armed = false;
            sock.connect_error = STATUS_SUCCESS;
        }
        let selected = sock.event.as_ref().map(|e| e.handle);
        mem.write(req.out_buf, &[0u8; ENUM_EVENTS_OUT_LEN as usize])?;
        mem.write_u32(req.out_buf, fired)?;
        if fired & AFD_POLL_CONNECT_ERR != 0 {
            let slot = req.out_buf + ENUM_STATUS_OFF + u64::from(AFD_POLL_BIT_CONNECT_ERR) * 4;
            mem.write_u32(slot, connect_status)?;
        }
        for handle in selected.into_iter().chain((req.in_buf != 0).then_some(req.in_buf)) {
            if let Some(KObject::Event { signaled, .. }) = self.kobjects.get_mut(&handle) {
                *signaled = false;
            }
        }
        Ok(OpResult::Done(STATUS_SUCCESS, ENUM_EVENTS_OUT_LEN))
    }

    fn socket_events(&mut self, handle: u64) -> u32 {
        let ready = self.afd_readiness(handle);
        let Some(sock) = self.sockets.get(&handle) else { return 0 };
        let Some(selected) = &sock.event else { return 0 };
        let mut ready = ready;
        if !sock.write_armed {
            ready &= !AFD_POLL_WRITE;
        }
        ready &= !sock.read_masked;
        if sock.connect_armed {
            ready |= if sock.connect_error == STATUS_SUCCESS { AFD_POLL_CONNECT } else { AFD_POLL_CONNECT_ERR };
        }
        ready & selected.mask
    }

    fn signal_socket_event(&mut self, handle: u64) {
        if self.socket_events(handle) == 0 {
            return;
        }
        let Some(selected) = self.sockets.get(&handle).and_then(|s| s.event.as_ref()).map(|e| e.handle) else {
            return;
        };
        if let Some(KObject::Event { signaled, .. }) = self.kobjects.get_mut(&selected) {
            *signaled = true;
        }
    }

    pub(crate) fn refresh_socket_events(&mut self) {
        let selected: Vec<u64> =
            self.sockets.iter().filter(|(_, s)| s.event.is_some()).map(|(h, _)| *h).collect();
        for handle in selected {
            self.signal_socket_event(handle);
        }
    }

    fn waits_on_socket_event(&self, handles: &[u64]) -> bool {
        handles.iter().any(|h| self.sockets.values().any(|s| s.event.as_ref().is_some_and(|e| e.handle == *h)))
    }

    pub(crate) fn wait_for_socket_events(&mut self, handles: &[u64], all: bool, tid: u32, limit: Duration) -> bool {
        self.refresh_socket_events();
        let satisfied = |os: &WinOs| {
            let sig = |h: &u64| os.kobject_is_signaled(*h, tid);
            if all {
                handles.iter().all(sig)
            } else {
                handles.iter().any(sig)
            }
        };
        if satisfied(self) {
            return true;
        }
        if !self.waits_on_socket_event(handles) {
            return false;
        }
        let deadline = Instant::now() + limit.min(BLOCKING_WAIT_LIMIT);
        let mut spins = 0u32;
        loop {
            std::thread::sleep(if spins < FAST_SPINS { FAST_SLICE } else { SLOW_SLICE });
            spins = spins.saturating_add(1);
            self.refresh_socket_events();
            if satisfied(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
        }
    }
}

pub(crate) fn nt_relative_timeout(raw: i64) -> Duration {
    if raw >= 0 {
        return BLOCKING_WAIT_LIMIT;
    }
    Duration::from_nanos(raw.unsigned_abs().saturating_mul(1_000_000_000 / HUNDRED_NS_PER_SEC))
}
