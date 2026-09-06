use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use exemu_core::{CpuState, Memory, Result};

use crate::thread::WaitDesc;
use crate::WinOs;

pub const SSDT_NT_DEVICE_IO_CONTROL_FILE: u32 = 0x07;

pub const AFD_DEVICE_NAME: &str = "\\Device\\Afd";

pub const AFD_DESIRED_ACCESS: u32 = 0xC010_0000;

pub const FILE_DEVICE_NETWORK: u32 = 0x12;

pub const fn afd_control_code(op: u32, method: u32) -> u32 {
    (FILE_DEVICE_NETWORK << 12) | (op << 2) | method
}

pub const fn ctl_code(op: u32, method: u32) -> u32 {
    (FILE_DEVICE_NETWORK << 16) | (op << 2) | method
}

pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_NEITHER: u32 = 3;

pub const IOCTL_AFD_BIND: u32 = afd_control_code(0, METHOD_NEITHER);
pub const IOCTL_AFD_START_LISTEN: u32 = afd_control_code(2, METHOD_NEITHER);
pub const IOCTL_AFD_SELECT: u32 = afd_control_code(9, METHOD_BUFFERED);
pub const IOCTL_AFD_GET_SOCK_NAME: u32 = afd_control_code(11, METHOD_NEITHER);
pub const IOCTL_AFD_EVENT_SELECT: u32 = afd_control_code(33, METHOD_NEITHER);
pub const IOCTL_AFD_ENUM_NETWORK_EVENTS: u32 = afd_control_code(34, METHOD_NEITHER);

pub const IOCTL_AFD_WINE_CREATE: u32 = ctl_code(200, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_ACCEPT: u32 = ctl_code(201, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_OP_202: u32 = ctl_code(202, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_CONNECT: u32 = ctl_code(203, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SHUTDOWN: u32 = ctl_code(204, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_RECVMSG: u32 = ctl_code(205, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SENDMSG: u32 = ctl_code(206, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_OP_207: u32 = ctl_code(207, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_OP_210: u32 = ctl_code(210, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_ASYNC_SELECT: u32 = ctl_code(215, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_PEER_NAME: u32 = ctl_code(216, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_OP_217: u32 = ctl_code(217, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SOCKET_INFO: u32 = ctl_code(218, METHOD_BUFFERED);

pub const CREATE_PARAMS_LEN: u32 = 0x10;
pub const LISTEN_PARAMS_LEN: u32 = 0x0c;
pub const LISTEN_BACKLOG_OFF: u64 = 4;
pub const ACCEPT_OUT_LEN: u32 = 4;
pub const SHUTDOWN_PARAMS_LEN: u32 = 4;
pub const SOCKET_INFO_LEN: u32 = 0x0c;

pub const CONNECT_PARAMS_HEADER: u64 = 8;
pub const BIND_PARAMS_HEADER: u64 = 4;

pub const RECVMSG_PARAMS_LEN: u32 = 0x30;
pub const RECVMSG_ADDR_OFF: u64 = 0x08;
pub const RECVMSG_ADDR_LEN_OFF: u64 = 0x10;
pub const RECVMSG_WS_FLAGS_OFF: u64 = 0x18;
pub const RECVMSG_COUNT_OFF: u64 = 0x24;
pub const RECVMSG_BUFFERS_OFF: u64 = 0x28;

pub const SENDMSG_PARAMS_LEN: u32 = 0x20;
pub const SENDMSG_ADDR_OFF: u64 = 0x00;
pub const SENDMSG_ADDR_LEN_OFF: u64 = 0x08;
pub const SENDMSG_COUNT_OFF: u64 = 0x14;
pub const SENDMSG_BUFFERS_OFF: u64 = 0x18;

pub const WSABUF_STRIDE: u64 = 0x10;
pub const WSABUF_PTR_OFF: u64 = 0x08;

pub const POLL_PARAMS_HEADER: u64 = 0x10;
pub const POLL_PARAMS_COUNT_OFF: u64 = 0x08;
pub const POLL_ENTRY_STRIDE: u64 = 0x10;
pub const POLL_ENTRY_FLAGS_OFF: u64 = 0x08;
pub const POLL_ENTRY_STATUS_OFF: u64 = 0x0c;

pub const AFD_POLL_READ: u32 = 0x0001;
pub const AFD_POLL_OOB: u32 = 0x0002;
pub const AFD_POLL_WRITE: u32 = 0x0004;
pub const AFD_POLL_HUP: u32 = 0x0008;
pub const AFD_POLL_RESET: u32 = 0x0010;
pub const AFD_POLL_CLOSE: u32 = 0x0020;
pub const AFD_POLL_CONNECT: u32 = 0x0040;
pub const AFD_POLL_ACCEPT: u32 = 0x0080;
pub const AFD_POLL_CONNECT_ERR: u32 = 0x0100;
pub const AFD_POLL_ALWAYS: u32 = AFD_POLL_HUP | AFD_POLL_RESET | AFD_POLL_CONNECT_ERR;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ADDRESS_ALREADY_EXISTS: u32 = 0xC000_020A;
const STATUS_INVALID_ADDRESS_COMPONENT: u32 = 0xC000_0207;
const STATUS_CONNECTION_REFUSED: u32 = 0xC000_0236;
const STATUS_CONNECTION_RESET: u32 = 0xC000_020D;
const STATUS_CONNECTION_ABORTED: u32 = 0xC000_0241;
const STATUS_CONNECTION_ACTIVE: u32 = 0xC000_023B;
const STATUS_INVALID_CONNECTION: u32 = 0xC000_0140;
const STATUS_NETWORK_UNREACHABLE: u32 = 0xC000_023C;
const STATUS_HOST_UNREACHABLE: u32 = 0xC000_023D;
const STATUS_IO_TIMEOUT: u32 = 0xC000_00B5;
const STATUS_PIPE_DISCONNECTED: u32 = 0xC000_00B0;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;

const SOCKADDR_IN_LEN: usize = 16;
const SOCKADDR_IN6_LEN: usize = 28;

const SD_RECEIVE: u32 = 0;
const SD_SEND: u32 = 1;

pub const BLOCKING_WAIT_LIMIT: Duration = Duration::from_secs(20);

const FAST_SLICE: Duration = Duration::from_micros(100);
const SLOW_SLICE: Duration = Duration::from_millis(2);
const FAST_SPINS: u32 = 64;

const MAX_TRANSFER: u64 = 16 << 20;
const MAX_POLL_ENTRIES: u32 = 4096;
const MAX_WSABUFS: u32 = 1024;

enum Endpoint {
    Unbound,
    Listener(TcpListener),
    Stream(TcpStream),
    Datagram(UdpSocket),
}

pub(crate) struct Socket {
    family: i32,
    kind: i32,
    protocol: i32,
    ep: Endpoint,
    requested_bind: Option<SocketAddr>,
    listening: bool,
    pending: VecDeque<TcpStream>,
    peer: Option<SocketAddr>,
    rd_shutdown: bool,
    wr_shutdown: bool,
}

impl Socket {
    fn new() -> Socket {
        Socket {
            family: 0,
            kind: 0,
            protocol: 0,
            ep: Endpoint::Unbound,
            requested_bind: None,
            listening: false,
            pending: VecDeque::new(),
            peer: None,
            rd_shutdown: false,
            wr_shutdown: false,
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        match &self.ep {
            Endpoint::Listener(l) => l.local_addr().ok(),
            Endpoint::Stream(s) => s.local_addr().ok(),
            Endpoint::Datagram(d) => d.local_addr().ok(),
            Endpoint::Unbound => None,
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        match &self.ep {
            Endpoint::Stream(s) => s.peer_addr().ok(),
            Endpoint::Datagram(_) => self.peer,
            _ => None,
        }
    }
}

enum OpResult {
    Done(u32, u64),
    WouldBlock,
}

const OK: OpResult = OpResult::Done(STATUS_SUCCESS, 0);

fn status_for(e: &std::io::Error) -> u32 {
    match e.kind() {
        ErrorKind::ConnectionRefused => STATUS_CONNECTION_REFUSED,
        ErrorKind::ConnectionReset => STATUS_CONNECTION_RESET,
        ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => STATUS_CONNECTION_ABORTED,
        ErrorKind::AddrInUse => STATUS_ADDRESS_ALREADY_EXISTS,
        ErrorKind::AddrNotAvailable => STATUS_INVALID_ADDRESS_COMPONENT,
        ErrorKind::NotConnected => STATUS_INVALID_CONNECTION,
        ErrorKind::TimedOut => STATUS_IO_TIMEOUT,
        ErrorKind::PermissionDenied => STATUS_NETWORK_UNREACHABLE,
        _ => STATUS_HOST_UNREACHABLE,
    }
}

fn from_io<T>(r: std::io::Result<T>, ok: impl FnOnce(T) -> OpResult) -> OpResult {
    match r {
        Ok(v) => ok(v),
        Err(e) if e.kind() == ErrorKind::WouldBlock => OpResult::WouldBlock,
        Err(e) => OpResult::Done(status_for(&e), 0),
    }
}

fn read_sockaddr(mem: &dyn Memory, ptr: u64, len: u64) -> Result<Option<SocketAddr>> {
    if ptr == 0 || len < 2 {
        return Ok(None);
    }
    let family = mem.read_u16(ptr)? as i32;
    Ok(match family {
        AF_INET if len >= SOCKADDR_IN_LEN as u64 => {
            let port = mem.read_u16(ptr + 2)?.to_be();
            let mut octets = [0u8; 4];
            mem.read(ptr + 4, &mut octets)?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        AF_INET6 if len >= SOCKADDR_IN6_LEN as u64 => {
            let port = mem.read_u16(ptr + 2)?.to_be();
            let mut raw = [0u8; 16];
            mem.read(ptr + 8, &mut raw)?;
            let scope = mem.read_u32(ptr + 24)?;
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(raw),
                port,
                0,
                scope,
            )))
        }
        _ => None,
    })
}

fn sockaddr_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            out.extend_from_slice(&(AF_INET as u16).to_le_bytes());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&[0u8; 8]);
        }
        SocketAddr::V6(v6) => {
            out.extend_from_slice(&(AF_INET6 as u16).to_le_bytes());
            out.extend_from_slice(&v6.port().to_be_bytes());
            out.extend_from_slice(&v6.flowinfo().to_be_bytes());
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.scope_id().to_le_bytes());
        }
    }
    debug_assert!(out.len() == SOCKADDR_IN_LEN || out.len() == SOCKADDR_IN6_LEN);
    out
}

fn write_sockaddr(mem: &mut dyn Memory, ptr: u64, cap: u64, addr: &SocketAddr) -> Result<Option<u64>> {
    let bytes = sockaddr_bytes(addr);
    if ptr == 0 || cap < bytes.len() as u64 {
        return Ok(None);
    }
    mem.write(ptr, &bytes)?;
    Ok(Some(bytes.len() as u64))
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

struct WsaBuf {
    ptr: u64,
    len: u64,
}

fn read_wsabufs(mem: &dyn Memory, array: u64, count: u32) -> Result<Vec<WsaBuf>> {
    let mut out = Vec::new();
    let mut total = 0u64;
    if array == 0 {
        return Ok(out);
    }
    for i in 0..count as u64 {
        let base = array + i * WSABUF_STRIDE;
        let len = mem.read_u32(base)? as u64;
        let ptr = mem.read_u64(base + WSABUF_PTR_OFF)?;
        let len = len.min(MAX_TRANSFER.saturating_sub(total));
        total += len;
        out.push(WsaBuf { ptr, len });
        if total >= MAX_TRANSFER {
            break;
        }
    }
    Ok(out)
}

fn gather(mem: &dyn Memory, bufs: &[WsaBuf]) -> Result<Vec<u8>> {
    let total: u64 = bufs.iter().map(|b| b.len).sum();
    let mut out = vec![0u8; total as usize];
    let mut at = 0usize;
    for b in bufs {
        if b.len == 0 {
            continue;
        }
        mem.read(b.ptr, &mut out[at..at + b.len as usize])?;
        at += b.len as usize;
    }
    Ok(out)
}

fn scatter(mem: &mut dyn Memory, bufs: &[WsaBuf], data: &[u8]) -> Result<()> {
    let mut at = 0usize;
    for b in bufs {
        if at >= data.len() {
            break;
        }
        let n = (b.len as usize).min(data.len() - at);
        if n != 0 {
            mem.write(b.ptr, &data[at..at + n])?;
        }
        at += n;
    }
    Ok(())
}

impl WinOs {
    pub(crate) fn is_socket_handle(&self, handle: u64) -> bool {
        self.sockets.contains_key(&handle)
    }

    pub(crate) fn nt_open_afd(
        &mut self,
        mem: &mut dyn Memory,
        name: &str,
        handle_ptr: u64,
        iosb_ptr: u64,
    ) -> Result<Option<u32>> {
        if !name.eq_ignore_ascii_case(AFD_DEVICE_NAME) {
            return Ok(None);
        }
        if handle_ptr == 0 {
            return Ok(Some(STATUS_ACCESS_VIOLATION));
        }
        let handle = self.alloc_khandle();
        self.sockets.insert(handle, Socket::new());
        mem.write_u64(handle_ptr, handle)?;
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 1)?;
        Ok(Some(STATUS_SUCCESS))
    }

    pub(crate) fn close_socket(&mut self, handle: u64) -> bool {
        self.sockets.remove(&handle).is_some()
    }

    fn afd_policy_check(&self, addr: &SocketAddr) -> std::result::Result<(), u32> {
        match addr {
            SocketAddr::V4(_) | SocketAddr::V6(_) => Ok(()),
        }
    }

    pub(crate) fn nt_device_io_control_file(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let iosb = self.syscall_arg(cpu, mem, 4)?;
        let code = self.syscall_arg(cpu, mem, 5)? as u32;
        let in_buf = self.syscall_arg(cpu, mem, 6)?;
        let in_len = self.syscall_arg(cpu, mem, 7)? & 0xFFFF_FFFF;
        let out_buf = self.syscall_arg(cpu, mem, 8)?;
        let out_len = self.syscall_arg(cpu, mem, 9)? & 0xFFFF_FFFF;

        if !self.is_socket_handle(handle) {
            let status = if self.is_file_handle(handle) || self.is_std_handle(handle) {
                STATUS_NOT_IMPLEMENTED
            } else {
                STATUS_INVALID_HANDLE
            };
            write_iosb(mem, iosb, status, 0)?;
            return Ok(status);
        }

        let req = Request { handle, code, in_buf, in_len, out_buf, out_len };
        match self.afd_dispatch(mem, &req)? {
            OpResult::Done(status, info) => {
                write_iosb(mem, iosb, status, info)?;
                Ok(status)
            }
            OpResult::WouldBlock => self.afd_block(cpu, mem, &req, iosb),
        }
    }

    fn afd_block(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        req: &Request,
        iosb: u64,
    ) -> Result<u32> {
        self.rewind_syscall(cpu);
        if self.block_and_switch(cpu, WaitDesc { handles: Vec::new(), all: true }) {
            self.syscall_resume_as_is = true;
            return Ok(STATUS_PENDING);
        }
        let deadline = Instant::now() + self.afd_wait_limit(mem, req)?;
        let mut spins = 0u32;
        loop {
            std::thread::sleep(if spins < FAST_SPINS { FAST_SLICE } else { SLOW_SLICE });
            spins = spins.saturating_add(1);
            if let OpResult::Done(status, info) = self.afd_dispatch(mem, req)? {
                write_iosb(mem, iosb, status, info)?;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return self.afd_wait_expired(mem, req, iosb);
            }
        }
    }

    fn afd_wait_limit(&self, mem: &dyn Memory, req: &Request) -> Result<Duration> {
        if req.code != IOCTL_AFD_SELECT || req.in_buf == 0 {
            return Ok(BLOCKING_WAIT_LIMIT);
        }
        let raw = mem.read_u64(req.in_buf)? as i64;
        if raw >= 0 {
            return Ok(BLOCKING_WAIT_LIMIT);
        }
        let nanos = raw.unsigned_abs().saturating_mul(100);
        Ok(Duration::from_nanos(nanos).min(BLOCKING_WAIT_LIMIT))
    }

    fn afd_wait_expired(&mut self, mem: &mut dyn Memory, req: &Request, iosb: u64) -> Result<u32> {
        if req.code == IOCTL_AFD_SELECT && req.in_buf != 0 {
            mem.write_u32(req.in_buf + POLL_PARAMS_COUNT_OFF, 0)?;
            write_iosb(mem, iosb, STATUS_SUCCESS, POLL_PARAMS_HEADER)?;
            return Ok(STATUS_SUCCESS);
        }
        write_iosb(mem, iosb, STATUS_IO_TIMEOUT, 0)?;
        Ok(STATUS_IO_TIMEOUT)
    }

    fn afd_dispatch(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        Ok(match req.code {
            IOCTL_AFD_WINE_CREATE => self.afd_create(mem, req)?,
            IOCTL_AFD_BIND => self.afd_bind(mem, req)?,
            IOCTL_AFD_START_LISTEN => self.afd_listen(mem, req)?,
            IOCTL_AFD_WINE_CONNECT => self.afd_connect(mem, req)?,
            IOCTL_AFD_WINE_ACCEPT => self.afd_accept(mem, req)?,
            IOCTL_AFD_WINE_RECVMSG => self.afd_recv(mem, req)?,
            IOCTL_AFD_WINE_SENDMSG => self.afd_send(mem, req)?,
            IOCTL_AFD_WINE_SHUTDOWN => self.afd_shutdown(mem, req)?,
            IOCTL_AFD_GET_SOCK_NAME => self.afd_get_name(mem, req, false)?,
            IOCTL_AFD_WINE_GET_PEER_NAME => self.afd_get_name(mem, req, true)?,
            IOCTL_AFD_WINE_GET_SOCKET_INFO => self.afd_get_socket_info(mem, req)?,
            IOCTL_AFD_SELECT => self.afd_select(mem, req)?,
            IOCTL_AFD_WINE_OP_210 => OK,
            _ => OpResult::Done(STATUS_NOT_IMPLEMENTED, 0),
        })
    }

    fn afd_create(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < CREATE_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let family = mem.read_u32(req.in_buf)? as i32;
        let kind = mem.read_u32(req.in_buf + 4)? as i32;
        let protocol = mem.read_u32(req.in_buf + 8)? as i32;
        if !matches!(family, AF_INET | AF_INET6) || !matches!(kind, SOCK_STREAM | SOCK_DGRAM) {
            return Ok(OpResult::Done(STATUS_NOT_IMPLEMENTED, 0));
        }
        let sock = self.socket_mut(req.handle);
        sock.family = family;
        sock.kind = kind;
        sock.protocol = protocol;
        Ok(OK)
    }

    fn afd_bind(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        let Some(addr) = read_sockaddr(mem, req.in_buf + BIND_PARAMS_HEADER, req.in_len.saturating_sub(BIND_PARAMS_HEADER))? else {
            return Ok(OpResult::Done(STATUS_INVALID_ADDRESS_COMPONENT, 0));
        };
        if let Err(status) = self.afd_policy_check(&addr) {
            return Ok(OpResult::Done(status, 0));
        }
        let kind = self.socket_mut(req.handle).kind;
        let ep = match kind {
            SOCK_DGRAM => match UdpSocket::bind(addr) {
                Ok(s) => {
                    let _ = s.set_nonblocking(true);
                    Endpoint::Datagram(s)
                }
                Err(e) => return Ok(OpResult::Done(status_for(&e), 0)),
            },
            SOCK_STREAM => match TcpListener::bind(addr) {
                Ok(l) => {
                    let _ = l.set_nonblocking(true);
                    Endpoint::Listener(l)
                }
                Err(e) => return Ok(OpResult::Done(status_for(&e), 0)),
            },
            _ => return Ok(OpResult::Done(STATUS_INVALID_PARAMETER, 0)),
        };
        let sock = self.socket_mut(req.handle);
        sock.ep = ep;
        sock.requested_bind = Some(addr);
        let Some(local) = sock.local_addr() else {
            return Ok(OK);
        };
        let written = write_sockaddr(mem, req.out_buf, req.out_len, &local)?.unwrap_or(0);
        Ok(OpResult::Done(STATUS_SUCCESS, written))
    }

    fn afd_listen(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < LISTEN_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let _backlog = mem.read_u32(req.in_buf + LISTEN_BACKLOG_OFF)?;
        let sock = self.socket_mut(req.handle);
        if !matches!(sock.ep, Endpoint::Listener(_)) {
            return Ok(OpResult::Done(STATUS_INVALID_PARAMETER, 0));
        }
        sock.listening = true;
        Ok(OK)
    }

    fn afd_connect(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < CONNECT_PARAMS_HEADER || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let addr_len = mem.read_u32(req.in_buf)? as u64;
        let Some(addr) = read_sockaddr(mem, req.in_buf + CONNECT_PARAMS_HEADER, addr_len)? else {
            return Ok(OpResult::Done(STATUS_INVALID_ADDRESS_COMPONENT, 0));
        };
        if let Err(status) = self.afd_policy_check(&addr) {
            return Ok(OpResult::Done(status, 0));
        }

        let sock = self.socket_mut(req.handle);
        match (&sock.ep, sock.kind) {
            (Endpoint::Stream(_), _) => return Ok(OpResult::Done(STATUS_CONNECTION_ACTIVE, 0)),
            (Endpoint::Listener(_), _) => {
                let ephemeral = sock.requested_bind.map(|a| a.port() == 0).unwrap_or(false);
                if sock.listening || !ephemeral {
                    return Ok(OpResult::Done(STATUS_INVALID_PARAMETER, 0));
                }
                sock.ep = Endpoint::Unbound;
            }
            (Endpoint::Datagram(d), _) => {
                return Ok(match d.connect(addr) {
                    Ok(()) => {
                        self.socket_mut(req.handle).peer = Some(addr);
                        OK
                    }
                    Err(e) => OpResult::Done(status_for(&e), 0),
                });
            }
            (Endpoint::Unbound, SOCK_DGRAM) => {
                let any = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let bound = any.parse::<SocketAddr>().expect("literal");
                return Ok(match UdpSocket::bind(bound).and_then(|d| {
                    d.set_nonblocking(true)?;
                    d.connect(addr)?;
                    Ok(d)
                }) {
                    Ok(d) => {
                        let sock = self.socket_mut(req.handle);
                        sock.ep = Endpoint::Datagram(d);
                        sock.peer = Some(addr);
                        OK
                    }
                    Err(e) => OpResult::Done(status_for(&e), 0),
                });
            }
            (Endpoint::Unbound, _) => {}
        }

        match TcpStream::connect_timeout(&addr, BLOCKING_WAIT_LIMIT) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_nonblocking(true);
                self.socket_mut(req.handle).ep = Endpoint::Stream(s);
                Ok(OK)
            }
            Err(e) => Ok(OpResult::Done(status_for(&e), 0)),
        }
    }

    fn afd_accept(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.out_len < ACCEPT_OUT_LEN as u64 || req.out_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let sock = self.socket_mut(req.handle);
        let stream = match sock.pending.pop_front() {
            Some(s) => s,
            None => {
                let Endpoint::Listener(l) = &sock.ep else {
                    return Ok(OpResult::Done(STATUS_INVALID_CONNECTION, 0));
                };
                match l.accept() {
                    Ok((s, _)) => s,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(OpResult::WouldBlock),
                    Err(e) => return Ok(OpResult::Done(status_for(&e), 0)),
                }
            }
        };
        let _ = stream.set_nonblocking(true);
        let (family, protocol) = {
            let s = self.socket_mut(req.handle);
            (s.family, s.protocol)
        };
        let child = self.alloc_khandle();
        let mut accepted = Socket::new();
        accepted.family = family;
        accepted.kind = SOCK_STREAM;
        accepted.protocol = protocol;
        accepted.ep = Endpoint::Stream(stream);
        self.sockets.insert(child, accepted);
        debug_assert!(child <= u64::from(u32::MAX));
        mem.write_u32(req.out_buf, child as u32)?;
        Ok(OpResult::Done(STATUS_SUCCESS, ACCEPT_OUT_LEN as u64))
    }

    fn afd_recv(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < RECVMSG_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let p = req.in_buf;
        let count = mem.read_u32(p + RECVMSG_COUNT_OFF)?.min(MAX_WSABUFS);
        let buffers = mem.read_u64(p + RECVMSG_BUFFERS_OFF)?;
        let addr_ptr = mem.read_u64(p + RECVMSG_ADDR_OFF)?;
        let addr_len_ptr = mem.read_u64(p + RECVMSG_ADDR_LEN_OFF)?;
        let bufs = read_wsabufs(mem, buffers, count)?;
        let cap: u64 = bufs.iter().map(|b| b.len).sum();

        let sock = self.socket_mut(req.handle);
        if sock.rd_shutdown {
            return Ok(OK);
        }
        let mut tmp = vec![0u8; cap as usize];
        let (n, from) = match &mut sock.ep {
            Endpoint::Stream(s) => match s.read(&mut tmp) {
                Ok(n) => (n, None),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(OpResult::WouldBlock),
                Err(e) => return Ok(OpResult::Done(status_for(&e), 0)),
            },
            Endpoint::Datagram(d) => match d.recv_from(&mut tmp) {
                Ok((n, from)) => (n, Some(from)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(OpResult::WouldBlock),
                Err(e) => return Ok(OpResult::Done(status_for(&e), 0)),
            },
            _ => return Ok(OpResult::Done(STATUS_INVALID_CONNECTION, 0)),
        };
        if n == 0 && cap != 0 && from.is_none() {
            return Ok(OK);
        }
        scatter(mem, &bufs, &tmp[..n])?;
        if let (Some(from), true) = (from, addr_ptr != 0) {
            let cap = if addr_len_ptr != 0 { mem.read_u32(addr_len_ptr)? as u64 } else { 0 };
            if let Some(written) = write_sockaddr(mem, addr_ptr, cap, &from)? {
                if addr_len_ptr != 0 {
                    mem.write_u32(addr_len_ptr, written as u32)?;
                }
            }
        }
        Ok(OpResult::Done(STATUS_SUCCESS, n as u64))
    }

    fn afd_send(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < SENDMSG_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let p = req.in_buf;
        let count = mem.read_u32(p + SENDMSG_COUNT_OFF)?.min(MAX_WSABUFS);
        let buffers = mem.read_u64(p + SENDMSG_BUFFERS_OFF)?;
        let addr_ptr = mem.read_u64(p + SENDMSG_ADDR_OFF)?;
        let addr_len = mem.read_u32(p + SENDMSG_ADDR_LEN_OFF)? as u64;
        let to = read_sockaddr(mem, addr_ptr, addr_len)?;
        let bufs = read_wsabufs(mem, buffers, count)?;
        let data = gather(mem, &bufs)?;

        if let Some(a) = &to {
            if let Err(status) = self.afd_policy_check(a) {
                return Ok(OpResult::Done(status, 0));
            }
        }
        let sock = self.socket_mut(req.handle);
        if sock.wr_shutdown {
            return Ok(OpResult::Done(STATUS_PIPE_DISCONNECTED, 0));
        }
        Ok(match &mut sock.ep {
            Endpoint::Stream(s) => from_io(s.write(&data), |n| OpResult::Done(STATUS_SUCCESS, n as u64)),
            Endpoint::Datagram(d) => {
                let r = match to {
                    Some(a) => d.send_to(&data, a),
                    None => d.send(&data),
                };
                from_io(r, |n| OpResult::Done(STATUS_SUCCESS, n as u64))
            }
            _ => OpResult::Done(STATUS_INVALID_CONNECTION, 0),
        })
    }

    fn afd_shutdown(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < SHUTDOWN_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let how = mem.read_u32(req.in_buf)?;
        let (rd, wr) = match how {
            SD_RECEIVE => (true, false),
            SD_SEND => (false, true),
            _ => (true, true),
        };
        let sock = self.socket_mut(req.handle);
        sock.rd_shutdown |= rd;
        sock.wr_shutdown |= wr;
        let how = match (sock.rd_shutdown, sock.wr_shutdown) {
            (true, true) => Shutdown::Both,
            (true, false) => Shutdown::Read,
            _ => Shutdown::Write,
        };
        Ok(match &sock.ep {
            Endpoint::Stream(s) => match s.shutdown(how) {
                Ok(()) => OK,
                Err(e) if e.kind() == ErrorKind::NotConnected => OK,
                Err(e) => OpResult::Done(status_for(&e), 0),
            },
            Endpoint::Datagram(_) | Endpoint::Listener(_) => OK,
            Endpoint::Unbound => OpResult::Done(STATUS_INVALID_CONNECTION, 0),
        })
    }

    fn afd_get_name(&mut self, mem: &mut dyn Memory, req: &Request, peer: bool) -> Result<OpResult> {
        let sock = self.socket_mut(req.handle);
        let addr = if peer { sock.peer_addr() } else { sock.local_addr() };
        let Some(addr) = addr else {
            return Ok(OpResult::Done(STATUS_INVALID_CONNECTION, 0));
        };
        match write_sockaddr(mem, req.out_buf, req.out_len, &addr)? {
            Some(n) => Ok(OpResult::Done(STATUS_SUCCESS, n)),
            None => Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0)),
        }
    }

    fn afd_get_socket_info(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.out_len < SOCKET_INFO_LEN as u64 || req.out_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let sock = self.socket_mut(req.handle);
        let (family, kind, protocol) = (sock.family, sock.kind, sock.protocol);
        mem.write_u32(req.out_buf, family as u32)?;
        mem.write_u32(req.out_buf + 4, kind as u32)?;
        mem.write_u32(req.out_buf + 8, protocol as u32)?;
        Ok(OpResult::Done(STATUS_SUCCESS, SOCKET_INFO_LEN as u64))
    }

    fn afd_select(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        let p = req.in_buf;
        if p == 0 || req.in_len < POLL_PARAMS_HEADER {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let timeout = mem.read_u64(p)? as i64;
        let count = mem.read_u32(p + POLL_PARAMS_COUNT_OFF)?.min(MAX_POLL_ENTRIES);

        let mut ready: Vec<(u64, u32)> = Vec::new();
        for i in 0..count as u64 {
            let e = p + POLL_PARAMS_HEADER + i * POLL_ENTRY_STRIDE;
            let handle = mem.read_u64(e)?;
            let want = mem.read_u32(e + POLL_ENTRY_FLAGS_OFF)?;
            let got = self.afd_readiness(handle) & want;
            if got != 0 {
                ready.push((handle, got));
            }
        }

        if ready.is_empty() && timeout != 0 {
            return Ok(OpResult::WouldBlock);
        }
        for (i, (handle, flags)) in ready.iter().enumerate() {
            let e = p + POLL_PARAMS_HEADER + i as u64 * POLL_ENTRY_STRIDE;
            mem.write_u64(e, *handle)?;
            mem.write_u32(e + POLL_ENTRY_FLAGS_OFF, *flags)?;
            mem.write_u32(e + POLL_ENTRY_STATUS_OFF, STATUS_SUCCESS)?;
        }
        mem.write_u32(p + POLL_PARAMS_COUNT_OFF, ready.len() as u32)?;
        Ok(OpResult::Done(
            STATUS_SUCCESS,
            POLL_PARAMS_HEADER + ready.len() as u64 * POLL_ENTRY_STRIDE,
        ))
    }

    fn afd_readiness(&mut self, handle: u64) -> u32 {
        let Some(sock) = self.sockets.get_mut(&handle) else {
            return AFD_POLL_CONNECT_ERR;
        };
        let mut flags = 0;
        if sock.wr_shutdown && sock.rd_shutdown {
            flags |= AFD_POLL_HUP;
        }
        match &mut sock.ep {
            Endpoint::Stream(s) => {
                if !sock.wr_shutdown {
                    flags |= AFD_POLL_WRITE;
                }
                let mut probe = [0u8; 1];
                match s.peek(&mut probe) {
                    Ok(0) => flags |= AFD_POLL_READ | AFD_POLL_HUP,
                    Ok(_) => flags |= AFD_POLL_READ,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => flags |= AFD_POLL_RESET | AFD_POLL_READ,
                }
            }
            Endpoint::Listener(l) => {
                if sock.pending.is_empty() {
                    if let Ok((s, _)) = l.accept() {
                        let _ = s.set_nonblocking(true);
                        sock.pending.push_back(s);
                    }
                }
                if !sock.pending.is_empty() {
                    flags |= AFD_POLL_ACCEPT | AFD_POLL_READ;
                }
            }
            Endpoint::Datagram(d) => {
                flags |= AFD_POLL_WRITE;
                let mut probe = [0u8; 1];
                if d.peek(&mut probe).is_ok() {
                    flags |= AFD_POLL_READ;
                }
            }
            Endpoint::Unbound => flags |= AFD_POLL_WRITE,
        }
        flags
    }

    fn socket_mut(&mut self, handle: u64) -> &mut Socket {
        self.sockets.get_mut(&handle).expect("the handle was checked to be a live socket")
    }
}

struct Request {
    handle: u64,
    code: u32,
    in_buf: u64,
    in_len: u64,
    out_buf: u64,
    out_len: u64,
}

use crate::unixlib::{UnixEntry, Unixlib};

const WSAHOST_NOT_FOUND: u32 = 11001;

fn unix_unresolved(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(WSAHOST_NOT_FOUND)
}

static WS2_32_UNIXLIB: &[UnixEntry] = &[
    unix_unresolved,
    unix_unresolved,
    unix_unresolved,
    unix_unresolved,
    unix_unresolved,
];

pub(crate) fn ws2_32_unixlib() -> Unixlib {
    Unixlib { name: "ws2_32", table: WS2_32_UNIXLIB, wow64: false }
}

pub(crate) fn ssdt_nt_device_io_control_file(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_device_io_control_file(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn afd_control_codes_use_both_recovered_encodings() {
        assert_eq!(IOCTL_AFD_BIND, 0x0001_2003);
        assert_eq!(IOCTL_AFD_START_LISTEN, 0x0001_200b);
        assert_eq!(IOCTL_AFD_SELECT, 0x0001_2024);
        assert_eq!(IOCTL_AFD_GET_SOCK_NAME, 0x0001_202f);
        assert_eq!(IOCTL_AFD_EVENT_SELECT, 0x0001_2087);
        assert_eq!(IOCTL_AFD_ENUM_NETWORK_EVENTS, 0x0001_208b);
        assert_eq!(IOCTL_AFD_WINE_CREATE, 0x0012_0320);
        assert_eq!(IOCTL_AFD_WINE_ACCEPT, 0x0012_0324);
        assert_eq!(IOCTL_AFD_WINE_CONNECT, 0x0012_032c);
        assert_eq!(IOCTL_AFD_WINE_SHUTDOWN, 0x0012_0330);
        assert_eq!(IOCTL_AFD_WINE_RECVMSG, 0x0012_0334);
        assert_eq!(IOCTL_AFD_WINE_SENDMSG, 0x0012_0338);
        assert_eq!(IOCTL_AFD_WINE_OP_210, 0x0012_0348);
        assert_eq!(IOCTL_AFD_WINE_GET_PEER_NAME, 0x0012_0360);
        assert_eq!(IOCTL_AFD_WINE_GET_SOCKET_INFO, 0x0012_0368);
        assert_ne!(afd_control_code(200, METHOD_BUFFERED), IOCTL_AFD_WINE_CREATE);
        assert_ne!(ctl_code(0, METHOD_NEITHER), IOCTL_AFD_BIND);
        for c in [IOCTL_AFD_BIND, IOCTL_AFD_START_LISTEN, IOCTL_AFD_SELECT, IOCTL_AFD_GET_SOCK_NAME] {
            assert_eq!(c >> 12, FILE_DEVICE_NETWORK, "{c:#x}");
        }
        for c in [IOCTL_AFD_WINE_CREATE, IOCTL_AFD_WINE_CONNECT, IOCTL_AFD_WINE_SENDMSG] {
            assert_eq!(c >> 16, FILE_DEVICE_NETWORK, "{c:#x}");
        }
    }

    #[test]
    fn poll_bits_match_wsapoll_translation() {
        assert_eq!(AFD_POLL_READ | AFD_POLL_ACCEPT, 0x81);
        assert_eq!(AFD_POLL_ALWAYS, 0x118);
        assert_eq!(AFD_POLL_ALWAYS | AFD_POLL_READ | AFD_POLL_ACCEPT, 0x199);
    }
}
