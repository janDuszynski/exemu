use super::*;

pub const IOCTL_AFD_WINE_FIONBIO: u32 = ctl_code(209, METHOD_BUFFERED);

pub const IOCTL_AFD_WINE_GET_SO_ACCEPTCONN: u32 = ctl_code(219, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_BROADCAST: u32 = ctl_code(220, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_BROADCAST: u32 = ctl_code(221, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_ERROR: u32 = ctl_code(222, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_KEEPALIVE: u32 = ctl_code(223, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_KEEPALIVE: u32 = ctl_code(224, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_LINGER: u32 = ctl_code(225, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_LINGER: u32 = ctl_code(226, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_OOBINLINE: u32 = ctl_code(227, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_OOBINLINE: u32 = ctl_code(228, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_RCVBUF: u32 = ctl_code(229, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_RCVBUF: u32 = ctl_code(230, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_RCVTIMEO: u32 = ctl_code(231, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_RCVTIMEO: u32 = ctl_code(232, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_REUSEADDR: u32 = ctl_code(233, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_REUSEADDR: u32 = ctl_code(234, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_SNDBUF: u32 = ctl_code(235, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_SNDBUF: u32 = ctl_code(236, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_SO_SNDTIMEO: u32 = ctl_code(237, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_SO_SNDTIMEO: u32 = ctl_code(238, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_TCP_NODELAY: u32 = ctl_code(284, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_TCP_NODELAY: u32 = ctl_code(285, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_TCP_KEEPIDLE: u32 = ctl_code(299, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_TCP_KEEPIDLE: u32 = ctl_code(300, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_TCP_KEEPCNT: u32 = ctl_code(301, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_TCP_KEEPCNT: u32 = ctl_code(302, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_GET_TCP_KEEPINTVL: u32 = ctl_code(303, METHOD_BUFFERED);
pub const IOCTL_AFD_WINE_SET_TCP_KEEPINTVL: u32 = ctl_code(304, METHOD_BUFFERED);

const DEFAULT_SOCKET_BUFFER: u32 = 65536;
const DEFAULT_KEEPIDLE_SECS: u32 = 7200;
const DEFAULT_KEEPCNT: u32 = 10;
const DEFAULT_KEEPINTVL_SECS: u32 = 1;

const OPTION_VALUE_LEN: u64 = 4;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

struct SockOpt {
    set: u32,
    get: u32,
    default: u32,
}

const fn opt(set: u32, get: u32, default: u32) -> SockOpt {
    SockOpt { set, get, default }
}

const SOCK_OPTS: &[SockOpt] = &[
    opt(IOCTL_AFD_WINE_SET_SO_BROADCAST, IOCTL_AFD_WINE_GET_SO_BROADCAST, 0),
    opt(IOCTL_AFD_WINE_SET_SO_KEEPALIVE, IOCTL_AFD_WINE_GET_SO_KEEPALIVE, 0),
    opt(IOCTL_AFD_WINE_SET_SO_LINGER, IOCTL_AFD_WINE_GET_SO_LINGER, 0),
    opt(IOCTL_AFD_WINE_SET_SO_OOBINLINE, IOCTL_AFD_WINE_GET_SO_OOBINLINE, 0),
    opt(IOCTL_AFD_WINE_SET_SO_RCVBUF, IOCTL_AFD_WINE_GET_SO_RCVBUF, DEFAULT_SOCKET_BUFFER),
    opt(IOCTL_AFD_WINE_SET_SO_RCVTIMEO, IOCTL_AFD_WINE_GET_SO_RCVTIMEO, 0),
    opt(IOCTL_AFD_WINE_SET_SO_REUSEADDR, IOCTL_AFD_WINE_GET_SO_REUSEADDR, 0),
    opt(IOCTL_AFD_WINE_SET_SO_SNDBUF, IOCTL_AFD_WINE_GET_SO_SNDBUF, DEFAULT_SOCKET_BUFFER),
    opt(IOCTL_AFD_WINE_SET_SO_SNDTIMEO, IOCTL_AFD_WINE_GET_SO_SNDTIMEO, 0),
    opt(IOCTL_AFD_WINE_SET_TCP_NODELAY, IOCTL_AFD_WINE_GET_TCP_NODELAY, 0),
    opt(IOCTL_AFD_WINE_SET_TCP_KEEPIDLE, IOCTL_AFD_WINE_GET_TCP_KEEPIDLE, DEFAULT_KEEPIDLE_SECS),
    opt(IOCTL_AFD_WINE_SET_TCP_KEEPCNT, IOCTL_AFD_WINE_GET_TCP_KEEPCNT, DEFAULT_KEEPCNT),
    opt(IOCTL_AFD_WINE_SET_TCP_KEEPINTVL, IOCTL_AFD_WINE_GET_TCP_KEEPINTVL, DEFAULT_KEEPINTVL_SECS),
];

pub(super) fn is_option_ioctl(code: u32) -> bool {
    code == IOCTL_AFD_WINE_GET_SO_ACCEPTCONN
        || code == IOCTL_AFD_WINE_GET_SO_ERROR
        || SOCK_OPTS.iter().any(|o| o.set == code || o.get == code)
}

pub(super) fn tcp_nodelay_of(sock: &Socket) -> bool {
    sock.opts.get(&IOCTL_AFD_WINE_SET_TCP_NODELAY).copied().unwrap_or(0) != 0
}

impl WinOs {
    pub(super) fn afd_option(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.code == IOCTL_AFD_WINE_GET_SO_ACCEPTCONN {
            let sock = self.socket_mut(req.handle);
            let value = u32::from(sock.listening);
            return write_option(mem, req, value);
        }
        if req.code == IOCTL_AFD_WINE_GET_SO_ERROR {
            let sock = self.socket_mut(req.handle);
            let value = std::mem::take(&mut sock.pending_error);
            return write_option(mem, req, value);
        }
        let Some(spec) = SOCK_OPTS.iter().find(|o| o.set == req.code || o.get == req.code) else {
            return Ok(OpResult::Done(STATUS_NOT_IMPLEMENTED, 0));
        };
        if spec.get == req.code {
            let value = self.socket_mut(req.handle).opts.get(&spec.set).copied().unwrap_or(spec.default);
            return write_option(mem, req, value);
        }
        if req.in_len < OPTION_VALUE_LEN || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_BUFFER_TOO_SMALL, 0));
        }
        let value = mem.read_u32(req.in_buf)?;
        let sock = self.socket_mut(req.handle);
        sock.opts.insert(spec.set, value);
        if spec.set == IOCTL_AFD_WINE_SET_TCP_NODELAY {
            if let Endpoint::Stream(s) = &sock.ep {
                let _ = s.set_nodelay(value != 0);
            }
        }
        Ok(OK)
    }

    pub(super) fn afd_fionbio(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < OPTION_VALUE_LEN || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_BUFFER_TOO_SMALL, 0));
        }
        let enable = mem.read_u32(req.in_buf)? != 0;
        self.socket_mut(req.handle).nonblocking = enable;
        Ok(OK)
    }

    pub(super) fn socket_is_nonblocking(&self, handle: u64) -> bool {
        self.sockets.get(&handle).is_some_and(|s| s.nonblocking)
    }
}

fn write_option(mem: &mut dyn Memory, req: &Request, value: u32) -> Result<OpResult> {
    if req.out_len < OPTION_VALUE_LEN || req.out_buf == 0 {
        return Ok(OpResult::Done(STATUS_BUFFER_TOO_SMALL, 0));
    }
    mem.write_u32(req.out_buf, value)?;
    Ok(OpResult::Done(STATUS_SUCCESS, OPTION_VALUE_LEN))
}
