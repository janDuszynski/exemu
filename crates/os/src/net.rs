//! Sockets — the `\Device\Afd` NT surface Wine's `ws2_32.dll` issues, and the
//! host-socket backend behind it (roadmap W7.1).
//!
//! # The boundary, recovered — not assumed
//!
//! Every constant and structure offset in this module was **recovered by
//! disassembling the pinned Wine 11.0 binaries** in
//! `example_exe/wine-dlls/x86_64-windows/`, the same method that established the
//! WoW64, COM and win32k boundaries. `crates/app/tests/afd_abi.rs` re-derives
//! each one from those bytes on every run and asserts it against the constants
//! below, so a wrong guess here cannot survive a test run. No Wine source was
//! read (clean-room Class B); the NT signatures themselves are the public
//! `winternl.h` / `ntifs.h` ones.
//!
//! ## A socket is an NT file handle on `\Device\Afd`
//!
//! `ws2_32!WSASocketW` opens the AFD device and returns the resulting **NT file
//! handle** as the `SOCKET`:
//!
//! ```text
//! NtOpenFile(&handle,
//!            DesiredAccess = 0xC0100000,        // GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE
//!            &OBJECT_ATTRIBUTES{ Length = 0x30,
//!                                RootDirectory = NULL,
//!                                ObjectName = &UNICODE_STRING{ 0x16, 0x18, L"\Device\Afd" },
//!                                Attributes = OBJ_INHERIT unless WSA_FLAG_NO_HANDLE_INHERIT },
//!            &iosb,
//!            ShareAccess = 0,
//!            OpenOptions = FILE_SYNCHRONOUS_IO_NONALERT unless WSA_FLAG_OVERLAPPED)
//! ```
//!
//! `closesocket` is `kernel32!CloseHandle` → `NtClose`. There is no separate
//! socket namespace: the handle lives in the one handle space `NtClose` already
//! routes by lookup.
//!
//! ## Everything else is one syscall: `NtDeviceIoControlFile` (SSDT 0x07)
//!
//! ws2_32 imports exactly three `Nt*` entry points for socket work —
//! `NtOpenFile`, `NtClose` and `NtDeviceIoControlFile` — and drives *all* of
//! bind/listen/connect/accept/send/recv/select/shutdown/getsockname through the
//! last one. So the whole networking boundary is a single new SSDT slot plus an
//! IOCTL demultiplexer.
//!
//! The control codes come in **two different encodings**, and this is the detail
//! most likely to be assumed wrong. The operations Windows' own AFD defines keep
//! AFD's historical form, whose device type is shifted by **12**:
//!
//! ```text
//! _AFD_CONTROL_CODE(op, method) = (FILE_DEVICE_NETWORK=0x12) << 12 | op << 2 | method
//! ```
//!
//! while the operations Wine adds for itself (all numbered above 200) use the
//! ordinary `CTL_CODE`, shifted by **16**:
//!
//! ```text
//! CTL_CODE(dev, fn, method, access) = dev << 16 | access << 14 | fn << 2 | method
//! ```
//!
//! So the classic operations land in `0x0001_2xxx` and Wine's in `0x0012_0xxx`,
//! and neither formula produces the other block. Both are re-derived from the
//! binary by `crates/app/tests/afd_abi.rs`:
//!
//! | code | op | method | issued by | input | output |
//! | --- | --- | --- | --- | --- | --- |
//! | `0x00012003` | 0 | NEITHER | `bind` | `{u32 unknown; sockaddr}` | bound `sockaddr` |
//! | `0x0001200b` | 2 | NEITHER | `listen` | `{u32; i32 backlog; u32}` (12) | — |
//! | `0x00012024` | 9 | BUFFERED | `select`, `WSAPoll` | poll params | same buffer |
//! | `0x0001202f` | 11 | NEITHER | `getsockname` | — | `sockaddr` |
//! | `0x00012087` | 33 | NEITHER | `WSAEventSelect` | 16 bytes | — |
//! | `0x0001208b` | 34 | NEITHER | `WSAEnumNetworkEvents` | — | 0x38 bytes |
//! | `0x00120320` | 200 | BUFFERED | `WSASocketW` | `{i32 af; i32 type; i32 proto; u32 flags}` | — |
//! | `0x00120324` | 201 | BUFFERED | `accept` | — | `u32` accepted handle |
//! | `0x00120328` | 202 | BUFFERED | SPI dispatch only | 12 bytes | — |
//! | `0x0012032c` | 203 | BUFFERED | `connect` | `{i32 addr_len; i32 sync; sockaddr; data}` | — |
//! | `0x00120330` | 204 | BUFFERED | `shutdown` | `{i32 how}` | — |
//! | `0x00120334` | 205 | BUFFERED | `recv`/`recvfrom`/`WSARecv[From]` | [`RECVMSG_PARAMS_LEN`] | — |
//! | `0x00120338` | 206 | BUFFERED | `send`/`sendto`/`WSASend[To|Msg]` | [`SENDMSG_PARAMS_LEN`] | — |
//! | `0x0012033c` | 207 | BUFFERED | SPI dispatch only | 0x30 bytes | — |
//! | `0x00120348` | 210 | BUFFERED | the send core | `u32` (0) | — |
//! | `0x0012035c` | 215 | BUFFERED | `WSAAsyncSelect` | 16 bytes | — |
//! | `0x00120360` | 216 | BUFFERED | `getpeername` | — | `sockaddr` |
//! | `0x00120364` | 217 | BUFFERED | `WSAAccept` | `u32` | — |
//! | `0x00120368` | 218 | BUFFERED | `getsockopt`/`ioctlsocket`/… | — | `{i32 af; i32 type; i32 proto}` |
//!
//! ## Completion convention
//!
//! Each call passes an `IO_STATUS_BLOCK`; ws2_32 reads `Information` from it for
//! the transferred byte count on send/recv. When a call returns `STATUS_PENDING`
//! (0x103) ws2_32 waits on the manual-reset `Event` it passed (a per-thread event
//! cached at `TEB+0x1738 → [0]`). exemu never returns `STATUS_PENDING`: an
//! operation either completes or blocks for real inside the syscall, so the guest
//! sees a synchronous completion and the event path is never entered.
//!
//! ## Which NTSTATUS to fail with
//!
//! ws2_32 carries a 60-entry `NTSTATUS → WSA error` table (recovered at
//! `.rdata:0x1a0c0`) and, for a status that is not in it, sets `WSAEINVAL` when
//! the status is negative. Every failure below is therefore spelled with a status
//! the table actually maps, so a guest calling `WSAGetLastError` gets the Winsock
//! error the condition deserves instead of a Win32 code that leaked through.
//!
//! # Scope, and what is deliberately not here
//!
//! Only `AF_INET`/`AF_INET6` and only `SOCK_STREAM`/`SOCK_DGRAM`. A guest asking
//! for a raw socket, a Unix-domain socket or any other family is refused
//! (`STATUS_NOT_IMPLEMENTED` → `WSAEOPNOTSUPP`) rather than quietly given
//! something else — those are the families that would hand a guest reach beyond
//! ordinary networking (raw packets; host filesystem objects through `AF_UNIX`).
//! Address policy has one choke point, [`WinOs::afd_policy_check`], which is
//! where W9.5's sandbox confinement attaches when it lands.
//!
//! # Blocking is real
//!
//! Host sockets are held non-blocking, so every operation either completes or
//! reports "would block". On "would block" the handler does **not** fabricate a
//! result. It rewinds the `SYSCALL` exactly as `NtWaitForSingleObject` does
//! (design §5) and hands the CPU to another runnable guest thread; the whole
//! syscall re-executes, and re-polls, when that thread is scheduled again. If no
//! other guest thread can run — the single-threaded case — there is nothing to
//! switch to, but the *host* peer can still make progress on its own, so the
//! handler parks the emulator thread on the socket for real until the operation
//! completes or [`BLOCKING_WAIT_LIMIT`] elapses (then `STATUS_IO_TIMEOUT` →
//! `WSAETIMEDOUT`, an honest failure, never a fabricated success).

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use exemu_core::{CpuState, Memory, Result};

use crate::thread::WaitDesc;
use crate::WinOs;

/// SSDT index of `NtDeviceIoControlFile`, read out of the pinned guest
/// `ntdll.dll`'s own `mov r10,rcx; mov eax,N` stub — the same method used for
/// every other `Nt*` group in this crate.
pub const SSDT_NT_DEVICE_IO_CONTROL_FILE: u32 = 0x07;

/// The NT object name `ws2_32!WSASocketW` opens to make a socket.
pub const AFD_DEVICE_NAME: &str = "\\Device\\Afd";

/// `DesiredAccess` that same `NtOpenFile` asks for:
/// `GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE`.
pub const AFD_DESIRED_ACCESS: u32 = 0xC010_0000;

/// `FILE_DEVICE_NETWORK`, the device type in AFD's control codes.
pub const FILE_DEVICE_NETWORK: u32 = 0x12;

/// AFD's historical control-code encoding, used by the operations Windows' own
/// AFD defines. **Not** `CTL_CODE`: the device type is shifted by 12, not 16,
/// which is why these land in the `0x0001_2xxx` block.
pub const fn afd_control_code(op: u32, method: u32) -> u32 {
    (FILE_DEVICE_NETWORK << 12) | (op << 2) | method
}

/// The ordinary `CTL_CODE`, used by the operations Wine adds for itself (all
/// numbered above 200), which land in the `0x0012_0xxx` block. `FILE_ANY_ACCESS`
/// (0) throughout — no AFD code recovered from the binary sets the access bits.
pub const fn ctl_code(op: u32, method: u32) -> u32 {
    (FILE_DEVICE_NETWORK << 16) | (op << 2) | method
}

/// `METHOD_BUFFERED` / `METHOD_NEITHER` (public `devioctl.h`). AFD uses only
/// these two; the method does not change how exemu reads the buffers, because
/// the guest and the "driver" share one address space here.
pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_NEITHER: u32 = 3;

// ---- the control codes, by the operation numbers recovered above ------------

/// `bind` — input `{u32 unknown; struct sockaddr addr;}`, output the sockaddr
/// actually bound (which is how a `sin_port` of 0 is resolved to a real port).
pub const IOCTL_AFD_BIND: u32 = afd_control_code(0, METHOD_NEITHER);
/// `listen` — input `{u32 unknown1; i32 backlog; u32 unknown2;}` (12 bytes).
pub const IOCTL_AFD_START_LISTEN: u32 = afd_control_code(2, METHOD_NEITHER);
/// `select` / `WSAPoll` — the poll-params buffer is both input and output.
pub const IOCTL_AFD_SELECT: u32 = afd_control_code(9, METHOD_BUFFERED);
/// `getsockname` — no input; the local sockaddr is written to the output buffer.
pub const IOCTL_AFD_GET_SOCK_NAME: u32 = afd_control_code(11, METHOD_NEITHER);
/// `WSAEventSelect` — 16-byte input. Recovered; not serviced.
pub const IOCTL_AFD_EVENT_SELECT: u32 = afd_control_code(33, METHOD_NEITHER);
/// `WSAEnumNetworkEvents` — 0x38-byte output. Recovered; not serviced.
pub const IOCTL_AFD_ENUM_NETWORK_EVENTS: u32 = afd_control_code(34, METHOD_NEITHER);

/// `WSASocketW` — creates the socket behind an already-open `\Device\Afd`
/// handle. Input `{i32 family; i32 type; i32 protocol; u32 flags}`.
pub const IOCTL_AFD_WINE_CREATE: u32 = ctl_code(200, METHOD_BUFFERED);
/// `accept` — no input; a 4-byte output receives the accepted socket's handle.
pub const IOCTL_AFD_WINE_ACCEPT: u32 = ctl_code(201, METHOD_BUFFERED);
/// Op 202, 12-byte input. Reached only through the service-provider dispatch
/// table (no named export calls it directly). Recovered; not serviced.
pub const IOCTL_AFD_WINE_OP_202: u32 = ctl_code(202, METHOD_BUFFERED);
/// `connect` — input `{i32 addr_len; i32 synchronous; sockaddr addr; …data}`.
pub const IOCTL_AFD_WINE_CONNECT: u32 = ctl_code(203, METHOD_BUFFERED);
/// `shutdown` — input `{i32 how}` (`SD_RECEIVE`=0 / `SD_SEND`=1 / `SD_BOTH`=2).
pub const IOCTL_AFD_WINE_SHUTDOWN: u32 = ctl_code(204, METHOD_BUFFERED);
/// The receive core behind `recv`/`recvfrom`/`WSARecv`/`WSARecvFrom`.
pub const IOCTL_AFD_WINE_RECVMSG: u32 = ctl_code(205, METHOD_BUFFERED);
/// The send core behind `send`/`sendto`/`WSASend`/`WSASendTo`/`WSASendMsg`.
pub const IOCTL_AFD_WINE_SENDMSG: u32 = ctl_code(206, METHOD_BUFFERED);
/// Op 207, 0x30-byte input, SPI dispatch only. Recovered; not serviced.
pub const IOCTL_AFD_WINE_OP_207: u32 = ctl_code(207, METHOD_BUFFERED);
/// Op 210, 4-byte input carrying 0. The send core issues it **only** for a
/// handle that this `ws2_32` did not itself create (its own sockets are held in
/// a process-wide list), and treats a failure as `WSAENOTSOCK` — so its
/// observable contract is "is this handle a live AFD socket?". Named by its
/// operation number rather than a guessed meaning.
pub const IOCTL_AFD_WINE_OP_210: u32 = ctl_code(210, METHOD_BUFFERED);
/// `WSAAsyncSelect` — 16-byte input. Recovered; not serviced.
pub const IOCTL_AFD_WINE_ASYNC_SELECT: u32 = ctl_code(215, METHOD_BUFFERED);
/// `getpeername` — no input; the peer sockaddr goes to the output buffer.
pub const IOCTL_AFD_WINE_GET_PEER_NAME: u32 = ctl_code(216, METHOD_BUFFERED);
/// `WSAAccept` — 4-byte input. Recovered; not serviced.
pub const IOCTL_AFD_WINE_OP_217: u32 = ctl_code(217, METHOD_BUFFERED);
/// `getsockopt` / `ioctlsocket` / `WSAIoctl` / `WSADuplicateSocket` /
/// `WSAConnectByName` — a 12-byte output `{i32 family; i32 type; i32 protocol}`.
pub const IOCTL_AFD_WINE_GET_SOCKET_INFO: u32 = ctl_code(218, METHOD_BUFFERED);

// ---- request-structure shapes ----------------------------------------------

/// `IOCTL_AFD_WINE_CREATE` input: four `u32`s — family, type, protocol, flags.
pub const CREATE_PARAMS_LEN: u32 = 0x10;
/// `IOCTL_AFD_START_LISTEN` input: `{u32 unknown1; i32 backlog; u32 unknown2;}`.
pub const LISTEN_PARAMS_LEN: u32 = 0x0c;
/// Offset of `backlog` within that structure.
pub const LISTEN_BACKLOG_OFF: u64 = 4;
/// `IOCTL_AFD_WINE_ACCEPT` output: the accepted socket's handle as a `u32`.
pub const ACCEPT_OUT_LEN: u32 = 4;
/// `IOCTL_AFD_WINE_SHUTDOWN` input: a single `i32 how`.
pub const SHUTDOWN_PARAMS_LEN: u32 = 4;
/// `IOCTL_AFD_WINE_GET_SOCKET_INFO` output: three `i32`s.
pub const SOCKET_INFO_LEN: u32 = 0x0c;

/// `IOCTL_AFD_WINE_CONNECT` input header, ahead of the sockaddr:
/// `{i32 addr_len; i32 synchronous;}`.
pub const CONNECT_PARAMS_HEADER: u64 = 8;
/// `IOCTL_AFD_BIND` input header, ahead of the sockaddr: one `u32`.
pub const BIND_PARAMS_HEADER: u64 = 4;

/// `IOCTL_AFD_WINE_RECVMSG` input, 0x30 bytes:
/// ```text
/// +0x00 WSABUF *control
/// +0x08 struct sockaddr *addr
/// +0x10 int *addr_len
/// +0x18 unsigned int *ws_flags
/// +0x20 int force_async
/// +0x24 unsigned int count
/// +0x28 WSABUF *buffers
/// ```
pub const RECVMSG_PARAMS_LEN: u32 = 0x30;
pub const RECVMSG_ADDR_OFF: u64 = 0x08;
pub const RECVMSG_ADDR_LEN_OFF: u64 = 0x10;
pub const RECVMSG_WS_FLAGS_OFF: u64 = 0x18;
pub const RECVMSG_COUNT_OFF: u64 = 0x24;
pub const RECVMSG_BUFFERS_OFF: u64 = 0x28;

/// `IOCTL_AFD_WINE_SENDMSG` input, 0x20 bytes:
/// ```text
/// +0x00 const struct sockaddr *addr
/// +0x08 unsigned int addr_len
/// +0x0c unsigned int ws_flags
/// +0x10 int force_async
/// +0x14 unsigned int count
/// +0x18 const WSABUF *buffers
/// ```
pub const SENDMSG_PARAMS_LEN: u32 = 0x20;
pub const SENDMSG_ADDR_OFF: u64 = 0x00;
pub const SENDMSG_ADDR_LEN_OFF: u64 = 0x08;
pub const SENDMSG_COUNT_OFF: u64 = 0x14;
pub const SENDMSG_BUFFERS_OFF: u64 = 0x18;

/// A `WSABUF` is `{ULONG len; char *buf;}` — 16 bytes on x64 with padding.
pub const WSABUF_STRIDE: u64 = 0x10;
pub const WSABUF_PTR_OFF: u64 = 0x08;

/// `IOCTL_AFD_SELECT` input/output header:
/// `{LONGLONG timeout; unsigned int count; BOOLEAN exclusive;}`, then `count`
/// entries of `{HANDLE socket; int flags; NTSTATUS status;}`.
pub const POLL_PARAMS_HEADER: u64 = 0x10;
pub const POLL_PARAMS_COUNT_OFF: u64 = 0x08;
pub const POLL_ENTRY_STRIDE: u64 = 0x10;
pub const POLL_ENTRY_FLAGS_OFF: u64 = 0x08;
pub const POLL_ENTRY_STATUS_OFF: u64 = 0x0c;

/// The `AFD_POLL_*` request/result bits, recovered from `WSAPoll`'s translation
/// both ways: `POLLRDNORM` (0x0100) maps to `READ|ACCEPT` (0x81) and back via
/// `test cl,0x81`; `POLLRDBAND` (0x0200) ↔ 0x02; `POLLWRNORM` (0x0010) ↔ 0x04;
/// and `HUP|RESET|CONNECT_ERR` (0x118) is requested unconditionally, which is
/// exactly the set `WSAPoll` reports without being asked.
pub const AFD_POLL_READ: u32 = 0x0001;
pub const AFD_POLL_OOB: u32 = 0x0002;
pub const AFD_POLL_WRITE: u32 = 0x0004;
pub const AFD_POLL_HUP: u32 = 0x0008;
pub const AFD_POLL_RESET: u32 = 0x0010;
pub const AFD_POLL_CLOSE: u32 = 0x0020;
pub const AFD_POLL_CONNECT: u32 = 0x0040;
pub const AFD_POLL_ACCEPT: u32 = 0x0080;
pub const AFD_POLL_CONNECT_ERR: u32 = 0x0100;
/// The bits `WSAPoll` always asks for, whatever the caller requested.
pub const AFD_POLL_ALWAYS: u32 = AFD_POLL_HUP | AFD_POLL_RESET | AFD_POLL_CONNECT_ERR;

// ===========================================================================
// NTSTATUS palette
//
// Every value here is one the ws2_32 status→WSA table maps (see the module
// note), so the guest's `WSAGetLastError` is meaningful. The comment on each
// gives the Winsock error it becomes.
// ===========================================================================

const STATUS_SUCCESS: u32 = 0x0000_0000;
/// Returned when the handler blocked; discarded by the dispatcher (see
/// [`WinOs::afd_block`]). Never reaches the guest.
const STATUS_PENDING: u32 = 0x0000_0103;
/// → `WSAEOPNOTSUPP`. An operation exemu does not model.
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
/// → `WSAEFAULT`. A NULL/short buffer where one was required.
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// → `WSAENOTSOCK`. The handle names no live socket.
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// → `WSAEINVAL` (the table has no entry, and ws2_32 maps an unlisted negative
/// status to `WSAEINVAL` — which is the right answer for these cases anyway).
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// → `WSAEADDRINUSE`.
const STATUS_ADDRESS_ALREADY_EXISTS: u32 = 0xC000_020A;
/// → `WSAEADDRNOTAVAIL`.
const STATUS_INVALID_ADDRESS_COMPONENT: u32 = 0xC000_0207;
/// → `WSAECONNREFUSED`.
const STATUS_CONNECTION_REFUSED: u32 = 0xC000_0236;
/// → `WSAECONNRESET`.
const STATUS_CONNECTION_RESET: u32 = 0xC000_020D;
/// → `WSAECONNABORTED`.
const STATUS_CONNECTION_ABORTED: u32 = 0xC000_0241;
/// → `WSAEISCONN`.
const STATUS_CONNECTION_ACTIVE: u32 = 0xC000_023B;
/// → `WSAENOTCONN`.
const STATUS_INVALID_CONNECTION: u32 = 0xC000_0140;
/// → `WSAENETUNREACH`.
const STATUS_NETWORK_UNREACHABLE: u32 = 0xC000_023C;
/// → `WSAEHOSTUNREACH`.
const STATUS_HOST_UNREACHABLE: u32 = 0xC000_023D;
/// → `WSAETIMEDOUT`. Also what [`BLOCKING_WAIT_LIMIT`] surfaces as.
const STATUS_IO_TIMEOUT: u32 = 0xC000_00B5;
/// → `WSAESHUTDOWN`.
const STATUS_PIPE_DISCONNECTED: u32 = 0xC000_00B0;

// ---- Winsock address families / socket types (public winsock2.h) -----------

const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;

/// `sockaddr_in` — `{u16 family; u16 port(BE); u32 addr(BE); u8 zero[8]}`.
const SOCKADDR_IN_LEN: usize = 16;
/// `sockaddr_in6` — `{u16 family; u16 port(BE); u32 flowinfo(BE); u8 addr[16];
/// u32 scope_id}`.
const SOCKADDR_IN6_LEN: usize = 28;

/// `SD_RECEIVE` / `SD_SEND` / `SD_BOTH`, `shutdown`'s `how`.
const SD_RECEIVE: u32 = 0;
const SD_SEND: u32 = 1;

/// How long the single-threaded blocking path parks the emulator thread on a
/// socket before giving up with `STATUS_IO_TIMEOUT`.
///
/// A blocking Winsock recv has no timeout on Windows, so the faithful value is
/// "forever" — but a guest that waits forever for a peer that never speaks would
/// hang the emulator with no diagnosis, and exemu's house rule on the NT path is
/// that an unsatisfiable wait must surface, not hang (see `sync.rs`'s deadlock
/// fault). Twenty seconds is far longer than any loopback exchange and short
/// enough that a stuck guest is reported rather than endured.
pub const BLOCKING_WAIT_LIMIT: Duration = Duration::from_secs(20);

/// Poll slice while parked: tight for the first few iterations (a peer that is
/// about to write usually does so within microseconds), then relaxed so a long
/// wait costs no measurable CPU.
const FAST_SLICE: Duration = Duration::from_micros(100);
const SLOW_SLICE: Duration = Duration::from_millis(2);
const FAST_SPINS: u32 = 64;

/// Ceiling on the bytes one send/recv gathers out of a `WSABUF` array, so a
/// garbage length cannot make exemu allocate wildly. Well past any real socket
/// buffer.
const MAX_TRANSFER: u64 = 16 << 20;
/// Ceiling on the number of sockets one `IOCTL_AFD_SELECT` may name.
const MAX_POLL_ENTRIES: u32 = 4096;

// ===========================================================================
// Socket objects
// ===========================================================================

/// The host socket behind a guest `SOCKET`, if one exists yet.
///
/// `WSASocketW` creates the AFD handle *before* anything is known about how it
/// will be used, and `std::net` has no "socket, not yet bound or connected"
/// type — a `TcpListener` is already listening and a `TcpStream` already
/// connected. So the host object is created at the first operation that
/// determines which it must be, and [`Endpoint::Unbound`] is the state before
/// that. This is the one place the std-only backend shows through; see
/// [`WinOs::afd_connect`] for the single case where it is observable.
enum Endpoint {
    /// Created by `IOCTL_AFD_WINE_CREATE`; no host socket yet.
    Unbound,
    /// Bound (and, at the host level, already listening) TCP socket.
    Listener(TcpListener),
    /// Connected or accepted TCP socket.
    Stream(TcpStream),
    /// Bound UDP socket.
    Datagram(UdpSocket),
}

/// One guest socket.
pub(crate) struct Socket {
    family: i32,
    kind: i32,
    protocol: i32,
    ep: Endpoint,
    /// The address `IOCTL_AFD_BIND` asked for, as the guest asked for it (before
    /// the host resolved a zero port). Kept so `afd_connect` can tell an
    /// ephemeral bind — which it may discard — from a specific one, which it
    /// may not.
    requested_bind: Option<SocketAddr>,
    /// Whether the guest issued `IOCTL_AFD_START_LISTEN`.
    listening: bool,
    /// Connections a readiness probe accepted early; `IOCTL_AFD_WINE_ACCEPT`
    /// drains this before touching the listener. Without it, answering
    /// "is this listener readable?" would mean accepting and dropping a client.
    pending: VecDeque<TcpStream>,
    /// The peer a connected datagram socket sends to.
    peer: Option<SocketAddr>,
    /// `shutdown(SD_RECEIVE)` / `shutdown(SD_SEND)` seen.
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

/// What one attempt at an AFD operation produced.
enum OpResult {
    /// Finished: the NTSTATUS to return and the `IO_STATUS_BLOCK.Information`
    /// to publish (the transferred byte count, where the operation has one).
    Done(u32, u64),
    /// Nothing to report yet, and nothing was consumed — the caller blocks and
    /// retries. Never turned into a success.
    WouldBlock,
}

/// A completed operation that transferred nothing.
const OK: OpResult = OpResult::Done(STATUS_SUCCESS, 0);

/// Map a host I/O error onto the NTSTATUS whose Winsock translation matches.
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

/// `Done` from a host result, or `WouldBlock` when the host said so.
fn from_io<T>(r: std::io::Result<T>, ok: impl FnOnce(T) -> OpResult) -> OpResult {
    match r {
        Ok(v) => ok(v),
        Err(e) if e.kind() == ErrorKind::WouldBlock => OpResult::WouldBlock,
        Err(e) => OpResult::Done(status_for(&e), 0),
    }
}

// ---- sockaddr marshalling ---------------------------------------------------

/// Read a Winsock `sockaddr` out of guest memory. `len` is what the guest said
/// the buffer holds; a family that needs more than that is rejected rather than
/// read past.
fn read_sockaddr(mem: &dyn Memory, ptr: u64, len: u64) -> Result<Option<SocketAddr>> {
    if ptr == 0 || len < 2 {
        return Ok(None);
    }
    let family = mem.read_u16(ptr)? as i32;
    Ok(match family {
        AF_INET if len >= SOCKADDR_IN_LEN as u64 => {
            let port = mem.read_u16(ptr + 2)?.to_be(); // stored network-order
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

/// Serialise a `SocketAddr` in Winsock's on-the-wire layout.
fn sockaddr_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            out.extend_from_slice(&(AF_INET as u16).to_le_bytes());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&[0u8; 8]); // sin_zero
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

/// Write a `sockaddr` into a guest buffer of `cap` bytes. Returns the number of
/// bytes written, or `None` when the buffer cannot hold the address (which is
/// `WSAEFAULT` territory, not a truncation).
fn write_sockaddr(mem: &mut dyn Memory, ptr: u64, cap: u64, addr: &SocketAddr) -> Result<Option<u64>> {
    let bytes = sockaddr_bytes(addr);
    if ptr == 0 || cap < bytes.len() as u64 {
        return Ok(None);
    }
    mem.write(ptr, &bytes)?;
    Ok(Some(bytes.len() as u64))
}

/// `IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR
/// Information; }`.
fn write_iosb(mem: &mut dyn Memory, ptr: u64, status: u32, information: u64) -> Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    mem.write_u32(ptr, status)?;
    mem.write_u32(ptr + 4, 0)?;
    mem.write_u64(ptr + 8, information)?;
    Ok(())
}

// ---- WSABUF gather/scatter ---------------------------------------------------

/// One `WSABUF { ULONG len; char *buf; }` as the guest laid it out.
struct WsaBuf {
    ptr: u64,
    len: u64,
}

/// Read a `WSABUF` array. The total is clamped to [`MAX_TRANSFER`] so a garbage
/// count/length cannot drive an unbounded allocation.
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

/// Concatenate the bytes the guest wants to send.
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

/// Spread received bytes back across the guest's buffers.
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

// ===========================================================================
// The handlers
// ===========================================================================

impl WinOs {
    /// Whether `handle` names a live socket.
    pub(crate) fn is_socket_handle(&self, handle: u64) -> bool {
        self.sockets.contains_key(&handle)
    }

    /// `NtOpenFile` on `\Device\Afd`: mint the handle that will become a
    /// `SOCKET`. Returns `None` when `name` is some other object, so
    /// [`crate::fs`]'s filesystem path takes over unchanged.
    ///
    /// The socket has no family or type yet — `IOCTL_AFD_WINE_CREATE` supplies
    /// those on the very next call — and no host socket at all; see
    /// [`Endpoint`].
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
        // FILE_OPENED — the device was opened, not created.
        write_iosb(mem, iosb_ptr, STATUS_SUCCESS, 1)?;
        Ok(Some(STATUS_SUCCESS))
    }

    /// Drop a socket (and its host object). Called by `NtClose` through
    /// [`WinOs::close_handle`].
    pub(crate) fn close_socket(&mut self, handle: u64) -> bool {
        self.sockets.remove(&handle).is_some()
    }

    /// The single policy gate every host address passes through.
    ///
    /// Today it enforces only what the module claims: nothing beyond ordinary
    /// IPv4/IPv6 networking. When W9.5's sandbox confinement lands, an address
    /// policy attaches **here** and nowhere else — one function to change, one
    /// place to test.
    fn afd_policy_check(&self, addr: &SocketAddr) -> std::result::Result<(), u32> {
        match addr {
            SocketAddr::V4(_) | SocketAddr::V6(_) => Ok(()),
        }
    }

    /// `NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
    /// *IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
    /// OutputBuffer, OutputBufferLength)`.
    ///
    /// arg0=FileHandle, arg4=&IoStatusBlock, arg5=IoControlCode, arg6=InputBuffer,
    /// arg7=InputBufferLength, arg8=OutputBuffer, arg9=OutputBufferLength.
    ///
    /// A handle that is not a socket is *not* an error here — it is simply not
    /// ours; there is no other device control implemented, so those get
    /// `STATUS_NOT_IMPLEMENTED` (which Wine's callers tolerate, as the
    /// `NtFsControlFile` reparse probe already does).
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

    /// Block for real on an operation that cannot proceed (see the module note).
    ///
    /// First choice: rewind the `SYSCALL` and let another guest thread run — the
    /// same mechanism `NtWaitForSingleObject` uses, so the operation re-executes
    /// from scratch (and re-polls) when this thread is scheduled again, and
    /// nothing is consumed in the meantime. `WaitDesc` carries an empty handle
    /// set, whose wait-all reading is trivially satisfiable: this thread is
    /// runnable again immediately and simply takes its turn.
    ///
    /// Fallback, when nothing else can run: park the emulator thread on the
    /// socket. That is not a deadlock the way an unsignalled event would be —
    /// the peer is a host socket and can make progress with no guest thread
    /// running at all — so waiting is the correct behaviour, bounded by
    /// [`BLOCKING_WAIT_LIMIT`] so a peer that never speaks is reported rather
    /// than endured.
    fn afd_block(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        req: &Request,
        iosb: u64,
    ) -> Result<u32> {
        self.rewind_syscall(cpu);
        if self.block_and_switch(cpu, WaitDesc { handles: Vec::new(), all: true }) {
            // The dispatcher must not restore this thread's frame over the
            // switched-in thread, and it discards the status we return.
            self.syscall_resume_as_is = true;
            return Ok(STATUS_PENDING);
        }
        // Nobody else to run. The rewind above is undone by the dispatcher's
        // phase-4 restore, exactly as on `sync.rs`'s no-switch fallback.
        let deadline = Instant::now() + BLOCKING_WAIT_LIMIT;
        let mut spins = 0u32;
        loop {
            std::thread::sleep(if spins < FAST_SPINS { FAST_SLICE } else { SLOW_SLICE });
            spins = spins.saturating_add(1);
            if let OpResult::Done(status, info) = self.afd_dispatch(mem, req)? {
                write_iosb(mem, iosb, status, info)?;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                write_iosb(mem, iosb, STATUS_IO_TIMEOUT, 0)?;
                return Ok(STATUS_IO_TIMEOUT);
            }
        }
    }

    /// One attempt at an AFD operation. Pure with respect to blocking: it either
    /// finishes or reports [`OpResult::WouldBlock`] having consumed nothing, so
    /// [`WinOs::afd_block`] can call it again as often as it likes.
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
            // Recovered from the binary, and the send core's only use of it is
            // "is this a live AFD socket?" — which it is, or we would not be
            // here (the handle was looked up above).
            IOCTL_AFD_WINE_OP_210 => OK,
            _ => OpResult::Done(STATUS_NOT_IMPLEMENTED, 0),
        })
    }

    // ---- the individual operations ---------------------------------------

    /// `IOCTL_AFD_WINE_CREATE` — `{i32 family; i32 type; i32 protocol; u32 flags}`.
    /// Records what the guest asked for; the host socket is created by the first
    /// operation that decides its shape (see [`Endpoint`]).
    fn afd_create(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < CREATE_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let family = mem.read_u32(req.in_buf)? as i32;
        let kind = mem.read_u32(req.in_buf + 4)? as i32;
        let protocol = mem.read_u32(req.in_buf + 8)? as i32;
        // The scope gate: anything but ordinary IPv4/IPv6 stream/datagram is
        // refused outright rather than approximated.
        if !matches!(family, AF_INET | AF_INET6) || !matches!(kind, SOCK_STREAM | SOCK_DGRAM) {
            return Ok(OpResult::Done(STATUS_NOT_IMPLEMENTED, 0));
        }
        let sock = self.socket_mut(req.handle);
        sock.family = family;
        sock.kind = kind;
        sock.protocol = protocol;
        Ok(OK)
    }

    /// `IOCTL_AFD_BIND` — input `{u32 unknown; sockaddr}`, output the address
    /// actually bound (which is how a guest that asked for port 0 learns the
    /// port it got).
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
            // A TCP bind produces a listening host socket immediately: std has
            // no bound-but-not-listening type. `afd_connect` undoes it when the
            // guest turns out to have wanted a client socket.
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

    /// `IOCTL_AFD_START_LISTEN` — `{u32; i32 backlog; u32}`. The host socket is
    /// already listening (see [`WinOs::afd_bind`]); this records the guest's
    /// intent, which is what distinguishes a server socket from one that merely
    /// bound a local port. The backlog is read and not applied: `std`'s
    /// `TcpListener` fixes it at bind time, and no guest can observe the depth.
    fn afd_listen(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < LISTEN_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let _backlog = mem.read_u32(req.in_buf + LISTEN_BACKLOG_OFF)?;
        let sock = self.socket_mut(req.handle);
        if !matches!(sock.ep, Endpoint::Listener(_)) {
            // listen() before bind() — WSAEINVAL, exactly as Windows.
            return Ok(OpResult::Done(STATUS_INVALID_PARAMETER, 0));
        }
        sock.listening = true;
        Ok(OK)
    }

    /// `IOCTL_AFD_WINE_CONNECT` — `{i32 addr_len; i32 synchronous; sockaddr; …}`.
    ///
    /// The `Unbound → Stream` case is the ordinary one. The awkward case is a
    /// guest that bound *before* connecting: [`WinOs::afd_bind`] had to produce a
    /// listening host socket, which cannot be connected. When the bind asked for
    /// port 0 that is harmless — an ephemeral local port is what an unbound
    /// connect gets anyway — so the listener is discarded. When it asked for a
    /// *specific* local port the guest's request cannot be honoured, and this
    /// says so (`WSAEINVAL`) rather than silently connecting from a different
    /// port.
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
                sock.ep = Endpoint::Unbound; // drop the listener; reconnect below
            }
            (Endpoint::Datagram(d), _) => {
                // A connected datagram socket only records its default peer.
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

        // A blocking, bounded TCP connect. `std` cannot start a non-blocking
        // connect, so this one operation parks the emulator thread rather than
        // going through `afd_block`; a connect settles (or is refused) in one
        // round trip, which is why that is acceptable here and nowhere else.
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

    /// `IOCTL_AFD_WINE_ACCEPT` — no input; the accepted socket's handle comes
    /// back as a **4-byte value in the output buffer** (recovered, and asserted
    /// by `afd_abi.rs`; it is not a return value and not `IoStatusBlock`).
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
        // The output slot is 4 bytes wide; handles come from the same monotonic
        // counter as file handles (base 0x1000, step 4) and never approach 2^32.
        debug_assert!(child <= u64::from(u32::MAX));
        mem.write_u32(req.out_buf, child as u32)?;
        Ok(OpResult::Done(STATUS_SUCCESS, ACCEPT_OUT_LEN as u64))
    }

    /// `IOCTL_AFD_WINE_RECVMSG` — the receive core behind every `recv` family
    /// entry point. `IoStatusBlock.Information` carries the byte count, which is
    /// what ws2_32 hands back as the return value; zero means the peer closed.
    fn afd_recv(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < RECVMSG_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let p = req.in_buf;
        let count = mem.read_u32(p + RECVMSG_COUNT_OFF)?.min(MAX_POLL_ENTRIES);
        let buffers = mem.read_u64(p + RECVMSG_BUFFERS_OFF)?;
        let addr_ptr = mem.read_u64(p + RECVMSG_ADDR_OFF)?;
        let addr_len_ptr = mem.read_u64(p + RECVMSG_ADDR_LEN_OFF)?;
        let bufs = read_wsabufs(mem, buffers, count)?;
        let cap: u64 = bufs.iter().map(|b| b.len).sum();

        let sock = self.socket_mut(req.handle);
        if sock.rd_shutdown {
            return Ok(OK); // a shut-down receive side reads as end-of-stream
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
        // A zero-length request must not be read as end-of-stream.
        if n == 0 && cap != 0 && from.is_none() {
            // Genuine graceful close: report success with nothing transferred,
            // which is how `recv` returns 0.
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

    /// `IOCTL_AFD_WINE_SENDMSG` — the send core behind every `send` family entry
    /// point.
    fn afd_send(&mut self, mem: &mut dyn Memory, req: &Request) -> Result<OpResult> {
        if req.in_len < SENDMSG_PARAMS_LEN as u64 || req.in_buf == 0 {
            return Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0));
        }
        let p = req.in_buf;
        let count = mem.read_u32(p + SENDMSG_COUNT_OFF)?.min(MAX_POLL_ENTRIES);
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

    /// `IOCTL_AFD_WINE_SHUTDOWN` — `{i32 how}`.
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
                // Shutting down an already-dead connection is not an error the
                // guest can act on; it asked for the end state it already has.
                Err(e) if e.kind() == ErrorKind::NotConnected => OK,
                Err(e) => OpResult::Done(status_for(&e), 0),
            },
            Endpoint::Datagram(_) | Endpoint::Listener(_) => OK,
            Endpoint::Unbound => OpResult::Done(STATUS_INVALID_CONNECTION, 0),
        })
    }

    /// `IOCTL_AFD_GET_SOCK_NAME` / `IOCTL_AFD_WINE_GET_PEER_NAME` — the address
    /// goes to the output buffer, its length to `IoStatusBlock.Information`.
    fn afd_get_name(&mut self, mem: &mut dyn Memory, req: &Request, peer: bool) -> Result<OpResult> {
        let sock = self.socket_mut(req.handle);
        let addr = if peer { sock.peer_addr() } else { sock.local_addr() };
        let Some(addr) = addr else {
            // getsockname on an unbound socket / getpeername on an unconnected
            // one → WSAENOTCONN.
            return Ok(OpResult::Done(STATUS_INVALID_CONNECTION, 0));
        };
        match write_sockaddr(mem, req.out_buf, req.out_len, &addr)? {
            Some(n) => Ok(OpResult::Done(STATUS_SUCCESS, n)),
            None => Ok(OpResult::Done(STATUS_ACCESS_VIOLATION, 0)),
        }
    }

    /// `IOCTL_AFD_WINE_GET_SOCKET_INFO` — `{i32 family; i32 type; i32 protocol}`,
    /// which is how `getsockopt`/`ioctlsocket` recover what the socket is.
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

    /// `IOCTL_AFD_SELECT` — `select`/`WSAPoll`. The parameter block is rewritten
    /// in place with only the entries that are ready, and `count` updated;
    /// `WSAPoll` re-reads `count` from the buffer after the call and matches the
    /// surviving entries back to the caller's `pollfd`s by handle.
    ///
    /// A poll whose timeout expires with nothing ready reports **success with
    /// `count = 0`**, which is what `select` turns into "no descriptors ready".
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

        // Nothing yet: block unless the caller asked not to. A zero timeout is a
        // poll; anything else waits (the value is an NT relative time, and exemu
        // has no timed wakeups — see `sync.rs` — so the wait is bounded by the
        // blocking path's own limit rather than by the guest's number).
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

    /// The `AFD_POLL_*` bits that are true for `handle` right now.
    ///
    /// Readability on a stream is tested by peeking one byte, which consumes
    /// nothing. Readability on a *listener* cannot be tested without accepting,
    /// so the connection is accepted and parked in [`Socket::pending`] for the
    /// next `IOCTL_AFD_WINE_ACCEPT` — the client is never dropped. Writability
    /// on a connected stream is reported unconditionally: the honest test is
    /// whether the send buffer has room, `std` cannot ask that, and a guest that
    /// acts on it lands in [`WinOs::afd_send`], which blocks properly if it was
    /// wrong.
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

    /// The socket behind a handle the caller has already established is live
    /// (every path into these handlers checks first).
    fn socket_mut(&mut self, handle: u64) -> &mut Socket {
        self.sockets.get_mut(&handle).expect("the handle was checked to be a live socket")
    }
}

/// The arguments of one `NtDeviceIoControlFile`, carried together so
/// [`WinOs::afd_block`] can re-issue an attempt verbatim.
struct Request {
    handle: u64,
    code: u32,
    in_buf: u64,
    in_len: u64,
    out_buf: u64,
    out_len: u64,
}

/// The SSDT thunk.
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

    /// The two encodings, pinned as literals. The classic operations use AFD's
    /// 12-bit device shift and the Wine-added ones the ordinary `CTL_CODE`;
    /// applying either formula to the other block yields a *different, valid
    /// looking* code, which is exactly why both are spelled out here.
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
        // The two formulas are not interchangeable in either direction.
        assert_ne!(afd_control_code(200, METHOD_BUFFERED), IOCTL_AFD_WINE_CREATE);
        assert_ne!(ctl_code(0, METHOD_NEITHER), IOCTL_AFD_BIND);
        // Every classic code sits in the 0x0001_2xxx block, every Wine one in
        // 0x0012_0xxx — the cheap discriminator the dispatcher can rely on.
        for c in [IOCTL_AFD_BIND, IOCTL_AFD_START_LISTEN, IOCTL_AFD_SELECT, IOCTL_AFD_GET_SOCK_NAME] {
            assert_eq!(c >> 12, FILE_DEVICE_NETWORK, "{c:#x}");
        }
        for c in [IOCTL_AFD_WINE_CREATE, IOCTL_AFD_WINE_CONNECT, IOCTL_AFD_WINE_SENDMSG] {
            assert_eq!(c >> 16, FILE_DEVICE_NETWORK, "{c:#x}");
        }
    }

    /// The `AFD_POLL_*` bits must round-trip `WSAPoll`'s own mapping: the set it
    /// requests for `POLLRDNORM` is `READ|ACCEPT` = 0x81 and the set it always
    /// requests is 0x118 — both immediates appear verbatim in the binary.
    #[test]
    fn poll_bits_match_wsapoll_translation() {
        assert_eq!(AFD_POLL_READ | AFD_POLL_ACCEPT, 0x81);
        assert_eq!(AFD_POLL_ALWAYS, 0x118);
        assert_eq!(AFD_POLL_ALWAYS | AFD_POLL_READ | AFD_POLL_ACCEPT, 0x199);
    }
}
