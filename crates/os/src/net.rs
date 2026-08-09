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
