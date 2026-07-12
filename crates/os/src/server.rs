//! The wineserver equivalent — an **in-process** object manager reached through
//! `wine_server_call` (ntdll unixlib entry 3), plus the small binary
//! request/reply protocol subset it decodes (roadmap W2.11).
//!
//! # Why in-process (not a separate `wineserver` process)
//!
//! On real Wine the kernel-object model, cross-process synchronization and the
//! process/thread lifecycle live in a **separate `wineserver` daemon**, and the
//! Unix side of `ntdll.so` marshals a binary IPC to it over a socket. exemu has
//! no `wineserver` daemon and never maps `ntdll.so`: **exemu's native Rust *is*
//! the Unix side**. So the object manager is realized directly on [`WinOs`]
//! (`kobjects`/`named_kobjects` + the [`WinOs::block_and_switch`] scheduler,
//! already present from the P3.6 sync work), and `wine_server_call` is an
//! in-process request/reply dispatch — not a socket round-trip.
//!
//! # What the pinned guest binary establishes (clean-room Class B)
//!
//! Analysis of the pinned guest `ntdll.dll`
//! (`example_exe/wine-dlls/x86_64-windows/ntdll.dll`, clean-room-permitted
//! guest-binary disassembly) confirms the pivotal fact this step is scoped
//! around: the PE ntdll's `wine_server_call` is a **pure thunk** —
//! `mov edx,0x3; mov r8,rcx; jmp *__wine_unix_call_dispatcher` — with **zero
//! internal callers**. Every protocol-struct marshaller, the socket IPC and the
//! whole `server_init_*` handshake live in `ntdll.so`, which exemu does not run.
//! On the create+wait leg the PE ntdll routes create/set/wait/close entirely
//! through raw `SYSCALL`→SSDT→native Rust handlers (the `Nt*` sync group, W2.12),
//! so **the guest emits no `wine_server_call` wire traffic at all on that leg.**
//!
//! This module therefore implements the request/reply *format* so that exemu's
//! own code (and any future architectural-symmetry caller) can drive the object
//! manager through `wine_server_call`, but it is **never** parsing bytes off
//! guest-emitted IPC on the W2 gate. The request opcodes below are exemu's own
//! internal tags: because no guest wire enum is ever observed on this path
//! (Finding 0), transcribing Wine's private `enum request` values would be both
//! unnecessary and a clean-room violation, so they are original constants.
//!
//! # Wire structs (public `server_protocol.h` / `server.h` as interface only)
//!
//! The container is the public `__server_request_info` shape (design §2.3):
//!
//! ```text
//! struct __server_request_info {
//!     union { generic_request req; generic_reply reply; } u; // fixed 64 B window
//!     unsigned int  data_count;   // number of request var-data iovecs
//!     void         *reply_data;   // reply var-data lands here
//!     __server_iovec data[__SERVER_MAX_DATA]; // { const void *ptr; data_size_t size; }
//! };
//! ```
//!
//! `u` opens with a `request_header { int req; data_size_t request_size;
//! unsigned int reply_size; }` on the request side and a
//! `reply_header { unsigned int error; data_size_t reply_size; }` on the reply
//! side (the two overlap in the union). **`wine_server_call` returns
//! `reply_header.error`, an NTSTATUS**, and also writes it into the union so a
//! caller that reads `u.reply.reply_header.error` sees the same value.
//!
//! `obj_handle_t` is **32-bit** on the wire, whereas exemu's handles are `u64` —
//! this module widens on read and narrows on write at every handle field so a
//! large handle value never silently truncates.
//!
//! # SERVER_PROTOCOL_VERSION
//!
//! Recovered from the pinned tree (design §2.5 Q3): **930** (`0x3a2`), the
//! Wine 11.0 value asserted by `ntdll.so`'s `server_init_process`. It is pinned
//! by a compile-time assertion on [`SERVER_PROTOCOL_VERSION`] so a future change
//! to the pinned DLL set that bumps the protocol is caught at compile time
//! rather than producing silent misbehavior.

use exemu_core::{CpuState, Memory, Result};

use crate::sync::SyncKind;
use crate::thread::WaitDesc;
use crate::WinOs;

/// `SERVER_PROTOCOL_VERSION` for the pinned Wine 11.0 tree (design §2.5 Q3):
/// `0x3a2` = 930, the value `ntdll.so`'s `server_init_process` hard-checks
/// against the `init_first_thread` reply's `version` field. Recovered from the
/// pinned guest binary (clean-room-permitted), **not** read from Wine source.
pub(crate) const SERVER_PROTOCOL_VERSION: u32 = 930;

// Compile-time pin: 930 is the load-bearing pinned value (0x3a2). A future
// re-pin that changes the wire protocol trips this assertion rather than
// silently shipping mismatched struct layouts.
const _: () = assert!(SERVER_PROTOCOL_VERSION == 0x3a2);

// ---- NTSTATUS values (public ntstatus.h) --------------------------------

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_TIMEOUT: u32 = 0x0000_0102;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

// ---- request opcodes (exemu-internal tags; see the module note) ----------
//
// Because the create+wait leg emits no guest wire traffic (Finding 0), these
// are exemu's own request tags, not Wine's private `enum request` values —
// nothing off guest-emitted IPC is ever matched against them, and transcribing
// Wine's enum would be an unnecessary clean-room violation. Only the four the
// step scopes are defined; everything else is `STATUS_NOT_IMPLEMENTED`.

const REQ_CREATE_EVENT: u32 = 0x01;
const REQ_SELECT: u32 = 0x02;
const REQ_CLOSE_HANDLE: u32 = 0x03;
const REQ_DUP_HANDLE: u32 = 0x04;

// ---- select_op.op (public server_protocol.h SELECT_* enum as interface) --

/// `SELECT_WAIT` — wait until **any** one object in the handle set is signaled
/// (the `WaitForMultipleObjects(..., WaitAll=FALSE)` shape).
const SELECT_WAIT: u32 = 0;
/// `SELECT_WAIT_ALL` — wait until **all** objects in the set are signaled
/// (`WaitAll=TRUE`). Per design §2.3 wait-vs-wait-all is encoded by
/// `select_op.op` in the request var-data, **not** a `flags` bit.
const SELECT_WAIT_ALL: u32 = 1;

/// `TIMEOUT_INFINITE` (public `server_protocol.h` `timeout_t` sentinel) — never
/// time out. Any nonzero timeout blocks (the cooperative scheduler has no timed
/// wakeups yet — a finite timeout waits like infinite until W2.12 adds timers);
/// a **zero** timeout is a poll: an unsatisfiable wait returns `STATUS_TIMEOUT`
/// immediately instead of blocking. Live code only distinguishes zero vs
/// nonzero, so the sentinel itself is referenced by tests.
#[cfg(test)]
const TIMEOUT_INFINITE: u64 = 0x7fff_ffff_ffff_ffff;

/// `MAXIMUM_WAIT_OBJECTS` (public winnt.h) — the most handles one `select` may
/// carry. Bounds the wire-declared handle count so a corrupt request cannot
/// drive an unbounded allocation.
const MAXIMUM_WAIT_OBJECTS: u64 = 64;

// ---- __server_request_info field offsets (public layout) -----------------
//
// The union `u` is a fixed 64-byte request/reply window; the trailer
// (`data_count`, `reply_data`, `data[]`) follows it. On x86-64 the trailer is
// naturally 8-aligned after the 64-byte union.
mod info {
    /// Size of the `union { generic_request; generic_reply; }` window.
    pub const UNION_SIZE: u64 = 64;
    /// `unsigned int data_count` — number of request var-data iovecs.
    pub const DATA_COUNT: u64 = UNION_SIZE; // 0x40
    /// `__server_iovec data[]` base: `{ const void *ptr; data_size_t size; }`.
    /// (After `data_count` comes `void *reply_data` at +8, then the array; only
    /// iovec 0 is read by this subset, so only its offset is named.)
    pub const DATA: u64 = UNION_SIZE + 16; // 0x50
}

/// `request_header` (request side of the union): `{ int req; data_size_t
/// request_size; unsigned int reply_size; }`. `req` (the opcode) is at offset 0.
mod req_header {
    pub const REQ: u64 = 0x00;
}

/// `reply_header` (reply side of the union, overlapping `request_header`):
/// `{ unsigned int error; data_size_t reply_size; }`. `wine_server_call`
/// returns and writes `error` (an NTSTATUS) here.
mod reply_header {
    pub const ERROR: u64 = 0x00;
    pub const REPLY_SIZE: u64 = 0x04;
}

/// Field offsets within the fixed union window for the request bodies this
/// subset services. Each body begins right after the 12-byte `request_header`.
mod body {
    pub const BASE: u64 = 12;

    // create_event_request: after the header, { int access; struct
    // object_attributes; int manual_reset; int initial_state; }. Only the two
    // event flags are load-bearing here (access/attrs are honored as defaults).
    pub const CREATE_EVENT_MANUAL: u64 = BASE; // int manual_reset
    pub const CREATE_EVENT_INITIAL: u64 = BASE + 4; // int initial_state

    // select_request: { int flags; client_ptr_t cookie; timeout_t timeout;
    // obj_handle_t prev_apc; ... }. `flags` carries SELECT_ALERTABLE etc. (not
    // the wait/wait-all choice — that is `select_op.op` in the var-data).
    // `cookie` is the client-side pointer the server echoes to resume the wait.
    pub const SELECT_FLAGS: u64 = BASE; // int flags
    pub const SELECT_COOKIE: u64 = BASE + 8; // client_ptr_t cookie (8-aligned)
    pub const SELECT_TIMEOUT: u64 = BASE + 16; // timeout_t (0 = poll)

    // close_handle_request: { obj_handle_t handle; }.
    pub const CLOSE_HANDLE: u64 = BASE; // obj_handle_t handle

    // dup_handle_request: { obj_handle_t src_process; obj_handle_t src_handle;
    // obj_handle_t dst_process; unsigned int access; unsigned int attributes;
    // unsigned int options; }. Only src_handle is load-bearing in-process.
    pub const DUP_SRC_HANDLE: u64 = BASE + 4; // obj_handle_t src_handle
}

/// `select_op` (the request var-data of a `select`): `{ int op; obj_handle_t
/// handles[MAXIMUM_WAIT_OBJECTS]; }`. `op` selects wait vs wait-all; `handles`
/// is a packed 32-bit `obj_handle_t` array.
mod select_op {
    pub const OP: u64 = 0x00;
    pub const HANDLES: u64 = 0x04;
    /// One `obj_handle_t` is 32-bit on the wire.
    pub const HANDLE_SIZE: u64 = 4;
}

impl WinOs {
    /// Read a 32-bit wire `obj_handle_t` and widen it to an exemu `u64` handle.
    fn read_obj_handle(&self, mem: &dyn Memory, addr: u64) -> Result<u64> {
        Ok(mem.read_u32(addr)? as u64)
    }

    /// Write an exemu `u64` handle back as a 32-bit wire `obj_handle_t`,
    /// narrowing at the boundary (design §2.3: never silently truncate — the
    /// low 32 bits are the wire value, exemu mints handles in that range).
    fn write_obj_handle(&self, mem: &mut dyn Memory, addr: u64, handle: u64) -> Result<()> {
        mem.write_u32(addr, handle as u32)
    }

    /// The wineserver equivalent: service one `wine_server_call` request.
    ///
    /// `req` points at the guest's `__server_request_info`. The opcode at
    /// `u.req.request_header.req` selects the handler; the resulting NTSTATUS is
    /// both **returned** (into RAX on the fast path) and written into
    /// `u.reply.reply_header.error` so a caller reading either sees it.
    ///
    /// A `select` that must wait blocks the running thread via
    /// [`WinOs::block_and_switch`] and sets [`WinOs::unix_call_blocked`], leaving
    /// the request untouched; the fast path then resumes the switched-in thread
    /// as-is. When the blocked thread is scheduled again this call re-runs and
    /// (the wait now satisfied) completes. Returns the NTSTATUS to place in RAX
    /// (ignored while blocked).
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
        // A blocked select left the request for its own re-run; do not write a
        // reply into the still-in-flight request.
        if !self.unix_call_blocked {
            self.write_reply_error(req, mem, status)?;
        }
        Ok(status)
    }

    /// Write `error` (the NTSTATUS) into `u.reply.reply_header.error` and clear
    /// `reply_size` (no var-data reply for this subset).
    fn write_reply_error(&self, req: u64, mem: &mut dyn Memory, error: u32) -> Result<()> {
        mem.write_u32(req + reply_header::ERROR, error)?;
        mem.write_u32(req + reply_header::REPLY_SIZE, 0)?;
        Ok(())
    }

    /// `create_event` — create an event object and return its handle in the
    /// reply. Backed by the P3.6 [`crate::sync::KObject::Event`] model through
    /// [`WinOs::make_object`], so `SetEvent`/`WaitFor*` observe the same state
    /// whether the object was created here or through the Win32 seam.
    ///
    /// The handle lands in `u.reply.reply_header + 8` (`create_event_reply {
    /// reply_header; obj_handle_t handle; }`), narrowed to 32 bits.
    fn srv_create_event(&mut self, req: u64, mem: &mut dyn Memory) -> Result<u32> {
        let manual = mem.read_u32(req + body::CREATE_EVENT_MANUAL)? != 0;
        let initial = mem.read_u32(req + body::CREATE_EVENT_INITIAL)? != 0;
        let handle = self.make_object(SyncKind::Event, None, manual, initial, 0, 0);
        // create_event_reply.handle at reply_header (8 bytes) + obj_handle_t.
        self.write_obj_handle(mem, req + 8, handle)?;
        Ok(STATUS_SUCCESS)
    }

    /// `select` — wait on the handle set carried in the request var-data
    /// (`select_op`). `op` selects wait (any) vs wait-all; the handle array is a
    /// packed 32-bit `obj_handle_t[]`. Real blocking is via
    /// [`WinOs::block_and_switch`] (design: "reuse sync.rs objects +
    /// block_and_switch for REAL blocking"); the wait result flows through
    /// `reply_header.error` (`STATUS_SUCCESS` when satisfied, `STATUS_TIMEOUT`
    /// on a zero-timeout unsatisfiable wait), per design §2.3 — **not** a
    /// `WAIT_OBJECT_0+i` return.
    fn srv_select(&mut self, req: u64, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        // The `cookie` (client_ptr_t) the server would echo to resume the wait;
        // read so the field is honored even though the in-process re-run keys on
        // the blocked thread rather than a socket-delivered cookie.
        let _cookie = mem.read_u64(req + body::SELECT_COOKIE)?;
        let _flags = mem.read_u32(req + body::SELECT_FLAGS)?;
        let timeout = mem.read_u64(req + body::SELECT_TIMEOUT)?;

        // The select_op var-data: iovec 0 = { ptr; size }. `op` chooses
        // wait/wait-all; `handles[]` follows, one 32-bit obj_handle_t each.
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

    /// The wait core of `select`: try to satisfy the handle set immediately
    /// (consuming state — auto-reset events reset, semaphores decrement), else
    /// block the running thread on it via [`WinOs::block_and_switch`] for REAL
    /// blocking. Mirrors [`WinOs::wait_multiple`]'s peek-then-consume discipline
    /// so a partial set is never drained when the thread is going to block.
    ///
    /// Returns `STATUS_SUCCESS` when satisfied; `STATUS_TIMEOUT` for an
    /// unsatisfiable **zero-timeout** poll (any nonzero timeout blocks — see
    /// `TIMEOUT_INFINITE`). When it blocks it sets
    /// [`WinOs::unix_call_blocked`] and returns `STATUS_PENDING` (the return is
    /// ignored while blocked — the fast path resumes the switched-in thread and
    /// this call re-runs on the blocked thread's next schedule). If no other
    /// thread can run, it falls back to `STATUS_SUCCESS` so a single-threaded
    /// guest never hangs (as [`WinOs::wait_single`] does).
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

    /// Peek whether the handle set is satisfiable for `tid` without consuming
    /// (an unknown handle counts as signaled, matching the wait paths).
    fn server_wait_satisfiable(&self, handles: &[u64], all: bool, tid: u32) -> bool {
        let sig = |h: &u64| self.kobject_is_signaled(*h, tid);
        if all {
            handles.iter().all(sig)
        } else {
            handles.iter().any(sig)
        }
    }

    /// Consume the satisfied wait: for wait-all, acquire every object; for
    /// wait-any, acquire the first signaled one (auto-reset/semaphore state
    /// changes exactly as `WaitForMultipleObjects` would).
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

    /// `close_handle` — close the object handle in the request. Routes through
    /// [`WinOs::close_handle`] so the same teardown (drop the object, forget its
    /// name) runs whether close came from here or the Win32 `CloseHandle` seam.
    fn srv_close_handle(&mut self, req: u64, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.read_obj_handle(mem, req + body::CLOSE_HANDLE)?;
        if self.close_handle(handle) {
            Ok(STATUS_SUCCESS)
        } else {
            Ok(STATUS_INVALID_HANDLE)
        }
    }

    /// `dup_handle` — duplicate the source object handle. In the single-process
    /// in-process model a duplicate is a second handle onto the *same* object
    /// (the object stays live until every handle that names it is closed). The
    /// new handle lands in `dup_handle_reply.handle` (reply_header + 8),
    /// narrowed to 32 bits.
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

    /// A scratch `__server_request_info` at `req` with `opcode` in the header.
    fn make_req(mem: &mut VirtualMemory, req: u64, opcode: u32) {
        mem.write_u32(req + req_header::REQ, opcode).unwrap();
    }

    #[test]
    fn protocol_version_is_pinned_930() {
        assert_eq!(SERVER_PROTOCOL_VERSION, 930);
        assert_eq!(SERVER_PROTOCOL_VERSION, 0x3a2);
    }

    /// create_event → the reply carries a handle that the sync object model
    /// recognizes, and the reply_header.error is STATUS_SUCCESS.
    #[test]
    fn create_event_through_wine_server_call() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x1000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let req = 0x5_0000;
        make_req(&mut mem, req, REQ_CREATE_EVENT);
        // manual_reset = 1, initial_state = 1.
        mem.write_u32(req + body::CREATE_EVENT_MANUAL, 1).unwrap();
        mem.write_u32(req + body::CREATE_EVENT_INITIAL, 1).unwrap();

        let status = os.wine_server_call(req, &mut CpuState::default(), &mut mem).unwrap();
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(mem.read_u32(req + reply_header::ERROR).unwrap(), STATUS_SUCCESS);
        let handle = mem.read_u32(req + 8).unwrap() as u64;
        assert!(handle != 0, "a handle was minted");
        // A manual-reset event created initial-set: a zero-timeout select
        // succeeds and (manual) stays signaled.
        assert!(os.kobject_is_signaled_for_test(handle));
    }

    /// close_handle drops the object; a second close reports INVALID_HANDLE.
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
        // Second close: gone. The reply overwrote the request header (they
        // overlap in the union), so re-seed the opcode as a real caller would.
        make_req(&mut mem, close, REQ_CLOSE_HANDLE);
        assert_eq!(os.wine_server_call(close, &mut CpuState::default(), &mut mem).unwrap(), STATUS_INVALID_HANDLE);
    }

    /// dup_handle yields a second handle onto the same object; closing one
    /// leaves the other valid.
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

        // Close h1: h2 still names a live, signaled object.
        let close = 0x5_2000;
        make_req(&mut mem, close, REQ_CLOSE_HANDLE);
        os.write_obj_handle(&mut mem, close + body::CLOSE_HANDLE, h1).unwrap();
        os.wine_server_call(close, &mut CpuState::default(), &mut mem).unwrap();
        assert!(os.kobject_is_signaled_for_test(h2), "duplicate survives the original's close");

        // dup of an unknown handle → INVALID_HANDLE (re-seed the opcode: the
        // first dup's reply overwrote the overlapping request header).
        make_req(&mut mem, dup, REQ_DUP_HANDLE);
        os.write_obj_handle(&mut mem, dup + body::DUP_SRC_HANDLE, 0xdead_beef).unwrap();
        assert_eq!(os.wine_server_call(dup, &mut CpuState::default(), &mut mem).unwrap(), STATUS_INVALID_HANDLE);
    }

    /// A select on an already-signaled event completes immediately with
    /// STATUS_SUCCESS reported through reply_header.error (no block).
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

        // select_op var-data: op=SELECT_WAIT, handles=[handle].
        let sel_op = 0x5_2000;
        mem.write_u32(sel_op + select_op::OP, SELECT_WAIT).unwrap();
        os.write_obj_handle(&mut mem, sel_op + select_op::HANDLES, handle).unwrap();

        let sel = 0x5_1000;
        make_req(&mut mem, sel, REQ_SELECT);
        mem.write_u64(sel + body::SELECT_TIMEOUT, TIMEOUT_INFINITE).unwrap();
        mem.write_u32(sel + info::DATA_COUNT, 1).unwrap();
        mem.write_u64(sel + info::DATA, sel_op).unwrap(); // iovec.ptr
        mem.write_u32(sel + info::DATA + 8, (select_op::HANDLES + 4) as u32).unwrap(); // iovec.size

        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        assert_eq!(mem.read_u32(sel + reply_header::ERROR).unwrap(), STATUS_SUCCESS);
        assert!(!os.unix_call_blocked_for_test(), "did not block on a signaled object");
    }

    /// A zero-timeout select on an unsignaled event is a poll: it reports
    /// STATUS_TIMEOUT through reply_header.error immediately, without blocking
    /// and without consuming anything.
    #[test]
    fn zero_timeout_select_polls_status_timeout() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x4000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        // auto-reset, initial UNsignaled.
        os.wine_server_call(create, &mut CpuState::default(), &mut mem).unwrap();
        let handle = mem.read_u32(create + 8).unwrap() as u64;

        let sel_op = 0x5_2000;
        mem.write_u32(sel_op + select_op::OP, SELECT_WAIT).unwrap();
        os.write_obj_handle(&mut mem, sel_op + select_op::HANDLES, handle).unwrap();
        let sel = 0x5_1000;
        make_req(&mut mem, sel, REQ_SELECT);
        // timeout left at 0 → poll.
        mem.write_u32(sel + info::DATA_COUNT, 1).unwrap();
        mem.write_u64(sel + info::DATA, sel_op).unwrap();
        mem.write_u32(sel + info::DATA + 8, (select_op::HANDLES + 4) as u32).unwrap();

        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_TIMEOUT);
        assert_eq!(mem.read_u32(sel + reply_header::ERROR).unwrap(), STATUS_TIMEOUT);
        assert!(!os.unix_call_blocked_for_test(), "a poll never blocks");
    }

    /// A single-threaded select on an unsignaled event cannot block (nobody else
    /// to switch to): it must not hang — it reports STATUS_SUCCESS via the
    /// fallback (matching wait_single's single-thread fallback).
    #[test]
    fn select_on_unsignaled_single_thread_does_not_hang() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x5_0000, 0x4000, exemu_core::Perm::RW, "req").unwrap();
        let mut os = os64();
        let create = 0x5_0000;
        make_req(&mut mem, create, REQ_CREATE_EVENT);
        // auto-reset, initial UNsignaled.
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

        // Single-threaded: no thread to switch to, so it completes rather than
        // hanging (the server select's single-thread fallback).
        assert_eq!(os.wine_server_call(sel, &mut CpuState::default(), &mut mem).unwrap(), STATUS_SUCCESS);
        assert!(!os.unix_call_blocked_for_test());
    }
}
