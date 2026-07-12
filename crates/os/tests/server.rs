//! W2.11 — the in-process wineserver equivalent, driven end-to-end through the
//! real interpreter: a guest thread creates an event through `wine_server_call`
//! (ntdll unixlib entry 3, reached via the `__wine_unix_call` fast-path thunk),
//! spawns a producer thread, then issues a blocking `select` on the event.
//!
//! De-risk (roadmap W2.11, "create+wait an event cross-thread"): the event
//! starts auto-reset/UNsignaled and only the producer sets it, so the consumer's
//! `select` completing with STATUS_SUCCESS *and* observing the producer's
//! sentinel proves a REAL block → switch → signal → resume handoff through
//! `block_and_switch` — a speculative WAIT_OBJECT_0-style return would read the
//! sentinel cell before the producer ever ran and fail the assertion. A final
//! zero-timeout `select` polls STATUS_TIMEOUT, proving the auto-reset event was
//! consumed by the satisfied wait.

use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const PROG: u64 = 0x0000_0000_0040_0000; // code + data cells + requests (RWX)
const MAIN: u64 = 0x0000_0000_0040_1000;
const WORKER: u64 = 0x0000_0000_0040_1800;
const HANDLE_CELL: u64 = 0x0000_0000_0040_3000; // event handle, main → worker
const FLAG: u64 = 0x0000_0000_0040_3008; // producer sentinel
const RESULT_STATUS: u64 = 0x0000_0000_0040_3010; // blocking select's RAX
const RESULT_FLAG: u64 = 0x0000_0000_0040_3018; // FLAG as seen after the wait
const RESULT_POLL: u64 = 0x0000_0000_0040_3020; // zero-timeout select's RAX
const CREATE_REQ: u64 = 0x0000_0000_0040_4000;
const SEL_REQ: u64 = 0x0000_0000_0040_5000; // infinite-timeout select
const SEL2_REQ: u64 = 0x0000_0000_0040_5800; // zero-timeout poll
const SEL_OP: u64 = 0x0000_0000_0040_6000; // shared select_op var-data
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const PEB: u64 = GS_BASE + 0x2000;

// The wine_server_call wire subset (exemu-internal tags + public
// __server_request_info layout — see crates/os/src/server.rs).
const REQ_CREATE_EVENT: u32 = 0x01;
const REQ_SELECT: u32 = 0x02;
const CREATE_REPLY_HANDLE: u64 = 8; // create_event_reply.handle
const REPLY_ERROR: u64 = 0; // reply_header.error
const SELECT_TIMEOUT: u64 = 28; // select_request.timeout (body base 12 + 16)
const DATA_COUNT: u64 = 0x40; // __server_request_info.data_count
const IOV_PTR: u64 = 0x50; // data[0].ptr
const IOV_SIZE: u64 = 0x58; // data[0].size
const SELECT_OP_HANDLES: u64 = 4; // select_op.handles[] (op @0 = SELECT_WAIT)
const TIMEOUT_INFINITE: u64 = 0x7fff_ffff_ffff_ffff;

const NTDLL_UNIXLIB_WINE_SERVER_CALL: u32 = 3;
const STATUS_SUCCESS: u64 = 0;
const STATUS_TIMEOUT: u64 = 0x102;

/// Tiny x86-64 emitter for the handful of forms the guest code needs.
struct Asm(Vec<u8>);
impl Asm {
    fn new() -> Self {
        Asm(Vec::new())
    }
    fn mov_rcx_imm(&mut self, v: u64) {
        self.0.extend([0x48, 0xB9]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_edx_imm(&mut self, v: u32) {
        self.0.push(0xBA);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_r8_imm(&mut self, v: u64) {
        self.0.extend([0x49, 0xB8]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_rax_imm(&mut self, v: u64) {
        self.0.extend([0x48, 0xB8]);
        self.0.extend(v.to_le_bytes());
    }
    fn call_rax(&mut self) {
        self.0.extend([0xFF, 0xD0]);
    }
    /// `mov r11, addr; mov rax, [r11]`
    fn load_rax_from(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x8B, 0x03]);
    }
    /// `mov r11, addr; mov [r11], rax`
    fn store_rax_to(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x89, 0x03]);
    }
    /// `__wine_unix_call(unixlib_handle, code=wine_server_call, req)` through
    /// the fast-path thunk; NTSTATUS lands in RAX.
    fn wine_server_call(&mut self, unixlib: u64, thunk: u64, req: u64) {
        self.mov_rcx_imm(unixlib);
        self.mov_edx_imm(NTDLL_UNIXLIB_WINE_SERVER_CALL);
        self.mov_r8_imm(req);
        self.mov_rax_imm(thunk);
        self.call_rax();
    }
}

#[test]
fn cross_thread_event_create_and_wait_through_wine_server_call() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", PROG, 0x8000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    let unixlib = os.register_ntdll_unixlib(0x7f00_0000);
    let unix_thunk = os.wine_unix_call_thunk();
    let create_thread = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    let set_event = os.resolve_import("kernel32.dll", &ImportSymbol::Named("SetEvent".into()));

    // --- the requests (auto-reset, UNsignaled event; select_op = wait-any) ---
    mem.write_u32(CREATE_REQ, REQ_CREATE_EVENT).unwrap();
    for (req, timeout) in [(SEL_REQ, TIMEOUT_INFINITE), (SEL2_REQ, 0)] {
        mem.write_u32(req, REQ_SELECT).unwrap();
        mem.write_u64(req + SELECT_TIMEOUT, timeout).unwrap();
        mem.write_u32(req + DATA_COUNT, 1).unwrap();
        mem.write_u64(req + IOV_PTR, SEL_OP).unwrap();
        mem.write_u32(req + IOV_SIZE, (SELECT_OP_HANDLES + 4) as u32).unwrap();
    }
    // SEL_OP.op = 0 (SELECT_WAIT) already; handles[0] is planted by the guest.

    // --- main (consumer): create event → spawn producer → blocking select ---
    let mut m = Asm::new();
    m.wine_server_call(unixlib, unix_thunk, CREATE_REQ);
    // Plant the reply handle where the worker and the select_op read it.
    m.load_rax_from(CREATE_REQ + CREATE_REPLY_HANDLE);
    m.store_rax_to(HANDLE_CELL);
    m.store_rax_to(SEL_OP + SELECT_OP_HANDLES);
    // CreateThread(NULL, 0, WORKER, NULL, 0, NULL) — win64 ABI, 2 stack args.
    m.0.extend([0x48, 0x83, 0xEC, 0x38]); // sub rsp, 0x38
    m.0.extend([0x31, 0xC9]); // xor ecx, ecx
    m.0.extend([0x31, 0xD2]); // xor edx, edx
    m.mov_r8_imm(WORKER);
    m.0.extend([0x45, 0x31, 0xC9]); // xor r9d, r9d
    m.0.extend([0x31, 0xC0]); // xor eax, eax
    m.0.extend([0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    m.0.extend([0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax
    m.mov_rax_imm(create_thread);
    m.call_rax();
    m.0.extend([0x48, 0x83, 0xC4, 0x38]); // add rsp, 0x38
    // The blocking wait: nothing has signaled the event yet, so this MUST
    // block and switch to the producer; it re-runs and completes only after
    // SetEvent. RAX and the observed FLAG are stored for the assertions.
    m.wine_server_call(unixlib, unix_thunk, SEL_REQ);
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    // Poll again with zero timeout: the auto-reset event was consumed by the
    // satisfied wait, so this reports STATUS_TIMEOUT without blocking.
    m.wine_server_call(unixlib, unix_thunk, SEL2_REQ);
    m.store_rax_to(RESULT_POLL);
    m.0.push(0xF4); // hlt
    mem.write(MAIN, &m.0).unwrap();

    // --- worker (producer): sentinel first, then SetEvent, then exit ---
    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_rax_from(HANDLE_CELL);
    w.0.extend([0x48, 0x89, 0xC1]); // mov rcx, rax
    w.mov_rax_imm(set_event);
    w.call_rax();
    w.0.extend([0x31, 0xC0]); // xor eax, eax
    w.0.push(0xC3); // ret → thread exit
    mem.write(WORKER, &w.0).unwrap();

    // --- run ---
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = MAIN;
        s.set_rsp(STACK_TOP - 0x100);
        s.gs_base = GS_BASE;
    }
    let mut halted = false;
    for _ in 0..200_000 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::Halted => {
                halted = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(halted, "the guest never reached its hlt — a wait hung or a thread was corrupted");

    // The producer really ran while the consumer was blocked: the consumer
    // resumed only after the sentinel was written (a speculative non-blocking
    // select would have read 0 here).
    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer resumed before the producer signaled");
    assert_eq!(mem.read_u64(RESULT_STATUS).unwrap(), STATUS_SUCCESS, "blocking select's NTSTATUS");
    assert_eq!(
        mem.read_u32(SEL_REQ + REPLY_ERROR).unwrap() as u64,
        STATUS_SUCCESS,
        "reply_header.error written on the satisfied re-run"
    );
    // The satisfied wait consumed the auto-reset event: a zero-timeout poll
    // now reports STATUS_TIMEOUT (and never blocks).
    assert_eq!(mem.read_u64(RESULT_POLL).unwrap(), STATUS_TIMEOUT, "auto-reset event was consumed by the wait");
}
