use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const PROG: u64 = 0x0000_0000_0040_0000;
const MAIN: u64 = 0x0000_0000_0040_1000;
const WORKER: u64 = 0x0000_0000_0040_1800;
const HANDLE_CELL: u64 = 0x0000_0000_0040_3000;
const FLAG: u64 = 0x0000_0000_0040_3008;
const RESULT_STATUS: u64 = 0x0000_0000_0040_3010;
const RESULT_FLAG: u64 = 0x0000_0000_0040_3018;
const RESULT_POLL: u64 = 0x0000_0000_0040_3020;
const CREATE_REQ: u64 = 0x0000_0000_0040_4000;
const SEL_REQ: u64 = 0x0000_0000_0040_5000;
const SEL2_REQ: u64 = 0x0000_0000_0040_5800;
const SEL_OP: u64 = 0x0000_0000_0040_6000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const PEB: u64 = GS_BASE + 0x2000;

const REQ_CREATE_EVENT: u32 = 0x01;
const REQ_SELECT: u32 = 0x02;
const CREATE_REPLY_HANDLE: u64 = 8;
const REPLY_ERROR: u64 = 0;
const SELECT_TIMEOUT: u64 = 28;
const DATA_COUNT: u64 = 0x40;
const IOV_PTR: u64 = 0x50;
const IOV_SIZE: u64 = 0x58;
const SELECT_OP_HANDLES: u64 = 4;
const TIMEOUT_INFINITE: u64 = 0x7fff_ffff_ffff_ffff;

const NTDLL_UNIXLIB_WINE_SERVER_CALL: u32 = 3;
const STATUS_SUCCESS: u64 = 0;
const STATUS_TIMEOUT: u64 = 0x102;

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
    fn load_rax_from(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x8B, 0x03]);
    }
    fn store_rax_to(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x49, 0x89, 0x03]);
    }
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

    mem.write_u32(CREATE_REQ, REQ_CREATE_EVENT).unwrap();
    for (req, timeout) in [(SEL_REQ, TIMEOUT_INFINITE), (SEL2_REQ, 0)] {
        mem.write_u32(req, REQ_SELECT).unwrap();
        mem.write_u64(req + SELECT_TIMEOUT, timeout).unwrap();
        mem.write_u32(req + DATA_COUNT, 1).unwrap();
        mem.write_u64(req + IOV_PTR, SEL_OP).unwrap();
        mem.write_u32(req + IOV_SIZE, (SELECT_OP_HANDLES + 4) as u32).unwrap();
    }

    let mut m = Asm::new();
    m.wine_server_call(unixlib, unix_thunk, CREATE_REQ);
    m.load_rax_from(CREATE_REQ + CREATE_REPLY_HANDLE);
    m.store_rax_to(HANDLE_CELL);
    m.store_rax_to(SEL_OP + SELECT_OP_HANDLES);
    m.0.extend([0x48, 0x83, 0xEC, 0x38]);
    m.0.extend([0x31, 0xC9]);
    m.0.extend([0x31, 0xD2]);
    m.mov_r8_imm(WORKER);
    m.0.extend([0x45, 0x31, 0xC9]);
    m.0.extend([0x31, 0xC0]);
    m.0.extend([0x48, 0x89, 0x44, 0x24, 0x20]);
    m.0.extend([0x48, 0x89, 0x44, 0x24, 0x28]);
    m.mov_rax_imm(create_thread);
    m.call_rax();
    m.0.extend([0x48, 0x83, 0xC4, 0x38]);
    m.wine_server_call(unixlib, unix_thunk, SEL_REQ);
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    m.wine_server_call(unixlib, unix_thunk, SEL2_REQ);
    m.store_rax_to(RESULT_POLL);
    m.0.push(0xF4);
    mem.write(MAIN, &m.0).unwrap();

    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_rax_from(HANDLE_CELL);
    w.0.extend([0x48, 0x89, 0xC1]);
    w.mov_rax_imm(set_event);
    w.call_rax();
    w.0.extend([0x31, 0xC0]);
    w.0.push(0xC3);
    mem.write(WORKER, &w.0).unwrap();

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

    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer resumed before the producer signaled");
    assert_eq!(mem.read_u64(RESULT_STATUS).unwrap(), STATUS_SUCCESS, "blocking select's NTSTATUS");
    assert_eq!(
        mem.read_u32(SEL_REQ + REPLY_ERROR).unwrap() as u64,
        STATUS_SUCCESS,
        "reply_header.error written on the satisfied re-run"
    );
    assert_eq!(mem.read_u64(RESULT_POLL).unwrap(), STATUS_TIMEOUT, "auto-reset event was consumed by the wait");
}
