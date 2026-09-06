use exemu_core::{Cpu, EmuError, Exit, ImportSymbol, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const NT_CREATE_EVENT: u32 = 0x48;
const NT_OPEN_EVENT: u32 = 0x40;
const NT_SET_EVENT: u32 = 0x0e;
const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x04;
const NT_WAIT_FOR_MULTIPLE_OBJECTS: u32 = 0x5b;
const NT_RELEASE_SEMAPHORE: u32 = 0x0a;
const NT_CREATE_MUTANT: u32 = 0x7e;
const NT_CREATE_SEMAPHORE: u32 = 0x83;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_WAIT_0: u64 = 0x0000_0000;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u64 = 0xC000_0047;

const NOTIFICATION_EVENT: u64 = 0;
const SYNCHRONIZATION_EVENT: u64 = 1;
const WAIT_ANY: u64 = 1;

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const PEB: u64 = GS_BASE + 0x2000;
const TEB_SIZE: u64 = 0x2000;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    (os, mem)
}

fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    try_syscall(os, mem, index, args).expect("syscall faulted")
}

fn try_syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> Result<u64> {
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x48, 0xB9]);
    asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]);
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm.push(0xF4);
    mem.poke(CODE, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE;
        let regs = [exemu_core::Reg::Rdx, exemu_core::Reg::R8, exemu_core::Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os)? {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    Ok(cpu.state().reg(exemu_core::Reg::Rax))
}

fn put_objattr(mem: &mut VirtualMemory, base: u64, name: &str) -> u64 {
    let objattr = base;
    let ustr = base + 0x40;
    let name_buf = base + 0x80;
    let units: Vec<u16> = name.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(name_buf + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(ustr, bytes).unwrap();
    mem.write_u16(ustr + 2, bytes).unwrap();
    mem.write_u64(ustr + 8, name_buf).unwrap();
    mem.write_u32(objattr, 0x30).unwrap();
    mem.write_u64(objattr + 8, 0).unwrap();
    mem.write_u64(objattr + 0x10, ustr).unwrap();
    objattr
}

#[test]
fn nt_semaphore_release_and_limit() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let prev = SCRATCH + 0x40;
    let zero_timeout = SCRATCH + 0x80;

    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_SEMAPHORE, &[h_out, 0, 0, 1, 2]), STATUS_SUCCESS);
    let sem = mem.read_u64(h_out).unwrap();
    assert_ne!(sem, 0);

    assert_eq!(syscall(&mut os, &mut mem, NT_RELEASE_SEMAPHORE, &[sem, 1, prev]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(prev).unwrap(), 1, "PreviousCount reported");

    mem.write_u32(prev, 0xDEAD).unwrap();
    assert_eq!(
        syscall(&mut os, &mut mem, NT_RELEASE_SEMAPHORE, &[sem, 1, prev]),
        STATUS_SEMAPHORE_LIMIT_EXCEEDED
    );
    assert_eq!(mem.read_u32(prev).unwrap(), 0xDEAD, "PreviousCount untouched on failure");

    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_WAIT_0);
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_WAIT_0);
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[sem, 0, zero_timeout]), STATUS_TIMEOUT);
}

#[test]
fn nt_create_mutant_initial_owner() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let zero_timeout = SCRATCH + 0x80;

    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_MUTANT, &[h_out, 0, 0, 1]), STATUS_SUCCESS);
    let owned = mem.read_u64(h_out).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[owned, 0, zero_timeout]), STATUS_WAIT_0);

    let h_out2 = SCRATCH + 0x8;
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_MUTANT, &[h_out2, 0, 0, 0]), STATUS_SUCCESS);
    let free = mem.read_u64(h_out2).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[free, 0, zero_timeout]), STATUS_WAIT_0);
}

#[test]
fn nt_zero_timeout_poll_times_out() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let zero_timeout = SCRATCH + 0x80;
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, 0, SYNCHRONIZATION_EVENT, 0]);
    let ev = mem.read_u64(h_out).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[ev, 0, zero_timeout]), STATUS_TIMEOUT);
}

#[test]
fn nt_open_event_by_name_and_win32_interop() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;

    let create_attr = put_objattr(&mut mem, SCRATCH + 0x100, "\\BaseNamedObjects\\Evt");
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, create_attr, NOTIFICATION_EVENT, 1]);
    let created = mem.read_u64(h_out).unwrap();
    assert_ne!(created, 0);

    let open_attr = put_objattr(&mut mem, SCRATCH + 0x300, "Evt");
    let h_out2 = SCRATCH + 0x8;
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_EVENT, &[h_out2, 0, open_attr]), STATUS_SUCCESS);
    assert_eq!(mem.read_u64(h_out2).unwrap(), created, "NtOpenEvent found the NtCreateEvent'd object");

    let miss_attr = put_objattr(&mut mem, SCRATCH + 0x500, "Nope");
    let h_out3 = SCRATCH + 0x10;
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_EVENT, &[h_out3, 0, miss_attr]), STATUS_OBJECT_NAME_NOT_FOUND);

    let name_w = SCRATCH + 0x700;
    for (i, u) in "Evt".encode_utf16().chain(std::iter::once(0)).enumerate() {
        mem.write_u16(name_w + (i as u64) * 2, u).unwrap();
    }
    let open_event_w = os.resolve_import("kernel32.dll", &ImportSymbol::Named("OpenEventW".into()));
    let win32 = call_win32_openevent(&mut os, &mut mem, open_event_w, name_w);
    assert_eq!(win32, created, "Win32 OpenEventW sees the NT-created named object");
}

fn call_win32_openevent(os: &mut WinOs, mem: &mut VirtualMemory, thunk: u64, name_w: u64) -> u64 {
    let mut a: Vec<u8> = Vec::new();
    a.extend_from_slice(&[0x48, 0xB9]);
    a.extend_from_slice(&0u64.to_le_bytes());
    a.extend_from_slice(&[0x48, 0xBA]);
    a.extend_from_slice(&0u64.to_le_bytes());
    a.extend_from_slice(&[0x49, 0xB8]);
    a.extend_from_slice(&name_w.to_le_bytes());
    a.extend_from_slice(&[0x48, 0xB8]);
    a.extend_from_slice(&thunk.to_le_bytes());
    a.extend_from_slice(&[0xFF, 0xD0]);
    a.push(0xF4);
    mem.poke(CODE, &a).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(STACK_TOP - 0x100);
        s.gs_base = GS_BASE;
    }
    loop {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(exemu_core::Reg::Rax)
}

#[test]
fn nt_bad_handle_is_invalid_handle() {
    let (mut os, mut mem) = setup();
    let bad = 0xDEAD_BEEF;
    assert_eq!(syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[bad, 0, 0]), STATUS_INVALID_HANDLE);
    assert_eq!(syscall(&mut os, &mut mem, NT_SET_EVENT, &[bad, 0]), STATUS_INVALID_HANDLE);
}

#[test]
fn nt_infinite_wait_single_thread_deadlocks() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    syscall(&mut os, &mut mem, NT_CREATE_EVENT, &[h_out, 0, 0, SYNCHRONIZATION_EVENT, 0]);
    let ev = mem.read_u64(h_out).unwrap();
    let err = try_syscall(&mut os, &mut mem, NT_WAIT_FOR_SINGLE_OBJECT, &[ev, 0, 0]).unwrap_err();
    match err.cause() {
        EmuError::Os(msg) => assert!(msg.contains("deadlock"), "fault names the deadlock: {msg}"),
        other => panic!("expected an Os deadlock fault, got {other:?}"),
    }
}

const PROG: u64 = 0x0000_0000_0040_0000;
const MAIN: u64 = 0x0000_0000_0040_1000;
const WORKER: u64 = 0x0000_0000_0040_1800;
const HANDLE_CELL: u64 = 0x0000_0000_0040_3000;
const FLAG: u64 = 0x0000_0000_0040_3008;
const RESULT_STATUS: u64 = 0x0000_0000_0040_3010;
const RESULT_FLAG: u64 = 0x0000_0000_0040_3018;
const RESULT_POLL: u64 = 0x0000_0000_0040_3020;
const OUT_HANDLE: u64 = 0x0000_0000_0040_3028;
const TIMEOUT0: u64 = 0x0000_0000_0040_3030;
const HANDLES: u64 = 0x0000_0000_0040_3040;

struct Asm(Vec<u8>);
impl Asm {
    fn new() -> Self {
        Asm(Vec::new())
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn mov_r10_imm(&mut self, v: u64) {
        self.0.extend([0x49, 0xBA]);
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
    fn mov_r9d_imm(&mut self, v: u32) {
        self.0.extend([0x41, 0xB9]);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_eax_imm(&mut self, v: u32) {
        self.0.push(0xB8);
        self.0.extend(v.to_le_bytes());
    }
    fn mov_rax_imm(&mut self, v: u64) {
        self.0.extend([0x48, 0xB8]);
        self.0.extend(v.to_le_bytes());
    }
    fn syscall(&mut self) {
        self.0.extend([0x0F, 0x05]);
    }
    fn call_rax(&mut self) {
        self.0.extend([0xFF, 0xD0]);
    }
    fn load_r10_from(&mut self, addr: u64) {
        self.0.extend([0x49, 0xBB]);
        self.0.extend(addr.to_le_bytes());
        self.0.extend([0x4D, 0x8B, 0x13]);
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
    fn create_thread(&mut self, thunk: u64, entry: u64) {
        self.raw(&[0x48, 0x83, 0xEC, 0x38]);
        self.raw(&[0x31, 0xC9]);
        self.raw(&[0x31, 0xD2]);
        self.mov_r8_imm(entry);
        self.raw(&[0x45, 0x31, 0xC9]);
        self.raw(&[0x31, 0xC0]);
        self.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]);
        self.raw(&[0x48, 0x89, 0x44, 0x24, 0x28]);
        self.mov_rax_imm(thunk);
        self.call_rax();
        self.raw(&[0x48, 0x83, 0xC4, 0x38]);
    }
}

fn cross_thread_env() -> (WinOs, VirtualMemory, u64) {
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
    let create_thread = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    (os, mem, create_thread)
}

fn run_to_halt(os: &mut WinOs, mem: &mut VirtualMemory) {
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = MAIN;
        s.set_rsp(STACK_TOP - 0x100);
        s.gs_base = GS_BASE;
    }
    let mut halted = false;
    for _ in 0..200_000 {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => {}
            Exit::Halted => {
                halted = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(halted, "the guest never reached its hlt — a wait hung or a thread was corrupted");
}

#[test]
fn nt_producer_consumer_event_cross_thread() {
    let (mut os, mut mem, create_thread) = cross_thread_env();

    let mut m = Asm::new();
    m.mov_r10_imm(OUT_HANDLE);
    m.mov_edx_imm(0);
    m.mov_r8_imm(0);
    m.mov_r9d_imm(SYNCHRONIZATION_EVENT as u32);
    m.mov_eax_imm(NT_CREATE_EVENT);
    m.syscall();
    m.load_rax_from(OUT_HANDLE);
    m.store_rax_to(HANDLE_CELL);
    m.create_thread(create_thread, WORKER);
    m.load_r10_from(HANDLE_CELL);
    m.mov_edx_imm(0);
    m.mov_r8_imm(0);
    m.mov_eax_imm(NT_WAIT_FOR_SINGLE_OBJECT);
    m.syscall();
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    m.load_r10_from(HANDLE_CELL);
    m.mov_edx_imm(0);
    m.mov_r8_imm(TIMEOUT0);
    m.mov_eax_imm(NT_WAIT_FOR_SINGLE_OBJECT);
    m.syscall();
    m.store_rax_to(RESULT_POLL);
    m.0.push(0xF4);
    mem.write(MAIN, &m.0).unwrap();

    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_r10_from(HANDLE_CELL);
    w.mov_edx_imm(0);
    w.mov_eax_imm(NT_SET_EVENT);
    w.syscall();
    w.0.extend([0x31, 0xC0]);
    w.0.push(0xC3);
    mem.write(WORKER, &w.0).unwrap();

    run_to_halt(&mut os, &mut mem);

    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer resumed only after the producer signaled");
    assert_eq!(mem.read_u64(RESULT_STATUS).unwrap(), STATUS_WAIT_0, "blocking wait returned STATUS_WAIT_0");
    assert_eq!(mem.read_u64(RESULT_POLL).unwrap(), STATUS_TIMEOUT, "auto-reset event consumed by the wait");
}

#[test]
fn nt_wait_for_multiple_wait_any_reports_index() {
    let (mut os, mut mem, create_thread) = cross_thread_env();
    let out0 = OUT_HANDLE;
    let out1 = OUT_HANDLE + 8;

    let mut m = Asm::new();
    for out in [out0, out1] {
        m.mov_r10_imm(out);
        m.mov_edx_imm(0);
        m.mov_r8_imm(0);
        m.mov_r9d_imm(SYNCHRONIZATION_EVENT as u32);
        m.mov_eax_imm(NT_CREATE_EVENT);
        m.syscall();
    }
    m.load_rax_from(out0);
    m.store_rax_to(HANDLES);
    m.load_rax_from(out1);
    m.store_rax_to(HANDLES + 8);
    m.store_rax_to(HANDLE_CELL);
    m.create_thread(create_thread, WORKER);
    m.mov_r10_imm(2);
    m.raw(&[0x48, 0xBA]);
    m.0.extend(HANDLES.to_le_bytes());
    m.mov_r8_imm(WAIT_ANY);
    m.mov_r9d_imm(0);
    m.mov_eax_imm(NT_WAIT_FOR_MULTIPLE_OBJECTS);
    m.syscall();
    m.store_rax_to(RESULT_STATUS);
    m.load_rax_from(FLAG);
    m.store_rax_to(RESULT_FLAG);
    m.0.push(0xF4);
    mem.write(MAIN, &m.0).unwrap();

    let mut w = Asm::new();
    w.mov_rax_imm(0x1234);
    w.store_rax_to(FLAG);
    w.load_r10_from(HANDLE_CELL);
    w.mov_edx_imm(0);
    w.mov_eax_imm(NT_SET_EVENT);
    w.syscall();
    w.0.extend([0x31, 0xC0]);
    w.0.push(0xC3);
    mem.write(WORKER, &w.0).unwrap();

    run_to_halt(&mut os, &mut mem);

    assert_eq!(mem.read_u64(RESULT_FLAG).unwrap(), 0x1234, "consumer really blocked until the producer ran");
    assert_eq!(
        mem.read_u64(RESULT_STATUS).unwrap(),
        STATUS_WAIT_0 + 1,
        "wait-any reports the satisfied handle's index (1)"
    );
}
