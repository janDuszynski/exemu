use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const REGION: u64 = 0x0040_0000;
const MAIN: u64 = 0x0040_1000;
const WORKER: u64 = 0x0040_1400;
const IAT_CREATE: u64 = 0x0040_2000;
const IAT_WFSO: u64 = 0x0040_2008;
const IAT_SET: u64 = 0x0040_2010;
const IAT_GET: u64 = 0x0040_2018;
const DATA: u64 = 0x0040_3000;
const HANDLE: u64 = DATA;
const WORKER_SET: u64 = DATA + 0x10;
const MAIN_READ: u64 = DATA + 0x14;
const WORKER_DONE: u64 = DATA + 0x18;
const MAIN_VIA_API: u64 = DATA + 0x20;
const MAIN_VIA_TEB: u64 = DATA + 0x24;
const WORKER_VIA_API: u64 = DATA + 0x28;
const WORKER_VIA_TEB: u64 = DATA + 0x2C;
const STACK_BASE: u64 = 0x0018_0000;
const STACK_TOP: u64 = 0x0037_FF00;
const MAIN_VALUE: u32 = 111;
const WORKER_VALUE: u32 = 222;
const TEB32_LAST_ERROR: u8 = 0x34;
const TEB64_LAST_ERROR: u8 = 0x68;
const MAX_STEPS: u64 = 5_000_000;

struct Asm {
    wide: bool,
    base: u64,
    code: Vec<u8>,
}

impl Asm {
    fn new(wide: bool, base: u64) -> Self {
        Asm { wide, base, code: Vec::new() }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn mem_op(&mut self, opcode: &[u8], target: u64, trailing: usize) {
        self.raw(opcode);
        let end = self.base + self.code.len() as u64 + 4 + trailing as u64;
        let disp = if self.wide { target.wrapping_sub(end) as u32 } else { target as u32 };
        self.raw(&disp.to_le_bytes());
    }

    fn call_iat(&mut self, slot: u64) {
        self.mem_op(&[0xFF, 0x15], slot, 0);
    }

    fn shadow(&mut self, sub: bool) {
        if self.wide {
            self.raw(if sub { &[0x48, 0x83, 0xEC, 0x38] } else { &[0x48, 0x83, 0xC4, 0x38] });
        }
    }

    fn set_last_error(&mut self, value: u32) {
        if self.wide {
            self.shadow(true);
            self.raw(&[0xB9]);
            self.raw(&value.to_le_bytes());
        } else {
            self.raw(&[0x68]);
            self.raw(&value.to_le_bytes());
        }
        self.call_iat(IAT_SET);
        self.shadow(false);
    }

    fn get_last_error_to(&mut self, dst: u64) {
        self.shadow(true);
        self.call_iat(IAT_GET);
        self.shadow(false);
        self.mem_op(&[0x89, 0x05], dst, 0);
    }

    fn teb_last_error_to(&mut self, dst: u64) {
        if self.wide {
            self.raw(&[0x65, 0x8B, 0x04, 0x25, TEB64_LAST_ERROR, 0, 0, 0]);
        } else {
            self.raw(&[0x64, 0xA1, TEB32_LAST_ERROR, 0, 0, 0]);
        }
        self.mem_op(&[0x89, 0x05], dst, 0);
    }

    fn store_flag(&mut self, flag: u64) {
        self.mem_op(&[0xC7, 0x05], flag, 4);
        self.raw(&1u32.to_le_bytes());
    }

    fn spin_until(&mut self, flag: u64) {
        self.mem_op(&[0x8B, 0x05], flag, 0);
        self.raw(&[0x85, 0xC0, 0x74, 0xF6]);
    }
}

fn main_code(wide: bool) -> Vec<u8> {
    let mut a = Asm::new(wide, MAIN);
    if wide {
        a.raw(&[0x48, 0x83, 0xEC, 0x38]);
        a.raw(&[0x31, 0xC9, 0x31, 0xD2, 0x41, 0xB8]);
        a.raw(&(WORKER as u32).to_le_bytes());
        a.raw(&[0x45, 0x31, 0xC9]);
        a.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
        a.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
        a.call_iat(IAT_CREATE);
        a.mem_op(&[0x48, 0x89, 0x05], HANDLE, 0);
        a.raw(&[0x48, 0x83, 0xC4, 0x38]);
    } else {
        for v in [0, 0, 0, WORKER as u32, 0, 0] {
            a.raw(&[0x68]);
            a.raw(&v.to_le_bytes());
        }
        a.call_iat(IAT_CREATE);
        a.mem_op(&[0xA3], HANDLE, 0);
    }
    a.set_last_error(MAIN_VALUE);
    a.spin_until(WORKER_SET);
    a.get_last_error_to(MAIN_VIA_API);
    a.teb_last_error_to(MAIN_VIA_TEB);
    a.store_flag(MAIN_READ);
    a.spin_until(WORKER_DONE);
    if wide {
        a.raw(&[0x48, 0x83, 0xEC, 0x28]);
        a.mem_op(&[0x48, 0x8B, 0x0D], HANDLE, 0);
        a.raw(&[0xBA, 0xFF, 0xFF, 0xFF, 0xFF]);
        a.call_iat(IAT_WFSO);
        a.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    } else {
        a.raw(&[0x68, 0xFF, 0xFF, 0xFF, 0xFF]);
        a.mem_op(&[0xFF, 0x35], HANDLE, 0);
        a.call_iat(IAT_WFSO);
        a.raw(&[0xC3]);
    }
    a.code
}

fn worker_code(wide: bool) -> Vec<u8> {
    let mut a = Asm::new(wide, WORKER);
    a.set_last_error(WORKER_VALUE);
    a.store_flag(WORKER_SET);
    a.spin_until(MAIN_READ);
    a.get_last_error_to(WORKER_VIA_API);
    a.teb_last_error_to(WORKER_VIA_TEB);
    a.store_flag(WORKER_DONE);
    if wide {
        a.raw(&[0x31, 0xC0, 0xC3]);
    } else {
        a.raw(&[0x31, 0xC0, 0xC2, 0x04, 0x00]);
    }
    a.code
}

fn run(wide: bool) -> [u32; 4] {
    let teb_base = if wide { GS_BASE } else { FS_BASE_32 };
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, 0x0020_0000, Perm::RW)).unwrap();
    mem.map(Region::new("main-teb", teb_base, 0x2000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: wide,
        teb_base,
        api_base: 0x7000_0000,
        heap_base: 0x1000_0000,
        heap_size: 0x0010_0000,
        valloc_base: 0x3000_0000,
        echo: false,
        ..WinConfig::default()
    });
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_TOP).unwrap();

    let slot = |os: &mut WinOs, name: &str| os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    let width = if wide { 8 } else { 4 };
    for (iat, name) in [(IAT_CREATE, "CreateThread"), (IAT_WFSO, "WaitForSingleObject"), (IAT_SET, "SetLastError"), (IAT_GET, "GetLastError")] {
        let thunk = slot(&mut os, name);
        if wide {
            mem.write_u64(iat, thunk).unwrap();
        } else {
            mem.write_u32(iat, thunk as u32).unwrap();
        }
    }
    let exit_thunk = os.exit_thunk();

    mem.write(MAIN, &main_code(wide)).unwrap();
    mem.write(WORKER, &worker_code(wide)).unwrap();
    assert!(MAIN + main_code(wide).len() as u64 <= WORKER);

    let mut cpu = Interpreter::with_bits(if wide { Bits::B64 } else { Bits::B32 });
    let ret_slot = STACK_TOP - width;
    if wide {
        mem.write_u64(ret_slot, exit_thunk).unwrap();
    } else {
        mem.write_u32(ret_slot, exit_thunk as u32).unwrap();
    }
    cpu.state_mut().set_rsp(ret_slot);
    cpu.state_mut().rip = MAIN;

    let mut exited = false;
    for _ in 0..MAX_STEPS {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(_) => {
                exited = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(exited, "process never exited");
    [
        mem.read_u32(MAIN_VIA_API).unwrap(),
        mem.read_u32(MAIN_VIA_TEB).unwrap(),
        mem.read_u32(WORKER_VIA_API).unwrap(),
        mem.read_u32(WORKER_VIA_TEB).unwrap(),
    ]
}

#[test]
fn each_32bit_thread_keeps_its_own_last_error_in_fs_0x34() {
    assert_eq!(run(false), [MAIN_VALUE, MAIN_VALUE, WORKER_VALUE, WORKER_VALUE]);
}

#[test]
fn each_64bit_thread_keeps_its_own_last_error_in_gs_0x68() {
    assert_eq!(run(true), [MAIN_VALUE, MAIN_VALUE, WORKER_VALUE, WORKER_VALUE]);
}
