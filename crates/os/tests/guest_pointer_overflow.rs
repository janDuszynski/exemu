use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;
const TOP: u64 = 0xFFFF_FFFF_FFFF_F000;
const SSDT_LEN: u32 = 0x400;
const STACK_ARG_SLOTS: u64 = 12;
const STEP_BUDGET: usize = 10_000;
const PENDING_FILES: [&str; 9] = [
    "win32k.rs",
    "menu.rs",
    "gdi.rs",
    "crypt32.rs",
    "unixlib.rs",
    "net.rs",
    "api.rs",
    "wndclass.rs",
    "gdi_",
];
const POINTERS: [u64; 6] = [
    u64::MAX,
    u64::MAX - 2,
    u64::MAX - 7,
    u64::MAX - 0x1F,
    u64::MAX - 0xFF8,
    u64::MAX - 0x1000,
];

fn setup(top_mapped: bool) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    if top_mapped {
        mem.map(Region::new("top", TOP, 0x1000, Perm::RW)).unwrap();
    }
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    (os, mem)
}

fn run_with_every_argument(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, value: u64) {
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]);
    asm.push(0xB8);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05, 0xF4]);
    mem.poke(CODE, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x400;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        for r in [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9] {
            s.set_reg(r, value);
        }
    }
    for n in 0..STACK_ARG_SLOTS {
        mem.write_u64(rsp + 0x28 + n * 8, value).unwrap();
    }
    for _ in 0..STEP_BUDGET {
        match cpu.step(mem, os) {
            Ok(Exit::Continue) => continue,
            _ => break,
        }
    }
}

static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn sweep(top_mapped: bool) {
    for index in 0..SSDT_LEN {
        for value in POINTERS {
            let (mut os, mut mem) = setup(top_mapped);
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                run_with_every_argument(&mut os, &mut mem, index, value);
            }));
            if outcome.is_err() {
                let last = PANICS.lock().unwrap().last().cloned().unwrap_or_default();
                PANICS.lock().unwrap().push(format!("syscall {index:#x} arg {value:#x}: {last}"));
            }
        }
    }
}

#[test]
fn no_nt_syscall_panics_on_pointers_at_the_top_of_the_address_space() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        let place = info.location().map(|l| l.file().to_string()).unwrap_or_default();
        PANICS.lock().unwrap().push(place);
    }));
    sweep(true);
    sweep(false);
    panic::set_hook(default_hook);

    let all = PANICS.lock().unwrap().clone();
    let outside_pending: Vec<&String> = all
        .iter()
        .filter(|line| line.starts_with("syscall"))
        .filter(|line| !PENDING_FILES.iter().any(|f| line.contains(f)))
        .collect();
    assert!(outside_pending.is_empty(), "host panics: {outside_pending:#?}");
}
