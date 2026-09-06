use exemu_core::{CpuState, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const RSP: u64 = 0x0000_0010_0000_1000;
const RETADDR: u64 = 0x0000_0001_4000_1000;
const MSGBUF: u64 = 0x0000_0000_5000_0000;

const WM_QUIT: u64 = 0x0012;
const WM_KEYDOWN: u64 = 0x0100;
const WM_CHAR: u64 = 0x0102;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("msg", MSGBUF, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem)
}

fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, args: &[u64]) -> u64 {
    let thunk = os.resolve_import("user32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        if i < 4 {
            cpu.set_reg(regs[i], a);
        } else {
            mem.write_u64(RSP + 0x28 + (i as u64 - 4) * 8, a).unwrap();
        }
    }
    cpu.rip = thunk;
    os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(cpu.rip, RETADDR, "{name} must ret");
    cpu.reg(Reg::Rax)
}

fn read_msg(mem: &VirtualMemory) -> (u64, u64, u64, u64) {
    (
        mem.read_u64(MSGBUF).unwrap(),
        mem.read_u32(MSGBUF + 8).unwrap() as u64,
        mem.read_u64(MSGBUF + 16).unwrap(),
        mem.read_u64(MSGBUF + 24).unwrap(),
    )
}

#[test]
fn post_then_get_roundtrip() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[0x1234, 0x0400, 7, 99]), 1);
    let r = call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[MSGBUF, 0, 0, 0]);
    assert_eq!(r, 1, "GetMessage returns TRUE for a normal message");
    assert_eq!(read_msg(&mem), (0x1234, 0x0400, 7, 99));
}

#[test]
fn fifo_order_preserved() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[1, 0x0400, 0, 0]);
    call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[2, 0x0400, 0, 0]);
    call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[MSGBUF, 0, 0, 0]);
    assert_eq!(read_msg(&mem).0, 1, "first posted is first delivered");
    call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[MSGBUF, 0, 0, 0]);
    assert_eq!(read_msg(&mem).0, 2);
}

#[test]
fn post_quit_delivers_wm_quit_and_returns_zero() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[9, 0x0400, 0, 0]);
    call(&mut os, &mut mem, &mut cpu, "PostQuitMessage", &[42]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[MSGBUF, 0, 0, 0]), 1);
    assert_eq!(read_msg(&mem).0, 9);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[MSGBUF, 0, 0, 0]), 0);
    let (_, message, wparam, _) = read_msg(&mem);
    assert_eq!(message, WM_QUIT);
    assert_eq!(wparam, 42, "WM_QUIT carries the exit code");
}

#[test]
fn peek_noremove_then_remove() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[5, 0x0400, 1, 2]);
    call(&mut os, &mut mem, &mut cpu, "PostMessageW", &[6, 0x0400, 0, 0]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "PeekMessageW", &[MSGBUF, 0, 0, 0, 0]), 1);
    assert_eq!(read_msg(&mem).0, 5);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "PeekMessageW", &[MSGBUF, 0, 0, 0, 0]), 1);
    assert_eq!(read_msg(&mem).0, 5, "PM_NOREMOVE does not consume");
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "PeekMessageW", &[MSGBUF, 0, 0, 0, 1]), 1);
    assert_eq!(read_msg(&mem).0, 5);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "PeekMessageW", &[MSGBUF, 0, 0, 0, 0]), 1);
    assert_eq!(read_msg(&mem).0, 6);
}

#[test]
fn translate_keydown_to_char() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    mem.write_u64(MSGBUF, 0).unwrap();
    mem.write_u32(MSGBUF + 8, WM_KEYDOWN as u32).unwrap();
    mem.write_u64(MSGBUF + 16, 0x41).unwrap();
    mem.write_u64(MSGBUF + 24, 0).unwrap();
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "TranslateMessage", &[MSGBUF]), 1, "keydown translates");
    let out = MSGBUF + 0x100;
    call(&mut os, &mut mem, &mut cpu, "GetMessageW", &[out, 0, 0, 0]);
    assert_eq!(mem.read_u32(out + 8).unwrap() as u64, WM_CHAR);
    assert_eq!(mem.read_u64(out + 16).unwrap(), 'a' as u64, "unshifted 'a'");
}
