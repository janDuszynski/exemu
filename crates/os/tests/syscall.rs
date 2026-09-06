use exemu_core::{flags, Cpu, CpuState, Exit, Memory, Perm, Reg, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const TEB_SIZE: u64 = 0x2000;
const SYSCALL_INDEX: u32 = 0x0037;

const RBX_CANARY: u64 = 0xB16B_00B5_1234_5678;
const XMM6_CANARY: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
const ARG0: u64 = 0xDEAD_BEEF_0000_1111;
const STATUS: u32 = 0x4000_0001;

fn handler(_os: &mut WinOs, cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    assert_eq!(cpu.reg(Reg::R10), ARG0, "handler must see arg0 in R10");
    let rsp = cpu.rsp();
    assert!(
        !(STACK_TOP - 0x2000..STACK_TOP).contains(&rsp),
        "handler must run on the unix stack, not the guest stack (rsp={rsp:#x})"
    );
    cpu.set_reg(Reg::Rbx, 0xFFFF_FFFF_FFFF_FFFF);
    cpu.set_xmm_keep_upper(6, 0xDEAD);
    cpu.set_reg(Reg::Rdx, 0xCAFE_F00D);
    cpu.set_xmm_keep_upper(0, 0xBEEF);
    Ok(STATUS)
}

#[test]
fn syscall_dispatcher_full_roundtrip() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW))
        .unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();

    let mut asm = vec![0x49, 0x89, 0xCA];
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&SYSCALL_INDEX.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm.push(0xF4);
    mem.poke(CODE, &asm).unwrap();
    let syscall_ret = CODE + (asm.len() as u64 - 1);

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        ..WinConfig::default()
    });
    os.set_syscall_handler(SYSCALL_INDEX, handler);

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rcx, ARG0);
        s.set_reg(Reg::Rbx, RBX_CANARY);
        s.set_xmm_keep_upper(6, XMM6_CANARY);
        s.rflags |= flags::CF | flags::DF;
    }
    let rflags_before = cpu.state().rflags;

    loop {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit before hlt: {other:?}"),
        }
    }

    let s = cpu.state();
    assert_eq!(s.reg(Reg::Rax), STATUS as u64, "NTSTATUS must land in RAX");
    assert_eq!(s.reg(Reg::Rbx), RBX_CANARY, "RBX (non-volatile) must be restored");
    assert_eq!(s.xmm(6), XMM6_CANARY, "XMM6 (non-volatile) must be restored");
    assert_eq!(s.reg(Reg::Rdx), 0xCAFE_F00D, "RDX (volatile) passes through");
    assert_eq!(s.xmm(0), 0xBEEF, "XMM0 (volatile) passes through");
    assert_eq!(s.rip, syscall_ret, "guest must resume past the syscall (at the hlt)");
    assert_eq!(s.rsp(), STACK_TOP, "guest RSP must be restored");
    assert_eq!(s.rflags, rflags_before, "guest RFLAGS must be restored");
}
