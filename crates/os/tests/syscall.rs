//! The NT-syscall dispatcher round-trip (roadmap W2.3), driven end-to-end
//! through the real interpreter exactly as a Wine PE `Nt*` stub would.
//!
//! A Wine native-x64 `Nt*` stub is `mov r10,rcx; mov eax,N; syscall; ret`. We
//! assemble that (ending in `hlt` so the test terminates cleanly), point an
//! SSDT slot at a handler that mutates registers, run the CPU, and assert:
//!
//!   * the handler saw the syscall's argument (arg0 in R10);
//!   * its NTSTATUS is in RAX on return;
//!   * a **non-volatile** register the handler clobbered (RBX, XMM6) is
//!     restored to the guest's pre-syscall value;
//!   * a **volatile** register the handler wrote (RDX, XMM0) passes through;
//!   * the guest resumes at the instruction after `syscall` (the saved RCX);
//!   * the guest's RFLAGS (incl. DF) is restored wholesale.

use exemu_core::{flags, Cpu, CpuState, Exit, Memory, Perm, Reg, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const TEB_SIZE: u64 = 0x2000;
const SYSCALL_INDEX: u32 = 0x0037;

// Canary values the handler must not be able to corrupt in the guest's view.
const RBX_CANARY: u64 = 0xB16B_00B5_1234_5678; // non-volatile → must survive
const XMM6_CANARY: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10; // non-volatile
const ARG0: u64 = 0xDEAD_BEEF_0000_1111; // passed in RCX → moved to R10 by stub
const STATUS: u32 = 0x4000_0001; // handler's NTSTATUS (an informational code)

/// The handler: proves args arrive, returns a status, and clobbers both a
/// non-volatile set (RBX, XMM6 — the dispatcher must restore these) and a
/// volatile set (RDX, XMM0 — these must survive to the guest).
fn handler(_os: &mut WinOs, cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    // arg0 is in R10 (the stub did `mov r10,rcx`).
    assert_eq!(cpu.reg(Reg::R10), ARG0, "handler must see arg0 in R10");
    // Phase 2: we run on the switched unix stack, not the guest stack.
    let rsp = cpu.rsp();
    assert!(
        !(STACK_TOP - 0x2000..STACK_TOP).contains(&rsp),
        "handler must run on the unix stack, not the guest stack (rsp={rsp:#x})"
    );
    // Clobber a non-volatile pair (must be restored by the dispatcher).
    cpu.set_reg(Reg::Rbx, 0xFFFF_FFFF_FFFF_FFFF);
    cpu.set_xmm_keep_upper(6, 0xDEAD);
    // Write a volatile pair (must pass through to the guest untouched).
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
    // The TEB region the dispatcher parks its syscall_frame in.
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();

    // `mov r10,rcx; mov eax,N; syscall; hlt` — the Wine native-x64 stub shape.
    let mut asm = vec![0x49, 0x89, 0xCA]; // mov r10, rcx
    asm.extend_from_slice(&[0xB8]); // mov eax, imm32
    asm.extend_from_slice(&SYSCALL_INDEX.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]); // syscall
    asm.push(0xF4); // hlt
    mem.poke(CODE, &asm).unwrap();
    let syscall_ret = CODE + (asm.len() as u64 - 1); // address of the hlt

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
        s.set_reg(Reg::Rcx, ARG0); // syscall arg0 (stub moves it to R10)
        s.set_reg(Reg::Rbx, RBX_CANARY);
        s.set_xmm_keep_upper(6, XMM6_CANARY);
        // Seed a couple of flags including DF to prove RFLAGS is restored.
        s.rflags |= flags::CF | flags::DF;
    }
    let rflags_before = cpu.state().rflags;

    // Run until the trailing hlt.
    loop {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit before hlt: {other:?}"),
        }
    }

    let s = cpu.state();
    // The syscall's NTSTATUS is in RAX.
    assert_eq!(s.reg(Reg::Rax), STATUS as u64, "NTSTATUS must land in RAX");
    // Non-volatiles the handler clobbered are restored to the guest's values.
    assert_eq!(s.reg(Reg::Rbx), RBX_CANARY, "RBX (non-volatile) must be restored");
    assert_eq!(s.xmm(6), XMM6_CANARY, "XMM6 (non-volatile) must be restored");
    // Volatiles the handler wrote pass through to the guest.
    assert_eq!(s.reg(Reg::Rdx), 0xCAFE_F00D, "RDX (volatile) passes through");
    assert_eq!(s.xmm(0), 0xBEEF, "XMM0 (volatile) passes through");
    // The guest resumed exactly after the syscall — at the `hlt`, whose
    // handler leaves `rip` at the hlt address (it does not advance past it).
    assert_eq!(s.rip, syscall_ret, "guest must resume past the syscall (at the hlt)");
    // The guest stack pointer is restored off the unix stack.
    assert_eq!(s.rsp(), STACK_TOP, "guest RSP must be restored");
    // RFLAGS (including the guest's DF) is restored wholesale.
    assert_eq!(s.rflags, rflags_before, "guest RFLAGS must be restored");
}
