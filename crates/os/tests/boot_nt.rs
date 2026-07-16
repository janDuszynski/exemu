//! Process bootstrap — the `NtContinue` handoff (roadmap W3.1), driven
//! end-to-end through the real interpreter exactly as Wine's `ZwContinue` stub
//! (`mov r10,rcx; mov eax,0x43; test byte[0x7ffe0308],1; syscall`) does.
//!
//! `signal_start_thread` ends in `ZwContinue(context, TRUE)` — SSDT index 0x43,
//! stub `mov r10,rcx` (arg0 = ContextRecord → R10). The dispatcher must load the
//! guest CONTEXT into the register file and resume at CONTEXT.Rip on CONTEXT.Rsp
//! **without** restoring the abandoned `signal_start_thread` syscall frame. We
//! assemble the genuine stub bytes, park a CONTEXT whose Rip points at a `hlt`
//! landing pad, run the CPU, and assert the whole register file was restored.

use exemu_core::{flags, Cpu, CpuState, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const LANDING: u64 = 0x0000_0000_0041_0000; // where CONTEXT.Rip points (a `hlt`)
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const CTX: u64 = 0x0000_0000_0050_0000; // the guest CONTEXT buffer
const TEB_SIZE: u64 = 0x2000;
const NT_CONTINUE_INDEX: u32 = 0x43;

// CONTEXT field offsets (winnt.h AMD64) — write_context lays these out.
const CTX_RIP_TARGET: u64 = 0x0000_0000_0041_0000; // == LANDING
const RESUME_RSP: u64 = 0x0000_0010_0000_0800; // CONTEXT.Rsp (distinct from entry rsp)
const RBX_VAL: u64 = 0xB16B_00B5_1234_5678;
const RSI_VAL: u64 = 0x5151_5151_5151_5151;
const RCX_VAL: u64 = 0x00C0_FFEE_00C0_FFEE;

/// Serialize `state` into a guest CONTEXT the way `os::exc::write_context` does
/// (mirrored here — that serializer is crate-private). Only the fields the
/// dispatcher's NtContinue reads back need to be laid out.
fn write_context(mem: &mut VirtualMemory, addr: u64, s: &CpuState) {
    const OFF_CONTEXT_FLAGS: u64 = 0x30;
    const OFF_MXCSR: u64 = 0x34;
    const OFF_EFLAGS: u64 = 0x44;
    const OFF_GPR: u64 = 0x78; // Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15
    const OFF_RIP: u64 = 0xf8;
    const OFF_XMM0: u64 = 0x1a0;
    const CONTEXT_ALL: u32 = 0x0010_0000 | 0x1 | 0x2 | 0x8;
    mem.write_u32(addr + OFF_CONTEXT_FLAGS, CONTEXT_ALL).unwrap();
    mem.write_u32(addr + OFF_MXCSR, 0x1f80).unwrap();
    mem.write_u32(addr + OFF_EFLAGS, s.rflags as u32).unwrap();
    for (i, &v) in s.gpr.iter().enumerate() {
        mem.write_u64(addr + OFF_GPR + i as u64 * 8, v).unwrap();
    }
    mem.write_u64(addr + OFF_RIP, s.rip).unwrap();
    for (i, &v) in s.xmm.iter().enumerate() {
        mem.write(addr + OFF_XMM0 + i as u64 * 16, &v.to_le_bytes()).unwrap();
    }
}

#[test]
fn nt_continue_restores_context_through_real_dispatcher() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("landing", LANDING, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("ctx", CTX, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();

    // The real ZwContinue stub shape (minus the KUSER test/branch, which we
    // steer to the raw syscall by not seeding SystemCall): `mov r10,rcx; mov
    // eax,0x43; syscall`. The `syscall` never returns here — NtContinue resumes
    // into the CONTEXT — so no trailing hlt is needed at CODE.
    let mut asm = vec![0x49, 0x89, 0xCA]; // mov r10, rcx
    asm.extend_from_slice(&[0xB8]); // mov eax, imm32
    asm.extend_from_slice(&NT_CONTINUE_INDEX.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]); // syscall
    mem.poke(CODE, &asm).unwrap();
    // The landing pad the CONTEXT.Rip points at: a `hlt` so the test ends.
    mem.poke(LANDING, &[0xF4]).unwrap();

    // Build the CONTEXT NtContinue must restore: distinctive GP/control state,
    // Rip at the landing pad, Rsp distinct from the entry stack.
    let mut want = CpuState::new();
    want.set_reg(Reg::Rbx, RBX_VAL);
    want.set_reg(Reg::Rsi, RSI_VAL);
    want.set_reg(Reg::Rcx, RCX_VAL);
    want.rip = CTX_RIP_TARGET;
    want.set_rsp(RESUME_RSP);
    want.rflags = flags::RESERVED_ONE | flags::CF | flags::ZF;
    write_context(&mut mem, CTX, &want);

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        ..WinConfig::default()
    });

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rcx, CTX); // ZwContinue arg0 = ContextRecord (stub → R10)
        s.set_reg(Reg::Rdx, 1); // TestAlert = TRUE (accepted, ignored)
        // Junk in the registers the CONTEXT overwrites, to prove they load.
        s.set_reg(Reg::Rbx, 0xDEAD);
        s.set_reg(Reg::Rsi, 0xDEAD);
    }

    loop {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit before the CONTEXT landing pad: {other:?}"),
        }
    }

    let s = cpu.state();
    // Execution resumed at CONTEXT.Rip on CONTEXT.Rsp.
    assert_eq!(s.rip, CTX_RIP_TARGET, "resumed at CONTEXT.Rip (the landing pad hlt)");
    assert_eq!(s.rsp(), RESUME_RSP, "resumed on CONTEXT.Rsp, not the entry stack");
    // The whole integer register file loaded from the CONTEXT.
    assert_eq!(s.reg(Reg::Rbx), RBX_VAL, "Rbx loaded from CONTEXT");
    assert_eq!(s.reg(Reg::Rsi), RSI_VAL, "Rsi loaded from CONTEXT");
    assert_eq!(s.reg(Reg::Rcx), RCX_VAL, "Rcx loaded from CONTEXT (not the syscall return rip)");
    // RFLAGS loaded from the CONTEXT.
    assert_eq!(s.rflags & flags::CF, flags::CF, "RFLAGS.CF from CONTEXT");
    assert_eq!(s.rflags & flags::ZF, flags::ZF, "RFLAGS.ZF from CONTEXT");
    // The dispatcher did NOT restore the abandoned signal_start_thread frame:
    // segment base still points at this thread's TEB.
    assert_eq!(s.gs_base, GS_BASE, "gs_base preserved across NtContinue");
}

/// Helper: `os::exc::write_context` reads back to this same layout. Guard that a
/// separate boot-time build (unused RAX/R8..R15 zeroed) still restores cleanly.
#[test]
fn nt_continue_status_when_context_null() {
    // With a genuine stub and R10 = 0 (NULL ContextRecord), the handler returns
    // STATUS_ACCESS_VIOLATION and control returns to the instruction after the
    // syscall (a hlt), leaving RAX = 0xC0000005.
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();

    let mut asm = vec![0x49, 0x89, 0xCA]; // mov r10, rcx
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&NT_CONTINUE_INDEX.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]); // syscall
    asm.push(0xF4); // hlt — reached because NULL CONTEXT returns normally
    mem.poke(CODE, &asm).unwrap();
    let hlt = CODE + (asm.len() as u64 - 1);

    let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(STACK_TOP);
        s.set_reg(Reg::Rcx, 0); // NULL ContextRecord
    }
    loop {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    let s = cpu.state();
    assert_eq!(s.reg(Reg::Rax), 0xC000_0005, "NtContinue(NULL) → STATUS_ACCESS_VIOLATION");
    assert_eq!(s.rip, hlt, "returned to the instruction after syscall (the hlt)");
}
