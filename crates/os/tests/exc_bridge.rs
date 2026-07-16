//! The hardware→software exception bridge (roadmap W3.3): a guest CPU fault is
//! marshalled into the `KiUserExceptionDispatcher` stack frame and the CPU is
//! seated on ntdll's dispatcher, so Wine's own `RtlDispatchException` (real
//! guest code) runs; a handled exception returns through `NtContinue`.
//!
//! These tests drive `WinOs::deliver_hw_exception` directly (it is `pub`) and
//! assert the exact §4 stack math the dispatcher and `NtContinue` depend on,
//! then prove the round-trip: the CONTEXT the bridge builds is precisely what
//! `NtContinue` consumes to resume the faulting thread.

use exemu_core::{flags, Cpu, CpuState, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs, RVA_KI_USER_EXCEPTION_DISPATCHER};

// A synthetic ntdll base for the direct-delivery assertions. `deliver_hw_exception`
// only uses it to compute the dispatcher rip; no image need be mapped.
const NTDLL_BASE: u64 = 0x0000_0001_7000_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const TEB_SIZE: u64 = 0x2000;

// CONTEXT / EXCEPTION_RECORD field offsets within the built frame (winnt.h
// AMD64 + the §4 layout), relative to `new_rsp`.
const CTX_RSP: u64 = 0x98; // CONTEXT.Rsp
const CTX_RIP: u64 = 0xf8; // CONTEXT.Rip
const ER: u64 = 0x4F0; // EXCEPTION_RECORD base
const ER_CODE: u64 = ER; // ExceptionCode @ +0x00
const ER_ADDRESS: u64 = ER + 0x10;
const ER_NUM_PARAMS: u64 = ER + 0x18;
const ER_INFO: u64 = ER + 0x20;
const MF: u64 = 0x590; // machine frame base
const MF_RIP: u64 = MF; // RIP @ +0x00
const MF_CS: u64 = MF + 0x08;
const MF_RFLAGS: u64 = MF + 0x10;
const MF_OLDRSP: u64 = MF + 0x18;
const MF_SS: u64 = MF + 0x20;

fn os_mem() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    // A generous guest stack: the frame lands 0x5C0 below the faulting RSP.
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    (os, mem)
}

/// An access-violation delivery lays out CONTEXT + EXCEPTION_RECORD + machine
/// frame at exactly the §4 offsets and seats the CPU on the dispatcher.
#[test]
fn deliver_av_builds_dispatcher_frame() {
    let (mut os, mut mem) = os_mem();
    let old_rsp = 0x0000_0010_0000_0F00u64;
    let fault_rip = 0x0000_0001_4000_1234u64;
    let fault_addr = 0x0000_0000_DEAD_0000u64;

    let mut cpu = CpuState::new();
    cpu.rip = fault_rip;
    cpu.set_rsp(old_rsp);
    cpu.set_reg(Reg::Rbx, 0xB16B_00B5); // a live GPR that must survive into CONTEXT
    cpu.rflags = flags::RESERVED_ONE | flags::CF | flags::ZF;

    os.deliver_hw_exception(&mut cpu, &mut mem, NTDLL_BASE, 0xC000_0005, fault_addr, &[0, fault_addr])
        .unwrap();

    // The CPU is seated on the dispatcher with RSP → CONTEXT, no return pushed.
    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(cpu.rip, NTDLL_BASE + RVA_KI_USER_EXCEPTION_DISPATCHER, "rip = KiUserExceptionDispatcher");
    assert_eq!(cpu.rsp(), new_rsp, "rsp = 16-aligned (old_rsp - 0x5C0) & !0xF");
    assert_eq!(cpu.rsp() & 0xf, 0, "rsp 16-byte aligned");

    // CONTEXT @ +0x000: faulting Rip/Rsp and a live GPR.
    assert_eq!(mem.read_u64(new_rsp + CTX_RIP).unwrap(), fault_rip, "CONTEXT.Rip = faulting rip");
    assert_eq!(mem.read_u64(new_rsp + CTX_RSP).unwrap(), old_rsp, "CONTEXT.Rsp = pre-fault rsp");
    assert_eq!(mem.read_u64(new_rsp + 0x78 + 3 * 8).unwrap(), 0xB16B_00B5, "CONTEXT.Rbx captured");

    // EXCEPTION_RECORD @ +0x4F0.
    assert_eq!(mem.read_u32(new_rsp + ER_CODE).unwrap(), 0xC000_0005, "ER.ExceptionCode = AV");
    assert_eq!(mem.read_u64(new_rsp + ER_ADDRESS).unwrap(), fault_addr, "ER.ExceptionAddress");
    assert_eq!(mem.read_u32(new_rsp + ER_NUM_PARAMS).unwrap(), 2, "ER.NumberParameters = 2");
    assert_eq!(mem.read_u64(new_rsp + ER_INFO).unwrap(), 0, "ER.Info[0] = rw (0 = read)");
    assert_eq!(mem.read_u64(new_rsp + ER_INFO + 8).unwrap(), fault_addr, "ER.Info[1] = fault addr");

    // Machine frame @ +0x590.
    assert_eq!(mem.read_u64(new_rsp + MF_RIP).unwrap(), fault_rip, "machine frame RIP");
    assert_eq!(mem.read_u64(new_rsp + MF_CS).unwrap(), 0x33, "machine frame CS = 0x33");
    assert_eq!(mem.read_u64(new_rsp + MF_RFLAGS).unwrap(), cpu.rflags, "machine frame RFLAGS");
    assert_eq!(mem.read_u64(new_rsp + MF_OLDRSP).unwrap(), old_rsp, "machine frame OldRSP = old_rsp");
    assert_eq!(new_rsp + MF_OLDRSP, new_rsp + 0x5A8, "OldRSP slot at +0x5A8");
    assert_eq!(mem.read_u64(new_rsp + MF_SS).unwrap(), 0x2B, "machine frame SS = 0x2B");
}

/// A `#BP` (int3) delivery reports the address *after* the breakpoint: the
/// delivered CONTEXT.Rip and ER.ExceptionAddress are the faulting rip + 1.
#[test]
fn deliver_bp_reports_rip_plus_one() {
    let (mut os, mut mem) = os_mem();
    let old_rsp = 0x0000_0010_0000_0F00u64;
    let int3_rip = 0x0000_0001_4000_2000u64;

    let mut cpu = CpuState::new();
    // The bridge's classifier advances rip past the 0xCC before delivering; model
    // that here (deliver_hw_exception itself captures cpu.rip verbatim).
    cpu.rip = int3_rip + 1;
    cpu.set_rsp(old_rsp);

    os.deliver_hw_exception(&mut cpu, &mut mem, NTDLL_BASE, 0x8000_0003, int3_rip + 1, &[]).unwrap();

    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(mem.read_u64(new_rsp + CTX_RIP).unwrap(), int3_rip + 1, "CONTEXT.Rip = int3 rip + 1");
    assert_eq!(mem.read_u32(new_rsp + ER_CODE).unwrap(), 0x8000_0003, "ER.ExceptionCode = #BP");
    assert_eq!(mem.read_u64(new_rsp + ER_ADDRESS).unwrap(), int3_rip + 1, "ER.ExceptionAddress = rip + 1");
    assert_eq!(mem.read_u32(new_rsp + ER_NUM_PARAMS).unwrap(), 0, "#BP carries no parameters");
}

/// Round-trip: the CONTEXT the bridge builds is exactly what `NtContinue`
/// consumes. Deliver an AV, then feed the built CONTEXT (at `new_rsp`) to a real
/// `ZwContinue` stub through the interpreter and assert it restores the faulting
/// rip and the pre-fault rsp — proving the frame `NtContinue` reads matches what
/// the bridge writes.
#[test]
fn delivered_context_round_trips_through_nt_continue() {
    let code: u64 = 0x0000_0000_0040_0000;
    let landing: u64 = 0x0000_0001_4000_1234; // == the faulting rip the CONTEXT carries
    let old_rsp = 0x0000_0010_0000_0F00u64;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("code", code, 0x1000, Perm::RX)).unwrap();
    // The faulting rip must be executable so the resumed thread can land there.
    mem.map(Region::new("landing", landing & !0xfff, 0x1000, Perm::RX)).unwrap();
    mem.poke(landing, &[0xF4]).unwrap(); // hlt at the faulting rip → test ends

    let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });

    // Build the exception frame for an AV at `landing`.
    let mut faulted = CpuState::new();
    faulted.rip = landing;
    faulted.set_rsp(old_rsp);
    faulted.set_reg(Reg::Rbx, 0xB16B_00B5);
    faulted.rflags = flags::RESERVED_ONE | flags::CF;
    os.deliver_hw_exception(&mut faulted, &mut mem, NTDLL_BASE, 0xC000_0005, landing, &[0, landing])
        .unwrap();
    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(faulted.rsp(), new_rsp);

    // ZwContinue stub: `mov r10,rcx; mov eax,0x43; syscall` — RCX = &CONTEXT.
    let mut asm = vec![0x49, 0x89, 0xCA]; // mov r10, rcx
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&0x43u32.to_le_bytes()); // mov eax, 0x43 (NtContinue)
    asm.extend_from_slice(&[0x0F, 0x05]); // syscall
    mem.poke(code, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = code;
        s.set_rsp(STACK_TOP);
        s.gs_base = GS_BASE;
        s.fs_base = GS_BASE;
        s.set_reg(Reg::Rcx, new_rsp); // &CONTEXT = the frame base the bridge built
        s.set_reg(Reg::Rbx, 0xDEAD); // junk the CONTEXT must overwrite
    }

    loop {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit before the resumed landing pad: {other:?}"),
        }
    }

    let s = cpu.state();
    assert_eq!(s.rip, landing, "NtContinue resumed at the faulting rip the bridge saved");
    assert_eq!(s.rsp(), old_rsp, "NtContinue restored the pre-fault rsp (CONTEXT.Rsp)");
    assert_eq!(s.reg(Reg::Rbx), 0xB16B_00B5, "the live GPR round-tripped through the CONTEXT");
    assert_eq!(s.rflags & flags::CF, flags::CF, "RFLAGS.CF round-tripped through the CONTEXT");
}
