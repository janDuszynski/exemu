use exemu_core::{flags, Cpu, CpuState, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{Trap, TrapMode, WinConfig, WinOs, RVA_KI_USER_EXCEPTION_DISPATCHER};

const NTDLL_BASE: u64 = 0x0000_0001_7000_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const TEB_SIZE: u64 = 0x2000;

const CTX_RSP: u64 = 0x98;
const CTX_RIP: u64 = 0xf8;
const ER: u64 = 0x4F0;
const ER_CODE: u64 = ER;
const ER_ADDRESS: u64 = ER + 0x10;
const ER_NUM_PARAMS: u64 = ER + 0x18;
const ER_INFO: u64 = ER + 0x20;
const MF: u64 = 0x590;
const MF_RIP: u64 = MF;
const MF_CS: u64 = MF + 0x08;
const MF_RFLAGS: u64 = MF + 0x10;
const MF_OLDRSP: u64 = MF + 0x18;
const MF_SS: u64 = MF + 0x20;

fn os_mem() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    (os, mem)
}

#[test]
fn deliver_av_builds_dispatcher_frame() {
    let (mut os, mut mem) = os_mem();
    let old_rsp = 0x0000_0010_0000_0F00u64;
    let fault_rip = 0x0000_0001_4000_1234u64;
    let fault_addr = 0x0000_0000_DEAD_0000u64;

    let mut cpu = CpuState::new();
    cpu.rip = fault_rip;
    cpu.set_rsp(old_rsp);
    cpu.set_reg(Reg::Rbx, 0xB16B_00B5);
    cpu.rflags = flags::RESERVED_ONE | flags::CF | flags::ZF;

    os.deliver_hw_exception(&mut cpu, &mut mem, NTDLL_BASE,
        Trap { code: 0xC000_0005, address: fault_addr, info: &[0, fault_addr], mode: TrapMode::Long })
        .unwrap();

    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(cpu.rip, NTDLL_BASE + RVA_KI_USER_EXCEPTION_DISPATCHER, "rip = KiUserExceptionDispatcher");
    assert_eq!(cpu.rsp(), new_rsp, "rsp = 16-aligned (old_rsp - 0x5C0) & !0xF");
    assert_eq!(cpu.rsp() & 0xf, 0, "rsp 16-byte aligned");

    assert_eq!(mem.read_u64(new_rsp + CTX_RIP).unwrap(), fault_rip, "CONTEXT.Rip = faulting rip");
    assert_eq!(mem.read_u64(new_rsp + CTX_RSP).unwrap(), old_rsp, "CONTEXT.Rsp = pre-fault rsp");
    assert_eq!(mem.read_u64(new_rsp + 0x78 + 3 * 8).unwrap(), 0xB16B_00B5, "CONTEXT.Rbx captured");

    assert_eq!(mem.read_u32(new_rsp + ER_CODE).unwrap(), 0xC000_0005, "ER.ExceptionCode = AV");
    assert_eq!(mem.read_u64(new_rsp + ER_ADDRESS).unwrap(), fault_addr, "ER.ExceptionAddress");
    assert_eq!(mem.read_u32(new_rsp + ER_NUM_PARAMS).unwrap(), 2, "ER.NumberParameters = 2");
    assert_eq!(mem.read_u64(new_rsp + ER_INFO).unwrap(), 0, "ER.Info[0] = rw (0 = read)");
    assert_eq!(mem.read_u64(new_rsp + ER_INFO + 8).unwrap(), fault_addr, "ER.Info[1] = fault addr");

    assert_eq!(mem.read_u64(new_rsp + MF_RIP).unwrap(), fault_rip, "machine frame RIP");
    assert_eq!(mem.read_u64(new_rsp + MF_CS).unwrap(), 0x33, "machine frame CS = 0x33");
    assert_eq!(mem.read_u64(new_rsp + MF_RFLAGS).unwrap(), cpu.rflags, "machine frame RFLAGS");
    assert_eq!(mem.read_u64(new_rsp + MF_OLDRSP).unwrap(), old_rsp, "machine frame OldRSP = old_rsp");
    assert_eq!(new_rsp + MF_OLDRSP, new_rsp + 0x5A8, "OldRSP slot at +0x5A8");
    assert_eq!(mem.read_u64(new_rsp + MF_SS).unwrap(), 0x2B, "machine frame SS = 0x2B");
}

#[test]
fn deliver_bp_reports_rip_plus_one() {
    let (mut os, mut mem) = os_mem();
    let old_rsp = 0x0000_0010_0000_0F00u64;
    let int3_rip = 0x0000_0001_4000_2000u64;

    let mut cpu = CpuState::new();
    cpu.rip = int3_rip + 1;
    cpu.set_rsp(old_rsp);

    os.deliver_hw_exception(&mut cpu, &mut mem, NTDLL_BASE,
        Trap { code: 0x8000_0003, address: int3_rip + 1, info: &[], mode: TrapMode::Long })
        .unwrap();

    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(mem.read_u64(new_rsp + CTX_RIP).unwrap(), int3_rip + 1, "CONTEXT.Rip = int3 rip + 1");
    assert_eq!(mem.read_u32(new_rsp + ER_CODE).unwrap(), 0x8000_0003, "ER.ExceptionCode = #BP");
    assert_eq!(mem.read_u64(new_rsp + ER_ADDRESS).unwrap(), int3_rip + 1, "ER.ExceptionAddress = rip + 1");
    assert_eq!(mem.read_u32(new_rsp + ER_NUM_PARAMS).unwrap(), 0, "#BP carries no parameters");
}

#[test]
fn delivered_context_round_trips_through_nt_continue() {
    let code: u64 = 0x0000_0000_0040_0000;
    let landing: u64 = 0x0000_0001_4000_1234;
    let old_rsp = 0x0000_0010_0000_0F00u64;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("code", code, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("landing", landing & !0xfff, 0x1000, Perm::RX)).unwrap();
    mem.poke(landing, &[0xF4]).unwrap();

    let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });

    let mut faulted = CpuState::new();
    faulted.rip = landing;
    faulted.set_rsp(old_rsp);
    faulted.set_reg(Reg::Rbx, 0xB16B_00B5);
    faulted.rflags = flags::RESERVED_ONE | flags::CF;
    os.deliver_hw_exception(&mut faulted, &mut mem, NTDLL_BASE,
        Trap { code: 0xC000_0005, address: landing, info: &[0, landing], mode: TrapMode::Long })
        .unwrap();
    let new_rsp = (old_rsp - 0x5C0) & !0xF;
    assert_eq!(faulted.rsp(), new_rsp);

    let mut asm = vec![0x49, 0x89, 0xCA];
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&0x43u32.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    mem.poke(code, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = code;
        s.set_rsp(STACK_TOP);
        s.gs_base = GS_BASE;
        s.fs_base = GS_BASE;
        s.set_reg(Reg::Rcx, new_rsp);
        s.set_reg(Reg::Rbx, 0xDEAD);
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

const SSDT_NT_RAISE_EXCEPTION: u32 = 0xCF;
const SSDT_NT_CONTINUE: u32 = 0x43;
const REC_CODE: u64 = 0x00;
const REC_ADDRESS: u64 = 0x10;
const REC_NUM_PARAMS: u64 = 0x18;

fn syscall_stub(index: u32) -> Vec<u8> {
    let mut asm = vec![0x49, 0x89, 0xCA];
    asm.push(0xB8);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm
}

fn seated(cpu: &mut Interpreter, rip: u64) {
    let s = cpu.state_mut();
    s.rip = rip;
    s.set_rsp(STACK_TOP);
    s.gs_base = GS_BASE;
    s.fs_base = GS_BASE;
}

#[test]
fn last_resort_raise_terminates_the_process_with_the_exception() {
    let code_va: u64 = 0x0000_0000_0040_0000;
    let rec_va: u64 = 0x0000_0000_0050_0000;
    let fault_addr: u64 = 0x0000_0001_4000_1234;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("code", code_va, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("rec", rec_va, 0x1000, Perm::RW)).unwrap();
    mem.poke(code_va, &syscall_stub(SSDT_NT_RAISE_EXCEPTION)).unwrap();
    mem.write_u32(rec_va + REC_CODE, 0xC000_0005).unwrap();
    mem.write_u64(rec_va + REC_ADDRESS, fault_addr).unwrap();
    mem.write_u32(rec_va + REC_NUM_PARAMS, 2).unwrap();

    let mut os =
        WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    let mut cpu = Interpreter::with_bits(Bits::B64);
    seated(&mut cpu, code_va);
    {
        let s = cpu.state_mut();
        s.set_reg(Reg::Rcx, rec_va);
        s.set_reg(Reg::Rdx, 0);
        s.set_reg(Reg::R8, 0);
    }

    let mut exit = None;
    for _ in 0..64 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            other => {
                exit = Some(other);
                break;
            }
        }
    }
    assert_eq!(
        exit,
        Some(Exit::ProcessExit(0xC000_0005u32 as i32)),
        "a non-first-chance raise must END the process with the exception code, not return to \
         the guest — returning is what ran KiUserExceptionDispatcher's int3 and started the loop",
    );

    let u = os.take_unhandled_exception().expect("the killing exception is recorded for the report");
    assert_eq!(u.code, 0xC000_0005, "the report names the record's ExceptionCode");
    assert_eq!(u.address, fault_addr, "…and its ExceptionAddress");
    assert_eq!(u.how, exemu_os::UnhandledException::LAST_RESORT, "the guest asked for it itself");
    assert!(os.take_unhandled_exception().is_none(), "taking it clears it");
}

#[test]
fn first_chance_raise_without_a_dispatcher_is_refused_not_fatal() {
    let code_va: u64 = 0x0000_0000_0040_0000;
    let rec_va: u64 = 0x0000_0000_0050_0000;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("code", code_va, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("rec", rec_va, 0x1000, Perm::RW)).unwrap();
    let mut asm = syscall_stub(SSDT_NT_RAISE_EXCEPTION);
    asm.push(0xF4);
    mem.poke(code_va, &asm).unwrap();
    mem.write_u32(rec_va + REC_CODE, 0xC000_0005).unwrap();

    let mut os =
        WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    let mut cpu = Interpreter::with_bits(Bits::B64);
    seated(&mut cpu, code_va);
    {
        let s = cpu.state_mut();
        s.set_reg(Reg::Rcx, rec_va);
        s.set_reg(Reg::R8, 1);
    }
    let mut halted = false;
    for _ in 0..64 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => {
                halted = true;
                break;
            }
            other => panic!("a first-chance raise must not end the process: {other:?}"),
        }
    }
    assert!(halted, "the service returned to its caller");
    assert_eq!(cpu.state().reg(Reg::Rax), 0xC000_0002, "STATUS_NOT_IMPLEMENTED");
    assert!(os.take_unhandled_exception().is_none(), "nothing was killed");
}

#[test]
fn re_delivery_bound_reports_the_exception_that_opened_the_chain() {
    let mut os =
        WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });

    os.note_exception_delivery(0xC000_0005, 0xDEAD, 0x1_4000_1000).expect("the first delivery");
    let bp_rip = 0x6_0001_0A5A;
    os.note_exception_delivery(0x8000_0003, bp_rip + 1, bp_rip).expect("a second exception is normal");
    let mut more = 0;
    let u = loop {
        more += 1;
        assert!(more < 64, "the bound must fire — that is the whole point");
        match os.note_exception_delivery(0x8000_0003, bp_rip + 1, bp_rip) {
            Ok(()) => continue,
            Err(u) => break u,
        }
    };
    assert_eq!(u.code, 0xC000_0005, "the ORIGINAL access violation, not the int3's STATUS_BREAKPOINT");
    assert_eq!(u.address, 0xDEAD, "…at the address the guest actually faulted on");
    assert_eq!(u.how, exemu_os::UnhandledException::RE_DELIVERY_BOUND);
    assert_eq!(
        os.take_unhandled_exception().map(|u| u.code),
        Some(0xC000_0005),
        "the run loop can pick it up to build the report",
    );
}

#[test]
fn a_guest_that_keeps_resuming_is_never_bounded() {
    let code_va: u64 = 0x0000_0000_0040_0000;
    let landing: u64 = 0x0000_0001_4000_1234;

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x10000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("code", code_va, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("landing", landing & !0xfff, 0x1000, Perm::RX)).unwrap();
    mem.poke(landing, &[0xF4]).unwrap();
    mem.poke(code_va, &syscall_stub(SSDT_NT_CONTINUE)).unwrap();

    let mut os =
        WinOs::new(WinConfig { is_64bit: true, echo: false, teb_base: GS_BASE, ..WinConfig::default() });
    let mut cpu = Interpreter::with_bits(Bits::B64);

    for round in 0..200u32 {
        os.note_exception_delivery(0xC000_0005, 0xDEAD, landing)
            .unwrap_or_else(|u| panic!("round {round}: bounded a guest that keeps resuming ({u:?})"));
        let mut faulted = CpuState::new();
        faulted.rip = landing;
        faulted.set_rsp(STACK_TOP - 0x1000);
        os.deliver_hw_exception(&mut faulted, &mut mem, NTDLL_BASE,
            Trap { code: 0xC000_0005, address: 0xDEAD, info: &[0, 0xDEAD], mode: TrapMode::Long })
            .unwrap();
        let frame = faulted.rsp();
        seated(&mut cpu, code_va);
        cpu.state_mut().set_reg(Reg::Rcx, frame);
        loop {
            match cpu.step(&mut mem, &mut os).unwrap() {
                Exit::Continue => continue,
                Exit::Halted => break,
                other => panic!("round {round}: unexpected exit {other:?}"),
            }
        }
        assert_eq!(cpu.state().rip, landing, "round {round}: NtContinue resumed the guest");
    }
    assert!(os.take_unhandled_exception().is_none(), "nothing was ever declared unhandled");
}
