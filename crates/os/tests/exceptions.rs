use exemu_core::{
    CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg, UnwindCode, UnwindEntry,
    UnwindInfo, UnwindOp,
};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const STACK: u64 = 0x9000;
const RET_ADDR: u64 = 0x1_2345;
const CTX: u64 = 0x5000;
const OUT: u64 = 0x6000;

const CTX_RBX: u64 = 0x90;
const CTX_RSP: u64 = 0x98;
const CTX_RIP: u64 = 0xf8;

fn setup(table: Vec<UnwindEntry>) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("scratch", 0x4000, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    let mut os = WinOs::new(WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        image_base: IMAGE_BASE,
        echo: false,
        ..WinConfig::default()
    });
    os.set_unwind_table(table);
    (os, mem)
}

fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str) -> u64 {
    let thunk = os.resolve_import("ntdll.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.rip, RET_ADDR, "shim did not return to caller");
    cpu.reg(Reg::Rax)
}

fn set_stack_arg(mem: &mut VirtualMemory, i: usize, v: u64) {
    mem.write_u64(STACK + 0x28 + (i as u64 - 4) * 8, v).unwrap();
}

fn entry(begin: u32, end: u32, record_rva: u32, codes: Vec<UnwindCode>) -> UnwindEntry {
    UnwindEntry {
        begin_rva: begin,
        end_rva: end,
        record_rva,
        info: UnwindInfo {
            version: 1,
            has_exception_handler: false,
            has_termination_handler: false,
            prolog_size: 0,
            frame_register: None,
            frame_offset: 0,
            codes,
            handler_rva: None,
            handler_data_rva: None,
            chained: None,
        },
    }
}

#[test]
fn lookup_function_entry_hits_and_writes_base() {
    let table = vec![entry(0x1000, 0x1080, 0x9000, vec![])];
    let (mut os, mut mem) = setup(table);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x1040);
    cpu.set_reg(Reg::Rdx, OUT);
    cpu.set_reg(Reg::R8, 0);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlLookupFunctionEntry");
    assert_eq!(rax, IMAGE_BASE + 0x9000, "returns RUNTIME_FUNCTION guest VA");
    assert_eq!(mem.read_u64(OUT).unwrap(), IMAGE_BASE, "wrote image base out");
}

#[test]
fn lookup_function_entry_misses_leaf() {
    let table = vec![entry(0x1000, 0x1080, 0x9000, vec![])];
    let (mut os, mut mem) = setup(table);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x5000);
    cpu.set_reg(Reg::Rdx, OUT);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlLookupFunctionEntry");
    assert_eq!(rax, 0, "leaf function → NULL");
}

#[test]
fn capture_context_snapshots_caller_state() {
    let (mut os, mut mem) = setup(vec![]);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rbx, 0xDEAD_BEEF);
    cpu.set_reg(Reg::Rcx, CTX);
    call(&mut os, &mut mem, &mut cpu, "RtlCaptureContext");
    assert_eq!(mem.read_u64(CTX + CTX_RIP).unwrap(), RET_ADDR);
    assert_eq!(mem.read_u64(CTX + CTX_RSP).unwrap(), STACK + 8);
    assert_eq!(mem.read_u64(CTX + CTX_RBX).unwrap(), 0xDEAD_BEEF);
}

#[test]
fn virtual_unwind_pops_frame_and_reports_handler() {
    let mut e = entry(
        0x1000,
        0x1080,
        0x9000,
        vec![
            UnwindCode { prolog_offset: 5, op: UnwindOp::Alloc { size: 0x20 } },
            UnwindCode { prolog_offset: 1, op: UnwindOp::PushNonvolatile { reg: 3 } },
        ],
    );
    e.info.has_exception_handler = true;
    e.info.handler_rva = Some(0xA000);
    e.info.handler_data_rva = Some(0xA100);
    let (mut os, mut mem) = setup(vec![e]);

    let frame = 0x7000u64;
    mem.write_u64(frame + 0x20, 0xBBBB_0003).unwrap();
    mem.write_u64(frame + 0x28, IMAGE_BASE + 0x2000).unwrap();

    mem.write_u64(CTX + CTX_RIP, IMAGE_BASE + 0x1040).unwrap();
    mem.write_u64(CTX + CTX_RSP, frame).unwrap();

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 1);
    cpu.set_reg(Reg::Rdx, IMAGE_BASE);
    cpu.set_reg(Reg::R8, IMAGE_BASE + 0x1040);
    cpu.set_reg(Reg::R9, IMAGE_BASE + 0x9000);
    set_stack_arg(&mut mem, 4, CTX);
    set_stack_arg(&mut mem, 5, OUT);
    set_stack_arg(&mut mem, 6, OUT + 8);
    set_stack_arg(&mut mem, 7, 0);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlVirtualUnwind");

    assert_eq!(rax, IMAGE_BASE + 0xA000, "returns the language handler VA");
    assert_eq!(mem.read_u64(OUT).unwrap(), IMAGE_BASE + 0xA100, "HandlerData out");
    assert_eq!(mem.read_u64(OUT + 8).unwrap(), frame, "EstablisherFrame out");
    assert_eq!(mem.read_u64(CTX + CTX_RIP).unwrap(), IMAGE_BASE + 0x2000);
    assert_eq!(mem.read_u64(CTX + CTX_RBX).unwrap(), 0xBBBB_0003);
}

fn raise_inside_a(os: &mut WinOs, mem: &mut VirtualMemory, with_handler: bool) -> (CpuState, Option<Exit>) {
    let mut a = entry(
        0x1000,
        0x1080,
        0x9000,
        vec![UnwindCode { prolog_offset: 1, op: UnwindOp::PushNonvolatile { reg: 3 } }],
    );
    a.info.has_exception_handler = with_handler;
    a.info.handler_rva = with_handler.then_some(0x2000);
    a.info.handler_data_rva = with_handler.then_some(0x2100);
    os.set_unwind_table(vec![a]);

    let mut cpu = CpuState::new();
    let raise_from = IMAGE_BASE + 0x1040;
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, raise_from).unwrap();
    mem.write_u64(STACK + 8, 0xBBBB_0003).unwrap();
    mem.write_u64(STACK + 0x10, 0x0000_7EFF_0000_0500).unwrap();
    cpu.set_reg(Reg::Rcx, 0xE06D_7363);
    cpu.set_reg(Reg::Rdx, 1);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named("RaiseException".into()));
    cpu.rip = thunk;
    let exit = os.intercept(thunk, &mut cpu, mem).unwrap();
    (cpu, exit)
}

#[test]
fn raise_exception_invokes_frame_handler() {
    let (mut os, mut mem) = setup(vec![]);
    let (cpu, exit) = raise_inside_a(&mut os, &mut mem, true);
    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.rip, IMAGE_BASE + 0x2000, "handler invoked");
    assert_eq!(cpu.reg(Reg::Rdx), STACK + 8, "establisher frame");
    let record = cpu.reg(Reg::Rcx);
    assert_eq!(mem.read_u32(record).unwrap(), 0xE06D_7363, "record ExceptionCode");
    let disp = cpu.reg(Reg::R9);
    assert_eq!(mem.read_u64(disp + 0x30).unwrap(), IMAGE_BASE + 0x2000);
    assert_eq!(mem.read_u64(disp + 0x38).unwrap(), IMAGE_BASE + 0x2100);
}

#[test]
fn unhandled_exception_terminates_with_code() {
    let (mut os, mut mem) = setup(vec![]);
    let (_cpu, exit) = raise_inside_a(&mut os, &mut mem, false);
    assert_eq!(exit, Some(Exit::ProcessExit(0xE06D_7363u32 as i32)));
}

#[test]
fn continue_search_advances_then_terminates() {
    let (mut os, mut mem) = setup(vec![]);
    let (cpu_after_call, _) = raise_inside_a(&mut os, &mut mem, true);
    assert_eq!(cpu_after_call.rip, IMAGE_BASE + 0x2000);

    let driver_ret = mem.read_u64(cpu_after_call.rsp()).unwrap();
    let mut cpu = cpu_after_call;
    cpu.set_reg(Reg::Rax, 1);
    cpu.rip = driver_ret;
    let exit = os.intercept(driver_ret, &mut cpu, &mut mem).unwrap();
    assert_eq!(exit, Some(Exit::ProcessExit(0xE06D_7363u32 as i32)));
}

#[test]
fn rtl_unwind_ex_transfers_to_target() {
    let a = entry(
        0x1000,
        0x1080,
        0x9000,
        vec![UnwindCode { prolog_offset: 1, op: UnwindOp::PushNonvolatile { reg: 3 } }],
    );
    let (mut os, mut mem) = setup(vec![a]);

    let ctx_in = 0x6800u64;
    mem.write_u64(ctx_in + 0xf8, IMAGE_BASE + 0x1040).unwrap();
    mem.write_u64(ctx_in + 0x98, STACK + 8).unwrap();

    let catch_ip = IMAGE_BASE + 0x1055;
    let mut cpu = CpuState::new();
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.set_reg(Reg::Rcx, STACK + 8);
    cpu.set_reg(Reg::Rdx, catch_ip);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0xCAFE);
    set_stack_arg(&mut mem, 4, ctx_in);
    set_stack_arg(&mut mem, 5, 0);
    let thunk = os.resolve_import("ntdll.dll", &ImportSymbol::Named("RtlUnwindEx".into()));
    cpu.rip = thunk;
    let exit = os.intercept(thunk, &mut cpu, &mut mem).unwrap();

    assert_eq!(exit, Some(Exit::Continue));
    assert_eq!(cpu.rip, catch_ip, "resumed at the catch funclet");
    assert_eq!(cpu.reg(Reg::Rax), 0xCAFE, "return value delivered in RAX");
    assert_eq!(cpu.rsp(), STACK + 8, "stack unwound to the target frame");
}

#[test]
fn set_unhandled_exception_filter_round_trips() {
    let (mut os, mut mem) = setup(vec![]);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 0xF00D);
    let r = call(&mut os, &mut mem, &mut cpu, "SetUnhandledExceptionFilter");
    assert_eq!(r, 0, "no previous filter");
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 0xBEEF);
    let r = call(&mut os, &mut mem, &mut cpu, "SetUnhandledExceptionFilter");
    assert_eq!(r, 0xF00D, "returns the previously installed filter");
}

#[test]
fn pc_to_file_header_classifies_image() {
    let table = vec![entry(0x1000, 0x1080, 0x9000, vec![])];
    let (mut os, mut mem) = setup(table);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x1010);
    cpu.set_reg(Reg::Rdx, OUT);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlPcToFileHeader");
    assert_eq!(rax, IMAGE_BASE);
    assert_eq!(mem.read_u64(OUT).unwrap(), IMAGE_BASE);

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x5000);
    cpu.set_reg(Reg::Rdx, OUT);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlPcToFileHeader");
    assert_eq!(rax, 0);
}
