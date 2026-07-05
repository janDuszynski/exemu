//! Tests for the native x64 exception surface (roadmap P4.3), driven through
//! the public `Hooks::intercept` seam exactly as the interpreter would — the
//! guest CRT's language handlers call these ntdll entry points.

use exemu_core::{
    CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg, UnwindCode, UnwindEntry,
    UnwindInfo, UnwindOp,
};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const STACK: u64 = 0x9000;
const RET_ADDR: u64 = 0x1_2345;
const CTX: u64 = 0x5000; // scratch CONTEXT buffer
const OUT: u64 = 0x6000; // scratch out-parameter area

// CONTEXT field offsets we assert against (winnt.h AMD64).
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

/// Invoke `name` through intercept with args already in the register file;
/// returns RAX. Asserts the shim `ret`ed cleanly.
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

/// x64-arg positions 4.. live on the stack above the 32-byte shadow space.
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
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x1040); // ControlPc inside the function
    cpu.set_reg(Reg::Rdx, OUT); // *ImageBase
    cpu.set_reg(Reg::R8, 0); // *HistoryTable
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlLookupFunctionEntry");
    assert_eq!(rax, IMAGE_BASE + 0x9000, "returns RUNTIME_FUNCTION guest VA");
    assert_eq!(mem.read_u64(OUT).unwrap(), IMAGE_BASE, "wrote image base out");
}

#[test]
fn lookup_function_entry_misses_leaf() {
    let table = vec![entry(0x1000, 0x1080, 0x9000, vec![])];
    let (mut os, mut mem) = setup(table);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x5000); // outside any function
    cpu.set_reg(Reg::Rdx, OUT);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlLookupFunctionEntry");
    assert_eq!(rax, 0, "leaf function → NULL");
}

#[test]
fn capture_context_snapshots_caller_state() {
    let (mut os, mut mem) = setup(vec![]);
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rbx, 0xDEAD_BEEF);
    cpu.set_reg(Reg::Rcx, CTX); // arg0 = CONTEXT*
    call(&mut os, &mut mem, &mut cpu, "RtlCaptureContext");
    // RIP captured = the return address; RSP = post-return stack.
    assert_eq!(mem.read_u64(CTX + CTX_RIP).unwrap(), RET_ADDR);
    assert_eq!(mem.read_u64(CTX + CTX_RSP).unwrap(), STACK + 8);
    assert_eq!(mem.read_u64(CTX + CTX_RBX).unwrap(), 0xDEAD_BEEF);
}

#[test]
fn virtual_unwind_pops_frame_and_reports_handler() {
    // Function that pushes rbx then allocs 0x20; it has an exception handler.
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

    // Lay out the guest frame at 0x7000: [rsp]=alloc, saved rbx above it, then
    // the return address into the caller.
    let frame = 0x7000u64;
    mem.write_u64(frame + 0x20, 0xBBBB_0003).unwrap(); // saved rbx
    mem.write_u64(frame + 0x28, IMAGE_BASE + 0x2000).unwrap(); // return address

    // Build the incoming CONTEXT: rip mid-body, rsp at the frame base. Only
    // the fields the unwinder reads (RIP, RSP) need seeding.
    mem.write_u64(CTX + CTX_RIP, IMAGE_BASE + 0x1040).unwrap();
    mem.write_u64(CTX + CTX_RSP, frame).unwrap();

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::Rcx, 1); // HandlerType = UNW_FLAG_EHANDLER (search)
    cpu.set_reg(Reg::Rdx, IMAGE_BASE); // ImageBase
    cpu.set_reg(Reg::R8, IMAGE_BASE + 0x1040); // ControlPc
    cpu.set_reg(Reg::R9, IMAGE_BASE + 0x9000); // FunctionEntry (unused by us)
    set_stack_arg(&mut mem, 4, CTX); // ContextRecord
    set_stack_arg(&mut mem, 5, OUT); // *HandlerData
    set_stack_arg(&mut mem, 6, OUT + 8); // *EstablisherFrame
    set_stack_arg(&mut mem, 7, 0); // ContextPointers
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlVirtualUnwind");

    assert_eq!(rax, IMAGE_BASE + 0xA000, "returns the language handler VA");
    assert_eq!(mem.read_u64(OUT).unwrap(), IMAGE_BASE + 0xA100, "HandlerData out");
    assert_eq!(mem.read_u64(OUT + 8).unwrap(), frame, "EstablisherFrame out");
    // The CONTEXT now holds the caller's state.
    assert_eq!(mem.read_u64(CTX + CTX_RIP).unwrap(), IMAGE_BASE + 0x2000);
    assert_eq!(mem.read_u64(CTX + CTX_RBX).unwrap(), 0xBBBB_0003);
}

/// Handler-bearing function A, with the raise happening inside it. Lays out
/// A's frame on the stack (saved rbx, then a return address that leaves the
/// image so the walk terminates) and invokes RaiseException. Returns the CPU
/// after dispatch has set up (or declined) the handler call.
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
    mem.write_u64(STACK, raise_from).unwrap(); // RaiseException's return addr = raise site in A
    mem.write_u64(STACK + 8, 0xBBBB_0003).unwrap(); // A's saved rbx
    mem.write_u64(STACK + 0x10, 0x0000_7EFF_0000_0500).unwrap(); // return into OS region → walk ends
    cpu.set_reg(Reg::Rcx, 0xE06D_7363); // ExceptionCode (C++ throw)
    cpu.set_reg(Reg::Rdx, 1); // ExceptionFlags
    cpu.set_reg(Reg::R8, 0); // NumberParameters
    cpu.set_reg(Reg::R9, 0); // lpArguments
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
    // Dispatch set up a call into the language handler with the x64 ABI.
    assert_eq!(cpu.rip, IMAGE_BASE + 0x2000, "handler invoked");
    assert_eq!(cpu.reg(Reg::Rdx), STACK + 8, "establisher frame");
    let record = cpu.reg(Reg::Rcx);
    assert_eq!(mem.read_u32(record).unwrap(), 0xE06D_7363, "record ExceptionCode");
    // DISPATCHER_CONTEXT (r9): LanguageHandler at +0x30, HandlerData at +0x38.
    let disp = cpu.reg(Reg::R9);
    assert_eq!(mem.read_u64(disp + 0x30).unwrap(), IMAGE_BASE + 0x2000);
    assert_eq!(mem.read_u64(disp + 0x38).unwrap(), IMAGE_BASE + 0x2100);
}

#[test]
fn unhandled_exception_terminates_with_code() {
    let (mut os, mut mem) = setup(vec![]);
    let (_cpu, exit) = raise_inside_a(&mut os, &mut mem, false);
    // No frame caught it → std::terminate: exit with the exception code.
    assert_eq!(exit, Some(Exit::ProcessExit(0xE06D_7363u32 as i32)));
}

#[test]
fn continue_search_advances_then_terminates() {
    // A handler that returns ExceptionContinueSearch (RAX=1) must move the
    // walk on; with no further frame it terminates.
    let (mut os, mut mem) = setup(vec![]);
    let (cpu_after_call, _) = raise_inside_a(&mut os, &mut mem, true);
    assert_eq!(cpu_after_call.rip, IMAGE_BASE + 0x2000);

    // Simulate the handler returning ContinueSearch to the driver thunk.
    let driver_ret = mem.read_u64(cpu_after_call.rsp()).unwrap(); // = exc_driver thunk
    let mut cpu = cpu_after_call;
    cpu.set_reg(Reg::Rax, 1); // EXCEPTION_CONTINUE_SEARCH
    cpu.rip = driver_ret;
    let exit = os.intercept(driver_ret, &mut cpu, &mut mem).unwrap();
    // The only handler declined and the next frame leaves the image → terminate.
    assert_eq!(exit, Some(Exit::ProcessExit(0xE06D_7363u32 as i32)));
}

#[test]
fn rtl_unwind_ex_transfers_to_target() {
    // A language handler decides to catch: it calls RtlUnwindEx targeting its
    // own establisher frame, and control must resume at the catch IP.
    let a = entry(
        0x1000,
        0x1080,
        0x9000,
        vec![UnwindCode { prolog_offset: 1, op: UnwindOp::PushNonvolatile { reg: 3 } }],
    );
    let (mut os, mut mem) = setup(vec![a]);

    // Build the ContextRecord RtlUnwindEx unwinds from: positioned in A.
    let ctx_in = 0x6800u64;
    mem.write_u64(ctx_in + 0xf8, IMAGE_BASE + 0x1040).unwrap(); // RIP in A
    mem.write_u64(ctx_in + 0x98, STACK + 8).unwrap(); // RSP = A's frame base

    let catch_ip = IMAGE_BASE + 0x1055;
    let mut cpu = CpuState::new();
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.set_reg(Reg::Rcx, STACK + 8); // TargetFrame = A's establisher
    cpu.set_reg(Reg::Rdx, catch_ip); // TargetIp
    cpu.set_reg(Reg::R8, 0); // ExceptionRecord
    cpu.set_reg(Reg::R9, 0xCAFE); // ReturnValue → RAX at the catch
    set_stack_arg(&mut mem, 4, ctx_in); // ContextRecord
    set_stack_arg(&mut mem, 5, 0); // HistoryTable
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
    cpu.set_reg(Reg::Rcx, IMAGE_BASE + 0x5000); // not in any function
    cpu.set_reg(Reg::Rdx, OUT);
    let rax = call(&mut os, &mut mem, &mut cpu, "RtlPcToFileHeader");
    assert_eq!(rax, 0);
}
