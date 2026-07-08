//! End-to-end test of the cooperative thread scheduler (roadmap P3.4).
//!
//! Hand-assembled 32-bit code: the main thread `CreateThread`s a worker, then
//! `WaitForSingleObject`s on its handle; the worker writes a sentinel to shared
//! memory and returns. The whole thing is stepped through the real interpreter
//! with `WinOs` as the hook layer, so the *only* way the sentinel becomes
//! non-zero — and the only way the join returns — is if the scheduler actually
//! saved the main thread, ran the worker to its `ret`, and switched back. A
//! stubbed/no-op CreateThread would leave the sentinel at zero.

use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const REGION: u64 = 0x0040_0000; // code + IAT + data (RWX)
const MAIN: u64 = 0x0040_1000;
const WORKER: u64 = 0x0040_1100;
const IAT_CREATE: u64 = 0x0040_2000;
const IAT_WFSO: u64 = 0x0040_2004;
const HANDLE: u64 = 0x0040_3000;
const FLAG: u64 = 0x0040_3004;
const STACK_BASE: u64 = 0x0018_0000;
const STACK_TOP: u64 = 0x0037_FF00;

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[test]
fn worker_runs_and_main_joins() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, 0x0020_0000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: false,
        api_base: 0x7000_0000,
        heap_base: 0x1000_0000,
        heap_size: 0x0010_0000,
        valloc_base: 0x3000_0000, // thread stacks live here in 32-bit mode
        echo: false,
        ..WinConfig::default()
    });

    // Resolve the thunks and seat them in the IAT the code calls through.
    let create = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("CreateThread".into()));
    let wfso = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("WaitForSingleObject".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u32(IAT_CREATE, create as u32).unwrap();
    mem.write_u32(IAT_WFSO, wfso as u32).unwrap();

    // --- main thread ---------------------------------------------------
    let mut main = Vec::new();
    // CreateThread(NULL, 0, WORKER, NULL, 0, NULL)  (stdcall, push right→left)
    main.extend([0x68]); main.extend(le32(0)); // push lpThreadId
    main.extend([0x68]); main.extend(le32(0)); // push dwCreationFlags
    main.extend([0x68]); main.extend(le32(0)); // push lpParameter
    main.extend([0x68]); main.extend(le32(WORKER as u32)); // push lpStartAddress
    main.extend([0x68]); main.extend(le32(0)); // push dwStackSize
    main.extend([0x68]); main.extend(le32(0)); // push lpThreadAttributes
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32)); // call [IAT_CREATE]
    main.extend([0xA3]); main.extend(le32(HANDLE as u32)); // mov [HANDLE], eax
    // WaitForSingleObject([HANDLE], INFINITE)
    main.extend([0x68]); main.extend(le32(0xFFFF_FFFF)); // push INFINITE
    main.extend([0xFF, 0x35]); main.extend(le32(HANDLE as u32)); // push [HANDLE]
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_WFSO as u32)); // call [IAT_WFSO]
    main.extend([0xA1]); main.extend(le32(FLAG as u32)); // mov eax, [FLAG]
    main.extend([0xC3]); // ret → exit sentinel
    mem.write(MAIN, &main).unwrap();

    // --- worker thread -------------------------------------------------
    let mut worker = Vec::new();
    worker.extend([0xC7, 0x05]); // mov dword [FLAG], 0x1234
    worker.extend(le32(FLAG as u32));
    worker.extend(le32(0x1234));
    worker.extend([0xB8]); worker.extend(le32(0x99)); // mov eax, 0x99 (exit code)
    worker.extend([0xC2, 0x04, 0x00]); // ret 4  (stdcall: clean the LPVOID arg)
    mem.write(WORKER, &worker).unwrap();

    // --- run -----------------------------------------------------------
    let mut cpu = Interpreter::with_bits(Bits::B32);
    // Push the process-exit sentinel so main's final `ret` terminates cleanly.
    mem.write_u32(STACK_TOP - 4, exit_thunk as u32).unwrap();
    cpu.state_mut().set_rsp(STACK_TOP - 4);
    cpu.state_mut().rip = MAIN;

    let mut exit_code = None;
    for _ in 0..100_000 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }

    // The worker's sentinel is present → it actually executed.
    assert_eq!(mem.read_u32(FLAG).unwrap(), 0x1234, "worker thread did not run");
    // Main resumed past its join and returned the sentinel it read.
    assert_eq!(exit_code, Some(0x1234), "main did not resume after joining the worker");
}

#[test]
fn spinning_main_is_preempted_so_worker_runs() {
    // Main busy-waits on a flag with NO API call in the loop; only timeslice
    // preemption (roadmap P3.4) can let the worker run and set the flag.
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, 0x0020_0000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: false,
        api_base: 0x7000_0000,
        heap_base: 0x1000_0000,
        heap_size: 0x0010_0000,
        valloc_base: 0x3000_0000,
        echo: false,
        ..WinConfig::default()
    });
    let create = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("CreateThread".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u32(IAT_CREATE, create as u32).unwrap();

    // main: CreateThread(worker); then `while ([FLAG]==0) {}`; return [FLAG].
    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32)); // call CreateThread
    // spin: cmp dword [FLAG], 0 ; je spin
    main.extend([0x83, 0x3D]); main.extend(le32(FLAG as u32)); main.extend([0x00]); // cmp [FLAG],0 (7 bytes)
    main.extend([0x74, 0xF7]); // je -9 → back to the cmp
    main.extend([0xA1]); main.extend(le32(FLAG as u32)); // mov eax, [FLAG]
    main.extend([0xC3]); // ret
    mem.write(MAIN, &main).unwrap();

    // worker: mov [FLAG], 0x1234 ; ret 4
    let mut worker = Vec::new();
    worker.extend([0xC7, 0x05]); worker.extend(le32(FLAG as u32)); worker.extend(le32(0x1234));
    worker.extend([0xB8]); worker.extend(le32(0));
    worker.extend([0xC2, 0x04, 0x00]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
    mem.write_u32(STACK_TOP - 4, exit_thunk as u32).unwrap();
    cpu.state_mut().set_rsp(STACK_TOP - 4);
    cpu.state_mut().rip = MAIN;

    let mut exit_code = None;
    for _ in 0..5_000_000 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert_eq!(exit_code, Some(0x1234), "preemption never let the worker set the flag");
}
