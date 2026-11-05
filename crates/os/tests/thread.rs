use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const REGION: u64 = 0x0040_0000;
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
        valloc_base: 0x3000_0000,
        echo: false,
        ..WinConfig::default()
    });

    let create = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("CreateThread".into()));
    let wfso = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("WaitForSingleObject".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u32(IAT_CREATE, create as u32).unwrap();
    mem.write_u32(IAT_WFSO, wfso as u32).unwrap();

    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32));
    main.extend([0xA3]); main.extend(le32(HANDLE as u32));
    main.extend([0x68]); main.extend(le32(0xFFFF_FFFF));
    main.extend([0xFF, 0x35]); main.extend(le32(HANDLE as u32));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_WFSO as u32));
    main.extend([0xA1]); main.extend(le32(FLAG as u32));
    main.extend([0xC3]);
    mem.write(MAIN, &main).unwrap();

    let mut worker = Vec::new();
    worker.extend([0xC7, 0x05]);
    worker.extend(le32(FLAG as u32));
    worker.extend(le32(0x1234));
    worker.extend([0xB8]); worker.extend(le32(0x99));
    worker.extend([0xC2, 0x04, 0x00]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
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

    assert_eq!(mem.read_u32(FLAG).unwrap(), 0x1234, "worker thread did not run");
    assert_eq!(exit_code, Some(0x1234), "main did not resume after joining the worker");
}

#[test]
fn tls_thread_attach_callback_runs_before_the_start_routine() {
    const TLS_CB: u64 = 0x0040_1400;
    const TLS_FLAG: u64 = 0x0040_3008;

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
    let wfso = os.resolve_import("kernel32.dll", &exemu_core::ImportSymbol::Named("WaitForSingleObject".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u32(IAT_CREATE, create as u32).unwrap();
    mem.write_u32(IAT_WFSO, wfso as u32).unwrap();
    os.set_tls_callbacks(vec![TLS_CB]);

    let mut cb = Vec::new();
    cb.extend([0x83, 0x7C, 0x24, 0x08, 0x02]);
    cb.extend([0x75, 0x0A]);
    cb.extend([0xC7, 0x05]); cb.extend(le32(TLS_FLAG as u32)); cb.extend(le32(0x55));
    cb.extend([0xC2, 0x0C, 0x00]);
    mem.write(TLS_CB, &cb).unwrap();

    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32));
    main.extend([0xA3]); main.extend(le32(HANDLE as u32));
    main.extend([0x68]); main.extend(le32(0xFFFF_FFFF));
    main.extend([0xFF, 0x35]); main.extend(le32(HANDLE as u32));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_WFSO as u32));
    main.extend([0xA1]); main.extend(le32(FLAG as u32));
    main.extend([0xC3]);
    mem.write(MAIN, &main).unwrap();

    let mut worker = Vec::new();
    worker.extend([0xA1]); worker.extend(le32(TLS_FLAG as u32));
    worker.extend([0xA3]); worker.extend(le32(FLAG as u32));
    worker.extend([0xC2, 0x04, 0x00]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
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
    assert_eq!(mem.read_u32(TLS_FLAG).unwrap(), 0x55, "TLS DLL_THREAD_ATTACH callback did not run");
    assert_eq!(exit_code, Some(0x55), "start routine ran before its TLS callback");
}

#[test]
fn spinning_main_is_preempted_so_worker_runs() {
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

    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32));
    main.extend([0x83, 0x3D]); main.extend(le32(FLAG as u32)); main.extend([0x00]);
    main.extend([0x74, 0xF7]);
    main.extend([0xA1]); main.extend(le32(FLAG as u32));
    main.extend([0xC3]);
    mem.write(MAIN, &main).unwrap();

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

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn a_jitted_spin_loop_is_still_preempted() {
    use exemu_core::Hooks;
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

    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32));
    main.extend([0x83, 0x3D]); main.extend(le32(FLAG as u32)); main.extend([0x00]);
    main.extend([0x74, 0xF7]);
    main.extend([0xA1]); main.extend(le32(FLAG as u32));
    main.extend([0xC3]);
    mem.write(MAIN, &main).unwrap();

    let mut worker = Vec::new();
    worker.extend([0xC7, 0x05]); worker.extend(le32(FLAG as u32)); worker.extend(le32(0x1234));
    worker.extend([0xB8]); worker.extend(le32(0));
    worker.extend([0xC2, 0x04, 0x00]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
    mem.write_u32(STACK_TOP - 4, exit_thunk as u32).unwrap();
    cpu.state_mut().set_rsp(STACK_TOP - 4);
    cpu.state_mut().rip = MAIN;

    let mut jit = exemu_jit::Jit::new(1 << 20).expect("JIT should be available here");
    let mut exit_code = None;
    let mut budget = 5_000_000i64;
    while budget > 0 {
        let chunk = os.retire_budget().min(budget as u64);
        match jit.run(cpu.state_mut(), &mut mem, exemu_jit::Mode::Protected, chunk) {
            exemu_jit::Run::Executed { insns } if insns > 0 => {
                budget -= insns as i64;
                Hooks::retire(&mut os, insns as u64, cpu.state_mut(), &mut mem).unwrap();
                continue;
            }
            _ => {}
        }
        budget -= 1;
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert_eq!(
        exit_code,
        Some(0x1234),
        "a JIT-compiled spin loop was never preempted, so the worker never ran"
    );
    assert!(jit.stats().insns_executed > 0, "the JIT executed nothing, so this proved nothing");
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const COUNT_MAIN: u64 = 0x0040_3008;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const COUNT_WORKER: u64 = 0x0040_300C;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn two_spinners() -> (VirtualMemory, WinOs, Interpreter) {
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
    mem.write_u32(IAT_CREATE, create as u32).unwrap();

    let mut main = Vec::new();
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(WORKER as u32));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0x68]); main.extend(le32(0));
    main.extend([0xFF, 0x15]); main.extend(le32(IAT_CREATE as u32));
    main.extend([0xFF, 0x05]); main.extend(le32(COUNT_MAIN as u32));
    main.extend([0x83, 0xC0, 0x03]);
    main.extend([0xEB, 0xF5]);
    mem.write(MAIN, &main).unwrap();

    let mut worker = Vec::new();
    worker.extend([0xFF, 0x05]); worker.extend(le32(COUNT_WORKER as u32));
    worker.extend([0x01, 0xC3]);
    worker.extend([0xD1, 0xC3]);
    worker.extend([0xF7, 0xD0]);
    worker.extend([0xEB, 0xF2]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
    cpu.state_mut().set_rsp(STACK_TOP - 4);
    cpu.state_mut().rip = MAIN;
    (mem, os, cpu)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn spin_for(steps: u64, mut jit: Option<&mut exemu_jit::Jit>) -> (exemu_core::CpuState, u32, u32) {
    use exemu_core::Hooks;
    let (mut mem, mut os, mut cpu) = two_spinners();
    let mut done = 0u64;
    while done < steps {
        if let Some(j) = jit.as_deref_mut() {
            let budget = os.retire_budget().min(steps - done);
            let ran = j.run(cpu.state_mut(), &mut mem, exemu_jit::Mode::Protected, budget);
            let n = u64::from(ran.insns());
            assert!(n <= budget, "the JIT retired {n} against a budget of {budget} at step {done}");
            if n != 0 {
                done += n;
                Hooks::retire(&mut os, n, cpu.state_mut(), &mut mem).unwrap();
            }
            if matches!(ran, exemu_jit::Run::Executed { .. }) {
                continue;
            }
        }
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => done += 1,
            other => panic!("unexpected exit at step {done}: {other:?}"),
        }
    }
    let main = mem.read_u32(COUNT_MAIN).unwrap();
    let worker = mem.read_u32(COUNT_WORKER).unwrap();
    (cpu.state().clone(), main, worker)
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn a_jitted_thread_is_preempted_at_the_interpreters_instruction() {
    let steps = 230_017;
    let (want, want_main, want_worker) = spin_for(steps, None);
    assert!(want_main > 0 && want_worker > 0, "both threads must have run");
    let mut jit = exemu_jit::Jit::new(1 << 20).expect("JIT should be available here");
    let (got, got_main, got_worker) = spin_for(steps, Some(&mut jit));
    assert_eq!(got_main, want_main, "main's counter: the JIT switched at a different instruction");
    assert_eq!(got_worker, want_worker, "worker's counter");
    assert_eq!(got.rip, want.rip, "rip");
    assert_eq!(got.gpr, want.gpr, "registers");
    assert_eq!(got.rflags, want.rflags, "flags");
    assert!(jit.stats().insns_executed > steps / 2, "the JIT barely ran, so this proved nothing");
    assert!(jit.stats().budget_refusals > 0, "no timeslice ever ended inside a block");
}
