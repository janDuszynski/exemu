use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const REGION: u64 = 0x0040_0000;
const MAIN: u64 = 0x0040_1000;
const WORKER: u64 = 0x0040_1100;
const IAT_CREATE: u64 = 0x0040_2000;
const IAT_WFSO: u64 = 0x0040_2004;
const IAT_PROLOG: u64 = 0x0040_2008;
const HANDLE: u64 = 0x0040_3000;
const WORKER_HEAD: u64 = 0x0040_3004;
const WORKER_TEB: u64 = 0x0040_3008;
const STACK_BASE: u64 = 0x0018_0000;
const STACK_TOP: u64 = 0x0037_FF00;
const SENTINEL: u32 = 0xA5A5_A5A5;

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[test]
fn eh_prolog_in_a_worker_thread_links_its_own_teb() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, 0x0020_0000, Perm::RW)).unwrap();
    mem.map(Region::new("main-teb", FS_BASE_32, 0x1000, Perm::RW)).unwrap();
    mem.write_u32(FS_BASE_32, SENTINEL).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: false,
        api_base: 0x7000_0000,
        heap_base: 0x1000_0000,
        heap_size: 0x0010_0000,
        valloc_base: 0x3000_0000,
        echo: false,
        ..WinConfig::default()
    });

    let create = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    let wfso = os.resolve_import("kernel32.dll", &ImportSymbol::Named("WaitForSingleObject".into()));
    let prolog = os.resolve_import("msvcrt.dll", &ImportSymbol::Named("_EH_prolog".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u32(IAT_CREATE, create as u32).unwrap();
    mem.write_u32(IAT_WFSO, wfso as u32).unwrap();
    mem.write_u32(IAT_PROLOG, prolog as u32).unwrap();

    let mut main = Vec::new();
    main.extend([0x68]);
    main.extend(le32(0));
    main.extend([0x68]);
    main.extend(le32(0));
    main.extend([0x68]);
    main.extend(le32(0));
    main.extend([0x68]);
    main.extend(le32(WORKER as u32));
    main.extend([0x68]);
    main.extend(le32(0));
    main.extend([0x68]);
    main.extend(le32(0));
    main.extend([0xFF, 0x15]);
    main.extend(le32(IAT_CREATE as u32));
    main.extend([0xA3]);
    main.extend(le32(HANDLE as u32));
    main.extend([0x68]);
    main.extend(le32(0xFFFF_FFFF));
    main.extend([0xFF, 0x35]);
    main.extend(le32(HANDLE as u32));
    main.extend([0xFF, 0x15]);
    main.extend(le32(IAT_WFSO as u32));
    main.extend([0xC3]);
    mem.write(MAIN, &main).unwrap();

    let mut worker = Vec::new();
    worker.extend([0xFF, 0x15]);
    worker.extend(le32(IAT_PROLOG as u32));
    worker.extend([0x64, 0xA1, 0, 0, 0, 0, 0xA3]);
    worker.extend(le32(WORKER_HEAD as u32));
    worker.extend([0x64, 0xA1, 0x18, 0, 0, 0, 0xA3]);
    worker.extend(le32(WORKER_TEB as u32));
    worker.extend([0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00]);
    mem.write(WORKER, &worker).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B32);
    mem.write_u32(STACK_TOP - 4, exit_thunk as u32).unwrap();
    cpu.state_mut().set_rsp(STACK_TOP - 4);
    cpu.state_mut().rip = MAIN;

    let mut exited = false;
    for _ in 0..100_000 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(_) => {
                exited = true;
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    assert!(exited, "process never exited");

    let teb = u64::from(mem.read_u32(WORKER_TEB).unwrap());
    let head = mem.read_u32(WORKER_HEAD).unwrap();
    assert_ne!(teb, 0, "worker never reached the TEB read");
    assert_ne!(teb, FS_BASE_32, "worker shares the main thread's TEB");
    assert_ne!(head, 0xFFFF_FFFF, "record was not linked into the worker chain");
    assert!(u64::from(head) >= 0x3000_0000, "head is a record on the worker stack");
    assert_eq!(mem.read_u32(FS_BASE_32).unwrap(), SENTINEL, "main thread chain untouched");
}
