use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const REGION: u64 = 0x0000_0000_0040_0000;
const REGION_SIZE: u64 = 0x0001_0000;
const MAIN: u64 = REGION + 0x1000;
const WORKER: u64 = REGION + 0x1800;
const IAT_CREATE: u64 = REGION + 0x2000;
const IAT_WFSO: u64 = REGION + 0x2008;
const IAT_SWITCH: u64 = REGION + 0x2010;
const COUNTER: u64 = REGION + 0x3000;
const ITERS: u64 = REGION + 0x3008;
const HANDLE0: u64 = REGION + 0x3100;

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const PEB: u64 = GS_BASE + 0x3000;

const N_WORKERS: usize = 2;
const N_THREADS: u64 = N_WORKERS as u64 + 1;
const K: u64 = 500;
const INFINITE: u64 = 0xFFFF_FFFF;

fn cas_loop_body(out: &mut Vec<u8>) {
    out.extend([0x4D, 0x31, 0xFF]);
    let loop_start = out.len();
    out.extend([0xF0, 0x48, 0xFF, 0x04, 0x25]);
    out.extend((ITERS as u32).to_le_bytes());
    out.extend([0x4C, 0x8B, 0x34, 0x25]);
    out.extend((COUNTER as u32).to_le_bytes());
    out.extend([0xFF, 0x14, 0x25]);
    out.extend((IAT_SWITCH as u32).to_le_bytes());
    out.extend([0x4C, 0x89, 0xF0]);
    out.extend([0x49, 0x8D, 0x56, 0x01]);
    out.extend([0xF0, 0x48, 0x0F, 0xB1, 0x14, 0x25]);
    out.extend((COUNTER as u32).to_le_bytes());
    out.extend([0x0F, 0x85]);
    let after = out.len() + 4;
    out.extend(((loop_start as i64 - after as i64) as i32).to_le_bytes());
    out.extend([0x49, 0xFF, 0xC7]);
    out.extend([0x49, 0x81, 0xFF]);
    out.extend((K as u32).to_le_bytes());
    out.extend([0x0F, 0x82]);
    let after2 = out.len() + 4;
    out.extend(((loop_start as i64 - after2 as i64) as i32).to_le_bytes());
    out.push(0xC3);
}

#[test]
fn lock_cmpxchg_cas_increment_never_loses_an_update() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, REGION_SIZE, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x4000, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x3000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        valloc_base: 0x0000_0040_0000_0000,
        ..WinConfig::default()
    });

    let create = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    let wfso = os.resolve_import("kernel32.dll", &ImportSymbol::Named("WaitForSingleObject".into()));
    let switch = os.resolve_import("kernel32.dll", &ImportSymbol::Named("SwitchToThread".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u64(IAT_CREATE, create).unwrap();
    mem.write_u64(IAT_WFSO, wfso).unwrap();
    mem.write_u64(IAT_SWITCH, switch).unwrap();
    mem.write_u64(COUNTER, 0).unwrap();
    mem.write_u64(ITERS, 0).unwrap();

    let mut worker = Vec::new();
    cas_loop_body(&mut worker);
    mem.write(WORKER, &worker).unwrap();

    let mut main = Vec::new();
    main.extend([0x48, 0x83, 0xEC, 0x40]);
    for w in 0..N_WORKERS {
        main.extend([0x31, 0xC9]);
        main.extend([0x31, 0xD2]);
        main.extend([0x49, 0xB8]);
        main.extend(WORKER.to_le_bytes());
        main.extend([0x45, 0x31, 0xC9]);
        main.extend([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        main.extend([0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        main.extend([0xFF, 0x14, 0x25]);
        main.extend((IAT_CREATE as u32).to_le_bytes());
        main.extend([0x48, 0x89, 0x04, 0x25]);
        main.extend(((HANDLE0 + w as u64 * 8) as u32).to_le_bytes());
    }
    let mut body = Vec::new();
    cas_loop_body(&mut body);
    body.pop();
    main.extend_from_slice(&body);
    for w in 0..N_WORKERS {
        main.extend([0x48, 0x8B, 0x0C, 0x25]);
        main.extend(((HANDLE0 + w as u64 * 8) as u32).to_le_bytes());
        main.extend([0xBA]);
        main.extend((INFINITE as u32).to_le_bytes());
        main.extend([0xFF, 0x14, 0x25]);
        main.extend((IAT_WFSO as u32).to_le_bytes());
    }
    main.extend([0x48, 0x8B, 0x04, 0x25]);
    main.extend((COUNTER as u32).to_le_bytes());
    main.extend([0x48, 0x83, 0xC4, 0x40]);
    main.push(0xC3);
    mem.write(MAIN, &main).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = (STACK_TOP - 0x100) & !0xf;
    let rsp = rsp - 8;
    mem.write_u64(rsp, exit_thunk).unwrap();
    {
        let s = cpu.state_mut();
        s.rip = MAIN;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE;
        s.fs_base = GS_BASE;
    }

    let mut exit_code = None;
    for _ in 0..50_000_000u64 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }

    let final_counter = mem.read_u64(COUNTER).unwrap();
    let expected = N_THREADS * K;
    assert_eq!(
        final_counter, expected,
        "lost an update: {N_THREADS} threads × {K} lock-cmpxchg increments should total {expected}, got {final_counter}",
    );
    assert_eq!(
        exit_code,
        Some(expected as i32),
        "main did not resume past the joins with the final counter",
    );
    let total_iters = mem.read_u64(ITERS).unwrap();
    assert!(
        total_iters > expected,
        "threads did not interleave over the shared counter: {total_iters} iterations for {expected} increments (expected retries from contention)",
    );
}
