use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const NTDLL: &str = "../../example_exe/wine-dlls/x86_64-windows/ntdll.dll";
const WOW64CPU: &str = "../../example_exe/wine-dlls/x86_64-windows/wow64cpu.dll";
const WOW64CPU_BASE: u64 = 0x0000_0000_6A40_0000;
const WOW64: &str = "../../example_exe/wine-dlls/x86_64-windows/wow64.dll";
const WOW64_BASE: u64 = 0x0000_0000_6B00_0000;

const KUSER_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER: u64 = 0x7ffe_1000;
const KUSER_SYSTEM_CALL: u64 = 0x308;

const GS_BASE: u64 = 0x7fff_0000_0000;
const PEB_BASE: u64 = GS_BASE + 0x2000;

const NTDLL_BASE: u64 = 0x0000_0006_0000_0000;

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const STACK_SIZE: u64 = 0x4000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SCRATCH_SIZE: u64 = 0x4000;
const SENTINEL: u64 = 0x0000_0000_6000_0000;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;

struct Dll {
    base: u64,
    exports: HashMap<String, u64>,
    imports: Vec<(u32, String)>,
}

impl Dll {
    fn export(&self, name: &str) -> u64 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("{name} not exported by the loaded DLL"))
    }
}

fn bind_imports(mem: &mut VirtualMemory, dll: &Dll, provider: &Dll) -> usize {
    let mut bound = 0;
    for (iat_rva, name) in &dll.imports {
        if let Some(&addr) = provider.exports.get(name) {
            mem.write_u64(dll.base + *iat_rva as u64, addr).unwrap();
            bound += 1;
        }
    }
    bound
}

fn ssdt_index_of(mem: &VirtualMemory, dll: &Dll, name: &str) -> u32 {
    let stub = dll.export(name);
    let mut head = [0u8; 4];
    mem.read(stub, &mut head).expect("the stub is mapped");
    assert_eq!(&head, &[0x4C, 0x8B, 0xD1, 0xB8], "{name} is not a `mov r10,rcx; mov eax,N` syscall stub");
    mem.read_u32(stub + 4).unwrap()
}

fn load_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Dll {
    let mut image = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    assert!(image.is_64bit, "the x86_64-windows DLL must be PE32+");

    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)
        .expect("apply base relocations");

    let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
    mem.map(Region::new("dll_headers", base, hdr_len, Perm::RWX)).unwrap();
    mem.write(base, &image.headers).unwrap();
    for s in &image.sections {
        let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
        let map_len = align_up(vsize, 0x1000).max(0x1000);
        let addr = base + s.rva as u64;
        if mem.map(Region::new("dll_section", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
            mem.write(addr, &s.data).unwrap();
        } else if !s.data.is_empty() {
            mem.poke(addr, &s.data).unwrap();
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    let imports = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    Dll { base, exports, imports }
}

fn setup(sandbox: &Path) -> (WinOs, VirtualMemory, Dll) {
    let bytes = std::fs::read(NTDLL).expect("read ntdll.dll");
    let mut mem = VirtualMemory::new();

    mem.map(Region::new("kuser", KUSER_BASE, 0x1000, Perm::READ)).unwrap();
    mem.map(Region::new("dispatcher", KUSER_DISPATCHER, 0x1000, Perm::RWX)).unwrap();
    mem.poke(KUSER_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes()).unwrap();

    mem.map(Region::new("stack", STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, SCRATCH_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_BASE, 0x1000, Perm::RW)).unwrap();

    let dll = load_dll(&mut mem, &bytes, NTDLL_BASE);

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB_BASE,
        sandbox: sandbox.to_string_lossy().into_owned(),
        ..WinConfig::default()
    });
    os.register_ntdll_unixlib(dll.base);
    (os, mem, dll)
}

fn call_export(os: &mut WinOs, mem: &mut VirtualMemory, entry: u64, args: &[u64]) -> u64 {
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = entry;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE;
        let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().take(4).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    mem.write_u64(rsp, SENTINEL).unwrap();
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os).expect("ntdll stub faulted (a W2 gate defect)") {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit driving ntdll export: {other:?}"),
        }
    }
    cpu.state().reg(Reg::Rax)
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn write_unicode_string(mem: &mut VirtualMemory, us_ptr: u64, buf_ptr: u64, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(buf_ptr + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(us_ptr, bytes).unwrap();
    mem.write_u16(us_ptr + 2, bytes).unwrap();
    mem.write_u32(us_ptr + 4, 0).unwrap();
    mem.write_u64(us_ptr + 8, buf_ptr).unwrap();
}

fn write_object_attributes(mem: &mut VirtualMemory, oa_ptr: u64, nt_path: &str) {
    let us_ptr = oa_ptr + 0x20;
    let buf_ptr = oa_ptr + 0x40;
    mem.write_u32(oa_ptr, 0x30).unwrap();
    mem.write_u64(oa_ptr + 8, 0).unwrap();
    mem.write_u64(oa_ptr + 0x10, us_ptr).unwrap();
    mem.write_u32(oa_ptr + 0x18, 0).unwrap();
    write_unicode_string(mem, us_ptr, buf_ptr, nt_path);
}

fn filetime_host_now() -> u64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (d.as_secs() + EPOCH_DIFF_SECS) * 10_000_000 + d.subsec_nanos() as u64 / 100
}

#[test]
fn ntdll_alloc_time_file_event_through_dispatcher() {
    if !Path::new(NTDLL).exists() {
        eprintln!("SKIP: {NTDLL} not present (Wine DLL set is git-ignored) — deferred to a host with the DLLs");
        return;
    }

    let dir = std::env::temp_dir().join(format!("exemu-w2_16-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, dll) = setup(&dir);

    for name in [
        "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueryVirtualMemory",
        "NtQuerySystemTime",
        "NtQueryPerformanceCounter",
        "NtCreateFile",
        "NtWriteFile",
        "NtReadFile",
        "NtClose",
        "NtCreateEvent",
        "NtSetEvent",
        "NtWaitForSingleObject",
    ] {
        assert!(dll.exports.contains_key(name), "ntdll must export {name} as a non-forwarder stub");
    }

    alloc_capability(&mut os, &mut mem, &dll);
    time_capability(&mut os, &mut mem, &dll);
    file_capability(&mut os, &mut mem, &dll, &dir);
    event_capability(&mut os, &mut mem, &dll);

    let _ = std::fs::remove_dir_all(&dir);
}

fn alloc_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const MEM_COMMIT_RESERVE: u64 = 0x3000;
    const MEM_RELEASE: u64 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const STATE_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x0002_0000;
    const CURRENT_PROCESS: u64 = u64::MAX;

    let base_ptr = SCRATCH;
    let size_ptr = SCRATCH + 0x10;
    mem.write_u64(base_ptr, 0).unwrap();
    mem.write_u64(size_ptr, 0x2000).unwrap();

    let st = call_export(
        os,
        mem,
        dll.export("NtAllocateVirtualMemory"),
        &[CURRENT_PROCESS, base_ptr, 0, size_ptr, MEM_COMMIT_RESERVE, PAGE_READWRITE as u64],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtAllocateVirtualMemory (ntdll stub)");
    let base = mem.read_u64(base_ptr).unwrap();
    assert_ne!(base, 0, "kernel wrote back a base");
    assert_eq!(base & 0xFFFF, 0, "base 64 KiB aligned");
    assert_eq!(mem.read_u64(size_ptr).unwrap(), 0x2000, "size written back");
    mem.write_u64(base, 0xdead_beef_cafe_babe).unwrap();
    assert_eq!(mem.read_u64(base).unwrap(), 0xdead_beef_cafe_babe, "backing is writable");

    let pbase = SCRATCH + 0x20;
    let psize = SCRATCH + 0x28;
    let old = SCRATCH + 0x30;
    mem.write_u64(pbase, base).unwrap();
    mem.write_u64(psize, 0x1000).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtProtectVirtualMemory"),
        &[CURRENT_PROCESS, pbase, psize, PAGE_EXECUTE_READ as u64, old],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtProtectVirtualMemory (ntdll stub)");
    assert_eq!(mem.read_u32(old).unwrap(), PAGE_READWRITE, "old protect written back");

    let mbi = SCRATCH + 0x100;
    let ret = SCRATCH + 0x40;
    let st = call_export(
        os,
        mem,
        dll.export("NtQueryVirtualMemory"),
        &[CURRENT_PROCESS, base, 0, mbi, 0x30, ret],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryVirtualMemory (ntdll stub)");
    assert_eq!(mem.read_u64(ret).unwrap(), 0x30, "ReturnLength = sizeof(MBI)");
    assert_eq!(mem.read_u64(mbi).unwrap(), base, "MBI.BaseAddress");
    assert_eq!(mem.read_u64(mbi + 0x18).unwrap(), 0x2000, "MBI.RegionSize");
    assert_eq!(mem.read_u32(mbi + 0x20).unwrap(), STATE_COMMIT, "MBI.State = COMMIT");
    assert_eq!(mem.read_u32(mbi + 0x24).unwrap(), PAGE_EXECUTE_READ, "MBI.Protect");
    assert_eq!(mem.read_u32(mbi + 0x28).unwrap(), MEM_PRIVATE, "MBI.Type = MEM_PRIVATE");

    let fbase = SCRATCH + 0x50;
    let fsize = SCRATCH + 0x58;
    mem.write_u64(fbase, base).unwrap();
    mem.write_u64(fsize, 0).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtFreeVirtualMemory"),
        &[CURRENT_PROCESS, fbase, fsize, MEM_RELEASE],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtFreeVirtualMemory (ntdll stub)");
    assert!(mem.read_u64(base).is_err(), "released memory is unmapped");
}

fn time_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const QPC_FREQ: u64 = 10_000_000;
    let out = SCRATCH;

    let before = filetime_host_now();
    let st = call_export(os, mem, dll.export("NtQuerySystemTime"), &[out]);
    let after = filetime_host_now();
    assert_eq!(st, STATUS_SUCCESS, "NtQuerySystemTime (ntdll stub)");
    let t = mem.read_u64(out).unwrap();
    assert!(before <= t && t <= after, "system time {t} not in [{before}, {after}]");

    let st = call_export(os, mem, dll.export("NtQuerySystemTime"), &[0]);
    assert_eq!(st, STATUS_ACCESS_VIOLATION, "NtQuerySystemTime(NULL) → AV");

    let counter = SCRATCH + 0x40;
    let freq = SCRATCH + 0x48;
    let st = call_export(os, mem, dll.export("NtQueryPerformanceCounter"), &[counter, freq]);
    assert_eq!(st, STATUS_SUCCESS, "NtQueryPerformanceCounter (ntdll stub)");
    let first = mem.read_u64(counter).unwrap();
    assert_eq!(mem.read_u64(freq).unwrap(), QPC_FREQ, "QPC frequency = 10 MHz");

    let st = call_export(os, mem, dll.export("NtQueryPerformanceCounter"), &[counter, 0]);
    assert_eq!(st, STATUS_SUCCESS);
    let second = mem.read_u64(counter).unwrap();
    assert!(second >= first, "QPC counter went backwards: {second} < {first}");
}

fn file_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll, sandbox: &Path) {
    const FILE_CREATE: u64 = 2;
    const FILE_CREATED: u64 = 2;
    const GENERIC_WRITE: u64 = 0x4000_0000;

    std::fs::create_dir_all(sandbox.join("C").join("out")).unwrap();
    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let byteoff_ptr = SCRATCH + 0x20;
    let oa_ptr = SCRATCH + 0x100;
    let data_ptr = SCRATCH + 0x300;

    write_object_attributes(mem, oa_ptr, "\\??\\C:\\out\\hello.txt");
    let st = call_export(
        os,
        mem,
        dll.export("NtCreateFile"),
        &[handle_ptr, GENERIC_WRITE, oa_ptr, iosb_ptr, 0, 0x80, 0, FILE_CREATE, 0x60, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateFile (ntdll stub)");
    let handle = mem.read_u64(handle_ptr).unwrap();
    assert_ne!(handle, 0, "a file handle was written back");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), FILE_CREATED, "IOSB.Information = FILE_CREATED");

    let payload = b"hello from the wine ntdll dll-smoke harness";
    mem.write(data_ptr, payload).unwrap();
    mem.write_u64(byteoff_ptr, 0).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtWriteFile"),
        &[handle, 0, 0, 0, iosb_ptr, data_ptr, payload.len() as u64, byteoff_ptr, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWriteFile (ntdll stub)");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), payload.len() as u64, "IOSB = bytes written");

    let host_file = sandbox.join("C").join("out").join("hello.txt");
    assert!(host_file.exists(), "the file was created on the host under the sandbox");
    assert_eq!(std::fs::read(&host_file).unwrap(), payload, "host file has the written bytes");

    mem.write_u64(byteoff_ptr, 0).unwrap();
    mem.write(data_ptr, &[0u8; 64]).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtReadFile"),
        &[handle, 0, 0, 0, iosb_ptr, data_ptr, 64, byteoff_ptr, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtReadFile (ntdll stub)");
    let n = mem.read_u64(iosb_ptr + 8).unwrap() as usize;
    assert_eq!(n, payload.len(), "IOSB = bytes read");
    let mut got = vec![0u8; n];
    mem.read(data_ptr, &mut got).unwrap();
    assert_eq!(&got, payload, "read-back bytes match");

    let st = call_export(os, mem, dll.export("NtClose"), &[handle]);
    assert_eq!(st, STATUS_SUCCESS, "NtClose (ntdll stub) on the file handle");
}

fn event_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const NOTIFICATION_EVENT: u64 = 0;
    const INITIAL_SIGNALED: u64 = 1;

    let handle_ptr = SCRATCH;
    let prev_ptr = SCRATCH + 0x40;
    let zero_timeout = SCRATCH + 0x80;

    let st = call_export(
        os,
        mem,
        dll.export("NtCreateEvent"),
        &[handle_ptr, 0, 0, NOTIFICATION_EVENT, INITIAL_SIGNALED],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateEvent (ntdll stub)");
    let handle = mem.read_u64(handle_ptr).unwrap();
    assert_ne!(handle, 0, "an event handle was written back");

    let st = call_export(os, mem, dll.export("NtSetEvent"), &[handle, prev_ptr]);
    assert_eq!(st, STATUS_SUCCESS, "NtSetEvent (ntdll stub)");

    mem.write_u64(zero_timeout, 0).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtWaitForSingleObject"),
        &[handle, 0, zero_timeout],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWaitForSingleObject(zero-timeout) → STATUS_WAIT_0");

    let st = call_export(os, mem, dll.export("NtClose"), &[handle]);
    assert_eq!(st, STATUS_SUCCESS, "NtClose (ntdll stub) on the event handle");
}

#[test]
fn wow64cpu_loads_and_bopcode_stub_runs() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }

    let dir = std::env::temp_dir().join(format!("exemu-w5_1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);

    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);

    for name in ["BTCpuProcessInit", "BTCpuSimulate", "BTCpuGetBopCode", "BTCpuGetContext", "BTCpuSetContext"] {
        assert!(wow64cpu.exports.contains_key(name), "wow64cpu must export {name}");
    }

    const BOP_SLOT_RVA: u64 = 0x7000;
    let ptr = call_export(&mut os, &mut mem, wow64cpu.export("BTCpuGetBopCode"), &[]);
    assert_eq!(
        ptr,
        WOW64CPU_BASE + BOP_SLOT_RVA,
        "BTCpuGetBopCode's rip-relative lea resolves to the BOP slot after relocation"
    );
    let mut buf = [0u8; 4];
    mem.read(ptr, &mut buf).expect("the BOP slot is mapped");
}

fn drive_btcpusimulate_guest(resume: bool) -> u32 {
    let dir = std::env::temp_dir().join(format!("exemu-w5_4-{}-{resume}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);

    const GUEST_CODE: u64 = 0x0040_0000;
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();
    mem.write(GUEST_CODE, &[0xC7, 0x05, 0x00, 0x00, 0x42, 0x00, 0xBE, 0xBA, 0xFE, 0xCA, 0xF4]).unwrap();

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);
    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: GUEST_CODE as u32,
        esp: GUEST_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();
    if resume {
        mem.write_u32(CPU_AREA, 1).unwrap();
    }

    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);
    mem.read_u32(SENTINEL32).unwrap()
}

#[test]
fn btcpusimulate_switches_into_a_32bit_guest() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    assert_eq!(drive_btcpusimulate_guest(false), 0xCAFE_BABE, "far-jmp path: 32-bit guest ran");
}

#[test]
fn btcpusimulate_iretq_path_switches_into_a_32bit_guest() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    assert_eq!(drive_btcpusimulate_guest(true), 0xCAFE_BABE, "iretq path: 32-bit guest ran");
}

#[test]
fn btcpusimulate_round_trips_32bit_to_64bit() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w5_rt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);

    const GUEST_CODE: u64 = 0x0040_0000;
    const STUB64: u64 = 0x0040_1000;
    const RET_PTR: u64 = 0x0040_2000;
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    const SENTINEL64: u64 = 0x0042_0004;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();

    mem.write(GUEST_CODE, &[0xC7, 0x05, 0x00, 0x00, 0x42, 0x00, 0xBE, 0xBA, 0xFE, 0xCA]).unwrap();
    mem.write(GUEST_CODE + 10, &[0xFF, 0x2D, 0x00, 0x20, 0x40, 0x00]).unwrap();
    mem.write_u32(RET_PTR, STUB64 as u32).unwrap();
    mem.write_u16(RET_PTR + 4, 0x33).unwrap();
    mem.write(STUB64, &[0x48, 0xB8]).unwrap();
    mem.write_u64(STUB64 + 2, SENTINEL64).unwrap();
    mem.write(STUB64 + 10, &[0xC7, 0x00, 0x0D, 0xF0, 0x00, 0x00, 0xF4]).unwrap();

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);
    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: GUEST_CODE as u32,
        esp: GUEST_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();

    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);

    assert_eq!(mem.read_u32(SENTINEL32).unwrap(), 0xCAFE_BABE, "32-bit guest ran (64→32)");
    assert_eq!(mem.read_u32(SENTINEL64).unwrap(), 0x0000_F00D, "64-bit stub ran after the reverse switch (32→64)");
}

fn run_wow64_process_init(os: &mut WinOs, mem: &mut VirtualMemory, wow64cpu: &Dll) {
    let base = wow64cpu.base;

    const STUBS: u64 = 0x0000_0000_5200_0000;
    const FIND_RET: u64 = STUBS + 0x200;
    mem.map(Region::new("wow64_stubs", STUBS, 0x1000, Perm::RWX)).unwrap();

    let mut a = vec![0x48, 0xB8];
    a.extend_from_slice(&NTDLL_BASE.to_le_bytes());
    a.extend_from_slice(&[0x49, 0x89, 0x01, 0x31, 0xC0, 0xC3]);
    let mut b = vec![0x48, 0xB8];
    b.extend_from_slice(&FIND_RET.to_le_bytes());
    b.push(0xC3);
    let c = vec![
        0x66, 0xC7, 0x41, 0x38, 0x33, 0x00,
        0x66, 0xC7, 0x41, 0x3A, 0x2B, 0x00,
        0x66, 0xC7, 0x41, 0x3E, 0x53, 0x00,
        0xC3,
    ];
    let d = vec![
        0xC7, 0x82, 0xBC, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
        0xC7, 0x82, 0xC8, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x00,
        0x31, 0xC0, 0xC3,
    ];
    let e = vec![0x31, 0xC0, 0xC3];

    let (stub_a, stub_b, stub_c, stub_d, stub_e) =
        (STUBS, STUBS + 0x40, STUBS + 0x80, STUBS + 0xC0, STUBS + 0x100);
    mem.write(stub_a, &a).unwrap();
    mem.write(stub_b, &b).unwrap();
    mem.write(stub_c, &c).unwrap();
    mem.write(stub_d, &d).unwrap();
    mem.write(stub_e, &e).unwrap();

    mem.write_u64(base + 0x90b8, stub_a).unwrap();
    mem.write_u64(base + 0x90d0, stub_b).unwrap();
    mem.write_u64(base + 0x90c8, stub_c).unwrap();
    mem.write_u64(base + 0x90e0, stub_d).unwrap();
    mem.write_u64(base + 0x90c0, stub_e).unwrap();

    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    mem.write_u64(GS_BASE + 0x14d0, SCRATCH).unwrap();

    call_export(os, mem, wow64cpu.export("BTCpuProcessInit"), &[]);
}

#[test]
fn btcpuprocessinit_builds_the_return_bop_and_selectors() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w5_1init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);
    let base = wow64cpu.base;

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);

    assert_eq!(mem.read_u16(base + 0x7000).unwrap(), 0x2DFF, "BOP opcode = FF 2D (jmp fword [mem])");
    assert_eq!(
        mem.read_u32(base + 0x7006).unwrap(),
        (base + 0x1110) as u32,
        "BOP far-ptr offset = the 64-bit return handler",
    );
    assert_eq!(mem.read_u16(base + 0x700a).unwrap(), 0x33, "BOP far-ptr selector = 64-bit CS");
    assert_eq!(
        mem.read_u32(base + 0x7002).unwrap(),
        (base + 0x7006) as u32,
        "BOP disp32 = abs32(far-ptr) — the sub-4 GiB requirement",
    );

    assert_eq!(mem.read_u32(base + 0x600c).unwrap(), exemu_os::wow64::SEL_CS32, "32-bit CS = 0x23");
    assert_eq!(mem.read_u32(base + 0x6008).unwrap(), exemu_os::wow64::SEL_SS32, "32-bit SS = 0x2b");
    assert_eq!(mem.read_u16(base + 0x6014).unwrap(), 0x33, "64-bit CS = 0x33");
}

#[test]
fn wow64_guest_syscall_round_trips_through_the_real_bop() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w5_1bop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);
    let base = wow64cpu.base;

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);

    const SVC: u64 = 0x0000_0000_5300_0000;
    const RECORD: u64 = SVC + 0x100;
    mem.map(Region::new("wow64_svc", SVC, 0x1000, Perm::RWX)).unwrap();
    let mut svc = vec![0x48, 0xB8];
    svc.extend_from_slice(&RECORD.to_le_bytes());
    svc.extend_from_slice(&[0x89, 0x08]);
    svc.extend_from_slice(&[0xB8, 0x0D, 0xD0, 0x00, 0x00]);
    svc.push(0xC3);
    mem.write(SVC, &svc).unwrap();
    mem.write_u64(base + 0x9110, SVC).unwrap();

    const GUEST_CODE: u64 = 0x0040_0000;
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    const INDEX: u32 = 0x0000_1234;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();
    let bop = base + 0x7000;
    let call_next = GUEST_CODE + 5 + 5;
    let rel32 = (bop as i64 - call_next as i64) as i32 as u32;
    let mut g = vec![0xB8];
    g.extend_from_slice(&INDEX.to_le_bytes());
    g.push(0xE8);
    g.extend_from_slice(&rel32.to_le_bytes());
    g.extend_from_slice(&[0x89, 0x05, 0x00, 0x00, 0x42, 0x00]);
    g.push(0xF4);
    mem.write(GUEST_CODE, &g).unwrap();

    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: GUEST_CODE as u32,
        esp: GUEST_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();

    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);

    assert_eq!(mem.read_u32(RECORD).unwrap(), INDEX, "Wow64SystemServiceEx received the guest's service index");
    assert_eq!(mem.read_u32(SENTINEL32).unwrap(), 0x0000_D00D, "the 32-bit guest resumed with the service result in eax");
}

const G32_REGION: u64 = 0x0040_0000;
const G32_CALLER: u64 = G32_REGION;
const G32_STUB: u64 = G32_REGION + 0x100;
const G32_SVC_CALL: u64 = G32_REGION + 0x200;
const G32_TRANSITION: u64 = G32_REGION + 0x300;
const G32_STACK: u64 = 0x0041_0000;
const G32_STATUS: u64 = 0x0042_0000;
const G32_ESP_OUT: u64 = 0x0042_0004;
const G32_OUT: u64 = 0x0042_0008;
const G32_INOUT_A: u64 = 0x0042_0010;
const G32_INOUT_B: u64 = 0x0042_0014;

fn build_wow64_syscall_guest(mem: &mut VirtualMemory, bop: u64, index: u32, args: &[u32]) {
    mem.map(Region::new("guest32", G32_REGION, 0x3_0000, Perm::RWX)).unwrap();

    let mut c = Vec::new();
    for a in args.iter().rev() {
        c.push(0x68);
        c.extend_from_slice(&a.to_le_bytes());
    }
    c.push(0xE8);
    let after_call = G32_CALLER + c.len() as u64 + 4;
    c.extend_from_slice(&((G32_STUB as i64 - after_call as i64) as i32).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x05]);
    c.extend_from_slice(&(G32_STATUS as u32).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x25]);
    c.extend_from_slice(&(G32_ESP_OUT as u32).to_le_bytes());
    c.push(0xF4);
    mem.write(G32_CALLER, &c).unwrap();

    let mut s = vec![0xB8];
    s.extend_from_slice(&index.to_le_bytes());
    s.push(0xBA);
    s.extend_from_slice(&(G32_SVC_CALL as u32).to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD2]);
    s.push(0xC2);
    s.extend_from_slice(&((args.len() * 4) as u16).to_le_bytes());
    mem.write(G32_STUB, &s).unwrap();

    let mut j = vec![0xFF, 0x25];
    j.extend_from_slice(&(G32_TRANSITION as u32).to_le_bytes());
    mem.write(G32_SVC_CALL, &j).unwrap();

    exemu_os::wow64::publish_wow64_transition(mem, G32_TRANSITION, bop).unwrap();
}

#[test]
fn wow64_transition_routes_a_32bit_ntdll_stub_through_the_real_bop() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w5_1trans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);
    let base = wow64cpu.base;

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);

    let bop = call_export(&mut os, &mut mem, wow64cpu.export("BTCpuGetBopCode"), &[]);
    assert_eq!(mem.read_u16(bop).unwrap(), 0x2DFF, "BTCpuGetBopCode points at the init-built `FF 2D` far jmp");

    const SVC: u64 = 0x0000_0000_5300_0000;
    const RECORD_INDEX: u64 = SVC + 0x100;
    const RECORD_ARG0: u64 = SVC + 0x104;
    mem.map(Region::new("wow64_svc", SVC, 0x1000, Perm::RWX)).unwrap();
    let mut svc = vec![0x48, 0xB8];
    svc.extend_from_slice(&RECORD_INDEX.to_le_bytes());
    svc.extend_from_slice(&[0x89, 0x08]);
    svc.extend_from_slice(&[0x8B, 0x0A]);
    svc.extend_from_slice(&[0x89, 0x48, 0x04]);
    svc.extend_from_slice(&[0xB8, 0x0D, 0xD0, 0x00, 0x00]);
    svc.push(0xC3);
    mem.write(SVC, &svc).unwrap();
    mem.write_u64(base + 0x9110, SVC).unwrap();

    const INDEX: u32 = 0x0000_005A;
    const ARG0: u32 = 0x0042_1234;
    build_wow64_syscall_guest(&mut mem, bop, INDEX, &[ARG0]);
    assert_eq!(mem.read_u32(G32_TRANSITION).unwrap(), bop as u32, "Wow64Transition holds the BOP VA");

    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: G32_CALLER as u32,
        esp: G32_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();
    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);

    assert_eq!(mem.read_u32(RECORD_INDEX).unwrap(), INDEX, "the service index reached Wow64SystemServiceEx");
    assert_eq!(
        mem.read_u32(RECORD_ARG0).unwrap(),
        ARG0,
        "the argument-block pointer (esp+8) addressed the guest's pushed stdcall argument",
    );
    assert_eq!(mem.read_u32(G32_STATUS).unwrap(), 0x0000_D00D, "the 32-bit caller got the result in eax");
    assert_eq!(
        mem.read_u32(G32_ESP_OUT).unwrap(),
        G32_STACK as u32,
        "the stub's `ret 4` unwound the double-call to a balanced 32-bit stack",
    );
}

fn boot_wow64_stack(tag: &str) -> (WinOs, VirtualMemory, Dll, Dll, u64) {
    let dir = std::env::temp_dir().join(format!("exemu-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, ntdll) = setup(&dir);

    let cpu_bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &cpu_bytes, WOW64CPU_BASE);
    let svc_bytes = std::fs::read(WOW64).expect("read wow64.dll");
    let wow64 = load_dll(&mut mem, &svc_bytes, WOW64_BASE);

    let bound = bind_imports(&mut mem, &wow64, &ntdll);
    assert!(bound > 200, "wow64.dll's ntdll imports bound to real stubs (bound {bound})");
    let dispatched = bind_imports(&mut mem, &wow64cpu, &wow64);
    assert_eq!(dispatched, 1, "wow64cpu imports exactly one wow64.dll symbol");
    assert_eq!(
        mem.read_u64(wow64cpu.base + 0x9110).unwrap(),
        wow64.export("Wow64SystemServiceEx"),
        "wow64cpu's turbo-thunk IAT slot now holds the real Wow64SystemServiceEx",
    );

    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);
    let bop = call_export(&mut os, &mut mem, wow64cpu.export("BTCpuGetBopCode"), &[]);
    (os, mem, ntdll, wow64cpu, bop)
}

#[test]
fn wow64_32bit_guest_reaches_the_real_nt_ssdt() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() || !Path::new(WOW64).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let (mut os, mut mem, ntdll, wow64cpu, bop) = boot_wow64_stack("w5_3time");

    let index = ssdt_index_of(&mem, &ntdll, "NtQuerySystemTime");
    build_wow64_syscall_guest(&mut mem, bop, index, &[G32_OUT as u32]);

    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: G32_CALLER as u32,
        esp: G32_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();

    let before = filetime_host_now();
    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);
    let after = filetime_host_now();

    assert_eq!(
        mem.read_u32(G32_STATUS).unwrap() as u64,
        STATUS_SUCCESS,
        "the 32-bit guest got STATUS_SUCCESS back from exemu's NtQuerySystemTime",
    );
    let t = mem.read_u64(G32_OUT).unwrap();
    assert!(
        before <= t && t <= after,
        "exemu's SSDT handler wrote a live FILETIME {t} into the 32-bit guest's buffer (not in [{before}, {after}])",
    );
    assert_eq!(
        mem.read_u32(G32_ESP_OUT).unwrap(),
        G32_STACK as u32,
        "the 32-bit stack is balanced after the full WoW64 round trip",
    );
}

#[test]
fn wow64_32bit_guest_allocates_through_the_real_wow64_thunk() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() || !Path::new(WOW64).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;
    const CURRENT_PROCESS32: u32 = 0xFFFF_FFFF;

    let (mut os, mut mem, ntdll, wow64cpu, bop) = boot_wow64_stack("w5_3alloc");
    let index = ssdt_index_of(&mem, &ntdll, "NtAllocateVirtualMemory");

    build_wow64_syscall_guest(
        &mut mem,
        bop,
        index,
        &[
            CURRENT_PROCESS32,
            G32_INOUT_A as u32,
            0,
            G32_INOUT_B as u32,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        ],
    );
    mem.write_u32(G32_INOUT_A, 0).unwrap();
    mem.write_u32(G32_INOUT_B, 0x2000).unwrap();

    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: G32_CALLER as u32,
        esp: G32_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();
    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);

    assert_eq!(
        mem.read_u32(G32_STATUS).unwrap() as u64,
        STATUS_SUCCESS,
        "the 32-bit guest got STATUS_SUCCESS back from exemu's NtAllocateVirtualMemory",
    );
    let base = mem.read_u32(G32_INOUT_A).unwrap() as u64;
    assert_ne!(base, 0, "wow64.dll narrowed the 64-bit base back into the guest's 32-bit cell");
    assert_eq!(base & 0xFFFF, 0, "the written-back base is 64 KiB aligned");
    assert!(base <= 0x7FFF_FFFF, "the base honours wow64.dll's 0x7fffffff ZeroBits ceiling");
    assert_eq!(mem.read_u32(G32_INOUT_B).unwrap(), 0x2000, "the region size was written back");
    mem.write_u32(base, 0xCAFE_BABE).unwrap();
    assert_eq!(mem.read_u32(base).unwrap(), 0xCAFE_BABE, "the allocated pages are writable");
    assert_eq!(
        mem.read_u32(G32_ESP_OUT).unwrap(),
        G32_STACK as u32,
        "the six-argument stdcall unwound to a balanced 32-bit stack",
    );
}

