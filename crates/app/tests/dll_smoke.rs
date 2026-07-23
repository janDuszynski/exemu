//! W2.16 — the **DLL-smoke harness**: the standing de-risk for phases W2–W6.
//!
//! This loads Wine's own PE `ntdll.dll` **alone** — no `Process::load`, no
//! `LdrInitializeThunk`, no W3 boot — maps its sections at a chosen base,
//! relocates it, and then drives its **real exported `Nt*` stubs** through the
//! CPU + the W2.3 SSDT dispatcher. Each stub is the genuine Wine assembly
//! `mov r10,rcx; mov eax,N; test byte [0x7ffe0308],1; …; syscall`, so a call
//! that returns a serviced NTSTATUS proves the whole PE/Unix boundary end to
//! end: a Wine-PE guest issues a real `SYSCALL`, the dispatcher saves/switches/
//! indexes/restores, the native `Nt*` handler services it, and the result lands
//! back in the guest's `RAX` — the W2 GATE.
//!
//! Style **(b)** (the true gate): we do NOT hand-assemble a `mov eax,N; syscall`
//! stub (that would test our own bytes). We resolve each export's RVA **by name**
//! from ntdll's parsed export table, point `rip` at `image_base+rva`, place the
//! Win64 argument registers + stack args, and let ntdll's *own* stub bytes run
//! into the `SYSCALL`. The SSDT indices are used only to sanity-check the
//! registrations if a path faults; the RVAs are resolved, never hardcoded.
//!
//! Capabilities exercised through ntdll's real stubs, all asserting "no fault":
//!   * **ALLOC** — NtAllocateVirtualMemory → Protect → Query → Free
//!   * **TIME** — NtQuerySystemTime, NtQueryPerformanceCounter (+ NULL AV)
//!   * **FILE** — NtCreateFile → NtWriteFile (bytes land on the host) →
//!     NtReadFile → NtClose, sandbox-rooted
//!   * **EVENT** — NtCreateEvent (manual/signaled) → NtSetEvent →
//!     NtWaitForSingleObject(zero-timeout) → NtClose
//!
//! The suite is GENERIC over `(dll bytes, base, name→rva map)` via [`Dll`] so a
//! W3+ case for kernelbase/kernel32 is a one-liner ("add a case per DLL").
//!
//! Skips cleanly when the (git-ignored) Wine DLL set is absent, so it never
//! breaks a checkout that lacks `example_exe/wine-dlls/`.

use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const NTDLL: &str = "../../example_exe/wine-dlls/x86_64-windows/ntdll.dll";
const WOW64CPU: &str = "../../example_exe/wine-dlls/x86_64-windows/wow64cpu.dll";
// A base clear of ntdll's (kept below the TEB/PEB); wow64cpu has a full .reloc.
const WOW64CPU_BASE: u64 = 0x0000_0007_0000_0000;

// --- The fixed low-page layout Wine's ntdll stubs assume. ------------------
// KUSER_SHARED_DATA read-only at 0x7ffe0000 with SystemCall@0x308 nonzero (the
// stub does `test byte [0x7ffe0308],1` before the syscall), dispatcher landing
// page at 0x7ffe1000. Replicated inline (crates/app's map_kuser_shared_data is
// private and takes the full Process path).
const KUSER_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER: u64 = 0x7ffe_1000;
const KUSER_SYSTEM_CALL: u64 = 0x308;

// TEB/PEB bases (kept clear of KUSER and the ntdll image). The dispatcher reads
// the current-thread TEB for its syscall_frame from `teb_base`.
const GS_BASE: u64 = 0x7fff_0000_0000;
const PEB_BASE: u64 = GS_BASE + 0x2000;

// The base we relocate ntdll to (clear of everything above; ntdll's preferred
// base is 0x1_7000_0000, but any 64 KiB-aligned base works given its .reloc).
const NTDLL_BASE: u64 = 0x0000_0006_0000_0000;

// Guest stack + a scratch data region for OUT cells / OBJECT_ATTRIBUTES /
// buffers, and a one-page RWX code region holding the `hlt` return sentinel.
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const STACK_SIZE: u64 = 0x4000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SCRATCH_SIZE: u64 = 0x4000;
const SENTINEL: u64 = 0x0000_0000_6000_0000; // a page whose first byte is `hlt`

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;

// ==========================================================================
// A loaded DLL image: mapped + relocated, with its exports resolved by name.
// Generic host for "add a case per DLL" (W3+ kernelbase/kernel32).
// ==========================================================================
struct Dll {
    base: u64,
    /// export name → absolute virtual address (base + rva). Forwarders excluded.
    exports: HashMap<String, u64>,
}

impl Dll {
    /// Absolute address of an exported `Nt*`/`Rtl*` stub, by name.
    fn export(&self, name: &str) -> u64 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("{name} not exported by the loaded DLL"))
    }
}

/// Parse + map + relocate `bytes` at `base` into `mem`, returning the resolved
/// export map. Every section is mapped RWX so the stub bytes execute and the
/// `test`/`syscall` run; the header page is mapped too (guests walk it).
fn load_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Dll {
    let mut image = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    assert!(image.is_64bit, "the x86_64-windows DLL must be PE32+");

    // Relocate to `base` before mapping (ntdll has a full .reloc). The same
    // fixup code the loader uses for the main image and plugins.
    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)
        .expect("apply base relocations");

    // Map the header page + each section, region-sized to max(virtual, raw).
    let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
    mem.map(Region::new("dll_headers", base, hdr_len, Perm::RWX)).unwrap();
    mem.write(base, &image.headers).unwrap();
    for s in &image.sections {
        let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
        let map_len = align_up(vsize, 0x1000).max(0x1000);
        // Sections can share a page; only map the first that covers each range.
        let addr = base + s.rva as u64;
        if mem.map(Region::new("dll_section", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
            mem.write(addr, &s.data).unwrap();
        } else if !s.data.is_empty() {
            // Overlapping/adjacent section already mapped its page — poke bytes.
            mem.poke(addr, &s.data).unwrap();
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue; // a forwarder is a re-export string, not a callable stub
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Dll { base, exports }
}

/// Build a fresh `(WinOs, VirtualMemory)` with the fixed low-page layout, a
/// stack, scratch, a `hlt` return sentinel, and the TEB/PEB regions, plus the
/// loaded ntdll. `sandbox` roots the guest filesystem for the FILE capability.
fn setup(sandbox: &Path) -> (WinOs, VirtualMemory, Dll) {
    let bytes = std::fs::read(NTDLL).expect("read ntdll.dll");
    let mut mem = VirtualMemory::new();

    // Fixed low-page layout Wine's stubs assume.
    mem.map(Region::new("kuser", KUSER_BASE, 0x1000, Perm::READ)).unwrap();
    mem.map(Region::new("dispatcher", KUSER_DISPATCHER, 0x1000, Perm::RWX)).unwrap();
    // SystemCall selector. The real ntdll stub is
    //   test byte [0x7ffe0308],1; jne +3; <syscall>; ret; ...; call [0x7ffe1000]
    // — the `jne` is *taken* when the SystemCall bit is set, routing to the
    // dispatcher-page indirect call. Clearing it (=0) makes the stub run its own
    // raw `0f 05 syscall`, which W2.2/W2.3 route through `Hooks::syscall` →
    // `dispatch_syscall` → the native `Nt*` handler. That inline `syscall` IS the
    // W2 gate, so we seed 0 (READ-only region — poke bypasses the perm check).
    mem.poke(KUSER_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes()).unwrap();

    // Stack, scratch, sentinel page, TEB, PEB.
    mem.map(Region::new("stack", STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, SCRATCH_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt
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
    // Register ntdll's unixlib (needed only for the optional Rtl/unixlib bonus;
    // harmless otherwise).
    os.register_ntdll_unixlib(dll.base);
    (os, mem, dll)
}

/// Drive a call to `entry` (an absolute VA — an ntdll export) through the real
/// CPU. Places args 0..4 in RCX/RDX/R8/R9 and args 4+ on the guest stack at the
/// Win64 home-slot offsets `[rsp+0x28+(n-4)*8]` (ntdll's stub forwards them);
/// sets `rip=entry`, `rsp` below the stack top, and the `hlt` sentinel at
/// `[rsp]` so the stub's `ret` (if any) halts cleanly. The stub itself does the
/// `mov r10,rcx` and the `SYSCALL`; we place the *outer* Win64 args. Loops
/// `cpu.step()` — any unimplemented path surfaces as an `Err(fault)` that fails
/// the test with the fault report ("no fault" globally). Returns RAX.
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
    // Return sentinel at [rsp]: a straight `ret` inside the stub lands on `hlt`.
    mem.write_u64(rsp, SENTINEL).unwrap();
    // Stack args 5+ at the home-slot offsets the stub forwards to R10-relative.
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

/// Lay out a UNICODE_STRING {Length@0, MaximumLength@2, pad@4, Buffer@8} at
/// `us_ptr` with its buffer at `buf_ptr`. (Copied from fs_nt.rs.)
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

/// Build an OBJECT_ATTRIBUTES {Length@0, RootDirectory@8, ObjectName@0x10} at
/// `oa_ptr` naming the NT path `nt_path`. (Copied from fs_nt.rs.)
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
    // FILETIME (100-ns units since 1601) — the same clock os/time.rs reads.
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (d.as_secs() + EPOCH_DIFF_SECS) * 10_000_000 + d.subsec_nanos() as u64 / 100
}

// ==========================================================================
// The W2 GATE: one test, four capabilities, all through ntdll's real stubs.
// ==========================================================================
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

    // Sanity-check the export resolution against a few known stubs (the RVAs in
    // the plan are only a cross-check; we resolve by name).
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

/// ALLOC: NtAllocateVirtualMemory → write/read → NtProtectVirtualMemory →
/// NtQueryVirtualMemory → NtFreeVirtualMemory, all via ntdll's real stubs.
fn alloc_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const MEM_COMMIT_RESERVE: u64 = 0x3000;
    const MEM_RELEASE: u64 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const STATE_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x0002_0000;
    const CURRENT_PROCESS: u64 = u64::MAX; // NtCurrentProcess = -1

    let base_ptr = SCRATCH;
    let size_ptr = SCRATCH + 0x10;
    mem.write_u64(base_ptr, 0).unwrap(); // *BaseAddress = NULL → kernel picks
    mem.write_u64(size_ptr, 0x2000).unwrap();

    // NtAllocateVirtualMemory(ProcessHandle, &Base, ZeroBits, &Size, Type, Prot).
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

    // NtProtectVirtualMemory(ProcessHandle, &Base, &Size, NewProtect, &Old).
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

    // NtQueryVirtualMemory(ProcessHandle, Base, MemoryBasicInformation=0, &mbi, 0x30, &ret).
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

    // NtFreeVirtualMemory(ProcessHandle, &Base, &Size=0, MEM_RELEASE).
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

/// TIME: NtQuerySystemTime bracketed by the host clock (+ NULL → AV);
/// NtQueryPerformanceCounter monotonic + fixed frequency.
fn time_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const QPC_FREQ: u64 = 10_000_000;
    let out = SCRATCH;

    let before = filetime_host_now();
    let st = call_export(os, mem, dll.export("NtQuerySystemTime"), &[out]);
    let after = filetime_host_now();
    assert_eq!(st, STATUS_SUCCESS, "NtQuerySystemTime (ntdll stub)");
    let t = mem.read_u64(out).unwrap();
    assert!(before <= t && t <= after, "system time {t} not in [{before}, {after}]");

    // NULL out-pointer → STATUS_ACCESS_VIOLATION (clean status, not a fault).
    let st = call_export(os, mem, dll.export("NtQuerySystemTime"), &[0]);
    assert_eq!(st, STATUS_ACCESS_VIOLATION, "NtQuerySystemTime(NULL) → AV");

    // NtQueryPerformanceCounter(&counter, &freq).
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

/// FILE: NtCreateFile(FILE_CREATE) → NtWriteFile (bytes land on the host) →
/// NtReadFile back → NtClose, all sandbox-rooted, through ntdll's real stubs.
fn file_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll, sandbox: &Path) {
    const FILE_CREATE: u64 = 2;
    const FILE_CREATED: u64 = 2;
    const GENERIC_WRITE: u64 = 0x4000_0000;

    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let byteoff_ptr = SCRATCH + 0x20;
    let oa_ptr = SCRATCH + 0x100;
    let data_ptr = SCRATCH + 0x300;

    write_object_attributes(mem, oa_ptr, "\\??\\C:\\out\\hello.txt");
    // NtCreateFile(&h, access, &oa, &iosb, &alloc=0, attrs, share=0, disp,
    //              opts, ea=0, ealen=0).
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

    // NtWriteFile(h, ev=0, apc=0, ctx=0, &iosb, buf, len, &offset=0, key=0).
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

    // THE LOAD-BEARING CHECK: the bytes landed on the HOST filesystem.
    let host_file = sandbox.join("C").join("out").join("hello.txt");
    assert!(host_file.exists(), "the file was created on the host under the sandbox");
    assert_eq!(std::fs::read(&host_file).unwrap(), payload, "host file has the written bytes");

    // NtReadFile back.
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

    // NtClose(h).
    let st = call_export(os, mem, dll.export("NtClose"), &[handle]);
    assert_eq!(st, STATUS_SUCCESS, "NtClose (ntdll stub) on the file handle");
}

/// EVENT (wineserver-backed poll): NtCreateEvent(manual, signaled) →
/// NtSetEvent → NtWaitForSingleObject(zero-timeout) → NtClose.
fn event_capability(os: &mut WinOs, mem: &mut VirtualMemory, dll: &Dll) {
    const NOTIFICATION_EVENT: u64 = 0; // manual-reset
    const INITIAL_SIGNALED: u64 = 1;

    let handle_ptr = SCRATCH;
    let prev_ptr = SCRATCH + 0x40;
    let zero_timeout = SCRATCH + 0x80; // cell holds 0 → poll, never blocks

    // NtCreateEvent(&h, access=0, &objattr=NULL, EventType=Notification, Initial=1).
    let st = call_export(
        os,
        mem,
        dll.export("NtCreateEvent"),
        &[handle_ptr, 0, 0, NOTIFICATION_EVENT, INITIAL_SIGNALED],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateEvent (ntdll stub)");
    let handle = mem.read_u64(handle_ptr).unwrap();
    assert_ne!(handle, 0, "an event handle was written back");

    // NtSetEvent(h, &prev). prev may be 1 (it was created signaled) — don't
    // assert on the prior state; only that the call succeeds.
    let st = call_export(os, mem, dll.export("NtSetEvent"), &[handle, prev_ptr]);
    assert_eq!(st, STATUS_SUCCESS, "NtSetEvent (ntdll stub)");

    // NtWaitForSingleObject(h, Alertable=0, &Timeout=0). A manual-reset event
    // stays signaled, so a zero-timeout poll returns STATUS_WAIT_0 immediately.
    mem.write_u64(zero_timeout, 0).unwrap();
    let st = call_export(
        os,
        mem,
        dll.export("NtWaitForSingleObject"),
        &[handle, 0, zero_timeout],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWaitForSingleObject(zero-timeout) → STATUS_WAIT_0");

    // NtClose(h).
    let st = call_export(os, mem, dll.export("NtClose"), &[handle]);
    assert_eq!(st, STATUS_SUCCESS, "NtClose (ntdll stub) on the event handle");
}

// ==========================================================================
// W5.1: Wine's WoW64 thunk layer loads and its stubs run under exemu.
// ==========================================================================
/// `wow64cpu.dll` (the 64-bit binary-translator core for 32-bit guests) maps,
/// relocates, resolves its `BTCpu*` exports, and one of its stubs actually runs:
/// `BTCpuGetBopCode` (`lea rax,[rip+disp]; ret`) returns a pointer into the
/// mapped image at the recovered BOP bytes — proving the load + relocation +
/// RIP-relative computation are correct (roadmap W5.1). The `BTCpuSimulate`
/// mode-switch integration is W5.2+/W5.4.
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

    // The binary-translator ABI ntdll drives is present as callable stubs.
    for name in ["BTCpuProcessInit", "BTCpuSimulate", "BTCpuGetBopCode", "BTCpuGetContext", "BTCpuSetContext"] {
        assert!(wow64cpu.exports.contains_key(name), "wow64cpu must export {name}");
    }

    // Run BTCpuGetBopCode through its own bytes: `lea rax,[rip+0x5c59]; ret`
    // resolves to the BOP-code slot at rva 0x7000 (in .bss — filled at runtime by
    // wow64cpu's init, so it reads back zero statically). The exact pointer proves
    // the load + relocation + RIP-relative computation are all correct.
    const BOP_SLOT_RVA: u64 = 0x7000;
    let ptr = call_export(&mut os, &mut mem, wow64cpu.export("BTCpuGetBopCode"), &[]);
    assert_eq!(
        ptr,
        WOW64CPU_BASE + BOP_SLOT_RVA,
        "BTCpuGetBopCode's rip-relative lea resolves to the BOP slot after relocation"
    );
    // The slot is a mapped, readable page (zero-filled .bss until runtime init).
    let mut buf = [0u8; 4];
    mem.read(ptr, &mut buf).expect("the BOP slot is mapped");
}

/// W5.4/W5.2: the *real* `wow64cpu!BTCpuSimulate` stub drives the 64→32 mode
/// switch into a 32-bit guest. We set up the WoW64 process model the stub reads —
/// the TEB self-pointer, the CPU-reserved area at TEB+0x1488 → a WOW64_CONTEXT
/// (Eip/Esp/SegCs at the recovered offsets), and the .bss CS/SS selector slots
/// `BTCpuProcessInit` would fill — then let the stub's own bytes run: it loads the
/// 32-bit regs, `xchg`es to the 32-bit stack, and far-jumps through [Eip, SegCs].
/// The guest's `C7 05 …` is an **absolute** `[disp32]` store in 32-bit mode but a
/// **RIP-relative** one in 64-bit mode — so its sentinel lands at the expected
/// address *only if* the CPU actually dropped into 32-bit mode (roadmap W5.2/W5.4).
/// Drive the real `BTCpuSimulate` into a 32-bit guest and return the value the
/// guest stored at its sentinel address. `resume` selects the stub's forward
/// path via the cpu-area header bit 0: `false` → the fast far-jmp path, `true` →
/// the full-context `iretq` restore path. The guest is
/// `mov dword [0x00420000], 0xCAFEBABE ; hlt` — an **absolute** `[disp32]` store
/// in 32-bit mode but **RIP-relative** in 64-bit, so its sentinel only lands if
/// the CPU truly switched to 32-bit mode.
fn drive_btcpusimulate_guest(resume: bool) -> u32 {
    let dir = std::env::temp_dir().join(format!("exemu-w5_4-{}-{resume}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, _ntdll) = setup(&dir);
    let bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &bytes, WOW64CPU_BASE);

    // A 32-bit guest region (< 4 GiB, so Esp/Eip fit in 32 bits): code + stack +
    // the sentinel target.
    const GUEST_CODE: u64 = 0x0040_0000;
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();
    mem.write(GUEST_CODE, &[0xC7, 0x05, 0x00, 0x00, 0x42, 0x00, 0xBE, 0xBA, 0xFE, 0xCA, 0xF4]).unwrap();

    // The WoW64 process model BTCpuSimulate reads: TEB self-pointer (gs:[0x30])
    // and the CPU-reserved area (pointer at TEB+0x1488 → the WOW64_CONTEXT), laid
    // out by the production `exemu_os::wow64` helper the real boot will use.
    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, GUEST_CODE as u32, GUEST_STACK as u32).unwrap();
    if resume {
        mem.write_u32(CPU_AREA, 1).unwrap(); // set the resume bit → iretq forward path
    }

    // The CS/SS selector constants BTCpuProcessInit would populate (we skip init):
    // BTCpuSimulate copies these into the context, and the iretq path pops CS from
    // there, so setting them right matters here.
    mem.write_u32(WOW64CPU_BASE + 0x600c, exemu_os::wow64::SEL_CS32).unwrap();
    mem.write_u32(WOW64CPU_BASE + 0x6008, exemu_os::wow64::SEL_SS32).unwrap();

    // Run the real stub: 64-bit setup → far jmp / iretq → 32-bit guest → hlt.
    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);
    mem.read_u32(SENTINEL32).unwrap()
}

/// W5.4/W5.2: the real `BTCpuSimulate` **fast far-jmp** path drops into a 32-bit
/// guest. (See [`drive_btcpusimulate_guest`] for the decode-sensitive proof.)
#[test]
fn btcpusimulate_switches_into_a_32bit_guest() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    assert_eq!(drive_btcpusimulate_guest(false), 0xCAFE_BABE, "far-jmp path: 32-bit guest ran");
}

/// W5.2: the real `BTCpuSimulate` **full-restore `iretq`** path (resume bit set)
/// also drops into a 32-bit guest — exercising `iretq`'s mode switch and the
/// `mov ds/es/fs` (0x8E) segment moves through wow64cpu's own bytes.
#[test]
fn btcpusimulate_iretq_path_switches_into_a_32bit_guest() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    assert_eq!(drive_btcpusimulate_guest(true), 0xCAFE_BABE, "iretq path: 32-bit guest ran");
}

/// W5.2 capstone: a full **64→32→64 round trip**. The real `BTCpuSimulate`
/// forward-switches into a 32-bit guest, which stores its sentinel and then
/// **far-jumps back to a 64-bit stub** (selector 0x33) — the reverse transition
/// Wine's WoW64 uses (a far transfer to the 64-bit return handler). The 64-bit
/// stub, reachable only if the reverse switch landed in *long* mode, stores its
/// own sentinel with a `movabs`-addressed store (an instruction form that only
/// exists in 64-bit). Seeing both sentinels proves the round trip end to end.
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

    const GUEST_CODE: u64 = 0x0040_0000; // 32-bit guest
    const STUB64: u64 = 0x0040_1000; // 64-bit return stub
    const RET_PTR: u64 = 0x0040_2000; // far pointer [STUB64:32, 0x33:16]
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    const SENTINEL64: u64 = 0x0042_0004;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();

    // 32-bit guest: mov dword [SENTINEL32], 0xCAFEBABE ; jmp fword [RET_PTR]
    mem.write(GUEST_CODE, &[0xC7, 0x05, 0x00, 0x00, 0x42, 0x00, 0xBE, 0xBA, 0xFE, 0xCA]).unwrap();
    mem.write(GUEST_CODE + 10, &[0xFF, 0x2D, 0x00, 0x20, 0x40, 0x00]).unwrap();
    // The far pointer the reverse jump reads: offset = STUB64, selector = 0x33.
    mem.write_u32(RET_PTR, STUB64 as u32).unwrap();
    mem.write_u16(RET_PTR + 4, 0x33).unwrap();
    // 64-bit stub: movabs rax, SENTINEL64 ; mov dword [rax], 0x0000F00D ; hlt
    mem.write(STUB64, &[0x48, 0xB8]).unwrap();
    mem.write_u64(STUB64 + 2, SENTINEL64).unwrap();
    mem.write(STUB64 + 10, &[0xC7, 0x00, 0x0D, 0xF0, 0x00, 0x00, 0xF4]).unwrap();

    // The WoW64 process model + CS/SS constants (as in the single-hop tests).
    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, GUEST_CODE as u32, GUEST_STACK as u32).unwrap();
    mem.write_u32(WOW64CPU_BASE + 0x600c, exemu_os::wow64::SEL_CS32).unwrap();
    mem.write_u32(WOW64CPU_BASE + 0x6008, exemu_os::wow64::SEL_SS32).unwrap();

    call_export(&mut os, &mut mem, wow64cpu.export("BTCpuSimulate"), &[]);

    assert_eq!(mem.read_u32(SENTINEL32).unwrap(), 0xCAFE_BABE, "32-bit guest ran (64→32)");
    assert_eq!(mem.read_u32(SENTINEL64).unwrap(), 0x0000_F00D, "64-bit stub ran after the reverse switch (32→64)");
}
