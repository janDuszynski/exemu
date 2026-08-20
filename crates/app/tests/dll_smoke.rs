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
// wow64cpu's load base. It MUST be **sub-4 GiB**: `BTCpuProcessInit` builds the
// 32→64 return BOP as a far pointer with an m16:32 (32-bit) offset and range-checks
// that the return handler's high 32 bits are zero (`shr rcx,0x20; jne <error>`) —
// above 4 GiB it takes the error path and never builds the BOP. A 32-bit guest also
// reaches the BOP via an absolute 32-bit address, so it must live low. (Preferred
// base is 0x7a40_0000; we relocate to exercise the fixups, staying clear of the
// 32-bit guest region, SCRATCH/SENTINEL, and KUSER.)
const WOW64CPU_BASE: u64 = 0x0000_0000_6A40_0000;
// `wow64.dll` — the 64-bit WoW64 *service* half: it owns the 32→64 argument
// marshalling and issues the real 64-bit `Nt*` calls itself (roadmap W5.3).
// Unlike wow64cpu it has no sub-4 GiB constraint (only 64-bit code calls it);
// relocated off its preferred 0x1_8000_0000 base to exercise the fixups.
const WOW64: &str = "../../example_exe/wine-dlls/x86_64-windows/wow64.dll";
const WOW64_BASE: u64 = 0x0000_0000_6B00_0000;

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
    /// `(IAT slot rva, imported symbol name)` for every by-name import. Used by
    /// [`bind_imports`] to wire one loaded image's IAT to another's real exports
    /// — `wow64.dll` reaches the 64-bit NT layer through 271 ntdll imports
    /// (roadmap W5.3).
    imports: Vec<(u32, String)>,
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

/// Bind every by-name import of `dll` that `provider` actually exports, writing
/// the provider's real export VA into the importer's IAT slot — the loader step
/// that makes `wow64.dll`'s thunks reach Wine's real 64-bit `ntdll` stubs (and
/// through them exemu's SSDT). Returns the number of slots bound; imports the
/// provider does not export are left as-is (they are never called on the paths
/// under test, and a null slot faults loudly if that ever changes).
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

/// The SSDT index a Wine 64-bit `ntdll` stub carries, read out of the **mapped
/// image's own bytes**: every stub opens `4C 8B D1` (`mov r10,rcx`) followed by
/// `B8 <imm32>` (`mov eax,<index>`). Resolving the index this way keeps the
/// WoW64 tests free of hardcoded service numbers — the same "resolve, never
/// hardcode" rule the rest of this harness follows.
fn ssdt_index_of(mem: &VirtualMemory, dll: &Dll, name: &str) -> u32 {
    let stub = dll.export(name);
    let mut head = [0u8; 4];
    mem.read(stub, &mut head).expect("the stub is mapped");
    assert_eq!(&head, &[0x4C, 0x8B, 0xD1, 0xB8], "{name} is not a `mov r10,rcx; mov eax,N` syscall stub");
    mem.read_u32(stub + 4).unwrap()
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

    // Run the real `BTCpuProcessInit` first: it populates the CS/SS selector .bss
    // slots BTCpuSimulate reads (and the iretq path pops CS from) plus the TEB
    // self-pointer — exactly as a WoW64 boot would, with no hand-faked constants.
    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);
    // The CPU-reserved area (pointer at TEB+0x1488 → the WOW64_CONTEXT) the real
    // BTCpuSimulate reads, laid out by the production `exemu_os::wow64` helper.
    const CPU_AREA: u64 = SCRATCH + 0x1000;
    exemu_os::wow64::init_cpu_area(&mut mem, GS_BASE, CPU_AREA, exemu_os::wow64::Start32 {
        eip: GUEST_CODE as u32,
        esp: GUEST_STACK as u32,
        eax: 0,
        ebx: 0,
    }).unwrap();
    if resume {
        mem.write_u32(CPU_AREA, 1).unwrap(); // set the resume bit → iretq forward path
    }

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

    // Populate the CS/SS selectors + TEB self via the real BTCpuProcessInit, then
    // lay out the WOW64_CONTEXT for the forward switch (as in the single-hop tests).
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

/// Run the **real** `wow64cpu!BTCpuProcessInit` through its own bytes (roadmap
/// W5.1). Unlike `BTCpuSimulate`, the init is *not* self-contained — it calls five
/// ntdll routines. We patch its five IAT slots (rvas recovered from wow64cpu's
/// import table) to tiny hand-assembled stubs that feed exactly what a real WoW64
/// boot would: the live 64-bit selectors (`RtlCaptureContext` → CS=0x33/DS=0x2b/
/// FS=0x53) and the 32-bit CONTEXT selectors (`RtlWow64GetThreadContext` →
/// SegCs=0x23/SegSs=0x2b). Then its own bytes populate the `.bss` selector slots
/// and build the 32→64 **return-BOP trampoline** at rva 0x7000. Requires `wow64cpu`
/// at a **sub-4 GiB base** (see [`WOW64CPU_BASE`]).
fn run_wow64_process_init(os: &mut WinOs, mem: &mut VirtualMemory, wow64cpu: &Dll) {
    let base = wow64cpu.base;

    // A page for the five import stubs (Win64 ABI: rcx/rdx/r8/r9, arg5 @[rsp+0x28]).
    const STUBS: u64 = 0x0000_0000_5200_0000;
    const FIND_RET: u64 = STUBS + 0x200; // a readable ptr the init dereferences once
    mem.map(Region::new("wow64_stubs", STUBS, 0x1000, Perm::RWX)).unwrap();

    // (A) LdrGetDllHandle(_, _, _, r9=&handle) → *handle = ntdll base; return 0.
    let mut a = vec![0x48, 0xB8];
    a.extend_from_slice(&NTDLL_BASE.to_le_bytes()); // mov rax, NTDLL_BASE
    a.extend_from_slice(&[0x49, 0x89, 0x01, 0x31, 0xC0, 0xC3]); // mov [r9],rax; xor eax,eax; ret
    // (B) RtlFindExportedRoutineByName(_, _) → rax = a readable ptr (the init does
    //     `mov rax,[rax]` and stashes it, unused by the BOP build); return it.
    let mut b = vec![0x48, 0xB8];
    b.extend_from_slice(&FIND_RET.to_le_bytes()); // mov rax, FIND_RET
    b.push(0xC3); // ret
    // (C) RtlCaptureContext(rcx=&CONTEXT) → seed the live 64-bit selectors the init
    //     reads (SegCs@0x38, SegDs@0x3a, SegFs@0x3e). CS=0x33 becomes the BOP's sel.
    let c = vec![
        0x66, 0xC7, 0x41, 0x38, 0x33, 0x00, // mov word [rcx+0x38], 0x33
        0x66, 0xC7, 0x41, 0x3A, 0x2B, 0x00, // mov word [rcx+0x3a], 0x2b
        0x66, 0xC7, 0x41, 0x3E, 0x53, 0x00, // mov word [rcx+0x3e], 0x53
        0xC3,
    ];
    // (D) RtlWow64GetThreadContext(_, rdx=&WOW64_CONTEXT) → seed the 32-bit selectors
    //     (SegCs@0xbc=0x23, SegSs@0xc8=0x2b) the init copies to .bss; return 0.
    let d = vec![
        0xC7, 0x82, 0xBC, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, // mov dword [rdx+0xbc], 0x23
        0xC7, 0x82, 0xC8, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x00, // mov dword [rdx+0xc8], 0x2b
        0x31, 0xC0, 0xC3, // xor eax,eax; ret
    ];
    // (E) NtProtectVirtualMemory(...) → success (the BOP page is already RWX here).
    let e = vec![0x31, 0xC0, 0xC3]; // xor eax,eax; ret

    let (stub_a, stub_b, stub_c, stub_d, stub_e) =
        (STUBS, STUBS + 0x40, STUBS + 0x80, STUBS + 0xC0, STUBS + 0x100);
    mem.write(stub_a, &a).unwrap();
    mem.write(stub_b, &b).unwrap();
    mem.write(stub_c, &c).unwrap();
    mem.write(stub_d, &d).unwrap();
    mem.write(stub_e, &e).unwrap();

    // Patch BTCpuProcessInit's five IAT slots to the stubs above.
    mem.write_u64(base + 0x90b8, stub_a).unwrap(); // LdrGetDllHandle
    mem.write_u64(base + 0x90d0, stub_b).unwrap(); // RtlFindExportedRoutineByName
    mem.write_u64(base + 0x90c8, stub_c).unwrap(); // RtlCaptureContext
    mem.write_u64(base + 0x90e0, stub_d).unwrap(); // RtlWow64GetThreadContext
    mem.write_u64(base + 0x90c0, stub_e).unwrap(); // NtProtectVirtualMemory

    // The init reads gs:[0x30] (TEB self) and [TEB+0x14d0] (a writable pointer it
    // flags with `or [P+4],1`); point the latter at scratch.
    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    mem.write_u64(GS_BASE + 0x14d0, SCRATCH).unwrap();

    call_export(os, mem, wow64cpu.export("BTCpuProcessInit"), &[]);
}

/// W5.1: run the **real** `wow64cpu!BTCpuProcessInit` and verify it builds the
/// 32→64 return BOP and populates the selector slots — no hand-faked constants.
/// The init constructs, at rva 0x7000, a `jmp fword ptr [...]` (opcode `FF 2D`)
/// far-indirect jump whose m16:32 far pointer is `{offset = the 64-bit return
/// handler @0x1110, selector = the 64-bit CS 0x33}` — i.e. the reverse of the W5.2
/// forward switch, assembled from wow64cpu's own bytes. Recovering the BOP by
/// *running* the init (the slot is zero-filled `.bss` statically — the W5.1 note's
/// trap) is the de-risk, and confirms the CS/SS constants the `BTCpuSimulate` tests
/// previously hand-faked are exactly what the real init writes (roadmap W5.1).
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

    // The BOP trampoline at rva 0x7000: `FF 2D <disp32>` (far indirect jmp fword).
    assert_eq!(mem.read_u16(base + 0x7000).unwrap(), 0x2DFF, "BOP opcode = FF 2D (jmp fword [mem])");
    // Its m16:32 far pointer at 0x7006: offset = low32(return handler @0x1110),
    // selector = the 64-bit CS 0x33 — the reverse-switch target.
    assert_eq!(
        mem.read_u32(base + 0x7006).unwrap(),
        (base + 0x1110) as u32,
        "BOP far-ptr offset = the 64-bit return handler",
    );
    assert_eq!(mem.read_u16(base + 0x700a).unwrap(), 0x33, "BOP far-ptr selector = 64-bit CS");
    // The disp32 addresses the far pointer as an absolute 32-bit address — why the
    // image must be sub-4 GiB (a 32-bit guest reaches it): abs32 of the 0x7006 VA.
    assert_eq!(
        mem.read_u32(base + 0x7002).unwrap(),
        (base + 0x7006) as u32,
        "BOP disp32 = abs32(far-ptr) — the sub-4 GiB requirement",
    );

    // The selector `.bss` slots the init populated from the captured contexts — the
    // exact values the BTCpuSimulate tests fed by hand before this step.
    assert_eq!(mem.read_u32(base + 0x600c).unwrap(), exemu_os::wow64::SEL_CS32, "32-bit CS = 0x23");
    assert_eq!(mem.read_u32(base + 0x6008).unwrap(), exemu_os::wow64::SEL_SS32, "32-bit SS = 0x2b");
    assert_eq!(mem.read_u16(base + 0x6014).unwrap(), 0x33, "64-bit CS = 0x33");
}

/// W5.1 capstone: a 32-bit guest issues a **WoW64 service call through the real
/// init-built BOP** — the full syscall cycle on wow64cpu's own bytes.
///
/// `BTCpuProcessInit` builds the BOP trampoline at 0x7000; `BTCpuSimulate`
/// forward-switches into the 32-bit guest; the guest `call`s the BOP, which
/// far-jumps back to the real 64-bit return handler @0x1110; that handler saves
/// the 32-bit context and dispatches to `wow64.dll!Wow64SystemServiceEx` (via the
/// turbo-thunk at 0x12e0 → IAT 0x9110) with the service index the guest left in
/// eax; we stub Wow64SystemServiceEx to record the index and return a sentinel
/// result, and the handler **resumes the 32-bit guest** (fast far-jmp path) with
/// that result in eax — which the guest stores. Both the recorded index and the
/// resumed result landing prove forward + reverse (through the *real* BOP) +
/// context save + dispatch + resume, entirely on wow64cpu's own code (roadmap
/// W5.1). This is the mechanism a real 32-bit guest uses to reach the 64-bit NT
/// layer — no hand-built reverse stub (contrast `btcpusimulate_round_trips_*`).
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

    // Build the real BOP + fill the selector slots by running BTCpuProcessInit.
    run_wow64_process_init(&mut os, &mut mem, &wow64cpu);

    // Stub wow64.dll!Wow64SystemServiceEx (the turbo-thunk target at IAT 0x9110):
    // record the service index (ecx = the guest's eax) and return a sentinel result
    // (eax = 0xD00D). The real service would dispatch the 64-bit NT syscall (W5.3+).
    const SVC: u64 = 0x0000_0000_5300_0000;
    const RECORD: u64 = SVC + 0x100;
    mem.map(Region::new("wow64_svc", SVC, 0x1000, Perm::RWX)).unwrap();
    let mut svc = vec![0x48, 0xB8];
    svc.extend_from_slice(&RECORD.to_le_bytes()); // mov rax, RECORD
    svc.extend_from_slice(&[0x89, 0x08]); // mov [rax], ecx
    svc.extend_from_slice(&[0xB8, 0x0D, 0xD0, 0x00, 0x00]); // mov eax, 0xD00D
    svc.push(0xC3); // ret
    mem.write(SVC, &svc).unwrap();
    mem.write_u64(base + 0x9110, SVC).unwrap(); // IAT: Wow64SystemServiceEx

    // The 32-bit guest: `mov eax, INDEX ; call BOP ; mov [SENTINEL32], eax ; hlt`.
    // `call BOP` pushes a 32-bit return address; the BOP far-jumps to the 64-bit
    // handler @0x1110, which dispatches and resumes here with the service result in
    // eax — which the guest stores at SENTINEL32.
    const GUEST_CODE: u64 = 0x0040_0000;
    const GUEST_STACK: u64 = 0x0041_0000;
    const SENTINEL32: u64 = 0x0042_0000;
    const INDEX: u32 = 0x0000_1234;
    mem.map(Region::new("guest32", GUEST_CODE, 0x3_0000, Perm::RWX)).unwrap();
    let bop = base + 0x7000;
    let call_next = GUEST_CODE + 5 + 5; // rip after `mov eax,imm32`(5) + `call rel32`(5)
    let rel32 = (bop as i64 - call_next as i64) as i32 as u32;
    let mut g = vec![0xB8];
    g.extend_from_slice(&INDEX.to_le_bytes()); // mov eax, INDEX
    g.push(0xE8);
    g.extend_from_slice(&rel32.to_le_bytes()); // call BOP (near, rel32)
    g.extend_from_slice(&[0x89, 0x05, 0x00, 0x00, 0x42, 0x00]); // mov [0x00420000], eax
    g.push(0xF4); // hlt
    mem.write(GUEST_CODE, &g).unwrap();

    // Lay out the WOW64_CONTEXT (fast-entry: resume bit clear) and forward-switch.
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

// ==========================================================================
// W5.1-final + W5.3: `ntdll!Wow64Transition` — a 32-bit ntdll-shaped syscall
// stub reaches the 64-bit NT layer through the real BOP.
// ==========================================================================
// The synthesized 32-bit guest image. The pinned Wine set is the **64-bit**
// `x86_64-windows` set and contains **no 32-bit ntdll**, so the ntdll32 half
// below is hand-assembled to the documented stub shape (see
// `exemu_os::wow64::publish_wow64_transition`). It pins the *mechanism* —
// published pointer → BOP → 64-bit handler → service → resume — not Wine's own
// 32-bit ntdll bytes.
const G32_REGION: u64 = 0x0040_0000; // one RWX region, 0x30000 bytes
const G32_CALLER: u64 = G32_REGION; // the "application" that calls NtXxx
const G32_STUB: u64 = G32_REGION + 0x100; // ntdll32!NtXxx (the syscall stub)
const G32_SVC_CALL: u64 = G32_REGION + 0x200; // ntdll32!Wow64SystemServiceCall
const G32_TRANSITION: u64 = G32_REGION + 0x300; // ntdll32!Wow64Transition (data)
const G32_STACK: u64 = 0x0041_0000; // initial 32-bit ESP
const G32_STATUS: u64 = 0x0042_0000; // caller stores the returned EAX here
const G32_ESP_OUT: u64 = 0x0042_0004; // …and the post-call ESP here
const G32_OUT: u64 = 0x0042_0008; // the NT service's out-buffer (8 bytes)
const G32_INOUT_A: u64 = 0x0042_0010; // a 32-bit IN/OUT cell (e.g. *BaseAddress)
const G32_INOUT_B: u64 = 0x0042_0014; // a second 32-bit IN/OUT cell (e.g. *RegionSize)

/// Lay out the synthesized 32-bit guest: an application-side caller, an
/// ntdll32-shaped `Nt*` stub for `index` taking `args` (stdcall, `4*len` bytes
/// of arguments), `Wow64SystemServiceCall`, and the `Wow64Transition` data slot
/// — then publish `bop` into that slot through the production
/// [`exemu_os::wow64::publish_wow64_transition`].
///
/// ```text
///   caller:                   push argN … push arg0   ; stdcall, right-to-left
///                             call ntdll32!NtXxx      ; pushes the OUTER retaddr
///                             mov [G32_STATUS], eax   ; the NTSTATUS
///                             mov [G32_ESP_OUT], esp  ; the stack must be balanced
///                             hlt
///   ntdll32!NtXxx:            mov eax, index
///                             mov edx, offset Wow64SystemServiceCall
///                             call edx                ; pushes the INNER retaddr
///                             ret 4*N                 ; stdcall callee cleanup
///   ntdll32!Wow64SystemServiceCall:
///                             jmp dword ptr [Wow64Transition]
/// ```
///
/// That double-call depth is what makes `wow64cpu`'s recovered return handler
/// line up: it takes `Eip` from `[esp]` (the inner retaddr), `Esp = esp+4` (past
/// it), and the **argument block from `esp+8`** — i.e. past the outer retaddr,
/// exactly where a stdcall's first argument sits.
fn build_wow64_syscall_guest(mem: &mut VirtualMemory, bop: u64, index: u32, args: &[u32]) {
    mem.map(Region::new("guest32", G32_REGION, 0x3_0000, Perm::RWX)).unwrap();

    // caller — push the stdcall arguments right-to-left, then call the stub.
    let mut c = Vec::new();
    for a in args.iter().rev() {
        c.push(0x68); // push imm32
        c.extend_from_slice(&a.to_le_bytes());
    }
    c.push(0xE8); // call rel32 → G32_STUB
    let after_call = G32_CALLER + c.len() as u64 + 4;
    c.extend_from_slice(&((G32_STUB as i64 - after_call as i64) as i32).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x05]); // mov [disp32], eax
    c.extend_from_slice(&(G32_STATUS as u32).to_le_bytes());
    c.extend_from_slice(&[0x89, 0x25]); // mov [disp32], esp
    c.extend_from_slice(&(G32_ESP_OUT as u32).to_le_bytes());
    c.push(0xF4); // hlt
    mem.write(G32_CALLER, &c).unwrap();

    // ntdll32!NtXxx — the real 32-bit ntdll stub shape.
    let mut s = vec![0xB8]; // mov eax, index
    s.extend_from_slice(&index.to_le_bytes());
    s.push(0xBA); // mov edx, offset Wow64SystemServiceCall
    s.extend_from_slice(&(G32_SVC_CALL as u32).to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD2]); // call edx
    s.push(0xC2); // ret imm16 (stdcall: callee pops the arguments)
    s.extend_from_slice(&((args.len() * 4) as u16).to_le_bytes());
    mem.write(G32_STUB, &s).unwrap();

    // ntdll32!Wow64SystemServiceCall — `jmp dword ptr [Wow64Transition]`. In
    // 32-bit mode `FF 25 disp32` is an **absolute** indirect near jump.
    let mut j = vec![0xFF, 0x25];
    j.extend_from_slice(&(G32_TRANSITION as u32).to_le_bytes());
    mem.write(G32_SVC_CALL, &j).unwrap();

    // THE STEP UNDER TEST: publish the BOP pointer into ntdll32!Wow64Transition.
    exemu_os::wow64::publish_wow64_transition(mem, G32_TRANSITION, bop).unwrap();
}

/// W5.1-final: **`Wow64Transition` published from the real `BTCpuGetBopCode`**.
///
/// Everything on the wow64cpu side is the DLL's own bytes: `BTCpuProcessInit`
/// builds the BOP, `BTCpuGetBopCode` (`lea rax,[rip+disp]; ret`) *hands out its
/// address* — no 0x7000 assumption — and the production
/// `exemu_os::wow64::publish_wow64_transition` writes that address into the
/// 32-bit `Wow64Transition` slot. A 32-bit ntdll-shaped syscall stub then runs
/// as real 32-bit guest code: `mov eax,index; mov edx,&Wow64SystemServiceCall;
/// call edx` → `jmp dword ptr [Wow64Transition]` → the BOP → wow64cpu's own
/// return handler in 64-bit mode → `Wow64SystemServiceEx` → resume.
///
/// The `Wow64SystemServiceEx` seam is stubbed here so the assertions can pin the
/// *boundary contract* exactly: the service index the guest left in `eax`, and
/// the **argument block pointer** (`esp+8`) actually addressing the guest's
/// pushed stdcall argument. `wow64_32bit_guest_reaches_the_real_nt_ssdt` (W5.3)
/// replaces the stub with the real `wow64.dll`.
///
/// **The pinned DLL set has no 32-bit ntdll**, so the stub is synthesized to the
/// documented shape — this pins the mechanism, not Wine's 32-bit ntdll bytes.
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

    // Obtain the BOP the *real* way: run wow64cpu's own `BTCpuGetBopCode`.
    let bop = call_export(&mut os, &mut mem, wow64cpu.export("BTCpuGetBopCode"), &[]);
    assert_eq!(mem.read_u16(bop).unwrap(), 0x2DFF, "BTCpuGetBopCode points at the init-built `FF 2D` far jmp");

    // Stub Wow64SystemServiceEx (wow64cpu IAT 0x9110): record ecx (the service
    // index) and [rdx] (the first dword of the argument block), return a sentinel.
    const SVC: u64 = 0x0000_0000_5300_0000;
    const RECORD_INDEX: u64 = SVC + 0x100;
    const RECORD_ARG0: u64 = SVC + 0x104;
    mem.map(Region::new("wow64_svc", SVC, 0x1000, Perm::RWX)).unwrap();
    let mut svc = vec![0x48, 0xB8];
    svc.extend_from_slice(&RECORD_INDEX.to_le_bytes()); // mov rax, RECORD_INDEX
    svc.extend_from_slice(&[0x89, 0x08]); // mov [rax], ecx        (service index)
    svc.extend_from_slice(&[0x8B, 0x0A]); // mov ecx, [rdx]        (args[0])
    svc.extend_from_slice(&[0x89, 0x48, 0x04]); // mov [rax+4], ecx
    svc.extend_from_slice(&[0xB8, 0x0D, 0xD0, 0x00, 0x00]); // mov eax, 0xD00D
    svc.push(0xC3); // ret
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

/// Boot the whole WoW64 stack for a W5.3 case: Wine's 64-bit `ntdll`,
/// `wow64cpu.dll` and `wow64.dll` all mapped, relocated and **IAT-bound to each
/// other**, `BTCpuProcessInit` run through its own bytes, and the BOP obtained
/// from the real `BTCpuGetBopCode`. Returns `(os, mem, ntdll, wow64cpu, bop)`.
///
/// `wow64.dll` needs **no initialization call**: its ntdll service descriptor
/// (`{ServiceTable, Counter, ServiceLimit = 0x108, ArgumentTable}`) is
/// statically initialized in `.data` and merely relocated by the loader.
fn boot_wow64_stack(tag: &str) -> (WinOs, VirtualMemory, Dll, Dll, u64) {
    let dir = std::env::temp_dir().join(format!("exemu-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem, ntdll) = setup(&dir);

    let cpu_bytes = std::fs::read(WOW64CPU).expect("read wow64cpu.dll");
    let wow64cpu = load_dll(&mut mem, &cpu_bytes, WOW64CPU_BASE);
    let svc_bytes = std::fs::read(WOW64).expect("read wow64.dll");
    let wow64 = load_dll(&mut mem, &svc_bytes, WOW64_BASE);

    // wow64.dll reaches the 64-bit NT layer through its own ntdll IAT — bind it
    // to the real, already-mapped Wine ntdll stubs (the loader's job).
    let bound = bind_imports(&mut mem, &wow64, &ntdll);
    assert!(bound > 200, "wow64.dll's ntdll imports bound to real stubs (bound {bound})");
    // …and wow64cpu's single wow64.dll import is the real Wow64SystemServiceEx.
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

/// **W5.3 GATE** — a 32-bit guest issues a real NT service that lands in exemu's
/// real 64-bit SSDT handler, with **no exemu marshalling anywhere**.
///
/// The chain, every hop on Wine's own bytes except the synthesized 32-bit stub:
///
/// ```text
///   32-bit ntdll stub (mov eax,N; call Wow64SystemServiceCall)
///     → jmp [Wow64Transition]              (published by exemu_os::wow64)
///     → wow64cpu BOP  (FF 2D → CS 0x33)    (built by the real BTCpuProcessInit)
///     → wow64cpu return handler @0x1110    (saves the 32-bit context)
///     → wow64.dll!Wow64SystemServiceEx     (index → service table → thunk)
///     → wow64.dll's per-service thunk      (32→64 argument marshalling)
///     → ntdll.dll!NtQuerySystemTime        (Wine's real 64-bit stub: `syscall`)
///     → exemu's SSDT handler               (crates/os/src/syscall.rs)
///     → back out to the 32-bit guest with the NTSTATUS in eax
/// ```
///
/// Two recovered facts make this work and are asserted here rather than assumed:
///
/// 1. `Wow64SystemServiceEx(ecx = index, rdx = &args32)` splits the index as
///    `table = (index >> 12) & 3`, `service = index & 0xfff`, bounds-checks it
///    against a 32-byte service **descriptor** `{ServiceTable, Counter,
///    ServiceLimit, ArgumentTable}` and tail-calls `ServiceTable[service]`. The
///    ntdll descriptor (table 0, 0x108 services) is **statically initialized in
///    `wow64.dll`'s `.data`** — relocated by the loader, needing no init call.
/// 2. That table's index space is **identical to the 64-bit ntdll SSDT index
///    space**: entry 0x5a is `NtQuerySystemTime`, which is exactly the immediate
///    in the 64-bit `ntdll` stub's `mov eax,0x5a`. The test therefore reads the
///    index out of the mapped 64-bit stub ([`ssdt_index_of`]) and feeds it to the
///    32-bit guest — if the two spaces ever diverged, this test fails.
///
/// The service returns a real FILETIME written by exemu's own handler into a
/// **32-bit guest pointer**, bracketed against the host clock: a serviced value,
/// not just a status code.
#[test]
fn wow64_32bit_guest_reaches_the_real_nt_ssdt() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() || !Path::new(WOW64).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    let (mut os, mut mem, ntdll, wow64cpu, bop) = boot_wow64_stack("w5_3time");

    // The service index, read out of Wine's own 64-bit ntdll stub bytes.
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

/// W5.3, the marshalling half: a 32-bit guest **allocates memory** through the
/// same chain, exercising `wow64.dll`'s real 32↔64 argument marshalling.
///
/// `NtQuerySystemTime` proves the route; this proves the thunk does real work on
/// it. `NtAllocateVirtualMemory`'s wow64 thunk (unlike the time thunk's
/// two-instruction tail-jump) is a couple of hundred instructions: it reads the
/// six 32-bit stdcall arguments out of the guest block, **sign-extends** the
/// pseudo-handle (`movsxd`, so the guest's `0xFFFFFFFF` becomes the 64-bit
/// `NtCurrentProcess` = -1), widens the `*BaseAddress` / `*RegionSize` IN/OUT
/// cells into 64-bit locals, calls `ntdll!RtlIsCurrentProcess` to pick the
/// in-process path, **substitutes its own `0x7fffffff` for a zero `ZeroBits`**,
/// places the two overflow arguments at the Win64 home slots, issues the real
/// 64-bit `ntdll!NtAllocateVirtualMemory`, and narrows the results back into the
/// guest's 32-bit cells.
///
/// That `ZeroBits` substitution is load-bearing and is why `crates/os/src/vm.rs`
/// now honours the argument: exemu's `VirtualAlloc` arena lives at 256 GiB, so
/// ignoring the ceiling handed the guest a **truncated, unmapped** base. The
/// assertions below (nonzero 64 KiB-aligned base under 2 GiB, page-rounded size,
/// pages actually writable at the address the *guest* sees) only hold if Wine's
/// own marshalling and exemu's ceiling agree.
#[test]
fn wow64_32bit_guest_allocates_through_the_real_wow64_thunk() {
    if !Path::new(NTDLL).exists() || !Path::new(WOW64CPU).exists() || !Path::new(WOW64).exists() {
        eprintln!("SKIP: Wine WoW64 DLL set not present (git-ignored)");
        return;
    }
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;
    const CURRENT_PROCESS32: u32 = 0xFFFF_FFFF; // the 32-bit NtCurrentProcess

    let (mut os, mut mem, ntdll, wow64cpu, bop) = boot_wow64_stack("w5_3alloc");
    let index = ssdt_index_of(&mem, &ntdll, "NtAllocateVirtualMemory");

    // NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits, &RegionSize,
    //                         AllocationType, Protect) — six 32-bit stdcall args.
    build_wow64_syscall_guest(
        &mut mem,
        bop,
        index,
        &[
            CURRENT_PROCESS32,
            G32_INOUT_A as u32,
            0, // ZeroBits — wow64.dll replaces this with its own 0x7fffffff
            G32_INOUT_B as u32,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        ],
    );
    mem.write_u32(G32_INOUT_A, 0).unwrap(); // *BaseAddress = NULL → kernel picks
    mem.write_u32(G32_INOUT_B, 0x2000).unwrap(); // *RegionSize

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
    // THE LOAD-BEARING CHECK: the base the *32-bit guest* sees is the real,
    // writable allocation — not a pointer truncated out of the 64-bit arena.
    mem.write_u32(base, 0xCAFE_BABE).unwrap();
    assert_eq!(mem.read_u32(base).unwrap(), 0xCAFE_BABE, "the allocated pages are writable");
    assert_eq!(
        mem.read_u32(G32_ESP_OUT).unwrap(),
        G32_STACK as u32,
        "the six-argument stdcall unwound to a balanced 32-bit stack",
    );
}

