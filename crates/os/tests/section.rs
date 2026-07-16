//! W2.7 de-risk: section objects driven end-to-end through the real interpreter
//! and the SSDT dispatcher, exactly as Wine's PE loader would issue them via a
//! `mov r10,rcx; mov eax,N; syscall; ret` stub.
//!
//! The load-bearing check: create a `SEC_IMAGE` section over a real file, map a
//! view of it, and read the file's bytes back **through the mapped guest view** —
//! then confirm `NtQueryVirtualMemory` reports the view as `MEM_IMAGE`, and that
//! `NtUnmapViewOfSection` releases the backing (a later read faults). This is the
//! shape of Wine's `LdrLoadDll` path.

use std::io::Write;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000; // IN/OUT pointer cells + MBI buffer
const TEB_SIZE: u64 = 0x2000;

// SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
const NT_CREATE_SECTION: u32 = 0x4a;
const NT_QUERY_SECTION: u32 = 0x51;
const NT_MAP_VIEW: u32 = 0x28;
const NT_UNMAP_VIEW: u32 = 0x2a;
const NT_QUERY: u32 = 0x23;

const SEC_IMAGE: u64 = 0x0100_0000;
const PAGE_READONLY: u64 = 0x02;
const MEM_IMAGE: u32 = 0x0100_0000;
const MEMORY_BASIC_INFORMATION: u64 = 0;
const STATE_COMMIT: u32 = 0x1000;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;

/// Drive one raw `SYSCALL n` through the real interpreter with args placed in
/// the syscall ABI registers (arg0=R10, arg1=RDX, arg2=R8, arg3=R9) plus any
/// stack args (5+) at `[rsp+0x28+(n-4)*8]`. Returns the NTSTATUS in RAX.
fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    // `mov rcx,arg0; mov r10,rcx; mov eax,N; syscall; hlt`.
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
    asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]); // mov r10, rcx
    asm.extend_from_slice(&[0xB8]); // mov eax, imm32
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]); // syscall
    asm.push(0xF4); // hlt
    mem.poke(CODE, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        let regs = [Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(Reg::Rax)
}

fn setup(sandbox: &std::path::Path) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        sandbox: sandbox.to_string_lossy().into_owned(),
        ..WinConfig::default()
    });
    (os, mem)
}

/// The W2.7 de-risk: map a DLL (any file) as a SEC_IMAGE section and read it
/// back through the mapped view, then query it as MEM_IMAGE and unmap it.
#[test]
fn sec_image_create_map_read_query_unmap() {
    // A stand-in "DLL": a small file with a recognizable payload spanning a
    // page boundary (so the view is multi-page and the tail is zero-filled).
    let dir = std::env::temp_dir().join(format!("exemu-w2_7-{}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("C"));
    let dll_path = dir.join("C").join("fake.dll");
    let mut payload = b"MZ\x90\x00this-is-the-image-header".to_vec();
    payload.resize(0x1800, 0xAB); // 6 KiB → two pages; second page all 0xAB
    payload[0x1000] = 0xCC; // a marker on the second page
    std::fs::File::create(&dll_path).unwrap().write_all(&payload).unwrap();

    let (mut os, mut mem) = setup(&dir);

    // Open the file so the section has a FileHandle to snapshot. `CreateFileW`
    // routes through the sandbox; drive it via the Win32 intercept seam.
    let handle = open_via_createfile(&mut os, &mut mem, "C:\\fake.dll");
    assert_ne!(handle, 0xFFFF_FFFF, "CreateFileW opened the fake DLL");

    // --- NtCreateSection(&sh, 0, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file). ---
    let sh_ptr = SCRATCH;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_SECTION,
        &[sh_ptr, 0, 0, 0, PAGE_READONLY, SEC_IMAGE, handle],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateSection(SEC_IMAGE) succeeds");
    let section = mem.read_u64(sh_ptr).unwrap();
    assert_ne!(section, 0, "a section handle was written back");

    // --- NtMapViewOfSection(sh, proc, &base, 0, 0, NULL, &viewsize, 1, 0, RO). ---
    let base_ptr = SCRATCH + 0x10;
    let size_ptr = SCRATCH + 0x18;
    mem.write_u64(base_ptr, 0).unwrap(); // NULL → kernel picks the base
    mem.write_u64(size_ptr, 0).unwrap(); // 0 → whole section
    let st = syscall(
        &mut os,
        &mut mem,
        NT_MAP_VIEW,
        &[section, 0xFFFF_FFFF_FFFF_FFFF, base_ptr, 0, 0, 0, size_ptr, 1, 0, PAGE_READONLY],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtMapViewOfSection succeeds");
    let base = mem.read_u64(base_ptr).unwrap();
    assert_ne!(base, 0, "a view base was written back");
    assert_eq!(base & 0xFFFF, 0, "view base is 64 KiB aligned");
    let view_size = mem.read_u64(size_ptr).unwrap();
    assert_eq!(view_size, 0x2000, "view spans the two page-rounded section pages");

    // Read the image back THROUGH THE MAPPED GUEST VIEW (the load-bearing check).
    assert_eq!(&read_bytes(&mem, base, 2), b"MZ", "PE magic via the mapped view");
    assert_eq!(&read_bytes(&mem, base + 4, 24), b"this-is-the-image-header");
    assert_eq!(mem.read_u8(base + 0x1000).unwrap(), 0xCC, "second-page marker readable");
    assert_eq!(mem.read_u8(base + 0x1001).unwrap(), 0xAB, "second-page fill readable");
    // Past the backing (0x1800) but inside the page-rounded view: zero fill.
    assert_eq!(mem.read_u8(base + 0x1800).unwrap(), 0x00, "tail past the file is zero");

    // --- NtQueryVirtualMemory(base, MemoryBasicInformation, &mbi,…) → MEM_IMAGE.
    let mbi = SCRATCH + 0x100;
    let ret_ptr = SCRATCH + 0x30;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY,
        &[0xFFFF_FFFF_FFFF_FFFF, base, MEMORY_BASIC_INFORMATION, mbi, 0x30, ret_ptr],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryVirtualMemory on the view succeeds");
    assert_eq!(mem.read_u64(mbi).unwrap(), base, "MBI.BaseAddress");
    assert_eq!(mem.read_u64(mbi + 0x18).unwrap(), 0x2000, "MBI.RegionSize");
    assert_eq!(mem.read_u32(mbi + 0x20).unwrap(), STATE_COMMIT, "MBI.State = COMMIT");
    assert_eq!(mem.read_u32(mbi + 0x28).unwrap(), MEM_IMAGE, "MBI.Type = MEM_IMAGE");

    // --- NtUnmapViewOfSection(proc, base) → the backing is released. ---
    let st = syscall(&mut os, &mut mem, NT_UNMAP_VIEW, &[0xFFFF_FFFF_FFFF_FFFF, base]);
    assert_eq!(st, STATUS_SUCCESS, "NtUnmapViewOfSection succeeds");
    assert!(mem.read_u8(base).is_err(), "unmapped view is no longer accessible");

    // A second unmap of the same (now-free) base is a clean STATUS_INVALID_PARAMETER.
    let st = syscall(&mut os, &mut mem, NT_UNMAP_VIEW, &[0xFFFF_FFFF_FFFF_FFFF, base]);
    assert_eq!(st, STATUS_INVALID_PARAMETER, "double-unmap → STATUS_INVALID_PARAMETER");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A pagefile-backed (NULL FileHandle) section maps a zero-filled view.
#[test]
fn pagefile_backed_section_is_zeroed() {
    let dir = std::env::temp_dir().join(format!("exemu-w2_7pf-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let (mut os, mut mem) = setup(&dir);

    // MaximumSize = 0x1000, no file → zero-filled section.
    let max_ptr = SCRATCH + 0x40;
    mem.write_u64(max_ptr, 0x1000).unwrap();
    let sh_ptr = SCRATCH;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_SECTION,
        &[sh_ptr, 0, 0, max_ptr, 0x04 /* PAGE_READWRITE */, 0 /* SEC_COMMIT */, 0],
    );
    assert_eq!(st, STATUS_SUCCESS);
    let section = mem.read_u64(sh_ptr).unwrap();

    let base_ptr = SCRATCH + 0x10;
    let size_ptr = SCRATCH + 0x18;
    mem.write_u64(base_ptr, 0).unwrap();
    mem.write_u64(size_ptr, 0).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_MAP_VIEW,
        &[section, 0xFFFF_FFFF_FFFF_FFFF, base_ptr, 0, 0, 0, size_ptr, 1, 0, 0x04],
    );
    assert_eq!(st, STATUS_SUCCESS);
    let base = mem.read_u64(base_ptr).unwrap();
    assert_eq!(mem.read_u64(size_ptr).unwrap(), 0x1000, "one-page view");
    assert_eq!(mem.read_u64(base).unwrap(), 0, "pagefile-backed view reads zero");
    // The view is writable (RWX backing).
    mem.write_u64(base, 0xdead_beef).unwrap();
    assert_eq!(mem.read_u64(base).unwrap(), 0xdead_beef);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A bad section handle → STATUS_INVALID_HANDLE, not a fault.
#[test]
fn map_bad_section_handle_rejected() {
    let dir = std::env::temp_dir().join(format!("exemu-w2_7bad-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let (mut os, mut mem) = setup(&dir);
    let base_ptr = SCRATCH + 0x10;
    let size_ptr = SCRATCH + 0x18;
    mem.write_u64(base_ptr, 0).unwrap();
    mem.write_u64(size_ptr, 0).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_MAP_VIEW,
        &[0xDEAD_BEEF, 0xFFFF_FFFF_FFFF_FFFF, base_ptr, 0, 0, 0, size_ptr, 1, 0, 0x02],
    );
    assert_eq!(st, 0xC000_0008, "unknown section handle → STATUS_INVALID_HANDLE");
    let _ = std::fs::remove_dir_all(&dir);
}

// --- W3.2 real SEC_IMAGE image sections ------------------------------------

/// The pinned Wine kernel32.dll (a real PE image). Absent in a checkout without
/// the `example_exe/wine-dlls/` prefix — the image-section tests skip-guard on it
/// so they never break such a checkout (like `dll_smoke`/`ntdll_decode_sweep`).
const KERNEL32: &str = "../../example_exe/wine-dlls/x86_64-windows/kernel32.dll";

const SECTION_IMAGE_INFORMATION: u64 = 1;

/// Create a `SEC_IMAGE` section over the real kernel32.dll and drive
/// `NtQuerySection(SectionImageInformation)` + image-mode `NtMapViewOfSection`
/// through the interpreter/dispatcher, asserting the W3.2 invariants:
///  - the query reports `Machine == 0x8664`, `TransferAddress == base+entry`,
///    and nonzero stack sizes;
///  - the map lays valid PE headers at the returned base, a known section's raw
///    bytes at `base + rva`, a zero-filled tail;
///  - the image is **NOT relocated** — a section's bytes equal the file's raw
///    bytes byte-for-byte even though the view base differs from the preferred
///    `ImageBase` (a relocated copy would differ at every fixup site).
#[test]
fn sec_image_kernel32_query_and_map_unrelocated() {
    let kpath = std::path::Path::new(KERNEL32);
    if !kpath.exists() {
        eprintln!("skipping: pinned kernel32.dll not present ({KERNEL32})");
        return;
    }
    let bytes = std::fs::read(kpath).unwrap();
    // Parse the same PE independently to derive the expected fields + a known
    // section to check against.
    let pe = exemu_loader::parse(&bytes).expect("kernel32.dll parses as PE");
    let preferred_base = pe.image_base;
    let expected_transfer = preferred_base + pe.entry_rva as u64;
    // Pick the first section with real initialized data whose raw len < virtual
    // size (so it also has a zero-fill tail we can check) — falling back to any
    // section with data.
    let known = pe
        .sections
        .iter()
        .find(|s| !s.data.is_empty() && (s.data.len() as u32) < s.virtual_size)
        .or_else(|| pe.sections.iter().find(|s| !s.data.is_empty()))
        .expect("kernel32 has an initialized section");
    let known_rva = known.rva;
    let known_data = known.data.clone();
    let known_vsize = known.virtual_size;

    // Stage kernel32 as C:\fake32.dll in the sandbox so CreateFileW can open it.
    let dir = std::env::temp_dir().join(format!("exemu-w3_2-{}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("C"));
    std::fs::write(dir.join("C").join("fake32.dll"), &bytes).unwrap();
    let (mut os, mut mem) = setup(&dir);

    let handle = open_via_createfile(&mut os, &mut mem, "C:\\fake32.dll");
    assert_ne!(handle, 0xFFFF_FFFF, "CreateFileW opened kernel32");

    // NtCreateSection(&sh, 0, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file).
    let sh_ptr = SCRATCH;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_SECTION,
        &[sh_ptr, 0, 0, 0, PAGE_READONLY, SEC_IMAGE, handle],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateSection(SEC_IMAGE) over kernel32");
    let section = mem.read_u64(sh_ptr).unwrap();
    assert_ne!(section, 0);

    // NtQuerySection(section, SectionImageInformation, &info, 0x40, &retlen).
    let info = SCRATCH + 0x200;
    let retlen = SCRATCH + 0x40;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_SECTION,
        &[section, SECTION_IMAGE_INFORMATION, info, 0x40, retlen],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQuerySection(SectionImageInformation)");
    assert_eq!(mem.read_u64(retlen).unwrap(), 0x40, "ReturnLength = sizeof(SECTION_IMAGE_INFORMATION)");
    assert_eq!(mem.read_u64(info).unwrap(), expected_transfer, "TransferAddress = image_base + entry_rva");
    assert_ne!(mem.read_u64(info + 0x10).unwrap(), 0, "MaximumStackSize nonzero");
    assert_ne!(mem.read_u64(info + 0x18).unwrap(), 0, "CommittedStackSize nonzero");
    assert_eq!(mem.read_u16(info + 0x30).unwrap(), 0x8664, "Machine = AMD64");
    assert_eq!(mem.read_u8(info + 0x32).unwrap(), 1, "ImageContainsCode");
    assert_eq!(mem.read_u8(info + 0x33).unwrap() & 1, 0, "ImageFlags bit0 clear");

    // A too-small buffer → STATUS_INFO_LENGTH_MISMATCH, ReturnLength set.
    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_SECTION,
        &[section, SECTION_IMAGE_INFORMATION, info, 0x10, retlen],
    );
    assert_eq!(st, 0xC000_0004, "buffer-too-small → STATUS_INFO_LENGTH_MISMATCH");
    assert_eq!(mem.read_u64(retlen).unwrap(), 0x40, "ReturnLength still 0x40");

    // NtMapViewOfSection(section, proc, &base=0, 0, 0, NULL, &viewsize=0, 1, 0, RO).
    let base_ptr = SCRATCH + 0x10;
    let size_ptr = SCRATCH + 0x18;
    mem.write_u64(base_ptr, 0).unwrap(); // NULL → kernel picks the base
    mem.write_u64(size_ptr, 0).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_MAP_VIEW,
        &[section, 0xFFFF_FFFF_FFFF_FFFF, base_ptr, 0, 0, 0, size_ptr, 1, 0, PAGE_READONLY],
    );
    assert_eq!(st, STATUS_SUCCESS, "image-mode NtMapViewOfSection");
    let base = mem.read_u64(base_ptr).unwrap();
    assert_ne!(base, 0, "a view base was written back");
    assert_eq!(base & 0xFFFF, 0, "view base is 64 KiB aligned");
    assert_ne!(base, preferred_base, "view base differs from preferred ImageBase (proves the relocation-invariant test is meaningful)");
    let view_size = mem.read_u64(size_ptr).unwrap();
    assert_eq!(view_size, pe.size_of_image as u64, "*ViewSize = SizeOfImage");

    // 1) Valid PE headers at base: MZ @base, PE\0\0 @ base+e_lfanew.
    assert_eq!(&read_bytes(&mem, base, 2), b"MZ", "MZ magic at the image base");
    let e_lfanew = mem.read_u32(base + 0x3C).unwrap() as u64;
    assert_eq!(&read_bytes(&mem, base + e_lfanew, 4), b"PE\0\0", "PE\\0\\0 at base+e_lfanew");

    // 2) A known section's raw bytes land at base + rva, UN-RELOCATED: they equal
    //    the file's raw bytes byte-for-byte. Because the view base differs from
    //    the preferred ImageBase, a relocated copy would have altered every DIR64
    //    fixup site inside this range; exact equality proves no relocation was
    //    applied here (the guest's build_module does it later).
    let mapped = read_bytes(&mem, base + known_rva as u64, known_data.len());
    assert_eq!(mapped, known_data, "section bytes at base+rva equal the file's raw bytes (un-relocated)");

    // 3) Zero-fill tail: past the raw data up to VirtualSize is zero.
    if (known_data.len() as u32) < known_vsize {
        let tail_off = base + known_rva as u64 + known_data.len() as u64;
        assert_eq!(mem.read_u8(tail_off).unwrap(), 0, "section tail past raw data is zero-filled");
    }

    // 4) The view queries as MEM_IMAGE.
    let mbi = SCRATCH + 0x300;
    let ret_ptr = SCRATCH + 0x38;
    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY,
        &[0xFFFF_FFFF_FFFF_FFFF, base, MEMORY_BASIC_INFORMATION, mbi, 0x30, ret_ptr],
    );
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(mem.read_u32(mbi + 0x28).unwrap(), MEM_IMAGE, "MBI.Type = MEM_IMAGE");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- helpers ---------------------------------------------------------------

/// Open a guest file via the Win32 `CreateFileW` intercept (OPEN_EXISTING).
fn open_via_createfile(os: &mut WinOs, mem: &mut VirtualMemory, guest: &str) -> u64 {
    use exemu_core::{Hooks, ImportSymbol};
    // Write the UTF-16 filename into scratch (well above the pointer cells).
    let name_ptr = SCRATCH + 0x300;
    let units: Vec<u16> = guest.encode_utf16().chain(std::iter::once(0)).collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(name_ptr + (i as u64) * 2, *u).unwrap();
    }
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateFileW".into()));
    let rsp = STACK_TOP - 0x100;
    mem.write_u64(rsp, 0x0000_0001_4000_1000).unwrap(); // return address
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let st = cpu.state_mut();
        st.rip = thunk;
        st.set_rsp(rsp);
        st.set_reg(Reg::Rcx, name_ptr); // lpFileName
        st.set_reg(Reg::Rdx, 0x8000_0000); // GENERIC_READ
        st.set_reg(Reg::R8, 0); // share
        st.set_reg(Reg::R9, 0); // security attrs
        // dwCreationDisposition (arg4) + flags (arg5) on the stack above shadow.
        mem.write_u64(rsp + 0x28, 3).unwrap(); // OPEN_EXISTING
        mem.write_u64(rsp + 0x30, 0).unwrap();
        mem.write_u64(rsp + 0x38, 0).unwrap();
    }
    os.intercept(thunk, cpu.state_mut(), mem).unwrap();
    cpu.state().reg(Reg::Rax)
}

fn read_bytes(mem: &VirtualMemory, addr: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    mem.read(addr, &mut b).unwrap();
    b
}
