//! W2.13 — the NT registry syscalls (`NtCreateKey`/`NtOpenKey`/`NtQueryValueKey`/
//! `NtSetValueKey`/`NtEnumerateKey`/`NtQueryKey`), driven end-to-end through the
//! real interpreter + the W2.3 SSDT dispatcher exactly as a Wine PE `Nt*` stub
//! would (`mov r10,rcx; mov eax,N; syscall`).
//!
//! De-risk (roadmap W2.13): a create → set → query round-trip through the raw
//! syscall path, the KEY_VALUE class buffer-sizing protocol, sub-key enumeration
//! and key-info queries, and that the NT namespace (`\Registry\Machine\…`) meets
//! the Win32 seam's hive in one place (the Win32-seeded `ProductName` reads back
//! through NtOpenKey/NtQueryValueKey).

use exemu_core::{Cpu, Exit, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// SSDT indices recovered from the pinned guest ntdll.dll stubs' `mov eax,N`.
const NT_CREATE_KEY: u32 = 0x1d;
const NT_OPEN_KEY: u32 = 0x12;
const NT_QUERY_VALUE_KEY: u32 = 0x17;
const NT_SET_VALUE_KEY: u32 = 0x60;
const NT_ENUMERATE_KEY: u32 = 0x32;
const NT_QUERY_KEY: u32 = 0x16;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001A;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;

// Predefined root pseudo-handle (usable as OBJECT_ATTRIBUTES.RootDirectory).
const HKLM: u64 = 0x8000_0002;

// Value types + info classes (public winnt.h / wdm.h).
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const KEY_VALUE_FULL_INFORMATION: u64 = 1;
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
const KEY_BASIC_INFORMATION: u64 = 0;
const KEY_FULL_INFORMATION: u64 = 2;
const KEY_NAME_INFORMATION: u64 = 3;

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const PEB: u64 = GS_BASE + 0x2000;
const TEB_SIZE: u64 = 0x2000;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    (os, mem)
}

/// Assemble `mov rcx,arg0; mov r10,rcx; mov eax,N; syscall; hlt`, run it on a
/// fresh interpreter over the shared `os`/`mem`, and return RAX. args 1..=3 land
/// in RDX/R8/R9; args 4+ on the guest stack at `[rsp+0x28+…]`.
fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
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
        s.gs_base = GS_BASE;
        let regs = [exemu_core::Reg::Rdx, exemu_core::Reg::R8, exemu_core::Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os).expect("syscall faulted") {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(exemu_core::Reg::Rax)
}

/// Lay a UNICODE_STRING + its wide buffer at `addr`, return the UNICODE_STRING
/// pointer. `{Length@0, MaximumLength@2, Buffer@8}`.
fn put_ustr(mem: &mut VirtualMemory, addr: u64, s: &str) -> u64 {
    let buf = addr + 0x40;
    let units: Vec<u16> = s.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(buf + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(addr, bytes).unwrap();
    mem.write_u16(addr + 2, bytes).unwrap();
    mem.write_u64(addr + 8, buf).unwrap();
    addr
}

/// Lay an OBJECT_ATTRIBUTES {Length@0, RootDirectory@8, ObjectName@0x10} at
/// `addr` naming `name` under `root`, return its pointer.
fn put_objattr(mem: &mut VirtualMemory, addr: u64, root: u64, name: &str) -> u64 {
    let ustr = put_ustr(mem, addr + 0x100, name);
    mem.write_u32(addr, 0x30).unwrap(); // Length
    mem.write_u64(addr + 8, root).unwrap(); // RootDirectory
    mem.write_u64(addr + 0x10, ustr).unwrap(); // ObjectName
    addr
}

fn read_utf16(mem: &VirtualMemory, addr: u64, bytes: u32) -> String {
    let units: Vec<u16> = (0..bytes / 2).map(|i| mem.read_u16(addr + (i as u64) * 2).unwrap()).collect();
    String::from_utf16_lossy(&units)
}

// ==========================================================================
// The de-risk: create → set → query round-trip through the raw syscall path.
// ==========================================================================

#[test]
fn nt_create_set_query_roundtrip() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let data = SCRATCH + 0x600;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    // NtCreateKey under HKLM (RootDirectory pseudo-handle) + relative subkey.
    let oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuW213Test");
    let disp = SCRATCH + 0xC40;
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();
    assert_ne!(key, 0);
    assert_eq!(mem.read_u32(disp).unwrap(), 1); // REG_CREATED_NEW_KEY

    // NtSetValueKey: a REG_DWORD "Answer" = 42.
    let vn = put_ustr(&mut mem, vname, "Answer");
    mem.write_u32(data, 42).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_SET_VALUE_KEY, &[key, vn, 0, REG_DWORD as u64, data, 4]), STATUS_SUCCESS);

    // NtQueryValueKey (Partial): Type=REG_DWORD, DataLength=4, Data=42.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 4).unwrap(), REG_DWORD); // Type
    assert_eq!(mem.read_u32(out + 8).unwrap(), 4); // DataLength
    assert_eq!(mem.read_u32(out + 12).unwrap(), 42); // Data
    assert_eq!(mem.read_u32(rlen).unwrap(), 12 + 4); // ResultLength

    // NtQueryValueKey (Full): carries the value name too.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_FULL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    let name_len = mem.read_u32(out + 16).unwrap();
    assert_eq!(read_utf16(&mem, out + 20, name_len), "Answer");
    let data_off = mem.read_u32(out + 8).unwrap() as u64;
    assert_eq!(mem.read_u32(out + data_off).unwrap(), 42);

    // Reopen the *same* key by absolute NT path — proves \Registry\Machine\…
    // folds onto the HKLM hive the create used.
    let oa2 = put_objattr(&mut mem, objattr, 0, "\\Registry\\Machine\\SOFTWARE\\ExemuW213Test");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa2]), STATUS_SUCCESS);
    let key2 = mem.read_u64(h_out).unwrap();
    assert_ne!(key2, 0);
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key2, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 12).unwrap(), 42);

    // Recreate the existing key → REG_OPENED_EXISTING_KEY.
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(disp).unwrap(), 2);
}

// ==========================================================================
// Buffer-sizing protocol + the Win32-seeded hive is visible through the NT face.
// ==========================================================================

#[test]
fn nt_query_value_buffer_sizing_and_win32_seed_interop() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    // Open the Win32-seeded HKLM\SOFTWARE\...\CurrentVersion key by NT path.
    let oa = put_objattr(
        &mut mem,
        objattr,
        0,
        "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    );
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();

    // "ProductName" = REG_SZ "Windows 10 Pro" (14 chars + NUL → 30 bytes utf16).
    let vn = put_ustr(&mut mem, vname, "ProductName");
    let expect_data = 30u32;
    let expect_total = 12 + expect_data; // Partial header + data

    // Size query: buffer too small for the header → BUFFER_TOO_SMALL, but
    // ResultLength still reports the full size.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 8, rlen]),
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), expect_total);

    // Header fits but not the data → BUFFER_OVERFLOW; ResultLength full.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 16, rlen]),
        STATUS_BUFFER_OVERFLOW
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), expect_total);

    // Full buffer → SUCCESS, type + data correct.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 4).unwrap(), REG_SZ);
    assert_eq!(mem.read_u32(out + 8).unwrap(), expect_data);
    assert_eq!(read_utf16(&mem, out + 12, expect_data - 2), "Windows 10 Pro");

    // A missing value → OBJECT_NAME_NOT_FOUND.
    let missing = put_ustr(&mut mem, vname, "NoSuchValue");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, missing, KEY_VALUE_PARTIAL_INFORMATION, out, 0x80, rlen]),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

// ==========================================================================
// Sub-key enumeration + key-info queries.
// ==========================================================================

#[test]
fn nt_enumerate_and_query_key() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    // Create parent + two sub-keys.
    let parent_oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuEnum");
    let noarg = SCRATCH + 0xC40; // spare disposition cell
    syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, parent_oa, 0, 0, 0, noarg]);
    for sub in ["Alpha", "Beta"] {
        let oa = put_objattr(&mut mem, objattr, HKLM, &format!("SOFTWARE\\ExemuEnum\\{sub}"));
        syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, noarg]);
    }

    // Open the parent and enumerate its sub-keys (KeyBasicInformation).
    let poa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuEnum");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, poa]), STATUS_SUCCESS);
    let parent = mem.read_u64(h_out).unwrap();

    let mut names = Vec::new();
    for i in 0..2u64 {
        assert_eq!(
            syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, i, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
            STATUS_SUCCESS
        );
        let nlen = mem.read_u32(out + 12).unwrap();
        names.push(read_utf16(&mem, out + 16, nlen));
    }
    assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()]); // sorted

    // Index past the end → NO_MORE_ENTRIES.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, 2, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
        STATUS_NO_MORE_ENTRIES
    );

    // A too-small enumerate buffer → BUFFER_TOO_SMALL with the full ResultLength.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, 0, KEY_BASIC_INFORMATION, out, 8, rlen]),
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), 16 + 2 * 5); // header + "Alpha" utf16

    // NtQueryKey (Full): 2 sub-keys, 0 values.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_FULL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 20).unwrap(), 2); // SubKeys
    assert_eq!(mem.read_u32(out + 32).unwrap(), 0); // Values

    // NtQueryKey (Name): the full path of the key.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_NAME_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let nlen = mem.read_u32(out).unwrap();
    assert_eq!(read_utf16(&mem, out + 4, nlen), "HKLM\\SOFTWARE\\ExemuEnum");

    // NtQueryKey (Basic): the leaf name.
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let blen = mem.read_u32(out + 12).unwrap();
    assert_eq!(read_utf16(&mem, out + 16, blen), "ExemuEnum");
}

// ==========================================================================
// Error faces: bad handle, missing key.
// ==========================================================================

#[test]
fn nt_error_paths() -> Result<()> {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    // NtOpenKey on a nonexistent key → OBJECT_NAME_NOT_FOUND.
    let oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\DoesNotExist\\Nope");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]), STATUS_OBJECT_NAME_NOT_FOUND);

    // NtQueryValueKey on a bogus handle → INVALID_HANDLE.
    let vn = put_ustr(&mut mem, vname, "x");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[0xdead_beef, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_INVALID_HANDLE
    );
    Ok(())
}
