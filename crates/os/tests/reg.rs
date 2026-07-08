//! Tests for the in-memory registry hive (roadmap P3.12, partial).
//! Drives `WinOs::intercept` directly with a mock `VirtualMemory` +
//! `CpuState`, exactly as the interpreter would call it.

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// ── layout constants ──────────────────────────────────────────────────────────
const DATA: u64 = 0x4000;
const STACK: u64 = 0x9000;
const RET_ADDR: u64 = 0x1_2345;

// Predefined root handles (mirrors the constants in lib.rs).
const HKCU: u64 = 0x8000_0001;
const HKLM: u64 = 0x8000_0002;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    // DATA page for strings and output buffers.
    mem.map(Region::new("data", DATA, 0x2000, Perm::RW)).unwrap();
    // Stack: 0x8000..0xA000 so writes at STACK+0x48 (arg8) are safe.
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    // API thunk region.
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x1000, Perm::RW)).unwrap();
    // Heap arena.
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();

    let os = WinOs::new(WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        echo: false,
        ..WinConfig::default()
    });
    (os, mem)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Call `dll!name` through `WinOs::intercept`, return RAX. No stack-resident
/// args are set here — callers that need args 4+ must write them to the stack
/// at `[STACK + 0x28 + (i-4)*8]` before calling.
fn call_reg(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    cpu: &mut CpuState,
    dll: &str,
    name: &str,
) -> u64 {
    let thunk = os.resolve_import(dll, &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "{name} should return Continue");
    assert_eq!(cpu.rip, RET_ADDR, "{name} did not ret to caller");
    assert_eq!(cpu.rsp(), STACK + 8, "{name} left stack unbalanced");
    cpu.reg(Reg::Rax)
}

/// Write a NUL-terminated UTF-16 string into guest memory at `addr`.
fn write_wstr(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, u) in s.encode_utf16().chain([0]).enumerate() {
        mem.write_u16(addr + i as u64 * 2, u).unwrap();
    }
}

/// Seat a stack-resident argument (args 4+ in Win64 ABI) before the call:
/// `arg_index` is 0-based (0 = RCX, ..., 4 = [rsp+0x28]).
fn seat_stack_arg(mem: &mut VirtualMemory, arg_index: usize, value: u64) {
    assert!(arg_index >= 4, "use cpu.set_reg for args 0-3");
    let offset = 0x28 + (arg_index as u64 - 4) * 8;
    mem.write_u64(STACK + offset, value).unwrap();
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn reg_create_and_open_roundtrip() {
    // RegCreateKeyExW(HKCU, "Software\\ExemuTest", ..., &phkResult, &disp)
    // -> returns 0, writes a handle into phkResult.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // Addresses in DATA page.
    let subkey = DATA; // "Software\ExemuTest" (wide)
    let phk_result = DATA + 0x100; // HKEY output
    let lpdw_disp = DATA + 0x108; // disposition output

    write_wstr(&mut mem, subkey, "Software\\ExemuTest");

    // RegCreateKeyExW(hKey, lpSubKey, 0, 0, 0, 0, 0, phkResult, lpdwDisp)
    // Win64 ABI: RCX=hKey, RDX=subkey, R8=0, R9=0,
    //            [rsp+0x28]=0 (dwOptions), [rsp+0x30]=0 (samDesired),
    //            [rsp+0x38]=0 (lpSecurity), [rsp+0x40]=phkResult,
    //            [rsp+0x48]=lpdwDisp
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0); // dwOptions
    seat_stack_arg(&mut mem, 5, 0); // samDesired
    seat_stack_arg(&mut mem, 6, 0); // lpSecurity
    seat_stack_arg(&mut mem, 7, phk_result);
    seat_stack_arg(&mut mem, 8, lpdw_disp);

    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExW");
    assert_eq!(r, 0, "RegCreateKeyExW must return 0 (ERROR_SUCCESS)");

    let hkey = mem.read_u64(phk_result).unwrap();
    assert_ne!(hkey, 0, "phkResult must be non-null");

    let disp = mem.read_u32(lpdw_disp).unwrap();
    assert_eq!(disp, 1, "first create => REG_CREATED_NEW_KEY (1)");

    // RegCloseKey
    cpu.set_reg(Reg::Rcx, hkey);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCloseKey");
    assert_eq!(r, 0, "RegCloseKey must return 0");
}

#[test]
fn reg_set_then_query() {
    // Full round-trip: Create -> Set -> Query.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    // Layout.
    let subkey = DATA;
    let val_name = DATA + 0x080;
    let val_data = DATA + 0x100; // source bytes ("hello" as UTF-16)
    let phk_result = DATA + 0x200;
    let lpdw_disp = DATA + 0x208;
    let out_type = DATA + 0x210;
    let out_buf = DATA + 0x220;
    let out_cb = DATA + 0x230;

    write_wstr(&mut mem, subkey, "Software\\ExemuTest");
    write_wstr(&mut mem, val_name, "Val");

    // Write "hello" as UTF-16 into val_data.
    let hello_units: Vec<u16> = "hello".encode_utf16().collect();
    let hello_bytes: Vec<u8> = hello_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let hello_cb = hello_bytes.len() as u64;
    for (i, b) in hello_bytes.iter().enumerate() {
        mem.write_u8(val_data + i as u64, *b).unwrap();
    }

    // 1. RegCreateKeyExW
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0);
    seat_stack_arg(&mut mem, 5, 0);
    seat_stack_arg(&mut mem, 6, 0);
    seat_stack_arg(&mut mem, 7, phk_result);
    seat_stack_arg(&mut mem, 8, lpdw_disp);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExW");
    assert_eq!(r, 0);
    let hkey = mem.read_u64(phk_result).unwrap();
    assert_ne!(hkey, 0);

    // 2. RegSetValueExW(hKey, "Val", 0, REG_SZ=1, val_data, hello_cb)
    // RCX=hKey, RDX=val_name, R8=0 (Reserved), R9=1 (REG_SZ),
    // [rsp+0x28]=val_data, [rsp+0x30]=hello_cb
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0); // Reserved
    cpu.set_reg(Reg::R9, 1); // REG_SZ
    seat_stack_arg(&mut mem, 4, val_data);
    seat_stack_arg(&mut mem, 5, hello_cb);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegSetValueExW");
    assert_eq!(r, 0, "RegSetValueExW must return 0");

    // 3. RegQueryValueExW(hKey, "Val", 0, &type, &buf, &cb)
    // Seed the caller's buffer-size field first.
    mem.write_u32(out_cb, 0x400).unwrap();
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0); // Reserved
    cpu.set_reg(Reg::R9, out_type);
    seat_stack_arg(&mut mem, 4, out_buf);
    seat_stack_arg(&mut mem, 5, out_cb);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegQueryValueExW");
    assert_eq!(r, 0, "RegQueryValueExW must return 0 for a known value");

    // Type must be REG_SZ.
    let ty = mem.read_u32(out_type).unwrap();
    assert_eq!(ty, 1, "stored type must be REG_SZ (1)");

    // Byte count must equal what we stored.
    let returned_cb = mem.read_u32(out_cb).unwrap();
    assert_eq!(returned_cb as u64, hello_cb, "returned byte count must match");

    // Bytes in out_buf must equal the original UTF-16 data.
    for (i, &expected) in hello_bytes.iter().enumerate() {
        let got = mem.read_u8(out_buf + i as u64).unwrap();
        assert_eq!(got, expected, "byte {i} mismatch");
    }

    // 4. RegCloseKey
    cpu.set_reg(Reg::Rcx, hkey);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCloseKey");
    assert_eq!(r, 0);
}

#[test]
fn reg_query_missing_value_returns_not_found() {
    // RegQueryValueExW for a value that was never written → ERROR_FILE_NOT_FOUND (2).
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    let subkey = DATA;
    let val_name = DATA + 0x080;
    let missing_name = DATA + 0x100;
    let phk_result = DATA + 0x200;
    let lpdw_disp = DATA + 0x208;
    let out_type = DATA + 0x210;
    let out_buf = DATA + 0x220;
    let out_cb = DATA + 0x230;

    write_wstr(&mut mem, subkey, "Software\\ExemuTest");
    write_wstr(&mut mem, val_name, "Present");
    write_wstr(&mut mem, missing_name, "Absent");

    // Create the key.
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0);
    seat_stack_arg(&mut mem, 5, 0);
    seat_stack_arg(&mut mem, 6, 0);
    seat_stack_arg(&mut mem, 7, phk_result);
    seat_stack_arg(&mut mem, 8, lpdw_disp);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExW");
    let hkey = mem.read_u64(phk_result).unwrap();

    // Set only "Present".
    let present_bytes: Vec<u8> = "ok".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    for (i, b) in present_bytes.iter().enumerate() {
        mem.write_u8(DATA + 0x300 + i as u64, *b).unwrap();
    }
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 1); // REG_SZ
    seat_stack_arg(&mut mem, 4, DATA + 0x300);
    seat_stack_arg(&mut mem, 5, present_bytes.len() as u64);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegSetValueExW");

    // Query "Absent" — must return 2.
    mem.write_u32(out_cb, 0x400).unwrap();
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, missing_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, out_type);
    seat_stack_arg(&mut mem, 4, out_buf);
    seat_stack_arg(&mut mem, 5, out_cb);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegQueryValueExW");
    assert_eq!(r, 2, "missing value must return ERROR_FILE_NOT_FOUND (2)");

    cpu.set_reg(Reg::Rcx, hkey);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCloseKey");
}

#[test]
fn reg_open_never_written_returns_not_found() {
    // RegOpenKeyExW for a path never written must NOT auto-create;
    // it must return ERROR_FILE_NOT_FOUND (2).
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    let subkey = DATA;
    let phk_result = DATA + 0x200;

    write_wstr(&mut mem, subkey, "Software\\NeverWritten");

    // RegOpenKeyExW(HKLM, "Software\\NeverWritten", 0, 0, &phkResult)
    // RCX=HKLM, RDX=subkey, R8=0, R9=0, [rsp+0x28]=phkResult
    cpu.set_reg(Reg::Rcx, HKLM);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, phk_result);

    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegOpenKeyExW");
    assert_eq!(r, 2, "RegOpenKeyExW on unwritten key must return ERROR_FILE_NOT_FOUND (2)");
}

#[test]
fn reg_close_key_returns_success() {
    // RegCloseKey on a freshly created handle returns 0.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    let subkey = DATA;
    let phk_result = DATA + 0x200;
    let lpdw_disp = DATA + 0x208;
    write_wstr(&mut mem, subkey, "Software\\CloseTest");

    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0);
    seat_stack_arg(&mut mem, 5, 0);
    seat_stack_arg(&mut mem, 6, 0);
    seat_stack_arg(&mut mem, 7, phk_result);
    seat_stack_arg(&mut mem, 8, lpdw_disp);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExW");
    let hkey = mem.read_u64(phk_result).unwrap();
    assert_ne!(hkey, 0);

    cpu.set_reg(Reg::Rcx, hkey);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCloseKey");
    assert_eq!(r, 0, "RegCloseKey must return 0");
}

#[test]
fn reg_query_size_query_null_data() {
    // RegQueryValueExW with lpData=NULL (size query): returns 0 and writes
    // the required byte count into *lpcbData.
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();

    let subkey = DATA;
    let val_name = DATA + 0x080;
    let phk_result = DATA + 0x200;
    let lpdw_disp = DATA + 0x208;
    let out_type = DATA + 0x210;
    let out_cb = DATA + 0x230;

    write_wstr(&mut mem, subkey, "Software\\SizeQuery");
    write_wstr(&mut mem, val_name, "Num");

    // Create key.
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0);
    seat_stack_arg(&mut mem, 5, 0);
    seat_stack_arg(&mut mem, 6, 0);
    seat_stack_arg(&mut mem, 7, phk_result);
    seat_stack_arg(&mut mem, 8, lpdw_disp);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExW");
    let hkey = mem.read_u64(phk_result).unwrap();

    // Set a 4-byte DWORD value (REG_DWORD = 4).
    let dword_data: u32 = 0xDEAD_BEEF;
    let data_bytes = dword_data.to_le_bytes();
    for (i, b) in data_bytes.iter().enumerate() {
        mem.write_u8(DATA + 0x300 + i as u64, *b).unwrap();
    }
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 4); // REG_DWORD
    seat_stack_arg(&mut mem, 4, DATA + 0x300);
    seat_stack_arg(&mut mem, 5, 4); // cbData = 4 bytes
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegSetValueExW");

    // Size query: lpData = 0, lpcbData = &out_cb.
    mem.write_u32(out_cb, 0).unwrap(); // start with 0 capacity
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, out_type);
    seat_stack_arg(&mut mem, 4, 0); // lpData = NULL
    seat_stack_arg(&mut mem, 5, out_cb);
    let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegQueryValueExW");
    assert_eq!(r, 0, "size query must return 0");
    assert_eq!(mem.read_u32(out_cb).unwrap(), 4, "size query must report 4 bytes");

    cpu.set_reg(Reg::Rcx, hkey);
    call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCloseKey");
}

// ── P3.12 additions: enumeration, A-variants, seeded roots ──────────────────

fn write_astr(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, b) in s.bytes().chain([0]).enumerate() {
        mem.write_u8(addr + i as u64, b).unwrap();
    }
}

fn read_wstr_at(mem: &VirtualMemory, addr: u64) -> String {
    let mut units = Vec::new();
    for i in 0.. {
        let u = mem.read_u16(addr + i * 2).unwrap();
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// Create HKCU\<path> (helper for the enum test).
fn create_key(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, path: &str) {
    let subkey = DATA + 0x400;
    let phk = DATA + 0x500;
    write_wstr(mem, subkey, path);
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(mem, 4, 0);
    seat_stack_arg(mem, 5, 0);
    seat_stack_arg(mem, 6, 0);
    seat_stack_arg(mem, 7, phk);
    seat_stack_arg(mem, 8, 0);
    assert_eq!(call_reg(os, mem, cpu, "advapi32.dll", "RegCreateKeyExW"), 0);
}

#[test]
fn reg_enum_key_lists_subkeys() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    create_key(&mut os, &mut mem, &mut cpu, "Software\\Enum\\Alpha");
    create_key(&mut os, &mut mem, &mut cpu, "Software\\Enum\\Beta");

    // Open the parent.
    let subkey = DATA;
    let phk = DATA + 0x100;
    write_wstr(&mut mem, subkey, "Software\\Enum");
    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, phk);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegOpenKeyExW"), 0);
    let hkey = mem.read_u64(phk).unwrap();

    let name_buf = DATA + 0x200;
    let cch = DATA + 0x300;
    let mut names = Vec::new();
    for i in 0..3u64 {
        mem.write_u32(cch, 260).unwrap();
        cpu.set_reg(Reg::Rcx, hkey);
        cpu.set_reg(Reg::Rdx, i);
        cpu.set_reg(Reg::R8, name_buf);
        cpu.set_reg(Reg::R9, cch);
        seat_stack_arg(&mut mem, 4, 0);
        seat_stack_arg(&mut mem, 5, 0);
        seat_stack_arg(&mut mem, 6, 0);
        seat_stack_arg(&mut mem, 7, 0);
        let r = call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegEnumKeyExW");
        if r == 259 {
            break; // ERROR_NO_MORE_ITEMS
        }
        assert_eq!(r, 0);
        names.push(read_wstr_at(&mem, name_buf));
    }
    assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()], "sorted subkeys");
}

#[test]
fn reg_ansi_roundtrip() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let subkey = DATA;
    let val_name = DATA + 0x80;
    let val_data = DATA + 0x100;
    let phk = DATA + 0x200;
    let out_type = DATA + 0x210;
    let out_buf = DATA + 0x220;
    let out_cb = DATA + 0x240;

    write_astr(&mut mem, subkey, "Software\\AnsiTest");
    write_astr(&mut mem, val_name, "AVal");
    write_astr(&mut mem, val_data, "hi"); // 3 bytes incl NUL

    cpu.set_reg(Reg::Rcx, HKCU);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, 0);
    seat_stack_arg(&mut mem, 5, 0);
    seat_stack_arg(&mut mem, 6, 0);
    seat_stack_arg(&mut mem, 7, phk);
    seat_stack_arg(&mut mem, 8, 0);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegCreateKeyExA"), 0);
    let hkey = mem.read_u64(phk).unwrap();

    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 1); // REG_SZ
    seat_stack_arg(&mut mem, 4, val_data);
    seat_stack_arg(&mut mem, 5, 3);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegSetValueExA"), 0);

    mem.write_u32(out_cb, 0x100).unwrap();
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, out_type);
    seat_stack_arg(&mut mem, 4, out_buf);
    seat_stack_arg(&mut mem, 5, out_cb);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegQueryValueExA"), 0);
    assert_eq!(mem.read_u32(out_cb).unwrap(), 3);
    assert_eq!(mem.read_u8(out_buf).unwrap(), b'h');
    assert_eq!(mem.read_u8(out_buf + 1).unwrap(), b'i');
}

#[test]
fn reg_seeded_hklm_product_name() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::new();
    let subkey = DATA;
    let val_name = DATA + 0x100;
    let phk = DATA + 0x180;
    let out_buf = DATA + 0x200;
    let out_cb = DATA + 0x300;

    write_wstr(&mut mem, subkey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    write_wstr(&mut mem, val_name, "ProductName");
    cpu.set_reg(Reg::Rcx, HKLM);
    cpu.set_reg(Reg::Rdx, subkey);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, phk);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegOpenKeyExW"), 0, "seeded key must open");
    let hkey = mem.read_u64(phk).unwrap();

    mem.write_u32(out_cb, 0x200).unwrap();
    cpu.set_reg(Reg::Rcx, hkey);
    cpu.set_reg(Reg::Rdx, val_name);
    cpu.set_reg(Reg::R8, 0);
    cpu.set_reg(Reg::R9, 0);
    seat_stack_arg(&mut mem, 4, out_buf);
    seat_stack_arg(&mut mem, 5, out_cb);
    assert_eq!(call_reg(&mut os, &mut mem, &mut cpu, "advapi32.dll", "RegQueryValueExW"), 0);
    assert_eq!(read_wstr_at(&mem, out_buf), "Windows 10 Pro");
}
