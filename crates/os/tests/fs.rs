//! Tests for the host-backed sandbox directory enumeration APIs:
//! FindFirstFileW / FindNextFileW / FindClose.
//!
//! The test harness mirrors `crt.rs`: it drives `WinOs::intercept` directly
//! with a mock `VirtualMemory` and `CpuState`, bypassing the CPU interpreter.

use std::collections::HashSet;

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// Guest memory layout for these tests.
const DATA: u64 = 0x4000; // writable data segment (4 KiB)
const STACK: u64 = 0x9000; // stack grows down from here
const RET_ADDR: u64 = 0x1_2345; // synthetic return address

// Windows INVALID_HANDLE_VALUE as seen by a 64-bit guest.
const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF;

// Offset of cFileName inside WIN32_FIND_DATAW.
const FIND_DATA_CFILENAME_OFFSET: u64 = 44;

fn make_os(sandbox: &str) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    // Data + stack + heap + API-thunk region.
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x1_0000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x1_0000,
        echo: false,
        sandbox: sandbox.to_string(),
        ..WinConfig::default()
    });
    (os, mem)
}

/// Seat `name` as a kernel32 thunk, push a return address, invoke intercept,
/// assert it returned `Exit::Continue` to the right address, and return RAX.
fn call_k32(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    cpu: &mut CpuState,
    name: &str,
) -> u64 {
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET_ADDR).unwrap();
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "{name}: intercept should Continue");
    assert_eq!(cpu.rip, RET_ADDR, "{name}: shim must ret to caller");
    assert_eq!(cpu.rsp(), STACK + 8, "{name}: stack must be balanced");
    cpu.reg(Reg::Rax)
}

/// Write a NUL-terminated UTF-16 string into guest memory.
fn write_utf16(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, unit) in s.encode_utf16().chain(std::iter::once(0)).enumerate() {
        mem.write_u16(addr + i as u64 * 2, unit).unwrap();
    }
}

/// Read a NUL-terminated UTF-16 string from guest memory (up to `max` chars).
fn read_utf16(mem: &VirtualMemory, addr: u64, max: usize) -> String {
    let mut units = Vec::new();
    for i in 0..max {
        let u = mem.read_u16(addr + i as u64 * 2).unwrap();
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units).to_owned()
}

/// A unique temp-dir path for this test run (process id + a static counter
/// so parallel test threads do not collide).
fn unique_sandbox() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "exemu_fs_test_{}_{:04}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[test]
fn find_first_next_close_enumerates_txt_files() {
    // Build a mini sandbox: <tmp>/C/dir/a.txt + b.txt
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("a.txt"), b"hello").unwrap();
    std::fs::write(dir_c.join("b.txt"), b"world").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    // Guest layout:
    //   DATA+0x000  ← pattern string (UTF-16)
    //   DATA+0x100  ← 592-byte WIN32_FIND_DATAW buffer
    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    // FindFirstFileW("C:\dir\*.txt", &find_data)
    write_utf16(&mut mem, pattern_ptr, "C:\\dir\\*.txt");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");

    assert_ne!(handle, INVALID_HANDLE_VALUE, "FindFirstFileW must succeed");

    // First filename (cFileName is at offset 44).
    let first_name =
        read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260);

    // Collect remaining names with FindNextFileW.
    let mut names: Vec<String> = vec![first_name];
    loop {
        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, find_data_ptr);
        let ok = call_k32(&mut os, &mut mem, &mut cpu, "FindNextFileW");
        if ok == 0 {
            break;
        }
        names.push(read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260));
    }

    let name_set: HashSet<&str> = names.iter().map(String::as_str).collect();
    assert!(name_set.contains("a.txt"), "a.txt missing; got {:?}", name_set);
    assert!(name_set.contains("b.txt"), "b.txt missing; got {:?}", name_set);

    // FindClose must return TRUE.
    cpu.set_reg(Reg::Rcx, handle);
    let closed = call_k32(&mut os, &mut mem, &mut cpu, "FindClose");
    assert_eq!(closed, 1, "FindClose must return TRUE");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn find_first_no_match_returns_invalid_handle() {
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("a.txt"), b"hello").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    write_utf16(&mut mem, pattern_ptr, "C:\\dir\\*.zip");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");

    assert_eq!(
        handle, INVALID_HANDLE_VALUE,
        "no-match pattern must return INVALID_HANDLE_VALUE"
    );

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn wildcard_star_includes_dot_dotdot() {
    // A pattern of "C:\dir\*" must include the "." and ".." virtual entries
    // that Windows returns for a star glob.
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("file.txt"), b"data").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    write_utf16(&mut mem, pattern_ptr, "C:\\dir\\*");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");
    assert_ne!(handle, INVALID_HANDLE_VALUE);

    let mut names = vec![read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260)];
    loop {
        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, find_data_ptr);
        if call_k32(&mut os, &mut mem, &mut cpu, "FindNextFileW") == 0 {
            break;
        }
        names.push(read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260));
    }

    let name_set: HashSet<&str> = names.iter().map(String::as_str).collect();
    assert!(name_set.contains("."), ". missing; got {:?}", name_set);
    assert!(name_set.contains(".."), ".. missing; got {:?}", name_set);
    assert!(name_set.contains("file.txt"), "file.txt missing; got {:?}", name_set);

    cpu.set_reg(Reg::Rcx, handle);
    call_k32(&mut os, &mut mem, &mut cpu, "FindClose");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn find_data_attributes_set_correctly() {
    // Verify that dwFileAttributes is FILE_ATTRIBUTE_DIRECTORY (0x10) for
    // directories and FILE_ATTRIBUTE_NORMAL (0x80) for regular files.
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("root");
    let subdir = dir_c.join("subdir");
    std::fs::create_dir_all(&subdir).unwrap();
    std::fs::write(dir_c.join("file.txt"), b"x").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    write_utf16(&mut mem, pattern_ptr, "C:\\root\\*");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");
    assert_ne!(handle, INVALID_HANDLE_VALUE);

    let mut attr_by_name: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    loop {
        let name = read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260);
        let attrs = mem.read_u32(find_data_ptr).unwrap(); // dwFileAttributes at offset 0
        attr_by_name.insert(name, attrs);

        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, find_data_ptr);
        if call_k32(&mut os, &mut mem, &mut cpu, "FindNextFileW") == 0 {
            break;
        }
    }

    // "." and ".." are directories.
    assert_eq!(
        attr_by_name.get(".").copied().unwrap_or(0),
        0x10,
        ". must have FILE_ATTRIBUTE_DIRECTORY"
    );
    assert_eq!(
        attr_by_name.get("..").copied().unwrap_or(0),
        0x10,
        ".. must have FILE_ATTRIBUTE_DIRECTORY"
    );
    // "subdir" is a directory.
    assert_eq!(
        attr_by_name.get("subdir").copied().unwrap_or(0),
        0x10,
        "subdir must have FILE_ATTRIBUTE_DIRECTORY"
    );
    // "file.txt" is a normal file.
    assert_eq!(
        attr_by_name.get("file.txt").copied().unwrap_or(0),
        0x80,
        "file.txt must have FILE_ATTRIBUTE_NORMAL"
    );

    cpu.set_reg(Reg::Rcx, handle);
    call_k32(&mut os, &mut mem, &mut cpu, "FindClose");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn find_close_on_unknown_handle_is_lenient() {
    // FindClose on a bogus handle (e.g. INVALID_HANDLE_VALUE) must return TRUE
    // and not panic — some callers are sloppy about error-path cleanup.
    let sandbox = unique_sandbox();
    std::fs::create_dir_all(sandbox.join("C")).unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, INVALID_HANDLE_VALUE);
    let r = call_k32(&mut os, &mut mem, &mut cpu, "FindClose");
    assert_eq!(r, 1, "FindClose on unknown handle must return TRUE");

    let _ = std::fs::remove_dir_all(&sandbox);
}

// ─── P3.9 additions: A-variants, GetFullPathName, Copy/MoveFile ─────────────

fn write_ansi(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, b) in s.bytes().chain(std::iter::once(0)).enumerate() {
        mem.write_u8(addr + i as u64, b).unwrap();
    }
}

fn read_ansi(mem: &VirtualMemory, addr: u64, max: usize) -> String {
    let mut bytes = Vec::new();
    for i in 0..max {
        let b = mem.read_u8(addr + i as u64).unwrap();
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn find_first_next_close_ansi_enumerates() {
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("a.txt"), b"hello").unwrap();
    std::fs::write(dir_c.join("b.txt"), b"world").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();
    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    write_ansi(&mut mem, pattern_ptr, "C:\\dir\\*.txt");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileA");
    assert_ne!(handle, INVALID_HANDLE_VALUE, "FindFirstFileA must succeed");

    let mut names = vec![read_ansi(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260)];
    loop {
        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, find_data_ptr);
        if call_k32(&mut os, &mut mem, &mut cpu, "FindNextFileA") == 0 {
            break;
        }
        names.push(read_ansi(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260));
    }
    let set: HashSet<&str> = names.iter().map(String::as_str).collect();
    assert!(set.contains("a.txt") && set.contains("b.txt"), "got {set:?}");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn get_full_path_name_makes_absolute() {
    let sandbox = unique_sandbox();
    std::fs::create_dir_all(sandbox.join("C")).unwrap();
    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    let name_ptr = DATA;
    let buf = DATA + 0x100;
    let part_ptr = DATA + 0x300;
    write_utf16(&mut mem, name_ptr, "sub\\file.txt");
    cpu.set_reg(Reg::Rcx, name_ptr);
    cpu.set_reg(Reg::Rdx, 260); // nBufferLength (chars)
    cpu.set_reg(Reg::R8, buf);
    cpu.set_reg(Reg::R9, part_ptr);
    let n = call_k32(&mut os, &mut mem, &mut cpu, "GetFullPathNameW");
    assert!(n > 0, "GetFullPathNameW returned 0");
    assert_eq!(read_utf16(&mem, buf, 260), "C:\\sub\\file.txt");
    // lpFilePart points at "file.txt" within the buffer.
    let part = mem.read_u64(part_ptr).unwrap();
    assert_eq!(read_utf16(&mem, part, 260), "file.txt");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn copy_then_move_file_roundtrip() {
    let sandbox = unique_sandbox();
    let c = sandbox.join("C");
    std::fs::create_dir_all(&c).unwrap();
    std::fs::write(c.join("a.txt"), b"payload").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();
    let src = DATA;
    let dst = DATA + 0x80;
    let dst2 = DATA + 0x100;

    // CopyFileW("C:\a.txt", "C:\b.txt", FALSE)
    write_utf16(&mut mem, src, "C:\\a.txt");
    write_utf16(&mut mem, dst, "C:\\b.txt");
    cpu.set_reg(Reg::Rcx, src);
    cpu.set_reg(Reg::Rdx, dst);
    cpu.set_reg(Reg::R8, 0);
    assert_eq!(call_k32(&mut os, &mut mem, &mut cpu, "CopyFileW"), 1, "CopyFileW must succeed");
    assert!(c.join("b.txt").exists(), "copy target missing");

    // MoveFileW("C:\b.txt", "C:\c.txt")
    write_utf16(&mut mem, dst2, "C:\\c.txt");
    cpu.set_reg(Reg::Rcx, dst);
    cpu.set_reg(Reg::Rdx, dst2);
    assert_eq!(call_k32(&mut os, &mut mem, &mut cpu, "MoveFileW"), 1, "MoveFileW must succeed");
    assert!(c.join("c.txt").exists(), "move target missing");
    assert!(!c.join("b.txt").exists(), "source should be gone after move");

    let _ = std::fs::remove_dir_all(&sandbox);
}
