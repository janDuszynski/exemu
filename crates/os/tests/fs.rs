use std::collections::HashSet;

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Region, Reg};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const DATA: u64 = 0x4000;
const STACK: u64 = 0x9000;
const RET_ADDR: u64 = 0x1_2345;

const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF;

const FIND_DATA_CFILENAME_OFFSET: u64 = 44;

fn make_os(sandbox: &str) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
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

fn write_utf16(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, unit) in s.encode_utf16().chain(std::iter::once(0)).enumerate() {
        mem.write_u16(addr + i as u64 * 2, unit).unwrap();
    }
}

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

fn unique_sandbox() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "exemu_fs_test_{}_{:04}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

#[test]
fn find_first_next_close_enumerates_txt_files() {
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("a.txt"), b"hello").unwrap();
    std::fs::write(dir_c.join("b.txt"), b"world").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    let pattern_ptr = DATA;
    let find_data_ptr = DATA + 0x100;

    write_utf16(&mut mem, pattern_ptr, "C:\\dir\\*.txt");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");

    assert_ne!(handle, INVALID_HANDLE_VALUE, "FindFirstFileW must succeed");

    let first_name =
        read_utf16(&mem, find_data_ptr + FIND_DATA_CFILENAME_OFFSET, 260);

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
        let attrs = mem.read_u32(find_data_ptr).unwrap();
        attr_by_name.insert(name, attrs);

        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, find_data_ptr);
        if call_k32(&mut os, &mut mem, &mut cpu, "FindNextFileW") == 0 {
            break;
        }
    }

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
    assert_eq!(
        attr_by_name.get("subdir").copied().unwrap_or(0),
        0x10,
        "subdir must have FILE_ATTRIBUTE_DIRECTORY"
    );
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
    let sandbox = unique_sandbox();
    std::fs::create_dir_all(sandbox.join("C")).unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    let mut cpu = CpuState::new();

    cpu.set_reg(Reg::Rcx, INVALID_HANDLE_VALUE);
    let r = call_k32(&mut os, &mut mem, &mut cpu, "FindClose");
    assert_eq!(r, 1, "FindClose on unknown handle must return TRUE");

    let _ = std::fs::remove_dir_all(&sandbox);
}

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
    cpu.set_reg(Reg::Rdx, 260);
    cpu.set_reg(Reg::R8, buf);
    cpu.set_reg(Reg::R9, part_ptr);
    let n = call_k32(&mut os, &mut mem, &mut cpu, "GetFullPathNameW");
    assert!(n > 0, "GetFullPathNameW returned 0");
    assert_eq!(read_utf16(&mem, buf, 260), "C:\\sub\\file.txt");
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

    write_utf16(&mut mem, src, "C:\\a.txt");
    write_utf16(&mut mem, dst, "C:\\b.txt");
    cpu.set_reg(Reg::Rcx, src);
    cpu.set_reg(Reg::Rdx, dst);
    cpu.set_reg(Reg::R8, 0);
    assert_eq!(call_k32(&mut os, &mut mem, &mut cpu, "CopyFileW"), 1, "CopyFileW must succeed");
    assert!(c.join("b.txt").exists(), "copy target missing");

    write_utf16(&mut mem, dst2, "C:\\c.txt");
    cpu.set_reg(Reg::Rcx, dst);
    cpu.set_reg(Reg::Rdx, dst2);
    assert_eq!(call_k32(&mut os, &mut mem, &mut cpu, "MoveFileW"), 1, "MoveFileW must succeed");
    assert!(c.join("c.txt").exists(), "move target missing");
    assert!(!c.join("b.txt").exists(), "source should be gone after move");

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn file_timestamps_are_still_the_host_clock_a_pinned_gap() {
    let sandbox = unique_sandbox();
    let dir_c = sandbox.join("C").join("dir");
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_c.join("a.txt"), b"hello").unwrap();

    let (mut os, mut mem) = make_os(sandbox.to_str().unwrap());
    os.set_clock(exemu_core::GuestClock::virtualized());
    let mut cpu = CpuState::new();

    let (pattern_ptr, find_data_ptr) = (DATA, DATA + 0x100);
    write_utf16(&mut mem, pattern_ptr, "C:\\dir\\a.txt");
    cpu.set_reg(Reg::Rcx, pattern_ptr);
    cpu.set_reg(Reg::Rdx, find_data_ptr);
    let handle = call_k32(&mut os, &mut mem, &mut cpu, "FindFirstFileW");
    assert_ne!(handle, INVALID_HANDLE_VALUE, "FindFirstFileW must succeed");

    let lo = mem.read_u32(find_data_ptr + 20).unwrap() as u64;
    let hi = mem.read_u32(find_data_ptr + 24).unwrap() as u64;
    let mtime = (hi << 32) | lo;

    assert!(
        mtime > exemu_core::VIRTUAL_EPOCH_FILETIME + 10_000_000,
        "file times are documented as un-virtualised; got {mtime}, virtual epoch is {}",
        exemu_core::VIRTUAL_EPOCH_FILETIME
    );

    cpu.set_reg(Reg::Rcx, handle);
    call_k32(&mut os, &mut mem, &mut cpu, "FindClose");
    let _ = std::fs::remove_dir_all(&sandbox);
}
