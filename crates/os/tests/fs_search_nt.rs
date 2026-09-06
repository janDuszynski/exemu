use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;

const NT_OPEN_FILE: u32 = 0x33;
const NT_QUERY_ATTRIBUTES_FILE: u32 = 0x3d;
const NT_FS_CONTROL_FILE: u32 = 0x39;
const NT_TERMINATE_PROCESS: u32 = 0x2c;

const STATUS_SUCCESS: u64 = 0;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;

const GENERIC_READ: u64 = 0x8000_0000;
const NT_CURRENT_PROCESS: u64 = u64::MAX;

const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

enum SysOutcome {
    Halted(u64),
    Exited(i32),
}

fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> SysOutcome {
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x48, 0xB9]);
    asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]);
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm.push(0xF4);
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
            Exit::Halted => break SysOutcome::Halted(cpu.state().reg(Reg::Rax)),
            Exit::ProcessExit(code) => break SysOutcome::Exited(code),
            other => panic!("unexpected exit: {other:?}"),
        }
    }
}

fn status(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    match syscall(os, mem, index, args) {
        SysOutcome::Halted(rax) => rax,
        SysOutcome::Exited(c) => panic!("syscall {index:#x} exited the process ({c}) unexpectedly"),
    }
}

fn setup(sandbox: &std::path::Path, prefix: &std::path::Path) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        sandbox: sandbox.to_string_lossy().into_owned(),
        wine_dll_dir: Some(prefix.to_string_lossy().into_owned()),
        ..WinConfig::default()
    });
    (os, mem)
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

#[test]
fn nt_open_and_query_kernel32_via_wine_prefix() {
    let base = std::env::temp_dir().join(format!("exemu-w3_2fs-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let prefix = base.join("prefix");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(sandbox.join("C").join("windows").join("system32")).unwrap();
    std::fs::create_dir_all(&prefix).unwrap();
    let dll_bytes = b"MZ this stands in for the pinned kernel32.dll bytes";
    std::fs::write(prefix.join("kernel32.dll"), dll_bytes).unwrap();
    let (mut os, mut mem) = setup(&sandbox, &prefix);

    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let info_ptr = SCRATCH + 0x40;
    let oa_ptr = SCRATCH + 0x100;

    write_object_attributes(&mut mem, oa_ptr, "\\??\\C:\\windows\\system32\\kernel32.dll");
    let st = status(
        &mut os,
        &mut mem,
        NT_OPEN_FILE,
        &[handle_ptr, GENERIC_READ, oa_ptr, iosb_ptr, 0, 0x20 ],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtOpenFile resolves kernel32 via the Wine prefix");
    let handle = mem.read_u64(handle_ptr).unwrap();
    assert_ne!(handle, 0, "a real file handle was written back");
    assert_eq!(mem.read_u32(iosb_ptr).unwrap() as u64, STATUS_SUCCESS, "IOSB.Status");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), 1, "IOSB.Information = FILE_OPENED");

    let st = status(&mut os, &mut mem, NT_QUERY_ATTRIBUTES_FILE, &[oa_ptr, info_ptr]);
    assert_eq!(st, STATUS_SUCCESS, "NtQueryAttributesFile succeeds");
    assert_eq!(
        mem.read_u32(info_ptr + 0x20).unwrap(),
        FILE_ATTRIBUTE_NORMAL,
        "FileAttributes = FILE_ATTRIBUTE_NORMAL for a regular file"
    );
    assert_ne!(mem.read_u64(info_ptr + 0x10).unwrap(), 0, "LastWriteTime populated");

    let st = status(&mut os, &mut mem, NT_FS_CONTROL_FILE, &[handle, 0, 0, 0, iosb_ptr, 0x9009c, 0, 0, 0, 0]);
    assert_ne!(st, STATUS_SUCCESS, "NtFsControlFile reparse probe returns a benign non-success");

    write_object_attributes(&mut mem, oa_ptr, "\\??\\C:\\windows\\system32\\does-not-exist.dll");
    let st = status(
        &mut os,
        &mut mem,
        NT_OPEN_FILE,
        &[handle_ptr, GENERIC_READ, oa_ptr, iosb_ptr, 0, 0x20],
    );
    assert_eq!(st, STATUS_OBJECT_NAME_NOT_FOUND, "a missing DLL is OBJECT_NAME_NOT_FOUND");

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn nt_terminate_process_current_exits() {
    let dir = std::env::temp_dir().join(format!("exemu-w3_2term-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir, &dir);

    match syscall(&mut os, &mut mem, NT_TERMINATE_PROCESS, &[NT_CURRENT_PROCESS, 0x2a]) {
        SysOutcome::Exited(code) => assert_eq!(code, 0x2a, "exit code propagates"),
        SysOutcome::Halted(rax) => panic!("expected a process exit, got NTSTATUS {rax:#x}"),
    }

    match syscall(&mut os, &mut mem, NT_TERMINATE_PROCESS, &[0, 7]) {
        SysOutcome::Exited(code) => assert_eq!(code, 7, "handle 0 = current process"),
        SysOutcome::Halted(rax) => panic!("expected a process exit, got NTSTATUS {rax:#x}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
