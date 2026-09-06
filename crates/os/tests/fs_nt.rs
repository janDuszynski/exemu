use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;

const NT_CREATE_FILE: u32 = 0x55;
const NT_READ_FILE: u32 = 0x06;
const NT_WRITE_FILE: u32 = 0x08;
const NT_QUERY_INFORMATION_FILE: u32 = 0x11;
const NT_QUERY_DIRECTORY_FILE: u32 = 0x35;
const NT_QUERY_VOLUME_INFORMATION_FILE: u32 = 0x49;
const NT_CLOSE: u32 = 0x0f;

const HANDLE_STDIN: u64 = 0x0C;
const HANDLE_STDOUT: u64 = 0x10;
const HANDLE_STDERR: u64 = 0x14;

const STATUS_SUCCESS: u64 = 0;
const STATUS_END_OF_FILE: u64 = 0xC000_0011;
const STATUS_NO_MORE_FILES: u64 = 0x8000_0006;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;

const FILE_OPEN: u64 = 1;
const FILE_CREATE: u64 = 2;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;
const FILE_STANDARD_INFORMATION: u64 = 5;
const FILE_POSITION_INFORMATION: u64 = 14;
const FILE_FS_SIZE_INFORMATION: u64 = 3;
const FILE_FS_DEVICE_INFORMATION: u64 = 4;

const GENERIC_WRITE: u64 = 0x4000_0000;

fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
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
    mem.map(Region::new("scratch", SCRATCH, 0x2000, Perm::RW)).unwrap();
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
fn nt_create_write_readback_and_queries() {
    let dir = std::env::temp_dir().join(format!("exemu-w2_8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);

    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let byteoff_ptr = SCRATCH + 0x20;
    let info_ptr = SCRATCH + 0x40;
    let oa_ptr = SCRATCH + 0x100;
    let data_ptr = SCRATCH + 0x300;

    write_object_attributes(&mut mem, oa_ptr, "\\??\\C:\\out\\hello.txt");
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_FILE,
        &[handle_ptr, GENERIC_WRITE, oa_ptr, iosb_ptr, 0, 0x80, 0, FILE_CREATE, 0x60, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtCreateFile(FILE_CREATE) succeeds");
    let handle = mem.read_u64(handle_ptr).unwrap();
    assert_ne!(handle, 0, "a file handle was written back");
    assert_eq!(mem.read_u32(iosb_ptr).unwrap() as u64, STATUS_SUCCESS, "IOSB.Status");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), FILE_CREATED, "IOSB.Information = FILE_CREATED");

    let payload = b"hello from the wine extractor";
    mem.write(data_ptr, payload).unwrap();
    mem.write_u64(byteoff_ptr, 0).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_WRITE_FILE,
        &[handle, 0, 0, 0, iosb_ptr, data_ptr, payload.len() as u64, byteoff_ptr, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWriteFile succeeds");
    assert_eq!(
        mem.read_u64(iosb_ptr + 8).unwrap(),
        payload.len() as u64,
        "IOSB.Information = bytes written"
    );

    let host_file = dir.join("C").join("out").join("hello.txt");
    assert!(host_file.exists(), "the file was created on the host under the sandbox");
    assert_eq!(std::fs::read(&host_file).unwrap(), payload, "host file has the written bytes");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_INFORMATION_FILE,
        &[handle, iosb_ptr, info_ptr, 0x18, FILE_STANDARD_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryInformationFile(standard) succeeds");
    assert_eq!(mem.read_u64(info_ptr + 8).unwrap(), payload.len() as u64, "EndOfFile = size");

    mem.write_u64(byteoff_ptr, 0).unwrap();
    mem.write(data_ptr, &[0u8; 64]).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_READ_FILE,
        &[handle, 0, 0, 0, iosb_ptr, data_ptr, 64, byteoff_ptr, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtReadFile succeeds");
    let n = mem.read_u64(iosb_ptr + 8).unwrap() as usize;
    assert_eq!(n, payload.len(), "IOSB.Information = bytes read");
    let mut got = vec![0u8; n];
    mem.read(data_ptr, &mut got).unwrap();
    assert_eq!(&got, payload, "read-back bytes match what was written");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_INFORMATION_FILE,
        &[handle, iosb_ptr, info_ptr, 8, FILE_POSITION_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(mem.read_u64(info_ptr).unwrap(), payload.len() as u64, "position at EOF after read");

    mem.write_u64(byteoff_ptr, payload.len() as u64).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_READ_FILE,
        &[handle, 0, 0, 0, iosb_ptr, data_ptr, 64, byteoff_ptr, 0],
    );
    assert_eq!(st, STATUS_END_OF_FILE, "read at EOF → STATUS_END_OF_FILE");

    let _ = std::fs::remove_dir_all(&dir);
}

const BOTH_DIR_FILE_NAME: u64 = 0x5E;

const ID_EXTD_BOTH_DIR_FILE_NAME: u64 = 0x72;

#[test]
fn nt_query_directory_enumerates() {
    let dir = std::env::temp_dir().join(format!("exemu-w2_8dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C").join("data")).unwrap();
    std::fs::write(dir.join("C").join("data").join("a.txt"), b"aa").unwrap();
    std::fs::write(dir.join("C").join("data").join("b.txt"), b"bbb").unwrap();
    let (mut os, mut mem) = setup(&dir);

    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let oa_ptr = SCRATCH + 0x100;
    let info_ptr = SCRATCH + 0x400;

    write_object_attributes(&mut mem, oa_ptr, "\\??\\C:\\data");
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_FILE,
        &[handle_ptr, 0x8000_0000, oa_ptr, iosb_ptr, 0, 0, 0, FILE_OPEN, 0x20 , 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "open the directory");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), FILE_OPENED, "IOSB = FILE_OPENED");
    let handle = mem.read_u64(handle_ptr).unwrap();

    for (class, name_off) in
        [(3u64, BOTH_DIR_FILE_NAME), (0x3F, ID_EXTD_BOTH_DIR_FILE_NAME)]
    {
        let mut names = Vec::new();
        let mut lengths = Vec::new();
        for i in 0..3 {
            let restart = if i == 0 { 1 } else { 0 };
            mem.write(info_ptr, &[0xCCu8; 0x200]).unwrap();
            let st = syscall(
                &mut os,
                &mut mem,
                NT_QUERY_DIRECTORY_FILE,
                &[handle, 0, 0, 0, iosb_ptr, info_ptr, 0x200, class, 0, 0, restart],
            );
            if st == STATUS_NO_MORE_FILES {
                break;
            }
            assert_eq!(st, STATUS_SUCCESS, "NtQueryDirectoryFile class {class:#x} entry {i}");
            let name_len = mem.read_u32(info_ptr + 0x3C).unwrap() as u64;
            let mut units = Vec::new();
            for j in 0..name_len / 2 {
                units.push(mem.read_u16(info_ptr + name_off + j * 2).unwrap());
            }
            names.push(String::from_utf16_lossy(&units));
            lengths.push((mem.read_u64(iosb_ptr + 8).unwrap(), name_off + name_len));
        }
        assert_eq!(names, vec!["a.txt", "b.txt"], "class {class:#x}: both files, in order");
        for (reported, expected) in lengths {
            assert_eq!(reported, expected, "class {class:#x}: IOSB.Information = name_off + name");
        }
    }

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_DIRECTORY_FILE,
        &[handle, 0, 0, 0, iosb_ptr, info_ptr, 0x200, 0xC, 0, 0, 1],
    );
    assert_eq!(st, 0xC000_0003, "an unimplemented class is STATUS_INVALID_INFO_CLASS");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nt_query_volume_and_bad_handle() {
    let dir = std::env::temp_dir().join(format!("exemu-w2_8vol-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("C")).unwrap();
    std::fs::write(dir.join("C").join("f.bin"), b"x").unwrap();
    let (mut os, mut mem) = setup(&dir);

    let handle_ptr = SCRATCH;
    let iosb_ptr = SCRATCH + 0x10;
    let oa_ptr = SCRATCH + 0x100;
    let info_ptr = SCRATCH + 0x40;

    write_object_attributes(&mut mem, oa_ptr, "\\??\\C:\\f.bin");
    let st = syscall(
        &mut os,
        &mut mem,
        NT_CREATE_FILE,
        &[handle_ptr, 0x8000_0000, oa_ptr, iosb_ptr, 0, 0, 0, FILE_OPEN, 0x60, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS);
    let handle = mem.read_u64(handle_ptr).unwrap();

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_VOLUME_INFORMATION_FILE,
        &[handle, iosb_ptr, info_ptr, 0x18, FILE_FS_SIZE_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS, "FILE_FS_SIZE_INFORMATION");
    assert_eq!(mem.read_u32(info_ptr + 0x14).unwrap(), 512, "BytesPerSector");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_VOLUME_INFORMATION_FILE,
        &[handle, iosb_ptr, info_ptr, 8, FILE_FS_DEVICE_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS, "FILE_FS_DEVICE_INFORMATION");
    assert_eq!(mem.read_u32(info_ptr).unwrap(), 7, "DeviceType = FILE_DEVICE_DISK");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_INFORMATION_FILE,
        &[0xDEAD_BEEF, iosb_ptr, info_ptr, 0x18, FILE_STANDARD_INFORMATION],
    );
    assert_eq!(st, STATUS_INVALID_HANDLE, "bad handle → STATUS_INVALID_HANDLE");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nt_std_handles_bridge_to_host_stdio() {
    let dir = std::env::temp_dir().join(format!("exemu-w3_4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);

    let iosb_ptr = SCRATCH + 0x10;
    let info_ptr = SCRATCH + 0x40;
    let data_ptr = SCRATCH + 0x300;

    let pp = SCRATCH + 0x800;
    mem.write_u64(pp + 0x20, HANDLE_STDIN).unwrap();
    mem.write_u64(pp + 0x28, HANDLE_STDOUT).unwrap();
    mem.write_u64(pp + 0x30, HANDLE_STDERR).unwrap();
    let std_out = mem.read_u64(pp + 0x28).unwrap();
    let std_err = mem.read_u64(pp + 0x30).unwrap();
    let std_in = mem.read_u64(pp + 0x20).unwrap();
    assert_eq!(std_out, HANDLE_STDOUT, "GetStdHandle(STD_OUTPUT) == the seeded sentinel");

    let payload = b"hello\n";
    mem.write(data_ptr, payload).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_WRITE_FILE,
        &[std_out, 0, 0, 0, iosb_ptr, data_ptr, payload.len() as u64, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWriteFile(std_out) succeeds");
    assert_eq!(mem.read_u32(iosb_ptr).unwrap() as u64, STATUS_SUCCESS, "IOSB.Status");
    assert_eq!(mem.read_u64(iosb_ptr + 8).unwrap(), payload.len() as u64, "IOSB.Information = 6");
    assert_eq!(os.captured_stdout(), payload, "bytes landed on captured stdout");
    assert_eq!(os.captured_stderr(), b"", "nothing on stderr yet");

    let err_payload = b"oops\n";
    mem.write(data_ptr, err_payload).unwrap();
    let st = syscall(
        &mut os,
        &mut mem,
        NT_WRITE_FILE,
        &[std_err, 0, 0, 0, iosb_ptr, data_ptr, err_payload.len() as u64, 0, 0],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtWriteFile(std_err) succeeds");
    assert_eq!(os.captured_stderr(), err_payload, "bytes landed on captured stderr");
    assert_eq!(os.captured_stdout(), payload, "stdout unchanged by the stderr write");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_VOLUME_INFORMATION_FILE,
        &[std_out, iosb_ptr, info_ptr, 8, FILE_FS_DEVICE_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryVolumeInformationFile(device) on std handle");
    assert_eq!(mem.read_u32(info_ptr).unwrap(), 0x11, "DeviceType = FILE_DEVICE_NAMED_PIPE (non-console)");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_QUERY_INFORMATION_FILE,
        &[std_out, iosb_ptr, info_ptr, 0x18, FILE_STANDARD_INFORMATION],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtQueryInformationFile(standard) on std handle");
    assert_eq!(mem.read_u64(info_ptr + 8).unwrap(), 0, "EndOfFile = 0 (empty stream)");

    let st = syscall(
        &mut os,
        &mut mem,
        NT_READ_FILE,
        &[std_in, 0, 0, 0, iosb_ptr, data_ptr, 64, 0, 0],
    );
    assert_eq!(st, STATUS_END_OF_FILE, "NtReadFile(std_in) → STATUS_END_OF_FILE");

    let st = syscall(&mut os, &mut mem, NT_CLOSE, &[std_out]);
    assert_eq!(st, STATUS_SUCCESS, "NtClose(std_out) is a benign success");

    let _ = std::fs::remove_dir_all(&dir);
}
