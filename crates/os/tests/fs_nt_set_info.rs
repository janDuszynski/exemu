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
const NT_CLOSE: u32 = 0x0f;
const NT_SET_INFORMATION_FILE: u32 = 0x27;

const STATUS_SUCCESS: u64 = 0;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xC000_003A;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const FILE_DIRECTORY_FILE: u64 = 0x1;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;

const FILE_OPEN: u64 = 1;
const FILE_CREATE: u64 = 2;

const GENERIC_WRITE: u64 = 0x4000_0000;
const GENERIC_READ: u64 = 0x8000_0000;
const SYNCHRONIZE: u64 = 0x10_0000;

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


struct Fixture {
    root: std::path::PathBuf,
    os: WinOs,
    mem: VirtualMemory,
}

const INFO: u64 = SCRATCH + 0x400;
const FILE_RENAME_INFORMATION: u64 = 10;
const FILE_DISPOSITION_INFORMATION: u64 = 13;
const FILE_POSITION_INFORMATION: u64 = 14;
const FILE_END_OF_FILE_INFORMATION: u64 = 20;
const FILE_DISPOSITION_INFORMATION_EX: u64 = 64;
const FILE_RENAME_INFORMATION_EX: u64 = 65;
const FILE_BASIC_INFORMATION: u64 = 4;
const STATUS_DIRECTORY_NOT_EMPTY: u64 = 0xC000_0101;
const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
const DELETE: u64 = 0x1_0000;
const FILE_OPTS: u64 = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
const DIR_OPTS: u64 = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("exemu-setinfo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("C").join("Temp")).unwrap();
        let (os, mem) = setup(&root);
        Fixture { root, os, mem }
    }

    fn host(&self, rel: &str) -> std::path::PathBuf {
        self.root.join("C").join(rel)
    }

    fn open(&mut self, nt_path: &str, access: u64, disposition: u64, options: u64) -> u64 {
        let oa_ptr = SCRATCH + 0x100;
        write_object_attributes(&mut self.mem, oa_ptr, nt_path);
        let st = syscall(
            &mut self.os,
            &mut self.mem,
            NT_CREATE_FILE,
            &[SCRATCH, access, oa_ptr, SCRATCH + 0x10, 0, 0x80, 0, disposition, options, 0, 0],
        );
        assert_eq!(st, STATUS_SUCCESS, "open {nt_path}");
        self.mem.read_u64(SCRATCH).unwrap()
    }

    fn set(&mut self, handle: u64, class: u64, bytes: &[u8]) -> u64 {
        self.mem.write(INFO, bytes).unwrap();
        syscall(
            &mut self.os,
            &mut self.mem,
            NT_SET_INFORMATION_FILE,
            &[handle, SCRATCH + 0x20, INFO, bytes.len() as u64, class],
        )
    }

    fn read(&mut self, handle: u64, len: u64) -> Vec<u8> {
        let buf = SCRATCH + 0x800;
        let st = syscall(
            &mut self.os,
            &mut self.mem,
            NT_READ_FILE,
            &[handle, 0, 0, 0, SCRATCH + 0x30, buf, len, 0, 0],
        );
        assert_eq!(st, STATUS_SUCCESS);
        let n = self.mem.read_u64(SCRATCH + 0x38).unwrap() as usize;
        let mut out = vec![0u8; n];
        self.mem.read(buf, &mut out).unwrap();
        out
    }

    fn close(&mut self, handle: u64) {
        assert_eq!(syscall(&mut self.os, &mut self.mem, NT_CLOSE, &[handle]), STATUS_SUCCESS);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn rename_info(flags: u32, nt_path: &str, wide_flags: bool) -> Vec<u8> {
    let units: Vec<u16> = nt_path.encode_utf16().collect();
    let mut v = vec![0u8; 0x14 + units.len() * 2];
    if wide_flags {
        v[..4].copy_from_slice(&flags.to_le_bytes());
    } else {
        v[0] = flags as u8;
    }
    v[0x10..0x14].copy_from_slice(&((units.len() * 2) as u32).to_le_bytes());
    for (i, u) in units.iter().enumerate() {
        v[0x14 + i * 2..0x16 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    v
}

#[test]
fn position_information_moves_the_read_cursor() {
    let mut f = Fixture::new("pos");
    std::fs::write(f.host("Temp/p.bin"), b"0123456789").unwrap();
    let h = f.open("\\??\\C:\\Temp\\p.bin", GENERIC_READ | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    assert_eq!(f.read(h, 2), b"01");
    assert_eq!(f.set(h, FILE_POSITION_INFORMATION, &6u64.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(f.read(h, 4), b"6789");
    assert_eq!(f.set(h, FILE_POSITION_INFORMATION, &[0xff; 8]), STATUS_INVALID_PARAMETER);
    assert_eq!(f.set(h, FILE_POSITION_INFORMATION, &[0; 4]), 0xC000_0023);
}

#[test]
fn end_of_file_information_truncates_and_extends() {
    let mut f = Fixture::new("eof");
    let h = f.open("\\??\\C:\\Temp\\e.bin", GENERIC_WRITE | SYNCHRONIZE, FILE_CREATE, FILE_OPTS);
    assert_eq!(f.set(h, FILE_END_OF_FILE_INFORMATION, &4096u64.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(std::fs::metadata(f.host("Temp/e.bin")).unwrap().len(), 4096);
    assert_eq!(f.set(h, FILE_END_OF_FILE_INFORMATION, &3u64.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(std::fs::metadata(f.host("Temp/e.bin")).unwrap().len(), 3);
}

#[test]
fn disposition_deletes_on_the_last_close_not_before() {
    let mut f = Fixture::new("del");
    std::fs::write(f.host("Temp/d.tmp"), b"x").unwrap();
    let h = f.open("\\??\\C:\\Temp\\d.tmp", DELETE | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION, &[1]), STATUS_SUCCESS);
    assert!(f.host("Temp/d.tmp").exists(), "still present until the handle closes");
    f.close(h);
    assert!(!f.host("Temp/d.tmp").exists());

    std::fs::write(f.host("Temp/k.tmp"), b"x").unwrap();
    let h = f.open("\\??\\C:\\Temp\\k.tmp", DELETE | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION, &[1]), STATUS_SUCCESS);
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION, &[0]), STATUS_SUCCESS);
    f.close(h);
    assert!(f.host("Temp/k.tmp").exists(), "a cancelled disposition keeps the file");

    std::fs::write(f.host("Temp/x.tmp"), b"x").unwrap();
    let h = f.open("\\??\\C:\\Temp\\x.tmp", DELETE | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION_EX, &1u32.to_le_bytes()), STATUS_SUCCESS);
    f.close(h);
    assert!(!f.host("Temp/x.tmp").exists());
}

#[test]
fn disposition_of_a_non_empty_directory_is_refused() {
    let mut f = Fixture::new("dirdel");
    std::fs::create_dir_all(f.host("Temp/sub")).unwrap();
    std::fs::write(f.host("Temp/sub/in.txt"), b"x").unwrap();
    let h = f.open("\\??\\C:\\Temp\\sub", DELETE | SYNCHRONIZE, FILE_OPEN, DIR_OPTS);
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION, &[1]), STATUS_DIRECTORY_NOT_EMPTY);
    std::fs::remove_file(f.host("Temp/sub/in.txt")).unwrap();
    assert_eq!(f.set(h, FILE_DISPOSITION_INFORMATION, &[1]), STATUS_SUCCESS);
    f.close(h);
    assert!(!f.host("Temp/sub").exists());
}

#[test]
fn delete_on_close_option_removes_the_file_on_close() {
    let mut f = Fixture::new("doc");
    let h = f.open(
        "\\??\\C:\\Temp\\doc.tmp",
        GENERIC_WRITE | DELETE | SYNCHRONIZE,
        FILE_CREATE,
        FILE_OPTS | 0x1000,
    );
    assert!(f.host("Temp/doc.tmp").exists());
    f.close(h);
    assert!(!f.host("Temp/doc.tmp").exists());
}

#[test]
fn rename_moves_the_file_and_honours_replace() {
    let mut f = Fixture::new("ren");
    std::fs::write(f.host("Temp/a.txt"), b"AAA").unwrap();
    std::fs::write(f.host("Temp/b.txt"), b"BBB").unwrap();
    let h = f.open("\\??\\C:\\Temp\\a.txt", DELETE | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    let to_b = rename_info(0, "\\??\\C:\\Temp\\b.txt", false);
    assert_eq!(f.set(h, FILE_RENAME_INFORMATION, &to_b), STATUS_OBJECT_NAME_COLLISION);
    assert!(f.host("Temp/a.txt").exists());
    let replace = rename_info(1, "\\??\\C:\\Temp\\b.txt", false);
    assert_eq!(f.set(h, FILE_RENAME_INFORMATION, &replace), STATUS_SUCCESS);
    assert!(!f.host("Temp/a.txt").exists());
    assert_eq!(std::fs::read(f.host("Temp/b.txt")).unwrap(), b"AAA");
    let again = rename_info(0, "\\??\\C:\\Temp\\c.txt", true);
    assert_eq!(f.set(h, FILE_RENAME_INFORMATION_EX, &again), STATUS_SUCCESS);
    assert_eq!(std::fs::read(f.host("Temp/c.txt")).unwrap(), b"AAA");
    let nowhere = rename_info(0, "\\??\\C:\\Missing\\c.txt", false);
    assert_eq!(f.set(h, FILE_RENAME_INFORMATION, &nowhere), STATUS_OBJECT_PATH_NOT_FOUND);
}

#[test]
fn basic_information_sets_the_write_time_and_unknown_classes_are_not_implemented() {
    let mut f = Fixture::new("basic");
    std::fs::write(f.host("Temp/t.txt"), b"x").unwrap();
    let h = f.open("\\??\\C:\\Temp\\t.txt", GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN, FILE_OPTS);
    let when_unix: u64 = 1_000_000_000;
    let ft = (when_unix * 10_000_000) + 116_444_736_000_000_000;
    let mut basic = vec![0u8; 40];
    basic[16..24].copy_from_slice(&ft.to_le_bytes());
    assert_eq!(f.set(h, FILE_BASIC_INFORMATION, &basic), STATUS_SUCCESS);
    let got = std::fs::metadata(f.host("Temp/t.txt")).unwrap().modified().unwrap();
    let secs = got.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(secs, when_unix);
    assert_eq!(f.set(h, 0x7f, &[0; 8]), STATUS_NOT_IMPLEMENTED);
}
