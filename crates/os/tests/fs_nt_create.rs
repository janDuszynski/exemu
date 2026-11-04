use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;

const NT_CREATE_FILE: u32 = 0x55;


const STATUS_SUCCESS: u64 = 0;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xC000_003A;
const STATUS_NOT_A_DIRECTORY: u64 = 0xC000_0103;
const STATUS_FILE_IS_A_DIRECTORY: u64 = 0xC000_00BA;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const FILE_DIRECTORY_FILE: u64 = 0x1;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;

const FILE_SUPERSEDE: u64 = 0;
const FILE_OPEN: u64 = 1;
const FILE_OPEN_IF: u64 = 3;
const FILE_OVERWRITE: u64 = 4;
const FILE_OVERWRITE_IF: u64 = 5;
const FILE_CREATE: u64 = 2;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;
const FILE_SUPERSEDED: u64 = 0;
const FILE_OVERWRITTEN: u64 = 3;

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

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("exemu-create-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("C").join("Temp")).unwrap();
        let (os, mem) = setup(&root);
        Fixture { root, os, mem }
    }

    fn host(&self, rel: &str) -> std::path::PathBuf {
        self.root.join("C").join(rel)
    }

    fn create(&mut self, nt_path: &str, access: u64, disposition: u64, options: u64) -> u64 {
        let oa_ptr = SCRATCH + 0x100;
        write_object_attributes(&mut self.mem, oa_ptr, nt_path);
        syscall(
            &mut self.os,
            &mut self.mem,
            NT_CREATE_FILE,
            &[SCRATCH, access, oa_ptr, SCRATCH + 0x10, 0, 0x80, 0, disposition, options, 0, 0],
        )
    }

    fn information(&self) -> u64 {
        self.mem.read_u64(SCRATCH + 0x18).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const FILE_OPTS: u64 = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
const DIR_OPTS: u64 = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
const DIR_ACCESS: u64 = GENERIC_READ | SYNCHRONIZE;

#[test]
fn file_create_in_existing_directory_creates_the_file() {
    let mut f = Fixture::new("create-new");
    let st = f.create("\\??\\C:\\Temp\\a.txt", GENERIC_WRITE, FILE_CREATE, FILE_OPTS);
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_CREATED);
    assert!(f.host("Temp/a.txt").is_file());
}

#[test]
fn file_create_on_existing_file_collides() {
    let mut f = Fixture::new("collide");
    std::fs::write(f.host("Temp/a.txt"), b"keep").unwrap();
    let st = f.create("\\??\\C:\\Temp\\a.txt", GENERIC_WRITE, FILE_CREATE, FILE_OPTS);
    assert_eq!(st, STATUS_OBJECT_NAME_COLLISION);
    assert_eq!(std::fs::read(f.host("Temp/a.txt")).unwrap(), b"keep");
}

#[test]
fn missing_parent_is_path_not_found_and_creates_nothing() {
    let mut f = Fixture::new("noparent");
    for disposition in [FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE, FILE_OPEN] {
        let st = f.create("\\??\\C:\\Missing\\a.txt", GENERIC_WRITE, disposition, FILE_OPTS);
        assert_eq!(st, STATUS_OBJECT_PATH_NOT_FOUND, "disposition {disposition}");
    }
    assert!(!f.host("Missing").exists());
}

#[test]
fn file_open_and_overwrite_require_existence() {
    let mut f = Fixture::new("open");
    assert_eq!(
        f.create("\\??\\C:\\Temp\\n.txt", GENERIC_WRITE, FILE_OPEN, FILE_OPTS),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        f.create("\\??\\C:\\Temp\\n.txt", GENERIC_WRITE, FILE_OVERWRITE, FILE_OPTS),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(!f.host("Temp/n.txt").exists());
    std::fs::write(f.host("Temp/n.txt"), b"x").unwrap();
    assert_eq!(f.create("\\??\\C:\\Temp\\n.txt", GENERIC_WRITE, FILE_OPEN, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_OPENED);
}

#[test]
fn open_if_overwrite_if_and_supersede_report_what_happened() {
    let mut f = Fixture::new("ifs");
    let path = "\\??\\C:\\Temp\\b.txt";
    assert_eq!(f.create(path, GENERIC_WRITE, FILE_OPEN_IF, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_CREATED);
    std::fs::write(f.host("Temp/b.txt"), b"data").unwrap();
    assert_eq!(f.create(path, GENERIC_WRITE, FILE_OPEN_IF, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_OPENED);
    assert_eq!(std::fs::read(f.host("Temp/b.txt")).unwrap(), b"data");
    assert_eq!(f.create(path, GENERIC_WRITE, FILE_OVERWRITE_IF, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_OVERWRITTEN);
    assert!(std::fs::read(f.host("Temp/b.txt")).unwrap().is_empty());
    std::fs::write(f.host("Temp/b.txt"), b"data").unwrap();
    assert_eq!(f.create(path, GENERIC_WRITE, FILE_SUPERSEDE, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_SUPERSEDED);
    assert_eq!(f.create("\\??\\C:\\Temp\\c.txt", GENERIC_WRITE, FILE_SUPERSEDE, FILE_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_CREATED);
}

#[test]
fn directory_create_makes_a_directory_not_a_file() {
    let mut f = Fixture::new("mkdir");
    let st = f.create("\\??\\C:\\Temp\\13385", DIR_ACCESS, FILE_CREATE, DIR_OPTS);
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_CREATED);
    assert!(f.host("Temp/13385").is_dir());
    assert_eq!(f.create("\\??\\C:\\Temp\\13385", DIR_ACCESS, FILE_CREATE, DIR_OPTS), STATUS_OBJECT_NAME_COLLISION);
    let st = f.create("\\??\\C:\\Temp\\13385\\*.txt", GENERIC_WRITE, FILE_CREATE, FILE_OPTS);
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_CREATED);
}

#[test]
fn directory_open_and_kind_mismatches() {
    let mut f = Fixture::new("kinds");
    std::fs::create_dir(f.host("Temp/d")).unwrap();
    std::fs::write(f.host("Temp/f.txt"), b"x").unwrap();
    assert_eq!(f.create("\\??\\C:\\Temp\\d", DIR_ACCESS, FILE_OPEN_IF, DIR_OPTS), STATUS_SUCCESS);
    assert_eq!(f.information(), FILE_OPENED);
    assert_eq!(f.create("\\??\\C:\\Temp\\f.txt", DIR_ACCESS, FILE_OPEN, DIR_OPTS), STATUS_NOT_A_DIRECTORY);
    assert_eq!(f.create("\\??\\C:\\Temp\\d", GENERIC_WRITE, FILE_OPEN, FILE_OPTS), STATUS_FILE_IS_A_DIRECTORY);
    assert_eq!(f.create("\\??\\C:\\Temp\\d", DIR_ACCESS, FILE_SUPERSEDE, DIR_OPTS), STATUS_INVALID_PARAMETER);
    assert_eq!(
        f.create("\\??\\C:\\Temp\\d", DIR_ACCESS, FILE_OPEN, DIR_OPTS | FILE_NON_DIRECTORY_FILE),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(f.create("\\??\\C:\\Temp\\d", DIR_ACCESS, 9, 0), STATUS_INVALID_PARAMETER);
}
