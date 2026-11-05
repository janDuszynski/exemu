use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_app::prefix_dirs::{stage_prefix_dirs, PREFIX_DIRS};
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;

const NT_CREATE_FILE: u32 = 0x55;


const STATUS_SUCCESS: u64 = 0;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xC000_003A;

const FILE_CREATE: u64 = 2;

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


struct Fixture {
    root: std::path::PathBuf,
    os: WinOs,
    mem: VirtualMemory,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("exemu-prefix-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("C")).unwrap();
        stage_prefix_dirs(&root);
        let (os, mem) = setup(&root);
        Fixture { root, os, mem }
    }

    fn create(&mut self, nt_path: &str) -> u64 {
        let oa_ptr = SCRATCH + 0x100;
        write_object_attributes(&mut self.mem, oa_ptr, nt_path);
        syscall(
            &mut self.os,
            &mut self.mem,
            NT_CREATE_FILE,
            &[SCRATCH, GENERIC_WRITE, oa_ptr, SCRATCH + 0x10, 0, 0x80, 0, FILE_CREATE, 0x60, 0, 0],
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn fresh_sandbox_has_the_prefix_directories() {
    let f = Fixture::new("dirs");
    for rel in PREFIX_DIRS {
        assert!(f.root.join("C").join(rel).is_dir(), "{rel}");
    }
}

#[test]
fn create_under_temp_succeeds_and_under_a_missing_directory_does_not() {
    let mut f = Fixture::new("create");
    assert_eq!(f.create("\\??\\C:\\Temp\\new.txt"), STATUS_SUCCESS);
    assert!(f.root.join("C/Temp/new.txt").is_file());
    assert_eq!(f.create("\\??\\C:\\Users\\exemu\\AppData\\Local\\Temp\\new.txt"), STATUS_SUCCESS);
    assert_eq!(f.create("\\??\\C:\\nope\\x.txt"), STATUS_OBJECT_PATH_NOT_FOUND);
    assert!(!f.root.join("C/nope").exists());
}
