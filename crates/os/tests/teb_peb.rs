use exemu_core::{Memory, Perm, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const TEB_BASE: u64 = 0x0000_7FFF_0000_0000;
const PEB_BASE: u64 = 0x0000_7FFF_0000_2000;
const IMAGE_BASE: u64 = 0x1_4000_0000;
const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x0020_0000;
const CMDLINE_PTR: u64 = 0x5000_0400;

fn read_wstr(mem: &dyn Memory, addr: u64) -> String {
    let mut units = Vec::new();
    let mut i = 0u64;
    loop {
        let u = mem.read_u16(addr + i * 2).unwrap();
        if u == 0 {
            break;
        }
        units.push(u);
        i += 1;
    }
    String::from_utf16(&units).unwrap()
}

fn setup() -> (VirtualMemory,) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("teb", TEB_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_BASE, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("dlls", 0x0000_0006_0000_0000, 0x0080_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("env", 0x5000_0000, 0x1000, Perm::RW)).unwrap();
    for (i, u) in "program.exe arg1".encode_utf16().enumerate() {
        mem.write_u16(CMDLINE_PTR + (i as u64) * 2, u).unwrap();
    }

    let cfg = WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        echo: false,
        is_64bit: true,
        image_base: IMAGE_BASE,
        image_size: 0x1000,
        image_entry: IMAGE_BASE + 0x1000,
        image_name: "program.exe".into(),
        module_path_w: "C:\\program.exe".into(),
        cmdline_ptr_w: CMDLINE_PTR,
        dll_base: 0x0000_0006_0000_0000,
        dll_size: 0x0080_0000,
        peb_addr: PEB_BASE,
        teb_base: TEB_BASE,
        peb_ldr_off: 0x18,
        peb_loaderlock_off: 0x110,
        ..WinConfig::default()
    };
    mem.write_u64(PEB_BASE + 0x10, IMAGE_BASE).unwrap();

    let mut os = WinOs::new(cfg);
    os.init_ldr(&mut mem).unwrap();
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_BASE + STACK_SIZE).unwrap();
    (mem,)
}

#[test]
fn peb_field_walk_populates_every_probed_offset() {
    let (mem,) = setup();

    assert_eq!(mem.read_u8(PEB_BASE + 0x02).unwrap(), 0);
    assert_eq!(mem.read_u64(PEB_BASE + 0x10).unwrap(), IMAGE_BASE);
    let ldr = mem.read_u64(PEB_BASE + 0x18).unwrap();
    assert_ne!(ldr, 0, "PEB.Ldr must be published");
    assert_ne!(mem.read_u32(ldr).unwrap(), 0);
    assert_eq!(mem.read_u32(ldr + 4).unwrap(), 1);
    let pp = mem.read_u64(PEB_BASE + 0x20).unwrap();
    assert_ne!(pp, 0, "PEB.ProcessParameters must be published");
    assert_eq!(mem.read_u32(PEB_BASE + 0xBC).unwrap(), 0);
    assert_eq!(mem.read_u32(PEB_BASE + 0x118).unwrap(), 10);
    assert_eq!(mem.read_u32(PEB_BASE + 0x11C).unwrap(), 0);
    assert_eq!(mem.read_u16(PEB_BASE + 0x120).unwrap(), 19045);
    assert_eq!(mem.read_u32(PEB_BASE + 0x124).unwrap(), 2);
    assert_eq!(mem.read_u32(PEB_BASE + 0x2C0).unwrap(), 0);

    let img_len = mem.read_u16(pp + 0x60).unwrap();
    let img_buf = mem.read_u64(pp + 0x60 + 8).unwrap();
    assert!(img_len > 0 && img_buf != 0);
    assert_eq!(read_wstr(&mem, img_buf), "C:\\program.exe");
    let cmd_len = mem.read_u16(pp + 0x70).unwrap();
    let cmd_buf = mem.read_u64(pp + 0x70 + 8).unwrap();
    assert!(cmd_len > 0 && cmd_buf != 0);
    assert_eq!(cmd_buf, CMDLINE_PTR);
    assert_eq!(read_wstr(&mem, cmd_buf), "program.exe arg1");
}

#[test]
fn process_parameters_is_full_and_wine_readable() {
    let (mem,) = setup();
    let peb = PEB_BASE;
    let pp = mem.read_u64(peb + 0x20).unwrap();
    assert_ne!(pp, 0, "PEB.ProcessParameters must be published");

    let max_len = mem.read_u32(pp).unwrap();
    let length = mem.read_u32(pp + 0x04).unwrap();
    assert!(max_len >= 0x410, "MaximumLength {max_len:#x} must span the full header");
    assert!(length >= 0x410, "Length {length:#x} must span the full header");

    assert_eq!(mem.read_u32(pp + 0x08).unwrap() & 0x1, 0x1, "Flags must be NORMALIZED");

    let read_us = |off: u64| -> (u16, u64) {
        (mem.read_u16(pp + off).unwrap(), mem.read_u64(pp + off + 8).unwrap())
    };
    let (cd_len, cd_buf) = read_us(0x38);
    assert!(cd_buf != 0 && cd_len > 0, "CurrentDirectory must have a buffer");
    assert_eq!(read_wstr(&mem, cd_buf), "C:\\");
    let (_, dll_buf) = read_us(0x50);
    assert!(dll_buf != 0, "DllPath must have a buffer");
    assert_eq!(read_wstr(&mem, dll_buf), "C:\\windows\\system32");
    let (img_len, img_buf) = read_us(0x60);
    assert!(img_buf != 0 && img_len > 0);
    assert_eq!(read_wstr(&mem, img_buf), "C:\\program.exe");
    let (cmd_len, cmd_buf) = read_us(0x70);
    assert!(cmd_buf != 0 && cmd_len > 0);
    assert_eq!(read_wstr(&mem, cmd_buf), "program.exe arg1");

    for off in [0xb0u64, 0xc0, 0xd0, 0xe0] {
        let (len, buf) = read_us(off);
        assert_eq!(len, 0, "field @{off:#x} is an empty string");
        assert_ne!(buf, 0, "field @{off:#x} still needs a valid (NUL) buffer");
        assert_eq!(mem.read_u16(buf).unwrap(), 0, "empty buffer is NUL-terminated");
    }

    let env = mem.read_u64(pp + 0x80).unwrap();
    assert_ne!(env, 0, "Environment must be non-null");
    let env_size = mem.read_u64(pp + 0x3f0).unwrap();
    assert!(env_size >= 4, "EnvironmentSize {env_size:#x} covers at least the terminator");
    assert_eq!(env_size % 2, 0, "UTF-16 environment size is even");
    let last = env + env_size - 2;
    assert_eq!(mem.read_u16(last).unwrap(), 0, "block ends in NUL");
    assert_eq!(mem.read_u16(last - 2).unwrap(), 0, "double-NUL terminated");
    let mut blob = Vec::new();
    let mut i = 0u64;
    while i < env_size - 2 {
        blob.push(mem.read_u16(env + i).unwrap());
        i += 2;
    }
    let text = String::from_utf16(&blob).unwrap();
    assert!(text.contains("SystemRoot=C:\\Windows"), "env carries real variables");

    assert_eq!(mem.read_u32(pp + 0x408).unwrap(), 0);
    assert_eq!(mem.read_u64(pp + 0x3e8).unwrap(), 0);
    assert_eq!(mem.read_u32(pp + 0x3f8).unwrap(), 0);
}

#[test]
fn teb_field_walk_populates_every_dereferenced_offset() {
    let (mem,) = setup();

    assert_eq!(mem.read_u64(TEB_BASE).unwrap(), u64::MAX);
    assert_eq!(mem.read_u64(TEB_BASE + 0x08).unwrap(), STACK_BASE + STACK_SIZE);
    assert_eq!(mem.read_u64(TEB_BASE + 0x10).unwrap(), STACK_BASE);
    assert_eq!(mem.read_u64(TEB_BASE + 0x30).unwrap(), TEB_BASE);
    assert_eq!(mem.read_u64(TEB_BASE + 0x40).unwrap(), 0x1000);
    assert_eq!(mem.read_u64(TEB_BASE + 0x48).unwrap(), 0x1001);
    assert_eq!(mem.read_u64(TEB_BASE + 0x58).unwrap(), 0);
    assert_eq!(mem.read_u64(TEB_BASE + 0x60).unwrap(), PEB_BASE);
    assert_eq!(mem.read_u16(TEB_BASE + 0x1258).unwrap(), 0);
    assert_eq!(mem.read_u16(TEB_BASE + 0x125A).unwrap(), 261 * 2);
    assert_eq!(mem.read_u64(TEB_BASE + 0x1258 + 8).unwrap(), TEB_BASE + 0x1268);
    assert_eq!(mem.read_u32(TEB_BASE + 0x6C8).unwrap(), 0);
    assert_eq!(mem.read_u64(TEB_BASE + 0x1478).unwrap(), STACK_BASE);
    assert_eq!(mem.read_u64(TEB_BASE + 0x1780).unwrap(), 0);
}
