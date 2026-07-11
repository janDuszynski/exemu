//! Field-walk of the completed 64-bit TEB (~0x1838) + PEB (~0x7C8) (roadmap
//! W2.10). The de-risk: every field the loader populates is read back at its
//! documented offset — a missing/mis-offset write would surface in real Wine as
//! a null-deref deep in ntdll, so here it surfaces as a failed assertion.
//!
//! Drives the public `WinOs` surface exactly as the app does: map the TEB/PEB
//! regions + the DLL/heap arenas, then `init_ldr` (which publishes `PEB.Ldr` and
//! seeds the rest of the PEB) + `seed_main_teb` (which completes the TEB), then
//! walk guest memory.

use exemu_core::{Memory, Perm, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const TEB_BASE: u64 = 0x0000_7FFF_0000_0000;
const PEB_BASE: u64 = 0x0000_7FFF_0000_2000;
const IMAGE_BASE: u64 = 0x1_4000_0000;
const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x0020_0000;
const CMDLINE_PTR: u64 = 0x5000_0400;

/// Read a NUL-terminated UTF-16 string starting at `addr` back into a `String`.
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
    // The TEB region spans the whole ~0x1838 struct (0x2000); PEB is one page.
    mem.map(Region::new("teb", TEB_BASE, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_BASE, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("dlls", 0x0000_0006_0000_0000, 0x0080_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    // The app-mapped UTF-16 command line the PEB.ProcessParameters points at.
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
    // The app seeds PEB.ImageBaseAddress @0x10 before the OS exists.
    mem.write_u64(PEB_BASE + 0x10, IMAGE_BASE).unwrap();

    let mut os = WinOs::new(cfg);
    os.init_ldr(&mut mem).unwrap(); // publishes PEB.Ldr + seeds the rest of the PEB
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_BASE + STACK_SIZE).unwrap();
    (mem,)
}

#[test]
fn peb_field_walk_populates_every_probed_offset() {
    let (mem,) = setup();

    // BeingDebugged @0x02 = 0 (not debugged).
    assert_eq!(mem.read_u8(PEB_BASE + 0x02).unwrap(), 0);
    // ImageBaseAddress @0x10 (seeded by the app, preserved).
    assert_eq!(mem.read_u64(PEB_BASE + 0x10).unwrap(), IMAGE_BASE);
    // Ldr @0x18 is a valid, non-null PEB_LDR_DATA pointer.
    let ldr = mem.read_u64(PEB_BASE + 0x18).unwrap();
    assert_ne!(ldr, 0, "PEB.Ldr must be published");
    // PEB_LDR_DATA.Length @0 is nonzero (materialized), Initialized @4 = 1.
    assert_ne!(mem.read_u32(ldr).unwrap(), 0);
    assert_eq!(mem.read_u32(ldr + 4).unwrap(), 1);
    // ProcessParameters @0x20 → valid RTL_USER_PROCESS_PARAMETERS.
    let pp = mem.read_u64(PEB_BASE + 0x20).unwrap();
    assert_ne!(pp, 0, "PEB.ProcessParameters must be published");
    // NtGlobalFlag @0xBC = 0 (confirmed offset from the pinned ntdll).
    assert_eq!(mem.read_u32(PEB_BASE + 0xBC).unwrap(), 0);
    // OS version block: 10.0.19045, VER_PLATFORM_WIN32_NT.
    assert_eq!(mem.read_u32(PEB_BASE + 0x118).unwrap(), 10); // OSMajorVersion
    assert_eq!(mem.read_u32(PEB_BASE + 0x11C).unwrap(), 0); // OSMinorVersion
    assert_eq!(mem.read_u16(PEB_BASE + 0x120).unwrap(), 19045); // OSBuildNumber (u16)
    assert_eq!(mem.read_u32(PEB_BASE + 0x124).unwrap(), 2); // OSPlatformId
    // SessionId @0x2C0 = 0.
    assert_eq!(mem.read_u32(PEB_BASE + 0x2C0).unwrap(), 0);

    // Walk into ProcessParameters: ImagePathName @0x60, CommandLine @0x70
    // (public winternl.h layout; UNICODE_STRING {Length u16, MaxLen u16, +pad,
    // Buffer ptr}).
    let img_len = mem.read_u16(pp + 0x60).unwrap();
    let img_buf = mem.read_u64(pp + 0x60 + 8).unwrap();
    assert!(img_len > 0 && img_buf != 0);
    assert_eq!(read_wstr(&mem, img_buf), "C:\\program.exe");
    let cmd_len = mem.read_u16(pp + 0x70).unwrap();
    let cmd_buf = mem.read_u64(pp + 0x70 + 8).unwrap();
    assert!(cmd_len > 0 && cmd_buf != 0);
    assert_eq!(cmd_buf, CMDLINE_PTR); // points at the app's UTF-16 command line
    assert_eq!(read_wstr(&mem, cmd_buf), "program.exe arg1");
}

#[test]
fn teb_field_walk_populates_every_dereferenced_offset() {
    let (mem,) = setup();

    // NtTib.ExceptionList @0x00 = -1 sentinel (no SEH frame yet).
    assert_eq!(mem.read_u64(TEB_BASE).unwrap(), u64::MAX);
    // NtTib.StackBase @0x08 / StackLimit @0x10.
    assert_eq!(mem.read_u64(TEB_BASE + 0x08).unwrap(), STACK_BASE + STACK_SIZE);
    assert_eq!(mem.read_u64(TEB_BASE + 0x10).unwrap(), STACK_BASE);
    // NtTib.Self @0x30 → the TEB itself.
    assert_eq!(mem.read_u64(TEB_BASE + 0x30).unwrap(), TEB_BASE);
    // ClientId.UniqueProcess @0x40 / UniqueThread @0x48 (main tid 0x1001).
    assert_eq!(mem.read_u64(TEB_BASE + 0x40).unwrap(), 0x1000);
    assert_eq!(mem.read_u64(TEB_BASE + 0x48).unwrap(), 0x1001);
    // ThreadLocalStoragePointer @0x58 = 0 (lazily set by the CRT/ntdll).
    assert_eq!(mem.read_u64(TEB_BASE + 0x58).unwrap(), 0);
    // ProcessEnvironmentBlock @0x60 → the PEB.
    assert_eq!(mem.read_u64(TEB_BASE + 0x60).unwrap(), PEB_BASE);
    // StaticUnicodeString @0xB8: Length 0, MaxLength 522, Buffer → inline buffer.
    assert_eq!(mem.read_u16(TEB_BASE + 0xB8).unwrap(), 0); // Length
    assert_eq!(mem.read_u16(TEB_BASE + 0xBA).unwrap(), 261 * 2); // MaximumLength
    assert_eq!(mem.read_u64(TEB_BASE + 0xB8 + 8).unwrap(), TEB_BASE + 0xC8);
    // CountOfOwnedCriticalSections @0x6C8 = 0.
    assert_eq!(mem.read_u32(TEB_BASE + 0x6C8).unwrap(), 0);
    // DeallocationStack @0x1478 = the stack base (used on teardown).
    assert_eq!(mem.read_u64(TEB_BASE + 0x1478).unwrap(), STACK_BASE);
    // TlsExpansionSlots @0x1780 = 0 (array not grown yet).
    assert_eq!(mem.read_u64(TEB_BASE + 0x1780).unwrap(), 0);
}
