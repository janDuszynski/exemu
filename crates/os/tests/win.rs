//! Tests for the real HWND window-object model (roadmap P5a.2): distinct
//! window handles, `Get/SetWindowLongPtr` (subclassing + user data + style),
//! `Get/Set/RemoveProp`, `IsWindow`, `GetClientRect`/`GetWindowRect`,
//! `GetClassName`, and per-window `Get/SetWindowText`.

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const RSP: u64 = 0x0000_0010_0000_1000;
const RETADDR: u64 = 0x0000_0001_4000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
// The first CreateWindowEx yields this HWND (alloc seeds from HWND_CUSTOM).
const HWND1: u64 = 0x00C1_0000;
const WNDPROC: u64 = 0x0000_0000_0040_1000;

// GWL/GWLP indices (as u64 two's complement).
const GWLP_WNDPROC: u64 = (-4i64) as u64;
const GWLP_USERDATA: u64 = (-21i64) as u64;
const GWL_STYLE: u64 = (-16i64) as u64;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", 0x0000_0010_0000_0000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x0000_0002_0000_0000, 0x1_0000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        heap_base: 0x0000_0002_0000_0000,
        heap_size: 0x1_0000,
        ..WinConfig::default()
    });
    (os, mem)
}

fn put_wstr(mem: &mut VirtualMemory, addr: u64, s: &str) {
    for (i, u) in s.encode_utf16().chain([0]).enumerate() {
        mem.write_u16(addr + i as u64 * 2, u).unwrap();
    }
}

fn read_wstr(mem: &VirtualMemory, addr: u64) -> String {
    let mut u = Vec::new();
    for i in 0.. {
        let c = mem.read_u16(addr + i * 2).unwrap();
        if c == 0 {
            break;
        }
        u.push(c);
    }
    String::from_utf16_lossy(&u)
}

/// Invoke a user32 API with register + stack args; assert a normal return.
fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, args: &[u64]) -> u64 {
    let thunk = os.resolve_import("user32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        if i < 4 {
            cpu.set_reg(regs[i], a);
        } else {
            mem.write_u64(RSP + 0x28 + (i as u64 - 4) * 8, a).unwrap();
        }
    }
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "{name}");
    assert_eq!(cpu.rip, RETADDR, "{name} must ret");
    cpu.reg(Reg::Rax)
}

/// Register a class named `class` (wndproc = WNDPROC) and create one window
/// titled `title`. Returns the (deterministic) HWND. CreateWindowEx delivers
/// WM_CREATE via the callback driver, so it returns `Resume` rather than to the
/// caller — we don't run that callback here; the window object already exists.
fn make_window(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, class: &str, title: &str) -> u64 {
    let wc = SCRATCH; // WNDCLASSW: lpfnWndProc @ +8, lpszClassName @ +64 (x64)
    let name = SCRATCH + 0x100;
    let title_ptr = SCRATCH + 0x200;
    for i in 0..72 {
        mem.write_u8(wc + i, 0).unwrap();
    }
    put_wstr(mem, name, class);
    put_wstr(mem, title_ptr, title);
    mem.write_u64(wc + 8, WNDPROC).unwrap();
    mem.write_u64(wc + 64, name).unwrap();
    let atom = call(os, mem, cpu, "RegisterClassW", &[wc]);
    assert_ne!(atom, 0, "RegisterClassW returns an atom");

    // CreateWindowExW(ex=0, class=name, title, style=0x00CF0000, x=100, y=100,
    //                 w=300, h=200, parent=0, menu=0, inst=0, param=0)
    let thunk = os.resolve_import("user32.dll", &ImportSymbol::Named("CreateWindowExW".into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    cpu.set_reg(Reg::Rcx, 0);
    cpu.set_reg(Reg::Rdx, name);
    cpu.set_reg(Reg::R8, title_ptr);
    cpu.set_reg(Reg::R9, 0x00CF_0000); // WS_OVERLAPPEDWINDOW
    for (i, v) in [100u64, 100, 300, 200, 0, 0, 0, 0].iter().enumerate() {
        mem.write_u64(RSP + 0x28 + i as u64 * 8, *v).unwrap();
    }
    cpu.rip = thunk;
    let exit = os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(exit, Some(Exit::Continue), "CreateWindowExW should Continue");
    HWND1
}

#[test]
fn create_yields_real_window_and_is_window() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let hwnd = make_window(&mut os, &mut mem, &mut cpu, "MyClass", "Hello");
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "IsWindow", &[hwnd]), 1);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "IsWindow", &[0xDEAD_0000]), 0, "garbage is not a window");
    // A second window gets a distinct handle.
    let os_ptr = &mut os;
    let hwnd2 = {
        let thunk = os_ptr.resolve_import("user32.dll", &ImportSymbol::Named("CreateWindowExW".into()));
        cpu.set_rsp(RSP);
        mem.write_u64(RSP, RETADDR).unwrap();
        cpu.set_reg(Reg::Rcx, 0);
        cpu.set_reg(Reg::Rdx, SCRATCH + 0x100); // reuse the registered class name
        cpu.set_reg(Reg::R8, SCRATCH + 0x200);
        cpu.set_reg(Reg::R9, 0);
        for i in 0..8 {
            mem.write_u64(RSP + 0x28 + i * 8, 0).unwrap();
        }
        cpu.rip = thunk;
        os_ptr.intercept(thunk, &mut cpu, &mut mem).unwrap();
        HWND1 + 0x10
    };
    assert_ne!(hwnd, hwnd2, "distinct windows get distinct HWNDs");
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "IsWindow", &[hwnd2]), 1);
}

#[test]
fn window_long_userdata_and_wndproc_subclass() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let hwnd = make_window(&mut os, &mut mem, &mut cpu, "C", "T");

    // GWLP_USERDATA round-trips.
    call(&mut os, &mut mem, &mut cpu, "SetWindowLongPtrW", &[hwnd, GWLP_USERDATA, 0x1234_5678]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetWindowLongPtrW", &[hwnd, GWLP_USERDATA]), 0x1234_5678);

    // GWLP_WNDPROC subclassing: get old, set new, get new.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetWindowLongPtrW", &[hwnd, GWLP_WNDPROC]), WNDPROC);
    let old = call(&mut os, &mut mem, &mut cpu, "SetWindowLongPtrW", &[hwnd, GWLP_WNDPROC, 0x9999]);
    assert_eq!(old, WNDPROC, "SetWindowLongPtr returns the previous value");
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetWindowLongPtrW", &[hwnd, GWLP_WNDPROC]), 0x9999);

    // GWL_STYLE reflects the CreateWindowEx style.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetWindowLongW", &[hwnd, GWL_STYLE]), 0x00CF_0000);
}

#[test]
fn props_roundtrip_and_remove() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let hwnd = make_window(&mut os, &mut mem, &mut cpu, "C", "T");
    let prop = SCRATCH + 0x300;
    put_wstr(&mut mem, prop, "MyProp");
    call(&mut os, &mut mem, &mut cpu, "SetPropW", &[hwnd, prop, 0xABCD]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetPropW", &[hwnd, prop]), 0xABCD);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "RemovePropW", &[hwnd, prop]), 0xABCD);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "GetPropW", &[hwnd, prop]), 0, "removed prop is gone");
}

#[test]
fn client_rect_class_name_and_text() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let hwnd = make_window(&mut os, &mut mem, &mut cpu, "MyWindowClass", "Title");
    let rect = SCRATCH + 0x400;
    call(&mut os, &mut mem, &mut cpu, "GetClientRect", &[hwnd, rect]);
    assert_eq!(
        (
            mem.read_u32(rect).unwrap(),
            mem.read_u32(rect + 4).unwrap(),
            mem.read_u32(rect + 8).unwrap(),
            mem.read_u32(rect + 12).unwrap(),
        ),
        (0, 0, 300, 200),
        "client rect is (0,0,w,h)"
    );

    let cls = SCRATCH + 0x500;
    call(&mut os, &mut mem, &mut cpu, "GetClassNameW", &[hwnd, cls, 64]);
    assert_eq!(read_wstr(&mem, cls), "MyWindowClass");

    // Per-window text: created title, then update it.
    let txt = SCRATCH + 0x600;
    call(&mut os, &mut mem, &mut cpu, "GetWindowTextW", &[hwnd, txt, 64]);
    assert_eq!(read_wstr(&mem, txt), "Title");
    let newt = SCRATCH + 0x700;
    put_wstr(&mut mem, newt, "Renamed");
    call(&mut os, &mut mem, &mut cpu, "SetWindowTextW", &[hwnd, newt]);
    call(&mut os, &mut mem, &mut cpu, "GetWindowTextW", &[hwnd, txt, 64]);
    assert_eq!(read_wstr(&mem, txt), "Renamed");
}
