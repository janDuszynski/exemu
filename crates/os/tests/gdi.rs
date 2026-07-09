//! Tests for the typed GDI device-context object model (roadmap P5b.1):
//! `SelectObject` returning the previously-selected object of the same kind,
//! `SaveDC`/`RestoreDC`, `CreateFontIndirect` + `GetObject`, and the background
//! color/mode setters. Driven through `Hooks::intercept`.

use exemu_core::{CpuState, Hooks, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const RSP: u64 = 0x0000_0010_0000_1000;
const RETADDR: u64 = 0x0000_0001_4000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const HDC: u64 = 0x00DC_0001;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", 0x0000_0010_0000_0000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
    (os, mem)
}

fn call(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, name: &str, args: &[u64]) -> u64 {
    let thunk = os.resolve_import("gdi32.dll", &ImportSymbol::Named(name.into()));
    cpu.set_rsp(RSP);
    mem.write_u64(RSP, RETADDR).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        cpu.set_reg(regs[i], a);
    }
    cpu.rip = thunk;
    os.intercept(thunk, cpu, mem).unwrap();
    assert_eq!(cpu.rip, RETADDR, "{name} must ret");
    cpu.reg(Reg::Rax)
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

#[test]
fn select_object_returns_previous_of_same_kind() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let b1 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x00FF_0000]);
    let b2 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x0000_FF00]);
    let p1 = call(&mut os, &mut mem, &mut cpu, "CreatePen", &[0, 1, 0x0000_00FF]);
    assert_ne!(b1, 0);
    assert_ne!(b1, b2);

    // Selecting a brush returns the previously-selected brush (0 initially).
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b1]), 0);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b2]), b1);
    // A pen is a distinct slot: selecting it returns the previous *pen* (0), not b2.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, p1]), 0);
    // Selecting another brush still tracks the brush slot (b2).
    let b3 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x0012_3456]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b3]), b2);
}

#[test]
fn save_restore_dc_reverts_selection() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    let b1 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x0011_1111]);
    let b2 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x0022_2222]);
    let b3 = call(&mut os, &mut mem, &mut cpu, "CreateSolidBrush", &[0x0033_3333]);

    call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b1]);
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SaveDC", &[HDC]), 1, "first SaveDC → level 1");
    // Change the selection inside the saved state.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b2]), b1);
    // Restore reverts the current brush back to b1.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "RestoreDC", &[HDC, (-1i64) as u64]), 1);
    assert_eq!(
        call(&mut os, &mut mem, &mut cpu, "SelectObject", &[HDC, b3]),
        b1,
        "RestoreDC reverted the selected brush to b1"
    );
}

#[test]
fn create_font_and_get_object_roundtrip() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    // Build a LOGFONTW: lfHeight @0, lfWeight @16, lfItalic @20, lfFaceName @28.
    let lf = SCRATCH;
    for i in 0..92u64 {
        mem.write_u8(lf + i, 0).unwrap();
    }
    mem.write_u32(lf, (-24i32) as u32).unwrap(); // height
    mem.write_u32(lf + 16, 700).unwrap(); // weight (bold)
    mem.write_u8(lf + 20, 1).unwrap(); // italic
    put_wstr(&mut mem, lf + 28, "Segoe UI");

    let hfont = call(&mut os, &mut mem, &mut cpu, "CreateFontIndirectW", &[lf]);
    assert_ne!(hfont, 0, "CreateFontIndirect returns a font handle");

    let out = SCRATCH + 0x200;
    let n = call(&mut os, &mut mem, &mut cpu, "GetObjectW", &[hfont, 92, out]);
    assert_eq!(n, 92, "GetObjectW(font) returns sizeof(LOGFONTW)");
    assert_eq!(mem.read_u32(out).unwrap() as i32, -24, "lfHeight");
    assert_eq!(mem.read_u32(out + 16).unwrap(), 700, "lfWeight");
    assert_eq!(mem.read_u8(out + 20).unwrap(), 1, "lfItalic");
    assert_eq!(read_wstr(&mem, out + 28), "Segoe UI", "lfFaceName");
}

#[test]
fn bk_color_and_mode_return_previous() {
    let (mut os, mut mem) = setup();
    let mut cpu = CpuState::default();
    // First set returns the default (0), second returns the prior value.
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetBkColor", &[HDC, 0x00AA_BBCC]), 0);
    // COLORREF 0x00CCBBAA (BGR) → packed 0x00AABBCC; the previous is returned as
    // the packed value we stored.
    let prev = call(&mut os, &mut mem, &mut cpu, "SetBkColor", &[HDC, 0]);
    assert_ne!(prev, 0, "second SetBkColor returns the previously set color");

    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetBkMode", &[HDC, 1]), 0); // TRANSPARENT
    assert_eq!(call(&mut os, &mut mem, &mut cpu, "SetBkMode", &[HDC, 2]), 1, "returns prior mode");
}
