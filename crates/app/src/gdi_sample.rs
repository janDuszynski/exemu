use crate::gui_sample::{pe_image, wide, Arg, Asm, Rdata, RBX, RCX};

const CLASS_NAME: &str = "ExemuGdiClass";
const WINDOW_TITLE: &str = "exemu gdi readback";

const SRCCOPY: u32 = 0x00CC_0020;
const PATCOPY: u32 = 0x00F0_0021;
const SHOW_NORMAL: u32 = 5;
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const DIB_RGB_COLORS: u32 = 0;
const PS_SOLID: u32 = 0;

const RED: u32 = 0x0000_00FF;
const GREEN: u32 = 0x0000_FF00;
const BLUE: u32 = 0x00FF_0000;
const WHITE: u32 = 0x00FF_FFFF;
const MAGENTA: u32 = 0x00FF_00FF;

pub const WINDOW_SIZE: (u32, u32) = (480, 260);
pub const NON_WHITE_PIXELS: u32 = 1721;

const FRAME: u32 = 0x148;
const HWND: i32 = 0x100;
const HDC_WIN: i32 = 0x108;
const HDC_MEM: i32 = 0x110;
const HBITMAP: i32 = 0x118;
const BRUSH_RED: i32 = 0x120;
const BRUSH_GREEN: i32 = 0x128;
const PEN: i32 = 0x130;
const BRUSH_PATTERN: i32 = 0x138;

const DIB_HEADER_BYTES: usize = 40;
const DIB_BLOB: usize = 2;

pub const READBACKS: [(i32, i32, u32); 26] = [
    (10, 10, RED),
    (26, 10, RED),
    (5, 5, WHITE),
    (20, 10, RED),
    (35, 10, RED),
    (36, 10, GREEN),
    (45, 10, GREEN),
    (100, 100, BLUE),
    (101, 100, WHITE),
    (100, 101, RED),
    (101, 101, GREEN),
    (150, 100, BLUE),
    (153, 100, WHITE),
    (150, 103, RED),
    (153, 103, GREEN),
    (205, 50, MAGENTA),
    (209, 50, MAGENTA),
    (210, 50, WHITE),
    (0, 160, RED),
    (20, 160, GREEN),
    (0, 176, WHITE),
    (31, 175, GREEN),
    (32, 160, RED),
    (42, 10, GREEN),
    (51, 10, GREEN),
    (52, 10, WHITE),
];

fn dib_blob() -> Vec<u8> {
    let mut b = vec![0u8; DIB_HEADER_BYTES];
    b[0..4].copy_from_slice(&(DIB_HEADER_BYTES as u32).to_le_bytes());
    b[4..8].copy_from_slice(&2i32.to_le_bytes());
    b[8..12].copy_from_slice(&2i32.to_le_bytes());
    b[12..14].copy_from_slice(&1u16.to_le_bytes());
    b[14..16].copy_from_slice(&32u16.to_le_bytes());
    for bgra in [[0, 0, 255, 0], [0, 255, 0, 0], [255, 0, 0, 0], [255, 255, 255, 0]] {
        b.extend_from_slice(&bgra);
    }
    b
}

fn import_plan() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "user32.dll",
            vec![
                "RegisterClassW",
                "CreateWindowExW",
                "ShowWindow",
                "DefWindowProcW",
                "GetDC",
                "ReleaseDC",
            ],
        ),
        (
            "gdi32.dll",
            vec![
                "CreateCompatibleDC",
                "CreateCompatibleBitmap",
                "SelectObject",
                "CreateSolidBrush",
                "PatBlt",
                "BitBlt",
                "GetPixel",
                "SetDIBitsToDevice",
                "StretchDIBits",
                "CreatePen",
                "MoveToEx",
                "LineTo",
                "CreatePatternBrush",
            ],
        ),
        ("kernel32.dll", vec!["ExitProcess"]),
    ]
}

pub fn build() -> Vec<u8> {
    let blobs = [wide(CLASS_NAME), wide(WINDOW_TITLE), dib_blob()];
    let r = Rdata::layout(import_plan(), &blobs);
    let text = build_text(&r);
    pe_image(&r, &text)
}

fn build_text(r: &Rdata) -> Vec<u8> {
    use Arg::{Imm, Rva, Slot};
    let mut a = Asm::new();
    let bmi = r.blob(DIB_BLOB);
    let bits = bmi + DIB_HEADER_BYTES as u32;

    a.sub_rsp(FRAME);
    a.xor32(RBX);
    a.lea_label(0, "wndproc");
    a.mov_at_rsp_reg(0x68, 0);
    a.lea_rip(0, r.blob(0));
    a.mov_at_rsp_reg(0xA0, 0);
    a.lea_rsp(RCX, 0x60);
    a.call_iat(r.slot("RegisterClassW"));

    a.call(
        r.slot("CreateWindowExW"),
        &[
            Imm(0),
            Rva(r.blob(0)),
            Rva(r.blob(1)),
            Imm(WS_OVERLAPPEDWINDOW),
            Imm(120),
            Imm(120),
            Imm(WINDOW_SIZE.0),
            Imm(WINDOW_SIZE.1),
            Imm(0),
            Imm(0),
            Imm(0),
            Imm(0),
        ],
    );
    a.mov_at_rsp_reg(HWND, 0);
    a.call(r.slot("ShowWindow"), &[Slot(HWND), Imm(SHOW_NORMAL)]);
    a.call(r.slot("GetDC"), &[Slot(HWND)]);
    a.mov_at_rsp_reg(HDC_WIN, 0);

    a.call(r.slot("CreateCompatibleDC"), &[Slot(HDC_WIN)]);
    a.mov_at_rsp_reg(HDC_MEM, 0);
    a.call(r.slot("CreateCompatibleBitmap"), &[Slot(HDC_WIN), Imm(32), Imm(32)]);
    a.mov_at_rsp_reg(HBITMAP, 0);
    a.call(r.slot("SelectObject"), &[Slot(HDC_MEM), Slot(HBITMAP)]);

    a.call(r.slot("CreateSolidBrush"), &[Imm(RED)]);
    a.mov_at_rsp_reg(BRUSH_RED, 0);
    a.call(r.slot("SelectObject"), &[Slot(HDC_MEM), Slot(BRUSH_RED)]);
    a.call(r.slot("PatBlt"), &[Slot(HDC_MEM), Imm(0), Imm(0), Imm(16), Imm(16), Imm(PATCOPY)]);
    a.call(r.slot("CreateSolidBrush"), &[Imm(GREEN)]);
    a.mov_at_rsp_reg(BRUSH_GREEN, 0);
    a.call(r.slot("SelectObject"), &[Slot(HDC_MEM), Slot(BRUSH_GREEN)]);
    a.call(r.slot("PatBlt"), &[Slot(HDC_MEM), Imm(16), Imm(0), Imm(16), Imm(16), Imm(PATCOPY)]);

    a.call(
        r.slot("BitBlt"),
        &[Slot(HDC_WIN), Imm(10), Imm(10), Imm(32), Imm(16), Slot(HDC_MEM), Imm(0), Imm(0), Imm(SRCCOPY)],
    );
    a.call(
        r.slot("BitBlt"),
        &[Slot(HDC_WIN), Imm(20), Imm(10), Imm(32), Imm(16), Slot(HDC_WIN), Imm(10), Imm(10), Imm(SRCCOPY)],
    );

    a.call(
        r.slot("SetDIBitsToDevice"),
        &[
            Slot(HDC_WIN),
            Imm(100),
            Imm(100),
            Imm(2),
            Imm(2),
            Imm(0),
            Imm(0),
            Imm(0),
            Imm(2),
            Rva(bits),
            Rva(bmi),
            Imm(DIB_RGB_COLORS),
        ],
    );
    a.call(
        r.slot("StretchDIBits"),
        &[
            Slot(HDC_WIN),
            Imm(150),
            Imm(100),
            Imm(4),
            Imm(4),
            Imm(0),
            Imm(0),
            Imm(2),
            Imm(2),
            Rva(bits),
            Rva(bmi),
            Imm(DIB_RGB_COLORS),
            Imm(SRCCOPY),
        ],
    );

    a.call(r.slot("CreatePen"), &[Imm(PS_SOLID), Imm(1), Imm(MAGENTA)]);
    a.mov_at_rsp_reg(PEN, 0);
    a.call(r.slot("SelectObject"), &[Slot(HDC_WIN), Slot(PEN)]);
    a.call(r.slot("MoveToEx"), &[Slot(HDC_WIN), Imm(200), Imm(50), Imm(0)]);
    a.call(r.slot("LineTo"), &[Slot(HDC_WIN), Imm(210), Imm(50)]);

    a.call(r.slot("CreatePatternBrush"), &[Slot(HBITMAP)]);
    a.mov_at_rsp_reg(BRUSH_PATTERN, 0);
    a.call(r.slot("SelectObject"), &[Slot(HDC_WIN), Slot(BRUSH_PATTERN)]);
    a.call(r.slot("PatBlt"), &[Slot(HDC_WIN), Imm(0), Imm(160), Imm(64), Imm(16), Imm(PATCOPY)]);

    for (i, (x, y, colorref)) in READBACKS.iter().enumerate() {
        let ok = format!("ok{i}");
        a.call(r.slot("GetPixel"), &[Slot(HDC_WIN), Imm(*x as u32), Imm(*y as u32)]);
        a.cmp_eax_imm(*colorref);
        a.je(&ok);
        a.or_ebx_imm(1 << i);
        a.label(&ok);
    }

    a.call(r.slot("ReleaseDC"), &[Slot(HWND), Slot(HDC_WIN)]);
    a.mov_reg_reg(RCX, RBX);
    a.call_iat(r.slot("ExitProcess"));
    a.int3();

    a.label("wndproc");
    a.sub_rsp(0x28);
    a.call_iat(r.slot("DefWindowProcW"));
    a.add_rsp(0x28);
    a.ret();

    a.finish()
}
