use exemu_core::{CpuState, Memory, Perm, Result, WindowParams};

use crate::api::read_wstr;
use crate::wndclass::{ClassClient, ClientMenuName, WndClassEx};
use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;

const WIN32K_FIRST: u32 = 0x1084;
const WIN32K_LAST: u32 = 0x1601;

const NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS: u32 = 0x147a;
const NT_USER_GET_SYSTEM_DPI_FOR_PROCESS: u32 = 0x144b;
const NT_USER_SET_PROCESS_DPI_AWARENESS_CONTEXT: u32 = 0x1577;
const NT_USER_GET_PROCESS_DPI_AWARENESS_CONTEXT: u32 = 0x1435;
const NT_USER_GET_ATOM_NAME: u32 = 0x13d1;
const NT_USER_GET_CLASS_INFO_EX: u32 = 0x13d8;
const NT_USER_REGISTER_CLASS_EX_WOW: u32 = 0x14eb;
const NT_USER_CREATE_WINDOW_EX: u32 = 0x136b;
const NT_USER_SHOW_WINDOW: u32 = 0x15bd;
const NT_USER_SHOW_WINDOW_ASYNC: u32 = 0x15be;
const NT_USER_DESTROY_WINDOW: u32 = 0x1384;
const NT_USER_SET_WINDOW_POS: u32 = 0x15a7;
const NT_USER_MESSAGE_CALL: u32 = 0x14b5;
const NT_USER_INTERNAL_GET_WINDOW_TEXT: u32 = 0x1489;
const NT_USER_GET_DC: u32 = 0x13eb;
const NT_USER_GET_DC_EX: u32 = 0x13ec;
const NT_USER_RELEASE_DC: u32 = 0x1509;
const NT_USER_BEGIN_PAINT: u32 = 0x1327;
const NT_USER_END_PAINT: u32 = 0x13bc;
const NT_USER_GET_MESSAGE: u32 = 0x141b;
const NT_USER_PEEK_MESSAGE: u32 = 0x14ca;
const NT_USER_POST_QUIT_MESSAGE: u32 = 0x14d1;
const NT_USER_POST_MESSAGE: u32 = 0x14d0;
const NT_USER_TRANSLATE_MESSAGE: u32 = 0x15d8;
const NT_USER_DISPATCH_MESSAGE: u32 = 0x138b;

const NT_USER_GET_CURSOR: u32 = 0x13e7;
const NT_USER_GET_CURSOR_POS: u32 = 0x13ea;
const NT_USER_SET_CURSOR: u32 = 0x1546;
const NT_USER_SET_CURSOR_POS: u32 = 0x154a;
const NT_USER_CLIP_CURSOR: u32 = 0x1350;
const NT_USER_CHANGE_DISPLAY_SETTINGS: u32 = 0x1342;
const NT_USER_ENUM_DISPLAY_SETTINGS: u32 = 0x13c1;
const NT_USER_MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX: u32 = 0x14bb;

const NT_USER_WINDOW_FROM_POINT: u32 = 0x15ff;
const NT_USER_CHILD_WINDOW_FROM_POINT_EX: u32 = 0x134b;
const NT_USER_SET_CAPTURE: u32 = 0x153a;
const NT_USER_RELEASE_CAPTURE: u32 = 0x1508;
const NT_USER_SET_FOCUS: u32 = 0x1557;
const NT_USER_SET_ACTIVE_WINDOW: u32 = 0x1532;
const NT_USER_GET_THREAD_STATE: u32 = 0x144e;
const NT_USER_GET_ANCESTOR: u32 = 0x13ce;

mod thread_state {
    pub const FOCUS: u64 = 0;
    pub const ACTIVE: u64 = 1;
    pub const CAPTURE: u64 = 2;
}

mod message_call {
    pub const SCROLL_BAR_WND_PROC: u64 = 0x29a;
    pub const POPUP_MENU_WND_PROC: u64 = 0x29c;
    pub const DESKTOP_WND_PROC: u64 = 0x29d;
    pub const DEF_WINDOW_PROC: u64 = 0x29e;
    pub const CLIPBOARD_WND_PROC: u64 = 0x300;

    pub const CALL_WINDOW_PROC: u64 = 0x2ab;
    pub const SEND_MESSAGE: u64 = 0x2b1;
    pub const SEND_MESSAGE_TIMEOUT: u64 = 0x2b3;
    pub const SEND_NOTIFY_MESSAGE: u64 = 0x2b7;
    pub const SEND_MESSAGE_CALLBACK: u64 = 0x2b8;
    pub const DISPATCH_MESSAGE: u64 = 0x3001;

    pub const SPY_ENTER: u64 = 0x303;
    pub const SPY_EXIT: u64 = 0x304;
    pub const IME_DRIVER_CALL: u64 = 0x305;
    pub const SYSTRAY_CALL: u64 = 0x306;
    pub const DRIVER_CALL_307: u64 = 0x307;
    pub const POST_DDE_MESSAGE: u64 = 0x308;
    pub const TABLET_CALL: u64 = 0x309;
    pub const SPY_GET_MSG_NAME: u64 = 0x3002;

    pub const SENDS: [u64; 4] =
        [SEND_MESSAGE, SEND_MESSAGE_TIMEOUT, SEND_NOTIFY_MESSAGE, SEND_MESSAGE_CALLBACK];

    pub const KERNEL_WND_PROCS: [u64; 5] = [
        DEF_WINDOW_PROC,
        SCROLL_BAR_WND_PROC,
        POPUP_MENU_WND_PROC,
        DESKTOP_WND_PROC,
        CLIPBOARD_WND_PROC,
    ];

    pub const NOT_A_MESSAGE: [u64; 8] = [
        SPY_ENTER,
        SPY_EXIT,
        IME_DRIVER_CALL,
        SYSTRAY_CALL,
        DRIVER_CALL_307,
        POST_DDE_MESSAGE,
        TABLET_CALL,
        SPY_GET_MSG_NAME,
    ];
}

const WIN_PROC_PARAMS_FUNC: u64 = 0x00;

const NT_GDI_EXT_TEXT_OUT_W: u32 = 0x11c9;
const NT_GDI_RECTANGLE: u32 = 0x1259;

const NT_GDI_PAT_BLT: u32 = 0x124c;
const NT_GDI_SELECT_BRUSH: u32 = 0x126c;
const NT_GDI_SELECT_PEN: u32 = 0x126f;
const NT_GDI_CREATE_SOLID_BRUSH: u32 = 0x10bf;
const NT_GDI_CREATE_PEN: u32 = 0x10ba;
const NT_GDI_GET_AND_SET_DC_DWORD: u32 = 0x11da;
const NT_GDI_SELECT_FONT: u32 = 0x126e;
const NT_GDI_CREATE_RECT_RGN: u32 = 0x10bb;
const NT_GDI_DELETE_OBJECT_APP: u32 = 0x118f;
const NT_GDI_INTERSECT_CLIP_RECT: u32 = 0x1238;
const NT_GDI_GET_TEXT_METRICS_W: u32 = 0x1229;
const NT_GDI_GET_TEXT_EXTENT_EX_W: u32 = 0x1227;

const NT_GDI_CREATE_COMPATIBLE_DC: u32 = 0x10ae;
const NT_GDI_CREATE_BITMAP: u32 = 0x10a7;
const NT_GDI_CREATE_COMPATIBLE_BITMAP: u32 = 0x10ad;
const NT_GDI_SELECT_BITMAP: u32 = 0x126b;
const NT_GDI_GET_DEVICE_CAPS: u32 = 0x11f4;
const NT_GDI_CREATE_DIB_SECTION: u32 = 0x10b0;
const NT_GDI_EXT_GET_OBJECT_W: u32 = 0x11c7;
const NT_GDI_HFONT_CREATE: u32 = 0x1233;
const NT_GDI_GET_DC_OBJECT: u32 = 0x11f0;
const NT_GDI_GET_FONT_DATA: u32 = 0x11fe;
const NT_GDI_GET_TEXT_FACE_W: u32 = 0x1228;

const LOGFONTW_SIZE: u32 = 0x5c;
const LOGFONT_HEIGHT: usize = 0x00;
const LOGFONT_WEIGHT: usize = 0x10;
const LOGFONT_ITALIC: usize = 0x14;
const LOGFONT_UNDERLINE: usize = 0x15;
const LOGFONT_STRIKE_OUT: usize = 0x16;
const LOGFONT_CHAR_SET: usize = 0x17;
const LOGFONT_PITCH_AND_FAMILY: usize = 0x1b;
const LOGFONT_FACE_NAME: usize = 0x1c;
const LOGFONT_FACE_CHARS: usize = 32;

const GDI_ERROR: u32 = 0xFFFF_FFFF;

const STOCK_SYSTEM_FONT: u32 = 0x2d;
const STOCK_DEFAULT_GUI_FONT: u32 = 0x31;
const STOCK_WHITE_BRUSH: u32 = 0x20;
const STOCK_BLACK_PEN: u32 = 0x27;
const STOCK_DEFAULT_PALETTE: u32 = 0x2f;

const NTGDI_OBJ_SURF: u32 = 0x05;
const NTGDI_OBJ_EXTPEN: u32 = 0x50;

const DEFAULT_CHARSET: u8 = 1;
const FW_NORMAL: i32 = 400;
const FW_BOLD: i32 = 700;
const FIXED_PITCH_MODERN: u8 = 0x31;
const VARIABLE_PITCH_SWISS: u8 = 0x22;

const STOCK_FONTS: [(u32, i32, i32, u8, &str); 6] = [
    (0x2a, 12, FW_NORMAL, FIXED_PITCH_MODERN, "Terminal"),
    (0x2b, 13, FW_NORMAL, FIXED_PITCH_MODERN, "Courier"),
    (0x2c, 12, FW_NORMAL, VARIABLE_PITCH_SWISS, "MS Sans Serif"),
    (STOCK_SYSTEM_FONT, 16, FW_BOLD, VARIABLE_PITCH_SWISS, "System"),
    (0x30, 15, FW_NORMAL, FIXED_PITCH_MODERN, "Fixedsys"),
    (STOCK_DEFAULT_GUI_FONT, -11, FW_NORMAL, VARIABLE_PITCH_SWISS, "MS Shell Dlg"),
];

const BIH_WIDTH: u64 = 0x04;
const BIH_HEIGHT: u64 = 0x08;
const BIH_PLANES: u64 = 0x0c;
const BIH_BIT_COUNT: u64 = 0x0e;

const BITMAP_TYPE: u64 = 0x00;
const BITMAP_WIDTH: u64 = 0x04;
const BITMAP_HEIGHT: u64 = 0x08;
const BITMAP_WIDTH_BYTES: u64 = 0x0c;
const BITMAP_PLANES: u64 = 0x10;
const BITMAP_BITS_PIXEL: u64 = 0x12;
const BITMAP_BITS: u64 = 0x18;
const BITMAP_SIZE: u32 = 0x20;

const SURFACE_BPP: u32 = 32;

const CALL_ONE_CREATE_CURSOR_ICON: u64 = 0x00;
const NT_USER_SET_CURSOR_ICON_DATA: u32 = 0x1548;
const NT_USER_GET_ICON_INFO: u32 = 0x1403;
const NT_USER_GET_ICON_SIZE: u32 = 0x1404;
const NT_USER_FIND_EXISTING_CURSOR_ICON: u32 = 0x13c5;
const NT_USER_DESTROY_CURSOR: u32 = 0x137f;

const DESC_FRAMES: u64 = 0x10;
const FRAME_WIDTH: u64 = 0x00;
const FRAME_HEIGHT: u64 = 0x04;
const FRAME_COLOR: u64 = 0x08;
const FRAME_ALPHA: u64 = 0x10;
const FRAME_MASK: u64 = 0x18;
const FRAME_HOTSPOT_X: u64 = 0x20;
const FRAME_HOTSPOT_Y: u64 = 0x24;

const ICONINFO_F_ICON: u64 = 0x00;
const ICONINFO_X_HOTSPOT: u64 = 0x04;
const ICONINFO_Y_HOTSPOT: u64 = 0x08;
const ICONINFO_HBM_MASK: u64 = 0x10;
const ICONINFO_HBM_COLOR: u64 = 0x18;
const USTR_LENGTH: u64 = 0x00;
const USTR_BUFFER: u64 = 0x08;

mod dev_caps {
    pub const TECHNOLOGY: u64 = 2;
    pub const HORZRES: u64 = 8;
    pub const VERTRES: u64 = 10;
    pub const BITSPIXEL: u64 = 12;
    pub const PLANES: u64 = 14;
    pub const NUMCOLORS: u64 = 24;
    pub const LOGPIXELSX: u64 = 88;
    pub const LOGPIXELSY: u64 = 90;
    pub const DT_RASDISPLAY: u32 = 1;
}

const NT_USER_SET_PROP: u32 = 0x157f;
const NT_USER_GET_PROP: u32 = 0x1438;
const NT_USER_REMOVE_PROP: u32 = 0x151e;

const TM_HEIGHT: u64 = 0x00;
const TM_ASCENT: u64 = 0x04;
const TM_DESCENT: u64 = 0x08;
const TM_INTERNAL_LEADING: u64 = 0x0C;
const TM_EXTERNAL_LEADING: u64 = 0x10;
const TM_AVE_CHAR_WIDTH: u64 = 0x14;
const TM_MAX_CHAR_WIDTH: u64 = 0x18;
const TM_WEIGHT: u64 = 0x1C;
const TM_OVERHANG: u64 = 0x20;
const TM_DIGITIZED_ASPECT_X: u64 = 0x24;
const TM_DIGITIZED_ASPECT_Y: u64 = 0x28;
const TM_FIRST_CHAR: u64 = 0x2C;
const TM_LAST_CHAR: u64 = 0x2E;
const TM_DEFAULT_CHAR: u64 = 0x30;
const TM_BREAK_CHAR: u64 = 0x32;
const TM_ITALIC: u64 = 0x34;
const TM_UNDERLINED: u64 = 0x35;
const TM_STRUCK_OUT: u64 = 0x36;
const TM_PITCH_AND_FAMILY: u64 = 0x37;
const TM_CHARSET: u64 = 0x38;

const STUB_FONT_CELL_W: u32 = 8;
const STUB_FONT_CELL_H: u32 = 16;

const SIMPLEREGION: u32 = 2;

const NT_USER_BUILD_HWND_LIST: u32 = 0x132d;
const NT_USER_CALL_HWND: u32 = 0x1332;
const NT_USER_CALL_HWND_PARAM: u32 = 0x1336;
const NT_USER_CALL_ONE_PARAM: u32 = 0x133d;
const NT_USER_CALL_TWO_PARAM: u32 = 0x133e;
const NT_USER_SET_WINDOW_LONG: u32 = 0x15a3;
const NT_USER_SET_WINDOW_LONG_PTR: u32 = 0x15a4;

const DC_ATTR_ORG_X: u64 = 0x48;
const DC_ATTR_ORG_Y: u64 = 0x4C;
const DC_ATTR_BK_COLOR: u64 = 0x0C;
const DC_ATTR_TEXT_COLOR: u64 = 0x18;

mod dc_dword {
    pub const BK_COLOR: u64 = 0x64;
    pub const TEXT_COLOR: u64 = 0x66;
}

const PATCOPY: u32 = 0x00F0_0021;
const BLACKNESS: u32 = 0x0000_0042;
const WHITENESS: u32 = 0x00FF_0062;

const GDI_PEB_TABLE_PTR_OFF: u64 = 0xF8;
const GDI_PEB32_TABLE_PTR_OFF: u64 = 0x94;
const GDI_ENTRY_SIZE: u64 = 24;
const GDI_ENTRY_GENERATION_OFF: u64 = 0xC;
const GDI_ENTRY_TYPE_OFF: u64 = 0xE;
const GDI_ENTRY_OBJECT_OFF: u64 = 0x10;
const GDI_TABLE_SLOTS: u64 = 4096;
const GDI_ENTRY_IN_USE: u8 = 0x01;
const GDI_DC_OBJECT_SIZE: u64 = 0x100;

mod gdi_type {
    pub const DC: u16 = 0x01;
    pub const REGION: u16 = 0x04;
    pub const PALETTE: u16 = 0x08;
    pub const BITMAP: u16 = 0x09;
    pub const FONT: u16 = 0x0a;
    pub const BRUSH: u16 = 0x10;
    pub const PEN: u16 = 0x30;
}

const STOCK_SLOT_BASE: u64 = 0x20;
const STOCK_SLOT_LAST: u64 = 0x37;

const STOCK_OBJECTS: [(u64, u16, Option<u32>); 24] = [
    (0x20, gdi_type::BRUSH, Some(0x00FF_FFFF)),
    (0x21, gdi_type::BRUSH, Some(0x00C0_C0C0)),
    (0x22, gdi_type::BRUSH, Some(0x0080_8080)),
    (0x23, gdi_type::BRUSH, Some(0x0040_4040)),
    (0x24, gdi_type::BRUSH, Some(0x0000_0000)),
    (0x25, gdi_type::BRUSH, None),
    (0x26, gdi_type::PEN, None),
    (0x27, gdi_type::PEN, None),
    (0x28, gdi_type::PEN, None),
    (0x29, gdi_type::FONT, None),
    (0x2a, gdi_type::FONT, None),
    (0x2b, gdi_type::FONT, None),
    (0x2c, gdi_type::FONT, None),
    (0x2d, gdi_type::FONT, None),
    (0x2e, gdi_type::FONT, None),
    (0x2f, gdi_type::PALETTE, None),
    (0x30, gdi_type::FONT, None),
    (0x31, gdi_type::FONT, None),
    (0x32, gdi_type::BRUSH, Some(0x00FF_FFFF)),
    (0x33, gdi_type::PEN, None),
    (0x34, gdi_type::BITMAP, None),
    (0x35, gdi_type::FONT, None),
    (0x36, gdi_type::FONT, None),
    (0x37, gdi_type::FONT, None),
];

const CLASS_ATOM_BASE: u16 = 0xC000;

const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CHILD: u32 = 0x4000_0000;

const WND_EXTRA_MAX: u32 = 4096;

const GWLP_WNDPROC: i64 = -4;
const GWLP_HINSTANCE: i64 = -6;
const GWLP_HWNDPARENT: i64 = -8;
const GWL_STYLE: i64 = -16;
const GWL_EXSTYLE: i64 = -20;
const GWLP_USERDATA: i64 = -21;
const GWLP_ID: i64 = -12;

mod call_hwnd {
    pub const GET_DIALOG_INFO: u64 = 0x01;
    pub const GET_DPI_FOR_WINDOW: u64 = 0x02;
    pub const GET_PARENT: u64 = 0x05;
    pub const IS_WINDOW: u64 = 0x0a;
    pub const IS_WINDOW_ENABLED: u64 = 0x0b;
    pub const IS_WINDOW_UNICODE: u64 = 0x0c;
    pub const IS_WINDOW_VISIBLE: u64 = 0x0d;
    pub const GET_FULL_WINDOW_HANDLE: u64 = 0x0f;
    pub const IS_SELF_THREAD: u64 = 0x10;
}

mod call_hwnd_param {
    pub const GET_WINDOW_LONG: u64 = 0x0a;
    pub const GET_WINDOW_LONG_PTR_A: u64 = 0x0b;
    pub const GET_WINDOW_LONG_PTR_W: u64 = 0x0c;
    pub const GET_WINDOW_RECT: u64 = 0x0d;
    pub const GET_CLIENT_RECT: u64 = 0x0e;
    pub const GET_WINDOW_RELATIVE: u64 = 0x10;
    pub const IS_CHILD: u64 = 0x13;
    pub const SET_DIALOG_INFO: u64 = 0x18;
}

mod window_relative {
    pub const HWND_FIRST: u64 = 0;
    pub const HWND_LAST: u64 = 1;
    pub const HWND_NEXT: u64 = 2;
    pub const HWND_PREV: u64 = 3;
    pub const OWNER: u64 = 4;
    pub const CHILD: u64 = 5;
}

const HWND_LIST_MAX: usize = 4096;
const DIALOG_CLASS: &str = "#32770";
const IDC_FILENAME_COMBO: u64 = 0x47c;
const IDOK: u64 = 1;
const WM_COMMAND: u32 = 0x0111;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

mod call_two_param {
    pub const GET_DIALOG_PROC: u64 = 0x00;
    pub const ALLOC_WIN_PROC: u64 = 0x09;
}

const WINPROC_HANDLE_TAG: u64 = 0xFFFF_0000;
const WINPROC_HANDLE_MASK: u64 = 0xFFFF;
const WINPROC_MAX: usize = 0x1000;

mod call_one_param {
    pub const CREATE_CURSOR_ICON: u64 = super::CALL_ONE_CREATE_CURSOR_ICON;
    pub const GET_SYS_COLOR: u64 = 0x06;
    pub const GET_SYS_COLOR_BRUSH: u64 = 0x07;
    pub const GET_SYSTEM_METRICS: u64 = 0x09;
}

const CALL_RECT_PARAM_RECT: u64 = 0x00;

const WINDOW_ANCESTRY_MAX: usize = 64;

const CLIENT_PFN_COUNT: usize = 17;
const PFN_THUNK_JMP: [u8; 3] = [0x48, 0xFF, 0x25];
const PFN_THUNK_LEN: u64 = 7;

const PFN_SCROLL_BAR: usize = 0;
const PFN_MESSAGE: usize = 1;
const PFN_POPUP_MENU: usize = 2;
const PFN_DESKTOP: usize = 3;
const PFN_ICON_TITLE: usize = 5;
const PFN_BUTTON: usize = 7;
const PFN_COMBO_BOX: usize = 8;
const PFN_COMBO_LBOX: usize = 9;
const PFN_DIALOG: usize = 10;
const PFN_EDIT: usize = 11;
const PFN_LIST_BOX: usize = 12;
const PFN_MDI_CLIENT: usize = 13;
const PFN_STATIC: usize = 14;
const PFN_IME: usize = 15;

const BUILTIN_CLASSES: [(&str, usize); 14] = [
    ("BUTTON", PFN_BUTTON),
    ("EDIT", PFN_EDIT),
    ("STATIC", PFN_STATIC),
    ("LISTBOX", PFN_LIST_BOX),
    ("COMBOBOX", PFN_COMBO_BOX),
    ("ComboLBox", PFN_COMBO_LBOX),
    ("ScrollBar", PFN_SCROLL_BAR),
    ("MDIClient", PFN_MDI_CLIENT),
    ("IME", PFN_IME),
    ("Message", PFN_MESSAGE),
    ("#32768", PFN_POPUP_MENU),
    ("#32769", PFN_DESKTOP),
    ("#32770", PFN_DIALOG),
    ("#32772", PFN_ICON_TITLE),
];

const BUILTIN_CLASS_STYLE: u32 = 0x4000 | 0x0008 | 0x0080;

const BUILTIN_WND_EXTRA: u32 = 8 * 8;

const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;
const DEFAULT_X: i32 = 100;
const DEFAULT_Y: i32 = 100;
const DEFAULT_CX: i32 = 640;
const DEFAULT_CY: i32 = 480;

const WM_SETTEXT: u32 = 0x000c;
const WM_NCCREATE: u32 = 0x0081;

const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_GETTEXTLENGTH: u32 = 0x000e;
const WM_GETTEXT: u32 = 0x000d;
const WM_CLOSE: u32 = 0x0010;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_NCCALCSIZE: u32 = 0x0083;
const WM_NCHITTEST: u32 = 0x0084;
const WM_NCDESTROY: u32 = 0x0082;
const WM_SETCURSOR: u32 = 0x0020;
const WM_MOUSEACTIVATE: u32 = 0x0021;
const WM_CAPTURECHANGED: u32 = 0x0215;
const WM_MOUSEFIRST: u32 = 0x0200;
const WM_NCMOUSEFIRST: u32 = 0x00a0;
const NC_MOUSE_DELTA: u32 = WM_MOUSEFIRST - WM_NCMOUSEFIRST;
const WM_MOUSELAST_NC: u32 = 0x020d;

mod hit {
    pub const CLIENT: i64 = 1;
    pub const NOWHERE: i64 = 0;
    pub const TRANSPARENT: i64 = -1;
}

mod ancestor {
    pub const PARENT: u64 = 1;
    pub const ROOT: u64 = 2;
    pub const ROOTOWNER: u64 = 3;
}

const HIT_TEST_ROUNDS_MAX: usize = 8;

struct CsLayout {
    lp_create_params: u64,
    hinstance: u64,
    hmenu: u64,
    hwnd_parent: u64,
    cy: u64,
    cx: u64,
    y: u64,
    x: u64,
    style: u64,
    lpsz_name: u64,
    lpsz_class: u64,
    dw_ex_style: u64,
    size: u64,
}

const CS64: CsLayout = CsLayout {
    lp_create_params: 0x00,
    hinstance: 0x08,
    hmenu: 0x10,
    hwnd_parent: 0x18,
    cy: 0x20,
    cx: 0x24,
    y: 0x28,
    x: 0x2C,
    style: 0x30,
    lpsz_name: 0x38,
    lpsz_class: 0x40,
    dw_ex_style: 0x48,
    size: 0x50,
};

const CS32: CsLayout = CsLayout {
    lp_create_params: 0x00,
    hinstance: 0x04,
    hmenu: 0x08,
    hwnd_parent: 0x0C,
    cy: 0x10,
    cx: 0x14,
    y: 0x18,
    x: 0x1C,
    style: 0x20,
    lpsz_name: 0x24,
    lpsz_class: 0x28,
    dw_ex_style: 0x2C,
    size: 0x30,
};

const CREATE_SCRATCH: u64 = 0x200;
const CREATE_NAME_MAX: usize = 96;

const DEVMODE_SIZE: u16 = 220;
const DEVMODE_DMSIZE_OFF: u64 = 68;
const DEVMODE_DMFIELDS_OFF: u64 = 72;
const DEVMODE_DMLOGPIXELS_OFF: u64 = 166;
const DEVMODE_DMBITSPERPEL_OFF: u64 = 168;
const DEVMODE_DMPELSWIDTH_OFF: u64 = 172;
const DEVMODE_DMPELSHEIGHT_OFF: u64 = 176;
const DEVMODE_DMDISPLAYFREQUENCY_OFF: u64 = 184;
const DM_DISPLAY_FIELDS: u32 = 0x0004_0000 | 0x0008_0000 | 0x0010_0000 | 0x0040_0000;
const DISP_CHANGE_SUCCESSFUL: u32 = 0;
const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;

#[allow(dead_code)]
struct Class {
    name: String,
    wndproc: u64,
    style: u32,
    background: u64,
    wnd_extra: u32,
    client: ClassClient,
}

#[allow(dead_code)]
struct Window {
    class_atom: u16,
    class_name: String,
    title: String,
    rect: [i32; 4],
    style: u32,
    ex_style: u32,
    parent: u32,
    shown: bool,
    wndproc: u64,
    needs_paint: bool,
    surface: Option<Surface>,
    extra: Vec<u8>,
    user_data: u64,
    id: u64,
    instance: u64,
    props: Vec<(String, u64)>,
    dialog_info: u64,
    dialog_cancelled: bool,
}

#[derive(Clone, Copy)]
struct Surface {
    base: u64,
    w: u32,
    h: u32,
}

#[derive(Clone, Copy)]
struct Bitmap {
    w: i32,
    h: i32,
    planes: u32,
    bpp: u32,
    bits: u64,
    stride: u32,
    top_down: bool,
}

#[derive(Clone, Copy, Default)]
struct WinProc {
    proc_a: u64,
    proc_w: u64,
}

#[derive(Clone, Copy, Default)]
struct IconObject {
    is_icon: bool,
    width: i32,
    height: i32,
    hotspot: (i32, i32),
    color: u32,
    alpha: u32,
    mask: u32,
}

#[derive(Clone, Copy)]
struct LogFont([u8; LOGFONTW_SIZE as usize]);

impl LogFont {
    fn from_bytes(src: &[u8]) -> LogFont {
        let mut lf = [0u8; LOGFONTW_SIZE as usize];
        let n = src.len().min(lf.len());
        lf[..n].copy_from_slice(&src[..n]);
        LogFont(lf)
    }

    fn stock(height: i32, weight: i32, pitch_and_family: u8, face: &str) -> LogFont {
        let mut lf = [0u8; LOGFONTW_SIZE as usize];
        lf[LOGFONT_HEIGHT..LOGFONT_HEIGHT + 4].copy_from_slice(&height.to_le_bytes());
        lf[LOGFONT_WEIGHT..LOGFONT_WEIGHT + 4].copy_from_slice(&weight.to_le_bytes());
        lf[LOGFONT_CHAR_SET] = DEFAULT_CHARSET;
        lf[LOGFONT_PITCH_AND_FAMILY] = pitch_and_family;
        for (i, unit) in face.encode_utf16().take(LOGFONT_FACE_CHARS - 1).enumerate() {
            let at = LOGFONT_FACE_NAME + i * 2;
            lf[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        LogFont(lf)
    }

    fn i32_at(&self, off: usize) -> i32 {
        i32::from_le_bytes([self.0[off], self.0[off + 1], self.0[off + 2], self.0[off + 3]])
    }

    fn height(&self) -> i32 {
        self.i32_at(LOGFONT_HEIGHT)
    }

    fn weight(&self) -> i32 {
        match self.i32_at(LOGFONT_WEIGHT) {
            0 => FW_NORMAL,
            w => w,
        }
    }

    fn face(&self) -> String {
        let mut units = Vec::with_capacity(LOGFONT_FACE_CHARS);
        for i in 0..LOGFONT_FACE_CHARS {
            let at = LOGFONT_FACE_NAME + i * 2;
            let unit = u16::from_le_bytes([self.0[at], self.0[at + 1]]);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16_lossy(&units)
    }

    fn cell_height(&self) -> u32 {
        match self.height() {
            0 => STUB_FONT_CELL_H,
            h if h > 0 => h as u32,
            h => {
                let em = h.unsigned_abs();
                em + em.div_ceil(4)
            }
        }
        .clamp(1, 512)
    }

    fn metrics(&self) -> TextMetrics {
        let cell = self.cell_height();
        let descent = (cell / 4).max(1);
        let internal_leading = match self.height() {
            h if h < 0 => cell - h.unsigned_abs(),
            _ => cell / 8,
        };
        let ave = (cell * 3 / 8).max(1);
        TextMetrics {
            height: cell,
            ascent: cell - descent,
            descent,
            internal_leading,
            ave_char_width: ave,
            max_char_width: ave * 2,
            weight: self.weight() as u32,
            italic: self.0[LOGFONT_ITALIC],
            underlined: self.0[LOGFONT_UNDERLINE],
            struck_out: self.0[LOGFONT_STRIKE_OUT],
            char_set: self.0[LOGFONT_CHAR_SET],
            pitch_and_family: self.0[LOGFONT_PITCH_AND_FAMILY],
        }
    }
}

struct TextMetrics {
    height: u32,
    ascent: u32,
    descent: u32,
    internal_leading: u32,
    ave_char_width: u32,
    max_char_width: u32,
    weight: u32,
    italic: u8,
    underlined: u8,
    struck_out: u8,
    char_set: u8,
    pitch_and_family: u8,
}

struct Dc {
    hwnd: u32,
    brush: u32,
    org: (i32, i32),
    clip: [i32; 4],
    bitmap: u32,
    font: u32,
}

#[derive(Default)]
pub(crate) struct Win32kState {
    client_pfn_table: u64,
    client_pfn_w: [u64; CLIENT_PFN_COUNT],
    #[allow(dead_code)]
    client_pfn_a: [u64; CLIENT_PFN_COUNT],
    user32_image: (u64, u64),
    classes: Vec<(u16, Class)>,
    windows: Vec<(u32, Window)>,
    dcs: Vec<(u32, Dc)>,
    brushes: Vec<(u32, u32)>,
    bitmaps: Vec<(u32, Bitmap)>,
    fonts: Vec<(u32, LogFont)>,
    icons: Vec<(u32, IconObject)>,
    win_procs: Vec<WinProc>,
    driven_dialogs: Vec<u32>,
    pick_text: u64,
    sys_brushes: Vec<(u32, u32)>,
    gdi_table_base: u64,
    gdi_next_slot: u64,
    gdi_free_slots: Vec<u64>,
    gdi_dc_arena: u64,
    cursor_pos: (i32, i32),
    current_cursor: u64,
    raw_input: std::collections::VecDeque<exemu_core::InputEvent>,
    capture: u32,
    focus: u32,
    active: u32,
}

impl Win32kState {
    fn class_by_name(&self, name: &str) -> Option<u16> {
        self.classes
            .iter()
            .find(|(_, c)| c.name.eq_ignore_ascii_case(name))
            .map(|(a, _)| *a)
    }

    fn class_by_atom(&self, atom: u16) -> Option<&Class> {
        self.classes.iter().find(|(a, _)| *a == atom).map(|(_, c)| c)
    }

    fn wndproc_for(&self, hwnd: u32) -> u64 {
        self.window(hwnd).map(|w| w.wndproc).unwrap_or(0)
    }

    fn shown_window(&self) -> Option<u32> {
        self.windows
            .iter()
            .find(|(h, w)| w.shown && self.surface_owner(*h) == *h)
            .map(|(h, _)| *h)
    }

    fn take_paint_pending(&mut self) -> Option<u32> {
        let hwnd = self
            .windows
            .iter()
            .find(|(h, w)| w.needs_paint && self.chain_visible(*h))
            .map(|(h, _)| *h)?;
        if let Some(w) = self.window_mut(hwnd) {
            w.needs_paint = false;
        }
        Some(hwnd)
    }

    fn chain_visible(&self, hwnd: u32) -> bool {
        let mut cur = hwnd;
        for _ in 0..WINDOW_ANCESTRY_MAX {
            let Some(w) = self.window(cur) else { return false };
            if !w.shown {
                return false;
            }
            if w.parent == 0 || self.window(w.parent).is_none() {
                return true;
            }
            cur = w.parent;
        }
        false
    }

    fn surface_owner(&self, hwnd: u32) -> u32 {
        let mut cur = hwnd;
        for _ in 0..WINDOW_ANCESTRY_MAX {
            let Some(w) = self.window(cur) else { return cur };
            if w.parent == 0 || self.window(w.parent).is_none() {
                return cur;
            }
            cur = w.parent;
        }
        cur
    }

    fn client_origin(&self, hwnd: u32) -> (i32, i32) {
        let (mut ox, mut oy) = (0i32, 0i32);
        let mut cur = hwnd;
        for _ in 0..WINDOW_ANCESTRY_MAX {
            let Some(w) = self.window(cur) else { break };
            if w.parent == 0 || self.window(w.parent).is_none() {
                break;
            }
            ox += w.rect[0];
            oy += w.rect[1];
            cur = w.parent;
        }
        (ox, oy)
    }

    fn window_visible_rect(&self, hwnd: u32) -> [i32; 4] {
        let (ox, oy) = self.client_origin(hwnd);
        let Some(w) = self.window(hwnd) else { return [0; 4] };
        let (cx, cy) = client_size(w);
        let mut r = [ox, oy, ox + cx as i32, oy + cy as i32];
        let mut cur = hwnd;
        for _ in 0..WINDOW_ANCESTRY_MAX {
            let Some(w) = self.window(cur) else { break };
            let parent = w.parent;
            if parent == 0 || self.window(parent).is_none() {
                break;
            }
            let (px, py) = self.client_origin(parent);
            let Some(p) = self.window(parent) else { break };
            let (pcx, pcy) = client_size(p);
            r[0] = r[0].max(px);
            r[1] = r[1].max(py);
            r[2] = r[2].min(px + pcx as i32);
            r[3] = r[3].min(py + pcy as i32);
            cur = parent;
        }
        r
    }

    fn window_mut(&mut self, hwnd: u32) -> Option<&mut Window> {
        self.windows.iter_mut().find(|(h, _)| *h == hwnd).map(|(_, w)| w)
    }

    fn window(&self, hwnd: u32) -> Option<&Window> {
        self.windows.iter().find(|(h, _)| *h == hwnd).map(|(_, w)| w)
    }

    fn dc(&self, hdc: u32) -> Option<&Dc> {
        self.dcs.iter().find(|(h, _)| *h == hdc).map(|(_, d)| d)
    }

    fn bitmap(&self, handle: u32) -> Option<Bitmap> {
        self.bitmaps.iter().find(|(h, _)| *h == handle).map(|(_, b)| *b)
    }

    fn font(&self, handle: u32) -> Option<LogFont> {
        let ty = handle >> 16;
        if ty != 0 && ty != gdi_type::FONT as u32 {
            return None;
        }
        let slot = handle & 0xFFFF;
        self.fonts.iter().find(|(s, _)| *s == slot).map(|(_, f)| *f)
    }

    fn dc_font(&self, hdc: u32) -> Option<LogFont> {
        let handle = self.dc(hdc).map(|d| d.font).unwrap_or(STOCK_SYSTEM_FONT);
        self.font(handle).or_else(|| self.font(STOCK_SYSTEM_FONT))
    }

    fn contains_point(&self, hwnd: u32, x: i32, y: i32) -> bool {
        let (ox, oy) = self.client_origin(hwnd);
        let Some(w) = self.window(hwnd) else { return false };
        let (cx, cy) = client_size(w);
        x >= ox && y >= oy && x < ox + cx as i32 && y < oy + cy as i32
    }

    fn window_from_point(&self, x: i32, y: i32, skip: &[u32]) -> u32 {
        let Some(top) = self.shown_window() else { return 0 };
        self.window_from_point_in(top, x, y, skip)
    }

    fn window_from_point_in(&self, root: u32, x: i32, y: i32, skip: &[u32]) -> u32 {
        if skip.contains(&root) || !self.contains_point(root, x, y) {
            return 0;
        }
        let mut cur = root;
        for _ in 0..WINDOW_ANCESTRY_MAX {
            let next = self
                .windows
                .iter()
                .rev()
                .find(|(h, w)| {
                    w.parent == cur
                        && w.shown
                        && !skip.contains(h)
                        && self.contains_point(*h, x, y)
                })
                .map(|(h, _)| *h);
            match next {
                Some(h) => cur = h,
                None => return cur,
            }
        }
        cur
    }

    fn child_window_from_point(&self, parent: u32, x: i32, y: i32) -> u32 {
        self.windows
            .iter()
            .rev()
            .find(|(h, w)| w.parent == parent && w.shown && self.contains_point(*h, x, y))
            .map(|(h, _)| *h)
            .unwrap_or(parent)
    }
}

pub(crate) fn register(os: &mut WinOs) {
    for idx in WIN32K_FIRST..=WIN32K_LAST {
        os.set_win32k_stub(idx, honest_stub);
    }
    os.set_win32k_handler(
        NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS,
        nt_user_initialize_client_pfn_arrays,
    );
    os.set_win32k_handler(NT_USER_GET_SYSTEM_DPI_FOR_PROCESS, nt_user_get_system_dpi_for_process);
    os.set_win32k_handler(
        NT_USER_SET_PROCESS_DPI_AWARENESS_CONTEXT,
        nt_user_set_process_dpi_awareness_context,
    );
    os.set_win32k_handler(
        NT_USER_GET_PROCESS_DPI_AWARENESS_CONTEXT,
        nt_user_get_process_dpi_awareness_context,
    );
    os.set_win32k_handler(NT_USER_GET_ATOM_NAME, nt_user_get_atom_name);
    os.set_win32k_handler(NT_USER_GET_CLASS_INFO_EX, nt_user_get_class_info_ex);
    os.set_win32k_handler(NT_USER_REGISTER_CLASS_EX_WOW, nt_user_register_class_ex_wow);
    os.set_win32k_handler(NT_USER_CREATE_WINDOW_EX, nt_user_create_window_ex);
    os.set_win32k_handler(NT_USER_SHOW_WINDOW, nt_user_show_window);
    os.set_win32k_handler(NT_USER_SHOW_WINDOW_ASYNC, nt_user_show_window);
    os.set_win32k_handler(NT_USER_DESTROY_WINDOW, nt_user_destroy_window);
    os.set_win32k_handler(NT_USER_SET_WINDOW_POS, nt_user_set_window_pos);
    os.set_win32k_handler(NT_USER_MESSAGE_CALL, nt_user_message_call);
    os.set_win32k_handler(NT_USER_INTERNAL_GET_WINDOW_TEXT, nt_user_internal_get_window_text);
    os.set_win32k_handler(NT_USER_GET_DC, nt_user_get_dc);
    os.set_win32k_handler(NT_USER_GET_DC_EX, nt_user_get_dc);
    os.set_win32k_handler(NT_USER_RELEASE_DC, nt_user_release_dc);
    os.set_win32k_handler(NT_USER_BEGIN_PAINT, nt_user_begin_paint);
    os.set_win32k_handler(NT_USER_END_PAINT, nt_user_end_paint);
    os.set_win32k_handler(NT_USER_GET_MESSAGE, nt_user_get_message);
    os.set_win32k_handler(NT_USER_PEEK_MESSAGE, nt_user_peek_message);
    os.set_win32k_handler(NT_USER_POST_QUIT_MESSAGE, nt_user_post_quit_message);
    os.set_win32k_handler(NT_USER_POST_MESSAGE, nt_user_post_message);
    os.set_win32k_handler(NT_USER_TRANSLATE_MESSAGE, nt_user_translate_message);
    os.set_win32k_handler(NT_USER_DISPATCH_MESSAGE, nt_user_dispatch_message);
    os.set_win32k_handler(NT_USER_GET_CURSOR, nt_user_get_cursor);
    os.set_win32k_handler(NT_USER_GET_CURSOR_POS, nt_user_get_cursor_pos);
    os.set_win32k_handler(NT_USER_SET_CURSOR, nt_user_set_cursor);
    os.set_win32k_handler(NT_USER_SET_CURSOR_POS, nt_user_set_cursor_pos);
    os.set_win32k_handler(NT_USER_CLIP_CURSOR, nt_user_clip_cursor);
    os.set_win32k_handler(NT_USER_CHANGE_DISPLAY_SETTINGS, nt_user_change_display_settings);
    os.set_win32k_handler(NT_USER_ENUM_DISPLAY_SETTINGS, nt_user_enum_display_settings);
    os.set_win32k_handler(
        NT_USER_MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX,
        nt_user_msg_wait_for_multiple_objects_ex,
    );
    os.set_win32k_handler(NT_USER_WINDOW_FROM_POINT, nt_user_window_from_point);
    os.set_win32k_handler(NT_USER_CHILD_WINDOW_FROM_POINT_EX, nt_user_child_window_from_point_ex);
    os.set_win32k_handler(NT_USER_SET_CAPTURE, nt_user_set_capture);
    os.set_win32k_handler(NT_USER_RELEASE_CAPTURE, nt_user_release_capture);
    os.set_win32k_handler(NT_USER_SET_FOCUS, nt_user_set_focus);
    os.set_win32k_handler(NT_USER_SET_ACTIVE_WINDOW, nt_user_set_active_window);
    os.set_win32k_handler(NT_USER_GET_THREAD_STATE, nt_user_get_thread_state);
    os.set_win32k_handler(NT_USER_GET_ANCESTOR, nt_user_get_ancestor);
    os.set_win32k_handler(NT_USER_CALL_HWND, nt_user_call_hwnd);
    os.set_win32k_handler(NT_USER_CALL_HWND_PARAM, nt_user_call_hwnd_param);
    os.set_win32k_handler(NT_USER_CALL_ONE_PARAM, nt_user_call_one_param);
    os.set_win32k_handler(NT_USER_CALL_TWO_PARAM, nt_user_call_two_param);
    os.set_win32k_handler(NT_USER_BUILD_HWND_LIST, nt_user_build_hwnd_list);
    os.set_win32k_handler(NT_USER_SET_WINDOW_LONG, nt_user_set_window_long);
    os.set_win32k_handler(NT_USER_SET_WINDOW_LONG_PTR, nt_user_set_window_long_ptr);
    os.set_win32k_handler(NT_GDI_EXT_TEXT_OUT_W, nt_gdi_ext_text_out_w);
    os.set_win32k_handler(NT_GDI_RECTANGLE, nt_gdi_rectangle);
    os.set_win32k_handler(NT_GDI_CREATE_SOLID_BRUSH, nt_gdi_create_solid_brush);
    os.set_win32k_handler(NT_GDI_CREATE_PEN, nt_gdi_create_pen);
    os.set_win32k_handler(NT_GDI_SELECT_BRUSH, nt_gdi_select_brush);
    os.set_win32k_handler(NT_GDI_SELECT_PEN, nt_gdi_select_pen);
    os.set_win32k_handler(NT_GDI_PAT_BLT, nt_gdi_pat_blt);
    os.set_win32k_handler(NT_GDI_GET_AND_SET_DC_DWORD, nt_gdi_get_and_set_dc_dword);
    os.set_win32k_handler(NT_GDI_SELECT_FONT, nt_gdi_select_font);
    os.set_win32k_handler(NT_GDI_CREATE_RECT_RGN, nt_gdi_create_rect_rgn);
    os.set_win32k_handler(NT_GDI_DELETE_OBJECT_APP, nt_gdi_delete_object_app);
    os.set_win32k_handler(NT_GDI_INTERSECT_CLIP_RECT, nt_gdi_intersect_clip_rect);
    os.set_win32k_handler(NT_GDI_GET_TEXT_METRICS_W, nt_gdi_get_text_metrics_w);
    os.set_win32k_handler(NT_GDI_GET_TEXT_EXTENT_EX_W, nt_gdi_get_text_extent_ex_w);
    os.set_win32k_handler(NT_USER_SET_PROP, nt_user_set_prop);
    os.set_win32k_handler(NT_USER_GET_PROP, nt_user_get_prop);
    os.set_win32k_handler(NT_USER_REMOVE_PROP, nt_user_remove_prop);
    os.set_win32k_handler(NT_GDI_GET_DEVICE_CAPS, nt_gdi_get_device_caps);
    os.set_win32k_handler(NT_GDI_CREATE_COMPATIBLE_DC, nt_gdi_create_compatible_dc);
    os.set_win32k_handler(NT_GDI_CREATE_BITMAP, nt_gdi_create_bitmap);
    os.set_win32k_handler(NT_GDI_CREATE_COMPATIBLE_BITMAP, nt_gdi_create_compatible_bitmap);
    os.set_win32k_handler(NT_GDI_SELECT_BITMAP, nt_gdi_select_bitmap);
    os.set_win32k_handler(NT_GDI_CREATE_DIB_SECTION, nt_gdi_create_dib_section);
    os.set_win32k_handler(NT_GDI_EXT_GET_OBJECT_W, nt_gdi_ext_get_object_w);
    os.set_win32k_handler(NT_GDI_HFONT_CREATE, nt_gdi_hfont_create);
    os.set_win32k_handler(NT_GDI_GET_DC_OBJECT, nt_gdi_get_dc_object);
    os.set_win32k_handler(NT_GDI_GET_FONT_DATA, nt_gdi_get_font_data);
    os.set_win32k_handler(NT_GDI_GET_TEXT_FACE_W, nt_gdi_get_text_face_w);
    os.set_win32k_handler(NT_USER_SET_CURSOR_ICON_DATA, nt_user_set_cursor_icon_data);
    os.set_win32k_handler(NT_USER_GET_ICON_INFO, nt_user_get_icon_info);
    os.set_win32k_handler(NT_USER_GET_ICON_SIZE, nt_user_get_icon_size);
    os.set_win32k_handler(NT_USER_FIND_EXISTING_CURSOR_ICON, nt_user_find_existing_cursor_icon);
    os.set_win32k_handler(NT_USER_DESTROY_CURSOR, nt_user_destroy_cursor);
}

fn alloc_handle(os: &mut WinOs) -> u32 {
    let h = os.next_handle;
    os.next_handle += 4;
    h as u32
}

fn read_unicode_string(mem: &dyn Memory, ptr: u64) -> Result<String> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let len_bytes = mem.read_u16(ptr)? as u64;
    let buffer = mem.read_u64(ptr + 8)?;
    if buffer == 0 {
        return Ok(String::new());
    }
    let n = (len_bytes / 2) as usize;
    if n == 0 {
        return read_wstr(mem, buffer);
    }
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(mem.read_u16(buffer + (i as u64) * 2)?);
    }
    Ok(String::from_utf16_lossy(&units))
}

fn honest_stub(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(0)
}

fn resolve_client_pfn(mem: &dyn Memory, entry: u64) -> Result<(u64, u64)> {
    if entry == 0 {
        return Ok((0, 0));
    }
    let mut op = [0u8; 3];
    for (i, b) in op.iter_mut().enumerate() {
        *b = mem.read_u8(entry + i as u64)?;
    }
    if op != PFN_THUNK_JMP {
        return Ok((entry, 0));
    }
    let disp = mem.read_u32(entry + 3)? as i32 as i64;
    let slot = (entry.wrapping_add(PFN_THUNK_LEN) as i64).wrapping_add(disp) as u64;
    Ok((mem.read_u64(slot)?, slot))
}

#[allow(clippy::type_complexity)]
fn read_client_pfn_array(
    mem: &dyn Memory,
    base: u64,
) -> Result<([u64; CLIENT_PFN_COUNT], [u64; CLIENT_PFN_COUNT])> {
    let mut procs = [0u64; CLIENT_PFN_COUNT];
    let mut slots = [0u64; CLIENT_PFN_COUNT];
    if base == 0 {
        return Ok((procs, slots));
    }
    for i in 0..CLIENT_PFN_COUNT {
        let (p, s) = resolve_client_pfn(mem, mem.read_u64(base + (i as u64) * 8)?)?;
        procs[i] = p;
        slots[i] = s;
    }
    Ok((procs, slots))
}

fn nt_user_initialize_client_pfn_arrays(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let procs_a = os.syscall_arg(cpu, mem, 0)?;
    let procs_w = os.syscall_arg(cpu, mem, 1)?;
    let user32 = os.syscall_arg(cpu, mem, 3)?;
    os.win32k_state.client_pfn_table = procs_a;
    os.win32k_state.user32_image = (user32, pe_image_size(mem, user32).unwrap_or(0));
    let (pfn_a, slots_a) = read_client_pfn_array(mem, procs_a).unwrap_or_default();
    let (pfn_w, slots_w) = read_client_pfn_array(mem, procs_w).unwrap_or_default();
    os.win32k_state.client_pfn_a = pfn_a;
    os.win32k_state.client_pfn_w = pfn_w;
    if let Some(ntdll) = os.module_base("ntdll.dll") {
        mirror_client_pfn_to_ntdll_copies(mem, ntdll, &[(&slots_a, &pfn_a), (&slots_w, &pfn_w)]);
    }
    register_builtin_classes(os);
    Ok(STATUS_SUCCESS)
}

fn mirror_client_pfn_to_ntdll_copies(
    mem: &mut dyn Memory,
    live: u64,
    arrays: &[(&[u64; CLIENT_PFN_COUNT], &[u64; CLIENT_PFN_COUNT])],
) {
    let Some(live_size) = pe_image_size(mem, live) else { return };
    for copy in ntdll_copies(mem, live, live_size) {
        for (slots, procs) in arrays {
            for (slot, proc) in slots.iter().zip(procs.iter()) {
                if *slot < live || *slot >= live + live_size || *proc == 0 {
                    continue;
                }
                let _ = mem.write_u64(copy + (slot - live), *proc);
            }
        }
    }
}

fn ntdll_copies(mem: &dyn Memory, live: u64, live_size: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut addr = 0u64;
    while let Some((base, size, _)) = mem.next_region(addr) {
        addr = base.saturating_add(size.max(1));
        if base == live || pe_image_size(mem, base) != Some(live_size) {
            continue;
        }
        if pe_export_name(mem, base).is_some_and(|n| n.eq_ignore_ascii_case("ntdll.dll")) {
            out.push(base);
        }
    }
    out
}

fn pe_export_name(mem: &dyn Memory, base: u64) -> Option<String> {
    if base == 0 || mem.read_u16(base).ok()? != 0x5A4D {
        return None;
    }
    let pe = base + mem.read_u32(base + 0x3C).ok()? as u64;
    if mem.read_u32(pe).ok()? != 0x0000_4550 {
        return None;
    }
    let export_rva = mem.read_u32(pe + 24 + 112).ok()? as u64;
    if export_rva == 0 {
        return None;
    }
    let name_rva = mem.read_u32(base + export_rva + 12).ok()? as u64;
    if name_rva == 0 {
        return None;
    }
    let mut s = String::new();
    for i in 0..64u64 {
        match mem.read_u8(base + name_rva + i).ok()? {
            0 => break,
            c => s.push(c as char),
        }
    }
    Some(s)
}

fn pe_image_size(mem: &dyn Memory, base: u64) -> Option<u64> {
    if base == 0 || mem.read_u16(base).ok()? != 0x5A4D {
        return None;
    }
    let pe = base + mem.read_u32(base + 0x3C).ok()? as u64;
    if mem.read_u32(pe).ok()? != 0x0000_4550 {
        return None;
    }
    Some(mem.read_u32(pe + 24 + 56).ok()? as u64)
}

fn register_builtin_classes(os: &mut WinOs) {
    let (u32_base, u32_size) = os.win32k_state.user32_image;
    for (name, index) in BUILTIN_CLASSES {
        let wndproc = os.win32k_state.client_pfn_w[index];
        let in_user32 = u32_size == 0 || (wndproc >= u32_base && wndproc < u32_base + u32_size);
        if wndproc == 0 || !in_user32 || os.win32k_state.class_by_name(name).is_some() {
            continue;
        }
        let atom = CLASS_ATOM_BASE.wrapping_add(os.win32k_state.classes.len() as u16);
        os.win32k_state.classes.push((
            atom,
            Class {
                name: name.to_string(),
                wndproc,
                style: BUILTIN_CLASS_STYLE,
                background: 0,
                wnd_extra: BUILTIN_WND_EXTRA,
                client: ClassClient::default(),
            },
        ));
    }
}

fn nt_user_get_system_dpi_for_process(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(os.cfg.dpi)
}

fn nt_user_set_process_dpi_awareness_context(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(1)
}

fn nt_user_get_process_dpi_awareness_context(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(crate::wow64::NTUSER_DPI_UNAWARE)
}

fn nt_user_get_atom_name(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let atom = os.syscall_arg(cpu, mem, 0)? as u16;
    let out = os.syscall_arg(cpu, mem, 1)?;
    if out == 0 {
        return Ok(0);
    }
    let name = match os.win32k_state.class_by_atom(atom) {
        Some(class) => class.name.clone(),
        None => format!("#{atom}"),
    };

    let max_bytes = mem.read_u16(out + 2)? as usize;
    let buffer = mem.read_u64(out + 8)?;
    if buffer == 0 {
        return Ok(0);
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let n = units.len().min(max_bytes.saturating_sub(2) / 2);
    for (i, unit) in units.iter().take(n).enumerate() {
        mem.write_u16(buffer + (i as u64) * 2, *unit)?;
    }
    mem.write_u16(buffer + (n as u64) * 2, 0)?;
    mem.write_u16(out, (n * 2) as u16)?;
    Ok(n as u32)
}

fn nt_user_get_class_info_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let name_ptr = os.syscall_arg(cpu, mem, 1)?;
    let wc = os.syscall_arg(cpu, mem, 2)?;
    let menu_name = os.syscall_arg(cpu, mem, 3)?;
    let ansi = os.syscall_arg_u32(cpu, mem, 4)? != 0;
    let name = read_unicode_string(mem, name_ptr)?;
    let Some(atom) = os.win32k_state.class_by_name(&name) else {
        return Ok(0);
    };
    let Some(class) = os.win32k_state.class_by_atom(atom) else {
        return Ok(0);
    };
    if wc != 0 {
        let class_name = if name_ptr != 0 { mem.read_u64(name_ptr + 8)? } else { 0 };
        let info = WndClassEx {
            style: class.style,
            wndproc: class.wndproc,
            cls_extra: class.client.cls_extra,
            wnd_extra: class.wnd_extra,
            instance: class.client.instance,
            icon: class.client.icon,
            cursor: class.client.cursor,
            background: class.background,
            menu_name: class.client.menu_name.for_charset(ansi),
            class_name,
            icon_sm: class.client.icon_sm,
        };
        info.write(mem, wc)?;
    }
    if menu_name != 0 {
        class.client.menu_name.write(mem, menu_name)?;
    }
    Ok(u32::from(atom))
}

fn nt_user_register_class_ex_wow(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let wc = os.syscall_arg(cpu, mem, 0)?;
    let name_ptr = os.syscall_arg(cpu, mem, 1)?;
    let menu_name_ptr = os.syscall_arg(cpu, mem, 3)?;
    let name = read_unicode_string(mem, name_ptr)?;

    let registered = if wc != 0 { WndClassEx::read(mem, wc)? } else { WndClassEx::default() };
    let client = ClassClient::registered(&registered, ClientMenuName::read(mem, menu_name_ptr)?);
    let (style, wndproc, background, wnd_extra) = (
        registered.style,
        registered.wndproc,
        registered.background,
        registered.wnd_extra.min(WND_EXTRA_MAX),
    );

    if let Some(existing) = os.win32k_state.class_by_name(&name) {
        return Ok(existing as u32);
    }

    let atom = CLASS_ATOM_BASE.wrapping_add(os.win32k_state.classes.len() as u16);
    os.win32k_state
        .classes
        .push((atom, Class { name, wndproc, style, background, wnd_extra, client }));
    Ok(atom as u32)
}

fn nt_user_create_window_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let ex_style = os.syscall_arg(cpu, mem, 0)? as u32;
    let class_ptr = os.syscall_arg(cpu, mem, 1)?;
    let window_name_ptr = os.syscall_arg(cpu, mem, 3)?;
    let style = os.syscall_arg(cpu, mem, 4)? as u32;
    let x = os.syscall_arg(cpu, mem, 5)? as i32;
    let y = os.syscall_arg(cpu, mem, 6)? as i32;
    let cx = os.syscall_arg(cpu, mem, 7)? as i32;
    let cy = os.syscall_arg(cpu, mem, 8)? as i32;
    let parent = os.syscall_arg(cpu, mem, 9)? as u32;
    let menu = os.syscall_arg(cpu, mem, 10)?;
    let instance = os.syscall_arg(cpu, mem, 11)?;
    let create_params = os.syscall_arg(cpu, mem, 12)?;

    let class_name = read_unicode_string(mem, class_ptr)?;
    let title = read_unicode_string(mem, window_name_ptr)?;

    let subst = |v: i32, def: i32| if v == CW_USEDEFAULT { def } else { v };
    let rect = [
        subst(x, DEFAULT_X),
        subst(y, DEFAULT_Y),
        subst(cx, DEFAULT_CX),
        subst(cy, DEFAULT_CY),
    ];

    let class_atom = os.win32k_state.class_by_name(&class_name).unwrap_or(0);
    let class = os.win32k_state.class_by_atom(class_atom);
    let wndproc = class.map(|c| c.wndproc).unwrap_or(0);
    let wnd_extra = class.map(|c| c.wnd_extra).unwrap_or(0) as usize;

    let hwnd = alloc_handle(os);
    os.win32k_state.windows.push((
        hwnd,
        Window {
            class_atom,
            class_name: class_name.clone(),
            title: title.clone(),
            rect,
            style,
            ex_style,
            parent,
            shown: style & WS_VISIBLE != 0,
            wndproc,
            needs_paint: style & WS_VISIBLE != 0,
            surface: None,
            extra: vec![0u8; wnd_extra],
            user_data: 0,
            id: if style & WS_CHILD != 0 { menu } else { 0 },
            instance,
            props: Vec::new(),
            dialog_info: 0,
            dialog_cancelled: false,
        },
    ));

    let params = WindowParams {
        class_atom,
        class_name: class_name.clone(),
        title: title.clone(),
        x: rect[0],
        y: rect[1],
        cx: rect[2],
        cy: rect[3],
        style,
        ex_style,
        parent,
    };
    os.driver.window_pos_changing(hwnd);
    os.driver.create_window(hwnd, &params);
    os.driver.window_pos_changed(hwnd, rect);

    dispatch_create_messages(
        os,
        cpu,
        mem,
        hwnd,
        &CreateInfo {
            create_params,
            instance,
            menu,
            parent,
            rect,
            style,
            ex_style,
            title: &title,
            class_name: &class_name,
        },
    )?;
    Ok(hwnd)
}

struct CreateInfo<'a> {
    create_params: u64,
    instance: u64,
    menu: u64,
    parent: u32,
    rect: [i32; 4],
    style: u32,
    ex_style: u32,
    title: &'a str,
    class_name: &'a str,
}

fn write_wstr_at(mem: &mut dyn Memory, at: u64, s: &str) -> Result<(u64, u64)> {
    if s.is_empty() {
        return Ok((0, 0));
    }
    let units: Vec<u16> = s.encode_utf16().take(CREATE_NAME_MAX).collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(at + (i as u64) * 2, *u)?;
    }
    mem.write_u16(at + (units.len() as u64) * 2, 0)?;
    Ok((at, (units.len() as u64 + 1) * 2))
}

fn dispatch_create_messages(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    hwnd: u32,
    info: &CreateInfo,
) -> Result<bool> {
    let wndproc = os.win32k_state.wndproc_for(hwnd);
    if wndproc == 0 {
        return Ok(false);
    }
    let wow64 = os.is_wow64();
    let (cs, reserve) = if wow64 {
        let Some(low) = os.wow64_callback_scratch(mem, CREATE_SCRATCH) else {
            return Ok(false);
        };
        (low, 0)
    } else {
        (os.syscall_guest_rsp.wrapping_sub(CREATE_SCRATCH) & !0xf, CREATE_SCRATCH)
    };
    let layout = if wow64 { &CS32 } else { &CS64 };
    let strings = cs + layout.size;
    let Ok((name_ptr, name_len)) = write_wstr_at(mem, strings, info.title) else {
        return Ok(false);
    };
    let (class_ptr, _) = write_wstr_at(mem, strings + name_len, info.class_name)?;

    let ptr = |mem: &mut dyn Memory, at: u64, v: u64| -> Result<()> {
        if wow64 {
            mem.write_u32(at, v as u32)
        } else {
            mem.write_u64(at, v)
        }
    };
    ptr(mem, cs + layout.lp_create_params, info.create_params)?;
    ptr(mem, cs + layout.hinstance, info.instance)?;
    ptr(mem, cs + layout.hmenu, info.menu)?;
    ptr(mem, cs + layout.hwnd_parent, info.parent as u64)?;
    mem.write_u32(cs + layout.cy, info.rect[3] as u32)?;
    mem.write_u32(cs + layout.cx, info.rect[2] as u32)?;
    mem.write_u32(cs + layout.y, info.rect[1] as u32)?;
    mem.write_u32(cs + layout.x, info.rect[0] as u32)?;
    mem.write_u32(cs + layout.style, info.style)?;
    ptr(mem, cs + layout.lpsz_name, name_ptr)?;
    ptr(mem, cs + layout.lpsz_class, class_ptr)?;
    mem.write_u32(cs + layout.dw_ex_style, info.ex_style)?;

    let hwnd = hwnd as u64;
    let calls = vec![
        (wndproc, vec![hwnd, WM_NCCREATE as u64, 0, cs]),
        (wndproc, vec![hwnd, crate::gdi::WM_CREATE, 0, cs]),
    ];
    os.call_wndprocs_from_syscall(cpu, mem, calls, Some(hwnd), reserve)
}

fn nt_user_show_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let cmd = os.syscall_arg(cpu, mem, 1)? as i32;
    let was_visible = match os.win32k_state.window_mut(hwnd) {
        Some(w) => {
            let prev = w.shown;
            w.shown = cmd != 0;
            if w.shown {
                w.needs_paint = true;
            }
            prev
        }
        None => false,
    };
    if cmd != 0 && os.win32k_state.surface_owner(hwnd) == hwnd {
        os.win32k_state.active = hwnd;
    }
    os.driver.show_window(hwnd, cmd);
    Ok(was_visible as u32)
}

fn nt_user_destroy_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(destroy_window(os, hwnd) as u32)
}

fn destroy_window(os: &mut WinOs, hwnd: u32) -> bool {
    let existed = os.win32k_state.windows.iter().any(|(h, _)| *h == hwnd);
    os.win32k_state.windows.retain(|(h, _)| *h != hwnd);
    if existed {
        let st = &mut os.win32k_state;
        for slot in [&mut st.capture, &mut st.focus, &mut st.active] {
            if *slot == hwnd {
                *slot = 0;
            }
        }
        os.driver.destroy_window(hwnd);
    }
    existed
}

fn nt_user_set_window_pos(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    const SWP_NOSIZE: u32 = 0x0001;
    const SWP_NOMOVE: u32 = 0x0002;
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let x = os.syscall_arg(cpu, mem, 2)? as i32;
    let y = os.syscall_arg(cpu, mem, 3)? as i32;
    let cx = os.syscall_arg(cpu, mem, 4)? as i32;
    let cy = os.syscall_arg(cpu, mem, 5)? as i32;
    let flags = os.syscall_arg(cpu, mem, 6)? as u32;

    let rect = match os.win32k_state.window_mut(hwnd) {
        Some(w) => {
            if flags & SWP_NOMOVE == 0 {
                w.rect[0] = x;
                w.rect[1] = y;
            }
            if flags & SWP_NOSIZE == 0 {
                w.rect[2] = cx;
                w.rect[3] = cy;
            }
            Some(w.rect)
        }
        None => None,
    };
    if let Some(rect) = rect {
        os.driver.window_pos_changing(hwnd);
        os.driver.window_pos_changed(hwnd, rect);
        Ok(1)
    } else {
        Ok(0)
    }
}

fn nt_user_message_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let msg = os.syscall_arg(cpu, mem, 1)? as u32;
    let wparam = os.syscall_arg(cpu, mem, 2)?;
    let lparam = os.syscall_arg(cpu, mem, 3)?;
    let result_info = os.syscall_arg(cpu, mem, 4)?;
    let call_type = os.syscall_arg(cpu, mem, 5)? as u32 as u64;
    let ansi = os.syscall_arg(cpu, mem, 6)? as u32 != 0;

    if message_call::KERNEL_WND_PROCS.contains(&call_type) {
        let r = def_window_proc(os, cpu, mem, hwnd, msg, wparam, lparam, ansi)?;
        os.return_u64_from_syscall(r);
        return Ok(0);
    }
    if message_call::SENDS.contains(&call_type) {
        if msg == WM_SETTEXT {
            let text = read_text_param(mem, lparam, ansi)?;
            if let Some(w) = os.win32k_state.window_mut(hwnd) {
                w.title = text.clone();
            }
            os.driver.set_window_text(hwnd, &text);
            return Ok(1);
        }
        return dispatch_to_wndproc(os, cpu, mem, hwnd as u64, msg, wparam, lparam, None);
    }

    match call_type {
        message_call::DISPATCH_MESSAGE => {
            dispatch_to_wndproc(os, cpu, mem, hwnd as u64, msg, wparam, lparam, Some(0))
        }
        message_call::SPY_GET_MSG_NAME => {
            let size = wparam.min(32) as usize;
            if result_info != 0 && size > 1 {
                let name = format!("{msg:#06x}");
                let bytes = &name.as_bytes()[..name.len().min(size - 1)];
                mem.write(result_info, bytes)?;
                mem.write_u8(result_info + bytes.len() as u64, 0)?;
            }
            Ok(0)
        }
        message_call::CALL_WINDOW_PROC => {
            let proc = if result_info != 0 {
                mem.read_u64(result_info + WIN_PROC_PARAMS_FUNC)?
            } else {
                0
            };
            if proc == 0 {
                return Ok(0);
            }
            let m = crate::msg::PostedMsg { hwnd: hwnd as u64, message: msg, wparam, lparam };
            os.call_wndprocs_from_syscall(cpu, mem, vec![(proc, m.into_args())], Some(0), 0)?;
            Ok(0)
        }
        _ => Ok(0),
    }
}

fn read_text_param(mem: &dyn Memory, ptr: u64, ansi: bool) -> Result<String> {
    if ptr == 0 {
        return Ok(String::new());
    }
    if ansi {
        crate::api::read_astr(mem, ptr)
    } else {
        read_wstr(mem, ptr)
    }
}

#[allow(clippy::too_many_arguments)]
fn def_window_proc(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    hwnd: u32,
    msg: u32,
    wparam: u64,
    lparam: u64,
    ansi: bool,
) -> Result<u64> {
    match msg {
        WM_NCHITTEST => {
            let (x, y) = (lo_word_i32(lparam), hi_word_i32(lparam));
            Ok(if os.win32k_state.contains_point(hwnd, x, y) {
                hit::CLIENT as u64
            } else {
                hit::NOWHERE as u64
            })
        }
        WM_NCCREATE => Ok(1),
        WM_SETTEXT => {
            let text = read_text_param(mem, lparam, ansi)?;
            if let Some(w) = os.win32k_state.window_mut(hwnd) {
                w.title = text.clone();
            }
            os.driver.set_window_text(hwnd, &text);
            Ok(1)
        }
        WM_GETTEXTLENGTH => {
            Ok(os.win32k_state.window(hwnd).map(|w| w.title.chars().count() as u64).unwrap_or(0))
        }
        WM_GETTEXT => {
            let max = wparam as usize;
            if lparam == 0 || max == 0 {
                return Ok(0);
            }
            let title = os.win32k_state.window(hwnd).map(|w| w.title.clone()).unwrap_or_default();
            let units: Vec<u16> = title.encode_utf16().take(max.saturating_sub(1)).collect();
            for (i, u) in units.iter().enumerate() {
                mem.write_u16(lparam + (i as u64) * 2, *u)?;
            }
            mem.write_u16(lparam + (units.len() as u64) * 2, 0)?;
            Ok(units.len() as u64)
        }
        WM_MOUSEACTIVATE => Ok(1),
        WM_SETCURSOR => Ok(1),
        WM_NCCALCSIZE => Ok(0),
        WM_ERASEBKGND => erase_background(os, mem, hwnd),
        WM_CLOSE => {
            destroy_window(os, hwnd);
            Ok(0)
        }
        WM_SETFOCUS | WM_KILLFOCUS | WM_CAPTURECHANGED | WM_NCDESTROY => Ok(0),
        _ => {
            let _ = cpu;
            Ok(0)
        }
    }
}

fn erase_background(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<u64> {
    let atom = os.win32k_state.window(hwnd).map(|w| w.class_atom).unwrap_or(0);
    let brush = os.win32k_state.class_by_atom(atom).map(|c| c.background).unwrap_or(0);
    if brush == 0 {
        return Ok(0);
    }
    let color = match os.win32k_state.brushes.iter().find(|(h, _)| *h as u64 == brush) {
        Some((_, c)) => *c,
        None if brush <= 0x20 => sys_color(brush as u32 - 1),
        None => return Ok(0),
    };
    let rect = os.win32k_state.window_visible_rect(hwnd);
    let Some(surface) = os
        .win32k_state
        .window(os.win32k_state.surface_owner(hwnd))
        .and_then(|w| w.surface)
    else {
        return Ok(0);
    };
    let target = DcTarget { surface, org: (0, 0), clip: rect };
    fill_rect(
        mem,
        &target,
        rect[0],
        rect[1],
        rect[2] - rect[0],
        rect[3] - rect[1],
        colorref_to_bgra(color),
    )?;
    Ok(1)
}

fn lo_word_i32(v: u64) -> i32 {
    (v & 0xffff) as u16 as i16 as i32
}
fn hi_word_i32(v: u64) -> i32 {
    ((v >> 16) & 0xffff) as u16 as i16 as i32
}

fn sys_color(index: u32) -> u32 {
    const COLOR_WINDOW: u32 = 5;
    const COLOR_WINDOWFRAME: u32 = 6;
    const COLOR_WINDOWTEXT: u32 = 8;
    const COLOR_BTNSHADOW: u32 = 16;
    const COLOR_GRAYTEXT: u32 = 17;
    const COLOR_BTNTEXT: u32 = 18;
    const COLOR_BTNHIGHLIGHT: u32 = 20;
    const COLOR_3DDKSHADOW: u32 = 21;
    const COLOR_3DLIGHT: u32 = 22;
    const COLOR_HIGHLIGHT: u32 = 13;
    const COLOR_HIGHLIGHTTEXT: u32 = 14;
    const GREY: u32 = 0x00C0_C0C0;
    match index {
        COLOR_WINDOW | COLOR_BTNHIGHLIGHT => 0x00FF_FFFF,
        COLOR_WINDOWFRAME | COLOR_WINDOWTEXT | COLOR_BTNTEXT | COLOR_3DDKSHADOW => 0x0000_0000,
        COLOR_BTNSHADOW | COLOR_GRAYTEXT => 0x0080_8080,
        COLOR_3DLIGHT => 0x00E0_E0E0,
        COLOR_HIGHLIGHT => 0x0080_0000,
        COLOR_HIGHLIGHTTEXT => 0x00FF_FFFF,
        _ => GREY,
    }
}

fn system_metric(index: u32) -> u32 {
    const SM_CXSCREEN: u32 = 0;
    const SM_CYSCREEN: u32 = 1;
    const SM_CXBORDER: u32 = 5;
    const SM_CYBORDER: u32 = 6;
    const SM_CXICON: u32 = 11;
    const SM_CYICON: u32 = 12;
    const SM_CXCURSOR: u32 = 13;
    const SM_CYCURSOR: u32 = 14;
    const SM_CXEDGE: u32 = 45;
    const SM_CYEDGE: u32 = 46;
    const SM_CXSMICON: u32 = 49;
    const SM_CYSMICON: u32 = 50;
    match index {
        SM_CXSCREEN => 1920,
        SM_CYSCREEN => 1080,
        SM_CXBORDER | SM_CYBORDER => 1,
        SM_CXICON | SM_CYICON | SM_CXCURSOR | SM_CYCURSOR => 32,
        SM_CXEDGE | SM_CYEDGE => 2,
        SM_CXSMICON | SM_CYSMICON => 16,
        _ => 0,
    }
}

fn nt_user_call_hwnd(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let code = os.syscall_arg(cpu, mem, 1)?;
    let st = &os.win32k_state;
    Ok(match code {
        call_hwnd::IS_WINDOW => st.window(hwnd).is_some() as u32,
        call_hwnd::IS_WINDOW_ENABLED => st.window(hwnd).is_some() as u32,
        call_hwnd::IS_WINDOW_UNICODE => st.window(hwnd).is_some() as u32,
        call_hwnd::IS_WINDOW_VISIBLE => st.chain_visible(hwnd) as u32,
        call_hwnd::GET_PARENT => st.window(hwnd).map(|w| w.parent).unwrap_or(0),
        call_hwnd::GET_DPI_FOR_WINDOW => os.cfg.dpi,
        call_hwnd::IS_SELF_THREAD => st.window(hwnd).map(|_| hwnd).unwrap_or(0),
        call_hwnd::GET_FULL_WINDOW_HANDLE => st.window(hwnd).map(|_| hwnd).unwrap_or(0),
        call_hwnd::GET_DIALOG_INFO => {
            let info = st.window(hwnd).map(|w| w.dialog_info).unwrap_or(0);
            os.return_u64_from_syscall(info);
            return Ok(0);
        }
        _ => 0,
    })
}

fn edit_within(st: &Win32kState, root: u32) -> Option<u32> {
    let mut frontier = vec![root];
    for _ in 0..WINDOW_ANCESTRY_MAX {
        let mut next = Vec::new();
        for (h, w) in &st.windows {
            if !frontier.contains(&w.parent) {
                continue;
            }
            if w.class_name.eq_ignore_ascii_case("Edit") {
                return Some(*h);
            }
            next.push(*h);
        }
        if next.is_empty() {
            return None;
        }
        frontier = next;
    }
    None
}

fn drive_file_dialog(os: &mut WinOs, mem: &mut dyn Memory) -> bool {
    let Some(pick) = os.cfg.file_dialog_pick.clone() else { return false };
    let st = &os.win32k_state;
    let Some((hwnd, target)) = st
        .windows
        .iter()
        .filter(|(h, w)| w.class_name == DIALOG_CLASS && !st.driven_dialogs.contains(h))
        .find_map(|(h, _)| {
            let combo = st
                .windows
                .iter()
                .find(|(_, w)| w.parent == *h && w.id == IDC_FILENAME_COMBO)
                .map(|(c, _)| *c)?;
            Some((*h, edit_within(st, combo).unwrap_or(combo)))
        })
    else {
        return false;
    };

    if os.win32k_state.pick_text == 0 {
        let bytes: Vec<u8> =
            pick.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();
        let Some(base) = os.map_anywhere(mem, bytes.len() as u64, Perm::RW, "dialog-pick") else {
            return false;
        };
        if mem.write(base, &bytes).is_err() {
            return false;
        }
        os.win32k_state.pick_text = base;
    }

    os.win32k_state.driven_dialogs.push(hwnd);
    let text = os.win32k_state.pick_text;
    os.post_internal(target as u64, WM_SETTEXT, 0, text);
    os.post_internal(hwnd as u64, WM_COMMAND, IDOK, 0);
    true
}

fn window_relative(st: &Win32kState, hwnd: u32, rel: u64) -> u32 {
    let Some(w) = st.window(hwnd) else { return 0 };
    let (parent, style) = (w.parent, w.style);
    if rel == window_relative::CHILD {
        return st.windows.iter().find(|(_, c)| c.parent == hwnd).map(|(h, _)| *h).unwrap_or(0);
    }
    if rel == window_relative::OWNER {
        return if style & WS_CHILD == 0 { parent } else { 0 };
    }
    let siblings: Vec<u32> =
        st.windows.iter().filter(|(_, c)| c.parent == parent).map(|(h, _)| *h).collect();
    let at = siblings.iter().position(|h| *h == hwnd);
    match rel {
        window_relative::HWND_FIRST => siblings.first().copied().unwrap_or(0),
        window_relative::HWND_LAST => siblings.last().copied().unwrap_or(0),
        window_relative::HWND_NEXT => at.and_then(|i| siblings.get(i + 1)).copied().unwrap_or(0),
        window_relative::HWND_PREV => {
            at.filter(|i| *i > 0).and_then(|i| siblings.get(i - 1)).copied().unwrap_or(0)
        }
        _ => 0,
    }
}

fn collect_descendants(st: &Win32kState, root: u32, depth: usize, out: &mut Vec<u32>) {
    if depth >= WINDOW_ANCESTRY_MAX {
        return;
    }
    let kids: Vec<u32> =
        st.windows.iter().filter(|(_, w)| w.parent == root).map(|(h, _)| *h).collect();
    for k in kids {
        if out.len() >= HWND_LIST_MAX {
            return;
        }
        out.push(k);
        collect_descendants(st, k, depth + 1, out);
    }
}

fn hwnd_list(st: &Win32kState, hwnd: u32, descendants: bool) -> Vec<u32> {
    if descendants {
        let mut out = Vec::new();
        collect_descendants(st, hwnd, 0, &mut out);
        return out;
    }
    if hwnd == 0 {
        return st.windows.iter().filter(|(_, w)| w.parent == 0).map(|(h, _)| *h).collect();
    }
    let Some(parent) = st.window(hwnd).map(|w| w.parent) else { return Vec::new() };
    st.windows
        .iter()
        .skip_while(|(h, _)| *h != hwnd)
        .filter(|(_, w)| w.parent == parent)
        .map(|(h, _)| *h)
        .take(HWND_LIST_MAX)
        .collect()
}

fn nt_user_build_hwnd_list(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg_u32(cpu, mem, 1)?;
    let descendants = os.syscall_arg_u32(cpu, mem, 2)? != 0;
    let count = os.syscall_arg_u32(cpu, mem, 5)? as usize;
    let buffer = os.syscall_arg(cpu, mem, 6)?;
    let size_out = os.syscall_arg(cpu, mem, 7)?;
    let list = hwnd_list(&os.win32k_state, hwnd, descendants);
    if size_out != 0 {
        mem.write_u32(size_out, (list.len() + 1) as u32)?;
    }
    if buffer == 0 || list.len() + 1 > count {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    for (i, h) in list.iter().enumerate() {
        mem.write_u64(buffer + (i as u64) * 8, *h as u64)?;
    }
    Ok(0)
}

fn winproc_slot(value: u64) -> Option<usize> {
    if value & !WINPROC_HANDLE_MASK != WINPROC_HANDLE_TAG {
        return None;
    }
    Some((value & WINPROC_HANDLE_MASK) as usize)
}

fn alloc_win_proc(st: &mut Win32kState, func: u64, ansi: bool) -> u64 {
    if func == 0 || winproc_slot(func).is_some() {
        return func;
    }
    let existing = st
        .win_procs
        .iter()
        .position(|p| if ansi { p.proc_a == func } else { p.proc_w == func });
    if let Some(slot) = existing {
        return WINPROC_HANDLE_TAG | slot as u64;
    }
    if st.win_procs.len() >= WINPROC_MAX {
        return func;
    }
    let entry = if ansi {
        WinProc { proc_a: func, proc_w: 0 }
    } else {
        WinProc { proc_a: 0, proc_w: func }
    };
    st.win_procs.push(entry);
    WINPROC_HANDLE_TAG | (st.win_procs.len() - 1) as u64
}

fn get_dialog_proc(st: &Win32kState, value: u64, ansi: bool) -> u64 {
    let Some(slot) = winproc_slot(value) else { return value };
    st.win_procs.get(slot).map(|p| if ansi { p.proc_a } else { p.proc_w }).unwrap_or(0)
}

fn nt_user_call_two_param(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let a = os.syscall_arg(cpu, mem, 0)?;
    let b = os.syscall_arg(cpu, mem, 1)?;
    let code = os.syscall_arg(cpu, mem, 2)?;
    match code {
        call_two_param::GET_DIALOG_PROC => {
            let proc = get_dialog_proc(&os.win32k_state, a, b != 0);
            os.return_u64_from_syscall(proc);
            Ok(0)
        }
        call_two_param::ALLOC_WIN_PROC => {
            let handle = alloc_win_proc(&mut os.win32k_state, a, b != 0);
            os.return_u64_from_syscall(handle);
            Ok(0)
        }
        _ => Ok(0),
    }
}

fn nt_user_call_hwnd_param(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let param = os.syscall_arg(cpu, mem, 1)?;
    let code = os.syscall_arg(cpu, mem, 2)?;
    match code {
        call_hwnd_param::GET_WINDOW_LONG
        | call_hwnd_param::GET_WINDOW_LONG_PTR_A
        | call_hwnd_param::GET_WINDOW_LONG_PTR_W => {
            let value = get_window_long(os, hwnd, param as i64);
            os.return_u64_from_syscall(value);
            Ok(0)
        }
        call_hwnd_param::GET_WINDOW_RECT | call_hwnd_param::GET_CLIENT_RECT => {
            let Some(w) = os.win32k_state.window(hwnd) else { return Ok(0) };
            let (cx, cy) = client_size(w);
            let rect = if code == call_hwnd_param::GET_CLIENT_RECT {
                [0, 0, cx as i32, cy as i32]
            } else {
                let owner = os.win32k_state.surface_owner(hwnd);
                let (ox, oy) = os.win32k_state.client_origin(hwnd);
                let screen = os.win32k_state.window(owner).map(|w| (w.rect[0], w.rect[1])).unwrap_or((0, 0));
                let (x, y) = (screen.0 + ox, screen.1 + oy);
                [x, y, x + cx as i32, y + cy as i32]
            };
            let out = mem.read_u64(param + CALL_RECT_PARAM_RECT)?;
            if out == 0 {
                return Ok(0);
            }
            for (i, v) in rect.iter().enumerate() {
                mem.write_u32(out + (i as u64) * 4, *v as u32)?;
            }
            Ok(1)
        }
        call_hwnd_param::GET_WINDOW_RELATIVE => {
            Ok(window_relative(&os.win32k_state, hwnd, param))
        }
        call_hwnd_param::SET_DIALOG_INFO => {
            let Some(w) = os.win32k_state.window_mut(hwnd) else { return Ok(0) };
            w.dialog_info = param;
            Ok(1)
        }
        call_hwnd_param::IS_CHILD => {
            let child = param as u32;
            if os.win32k_state.window(hwnd).is_none() {
                return Ok(0);
            }
            let mut cur = os.win32k_state.window(child).map(|w| w.parent).unwrap_or(0);
            for _ in 0..WINDOW_ANCESTRY_MAX {
                if cur == 0 {
                    return Ok(0);
                }
                if cur == hwnd {
                    return Ok(1);
                }
                cur = os.win32k_state.window(cur).map(|w| w.parent).unwrap_or(0);
            }
            Ok(0)
        }
        _ => Ok(0),
    }
}

fn nt_user_call_one_param(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let arg = os.syscall_arg(cpu, mem, 0)?;
    let code = os.syscall_arg(cpu, mem, 1)?;
    match code {
        call_one_param::CREATE_CURSOR_ICON => Ok(create_cursor_icon(os, arg != 0)),
        call_one_param::GET_SYS_COLOR => Ok(sys_color(arg as u32)),
        call_one_param::GET_SYS_COLOR_BRUSH => {
            let h = sys_color_brush(os, mem, arg as u32)?;
            Ok(h)
        }
        call_one_param::GET_SYSTEM_METRICS => Ok(system_metric(arg as u32)),
        _ => Ok(0),
    }
}

fn get_window_long(os: &WinOs, hwnd: u32, offset: i64) -> u64 {
    let Some(w) = os.win32k_state.window(hwnd) else { return 0 };
    match offset {
        GWL_STYLE => w.style as u64,
        GWL_EXSTYLE => w.ex_style as u64,
        GWLP_WNDPROC => w.wndproc,
        GWLP_HINSTANCE => w.instance,
        GWLP_HWNDPARENT => w.parent as u64,
        GWLP_USERDATA => w.user_data,
        GWLP_ID => w.id,
        off if off >= 0 => {
            let off = off as usize;
            if off + 8 > w.extra.len() {
                return 0;
            }
            u64::from_le_bytes(w.extra[off..off + 8].try_into().unwrap_or([0; 8]))
        }
        _ => 0,
    }
}

fn set_window_long(os: &mut WinOs, hwnd: u32, offset: i64, value: u64) -> u64 {
    let previous = get_window_long(os, hwnd, offset);
    let Some(w) = os.win32k_state.window_mut(hwnd) else { return 0 };
    match offset {
        GWL_STYLE => w.style = value as u32,
        GWL_EXSTYLE => w.ex_style = value as u32,
        GWLP_WNDPROC => w.wndproc = value,
        GWLP_HINSTANCE => w.instance = value,
        GWLP_USERDATA => w.user_data = value,
        GWLP_ID => w.id = value,
        off if off >= 0 => {
            let off = off as usize;
            if off + 8 <= w.extra.len() {
                w.extra[off..off + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        _ => {}
    }
    previous
}

fn nt_user_set_window_long(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let offset = os.syscall_arg(cpu, mem, 1)? as i32 as i64;
    let value = os.syscall_arg(cpu, mem, 2)? as u32 as u64;
    let previous = set_window_long(os, hwnd, offset, value);
    Ok(previous as u32)
}

fn nt_user_set_window_long_ptr(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let offset = os.syscall_arg(cpu, mem, 1)? as i32 as i64;
    let value = os.syscall_arg(cpu, mem, 2)?;
    let previous = set_window_long(os, hwnd, offset, value);
    os.return_u64_from_syscall(previous);
    Ok(0)
}

fn nt_user_internal_get_window_text(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let buffer = os.syscall_arg(cpu, mem, 1)?;
    let max = os.syscall_arg(cpu, mem, 2)? as usize;
    let title = os
        .win32k_state
        .window_mut(hwnd)
        .map(|w| w.title.clone())
        .unwrap_or_default();
    if buffer == 0 || max == 0 {
        return Ok(0);
    }
    let units: Vec<u16> = title.encode_utf16().collect();
    let n = units.len().min(max - 1);
    for (i, u) in units.iter().take(n).enumerate() {
        mem.write_u16(buffer + (i as u64) * 2, *u)?;
    }
    mem.write_u16(buffer + (n as u64) * 2, 0)?;
    Ok(n as u32)
}

fn client_size(w: &Window) -> (u32, u32) {
    let cx = w.rect[2].max(1) as u32;
    let cy = w.rect[3].max(1) as u32;
    (cx, cy)
}

fn ensure_gdi_table(os: &mut WinOs, mem: &mut dyn Memory) -> bool {
    if os.win32k_state.gdi_table_base != 0 {
        return true;
    }
    let peb = os.cfg.peb_addr;
    if peb == 0 {
        return false;
    }
    let peb32 = os.wow64_peb32();
    let table_size = GDI_TABLE_SLOTS * GDI_ENTRY_SIZE;
    let Some(table) = map_gdi_arena(os, mem, table_size, "gdi-handle-table", peb32 != 0) else {
        return false;
    };
    let arena_size = GDI_TABLE_SLOTS * GDI_DC_OBJECT_SIZE;
    let Some(arena) = map_gdi_arena(os, mem, arena_size, "gdi-dc-arena", peb32 != 0) else {
        return false;
    };
    if mem.write_u64(peb + GDI_PEB_TABLE_PTR_OFF, table).is_err() {
        return false;
    }
    if peb32 != 0 && mem.write_u32(peb32 + GDI_PEB32_TABLE_PTR_OFF, table as u32).is_err() {
        return false;
    }
    os.win32k_state.gdi_table_base = table;
    os.win32k_state.gdi_dc_arena = arena;
    os.win32k_state.gdi_next_slot = STOCK_SLOT_LAST + 1;
    publish_stock_objects(os, mem).is_ok()
}

fn map_gdi_arena(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    size: u64,
    name: &str,
    below_4g: bool,
) -> Option<u64> {
    if below_4g {
        if let Some(base) = os.map_anywhere_low(mem, size, Perm::RW, name) {
            return Some(base);
        }
    }
    os.map_anywhere(mem, size, Perm::RW, name)
}

fn publish_stock_objects(os: &mut WinOs, mem: &mut dyn Memory) -> Result<()> {
    let (table, arena) = (os.win32k_state.gdi_table_base, os.win32k_state.gdi_dc_arena);
    for (slot, ty, color) in STOCK_OBJECTS {
        debug_assert!((STOCK_SLOT_BASE..=STOCK_SLOT_LAST).contains(&slot));
        let entry = table + slot * GDI_ENTRY_SIZE;
        mem.write_u16(entry + GDI_ENTRY_GENERATION_OFF, ty)?;
        mem.write_u8(entry + GDI_ENTRY_TYPE_OFF, GDI_ENTRY_IN_USE)?;
        mem.write_u64(entry + GDI_ENTRY_OBJECT_OFF, arena + slot * GDI_DC_OBJECT_SIZE)?;
        if let Some(color) = color {
            let handle = ((ty as u32) << 16) | (slot as u32);
            os.win32k_state.brushes.push((handle, color));
        }
        if ty == gdi_type::FONT {
            let named = STOCK_FONTS.iter().find(|(s, ..)| *s == slot as u32);
            let (_, height, weight, pitch, face) =
                named.copied().unwrap_or((0, 16, FW_NORMAL, VARIABLE_PITCH_SWISS, "System"));
            os.win32k_state
                .fonts
                .push((slot as u32, LogFont::stock(height, weight, pitch, face)));
        }
    }
    Ok(())
}

fn alloc_dc(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<u32> {
    let (hdc, obj) = match alloc_gdi_object(os, mem, gdi_type::DC)? {
        Some(v) => v,
        None => return Ok(0),
    };
    let org = os.win32k_state.client_origin(hwnd);
    let clip = os.win32k_state.window_visible_rect(hwnd);
    mem.write_u32(obj + DC_ATTR_ORG_X, org.0 as u32)?;
    mem.write_u32(obj + DC_ATTR_ORG_Y, org.1 as u32)?;
    os.win32k_state.dcs.push((hdc, Dc { hwnd, brush: 0, org, clip, bitmap: 0, font: STOCK_SYSTEM_FONT }));
    Ok(hdc)
}

fn alloc_gdi_object(os: &mut WinOs, mem: &mut dyn Memory, ty: u16) -> Result<Option<(u32, u64)>> {
    if !ensure_gdi_table(os, mem) {
        return Ok(None);
    }
    let slot = match os.win32k_state.gdi_free_slots.pop() {
        Some(slot) => slot,
        None => {
            let slot = os.win32k_state.gdi_next_slot;
            if slot >= GDI_TABLE_SLOTS {
                return Ok(None);
            }
            os.win32k_state.gdi_next_slot += 1;
            slot
        }
    };

    let entry = os.win32k_state.gdi_table_base + slot * GDI_ENTRY_SIZE;
    let obj = os.win32k_state.gdi_dc_arena + slot * GDI_DC_OBJECT_SIZE;
    for off in (0..GDI_DC_OBJECT_SIZE).step_by(8) {
        mem.write_u64(obj + off, 0)?;
    }
    mem.write_u16(entry + GDI_ENTRY_GENERATION_OFF, ty)?;
    mem.write_u8(entry + GDI_ENTRY_TYPE_OFF, GDI_ENTRY_IN_USE)?;
    mem.write_u64(entry + GDI_ENTRY_OBJECT_OFF, obj)?;
    Ok(Some((((ty as u32) << 16) | (slot as u32 & 0xFFFF), obj)))
}

fn alloc_brush(os: &mut WinOs, mem: &mut dyn Memory, color: u32) -> Result<u32> {
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::BRUSH)? else {
        return Ok(0);
    };
    os.win32k_state.brushes.push((handle, color));
    Ok(handle)
}

fn sys_color_brush(os: &mut WinOs, mem: &mut dyn Memory, index: u32) -> Result<u32> {
    if let Some((_, h)) = os.win32k_state.sys_brushes.iter().find(|(i, _)| *i == index) {
        return Ok(*h);
    }
    let handle = alloc_brush(os, mem, sys_color(index))?;
    if handle != 0 {
        os.win32k_state.sys_brushes.push((index, handle));
    }
    Ok(handle)
}

fn ensure_surface(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Option<Surface> {
    let owner = os.win32k_state.surface_owner(hwnd);
    let w = os.win32k_state.window(owner)?;
    if let Some(s) = w.surface {
        return Some(s);
    }
    let (cx, cy) = client_size(w);
    let bytes = (cx as u64) * (cy as u64) * 4;
    let base = os.map_anywhere(mem, bytes, Perm::RW, "window-surface")?;
    for off in (0..bytes).step_by(4) {
        mem.write_u32(base + off, 0xFFFF_FFFF).ok()?;
    }
    let surface = Surface { base, w: cx, h: cy };
    if let Some(w) = os.win32k_state.window_mut(owner) {
        w.surface = Some(surface);
    }
    os.driver.create_window_surface(owner, cx, cy);
    Some(surface)
}

fn present_surface(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<()> {
    let hwnd = os.win32k_state.surface_owner(hwnd);
    let Some(surface) = os.win32k_state.window(hwnd).and_then(|w| w.surface) else {
        return Ok(());
    };
    let len = (surface.w as usize) * (surface.h as usize) * 4;
    let mut pixels = vec![0u8; len];
    for (i, b) in pixels.iter_mut().enumerate() {
        *b = mem.read_u8(surface.base + i as u64)?;
    }
    os.driver.flush_surface(hwnd, &pixels, surface.w, surface.h);
    Ok(())
}

fn nt_user_get_dc(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd_arg = os.syscall_arg(cpu, mem, 0)? as u32;
    let hwnd = resolve_dc_hwnd(os, hwnd_arg);
    if hwnd == 0 {
        return Ok(0);
    }
    if ensure_surface(os, mem, hwnd).is_none() {
        return Ok(0);
    }
    alloc_dc(os, mem, hwnd)
}

fn resolve_dc_hwnd(os: &WinOs, hwnd_arg: u32) -> u32 {
    if hwnd_arg != 0 && os.win32k_state.window(hwnd_arg).is_some() {
        return hwnd_arg;
    }
    os.win32k_state
        .windows
        .iter()
        .map(|(h, _)| *h)
        .find(|h| os.win32k_state.surface_owner(*h) == *h)
        .unwrap_or(0)
}

fn nt_user_release_dc(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 1)? as u32;
    if let Some(hwnd) = os.win32k_state.dc(hdc).map(|d| d.hwnd) {
        present_surface(os, mem, hwnd)?;
    }
    free_gdi_object(os, mem, hdc)?;
    Ok(1)
}

fn nt_user_begin_paint(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let ps = os.syscall_arg(cpu, mem, 1)?;
    if os.win32k_state.window(hwnd).is_none() {
        return Ok(0);
    }
    if ensure_surface(os, mem, hwnd).is_none() {
        return Ok(0);
    }
    let hdc = alloc_dc(os, mem, hwnd)?;
    if ps != 0 {
        mem.write_u64(ps, hdc as u64)?;
        mem.write_u32(ps + 8, 0)?;
        let (cx, cy) = os.win32k_state.window(hwnd).map(client_size).unwrap_or((0, 0));
        mem.write_u32(ps + 0xC, 0)?;
        mem.write_u32(ps + 0x10, 0)?;
        mem.write_u32(ps + 0x14, cx)?;
        mem.write_u32(ps + 0x18, cy)?;
    }
    Ok(hdc)
}

fn nt_user_end_paint(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let ps = os.syscall_arg(cpu, mem, 1)?;
    if os.win32k_state.window(hwnd).is_some() {
        present_surface(os, mem, hwnd)?;
    }
    if ps != 0 {
        let hdc = mem.read_u64(ps)? as u32;
        free_gdi_object(os, mem, hdc)?;
    }
    Ok(1)
}

fn quit_when_headless(os: &mut WinOs) {
    if !os.has_input() {
        os.threads[os.current].quit_code.get_or_insert(0);
    }
}

fn cancel_unattended_dialog(os: &mut WinOs) {
    let t = &os.threads[os.current];
    if t.quit_code.is_none() || !t.msgs.is_empty() {
        return;
    }
    if !os.win32k_state.raw_input.is_empty() {
        return;
    }
    fn dialog(st: &Win32kState, asked: bool) -> Option<u32> {
        st.windows
            .iter()
            .rev()
            .find(|(_, w)| w.dialog_info != 0 && w.dialog_cancelled == asked)
            .map(|(h, _)| *h)
    }
    if let Some(hwnd) = dialog(&os.win32k_state, false) {
        if let Some(w) = os.win32k_state.window_mut(hwnd) {
            w.dialog_cancelled = true;
        }
        os.post_internal(hwnd as u64, WM_CLOSE, 0, 0);
        return;
    }
    if let Some(hwnd) = dialog(&os.win32k_state, true) {
        destroy_window(os, hwnd);
    }
}

fn nt_user_get_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let lp = os.syscall_arg(cpu, mem, 0)?;
    loop {
        drive_file_dialog(os, mem);
        quit_when_headless(os);
        os.drain_input();
        synthesize_paint(os);
        cancel_unattended_dialog(os);
        if !os.threads[os.current].msgs.is_empty() {
            if let Some(m) = os.msg_next() {
                os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
                return Ok(if m.message == crate::msg::WM_QUIT { 0 } else { 1 });
            }
        }
        if let Some(ev) = os.win32k_state.raw_input.pop_front() {
            if route_raw_input(os, cpu, mem, lp, ev)? {
                return Ok(0);
            }
            continue;
        }
        if let Some(m) = os.msg_next() {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            return Ok(if m.message == crate::msg::WM_QUIT { 0 } else { 1 });
        }
        os.wait_for_input(std::time::Duration::from_millis(50));
    }
}

fn synthesize_paint(os: &mut WinOs) {
    if !os.threads[os.current].msgs.is_empty() {
        return;
    }
    if let Some(hwnd) = os.win32k_state.take_paint_pending() {
        os.post_internal(hwnd as u64, crate::gdi::WM_PAINT as u32, 0, 0);
    }
}

impl WinOs {
    pub(crate) fn post_input_event(&mut self, ev: exemu_core::InputEvent) {
        use exemu_core::InputEvent;
        match ev {
            InputEvent::MouseMove { x, y, .. } | InputEvent::MouseButton { x, y, .. } => {
                self.win32k_state.cursor_pos = (x, y)
            }
            InputEvent::Close => return,
            _ => {}
        }
        self.win32k_state.raw_input.push_back(ev);
    }
}

fn input_message(ev: exemu_core::InputEvent) -> Option<(u32, u64)> {
    use crate::gdi::{
        MK_LBUTTON, MK_RBUTTON, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
        WM_RBUTTONDOWN, WM_RBUTTONUP,
    };
    use exemu_core::{InputEvent, MouseButton};
    let (msg, wparam) = match ev {
        InputEvent::Close => return None,
        InputEvent::MouseMove { .. } => (WM_MOUSEMOVE, 0),
        InputEvent::MouseButton { button: MouseButton::Left, down: true, .. } => {
            (WM_LBUTTONDOWN, MK_LBUTTON)
        }
        InputEvent::MouseButton { button: MouseButton::Left, down: false, .. } => (WM_LBUTTONUP, 0),
        InputEvent::MouseButton { button: MouseButton::Right, down: true, .. } => {
            (WM_RBUTTONDOWN, MK_RBUTTON)
        }
        InputEvent::MouseButton { button: MouseButton::Right, down: false, .. } => {
            (WM_RBUTTONUP, 0)
        }
        InputEvent::Key { vk, down: true, .. } => (WM_KEYDOWN, vk as u64),
        InputEvent::Key { vk, down: false, .. } => (WM_KEYUP, vk as u64),
    };
    Some((msg as u32, wparam))
}

fn input_point(ev: exemu_core::InputEvent) -> Option<(i32, i32)> {
    use exemu_core::InputEvent;
    match ev {
        InputEvent::MouseMove { x, y, .. } | InputEvent::MouseButton { x, y, .. } => Some((x, y)),
        _ => None,
    }
}

fn pack_point(x: i32, y: i32) -> u64 {
    (x as u32 as u64 & 0xffff) | ((y as u32 as u64 & 0xffff) << 16)
}

fn route_raw_input(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    lp: u64,
    ev: exemu_core::InputEvent,
) -> Result<bool> {
    let Some((msg, wparam)) = input_message(ev) else { return Ok(false) };
    let Some((x, y)) = input_point(ev) else {
        let target = keyboard_target(os, ev.hwnd());
        if target != 0 {
            os.post_internal(target as u64, msg, wparam, 0);
        }
        return Ok(false);
    };

    let capture = os.win32k_state.capture;
    if capture != 0 && os.win32k_state.window(capture).is_some() {
        let (ox, oy) = os.win32k_state.client_origin(capture);
        os.post_internal(capture as u64, msg, wparam, pack_point(x - ox, y - oy));
        return Ok(false);
    }

    let Some(root) = input_root(&os.win32k_state, ev.hwnd()) else { return Ok(false) };
    let target = os.win32k_state.window_from_point_in(root, x, y, &[]);
    if target == 0 {
        return Ok(false);
    }
    begin_hit_test(os, cpu, mem, lp, ev, msg, wparam, target, Vec::new())
}

fn input_root(st: &Win32kState, hwnd: u32) -> Option<u32> {
    if hwnd == 0 {
        return st.shown_window();
    }
    let root = st.surface_owner(hwnd);
    st.window(root).filter(|w| w.shown).map(|_| root)
}

fn keyboard_target(os: &WinOs, hwnd: u32) -> u32 {
    let st = &os.win32k_state;
    if hwnd == 0 {
        for h in [st.focus, st.active] {
            if h != 0 && st.window(h).is_some() {
                return h;
            }
        }
        return st.shown_window().unwrap_or(0);
    }
    let Some(root) = input_root(st, hwnd) else { return 0 };
    for h in [st.focus, st.active] {
        if h != 0 && st.window(h).is_some() && st.surface_owner(h) == root {
            return h;
        }
    }
    root
}

pub(crate) struct PendingHitTest {
    ev: exemu_core::InputEvent,
    msg: u32,
    wparam: u64,
    hwnd: u32,
    lp: u64,
    skipped: Vec<u32>,
}

fn arm_hit_test(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    pending: &PendingHitTest,
) -> Result<Option<(u64, Vec<u64>)>> {
    let hwnd = pending.hwnd;
    let wndproc = os.win32k_state.wndproc_for(hwnd);
    let (x, y) = input_point(pending.ev).unwrap_or((0, 0));
    if wndproc == 0 || !os.can_call_client() || pending.skipped.len() >= HIT_TEST_ROUNDS_MAX {
        let code =
            if os.win32k_state.contains_point(hwnd, x, y) { hit::CLIENT } else { hit::NOWHERE };
        deliver_hit(os, mem, pending.lp, pending.ev, pending.msg, pending.wparam, hwnd, code)?;
        return Ok(None);
    }
    Ok(Some((wndproc, vec![hwnd as u64, WM_NCHITTEST as u64, 0, pack_point(x, y)])))
}

#[allow(clippy::too_many_arguments)]
fn begin_hit_test(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    lp: u64,
    ev: exemu_core::InputEvent,
    msg: u32,
    wparam: u64,
    hwnd: u32,
    skipped: Vec<u32>,
) -> Result<bool> {
    let pending = PendingHitTest { ev, msg, wparam, hwnd, lp, skipped };
    match arm_hit_test(os, mem, &pending)? {
        Some((wndproc, args)) => {
            os.call_hit_test_from_syscall(cpu, mem, wndproc, args, pending)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

pub(crate) fn finish_hit_test(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    mem: &mut dyn Memory,
    mut pending: PendingHitTest,
    lresult: u64,
) -> Result<()> {
    let code = lresult as i64;
    os.win32k_cb_set_result(1);
    if code == hit::TRANSPARENT {
        pending.skipped.push(pending.hwnd);
        let (x, y) = input_point(pending.ev).unwrap_or((0, 0));
        let next = match input_root(&os.win32k_state, pending.ev.hwnd()) {
            Some(root) => os.win32k_state.window_from_point_in(root, x, y, &pending.skipped),
            None => 0,
        };
        if next != 0 && next != pending.hwnd {
            pending.hwnd = next;
            if let Some((wndproc, args)) = arm_hit_test(os, mem, &pending)? {
                os.win32k_cb_queue(wndproc, args);
                os.win32k_cb_set_then(pending);
            }
            return Ok(());
        }
        return write_null_message(os, mem, pending.lp);
    }
    deliver_hit(os, mem, pending.lp, pending.ev, pending.msg, pending.wparam, pending.hwnd, code)
}

#[allow(clippy::too_many_arguments)]
fn deliver_hit(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    lp: u64,
    ev: exemu_core::InputEvent,
    msg: u32,
    wparam: u64,
    hwnd: u32,
    code: i64,
) -> Result<()> {
    let (x, y) = input_point(ev).unwrap_or((0, 0));
    let (msg, wparam, lparam) = if code == hit::CLIENT {
        let (ox, oy) = os.win32k_state.client_origin(hwnd);
        (msg, wparam, pack_point(x - ox, y - oy))
    } else if (WM_MOUSEFIRST..=WM_MOUSELAST_NC).contains(&msg) {
        (msg - NC_MOUSE_DELTA, code as u64, pack_point(x, y))
    } else {
        (msg, wparam, pack_point(x, y))
    };
    if lp == 0 {
        os.post_internal(hwnd as u64, msg, wparam, lparam);
        return Ok(());
    }
    os.write_msg_full(mem, lp, hwnd as u64, msg as u64, wparam, lparam)
}

fn write_null_message(os: &mut WinOs, mem: &mut dyn Memory, lp: u64) -> Result<()> {
    if lp == 0 {
        return Ok(());
    }
    os.write_msg_full(mem, lp, 0, 0, 0, 0)
}

fn nt_user_window_from_point(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let x = os.syscall_arg(cpu, mem, 0)? as i32;
    let y = os.syscall_arg(cpu, mem, 1)? as i32;
    Ok(os.win32k_state.window_from_point(x, y, &[]))
}

fn nt_user_child_window_from_point_ex(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let parent = os.syscall_arg(cpu, mem, 0)? as u32;
    let x = os.syscall_arg(cpu, mem, 1)? as i32;
    let y = os.syscall_arg(cpu, mem, 2)? as i32;
    if os.win32k_state.window(parent).is_none() {
        return Ok(0);
    }
    let (ox, oy) = os.win32k_state.client_origin(parent);
    Ok(os.win32k_state.child_window_from_point(parent, x + ox, y + oy))
}

fn nt_user_set_capture(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    set_capture(os, cpu, mem, hwnd)
}

fn nt_user_release_capture(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    set_capture(os, cpu, mem, 0)?;
    Ok(1)
}

fn set_capture(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory, hwnd: u32) -> Result<u32> {
    let prev = os.win32k_state.capture;
    if prev == hwnd {
        return Ok(prev);
    }
    os.win32k_state.capture = if os.win32k_state.window(hwnd).is_some() { hwnd } else { 0 };
    if prev != 0 {
        let wndproc = os.win32k_state.wndproc_for(prev);
        if wndproc != 0 {
            let m = crate::msg::PostedMsg {
                hwnd: prev as u64,
                message: WM_CAPTURECHANGED,
                wparam: 0,
                lparam: hwnd as u64,
            };
            os.call_wndprocs_from_syscall(cpu, mem, vec![(wndproc, m.into_args())], Some(prev as u64), 0)?;
        }
    }
    Ok(prev)
}

fn nt_user_set_focus(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let prev = os.win32k_state.focus;
    if prev == hwnd || os.win32k_state.window(hwnd).is_none() {
        return Ok(prev);
    }
    os.win32k_state.focus = hwnd;
    let mut calls = Vec::new();
    for (target, msg, wparam) in
        [(prev, WM_KILLFOCUS, hwnd as u64), (hwnd, WM_SETFOCUS, prev as u64)]
    {
        let wndproc = os.win32k_state.wndproc_for(target);
        if target != 0 && wndproc != 0 {
            let m =
                crate::msg::PostedMsg { hwnd: target as u64, message: msg, wparam, lparam: 0 };
            calls.push((wndproc, m.into_args()));
        }
    }
    os.call_wndprocs_from_syscall(cpu, mem, calls, Some(prev as u64), 0)?;
    Ok(prev)
}

fn nt_user_set_active_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let prev = os.win32k_state.active;
    if os.win32k_state.window(hwnd).is_some() {
        os.win32k_state.active = hwnd;
    }
    Ok(prev)
}

fn nt_user_get_thread_state(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let index = os.syscall_arg(cpu, mem, 0)?;
    let st = &os.win32k_state;
    Ok(match index {
        thread_state::FOCUS => st.focus,
        thread_state::ACTIVE => st.active,
        thread_state::CAPTURE => st.capture,
        _ => 0,
    })
}

fn nt_user_get_ancestor(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let kind = os.syscall_arg(cpu, mem, 1)?;
    if os.win32k_state.window(hwnd).is_none() {
        return Ok(0);
    }
    Ok(match kind {
        ancestor::PARENT => os.win32k_state.window(hwnd).map(|w| w.parent).unwrap_or(0),
        ancestor::ROOT | ancestor::ROOTOWNER => os.win32k_state.surface_owner(hwnd),
        _ => 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn dispatch_to_wndproc(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    hwnd: u64,
    msg: u32,
    wparam: u64,
    lparam: u64,
    result: Option<u64>,
) -> Result<u32> {
    let wndproc = os.win32k_state.wndproc_for(hwnd as u32);
    if wndproc == 0 {
        return Ok(result.unwrap_or(0) as u32);
    }
    let m = crate::msg::PostedMsg { hwnd, message: msg, wparam, lparam };
    if !os.call_wndprocs_from_syscall(cpu, mem, vec![(wndproc, m.into_args())], result, 0)? {
        return Ok(result.unwrap_or(0) as u32);
    }
    Ok(0)
}

fn nt_user_dispatch_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let lp = os.syscall_arg(cpu, mem, 0)?;
    if lp == 0 {
        return Ok(0);
    }
    let (hwnd, message, wparam, lparam) = os.read_msg(mem, lp)?;
    dispatch_to_wndproc(os, cpu, mem, hwnd, message as u32, wparam, lparam, None)
}

fn nt_user_peek_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    const PM_REMOVE: u32 = 0x0001;
    let lp = os.syscall_arg(cpu, mem, 0)?;
    let remove = os.syscall_arg(cpu, mem, 4)? as u32 & PM_REMOVE != 0;
    drive_file_dialog(os, mem);
    quit_when_headless(os);
    os.drain_input();
    synthesize_paint(os);
    cancel_unattended_dialog(os);
    if !os.threads[os.current].msgs.is_empty() {
        if let Some(m) = os.msg_peek(remove) {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            return Ok(1);
        }
    }
    if remove {
        if let Some(ev) = os.win32k_state.raw_input.pop_front() {
            if route_raw_input(os, cpu, mem, lp, ev)? {
                return Ok(0);
            }
            if let Some(m) = os.msg_peek(true) {
                os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
                return Ok(1);
            }
        }
    }
    match os.msg_peek(remove) {
        Some(m) => {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            Ok(1)
        }
        None => Ok(0),
    }
}

fn nt_user_translate_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    const WM_KEYDOWN: u32 = 0x0100;
    const WM_SYSKEYDOWN: u32 = 0x0104;
    const WM_CHAR: u32 = 0x0102;
    const WM_SYSCHAR: u32 = 0x0106;
    let lp = os.syscall_arg(cpu, mem, 0)?;
    if lp == 0 {
        return Ok(0);
    }
    let (hwnd, message, wparam, lparam) = os.read_msg(mem, lp)?;
    let char_msg = match message as u32 {
        WM_KEYDOWN => WM_CHAR,
        WM_SYSKEYDOWN => WM_SYSCHAR,
        _ => return Ok(0),
    };
    if let Some(ch) = crate::msg::vkey_to_char(wparam as u32) {
        os.post_internal(hwnd, char_msg, ch as u64, lparam);
    }
    Ok(1)
}

fn nt_user_post_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)?;
    let message = os.syscall_arg(cpu, mem, 1)? as u32;
    let wparam = os.syscall_arg(cpu, mem, 2)?;
    let lparam = os.syscall_arg(cpu, mem, 3)?;
    if message == crate::msg::WM_QUIT {
        os.threads[os.current].quit_code = Some(wparam as i32);
        return Ok(1);
    }
    if hwnd != 0 && os.win32k_state.window(hwnd as u32).is_none() {
        return Ok(0);
    }
    os.post_internal(hwnd, message, wparam, lparam);
    Ok(1)
}

fn nt_user_post_quit_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let code = os.syscall_arg(cpu, mem, 0)? as i32;
    os.threads[os.current].quit_code = Some(code);
    Ok(0)
}

fn nt_user_get_cursor(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(os.win32k_state.current_cursor as u32)
}

fn nt_user_set_cursor(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hcursor = os.syscall_arg(cpu, mem, 0)?;
    let prev = os.win32k_state.current_cursor;
    os.win32k_state.current_cursor = hcursor;
    os.driver.set_cursor(hcursor);
    Ok(prev as u32)
}

fn nt_user_get_cursor_pos(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let lp = os.syscall_arg(cpu, mem, 0)?;
    if lp == 0 {
        return Ok(0);
    }
    let (x, y) = os.win32k_state.cursor_pos;
    mem.write_u32(lp, x as u32)?;
    mem.write_u32(lp + 4, y as u32)?;
    Ok(1)
}

fn nt_user_set_cursor_pos(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let x = os.syscall_arg(cpu, mem, 0)? as i32;
    let y = os.syscall_arg(cpu, mem, 1)? as i32;
    os.win32k_state.cursor_pos = (x, y);
    Ok(1)
}

fn nt_user_clip_cursor(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(1)
}

fn nt_user_change_display_settings(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(DISP_CHANGE_SUCCESSFUL)
}

fn nt_user_enum_display_settings(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let mode_num = os.syscall_arg(cpu, mem, 1)? as u32;
    let lp = os.syscall_arg(cpu, mem, 2)?;
    if lp == 0 {
        return Ok(0);
    }
    if mode_num != 0 && mode_num != ENUM_CURRENT_SETTINGS && mode_num != ENUM_REGISTRY_SETTINGS {
        return Ok(0);
    }
    write_devmode(mem, lp, os.driver.display_mode())?;
    Ok(1)
}

fn write_devmode(mem: &mut dyn Memory, lp: u64, mode: exemu_core::DisplayMode) -> Result<()> {
    mem.write_u16(lp + DEVMODE_DMSIZE_OFF, DEVMODE_SIZE)?;
    mem.write_u32(lp + DEVMODE_DMFIELDS_OFF, DM_DISPLAY_FIELDS)?;
    mem.write_u16(lp + DEVMODE_DMLOGPIXELS_OFF, mode.dpi as u16)?;
    mem.write_u32(lp + DEVMODE_DMBITSPERPEL_OFF, mode.bpp)?;
    mem.write_u32(lp + DEVMODE_DMPELSWIDTH_OFF, mode.width)?;
    mem.write_u32(lp + DEVMODE_DMPELSHEIGHT_OFF, mode.height)?;
    mem.write_u32(lp + DEVMODE_DMDISPLAYFREQUENCY_OFF, mode.frequency)?;
    Ok(())
}

fn nt_user_msg_wait_for_multiple_objects_ex(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let count = os.syscall_arg(cpu, mem, 0)? as u32;
    quit_when_headless(os);
    os.drain_input();
    synthesize_paint(os);
    let idle = os.threads[os.current].msgs.is_empty() && os.threads[os.current].quit_code.is_none();
    if idle {
        os.wait_for_input(std::time::Duration::from_millis(50));
    }
    Ok(count)
}

const BGRA_BLACK: u32 = 0xFF00_0000;

#[derive(Clone, Copy)]
struct DcTarget {
    surface: Surface,
    org: (i32, i32),
    clip: [i32; 4],
}

impl DcTarget {
    fn map(&self, x: i32, y: i32) -> (i32, i32) {
        (x + self.org.0, y + self.org.1)
    }
}

fn dc_surface(os: &WinOs, hdc: u32) -> Option<DcTarget> {
    let dc = os.win32k_state.dc(hdc)?;
    let (org, clip) = (dc.org, dc.clip);
    if dc.hwnd == 0 {
        let b = os.win32k_state.bitmap(dc.bitmap)?;
        if !b.top_down || b.bpp != SURFACE_BPP || b.stride != b.w.max(0) as u32 * 4 {
            return None;
        }
        let surface = Surface { base: b.bits, w: b.w.max(0) as u32, h: b.h.max(0) as u32 };
        return Some(DcTarget { surface, org: (0, 0), clip: [0, 0, b.w, b.h] });
    }
    let owner = os.win32k_state.surface_owner(dc.hwnd);
    let surface = os.win32k_state.window(owner)?.surface?;
    Some(DcTarget { surface, org, clip })
}

fn put_pixel(mem: &mut dyn Memory, t: &DcTarget, x: i32, y: i32, bgra: u32) -> Result<()> {
    let s = &t.surface;
    if x < t.clip[0] || y < t.clip[1] || x >= t.clip[2] || y >= t.clip[3] {
        return Ok(());
    }
    if x < 0 || y < 0 || x >= s.w as i32 || y >= s.h as i32 {
        return Ok(());
    }
    let off = (y as u64 * s.w as u64 + x as u64) * 4;
    mem.write_u32(s.base + off, bgra)
}

fn draw_glyph(mem: &mut dyn Memory, t: &DcTarget, ch: char, x: i32, y: i32, bgra: u32) -> Result<()> {
    use font8x8::UnicodeFonts;
    if let Some(rows) = font8x8::BASIC_FONTS.get(ch) {
        for (ry, bits) in rows.iter().enumerate() {
            for rx in 0..8i32 {
                if bits & (1 << rx) != 0 {
                    let (px, py) = t.map(x + rx, y + ry as i32);
                    put_pixel(mem, t, px, py, bgra)?;
                }
            }
        }
    }
    Ok(())
}

fn nt_gdi_ext_text_out_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let x = os.syscall_arg(cpu, mem, 1)? as i32;
    let y = os.syscall_arg(cpu, mem, 2)? as i32;
    let str_ptr = os.syscall_arg(cpu, mem, 5)?;
    let count = os.syscall_arg(cpu, mem, 6)? as u32;

    let Some(target) = dc_surface(os, hdc) else {
        return Ok(0);
    };

    let mut units = Vec::with_capacity(count as usize);
    for i in 0..count {
        units.push(mem.read_u16(str_ptr + i as u64 * 2)?);
    }
    let text = String::from_utf16_lossy(&units);

    let m = os.win32k_state.dc_font(hdc).map(|f| f.metrics()).unwrap_or_else(default_metrics);
    let color = gdi_client_object(os, mem, hdc)
        .and_then(|obj| mem.read_u32(obj + DC_ATTR_TEXT_COLOR).ok())
        .map(colorref_to_bgra)
        .unwrap_or(BGRA_BLACK);
    if let Some(tb) = os.driver.rasterize_text(&text, m.height) {
        composite_coverage(mem, &target, x, y, &tb, color)?;
    } else {
        let mut cx = x;
        for ch in text.chars() {
            draw_glyph(mem, &target, ch, cx, y, color)?;
            cx += STUB_FONT_CELL_W as i32;
        }
    }
    Ok(1)
}

fn composite_coverage(
    mem: &mut dyn Memory,
    t: &DcTarget,
    x: i32,
    y: i32,
    tb: &exemu_core::TextBitmap,
    color: u32,
) -> Result<()> {
    let s = &t.surface;
    let (fb, fg, fr) = (color & 0xff, (color >> 8) & 0xff, (color >> 16) & 0xff);
    for gy in 0..tb.height {
        for gx in 0..tb.width {
            let a = tb.coverage[(gy * tb.width + gx) as usize] as u32;
            if a == 0 {
                continue;
            }
            let (px, py) = t.map(x + gx as i32, y + gy as i32);
            if px < t.clip[0] || py < t.clip[1] || px >= t.clip[2] || py >= t.clip[3] {
                continue;
            }
            if px < 0 || py < 0 || px >= s.w as i32 || py >= s.h as i32 {
                continue;
            }
            let off = s.base + (py as u64 * s.w as u64 + px as u64) * 4;
            let existing = mem.read_u32(off)?;
            let inv = 255 - a;
            let b = ((existing & 0xff) * inv + fb * a) / 255;
            let g = (((existing >> 8) & 0xff) * inv + fg * a) / 255;
            let r = (((existing >> 16) & 0xff) * inv + fr * a) / 255;
            mem.write_u32(off, (existing & 0xff00_0000) | (r << 16) | (g << 8) | b)?;
        }
    }
    Ok(())
}

fn nt_gdi_rectangle(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let left = os.syscall_arg(cpu, mem, 1)? as i32;
    let top = os.syscall_arg(cpu, mem, 2)? as i32;
    let right = os.syscall_arg(cpu, mem, 3)? as i32;
    let bottom = os.syscall_arg(cpu, mem, 4)? as i32;

    let Some(target) = dc_surface(os, hdc) else {
        return Ok(0);
    };
    if right <= left || bottom <= top {
        return Ok(1);
    }
    let (x0, y0) = target.map(left, top);
    let (x1, y1) = target.map(right - 1, bottom - 1);
    for x in x0..=x1 {
        put_pixel(mem, &target, x, y0, BGRA_BLACK)?;
        put_pixel(mem, &target, x, y1, BGRA_BLACK)?;
    }
    for y in y0..=y1 {
        put_pixel(mem, &target, x0, y, BGRA_BLACK)?;
        put_pixel(mem, &target, x1, y, BGRA_BLACK)?;
    }
    Ok(1)
}

pub mod abi {
    pub const SYSCALLS: [(&str, u32); 38] = [
        ("NtUserBuildHwndList", super::NT_USER_BUILD_HWND_LIST),
        ("NtUserWindowFromPoint", super::NT_USER_WINDOW_FROM_POINT),
        ("NtUserChildWindowFromPointEx", super::NT_USER_CHILD_WINDOW_FROM_POINT_EX),
        ("NtUserSetCapture", super::NT_USER_SET_CAPTURE),
        ("NtUserReleaseCapture", super::NT_USER_RELEASE_CAPTURE),
        ("NtUserSetFocus", super::NT_USER_SET_FOCUS),
        ("NtUserSetActiveWindow", super::NT_USER_SET_ACTIVE_WINDOW),
        ("NtUserGetThreadState", super::NT_USER_GET_THREAD_STATE),
        ("NtUserGetAncestor", super::NT_USER_GET_ANCESTOR),
        ("NtUserPeekMessage", super::NT_USER_PEEK_MESSAGE),
        ("NtUserTranslateMessage", super::NT_USER_TRANSLATE_MESSAGE),
        ("NtUserCreateWindowEx", super::NT_USER_CREATE_WINDOW_EX),
        ("NtUserShowWindow", super::NT_USER_SHOW_WINDOW),
        ("NtUserDestroyWindow", super::NT_USER_DESTROY_WINDOW),
        ("NtUserSetWindowPos", super::NT_USER_SET_WINDOW_POS),
        ("NtUserMessageCall", super::NT_USER_MESSAGE_CALL),
        ("NtUserGetDC", super::NT_USER_GET_DC),
        ("NtUserGetDCEx", super::NT_USER_GET_DC_EX),
        ("NtUserReleaseDC", super::NT_USER_RELEASE_DC),
        ("NtUserBeginPaint", super::NT_USER_BEGIN_PAINT),
        ("NtUserEndPaint", super::NT_USER_END_PAINT),
        ("NtUserGetMessage", super::NT_USER_GET_MESSAGE),
        ("NtUserDispatchMessage", super::NT_USER_DISPATCH_MESSAGE),
        ("NtUserCallHwnd", super::NT_USER_CALL_HWND),
        ("NtUserCallHwndParam", super::NT_USER_CALL_HWND_PARAM),
        ("NtUserCallOneParam", super::NT_USER_CALL_ONE_PARAM),
        ("NtUserCallTwoParam", super::NT_USER_CALL_TWO_PARAM),
        ("NtUserSetWindowLong", super::NT_USER_SET_WINDOW_LONG),
        ("NtUserSetWindowLongPtr", super::NT_USER_SET_WINDOW_LONG_PTR),
        ("NtGdiExtTextOutW", super::NT_GDI_EXT_TEXT_OUT_W),
        ("NtGdiRectangle", super::NT_GDI_RECTANGLE),
        ("NtGdiPatBlt", super::NT_GDI_PAT_BLT),
        ("NtGdiSelectBrush", super::NT_GDI_SELECT_BRUSH),
        ("NtGdiSelectPen", super::NT_GDI_SELECT_PEN),
        ("NtGdiSelectFont", super::NT_GDI_SELECT_FONT),
        ("NtGdiCreateSolidBrush", super::NT_GDI_CREATE_SOLID_BRUSH),
        ("NtGdiCreatePen", super::NT_GDI_CREATE_PEN),
        ("NtGdiGetAndSetDCDword", super::NT_GDI_GET_AND_SET_DC_DWORD),
    ];

    pub const CALL_HWND: [(&str, u64); 7] = [
        ("IsWindow", super::call_hwnd::IS_WINDOW),
        ("IsWindowEnabled", super::call_hwnd::IS_WINDOW_ENABLED),
        ("IsWindowUnicode", super::call_hwnd::IS_WINDOW_UNICODE),
        ("IsWindowVisible", super::call_hwnd::IS_WINDOW_VISIBLE),
        ("GetParent", super::call_hwnd::GET_PARENT),
        ("SetWindowTextW", super::call_hwnd::IS_SELF_THREAD),
        ("DIALOG_get_info", super::call_hwnd::GET_DIALOG_INFO),
    ];

    pub const THREAD_STATE: [(&str, u64); 3] = [
        ("GetFocus", super::thread_state::FOCUS),
        ("GetActiveWindow", super::thread_state::ACTIVE),
        ("GetCapture", super::thread_state::CAPTURE),
    ];

    pub const MESSAGE_CALL_TYPES: [(&str, &str, u64); 18] = [
        ("user32.dll", "SendMessageW", super::message_call::SEND_MESSAGE),
        ("user32.dll", "SendMessageTimeoutW", super::message_call::SEND_MESSAGE_TIMEOUT),
        ("user32.dll", "SendNotifyMessageW", super::message_call::SEND_NOTIFY_MESSAGE),
        ("user32.dll", "SendMessageCallbackW", super::message_call::SEND_MESSAGE_CALLBACK),
        ("user32.dll", "CallWindowProcW", super::message_call::CALL_WINDOW_PROC),
        ("user32.dll", "DefWindowProcW", super::message_call::DEF_WINDOW_PROC),
        ("user32.dll", "NC_HandleSysCommand", super::message_call::DEF_WINDOW_PROC),
        ("user32.dll", "USER_ScrollBarProc", super::message_call::SCROLL_BAR_WND_PROC),
        ("user32.dll", "PopupMenuWndProcW", super::message_call::POPUP_MENU_WND_PROC),
        ("user32.dll", "DesktopWndProcW", super::message_call::DESKTOP_WND_PROC),
        ("user32.dll", "SPY_EnterMessage", super::message_call::SPY_ENTER),
        ("user32.dll", "SPY_ExitMessage", super::message_call::SPY_EXIT),
        ("user32.dll", "SPY_GetMsgName", super::message_call::SPY_GET_MSG_NAME),
        ("user32.dll", "post_dde_message", super::message_call::POST_DDE_MESSAGE),
        ("explorer.exe", "clipboard_wndproc", super::message_call::CLIPBOARD_WND_PROC),
        ("explorer.exe", "initialize_systray", super::message_call::SYSTRAY_CALL),
        ("imm32.dll", "ImeProcessKey", super::message_call::IME_DRIVER_CALL),
        ("wintab32.dll", "WTInfoW", super::message_call::TABLET_CALL),
    ];

    pub const MESSAGE_CALL_DISPATCH: u64 = super::message_call::DISPATCH_MESSAGE;

    pub const MESSAGE_CALL_DRIVER_307: u64 = super::message_call::DRIVER_CALL_307;

    pub const MESSAGE_CALL_CALL_WINDOW_PROC: u64 = super::message_call::CALL_WINDOW_PROC;

    pub const MESSAGE_CALL_SENDS: [u64; 4] = super::message_call::SENDS;
    pub const MESSAGE_CALL_KERNEL_PROCS: [u64; 5] = super::message_call::KERNEL_WND_PROCS;
    pub const MESSAGE_CALL_NOT_A_MESSAGE: [u64; 8] = super::message_call::NOT_A_MESSAGE;

    pub const WM_NCHITTEST: u32 = super::WM_NCHITTEST;
    pub const HT_CLIENT: i64 = super::hit::CLIENT;
    pub const HT_TRANSPARENT: i64 = super::hit::TRANSPARENT;

    pub const CALL_HWND_PARAM: [(&str, u64); 7] = [
        ("GetWindowRect", super::call_hwnd_param::GET_WINDOW_RECT),
        ("GetClientRect", super::call_hwnd_param::GET_CLIENT_RECT),
        ("GetWindowLongPtrA", super::call_hwnd_param::GET_WINDOW_LONG_PTR_A),
        ("GetWindowLongPtrW", super::call_hwnd_param::GET_WINDOW_LONG_PTR_W),
        ("GetWindow", super::call_hwnd_param::GET_WINDOW_RELATIVE),
        ("IsChild", super::call_hwnd_param::IS_CHILD),
        ("DIALOG_get_info", super::call_hwnd_param::SET_DIALOG_INFO),
    ];

    pub const CALL_ONE_PARAM: [(&str, u64); 3] = [
        ("GetSysColor", super::call_one_param::GET_SYS_COLOR),
        ("GetSysColorBrush", super::call_one_param::GET_SYS_COLOR_BRUSH),
        ("GetSystemMetrics", super::call_one_param::GET_SYSTEM_METRICS),
    ];

    pub const CALL_TWO_PARAM_VIA_SET_WINDOW_LONG_PTR_A: [(&str, u64); 2] =
        [
            ("AllocWinProc", super::call_two_param::ALLOC_WIN_PROC),
            ("GetDialogProc", super::call_two_param::GET_DIALOG_PROC),
        ];

    pub const DC_DWORD: [(&str, u64); 2] = [
        ("SetTextColor", super::dc_dword::TEXT_COLOR),
        ("SetBkColor", super::dc_dword::BK_COLOR),
    ];

    pub const DC_ATTR: [(&str, u64); 3] = [
        ("GetDCOrgEx", super::DC_ATTR_ORG_X),
        ("GetTextColor", super::DC_ATTR_TEXT_COLOR),
        ("GetBkColor", super::DC_ATTR_BK_COLOR),
    ];

    pub const GDI_ENTRY_SIZE: u64 = super::GDI_ENTRY_SIZE;
    pub const GDI_ENTRY_GENERATION_OFF: u64 = super::GDI_ENTRY_GENERATION_OFF;
    pub const GDI_ENTRY_TYPE_OFF: u64 = super::GDI_ENTRY_TYPE_OFF;
    pub const GDI_ENTRY_OBJECT_OFF: u64 = super::GDI_ENTRY_OBJECT_OFF;
    pub const GDI_PEB_TABLE_PTR_OFF: u64 = super::GDI_PEB_TABLE_PTR_OFF;
    pub const GDI_TYPE_BRUSH: u16 = super::gdi_type::BRUSH;
    pub const STOCK_SLOT_BASE: u64 = super::STOCK_SLOT_BASE;
    pub const STOCK_SLOT_LAST: u64 = super::STOCK_SLOT_LAST;
    pub fn stock_slots() -> Vec<(u64, u16)> {
        super::STOCK_OBJECTS.iter().map(|(s, t, _)| (*s, *t)).collect()
    }
    pub const CLIENT_PFN_COUNT: usize = super::CLIENT_PFN_COUNT;
}

fn colorref_to_bgra(c: u32) -> u32 {
    let (r, g, b) = (c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF);
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

fn nt_gdi_create_solid_brush(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let color = os.syscall_arg(cpu, mem, 0)? as u32;
    alloc_brush(os, mem, color)
}

fn nt_gdi_create_pen(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(alloc_gdi_object(os, mem, gdi_type::PEN)?.map(|(h, _)| h).unwrap_or(0))
}

fn nt_gdi_select_brush(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let brush = os.syscall_arg(cpu, mem, 1)? as u32;
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(0);
    };
    let previous = dc.brush;
    dc.brush = brush;
    Ok(previous)
}

fn nt_gdi_select_pen(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(os.syscall_arg(cpu, mem, 1)? as u32)
}

fn prop_key(mem: &dyn Memory, name: u64) -> Result<String> {
    if name < 0x1_0000 {
        return Ok(format!("#{name}"));
    }
    Ok(read_wstr(mem, name)?.to_ascii_lowercase())
}

fn nt_user_set_prop(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let key = prop_key(mem, os.syscall_arg(cpu, mem, 1)?)?;
    let handle = os.syscall_arg(cpu, mem, 2)?;
    let Some(w) = os.win32k_state.window_mut(hwnd) else { return Ok(0) };
    match w.props.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = handle,
        None => w.props.push((key, handle)),
    }
    Ok(1)
}

fn nt_user_get_prop(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let key = prop_key(mem, os.syscall_arg(cpu, mem, 1)?)?;
    let value = os
        .win32k_state
        .window(hwnd)
        .and_then(|w| w.props.iter().find(|(k, _)| *k == key).map(|(_, v)| *v))
        .unwrap_or(0);
    os.return_u64_from_syscall(value);
    Ok(0)
}

fn nt_user_remove_prop(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let key = prop_key(mem, os.syscall_arg(cpu, mem, 1)?)?;
    let mut value = 0;
    if let Some(w) = os.win32k_state.window_mut(hwnd) {
        if let Some(i) = w.props.iter().position(|(k, _)| *k == key) {
            value = w.props.remove(i).1;
        }
    }
    os.return_u64_from_syscall(value);
    Ok(0)
}

fn nt_gdi_select_font(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let hfont = os.syscall_arg(cpu, mem, 1)? as u32;
    if os.win32k_state.font(hfont).is_none() {
        return Ok(0);
    }
    Ok(os
        .win32k_state
        .dcs
        .iter_mut()
        .find(|(h, _)| *h == hdc)
        .map(|(_, dc)| std::mem::replace(&mut dc.font, hfont))
        .unwrap_or(0))
}

fn nt_gdi_hfont_create(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let enumex = os.syscall_arg(cpu, mem, 0)?;
    if enumex == 0 {
        return Ok(0);
    }
    let mut bytes = [0u8; LOGFONTW_SIZE as usize];
    mem.read(enumex, &mut bytes)?;
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::FONT)? else {
        return Ok(0);
    };
    os.win32k_state.fonts.push((handle & 0xFFFF, LogFont::from_bytes(&bytes)));
    Ok(handle)
}

fn nt_gdi_get_dc_object(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let ty = (os.syscall_arg_u32(cpu, mem, 1)? >> 16) & 0xFFFF;
    let dc = os.win32k_state.dc(hdc);
    Ok(match ty as u16 {
        gdi_type::FONT => dc.map(|d| d.font).unwrap_or(STOCK_SYSTEM_FONT),
        gdi_type::BRUSH => match dc.map(|d| d.brush).unwrap_or(0) {
            0 => STOCK_WHITE_BRUSH,
            h => h,
        },
        gdi_type::PEN => STOCK_BLACK_PEN,
        gdi_type::PALETTE => STOCK_DEFAULT_PALETTE,
        gdi_type::BITMAP => dc.map(|d| d.bitmap).unwrap_or(0),
        _ if ty == NTGDI_OBJ_SURF => dc.map(|d| d.bitmap).unwrap_or(0),
        _ if ty == NTGDI_OBJ_EXTPEN => STOCK_BLACK_PEN,
        _ => 0,
    })
}

fn nt_gdi_get_font_data(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(GDI_ERROR)
}

fn nt_gdi_get_text_face_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let count = os.syscall_arg_u32(cpu, mem, 1)?;
    let buffer = os.syscall_arg(cpu, mem, 2)?;
    let Some(lf) = os.win32k_state.dc_font(hdc) else { return Ok(0) };
    let units: Vec<u16> = lf.face().encode_utf16().collect();
    if buffer == 0 || count == 0 {
        return Ok(units.len() as u32 + 1);
    }
    let n = (units.len() as u32 + 1).min(count);
    for i in 0..n {
        let unit = if i + 1 == n { 0 } else { units[i as usize] };
        mem.write_u16(buffer + i as u64 * 2, unit)?;
    }
    Ok(n)
}

fn alloc_bitmap(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    w: i32,
    h: i32,
    planes: u32,
    bpp: u32,
    top_down: bool,
) -> Result<u32> {
    let (planes, bpp) = (planes.max(1), bpp);
    let rows = h.unsigned_abs() as u64;
    let stride = (w.max(0) as u64 * bpp as u64 * planes as u64).div_ceil(32) * 4;
    if w <= 0 || rows == 0 || stride == 0 {
        return Ok(0);
    }
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::BITMAP)? else {
        return Ok(0);
    };
    let Some(bits) = os.map_anywhere(mem, stride * rows, Perm::RW, "gdi-bitmap") else {
        return Ok(0);
    };
    let bmp = Bitmap { w, h: rows as i32, planes, bpp, bits, stride: stride as u32, top_down };
    os.win32k_state.bitmaps.push((handle, bmp));
    Ok(handle)
}

fn nt_gdi_create_compatible_dc(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    alloc_memory_dc(os, mem)
}

fn alloc_memory_dc(os: &mut WinOs, mem: &mut dyn Memory) -> Result<u32> {
    let Some((hdc, obj)) = alloc_gdi_object(os, mem, gdi_type::DC)? else {
        return Ok(0);
    };
    mem.write_u32(obj + DC_ATTR_ORG_X, 0)?;
    mem.write_u32(obj + DC_ATTR_ORG_Y, 0)?;
    let dc = Dc {
        hwnd: 0,
        brush: 0,
        org: (0, 0),
        clip: [0, 0, 0, 0],
        bitmap: 0,
        font: STOCK_SYSTEM_FONT,
    };
    os.win32k_state.dcs.push((hdc, dc));
    Ok(hdc)
}

fn nt_gdi_create_bitmap(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let w = os.syscall_arg_u32(cpu, mem, 0)? as i32;
    let h = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let planes = os.syscall_arg_u32(cpu, mem, 2)?;
    let bpp = os.syscall_arg_u32(cpu, mem, 3)?;
    let src = os.syscall_arg(cpu, mem, 4)?;
    let handle = alloc_bitmap(os, mem, w, h, planes, bpp, true)?;
    if handle == 0 {
        return Ok(0);
    }
    if src != 0 {
        let bmp = os.win32k_state.bitmap(handle).expect("just registered");
        let mut buf = vec![0u8; bmp.stride as usize * bmp.h as usize];
        mem.read(src, &mut buf)?;
        mem.write(bmp.bits, &buf)?;
    }
    Ok(handle)
}

fn nt_gdi_create_compatible_bitmap(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let w = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let h = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    alloc_bitmap(os, mem, w, h, 1, SURFACE_BPP, true)
}

fn nt_gdi_create_dib_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let bmi = os.syscall_arg(cpu, mem, 3)?;
    let out_bits = os.syscall_arg(cpu, mem, 8)?;
    if bmi == 0 {
        return Ok(0);
    }
    let w = mem.read_u32(bmi + BIH_WIDTH)? as i32;
    let h = mem.read_u32(bmi + BIH_HEIGHT)? as i32;
    let planes = mem.read_u16(bmi + BIH_PLANES)? as u32;
    let bpp = mem.read_u16(bmi + BIH_BIT_COUNT)? as u32;
    let handle = alloc_bitmap(os, mem, w, h, planes, bpp, h < 0)?;
    if handle == 0 {
        return Ok(0);
    }
    let bits = os.win32k_state.bitmap(handle).map_or(0, |b| b.bits);
    if bits == 0 {
        return Ok(0);
    }
    if out_bits != 0 {
        mem.write_u64(out_bits, bits)?;
    }
    Ok(handle)
}

fn nt_gdi_select_bitmap(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let hbm = os.syscall_arg(cpu, mem, 1)? as u32;
    if os.win32k_state.bitmap(hbm).is_none() {
        return Ok(0);
    }
    Ok(os
        .win32k_state
        .dcs
        .iter_mut()
        .find(|(h, _)| *h == hdc)
        .map(|(_, dc)| std::mem::replace(&mut dc.bitmap, hbm))
        .unwrap_or(0))
}

fn nt_gdi_get_device_caps(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let index = os.syscall_arg(cpu, mem, 1)?;
    Ok(match index {
        dev_caps::TECHNOLOGY => dev_caps::DT_RASDISPLAY,
        dev_caps::HORZRES => system_metric(0),
        dev_caps::VERTRES => system_metric(1),
        dev_caps::BITSPIXEL => SURFACE_BPP,
        dev_caps::PLANES => 1,
        dev_caps::NUMCOLORS => u32::MAX,
        dev_caps::LOGPIXELSX | dev_caps::LOGPIXELSY => os.cfg.dpi,
        _ => 0,
    })
}

fn nt_gdi_ext_get_object_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let count = os.syscall_arg_u32(cpu, mem, 1)?;
    let buffer = os.syscall_arg(cpu, mem, 2)?;

    if let Some(lf) = os.win32k_state.font(handle) {
        if buffer == 0 {
            return Ok(LOGFONTW_SIZE);
        }
        let n = count.min(LOGFONTW_SIZE);
        mem.write(buffer, &lf.0[..n as usize])?;
        return Ok(n);
    }

    let Some(b) = os.win32k_state.bitmap(handle) else { return Ok(0) };

    if buffer == 0 || count == 0 {
        return Ok(BITMAP_SIZE);
    }
    if count < BITMAP_SIZE {
        return Ok(0);
    }
    mem.write_u32(buffer + BITMAP_TYPE, 0)?;
    mem.write_u32(buffer + BITMAP_WIDTH, b.w as u32)?;
    mem.write_u32(buffer + BITMAP_HEIGHT, b.h as u32)?;
    mem.write_u32(buffer + BITMAP_WIDTH_BYTES, b.stride)?;
    mem.write_u16(buffer + BITMAP_PLANES, b.planes as u16)?;
    mem.write_u16(buffer + BITMAP_BITS_PIXEL, b.bpp as u16)?;
    mem.write_u64(buffer + BITMAP_BITS, b.bits)?;
    Ok(BITMAP_SIZE)
}

fn create_cursor_icon(os: &mut WinOs, is_icon: bool) -> u32 {
    let handle = alloc_handle(os);
    os.win32k_state.icons.push((handle, IconObject { is_icon, ..IconObject::default() }));
    handle
}

fn nt_user_set_cursor_icon_data(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hicon = os.syscall_arg(cpu, mem, 0)? as u32;
    let desc = os.syscall_arg(cpu, mem, 3)?;
    if desc == 0 || !os.win32k_state.icons.iter().any(|(h, _)| *h == hicon) {
        return Ok(0);
    }
    let frames = mem.read_u64(desc + DESC_FRAMES)?;
    if frames == 0 {
        return Ok(0);
    }
    let f = frames;
    let (w, h) = (mem.read_u32(f + FRAME_WIDTH)? as i32, mem.read_u32(f + FRAME_HEIGHT)? as i32);
    let color = mem.read_u64(f + FRAME_COLOR)? as u32;
    let alpha = mem.read_u64(f + FRAME_ALPHA)? as u32;
    let mask = mem.read_u64(f + FRAME_MASK)? as u32;
    let hotspot =
        (mem.read_u32(f + FRAME_HOTSPOT_X)? as i32, mem.read_u32(f + FRAME_HOTSPOT_Y)? as i32);

    if let Some((_, icon)) = os.win32k_state.icons.iter_mut().find(|(h, _)| *h == hicon) {
        icon.width = w;
        icon.height = h;
        icon.hotspot = hotspot;
        icon.color = color;
        icon.alpha = alpha;
        icon.mask = mask;
    }
    Ok(1)
}

fn nt_user_find_existing_cursor_icon(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(0)
}

fn copy_bitmap(os: &mut WinOs, mem: &mut dyn Memory, src: u32) -> Result<u32> {
    let Some(b) = os.win32k_state.bitmap(src) else { return Ok(0) };
    let dst = alloc_bitmap(os, mem, b.w, b.h, b.planes, b.bpp, b.top_down)?;
    if dst == 0 {
        return Ok(0);
    }
    let bits = os.win32k_state.bitmap(dst).map_or(0, |d| d.bits);
    let mut buf = vec![0u8; b.stride as usize * b.h.max(0) as usize];
    mem.read(b.bits, &mut buf)?;
    mem.write(bits, &buf)?;
    Ok(dst)
}

fn clear_unicode_string(mem: &mut dyn Memory, addr: u64) -> Result<()> {
    if addr == 0 {
        return Ok(());
    }
    mem.write_u16(addr + USTR_LENGTH, 0)?;
    mem.write_u64(addr + USTR_BUFFER, 0)?;
    Ok(())
}

fn nt_user_get_icon_info(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hicon = os.syscall_arg(cpu, mem, 0)? as u32;
    let info = os.syscall_arg(cpu, mem, 1)?;
    let module = os.syscall_arg(cpu, mem, 2)?;
    let res_name = os.syscall_arg(cpu, mem, 3)?;
    let bpp_out = os.syscall_arg(cpu, mem, 4)?;
    let Some(icon) = os.win32k_state.icons.iter().find(|(h, _)| *h == hicon).map(|(_, i)| *i)
    else {
        return Ok(0);
    };
    if info == 0 {
        return Ok(0);
    }
    clear_unicode_string(mem, module)?;
    clear_unicode_string(mem, res_name)?;
    let mask = copy_bitmap(os, mem, icon.mask)?;
    let color = copy_bitmap(os, mem, icon.color)?;
    mem.write_u32(info + ICONINFO_F_ICON, u32::from(icon.is_icon))?;
    mem.write_u32(info + ICONINFO_X_HOTSPOT, icon.hotspot.0 as u32)?;
    mem.write_u32(info + ICONINFO_Y_HOTSPOT, icon.hotspot.1 as u32)?;
    mem.write_u64(info + ICONINFO_HBM_MASK, mask as u64)?;
    mem.write_u64(info + ICONINFO_HBM_COLOR, color as u64)?;
    if bpp_out != 0 {
        let bpp = os.win32k_state.bitmap(icon.color).map_or(0, |b| b.bpp);
        mem.write_u32(bpp_out, bpp)?;
    }
    Ok(1)
}

fn nt_user_get_icon_size(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hicon = os.syscall_arg(cpu, mem, 0)? as u32;
    let out_w = os.syscall_arg(cpu, mem, 2)?;
    let out_h = os.syscall_arg(cpu, mem, 3)?;
    let Some(icon) = os.win32k_state.icons.iter().find(|(h, _)| *h == hicon).map(|(_, i)| *i)
    else {
        return Ok(0);
    };
    if out_w != 0 {
        mem.write_u32(out_w, icon.width as u32)?;
    }
    if out_h != 0 {
        mem.write_u32(out_h, icon.height.saturating_mul(2) as u32)?;
    }
    Ok(1)
}

fn nt_user_destroy_cursor(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hicon = os.syscall_arg(cpu, mem, 0)? as u32;
    let Some(icon) = os.win32k_state.icons.iter().find(|(h, _)| *h == hicon).map(|(_, i)| *i)
    else {
        return Ok(0);
    };
    os.win32k_state.icons.retain(|(h, _)| *h != hicon);
    for bm in [icon.color, icon.alpha, icon.mask] {
        os.win32k_state.bitmaps.retain(|(h, _)| *h != bm);
    }
    Ok(1)
}

fn nt_gdi_get_text_metrics_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let tm = os.syscall_arg(cpu, mem, 1)?;
    if tm == 0 || os.win32k_state.dc(hdc).is_none() {
        return Ok(0);
    }
    let m = os.win32k_state.dc_font(hdc).map(|f| f.metrics()).unwrap_or_else(default_metrics);
    mem.write_u32(tm + TM_HEIGHT, m.height)?;
    mem.write_u32(tm + TM_ASCENT, m.ascent)?;
    mem.write_u32(tm + TM_DESCENT, m.descent)?;
    mem.write_u32(tm + TM_INTERNAL_LEADING, m.internal_leading)?;
    mem.write_u32(tm + TM_EXTERNAL_LEADING, 0)?;
    mem.write_u32(tm + TM_AVE_CHAR_WIDTH, m.ave_char_width)?;
    mem.write_u32(tm + TM_MAX_CHAR_WIDTH, m.max_char_width)?;
    mem.write_u32(tm + TM_WEIGHT, m.weight)?;
    mem.write_u32(tm + TM_OVERHANG, 0)?;
    mem.write_u32(tm + TM_DIGITIZED_ASPECT_X, 96)?;
    mem.write_u32(tm + TM_DIGITIZED_ASPECT_Y, 96)?;
    mem.write_u16(tm + TM_FIRST_CHAR, 0x20)?;
    mem.write_u16(tm + TM_LAST_CHAR, 0xFF)?;
    mem.write_u16(tm + TM_DEFAULT_CHAR, 0x1F)?;
    mem.write_u16(tm + TM_BREAK_CHAR, 0x20)?;
    mem.write_u8(tm + TM_ITALIC, m.italic)?;
    mem.write_u8(tm + TM_UNDERLINED, m.underlined)?;
    mem.write_u8(tm + TM_STRUCK_OUT, m.struck_out)?;
    mem.write_u8(tm + TM_PITCH_AND_FAMILY, m.pitch_and_family)?;
    mem.write_u8(tm + TM_CHARSET, m.char_set)?;
    Ok(1)
}

fn nt_gdi_get_text_extent_ex_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let str_ptr = os.syscall_arg(cpu, mem, 1)?;
    let count = os.syscall_arg(cpu, mem, 2)? as u32;
    let alp_dx = os.syscall_arg(cpu, mem, 5)?;
    let size = os.syscall_arg(cpu, mem, 6)?;
    if os.win32k_state.dc(hdc).is_none() {
        return Ok(0);
    }
    let mut units = Vec::with_capacity(count as usize);
    for i in 0..count {
        units.push(mem.read_u16(str_ptr + i as u64 * 2)?);
    }
    let text = String::from_utf16_lossy(&units);
    let m = os.win32k_state.dc_font(hdc).map(|f| f.metrics()).unwrap_or_else(default_metrics);
    let (cx, cy) = measure_run(os, &text, &m);
    if size != 0 {
        mem.write_u32(size, cx)?;
        mem.write_u32(size + 4, cy)?;
    }
    if alp_dx != 0 {
        for i in 0..count {
            mem.write_u32(alp_dx + i as u64 * 4, (i + 1) * m.ave_char_width)?;
        }
    }
    Ok(1)
}

fn default_metrics() -> TextMetrics {
    LogFont::stock(STUB_FONT_CELL_H as i32, FW_NORMAL, VARIABLE_PITCH_SWISS, "System").metrics()
}

fn measure_run(os: &WinOs, text: &str, m: &TextMetrics) -> (u32, u32) {
    match os.driver.rasterize_text(text, m.height) {
        Some(tb) => (tb.width, tb.height),
        None => (text.chars().count() as u32 * m.ave_char_width, m.height),
    }
}

fn nt_gdi_create_rect_rgn(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(alloc_gdi_object(os, mem, gdi_type::REGION)?.map(|(h, _)| h).unwrap_or(0))
}

fn nt_gdi_delete_object_app(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let slot = (handle & 0xFFFF) as u64;
    if slot == 0 || slot >= GDI_TABLE_SLOTS {
        return Ok(0);
    }
    if (STOCK_SLOT_BASE..=STOCK_SLOT_LAST).contains(&slot) {
        return Ok(1);
    }
    free_gdi_object(os, mem, handle)?;
    Ok(1)
}

fn free_gdi_object(os: &mut WinOs, mem: &mut dyn Memory, handle: u32) -> Result<()> {
    let slot = (handle & 0xFFFF) as u64;
    if slot == 0 || slot >= GDI_TABLE_SLOTS || (STOCK_SLOT_BASE..=STOCK_SLOT_LAST).contains(&slot) {
        return Ok(());
    }
    let base = os.win32k_state.gdi_table_base;
    if base != 0 {
        let entry = base + slot * GDI_ENTRY_SIZE;
        if mem.read_u8(entry + GDI_ENTRY_TYPE_OFF)? & GDI_ENTRY_IN_USE != 0 {
            mem.write_u8(entry + GDI_ENTRY_TYPE_OFF, 0)?;
            os.win32k_state.gdi_free_slots.push(slot);
        }
    }
    os.win32k_state.brushes.retain(|(h, _)| *h != handle);
    os.win32k_state.dcs.retain(|(h, _)| *h != handle);
    os.win32k_state.bitmaps.retain(|(h, _)| *h != handle);
    os.win32k_state.fonts.retain(|(s, _)| *s != slot as u32);
    Ok(())
}

fn nt_gdi_intersect_clip_rect(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let left = os.syscall_arg(cpu, mem, 1)? as i32;
    let top = os.syscall_arg(cpu, mem, 2)? as i32;
    let right = os.syscall_arg(cpu, mem, 3)? as i32;
    let bottom = os.syscall_arg(cpu, mem, 4)? as i32;
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(0);
    };
    let (ox, oy) = dc.org;
    dc.clip[0] = dc.clip[0].max(left + ox);
    dc.clip[1] = dc.clip[1].max(top + oy);
    dc.clip[2] = dc.clip[2].min(right + ox);
    dc.clip[3] = dc.clip[3].min(bottom + oy);
    if dc.clip[2] <= dc.clip[0] || dc.clip[3] <= dc.clip[1] {
        return Ok(1);
    }
    Ok(SIMPLEREGION)
}

fn nt_gdi_get_and_set_dc_dword(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let code = os.syscall_arg(cpu, mem, 1)?;
    let value = os.syscall_arg(cpu, mem, 2)? as u32;
    let out = os.syscall_arg(cpu, mem, 3)?;
    let off = match code {
        dc_dword::TEXT_COLOR => DC_ATTR_TEXT_COLOR,
        dc_dword::BK_COLOR => DC_ATTR_BK_COLOR,
        _ => return Ok(0),
    };
    let Some(obj) = gdi_client_object(os, mem, hdc) else {
        return Ok(0);
    };
    let previous = mem.read_u32(obj + off)?;
    mem.write_u32(obj + off, value)?;
    if out != 0 {
        mem.write_u32(out, previous)?;
    }
    Ok(1)
}

fn gdi_client_object(os: &WinOs, mem: &dyn Memory, handle: u32) -> Option<u64> {
    let base = os.win32k_state.gdi_table_base;
    if base == 0 {
        return None;
    }
    let slot = (handle & 0xFFFF) as u64;
    if slot == 0 || slot >= GDI_TABLE_SLOTS {
        return None;
    }
    let entry = base + slot * GDI_ENTRY_SIZE;
    if mem.read_u16(entry + GDI_ENTRY_GENERATION_OFF).ok()? != (handle >> 16) as u16 {
        return None;
    }
    mem.read_u64(entry + GDI_ENTRY_OBJECT_OFF).ok()
}

fn nt_gdi_pat_blt(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let x = os.syscall_arg(cpu, mem, 1)? as i32;
    let y = os.syscall_arg(cpu, mem, 2)? as i32;
    let cx = os.syscall_arg(cpu, mem, 3)? as i32;
    let cy = os.syscall_arg(cpu, mem, 4)? as i32;
    let rop = os.syscall_arg(cpu, mem, 5)? as u32;

    let brush = os.win32k_state.dc(hdc).map(|d| d.brush).unwrap_or(0);
    let bgra = match rop {
        BLACKNESS => 0xFF00_0000,
        WHITENESS => 0xFFFF_FFFF,
        PATCOPY => match os.win32k_state.brushes.iter().find(|(h, _)| *h == brush) {
            Some((_, color)) => colorref_to_bgra(*color),
            None => return Ok(1),
        },
        _ => return Ok(0),
    };
    let Some(target) = dc_surface(os, hdc) else {
        return Ok(0);
    };
    fill_rect(mem, &target, x, y, cx, cy, bgra)?;
    Ok(1)
}

fn fill_rect(
    mem: &mut dyn Memory,
    t: &DcTarget,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    bgra: u32,
) -> Result<()> {
    if cx <= 0 || cy <= 0 {
        return Ok(());
    }
    let (sx, sy) = t.map(x, y);
    let x0 = sx.max(t.clip[0]).max(0);
    let y0 = sy.max(t.clip[1]).max(0);
    let x1 = (sx + cx).min(t.clip[2]).min(t.surface.w as i32);
    let y1 = (sy + cy).min(t.clip[3]).min(t.surface.h as i32);
    for py in y0..y1 {
        for px in x0..x1 {
            let off = t.surface.base + (py as u64 * t.surface.w as u64 + px as u64) * 4;
            mem.write_u32(off, bgra)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{DisplayMode, Perm, Reg, Region};
    use exemu_memory::VirtualMemory;

    #[test]
    fn the_icon_metrics_an_image_list_is_sized_from_are_not_degenerate() {
        const SM_CXICON: u32 = 11;
        const SM_CYICON: u32 = 12;
        const SM_CXCURSOR: u32 = 13;
        const SM_CYCURSOR: u32 = 14;
        const SM_CXSMICON: u32 = 49;
        const SM_CYSMICON: u32 = 50;

        for index in [SM_CXICON, SM_CYICON, SM_CXCURSOR, SM_CYCURSOR, SM_CXSMICON, SM_CYSMICON] {
            assert_ne!(
                system_metric(index),
                0,
                "SM_{index} answering 0 builds a degenerate image list, which comctl32 destroys"
            );
        }
        assert_eq!(system_metric(SM_CXICON), system_metric(SM_CYICON), "icons are square");
        assert_eq!(system_metric(SM_CXSMICON), system_metric(SM_CYSMICON), "…and so are small ones");
        assert_eq!(system_metric(SM_CXICON), 32);
        assert_eq!(system_metric(SM_CXSMICON), 16);
        assert!(
            system_metric(SM_CXSMICON) < system_metric(SM_CXICON),
            "the small icon must actually be smaller"
        );
        assert_eq!(system_metric(SM_CXCURSOR), system_metric(SM_CXICON));
        assert_eq!(system_metric(0x0fff), 0, "an unmodelled metric stays honestly 0");
    }

    fn os_with_gdi() -> (WinOs, VirtualMemory) {
        const PEB: u64 = 0x7F00_0000;
        let mut os =
            WinOs::new(crate::WinConfig { is_64bit: true, peb_addr: PEB, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", 0x10_0000, 0x10_000, Perm::RW)).unwrap();
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        (os, mem)
    }

    #[test]
    fn a_created_font_answers_get_object_with_the_logfont_it_was_given() {
        let (mut os, mut mem) = os_with_gdi();
        let lf = 0x10_2000u64;
        let out = 0x10_3000u64;
        mem.write_u32(lf + LOGFONT_HEIGHT as u64, (-11i32) as u32).unwrap();
        mem.write_u32(lf + LOGFONT_WEIGHT as u64, 700).unwrap();
        mem.write_u8(lf + LOGFONT_ITALIC as u64, 1).unwrap();
        for (i, unit) in "Tahoma".encode_utf16().enumerate() {
            mem.write_u16(lf + LOGFONT_FACE_NAME as u64 + i as u64 * 2, unit).unwrap();
        }

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, lf);
        cpu.set_reg(Reg::Rdx, 0x1a4);
        let hfont = nt_gdi_hfont_create(&mut os, &mut cpu, &mut mem).unwrap();
        assert_ne!(hfont, 0, "NtGdiHfontCreate answers a handle");
        assert_eq!(
            hfont >> 16,
            gdi_type::FONT as u32,
            "gdi32 dispatches SelectObject by the handle's NTGDI type"
        );

        cpu.set_reg(Reg::R10, hfont as u64);
        cpu.set_reg(Reg::Rdx, LOGFONTW_SIZE as u64);
        cpu.set_reg(Reg::R8, out);
        assert_eq!(
            nt_gdi_ext_get_object_w(&mut os, &mut cpu, &mut mem).unwrap(),
            LOGFONTW_SIZE,
            "uniscribe asks for exactly 0x5c bytes and refuses a font that answers 0"
        );
        assert_eq!(mem.read_u32(out + LOGFONT_HEIGHT as u64).unwrap(), (-11i32) as u32);
        assert_eq!(mem.read_u32(out + LOGFONT_WEIGHT as u64).unwrap(), 700);
        assert_eq!(mem.read_u8(out + LOGFONT_ITALIC as u64).unwrap(), 1);
        assert_ne!(
            mem.read_u16(out + LOGFONT_FACE_NAME as u64).unwrap(),
            0,
            "init_script_cache rejects a LOGFONTW whose lfFaceName[0] is 0"
        );
    }

    #[test]
    fn a_dc_reports_a_font_before_anything_is_selected_into_it() {
        let (mut os, mut mem) = os_with_gdi();
        let hdc = alloc_memory_dc(&mut os, &mut mem).unwrap();
        assert_ne!(hdc, 0);

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, hdc as u64);
        cpu.set_reg(Reg::Rdx, (gdi_type::FONT as u64) << 16);
        let stock = nt_gdi_get_dc_object(&mut os, &mut cpu, &mut mem).unwrap();
        assert_eq!(stock, STOCK_SYSTEM_FONT, "a fresh DC carries SYSTEM_FONT, as Wine's dc_init does");

        let lf = 0x10_2000u64;
        mem.write_u32(lf + LOGFONT_HEIGHT as u64, (-13i32) as u32).unwrap();
        mem.write_u16(lf + LOGFONT_FACE_NAME as u64, u16::from(b'X')).unwrap();
        cpu.set_reg(Reg::R10, lf);
        let hfont = nt_gdi_hfont_create(&mut os, &mut cpu, &mut mem).unwrap();

        cpu.set_reg(Reg::R10, hdc as u64);
        cpu.set_reg(Reg::Rdx, hfont as u64);
        assert_eq!(
            nt_gdi_select_font(&mut os, &mut cpu, &mut mem).unwrap(),
            stock,
            "SelectObject answers the font that was there before"
        );

        cpu.set_reg(Reg::Rdx, (gdi_type::FONT as u64) << 16);
        assert_eq!(nt_gdi_get_dc_object(&mut os, &mut cpu, &mut mem).unwrap(), hfont);

        let tm = 0x10_4000u64;
        cpu.set_reg(Reg::R10, hdc as u64);
        cpu.set_reg(Reg::Rdx, tm);
        assert_eq!(nt_gdi_get_text_metrics_w(&mut os, &mut cpu, &mut mem).unwrap(), 1);
        assert_eq!(
            mem.read_u32(tm + TM_HEIGHT).unwrap(),
            17,
            "tmHeight follows the selected font's lfHeight, not a fixed cell"
        );
        assert_eq!(mem.read_u32(tm + TM_INTERNAL_LEADING).unwrap(), 4);
        assert_eq!(
            mem.read_u32(tm + TM_ASCENT).unwrap() + mem.read_u32(tm + TM_DESCENT).unwrap(),
            mem.read_u32(tm + TM_HEIGHT).unwrap(),
            "ascent + descent is the cell, which is what a line-height calculation adds up"
        );
    }

    #[test]
    fn a_wow64_guest_can_reach_the_gdi_table_through_its_own_peb() {
        const PEB: u64 = 0x7F00_0000;
        const PEB32: u64 = 0x0020_0000;
        let mut os =
            WinOs::new(crate::WinConfig { is_64bit: true, peb_addr: PEB, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("peb32", PEB32, 0x1000, Perm::RW)).unwrap();
        os.set_wow64_peb32(PEB32);

        assert!(ensure_gdi_table(&mut os, &mut mem));
        let table = os.win32k_state.gdi_table_base;
        assert_eq!(mem.read_u64(PEB + GDI_PEB_TABLE_PTR_OFF).unwrap(), table);
        assert_eq!(
            mem.read_u32(PEB32 + GDI_PEB32_TABLE_PTR_OFF).unwrap() as u64,
            table,
            "32-bit gdi32 indexes PEB32->GdiSharedHandleTable and faults on a 0 there"
        );
        assert!(
            table + GDI_TABLE_SLOTS * GDI_ENTRY_SIZE <= u32::MAX as u64,
            "the whole table must be addressable by a 32-bit pointer"
        );
        assert!(
            os.win32k_state.gdi_dc_arena + GDI_TABLE_SLOTS * GDI_DC_OBJECT_SIZE
                <= u32::MAX as u64,
            "…and so must every object the entries point at"
        );
    }

    #[test]
    fn a_deleted_gdi_object_returns_its_table_slot() {
        let (mut os, mut mem) = os_with_gdi();

        let mut last = 0;
        for i in 0..(GDI_TABLE_SLOTS as usize * 4) {
            let (handle, _) = alloc_gdi_object(&mut os, &mut mem, gdi_type::REGION)
                .unwrap()
                .unwrap_or_else(|| panic!("the GDI table ran out after {i} create/delete pairs"));
            assert_ne!(handle, 0);
            free_gdi_object(&mut os, &mut mem, handle).unwrap();
            last = handle;
        }
        assert_ne!(last, 0);
        assert!(
            os.win32k_state.gdi_next_slot < GDI_TABLE_SLOTS,
            "a balanced create/delete pair must not consume a fresh slot each time"
        );
    }

    #[test]
    fn freeing_a_gdi_object_twice_lists_its_slot_once() {
        let (mut os, mut mem) = os_with_gdi();

        let (handle, _) = alloc_gdi_object(&mut os, &mut mem, gdi_type::BITMAP).unwrap().unwrap();
        free_gdi_object(&mut os, &mut mem, handle).unwrap();
        free_gdi_object(&mut os, &mut mem, handle).unwrap();
        assert_eq!(os.win32k_state.gdi_free_slots.len(), 1);

        let (again, _) = alloc_gdi_object(&mut os, &mut mem, gdi_type::BITMAP).unwrap().unwrap();
        assert_eq!(again, handle, "the recycled slot comes back with the same type tag");
        assert!(os.win32k_state.gdi_free_slots.is_empty());
    }

    #[test]
    fn a_bitmap_store_matches_the_geometry_get_object_reports() {
        let (mut os, mut mem) = os_with_gdi();

        let color = alloc_bitmap(&mut os, &mut mem, 32, 32, 1, 32, true).unwrap();
        assert_ne!(color, 0, "the colour plane was allocated");
        let b = os.win32k_state.bitmap(color).unwrap();
        assert_eq!(b.stride, 32 * 4);
        assert_ne!(b.bits, 0, "and its pixels have a guest address");
        let last = b.bits + (b.stride as u64 * b.h as u64) - 4;
        mem.write_u32(last, 0xDEAD_BEEF).unwrap();
        assert_eq!(mem.read_u32(last).unwrap(), 0xDEAD_BEEF);

        let mask = alloc_bitmap(&mut os, &mut mem, 32, 64, 1, 1, true).unwrap();
        assert_eq!(os.win32k_state.bitmap(mask).unwrap().stride, 4);
        let odd = alloc_bitmap(&mut os, &mut mem, 33, 8, 1, 1, true).unwrap();
        assert_eq!(os.win32k_state.bitmap(odd).unwrap().stride, 8, "DWORD-aligned rows");

        let buf = 0x10_1000u64;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, color as u64);
        cpu.set_reg(Reg::Rdx, BITMAP_SIZE as u64);
        cpu.set_reg(Reg::R8, buf);
        assert_eq!(nt_gdi_ext_get_object_w(&mut os, &mut cpu, &mut mem).unwrap(), BITMAP_SIZE);
        assert_eq!(mem.read_u32(buf + BITMAP_WIDTH).unwrap(), 32);
        assert_eq!(mem.read_u32(buf + BITMAP_HEIGHT).unwrap(), 32);
        assert_eq!(mem.read_u32(buf + BITMAP_WIDTH_BYTES).unwrap(), 32 * 4);
        assert_eq!(mem.read_u16(buf + BITMAP_BITS_PIXEL).unwrap(), 32);
        assert_eq!(mem.read_u64(buf + BITMAP_BITS).unwrap(), b.bits);

        cpu.set_reg(Reg::R10, 0x000A_0007);
        assert_eq!(nt_gdi_ext_get_object_w(&mut os, &mut cpu, &mut mem).unwrap(), 0);
    }

    #[test]
    fn create_dib_section_reads_arg3_and_writes_the_pixels_back_through_arg8() {
        let (mut os, mut mem) = os_with_gdi();
        let bmi = 0x10_2000u64;
        let out = 0x10_3000u64;
        mem.write_u32(bmi + BIH_WIDTH, 48).unwrap();
        mem.write_u32(bmi + BIH_HEIGHT, (-16i32) as u32).unwrap();
        mem.write_u16(bmi + BIH_PLANES, 1).unwrap();
        mem.write_u16(bmi + BIH_BIT_COUNT, 32).unwrap();

        let mut cpu = CpuState::default();
        let rsp = 0x10_8000u64;
        cpu.set_reg(Reg::R10, 0);
        cpu.set_reg(Reg::Rdx, 0);
        cpu.set_reg(Reg::R8, 0);
        cpu.set_reg(Reg::R9, bmi);
        for i in 4..=8u64 {
            mem.write_u64(rsp + 0x28 + (i - 4) * 8, if i == 8 { out } else { 0 }).unwrap();
        }
        let h = nt_gdi_create_dib_section(&mut os, &mut cpu, &mut mem).unwrap();
        assert_ne!(h, 0, "a DIB section was created from arg3's BITMAPINFO");

        let b = os.win32k_state.bitmap(h).unwrap();
        assert_eq!((b.w, b.h), (48, 16), "geometry came from the header");
        assert!(b.top_down, "a negative biHeight is the top-down form");
        assert_eq!(mem.read_u64(out).unwrap(), b.bits, "arg8 received the pixel address");
        assert_ne!(b.bits, 0);
        mem.write_u32(b.bits, 0x1122_3344).unwrap();
        assert_eq!(mem.read_u32(os.win32k_state.bitmap(h).unwrap().bits).unwrap(), 0x1122_3344);

        cpu.set_reg(Reg::R9, 0);
        assert_eq!(nt_gdi_create_dib_section(&mut os, &mut cpu, &mut mem).unwrap(), 0);
    }

    #[test]
    fn a_memory_dc_draws_into_whatever_bitmap_is_selected_into_it() {
        let (mut os, mut mem) = os_with_gdi();
        let mut cpu = CpuState::default();
        let hdc = nt_gdi_create_compatible_dc(&mut os, &mut cpu, &mut mem).unwrap();
        assert_ne!(hdc, 0);
        assert!(dc_surface(&os, hdc).is_none(), "a fresh memory DC has no surface at all");

        let hbm = alloc_bitmap(&mut os, &mut mem, 16, 8, 1, 32, true).unwrap();
        cpu.set_reg(Reg::R10, hdc as u64);
        cpu.set_reg(Reg::Rdx, hbm as u64);
        assert_eq!(nt_gdi_select_bitmap(&mut os, &mut cpu, &mut mem).unwrap(), 0, "none before");

        let t = dc_surface(&os, hdc).expect("the selected bitmap is now the surface");
        assert_eq!((t.surface.w, t.surface.h), (16, 8));
        assert_eq!(t.surface.base, os.win32k_state.bitmap(hbm).unwrap().bits);
        assert_eq!(t.clip, [0, 0, 16, 8], "clipped to the bitmap, not to a window");

        let other = alloc_bitmap(&mut os, &mut mem, 4, 4, 1, 32, true).unwrap();
        cpu.set_reg(Reg::Rdx, other as u64);
        assert_eq!(nt_gdi_select_bitmap(&mut os, &mut cpu, &mut mem).unwrap(), hbm);

        let flipped = alloc_bitmap(&mut os, &mut mem, 4, 4, 1, 32, false).unwrap();
        assert_ne!(os.win32k_state.bitmap(flipped).unwrap().bits, 0);
        cpu.set_reg(Reg::Rdx, flipped as u64);
        nt_gdi_select_bitmap(&mut os, &mut cpu, &mut mem).unwrap();
        assert!(dc_surface(&os, hdc).is_none());
    }

    #[test]
    fn an_icon_is_allocated_then_described_and_reports_itself_back() {
        let (mut os, mut mem) = os_with_gdi();
        let mut cpu = CpuState::default();

        cpu.set_reg(Reg::R10, 1);
        cpu.set_reg(Reg::Rdx, call_one_param::CREATE_CURSOR_ICON);
        let hicon = nt_user_call_one_param(&mut os, &mut cpu, &mut mem).unwrap();
        assert_ne!(hicon, 0, "an empty icon object exists before it is described");

        let color = alloc_bitmap(&mut os, &mut mem, 32, 32, 1, 32, true).unwrap();
        let mask = alloc_bitmap(&mut os, &mut mem, 32, 64, 1, 1, true).unwrap();
        let (desc, frame) = (0x10_4000u64, 0x10_5000u64);
        mem.write_u64(desc + DESC_FRAMES, frame).unwrap();
        mem.write_u32(frame + FRAME_WIDTH, 32).unwrap();
        mem.write_u32(frame + FRAME_HEIGHT, 32).unwrap();
        mem.write_u64(frame + FRAME_COLOR, color as u64).unwrap();
        mem.write_u64(frame + FRAME_ALPHA, 0).unwrap();
        mem.write_u64(frame + FRAME_MASK, mask as u64).unwrap();
        mem.write_u32(frame + FRAME_HOTSPOT_X, 16).unwrap();
        mem.write_u32(frame + FRAME_HOTSPOT_Y, 16).unwrap();

        cpu.set_reg(Reg::R10, hicon as u64);
        cpu.set_reg(Reg::Rdx, 0);
        cpu.set_reg(Reg::R8, 0);
        cpu.set_reg(Reg::R9, desc);
        assert_eq!(nt_user_set_cursor_icon_data(&mut os, &mut cpu, &mut mem).unwrap(), 1);

        let info = 0x10_6000u64;
        cpu.set_reg(Reg::R10, hicon as u64);
        cpu.set_reg(Reg::Rdx, info);
        for i in 4..=5u64 {
            mem.write_u64(0x10_8000 + 0x28 + (i - 4) * 8, 0).unwrap();
        }
        assert_eq!(nt_user_get_icon_info(&mut os, &mut cpu, &mut mem).unwrap(), 1);
        assert_eq!(mem.read_u32(info + ICONINFO_F_ICON).unwrap(), 1);
        assert_eq!(mem.read_u32(info + ICONINFO_X_HOTSPOT).unwrap(), 16);
        assert_eq!(mem.read_u32(info + ICONINFO_Y_HOTSPOT).unwrap(), 16);
        let (got_mask, got_color) = (
            mem.read_u64(info + ICONINFO_HBM_MASK).unwrap() as u32,
            mem.read_u64(info + ICONINFO_HBM_COLOR).unwrap() as u32,
        );
        assert_ne!(got_mask, 0);
        assert_ne!(got_color, 0);
        assert_ne!(got_color, color, "GetIconInfo hands back a COPY the caller may delete");
        assert_ne!(got_mask, mask, "…and so does the mask");
        assert_eq!(os.win32k_state.bitmap(got_color).unwrap().bpp, 32, "same geometry, own store");
        assert_ne!(os.win32k_state.bitmap(got_color).unwrap().bits, 0);

        let (w, h) = (0x10_7000u64, 0x10_7010u64);
        cpu.set_reg(Reg::R10, hicon as u64);
        cpu.set_reg(Reg::Rdx, 0);
        cpu.set_reg(Reg::R8, w);
        cpu.set_reg(Reg::R9, h);
        assert_eq!(nt_user_get_icon_size(&mut os, &mut cpu, &mut mem).unwrap(), 1);
        assert_eq!(mem.read_u32(w).unwrap(), 32);
        assert_eq!(mem.read_u32(h).unwrap(), 64, "2 x the icon height, per get_icon_size");

        cpu.set_reg(Reg::R10, 0xDEAD);
        assert_eq!(nt_user_get_icon_size(&mut os, &mut cpu, &mut mem).unwrap(), 0);
    }

    #[test]
    fn get_icon_info_empties_the_module_and_resource_strings_it_is_handed() {
        let (mut os, mut mem) = os_with_gdi();
        let mut cpu = CpuState::default();

        cpu.set_reg(Reg::R10, 1);
        cpu.set_reg(Reg::Rdx, call_one_param::CREATE_CURSOR_ICON);
        let hicon = nt_user_call_one_param(&mut os, &mut cpu, &mut mem).unwrap();

        let (module, res_name, info) = (0x10_4000u64, 0x10_4100u64, 0x10_4200u64);
        for base in [module, res_name] {
            mem.write_u16(base + USTR_LENGTH, 0x1C55).unwrap();
            mem.write_u16(base + 2, 0x206).unwrap();
            mem.write_u64(base + USTR_BUFFER, 0xDEAD_BEEF).unwrap();
        }
        cpu.set_reg(Reg::R10, hicon as u64);
        cpu.set_reg(Reg::Rdx, info);
        cpu.set_reg(Reg::R8, module);
        cpu.set_reg(Reg::R9, res_name);
        mem.write_u64(0x10_8000 + 0x28, 0).unwrap();
        assert_eq!(nt_user_get_icon_info(&mut os, &mut cpu, &mut mem).unwrap(), 1);

        for base in [module, res_name] {
            assert_eq!(
                mem.read_u16(base + USTR_LENGTH).unwrap(),
                0,
                "GetIconInfoExW writes its terminator at szModName[Length]"
            );
            assert_eq!(
                mem.read_u64(base + USTR_BUFFER).unwrap(),
                0,
                "…and reads the buffer field back as the integer resource id"
            );
        }
    }

    #[test]
    fn the_shared_icon_cache_answers_not_cached() {
        let (mut os, mut mem) = os_with_gdi();
        let mut cpu = CpuState::default();
        assert_eq!(nt_user_find_existing_cursor_icon(&mut os, &mut cpu, &mut mem).unwrap(), 0);
    }

    #[test]
    fn devmode_display_fields_land_at_their_offsets() {
        let mut mem = VirtualMemory::new();
        let base = 0x1_0000u64;
        mem.map(Region::new("dm", base, 0x1000, Perm::RW)).unwrap();
        let mode = DisplayMode { width: 1920, height: 1080, bpp: 32, frequency: 60, dpi: 96 };
        write_devmode(&mut mem, base, mode).unwrap();

        assert_eq!(mem.read_u16(base + DEVMODE_DMSIZE_OFF).unwrap(), DEVMODE_SIZE);
        assert_eq!(mem.read_u32(base + DEVMODE_DMFIELDS_OFF).unwrap(), DM_DISPLAY_FIELDS);
        assert_eq!(mem.read_u16(base + DEVMODE_DMLOGPIXELS_OFF).unwrap(), 96);
        assert_eq!(mem.read_u32(base + DEVMODE_DMBITSPERPEL_OFF).unwrap(), 32);
        assert_eq!(mem.read_u32(base + DEVMODE_DMPELSWIDTH_OFF).unwrap(), 1920);
        assert_eq!(mem.read_u32(base + DEVMODE_DMPELSHEIGHT_OFF).unwrap(), 1080);
        assert_eq!(mem.read_u32(base + DEVMODE_DMDISPLAYFREQUENCY_OFF).unwrap(), 60);
        assert_ne!(DEVMODE_DMPELSWIDTH_OFF, DEVMODE_DMPELSHEIGHT_OFF);
        assert_eq!(DEVMODE_DMPELSHEIGHT_OFF - DEVMODE_DMPELSWIDTH_OFF, 4);
    }

    fn synth_client_pfn() -> (VirtualMemory, u64, [u64; CLIENT_PFN_COUNT]) {
        const FUNCS: u64 = 0x2000_0000;
        const SLOTS: u64 = 0x2000_1000;
        const THUNKS: u64 = 0x2000_2000;
        const USER32: u64 = 0x3000_0000;
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("pfn", FUNCS, 0x3000, Perm::RWX)).unwrap();

        let mut procs = [0u64; CLIENT_PFN_COUNT];
        for (i, entry) in procs.iter_mut().enumerate() {
            if i == 6 {
                mem.write_u64(FUNCS + (i as u64) * 8, 0).unwrap();
                continue;
            }
            let proc_va = USER32 + 0x1000 + (i as u64) * 0x40;
            *entry = proc_va;
            let slot = SLOTS + (i as u64) * 8;
            mem.write_u64(slot, proc_va).unwrap();
            let thunk = THUNKS + (i as u64) * 0x10;
            let disp = (slot as i64 - (thunk as i64 + PFN_THUNK_LEN as i64)) as i32;
            mem.write_u8(thunk, PFN_THUNK_JMP[0]).unwrap();
            mem.write_u8(thunk + 1, PFN_THUNK_JMP[1]).unwrap();
            mem.write_u8(thunk + 2, PFN_THUNK_JMP[2]).unwrap();
            mem.write_u32(thunk + 3, disp as u32).unwrap();
            mem.write_u64(FUNCS + (i as u64) * 8, thunk).unwrap();
        }
        (mem, FUNCS, procs)
    }

    #[test]
    fn client_pfn_entries_resolve_through_their_thunks() {
        let (mem, funcs, procs) = synth_client_pfn();
        let (resolved, slots) = read_client_pfn_array(&mem, funcs).unwrap();
        assert!(slots[PFN_BUTTON] != 0, "a thunked entry reports the slot it jumps through");
        assert_eq!(resolved, procs, "every published index resolves to its own proc");
        assert_eq!(resolved[6], 0, "the unpublished index stays null");
        assert_ne!(resolved[PFN_BUTTON], resolved[PFN_EDIT]);
        assert_ne!(resolved[PFN_STATIC], resolved[PFN_LIST_BOX]);
    }

    #[test]
    fn client_pfn_resolution_is_honest_about_non_thunks() {
        let (mem, _, _) = synth_client_pfn();
        assert_eq!(read_client_pfn_array(&mem, 0).unwrap().0, [0u64; CLIENT_PFN_COUNT]);
        assert_eq!(resolve_client_pfn(&mem, 0).unwrap(), (0, 0));
        let direct = 0x2000_1000;
        assert_eq!(resolve_client_pfn(&mem, direct).unwrap(), (direct, 0));
    }

    #[test]
    fn builtin_classes_register_against_the_recovered_wndprocs() {
        let (_, _, procs) = synth_client_pfn();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.win32k_state.client_pfn_w = procs;
        os.win32k_state.user32_image = (0x3000_0000, 0x10_0000);
        register_builtin_classes(&mut os);

        let atom = os.win32k_state.class_by_name("BUTTON").expect("BUTTON registered");
        let class = os.win32k_state.class_by_atom(atom).unwrap();
        assert_eq!(class.wndproc, procs[PFN_BUTTON], "BUTTON is wired to index 7's proc");
        assert_eq!(class.style & 0x4000, 0x4000, "built-ins are CS_GLOBALCLASS");
        assert_eq!(os.win32k_state.class_by_name("button"), Some(atom));
        for (name, index) in BUILTIN_CLASSES {
            let a = os.win32k_state.class_by_name(name).unwrap_or_else(|| panic!("{name} registered"));
            assert_eq!(os.win32k_state.class_by_atom(a).unwrap().wndproc, procs[index]);
        }
        let atoms: std::collections::HashSet<u16> =
            os.win32k_state.classes.iter().map(|(a, _)| *a).collect();
        assert_eq!(atoms.len(), BUILTIN_CLASSES.len(), "every built-in got a distinct atom");

        register_builtin_classes(&mut os);
        assert_eq!(os.win32k_state.classes.len(), BUILTIN_CLASSES.len());
        assert_eq!(os.win32k_state.class_by_name("BUTTON"), Some(atom));
    }

    #[test]
    fn builtin_classes_refuse_procs_outside_user32() {
        let (_, _, procs) = synth_client_pfn();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.win32k_state.client_pfn_w = procs;
        os.win32k_state.user32_image = (0x9000_0000, 0x10_0000);
        register_builtin_classes(&mut os);
        assert!(os.win32k_state.classes.is_empty(), "no class trusts an out-of-image proc");

        os.win32k_state.user32_image = (0x9000_0000, 0);
        register_builtin_classes(&mut os);
        assert_eq!(os.win32k_state.classes.len(), BUILTIN_CLASSES.len());
    }

    fn child(os: &mut WinOs, parent: u32, rect: [i32; 4]) -> u32 {
        let hwnd = alloc_handle(os);
        os.win32k_state.windows.push((
            hwnd,
            Window {
                class_atom: 0,
                class_name: "C".into(),
                title: String::new(),
                rect,
                style: if parent == 0 { WS_VISIBLE } else { WS_CHILD | WS_VISIBLE },
                ex_style: 0,
                parent,
                shown: true,
                wndproc: 0,
                needs_paint: false,
                surface: None,
                extra: vec![0u8; 16],
                user_data: 0,
                id: 0,
                instance: 0,
                props: Vec::new(),
                dialog_info: 0,
                dialog_cancelled: false,
            },
        ));
        hwnd
    }

    #[test]
    fn a_winproc_handle_round_trips_only_through_the_flavour_it_was_allocated_for() {
        let mut st = Win32kState::default();
        const PROC_W: u64 = 0x4001_2345;
        const PROC_A: u64 = 0x4009_9999;

        assert_eq!(alloc_win_proc(&mut st, 0, false), 0, "a null procedure stays null");

        let hw = alloc_win_proc(&mut st, PROC_W, false);
        assert_ne!(hw, PROC_W, "a handle is not the procedure address");
        assert!(hw >= 2, "GetWindowLongPtrW keeps the raw value for 0 and 1");
        assert_eq!(get_dialog_proc(&st, hw, false), PROC_W, "SetWindowLongPtrW round-trips it");
        assert_eq!(get_dialog_proc(&st, hw, true), 0, "…and the ANSI flavour is not this one");

        assert_eq!(alloc_win_proc(&mut st, PROC_W, false), hw, "the same pair reuses its slot");
        assert_eq!(alloc_win_proc(&mut st, hw, false), hw, "an existing handle is left alone");

        let ha = alloc_win_proc(&mut st, PROC_A, true);
        assert_ne!(ha, hw);
        assert_eq!(get_dialog_proc(&st, ha, true), PROC_A);
        assert_eq!(get_dialog_proc(&st, ha, false), 0);

        assert_eq!(get_dialog_proc(&st, PROC_W, false), PROC_W, "a plain address is its own answer");
        assert_eq!(get_dialog_proc(&st, WINPROC_HANDLE_TAG | 0x800, false), 0, "an unissued slot");
    }

    #[test]
    fn get_window_walks_the_sibling_chain_a_dialog_is_searched_along() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let dlg = child(&mut os, 0, [0, 0, 100, 100]);
        let a = child(&mut os, dlg, [0, 0, 10, 10]);
        let b = child(&mut os, dlg, [0, 0, 10, 10]);
        let c = child(&mut os, dlg, [0, 0, 10, 10]);
        let inner = child(&mut os, b, [0, 0, 5, 5]);
        let st = &os.win32k_state;

        assert_eq!(window_relative(st, dlg, window_relative::CHILD), a);
        assert_eq!(window_relative(st, a, window_relative::HWND_NEXT), b);
        assert_eq!(window_relative(st, b, window_relative::HWND_NEXT), c);
        assert_eq!(window_relative(st, c, window_relative::HWND_NEXT), 0);
        assert_eq!(window_relative(st, c, window_relative::HWND_PREV), b);
        assert_eq!(window_relative(st, a, window_relative::HWND_PREV), 0);
        assert_eq!(window_relative(st, c, window_relative::HWND_FIRST), a);
        assert_eq!(window_relative(st, a, window_relative::HWND_LAST), c);
        assert_eq!(window_relative(st, a, window_relative::OWNER), 0, "a child has no owner");
        assert_eq!(window_relative(st, dlg, window_relative::OWNER), 0);
        assert_eq!(window_relative(st, inner, window_relative::HWND_NEXT), 0);
        assert_eq!(window_relative(st, 0xDEAD, window_relative::CHILD), 0);

        assert_eq!(hwnd_list(st, a, false), vec![a, b, c], "GetDlgItem sees every control once");
        assert_eq!(hwnd_list(st, dlg, true), vec![a, b, inner, c], "…and EnumChildWindows recurses");
        assert_eq!(hwnd_list(st, 0, false), vec![dlg], "a zero hwnd is the top-level chain");
    }

    #[test]
    fn build_hwnd_list_reserves_the_terminator_slot_its_caller_writes() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        mem.map_fixed(0x10_0000, 0x10_000, Perm::RW, "stack").unwrap();
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        let dlg = child(&mut os, 0, [0, 0, 100, 100]);
        let a = child(&mut os, dlg, [0, 0, 10, 10]);
        let b = child(&mut os, dlg, [0, 0, 10, 10]);

        let (buffer, size_out) = (0x2_0000u64, 0x2_0800u64);
        let mut cpu = CpuState::default();
        let mut call = |cpu: &mut CpuState, mem: &mut VirtualMemory, count: u64| {
            cpu.set_reg(Reg::Rdx, a as u64);
            cpu.set_reg(Reg::R8, 0);
            mem.write_u64(0x10_8000 + 0x28, 0).unwrap();
            mem.write_u64(0x10_8000 + 0x30, count).unwrap();
            mem.write_u64(0x10_8000 + 0x38, buffer).unwrap();
            mem.write_u64(0x10_8000 + 0x40, size_out).unwrap();
            nt_user_build_hwnd_list(&mut os, cpu, mem).unwrap()
        };

        assert_eq!(call(&mut cpu, &mut mem, 2), STATUS_BUFFER_TOO_SMALL, "two windows need three");
        assert_eq!(mem.read_u32(size_out).unwrap(), 3, "…and the retry size says so");

        assert_eq!(call(&mut cpu, &mut mem, 3), 0);
        assert_eq!(mem.read_u32(size_out).unwrap(), 3);
        assert_eq!(mem.read_u64(buffer).unwrap(), a as u64);
        assert_eq!(mem.read_u64(buffer + 8).unwrap(), b as u64);
    }

    #[test]
    fn window_properties_round_trip_per_window() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let a = child(&mut os, 0, [0, 0, 100, 100]);
        let b = child(&mut os, 0, [0, 0, 100, 100]);
        let name = 0x2_0100u64;
        for (i, u) in "FileOpenDlgInfos".encode_utf16().enumerate() {
            mem.write_u16(name + i as u64 * 2, u).unwrap();
        }
        mem.write_u16(name + 32, 0).unwrap();

        let set = |os: &mut WinOs, mem: &mut VirtualMemory, h: u32, n: u64, v: u64| {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, h as u64);
            cpu.set_reg(exemu_core::Reg::Rdx, n);
            cpu.set_reg(exemu_core::Reg::R8, v);
            nt_user_set_prop(os, &mut cpu, mem).unwrap()
        };
        let get = |os: &mut WinOs, mem: &mut VirtualMemory, h: u32, n: u64| -> u64 {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, h as u64);
            cpu.set_reg(exemu_core::Reg::Rdx, n);
            nt_user_get_prop(os, &mut cpu, mem).unwrap();
            os.syscall_result64.take().unwrap_or(0)
        };

        assert_eq!(set(&mut os, &mut mem, a, name, 0xDEAD_BEEF_1234), 1, "SetProp reports TRUE");
        assert_eq!(get(&mut os, &mut mem, a, name), 0xDEAD_BEEF_1234, "GetProp reads it back");
        assert_eq!(get(&mut os, &mut mem, b, name), 0, "…and it is per window");
        set(&mut os, &mut mem, a, 0xC123, 7);
        assert_eq!(get(&mut os, &mut mem, a, 0xC123), 7, "MAKEINTATOM keys work");
        assert_eq!(get(&mut os, &mut mem, a, name), 0xDEAD_BEEF_1234, "…without colliding");
        set(&mut os, &mut mem, a, name, 9);
        assert_eq!(get(&mut os, &mut mem, a, name), 9, "SetProp replaces");
        let mut cpu = CpuState::default();
        cpu.set_rsp(0x2_0800);
        cpu.set_reg(exemu_core::Reg::R10, a as u64);
        cpu.set_reg(exemu_core::Reg::Rdx, name);
        nt_user_remove_prop(&mut os, &mut cpu, &mut mem).unwrap();
        assert_eq!(os.syscall_result64.take(), Some(9), "RemoveProp returns the value");
        assert_eq!(get(&mut os, &mut mem, a, name), 0, "…and it is gone");
    }

    #[test]
    fn get_full_window_handle_widens_a_live_window_to_itself() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let hwnd = child(&mut os, 0, [0, 0, 100, 100]);
        let call = |os: &mut WinOs, mem: &mut VirtualMemory, h: u64| -> u32 {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, h);
            cpu.set_reg(exemu_core::Reg::Rdx, call_hwnd::GET_FULL_WINDOW_HANDLE);
            nt_user_call_hwnd(os, &mut cpu, mem).unwrap()
        };
        assert_eq!(call(&mut os, &mut mem, hwnd as u64), hwnd, "a live handle widens to itself");
        assert_eq!(call(&mut os, &mut mem, 0xDEAD), 0, "an unknown handle stays 0");
    }

    #[test]
    fn a_run_with_no_window_host_is_handed_wm_quit_not_an_untouched_msg() {
        const WM_QUIT: u32 = 0x0012;
        const POISON: u64 = 0xDEAD_BEEF_DEAD_BEEF;
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let lp = 0x2_0100u64;
        mem.write_u64(lp, POISON).unwrap();
        mem.write_u32(lp + 8, 0xC0DE).unwrap();

        let call = |os: &mut WinOs, mem: &mut VirtualMemory, index_get: bool| -> u32 {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, lp);
            if index_get {
                nt_user_get_message(os, &mut cpu, mem).unwrap()
            } else {
                os.syscall_guest_rsp = 0x2_0800;
                mem.write_u64(0x2_0800 + 0x28, 0).unwrap();
                nt_user_peek_message(os, &mut cpu, mem).unwrap()
            }
        };

        assert_eq!(call(&mut os, &mut mem, true), 0, "GetMessage reports the quit");
        assert_eq!(mem.read_u64(lp).unwrap(), 0, "hwnd — a thread message, so NULL");
        assert_eq!(mem.read_u32(lp + 8).unwrap(), WM_QUIT, "…and the message really is WM_QUIT");

        mem.write_u64(lp, POISON).unwrap();
        mem.write_u32(lp + 8, 0xC0DE).unwrap();
        assert_eq!(call(&mut os, &mut mem, false), 1, "PeekMessage found a message");
        assert_eq!(mem.read_u32(lp + 8).unwrap(), WM_QUIT, "…the same WM_QUIT");

        assert_eq!(call(&mut os, &mut mem, true), 0);
        assert_eq!(mem.read_u32(lp + 8).unwrap(), WM_QUIT, "…on every later round too");
    }

    #[test]
    fn nt_user_post_message_queues_and_a_posted_quit_stays_last() {
        const WM_QUIT: u32 = 0x0012;
        const WM_COMMAND: u32 = 0x0111;
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let hwnd = child(&mut os, 0, [0, 0, 100, 100]);

        let post = |os: &mut WinOs, mem: &mut VirtualMemory, h: u64, m: u32, w: u64| -> u32 {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, h);
            cpu.set_reg(exemu_core::Reg::Rdx, m as u64);
            cpu.set_reg(exemu_core::Reg::R8, w);
            cpu.set_reg(exemu_core::Reg::R9, 0);
            nt_user_post_message(os, &mut cpu, mem).unwrap()
        };

        assert_eq!(post(&mut os, &mut mem, hwnd as u64, WM_COMMAND, 2), 1, "posted");
        assert_eq!(post(&mut os, &mut mem, 0, WM_QUIT, 7), 1, "…and so is a quit");
        assert_eq!(post(&mut os, &mut mem, 0xDEAD, WM_COMMAND, 0), 0, "…but not to a dead hwnd");

        let first = os.msg_next().expect("the queued command");
        assert_eq!((first.hwnd, first.message, first.wparam), (hwnd as u64, WM_COMMAND, 2));
        let last = os.msg_next().expect("then the quit");
        assert_eq!((last.message, last.wparam), (WM_QUIT, 7), "with the posted exit code");
        assert!(os.msg_next().is_none(), "and nothing after it");
    }

    #[test]
    fn an_unattended_dialog_is_closed_and_then_destroyed() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let plain = child(&mut os, 0, [0, 0, 100, 100]);
        let dialog = child(&mut os, 0, [0, 0, 100, 100]);
        os.win32k_state.window_mut(dialog).unwrap().dialog_info = 0x4000_0000;
        os.threads[os.current].quit_code = Some(0);

        cancel_unattended_dialog(&mut os);
        let m = os.msg_next().expect("a WM_CLOSE was posted");
        assert_eq!((m.hwnd, m.message), (dialog as u64, WM_CLOSE), "to the dialog, not {plain:#x}");
        assert!(os.win32k_state.window(dialog).is_some(), "asking does not destroy it");

        os.threads[os.current].quit_code = Some(0);
        cancel_unattended_dialog(&mut os);
        assert!(os.win32k_state.window(dialog).is_none(), "the dialog is gone");
        assert!(os.win32k_state.window(plain).is_some(), "an ordinary window is not");
        assert!(os.threads[os.current].msgs.is_empty(), "and nothing more was invented");

        cancel_unattended_dialog(&mut os);
        assert!(os.threads[os.current].msgs.is_empty());
    }

    #[test]
    fn is_child_reads_hwnd_as_the_parent_and_param_as_the_child() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let panel = child(&mut os, top, [10, 10, 200, 150]);
        let button = child(&mut os, panel, [5, 5, 60, 24]);
        let other = child(&mut os, 0, [0, 0, 100, 100]);

        let is_child = |os: &mut WinOs, mem: &mut VirtualMemory, parent: u64, kid: u64| -> u32 {
            let mut cpu = CpuState::default();
            cpu.set_rsp(0x2_0800);
            cpu.set_reg(exemu_core::Reg::R10, parent);
            cpu.set_reg(exemu_core::Reg::Rdx, kid);
            cpu.set_reg(exemu_core::Reg::R8, call_hwnd_param::IS_CHILD);
            nt_user_call_hwnd_param(os, &mut cpu, mem).unwrap()
        };

        assert_eq!(is_child(&mut os, &mut mem, top as u64, panel as u64), 1, "a direct child");
        assert_eq!(is_child(&mut os, &mut mem, top as u64, button as u64), 1, "…however deeply nested");
        assert_eq!(is_child(&mut os, &mut mem, panel as u64, button as u64), 1, "and at every level");
        assert_eq!(is_child(&mut os, &mut mem, panel as u64, top as u64), 0, "a parent is not its child's child");
        assert_eq!(is_child(&mut os, &mut mem, button as u64, top as u64), 0, "…transitively either");

        assert_eq!(is_child(&mut os, &mut mem, top as u64, other as u64), 0, "different tree");
        assert_eq!(is_child(&mut os, &mut mem, top as u64, top as u64), 0, "a window is not its own child");
        assert_eq!(is_child(&mut os, &mut mem, 0xDEAD, button as u64), 0, "an unknown parent");
        assert_eq!(is_child(&mut os, &mut mem, top as u64, 0xDEAD), 0, "an unknown child");
        assert_eq!(is_child(&mut os, &mut mem, top as u64, 0), 0, "a null child — what a stale MSG carries");
    }

    #[test]
    fn a_child_renders_into_its_top_level_ancestors_surface() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [100, 100, 400, 300]);
        let panel = child(&mut os, top, [10, 20, 200, 150]);
        let button = child(&mut os, panel, [5, 5, 60, 24]);

        let st = &os.win32k_state;
        assert_eq!(st.surface_owner(top), top, "a top-level window owns its surface");
        assert_eq!(st.surface_owner(panel), top, "a child renders into its ancestor's");
        assert_eq!(st.surface_owner(button), top, "…however deep it is nested");

        assert_eq!(st.client_origin(top), (0, 0));
        assert_eq!(st.client_origin(panel), (10, 20));
        assert_eq!(st.client_origin(button), (15, 25), "origins accumulate down the chain");

        assert_eq!(st.window_visible_rect(button), [15, 25, 75, 49]);
        assert_eq!(st.window_visible_rect(top), [0, 0, 400, 300]);
    }

    #[test]
    fn a_child_is_clipped_to_every_ancestor() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 200, 100]);
        let panel = child(&mut os, top, [50, 20, 100, 60]);
        let wide = child(&mut os, panel, [80, 50, 200, 200]);
        assert_eq!(
            os.win32k_state.window_visible_rect(wide),
            [130, 70, 150, 80],
            "clipped to the panel's right/bottom edge, not the top-level window's"
        );
        let gone = child(&mut os, panel, [500, 500, 20, 20]);
        let r = os.win32k_state.window_visible_rect(gone);
        assert!(r[2] <= r[0] || r[3] <= r[1], "a fully clipped child has an empty rect: {r:?}");
    }

    #[test]
    fn window_from_point_finds_the_deepest_topmost_child() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let panel = child(&mut os, top, [10, 20, 200, 150]);
        let button = child(&mut os, panel, [5, 5, 60, 24]);
        let overlay = child(&mut os, top, [100, 100, 80, 40]);
        let st = &os.win32k_state;

        assert_eq!(st.window_from_point(300, 250, &[]), top, "bare client area → the window");
        assert_eq!(st.window_from_point(150, 40, &[]), panel, "inside the panel → the panel");
        assert_eq!(st.window_from_point(20, 30, &[]), button, "inside the button → the button");
        assert_eq!(st.window_from_point(120, 110, &[]), overlay, "the newer sibling is on top");
        assert_eq!(st.window_from_point(500, 500, &[]), 0, "outside every window → nothing");

        assert_eq!(st.window_from_point(20, 30, &[button]), panel, "skip the button → the panel");
        assert_eq!(
            st.window_from_point(20, 30, &[button, panel]),
            top,
            "skip both → the top-level window"
        );
        assert_eq!(st.child_window_from_point(top, 20, 30), panel);
        assert_eq!(st.child_window_from_point(panel, 20, 30), button);
    }

    #[test]
    fn a_hidden_window_is_not_hit() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let panel = child(&mut os, top, [10, 20, 200, 150]);
        os.win32k_state.window_mut(panel).unwrap().shown = false;
        assert_eq!(
            os.win32k_state.window_from_point(150, 40, &[]),
            top,
            "a hidden child is skipped and the point lands on its parent"
        );
    }

    #[test]
    fn client_mouse_messages_map_onto_their_non_client_twins() {
        use crate::gdi::{WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE};
        assert_eq!(WM_MOUSEMOVE as u32 - NC_MOUSE_DELTA, 0x00a0, "WM_NCMOUSEMOVE");
        assert_eq!(WM_LBUTTONDOWN as u32 - NC_MOUSE_DELTA, 0x00a1, "WM_NCLBUTTONDOWN");
        assert_eq!(WM_LBUTTONUP as u32 - NC_MOUSE_DELTA, 0x00a2, "WM_NCLBUTTONUP");
        assert!((WM_MOUSEFIRST..=WM_MOUSELAST_NC).contains(&(WM_LBUTTONUP as u32)));
    }

    #[test]
    fn packed_points_survive_negative_coordinates() {
        for (x, y) in [(0, 0), (150, 90), (-3, 7), (12, -40), (-1, -1)] {
            let lp = pack_point(x, y);
            assert_eq!((lo_word_i32(lp), hi_word_i32(lp)), (x, y), "round-trip ({x}, {y})");
        }
    }

    #[test]
    fn the_capture_takes_the_mouse_regardless_of_the_point() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let button = child(&mut os, top, [24, 200, 140, 32]);
        os.win32k_state.capture = button;
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        let ev = exemu_core::InputEvent::MouseButton {
            hwnd: 0,
            button: exemu_core::MouseButton::Left,
            down: false,
            x: 300,
            y: 40,
        };
        let installed = route_raw_input(&mut os, &mut cpu, &mut mem, 0, ev).expect("routes");
        assert!(!installed, "the capture path never asks WM_NCHITTEST");
        let m = os.msg_next().expect("the button-up was posted");
        assert_eq!(m.hwnd, button as u64, "…to the capture window, not the one under the cursor");
        assert_eq!(m.message, crate::gdi::WM_LBUTTONUP as u32);
        assert_eq!(
            (lo_word_i32(m.lparam), hi_word_i32(m.lparam)),
            (300 - 24, 40 - 200),
            "in the capture window's own client coordinates"
        );
    }

    #[test]
    fn an_event_reaches_the_top_level_window_it_names() {
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let first = child(&mut os, 0, [0, 0, 400, 300]);
        let first_button = child(&mut os, first, [10, 10, 100, 40]);
        let second = child(&mut os, 0, [0, 0, 400, 300]);
        let second_button = child(&mut os, second, [10, 10, 100, 40]);

        let click = |hwnd| exemu_core::InputEvent::MouseButton {
            hwnd,
            button: exemu_core::MouseButton::Left,
            down: true,
            x: 50,
            y: 30,
        };
        let mut route = |os: &mut WinOs, hwnd| {
            route_raw_input(os, &mut cpu, &mut mem, 0, click(hwnd)).expect("routes");
            os.msg_next()
        };

        let m = route(&mut os, second).expect("the click was posted");
        assert_eq!(m.hwnd, second_button as u64, "the second window's control, not the first's");
        assert_eq!(m.message, crate::gdi::WM_LBUTTONDOWN as u32);
        assert_eq!(
            (lo_word_i32(m.lparam), hi_word_i32(m.lparam)),
            (40, 20),
            "in that control's own client coordinates"
        );

        let m = route(&mut os, first).expect("the click was posted");
        assert_eq!(m.hwnd, first_button as u64, "naming the first window still reaches it");

        let m = route(&mut os, 0).expect("the click was posted");
        assert_eq!(m.hwnd, first_button as u64, "an unnamed event keeps the old first-shown rule");

        assert!(route(&mut os, 0xDEAD_BEEF).is_none(), "a window win32k never made takes nothing");

        os.win32k_state.window_mut(second).unwrap().shown = false;
        assert!(route(&mut os, second).is_none(), "a hidden window is not a fallback for the first");
    }

    #[test]
    fn keys_stay_inside_the_window_the_event_names() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let first = child(&mut os, 0, [0, 0, 400, 300]);
        let first_edit = child(&mut os, first, [10, 10, 100, 20]);
        let second = child(&mut os, 0, [0, 0, 400, 300]);
        let second_edit = child(&mut os, second, [10, 10, 100, 20]);

        os.win32k_state.focus = first_edit;
        assert_eq!(keyboard_target(&os, 0), first_edit, "an unnamed key follows the focus");
        assert_eq!(keyboard_target(&os, first), first_edit);
        assert_eq!(
            keyboard_target(&os, second),
            second,
            "a key typed into the second window never lands in the first window's focus"
        );

        os.win32k_state.focus = second_edit;
        assert_eq!(keyboard_target(&os, second), second_edit);
        assert_eq!(keyboard_target(&os, first), first);
        assert_eq!(keyboard_target(&os, 0xDEAD_BEEF), 0, "a window win32k never made takes nothing");
    }

    #[test]
    fn a_window_with_a_wndproc_is_asked_where_the_point_landed() {
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let ev = exemu_core::InputEvent::MouseMove { hwnd: 0, x: 40, y: 40 };

        assert!(!route_raw_input(&mut os, &mut cpu, &mut mem, 0, ev).expect("routes"));
        let m = os.msg_next().expect("the move was posted");
        assert_eq!(m.hwnd, top as u64);
        assert_eq!(m.message, crate::gdi::WM_MOUSEMOVE as u32);

        os.win32k_state.window_mut(top).unwrap().wndproc = 0x1234_5678;
        let pending = PendingHitTest {
            ev,
            msg: crate::gdi::WM_MOUSEMOVE as u32,
            wparam: 0,
            hwnd: top,
            lp: 0,
            skipped: Vec::new(),
        };
        let armed = arm_hit_test(&mut os, &mut mem, &pending).expect("arms");
        let (proc, args) = armed.expect("a window with a WndProc is asked WM_NCHITTEST");
        assert_eq!(proc, 0x1234_5678, "…its own WndProc");
        assert_eq!(args[1], WM_NCHITTEST as u64, "…with WM_NCHITTEST");
        assert_eq!(
            (lo_word_i32(args[3]), hi_word_i32(args[3])),
            (40, 40),
            "…and the point in screen coordinates, not client"
        );
    }

    #[test]
    fn keys_follow_the_focus_then_the_active_window() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let edit = child(&mut os, top, [10, 10, 100, 20]);
        assert_eq!(keyboard_target(&os, 0), top, "no focus, no active → the shown top-level");
        os.win32k_state.active = top;
        assert_eq!(keyboard_target(&os, 0), top);
        os.win32k_state.focus = edit;
        assert_eq!(keyboard_target(&os, 0), edit, "the focus window wins");
        destroy_window(&mut os, edit);
        assert_eq!(os.win32k_state.focus, 0, "destroying the focus window clears it");
        assert_eq!(keyboard_target(&os, 0), top);
    }

    #[test]
    fn a_parent_cycle_terminates() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let a = child(&mut os, 0, [0, 0, 10, 10]);
        let b = child(&mut os, a, [1, 1, 5, 5]);
        os.win32k_state.window_mut(a).unwrap().parent = b;
        let _ = os.win32k_state.surface_owner(b);
        let _ = os.win32k_state.client_origin(b);
        assert!(!os.win32k_state.chain_visible(b), "a cycle never reaches a top level");
    }

    #[test]
    fn window_longs_cover_the_named_fields_and_the_extra_bytes() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let hwnd = child(&mut os, 0, [1, 2, 30, 40]);

        assert_eq!(get_window_long(&os, hwnd, GWL_STYLE), WS_VISIBLE as u64);
        assert_eq!(set_window_long(&mut os, hwnd, GWL_EXSTYLE, 0x20000), 0, "ex-style started 0");
        assert_eq!(get_window_long(&os, hwnd, GWL_EXSTYLE), 0x20000);

        const INFO: u64 = 0x4000_0001_7AA0;
        assert_eq!(get_window_long(&os, hwnd, 0), 0, "extra bytes start zeroed");
        assert_eq!(set_window_long(&mut os, hwnd, 0, INFO), 0);
        assert_eq!(get_window_long(&os, hwnd, 0), INFO, "a pointer survives the round trip");
        assert_eq!(set_window_long(&mut os, hwnd, 0, 1), INFO, "Set returns the previous value");

        assert_eq!(get_window_long(&os, hwnd, 4096), 0);
        assert_eq!(set_window_long(&mut os, hwnd, 4096, 0xFF), 0);
        assert_eq!(get_window_long(&os, hwnd, -999), 0);
        assert_eq!(get_window_long(&os, 0xDEAD, 0), 0, "an unknown hwnd reads nothing");
    }

    #[test]
    fn gdi_handles_encode_their_type_in_the_high_word() {
        for (slot, ty, _) in STOCK_OBJECTS {
            let handle = ((ty as u32) << 16) | slot as u32;
            assert_eq!(handle >> 16, ty as u32, "the high word is the type");
            assert_eq!((handle & 0xFFFF) as u64, slot, "the low word is the slot");
            assert_ne!(handle & 0xFFFF, 0, "slot 0 would be indistinguishable from NULL");
        }
        assert_eq!((gdi_type::DC as u32) << 16, 0x0001_0000);
    }

    #[test]
    fn colorref_converts_to_opaque_bgra() {
        assert_eq!(colorref_to_bgra(0x0020_4080), 0xFF80_4020);
        assert_eq!(colorref_to_bgra(0x0000_0000), 0xFF00_0000, "black stays opaque");
        assert_eq!(colorref_to_bgra(0x00FF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn pe_image_size_reads_the_mapped_header() {
        let mut mem = VirtualMemory::new();
        let base = 0x4000_0000u64;
        mem.map(Region::new("img", base, 0x1000, Perm::RW)).unwrap();
        assert_eq!(pe_image_size(&mem, 0), None, "a null base has no image");
        assert_eq!(pe_image_size(&mem, base), None, "an unsigned page is not a PE");
        mem.write_u16(base, 0x5A4D).unwrap();
        mem.write_u32(base + 0x3C, 0x80).unwrap();
        assert_eq!(pe_image_size(&mem, base), None, "MZ alone is not enough");
        mem.write_u32(base + 0x80, 0x0000_4550).unwrap();
        mem.write_u32(base + 0x80 + 24 + 56, 0x2A6000).unwrap();
        assert_eq!(pe_image_size(&mem, base), Some(0x2A6000));
    }

    fn write_class_name(mem: &mut VirtualMemory, us: u64, buffer: u64, name: &str) {
        let units: Vec<u16> = name.encode_utf16().collect();
        for (i, u) in units.iter().enumerate() {
            mem.write_u16(buffer + i as u64 * 2, *u).unwrap();
        }
        mem.write_u16(buffer + units.len() as u64 * 2, 0).unwrap();
        mem.write_u16(us, (units.len() * 2) as u16).unwrap();
        mem.write_u16(us + 2, (units.len() * 2 + 2) as u16).unwrap();
        mem.write_u64(us + 8, buffer).unwrap();
    }

    #[test]
    fn get_class_info_answers_what_the_class_was_registered_with() {
        let (mut os, mut mem) = os_with_gdi();
        let (wc_in, us, buffer, menu_in) = (0x10_1000u64, 0x10_1100u64, 0x10_1200u64, 0x10_1300u64);
        let (wc_out, menu_out, query_us) = (0x10_2000u64, 0x10_2100u64, 0x10_2200u64);
        write_class_name(&mut mem, us, buffer, "MenuClass");
        let registered = WndClassEx {
            style: 0x0b,
            wndproc: 0x0040_1005,
            cls_extra: 8,
            wnd_extra: 16,
            instance: 0x0040_0000,
            icon: 0x0001_0042,
            cursor: 0x0001_0043,
            background: 6,
            menu_name: 0x0040_3000,
            class_name: buffer,
            icon_sm: 0x0001_0044,
        };
        registered.write(&mut mem, wc_in).unwrap();
        let menu = ClientMenuName { name_a: 0x0040_3100, name_w: 0x0040_3200, name_us: 0x0040_3300 };
        menu.write(&mut mem, menu_in).unwrap();

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, wc_in);
        cpu.set_reg(Reg::Rdx, us);
        cpu.set_reg(Reg::R8, 0);
        cpu.set_reg(Reg::R9, menu_in);
        let atom = nt_user_register_class_ex_wow(&mut os, &mut cpu, &mut mem).unwrap();
        assert_ne!(atom, 0);

        let query_buffer = 0x10_2300u64;
        write_class_name(&mut mem, query_us, query_buffer, "menuclass");
        for ansi in [false, true] {
            mem.write(wc_out, &[0xA5; 0x50]).unwrap();
            mem.write(menu_out, &[0xA5; 0x18]).unwrap();
            cpu.set_reg(Reg::R10, 0x0040_0000);
            cpu.set_reg(Reg::Rdx, query_us);
            cpu.set_reg(Reg::R8, wc_out);
            cpu.set_reg(Reg::R9, menu_out);
            mem.write_u64(0x10_8000 + 0x28, u64::from(ansi) | 0xFFFF_FFFF_0000_0000).unwrap();
            assert_eq!(nt_user_get_class_info_ex(&mut os, &mut cpu, &mut mem).unwrap(), atom);

            let got = WndClassEx::read(&mem, wc_out).unwrap();
            assert_eq!(
                got.menu_name,
                if ansi { menu.name_a } else { menu.name_w },
                "lpszMenuName is the client's own menu-name pointer for the charset asked; \
                 user32's WIN_CreateWindowEx hands it straight to LoadMenuW"
            );
            assert_eq!(
                got,
                WndClassEx { menu_name: got.menu_name, class_name: query_buffer, ..registered },
                "every other field is the registered one, the class name is the caller's buffer"
            );
            assert_eq!(mem.read_u32(wc_out).unwrap(), 0xA5A5_A5A5, "cbSize is the caller's");
            assert_eq!(ClientMenuName::read(&mem, menu_out).unwrap(), menu);
        }

        mem.write(wc_out, &[0xA5; 0x50]).unwrap();
        write_class_name(&mut mem, query_us, query_buffer, "NoSuchClass");
        assert_eq!(nt_user_get_class_info_ex(&mut os, &mut cpu, &mut mem).unwrap(), 0);
        assert_eq!(
            mem.read_u64(wc_out + 0x38).unwrap(),
            0xA5A5_A5A5_A5A5_A5A5,
            "an unknown class writes nothing"
        );
    }

    fn window_for_create(wndproc: u64) -> (WinOs, VirtualMemory, u32) {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.win32k_state.classes.push((
            CLASS_ATOM_BASE,
            Class {
                name: "TestClass".into(),
                wndproc,
                style: 0,
                background: 0,
                wnd_extra: 16,
                client: ClassClient::default(),
            },
        ));
        let hwnd = alloc_handle(&mut os);
        os.win32k_state.windows.push((
            hwnd,
            Window {
                class_atom: CLASS_ATOM_BASE,
                class_name: "TestClass".into(),
                title: "Title".into(),
                rect: [10, 20, 300, 200],
                style: 0x5000_0000,
                ex_style: 0x8,
                parent: 0x1234,
                shown: false,
                wndproc,
                needs_paint: false,
                surface: None,
                extra: vec![0u8; 16],
                user_data: 0,
                id: 0x65,
                instance: 0x1_4000_0000,
                props: Vec::new(),
                dialog_info: 0,
                dialog_cancelled: false,
            },
        ));
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", 0x10_0000, 0x10_000, Perm::RW)).unwrap();
        (os, mem, hwnd)
    }

    #[test]
    fn create_struct_lands_at_its_abi_offsets() {
        const WNDPROC: u64 = 0x1_4000_1000;
        let (mut os, mut mem, hwnd) = window_for_create(WNDPROC);
        let guest_rsp = 0x10_8000u64;
        os.set_syscall_guest_rsp_for_test(guest_rsp);
        let mut cpu = CpuState::default();

        let info = CreateInfo {
            create_params: 0xDEAD_BEEF,
            instance: 0x1_4000_0000,
            menu: 0x65,
            parent: 0x1234,
            rect: [10, 20, 300, 200],
            style: 0x5000_0000,
            ex_style: 0x8,
            title: "Title",
            class_name: "TestClass",
        };
        assert!(dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap());

        let cs = (guest_rsp - CREATE_SCRATCH) & !0xf;
        assert_eq!(mem.read_u64(cs + CS64.lp_create_params).unwrap(), 0xDEAD_BEEF);
        assert_eq!(mem.read_u64(cs + CS64.hinstance).unwrap(), 0x1_4000_0000);
        assert_eq!(mem.read_u64(cs + CS64.hmenu).unwrap(), 0x65);
        assert_eq!(mem.read_u64(cs + CS64.hwnd_parent).unwrap(), 0x1234);
        assert_eq!(mem.read_u32(cs + CS64.cy).unwrap(), 200);
        assert_eq!(mem.read_u32(cs + CS64.cx).unwrap(), 300);
        assert_eq!(mem.read_u32(cs + CS64.y).unwrap(), 20);
        assert_eq!(mem.read_u32(cs + CS64.x).unwrap(), 10);
        assert_eq!(mem.read_u32(cs + CS64.style).unwrap(), 0x5000_0000);
        assert_eq!(mem.read_u32(cs + CS64.dw_ex_style).unwrap(), 0x8);

        let read = |p: u64| {
            let mut s = String::new();
            for i in 0.. {
                match mem.read_u16(p + i * 2).unwrap() {
                    0 => break,
                    c => s.push(char::from_u32(c as u32).unwrap()),
                }
            }
            s
        };
        let name = mem.read_u64(cs + CS64.lpsz_name).unwrap();
        let class = mem.read_u64(cs + CS64.lpsz_class).unwrap();
        assert_eq!(read(name), "Title", "lpszName is a NUL-terminated copy");
        assert_eq!(read(class), "TestClass", "lpszClass is a NUL-terminated copy");
        assert!(name >= cs + CS64.size && class > name, "the names follow the struct");
        assert!(
            class < guest_rsp,
            "the whole scratch stays below the interrupted syscall's stack pointer"
        );

        assert_eq!(cpu.rip, WNDPROC, "WM_NCCREATE goes to the class WndProc first");
        assert_eq!(cpu.reg(Reg::Rcx), hwnd as u64);
        assert_eq!(cpu.reg(Reg::Rdx), WM_NCCREATE as u64);
        assert_eq!(cpu.reg(Reg::R9), cs, "lParam is the CREATESTRUCTW");
        assert!(cpu.rsp() < cs, "the callback frame cannot overwrite the struct");
    }

    #[test]
    fn create_struct_reports_a_missing_name_as_null() {
        let (mut os, mut mem, hwnd) = window_for_create(0x1_4000_1000);
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        let mut cpu = CpuState::default();
        let info = CreateInfo {
            create_params: 0,
            instance: 0,
            menu: 0,
            parent: 0,
            rect: [0, 0, 1, 1],
            style: 0,
            ex_style: 0,
            title: "",
            class_name: "msctls_progress32",
        };
        dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap();
        let cs = (0x10_8000u64 - CREATE_SCRATCH) & !0xf;
        assert_eq!(mem.read_u64(cs + CS64.lpsz_name).unwrap(), 0);
        assert_eq!(
            mem.read_u64(cs + CS64.lpsz_class).unwrap(),
            cs + CS64.size,
            "the class name takes the start of the string area when there is no window name"
        );
    }

    #[test]
    fn a_classless_window_gets_no_creation_pair() {
        let (mut os, mut mem, hwnd) = window_for_create(0);
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        let mut cpu = CpuState::default();
        let info = CreateInfo {
            create_params: 0,
            instance: 0,
            menu: 0,
            parent: 0,
            rect: [0, 0, 1, 1],
            style: 0,
            ex_style: 0,
            title: "",
            class_name: "Unregistered",
        };
        assert!(!dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap());
        assert_eq!(cpu.rip, 0, "nothing was seated");
    }

    #[test]
    fn a_wow64_process_gets_its_creation_pair_through_a_client_callback() {
        use crate::wow64::{cb_frame, win_proc_params as p};
        const WNDPROC: u64 = 0x0040_1000;
        const DISPATCHER: u64 = 0x6001_2345;
        let info = CreateInfo {
            create_params: 0,
            instance: 0,
            menu: 0,
            parent: 0,
            rect: [0, 0, 1, 1],
            style: 0,
            ex_style: 0,
            title: "",
            class_name: "TestClass",
        };

        let (mut os, mut mem, hwnd) = window_for_create(WNDPROC);
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        let mut cpu = CpuState::default();
        assert!(dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap());
        assert_eq!(cpu.rip, WNDPROC, "a 64-bit process calls the WndProc directly");

        let (mut os, mut mem, hwnd) = window_for_create(WNDPROC);
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        os.set_wow64_peb32(0x7f00_8000);
        os.set_client_callback_dispatcher(DISPATCHER);
        let mut cpu = CpuState::default();
        assert!(os.can_call_client(), "a WoW64 process with a published dispatcher can call back");
        assert!(dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap());

        assert_eq!(cpu.rip, DISPATCHER, "the guest resumes at KiUserCallbackDispatcher");
        let frame = cpu.rsp();
        assert_eq!(frame % 16, 0, "16-byte aligned, so its `call` leaves the callee aligned");
        assert_eq!(
            mem.read_u32(frame + cb_frame::ID).unwrap() as u64,
            u64::from(crate::wow64::NT_USER_CALL_WIN_PROC),
            "…asking for NtUserCallWinProc",
        );
        assert_eq!(mem.read_u32(frame + cb_frame::LEN).unwrap(), p::CALL_LEN);

        let params = mem.read_u64(frame + cb_frame::ARGS).unwrap();
        assert!(params > frame, "the block sits above the frame the callee grows down from");
        assert_eq!(mem.read_u64(params + p::FUNC).unwrap(), WNDPROC);
        assert_eq!(mem.read_u64(params + p::PROC_W).unwrap(), WNDPROC, "the pointer user32 calls");
        assert_eq!(mem.read_u64(params + p::HWND).unwrap(), hwnd as u64);
        assert_eq!(mem.read_u32(params + p::MSG).unwrap(), WM_NCCREATE);
        assert_eq!(mem.read_u64(params + p::WPARAM).unwrap(), 0);
        assert_eq!(mem.read_u32(params + p::SIZE).unwrap(), 0, "no packed message data");
        assert_eq!(mem.read_u32(params + p::ANSI).unwrap(), 0);
        assert_eq!(mem.read_u32(params + p::DPI_CONTEXT).unwrap(), crate::wow64::NTUSER_DPI_UNAWARE);

        let cs = mem.read_u64(params + p::LPARAM).unwrap();
        assert!(cs <= u32::MAX as u64, "a 32-bit WndProc must be able to hold the lParam");
        assert_eq!(mem.read_u32(cs + CS32.style).unwrap(), 0);
        let class = mem.read_u32(cs + CS32.lpsz_class).unwrap() as u64;
        assert_eq!(class, cs + CS32.size, "lpszClass follows the 0x30-byte 32-bit struct");
        let mut name = String::new();
        for i in 0.. {
            match mem.read_u16(class + i * 2).unwrap() {
                0 => break,
                c => name.push(char::from_u32(c as u32).unwrap()),
            }
        }
        assert_eq!(name, "TestClass");

        let ret = 0x30_0000u64;
        mem.map(Region::new("ret", ret, 0x1000, Perm::RW)).unwrap();
        mem.write_u64(ret, 0x1234_5678).unwrap();
        assert_eq!(os.client_callback_return(&mut cpu, &mut mem, ret, 8, 0).unwrap(), 0);
        assert_eq!(cpu.rip, DISPATCHER, "the second creation message is seated the same way");
        let params2 = mem.read_u64(cpu.rsp() + cb_frame::ARGS).unwrap();
        assert_eq!(mem.read_u32(params2 + p::MSG).unwrap(), crate::gdi::WM_CREATE as u32);

        assert_eq!(os.client_callback_return(&mut cpu, &mut mem, ret, 8, 0).unwrap(), 0);
        assert_eq!(cpu.reg(Reg::Rax), hwnd as u64, "NtUserCreateWindowEx still returns the HWND");

        assert_eq!(
            os.client_callback_return(&mut cpu, &mut mem, ret, 8, 0).unwrap(),
            0xC000_0258,
            "STATUS_NO_CALLBACK_ACTIVE",
        );
    }

    #[test]
    fn ntdll_copies_are_found_by_their_export_name() {
        fn fake_pe(mem: &mut VirtualMemory, base: u64, name: &str, size_of_image: u32) {
            mem.map(Region::new("img", base, 0x2000, Perm::RW)).unwrap();
            mem.write_u16(base, 0x5A4D).unwrap();
            mem.write_u32(base + 0x3C, 0x80).unwrap();
            mem.write_u32(base + 0x80, 0x0000_4550).unwrap();
            mem.write_u32(base + 0x80 + 24 + 56, size_of_image).unwrap();
            mem.write_u32(base + 0x80 + 24 + 112, 0x1000).unwrap();
            mem.write_u32(base + 0x1000 + 12, 0x1100).unwrap();
            for (i, b) in name.bytes().enumerate() {
                mem.write_u8(base + 0x1100 + i as u64, b).unwrap();
            }
            mem.write_u8(base + 0x1100 + name.len() as u64, 0).unwrap();
        }

        let mut mem = VirtualMemory::new();
        fake_pe(&mut mem, 0x1_0000, "ntdll.dll", 0x3EE000);
        fake_pe(&mut mem, 0x2_0000, "NTDLL.dll", 0x3EE000);
        fake_pe(&mut mem, 0x3_0000, "user32.dll", 0x3EE000);
        fake_pe(&mut mem, 0x4_0000, "ntdll.dll", 0x10_0000);

        assert_eq!(
            ntdll_copies(&mem, 0x1_0000, 0x3EE000),
            vec![0x2_0000],
            "only a same-size image that calls itself ntdll, and never the running one"
        );
        assert_eq!(pe_export_name(&mem, 0x3_0000).as_deref(), Some("user32.dll"));
        assert_eq!(pe_export_name(&mem, 0), None, "a null base names nothing");
    }

    #[test]
    fn client_pfn_mirroring_writes_the_same_rva_in_every_copy() {
        let mut mem = VirtualMemory::new();
        for base in [0x1_0000u64, 0x2_0000] {
            let name = "ntdll.dll";
            mem.map(Region::new("img", base, 0x2000, Perm::RW)).unwrap();
            mem.write_u16(base, 0x5A4D).unwrap();
            mem.write_u32(base + 0x3C, 0x80).unwrap();
            mem.write_u32(base + 0x80, 0x0000_4550).unwrap();
            mem.write_u32(base + 0x80 + 24 + 56, 0x3EE000).unwrap();
            mem.write_u32(base + 0x80 + 24 + 112, 0x1000).unwrap();
            mem.write_u32(base + 0x1000 + 12, 0x1100).unwrap();
            for (i, b) in name.bytes().enumerate() {
                mem.write_u8(base + 0x1100 + i as u64, b).unwrap();
            }
        }

        let mut slots = [0u64; CLIENT_PFN_COUNT];
        let mut procs = [0u64; CLIENT_PFN_COUNT];
        slots[PFN_BUTTON] = 0x1_0000 + 0x1800;
        procs[PFN_BUTTON] = 0xABCD_1234;
        slots[PFN_EDIT] = 0x9_9000;
        procs[PFN_EDIT] = 0xFFFF;

        mirror_client_pfn_to_ntdll_copies(&mut mem, 0x1_0000, &[(&slots, &procs)]);
        assert_eq!(
            mem.read_u64(0x2_0000 + 0x1800).unwrap(),
            0xABCD_1234,
            "the duplicate's slot now holds the proc user32 published"
        );
        assert_eq!(mem.read_u64(0x1_0000 + 0x1800).unwrap(), 0, "the running image is untouched");
    }

    fn message_call(
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        hwnd: u32,
        result_info: u64,
        ty: u64,
    ) -> (u32, usize) {
        const GUEST_RSP: u64 = MSG_CALL_STACK + 0x800;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, hwnd as u64);
        cpu.set_reg(Reg::Rdx, WM_NCCREATE as u64);
        cpu.set_reg(Reg::R8, 0x80);
        cpu.set_reg(Reg::R9, 0);
        mem.write_u64(GUEST_RSP + 0x28, result_info).unwrap();
        mem.write_u64(GUEST_RSP + 0x30, ty).unwrap();
        mem.write_u64(GUEST_RSP + 0x38, 0).unwrap();
        let status = nt_user_message_call(os, &mut cpu, mem).unwrap();
        (status, os.win32k_cb.len())
    }

    const MSG_CALL_STACK: u64 = 0x7000_0000;
    const MSG_CALL_SCRATCH: u64 = 0x7000_2000;
    const MSG_CALL_WNDPROC: u64 = 0x4000_1000;

    fn message_call_fixture() -> (WinOs, VirtualMemory, u32) {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", MSG_CALL_STACK, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", MSG_CALL_SCRATCH, 0x1000, Perm::RW)).unwrap();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let hwnd = child(&mut os, 0, [0, 0, 100, 100]);
        os.win32k_state.window_mut(hwnd).unwrap().wndproc = MSG_CALL_WNDPROC;
        os.set_syscall_guest_rsp_for_test(MSG_CALL_STACK + 0x800);
        (os, mem, hwnd)
    }

    #[test]
    fn a_message_call_query_type_never_reaches_a_wndproc() {
        let (mut os, mut mem, hwnd) = message_call_fixture();

        let (_, frames) = message_call(&mut os, &mut mem, hwnd, 0, message_call::SEND_MESSAGE);
        assert_eq!(frames, 1, "SendMessage runs the window's WndProc");

        for ty in message_call::NOT_A_MESSAGE {
            let (mut os, mut mem, hwnd) = message_call_fixture();
            let (status, frames) =
                message_call(&mut os, &mut mem, hwnd, MSG_CALL_SCRATCH, ty);
            assert_eq!(frames, 0, "type {ty:#x} is not a send, yet it ran a WndProc");
            assert_eq!(status, 0, "type {ty:#x} answers the honest zero");
        }

        for ty in [0x0000_1234, 0x0000_02b2, 0x0003_0003, 0xFFFF_FFFF] {
            let (mut os, mut mem, hwnd) = message_call_fixture();
            let (status, frames) = message_call(&mut os, &mut mem, hwnd, MSG_CALL_SCRATCH, ty);
            assert_eq!(frames, 0, "unknown type {ty:#x} ran a WndProc");
            assert_eq!(status, 0, "unknown type {ty:#x} answers the honest zero");
        }
    }

    #[test]
    fn the_spy_hooks_answer_without_delivering_anything() {
        let (mut os, mut mem, hwnd) = message_call_fixture();
        for ty in [message_call::SPY_ENTER, message_call::SPY_EXIT] {
            let (status, frames) = message_call(&mut os, &mut mem, hwnd, 0, ty);
            assert_eq!((status, frames), (0, 0), "spy hook {ty:#x} delivers nothing");
        }

        let (status, frames) =
            message_call(&mut os, &mut mem, hwnd, MSG_CALL_SCRATCH, message_call::SPY_GET_MSG_NAME);
        assert_eq!((status, frames), (0, 0), "the name query delivers nothing");
        let name = crate::api::read_astr(&mem, MSG_CALL_SCRATCH).unwrap();
        assert_eq!(name, format!("{WM_NCCREATE:#06x}"), "the query filled the caller's buffer");
    }

    #[test]
    fn the_kernel_side_window_procedures_do_not_call_the_application() {
        for ty in message_call::KERNEL_WND_PROCS {
            let (mut os, mut mem, hwnd) = message_call_fixture();
            let (_, frames) = message_call(&mut os, &mut mem, hwnd, 0, ty);
            assert_eq!(frames, 0, "kernel procedure {ty:#x} called the application's WndProc");
            assert_eq!(os.syscall_result64, Some(1), "type {ty:#x} answers WM_NCCREATE");
        }
    }
}
