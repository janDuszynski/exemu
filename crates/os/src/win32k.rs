//! win32k (USER/GDI) unix backend — the `NtUser*`/`NtGdi*` SSDT handlers
//! (roadmap W4.1 skeleton, W4.2 object model).
//!
//! Wine's `user32.dll`/`gdi32.dll` hold the *real* USER/GDI logic and import
//! ~470 `NtUser*`/`NtGdi*` calls from `win32u.dll`, which is a **pure syscall
//! shim** (1290 stubs, indices 0x1084–0x1601 — the `0x1000` table bit selects
//! this second SSDT). The kernel-side USER/GDI logic + display driver that
//! normally live in `win32u.so` become exemu's win32k handlers + a native Rust
//! driver (see `knowledge/w4-gui-design.know` §0/§2); exemu never loads
//! `win32u.so`, so there is no guest-visible driver-registration seam.
//!
//! **W4.1 gave the skeleton** valid-but-inert return values (a nonzero class
//! ATOM, HWND/HDC handles, 96 DPI, an empty message queue) so Wine's user32/
//! gdi32 stop null-dereferencing the syscall results. **W4.2 gives it a real
//! (still headless) object model:** a class registry (atom→[`Class`]), window
//! objects (hwnd→[`Window`]), and — the load-bearing part — every window-
//! lifecycle event marshalled from the recovered guest arg layout and pushed
//! through the injected [`exemu_core::UserDriver`]. Every index outside the
//! serviced set still falls to [`honest_stub`], which returns 0 (a null handle /
//! FALSE) so nothing pretends to have done work it didn't.
//!
//! **Corpus-safe:** the whole win32k table is reached only via a guest win32u
//! `SYSCALL`, which the emulated corpus never issues — the legacy `Gui` path in
//! `crate::win`/`crate::gdi` is untouched.

use exemu_core::{CpuState, Memory, Perm, Result, WindowParams};

use crate::api::read_wstr;
use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;

/// The win32u index range — the raw immediates (each carries the `0x1000` table
/// bit; `set_win32k_handler` masks it off before indexing).
const WIN32K_FIRST: u32 = 0x1084;
const WIN32K_LAST: u32 = 0x1601;

// --- win32u syscall indices (this pinned Wine build; each is the `mov eax,IDX`
//     immediate in the corresponding win32u.dll stub) ------------------------
const NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS: u32 = 0x147a;
const NT_USER_GET_SYSTEM_DPI_FOR_PROCESS: u32 = 0x144b;
const NT_USER_SET_PROCESS_DPI_AWARENESS_CONTEXT: u32 = 0x1577;
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
const NT_USER_TRANSLATE_MESSAGE: u32 = 0x15d8;
const NT_USER_DISPATCH_MESSAGE: u32 = 0x138b;

// --- cursor / display members (roadmap W4.7) ------------------------------
const NT_USER_GET_CURSOR: u32 = 0x13e7;
const NT_USER_GET_CURSOR_POS: u32 = 0x13ea;
const NT_USER_SET_CURSOR: u32 = 0x1546;
const NT_USER_SET_CURSOR_POS: u32 = 0x154a;
const NT_USER_CLIP_CURSOR: u32 = 0x1350;
const NT_USER_CHANGE_DISPLAY_SETTINGS: u32 = 0x1342;
const NT_USER_ENUM_DISPLAY_SETTINGS: u32 = 0x13c1;
const NT_USER_MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX: u32 = 0x14bb;

// --- input routing: hit-testing, capture, focus (roadmap W4.8 follow-up) -----
// Recovered the same way as every other index — the `mov eax, imm32` in that
// export's win32u stub — and cross-checked against the user32 wrapper that
// issues it (see [`abi`] and `crates/app/tests/win32k_abi.rs`):
//
//   user32!WindowFromPoint  @ 0x560a0: mov rax,rcx; shr rax,0x20; mov edx,eax;
//                                      jmp NtUserWindowFromPoint
//     — the whole body. **Hit-testing belongs to the kernel side**: user32 only
//       unpacks the by-value POINT into (x in ecx, y in edx) and tail-jumps.
//   user32!SetCapture / ReleaseCapture / SetFocus: bare `jmp` thunks.
//   user32!GetFocus  @ 0x2f4f0: xor ecx,ecx     ; jmp NtUserGetThreadState
//   user32!GetActiveWindow @ 0x2e330: mov ecx,1 ; jmp NtUserGetThreadState
//   user32!GetCapture      @ 0x2e5a0: mov ecx,2 ; jmp NtUserGetThreadState
const NT_USER_WINDOW_FROM_POINT: u32 = 0x15ff;
const NT_USER_CHILD_WINDOW_FROM_POINT_EX: u32 = 0x134b;
const NT_USER_SET_CAPTURE: u32 = 0x153a;
const NT_USER_RELEASE_CAPTURE: u32 = 0x1508;
const NT_USER_SET_FOCUS: u32 = 0x1557;
const NT_USER_SET_ACTIVE_WINDOW: u32 = 0x1532;
const NT_USER_GET_THREAD_STATE: u32 = 0x144e;
const NT_USER_GET_ANCESTOR: u32 = 0x13ce;

/// `NtUserGetThreadState(index)` selectors, recovered from the three user32
/// one-liners above.
mod thread_state {
    /// `GetFocus`.
    pub const FOCUS: u64 = 0;
    /// `GetActiveWindow`.
    pub const ACTIVE: u64 = 1;
    /// `GetCapture`.
    pub const CAPTURE: u64 = 2;
}

/// `NtUserMessageCall`'s **type** argument (the 6th slot). One syscall carries
/// the whole `SendMessage`/`DefWindowProc`/`CallWindowProc`/dispatch family, and
/// the type is what says which — recovered from the immediate each user32
/// wrapper stores at `[rsp+0x28]` right before the win32u thunk:
///
/// ```text
///   SendMessageW         mov [rsp+0x28], 0x2b1
///   SendMessageTimeoutW  mov [rsp+0x28], 0x2b3
///   SendNotifyMessageW   mov [rsp+0x28], 0x2b7
///   SendMessageCallbackW mov [rsp+0x28], 0x2b8
///   CallWindowProcW      mov [rsp+0x28], 0x2ab
///   DefWindowProcW       mov [rsp+0x28], 0x29e
///   (internal) dispatch_message, the tail of DispatchMessageW:
///                        mov [rsp+0x28], 0x3001
/// ```
///
/// **Getting this wrong is not cosmetic.** `DefWindowProcW` is *nothing but*
/// this syscall — the pinned user32 handles only five IME/syscommand messages
/// client-side and forwards everything else, `WM_NCHITTEST` included — so a
/// handler that re-dispatches type `0x29e` to the window's own WndProc calls the
/// proc that just called `DefWindowProc`, for ever.
mod message_call {
    /// `DefWindowProc{A,W}` — the kernel-side default window procedure.
    pub const DEF_WINDOW_PROC: u64 = 0x29e;
    /// `CallWindowProc{A,W}` — `resultInfo` arrives with the proc at offset 0.
    pub const CALL_WINDOW_PROC: u64 = 0x2ab;
    /// `SendMessage{A,W}`.
    pub const SEND_MESSAGE: u64 = 0x2b1;
    /// `SendMessageTimeout{A,W}`.
    pub const SEND_MESSAGE_TIMEOUT: u64 = 0x2b3;
    /// `SendNotifyMessage{A,W}`.
    pub const SEND_NOTIFY_MESSAGE: u64 = 0x2b7;
    /// `SendMessageCallback{A,W}`.
    pub const SEND_MESSAGE_CALLBACK: u64 = 0x2b8;
    /// The internal `dispatch_message` every `DispatchMessage{A,W}` that is not
    /// `WM_PAINT`/`WM_TIMER` lowers to.
    pub const DISPATCH_MESSAGE: u64 = 0x3001;
}

/// `CallWindowProc`'s `resultInfo` block starts with the procedure to call —
/// `user32!CallWindowProcW` stores its `lpPrevWndFunc` argument at offset 0 of
/// the block it hands the syscall (`mov [rsp+0x40], rax`, then
/// `lea rbx,[rsp+0x40]` as `resultInfo`). Nothing else in the block is filled by
/// the caller.
const WIN_PROC_PARAMS_FUNC: u64 = 0x00;

// --- NtGdi* indices (the win32u.dll `mov eax,IDX` immediates; spot-verified
//     against the pinned build's stubs — see the W4.3 static gdi32 contract).
//     gdi32!TextOutW→ExtTextOutW lowers to NtGdiExtTextOutW; gdi32!Rectangle
//     tail-calls NtGdiRectangle directly. Both carry the 0x1000 table bit.
const NT_GDI_EXT_TEXT_OUT_W: u32 = 0x11c9;
const NT_GDI_RECTANGLE: u32 = 0x1259;

// --- W4.8: the physdev primitive set Wine's own controls paint with ---------
// Recovered by tracing `comctl_sample`'s pump (`EXEMU_W32K_TRACE`) and reading
// the pinned gdi32/user32 wrappers those indices come from:
//   user32!FillRect  @ RVA 0x2dd40 -> SelectObject(hdc, hbr)
//                                     PatBlt(hdc, l, t, r-l, b-t, PATCOPY)
//                                     SelectObject(hdc, previous)
//   gdi32!PatBlt     @ RVA 0x2c490 -> tail-jmp NtGdiPatBlt, args untouched:
//                                     (hdc, x, y, cx, cy, rop) with cy/rop the
//                                     5th/6th (first two stack) arguments
//   gdi32!SelectObject @ RVA 0x39e20 -> NtGdiSelectBrush for a 0x10-typed handle
//   gdi32!CreateSolidBrush @ RVA 0x13e00 -> `xor edx,edx; jmp NtGdiCreateSolidBrush`
//   gdi32!SetTextColor @ RVA 0x3b670 / SetBkColor @ 0x3a260 ->
//                                     NtGdiGetAndSetDCDword(hdc, 0x66/0x64,
//                                                           color, &previous)
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

// --- TEXTMETRICW field offsets (documented Win32 layout; all LONG/WCHAR/BYTE,
//     so identical on 32- and 64-bit). `gdi32!GetTextMetricsW` (RVA 0x26290) is
//     `xor r8d,r8d; jmp NtGdiGetTextMetricsW`, so the caller's buffer arrives
//     untouched as arg1 and win32k fills it.
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

/// The stand-in font's cell metrics. exemu does not track HFONT selection yet
/// (design §5 defers it), so one cell stands in: 8 px wide, 16 px tall, the same
/// advance the deterministic `font8x8` fallback uses. A control that lays its
/// label out from these gets a sane box; a real per-HFONT metric set arrives with
/// font selection.
const STUB_FONT_CELL_W: u32 = 8;
const STUB_FONT_CELL_H: u32 = 16;
const STUB_FONT_DESCENT: u32 = 3;

/// `SIMPLEREGION` — the region-complexity result a successful clip operation
/// reports (`NULLREGION` = 1 means "the clip is now empty", `ERROR` = 0).
const SIMPLEREGION: u32 = 2;

/// `NtUserCallHwnd` / `NtUserCallHwndParam` / `NtUserCallOneParam` — the fan-in
/// multiplexers (roadmap W4.8; the call-number enums are recovered from user32,
/// see [`call_hwnd`]).
const NT_USER_CALL_HWND: u32 = 0x1332;
const NT_USER_CALL_HWND_PARAM: u32 = 0x1336;
const NT_USER_CALL_ONE_PARAM: u32 = 0x133d;
/// `NtUserSetWindowLong` / `NtUserSetWindowLongPtr` — the write half of the
/// `GetWindowLong*` family the multiplexers read.
const NT_USER_SET_WINDOW_LONG: u32 = 0x15a3;
const NT_USER_SET_WINDOW_LONG_PTR: u32 = 0x15a4;

// --- DC_ATTR (the guest-visible DC object) field offsets --------------------
// Recovered from the pinned gdi32: each accessor reaches its field through
// `get_dc_attr` (RVA 0x455f0), which walks the PEB+0xF8 handle table.
/// DC origin x — `gdi32!GetDCOrgEx` (RVA 0x23470) reads `[dc_attr+0x48]`.
const DC_ATTR_ORG_X: u64 = 0x48;
/// DC origin y — the dword after it.
const DC_ATTR_ORG_Y: u64 = 0x4C;
/// Background colour — `gdi32!GetBkColor` (RVA 0x22430) reads `[dc_attr+0x0c]`.
const DC_ATTR_BK_COLOR: u64 = 0x0C;
/// Text colour — `gdi32!GetTextColor` (RVA 0x25930) reads `[dc_attr+0x18]`.
const DC_ATTR_TEXT_COLOR: u64 = 0x18;

/// `NtGdiGetAndSetDCDword` selectors, from the immediates in gdi32's setters.
mod dc_dword {
    /// `SetBkColor` (`gdi32!SetBkColor` RVA 0x3a260: `mov edx, 0x64`).
    pub const BK_COLOR: u64 = 0x64;
    /// `SetTextColor` (`gdi32!SetTextColor` RVA 0x3b670: `mov edx, 0x66`).
    pub const TEXT_COLOR: u64 = 0x66;
}

/// `PATCOPY` — the raster op `FillRect` issues (`0x00F00021`): paint the
/// destination with the selected brush.
const PATCOPY: u32 = 0x00F0_0021;
/// `BLACKNESS` / `WHITENESS` — the two constant-fill raster ops.
const BLACKNESS: u32 = 0x0000_0042;
const WHITENESS: u32 = 0x00FF_0062;

// --- GDI shared handle-table contract (recovered from gdi32.dll disasm) -------
// gdi32's user-mode HDC decode (`get_gdi_client_ptr` @ RVA 0x455f0) reads the
// per-process handle-table base from PEB+0xF8 (via TEB gs:[0x30]+0x60→+0xF8),
// indexes `entry = base + (hdc & 0xFFFF) * 24`, then requires:
//   * byte[entry+0xE]  (type)       != 0
//   * word[entry+0xC]  (generation) == (hdc >> 16) & 0xFFFF   (only when the
//     handle's high 16 bits are non-zero — which they always are for a DC,
//     since the type prefilter demands bit 16 set)
//   * ptr [entry+0x10] (client obj) → a user-mode DC object whose
//       dword[+0x04] == 0, qword[+0xA8] == 0 (no open path),
//       qword[+0xB8] == 0 (no batch)  →  the direct-syscall fast path.
// We publish a real table + one minimal DC object per HDC so gdi32 stops
// short-circuiting draws to ERROR_INVALID_HANDLE and actually issues the
// NtGdi* syscalls this module services.
const GDI_PEB_TABLE_PTR_OFF: u64 = 0xF8;
const GDI_ENTRY_SIZE: u64 = 24;
const GDI_ENTRY_GENERATION_OFF: u64 = 0xC;
const GDI_ENTRY_TYPE_OFF: u64 = 0xE;
const GDI_ENTRY_OBJECT_OFF: u64 = 0x10;
/// Number of 24-byte slots in the published handle table. Only a handful of DCs
/// are ever live in the gate, but a full page's worth costs nothing.
const GDI_TABLE_SLOTS: u64 = 128;
/// Non-zero "slot in use" byte written at entry+0xE. gdi32 only tests it against
/// zero (a free slot); the *type* lives in the generation word, see [`gdi_type`].
const GDI_ENTRY_IN_USE: u8 = 0x01;
/// Size of one minimal user-mode GDI object (for a DC only offsets +4/+0xA8/
/// +0xB8 are read by gdi32; round up to cover them with slack). Brushes and pens
/// share the arena — nothing on the recovered paths dereferences theirs.
const GDI_DC_OBJECT_SIZE: u64 = 0x100;

/// GDI object types, as recovered from `gdi32!SelectObject` (RVA 0x39e20).
///
/// After validating the handle-table entry, `SelectObject` computes
/// `type = (byte[entry+0x0C] & 0x7f) << 16` — i.e. **the object type is the low
/// byte of the entry's generation word** — and dispatches on it:
/// `0x100000` → `NtGdiSelectBrush`, `0x300000`/`0x320000` → the pen path,
/// `0x0a0000` and below → bitmap/font/palette. The same word must equal
/// `handle >> 16` (the entry's generation check), so **a GDI handle is
/// `(type << 16) | slot`** and one word satisfies both gates. The pre-existing
/// HDC encoding (`0x0001_0000 | slot`) was already exactly this rule with
/// `type = 1`; naming it makes brushes and pens fall out.
mod gdi_type {
    /// A device context — what the `(hdc & 0x1F0000) == 0x10000` prefilter in
    /// `gdi32!get_dc_attr` demands.
    pub const DC: u16 = 0x01;
    /// A region (`SelectObject` sends `0x040000` to its clip-region arm).
    pub const REGION: u16 = 0x04;
    /// A palette. **Not** recovered from the binary — `SelectObject` never sees
    /// one (`SelectPalette` handles palettes) — so this is the documented NT GDI
    /// value, used only to make the stock-palette slot non-empty.
    pub const PALETTE: u16 = 0x08;
    /// A bitmap (`SelectObject` sends `0x090000` to `NtGdiSelectBitmap`).
    pub const BITMAP: u16 = 0x09;
    /// A font (`SelectObject` sends `0x0a0000` to `NtGdiSelectFont`).
    pub const FONT: u16 = 0x0a;
    /// A brush (`SelectObject` dispatches `0x100000` to `NtGdiSelectBrush`).
    pub const BRUSH: u16 = 0x10;
    /// A pen (`SelectObject` accepts `0x300000` and `0x320000`, the plain and
    /// extended pens; exemu mints the plain one).
    pub const PEN: u16 = 0x30;
}

// --- Stock objects: fixed handle-table slots, recovered from GetStockObject ---
//
// `gdi32!GetStockObject` (RVA 0x25610) does **not** issue a syscall. It maps the
// index to a fixed slot, reads `PEB[0xF8] + slot*24` directly, and — this is the
// load-bearing part — **executes `ud2` if that entry's in-use byte is zero**
// (the branch at RVA 0x256bb into the trap block at 0x4d770). A win32k that
// leaves the stock slots empty therefore does not merely return NULL: it crashes
// any Wine control that asks for a stock brush, pen or font, which is exactly
// what `ButtonWndProc` does while painting.
//
// The mapping, straight out of that disassembly:
//   index > 0x14 or index == 9      -> NULL (no table read)
//   index 0x0a  -> slot 0x2a (96 DPI) / 0x29    | the DPI-variant fonts, each of
//   index 0x0d  -> slot 0x2d (96 DPI) / 0x35    | which owns *two* slots chosen
//   index 0x10  -> slot 0x30 (96 DPI) / 0x36    | by `user32!GetDpiForSystem`
//   index 0x11  -> slot 0x31 (96 DPI) / 0x37    |
//   anything else -> slot = index + 0x20
// and the handle it returns is rebuilt as `(word[entry+0x0C] << 16) | slot` —
// the same `(type << 16) | slot` encoding as every other GDI handle.

/// First slot reserved for stock objects (`index + 0x20`).
const STOCK_SLOT_BASE: u64 = 0x20;
/// Last stock slot — `0x37`, the high-DPI variant of `DEFAULT_GUI_FONT`.
/// Dynamic allocation starts above it so nothing overwrites a stock entry.
const STOCK_SLOT_LAST: u64 = 0x37;

/// `(slot, type, brush COLORREF)` for every stock slot exemu publishes. The
/// colours are the documented stock-brush shades; a font/pen/palette slot has
/// none (`None`), and `NULL_BRUSH` deliberately has none either — an unregistered
/// brush handle is exactly the hollow brush [`nt_gdi_pat_blt`] treats as "paint
/// nothing", which is the correct behaviour for it.
const STOCK_OBJECTS: [(u64, u16, Option<u32>); 24] = [
    (0x20, gdi_type::BRUSH, Some(0x00FF_FFFF)), // WHITE_BRUSH
    (0x21, gdi_type::BRUSH, Some(0x00C0_C0C0)), // LTGRAY_BRUSH
    (0x22, gdi_type::BRUSH, Some(0x0080_8080)), // GRAY_BRUSH
    (0x23, gdi_type::BRUSH, Some(0x0040_4040)), // DKGRAY_BRUSH
    (0x24, gdi_type::BRUSH, Some(0x0000_0000)), // BLACK_BRUSH
    (0x25, gdi_type::BRUSH, None),              // NULL_BRUSH (hollow)
    (0x26, gdi_type::PEN, None),                // WHITE_PEN
    (0x27, gdi_type::PEN, None),                // BLACK_PEN
    (0x28, gdi_type::PEN, None),                // NULL_PEN
    (0x29, gdi_type::FONT, None),               // OEM_FIXED_FONT (non-96 DPI)
    (0x2a, gdi_type::FONT, None),               // OEM_FIXED_FONT (96 DPI)
    (0x2b, gdi_type::FONT, None),               // ANSI_FIXED_FONT
    (0x2c, gdi_type::FONT, None),               // ANSI_VAR_FONT
    (0x2d, gdi_type::FONT, None),               // SYSTEM_FONT (96 DPI)
    (0x2e, gdi_type::FONT, None),               // DEVICE_DEFAULT_FONT
    (0x2f, gdi_type::PALETTE, None),            // DEFAULT_PALETTE
    (0x30, gdi_type::FONT, None),               // SYSTEM_FIXED_FONT (96 DPI)
    (0x31, gdi_type::FONT, None),               // DEFAULT_GUI_FONT (96 DPI)
    (0x32, gdi_type::BRUSH, Some(0x00FF_FFFF)), // DC_BRUSH
    (0x33, gdi_type::PEN, None),                // DC_PEN
    (0x34, gdi_type::BITMAP, None),             // index 0x14, the last accepted
    (0x35, gdi_type::FONT, None),               // SYSTEM_FONT (non-96 DPI)
    (0x36, gdi_type::FONT, None),               // SYSTEM_FIXED_FONT (non-96 DPI)
    (0x37, gdi_type::FONT, None),               // DEFAULT_GUI_FONT (non-96 DPI)
];

/// The base of the Windows `RegisterClass` atom range (0xC000–0xFFFF).
const CLASS_ATOM_BASE: u16 = 0xC000;

/// `WS_VISIBLE` — set in a child control's creation style (a `WS_CHILD |
/// WS_VISIBLE` control is never given its own `ShowWindow` call), so window
/// visibility is seeded from it at creation.
const WS_VISIBLE: u32 = 0x1000_0000;
/// `WS_CHILD` — a child window's `hMenu` argument is its control id, not a menu.
const WS_CHILD: u32 = 0x4000_0000;

// --- WNDCLASSEXW (64-bit) field offsets the class registration reads ---------
/// `lpfnWndProc`.
const WNDCLASSEXW_WNDPROC: u64 = 0x08;
/// `style`.
const WNDCLASSEXW_STYLE: u64 = 0x04;
/// `cbWndExtra` — bytes of per-window scratch (`cbClsExtra` precedes it at
/// +0x10). The load-bearing field for a control's instance data.
const WNDCLASSEXW_CB_WND_EXTRA: u64 = 0x14;
/// `hbrBackground`.
const WNDCLASSEXW_BACKGROUND: u64 = 0x30;
/// Ceiling on a class's `cbWndExtra`, so a garbage read cannot ask for a huge
/// allocation per window. Real classes reserve a few pointers.
const WND_EXTRA_MAX: u32 = 4096;

// --- `GetWindowLong*` / `SetWindowLong*` negative offsets (documented Win32) --
/// `GWLP_WNDPROC`.
const GWLP_WNDPROC: i64 = -4;
/// `GWLP_HINSTANCE`.
const GWLP_HINSTANCE: i64 = -6;
/// `GWLP_HWNDPARENT`.
const GWLP_HWNDPARENT: i64 = -8;
/// `GWL_STYLE`.
const GWL_STYLE: i64 = -16;
/// `GWL_EXSTYLE`.
const GWL_EXSTYLE: i64 = -20;
/// `GWLP_USERDATA`.
const GWLP_USERDATA: i64 = -21;
/// `GWLP_ID`.
const GWLP_ID: i64 = -12;

// --- The `NtUserCall*` fan-in multiplexers (roadmap W4.8) -------------------
// One syscall index carries a whole family of tiny operations, selected by a
// trailing "call number". The numbers are **not public**; they were recovered by
// disassembling the pinned `user32.dll`, whose thin wrapper for each public API
// loads the selector as an immediate straight before the win32u thunk — e.g.
//
//   user32!GetClientRect  @ RVA 0x2eda0:  mov r8d, 0xe   ; call NtUserCallHwndParam
//   user32!IsWindow       @ RVA 0x34c10:  mov edx, 0xa   ; call NtUserCallHwnd
//   user32!GetSysColorBrush @ RVA 0x313e0: mov edx, 7    ; call NtUserCallOneParam
//   user32!IsIconic       @ RVA 0x349f0:  mov rdx, -16 (GWL_STYLE); mov r8d, 0xa
//                                         ; call NtUserCallHwndParam
//
// so each constant below is re-derivable from the binary, and the last of those
// pins the *meaning* of code 0xa: `IsIconic` reads `WS_MINIMIZE` out of what it
// returns for `GWL_STYLE`, which makes 0xa `GetWindowLong`.
// (`crates/app/tests/comctl_gate.rs` re-derives the whole set from the pinned
// binary so a Wine bump that renumbers them fails loudly.)

/// `NtUserCallHwnd(hwnd, code)` selectors.
mod call_hwnd {
    /// `GetDpiForWindow`.
    pub const GET_DPI_FOR_WINDOW: u64 = 0x02;
    /// `GetParent`.
    pub const GET_PARENT: u64 = 0x05;
    /// `IsWindow`.
    pub const IS_WINDOW: u64 = 0x0a;
    /// `IsWindowEnabled`.
    pub const IS_WINDOW_ENABLED: u64 = 0x0b;
    /// `IsWindowUnicode`.
    pub const IS_WINDOW_UNICODE: u64 = 0x0c;
    /// `IsWindowVisible`.
    pub const IS_WINDOW_VISIBLE: u64 = 0x0d;
    /// The "does this window belong to the calling thread" probe every
    /// `GetWindowText` / `SetWindowText` / `GetWindowModuleFileName` makes first
    /// (recovered from `user32!SetWindowTextW` @ RVA 0x47590, which sends the
    /// message itself when this answers non-zero).
    pub const IS_SELF_THREAD: u64 = 0x10;
}

/// `NtUserCallHwndParam(hwnd, param, code)` selectors.
mod call_hwnd_param {
    /// `GetWindowLong{A,W}` — `param` is the offset, sign-extended.
    pub const GET_WINDOW_LONG: u64 = 0x0a;
    /// `GetWindowLongPtrA`.
    pub const GET_WINDOW_LONG_PTR_A: u64 = 0x0b;
    /// `GetWindowLongPtrW`.
    pub const GET_WINDOW_LONG_PTR_W: u64 = 0x0c;
    /// `GetWindowRect` — `param` → `{ RECT *rect; DWORD dpi_context; }`.
    pub const GET_WINDOW_RECT: u64 = 0x0d;
    /// `GetClientRect` — same `param` shape as [`GET_WINDOW_RECT`].
    pub const GET_CLIENT_RECT: u64 = 0x0e;
    /// `IsChild` — `param` is the candidate parent HWND.
    pub const IS_CHILD: u64 = 0x13;
}

/// `NtUserCallOneParam(arg, code)` selectors.
mod call_one_param {
    /// `GetSysColor` — `arg` is the `COLOR_*` index.
    pub const GET_SYS_COLOR: u64 = 0x06;
    /// `GetSysColorBrush` — `arg` is the `COLOR_*` index.
    pub const GET_SYS_COLOR_BRUSH: u64 = 0x07;
    /// `GetSystemMetrics` — `arg` is the `SM_*` index.
    pub const GET_SYSTEM_METRICS: u64 = 0x09;
}

/// The `{ RECT *rect; DWORD dpi_context; }` block `GetWindowRect`/`GetClientRect`
/// pass as `param` (recovered from `user32!GetClientRect`, which stores the
/// caller's `RECT*` at +0 and `(dpi_ctx >> 8) & 0x1ff` at +8). exemu is 96 DPI
/// throughout, so only the pointer is read.
const CALL_RECT_PARAM_RECT: u64 = 0x00;

/// Longest parent chain any ancestry walk will follow. Bounds every
/// `surface_owner` / `client_origin` / `chain_visible` loop so a cyclic or
/// corrupted parent link degrades to "treat it as top-level" instead of hanging
/// a syscall handler. Real window nesting is a handful deep.
const WINDOW_ANCESTRY_MAX: usize = 64;

// --- user32's built-in control WndProcs, via the client-PFN arrays (W6.2) ----
// Wine's split leaves the built-in control classes (BUTTON / EDIT / STATIC /
// LISTBOX / COMBOBOX / SCROLLBAR / …) to the *kernel* side: user32 holds the
// WndProcs but never registers the classes, so a `CreateWindowExW(L"BUTTON", …)`
// fails inside user32 unless win32k already knows the class. The WndProcs reach
// the kernel through `NtUserInitializeClientPfnArrays`.
//
// **Recovered chain** (disassembly of the pinned `user32.dll` / `ntdll.dll`, plus
// their own COFF symbol tables — no Wine source read):
//
// 1. user32's `winproc_init` (RVA 0x8f8b0) calls
//    `RtlInitializeNtUserPfn(client_procsA, 0x88, client_procsW, 0x88,
//    client_workers, 0x58)`. **0x88 bytes = 17 pointers per array**, which is
//    where [`CLIENT_PFN_COUNT`] comes from; the workers array is 11 pointers and
//    is entirely NULL in this build.
// 2. ntdll's `RtlInitializeNtUserPfn` copies those arrays into its own
//    `user_procs` block, and `RtlRetrieveNtUserPfn` hands back a *different*
//    triple — ntdll's `user_funcs` (RVA 0x818c0) — which user32 then passes to
//    `NtUserInitializeClientPfnArrays(funcsA, funcsW, workers, user32_module)`.
// 3. Each `user_funcs` entry is a `jmp qword [rip+disp32]` thunk (`48 ff 25 …`,
//    7 bytes) in ntdll's `.text`; the slot it jumps through is exactly
//    `user_procs + index*8`. **Following the thunk therefore yields the real
//    per-class WndProc inside user32's image**, index-for-index.
//
// The per-index identities below come from the pinned user32's own symbol table
// (`client_procs` @ .rdata 0xe2e0): index 0 `ScrollBarWndProc`, 1
// `MessageWndProc`, 2 `PopupMenuWndProc`, 3 `DesktopWndProc`, 4 `DefWindowProc`,
// 5 `IconTitleWndProc`, 6 NULL, 7 `ButtonWndProc`, 8 `ComboWndProc`, 9/12
// `ListBoxWndProc`, 10 `DialogWndProc`, 11 `EditWndProc`, 13 `MDIClientWndProc`,
// 14 `StaticWndProc`, 15 `ImeWndProc`, 16 `DefWindowProc` (again).

/// Entries in each client-PFN array — `0x88 / 8`, from the size user32's
/// `winproc_init` passes to `RtlInitializeNtUserPfn`.
const CLIENT_PFN_COUNT: usize = 17;
/// Opcode of a client-PFN entry: `jmp qword [rip+disp32]`.
const PFN_THUNK_JMP: [u8; 3] = [0x48, 0xFF, 0x25];
/// Length of that thunk — the base the `disp32` is relative to.
const PFN_THUNK_LEN: u64 = 7;

// Client-PFN indices of the procs exemu registers a class for.
const PFN_SCROLL_BAR: usize = 0;
const PFN_MESSAGE: usize = 1;
const PFN_POPUP_MENU: usize = 2;
const PFN_DESKTOP: usize = 3;
const PFN_ICON_TITLE: usize = 5;
const PFN_BUTTON: usize = 7;
const PFN_COMBO_BOX: usize = 8;
/// The combo box's drop-down list — the same proc as [`PFN_LIST_BOX`].
const PFN_COMBO_LBOX: usize = 9;
const PFN_DIALOG: usize = 10;
const PFN_EDIT: usize = 11;
const PFN_LIST_BOX: usize = 12;
const PFN_MDI_CLIENT: usize = 13;
const PFN_STATIC: usize = 14;
const PFN_IME: usize = 15;

/// The built-in window classes win32k owns, and the client-PFN index whose
/// WndProc backs each one. Registered as soon as user32 publishes the arrays
/// (`NtUserInitializeClientPfnArrays`), which happens in user32's `DllMain` —
/// long before any guest `CreateWindowExW`.
///
/// The `#3277x` names are the documented magic class names of the four classes
/// Windows exposes only by atom (menu / desktop / dialog / icon-title); the rest
/// are the documented control-class names. Comparison is case-insensitive
/// ([`Win32kState::class_by_name`]), matching Windows' class lookup.
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
    ("#32768", PFN_POPUP_MENU), // PopupMenu
    ("#32769", PFN_DESKTOP),    // Desktop
    ("#32770", PFN_DIALOG),     // Dialog
    ("#32772", PFN_ICON_TITLE), // IconTitle
];

/// `CS_GLOBALCLASS | CS_DBLCLKS | CS_PARENTDC` — the class style the built-ins
/// are registered with. `CS_GLOBALCLASS` is the load-bearing bit: the classes
/// belong to the system, not to one module's instance.
const BUILTIN_CLASS_STYLE: u32 = 0x4000 | 0x0008 | 0x0080;

/// `cbWndExtra` reserved for each built-in control class (roadmap W4.8).
///
/// A registered class states its own `cbWndExtra`, but the built-ins are
/// registered by the *kernel* side — which for Wine is `win32u.so`, a binary
/// exemu does not have and cannot disassemble. What the PE side does show is
/// the **use**: user32's `ButtonWndProc` and comctl32's `ProgressWindowProc`
/// both store one instance pointer at offset 0 (`SetWindowLongPtr(hwnd, 0, p)`
/// during `WM_NCCREATE`) and read it back on every message. So exemu reserves a
/// generous fixed block rather than pretending to know the real number; a
/// control that stored past it would read back 0, which is the same honest
/// failure as before rather than a silent corruption.
const BUILTIN_WND_EXTRA: u32 = 8 * 8;

/// `CW_USEDEFAULT` — the "let the manager choose" sentinel for x/y/cx/cy. Read
/// as an i32 it is negative (0x80000000); substitute a sane default before
/// storing the window and calling the driver, since a headless driver has no
/// window manager to consult.
const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;
const DEFAULT_X: i32 = 100;
const DEFAULT_Y: i32 = 100;
const DEFAULT_CX: i32 = 640;
const DEFAULT_CY: i32 = 480;

/// `WM_SETTEXT` — the message `SetWindowTextW` delivers via `NtUserMessageCall`
/// (there is no dedicated `NtUserSetWindowText` syscall; recovered evidence).
const WM_SETTEXT: u32 = 0x000c;
/// `WM_NCCREATE` — the first message a window ever receives, ahead of
/// `WM_CREATE` (roadmap W6.2).
const WM_NCCREATE: u32 = 0x0081;

// --- input routing (documented Win32 message ids and hit-test codes) --------
/// `WM_SETFOCUS` — sent to the window gaining the keyboard focus; `wParam` is
/// the window that lost it.
const WM_SETFOCUS: u32 = 0x0007;
/// `WM_KILLFOCUS` — sent to the window losing it; `wParam` is the winner.
const WM_KILLFOCUS: u32 = 0x0008;
/// `WM_GETTEXTLENGTH`.
const WM_GETTEXTLENGTH: u32 = 0x000e;
/// `WM_GETTEXT`.
const WM_GETTEXT: u32 = 0x000d;
/// `WM_CLOSE`.
const WM_CLOSE: u32 = 0x0010;
/// `WM_ERASEBKGND`.
const WM_ERASEBKGND: u32 = 0x0014;
/// `WM_NCCALCSIZE`.
const WM_NCCALCSIZE: u32 = 0x0083;
/// `WM_NCHITTEST` — "which part of you is this screen point over?". The one
/// message whose *return value* routes every other mouse message.
const WM_NCHITTEST: u32 = 0x0084;
/// `WM_NCDESTROY`.
const WM_NCDESTROY: u32 = 0x0082;
/// `WM_SETCURSOR`.
const WM_SETCURSOR: u32 = 0x0020;
/// `WM_MOUSEACTIVATE`.
const WM_MOUSEACTIVATE: u32 = 0x0021;
/// `WM_CAPTURECHANGED` — sent to the window that just lost the mouse capture,
/// `lParam` = the window that gained it. Wine's `ButtonWndProc` handles it (its
/// `0x215` arm drops the pushed state), so it is load-bearing, not decoration.
const WM_CAPTURECHANGED: u32 = 0x0215;
/// The first mouse message (`WM_MOUSEMOVE`) and the first non-client mouse
/// message (`WM_NCMOUSEMOVE`); their difference maps one family onto the other.
const WM_MOUSEFIRST: u32 = 0x0200;
const WM_NCMOUSEFIRST: u32 = 0x00a0;
/// Distance from a client mouse message to its non-client twin.
const NC_MOUSE_DELTA: u32 = WM_MOUSEFIRST - WM_NCMOUSEFIRST;
/// The last mouse message that has a non-client twin (`WM_XBUTTONDBLCLK`).
const WM_MOUSELAST_NC: u32 = 0x020d;

/// `WM_NCHITTEST` results (documented `HT*` codes). Only the three exemu's own
/// routing branches on are named.
mod hit {
    /// The point is over the client area — deliver the ordinary mouse message.
    pub const CLIENT: i64 = 1;
    /// Nothing there; deliver the non-client twin with this code in `wParam`.
    pub const NOWHERE: i64 = 0;
    /// "I am not here" — retry the hit test with this window excluded.
    /// Wine's `ButtonWndProc` answers this for a `BS_GROUPBOX`.
    pub const TRANSPARENT: i64 = -1;
}

/// `GetAncestor` flags (documented).
mod ancestor {
    pub const PARENT: u64 = 1;
    pub const ROOT: u64 = 2;
    pub const ROOTOWNER: u64 = 3;
}

/// How many `WM_NCHITTEST` rounds one native event may drive before the routing
/// gives up and delivers to whatever it last found. Each `HTTRANSPARENT` costs
/// one round; a pathological chain of transparent controls must not be able to
/// keep the message pump inside the kernel for ever.
const HIT_TEST_ROUNDS_MAX: usize = 8;

// --- CREATESTRUCTW (64-bit) field offsets ---------------------------------
// The struct `WM_NCCREATE`/`WM_CREATE` carry in lParam. The `cy, cx, y, x`
// ordering is the documented (counter-intuitive) Win32 layout, not a typo.
const CS_LP_CREATE_PARAMS: u64 = 0x00;
const CS_HINSTANCE: u64 = 0x08;
const CS_HMENU: u64 = 0x10;
const CS_HWND_PARENT: u64 = 0x18;
const CS_CY: u64 = 0x20;
const CS_CX: u64 = 0x24;
const CS_Y: u64 = 0x28;
const CS_X: u64 = 0x2C;
const CS_STYLE: u64 = 0x30;
const CS_LPSZ_NAME: u64 = 0x38;
const CS_LPSZ_CLASS: u64 = 0x40;
const CS_DW_EX_STYLE: u64 = 0x48;
/// `sizeof(CREATESTRUCTW)` on 64-bit.
const CREATESTRUCT_SIZE: u64 = 0x50;

/// Bytes reserved below the interrupted `NtUserCreateWindowEx` syscall's guest
/// rsp to hold the `CREATESTRUCTW` plus NUL-terminated copies of the window and
/// class names. The creation callbacks are seated *below* this, so they cannot
/// overwrite the struct they were handed (and the reservation nests naturally
/// when a WndProc creates a window of its own).
const CREATE_SCRATCH: u64 = 0x200;
/// Longest name copied into that scratch, in UTF-16 code units (excluding the
/// terminator). Two of these plus the struct fit inside [`CREATE_SCRATCH`].
const CREATE_NAME_MAX: usize = 96;

// --- DEVMODEW field offsets (64-bit `_devicemodeW`, roadmap W4.7) ----------
// `NtUserEnumDisplaySettings` fills these display fields; the rest of the
// caller-supplied struct is left as-is (the caller zeroes it and sets dmSize).
const DEVMODE_SIZE: u16 = 220; // full DEVMODEW incl. the ICM tail
const DEVMODE_DMSIZE_OFF: u64 = 68;
const DEVMODE_DMFIELDS_OFF: u64 = 72;
const DEVMODE_DMLOGPIXELS_OFF: u64 = 166;
const DEVMODE_DMBITSPERPEL_OFF: u64 = 168;
const DEVMODE_DMPELSWIDTH_OFF: u64 = 172;
const DEVMODE_DMPELSHEIGHT_OFF: u64 = 176;
const DEVMODE_DMDISPLAYFREQUENCY_OFF: u64 = 184;
/// `dmFields`: DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY.
const DM_DISPLAY_FIELDS: u32 = 0x0004_0000 | 0x0008_0000 | 0x0010_0000 | 0x0040_0000;
/// `ChangeDisplaySettings` return: the mode is compatible / applied.
const DISP_CHANGE_SUCCESSFUL: u32 = 0;
/// `EnumDisplaySettings` `iModeNum` sentinels that mean "the current mode".
const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;

/// A registered window class. `name` keys the registry (atom lookup on
/// CreateWindow / GetClassInfoEx); `wndproc`/`style`/`background` are stored for
/// the WndProc kernel-callback + paint path (W4.3/W4.6) but not yet read.
#[allow(dead_code)] // style/background: consumed by W4.3/W4.6.
struct Class {
    name: String,
    wndproc: u64,
    style: u32,
    background: u64,
    /// `cbWndExtra` — bytes of per-window scratch the class reserves
    /// ([`WNDCLASSEXW_CB_WND_EXTRA`]). **This is where a Wine control keeps its
    /// instance-data pointer**: `ButtonWndProc` / `ProgressWindowProc` store it
    /// at offset 0 with `SetWindowLongPtr` during `WM_NCCREATE` and read it back
    /// with `GetWindowLongPtr` on every later message, so a class whose extra
    /// bytes do not persist has a control that cannot function.
    wnd_extra: u32,
}

/// A live window object. The HWND is an opaque monotonic counter (the recovered
/// `hwnd_usage` audit confirms user32 never decodes the handle bits nor derives
/// pointers from it — it flows straight back into later syscalls), so a bare
/// counter handle is safe. `class_*`/`style`/`ex_style`/`parent` are captured
/// for the surface-sizing + WndProc path (W4.3/W4.6) but not yet read back;
/// `title`/`rect`/`shown` are the load-bearing mutable state.
#[allow(dead_code)] // class_atom/class_name/style/ex_style/parent: W4.3/W4.6.
struct Window {
    class_atom: u16,
    class_name: String,
    title: String,
    /// `[x, y, cx, cy]` in pixels (CW_USEDEFAULT already substituted).
    rect: [i32; 4],
    style: u32,
    ex_style: u32,
    parent: u32,
    shown: bool,
    /// The window-class WndProc (resolved from the class at CreateWindowEx), the
    /// guest procedure `NtUserDispatchMessage` invokes (roadmap W4.6). 0 when the
    /// class was never registered.
    wndproc: u64,
    /// A WM_PAINT is owed to this window (set on show / expose). `NtUserGetMessage`
    /// synthesizes the WM_PAINT when the queue is otherwise empty (exemu drives
    /// the initial paint; design §5), then clears the flag.
    needs_paint: bool,
    /// The per-window backing surface (W4.3), allocated lazily on the first
    /// GetDC/BeginPaint. Top-down BGRA32, guest-mapped so gdi32's PE code and
    /// the presenter share one allocation. Only a [`surface_owner`] carries one;
    /// a child window's stays `None` and it renders into its ancestor's.
    ///
    /// [`surface_owner`]: Win32kState::surface_owner
    surface: Option<Surface>,
    /// The class's `cbWndExtra` scratch bytes, zero-initialized at creation
    /// (roadmap W4.8). Read and written through `GetWindowLongPtr` /
    /// `SetWindowLongPtr` at non-negative offsets — the store every Wine control
    /// keeps its instance data in.
    extra: Vec<u8>,
    /// `GWLP_USERDATA` — the one negative slot with no other home.
    user_data: u64,
    /// `GWLP_ID` — the control id, taken from the `hMenu` argument of a child
    /// window's `CreateWindowEx` (documented Win32 overload).
    id: u64,
    /// `GWLP_HINSTANCE`.
    instance: u64,
}

/// A per-window backing surface (W4.3): a guest-mapped top-down BGRA32 DIB the
/// win32k GDI handlers paint into and the driver presents. `base` is the guest
/// virtual address of the first pixel; `stride = w * 4`.
#[derive(Clone, Copy)]
struct Surface {
    base: u64,
    w: u32,
    h: u32,
}

/// A device context bound to a window (W4.3 / W4.8). Every HDC handed back by
/// GetDC/GetDCEx/BeginPaint records the hwnd it draws into so the NtGdi paint
/// handlers can resolve `hdc → hwnd → surface`.
///
/// **The child-window half (W4.8).** A child window has no surface of its own —
/// it renders into its top-level ancestor's, which is what makes its pixels
/// appear inside the parent. The DC therefore carries the two things that turns
/// "the window's own client coordinates" (what gdi32 hands the kernel) into
/// "surface coordinates": an **origin** (`org`, the window's client origin
/// inside the surface owner) and a **clip rect** (`clip`, the visible slice of
/// that surface the window may touch, already intersected with every ancestor's
/// client rect). Both are computed once, at DC allocation, by
/// [`window_visible_rect`].
struct Dc {
    /// The window the DC draws for (**not** necessarily the surface owner).
    hwnd: u32,
    /// The currently selected brush handle, or 0 for "none".
    ///
    /// Windows starts a DC on `WHITE_BRUSH`; exemu starts it on *nothing*, and
    /// [`nt_gdi_pat_blt`] treats that as the hollow brush. The divergence is
    /// deliberate and bounded: every recovered paint path selects a brush before
    /// it fills (`user32!FillRect` does `SelectObject` → `PatBlt(PATCOPY)` →
    /// restore), so nothing reaches the fill without one — and "fills nothing"
    /// is a visible, debuggable failure, where a default white would silently
    /// blank whatever the parent had already drawn underneath a control.
    brush: u32,
    /// The window's client origin in surface coordinates: every logical `(x, y)`
    /// a GDI primitive is given is offset by this before it hits a pixel.
    org: (i32, i32),
    /// The visible rect in surface coordinates, `[left, top, right, bottom)` —
    /// nothing outside it is drawn. For a top-level window this is the whole
    /// client area; for a child it is its rect clipped by every ancestor.
    clip: [i32; 4],
}

/// win32k unix-backend state (roadmap W4.1/W4.2): the client PFN table, the
/// class registry, and the window object model.
#[derive(Default)]
pub(crate) struct Win32kState {
    /// The client-side PFN table pointer recorded by
    /// `NtUserInitializeClientPfnArrays` — the guest WndProc-caller thunks the
    /// kernel→user callback path (roadmap W4.6) will jump to.
    client_pfn_table: u64,
    /// The **resolved** per-index WndProcs of the Unicode client-PFN array
    /// (roadmap W6.2): each entry is the user32 procedure the corresponding
    /// `user_funcs` thunk jumps to. Index meanings: see [`BUILTIN_CLASSES`].
    client_pfn_w: [u64; CLIENT_PFN_COUNT],
    /// The same for the ANSI array. Recorded for the A-class registrations the
    /// `RegisterClassExWOW` `ansi` flag will select once A/W WndProc pairing is
    /// wired; unread today.
    #[allow(dead_code)] // A-side pairing: W6.3.
    client_pfn_a: [u64; CLIENT_PFN_COUNT],
    /// user32's mapped image span `[base, base+SizeOfImage)` — arg3 of
    /// `NtUserInitializeClientPfnArrays` plus the size read out of the mapped PE
    /// header. Every resolved WndProc must land inside it to be trusted.
    user32_image: (u64, u64),
    /// Registered classes, keyed by their assigned atom. The next atom is
    /// `CLASS_ATOM_BASE + classes.len()`.
    classes: Vec<(u16, Class)>,
    /// Live windows, keyed by HWND.
    windows: Vec<(u32, Window)>,
    /// Live device contexts, keyed by HDC. Binds each HDC to its window +
    /// handle-table slot for the GDI paint path (W4.3).
    dcs: Vec<(u32, Dc)>,
    /// Live brushes, `handle → COLORREF` (roadmap W4.8). A brush is the only
    /// GDI object the recovered paint paths actually consume: `FillRect` selects
    /// one and `PatBlt`s `PATCOPY` with it.
    brushes: Vec<(u32, u32)>,
    /// `GetSysColorBrush` cache, `COLOR_* index → handle`. Windows hands back the
    /// *same* handle for a given index every time (the caller must not delete
    /// it), so this both matches the contract and stops a repainting control
    /// from exhausting the handle table.
    sys_brushes: Vec<(u32, u32)>,
    /// Guest base of the GDI shared handle table (published at PEB+0xF8), or 0
    /// before the first HDC is allocated. Lazily mapped by `ensure_gdi_table`.
    gdi_table_base: u64,
    /// Next free 24-byte slot index in the handle table. Slot 0 is reserved
    /// (a zero index would make `hdc & 0xFFFF == 0`, indistinguishable from a
    /// null handle), so allocation starts at 1.
    gdi_next_slot: u64,
    /// Guest base of the DC-object arena (one `GDI_DC_OBJECT_SIZE` block per
    /// slot); the handle-table entry at +0x10 points into this.
    gdi_dc_arena: u64,
    /// Last known cursor position in screen pixels (roadmap W4.7). Tracked from
    /// native input (`post_input_event`) and `SetCursorPos`; read by
    /// `NtUserGetCursorPos`. The window is at (0,0) so screen == client here.
    cursor_pos: (i32, i32),
    /// The current cursor handle (`SetCursor`/`GetCursor`, roadmap W4.7). 0 = the
    /// default arrow / hidden.
    current_cursor: u64,
    /// Native events that have arrived but not yet been given a target window.
    ///
    /// **Routing happens at retrieval, not at arrival** — that is the whole
    /// point of keeping a raw queue. A mouse event's target depends on the
    /// capture, on the window tree *at the moment the app asks for a message*,
    /// and on what the candidate window answers to `WM_NCHITTEST`; none of that
    /// can be decided when the event is pulled off the channel, because
    /// answering `WM_NCHITTEST` means running guest code.
    raw_input: std::collections::VecDeque<exemu_core::InputEvent>,
    /// The window holding the mouse capture (`SetCapture`), or 0. While it is
    /// set every mouse event goes to it, hit-testing skipped, in **its** client
    /// coordinates — which is what lets a pushed button track a drag that leaves
    /// its rect and still see the matching button-up.
    capture: u32,
    /// The keyboard focus window (`SetFocus`), or 0 — the target of every key
    /// message.
    focus: u32,
    /// The active window (`SetActiveWindow`/`GetActiveWindow`), or 0.
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

    /// The WndProc a message for `hwnd` should be dispatched to, or 0.
    fn wndproc_for(&self, hwnd: u32) -> u64 {
        self.window(hwnd).map(|w| w.wndproc).unwrap_or(0)
    }

    /// The first shown *top-level* window — the target for synthesized native
    /// input (roadmap W4.6). Child windows never take raw input directly; the
    /// hit-test that routes a click to a control is W6-follow-up work.
    fn shown_window(&self) -> Option<u32> {
        self.windows
            .iter()
            .find(|(h, w)| w.shown && self.surface_owner(*h) == *h)
            .map(|(h, _)| *h)
    }

    /// A window owing a WM_PAINT, clearing its flag. Used by the pump to
    /// synthesize a WM_PAINT when the queue is empty. A window counts as
    /// paintable when it is visible *and every ancestor is* — a child of a
    /// hidden parent paints nothing, exactly as on Windows.
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

    /// Is `hwnd` visible *and* is every ancestor up to the top level visible?
    /// A `WS_CHILD` window is created with `WS_VISIBLE` already in its style and
    /// never gets its own `ShowWindow` call, so its `shown` flag is seeded from
    /// [`WS_VISIBLE`] at creation.
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

    /// The window that owns the backing surface `hwnd` renders into: itself if
    /// it is top-level, otherwise its top-most mapped ancestor (roadmap W4.8).
    ///
    /// **This is the child-window painting model.** Wine gives a surface to a
    /// window that has somewhere to *put* pixels — a top-level window backed by
    /// a native window. A child has none: it draws into its ancestor's surface
    /// through a DC carrying an origin offset and a clip region ([`Dc`]), which
    /// is why a control's pixels land inside its parent. Walking the chain is
    /// bounded so a corrupted parent link cannot hang the handler.
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

    /// `hwnd`'s client origin **in its surface owner's coordinates** — the sum of
    /// every intervening child's `(x, y)`. `(0, 0)` for a top-level window.
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

    /// `hwnd`'s visible rect in surface coordinates, `[left, top, right, bottom)`
    /// — its client rect at [`client_origin`], intersected with every ancestor's
    /// client rect so a control can never paint outside its parent. An empty
    /// result (`right <= left`) means the window is entirely clipped away.
    fn window_visible_rect(&self, hwnd: u32) -> [i32; 4] {
        let (ox, oy) = self.client_origin(hwnd);
        let Some(w) = self.window(hwnd) else { return [0; 4] };
        let (cx, cy) = client_size(w);
        let mut r = [ox, oy, ox + cx as i32, oy + cy as i32];
        // Clip against each ancestor's client rect, expressed in the same
        // surface coordinates.
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

    /// Does `hwnd`'s client rect contain the surface-space point `(x, y)`?
    fn contains_point(&self, hwnd: u32, x: i32, y: i32) -> bool {
        let (ox, oy) = self.client_origin(hwnd);
        let Some(w) = self.window(hwnd) else { return false };
        let (cx, cy) = client_size(w);
        x >= ox && y >= oy && x < ox + cx as i32 && y < oy + cy as i32
    }

    /// **The hit test.** The deepest visible window containing the point, or 0.
    ///
    /// `user32!WindowFromPoint` is four instructions — unpack the by-value
    /// `POINT` and tail-jump `NtUserWindowFromPoint` — so the window tree walk is
    /// unambiguously the kernel side's job, and this is it. Siblings are searched
    /// **newest first**, matching Windows' "a freshly created child goes to the
    /// top of its siblings' Z-order"; `skip` carries the windows a previous
    /// round's `HTTRANSPARENT` has already excluded.
    fn window_from_point(&self, x: i32, y: i32, skip: &[u32]) -> u32 {
        let Some(top) = self.shown_window() else { return 0 };
        if skip.contains(&top) || !self.contains_point(top, x, y) {
            return 0;
        }
        let mut cur = top;
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

    /// The direct child of `parent` under the point, or `parent` itself — the
    /// `ChildWindowFromPointEx` contract (one level, not the deepest).
    fn child_window_from_point(&self, parent: u32, x: i32, y: i32) -> u32 {
        self.windows
            .iter()
            .rev()
            .find(|(h, w)| w.parent == parent && w.shown && self.contains_point(*h, x, y))
            .map(|(h, _)| *h)
            .unwrap_or(parent)
    }
}

/// Install the win32k SSDT table: fill the whole win32u index range with
/// [`honest_stub`], then override the serviced slots. Called from `WinOs::new`.
/// Corpus-safe: the win32k table is only reached via a guest win32u `SYSCALL`,
/// which the emulated corpus never issues.
pub(crate) fn register(os: &mut WinOs) {
    for idx in WIN32K_FIRST..=WIN32K_LAST {
        os.set_win32k_handler(idx, honest_stub);
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
    os.set_win32k_handler(NT_USER_TRANSLATE_MESSAGE, nt_user_translate_message);
    os.set_win32k_handler(NT_USER_DISPATCH_MESSAGE, nt_user_dispatch_message);
    // Cursor / display driver members (W4.7).
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
    // Input routing: hit-testing, capture, focus.
    os.set_win32k_handler(NT_USER_WINDOW_FROM_POINT, nt_user_window_from_point);
    os.set_win32k_handler(NT_USER_CHILD_WINDOW_FROM_POINT_EX, nt_user_child_window_from_point_ex);
    os.set_win32k_handler(NT_USER_SET_CAPTURE, nt_user_set_capture);
    os.set_win32k_handler(NT_USER_RELEASE_CAPTURE, nt_user_release_capture);
    os.set_win32k_handler(NT_USER_SET_FOCUS, nt_user_set_focus);
    os.set_win32k_handler(NT_USER_SET_ACTIVE_WINDOW, nt_user_set_active_window);
    os.set_win32k_handler(NT_USER_GET_THREAD_STATE, nt_user_get_thread_state);
    os.set_win32k_handler(NT_USER_GET_ANCESTOR, nt_user_get_ancestor);
    // The NtUserCall* fan-in multiplexers + the window-long store (W4.8) — what
    // a real control consults on every message it handles.
    os.set_win32k_handler(NT_USER_CALL_HWND, nt_user_call_hwnd);
    os.set_win32k_handler(NT_USER_CALL_HWND_PARAM, nt_user_call_hwnd_param);
    os.set_win32k_handler(NT_USER_CALL_ONE_PARAM, nt_user_call_one_param);
    os.set_win32k_handler(NT_USER_SET_WINDOW_LONG, nt_user_set_window_long);
    os.set_win32k_handler(NT_USER_SET_WINDOW_LONG_PTR, nt_user_set_window_long_ptr);
    // NtGdi paint path (W4.3): rasterize into the per-window surface.
    os.set_win32k_handler(NT_GDI_EXT_TEXT_OUT_W, nt_gdi_ext_text_out_w);
    os.set_win32k_handler(NT_GDI_RECTANGLE, nt_gdi_rectangle);
    // The physdev primitive set (W4.8): brush/pen objects + the fill blitter.
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
}

/// Allocate a fresh nonzero handle (HWND/HDC) from the shared handle space. The
/// handle stays under 2³², so it round-trips through the u32 syscall return
/// cleanly and never collides with file/kernel handles (same allocator).
fn alloc_handle(os: &mut WinOs) -> u32 {
    let h = os.next_handle;
    os.next_handle += 4;
    h as u32
}

/// Read a UNICODE_STRING (`+0x00 Length(u16, bytes)`, `+0x08 Buffer(ptr)`) from
/// guest memory into a `String`. A null struct pointer or null buffer yields the
/// empty string. Length is in *bytes* (2 × the WCHAR count).
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
        // A zero-Length UNICODE_STRING with a live buffer: the class name is
        // often a NUL-terminated string the caller left Length=0 on. Fall back
        // to reading up to the terminator so a name still surfaces.
        return read_wstr(mem, buffer);
    }
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(mem.read_u16(buffer + (i as u64) * 2)?);
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Every win32u index outside the serviced set → 0 (a null handle / FALSE),
/// never a garbage non-null status, so Wine's user32/gdi32 see a clean "no
/// object" instead of dereferencing a fake pointer.
fn honest_stub(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(0)
}

/// Follow one client-PFN array entry to the user32 WndProc it stands for
/// (roadmap W6.2). An entry is a `jmp qword [rip+disp32]` thunk: the WndProc is
/// what its slot holds. A null entry stays null; an entry that is *not* that
/// thunk shape is taken to be the procedure address itself (a future Wine build
/// could publish the pointers directly — resolving would then be a no-op rather
/// than a silent misread).
/// Returns `(wndproc, slot)` — the procedure, and **the address of the slot the
/// thunk jumps through** (ntdll's `user_procs + index*8`). The slot address is
/// what [`mirror_client_pfn_to_ntdll_copies`] needs; a non-thunk entry has no
/// slot and reports 0.
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

/// Read and resolve a whole [`CLIENT_PFN_COUNT`]-entry client-PFN array
/// (roadmap W6.2), as `(procs, slots)`. A null array pointer yields all zeros.
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

/// `NtUserInitializeClientPfnArrays(client_procsA, client_procsW, client_worker,
/// user32)` — user32's DllMain hands the kernel the client-side WndProc arrays.
///
/// Record arg0 for the kernel→user callback path (roadmap W4.6), **resolve both
/// arrays through their thunks, and register user32's built-in control classes**
/// against the recovered WndProcs (roadmap W6.2) — that is what makes
/// `CreateWindowExW(L"BUTTON", …)` reach [`nt_user_create_window_ex`] instead of
/// failing the class lookup inside user32.
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
    // A malformed / unmapped array must not fault the guest: fall back to an
    // all-zero table, which simply registers no built-ins (the pre-W6.2 state).
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

/// Republish the resolved client-PFN procs into **every other mapped copy of
/// ntdll** (roadmap W6.2).
///
/// **Why this is needed.** Wine's split routes `DefWindowProcW` through ntdll:
/// `user32!DefWindowProcW` is a *forwarder* to `NTDLL.NtdllDefWindowProc_W`,
/// which is nothing but `jmp qword [user_procs + 4*8 + 0x88]` — a jump through
/// the very slot `RtlInitializeNtUserPfn` fills when user32 publishes its arrays.
/// Under exemu's Wine boot the process ends up with **two** ntdll images: the one
/// exemu pre-maps (the running image — the copy user32 binds to and therefore the
/// only one whose `user_procs` is ever filled) and a second one Wine's own loader
/// maps for the name `NTDLL.dll` while resolving forwarders. Modules bound after
/// that second map — the exe itself, and comctl32 — reach `DefWindowProcW`
/// through the *dead* copy, whose slot is still NULL, so the call tail-jumps to
/// address 0. (Measured: the AV then never surfaces either, because ntdll's
/// `call_seh_handlers` re-runs `virtual_unwind` until the frame reaches
/// `TEB.StackBase`, and exemu's win32k callback-return thunk carries no `.pdata`,
/// so the walk never terminates — the run spins instead of faulting.)
///
/// Mirroring the slots makes the WndProc table exemu recovered authoritative for
/// every copy, so `DefWindowProc` works no matter which image a module was bound
/// against.
///
/// **The duplicate load itself was fixed in W6.6** — it was caused by exemu
/// answering `NtGetNlsSectionPtr(type 0xA)` with an all-zero case-mapping table,
/// which turned every case-insensitive comparison in the process into a
/// case-sensitive one, so the loader never matched the `NTDLL.dll` a forwarder
/// named against the loaded `ntdll.dll` (see `crate::nls::build_casemap_nls`).
/// This mirroring is kept as defence in depth: with one copy it is a no-op, and
/// any future path that does map a second one stays safe.
///
/// A copy is identified structurally: a mapped region holding a PE whose export
/// directory names `ntdll.dll` and whose `SizeOfImage` matches the running one.
/// Failures are silent — an unmirrored copy is exactly the pre-existing state.
fn mirror_client_pfn_to_ntdll_copies(
    mem: &mut dyn Memory,
    live: u64,
    arrays: &[(&[u64; CLIENT_PFN_COUNT], &[u64; CLIENT_PFN_COUNT])],
) {
    let Some(live_size) = pe_image_size(mem, live) else { return };
    for copy in ntdll_copies(mem, live, live_size) {
        for (slots, procs) in arrays {
            for (slot, proc) in slots.iter().zip(procs.iter()) {
                // A slot inside the running ntdll maps to the same RVA in the copy.
                if *slot < live || *slot >= live + live_size || *proc == 0 {
                    continue;
                }
                let _ = mem.write_u64(copy + (slot - live), *proc);
            }
        }
    }
}

/// Bases of every mapped image that is a **second copy of the running ntdll** —
/// same `SizeOfImage`, export-directory name `ntdll.dll`, different base
/// (roadmap W6.2). Walks the guest's mapped regions; a region that is not a PE
/// is skipped.
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

/// The name in the export directory of the PE mapped at `base` (the DLL's own
/// idea of what it is called), or `None` when `base` holds no PE with exports.
fn pe_export_name(mem: &dyn Memory, base: u64) -> Option<String> {
    if base == 0 || mem.read_u16(base).ok()? != 0x5A4D {
        return None;
    }
    let pe = base + mem.read_u32(base + 0x3C).ok()? as u64;
    if mem.read_u32(pe).ok()? != 0x0000_4550 {
        return None;
    }
    // Optional header + data directory 0 (export) → the directory's Name RVA.
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

/// `SizeOfImage` of the PE mapped at `base`, read out of guest memory
/// (`e_lfanew` @ +0x3C, then optional header +56). `None` when `base` is 0 or
/// the MZ/PE signatures are absent, so a caller can decline to trust the span.
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

/// Register the built-in control classes ([`BUILTIN_CLASSES`]) against the
/// resolved Unicode WndProcs (roadmap W6.2). Idempotent — a class whose name is
/// already registered (a second `NtUserInitializeClientPfnArrays`, or a guest
/// that got there first) is left alone. A class whose PFN slot resolved to 0, or
/// to an address **outside user32's mapped image**, is skipped rather than
/// registered with a WndProc that would not survive the first message.
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
            },
        ));
    }
}

/// `NtUserGetSystemDpiForProcess` → `WinConfig::dpi` (96 = 100% scaling by
/// default; settable per-exe via a W9.4 profile's `dpi` key).
fn nt_user_get_system_dpi_for_process(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(os.cfg.dpi)
}

/// `NtUserSetProcessDpiAwarenessContext` → nonzero (accepted).
fn nt_user_set_process_dpi_awareness_context(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(1)
}

/// `NtUserGetClassInfoEx(hInstance, className*, WNDCLASSEXW* out, …)` → the
/// class atom when the class is already registered, else 0 (not-found) so
/// user32 proceeds to register it. Consults the W4.2 registry.
///
/// arg2 is a UNICODE_STRING* for the class name (same marshalling user32 uses
/// for RegisterClass/CreateWindow — recovered `init_class_name`).
fn nt_user_get_class_info_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let name_ptr = os.syscall_arg(cpu, mem, 1)?;
    let name = read_unicode_string(mem, name_ptr)?;
    Ok(os.win32k_state.class_by_name(&name).map(u32::from).unwrap_or(0))
}

/// `NtUserRegisterClassExWOW(WNDCLASSEXW* wc, className*, version*, menuName*,
/// …)` → a fresh nonzero class ATOM. Reads the class name from the resolved
/// UNICODE_STRING in arg2 (never the WNDCLASS `lpszClassName`, which may be an
/// atom) and the WndProc/style/background from the raw WNDCLASSEXW in arg1.
///
/// Recovered arg layout (RegisterClassExW @ user32 RVA 0x42eb5): rcx = raw
/// WNDCLASSEXW*, rdx = class-name UNICODE_STRING*. WNDCLASSEXW field offsets:
/// `+0x04 style`, `+0x08 lpfnWndProc`, `+0x30 hbrBackground`. `RegisterClassW`
/// (what gui_sample calls) converges to this same syscall via user32.
fn nt_user_register_class_ex_wow(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let wc = os.syscall_arg(cpu, mem, 0)?;
    let name_ptr = os.syscall_arg(cpu, mem, 1)?;
    let name = read_unicode_string(mem, name_ptr)?;

    let (style, wndproc, background, wnd_extra) = if wc != 0 {
        (
            mem.read_u32(wc + WNDCLASSEXW_STYLE)?,
            mem.read_u64(wc + WNDCLASSEXW_WNDPROC)?,
            mem.read_u64(wc + WNDCLASSEXW_BACKGROUND)?,
            mem.read_u32(wc + WNDCLASSEXW_CB_WND_EXTRA)?.min(WND_EXTRA_MAX),
        )
    } else {
        (0, 0, 0, 0)
    };

    // A duplicate registration of the same name reuses its atom (matches
    // Windows returning the existing atom rather than a second one).
    if let Some(existing) = os.win32k_state.class_by_name(&name) {
        return Ok(existing as u32);
    }

    let atom = CLASS_ATOM_BASE.wrapping_add(os.win32k_state.classes.len() as u16);
    os.win32k_state
        .classes
        .push((atom, Class { name, wndproc, style, background, wnd_extra }));
    Ok(atom as u32)
}

/// `NtUserCreateWindowEx(exStyle, className*, unused0, windowName*, style, x, y,
/// cx, cy, parent, menu, cbtParam, createParams, flags, instance, rawClassPtr,
/// unicode)` — marshal the recovered arg slots, allocate the HWND, store the
/// window object, then drive the driver create sequence (§4 ordering:
/// window_pos_changing → create_window → window_pos_changed).
///
/// arg1 (class) and arg3 (window name) are POINTERS to UNICODE_STRING; the
/// exStyle/style/x/y/cx/cy dwords are raw; parent/menu/instance are raw handles
/// and arg12 is the caller's `lpParam`. Stack args 5+ are read via `syscall_arg`
/// relative to the captured guest RSP. **The instance/params/module slots were
/// pinned by probing the pinned user32 with distinctive values** (a guest
/// `CreateWindowExW(..., hInstance = 0x11112222, lpParam = 0x33334444)` lands in
/// arg11 / arg12; arg14 repeats the instance and arg13 is a flags dword).
///
/// Finally the creation pair is dispatched to the class WndProc — see
/// [`dispatch_create_messages`], which hijacks the syscall return so the HWND is
/// still what user32 receives (roadmap W6.2).
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

    // CW_USEDEFAULT: a headless driver has no window manager to size against,
    // so substitute a sane default rect before storing / calling the driver.
    let subst = |v: i32, def: i32| if v == CW_USEDEFAULT { def } else { v };
    let rect = [
        subst(x, DEFAULT_X),
        subst(y, DEFAULT_Y),
        subst(cx, DEFAULT_CX),
        subst(cy, DEFAULT_CY),
    ];

    // Resolve the class atom from the registered name so the driver + window
    // carry a stable identifier; 0 when the class was never registered.
    let class_atom = os.win32k_state.class_by_name(&class_name).unwrap_or(0);
    // The class WndProc is the guest procedure NtUserDispatchMessage invokes;
    // `cbWndExtra` sizes the per-window scratch a control keeps its state in.
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
            // A `WS_CHILD | WS_VISIBLE` control is visible the moment it is
            // created — nothing ever calls `ShowWindow` on it — so seed
            // visibility (and the WM_PAINT it is owed) straight from the style.
            // A top-level window's `WS_VISIBLE` is honoured for the same reason.
            shown: style & WS_VISIBLE != 0,
            wndproc,
            needs_paint: style & WS_VISIBLE != 0,
            surface: None,
            extra: vec![0u8; wnd_extra],
            user_data: 0,
            // A child window's `hMenu` argument is its control id (the
            // documented `CreateWindowEx` overload); a top-level window's is a
            // real menu handle and has no id.
            id: if style & WS_CHILD != 0 { menu } else { 0 },
            instance,
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
    // §4 ordering: pos-changing (no-op default) → create → pos-changed.
    os.driver.window_pos_changing(hwnd);
    os.driver.create_window(hwnd, &params);
    os.driver.window_pos_changed(hwnd, rect);

    // The creation pair. Installing it hijacks the syscall return, so the HWND
    // travels in the callback frame instead of this handler's status.
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

/// Everything `WM_NCCREATE`/`WM_CREATE`'s `CREATESTRUCTW` carries, gathered from
/// the `NtUserCreateWindowEx` argument slots (roadmap W6.2).
struct CreateInfo<'a> {
    create_params: u64,
    instance: u64,
    menu: u64,
    parent: u32,
    /// `[x, y, cx, cy]`, `CW_USEDEFAULT` already substituted.
    rect: [i32; 4],
    style: u32,
    ex_style: u32,
    title: &'a str,
    class_name: &'a str,
}

/// Copy `s` to `at` as a NUL-terminated UTF-16 string (at most
/// [`CREATE_NAME_MAX`] code units), returning the guest address of the copy —
/// or 0 for an empty string, which is what `CREATESTRUCTW` uses for "no name".
/// Returns the byte length written so the caller can bump its cursor.
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

/// Build a `CREATESTRUCTW` in the scratch below the interrupted syscall's guest
/// rsp and dispatch `WM_NCCREATE` then `WM_CREATE` to the class WndProc
/// (roadmap W6.2). Without this a control never allocates its instance data, so
/// nothing it is later asked to do can work.
///
/// **Why the callback queue and not the plain return-hijack:**
/// `call_wndproc_from_syscall` leaves the WndProc's LRESULT in rax, which is
/// exactly the register `NtUserCreateWindowEx` must return the HWND in. The
/// queue form ([`WinOs::call_wndprocs_from_syscall`]) carries the handler's own
/// result across both callbacks — the same re-entrant shape `_initterm`, the TLS
/// callbacks and `DllMain` already use on the intercepted-import path.
///
/// The names are **copied** into the scratch rather than aliased from the
/// caller's `UNICODE_STRING` buffers: those carry an explicit length and are not
/// promised to be NUL-terminated, while `CREATESTRUCTW.lpsz*` are plain C
/// strings.
///
/// Known simplification: Windows aborts creation when `WM_NCCREATE` returns
/// FALSE (or `WM_CREATE` returns −1). exemu dispatches both and keeps the
/// window; the LRESULTs are not inspected. Nothing in the current corpus refuses
/// its own creation, and a half-created window would be a worse failure than a
/// live one.
///
/// A class with no WndProc (never registered) is left alone — the handler then
/// returns the HWND the ordinary way.
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
    let scratch = os.syscall_guest_rsp.wrapping_sub(CREATE_SCRATCH);
    let cs = scratch & !0xf;
    let strings = cs + CREATESTRUCT_SIZE;
    // A stack too shallow to hold the scratch is not worth faulting the guest
    // over: skip the creation pair rather than corrupt memory.
    let Ok((name_ptr, name_len)) = write_wstr_at(mem, strings, info.title) else {
        return Ok(false);
    };
    let (class_ptr, _) = write_wstr_at(mem, strings + name_len, info.class_name)?;

    mem.write_u64(cs + CS_LP_CREATE_PARAMS, info.create_params)?;
    mem.write_u64(cs + CS_HINSTANCE, info.instance)?;
    mem.write_u64(cs + CS_HMENU, info.menu)?;
    mem.write_u64(cs + CS_HWND_PARENT, info.parent as u64)?;
    mem.write_u32(cs + CS_CY, info.rect[3] as u32)?;
    mem.write_u32(cs + CS_CX, info.rect[2] as u32)?;
    mem.write_u32(cs + CS_Y, info.rect[1] as u32)?;
    mem.write_u32(cs + CS_X, info.rect[0] as u32)?;
    mem.write_u32(cs + CS_STYLE, info.style)?;
    mem.write_u64(cs + CS_LPSZ_NAME, name_ptr)?;
    mem.write_u64(cs + CS_LPSZ_CLASS, class_ptr)?;
    mem.write_u32(cs + CS_DW_EX_STYLE, info.ex_style)?;

    let hwnd = hwnd as u64;
    let calls = vec![
        (wndproc, vec![hwnd, WM_NCCREATE as u64, 0, cs]),
        (wndproc, vec![hwnd, crate::gdi::WM_CREATE, 0, cs]),
    ];
    os.call_wndprocs_from_syscall(cpu, mem, calls, Some(hwnd), CREATE_SCRATCH)
}

/// `NtUserShowWindow(hwnd, cmd)` / `NtUserShowWindowAsync` — mark the window
/// shown, notify the driver, return the previous-visible BOOL (Windows'
/// contract). A bare import thunk: hwnd in arg0, `SW_*` cmd in arg1 (recovered).
fn nt_user_show_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let cmd = os.syscall_arg(cpu, mem, 1)? as i32;
    let was_visible = match os.win32k_state.window_mut(hwnd) {
        Some(w) => {
            let prev = w.shown;
            // SW_HIDE = 0 hides; any other SW_* command shows.
            w.shown = cmd != 0;
            // Showing a window owes it an initial WM_PAINT (design §5): exemu
            // drives the first paint rather than waiting on the native compositor.
            if w.shown {
                w.needs_paint = true;
            }
            prev
        }
        None => false,
    };
    // Showing a top-level window activates it, which is what gives keyboard
    // input somewhere to go before any `SetFocus` has run.
    if cmd != 0 && os.win32k_state.surface_owner(hwnd) == hwnd {
        os.win32k_state.active = hwnd;
    }
    os.driver.show_window(hwnd, cmd);
    Ok(was_visible as u32)
}

/// `NtUserDestroyWindow(hwnd)` — remove the window object, notify the driver,
/// return TRUE for a known hwnd / FALSE otherwise. Bare import thunk: hwnd in
/// arg0 (recovered).
fn nt_user_destroy_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(destroy_window(os, hwnd) as u32)
}

/// Drop a window object and notify the driver, clearing any input state that
/// pointed at it — a destroyed window must not keep the capture or the focus.
/// Returns whether it existed.
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

/// `NtUserSetWindowPos(hwnd, insertAfter, x, y, cx, cy, flags)` — update the
/// stored rect and notify the driver. arg0 hwnd, args 2..5 x/y/cx/cy (raw
/// dwords). `SWP_NOMOVE`/`SWP_NOSIZE` keep the existing coordinate.
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

/// `NtUserMessageCall(hwnd, msg, wParam, lParam, resultInfo, type, ansi)` — the
/// **whole message-delivery family behind one index**, selected by the `type`
/// argument (see [`message_call`]).
///
/// * [`SEND_MESSAGE`](message_call::SEND_MESSAGE) and its notify/timeout/callback
///   variants: deliver synchronously to the window's WndProc; the syscall's
///   return value **is** the `LRESULT`. (`SendMessageW` zeroes `resultInfo+8`
///   before the call and only re-dispatches client-side if the kernel filled it,
///   which exemu never does — so returning the LRESULT is exactly the contract.)
/// * [`DISPATCH_MESSAGE`](message_call::DISPATCH_MESSAGE): the tail of
///   `DispatchMessage{A,W}` for every message that is not `WM_PAINT`/`WM_TIMER`
///   — i.e. **this is how a mouse or key message reaches its window**. Same
///   delivery, but the syscall must answer **zero**: a non-zero answer tells
///   user32 to run `dispatch_win_proc_params` over a `resultInfo` block the
///   caller never initialized.
/// * [`DEF_WINDOW_PROC`](message_call::DEF_WINDOW_PROC): `DefWindowProc{A,W}` is
///   *nothing but* this syscall, so it must run [`def_window_proc`] here.
///   Re-dispatching it to the window's WndProc would call the procedure that
///   just called `DefWindowProc`, without end.
/// * [`CALL_WINDOW_PROC`](message_call::CALL_WINDOW_PROC): the procedure to call
///   is at offset 0 of `resultInfo`.
///
/// `WM_SETTEXT` keeps its native arm on the send path (there is no dedicated
/// `NtUserSetWindowText` syscall — `SetWindowTextW` delivers it here): update
/// the stored title and notify the driver.
fn nt_user_message_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let msg = os.syscall_arg(cpu, mem, 1)? as u32;
    let wparam = os.syscall_arg(cpu, mem, 2)?;
    let lparam = os.syscall_arg(cpu, mem, 3)?;
    let result_info = os.syscall_arg(cpu, mem, 4)?;
    // `type` and `ansi` are **DWORD** slots: every user32 wrapper fills them with
    // `mov dword ptr [rsp+0x28], imm` / `[rsp+0x30]`, leaving whatever the stack
    // already held in the upper half. Reading the full qword picks that garbage
    // up — which is how `SetWindowTextW` came out as ANSI on one call and Unicode
    // on the next, purely from what the previous frame had left behind.
    let call_type = os.syscall_arg(cpu, mem, 5)? as u32 as u64;
    let ansi = os.syscall_arg(cpu, mem, 6)? as u32 != 0;

    match call_type {
        message_call::DEF_WINDOW_PROC => {
            let r = def_window_proc(os, cpu, mem, hwnd, msg, wparam, lparam, ansi)?;
            os.return_u64_from_syscall(r);
            Ok(0) // ignored: the 64-bit LRESULT above is what reaches rax
        }
        message_call::CALL_WINDOW_PROC => {
            // `resultInfo+0` is the `lpPrevWndFunc` the caller passed.
            let proc = if result_info != 0 {
                mem.read_u64(result_info + WIN_PROC_PARAMS_FUNC)?
            } else {
                0
            };
            if proc == 0 {
                return Ok(0);
            }
            let m = crate::msg::PostedMsg { hwnd: hwnd as u64, message: msg, wparam, lparam };
            // Zero: user32 must not walk the params block afterwards (exemu ran
            // the procedure itself), which costs `CallWindowProc` its LRESULT.
            os.call_wndprocs_from_syscall(cpu, mem, vec![(proc, m.into_args())], Some(0), 0)?;
            Ok(0)
        }
        _ => {
            if msg == WM_SETTEXT && call_type != message_call::DISPATCH_MESSAGE {
                let text = read_text_param(mem, lparam, ansi)?;
                if let Some(w) = os.win32k_state.window_mut(hwnd) {
                    w.title = text.clone();
                }
                os.driver.set_window_text(hwnd, &text);
                return Ok(1);
            }
            // `DispatchMessage` must see 0; a send wants the WndProc's LRESULT.
            let forced = (call_type == message_call::DISPATCH_MESSAGE).then_some(0);
            dispatch_to_wndproc(os, cpu, mem, hwnd as u64, msg, wparam, lparam, forced)
        }
    }
}

/// Read a `WM_SETTEXT`/`WM_GETTEXT`-style string parameter out of guest memory.
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

/// **The kernel-side `DefWindowProc`** — what `user32!DefWindowProcW` actually
/// is (roadmap W4.8 input routing).
///
/// The pinned `user32!DefWindowProcW` (RVA 0x1ddd0) handles five IME/syscommand
/// messages itself and forwards **everything else** to `NtUserMessageCall` with
/// type `0x29e`. There is no `WM_NCHITTEST` arm anywhere in user32, no
/// `NC_HandleNCHitTest` in its symbol table: the default hit test is the kernel
/// side's, which is why answering it here is what makes a click land.
///
/// Only the messages a real control's `DefWindowProc` chain depends on are
/// answered; everything else is 0, the same honest "nothing happened" the rest
/// of this module returns.
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
        // The default hit test: inside the client area, or nowhere. exemu draws
        // no non-client frame, so a window *is* its client area and there is no
        // caption/border/sizing region to report.
        WM_NCHITTEST => {
            let (x, y) = (lo_word_i32(lparam), hi_word_i32(lparam));
            Ok(if os.win32k_state.contains_point(hwnd, x, y) {
                hit::CLIENT as u64
            } else {
                hit::NOWHERE as u64
            })
        }
        // TRUE = "carry on creating me". A control that lets its DefWindowProc
        // answer this and gets FALSE is being told its own creation failed.
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
        // A click on an inactive window activates it and then delivers the
        // message (`MA_ACTIVATE` = 1).
        WM_MOUSEACTIVATE => Ok(1),
        // "I set the cursor" — exemu has one shape, and saying FALSE makes a
        // control keep asking its parent.
        WM_SETCURSOR => Ok(1),
        // The window is its own client area; nothing to subtract.
        WM_NCCALCSIZE => Ok(0),
        WM_ERASEBKGND => erase_background(os, mem, hwnd),
        WM_CLOSE => {
            destroy_window(os, hwnd);
            Ok(0)
        }
        // Focus changes have already been applied by `NtUserSetFocus`; the
        // default handler only needs to not object.
        WM_SETFOCUS | WM_KILLFOCUS | WM_CAPTURECHANGED | WM_NCDESTROY => Ok(0),
        _ => {
            let _ = cpu;
            Ok(0)
        }
    }
}

/// `WM_ERASEBKGND`'s default: fill the window's visible rect with its class
/// background brush. Returns 1 when it painted (the documented "background is
/// erased" answer), 0 when the class asked for no background at all.
fn erase_background(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<u64> {
    let atom = os.win32k_state.window(hwnd).map(|w| w.class_atom).unwrap_or(0);
    let brush = os.win32k_state.class_by_atom(atom).map(|c| c.background).unwrap_or(0);
    if brush == 0 {
        return Ok(0);
    }
    // A class background is either a brush handle or `COLOR_x + 1`.
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

/// The low / high 16 bits of a packed `lParam` point, as signed coordinates.
fn lo_word_i32(v: u64) -> i32 {
    (v & 0xffff) as u16 as i16 as i32
}
fn hi_word_i32(v: u64) -> i32 {
    ((v >> 16) & 0xffff) as u16 as i16 as i32
}

/// The system colour for a documented `COLOR_*` index, as a `COLORREF`
/// (`0x00BBGGRR`). These are the classic (non-themed) Windows values — the
/// palette Wine's own built-in controls draw with when no theme is active,
/// which is exemu's case (`uxtheme` reports no active theme).
///
/// Indices outside the table answer `COLOR_BTNFACE`'s grey rather than black, so
/// an unlisted element is drawn in a plausible neutral instead of a hole.
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
        _ => GREY, // COLOR_BTNFACE and everything unlisted
    }
}

/// A documented `SM_*` system metric. Only the ones a control consults while
/// painting are answered; the rest report 0, which is the honest "no such
/// metric" and never a fabricated size.
fn system_metric(index: u32) -> u32 {
    const SM_CXSCREEN: u32 = 0;
    const SM_CYSCREEN: u32 = 1;
    const SM_CXBORDER: u32 = 5;
    const SM_CYBORDER: u32 = 6;
    const SM_CXEDGE: u32 = 45;
    const SM_CYEDGE: u32 = 46;
    match index {
        SM_CXSCREEN => 1920,
        SM_CYSCREEN => 1080,
        SM_CXBORDER | SM_CYBORDER => 1,
        SM_CXEDGE | SM_CYEDGE => 2,
        _ => 0,
    }
}

// ================= W4.8: the NtUserCall* fan-in multiplexers =================

/// `NtUserCallHwnd(hwnd, code)` — the one-argument window query family.
///
/// Every unrecognised selector returns 0, the same honest "no" the blanket stub
/// gave, so adding a member here can only ever turn a false answer true.
fn nt_user_call_hwnd(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let code = os.syscall_arg(cpu, mem, 1)?;
    let st = &os.win32k_state;
    Ok(match code {
        call_hwnd::IS_WINDOW => st.window(hwnd).is_some() as u32,
        // Nothing disables a window yet; a live window is enabled.
        call_hwnd::IS_WINDOW_ENABLED => st.window(hwnd).is_some() as u32,
        // Every class exemu registers is Unicode (the `RegisterClassExWOW` ansi
        // flag is not tracked yet), and so is every Wine built-in.
        call_hwnd::IS_WINDOW_UNICODE => st.window(hwnd).is_some() as u32,
        call_hwnd::IS_WINDOW_VISIBLE => st.chain_visible(hwnd) as u32,
        call_hwnd::GET_PARENT => st.window(hwnd).map(|w| w.parent).unwrap_or(0),
        call_hwnd::GET_DPI_FOR_WINDOW => os.cfg.dpi,
        // **Not a boolean — the validated HWND.** `user32!WIN_IsCurrentProcess`
        // is `mov edx,0x10; call NtUserCallHwnd; mov eax,eax; ret`, and
        // `DefWindowProcW` uses what it returns *as the window handle* it passes
        // on to `NtUserMessageCall` (`mov rbx, rax`). Answering 1 sent every
        // `DefWindowProc` in the process to window number 1. Single-threaded
        // guest, so a live window always belongs to the caller.
        call_hwnd::IS_SELF_THREAD => st.window(hwnd).map(|_| hwnd).unwrap_or(0),
        _ => 0,
    })
}

/// `NtUserCallHwndParam(hwnd, param, code)` — the two-argument window family:
/// the `GetWindowLong*` readers and the rect queries.
fn nt_user_call_hwnd_param(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let param = os.syscall_arg(cpu, mem, 1)?;
    let code = os.syscall_arg(cpu, mem, 2)?;
    match code {
        call_hwnd_param::GET_WINDOW_LONG
        | call_hwnd_param::GET_WINDOW_LONG_PTR_A
        | call_hwnd_param::GET_WINDOW_LONG_PTR_W => {
            let value = get_window_long(os, hwnd, param as i64);
            // A 64-bit result cannot come back through the u32 syscall return, so
            // seat it in RAX directly and tell the dispatcher to leave it alone.
            os.return_u64_from_syscall(value);
            Ok(0)
        }
        call_hwnd_param::GET_WINDOW_RECT | call_hwnd_param::GET_CLIENT_RECT => {
            let Some(w) = os.win32k_state.window(hwnd) else { return Ok(0) };
            let (cx, cy) = client_size(w);
            // `GetClientRect` is always origin-relative; `GetWindowRect` is in
            // screen coordinates, which for a child is its ancestors' origins
            // summed plus the top-level window's own screen position.
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
        call_hwnd_param::IS_CHILD => {
            let ancestor = param as u32;
            let mut cur = os.win32k_state.window(hwnd).map(|w| w.parent).unwrap_or(0);
            for _ in 0..WINDOW_ANCESTRY_MAX {
                if cur == 0 {
                    return Ok(0);
                }
                if cur == ancestor {
                    return Ok(1);
                }
                cur = os.win32k_state.window(cur).map(|w| w.parent).unwrap_or(0);
            }
            Ok(0)
        }
        _ => Ok(0),
    }
}

/// `NtUserCallOneParam(arg, code)` — the system-metric / system-colour family.
fn nt_user_call_one_param(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let arg = os.syscall_arg(cpu, mem, 0)?;
    let code = os.syscall_arg(cpu, mem, 1)?;
    match code {
        call_one_param::GET_SYS_COLOR => Ok(sys_color(arg as u32)),
        call_one_param::GET_SYS_COLOR_BRUSH => {
            // A stock system brush: a real GDI handle carrying the colour, so a
            // control's `FillRect(hdc, &r, GetSysColorBrush(COLOR_BTNFACE))`
            // paints the right shade.
            let h = sys_color_brush(os, mem, arg as u32)?;
            Ok(h)
        }
        call_one_param::GET_SYSTEM_METRICS => Ok(system_metric(arg as u32)),
        _ => Ok(0),
    }
}

/// Read a window's `GetWindowLong*` slot. Negative offsets are the documented
/// named fields; a non-negative offset indexes the class's `cbWndExtra` scratch
/// as a little-endian qword — which is where a Wine control keeps its instance
/// data. An out-of-range offset reads 0 rather than faulting.
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

/// Write a window's `SetWindowLong*` slot, returning the previous value. The
/// mirror of [`get_window_long`]; an out-of-range offset is a no-op returning 0.
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

/// `NtUserSetWindowLong(hwnd, offset, value, ansi)` /
/// `NtUserSetWindowLongPtr(hwnd, offset, value, ansi)` — the write half of
/// [`set_window_long`]. The offset arrives sign-extended; the 32-bit form
/// truncates its value, the pointer form does not.
fn nt_user_set_window_long(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let offset = os.syscall_arg(cpu, mem, 1)? as i32 as i64;
    let value = os.syscall_arg(cpu, mem, 2)? as u32 as u64;
    let previous = set_window_long(os, hwnd, offset, value);
    Ok(previous as u32)
}

/// `NtUserSetWindowLongPtr` — as above but full-width in and out.
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

/// `NtUserInternalGetWindowText(hwnd, buffer, maxCount)` — the kernel-side text
/// reader backing `GetWindowTextW`'s fast path. Copy the stored title into the
/// guest buffer (bounded by `maxCount` WCHARs incl. terminator), return the
/// count copied (excluding terminator).
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

// ============================ W4.3: GDI surface + DC =========================

/// Client-area extent (cx, cy) of a window, floored to at least 1×1 so the
/// surface is always allocatable. The stored `rect` is `[x, y, cx, cy]`.
fn client_size(w: &Window) -> (u32, u32) {
    let cx = w.rect[2].max(1) as u32;
    let cy = w.rect[3].max(1) as u32;
    (cx, cy)
}

/// Lazily map the GDI shared handle table + DC-object arena and publish the
/// table base at PEB+0xF8, so gdi32's user-mode HDC decode
/// (`get_gdi_client_ptr`) can walk it. Idempotent — later calls are no-ops.
///
/// Returns `false` (and leaves the table unpublished) if the guest memory map
/// is exhausted or the PEB is unmapped; callers then fall back to bare handles,
/// which gdi32 rejects gracefully (ERROR_INVALID_HANDLE) rather than faulting.
fn ensure_gdi_table(os: &mut WinOs, mem: &mut dyn Memory) -> bool {
    if os.win32k_state.gdi_table_base != 0 {
        return true;
    }
    let peb = os.cfg.peb_addr;
    if peb == 0 {
        return false;
    }
    let table_size = GDI_TABLE_SLOTS * GDI_ENTRY_SIZE;
    let Some(table) = os.map_anywhere(mem, table_size, Perm::RW, "gdi-handle-table") else {
        return false;
    };
    let arena_size = GDI_TABLE_SLOTS * GDI_DC_OBJECT_SIZE;
    let Some(arena) = os.map_anywhere(mem, arena_size, Perm::RW, "gdi-dc-arena") else {
        return false;
    };
    // Publish the table base where gdi32 reads it (PEB+0xF8). map_anywhere
    // zero-fills, so every entry's type byte starts 0 (invalid) — exactly what
    // gdi32 wants for an unallocated slot.
    if mem.write_u64(peb + GDI_PEB_TABLE_PTR_OFF, table).is_err() {
        return false;
    }
    os.win32k_state.gdi_table_base = table;
    os.win32k_state.gdi_dc_arena = arena;
    // Dynamic objects start above the stock block so nothing can overwrite a
    // slot `GetStockObject` reads directly (slot 0 stays reserved: index 0 would
    // make `handle & 0xFFFF == 0`, indistinguishable from a null handle).
    os.win32k_state.gdi_next_slot = STOCK_SLOT_LAST + 1;
    publish_stock_objects(os, mem).is_ok()
}

/// Fill the fixed stock-object slots ([`STOCK_OBJECTS`]) so `gdi32!GetStockObject`
/// finds a live entry instead of executing its `ud2`, and register the stock
/// brushes' colours so selecting one really fills.
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
    }
    Ok(())
}

/// Allocate a GDI-formatted HDC bound to `hwnd`: claim a table slot, fill its
/// 24-byte entry (type/generation/object-pointer) so gdi32's `get_gdi_client_ptr`
/// accepts it, and zero the DC object (offsets +4/+0xA8/+0xB8 = 0 → the direct
/// syscall fast path). Returns 0 if the table could not be published or the
/// slots are exhausted.
///
/// The DC captures `hwnd`'s origin and visible rect **in surface coordinates**
/// (roadmap W4.8), so a child control's primitives land inside its parent's
/// backing store, clipped to the child. gdi32 cannot compute that itself: the
/// user-mode DC object exemu publishes carries no origin fields, so every
/// coordinate arrives in the window's own client space and the offset is applied
/// here, kernel-side.
fn alloc_dc(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<u32> {
    let (hdc, obj) = match alloc_gdi_object(os, mem, gdi_type::DC)? {
        Some(v) => v,
        None => return Ok(0),
    };
    let org = os.win32k_state.client_origin(hwnd);
    let clip = os.win32k_state.window_visible_rect(hwnd);
    // Publish the DC origin where gdi32 reads it. `gdi32!GetDCOrgEx` (RVA
    // 0x23470) answers straight out of `dc_attr[+0x48]` / `[+0x4c]` and issues no
    // syscall — across the whole DLL those two dwords are read and never written,
    // so the kernel side is the only thing that can fill them. A child control
    // asking where its DC sits therefore gets its real offset in the parent.
    mem.write_u32(obj + DC_ATTR_ORG_X, org.0 as u32)?;
    mem.write_u32(obj + DC_ATTR_ORG_Y, org.1 as u32)?;
    os.win32k_state.dcs.push((hdc, Dc { hwnd, brush: 0, org, clip }));
    Ok(hdc)
}

/// Claim a handle-table slot for a GDI object of `ty` (see [`gdi_type`]) and
/// return `(handle, client_object_address)`, or `None` when the table could not
/// be published or its slots are exhausted.
///
/// The entry is filled exactly as gdi32's decoders demand: generation word
/// (@+0x0C) = `ty`, which must equal `handle >> 16` **and** carries the type in
/// its low byte; in-use byte (@+0x0E) non-zero; client-object pointer (@+0x10)
/// into the zeroed arena. A DC's zeroed object additionally selects gdi32's
/// direct-syscall fast path (dword[+4] == 0, qword[+0xA8] == 0, qword[+0xB8] == 0
/// — no batch, no open path, not disabled).
fn alloc_gdi_object(os: &mut WinOs, mem: &mut dyn Memory, ty: u16) -> Result<Option<(u32, u64)>> {
    if !ensure_gdi_table(os, mem) {
        return Ok(None);
    }
    let slot = os.win32k_state.gdi_next_slot;
    if slot >= GDI_TABLE_SLOTS {
        return Ok(None);
    }
    os.win32k_state.gdi_next_slot += 1;

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

/// Mint a solid brush of `color` (a `COLORREF`, `0x00BBGGRR`) and register it,
/// returning its handle (0 if the table is exhausted).
fn alloc_brush(os: &mut WinOs, mem: &mut dyn Memory, color: u32) -> Result<u32> {
    let Some((handle, _)) = alloc_gdi_object(os, mem, gdi_type::BRUSH)? else {
        return Ok(0);
    };
    os.win32k_state.brushes.push((handle, color));
    Ok(handle)
}

/// `GetSysColorBrush(index)` — the cached stock brush for a `COLOR_*` index.
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

/// Ensure the backing surface `hwnd` renders into exists (lazy on first
/// GetDC/BeginPaint): map a guest-addressable top-down BGRA32 DIB (`w*h*4`,
/// stride `w*4`), initialize it to opaque white, store it on the window, and
/// notify the driver. Idempotent. Returns the surface, or `None` if the window
/// is unknown or the map fails.
///
/// **The surface belongs to `hwnd`'s [`surface_owner`]** (roadmap W4.8): a child
/// control shares its top-level ancestor's store rather than getting one of its
/// own, so its pixels appear inside the parent window and one `flush_surface`
/// presents the whole composed frame.
///
/// [`surface_owner`]: Win32kState::surface_owner
fn ensure_surface(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Option<Surface> {
    let owner = os.win32k_state.surface_owner(hwnd);
    let w = os.win32k_state.window(owner)?;
    if let Some(s) = w.surface {
        return Some(s);
    }
    let (cx, cy) = client_size(w);
    let bytes = (cx as u64) * (cy as u64) * 4;
    let base = os.map_anywhere(mem, bytes, Perm::RW, "window-surface")?;
    // Opaque white (0xFFFFFFFF) so drawn text/frame is measurable against it.
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

/// Read the surface `hwnd` renders into out of guest memory and present it
/// through the driver (`flush_surface`). Fire-and-forget; a missing surface is a
/// no-op. A child window presents its **owner's** surface — the composed frame,
/// parent pixels and control pixels together (roadmap W4.8).
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

/// `NtUserGetDC`/`GetDCEx` → a GDI-formatted HDC bound to arg0's window, with
/// its backing surface lazily allocated. arg0 is the hwnd (0 → the desktop; we
/// bind the DC to the first live window in that case, matching the gate's
/// single-window shape). Returns 0 when no window can back the DC.
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

/// Resolve the window an HDC should bind to. A real hwnd is used directly; a
/// NULL hwnd (GetDC(NULL) = the screen DC) binds to the first live **top-level**
/// window so the gate's `GetDC(hwnd)`/`GetDC(NULL)` both land on a surface.
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

/// `NtUserReleaseDC(hwnd, hdc)` → present the surface (the guest is done
/// drawing into it) and drop the DC binding. Returns 1 (released).
fn nt_user_release_dc(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 1)? as u32;
    if let Some(hwnd) = os.win32k_state.dc(hdc).map(|d| d.hwnd) {
        present_surface(os, mem, hwnd)?;
    }
    os.win32k_state.dcs.retain(|(h, _)| *h != hdc);
    Ok(1)
}

/// `NtUserBeginPaint(hwnd, *PAINTSTRUCT)` → allocate a GDI-formatted HDC bound
/// to the window (with its surface), write the PAINTSTRUCT (hdc, fErase=FALSE,
/// rcPaint = the full client rect), and return the HDC. Returns 0 (no paint
/// possible) when the window is unknown.
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
        // PAINTSTRUCT { HDC hdc @0; BOOL fErase @8; RECT rcPaint @0xC (l,t,r,b) }.
        mem.write_u64(ps, hdc as u64)?;
        mem.write_u32(ps + 8, 0)?;
        // rcPaint = **this window's** full client rect (0,0,cx,cy) in its own
        // client coordinates — for a child that is its own extent, not the
        // surface's, which is what a control's WndProc paints against.
        let (cx, cy) = os.win32k_state.window(hwnd).map(client_size).unwrap_or((0, 0));
        mem.write_u32(ps + 0xC, 0)?; // left
        mem.write_u32(ps + 0x10, 0)?; // top
        mem.write_u32(ps + 0x14, cx)?; // right
        mem.write_u32(ps + 0x18, cy)?; // bottom
    }
    Ok(hdc)
}

/// `NtUserEndPaint(hwnd, *PAINTSTRUCT)` → present the surface and drop the paint
/// HDC (read from the PAINTSTRUCT's hdc field). Returns 1.
fn nt_user_end_paint(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let ps = os.syscall_arg(cpu, mem, 1)?;
    if os.win32k_state.window(hwnd).is_some() {
        present_surface(os, mem, hwnd)?;
    }
    if ps != 0 {
        let hdc = mem.read_u64(ps)? as u32;
        os.win32k_state.dcs.retain(|(h, _)| *h != hdc);
    }
    Ok(1)
}

/// `NtUserGetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)`.
///
/// Headless / console / emulated-corpus runs (no input channel attached) keep
/// the W4.1 behaviour: return 0 = `WM_QUIT` at once, so a GUI guest's
/// `while (GetMessage(...))` loop exits immediately.
///
/// On the live Cocoa path (roadmap W4.5c) an input channel is attached: deliver
/// a queued message or `WM_QUIT`, otherwise **park the interpreter thread** on
/// native input until one arrives. The window stays live (no busy-spin) until
/// the user closes it (close → `WM_QUIT`).
fn nt_user_get_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    if !os.has_input() {
        return Ok(0);
    }
    let lp = os.syscall_arg(cpu, mem, 0)?; // lpMsg
    loop {
        os.drain_input();
        // A shown window owes an initial WM_PAINT; synthesize it when the queue
        // is otherwise empty (roadmap W4.6) so the guest's WM_PAINT handler runs.
        synthesize_paint(os);
        // 1. Anything already posted, in order.
        if !os.threads[os.current].msgs.is_empty() {
            if let Some(m) = os.msg_next() {
                os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
                return Ok(if m.message == crate::msg::WM_QUIT { 0 } else { 1 });
            }
        }
        // 2. Then native input, **routed here** rather than when it arrived —
        //    the target depends on the capture, the window tree and, for a
        //    mouse event, on what the window under the cursor answers to
        //    `WM_NCHITTEST`, which means running guest code.
        if let Some(ev) = os.win32k_state.raw_input.pop_front() {
            if route_raw_input(os, cpu, mem, lp, ev)? {
                return Ok(0); // ignored: the hit-test frame supplies rax
            }
            continue;
        }
        // 3. `WM_QUIT` only once nothing else is pending, matching Windows'
        //    "quit is the last message a queue ever delivers".
        if let Some(m) = os.msg_next() {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            return Ok(if m.message == crate::msg::WM_QUIT { 0 } else { 1 });
        }
        os.wait_for_input(std::time::Duration::from_millis(50));
    }
}

/// Post a synthetic `WM_PAINT` to a shown window that owes one, when the current
/// thread's queue is otherwise empty (roadmap W4.6 / design §5).
fn synthesize_paint(os: &mut WinOs) {
    if !os.threads[os.current].msgs.is_empty() {
        return;
    }
    if let Some(hwnd) = os.win32k_state.take_paint_pending() {
        os.post_internal(hwnd as u64, crate::gdi::WM_PAINT as u32, 0, 0);
    }
}

impl WinOs {
    /// Queue a native [`InputEvent`](exemu_core::InputEvent) as **raw input**
    /// (roadmap W4.8 input routing). Nothing is translated here: which window a
    /// mouse event belongs to is decided at retrieval by [`route_raw_input`],
    /// because it needs the capture state, the current window tree and — for a
    /// mouse event over a control — the answer that control gives to
    /// `WM_NCHITTEST`, which is guest code.
    ///
    /// `Close` is handled by the caller (it becomes `WM_QUIT`, not a window
    /// message), so it is dropped here.
    pub(crate) fn post_input_event(&mut self, ev: exemu_core::InputEvent) {
        use exemu_core::InputEvent;
        // Track the cursor position from every pointer event so GetCursorPos
        // reports where the user last pointed (roadmap W4.7).
        match ev {
            InputEvent::MouseMove { x, y } | InputEvent::MouseButton { x, y, .. } => {
                self.win32k_state.cursor_pos = (x, y)
            }
            InputEvent::Close => return,
            _ => {}
        }
        self.win32k_state.raw_input.push_back(ev);
    }
}

/// The Win32 message a native event becomes, as `(message, wParam)`. Mouse
/// events carry their position separately because it still has to be rebased
/// into the target window's client space.
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
        InputEvent::Key { vk, down: true } => (WM_KEYDOWN, vk as u64),
        InputEvent::Key { vk, down: false } => (WM_KEYUP, vk as u64),
    };
    Some((msg as u32, wparam))
}

/// The screen point of a native event, or `None` for a keyboard event.
fn input_point(ev: exemu_core::InputEvent) -> Option<(i32, i32)> {
    use exemu_core::InputEvent;
    match ev {
        InputEvent::MouseMove { x, y } | InputEvent::MouseButton { x, y, .. } => Some((x, y)),
        _ => None,
    }
}

/// Pack a point into an `lParam` (x in the low word, y in the high).
fn pack_point(x: i32, y: i32) -> u64 {
    (x as u32 as u64 & 0xffff) | ((y as u32 as u64 & 0xffff) << 16)
}

/// **Route one native event to a window** (roadmap W4.8 input routing).
///
/// Returns `true` when a `WM_NCHITTEST` callback was installed, in which case the
/// syscall's caller is resumed by the callback frame and the delivered message
/// has already been written into `lp` by [`finish_hit_test`]; `false` when the
/// event was posted (or dropped) and the pump should carry on.
///
/// The order is Windows': **capture first, hit test second**. While a window
/// holds the capture every mouse event goes to it in its own client coordinates
/// with no hit test at all — that is what lets Wine's `ButtonWndProc`, which
/// takes the capture on `WM_LBUTTONDOWN`, still receive the matching
/// `WM_LBUTTONUP` after the pointer has left the button.
fn route_raw_input(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    lp: u64,
    ev: exemu_core::InputEvent,
) -> Result<bool> {
    let Some((msg, wparam)) = input_message(ev) else { return Ok(false) };
    let Some((x, y)) = input_point(ev) else {
        // Keyboard: the focus window, or the active top-level as a fallback so a
        // guest that never calls `SetFocus` still receives its keys.
        let target = keyboard_target(os);
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

    let target = os.win32k_state.window_from_point(x, y, &[]);
    if target == 0 {
        return Ok(false); // outside every window — nothing to deliver to
    }
    begin_hit_test(os, cpu, mem, lp, ev, msg, wparam, target, Vec::new())
}

/// The window a key message goes to: the focus window, else the active window,
/// else the shown top-level.
fn keyboard_target(os: &WinOs) -> u32 {
    let st = &os.win32k_state;
    for h in [st.focus, st.active] {
        if h != 0 && st.window(h).is_some() {
            return h;
        }
    }
    st.shown_window().unwrap_or(0)
}

/// State carried across a `WM_NCHITTEST` callback so the answer can be turned
/// into the message that is actually delivered.
pub(crate) struct PendingHitTest {
    /// The native event being routed.
    ev: exemu_core::InputEvent,
    /// The client message it maps to, and its `wParam`.
    msg: u32,
    wparam: u64,
    /// The window being asked.
    hwnd: u32,
    /// The guest `MSG*` `GetMessage` was called with.
    lp: u64,
    /// Windows already excluded by an `HTTRANSPARENT` answer.
    skipped: Vec<u32>,
}

/// Prepare one `WM_NCHITTEST` round for `hwnd`.
///
/// `Ok(Some((wndproc, args)))` — ask that window; `Ok(None)` — no ask was
/// possible or warranted, and the message has already been delivered using the
/// kernel's own answer. A window with no WndProc (one whose class was never
/// registered) cannot answer, so the default applies straight away — which keeps
/// a plain single-window guest on exactly the path it had before hit-testing
/// existed.
fn arm_hit_test(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    pending: &PendingHitTest,
) -> Result<Option<(u64, Vec<u64>)>> {
    let hwnd = pending.hwnd;
    let wndproc = os.win32k_state.wndproc_for(hwnd);
    let (x, y) = input_point(pending.ev).unwrap_or((0, 0));
    // `!can_call_client()` (a WoW64 process) is handled here rather than at the
    // callback itself because `pending` is consumed by the install: a window
    // that *cannot* be asked is indistinguishable from one that has no WndProc,
    // and both take the kernel's own answer.
    if wndproc == 0 || !os.can_call_client() || pending.skipped.len() >= HIT_TEST_ROUNDS_MAX {
        let code =
            if os.win32k_state.contains_point(hwnd, x, y) { hit::CLIENT } else { hit::NOWHERE };
        deliver_hit(os, mem, pending.lp, pending.ev, pending.msg, pending.wparam, hwnd, code)?;
        return Ok(None);
    }
    Ok(Some((wndproc, vec![hwnd as u64, WM_NCHITTEST as u64, 0, pack_point(x, y)])))
}

/// Ask `hwnd` what part of itself the point is over, then deliver accordingly.
/// Returns whether a callback was installed (see [`route_raw_input`]).
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

/// The `WM_NCHITTEST` answer came back: either retry with the transparent window
/// excluded, or deliver the message the answer selects.
///
/// This runs from the win32k callback-driver thunk, **not** from a syscall
/// handler, so a second round is queued onto the frame that is already open
/// rather than opening a new one.
pub(crate) fn finish_hit_test(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    mem: &mut dyn Memory,
    mut pending: PendingHitTest,
    lresult: u64,
) -> Result<()> {
    let code = lresult as i64;
    // The message is written straight into the guest's MSG buffer, so
    // `GetMessage` answers TRUE — a zero would mean `WM_QUIT` and stop the loop.
    os.win32k_cb_set_result(1);
    if code == hit::TRANSPARENT {
        // "I am not here": exclude this window and look again. Wine's
        // `ButtonWndProc` answers exactly this for a `BS_GROUPBOX`, so a click
        // inside a group box must reach whatever is underneath it.
        pending.skipped.push(pending.hwnd);
        let (x, y) = input_point(pending.ev).unwrap_or((0, 0));
        let next = os.win32k_state.window_from_point(x, y, &pending.skipped);
        if next != 0 && next != pending.hwnd {
            pending.hwnd = next;
            if let Some((wndproc, args)) = arm_hit_test(os, mem, &pending)? {
                os.win32k_cb_queue(wndproc, args);
                os.win32k_cb_set_then(pending);
            }
            return Ok(());
        }
        // Nothing underneath: the event has nowhere to go.
        return write_null_message(os, mem, pending.lp);
    }
    deliver_hit(os, mem, pending.lp, pending.ev, pending.msg, pending.wparam, pending.hwnd, code)
}

/// Turn a hit-test answer into the delivered message and write it into the
/// guest's `MSG` — or post it, when there is no `MSG` to fill (the pre-hit-test
/// path that reached here without a callback frame).
///
/// `HTCLIENT` gives the ordinary client message with the point rebased into the
/// window's client space; any other code gives the **non-client twin**
/// (`WM_MOUSEMOVE` → `WM_NCMOUSEMOVE`, …) with the hit code in `wParam` and the
/// screen point in `lParam`, which is the documented Win32 shape.
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

/// Fill the guest's `MSG` with a benign `WM_NULL` for a window that is nowhere.
/// `DispatchMessage` on a null hwnd is a documented no-op, so the pump keeps
/// running instead of the kernel having to invent a target.
fn write_null_message(os: &mut WinOs, mem: &mut dyn Memory, lp: u64) -> Result<()> {
    if lp == 0 {
        return Ok(());
    }
    os.write_msg_full(mem, lp, 0, 0, 0, 0)
}

// =================== W4.8 input routing: the syscall surface =================

/// `NtUserWindowFromPoint(x, y)` — `user32!WindowFromPoint` is four instructions
/// that unpack the by-value `POINT` (x in the low half of `rcx`, y shifted into
/// `edx`) and tail-jump here, so the entire tree walk is the kernel's.
fn nt_user_window_from_point(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let x = os.syscall_arg(cpu, mem, 0)? as i32;
    let y = os.syscall_arg(cpu, mem, 1)? as i32;
    Ok(os.win32k_state.window_from_point(x, y, &[]))
}

/// `NtUserChildWindowFromPointEx(hwnd, x, y, flags)` — the *direct* child of
/// `hwnd` under the point (one level, unlike `WindowFromPoint`'s descent), or
/// `hwnd` itself. `user32!ChildWindowFromPointEx` likewise only unpacks the
/// `POINT` (`mov r8,rdx; shr r8,0x20`) and tail-jumps.
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
    // The point arrives in the parent's client coordinates.
    let (ox, oy) = os.win32k_state.client_origin(parent);
    Ok(os.win32k_state.child_window_from_point(parent, x + ox, y + oy))
}

/// `NtUserSetCapture(hwnd)` → the window that held the capture before, and
/// `WM_CAPTURECHANGED` to it. `user32!SetCapture` is a bare thunk, so all of the
/// semantics live here.
fn nt_user_set_capture(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    set_capture(os, cpu, mem, hwnd)
}

/// `NtUserReleaseCapture()` → TRUE, releasing whatever held it.
fn nt_user_release_capture(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    set_capture(os, cpu, mem, 0)?;
    Ok(1)
}

/// Install (or drop, with `hwnd == 0`) the mouse capture, notifying the window
/// that loses it. Returns the previous holder.
///
/// The notification matters: Wine's `ButtonWndProc` has a `WM_CAPTURECHANGED`
/// arm that drops its pushed state, so a button whose capture is stolen
/// un-presses itself instead of staying stuck down.
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

/// `NtUserSetFocus(hwnd)` → the previously focused window, with `WM_KILLFOCUS`
/// to it and `WM_SETFOCUS` to the new one (documented order and `wParam`s).
/// `user32!SetFocus` is a bare thunk into this.
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

/// `NtUserSetActiveWindow(hwnd)` → the previously active window.
fn nt_user_set_active_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let prev = os.win32k_state.active;
    if os.win32k_state.window(hwnd).is_some() {
        os.win32k_state.active = hwnd;
    }
    Ok(prev)
}

/// `NtUserGetThreadState(index)` — the read side of the per-thread input state.
/// `GetFocus`/`GetActiveWindow`/`GetCapture` are one-line user32 wrappers that do
/// nothing but load index 0/1/2 and tail-jump here.
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

/// `NtUserGetAncestor(hwnd, type)` — `GA_PARENT` walks one link, `GA_ROOT` /
/// `GA_ROOTOWNER` walk to the top-level window (which is also the window that
/// owns the backing surface).
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

/// Dispatch `(hwnd, msg, wParam, lParam)` to the target window's WndProc via the
/// direct-call path (roadmap W4.6): seat `wndproc(hwnd, msg, wParam, lParam)` on
/// the guest stack and resume the interrupted syscall's caller when it returns,
/// with the WndProc's LRESULT in rax. A message for an unknown / class-less
/// window is a no-op (returns 0). Shared by `NtUserDispatchMessage` and the
/// WndProc arm of `NtUserMessageCall`.
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
        // No frame was installed (a WoW64 process — see `can_call_client`), so
        // nothing will supply rax on resume: answer here instead of returning
        // a 0 the handler never meant.
        return Ok(result.unwrap_or(0) as u32);
    }
    Ok(0) // ignored: the callback frame supplies rax on resume
}

/// `NtUserDispatchMessage(lpMsg)` — invoke the target window's WndProc with the
/// message (roadmap W4.6). Wine's `DispatchMessageW` reaches this for `WM_PAINT`
/// (and other "posted" messages that lower straight to the dispatcher); input
/// messages arrive instead through [`nt_user_message_call`].
fn nt_user_dispatch_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let lp = os.syscall_arg(cpu, mem, 0)?;
    if lp == 0 {
        return Ok(0);
    }
    let (hwnd, message, wparam, lparam) = os.read_msg(mem, lp)?;
    // `DispatchMessageW` returns this syscall's result verbatim, so the WndProc's
    // own LRESULT is what belongs in rax.
    dispatch_to_wndproc(os, cpu, mem, hwnd, message as u32, wparam, lparam, None)
}

/// `NtUserPeekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg)` —
/// the non-blocking half of the pump (`user32!PeekMessageW` is a bare thunk into
/// it). Returns TRUE when a message was available.
///
/// With `PM_REMOVE` it does everything [`nt_user_get_message`] does short of
/// parking — including routing a pending native event, which may run a
/// `WM_NCHITTEST` callback before the message is written. With `PM_NOREMOVE` it
/// only looks at what is already queued: routing an event *consumes* it, and a
/// caller that asked not to remove anything must not lose it.
///
/// Without an input channel it keeps the W4.1 answer (0 = nothing), which is what
/// every headless and emulated-corpus run sees.
fn nt_user_peek_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    const PM_REMOVE: u32 = 0x0001;
    if !os.has_input() {
        return Ok(0);
    }
    let lp = os.syscall_arg(cpu, mem, 0)?;
    let remove = os.syscall_arg(cpu, mem, 4)? as u32 & PM_REMOVE != 0;
    os.drain_input();
    synthesize_paint(os);
    if !os.threads[os.current].msgs.is_empty() {
        if let Some(m) = os.msg_peek(remove) {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            return Ok(1);
        }
    }
    if remove {
        if let Some(ev) = os.win32k_state.raw_input.pop_front() {
            if route_raw_input(os, cpu, mem, lp, ev)? {
                return Ok(0); // ignored: the hit-test frame supplies rax
            }
            // Routed into the queue: hand it straight back.
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

/// `NtUserTranslateMessage(lpMsg, flags)` — turn a key-down into the character
/// message that follows it (`user32!TranslateMessage` is `xor edx,edx; jmp`
/// here). The `WM_CHAR` is *posted*, not delivered: it becomes the next message
/// the pump hands out, which is the documented behaviour and what a text control
/// relies on.
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
    // TRUE means "this was a key message", whether or not it produced a
    // character — the documented contract.
    Ok(1)
}

/// `NtUserPostQuitMessage(nExitCode)` — mark the running thread to receive
/// `WM_QUIT` once its queue drains (roadmap W4.6), so a guest WndProc's
/// `WM_DESTROY → PostQuitMessage` stops the message loop.
fn nt_user_post_quit_message(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let code = os.syscall_arg(cpu, mem, 0)? as i32;
    os.threads[os.current].quit_code = Some(code);
    Ok(0)
}

// ============================ W4.7: cursor / display =========================

/// `NtUserGetCursor()` → the current cursor handle (roadmap W4.7).
fn nt_user_get_cursor(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(os.win32k_state.current_cursor as u32)
}

/// `NtUserSetCursor(hCursor)` — install a new cursor shape, returning the
/// previous handle (roadmap W4.7). Notifies the driver so a live backend can swap
/// the `NSCursor`.
fn nt_user_set_cursor(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hcursor = os.syscall_arg(cpu, mem, 0)?;
    let prev = os.win32k_state.current_cursor;
    os.win32k_state.current_cursor = hcursor;
    os.driver.set_cursor(hcursor);
    Ok(prev as u32)
}

/// `NtUserGetCursorPos(lpPoint)` — write the tracked cursor position (screen
/// pixels) into the guest `POINT{LONG x, LONG y}` (roadmap W4.7). Returns TRUE.
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

/// `NtUserSetCursorPos(x, y)` — move the tracked cursor position (roadmap W4.7).
/// exemu does not warp the host cursor; it updates the position `GetCursorPos`
/// reports. Returns TRUE.
fn nt_user_set_cursor_pos(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let x = os.syscall_arg(cpu, mem, 0)? as i32;
    let y = os.syscall_arg(cpu, mem, 1)? as i32;
    os.win32k_state.cursor_pos = (x, y);
    Ok(1)
}

/// `NtUserClipCursor(lpRect)` — accept the cursor confinement (roadmap W4.7).
/// exemu does not confine the host cursor; the call succeeds so guests that gate
/// on the BOOL proceed. Returns TRUE.
fn nt_user_clip_cursor(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(1)
}

/// `NtUserChangeDisplaySettings(...)` — accept the requested mode (roadmap W4.7).
/// exemu presents a fixed display, so the change is not applied, but a query /
/// compatible mode reports success. Returns `DISP_CHANGE_SUCCESSFUL`.
fn nt_user_change_display_settings(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(DISP_CHANGE_SUCCESSFUL)
}

/// `NtUserEnumDisplaySettings(device, iModeNum, lpDevMode, flags)` — report the
/// driver's single display mode (roadmap W4.7). Mode 0 and the current/registry
/// sentinels resolve to that mode; any higher index returns FALSE (end of
/// enumeration). Fills the display fields of the caller's `DEVMODEW`, leaving the
/// rest (which the caller zeroed) untouched.
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
        return Ok(0); // exemu exposes exactly one mode
    }
    write_devmode(mem, lp, os.driver.display_mode())?;
    Ok(1)
}

/// Fill the display fields of a guest `DEVMODEW` at `lp` from `mode` (roadmap
/// W4.7). Leaves the rest of the struct — which the caller zeroed — untouched.
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

/// `NtUserMsgWaitForMultipleObjectsEx(count, handles, timeout, wakeMask, flags)`
/// — the message-aware wait (roadmap W4.7). exemu's single interpreter thread
/// drains native input; if a message is now queued it reports it, otherwise it
/// parks briefly on the input channel (never blocking the OS thread on AppKit)
/// and reports the message-available result so the caller re-checks its queue.
fn nt_user_msg_wait_for_multiple_objects_ex(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let count = os.syscall_arg(cpu, mem, 0)? as u32;
    os.drain_input();
    synthesize_paint(os);
    let idle = os.threads[os.current].msgs.is_empty() && os.threads[os.current].quit_code.is_none();
    if idle {
        os.wait_for_input(std::time::Duration::from_millis(50));
    }
    // WAIT_OBJECT_0 + count == "a queued message is available"; the caller then
    // drains it via PeekMessage/GetMessage.
    Ok(count)
}

// ============================ W4.3: NtGdi paint handlers =====================

/// Opaque-black pixel (BGRA32, `0xFF000000`) — text + rectangle frame draw in
/// black on the white surface.
const BGRA_BLACK: u32 = 0xFF00_0000;

/// A DC resolved to the pixels it may touch (roadmap W4.8): the surface it
/// renders into, the window's origin inside that surface, and the visible rect
/// every primitive is clipped to. This is the whole child-window painting
/// contract in one value — a top-level DC has `org == (0, 0)` and a full-surface
/// clip, a control's DC carries its offset and its slice of the parent.
#[derive(Clone, Copy)]
struct DcTarget {
    surface: Surface,
    /// The DC window's client origin in surface coordinates.
    org: (i32, i32),
    /// The clip rect in surface coordinates, `[left, top, right, bottom)`.
    clip: [i32; 4],
}

impl DcTarget {
    /// Map a logical `(x, y)` in the DC window's client space to surface pixels.
    fn map(&self, x: i32, y: i32) -> (i32, i32) {
        (x + self.org.0, y + self.org.1)
    }
}

/// Resolve `hdc → window → surface + origin + clip` for a paint handler. Returns
/// `None` (the honest "unbound HDC" failure) when the HDC was never issued by
/// this module or the surface it would draw into does not exist.
fn dc_surface(os: &WinOs, hdc: u32) -> Option<DcTarget> {
    let dc = os.win32k_state.dc(hdc)?;
    let (org, clip) = (dc.org, dc.clip);
    let owner = os.win32k_state.surface_owner(dc.hwnd);
    let surface = os.win32k_state.window(owner)?.surface?;
    Some(DcTarget { surface, org, clip })
}

/// Write one BGRA32 pixel into a DC's surface, in **surface** coordinates,
/// clipped to both the surface bounds and the DC's visible rect. Callers map
/// logical coordinates with [`DcTarget::map`] first.
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

/// Rasterize one UTF-16 code unit as an 8×8 `font8x8` glyph at logical `(x, y)`,
/// top-left origin, in `bgra`, clipped to the DC. Non-representable units draw
/// nothing (a blank cell), matching a metric-only stub font.
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

/// `NtGdiExtTextOutW(hdc, x, y, flags, RECT* rect, WCHAR* str, UINT count,
/// INT* dx, DWORD reserved)` — the syscall gdi32!TextOutW→ExtTextOutW lowers to
/// (recovered ABI; args 0..3 in R10/RDX/R8/R9, args 4+ on the guest stack).
///
/// Renders `count` UTF-16 units of `str` with the stub 8×8 font (black on the
/// white surface, 8px advance per cell), clipped to surface bounds. Returns 1
/// (TRUE) on a bound HDC, 0 (FALSE) when the HDC is not one of ours.
fn nt_gdi_ext_text_out_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let x = os.syscall_arg(cpu, mem, 1)? as i32;
    let y = os.syscall_arg(cpu, mem, 2)? as i32;
    let str_ptr = os.syscall_arg(cpu, mem, 5)?;
    let count = os.syscall_arg(cpu, mem, 6)? as u32;

    let Some(target) = dc_surface(os, hdc) else {
        return Ok(0);
    };

    // Read the run.
    let mut units = Vec::with_capacity(count as usize);
    for i in 0..count {
        units.push(mem.read_u16(str_ptr + i as u64 * 2)?);
    }
    let text = String::from_utf16_lossy(&units);

    // Prefer the driver's real (CoreText) glyph rasterizer (roadmap W4.8),
    // compositing its alpha coverage in black at the run origin; fall back to the
    // built-in font8x8 stub headlessly / when the driver has no font backend.
    // The HFONT-selected size isn't tracked yet, so a default cell height stands
    // in (proportional metrics come from the rasterizer regardless).
    const DEFAULT_TEXT_PX: u32 = 16;
    // The text colour is the DC's own — `SetTextColor` wrote it into the
    // guest-visible DC object at `DC_ATTR_TEXT_COLOR`, and a zeroed object is
    // already the default black, so this reads correctly with or without a
    // `SetTextColor` call (roadmap W4.8).
    let color = gdi_client_object(os, mem, hdc)
        .and_then(|obj| mem.read_u32(obj + DC_ATTR_TEXT_COLOR).ok())
        .map(colorref_to_bgra)
        .unwrap_or(BGRA_BLACK);
    if let Some(tb) = os.driver.rasterize_text(&text, DEFAULT_TEXT_PX) {
        composite_coverage(mem, &target, x, y, &tb, color)?;
    } else {
        let mut cx = x;
        for ch in text.chars() {
            draw_glyph(mem, &target, ch, cx, y, color)?;
            cx += 8;
        }
    }
    Ok(1)
}

/// Composite a top-down 8-bit alpha `coverage` (from the driver's text
/// rasterizer) onto the DC's surface at logical `(x, y)`, blending each covered
/// pixel toward `color` — the DC's text colour (roadmap W4.8). Clipped to the
/// DC's visible rect; opaque background modes (`SetBkMode(OPAQUE)`) are deferred.
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
                continue; // fully transparent: leave the background pixel
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
            // out = existing*(1-a) + color*a, per BGR channel; keep A.
            let inv = 255 - a;
            let b = ((existing & 0xff) * inv + fb * a) / 255;
            let g = (((existing >> 8) & 0xff) * inv + fg * a) / 255;
            let r = (((existing >> 16) & 0xff) * inv + fr * a) / 255;
            mem.write_u32(off, (existing & 0xff00_0000) | (r << 16) | (g << 8) | b)?;
        }
    }
    Ok(())
}

/// `NtGdiRectangle(hdc, left, top, right, bottom)` — the syscall gdi32!Rectangle
/// tail-calls directly (recovered ABI: hdc/left/top/right in R10/RDX/R8/R9,
/// bottom the 5th stack arg).
///
/// Draws a 1px black frame (no fill — the stub uses the DC's implicit hollow
/// brush / null-fill fast path), clipped to the surface. `right`/`bottom` are
/// exclusive per the Win32 `Rectangle` contract, so the frame's far edges sit
/// at `right-1`/`bottom-1`. Returns 1 (TRUE) on a bound HDC, else 0.
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
        return Ok(1); // degenerate rect: nothing to draw, still success.
    }
    let (x0, y0) = target.map(left, top);
    let (x1, y1) = target.map(right - 1, bottom - 1);
    // Top + bottom edges.
    for x in x0..=x1 {
        put_pixel(mem, &target, x, y0, BGRA_BLACK)?;
        put_pixel(mem, &target, x, y1, BGRA_BLACK)?;
    }
    // Left + right edges.
    for y in y0..=y1 {
        put_pixel(mem, &target, x0, y, BGRA_BLACK)?;
        put_pixel(mem, &target, x1, y, BGRA_BLACK)?;
    }
    Ok(1)
}

/// **The recovered win32u / GDI boundary, published for the ABI gate.**
///
/// Every value here was read out of the pinned Wine binaries, never guessed, and
/// `crates/app/tests/win32k_abi.rs` re-derives each one from those same bytes on
/// every run. Re-exporting the module's own constants (rather than mirroring
/// them in the test) means the gate checks *what the handlers actually use*: a
/// Wine bump that renumbers a syscall, a call selector or a DC_ATTR field fails
/// there, loudly, instead of turning into a silently wrong answer at paint time.
pub mod abi {
    /// win32u syscall indices, as `(export name, index)`. The index is the
    /// `mov eax, imm32` immediate in that export's stub.
    pub const SYSCALLS: [(&str, u32); 36] = [
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

    /// `NtUserCallHwnd(hwnd, code)` selectors, as `(user32 export that issues
    /// this code, code)`.
    pub const CALL_HWND: [(&str, u64); 6] = [
        ("IsWindow", super::call_hwnd::IS_WINDOW),
        ("IsWindowEnabled", super::call_hwnd::IS_WINDOW_ENABLED),
        ("IsWindowUnicode", super::call_hwnd::IS_WINDOW_UNICODE),
        ("IsWindowVisible", super::call_hwnd::IS_WINDOW_VISIBLE),
        ("GetParent", super::call_hwnd::GET_PARENT),
        // `WIN_IsCurrentProcess`, which `SetWindowTextW` inlines the call to,
        // and whose result `DefWindowProcW` uses as the window handle.
        ("SetWindowTextW", super::call_hwnd::IS_SELF_THREAD),
    ];

    /// `NtUserGetThreadState(index)` selectors, as `(user32 export, index)` —
    /// each of those exports is a two-instruction wrapper around this syscall.
    pub const THREAD_STATE: [(&str, u64); 3] = [
        ("GetFocus", super::thread_state::FOCUS),
        ("GetActiveWindow", super::thread_state::ACTIVE),
        ("GetCapture", super::thread_state::CAPTURE),
    ];

    /// `NtUserMessageCall`'s `type` argument, as `(user32 export, type)`. The
    /// immediate each wrapper stores in the syscall's 6th argument slot.
    pub const MESSAGE_CALL_TYPES: [(&str, u64); 6] = [
        ("SendMessageW", super::message_call::SEND_MESSAGE),
        ("SendMessageTimeoutW", super::message_call::SEND_MESSAGE_TIMEOUT),
        ("SendNotifyMessageW", super::message_call::SEND_NOTIFY_MESSAGE),
        ("SendMessageCallbackW", super::message_call::SEND_MESSAGE_CALLBACK),
        ("CallWindowProcW", super::message_call::CALL_WINDOW_PROC),
        ("DefWindowProcW", super::message_call::DEF_WINDOW_PROC),
    ];

    /// The type the internal `dispatch_message` — the tail of
    /// `DispatchMessage{A,W}` — passes. Not reachable by export name; the test
    /// follows `DispatchMessageW`'s own call into it.
    pub const MESSAGE_CALL_DISPATCH: u64 = super::message_call::DISPATCH_MESSAGE;

    /// `WM_NCHITTEST`, and the `HTCLIENT`/`HTTRANSPARENT` codes exemu's routing
    /// branches on.
    pub const WM_NCHITTEST: u32 = super::WM_NCHITTEST;
    pub const HT_CLIENT: i64 = super::hit::CLIENT;
    pub const HT_TRANSPARENT: i64 = super::hit::TRANSPARENT;

    /// `NtUserCallHwndParam(hwnd, param, code)` selectors, likewise.
    pub const CALL_HWND_PARAM: [(&str, u64); 5] = [
        ("GetWindowRect", super::call_hwnd_param::GET_WINDOW_RECT),
        ("GetClientRect", super::call_hwnd_param::GET_CLIENT_RECT),
        ("GetWindowLongPtrA", super::call_hwnd_param::GET_WINDOW_LONG_PTR_A),
        ("GetWindowLongPtrW", super::call_hwnd_param::GET_WINDOW_LONG_PTR_W),
        ("IsChild", super::call_hwnd_param::IS_CHILD),
    ];

    /// `NtUserCallOneParam(arg, code)` selectors, likewise.
    pub const CALL_ONE_PARAM: [(&str, u64); 3] = [
        ("GetSysColor", super::call_one_param::GET_SYS_COLOR),
        ("GetSysColorBrush", super::call_one_param::GET_SYS_COLOR_BRUSH),
        ("GetSystemMetrics", super::call_one_param::GET_SYSTEM_METRICS),
    ];

    /// `NtGdiGetAndSetDCDword` selectors, as `(gdi32 setter, code)`.
    pub const DC_DWORD: [(&str, u64); 2] = [
        ("SetTextColor", super::dc_dword::TEXT_COLOR),
        ("SetBkColor", super::dc_dword::BK_COLOR),
    ];

    /// DC_ATTR field offsets, as `(gdi32 accessor that reads it, offset)`.
    pub const DC_ATTR: [(&str, u64); 3] = [
        ("GetDCOrgEx", super::DC_ATTR_ORG_X),
        ("GetTextColor", super::DC_ATTR_TEXT_COLOR),
        ("GetBkColor", super::DC_ATTR_BK_COLOR),
    ];

    /// The GDI shared handle table's entry stride and the three field offsets
    /// gdi32's decoders read: generation/type word, in-use byte, object pointer.
    pub const GDI_ENTRY_SIZE: u64 = super::GDI_ENTRY_SIZE;
    pub const GDI_ENTRY_GENERATION_OFF: u64 = super::GDI_ENTRY_GENERATION_OFF;
    pub const GDI_ENTRY_TYPE_OFF: u64 = super::GDI_ENTRY_TYPE_OFF;
    pub const GDI_ENTRY_OBJECT_OFF: u64 = super::GDI_ENTRY_OBJECT_OFF;
    /// Where the table base is published in the PEB.
    pub const GDI_PEB_TABLE_PTR_OFF: u64 = super::GDI_PEB_TABLE_PTR_OFF;
    /// The GDI object type of a brush — the value `gdi32!SelectObject` compares
    /// `(byte[entry+0x0C] & 0x7f) << 16` against before calling
    /// `NtGdiSelectBrush`.
    pub const GDI_TYPE_BRUSH: u16 = super::gdi_type::BRUSH;
    /// Stock-object slots: base (`slot = index + BASE`) and the last slot.
    pub const STOCK_SLOT_BASE: u64 = super::STOCK_SLOT_BASE;
    pub const STOCK_SLOT_LAST: u64 = super::STOCK_SLOT_LAST;
    /// Every stock slot exemu publishes, `(slot, type)`.
    pub fn stock_slots() -> Vec<(u64, u16)> {
        super::STOCK_OBJECTS.iter().map(|(s, t, _)| (*s, *t)).collect()
    }
    /// Entries in each client-PFN array (roadmap W6.2).
    pub const CLIENT_PFN_COUNT: usize = super::CLIENT_PFN_COUNT;
}

/// Convert a Win32 `COLORREF` (`0x00BBGGRR`) to the surface's opaque BGRA32.
fn colorref_to_bgra(c: u32) -> u32 {
    let (r, g, b) = (c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF);
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

/// `NtGdiCreateSolidBrush(color, unused)` — `gdi32!CreateSolidBrush` is a bare
/// `xor edx,edx; jmp` into this, so the COLORREF arrives untouched in arg0.
fn nt_gdi_create_solid_brush(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let color = os.syscall_arg(cpu, mem, 0)? as u32;
    alloc_brush(os, mem, color)
}

/// `NtGdiCreatePen(style, width, color, brush)` — minted as a typed handle so
/// `gdi32!SelectObject`'s pen arm accepts it. exemu draws 1-px frames only, so
/// style and width are recorded nowhere yet; the handle exists so a control that
/// creates and selects a pen proceeds instead of failing.
fn nt_gdi_create_pen(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(alloc_gdi_object(os, mem, gdi_type::PEN)?.map(|(h, _)| h).unwrap_or(0))
}

/// `NtGdiSelectBrush(hdc, hbrush)` → the previously selected brush. This is
/// where `FillRect`'s `SelectObject(hdc, hbr)` lands.
fn nt_gdi_select_brush(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let brush = os.syscall_arg(cpu, mem, 1)? as u32;
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(0);
    };
    let previous = dc.brush;
    dc.brush = brush;
    // A brush was really selected even when the DC had none before: report the
    // handle back so `FillRect`'s restoring `SelectObject` is not a no-op.
    Ok(previous)
}

/// `NtGdiSelectPen(hdc, hpen, ...)` → the previous pen. exemu tracks no pen
/// state yet (frames are 1-px black), so this only has to succeed.
fn nt_gdi_select_pen(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(os.syscall_arg(cpu, mem, 1)? as u32)
}

/// `NtGdiSelectFont(hdc, hfont)` → the previous font. The CoreText path picks
/// its own metrics (design §5), so an HFONT is only a handle that must
/// round-trip; selecting one must not fail or a control abandons its text.
fn nt_gdi_select_font(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(os.syscall_arg(cpu, mem, 1)? as u32)
}

/// `NtGdiGetTextMetricsW(hdc, TEXTMETRICW*, flags)` — fill the caller's metrics
/// from the stand-in font cell.
///
/// **Load-bearing for a control's label.** `DrawTextW` asks for the metrics
/// before it lays anything out; with the honest-0 stub it received a zero line
/// height and drew no text at all, which is why Wine's `BUTTON` came out blank
/// even once it was filling its own background.
fn nt_gdi_get_text_metrics_w(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let tm = os.syscall_arg(cpu, mem, 1)?;
    if tm == 0 || os.win32k_state.dc(hdc).is_none() {
        return Ok(0);
    }
    let (h, d) = (STUB_FONT_CELL_H, STUB_FONT_DESCENT);
    mem.write_u32(tm + TM_HEIGHT, h)?;
    mem.write_u32(tm + TM_ASCENT, h - d)?;
    mem.write_u32(tm + TM_DESCENT, d)?;
    mem.write_u32(tm + TM_INTERNAL_LEADING, 2)?;
    mem.write_u32(tm + TM_EXTERNAL_LEADING, 0)?;
    mem.write_u32(tm + TM_AVE_CHAR_WIDTH, STUB_FONT_CELL_W)?;
    mem.write_u32(tm + TM_MAX_CHAR_WIDTH, STUB_FONT_CELL_W)?;
    mem.write_u32(tm + TM_WEIGHT, 400)?; // FW_NORMAL
    mem.write_u32(tm + TM_OVERHANG, 0)?;
    mem.write_u32(tm + TM_DIGITIZED_ASPECT_X, 96)?;
    mem.write_u32(tm + TM_DIGITIZED_ASPECT_Y, 96)?;
    mem.write_u16(tm + TM_FIRST_CHAR, 0x20)?;
    mem.write_u16(tm + TM_LAST_CHAR, 0xFF)?;
    mem.write_u16(tm + TM_DEFAULT_CHAR, 0x1F)?;
    mem.write_u16(tm + TM_BREAK_CHAR, 0x20)?;
    mem.write_u8(tm + TM_ITALIC, 0)?;
    mem.write_u8(tm + TM_UNDERLINED, 0)?;
    mem.write_u8(tm + TM_STRUCK_OUT, 0)?;
    // Fixed pitch (bit 0 clear), FF_DONTCARE — true of the deterministic
    // `font8x8` cell the headless path renders with.
    mem.write_u8(tm + TM_PITCH_AND_FAMILY, 0)?;
    mem.write_u8(tm + TM_CHARSET, 0)?; // ANSI_CHARSET
    Ok(1)
}

/// `NtGdiGetTextExtentExW(hdc, str, count, maxExtent, lpnFit, alpDx, lpSize,
/// flags)` — measure a run.
///
/// Recovered arg layout from `gdi32!GetTextExtentExPointW` (RVA 0x25c10): at its
/// call site (0x25d85) `rcx`/`rdx`/`r8d` carry hdc/string/count and the caller's
/// `LPSIZE` is stored into the 7th argument slot (`[rsp+0x30]` of its frame).
///
/// **The other half of a control's label.** `DrawTextW` measures before it
/// positions: with this unserviced it centred the text against an uninitialized
/// width and placed the run a million pixels off-surface, so nothing appeared
/// even though `ExtTextOutW` really was called. The width comes from the same
/// rasterizer the draw uses, so measure and draw agree.
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
    let (cx, cy) = measure_run(os, &text);
    if size != 0 {
        // SIZE { LONG cx; LONG cy; }
        mem.write_u32(size, cx)?;
        mem.write_u32(size + 4, cy)?;
    }
    if alp_dx != 0 {
        // Cumulative advance after each character — uniform for the stand-in
        // cell, and the same advance `nt_gdi_ext_text_out_w`'s fallback steps by.
        for i in 0..count {
            mem.write_u32(alp_dx + i as u64 * 4, (i + 1) * STUB_FONT_CELL_W)?;
        }
    }
    Ok(1)
}

/// The pixel extent of `text`: the driver's real rasterizer when it has one
/// (so measure and draw agree glyph for glyph), else the stand-in cell.
fn measure_run(os: &WinOs, text: &str) -> (u32, u32) {
    const DEFAULT_TEXT_PX: u32 = 16;
    match os.driver.rasterize_text(text, DEFAULT_TEXT_PX) {
        Some(tb) => (tb.width, tb.height),
        None => (text.chars().count() as u32 * STUB_FONT_CELL_W, STUB_FONT_CELL_H),
    }
}

/// `NtGdiCreateRectRgn(left, top, right, bottom)` → a region handle typed so
/// `gdi32!SelectObject`'s `0x040000` arm accepts it. Regions are handles-only for
/// now: [`nt_gdi_intersect_clip_rect`] is the clip path a control actually uses.
fn nt_gdi_create_rect_rgn(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    Ok(alloc_gdi_object(os, mem, gdi_type::REGION)?.map(|(h, _)| h).unwrap_or(0))
}

/// `NtGdiDeleteObjectApp(handle)` — release a GDI object. Stock objects are
/// never deleted (Windows ignores the attempt and reports success); a dynamic
/// slot is marked free so it can be reused. Returns TRUE.
fn nt_gdi_delete_object_app(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let slot = (handle & 0xFFFF) as u64;
    if slot == 0 || slot >= GDI_TABLE_SLOTS {
        return Ok(0);
    }
    if (STOCK_SLOT_BASE..=STOCK_SLOT_LAST).contains(&slot) {
        return Ok(1); // a stock object outlives every caller
    }
    let base = os.win32k_state.gdi_table_base;
    if base != 0 {
        mem.write_u8(base + slot * GDI_ENTRY_SIZE + GDI_ENTRY_TYPE_OFF, 0)?;
    }
    os.win32k_state.brushes.retain(|(h, _)| *h != handle);
    os.win32k_state.dcs.retain(|(h, _)| *h != handle);
    Ok(1)
}

/// `NtGdiIntersectClipRect(hdc, left, top, right, bottom)` — narrow the DC's
/// clip to the given logical rect, returning the resulting region complexity.
/// This is how a control confines its painting to its own client area, so it has
/// to really clip: the rect is mapped through the DC origin and intersected with
/// the visible rect the DC was created with.
fn nt_gdi_intersect_clip_rect(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hdc = os.syscall_arg(cpu, mem, 0)? as u32;
    let left = os.syscall_arg(cpu, mem, 1)? as i32;
    let top = os.syscall_arg(cpu, mem, 2)? as i32;
    let right = os.syscall_arg(cpu, mem, 3)? as i32;
    let bottom = os.syscall_arg(cpu, mem, 4)? as i32;
    let Some(dc) = os.win32k_state.dcs.iter_mut().find(|(h, _)| *h == hdc).map(|(_, d)| d) else {
        return Ok(0); // ERROR: not one of ours
    };
    let (ox, oy) = dc.org;
    dc.clip[0] = dc.clip[0].max(left + ox);
    dc.clip[1] = dc.clip[1].max(top + oy);
    dc.clip[2] = dc.clip[2].min(right + ox);
    dc.clip[3] = dc.clip[3].min(bottom + oy);
    if dc.clip[2] <= dc.clip[0] || dc.clip[3] <= dc.clip[1] {
        return Ok(1); // NULLREGION — everything is clipped away
    }
    Ok(SIMPLEREGION)
}

/// `NtGdiGetAndSetDCDword(hdc, code, value, *previous)` — the read-modify-write
/// gdi32's `SetTextColor` / `SetBkColor` reach. Stores into the guest-visible
/// DC object so the *next* `get_dc_attr` read sees it, writes the old value
/// through `previous`, and returns TRUE.
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

/// The guest address of an HDC's client-side DC object, read back out of the
/// published handle table (the same walk gdi32 does).
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

/// `NtGdiPatBlt(hdc, x, y, cx, cy, rop)` — the fill primitive every
/// `FillRect`/`DrawEdge`/theme-less control paint bottoms out in.
///
/// Only the three constant-source raster ops are honoured: `PATCOPY` (paint with
/// the selected brush — what `FillRect` issues), `BLACKNESS` and `WHITENESS`.
/// Anything else returns FALSE rather than guessing a blend, so an unhandled ROP
/// is visible as "nothing was drawn" instead of a wrong colour.
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
            // PATCOPY with no brush selected: the hollow brush paints nothing.
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

/// Fill `cx × cy` logical pixels at `(x, y)` with `bgra`, mapped through the
/// DC's origin and clipped to its visible rect.
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
    // Clip in surface space first so a huge rect costs only its visible part.
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

    /// `NtUserEnumDisplaySettings` writes the DEVMODEW display fields at their
    /// ABI offsets, non-overlapping, from the driver's mode (roadmap W4.7).
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
        // Width and height are distinct 4-byte fields (a classic overlap bug).
        assert_ne!(DEVMODE_DMPELSWIDTH_OFF, DEVMODE_DMPELSHEIGHT_OFF);
        assert_eq!(DEVMODE_DMPELSHEIGHT_OFF - DEVMODE_DMPELSWIDTH_OFF, 4);
    }

    // ---- W6.2: the client-PFN arrays -> built-in class registry -------------

    /// A synthetic stand-in for the pinned layout: a `user_procs` block of
    /// [`CLIENT_PFN_COUNT`] procedure addresses, and a `user_funcs` array of
    /// `jmp qword [rip+disp32]` thunks jumping through it index-for-index (with
    /// index 6 left NULL, as the real build leaves it). Returns
    /// `(memory, funcs_array, procs)`.
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
            // The "WndProc" this index stands for, somewhere inside user32.
            let proc_va = USER32 + 0x1000 + (i as u64) * 0x40;
            *entry = proc_va;
            let slot = SLOTS + (i as u64) * 8;
            mem.write_u64(slot, proc_va).unwrap();
            // `jmp qword [rip+disp32]` — disp is relative to the end of the
            // 7-byte instruction.
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

    /// Following a client-PFN entry's `jmp qword [rip+disp32]` thunk yields the
    /// WndProc its slot holds, index-for-index, with the unpublished slot
    /// staying null (roadmap W6.2).
    #[test]
    fn client_pfn_entries_resolve_through_their_thunks() {
        let (mem, funcs, procs) = synth_client_pfn();
        let (resolved, slots) = read_client_pfn_array(&mem, funcs).unwrap();
        assert!(slots[PFN_BUTTON] != 0, "a thunked entry reports the slot it jumps through");
        assert_eq!(resolved, procs, "every published index resolves to its own proc");
        assert_eq!(resolved[6], 0, "the unpublished index stays null");
        // Distinct indices must not collapse onto one another (a displacement
        // sign/base error would alias them).
        assert_ne!(resolved[PFN_BUTTON], resolved[PFN_EDIT]);
        assert_ne!(resolved[PFN_STATIC], resolved[PFN_LIST_BOX]);
    }

    /// A null array pointer, and an entry that is *not* a thunk, are handled
    /// without inventing an address: the array reads as all-zero, and a direct
    /// procedure pointer resolves to itself (roadmap W6.2).
    #[test]
    fn client_pfn_resolution_is_honest_about_non_thunks() {
        let (mem, _, _) = synth_client_pfn();
        assert_eq!(read_client_pfn_array(&mem, 0).unwrap().0, [0u64; CLIENT_PFN_COUNT]);
        assert_eq!(resolve_client_pfn(&mem, 0).unwrap(), (0, 0));
        // A direct pointer (no `48 ff 25` at it) is taken as the proc itself.
        let direct = 0x2000_1000; // the slot block: qwords, not thunk opcodes
        assert_eq!(resolve_client_pfn(&mem, direct).unwrap(), (direct, 0));
    }

    /// The built-in classes are registered against the resolved Unicode procs,
    /// with distinct atoms, and re-registration is a no-op (roadmap W6.2).
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
        // Lookup is case-insensitive, as Windows' class lookup is.
        assert_eq!(os.win32k_state.class_by_name("button"), Some(atom));
        for (name, index) in BUILTIN_CLASSES {
            let a = os.win32k_state.class_by_name(name).unwrap_or_else(|| panic!("{name} registered"));
            assert_eq!(os.win32k_state.class_by_atom(a).unwrap().wndproc, procs[index]);
        }
        let atoms: std::collections::HashSet<u16> =
            os.win32k_state.classes.iter().map(|(a, _)| *a).collect();
        assert_eq!(atoms.len(), BUILTIN_CLASSES.len(), "every built-in got a distinct atom");

        // Idempotent: a second publish does not duplicate or renumber.
        register_builtin_classes(&mut os);
        assert_eq!(os.win32k_state.classes.len(), BUILTIN_CLASSES.len());
        assert_eq!(os.win32k_state.class_by_name("BUTTON"), Some(atom));
    }

    /// A proc that resolved *outside* user32's mapped image is refused rather
    /// than registered — a WndProc that would fault on the first message is
    /// worse than an unregistered class (roadmap W6.2).
    #[test]
    fn builtin_classes_refuse_procs_outside_user32() {
        let (_, _, procs) = synth_client_pfn();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.win32k_state.client_pfn_w = procs;
        // An image span that excludes every synthetic proc.
        os.win32k_state.user32_image = (0x9000_0000, 0x10_0000);
        register_builtin_classes(&mut os);
        assert!(os.win32k_state.classes.is_empty(), "no class trusts an out-of-image proc");

        // A zero size means "SizeOfImage unreadable" — the span check is then
        // skipped rather than silently rejecting everything.
        os.win32k_state.user32_image = (0x9000_0000, 0);
        register_builtin_classes(&mut os);
        assert_eq!(os.win32k_state.classes.len(), BUILTIN_CLASSES.len());
    }

    // ---- W4.8: the child-window painting model ------------------------------

    /// Register a class and create `hwnd` as a child of `parent` at `rect`, with
    /// no driver and no memory — enough to exercise the ancestry maths.
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
            },
        ));
        hwnd
    }

    /// **The child-window model.** A child has no surface of its own: it renders
    /// into its top-level ancestor's, at an origin that is the sum of every
    /// intervening child's position, clipped by every ancestor's client rect.
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

        // The button's visible rect is its own extent at that origin…
        assert_eq!(st.window_visible_rect(button), [15, 25, 75, 49]);
        // …and the whole top-level client area for the owner.
        assert_eq!(st.window_visible_rect(top), [0, 0, 400, 300]);
    }

    /// A child that overhangs its parent is **clipped to it**, so a control can
    /// never paint over its parent's siblings. An entirely-outside child ends up
    /// with an empty rect rather than a negative one.
    #[test]
    fn a_child_is_clipped_to_every_ancestor() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 200, 100]);
        let panel = child(&mut os, top, [50, 20, 100, 60]);
        // Overhangs the panel on the right and bottom.
        let wide = child(&mut os, panel, [80, 50, 200, 200]);
        assert_eq!(
            os.win32k_state.window_visible_rect(wide),
            [130, 70, 150, 80],
            "clipped to the panel's right/bottom edge, not the top-level window's"
        );
        // Entirely past the parent: empty, not inverted.
        let gone = child(&mut os, panel, [500, 500, 20, 20]);
        let r = os.win32k_state.window_visible_rect(gone);
        assert!(r[2] <= r[0] || r[3] <= r[1], "a fully clipped child has an empty rect: {r:?}");
    }

    /// **The hit test.** `WindowFromPoint` descends to the *deepest* window
    /// containing the point, searching siblings newest-first (a freshly created
    /// child sits on top of its siblings' Z-order), and answers 0 outside the
    /// top-level window entirely.
    #[test]
    fn window_from_point_finds_the_deepest_topmost_child() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let panel = child(&mut os, top, [10, 20, 200, 150]);
        let button = child(&mut os, panel, [5, 5, 60, 24]);
        // A later sibling of `panel` overlapping it: newest wins.
        let overlay = child(&mut os, top, [100, 100, 80, 40]);
        let st = &os.win32k_state;

        assert_eq!(st.window_from_point(300, 250, &[]), top, "bare client area → the window");
        assert_eq!(st.window_from_point(150, 40, &[]), panel, "inside the panel → the panel");
        assert_eq!(st.window_from_point(20, 30, &[]), button, "inside the button → the button");
        assert_eq!(st.window_from_point(120, 110, &[]), overlay, "the newer sibling is on top");
        assert_eq!(st.window_from_point(500, 500, &[]), 0, "outside every window → nothing");

        // `HTTRANSPARENT` re-runs the search with the answering window excluded,
        // which is how a click passes through a group box to what is under it.
        assert_eq!(st.window_from_point(20, 30, &[button]), panel, "skip the button → the panel");
        assert_eq!(
            st.window_from_point(20, 30, &[button, panel]),
            top,
            "skip both → the top-level window"
        );
        // `ChildWindowFromPointEx` stops at one level, unlike the descent above.
        assert_eq!(st.child_window_from_point(top, 20, 30), panel);
        assert_eq!(st.child_window_from_point(panel, 20, 30), button);
    }

    /// A hidden window takes no input, and neither does a visible child of a
    /// hidden parent.
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

    /// A non-client hit code maps the mouse message onto its `WM_NC*` twin —
    /// `WM_MOUSEMOVE`/`WM_LBUTTONDOWN`/`WM_LBUTTONUP` sit exactly
    /// [`NC_MOUSE_DELTA`] above `WM_NCMOUSEMOVE`/`WM_NCLBUTTONDOWN`/`WM_NCLBUTTONUP`.
    #[test]
    fn client_mouse_messages_map_onto_their_non_client_twins() {
        use crate::gdi::{WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE};
        assert_eq!(WM_MOUSEMOVE as u32 - NC_MOUSE_DELTA, 0x00a0, "WM_NCMOUSEMOVE");
        assert_eq!(WM_LBUTTONDOWN as u32 - NC_MOUSE_DELTA, 0x00a1, "WM_NCLBUTTONDOWN");
        assert_eq!(WM_LBUTTONUP as u32 - NC_MOUSE_DELTA, 0x00a2, "WM_NCLBUTTONUP");
        assert!((WM_MOUSEFIRST..=WM_MOUSELAST_NC).contains(&(WM_LBUTTONUP as u32)));
    }

    /// A packed mouse `lParam` round-trips through the low/high word helpers,
    /// **including negative coordinates** — a drag that leaves a control to the
    /// left reports x as a negative 16-bit value, and reading it unsigned would
    /// put the pointer 65 000 pixels to the right instead.
    #[test]
    fn packed_points_survive_negative_coordinates() {
        for (x, y) in [(0, 0), (150, 90), (-3, 7), (12, -40), (-1, -1)] {
            let lp = pack_point(x, y);
            assert_eq!((lo_word_i32(lp), hi_word_i32(lp)), (x, y), "round-trip ({x}, {y})");
        }
    }

    /// The mouse capture overrides hit-testing: while it is held every mouse
    /// event goes to the capture window, in **its** client coordinates. Without
    /// this a pushed button never sees the button-up that releases it.
    #[test]
    fn the_capture_takes_the_mouse_regardless_of_the_point() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let button = child(&mut os, top, [24, 200, 140, 32]);
        os.win32k_state.capture = button;
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        // A point well outside the button — the drag left its rect.
        let ev = exemu_core::InputEvent::MouseButton {
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

    /// A mouse event over a window that **has** a WndProc is not delivered
    /// straight away: the routing first asks it `WM_NCHITTEST` and lets the
    /// answer choose the message. A window with no WndProc cannot answer, so the
    /// kernel's own default applies immediately — the path a plain single-window
    /// guest keeps.
    #[test]
    fn a_window_with_a_wndproc_is_asked_where_the_point_landed() {
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let ev = exemu_core::InputEvent::MouseMove { x: 40, y: 40 };

        // No WndProc: answered in-kernel and posted at once.
        assert!(!route_raw_input(&mut os, &mut cpu, &mut mem, 0, ev).expect("routes"));
        let m = os.msg_next().expect("the move was posted");
        assert_eq!(m.hwnd, top as u64);
        assert_eq!(m.message, crate::gdi::WM_MOUSEMOVE as u32);

        // With one, the hit test is armed instead. (Driving the callback needs a
        // real guest stack; the gate in `comctl_gate.rs` runs it end to end.)
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

    /// A key message goes to the focus window, falling back to the active
    /// top-level so a guest that never calls `SetFocus` still receives keys.
    #[test]
    fn keys_follow_the_focus_then_the_active_window() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let top = child(&mut os, 0, [0, 0, 400, 300]);
        let edit = child(&mut os, top, [10, 10, 100, 20]);
        assert_eq!(keyboard_target(&os), top, "no focus, no active → the shown top-level");
        os.win32k_state.active = top;
        assert_eq!(keyboard_target(&os), top);
        os.win32k_state.focus = edit;
        assert_eq!(keyboard_target(&os), edit, "the focus window wins");
        // A destroyed focus window must not keep the keyboard.
        destroy_window(&mut os, edit);
        assert_eq!(os.win32k_state.focus, 0, "destroying the focus window clears it");
        assert_eq!(keyboard_target(&os), top);
    }

    /// A cyclic parent link degrades to "treat it as top-level" instead of
    /// hanging a syscall handler.
    #[test]
    fn a_parent_cycle_terminates() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let a = child(&mut os, 0, [0, 0, 10, 10]);
        let b = child(&mut os, a, [1, 1, 5, 5]);
        os.win32k_state.window_mut(a).unwrap().parent = b;
        // Both calls must return, and the walk must be bounded.
        let _ = os.win32k_state.surface_owner(b);
        let _ = os.win32k_state.client_origin(b);
        assert!(!os.win32k_state.chain_visible(b), "a cycle never reaches a top level");
    }

    /// `GetWindowLong*` / `SetWindowLong*`: the documented negative offsets map
    /// to the named fields, and a non-negative offset indexes the class's
    /// `cbWndExtra` — the store every Wine control keeps its instance data in.
    #[test]
    fn window_longs_cover_the_named_fields_and_the_extra_bytes() {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let hwnd = child(&mut os, 0, [1, 2, 30, 40]);

        assert_eq!(get_window_long(&os, hwnd, GWL_STYLE), WS_VISIBLE as u64);
        assert_eq!(set_window_long(&mut os, hwnd, GWL_EXSTYLE, 0x20000), 0, "ex-style started 0");
        assert_eq!(get_window_long(&os, hwnd, GWL_EXSTYLE), 0x20000);

        // The instance pointer a control stores at extra offset 0 round-trips at
        // full width — the whole reason the syscall needs a 64-bit result path.
        const INFO: u64 = 0x4000_0001_7AA0;
        assert_eq!(get_window_long(&os, hwnd, 0), 0, "extra bytes start zeroed");
        assert_eq!(set_window_long(&mut os, hwnd, 0, INFO), 0);
        assert_eq!(get_window_long(&os, hwnd, 0), INFO, "a pointer survives the round trip");
        assert_eq!(set_window_long(&mut os, hwnd, 0, 1), INFO, "Set returns the previous value");

        // Out-of-range offsets are inert, never a panic or an out-of-bounds write.
        assert_eq!(get_window_long(&os, hwnd, 4096), 0);
        assert_eq!(set_window_long(&mut os, hwnd, 4096, 0xFF), 0);
        assert_eq!(get_window_long(&os, hwnd, -999), 0);
        assert_eq!(get_window_long(&os, 0xDEAD, 0), 0, "an unknown hwnd reads nothing");
    }

    /// A GDI handle is `(type << 16) | slot`, the encoding `gdi32!SelectObject`
    /// demands — and the pre-existing HDC encoding is that same rule with
    /// `type = DC`, which is why extending it to brushes needed no new scheme.
    #[test]
    fn gdi_handles_encode_their_type_in_the_high_word() {
        for (slot, ty, _) in STOCK_OBJECTS {
            let handle = ((ty as u32) << 16) | slot as u32;
            assert_eq!(handle >> 16, ty as u32, "the high word is the type");
            assert_eq!((handle & 0xFFFF) as u64, slot, "the low word is the slot");
            assert_ne!(handle & 0xFFFF, 0, "slot 0 would be indistinguishable from NULL");
        }
        // The DC type is what gdi32's `(hdc & 0x1F0000) == 0x10000` prefilter
        // demands, i.e. exactly bit 16.
        assert_eq!((gdi_type::DC as u32) << 16, 0x0001_0000);
    }

    /// `COLORREF` is `0x00BBGGRR`; the surface is BGRA32. Getting this backwards
    /// is invisible on greys (the classic way it hides) and wrong on everything
    /// else, so it is pinned on a colour with three distinct channels.
    #[test]
    fn colorref_converts_to_opaque_bgra() {
        // COLORREF 0x00204080 = R=0x80, G=0x40, B=0x20.
        assert_eq!(colorref_to_bgra(0x0020_4080), 0xFF80_4020);
        assert_eq!(colorref_to_bgra(0x0000_0000), 0xFF00_0000, "black stays opaque");
        assert_eq!(colorref_to_bgra(0x00FF_FFFF), 0xFFFF_FFFF);
    }

    /// `SizeOfImage` is read out of the mapped PE header, and a non-PE base is
    /// reported as unknown rather than guessed (roadmap W6.2).
    #[test]
    fn pe_image_size_reads_the_mapped_header() {
        let mut mem = VirtualMemory::new();
        let base = 0x4000_0000u64;
        mem.map(Region::new("img", base, 0x1000, Perm::RW)).unwrap();
        assert_eq!(pe_image_size(&mem, 0), None, "a null base has no image");
        assert_eq!(pe_image_size(&mem, base), None, "an unsigned page is not a PE");
        mem.write_u16(base, 0x5A4D).unwrap(); // "MZ"
        mem.write_u32(base + 0x3C, 0x80).unwrap(); // e_lfanew
        assert_eq!(pe_image_size(&mem, base), None, "MZ alone is not enough");
        mem.write_u32(base + 0x80, 0x0000_4550).unwrap(); // "PE\0\0"
        mem.write_u32(base + 0x80 + 24 + 56, 0x2A6000).unwrap(); // SizeOfImage
        assert_eq!(pe_image_size(&mem, base), Some(0x2A6000));
    }

    // ---- W6.2: the CREATESTRUCTW the creation pair carries -------------------

    /// A window `WinOs` can dispatch a creation pair for, plus a mapped guest
    /// stack. Returns `(os, memory, hwnd, guest_rsp)`.
    fn window_for_create(wndproc: u64) -> (WinOs, VirtualMemory, u32) {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.win32k_state.classes.push((
            CLASS_ATOM_BASE,
            Class { name: "TestClass".into(), wndproc, style: 0, background: 0, wnd_extra: 16 },
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
            },
        ));
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", 0x10_0000, 0x10_000, Perm::RW)).unwrap();
        (os, mem, hwnd)
    }

    /// The struct `WM_NCCREATE`/`WM_CREATE` carry lands at its documented
    /// offsets, with **NUL-terminated copies** of the two names (the caller's
    /// `UNICODE_STRING` buffers carry a length, not a terminator), and sits far
    /// enough above the callbacks' own frames that they cannot overwrite it
    /// (roadmap W6.2).
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
        assert_eq!(mem.read_u64(cs + CS_LP_CREATE_PARAMS).unwrap(), 0xDEAD_BEEF);
        assert_eq!(mem.read_u64(cs + CS_HINSTANCE).unwrap(), 0x1_4000_0000);
        assert_eq!(mem.read_u64(cs + CS_HMENU).unwrap(), 0x65);
        assert_eq!(mem.read_u64(cs + CS_HWND_PARENT).unwrap(), 0x1234);
        // The `cy, cx, y, x` ordering is the documented (inverted) Win32 layout.
        assert_eq!(mem.read_u32(cs + CS_CY).unwrap(), 200);
        assert_eq!(mem.read_u32(cs + CS_CX).unwrap(), 300);
        assert_eq!(mem.read_u32(cs + CS_Y).unwrap(), 20);
        assert_eq!(mem.read_u32(cs + CS_X).unwrap(), 10);
        assert_eq!(mem.read_u32(cs + CS_STYLE).unwrap(), 0x5000_0000);
        assert_eq!(mem.read_u32(cs + CS_DW_EX_STYLE).unwrap(), 0x8);

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
        let name = mem.read_u64(cs + CS_LPSZ_NAME).unwrap();
        let class = mem.read_u64(cs + CS_LPSZ_CLASS).unwrap();
        assert_eq!(read(name), "Title", "lpszName is a NUL-terminated copy");
        assert_eq!(read(class), "TestClass", "lpszClass is a NUL-terminated copy");
        assert!(name >= cs + CREATESTRUCT_SIZE && class > name, "the names follow the struct");
        assert!(
            class < guest_rsp,
            "the whole scratch stays below the interrupted syscall's stack pointer"
        );

        // The first callback is seated, and its frame is *below* the struct.
        assert_eq!(cpu.rip, WNDPROC, "WM_NCCREATE goes to the class WndProc first");
        assert_eq!(cpu.reg(Reg::Rcx), hwnd as u64);
        assert_eq!(cpu.reg(Reg::Rdx), WM_NCCREATE as u64);
        assert_eq!(cpu.reg(Reg::R9), cs, "lParam is the CREATESTRUCTW");
        assert!(cpu.rsp() < cs, "the callback frame cannot overwrite the struct");
    }

    /// An empty window name yields a NULL `lpszName` (Windows' "no name"), not a
    /// pointer to an empty string that the class name then overlaps.
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
        assert_eq!(mem.read_u64(cs + CS_LPSZ_NAME).unwrap(), 0);
        assert_eq!(
            mem.read_u64(cs + CS_LPSZ_CLASS).unwrap(),
            cs + CREATESTRUCT_SIZE,
            "the class name takes the start of the string area when there is no window name"
        );
    }

    /// A class with no WndProc gets no creation pair — the handler then returns
    /// the HWND the ordinary way instead of hijacking the syscall return.
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

    /// **A WoW64 process gets no creation pair either — the pinned W5.10 gap.**
    ///
    /// The WndProc is 32-bit guest code but the win32k syscall arrives in long
    /// mode, so seating it directly would run 32-bit bytes as 64-bit ones (see
    /// `WinOs::can_call_client` for the measured `SteamSetup` failure). The
    /// window is still created; it simply never hears `WM_NCCREATE`/`WM_CREATE`.
    ///
    /// This test fails the day exemu routes client callbacks through
    /// `ntdll64!KiUserCallbackDispatcher` → `wow64!Wow64KiUserCallbackDispatcher`,
    /// which is exactly when the claim above must be rewritten.
    #[test]
    fn a_wow64_process_gets_no_creation_pair() {
        const WNDPROC: u64 = 0x1_4000_1000;
        let (mut os, mut mem, hwnd) = window_for_create(WNDPROC);
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
            class_name: "TestClass",
        };
        // The same window, same registered WndProc: only the process changes.
        assert!(
            dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap(),
            "control: a 64-bit process does get the creation pair",
        );

        let (mut os, mut mem, hwnd) = window_for_create(WNDPROC);
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        os.set_wow64_peb32(0x7f00_8000); // this process is now WoW64
        let mut cpu = CpuState::default();
        assert!(!os.can_call_client(), "a WoW64 process takes no direct client callback");
        assert!(
            !dispatch_create_messages(&mut os, &mut cpu, &mut mem, hwnd, &info).unwrap(),
            "no creation pair is seated in a WoW64 process",
        );
        assert_eq!(cpu.rip, 0, "nothing was seated, so no 32-bit code runs in long mode");
    }

    /// A second copy of ntdll is recognised structurally (export-directory name
    /// plus `SizeOfImage`), and the running image itself is never reported as its
    /// own copy (roadmap W6.2).
    #[test]
    fn ntdll_copies_are_found_by_their_export_name() {
        /// Lay a minimal PE at `base` whose export directory names `name`.
        fn fake_pe(mem: &mut VirtualMemory, base: u64, name: &str, size_of_image: u32) {
            mem.map(Region::new("img", base, 0x2000, Perm::RW)).unwrap();
            mem.write_u16(base, 0x5A4D).unwrap();
            mem.write_u32(base + 0x3C, 0x80).unwrap();
            mem.write_u32(base + 0x80, 0x0000_4550).unwrap();
            mem.write_u32(base + 0x80 + 24 + 56, size_of_image).unwrap();
            mem.write_u32(base + 0x80 + 24 + 112, 0x1000).unwrap(); // export dir RVA
            mem.write_u32(base + 0x1000 + 12, 0x1100).unwrap(); // Name RVA
            for (i, b) in name.bytes().enumerate() {
                mem.write_u8(base + 0x1100 + i as u64, b).unwrap();
            }
            mem.write_u8(base + 0x1100 + name.len() as u64, 0).unwrap();
        }

        let mut mem = VirtualMemory::new();
        fake_pe(&mut mem, 0x1_0000, "ntdll.dll", 0x3EE000); // the running image
        fake_pe(&mut mem, 0x2_0000, "NTDLL.dll", 0x3EE000); // the duplicate
        fake_pe(&mut mem, 0x3_0000, "user32.dll", 0x3EE000); // same size, other DLL
        fake_pe(&mut mem, 0x4_0000, "ntdll.dll", 0x10_0000); // same name, other size

        assert_eq!(
            ntdll_copies(&mem, 0x1_0000, 0x3EE000),
            vec![0x2_0000],
            "only a same-size image that calls itself ntdll, and never the running one"
        );
        assert_eq!(pe_export_name(&mem, 0x3_0000).as_deref(), Some("user32.dll"));
        assert_eq!(pe_export_name(&mem, 0), None, "a null base names nothing");
    }

    /// Mirroring rewrites the duplicate's `user_procs` slot at the same RVA the
    /// running image's slot sits at, leaving unrelated memory alone
    /// (roadmap W6.2).
    #[test]
    fn client_pfn_mirroring_writes_the_same_rva_in_every_copy() {
        let mut mem = VirtualMemory::new();
        // A live "ntdll" at 0x1_0000 and a duplicate at 0x2_0000, both 0x3EE000.
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
        slots[PFN_BUTTON] = 0x1_0000 + 0x1800; // a slot inside the running image
        procs[PFN_BUTTON] = 0xABCD_1234;
        // An out-of-image slot must be ignored rather than mirrored blindly.
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
}
