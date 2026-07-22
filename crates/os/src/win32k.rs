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

// --- NtGdi* indices (the win32u.dll `mov eax,IDX` immediates; spot-verified
//     against the pinned build's stubs — see the W4.3 static gdi32 contract).
//     gdi32!TextOutW→ExtTextOutW lowers to NtGdiExtTextOutW; gdi32!Rectangle
//     tail-calls NtGdiRectangle directly. Both carry the 0x1000 table bit.
const NT_GDI_EXT_TEXT_OUT_W: u32 = 0x11c9;
const NT_GDI_RECTANGLE: u32 = 0x1259;

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
/// Non-zero type byte written at entry+0xE (any non-zero value passes the
/// `byte[entry+0xE] != 0` gate; `LO_TYPE_DC`-shaped for readability).
const GDI_ENTRY_TYPE_DC: u8 = 0x01;
/// The `(hdc & 0x1F0000) == 0x10000` type prefilter forces bit 16 set, so every
/// DC handle's high 16 bits are `0x0001`; the generation word must match.
const HDC_TYPE_BITS: u32 = 0x0001_0000;
const HDC_GENERATION: u16 = 0x0001;
/// Size of one minimal user-mode DC object (only offsets +4/+0xA8/+0xB8 are read
/// by gdi32; round up to cover them with slack).
const GDI_DC_OBJECT_SIZE: u64 = 0x100;

/// The base of the Windows `RegisterClass` atom range (0xC000–0xFFFF).
const CLASS_ATOM_BASE: u16 = 0xC000;

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
#[allow(dead_code)] // wndproc/style/background: consumed by W4.3/W4.6.
struct Class {
    name: String,
    wndproc: u64,
    style: u32,
    background: u64,
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
    /// the presenter share one allocation.
    surface: Option<Surface>,
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

/// A device context bound to a window (W4.3). Every HDC handed back by
/// GetDC/GetDCEx/BeginPaint records the hwnd it draws into so the NtGdi paint
/// handlers can resolve `hdc → hwnd → surface`.
struct Dc {
    hwnd: u32,
}

/// win32k unix-backend state (roadmap W4.1/W4.2): the client PFN table, the
/// class registry, and the window object model.
#[derive(Default)]
pub(crate) struct Win32kState {
    /// The client-side PFN table pointer recorded by
    /// `NtUserInitializeClientPfnArrays` — the guest WndProc-caller thunks the
    /// kernel→user callback path (roadmap W4.6) will jump to.
    client_pfn_table: u64,
    /// Registered classes, keyed by their assigned atom. The next atom is
    /// `CLASS_ATOM_BASE + classes.len()`.
    classes: Vec<(u16, Class)>,
    /// Live windows, keyed by HWND.
    windows: Vec<(u32, Window)>,
    /// Live device contexts, keyed by HDC. Binds each HDC to its window +
    /// handle-table slot for the GDI paint path (W4.3).
    dcs: Vec<(u32, Dc)>,
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

    /// The first shown window — the target for synthesized native input
    /// (roadmap W4.6). Single top-level window is the model for now.
    fn shown_window(&self) -> Option<u32> {
        self.windows.iter().find(|(_, w)| w.shown).map(|(h, _)| *h)
    }

    /// A shown window owing a WM_PAINT, clearing its flag. Used by the pump to
    /// synthesize a WM_PAINT when the queue is empty.
    fn take_paint_pending(&mut self) -> Option<u32> {
        let hwnd = self.windows.iter().find(|(_, w)| w.needs_paint && w.shown).map(|(h, _)| *h)?;
        if let Some(w) = self.window_mut(hwnd) {
            w.needs_paint = false;
        }
        Some(hwnd)
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
    // NtGdi paint path (W4.3): rasterize into the per-window surface.
    os.set_win32k_handler(NT_GDI_EXT_TEXT_OUT_W, nt_gdi_ext_text_out_w);
    os.set_win32k_handler(NT_GDI_RECTANGLE, nt_gdi_rectangle);
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

/// `NtUserInitializeClientPfnArrays(client_procsW, client_procsA, client_worker,
/// user32)` — user32's DllMain hands the kernel the client-side WndProc-caller
/// table. Record arg0 for the kernel→user callback path (roadmap W4.6).
fn nt_user_initialize_client_pfn_arrays(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.win32k_state.client_pfn_table = os.syscall_arg(cpu, mem, 0)?;
    Ok(STATUS_SUCCESS)
}

/// `NtUserGetSystemDpiForProcess` → 96 (100% scaling; Retina/DPI is deferred).
fn nt_user_get_system_dpi_for_process(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(96)
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

    let (style, wndproc, background) = if wc != 0 {
        (mem.read_u32(wc + 0x04)?, mem.read_u64(wc + 0x08)?, mem.read_u64(wc + 0x30)?)
    } else {
        (0, 0, 0)
    };

    // A duplicate registration of the same name reuses its atom (matches
    // Windows returning the existing atom rather than a second one).
    if let Some(existing) = os.win32k_state.class_by_name(&name) {
        return Ok(existing as u32);
    }

    let atom = CLASS_ATOM_BASE.wrapping_add(os.win32k_state.classes.len() as u16);
    os.win32k_state
        .classes
        .push((atom, Class { name, wndproc, style, background }));
    Ok(atom as u32)
}

/// `NtUserCreateWindowEx(exStyle, className*, unused0, windowName*, style, x, y,
/// cx, cy, parent, menu, cbtParam, createParams, flags, instance, rawClassPtr,
/// unicode)` — marshal the recovered arg slots, allocate the HWND, store the
/// window object, then drive the driver create sequence (§4 ordering:
/// window_pos_changing → create_window → window_pos_changed).
///
/// arg2 (class) and arg4 (window name) are POINTERS to UNICODE_STRING; the
/// exStyle/style/x/y/cx/cy dwords are raw; parent is a raw handle. Stack args
/// 5+ are read via `syscall_arg` relative to the captured guest RSP.
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
    // The class WndProc is the guest procedure NtUserDispatchMessage invokes.
    let wndproc = os.win32k_state.class_by_atom(class_atom).map(|c| c.wndproc).unwrap_or(0);

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
            shown: false,
            wndproc,
            needs_paint: false,
            surface: None,
        },
    ));

    let params = WindowParams {
        class_atom,
        class_name,
        title,
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

    Ok(hwnd)
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
    os.driver.show_window(hwnd, cmd);
    Ok(was_visible as u32)
}

/// `NtUserDestroyWindow(hwnd)` — remove the window object, notify the driver,
/// return TRUE for a known hwnd / FALSE otherwise. Bare import thunk: hwnd in
/// arg0 (recovered).
fn nt_user_destroy_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let existed = os.win32k_state.windows.iter().any(|(h, _)| *h == hwnd);
    os.win32k_state.windows.retain(|(h, _)| *h != hwnd);
    if existed {
        os.driver.destroy_window(hwnd);
    }
    Ok(existed as u32)
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
/// syscall user32's `SendMessageW` reaches, and the path Wine's `DispatchMessageW`
/// lowers *input* messages (`WM_LBUTTONDOWN`/`WM_KEYDOWN`/…) into (`WM_PAINT` and
/// other posted messages go via [`nt_user_dispatch_message`] instead — recovered
/// by tracing gui_sample's pump). `WM_SETTEXT` keeps its native arm (there is no
/// dedicated `NtUserSetWindowText` syscall — `SetWindowTextW` delivers it here):
/// update the stored title and notify the driver. Every other message is
/// dispatched to the window's WndProc, returning its LRESULT (roadmap W4.6).
fn nt_user_message_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let msg = os.syscall_arg(cpu, mem, 1)? as u32;
    if msg == WM_SETTEXT {
        let text_ptr = os.syscall_arg(cpu, mem, 3)?; // lParam = the text pointer
        let ansi = os.syscall_arg(cpu, mem, 6)? != 0;
        let text = if ansi {
            crate::api::read_astr(mem, text_ptr)?
        } else {
            read_wstr(mem, text_ptr)?
        };
        if let Some(w) = os.win32k_state.window_mut(hwnd) {
            w.title = text.clone();
        }
        os.driver.set_window_text(hwnd, &text);
        return Ok(1);
    }
    let wparam = os.syscall_arg(cpu, mem, 2)?;
    let lparam = os.syscall_arg(cpu, mem, 3)?;
    dispatch_to_wndproc(os, cpu, mem, hwnd as u64, msg, wparam, lparam)
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
    os.win32k_state.gdi_next_slot = 1; // slot 0 reserved (index 0 == null)
    true
}

/// Allocate a GDI-formatted HDC bound to `hwnd`: claim a table slot, fill its
/// 24-byte entry (type/generation/object-pointer) so gdi32's `get_gdi_client_ptr`
/// accepts it, and zero the DC object (offsets +4/+0xA8/+0xB8 = 0 → the direct
/// syscall fast path). Returns 0 if the table could not be published or the
/// slots are exhausted.
fn alloc_dc(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<u32> {
    if !ensure_gdi_table(os, mem) {
        return Ok(0);
    }
    let slot = os.win32k_state.gdi_next_slot;
    if slot >= GDI_TABLE_SLOTS {
        return Ok(0);
    }
    os.win32k_state.gdi_next_slot += 1;

    let entry = os.win32k_state.gdi_table_base + slot * GDI_ENTRY_SIZE;
    let obj = os.win32k_state.gdi_dc_arena + slot * GDI_DC_OBJECT_SIZE;
    // Zero the DC object: dword[+4]==0, qword[+0xA8]==0, qword[+0xB8]==0 select
    // gdi32's direct-syscall fast path (no batch, no open path).
    for off in (0..GDI_DC_OBJECT_SIZE).step_by(8) {
        mem.write_u64(obj + off, 0)?;
    }
    // Handle-table entry: generation (word @+0xC) must equal (hdc>>16); type
    // byte (@+0xE) must be non-zero; object pointer (@+0x10).
    mem.write_u16(entry + GDI_ENTRY_GENERATION_OFF, HDC_GENERATION)?;
    mem.write_u8(entry + GDI_ENTRY_TYPE_OFF, GDI_ENTRY_TYPE_DC)?;
    mem.write_u64(entry + GDI_ENTRY_OBJECT_OFF, obj)?;

    // hdc: low 16 = slot index; high 16 = generation, which also carries the
    // 0x0001 DC type bit the `(hdc & 0x1F0000) == 0x10000` prefilter demands
    // (HDC_TYPE_BITS == HDC_GENERATION << 16, so one word satisfies both gates).
    debug_assert_eq!((HDC_GENERATION as u32) << 16, HDC_TYPE_BITS);
    let hdc = ((HDC_GENERATION as u32) << 16) | (slot as u32 & 0xFFFF);
    os.win32k_state.dcs.push((hdc, Dc { hwnd }));
    Ok(hdc)
}

/// Ensure `hwnd`'s backing surface exists (lazy on first GetDC/BeginPaint):
/// map a guest-addressable top-down BGRA32 DIB (`w*h*4`, stride `w*4`),
/// initialize it to opaque white, store it on the window, and notify the
/// driver. Idempotent. Returns the surface, or `None` if the window is unknown
/// or the map fails.
fn ensure_surface(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Option<Surface> {
    let w = os.win32k_state.window(hwnd)?;
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
    if let Some(w) = os.win32k_state.window_mut(hwnd) {
        w.surface = Some(surface);
    }
    os.driver.create_window_surface(hwnd, cx, cy);
    Some(surface)
}

/// Read `hwnd`'s surface pixels out of guest memory and present them through
/// the driver (`flush_surface`). Fire-and-forget; a missing surface is a no-op.
fn present_surface(os: &mut WinOs, mem: &mut dyn Memory, hwnd: u32) -> Result<()> {
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
/// NULL hwnd (GetDC(NULL) = the screen DC) binds to the single live top-level
/// window so the gate's `GetDC(hwnd)`/`GetDC(NULL)` both land on a surface.
fn resolve_dc_hwnd(os: &WinOs, hwnd_arg: u32) -> u32 {
    if hwnd_arg != 0 && os.win32k_state.window(hwnd_arg).is_some() {
        return hwnd_arg;
    }
    os.win32k_state.windows.first().map(|(h, _)| *h).unwrap_or(0)
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
    let surface = ensure_surface(os, mem, hwnd);
    let hdc = alloc_dc(os, mem, hwnd)?;
    if ps != 0 {
        // PAINTSTRUCT { HDC hdc @0; BOOL fErase @8; RECT rcPaint @0xC (l,t,r,b) }.
        mem.write_u64(ps, hdc as u64)?;
        mem.write_u32(ps + 8, 0)?;
        // rcPaint = the full client rect (0,0,cx,cy) — the whole window is dirty.
        let (cx, cy) = surface.map(|s| (s.w as i32, s.h as i32)).unwrap_or((0, 0));
        mem.write_u32(ps + 0xC, 0)?; // left
        mem.write_u32(ps + 0x10, 0)?; // top
        mem.write_u32(ps + 0x14, cx as u32)?; // right
        mem.write_u32(ps + 0x18, cy as u32)?; // bottom
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
        if let Some(m) = os.msg_next() {
            os.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
            // GetMessage returns 0 only for WM_QUIT (stop the loop).
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
    /// Translate a native [`InputEvent`](exemu_core::InputEvent) into the Win32
    /// message the guest expects and post it to the shown window's queue (roadmap
    /// W4.6). The [`NtUserDispatchMessage`](nt_user_dispatch_message) path then
    /// routes it to the guest's WndProc. `Close` is handled by the caller (it
    /// becomes `WM_QUIT`, not a window message), so it is a no-op here; input for
    /// a guest with no shown window is dropped.
    pub(crate) fn post_input_event(&mut self, ev: exemu_core::InputEvent) {
        use crate::gdi::{
            MK_LBUTTON, MK_RBUTTON, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP,
            WM_MOUSEMOVE, WM_RBUTTONDOWN, WM_RBUTTONUP,
        };
        use exemu_core::{InputEvent, MouseButton};
        // Track the cursor position from every pointer event so GetCursorPos
        // reports where the user last pointed (roadmap W4.7).
        match ev {
            InputEvent::MouseMove { x, y }
            | InputEvent::MouseButton { x, y, .. } => self.win32k_state.cursor_pos = (x, y),
            _ => {}
        }
        let Some(hwnd) = self.win32k_state.shown_window() else { return };
        // Mouse position packs into lParam as (x in low word, y in high word).
        let pos = |x: i32, y: i32| (x as u32 as u64 & 0xffff) | ((y as u32 as u64 & 0xffff) << 16);
        let (message, wparam, lparam) = match ev {
            InputEvent::Close => return,
            InputEvent::MouseMove { x, y } => (WM_MOUSEMOVE, 0, pos(x, y)),
            InputEvent::MouseButton { button: MouseButton::Left, down: true, x, y } => {
                (WM_LBUTTONDOWN, MK_LBUTTON, pos(x, y))
            }
            InputEvent::MouseButton { button: MouseButton::Left, down: false, x, y } => {
                (WM_LBUTTONUP, 0, pos(x, y))
            }
            InputEvent::MouseButton { button: MouseButton::Right, down: true, x, y } => {
                (WM_RBUTTONDOWN, MK_RBUTTON, pos(x, y))
            }
            InputEvent::MouseButton { button: MouseButton::Right, down: false, x, y } => {
                (WM_RBUTTONUP, 0, pos(x, y))
            }
            InputEvent::Key { vk, down: true } => (WM_KEYDOWN, vk as u64, 0),
            InputEvent::Key { vk, down: false } => (WM_KEYUP, vk as u64, 0),
        };
        self.post_internal(hwnd as u64, message as u32, wparam, lparam);
    }
}

/// Dispatch `(hwnd, msg, wParam, lParam)` to the target window's WndProc via the
/// direct-call path (roadmap W4.6): seat `wndproc(hwnd, msg, wParam, lParam)` on
/// the guest stack and resume the interrupted syscall's caller when it returns,
/// with the WndProc's LRESULT in rax. A message for an unknown / class-less
/// window is a no-op (returns 0). Shared by `NtUserDispatchMessage` and the
/// WndProc arm of `NtUserMessageCall`.
fn dispatch_to_wndproc(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    hwnd: u64,
    msg: u32,
    wparam: u64,
    lparam: u64,
) -> Result<u32> {
    let wndproc = os.win32k_state.wndproc_for(hwnd as u32);
    if wndproc == 0 {
        return Ok(0);
    }
    let m = crate::msg::PostedMsg { hwnd, message: msg, wparam, lparam };
    os.call_wndproc_from_syscall(cpu, mem, wndproc, m)?;
    Ok(0) // ignored: call_wndproc_from_syscall sets syscall_resume_as_is
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
    dispatch_to_wndproc(os, cpu, mem, hwnd, message as u32, wparam, lparam)
}

/// `NtUserPeekMessage` → 0 (no message available).
fn nt_user_peek_message(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(0)
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

/// Resolve `hdc → hwnd → surface` for a paint handler. Returns `None` (the
/// honest "unbound HDC" failure) when the HDC was never issued by this module
/// or its window has no surface.
fn dc_surface(os: &WinOs, hdc: u32) -> Option<(u32, Surface)> {
    let hwnd = os.win32k_state.dc(hdc)?.hwnd;
    let surface = os.win32k_state.window(hwnd)?.surface?;
    Some((hwnd, surface))
}

/// Write one BGRA32 pixel into a surface, clipped to its bounds. `x`/`y` in
/// client-area pixels (top-down).
fn put_pixel(mem: &mut dyn Memory, s: &Surface, x: i32, y: i32, bgra: u32) -> Result<()> {
    if x < 0 || y < 0 || x >= s.w as i32 || y >= s.h as i32 {
        return Ok(());
    }
    let off = (y as u64 * s.w as u64 + x as u64) * 4;
    mem.write_u32(s.base + off, bgra)
}

/// Rasterize one UTF-16 code unit as an 8×8 `font8x8` glyph at `(x, y)`, top-
/// left origin, in `bgra`, clipped to the surface. Non-representable units draw
/// nothing (a blank cell), matching a metric-only stub font.
fn draw_glyph(mem: &mut dyn Memory, s: &Surface, ch: char, x: i32, y: i32, bgra: u32) -> Result<()> {
    use font8x8::UnicodeFonts;
    if let Some(rows) = font8x8::BASIC_FONTS.get(ch) {
        for (ry, bits) in rows.iter().enumerate() {
            for rx in 0..8i32 {
                if bits & (1 << rx) != 0 {
                    put_pixel(mem, s, x + rx, y + ry as i32, bgra)?;
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

    let Some((_hwnd, surface)) = dc_surface(os, hdc) else {
        return Ok(0);
    };

    // Read `count` WCHARs and rasterize left-to-right at a fixed 8px advance
    // (metric-only stub; proportional metrics + the CoreText path are W4.8).
    let mut cx = x;
    for i in 0..count {
        let unit = mem.read_u16(str_ptr + i as u64 * 2)?;
        let ch = char::from_u32(unit as u32).unwrap_or('\u{FFFD}');
        draw_glyph(mem, &surface, ch, cx, y, BGRA_BLACK)?;
        cx += 8;
    }
    Ok(1)
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

    let Some((_hwnd, surface)) = dc_surface(os, hdc) else {
        return Ok(0);
    };
    if right <= left || bottom <= top {
        return Ok(1); // degenerate rect: nothing to draw, still success.
    }
    let (x0, y0, x1, y1) = (left, top, right - 1, bottom - 1);
    // Top + bottom edges.
    for x in x0..=x1 {
        put_pixel(mem, &surface, x, y0, BGRA_BLACK)?;
        put_pixel(mem, &surface, x, y1, BGRA_BLACK)?;
    }
    // Left + right edges.
    for y in y0..=y1 {
        put_pixel(mem, &surface, x0, y, BGRA_BLACK)?;
        put_pixel(mem, &surface, x1, y, BGRA_BLACK)?;
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{DisplayMode, Perm, Region};
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
}
