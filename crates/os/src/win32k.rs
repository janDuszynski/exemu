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

use exemu_core::{CpuState, Memory, Result, WindowParams};

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
}

impl Win32kState {
    fn class_by_name(&self, name: &str) -> Option<u16> {
        self.classes
            .iter()
            .find(|(_, c)| c.name.eq_ignore_ascii_case(name))
            .map(|(a, _)| *a)
    }

    fn window_mut(&mut self, hwnd: u32) -> Option<&mut Window> {
        self.windows.iter_mut().find(|(h, _)| *h == hwnd).map(|(_, w)| w)
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
/// syscall user32's `SendMessageW` reaches (recovered: there is *no* dedicated
/// `NtUserSetWindowText` syscall — `SetWindowTextW` delivers `WM_SETTEXT` here).
/// We implement the minimal `WM_SETTEXT` arm: update the stored title and notify
/// the driver's `set_window_text`. Every other message returns 0 (the full
/// message dispatch is W4.5/W4.6).
fn nt_user_message_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let msg = os.syscall_arg(cpu, mem, 1)? as u32;
    if msg != WM_SETTEXT {
        return Ok(0);
    }
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
    Ok(1)
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

/// `NtUserGetDC`/`GetDCEx` → a fresh HDC handle. The backing surface is W4.3.
fn nt_user_get_dc(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(alloc_handle(os))
}

/// `NtUserReleaseDC` → 1 (released).
fn nt_user_release_dc(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(1)
}

/// `NtUserBeginPaint(hwnd, *PAINTSTRUCT)` → allocate an HDC, write a minimal
/// PAINTSTRUCT (hdc, fErase=FALSE, empty rcPaint), return the HDC. Real update
/// regions arrive with the surface in W4.3.
fn nt_user_begin_paint(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let ps = os.syscall_arg(cpu, mem, 1)?;
    let hdc = alloc_handle(os);
    if ps != 0 {
        // PAINTSTRUCT { HDC hdc @0; BOOL fErase @8; RECT rcPaint @0xC (l,t,r,b) }.
        mem.write_u64(ps, hdc as u64)?;
        mem.write_u32(ps + 8, 0)?;
        for off in (0xC..0x1C).step_by(4) {
            mem.write_u32(ps + off, 0)?;
        }
    }
    Ok(hdc)
}

/// `NtUserEndPaint` → 1. The present/blit arrives with the surface in W4.3.
fn nt_user_end_paint(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(1)
}

/// `NtUserGetMessage` → 0 (the WM_QUIT path), so the guest message loop
/// (`while (GetMessage(...))`) exits cleanly. The real native-event pump is
/// W4.5 — until then a GUI guest reaches its loop, gets no messages, and exits.
fn nt_user_get_message(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(0)
}

/// `NtUserPeekMessage` → 0 (no message available).
fn nt_user_peek_message(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(0)
}

/// `NtUserPostQuitMessage` → 0. The quit flag is a W4.5 concern.
fn nt_user_post_quit_message(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(0)
}
