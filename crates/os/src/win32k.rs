//! win32k (USER/GDI) unix backend — the skeleton `NtUser*`/`NtGdi*` SSDT
//! handlers (roadmap W4.1).
//!
//! Wine's `user32.dll`/`gdi32.dll` hold the *real* USER/GDI logic and import
//! ~470 `NtUser*`/`NtGdi*` calls from `win32u.dll`, which is a **pure syscall
//! shim** (1290 stubs, indices 0x1084–0x1601 — the `0x1000` table bit selects
//! this second SSDT). The kernel-side USER/GDI logic + display driver that
//! normally live in `win32u.so` become exemu's win32k handlers + a native Rust
//! driver (see `knowledge/w4-gui-design.know` §0/§2); exemu never loads
//! `win32u.so`, so there is no guest-visible driver-registration seam.
//!
//! **W4.1 is the skeleton.** It gives Wine's user32/gdi32 valid-but-inert return
//! values (a nonzero class ATOM, HWND/HDC handles, 96 DPI, an empty message
//! queue) so they stop null-dereferencing the syscall results — getting a GUI
//! guest past the win32k boundary. No window is created and no driver runs yet
//! (that is W4.2+). Every index outside the load-bearing set falls to
//! [`honest_stub`], which returns 0 (a null handle / FALSE) rather than a
//! garbage non-null status, so nothing pretends to have done work it didn't.

use exemu_core::{CpuState, Memory, Result};

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

/// win32k unix-backend state (roadmap W4.1). Grows into the window/class/DC
/// object model in W4.2+.
#[derive(Default)]
pub(crate) struct Win32kState {
    /// The client-side PFN table pointer recorded by
    /// `NtUserInitializeClientPfnArrays` — the guest WndProc-caller thunks the
    /// kernel→user callback path (roadmap W4.6) will jump to.
    client_pfn_table: u64,
    /// Number of `NtUserRegisterClassExWOW` calls so far; the next class atom is
    /// `CLASS_ATOM_BASE + class_count`. The real class registry is W4.2.
    class_count: u16,
}

/// Install the W4.1 skeleton into the win32k SSDT table: fill the whole win32u
/// index range with [`honest_stub`], then override the load-bearing slots.
/// Called from `WinOs::new`. Corpus-safe: the win32k table is only reached via a
/// guest win32u `SYSCALL`, which the emulated corpus never issues.
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

/// Every win32u index outside the load-bearing skeleton set → 0 (a null handle
/// / FALSE), never a garbage non-null status, so Wine's user32/gdi32 see a clean
/// "no object" instead of dereferencing a fake pointer.
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

/// `NtUserGetClassInfoEx` → 0 (not found), so user32 proceeds to register the
/// class (the class registry is W4.2).
fn nt_user_get_class_info_ex(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(0)
}

/// `NtUserRegisterClassExWOW` → a fresh nonzero class ATOM (Windows' 0xC000+
/// range). The class object model (name→WNDCLASS) is W4.2.
fn nt_user_register_class_ex_wow(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    let atom = CLASS_ATOM_BASE.wrapping_add(os.win32k_state.class_count);
    os.win32k_state.class_count = os.win32k_state.class_count.wrapping_add(1);
    Ok(atom as u32)
}

/// `NtUserCreateWindowEx` → a fresh HWND handle so user32 has a valid window.
/// The driver window + WM_NCCREATE/WM_CREATE callbacks are W4.2/W4.6.
fn nt_user_create_window_ex(
    os: &mut WinOs,
    _cpu: &mut CpuState,
    _mem: &mut dyn Memory,
) -> Result<u32> {
    Ok(alloc_handle(os))
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
