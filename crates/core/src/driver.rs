//! The display-driver abstraction (W4.2 / W4.3).
//!
//! The domain only knows that *some* backend can be told about window lifecycle
//! events — create, destroy, show, resize, title change — and surface/present
//! operations. The concrete driver (a real AppKit/Metal window or a headless
//! recorder) lives in `exemu-gui`; the OS layer calls through [`UserDriver`] so
//! it stays free of any windowing dependency.
//!
//! This is the Rust-native moral equivalent of Wine's `user_driver_funcs` vtable.
//! All marshalling from guest pointers happens in the win32k handler **before**
//! calling the driver; the driver itself only sees plain Rust types and is
//! testable without a running guest.
//!
//! ## Surface / present (W4.3)
//!
//! The win32k present path reads the DIB pixel buffer out of guest memory and
//! hands a plain `&[u8]` to [`UserDriver::flush_surface`]. The driver never
//! touches guest memory — all guest-pointer work is done in the handler before
//! the call crosses this boundary.

/// Parameters for a window creation call, mirroring the flat arguments that
/// `NtUserCreateWindowEx` receives from user32's `CreateWindowExW` wrapper.
#[derive(Debug, Clone)]
pub struct WindowParams {
    /// The registered window-class atom (nonzero) or 0 if the class is
    /// identified by name only. When nonzero it takes precedence.
    pub class_atom: u16,
    /// Window-class name (empty when `class_atom` is nonzero).
    pub class_name: String,
    /// Window title / caption text.
    pub title: String,
    /// Top-left x coordinate (client-area, in pixels).
    pub x: i32,
    /// Top-left y coordinate (client-area, in pixels).
    pub y: i32,
    /// Width in pixels.
    pub cx: i32,
    /// Height in pixels.
    pub cy: i32,
    /// `WS_*` style bits.
    pub style: u32,
    /// `WS_EX_*` extended style bits.
    pub ex_style: u32,
    /// Guest handle of the parent window, or 0 for a top-level window.
    pub parent: u32,
}

/// A window-management driver. Implemented by `exemu-gui`; the OS layer holds a
/// `Box<dyn UserDriver>`.
///
/// Every method has a default no-op implementation so adding future members to
/// this trait (W4.3+) does not break existing impls. Load-bearing overrides live
/// in the concrete driver structs.
pub trait UserDriver: Send {
    /// A new top-level or child window is being created.
    ///
    /// `hwnd` is the fresh handle allocated by the win32k HWND allocator.
    /// The driver should allocate a backing surface or native window object and
    /// associate it with `hwnd` for later calls.
    fn create_window(&mut self, hwnd: u32, params: &WindowParams) {
        let _ = (hwnd, params);
    }

    /// The window identified by `hwnd` is being destroyed.
    ///
    /// The driver should release any resources (native window, surface) it
    /// associated with `hwnd` in [`create_window`].
    fn destroy_window(&mut self, hwnd: u32) {
        let _ = hwnd;
    }

    /// Called before the window's position/size changes (default no-op).
    ///
    /// Drivers that need to prepare before a resize (e.g. locking a surface)
    /// can do so here. If not overridden the position change proceeds silently.
    fn window_pos_changing(&mut self, hwnd: u32) {
        let _ = hwnd;
    }

    /// The window's position or size has changed.
    ///
    /// `rect` is `[x, y, cx, cy]` — top-left plus extent in pixels. The
    /// driver should resize its backing surface to match.
    fn window_pos_changed(&mut self, hwnd: u32, rect: [i32; 4]) {
        let _ = (hwnd, rect);
    }

    /// The window's visibility state has changed.
    ///
    /// `cmd` is the `SW_*` constant (e.g. `SW_SHOW` = 5, `SW_HIDE` = 0).
    fn show_window(&mut self, hwnd: u32, cmd: i32) {
        let _ = (hwnd, cmd);
    }

    /// The window's parent has changed (default no-op).
    ///
    /// Called when `SetParent` re-parents an existing window. Drivers that
    /// track parent/child hierarchies can update their internal tree here.
    fn set_parent(&mut self, hwnd: u32, parent: u32) {
        let _ = (hwnd, parent);
    }

    /// The window's clipping region has changed (default no-op).
    ///
    /// `rgn_hwnd` is the source-window handle for the region, or 0 to clear.
    /// Deferred until W4.7+; the default is intentionally inert.
    fn set_window_rgn(&mut self, hwnd: u32, rgn_hwnd: u32) {
        let _ = (hwnd, rgn_hwnd);
    }

    /// The window's title bar text has changed.
    ///
    /// `text` is already decoded to UTF-8. The driver should update the
    /// native window title if one is visible.
    fn set_window_text(&mut self, hwnd: u32, text: &str) {
        let _ = (hwnd, text);
    }

    /// Allocate a per-HWND backing surface of the given pixel dimensions (W4.3).
    ///
    /// `w` and `h` are in pixels. The surface format is top-down BGRA32 with
    /// `stride = w * 4`, matching the Windows GDI DIB layout. Replaces any
    /// existing surface for `hwnd`. The window management side-effect (native
    /// window resize) is covered by [`window_pos_changed`]; this call is
    /// exclusively about surface storage.
    ///
    /// Called by the win32k `NtGdiCreateDIBSection` handler after the DIB
    /// backing store has been mapped into guest memory.
    fn create_window_surface(&mut self, hwnd: u32, w: u32, h: u32) {
        let _ = (hwnd, w, h);
    }

    /// Present a rendered frame for `hwnd` (W4.3).
    ///
    /// `pixels` is a top-down BGRA32 slice of exactly `w * h * 4` bytes
    /// (`stride = w * 4`) that the win32k handler has already read out of guest
    /// memory. The driver never touches guest memory — all marshalling is done
    /// before this call.
    ///
    /// For the `OffscreenPresenter` this writes a PNG to the configured output
    /// directory (or just increments the frame counter when no directory is set).
    /// For the live Cocoa path (W4.4) it uploads the texture and presents.
    ///
    /// Called by the win32k `NtUserEndPaint` handler (the present point).
    fn flush_surface(&mut self, hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        let _ = (hwnd, pixels, w, h);
    }
}

/// A no-op driver for headless runs and automated test corpus execution.
///
/// Every call is a silent no-op; no allocation, no rendering, no I/O.
pub struct NoDriver;

impl UserDriver for NoDriver {}

/// An input event delivered from the native windowing host (main thread) to the
/// interpreter thread's message pump (roadmap W4.5c/W4.6).
///
/// This is the reverse direction of [`UserDriver`]: the host produces these as
/// the user interacts with a native window; the win32k `NtUserGetMessage`
/// handler drains them into the guest's message queue so a Wine-hosted GUI stays
/// live. Only window-close is modelled for now; mouse/keyboard follow in W4.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// The user asked to close the window (the red close button / Cmd-W). The
    /// pump turns this into a `WM_QUIT`, so the guest's message loop exits
    /// cleanly.
    Close,
}
