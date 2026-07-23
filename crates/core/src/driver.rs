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

/// The display mode a [`UserDriver`] presents (roadmap W4.7). Backs
/// `NtUserEnumDisplaySettings` / `ChangeDisplaySettings`; a live backend can
/// override [`UserDriver::display_mode`] with the real `NSScreen` geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayMode {
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Colour depth in bits per pixel.
    pub bpp: u32,
    /// Refresh rate in Hz.
    pub frequency: u32,
    /// Logical dots per inch (`dmLogPixels` / `GetDpiForSystem`).
    pub dpi: u32,
}

impl Default for DisplayMode {
    /// A single 1920×1080, 32-bpp, 60 Hz, 96-DPI monitor — the headless default.
    fn default() -> Self {
        DisplayMode { width: 1920, height: 1080, bpp: 32, frequency: 60, dpi: 96 }
    }
}

/// A rasterized run of text produced by [`UserDriver::rasterize_text`] (roadmap
/// W4.8). `coverage` is a top-down, `width × height` 8-bit alpha mask (0 =
/// background, 255 = full glyph coverage); the win32k text path composites it in
/// the text colour over the DIB. `(0,0)` is the top-left of the text cell, so it
/// blits directly at the `TextOut` origin (baseline sits `height − descent` down).
#[derive(Debug, Clone)]
pub struct TextBitmap {
    /// Width of the coverage mask in pixels (the summed glyph advances).
    pub width: u32,
    /// Height of the coverage mask in pixels (font ascent + descent).
    pub height: u32,
    /// Row-major, top-down 8-bit alpha, `width * height` bytes.
    pub coverage: Vec<u8>,
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

    /// The cursor shape changed (roadmap W4.7). `hcursor` is the guest `HCURSOR`
    /// the app passed to `SetCursor`, or 0 to hide the cursor. Default no-op; a
    /// live backend maps it to an `NSCursor`. The current-cursor bookkeeping (and
    /// the previous-handle return `SetCursor` needs) lives in the win32k layer.
    fn set_cursor(&mut self, hcursor: u64) {
        let _ = hcursor;
    }

    /// The display mode this driver presents (roadmap W4.7). Default: a single
    /// 1920×1080 monitor (see [`DisplayMode::default`]). A live backend reports
    /// the real screen. Read-only here — `ChangeDisplaySettings` is accepted but
    /// not applied (exemu does not resize the host display).
    fn display_mode(&self) -> DisplayMode {
        DisplayMode::default()
    }

    /// Rasterize `text` at `px` pixels into an alpha-coverage [`TextBitmap`]
    /// (roadmap W4.8). The win32k `NtGdiExtTextOutW` path calls this so real
    /// (CoreText) glyphs land in the DIB; returning `None` (the default) makes it
    /// fall back to the built-in `font8x8` stub, so headless / non-macOS runs
    /// still render text deterministically.
    fn rasterize_text(&self, text: &str, px: u32) -> Option<TextBitmap> {
        let _ = (text, px);
        None
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
/// handler drains them into the guest's message queue (as `WM_MOUSEMOVE` /
/// `WM_*BUTTON*` / `WM_KEY*` / `WM_QUIT`) so a Wine-hosted GUI stays interactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// The user asked to close the window (the red close button / Cmd-W). The
    /// pump turns this into a `WM_QUIT`, so the guest's message loop exits
    /// cleanly.
    Close,
    /// The pointer moved to client-area point `(x, y)`. → `WM_MOUSEMOVE`.
    MouseMove { x: i32, y: i32 },
    /// A mouse button transitioned at client-area point `(x, y)`. →
    /// `WM_LBUTTONDOWN`/`WM_LBUTTONUP` (or the right-button pair).
    MouseButton { button: MouseButton, down: bool, x: i32, y: i32 },
    /// A key transitioned. `vk` is the Windows virtual-key code. →
    /// `WM_KEYDOWN`/`WM_KEYUP`.
    Key { vk: u32, down: bool },
}

/// Which mouse button an [`InputEvent::MouseButton`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// The primary (left) button.
    Left,
    /// The secondary (right) button.
    Right,
}
