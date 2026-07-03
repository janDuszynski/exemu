//! The GUI abstraction.
//!
//! The domain only knows that *some* backend can show a dialog made of
//! standard Windows controls, let their text change, and report clicks and
//! window-close events. The concrete renderer (a real window) lives in the
//! `exemu-gui` crate; the OS layer talks to it through [`Gui`] so it stays
//! free of any windowing dependency.

/// The kind of a dialog control, mapped from its window class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    /// A push button. `default` marks the IDOK/default button.
    Button { default: bool },
    /// An editable text field.
    Edit,
    /// Static (label) text.
    Static,
    /// A checkbox / radio (drawn as a button with a box).
    Check,
    /// A progress bar (`msctls_progress32`).
    Progress,
    /// Anything else — drawn as a plain box.
    Other,
}

/// A single control in a dialog, positioned in dialog units.
#[derive(Debug, Clone)]
pub struct Control {
    pub id: u32,
    pub kind: ControlKind,
    pub text: String,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
}

/// A parsed dialog template ready to render.
#[derive(Debug, Clone, Default)]
pub struct DialogTemplate {
    pub title: String,
    /// Size in dialog units.
    pub cx: u16,
    pub cy: u16,
    pub controls: Vec<Control>,
}

/// Something a rendered dialog reports back to the OS layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiEvent {
    /// A control (usually a button) was activated; carries its id.
    Command(u32),
    /// The window's close box was clicked.
    Close,
    /// The mouse was pressed at a client-area position (custom windows).
    MouseDown(i32, i32),
}

/// A primitive drawing operation issued by the emulated GDI into a custom
/// window's framebuffer. Colors are `0x00RRGGBB`.
#[derive(Debug, Clone)]
pub enum DrawOp {
    Clear(u32),
    FillRect { x: i32, y: i32, w: i32, h: i32, color: u32 },
    FrameRect { x: i32, y: i32, w: i32, h: i32, color: u32 },
    Text { x: i32, y: i32, text: String, color: u32 },
    Line { x0: i32, y0: i32, x1: i32, y1: i32, color: u32 },
    Pixel { x: i32, y: i32, color: u32 },
}

/// A windowing backend. Implemented by `exemu-gui`; the OS layer holds a
/// `Box<dyn Gui>`.
pub trait Gui {
    /// Show a dialog window built from `tpl`. Replaces any current window.
    fn open(&mut self, tpl: &DialogTemplate);
    /// Update a control's text (e.g. after `SetDlgItemTextW`) and redraw.
    fn set_text(&mut self, id: u32, text: &str);
    /// Current text of a control (edits the user may have changed).
    fn get_text(&self, id: u32) -> Option<String>;
    /// Pump the window: process input, redraw, and return one pending event.
    /// `block` = keep the window responsive until an event arrives (used by a
    /// blocking `GetMessage`); otherwise poll once and return quickly.
    fn pump(&mut self, block: bool) -> Option<GuiEvent>;
    /// Whether a window is currently shown.
    fn is_open(&self) -> bool;
    /// Close the window.
    fn close(&mut self);

    // ---- custom (non-dialog) windows, drawn by the emulated GDI ----------

    /// Open a blank client-area window of the given pixel size. Default no-op.
    fn open_window(&mut self, _title: &str, _w: u32, _h: u32) {}
    /// Apply a GDI drawing operation to the window's framebuffer. Default no-op.
    fn draw(&mut self, _op: &DrawOp) {}
    /// Flush accumulated drawing to the screen (EndPaint / a pump tick).
    fn present(&mut self) {}
    /// Client-area size in pixels, if a custom window is open.
    fn client_size(&self) -> Option<(u32, u32)> {
        None
    }
}

/// A no-op backend for headless runs and tests.
pub struct NoGui;

impl Gui for NoGui {
    fn open(&mut self, _tpl: &DialogTemplate) {}
    fn set_text(&mut self, _id: u32, _text: &str) {}
    fn get_text(&self, _id: u32) -> Option<String> {
        None
    }
    fn pump(&mut self, _block: bool) -> Option<GuiEvent> {
        None
    }
    fn is_open(&self) -> bool {
        false
    }
    fn close(&mut self) {}
}
