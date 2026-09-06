#[derive(Debug, Clone)]
pub struct WindowParams {
    pub class_atom: u16,
    pub class_name: String,
    pub title: String,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub style: u32,
    pub ex_style: u32,
    pub parent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub frequency: u32,
    pub dpi: u32,
}

impl Default for DisplayMode {
    fn default() -> Self {
        DisplayMode { width: 1920, height: 1080, bpp: 32, frequency: 60, dpi: 96 }
    }
}

#[derive(Debug, Clone)]
pub struct TextBitmap {
    pub width: u32,
    pub height: u32,
    pub coverage: Vec<u8>,
}

pub trait UserDriver: Send {
    fn create_window(&mut self, hwnd: u32, params: &WindowParams) {
        let _ = (hwnd, params);
    }

    fn destroy_window(&mut self, hwnd: u32) {
        let _ = hwnd;
    }

    fn window_pos_changing(&mut self, hwnd: u32) {
        let _ = hwnd;
    }

    fn window_pos_changed(&mut self, hwnd: u32, rect: [i32; 4]) {
        let _ = (hwnd, rect);
    }

    fn show_window(&mut self, hwnd: u32, cmd: i32) {
        let _ = (hwnd, cmd);
    }

    fn set_parent(&mut self, hwnd: u32, parent: u32) {
        let _ = (hwnd, parent);
    }

    fn set_window_rgn(&mut self, hwnd: u32, rgn_hwnd: u32) {
        let _ = (hwnd, rgn_hwnd);
    }

    fn set_window_text(&mut self, hwnd: u32, text: &str) {
        let _ = (hwnd, text);
    }

    fn create_window_surface(&mut self, hwnd: u32, w: u32, h: u32) {
        let _ = (hwnd, w, h);
    }

    fn flush_surface(&mut self, hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        let _ = (hwnd, pixels, w, h);
    }

    fn set_cursor(&mut self, hcursor: u64) {
        let _ = hcursor;
    }

    fn display_mode(&self) -> DisplayMode {
        DisplayMode::default()
    }

    fn rasterize_text(&self, text: &str, px: u32) -> Option<TextBitmap> {
        let _ = (text, px);
        None
    }
}

pub struct NoDriver;

impl UserDriver for NoDriver {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    Close,
    MouseMove { x: i32, y: i32 },
    MouseButton { button: MouseButton, down: bool, x: i32, y: i32 },
    Key { vk: u32, down: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
}
