#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Button { default: bool },
    Edit,
    Static,
    Check,
    Progress,
    Other,
}

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

#[derive(Debug, Clone, Default)]
pub struct DialogTemplate {
    pub title: String,
    pub cx: u16,
    pub cy: u16,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiEvent {
    Command(u32),
    Close,
    MouseDown(i32, i32),
}

#[derive(Debug, Clone)]
pub enum DrawOp {
    Clear(u32),
    FillRect { x: i32, y: i32, w: i32, h: i32, color: u32 },
    FrameRect { x: i32, y: i32, w: i32, h: i32, color: u32 },
    Text { x: i32, y: i32, text: String, color: u32 },
    Line { x0: i32, y0: i32, x1: i32, y1: i32, color: u32 },
    Pixel { x: i32, y: i32, color: u32 },
}

pub trait Gui {
    fn open(&mut self, tpl: &DialogTemplate);
    fn set_text(&mut self, id: u32, text: &str);
    fn get_text(&self, id: u32) -> Option<String>;
    fn pump(&mut self, block: bool) -> Option<GuiEvent>;
    fn is_open(&self) -> bool;
    fn close(&mut self);

    fn open_window(&mut self, _title: &str, _w: u32, _h: u32) {}
    fn draw(&mut self, _op: &DrawOp) {}
    fn present(&mut self) {}
    fn client_size(&self) -> Option<(u32, u32)> {
        None
    }
}

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
