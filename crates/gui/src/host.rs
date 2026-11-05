use std::collections::{HashMap, HashSet};

pub const SW_HIDE: i32 = 0;

pub(crate) const DEFAULT_TITLE: &str = "exemu";

#[derive(Debug, Clone)]
pub enum WindowCommand {
    Create {
        hwnd: u32,
        parent: u32,
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        visible: bool,
        title: String,
    },
    SetTitle {
        hwnd: u32,
        title: String,
    },
    Show {
        hwnd: u32,
        cmd: i32,
    },
    Pos {
        hwnd: u32,
        rect: [i32; 4],
    },
    Present {
        hwnd: u32,
        w: u32,
        h: u32,
        bgra: Vec<u8>,
    },
    Destroy {
        hwnd: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAction {
    Open { hwnd: u32, w: u32, h: u32, title: String },
    Title { hwnd: u32, title: String },
    Front { hwnd: u32 },
    Hide { hwnd: u32 },
    Resize { hwnd: u32, w: u32, h: u32 },
    Present { hwnd: u32 },
    Close { hwnd: u32 },
}

#[derive(Debug, Clone)]
struct Top {
    w: u32,
    h: u32,
    title: String,
    open: bool,
    shown: bool,
}

#[derive(Debug, Default)]
pub struct WindowModel {
    order: Vec<u32>,
    tops: HashMap<u32, Top>,
    children: HashSet<u32>,
}

impl Top {
    fn closed(w: u32, h: u32, title: &str) -> Self {
        Top { w, h, title: title.to_string(), open: false, shown: false }
    }
}

impl WindowModel {
    pub fn new() -> Self {
        WindowModel::default()
    }

    pub fn is_child(&self, hwnd: u32) -> bool {
        self.children.contains(&hwnd)
    }

    pub fn is_open(&self, hwnd: u32) -> bool {
        self.tops.get(&hwnd).is_some_and(|t| t.open)
    }

    pub fn primary(&self) -> Option<u32> {
        self.order.iter().copied().find(|h| self.visible(*h))
    }

    pub fn visible(&self, hwnd: u32) -> bool {
        self.tops.get(&hwnd).is_some_and(|t| t.open && t.shown)
    }

    pub fn visible_windows(&self) -> Vec<u32> {
        self.order.iter().copied().filter(|h| self.visible(*h)).collect()
    }

    pub fn open_windows(&self) -> Vec<u32> {
        self.order.iter().copied().filter(|h| self.is_open(*h)).collect()
    }

    pub fn forget(&mut self, hwnd: u32) {
        self.order.retain(|h| *h != hwnd);
        self.tops.remove(&hwnd);
        self.children.remove(&hwnd);
    }

    fn known(&self, hwnd: u32) -> bool {
        self.tops.contains_key(&hwnd) || self.children.contains(&hwnd)
    }

    fn ensure_top(&mut self, hwnd: u32, w: u32, h: u32, title: &str) -> Vec<HostAction> {
        if !self.tops.contains_key(&hwnd) {
            self.order.push(hwnd);
            self.tops.insert(hwnd, Top::closed(w, h, title));
        }
        let Some(entry) = self.tops.get_mut(&hwnd) else { return Vec::new() };
        if entry.open {
            return Vec::new();
        }
        entry.open = true;
        let (w, h, title) = (entry.w.max(1), entry.h.max(1), entry.title.clone());
        vec![HostAction::Open { hwnd, w, h, title }]
    }

    pub fn plan(&mut self, cmd: &WindowCommand) -> Vec<HostAction> {
        match cmd {
            WindowCommand::Create { hwnd, parent, w, h, visible, title, .. } => {
                if *parent != 0 && self.known(*parent) {
                    self.children.insert(*hwnd);
                    return Vec::new();
                }
                self.forget(*hwnd);
                self.order.push(*hwnd);
                self.tops.insert(*hwnd, Top::closed(*w, *h, title));
                if !*visible {
                    return Vec::new();
                }
                self.show(*hwnd)
            }
            WindowCommand::SetTitle { hwnd, title } => {
                let Some(top) = self.tops.get_mut(hwnd) else { return Vec::new() };
                top.title = title.clone();
                if !top.open {
                    return Vec::new();
                }
                vec![HostAction::Title { hwnd: *hwnd, title: title.clone() }]
            }
            WindowCommand::Show { hwnd, cmd } => {
                if !self.tops.contains_key(hwnd) {
                    return Vec::new();
                }
                if *cmd == SW_HIDE {
                    return self.hide(*hwnd);
                }
                self.show(*hwnd)
            }
            WindowCommand::Pos { hwnd, rect } => {
                let (w, h) = (rect[2].max(0) as u32, rect[3].max(0) as u32);
                let Some(top) = self.tops.get_mut(hwnd) else { return Vec::new() };
                if w == 0 || h == 0 || (top.w == w && top.h == h) {
                    return Vec::new();
                }
                top.w = w;
                top.h = h;
                if !top.open {
                    return Vec::new();
                }
                vec![HostAction::Resize { hwnd: *hwnd, w, h }]
            }
            WindowCommand::Present { hwnd, w, h, .. } => {
                if self.children.contains(hwnd) {
                    return Vec::new();
                }
                let mut actions = if self.is_open(*hwnd) {
                    Vec::new()
                } else {
                    if !self.tops.contains_key(hwnd) {
                        self.order.push(*hwnd);
                        self.tops.insert(*hwnd, Top::closed(*w, *h, DEFAULT_TITLE));
                    }
                    self.show(*hwnd)
                };
                actions.push(HostAction::Present { hwnd: *hwnd });
                actions
            }
            WindowCommand::Destroy { hwnd } => {
                self.children.remove(hwnd);
                let was_open = self.is_open(*hwnd);
                self.forget(*hwnd);
                if was_open {
                    vec![HostAction::Close { hwnd: *hwnd }]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn show(&mut self, hwnd: u32) -> Vec<HostAction> {
        let mut actions = self.ensure_top(hwnd, 1, 1, DEFAULT_TITLE);
        if let Some(top) = self.tops.get_mut(&hwnd) {
            top.shown = true;
        }
        actions.push(HostAction::Front { hwnd });
        actions
    }

    fn hide(&mut self, hwnd: u32) -> Vec<HostAction> {
        let Some(top) = self.tops.get_mut(&hwnd) else { return Vec::new() };
        if !top.shown {
            return Vec::new();
        }
        top.shown = false;
        if !top.open {
            return Vec::new();
        }
        vec![HostAction::Hide { hwnd }]
    }
}
