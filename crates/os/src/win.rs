use exemu_core::{CpuState, Memory, Result};

use crate::api::{read_wstr, Outcome};
use crate::WinOs;

const GWL_WNDPROC: i32 = -4;
const GWL_HWNDPARENT: i32 = -8;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWL_USERDATA: i32 = -21;

impl WinOs {
    pub(crate) fn window_long(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, set: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let index = self.arg(cpu, mem, 1)? as i32;
        let value = if set { self.arg(cpu, mem, 2)? } else { 0 };
        let Some(w) = self.gdi.windows.get_mut(&hwnd) else {
            return Ok(Outcome::Return(0));
        };
        let old = match index {
            GWL_WNDPROC => {
                let o = w.wndproc;
                if set {
                    w.wndproc = value;
                }
                o
            }
            GWL_USERDATA => {
                let o = w.userdata;
                if set {
                    w.userdata = value;
                }
                o
            }
            GWL_STYLE => {
                let o = w.style as u64;
                if set {
                    w.style = value as u32;
                }
                o
            }
            GWL_EXSTYLE => {
                let o = w.ex_style as u64;
                if set {
                    w.ex_style = value as u32;
                }
                o
            }
            GWL_HWNDPARENT => {
                let o = w.parent;
                if set {
                    w.parent = value;
                }
                o
            }
            other => {
                let o = w.longs.get(&other).copied().unwrap_or(0);
                if set {
                    w.longs.insert(other, value);
                }
                o
            }
        };
        Ok(Outcome::Return(old))
    }

    pub(crate) fn get_class_name(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let buf = self.arg(cpu, mem, 1)?;
        let max = self.arg(cpu, mem, 2)? as usize;
        let name = self.gdi.windows.get(&hwnd).map(|w| w.class.clone()).unwrap_or_default();
        let n = if wide {
            WinOs::write_wstr(mem, buf, &name, max)?
        } else {
            crate::api::write_astr(mem, buf, &name, max)?
        };
        Ok(Outcome::Return(n))
    }

    pub(crate) fn is_window(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        Ok(Outcome::Return(self.gdi.windows.contains_key(&hwnd) as u64))
    }

    pub(crate) fn get_client_rect_win(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let rect = self.arg(cpu, mem, 1)?;
        let (_, _, w, h) = self.gdi.windows.get(&hwnd).map(|win| win.rect).unwrap_or((0, 0, 640, 480));
        if rect != 0 {
            mem.write_u32(rect, 0)?;
            mem.write_u32(rect + 4, 0)?;
            mem.write_u32(rect + 8, w as u32)?;
            mem.write_u32(rect + 12, h as u32)?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn get_window_rect(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let rect = self.arg(cpu, mem, 1)?;
        let (x, y, w, h) = self.gdi.windows.get(&hwnd).map(|win| win.rect).unwrap_or((0, 0, 640, 480));
        if rect != 0 {
            mem.write_u32(rect, x as u32)?;
            mem.write_u32(rect + 4, y as u32)?;
            mem.write_u32(rect + 8, (x + w) as u32)?;
            mem.write_u32(rect + 12, (y + h) as u32)?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn show_window(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let cmd = self.arg(cpu, mem, 1)?;
        let was_visible = self.gdi.windows.get(&hwnd).map(|w| w.visible).unwrap_or(false);
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.visible = cmd != 0;
        }
        Ok(Outcome::Return(was_visible as u64))
    }

    pub(crate) fn set_prop(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let name = self.prop_name(mem, self.arg(cpu, mem, 1)?, wide)?;
        let data = self.arg(cpu, mem, 2)?;
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.props.insert(name, data);
            Ok(Outcome::Return(1))
        } else {
            Ok(Outcome::Return(0))
        }
    }

    pub(crate) fn get_prop(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let name = self.prop_name(mem, self.arg(cpu, mem, 1)?, wide)?;
        let v = self.gdi.windows.get(&hwnd).and_then(|w| w.props.get(&name)).copied().unwrap_or(0);
        Ok(Outcome::Return(v))
    }

    pub(crate) fn remove_prop(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let name = self.prop_name(mem, self.arg(cpu, mem, 1)?, wide)?;
        let v = self.gdi.windows.get_mut(&hwnd).and_then(|w| w.props.remove(&name)).unwrap_or(0);
        Ok(Outcome::Return(v))
    }

    pub(crate) fn set_focus(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let prev = self.gdi.focus_hwnd;
        self.gdi.focus_hwnd = hwnd;
        Ok(Outcome::Return(prev))
    }

    pub(crate) fn get_focus(&mut self) -> Result<Outcome> {
        Ok(Outcome::Return(self.gdi.focus_hwnd))
    }

    pub(crate) fn set_capture(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let prev = self.gdi.capture_hwnd;
        self.gdi.capture_hwnd = hwnd;
        Ok(Outcome::Return(prev))
    }

    pub(crate) fn get_capture(&mut self) -> Result<Outcome> {
        Ok(Outcome::Return(self.gdi.capture_hwnd))
    }

    pub(crate) fn release_capture(&mut self) -> Result<Outcome> {
        self.gdi.capture_hwnd = 0;
        Ok(Outcome::Return(1))
    }

    pub(crate) fn get_key_state(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let _ = self.arg(cpu, mem, 0)?;
        Ok(Outcome::Return(0))
    }

    pub(crate) fn get_cursor_pos(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let p = self.arg(cpu, mem, 0)?;
        if p != 0 {
            mem.write_u32(p, 0)?;
            mem.write_u32(p + 4, 0)?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn move_window(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let x = self.arg(cpu, mem, 1)? as i32;
        let y = self.arg(cpu, mem, 2)? as i32;
        let w = self.arg(cpu, mem, 3)? as i32;
        let h = self.arg(cpu, mem, 4)? as i32;
        let repaint = self.arg(cpu, mem, 5)? != 0;
        self.reposition(hwnd, x, y, w, h, repaint)
    }

    pub(crate) fn set_window_pos(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        const SWP_NOSIZE: u64 = 0x0001;
        const SWP_NOMOVE: u64 = 0x0002;
        let hwnd = self.arg(cpu, mem, 0)?;
        let x = self.arg(cpu, mem, 2)? as i32;
        let y = self.arg(cpu, mem, 3)? as i32;
        let cx = self.arg(cpu, mem, 4)? as i32;
        let cy = self.arg(cpu, mem, 5)? as i32;
        let flags = self.arg(cpu, mem, 6)?;
        let cur = self.gdi.windows.get(&hwnd).map(|w| w.rect).unwrap_or((0, 0, 640, 480));
        let (nx, ny) = if flags & SWP_NOMOVE != 0 { (cur.0, cur.1) } else { (x, y) };
        let (nw, nh) = if flags & SWP_NOSIZE != 0 { (cur.2, cur.3) } else { (cx, cy) };
        self.reposition(hwnd, nx, ny, nw, nh, true)
    }

    fn reposition(&mut self, hwnd: u64, x: i32, y: i32, w: i32, h: i32, repaint: bool) -> Result<Outcome> {
        let Some(win) = self.gdi.windows.get_mut(&hwnd) else {
            return Ok(Outcome::Return(0));
        };
        let moved = (win.rect.0, win.rect.1) != (x, y);
        let sized = (win.rect.2, win.rect.3) != (w, h);
        win.rect = (x, y, w, h);
        if repaint {
            win.paint_pending = true;
            win.update_rect = (0, 0, w, h);
        }
        if moved {
            let lp = (x as u32 as u64 & 0xFFFF) | ((y as u32 as u64 & 0xFFFF) << 16);
            self.post_internal(hwnd, 0x0003, 0, lp);
        }
        if sized {
            let lp = (w as u32 as u64 & 0xFFFF) | ((h as u32 as u64 & 0xFFFF) << 16);
            self.post_internal(hwnd, 0x0005, 0, lp);
        }
        Ok(Outcome::Return(1))
    }

    fn prop_name(&self, mem: &dyn Memory, ptr: u64, wide: bool) -> Result<String> {
        if ptr <= 0xFFFF {
            return Ok(format!("#{ptr}"));
        }
        if wide {
            read_wstr(mem, ptr)
        } else {
            Ok(String::from_utf8_lossy(&mem.read_cstr(ptr, 256)?).into_owned())
        }
    }
}
