//! Window-object query/mutate APIs on top of the real HWND table (roadmap
//! P5a.2), see [`crate::gdi::Window`].
//!
//! `Get/SetWindowLongPtr`, `IsWindow`, `GetClientRect`/`GetWindowRect`,
//! `Get/Set/RemoveProp`, `ShowWindow` — the surface guest code uses to store
//! and retrieve per-window state (window subclassing, user data, properties)
//! that a single shared fake HWND could never satisfy. This is what lets an app
//! (and installer plugins like nsDialogs) treat its HWND as a real object.

use exemu_core::{CpuState, Memory, Result};

use crate::api::{read_wstr, Outcome};
use crate::WinOs;

// GWL/GWLP indices (negative, interpreted as i32).
const GWL_WNDPROC: i32 = -4;
const GWL_HWNDPARENT: i32 = -8;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWL_USERDATA: i32 = -21;

impl WinOs {
    /// Get/SetWindowLong[Ptr][AW]. Pointer-sized on 64-bit; the standard
    /// negative indices map to named window fields, other offsets round-trip
    /// through the per-window extra-longs map.
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

    /// GetClassName[AW](hWnd, lpBuf, nMaxCount) → the window's class name.
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

    /// IsWindow(hWnd) → TRUE if it is a live window object.
    pub(crate) fn is_window(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        Ok(Outcome::Return(self.gdi.windows.contains_key(&hwnd) as u64))
    }

    /// GetClientRect(hWnd, lpRect): the window's client area as (0,0,w,h).
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

    /// GetWindowRect(hWnd, lpRect): the window's screen rectangle.
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

    /// ShowWindow(hWnd, nCmdShow): track visibility; return the previous state.
    pub(crate) fn show_window(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let cmd = self.arg(cpu, mem, 1)?;
        let was_visible = self.gdi.windows.get(&hwnd).map(|w| w.visible).unwrap_or(false);
        if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
            w.visible = cmd != 0; // SW_HIDE = 0
        }
        Ok(Outcome::Return(was_visible as u64))
    }

    /// SetProp[AW](hWnd, lpString, hData): attach a named property.
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

    /// GetProp[AW](hWnd, lpString) → the property handle, or 0.
    pub(crate) fn get_prop(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let name = self.prop_name(mem, self.arg(cpu, mem, 1)?, wide)?;
        let v = self.gdi.windows.get(&hwnd).and_then(|w| w.props.get(&name)).copied().unwrap_or(0);
        Ok(Outcome::Return(v))
    }

    /// RemoveProp[AW](hWnd, lpString) → the removed handle, or 0.
    pub(crate) fn remove_prop(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, wide: bool) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let name = self.prop_name(mem, self.arg(cpu, mem, 1)?, wide)?;
        let v = self.gdi.windows.get_mut(&hwnd).and_then(|w| w.props.remove(&name)).unwrap_or(0);
        Ok(Outcome::Return(v))
    }

    /// A property name is either a string pointer or, when the high bits are
    /// zero, a global atom (encoded as `#<atom>`).
    fn prop_name(&self, mem: &dyn Memory, ptr: u64, wide: bool) -> Result<String> {
        if ptr <= 0xFFFF {
            return Ok(format!("#{ptr}")); // atom
        }
        if wide {
            read_wstr(mem, ptr)
        } else {
            Ok(String::from_utf8_lossy(&mem.read_cstr(ptr, 256)?).into_owned())
        }
    }
}
