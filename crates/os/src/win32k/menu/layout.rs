use exemu_core::{CpuState, Memory, Result};

use super::{guarded, mf, Item, Menu};
use crate::win32k::{default_metrics, measure_run, WS_CHILD};
use crate::WinOs;

const NT_USER_CALC_MENU_BAR: u32 = 0x1330;
const NT_USER_GET_MENU_BAR_INFO: u32 = 0x1418;
const NT_USER_GET_MENU_ITEM_RECT: u32 = 0x141a;

const MENU_TEXT_PADDING: u32 = 2;
const MENU_BAR_DIVIDER: i32 = 1;
const ITEM_SPACING: i32 = 12;
const SEPARATOR_HEIGHT: i32 = 5;
const ACCELERATOR_MARK: char = '&';

const OBJID_MENU: i32 = -3;
const MENU_BAR_INFO_CB_SIZE: u32 = 0x30;

mod rect {
    pub const LEFT: u64 = 0x00;
    pub const TOP: u64 = 0x04;
    pub const RIGHT: u64 = 0x08;
    pub const BOTTOM: u64 = 0x0c;
}

mod menubarinfo {
    pub const CB_SIZE: u64 = 0x00;
    pub const RC_BAR: u64 = 0x04;
    pub const HMENU: u64 = 0x18;
    pub const HWND_MENU: u64 = 0x20;
    pub const FLAGS: u64 = 0x28;
}

pub(in crate::win32k) fn menu_height() -> u32 {
    MENU_TEXT_PADDING + default_metrics().height + MENU_BAR_DIVIDER as u32
}

pub(super) struct Bar {
    pub items: Vec<[i32; 4]>,
    pub height: i32,
}

impl Bar {
    pub(super) fn band(&self) -> i32 {
        self.height + MENU_BAR_DIVIDER
    }

    pub(super) fn rect(&self, width: i32) -> [i32; 4] {
        [0, 0, width, self.height]
    }
}

fn strip_accelerator_marks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ACCELERATOR_MARK {
            if chars.peek() == Some(&ACCELERATOR_MARK) {
                out.push(c);
                chars.next();
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn item_width(os: &WinOs, item: &Item) -> i32 {
    if item.kind & (mf::SEPARATOR | mf::BITMAP | mf::OWNERDRAW) != 0 {
        return 0;
    }
    let Some(text) = item.text.as_deref() else { return 0 };
    let metrics = default_metrics();
    let (width, _) = measure_run(os, &strip_accelerator_marks(text), &metrics);
    i32::try_from(width).unwrap_or(i32::MAX / 4).saturating_add(ITEM_SPACING)
}

fn item_height(item: &Item, row_height: i32) -> i32 {
    if item.kind & mf::SEPARATOR != 0 {
        SEPARATOR_HEIGHT
    } else {
        row_height
    }
}

pub(super) fn lay_out(os: &WinOs, menu: &Menu, width: i32) -> Bar {
    let width = width.max(1);
    let count = menu.items.len();
    let row_height = (default_metrics().height as i32).max(menu_height() as i32 - 1);
    let widths: Vec<i32> = menu.items.iter().map(|item| item_width(os, item)).collect();
    let mut rects = vec![[0i32; 4]; count];
    let mut origin_y = 0;
    let mut max_y = if count == 0 { row_height } else { 1 };
    let mut right_justify = None;
    let mut start = 0;
    while start < count {
        let mut origin_x = 0i32;
        let mut end = start;
        while end < count {
            let item = &menu.items[end];
            if right_justify.is_none() && item.kind & mf::RIGHTJUSTIFY != 0 {
                right_justify = Some(end);
            }
            if end != start && item.kind & (mf::MENUBREAK | mf::MENUBARBREAK) != 0 {
                break;
            }
            let mut r = [
                origin_x,
                origin_y,
                origin_x.saturating_add(widths[end]),
                origin_y + item_height(item, row_height),
            ];
            if r[2] > width {
                if end != start {
                    break;
                }
                r[2] = width;
            }
            rects[end] = r;
            max_y = max_y.max(r[3]);
            origin_x = r[2];
            end += 1;
        }
        for r in &mut rects[start..end] {
            r[3] = max_y;
        }
        origin_y = max_y;
        start = end;
    }
    if let Some(first) = right_justify {
        flush_right(&mut rects, first, width);
    }
    Bar { items: rects, height: max_y }
}

fn flush_right(rects: &mut [[i32; 4]], first: usize, width: i32) {
    let Some(last_top) = rects.last().map(|r| r[1]) else { return };
    let mut edge = width;
    for r in rects[first..].iter_mut().rev() {
        if r[1] != last_top || r[2] >= edge {
            break;
        }
        let shift = edge - r[2];
        r[0] += shift;
        r[2] = edge;
        edge = r[0];
    }
}

fn attached_menu(os: &WinOs, hwnd: u32) -> Option<u32> {
    let window = os.win32k_state.window(hwnd)?;
    if window.style & WS_CHILD != 0 {
        return None;
    }
    let handle = u32::try_from(window.id).ok()?;
    os.win32k_state.menus.contains(handle).then_some(handle)
}

fn window_with_menu(os: &WinOs, menu: u32) -> Option<u32> {
    os.win32k_state.windows.iter().map(|(h, _)| *h).find(|h| attached_menu(os, *h) == Some(menu))
}

fn bar_for(os: &WinOs, hwnd: u32) -> Option<(u32, Bar)> {
    let handle = attached_menu(os, hwnd)?;
    let width = os.win32k_state.window(hwnd)?.rect[2];
    let menu = os.win32k_state.menus.menu(handle)?;
    Some((handle, lay_out(os, menu, width)))
}

pub(super) fn relayout_window(os: &mut WinOs, hwnd: u32) {
    let band = bar_for(os, hwnd).map_or(0, |(_, bar)| bar.band());
    if let Some(window) = os.win32k_state.window_mut(hwnd) {
        window.menu_bar = band;
    }
}

pub(super) fn relayout_all(os: &mut WinOs) {
    let handles: Vec<u32> = os.win32k_state.windows.iter().map(|(h, _)| *h).collect();
    for hwnd in handles {
        relayout_window(os, hwnd);
    }
}

fn screen_offset(os: &WinOs, hwnd: u32) -> Option<(i32, i32)> {
    let window = os.win32k_state.window(hwnd)?;
    Some((window.rect[0], window.rect[1]))
}

fn offset(r: [i32; 4], (dx, dy): (i32, i32)) -> [i32; 4] {
    [r[0].wrapping_add(dx), r[1].wrapping_add(dy), r[2].wrapping_add(dx), r[3].wrapping_add(dy)]
}

fn write_rect(mem: &mut dyn Memory, at: u64, r: [i32; 4]) -> Result<()> {
    mem.write_u32(at + rect::LEFT, r[0] as u32)?;
    mem.write_u32(at + rect::TOP, r[1] as u32)?;
    mem.write_u32(at + rect::RIGHT, r[2] as u32)?;
    mem.write_u32(at + rect::BOTTOM, r[3] as u32)
}

fn item_screen_rect(os: &WinOs, hwnd: u32, menu: u32, pos: u32) -> Option<[i32; 4]> {
    let hwnd = if hwnd == 0 { window_with_menu(os, menu)? } else { hwnd };
    let (attached, bar) = bar_for(os, hwnd)?;
    if attached != menu {
        return None;
    }
    let local = *bar.items.get(usize::try_from(pos).ok()?)?;
    Some(offset(local, screen_offset(os, hwnd)?))
}

fn nt_user_get_menu_item_rect(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let menu = os.syscall_arg(cpu, mem, 1)? as u32;
    let pos = os.syscall_arg(cpu, mem, 2)? as u32;
    let out = os.syscall_arg(cpu, mem, 3)?;
    guarded(get_menu_item_rect(os, mem, [hwnd, menu, pos], out), 0)
}

fn get_menu_item_rect(os: &WinOs, mem: &mut dyn Memory, [hwnd, menu, pos]: [u32; 3], out: u64) -> Result<u32> {
    if out == 0 {
        return Ok(0);
    }
    let Some(r) = item_screen_rect(os, hwnd, menu, pos) else { return Ok(0) };
    write_rect(mem, out, r)?;
    Ok(1)
}

fn nt_user_get_menu_bar_info(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let object = os.syscall_arg(cpu, mem, 1)? as u32 as i32;
    let item = os.syscall_arg(cpu, mem, 2)? as u32 as i32;
    let info = os.syscall_arg(cpu, mem, 3)?;
    guarded(get_menu_bar_info(os, mem, hwnd, [object, item], info), 0)
}

fn get_menu_bar_info(os: &WinOs, mem: &mut dyn Memory, hwnd: u32, [object, item]: [i32; 2], info: u64) -> Result<u32> {
    if info == 0 || object != OBJID_MENU || item < 0 {
        return Ok(0);
    }
    if mem.read_u32(info + menubarinfo::CB_SIZE)? != MENU_BAR_INFO_CB_SIZE {
        return Ok(0);
    }
    let Some((menu, bar)) = bar_for(os, hwnd) else { return Ok(0) };
    let Some(origin) = screen_offset(os, hwnd) else { return Ok(0) };
    let width = os.win32k_state.window(hwnd).map_or(0, |w| w.rect[2]);
    let local = match usize::try_from(item) {
        Ok(0) => bar.rect(width.max(1)),
        Ok(n) => match bar.items.get(n - 1) {
            Some(r) => *r,
            None => return Ok(0),
        },
        Err(_) => return Ok(0),
    };
    write_rect(mem, info + menubarinfo::RC_BAR, offset(local, origin))?;
    mem.write_u64(info + menubarinfo::HMENU, u64::from(menu))?;
    mem.write_u64(info + menubarinfo::HWND_MENU, 0)?;
    mem.write_u32(info + menubarinfo::FLAGS, 0)?;
    Ok(1)
}

fn nt_user_calc_menu_bar(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let left = os.syscall_arg(cpu, mem, 1)? as u32 as i32;
    let right = os.syscall_arg(cpu, mem, 2)? as u32 as i32;
    let area = os.syscall_arg(cpu, mem, 4)?;
    guarded(calc_menu_bar(os, mem, hwnd, [left, right], area), 0)
}

fn calc_menu_bar(os: &WinOs, mem: &dyn Memory, hwnd: u32, [left, right]: [i32; 2], area: u64) -> Result<u32> {
    let Some(handle) = attached_menu(os, hwnd) else { return Ok(0) };
    let Some(menu) = os.win32k_state.menus.menu(handle) else { return Ok(0) };
    let span = if area == 0 {
        os.win32k_state.window(hwnd).map_or(0, |w| w.rect[2])
    } else {
        let l = mem.read_u32(area + rect::LEFT)? as i32;
        let r = mem.read_u32(area + rect::RIGHT)? as i32;
        r.wrapping_sub(l)
    };
    let width = span.saturating_sub(left).saturating_sub(right);
    Ok(u32::try_from(lay_out(os, menu, width).band()).unwrap_or(0))
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_CALC_MENU_BAR, nt_user_calc_menu_bar);
    os.set_win32k_handler(NT_USER_GET_MENU_BAR_INFO, nt_user_get_menu_bar_info);
    os.set_win32k_handler(NT_USER_GET_MENU_ITEM_RECT, nt_user_get_menu_item_rect);
}

#[cfg(test)]
mod tests;
