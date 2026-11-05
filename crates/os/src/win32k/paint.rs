use exemu_core::{CpuState, Memory, Result};

use crate::WinOs;

pub(super) const NT_USER_MOVE_WINDOW: u32 = 0x14ba;
pub(super) const NT_USER_INVALIDATE_RECT: u32 = 0x148c;
pub(super) const NT_USER_REDRAW_WINDOW: u32 = 0x14e9;

const RDW_INVALIDATE: u32 = 0x0001;
const RDW_VALIDATE: u32 = 0x0008;
const WINDOW_DIM_MAX: i32 = 32767;
const FALSE: u32 = 0;
const TRUE: u32 = 1;

fn nt_user_move_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg_u32(cpu, mem, 0)?;
    let x = os.syscall_arg_u32(cpu, mem, 1)? as i32;
    let y = os.syscall_arg_u32(cpu, mem, 2)? as i32;
    let cx = (os.syscall_arg_u32(cpu, mem, 3)? as i32).clamp(0, WINDOW_DIM_MAX);
    let cy = (os.syscall_arg_u32(cpu, mem, 4)? as i32).clamp(0, WINDOW_DIM_MAX);
    let repaint = os.syscall_arg_u32(cpu, mem, 5)? != 0;
    let owns_surface = os.win32k_state.surface_owner(hwnd) == hwnd;
    let Some(w) = os.win32k_state.window_mut(hwnd) else { return Ok(FALSE) };
    let resized = w.rect[2] != cx || w.rect[3] != cy;
    w.rect = [x, y, cx, cy];
    if resized && owns_surface {
        w.surface = None;
    }
    if resized || repaint {
        w.needs_paint = true;
    }
    let rect = w.rect;
    os.driver.window_pos_changing(hwnd);
    os.driver.window_pos_changed(hwnd, rect);
    Ok(TRUE)
}

fn invalidate(os: &mut WinOs, hwnd: u32) -> bool {
    if hwnd == 0 {
        for (_, w) in os.win32k_state.windows.iter_mut() {
            w.needs_paint = true;
        }
        return true;
    }
    match os.win32k_state.window_mut(hwnd) {
        Some(w) => {
            w.needs_paint = true;
            true
        }
        None => false,
    }
}

fn nt_user_invalidate_rect(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg_u32(cpu, mem, 0)?;
    Ok(u32::from(invalidate(os, hwnd)))
}

fn nt_user_redraw_window(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg_u32(cpu, mem, 0)?;
    let flags = os.syscall_arg_u32(cpu, mem, 3)?;
    if flags & RDW_INVALIDATE != 0 {
        return Ok(u32::from(invalidate(os, hwnd)));
    }
    if flags & RDW_VALIDATE != 0 {
        let Some(w) = os.win32k_state.window_mut(hwnd) else { return Ok(FALSE) };
        w.needs_paint = false;
        return Ok(TRUE);
    }
    Ok(u32::from(hwnd == 0 || os.win32k_state.window(hwnd).is_some()))
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_MOVE_WINDOW, nt_user_move_window);
    os.set_win32k_handler(NT_USER_INVALIDATE_RECT, nt_user_invalidate_rect);
    os.set_win32k_handler(NT_USER_REDRAW_WINDOW, nt_user_redraw_window);
}

#[cfg(test)]
mod tests {
    use exemu_core::{Perm, Reg, Region};
    use exemu_memory::VirtualMemory;

    use super::*;
    use crate::win32k::{alloc_handle, ensure_surface, Window, WS_VISIBLE};

    fn harness() -> (WinOs, VirtualMemory) {
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("scratch", 0x10_0000, 0x1_0000, Perm::RW)).unwrap();
        os.set_syscall_guest_rsp_for_test(0x10_8000);
        (os, mem)
    }

    fn window(os: &mut WinOs, parent: u32, rect: [i32; 4]) -> u32 {
        let hwnd = alloc_handle(os);
        let style = if parent == 0 { WS_VISIBLE } else { WS_VISIBLE | 0x4000_0000 };
        os.win32k_state.windows.push((
            hwnd,
            Window { rect, parent, style, shown: true, ..Window::default() },
        ));
        hwnd
    }

    fn call(
        f: fn(&mut WinOs, &mut CpuState, &mut dyn Memory) -> Result<u32>,
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        args: [u64; 6],
    ) -> u32 {
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, args[0]);
        cpu.set_reg(Reg::Rdx, args[1]);
        cpu.set_reg(Reg::R8, args[2]);
        cpu.set_reg(Reg::R9, args[3]);
        mem.write_u64(0x10_8000 + 0x28, args[4]).unwrap();
        mem.write_u64(0x10_8000 + 0x30, args[5]).unwrap();
        f(os, &mut cpu, mem).unwrap()
    }

    fn pending(os: &WinOs, hwnd: u32) -> bool {
        os.win32k_state.window(hwnd).unwrap().needs_paint
    }

    #[test]
    fn move_window_resizes_a_top_level_window_and_gives_it_a_fresh_surface() {
        let (mut os, mut mem) = harness();
        let hwnd = window(&mut os, 0, [0, 0, 2, 1]);
        let first = ensure_surface(&mut os, &mut mem, hwnd).unwrap();
        assert_eq!((first.w, first.h), (2, 1));

        let args = [hwnd as u64, 10, 20, 300, 200, 1];
        assert_eq!(call(nt_user_move_window, &mut os, &mut mem, args), 1);
        assert_eq!(os.win32k_state.window(hwnd).unwrap().rect, [10, 20, 300, 200]);
        assert!(pending(&os, hwnd), "a resized window repaints");
        let again = ensure_surface(&mut os, &mut mem, hwnd).unwrap();
        assert_eq!((again.w, again.h), (300, 200), "the 2x1 surface from creation time is gone");
        assert_ne!(again.base, first.base);
    }

    #[test]
    fn move_window_without_a_resize_keeps_the_surface_and_repaints_only_on_request() {
        let (mut os, mut mem) = harness();
        let hwnd = window(&mut os, 0, [0, 0, 50, 50]);
        let first = ensure_surface(&mut os, &mut mem, hwnd).unwrap();
        call(nt_user_move_window, &mut os, &mut mem, [hwnd as u64, 7, 8, 50, 50, 0]);
        assert_eq!(os.win32k_state.window(hwnd).unwrap().rect, [7, 8, 50, 50]);
        assert!(!pending(&os, hwnd));
        assert_eq!(ensure_surface(&mut os, &mut mem, hwnd).unwrap().base, first.base);
        call(nt_user_move_window, &mut os, &mut mem, [hwnd as u64, 7, 8, 50, 50, 1]);
        assert!(pending(&os, hwnd));
    }

    #[test]
    fn move_window_on_a_child_leaves_the_ancestors_surface_alone() {
        let (mut os, mut mem) = harness();
        let top = window(&mut os, 0, [0, 0, 100, 100]);
        let kid = window(&mut os, top, [5, 5, 10, 10]);
        let first = ensure_surface(&mut os, &mut mem, top).unwrap();
        call(nt_user_move_window, &mut os, &mut mem, [kid as u64, 1, 2, 30, 40, 1]);
        assert_eq!(os.win32k_state.window(kid).unwrap().rect, [1, 2, 30, 40]);
        assert_eq!(ensure_surface(&mut os, &mut mem, top).unwrap().base, first.base);
    }

    #[test]
    fn move_window_refuses_an_unknown_window_and_bounds_a_giant_size() {
        let (mut os, mut mem) = harness();
        assert_eq!(call(nt_user_move_window, &mut os, &mut mem, [0x9999, 0, 0, 1, 1, 1]), 0);
        let hwnd = window(&mut os, 0, [0, 0, 1, 1]);
        let giant = [hwnd as u64, 0, 0, 0x7FFF_FFFF, 0xFFFF_FFFF, 1];
        assert_eq!(call(nt_user_move_window, &mut os, &mut mem, giant), 1);
        let rect = os.win32k_state.window(hwnd).unwrap().rect;
        assert_eq!((rect[2], rect[3]), (WINDOW_DIM_MAX, 0));
    }

    #[test]
    fn invalidate_rect_queues_a_paint_for_the_window_and_for_null_every_window() {
        let (mut os, mut mem) = harness();
        let a = window(&mut os, 0, [0, 0, 10, 10]);
        let b = window(&mut os, 0, [0, 0, 10, 10]);
        assert!(!pending(&os, a));
        assert_eq!(call(nt_user_invalidate_rect, &mut os, &mut mem, [a as u64, 0, 1, 0, 0, 0]), 1);
        assert!(pending(&os, a));
        assert!(!pending(&os, b));
        os.win32k_state.window_mut(a).unwrap().needs_paint = false;
        assert_eq!(call(nt_user_invalidate_rect, &mut os, &mut mem, [0, 0, 1, 0, 0, 0]), 1);
        assert!(pending(&os, a) && pending(&os, b));
        assert_eq!(call(nt_user_invalidate_rect, &mut os, &mut mem, [0x9999, 0, 1, 0, 0, 0]), 0);
    }

    #[test]
    fn redraw_window_invalidates_or_validates_by_its_flags() {
        let (mut os, mut mem) = harness();
        let a = window(&mut os, 0, [0, 0, 10, 10]);
        let flags = |f: u64| [a as u64, 0, 0, f, 0, 0];
        assert_eq!(call(nt_user_redraw_window, &mut os, &mut mem, flags(RDW_INVALIDATE as u64)), 1);
        assert!(pending(&os, a));
        assert_eq!(call(nt_user_redraw_window, &mut os, &mut mem, flags(RDW_VALIDATE as u64)), 1);
        assert!(!pending(&os, a));
        assert_eq!(call(nt_user_redraw_window, &mut os, &mut mem, flags(0)), 1);
        assert!(!pending(&os, a), "no flag, no change");
    }
}
