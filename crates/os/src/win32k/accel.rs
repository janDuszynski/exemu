use exemu_core::{CpuState, Memory, Result};

use super::keystate::{VK_CONTROL, VK_MENU, VK_SHIFT};
use super::{alloc_handle, dispatch_to_wndproc, WM_COMMAND, WS_CHILD};
use crate::WinOs;

const NT_USER_COPY_ACCELERATOR_TABLE: u32 = 0x135a;
const NT_USER_CREATE_ACCELERATOR_TABLE: u32 = 0x135c;
const NT_USER_DESTROY_ACCELERATOR_TABLE: u32 = 0x137b;
const NT_USER_TRANSLATE_ACCELERATOR: u32 = 0x15d7;

const ACCEL_COUNT_MAX: i32 = 0x1_0000;
const COMMAND_FROM_ACCELERATOR: u64 = 1 << 16;
const MF_DISABLED_OR_GRAYED: u32 = 0x0003;
const MENU_NOT_FOUND: u32 = u32::MAX;

const WM_KEYDOWN: u32 = 0x0100;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSCHAR: u32 = 0x0106;

mod accel_layout {
    pub const SIZE: u64 = 6;
    pub const VIRT: u64 = 0;
    pub const KEY: u64 = 2;
    pub const CMD: u64 = 4;
}

mod msg_layout {
    pub const MESSAGE: u64 = 8;
    pub const WPARAM: u64 = 16;
}

mod fvirt {
    pub const VIRTKEY: u8 = 0x01;
    pub const SHIFT: u8 = 0x04;
    pub const CONTROL: u8 = 0x08;
    pub const ALT: u8 = 0x10;
    pub const MODIFIERS: u8 = SHIFT | CONTROL | ALT;
    pub const STORED: u8 = 0x7F;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Accel {
    virt: u8,
    key: u16,
    cmd: u16,
}

#[derive(Default)]
pub(super) struct AccelState {
    tables: Vec<(u32, Vec<Accel>)>,
}

impl AccelState {
    fn table(&self, handle: u32) -> Option<&[Accel]> {
        self.tables.iter().find(|(h, _)| *h == handle).map(|(_, t)| t.as_slice())
    }

    fn destroy(&mut self, handle: u32) -> bool {
        let before = self.tables.len();
        self.tables.retain(|(h, _)| *h != handle);
        self.tables.len() != before
    }
}

fn matches(entry: Accel, message: u32, key: u16, modifiers: u8) -> bool {
    if entry.key != key {
        return false;
    }
    let virtual_key = entry.virt & fvirt::VIRTKEY != 0;
    let wants_alt = entry.virt & fvirt::ALT != 0;
    match message {
        WM_CHAR => !virtual_key && !wants_alt,
        WM_SYSCHAR => !virtual_key && wants_alt,
        _ => virtual_key && modifiers == entry.virt & fvirt::MODIFIERS,
    }
}

fn find_command(table: &[Accel], message: u32, key: u16, modifiers: u8) -> Option<u16> {
    table.iter().find(|e| matches(**e, message, key, modifiers)).map(|e| e.cmd)
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_CREATE_ACCELERATOR_TABLE, nt_user_create_accelerator_table);
    os.set_win32k_handler(NT_USER_COPY_ACCELERATOR_TABLE, nt_user_copy_accelerator_table);
    os.set_win32k_handler(NT_USER_DESTROY_ACCELERATOR_TABLE, nt_user_destroy_accelerator_table);
    os.set_win32k_handler(NT_USER_TRANSLATE_ACCELERATOR, nt_user_translate_accelerator);
}

fn read_table(mem: &dyn Memory, at: u64, count: usize) -> Result<Vec<Accel>> {
    let mut entries = Vec::with_capacity(count);
    for i in 0..count as u64 {
        let base = at.wrapping_add(i * accel_layout::SIZE);
        entries.push(Accel {
            virt: mem.read_u8(base + accel_layout::VIRT)? & fvirt::STORED,
            key: mem.read_u16(base + accel_layout::KEY)?,
            cmd: mem.read_u16(base + accel_layout::CMD)?,
        });
    }
    Ok(entries)
}

fn nt_user_create_accelerator_table(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let at = os.syscall_arg(cpu, mem, 0)?;
    let count = os.syscall_arg(cpu, mem, 1)? as i32;
    if at == 0 || !(1..=ACCEL_COUNT_MAX).contains(&count) {
        return Ok(0);
    }
    let Ok(entries) = read_table(mem, at, count as usize) else { return Ok(0) };
    let handle = alloc_handle(os);
    os.win32k_state.accels.tables.push((handle, entries));
    Ok(handle)
}

fn nt_user_copy_accelerator_table(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let out = os.syscall_arg(cpu, mem, 1)?;
    let count = os.syscall_arg(cpu, mem, 2)? as i32;
    let Some(table) = os.win32k_state.accels.table(handle) else { return Ok(0) };
    if out == 0 {
        return Ok(table.len() as u32);
    }
    let copied = table.len().min(usize::try_from(count).unwrap_or(0));
    for (i, entry) in table.iter().take(copied).enumerate() {
        let base = out.wrapping_add(i as u64 * accel_layout::SIZE);
        let written = mem
            .write_u16(base + accel_layout::VIRT, u16::from(entry.virt))
            .and_then(|()| mem.write_u16(base + accel_layout::KEY, entry.key))
            .and_then(|()| mem.write_u16(base + accel_layout::CMD, entry.cmd));
        if written.is_err() {
            return Ok(0);
        }
    }
    Ok(copied as u32)
}

fn nt_user_destroy_accelerator_table(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(u32::from(os.win32k_state.accels.destroy(handle)))
}

fn current_modifiers(os: &WinOs) -> u8 {
    let keys = &os.win32k_state.keys;
    [(VK_SHIFT, fvirt::SHIFT), (VK_CONTROL, fvirt::CONTROL), (VK_MENU, fvirt::ALT)]
        .into_iter()
        .filter(|(vk, _)| keys.is_down(*vk))
        .fold(0, |mask, (_, bit)| mask | bit)
}

fn command_disabled_in_window_menu(os: &WinOs, hwnd: u32, cmd: u16) -> bool {
    let Some(window) = os.win32k_state.window(hwnd) else { return false };
    if window.style & WS_CHILD != 0 {
        return false;
    }
    let Ok(menu) = u32::try_from(window.id) else { return false };
    let menus = &os.win32k_state.menus;
    let state = menus.state(menu, u32::from(cmd), 0);
    state != MENU_NOT_FOUND && state & MF_DISABLED_OR_GRAYED != 0
}

fn nt_user_translate_accelerator(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let handle = os.syscall_arg(cpu, mem, 1)? as u32;
    let msg = os.syscall_arg(cpu, mem, 2)?;
    if msg == 0 || os.win32k_state.window(hwnd).is_none() {
        return Ok(0);
    }
    let (Ok(message), Ok(wparam)) =
        (mem.read_u32(msg + msg_layout::MESSAGE), mem.read_u64(msg + msg_layout::WPARAM))
    else {
        return Ok(0);
    };
    if !matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR | WM_SYSCHAR) {
        return Ok(0);
    }
    let Some(table) = os.win32k_state.accels.table(handle) else { return Ok(0) };
    let key = (wparam & 0xFFFF) as u16;
    let Some(cmd) = find_command(table, message, key, current_modifiers(os)) else { return Ok(0) };
    if command_disabled_in_window_menu(os, hwnd, cmd) {
        return Ok(1);
    }
    let wparam = COMMAND_FROM_ACCELERATOR | u64::from(cmd);
    dispatch_to_wndproc(os, cpu, mem, u64::from(hwnd), WM_COMMAND, wparam, 0, Some(1))
}

#[cfg(test)]
mod tests;
