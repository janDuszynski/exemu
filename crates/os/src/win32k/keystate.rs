use exemu_core::{CpuState, InputEvent, Memory, Result};

use crate::WinOs;

const NT_USER_GET_KEY_STATE: u32 = 0x1410;
const NT_USER_GET_ASYNC_KEY_STATE: u32 = 0x13d0;

const KEY_COUNT: usize = 256;
const KEY_STATE_DOWN: u32 = 0x8000;

pub(super) const VK_SHIFT: u32 = 0x10;
pub(super) const VK_CONTROL: u32 = 0x11;
pub(super) const VK_MENU: u32 = 0x12;
const VK_LSHIFT: u32 = 0xA0;
const VK_RSHIFT: u32 = 0xA1;
const VK_LCONTROL: u32 = 0xA2;
const VK_RCONTROL: u32 = 0xA3;
const VK_LMENU: u32 = 0xA4;
const VK_RMENU: u32 = 0xA5;

pub(super) struct KeyState {
    down: [bool; KEY_COUNT],
}

impl Default for KeyState {
    fn default() -> Self {
        KeyState { down: [false; KEY_COUNT] }
    }
}

impl KeyState {
    pub(super) fn note(&mut self, event: InputEvent) {
        if let InputEvent::Key { vk, down, .. } = event {
            if let Some(slot) = usize::try_from(vk).ok().and_then(|i| self.down.get_mut(i)) {
                *slot = down;
            }
        }
    }

    pub(super) fn is_down(&self, vk: u32) -> bool {
        let held = |code: u32| self.down.get(code as usize).copied().unwrap_or(false);
        match vk {
            VK_SHIFT => held(VK_SHIFT) || held(VK_LSHIFT) || held(VK_RSHIFT),
            VK_CONTROL => held(VK_CONTROL) || held(VK_LCONTROL) || held(VK_RCONTROL),
            VK_MENU => held(VK_MENU) || held(VK_LMENU) || held(VK_RMENU),
            other => held(other),
        }
    }
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_GET_KEY_STATE, nt_user_get_key_state);
    os.set_win32k_handler(NT_USER_GET_ASYNC_KEY_STATE, nt_user_get_key_state);
}

fn nt_user_get_key_state(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let vk = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(if os.win32k_state.keys.is_down(vk) { KEY_STATE_DOWN } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(vk: u32, down: bool) -> InputEvent {
        InputEvent::Key { hwnd: 0, vk, down }
    }

    #[test]
    fn a_pressed_key_reads_down_until_it_is_released() {
        let mut keys = KeyState::default();
        assert!(!keys.is_down(0x41));
        keys.note(key(0x41, true));
        assert!(keys.is_down(0x41));
        assert!(!keys.is_down(0x42));
        keys.note(key(0x41, false));
        assert!(!keys.is_down(0x41));
    }

    #[test]
    fn the_generic_modifier_answers_for_either_side() {
        let mut keys = KeyState::default();
        keys.note(key(VK_RCONTROL, true));
        assert!(keys.is_down(VK_CONTROL), "right control is control");
        assert!(!keys.is_down(VK_SHIFT));
        keys.note(key(VK_SHIFT, true));
        assert!(keys.is_down(VK_SHIFT));
        keys.note(key(VK_LMENU, true));
        assert!(keys.is_down(VK_MENU));
    }

    #[test]
    fn a_wild_virtual_key_is_not_a_panic() {
        let mut keys = KeyState::default();
        keys.note(key(0xFFFF_FFFF, true));
        keys.note(InputEvent::Close);
        assert!(!keys.is_down(0xFFFF_FFFF));
        assert!(!keys.is_down(KEY_COUNT as u32));
    }
}
