use exemu_core::{CpuState, Memory, Result};

use crate::api::Outcome;
use crate::WinOs;

pub(crate) const WM_QUIT: u32 = 0x0012;
const WM_KEYDOWN: u32 = 0x0100;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSCHAR: u32 = 0x0106;

#[derive(Clone, Copy)]
pub(crate) struct PostedMsg {
    pub hwnd: u64,
    pub message: u32,
    pub wparam: u64,
    pub lparam: u64,
}

impl PostedMsg {
    pub(crate) fn into_args(self) -> Vec<u64> {
        vec![self.hwnd, self.message as u64, self.wparam, self.lparam]
    }
}

impl WinOs {
    fn msg_target(&self, _hwnd: u64) -> usize {
        self.current
    }

    fn enqueue(&mut self, idx: usize, m: PostedMsg) {
        self.threads[idx].msgs.push_back(m);
    }

    pub(crate) fn post_internal(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: u64) {
        let idx = self.msg_target(hwnd);
        self.enqueue(idx, PostedMsg { hwnd, message, wparam, lparam });
    }

    pub(crate) fn msg_next(&mut self) -> Option<PostedMsg> {
        let t = &mut self.threads[self.current];
        if let Some(m) = t.msgs.pop_front() {
            return Some(m);
        }
        t.quit_code.take().map(|code| PostedMsg {
            hwnd: 0,
            message: WM_QUIT,
            wparam: code as u32 as u64,
            lparam: 0,
        })
    }

    pub(crate) fn msg_peek(&mut self, remove: bool) -> Option<PostedMsg> {
        let t = &mut self.threads[self.current];
        if let Some(&front) = t.msgs.front() {
            if remove {
                t.msgs.pop_front();
            }
            return Some(front);
        }
        t.quit_code.map(|code| {
            if remove {
                t.quit_code = None;
            }
            PostedMsg { hwnd: 0, message: WM_QUIT, wparam: code as u32 as u64, lparam: 0 }
        })
    }

    pub(crate) fn post_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let message = self.arg(cpu, mem, 1)? as u32;
        let wparam = self.arg(cpu, mem, 2)?;
        let lparam = self.arg(cpu, mem, 3)?;
        if message == WM_QUIT {
            self.threads[self.current].quit_code = Some(wparam as i32);
            return Ok(Outcome::Return(1));
        }
        let idx = self.msg_target(hwnd);
        self.enqueue(idx, PostedMsg { hwnd, message, wparam, lparam });
        Ok(Outcome::Return(1))
    }

    pub(crate) fn post_thread_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let tid = self.arg(cpu, mem, 0)? as u32;
        let message = self.arg(cpu, mem, 1)? as u32;
        let wparam = self.arg(cpu, mem, 2)?;
        let lparam = self.arg(cpu, mem, 3)?;
        let Some(idx) = self.threads.iter().position(|t| t.tid == tid) else {
            self.set_last_error(mem, 1444);
            return Ok(Outcome::Return(0));
        };
        self.enqueue(idx, PostedMsg { hwnd: 0, message, wparam, lparam });
        Ok(Outcome::Return(1))
    }

    pub(crate) fn post_quit_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as i32;
        self.threads[self.current].quit_code = Some(code);
        Ok(Outcome::Return(0))
    }

    pub(crate) fn translate_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let lp = self.arg(cpu, mem, 0)?;
        if lp == 0 {
            return Ok(Outcome::Return(0));
        }
        let (hwnd, message, wparam, _lparam) = self.read_msg(mem, lp)?;
        let message = message as u32;
        let (char_msg, is_key) = match message {
            WM_KEYDOWN => (WM_CHAR, true),
            WM_SYSKEYDOWN => (WM_SYSCHAR, true),
            _ => (0, false),
        };
        if !is_key {
            return Ok(Outcome::Return(0));
        }
        if let Some(ch) = vkey_to_char(wparam as u32) {
            let idx = self.current;
            self.enqueue(idx, PostedMsg { hwnd, message: char_msg, wparam: ch as u64, lparam: 0 });
        }
        Ok(Outcome::Return(1))
    }
}

pub(crate) fn vkey_to_char(vk: u32) -> Option<char> {
    match vk {
        0x08 => Some('\u{8}'),
        0x09 => Some('\t'),
        0x0D => Some('\r'),
        0x1B => Some('\u{1b}'),
        0x20 => Some(' '),
        0x30..=0x39 => char::from_u32(vk),
        0x41..=0x5A => char::from_u32(vk + 0x20),
        _ => None,
    }
}
