//! The Win32 message queue (roadmap P5a.1).
//!
//! Each thread owns a queue of [`PostedMsg`]s. `PostMessage`/`PostThreadMessage`
//! enqueue asynchronously; `GetMessage`/`PeekMessage` drain it (delivering a
//! synthetic `WM_QUIT` once the queue empties after `PostQuitMessage`);
//! `TranslateMessage` turns a key-down into a `WM_CHAR`. This is additive: when
//! nothing has been posted, the legacy dialog/custom-window pump behaviour is
//! unchanged, so the installer path is unaffected.

use exemu_core::{CpuState, Memory, Result};

use crate::api::Outcome;
use crate::WinOs;

// Window messages this module produces or recognises.
pub(crate) const WM_QUIT: u32 = 0x0012;
const WM_KEYDOWN: u32 = 0x0100;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSCHAR: u32 = 0x0106;

/// One queued message.
#[derive(Clone, Copy)]
pub(crate) struct PostedMsg {
    pub hwnd: u64,
    pub message: u32,
    pub wparam: u64,
    pub lparam: u64,
}

impl WinOs {
    /// The index of the thread that should receive a message for `hwnd`. Windows
    /// are single-threaded for now, so everything targets the running thread.
    fn msg_target(&self, _hwnd: u64) -> usize {
        self.current
    }

    /// Enqueue a message on thread `idx`.
    fn enqueue(&mut self, idx: usize, m: PostedMsg) {
        self.threads[idx].msgs.push_back(m);
    }

    /// Post a message the OS synthesizes itself (e.g. `WM_SIZE`/`WM_MOVE` from a
    /// geometry change) to the window's owning thread.
    pub(crate) fn post_internal(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: u64) {
        let idx = self.msg_target(hwnd);
        self.enqueue(idx, PostedMsg { hwnd, message, wparam, lparam });
    }

    /// The next message for the running thread: a queued one, or a synthetic
    /// `WM_QUIT` exactly once after `PostQuitMessage` drains the queue.
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

    /// Peek the running thread's next message (`PeekMessage`). With `remove`,
    /// dequeue it; otherwise leave it in place. Surfaces a pending `WM_QUIT`.
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

    /// PostMessage(hWnd, Msg, wParam, lParam) — enqueue to the target window's
    /// thread. Returns TRUE.
    pub(crate) fn post_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let hwnd = self.arg(cpu, mem, 0)?;
        let message = self.arg(cpu, mem, 1)? as u32;
        let wparam = self.arg(cpu, mem, 2)?;
        let lparam = self.arg(cpu, mem, 3)?;
        // WM_QUIT via PostMessage behaves like PostQuitMessage on this thread.
        if message == WM_QUIT {
            self.threads[self.current].quit_code = Some(wparam as i32);
            return Ok(Outcome::Return(1));
        }
        let idx = self.msg_target(hwnd);
        self.enqueue(idx, PostedMsg { hwnd, message, wparam, lparam });
        Ok(Outcome::Return(1))
    }

    /// PostThreadMessage(idThread, Msg, wParam, lParam) — enqueue to a thread's
    /// queue with a null hwnd. Unknown thread ids fail (FALSE).
    pub(crate) fn post_thread_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let tid = self.arg(cpu, mem, 0)? as u32;
        let message = self.arg(cpu, mem, 1)? as u32;
        let wparam = self.arg(cpu, mem, 2)?;
        let lparam = self.arg(cpu, mem, 3)?;
        let Some(idx) = self.threads.iter().position(|t| t.tid == tid) else {
            self.set_last_error(1444); // ERROR_INVALID_THREAD_ID
            return Ok(Outcome::Return(0));
        };
        self.enqueue(idx, PostedMsg { hwnd: 0, message, wparam, lparam });
        Ok(Outcome::Return(1))
    }

    /// PostQuitMessage(nExitCode): mark the running thread to receive `WM_QUIT`
    /// once its queue drains.
    pub(crate) fn post_quit_message(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let code = self.arg(cpu, mem, 0)? as i32;
        self.threads[self.current].quit_code = Some(code);
        Ok(Outcome::Return(0))
    }

    /// TranslateMessage(lpMsg): if the message is a key-down, post the
    /// corresponding `WM_CHAR`/`WM_SYSCHAR` and report that a translation
    /// happened; otherwise a no-op returning FALSE.
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

/// Map a virtual-key code to a character for `TranslateMessage`. Covers the
/// printable ASCII range whose VK codes equal the uppercase character, plus
/// space and return — enough for keyboard-driven text entry in a plain window.
fn vkey_to_char(vk: u32) -> Option<char> {
    match vk {
        0x08 => Some('\u{8}'),  // VK_BACK
        0x09 => Some('\t'),     // VK_TAB
        0x0D => Some('\r'),     // VK_RETURN
        0x1B => Some('\u{1b}'), // VK_ESCAPE
        0x20 => Some(' '),      // VK_SPACE
        0x30..=0x39 => char::from_u32(vk),          // '0'..'9'
        0x41..=0x5A => char::from_u32(vk + 0x20),   // 'a'..'z' (unshifted)
        _ => None,
    }
}
