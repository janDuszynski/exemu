use exemu_core::{CpuState, Memory, Result};

use crate::WinOs;

const NT_USER_MAP_VIRTUAL_KEY_EX: u32 = 0x14b1;
const NT_USER_GET_KEYBOARD_LAYOUT: u32 = 0x1411;
const NT_USER_GET_KEY_NAME_TEXT: u32 = 0x140f;

pub(super) const HKL_US_ENGLISH: u32 = 0x0409_0409;

const MAPVK_VK_TO_VSC: u32 = 0;
const MAPVK_VSC_TO_VK: u32 = 1;
const MAPVK_VK_TO_CHAR: u32 = 2;
const MAPVK_VSC_TO_VK_EX: u32 = 3;
const MAPVK_VK_TO_VSC_EX: u32 = 4;

const PREFIX_E0: u32 = 0xE000;
const PREFIX_E1: u32 = 0xE100;
const PREFIX_MASK: u32 = 0xFF00;
const SCAN_MASK: u32 = 0x00FF;

const KEY_NAME_SCAN_SHIFT: u32 = 16;
const KEY_NAME_SCAN_MASK: u32 = 0xFF;
const KEY_NAME_EXTENDED: u32 = 1 << 24;
const KEY_NAME_DONT_CARE: u32 = 1 << 25;

const VK_CANCEL: u8 = 0x03;
const VK_BACK: u8 = 0x08;
const VK_TAB: u8 = 0x09;
const VK_CLEAR: u8 = 0x0C;
const VK_RETURN: u8 = 0x0D;
const VK_SHIFT: u8 = 0x10;
const VK_CONTROL: u8 = 0x11;
const VK_MENU: u8 = 0x12;
const VK_PAUSE: u8 = 0x13;
const VK_CAPITAL: u8 = 0x14;
const VK_ESCAPE: u8 = 0x1B;
const VK_SPACE: u8 = 0x20;
const VK_PRIOR: u8 = 0x21;
const VK_NEXT: u8 = 0x22;
const VK_END: u8 = 0x23;
const VK_HOME: u8 = 0x24;
const VK_LEFT: u8 = 0x25;
const VK_UP: u8 = 0x26;
const VK_RIGHT: u8 = 0x27;
const VK_DOWN: u8 = 0x28;
const VK_SNAPSHOT: u8 = 0x2C;
const VK_INSERT: u8 = 0x2D;
const VK_DELETE: u8 = 0x2E;
const VK_LWIN: u8 = 0x5B;
const VK_RWIN: u8 = 0x5C;
const VK_APPS: u8 = 0x5D;
const VK_NUMPAD0: u8 = 0x60;
const VK_MULTIPLY: u8 = 0x6A;
const VK_ADD: u8 = 0x6B;
const VK_SUBTRACT: u8 = 0x6D;
const VK_DECIMAL: u8 = 0x6E;
const VK_DIVIDE: u8 = 0x6F;
const VK_F1: u8 = 0x70;
const VK_F13: u8 = 0x7C;
const VK_NUMLOCK: u8 = 0x90;
const VK_SCROLL: u8 = 0x91;
const VK_LSHIFT: u8 = 0xA0;
const VK_RSHIFT: u8 = 0xA1;
const VK_LCONTROL: u8 = 0xA2;
const VK_RCONTROL: u8 = 0xA3;
const VK_LMENU: u8 = 0xA4;
const VK_RMENU: u8 = 0xA5;
const VK_OEM_1: u8 = 0xBA;
const VK_OEM_PLUS: u8 = 0xBB;
const VK_OEM_COMMA: u8 = 0xBC;
const VK_OEM_MINUS: u8 = 0xBD;
const VK_OEM_PERIOD: u8 = 0xBE;
const VK_OEM_2: u8 = 0xBF;
const VK_OEM_3: u8 = 0xC0;
const VK_OEM_4: u8 = 0xDB;
const VK_OEM_5: u8 = 0xDC;
const VK_OEM_6: u8 = 0xDD;
const VK_OEM_7: u8 = 0xDE;
const VK_OEM_102: u8 = 0xE2;

const SC_ESCAPE: u8 = 0x01;
const SC_BACK: u8 = 0x0E;
const SC_TAB: u8 = 0x0F;
const SC_RETURN: u8 = 0x1C;
const SC_LCONTROL: u8 = 0x1D;
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_MULTIPLY: u8 = 0x37;
const SC_LMENU: u8 = 0x38;
const SC_SPACE: u8 = 0x39;
const SC_CAPITAL: u8 = 0x3A;
const SC_NUMLOCK: u8 = 0x45;
const SC_SCROLL: u8 = 0x46;
const SC_SNAPSHOT: u8 = 0x54;
const SC_DIVIDE: u8 = 0x35;
const SC_PAUSE_E1: u8 = 0x1D;
const SC_CANCEL: u8 = 0x46;
const SC_LWIN: u8 = 0x5B;
const SC_RWIN: u8 = 0x5C;
const SC_APPS: u8 = 0x5D;

#[derive(Clone, Copy)]
struct Key {
    vk: u8,
    scan: u8,
    extended: bool,
    ch: u16,
}

const fn key(vk: u8, scan: u8, ch: u8) -> Key {
    Key { vk, scan, extended: false, ch: ch as u16 }
}

const fn ext(vk: u8, scan: u8) -> Key {
    Key { vk, scan, extended: true, ch: 0 }
}

const fn ext_char(vk: u8, scan: u8, ch: u8) -> Key {
    Key { vk, scan, extended: true, ch: ch as u16 }
}

const KEYS: &[Key] = &[
    key(VK_ESCAPE, SC_ESCAPE, 0x1B),
    key(b'1', 0x02, b'1'),
    key(b'2', 0x03, b'2'),
    key(b'3', 0x04, b'3'),
    key(b'4', 0x05, b'4'),
    key(b'5', 0x06, b'5'),
    key(b'6', 0x07, b'6'),
    key(b'7', 0x08, b'7'),
    key(b'8', 0x09, b'8'),
    key(b'9', 0x0A, b'9'),
    key(b'0', 0x0B, b'0'),
    key(VK_OEM_MINUS, 0x0C, b'-'),
    key(VK_OEM_PLUS, 0x0D, b'='),
    key(VK_BACK, SC_BACK, 0x08),
    key(VK_TAB, SC_TAB, b'\t'),
    key(b'Q', 0x10, b'Q'),
    key(b'W', 0x11, b'W'),
    key(b'E', 0x12, b'E'),
    key(b'R', 0x13, b'R'),
    key(b'T', 0x14, b'T'),
    key(b'Y', 0x15, b'Y'),
    key(b'U', 0x16, b'U'),
    key(b'I', 0x17, b'I'),
    key(b'O', 0x18, b'O'),
    key(b'P', 0x19, b'P'),
    key(VK_OEM_4, 0x1A, b'['),
    key(VK_OEM_6, 0x1B, b']'),
    key(VK_RETURN, SC_RETURN, b'\r'),
    key(VK_LCONTROL, SC_LCONTROL, 0),
    key(b'A', 0x1E, b'A'),
    key(b'S', 0x1F, b'S'),
    key(b'D', 0x20, b'D'),
    key(b'F', 0x21, b'F'),
    key(b'G', 0x22, b'G'),
    key(b'H', 0x23, b'H'),
    key(b'J', 0x24, b'J'),
    key(b'K', 0x25, b'K'),
    key(b'L', 0x26, b'L'),
    key(VK_OEM_1, 0x27, b';'),
    key(VK_OEM_7, 0x28, b'\''),
    key(VK_OEM_3, 0x29, b'`'),
    key(VK_LSHIFT, SC_LSHIFT, 0),
    key(VK_OEM_5, 0x2B, b'\\'),
    key(b'Z', 0x2C, b'Z'),
    key(b'X', 0x2D, b'X'),
    key(b'C', 0x2E, b'C'),
    key(b'V', 0x2F, b'V'),
    key(b'B', 0x30, b'B'),
    key(b'N', 0x31, b'N'),
    key(b'M', 0x32, b'M'),
    key(VK_OEM_COMMA, 0x33, b','),
    key(VK_OEM_PERIOD, 0x34, b'.'),
    key(VK_OEM_2, 0x35, b'/'),
    key(VK_RSHIFT, SC_RSHIFT, 0),
    key(VK_MULTIPLY, SC_MULTIPLY, b'*'),
    key(VK_LMENU, SC_LMENU, 0),
    key(VK_SPACE, SC_SPACE, b' '),
    key(VK_CAPITAL, SC_CAPITAL, 0),
    key(VK_F1, 0x3B, 0),
    key(VK_F1 + 1, 0x3C, 0),
    key(VK_F1 + 2, 0x3D, 0),
    key(VK_F1 + 3, 0x3E, 0),
    key(VK_F1 + 4, 0x3F, 0),
    key(VK_F1 + 5, 0x40, 0),
    key(VK_F1 + 6, 0x41, 0),
    key(VK_F1 + 7, 0x42, 0),
    key(VK_F1 + 8, 0x43, 0),
    key(VK_F1 + 9, 0x44, 0),
    key(VK_NUMLOCK, SC_NUMLOCK, 0),
    key(VK_SCROLL, SC_SCROLL, 0),
    key(VK_NUMPAD0 + 7, 0x47, b'7'),
    key(VK_NUMPAD0 + 8, 0x48, b'8'),
    key(VK_NUMPAD0 + 9, 0x49, b'9'),
    key(VK_SUBTRACT, 0x4A, b'-'),
    key(VK_NUMPAD0 + 4, 0x4B, b'4'),
    key(VK_NUMPAD0 + 5, 0x4C, b'5'),
    key(VK_NUMPAD0 + 6, 0x4D, b'6'),
    key(VK_ADD, 0x4E, b'+'),
    key(VK_NUMPAD0 + 1, 0x4F, b'1'),
    key(VK_NUMPAD0 + 2, 0x50, b'2'),
    key(VK_NUMPAD0 + 3, 0x51, b'3'),
    key(VK_NUMPAD0, 0x52, b'0'),
    key(VK_DECIMAL, 0x53, b'.'),
    key(VK_SNAPSHOT, SC_SNAPSHOT, 0),
    key(VK_OEM_102, 0x56, b'\\'),
    key(VK_F1 + 10, 0x57, 0),
    key(VK_F1 + 11, 0x58, 0),
    key(VK_F13, 0x64, 0),
    key(VK_F13 + 1, 0x65, 0),
    key(VK_F13 + 2, 0x66, 0),
    key(VK_F13 + 3, 0x67, 0),
    key(VK_F13 + 4, 0x68, 0),
    key(VK_F13 + 5, 0x69, 0),
    key(VK_F13 + 6, 0x6A, 0),
    key(VK_F13 + 7, 0x6B, 0),
    key(VK_F13 + 8, 0x6C, 0),
    key(VK_F13 + 9, 0x6D, 0),
    key(VK_F13 + 10, 0x6E, 0),
    key(VK_F13 + 11, 0x76, 0),
    key(VK_CLEAR, 0x4C, 0),
    ext(VK_RETURN, SC_RETURN),
    ext(VK_RCONTROL, SC_LCONTROL),
    ext_char(VK_DIVIDE, SC_DIVIDE, b'/'),
    ext(VK_SNAPSHOT, SC_MULTIPLY),
    ext(VK_RMENU, SC_LMENU),
    ext(VK_NUMLOCK, SC_NUMLOCK),
    ext(VK_CANCEL, SC_CANCEL),
    ext(VK_HOME, 0x47),
    ext(VK_UP, 0x48),
    ext(VK_PRIOR, 0x49),
    ext(VK_LEFT, 0x4B),
    ext(VK_RIGHT, 0x4D),
    ext(VK_END, 0x4F),
    ext(VK_DOWN, 0x50),
    ext(VK_NEXT, 0x51),
    ext(VK_INSERT, 0x52),
    ext(VK_DELETE, 0x53),
    ext(VK_LWIN, SC_LWIN),
    ext(VK_RWIN, SC_RWIN),
    ext(VK_APPS, SC_APPS),
];

const NAV_CLUSTER: &[(u8, u8)] = &[
    (0x47, VK_HOME),
    (0x48, VK_UP),
    (0x49, VK_PRIOR),
    (0x4B, VK_LEFT),
    (0x4C, VK_CLEAR),
    (0x4D, VK_RIGHT),
    (0x4F, VK_END),
    (0x50, VK_DOWN),
    (0x51, VK_NEXT),
    (0x52, VK_INSERT),
    (0x53, VK_DELETE),
];

const PLAIN_NAMES: &[(u8, &str)] = &[
    (0x01, "Esc"),
    (0x0E, "Backspace"),
    (0x0F, "Tab"),
    (0x1C, "Enter"),
    (0x1D, "Ctrl"),
    (0x2A, "Shift"),
    (0x36, "Right Shift"),
    (0x37, "Num *"),
    (0x38, "Alt"),
    (0x39, "Space"),
    (0x3A, "Caps Lock"),
    (0x3B, "F1"),
    (0x3C, "F2"),
    (0x3D, "F3"),
    (0x3E, "F4"),
    (0x3F, "F5"),
    (0x40, "F6"),
    (0x41, "F7"),
    (0x42, "F8"),
    (0x43, "F9"),
    (0x44, "F10"),
    (0x45, "Pause"),
    (0x46, "Scroll Lock"),
    (0x47, "Num 7"),
    (0x48, "Num 8"),
    (0x49, "Num 9"),
    (0x4A, "Num -"),
    (0x4B, "Num 4"),
    (0x4C, "Num 5"),
    (0x4D, "Num 6"),
    (0x4E, "Num +"),
    (0x4F, "Num 1"),
    (0x50, "Num 2"),
    (0x51, "Num 3"),
    (0x52, "Num 0"),
    (0x53, "Num Del"),
    (0x54, "Sys Req"),
    (0x57, "F11"),
    (0x58, "F12"),
    (0x64, "F13"),
    (0x65, "F14"),
    (0x66, "F15"),
    (0x67, "F16"),
    (0x68, "F17"),
    (0x69, "F18"),
    (0x6A, "F19"),
    (0x6B, "F20"),
    (0x6C, "F21"),
    (0x6D, "F22"),
    (0x6E, "F23"),
    (0x76, "F24"),
];

const EXTENDED_NAMES: &[(u8, &str)] = &[
    (0x1C, "Num Enter"),
    (0x1D, "Right Ctrl"),
    (0x35, "Num /"),
    (0x37, "Prnt Scrn"),
    (0x38, "Right Alt"),
    (0x45, "Num Lock"),
    (0x46, "Break"),
    (0x47, "Home"),
    (0x48, "Up"),
    (0x49, "Page Up"),
    (0x4B, "Left"),
    (0x4D, "Right"),
    (0x4F, "End"),
    (0x50, "Down"),
    (0x51, "Page Down"),
    (0x52, "Insert"),
    (0x53, "Delete"),
    (0x56, "Help"),
    (0x5B, "Left Windows"),
    (0x5C, "Right Windows"),
    (0x5D, "Application"),
];

fn find(vk: u8, extended: bool) -> Option<Key> {
    KEYS.iter().copied().find(|k| k.vk == vk && k.extended == extended)
}

fn generic_modifier_scan(vk: u8) -> Option<u8> {
    match vk {
        VK_SHIFT => Some(SC_LSHIFT),
        VK_CONTROL => Some(SC_LCONTROL),
        VK_MENU => Some(SC_LMENU),
        _ => None,
    }
}

fn plain_vk_for_scan(scan: u8) -> Option<u8> {
    if let Some((_, vk)) = NAV_CLUSTER.iter().find(|(s, _)| *s == scan) {
        return Some(*vk);
    }
    match scan {
        SC_NUMLOCK => Some(VK_NUMLOCK),
        _ => KEYS
            .iter()
            .find(|k| !k.extended && k.scan == scan && !is_numpad_digit(k.vk))
            .map(|k| k.vk),
    }
}

fn is_numpad_digit(vk: u8) -> bool {
    (VK_NUMPAD0..=VK_NUMPAD0 + 9).contains(&vk)
}

fn generic_vk(vk: u8) -> u8 {
    match vk {
        VK_LSHIFT | VK_RSHIFT => VK_SHIFT,
        VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
        VK_LMENU | VK_RMENU => VK_MENU,
        other => other,
    }
}

fn scan_to_vk(code: u32, exact_side: bool) -> u32 {
    let scan = (code & SCAN_MASK) as u8;
    let vk = match code & PREFIX_MASK {
        0 => plain_vk_for_scan(scan),
        PREFIX_E0 => find_extended_vk(scan),
        PREFIX_E1 if scan == SC_PAUSE_E1 => Some(VK_PAUSE),
        _ => None,
    };
    match vk {
        Some(vk) if exact_side => u32::from(vk),
        Some(vk) => u32::from(generic_vk(vk)),
        None => 0,
    }
}

fn find_extended_vk(scan: u8) -> Option<u8> {
    KEYS.iter().find(|k| k.extended && k.scan == scan).map(|k| k.vk)
}

fn vk_to_scan(code: u32, with_prefix: bool) -> u32 {
    let Ok(vk) = u8::try_from(code) else {
        return 0;
    };
    if let Some(scan) = generic_modifier_scan(vk) {
        return u32::from(scan);
    }
    if vk == VK_PAUSE {
        return if with_prefix {
            PREFIX_E1 | u32::from(SC_PAUSE_E1)
        } else {
            u32::from(SC_NUMLOCK)
        };
    }
    if let Some(key) = find(vk, false) {
        return u32::from(key.scan);
    }
    match find(vk, true) {
        Some(key) if with_prefix => PREFIX_E0 | u32::from(key.scan),
        Some(key) => u32::from(key.scan),
        None => 0,
    }
}

fn vk_to_char(code: u32) -> u32 {
    let Ok(vk) = u8::try_from(code) else {
        return 0;
    };
    find(vk, false).or_else(|| find(vk, true)).map_or(0, |k| u32::from(k.ch))
}

fn map_virtual_key(code: u32, map_type: u32) -> u32 {
    match map_type {
        MAPVK_VK_TO_VSC => vk_to_scan(code, false),
        MAPVK_VSC_TO_VK => scan_to_vk(code, false),
        MAPVK_VK_TO_CHAR => vk_to_char(code),
        MAPVK_VSC_TO_VK_EX => scan_to_vk(code, true),
        MAPVK_VK_TO_VSC_EX => vk_to_scan(code, true),
        _ => 0,
    }
}

fn named(table: &'static [(u8, &'static str)], scan: u8) -> Option<&'static str> {
    table.iter().find(|(s, _)| *s == scan).map(|(_, name)| *name)
}

fn key_name(lparam: u32) -> Option<String> {
    let scan = ((lparam >> KEY_NAME_SCAN_SHIFT) & KEY_NAME_SCAN_MASK) as u8;
    let extended = lparam & KEY_NAME_EXTENDED != 0;
    let dont_care = lparam & KEY_NAME_DONT_CARE != 0;
    if dont_care {
        let side_agnostic = match (scan, extended) {
            (SC_RSHIFT, false) => Some("Shift"),
            (SC_LCONTROL, true) => Some("Ctrl"),
            (SC_LMENU, true) => Some("Alt"),
            _ => None,
        };
        if let Some(name) = side_agnostic {
            return Some(name.to_string());
        }
    }
    if extended {
        if let Some(name) = named(EXTENDED_NAMES, scan) {
            return Some(name.to_string());
        }
    }
    if let Some(name) = named(PLAIN_NAMES, scan) {
        return Some(name.to_string());
    }
    let key = KEYS.iter().find(|k| !k.extended && k.scan == scan && k.ch != 0)?;
    char::from_u32(u32::from(key.ch)).filter(|c| c.is_ascii_graphic()).map(String::from)
}

#[cfg(test)]
mod tests;

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_MAP_VIRTUAL_KEY_EX, nt_user_map_virtual_key_ex);
    os.set_win32k_handler(NT_USER_GET_KEYBOARD_LAYOUT, nt_user_get_keyboard_layout);
    os.set_win32k_handler(NT_USER_GET_KEY_NAME_TEXT, nt_user_get_key_name_text);
}

fn nt_user_map_virtual_key_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let code = os.syscall_arg_u32(cpu, mem, 0)?;
    let map_type = os.syscall_arg_u32(cpu, mem, 1)?;
    Ok(map_virtual_key(code, map_type))
}

fn nt_user_get_keyboard_layout(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    Ok(HKL_US_ENGLISH)
}

fn nt_user_get_key_name_text(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let lparam = os.syscall_arg_u32(cpu, mem, 0)?;
    let buffer = os.syscall_arg(cpu, mem, 1)?;
    let size = os.syscall_arg_u32(cpu, mem, 2)?;
    let capacity = match usize::try_from(size as i32) {
        Ok(n) if n > 0 && buffer != 0 => n,
        _ => return Ok(0),
    };
    let Some(name) = key_name(lparam) else {
        return Ok(0);
    };
    let units: Vec<u16> = name.encode_utf16().take(capacity - 1).collect();
    let mut bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    bytes.extend_from_slice(&0u16.to_le_bytes());
    if mem.write(buffer, &bytes).is_err() {
        return Ok(0);
    }
    Ok(u32::try_from(units.len()).unwrap_or(0))
}
