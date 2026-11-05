use exemu_core::{CpuState, Memory, Result};

use super::{alloc_handle, WS_CHILD};
use crate::WinOs;

const NT_USER_CREATE_MENU: u32 = 0x1366;
const NT_USER_CREATE_POPUP_MENU: u32 = 0x1368;
const NT_USER_DESTROY_MENU: u32 = 0x1382;
const NT_USER_DELETE_MENU: u32 = 0x1378;
const NT_USER_REMOVE_MENU: u32 = 0x151d;
const NT_USER_SET_MENU: u32 = 0x1569;
const NT_USER_CHECK_MENU_ITEM: u32 = 0x1347;
const NT_USER_ENABLE_MENU_ITEM: u32 = 0x13a7;
const NT_USER_DRAW_MENU_BAR: u32 = 0x139b;
const NT_USER_THUNKED_MENU_INFO: u32 = 0x15cf;
const NT_USER_THUNKED_MENU_ITEM_INFO: u32 = 0x15d0;

pub(super) const CALL_ONE_PARAM_GET_MENU_ITEM_COUNT: u64 = 0x04;
pub(super) const CALL_TWO_PARAM_GET_MENU_INFO: u64 = 0x01;

const NO_ITEM: u32 = u32::MAX;
const MENU_TEXT_UNITS_MAX: usize = 0x1000;
const MENU_DEPTH_MAX: usize = 32;
const RADIO_SPAN_MAX: u32 = 0xFFFF;
const ANSI_REPLACEMENT: u8 = b'?';
const ANSI_MAX: u32 = 0xFF;

mod mf {
    pub const GRAYED: u32 = 0x0001;
    pub const DISABLED: u32 = 0x0002;
    pub const BITMAP: u32 = 0x0004;
    pub const CHECKED: u32 = 0x0008;
    pub const POPUP: u32 = 0x0010;
    pub const MENUBARBREAK: u32 = 0x0020;
    pub const MENUBREAK: u32 = 0x0040;
    pub const HILITE: u32 = 0x0080;
    pub const OWNERDRAW: u32 = 0x0100;
    pub const RADIOCHECK: u32 = 0x0200;
    pub const BYPOSITION: u32 = 0x0400;
    pub const SEPARATOR: u32 = 0x0800;
    pub const DEFAULT: u32 = 0x1000;
    pub const RIGHTORDER: u32 = 0x2000;
    pub const RIGHTJUSTIFY: u32 = 0x4000;

    pub const ENABLE_BITS: u32 = GRAYED | DISABLED;
    pub const TYPE_MASK: u32 =
        BITMAP | MENUBARBREAK | MENUBREAK | OWNERDRAW | RADIOCHECK | SEPARATOR | RIGHTORDER | RIGHTJUSTIFY;
    pub const STATE_MASK: u32 = GRAYED | DISABLED | CHECKED | HILITE | DEFAULT;
    pub const NON_STRING: u32 = BITMAP | OWNERDRAW | SEPARATOR;
    pub const STATE_REPORT_LOW: u32 = 0xFF;
    pub const STATE_REPORT_COUNT_SHIFT: u32 = 8;
}

mod miim {
    pub const STATE: u32 = 0x01;
    pub const ID: u32 = 0x02;
    pub const SUBMENU: u32 = 0x04;
    pub const CHECKMARKS: u32 = 0x08;
    pub const TYPE: u32 = 0x10;
    pub const DATA: u32 = 0x20;
    pub const STRING: u32 = 0x40;
    pub const BITMAP: u32 = 0x80;
    pub const FTYPE: u32 = 0x100;
}

mod mim {
    pub const MAXHEIGHT: u32 = 0x01;
    pub const BACKGROUND: u32 = 0x02;
    pub const HELPID: u32 = 0x04;
    pub const MENUDATA: u32 = 0x08;
    pub const STYLE: u32 = 0x10;
    pub const APPLYTOSUBMENUS: u32 = 0x8000_0000;
    pub const SETTABLE: u32 = MAXHEIGHT | BACKGROUND | HELPID | MENUDATA | STYLE | APPLYTOSUBMENUS;
}

mod gmdi {
    pub const USEDISABLED: u32 = 0x01;
    pub const GOINTOPOPUPS: u32 = 0x02;
}

mod method {
    pub const SET_ITEM_INFO: u64 = 0;
    pub const INSERT_ITEM: u64 = 1;
    pub const CHECK_RADIO_ITEM: u64 = 2;
    pub const DEFAULT_ITEM: u64 = 3;
    pub const ITEM_ID: u64 = 4;
    pub const ITEM_INFO_A: u64 = 5;
    pub const ITEM_INFO_W: u64 = 6;
    pub const STATE: u64 = 7;
    pub const SUB_MENU: u64 = 8;
}

mod mii {
    pub const CB_SIZE: u64 = 0x00;
    pub const MASK: u64 = 0x04;
    pub const TYPE: u64 = 0x08;
    pub const STATE: u64 = 0x0c;
    pub const ID: u64 = 0x10;
    pub const SUBMENU: u64 = 0x18;
    pub const BMP_CHECKED: u64 = 0x20;
    pub const BMP_UNCHECKED: u64 = 0x28;
    pub const ITEM_DATA: u64 = 0x30;
    pub const TYPE_DATA: u64 = 0x38;
    pub const CCH: u64 = 0x40;
    pub const BMP_ITEM: u64 = 0x48;
    pub const SIZE: u32 = 0x50;
    pub const SIZE_V1: u32 = 0x30;
}

mod menuinfo {
    pub const CB_SIZE: u64 = 0x00;
    pub const MASK: u64 = 0x04;
    pub const STYLE: u64 = 0x08;
    pub const MAX_HEIGHT: u64 = 0x0c;
    pub const BACKGROUND: u64 = 0x10;
    pub const HELP_ID: u64 = 0x18;
    pub const MENU_DATA: u64 = 0x20;
    pub const SIZE: u32 = 0x28;
}

mod unicode_string {
    pub const LENGTH: u64 = 0x00;
    pub const BUFFER: u64 = 0x08;
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Item {
    kind: u32,
    state: u32,
    id: u32,
    submenu: u32,
    text: Option<String>,
    item_data: u64,
    bmp_checked: u64,
    bmp_unchecked: u64,
    bmp_item: u64,
}

impl Item {
    fn is_popup(&self) -> bool {
        self.kind & mf::POPUP != 0
    }

    fn has_string(&self) -> bool {
        self.kind & mf::NON_STRING == 0
    }
}

#[derive(Default)]
struct Menu {
    items: Vec<Item>,
    style: u32,
    max_height: u32,
    background: u64,
    help_id: u32,
    menu_data: u64,
}

#[derive(Default)]
struct ItemInfo {
    mask: u32,
    kind: u32,
    state: u32,
    id: u32,
    submenu: u32,
    bmp_checked: u64,
    bmp_unchecked: u64,
    item_data: u64,
    type_data: u64,
    bmp_item: u64,
    text: Option<String>,
}

#[derive(Default)]
pub(super) struct MenuState {
    menus: Vec<(u32, Menu)>,
}

pub(super) type Slot = (u32, usize);

impl MenuState {
    fn create(&mut self, handle: u32) {
        self.menus.push((handle, Menu::default()));
    }

    fn menu(&self, handle: u32) -> Option<&Menu> {
        self.menus.iter().find(|(h, _)| *h == handle).map(|(_, m)| m)
    }

    fn menu_mut(&mut self, handle: u32) -> Option<&mut Menu> {
        self.menus.iter_mut().find(|(h, _)| *h == handle).map(|(_, m)| m)
    }

    pub(super) fn contains(&self, handle: u32) -> bool {
        self.menu(handle).is_some()
    }

    fn item_count(&self, handle: u32) -> u32 {
        self.menu(handle).map_or(NO_ITEM, |m| m.items.len() as u32)
    }

    fn item(&self, (menu, pos): Slot) -> Option<&Item> {
        self.menu(menu).and_then(|m| m.items.get(pos))
    }

    fn item_mut(&mut self, (menu, pos): Slot) -> Option<&mut Item> {
        self.menu_mut(menu).and_then(|m| m.items.get_mut(pos))
    }

    pub(super) fn find(&self, handle: u32, id: u32, flags: u32) -> Option<Slot> {
        self.find_at(handle, id, flags, 0)
    }

    fn find_at(&self, handle: u32, id: u32, flags: u32, depth: usize) -> Option<Slot> {
        let menu = self.menu(handle)?;
        if flags & mf::BYPOSITION != 0 {
            let pos = usize::try_from(id).ok()?;
            return (pos < menu.items.len()).then_some((handle, pos));
        }
        if depth >= MENU_DEPTH_MAX {
            return None;
        }
        for (pos, item) in menu.items.iter().enumerate() {
            if item.is_popup() {
                if let Some(found) = self.find_at(item.submenu, id, flags, depth + 1) {
                    return Some(found);
                }
            } else if item.id == id {
                return Some((handle, pos));
            }
        }
        None
    }

    fn check_item(&mut self, handle: u32, id: u32, flags: u32) -> u32 {
        let Some(slot) = self.find(handle, id, flags) else { return NO_ITEM };
        let Some(item) = self.item_mut(slot) else { return NO_ITEM };
        let previous = item.state & mf::CHECKED;
        item.state = (item.state & !mf::CHECKED) | (flags & mf::CHECKED);
        previous
    }

    fn enable_item(&mut self, handle: u32, id: u32, flags: u32) -> u32 {
        let Some(slot) = self.find(handle, id, flags) else { return NO_ITEM };
        let Some(item) = self.item_mut(slot) else { return NO_ITEM };
        let previous = item.state & mf::ENABLE_BITS;
        item.state = (item.state & !mf::ENABLE_BITS) | (flags & mf::ENABLE_BITS);
        previous
    }

    pub(super) fn state(&self, handle: u32, id: u32, flags: u32) -> u32 {
        let Some(item) = self.find(handle, id, flags).and_then(|slot| self.item(slot)) else {
            return NO_ITEM;
        };
        if item.is_popup() {
            let Some(sub) = self.menu(item.submenu) else { return NO_ITEM };
            let count = sub.items.len() as u32;
            return (count << mf::STATE_REPORT_COUNT_SHIFT)
                | ((item.state | item.kind) & mf::STATE_REPORT_LOW);
        }
        item.kind | item.state
    }

    fn sub_menu(&self, handle: u32, pos: u32) -> u32 {
        self.find(handle, pos, mf::BYPOSITION)
            .and_then(|slot| self.item(slot))
            .filter(|item| item.is_popup())
            .map_or(0, |item| item.submenu)
    }

    fn item_id(&self, handle: u32, pos: u32) -> u32 {
        match self.find(handle, pos, mf::BYPOSITION).and_then(|slot| self.item(slot)) {
            Some(item) if !item.is_popup() => item.id,
            _ => NO_ITEM,
        }
    }

    fn default_item(&self, handle: u32, by_position: bool, flags: u32, depth: usize) -> u32 {
        let Some(menu) = self.menu(handle) else { return NO_ITEM };
        let Some((pos, item)) = menu.items.iter().enumerate().find(|(_, i)| i.state & mf::DEFAULT != 0)
        else {
            return NO_ITEM;
        };
        if flags & gmdi::USEDISABLED == 0 && item.state & mf::DISABLED != 0 {
            return NO_ITEM;
        }
        if flags & gmdi::GOINTOPOPUPS != 0 && item.is_popup() && depth < MENU_DEPTH_MAX {
            let inner = self.default_item(item.submenu, by_position, flags, depth + 1);
            if inner != NO_ITEM {
                return inner;
            }
        }
        if by_position {
            pos as u32
        } else {
            item.id
        }
    }

    fn check_radio(&mut self, handle: u32, first: u32, last: u32, check: u32, flags: u32) -> bool {
        let mut first_menu = None;
        let mut done = false;
        for i in first..=last.min(first.saturating_add(RADIO_SPAN_MAX)) {
            let Some((menu, pos)) = self.find(handle, i, flags) else { continue };
            let anchor = *first_menu.get_or_insert(menu);
            if menu != anchor {
                continue;
            }
            let Some(item) = self.item_mut((menu, pos)) else { continue };
            if item.kind & mf::SEPARATOR != 0 {
                continue;
            }
            if i == check {
                item.kind |= mf::RADIOCHECK;
                item.state |= mf::CHECKED;
                done = true;
            } else {
                item.state &= !mf::CHECKED;
            }
        }
        done
    }

    fn apply(&self, item: &mut Item, info: &ItemInfo) -> bool {
        let mask = info.mask;
        if mask & miim::FTYPE != 0 {
            item.kind = (item.kind & !mf::TYPE_MASK) | (info.kind & mf::TYPE_MASK);
        }
        if mask & miim::TYPE != 0 {
            if mask & (miim::STRING | miim::FTYPE | miim::BITMAP) != 0 {
                return false;
            }
            item.kind = (item.kind & !mf::TYPE_MASK) | (info.kind & mf::TYPE_MASK);
            if item.kind & mf::BITMAP != 0 {
                item.text = None;
                item.bmp_item = info.type_data;
            } else if item.kind & mf::SEPARATOR != 0 {
                item.text = None;
            } else {
                item.text = info.text.clone();
            }
        }
        if mask & miim::STRING != 0 && mask & miim::TYPE == 0 {
            item.text = info.text.clone();
        }
        if mask & miim::STATE != 0 {
            item.state = info.state & mf::STATE_MASK;
        }
        if mask & miim::ID != 0 {
            item.id = info.id;
        }
        if mask & miim::SUBMENU != 0 {
            if info.submenu != 0 {
                if !self.contains(info.submenu) {
                    return false;
                }
                item.submenu = info.submenu;
                item.kind |= mf::POPUP;
            } else {
                item.submenu = 0;
                item.kind &= !mf::POPUP;
            }
        }
        if mask & miim::CHECKMARKS != 0 {
            item.bmp_checked = info.bmp_checked;
            item.bmp_unchecked = info.bmp_unchecked;
        }
        if mask & miim::DATA != 0 {
            item.item_data = info.item_data;
        }
        if mask & miim::BITMAP != 0 {
            item.bmp_item = info.bmp_item;
        }
        true
    }

    fn insert_item(&mut self, handle: u32, pos: u32, flags: u32, info: &ItemInfo) -> bool {
        let Some(len) = self.menu(handle).map(|m| m.items.len()) else { return false };
        let (target, at) = if flags & mf::BYPOSITION != 0 {
            (handle, usize::try_from(pos).map_or(len, |p| p.min(len)))
        } else {
            match self.find(handle, pos, flags) {
                Some(slot) => slot,
                None => (handle, len),
            }
        };
        let mut item = Item::default();
        if !self.apply(&mut item, info) {
            return false;
        }
        let Some(menu) = self.menu_mut(target) else { return false };
        menu.items.insert(at.min(menu.items.len()), item);
        true
    }

    fn set_item_info(&mut self, handle: u32, pos: u32, flags: u32, info: &ItemInfo) -> bool {
        let Some(slot) = self.find(handle, pos, flags) else { return false };
        let Some(mut item) = self.item(slot).cloned() else { return false };
        if !self.apply(&mut item, info) {
            return false;
        }
        if let Some(target) = self.item_mut(slot) {
            *target = item;
        }
        true
    }

    fn remove_item(&mut self, handle: u32, id: u32, flags: u32, destroy_submenu: bool) -> bool {
        let Some((menu, pos)) = self.find(handle, id, flags) else { return false };
        let Some(m) = self.menu_mut(menu) else { return false };
        if pos >= m.items.len() {
            return false;
        }
        let item = m.items.remove(pos);
        if destroy_submenu && item.is_popup() {
            self.destroy(item.submenu);
        }
        true
    }

    fn destroy(&mut self, handle: u32) -> bool {
        let Some(index) = self.menus.iter().position(|(h, _)| *h == handle) else { return false };
        let (_, menu) = self.menus.remove(index);
        for item in menu.items.iter().filter(|i| i.is_popup()) {
            self.destroy(item.submenu);
        }
        true
    }

    fn set_info(&mut self, handle: u32, mask: u32, values: &MenuInfo, depth: usize) {
        let Some(menu) = self.menu_mut(handle) else { return };
        if mask & mim::MAXHEIGHT != 0 {
            menu.max_height = values.max_height;
        }
        if mask & mim::BACKGROUND != 0 {
            menu.background = values.background;
        }
        if mask & mim::HELPID != 0 {
            menu.help_id = values.help_id;
        }
        if mask & mim::MENUDATA != 0 {
            menu.menu_data = values.menu_data;
        }
        if mask & mim::STYLE != 0 {
            menu.style = values.style;
        }
        if mask & mim::APPLYTOSUBMENUS != 0 && depth < MENU_DEPTH_MAX {
            let subs: Vec<u32> =
                menu.items.iter().filter(|i| i.is_popup()).map(|i| i.submenu).collect();
            for sub in subs {
                self.set_info(sub, mask, values, depth + 1);
            }
        }
    }
}

#[derive(Default)]
struct MenuInfo {
    style: u32,
    max_height: u32,
    background: u64,
    help_id: u32,
    menu_data: u64,
}

fn read_units(mem: &dyn Memory, mut at: u64, limit: Option<usize>) -> Result<String> {
    let mut units = Vec::new();
    while units.len() < limit.unwrap_or(MENU_TEXT_UNITS_MAX).min(MENU_TEXT_UNITS_MAX) {
        let unit = mem.read_u16(at)?;
        if limit.is_none() && unit == 0 {
            break;
        }
        units.push(unit);
        at = at.wrapping_add(2);
    }
    Ok(String::from_utf16_lossy(&units))
}

fn read_item_info(mem: &dyn Memory, at: u64, text: u64) -> Result<Option<ItemInfo>> {
    let size = mem.read_u32(at + mii::CB_SIZE)?;
    if size < mii::SIZE_V1 {
        return Ok(None);
    }
    let mut raw = [0u8; mii::SIZE as usize];
    let readable = size.min(mii::SIZE) as usize;
    mem.read(at, &mut raw[..readable])?;
    let u32_at = |off: u64| u32::from_le_bytes(raw[off as usize..off as usize + 4].try_into().unwrap_or([0; 4]));
    let u64_at = |off: u64| u64::from_le_bytes(raw[off as usize..off as usize + 8].try_into().unwrap_or([0; 8]));
    let mut info = ItemInfo {
        mask: u32_at(mii::MASK),
        kind: u32_at(mii::TYPE),
        state: u32_at(mii::STATE),
        id: u32_at(mii::ID),
        submenu: u64_at(mii::SUBMENU) as u32,
        bmp_checked: u64_at(mii::BMP_CHECKED),
        bmp_unchecked: u64_at(mii::BMP_UNCHECKED),
        item_data: u64_at(mii::ITEM_DATA),
        type_data: u64_at(mii::TYPE_DATA),
        bmp_item: u64_at(mii::BMP_ITEM),
        text: None,
    };
    let carries_text = info.mask & miim::STRING != 0
        || (info.mask & miim::TYPE != 0 && info.kind & mf::NON_STRING == 0);
    if carries_text {
        info.text = if text != 0 {
            let len = usize::from(mem.read_u16(text + unicode_string::LENGTH)?) / 2;
            let buffer = mem.read_u64(text + unicode_string::BUFFER)?;
            (buffer != 0).then(|| read_units(mem, buffer, Some(len))).transpose()?
        } else if info.type_data != 0 {
            Some(read_units(mem, info.type_data, None)?)
        } else {
            None
        };
    }
    Ok(Some(info))
}

fn narrow(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| if u32::from(c) <= ANSI_MAX { u32::from(c) as u8 } else { ANSI_REPLACEMENT })
        .collect()
}

fn write_text(mem: &mut dyn Memory, item: &Item, info: u64, ansi: bool) -> Result<()> {
    let buffer = mem.read_u64(info + mii::TYPE_DATA)?;
    let capacity = mem.read_u32(info + mii::CCH)? as usize;
    let text = item.text.as_deref().unwrap_or("");
    let (len, bytes) = if ansi {
        let b = narrow(text);
        (b.len(), b)
    } else {
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut b = Vec::with_capacity(units.len() * 2);
        for u in &units {
            b.extend_from_slice(&u.to_le_bytes());
        }
        (units.len(), b)
    };
    if buffer == 0 {
        return mem.write_u32(info + mii::CCH, len as u32);
    }
    if capacity == 0 {
        return Ok(());
    }
    let unit = if ansi { 1 } else { 2 };
    let copied = len.min(capacity - 1);
    mem.write(buffer, &bytes[..copied * unit])?;
    mem.write(buffer + (copied * unit) as u64, &[0u8; 2][..unit])?;
    mem.write_u32(info + mii::CCH, copied as u32)
}

fn write_item_info(mem: &mut dyn Memory, at: u64, item: &Item, ansi: bool) -> Result<()> {
    let mask = mem.read_u32(at + mii::MASK)?;
    if mask & (miim::TYPE | miim::FTYPE) != 0 {
        mem.write_u32(at + mii::TYPE, item.kind & mf::TYPE_MASK)?;
    }
    if mask & miim::STATE != 0 {
        mem.write_u32(at + mii::STATE, item.state & mf::STATE_MASK)?;
    }
    if mask & miim::ID != 0 {
        mem.write_u32(at + mii::ID, item.id)?;
    }
    if mask & miim::SUBMENU != 0 {
        let sub = if item.is_popup() { u64::from(item.submenu) } else { 0 };
        mem.write_u64(at + mii::SUBMENU, sub)?;
    }
    if mask & miim::CHECKMARKS != 0 {
        mem.write_u64(at + mii::BMP_CHECKED, item.bmp_checked)?;
        mem.write_u64(at + mii::BMP_UNCHECKED, item.bmp_unchecked)?;
    }
    if mask & miim::DATA != 0 {
        mem.write_u64(at + mii::ITEM_DATA, item.item_data)?;
    }
    if mask & miim::BITMAP != 0 {
        mem.write_u64(at + mii::BMP_ITEM, item.bmp_item)?;
    }
    if mask & (miim::STRING | miim::TYPE) != 0 {
        if item.has_string() {
            write_text(mem, item, at, ansi)?;
        } else {
            mem.write_u32(at + mii::CCH, 0)?;
            if mask & miim::TYPE != 0 {
                mem.write_u64(at + mii::TYPE_DATA, item.bmp_item)?;
            }
        }
    }
    Ok(())
}

fn guarded(result: Result<u32>, failure: u32) -> Result<u32> {
    Ok(result.unwrap_or(failure))
}

fn bool_u32(value: bool) -> u32 {
    u32::from(value)
}

pub(super) fn register(os: &mut WinOs) {
    os.set_win32k_handler(NT_USER_CREATE_MENU, nt_user_create_menu);
    os.set_win32k_handler(NT_USER_CREATE_POPUP_MENU, nt_user_create_popup_menu);
    os.set_win32k_handler(NT_USER_DESTROY_MENU, nt_user_destroy_menu);
    os.set_win32k_handler(NT_USER_DELETE_MENU, nt_user_delete_menu);
    os.set_win32k_handler(NT_USER_REMOVE_MENU, nt_user_remove_menu);
    os.set_win32k_handler(NT_USER_SET_MENU, nt_user_set_menu);
    os.set_win32k_handler(NT_USER_CHECK_MENU_ITEM, nt_user_check_menu_item);
    os.set_win32k_handler(NT_USER_ENABLE_MENU_ITEM, nt_user_enable_menu_item);
    os.set_win32k_handler(NT_USER_DRAW_MENU_BAR, nt_user_draw_menu_bar);
    os.set_win32k_handler(NT_USER_THUNKED_MENU_INFO, nt_user_thunked_menu_info);
    os.set_win32k_handler(NT_USER_THUNKED_MENU_ITEM_INFO, nt_user_thunked_menu_item_info);
}

fn nt_user_create_menu(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    let handle = alloc_handle(os);
    os.win32k_state.menus.create(handle);
    Ok(handle)
}

fn nt_user_create_popup_menu(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<u32> {
    let handle = alloc_handle(os);
    os.win32k_state.menus.create(handle);
    Ok(handle)
}

fn nt_user_destroy_menu(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(bool_u32(os.win32k_state.menus.destroy(handle)))
}

fn nt_user_delete_menu(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let id = os.syscall_arg(cpu, mem, 1)? as u32;
    let flags = os.syscall_arg(cpu, mem, 2)? as u32;
    Ok(bool_u32(os.win32k_state.menus.remove_item(handle, id, flags, true)))
}

fn nt_user_remove_menu(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let id = os.syscall_arg(cpu, mem, 1)? as u32;
    let flags = os.syscall_arg(cpu, mem, 2)? as u32;
    Ok(bool_u32(os.win32k_state.menus.remove_item(handle, id, flags, false)))
}

pub(super) fn attach(os: &mut WinOs, hwnd: u32, menu: u32) -> bool {
    if menu != 0 && !os.win32k_state.menus.contains(menu) {
        return false;
    }
    let Some(window) = os.win32k_state.window_mut(hwnd) else { return false };
    if window.style & WS_CHILD != 0 {
        return false;
    }
    window.id = u64::from(menu);
    true
}

fn nt_user_set_menu(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    let menu = os.syscall_arg(cpu, mem, 1)? as u32;
    Ok(bool_u32(attach(os, hwnd, menu)))
}

fn nt_user_check_menu_item(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let id = os.syscall_arg(cpu, mem, 1)? as u32;
    let flags = os.syscall_arg(cpu, mem, 2)? as u32;
    Ok(os.win32k_state.menus.check_item(handle, id, flags))
}

fn nt_user_enable_menu_item(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let id = os.syscall_arg(cpu, mem, 1)? as u32;
    let flags = os.syscall_arg(cpu, mem, 2)? as u32;
    Ok(os.win32k_state.menus.enable_item(handle, id, flags))
}

fn nt_user_draw_menu_bar(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let hwnd = os.syscall_arg(cpu, mem, 0)? as u32;
    Ok(bool_u32(os.win32k_state.window(hwnd).is_some()))
}

fn nt_user_thunked_menu_item_info(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let pos = os.syscall_arg(cpu, mem, 1)? as u32;
    let flags = os.syscall_arg(cpu, mem, 2)? as u32;
    let which = os.syscall_arg(cpu, mem, 3)? & 0xFFFF_FFFF;
    let info = os.syscall_arg(cpu, mem, 4)?;
    let text = os.syscall_arg(cpu, mem, 5)?;
    let failure = match which {
        method::ITEM_ID | method::STATE | method::DEFAULT_ITEM => NO_ITEM,
        _ => 0,
    };
    guarded(thunked_menu_item_info(os, mem, [handle, pos, flags], which, info, text), failure)
}

fn thunked_menu_item_info(
    os: &mut WinOs,
    mem: &mut dyn Memory,
    [handle, pos, flags]: [u32; 3],
    which: u64,
    info: u64,
    text: u64,
) -> Result<u32> {
    let menus = &mut os.win32k_state.menus;
    Ok(match which {
        method::SET_ITEM_INFO | method::INSERT_ITEM => {
            if info == 0 {
                return Ok(0);
            }
            let Some(parsed) = read_item_info(mem, info, text)? else { return Ok(0) };
            let done = if which == method::INSERT_ITEM {
                menus.insert_item(handle, pos, flags, &parsed)
            } else {
                menus.set_item_info(handle, pos, flags, &parsed)
            };
            bool_u32(done)
        }
        method::CHECK_RADIO_ITEM => {
            if info == 0 {
                return Ok(0);
            }
            let check = mem.read_u32(info + mii::MASK)?;
            let last = mem.read_u32(info + mii::CCH)?;
            bool_u32(menus.check_radio(handle, pos, last, check, flags))
        }
        method::DEFAULT_ITEM => menus.default_item(handle, pos != 0, flags, 0),
        method::ITEM_ID => menus.item_id(handle, pos),
        method::STATE => menus.state(handle, pos, flags),
        method::SUB_MENU => menus.sub_menu(handle, pos),
        method::ITEM_INFO_A | method::ITEM_INFO_W => {
            if info == 0 {
                return Ok(0);
            }
            let Some(item) = menus.find(handle, pos, flags).and_then(|s| menus.item(s)).cloned()
            else {
                return Ok(0);
            };
            write_item_info(mem, info, &item, which == method::ITEM_INFO_A)?;
            1
        }
        _ => 0,
    })
}

fn read_menu_info(mem: &dyn Memory, at: u64) -> Result<Option<(u32, MenuInfo)>> {
    if at == 0 || mem.read_u32(at + menuinfo::CB_SIZE)? != menuinfo::SIZE {
        return Ok(None);
    }
    let mask = mem.read_u32(at + menuinfo::MASK)?;
    let values = MenuInfo {
        style: mem.read_u32(at + menuinfo::STYLE)?,
        max_height: mem.read_u32(at + menuinfo::MAX_HEIGHT)?,
        background: mem.read_u64(at + menuinfo::BACKGROUND)?,
        help_id: mem.read_u32(at + menuinfo::HELP_ID)?,
        menu_data: mem.read_u64(at + menuinfo::MENU_DATA)?,
    };
    Ok(Some((mask, values)))
}

fn nt_user_thunked_menu_info(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let handle = os.syscall_arg(cpu, mem, 0)? as u32;
    let at = os.syscall_arg(cpu, mem, 1)?;
    guarded(set_menu_info(os, mem, handle, at), 0)
}

fn set_menu_info(os: &mut WinOs, mem: &mut dyn Memory, handle: u32, at: u64) -> Result<u32> {
    let Some((mask, values)) = read_menu_info(mem, at)? else { return Ok(0) };
    if mask & !mim::SETTABLE != 0 || !os.win32k_state.menus.contains(handle) {
        return Ok(0);
    }
    os.win32k_state.menus.set_info(handle, mask, &values, 0);
    Ok(1)
}

pub(super) fn item_count(os: &WinOs, handle: u64) -> u32 {
    os.win32k_state.menus.item_count(handle as u32)
}

pub(super) fn get_menu_info(os: &WinOs, mem: &mut dyn Memory, handle: u64, at: u64) -> u32 {
    read_back_menu_info(os, mem, handle as u32, at).unwrap_or(0)
}

fn read_back_menu_info(os: &WinOs, mem: &mut dyn Memory, handle: u32, at: u64) -> Result<u32> {
    let Some(menu) = os.win32k_state.menus.menu(handle) else { return Ok(0) };
    if at == 0 || mem.read_u32(at + menuinfo::CB_SIZE)? != menuinfo::SIZE {
        return Ok(0);
    }
    let mask = mem.read_u32(at + menuinfo::MASK)?;
    if mask & mim::BACKGROUND != 0 {
        mem.write_u64(at + menuinfo::BACKGROUND, menu.background)?;
    }
    if mask & mim::HELPID != 0 {
        mem.write_u32(at + menuinfo::HELP_ID, menu.help_id)?;
    }
    if mask & mim::MAXHEIGHT != 0 {
        mem.write_u32(at + menuinfo::MAX_HEIGHT, menu.max_height)?;
    }
    if mask & mim::MENUDATA != 0 {
        mem.write_u64(at + menuinfo::MENU_DATA, menu.menu_data)?;
    }
    if mask & mim::STYLE != 0 {
        mem.write_u32(at + menuinfo::STYLE, menu.style)?;
    }
    Ok(1)
}

#[cfg(test)]
pub(super) fn test_menu_with_command(os: &mut WinOs, id: u32, state: u32) -> u32 {
    let handle = alloc_handle(os);
    let menus = &mut os.win32k_state.menus;
    menus.create(handle);
    let info = ItemInfo { mask: miim::ID | miim::STATE, id, state, ..ItemInfo::default() };
    menus.insert_item(handle, NO_ITEM, mf::BYPOSITION, &info);
    handle
}

#[cfg(test)]
mod tests;
