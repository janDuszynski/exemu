use super::*;
use crate::win32k::call_hwnd_param;
use crate::win32k::rig::{Rig, SCRATCH};
use crate::win32k::{nt_user_call_hwnd_param, nt_user_set_window_pos, system_metric};
use crate::win32k::menu::{
    mii, method, miim, nt_user_create_menu, nt_user_create_popup_menu, nt_user_draw_menu_bar, nt_user_set_menu,
    nt_user_thunked_menu_item_info, NO_ITEM,
};

const INFO: u64 = SCRATCH;
const TEXT: u64 = SCRATCH + 0x200;
const OUT: u64 = SCRATCH + 0x400;
const PARAM: u64 = SCRATCH + 0x500;
const AREA: u64 = SCRATCH + 0x600;
const SM_CYMENU: u32 = 15;
const GLYPH_WIDTH: i32 = 6;
const SPACED_FOUR: i32 = 4 * GLYPH_WIDTH + ITEM_SPACING;
const ROW: i32 = 18;
const SWP_NOMOVE: u64 = 0x0002;
const MENU_INFO_CB_SIZE: u32 = 0x30;

trait BarRig {
    fn bar_menu(&mut self) -> u32;
    fn add(&mut self, menu: u32, kind: u32, text: &str);
    fn attach(&mut self, hwnd: u32, menu: u32) -> u32;
    fn item_rect(&mut self, hwnd: u32, menu: u32, pos: u32) -> Option<[i32; 4]>;
    fn bar_info(&mut self, hwnd: u32, object: i32, item: i32) -> Option<([i32; 4], u32, u32)>;
    fn client_rect(&mut self, hwnd: u32) -> [i32; 4];
    fn window_rect(&mut self, hwnd: u32) -> [i32; 4];
    fn resize(&mut self, hwnd: u32, cx: i32, cy: i32);
    fn place(&mut self, hwnd: u32, rect: [i32; 4]);
}

fn read_rect(rig: &Rig, at: u64) -> [i32; 4] {
    let mut r = [0i32; 4];
    for (i, v) in r.iter_mut().enumerate() {
        *v = rig.mem.read_u32(at + i as u64 * 4).unwrap() as i32;
    }
    r
}

impl BarRig for Rig {
    fn bar_menu(&mut self) -> u32 {
        self.call(nt_user_create_menu, &[])
    }

    fn add(&mut self, menu: u32, kind: u32, text: &str) {
        self.mem.write(INFO, &[0u8; mii::SIZE as usize]).unwrap();
        self.mem.write_u32(INFO + mii::CB_SIZE, mii::SIZE).unwrap();
        let sep = kind & mf::SEPARATOR != 0;
        let mask = if sep { miim::FTYPE } else { miim::FTYPE | miim::STRING };
        self.mem.write_u32(INFO + mii::MASK, mask).unwrap();
        self.mem.write_u32(INFO + mii::TYPE, kind).unwrap();
        if !sep {
            self.wide(TEXT, text);
            self.mem.write_u64(INFO + mii::TYPE_DATA, TEXT).unwrap();
        }
        let done = self.call(
            nt_user_thunked_menu_item_info,
            &[u64::from(menu), u64::from(NO_ITEM), u64::from(mf::BYPOSITION), method::INSERT_ITEM, INFO, 0],
        );
        assert_eq!(done, 1);
    }

    fn attach(&mut self, hwnd: u32, menu: u32) -> u32 {
        self.call(nt_user_set_menu, &[u64::from(hwnd), u64::from(menu)])
    }

    fn item_rect(&mut self, hwnd: u32, menu: u32, pos: u32) -> Option<[i32; 4]> {
        self.mem.write(OUT, &[0xEE; 16]).unwrap();
        let ok = self.call(nt_user_get_menu_item_rect, &[u64::from(hwnd), u64::from(menu), u64::from(pos), OUT]);
        (ok == 1).then(|| read_rect(self, OUT))
    }

    fn bar_info(&mut self, hwnd: u32, object: i32, item: i32) -> Option<([i32; 4], u32, u32)> {
        self.mem.write(INFO, &[0u8; 0x30]).unwrap();
        self.mem.write_u32(INFO, MENU_INFO_CB_SIZE).unwrap();
        let ok = self.call(
            nt_user_get_menu_bar_info,
            &[u64::from(hwnd), u64::from(object as u32), u64::from(item as u32), INFO],
        );
        (ok == 1).then(|| {
            let hmenu = self.mem.read_u64(INFO + menubarinfo::HMENU).unwrap() as u32;
            let flags = self.mem.read_u32(INFO + menubarinfo::FLAGS).unwrap();
            (read_rect(self, INFO + menubarinfo::RC_BAR), hmenu, flags)
        })
    }

    fn client_rect(&mut self, hwnd: u32) -> [i32; 4] {
        self.mem.write_u64(PARAM, OUT).unwrap();
        let ok = self.call(nt_user_call_hwnd_param, &[u64::from(hwnd), PARAM, call_hwnd_param::GET_CLIENT_RECT]);
        assert_eq!(ok, 1);
        read_rect(self, OUT)
    }

    fn window_rect(&mut self, hwnd: u32) -> [i32; 4] {
        self.mem.write_u64(PARAM, OUT).unwrap();
        let ok = self.call(nt_user_call_hwnd_param, &[u64::from(hwnd), PARAM, call_hwnd_param::GET_WINDOW_RECT]);
        assert_eq!(ok, 1);
        read_rect(self, OUT)
    }

    fn resize(&mut self, hwnd: u32, cx: i32, cy: i32) {
        let done = self.call(
            nt_user_set_window_pos,
            &[u64::from(hwnd), 0, 0, 0, cx as u64, cy as u64, SWP_NOMOVE],
        );
        assert_eq!(done, 1);
    }

    fn place(&mut self, hwnd: u32, rect: [i32; 4]) {
        self.os.win32k_state.window_mut(hwnd).unwrap().rect = rect;
    }
}

fn four_letter_bar(rig: &mut Rig, count: usize) -> u32 {
    let menu = rig.bar_menu();
    for i in 0..count {
        rig.add(menu, 0, &format!("It{}m", i % 10));
    }
    menu
}

fn laid_out(rig: &Rig, menu: u32, width: i32) -> Bar {
    lay_out(&rig.os, rig.os.win32k_state.menus.menu(menu).unwrap(), width)
}

#[test]
fn items_sit_left_to_right_each_as_wide_as_its_text_plus_the_item_spacing() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 3);
    let bar = laid_out(&rig, menu, 400);
    assert_eq!(bar.items[0], [0, 0, SPACED_FOUR, ROW]);
    assert_eq!(bar.items[1], [SPACED_FOUR, 0, 2 * SPACED_FOUR, ROW]);
    assert_eq!(bar.items[2], [2 * SPACED_FOUR, 0, 3 * SPACED_FOUR, ROW]);
    assert_eq!(bar.height, ROW);
    assert_eq!(bar.band(), ROW + 1, "the divider line under the bar belongs to the non-client band");
}

#[test]
fn an_accelerator_ampersand_takes_no_width_but_a_doubled_one_is_a_literal() {
    let mut rig = Rig::new();
    let menu = rig.bar_menu();
    rig.add(menu, 0, "&File");
    rig.add(menu, 0, "A&&B");
    let bar = laid_out(&rig, menu, 400);
    assert_eq!(bar.items[0][2] - bar.items[0][0], 4 * GLYPH_WIDTH + ITEM_SPACING, "File, not &File");
    assert_eq!(bar.items[1][2] - bar.items[1][0], 3 * GLYPH_WIDTH + ITEM_SPACING, "A&B");
}

#[test]
fn the_single_row_band_is_exactly_what_get_system_metrics_calls_sm_cymenu() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 2);
    let bar = laid_out(&rig, menu, 400);
    assert_eq!(system_metric(SM_CYMENU), menu_height());
    assert_eq!(bar.band() as u32, system_metric(SM_CYMENU));
    let empty = rig.bar_menu();
    assert_eq!(laid_out(&rig, empty, 400).band() as u32, system_metric(SM_CYMENU), "an empty bar keeps one row");
}

#[test]
fn items_wrap_to_a_second_row_when_the_bar_is_too_narrow() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 3);
    let bar = laid_out(&rig, menu, 2 * SPACED_FOUR + 5);
    assert_eq!(bar.items[0], [0, 0, SPACED_FOUR, ROW]);
    assert_eq!(bar.items[1], [SPACED_FOUR, 0, 2 * SPACED_FOUR, ROW]);
    assert_eq!(bar.items[2], [0, ROW, SPACED_FOUR, 2 * ROW], "the third starts the second row");
    assert_eq!(bar.height, 2 * ROW);
}

#[test]
fn a_lone_item_wider_than_the_bar_is_clamped_to_it() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 1);
    let bar = laid_out(&rig, menu, 20);
    assert_eq!(bar.items[0], [0, 0, 20, ROW]);
    assert_eq!(bar.height, ROW);
}

#[test]
fn a_menu_break_starts_a_new_row_even_with_room_left() {
    let mut rig = Rig::new();
    let menu = rig.bar_menu();
    rig.add(menu, 0, "Item");
    rig.add(menu, mf::MENUBARBREAK, "Item");
    let bar = laid_out(&rig, menu, 400);
    assert_eq!(bar.items[1][0], 0);
    assert_eq!(bar.items[1][1], ROW);
}

#[test]
fn right_justified_items_are_flushed_against_the_right_edge() {
    let mut rig = Rig::new();
    let menu = rig.bar_menu();
    rig.add(menu, 0, "Item");
    rig.add(menu, mf::RIGHTJUSTIFY, "Item");
    rig.add(menu, 0, "Item");
    let bar = laid_out(&rig, menu, 300);
    assert_eq!(bar.items[0][0], 0, "before the help item nothing moves");
    assert_eq!(bar.items[2], [300 - SPACED_FOUR, 0, 300, ROW], "the last item touches the right edge");
    assert_eq!(bar.items[1], [300 - 2 * SPACED_FOUR, 0, 300 - SPACED_FOUR, ROW], "and the help item abuts it");
}

#[test]
fn a_separator_takes_no_width_and_does_not_shorten_the_row() {
    let mut rig = Rig::new();
    let menu = rig.bar_menu();
    rig.add(menu, 0, "Item");
    rig.add(menu, mf::SEPARATOR, "");
    rig.add(menu, 0, "Item");
    let bar = laid_out(&rig, menu, 400);
    assert_eq!(bar.items[1][2] - bar.items[1][0], 0);
    assert_eq!(bar.items[2][0], SPACED_FOUR);
    assert_eq!(bar.height, ROW);
}

#[test]
fn get_menu_item_rect_answers_in_screen_coordinates_for_an_attached_bar() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 3);
    let win = rig.window(0);
    rig.place(win, [30, 40, 400, 200]);
    assert_eq!(rig.attach(win, menu), 1);
    assert_eq!(rig.item_rect(win, menu, 0), Some([30, 40, 30 + SPACED_FOUR, 40 + ROW]));
    assert_eq!(rig.item_rect(win, menu, 2), Some([30 + 2 * SPACED_FOUR, 40, 30 + 3 * SPACED_FOUR, 40 + ROW]));
    assert_eq!(rig.item_rect(0, menu, 1), Some([30 + SPACED_FOUR, 40, 30 + 2 * SPACED_FOUR, 40 + ROW]), "no hwnd: the menu's own window");
    assert_eq!(rig.item_rect(win, menu, 3), None, "past the last item");
    assert_eq!(rig.item_rect(win, menu, u32::MAX), None);
    assert_eq!(rig.item_rect(win, 0xBEEF, 0), None, "not a menu");
    assert_eq!(rig.item_rect(0xDEAD, menu, 0), None, "not a window");
    let rejected = rig.call(nt_user_get_menu_item_rect, &[u64::from(win), u64::from(menu), 0, 0]);
    assert_eq!(rejected, 0, "a null RECT is refused, not dereferenced");
}

#[test]
fn a_popup_that_is_not_showing_has_no_item_rectangles() {
    let mut rig = Rig::new();
    let bar = four_letter_bar(&mut rig, 1);
    let popup = rig.call(nt_user_create_popup_menu, &[]);
    rig.add(popup, 0, "Item");
    let win = rig.window(0);
    assert_eq!(rig.attach(win, bar), 1);
    assert_eq!(rig.item_rect(win, popup, 0), None, "a menu that is not the window's bar");
    assert_eq!(rig.item_rect(0, popup, 0), None, "a menu with no window at all");
    assert_eq!(rig.item_rect(0, bar, 0).is_some(), true);
}

#[test]
fn get_menu_bar_info_reports_the_bar_and_each_item_in_screen_coordinates() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 2);
    let win = rig.window(0);
    rig.place(win, [30, 40, 400, 200]);
    rig.attach(win, menu);
    let (bar, hmenu, flags) = rig.bar_info(win, OBJID_MENU, 0).expect("OBJID_MENU item 0 is the bar");
    assert_eq!(bar, [30, 40, 430, 40 + ROW]);
    assert_eq!((hmenu, flags), (menu, 0));
    let (first, _, _) = rig.bar_info(win, OBJID_MENU, 1).unwrap();
    assert_eq!(first, rig.item_rect(win, menu, 0).unwrap(), "item 1 is the first item");
    let (second, _, _) = rig.bar_info(win, OBJID_MENU, 2).unwrap();
    assert_eq!(second, rig.item_rect(win, menu, 1).unwrap());
    assert!(rig.bar_info(win, OBJID_MENU, 3).is_none(), "only two items");
    assert!(rig.bar_info(win, OBJID_MENU, -1).is_none());
    assert!(rig.bar_info(win, 0, 0).is_none(), "OBJID_WINDOW is not the menu");
    assert!(rig.bar_info(win, -1, 0).is_none(), "the system menu is not modelled");
    let bare = rig.window(0);
    assert!(rig.bar_info(bare, OBJID_MENU, 0).is_none(), "a window with no menu");
    rig.mem.write_u32(INFO, 0x20).unwrap();
    let wrong_size = rig.call(nt_user_get_menu_bar_info, &[u64::from(win), OBJID_MENU as u32 as u64, 0, INFO]);
    assert_eq!(wrong_size, 0, "cbSize must be sizeof(MENUBARINFO)");
}

#[test]
fn attaching_a_menu_takes_its_band_off_the_client_height_and_adds_it_to_the_window() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 2);
    let win = rig.window(0);
    rig.place(win, [30, 40, 400, 200]);
    assert_eq!(rig.client_rect(win), [0, 0, 400, 200]);
    assert_eq!(rig.window_rect(win), [30, 40, 430, 240]);
    rig.attach(win, menu);
    let band = system_metric(SM_CYMENU) as i32;
    assert_eq!(rig.client_rect(win), [0, 0, 400, 200 - band], "the client lost the menu band");
    assert_eq!(rig.window_rect(win), [30, 40, 430, 240], "the window itself did not move or grow");
    rig.attach(win, 0);
    assert_eq!(rig.client_rect(win), [0, 0, 400, 200], "detaching gives it back");
}

#[test]
fn editing_the_attached_menu_or_narrowing_the_window_re_flows_the_bar() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 2);
    let win = rig.window(0);
    rig.place(win, [0, 0, 3 * SPACED_FOUR, 200]);
    rig.attach(win, menu);
    assert_eq!(rig.client_rect(win)[3], 200 - (ROW + 1));
    rig.add(menu, 0, "Item");
    rig.add(menu, 0, "Item");
    assert_eq!(rig.client_rect(win)[3], 200 - (2 * ROW + 1), "four items no longer fit one row");
    rig.resize(win, 4 * SPACED_FOUR, 200);
    assert_eq!(rig.client_rect(win)[3], 200 - (ROW + 1), "widening the window joins the rows again");
    rig.resize(win, SPACED_FOUR, 200);
    assert_eq!(rig.client_rect(win)[3], 200 - (4 * ROW + 1), "narrowing it stacks every item");
    let before = rig.os.win32k_state.window(win).unwrap().menu_bar;
    assert_eq!(rig.call(nt_user_draw_menu_bar, &[u64::from(win)]), 1);
    assert_eq!(rig.os.win32k_state.window(win).unwrap().menu_bar, before, "DrawMenuBar is idempotent");
}

#[test]
fn a_child_window_keeps_its_full_height_whatever_its_id() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 1);
    let child = rig.window(WS_CHILD);
    rig.place(child, [0, 0, 100, 50]);
    rig.os.win32k_state.window_mut(child).unwrap().id = u64::from(menu);
    rig.resize(child, 100, 50);
    assert_eq!(rig.client_rect(child), [0, 0, 100, 50]);
}

#[test]
fn calc_menu_bar_returns_the_band_for_the_width_it_is_given() {
    let mut rig = Rig::new();
    let menu = four_letter_bar(&mut rig, 3);
    let win = rig.window(0);
    rig.place(win, [0, 0, 400, 200]);
    let calc = |rig: &mut Rig, left: u64, right: u64, area: u64| {
        rig.call(nt_user_calc_menu_bar, &[u64::from(win), left, right, 0, area])
    };
    assert_eq!(calc(&mut rig, 0, 0, 0), 0, "no menu attached yet");
    rig.attach(win, menu);
    assert_eq!(calc(&mut rig, 0, 0, 0), ROW as u32 + 1);
    let narrow = 2 * SPACED_FOUR as u64 + 5;
    assert_eq!(calc(&mut rig, 0, 400 - narrow, 0), 2 * ROW as u32 + 1, "margins narrow the bar");
    for (i, v) in [0i32, 0, 300, 20].iter().enumerate() {
        rig.mem.write_u32(AREA + i as u64 * 4, *v as u32).unwrap();
    }
    assert_eq!(calc(&mut rig, 0, 0, AREA), ROW as u32 + 1, "a 300 wide rect holds three items");
    assert_eq!(calc(&mut rig, 250, 0, AREA), 3 * ROW as u32 + 1, "a 50 wide bar takes one item per row");
}
