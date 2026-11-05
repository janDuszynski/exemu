use super::*;
use crate::syscall::SyscallHandler;
use exemu_core::{Perm, Reg};
use exemu_memory::VirtualMemory;

const SCRATCH: u64 = 0x2_0000;
const INFO: u64 = SCRATCH;
const TEXT: u64 = SCRATCH + 0x200;
const COUNTED: u64 = SCRATCH + 0x100;
const COUNTED_TEXT: u64 = SCRATCH + 0x800;
const OUT: u64 = SCRATCH + 0x400;
const STACK: u64 = SCRATCH + 0x3000;
const REGISTER_ARGS: usize = 4;
const STACK_ARGS_OFFSET: u64 = 0x28;

struct Rig {
    os: WinOs,
    mem: VirtualMemory,
}

impl Rig {
    fn new() -> Rig {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(SCRATCH, 0x4000, Perm::RW, "scratch").unwrap();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.set_syscall_guest_rsp_for_test(STACK);
        Rig { os, mem }
    }

    fn call(&mut self, handler: SyscallHandler, args: &[u64]) -> u32 {
        let mut cpu = CpuState::default();
        cpu.set_rsp(STACK);
        let regs = [Reg::R10, Reg::Rdx, Reg::R8, Reg::R9];
        for (reg, value) in regs.iter().zip(args) {
            cpu.set_reg(*reg, *value);
        }
        for (i, value) in args.iter().enumerate().skip(REGISTER_ARGS) {
            let at = STACK + STACK_ARGS_OFFSET + (i - REGISTER_ARGS) as u64 * 8;
            self.mem.write_u64(at, *value).unwrap();
        }
        handler(&mut self.os, &mut cpu, &mut self.mem).unwrap()
    }

    fn menu(&mut self) -> u32 {
        self.call(nt_user_create_menu, &[])
    }

    fn popup(&mut self) -> u32 {
        self.call(nt_user_create_popup_menu, &[])
    }

    fn wide(&mut self, at: u64, text: &str) {
        let mut bytes = Vec::new();
        for u in text.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        self.mem.write(at, &bytes).unwrap();
    }

    fn put_info(&mut self, mask: u32, kind: u32, state: u32, id: u32, sub: u32, text: Option<&str>) {
        self.mem.write(INFO, &[0u8; mii::SIZE as usize]).unwrap();
        self.mem.write_u32(INFO + mii::CB_SIZE, mii::SIZE).unwrap();
        self.mem.write_u32(INFO + mii::MASK, mask).unwrap();
        self.mem.write_u32(INFO + mii::TYPE, kind).unwrap();
        self.mem.write_u32(INFO + mii::STATE, state).unwrap();
        self.mem.write_u32(INFO + mii::ID, id).unwrap();
        self.mem.write_u64(INFO + mii::SUBMENU, u64::from(sub)).unwrap();
        if let Some(t) = text {
            self.wide(TEXT, t);
            self.mem.write_u64(INFO + mii::TYPE_DATA, TEXT).unwrap();
        }
    }

    fn thunked(&mut self, menu: u32, pos: u32, flags: u32, which: u64) -> u32 {
        self.call(
            nt_user_thunked_menu_item_info,
            &[u64::from(menu), u64::from(pos), u64::from(flags), which, INFO, 0],
        )
    }

    fn append(&mut self, menu: u32, id: u32, state: u32, text: &str) -> u32 {
        let mask = miim::ID | miim::STATE | miim::STRING | miim::FTYPE;
        self.put_info(mask, 0, state, id, 0, Some(text));
        self.thunked(menu, NO_ITEM, mf::BYPOSITION, method::INSERT_ITEM)
    }

    fn append_popup(&mut self, menu: u32, sub: u32, text: &str) -> u32 {
        let mask = miim::SUBMENU | miim::STRING | miim::FTYPE;
        self.put_info(mask, 0, 0, 0, sub, Some(text));
        self.thunked(menu, NO_ITEM, mf::BYPOSITION, method::INSERT_ITEM)
    }

    fn window(&mut self, style: u32) -> u32 {
        let hwnd = alloc_handle(&mut self.os);
        self.os.win32k_state.windows.push((
            hwnd,
            super::super::Window {
                class_atom: 0,
                class_name: "C".into(),
                title: String::new(),
                rect: [0, 0, 100, 100],
                style,
                ex_style: 0,
                parent: 0,
                shown: true,
                wndproc: 0,
                needs_paint: false,
                surface: None,
                extra: vec![0u8; 16],
                user_data: 0,
                id: 0,
                instance: 0,
                props: Vec::new(),
                dialog_info: 0,
                dialog_cancelled: false,
            },
        ));
        hwnd
    }

    fn check(&mut self, menu: u32, id: u32, flags: u32) -> u32 {
        self.call(nt_user_check_menu_item, &[u64::from(menu), u64::from(id), u64::from(flags)])
    }

    fn enable(&mut self, menu: u32, id: u32, flags: u32) -> u32 {
        self.call(nt_user_enable_menu_item, &[u64::from(menu), u64::from(id), u64::from(flags)])
    }

    fn state(&mut self, menu: u32, id: u32, flags: u32) -> u32 {
        self.thunked(menu, id, flags, method::STATE)
    }

    fn items(&self, menu: u32) -> Vec<Item> {
        self.os.win32k_state.menus.menu(menu).unwrap().items.clone()
    }
}

#[test]
fn a_new_menu_is_empty_and_each_handle_is_distinct() {
    let mut rig = Rig::new();
    let a = rig.menu();
    let b = rig.popup();
    assert!(a != 0 && b != 0 && a != b);
    assert_eq!(item_count(&rig.os, u64::from(a)), 0);
    assert_eq!(item_count(&rig.os, u64::from(b)), 0);
    assert_eq!(item_count(&rig.os, 0xDEAD), NO_ITEM, "an unknown handle is -1, as GetMenuItemCount");
}

#[test]
fn check_and_enable_return_the_previous_state_and_minus_one_for_unknown_items() {
    let mut rig = Rig::new();
    let m = rig.menu();
    assert_eq!(rig.append(m, 100, 0, "One"), 1);
    assert_eq!(rig.append(m, 101, mf::CHECKED, "Two"), 1);

    assert_eq!(rig.check(m, 100, mf::CHECKED), 0, "was unchecked");
    assert_eq!(rig.check(m, 100, mf::CHECKED), mf::CHECKED, "now reports it was checked");
    assert_eq!(rig.check(m, 100, 0), mf::CHECKED, "unchecking reports the old check");
    assert_eq!(
        rig.check(m, 1, mf::BYPOSITION | mf::CHECKED),
        mf::CHECKED,
        "by position, item 1 started checked"
    );
    assert_eq!(rig.check(m, 999, 0), NO_ITEM, "no such id");
    assert_eq!(rig.check(m, 5, mf::BYPOSITION), NO_ITEM, "no such position");
    assert_eq!(rig.check(0xDEAD, 100, 0), NO_ITEM, "no such menu");

    assert_eq!(rig.enable(m, 100, mf::GRAYED), 0, "was enabled");
    assert_eq!(rig.enable(m, 100, mf::DISABLED), mf::GRAYED, "gray reported, now disabled");
    assert_eq!(rig.state(m, 100, 0) & (mf::GRAYED | mf::DISABLED), mf::DISABLED);
    assert_eq!(rig.enable(m, 100, 0), mf::DISABLED, "re-enabling reports disabled");
    assert_eq!(rig.state(m, 100, 0) & (mf::GRAYED | mf::DISABLED), 0);
    assert_eq!(rig.enable(m, 999, 0), NO_ITEM);
}

#[test]
fn get_menu_state_id_and_submenu_read_back_the_items() {
    let mut rig = Rig::new();
    let bar = rig.menu();
    let file = rig.popup();
    rig.append(file, 10, 0, "New");
    rig.append(file, 11, mf::GRAYED, "Open");
    assert_eq!(rig.append_popup(bar, file, "File"), 1);
    rig.append(bar, 20, mf::CHECKED, "Help");

    assert_eq!(item_count(&rig.os, u64::from(bar)), 2);
    assert_eq!(rig.thunked(bar, 0, mf::BYPOSITION, method::SUB_MENU), file);
    assert_eq!(rig.thunked(bar, 1, mf::BYPOSITION, method::SUB_MENU), 0, "a plain item has no submenu");
    assert_eq!(rig.thunked(bar, 9, mf::BYPOSITION, method::SUB_MENU), 0);
    assert_eq!(rig.thunked(bar, 1, mf::BYPOSITION, method::ITEM_ID), 20);
    assert_eq!(rig.thunked(bar, 0, mf::BYPOSITION, method::ITEM_ID), NO_ITEM, "a popup has no command id");

    assert_eq!(rig.state(file, 11, 0), mf::GRAYED);
    assert_eq!(rig.state(bar, 20, 0), mf::CHECKED);
    assert_eq!(rig.state(bar, 11, 0), mf::GRAYED, "an id is found in a submenu from the bar");
    assert_eq!(
        rig.state(bar, 0, mf::BYPOSITION),
        (2 << 8) | mf::POPUP,
        "a popup reports its item count in the high byte and MF_POPUP below it"
    );
    assert_eq!(rig.state(bar, 777, 0), NO_ITEM);
}

#[test]
fn menu_item_info_round_trips_strings_ids_and_data() {
    let mut rig = Rig::new();
    let m = rig.menu();
    let mask = miim::ID | miim::STATE | miim::STRING | miim::FTYPE | miim::DATA | miim::CHECKMARKS;
    rig.put_info(mask, mf::RADIOCHECK, mf::CHECKED, 42, 0, Some("Hello"));
    rig.mem.write_u64(INFO + mii::ITEM_DATA, 0xFEED).unwrap();
    rig.mem.write_u64(INFO + mii::BMP_CHECKED, 7).unwrap();
    assert_eq!(rig.thunked(m, NO_ITEM, mf::BYPOSITION, method::INSERT_ITEM), 1);

    rig.mem.write(INFO, &[0u8; mii::SIZE as usize]).unwrap();
    rig.mem.write_u32(INFO + mii::CB_SIZE, mii::SIZE).unwrap();
    rig.mem.write_u32(INFO + mii::MASK, mask).unwrap();
    rig.mem.write_u64(INFO + mii::TYPE_DATA, OUT).unwrap();
    rig.mem.write_u32(INFO + mii::CCH, 16).unwrap();
    assert_eq!(rig.thunked(m, 42, 0, method::ITEM_INFO_W), 1);
    assert_eq!(rig.mem.read_u32(INFO + mii::ID).unwrap(), 42);
    assert_eq!(rig.mem.read_u32(INFO + mii::STATE).unwrap(), mf::CHECKED);
    assert_eq!(rig.mem.read_u32(INFO + mii::TYPE).unwrap(), mf::RADIOCHECK);
    assert_eq!(rig.mem.read_u64(INFO + mii::ITEM_DATA).unwrap(), 0xFEED);
    assert_eq!(rig.mem.read_u64(INFO + mii::BMP_CHECKED).unwrap(), 7);
    assert_eq!(rig.mem.read_u32(INFO + mii::CCH).unwrap(), 5);
    assert_eq!(read_units(&rig.mem, OUT, None).unwrap(), "Hello");

    rig.mem.write_u32(INFO + mii::CCH, 3).unwrap();
    assert_eq!(rig.thunked(m, 42, 0, method::ITEM_INFO_W), 1);
    assert_eq!(read_units(&rig.mem, OUT, None).unwrap(), "He", "truncated to cch-1 plus the NUL");
    assert_eq!(rig.mem.read_u32(INFO + mii::CCH).unwrap(), 2);

    rig.mem.write_u64(INFO + mii::TYPE_DATA, 0).unwrap();
    assert_eq!(rig.thunked(m, 42, 0, method::ITEM_INFO_W), 1);
    assert_eq!(rig.mem.read_u32(INFO + mii::CCH).unwrap(), 5, "no buffer asks for the length only");

    rig.mem.write_u64(INFO + mii::TYPE_DATA, OUT).unwrap();
    rig.mem.write_u32(INFO + mii::CCH, 16).unwrap();
    assert_eq!(rig.thunked(m, 42, 0, method::ITEM_INFO_A), 1);
    let mut narrow = [0u8; 6];
    rig.mem.read(OUT, &mut narrow).unwrap();
    assert_eq!(&narrow, b"Hello\0", "the A flavour writes bytes");

    assert_eq!(rig.thunked(m, 99, 0, method::ITEM_INFO_W), 0, "an unknown item fails");
}

#[test]
fn set_item_info_modifies_in_place_and_a_counted_string_wins() {
    let mut rig = Rig::new();
    let m = rig.menu();
    rig.append(m, 5, 0, "Old");
    rig.put_info(miim::STRING | miim::ID, 0, 0, 6, 0, None);
    rig.wide(COUNTED_TEXT, "Newer!");
    rig.mem.write_u16(COUNTED + unicode_string::LENGTH, 6).unwrap();
    rig.mem.write_u64(COUNTED + unicode_string::BUFFER, COUNTED_TEXT).unwrap();
    let ok = rig.call(
        nt_user_thunked_menu_item_info,
        &[u64::from(m), 5, 0, method::SET_ITEM_INFO, INFO, COUNTED],
    );
    assert_eq!(ok, 1);
    assert_eq!(item_count(&rig.os, u64::from(m)), 1, "modified, not appended");
    let item = rig.items(m)[0].clone();
    assert_eq!(item.text.as_deref(), Some("New"), "the UNICODE_STRING length bounds the text");
    assert_eq!(item.id, 6);
    assert_eq!(rig.thunked(m, 5, 0, method::SET_ITEM_INFO), 0, "the old id is gone");
}

#[test]
fn insert_honours_position_and_falls_back_to_appending() {
    let mut rig = Rig::new();
    let m = rig.menu();
    rig.append(m, 1, 0, "a");
    rig.append(m, 3, 0, "c");
    rig.put_info(miim::ID | miim::STRING, 0, 0, 2, 0, Some("b"));
    assert_eq!(rig.thunked(m, 1, mf::BYPOSITION, method::INSERT_ITEM), 1);
    rig.put_info(miim::ID | miim::STRING, 0, 0, 4, 0, Some("d"));
    assert_eq!(rig.thunked(m, 99, 0, method::INSERT_ITEM), 1, "by an id nobody has: append");
    rig.put_info(miim::ID | miim::STRING, 0, 0, 0, 0, Some("before3"));
    assert_eq!(rig.thunked(m, 3, 0, method::INSERT_ITEM), 1, "by id: before the item that has it");
    let ids: Vec<u32> = rig.items(m).iter().map(|i| i.id).collect();
    assert_eq!(ids, [1, 2, 0, 3, 4]);
}

#[test]
fn a_submenu_that_is_not_a_menu_is_refused_and_nothing_is_inserted() {
    let mut rig = Rig::new();
    let m = rig.menu();
    assert_eq!(rig.append_popup(m, 0xBEEF, "bad"), 0);
    assert_eq!(item_count(&rig.os, u64::from(m)), 0);
    rig.put_info(miim::ID, 0, 0, 1, 0, None);
    rig.mem.write_u32(INFO + mii::CB_SIZE, 8).unwrap();
    assert_eq!(rig.thunked(m, 0, mf::BYPOSITION, method::INSERT_ITEM), 0, "a short cbSize is refused");
    let null_info = [u64::from(m), 0, 0, method::INSERT_ITEM, 0, 0];
    assert_eq!(rig.call(nt_user_thunked_menu_item_info, &null_info), 0);
    let wild_info = [u64::from(m), 0, 0, method::INSERT_ITEM, 0xFFFF_0000_0000, 0];
    assert_eq!(
        rig.call(nt_user_thunked_menu_item_info, &wild_info),
        0,
        "an unreadable info pointer fails instead of faulting the host"
    );
}

#[test]
fn delete_destroys_a_submenu_remove_keeps_it() {
    let mut rig = Rig::new();
    let bar = rig.menu();
    let kept = rig.popup();
    let doomed = rig.popup();
    rig.append_popup(bar, kept, "kept");
    rig.append_popup(bar, doomed, "doomed");
    rig.append(bar, 9, 0, "plain");

    let args = |id: u32, flags: u32| [u64::from(bar), u64::from(id), u64::from(flags)];
    assert_eq!(rig.call(nt_user_remove_menu, &args(0, mf::BYPOSITION)), 1);
    assert!(rig.os.win32k_state.menus.contains(kept), "RemoveMenu leaves the popup alive");
    assert_eq!(rig.call(nt_user_delete_menu, &args(0, mf::BYPOSITION)), 1);
    assert!(!rig.os.win32k_state.menus.contains(doomed), "DeleteMenu destroys it");
    assert_eq!(rig.call(nt_user_delete_menu, &args(9, 0)), 1);
    assert_eq!(rig.call(nt_user_delete_menu, &args(9, 0)), 0, "already gone");
    assert_eq!(item_count(&rig.os, u64::from(bar)), 0);
}

#[test]
fn destroy_menu_releases_the_whole_tree_once() {
    let mut rig = Rig::new();
    let bar = rig.menu();
    let file = rig.popup();
    let recent = rig.popup();
    rig.append_popup(file, recent, "Recent");
    rig.append_popup(bar, file, "File");
    assert_eq!(rig.call(nt_user_destroy_menu, &[u64::from(bar)]), 1);
    for h in [bar, file, recent] {
        assert!(!rig.os.win32k_state.menus.contains(h), "{h:#x} released");
    }
    assert_eq!(rig.call(nt_user_destroy_menu, &[u64::from(bar)]), 0, "a stale handle fails");
}

#[test]
fn a_menu_that_contains_itself_does_not_loop() {
    let mut rig = Rig::new();
    let m = rig.menu();
    rig.append_popup(m, m, "me");
    assert_eq!(rig.state(m, 12345, 0), NO_ITEM, "searching a cycle terminates");
    assert_eq!(rig.call(nt_user_destroy_menu, &[u64::from(m)]), 1, "destroying a cycle terminates");
}

#[test]
fn set_menu_attaches_through_the_window_id_that_get_menu_reads() {
    let mut rig = Rig::new();
    let m = rig.menu();
    let top = rig.window(0);
    let child = rig.window(WS_CHILD);
    let set = |rig: &mut Rig, w: u32, menu: u32| rig.call(nt_user_set_menu, &[u64::from(w), u64::from(menu)]);
    assert_eq!(set(&mut rig, top, m), 1);
    assert_eq!(rig.os.win32k_state.window(top).unwrap().id, u64::from(m), "GetMenu = GWLP_ID");
    assert_eq!(set(&mut rig, top, 0xBEEF), 0, "not a menu");
    assert_eq!(rig.os.win32k_state.window(top).unwrap().id, u64::from(m), "a refusal changes nothing");
    assert_eq!(set(&mut rig, child, m), 0, "a child window cannot carry a menu bar");
    assert_eq!(set(&mut rig, 0xDEAD, m), 0, "no such window");
    assert_eq!(set(&mut rig, top, 0), 1, "detaching");
    assert_eq!(rig.os.win32k_state.window(top).unwrap().id, 0);
}

#[test]
fn check_menu_radio_item_moves_the_check_within_the_range() {
    let mut rig = Rig::new();
    let m = rig.menu();
    for id in 1..=4 {
        rig.append(m, id, if id == 1 { mf::CHECKED } else { 0 }, "r");
    }
    rig.put_info(0, 0, 0, 0, 0, None);
    rig.mem.write_u32(INFO + mii::MASK, 3).unwrap();
    rig.mem.write_u32(INFO + mii::CCH, 4).unwrap();
    assert_eq!(rig.thunked(m, 1, 0, method::CHECK_RADIO_ITEM), 1);
    let states: Vec<u32> = rig.items(m).iter().map(|i| i.state).collect();
    assert_eq!(states, [0, 0, mf::CHECKED, 0]);
    assert_eq!(rig.items(m)[2].kind & mf::RADIOCHECK, mf::RADIOCHECK);

    rig.mem.write_u32(INFO + mii::MASK, 99).unwrap();
    assert_eq!(rig.thunked(m, 1, 0, method::CHECK_RADIO_ITEM), 0, "the checked id is outside the range");
    rig.mem.write_u32(INFO + mii::CCH, u32::MAX).unwrap();
    assert_eq!(rig.thunked(m, 0, 0, method::CHECK_RADIO_ITEM), 0, "a 4-billion-wide range ends");
}

#[test]
fn default_item_respects_disabled_and_the_position_flag() {
    let mut rig = Rig::new();
    let m = rig.menu();
    rig.append(m, 7, 0, "a");
    rig.append(m, 8, mf::DEFAULT, "b");
    assert_eq!(rig.thunked(m, 0, 0, method::DEFAULT_ITEM), 8);
    assert_eq!(rig.thunked(m, 1, 0, method::DEFAULT_ITEM), 1, "by position");
    rig.enable(m, 8, mf::GRAYED | mf::DISABLED);
    assert_eq!(rig.thunked(m, 0, 0, method::DEFAULT_ITEM), NO_ITEM, "a disabled default is skipped");
    assert_eq!(rig.thunked(m, 0, gmdi::USEDISABLED, method::DEFAULT_ITEM), 8);
}

#[test]
fn menu_info_round_trips_and_validates_its_mask_and_size() {
    let mut rig = Rig::new();
    let m = rig.menu();
    let put = |rig: &mut Rig, mask: u32| {
        rig.mem.write_u32(INFO + menuinfo::CB_SIZE, menuinfo::SIZE).unwrap();
        rig.mem.write_u32(INFO + menuinfo::MASK, mask).unwrap();
    };
    put(&mut rig, mim::MAXHEIGHT | mim::HELPID | mim::MENUDATA | mim::STYLE | mim::BACKGROUND);
    rig.mem.write_u32(INFO + menuinfo::STYLE, 0x8000_0000).unwrap();
    rig.mem.write_u32(INFO + menuinfo::MAX_HEIGHT, 90).unwrap();
    rig.mem.write_u64(INFO + menuinfo::BACKGROUND, 0x55).unwrap();
    rig.mem.write_u32(INFO + menuinfo::HELP_ID, 12).unwrap();
    rig.mem.write_u64(INFO + menuinfo::MENU_DATA, 0xABCD).unwrap();
    assert_eq!(rig.call(nt_user_thunked_menu_info, &[u64::from(m), INFO]), 1);

    rig.mem.write(INFO + menuinfo::STYLE, &[0u8; 0x20]).unwrap();
    assert_eq!(get_menu_info(&rig.os, &mut rig.mem, u64::from(m), INFO), 1);
    assert_eq!(rig.mem.read_u32(INFO + menuinfo::STYLE).unwrap(), 0x8000_0000);
    assert_eq!(rig.mem.read_u32(INFO + menuinfo::MAX_HEIGHT).unwrap(), 90);
    assert_eq!(rig.mem.read_u64(INFO + menuinfo::BACKGROUND).unwrap(), 0x55);
    assert_eq!(rig.mem.read_u32(INFO + menuinfo::HELP_ID).unwrap(), 12);
    assert_eq!(rig.mem.read_u64(INFO + menuinfo::MENU_DATA).unwrap(), 0xABCD);

    put(&mut rig, 0x40);
    assert_eq!(rig.call(nt_user_thunked_menu_info, &[u64::from(m), INFO]), 0, "an unknown mask bit");
    rig.mem.write_u32(INFO + menuinfo::CB_SIZE, 4).unwrap();
    assert_eq!(rig.call(nt_user_thunked_menu_info, &[u64::from(m), INFO]), 0, "a wrong cbSize");
    assert_eq!(get_menu_info(&rig.os, &mut rig.mem, 0xDEAD, INFO), 0, "an unknown menu");
}

#[test]
fn apply_to_submenus_reaches_every_popup_below() {
    let mut rig = Rig::new();
    let bar = rig.menu();
    let sub = rig.popup();
    rig.append_popup(bar, sub, "s");
    rig.mem.write_u32(INFO + menuinfo::CB_SIZE, menuinfo::SIZE).unwrap();
    rig.mem.write_u32(INFO + menuinfo::MASK, mim::HELPID | mim::APPLYTOSUBMENUS).unwrap();
    rig.mem.write_u32(INFO + menuinfo::HELP_ID, 77).unwrap();
    assert_eq!(rig.call(nt_user_thunked_menu_info, &[u64::from(bar), INFO]), 1);
    assert_eq!(rig.os.win32k_state.menus.menu(sub).unwrap().help_id, 77);
}
