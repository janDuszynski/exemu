use super::*;
use crate::win32k::menu::test_menu_with_command;
use crate::win32k::rig::{Rig, SCRATCH};
use exemu_core::InputEvent;

const TABLE: u64 = SCRATCH;
const COPY_OUT: u64 = SCRATCH + 0x200;
const MSG: u64 = SCRATCH + 0x400;
const VK_S: u16 = 0x53;
const VK_F5: u16 = 0x74;
const CTRL_S: u16 = 100;
const F5_CMD: u16 = 101;
const CHAR_X: u16 = 0x78;
const CHAR_X_CMD: u16 = 102;
const ALT_Q_CMD: u16 = 103;
const FLAST: u8 = 0x80;
const VK_CONTROL_CODE: u32 = 0x11;
const VK_MENU_CODE: u32 = 0x12;
const SHIFT_BIT: u8 = fvirt::SHIFT;

fn put_table(rig: &mut Rig, entries: &[(u8, u16, u16)]) {
    for (i, (virt, key, cmd)) in entries.iter().enumerate() {
        let at = TABLE + i as u64 * accel_layout::SIZE;
        rig.mem.write_u16(at + accel_layout::VIRT, u16::from(*virt)).unwrap();
        rig.mem.write_u16(at + accel_layout::KEY, *key).unwrap();
        rig.mem.write_u16(at + accel_layout::CMD, *cmd).unwrap();
    }
}

fn standard_table(rig: &mut Rig) -> u32 {
    let entries = [
        (fvirt::VIRTKEY | fvirt::CONTROL, VK_S, CTRL_S),
        (fvirt::VIRTKEY, VK_F5, F5_CMD),
        (0, CHAR_X, CHAR_X_CMD),
        (fvirt::ALT | FLAST, 0x71, ALT_Q_CMD),
    ];
    put_table(rig, &entries);
    rig.call(nt_user_create_accelerator_table, &[TABLE, entries.len() as u64])
}

fn put_msg(rig: &mut Rig, message: u32, wparam: u64) {
    rig.mem.write_u32(MSG + msg_layout::MESSAGE, message).unwrap();
    rig.mem.write_u64(MSG + msg_layout::WPARAM, wparam).unwrap();
}

fn translate(rig: &mut Rig, hwnd: u32, table: u32) -> u32 {
    rig.call(nt_user_translate_accelerator, &[u64::from(hwnd), u64::from(table), MSG])
}

fn key(rig: &mut Rig, vk: u32, down: bool) {
    rig.os.win32k_state.keys.note(InputEvent::Key { hwnd: 0, vk, down });
}

#[test]
fn a_table_round_trips_through_copy_without_the_last_marker() {
    let mut rig = Rig::new();
    let table = standard_table(&mut rig);
    assert_ne!(table, 0);

    let args = |out: u64, n: u64| [u64::from(table), out, n];
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &args(0, 0)), 4, "no buffer asks the count");
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &args(COPY_OUT, 2)), 2, "bounded by the caller");
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &args(COPY_OUT, 99)), 4, "bounded by the table");
    let read = |rig: &Rig, i: u64| {
        let at = COPY_OUT + i * accel_layout::SIZE;
        (
            rig.mem.read_u16(at + accel_layout::VIRT).unwrap(),
            rig.mem.read_u16(at + accel_layout::KEY).unwrap(),
            rig.mem.read_u16(at + accel_layout::CMD).unwrap(),
        )
    };
    assert_eq!(read(&rig, 0), (u16::from(fvirt::VIRTKEY | fvirt::CONTROL), VK_S, CTRL_S));
    assert_eq!(read(&rig, 3), (u16::from(fvirt::ALT), 0x71, ALT_Q_CMD), "FLAST is not stored");
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &[0xBAD, COPY_OUT, 4]), 0, "an unknown table");
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &args(0xFFFF_0000_0000, 4)), 0, "an unwritable buffer");
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &args(COPY_OUT, 0xFFFF_FFFF)), 0, "a negative count copies nothing");
}

#[test]
fn a_bad_create_is_refused() {
    let mut rig = Rig::new();
    put_table(&mut rig, &[(fvirt::VIRTKEY, VK_F5, F5_CMD)]);
    for (at, count) in [(TABLE, 0u64), (TABLE, 0xFFFF_FFFF), (TABLE, 0x2_0000), (0, 1), (0xFFFF_0000_0000, 1)] {
        assert_eq!(rig.call(nt_user_create_accelerator_table, &[at, count]), 0, "{at:#x} x {count:#x}");
    }
    assert!(rig.os.win32k_state.accels.tables.is_empty(), "nothing was left behind");
}

#[test]
fn destroy_releases_once() {
    let mut rig = Rig::new();
    let table = standard_table(&mut rig);
    assert_eq!(rig.call(nt_user_destroy_accelerator_table, &[u64::from(table)]), 1);
    assert_eq!(rig.call(nt_user_destroy_accelerator_table, &[u64::from(table)]), 0);
    assert_eq!(rig.call(nt_user_copy_accelerator_table, &[u64::from(table), 0, 0]), 0, "gone for copy too");
}

#[test]
fn virtual_key_accelerators_need_exactly_their_modifiers() {
    let table = [Accel { virt: fvirt::VIRTKEY | fvirt::CONTROL, key: VK_S, cmd: CTRL_S }];
    let find = |message, modifiers| find_command(&table, message, VK_S, modifiers);
    assert_eq!(find(WM_KEYDOWN, fvirt::CONTROL), Some(CTRL_S));
    assert_eq!(find(WM_KEYDOWN, 0), None, "plain S is not Ctrl+S");
    assert_eq!(find(WM_KEYDOWN, fvirt::CONTROL | SHIFT_BIT), None, "Ctrl+Shift+S is not Ctrl+S");
    assert_eq!(find(WM_SYSKEYDOWN, fvirt::CONTROL), Some(CTRL_S), "SYSKEYDOWN matches virtual keys too");
    assert_eq!(find(WM_CHAR, fvirt::CONTROL), None, "a virtual-key accelerator ignores WM_CHAR");
    assert_eq!(find_command(&table, WM_KEYDOWN, VK_F5, fvirt::CONTROL), None, "another key");
}

#[test]
fn character_accelerators_match_chars_and_alt_means_syschar() {
    let table = [
        Accel { virt: 0, key: CHAR_X, cmd: CHAR_X_CMD },
        Accel { virt: fvirt::ALT, key: 0x71, cmd: ALT_Q_CMD },
    ];
    assert_eq!(find_command(&table, WM_CHAR, CHAR_X, 0), Some(CHAR_X_CMD));
    assert_eq!(find_command(&table, WM_KEYDOWN, CHAR_X, 0), None, "a character accelerator ignores key-downs");
    assert_eq!(find_command(&table, WM_SYSCHAR, 0x71, fvirt::ALT), Some(ALT_Q_CMD));
    assert_eq!(find_command(&table, WM_CHAR, 0x71, 0), None, "an Alt accelerator wants WM_SYSCHAR");
}

#[test]
fn translate_reports_a_match_only_with_the_held_modifiers() {
    let mut rig = Rig::new();
    let table = standard_table(&mut rig);
    let hwnd = rig.window(0);

    put_msg(&mut rig, WM_KEYDOWN, u64::from(VK_F5));
    assert_eq!(translate(&mut rig, hwnd, table), 1, "F5 needs no modifier");

    put_msg(&mut rig, WM_KEYDOWN, u64::from(VK_S));
    assert_eq!(translate(&mut rig, hwnd, table), 0, "S alone is no accelerator");
    key(&mut rig, VK_CONTROL_CODE, true);
    assert_eq!(translate(&mut rig, hwnd, table), 1, "Ctrl is held now");
    key(&mut rig, VK_MENU_CODE, true);
    assert_eq!(translate(&mut rig, hwnd, table), 0, "Ctrl+Alt+S is not Ctrl+S");
    key(&mut rig, VK_MENU_CODE, false);
    key(&mut rig, VK_CONTROL_CODE, false);
    assert_eq!(translate(&mut rig, hwnd, table), 0, "released again");
}

#[test]
fn translate_ignores_what_it_cannot_translate() {
    let mut rig = Rig::new();
    let table = standard_table(&mut rig);
    let hwnd = rig.window(0);
    put_msg(&mut rig, WM_KEYDOWN, u64::from(VK_F5));
    assert_eq!(translate(&mut rig, 0xDEAD, table), 0, "no such window");
    assert_eq!(translate(&mut rig, hwnd, 0xBAD), 0, "no such table");
    assert_eq!(rig.call(nt_user_translate_accelerator, &[u64::from(hwnd), u64::from(table), 0]), 0, "no MSG");
    assert_eq!(
        rig.call(nt_user_translate_accelerator, &[u64::from(hwnd), u64::from(table), 0xFFFF_0000_0000]),
        0,
        "an unreadable MSG"
    );
    put_msg(&mut rig, 0x0200, u64::from(VK_F5));
    assert_eq!(translate(&mut rig, hwnd, table), 0, "WM_MOUSEMOVE is no key message");
    put_msg(&mut rig, WM_KEYDOWN, 0x1_0000 | u64::from(VK_F5));
    assert_eq!(translate(&mut rig, hwnd, table), 1, "only the low word of wParam is the key");
}

#[test]
fn a_disabled_menu_item_swallows_its_accelerator() {
    let mut rig = Rig::new();
    let hwnd = rig.window(0);
    let enabled = test_menu_with_command(&mut rig.os, u32::from(F5_CMD), 0);
    let disabled = test_menu_with_command(&mut rig.os, u32::from(F5_CMD), 0x0003);
    let set_menu = |rig: &mut Rig, menu: u32| {
        rig.os.win32k_state.window_mut(hwnd).unwrap().id = u64::from(menu);
    };

    assert!(!command_disabled_in_window_menu(&rig.os, hwnd, F5_CMD), "no menu at all");
    set_menu(&mut rig, enabled);
    assert!(!command_disabled_in_window_menu(&rig.os, hwnd, F5_CMD));
    assert!(!command_disabled_in_window_menu(&rig.os, hwnd, 999), "a command the menu does not have");
    set_menu(&mut rig, disabled);
    assert!(command_disabled_in_window_menu(&rig.os, hwnd, F5_CMD));

    let table = standard_table(&mut rig);
    put_msg(&mut rig, WM_KEYDOWN, u64::from(VK_F5));
    assert_eq!(translate(&mut rig, hwnd, table), 1, "the key is still consumed");
}

#[test]
fn the_command_message_carries_the_accelerator_flag_in_the_high_word() {
    assert_eq!(COMMAND_FROM_ACCELERATOR | u64::from(CTRL_S), 0x0001_0064);
}
