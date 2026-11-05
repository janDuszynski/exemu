use super::*;
use crate::win32k::rig::{Rig, SCRATCH};

const HKL_ARG: u64 = HKL_US_ENGLISH as u64;
const FILL: u8 = 0xAA;
const FILL_UNIT: u16 = 0xAAAA;
const NAME_BUFFER_BYTES: usize = 128;

fn map(rig: &mut Rig, code: u32, map_type: u32) -> u32 {
    rig.call(nt_user_map_virtual_key_ex, &[u64::from(code), u64::from(map_type), HKL_ARG])
}

fn name(rig: &mut Rig, lparam: u32, size: u32) -> (u32, String) {
    rig.mem.write(SCRATCH, &[FILL; NAME_BUFFER_BYTES]).unwrap();
    let n = rig.call(nt_user_get_key_name_text, &[u64::from(lparam), SCRATCH, u64::from(size)]);
    let mut units = Vec::new();
    for i in 0..(NAME_BUFFER_BYTES as u64 / 2) {
        let u = rig.mem.read_u16(SCRATCH + i * 2).unwrap();
        if u == 0 || u == FILL_UNIT {
            break;
        }
        units.push(u);
    }
    (n, String::from_utf16(&units).unwrap())
}

fn lparam(scan: u32, extended: bool, dont_care: bool) -> u32 {
    (scan << KEY_NAME_SCAN_SHIFT)
        | if extended { KEY_NAME_EXTENDED } else { 0 }
        | if dont_care { KEY_NAME_DONT_CARE } else { 0 }
}

#[test]
fn vk_to_vsc_maps_letters_digits_function_keys_and_numpad() {
    let mut rig = Rig::new();
    for (vk, scan) in [
        (u32::from(b'A'), 0x1E),
        (u32::from(b'Z'), 0x2C),
        (u32::from(b'Q'), 0x10),
        (u32::from(b'1'), 0x02),
        (u32::from(b'0'), 0x0B),
        (0x70, 0x3B),
        (0x79, 0x44),
        (0x7A, 0x57),
        (0x7B, 0x58),
        (0x60, 0x52),
        (0x67, 0x47),
        (0x6B, 0x4E),
        (0x6D, 0x4A),
        (0x6E, 0x53),
        (0x10, 0x2A),
        (0x11, 0x1D),
        (0x12, 0x38),
        (0xA1, 0x36),
        (0xA3, 0x1D),
        (0x20, 0x39),
        (0x0D, 0x1C),
        (0x1B, 0x01),
    ] {
        assert_eq!(map(&mut rig, vk, MAPVK_VK_TO_VSC), scan, "vk {vk:#x}");
    }
}

#[test]
fn vk_to_vsc_ex_adds_the_e0_prefix_on_extended_keys_only() {
    let mut rig = Rig::new();
    for (vk, plain, with_prefix) in [
        (0x25, 0x4B, 0xE04B),
        (0x26, 0x48, 0xE048),
        (0x27, 0x4D, 0xE04D),
        (0x28, 0x50, 0xE050),
        (0x2D, 0x52, 0xE052),
        (0x2E, 0x53, 0xE053),
        (0x24, 0x47, 0xE047),
        (0x23, 0x4F, 0xE04F),
        (0x21, 0x49, 0xE049),
        (0x22, 0x51, 0xE051),
        (0x6F, 0x35, 0xE035),
        (0xA3, 0x1D, 0xE01D),
        (0xA5, 0x38, 0xE038),
        (0x5B, 0x5B, 0xE05B),
        (0x13, 0x45, 0xE11D),
        (0x41, 0x1E, 0x1E),
        (0x70, 0x3B, 0x3B),
        (0x0D, 0x1C, 0x1C),
        (0x68, 0x48, 0x48),
    ] {
        assert_eq!(map(&mut rig, vk, MAPVK_VK_TO_VSC), plain, "vk {vk:#x} plain");
        assert_eq!(map(&mut rig, vk, MAPVK_VK_TO_VSC_EX), with_prefix, "vk {vk:#x} ex");
    }
}

#[test]
fn vsc_to_vk_folds_sides_and_ex_keeps_them() {
    let mut rig = Rig::new();
    assert_eq!(map(&mut rig, 0x2A, MAPVK_VSC_TO_VK), 0x10);
    assert_eq!(map(&mut rig, 0x36, MAPVK_VSC_TO_VK), 0x10);
    assert_eq!(map(&mut rig, 0x1D, MAPVK_VSC_TO_VK), 0x11);
    assert_eq!(map(&mut rig, 0x38, MAPVK_VSC_TO_VK), 0x12);
    assert_eq!(map(&mut rig, 0x2A, MAPVK_VSC_TO_VK_EX), 0xA0);
    assert_eq!(map(&mut rig, 0x36, MAPVK_VSC_TO_VK_EX), 0xA1);
    assert_eq!(map(&mut rig, 0x1D, MAPVK_VSC_TO_VK_EX), 0xA2);
    assert_eq!(map(&mut rig, 0xE01D, MAPVK_VSC_TO_VK_EX), 0xA3);
    assert_eq!(map(&mut rig, 0x38, MAPVK_VSC_TO_VK_EX), 0xA4);
    assert_eq!(map(&mut rig, 0xE038, MAPVK_VSC_TO_VK_EX), 0xA5);
    assert_eq!(map(&mut rig, 0xE038, MAPVK_VSC_TO_VK), 0x12);
}

#[test]
fn vsc_to_vk_maps_letters_function_keys_and_the_cursor_cluster() {
    let mut rig = Rig::new();
    assert_eq!(map(&mut rig, 0x1E, MAPVK_VSC_TO_VK), u32::from(b'A'));
    assert_eq!(map(&mut rig, 0x02, MAPVK_VSC_TO_VK), u32::from(b'1'));
    assert_eq!(map(&mut rig, 0x3B, MAPVK_VSC_TO_VK), 0x70);
    assert_eq!(map(&mut rig, 0x58, MAPVK_VSC_TO_VK), 0x7B);
    assert_eq!(map(&mut rig, 0x47, MAPVK_VSC_TO_VK), 0x24, "numpad 7 scan is VK_HOME unshifted");
    assert_eq!(map(&mut rig, 0x52, MAPVK_VSC_TO_VK), 0x2D);
    assert_eq!(map(&mut rig, 0x53, MAPVK_VSC_TO_VK), 0x2E);
    assert_eq!(map(&mut rig, 0x4E, MAPVK_VSC_TO_VK), 0x6B);
    assert_eq!(map(&mut rig, 0x45, MAPVK_VSC_TO_VK), 0x90);
    assert_eq!(map(&mut rig, 0xE04B, MAPVK_VSC_TO_VK_EX), 0x25);
    assert_eq!(map(&mut rig, 0xE048, MAPVK_VSC_TO_VK_EX), 0x26);
    assert_eq!(map(&mut rig, 0xE052, MAPVK_VSC_TO_VK_EX), 0x2D);
    assert_eq!(map(&mut rig, 0xE053, MAPVK_VSC_TO_VK_EX), 0x2E);
    assert_eq!(map(&mut rig, 0xE11D, MAPVK_VSC_TO_VK_EX), 0x13);
    assert_eq!(map(&mut rig, 0xE135, MAPVK_VSC_TO_VK_EX), 0, "only 0xE11D is an E1 key");
    assert_eq!(map(&mut rig, 0x7F, MAPVK_VSC_TO_VK), 0);
    assert_eq!(map(&mut rig, 0xE07F, MAPVK_VSC_TO_VK_EX), 0);
}

#[test]
fn vk_to_char_gives_the_unshifted_character() {
    let mut rig = Rig::new();
    for (vk, ch) in [
        (u32::from(b'A'), u32::from(b'A')),
        (u32::from(b'7'), u32::from(b'7')),
        (0x20, u32::from(b' ')),
        (0x60, u32::from(b'0')),
        (0x69, u32::from(b'9')),
        (0x6A, u32::from(b'*')),
        (0x6B, u32::from(b'+')),
        (0x6D, u32::from(b'-')),
        (0x6E, u32::from(b'.')),
        (0x6F, u32::from(b'/')),
        (0xBA, u32::from(b';')),
        (0xBB, u32::from(b'=')),
        (0xBC, u32::from(b',')),
        (0xBD, u32::from(b'-')),
        (0xBE, u32::from(b'.')),
        (0xBF, u32::from(b'/')),
        (0xC0, u32::from(b'`')),
        (0xDB, u32::from(b'[')),
        (0xDC, u32::from(b'\\')),
        (0xDD, u32::from(b']')),
        (0xDE, u32::from(b'\'')),
        (0x0D, 0x0D),
        (0x1B, 0x1B),
        (0x70, 0),
        (0x25, 0),
        (0x2E, 0),
        (0x10, 0),
    ] {
        assert_eq!(map(&mut rig, vk, MAPVK_VK_TO_CHAR), ch, "vk {vk:#x}");
    }
}

#[test]
fn an_unknown_type_or_wild_code_maps_to_zero() {
    let mut rig = Rig::new();
    assert_eq!(map(&mut rig, 0x41, 5), 0);
    assert_eq!(map(&mut rig, 0x41, u32::MAX), 0);
    assert_eq!(map(&mut rig, 0x1_0041, MAPVK_VK_TO_VSC), 0);
    assert_eq!(map(&mut rig, u32::MAX, MAPVK_VK_TO_CHAR), 0);
    assert_eq!(map(&mut rig, u32::MAX, MAPVK_VSC_TO_VK_EX), 0);
    assert_eq!(map(&mut rig, 0xFF, MAPVK_VK_TO_VSC_EX), 0);
}

#[test]
fn the_keyboard_layout_is_us_english_for_any_thread() {
    let mut rig = Rig::new();
    assert_eq!(rig.call(nt_user_get_keyboard_layout, &[0]), 0x0409_0409);
    assert_eq!(rig.call(nt_user_get_keyboard_layout, &[0x1234]), 0x0409_0409);
}

#[test]
fn key_names_follow_the_scan_code_and_the_extended_bit() {
    let mut rig = Rig::new();
    for (scan, extended, expected) in [
        (0x1D, false, "Ctrl"),
        (0x1D, true, "Right Ctrl"),
        (0x2A, false, "Shift"),
        (0x38, false, "Alt"),
        (0x3B, false, "F1"),
        (0x58, false, "F12"),
        (0x4E, false, "Num +"),
        (0x53, false, "Num Del"),
        (0x53, true, "Delete"),
        (0x52, true, "Insert"),
        (0x4B, true, "Left"),
        (0x1C, false, "Enter"),
        (0x1C, true, "Num Enter"),
        (0x39, false, "Space"),
    ] {
        let units = u32::try_from(expected.len()).unwrap();
        assert_eq!(
            name(&mut rig, lparam(scan, extended, false), 64),
            (units, expected.into()),
            "scan {scan:#x} extended {extended}"
        );
    }
}

#[test]
fn character_keys_are_named_by_their_character() {
    let mut rig = Rig::new();
    assert_eq!(name(&mut rig, lparam(0x2C, false, false), 64), (1, "Z".into()));
    assert_eq!(name(&mut rig, lparam(0x02, false, false), 64), (1, "1".into()));
    assert_eq!(name(&mut rig, lparam(0x27, false, false), 64), (1, ";".into()));
    assert_eq!(name(&mut rig, lparam(0x7F, false, false), 64), (0, String::new()));
}

#[test]
fn the_dont_care_bit_folds_right_hand_modifiers() {
    let mut rig = Rig::new();
    assert_eq!(name(&mut rig, lparam(0x36, false, false), 64), (11, "Right Shift".into()));
    assert_eq!(name(&mut rig, lparam(0x36, false, true), 64), (5, "Shift".into()));
    assert_eq!(name(&mut rig, lparam(0x1D, true, true), 64), (4, "Ctrl".into()));
    assert_eq!(name(&mut rig, lparam(0x38, true, true), 64), (3, "Alt".into()));
    assert_eq!(name(&mut rig, lparam(0x4B, true, true), 64), (4, "Left".into()));
}

#[test]
fn the_name_is_truncated_to_the_buffer_and_always_terminated() {
    let mut rig = Rig::new();
    assert_eq!(name(&mut rig, lparam(0x1D, true, false), 6), (5, "Right".into()));
    assert_eq!(name(&mut rig, lparam(0x1D, true, false), 1), (0, String::new()));
    assert_eq!(name(&mut rig, lparam(0x1D, true, false), 11), (10, "Right Ctrl".into()));
}

#[test]
fn a_zero_size_a_negative_size_or_a_null_buffer_returns_zero_untouched() {
    let mut rig = Rig::new();
    rig.mem.write(SCRATCH, &[FILL; 8]).unwrap();
    let ctrl = u64::from(lparam(0x1D, false, false));
    assert_eq!(rig.call(nt_user_get_key_name_text, &[ctrl, SCRATCH, 0]), 0);
    assert_eq!(rig.call(nt_user_get_key_name_text, &[ctrl, SCRATCH, u64::from(u32::MAX)]), 0);
    assert_eq!(rig.call(nt_user_get_key_name_text, &[ctrl, 0, 16]), 0);
    assert_eq!(rig.mem.read_u16(SCRATCH).unwrap(), FILL_UNIT, "no write on rejected sizes");
}

#[test]
fn an_unmapped_buffer_is_zero_not_a_panic() {
    let mut rig = Rig::new();
    let ctrl = u64::from(lparam(0x1D, false, false));
    assert_eq!(rig.call(nt_user_get_key_name_text, &[ctrl, 0x9000_0000, 16]), 0);
}
