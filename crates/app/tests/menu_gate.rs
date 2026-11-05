use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, wow64_menu_sample as s, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";
const MAX_STEPS: u64 = 120_000_000;
const NO_SUCH_ITEM: u32 = u32::MAX;
const COMMAND_FROM_ACCELERATOR: u32 = 1 << 16;
const US_ENGLISH_HKL: u32 = 0x0409_0409;
const VK_RCONTROL: u32 = 0xA3;

fn have_wow64_set() -> bool {
    wow64_boot::Wow64Dirs { dir64: Path::new(WINE_DLLS64), dir32: Path::new(WINE_DLLS32) }.complete()
}

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-menu-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_32bit_guest_builds_a_menu_and_runs_an_accelerator_through_wine_user32() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = s::build();
    let mut cfg = RunConfig {
        echo: false,
        max_steps: MAX_STEPS,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox("menu")),
        ..RunConfig::default()
    };
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let r = proc.run_borrowed().expect("the WoW64 menu guest ran");

    let cell = |off: u32| proc.peek_u32(s::data_va(off)).unwrap();
    eprintln!("menu gate: exit {} after {} instructions", r.exit_code, r.steps);
    assert_eq!(r.exit_code, s::MENU_OK_EXIT, "the guest ran to its end");

    let hwnd = cell(s::data::HWND);
    let menu = cell(s::data::HMENU);
    assert_ne!(hwnd, 0, "CreateWindowExW returned a window");
    assert_ne!(menu, 0, "CreateMenu returned a menu");

    assert_eq!(cell(s::data::COUNT_BEFORE), 2, "AppendMenuW twice: GetMenuItemCount sees both");
    assert_eq!(cell(s::data::GET_MENU), menu, "GetMenu reads back what SetMenu attached");

    assert_eq!(cell(s::data::CHECK_FIRST), 0, "CheckMenuItem: the item was unchecked");
    assert_eq!(cell(s::data::CHECK_SECOND), s::MF_CHECKED, "…and now it reports it was checked");
    assert_eq!(cell(s::data::CHECK_MISSING), NO_SUCH_ITEM, "an id the menu lacks is -1");
    assert_eq!(cell(s::data::ENABLE_FIRST), 0, "EnableMenuItem: the item was enabled");
    assert_eq!(cell(s::data::ENABLE_SECOND), s::MF_GRAYED, "…and re-enabling reports it was grayed");
    assert_eq!(cell(s::data::STATE_AFTER), s::MF_CHECKED, "GetMenuState sees the check");
    assert_eq!(cell(s::data::DELETE_RESULT), 1, "DeleteMenu found its item");
    assert_eq!(cell(s::data::COUNT_AFTER_DELETE), 1, "…and the menu is one item shorter");

    assert_ne!(cell(s::data::HACCEL), 0, "CreateAcceleratorTableW returned a table");
    assert_eq!(cell(s::data::TRANSLATE_HIT), 1, "F5 is in the table: TranslateAcceleratorW translated it");
    assert_eq!(cell(s::data::COMMANDS_AFTER_HIT), 1, "…and the window procedure got one WM_COMMAND");
    assert_eq!(
        cell(s::data::LAST_WPARAM),
        COMMAND_FROM_ACCELERATOR | s::ACCEL_COMMAND,
        "…with HIWORD(wParam)=1 (from an accelerator) and the table's command id"
    );
    assert_eq!(cell(s::data::LAST_HWND), hwnd, "…delivered to the window that was asked");
    assert_eq!(cell(s::data::TRANSLATE_MISS), 0, "F6 is not in the table");
    assert_eq!(cell(s::data::COMMANDS_AFTER_MISS), 1, "…and no second WM_COMMAND was sent for it");
    assert_eq!(cell(s::data::DESTROY_ACCEL), 1, "DestroyAcceleratorTable released the table");
    assert_eq!(cell(s::data::TRANSLATE_AFTER_DESTROY), 0, "a destroyed table translates nothing");
    assert_eq!(cell(s::data::COMMANDS), 1, "the dead table delivered nothing either");

    assert_eq!(cell(s::data::KEY_LAYOUT), US_ENGLISH_HKL, "GetKeyboardLayout reports the one modelled layout");
    assert_eq!(cell(s::data::MAP_F5_TO_VSC), s::SCAN_F5, "MapVirtualKeyW(VK_F5, MAPVK_VK_TO_VSC)");
    assert_eq!(cell(s::data::MAP_VSC_TO_A), s::VK_A, "MapVirtualKeyW(0x1E, MAPVK_VSC_TO_VK) is 'A'");
    assert_eq!(cell(s::data::MAP_A_TO_CHAR), s::VK_A, "MapVirtualKeyW('A', MAPVK_VK_TO_CHAR)");
    assert_eq!(cell(s::data::MAP_RCTRL_EX), VK_RCONTROL, "0xE01D with MAPVK_VSC_TO_VK_EX is right control");
    assert_eq!(cell(s::data::MAP_LEFT_TO_VSC_EX), 0xE04B, "VK_LEFT with MAPVK_VK_TO_VSC_EX carries the E0 prefix");
    assert_eq!(cell(s::data::KEY_NAME_CTRL_LEN), 4, "GetKeyNameTextW returns the length of \"Ctrl\"");
    assert_eq!(wide_at(&proc, s::data::KEY_NAME_CTRL, 4), "Ctrl");
    assert_eq!(cell(s::data::KEY_NAME_DELETE_LEN), 6, "the extended bit selects \"Delete\" over \"Num Del\"");
    assert_eq!(wide_at(&proc, s::data::KEY_NAME_DELETE, 6), "Delete");
}

fn wide_at(proc: &Process, off: u32, units: u32) -> String {
    let at = s::data_va(off);
    let units: Vec<u16> = (0..units)
        .map(|i| {
            let lo = proc.peek_u32(at + u64::from(i) * 2).unwrap();
            lo as u16
        })
        .collect();
    String::from_utf16(&units).unwrap()
}
