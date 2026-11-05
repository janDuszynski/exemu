use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, wow64_menu_sample as s, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";
const MAX_STEPS: u64 = 120_000_000;
const NO_SUCH_ITEM: u32 = u32::MAX;
const COMMAND_FROM_ACCELERATOR: u32 = 1 << 16;

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

    let rect = |off: u32| -> [i32; 4] {
        let mut r = [0i32; 4];
        for (i, v) in r.iter_mut().enumerate() {
            *v = cell(off + i as u32 * 4) as i32;
        }
        r
    };
    let (wx, wy, ww, wh) = (s::WINDOW_X as i32, s::WINDOW_Y as i32, s::WINDOW_W as i32, s::WINDOW_H as i32);
    let band = cell(s::data::SYSTEM_MENU_HEIGHT) as i32;
    assert!(band > 0, "GetSystemMetrics(SM_CYMENU) is no longer zero");
    assert_eq!(rect(s::data::CLIENT_BEFORE), [0, 0, ww, wh], "no menu: the client is the whole window");
    assert_eq!(rect(s::data::CLIENT_AFTER), [0, 0, ww, wh - band], "SetMenu took one menu band off the client");
    assert_eq!(rect(s::data::WINDOW_RECT), [wx, wy, wx + ww, wy + wh], "the window rectangle did not change");

    assert_eq!(cell(s::data::ITEM0_OK), 1, "GetMenuItemRect item 0");
    assert_eq!(cell(s::data::ITEM1_OK), 1, "GetMenuItemRect item 1");
    assert_eq!(cell(s::data::ITEM_BEYOND_OK), 0, "item 2 does not exist");
    assert_eq!(rect(s::data::BEYOND_RECT), [0; 4], "a failed GetMenuItemRect writes nothing");
    let (item0, item1) = (rect(s::data::ITEM0_RECT), rect(s::data::ITEM1_RECT));
    assert_eq!(cell(s::data::BAR_INFO_OK), 1, "GetMenuBarInfo(OBJID_MENU, 0)");
    assert_eq!(cell(s::data::BAR_INFO_ITEM1_OK), 1, "GetMenuBarInfo(OBJID_MENU, 1)");
    assert_eq!(cell(s::data::BAR_INFO_BEYOND_OK), 0, "the bar has two items, not three");
    assert_eq!(cell(s::data::BEYOND_INFO + s::menubarinfo32::HMENU), 0, "a failed GetMenuBarInfo writes nothing");
    let bar = rect(s::data::BAR_INFO + s::menubarinfo32::RC_BAR);
    assert_eq!(cell(s::data::BAR_INFO + s::menubarinfo32::HMENU), menu, "the bar's menu");
    assert_eq!(cell(s::data::BAR_INFO + s::menubarinfo32::FLAGS), 0, "the bar is not focused");
    assert_eq!(
        rect(s::data::BAR_INFO_ITEM1 + s::menubarinfo32::RC_BAR),
        item0,
        "item 1 of GetMenuBarInfo is position 0 of GetMenuItemRect"
    );

    assert_eq!(item0[0], bar[0], "item 0 starts at the bar's left edge");
    assert_eq!(bar[0], wx, "the bar starts at the window's left edge");
    assert_eq!(bar[2], wx + ww, "and spans its width");
    assert!(item0[0] < item0[2] && item1[0] < item1[2], "items have width");
    assert!(item0[2] <= item1[0], "items do not overlap: {item0:?} then {item1:?}");
    assert_eq!((item0[1], item0[3]), (item1[1], item1[3]), "both items share the row");
    let band_bottom = wy + band;
    for r in [item0, item1, bar] {
        assert!(r[1] >= wy && r[3] <= band_bottom, "{r:?} sits inside the top non-client band {wy}..{band_bottom}");
    }
    assert_eq!(bar[3] - bar[1] + 1, band, "bar height plus its divider line is the client's loss");

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
}
