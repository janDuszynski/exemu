use std::path::Path;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";
const MOV_R9D_IMM32: [u8; 2] = [0x41, 0xB9];
const MOV_EDX_IMM32: u8 = 0xBA;
const GWLP_ID: u32 = 0xFFFF_FFF4;

fn present() -> bool {
    Path::new(WINE_DLLS).join("user32.dll").exists() && Path::new(WINE_DLLS).join("win32u.dll").exists()
}

fn dll(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(WINE_DLLS).join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn export_bytes(bytes: &[u8], name: &str, len: usize) -> Option<Vec<u8>> {
    let image = exemu_loader::parse(bytes).ok()?;
    let rva = image
        .exports
        .iter()
        .find(|e| e.name.as_deref() == Some(name) && e.forwarder.is_none())?
        .rva;
    for s in &image.sections {
        let end = s.rva + s.data.len() as u32;
        if rva >= s.rva && rva < end {
            let off = (rva - s.rva) as usize;
            return Some(s.data[off..(off + len).min(s.data.len())].to_vec());
        }
    }
    None
}

fn syscall_index(bytes: &[u8], name: &str) -> Option<u32> {
    let code = export_bytes(bytes, name, 16)?;
    if code.len() < 8 || code[0..3] != [0x4C, 0x8B, 0xD1] || code[3] != 0xB8 {
        return None;
    }
    Some(u32::from_le_bytes([code[4], code[5], code[6], code[7]]))
}

fn thunked_method(user32: &[u8], api: &str) -> Option<u32> {
    let code = export_bytes(user32, api, 0x60)?;
    let at = code.windows(2).position(|w| w == MOV_R9D_IMM32)?;
    let imm = code.get(at + 2..at + 6)?;
    Some(u32::from_le_bytes([imm[0], imm[1], imm[2], imm[3]]))
}

#[test]
fn win32u_publishes_the_menu_and_accelerator_indices_the_handlers_use() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let w = dll("win32u.dll");
    for (name, index) in [
        ("NtUserCreateMenu", 0x1366u32),
        ("NtUserCreatePopupMenu", 0x1368),
        ("NtUserDestroyMenu", 0x1382),
        ("NtUserDeleteMenu", 0x1378),
        ("NtUserRemoveMenu", 0x151d),
        ("NtUserSetMenu", 0x1569),
        ("NtUserCheckMenuItem", 0x1347),
        ("NtUserEnableMenuItem", 0x13a7),
        ("NtUserDrawMenuBar", 0x139b),
        ("NtUserThunkedMenuInfo", 0x15cf),
        ("NtUserThunkedMenuItemInfo", 0x15d0),
        ("NtUserCreateAcceleratorTable", 0x135c),
        ("NtUserCopyAcceleratorTable", 0x135a),
        ("NtUserDestroyAcceleratorTable", 0x137b),
        ("NtUserTranslateAccelerator", 0x15d7),
        ("NtUserGetKeyState", 0x1410),
        ("NtUserGetAsyncKeyState", 0x13d0),
    ] {
        assert_eq!(syscall_index(&w, name), Some(index), "{name}'s own stub");
    }
}

#[test]
fn user32_selects_the_thunked_menu_item_methods_the_handler_decodes() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    for (api, method) in [
        ("CheckMenuRadioItem", 2u32),
        ("GetMenuDefaultItem", 3),
        ("GetMenuItemID", 4),
        ("GetMenuState", 7),
        ("GetSubMenu", 8),
    ] {
        assert_eq!(thunked_method(&u, api), Some(method), "{api} passes method {method}");
    }
}

#[test]
fn get_menu_reads_the_window_id_which_is_where_set_menu_stores_the_menu() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    let code = export_bytes(&u, "GetMenu", 0x20).expect("user32 exports GetMenu");
    let at = code.iter().position(|b| *b == MOV_EDX_IMM32).expect("GetMenu loads an index into edx");
    let index = u32::from_le_bytes([code[at + 1], code[at + 2], code[at + 3], code[at + 4]]);
    assert_eq!(index, GWLP_ID, "GetMenu is GetWindowLongPtrW(hwnd, GWLP_ID)");
}

#[test]
fn the_menu_info_calls_ride_the_call_one_and_two_param_selectors() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    let code = export_bytes(&u, "GetMenuItemCount", 0x20).expect("user32 exports GetMenuItemCount");
    assert!(
        code.windows(5).any(|w| w == [MOV_EDX_IMM32, 0x04, 0, 0, 0]),
        "GetMenuItemCount asks NtUserCallOneParam for selector 4"
    );
}
