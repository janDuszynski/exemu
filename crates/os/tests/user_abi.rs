use std::path::Path;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn present() -> bool {
    Path::new(WINE_DLLS).join("user32.dll").exists()
        && Path::new(WINE_DLLS).join("win32u.dll").exists()
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

#[test]
fn win32u_publishes_the_indices_the_new_handlers_use() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let w = dll("win32u.dll");
    for (name, index) in [
        ("NtUserSetProp", 0x157fu32),
        ("NtUserGetProp", 0x1438),
        ("NtUserRemoveProp", 0x151e),
        ("NtUserCallHwnd", 0x1332),
    ] {
        assert_eq!(syscall_index(&w, name), Some(index), "{name}'s own stub");
    }
}

#[test]
fn win_get_full_handle_is_call_hwnd_selector_0x0f() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    let image = exemu_loader::parse(&u).expect("user32 parses");
    let text = image
        .sections
        .iter()
        .find(|s| s.name.starts_with(".text"))
        .expect("user32 has .text");

    let head = [0x48, 0x83, 0xEC, 0x28, 0xBA, 0x0F, 0x00, 0x00, 0x00, 0xFF, 0x15];
    let at = text
        .data
        .windows(head.len())
        .position(|w| w == head)
        .expect("user32 contains WIN_GetFullHandle's body: it asks selector 0x0f and nothing else");
    let tail = &text.data[at + head.len() + 4..at + head.len() + 4 + 7];
    assert_eq!(
        tail,
        &[0x89, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3],
        "…and returns what the selector answered, widened to the full handle"
    );
}

#[test]
fn the_prop_apis_tail_jump_straight_into_their_syscalls() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    for name in ["SetPropW", "GetPropW"] {
        let Some(code) = export_bytes(&u, name, 0x10) else { continue };
        assert_eq!(
            &code[0..3],
            &[0x48, 0xFF, 0x25],
            "{name} is a bare tail-jump into its syscall"
        );
    }
}

#[test]
fn win32u_publishes_the_bitmap_and_icon_indices() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let w = dll("win32u.dll");
    for (name, index) in [
        ("NtGdiCreateCompatibleDC", 0x10aeu32),
        ("NtGdiCreateBitmap", 0x10a7),
        ("NtGdiCreateCompatibleBitmap", 0x10ad),
        ("NtGdiCreateDIBSection", 0x10b0),
        ("NtGdiSelectBitmap", 0x126b),
        ("NtGdiGetDeviceCaps", 0x11f4),
        ("NtGdiExtGetObjectW", 0x11c7),
        ("NtUserSetCursorIconData", 0x1548),
        ("NtUserGetIconInfo", 0x1403),
        ("NtUserGetIconSize", 0x1404),
        ("NtUserFindExistingCursorIcon", 0x13c5),
        ("NtUserDestroyCursor", 0x137f),
        ("NtUserCallOneParam", 0x133d),
    ] {
        assert_eq!(syscall_index(&w, name), Some(index), "{name}'s own stub");
    }
    let all = [
        0x10aeu32, 0x10a7, 0x10ad, 0x10b0, 0x126b, 0x11f4, 0x11c7, 0x1548, 0x1403, 0x1404, 0x13c5,
        0x137f, 0x133d,
    ];
    assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
}

#[test]
fn create_cursor_icon_is_call_one_param_code_zero() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");

    let gsm = export_bytes(&u, "GetSystemMetrics", 0x10).expect("user32 exports GetSystemMetrics");
    assert_eq!(
        &gsm[0..9],
        &[0x48, 0x83, 0xEC, 0x28, 0xBA, 0x09, 0x00, 0x00, 0x00],
        "GetSystemMetrics is CallOneParam with code 9 in edx and the param in rcx"
    );
    assert_eq!(&gsm[9..12], &[0x48, 0x63, 0xC9], "…sign-extending the caller's int index");
    assert_eq!(&gsm[12..14], &[0xFF, 0x15], "…and then calls straight through the IAT");

    let image = exemu_loader::parse(&u).expect("user32 parses");
    let text = image.sections.iter().find(|s| s.name.starts_with(".text")).expect(".text");
    let anchor = [0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x08, 0x02];
    let at = text
        .data
        .windows(anchor.len())
        .position(|w| w == anchor)
        .expect("user32 contains create_cursoricon_object's module-name UNICODE_STRING setup");
    let window = &text.data[at..(at + 0x40).min(text.data.len())];
    let xor_at = window
        .windows(2)
        .position(|w| w == [0x31, 0xD2])
        .expect("the allocation passes code 0, not a named CallOneParam selector");
    let call_at = window[xor_at..]
        .windows(2)
        .position(|w| w == [0xFF, 0x15])
        .expect("…and then calls NtUserCallOneParam through the IAT");
    assert!(
        !window[xor_at..xor_at + call_at].windows(1).any(|w| w == [0xBA]),
        "nothing reloads edx between the xor and the call: the code really is 0"
    );
}

#[test]
fn get_icon_size_halves_the_height_the_syscall_reports() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    let image = exemu_loader::parse(&u).expect("user32 parses");
    let text = image.sections.iter().find(|s| s.name.starts_with(".text")).expect(".text");

    let halve = [
        0x8B, 0x4B, 0x04,
        0x89, 0xCA,
        0xC1, 0xEA, 0x1F,
        0x01, 0xCA,
        0xD1, 0xFA,
        0x89, 0x53, 0x04,
    ];
    let at = text
        .data
        .windows(halve.len())
        .position(|w| w == halve)
        .expect("user32!get_icon_size halves the height NtUserGetIconSize reported");

    let before = &text.data[at - 10..at];
    assert_eq!(&before[0..2], &[0xFF, 0x15], "…immediately after the syscall call");
    assert_eq!(&before[6..8], &[0x85, 0xC0], "…guarded by test eax,eax");
    assert_eq!(before[8], 0x74, "…and skipped when the syscall failed");
}
