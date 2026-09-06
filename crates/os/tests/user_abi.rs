//! Two USER primitives, re-derived from the pinned Wine binaries on every run
//! (roadmap W6.2).
//!
//! Each of these was answering **0** — the blanket "not implemented" stub — for
//! something whose zero is not a harmless "no" but a wrong answer the caller
//! then acts on. They were found by tracing the win32u boundary
//! (`EXEMU_W32K_TRACE`) through Wine's own file dialog, and the numbers they
//! rest on are recovered here from the binaries rather than asserted, so a
//! prefix refresh that renumbers the SSDT fails this file instead of silently
//! reintroducing the bug.
//!
//! * **`NtUserCallHwnd(hwnd, 0x0f)` — `GetFullWindowHandle`.** `WIN_GetFullHandle`
//!   is the handle widener every user32 entry point runs its `HWND` through, and
//!   `call_dialog_proc` passes its result to the dialog procedure *as the
//!   `hwnd`*. Answering 0 gave every dialog procedure a null window.
//! * **`NtUserSetProp` / `NtUserGetProp` / `NtUserRemoveProp`.** `SetPropW` and
//!   `GetPropW` are bare tail-jumps into them, and window properties are where
//!   comctl32's subclass chain and comdlg32's dialog state live.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn present() -> bool {
    Path::new(WINE_DLLS).join("user32.dll").exists()
        && Path::new(WINE_DLLS).join("win32u.dll").exists()
}

fn dll(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(WINE_DLLS).join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// Bytes of the named export's code, up to `len`, or `None` if it is missing or
/// a forwarder.
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

/// The syscall index a `win32u.dll` stub carries: `4c 8b d1` (`mov r10,rcx`)
/// then `b8 <imm32>` (`mov eax,index`).
fn syscall_index(bytes: &[u8], name: &str) -> Option<u32> {
    let code = export_bytes(bytes, name, 16)?;
    if code.len() < 8 || code[0..3] != [0x4C, 0x8B, 0xD1] || code[3] != 0xB8 {
        return None;
    }
    Some(u32::from_le_bytes([code[4], code[5], code[6], code[7]]))
}

/// The `win32u` indices the three handlers are registered under.
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

/// `user32!WIN_GetFullHandle` **is** `NtUserCallHwnd(hwnd, 0x0f)` — that is the
/// whole function, which is what fixes selector `0x0f` as `GetFullWindowHandle`.
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

    // `WIN_GetFullHandle` is a static, so find it by its whole body instead of
    // by name — which is the stronger check anyway, because the body *is* the
    // claim: sub rsp,0x28 / mov edx,0xf / call [rip+d] / mov eax,eax /
    // add rsp,0x28 / ret. Nothing but the selector and the IAT slot varies.
    let head = [0x48, 0x83, 0xEC, 0x28, 0xBA, 0x0F, 0x00, 0x00, 0x00, 0xFF, 0x15];
    let at = text
        .data
        .windows(head.len())
        .position(|w| w == head)
        .expect("user32 contains WIN_GetFullHandle's body: it asks selector 0x0f and nothing else");
    let tail = &text.data[at + head.len() + 4..at + head.len() + 4 + 7];
    assert_eq!(
        tail,
        // mov eax,eax ; add rsp,0x28 ; ret  — the answer *is* the handle,
        // zero-extended: this selector returns an HWND, not a BOOL.
        &[0x89, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3],
        "…and returns what the selector answered, widened to the full handle"
    );
}

/// `SetPropW`/`GetPropW` are **bare tail-jumps** into their syscalls, so the
/// arguments arrive in the order `(hwnd, str, handle)` untouched — which is what
/// lets exemu read them straight out of the syscall register slots.
#[test]
fn the_prop_apis_tail_jump_straight_into_their_syscalls() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    for name in ["SetPropW", "GetPropW"] {
        let Some(code) = export_bytes(&u, name, 0x10) else { continue };
        // `48 ff 25 <disp32>` = `jmp qword ptr [rip+disp]` as the *first*
        // instruction: no prologue, no argument shuffling.
        assert_eq!(
            &code[0..3],
            &[0x48, 0xFF, 0x25],
            "{name} is a bare tail-jump into its syscall"
        );
    }
}

// ===========================================================================
// W6.2 (second pass) — the GDI bitmap object model and icon/cursor objects.
// ===========================================================================

/// The `win32u` indices the W6.2 bitmap/icon handlers are registered under,
/// re-derived from `win32u.dll`'s own stubs on every run.
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
    // All distinct: a copy-paste that duplicated an index would otherwise pass.
    let all = [
        0x10aeu32, 0x10a7, 0x10ad, 0x10b0, 0x126b, 0x11f4, 0x11c7, 0x1548, 0x1403, 0x1404, 0x13c5,
        0x137f, 0x133d,
    ];
    assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
}

/// **`NtUserCallOneParam_CreateCursorIcon` is code 0**, and the proof is a pair
/// of bodies in the pinned `user32.dll` read against each other.
///
/// `GetSystemMetrics` is the calibration: its whole body is
/// `sub rsp,0x28 / mov edx,9 / movsxd rcx,ecx / call [rip+d] / add rsp,0x28 /
/// ret`, which fixes the ABI as `NtUserCallOneParam(param /*rcx*/,
/// code /*edx*/)` and fixes `GetSystemMetrics` at **9** — a value exemu already
/// depended on. `create_cursoricon_object` then does the same call with
/// `xor edx,edx`, i.e. **code 0**, and treats a zero answer as total failure:
///
/// ```text
///   mov  dword [rsp+0x20], 0x2080000   ; the module UNICODE_STRING it will fill
///   xor  edx, edx                      ; code = 0
///   call qword [rip+d]                 ; NtUserCallOneParam
///   and  eax, 0xffffffff
///   mov  rbp, rax
///   je   <return NULL>
/// ```
///
/// That `je` is why every `LoadIcon`/`LoadCursor` in the process failed while
/// the index was unserviced, and why this test pins the number rather than
/// trusting a remembered enumeration.
#[test]
fn create_cursor_icon_is_call_one_param_code_zero() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");

    // 1. The calibration, from an export whose code is the entire function.
    let gsm = export_bytes(&u, "GetSystemMetrics", 0x10).expect("user32 exports GetSystemMetrics");
    assert_eq!(
        &gsm[0..9],
        // sub rsp,0x28 ; mov edx,9 ; movsxd rcx,ecx
        &[0x48, 0x83, 0xEC, 0x28, 0xBA, 0x09, 0x00, 0x00, 0x00],
        "GetSystemMetrics is CallOneParam with code 9 in edx and the param in rcx"
    );
    assert_eq!(&gsm[9..12], &[0x48, 0x63, 0xC9], "…sign-extending the caller's int index");
    assert_eq!(&gsm[12..14], &[0xFF, 0x15], "…and then calls straight through the IAT");

    // 2. `create_cursoricon_object`'s allocation, found by its own body — the
    //    only site in user32 that pairs this constant with `xor edx,edx`.
    let image = exemu_loader::parse(&u).expect("user32 parses");
    let text = image.sections.iter().find(|s| s.name.starts_with(".text")).expect(".text");
    // `mov dword [rsp+0x20], 0x02080000` — MAX_PATH*2 as a UNICODE_STRING
    // MaximumLength, which is the buffer it is about to fill with the module
    // name for `NtUserSetCursorIconData`.
    let anchor = [0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x08, 0x02];
    let at = text
        .data
        .windows(anchor.len())
        .position(|w| w == anchor)
        .expect("user32 contains create_cursoricon_object's module-name UNICODE_STRING setup");
    let window = &text.data[at..(at + 0x40).min(text.data.len())];
    // `xor edx,edx` (code 0) followed, within the same window, by the indirect
    // call — and *no* `mov edx,imm32` in between that would set another code.
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

/// **`NtUserGetIconSize` reports the height doubled.** Its only caller,
/// `user32!get_icon_size`, halves what it gets back before returning it, so a
/// handler that answered the plain height would give every caller a half-height
/// icon — silently, since nothing else in the chain checks.
///
/// The body pinned here is
/// `call NtUserGetIconSize / test eax,eax / je / mov ecx,[rbx+4] /
/// mov edx,ecx / shr edx,31 / add edx,ecx / sar edx,1 / mov [rbx+4],edx`
/// — a signed divide by two applied to the **second** `LONG` of the caller's
/// `SIZE`, which is the one the syscall's `height` out-parameter fills.
#[test]
fn get_icon_size_halves_the_height_the_syscall_reports() {
    if !present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let u = dll("user32.dll");
    let image = exemu_loader::parse(&u).expect("user32 parses");
    let text = image.sections.iter().find(|s| s.name.starts_with(".text")).expect(".text");

    // The halving sequence, applied to `[rbx+4]` — the `cy` the syscall filled.
    let halve = [
        0x8B, 0x4B, 0x04, // mov ecx,[rbx+4]
        0x89, 0xCA, // mov edx,ecx
        0xC1, 0xEA, 0x1F, // shr edx,31
        0x01, 0xCA, // add edx,ecx
        0xD1, 0xFA, // sar edx,1
        0x89, 0x53, 0x04, // mov [rbx+4],edx
    ];
    let at = text
        .data
        .windows(halve.len())
        .position(|w| w == halve)
        .expect("user32!get_icon_size halves the height NtUserGetIconSize reported");

    // And that sequence really does follow the call: the 16 bytes before it are
    // `call qword [rip+d] / test eax,eax / je +N`.
    let before = &text.data[at - 10..at];
    assert_eq!(&before[0..2], &[0xFF, 0x15], "…immediately after the syscall call");
    assert_eq!(&before[6..8], &[0x85, 0xC0], "…guarded by test eax,eax");
    assert_eq!(before[8], 0x74, "…and skipped when the syscall failed");
}
