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
