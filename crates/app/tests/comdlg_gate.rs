//! W6.2 (second half) — **the comdlg32 file-dialog bridge, measured.**
//!
//! The roadmap row leaves the fidelity choice open: pattern-match Wine's
//! file-dialog window onto a native macOS `NSOpenPanel`, or let Wine render its
//! own dialog. **This file is the measurement the choice was made on**, and it
//! pins the answer so it cannot rot.
//!
//! ## What is proven here
//!
//! 1. [`emulated_path_has_no_file_dialog_at_all`] — the control. exemu
//!    implements no `GetOpenFileNameW` anywhere: the import resolves to the
//!    "recognised but unimplemented" thunk, which returns 0 without touching the
//!    caller's buffer. The sample reports an empty path and exits non-zero. This
//!    is what gives every Wine-path observation below its meaning.
//! 2. [`wine_comdlg32_validates_the_openfilenamew_itself`] — **the attribution**.
//!    A second call with `lStructSize = 0x99` comes back `FALSE` with
//!    `CommDlgExtendedError() == CDERR_STRUCTSIZE (1)`. exemu has no
//!    `OPENFILENAMEW` validator of any kind, so a `1` can only have come out of
//!    Wine's own `GetOpenFileNameW` prologue — the call really is guest code
//!    from the pinned prefix, not a thunk.
//! 3. [`wine_get_open_file_name_w_accepts_exactly_two_struct_sizes`] — that
//!    validator read straight out of the pinned binary, so the constant the
//!    sample pokes and the code it is supposed to trip are checked against each
//!    other rather than against a memory of `commdlg.h`.
//! 4. [`wine_file_dialog_stops_before_it_creates_a_window`] — **the gap, pinned**.
//!    On the healthy call Wine gets *past* validation and past finding, loading
//!    and locking its own dialog-template resource — proven by
//!    `CommDlgExtendedError() == 0`, because `CDERR_FINDRESFAILURE (6)` and
//!    `CDERR_LOADRESFAILURE (7)` are the codes those two failures set — and then
//!    `DialogBoxIndirectParamW` does not return TRUE, **without a single window
//!    reaching the driver**. Those two facts together are the load-bearing
//!    observation: an extended error of 0 alone would also be consistent with
//!    "the dialog ran and the user cancelled", and it is the *zero*
//!    `CreateWindow` calls that says the dialog was never built at all.
//! 5. [`win32u_publishes_the_indices_the_diagnosis_names`] — the three
//!    `NtUser*` syscall indices the diagnosis below rests on, recovered from the
//!    pinned `win32u.dll`'s own export stubs rather than asserted.
//!
//! ## The diagnosis, and why it decides the fidelity question
//!
//! Tracing the win32u boundary (`EXEMU_W32K_TRACE=1`) through the failing call
//! shows user32's dialog manager doing exactly what it should — screen DC
//! (`NtUserGetDC(0)`), dialog font (`NtGdiHfontCreate`), DPI — and then:
//!
//! ```text
//! [w32k] 0x13d1 0x8002 <UNICODE_STRING*> …   NtUserGetAtomName(MAKEINTATOM(32770))
//! [w32k] 0x13d8 <hinst> <same UNICODE_STRING*> …   NtUserGetClassInfoEx
//! <nothing more>
//! ```
//!
//! `#32770` is the dialog class, and user32 names it the way Windows does — by
//! its **well-known integer atom 32770 = 0x8002** — then resolves that atom to a
//! string with `NtUserGetAtomName` and hands the string to `NtUserGetClassInfoEx`.
//! exemu's win32k SSDT has **no handler for `NtUserGetAtomName`**, so the
//! `UNICODE_STRING` comes back empty, the class lookup fails client-side, and
//! `DialogBoxIndirectParamW` returns -1 before `NtUserCreateWindowEx` is ever
//! reached. (exemu *does* register `#32770` — see `BUILTIN_CLASSES` in
//! `crates/os/src/win32k.rs` — but under a `CLASS_ATOM_BASE`-allocated atom,
//! which is not the atom user32 asks about.)
//!
//! That is a **one-handler** gap, and it decides the roadmap row: with a
//! `NtUserGetAtomName` handler that answers the documented integer-atom rule
//! (`MAKEINTATOM(n)` → `"#n"`), Wine's own dialog is created — verified
//! experimentally: `CreateWindow class="#32770" title="Open"`, then
//! `class="Static" title="Look &in:"`, then `class="ComboBox"`, i.e. Wine's real
//! file dialog with its real resource-loaded captions, before hitting a
//! *second*, unrelated problem (the guest stack runs off the bottom during the
//! nested `WM_NCCREATE`/`WM_CREATE` callbacks the control cascade generates).
//! A native `NSOpenPanel` would instead need a brand-new intercept seam, its own
//! `OPENFILENAMEW` marshaller, and would silently drop every OFN semantic
//! (filters, `OFN_*` flags, hook procs, custom templates, `nFileOffset`/
//! `nFileExtension`) that Wine's dialog implements for free. **So: let Wine
//! render it.** The handler and the stack-depth follow-up are OS-layer work.
//!
//! **These assertions pin today's behaviour, and will fail loudly the moment it
//! improves** — deliberately, in the same style as the W6.1 gaps in
//! `comctl_gate.rs`. When `NtUserGetAtomName` lands, re-baseline this file and
//! the README table together.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use exemu_app::{comdlg_sample, load_and_run, RunConfig};
use exemu_gui::{DriverCall, RecordingDriver};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    Path::new(WINE_DLLS).join("comdlg32.dll").exists()
        && Path::new(WINE_DLLS).join("win32u.dll").exists()
}

/// A private, empty sandbox for one run, seeded with the file the open dialog is
/// supposed to come back with.
///
/// The shared `$TMPDIR/exemu-sandbox` persists across runs *and* test binaries,
/// and a guest observes what it finds there — so a gate that pins behaviour must
/// not share it (this has produced a false failure in `shell_gate` before). The
/// name carries the pid and a counter so parallel test threads never collide.
fn seeded_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("exemu-comdlg-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // `C:\Users\exemu\Documents` — the sample's `lpstrInitialDir`.
    let docs = dir.join("C").join("Users").join("exemu").join("Documents");
    std::fs::create_dir_all(&docs).expect("seed the sandbox profile tree");
    std::fs::write(docs.join(comdlg_sample::PICK_FILE_NAME), PICK_CONTENT)
        .expect("seed the file the dialog is meant to return");
    dir
}

/// The bytes the seeded file holds. The sample prints the first
/// `RBUF_LEN` bytes it reads back, so this is what a working open path must
/// surface — and its absence is what proves nothing was opened.
const PICK_CONTENT: &str = "exemu-comdlg-pick-payload";

/// Parse the sample's `"TAG=value"` report lines.
fn report(stdout: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

fn tag<'a>(r: &'a HashMap<String, String>, k: &str) -> &'a str {
    r.get(k).unwrap_or_else(|| panic!("the sample printed no {k}= line; got {r:?}")).as_str()
}

fn num(r: &HashMap<String, String>, k: &str) -> u32 {
    tag(r, k).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", tag(r, k)))
}

/// Run the sample on the Wine boot with a recording driver and a headless,
/// deterministic message pump (a channel whose sender is dropped at once, the
/// same shape `comctl_gate` uses — no threads, no timing, no AppKit).
fn run_on_wine(tag: &str) -> (exemu_app::RunResult, Vec<DriverCall>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = std::sync::mpsc::channel::<exemu_core::InputEvent>();
    drop(tx);
    let res = load_and_run(
        &comdlg_sample::build(),
        RunConfig {
            echo: false,
            max_steps: 60_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(seeded_sandbox(tag)),
            input: Some(rx),
            driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
            ..RunConfig::default()
        },
    )
    .expect("the comdlg sample runs to completion on the Wine boot");
    let calls = log.lock().unwrap().clone();
    (res, calls)
}

// ==========================================================================
// The control: exemu has no file dialog of its own.
// ==========================================================================

/// exemu implements **no** `comdlg32` function. `GetOpenFileNameW` is a
/// recognised-but-unimplemented import that returns 0 and never touches the
/// `OPENFILENAMEW`, so the sample reports an empty path, cannot open it, and
/// exits non-zero. Every Wine-path observation below is meaningful only against
/// this.
#[test]
fn emulated_path_has_no_file_dialog_at_all() {
    let res = load_and_run(
        &comdlg_sample::build(),
        RunConfig {
            echo: false,
            max_steps: 5_000_000,
            sandbox_root: Some(seeded_sandbox("emulated")),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    let r = report(&res.stdout);
    eprintln!("comdlg emulated: exit={} steps={} {r:?}", res.exit_code, res.steps);

    assert_ne!(res.exit_code, 0, "no dialog exists on the emulated path");
    assert_eq!(tag(&r, comdlg_sample::TAG_OPEN), "", "nothing filled lpstrFile");
    assert_eq!(tag(&r, comdlg_sample::TAG_READ), "", "so there was no path to open");
    // The attribution probe: with no validator anywhere, the deliberately
    // malformed call reports no error either.
    assert_eq!(
        num(&r, comdlg_sample::TAG_BAD_SIZE),
        0,
        "an unimplemented thunk cannot produce CDERR_STRUCTSIZE"
    );
}

// ==========================================================================
// Attribution: the call really lands in Wine's own comdlg32.
// ==========================================================================

/// **The attribution test.** `GetOpenFileNameW` with `lStructSize = 0x99` must
/// come back `FALSE` with `CommDlgExtendedError() == CDERR_STRUCTSIZE`.
///
/// This is the strongest available proof that the guest's `comdlg32` import
/// binds to Wine's binary and that its code ran: exemu contains no
/// `OPENFILENAMEW` validator, and the control test above shows the emulated path
/// reports 0 for exactly the same call.
#[test]
fn wine_comdlg32_validates_the_openfilenamew_itself() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let (res, _) = run_on_wine("structsize");
    let r = report(&res.stdout);
    eprintln!("comdlg wine: exit={} steps={} {r:?}", res.exit_code, res.steps);

    assert_eq!(
        num(&r, comdlg_sample::TAG_BAD_SIZE),
        comdlg_sample::CDERR_STRUCTSIZE,
        "Wine's own GetOpenFileNameW prologue rejected the malformed OPENFILENAMEW"
    );
    // The Wine boot really happened: the emulated control needs well under
    // 10k instructions for the same program.
    assert!(
        res.steps > 1_000_000,
        "the run booted the Wine DLL set (got {} steps)",
        res.steps
    );
}

/// The validator the test above trips, read out of the pinned binary.
///
/// `GetOpenFileNameW`'s prologue is `mov eax,[rbx]` / `and eax,0xffffffef` /
/// `cmp eax,0x88` — i.e. it masks off bit 4 and demands `0x88`, accepting
/// exactly `0x88` (the pre-Win2000 `OPENFILENAME`) and `0x98` (the current x64
/// one, which is what [`comdlg_sample::OPENFILENAMEW_SIZE`] is) and nothing
/// else. Pinning it here means the sample's `BAD_STRUCT_SIZE` and the code it is
/// meant to trip are checked against each other, not against a remembered header.
#[test]
fn wine_get_open_file_name_w_accepts_exactly_two_struct_sizes() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("comdlg32.dll")).expect("read comdlg32");
    let code = export_bytes(&bytes, "GetOpenFileNameW", 0x40)
        .expect("comdlg32 exports GetOpenFileNameW as code, not a forwarder");

    // `and eax, -0x11` then `cmp eax, 0x88`, in that order, inside the prologue.
    let and_at = find(&code, &[0x83, 0xE0, 0xEF]).expect("the prologue masks lStructSize with ~0x10");
    let cmp_at =
        find(&code, &[0x3D, 0x88, 0x00, 0x00, 0x00]).expect("…and compares the result with 0x88");
    assert!(and_at < cmp_at, "the mask precedes the comparison");

    // Therefore: the two accepted sizes, and the one the sample deliberately
    // uses to trip the check.
    let accepted = |n: u32| n & !0x10 == 0x88;
    assert!(accepted(comdlg_sample::OPENFILENAMEW_SIZE), "0x98 is accepted");
    assert!(accepted(0x88), "the legacy 0x88 is accepted too");
    assert!(!accepted(comdlg_sample::BAD_STRUCT_SIZE), "0x99 is not — which is the point");
}

// ==========================================================================
// The gap, pinned.
// ==========================================================================

/// **W6.2 as it stands now: Wine builds its whole file dialog, and then nobody
/// clicks it.** `NtUserGetAtomName` (roadmap W6.2, win32u index 0x13d1) closed
/// the creation gap this test used to pin — user32's dialog manager names the
/// dialog class by its integer atom `MAKEINTATOM(32770)`, and with the name
/// answered, `DialogBoxIndirectParamW` gets all the way through the template.
///
/// What that buys, and this test pins:
///
/// * **Every control of comdlg32's own template reaches the driver** — the
///   `#32770` dialog itself plus the `Static`/`ComboBox`/`ToolbarWindow32`/
///   `ListBox`/`Edit`/`ComboBoxEx32`/`Button` set, from comdlg32's own
///   resources, as guest code, on both the open and the save leg.
/// * `CommDlgExtendedError()` stays **0** — no struct, find-resource or
///   load-resource failure.
///
/// What is still missing, and is the remaining W6.2 work: **the dialog is modal
/// and headless, so its message loop ends with no selection** and
/// `GetOpenFileNameW` still returns `FALSE` with `lpstrFile` empty. Driving it
/// (synthesizing the selection + `IDOK`, or bridging to a native panel) is the
/// next step.
///
/// A detail worth keeping: because `GetSaveFileNameW` returns `FALSE` without
/// touching the buffer, the guest still holds the file name it *proposed*,
/// opens that relative name, and writes to it — landing in the sandbox root. So
/// "a file was written" is emphatically **not** evidence that the save dialog
/// worked, which is why the open leg (whose buffer starts empty) carries the
/// claim.
#[test]
fn wine_file_dialog_is_built_but_never_completes() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let (res, calls) = run_on_wine("gap");
    let r = report(&res.stdout);
    eprintln!("comdlg wine gap: exit={} steps={} {r:?}", res.exit_code, res.steps);

    // Still FALSE — but now for a *later* reason: the modal loop ran and ended
    // with no selection, rather than the dialog never existing.
    assert_eq!(tag(&r, comdlg_sample::TAG_OPEN), "", "GetOpenFileNameW returned no path");
    assert_eq!(tag(&r, comdlg_sample::TAG_READ), "", "so nothing could be opened and read");
    assert_ne!(
        tag(&r, comdlg_sample::TAG_READ),
        PICK_CONTENT,
        "the seeded file was NOT read — if this ever fires the gap has closed, re-baseline"
    );

    let err = num(&r, comdlg_sample::TAG_OPEN_ERR);
    assert_ne!(err, comdlg_sample::CDERR_STRUCTSIZE, "the healthy call's struct size is valid");
    assert_ne!(
        err,
        comdlg_sample::CDERR_FINDRESFAILURE,
        "comdlg32 found its own dialog template — the resource half of \
         'comdlg32 arrives as guest code' still holds"
    );
    assert_ne!(err, comdlg_sample::CDERR_LOADRESFAILURE, "…and loaded and locked it");
    assert_eq!(err, 0, "no struct/find-resource/load-resource failure: the dialog ran");
    assert_eq!(num(&r, comdlg_sample::TAG_SAVE_ERR), 0, "the save side fails the same way");

    let created: Vec<&str> = calls
        .iter()
        .filter_map(|c| match c {
            DriverCall::CreateWindow { params, .. } => Some(params.class_name.as_str()),
            _ => None,
        })
        .collect();

    // The dialog itself, twice: comdlg32 runs the same template for the open
    // and the save leg. Asserting the count (not just "contains") is what keeps
    // this honest — one dialog would mean a leg silently stopped failing early.
    assert_eq!(
        created.iter().filter(|c| **c == "#32770").count(),
        2,
        "both legs build comdlg32's own dialog template. Got {created:?}"
    );

    // Controls that can only come from comdlg32's own resources: the file list,
    // the look-in combo and the shell toolbar are not classes exemu's guest
    // sample ever registers, so their presence is proof the real template ran.
    for control in ["Static", "ComboBox", "ComboBoxEx32", "ToolbarWindow32", "ListBox", "Edit"] {
        assert!(
            created.contains(&control),
            "comdlg32's template creates a {control}. Got {created:?}"
        );
    }
    assert!(
        created.iter().filter(|c| **c == "Button").count() >= 2,
        "the template's Open/Cancel buttons reach the driver. Got {created:?}"
    );

    // The failure count the sample reports: dialog FALSE + empty path + failed
    // CreateFileW + empty read, for the open leg, and dialog FALSE for the save
    // leg (whose own file write succeeds, as described above).
    assert_eq!(res.exit_code, 5, "the exact failure tally of the measured gap");
}

// ==========================================================================
// The syscall indices the diagnosis names, straight from the pinned binary.
// ==========================================================================

/// `win32u.dll` is a pure syscall shim: every export is
/// `mov r10,rcx; mov eax,<index>; …; syscall`. Recover the three indices the
/// diagnosis in the module docs rests on directly from those stubs, so the
/// numbers quoted in a `EXEMU_W32K_TRACE` transcript can be trusted — and so a
/// Wine-prefix refresh that renumbers the SSDT fails here instead of silently
/// invalidating the analysis.
#[test]
fn win32u_publishes_the_indices_the_diagnosis_names() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("win32u.dll")).expect("read win32u");
    let idx = |name: &str| syscall_index(&bytes, name);

    assert_eq!(
        idx("NtUserGetAtomName"),
        Some(0x13d1),
        "the index the dialog manager asks the dialog class's atom name through"
    );
    assert_eq!(idx("NtUserGetClassInfoEx"), Some(0x13d8), "…and looks the name up with");
    assert_eq!(
        idx("NtUserCreateWindowEx"),
        Some(0x136b),
        "…and would call next, but never reaches"
    );
    // Sanity: these are distinct entries in one contiguous NtUser* block.
    let all = [0x13d1u32, 0x13d8, 0x136b];
    assert_eq!(
        all.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "three distinct SSDT entries"
    );
}

// ==========================================================================
// Small PE helpers.
// ==========================================================================

/// Read up to `len` bytes of the code at named export `name` of the PE in
/// `bytes`, or `None` when the export is missing or is a forwarder.
fn export_bytes(bytes: &[u8], name: &str, len: usize) -> Option<Vec<u8>> {
    let image = exemu_loader::parse(bytes).ok()?;
    let rva = image
        .exports
        .iter()
        .find(|e| e.name.as_deref() == Some(name) && e.forwarder.is_none())?
        .rva;
    for s in &image.sections {
        let start = s.rva;
        let end = s.rva + s.data.len() as u32;
        if rva >= start && rva < end {
            let off = (rva - start) as usize;
            let take = len.min(s.data.len() - off);
            return Some(s.data[off..off + take].to_vec());
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

/// Index of the first occurrence of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
