use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use exemu_app::{comdlg_sample, load_and_run, Process, RunConfig};
use exemu_gui::{DriverCall, RecordingDriver};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn wine_dlls_present() -> bool {
    Path::new(WINE_DLLS).join("comdlg32.dll").exists()
        && Path::new(WINE_DLLS).join("win32u.dll").exists()
}

fn seeded_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("exemu-comdlg-gate-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let docs = dir.join("C").join("Users").join("exemu").join("Documents");
    std::fs::create_dir_all(&docs).expect("seed the sandbox profile tree");
    std::fs::write(docs.join(comdlg_sample::PICK_FILE_NAME), PICK_CONTENT)
        .expect("seed the file the dialog is meant to return");
    dir
}

const PICK_CONTENT: &str = "exemu-comdlg-pick-payload";

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

fn assert_no_hollow_success(r: &HashMap<String, String>) {
    for (ret, path, who) in [
        (comdlg_sample::TAG_OPEN_RET, comdlg_sample::TAG_OPEN, "GetOpenFileNameW"),
        (comdlg_sample::TAG_SAVE_RET, comdlg_sample::TAG_SAVE, "GetSaveFileNameW"),
    ] {
        if num(r, ret) != 0 {
            assert!(
                !tag(r, path).is_empty(),
                "{who} returned TRUE with an empty buffer — a HOLLOW SUCCESS, and worse \
                 than the FALSE it replaces, because a real app treats an empty path as a \
                 valid selection. Got {r:?}"
            );
        }
    }
}

fn dialog_sizes(calls: &[DriverCall]) -> Vec<(i32, i32)> {
    calls
        .iter()
        .filter_map(|c| match c {
            DriverCall::CreateWindow { params, .. } if params.class_name == "#32770" => {
                Some((params.cx, params.cy))
            }
            _ => None,
        })
        .collect()
}

fn assert_both_dialogs_laid_out(calls: &[DriverCall], state: &str) {
    let sizes = dialog_sizes(calls);
    assert_eq!(sizes.len(), 2, "comdlg32 built both dialogs. Got {sizes:?}. {state}");
    assert!(
        sizes.iter().all(|&(cx, cy)| cx > 0 && cy > 0),
        "the first dialog opens before any window exists, so DIALOG_CreateIndirect measures its \
         font on GetDC(NULL); without a screen DC there it lays the dialog out 0x0. Got {sizes:?}. {state}"
    );
    assert_eq!(sizes[0], sizes[1], "both legs lay out the same template alike. {state}");
}

fn run_on_wine(tag: &str) -> (exemu_app::RunResult, Vec<DriverCall>) {
    let (res, calls) = run_on_wine_picking(tag, None);
    (res.expect("the comdlg sample runs to completion on the Wine boot"), calls)
}

type PickedRun = (exemu_core::Result<exemu_app::RunResult>, Vec<DriverCall>);

fn run_on_wine_picking(tag: &str, pick: Option<&str>) -> PickedRun {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = std::sync::mpsc::channel::<exemu_core::InputEvent>();
    drop(tx);
    let res = load_and_run(
        &comdlg_sample::build(),
        RunConfig {
            echo: false,
            max_steps: 200_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(seeded_sandbox(tag)),
            input: Some(rx),
            driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
            file_dialog_pick: pick.map(str::to_string),
            ..RunConfig::default()
        },
    );
    let calls = log.lock().unwrap().clone();
    (res, calls)
}

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
    assert_no_hollow_success(&r);
    assert_eq!(tag(&r, comdlg_sample::TAG_OPEN), "", "nothing filled lpstrFile");
    assert_eq!(num(&r, comdlg_sample::TAG_OPEN_RET), 0, "…and the thunk said so, with FALSE");
    assert_eq!(num(&r, comdlg_sample::TAG_SAVE_RET), 0, "…on the save leg too");
    assert_eq!(tag(&r, comdlg_sample::TAG_READ), "", "so there was no path to open");
    assert_eq!(
        res.exit_code, 4,
        "open FALSE + empty path + empty read + save FALSE, and nothing else"
    );
    assert_eq!(
        num(&r, comdlg_sample::TAG_BAD_SIZE),
        0,
        "an unimplemented thunk cannot produce CDERR_STRUCTSIZE"
    );
}

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
    assert!(
        res.steps > 1_000_000,
        "the run booted the Wine DLL set (got {} steps)",
        res.steps
    );
}

#[test]
fn wine_get_open_file_name_w_accepts_exactly_two_struct_sizes() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let bytes = std::fs::read(Path::new(WINE_DLLS).join("comdlg32.dll")).expect("read comdlg32");
    let code = export_bytes(&bytes, "GetOpenFileNameW", 0x40)
        .expect("comdlg32 exports GetOpenFileNameW as code, not a forwarder");

    let and_at = find(&code, &[0x83, 0xE0, 0xEF]).expect("the prologue masks lStructSize with ~0x10");
    let cmp_at =
        find(&code, &[0x3D, 0x88, 0x00, 0x00, 0x00]).expect("…and compares the result with 0x88");
    assert!(and_at < cmp_at, "the mask precedes the comparison");

    let accepted = |n: u32| n & !0x10 == 0x88;
    assert!(accepted(comdlg_sample::OPENFILENAMEW_SIZE), "0x98 is accepted");
    assert!(accepted(0x88), "the legacy 0x88 is accepted too");
    assert!(!accepted(comdlg_sample::BAD_STRUCT_SIZE), "0x99 is not — which is the point");
}

#[test]
fn wine_file_dialog_is_built_but_never_completes() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let (res, calls) = run_on_wine("gap");
    let r = report(&res.stdout);
    eprintln!("comdlg wine gap: exit={} steps={} {r:?}", res.exit_code, res.steps);

    assert_no_hollow_success(&r);
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

    assert_eq!(
        created.iter().filter(|c| **c == "#32770").count(),
        2,
        "both legs build comdlg32's own dialog template. Got {created:?}"
    );

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

    assert_eq!(num(&r, comdlg_sample::TAG_OPEN_RET), 0, "no path came back, so the answer is FALSE");
    assert_eq!(num(&r, comdlg_sample::TAG_SAVE_RET), 0, "and the save leg cancels the same way");
    assert_eq!(
        res.exit_code, 5,
        "the five honest failures of a dialog nobody completed — a LOWER number is not \
         progress, it is a hollow success. Got {r:?}"
    );
}

#[test]
fn driving_both_dialogs_opens_the_first_pick_and_saves_to_the_second() {
    if !wine_dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} not present (the Wine DLL set is git-ignored)");
        return;
    }
    let (undriven, _) = run_on_wine_picking("nopick", None);
    let undriven = undriven.expect("with no pick configured the run completes");
    assert_eq!(tag(&report(&undriven.stdout), comdlg_sample::TAG_OPEN), "");
    assert!(
        undriven.steps > 30_000_000,
        "the undriven run builds and tears down the whole dialog (got {})",
        undriven.steps
    );

    let picks = format!("{}|{}", comdlg_sample::PICK_FILE_NAME, comdlg_sample::SAVE_FILE_NAME);
    let (driven, calls) = run_on_wine_picking("pick", Some(&picks));
    let res = driven.unwrap_or_else(|e| {
        panic!(
            "the driven dialog must run to completion. 0xc0000005 at 0x10 in \
             comctl32!COMBOEX_ComboWndProc means CallWindowProcW lost its LRESULT again: \
             NtUserCallWindowProc must fill win_proc_params and answer TRUE, not call the \
             procedure itself. {e}"
        )
    });
    let r = report(&res.stdout);
    eprintln!("comdlg wine drive: exit={} steps={} {r:?}", res.exit_code, res.steps);

    assert_both_dialogs_laid_out(&calls, &format!("{r:?}"));
    assert_no_hollow_success(&r);
    assert_eq!(num(&r, comdlg_sample::TAG_OPEN_RET), 1, "GetOpenFileNameW answered TRUE");
    assert_eq!(
        tag(&r, comdlg_sample::TAG_OPEN),
        format!(r"{}\{}", comdlg_sample::INITIAL_DIR, comdlg_sample::PICK_FILE_NAME),
        "comdlg32 resolved the typed name against the initial directory"
    );
    assert_eq!(num(&r, comdlg_sample::TAG_OPEN_ERR), 0);
    assert_eq!(
        tag(&r, comdlg_sample::TAG_READ),
        PICK_CONTENT,
        "the path it returned opens the seeded file"
    );

    assert_eq!(num(&r, comdlg_sample::TAG_SAVE_RET), 1, "GetSaveFileNameW answered TRUE");
    assert_eq!(
        tag(&r, comdlg_sample::TAG_SAVE),
        format!(r"{}\{}", comdlg_sample::INITIAL_DIR, comdlg_sample::SAVE_FILE_NAME),
        "the second dialog took the second pick, so no overwrite prompt stood in the way"
    );
    assert_eq!(num(&r, comdlg_sample::TAG_SAVE_ERR), 0);
    assert_eq!(num(&r, comdlg_sample::TAG_WROTE), comdlg_sample::SAVE_PAYLOAD.len() as u32);
    let saved = Path::new(&res.sandbox)
        .join("C")
        .join("Users")
        .join("exemu")
        .join("Documents")
        .join(comdlg_sample::SAVE_FILE_NAME);
    assert_eq!(
        std::fs::read_to_string(&saved).unwrap_or_default(),
        comdlg_sample::SAVE_PAYLOAD,
        "the guest wrote its payload through the path the save dialog returned ({})",
        saved.display()
    );
    assert_eq!(res.exit_code, 0, "both dialogs completed and nothing failed. Got {r:?}");
}

fn peek_wstr(proc: &Process, at: u64, max: u64) -> String {
    let units: Vec<u16> = (0..max)
        .map(|i| {
            let lo = proc.peek_u8(at + i * 2).unwrap_or(0) as u16;
            let hi = proc.peek_u8(at + i * 2 + 1).unwrap_or(0) as u16;
            lo | hi << 8
        })
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn peek_astr(proc: &Process, at: u64, len: u32) -> String {
    let bytes: Vec<u8> = (0..len as u64).map(|i| proc.peek_u8(at + i).unwrap_or(0)).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn a_32bit_guest_drives_both_dialogs_through_wow64() {
    if !wine_dlls_present() || !Path::new(WINE_DLLS32).join("comdlg32.dll").exists() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    use comdlg_sample::wow64::{self as s, data};

    let sandbox = seeded_sandbox("wow64");
    let log = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = std::sync::mpsc::channel::<exemu_core::InputEvent>();
    drop(tx);
    let mut cfg = RunConfig {
        echo: false,
        max_steps: 400_000_000,
        wine_boot_dir: Some(WINE_DLLS.to_string()),
        sandbox_root: Some(sandbox.clone()),
        input: Some(rx),
        driver: Some(Box::new(RecordingDriver::new(Arc::clone(&log)))),
        file_dialog_pick: Some(format!(
            "{}|{}",
            comdlg_sample::PICK_FILE_NAME,
            comdlg_sample::SAVE_FILE_NAME
        )),
        ..RunConfig::default()
    };
    let mut proc = Process::load(&s::build(), &mut cfg).expect("the PE32 guest boots on WoW64");
    assert!(proc.wow64().is_some(), "a PE32 on the Wine boot is a WoW64 process");
    let run = proc.run_borrowed();
    let u32_at = |off: u32| proc.peek_u32(s::data_va(off)).unwrap_or(u32::MAX);
    let open = peek_wstr(&proc, s::data_va(data::OPEN_BUF), 260);
    let save = peek_wstr(&proc, s::data_va(data::SAVE_BUF), 260);
    let read_len = u32_at(data::READ_COUNT).min(data::READ_BUF_LEN);
    let read = peek_astr(&proc, s::data_va(data::READ_BUF), read_len);
    let state = format!(
        "open_ret={} open_err={} open={open:?} read={read:?} save_ret={} save_err={} save={save:?} wrote={}",
        u32_at(data::OPEN_RET),
        u32_at(data::OPEN_ERR),
        u32_at(data::SAVE_RET),
        u32_at(data::SAVE_ERR),
        u32_at(data::WROTE)
    );
    let res = run.unwrap_or_else(|e| panic!("the WoW64 drive must run to completion: {e}\n{state}"));
    eprintln!("comdlg wow64 drive: exit={} steps={} {state}", res.exit_code, res.steps);

    assert_both_dialogs_laid_out(&log.lock().unwrap(), &state);
    assert_eq!(u32_at(data::OPEN_RET), 1, "GetOpenFileNameW answered TRUE. {state}");
    assert_eq!(
        open,
        format!(r"{}\{}", comdlg_sample::INITIAL_DIR, comdlg_sample::PICK_FILE_NAME),
        "{state}"
    );
    assert_eq!(read, PICK_CONTENT, "the 32-bit guest opened the seeded file through it. {state}");
    assert_eq!(u32_at(data::SAVE_RET), 1, "GetSaveFileNameW answered TRUE. {state}");
    assert_eq!(
        save,
        format!(r"{}\{}", comdlg_sample::INITIAL_DIR, comdlg_sample::SAVE_FILE_NAME),
        "{state}"
    );
    assert_eq!(u32_at(data::WROTE), comdlg_sample::SAVE_PAYLOAD.len() as u32, "{state}");
    let saved = sandbox
        .join("C")
        .join("Users")
        .join("exemu")
        .join("Documents")
        .join(comdlg_sample::SAVE_FILE_NAME);
    assert_eq!(std::fs::read_to_string(&saved).unwrap_or_default(), comdlg_sample::SAVE_PAYLOAD);
}

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
    let all = [0x13d1u32, 0x13d8, 0x136b];
    assert_eq!(
        all.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "three distinct SSDT entries"
    );
}

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

fn syscall_index(bytes: &[u8], name: &str) -> Option<u32> {
    let code = export_bytes(bytes, name, 16)?;
    if code.len() < 8 || code[0..3] != [0x4C, 0x8B, 0xD1] || code[3] != 0xB8 {
        return None;
    }
    Some(u32::from_le_bytes([code[4], code[5], code[6], code[7]]))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
