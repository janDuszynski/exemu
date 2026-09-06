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
fn driving_the_dialog_reaches_the_text_layout_path_and_stops_there() {
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

    let (driven, _) = run_on_wine_picking("pick", Some(comdlg_sample::PICK_FILE_NAME));
    let err = match driven {
        Ok(res) => {
            let r = report(&res.stdout);
            panic!(
                "the drive no longer faults — re-baseline this test to the positive \
                 assertion: OPEN must be the path comdlg32 resolved and READ must be \
                 {PICK_CONTENT:?}. Got exit={} {r:?}",
                res.exit_code
            )
        }
        Err(e) => e.to_string(),
    };
    eprintln!("comdlg wine drive: {err}");
    assert!(
        err.contains("0xc0000005"),
        "the wall is an access violation in gdi32's bundled Uniscribe, not something \
         else: {err}"
    );
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
