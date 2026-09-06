//! Where the comctl6 side-by-side assembly actually lives (roadmap W6.1).
//!
//! With Wine's own diagnostics on, a WoW64 guest that declares the standard
//! themed-controls dependency reports:
//!
//! ```text
//! fixme:actctx:parse_depend_manifests Could not find dependent assembly
//!     L"Microsoft.Windows.Common-Controls" (6.0.0.0)
//! ```
//!
//! and the fallback is real rather than cosmetic. Wine 11.0 ships **two**
//! comctl32 builds — `comctl32.dll` (`__WINE_COMCTL32_VERSION=5`) and
//! `comctl32_v6.dll` (`=6`) — and only the v6 one compiles the themed
//! replacements for the user32 built-ins (`button.c`, `combo.c`, `edit.c`,
//! `listbox.c`, `static.c`) plus `syslink.c` and `taskdialog.c`, and only it
//! delay-imports `uxtheme`. A guest that does not get the assembly gets v5.
//!
//! **The pinned prefix does ship the assembly.** It is not a loose file: Wine
//! embeds it in the v6 DLL as an `RT_MANIFEST` resource *named*
//! `WINE_MANIFEST`, and materialises the WinSxS store from there at prefix
//! creation (`dlls/setupapi/fakedll.c::register_manifest`, driven by
//! `wineboot --update`), writing
//! `%WINDIR%\winsxs\manifests\<key>.manifest` and copying the DLL to
//! `%WINDIR%\winsxs\<key>\<file name>`.
//!
//! **exemu now runs that step** — [`exemu_app::winsxs::stage_comctl6`], driven
//! from `Process::load` next to the `winecoreaudio.drv` staging. The first four
//! tests pin the *recovery* half (the assembly is in the prefix and exemu's
//! loader can read and parse it); the last three pin the *staging* half and the
//! end-to-end consequence:
//!
//! * [`staging_writes_the_store_the_loaders_filter_finds`] — the two files land
//!   under the exact key, the manifest is the resource verbatim, and the payload
//!   is **byte-identical to `comctl32_v6.dll`** and not to the v5 build.
//! * [`only_the_v6_build_exports_the_themed_entry_points`] — the export-level
//!   difference the whole thing is for, read out of the two pinned binaries, so
//!   the guest-side assertion below has a falsifiable meaning.
//! * [`a_wow64_guest_loads_comctl32_v6_out_of_the_store`] — the gate: a real
//!   corpus guest that declares the dependency loads `comctl32.dll` **from the
//!   winsxs assembly directory**, and the image Wine mapped exports
//!   `TaskDialogIndirect`, which only the v6 build has. Both facts are read out
//!   of the guest's own `PEB32.Ldr` and the mapped image, not off the host disk.

use exemu_app::winsxs;
use exemu_loader::{
    find_resource, list_resources, parse_activation_context_from_manifest, ResourceName, LANG_ANY,
    RT_MANIFEST,
};

const PREFIX64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const PREFIX32: &str = "../../example_exe/wine-dlls/i386-windows";

/// The resource name Wine's own prefix-creation step looks for. It matches by
/// prefix (`wcsncmp(res_name, L"WINE_MANIFEST", 13)`), so a DLL may publish
/// several.
const WINE_MANIFEST: &str = "WINE_MANIFEST";

fn read(dir: &str, leaf: &str) -> Option<Vec<u8>> {
    std::fs::read(std::path::Path::new(dir).join(leaf)).ok()
}

/// The production key builder — [`winsxs::sxs_key`], the one
/// [`winsxs::stage_comctl6`] writes the store with. Using it here rather than a
/// second copy is deliberate: the assertions below are then a pin on the code
/// that actually runs, not on a transcription of it.
use exemu_app::winsxs::sxs_key;

#[test]
fn the_winsxs_key_matches_wines_own_naming() {
    // Hermetic: no prefix needed. This is the exact name `lookup_winsxs` finds
    // through its `…_6.0.*.*_*_*.manifest` filter.
    assert_eq!(
        sxs_key(
            "x86",
            "Microsoft.Windows.Common-Controls",
            "6595b64144ccf1df",
            "6.0.2600.2982",
            "none"
        ),
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef"
    );
    // An empty field contributes nothing, separator included — the reason Wine
    // substitutes the current architecture before building the key.
    assert_eq!(
        sxs_key("", "N", "k", "1.0.0.0", "none"),
        "n_k_1.0.0.0_none_deadbeef"
    );
}

/// The assembly is in the prefix, inside `comctl32_v6.dll`, and exemu's loader
/// can already read it out and parse its identity.
#[test]
fn comctl6_assembly_is_recoverable_from_the_pinned_prefix() {
    let mut checked = 0;
    for (arch, dir) in [("x86", PREFIX32), ("amd64", PREFIX64)] {
        let Some(bytes) = read(dir, "comctl32_v6.dll") else {
            eprintln!("skipping {dir}: comctl32_v6.dll not present");
            continue;
        };

        // (a) It is a *named* RT_MANIFEST resource, not one of the integer IDs
        //     (1 = exe, 2 = DLL isolation) `parse_activation_context` tries.
        let named: Vec<_> = list_resources(&bytes)
            .into_iter()
            .filter(|e| e.type_id == RT_MANIFEST)
            .filter_map(|e| match e.name {
                ResourceName::Name(n) => Some(n),
                ResourceName::Id(_) => None,
            })
            .collect();
        assert!(
            named.iter().any(|n| n.starts_with(WINE_MANIFEST)),
            "{dir}: comctl32_v6.dll should publish a WINE_MANIFEST resource, saw {named:?}"
        );

        // (b) The loader can pull the bytes out by name.
        let name = named.iter().find(|n| n.starts_with(WINE_MANIFEST)).unwrap();
        let raw = find_resource(&bytes, RT_MANIFEST, &ResourceName::Name(name.clone()), LANG_ANY)
            .expect("the named manifest resource has data");
        let xml = std::str::from_utf8(raw).expect("the manifest is UTF-8");

        // (c) And it is the assembly the fixme names.
        let ctx = parse_activation_context_from_manifest(xml).expect("manifest parses");
        let id = &ctx.manifest.identity;
        assert_eq!(id.name, "Microsoft.Windows.Common-Controls");
        assert_eq!(id.version, "6.0.2600.2982");
        assert_eq!(id.public_key_token.as_deref(), Some("6595b64144ccf1df"));
        // Wine ships it architecture-neutral and substitutes the running
        // architecture as it writes the store — so the key cannot be built from
        // the resource alone.
        assert_eq!(id.processor_architecture, "", "{dir}: arch should be empty on disk");

        // (d) The `<file>` element names what the assembly redirects to, and the
        //     window classes it claims are why v5-vs-v6 is a visible difference.
        assert!(xml.contains(r#"<file name="comctl32.dll">"#), "{dir}: missing <file>");
        for class in ["Button", "Edit", "Static", "ComboBox", "ListBox", "SysLink"] {
            assert!(
                xml.contains(&format!("<windowClass>{class}</windowClass>")),
                "{dir}: the v6 assembly should claim the {class} class"
            );
        }

        // (e) The key exemu would have to write the store under.
        let key = sxs_key(
            arch,
            &id.name,
            id.public_key_token.as_deref().unwrap(),
            &id.version,
            id.language.as_deref().unwrap_or("none"),
        );
        assert_eq!(
            key,
            format!("{arch}_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef")
        );
        checked += 1;
    }
    if checked == 0 {
        eprintln!("skipping: the pinned Wine prefix is not present");
    }
}

/// …and the v5 build publishes no assembly at all, which is what makes the
/// silent fallback a real loss of function rather than a naming detail.
#[test]
fn the_v5_comctl32_publishes_no_assembly() {
    for dir in [PREFIX32, PREFIX64] {
        let Some(bytes) = read(dir, "comctl32.dll") else {
            continue;
        };
        let named: Vec<_> = list_resources(&bytes)
            .into_iter()
            .filter(|e| e.type_id == RT_MANIFEST)
            .collect();
        assert!(
            named.is_empty(),
            "{dir}: the v5 comctl32 should carry no RT_MANIFEST, saw {named:?}"
        );
    }
}

/// The corpus binary that emits the fixme really does declare the dependency —
/// so the gap is exemu's, not the guest's.
#[test]
fn the_wow64_corpus_guest_asks_for_common_controls_6() {
    let path = std::path::Path::new("../../example_exe/SteamSetup.exe");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let image = exemu_loader::parse(&bytes).expect("SteamSetup parses");
    let ctx = image.activation_context.expect("SteamSetup embeds a manifest");
    assert!(ctx.comctl32_v6, "its manifest should ask for Common-Controls 6");
    let dep = ctx
        .manifest
        .dependencies
        .iter()
        .find(|d| d.name == "Microsoft.Windows.Common-Controls")
        .expect("the dependency is listed");
    assert_eq!(dep.version, "6.0.0.0");
    assert_eq!(dep.public_key_token.as_deref(), Some("6595b64144ccf1df"));
    // It asks for `processorArchitecture="*"`, and Wine does **not** treat that
    // as a wildcard in the lookup: `parse_dependent_assembly_elem` rewrites `*`
    // to the running architecture (`current_archW`, i.e. `x86` inside the
    // 32-bit ntdll of a WoW64 process) before the identity is recorded. The
    // filter `ntdll!build_manifest_filter` then builds is
    // `x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.*.*_*_*.manifest`
    // — which is why the store has to be written per architecture, under the
    // exact key `the_winsxs_key_matches_wines_own_naming` pins.
    assert_eq!(dep.processor_architecture, "*");
}

// ===========================================================================
// The staging half (roadmap W6.1): exemu writes the store, and the guest
// loads v6 out of it.
// ===========================================================================

/// Byte-for-byte, [`winsxs::stage_comctl6`] writes what `ntdll!lookup_winsxs`
/// goes looking for: the manifest under the exact key its
/// `…_6.0.*.*_*_*.manifest` filter matches, and — the part that decides
/// v5-vs-v6 — a payload that **is** `comctl32_v6.dll`.
#[test]
fn staging_writes_the_store_the_loaders_filter_finds() {
    let Some(v6) = read(PREFIX32, "comctl32_v6.dll") else {
        eprintln!("SKIP: the pinned 32-bit Wine prefix is not present (git-ignored)");
        return;
    };
    let v5 = read(PREFIX32, "comctl32.dll").expect("the v5 build ships alongside it");

    let sandbox = std::env::temp_dir().join(format!("exemu-sxs-stage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    std::fs::create_dir_all(&sandbox).unwrap();

    let staged = winsxs::stage_comctl6(&sandbox, std::path::Path::new(PREFIX32), winsxs::ARCH_X86)
        .expect("the 32-bit prefix stages");

    assert_eq!(
        staged.key,
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef",
    );
    assert_eq!(staged.file_name, "comctl32.dll", "the <file> element names the redirected leaf");
    assert_eq!(
        staged.manifest,
        sandbox
            .join("C")
            .join("windows")
            .join("winsxs")
            .join("manifests")
            .join(format!("{}.manifest", staged.key)),
        "the manifest goes where lookup_winsxs enumerates",
    );
    assert_eq!(
        staged.payload,
        sandbox.join("C").join("windows").join("winsxs").join(&staged.key).join("comctl32.dll"),
        "the payload goes into the assembly directory, under the name the assembly redirects",
    );

    // The manifest is the resource verbatim — the same bytes
    // `comctl6_assembly_is_recoverable_from_the_pinned_prefix` pulled out.
    let named = list_resources(&v6)
        .into_iter()
        .filter(|e| e.type_id == RT_MANIFEST)
        .find_map(|e| match e.name {
            ResourceName::Name(n) if n.starts_with(WINE_MANIFEST) => Some(n),
            _ => None,
        })
        .expect("the v6 build publishes WINE_MANIFEST");
    let raw = find_resource(&v6, RT_MANIFEST, &ResourceName::Name(named), LANG_ANY).unwrap();
    assert_eq!(
        std::fs::read(&staged.manifest).unwrap(),
        raw,
        "the staged manifest is the RT_MANIFEST resource, byte for byte",
    );

    // …and the payload is the **v6** build. Asserting both halves is what makes
    // this a v6 test rather than a file-exists test: a staging step that copied
    // `comctl32.dll` would satisfy "a file is there" and silently keep the guest
    // on v5.
    let payload = std::fs::read(&staged.payload).unwrap();
    assert_eq!(payload, v6, "the store holds comctl32_v6.dll");
    assert_ne!(payload, v5, "…and emphatically not the v5 build");

    // Idempotent: a second staging over a warm sandbox is a no-op, which is what
    // makes it cheap enough to run on every process load.
    let again = winsxs::stage_comctl6(&sandbox, std::path::Path::new(PREFIX32), winsxs::ARCH_X86)
        .expect("re-staging succeeds");
    assert_eq!(again, staged);
    assert_eq!(std::fs::read(&staged.payload).unwrap(), v6);

    let _ = std::fs::remove_dir_all(&sandbox);
}

/// The export the guest-side gate looks for. `taskdialog.c` is compiled only
/// into the v6 build.
const V6_ONLY_EXPORT: &str = "TaskDialogIndirect";

/// The exports only the v6 build has, read out of the two pinned binaries. The
/// guest-side gate below looks for [`V6_ONLY_EXPORT`] in the image Wine mapped;
/// this is what makes finding it *mean* "the v6 build loaded".
#[test]
fn only_the_v6_build_exports_the_themed_entry_points() {
    let mut checked = 0;
    for dir in [PREFIX32, PREFIX64] {
        let (Some(v5), Some(v6)) = (read(dir, "comctl32.dll"), read(dir, "comctl32_v6.dll")) else {
            continue;
        };
        let names = |b: &[u8]| -> Vec<String> {
            exemu_loader::parse(b)
                .expect("comctl32 parses")
                .exports
                .iter()
                .filter_map(|e| e.name.clone())
                .collect()
        };
        let (a, b) = (names(&v5), names(&v6));
        for only_v6 in [V6_ONLY_EXPORT, "TaskDialog", "LoadIconMetric", "GetWindowSubclass"] {
            assert!(b.iter().any(|n| n == only_v6), "{dir}: v6 exports {only_v6}");
            assert!(!a.iter().any(|n| n == only_v6), "{dir}: v5 does NOT export {only_v6}");
        }
        checked += 1;
    }
    if checked == 0 {
        eprintln!("SKIP: the pinned Wine prefix is not present (git-ignored)");
    }
}

/// **The gate.** `SteamSetup.exe` declares
/// `Microsoft.Windows.Common-Controls 6.0.0.0` (pinned above). Booted as a
/// WoW64 process against the pinned prefix, with the store staged by
/// `Process::load`, its **own** loader resolves that dependency through the
/// activation context and maps comctl32 out of the assembly directory.
///
/// Both assertions are made against the guest, not the host disk:
///
/// 1. the `LDR_DATA_TABLE_ENTRY` Wine threaded onto `PEB32.Ldr` for
///    `comctl32.dll` reports a `FullDllName` under
///    `C:\windows\winsxs\<key>\` — so the redirect, not the plain `system32`
///    search, is what found it; and
/// 2. the image at that entry's `DllBase` exports [`V6_ONLY_EXPORT`], read out
///    of the *mapped* export directory — so what loaded is the v6 build.
///
/// Assertion 2 is the one that cannot be satisfied by accident: before the store
/// existed the same lookup found `C:\windows\system32\comctl32.dll`, whose
/// export table has no `TaskDialogIndirect` at all.
#[test]
fn a_wow64_guest_loads_comctl32_v6_out_of_the_store() {
    let exe = std::path::Path::new("../../example_exe/SteamSetup.exe");
    if !exe.is_file() || !std::path::Path::new(PREFIX32).join("comctl32_v6.dll").exists() {
        eprintln!("SKIP: SteamSetup.exe or the pinned Wine WoW64 set is absent (git-ignored)");
        return;
    }
    let bytes = std::fs::read(exe).unwrap();
    let sandbox = std::env::temp_dir().join(format!("exemu-sxs-guest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);

    let mut cfg = exemu_app::RunConfig {
        echo: false,
        max_steps: 60_000_000,
        args: vec![exe.to_string_lossy().into_owned()],
        wine_boot_dir: Some(PREFIX64.to_string()),
        sandbox_root: Some(sandbox.clone()),
        ..exemu_app::RunConfig::default()
    };
    let mut p = exemu_app::Process::load(&bytes, &mut cfg).expect("WoW64 boot");
    let peb32 = p.wow64().expect("a PE32 on the Wine set boots WoW64").peb32;
    let res = p.run_borrowed().expect("SteamSetup terminates itself on the WoW64 path");
    eprintln!("W6.1 sxs gate — SteamSetup: exit {} after {} steps", res.exit_code, res.steps);

    let modules = ldr32_modules(&p, peb32);
    assert!(
        modules.iter().any(|(n, _, _)| n.eq_ignore_ascii_case("ntdll.dll")),
        "Wine's 32-bit loader published its module list; got {:?}",
        modules.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>(),
    );
    let (_, full, base) = modules
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case("comctl32.dll"))
        .unwrap_or_else(|| {
            panic!(
                "the guest loads comctl32; got {:?}",
                modules.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>()
            )
        });

    // (1) It came out of the side-by-side store, under the key exemu staged.
    let key = "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef";
    let lower = full.to_ascii_lowercase().replace('/', "\\");
    assert!(
        lower.contains(&format!("\\winsxs\\{key}\\")),
        "comctl32 should be loaded from the staged assembly, not the plain \
         system32 search. FullDllName = {full:?}",
    );

    // (2) …and the mapped image is the v6 build.
    let exports = mapped_export_names(&p, *base);
    assert!(
        exports.iter().any(|n| n == V6_ONLY_EXPORT),
        "the mapped comctl32 at {base:#x} should export {V6_ONLY_EXPORT} (v6 only); \
         it exports {} names, e.g. {:?}",
        exports.len(),
        &exports[..exports.len().min(8)],
    );

    let _ = std::fs::remove_dir_all(&sandbox);
}

// ---------------------------------------------------------------------------
// Reading the guest's own loader data.
// ---------------------------------------------------------------------------

/// Read a UTF-16 string of `bytes` bytes from guest address `at`.
fn read_wstr(p: &exemu_app::Process, at: u64, bytes: u16) -> String {
    let mut units = Vec::with_capacity(bytes as usize / 2);
    for i in 0..(bytes as u64 / 2) {
        match p.memory().read_u16(at + i * 2) {
            Ok(u) => units.push(u),
            Err(_) => break,
        }
    }
    String::from_utf16_lossy(&units)
}

/// Walk `PEB32.Ldr`'s `InLoadOrderModuleList` and return
/// `(BaseDllName, FullDllName, DllBase)` for every module Wine's **32-bit**
/// loader threaded onto it.
///
/// 32-bit layout (`winternl.h`): `PEB.Ldr` at +0x0c; `PEB_LDR_DATA`'s
/// `InLoadOrderModuleList` at +0x0c; and in `LDR_DATA_TABLE_ENTRY`
/// `InLoadOrderLinks` at +0x00, `DllBase` +0x18, `FullDllName` +0x24,
/// `BaseDllName` +0x2c — the same offsets `exemu_os`'s own Ldr threading uses.
fn ldr32_modules(p: &exemu_app::Process, peb32: u64) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    let Ok(ldr) = p.peek_u32(peb32 + exemu_os::wow64::peb32::LDR) else {
        return out;
    };
    if ldr == 0 {
        return out;
    }
    let head = ldr as u64 + 0x0c;
    let Ok(mut cur) = p.peek_u32(head) else { return out };
    let mut guard = 0;
    while cur as u64 != head && cur != 0 && guard < 256 {
        guard += 1;
        let e = cur as u64;
        let name_at = |off: u64| -> String {
            let len = p.memory().read_u16(e + off).unwrap_or(0);
            let buf = p.peek_u32(e + off + 4).unwrap_or(0);
            if buf == 0 || len == 0 {
                String::new()
            } else {
                read_wstr(p, buf as u64, len)
            }
        };
        let full = name_at(0x24);
        let base_name = name_at(0x2c);
        let dll_base = p.peek_u32(e + 0x18).unwrap_or(0) as u64;
        if !base_name.is_empty() {
            out.push((base_name, full, dll_base));
        }
        let Ok(next) = p.peek_u32(e) else { break };
        cur = next;
    }
    out
}

/// Exported names of the PE **mapped in guest memory** at `base`, read straight
/// out of its export directory. Nothing on the host disk is consulted, so this
/// answers "which build did the guest actually map".
fn mapped_export_names(p: &exemu_app::Process, base: u64) -> Vec<String> {
    let mut names = Vec::new();
    if base == 0 {
        return names;
    }
    let m = p.memory();
    let Ok(e_lfanew) = m.read_u32(base + 0x3c) else { return names };
    let nt = base + e_lfanew as u64;
    if m.read_u32(nt).ok() != Some(0x0000_4550) {
        return names; // no "PE\0\0"
    }
    let Ok(magic) = m.read_u16(nt + 0x18) else { return names };
    // The export data directory is entry 0, right after the optional header's
    // fixed part: +0x60 for PE32, +0x70 for PE32+.
    let dd = nt + 0x18 + if magic == 0x20b { 0x70 } else { 0x60 };
    let Ok(export_rva) = m.read_u32(dd) else { return names };
    if export_rva == 0 {
        return names;
    }
    let dir = base + export_rva as u64;
    let (Ok(count), Ok(name_table)) = (m.read_u32(dir + 0x18), m.read_u32(dir + 0x20)) else {
        return names;
    };
    for i in 0..count.min(8192) as u64 {
        let Ok(rva) = m.read_u32(base + name_table as u64 + i * 4) else { break };
        let mut s = Vec::new();
        let mut at = base + rva as u64;
        while let Ok(b) = m.read_u8(at) {
            if b == 0 || s.len() > 256 {
                break;
            }
            s.push(b);
            at += 1;
        }
        names.push(String::from_utf8_lossy(&s).into_owned());
    }
    names
}
