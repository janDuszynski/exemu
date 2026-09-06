use exemu_app::winsxs;
use exemu_loader::{
    find_resource, list_resources, parse_activation_context_from_manifest, ResourceName, LANG_ANY,
    RT_MANIFEST,
};

const PREFIX64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const PREFIX32: &str = "../../example_exe/wine-dlls/i386-windows";

const WINE_MANIFEST: &str = "WINE_MANIFEST";

fn read(dir: &str, leaf: &str) -> Option<Vec<u8>> {
    std::fs::read(std::path::Path::new(dir).join(leaf)).ok()
}

use exemu_app::winsxs::sxs_key;

#[test]
fn the_winsxs_key_matches_wines_own_naming() {
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
    assert_eq!(
        sxs_key("", "N", "k", "1.0.0.0", "none"),
        "n_k_1.0.0.0_none_deadbeef"
    );
}

#[test]
fn comctl6_assembly_is_recoverable_from_the_pinned_prefix() {
    let mut checked = 0;
    for (arch, dir) in [("x86", PREFIX32), ("amd64", PREFIX64)] {
        let Some(bytes) = read(dir, "comctl32_v6.dll") else {
            eprintln!("skipping {dir}: comctl32_v6.dll not present");
            continue;
        };

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

        let name = named.iter().find(|n| n.starts_with(WINE_MANIFEST)).unwrap();
        let raw = find_resource(&bytes, RT_MANIFEST, &ResourceName::Name(name.clone()), LANG_ANY)
            .expect("the named manifest resource has data");
        let xml = std::str::from_utf8(raw).expect("the manifest is UTF-8");

        let ctx = parse_activation_context_from_manifest(xml).expect("manifest parses");
        let id = &ctx.manifest.identity;
        assert_eq!(id.name, "Microsoft.Windows.Common-Controls");
        assert_eq!(id.version, "6.0.2600.2982");
        assert_eq!(id.public_key_token.as_deref(), Some("6595b64144ccf1df"));
        assert_eq!(id.processor_architecture, "", "{dir}: arch should be empty on disk");

        assert!(xml.contains(r#"<file name="comctl32.dll">"#), "{dir}: missing <file>");
        for class in ["Button", "Edit", "Static", "ComboBox", "ListBox", "SysLink"] {
            assert!(
                xml.contains(&format!("<windowClass>{class}</windowClass>")),
                "{dir}: the v6 assembly should claim the {class} class"
            );
        }

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
    assert_eq!(dep.processor_architecture, "*");
}

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

    let payload = std::fs::read(&staged.payload).unwrap();
    assert_eq!(payload, v6, "the store holds comctl32_v6.dll");
    assert_ne!(payload, v5, "…and emphatically not the v5 build");

    let again = winsxs::stage_comctl6(&sandbox, std::path::Path::new(PREFIX32), winsxs::ARCH_X86)
        .expect("re-staging succeeds");
    assert_eq!(again, staged);
    assert_eq!(std::fs::read(&staged.payload).unwrap(), v6);

    let _ = std::fs::remove_dir_all(&sandbox);
}

const V6_ONLY_EXPORT: &str = "TaskDialogIndirect";

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

    let key = "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef";
    let lower = full.to_ascii_lowercase().replace('/', "\\");
    assert!(
        lower.contains(&format!("\\winsxs\\{key}\\")),
        "comctl32 should be loaded from the staged assembly, not the plain \
         system32 search. FullDllName = {full:?}",
    );

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

fn mapped_export_names(p: &exemu_app::Process, base: u64) -> Vec<String> {
    let mut names = Vec::new();
    if base == 0 {
        return names;
    }
    let m = p.memory();
    let Ok(e_lfanew) = m.read_u32(base + 0x3c) else { return names };
    let nt = base + e_lfanew as u64;
    if m.read_u32(nt).ok() != Some(0x0000_4550) {
        return names;
    }
    let Ok(magic) = m.read_u16(nt + 0x18) else { return names };
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
