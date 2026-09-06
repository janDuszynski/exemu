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
//! `%WINDIR%\winsxs\<key>\<file name>`. exemu never runs that step, so
//! `ntdll!lookup_winsxs` opens `\??\C:\windows\winsxs\manifests` and gets
//! nothing.
//!
//! These tests pin the *recovery* half — that the assembly is in the prefix and
//! that exemu's loader can already read and parse it, so the follow-up does not
//! have to guess. What is still missing is on the OS side and is recorded in the
//! W6.1 roadmap row.

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

/// Wine's `setupapi/fakedll.c::append_string`: keep only the characters it
/// considers valid, truncate to `maxlen` by replacing the middle with `..`,
/// append `_`, and lower-case. An empty field contributes *nothing at all* —
/// not even the separator — which is why the architecture fix-up below matters.
fn append_field(out: &mut String, s: &str, maxlen: usize) {
    if s.is_empty() {
        return;
    }
    let kept: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .collect();
    let field: String = if kept.len() > maxlen {
        let pos = maxlen / 2;
        let head: String = kept[..pos - 1].iter().collect();
        let tail: String = kept[kept.len() - pos + 1..].iter().collect();
        format!("{head}..{tail}")
    } else {
        kept.iter().collect()
    };
    out.push_str(&field.to_ascii_lowercase());
    out.push('_');
}

/// Wine's `append_manifest_filename`: the WinSxS key both the manifest file name
/// and the assembly directory are built from. `public_key` and `version` are
/// appended verbatim (each followed by `_`); only arch/name/lang go through
/// [`append_field`].
fn sxs_key(arch: &str, name: &str, public_key: &str, version: &str, lang: &str) -> String {
    let mut out = String::new();
    append_field(&mut out, arch, 16);
    append_field(&mut out, name, 40);
    out.push_str(public_key);
    out.push('_');
    out.push_str(version);
    out.push('_');
    append_field(&mut out, lang, 8);
    out.push_str("deadbeef");
    out
}

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
