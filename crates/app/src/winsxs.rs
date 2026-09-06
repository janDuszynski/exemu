//! Materialise the WinSxS store at prefix creation (roadmap W6.1).
//!
//! A guest whose manifest declares
//! `Microsoft.Windows.Common-Controls` `6.0.0.0` gets **comctl32 v6** — the
//! build that compiles the themed replacements for the user32 built-ins
//! (`Button`, `ComboBox`, `Edit`, `ListBox`, `Static`) plus `SysLink` and
//! `TaskDialog`, and the only one that delay-imports `uxtheme`. It gets it
//! because the loader resolves the dependency through a side-by-side
//! **assembly**, whose manifest redirects the plain name `comctl32.dll` to a
//! private copy in the store.
//!
//! Wine's pinned prefix ships **both** builds — `comctl32.dll` (v5) and
//! `comctl32_v6.dll` (v6) — and embeds the assembly manifest inside the v6 DLL
//! as an `RT_MANIFEST` resource *named* `WINE_MANIFEST`
//! (`crates/app/tests/sxs_assembly.rs` pins that recovery). Turning those
//! resources into a store is a **prefix-creation** step (Wine does it in
//! `setupapi`'s fake-DLL pass, driven by `wineboot --update`): for each such
//! resource it writes
//!
//! ```text
//! %WINDIR%\winsxs\manifests\<key>.manifest   <- the resource bytes, verbatim
//! %WINDIR%\winsxs\<key>\<file name>          <- the DLL the <file> element names
//! ```
//!
//! where `<key>` is `<arch>_<name>_<publicKeyToken>_<version>_<lang>_deadbeef`.
//! exemu never ran that step, so `ntdll!lookup_winsxs` opened
//! `\??\C:\windows\winsxs\manifests`, found nothing, logged
//! `fixme:actctx:parse_depend_manifests Could not find dependent assembly` and
//! **silently fell back to v5**. This module is that step.
//!
//! Scope: only the *running* architecture is staged (`x86` for a WoW64 process,
//! `amd64` for a native 64-bit one). The 32-bit ntdll inside a WoW64 process
//! rewrites `processorArchitecture="*"` to `x86` before it builds its filter and
//! the 64-bit one to `amd64`, so exactly one key is ever consulted per process,
//! and staging the other one would only put a multi-megabyte copy of a DLL
//! nobody opens into the guest's filesystem.

use std::path::{Path, PathBuf};

use exemu_loader::{
    find_resource, list_resources, parse_activation_context_from_manifest, ResourceName, LANG_ANY,
    RT_MANIFEST,
};

/// The DLL in the pinned prefix that carries the comctl6 assembly.
pub const COMCTL6_MODULE: &str = "comctl32_v6.dll";

/// The resource-name prefix Wine's own prefix-creation step matches on. The
/// match is by prefix (13 characters), so one DLL may publish several.
pub const WINE_MANIFEST: &str = "WINE_MANIFEST";

/// `processorArchitecture` a 32-bit (WoW64) guest's loader substitutes for `*`.
pub const ARCH_X86: &str = "x86";
/// …and the one a native 64-bit guest's loader substitutes.
pub const ARCH_AMD64: &str = "amd64";

/// The architecture whose store a process of this width consults.
pub fn arch_for(is_64bit_process: bool) -> &'static str {
    if is_64bit_process {
        ARCH_AMD64
    } else {
        ARCH_X86
    }
}

/// Keep only the characters the key builder considers valid, truncate to
/// `maxlen` by replacing the middle with `..`, lower-case, and append the `_`
/// separator. An **empty field contributes nothing at all** — not even the
/// separator — which is why the architecture has to be substituted before the
/// key is built rather than taken from the manifest (Wine ships the assembly
/// architecture-neutral).
fn append_field(out: &mut String, s: &str, maxlen: usize) {
    if s.is_empty() {
        return;
    }
    let kept: Vec<char> =
        s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').collect();
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

/// The WinSxS key both the manifest file name and the assembly directory are
/// built from: `<arch>_<name>_<publicKeyToken>_<version>_<lang>_deadbeef`.
/// `public_key` and `version` are appended verbatim (each followed by `_`);
/// only arch/name/lang go through [`append_field`].
///
/// This is the name `ntdll!lookup_winsxs` finds through its
/// `…_6.0.*.*_*_*.manifest` filter, and `crates/app/tests/sxs_assembly.rs`
/// pins the exact string it has to produce.
pub fn sxs_key(arch: &str, name: &str, public_key: &str, version: &str, lang: &str) -> String {
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

/// One assembly that was written into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// The WinSxS key, i.e. the assembly directory's name and the manifest's
    /// stem.
    pub key: String,
    /// `%WINDIR%\winsxs\manifests\<key>.manifest`, as a host path.
    pub manifest: PathBuf,
    /// `%WINDIR%\winsxs\<key>\<file name>`, as a host path.
    pub payload: PathBuf,
    /// The leaf the `<file>` element names — the DLL name the guest asks for and
    /// the assembly redirects.
    pub file_name: String,
}

/// The `name` attribute of the manifest's first `<file …>` element, which is
/// what the assembly redirects and therefore the leaf the payload is copied to.
fn file_element_name(xml: &str) -> Option<String> {
    let at = xml.find("<file ")?;
    let rest = &xml[at + "<file ".len()..];
    let end = rest.find('>')?;
    let attrs = &rest[..end];
    let np = attrs.find("name=")?;
    let after = &attrs[np + "name=".len()..];
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let body = &after[1..];
    let close = body.find(quote)?;
    Some(body[..close].to_string())
}

/// Write the comctl6 side-by-side assembly into `sandbox`'s `C:\windows\winsxs`
/// for one architecture, taking both the manifest and the payload out of
/// `prefix`'s [`COMCTL6_MODULE`].
///
/// Returns `None` — leaving the guest on the v5 fallback exactly as before —
/// when the prefix has no v6 build, when it publishes no `WINE_MANIFEST`, or
/// when the manifest does not parse. Idempotent: an existing payload of the
/// right length is left alone rather than re-copied, so repeated loads against a
/// warm sandbox cost one `stat`.
pub fn stage_comctl6(sandbox: &Path, prefix: &Path, arch: &str) -> Option<Staged> {
    let bytes = std::fs::read(prefix.join(COMCTL6_MODULE)).ok()?;

    // The assembly manifest is a *named* RT_MANIFEST, not one of the integer
    // IDs (1 = exe, 2 = DLL isolation) an image's own manifest uses.
    let name = list_resources(&bytes)
        .into_iter()
        .filter(|e| e.type_id == RT_MANIFEST)
        .find_map(|e| match e.name {
            ResourceName::Name(n) if n.starts_with(WINE_MANIFEST) => Some(n),
            _ => None,
        })?;
    let raw = find_resource(&bytes, RT_MANIFEST, &ResourceName::Name(name), LANG_ANY)?;
    let xml = std::str::from_utf8(raw).ok()?;

    let ctx = parse_activation_context_from_manifest(xml)?;
    let id = &ctx.manifest.identity;
    if id.name.is_empty() || id.version.is_empty() {
        return None;
    }
    // Wine ships the assembly architecture-neutral and substitutes the running
    // architecture as it writes the store, so the key cannot be built from the
    // resource alone (`sxs_assembly.rs` asserts the on-disk arch is empty).
    let key = sxs_key(
        arch,
        &id.name,
        id.public_key_token.as_deref().unwrap_or(""),
        &id.version,
        id.language.as_deref().unwrap_or("none"),
    );
    let file_name = file_element_name(xml)?;

    let winsxs = sandbox.join("C").join("windows").join("winsxs");
    let manifests = winsxs.join("manifests");
    std::fs::create_dir_all(&manifests).ok()?;
    let manifest = manifests.join(format!("{key}.manifest"));
    std::fs::write(&manifest, raw).ok()?;

    let assembly = winsxs.join(&key);
    std::fs::create_dir_all(&assembly).ok()?;
    let payload = assembly.join(&file_name);
    let already = std::fs::metadata(&payload).map(|m| m.len()).unwrap_or(0);
    if already != bytes.len() as u64 {
        std::fs::write(&payload, &bytes).ok()?;
    }

    Some(Staged { key, manifest, payload, file_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_built_the_way_the_loaders_filter_expects() {
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
        // An empty field contributes nothing, separator included.
        assert_eq!(sxs_key("", "N", "k", "1.0.0.0", "none"), "n_k_1.0.0.0_none_deadbeef");
    }

    #[test]
    fn the_file_element_names_what_the_assembly_redirects() {
        let xml = r#"<assembly><file name="comctl32.dll" hash="x"/></assembly>"#;
        assert_eq!(file_element_name(xml).as_deref(), Some("comctl32.dll"));
        assert_eq!(file_element_name("<assembly/>"), None);
    }

    #[test]
    fn a_prefix_without_the_v6_build_stages_nothing() {
        let dir = std::env::temp_dir().join(format!("exemu-winsxs-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(stage_comctl6(&dir, &dir, ARCH_X86), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
