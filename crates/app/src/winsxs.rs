use std::path::{Path, PathBuf};

use exemu_loader::{
    find_resource, list_resources, parse_activation_context_from_manifest, ResourceName, LANG_ANY,
    RT_MANIFEST,
};

pub const COMCTL6_MODULE: &str = "comctl32_v6.dll";

pub const WINE_MANIFEST: &str = "WINE_MANIFEST";

pub const ARCH_X86: &str = "x86";
pub const ARCH_AMD64: &str = "amd64";

pub fn arch_for(is_64bit_process: bool) -> &'static str {
    if is_64bit_process {
        ARCH_AMD64
    } else {
        ARCH_X86
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub key: String,
    pub manifest: PathBuf,
    pub payload: PathBuf,
    pub file_name: String,
}

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

pub fn stage_comctl6(sandbox: &Path, prefix: &Path, arch: &str) -> Option<Staged> {
    let bytes = std::fs::read(prefix.join(COMCTL6_MODULE)).ok()?;

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
