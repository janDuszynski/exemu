#![forbid(unsafe_code)]

use exemu_core::{ActivationContext, AssemblyIdentity, ManifestInfo};

use crate::resources::{find_resource_data, RT_MANIFEST};

const MANIFEST_ID_EXE: u32 = 1;
const MANIFEST_ID_DLL: u32 = 2;

pub fn parse_from_pe_resources(pe_bytes: &[u8]) -> Option<ActivationContext> {
    let manifest_bytes = find_resource_data(pe_bytes, RT_MANIFEST, MANIFEST_ID_EXE)
        .or_else(|| find_resource_data(pe_bytes, RT_MANIFEST, MANIFEST_ID_DLL))?;
    let text = std::str::from_utf8(manifest_bytes)
        .ok()
        .or_else(|| {
            if manifest_bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
                std::str::from_utf8(&manifest_bytes[3..]).ok()
            } else {
                None
            }
        })?;
    parse_manifest_xml(text)
}

pub fn parse_from_external_manifest(manifest_text: &str) -> Option<ActivationContext> {
    parse_manifest_xml(manifest_text)
}

fn parse_manifest_xml(xml: &str) -> Option<ActivationContext> {
    let mut identities: Vec<(bool, AssemblyIdentity)> = Vec::new();

    let bytes = xml.as_bytes();
    let tag = b"<assemblyIdentity";
    let dep_tag = b"<dependentAssembly";

    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some(rel) = find_bytes(&bytes[pos..], tag) else { break };
        let tag_start = pos + rel;

        let is_dependent = {
            let before = &bytes[..tag_start];
            let last_open = rfind_bytes(before, dep_tag);
            let last_close = rfind_bytes(before, b"</dependentAssembly");
            match (last_open, last_close) {
                (Some(o), Some(c)) => o > c,
                (Some(_), None) => true,
                _ => false,
            }
        };

        let Some(rel_close) = find_bytes(&bytes[tag_start..], b">") else { break };
        let tag_end = tag_start + rel_close + 1;
        let tag_body = &xml[tag_start + tag.len()..tag_end - 1];

        let id = parse_identity_attrs(tag_body);
        if !id.name.is_empty() {
            identities.push((is_dependent, id));
        }
        pos = tag_end;
    }

    let top_idx = identities.iter().position(|(dep, _)| !dep)
        .or(if identities.is_empty() { None } else { Some(0) })?;
    let identity = identities[top_idx].1.clone();

    let dependencies: Vec<AssemblyIdentity> = identities
        .into_iter()
        .filter(|(dep, _)| *dep)
        .map(|(_, id)| id)
        .collect();

    let comctl32_v6 = dependencies.iter().any(|d| {
        d.name.eq_ignore_ascii_case("Microsoft.Windows.Common-Controls")
            && d.version.starts_with("6.")
    });

    Some(ActivationContext { manifest: ManifestInfo { identity, dependencies }, comctl32_v6 })
}

fn parse_identity_attrs(body: &str) -> AssemblyIdentity {
    let mut id = AssemblyIdentity::default();
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i] == b'/' {
            i += 1;
            continue;
        }
        let key_start = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &body[key_start..i];
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'=') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let quote = b[i];
        if quote != b'"' && quote != b'\'' {
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        i += 1;
        let val_start = i;
        while i < b.len() && b[i] != quote {
            i += 1;
        }
        let value = &body[val_start..i];
        if i < b.len() {
            i += 1;
        }

        match key {
            "name" => id.name = value.to_owned(),
            "version" => id.version = value.to_owned(),
            "type" => id.type_ = value.to_owned(),
            "processorArchitecture" => id.processor_architecture = value.to_owned(),
            "publicKeyToken" => id.public_key_token = Some(value.to_owned()),
            "language" => id.language = Some(value.to_owned()),
            _ => {}
        }
    }
    id
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_7Z: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="7-Zip.7-Zip.7zipInstall" type="win32"/>
<description>7-Zip Installer</description>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v2"><security><requestedPrivileges>
  <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
</requestedPrivileges></security></trustInfo>
<dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
<!-- Vista   --> <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
<!-- Win 7   --> <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
<!-- Win 8   --> <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
<!-- Win 8.1 --> <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
<!-- Win 10  --> <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
</application></compatibility>
<asmv3:application><asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
<dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application>
</assembly>"#;

    #[test]
    fn parse_7z_manifest_identity_and_comctl32_dep() {
        let ctx = parse_manifest_xml(MANIFEST_7Z)
            .expect("7z manifest must parse to an ActivationContext");

        let id = &ctx.manifest.identity;
        assert_eq!(id.name, "7-Zip.7-Zip.7zipInstall", "identity name");
        assert_eq!(id.version, "1.0.0.0", "identity version");
        assert_eq!(id.type_, "win32", "identity type");
        assert_eq!(id.processor_architecture, "*", "identity processorArchitecture");
        assert!(id.public_key_token.is_none(), "exe identity has no publicKeyToken");

        assert_eq!(ctx.manifest.dependencies.len(), 1, "expected one dependentAssembly");
        let dep = &ctx.manifest.dependencies[0];
        assert_eq!(dep.name, "Microsoft.Windows.Common-Controls", "dep name");
        assert_eq!(dep.version, "6.0.0.0", "dep version — comctl32 v6");
        assert_eq!(dep.type_, "win32", "dep type");
        assert_eq!(dep.processor_architecture, "*", "dep processorArchitecture");
        assert_eq!(
            dep.public_key_token.as_deref(),
            Some("6595b64144ccf1df"),
            "dep publicKeyToken"
        );
        assert_eq!(dep.language.as_deref(), Some("*"), "dep language");

        assert!(ctx.comctl32_v6, "comctl32_v6 flag must be set for v6.0.0.0 dep");
    }

    #[test]
    fn manifest_with_no_dependencies_parses_identity_only() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity version="2.3.4.5" processorArchitecture="amd64"
    name="Acme.MyApp" type="win32"/>
</assembly>"#;
        let ctx = parse_manifest_xml(xml).expect("must parse");
        assert_eq!(ctx.manifest.identity.name, "Acme.MyApp");
        assert_eq!(ctx.manifest.identity.version, "2.3.4.5");
        assert_eq!(ctx.manifest.identity.processor_architecture, "amd64");
        assert!(ctx.manifest.dependencies.is_empty());
        assert!(!ctx.comctl32_v6);
    }

    #[test]
    fn comctl32_v5_dep_does_not_set_v6_flag() {
        let xml = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity version="1.0.0.0" name="OldApp" type="win32"/>
<dependency><dependentAssembly>
<assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
    version="5.82.0.0" processorArchitecture="x86"/>
</dependentAssembly></dependency>
</assembly>"#;
        let ctx = parse_manifest_xml(xml).expect("must parse");
        assert!(!ctx.comctl32_v6, "v5 dep must not set comctl32_v6");
    }

    #[test]
    fn empty_and_garbage_xml_returns_none() {
        assert!(parse_manifest_xml("").is_none());
        assert!(parse_manifest_xml("not xml at all").is_none());
        assert!(parse_manifest_xml("<assembly></assembly>").is_none());
    }

    #[test]
    fn utf8_bom_is_stripped() {
        let xml_with_bom = {
            let mut v = vec![0xEF, 0xBB, 0xBF];
            v.extend_from_slice(
                br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity version="1.0.0.0" name="BomApp" type="win32"/>
</assembly>"#,
            );
            v
        };
        let text = std::str::from_utf8(&xml_with_bom[3..]).unwrap();
        let ctx = parse_manifest_xml(text).expect("must parse after BOM strip");
        assert_eq!(ctx.manifest.identity.name, "BomApp");
    }

    #[test]
    fn single_quoted_attributes_are_parsed() {
        let xml = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity version='1.0.0.0' name='QuotedApp' type='win32'/>
</assembly>"#;
        let ctx = parse_manifest_xml(xml).expect("must parse");
        assert_eq!(ctx.manifest.identity.name, "QuotedApp");
        assert_eq!(ctx.manifest.identity.type_, "win32");
    }
}
