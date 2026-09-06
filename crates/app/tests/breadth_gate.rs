use std::collections::{HashMap, HashSet};
use std::path::Path;

use exemu_core::{Memory, Perm, Region};
use exemu_memory::VirtualMemory;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const DLL_BASE: u64 = 0x0000_0006_0000_0000;

const IMAGE_REL_BASED_DIR64: u8 = 10;

const BREADTH: &[(&str, &str, &[&str])] = &[
    ("cabinet.dll", "W6.5", &["FDICreate", "FDICopy", "FDIDestroy", "FDIIsCabinet", "FCICreate"]),
    ("msi.dll", "W6.5", &["MsiOpenPackageW", "MsiInstallProductW", "MsiGetPropertyW", "MsiCloseHandle"]),
    (
        "setupapi.dll",
        "W6.5",
        &["SetupIterateCabinetW", "SetupOpenInfFileW", "SetupCloseInfFile", "SetupDiGetClassDevsW"],
    ),
    (
        "shell32.dll",
        "W6.6",
        &["SHGetFolderPathW", "SHGetSpecialFolderPathW", "SHGetKnownFolderPath", "ShellExecuteW"],
    ),
    (
        "shlwapi.dll",
        "W6.6",
        &["PathFindExtensionW", "PathIsRelativeW", "PathFindFileNameW", "StrToIntW"],
    ),
    (
        "ws2_32.dll",
        "W7.1",
        &["WSAStartup", "socket", "connect", "send", "recv", "closesocket", "bind", "listen", "accept"],
    ),
];

fn dlls_present() -> bool {
    BREADTH.iter().all(|(d, _, _)| Path::new(WINE_DLLS).join(d).exists())
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn export_names(dir: &Path, dll: &str) -> Option<(HashSet<String>, Vec<String>)> {
    let bytes = std::fs::read(dir.join(dll)).ok()?;
    let image = exemu_loader::parse(&bytes).ok()?;
    let mut names = HashSet::new();
    let mut fwd = Vec::new();
    for e in &image.exports {
        if let Some(n) = &e.name {
            names.insert(n.clone());
        }
        if let Some(f) = &e.forwarder {
            if let Some((module, _)) = f.split_once('.') {
                fwd.push(format!("{}.dll", module.to_ascii_lowercase()));
            }
        }
    }
    Some((names, fwd))
}

#[test]
fn breadth_dlls_map_relocate_and_bind() {
    if !dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} breadth DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = Path::new(WINE_DLLS);

    let mut cache: HashMap<String, (HashSet<String>, Vec<String>)> = HashMap::new();
    let mut fwd_targets: Vec<String> = Vec::new();

    for (dll, step, entries) in BREADTH {
        let bytes = std::fs::read(dir.join(dll)).unwrap_or_else(|e| panic!("read {dll}: {e}"));
        let mut image = exemu_loader::parse(&bytes).unwrap_or_else(|e| panic!("{dll} parses as PE: {e}"));
        assert!(image.is_64bit, "{dll} (x86_64-windows) must be PE32+");
        assert!(!image.relocations.is_empty(), "{dll} must carry a .reloc table");

        let preferred = image.image_base;
        assert_ne!(preferred, DLL_BASE, "{dll}: DLL_BASE must not be the preferred base");
        let delta = DLL_BASE.wrapping_sub(preferred);

        let probe = image
            .relocations
            .iter()
            .find(|r| r.kind == IMAGE_REL_BASED_DIR64)
            .map(|r| r.rva)
            .unwrap_or_else(|| panic!("{dll}: no DIR64 fixup to probe"));
        let before = read_rva_u64(&image, probe)
            .unwrap_or_else(|| panic!("{dll}: DIR64 fixup at rva {probe:#x} is not inside a section"));

        exemu_loader::apply_relocations(&mut image.sections, &image.relocations, preferred, DLL_BASE)
            .unwrap_or_else(|e| panic!("{dll}: apply relocations: {e}"));

        let mut mem = VirtualMemory::new();
        let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
        mem.map(Region::new("hdr", DLL_BASE, hdr_len, Perm::RWX)).unwrap();
        mem.write(DLL_BASE, &image.headers).unwrap();
        for s in &image.sections {
            let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
            let map_len = align_up(vsize, 0x1000).max(0x1000);
            let addr = DLL_BASE + s.rva as u64;
            if mem.map(Region::new("sec", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
                mem.write(addr, &s.data).unwrap();
            } else if !s.data.is_empty() {
                mem.poke(addr, &s.data).unwrap();
            }
        }
        let after = mem
            .read_u64(DLL_BASE + probe as u64)
            .unwrap_or_else(|e| panic!("{dll}: fixup site is mapped: {e}"));
        assert_eq!(
            after,
            before.wrapping_add(delta),
            "{dll}: the DIR64 fixup at rva {probe:#x} was not relocated \
             (before {before:#x} + delta {delta:#x} != {after:#x})"
        );

        let by_name: HashMap<&str, u32> = image
            .exports
            .iter()
            .filter(|e| e.forwarder.is_none())
            .filter_map(|e| e.name.as_deref().map(|n| (n, e.rva)))
            .collect();
        for name in *entries {
            let rva = by_name
                .get(name)
                .unwrap_or_else(|| panic!("{dll}!{name} is not a local (non-forwarder) export"));
            let va = DLL_BASE + *rva as u64;
            let mut b = [0u8; 1];
            mem.read(va, &mut b).unwrap_or_else(|e| panic!("{dll}!{name} is mapped: {e}"));
        }

        let mut checked = 0usize;
        for imp in &image.imports {
            let exemu_core::ImportSymbol::Named(sym) = &imp.symbol else {
                continue;
            };
            let entry = cache.entry(imp.dll.clone()).or_insert_with(|| {
                export_names(dir, &imp.dll)
                    .unwrap_or_else(|| panic!("{dll} imports from {}, missing from the pinned prefix", imp.dll))
            });
            assert!(
                entry.0.contains(sym),
                "{dll} imports {}!{sym}, which that DLL does not export",
                imp.dll
            );
            checked += 1;
        }
        assert!(checked > 5, "{dll}: only cross-checked {checked} named imports");

        let fwd_count = image.exports.iter().filter(|e| e.forwarder.is_some()).count();
        fwd_targets.extend(image.exports.iter().filter_map(|e| {
            e.forwarder
                .as_deref()
                .and_then(|f| f.split_once('.'))
                .map(|(m, _)| format!("{}.dll", m.to_ascii_lowercase()))
        }));
        eprintln!(
            "{step} {dll}: {} exports ({fwd_count} forwarders), {checked} named imports all resolvable",
            image.exports.len()
        );
    }

    fwd_targets.extend(cache.values().flat_map(|(_, t)| t.clone()));
    fwd_targets.sort();
    fwd_targets.dedup();
    for t in &fwd_targets {
        assert!(dir.join(t).exists(), "forwarder target {t} is missing from the pinned prefix");
    }
    eprintln!("{} distinct forwarder target modules, all present", fwd_targets.len());
}

fn read_rva_u64(image: &exemu_core::PeImage, rva: u32) -> Option<u64> {
    for s in &image.sections {
        let start = s.rva;
        let end = start + s.data.len() as u32;
        if rva >= start && rva + 8 <= end {
            let off = (rva - start) as usize;
            return Some(u64::from_le_bytes(s.data[off..off + 8].try_into().ok()?));
        }
    }
    None
}

#[test]
fn msi_dependency_closure_is_satisfiable_from_the_prefix() {
    if !dlls_present() {
        eprintln!("SKIP: {WINE_DLLS} breadth DLLs not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = Path::new(WINE_DLLS);

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec!["msi.dll".to_string()];
    let mut missing: Vec<String> = Vec::new();

    while let Some(dll) = queue.pop() {
        if !seen.insert(dll.clone()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(dir.join(&dll)) else {
            missing.push(dll);
            continue;
        };
        let Ok(image) = exemu_loader::parse(&bytes) else {
            continue;
        };
        let mut deps: Vec<String> = image.imports.iter().map(|i| i.dll.to_ascii_lowercase()).collect();
        deps.sort();
        deps.dedup();
        queue.extend(deps);
    }

    assert!(
        missing.is_empty(),
        "msi.dll's transitive dependency closure is missing from the pinned prefix: {missing:?}"
    );
    assert!(seen.len() > 20, "expected a deep closure, walked only {}", seen.len());
    eprintln!("msi.dll closure: {} modules, all present in the prefix", seen.len());
}
