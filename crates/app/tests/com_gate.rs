use std::collections::HashMap;
use std::path::{Path, PathBuf};

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_app::{load_and_run, sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

struct ComDll {
    name: &'static str,
    base: u64,
    api: &'static [&'static str],
    local: &'static [&'static str],
}

const COM_DLLS: &[ComDll] = &[
    ComDll {
        name: "ole32.dll",
        base: 0x0000_0007_0000_0000,
        api: &["CoInitializeEx", "CoCreateInstance", "CoUninitialize", "CoGetClassObject"],
        local: &["CoInitialize", "DllGetClassObject", "Ole32DllGetClassObject"],
    },
    ComDll {
        name: "combase.dll",
        base: 0x0000_0008_0000_0000,
        api: &["CoInitializeEx", "CoCreateInstance", "CoUninitialize", "CoGetClassObject"],
        local: &["CoInitializeEx", "CoCreateInstance", "CoGetClassObject", "CoTaskMemAlloc", "StringFromGUID2"],
    },
    ComDll {
        name: "oleaut32.dll",
        base: 0x0000_0009_0000_0000,
        api: &["SysAllocString", "SysFreeString", "SysStringLen", "VariantInit", "VariantClear"],
        local: &["SysAllocString", "SysFreeString", "SysStringLen", "VariantInit", "VariantClear"],
    },
];

#[derive(Default)]
struct Prefix {
    modules: HashMap<String, Option<HashMap<String, Option<String>>>>,
}

impl Prefix {
    fn dir() -> PathBuf {
        PathBuf::from(WINE_DLLS)
    }

    fn exports(&mut self, dll: &str) -> Option<&HashMap<String, Option<String>>> {
        let key = dll.to_ascii_lowercase();
        if !self.modules.contains_key(&key) {
            let parsed = std::fs::read(Self::dir().join(&key)).ok().and_then(|bytes| {
                let img = exemu_loader::parse(&bytes).ok()?;
                let mut m = HashMap::new();
                for e in &img.exports {
                    if let Some(n) = &e.name {
                        m.insert(n.clone(), e.forwarder.clone());
                    }
                }
                Some(m)
            });
            self.modules.insert(key.clone(), parsed);
        }
        self.modules.get(&key).and_then(|o| o.as_ref())
    }

    fn resolves(&mut self, dll: &str, symbol: &str) -> bool {
        let (mut dll, mut symbol) = (dll.to_string(), symbol.to_string());
        for _ in 0..8 {
            let Some(exports) = self.exports(&dll) else {
                return false;
            };
            let Some(forwarder) = exports.get(&symbol) else {
                return false;
            };
            let Some(fwd) = forwarder.clone() else {
                return true;
            };
            let Some((target_dll, target_sym)) = fwd.rsplit_once('.') else {
                return false;
            };
            if target_sym.starts_with('#') {
                return self.exports(&format!("{}.dll", target_dll.to_ascii_lowercase())).is_some();
            }
            dll = format!("{}.dll", target_dll.to_ascii_lowercase());
            symbol = target_sym.to_string();
        }
        false
    }
}

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

struct Mapped {
    exports: HashMap<String, u64>,
    first_dir64: Option<(u64, u64)>,
}

fn map_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Mapped {
    let pristine = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    let mut image = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    assert!(image.is_64bit, "an x86_64-windows COM DLL must be PE32+");
    assert!(!image.relocations.is_empty(), "a Wine PE DLL carries a .reloc table");

    let preferred = image.image_base;
    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, preferred, base)
        .expect("apply base relocations");

    let first_dir64 = image.relocations.iter().find(|r| r.kind == 10).and_then(|r| {
        let s = pristine
            .sections
            .iter()
            .find(|s| r.rva >= s.rva && ((r.rva - s.rva) as usize) + 8 <= s.data.len())?;
        let off = (r.rva - s.rva) as usize;
        let mut w = [0u8; 8];
        w.copy_from_slice(&s.data[off..off + 8]);
        Some((base + r.rva as u64, u64::from_le_bytes(w)))
    });

    let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
    mem.map(Region::new("dll_headers", base, hdr_len, Perm::RWX)).unwrap();
    mem.write(base, &image.headers).unwrap();
    for s in &image.sections {
        let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
        let map_len = align_up(vsize, 0x1000).max(0x1000);
        let addr = base + s.rva as u64;
        if mem.map(Region::new("dll_section", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
            mem.write(addr, &s.data).unwrap();
        } else if !s.data.is_empty() {
            mem.poke(addr, &s.data).unwrap();
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Mapped { exports, first_dir64 }
}

fn call_export(mem: &mut VirtualMemory, entry: u64, args: &[u64]) -> u64 {
    let mut os = exemu_core::hooks::NoHooks;
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = entry;
        s.set_rsp(rsp);
        let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().take(4).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    mem.write_u64(rsp, SENTINEL).unwrap();
    let mut steps = 0u64;
    loop {
        match cpu.step(mem, &mut os).expect("the DLL's own bytes faulted") {
            Exit::Continue => steps += 1,
            Exit::Halted => break,
            other => panic!("unexpected exit driving the export: {other:?}"),
        }
        assert!(steps < 100_000, "leaf export ran away");
    }
    cpu.state().reg(Reg::Rax)
}

#[test]
fn com_core_dlls_map_relocate_and_resolve_imports() {
    if !Path::new(WINE_DLLS).join("ole32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ole32.dll not present (Wine DLL set is git-ignored)");
        return;
    }
    let mut prefix = Prefix::default();

    for ComDll { name, base, api, local } in COM_DLLS {
        let bytes = std::fs::read(Prefix::dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let image = exemu_loader::parse(&bytes).expect("parses as PE");

        let mut imported_dlls: Vec<String> = Vec::new();
        for imp in &image.imports {
            if !imported_dlls.contains(&imp.dll) {
                imported_dlls.push(imp.dll.clone());
            }
            let exemu_core::ImportSymbol::Named(sym) = &imp.symbol else {
                continue;
            };
            assert!(
                prefix.resolves(&imp.dll, sym),
                "{name} imports {}!{sym}, which does not resolve in the pinned prefix",
                imp.dll
            );
        }
        assert!(
            !imported_dlls.is_empty(),
            "{name} should import from the rest of the Wine set"
        );

        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", STACK_TOP - 0x4000, 0x4000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
        mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
        mem.poke(SENTINEL, &[0xF4]).unwrap();
        let mapped = map_dll(&mut mem, &bytes, *base);
        let delta = base.wrapping_sub(image.image_base);
        let (addr, before) = mapped
            .first_dir64
            .unwrap_or_else(|| panic!("{name} should carry DIR64 relocations"));
        assert_eq!(
            mem.read_u64(addr).unwrap(),
            before.wrapping_add(delta),
            "{name}: the DIR64 fixup at {addr:#x} was applied for the load delta"
        );

        for sym in *api {
            assert!(
                prefix.resolves(name, sym),
                "{name}!{sym} must resolve (directly or through its forwarder chain)"
            );
        }
        let extent = *base..*base + align_up(image.size_of_image as u64, 0x1000);
        for sym in *local {
            let va = *mapped
                .exports
                .get(*sym)
                .unwrap_or_else(|| panic!("{name} must export {sym} as local (non-forwarder) code"));
            assert!(extent.contains(&va), "{name}!{sym} at {va:#x} lands inside the mapped image");
        }

        if *name == "oleaut32.dll" {
            let sys_string_len = mapped.exports["SysStringLen"];
            assert_eq!(call_export(&mut mem, sys_string_len, &[0]), 0, "SysStringLen(NULL)");
            let bstr = SCRATCH + 0x100;
            mem.write_u32(bstr - 4, 10).unwrap();
            for (i, u) in "exemu".encode_utf16().enumerate() {
                mem.write_u16(bstr + (i as u64) * 2, u).unwrap();
            }
            assert_eq!(
                call_export(&mut mem, sys_string_len, &[bstr]) as u32,
                5,
                "oleaut32!SysStringLen ran its own relocated bytes and read the BSTR prefix"
            );
        }
    }
}

fn expected_lines() -> [String; 4] {
    [
        format!("{}00000000", sample::COM_LABEL_INIT),
        format!("{}00000000", sample::COM_LABEL_HR),
        format!("{}00000002", sample::COM_LABEL_REFS),
        sample::COM_OK_MESSAGE.trim_end().to_string(),
    ]
}

#[test]
fn com_create_instance_resolves_through_the_registry_on_wine() {
    if !Path::new(WINE_DLLS).join("ole32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ole32.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let exe = sample::build_com();

    let emulated = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 1_000_000,
            ..RunConfig::default()
        },
    )
    .expect("emulated run");
    assert_eq!(emulated.exit_code, 1, "emulated path has no COM, so the sample reports failure");
    assert!(
        String::from_utf8_lossy(&emulated.stdout).contains(sample::COM_FAIL_MESSAGE.trim_end()),
        "emulated stdout: {:?}",
        String::from_utf8_lossy(&emulated.stdout)
    );

    let wine = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 200_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            ..RunConfig::default()
        },
    )
    .expect("wine-boot run");

    let stdout = String::from_utf8_lossy(&wine.stdout).into_owned();
    for line in expected_lines() {
        assert!(
            stdout.contains(&line),
            "expected {line:?} in the COM sample's stdout, got:\n{stdout}"
        );
    }
    assert_eq!(
        wine.exit_code,
        sample::COM_OK_EXIT,
        "the COM sample's distinguishing success code, stdout:\n{stdout}"
    );
    assert!(
        wine.steps > 1_000_000,
        "the full Wine COM core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}
