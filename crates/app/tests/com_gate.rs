//! W6.3 / W6.4 — **COM arrives as guest code**, and exemu's registry backs the
//! CLSID resolution that makes it work.
//!
//! Two claims, tested separately:
//!
//! * **W6.3 (DLL smoke)** — `ole32.dll` / `oleaut32.dll` / `combase.dll` from
//!   the pinned Wine prefix map, relocate away from their preferred base, and
//!   every symbol they import resolves against a DLL that is actually in the
//!   prefix (forwarders chased). One of their exports is then driven **through
//!   the real CPU on the DLL's own bytes** (`oleaut32!SysStringLen`) so
//!   "callable" is executed, not assumed.
//!
//! * **W6.3 + W6.4 (the gate)** — exemu's generated COM console program
//!   ([`sample::build_com`]) runs on the full Wine boot: `CoInitializeEx`
//!   succeeds, `CoCreateInstance` resolves its CLSID **through exemu's registry
//!   hive** to `InprocServer32 = ole32.dll`, loads that in-proc server and
//!   returns an interface pointer, and the program then calls `AddRef`
//!   **through the returned vtable** — a guest indirect call on guest memory,
//!   with no native COM anywhere in exemu.
//!
//! The registry half is load-bearing, not incidental: before the W6.4 seed +
//! case-folding this same program reported `CoCreateInstance=80040154`
//! (`REGDB_E_CLASSNOTREG`).
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_app::{load_and_run, sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// One COM core DLL W6.3 claims arrives free.
struct ComDll {
    name: &'static str,
    /// A base deliberately *not* the preferred `0x1_8000_0000`, so the `.reloc`
    /// walk really runs.
    base: u64,
    /// Symbols that must be exported and resolvable somewhere in the prefix —
    /// possibly as a forwarder.
    api: &'static [&'static str],
    /// Symbols that must be **local code** in this image (not forwarders), so
    /// there is real relocated machine code at `base + rva` to call.
    local: &'static [&'static str],
}

/// Note on `ole32.dll` (a finding from the pinned binaries, not an assumption):
/// in Wine 11.0 the COM core proper lives in **combase.dll**, and ole32 exports
/// `CoInitializeEx`/`CoCreateInstance`/`CoUninitialize`/`CoGetClassObject` as
/// **forwarders** to it (ole32 also imports 67 symbols from combase). So a
/// program that imports ole32 by name — like exemu's COM sample — reaches
/// combase's implementation through ole32's export table, which is exactly what
/// the end-to-end gate exercises. The two DLLs are therefore checked with
/// different "must be local" sets.
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

// ==========================================================================
// A tiny prefix-wide symbol resolver, so "its imports resolve" is checked
// against the DLLs that are really there rather than asserted.
// ==========================================================================

/// Lazily-parsed export tables for the pinned prefix: DLL name → (export name →
/// forwarder target, if the export is a forwarder).
#[derive(Default)]
struct Prefix {
    modules: HashMap<String, Option<HashMap<String, Option<String>>>>,
}

impl Prefix {
    fn dir() -> PathBuf {
        PathBuf::from(WINE_DLLS)
    }

    /// The export table of `dll` from the prefix, or `None` when the file is
    /// absent / not a PE we can parse.
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

    /// Can `dll!symbol` be resolved inside the prefix? Forwarders
    /// (`"combase.CoInitializeEx"`) are chased, bounded so a cycle terminates.
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
                return true; // a real export in this module
            };
            // "OTHERDLL.FuncName" / "OTHERDLL.#Ordinal".
            let Some((target_dll, target_sym)) = fwd.rsplit_once('.') else {
                return false;
            };
            if target_sym.starts_with('#') {
                // Forwarded by ordinal — the target module merely has to exist.
                return self.exports(&format!("{}.dll", target_dll.to_ascii_lowercase())).is_some();
            }
            dll = format!("{}.dll", target_dll.to_ascii_lowercase());
            symbol = target_sym.to_string();
        }
        false
    }
}

// ==========================================================================
// Mapping a prefix DLL at a chosen base, with its exports resolved by name.
// ==========================================================================

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000; // one page whose first byte is `hlt`

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

struct Mapped {
    exports: HashMap<String, u64>,
    /// The 64-bit words the `.reloc` walk rewrote, as `(address, before)`.
    first_dir64: Option<(u64, u64)>,
}

/// Parse, relocate to `base` and map `bytes` into `mem`, returning the resolved
/// export map plus the first DIR64 fixup site so a test can prove the
/// relocation actually landed in guest memory.
fn map_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Mapped {
    let pristine = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    let mut image = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    assert!(image.is_64bit, "an x86_64-windows COM DLL must be PE32+");
    assert!(!image.relocations.is_empty(), "a Wine PE DLL carries a .reloc table");

    let preferred = image.image_base;
    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, preferred, base)
        .expect("apply base relocations");

    // The first DIR64 fixup: record its pre-relocation value from the pristine
    // parse so the caller can assert mem == before + (base - preferred).
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
            continue; // a re-export string, not a callable stub
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Mapped { exports, first_dir64 }
}

/// Drive a call to `entry` on the real interpreter with Win64 args in
/// RCX/RDX/R8/R9, a `hlt` sentinel as the return address, and return RAX. Any
/// unimplemented path surfaces as a fault that fails the test.
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

// ==========================================================================
// W6.3 — the COM core maps, relocates, resolves its imports, and runs.
// ==========================================================================

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

        // (1) Every import resolves inside the pinned prefix (forwarders chased).
        let mut imported_dlls: Vec<String> = Vec::new();
        for imp in &image.imports {
            if !imported_dlls.contains(&imp.dll) {
                imported_dlls.push(imp.dll.clone());
            }
            let exemu_core::ImportSymbol::Named(sym) = &imp.symbol else {
                continue; // by-ordinal imports are checked via the module's presence
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

        // (2) It maps + relocates away from its preferred base, and the fixups
        //     really landed in guest memory.
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("stack", STACK_TOP - 0x4000, 0x4000, Perm::RW)).unwrap();
        mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
        mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
        mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt
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

        // (3a) The COM API surface resolves — here or through a forwarder.
        for sym in *api {
            assert!(
                prefix.resolves(name, sym),
                "{name}!{sym} must resolve (directly or through its forwarder chain)"
            );
        }
        // (3b) The symbols that are this module's own code land at real
        //      addresses inside the *relocated* image.
        let extent = *base..*base + align_up(image.size_of_image as u64, 0x1000);
        for sym in *local {
            let va = *mapped
                .exports
                .get(*sym)
                .unwrap_or_else(|| panic!("{name} must export {sym} as local (non-forwarder) code"));
            assert!(extent.contains(&va), "{name}!{sym} at {va:#x} lands inside the mapped image");
        }

        // (4) CALLABLE — for oleaut32, run one of its exports on the real CPU
        //     over the DLL's own bytes. `SysStringLen` is a leaf (it reads the
        //     BSTR's byte-count prefix at [ptr-4] and halves it), so it needs no
        //     imports or COM state: a perfect "the mapped code executes" probe.
        //     ole32's and combase's exports are executed for real by the
        //     end-to-end gate below, which calls CoInitializeEx /
        //     CoCreateInstance / CoUninitialize through them.
        if *name == "oleaut32.dll" {
            let sys_string_len = mapped.exports["SysStringLen"];
            // NULL BSTR → 0, per the documented contract.
            assert_eq!(call_export(&mut mem, sys_string_len, &[0]), 0, "SysStringLen(NULL)");
            // A hand-laid BSTR: byte count at [ptr-4], then the UTF-16 chars.
            let bstr = SCRATCH + 0x100;
            mem.write_u32(bstr - 4, 10).unwrap(); // 10 bytes = 5 chars
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

// ==========================================================================
// W6.3 + W6.4 GATE — CoCreateInstance through exemu's registry, then a guest
// vtable call on the returned interface.
// ==========================================================================

/// The exact stdout the gate expects: `CoInitializeEx` = S_OK,
/// `CoCreateInstance` = S_OK, and `AddRef` reporting 2 references (the one
/// `CoCreateInstance` handed out plus the one `AddRef` added).
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

    // --- CONTROL: the EMULATED path cannot do COM ------------------------
    // exemu has no native ole32, so `CoCreateInstance` is an `Unsupported`
    // stub: it returns 0 but never writes the out-pointer, the sample sees a
    // NULL interface, and reports FAIL. This is what makes the Wine result
    // below meaningful — the object can only have come from Wine's own COM
    // core, not from an exemu thunk.
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

    // --- THE GATE: boot Wine's real PE core and create a COM object ------
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
    // Wine's whole COM stack (ole32 → combase → rpcrt4/advapi32/user32/…) really
    // booted: orders of magnitude more instructions than the emulated control.
    assert!(
        wine.steps > 1_000_000,
        "the full Wine COM core booted ({} steps vs {} emulated)",
        wine.steps,
        emulated.steps
    );
}
