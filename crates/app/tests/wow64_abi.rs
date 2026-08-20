//! W5 — **the WoW64 boundary, re-derived from the pinned binaries**.
//!
//! Modelled on `afd_abi.rs`: every fact exemu's WoW64 boot depends on is read
//! back out of `example_exe/wine-dlls/{i386,x86_64}-windows/*.dll` on **every
//! run** and asserted against the constants in [`exemu_os::wow64`]. A guessed
//! TEB offset, a drifted syscall-stub shape or the wrong publish target fails
//! *here*, by name, instead of turning into a silent wrong answer three layers
//! down — which is exactly what a WoW64 boundary does when it is guessed.
//!
//! What it establishes, all from the binary:
//!
//! 1. **Wine's 32-bit `ntdll` routes its syscall stubs through
//!    `__wine_syscall_dispatcher`, not `Wow64Transition`.** Every `Nt*`/`Zw*`
//!    stub is `mov eax,<index>; mov edx,<helper>; call edx; ret <argbytes>`, and
//!    that one shared helper is a single
//!    `jmp dword ptr [__wine_syscall_dispatcher]`. This is the fact that makes
//!    or breaks the boot: publishing only the famous `Wow64Transition` name
//!    leaves 526 stubs jumping through a null pointer.
//! 2. The one stub that does *not* — `NtQueryInformationProcess` — uses
//!    `call dword ptr fs:[0xC0]`, i.e. `TEB32.WOW32Reserved`, the third cell the
//!    boot publishes.
//! 3. `wow64.dll` resolves **both** names out of the 32-bit ntdll and stores
//!    `BTCpuGetBopCode()`'s result into each, and writes the same value to
//!    `TEB32+0xC0` — which is why exemu's bring-up trampoline writes all three.
//! 4. `TEB64+0x180c` is the signed 32-bit `WowTebOffset`, witnessed independently
//!    by `wow64.dll` and by the 64-bit `ntdll!RtlWow64GetCurrentMachine`.
//! 5. `RtlWow64GetThreadContext` is `NtQueryInformationThread(_,
//!    ThreadWow64Context = 0x1d, _, 0x2cc, _)` — the class and buffer size
//!    exemu's handler implements.
//! 6. The 32-bit and 64-bit ntdll **share one SSDT index space**, which is what
//!    lets `wow64.dll`'s table-0 dispatch work at all.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::BTreeMap;

use exemu_os::wow64;

const DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_set() -> bool {
    std::path::Path::new(DLLS32).join("ntdll.dll").is_file()
        && std::path::Path::new(DLLS64).join("wow64.dll").is_file()
}

/// A parsed image plus the raw bytes of its sections, addressed by RVA.
struct Img {
    image_base: u64,
    exports: BTreeMap<String, u32>,
    /// `(rva, bytes)` per section with file data, sorted by rva.
    sections: Vec<(u32, Vec<u8>)>,
    text_rva: u32,
    text: Vec<u8>,
}

fn load(path: &str) -> Img {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let img = exemu_loader::parse(&bytes).expect("pinned DLL parses");
    let mut exports = BTreeMap::new();
    for e in &img.exports {
        if e.forwarder.is_none() {
            if let Some(n) = &e.name {
                exports.insert(n.clone(), e.rva);
            }
        }
    }
    let mut sections: Vec<(u32, Vec<u8>)> = img
        .sections
        .iter()
        .filter(|s| !s.data.is_empty())
        .map(|s| (s.rva, s.data.clone()))
        .collect();
    sections.sort_by_key(|(r, _)| *r);
    // The first executable section is `.text` for every image here.
    let (text_rva, text) = img
        .sections
        .iter()
        .find(|s| s.executable && !s.data.is_empty())
        .map(|s| (s.rva, s.data.clone()))
        .expect("an executable section with data");
    Img { image_base: img.image_base, exports, sections, text_rva, text }
}

impl Img {
    /// Bytes at `rva`, from whichever section covers it (empty past the end).
    fn at(&self, rva: u32, len: usize) -> &[u8] {
        for (base, data) in &self.sections {
            if rva >= *base && (rva - *base) as usize <= data.len() {
                let off = (rva - *base) as usize;
                let end = (off + len).min(data.len());
                return &data[off..end];
            }
        }
        &[]
    }

    fn export(&self, name: &str) -> u32 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("the pinned DLL does not export {name}"))
    }

    fn va(&self, rva: u32) -> u64 {
        self.image_base + rva as u64
    }
}

/// One recovered 32-bit `Nt*` syscall stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stub32 {
    /// `B8 <index> BA <helper> FF D2 C2 <argbytes>` — the ordinary shape.
    ViaHelper { index: u32, helper: u32, arg_bytes: u16 },
    /// `B8 <index> 64 FF 15 <teb_disp32> C2 <argbytes>` — `call dword fs:[disp]`.
    ViaTeb { index: u32, teb_disp: u32, arg_bytes: u16 },
}

fn classify_stub32(b: &[u8]) -> Option<Stub32> {
    if b.len() < 16 || b[0] != 0xB8 {
        return None;
    }
    let index = u32::from_le_bytes(b[1..5].try_into().unwrap());
    if b[5] == 0xBA && b[10] == 0xFF && b[11] == 0xD2 && b[12] == 0xC2 {
        return Some(Stub32::ViaHelper {
            index,
            helper: u32::from_le_bytes(b[6..10].try_into().unwrap()),
            arg_bytes: u16::from_le_bytes(b[13..15].try_into().unwrap()),
        });
    }
    if b[5..8] == [0x64, 0xFF, 0x15] && b[12] == 0xC2 {
        return Some(Stub32::ViaTeb {
            index,
            teb_disp: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            arg_bytes: u16::from_le_bytes(b[13..15].try_into().unwrap()),
        });
    }
    None
}

/// The SSDT index carried by a **64-bit** Wine ntdll stub
/// (`4C 8B D1` `mov r10,rcx`; `B8 <imm32>` `mov eax,N`).
fn ssdt_index64(img: &Img, name: &str) -> Option<u32> {
    let b = img.at(img.export(name), 9);
    (b.len() >= 9 && b[..4] == [0x4C, 0x8B, 0xD1, 0xB8])
        .then(|| u32::from_le_bytes(b[4..8].try_into().unwrap()))
}

/// Every RVA in `.text` whose `lea r?, [rip+disp32]` resolves to `target`.
fn lea_rip_sites(img: &Img, target: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let c = &img.text;
    let mut i = 0usize;
    while i + 7 <= c.len() {
        // 48 8D <modrm with mod=00, rm=101> disp32  → lea r64, [rip+disp32]
        if c[i] == 0x48 && c[i + 1] == 0x8D && (c[i + 2] & 0xC7) == 0x05 {
            let disp = i32::from_le_bytes(c[i + 3..i + 7].try_into().unwrap());
            let next = img.text_rva as i64 + i as i64 + 7;
            if next + disp as i64 == target as i64 {
                out.push(img.text_rva + i as u32);
            }
        }
        i += 1;
    }
    out
}

/// Find the first occurrence of `pat` in `.text`, as an RVA.
fn find_text(img: &Img, pat: &[u8]) -> Option<u32> {
    find_text_all(img, pat).into_iter().next()
}

/// Every occurrence of `pat` in `.text`, as RVAs.
fn find_text_all(img: &Img, pat: &[u8]) -> Vec<u32> {
    img.text
        .windows(pat.len())
        .enumerate()
        .filter(|(_, w)| *w == pat)
        .map(|(i, _)| img.text_rva + i as u32)
        .collect()
}

/// The RVA of an ASCII string in any section (NUL-terminated, exact match).
fn find_string(img: &Img, s: &str) -> Option<u32> {
    let mut needle = s.as_bytes().to_vec();
    needle.push(0);
    for (base, data) in &img.sections {
        if let Some(i) = data.windows(needle.len()).position(|w| w == needle) {
            return Some(base + i as u32);
        }
    }
    None
}

// ==========================================================================
// (1) + (2) The 32-bit ntdll's syscall-stub shape
// ==========================================================================

/// **The load-bearing recovery.** Wine's 32-bit `ntdll` funnels every `Nt*` stub
/// through a single helper, and that helper jumps through
/// `__wine_syscall_dispatcher` — *not* `Wow64Transition`. Both cells exist and
/// are 0x10 bytes apart in `.bss`, so publishing the wrong one is a silent
/// null-pointer jump, which is why this is pinned rather than assumed.
#[test]
fn ntdll32_syscall_stubs_route_through_wine_syscall_dispatcher() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n32 = load(&format!("{DLLS32}/ntdll.dll"));

    let mut helpers = BTreeMap::<u32, usize>::new();
    let mut via_teb = Vec::new();
    let mut n_stubs = 0usize;
    for (name, &rva) in &n32.exports {
        if !(name.starts_with("Nt") || name.starts_with("Zw")) {
            continue;
        }
        match classify_stub32(n32.at(rva, 16)) {
            Some(Stub32::ViaHelper { helper, .. }) => {
                *helpers.entry(helper).or_default() += 1;
                n_stubs += 1;
            }
            Some(Stub32::ViaTeb { teb_disp, .. }) => {
                via_teb.push((name.clone(), teb_disp));
                n_stubs += 1;
            }
            None => {}
        }
    }
    assert!(n_stubs > 400, "the pinned 32-bit ntdll should carry hundreds of Nt* stubs, saw {n_stubs}");
    assert_eq!(helpers.len(), 1, "all helper-routed stubs share ONE helper, saw {helpers:?}");
    let (&helper_va, &n_via_helper) = helpers.iter().next().unwrap();
    assert!(n_via_helper > 400, "{n_via_helper} stubs route through the shared helper");

    // The helper is exactly `FF 25 <abs32>` — a 32-bit **absolute** indirect
    // near jump (not RIP-relative; this is 32-bit code).
    let helper_rva = (helper_va as u64 - n32.image_base) as u32;
    let h = n32.at(helper_rva, 6);
    assert_eq!(&h[..2], &[0xFF, 0x25], "the shared helper is `jmp dword ptr [mem]`, saw {h:02x?}");
    let cell_va = u32::from_le_bytes(h[2..6].try_into().unwrap()) as u64;

    let dispatcher_va = n32.va(n32.export("__wine_syscall_dispatcher"));
    let transition_va = n32.va(n32.export("Wow64Transition"));
    assert_eq!(
        cell_va, dispatcher_va,
        "the helper jumps through __wine_syscall_dispatcher ({dispatcher_va:#x}), \
         NOT Wow64Transition ({transition_va:#x})",
    );
    assert_ne!(
        cell_va, transition_va,
        "the two cells are distinct — publishing only Wow64Transition would leave the stubs null",
    );

    // (2) The single outlier reads TEB32.WOW32Reserved.
    assert_eq!(via_teb.len(), 2, "exactly the Nt/Zw alias pair uses the fs: shape: {via_teb:?}");
    for (name, disp) in &via_teb {
        assert_eq!(
            *disp as u64, wow64::TEB32_WOW32_RESERVED,
            "{name} reads TEB32+{disp:#x}; exemu_os::wow64::TEB32_WOW32_RESERVED is {:#x}",
            wow64::TEB32_WOW32_RESERVED,
        );
    }
}

/// (6) The 32-bit and 64-bit ntdll share one SSDT index space — the premise
/// `wow64.dll`'s table-0 dispatch rests on, and the reason a 32-bit guest's
/// `mov eax,0x18` reaches exemu's `NtAllocateVirtualMemory`.
#[test]
fn ntdll32_and_ntdll64_share_one_ssdt_index_space() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n32 = load(&format!("{DLLS32}/ntdll.dll"));
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));

    let mut checked = 0;
    for (name, &rva) in &n32.exports {
        if !name.starts_with("Nt") {
            continue;
        }
        let idx32 = match classify_stub32(n32.at(rva, 16)) {
            Some(Stub32::ViaHelper { index, .. }) | Some(Stub32::ViaTeb { index, .. }) => index,
            None => continue,
        };
        let Some(idx64) = n64.exports.get(name).and_then(|_| ssdt_index64(&n64, name)) else {
            continue;
        };
        assert_eq!(idx32, idx64, "{name}: 32-bit index {idx32:#x} != 64-bit index {idx64:#x}");
        checked += 1;
    }
    assert!(checked > 250, "cross-checked {checked} services (expected 250+)");
}

// ==========================================================================
// (3) + (4) wow64.dll publishes the BOP into all three cells
// ==========================================================================

/// `wow64.dll` resolves `"Wow64Transition"` **and** `"__wine_syscall_dispatcher"`
/// by name out of the 32-bit ntdll, and both stores take their value from the
/// *same* `BTCpuGetBopCode` pointer slot — the contract exemu's bring-up
/// trampoline reproduces.
#[test]
fn wow64_dll_publishes_the_bop_into_both_named_cells() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));

    let transition = find_string(&w, "Wow64Transition").expect("wow64.dll references \"Wow64Transition\"");
    let dispatcher =
        find_string(&w, "__wine_syscall_dispatcher").expect("wow64.dll references \"__wine_syscall_dispatcher\"");

    let t_sites = lea_rip_sites(&w, transition);
    let d_sites = lea_rip_sites(&w, dispatcher);
    assert!(!t_sites.is_empty(), "wow64.dll takes the address of \"Wow64Transition\"");
    assert!(
        !d_sites.is_empty(),
        "wow64.dll ALSO takes the address of \"__wine_syscall_dispatcher\" — \
         it publishes into both cells, which is why exemu does too",
    );

    // Both publish sites end in `call qword ptr [rip+disp32]` (BTCpuGetBopCode)
    // followed by a **32-bit** store of `eax` — `mov [r12], eax` (41 89 04 24)
    // at the Wow64Transition site and `mov [rbx], eax` (89 03) at the helper.
    // The store width is why the BOP must live below 4 GiB.
    let store32_sites = [
        find_text(&w, &[0x41, 0x89, 0x04, 0x24]), // mov dword ptr [r12], eax
        find_text(&w, &[0x89, 0x03]),             // mov dword ptr [rbx], eax
    ];
    assert!(
        store32_sites.iter().all(|s| s.is_some()),
        "wow64.dll stores the BOP as a 32-bit dword (the sub-4 GiB constraint)",
    );
}

/// (4) `TEB64+0x180c` is the signed 32-bit `WowTebOffset`, and `TEB32+0xC0` is
/// where the BOP goes — recovered from `wow64.dll`'s per-thread init, which does
/// `movsxd rdx,[rax+0x180c]` and then `mov [rax+rdx+0xc0], ecx` back to back.
#[test]
fn wow_teb_offset_and_wow32_reserved_are_recovered_from_wow64_dll() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));

    // movsxd rdx, dword ptr [rax + WowTebOffset]
    let mut movsxd = vec![0x48, 0x63, 0x90];
    movsxd.extend_from_slice(&(wow64::TEB64_WOW_TEB_OFFSET as u32).to_le_bytes());
    let loads = find_text_all(&w, &movsxd);
    assert!(
        !loads.is_empty(),
        "wow64.dll does not sign-extend [teb64+{:#x}] — TEB64_WOW_TEB_OFFSET has drifted",
        wow64::TEB64_WOW_TEB_OFFSET,
    );

    // …and the very next instruction of the per-thread init stores into
    // [rax + rdx + WOW32Reserved], i.e. into **TEB32**.
    let mut store = vec![0x89, 0x8C, 0x10];
    store.extend_from_slice(&(wow64::TEB32_WOW32_RESERVED as u32).to_le_bytes());
    let store_at = find_text(&w, &store).unwrap_or_else(|| {
        panic!(
            "wow64.dll does not store into [teb64+WowTebOffset+{:#x}]",
            wow64::TEB32_WOW32_RESERVED
        )
    });
    assert!(
        loads.iter().any(|&at| store_at > at && store_at - at < 0x20),
        "the WOW32Reserved store ({store_at:#x}) directly follows one of the WowTebOffset \
         loads ({loads:#x?}) — the two together are what identify TEB32",
    );

    // Independent witness: the 64-bit ntdll's RtlWow64GetCurrentMachine reads
    // the same field and treats zero as "not a WoW64 thread".
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));
    let m = n64.at(n64.export("RtlWow64GetCurrentMachine"), 0x30);
    let mut load_off = vec![0x8B, 0x90];
    load_off.extend_from_slice(&(wow64::TEB64_WOW_TEB_OFFSET as u32).to_le_bytes());
    assert!(
        m.windows(load_off.len()).any(|x| x == load_off),
        "ntdll!RtlWow64GetCurrentMachine reads TEB64+{:#x} too",
        wow64::TEB64_WOW_TEB_OFFSET,
    );
}

/// (5) `RtlWow64GetThreadContext` is a thin wrapper over
/// `NtQueryInformationThread(_, 0x1d, _, 0x2cc, NULL)` — the class and length
/// exemu's handler implements, read out of the stub rather than chosen.
#[test]
fn rtl_wow64_get_thread_context_pins_the_class_and_length() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));
    let rva = n64.export("RtlWow64GetThreadContext");
    let b = n64.at(rva, 0x28);

    let mut want_len = vec![0x41, 0xB9]; // mov r9d, imm32
    want_len.extend_from_slice(&(wow64::WOW64_CONTEXT_SIZE as u32).to_le_bytes());
    assert!(
        b.windows(want_len.len()).any(|w| w == want_len),
        "RtlWow64GetThreadContext passes ThreadInformationLength = {:#x}",
        wow64::WOW64_CONTEXT_SIZE,
    );
    let mut want_class = vec![0xBA]; // mov edx, imm32
    want_class.extend_from_slice(&wow64::THREAD_WOW64_CONTEXT.to_le_bytes());
    assert!(
        b.windows(want_class.len()).any(|w| w == want_class),
        "RtlWow64GetThreadContext passes ThreadInformationClass = {:#x}",
        wow64::THREAD_WOW64_CONTEXT,
    );

    // The direct `call rel32` lands on a real syscall stub, and its index is the
    // one `NtQueryInformationThread` exports — so the class above really is a
    // `NtQueryInformationThread` class, not some other service's.
    let call_off = b
        .iter()
        .position(|&x| x == 0xE8)
        .expect("RtlWow64GetThreadContext ends in a direct call");
    let disp = i32::from_le_bytes(b[call_off + 1..call_off + 5].try_into().unwrap());
    let target = (rva as i64 + call_off as i64 + 5 + disp as i64) as u32;
    let stub = n64.at(target, 9);
    assert_eq!(&stub[..4], &[0x4C, 0x8B, 0xD1, 0xB8], "the call target is a `mov r10,rcx` syscall stub");
    let idx = u32::from_le_bytes(stub[4..8].try_into().unwrap());
    assert_eq!(
        Some(idx),
        ssdt_index64(&n64, "NtQueryInformationThread"),
        "…and it is NtQueryInformationThread",
    );
}

/// The WoW64 CPU-reserved area pointer (`TEB64+0x1488`) that `BTCpuSimulate`
/// reads, and the `WOW64INFO` slot (`TEB64+0x14d0`) `BTCpuProcessInit` flags —
/// both re-derived from `wow64cpu.dll`'s own bytes.
#[test]
fn wow64cpu_reads_the_cpu_area_and_wow64info_teb_slots() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let c = load(&format!("{DLLS64}/wow64cpu.dll"));

    // mov rcx, qword ptr [r12 + 0x1488]   (BTCpuSimulate)
    let mut area = vec![0x49, 0x8B, 0x8C, 0x24];
    area.extend_from_slice(&(wow64::TEB_CPU_AREA_PTR_OFF as u32).to_le_bytes());
    // mov rax, qword ptr [rax + 0x14d0]   (BTCpuProcessInit)
    let mut info = vec![0x48, 0x8B, 0x80];
    info.extend_from_slice(&0x14d0u32.to_le_bytes());
    assert!(
        find_text(&c, &area).is_some(),
        "wow64cpu reads the CPU-reserved area at TEB+{:#x}",
        wow64::TEB_CPU_AREA_PTR_OFF,
    );
    assert!(
        find_text(&c, &info).is_some(),
        "wow64cpu reads the WOW64INFO pointer at TEB+0x14d0 (distinct from the cpu area)",
    );

    // Its five ntdll imports — the ones the WoW64 boot has to be able to service
    // for `BTCpuProcessInit` to run at all.
    let bytes = std::fs::read(format!("{DLLS64}/wow64cpu.dll")).unwrap();
    let img = exemu_loader::parse(&bytes).unwrap();
    let mut imports: Vec<String> = img
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) if i.dll == "ntdll.dll" => Some(n.clone()),
            _ => None,
        })
        .collect();
    imports.sort();
    for want in [
        "LdrGetDllHandle",
        "NtProtectVirtualMemory",
        "RtlCaptureContext",
        "RtlFindExportedRoutineByName",
        "RtlWow64GetThreadContext",
    ] {
        assert!(
            imports.iter().any(|n| n == want),
            "wow64cpu imports ntdll!{want} (its process init calls it); saw {imports:?}",
        );
    }
}
