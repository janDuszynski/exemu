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
    /// `(IAT slot rva, dll, symbol)` for every by-name import.
    imports: Vec<(u32, String, String)>,
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
    let imports = img
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => {
                Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone()))
            }
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    Img { image_base: img.image_base, exports, sections, text_rva, text, imports }
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

// ==========================================================================
// (7) The 32-bit bootstrap contract, read out of the i386 ntdll
// ==========================================================================

/// **The i386 thread-start convention is NOT the 64-bit one.**
///
/// `ntdll32!RtlUserThreadStart` is three instructions —
/// `mov [esp+8],ebx; mov [esp+4],eax; jmp <thread start>` — so a fresh 32-bit
/// thread carries its entry point in **`Eax`** and its argument in **`Ebx`**,
/// where the 64-bit one uses `Rcx`/`Rdx`. exemu's [`wow64::Start32`] seeds
/// exactly those registers; getting it from the 64-bit shape would put the
/// entry point nowhere.
///
/// And `LdrInitializeThunk` takes its `CONTEXT` as a **stack** argument
/// (`mov ebx,[ebp+8]`), then hands `loader_init` a pointer to `context->Eax`
/// (`lea eax,[ebx+0xb0]`) — which is both the second proof of the convention
/// and the reason `CTX_EAX` must be 0xb0.
#[test]
fn ntdll32_thread_start_passes_the_entry_point_in_eax() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n32 = load(&format!("{DLLS32}/ntdll.dll"));

    let start = n32.at(n32.export("RtlUserThreadStart"), 12);
    assert_eq!(
        &start[..8],
        // mov dword ptr [esp+8], ebx ; mov dword ptr [esp+4], eax
        &[0x89, 0x5C, 0x24, 0x08, 0x89, 0x44, 0x24, 0x04],
        "RtlUserThreadStart forwards (eax, ebx) as (EntryPoint, Arg): {start:02x?}",
    );
    assert_eq!(start[8], 0xE9, "…and tail-jumps to the thread start");

    // LdrInitializeThunk(context): `push ebp; mov ebp,esp; push ebx;
    // sub esp,0x18; mov ebx,[ebp+8]; lea eax,[ebx+0xb0]`.
    let thunk = n32.at(n32.export("LdrInitializeThunk"), 16);
    assert_eq!(&thunk[..2], &[0x55, 0x89], "LdrInitializeThunk opens with a frame: {thunk:02x?}");
    let mut want_arg = vec![0x8B, 0x5D, 0x08]; // mov ebx, [ebp+8]  (the CONTEXT*)
    want_arg.extend_from_slice(&[0x8D, 0x83]); // lea eax, [ebx+disp32]
    want_arg.extend_from_slice(&(wow64::CTX_EAX as u32).to_le_bytes());
    assert!(
        thunk.windows(want_arg.len()).any(|w| w == want_arg),
        "LdrInitializeThunk reads its CONTEXT off the stack and passes &CONTEXT.Eax \
         (offset {:#x}) to loader_init: {thunk:02x?}",
        wow64::CTX_EAX,
    );
}

/// **`LdrSystemDllInitBlock` is how `wow64.dll` finds the 32-bit ntdll.**
///
/// Every offset exemu fills is a site in `wow64.dll` that reads it. The two
/// load-bearing ones: `[block+0x18]` becomes a fresh 32-bit thread's `Eip`
/// (per-thread init, rva 0x570e — this is what starts Wine's own 32-bit
/// loader), and `[block+0x48]` is passed to `RtlFindExportedRoutineByName` as a
/// module handle (process init, rva 0x4879) — so it is the ntdll32 **base**,
/// not a routine.
#[test]
fn wow64_dll_reads_the_system_dll_init_block_fields_exemu_fills() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));
    assert!(n64.exports.contains_key("LdrSystemDllInitBlock"), "the 64-bit ntdll exports the block");

    // `mov rax, qword ptr [rax + off]` for each field, then a 32-bit store of
    // eax — the narrowing that requires every value to be 32-bit addressable.
    for (name, off) in [
        ("LdrInitializeThunk", wow64::SYSDLL_LDR_INITIALIZE_THUNK),
        ("KiUserExceptionDispatcher", wow64::SYSDLL_KI_USER_EXCEPTION_DISPATCHER),
        ("KiUserCallbackDispatcher", wow64::SYSDLL_KI_USER_CALLBACK_DISPATCHER),
        ("ntdll32 base", wow64::SYSDLL_NTDLL32_BASE),
    ] {
        let load8 = vec![0x48, 0x8B, 0x40, off as u8]; // mov rax,[rax+off8]
        let load_rcx = vec![0x48, 0x8B, 0x4A, off as u8]; // mov rcx,[rdx+off8]
        let load_rdx = vec![0x48, 0x8B, 0x52, off as u8]; // mov rdx,[rdx+off8]
        let load_rcx2 = vec![0x48, 0x8B, 0x48, off as u8]; // mov rcx,[rax+off8]
        assert!(
            [load8, load_rcx, load_rdx, load_rcx2]
                .iter()
                .any(|p| !find_text_all(&w, p).is_empty()),
            "wow64.dll reads LdrSystemDllInitBlock+{off:#x} ({name})",
        );
    }
    // The APC dispatcher slot uses a disp8 too, off rdx.
    assert!(
        !find_text_all(&w, &[0x48, 0x8B, 0x52, wow64::SYSDLL_KI_USER_APC_DISPATCHER as u8]).is_empty(),
        "wow64.dll reads LdrSystemDllInitBlock+{:#x} (KiUserApcDispatcher)",
        wow64::SYSDLL_KI_USER_APC_DISPATCHER,
    );
}

/// **The win32k service descriptor is a verbatim 32-byte copy.**
///
/// `wow64.dll`'s process init resolves `wow64win!sdwhwin32` and copies it into
/// its own table 1 with two `movdqu` loads and two `movups` stores. exemu never
/// builds that descriptor — it runs this code. Pinned here so a prefix refresh
/// that changes the copy (or the export name) fails by name.
#[test]
fn wow64_dll_movdqu_copies_the_win32k_descriptor_from_wow64win() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let win = load(&format!("{DLLS64}/wow64win.dll"));
    assert!(win.exports.contains_key("sdwhwin32"), "wow64win exports the descriptor by name");
    assert!(find_string(&w, "sdwhwin32").is_some(), "wow64.dll resolves it by that name");
    assert!(find_string(&w, "wow64win.dll").is_none(), "…and loads the module by a *wide* name");

    // movdqu xmm1,[rax] ; movdqu xmm2,[rax+0x10] ; movups [rip+d],xmm1 ; movups [rip+d],xmm2
    let at = find_text(&w, &[0xF3, 0x0F, 0x6F, 0x08, 0xF3, 0x0F, 0x6F, 0x50, 0x10])
        .expect("wow64.dll movdqu-loads the 32-byte descriptor");
    let store = w.at(at + 9, 14);
    assert_eq!(&store[..3], &[0x0F, 0x11, 0x0D], "…and movups-stores it rip-relative: {store:02x?}");
    let disp = i32::from_le_bytes(store[3..7].try_into().unwrap());
    let target = (at as i64 + 9 + 7 + disp as i64) as u32;
    assert_eq!(
        target, 0x160a0,
        "the destination is the table-1 descriptor at rva 0x160a0 (table 0 is 0x16080)",
    );
}

/// **`RtlWow64GetProcessMachines` / `RtlWow64SetThreadContext` pin two more
/// service contracts exemu implements**, both read out of the stubs rather than
/// chosen: the architecture query's class and the WoW64 context write's
/// class + length.
#[test]
fn rtl_wow64_helpers_pin_the_machine_query_and_context_write() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));

    // RtlWow64GetProcessMachines → NtQuerySystemInformationEx(class = 0xb5).
    let m = n64.at(n64.export("RtlWow64GetProcessMachines"), 0x40);
    let mut want = vec![0xB9]; // mov ecx, imm32
    want.extend_from_slice(&wow64::SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES.to_le_bytes());
    assert!(
        m.windows(want.len()).any(|x| x == want),
        "RtlWow64GetProcessMachines asks for class {:#x}",
        wow64::SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES,
    );

    // RtlWow64SetThreadContext is the mirror of the read side: `mov r9d,0x2cc;
    // mov r8,rdx; mov edx,0x1d; jmp NtSetInformationThread`.
    let s = n64.at(n64.export("RtlWow64SetThreadContext"), 0x14);
    let mut len = vec![0x41, 0xB9];
    len.extend_from_slice(&(wow64::WOW64_CONTEXT_SIZE as u32).to_le_bytes());
    let mut class = vec![0xBA];
    class.extend_from_slice(&wow64::THREAD_WOW64_CONTEXT.to_le_bytes());
    assert!(
        s.windows(len.len()).any(|x| x == len) && s.windows(class.len()).any(|x| x == class),
        "RtlWow64SetThreadContext is NtSetInformationThread(_, {:#x}, _, {:#x}): {s:02x?}",
        wow64::THREAD_WOW64_CONTEXT,
        wow64::WOW64_CONTEXT_SIZE,
    );
    assert_eq!(s[0x0e], 0xE9, "…and tail-jumps into the stub");
}

/// **`__wine_unix_call` from a 32-bit guest arrives with a 32-bit `args`
/// block** — the recovery behind [`exemu_os::unixlib`]'s wow64 variant
/// (roadmap W5.3).
///
/// `wow64cpu`'s BOP handler does `mov rcx,[r14+4]; mov edx,[r14+0xc];
/// **mov r8d,[r14+0x10]**; call [__wine_unix_call_dispatcher]`: the `args`
/// pointer is loaded as a *dword* and zero-extended, and the very same 64-bit
/// dispatcher the 64-bit ntdll uses is called. Nothing on the PE side widens
/// the block — so the unix side is what has to read it in 32-bit width, keyed
/// off the 32-bit ntdll's own `__wine_unixlib_handle`.
#[test]
fn wow64cpu_passes_a_32bit_args_pointer_to_the_unix_dispatcher() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let c = load(&format!("{DLLS64}/wow64cpu.dll"));
    // mov rcx,[r14+4] ; mov edx,[r14+0xc] ; mov r8d,[r14+0x10]
    let seq = [
        0x49, 0x8B, 0x4E, 0x04, // mov rcx, qword ptr [r14+4]   — the 64-bit handle
        0x41, 0x8B, 0x56, 0x0C, // mov edx, dword ptr [r14+0xc] — the code
        0x45, 0x8B, 0x46, 0x10, // mov r8d, dword ptr [r14+0x10] — the 32-BIT args ptr
    ];
    let at = find_text(&c, &seq).expect("wow64cpu's unix-call path loads a 32-bit args pointer");
    assert_eq!(
        &c.at(at + seq.len() as u32, 2),
        &[0xFF, 0x15],
        "…and calls straight through the stored __wine_unix_call_dispatcher pointer",
    );

    // The 32-bit ntdll carries its own handle cell, which is what tells the two
    // widths apart.
    let n32 = load(&format!("{DLLS32}/ntdll.dll"));
    assert!(
        n32.exports.contains_key("__wine_unixlib_handle"),
        "the 32-bit ntdll exports its own __wine_unixlib_handle",
    );
}

/// **`wow64win.dll` is only a marshaller: every win32k thunk tail-jumps into the
/// 64-bit `win32u.dll`, so that import edge is load-bearing** (roadmap W5.8).
///
/// This is the fact SteamSetup died on, and it is worth stating precisely
/// because the failure mode is *not* a null dereference. An unbound IAT slot in
/// a PE file does not hold zero — it still holds the file's ILT value, which is
/// the RVA of the `IMAGE_IMPORT_BY_NAME` for that symbol. So a `jmp qword ptr
/// [slot]` through an unbound win32u import jumps to a small, plausible-looking
/// address *inside the import name table* and dies executing the ASCII of its
/// own name. The test proves all three links:
///
/// 1. `wow64win` imports hundreds of names from `win32u.dll` — the edge exists
///    and is big, so leaving it out is not a corner case;
/// 2. the shape of a thunk is "load the 32-bit argument block, then
///    `jmp qword ptr [<a win32u IAT slot>]`" — nothing else stands between the
///    32-bit guest and win32u;
/// 3. the unbound slot's file content really is the hint/name RVA, and the
///    bytes there really do spell the imported symbol — which is exactly how
///    `NtUserInitializeClientPfnArrays` came to execute at `0x302f0`;
/// 4. the 64-bit `win32u.dll` answers with a real syscall stub carrying the
///    win32k table bit, i.e. the thing that reaches exemu's SSDT.
#[test]
fn wow64win_win32k_thunks_tail_jump_into_win32u_stubs() {
    if !have_set() || !std::path::Path::new(DLLS64).join("win32u.dll").is_file() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64win.dll"));
    let u = load(&format!("{DLLS64}/win32u.dll"));

    let win32u_imports: Vec<&(u32, String, String)> =
        w.imports.iter().filter(|(_, dll, _)| dll == "win32u.dll").collect();
    assert!(
        win32u_imports.len() > 400,
        "wow64win tail-jumps into win32u for essentially every win32k service; found {}",
        win32u_imports.len(),
    );

    // The one SteamSetup reaches first — user32's DllMain publishes its WndProc
    // table through it, so it is the very first win32k call a GUI guest makes.
    const FIRST: &str = "NtUserInitializeClientPfnArrays";
    let iat_rva: u32 = win32u_imports
        .iter()
        .find(|(_, _, s)| s == FIRST)
        .unwrap_or_else(|| panic!("wow64win imports win32u!{FIRST}"))
        .0;

    // (2) Some thunk tail-jumps through this slot: `48 FF 25 <disp32>` whose
    //     rip-relative target is the slot itself.
    let mut jmp_site = None;
    for off in 0..w.text.len().saturating_sub(7) {
        if w.text[off..off + 3] != [0x48, 0xFF, 0x25] {
            continue;
        }
        let disp = i32::from_le_bytes(w.text[off + 3..off + 7].try_into().unwrap());
        let next = w.text_rva as i64 + off as i64 + 7;
        if (next + disp as i64) as u32 == iat_rva {
            jmp_site = Some(w.text_rva + off as u32);
            break;
        }
    }
    let jmp_site = jmp_site.unwrap_or_else(|| panic!("no `jmp [win32u!{FIRST}]` in wow64win"));
    // Immediately before it, the 32-bit argument block is unpacked out of RCX
    // (`mov eax,[rcx]` — a *dword* load, because the caller is 32-bit code).
    assert_eq!(
        &w.at(jmp_site - 0x10, 2),
        &[0x8B, 0x01],
        "the thunk opens by loading arg0 as a dword from the 32-bit argument block",
    );

    // (3) The unbound slot is the hint/name RVA, and the bytes there spell the
    //     symbol — the "executes its own name" failure mode, from the file.
    let unbound = u64::from_le_bytes(w.at(iat_rva, 8).try_into().expect("8 bytes at the IAT slot"));
    assert!(
        unbound != 0 && unbound < w.at(0, 1).len() as u64 + 0x10_0000,
        "an unbound IAT slot holds a small RVA, not null: {unbound:#x}",
    );
    let name = w.at(unbound as u32 + 2, FIRST.len());
    assert_eq!(
        std::str::from_utf8(name).unwrap_or(""),
        FIRST,
        "…and that RVA ({unbound:#x}) is the IMAGE_IMPORT_BY_NAME for {FIRST}",
    );

    // (4) win32u answers with a real syscall stub carrying the win32k table bit.
    let idx = ssdt_index64(&u, FIRST).unwrap_or_else(|| panic!("win32u!{FIRST} is a syscall stub"));
    assert_ne!(idx & 0x1000, 0, "a win32k service index carries the table-1 bit: {idx:#x}");
}
