use std::collections::BTreeMap;

use exemu_os::wow64;

const DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_set() -> bool {
    std::path::Path::new(DLLS32).join("ntdll.dll").is_file()
        && std::path::Path::new(DLLS64).join("wow64.dll").is_file()
}

struct Img {
    image_base: u64,
    exports: BTreeMap<String, u32>,
    sections: Vec<(u32, Vec<u8>)>,
    text_rva: u32,
    text: Vec<u8>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stub32 {
    ViaHelper { index: u32, helper: u32, arg_bytes: u16 },
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

fn ssdt_index64(img: &Img, name: &str) -> Option<u32> {
    let b = img.at(img.export(name), 9);
    (b.len() >= 9 && b[..4] == [0x4C, 0x8B, 0xD1, 0xB8])
        .then(|| u32::from_le_bytes(b[4..8].try_into().unwrap()))
}

fn lea_rip_sites(img: &Img, target: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let c = &img.text;
    let mut i = 0usize;
    while i + 7 <= c.len() {
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

fn find_text(img: &Img, pat: &[u8]) -> Option<u32> {
    find_text_all(img, pat).into_iter().next()
}

fn find_text_all(img: &Img, pat: &[u8]) -> Vec<u32> {
    img.text
        .windows(pat.len())
        .enumerate()
        .filter(|(_, w)| *w == pat)
        .map(|(i, _)| img.text_rva + i as u32)
        .collect()
}

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

    assert_eq!(via_teb.len(), 2, "exactly the Nt/Zw alias pair uses the fs: shape: {via_teb:?}");
    for (name, disp) in &via_teb {
        assert_eq!(
            *disp as u64, wow64::TEB32_WOW32_RESERVED,
            "{name} reads TEB32+{disp:#x}; exemu_os::wow64::TEB32_WOW32_RESERVED is {:#x}",
            wow64::TEB32_WOW32_RESERVED,
        );
    }
}

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

    let store32_sites = [
        find_text(&w, &[0x41, 0x89, 0x04, 0x24]),
        find_text(&w, &[0x89, 0x03]),
    ];
    assert!(
        store32_sites.iter().all(|s| s.is_some()),
        "wow64.dll stores the BOP as a 32-bit dword (the sub-4 GiB constraint)",
    );
}

#[test]
fn wow_teb_offset_and_wow32_reserved_are_recovered_from_wow64_dll() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));

    let mut movsxd = vec![0x48, 0x63, 0x90];
    movsxd.extend_from_slice(&(wow64::TEB64_WOW_TEB_OFFSET as u32).to_le_bytes());
    let loads = find_text_all(&w, &movsxd);
    assert!(
        !loads.is_empty(),
        "wow64.dll does not sign-extend [teb64+{:#x}] — TEB64_WOW_TEB_OFFSET has drifted",
        wow64::TEB64_WOW_TEB_OFFSET,
    );

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

#[test]
fn rtl_wow64_get_thread_context_pins_the_class_and_length() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));
    let rva = n64.export("RtlWow64GetThreadContext");
    let b = n64.at(rva, 0x28);

    let mut want_len = vec![0x41, 0xB9];
    want_len.extend_from_slice(&(wow64::WOW64_CONTEXT_SIZE as u32).to_le_bytes());
    assert!(
        b.windows(want_len.len()).any(|w| w == want_len),
        "RtlWow64GetThreadContext passes ThreadInformationLength = {:#x}",
        wow64::WOW64_CONTEXT_SIZE,
    );
    let mut want_class = vec![0xBA];
    want_class.extend_from_slice(&wow64::THREAD_WOW64_CONTEXT.to_le_bytes());
    assert!(
        b.windows(want_class.len()).any(|w| w == want_class),
        "RtlWow64GetThreadContext passes ThreadInformationClass = {:#x}",
        wow64::THREAD_WOW64_CONTEXT,
    );

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

#[test]
fn wow64cpu_reads_the_cpu_area_and_wow64info_teb_slots() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let c = load(&format!("{DLLS64}/wow64cpu.dll"));

    let mut area = vec![0x49, 0x8B, 0x8C, 0x24];
    area.extend_from_slice(&(wow64::TEB_CPU_AREA_PTR_OFF as u32).to_le_bytes());
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
        &[0x89, 0x5C, 0x24, 0x08, 0x89, 0x44, 0x24, 0x04],
        "RtlUserThreadStart forwards (eax, ebx) as (EntryPoint, Arg): {start:02x?}",
    );
    assert_eq!(start[8], 0xE9, "…and tail-jumps to the thread start");

    let thunk = n32.at(n32.export("LdrInitializeThunk"), 16);
    assert_eq!(&thunk[..2], &[0x55, 0x89], "LdrInitializeThunk opens with a frame: {thunk:02x?}");
    let mut want_arg = vec![0x8B, 0x5D, 0x08];
    want_arg.extend_from_slice(&[0x8D, 0x83]);
    want_arg.extend_from_slice(&(wow64::CTX_EAX as u32).to_le_bytes());
    assert!(
        thunk.windows(want_arg.len()).any(|w| w == want_arg),
        "LdrInitializeThunk reads its CONTEXT off the stack and passes &CONTEXT.Eax \
         (offset {:#x}) to loader_init: {thunk:02x?}",
        wow64::CTX_EAX,
    );
}

#[test]
fn wow64_dll_reads_the_system_dll_init_block_fields_exemu_fills() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));
    assert!(n64.exports.contains_key("LdrSystemDllInitBlock"), "the 64-bit ntdll exports the block");

    for (name, off) in [
        ("LdrInitializeThunk", wow64::SYSDLL_LDR_INITIALIZE_THUNK),
        ("KiUserExceptionDispatcher", wow64::SYSDLL_KI_USER_EXCEPTION_DISPATCHER),
        ("KiUserCallbackDispatcher", wow64::SYSDLL_KI_USER_CALLBACK_DISPATCHER),
        ("ntdll32 base", wow64::SYSDLL_NTDLL32_BASE),
    ] {
        let load8 = vec![0x48, 0x8B, 0x40, off as u8];
        let load_rcx = vec![0x48, 0x8B, 0x4A, off as u8];
        let load_rdx = vec![0x48, 0x8B, 0x52, off as u8];
        let load_rcx2 = vec![0x48, 0x8B, 0x48, off as u8];
        assert!(
            [load8, load_rcx, load_rdx, load_rcx2]
                .iter()
                .any(|p| !find_text_all(&w, p).is_empty()),
            "wow64.dll reads LdrSystemDllInitBlock+{off:#x} ({name})",
        );
    }
    assert!(
        !find_text_all(&w, &[0x48, 0x8B, 0x52, wow64::SYSDLL_KI_USER_APC_DISPATCHER as u8]).is_empty(),
        "wow64.dll reads LdrSystemDllInitBlock+{:#x} (KiUserApcDispatcher)",
        wow64::SYSDLL_KI_USER_APC_DISPATCHER,
    );
}

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

#[test]
fn rtl_wow64_helpers_pin_the_machine_query_and_context_write() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n64 = load(&format!("{DLLS64}/ntdll.dll"));

    let m = n64.at(n64.export("RtlWow64GetProcessMachines"), 0x40);
    let mut want = vec![0xB9];
    want.extend_from_slice(&wow64::SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES.to_le_bytes());
    assert!(
        m.windows(want.len()).any(|x| x == want),
        "RtlWow64GetProcessMachines asks for class {:#x}",
        wow64::SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES,
    );

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

#[test]
fn wow64cpu_passes_a_32bit_args_pointer_to_the_unix_dispatcher() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let c = load(&format!("{DLLS64}/wow64cpu.dll"));
    let seq = [
        0x49, 0x8B, 0x4E, 0x04,
        0x41, 0x8B, 0x56, 0x0C,
        0x45, 0x8B, 0x46, 0x10,
    ];
    let at = find_text(&c, &seq).expect("wow64cpu's unix-call path loads a 32-bit args pointer");
    assert_eq!(
        &c.at(at + seq.len() as u32, 2),
        &[0xFF, 0x15],
        "…and calls straight through the stored __wine_unix_call_dispatcher pointer",
    );

    let n32 = load(&format!("{DLLS32}/ntdll.dll"));
    assert!(
        n32.exports.contains_key("__wine_unixlib_handle"),
        "the 32-bit ntdll exports its own __wine_unixlib_handle",
    );
}

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

    const FIRST: &str = "NtUserInitializeClientPfnArrays";
    let iat_rva: u32 = win32u_imports
        .iter()
        .find(|(_, _, s)| s == FIRST)
        .unwrap_or_else(|| panic!("wow64win imports win32u!{FIRST}"))
        .0;

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
    assert_eq!(
        &w.at(jmp_site - 0x10, 2),
        &[0x8B, 0x01],
        "the thunk opens by loading arg0 as a dword from the 32-bit argument block",
    );

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

    let idx = ssdt_index64(&u, FIRST).unwrap_or_else(|| panic!("win32u!{FIRST} is a syscall stub"));
    assert_ne!(idx & 0x1000, 0, "a win32k service index carries the table-1 bit: {idx:#x}");
}

#[test]
fn wow64_dll_asks_the_64bit_ntdll_for_the_wow64_unix_funcs_class() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    const MEMORY_WINE_UNIX_FUNCS: u32 = 1000;
    const MEMORY_WINE_UNIX_WOW64_FUNCS: u32 = 1001;
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let mut cmp_native = vec![0x3D];
    cmp_native.extend_from_slice(&MEMORY_WINE_UNIX_FUNCS.to_le_bytes());
    let at = find_text(&w, &cmp_native).expect("wow64_NtQueryVirtualMemory tests for MemoryWineUnixFuncs");
    assert_eq!(w.at(at + 5, 1), &[0x74], "…and branches on it");
    let mut cmp_wow64 = vec![0x3D];
    cmp_wow64.extend_from_slice(&MEMORY_WINE_UNIX_WOW64_FUNCS.to_le_bytes());
    assert_eq!(
        w.at(at + 7, 5),
        cmp_wow64.as_slice(),
        "a 32-bit caller asking for the wow64 class directly is refused by the thunk itself",
    );
    let mut mov_r8d = vec![0x41, 0xB8];
    mov_r8d.extend_from_slice(&MEMORY_WINE_UNIX_WOW64_FUNCS.to_le_bytes());
    let taken = at + 7 + u32::from(w.at(at + 6, 1)[0]);
    let window = w.at(taken, 0x30);
    let rewrite = window
        .windows(mov_r8d.len())
        .position(|win| win == mov_r8d.as_slice())
        .expect("the taken branch rewrites the class in r8d to MemoryWineUnixWow64Funcs");
    assert!(
        window[rewrite..].windows(2).any(|win| win == [0xFF, 0x15]),
        "…before calling the 64-bit NtQueryVirtualMemory through its IAT",
    );
}
