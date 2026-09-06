use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const GS_BASE: u64 = 0x0000_7fff_0000_0000;
const TEB_BASE: u64 = GS_BASE;
const TEB_SIZE: u64 = 0x2000;
const PEB_ADDR: u64 = GS_BASE + 0x2000;

const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x0020_0000;
const HEAP_BASE: u64 = 0x0000_0002_0000_0000;
const HEAP_SIZE: u64 = 0x0400_0000;
const DLL_BASE: u64 = 0x0000_0006_0000_0000;
const DLL_SIZE: u64 = 0x0800_0000;
const API_BASE: u64 = 0x0000_7EFF_0000_0000;
const API_SIZE: u64 = 0x0010_0000;
const VALLOC_BASE: u64 = 0x0000_0040_0000_0000;
const ENV_BASE: u64 = 0x0000_0000_5000_0000;

const KUSER_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER: u64 = 0x7ffe_1000;
const KUSER_SYSTEM_CALL: u64 = 0x308;

const SENTINEL: u64 = 0x0000_0000_6000_0000;

const IMAGE_BASE: u64 = 0x1_4000_0000;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn setup(sandbox: &Path) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();

    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("heap", HEAP_BASE, HEAP_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("dlls", DLL_BASE, DLL_SIZE, Perm::RWX)).unwrap();
    mem.map(Region::new("imports", API_BASE, API_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("teb", TEB_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_ADDR & !0xfff, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("env", ENV_BASE, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap();

    mem.map(Region::new("kuser", KUSER_BASE, 0x1000, Perm::READ)).unwrap();
    mem.map(Region::new("dispatcher", KUSER_DISPATCHER, 0x1000, Perm::RWX)).unwrap();
    mem.poke(KUSER_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes()).unwrap();

    let cmd_a = ENV_BASE;
    mem.poke(cmd_a, b"C:\\program.exe\0").unwrap();
    let cmd_w = ENV_BASE + 0x400;
    let mut wide: Vec<u8> = Vec::new();
    for u in "C:\\program.exe".encode_utf16() {
        wide.extend_from_slice(&u.to_le_bytes());
    }
    wide.extend_from_slice(&[0, 0]);
    mem.poke(cmd_w, &wide).unwrap();

    mem.poke(TEB_BASE + 0x30, &TEB_BASE.to_le_bytes()).unwrap();
    mem.poke(TEB_BASE + 0x60, &PEB_ADDR.to_le_bytes()).unwrap();
    mem.poke(TEB_BASE + 0x08, &(STACK_BASE + STACK_SIZE).to_le_bytes()).unwrap();
    mem.poke(TEB_BASE + 0x10, &STACK_BASE.to_le_bytes()).unwrap();
    mem.poke(PEB_ADDR + 0x10, &IMAGE_BASE.to_le_bytes()).unwrap();

    let mut os = WinOs::new(WinConfig {
        api_base: API_BASE,
        heap_base: HEAP_BASE,
        heap_size: HEAP_SIZE,
        image_base: IMAGE_BASE,
        cmdline_ptr_a: cmd_a,
        cmdline_ptr_w: cmd_w,
        echo: false,
        is_64bit: true,
        sandbox: sandbox.to_string_lossy().into_owned(),
        module_path_w: "C:\\program.exe".into(),
        dll_base: DLL_BASE,
        dll_size: DLL_SIZE,
        valloc_base: VALLOC_BASE,
        peb_addr: PEB_ADDR,
        teb_base: TEB_BASE,
        image_size: 0x1000,
        image_entry: IMAGE_BASE + 0x1000,
        image_name: "program.exe".into(),
        wine_dll_dir: Some(WINE_DLLS.to_string()),
        ..WinConfig::default()
    });
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_BASE + STACK_SIZE).unwrap();
    os.init_ldr(&mut mem).unwrap();
    (os, mem)
}

fn ldr_in_load_order_names(mem: &VirtualMemory) -> Vec<String> {
    let ldr = mem.read_u64(PEB_ADDR + 0x18).unwrap();
    assert_ne!(ldr, 0, "PEB.Ldr materialized");
    let head = ldr + 0x10;
    let mut names = Vec::new();
    let mut link = mem.read_u64(head).unwrap();
    for _ in 0..64 {
        if link == head || link == 0 {
            break;
        }
        let len = mem.read_u16(link + 0x58).unwrap() as u64;
        let buf = mem.read_u64(link + 0x60).unwrap();
        if buf != 0 && len > 0 {
            let mut s = String::new();
            for i in 0..(len / 2) {
                let u = mem.read_u16(buf + i * 2).unwrap();
                s.push(char::from_u32(u as u32).unwrap_or('?'));
            }
            names.push(s.to_ascii_lowercase());
        }
        link = mem.read_u64(link).unwrap();
    }
    names
}

#[test]
fn wine_core_maps_relocates_and_dllmains() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let dir = std::env::temp_dir().join(format!("exemu-w3_2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);

    let ntdll_base = os
        .load_wine_core(&mut mem)
        .expect("load_wine_core ok")
        .expect("the pinned Wine core set present → Some(ntdll_base)");
    assert_eq!(ntdll_base & 0xfff, 0, "ntdll base is page-aligned");
    assert!(
        (DLL_BASE..DLL_BASE + DLL_SIZE).contains(&ntdll_base),
        "ntdll mapped into the DLL arena"
    );

    assert_eq!(
        os.module_base("ntdll.dll"),
        Some(ntdll_base),
        "ntdll recorded as a real mapped image at its returned base"
    );
    for n in ["kernelbase.dll", "kernel32.dll", "ucrtbase.dll"] {
        assert_eq!(
            os.module_base(n),
            None,
            "{n} must NOT be pre-mapped by exemu (Wine loads it during the boot)"
        );
    }
    assert_eq!(
        os.ntdll_export("LdrInitializeThunk"),
        Some(ntdll_base + exemu_os::RVA_LDR_INITIALIZE_THUNK),
        "LdrInitializeThunk resolves by name to base + the W3.1 RVA"
    );

    let disp = mem.read_u64(ntdll_base + exemu_os::RVA_WINE_UNIX_CALL_DISPATCHER).unwrap();
    assert_eq!(disp, os.wine_unix_call_thunk(), "unix-call dispatcher global wired to the thunk");

    let names = ldr_in_load_order_names(&mem);
    assert!(names.contains(&"ntdll.dll".to_string()), "PEB.Ldr lists ntdll (got {names:?})");
    assert!(names.contains(&"program.exe".to_string()), "PEB.Ldr lists the exe (got {names:?})");
    for absent in ["kernelbase.dll", "kernel32.dll", "ucrtbase.dll"] {
        assert!(
            !names.contains(&absent.to_string()),
            "PEB.Ldr must NOT hold exemu-pre-mapped {absent} (Wine adds it) — got {names:?}"
        );
    }
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "no duplicate PEB.Ldr entries (got {names:?})");
    assert_eq!(names.len(), 2, "exactly ntdll + exe on PEB.Ldr post-trim (got {names:?})");

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = {
        let sp = (STACK_BASE + STACK_SIZE - 0x100) & !0xf;
        let sp = sp - 8;
        mem.write_u64(sp, SENTINEL).unwrap();
        sp
    };
    {
        let s = cpu.state_mut();
        s.set_rsp(rsp);
        s.gs_base = TEB_BASE;
        s.fs_base = TEB_BASE;
        s.rip = SENTINEL;
    }
    os.run_pending_dllmains(cpu.state_mut(), &mut mem)
        .expect("run_pending_dllmains seats the callback sequence");

    let ntdll_ext = {
        let bytes = std::fs::read(Path::new(WINE_DLLS).join("ntdll.dll")).unwrap();
        let img = exemu_loader::parse(&bytes).unwrap();
        ntdll_base..ntdll_base + align_up(img.size_of_image as u64, 0x1000)
    };

    let mut steps: u64 = 0;
    let mut entered_ntdll_dllmain = false;
    let ntdll_dllmain = ntdll_base + 0x12e10;
    loop {
        let rip = cpu.state().rip;
        if ntdll_ext.contains(&rip) && rip != ntdll_dllmain {
            entered_ntdll_dllmain = true;
        }
        match cpu.step(&mut mem, &mut os) {
            Ok(Exit::Continue) => steps += 1,
            Ok(Exit::Halted) => break,
            Ok(Exit::ProcessExit(_)) => break,
            Ok(other) => panic!("unexpected exit driving ntdll's DllMain: {other:?}"),
            Err(e) => panic!(
                "ntdll's PROCESS_ATTACH DllMain faulted (load/pre-map defect): {e:?} @ {rip:#x}"
            ),
        }
        assert!(steps < 200_000_000, "ntdll DllMain ran away without draining");
    }
    assert!(
        entered_ntdll_dllmain,
        "ntdll's PROCESS_ATTACH DllMain executed real code and returned fault-free"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wine_core_seeds_valid_apiset_map() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let dir = std::env::temp_dir().join(format!("exemu-w3_3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);

    os.load_wine_core(&mut mem).expect("load_wine_core ok").expect("the four Wine core DLLs present");

    let map = mem.read_u64(PEB_ADDR + 0x68).unwrap();
    assert_ne!(map, 0, "PEB.ApiSetMap seeded (non-null)");
    assert_eq!(map, os.api_set_map(), "PEB.ApiSetMap == the seeded namespace base");
    assert!((DLL_BASE..DLL_BASE + DLL_SIZE).contains(&map), "ApiSetMap in the DLL arena");

    let version = mem.read_u32(map).unwrap();
    let size = mem.read_u32(map + 0x04).unwrap();
    let count = mem.read_u32(map + 0x0C).unwrap();
    let entry_off = mem.read_u32(map + 0x10).unwrap();
    let hash_off = mem.read_u32(map + 0x14).unwrap();
    let hash_factor = mem.read_u32(map + 0x18).unwrap();
    assert_eq!(version, 6, "API_SET_NAMESPACE version 6");
    assert_eq!(hash_factor, exemu_os::HASH_FACTOR, "HashFactor matches the builder");
    assert!(count > 0, "populated namespace has entries");
    assert!(entry_off + count * 0x18 <= size, "entry table in-bounds");
    assert!(hash_off + count * 0x08 <= size, "hash table in-bounds");

    let mut prev = 0u32;
    for i in 0..count {
        let h = mem.read_u32(map + hash_off as u64 + (i * 8) as u64).unwrap();
        if i > 0 {
            assert!(h > prev, "hash table ascending at {i}");
        }
        prev = h;
    }

    let resolve = |contract: &str| -> Option<String> {
        let want = exemu_os::api_set_hash(contract, exemu_os::HASH_FACTOR);
        let (mut lo, mut hi) = (0i64, count as i64 - 1);
        while lo <= hi {
            let mid = (lo + hi) / 2;
            let ho = map + hash_off as u64 + (mid as u64) * 8;
            let h = mem.read_u32(ho).unwrap();
            match h.cmp(&want) {
                std::cmp::Ordering::Equal => {
                    let idx = mem.read_u32(ho + 4).unwrap();
                    let eo = map + entry_off as u64 + (idx as u64) * 0x18;
                    let vo = mem.read_u32(eo + 0x10).unwrap() as u64;
                    let val_off = mem.read_u32(map + vo + 0x0C).unwrap() as u64;
                    let val_len = mem.read_u32(map + vo + 0x10).unwrap() as u64;
                    let units: Vec<u16> = (0..val_len / 2)
                        .map(|j| mem.read_u16(map + val_off + j * 2).unwrap())
                        .collect();
                    return Some(String::from_utf16(&units).unwrap());
                }
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid - 1,
            }
        }
        None
    };
    assert_eq!(resolve("api-ms-win-crt-stdio-l1-1-0").as_deref(), Some("ucrtbase.dll"));
    assert_eq!(resolve("api-ms-win-core-synch-l1-2-0").as_deref(), Some("kernelbase.dll"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wine_core_seeds_full_process_parameters() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w3_6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);
    os.load_wine_core(&mut mem).expect("load_wine_core ok").expect("the four Wine core DLLs present");

    let pp = mem.read_u64(PEB_ADDR + 0x20).unwrap();
    assert_ne!(pp, 0, "PEB.ProcessParameters seeded");
    assert!((DLL_BASE..DLL_BASE + DLL_SIZE).contains(&pp), "PP in the loader arena");
    assert!(mem.read_u32(pp).unwrap() >= 0x410, "MaximumLength spans the full header");
    assert_eq!(mem.read_u32(pp + 0x08).unwrap() & 0x1, 0x1, "Flags NORMALIZED");

    let cmd_len = mem.read_u16(pp + 0x70).unwrap();
    let cmd_buf = mem.read_u64(pp + 0x70 + 8).unwrap();
    assert!(cmd_len > 0 && cmd_buf != 0, "CommandLine populated");
    let units: Vec<u16> =
        (0..cmd_len as u64 / 2).map(|i| mem.read_u16(cmd_buf + i * 2).unwrap()).collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "C:\\program.exe");

    let env = mem.read_u64(pp + 0x80).unwrap();
    let env_size = mem.read_u64(pp + 0x3f0).unwrap();
    assert_ne!(env, 0, "Environment non-null");
    assert!(env_size >= 4, "EnvironmentSize covers the terminator");
    assert_eq!(mem.read_u16(env + env_size - 2).unwrap(), 0, "env ends in NUL");
    assert_eq!(mem.read_u16(env + env_size - 4).unwrap(), 0, "env double-NUL terminated");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wine_core_wires_unix_call_dispatcher() {
    if !Path::new(WINE_DLLS).join("ntdll.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ntdll.dll not present (Wine DLL set is git-ignored)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("exemu-w3_2disp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut os, mut mem) = setup(&dir);

    let ntdll_base =
        os.load_wine_core(&mut mem).expect("load_wine_core ok").expect("the four Wine core DLLs present");

    let disp = ntdll_base + exemu_os::RVA_WINE_UNIX_CALL_DISPATCHER;
    let wired = mem.read_u64(disp).unwrap();
    assert_ne!(wired, 0, "__wine_unix_call_dispatcher no longer null (the boot blocker)");
    assert_eq!(wired, os.wine_unix_call_thunk(), "dispatcher global == the __wine_unix_call thunk");

    if let Some(export_va) = os.ntdll_export("__wine_unix_call_dispatcher") {
        assert_eq!(export_va, disp, "wired RVA == ntdll's __wine_unix_call_dispatcher export");
    }

    let syscall_disp = mem.read_u64(ntdll_base + 0x9c050).unwrap();
    assert_eq!(syscall_disp, 0, "__wine_syscall_dispatcher left null (unused by ntdll)");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wine_core_seeds_activation_context_stack() {
    let dir = std::env::temp_dir().join(format!("exemu-actctx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut mem = VirtualMemory::new();
    mem.map(Region::new("teb", TEB_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_ADDR & !0xfff, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        peb_addr: PEB_ADDR,
        teb_base: TEB_BASE,
        sandbox: dir.to_string_lossy().into_owned(),
        ..WinConfig::default()
    });
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_BASE + STACK_SIZE).unwrap();

    let actx = mem.read_u64(TEB_BASE + 0x2c8).unwrap();
    assert_ne!(actx, 0, "ActivationContextStackPointer seeded (the boot blocker)");
    assert_eq!(actx, TEB_BASE + 0x1900, "stack laid inline in the TEB region gap");
    assert!(actx + 0x28 <= TEB_BASE + (0x2000 - 0x140), "clear of the syscall_frame tail");

    assert_eq!(mem.read_u64(actx).unwrap(), 0, "ActiveFrame empty");
    assert_eq!(mem.read_u64(actx + 0x08).unwrap(), actx + 0x08, "FrameListCache.Flink → self");
    assert_eq!(mem.read_u64(actx + 0x10).unwrap(), actx + 0x08, "FrameListCache.Blink → self");

    let _ = std::fs::remove_dir_all(&dir);
}
