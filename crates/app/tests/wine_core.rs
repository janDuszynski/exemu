//! W3.2 (phase-iv trim) — the **ntdll pre-map** intermediate gate.
//!
//! Post-trim, [`WinOs::load_wine_core`] pre-maps **ntdll only** — the running
//! image Wine's `loader_init` never re-maps — as a **real guest image** (not
//! the emulated-DLL thunk stand-in), plus wires its unixlib/dispatcher and
//! threads it onto `PEB.Ldr`. Wine's own `loader_init`/`build_module` then
//! loads kernelbase/kernel32/ucrtbase itself from the prefix during the full
//! boot; that end-to-end four-DLL load (Wine loads + re-binds the exe's imports
//! to its own kernel32) is proven by the **W3 gate** (`wine_gate.rs`), so it is
//! deliberately NOT asserted here — this file asserts the exemu-side ntdll pre-
//! map contract that gate depends on:
//!
//!   1. ntdll mapped + relocated (its real base returned + recorded), exports
//!      resolving by name;
//!   2. its unixlib + `__wine_unix_call_dispatcher` wired;
//!   3. `PEB.Ldr` InLoadOrder holds **exactly ntdll + the exe** — no duplicate
//!      entries, and specifically NOT exemu-pre-mapped kernelbase/kernel32/
//!      ucrtbase (Wine adds those during the full boot, so pre-mapping them here
//!      would double-map them onto Ldr);
//!   4. ntdll's queued `DllMain(DLL_PROCESS_ATTACH)` driven through the real CPU
//!      **fault-free** (each step `Continue`/`Halted`, never `Err(fault)`).
//!
//! This is the W3.2 (phase-iv) deliverable — the *ntdll pre-map*, not the full
//! `LdrInitializeThunk` boot-to-console. Skips cleanly when the (git-ignored)
//! Wine DLL set is absent.

use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

// A layout that mirrors exemu-app's 64-bit process map closely enough that
// Wine's ntdll DllMain finds the TEB/PEB/KUSER fields it dereferences. The DLL
// arena is amply sized for the single ntdll image the trimmed load pre-maps.
const GS_BASE: u64 = 0x0000_7fff_0000_0000;
const TEB_BASE: u64 = GS_BASE;
const TEB_SIZE: u64 = 0x2000;
const PEB_ADDR: u64 = GS_BASE + 0x2000;

const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x0020_0000; // 2 MiB
const HEAP_BASE: u64 = 0x0000_0002_0000_0000;
const HEAP_SIZE: u64 = 0x0400_0000; // 64 MiB
const DLL_BASE: u64 = 0x0000_0006_0000_0000;
const DLL_SIZE: u64 = 0x0800_0000; // 128 MiB
const API_BASE: u64 = 0x0000_7EFF_0000_0000;
const API_SIZE: u64 = 0x0010_0000;
const VALLOC_BASE: u64 = 0x0000_0040_0000_0000;
const ENV_BASE: u64 = 0x0000_0000_5000_0000;

const KUSER_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER: u64 = 0x7ffe_1000;
const KUSER_SYSTEM_CALL: u64 = 0x308;

// A one-page RWX sentinel whose first byte is `hlt`: the drain-return address
// the DllMain callback queue lands on when it finishes.
const SENTINEL: u64 = 0x0000_0000_6000_0000;

const IMAGE_BASE: u64 = 0x1_4000_0000; // a stand-in "main exe" base

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// Build a `WinOs` + `VirtualMemory` with the pinned Wine DLL set wired via
/// `wine_dll_dir`, then run `init_ldr` (which threads the main exe onto
/// `PEB.Ldr`) so `load_wine_core` can thread ntdll on beside it. Returns the
/// pieces the test drives.
fn setup(sandbox: &Path) -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();

    // Core process regions.
    mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("heap", HEAP_BASE, HEAP_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("dlls", DLL_BASE, DLL_SIZE, Perm::RWX)).unwrap();
    mem.map(Region::new("imports", API_BASE, API_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("teb", TEB_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB_ADDR & !0xfff, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("env", ENV_BASE, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt

    // KUSER_SHARED_DATA + dispatcher landing page.
    mem.map(Region::new("kuser", KUSER_BASE, 0x1000, Perm::READ)).unwrap();
    mem.map(Region::new("dispatcher", KUSER_DISPATCHER, 0x1000, Perm::RWX)).unwrap();
    // SystemCall = 0 → ntdll's stubs take the bare `syscall` route (the W3.2
    // boot-path shape). Poke bypasses the READ-only perm.
    mem.poke(KUSER_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes()).unwrap();

    // A minimal ASCII/UTF-16 command line in the env region.
    let cmd_a = ENV_BASE;
    mem.poke(cmd_a, b"C:\\program.exe\0").unwrap();
    let cmd_w = ENV_BASE + 0x400;
    let mut wide: Vec<u8> = Vec::new();
    for u in "C:\\program.exe".encode_utf16() {
        wide.extend_from_slice(&u.to_le_bytes());
    }
    wide.extend_from_slice(&[0, 0]);
    mem.poke(cmd_w, &wide).unwrap();

    // TEB self/PEB/stack pointers the seeder + ntdll read via gs:.
    mem.poke(TEB_BASE + 0x30, &TEB_BASE.to_le_bytes()).unwrap(); // NT_TIB.Self
    mem.poke(TEB_BASE + 0x60, &PEB_ADDR.to_le_bytes()).unwrap(); // PEB
    mem.poke(TEB_BASE + 0x08, &(STACK_BASE + STACK_SIZE).to_le_bytes()).unwrap();
    mem.poke(TEB_BASE + 0x10, &STACK_BASE.to_le_bytes()).unwrap();
    mem.poke(PEB_ADDR + 0x10, &IMAGE_BASE.to_le_bytes()).unwrap(); // ImageBaseAddress

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
    // Complete the main TEB + the PEB.Ldr lists (needed for load_wine_core to
    // thread the four modules on).
    os.seed_main_teb(&mut mem, STACK_BASE, STACK_BASE + STACK_SIZE).unwrap();
    os.init_ldr(&mut mem).unwrap();
    (os, mem)
}

/// Walk `PEB.Ldr.InLoadOrderModuleList` and collect the lower-cased base names.
fn ldr_in_load_order_names(mem: &VirtualMemory) -> Vec<String> {
    let ldr = mem.read_u64(PEB_ADDR + 0x18).unwrap(); // PEB.Ldr (64-bit)
    assert_ne!(ldr, 0, "PEB.Ldr materialized");
    let head = ldr + 0x10; // InLoadOrderModuleList head
    let mut names = Vec::new();
    let mut link = mem.read_u64(head).unwrap(); // head.Flink
    // Bounded walk (guard against a corrupt ring).
    for _ in 0..64 {
        if link == head || link == 0 {
            break;
        }
        // LDR_DATA_TABLE_ENTRY: InLoadOrderLinks @0 → the entry base is `link`.
        // BaseDllName UNICODE_STRING @0x58 { Length, Max, pad, Buffer@0x60 }.
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
        link = mem.read_u64(link).unwrap(); // Flink
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

    // (1) load_wine_core pre-maps + relocates NTDLL ONLY; returns its real base.
    let ntdll_base = os
        .load_wine_core(&mut mem)
        .expect("load_wine_core ok")
        .expect("the pinned Wine core set present → Some(ntdll_base)");
    assert_eq!(ntdll_base & 0xfff, 0, "ntdll base is page-aligned");
    assert!(
        (DLL_BASE..DLL_BASE + DLL_SIZE).contains(&ntdll_base),
        "ntdll mapped into the DLL arena"
    );

    // ntdll is recorded as a REAL image (not an emulated synthetic handle).
    assert_eq!(
        os.module_base("ntdll.dll"),
        Some(ntdll_base),
        "ntdll recorded as a real mapped image at its returned base"
    );
    // kernelbase/kernel32/ucrtbase are NOT pre-mapped by exemu anymore — Wine's
    // own loader_init/build_module loads them during the full boot (proven by
    // the W3 gate, wine_gate.rs). Pre-mapping them here would double-map them
    // onto PEB.Ldr, the very duplicate-Ldr bug the phase-iv trim removes.
    for n in ["kernelbase.dll", "kernel32.dll", "ucrtbase.dll"] {
        assert_eq!(
            os.module_base(n),
            None,
            "{n} must NOT be pre-mapped by exemu (Wine loads it during the boot)"
        );
    }
    // ntdll exports resolve by name (proves the export table was recorded).
    assert_eq!(
        os.ntdll_export("LdrInitializeThunk"),
        Some(ntdll_base + exemu_os::RVA_LDR_INITIALIZE_THUNK),
        "LdrInitializeThunk resolves by name to base + the W3.1 RVA"
    );

    // (2) ntdll's unixlib + __wine_unix_call_dispatcher are wired (the boot needs
    // both non-null before LdrInitializeThunk runs; see the dedicated dispatcher
    // test for the full cross-checks). Here just confirm the trim kept them.
    let disp = mem.read_u64(ntdll_base + exemu_os::RVA_WINE_UNIX_CALL_DISPATCHER).unwrap();
    assert_eq!(disp, os.wine_unix_call_thunk(), "unix-call dispatcher global wired to the thunk");

    // (3) PEB.Ldr InLoadOrder holds EXACTLY ntdll + the exe — no duplicates, and
    // specifically NOT kernelbase/kernel32/ucrtbase (Wine threads those on during
    // the full boot; exemu pre-inserting them was the duplicate-Ldr bug).
    let names = ldr_in_load_order_names(&mem);
    assert!(names.contains(&"ntdll.dll".to_string()), "PEB.Ldr lists ntdll (got {names:?})");
    assert!(names.contains(&"program.exe".to_string()), "PEB.Ldr lists the exe (got {names:?})");
    for absent in ["kernelbase.dll", "kernel32.dll", "ucrtbase.dll"] {
        assert!(
            !names.contains(&absent.to_string()),
            "PEB.Ldr must NOT hold exemu-pre-mapped {absent} (Wine adds it) — got {names:?}"
        );
    }
    // No duplicate base names anywhere in the ring.
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "no duplicate PEB.Ldr entries (got {names:?})");
    assert_eq!(names.len(), 2, "exactly ntdll + exe on PEB.Ldr post-trim (got {names:?})");

    // (4) Drive ntdll's queued DllMain(DLL_PROCESS_ATTACH) through the REAL CPU.
    // Post-trim only ntdll's DllMain is queued (Wine drives the rest during the
    // full boot). This proves ntdll's own PROCESS_ATTACH DllMain — real Wine
    // code, reached via the re-entrant callback machinery on the seeded
    // TEB/PEB/Ldr — runs and RETURNS **fault-free**: the drain lands cleanly on
    // the sentinel `hlt` (Halted), never `Err(fault)`.
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
        // rip lands on the sentinel until run_pending_dllmains re-seats it; if
        // nothing is queued the loop halts immediately.
        s.rip = SENTINEL;
    }
    os.run_pending_dllmains(cpu.state_mut(), &mut mem)
        .expect("run_pending_dllmains seats the callback sequence");

    // ntdll's image extent (base .. base+aligned size_of_image) for attribution.
    let ntdll_ext = {
        let bytes = std::fs::read(Path::new(WINE_DLLS).join("ntdll.dll")).unwrap();
        let img = exemu_loader::parse(&bytes).unwrap();
        ntdll_base..ntdll_base + align_up(img.size_of_image as u64, 0x1000)
    };

    let mut steps: u64 = 0;
    let mut entered_ntdll_dllmain = false;
    let ntdll_dllmain = ntdll_base + 0x12e10; // ntdll's PE entry (DllMain)
    loop {
        let rip = cpu.state().rip;
        // ntdll's DllMain body executes real code inside ntdll's image.
        if ntdll_ext.contains(&rip) && rip != ntdll_dllmain {
            entered_ntdll_dllmain = true;
        }
        match cpu.step(&mut mem, &mut os) {
            Ok(Exit::Continue) => steps += 1,
            Ok(Exit::Halted) => break, // clean drain — DllMain returned to the sentinel
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

/// W3.3 part 1 — `load_wine_core` seeds a valid v6 `API_SET_NAMESPACE` and
/// publishes it at `PEB.ApiSetMap` (x64 PEB `+0x68`). Wine's `loader_init →
/// build_module → build_import_name` reads that pointer for every imported DLL
/// name; before this seed it faulted after ~145 instrs on the null pointer.
/// This asserts the pointer is non-null, in guest memory, and points at a
/// well-formed, walkable v6 header — and that a known contract resolves to its
/// host through it exactly as ntdll's `get_apiset_entry` would.
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

    // PEB.ApiSetMap (x64 PEB +0x68) is non-null and equals the seeded base.
    let map = mem.read_u64(PEB_ADDR + 0x68).unwrap();
    assert_ne!(map, 0, "PEB.ApiSetMap seeded (non-null)");
    assert_eq!(map, os.api_set_map(), "PEB.ApiSetMap == the seeded namespace base");
    // It lives in a real mapped region (the loader arena, top of the DLL arena).
    assert!((DLL_BASE..DLL_BASE + DLL_SIZE).contains(&map), "ApiSetMap in the DLL arena");

    // Valid v6 header (self-relative offsets from `map`).
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

    // Hash table is sorted ascending (ntdll binary-searches it).
    let mut prev = 0u32;
    for i in 0..count {
        let h = mem.read_u32(map + hash_off as u64 + (i * 8) as u64).unwrap();
        if i > 0 {
            assert!(h > prev, "hash table ascending at {i}");
        }
        prev = h;
    }

    // Walk a known contract end-to-end the way ntdll's `get_apiset_entry` does:
    // hash → binary-search the hash table → Index → entry → value → host DLL.
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
                    let vo = mem.read_u32(eo + 0x10).unwrap() as u64; // ValueOffset
                    let val_off = mem.read_u32(map + vo + 0x0C).unwrap() as u64; // Value.ValueOffset
                    let val_len = mem.read_u32(map + vo + 0x10).unwrap() as u64; // Value.ValueLength
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

/// W3.6 — `PEB.ProcessParameters` (x64 PEB `+0x20`) points at a **full**
/// `RTL_USER_PROCESS_PARAMETERS` (>= 0x410, Flags NORMALIZED, a readable
/// CommandLine, an Environment + matching EnvironmentSize @0x3f0). The prior
/// 0x80-byte stub faulted Wine's `init_user_process_params` at `+0x3f0` after
/// 5743 boot instructions; this proves the deep-read fields are now present.
/// `init_ldr` (run in `setup`) builds it, so this needs no live boot.
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

    // PEB.ProcessParameters (x64 PEB +0x20) is non-null and full-sized.
    let pp = mem.read_u64(PEB_ADDR + 0x20).unwrap();
    assert_ne!(pp, 0, "PEB.ProcessParameters seeded");
    assert!((DLL_BASE..DLL_BASE + DLL_SIZE).contains(&pp), "PP in the loader arena");
    assert!(mem.read_u32(pp).unwrap() >= 0x410, "MaximumLength spans the full header");
    assert_eq!(mem.read_u32(pp + 0x08).unwrap() & 0x1, 0x1, "Flags NORMALIZED");

    // CommandLine @0x70 (UNICODE_STRING) points at the mapped UTF-16 command line.
    let cmd_len = mem.read_u16(pp + 0x70).unwrap();
    let cmd_buf = mem.read_u64(pp + 0x70 + 8).unwrap();
    assert!(cmd_len > 0 && cmd_buf != 0, "CommandLine populated");
    let units: Vec<u16> =
        (0..cmd_len as u64 / 2).map(|i| mem.read_u16(cmd_buf + i * 2).unwrap()).collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "C:\\program.exe");

    // Environment @0x80 + EnvironmentSize @0x3f0 (the former fault offset) agree,
    // and the block is double-NUL terminated.
    let env = mem.read_u64(pp + 0x80).unwrap();
    let env_size = mem.read_u64(pp + 0x3f0).unwrap();
    assert_ne!(env, 0, "Environment non-null");
    assert!(env_size >= 4, "EnvironmentSize covers the terminator");
    assert_eq!(mem.read_u16(env + env_size - 2).unwrap(), 0, "env ends in NUL");
    assert_eq!(mem.read_u16(env + env_size - 4).unwrap(), 0, "env double-NUL terminated");

    let _ = std::fs::remove_dir_all(&dir);
}

/// W3.2 follow-up (W2.4) — `load_wine_core` wires ntdll's
/// `__wine_unix_call_dispatcher` global (RVA 0x9c058) to the intercepted
/// `__wine_unix_call` fast-path thunk. Wine maps ntdll with no unix side, so
/// this pointer would be null and every PE-side `call
/// [__wine_unix_call_dispatcher]` (the very first is `__wine_dbg_write` in
/// `loader_init`'s TRACE path) faults on a null call — the boot blocker at
/// ntdll RVA 0x3f375. This proves the global now reads back the thunk address.
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

    // The dispatcher global at ntdll_base + 0x9c058 holds the fast-path thunk,
    // not null. `wine_unix_call_thunk()` is idempotent, so this is the exact
    // pointer the guest's indirect call will land on.
    let disp = ntdll_base + exemu_os::RVA_WINE_UNIX_CALL_DISPATCHER;
    let wired = mem.read_u64(disp).unwrap();
    assert_ne!(wired, 0, "__wine_unix_call_dispatcher no longer null (the boot blocker)");
    assert_eq!(wired, os.wine_unix_call_thunk(), "dispatcher global == the __wine_unix_call thunk");

    // Cross-check the RVA independently against ntdll's own data export table:
    // the loader wired the same address the guest's disassembly resolves to.
    if let Some(export_va) = os.ntdll_export("__wine_unix_call_dispatcher") {
        assert_eq!(export_va, disp, "wired RVA == ntdll's __wine_unix_call_dispatcher export");
    }

    // Its sibling __wine_syscall_dispatcher (0x9c050) is NOT wired (ntdll's
    // syscall stubs take the bare `syscall` path; no code reads this pointer) —
    // it stays zero, confirming we only touched the one global that needs it.
    let syscall_disp = mem.read_u64(ntdll_base + 0x9c050).unwrap();
    assert_eq!(syscall_disp, 0, "__wine_syscall_dispatcher left null (unused by ntdll)");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Boot-progress (W3.x) — `seed_main_teb` seeds `TEB.ActivationContextStackPointer`
/// (TEB +0x2c8) with an inline, empty `ACTIVATION_CONTEXT_STACK`. Wine's ntdll
/// dereferences this in its SxS lookup (`RtlFindActivationContextSectionString`
/// @ RVA 0x24180: `mov rax,gs:[0x30]; mov rax,[rax+0x2c8]; mov rcx,[rax]`) — a
/// null pointer there faults on `mov rcx,[rax]` (the 60818-instr boot blocker).
/// This proves the pointer is non-null, sits inside the mapped TEB region clear
/// of the `syscall_frame` tail, and that its `ActiveFrame` (@0x00) reads 0 so the
/// lookup takes its "no active frame → process default" branch.
#[test]
fn wine_core_seeds_activation_context_stack() {
    let dir = std::env::temp_dir().join(format!("exemu-actctx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A minimal harness (no Wine DLLs needed — the seed is independent of them):
    // just the TEB region + a WinOs whose `seed_main_teb` writes the stack.
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

    // TEB+0x2c8 → an ACTIVATION_CONTEXT_STACK inside the mapped TEB region.
    let actx = mem.read_u64(TEB_BASE + 0x2c8).unwrap();
    assert_ne!(actx, 0, "ActivationContextStackPointer seeded (the boot blocker)");
    assert_eq!(actx, TEB_BASE + 0x1900, "stack laid inline in the TEB region gap");
    // Must clear the syscall_frame parked in the tail (0x2000 - 0x140 = 0x1ec0).
    assert!(actx + 0x28 <= TEB_BASE + (0x2000 - 0x140), "clear of the syscall_frame tail");

    // ActiveFrame (@0x00) is 0 → the "no active frame" branch (RtlFind*/RtlFree*
    // both short-circuit); FrameListCache LIST_ENTRY (@0x08) is self-referential.
    assert_eq!(mem.read_u64(actx).unwrap(), 0, "ActiveFrame empty");
    assert_eq!(mem.read_u64(actx + 0x08).unwrap(), actx + 0x08, "FrameListCache.Flink → self");
    assert_eq!(mem.read_u64(actx + 0x10).unwrap(), actx + 0x08, "FrameListCache.Blink → self");

    let _ = std::fs::remove_dir_all(&dir);
}
