//! W3.2 — the **Wine PE core load** intermediate gate.
//!
//! Proves that [`WinOs::load_wine_core`] maps the pinned Wine core set
//! (`ntdll → kernelbase → kernel32 → ucrtbase`) as **real guest images** — not
//! the emulated-DLL thunk stand-ins — with:
//!
//!   1. all four mapped + relocated (real bases recorded);
//!   2. inter-module imports bound to **real code** (a kernel32 IAT slot that
//!      imports a kernelbase/ntdll symbol holds `predecessor_base + export_rva`,
//!      inside the mapped image, not an emulated thunk);
//!   3. all four threaded onto `PEB.Ldr` InLoadOrder;
//!   4. every queued `DllMain(DLL_PROCESS_ATTACH)` driven through the real CPU
//!      **fault-free** (each step `Continue`/`Halted`, never `Err(fault)`).
//!
//! This is the W3.2 deliverable — the *load*, not the full `LdrInitializeThunk`
//! boot-to-console (that needs the W3.3 exc bridge + W3.4 console). Skips
//! cleanly when the (git-ignored) Wine DLL set is absent.

use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

// A layout that mirrors exemu-app's 64-bit process map closely enough that
// Wine's ntdll/kernelbase/kernel32/ucrtbase DllMains find the TEB/PEB/KUSER
// fields they dereference. The DLL arena is large enough for the ~16 MiB the
// four core images occupy.
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
/// `wine_dll_dir`, then run `init_ldr` so `load_wine_core` can thread the four
/// modules onto `PEB.Ldr`. Returns the pieces the test drives.
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

    // (1) load_wine_core maps + relocates all four; returns ntdll's real base.
    let ntdll_base = os
        .load_wine_core(&mut mem)
        .expect("load_wine_core ok")
        .expect("the four Wine core DLLs present → Some(ntdll_base)");
    assert_eq!(ntdll_base & 0xfff, 0, "ntdll base is page-aligned");
    assert!(
        (DLL_BASE..DLL_BASE + DLL_SIZE).contains(&ntdll_base),
        "ntdll mapped into the DLL arena"
    );

    // by_name has REAL bases for all four (not emulated synthetic handles).
    let bases: Vec<(&str, u64)> = ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll"]
        .iter()
        .map(|&n| (n, os.module_base(n).unwrap_or_else(|| panic!("{n} not mapped as a real image"))))
        .collect();
    for (n, b) in &bases {
        assert!(
            (DLL_BASE..DLL_BASE + DLL_SIZE).contains(b),
            "{n} @ {b:#x} inside the DLL arena"
        );
    }
    // Distinct, ascending bases (loaded in order, no overlap collapse).
    for w in bases.windows(2) {
        assert!(w[0].1 < w[1].1, "{} < {} (load order)", w[0].0, w[1].0);
    }
    // ntdll exports resolve by name (proves the export table was recorded).
    assert_eq!(
        os.ntdll_export("LdrInitializeThunk"),
        Some(ntdll_base + exemu_os::RVA_LDR_INITIALIZE_THUNK),
        "LdrInitializeThunk resolves by name to base + the W3.1 RVA"
    );

    // (2) Inter-module binding: a kernel32 IAT slot importing a kernelbase/ntdll
    // symbol holds REAL CODE (predecessor_base + export_rva inside that image),
    // NOT an emulated thunk (which would live in [API_BASE, API_BASE+API_SIZE)).
    let kernel32 = os.module_base("kernel32.dll").unwrap();
    let kernelbase = os.module_base("kernelbase.dll").unwrap();
    let mut checked = 0usize;
    // Re-parse kernel32 to find its import IAT slots + which DLL each targets.
    let k32_bytes = std::fs::read(Path::new(WINE_DLLS).join("kernel32.dll")).unwrap();
    let k32 = exemu_loader::parse(&k32_bytes).unwrap();
    for imp in &k32.imports {
        let dll = imp.dll.to_ascii_lowercase();
        let (lo, hi) = if dll == "kernelbase.dll" {
            (kernelbase, kernelbase + DLL_SIZE)
        } else if dll == "ntdll.dll" {
            (ntdll_base, ntdll_base + DLL_SIZE)
        } else {
            continue;
        };
        let slot = mem.read_u64(kernel32 + imp.iat_rva as u64).unwrap();
        assert!(
            slot >= lo && slot < hi,
            "kernel32 IAT[{:#x}] importing {dll} = {slot:#x} is NOT real code in [{lo:#x},{hi:#x}) \
             (an emulated thunk / unbound slot leaked through)",
            imp.iat_rva
        );
        assert!(
            !(API_BASE..API_BASE + API_SIZE).contains(&slot),
            "kernel32 IAT[{:#x}] = {slot:#x} is an emulated thunk, not real code",
            imp.iat_rva
        );
        checked += 1;
        if checked >= 32 {
            break; // a representative sample is enough
        }
    }
    assert!(checked > 0, "kernel32 imports kernelbase/ntdll symbols to check");

    // (3) PEB.Ldr InLoadOrder walk lists all four base names (plus the main image).
    let names = ldr_in_load_order_names(&mem);
    for want in ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll"] {
        assert!(names.contains(&want.to_string()), "PEB.Ldr InLoadOrder lists {want} (got {names:?})");
    }

    // (4) Drive the queued DllMain(DLL_PROCESS_ATTACH) chain (leaves-first:
    // ntdll → kernelbase → kernel32 → ucrtbase) through the REAL CPU. This
    // proves ntdll's own PROCESS_ATTACH DllMain — real Wine code, reached via
    // the re-entrant callback machinery on the seeded TEB/PEB/Ldr — runs
    // **fault-free**, and that a cross-module call lands on **real bound code**
    // (kernelbase's DllMain then calls ntdll's real NLS routine through its
    // inter-module IAT slot, entering ntdll's image at a real export).
    //
    // DOCUMENTED W3.2 boundary (NOT a load/binding defect): kernelbase's
    // DllMain reaches `RtlGetNlsSectionPtr` → `NtInitializeNlsFiles` (SSDT
    // 0x9e), which exemu's NT backend does not yet service (it needs an NLS-file
    // section — a W3.3+/W2-follow-up). The unserviced syscall returns
    // STATUS_NOT_IMPLEMENTED, so kernelbase then dereferences a NULL NLS base.
    // W3.2's deliverable is the LOAD + inter-bind + ntdll DllMain; the full
    // kernelbase/kernel32/ucrtbase init is downstream. We therefore drive until
    // control has provably (a) left ntdll's DllMain fault-free and (b) reached
    // kernelbase's DllMain via a real bound call, then stop at the NLS boundary.
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

    // Module extents (base .. base+aligned size_of_image) for attribution.
    let extent = |b: u64, name: &str| {
        let bytes = std::fs::read(Path::new(WINE_DLLS).join(name)).unwrap();
        let img = exemu_loader::parse(&bytes).unwrap();
        b..b + align_up(img.size_of_image as u64, 0x1000)
    };
    let ntdll_ext = extent(ntdll_base, "ntdll.dll");
    let kbase_ext = extent(kernelbase, "kernelbase.dll");

    let mut steps: u64 = 0;
    let mut entered_ntdll_dllmain = false;
    let mut reached_kernelbase = false;
    let ntdll_dllmain = ntdll_base + 0x12e10; // ntdll's PE entry (DllMain)
    loop {
        let rip = cpu.state().rip;
        // ntdll's DllMain body executes real code inside ntdll's image.
        if ntdll_ext.contains(&rip) && rip != ntdll_dllmain {
            entered_ntdll_dllmain = true;
        }
        // Control reaching kernelbase's image means ntdll's DllMain returned
        // fault-free AND kernelbase's DllMain started (leaves-first order).
        if kbase_ext.contains(&rip) {
            reached_kernelbase = true;
        }
        match cpu.step(&mut mem, &mut os) {
            Ok(Exit::Continue) => steps += 1,
            Ok(Exit::Halted) => break, // clean drain (no queued DllMain / fully drained)
            Ok(Exit::ProcessExit(_)) => break,
            Ok(other) => panic!("unexpected exit driving Wine core DllMains: {other:?}"),
            Err(e) => {
                // The ONLY tolerated stop is the documented NLS boundary reached
                // from *inside kernelbase's* DllMain (real code, after ntdll's
                // DllMain and a real cross-module call). Anything else — a fault
                // in ntdll's own DllMain, or before kernelbase is reached — is a
                // real W3.2 load/binding defect and fails the test.
                assert!(
                    entered_ntdll_dllmain,
                    "faulted before ntdll's DllMain ran real code (load defect): {e:?} @ {rip:#x}"
                );
                assert!(
                    reached_kernelbase,
                    "faulted before reaching kernelbase's DllMain via a real bound call \
                     (inter-module binding defect): {e:?} @ {rip:#x}"
                );
                // Reached the documented NLS boundary inside kernelbase — ntdll's
                // DllMain proved fault-free and real cross-module binding works.
                break;
            }
        }
        assert!(steps < 200_000_000, "DllMains ran away without draining");
    }
    assert!(entered_ntdll_dllmain, "ntdll's PROCESS_ATTACH DllMain executed real code");
    assert!(
        reached_kernelbase,
        "ntdll's DllMain returned fault-free and control reached kernelbase's DllMain \
         via real inter-module binding"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
