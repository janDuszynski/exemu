//! **W5 — the WoW64 gate**: a 32-bit guest PE boots on Wine's 64-bit PE set and
//! reaches exemu's `Nt*` layer through Wine's *own* thunks, with exemu
//! marshalling nothing.
//!
//! The chain under test, every hop after the first belonging to Wine:
//!
//! ```text
//!   <guest>.exe (PE32)  call [IAT]
//!     → ntdll32!NtAllocateVirtualMemory   Wine's own 32-bit stub
//!         mov eax,0x18; mov edx,<helper>; call edx; ret 0x18
//!     → ntdll32 rva 0xe0c4:  jmp dword ptr [__wine_syscall_dispatcher]
//!     → the wow64cpu BOP (FF 2D far jmp, CS 0x33)  built by BTCpuProcessInit
//!     → wow64cpu's 64-bit return handler
//!     → wow64.dll!Wow64SystemServiceEx
//!     → wow64.dll's per-service marshalling thunk
//!     → ntdll.dll (64-bit) NtAllocateVirtualMemory — a real `syscall`
//!     → exemu's SSDT handler → back out to the 32-bit guest
//! ```
//!
//! Skip-guarded on the git-ignored Wine DLL set (both halves).

use std::path::{Path, PathBuf};

use exemu_app::{wow64_boot, wow64_sample, Process, RunConfig};

const WINE_DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const WINE_DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_wow64_set() -> bool {
    wow64_boot::Wow64Dirs {
        dir64: Path::new(WINE_DLLS64),
        dir32: Path::new(WINE_DLLS32),
    }
    .complete()
}

fn private_sandbox(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("exemu-wow64-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn wow64_run_config(tag: &str) -> RunConfig {
    RunConfig {
        echo: false,
        max_steps: 40_000_000,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(tag)),
        ..RunConfig::default()
    }
}

/// **W5.4** — the WoW64 *process model* is built: both DLL sets mapped, the
/// dual TEB/PEB pair linked by the recovered `WowTebOffset`, and the guest's
/// imports bound to the **32-bit** ntdll (not the 64-bit one that shares its
/// name).
#[test]
fn wow64_process_model_is_built() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("model");
    let proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let boot = proc.wow64().expect("a 32-bit image on the Wine set boots WoW64");

    // Both halves are mapped, and the 32-bit-visible ones are below 4 GiB.
    assert!(boot.ntdll32.base < u32::MAX as u64, "the 32-bit ntdll must be 32-bit addressable");
    assert!(
        boot.wow64cpu.base + boot.wow64cpu.size <= u32::MAX as u64,
        "wow64cpu must load sub-4 GiB: BTCpuProcessInit range-checks the return handler's high 32 bits",
    );
    assert!(boot.wow64.base > u32::MAX as u64, "wow64.dll has no placement constraint (loaded high)");

    // The two ntdlls are genuinely different images.
    let ntdll32_alloc = boot.ntdll32.export("NtAllocateVirtualMemory").expect("32-bit ntdll export");
    assert!(ntdll32_alloc < u32::MAX as u64);
    assert_ne!(
        boot.ntdll32.export("LdrInitializeThunk"),
        boot.wow64.export("LdrInitializeThunk"),
        "the 32-bit and 64-bit ntdlls are distinct images",
    );

    // TEB64 → TEB32 through the recovered signed 32-bit WowTebOffset.
    let linked = exemu_os::wow64::teb32_of(proc.memory(), boot.teb64)
        .expect("TEB64 is mapped")
        .expect("WowTebOffset is non-zero — this IS a WoW64 thread");
    assert_eq!(linked, boot.teb32, "TEB64 + (i32)[TEB64+0x180c] resolves to TEB32");
    assert!(boot.teb32 <= u32::MAX as u64, "TEB32 must be 32-bit addressable");

    // TEB32 carries the 32-bit NT_TIB the guest reads through `fs:`.
    assert_eq!(
        proc.peek_u32(boot.teb32 + exemu_os::wow64::TEB32_SELF).unwrap() as u64,
        boot.teb32,
        "TEB32.NtTib.Self",
    );
    assert_eq!(
        proc.peek_u32(boot.teb32 + exemu_os::wow64::TEB32_PEB).unwrap() as u64,
        boot.peb32,
        "TEB32.ProcessEnvironmentBlock → PEB32",
    );
    assert_ne!(boot.peb32, boot.peb64, "PEB32 and PEB64 are distinct");
    assert_eq!(
        proc.peek_u32(boot.peb32 + exemu_os::wow64::peb32::IMAGE_BASE).unwrap() as u64,
        proc.image_base(),
        "PEB32.ImageBaseAddress is the *guest* PE32, not the 64-bit ntdll",
    );

    // The guest's IAT is bound to the 32-bit ntdll's real export.
    let iat = wow64_sample::iat_alloc_va();
    assert_eq!(
        proc.peek_u32(iat).unwrap() as u64,
        ntdll32_alloc,
        "the PE32 guest's ntdll import resolved to the i386 ntdll, not the x86_64 one",
    );
}

/// **W5.1** — the BOP is published where Wine's *own* 32-bit ntdll looks for it.
///
/// exemu's bring-up trampoline runs the real `BTCpuProcessInit` and the real
/// `BTCpuGetBopCode`, then stores the result into the three cells `wow64.dll`
/// itself fills. This asserts the outcome against the 32-bit ntdll's actual
/// bytes: the value published must be the `FF 2D` far-jump trampoline, and the
/// helper every syscall stub jumps through must reach it.
#[test]
fn wow64_transition_is_published_where_the_real_ntdll32_looks() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("publish");
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");

    // Run only the bring-up trampoline: BTCpuProcessInit → BTCpuGetBopCode →
    // the three stores. Stopping before `BTCpuSimulate` keeps the assertions
    // about the *publish* step alone.
    let (transition, dispatcher, wow32_reserved, bop_expected) = {
        let boot = proc.wow64().expect("WoW64 boot");
        (
            boot.ntdll32.export("Wow64Transition").expect("ntdll32!Wow64Transition"),
            boot.ntdll32
                .export("__wine_syscall_dispatcher")
                .expect("ntdll32!__wine_syscall_dispatcher"),
            boot.teb32 + exemu_os::wow64::TEB32_WOW32_RESERVED,
            boot.wow64cpu.base,
        )
    };
    let simulate = proc
        .wow64()
        .and_then(|b| b.wow64cpu.export("BTCpuSimulate"))
        .expect("wow64cpu!BTCpuSimulate");
    let steps = proc
        .run_until_rip(simulate, 2_000_000)
        .expect("the bring-up trampoline ran to the BTCpuSimulate call");
    assert!(steps > 0, "the trampoline executed instructions");

    let bop = proc.peek_u32(transition).unwrap() as u64;
    assert_ne!(bop, 0, "Wow64Transition was published");
    assert!(
        bop >= bop_expected && bop < bop_expected + 0x10000,
        "the published BOP {bop:#x} lies inside the mapped wow64cpu image",
    );
    assert_eq!(
        proc.peek_u32(dispatcher).unwrap() as u64,
        bop,
        "__wine_syscall_dispatcher gets the SAME pointer — it is what ntdll32's stubs actually jump through",
    );
    assert_eq!(
        proc.peek_u32(wow32_reserved).unwrap() as u64,
        bop,
        "TEB32.WOW32Reserved gets it too (the `call dword ptr fs:[0xc0]` stub shape)",
    );

    // The published value is the far-jump trampoline the real init assembled.
    assert_eq!(
        proc.peek_u32(bop).unwrap() & 0xFFFF,
        0x2DFF,
        "the BOP is wow64cpu's own `FF 2D` (jmp fword ptr [mem]) trampoline",
    );

    // The `.bss` selector slots `BTCpuProcessInit` fills from the two contexts it
    // captures. Their RVAs were recovered by *running* the init
    // (`dll_smoke.rs::btcpuprocessinit_builds_the_return_bop_and_selectors`).
    // Checking them here proves the two ntdll routines the init calls really
    // answered: `RtlCaptureContext` (whose `mov [rcx+0x38], cs` supplies the
    // 64-bit CS baked into the BOP) and `RtlWow64GetThreadContext` → exemu's
    // `NtQueryInformationThread(ThreadWow64Context)` (which supplies SegCs/SegSs
    // out of the CPU-reserved area). A silent failure in either would leave these
    // reading uninitialised stack.
    let cpu_base = proc.wow64().unwrap().wow64cpu.base;
    assert_eq!(
        proc.peek_u32(cpu_base + 0x600c).unwrap(),
        exemu_os::wow64::SEL_CS32,
        "BTCpuProcessInit cached the 32-bit CS from RtlWow64GetThreadContext",
    );
    assert_eq!(
        proc.peek_u32(cpu_base + 0x6008).unwrap(),
        exemu_os::wow64::SEL_SS32,
        "…and the 32-bit SS",
    );
    assert_eq!(
        proc.peek_u32(bop + 0xa).unwrap() & 0xFFFF,
        exemu_os::wow64::SEL_CS64,
        "the BOP's far-pointer selector is the live 64-bit CS RtlCaptureContext reported",
    );
}

/// **Measured gap, pinned so it stays visible (roadmap W5.5).**
///
/// exemu builds the WoW64 process itself instead of running Wine's
/// `Wow64LdrpInitialize`, so `wow64.dll`'s **table 1** — the win32k service
/// descriptor it copies out of `wow64win!sdwhwin32` — is never registered. Table
/// 0 (ntdll, 0x108 services) *is* live because its descriptor is statically
/// initialised in `.data` and merely relocated, which is why the `Nt*` path
/// works and the `NtUser*`/`NtGdi*` path does not.
///
/// Consequence: a 32-bit guest cannot yet open a window through the 64-bit set —
/// the second half of the W5.5 goal. Closing it (running `Wow64LdrpInitialize`,
/// or performing the descriptor copy) will fail this test and force the claim to
/// be updated.
#[test]
fn wow64_win32k_table_is_not_registered_yet() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    // Service descriptors are 32 bytes at `wow64.dll + 0x16080 + table*0x20`
    // (recovered in `knowledge/w5-wow64-design.know`).
    const DESC_BASE: u64 = 0x16080;
    const DESC_STRIDE: u64 = 0x20;
    const LIMIT: u64 = 0x10;

    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("win32k");
    let proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let w = proc.wow64().unwrap().wow64.base;

    // Table 0 (ntdll) is live: a real ServiceTable pointer and 0x108 services.
    assert_ne!(proc.memory().read_u64(w + DESC_BASE).unwrap(), 0, "table 0 ServiceTable is relocated in");
    assert_eq!(
        proc.peek_u32(w + DESC_BASE + LIMIT).unwrap(),
        0x108,
        "table 0 (ntdll) exposes 0x108 services",
    );

    // Table 1 (win32k) is still zero — the pinned gap.
    assert_eq!(
        proc.memory().read_u64(w + DESC_BASE + DESC_STRIDE).unwrap(),
        0,
        "table 1 (win32k) is UNREGISTERED: exemu does not run Wow64LdrpInitialize, so a 32-bit \
         NtUser*/NtGdi* call would dispatch through a null service table. A 32-bit GUI guest is \
         therefore NOT yet supported — see the W5.5 note.",
    );
    assert!(
        proc.wow64().unwrap().wow64win.export("sdwhwin32").is_some(),
        "the descriptor wow64.dll would copy is present in wow64win.dll — only the copy is missing",
    );
}

/// **W5.3 + W5.5 — the standing gate.** The 32-bit guest allocates memory
/// through the entire real chain and terminates with its own success code.
#[test]
fn wow64_guest_allocates_through_the_real_wine_chain() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("alloc");
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let (base_cell, size_cell, status_cell, read_cell) = (
        wow64_sample::data_va(wow64_sample::data::BASE),
        wow64_sample::data_va(wow64_sample::data::SIZE),
        wow64_sample::data_va(wow64_sample::data::STATUS),
        wow64_sample::data_va(wow64_sample::data::READBACK),
    );
    let r = proc.run_borrowed().expect("the WoW64 guest ran");

    let status = proc.peek_u32(status_cell).unwrap();
    let base = proc.peek_u32(base_cell).unwrap() as u64;
    assert_eq!(
        r.exit_code,
        wow64_sample::WOW64_OK_EXIT,
        "the 32-bit guest exited OK (status {status:#x}, base {base:#x}, {} instructions)",
        r.steps,
    );
    assert_eq!(status, 0, "STATUS_SUCCESS from exemu's NtAllocateVirtualMemory");
    assert_ne!(base, 0, "wow64.dll narrowed the 64-bit base back into the guest's 32-bit cell");
    assert_eq!(base & 0xFFFF, 0, "the written-back base is 64 KiB aligned");
    assert!(
        base <= 0x7FFF_FFFF,
        "the base honours wow64.dll's own 0x7fffffff ZeroBits ceiling ({base:#x})",
    );
    assert_eq!(proc.peek_u32(size_cell).unwrap(), wow64_sample::WOW64_ALLOC_SIZE, "RegionSize written back");
    assert_eq!(
        proc.peek_u32(read_cell).unwrap(),
        wow64_sample::WOW64_SENTINEL,
        "the pages the *32-bit guest* sees are really writable at the address it got back",
    );
    // A whole-chain sanity bound. `BTCpuProcessInit` alone is a few hundred
    // instructions and wow64.dll's NtAllocateVirtualMemory thunk another couple
    // of hundred, so a run that "passed" in a handful of instructions would mean
    // something short-circuited. Measured: 1292.
    assert!(
        (600..10_000).contains(&r.steps),
        "the full WoW64 chain should be ~1.3k instructions, ran {}",
        r.steps,
    );
}
