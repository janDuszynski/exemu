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
        wow64_bringup: wow64_boot::Bringup::Direct,
        ..wine_loader_config(tag)
    }
}

fn wine_loader_config(tag: &str) -> RunConfig {
    RunConfig {
        echo: false,
        max_steps: 40_000_000,
        wine_boot_dir: Some(WINE_DLLS64.to_string()),
        sandbox_root: Some(private_sandbox(tag)),
        ..RunConfig::default()
    }
}

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

    assert!(boot.ntdll32.base < u32::MAX as u64, "the 32-bit ntdll must be 32-bit addressable");
    assert!(
        boot.wow64cpu.base + boot.wow64cpu.size <= u32::MAX as u64,
        "wow64cpu must load sub-4 GiB: BTCpuProcessInit range-checks the return handler's high 32 bits",
    );
    assert!(boot.wow64.base > u32::MAX as u64, "wow64.dll has no placement constraint (loaded high)");

    let ntdll32_alloc = boot.ntdll32.export("NtAllocateVirtualMemory").expect("32-bit ntdll export");
    assert!(ntdll32_alloc < u32::MAX as u64);
    assert_ne!(
        boot.ntdll32.export("LdrInitializeThunk"),
        boot.wow64.export("LdrInitializeThunk"),
        "the 32-bit and 64-bit ntdlls are distinct images",
    );

    let linked = exemu_os::wow64::teb32_of(proc.memory(), boot.teb64)
        .expect("TEB64 is mapped")
        .expect("WowTebOffset is non-zero — this IS a WoW64 thread");
    assert_eq!(linked, boot.teb32, "TEB64 + (i32)[TEB64+0x180c] resolves to TEB32");
    assert!(boot.teb32 <= u32::MAX as u64, "TEB32 must be 32-bit addressable");

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

    let iat = wow64_sample::iat_alloc_va();
    assert_eq!(
        proc.peek_u32(iat).unwrap() as u64,
        ntdll32_alloc,
        "the PE32 guest's ntdll import resolved to the i386 ntdll, not the x86_64 one",
    );
}

#[test]
fn wow64_transition_is_published_where_the_real_ntdll32_looks() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("publish");
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");

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

    assert_eq!(
        proc.peek_u32(bop).unwrap() & 0xFFFF,
        0x2DFF,
        "the BOP is wow64cpu's own `FF 2D` (jmp fword ptr [mem]) trampoline",
    );

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

#[test]
fn wow64_win32k_table_is_not_registered_yet() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    const DESC_BASE: u64 = 0x16080;
    const DESC_STRIDE: u64 = 0x20;
    const LIMIT: u64 = 0x10;

    let exe = wow64_sample::build();
    let mut cfg = wow64_run_config("win32k");
    let proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let w = proc.wow64().unwrap().wow64.base;

    assert_ne!(proc.memory().read_u64(w + DESC_BASE).unwrap(), 0, "table 0 ServiceTable is relocated in");
    assert_eq!(
        proc.peek_u32(w + DESC_BASE + LIMIT).unwrap(),
        0x108,
        "table 0 (ntdll) exposes 0x108 services",
    );

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
    eprintln!("W5.1 (direct bring-up) — the guest exited {} after {} instructions", r.exit_code, r.steps);

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
    assert!(
        (600..10_000).contains(&r.steps),
        "the full WoW64 chain should be ~1.3k instructions, ran {}",
        r.steps,
    );
}

#[test]
fn wow64_wine_loader_registers_the_win32k_table() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    const DESC_BASE: u64 = 0x16080;
    const DESC_STRIDE: u64 = 0x20;
    const LIMIT: u64 = 0x10;

    let exe = wow64_sample::build();
    let mut cfg = wine_loader_config("table1");
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let simulate = proc
        .wow64()
        .and_then(|b| b.wow64cpu.export("BTCpuSimulate"))
        .expect("wow64cpu!BTCpuSimulate");
    let steps = proc.run_until_rip(simulate, 4_000_000).expect("Wow64LdrpInitialize ran");
    eprintln!("W5.7 — Wine's WoW64 process + thread init ran {steps} instructions");
    assert!(steps > 1_000, "Wine's process + thread init ran {steps} instructions");

    let (w, sdwhwin32) = {
        let b = proc.wow64().unwrap();
        (b.wow64.base, b.wow64win.export("sdwhwin32").expect("wow64win!sdwhwin32"))
    };

    assert_eq!(proc.peek_u32(w + DESC_BASE + LIMIT).unwrap(), 0x108, "table 0 (ntdll) still 0x108 services");
    let t1 = proc.memory().read_u64(w + DESC_BASE + DESC_STRIDE).unwrap();
    assert_ne!(t1, 0, "table 1 (win32k) ServiceTable is registered");

    for i in 0..4u64 {
        assert_eq!(
            proc.memory().read_u64(w + DESC_BASE + DESC_STRIDE + i * 8).unwrap(),
            proc.memory().read_u64(sdwhwin32 + i * 8).unwrap(),
            "descriptor qword {i} copied verbatim from wow64win!sdwhwin32",
        );
    }
    let limit = proc.peek_u32(w + DESC_BASE + DESC_STRIDE + LIMIT).unwrap();
    assert!(limit > 0x100, "table 1 exposes a real service count ({limit:#x})");

    let (transition, dispatcher, unix) = {
        let b = proc.wow64().unwrap();
        (
            b.ntdll32.export("Wow64Transition").unwrap(),
            b.ntdll32.export("__wine_syscall_dispatcher").unwrap(),
            b.ntdll32.export("__wine_unix_call_dispatcher").unwrap(),
        )
    };
    let bop = proc.peek_u32(transition).unwrap();
    assert_ne!(bop, 0, "wow64.dll published Wow64Transition");
    assert_eq!(proc.peek_u32(dispatcher).unwrap(), bop, "…and __wine_syscall_dispatcher");
    assert_ne!(
        proc.peek_u32(unix).unwrap(),
        0,
        "…and __wine_unix_call_dispatcher, which the direct bring-up never filled",
    );
}

#[test]
fn wow64_wine_loader_boots_the_i386_ntdll_loader() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let exe = wow64_sample::build();
    let mut cfg = wine_loader_config("ldr32");
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");
    let ldr_init = proc
        .wow64()
        .and_then(|b| b.ntdll32.export("LdrInitializeThunk"))
        .expect("ntdll32!LdrInitializeThunk");

    let to_loader = proc
        .run_until_rip(ldr_init, 4_000_000)
        .expect("the 32-bit thread was seated on ntdll32!LdrInitializeThunk");
    assert!(
        (1_000..400_000).contains(&to_loader),
        "Wine's WoW64 bring-up reached the i386 LdrInitializeThunk in {to_loader} instructions",
    );

    let (base_cell, size_cell, status_cell, read_cell) = (
        wow64_sample::data_va(wow64_sample::data::BASE),
        wow64_sample::data_va(wow64_sample::data::SIZE),
        wow64_sample::data_va(wow64_sample::data::STATUS),
        wow64_sample::data_va(wow64_sample::data::READBACK),
    );
    let r = proc.run_borrowed().expect("the WoW64 guest ran");
    eprintln!("W5.7 — the guest exited {} after {} instructions", r.exit_code, r.steps);

    assert_eq!(
        r.exit_code,
        wow64_sample::WOW64_OK_EXIT,
        "the 32-bit guest exited OK after {} instructions (status {:#x})",
        r.steps,
        proc.peek_u32(status_cell).unwrap(),
    );
    assert_eq!(proc.peek_u32(status_cell).unwrap(), 0, "STATUS_SUCCESS from exemu's NtAllocateVirtualMemory");
    assert_eq!(proc.peek_u32(size_cell).unwrap(), wow64_sample::WOW64_ALLOC_SIZE, "RegionSize written back");
    assert_eq!(
        proc.peek_u32(read_cell).unwrap(),
        wow64_sample::WOW64_SENTINEL,
        "the pages the *32-bit guest* sees are really writable at the address it got back",
    );
    let base = proc.peek_u32(base_cell).unwrap() as u64;
    assert!(base != 0 && base <= 0x7FFF_FFFF, "base {base:#x} inside the 32-bit address space");

    let peb32 = proc.wow64().unwrap().peb32;
    let ldr = proc.peek_u32(peb32 + exemu_os::wow64::peb32::LDR).unwrap();
    assert_ne!(ldr, 0, "ntdll32's loader_init published PEB32.Ldr");

    assert!(
        (300_000..8_000_000).contains(&r.steps),
        "Wine's i386 loader_init should dominate the run, total was {}",
        r.steps,
    );
}

#[test]
fn a_32bit_guest_wndproc_gets_its_creation_messages() {
    if !have_wow64_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    use exemu_app::wow64_gui_sample as s;

    let exe = s::build();
    let mut cfg = wine_loader_config("wndproc");
    cfg.max_steps = 80_000_000;
    let mut proc = Process::load(&exe, &mut cfg).expect("WoW64 boot");

    let (peb64, wow64win_base, wow64win_size) = {
        let b = proc.wow64().expect("WoW64 boot");
        (b.peb64, b.wow64win.base, b.wow64win.size)
    };
    let table = proc.peek_u64(peb64 + exemu_os::wow64::PEB64_KERNEL_CALLBACK_TABLE).unwrap();
    assert!(
        table > wow64win_base && table < wow64win_base + wow64win_size,
        "PEB.KernelCallbackTable {table:#x} points into the mapped wow64win image",
    );
    let win_proc_cb = proc
        .peek_u64(table + 8 * u64::from(exemu_os::wow64::NT_USER_CALL_WIN_PROC))
        .unwrap();
    assert!(
        win_proc_cb > wow64win_base && win_proc_cb < wow64win_base + wow64win_size,
        "…and its NtUserCallWinProc entry is real code in that image",
    );

    let r = proc.run_borrowed().expect("the WoW64 GUI guest ran");
    let seen = proc.peek_u32(s::data_va(s::data::SEEN)).unwrap();
    eprintln!(
        "W5.10 — the 32-bit guest exited {} after {} instructions (seen={seen:#x})",
        r.exit_code, r.steps,
    );
    assert_eq!(
        r.exit_code,
        s::GUI_OK_EXIT,
        "the guest's own checks all held; seen={seen:#x} style={:#x} lresult={:#x}",
        proc.peek_u32(s::data_va(s::data::CS_STYLE)).unwrap(),
        proc.peek_u32(s::data_va(s::data::SEND_RESULT)).unwrap(),
    );

    let class_cell = |off: u32| proc.peek_u32(s::data_va(s::data::WNDCLASS + off)).unwrap();
    let info_cell = |off: u32| proc.peek_u32(s::data_va(s::data::WNDCLASSEX + off)).unwrap();
    assert_eq!(
        proc.peek_u32(s::data_va(s::data::INFO_ATOM)).unwrap(),
        proc.peek_u32(s::data_va(s::data::ATOM)).unwrap(),
        "GetClassInfoExW answers the atom RegisterClassW returned",
    );
    for (what, registered, answered, want) in [
        ("style", s::wndclassw::STYLE, s::wndclassexw::STYLE, s::CLASS_STYLE),
        ("cbClsExtra", s::wndclassw::CLS_EXTRA, s::wndclassexw::CLS_EXTRA, s::CLASS_CLS_EXTRA),
        ("cbWndExtra", s::wndclassw::WND_EXTRA, s::wndclassexw::WND_EXTRA, s::CLASS_WND_EXTRA),
        ("hbrBackground", s::wndclassw::BACKGROUND, s::wndclassexw::BACKGROUND, s::CLASS_BACKGROUND),
        ("lpszMenuName", s::wndclassw::MENU_NAME, s::wndclassexw::MENU_NAME, s::CLASS_MENU_NAME),
    ] {
        assert_eq!(class_cell(registered), want, "the guest registered {what} {want:#x}");
        assert_eq!(
            info_cell(answered),
            want,
            "GetClassInfoExW's {what} came back through wow64win's 64-to-32 copy of the kernel's answer",
        );
    }
    assert_eq!(info_cell(s::wndclassexw::WNDPROC), class_cell(s::wndclassw::WNDPROC), "lpfnWndProc");
    assert_eq!(info_cell(s::wndclassexw::INSTANCE), class_cell(s::wndclassw::INSTANCE), "hInstance");
    assert_eq!(info_cell(s::wndclassexw::CLASS_NAME), class_cell(s::wndclassw::CLASS_NAME), "lpszClassName");

    assert_eq!(seen, s::seen::ALL, "WM_NCCREATE, WM_CREATE and the private probe all arrived");
    let hwnd = proc.peek_u32(s::data_va(s::data::HWND)).unwrap();
    assert_ne!(hwnd, 0, "CreateWindowExW returned a window");
    assert_eq!(
        proc.peek_u32(s::data_va(s::data::PROC_HWND)).unwrap(),
        hwnd,
        "the procedure was called with the window it was creating",
    );
    let cs = proc.peek_u32(s::data_va(s::data::CS_PTR)).unwrap();
    assert_ne!(cs, 0, "WM_NCCREATE carried a CREATESTRUCTW");
    assert_eq!(
        proc.peek_u32(s::data_va(s::data::CS_STYLE)).unwrap(),
        s::WINDOW_STYLE,
        "…in the 32-bit layout, at an address a 32-bit pointer can hold ({cs:#x})",
    );
    assert_eq!(
        proc.peek_u32(s::data_va(s::data::SEND_RESULT)).unwrap(),
        s::PROBE_LRESULT,
        "the procedure's LRESULT made the whole round trip back to SendMessageW",
    );
    assert_eq!(
        proc.peek_u32(s::data_va(s::data::ESP_AFTER)).unwrap(),
        proc.peek_u32(s::data_va(s::data::ESP_BEFORE)).unwrap(),
        "every stdcall frame the kernel built was popped by the callee it was handed to",
    );
}
