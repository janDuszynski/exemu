//! The **WoW64 process model** — a 32-bit guest booted on Wine's 64-bit PE set
//! (roadmap W5.4).
//!
//! Under Wine's *new* WoW64 a 32-bit program is not a 32-bit process: it is a
//! **64-bit NT process** with a 32-bit view laid over it. exemu therefore builds
//! one address space holding both worlds:
//!
//! ```text
//!   64-bit half (exemu services this)      32-bit half (the guest lives here)
//!   ──────────────────────────────────     ─────────────────────────────────────
//!   ntdll.dll     (x86_64-windows)         <guest>.exe        (PE32)
//!   wow64.dll     — the service thunks     ntdll.dll          (i386-windows)
//!   wow64win.dll  — the win32k thunks      wow64cpu.dll  ← must be < 4 GiB
//!   TEB64 (gs:)  ─ WowTebOffset ─────────► TEB32 (fs:)
//!   PEB64                                  PEB32
//! ```
//!
//! The link between the two TEBs is **recovered, not assumed**: `TEB64 + 0x180c`
//! is a signed 32-bit `WowTebOffset` (`exemu_os::wow64::TEB64_WOW_TEB_OFFSET`),
//! which `wow64.dll` dereferences as `movsxd rdx,[teb64+0x180c]; lea rsi,
//! [teb64+rdx]` and `ntdll!RtlWow64GetCurrentMachine` tests for zero. Because
//! the offset is a signed 32-bit field *and* 32-bit guest code must be able to
//! hold a TEB32 pointer, the pair is placed adjacently below 4 GiB.
//!
//! Placement constraints, all load-bearing:
//!
//! * **`wow64cpu.dll` must load below 4 GiB.** `BTCpuProcessInit` builds the
//!   32→64 return BOP as an `m16:32` far pointer and range-checks the return
//!   handler's high 32 bits (`shr rcx,0x20; jne <error>` → `0xC0000141`).
//! * **The 32-bit ntdll, the guest image, its stack and TEB32/PEB32** are all
//!   addressed by 32-bit code, so they live below 4 GiB too.
//! * **`ntdll.dll` (64-bit), `wow64.dll` and `wow64win.dll`** have no such
//!   constraint and stay in the ordinary 64-bit DLL arena.
//!
//! exemu's job here is the **kernel's** (and, in Wine's split, the Unix side's):
//! map the module set, build the dual TEB/PEB pair, fill
//! `ntdll!LdrSystemDllInitBlock` and `PEB32.ProcessParameters`, and seed the
//! CPU-reserved area with the thread's 32-bit start state. Everything after the
//! hand-off is Wine's own code — including, on the default
//! [`Bringup::WineLoader`] path, `Wow64LdrpInitialize` itself: it registers the
//! win32k service table, publishes the BOP, and starts the 32-bit thread inside
//! `ntdll32!LdrInitializeThunk`, so Wine's i386 loader binds the guest's whole
//! import graph. The mode switch, the service dispatch and all 32↔64 argument
//! marshalling are Wine's throughout.

use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, EmuError, Memory, Perm, Result};
use exemu_memory::VirtualMemory;
use exemu_os::wow64::{self, Wow64Image};

/// Base of the sub-4 GiB arena holding every image a 32-bit guest can address:
/// the 32-bit `ntdll.dll` and `wow64cpu.dll`. Chosen above the guest image /
/// heap / VirtualAlloc windows and below the TEB pair.
pub const WOW64_LOW_ARENA: u64 = 0x6000_0000;
/// Size of that arena (the pinned 32-bit ntdll alone is ~3.5 MiB of image).
pub const WOW64_LOW_ARENA_SIZE: u64 = 0x0800_0000; // 128 MiB

/// Base of the 64-bit TEB. Below 4 GiB — unlike an ordinary 64-bit process —
/// because `TEB64.WowTebOffset` is a **signed 32-bit** delta to TEB32 and 32-bit
/// guest code has to be able to hold a TEB32 pointer.
///
/// The `TEB64` / `PEB64` spacing (PEB one 0x2000 region above the TEB) is kept
/// identical to the ordinary 64-bit layout so the Wine-boot path's debug-scratch
/// pages, which are placed relative to both, land exactly where they do on the
/// 64-bit path.
pub const WOW64_TEB64: u64 = 0x7F00_0000;
/// `PEB64` — same relative placement as the plain 64-bit layout.
pub const WOW64_PEB64: u64 = WOW64_TEB64 + 0x2000;
/// Base of the WoW64-only block: the 32-bit TEB/PEB, the CPU-reserved area and
/// the `WOW64INFO`. Placed clear of the debug-scratch pages at `TEB64+0x3000`
/// and `PEB64+0x2000`.
pub const WOW64_EXTRA: u64 = WOW64_TEB64 + 0x8000;
/// Bytes covered by that block. Large enough to carry the 32-bit
/// `RTL_USER_PROCESS_PARAMETERS` and its strings/environment too — those are
/// reached through a 32-bit PEB field, so they cannot live in the ordinary
/// loader arena, which is above 4 GiB on this layout.
pub const WOW64_EXTRA_SIZE: u64 = 0x2_0000;
/// The 32-bit TEB (`fs:`). `TEB64.WowTebOffset` is the delta to here.
pub const WOW64_TEB32: u64 = WOW64_EXTRA;
/// `PEB32` (`fs:[0x30]`).
pub const WOW64_PEB32: u64 = WOW64_EXTRA + 0x2000;
/// The WoW64 CPU-reserved area (`TEB64+0x1488` points here) holding the
/// `WOW64_CONTEXT` that `BTCpuSimulate` loads the 32-bit registers from.
pub const WOW64_CPU_AREA: u64 = WOW64_EXTRA + 0x3000;
/// The `WOW64INFO` block `BTCpuProcessInit` flags through `TEB64+0x14d0`.
pub const WOW64_INFO: u64 = WOW64_EXTRA + 0x4000;
/// A sub-4 GiB arena for `PEB32.ProcessParameters` and the strings it points at.
pub const WOW64_PARAMS: u64 = WOW64_EXTRA + 0x5000;
/// Bytes available to it (the rest of the WoW64 block).
pub const WOW64_PARAMS_SIZE: u64 = WOW64_EXTRA_SIZE - 0x5000;

/// The 32-bit guest's own stack (separate from the 64-bit stack the WoW64 thunk
/// layer runs on — `BTCpuSimulate` `xchg`es between them).
pub const WOW64_STACK32_BASE: u64 = 0x0018_0000;
/// Size of the 32-bit guest stack (2 MiB, matching the plain 32-bit layout).
pub const WOW64_STACK32_SIZE: u64 = 0x0020_0000;

/// The mapped WoW64 module set plus the dual process structures.
pub struct Wow64Boot {
    /// Wine's 32-bit `ntdll.dll` (`i386-windows`) — the guest's syscall stubs.
    pub ntdll32: Wow64Image,
    /// Wine's `wow64cpu.dll` — the binary-translator core (sub-4 GiB).
    pub wow64cpu: Wow64Image,
    /// Wine's `wow64.dll` — the 32→64 service marshalling layer.
    pub wow64: Wow64Image,
    /// Wine's `wow64win.dll` — the win32k half (table 1).
    pub wow64win: Wow64Image,
    /// The 64-bit TEB (`gs:`).
    pub teb64: u64,
    /// The 32-bit TEB (`fs:`), reachable from `teb64` via `WowTebOffset`.
    pub teb32: u64,
    /// The 64-bit PEB.
    pub peb64: u64,
    /// The 32-bit PEB (`fs:[0x30]`).
    pub peb32: u64,
    /// The WoW64 CPU-reserved area.
    pub cpu_area: u64,
    /// Top of the 32-bit guest stack.
    pub stack32_top: u64,
}

/// Both halves of the pinned Wine PE prefix.
pub struct Wow64Dirs<'a> {
    /// `example_exe/wine-dlls/x86_64-windows` — the 64-bit set.
    pub dir64: &'a Path,
    /// `example_exe/wine-dlls/i386-windows` — the 32-bit set.
    pub dir32: &'a Path,
}

impl Wow64Dirs<'_> {
    /// Every file the WoW64 boot needs, so a partial prefix falls back to the
    /// ordinary path instead of half-booting.
    pub fn complete(&self) -> bool {
        self.dir64.join("ntdll.dll").is_file()
            && self.dir64.join("wow64.dll").is_file()
            && self.dir64.join("wow64cpu.dll").is_file()
            && self.dir64.join("wow64win.dll").is_file()
            && self.dir32.join("ntdll.dll").is_file()
    }
}

/// Given `<prefix>/x86_64-windows`, the matching 32-bit prefix directory.
pub fn sibling_i386_dir(dir64: &Path) -> std::path::PathBuf {
    match dir64.parent() {
        Some(p) => p.join("i386-windows"),
        None => std::path::PathBuf::from("i386-windows"),
    }
}

/// Map the WoW64 module set and build the dual TEB/PEB pair (roadmap W5.4).
///
/// `ntdll64` is the already-mapped 64-bit `ntdll.dll` image (exemu maps it as
/// the running image on the Wine-boot path); its exports are what `wow64.dll`'s
/// per-service thunks tail-jump into, so they are bound here.
pub fn build(
    mem: &mut VirtualMemory,
    dirs: &Wow64Dirs<'_>,
    ntdll64: &Wow64Image,
    guest_image_base: u64,
) -> Result<Wow64Boot> {
    // --- The sub-4 GiB image arena --------------------------------------
    let mut low = WOW64_LOW_ARENA;
    let mut place = |mem: &mut VirtualMemory, host: std::path::PathBuf, name: &'static str| -> Result<Wow64Image> {
        let bytes = std::fs::read(&host)
            .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read {}: {e}", host.display())))?;
        let img = wow64::map_image(mem, &bytes, low, name)?;
        low += img.size;
        low = (low + 0xffff) & !0xffff; // keep every image 64 KiB aligned
        if low > WOW64_LOW_ARENA + WOW64_LOW_ARENA_SIZE {
            return Err(EmuError::Os("WoW64 boot: the sub-4 GiB image arena is exhausted".into()));
        }
        Ok(img)
    };
    let ntdll32 = place(mem, dirs.dir32.join("ntdll.dll"), "ntdll32")?;
    let wow64cpu = place(mem, dirs.dir64.join("wow64cpu.dll"), "wow64cpu")?;
    debug_assert!(wow64cpu.base + wow64cpu.size <= u32::MAX as u64);

    // --- The 64-bit half (no placement constraint) ------------------------
    // Above the 32-bit arena but still inside the ordinary 64-bit space; a
    // fixed window keeps the boot deterministic.
    const HIGH: u64 = 0x0000_0007_0000_0000;
    let wow64_bytes = std::fs::read(dirs.dir64.join("wow64.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read wow64.dll: {e}")))?;
    let wow64_img = wow64::map_image(mem, &wow64_bytes, HIGH, "wow64")?;
    let win_bytes = std::fs::read(dirs.dir64.join("wow64win.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read wow64win.dll: {e}")))?;
    let wow64win = wow64::map_image(mem, &win_bytes, HIGH + 0x0400_0000, "wow64win")?;

    // --- Inter-module binding (what a loader does) ------------------------
    // `wow64.dll` reaches the 64-bit NT layer through its own ntdll IAT; its
    // per-service thunks tail-jump straight into Wine's real 64-bit stubs.
    let bound = wow64::bind_imports(mem, &wow64_img, &[ntdll64], 8)?;
    if bound < 200 {
        return Err(EmuError::Os(format!(
            "WoW64 boot: wow64.dll bound only {bound} ntdll imports (expected 200+) — wrong pinned set?"
        )));
    }
    // `wow64cpu.dll` imports exactly one wow64.dll symbol (Wow64SystemServiceEx)
    // and a handful of ntdll routines its process init calls.
    wow64::bind_imports(mem, &wow64cpu, &[&wow64_img, ntdll64], 8)?;
    wow64::bind_imports(mem, &wow64win, &[ntdll64, &wow64_img], 8)?;

    // --- The dual TEB/PEB pair -------------------------------------------
    // TEB64/PEB64 are mapped by the ordinary layout; this block adds the 32-bit
    // half plus the WoW64-specific structures.
    mem.map(exemu_core::Region::new("wow64_extra", WOW64_EXTRA, WOW64_EXTRA_SIZE, Perm::RW))?;
    let teb64 = WOW64_TEB64;
    let teb32 = WOW64_TEB32;
    wow64::link_teb32(mem, teb64, teb32)?;

    // The 32-bit guest's stack.
    mem.map(exemu_core::Region::new(
        "stack32",
        WOW64_STACK32_BASE,
        WOW64_STACK32_SIZE,
        Perm::RW,
    ))?;
    let stack32_top = WOW64_STACK32_BASE + WOW64_STACK32_SIZE;

    // TEB32: the NT_TIB fields 32-bit code and Wine's 32-bit ntdll read.
    wow64::seed_teb32(mem, teb32, WOW64_PEB32, WOW64_STACK32_BASE, stack32_top)?;
    mem.write_u32(teb32 + wow64::TEB32_CLIENT_ID, 0x1000)?; // UniqueProcess
    mem.write_u32(teb32 + wow64::TEB32_CLIENT_ID + 4, 0x1001)?; // UniqueThread

    // PEB32 — the 32-bit process view. `ImageBaseAddress` is the *guest* image,
    // not the 64-bit ntdll: 32-bit code that walks its own headers must find the
    // PE32 it is running.
    mem.write_u32(WOW64_PEB32 + wow64::peb32::IMAGE_BASE, guest_image_base as u32)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_MAJOR_VERSION, 10)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_MINOR_VERSION, 0)?;
    mem.write_u16(WOW64_PEB32 + wow64::peb32::OS_BUILD_NUMBER, 19043)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_PLATFORM_ID, 2)?; // VER_PLATFORM_WIN32_NT
    mem.write_u32(WOW64_PEB32 + wow64::peb32::SESSION_ID, 1)?;

    // The CPU-reserved area pointer + the WOW64INFO block wow64cpu's process
    // init flags (`or dword [P+4],1` through `TEB64+0x14d0`).
    mem.write_u64(teb64 + WOW64_INFO_TEB_SLOT, WOW64_INFO)?;

    // `ntdll!LdrSystemDllInitBlock` — the block through which the loader tells
    // `wow64.dll` where the 32-bit ntdll and its entry points are. On Windows
    // the kernel fills it; in Wine the *Unix* side of ntdll does, and that is
    // the role exemu plays here. `wow64.dll` reads it in two places that decide
    // the whole boot: its process init takes the ntdll32 base out of it to
    // publish the BOP, and its per-thread init takes `LdrInitializeThunk` out
    // of it to seat the 32-bit thread inside Wine's own loader.
    let block = ntdll64.export("LdrSystemDllInitBlock").ok_or_else(|| {
        EmuError::Os("WoW64 boot: the 64-bit ntdll exports no LdrSystemDllInitBlock".into())
    })?;
    let sysdll = wow64::SystemDllInitBlock {
        ntdll32_base: ntdll32.base,
        ldr_initialize_thunk: ntdll32_export(&ntdll32, "LdrInitializeThunk")?,
        exception_dispatcher: ntdll32_export(&ntdll32, "KiUserExceptionDispatcher")?,
        apc_dispatcher: ntdll32_export(&ntdll32, "KiUserApcDispatcher")?,
        callback_dispatcher: ntdll32_export(&ntdll32, "KiUserCallbackDispatcher")?,
    };
    wow64::publish_system_dll_init_block(mem, block, &sysdll)?;

    Ok(Wow64Boot {
        ntdll32,
        wow64cpu,
        wow64: wow64_img,
        wow64win,
        teb64,
        teb32,
        peb64: WOW64_PEB64,
        peb32: WOW64_PEB32,
        cpu_area: WOW64_CPU_AREA,
        stack32_top,
    })
}

/// `PEB.ProcessHeap` (x64 PEB). Witnessed from both sides of the boundary:
/// Wine's 64-bit `loader_init` stores `RtlCreateHeap`'s result there (ntdll rva
/// 0x547d3, `mov [rdi+0x30], rax` with `rdi = gs:[0x30]->Peb`), and
/// `wow64.dll!Wow64AllocateTemp` reads it back (`mov rcx,[rdx+0x30]`).
pub const PEB64_PROCESS_HEAP: u64 = 0x30;

/// An export of the mapped 32-bit `ntdll`, by name, or a loud error.
fn ntdll32_export(img: &Wow64Image, name: &str) -> Result<u64> {
    img.export(name)
        .ok_or_else(|| EmuError::Os(format!("WoW64 boot: the 32-bit ntdll exports no {name}")))
}

/// `TEB64` slot holding the `WOW64INFO` pointer. `wow64cpu!BTCpuProcessInit`
/// reads `gs:[0x30]` then `[teb+0x14d0]` and sets bit 0 of `[+4]`; `wow64.dll`'s
/// per-thread init writes the same slot, and its `Wow64LdrpInitialize` tests
/// `[ptr+4] & 2`. Distinct from the `0x1488` cpu-area pointer.
pub const WOW64_INFO_TEB_SLOT: u64 = 0x14d0;

/// Where the 64-bit WoW64 bring-up trampoline is assembled (one RWX page above
/// the WoW64 block — it must be executable, so it is its own region).
pub const WOW64_BOOTSTRAP: u64 = WOW64_EXTRA + WOW64_EXTRA_SIZE;

/// Which bring-up the WoW64 boot runs (roadmap W5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Bringup {
    /// **Direct**: exemu performs the WoW64 process's own setup — run
    /// `BTCpuProcessInit`, publish the BOP into the three cells Wine's own
    /// `wow64.dll` fills, then `BTCpuSimulate` straight into the guest's entry
    /// point with no 32-bit loader at all.
    ///
    /// Only the guest's `ntdll` imports are bound (by [`bind_guest_imports`]),
    /// so this is limited to a program that imports nothing else — but every
    /// hop it does take is Wine's, and it is the shortest path that proves the
    /// 32→64 service chain end to end.
    Direct,
    /// **Wine's own loader**: hand control to `wow64!Wow64LdrpInitialize`,
    /// which registers the win32k service table, publishes the BOP itself and
    /// starts the 32-bit thread inside `ntdll32!LdrInitializeThunk` — so Wine's
    /// i386 loader binds the guest's whole import graph. What a real 32-bit
    /// application needs, and the default; see [`seat_wine_loader`].
    #[default]
    WineLoader,
}

/// Seat the initial thread on the **direct** bring-up trampoline (roadmap
/// W5.1): exemu assembles the four steps `wow64.dll` would perform, as ordinary
/// 64-bit guest code, and lets Wine's own DLLs do all of them.
///
/// ```text
///   call wow64cpu!BTCpuProcessInit     ; builds the 32→64 return BOP + selectors
///   call wow64cpu!BTCpuGetBopCode      ; hands out its address
///   mov  [ntdll32!Wow64Transition], eax
///   mov  [ntdll32!__wine_syscall_dispatcher], eax
///   mov  [TEB32+0xC0], eax             ; WOW32Reserved
///   call wow64cpu!BTCpuSimulate        ; enters the 32-bit guest at its entry point
///   hlt
/// ```
///
/// The three stores mirror `wow64.dll` byte for byte: its publish helper (rva
/// 0x4150) and its process init (rva 0x4880/0x48b7) both do
/// `call [BTCpuGetBopCode]; mov dword ptr [rbx], eax`, and its per-thread init
/// (rva 0x5550) does the same into `TEB32+0xC0`. The **32-bit store width** is
/// why every one of those cells — and therefore `wow64cpu` itself — must live
/// below 4 GiB.
pub fn seat_direct(
    cpu: &mut exemu_cpu::Interpreter,
    mem: &mut VirtualMemory,
    boot: &Wow64Boot,
    guest_entry: u64,
    stack64_top: u64,
) -> Result<()> {
    let sym = |img: &Wow64Image, n: &str| -> Result<u64> {
        img.export(n)
            .ok_or_else(|| EmuError::Os(format!("WoW64 boot: wow64cpu.dll does not export {n}")))
    };
    let process_init = sym(&boot.wow64cpu, "BTCpuProcessInit")?;
    let get_bop = sym(&boot.wow64cpu, "BTCpuGetBopCode")?;
    let simulate = sym(&boot.wow64cpu, "BTCpuSimulate")?;
    let slots = wow64::BopSlots {
        transition: boot
            .ntdll32
            .export("Wow64Transition")
            .ok_or_else(|| EmuError::Os("WoW64 boot: 32-bit ntdll exports no Wow64Transition".into()))?,
        syscall_dispatcher: boot.ntdll32.export("__wine_syscall_dispatcher").ok_or_else(|| {
            EmuError::Os("WoW64 boot: 32-bit ntdll exports no __wine_syscall_dispatcher".into())
        })?,
        wow32_reserved: boot.teb32 + wow64::TEB32_WOW32_RESERVED,
    };

    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20 (Win64 shadow space)
    let call_abs = |code: &mut Vec<u8>, target: u64| {
        code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, target
        code.extend_from_slice(&target.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax
    };
    call_abs(&mut code, process_init);
    call_abs(&mut code, get_bop); // rax = the BOP
    for slot in [slots.transition, slots.syscall_dispatcher, slots.wow32_reserved] {
        code.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, slot
        code.extend_from_slice(&slot.to_le_bytes());
        code.extend_from_slice(&[0x89, 0x01]); // mov dword ptr [rcx], eax
    }
    call_abs(&mut code, simulate);
    code.push(0xF4); // hlt — BTCpuSimulate is not expected to return

    mem.map(exemu_core::Region::new("wow64_bootstrap", WOW64_BOOTSTRAP, 0x1000, Perm::RWX))?;
    mem.write(WOW64_BOOTSTRAP, &code)?;

    // The 32-bit thread starts *at the guest's entry point*: no loader runs, so
    // there is no `RtlUserThreadStart` frame to build.
    let esp32 = (boot.stack32_top - 0x100) & !0xf;
    let start = wow64::Start32 { eip: guest_entry as u32, esp: esp32 as u32, eax: 0, ebx: 0 };
    wow64::init_cpu_area(mem, boot.teb64, boot.cpu_area, start)?;
    seat_cpu(cpu, boot, stack64_top);
    Ok(())
}

/// Common CPU seating for both bring-ups.
fn seat_cpu(cpu: &mut exemu_cpu::Interpreter, boot: &Wow64Boot, stack64_top: u64) {
    let s = cpu.state_mut();
    s.rip = WOW64_BOOTSTRAP;
    s.set_rsp((stack64_top - 0x100) & !0xf);
    s.gs_base = boot.teb64; // 64-bit code reads its TEB through gs:
    s.fs_base = boot.teb32; // 32-bit guest code reads its TEB through fs:
    cpu.set_bits(exemu_cpu::Bits::B64); // the bring-up runs in long mode
}

/// Seat the initial thread on the **Wine-loader** bring-up (roadmap W5.7).
///
/// The trampoline hands straight to Wine, and everything it does is Wine's:
///
/// ```text
///   sub  rsp, 0x38
///   call ntdll!RtlCreateHeap           ; → PEB64.ProcessHeap
///   call wow64!Wow64LdrpInitialize     ; Wine's own WoW64 process/thread start
///   hlt                                ; it never returns
/// ```
///
/// `Wow64LdrpInitialize` (rva 0x2ce0) is exactly three calls:
///
/// ```text
///   RtlRunOnceExecuteOnce(&once, process_init)   ; rva 0x4440
///   thread_init()                                ; rva 0x5550
///   for (;;) pBTCpuSimulate();                   ; rva 0x1558
/// ```
///
/// and running it is what closes the two gaps exemu used to paper over:
///
/// * **process init** loads `wow64cpu.dll` and `wow64win.dll`, resolves their
///   `BTCpu*` exports, `movdqu`-copies the win32k service descriptor out of
///   `wow64win!sdwhwin32` into its own **table 1** (rva 0x160a0), and publishes
///   `BTCpuGetBopCode()` into `ntdll32!Wow64Transition`,
///   `ntdll32!__wine_syscall_dispatcher` and `ntdll32!__wine_unix_call_dispatcher`.
///   exemu used to hand-assemble a subset of those stores and could not do the
///   descriptor copy at all.
/// * **thread init** writes the BOP to `TEB32+0xC0`, publishes the `WOW64INFO`
///   at `TEB64+0x14d0`, then reads this thread's 32-bit context, copies it onto
///   the 32-bit stack and re-seats `Eip` on `LdrSystemDllInitBlock[0x18]` —
///   **`ntdll32!LdrInitializeThunk`** — with the copied `CONTEXT` as its stack
///   argument. So the first 32-bit code that runs is Wine's own loader.
///
/// exemu's remaining job is the one a kernel does: seed the CPU-reserved area
/// with the thread's start state ([`wow64::Start32`], recovered from
/// `ntdll32!RtlUserThreadStart`) and enter.
pub fn seat_wine_loader(
    cpu: &mut exemu_cpu::Interpreter,
    mem: &mut VirtualMemory,
    boot: &Wow64Boot,
    ntdll64: &Wow64Image,
    peb64: u64,
    guest_entry: u64,
    stack64_top: u64,
) -> Result<()> {
    let ldrp_init = boot
        .wow64
        .export("Wow64LdrpInitialize")
        .ok_or_else(|| EmuError::Os("WoW64 boot: wow64.dll does not export Wow64LdrpInitialize".into()))?;
    let create_heap = ntdll64
        .export("RtlCreateHeap")
        .ok_or_else(|| EmuError::Os("WoW64 boot: the 64-bit ntdll exports no RtlCreateHeap".into()))?;

    // Assemble the trampoline.
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]); // sub rsp, 0x38 (shadow space + 2 stack args)
    // --- PEB64.ProcessHeap ------------------------------------------------
    // `RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL)` — Wine's own heap
    // implementation — published at `PEB64 + 0x30`. This is the one piece of
    // 64-bit `loader_init` the WoW64 boot has to stand in for: `wow64.dll`
    // allocates every marshalling buffer through `Wow64AllocateTemp` (rva
    // 0x2730), which is `mov rbx,gs:[0x30]; mov rdx,[rbx+0x60]; mov
    // rcx,[rdx+0x30]; call RtlAllocateHeap` — i.e. straight out of
    // `PEB.ProcessHeap`. A null heap there faults inside `RtlAllocateHeap`.
    code.extend_from_slice(&[0xB9, 0x02, 0x00, 0x00, 0x00]); // mov ecx, 2 (HEAP_GROWABLE)
    code.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx      (Addr)
    code.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (TotalSize)
    code.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (CommitSize)
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]); // mov [rsp+0x20], 0 (Lock)
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]); // mov [rsp+0x28], 0 (Params)
    code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, RtlCreateHeap
    code.extend_from_slice(&create_heap.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax
    code.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, &PEB64.ProcessHeap
    code.extend_from_slice(&(peb64 + PEB64_PROCESS_HEAP).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x01]); // mov [rcx], rax
    // --- Wine's WoW64 process/thread start --------------------------------
    code.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx  (its CONTEXT arg is unused: it `lea`s over rcx)
    code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, Wow64LdrpInitialize
    code.extend_from_slice(&ldrp_init.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax
    code.push(0xF4); // hlt — Wow64LdrpInitialize is not expected to return

    mem.map(exemu_core::Region::new("wow64_bootstrap", WOW64_BOOTSTRAP, 0x1000, Perm::RWX))?;
    mem.write(WOW64_BOOTSTRAP, &code)?;

    // The WoW64 CPU-reserved area: `TEB64+0x1488` → a `WOW64_CONTEXT` seeded
    // with the fresh thread's 32-bit start state. This is the record
    // `BTCpuSimulate` loads the 32-bit register file from, the one
    // `NtQueryInformationThread(ThreadWow64Context)` answers with (which is how
    // `BTCpuProcessInit` learns the 32-bit `SegCs`/`SegSs` it caches), and the
    // one `wow64.dll`'s per-thread init reads back through `BTCpuGetContext`,
    // copies to the 32-bit stack and hands to `LdrInitializeThunk`.
    let esp32 = (boot.stack32_top - 0x100) & !0xf;
    let start = wow64::Start32 {
        eip: ntdll32_export(&boot.ntdll32, "RtlUserThreadStart")? as u32,
        esp: esp32 as u32,
        eax: guest_entry as u32, // RtlUserThreadStart: arg0 = EntryPoint, from EAX
        ebx: 0,                  //                     arg1 = Arg,        from EBX
    };
    wow64::init_cpu_area(mem, boot.teb64, boot.cpu_area, start)?;
    seat_cpu(cpu, boot, stack64_top);
    Ok(())
}

/// Bind a 32-bit guest image's imports to the WoW64 module set.
///
/// A 32-bit guest's `ntdll.dll` is the **i386** one — resolving it against the
/// 64-bit ntdll would write a 64-bit code address into a 4-byte IAT slot, which
/// is exactly the silent corruption this phase exists to prevent. Unresolved
/// imports are reported by name rather than left null.
pub fn bind_guest_imports(
    mem: &mut VirtualMemory,
    guest_base: u64,
    imports: &[exemu_core::Import],
    boot: &Wow64Boot,
) -> Result<(usize, Vec<String>)> {
    let mut by_dll: HashMap<&str, &Wow64Image> = HashMap::new();
    by_dll.insert("ntdll.dll", &boot.ntdll32);
    let mut bound = 0usize;
    let mut missing = Vec::new();
    for imp in imports {
        let exemu_core::ImportSymbol::Named(name) = &imp.symbol else {
            missing.push(format!("{}#<ordinal>", imp.dll));
            continue;
        };
        match by_dll.get(imp.dll.as_str()).and_then(|m| m.export(name)) {
            Some(addr) if addr <= u32::MAX as u64 => {
                mem.write_u32(guest_base + imp.iat_rva as u64, addr as u32)?;
                bound += 1;
            }
            _ => missing.push(format!("{}!{name}", imp.dll)),
        }
    }
    Ok((bound, missing))
}
