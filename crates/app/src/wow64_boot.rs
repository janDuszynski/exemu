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
//! What this module does *not* do: it does not run Wine's own
//! `Wow64LdrpInitialize`. exemu constructs the process, exactly as the Windows
//! kernel + `wow64.dll` would, and then hands control to Wine's binary
//! translator. Everything downstream of that hand-off — the mode switch, the
//! service dispatch and all 32↔64 argument marshalling — is Wine's own code.

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
/// Bytes covered by that block.
pub const WOW64_EXTRA_SIZE: u64 = 0x8000;
/// The 32-bit TEB (`fs:`). `TEB64.WowTebOffset` is the delta to here.
pub const WOW64_TEB32: u64 = WOW64_EXTRA;
/// `PEB32` (`fs:[0x30]`).
pub const WOW64_PEB32: u64 = WOW64_EXTRA + 0x2000;
/// The WoW64 CPU-reserved area (`TEB64+0x1488` points here) holding the
/// `WOW64_CONTEXT` that `BTCpuSimulate` loads the 32-bit registers from.
pub const WOW64_CPU_AREA: u64 = WOW64_EXTRA + 0x3000;
/// The `WOW64INFO` block `BTCpuProcessInit` flags through `TEB64+0x14d0`.
pub const WOW64_INFO: u64 = WOW64_EXTRA + 0x4000;

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
    mem.write_u32(teb32 + wow64::TEB32_EXCEPTION_LIST, u32::MAX)?;
    mem.write_u32(teb32 + wow64::TEB32_STACK_BASE, stack32_top as u32)?;
    mem.write_u32(teb32 + wow64::TEB32_STACK_LIMIT, WOW64_STACK32_BASE as u32)?;
    mem.write_u32(teb32 + wow64::TEB32_PEB, WOW64_PEB32 as u32)?;
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

/// `TEB64` slot holding the `WOW64INFO` pointer. `wow64cpu!BTCpuProcessInit`
/// reads `gs:[0x30]` then `[teb+0x14d0]` and sets bit 0 of `[+4]`; `wow64.dll`'s
/// per-thread init writes the same slot, and its `Wow64LdrpInitialize` tests
/// `[ptr+4] & 2`. Distinct from the `0x1488` cpu-area pointer.
pub const WOW64_INFO_TEB_SLOT: u64 = 0x14d0;

/// Where the 64-bit WoW64 bring-up trampoline is assembled (one RWX page above
/// the WoW64 block — it must be executable, so it is its own region).
pub const WOW64_BOOTSTRAP: u64 = WOW64_EXTRA + WOW64_EXTRA_SIZE;

/// Seat the initial thread on the WoW64 bring-up trampoline (roadmap W5.1).
///
/// exemu does **not** re-implement `Wow64LdrpInitialize`; it assembles the same
/// four steps Wine's `wow64.dll` performs, as ordinary 64-bit guest code, and
/// lets Wine's own DLLs do all of them:
///
/// ```text
///   call wow64cpu!BTCpuProcessInit     ; builds the 32→64 return BOP + selectors
///   call wow64cpu!BTCpuGetBopCode      ; hands out its address
///   mov  [ntdll32!Wow64Transition], eax
///   mov  [ntdll32!__wine_syscall_dispatcher], eax
///   mov  [TEB32+0xC0], eax             ; WOW32Reserved
///   call wow64cpu!BTCpuSimulate        ; enters the 32-bit guest
///   hlt
/// ```
///
/// The three stores mirror `wow64.dll` byte for byte: its publish helper (rva
/// 0x4150) and its process init (rva 0x4880/0x48b7) both do
/// `call [BTCpuGetBopCode]; mov dword ptr [rbx], eax`, and its per-thread init
/// (rva 0x5550) does the same into `TEB32+0xC0`. The **32-bit store width** is
/// why every one of those cells — and therefore `wow64cpu` itself — must live
/// below 4 GiB.
///
/// The addresses are resolved by name from the real export tables; nothing about
/// the BOP's shape, the selectors or the service dispatch is supplied by exemu.
pub fn seat(
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

    // Assemble the trampoline.
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20   (Win64 shadow space)
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

    // The WoW64 CPU-reserved area: `TEB64+0x1488` → a `WOW64_CONTEXT` seeded
    // with the 32-bit guest's entry point, stack and flat selectors. This is the
    // record `BTCpuSimulate` loads the 32-bit register file from, and the one
    // `NtQueryInformationThread(ThreadWow64Context)` answers with — which is how
    // `BTCpuProcessInit` learns the 32-bit `SegCs`/`SegSs` it caches.
    let esp32 = (boot.stack32_top - 0x100) & !0xf;
    wow64::init_cpu_area(mem, boot.teb64, boot.cpu_area, guest_entry as u32, esp32 as u32)?;

    let s = cpu.state_mut();
    s.rip = WOW64_BOOTSTRAP;
    s.set_rsp((stack64_top - 0x100) & !0xf);
    s.gs_base = boot.teb64; // 64-bit code reads its TEB through gs:
    s.fs_base = boot.teb32; // 32-bit guest code reads its TEB through fs:
    cpu.set_bits(exemu_cpu::Bits::B64); // the bring-up runs in long mode
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
