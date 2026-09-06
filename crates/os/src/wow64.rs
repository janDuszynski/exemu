//! WoW64 process-model support (roadmap W5): the CPU-reserved `WOW64_CONTEXT`
//! that `wow64cpu!BTCpuSimulate` reads to run a 32-bit guest on the 64-bit Wine
//! PE set.
//!
//! In Wine's new-WoW64 model, exemu services only the 64-bit DLL set; a 32-bit
//! guest runs via `wow64cpu.dll`, whose `BTCpuSimulate` reads the 32-bit register
//! state from a `WOW64_CONTEXT` in the thread's **CPU-reserved area** (a pointer
//! at TEB+0x1488), loads those registers, and far-jumps into 32-bit mode. The
//! offsets and selectors below were recovered from the pinned `wow64cpu.dll`
//! disassembly (see `knowledge/w5-wow64-design.know`); the CPU-side mode switch
//! the far jump performs is `crates/cpu` (Group-5 `/5` + `iretq`).
//!
//! This module is the process-model half: given a 32-bit guest's entry point and
//! stack, [`init_cpu_area`] lays out the area exactly as `BTCpuSimulate` expects.
//! It is verified both by [`tests`] (layout) and end to end by the real
//! `BTCpuSimulate` in `crates/app/tests/dll_smoke.rs`.

use std::collections::HashMap;

use exemu_core::{EmuError, Memory, Perm, Result};

/// Offset of the CPU-reserved-area pointer within the 64-bit TEB
/// (`WOW64_CPURESERVED`). `BTCpuSimulate` reads it as `gs:[0x30]` → `[teb+0x1488]`.
pub const TEB_CPU_AREA_PTR_OFF: u64 = 0x1488;

/// Bytes of machine-type header preceding the `WOW64_CONTEXT` in the CPU area;
/// `BTCpuSimulate` does `lea r13,[area+4]` to reach the context. Header bit 0 is
/// the resume flag (`btr [r13-4],0`): clear → the fast far-jmp forward path.
pub const CPU_AREA_HEADER_LEN: u64 = 4;

/// The header's "reload the whole 32-bit register file" bit.
///
/// `BTCpuSimulate` opens with `btr dword ptr [area], 0` (rva 0x1189) and
/// branches on the *old* value: clear → the fast forward path (rva 0x116d,
/// which restores only `Edi/Esi/Ebx/Ebp` plus `Eip`/`SegCs`/`Esp` and far-jumps),
/// set → the full restore (rva 0x11b3, which also loads `Eax/Ecx/Edx`, the
/// segment registers and `EFlags`, and enters via `iretq`). `btr` clears it, so
/// each arming is consumed by exactly one simulate.
pub const CPU_AREA_RELOAD_BIT: u32 = 1;

// --- WOW64_CONTEXT (== the 32-bit CONTEXT) field offsets --------------------
/// `Edi`.
pub const CTX_EDI: u64 = 0x9c;
/// `Esi`.
pub const CTX_ESI: u64 = 0xa0;
/// `Ebx`.
pub const CTX_EBX: u64 = 0xa4;
/// `Edx`.
pub const CTX_EDX: u64 = 0xa8;
/// `Ecx`.
pub const CTX_ECX: u64 = 0xac;
/// `Eax`.
pub const CTX_EAX: u64 = 0xb0;
/// `Ebp`.
pub const CTX_EBP: u64 = 0xb4;
/// `Eip` — the 32-bit instruction pointer the far jump targets.
pub const CTX_EIP: u64 = 0xb8;
/// `SegCs` — the code selector; `0x23` puts the far jump into 32-bit mode.
pub const CTX_SEGCS: u64 = 0xbc;
/// `EFlags`.
pub const CTX_EFLAGS: u64 = 0xc0;
/// `Esp` — the 32-bit stack pointer swapped in before the far jump.
pub const CTX_ESP: u64 = 0xc4;
/// `SegSs` — the stack selector.
pub const CTX_SEGSS: u64 = 0xc8;

/// The flat WoW64 32-bit code selector (GDT index 4). CS = this → 32-bit compat.
pub const SEL_CS32: u32 = 0x23;
/// The flat WoW64 32-bit data/stack selector (GDT index 5).
pub const SEL_SS32: u32 = 0x2b;
/// The flat WoW64 **64-bit** code selector (GDT index 6). CS = this → long mode.
/// This is the selector `wow64cpu!BTCpuProcessInit` bakes into the return BOP's
/// far pointer, taken from whatever `RtlCaptureContext` reports as the live `CS`
/// — so it is also what exemu's CPU must report for `mov r/m16, cs` in 64-bit
/// mode, or the reverse transition would land in the wrong mode.
pub const SEL_CS64: u32 = 0x33;

// --- The 64-bit TEB → 32-bit TEB link (recovered from the pinned binaries) ---

/// `TEB64.WowTebOffset` — a **signed 32-bit** byte offset from the 64-bit TEB to
/// this thread's 32-bit TEB; zero means "not a WoW64 thread".
///
/// Recovered, not assumed. Three pinned binaries agree on the shape:
///
/// * `wow64.dll` @ rva 0x29d4: `mov rax, gs:[0x30]; movsxd rdx, dword
///   [rax+0x180c]; lea rsi, [rax+rdx]` — TEB32 = TEB64 + (i32)WowTebOffset.
/// * `wow64.dll` @ rva 0x5563 (the per-thread init): the same `movsxd`, then
///   `mov dword [rax+rdx+0xc0], ecx` — i.e. a store into **TEB32**+0xC0.
/// * `ntdll.dll!RtlWow64GetCurrentMachine` @ rva 0x3a7f3: `mov edx,
///   [rax+0x180c]; test edx,edx; jne …` — a zero field means "not WoW64".
///
/// `wow64win.dll` reads the same field at 23 sites; it is the only TEB
/// displacement it uses at all.
pub const TEB64_WOW_TEB_OFFSET: u64 = 0x180c;

/// `TEB32.WOW32Reserved` — the second cell Wine's WoW64 fills with the BOP.
///
/// Recovered from `wow64.dll`'s per-thread init (rva 0x5550): it calls
/// `BTCpuGetBopCode`, then stores the result at `TEB32 + 0xC0`. That is exactly
/// the cell Wine's **32-bit** `ntdll` stub for `NtQueryInformationProcess` reads
/// (`mov eax,0x19; call dword ptr fs:[0xc0]`), the one `Nt*` stub in the pinned
/// 32-bit ntdll that does not go through `__wine_syscall_dispatcher`.
pub const TEB32_WOW32_RESERVED: u64 = 0xc0;

/// `ThreadWow64Context` — the `THREADINFOCLASS` whose
/// `NtQueryInformationThread` answer is a WoW64 thread's 32-bit `CONTEXT`.
///
/// Recovered from the pinned **64-bit** `ntdll.dll`: `RtlWow64GetThreadContext`
/// (rva 0x3a960) is nothing but `mov r9d,0x2cc; mov r8,rdx; mov edx,0x1d; call
/// NtQueryInformationThread`. Both the class and the buffer size below come out
/// of those bytes.
pub const THREAD_WOW64_CONTEXT: u32 = 0x1d;
/// `sizeof(WOW64_CONTEXT)` (= the 32-bit `CONTEXT`), from the same stub.
pub const WOW64_CONTEXT_SIZE: u64 = 0x2cc;

// --- `ntdll!LdrSystemDllInitBlock` — the kernel→wow64.dll hand-off block -----

/// `PS_SYSTEM_DLL_INIT_BLOCK.Wow64SharedInformation[0]` — the **32-bit**
/// `ntdll!LdrInitializeThunk`.
///
/// Recovered from `wow64.dll`'s per-thread init (rva 0x570e): `mov rax,
/// [LdrSystemDllInitBlock]; mov rax,[rax+0x18]; mov [ctx+Eip], eax` — i.e. the
/// value it seats a fresh WoW64 thread's 32-bit `Eip` on. That is what makes
/// the 32-bit guest start inside **Wine's own loader** rather than at the
/// program's entry point.
pub const SYSDLL_LDR_INITIALIZE_THUNK: u64 = 0x18;
/// `Wow64SharedInformation[1]` — 32-bit `KiUserExceptionDispatcher`.
/// `wow64.dll` rva 0x3838 loads `[block+0x20]` and stores it as the 32-bit
/// `Eip` of the context it builds for an exception (`ContextFlags` 0x10001 is
/// written two instructions later).
pub const SYSDLL_KI_USER_EXCEPTION_DISPATCHER: u64 = 0x20;
/// `Wow64SharedInformation[2]` — 32-bit `KiUserApcDispatcher`
/// (`wow64.dll!Wow64ApcRoutine`, rva 0x28dc / 0x298a: `[block+0x28]` → ctx Eip).
pub const SYSDLL_KI_USER_APC_DISPATCHER: u64 = 0x28;
/// `Wow64SharedInformation[3]` — 32-bit `KiUserCallbackDispatcher`
/// (`wow64.dll!Wow64KiUserCallbackDispatcher`, rva 0x2b08: `[block+0x30]`).
pub const SYSDLL_KI_USER_CALLBACK_DISPATCHER: u64 = 0x30;
/// The **32-bit ntdll's image base**. `wow64.dll`'s process init (rva 0x4879)
/// does `mov rcx,[block+0x48]` and hands it straight to
/// `RtlFindExportedRoutineByName("Wow64Transition")` — so this field is a
/// module handle, not a routine.
pub const SYSDLL_NTDLL32_BASE: u64 = 0x48;
/// Bytes of the block exemu fills (through the last field above, rounded up).
pub const SYSDLL_BLOCK_SIZE: u64 = 0x50;

/// The 32-bit `ntdll` entry points `LdrSystemDllInitBlock` publishes, resolved
/// by name by the caller from the mapped i386 image.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDllInitBlock {
    /// Image base of the 32-bit `ntdll.dll`.
    pub ntdll32_base: u64,
    /// `ntdll32!LdrInitializeThunk`.
    pub ldr_initialize_thunk: u64,
    /// `ntdll32!KiUserExceptionDispatcher`.
    pub exception_dispatcher: u64,
    /// `ntdll32!KiUserApcDispatcher`.
    pub apc_dispatcher: u64,
    /// `ntdll32!KiUserCallbackDispatcher`.
    pub callback_dispatcher: u64,
}

/// Fill `ntdll!LdrSystemDllInitBlock` — the block through which the loader
/// tells `wow64.dll` where the 32-bit `ntdll` and its entry points are
/// (roadmap W5.6).
///
/// On Windows this is the kernel's job; in Wine it is the **Unix side** of
/// ntdll, which exemu stands in for. Every consumer is `wow64.dll`, and every
/// offset above was read out of `wow64.dll`'s own use sites — so a drifted
/// field fails `crates/app/tests/wow64_abi.rs` rather than silently seating a
/// 32-bit thread on a null `Eip`.
///
/// All five values must be 32-bit addressable: `wow64.dll` narrows the
/// dispatcher entries into a 32-bit `CONTEXT` (`mov [ctx+Eip], eax`), so a
/// higher address would be truncated rather than rejected.
pub fn publish_system_dll_init_block(mem: &mut dyn Memory, block: u64, v: &SystemDllInitBlock) -> Result<()> {
    for (name, addr) in [
        ("ntdll32 base", v.ntdll32_base),
        ("LdrInitializeThunk", v.ldr_initialize_thunk),
        ("KiUserExceptionDispatcher", v.exception_dispatcher),
        ("KiUserApcDispatcher", v.apc_dispatcher),
        ("KiUserCallbackDispatcher", v.callback_dispatcher),
    ] {
        if addr > u32::MAX as u64 {
            return Err(EmuError::Os(format!(
                "LdrSystemDllInitBlock: 32-bit ntdll {name} at {addr:#x} is above 4 GiB — \
                 wow64.dll narrows it into a 32-bit CONTEXT"
            )));
        }
    }
    mem.write_u32(block, SYSDLL_BLOCK_SIZE as u32)?; // Size
    mem.write_u64(block + SYSDLL_LDR_INITIALIZE_THUNK, v.ldr_initialize_thunk)?;
    mem.write_u64(block + SYSDLL_KI_USER_EXCEPTION_DISPATCHER, v.exception_dispatcher)?;
    mem.write_u64(block + SYSDLL_KI_USER_APC_DISPATCHER, v.apc_dispatcher)?;
    mem.write_u64(block + SYSDLL_KI_USER_CALLBACK_DISPATCHER, v.callback_dispatcher)?;
    mem.write_u64(block + SYSDLL_NTDLL32_BASE, v.ntdll32_base)?;
    Ok(())
}

// --- The 64-bit ntdll's WoW64 exception hook --------------------------------

/// Publish `wow64.dll!Wow64PrepareForException` into the pointer cell the
/// **64-bit** `ntdll!KiUserExceptionDispatcher` calls it through, and return the
/// cell's address (roadmap W5.9).
///
/// **This is the single seam that makes a 32-bit guest's exceptions work**, and
/// it is easy to miss because nothing about it is 32-bit. The 64-bit dispatcher
/// opens with
///
/// ```text
///   cld
///   mov  rax, qword ptr [rip+disp32]      ; the cell this function fills
///   test rax, rax
///   je   .no_wow64
///   mov  rdx, rsp                         ; ContextRecord
///   lea  rcx, [rsp+0x4F0]                 ; ExceptionRecord
///   call rax                              ; Wow64PrepareForException(rec, ctx)
/// .no_wow64:
///   …RtlDispatchException…
/// ```
///
/// so a **zero** cell is not an error: the dispatcher simply skips the hook and
/// runs the ordinary 64-bit dispatch over a context whose `Rip` is a 32-bit
/// address, which finds no handler and ends in `NtRaiseException`. Wine fills
/// the cell in `ntdll`'s own `init_wow64` (rva 0x522b3, from
/// `RtlFindExportedRoutineByName(wow64, "Wow64PrepareForException")` — the
/// second of exactly two entry points it resolves), which runs inside the
/// 64-bit `loader_init` that the WoW64 boot deliberately does not run. So exemu
/// publishes it, exactly as it publishes `LdrSystemDllInitBlock`.
///
/// The cell address is **recovered, not hardcoded**: it is decoded from the
/// dispatcher's own `mov rax, [rip+disp32]`, anchored on the exported
/// `KiUserExceptionDispatcher`. A drifted prologue fails loudly here.
pub fn publish_wow64_exception_hook(mem: &mut dyn Memory, ntdll64_base: u64, prepare: u64) -> Result<u64> {
    let entry = ntdll64_base + crate::RVA_KI_USER_EXCEPTION_DISPATCHER;
    let mut b = [0u8; 8];
    mem.read(entry, &mut b)?;
    if b[0] != 0xFC || b[1..4] != [0x48, 0x8B, 0x05] {
        return Err(EmuError::Os(format!(
            "WoW64 boot: the 64-bit KiUserExceptionDispatcher at {entry:#x} does not open with \
             `cld; mov rax,[rip+disp32]` (saw {b:02x?}) — its WoW64 hook cell cannot be located"
        )));
    }
    let disp = i32::from_le_bytes(b[4..8].try_into().unwrap());
    let slot = (entry + 8).wrapping_add(disp as i64 as u64);
    mem.write_u64(slot, prepare)?;
    Ok(slot)
}

// --- The two NT queries wow64.dll's process init issues ---------------------

/// `ProcessWow64Information` — the `PROCESSINFOCLASS` whose answer is a
/// pointer to the process's **32-bit PEB**.
///
/// Recovered from `wow64.dll`'s process init (rva 0x44e0): `mov edx,0x1a; mov
/// r9d,8; lea r8,[rsp+0x50]; mov rcx,-1; call [NtQueryInformationProcess]`,
/// whose result it immediately treats as `PEB32` (`lea rcx,[rdx+0x480]` — the
/// `WOW64INFO` that follows the PEB32 — and stores that at `TEB64+0x14d0`).
pub const PROCESS_WOW64_INFORMATION: u32 = 0x1a;

/// `SystemSupportedProcessorArchitectures2` — the `SYSTEM_INFORMATION_CLASS`
/// behind `ntdll!RtlWow64GetProcessMachines`.
///
/// Recovered from that routine's own bytes (64-bit ntdll rva 0x3a851): `mov
/// ecx,0xb5` into `NtQuerySystemInformationEx`, with the process handle passed
/// as an 8-byte *input* buffer and a 0x20-byte output buffer.
pub const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES: u32 = 0xb5;

/// One `SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION` entry: a 32-bit
/// word whose low 16 bits are the machine and whose next bits are flags. The
/// decode is recovered from `RtlWow64GetProcessMachines`' loop, which reads
/// `word [entry]` as the machine and `byte [entry+2]` as the flag byte,
/// stopping at a zero machine.
pub mod arch_entry {
    /// `KernelMode` (bit 16 overall, bit 0 of the flag byte).
    pub const KERNEL_MODE: u32 = 1 << 16;
    /// `UserMode`.
    pub const USER_MODE: u32 = 1 << 17;
    /// `Native` — `RtlWow64GetProcessMachines` reports this entry's machine as
    /// the *native* one (`test cl,4` → `mov r8d,edx`).
    pub const NATIVE: u32 = 1 << 18;
    /// `Process` — …and this one as the process's *current* machine
    /// (`and ecx,8` → `cmovne r10d,edx`).
    pub const PROCESS: u32 = 1 << 19;

    /// Build one entry.
    pub const fn entry(machine: u16, flags: u32) -> u32 {
        machine as u32 | flags
    }
}

/// `IMAGE_FILE_MACHINE_I386` — the machine a WoW64 guest reports as *current*.
/// `wow64.dll` compares its recovered current machine against `0x14c` at three
/// sites (rva 0x4498, 0x458e, 0x559d) to select the i386 personality.
pub const MACHINE_I386: u16 = 0x014c;
/// `IMAGE_FILE_MACHINE_AMD64` — the native machine of an exemu WoW64 process.
pub const MACHINE_AMD64: u16 = 0x8664;

/// `TEB32.NtTib.Self` (public winternl 32-bit TEB layout).
pub const TEB32_SELF: u64 = 0x18;
/// `TEB32.ProcessEnvironmentBlock` — where 32-bit guest code finds its PEB32
/// (`fs:[0x30]`).
pub const TEB32_PEB: u64 = 0x30;
/// `TEB32.NtTib.StackBase` / `.StackLimit` / `.ExceptionList`.
pub const TEB32_STACK_BASE: u64 = 0x04;
/// `TEB32.NtTib.StackLimit`.
pub const TEB32_STACK_LIMIT: u64 = 0x08;
/// `TEB32.NtTib.ExceptionList`.
pub const TEB32_EXCEPTION_LIST: u64 = 0x00;
/// `TEB32.ClientId.UniqueProcess` / `.UniqueThread`.
pub const TEB32_CLIENT_ID: u64 = 0x20;
/// `TEB32.ActivationContextStackPointer`. Wine's i386 ntdll dereferences it
/// two levels deep in its SxS lookup — `RtlFindActivationContextSectionString`
/// (rva 0x22481) does `mov eax, fs:[0x18]; mov eax,[eax+0x1a8]; mov eax,[eax]`
/// — so it must point at a real, empty `ACTIVATION_CONTEXT_STACK`, exactly like
/// the 64-bit `+0x2c8` this crate already seeds.
pub const TEB32_ACTIVATION_CONTEXT_STACK_POINTER: u64 = 0x1a8;
/// Where the per-thread, inline 32-bit `ACTIVATION_CONTEXT_STACK` is laid down:
/// past the end of the 32-bit `TEB` struct but inside its 0x2000-byte region,
/// so it needs no separate allocation.
pub const TEB32_ACTIVATION_CONTEXT_STACK: u64 = 0x1800;

/// Seed the 32-bit `NT_TIB` + the fields Wine's i386 `ntdll` dereferences off
/// `fs:` before its loader has run (roadmap W5.7).
///
/// The `ACTIVATION_CONTEXT_STACK` is left in its empty initial state — the
/// region is zero-mapped, so `ActiveFrame`/`Flags`/`StackId` already read 0 —
/// with only the `FrameListCache` `LIST_ENTRY` made self-referential, matching
/// a live process's initial thread.
pub fn seed_teb32(mem: &mut dyn Memory, teb32: u64, peb32: u64, stack_base: u64, stack_top: u64) -> Result<()> {
    mem.write_u32(teb32 + TEB32_EXCEPTION_LIST, u32::MAX)?;
    mem.write_u32(teb32 + TEB32_STACK_BASE, stack_top as u32)?;
    mem.write_u32(teb32 + TEB32_STACK_LIMIT, stack_base as u32)?;
    mem.write_u32(teb32 + TEB32_SELF, teb32 as u32)?;
    mem.write_u32(teb32 + TEB32_PEB, peb32 as u32)?;
    let actx = teb32 + TEB32_ACTIVATION_CONTEXT_STACK;
    mem.write_u32(teb32 + TEB32_ACTIVATION_CONTEXT_STACK_POINTER, actx as u32)?;
    mem.write_u32(actx + 0x04, actx as u32 + 0x04)?; // FrameListCache.Flink → self
    mem.write_u32(actx + 0x08, actx as u32 + 0x04)?; // FrameListCache.Blink → self
    Ok(())
}

/// `PEB32` field offsets (public winternl 32-bit PEB layout).
pub mod peb32 {
    /// `BeingDebugged` (byte @ +2).
    pub const BEING_DEBUGGED: u64 = 0x02;
    /// `ImageBaseAddress`.
    pub const IMAGE_BASE: u64 = 0x08;
    /// `Ldr` (`PEB_LDR_DATA*`).
    pub const LDR: u64 = 0x0c;
    /// `ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS*`).
    pub const PROCESS_PARAMETERS: u64 = 0x10;
    /// `NtGlobalFlag`.
    pub const NT_GLOBAL_FLAG: u64 = 0x68;
    /// `OSMajorVersion` / `OSMinorVersion` / `OSBuildNumber` / `OSPlatformId`.
    pub const OS_MAJOR_VERSION: u64 = 0xa4;
    /// `OSMinorVersion`.
    pub const OS_MINOR_VERSION: u64 = 0xa8;
    /// `OSBuildNumber` (u16).
    pub const OS_BUILD_NUMBER: u64 = 0xac;
    /// `OSPlatformId`.
    pub const OS_PLATFORM_ID: u64 = 0xb0;
    /// `SessionId`.
    pub const SESSION_ID: u64 = 0x1d4;
}

/// Initial `EFlags` for a fresh 32-bit thread (only the reserved bit 1 set).
const EFLAGS_INIT: u32 = 0x0000_0202;

/// The register state a fresh 32-bit thread starts in, in the shape Wine's
/// **32-bit** `ntdll` expects (roadmap W5.6).
///
/// Recovered from `ntdll32!RtlUserThreadStart` (rva 0xe1d0), which is three
/// instructions long:
///
/// ```text
///   mov [esp+8], ebx      ; arg1 = Arg
///   mov [esp+4], eax      ; arg0 = EntryPoint
///   jmp  <thread start>
/// ```
///
/// — i.e. the i386 convention is **`Eax` = entry point, `Ebx` = argument**,
/// with `Eip` on `RtlUserThreadStart`, not the 64-bit `Rcx`/`Rdx` pair. That
/// difference is exactly why the 32-bit bootstrap had to be read out of the
/// i386 binary instead of mirrored from the 64-bit one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Start32 {
    /// `Eip` — for a boot through Wine's own loader this is
    /// `ntdll32!RtlUserThreadStart`, which `wow64.dll`'s per-thread init then
    /// *replaces* with `LdrInitializeThunk`, passing this record along as the
    /// `CONTEXT` the loader eventually `NtContinue`s back into.
    pub eip: u32,
    /// `Esp` — top of the 32-bit stack.
    pub esp: u32,
    /// `Eax` — the thread's entry point.
    pub eax: u32,
    /// `Ebx` — the thread's argument.
    pub ebx: u32,
}

/// Lay out the WoW64 CPU-reserved area for a fresh 32-bit guest thread (roadmap
/// W5.4): publish the area pointer at `teb_base + 0x1488`, clear the machine-type
/// header (so `BTCpuSimulate` takes the fast forward path), and seed the
/// `WOW64_CONTEXT` at `area + 4` with [`Start32`], initial flags, and the 32-bit
/// CS/SS selectors. The remaining general-purpose registers are left zeroed.
/// After this, `wow64cpu!BTCpuSimulate` will drop the CPU into the guest.
pub fn init_cpu_area(mem: &mut dyn Memory, teb_base: u64, area: u64, start: Start32) -> Result<()> {
    mem.write_u64(teb_base + TEB_CPU_AREA_PTR_OFF, area)?;
    mem.write_u32(area, 0)?; // header: bit0=0 → fast far-jmp forward path
    let ctx = area + CPU_AREA_HEADER_LEN;
    mem.write_u32(ctx + CTX_EIP, start.eip)?;
    mem.write_u32(ctx + CTX_ESP, start.esp)?;
    mem.write_u32(ctx + CTX_EAX, start.eax)?;
    mem.write_u32(ctx + CTX_EBX, start.ebx)?;
    mem.write_u32(ctx + CTX_EFLAGS, EFLAGS_INIT)?;
    mem.write_u32(ctx + CTX_SEGCS, SEL_CS32)?;
    mem.write_u32(ctx + CTX_SEGSS, SEL_SS32)?;
    Ok(())
}

/// Publish the WoW64 **transition pointer** into a 32-bit ntdll's
/// `ntdll!Wow64Transition` slot (roadmap W5.1).
///
/// This is the one seam a 32-bit guest needs in order to reach the 64-bit NT
/// layer. Every `Nt*` stub in a 32-bit ntdll has the shape
///
/// ```text
///   NtXxx:                      mov eax, <service index>
///                               mov edx, offset Wow64SystemServiceCall
///                               call edx                 ; pushes the inner retaddr
///                               ret <bytes of args>
///   Wow64SystemServiceCall:     jmp dword ptr [Wow64Transition]
/// ```
///
/// so `Wow64Transition` is a plain **32-bit data cell holding the VA of the BOP
/// trampoline** — the `jmp fword ptr [...]` that `wow64cpu!BTCpuProcessInit`
/// assembles and `wow64cpu!BTCpuGetBopCode` hands out. The near `jmp` through
/// this cell lands on the BOP, which far-jumps (CS = 0x33) into wow64cpu's
/// 64-bit return handler; that handler reads the guest return address from
/// `[esp]`, the service index from `eax`, and the argument block from `[esp+8]`
/// (past the inner and outer return addresses this double-call shape stacks),
/// then dispatches to `wow64.dll!Wow64SystemServiceEx`.
///
/// The cell is 32 bits wide, so the BOP — and therefore the whole `wow64cpu`
/// image — must live **below 4 GiB**; a higher address is rejected rather than
/// silently truncated. (`BTCpuProcessInit` range-checks the same invariant from
/// the other side and refuses to build the BOP above 4 GiB.)
///
/// **The pinned Wine 11.0 DLL set contains no 32-bit ntdll** (it is the 64-bit
/// `x86_64-windows` set only). So `transition_slot` is supplied by the caller —
/// a real boot resolves it from the 32-bit ntdll's export table — and the
/// end-to-end coverage in `crates/app/tests/dll_smoke.rs` drives a *synthesized*
/// 32-bit stub shaped exactly as above. That pins the **mechanism**, not a real
/// ntdll: it proves the published pointer routes a 32-bit `call` through the
/// real BOP into the real 64-bit handler, but it cannot prove that Wine's own
/// 32-bit ntdll stubs are byte-identical to the shape assumed here.
pub fn publish_wow64_transition(mem: &mut dyn Memory, transition_slot: u64, bop: u64) -> Result<()> {
    if bop > u32::MAX as u64 {
        return Err(EmuError::Os(format!(
            "WoW64 BOP at {bop:#x} is above 4 GiB — a 32-bit `jmp dword ptr [Wow64Transition]` cannot reach it"
        )));
    }
    mem.write_u32(transition_slot, bop as u32)
}

/// Link a 64-bit TEB to its 32-bit companion the way Wine's WoW64 does:
/// `TEB64.WowTebOffset` (a signed 32-bit byte delta at [`TEB64_WOW_TEB_OFFSET`])
/// plus the 32-bit TEB's own `NtTib.Self`.
///
/// The two TEBs must therefore be within ±2 GiB of each other, and the 32-bit
/// one must be addressable from 32-bit code — so a WoW64 process places the pair
/// adjacently below 4 GiB. Both constraints are enforced here rather than
/// silently truncated.
pub fn link_teb32(mem: &mut dyn Memory, teb64: u64, teb32: u64) -> Result<()> {
    if teb32 > u32::MAX as u64 {
        return Err(EmuError::Os(format!(
            "WoW64 TEB32 at {teb32:#x} is above 4 GiB — 32-bit guest code could not address it"
        )));
    }
    let delta = teb32 as i64 - teb64 as i64;
    let delta = i32::try_from(delta).map_err(|_| {
        EmuError::Os(format!(
            "WoW64 TEB32 {teb32:#x} is more than 2 GiB from TEB64 {teb64:#x} — \
             TEB64.WowTebOffset is a signed 32-bit field"
        ))
    })?;
    mem.write_u32(teb64 + TEB64_WOW_TEB_OFFSET, delta as u32)?;
    mem.write_u32(teb32 + TEB32_SELF, teb32 as u32)?;
    Ok(())
}

/// Resolve a 64-bit TEB's 32-bit companion the way `wow64.dll` does
/// (`movsxd rdx,[teb64+0x180c]; lea rsi,[teb64+rdx]`). `None` when the field is
/// zero — the "this is not a WoW64 thread" answer `RtlWow64GetCurrentMachine`
/// tests for.
pub fn teb32_of(mem: &dyn Memory, teb64: u64) -> Result<Option<u64>> {
    let off = mem.read_u32(teb64 + TEB64_WOW_TEB_OFFSET)? as i32;
    if off == 0 {
        return Ok(None);
    }
    Ok(Some(teb64.wrapping_add(off as i64 as u64)))
}

/// The three 32-bit cells Wine's own `wow64.dll` fills with the BOP address.
///
/// On the default WoW64 bring-up `Wow64LdrpInitialize` fills them itself and
/// exemu writes none of them; these are used by the shorter *direct* bring-up
/// (`wow64_boot::Bringup::Direct`), which skips Wine's process init entirely.
///
/// **Recovered by disassembling the pinned `wow64.dll`,** which resolves each
/// name out of the 32-bit ntdll with `RtlFindExportedRoutineByName` and stores
/// `BTCpuGetBopCode()` into it:
///
/// * rva 0x4880 → `"Wow64Transition"`   ← `BTCpuGetBopCode()`
/// * rva 0x48b7 → `"__wine_syscall_dispatcher"` ← `BTCpuGetBopCode()` (the same
///   pointer table slot, rva 0x1e1c8, is called at both sites)
/// * rva 0x5550 → `TEB32 + 0xC0` (`WOW32Reserved`) ← `BTCpuGetBopCode()`
///
/// The middle one is the load-bearing surprise: **Wine's 32-bit `ntdll` routes
/// its `Nt*` stubs through `__wine_syscall_dispatcher`, not `Wow64Transition`.**
/// Every one of its 526 syscall stubs is
/// `mov eax,<index>; mov edx,<helper>; call edx; ret <argbytes>`, and the helper
/// (rva 0xe0c4 in the pinned 32-bit ntdll) is a single
/// `jmp dword ptr [__wine_syscall_dispatcher]`. Publishing only
/// `Wow64Transition` — the name every WoW64 write-up mentions — would leave the
/// stubs jumping through a null pointer.
#[derive(Debug, Clone, Copy)]
pub struct BopSlots {
    /// `ntdll32!Wow64Transition` (a 32-bit data cell).
    pub transition: u64,
    /// `ntdll32!__wine_syscall_dispatcher` (a 32-bit data cell).
    pub syscall_dispatcher: u64,
    /// `TEB32 + 0xC0` (`WOW32Reserved`).
    pub wow32_reserved: u64,
}

/// Publish `bop` into all three cells of [`BopSlots`] (roadmap W5.1). A zero
/// slot is skipped, so a caller that could not resolve one of the names fails
/// loudly at the stub instead of corrupting an unrelated address.
pub fn publish_bop(mem: &mut dyn Memory, slots: BopSlots, bop: u64) -> Result<()> {
    for slot in [slots.transition, slots.syscall_dispatcher, slots.wow32_reserved] {
        if slot != 0 {
            publish_wow64_transition(mem, slot, bop)?;
        }
    }
    Ok(())
}

// ==========================================================================
// The WoW64 image set: mapping the 32-bit ntdll + the 64-bit thunk DLLs
// ==========================================================================

/// One image mapped for the WoW64 boot, with its exports resolved by name.
///
/// The WoW64 module set is deliberately kept **outside** the 64-bit loader's
/// `by_name` table: the process holds *two* `ntdll.dll`s, and letting the 32-bit
/// one answer a 64-bit `GetModuleHandle("ntdll.dll")` (or vice versa) is exactly
/// the kind of silent mix-up this phase exists to avoid.
pub struct Wow64Image {
    /// Mapped base address.
    pub base: u64,
    /// `SizeOfImage`, page-aligned.
    pub size: u64,
    /// Export name → absolute VA (forwarders excluded).
    pub exports: HashMap<String, u64>,
    /// `(IAT slot rva, dll, symbol)` for every by-name import.
    pub imports: Vec<(u32, String, String)>,
    /// Entry point VA, or 0.
    pub entry: u64,
}

impl Wow64Image {
    /// Absolute VA of an export, or `None` when absent/forwarded.
    pub fn export(&self, name: &str) -> Option<u64> {
        self.exports.get(name).copied()
    }
}

/// Map + relocate a PE at an explicit base, RWX, and resolve its export /
/// import tables (roadmap W5.4).
///
/// Unlike the 64-bit core loader this takes the base from the caller: the WoW64
/// process has hard placement constraints (`wow64cpu` and the whole 32-bit view
/// must live below 4 GiB) that a bump arena above 4 GiB cannot satisfy.
pub fn map_image(mem: &mut dyn Memory, bytes: &[u8], base: u64, name: &str) -> Result<Wow64Image> {
    let mut image = exemu_loader::parse(bytes)?;
    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)?;

    let size = align_up_page((image.size_of_image as u64).max(0x1000));
    mem.map_fixed(base, size, Perm::RWX, name)?;
    mem.write(base, &image.headers)?;
    for s in &image.sections {
        if !s.data.is_empty() {
            mem.write(base + s.rva as u64, &s.data)?;
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(n) = &e.name {
            exports.insert(n.clone(), base + e.rva as u64);
        }
    }
    let imports = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();

    Ok(Wow64Image {
        base,
        size,
        exports,
        imports,
        entry: if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 },
    })
}

/// An export/import view of an image that is **already mapped** at `base` (e.g.
/// the 64-bit `ntdll` the Wine-boot path maps as the running image), so the
/// WoW64 binder can treat it exactly like one it mapped itself.
pub fn image_view(bytes: &[u8], base: u64) -> Result<Wow64Image> {
    let image = exemu_loader::parse(bytes)?;
    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(n) = &e.name {
            exports.insert(n.clone(), base + e.rva as u64);
        }
    }
    let imports = image
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    Ok(Wow64Image {
        base,
        size: align_up_page((image.size_of_image as u64).max(0x1000)),
        exports,
        imports,
        entry: if image.entry_rva != 0 { base + image.entry_rva as u64 } else { 0 },
    })
}

/// Bind every by-name import of `image` that any of `providers` exports, writing
/// the provider's real export VA into the importer's IAT slot. Returns the
/// number of slots bound. Unresolved slots are left alone — they fault loudly if
/// a path under test ever reaches one.
pub fn bind_imports(mem: &mut dyn Memory, image: &Wow64Image, providers: &[&Wow64Image], ptr_size: u8) -> Result<usize> {
    let mut bound = 0;
    for (iat_rva, _dll, sym) in &image.imports {
        for p in providers {
            if let Some(addr) = p.export(sym) {
                mem.write(image.base + *iat_rva as u64, &addr.to_le_bytes()[..ptr_size as usize])?;
                bound += 1;
                break;
            }
        }
    }
    Ok(bound)
}

#[inline]
fn align_up_page(v: u64) -> u64 {
    (v + 0xfff) & !0xfff
}

// --- The user-mode client callback (roadmap W5.10) --------------------------
//
// The one path by which a kernel calls *back* into user mode. exemu's win32k is
// the kernel, so every `WM_NCCREATE` a `NtUserCreateWindowEx` owes its window
// travels this way in a WoW64 process. Everything below was read out of the
// pinned binaries; `crates/app/tests/wow64_callback_abi.rs` re-derives all of
// it on every run.

/// `PEB64.KernelCallbackTable` — the array `ntdll!KiUserCallbackDispatcher`
/// indexes with the callback id the kernel names.
///
/// Recovered from that dispatcher's own bytes (64-bit ntdll rva 0x10a88):
/// `mov rax, gs:[0x60]` (the TEB's PEB pointer) `; mov rax,[rax+0x58] ; call
/// qword ptr [rax + r8*8]`.
pub const PEB64_KERNEL_CALLBACK_TABLE: u64 = 0x58;

/// The `KiUserCallbackDispatcher` **entry frame**: the kernel resumes user mode
/// with `rsp` pointing at a block whose first `0x20` bytes are the callee's
/// shadow area and whose three fields follow.
///
/// Recovered verbatim from the dispatcher's first three instructions:
///
/// ```text
///   mov  rcx, qword ptr [rsp+0x20]     ; args
///   mov  edx, dword  ptr [rsp+0x28]    ; len
///   mov  r8d, dword  ptr [rsp+0x2c]    ; id
///   mov  rax, gs:[0x60]                ; PEB
///   mov  rax, [rax+0x58]               ; PEB.KernelCallbackTable
///   call qword ptr [rax + r8*8]        ; table[id]( args, len )
///   xor  rcx,rcx ; xor edx,edx ; mov r8d,eax
///   call NtCallbackReturn              ; …which never returns
/// ```
pub mod cb_frame {
    /// `void *args` — the parameter block the callback is handed.
    pub const ARGS: u64 = 0x20;
    /// `ULONG len` — its length in bytes.
    pub const LEN: u64 = 0x28;
    /// `ULONG id` — the index into `PEB.KernelCallbackTable`.
    pub const ID: u64 = 0x2c;
    /// Bytes of frame the kernel must leave below the callee's own stack use.
    pub const SIZE: u64 = 0x30;
}

/// `NtCallbackReturn` — SSDT index **5** in this pinned Wine build, read off the
/// 64-bit `ntdll!NtCallbackReturn` stub's own `mov eax, 5`. The 32-bit ntdll's
/// stub carries the same index (the two share one index space), so a WoW64
/// guest's return arrives through `wow64.dll`'s table-0 slot 5 and then, from
/// the 64-bit side, as this syscall.
pub const SSDT_NT_CALLBACK_RETURN: u32 = 5;

/// `NtUserCallWinProc` — the user-callback id that runs a window procedure.
///
/// Recovered by name, not by counting: `wow64win.dll`'s COFF symbol table names
/// the table `user_callbacks` (rva 0x16620) and its entries
/// `wow64_NtUser…`; the fifth is `wow64_NtUserCallWinProc` (rva 0xc6e0), and
/// that thunk passes literal `4` as the 32-bit callback id it forwards to
/// `Wow64KiUserCallbackDispatcher`. So the 64-bit index and the 32-bit id are
/// the same number.
pub const NT_USER_CALL_WIN_PROC: u32 = 4;

/// `NTUSER_DPI_UNAWARE` — a `dpi_context` value user32 accepts.
///
/// Not a guess and not zero: `user32!SetThreadDpiAwarenessContext` maps the
/// pseudo-handle `DPI_AWARENESS_CONTEXT_UNAWARE` (-1) through its own jump table
/// to `mov eax, 0x6010`, and `user32!is_valid_dpi_awareness_context` accepts a
/// value exactly when `(v & 0xf) == 0 && (v & 0x3ffe0000) == 0 && (v & 0xf0) ==
/// 0x10 && (v & 0x1ff00) == 0x6000` — which `0x6010` satisfies and `0` does not.
/// A zero here would make `dispatch_win_proc_params` set `ERROR_INVALID_PARAMETER`
/// before every single window message.
pub const NTUSER_DPI_UNAWARE: u32 = 0x6010;

/// Wine's **64-bit** `struct win_proc_params` — the block `NtUserCallWinProc`
/// carries, and the only structure exemu's kernel has to build for the callback
/// path. `wow64win!win_proc_params_64to32` narrows it to the 32-bit form before
/// the guest ever sees it, so exemu writes the 64-bit shape in both cases.
///
/// Field roles come from the two consumers, which agree field for field:
/// `user32!dispatch_win_proc_params` (x86_64 rva 0x5ddb0) and its i386 twin
/// (rva 0x63680). Sizes come from `win_proc_params_64to32` (rva 0x3d30), whose
/// map is `{0x00,0x08,0x10,0x18,0x20}→{0x00,0x04,0x08,0x0c,0x10}` (five
/// pointer-width fields narrowed), `0x28..0x30` copied as one qword to
/// `0x14..0x1c` (two dwords), then `{0x30,0x34,0x38,0x40}→{0x1c,0x20,0x24,0x28}`.
pub mod win_proc_params {
    /// `WNDPROC func` — the procedure the A/W wrappers target.
    pub const FUNC: u64 = 0x00;
    /// `HWND hwnd`.
    pub const HWND: u64 = 0x08;
    /// `UINT msg`.
    pub const MSG: u64 = 0x10;
    /// `WPARAM wparam`.
    pub const WPARAM: u64 = 0x18;
    /// `LPARAM lparam`.
    pub const LPARAM: u64 = 0x20;
    /// `ULONG size` of the packed message data that follows the struct. Zero
    /// means "nothing to unpack" — `dispatch_win_proc_params` branches on it
    /// first (`mov eax,[params+0x28]; test eax,eax`).
    pub const SIZE: u64 = 0x28;
    /// `BOOL ansi` — non-zero routes through `WINPROC_CallProcAtoW`/`WtoA`.
    pub const ANSI: u64 = 0x2c;
    /// `enum wm_char_mapping mapping` — only read on the ANSI path.
    pub const MAPPING: u64 = 0x30;
    /// `ULONG dpi_context` — handed straight to `SetThreadDpiAwarenessContext`.
    pub const DPI_CONTEXT: u64 = 0x34;
    /// `WNDPROC procA`.
    pub const PROC_A: u64 = 0x38;
    /// `WNDPROC procW` — **the pointer actually called** when `ansi` is clear
    /// (`call_window_proc`'s sixth argument). A value of `1` is the sentinel
    /// that selects the dialog-procedure path instead.
    pub const PROC_W: u64 = 0x40;
    /// `LRESULT result` — written by user32 when the packed form is in use.
    pub const RESULT: u64 = 0x48;
    /// `sizeof(struct win_proc_params)`. Passing exactly this as the callback
    /// `len` is what makes `wow64win` marshal no trailing message data
    /// (`cmp r9d,0x48; jbe`) and 32-bit user32 take its short return
    /// (`cmp esi,0x2c; ja`).
    pub const SIZE_OF: u64 = 0x50;
    /// The `len` exemu passes: the struct up to but excluding `result`.
    pub const CALL_LEN: u32 = 0x48;
}

/// Publish `PEB64.KernelCallbackTable` from `wow64win.dll`'s own `user_callbacks`
/// array, and return the table's address (roadmap W5.10).
///
/// On Windows — and in Wine — `wow64win!DllMain` does this itself on
/// `DLL_PROCESS_ATTACH`. exemu's WoW64 boot maps `wow64win` directly and never
/// runs a `DllMain` (its `LdrLoadDll` hands back the pre-mapped base), so the
/// table would stay null and `KiUserCallbackDispatcher` would `call [0 + id*8]`.
/// This publishes it exactly as that `DllMain` would.
///
/// **The table address is decoded out of `DllMain`'s own bytes, never
/// hardcoded.** From the module entry point (one `jmp rel32` thunk in the pinned
/// build), the first occurrence of
///
/// ```text
///   lea rdx, [rip+disp32]        ; 48 8D 15 <disp32>   → user_callbacks
///   mov rax, gs:[0x30]           ; 65 48 8B 04 25 30 00 00 00
///   mov rax, [rax+0x60]          ; 48 8B 40 60          → TEB.ProcessEnvironmentBlock
///   mov [rax+0x58], rdx          ; 48 89 50 58          → PEB.KernelCallbackTable
/// ```
///
/// yields both the array and — as a cross-check that this really is the publish
/// site — the two PEB offsets. A drifted prologue fails loudly here instead of
/// leaving a null table for the first `WM_NCCREATE` to fall into.
pub fn publish_kernel_callback_table(mem: &mut dyn Memory, wow64win_base: u64, entry: u64, peb64: u64) -> Result<u64> {
    /// `mov rax, gs:[0x30]; mov rax,[rax+0x60]; mov [rax+0x58], rdx`.
    const TAIL: [u8; 17] = [
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, // mov rax, gs:[0x30]
        0x48, 0x8B, 0x40, 0x60, // mov rax, [rax+0x60]
        0x48, 0x89, 0x50, 0x58, // mov [rax+0x58], rdx
    ];
    // The entry point is a `jmp rel32` thunk to DllMain in this build; follow it
    // once so the scan window starts at the real body.
    let mut head = [0u8; 5];
    mem.read(entry, &mut head)?;
    let body = if head[0] == 0xE9 {
        let rel = i32::from_le_bytes(head[1..5].try_into().unwrap());
        (entry + 5).wrapping_add(rel as i64 as u64)
    } else {
        entry
    };
    let mut win = vec![0u8; 0x100];
    mem.read(body, &mut win)?;
    for i in 0..win.len() - (7 + TAIL.len()) {
        if win[i] != 0x48 || win[i + 1] != 0x8D || win[i + 2] != 0x15 {
            continue;
        }
        if win[i + 7..i + 7 + TAIL.len()] != TAIL {
            continue;
        }
        let disp = i32::from_le_bytes(win[i + 3..i + 7].try_into().unwrap());
        let table = (body + i as u64 + 7).wrapping_add(disp as i64 as u64);
        if table < wow64win_base {
            break;
        }
        mem.write_u64(peb64 + PEB64_KERNEL_CALLBACK_TABLE, table)?;
        return Ok(table);
    }
    Err(EmuError::Os(format!(
        "WoW64 boot: wow64win.dll's DllMain at {body:#x} does not publish PEB.KernelCallbackTable in \
         the recovered shape (lea rdx,[rip+d32]; mov rax,gs:[0x30]; mov rax,[rax+0x60]; mov [rax+0x58],rdx) \
         — the user-callback table cannot be located"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{Perm, Region};
    use exemu_memory::VirtualMemory;

    #[test]
    fn init_cpu_area_lays_out_the_wow64_context() {
        let mut mem = VirtualMemory::new();
        let teb = 0x1_0000u64;
        let area = 0x2_0000u64;
        mem.map(Region::new("teb", teb, 0x2000, Perm::RW)).unwrap();
        mem.map(Region::new("cpu", area, 0x1000, Perm::RW)).unwrap();

        init_cpu_area(
            &mut mem,
            teb,
            area,
            Start32 { eip: 0x0040_1234, esp: 0x0041_0000, eax: 0x0040_5678, ebx: 0 },
        )
        .unwrap();

        assert_eq!(mem.read_u64(teb + TEB_CPU_AREA_PTR_OFF).unwrap(), area, "area ptr at TEB+0x1488");
        assert_eq!(mem.read_u32(area).unwrap(), 0, "header cleared → forward path");
        let ctx = area + CPU_AREA_HEADER_LEN;
        assert_eq!(mem.read_u32(ctx + CTX_EIP).unwrap(), 0x0040_1234, "Eip");
        assert_eq!(mem.read_u32(ctx + CTX_ESP).unwrap(), 0x0041_0000, "Esp");
        assert_eq!(mem.read_u32(ctx + CTX_EAX).unwrap(), 0x0040_5678, "Eax = the thread entry point");
        assert_eq!(mem.read_u32(ctx + CTX_SEGCS).unwrap(), SEL_CS32, "SegCs = 0x23");
        assert_eq!(mem.read_u32(ctx + CTX_SEGSS).unwrap(), SEL_SS32, "SegSs = 0x2b");
        assert_eq!(mem.read_u32(ctx + CTX_EFLAGS).unwrap(), EFLAGS_INIT, "EFlags");
        // Distinct, non-overlapping context fields (a classic layout bug).
        assert_eq!(CTX_SEGCS - CTX_EIP, 4, "SegCs directly follows Eip");
    }

    /// `Wow64Transition` is a 32-bit cell holding the BOP VA; a BOP above 4 GiB
    /// is refused rather than truncated into an unreachable pointer.
    #[test]
    fn publish_wow64_transition_writes_a_32bit_bop_pointer() {
        let mut mem = VirtualMemory::new();
        let slot = 0x50_0000u64;
        mem.map(Region::new("ntdll32", slot, 0x1000, Perm::RW)).unwrap();

        publish_wow64_transition(&mut mem, slot, 0x6A40_7000).unwrap();
        assert_eq!(mem.read_u32(slot).unwrap(), 0x6A40_7000, "BOP VA published as a 32-bit cell");
        // The neighbouring cell is untouched — the slot is 4 bytes, not 8.
        assert_eq!(mem.read_u32(slot + 4).unwrap(), 0, "only the 32-bit slot is written");

        let err = publish_wow64_transition(&mut mem, slot, 0x1_0000_7000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "a BOP above 4 GiB is rejected, not truncated: {err}");
        assert_eq!(mem.read_u32(slot).unwrap(), 0x6A40_7000, "the rejected publish left the slot intact");
    }

    /// `TEB64.WowTebOffset` round-trips as a **signed** 32-bit delta, and a TEB32
    /// that a 32-bit guest could not address (or that is too far from TEB64 for
    /// the field) is refused rather than truncated.
    #[test]
    fn teb32_link_round_trips_through_the_signed_wow_teb_offset() {
        let mut mem = VirtualMemory::new();
        let teb64 = 0x7F00_0000u64;
        let teb32 = teb64 + 0x8000;
        mem.map(Region::new("tebs", teb64, 0x1_0000, Perm::RW)).unwrap();

        assert_eq!(teb32_of(&mem, teb64).unwrap(), None, "a zero field means: not a WoW64 thread");
        link_teb32(&mut mem, teb64, teb32).unwrap();
        assert_eq!(teb32_of(&mem, teb64).unwrap(), Some(teb32), "TEB64 + (i32)WowTebOffset = TEB32");
        assert_eq!(mem.read_u32(teb32 + TEB32_SELF).unwrap() as u64, teb32, "TEB32.NtTib.Self");

        // A negative delta (TEB32 below TEB64) is legal — the field is signed.
        let below = teb64 - 0x8000;
        mem.map(Region::new("below", below, 0x1000, Perm::RW)).unwrap();
        link_teb32(&mut mem, teb64, below).unwrap();
        assert_eq!(mem.read_u32(teb64 + TEB64_WOW_TEB_OFFSET).unwrap() as i32, -0x8000);
        assert_eq!(teb32_of(&mem, teb64).unwrap(), Some(below), "a negative WowTebOffset resolves too");

        // Above 4 GiB: a 32-bit guest could never hold the pointer.
        let err = link_teb32(&mut mem, teb64, 0x1_0000_0000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "TEB32 above 4 GiB is refused: {err}");
        // Further than a signed 32-bit delta: the field cannot express it.
        let err = link_teb32(&mut mem, 0x10_0000_0000, 0x1000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "a >2 GiB TEB64→TEB32 distance is refused: {err}");
    }

    /// The publish step writes **all three** cells Wine's own `wow64.dll` fills.
    /// Only writing `Wow64Transition` — the name every WoW64 write-up mentions —
    /// would leave the 32-bit ntdll's 526 syscall stubs jumping through a null
    /// `__wine_syscall_dispatcher` (see `crates/app/tests/wow64_abi.rs`).
    #[test]
    fn publish_bop_fills_all_three_cells() {
        let mut mem = VirtualMemory::new();
        let page = 0x50_0000u64;
        mem.map(Region::new("cells", page, 0x1000, Perm::RW)).unwrap();
        let slots = BopSlots {
            transition: page,
            syscall_dispatcher: page + 0x10,
            wow32_reserved: page + 0x20,
        };
        publish_bop(&mut mem, slots, 0x6A40_7000).unwrap();
        for (name, at) in [
            ("Wow64Transition", slots.transition),
            ("__wine_syscall_dispatcher", slots.syscall_dispatcher),
            ("TEB32.WOW32Reserved", slots.wow32_reserved),
        ] {
            assert_eq!(mem.read_u32(at).unwrap(), 0x6A40_7000, "{name} holds the BOP");
        }
        // A zero slot is skipped rather than written at address 0.
        publish_bop(&mut mem, BopSlots { transition: 0, ..slots }, 0x6A40_8000).unwrap();
        assert_eq!(mem.read_u32(slots.syscall_dispatcher).unwrap(), 0x6A40_8000);
    }
}
