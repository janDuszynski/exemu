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

/// Lay out the WoW64 CPU-reserved area for a fresh 32-bit guest thread (roadmap
/// W5.4): publish the area pointer at `teb_base + 0x1488`, clear the machine-type
/// header (so `BTCpuSimulate` takes the fast forward path), and seed the
/// `WOW64_CONTEXT` at `area + 4` with the guest entry `eip`, stack `esp`, initial
/// flags, and the 32-bit CS/SS selectors. General-purpose registers are left
/// zeroed. After this, `wow64cpu!BTCpuSimulate` will drop the CPU into the guest.
pub fn init_cpu_area(mem: &mut dyn Memory, teb_base: u64, area: u64, eip: u32, esp: u32) -> Result<()> {
    mem.write_u64(teb_base + TEB_CPU_AREA_PTR_OFF, area)?;
    mem.write_u32(area, 0)?; // header: bit0=0 → fast far-jmp forward path
    let ctx = area + CPU_AREA_HEADER_LEN;
    mem.write_u32(ctx + CTX_EIP, eip)?;
    mem.write_u32(ctx + CTX_ESP, esp)?;
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

/// The three 32-bit cells Wine's own `wow64.dll` fills with the BOP address, and
/// the one place exemu has to stand in for it because exemu — not
/// `Wow64LdrpInitialize` — builds the WoW64 process.
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

        init_cpu_area(&mut mem, teb, area, 0x0040_1234, 0x0041_0000).unwrap();

        assert_eq!(mem.read_u64(teb + TEB_CPU_AREA_PTR_OFF).unwrap(), area, "area ptr at TEB+0x1488");
        assert_eq!(mem.read_u32(area).unwrap(), 0, "header cleared → forward path");
        let ctx = area + CPU_AREA_HEADER_LEN;
        assert_eq!(mem.read_u32(ctx + CTX_EIP).unwrap(), 0x0040_1234, "Eip");
        assert_eq!(mem.read_u32(ctx + CTX_ESP).unwrap(), 0x0041_0000, "Esp");
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
