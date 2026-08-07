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

use exemu_core::{EmuError, Memory, Result};

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
}
