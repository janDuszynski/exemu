//! WoW64 CS-based mode switch (roadmap W5.2).
//!
//! A far *indirect* jump (`FF /5`, `m16:32`) loads `[offset, selector]` from
//! memory. exemu has no GDT — it models Wine's flat WoW64 selectors, so the CS
//! selector alone picks the operating mode: `0x33` (GDT index 6) → 64-bit long
//! mode, `0x23` (index 4) → 32-bit compatibility mode. This is the mechanism
//! `wow64cpu!BTCpuSimulate` uses to drop from 64-bit Wine code into a 32-bit
//! guest (and back), recovered from the pinned `wow64cpu.dll`.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x0040_0000;
const DATA: u64 = 0x0050_0000;

/// A mapped interpreter in `bits` with `rip` at `CODE` and a `FF /5 [rAX]` far
/// jump (`FF 28`) whose far pointer at `DATA` is `[offset32, selector16]`.
fn far_jmp(bits: Bits, offset: u32, selector: u16) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE, &[0xFF, 0x28]).unwrap(); // jmp far [rax] / [eax]
    mem.write_u32(DATA, offset).unwrap();
    mem.write_u16(DATA + 4, selector).unwrap();

    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_reg(Reg::Rax, DATA); // the operand pointer

    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).expect("far jmp executes");
    cpu
}

#[test]
fn far_jmp_to_cs_0x33_switches_to_64bit() {
    let cpu = far_jmp(Bits::B32, 0x0000_1234, 0x33);
    assert_eq!(cpu.bits(), Bits::B64, "CS=0x33 (index 6) → 64-bit long mode");
    assert_eq!(cpu.state().rip, 0x1234, "rip = the far offset");
}

#[test]
fn far_jmp_to_cs_0x23_switches_to_32bit() {
    let cpu = far_jmp(Bits::B64, 0x0040_5678, 0x23);
    assert_eq!(cpu.bits(), Bits::B32, "CS=0x23 (index 4) → 32-bit compat mode");
    assert_eq!(cpu.state().rip, 0x0040_5678, "rip = the far offset");
}

#[test]
fn far_jmp_within_64bit_stays_64bit() {
    // A far jump that keeps CS=0x33 stays in long mode (a plain far branch).
    let cpu = far_jmp(Bits::B64, 0x0040_1000, 0x33);
    assert_eq!(cpu.bits(), Bits::B64);
    assert_eq!(cpu.state().rip, 0x0040_1000);
}

/// `iretq` is BTCpuSimulate's *other* forward path (full-context restore): it
/// pops RIP/CS/RFLAGS/RSP/SS, and the popped CS selector switches the mode.
fn iretq(cs: u64) -> Interpreter {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", 0x8000, 0x2000, Perm::RW)).unwrap();
    let sp = 0x9000;
    mem.write(CODE, &[0x48, 0xCF]).unwrap(); // iretq (REX.W + CF)
    mem.write_u64(sp, 0x0040_1234).unwrap(); // RIP
    mem.write_u64(sp + 8, cs).unwrap(); // CS
    mem.write_u64(sp + 16, 0x202).unwrap(); // RFLAGS
    mem.write_u64(sp + 24, 0x0041_0000).unwrap(); // RSP
    mem.write_u64(sp + 32, 0x2b).unwrap(); // SS

    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_rsp(sp);
    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).expect("iretq executes");
    cpu
}

#[test]
fn iretq_to_cs_0x23_restores_32bit_context() {
    let cpu = iretq(0x23);
    assert_eq!(cpu.bits(), Bits::B32, "popped CS=0x23 → 32-bit compat mode");
    assert_eq!(cpu.state().rip, 0x0040_1234, "rip = popped RIP");
    assert_eq!(cpu.state().rsp(), 0x0041_0000, "rsp = popped RSP");
}

#[test]
fn iretq_to_cs_0x33_stays_64bit() {
    let cpu = iretq(0x33);
    assert_eq!(cpu.bits(), Bits::B64, "popped CS=0x33 → 64-bit long mode");
    assert_eq!(cpu.state().rip, 0x0040_1234);
}

// ==========================================================================
// `mov r/m16, Sreg` (0x8C) — the selector a segment-register *store* reports.
// ==========================================================================
//
// This is not cosmetic. `ntdll!RtlCaptureContext` fills `CONTEXT.SegCs` with
// `mov word ptr [rcx+0x38], cs`, and `wow64cpu!BTCpuProcessInit` copies exactly
// that word into the 32→64 return BOP's far pointer. Report the wrong CS and
// the reverse WoW64 transition lands in the wrong mode — invisible until a
// 32-bit guest's first syscall corrupts itself.

/// Run `mov word ptr [rax], <sreg>` in `bits` and return the stored selector.
/// `reg` is the ModRM reg field: 0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS.
fn store_sreg(bits: Bits, reg: u8) -> u16 {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.write(CODE, &[0x8C, reg << 3]).unwrap(); // mov [rax], sreg (mod=00, rm=000)
    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().set_reg(Reg::Rax, DATA);
    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).expect("mov [rax], sreg executes");
    mem.read_u16(DATA).unwrap()
}

#[test]
fn mov_store_cs_reports_the_mode_selector() {
    assert_eq!(store_sreg(Bits::B64, 1), exemu_cpu::SEL_CS64, "64-bit mode: cs = 0x33");
    assert_eq!(store_sreg(Bits::B32, 1), exemu_cpu::SEL_CS32, "32-bit mode: cs = 0x23");
    // The reported CS must round-trip through the far-jmp mode rule: the 64-bit
    // value has to be one the `/5` handler maps back to B64 (`sel & 0xFFF8 ==
    // 0x30`), or the BOP built from it would drop the CPU to 32-bit.
    assert_eq!(exemu_cpu::SEL_CS64 & 0xFFF8, 0x30, "the reported 64-bit CS selects long mode");
    assert_ne!(exemu_cpu::SEL_CS32 & 0xFFF8, 0x30, "the reported 32-bit CS selects compat mode");
}

#[test]
fn mov_store_data_segments_report_the_flat_selector() {
    for reg in [0u8, 2, 3, 4, 5] {
        assert_eq!(
            store_sreg(Bits::B64, reg),
            exemu_cpu::SEL_DATA,
            "flat data selector for sreg {reg} (ES/SS/DS/FS/GS carry no base here)",
        );
    }
}

/// **`mov fs:[0], eax` must use the thread's *live* FS base** (roadmap W5.7).
///
/// The `moffs` forms of `MOV` (`A0`–`A3`) take an absolute address immediate
/// rather than a ModRM operand, and used to add a fixed, process-default
/// segment base instead of the per-thread one on [`exemu_core::CpuState`]. That
/// is invisible on the ordinary 32-bit path — where the two are the same value
/// — and fatal under WoW64, where the guest's TEB32 is nowhere near the
/// default: Wine's i386 `ntdll` installs its first SEH frame with exactly this
/// instruction (`64 a3 00 00 00 00` at rva 0x43b74), and the store landed in
/// unmapped memory.
#[test]
fn moffs_mov_uses_the_live_segment_bases() {
    const TEB32: u64 = 0x7F00_8000;
    const TEB64: u64 = 0x7F00_0000;
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    mem.map(Region::new("tebs", TEB64, 0x1_0000, Perm::RW)).unwrap();

    // 32-bit: `mov fs:[0], eax` — the SEH-frame install.
    mem.write(CODE, &[0x64, 0xA3, 0x00, 0x00, 0x00, 0x00]).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B32);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().fs_base = TEB32;
    cpu.state_mut().set_reg(Reg::Rax, 0x0012_3456);
    cpu.step(&mut mem, &mut NoHooks).expect("moffs store executes");
    assert_eq!(
        mem.read_u32(TEB32).unwrap(),
        0x0012_3456,
        "the store landed at the thread's own TEB32, not the process default",
    );

    // 64-bit: `mov eax, gs:[0x30]` — the same rule for the live GS base.
    mem.write(CODE, &[0x65, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    mem.write_u32(TEB64 + 0x30, 0xB16B_00B5).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    cpu.state_mut().rip = CODE;
    cpu.state_mut().gs_base = TEB64;
    cpu.step(&mut mem, &mut NoHooks).expect("moffs load executes");
    assert_eq!(cpu.state().reg(Reg::Rax), 0xB16B_00B5, "gs:[0x30] read through the live GS base");
}

/// **A near branch wraps at 2³² in 32-bit mode, because the instruction pointer
/// there is EIP.**
///
/// Every *non-branch* instruction already lands through `ctx.cur & addr_mask()`,
/// but the relative-branch arms assigned `rip` directly and skipped it — so a
/// backward branch from a low address left `rip = 0xFFFF_FFFF_FFFF_xxxx`
/// instead of `0xFFFF_xxxx`, and the CPU was internally inconsistent about its
/// own address width.
///
/// This was found by *reading* rather than by the differential oracle, which
/// structurally cannot reach it: the oracle assembles every trial at the base of
/// a page, so a branch's arithmetic never wraps. The block JIT masked all along;
/// the interpreter is what changed, because masking is what the hardware does.
#[test]
fn a_backward_branch_from_a_low_address_wraps_to_32_bits() {
    // `jmp rel32` at 0x100 with rel = -0x200: 0x105 + (-0x200) is negative, so
    // EIP wraps to just below 4 GiB.
    let base = 0x100u64;
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", 0, 0x1000, Perm::RX)).unwrap();
    mem.poke(base, &[0xE9, 0x00, 0xFE, 0xFF, 0xFF]).unwrap(); // jmp -0x200

    let mut cpu = Interpreter::with_bits(Bits::B32);
    cpu.state_mut().rip = base;
    let mut hooks = NoHooks;
    cpu.step(&mut mem, &mut hooks).unwrap();

    // 0x105 - 0x200 = -0xFB → 0xFFFF_FF05 as a 32-bit EIP.
    assert_eq!(
        cpu.state().rip,
        0xFFFF_FF05,
        "a wrapping near branch must leave a 32-bit EIP, not a sign-extended 64-bit value"
    );

    // The same encoding in 64-bit mode keeps the full 64-bit result: RIP is
    // 64 bits there, so nothing is truncated.
    let mut mem64 = VirtualMemory::new();
    mem64.map(Region::new("code", 0, 0x1000, Perm::RX)).unwrap();
    mem64.poke(base, &[0xE9, 0x00, 0xFE, 0xFF, 0xFF]).unwrap();
    let mut cpu64 = Interpreter::with_bits(Bits::B64);
    cpu64.state_mut().rip = base;
    cpu64.step(&mut mem64, &mut hooks).unwrap();
    assert_eq!(
        cpu64.state().rip,
        0xFFFF_FFFF_FFFF_FF05,
        "64-bit mode must NOT truncate — RIP is 64 bits wide"
    );
}
