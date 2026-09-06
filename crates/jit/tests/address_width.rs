//! The address-width rule: the JIT against the interpreter at the two places
//! where a 32-bit and a 64-bit answer differ by 2^32 (roadmap W8.7).
//!
//! The interpreter is the reference, and its rule — settled in `cpu: a near
//! branch wraps at 2^32 in 32-bit mode, as EIP does` — is that **every
//! architectural address the CPU produces is masked to the width of the mode**.
//! In `Bits::B32` that means 32 bits: `rip` after any instruction, a branch
//! target, an effective address, `esp` after a push or a pop, and the value a
//! `pop` leaves in its destination. In `Bits::B64` nothing is truncated at all.
//! The JIT has to implement *that same* rule — not a stricter one and not a
//! looser one — so every case here is written where the two answers differ:
//!
//! * 32-bit code in the **last page below 4 GiB**, with page zero mapped so
//!   that an address which carries past the boundary is a real address. A JIT
//!   that failed to mask would compute `0x1_0000_0005` and fault on unmapped
//!   memory instead of landing at `0x5`.
//! * 64-bit code **above 4 GiB**, where a stray 32-bit mask is just as visible
//!   in the other direction.
//!
//! None of this is reachable from the generated differential in
//! `crates/oracle`: it assembles every trial at the base of a low page, so no
//! arithmetic it produces ever crosses either boundary. That is why these are
//! hand-assembled pins rather than fuzz coverage.
//!
//! The last case is a different kind of boundary — the end of *executable*
//! memory rather than the end of the address space — but it belongs with these
//! for the same reason: it is a place where the compiler and the interpreter
//! can silently disagree about what instruction is even there.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

/// Last page below 4 GiB. The 32-bit wrap cases live here.
const TOP32: u64 = 0xFFFF_F000;
/// Where an address that carries past 2^32 lands.
const ZERO: u64 = 0x0;
/// The 64-bit cases live above 4 GiB, where the rule is the opposite one.
const HIGH64: u64 = 0x1_0000_0000;

fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn regions(bits: Bits) -> Vec<(u64, u64)> {
    match bits {
        Bits::B32 => vec![(TOP32, 0x1000), (ZERO, 0x1000)],
        Bits::B64 => vec![(HIGH64, 0x2000), (ZERO, 0x1000)],
    }
}

fn build(bits: Bits, at: u64, code: &[u8], s: &CpuState) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    for (base, size) in regions(bits) {
        mem.map(Region::new("wrap", base, size, Perm::RWX)).unwrap();
        let filler: Vec<u8> = (0..size as u32).map(|i| (i.wrapping_mul(37) >> 3) as u8).collect();
        mem.poke(base, &filler).unwrap();
    }
    mem.poke(at, code).unwrap();
    let mut cpu = Interpreter::with_bits(bits);
    *cpu.state_mut() = s.clone();
    cpu.state_mut().rip = at;
    (mem, cpu)
}

fn mode_of(bits: Bits) -> Mode {
    match bits {
        Bits::B32 => Mode::Protected,
        Bits::B64 => Mode::Long,
    }
}

fn diff(a: &CpuState, b: &CpuState, what: &str) {
    for i in 0..16 {
        assert_eq!(
            a.gpr[i], b.gpr[i],
            "{what}: {} jit={:#x} interp={:#x}",
            exemu_core::Reg::NAMES[i], a.gpr[i], b.gpr[i]
        );
    }
    assert_eq!(
        a.rflags, b.rflags,
        "{what}: rflags jit={:#x} interp={:#x} Δ={:#x}",
        a.rflags,
        b.rflags,
        a.rflags ^ b.rflags
    );
    assert_eq!(a.rip, b.rip, "{what}: rip jit={:#x} interp={:#x}", a.rip, b.rip);
}

/// Run `code` placed at `at` through both engines and require identical state
/// and memory. Returns the number of instructions the JIT retired.
fn parity(bits: Bits, at: u64, code: &[u8], what: &str, s: &CpuState) -> u32 {
    if !jit_available() {
        return 0;
    }
    let (mut mem_j, mut cpu_j) = build(bits, at, code, s);
    let (mut mem_i, mut cpu_i) = build(bits, at, code, s);
    let mut jit = Jit::new(256 * 1024).expect("JIT should be available");
    // Budget 1 = exactly one block, which is what every case below is written
    // against.
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode_of(bits), 1);
    let n = run.insns();
    assert!(n > 0, "{what}: the JIT executed nothing ({run:?})");
    let mut hooks = NoHooks;
    for step in 0..n {
        match cpu_i.step(&mut mem_i, &mut hooks) {
            Ok(Exit::Continue) => {}
            other => panic!("{what}: interpreter stopped at step {step} of {n}: {other:?}"),
        }
    }
    diff(cpu_j.state(), cpu_i.state(), what);
    for (base, size) in regions(bits) {
        let (mut x, mut y) = (vec![0u8; size as usize], vec![0u8; size as usize]);
        mem_j.read(base, &mut x).unwrap();
        mem_i.read(base, &mut y).unwrap();
        for i in 0..x.len() {
            assert_eq!(
                x[i], y[i],
                "{what}: mem[{:#x}] jit={:#04x} interp={:#04x}",
                base + i as u64,
                x[i],
                y[i]
            );
        }
    }
    n
}

/// The state the JIT alone leaves after one block — used where the case wants
/// to pin the *value*, not merely that the two engines agree on it.
fn jit_only(bits: Bits, at: u64, code: &[u8], s: &CpuState) -> CpuState {
    let (mut mem, mut cpu) = build(bits, at, code, s);
    let mut jit = Jit::new(64 * 1024).unwrap();
    jit.run(cpu.state_mut(), &mut mem, mode_of(bits), 1);
    cpu.state().clone()
}

/// A seed whose registers are ordinary values, so a case's own setup is the
/// only thing that puts anything near a boundary.
fn seed(bits: Bits) -> CpuState {
    let mut s = CpuState::new();
    for (i, g) in s.gpr.iter_mut().enumerate() {
        *g = 0x0011_2233_4400_0000u64.wrapping_add((i as u64) << 8) | 0x0f;
    }
    if bits == Bits::B32 {
        for g in s.gpr.iter_mut() {
            *g &= 0xffff_ffff;
        }
    }
    s.rflags = exemu_core::cpu::flags::RESERVED_ONE;
    s
}

#[test]
fn a_near_branch_wraps_at_2_32_in_32_bit_mode() {
    let s = seed(Bits::B32);

    // `jmp rel32` whose arithmetic carries past 4 GiB: 0xFFFFF005 + 0x1000.
    let mut code = vec![0xE9];
    code.extend_from_slice(&0x1000i32.to_le_bytes());
    parity(Bits::B32, TOP32, &code, "jmp rel32 across 2^32", &s);
    if jit_available() {
        assert_eq!(
            jit_only(Bits::B32, TOP32, &code, &s).rip,
            0x5,
            "the JIT must leave a 32-bit EIP, not a 33-bit value"
        );
    }

    // `jmp rel8` from the last sixteen bytes below the boundary.
    parity(Bits::B32, 0xFFFF_FFF0, &[0xEB, 0x7F], "jmp rel8 across 2^32", &s);

    // `jcc rel8`, both edges: the taken side wraps, the fall-through does not.
    let mut taken = s.clone();
    taken.rflags |= exemu_core::cpu::flags::ZF;
    parity(Bits::B32, 0xFFFF_FFF0, &[0x74, 0x7F], "je rel8 taken across 2^32", &taken);
    parity(Bits::B32, 0xFFFF_FFF0, &[0x74, 0x7F], "je rel8 not taken", &s);

    // `jcc rel32`.
    let mut jcc32 = vec![0x0F, 0x84];
    jcc32.extend_from_slice(&0x1000i32.to_le_bytes());
    parity(Bits::B32, TOP32, &jcc32, "je rel32 taken across 2^32", &taken);
    if jit_available() {
        assert_eq!(jit_only(Bits::B32, TOP32, &jcc32, &taken).rip, 0x6);
    }
}

#[test]
fn a_near_branch_keeps_all_64_bits_in_long_mode() {
    // The same encoding above 4 GiB must *not* be truncated: a JIT that masked
    // here would land at 0x105 instead of 0x1_0000_0105.
    let mut code = vec![0xE9];
    code.extend_from_slice(&0x100i32.to_le_bytes());
    let s = seed(Bits::B64);
    parity(Bits::B64, HIGH64, &code, "jmp rel32 above 4 GiB", &s);
    if jit_available() {
        assert_eq!(
            jit_only(Bits::B64, HIGH64, &code, &s).rip,
            HIGH64 + 0x105,
            "RIP is 64 bits in long mode"
        );
    }
}

#[test]
fn sequential_rip_wraps_at_2_32() {
    // An instruction ending exactly on the 4 GiB boundary: the *ordinary*
    // completion path has to wrap too, not only the branches.
    let code = [0x31, 0xC0]; // xor eax, eax
    let s = seed(Bits::B32);
    parity(Bits::B32, 0xFFFF_FFFE, &code, "fall through 2^32", &s);
    if jit_available() {
        let (mut mem, mut cpu) = build(Bits::B32, 0xFFFF_FFFE, &code, &s);
        let mut jit = Jit::new(64 * 1024).unwrap();
        jit.set_max_insns(1); // stop the block on the boundary itself
        jit.run(cpu.state_mut(), &mut mem, Mode::Protected, 1);
        assert_eq!(cpu.state().rip, 0, "EIP wraps to zero, not to 0x1_0000_0000");
    }
}

#[test]
fn the_stack_pointer_wraps_at_2_32() {
    // `push` from esp = 0 writes at 0xFFFFFFFC; the `pop` that follows carries
    // esp back across the boundary to 0. Both are sharp: without the mask the
    // store would go to 0xFFFF_FFFF_FFFF_FFFC, which is not mapped at all.
    let code = [
        0x50, // push eax
        0x5B, // pop ebx
        0xC3, // ret — declined, ends the block
    ];
    let mut s = seed(Bits::B32);
    s.gpr[4] = 0;
    let n = parity(Bits::B32, TOP32, &code, "push/pop across 2^32", &s);
    if jit_available() {
        assert_eq!(n, 2, "both the push and the pop must compile");
        let after = jit_only(Bits::B32, TOP32, &code, &s);
        assert_eq!(after.gpr[4], 0, "ESP wraps back to zero");
        assert_eq!(after.gpr[3], s.gpr[0], "the pop read back what the push wrote");
    }

    // `leave` takes the same path through ebp.
    let mut s2 = seed(Bits::B32);
    s2.gpr[5] = 0xFFFF_FFFC; // ebp
    s2.gpr[4] = 0x10;
    parity(Bits::B32, TOP32, &[0xC9, 0xC3], "leave across 2^32", &s2);

    // `push imm32` from the same edge.
    let mut pushi = vec![0x68];
    pushi.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    pushi.push(0xC3);
    let mut s3 = seed(Bits::B32);
    s3.gpr[4] = 0;
    parity(Bits::B32, TOP32, &pushi, "push imm32 across 2^32", &s3);
}

#[test]
fn an_effective_address_wraps_at_2_32() {
    // base + disp carries past 4 GiB, so the access lands in page zero — and
    // `lea`, the same computation without the access, must produce the *masked*
    // address as its value.
    let code = [
        0x8B, 0x43, 0x10, // mov eax, [ebx+0x10]
        0x89, 0x43, 0x20, // mov [ebx+0x20], eax
        0x8D, 0x4B, 0x30, // lea ecx, [ebx+0x30]
        0xC3,
    ];
    let mut s = seed(Bits::B32);
    s.gpr[3] = 0xFFFF_FFF8; // ebx
    let n = parity(Bits::B32, TOP32, &code, "wrapping effective address", &s);
    if jit_available() {
        assert_eq!(n, 3);
        assert_eq!(
            jit_only(Bits::B32, TOP32, &code, &s).gpr[1],
            0x28,
            "lea produces the 32-bit address"
        );
    }

    // The SIB form, where the index scaling is what carries the address over.
    let sib = [
        0x8B, 0x04, 0x73, // mov eax, [ebx+esi*2]
        0x8D, 0x14, 0xB3, // lea edx, [ebx+esi*4]
        0xC3,
    ];
    let mut s2 = seed(Bits::B32);
    s2.gpr[3] = 0xFFFF_FFF0; // ebx
    s2.gpr[6] = 0x10; // esi
    parity(Bits::B32, TOP32, &sib, "wrapping SIB address", &s2);

    // The absolute `disp32` form (`mod=00 rm=101`, which is RIP-relative in
    // long mode): a negative displacement is sign-extended to 64 bits and then
    // masked back down.
    let mut abs = vec![0x8B, 0x05];
    abs.extend_from_slice(&(-0x10i32).to_le_bytes()); // mov eax, [0xFFFFFFF0]
    abs.push(0xC3);
    parity(Bits::B32, TOP32, &abs, "negative absolute disp32", &s);
}

#[test]
fn addresses_above_4_gib_survive_in_long_mode() {
    let code = [
        0x48, 0x8B, 0x43, 0x10, // mov rax, [rbx+0x10]
        0x48, 0x89, 0x43, 0x20, // mov [rbx+0x20], rax
        0x48, 0x8D, 0x4B, 0x30, // lea rcx, [rbx+0x30]
        0x50, // push rax
        0x5A, // pop rdx
        0xC3,
    ];
    let mut s = seed(Bits::B64);
    s.gpr[3] = HIGH64 + 0x100; // rbx
    s.gpr[4] = HIGH64 + 0x1000; // rsp
    let n = parity(Bits::B64, HIGH64, &code, "addresses above 4 GiB", &s);
    if jit_available() {
        assert_eq!(n, 5);
        let after = jit_only(Bits::B64, HIGH64, &code, &s);
        assert_eq!(after.gpr[1], HIGH64 + 0x130, "lea keeps the high half");
        assert_eq!(after.gpr[4], HIGH64 + 0x1000, "rsp round-trips above 4 GiB");
    }
}

#[test]
fn an_instruction_running_past_executable_memory_is_not_compiled() {
    // The compiler fetches a 16-byte window and falls back to a byte-at-a-time
    // fill when the wide fetch overruns the region. The bytes it could *not*
    // fetch must not be decoded: here only `8B 05` is readable and the four
    // displacement bytes lie past the end of the mapping. The interpreter
    // faults fetching the third byte; a compiler that decoded the zero-filled
    // tail of its own window would instead run `mov eax, [0]` — a fabricated
    // instruction, at a real address, that succeeds.
    if !jit_available() {
        return;
    }
    let code = [0x8B, 0x05]; // the first two bytes of `mov eax, [disp32]`
    let s = seed(Bits::B32);
    let at = 0xFFFF_FFFE;
    let (mem, _) = build(Bits::B32, at, &code, &s);
    let plan = exemu_jit::compile::Compiler::compile(&mem, Mode::Protected, at, 64, None);
    assert_eq!(
        plan.insns, 0,
        "an instruction whose encoding runs past executable memory must not compile"
    );

    // End to end: the JIT declines and the interpreter raises the real fault.
    let (mut mem_j, mut cpu_j) = build(Bits::B32, at, &code, &s);
    let mut jit = Jit::new(64 * 1024).unwrap();
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, Mode::Protected, 1);
    assert_eq!(run, Run::NotCompiled, "nothing at this address is compilable");
    assert_eq!(cpu_j.state().rip, at, "a declined block leaves rip alone");
    let (mut mem_i, mut cpu_i) = build(Bits::B32, at, &code, &s);
    let mut hooks = NoHooks;
    assert!(
        cpu_i.step(&mut mem_i, &mut hooks).is_err(),
        "the interpreter must fault fetching the truncated instruction"
    );
}

#[test]
fn a_block_that_ends_on_2_32_still_sees_a_store_into_its_own_code() {
    // A block's guest byte range is what the store helper compares against to
    // notice that an instruction has just rewritten one the block has not run
    // yet. That range used to be derived from the address the block *ends* at —
    // which, for a block whose last instruction ends on the 4 GiB boundary, has
    // wrapped round to something **lower than the block's own start**. Clamped,
    // it collapsed to nothing, so no store could ever hit it and the block
    // carried on executing instructions the guest had overwritten a moment
    // earlier. The interpreter, of course, decoded the new bytes.
    //
    // Found by the differential once trials were assembled at the top of the
    // address space (roadmap W8.7): three separate divergences in 100k trials,
    // all this.
    if !jit_available() {
        return;
    }
    let at = 0xFFFF_FFF0u64;
    let mut code = vec![
        0xBD, 0xF0, 0xFF, 0xFF, 0xFF, // mov ebp, 0xFFFFFFF0
        0x89, 0x6D, 0x0C, // mov [ebp+0x0c], ebp   -> stores over the last 4 bytes
    ];
    code.resize(0x10, 0x90); // nops out to the 4 GiB boundary
    let s = seed(Bits::B32);

    // The compiler must not run past the boundary either: a block is one
    // contiguous byte range, so it stops where the address space wraps.
    let (mem, _) = build(Bits::B32, at, &code, &s);
    let plan = exemu_jit::compile::Compiler::compile(&mem, Mode::Protected, at, 64, None);
    assert_eq!(plan.stop, exemu_jit::StopReason::Wrapped);
    assert_eq!(plan.bytes, 0x10, "the block covers exactly the bytes it compiled");

    let n = parity(Bits::B32, at, &code, "store into a block that ends on 2^32", &s);
    assert_eq!(n, 2, "the block must commit the store and stop, not run the stale nops");
}
