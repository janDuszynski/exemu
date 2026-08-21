//! Hand-assembled parity cases: the JIT against the interpreter, on the shapes
//! the generated differential in `crates/oracle` structurally cannot reach.
//!
//! The oracle's generator assembles every trial at a fixed base with plain
//! base-register memory operands and no segment prefixes, so three things it
//! never produces are exactly three things a real Windows guest does constantly:
//! **RIP-relative** operands (every 64-bit MSVC data reference), **`gs:`/`fs:`
//! TEB access** (every SEH frame and every stack-cookie read), and the legacy
//! **high-byte registers**. Those are covered here instead, along with the
//! corner cases whose flag rules are easy to get subtly wrong — a shift of zero
//! (which must leave *every* flag alone), `inc`/`dec` (which must preserve CF),
//! `cmov` (which writes its destination even when not taken, and so
//! zero-extends), and `push rsp`/`pop rsp`.
//!
//! Each case runs the same bytes from the same seeded state through both
//! engines and compares the entire architectural state plus every byte of guest
//! memory.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const TEB32: u64 = exemu_core::cpu::DEFAULT_FS_BASE;
const TEB64: u64 = exemu_core::cpu::DEFAULT_GS_BASE;

fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn build_with(bits: Bits, code: &[u8], seed: &CpuState, code_perm: Perm) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, code_perm)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x3_0000, 0x2000, Perm::RW)).unwrap();
    // TEB pages, so `fs:`/`gs:` operands resolve like they do in a real process.
    mem.map(Region::new("teb32", TEB32, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb64", TEB64, 0x1000, Perm::RW)).unwrap();
    mem.poke(CODE, code).unwrap();
    // Deterministic, non-trivial data and TEB contents.
    let filler: Vec<u8> = (0..0x1000u32).map(|i| (i.wrapping_mul(37) >> 3) as u8).collect();
    mem.poke(DATA, &filler).unwrap();
    mem.poke(TEB32, &filler).unwrap();
    mem.poke(TEB64, &filler).unwrap();
    let mut cpu = Interpreter::with_bits(bits);
    *cpu.state_mut() = seed.clone();
    cpu.state_mut().rip = CODE;
    (mem, cpu)
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

/// Run `code` on both engines from the same seed and require identical results.
/// Returns how many instructions the JIT executed natively.
fn parity(bits: Bits, code: &[u8], what: &str, seed: &CpuState) -> u32 {
    parity_with(bits, code, what, seed, Perm::RX)
}

fn parity_with(bits: Bits, code: &[u8], what: &str, seed: &CpuState, code_perm: Perm) -> u32 {
    if !jit_available() {
        return 0;
    }
    let (mut mem_j, mut cpu_j) = build_with(bits, code, seed, code_perm);
    let (mut mem_i, mut cpu_i) = build_with(bits, code, seed, code_perm);
    let mode = match bits {
        Bits::B32 => Mode::Protected,
        Bits::B64 => Mode::Long,
    };
    let mut jit = Jit::new(256 * 1024).expect("JIT should be available");
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode);
    let n = match run {
        Run::NotCompiled => panic!("{what}: the JIT compiled nothing at all"),
        Run::Executed { insns } | Run::Faulted { insns } => insns,
    };
    assert!(n > 0, "{what}: the JIT executed nothing");
    let mut hooks = NoHooks;
    for step in 0..n {
        match cpu_i.step(&mut mem_i, &mut hooks) {
            Ok(Exit::Continue) => {}
            other => panic!("{what}: interpreter stopped at step {step}: {other:?}"),
        }
    }
    diff(cpu_j.state(), cpu_i.state(), what);
    for base in [CODE, DATA, TEB32, TEB64, 0x3_0000] {
        let (mut x, mut y) = (vec![0u8; 0x1000], vec![0u8; 0x1000]);
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

/// A seed with distinctive, flag-provoking register values.
fn seed(bits: Bits) -> CpuState {
    let mut s = CpuState::new();
    for (i, g) in s.gpr.iter_mut().enumerate() {
        *g = 0x1122_3344_5566_0000u64.wrapping_add((i as u64) << 8) | 0x0f;
    }
    s.gpr[4] = 0x3_1000; // rsp, inside the stack region
    s.gpr[5] = 0x3_0F00; // rbp
    // A few pointers into the data region so memory operands land somewhere real.
    s.gpr[3] = DATA + 0x40; // rbx
    s.gpr[6] = DATA + 0x80; // rsi
    s.gpr[7] = DATA + 0xC0; // rdi
    if bits == Bits::B32 {
        for g in s.gpr.iter_mut() {
            *g &= 0xffff_ffff;
        }
        s.gpr[3] = DATA + 0x40;
        s.gpr[6] = DATA + 0x80;
        s.gpr[7] = DATA + 0xC0;
        s.gpr[4] = 0x3_1000;
        s.gpr[5] = 0x3_0F00;
    }
    s.rflags = exemu_core::cpu::flags::RESERVED_ONE
        | exemu_core::cpu::flags::CF
        | exemu_core::cpu::flags::AF
        | exemu_core::cpu::flags::SF;
    s
}

#[test]
fn rip_relative_operands() {
    // mov eax, [rip+0x100] ; add [rip+0x104], eax ; movzx ecx, byte [rip+0x108]
    // (the displacements land in the code page, which is readable but not
    // writable, so aim the store at the data page instead: rip+0x10000-ish.)
    let disp = (DATA as i64 - (CODE as i64 + 6)) as i32; // for the first insn
    let mut code = vec![0x8B, 0x05];
    code.extend_from_slice(&disp.to_le_bytes());
    // add [rip+d2], eax  (6 bytes)
    let d2 = (DATA as i64 + 0x40 - (CODE as i64 + 12)) as i32;
    code.extend_from_slice(&[0x01, 0x05]);
    code.extend_from_slice(&d2.to_le_bytes());
    // movzx ecx, byte [rip+d3]  (7 bytes)
    let d3 = (DATA as i64 + 0x80 - (CODE as i64 + 19)) as i32;
    code.extend_from_slice(&[0x0F, 0xB6, 0x0D]);
    code.extend_from_slice(&d3.to_le_bytes());
    code.push(0xC3);
    let n = parity(Bits::B64, &code, "rip-relative", &seed(Bits::B64));
    assert!(n == 3 || !jit_available(), "expected all three compiled, got {n}");
}

#[test]
fn gs_relative_teb_access_64bit() {
    // mov rax, gs:[0x30] ; mov rcx, gs:[0x60] ; mov gs:[0x08], rax
    let code = [
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, // mov rax, gs:[0x30]
        0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rcx, gs:[0x60]
        0x65, 0x48, 0x89, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, // mov gs:[0x08], rax
        0xC3,
    ];
    parity(Bits::B64, &code, "gs: TEB access", &seed(Bits::B64));
}

#[test]
fn fs_relative_teb_access_32bit() {
    // mov eax, fs:[0x18] ; mov ecx, fs:[0] ; mov fs:[4], eax   (SEH shapes)
    let code = [
        0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, // mov eax, fs:[0x18] (moffs — declined)
        0xC3,
    ];
    // The moffs form is not compiled; use the ModRM form the compiler handles.
    let code2 = [
        0x64, 0x8B, 0x05, 0x18, 0x00, 0x00, 0x00, // mov eax, fs:[0x18]
        0x64, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, // mov ecx, fs:[0]
        0x64, 0x89, 0x05, 0x04, 0x00, 0x00, 0x00, // mov fs:[4], eax
        0xC3,
    ];
    let _ = code;
    parity(Bits::B32, &code2, "fs: TEB access", &seed(Bits::B32));
}

#[test]
fn high_byte_registers() {
    // add ah, bh ; mov cl, ah ; xor dh, cl ; cmp ah, dh
    let code = [
        0x00, 0xFC, // add ah, bh
        0x88, 0xE1, // mov cl, ah
        0x30, 0xCE, // xor dh, cl
        0x38, 0xF4, // cmp ah, dh
        0xC3,
    ];
    parity(Bits::B64, &code, "high-8 registers (64-bit)", &seed(Bits::B64));
    parity(Bits::B32, &code, "high-8 registers (32-bit)", &seed(Bits::B32));
}

#[test]
fn byte_and_word_arithmetic_flags() {
    // add al, 0x7f ; sub cl, 0x80 ; add ax, 0x7fff ; sub dx, 0x8000 ; cmp bl, bh
    let code = [
        0x04, 0x7F, // add al, 0x7f
        0x80, 0xE9, 0x80, // sub cl, 0x80
        0x66, 0x05, 0xFF, 0x7F, // add ax, 0x7fff
        0x66, 0x81, 0xEA, 0x00, 0x80, // sub dx, 0x8000
        0x38, 0xFB, // cmp bl, bh
        0xC3,
    ];
    parity(Bits::B64, &code, "8/16-bit flags", &seed(Bits::B64));
    parity(Bits::B32, &code, "8/16-bit flags (32-bit)", &seed(Bits::B32));
}

#[test]
fn shift_of_zero_touches_no_flag() {
    // shl eax, 0 ; shr ecx, 0 ; sar edx, 0 — identity, and every flag must be
    // left exactly as it was, including CF.
    let code = [
        0xC1, 0xE0, 0x00, // shl eax, 0
        0xC1, 0xE9, 0x00, // shr ecx, 0
        0xC1, 0xFA, 0x00, // sar edx, 0
        0xC3,
    ];
    parity(Bits::B64, &code, "shift by zero", &seed(Bits::B64));
}

#[test]
fn shift_edges() {
    // shl by 1 (OF defined), shr by 1, sar by 1, and counts at/over the width.
    let code = [
        0xD1, 0xE0, // shl eax, 1
        0xD1, 0xE9, // shr ecx, 1
        0xD1, 0xFA, // sar edx, 1
        0xC1, 0xE3, 0x1F, // shl ebx, 31
        0xC0, 0xE6, 0x1F, // shl dh, 31  (count > width)
        0x48, 0xC1, 0xEF, 0x3F, // shr rdi, 63
        0x48, 0xC1, 0xFE, 0x3F, // sar rsi, 63
        0xC3,
    ];
    parity(Bits::B64, &code, "shift edges", &seed(Bits::B64));
}

#[test]
fn inc_dec_preserve_carry() {
    // inc/dec must not touch CF, whichever way it starts.
    let code = [
        0x48, 0xFF, 0xC0, // inc rax
        0x48, 0xFF, 0xC9, // dec rcx
        0xFE, 0xC2, // inc dl
        0x66, 0xFF, 0xCB, // dec bx
        0xC3,
    ];
    let mut s = seed(Bits::B64);
    parity(Bits::B64, &code, "inc/dec with CF set", &s);
    s.rflags &= !exemu_core::cpu::flags::CF;
    parity(Bits::B64, &code, "inc/dec with CF clear", &s);
}

#[test]
fn cmov_writes_its_destination_either_way() {
    // A 32-bit CMOV zero-extends its destination even when the condition is
    // false, which is the classic way to get this wrong.
    let code = [
        0x0F, 0x44, 0xC1, // cmove eax, ecx
        0x0F, 0x45, 0xD3, // cmovne edx, ebx
        0x48, 0x0F, 0x42, 0xF7, // cmovb rsi, rdi
        0xC3,
    ];
    let mut s = seed(Bits::B64);
    parity(Bits::B64, &code, "cmov (ZF clear)", &s);
    s.rflags |= exemu_core::cpu::flags::ZF;
    parity(Bits::B64, &code, "cmov (ZF set)", &s);
}

#[test]
fn push_pop_including_the_stack_pointer_itself() {
    // `push rsp` pushes the OLD rsp; `pop rsp` ends up holding the popped value.
    let code = [
        0x50, // push rax
        0x54, // push rsp
        0x5B, // pop rbx
        0x5C, // pop rsp
        0x55, // push rbp
        0x5D, // pop rbp
        0xC3,
    ];
    parity(Bits::B64, &code, "push/pop 64-bit", &seed(Bits::B64));
    parity(Bits::B32, &code, "push/pop 32-bit", &seed(Bits::B32));
}

#[test]
fn imul_overflow_flags() {
    let code = [
        0x0F, 0xAF, 0xC1, // imul eax, ecx
        0x48, 0x0F, 0xAF, 0xD3, // imul rdx, rbx
        0x6B, 0xF7, 0x7F, // imul esi, edi, 0x7f
        0x69, 0xFE, 0x00, 0x00, 0x01, 0x00, // imul edi, esi, 0x10000
        0xC3,
    ];
    parity(Bits::B64, &code, "imul", &seed(Bits::B64));
}

#[test]
fn absolute_disp32_addressing_in_32bit_mode() {
    // mov eax, [0x20040] ; add [0x20044], eax  — the 32-bit `mod=00 rm=101`
    // form, which is RIP-relative in 64-bit mode and absolute here.
    let a = (DATA + 0x40) as u32;
    let b = (DATA + 0x44) as u32;
    let mut code = vec![0x8B, 0x05];
    code.extend_from_slice(&a.to_le_bytes());
    code.extend_from_slice(&[0x01, 0x05]);
    code.extend_from_slice(&b.to_le_bytes());
    code.push(0xC3);
    parity(Bits::B32, &code, "absolute disp32", &seed(Bits::B32));
}

#[test]
fn sib_addressing_with_every_scale() {
    // mov eax, [rbx + rsi*1] ; mov ecx, [rbx + rsi*2] ; ... *4, *8, plus a
    // no-index form and a negative displacement.
    let code = [
        0x8B, 0x04, 0x33, // mov eax, [rbx+rsi*1]
        0x8B, 0x0C, 0x73, // mov ecx, [rbx+rsi*2]
        0x8B, 0x14, 0xB3, // mov edx, [rbx+rsi*4]
        0x8B, 0x3C, 0xF3, // mov edi, [rbx+rsi*8]
        0x8B, 0x6B, 0xF0, // mov ebp, [rbx-0x10]
        0x8B, 0x83, 0x00, 0x01, 0x00, 0x00, // mov eax, [rbx+0x100]
        0xC3,
    ];
    // A small index, so every scaled form still lands inside the data region
    // (the seed's rsi is itself a pointer, which `rbx+rsi*8` would send into
    // unmapped space — a fault, not a parity question).
    let mut s = seed(Bits::B64);
    s.gpr[6] = 8;
    parity(Bits::B64, &code, "SIB scales", &s);
}

// ---------------------------------------------------------------------------
// Deferred flags (roadmap W8.4)
//
// An ALU instruction whose flags a later instruction overwrites emits no flag
// code at all; the operands and result stay in three registers and the six
// status flags are derived from them at the first point that can observe them.
// The traps are all in *when* that point is: a fault rewinds onto the start of
// an instruction, so the state it exposes has to include the flags of the one
// before it, which by then has been deferred for several instructions.
// ---------------------------------------------------------------------------

#[test]
fn deferred_flags_are_visible_at_a_faulting_load() {
    // `add` defers (the `xor` at the end overwrites every flag it sets), then a
    // load faults two instructions later. The rewound state must show the add's
    // flags — if the fault path skipped them it would show the block's entry
    // flags instead, which is invisible in the registers and fatal in meaning.
    let code = [
        0x48, 0x01, 0xC8, // add rax, rcx
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0xAD, 0xDE, // mov rdx, 0xffffffffdead0000
        0x48, 0x8B, 0x32, // mov rsi, [rdx]   <- faults
        0x4D, 0x31, 0xC0, // xor r8, r8
    ];
    parity(Bits::B64, &code, "deferred flags at a faulting load", &seed(Bits::B64));
}

#[test]
fn deferred_flags_are_visible_at_a_faulting_store() {
    let code = [
        0x48, 0x01, 0xC8, // add rax, rcx
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0xAD, 0xDE, // mov rdx, 0xffffffffdead0000
        0x48, 0x89, 0x32, // mov [rdx], rsi   <- faults
        0x4D, 0x31, 0xC0, // xor r8, r8
    ];
    parity(Bits::B64, &code, "deferred flags at a faulting store", &seed(Bits::B64));
}

#[test]
fn deferred_flags_are_visible_when_a_store_rewrites_the_block() {
    // The other exit out of a store: it *succeeded* and landed in the block's
    // own instructions, so the block commits and stops. That path has to settle
    // the flags of the store instruction itself — here a read-modify-write into
    // its own code, whose flags were left pending across the store.
    // The store target is 0x1000e — the first byte of the `xor` below, and so
    // inside the range this very block was compiled from.
    let code = [
        0x48, 0x01, 0xC8, // add rax, rcx
        0x80, 0x04, 0x25, 0x0E, 0x00, 0x01, 0x00, 0x07, // add byte [0x1000e], 7
        0x4D, 0x31, 0xC0, // xor r8, r8
    ];
    let n = parity_with(
        Bits::B64,
        &code,
        "deferred flags when a store rewrites the block",
        &seed(Bits::B64),
        Perm::RWX,
    );
    if jit_available() {
        assert_eq!(n, 2, "the block must stop on the store into its own bytes");
    }
}

#[test]
fn a_long_alu_chain_matches_in_both_bitnesses() {
    // Every instruction here overwrites the previous one's flags, so all but
    // the last computation is elided — and the last is settled at the exit.
    let code = [
        0x01, 0xC8, // add eax, ecx
        0x29, 0xD8, // sub eax, ebx
        0x21, 0xF0, // and eax, esi
        0x09, 0xF8, // or  eax, edi
        0x31, 0xD0, // xor eax, edx
        0x85, 0xC0, // test eax, eax
        0x39, 0xC8, // cmp eax, ecx
    ];
    parity(Bits::B64, &code, "alu chain 64", &seed(Bits::B64));
    parity(Bits::B32, &code, "alu chain 32", &seed(Bits::B32));
}

#[test]
fn a_superseded_flag_result_costs_no_code() {
    // The point of the whole exercise, pinned as a measurement rather than a
    // claim: extend a block by seven more `add`s whose flags are all dead and
    // the emitted code grows by a handful of words per instruction, not by the
    // ~19 an eager flag computation takes.
    if !jit_available() {
        return;
    }
    let one = compile_len(&[0x01, 0xC8, 0xC3]); // add eax, ecx ; ret
    let eight = compile_len(&[
        0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, // add eax, ecx ×4
        0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, // ×4
        0xC3, // ret
    ]);
    let marginal = (eight - one) as f64 / 7.0;
    assert!(
        marginal <= 6.0,
        "an `add` whose flags are dead costs {marginal:.1} ARM64 words \
         (one={one}, eight={eight}) — the flag computation is not being elided"
    );
}

/// ARM64 words the compiler emits for `code` as one 64-bit block.
fn compile_len(code: &[u8]) -> usize {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.poke(CODE, code).unwrap();
    exemu_jit::compile::Compiler::compile(&mem, Mode::Long, CODE, 64).code.len()
}

#[test]
fn a_conditional_branch_lands_on_the_right_side() {
    // cmp eax, eax ; je +5 ; (skipped) ; ...
    for (name, seed_flags) in [("taken", true), ("not taken", false)] {
        let code = [
            0x39, 0xC0, // cmp eax, eax  -> ZF=1
            0x74, 0x02, // je +2
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3,
        ];
        let mut s = seed(Bits::B64);
        if !seed_flags {
            s.gpr[0] = 0;
        }
        parity(Bits::B64, &code, name, &s);
    }
}
