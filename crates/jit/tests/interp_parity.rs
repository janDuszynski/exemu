use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const DECLINED: u8 = 0xF4;

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
    mem.map(Region::new("teb32", TEB32, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("teb64", TEB64, 0x1000, Perm::RW)).unwrap();
    mem.poke(CODE, code).unwrap();
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
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode, 1);
    let n = match run {
        Run::NotCompiled => panic!("{what}: the JIT compiled nothing at all"),
        Run::Executed { insns } | Run::SideExit { insns } | Run::Faulted { insns } => insns,
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

fn seed(bits: Bits) -> CpuState {
    let mut s = CpuState::new();
    for (i, g) in s.gpr.iter_mut().enumerate() {
        *g = 0x1122_3344_5566_0000u64.wrapping_add((i as u64) << 8) | 0x0f;
    }
    s.gpr[4] = 0x3_1000;
    s.gpr[5] = 0x3_0F00;
    s.gpr[3] = DATA + 0x40;
    s.gpr[6] = DATA + 0x80;
    s.gpr[7] = DATA + 0xC0;
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
    let disp = (DATA as i64 - (CODE as i64 + 6)) as i32;
    let mut code = vec![0x8B, 0x05];
    code.extend_from_slice(&disp.to_le_bytes());
    let d2 = (DATA as i64 + 0x40 - (CODE as i64 + 12)) as i32;
    code.extend_from_slice(&[0x01, 0x05]);
    code.extend_from_slice(&d2.to_le_bytes());
    let d3 = (DATA as i64 + 0x80 - (CODE as i64 + 19)) as i32;
    code.extend_from_slice(&[0x0F, 0xB6, 0x0D]);
    code.extend_from_slice(&d3.to_le_bytes());
    code.push(DECLINED);
    let n = parity(Bits::B64, &code, "rip-relative", &seed(Bits::B64));
    assert!(n == 3 || !jit_available(), "expected all three compiled, got {n}");
}

#[test]
fn gs_relative_teb_access_64bit() {
    let code = [
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00,
        0x65, 0x48, 0x89, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00,
        DECLINED,
    ];
    parity(Bits::B64, &code, "gs: TEB access", &seed(Bits::B64));
}

#[test]
fn fs_relative_teb_access_32bit() {
    let code = [
        0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,
        DECLINED,
    ];
    let code2 = [
        0x64, 0x8B, 0x05, 0x18, 0x00, 0x00, 0x00,
        0x64, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x89, 0x05, 0x04, 0x00, 0x00, 0x00,
        DECLINED,
    ];
    let _ = code;
    parity(Bits::B32, &code2, "fs: TEB access", &seed(Bits::B32));
}

#[test]
fn high_byte_registers() {
    let code = [
        0x00, 0xFC,
        0x88, 0xE1,
        0x30, 0xCE,
        0x38, 0xF4,
        DECLINED,
    ];
    parity(Bits::B64, &code, "high-8 registers (64-bit)", &seed(Bits::B64));
    parity(Bits::B32, &code, "high-8 registers (32-bit)", &seed(Bits::B32));
}

#[test]
fn byte_and_word_arithmetic_flags() {
    let code = [
        0x04, 0x7F,
        0x80, 0xE9, 0x80,
        0x66, 0x05, 0xFF, 0x7F,
        0x66, 0x81, 0xEA, 0x00, 0x80,
        0x38, 0xFB,
        DECLINED,
    ];
    parity(Bits::B64, &code, "8/16-bit flags", &seed(Bits::B64));
    parity(Bits::B32, &code, "8/16-bit flags (32-bit)", &seed(Bits::B32));
}

#[test]
fn shift_of_zero_touches_no_flag() {
    let code = [
        0xC1, 0xE0, 0x00,
        0xC1, 0xE9, 0x00,
        0xC1, 0xFA, 0x00,
        DECLINED,
    ];
    parity(Bits::B64, &code, "shift by zero", &seed(Bits::B64));
}

#[test]
fn shift_edges() {
    let code = [
        0xD1, 0xE0,
        0xD1, 0xE9,
        0xD1, 0xFA,
        0xC1, 0xE3, 0x1F,
        0xC0, 0xE6, 0x1F,
        0x48, 0xC1, 0xEF, 0x3F,
        0x48, 0xC1, 0xFE, 0x3F,
        DECLINED,
    ];
    parity(Bits::B64, &code, "shift edges", &seed(Bits::B64));
}

#[test]
fn inc_dec_preserve_carry() {
    let code = [
        0x48, 0xFF, 0xC0,
        0x48, 0xFF, 0xC9,
        0xFE, 0xC2,
        0x66, 0xFF, 0xCB,
        DECLINED,
    ];
    let mut s = seed(Bits::B64);
    parity(Bits::B64, &code, "inc/dec with CF set", &s);
    s.rflags &= !exemu_core::cpu::flags::CF;
    parity(Bits::B64, &code, "inc/dec with CF clear", &s);
}

#[test]
fn cmov_writes_its_destination_either_way() {
    let code = [
        0x0F, 0x44, 0xC1,
        0x0F, 0x45, 0xD3,
        0x48, 0x0F, 0x42, 0xF7,
        DECLINED,
    ];
    let mut s = seed(Bits::B64);
    parity(Bits::B64, &code, "cmov (ZF clear)", &s);
    s.rflags |= exemu_core::cpu::flags::ZF;
    parity(Bits::B64, &code, "cmov (ZF set)", &s);
}

#[test]
fn push_pop_including_the_stack_pointer_itself() {
    let code = [
        0x50,
        0x54,
        0x5B,
        0x5C,
        0x55,
        0x5D,
        DECLINED,
    ];
    parity(Bits::B64, &code, "push/pop 64-bit", &seed(Bits::B64));
    parity(Bits::B32, &code, "push/pop 32-bit", &seed(Bits::B32));
}

#[test]
fn imul_overflow_flags() {
    let code = [
        0x0F, 0xAF, 0xC1,
        0x48, 0x0F, 0xAF, 0xD3,
        0x6B, 0xF7, 0x7F,
        0x69, 0xFE, 0x00, 0x00, 0x01, 0x00,
        DECLINED,
    ];
    parity(Bits::B64, &code, "imul", &seed(Bits::B64));
}

#[test]
fn absolute_disp32_addressing_in_32bit_mode() {
    let a = (DATA + 0x40) as u32;
    let b = (DATA + 0x44) as u32;
    let mut code = vec![0x8B, 0x05];
    code.extend_from_slice(&a.to_le_bytes());
    code.extend_from_slice(&[0x01, 0x05]);
    code.extend_from_slice(&b.to_le_bytes());
    code.push(DECLINED);
    parity(Bits::B32, &code, "absolute disp32", &seed(Bits::B32));
}

#[test]
fn sib_addressing_with_every_scale() {
    let code = [
        0x8B, 0x04, 0x33,
        0x8B, 0x0C, 0x73,
        0x8B, 0x14, 0xB3,
        0x8B, 0x3C, 0xF3,
        0x8B, 0x6B, 0xF0,
        0x8B, 0x83, 0x00, 0x01, 0x00, 0x00,
        DECLINED,
    ];
    let mut s = seed(Bits::B64);
    s.gpr[6] = 8;
    parity(Bits::B64, &code, "SIB scales", &s);
}

#[test]
fn deferred_flags_are_visible_at_a_faulting_load() {
    let code = [
        0x48, 0x01, 0xC8,
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0xAD, 0xDE,
        0x48, 0x8B, 0x32,
        0x4D, 0x31, 0xC0,
    ];
    parity(Bits::B64, &code, "deferred flags at a faulting load", &seed(Bits::B64));
}

#[test]
fn deferred_flags_are_visible_at_a_faulting_store() {
    let code = [
        0x48, 0x01, 0xC8,
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0xAD, 0xDE,
        0x48, 0x89, 0x32,
        0x4D, 0x31, 0xC0,
    ];
    parity(Bits::B64, &code, "deferred flags at a faulting store", &seed(Bits::B64));
}

#[test]
fn deferred_flags_are_visible_when_a_store_rewrites_the_block() {
    let code = [
        0x48, 0x01, 0xC8,
        0x80, 0x04, 0x25, 0x0E, 0x00, 0x01, 0x00, 0x07,
        0x4D, 0x31, 0xC0,
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
    let code = [
        0x01, 0xC8,
        0x29, 0xD8,
        0x21, 0xF0,
        0x09, 0xF8,
        0x31, 0xD0,
        0x85, 0xC0,
        0x39, 0xC8,
    ];
    parity(Bits::B64, &code, "alu chain 64", &seed(Bits::B64));
    parity(Bits::B32, &code, "alu chain 32", &seed(Bits::B32));
}

#[test]
fn a_superseded_flag_result_costs_no_code() {
    if !jit_available() {
        return;
    }
    let one = compile_len(&[0x01, 0xC8, DECLINED]);
    let eight = compile_len(&[
        0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8,
        0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8, 0x01, 0xC8,
        DECLINED,
    ]);
    let marginal = (eight - one) as f64 / 7.0;
    assert!(
        marginal <= 6.0,
        "an `add` whose flags are dead costs {marginal:.1} ARM64 words \
         (one={one}, eight={eight}) — the flag computation is not being elided"
    );
}

fn compile_len(code: &[u8]) -> usize {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.poke(CODE, code).unwrap();
    exemu_jit::compile::Compiler::compile(&mem, Mode::Long, CODE, 64, None, u64::MAX).code.len()
}

#[test]
fn push_immediate_and_leave() {
    let code = [
        0x6A, 0x7F,
        0x68, 0xEF, 0xBE, 0xAD, 0xDE,
        0xC9,
        DECLINED,
    ];
    parity(Bits::B64, &code, "push imm / leave 64", &seed(Bits::B64));
    parity(Bits::B32, &code, "push imm / leave 32", &seed(Bits::B32));
}

#[test]
fn mov_to_and_from_an_absolute_offset() {
    let a = DATA + 0x100;
    let mut code = vec![0x48, 0xA1];
    code.extend_from_slice(&a.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xA3]);
    code.extend_from_slice(&(a + 8).to_le_bytes());
    code.push(0xA0);
    code.extend_from_slice(&(a + 0x20).to_le_bytes());
    code.push(0xA2);
    code.extend_from_slice(&(a + 0x21).to_le_bytes());
    code.push(DECLINED);
    parity(Bits::B64, &code, "moffs 64", &seed(Bits::B64));

    let mut code32 = vec![0xA1];
    code32.extend_from_slice(&(a as u32).to_le_bytes());
    code32.push(0xA3);
    code32.extend_from_slice(&((a + 4) as u32).to_le_bytes());
    code32.push(DECLINED);
    parity(Bits::B32, &code32, "moffs 32", &seed(Bits::B32));
}

#[test]
fn mov_from_an_absolute_offset_through_a_segment_base() {
    let mut code = vec![0x65, 0x48, 0xA1];
    code.extend_from_slice(&0x28u64.to_le_bytes());
    code.push(DECLINED);
    parity(Bits::B64, &code, "gs moffs 64", &seed(Bits::B64));

    let mut code32 = vec![0x64, 0xA1];
    code32.extend_from_slice(&0x18u32.to_le_bytes());
    code32.push(0x64);
    code32.push(0xA3);
    code32.extend_from_slice(&0x1Cu32.to_le_bytes());
    code32.push(DECLINED);
    parity(Bits::B32, &code32, "fs moffs 32", &seed(Bits::B32));
}

#[test]
fn a_direct_call_pushes_the_return_address_and_lands_on_its_target() {
    let mut code = vec![0xE8, 0x05, 0x00, 0x00, 0x00];
    code.extend_from_slice(&[0x90; 5]);
    code.push(DECLINED);
    parity(Bits::B64, &code, "call rel32 64", &seed(Bits::B64));
    parity(Bits::B32, &code, "call rel32 32", &seed(Bits::B32));
}

#[test]
fn an_indirect_jump_and_call_take_their_target_from_the_operand() {
    let target = CODE + 0x40;

    let mut s = seed(Bits::B64);
    s.gpr[0] = target;
    parity(Bits::B64, &[0xFF, 0xE0], "jmp rax", &s);
    parity(Bits::B64, &[0xFF, 0xD0], "call rax", &s);
    let mut s32 = seed(Bits::B32);
    s32.gpr[0] = target;
    parity(Bits::B32, &[0xFF, 0xE0], "jmp eax", &s32);
    parity(Bits::B32, &[0xFF, 0xD0], "call eax", &s32);

    parity(Bits::B64, &[0xFF, 0x23], "jmp [rbx]", &seed(Bits::B64));
    parity(Bits::B64, &[0xFF, 0x13], "call [rbx]", &seed(Bits::B64));
    parity(Bits::B32, &[0xFF, 0x23], "jmp [ebx]", &seed(Bits::B32));
    parity(Bits::B32, &[0xFF, 0x13], "call [ebx]", &seed(Bits::B32));
}

#[test]
fn an_indirect_call_through_the_stack_reads_its_operand_before_it_pushes() {
    let mut s = seed(Bits::B64);
    s.gpr[4] = 0x3_0F00;
    parity(Bits::B64, &[0xFF, 0x14, 0x24], "call [rsp] 64", &s);
    let mut s32 = seed(Bits::B32);
    s32.gpr[4] = 0x3_0F00;
    parity(Bits::B32, &[0xFF, 0x14, 0x24], "call [esp] 32", &s32);
}

#[test]
fn a_return_lands_on_the_address_that_was_pushed() {
    let mut code = vec![0x68];
    code.extend_from_slice(&((CODE + 0x40) as u32).to_le_bytes());
    code.push(0xC3);
    for (bits, mode) in [(Bits::B64, Mode::Long), (Bits::B32, Mode::Protected)] {
        let s = seed(bits);
        let n = parity(bits, &code, "push then ret", &s);
        if !jit_available() {
            continue;
        }
        assert_eq!(n, 2, "the push and the ret both compile");
        let (mut mem, mut cpu) = build_with(bits, &code, &s, Perm::RX);
        let mut jit = Jit::new(64 * 1024).expect("JIT should be available");
        jit.run(cpu.state_mut(), &mut mem, mode, 1);
        assert_eq!(cpu.state().rip, CODE + 0x40, "the ret took the pushed address");
        assert_eq!(cpu.state().gpr[4], s.gpr[4], "a push and a ret leave rsp where it was");
    }
}

#[test]
fn a_return_releases_the_bytes_its_immediate_names() {
    for extra in [0u16, 8, 0x0FF8, 0x1000, 0xFFFF] {
        let mut code = vec![0x68];
        code.extend_from_slice(&((CODE + 0x40) as u32).to_le_bytes());
        code.push(0xC2);
        code.extend_from_slice(&extra.to_le_bytes());
        let what = format!("push then ret {extra:#x}");
        for (bits, mode) in [(Bits::B64, Mode::Long), (Bits::B32, Mode::Protected)] {
            let s = seed(bits);
            let n = parity(bits, &code, &what, &s);
            if !jit_available() {
                continue;
            }
            assert_eq!(n, 2, "{what}: both compile");
            let (mut mem, mut cpu) = build_with(bits, &code, &s, Perm::RX);
            let mut jit = Jit::new(64 * 1024).expect("JIT should be available");
            jit.run(cpu.state_mut(), &mut mem, mode, 1);
            assert_eq!(cpu.state().rip, CODE + 0x40, "{what}: target");
            assert_eq!(
                cpu.state().gpr[4],
                s.gpr[4] + u64::from(extra),
                "{what}: rsp released the immediate on top of the return address"
            );
        }
    }
}

#[test]
fn a_return_whose_pop_faults_rewinds_onto_the_ret() {
    if !jit_available() {
        return;
    }
    for (bits, mode) in [(Bits::B64, Mode::Long), (Bits::B32, Mode::Protected)] {
        let mut s = seed(bits);
        s.gpr[4] = 0xDEAD_0000;
        let (mut mem, mut cpu) = build_with(bits, &[0xC3], &s, Perm::RX);
        let mut jit = Jit::new(64 * 1024).expect("JIT should be available");
        let run = jit.run(cpu.state_mut(), &mut mem, mode, 1);
        assert_eq!(run, Run::Faulted { insns: 0 }, "{bits:?}: the faulting ret must rewind");
        assert_eq!(cpu.state().rip, CODE, "{bits:?}: rip rewound onto the ret");
        assert_eq!(cpu.state().gpr[4], 0xDEAD_0000, "{bits:?}: rsp is untouched");

        let (mut mem_i, mut cpu_i) = build_with(bits, &[0xC3], &s, Perm::RX);
        let mut hooks = NoHooks;
        assert!(cpu_i.step(&mut mem_i, &mut hooks).is_err(), "{bits:?}: the interpreter faults too");
    }
}

#[test]
fn an_indirect_call_whose_push_faults_rewinds() {
    if !jit_available() {
        return;
    }
    let mut s = seed(Bits::B64);
    s.gpr[0] = CODE + 0x40;
    s.gpr[4] = 0x3_0000;
    let (mut mem, mut cpu) = build_with(Bits::B64, &[0xFF, 0xD0], &s, Perm::RX);
    let mut jit = Jit::new(64 * 1024).expect("JIT should be available");
    let run = jit.run(cpu.state_mut(), &mut mem, Mode::Long, 1);
    assert_eq!(run, Run::Faulted { insns: 0 }, "the faulting call must rewind");
    assert_eq!(cpu.state().rip, CODE, "rip rewound onto the call");
    assert_eq!(cpu.state().gpr[4], 0x3_0000, "rsp is untouched");
}

#[test]
fn a_conditional_branch_lands_on_the_right_side() {
    for (name, seed_flags) in [("taken", true), ("not taken", false)] {
        let code = [
            0x39, 0xC0,
            0x74, 0x02,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            DECLINED,
        ];
        let mut s = seed(Bits::B64);
        if !seed_flags {
            s.gpr[0] = 0;
        }
        parity(Bits::B64, &code, name, &s);
    }
}

fn ro_data(bits: Bits, code: &[u8], seed: &CpuState) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::READ)).unwrap();
    mem.map(Region::new("stack", 0x3_0000, 0x2000, Perm::RW)).unwrap();
    mem.poke(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(bits);
    *cpu.state_mut() = seed.clone();
    cpu.state_mut().rip = CODE;
    (mem, cpu)
}

fn store_fault_parity(bits: Bits, code: &[u8], expect_retired: u32, what: &str) {
    if !jit_available() {
        return;
    }
    let seed = CpuState {
        rflags: 0x896,
        gpr: {
            let mut g = [0u64; 16];
            g[4] = 0x3_1000;
            g[7] = DATA;
            g
        },
        ..CpuState::default()
    };
    let (mut mem_j, mut cpu_j) = ro_data(bits, code, &seed);
    let mode = match bits {
        Bits::B64 => Mode::Long,
        Bits::B32 => Mode::Protected,
    };
    let mut jit = Jit::new(1 << 20).unwrap();
    let ran = jit.run(cpu_j.state_mut(), &mut mem_j, mode, 1);
    assert_eq!(ran, Run::Faulted { insns: expect_retired }, "{what}: {ran:?}");

    let (mut mem_i, mut cpu_i) = ro_data(bits, code, &seed);
    let mut hooks = NoHooks;
    for i in 0..expect_retired {
        assert!(
            matches!(cpu_i.step(&mut mem_i, &mut hooks), Ok(Exit::Continue)),
            "{what}: the interpreter stopped at instruction {i}"
        );
    }
    diff(cpu_j.state(), cpu_i.state(), what);
    assert!(cpu_i.step(&mut mem_i, &mut hooks).is_err(), "{what}: that store did not fault");
}

#[test]
fn a_store_only_fault_rewinds_the_flags_it_had_already_computed() {
    store_fault_parity(Bits::B64, &[0xFE, 0x07, DECLINED], 0, "inc byte [rdi] 64-bit");
    store_fault_parity(Bits::B32, &[0xFE, 0x07, DECLINED], 0, "inc byte [rdi] 32-bit");
    store_fault_parity(Bits::B64, &[0x01, 0x07, DECLINED], 0, "add [rdi], eax");
    store_fault_parity(Bits::B64, &[0x29, 0x07, DECLINED], 0, "sub [rdi], eax");
    store_fault_parity(Bits::B64, &[0x21, 0x07, DECLINED], 0, "and [rdi], eax");
    store_fault_parity(Bits::B64, &[0xF6, 0x1F, DECLINED], 0, "neg byte [rdi]");
    store_fault_parity(Bits::B64, &[0xD1, 0x27, DECLINED], 0, "shl dword [rdi], 1");
    store_fault_parity(Bits::B64, &[0x31, 0x07, DECLINED], 0, "xor [rdi], eax");
}

#[test]
fn a_store_only_fault_rewinds_to_a_deferred_flag_state() {
    let code = [0x83, 0xC0, 0x01, 0x01, 0x07, DECLINED];
    store_fault_parity(Bits::B64, &code, 1, "deferred then a faulting store 64-bit");
    store_fault_parity(Bits::B32, &code, 1, "deferred then a faulting store 32-bit");
}
