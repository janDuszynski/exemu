use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::compile::{Compiler, MAX_INSNS};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const DECLINED: u8 = 0xF4;

const TOP32: u64 = 0xFFFF_F000;
const ZERO: u64 = 0x0;
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

fn block_len(mem: &VirtualMemory, bits: Bits, at: u64) -> u64 {
    u64::from(Compiler::compile(mem, mode_of(bits), at, MAX_INSNS, None, u64::MAX).insns)
}

fn parity(bits: Bits, at: u64, code: &[u8], what: &str, s: &CpuState) -> u32 {
    if !jit_available() {
        return 0;
    }
    let (mut mem_j, mut cpu_j) = build(bits, at, code, s);
    let (mut mem_i, mut cpu_i) = build(bits, at, code, s);
    let mut jit = Jit::new(256 * 1024).expect("JIT should be available");
    let budget = block_len(&mem_j, bits, at);
    let run = jit.run(cpu_j.state_mut(), &mut mem_j, mode_of(bits), budget);
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

fn jit_only(bits: Bits, at: u64, code: &[u8], s: &CpuState) -> CpuState {
    let (mut mem, mut cpu) = build(bits, at, code, s);
    let mut jit = Jit::new(64 * 1024).unwrap();
    let budget = block_len(&mem, bits, at);
    jit.run(cpu.state_mut(), &mut mem, mode_of(bits), budget);
    cpu.state().clone()
}

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

    parity(Bits::B32, 0xFFFF_FFF0, &[0xEB, 0x7F], "jmp rel8 across 2^32", &s);

    let mut taken = s.clone();
    taken.rflags |= exemu_core::cpu::flags::ZF;
    parity(Bits::B32, 0xFFFF_FFF0, &[0x74, 0x7F], "je rel8 taken across 2^32", &taken);
    parity(Bits::B32, 0xFFFF_FFF0, &[0x74, 0x7F], "je rel8 not taken", &s);

    let mut jcc32 = vec![0x0F, 0x84];
    jcc32.extend_from_slice(&0x1000i32.to_le_bytes());
    parity(Bits::B32, TOP32, &jcc32, "je rel32 taken across 2^32", &taken);
    if jit_available() {
        assert_eq!(jit_only(Bits::B32, TOP32, &jcc32, &taken).rip, 0x6);
    }
}

#[test]
fn a_near_branch_keeps_all_64_bits_in_long_mode() {
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
    let code = [0x31, 0xC0];
    let s = seed(Bits::B32);
    parity(Bits::B32, 0xFFFF_FFFE, &code, "fall through 2^32", &s);
    if jit_available() {
        let (mut mem, mut cpu) = build(Bits::B32, 0xFFFF_FFFE, &code, &s);
        let mut jit = Jit::new(64 * 1024).unwrap();
        jit.set_max_insns(1);
        jit.run(cpu.state_mut(), &mut mem, Mode::Protected, 1);
        assert_eq!(cpu.state().rip, 0, "EIP wraps to zero, not to 0x1_0000_0000");
    }
}

#[test]
fn the_stack_pointer_wraps_at_2_32() {
    let code = [
        0x50,
        0x5B,
        DECLINED,
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

    let mut s2 = seed(Bits::B32);
    s2.gpr[5] = 0xFFFF_FFFC;
    s2.gpr[4] = 0x10;
    parity(Bits::B32, TOP32, &[0xC9, DECLINED], "leave across 2^32", &s2);

    let mut pushi = vec![0x68];
    pushi.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    pushi.push(DECLINED);
    let mut s3 = seed(Bits::B32);
    s3.gpr[4] = 0;
    parity(Bits::B32, TOP32, &pushi, "push imm32 across 2^32", &s3);
}

#[test]
fn a_return_wraps_the_stack_pointer_at_2_32() {
    let mut s = seed(Bits::B32);
    s.gpr[4] = 0xFFFF_FFFC;
    let n = parity(Bits::B32, TOP32, &[0xC3], "ret across 2^32", &s);
    if jit_available() {
        assert_eq!(n, 1, "the ret compiles");
        assert_eq!(
            jit_only(Bits::B32, TOP32, &[0xC3], &s).gpr[4],
            0,
            "ESP wraps back to zero over the region's last dword"
        );
    }

    let mut s2 = seed(Bits::B32);
    s2.gpr[4] = 0xFFFF_FFF0;
    let released = [0xC2, 0x10, 0x00];
    parity(Bits::B32, TOP32, &released, "ret 0x10 across 2^32", &s2);
    if jit_available() {
        assert_eq!(
            jit_only(Bits::B32, TOP32, &released, &s2).gpr[4],
            4,
            "ESP wraps through the released bytes too"
        );
    }
}

#[test]
fn a_return_keeps_a_stack_pointer_above_4_gib() {
    let mut s = seed(Bits::B64);
    s.gpr[4] = HIGH64 + 0x1000;
    let n = parity(Bits::B64, HIGH64, &[0xC3], "ret above 4 GiB", &s);
    if jit_available() {
        assert_eq!(n, 1);
        assert_eq!(
            jit_only(Bits::B64, HIGH64, &[0xC3], &s).gpr[4],
            HIGH64 + 0x1008,
            "RSP keeps its high half"
        );
    }
}

#[test]
fn an_effective_address_wraps_at_2_32() {
    let code = [
        0x8B, 0x43, 0x10,
        0x89, 0x43, 0x20,
        0x8D, 0x4B, 0x30,
        DECLINED,
    ];
    let mut s = seed(Bits::B32);
    s.gpr[3] = 0xFFFF_FFF8;
    let n = parity(Bits::B32, TOP32, &code, "wrapping effective address", &s);
    if jit_available() {
        assert_eq!(n, 3);
        assert_eq!(
            jit_only(Bits::B32, TOP32, &code, &s).gpr[1],
            0x28,
            "lea produces the 32-bit address"
        );
    }

    let sib = [
        0x8B, 0x04, 0x73,
        0x8D, 0x14, 0xB3,
        DECLINED,
    ];
    let mut s2 = seed(Bits::B32);
    s2.gpr[3] = 0xFFFF_FFF0;
    s2.gpr[6] = 0x10;
    parity(Bits::B32, TOP32, &sib, "wrapping SIB address", &s2);

    let mut abs = vec![0x8B, 0x05];
    abs.extend_from_slice(&(-0x10i32).to_le_bytes());
    abs.push(DECLINED);
    parity(Bits::B32, TOP32, &abs, "negative absolute disp32", &s);
}

#[test]
fn addresses_above_4_gib_survive_in_long_mode() {
    let code = [
        0x48, 0x8B, 0x43, 0x10,
        0x48, 0x89, 0x43, 0x20,
        0x48, 0x8D, 0x4B, 0x30,
        0x50,
        0x5A,
        DECLINED,
    ];
    let mut s = seed(Bits::B64);
    s.gpr[3] = HIGH64 + 0x100;
    s.gpr[4] = HIGH64 + 0x1000;
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
    if !jit_available() {
        return;
    }
    let code = [0x8B, 0x05];
    let s = seed(Bits::B32);
    let at = 0xFFFF_FFFE;
    let (mem, _) = build(Bits::B32, at, &code, &s);
    let plan = exemu_jit::compile::Compiler::compile(&mem, Mode::Protected, at, 64, None, u64::MAX);
    assert_eq!(
        plan.insns, 0,
        "an instruction whose encoding runs past executable memory must not compile"
    );

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
    if !jit_available() {
        return;
    }
    let at = 0xFFFF_FFF0u64;
    let mut code = vec![
        0xBD, 0xF0, 0xFF, 0xFF, 0xFF,
        0x89, 0x6D, 0x0C,
    ];
    code.resize(0x10, 0x90);
    let s = seed(Bits::B32);

    let (mem, _) = build(Bits::B32, at, &code, &s);
    let plan = exemu_jit::compile::Compiler::compile(&mem, Mode::Protected, at, 64, None, u64::MAX);
    assert_eq!(plan.stop, exemu_jit::StopReason::Wrapped);
    assert_eq!(plan.bytes, 0x10, "the block covers exactly the bytes it compiled");

    parity(Bits::B32, at, &code, "store into a block that ends on 2^32", &s);
    let (mut mem, mut cpu) = build(Bits::B32, at, &code, &s);
    let mut jit = Jit::new(64 * 1024).unwrap();
    jit.run(cpu.state_mut(), &mut mem, Mode::Protected, u64::from(plan.insns));
    assert_eq!(
        jit.recent_blocks()[..2],
        [at, at + 8],
        "the block must commit the store and stop, not run the stale nops"
    );
}
