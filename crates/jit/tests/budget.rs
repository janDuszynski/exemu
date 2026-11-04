use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, CpuState, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_jit::{Jit, Mode, Run};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const STACK: u64 = 0x3_0000;
const DECLINED: u8 = 0xF4;

fn jit_available() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn program() -> Vec<u8> {
    let mut c = vec![0xB9, 0x06, 0x00, 0x00, 0x00];
    c.extend([0xBE]);
    c.extend((DATA as u32).to_le_bytes());
    let top = c.len() as i32;
    c.extend([0x01, 0x0E]);
    c.extend([0x83, 0xC6, 0x04]);
    c.extend([0x8D, 0x04, 0x49]);
    c.extend([0x31, 0xC3]);
    c.extend([0xE8]);
    let call_at = c.len() as i32 + 4;
    c.extend([0, 0, 0, 0]);
    c.extend([0xFF, 0xC9]);
    let back = top - (c.len() as i32 + 2);
    c.extend([0x75, back as i8 as u8]);
    c.extend([0x31, 0xD2]);
    c.push(DECLINED);
    let callee = c.len() as i32;
    c[call_at as usize - 4..call_at as usize].copy_from_slice(&(callee - call_at).to_le_bytes());
    c.extend([0x01, 0xC2]);
    c.extend([0xD1, 0xE2]);
    c.extend([0x29, 0xCA]);
    c.push(0xC3);
    c
}

fn build(bits: Bits) -> (VirtualMemory, Interpreter) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", STACK, 0x1000, Perm::RW)).unwrap();
    mem.poke(CODE, &program()).unwrap();
    let words: Vec<u8> = (0..0x400u32).flat_map(|i| (i.wrapping_mul(0x9E37_79B9)).to_le_bytes()).collect();
    mem.poke(DATA, &words).unwrap();
    let mut cpu = Interpreter::with_bits(bits);
    let s = cpu.state_mut();
    s.rip = CODE;
    s.gpr[4] = STACK + 0x800;
    s.gpr[3] = 0x1357_9BDF;
    (mem, cpu)
}

fn mode_of(bits: Bits) -> Mode {
    match bits {
        Bits::B32 => Mode::Protected,
        Bits::B64 => Mode::Long,
    }
}

fn reference(bits: Bits, steps: u64) -> (CpuState, Vec<u8>, u64) {
    let (mut mem, mut cpu) = build(bits);
    let mut hooks = NoHooks;
    let mut done = 0;
    while done < steps {
        match cpu.step(&mut mem, &mut hooks) {
            Ok(Exit::Continue) => done += 1,
            _ => break,
        }
    }
    let mut data = vec![0u8; 0x1000];
    mem.read(DATA, &mut data).unwrap();
    (cpu.state().clone(), data, done)
}

fn twin(jit: &mut Jit, bits: Bits, warm_up: u64, cut: u64) -> (CpuState, Vec<u8>, u64) {
    let (mut mem, mut cpu) = build(bits);
    let mode = mode_of(bits);
    let mut hooks = NoHooks;
    let mut done = 0;
    for limit in [warm_up, warm_up + cut] {
        while done < limit {
            let left = limit - done;
            let ran = jit.run(cpu.state_mut(), &mut mem, mode, left);
            assert!(
                u64::from(ran.insns()) <= left,
                "{bits:?}: {ran:?} against a budget of {left} at instruction {done}"
            );
            done += u64::from(ran.insns());
            if matches!(ran, Run::Executed { .. }) {
                continue;
            }
            if done == limit {
                break;
            }
            match cpu.step(&mut mem, &mut hooks) {
                Ok(Exit::Continue) => done += 1,
                _ => return (cpu.state().clone(), Vec::new(), done),
            }
        }
    }
    let mut data = vec![0u8; 0x1000];
    mem.read(DATA, &mut data).unwrap();
    (cpu.state().clone(), data, done)
}

#[test]
fn a_budget_that_ends_inside_a_block_is_met_to_the_instruction() {
    if !jit_available() {
        return;
    }
    for bits in [Bits::B64, Bits::B32] {
        let (_, _, natural) = reference(bits, u64::MAX);
        assert!(natural > 60, "{bits:?}: the program ran only {natural} instructions");
        let mut jit = Jit::new(1 << 20).unwrap();
        for warm_up in [0, 7, 23] {
            for cut in 0..=natural - warm_up {
                let want = reference(bits, warm_up + cut);
                let got = twin(&mut jit, bits, warm_up, cut);
                let at = format!("{bits:?} warm-up {warm_up} + cut {cut}");
                assert_eq!(got.2, want.2, "{at}: instructions retired");
                assert_eq!(got.0.rip, want.0.rip, "{at}: rip");
                assert_eq!(got.0.gpr, want.0.gpr, "{at}: registers");
                assert_eq!(got.0.rflags, want.0.rflags, "{at}: flags");
                assert_eq!(got.1, want.1, "{at}: guest memory");
            }
        }
        let s = jit.stats();
        assert!(s.budget_stops > 0, "{bits:?}: no budget ever ended inside a block");
        assert!(s.links_taken > 0, "{bits:?}: no native link was ever taken");
        assert!(s.insns_executed > natural, "{bits:?}: the JIT barely ran");
    }
}
