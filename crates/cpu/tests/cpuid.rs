use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, EmuError, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, CpuidReg, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;

fn step_probe(code: &[u8]) -> exemu_core::Result<Exit> {
    let mut m = VirtualMemory::new();
    m.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    m.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    m.write(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.gpr[0] = DATA;
    }
    cpu.set_mxcsr(0x1F80);
    let mut hooks = NoHooks;
    cpu.step(&mut m, &mut hooks)
}

fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let pure = Interpreter::cpuid_leaf(leaf, sub);
    let mut m = VirtualMemory::new();
    m.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    m.write(CODE, &[0x0F, 0xA2]).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.gpr[0] = leaf as u64;
        s.gpr[1] = sub as u64;
    }
    let mut hooks = NoHooks;
    assert!(matches!(cpu.step(&mut m, &mut hooks), Ok(Exit::Continue)));
    let s = cpu.state();
    let executed = (s.gpr[0] as u32, s.gpr[3] as u32, s.gpr[1] as u32, s.gpr[2] as u32);
    assert_eq!(pure, executed, "cpuid_leaf({leaf:#x},{sub}) disagrees with 0F A2 execution");
    pure
}

#[test]
fn leaf0_max_leaf_and_vendor() {
    let (eax, ebx, ecx, edx) = cpuid(0, 0);
    assert_eq!(eax, 0xD);
    assert_eq!(ebx, 0x756e_6547);
    assert_eq!(edx, 0x4965_6e69);
    assert_eq!(ecx, 0x6c65_746e);
}

#[test]
fn leaf1_feature_words_exact() {
    let (_eax, _ebx, ecx, edx) = cpuid(1, 0);
    assert_eq!(
        ecx,
        (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 23) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29)
    );
    assert_eq!(edx, 1 | (1 << 4) | (1 << 15) | (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26));
    assert_ne!(edx & 1, 0, "x87 (leaf1 EDX bit0) must be advertised after W1.1");
}

#[test]
fn leaf1_withholds_unimplemented_bits() {
    let (_eax, _ebx, ecx, edx) = cpuid(1, 0);
    assert_eq!(ecx & (1 << 0), 0, "SSE3 must be OFF");
    assert_eq!(ecx & (1 << 12), 0, "FMA must be OFF");
    assert_eq!(ecx & (1 << 25), 0, "AES must be OFF");
    assert_ne!(edx & (1 << 23), 0, "MMX must be ON (W1.6)");
}

#[test]
fn leaf7_bmi_avx2_adx() {
    let (eax, ebx, ecx, edx) = cpuid(7, 0);
    assert_eq!(eax, 0, "max sub-leaf 0");
    assert_eq!(ebx, (1 << 3) | (1 << 5) | (1 << 8) | (1 << 19), "leaf 7 EBX = BMI1|AVX2|BMI2|ADX");
    assert_eq!(ecx, 0);
    assert_eq!(edx, 0);
    assert_eq!(cpuid(7, 1), (0, 0, 0, 0));
    assert_ne!(ebx & (1 << 5), 0, "AVX2 must be ON (W1.5)");
    assert_ne!(ebx & (1 << 3), 0, "BMI1 must be ON (W1.6)");
    assert_ne!(ebx & (1 << 8), 0, "BMI2 must be ON (W1.6)");
    assert_ne!(ebx & (1 << 19), 0, "ADX must be ON (W1.6)");
    assert_eq!(ebx & (1 << 16), 0, "AVX-512F must be OFF");
}

#[test]
fn leafd_xsave_enumeration() {
    let (eax, ebx, ecx, edx) = cpuid(0xD, 0);
    assert_eq!(eax, 0x7, "XCR0 valid-bit mask = x87|SSE|AVX");
    assert_eq!(edx, 0, "XCR0 high mask = 0");
    assert_eq!(ebx, 832);
    assert_eq!(ecx, 832);
    assert_ne!(eax & (1 << 2), 0, "AVX (YMM) XSAVE component must be ON (W1.5)");
    assert_eq!(cpuid(0xD, 1), (0, 0, 0, 0));
    assert_eq!(cpuid(0xD, 2), (256, 576, 0, 0));
}

#[test]
fn ext_max_leaf_and_features() {
    let (eax, ..) = cpuid(0x8000_0000, 0);
    assert_eq!(eax, 0x8000_0004);
    let (_e, _b, ecx, edx) = cpuid(0x8000_0001, 0);
    assert_eq!(ecx, 1 << 5);
    assert_eq!(edx, (1 << 11) | (1 << 27) | (1 << 29));
    assert_eq!(edx & (1 << 29), 0x2000_0000, "Long Mode must be advertised");
    assert_eq!(ecx & (1 << 6), 0, "SSE4A must be OFF");
}

#[test]
fn brand_string_is_populated() {
    let mut bytes = Vec::new();
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        let (a, b, c, d) = cpuid(leaf, 0);
        for w in [a, b, c, d] {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
    }
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.starts_with("exemu"), "brand string was {s:?}");
}

#[test]
fn out_of_range_leaf_is_zero() {
    assert_eq!(cpuid(0x40, 0), (0, 0, 0, 0));
    assert_eq!(cpuid(0x8000_00FF, 0), (0, 0, 0, 0));
}

#[test]
fn every_advertised_feature_probe_decodes() {
    for f in Interpreter::CPUID_FEATURES {
        let word = f.reg.pick(Interpreter::cpuid_leaf(f.leaf, f.sub));
        assert_ne!(
            word & (1 << f.bit),
            0,
            "CPUID_FEATURES lists {} (leaf {:#x} {:?} bit {}) but that bit is NOT advertised",
            f.name, f.leaf, f.reg, f.bit
        );
        match step_probe(f.probe) {
            Err(EmuError::Decode { .. }) | Err(EmuError::Unsupported(_)) => {
                panic!("advertised feature {} has an unimplemented probe {:02x?}", f.name, f.probe);
            }
            _ => {}
        }
    }
}

#[test]
fn every_advertised_feature_bit_is_covered() {
    for &(leaf, sub, reg) in Interpreter::CPUID_FEATURE_WORDS {
        let word = reg.pick(Interpreter::cpuid_leaf(leaf, sub));
        for bit in 0..32u8 {
            if word & (1 << bit) == 0 {
                continue;
            }
            let covered = Interpreter::CPUID_FEATURES
                .iter()
                .any(|f| f.leaf == leaf && f.sub == sub && f.reg == reg && f.bit == bit);
            assert!(
                covered,
                "advertised CPUID bit (leaf {leaf:#x} sub {sub} {reg:?} bit {bit}) has no \
                 CPUID_FEATURES probe — flip it off or add its decoder support + probe"
            );
        }
    }
}

#[test]
fn feature_words_are_only_feature_flags() {
    for &(leaf, _sub, reg) in Interpreter::CPUID_FEATURE_WORDS {
        let is_flag_word = matches!(
            (leaf, reg),
            (1, CpuidReg::Ecx)
                | (1, CpuidReg::Edx)
                | (7, CpuidReg::Ebx)
                | (7, CpuidReg::Ecx)
                | (7, CpuidReg::Edx)
                | (0x8000_0001, CpuidReg::Ecx)
                | (0x8000_0001, CpuidReg::Edx)
        );
        assert!(is_flag_word, "unexpected non-feature word in CPUID_FEATURE_WORDS: {leaf:#x} {reg:?}");
    }
}
