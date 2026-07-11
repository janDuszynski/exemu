//! CPUID leaf-fidelity + the "advertised ⊆ implemented" invariant (roadmap W1.3).
//!
//! CPUID honesty is a **correctness** requirement, not cosmetics: if exemu
//! advertises a feature bit whose instructions the interpreter cannot execute,
//! Wine's feature-detection branches straight into that unimplemented path and
//! dies millions of instructions later. These tests do three things:
//!
//!  1. **Pin** the exact bytes of leaves 0 / 1 / 7.0 / 0xD.0 / 0x8000_0000 /
//!     0x8000_0001 against what the interpreter implements at this point in W1
//!     (x87 ON per W1.1, XSAVE ON per W1.2; SSSE3/SSE4/AVX/BMI still OFF).
//!  2. **Soundness** — every advertised feature bit has a representative
//!     instruction in `Interpreter::CPUID_FEATURES`, and each such probe decodes
//!     and executes (no `Decode`/`Unsupported`).
//!  3. **Completeness** — every bit set in a guarded feature-flag word
//!     (`CPUID_FEATURE_WORDS`) is covered by a `CPUID_FEATURES` entry, so a
//!     future step (W1.4–W1.6) cannot flip a CPUID bit on without also landing
//!     its decoder support and adding its probe here. This is the anti-desync
//!     latch the roadmap step calls for.

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, EmuError, Exit, Memory, Perm, Region};
use exemu_cpu::{Bits, CpuidReg, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000; // 64-byte aligned: valid FXSAVE (16) / XSAVE (64) operand

/// Run a single instruction in 64-bit mode with RAX pointing at a mapped,
/// readable+writable DATA region (so memory-operand probes like `FXSAVE [rax]`
/// have a valid, aligned operand). Returns the raw step result so the caller can
/// distinguish a *decoder* failure from a legitimate architectural outcome.
fn step_probe(code: &[u8]) -> exemu_core::Result<Exit> {
    let mut m = VirtualMemory::new();
    m.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    m.map(Region::new("data", DATA, 0x1000, Perm::RW)).unwrap();
    // A valid, mostly-masked XSAVE image header so XRSTOR-adjacent forms are sane
    // (unused by the FXSAVE/XSAVE probes, which only write).
    m.write(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.gpr[0] = DATA; // RAX → the mapped operand
    }
    cpu.set_mxcsr(0x1F80);
    let mut hooks = NoHooks;
    cpu.step(&mut m, &mut hooks)
}

/// Read a CPUID word by executing `0F A2` with EAX/ECX seeded — exercises the
/// same path the guest hits, and matches the pure `cpuid_leaf` helper.
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let pure = Interpreter::cpuid_leaf(leaf, sub);
    // Cross-check the pure helper against the executed instruction so the two
    // never drift.
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

// ---- (1) exact leaf pins ----------------------------------------------------

#[test]
fn leaf0_max_leaf_and_vendor() {
    let (eax, ebx, ecx, edx) = cpuid(0, 0);
    // Max standard leaf is 0xD (XSAVE enumeration is the highest we answer).
    assert_eq!(eax, 0xD);
    // "GenuineIntel" in EBX/EDX/ECX order.
    assert_eq!(ebx, 0x756e_6547); // "Genu"
    assert_eq!(edx, 0x4965_6e69); // "ineI"
    assert_eq!(ecx, 0x6c65_746e); // "ntel"
}

#[test]
fn leaf1_feature_words_exact() {
    let (_eax, _ebx, ecx, edx) = cpuid(1, 0);
    // ECX: SSSE3(9) | SSE4.1(19) | SSE4.2(20) | POPCNT(23) | XSAVE(26) |
    // OSXSAVE(27) — and nothing else. SSSE3/SSE4.1/SSE4.2 are ON after W1.4.
    assert_eq!(ecx, (1 << 9) | (1 << 19) | (1 << 20) | (1 << 23) | (1 << 26) | (1 << 27));
    // EDX: FPU(0) | TSC(4) | CMOV(15) | FXSR(24) | SSE(25) | SSE2(26).
    assert_eq!(edx, 1 | (1 << 4) | (1 << 15) | (1 << 24) | (1 << 25) | (1 << 26));
    // x87 must be ON now (W1.1).
    assert_ne!(edx & 1, 0, "x87 (leaf1 EDX bit0) must be advertised after W1.1");
}

#[test]
fn leaf1_withholds_unimplemented_bits() {
    let (_eax, _ebx, ecx, edx) = cpuid(1, 0);
    // These stay OFF until their W1 steps land — advertising any would send Wine
    // into a decode-fault. (SSSE3/SSE4.1/SSE4.2 are ON as of W1.4; see
    // `leaf1_feature_words_exact`. SSE3 is still off — its handful of extra ops
    // is a separate, not-yet-implemented feature bit.)
    assert_eq!(ecx & (1 << 0), 0, "SSE3 must be OFF");
    assert_eq!(ecx & (1 << 28), 0, "AVX must be OFF (W1.5)");
    assert_eq!(ecx & (1 << 12), 0, "FMA must be OFF");
    assert_eq!(ecx & (1 << 25), 0, "AES must be OFF");
    assert_eq!(edx & (1 << 23), 0, "MMX must be OFF (bare MMX unimplemented)");
}

#[test]
fn leaf7_all_zero_no_ext_features() {
    // exemu implements none of the structured extended features yet
    // (no BMI1/BMI2/AVX2). Max sub-leaf is 0.
    assert_eq!(cpuid(7, 0), (0, 0, 0, 0));
    // Sub-leaf variation stays zero.
    assert_eq!(cpuid(7, 1), (0, 0, 0, 0));
    let (_e, ebx, ecx, _d) = cpuid(7, 0);
    assert_eq!(ebx & (1 << 3), 0, "BMI1 must be OFF (W1.6)");
    assert_eq!(ebx & (1 << 8), 0, "BMI2 must be OFF (W1.6)");
    assert_eq!(ebx & (1 << 5), 0, "AVX2 must be OFF (W1.5)");
    assert_eq!(ebx & (1 << 19), 0, "ADX must be OFF (W1.6)");
    assert_eq!(ecx, 0);
}

#[test]
fn leafd_xsave_enumeration() {
    // Sub-leaf 0: EAX/EDX = XCR0 valid-bit mask (x87|SSE = 0x3); EBX = size for
    // the enabled features, ECX = max size for all supported — both 576 (512
    // legacy + 64 header) since we support exactly x87+SSE.
    let (eax, ebx, ecx, edx) = cpuid(0xD, 0);
    assert_eq!(eax, 0x3, "XCR0 valid-bit mask = x87|SSE");
    assert_eq!(edx, 0, "XCR0 high mask = 0");
    assert_eq!(ebx, 576);
    assert_eq!(ecx, 576);
    assert_eq!(eax & (1 << 2), 0, "AVX (YMM) XSAVE component must be OFF (W1.5)");
    // Sub-leaf 1 (XSAVEOPT/XSAVEC/XSAVES): none implemented ⇒ all zero.
    assert_eq!(cpuid(0xD, 1), (0, 0, 0, 0));
    // Sub-leaf 2 (first extended component, AVX): absent ⇒ zero.
    assert_eq!(cpuid(0xD, 2), (0, 0, 0, 0));
}

#[test]
fn ext_max_leaf_and_features() {
    // Highest extended leaf we answer honestly is the brand string 0x8000_0004.
    let (eax, ..) = cpuid(0x8000_0000, 0);
    assert_eq!(eax, 0x8000_0004);
    let (_e, _b, ecx, edx) = cpuid(0x8000_0001, 0);
    // ECX: LZCNT/ABM (bit 5). EDX: SYSCALL (11) | RDTSCP (27) | Long Mode (29).
    assert_eq!(ecx, 1 << 5);
    assert_eq!(edx, (1 << 11) | (1 << 27) | (1 << 29));
    assert_eq!(edx & (1 << 29), 0x2000_0000, "Long Mode must be advertised");
    assert_eq!(ecx & (1 << 6), 0, "SSE4A must be OFF");
}

#[test]
fn brand_string_is_populated() {
    // Concatenate 0x8000_0002..=0x8000_0004 into the 48-byte brand string.
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
    // A standard leaf above the max (0xD) that we do not implement returns zero
    // — exemu does not echo the max leaf, so no fabricated data leaks.
    assert_eq!(cpuid(0x40, 0), (0, 0, 0, 0));
    assert_eq!(cpuid(0x8000_00FF, 0), (0, 0, 0, 0));
}

// ---- (2) soundness: every probe decodes and executes ------------------------

#[test]
fn every_advertised_feature_probe_decodes() {
    for f in Interpreter::CPUID_FEATURES {
        // The bit this probe claims to cover must actually be advertised.
        let word = f.reg.pick(Interpreter::cpuid_leaf(f.leaf, f.sub));
        assert_ne!(
            word & (1 << f.bit),
            0,
            "CPUID_FEATURES lists {} (leaf {:#x} {:?} bit {}) but that bit is NOT advertised",
            f.name, f.leaf, f.reg, f.bit
        );
        // The representative instruction must not fault at the decoder /
        // unimplemented-instruction level. A legitimate architectural outcome
        // (Continue, or SYSCALL's Interrupt) is fine; only Decode/Unsupported is
        // a broken advertisement.
        match step_probe(f.probe) {
            Err(EmuError::Decode { .. }) | Err(EmuError::Unsupported(_)) => {
                panic!("advertised feature {} has an unimplemented probe {:02x?}", f.name, f.probe);
            }
            _ => {}
        }
    }
}

// ---- (3) completeness: no advertised bit is left un-probed -------------------

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
    // Guard against accidentally listing a structural word (max-leaf / vendor /
    // sizes) as a feature word, which would make the completeness check demand a
    // probe for a non-feature bit.
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
