use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, Exit, Memory, Perm, Region};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;

const CODE_BASE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;

fn run_with(code: &[u8], setup: impl FnOnce(&mut Interpreter, &mut VirtualMemory)) -> (Interpreter, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE_BASE, 0x1_0000, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1_0000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x8_0000, 0x2_0000, Perm::RW)).unwrap();
    mem.write(CODE_BASE, code).unwrap();

    let mut cpu = Interpreter::new();
    cpu.state_mut().rip = CODE_BASE;
    cpu.state_mut().set_rsp(0x9_0000);
    setup(&mut cpu, &mut mem);

    let mut hooks = NoHooks;
    for _ in 0..10_000 {
        if let Exit::Halted = cpu.step(&mut mem, &mut hooks).unwrap() {
            break;
        }
    }
    (cpu, mem)
}

#[test]
fn vex128_zeroes_upper_half() {
    let code = [0xC5, 0xF9, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xdead_beef_dead_beef, 0xcafe_babe_cafe_babe);
    });
    assert_eq!(cpu.state().xmm[0], 0, "low half computed to 0");
    assert_eq!(cpu.state().ymm_hi[0], 0, "VEX.128 must ZERO the upper half");
}

#[test]
fn legacy_sse_preserves_upper_half() {
    let code = [0x66, 0x0F, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xdead_beef_dead_beef, 0xcafe_babe_cafe_babe);
    });
    assert_eq!(cpu.state().xmm[0], 0);
    assert_eq!(cpu.state().ymm_hi[0], 0xcafe_babe_cafe_babe, "legacy SSE preserves upper");
}

#[test]
fn vex_three_operand_nondestructive() {
    let code = [0xC5, 0xF1, 0xFE, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xffff_ffff_ffff_ffff, 0);
        cpu.state_mut().set_ymm(1, 0x0000_0002_0000_0003, 0);
        cpu.state_mut().set_ymm(2, 0x0000_0004_0000_0005, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0x0000_0006_0000_0008);
    assert_eq!(cpu.state().xmm[1], 0x0000_0002_0000_0003, "vvvv source untouched");
}

#[test]
fn vex256_both_lanes() {
    let code = [0xC5, 0xF5, 0xEF, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xff00_ff00_ff00_ff00, 0x0f0f_0f0f_0f0f_0f0f);
        cpu.state_mut().set_ymm(2, 0x00ff_00ff_00ff_00ff, 0xf0f0_f0f0_f0f0_f0f0);
    });
    assert_eq!(cpu.state().xmm[0], 0xffff_ffff_ffff_ffff);
    assert_eq!(cpu.state().ymm_hi[0], 0xffff_ffff_ffff_ffff);
}

#[test]
fn vzeroupper_clears_only_upper() {
    let code = [0xC5, 0xF8, 0x77, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        for i in 0..16 {
            cpu.state_mut().set_ymm(i, 0x1111 + i as u128, 0x9999 + i as u128);
        }
    });
    for i in 0..16 {
        assert_eq!(cpu.state().xmm[i], 0x1111 + i as u128, "xmm{i} low preserved");
        assert_eq!(cpu.state().ymm_hi[i], 0, "ymm{i} upper zeroed");
    }
}

#[test]
fn vzeroall_clears_everything() {
    let code = [0xC5, 0xFC, 0x77, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        for i in 0..16 {
            cpu.state_mut().set_ymm(i, 0x1111 + i as u128, 0x9999 + i as u128);
        }
    });
    for i in 0..16 {
        assert_eq!(cpu.state().xmm[i], 0);
        assert_eq!(cpu.state().ymm_hi[i], 0);
    }
}

#[test]
fn vex_three_byte_extended_reg() {
    let code = [0xC4, 0xC1, 0x79, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0, 0xdead);
        cpu.state_mut().set_ymm(8, 0xaaaa_aaaa_aaaa_aaaa, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xaaaa_aaaa_aaaa_aaaa, "0 xor xmm8");
    assert_eq!(cpu.state().ymm_hi[0], 0, "zero-upper");
}

#[test]
fn vmovdqu_256_roundtrip() {
    let d0 = DATA;
    let d1 = DATA + 32;
    let code = [
        0xC5, 0xFE, 0x6F, 0x04, 0x25, d0 as u8, (d0 >> 8) as u8, (d0 >> 16) as u8, (d0 >> 24) as u8,
        0xC5, 0xFE, 0x7F, 0x04, 0x25, d1 as u8, (d1 >> 8) as u8, (d1 >> 16) as u8, (d1 >> 24) as u8,
        0xF4,
    ];
    let (_, mem) = run_with(&code, |_, mem| {
        for i in 0..32u64 {
            mem.write_u8(DATA + i, (i as u8) ^ 0x5a).unwrap();
        }
    });
    for i in 0..32u64 {
        assert_eq!(mem.read_u8(DATA + 32 + i).unwrap(), (i as u8) ^ 0x5a);
    }
}

#[test]
fn vpbroadcastb_replicates() {
    let code = [0xC4, 0xE2, 0x7D, 0x78, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xAB, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB);
    assert_eq!(cpu.state().ymm_hi[0], 0xABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB);
}

#[test]
fn vextracti128_high_lane() {
    let code = [0xC4, 0xE3, 0x7D, 0x39, 0xC8, 0x01, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222);
    });
    assert_eq!(cpu.state().xmm[0], 0x2222_2222_2222_2222, "upper lane extracted");
    assert_eq!(cpu.state().ymm_hi[0], 0, "xmm dst zero-upper");
}

#[test]
fn vpermq_qword_shuffle() {
    let code = [0xC4, 0xE3, 0xFD, 0x00, 0xC1, 0x1B, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 1u128 << 64, (3u128 << 64) | 2);
    });
    assert_eq!(cpu.state().xmm[0], (2u128 << 64) | 3);
    assert_eq!(cpu.state().ymm_hi[0], 1u128);
}

#[test]
fn vmovd_zero_extends_full_ymm() {
    let code = [0xC5, 0xF9, 0x6E, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, u128::MAX, u128::MAX);
        cpu.state_mut().gpr[0] = 0x1234_5678;
    });
    assert_eq!(cpu.state().xmm[0], 0x1234_5678);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

#[test]
fn xsave_xrstor_avx_component_roundtrip() {
    let code = [
        0xB8, 0x07, 0x00, 0x00, 0x00,
        0x31, 0xD2,
        0x0F, 0xAE, 0x23,
        0xF4,
    ];
    let (cpu, mem) = run_with(&code, |cpu, _| {
        cpu.state_mut().gpr[3] = DATA;
        cpu.state_mut().set_ymm(2, 0xdead, 0xBEEF_0000_0000_0000_0000_0000_0000_0002);
    });
    let mut b = [0u8; 16];
    mem.read(DATA + 576 + 32, &mut b).unwrap();
    assert_eq!(u128::from_le_bytes(b), 0xBEEF_0000_0000_0000_0000_0000_0000_0002);
    let bv = mem.read_u64(DATA + 512).unwrap();
    assert_eq!(bv & 0x7, 0x7, "x87|SSE|AVX marked in XSTATE_BV");
    let _ = cpu;
}

#[test]
fn cpuid_advertises_avx() {
    let (_, _, ecx, _) = Interpreter::cpuid_leaf(1, 0);
    assert_ne!(ecx & (1 << 28), 0, "AVX advertised");
    let (_, ebx7, _, _) = Interpreter::cpuid_leaf(7, 0);
    assert_ne!(ebx7 & (1 << 5), 0, "AVX2 advertised");
    let (eax_d, _, _, _) = Interpreter::cpuid_leaf(0xD, 0);
    assert_eq!(eax_d & 0x7, 0x7, "XCR0 valid mask includes AVX");
}

#[test]
fn vsubsd_three_operand_scalar() {
    let code = [0xC5, 0xD3, 0x5C, 0xE7, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(5, 0x3ff0000000000000_4000000000000000, 0x1111);
        cpu.state_mut().set_ymm(7, 0xdeadbeefdeadbeef_3ff0000000000000, 0);
    });
    assert_eq!(cpu.state().xmm[4] as u64, 1.0f64.to_bits(), "scalar sub result");
    assert_eq!(cpu.state().xmm[4] >> 64, 0x3ff0000000000000, "upper from vvvv");
    assert_eq!(cpu.state().ymm_hi[4], 0, "zero-upper");
}

#[test]
fn vphaddd_no_inplace_hazard() {
    let code = [0xC4, 0xE2, 0x59, 0x02, 0xE4, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(4, 0x00000004_00000003_00000002_00000001, 0);
    });
    assert_eq!(cpu.state().xmm[4], 0x00000007_00000003_00000007_00000003);
}

#[test]
fn vpsllvd_per_element() {
    let code = [0xC4, 0xE2, 0x71, 0x47, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0x00000008_00000004_00000002_00000001, 0);
        cpu.state_mut().set_ymm(2, 0x00000004_00000003_00000002_00000001, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0x00000080_00000020_00000008_00000002);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

#[test]
fn vpbroadcastd_reg_source() {
    let code = [0xC4, 0xE2, 0x79, 0x58, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xDEAD_BEEF, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xDEADBEEF_DEADBEEF_DEADBEEF_DEADBEEF);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

#[test]
fn vpblendd_imm() {
    let code = [0xC4, 0xE3, 0x71, 0x02, 0xC2, 0x05, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0x11111111_11111111_11111111_11111111, 0);
        cpu.state_mut().set_ymm(2, 0x22222222_22222222_22222222_22222222, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0x11111111_22222222_11111111_22222222);
}

#[test]
fn vpermd_dword_permute() {
    let code = [0xC4, 0xE2, 0x75, 0x36, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(2, 0x0000000d_0000000c_0000000b_0000000a, 0x00000011_00000010_0000000f_0000000e);
        cpu.state_mut().set_ymm(1, 0x00000004_00000005_00000006_00000007, 0x00000000_00000001_00000002_00000003);
    });
    assert_eq!(cpu.state().xmm[0], 0x0000000e_0000000f_00000010_00000011);
    assert_eq!(cpu.state().ymm_hi[0], 0x0000000a_0000000b_0000000c_0000000d);
}
