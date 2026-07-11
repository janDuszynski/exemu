//! AVX / AVX2 (VEX) decode tests — hand-assembled, focused on the correctness
//! traps that the differential oracle also guards: VEX.128 zero-upper vs
//! legacy-SSE upper-preserve, the 3-operand `vvvv` source, VEX.256 lanes, and
//! VZEROUPPER/VZEROALL.

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

/// THE trap: a VEX.128 op zeroes the upper 128 bits of the destination YMM,
/// whereas the legacy-SSE form preserves them.
#[test]
fn vex128_zeroes_upper_half() {
    // vpxor xmm0, xmm0, xmm0  =  C5 F9 EF C0  (VEX.128 66 0F EF /r)
    let code = [0xC5, 0xF9, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xdead_beef_dead_beef, 0xcafe_babe_cafe_babe);
    });
    assert_eq!(cpu.state().xmm[0], 0, "low half computed to 0");
    assert_eq!(cpu.state().ymm_hi[0], 0, "VEX.128 must ZERO the upper half");
}

/// The legacy (non-VEX) SSE form of the very same logical op must PRESERVE the
/// upper 128 bits — the mirror side of the zero-upper trap.
#[test]
fn legacy_sse_preserves_upper_half() {
    // pxor xmm0, xmm0  =  66 0F EF C0
    let code = [0x66, 0x0F, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xdead_beef_dead_beef, 0xcafe_babe_cafe_babe);
    });
    assert_eq!(cpu.state().xmm[0], 0);
    assert_eq!(cpu.state().ymm_hi[0], 0xcafe_babe_cafe_babe, "legacy SSE preserves upper");
}

/// The 3-operand form: `vpaddd xmm0, xmm1, xmm2` = dst is xmm0, sources are the
/// vvvv-encoded xmm1 and the r/m xmm2 — dst is NOT an implicit source.
#[test]
fn vex_three_operand_nondestructive() {
    // vpaddd xmm0, xmm1, xmm2 = C5 F1 FE C2 (VEX.128 66 0F FE, vvvv=1, rm=2)
    let code = [0xC5, 0xF1, 0xFE, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0xffff_ffff_ffff_ffff, 0); // clobber-me dst
        cpu.state_mut().set_ymm(1, 0x0000_0002_0000_0003, 0);
        cpu.state_mut().set_ymm(2, 0x0000_0004_0000_0005, 0);
    });
    // 32-bit lanes: (2+4)=6, (3+5)=8 in the low 64.
    assert_eq!(cpu.state().xmm[0], 0x0000_0006_0000_0008);
    assert_eq!(cpu.state().xmm[1], 0x0000_0002_0000_0003, "vvvv source untouched");
}

/// VEX.256 operates on both 128-bit lanes independently.
#[test]
fn vex256_both_lanes() {
    // vpxor ymm0, ymm1, ymm2 = C5 F5 EF C2 (VEX.256 66 0F EF, vvvv=1, rm=2)
    //   byte1 = R vvvv L pp = 1 1110 1 01 = 0xF5 (vvvv=~1=1110, L=1, pp=66)
    let code = [0xC5, 0xF5, 0xEF, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xff00_ff00_ff00_ff00, 0x0f0f_0f0f_0f0f_0f0f);
        cpu.state_mut().set_ymm(2, 0x00ff_00ff_00ff_00ff, 0xf0f0_f0f0_f0f0_f0f0);
    });
    assert_eq!(cpu.state().xmm[0], 0xffff_ffff_ffff_ffff);
    assert_eq!(cpu.state().ymm_hi[0], 0xffff_ffff_ffff_ffff);
}

/// VZEROUPPER zeroes only the upper 128 bits of every YMM; the low XMM halves
/// are preserved.
#[test]
fn vzeroupper_clears_only_upper() {
    // vzeroupper = C5 F8 77
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

/// VZEROALL zeroes the entire YMM register file.
#[test]
fn vzeroall_clears_everything() {
    // vzeroall = C5 FC 77
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

/// 3-byte VEX (0xC4) reaches the extended registers via the inverted B bit.
#[test]
fn vex_three_byte_extended_reg() {
    // vpxor xmm0, xmm0, xmm8 : need rm=8 → VEX.B must be 0 (inverted → set).
    // C4 [R=1 X=1 B=0 mmmmm=00001] [W=0 vvvv=1111 L=0 pp=01] EF /r(rm=0)
    //   byte1 = R X B mmmmm = 1 1 0 00001 = 0xC1
    //   byte2 = W vvvv L pp = 0 1111 0 01 = 0x79
    //   modrm = 11 000 000 = 0xC0  (reg=0, rm=0 → +B(=1)*8 = xmm8)
    let code = [0xC4, 0xC1, 0x79, 0xEF, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, 0, 0xdead);
        cpu.state_mut().set_ymm(8, 0xaaaa_aaaa_aaaa_aaaa, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xaaaa_aaaa_aaaa_aaaa, "0 xor xmm8");
    assert_eq!(cpu.state().ymm_hi[0], 0, "zero-upper");
}

/// VMOVDQA store/load round-trips a full 256-bit register through memory.
#[test]
fn vmovdqu_256_roundtrip() {
    // vmovdqu ymm0, [DATA] ; vmovdqu [DATA+32], ymm0
    // C5 FE 6F 04 25 <disp32>   (VEX.256 F3 0F 6F)
    // C5 FE 7F 04 25 <disp32>
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

/// VPBROADCASTB replicates the low byte across the whole destination.
#[test]
fn vpbroadcastb_replicates() {
    // vpbroadcastb ymm0, xmm1 = C4 E2 7D 78 C1 (VEX.256 66 0F38 78)
    //   byte1 = R X B mmmmm = 1 1 1 00010 = 0xE2
    //   byte2 = W vvvv L pp = 0 1111 1 01 = 0x7D
    let code = [0xC4, 0xE2, 0x7D, 0x78, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xAB, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB);
    assert_eq!(cpu.state().ymm_hi[0], 0xABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB_ABAB);
}

/// VEXTRACTI128 pulls the upper 128-bit lane out to an xmm (imm bit 0 = 1).
#[test]
fn vextracti128_high_lane() {
    // vextracti128 xmm0, ymm1, 1 = C4 E3 7D 39 C8 01 (VEX.256 66 0F3A 39)
    //   byte1 = 1 1 1 00011 = 0xE3 ; byte2 = 0 1111 1 01 = 0x7D
    //   modrm = 11 001 000 = 0xC8 (reg=ymm1 src, rm=xmm0 dst) ; imm=01
    let code = [0xC4, 0xE3, 0x7D, 0x39, 0xC8, 0x01, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222);
    });
    assert_eq!(cpu.state().xmm[0], 0x2222_2222_2222_2222, "upper lane extracted");
    assert_eq!(cpu.state().ymm_hi[0], 0, "xmm dst zero-upper");
}

/// VPERMQ with imm8 shuffles the four qwords of a 256-bit source.
#[test]
fn vpermq_qword_shuffle() {
    // vpermq ymm0, ymm1, 0b00_01_10_11 = reverse the 4 qwords.
    // C4 E3 FD 00 C1 1B (VEX.256 66 0F3A 00, W=1)
    //   byte1 = 1 1 1 00011 = 0xE3 ; byte2 = W=1 vvvv=1111 L=1 pp=01 = 0xFD
    let code = [0xC4, 0xE3, 0xFD, 0x00, 0xC1, 0x1B, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        // qwords: [0]=0, [1]=1, [2]=2, [3]=3
        cpu.state_mut().set_ymm(1, 1u128 << 64, (3u128 << 64) | 2);
    });
    // imm 0b00_01_10_11: out[0]=q3, out[1]=q2, out[2]=q1, out[3]=q0.
    // xmm[0] = out[1]<<64 | out[0] = 2<<64 | 3; ymm_hi[0] = out[3]<<64 | out[2] = 1.
    assert_eq!(cpu.state().xmm[0], (2u128 << 64) | 3);
    assert_eq!(cpu.state().ymm_hi[0], 1u128);
}

/// VMOVD from GP zero-extends into a zeroed 256-bit register.
#[test]
fn vmovd_zero_extends_full_ymm() {
    // vmovd xmm0, eax = C5 F9 6E C0 (VEX.128 66 0F 6E)
    let code = [0xC5, 0xF9, 0x6E, 0xC0, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(0, u128::MAX, u128::MAX);
        cpu.state_mut().gpr[0] = 0x1234_5678;
    });
    assert_eq!(cpu.state().xmm[0], 0x1234_5678);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

/// VXSAVE/XRSTOR round-trips the YMM upper halves through the AVX component.
#[test]
fn xsave_xrstor_avx_component_roundtrip() {
    // Enable AVX in XCR0 (default), then:
    //   xsave  [DATA]   with RFBM = 0x7 (x87|SSE|AVX)
    //   modify ymm upper halves
    //   xrstor [DATA]   with RFBM = 0x7 → upper halves restored
    // rax=DATA, edx:eax(rfbm)=0x7 for the mask via edx=0, eax=7 but rax also is
    // the address — so use a fixed address encoding with disp32 and set edx/eax.
    // Simpler: put address in rbx and use [rbx].
    //   mov eax,7 ; xor edx,edx ; xsave [rbx] ; xrstor [rbx]
    // xsave  [rbx] = 0F AE /4 → 0F AE 23
    // xrstor [rbx] = 0F AE /5 → 0F AE 2B
    let code = [
        0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
        0x31, 0xD2, // xor edx, edx
        0x0F, 0xAE, 0x23, // xsave [rbx]
        0xF4,
    ];
    let (cpu, mem) = run_with(&code, |cpu, _| {
        cpu.state_mut().gpr[3] = DATA; // rbx
        cpu.state_mut().set_ymm(2, 0xdead, 0xBEEF_0000_0000_0000_0000_0000_0000_0002);
    });
    // The AVX component lives at DATA + 576, register 2 → +32 bytes.
    let mut b = [0u8; 16];
    mem.read(DATA + 576 + 32, &mut b).unwrap();
    assert_eq!(u128::from_le_bytes(b), 0xBEEF_0000_0000_0000_0000_0000_0000_0002);
    // XSTATE_BV should mark AVX (bit 2) in-use.
    let bv = mem.read_u64(DATA + 512).unwrap();
    assert_eq!(bv & 0x7, 0x7, "x87|SSE|AVX marked in XSTATE_BV");
    let _ = cpu;
}

/// CPUID must now advertise AVX (leaf 1 ECX bit 28) and AVX2 (leaf 7 EBX bit 5),
/// with XCR0 reporting the AVX component.
#[test]
fn cpuid_advertises_avx() {
    let (_, _, ecx, _) = Interpreter::cpuid_leaf(1, 0);
    assert_ne!(ecx & (1 << 28), 0, "AVX advertised");
    let (_, ebx7, _, _) = Interpreter::cpuid_leaf(7, 0);
    assert_ne!(ebx7 & (1 << 5), 0, "AVX2 advertised");
    let (eax_d, _, _, _) = Interpreter::cpuid_leaf(0xD, 0);
    assert_eq!(eax_d & 0x7, 0x7, "XCR0 valid mask includes AVX");
}

/// VSUBSD 3-operand scalar: result[63:0] = vvvv[63:0] − rm[63:0], upper from
/// vvvv, upper 128 zeroed. (Regression: exemu must NOT leave the result equal to
/// the vvvv source — an early bug the oracle would have caught only if the
/// reference handled vvvv, which it does not.)
#[test]
fn vsubsd_three_operand_scalar() {
    // vsubsd xmm4, xmm5, xmm7  = c5 d3 5c e7 (vvvv=5, dst=4, rm=7)
    let code = [0xC5, 0xD3, 0x5C, 0xE7, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(5, 0x3ff0000000000000_4000000000000000, 0x1111);
        cpu.state_mut().set_ymm(7, 0xdeadbeefdeadbeef_3ff0000000000000, 0);
    });
    // low = 2.0 - 1.0 = 1.0; upper 64 = vvvv[127:64] = 0x3ff0000000000000.
    assert_eq!(cpu.state().xmm[4] as u64, 1.0f64.to_bits(), "scalar sub result");
    assert_eq!(cpu.state().xmm[4] >> 64, 0x3ff0000000000000, "upper from vvvv");
    assert_eq!(cpu.state().ymm_hi[4], 0, "zero-upper");
}

/// VPHADDD with a distinct 3-operand VEX destination has NO in-place hazard:
/// the result is a pure horizontal add of the two sources, even when the
/// destination aliases a source. (Pinned here because the Unicorn reference —
/// which evaluates VEX as legacy 2-operand in place — cannot verify it.)
#[test]
fn vphaddd_no_inplace_hazard() {
    // vphaddd xmm4, xmm4, xmm4 = c4 e2 59 02 e4 (map 0F38, vvvv=4, dst=4, rm=4)
    let code = [0xC4, 0xE2, 0x59, 0x02, 0xE4, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        // dwords: [0]=1, [1]=2, [2]=3, [3]=4
        cpu.state_mut().set_ymm(4, 0x00000004_00000003_00000002_00000001, 0);
    });
    // VPHADDD(src,src): out = [d0+d1, d2+d3, d0+d1, d2+d3] = [3, 7, 3, 7].
    assert_eq!(cpu.state().xmm[4], 0x00000007_00000003_00000007_00000003);
}

/// VPSLLVD — AVX2 per-element variable left shift (excluded from the oracle
/// because the reference faults on it).
#[test]
fn vpsllvd_per_element() {
    // vpsllvd xmm0, xmm1, xmm2 = c4 e2 71 47 c2 (map 0F38, vvvv=1, dst=0, rm=2)
    let code = [0xC4, 0xE2, 0x71, 0x47, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        // src1 (vvvv=xmm1) = data lanes [1, 2, 4, 8]; src2 (rm=xmm2) = counts [1, 2, 3, 4].
        cpu.state_mut().set_ymm(1, 0x00000008_00000004_00000002_00000001, 0);
        cpu.state_mut().set_ymm(2, 0x00000004_00000003_00000002_00000001, 0);
    });
    // lanes: 1<<1=2, 2<<2=8, 4<<3=32, 8<<4=128.
    assert_eq!(cpu.state().xmm[0], 0x00000080_00000020_00000008_00000002);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

/// VPBROADCASTD from a register source (AVX2) — replicates the low dword.
#[test]
fn vpbroadcastd_reg_source() {
    // vpbroadcastd xmm0, xmm1 = c4 e2 79 58 c1 (map 0F38, dst=0, rm=1)
    let code = [0xC4, 0xE2, 0x79, 0x58, 0xC1, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0xDEAD_BEEF, 0);
    });
    assert_eq!(cpu.state().xmm[0], 0xDEADBEEF_DEADBEEF_DEADBEEF_DEADBEEF);
    assert_eq!(cpu.state().ymm_hi[0], 0);
}

/// VPBLENDD — AVX2 imm8 dword blend (excluded from the oracle: reference faults).
#[test]
fn vpblendd_imm() {
    // vpblendd xmm0, xmm1, xmm2, 0b0101 = c4 e3 71 02 c2 05 (dst=0, vvvv=1, rm=2)
    let code = [0xC4, 0xE3, 0x71, 0x02, 0xC2, 0x05, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        cpu.state_mut().set_ymm(1, 0x11111111_11111111_11111111_11111111, 0);
        cpu.state_mut().set_ymm(2, 0x22222222_22222222_22222222_22222222, 0);
    });
    // imm 0b0101: dwords 0,2 from src2 (xmm2), 1,3 from src1 (xmm1).
    assert_eq!(cpu.state().xmm[0], 0x11111111_22222222_11111111_22222222);
}

/// VPERMD — AVX2 dword permute by a vvvv index vector (excluded from the oracle).
#[test]
fn vpermd_dword_permute() {
    // vpermd ymm0, ymm1, ymm2 = c4 e2 75 36 c2 (256-bit, dst=0, vvvv=1=idx, rm=2=src)
    let code = [0xC4, 0xE2, 0x75, 0x36, 0xC2, 0xF4];
    let (cpu, _) = run_with(&code, |cpu, _| {
        // source dwords [0..8] = 10,11,12,13,14,15,16,17
        cpu.state_mut().set_ymm(2, 0x0000000d_0000000c_0000000b_0000000a, 0x00000011_00000010_0000000f_0000000e);
        // index selects [7,6,5,4,3,2,1,0] → reverse
        cpu.state_mut().set_ymm(1, 0x00000004_00000005_00000006_00000007, 0x00000000_00000001_00000002_00000003);
    });
    // out[0]=src[7]=0x11, out[1]=src[6]=0x10, out[2]=src[5]=0x0f, out[3]=src[4]=0x0e
    assert_eq!(cpu.state().xmm[0], 0x0000000e_0000000f_00000010_00000011);
    // out[4]=src[3]=0x0d, out[5]=src[2]=0x0c, out[6]=src[1]=0x0b, out[7]=src[0]=0x0a
    assert_eq!(cpu.state().ymm_hi[0], 0x0000000a_0000000b_0000000c_0000000d);
}
