use exemu_core::{Cpu, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;

fn mem() -> VirtualMemory {
    let mut m = VirtualMemory::new();
    m.map(Region::new("code", CODE, 0x1000, Perm::RWX)).unwrap();
    m.map(Region::new("data", DATA, 0x2000, Perm::RW)).unwrap();
    m
}

fn run_bits(m: &mut VirtualMemory, code: &[u8], steps: usize, bits: Bits) -> Interpreter {
    m.write(CODE, code).unwrap();
    let mut cpu = Interpreter::with_bits(bits);
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    for _ in 0..steps {
        cpu.step(m, &mut hooks).unwrap();
    }
    cpu
}

#[test]
fn fxsave_layout_offsets_match_sdm() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.x87.cw = 0x0A5A;
        s.x87.sw = 0x1234 & !0x3800;
        s.x87.tw = 0xABCD;
        s.x87.fop = 0;
        s.x87.fip = 0x1122_3344_5566_7788;
        s.x87.fdp = 0x99AA_BBCC_DDEE_FF00;
        for i in 0..8 {
            s.x87.st[i] = ((0xAA00 + i as u128) << 64) | (0x1111_1111_1111_0000 + i as u128);
        }
        for i in 0..16 {
            s.xmm[i] = (0xDEAD_0000_0000_0000_0000_0000_0000_0000u128) | (i as u128);
        }
    }
    cpu.set_mxcsr(0x00001F80 | 0x20);
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x0F, 0xAE, 0x00]);
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    cpu.step(&mut m, &mut hooks).unwrap();

    let mut area = [0u8; 512];
    m.read(DATA, &mut area).unwrap();
    assert_eq!(u16::from_le_bytes([area[0], area[1]]), 0x0A5A, "FCW @0");
    assert_eq!(u16::from_le_bytes([area[2], area[3]]), 0x1234 & !0x3800, "FSW @2");
    let expected_ftw = {
        let tw = 0xABCDu16;
        let mut b = 0u8;
        for j in 0..8 {
            if (tw >> (j * 2)) & 3 != 0b11 {
                b |= 1 << j;
            }
        }
        b
    };
    assert_eq!(area[4], expected_ftw, "abridged FTW @4");
    assert_eq!(
        u64::from_le_bytes(area[8..16].try_into().unwrap()),
        0x1122_3344_5566_7788,
        "FIP @8 (64-bit)"
    );
    assert_eq!(
        u64::from_le_bytes(area[16..24].try_into().unwrap()),
        0x99AA_BBCC_DDEE_FF00,
        "FDP @16 (64-bit)"
    );
    assert_eq!(u32::from_le_bytes(area[24..28].try_into().unwrap()), 0x1FA0, "MXCSR @24");
    assert_eq!(u32::from_le_bytes(area[28..32].try_into().unwrap()), 0x0000_FFFF, "MXCSR_MASK @28");
    for i in 0..8usize {
        let off = 32 + i * 16;
        let mut b = [0u8; 16];
        b[..10].copy_from_slice(&area[off..off + 10]);
        let saved = u128::from_le_bytes(b);
        let expected = cpu.state().x87.st[i] & ((1u128 << 80) - 1);
        assert_eq!(saved, expected, "ST{i} @{off}");
    }
    for i in 0..16usize {
        let off = 160 + i * 16;
        let mut b = [0u8; 16];
        b.copy_from_slice(&area[off..off + 16]);
        assert_eq!(u128::from_le_bytes(b), cpu.state().xmm[i], "XMM{i} @{off}");
    }
}

#[test]
fn fxsave_32bit_pointer_selector_packing() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B32);
    {
        let s = cpu.state_mut();
        s.x87.fip = 0x1234_5678;
        s.x87.fcs = 0xABCD;
        s.x87.fdp = 0x0BAD_F00D;
        s.x87.fds = 0x4321;
        s.gpr[0] = DATA;
    }
    let code = [0x0F, 0xAE, 0x00];
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let mut area = [0u8; 512];
    m.read(DATA, &mut area).unwrap();
    assert_eq!(u32::from_le_bytes(area[8..12].try_into().unwrap()), 0x1234_5678, "FIP @8");
    assert_eq!(u16::from_le_bytes([area[12], area[13]]), 0xABCD, "FCS @12");
    assert_eq!(u32::from_le_bytes(area[16..20].try_into().unwrap()), 0x0BAD_F00D, "FDP @16");
    assert_eq!(u16::from_le_bytes([area[20], area[21]]), 0x4321, "FDS @20");
}

#[test]
fn fxsave_fxrstor_roundtrip() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let (want_st, want_xmm, want_cw, want_sw, want_tw, want_mxcsr, want_fop, want_fip, want_fdp);
    {
        let s = cpu.state_mut();
        s.x87.cw = 0x0372;
        s.x87.sw = 0x2800;
        s.x87.tw = 0x0000;
        s.x87.fop = 0x07FF;
        s.x87.fip = 0xCAFE_BABE_1234_5678;
        s.x87.fdp = 0x0BAD_C0DE_DEAD_BEEF;
        for i in 0..8 {
            s.x87.st[i] = (0x3FFF + i as u128) << 64 | 0x8000_0000_0000_0000u128;
        }
        for i in 0..16 {
            s.xmm[i] = ((i as u128) << 120) | 0x1234_5678_9ABC_DEF0;
        }
        want_st = s.x87.st;
        want_xmm = s.xmm;
        want_cw = s.x87.cw;
        want_sw = s.x87.sw;
        want_tw = s.x87.tw;
        want_fop = s.x87.fop;
        want_fip = s.x87.fip;
        want_fdp = s.x87.fdp;
        s.gpr[0] = DATA;
    }
    cpu.set_mxcsr(0x1F80 | 0x15);
    want_mxcsr = cpu.mxcsr();
    let mut code = vec![0x48, 0x0F, 0xAE, 0x00];
    code.extend_from_slice(&[0x48, 0x0F, 0xAE, 0x08]);
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    {
        let s = cpu.state_mut();
        s.x87.cw = 0;
        s.x87.sw = 0;
        s.x87.tw = 0xFFFF;
        s.x87.fip = 0;
        for r in s.x87.st.iter_mut() {
            *r = 0;
        }
        for x in s.xmm.iter_mut() {
            *x = 0;
        }
    }
    cpu.set_mxcsr(0x1F80);
    cpu.step(&mut m, &mut hooks).unwrap();
    let s = cpu.state();
    assert_eq!(s.x87.st, want_st, "ST stack restored");
    assert_eq!(s.xmm, want_xmm, "XMM restored");
    assert_eq!(s.x87.cw, want_cw, "FCW restored");
    assert_eq!(s.x87.sw, want_sw, "FSW restored (incl. TOP)");
    assert_eq!(s.x87.tw, want_tw, "FTW re-expanded");
    assert_eq!(s.x87.fop, want_fop, "FOP round-trips");
    assert_eq!(s.x87.fip, want_fip, "FIP round-trips");
    assert_eq!(s.x87.fdp, want_fdp, "FDP round-trips");
    assert_eq!(cpu.mxcsr(), want_mxcsr, "MXCSR restored");
}

#[test]
fn fxrstor_reexpands_abridged_ftw() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.x87.sw = 0;
        s.x87.st[0] = 0x3FFF_u128 << 64 | 0x8000_0000_0000_0000;
        s.x87.st[1] = 0;
        s.x87.st[2] = 0x1234;
        s.x87.tw = 0b11_11_11_11_11_11_01_00;
        s.gpr[0] = DATA;
    }
    let mut code = vec![0x0F, 0xAE, 0x00];
    code.extend_from_slice(&[0x0F, 0xAE, 0x08]);
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let mut b = [0u8; 1];
    m.read(DATA + 4, &mut b).unwrap();
    assert_eq!(b[0], 0b0000_0011, "abridged FTW: phys0,1 present; phys2 empty");
    cpu.step(&mut m, &mut hooks).unwrap();
    let tw = cpu.state().x87.tw;
    assert_eq!(tw & 0b11, 0b00, "phys0 → valid");
    assert_eq!((tw >> 2) & 0b11, 0b01, "phys1 → zero");
    assert_eq!((tw >> 4) & 0b11, 0b11, "phys2 → empty");
}

#[test]
fn xgetbv_reports_x87_sse_avx() {
    let mut m = mem();
    let code = [0x31, 0xC9, 0x0F, 0x01, 0xD0];
    let cpu = run_bits(&mut m, &code, 2, Bits::B64);
    assert_eq!(cpu.state().gpr_read(0, 4), 0x7, "EAX = XCR0 low = x87|SSE|AVX");
    assert_eq!(cpu.state().gpr_read(2, 4), 0x0, "EDX = XCR0 high");
    assert_eq!(cpu.xcr0(), 0x7);
}

#[test]
fn xsetbv_clamps_to_implemented_and_forces_x87() {
    let mut m = mem();
    let code = [
        0xB8, 0x27, 0x00, 0x00, 0x00,
        0x31, 0xD2,
        0x31, 0xC9,
        0x0F, 0x01, 0xD1,
    ];
    let cpu = run_bits(&mut m, &code, 4, Bits::B64);
    assert_eq!(cpu.xcr0(), 0x7, "unimplemented bit 5 rejected; x87+SSE+AVX kept");

    let mut m2 = mem();
    let code2 = [
        0xB8, 0x06, 0x00, 0x00, 0x00,
        0x31, 0xD2, 0x31, 0xC9, 0x0F, 0x01, 0xD1,
    ];
    let cpu2 = run_bits(&mut m2, &code2, 4, Bits::B64);
    assert_eq!(cpu2.xcr0(), 0x7, "bit 0 (x87) is forced on");
}

#[test]
fn cpuid_leaf_d_enumerates_x87_sse_avx() {
    let mut m = mem();
    let code = [0xB8, 0x0D, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2];
    let cpu = run_bits(&mut m, &code, 3, Bits::B64);
    assert_eq!(cpu.state().gpr_read(0, 4), 0x7, "XCR0 valid mask = x87|SSE|AVX");
    assert_eq!(cpu.state().gpr_read(2, 4), 0x0, "XCR0 high mask");
    assert_eq!(cpu.state().gpr_read(3, 4), 832, "EBX = enabled-state area size");
    assert_eq!(cpu.state().gpr_read(1, 4), 832, "ECX = max area size");
}

#[test]
fn xsave_writes_header_and_preserves_other_bits() {
    let mut m = mem();
    m.write_u64(DATA + 512, 1 << 9).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.gpr[0] = 0x3;
        s.gpr[2] = 0;
        s.gpr[3] = DATA;
        s.xmm[0] = 0xFEED_FACE;
    }
    let code = [0x0F, 0xAE, 0x23];
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let bv = m.read_u64(DATA + 512).unwrap();
    assert_eq!(bv & 0x3, 0x3, "XSTATE_BV marks x87+SSE saved");
    assert_eq!(bv & (1 << 9), 1 << 9, "out-of-RFBM header bit preserved");
    let mut xb = [0u8; 16];
    m.read(DATA + 160, &mut xb).unwrap();
    assert_eq!(u128::from_le_bytes(xb), 0xFEED_FACE);
}

#[test]
fn xrstor_restores_present_and_inits_absent() {
    let mut m = mem();
    let mut area = [0u8; 512];
    area[0..2].copy_from_slice(&0x0372u16.to_le_bytes());
    area[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
    area[4] = 0x01;
    let one = (0x3FFFu128 << 64 | 0x8000_0000_0000_0000u128).to_le_bytes();
    area[32..42].copy_from_slice(&one[..10]);
    area[160..176].copy_from_slice(&0xABCD_1234_u128.to_le_bytes());
    m.write(DATA, &area).unwrap();
    m.write_u64(DATA + 512, 0x2).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.gpr[0] = 0x3;
        s.gpr[2] = 0;
        s.gpr[3] = DATA;
        s.x87.st[0] = 0xDEAD;
        s.x87.tw = 0x0000;
    }
    let code = [0x0F, 0xAE, 0x2B];
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let s = cpu.state();
    assert_eq!(s.xmm[0], 0xABCD_1234, "XMM0 restored");
    assert_eq!(s.x87.cw, 0x037F, "x87 reset to FNINIT control word");
    assert_eq!(s.x87.tw, 0xFFFF, "x87 tag word reset to all-empty");
    assert_eq!(s.x87.st, [0u128; 8], "x87 registers zeroed");
}
