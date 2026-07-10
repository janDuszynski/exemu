//! FXSAVE / FXRSTOR / XSAVE / XRSTOR / XGETBV / XSETBV unit tests.
//!
//! These pin the 512-byte FXSAVE save-area layout against the Intel SDM table
//! (field offsets), the round-trip fidelity of the FPU + SSE register file, the
//! abridged tag-word compression, and the XCR0 accessor semantics. The oracle
//! (`crates/oracle`) proves byte-exact agreement with Unicorn at scale; these
//! tests lock the specific offsets and edge cases so a future refactor cannot
//! silently shift a field.

use exemu_core::{Cpu, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000; // 64-byte aligned (fine for FXSAVE's 16-byte and XSAVE's 64-byte alignment)

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

/// FXSAVE writes each architectural field at its SDM-defined offset. This is the
/// layout pin the roadmap step calls for (offsets against the SDM table).
#[test]
fn fxsave_layout_offsets_match_sdm() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    // Seed a distinctive x87 + SSE state.
    {
        let s = cpu.state_mut();
        s.x87.cw = 0x0A5A;
        s.x87.sw = 0x1234 & !0x3800; // keep TOP=0 for a clean ST-relative layout
        s.x87.tw = 0xABCD;
        s.x87.fop = 0; // FOP not compared against a real CPU; keep it 0 here
        s.x87.fip = 0x1122_3344_5566_7788;
        s.x87.fdp = 0x99AA_BBCC_DDEE_FF00;
        for i in 0..8 {
            // A recognisable 80-bit pattern per physical register.
            s.x87.st[i] = ((0xAA00 + i as u128) << 64) | (0x1111_1111_1111_0000 + i as u128);
        }
        for i in 0..16 {
            s.xmm[i] = (0xDEAD_0000_0000_0000_0000_0000_0000_0000u128) | (i as u128);
        }
    }
    cpu.set_mxcsr(0x00001F80 | 0x20);
    // mov rax, DATA ; fxsave64 [rax]  (48 0F AE /0)
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x0F, 0xAE, 0x00]); // fxsave64 [rax]
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap(); // mov
    cpu.step(&mut m, &mut hooks).unwrap(); // fxsave64

    let mut area = [0u8; 512];
    m.read(DATA, &mut area).unwrap();
    // FCW @0, FSW @2.
    assert_eq!(u16::from_le_bytes([area[0], area[1]]), 0x0A5A, "FCW @0");
    assert_eq!(u16::from_le_bytes([area[2], area[3]]), 0x1234 & !0x3800, "FSW @2");
    // Abridged FTW @4: bit j set ⇔ physical reg j non-empty. tw=0xABCD.
    // 0xABCD = 10 10 11 11 00 11 01 01 → per-reg tags (reg0 lowest 2 bits).
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
    // FIP @8 (REX.W → 8 bytes), FDP @16.
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
    // MXCSR @24, MXCSR_MASK @28.
    assert_eq!(u32::from_le_bytes(area[24..28].try_into().unwrap()), 0x1FA0, "MXCSR @24");
    assert_eq!(u32::from_le_bytes(area[28..32].try_into().unwrap()), 0x0000_FFFF, "MXCSR_MASK @28");
    // ST0..7 @32, 16 bytes/slot, low 10 bytes significant. TOP=0 so ST(i)=phys i.
    for i in 0..8usize {
        let off = 32 + i * 16;
        let mut b = [0u8; 16];
        b[..10].copy_from_slice(&area[off..off + 10]);
        let saved = u128::from_le_bytes(b);
        let expected = cpu.state().x87.st[i] & ((1u128 << 80) - 1);
        assert_eq!(saved, expected, "ST{i} @{off}");
    }
    // XMM0..15 @160, 16 bytes each.
    for i in 0..16usize {
        let off = 160 + i * 16;
        let mut b = [0u8; 16];
        b.copy_from_slice(&area[off..off + 16]);
        assert_eq!(u128::from_le_bytes(b), cpu.state().xmm[i], "XMM{i} @{off}");
    }
}

/// The 32-bit FXSAVE packs FIP/FCS/FDP/FDS as pointer+selector pairs.
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
        s.gpr[0] = DATA; // eax = DATA
    }
    // fxsave [eax]  (0F AE /0), no REX in 32-bit.
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

/// FXSAVE then FXRSTOR round-trips the whole register file bit-exactly,
/// including FOP/FIP/FDP (which exemu tracks purely for save/restore).
#[test]
fn fxsave_fxrstor_roundtrip() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let (want_st, want_xmm, want_cw, want_sw, want_tw, want_mxcsr, want_fop, want_fip, want_fdp);
    {
        let s = cpu.state_mut();
        s.x87.cw = 0x0372;
        s.x87.sw = 0x2800; // TOP=5, no exception bits
        // A tag word consistent with the ST values below (all non-empty).
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
    // fxsave64 [rax] ; scribble state ; fxrstor64 [rax]
    let mut code = vec![0x48, 0x0F, 0xAE, 0x00]; // fxsave64
    code.extend_from_slice(&[0x48, 0x0F, 0xAE, 0x08]); // fxrstor64 [rax] (/1)
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap(); // fxsave64
    // Corrupt the live state between save and restore.
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
    cpu.step(&mut m, &mut hooks).unwrap(); // fxrstor64
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

/// The abridged FTW written by FXSAVE expands correctly on FXRSTOR: an empty
/// register stays empty, a zero register is tagged zero, a normal register is
/// tagged valid.
#[test]
fn fxrstor_reexpands_abridged_ftw() {
    let mut m = mem();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.x87.sw = 0; // TOP=0
        // phys0 = normal 1.0, phys1 = +0.0, phys2 = empty (marked via tw).
        s.x87.st[0] = 0x3FFF_u128 << 64 | 0x8000_0000_0000_0000; // 1.0
        s.x87.st[1] = 0; // +0.0
        s.x87.st[2] = 0x1234; // garbage — but tagged empty, so ignored on save
        // tw: phys0 valid(00), phys1 zero(01), phys2 empty(11), rest empty(11).
        s.x87.tw = 0b11_11_11_11_11_11_01_00;
        s.gpr[0] = DATA;
    }
    let mut code = vec![0x0F, 0xAE, 0x00]; // fxsave [rax]  (no REX)
    code.extend_from_slice(&[0x0F, 0xAE, 0x08]); // fxrstor [rax]
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap(); // fxsave
    // The abridged FTW in memory: bit0 set (valid), bit1 set (zero non-empty),
    // bit2 clear (empty), rest clear.
    let mut b = [0u8; 1];
    m.read(DATA + 4, &mut b).unwrap();
    assert_eq!(b[0], 0b0000_0011, "abridged FTW: phys0,1 present; phys2 empty");
    // Restore and confirm the tag word re-expands to valid / zero / empty.
    cpu.step(&mut m, &mut hooks).unwrap(); // fxrstor
    let tw = cpu.state().x87.tw;
    assert_eq!(tw & 0b11, 0b00, "phys0 → valid");
    assert_eq!((tw >> 2) & 0b11, 0b01, "phys1 → zero");
    assert_eq!((tw >> 4) & 0b11, 0b11, "phys2 → empty");
}

/// XGETBV (0F 01 D0) reports XCR0 = 0x3 (x87 + SSE) — exactly the implemented
/// state components; AVX (bit 2) is not advertised.
#[test]
fn xgetbv_reports_x87_sse_only() {
    let mut m = mem();
    // xor ecx,ecx ; xgetbv  → EDX:EAX = XCR0.
    let code = [0x31, 0xC9, 0x0F, 0x01, 0xD0];
    let cpu = run_bits(&mut m, &code, 2, Bits::B64);
    assert_eq!(cpu.state().gpr_read(0, 4), 0x3, "EAX = XCR0 low = x87|SSE");
    assert_eq!(cpu.state().gpr_read(2, 4), 0x0, "EDX = XCR0 high");
    assert_eq!(cpu.xcr0(), 0x3);
}

/// XSETBV (0F 01 D1) may enable only implemented components; an attempt to set
/// AVX (bit 2) is clamped away and bit 0 stays forced on.
#[test]
fn xsetbv_clamps_to_implemented_and_forces_x87() {
    let mut m = mem();
    // mov eax, 0x7 ; xor edx,edx ; xor ecx,ecx ; xsetbv  → request x87|SSE|AVX.
    let code = [
        0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
        0x31, 0xD2, // xor edx,edx
        0x31, 0xC9, // xor ecx,ecx
        0x0F, 0x01, 0xD1, // xsetbv
    ];
    let cpu = run_bits(&mut m, &code, 4, Bits::B64);
    assert_eq!(cpu.xcr0(), 0x3, "AVX (bit 2) rejected; x87+SSE only");

    // Attempting to clear bit 0 (x87) is ignored — it is mandatory.
    let mut m2 = mem();
    let code2 = [
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (SSE only, x87 cleared)
        0x31, 0xD2, 0x31, 0xC9, 0x0F, 0x01, 0xD1,
    ];
    let cpu2 = run_bits(&mut m2, &code2, 4, Bits::B64);
    assert_eq!(cpu2.xcr0(), 0x3, "bit 0 (x87) is forced on");
}

/// CPUID leaf 0xD sub-leaf 0 enumerates exactly the implemented XSAVE state:
/// XCR0 valid mask = 0x3 (x87+SSE) and a 576-byte area size. The honesty
/// invariant: never advertise a component we cannot save/restore.
#[test]
fn cpuid_leaf_d_enumerates_x87_sse_only() {
    let mut m = mem();
    // mov eax, 0xD ; xor ecx,ecx ; cpuid  → EAX = XCR0 low, EBX/ECX = size.
    let code = [0xB8, 0x0D, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2];
    let cpu = run_bits(&mut m, &code, 3, Bits::B64);
    assert_eq!(cpu.state().gpr_read(0, 4), 0x3, "XCR0 valid mask = x87|SSE");
    assert_eq!(cpu.state().gpr_read(2, 4), 0x0, "XCR0 high mask");
    assert_eq!(cpu.state().gpr_read(3, 4), 576, "EBX = enabled-state area size");
    assert_eq!(cpu.state().gpr_read(1, 4), 576, "ECX = max area size");
}

/// XSAVE writes the 512-byte legacy area plus an 8-byte XSTATE_BV header,
/// setting the requested-and-used component bits and preserving header bits
/// outside the request-feature mask.
#[test]
fn xsave_writes_header_and_preserves_other_bits() {
    let mut m = mem();
    // Pre-seed the XSTATE_BV header word with an out-of-RFBM bit (bit 9) set.
    m.write_u64(DATA + 512, 1 << 9).unwrap();
    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.gpr[0] = 0x3; // EAX = requested mask (x87|SSE)
        s.gpr[2] = 0; // EDX
        s.gpr[3] = DATA; // rbx as base
        s.xmm[0] = 0xFEED_FACE;
    }
    // xsave [rbx]  (0F AE /4).
    let code = [0x0F, 0xAE, 0x23];
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let bv = m.read_u64(DATA + 512).unwrap();
    assert_eq!(bv & 0x3, 0x3, "XSTATE_BV marks x87+SSE saved");
    assert_eq!(bv & (1 << 9), 1 << 9, "out-of-RFBM header bit preserved");
    // XMM0 landed at offset 160.
    let mut xb = [0u8; 16];
    m.read(DATA + 160, &mut xb).unwrap();
    assert_eq!(u128::from_le_bytes(xb), 0xFEED_FACE);
}

/// XRSTOR restores components present in XSTATE_BV and resets the rest to their
/// INIT state.
#[test]
fn xrstor_restores_present_and_inits_absent() {
    let mut m = mem();
    // Build a legacy area with a known XMM0 and a known ST0, then a header that
    // marks *only* SSE present (bit 1), not x87 (bit 0).
    let mut area = [0u8; 512];
    area[0..2].copy_from_slice(&0x0372u16.to_le_bytes()); // FCW
    area[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
    area[4] = 0x01; // abridged FTW: phys0 present
    // ST0 (offset 32) = 1.0.
    let one = (0x3FFFu128 << 64 | 0x8000_0000_0000_0000u128).to_le_bytes();
    area[32..42].copy_from_slice(&one[..10]);
    // XMM0 (offset 160) = a marker.
    area[160..176].copy_from_slice(&0xABCD_1234_u128.to_le_bytes());
    m.write(DATA, &area).unwrap();
    m.write_u64(DATA + 512, 0x2).unwrap(); // XSTATE_BV = SSE only

    let mut cpu = Interpreter::with_bits(Bits::B64);
    {
        let s = cpu.state_mut();
        s.gpr[0] = 0x3; // request x87|SSE
        s.gpr[2] = 0;
        s.gpr[3] = DATA;
        // Dirty the x87 stack so INIT is observable.
        s.x87.st[0] = 0xDEAD;
        s.x87.tw = 0x0000;
    }
    let code = [0x0F, 0xAE, 0x2B]; // xrstor [rbx] (/5)
    m.write(CODE, &code).unwrap();
    cpu.state_mut().rip = CODE;
    let mut hooks = exemu_core::hooks::NoHooks;
    cpu.step(&mut m, &mut hooks).unwrap();
    let s = cpu.state();
    // SSE present → XMM0 restored from the area.
    assert_eq!(s.xmm[0], 0xABCD_1234, "XMM0 restored");
    // x87 absent → reset to FNINIT: control word 0x037F, tag word 0xFFFF, regs 0.
    assert_eq!(s.x87.cw, 0x037F, "x87 reset to FNINIT control word");
    assert_eq!(s.x87.tw, 0xFFFF, "x87 tag word reset to all-empty");
    assert_eq!(s.x87.st, [0u128; 8], "x87 registers zeroed");
}
