//! Arithmetic/logic helpers that also compute EFLAGS exactly as an x86 CPU
//! would. Keeping the flag math in one place makes the interpreter's opcode
//! handlers short and keeps conditional branches correct.
//!
//! `size` is always in bytes (1, 2, 4, 8). Inputs are treated as unsigned
//! `u64`s masked to `size`; results are returned masked to `size`.

use exemu_core::cpu::{flags, CpuState};

/// Mask covering the low `size` bytes.
#[inline]
pub fn mask(size: u8) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

/// The sign bit for a value of `size` bytes.
#[inline]
pub fn sign_bit(size: u8) -> u64 {
    1u64 << (size * 8 - 1)
}

/// Sign-extend the low `size` bytes of `v` to a full 64-bit value.
#[inline]
pub fn sext(v: u64, size: u8) -> u64 {
    match size {
        1 => v as u8 as i8 as i64 as u64,
        2 => v as u16 as i16 as i64 as u64,
        4 => v as u32 as i32 as i64 as u64,
        _ => v,
    }
}

#[inline]
fn parity(v: u64) -> bool {
    (v as u8).count_ones() % 2 == 0
}

/// Set SF, ZF and PF from a result. AF/CF/OF are handled per-operation.
#[inline]
pub fn set_szp(s: &mut CpuState, res: u64, size: u8) {
    let r = res & mask(size);
    s.set_flag(flags::ZF, r == 0);
    s.set_flag(flags::SF, r & sign_bit(size) != 0);
    s.set_flag(flags::PF, parity(r));
}

/// `a + b + carry_in`, setting CF/OF/AF/SF/ZF/PF. Returns the masked result.
pub fn add(s: &mut CpuState, a: u64, b: u64, carry_in: u64, size: u8) -> u64 {
    let m = mask(size);
    let (a, b) = (a & m, b & m);
    let full = a as u128 + b as u128 + carry_in as u128;
    let res = (full as u64) & m;
    s.set_flag(flags::CF, (full >> (size * 8)) & 1 != 0);
    s.set_flag(flags::AF, (a ^ b ^ res) & 0x10 != 0);
    let sb = sign_bit(size);
    s.set_flag(flags::OF, (!(a ^ b) & (a ^ res)) & sb != 0);
    set_szp(s, res, size);
    res
}

/// `a - b - borrow_in`, setting CF (borrow)/OF/AF/SF/ZF/PF. Returns the
/// masked result. Used for SUB, SBB, CMP and NEG.
pub fn sub(s: &mut CpuState, a: u64, b: u64, borrow_in: u64, size: u8) -> u64 {
    let m = mask(size);
    let (a, b) = (a & m, b & m);
    let rhs = b as u128 + borrow_in as u128;
    s.set_flag(flags::CF, (a as u128) < rhs);
    let res = a.wrapping_sub(b).wrapping_sub(borrow_in) & m;
    s.set_flag(flags::AF, (a ^ b ^ res) & 0x10 != 0);
    let sb = sign_bit(size);
    s.set_flag(flags::OF, (a ^ b) & (a ^ res) & sb != 0);
    set_szp(s, res, size);
    res
}

/// Bitwise result (AND/OR/XOR/TEST): clears CF and OF, sets SF/ZF/PF, and
/// clears AF (architecturally undefined, but real CPUs leave it 0 here).
pub fn logic(s: &mut CpuState, res: u64, size: u8) -> u64 {
    let r = res & mask(size);
    s.set_flag(flags::CF, false);
    s.set_flag(flags::OF, false);
    s.set_flag(flags::AF, false);
    set_szp(s, r, size);
    r
}

/// INC: like `add(.., 1)` but leaves CF untouched.
pub fn inc(s: &mut CpuState, a: u64, size: u8) -> u64 {
    let cf = s.flag(flags::CF);
    let r = add(s, a, 1, 0, size);
    s.set_flag(flags::CF, cf);
    r
}

/// DEC: like `sub(.., 1)` but leaves CF untouched.
pub fn dec(s: &mut CpuState, a: u64, size: u8) -> u64 {
    let cf = s.flag(flags::CF);
    let r = sub(s, a, 1, 0, size);
    s.set_flag(flags::CF, cf);
    r
}

/// Shift/rotate kinds selected by the ModRM `reg` field of group 2.
#[derive(Clone, Copy)]
pub enum Shift {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sar,
}

impl Shift {
    pub fn from_reg(reg: u8) -> Shift {
        match reg & 7 {
            0 => Shift::Rol,
            1 => Shift::Ror,
            2 => Shift::Rcl,
            3 => Shift::Rcr,
            4 | 6 => Shift::Shl, // /6 (SAL) is an alias of SHL
            5 => Shift::Shr,
            _ => Shift::Sar,
        }
    }
}

/// Execute a shift/rotate, updating CF/OF/SF/ZF/PF per x86 rules for the
/// common shift cases. Rotates update CF/OF only.
pub fn shift(s: &mut CpuState, kind: Shift, val: u64, count: u64, size: u8) -> u64 {
    let bits = size as u32 * 8;
    // Count is masked to 5 bits (6 for 64-bit operands).
    let count = (count & if size == 8 { 0x3f } else { 0x1f }) as u32;
    if count == 0 {
        return val & mask(size);
    }
    let m = mask(size);
    let v = val & m;
    let sb = sign_bit(size);

    match kind {
        Shift::Shl => {
            let cf = if count <= bits { (v >> (bits - count)) & 1 != 0 } else { false };
            let res = (v << count) & m;
            s.set_flag(flags::CF, cf);
            if count == 1 {
                s.set_flag(flags::OF, ((res & sb != 0) as u64 ^ cf as u64) != 0);
            }
            set_szp(s, res, size);
            res
        }
        Shift::Shr => {
            let cf = (v >> (count - 1)) & 1 != 0;
            let res = v >> count;
            s.set_flag(flags::CF, cf);
            if count == 1 {
                s.set_flag(flags::OF, v & sb != 0);
            }
            set_szp(s, res, size);
            res
        }
        Shift::Sar => {
            let signed = sext(v, size);
            let cf = (signed >> (count - 1)) & 1 != 0;
            let res = ((signed as i64) >> count) as u64 & m;
            s.set_flag(flags::CF, cf);
            if count == 1 {
                s.set_flag(flags::OF, false);
            }
            set_szp(s, res, size);
            res
        }
        Shift::Rol => {
            let c = count % bits;
            let res = ((v << c) | (v >> ((bits - c) % bits))) & m;
            let cf = res & 1 != 0;
            s.set_flag(flags::CF, cf);
            if count == 1 {
                s.set_flag(flags::OF, (res & sb != 0) as u64 ^ cf as u64 != 0);
            }
            res
        }
        Shift::Ror => {
            let c = count % bits;
            let res = ((v >> c) | (v << ((bits - c) % bits))) & m;
            let cf = res & sb != 0;
            s.set_flag(flags::CF, cf);
            if count == 1 {
                let top2 = res & sb != 0;
                let next = res & (sb >> 1) != 0;
                s.set_flag(flags::OF, top2 ^ next);
            }
            res
        }
        // RCL/RCR (rotate through carry) are uncommon in compiled code; a
        // faithful-enough implementation without the intermediate CF cascade.
        Shift::Rcl | Shift::Rcr => {
            let mut res = v;
            let mut cf = s.flag(flags::CF);
            for _ in 0..count {
                match kind {
                    Shift::Rcl => {
                        let new_cf = res & sb != 0;
                        res = ((res << 1) | cf as u64) & m;
                        cf = new_cf;
                    }
                    _ => {
                        let new_cf = res & 1 != 0;
                        res = (res >> 1) | ((cf as u64) << (bits - 1));
                        cf = new_cf;
                    }
                }
            }
            s.set_flag(flags::CF, cf);
            res & m
        }
    }
}
