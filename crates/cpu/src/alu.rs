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

/// SHLD: shift `dst` left by `count`, feeding in the high bits of `src`.
pub fn shld(s: &mut CpuState, dst: u64, src: u64, count: u64, size: u8) -> u64 {
    let bits = size as u32 * 8;
    let count = (count & if size == 8 { 0x3f } else { 0x1f }) as u32;
    if count == 0 {
        return dst & mask(size);
    }
    let m = mask(size);
    let (dst, src) = (dst & m, src & m);
    let res = if count >= bits {
        // Undefined for count >= width; approximate with src shifted.
        (src << (count - bits)) & m
    } else {
        ((dst << count) | (src >> (bits - count))) & m
    };
    let cf = (dst >> (bits - count)) & 1 != 0;
    s.set_flag(flags::CF, cf);
    set_szp(s, res, size);
    res
}

/// SHRD: shift `dst` right by `count`, feeding in the low bits of `src`.
pub fn shrd(s: &mut CpuState, dst: u64, src: u64, count: u64, size: u8) -> u64 {
    let bits = size as u32 * 8;
    let count = (count & if size == 8 { 0x3f } else { 0x1f }) as u32;
    if count == 0 {
        return dst & mask(size);
    }
    let m = mask(size);
    let (dst, src) = (dst & m, src & m);
    let res = if count >= bits {
        (src >> (count - bits)) & m
    } else {
        ((dst >> count) | (src << (bits - count))) & m
    };
    let cf = (dst >> (count - 1)) & 1 != 0;
    s.set_flag(flags::CF, cf);
    set_szp(s, res, size);
    res
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
            // OF is defined only for the single-bit rotates. For RCL it is
            // MSB(result) XOR CF(result); for RCR it is the XOR of the two most
            // significant bits of the result. (Undefined for multi-bit — left
            // untouched, matching real CPUs.)
            if count == 1 {
                let msb = res & sb != 0;
                let of = match kind {
                    Shift::Rcl => msb ^ cf,
                    _ => msb ^ (res & (sb >> 1) != 0),
                };
                s.set_flag(flags::OF, of);
            }
            res & m
        }
    }
}

#[cfg(test)]
mod tests {
    //! Flag-accuracy matrix (roadmap P0.3).
    //!
    //! Each ALU helper is checked against an *independent* derivation of every
    //! status flag, so a bug in the helper is not masked by a test that merely
    //! restates the helper's own formula:
    //!
    //! * CF — 128-bit wide add/sub, inspect the bit above the operand width.
    //! * OF — width-clamped *signed* range check (sign-extend, compute in i128,
    //!   test whether the true result fits the signed width).
    //! * AF — low-nibble arithmetic (`(a&0xf)+(b&0xf)+c > 0xf`), never the
    //!   `a^b^res` trick the implementation uses.
    //! * SF/ZF/PF — from the masked result directly.

    use super::*;

    const SIZES: [u8; 4] = [1, 2, 4, 8];

    /// A spread of operands per width that exercises the flag edges: zero, one,
    /// the sign bit, max unsigned, low-nibble carry boundaries, and a couple of
    /// arbitrary middles.
    fn operands(size: u8) -> Vec<u64> {
        let m = mask(size);
        let sb = sign_bit(size);
        let mut v = vec![
            0,
            1,
            0xf,
            0x10,
            0x7f,
            0x80,
            sb - 1,
            sb,
            sb + 1,
            m - 1,
            m,
            m & 0x5555_5555_5555_5555,
            m & 0xaaaa_aaaa_aaaa_aaaa,
        ];
        v.retain(|&x| x <= m);
        v.dedup();
        v
    }

    fn fresh() -> CpuState {
        CpuState::new()
    }

    // ---- independent reference flag derivations --------------------------

    fn ref_add(a: u64, b: u64, cin: u64, size: u8) -> (u64, bool, bool, bool) {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let full = a as u128 + b as u128 + cin as u128;
        let res = (full as u64) & m;
        let cf = (full >> (size as u32 * 8)) & 1 != 0;
        let af = (a & 0xf) + (b & 0xf) + cin > 0xf;
        // OF via signed range clamp. Cast through i64 so the u64 from `sext`
        // sign-extends into i128 rather than zero-extending.
        let sa = sext(a, size) as i64 as i128;
        let sb = sext(b, size) as i64 as i128;
        let sres = sa + sb + cin as i128;
        let lim = 1i128 << (size as u32 * 8 - 1);
        let of = sres < -lim || sres >= lim;
        (res, cf, af, of)
    }

    fn ref_sub(a: u64, b: u64, bin: u64, size: u8) -> (u64, bool, bool, bool) {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let rhs = b as u128 + bin as u128;
        let cf = (a as u128) < rhs;
        let res = a.wrapping_sub(b).wrapping_sub(bin) & m;
        let af = (a & 0xf) < (b & 0xf) + bin;
        let sa = sext(a, size) as i64 as i128;
        let sb = sext(b, size) as i64 as i128;
        let sres = sa - sb - bin as i128;
        let lim = 1i128 << (size as u32 * 8 - 1);
        let of = sres < -lim || sres >= lim;
        (res, cf, af, of)
    }

    fn assert_szp(st: &CpuState, res: u64, size: u8, ctx: &str) {
        let r = res & mask(size);
        assert_eq!(st.flag(flags::ZF), r == 0, "ZF {ctx}");
        assert_eq!(st.flag(flags::SF), r & sign_bit(size) != 0, "SF {ctx}");
        assert_eq!(st.flag(flags::PF), (r as u8).count_ones() % 2 == 0, "PF {ctx}");
    }

    #[test]
    fn add_flag_matrix() {
        for &size in &SIZES {
            for &a in &operands(size) {
                for &b in &operands(size) {
                    for cin in [0u64, 1] {
                        let mut st = fresh();
                        let got = add(&mut st, a, b, cin, size);
                        let (res, cf, af, of) = ref_add(a, b, cin, size);
                        let ctx = format!("add a={a:#x} b={b:#x} c={cin} sz={size}");
                        assert_eq!(got, res, "result {ctx}");
                        assert_eq!(st.flag(flags::CF), cf, "CF {ctx}");
                        assert_eq!(st.flag(flags::AF), af, "AF {ctx}");
                        assert_eq!(st.flag(flags::OF), of, "OF {ctx}");
                        assert_szp(&st, res, size, &ctx);
                    }
                }
            }
        }
    }

    #[test]
    fn sub_flag_matrix() {
        for &size in &SIZES {
            for &a in &operands(size) {
                for &b in &operands(size) {
                    for bin in [0u64, 1] {
                        let mut st = fresh();
                        let got = sub(&mut st, a, b, bin, size);
                        let (res, cf, af, of) = ref_sub(a, b, bin, size);
                        let ctx = format!("sub a={a:#x} b={b:#x} bin={bin} sz={size}");
                        assert_eq!(got, res, "result {ctx}");
                        assert_eq!(st.flag(flags::CF), cf, "CF {ctx}");
                        assert_eq!(st.flag(flags::AF), af, "AF {ctx}");
                        assert_eq!(st.flag(flags::OF), of, "OF {ctx}");
                        assert_szp(&st, res, size, &ctx);
                    }
                }
            }
        }
    }

    #[test]
    fn logic_clears_cf_of_af() {
        for &size in &SIZES {
            for &a in &operands(size) {
                for &b in &operands(size) {
                    let mut st = fresh();
                    // Seed CF/OF/AF set, to prove `logic` clears them.
                    st.set_flag(flags::CF, true);
                    st.set_flag(flags::OF, true);
                    st.set_flag(flags::AF, true);
                    let res = logic(&mut st, a & b, size);
                    let ctx = format!("and a={a:#x} b={b:#x} sz={size}");
                    assert!(!st.flag(flags::CF), "CF cleared {ctx}");
                    assert!(!st.flag(flags::OF), "OF cleared {ctx}");
                    assert!(!st.flag(flags::AF), "AF cleared {ctx}");
                    assert_szp(&st, res, size, &ctx);
                }
            }
        }
    }

    #[test]
    fn inc_dec_preserve_cf() {
        for &size in &SIZES {
            for &a in &operands(size) {
                for cf_seed in [false, true] {
                    let mut st = fresh();
                    st.set_flag(flags::CF, cf_seed);
                    let r = inc(&mut st, a, size);
                    assert_eq!(st.flag(flags::CF), cf_seed, "INC keeps CF sz={size} a={a:#x}");
                    let (_, _, af, of) = ref_add(a, 1, 0, size);
                    assert_eq!(st.flag(flags::AF), af, "INC AF sz={size} a={a:#x}");
                    assert_eq!(st.flag(flags::OF), of, "INC OF sz={size} a={a:#x}");
                    assert_szp(&st, r, size, "inc");

                    let mut st = fresh();
                    st.set_flag(flags::CF, cf_seed);
                    let r = dec(&mut st, a, size);
                    assert_eq!(st.flag(flags::CF), cf_seed, "DEC keeps CF sz={size} a={a:#x}");
                    let (_, _, af, of) = ref_sub(a, 1, 0, size);
                    assert_eq!(st.flag(flags::AF), af, "DEC AF sz={size} a={a:#x}");
                    assert_eq!(st.flag(flags::OF), of, "DEC OF sz={size} a={a:#x}");
                    assert_szp(&st, r, size, "dec");
                }
            }
        }
    }

    #[test]
    fn shl_shr_sar_cf_and_result() {
        for &size in &SIZES {
            let m = mask(size);
            let bits = size as u32 * 8;
            for &v in &operands(size) {
                for count in 1..=bits.min(31) as u64 {
                    // SHL
                    let mut st = fresh();
                    let r = shift(&mut st, Shift::Shl, v, count, size);
                    assert_eq!(r, (v << count) & m, "SHL res v={v:#x} n={count} sz={size}");
                    let exp_cf = count <= bits as u64 && ((v & m) >> (bits as u64 - count)) & 1 != 0;
                    assert_eq!(st.flag(flags::CF), exp_cf, "SHL CF v={v:#x} n={count} sz={size}");

                    // SHR
                    let mut st = fresh();
                    let r = shift(&mut st, Shift::Shr, v, count, size);
                    assert_eq!(r, (v & m) >> count, "SHR res v={v:#x} n={count} sz={size}");
                    let exp_cf = ((v & m) >> (count - 1)) & 1 != 0;
                    assert_eq!(st.flag(flags::CF), exp_cf, "SHR CF v={v:#x} n={count} sz={size}");

                    // SAR
                    let mut st = fresh();
                    let r = shift(&mut st, Shift::Sar, v, count, size);
                    let signed = sext(v, size);
                    assert_eq!(r, (((signed as i64) >> count) as u64) & m, "SAR res v={v:#x} n={count} sz={size}");
                }
            }
        }
    }

    #[test]
    fn zero_count_shift_is_identity_and_preserves_flags() {
        for &size in &SIZES {
            for &v in &operands(size) {
                for kind in [Shift::Shl, Shift::Shr, Shift::Sar, Shift::Rol, Shift::Ror] {
                    let mut st = fresh();
                    st.rflags = flags::RESERVED_ONE | flags::CF | flags::OF;
                    let before = st.rflags;
                    let r = shift(&mut st, kind, v, 0, size);
                    assert_eq!(r, v & mask(size), "zero-count identity sz={size}");
                    assert_eq!(st.rflags, before, "zero-count preserves flags sz={size}");
                }
            }
        }
    }
}
