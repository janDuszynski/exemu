//! # exemu-cpu — an x86-64 interpreter
//!
//! A decode-and-execute interpreter for a practical subset of x86-64. Each
//! [`Interpreter::step`] fetches one instruction, decodes its prefixes,
//! opcode, ModRM/SIB/displacement and immediate, then executes it against
//! the supplied [`Memory`].
//!
//! Design notes:
//! * RIP-relative addressing is resolved *after* the whole instruction
//!   (including any immediate) has been consumed, because it is relative to
//!   the address of the next instruction — see [`Ctx::rm_addr`].
//! * The regular ALU opcodes (`0x00..=0x3D`) share one handler driven by the
//!   opcode's high bits (operation) and low bits (operand form).
//! * Before decoding, the OS layer gets a chance to intercept the current
//!   `rip` via [`Hooks`]; that is how emulated API calls are serviced.

#![forbid(unsafe_code)]

mod alu;

use exemu_core::cpu::flags;
use exemu_core::{Cpu, CpuState, EmuError, Exit, Hooks, Memory, Result};

/// Processor operating mode: 32-bit (protected/IA-32) or 64-bit (long mode).
/// Selects default operand/address size, REX-vs-inc/dec decoding, stack
/// width and RIP-relative-vs-absolute addressing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bits {
    B32,
    B64,
}

/// The interpreter. Owns nothing but the architectural state and the CPU
/// mode; memory and OS hooks are passed in per step so the same CPU can
/// drive different worlds.
pub struct Interpreter {
    state: CpuState,
    bits: Bits,
    /// Monotonic time-stamp counter backing `RDTSC`. Advanced on each read so
    /// spin loops that wait for the TSC to change make progress.
    tsc: u64,
    /// SSE control/status register (`MXCSR`), round-tripped by `LDMXCSR`/
    /// `STMXCSR`/`FXSAVE`/`FXRSTOR`. Default 0x1F80 (all exceptions masked,
    /// round-to-nearest). Only the round-nearest default currently affects
    /// float→int conversions.
    mxcsr: u32,
    /// Extended-control register `XCR0` (read by `XGETBV`, written by `XSETBV`).
    /// The state components the interpreter implements: bit 0 (x87, always 1),
    /// bit 1 (SSE) and bit 2 (AVX/YMM upper halves). Default 0x7.
    xcr0: u64,
}

/// The bits of `MXCSR` that are defined (reserved bits 16..31 read as 0).
const MXCSR_MASK: u32 = 0x0000_FFFF;

/// `XCR0` state components the interpreter implements: bit 0 = x87 (mandatory,
/// always set), bit 1 = SSE, bit 2 = AVX (the YMM upper halves — implemented in
/// `vex.rs`). Beyond bit 2 (AVX-512 etc.) is not implemented, so `XSETBV`
/// rejects any attempt to enable those.
const XCR0_SUPPORTED: u64 = 0b111;

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    /// A fresh 64-bit interpreter.
    pub fn new() -> Self {
        Interpreter { state: CpuState::new(), bits: Bits::B64, tsc: 0, mxcsr: 0x1F80, xcr0: XCR0_SUPPORTED }
    }

    /// A fresh interpreter in the given mode.
    pub fn with_bits(bits: Bits) -> Self {
        Interpreter { state: CpuState::new(), bits, tsc: 0, mxcsr: 0x1F80, xcr0: XCR0_SUPPORTED }
    }

    pub fn with_state(state: CpuState) -> Self {
        Interpreter { state, bits: Bits::B64, tsc: 0, mxcsr: 0x1F80, xcr0: XCR0_SUPPORTED }
    }

    pub fn bits(&self) -> Bits {
        self.bits
    }

    /// The SSE control/status register (`MXCSR`).
    pub fn mxcsr(&self) -> u32 {
        self.mxcsr
    }

    /// Overwrite `MXCSR` (used by the differential oracle to seed state; masked
    /// to the defined bits just as `LDMXCSR` would).
    pub fn set_mxcsr(&mut self, v: u32) {
        self.mxcsr = v & MXCSR_MASK;
    }

    /// The extended-control register `XCR0`.
    pub fn xcr0(&self) -> u64 {
        self.xcr0
    }

    /// Address-space mask: full 64-bit, or 32-bit in protected mode.
    #[inline]
    fn addr_mask(&self) -> u64 {
        match self.bits {
            Bits::B64 => u64::MAX,
            Bits::B32 => 0xFFFF_FFFF,
        }
    }

    /// Stack slot / push-pop width in bytes.
    #[inline]
    fn stack_width(&self) -> u8 {
        match self.bits {
            Bits::B64 => 8,
            Bits::B32 => 4,
        }
    }
}

impl Cpu for Interpreter {
    fn state(&self) -> &CpuState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut CpuState {
        &mut self.state
    }

    fn step(&mut self, mem: &mut dyn Memory, hooks: &mut dyn Hooks) -> Result<Exit> {
        // Give the OS layer first refusal on this address (API thunks).
        if let Some(exit) = hooks.intercept(self.state.rip, &mut self.state, mem)? {
            return Ok(exit);
        }
        self.execute_one(mem)
    }
}

// --- Prefix / decode context -------------------------------------------------

/// Decoded legacy + REX prefixes for the current instruction.
#[derive(Default, Clone, Copy)]
struct Prefixes {
    rex: u8,
    has_rex: bool,
    /// 0x66 operand-size override.
    p66: bool,
    /// 0xF3 / 0xF2 repeat (or mandatory SSE) prefix, 0 if none.
    rep: u8,
    /// Segment override (0x64 = FS, 0x65 = GS), 0 if none.
    seg: u8,
}

impl Prefixes {
    #[inline]
    fn w(&self) -> bool {
        self.rex & 0b1000 != 0
    }
    #[inline]
    fn r(&self) -> u8 {
        (self.rex >> 2) & 1
    }
    #[inline]
    fn x(&self) -> u8 {
        (self.rex >> 1) & 1
    }
    #[inline]
    fn b(&self) -> u8 {
        self.rex & 1
    }
}

/// Where the ModRM r/m operand lives.
#[derive(Clone, Copy)]
enum Rm {
    /// A register, by (already REX-extended) index.
    Reg(u8),
    /// A memory operand. If `rip_rel` is set, `disp` is added to the address
    /// of the following instruction; otherwise `base` is the final address.
    Mem { base: u64, disp: i64, rip_rel: bool },
}

/// Mutable per-instruction decode state threaded through the handlers.
struct Ctx {
    pfx: Prefixes,
    /// Current fetch pointer; ends up at the first byte past the instruction.
    cur: u64,
    /// ModRM `reg` field, REX.R-extended.
    reg: u8,
    /// Decoded r/m location (valid once ModRM has been read).
    rm: Rm,
    /// Processor mode for this instruction.
    bits: Bits,
    /// The opcode byte captured by a VEX prefix decode (the VEX payload is
    /// consumed before the ModRM, so the opcode is stashed here). Unused by the
    /// legacy decode path.
    u8_at_op: u8,
}

impl Ctx {
    #[inline]
    fn addr_mask(&self) -> u64 {
        match self.bits {
            Bits::B64 => u64::MAX,
            Bits::B32 => 0xFFFF_FFFF,
        }
    }
}

impl Ctx {
    fn u8(&mut self, mem: &dyn Memory) -> Result<u8> {
        let mut b = [0u8; 1];
        mem.fetch(self.cur, &mut b)?;
        self.cur += 1;
        Ok(b[0])
    }
    fn u16(&mut self, mem: &dyn Memory) -> Result<u16> {
        Ok(u16::from_le_bytes([self.u8(mem)?, self.u8(mem)?]))
    }
    fn u32(&mut self, mem: &dyn Memory) -> Result<u32> {
        let mut v = [0u8; 4];
        for x in &mut v {
            *x = self.u8(mem)?;
        }
        Ok(u32::from_le_bytes(v))
    }
    fn u64(&mut self, mem: &dyn Memory) -> Result<u64> {
        let mut v = [0u8; 8];
        for x in &mut v {
            *x = self.u8(mem)?;
        }
        Ok(u64::from_le_bytes(v))
    }

    /// Final address of a memory r/m operand, resolving RIP-relative against
    /// the end of the instruction (`cur` must already point past it) and
    /// masking to the address width of the current mode.
    #[inline]
    fn rm_addr(&self) -> u64 {
        let a = match self.rm {
            Rm::Mem { base, disp, rip_rel } => {
                if rip_rel {
                    self.cur.wrapping_add(disp as u64)
                } else {
                    base.wrapping_add(disp as u64)
                }
            }
            Rm::Reg(_) => 0,
        };
        a & self.addr_mask()
    }
}

// --- The interpreter proper --------------------------------------------------

impl Interpreter {
    /// Operand size in bytes: default 4, `0x66` → 2, and REX.W → 8 in 64-bit
    /// mode (there is no REX in 32-bit mode).
    #[inline]
    fn opsize(ctx: &Ctx) -> u8 {
        if ctx.bits == Bits::B64 && ctx.pfx.w() {
            8
        } else if ctx.pfx.p66 {
            2
        } else {
            4
        }
    }

    fn read_prefixes(&self, ctx: &mut Ctx, mem: &dyn Memory) -> Result<()> {
        loop {
            let b = ctx.u8(mem)?;
            match b {
                0x66 => ctx.pfx.p66 = true,
                0x67 => {} // address-size override: handled per-mode elsewhere
                0xF0 => {} // LOCK: no-op for a single-threaded interpreter
                0xF2 | 0xF3 => ctx.pfx.rep = b,
                0x2E | 0x36 | 0x3E | 0x26 => {} // CS/SS/DS/ES overrides: flat model
                0x64 | 0x65 => ctx.pfx.seg = b, // FS/GS
                // 0x40..=0x4F are REX prefixes only in 64-bit mode; in 32-bit
                // mode they are inc/dec r32 opcodes, so fall through to decode.
                0x40..=0x4F if ctx.bits == Bits::B64 => {
                    ctx.pfx.rex = b;
                    ctx.pfx.has_rex = true;
                    return Ok(());
                }
                _ => {
                    // Not a prefix: step back so the opcode read sees it.
                    ctx.cur -= 1;
                    return Ok(());
                }
            }
        }
    }

    /// Read the ModRM byte (and SIB/displacement) into `ctx`.
    fn read_modrm(&self, ctx: &mut Ctx, mem: &dyn Memory) -> Result<()> {
        let modrm = ctx.u8(mem)?;
        let mod_ = modrm >> 6;
        let reg = ((modrm >> 3) & 7) | (ctx.pfx.r() << 3);
        let rm = modrm & 7;
        ctx.reg = reg;

        if mod_ == 3 {
            ctx.rm = Rm::Reg(rm | (ctx.pfx.b() << 3));
            return Ok(());
        }

        // Memory operand. Handle SIB and RIP-relative special cases.
        let (mut base, mut rip_rel) = (0u64, false);

        if rm == 4 {
            // SIB byte follows.
            let sib = ctx.u8(mem)?;
            let scale = 1u64 << (sib >> 6);
            let index = ((sib >> 3) & 7) | (ctx.pfx.x() << 3);
            let base_reg = (sib & 7) | (ctx.pfx.b() << 3);

            // index == 4 (rsp) means "no index".
            if (sib >> 3) & 7 != 4 || ctx.pfx.x() != 0 {
                base = base.wrapping_add(self.state.reg_at(index).wrapping_mul(scale));
            }

            if sib & 7 == 5 && mod_ == 0 {
                // No base register; disp32 follows. Still honor a segment
                // override (e.g. `gs:[disp32]` for TEB / stack-probe access).
                let disp = ctx.u32(mem)? as i32 as i64;
                if ctx.pfx.seg == 0x65 {
                    base = base.wrapping_add(GS_BASE);
                } else if ctx.pfx.seg == 0x64 {
                    base = base.wrapping_add(fs_base(ctx.bits));
                }
                ctx.rm = Rm::Mem { base, disp, rip_rel: false };
                return Ok(());
            } else {
                base = base.wrapping_add(self.state.reg_at(base_reg));
            }
        } else if rm == 5 && mod_ == 0 {
            // 64-bit: RIP-relative disp32. 32-bit: absolute disp32.
            let disp = ctx.u32(mem)? as i32 as i64;
            let rip_rel = ctx.bits == Bits::B64;
            let mut base = 0u64;
            if ctx.pfx.seg == 0x65 {
                base = GS_BASE;
            } else if ctx.pfx.seg == 0x64 {
                base = fs_base(ctx.bits);
            }
            ctx.rm = Rm::Mem { base, disp, rip_rel };
            return Ok(());
        } else {
            base = self.state.reg_at(rm | (ctx.pfx.b() << 3));
        }
        let _ = &mut rip_rel;

        let disp = match mod_ {
            0 => 0,
            1 => ctx.u8(mem)? as i8 as i64,
            _ => ctx.u32(mem)? as i32 as i64,
        };

        // FS/GS segment bases: we place the TEB at a fixed address and let
        // the OS layer expose it, so treat `gs:[x]` as an absolute offset
        // from a per-thread base the OS installs at reg-slot None. For the
        // common `gs:[0x60]` PEB probe the OS maps a page at GS_BASE.
        if ctx.pfx.seg == 0x65 {
            base = base.wrapping_add(GS_BASE);
        } else if ctx.pfx.seg == 0x64 {
            base = base.wrapping_add(fs_base(ctx.bits));
        }

        ctx.rm = Rm::Mem { base, disp, rip_rel: false };
        Ok(())
    }

    // ---- operand access --------------------------------------------------

    fn read_rm(&self, ctx: &Ctx, mem: &dyn Memory, size: u8) -> Result<u64> {
        match ctx.rm {
            Rm::Reg(i) => Ok(self.read_gpr(i, size, ctx.pfx.has_rex)),
            Rm::Mem { .. } => mem.read_uint(ctx.rm_addr(), size),
        }
    }

    fn write_rm(&mut self, ctx: &Ctx, mem: &mut dyn Memory, size: u8, val: u64) -> Result<()> {
        match ctx.rm {
            Rm::Reg(i) => {
                self.write_gpr(i, size, ctx.pfx.has_rex, val);
                Ok(())
            }
            Rm::Mem { .. } => mem.write_uint(ctx.rm_addr(), size, val),
        }
    }

    #[inline]
    fn read_reg_field(&self, ctx: &Ctx, size: u8) -> u64 {
        self.read_gpr(ctx.reg, size, ctx.pfx.has_rex)
    }

    #[inline]
    fn write_reg_field(&mut self, ctx: &Ctx, size: u8, val: u64) {
        self.write_gpr(ctx.reg, size, ctx.pfx.has_rex, val);
    }

    /// GPR read honoring 8-bit high-byte registers (AH/CH/DH/BH) when no REX
    /// prefix is present.
    #[inline]
    fn read_gpr(&self, index: u8, size: u8, has_rex: bool) -> u64 {
        if size == 1 && !has_rex && (4..8).contains(&index) {
            self.state.gpr_read_high8(index)
        } else {
            self.state.gpr_read(index, size)
        }
    }

    #[inline]
    fn write_gpr(&mut self, index: u8, size: u8, has_rex: bool, val: u64) {
        if size == 1 && !has_rex && (4..8).contains(&index) {
            self.state.gpr_write_high8(index, val);
        } else {
            self.state.gpr_write(index, size, val);
        }
    }

    // ---- stack -----------------------------------------------------------
    //
    // The slot width follows the CPU mode: 8 bytes in long mode, 4 in
    // protected mode. `rsp`/`esp` arithmetic is masked to the address width.

    fn push_stack(&mut self, mem: &mut dyn Memory, val: u64) -> Result<()> {
        let w = self.stack_width();
        let sp = self.state.rsp().wrapping_sub(w as u64) & self.addr_mask();
        self.state.set_rsp(sp);
        mem.write_uint(sp, w, val)
    }

    fn pop_stack(&mut self, mem: &mut dyn Memory) -> Result<u64> {
        let w = self.stack_width();
        let sp = self.state.rsp() & self.addr_mask();
        let v = mem.read_uint(sp, w)?;
        self.state.set_rsp(sp.wrapping_add(w as u64) & self.addr_mask());
        Ok(v)
    }

    // ---- immediates ------------------------------------------------------

    /// Immediate of the "Z" form: imm16 for 16-bit operands, otherwise imm32,
    /// sign-extended to the operand size.
    fn imm_z(&self, ctx: &mut Ctx, mem: &dyn Memory, size: u8) -> Result<u64> {
        Ok(if size == 2 {
            alu::sext(ctx.u16(mem)? as u64, 2)
        } else {
            alu::sext(ctx.u32(mem)? as u64, 4)
        } & alu::mask(size))
    }

    // ---- condition codes -------------------------------------------------

    fn cond(&self, tttn: u8) -> bool {
        let s = &self.state;
        let (cf, zf, sf, of, pf) = (
            s.flag(flags::CF),
            s.flag(flags::ZF),
            s.flag(flags::SF),
            s.flag(flags::OF),
            s.flag(flags::PF),
        );
        match tttn & 0xF {
            0x0 => of,
            0x1 => !of,
            0x2 => cf,
            0x3 => !cf,
            0x4 => zf,
            0x5 => !zf,
            0x6 => cf || zf,
            0x7 => !(cf || zf),
            0x8 => sf,
            0x9 => !sf,
            0xA => pf,
            0xB => !pf,
            0xC => sf != of,
            0xD => sf == of,
            0xE => zf || (sf != of),
            _ => !zf && (sf == of),
        }
    }
}

/// Fixed virtual bases for the GS/FS segment overrides. In 64-bit mode the
/// TEB lives at [`GS_BASE`] (`gs:[0x30]`/`gs:[0x60]`); in 32-bit mode it lives
/// at [`FS_BASE_32`] (`fs:[0x18]`/`fs:[0x30]`), which must be a 32-bit
/// address. The OS layer maps matching pages. All are public so it can.
pub const GS_BASE: u64 = 0x0000_7FFF_0000_0000;
pub const FS_BASE: u64 = 0x0000_7FFE_0000_0000;
pub const FS_BASE_32: u64 = 0x7EFD_0000;

/// The FS segment base for the current mode.
#[inline]
fn fs_base(bits: Bits) -> u64 {
    match bits {
        Bits::B32 => FS_BASE_32,
        Bits::B64 => FS_BASE,
    }
}

/// Convenience accessor used by the SIB/base math above.
trait RegAt {
    fn reg_at(&self, index: u8) -> u64;
}
impl RegAt for CpuState {
    #[inline]
    fn reg_at(&self, index: u8) -> u64 {
        self.gpr[index as usize & 0xf]
    }
}

mod exec;
mod mmx;
mod sse;
mod vex;
mod x87;

pub use exec::{CpuidFeature, CpuidReg};
