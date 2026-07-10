//! Architectural CPU state for x86-64, plus the [`Cpu`] execution trait.
//!
//! The state lives in the domain because it is part of the emulator's
//! vocabulary; the *interpreter* that mutates it lives in `exemu-cpu`.

use crate::hooks::Hooks;
use crate::memory::Memory;
use crate::Result;

/// General-purpose register indices, matching the x86-64 encoding order so
/// a ModRM `reg` field can index the register file directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    Rax = 0, Rcx = 1, Rdx = 2, Rbx = 3,
    Rsp = 4, Rbp = 5, Rsi = 6, Rdi = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
}

impl Reg {
    pub const NAMES: [&'static str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];
}

/// RFLAGS bit masks. Only the arithmetic/status flags the interpreter
/// actually maintains are named here.
pub mod flags {
    pub const CF: u64 = 1 << 0; // carry
    pub const PF: u64 = 1 << 2; // parity
    pub const AF: u64 = 1 << 4; // auxiliary carry
    pub const ZF: u64 = 1 << 6; // zero
    pub const SF: u64 = 1 << 7; // sign
    pub const TF: u64 = 1 << 8; // trap
    pub const IF: u64 = 1 << 9; // interrupt enable
    pub const DF: u64 = 1 << 10; // direction
    pub const OF: u64 = 1 << 11; // overflow

    /// Bit 1 is reserved and reads as 1.
    pub const RESERVED_ONE: u64 = 1 << 1;
}

/// The x87 FPU register stack and its control/status/tag words.
///
/// **Storage model.** The eight physical data registers `st[0..8]` each hold a
/// full 80-bit (double-extended) value in the low 80 bits of a `u128` (bits
/// 0..64 = mantissa, 64..80 = sign+exponent). This is *real* 80-bit storage,
/// so `FLD`/`FSTP` of a `long double` round-trip bit-exactly. Arithmetic,
/// however, is evaluated in the host `f64` (double, 53-bit) — see
/// `crates/cpu/src/x87.rs`. That is an honest limitation: results are correct
/// to double precision, not to the true 64-bit extended significand. Code that
/// runs the FPU in the standard double or single precision-control mode (the
/// overwhelmingly common case, incl. MSVC/mingw `long double==double` on
/// Windows) is unaffected; only code that deliberately keeps 64-bit-extended
/// precision control would see rounding differ in the last significand bits.
///
/// Registers are addressed **TOP-relative**: `ST(i)` is physical register
/// `(top + i) & 7`, where `top` is the 3-bit TOP field of the status word.
#[derive(Debug, Clone)]
pub struct X87 {
    /// The eight physical 80-bit data registers, indexed by physical number
    /// (not ST-relative). Use [`X87::st`]/[`X87::set_st`] for ST-relative
    /// access.
    pub st: [u128; 8],
    /// Control word: precision control (bits 8..10), rounding control
    /// (bits 10..12), exception masks (bits 0..6). Reset value `0x037F`.
    pub cw: u16,
    /// Status word: condition codes C0..C3, exception flags, and the 3-bit
    /// TOP field (bits 11..14). Reset value `0x0000`.
    pub sw: u16,
    /// Tag word: two bits per physical register (00=valid, 01=zero,
    /// 10=special/NaN/Inf/denormal, 11=empty). Reset value `0xFFFF` (all
    /// empty).
    pub tw: u16,
    /// Last-instruction opcode (the low 11 bits of the last non-control x87
    /// instruction). Not tracked per-instruction by the interpreter — only
    /// round-tripped through `FXSAVE`/`FXRSTOR`/`XSAVE`/`XRSTOR` so a guest that
    /// saves and restores an FPU context (Wine's ntdll does) sees it preserved.
    pub fop: u16,
    /// Last x87 instruction pointer (`FPU IP`), and its code selector `FCS`.
    /// Round-tripped through the save-area, not updated per-instruction.
    pub fip: u64,
    pub fcs: u16,
    /// Last x87 data-operand pointer (`FPU DP`), and its data selector `FDS`.
    pub fdp: u64,
    pub fds: u16,
}

impl Default for X87 {
    fn default() -> Self {
        Self::new()
    }
}

impl X87 {
    /// A freshly-reset FPU (the state `FNINIT` installs).
    pub const fn new() -> Self {
        X87 { st: [0; 8], cw: 0x037F, sw: 0x0000, tw: 0xFFFF, fop: 0, fip: 0, fcs: 0, fdp: 0, fds: 0 }
    }

    /// The 3-bit TOP field of the status word.
    #[inline]
    pub fn top(&self) -> u8 {
        ((self.sw >> 11) & 7) as u8
    }

    /// Overwrite the TOP field of the status word.
    #[inline]
    pub fn set_top(&mut self, top: u8) {
        self.sw = (self.sw & !0x3800) | (((top as u16) & 7) << 11);
    }

    /// The physical register index backing `ST(i)`.
    #[inline]
    pub fn phys(&self, i: u8) -> usize {
        ((self.top().wrapping_add(i)) & 7) as usize
    }
}

/// The full architectural register file.
#[derive(Debug, Clone)]
pub struct CpuState {
    /// The 16 general-purpose registers, indexed by [`Reg`].
    pub gpr: [u64; 16],
    /// The 16 128-bit SSE/SSE2 vector registers (`xmm0`..`xmm15`).
    pub xmm: [u128; 16],
    /// The x87 FPU register stack and its control/status/tag words.
    pub x87: X87,
    /// Instruction pointer.
    pub rip: u64,
    /// Status/control flags.
    pub rflags: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuState {
    pub fn new() -> Self {
        CpuState {
            gpr: [0; 16],
            xmm: [0; 16],
            x87: X87::new(),
            rip: 0,
            rflags: flags::RESERVED_ONE | flags::IF,
        }
    }

    // ---- whole-register access -------------------------------------------

    #[inline]
    pub fn reg(&self, r: Reg) -> u64 {
        self.gpr[r as usize]
    }

    #[inline]
    pub fn set_reg(&mut self, r: Reg, v: u64) {
        self.gpr[r as usize] = v;
    }

    #[inline]
    pub fn rsp(&self) -> u64 {
        self.gpr[Reg::Rsp as usize]
    }

    #[inline]
    pub fn set_rsp(&mut self, v: u64) {
        self.gpr[Reg::Rsp as usize] = v;
    }

    // ---- width-aware GPR access ------------------------------------------
    //
    // `size` is in bytes (1, 2, 4, 8). Reads zero-extend the sub-register
    // into the returned u64. Writes follow x86-64 rules: a 4-byte write
    // zeroes the upper 32 bits, whereas 1- and 2-byte writes preserve them.

    #[inline]
    pub fn gpr_read(&self, index: u8, size: u8) -> u64 {
        let full = self.gpr[index as usize & 0xf];
        match size {
            1 => full & 0xff,
            2 => full & 0xffff,
            4 => full & 0xffff_ffff,
            _ => full,
        }
    }

    #[inline]
    pub fn gpr_write(&mut self, index: u8, size: u8, value: u64) {
        let slot = &mut self.gpr[index as usize & 0xf];
        match size {
            1 => *slot = (*slot & !0xff) | (value & 0xff),
            2 => *slot = (*slot & !0xffff) | (value & 0xffff),
            4 => *slot = value & 0xffff_ffff, // zero-extends the top half
            _ => *slot = value,
        }
    }

    /// Read a legacy high-byte register (AH/CH/DH/BH), used only when no REX
    /// prefix is present and the operand size is one byte.
    #[inline]
    pub fn gpr_read_high8(&self, index: u8) -> u64 {
        (self.gpr[index as usize & 0x3] >> 8) & 0xff
    }

    #[inline]
    pub fn gpr_write_high8(&mut self, index: u8, value: u64) {
        let slot = &mut self.gpr[index as usize & 0x3];
        *slot = (*slot & !0xff00) | ((value & 0xff) << 8);
    }

    // ---- flags -----------------------------------------------------------

    #[inline]
    pub fn flag(&self, mask: u64) -> bool {
        self.rflags & mask != 0
    }

    #[inline]
    pub fn set_flag(&mut self, mask: u64, on: bool) {
        if on {
            self.rflags |= mask;
        } else {
            self.rflags &= !mask;
        }
    }
}

/// Why a single step (or a run) returned control to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// One instruction executed; keep going.
    Continue,
    /// A `hlt` was executed.
    Halted,
    /// A software interrupt `int n` was raised.
    Interrupt(u8),
    /// The guest asked the OS layer to terminate with this exit code.
    ProcessExit(i32),
}

/// A CPU that can execute guest instructions against some [`Memory`].
///
/// This is the seam between the application loop and the concrete
/// interpreter (or, one day, a JIT) in the infrastructure layer.
pub trait Cpu {
    fn state(&self) -> &CpuState;
    fn state_mut(&mut self) -> &mut CpuState;

    /// Execute a single instruction.
    ///
    /// Before decoding, the implementation consults `hooks` so the OS layer
    /// can intercept calls that land on emulated API thunks.
    fn step(&mut self, mem: &mut dyn Memory, hooks: &mut dyn Hooks) -> Result<Exit>;
}
