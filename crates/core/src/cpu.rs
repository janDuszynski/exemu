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

/// The full architectural register file.
#[derive(Debug, Clone)]
pub struct CpuState {
    /// The 16 general-purpose registers, indexed by [`Reg`].
    pub gpr: [u64; 16],
    /// The 16 128-bit SSE/SSE2 vector registers (`xmm0`..`xmm15`).
    pub xmm: [u128; 16],
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
