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

    /// Read MMX register `MM(i)` — the low 64 bits of *physical* x87 register
    /// `i` (MMX registers are **not** TOP-relative; `MMi` aliases physical
    /// register `i` directly, per the Intel SDM).
    #[inline]
    pub fn mmx(&self, i: u8) -> u64 {
        self.st[(i & 7) as usize] as u64
    }

    /// Write MMX register `MM(i)`. Per the SDM, an MMX write stores the 64-bit
    /// value in the mantissa and sets bits 64:79 (exponent + sign) of the
    /// aliased x87 register to all 1s, and marks the register **valid** in the
    /// tag word. (TOP is left untouched; MMX access is physical, not relative.)
    #[inline]
    pub fn set_mmx(&mut self, i: u8, v: u64) {
        let idx = (i & 7) as usize;
        self.st[idx] = (0xFFFFu128 << 64) | (v as u128);
        // Tag word: 2 bits per physical register, 00 = valid.
        self.tw &= !(0b11u16 << (idx * 2));
    }

    /// `EMMS` — mark all x87/MMX registers empty (tag word = 0xFFFF). The
    /// register contents are left unchanged.
    #[inline]
    pub fn emms(&mut self) {
        self.tw = 0xFFFF;
    }
}

/// The full architectural register file.
#[derive(Debug, Clone)]
pub struct CpuState {
    /// The 16 general-purpose registers, indexed by [`Reg`].
    pub gpr: [u64; 16],
    /// The low 128 bits of the 16 vector registers — the SSE/SSE2 `xmm0`..`xmm15`
    /// view. On a real CPU these are the low halves of the 256-bit `ymm`
    /// registers; [`Self::ymm_hi`] holds the upper halves. Legacy (non-VEX) SSE
    /// writes touch only this array (upper halves preserved); VEX.128 writes
    /// zero the corresponding [`Self::ymm_hi`] lane (see `crates/cpu/src/vex.rs`).
    pub xmm: [u128; 16],
    /// The upper 128 bits of the 16 vector registers — `ymm0[255:128]`..
    /// `ymm15[255:128]`. Together with [`Self::xmm`] this forms the full 256-bit
    /// AVX register file. Legacy SSE preserves these; VEX.128 zeroes them;
    /// VEX.256 writes them.
    pub ymm_hi: [u128; 16],
    /// The x87 FPU register stack and its control/status/tag words.
    pub x87: X87,
    /// Instruction pointer.
    pub rip: u64,
    /// Status/control flags.
    pub rflags: u64,
    /// The `gs` segment base used to resolve `gs:[disp]` operands. In 64-bit
    /// mode this is where the current thread's TEB lives, so it is a
    /// **per-thread** value: the scheduler saves/loads it with the rest of the
    /// state on a context switch, and each new thread gets its own TEB base
    /// (roadmap W2.9). Defaults to the process's initial TEB base
    /// ([`DEFAULT_GS_BASE`]); the `exemu-cpu` interpreter mirrors that constant.
    pub gs_base: u64,
    /// The `fs` segment base used to resolve `fs:[disp]` operands. In 32-bit
    /// mode this is where the current thread's TEB lives (the 64-bit `fs` base
    /// is unused by Windows guests). Per-thread for the same reason as
    /// [`Self::gs_base`]. Defaults to [`DEFAULT_FS_BASE`].
    pub fs_base: u64,
}

/// The default `gs` segment base (the process's initial 64-bit TEB). The
/// `exemu-cpu` crate re-exports the same value as `GS_BASE`; the two must stay
/// equal (a debug assertion in the interpreter checks it). Kept here so
/// [`CpuState::new`] needs no dependency on the interpreter crate.
pub const DEFAULT_GS_BASE: u64 = 0x0000_7FFF_0000_0000;
/// The default 32-bit `fs` segment base (the process's initial 32-bit TEB).
/// Mirrors `exemu-cpu`'s `FS_BASE_32`.
pub const DEFAULT_FS_BASE: u64 = 0x7EFD_0000;

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
            ymm_hi: [0; 16],
            x87: X87::new(),
            rip: 0,
            rflags: flags::RESERVED_ONE | flags::IF,
            gs_base: DEFAULT_GS_BASE,
            fs_base: DEFAULT_FS_BASE,
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

    // ---- vector (XMM/YMM) access -----------------------------------------

    /// Read the low 128 bits of vector register `i` (the `xmm` view).
    #[inline]
    pub fn xmm(&self, i: u8) -> u128 {
        self.xmm[i as usize & 0xf]
    }

    /// Read the high 128 bits of vector register `i` (`ymm[255:128]`).
    #[inline]
    pub fn ymm_hi(&self, i: u8) -> u128 {
        self.ymm_hi[i as usize & 0xf]
    }

    /// Write the full 256-bit YMM register `i` from `(low, high)` halves.
    #[inline]
    pub fn set_ymm(&mut self, i: u8, low: u128, high: u128) {
        let idx = i as usize & 0xf;
        self.xmm[idx] = low;
        self.ymm_hi[idx] = high;
    }

    /// Write the low 128 bits of vector register `i` and **zero** its upper
    /// half. This is the VEX.128 destination-update rule: any VEX-encoded
    /// instruction with a 128-bit destination clears `ymm[255:128]`.
    #[inline]
    pub fn set_xmm_zero_upper(&mut self, i: u8, low: u128) {
        let idx = i as usize & 0xf;
        self.xmm[idx] = low;
        self.ymm_hi[idx] = 0;
    }

    /// Write the low 128 bits of vector register `i`, **preserving** its upper
    /// half. This is the legacy-SSE destination-update rule.
    #[inline]
    pub fn set_xmm_keep_upper(&mut self, i: u8, low: u128) {
        self.xmm[i as usize & 0xf] = low;
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
    /// A native `SYSCALL` (`0F 05`) was executed. The payload is the SSDT index
    /// (`eax` at the point of the instruction). The hardware side-effects are
    /// already applied by the interpreter (return `rip`→`rcx`, `rflags`→`r11`,
    /// `rip` advanced past the instruction); the OS layer's [`Hooks::syscall`]
    /// services it. See roadmap W2.2.
    Syscall(u32),
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
