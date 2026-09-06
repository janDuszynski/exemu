use crate::hooks::Hooks;
use crate::memory::Memory;
use crate::Result;

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

pub mod flags {
    pub const CF: u64 = 1 << 0;
    pub const PF: u64 = 1 << 2;
    pub const AF: u64 = 1 << 4;
    pub const ZF: u64 = 1 << 6;
    pub const SF: u64 = 1 << 7;
    pub const TF: u64 = 1 << 8;
    pub const IF: u64 = 1 << 9;
    pub const DF: u64 = 1 << 10;
    pub const OF: u64 = 1 << 11;

    pub const RESERVED_ONE: u64 = 1 << 1;
}

#[derive(Debug, Clone)]
pub struct X87 {
    pub st: [u128; 8],
    pub cw: u16,
    pub sw: u16,
    pub tw: u16,
    pub fop: u16,
    pub fip: u64,
    pub fcs: u16,
    pub fdp: u64,
    pub fds: u16,
}

impl Default for X87 {
    fn default() -> Self {
        Self::new()
    }
}

impl X87 {
    pub const fn new() -> Self {
        X87 { st: [0; 8], cw: 0x037F, sw: 0x0000, tw: 0xFFFF, fop: 0, fip: 0, fcs: 0, fdp: 0, fds: 0 }
    }

    #[inline]
    pub fn top(&self) -> u8 {
        ((self.sw >> 11) & 7) as u8
    }

    #[inline]
    pub fn set_top(&mut self, top: u8) {
        self.sw = (self.sw & !0x3800) | (((top as u16) & 7) << 11);
    }

    #[inline]
    pub fn phys(&self, i: u8) -> usize {
        ((self.top().wrapping_add(i)) & 7) as usize
    }

    #[inline]
    pub fn mmx(&self, i: u8) -> u64 {
        self.st[(i & 7) as usize] as u64
    }

    #[inline]
    pub fn set_mmx(&mut self, i: u8, v: u64) {
        let idx = (i & 7) as usize;
        self.st[idx] = (0xFFFFu128 << 64) | (v as u128);
        self.tw &= !(0b11u16 << (idx * 2));
    }

    #[inline]
    pub fn emms(&mut self) {
        self.tw = 0xFFFF;
    }
}

#[derive(Debug, Clone)]
pub struct CpuState {
    pub gpr: [u64; 16],
    pub xmm: [u128; 16],
    pub ymm_hi: [u128; 16],
    pub x87: X87,
    pub rip: u64,
    pub rflags: u64,
    pub gs_base: u64,
    pub fs_base: u64,
}

pub const DEFAULT_GS_BASE: u64 = 0x0000_7FFF_0000_0000;
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
            4 => *slot = value & 0xffff_ffff,
            _ => *slot = value,
        }
    }

    #[inline]
    pub fn gpr_read_high8(&self, index: u8) -> u64 {
        (self.gpr[index as usize & 0x3] >> 8) & 0xff
    }

    #[inline]
    pub fn gpr_write_high8(&mut self, index: u8, value: u64) {
        let slot = &mut self.gpr[index as usize & 0x3];
        *slot = (*slot & !0xff00) | ((value & 0xff) << 8);
    }

    #[inline]
    pub fn xmm(&self, i: u8) -> u128 {
        self.xmm[i as usize & 0xf]
    }

    #[inline]
    pub fn ymm_hi(&self, i: u8) -> u128 {
        self.ymm_hi[i as usize & 0xf]
    }

    #[inline]
    pub fn set_ymm(&mut self, i: u8, low: u128, high: u128) {
        let idx = i as usize & 0xf;
        self.xmm[idx] = low;
        self.ymm_hi[idx] = high;
    }

    #[inline]
    pub fn set_xmm_zero_upper(&mut self, i: u8, low: u128) {
        let idx = i as usize & 0xf;
        self.xmm[idx] = low;
        self.ymm_hi[idx] = 0;
    }

    #[inline]
    pub fn set_xmm_keep_upper(&mut self, i: u8, low: u128) {
        self.xmm[i as usize & 0xf] = low;
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    Continue,
    Halted,
    Interrupt(u8),
    Syscall(u32),
    ProcessExit(i32),
}

pub trait Cpu {
    fn state(&self) -> &CpuState;
    fn state_mut(&mut self) -> &mut CpuState;

    fn step(&mut self, mem: &mut dyn Memory, hooks: &mut dyn Hooks) -> Result<Exit>;
}
