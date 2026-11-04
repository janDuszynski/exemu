#![forbid(unsafe_code)]

mod alu;

use exemu_core::cpu::flags;
use exemu_core::{Cpu, CpuState, EmuError, Exit, GuestClock, Hooks, Memory, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bits {
    B32,
    B64,
}

pub struct Interpreter {
    state: CpuState,
    bits: Bits,
    tsc: u64,
    clock: GuestClock,
    mxcsr: u32,
    xcr0: u64,
}

const MXCSR_MASK: u32 = 0x0000_FFFF;

const XCR0_SUPPORTED: u64 = 0b111;

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    pub fn new() -> Self {
        Interpreter::with_bits(Bits::B64)
    }

    pub fn with_bits(bits: Bits) -> Self {
        Interpreter {
            state: CpuState::new(),
            bits,
            tsc: 0,
            mxcsr: 0x1F80,
            xcr0: XCR0_SUPPORTED,
            clock: GuestClock::host(),
        }
    }

    pub fn with_state(state: CpuState) -> Self {
        Interpreter { state, ..Interpreter::with_bits(Bits::B64) }
    }

    pub fn bits(&self) -> Bits {
        self.bits
    }

    pub fn set_bits(&mut self, bits: Bits) {
        self.bits = bits;
    }

    pub fn set_clock(&mut self, clock: GuestClock) {
        self.clock = clock;
    }

    pub fn clock(&self) -> &GuestClock {
        &self.clock
    }

    #[inline]
    fn read_tsc(&mut self) -> u64 {
        match self.clock.tsc() {
            Some(t) => t,
            None => {
                let t = self.tsc;
                self.tsc = self.tsc.wrapping_add(64);
                t
            }
        }
    }

    pub fn mxcsr(&self) -> u32 {
        self.mxcsr
    }

    pub fn set_mxcsr(&mut self, v: u32) {
        self.mxcsr = v & MXCSR_MASK;
    }

    pub fn xcr0(&self) -> u64 {
        self.xcr0
    }

    #[inline]
    fn addr_mask(&self) -> u64 {
        match self.bits {
            Bits::B64 => u64::MAX,
            Bits::B32 => 0xFFFF_FFFF,
        }
    }

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
        self.clock.retire_one();
        if let Some(exit) = hooks.intercept(self.state.rip, &mut self.state, mem)? {
            return Ok(exit);
        }
        match self.execute_one(mem)? {
            Exit::Syscall(index) => hooks.syscall(index, &mut self.state, mem),
            other => Ok(other),
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Prefixes {
    rex: u8,
    has_rex: bool,
    p66: bool,
    rep: u8,
    seg: u8,
    lock: bool,
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

#[derive(Clone, Copy)]
enum Rm {
    Reg(u8),
    Mem { base: u64, disp: i64, rip_rel: bool },
}

pub(crate) const IBUF_LEN: usize = 16;

struct Ctx {
    pfx: Prefixes,
    cur: u64,
    reg: u8,
    rm: Rm,
    bits: Bits,
    u8_at_op: u8,
    ibuf: [u8; IBUF_LEN],
    ibuf_base: u64,
    ibuf_n: u8,
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
    #[inline]
    fn prefetch(mem: &dyn Memory, addr: u64) -> ([u8; IBUF_LEN], u8) {
        let mut buf = [0u8; IBUF_LEN];
        if mem.fetch(addr, &mut buf).is_ok() {
            (buf, IBUF_LEN as u8)
        } else {
            (buf, 0)
        }
    }

    #[inline]
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let off = self.cur.wrapping_sub(self.ibuf_base);
        if off < (self.ibuf_n as u64).saturating_sub(N as u64 - 1) {
            let i = off as usize;
            let mut out = [0u8; N];
            out.copy_from_slice(&self.ibuf[i..i + N]);
            self.cur += N as u64;
            Some(out)
        } else {
            None
        }
    }

    #[cfg(feature = "profile")]
    #[inline]
    fn peek(&self) -> Option<u8> {
        let off = self.cur.wrapping_sub(self.ibuf_base);
        if off < self.ibuf_n as u64 {
            Some(self.ibuf[off as usize])
        } else {
            None
        }
    }

    #[inline]
    fn u8(&mut self, mem: &dyn Memory) -> Result<u8> {
        match self.take::<1>() {
            Some([b]) => Ok(b),
            None => self.u8_slow(mem),
        }
    }

    #[cold]
    #[inline(never)]
    fn u8_slow(&mut self, mem: &dyn Memory) -> Result<u8> {
        let mut b = [0u8; 1];
        mem.fetch(self.cur, &mut b)?;
        self.cur += 1;
        Ok(b[0])
    }

    #[inline]
    fn u16(&mut self, mem: &dyn Memory) -> Result<u16> {
        match self.take::<2>() {
            Some(v) => Ok(u16::from_le_bytes(v)),
            None => Ok(u16::from_le_bytes([self.u8(mem)?, self.u8(mem)?])),
        }
    }
    #[inline]
    fn u32(&mut self, mem: &dyn Memory) -> Result<u32> {
        if let Some(v) = self.take::<4>() {
            return Ok(u32::from_le_bytes(v));
        }
        let mut v = [0u8; 4];
        for x in &mut v {
            *x = self.u8(mem)?;
        }
        Ok(u32::from_le_bytes(v))
    }
    #[inline]
    fn u64(&mut self, mem: &dyn Memory) -> Result<u64> {
        if let Some(v) = self.take::<8>() {
            return Ok(u64::from_le_bytes(v));
        }
        let mut v = [0u8; 8];
        for x in &mut v {
            *x = self.u8(mem)?;
        }
        Ok(u64::from_le_bytes(v))
    }

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

impl Interpreter {
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
                0x67 => {}
                0xF0 => ctx.pfx.lock = true,
                0xF2 | 0xF3 => ctx.pfx.rep = b,
                0x2E | 0x36 | 0x3E | 0x26 => {}
                0x64 | 0x65 => ctx.pfx.seg = b,
                0x40..=0x4F if ctx.bits == Bits::B64 => {
                    ctx.pfx.rex = b;
                    ctx.pfx.has_rex = true;
                    return Ok(());
                }
                _ => {
                    ctx.cur -= 1;
                    return Ok(());
                }
            }
        }
    }

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

        let (mut base, mut rip_rel) = (0u64, false);

        if rm == 4 {
            let sib = ctx.u8(mem)?;
            let scale = 1u64 << (sib >> 6);
            let index = ((sib >> 3) & 7) | (ctx.pfx.x() << 3);
            let base_reg = (sib & 7) | (ctx.pfx.b() << 3);

            if (sib >> 3) & 7 != 4 || ctx.pfx.x() != 0 {
                base = base.wrapping_add(self.state.reg_at(index).wrapping_mul(scale));
            }

            if sib & 7 == 5 && mod_ == 0 {
                let disp = ctx.u32(mem)? as i32 as i64;
                if ctx.pfx.seg == 0x65 {
                    base = base.wrapping_add(self.state.gs_base);
                } else if ctx.pfx.seg == 0x64 {
                    base = base.wrapping_add(self.fs_base(ctx.bits));
                }
                ctx.rm = Rm::Mem { base, disp, rip_rel: false };
                return Ok(());
            } else {
                base = base.wrapping_add(self.state.reg_at(base_reg));
            }
        } else if rm == 5 && mod_ == 0 {
            let disp = ctx.u32(mem)? as i32 as i64;
            let rip_rel = ctx.bits == Bits::B64;
            let mut base = 0u64;
            if ctx.pfx.seg == 0x65 {
                base = self.state.gs_base;
            } else if ctx.pfx.seg == 0x64 {
                base = self.fs_base(ctx.bits);
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

        if ctx.pfx.seg == 0x65 {
            base = base.wrapping_add(self.state.gs_base);
        } else if ctx.pfx.seg == 0x64 {
            base = base.wrapping_add(self.fs_base(ctx.bits));
        }

        ctx.rm = Rm::Mem { base, disp, rip_rel: false };
        Ok(())
    }

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

    fn imm_z(&self, ctx: &mut Ctx, mem: &dyn Memory, size: u8) -> Result<u64> {
        Ok(if size == 2 {
            alu::sext(ctx.u16(mem)? as u64, 2)
        } else {
            alu::sext(ctx.u32(mem)? as u64, 4)
        } & alu::mask(size))
    }

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

pub const GS_BASE: u64 = exemu_core::cpu::DEFAULT_GS_BASE;
pub const FS_BASE: u64 = 0x0000_7FFE_0000_0000;
pub const FS_BASE_32: u64 = exemu_core::cpu::DEFAULT_FS_BASE;

impl Interpreter {
    #[inline]
    fn fs_base(&self, bits: Bits) -> u64 {
        match bits {
            Bits::B32 => self.state.fs_base,
            Bits::B64 => FS_BASE,
        }
    }
}

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
#[cfg(feature = "profile")]
pub mod profile;
mod sse;
mod vex;
mod x87;

pub use exec::{CpuidFeature, CpuidReg};
pub use exemu_core::cpu::{SEL_CS32, SEL_CS64, SEL_DATA};

pub fn is_sse_opcode(op2: u8) -> bool {
    sse::is_sse(op2)
}

pub fn is_mmx_opcode(op2: u8) -> bool {
    mmx::is_mmx(op2)
}
