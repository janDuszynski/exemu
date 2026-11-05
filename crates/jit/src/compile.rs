use crate::a64::{Asm, Cond, Label, ZR};
use crate::rt::{ctx_off, status, tlb_off, TLB_PAGE_BITS, TLB_SLOT_BITS};
use exemu_core::cpu::CpuState;
use exemu_core::Memory;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Protected,
    Long,
}

impl Mode {
    #[inline]
    fn is64(self) -> bool {
        self == Mode::Long
    }
    #[inline]
    fn addr_mask(self) -> u64 {
        match self {
            Mode::Long => u64::MAX,
            Mode::Protected => 0xFFFF_FFFF,
        }
    }
    #[inline]
    fn stack_width(self) -> u8 {
        match self {
            Mode::Long => 8,
            Mode::Protected => 4,
        }
    }
}

const R_STATE: u32 = 19;
const R_CTX: u32 = 20;
const R_FLAGS: u32 = 21;
const R_PARITY: u32 = 22;
const R_FA: u32 = 23;
const R_FB: u32 = 24;
const R_FR: u32 = 25;
const R_VAL: u32 = 26;
const R_ADDR: u32 = 27;
const R_MASK: u32 = 28;

const TLB_ENTRY_SHIFT: u32 = 5;

const FRAME: i32 = 128;

const FSPILL: i32 = 96;

const T0: u32 = 9;
const T1: u32 = 10;
const T2: u32 = 11;
const T3: u32 = 12;

const F_CF: u32 = 0;
const F_PF: u32 = 2;
const F_AF: u32 = 4;
const F_ZF: u32 = 6;
const F_SF: u32 = 7;
const F_OF: u32 = 11;
const ARITH_MASK: u64 = (1 << F_CF) | (1 << F_PF) | (1 << F_AF) | (1 << F_ZF) | (1 << F_SF) | (1 << F_OF);

mod st {
    use super::CpuState;
    pub const GPR: u32 = std::mem::offset_of!(CpuState, gpr) as u32;
    pub const RIP: u32 = std::mem::offset_of!(CpuState, rip) as u32;
    pub const RFLAGS: u32 = std::mem::offset_of!(CpuState, rflags) as u32;
    pub const GS_BASE: u32 = std::mem::offset_of!(CpuState, gs_base) as u32;
    pub const FS_BASE: u32 = std::mem::offset_of!(CpuState, fs_base) as u32;
}

#[inline]
fn gpr_off(i: u8) -> u32 {
    st::GPR + 8 * (i as u32 & 15)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    Unsupported { rip: u64, opcode: u8, esc: bool },
    FetchFailed { rip: u64 },
    Full,
    Terminator,
    Wrapped,
    Breakpoint { rip: u64 },
}

pub struct BlockPlan {
    pub start: u64,
    pub insns: u32,
    pub end_rip: u64,
    pub bytes: u64,
    pub code: Vec<u32>,
    pub stop: StopReason,
    pub chain_off: u32,
    pub links: Vec<u64>,
}

pub const MAX_INSNS: u32 = 64;

#[derive(Clone, Copy, Default)]
struct Pfx {
    rex: u8,
    has_rex: bool,
    p66: bool,
    seg: u8,
}

impl Pfx {
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

#[derive(Clone, Copy, Default)]
struct MemOp {
    base: Option<u8>,
    index: Option<u8>,
    scale: u32,
    disp: i64,
    abs: Option<u64>,
    seg: u8,
}

#[derive(Clone, Copy)]
enum Rm {
    Reg(u8),
    Mem(MemOp),
}

struct Insn {
    pfx: Pfx,
    opcode: u8,
    esc: bool,
    reg: u8,
    rm: Rm,
    imm: u64,
    len: u8,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        let mut v = [0u8; 4];
        for x in &mut v {
            *x = self.u8()?;
        }
        Some(u32::from_le_bytes(v))
    }
    fn u64(&mut self) -> Option<u64> {
        let mut v = [0u8; 8];
        for x in &mut v {
            *x = self.u8()?;
        }
        Some(u64::from_le_bytes(v))
    }
}

#[inline]
fn sext(v: u64, size: u8) -> u64 {
    match size {
        1 => v as u8 as i8 as i64 as u64,
        2 => v as u16 as i16 as i64 as u64,
        4 => v as u32 as i32 as i64 as u64,
        _ => v,
    }
}

#[inline]
fn mask_of(size: u8) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alu {
    Add,
    Or,
    And,
    Sub,
    Xor,
    Cmp,
}

impl Alu {
    fn from_op(op: u8) -> Option<Alu> {
        match op & 7 {
            0 => Some(Alu::Add),
            1 => Some(Alu::Or),
            4 => Some(Alu::And),
            5 => Some(Alu::Sub),
            6 => Some(Alu::Xor),
            7 => Some(Alu::Cmp),
            _ => None,
        }
    }
    fn writes_back(self) -> bool {
        self != Alu::Cmp
    }
}

#[derive(Clone, Copy)]
enum Commit {
    None,
    Flags,
    Gpr { idx: u8, size: u8, has_rex: bool },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flags {
    Live,
    Arith { size: u8, sub: bool, keep_cf: bool },
    Logic { size: u8 },
}

struct FaultStub {
    label: Label,
    retired: u32,
    rip: u64,
    flags: Flags,
}

struct StoreStub {
    label: Label,
    retired: u32,
    rip: u64,
    next_rip: u64,
    next_reg: Option<u32>,
    commit: Commit,
    before: Flags,
    after: Flags,
    spilled: bool,
}

pub struct Compiler {
    asm: Asm,
    mode: Mode,
    insns: u32,
    rip: u64,
    flags: Flags,
    insn_flags: Flags,
    defer: bool,
    spilled: bool,
    fault_stubs: Vec<FaultStub>,
    store_stubs: Vec<StoreStub>,
    exits: Vec<Label>,
    slot_base: Option<u32>,
    link_targets: Vec<u64>,
}

pub const MAX_LINKS: u32 = 2;

pub const SLOT_BYTES: u32 = std::mem::size_of::<crate::rt::LinkSlot>() as u32;

pub const INDIRECT_TARGET: u64 = u64::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ExitKind {
    Return,
    Fault,
    Link,
}

impl ExitKind {
    fn of(linkable: bool) -> ExitKind {
        if linkable {
            ExitKind::Link
        } else {
            ExitKind::Return
        }
    }
}

pub const RET_FAULT: u64 = 1 << 32;

impl Compiler {
    pub fn compile<M: Memory + ?Sized>(
        mem: &M,
        mode: Mode,
        start: u64,
        max_insns: u32,
        slot_base: Option<u32>,
        stop_before: u64,
    ) -> BlockPlan {
        let mut c = Compiler {
            asm: Asm::new(),
            mode,
            insns: 0,
            rip: start,
            flags: Flags::Live,
            insn_flags: Flags::Live,
            defer: false,
            spilled: false,
            fault_stubs: Vec::new(),
            store_stubs: Vec::new(),
            exits: Vec::new(),
            slot_base,
            link_targets: Vec::new(),
        };
        c.prologue();
        let chain_off = c.asm.len() as u32;
        c.asm.mov_imm64(T0, start);
        let bytes_at = c.asm.len();
        c.asm.nop();
        c.asm.stp(T0, T1, R_CTX, ctx_off::CODE_LO as i32);
        let mut stop = StopReason::Full;
        let mut rip = start;
        while c.insns < max_insns {
            if rip == stop_before {
                stop = StopReason::Breakpoint { rip };
                break;
            }
            c.rip = rip;
            let mut window = [0u8; 16];
            let mut valid = window.len();
            if mem.fetch(rip, &mut window).is_err() {
                let mut n = 0;
                while n < 16 {
                    let mut b = [0u8; 1];
                    if mem.fetch(rip.wrapping_add(n as u64), &mut b).is_err() {
                        break;
                    }
                    window[n] = b[0];
                    n += 1;
                }
                if n == 0 {
                    stop = StopReason::FetchFailed { rip };
                    break;
                }
                valid = n;
            }
            let insn = match decode(&window[..valid], mode, rip) {
                Some(i) => i,
                None => {
                    stop = StopReason::Unsupported { rip, opcode: window[0], esc: false };
                    break;
                }
            };
            let next = rip.wrapping_add(insn.len as u64) & mode.addr_mask();
            let sets_flags = flag_effect(&insn) != FlagEffect::Neutral;
            c.defer = sets_flags && defer_pays(mem, mode, next, DEFER_SCAN);
            c.spilled = sets_flags && matches!(insn.rm, Rm::Mem(_));
            if c.spilled {
                c.asm.stp(R_FLAGS, R_FR, crate::a64::SP, FSPILL);
                if c.flags != Flags::Live {
                    c.asm.stp(R_FA, R_FB, crate::a64::SP, FSPILL + 16);
                }
            }
            match c.lower(&insn, next) {
                Lowered::Ok => {
                    c.insns += 1;
                    rip = next;
                    if next < start {
                        stop = StopReason::Wrapped;
                        break;
                    }
                }
                Lowered::Terminated => {
                    c.insns += 1;
                    rip = next;
                    stop = StopReason::Terminator;
                    break;
                }
                Lowered::Unsupported => {
                    stop = StopReason::Unsupported { rip, opcode: insn.opcode, esc: insn.esc };
                    break;
                }
            }
        }
        let end_rip = rip;
        let insns = c.insns;
        if stop != StopReason::Terminator {
            let linkable = matches!(stop, StopReason::Full | StopReason::Wrapped);
            c.exit_to(c.flags, end_rip, insns, ExitKind::of(linkable));
        }
        c.emit_stubs();
        c.epilogue();
        let bytes = end_rip.wrapping_sub(start) & mode.addr_mask();
        assert!(bytes < 4096, "block byte length {bytes} does not fit an add immediate");
        {
            let mut patch = Asm::new();
            patch.add_imm(true, T1, T0, bytes as u32, false);
            c.asm.words_mut()[bytes_at] = patch.words()[0];
        }
        BlockPlan {
            start,
            insns,
            end_rip,
            bytes,
            code: c.asm.into_words(),
            stop,
            chain_off,
            links: c.link_targets,
        }
    }

    fn prologue(&mut self) {
        let a = &mut self.asm;
        a.stp_pre(19, 20, crate::a64::SP, -FRAME);
        a.stp(21, 22, crate::a64::SP, 16);
        a.stp(23, 24, crate::a64::SP, 32);
        a.stp(25, 26, crate::a64::SP, 48);
        a.stp(27, 28, crate::a64::SP, 64);
        a.str(8, 30, crate::a64::SP, 80);
        a.mov_reg(true, R_STATE, 0);
        a.mov_reg(true, R_CTX, 1);
        a.ldr(8, R_FLAGS, R_STATE, st::RFLAGS);
        a.ldr(8, R_PARITY, R_CTX, ctx_off::PARITY);
        a.mov_imm64(R_MASK, ARITH_MASK);
    }

    fn epilogue(&mut self) {
        let labels: Vec<Label> = std::mem::take(&mut self.exits);
        for l in labels {
            self.asm.bind(l);
        }
        let a = &mut self.asm;
        a.str(8, R_FLAGS, R_STATE, st::RFLAGS);
        a.ldp(21, 22, crate::a64::SP, 16);
        a.ldp(23, 24, crate::a64::SP, 32);
        a.ldp(25, 26, crate::a64::SP, 48);
        a.ldp(27, 28, crate::a64::SP, 64);
        a.ldr(8, 30, crate::a64::SP, 80);
        a.ldp_post(19, 20, crate::a64::SP, FRAME);
        a.ret();
    }

    fn take_slot(&mut self, target: u64) -> Option<u32> {
        let base = self.slot_base?;
        let n = self.link_targets.len() as u32;
        if n >= MAX_LINKS {
            return None;
        }
        self.link_targets.push(target);
        Some(base + n)
    }

    fn exit_to(&mut self, flags: Flags, rip: u64, retired: u32, kind: ExitKind) {
        self.emit_flags(flags);
        self.asm.mov_imm64(T2, rip);
        let slot = if kind == ExitKind::Link { self.take_slot(rip) } else { None };
        self.emit_exit_tail(retired, kind == ExitKind::Fault, slot, false);
    }

    fn exit_indirect(&mut self, flags: Flags, target: u32, retired: u32) {
        self.emit_flags(flags);
        self.asm.mov_reg(true, T2, target);
        let slot = self.take_slot(INDIRECT_TARGET);
        self.emit_exit_tail(retired, false, slot, true);
    }

    fn emit_exit_tail(&mut self, retired: u32, fault: bool, slot: Option<u32>, indirect: bool) {
        self.asm.str(8, T2, R_STATE, st::RIP);
        self.asm.ldr(8, T0, R_CTX, ctx_off::RETIRED);
        if retired != 0 {
            self.asm.add_imm(true, T0, T0, retired, false);
            self.asm.str(8, T0, R_CTX, ctx_off::RETIRED);
        }
        if let Some(slot) = slot {
            self.asm.ldr(8, T1, R_CTX, ctx_off::LINK_LIMIT);
            self.asm.cmp_reg(true, T0, T1);
            let spent = self.asm.b_cond_forward(Cond::Cs);
            let off = slot * SLOT_BYTES;
            self.asm.ldr(8, T1, R_CTX, ctx_off::LINKS);
            let bias = if off + 16 <= 32_760 { 0 } else { off & !0xFFF };
            if bias != 0 {
                self.asm.add_imm(true, T1, T1, bias >> 12, true);
            }
            let at = off - bias;
            self.asm.ldr(8, T3, T1, at);
            self.asm.ldr(8, T0, R_CTX, ctx_off::LINK_EPOCH);
            self.asm.cmp_reg(true, T3, T0);
            let stale = self.asm.b_cond_forward(Cond::Ne);
            let missed = indirect.then(|| {
                self.asm.ldr(8, T3, T1, at + 8);
                self.asm.cmp_reg(true, T3, T2);
                self.asm.b_cond_forward(Cond::Ne)
            });
            self.asm.ldr(8, T1, T1, at + 16);
            self.asm.ldr(8, T3, R_CTX, ctx_off::TRAIL_AT);
            self.asm.add_imm(true, T0, T3, 1, false);
            self.asm.str(8, T0, R_CTX, ctx_off::TRAIL_AT);
            let ok = self.asm.and_imm(true, T3, T3, crate::rt::TRAIL as u64 - 1);
            debug_assert!(ok, "the trail ring size must be a logical immediate");
            self.asm.ldr(8, T0, R_CTX, ctx_off::TRAIL);
            self.asm.str_reg_lsl3(T2, T0, T3);
            self.asm.br(T1);
            self.asm.bind(stale);
            if let Some(m) = missed {
                self.asm.bind(m);
            }
            self.asm.bind(spent);
            self.asm.mov_imm64(T0, slot as u64);
            self.asm.str(8, T0, R_CTX, ctx_off::PENDING);
        }
        self.asm.mov_imm64(0, if fault { RET_FAULT } else { 0 });
        let l = self.asm.b_forward();
        self.exits.push(l);
    }

    fn emit_stubs(&mut self) {
        let stores = std::mem::take(&mut self.store_stubs);
        for s in stores {
            self.asm.bind(s.label);
            self.asm.subs_imm(true, ZR, 0, status::FAULT as u32, false);
            let is_fault = self.asm.b_cond_forward(Cond::Eq);
            self.emit_commit(s.commit);
            match s.next_reg {
                None => self.exit_to(s.after, s.next_rip, s.retired + 1, ExitKind::Return),
                Some(r) => {
                    self.emit_flags(s.after);
                    self.asm.mov_reg(true, T2, r);
                    self.emit_exit_tail(s.retired + 1, false, None, false);
                }
            }
            self.asm.bind(is_fault);
            if s.spilled {
                self.asm.ldp(R_FLAGS, R_FR, crate::a64::SP, FSPILL);
                if s.before != Flags::Live {
                    self.asm.ldp(R_FA, R_FB, crate::a64::SP, FSPILL + 16);
                }
            }
            self.exit_to(s.before, s.rip, s.retired, ExitKind::Fault);
        }
        let faults = std::mem::take(&mut self.fault_stubs);
        for f in faults {
            self.asm.bind(f.label);
            self.exit_to(f.flags, f.rip, f.retired, ExitKind::Fault);
        }
    }

    #[inline]
    fn high8(size: u8, has_rex: bool, idx: u8) -> bool {
        size == 1 && !has_rex && (4..8).contains(&idx)
    }

    fn load_gpr(&mut self, dst: u32, idx: u8, size: u8, has_rex: bool) {
        if Self::high8(size, has_rex, idx) {
            self.asm.ldr(1, dst, R_STATE, gpr_off(idx & 3) + 1);
        } else {
            self.asm.ldr(size, dst, R_STATE, gpr_off(idx));
        }
    }

    fn store_gpr(&mut self, src: u32, idx: u8, size: u8, has_rex: bool) {
        if Self::high8(size, has_rex, idx) {
            self.asm.str(1, src, R_STATE, gpr_off(idx & 3) + 1);
        } else if size == 4 {
            self.asm.str(8, src, R_STATE, gpr_off(idx));
        } else {
            self.asm.str(size, src, R_STATE, gpr_off(idx));
        }
    }

    fn emit_addr(&mut self, m: &MemOp) {
        if let Some(abs) = m.abs {
            self.asm.mov_imm64(R_ADDR, abs & self.mode.addr_mask());
            return;
        }
        let mut have = false;
        if let Some(b) = m.base {
            self.asm.ldr(8, R_ADDR, R_STATE, gpr_off(b));
            have = true;
        }
        if let Some(i) = m.index {
            self.asm.ldr(8, T0, R_STATE, gpr_off(i));
            if have {
                self.asm.add_reg(true, R_ADDR, R_ADDR, T0, m.scale);
            } else {
                self.asm.lsl_imm(true, R_ADDR, T0, m.scale);
                have = true;
            }
        }
        if !have {
            self.asm.mov_imm64(R_ADDR, 0);
        }
        match m.seg {
            0x65 => {
                self.asm.ldr(8, T0, R_STATE, st::GS_BASE);
                self.asm.add_reg(true, R_ADDR, R_ADDR, T0, 0);
            }
            0x64 => {
                self.asm.ldr(8, T0, R_STATE, st::FS_BASE);
                self.asm.add_reg(true, R_ADDR, R_ADDR, T0, 0);
            }
            _ => {}
        }
        if m.disp != 0 {
            let d = m.disp as u64;
            if m.disp > 0 && m.disp < 4096 {
                self.asm.add_imm(true, R_ADDR, R_ADDR, d as u32, false);
            } else if m.disp < 0 && -m.disp < 4096 {
                self.asm.sub_imm(true, R_ADDR, R_ADDR, (-m.disp) as u32, false);
            } else {
                self.asm.mov_imm64(T0, d);
                self.asm.add_reg(true, R_ADDR, R_ADDR, T0, 0);
            }
        }
        if !self.mode.is64() {
            let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
            debug_assert!(ok);
        }
    }

    fn emit_tlb_probe(&mut self, off: u32, size: u8) -> Label {
        debug_assert_eq!(tlb_off::SIZE, 1 << TLB_ENTRY_SHIFT);
        debug_assert!(matches!(size, 1 | 2 | 4 | 8));
        self.asm.ldr(8, T0, R_CTX, ctx_off::TLB);
        let last = if size == 1 {
            R_ADDR
        } else {
            self.asm.add_imm(true, T1, R_ADDR, size as u32 - 1, false);
            T1
        };
        self.asm.ubfx(true, T2, R_ADDR, TLB_PAGE_BITS, TLB_SLOT_BITS);
        self.asm.add_reg(true, T0, T0, T2, TLB_ENTRY_SHIFT);
        self.asm.ldp(T2, T3, T0, off as i32);
        self.asm.cmp_reg_lsr(true, T2, last, TLB_PAGE_BITS);
        self.asm.b_cond_forward(Cond::Ne)
    }

    fn emit_load(&mut self, dst: u32, size: u8) {
        let miss = self.emit_tlb_probe(tlb_off::READ, size);
        self.asm.ldr_reg(size, dst, T3, R_ADDR);
        let done = self.asm.b_forward();
        self.asm.bind(miss);
        self.asm.mov_reg(true, 0, R_CTX);
        self.asm.mov_reg(true, 1, R_ADDR);
        self.asm.mov_imm64(2, size as u64);
        self.asm.ldr(8, T0, R_CTX, ctx_off::READ);
        self.asm.blr(T0);
        let l = self.asm.cbnz_forward(true, 1);
        self.fault_stubs.push(FaultStub {
            label: l,
            retired: self.insns,
            rip: self.rip,
            flags: self.insn_flags,
        });
        self.asm.mov_reg(true, dst, 0);
        self.asm.bind(done);
    }

    fn emit_store(&mut self, src: u32, size: u8, commit: Commit, next_rip: u64) {
        let miss = self.emit_tlb_probe(tlb_off::WRITE, size);
        self.asm.str_reg(size, src, T3, R_ADDR);
        let done = self.asm.b_forward();
        self.asm.bind(miss);
        self.asm.mov_reg(true, 0, R_CTX);
        self.asm.mov_reg(true, 1, R_ADDR);
        self.asm.mov_imm64(2, size as u64);
        self.asm.mov_reg(true, 3, src);
        self.asm.ldr(8, T0, R_CTX, ctx_off::WRITE);
        self.asm.blr(T0);
        let l = self.asm.cbnz_forward(true, 0);
        self.store_stubs.push(StoreStub {
            label: l,
            retired: self.insns,
            rip: self.rip,
            next_rip,
            next_reg: None,
            commit,
            before: self.insn_flags,
            after: self.flags,
            spilled: self.spilled,
        });
        self.asm.bind(done);
        self.emit_commit(commit);
    }

    fn emit_commit(&mut self, c: Commit) {
        match c {
            Commit::None => {}
            Commit::Flags => self.asm.mov_reg(true, R_FLAGS, R_FA),
            Commit::Gpr { idx, size, has_rex } => self.store_gpr(R_VAL, idx, size, has_rex),
        }
    }

    fn read_rm(&mut self, rm: &Rm, dst: u32, size: u8, has_rex: bool) {
        match rm {
            Rm::Reg(i) => self.load_gpr(dst, *i, size, has_rex),
            Rm::Mem(_) => self.emit_load(dst, size),
        }
    }

    fn flags_szp_into(&mut self, dst: u32, res: u32, size: u8) {
        let bits = size as u32 * 8;
        self.asm.subs_imm(true, ZR, res, 0, false);
        self.asm.cset(true, T3, Cond::Eq);
        self.asm.orr_reg(true, dst, dst, T3, F_ZF);
        self.asm.ubfx(true, T3, res, bits - 1, 1);
        self.asm.orr_reg(true, dst, dst, T3, F_SF);
        let ok = self.asm.and_imm(true, T3, res, 0xff);
        debug_assert!(ok);
        self.asm.ldrb_reg(T3, R_PARITY, T3);
        self.asm.orr_reg(true, dst, dst, T3, F_PF);
    }

    fn emit_flags(&mut self, flags: Flags) {
        match flags {
            Flags::Live => {}
            Flags::Logic { size } => {
                self.asm.bic_reg(true, R_FLAGS, R_FLAGS, R_MASK, 0);
                self.flags_szp_into(R_FLAGS, R_FR, size);
            }
            Flags::Arith { size, sub, keep_cf } => {
                match size {
                    8 => {
                        if sub {
                            self.asm.subs_reg(true, ZR, R_FA, R_FB, 0);
                        } else {
                            self.asm.adds_reg(true, ZR, R_FA, R_FB, 0);
                        }
                    }
                    4 => {
                        if sub {
                            self.asm.subs_reg(false, ZR, R_FA, R_FB, 0);
                        } else {
                            self.asm.adds_reg(false, ZR, R_FA, R_FB, 0);
                        }
                    }
                    _ => {
                        let sh = 64 - size as u32 * 8;
                        self.asm.lsl_imm(true, T0, R_FA, sh);
                        self.asm.lsl_imm(true, T1, R_FB, sh);
                        if sub {
                            self.asm.subs_reg(true, ZR, T0, T1, 0);
                        } else {
                            self.asm.adds_reg(true, ZR, T0, T1, 0);
                        }
                    }
                }
                if keep_cf {
                    self.asm.mov_imm64(T2, ARITH_MASK & !(1 << F_CF));
                    self.asm.bic_reg(true, R_FLAGS, R_FLAGS, T2, 0);
                } else {
                    self.asm.bic_reg(true, R_FLAGS, R_FLAGS, R_MASK, 0);
                    self.asm.cset(true, T3, if sub { Cond::Cc } else { Cond::Cs });
                    self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_CF);
                }
                self.asm.cset(true, T3, Cond::Vs);
                self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_OF);
                self.asm.eor_reg(true, T3, R_FA, R_FB, 0);
                self.asm.eor_reg(true, T3, T3, R_FR, 0);
                self.asm.ubfx(true, T3, T3, 4, 1);
                self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_AF);
                self.flags_szp_into(R_FLAGS, R_FR, size);
            }
        }
    }

    fn materialize(&mut self) {
        if self.flags != Flags::Live {
            self.emit_flags(self.flags);
            self.flags = Flags::Live;
        }
        self.insn_flags = Flags::Live;
    }

    fn emit_arith_value(&mut self, size: u8, sub: bool) {
        match size {
            8 | 4 => {
                let sf = size == 8;
                if sub {
                    self.asm.sub_reg(sf, R_FR, R_FA, R_FB, 0);
                } else {
                    self.asm.add_reg(sf, R_FR, R_FA, R_FB, 0);
                }
            }
            _ => {
                if sub {
                    self.asm.sub_reg(true, R_FR, R_FA, R_FB, 0);
                } else {
                    self.asm.add_reg(true, R_FR, R_FA, R_FB, 0);
                }
                self.mask_to(R_FR, size);
            }
        }
    }

    fn emit_alu(&mut self, op: Alu, size: u8) {
        if self.defer {
            match op {
                Alu::Add => {
                    self.emit_arith_value(size, false);
                    self.flags = Flags::Arith { size, sub: false, keep_cf: false };
                }
                Alu::Sub | Alu::Cmp => {
                    self.emit_arith_value(size, true);
                    self.flags = Flags::Arith { size, sub: true, keep_cf: false };
                }
                _ => {
                    self.emit_logic_value(op);
                    self.flags = Flags::Logic { size };
                }
            }
            return;
        }
        match op {
            Alu::Add | Alu::Sub | Alu::Cmp => self.emit_arith_eager(size, op != Alu::Add, false),
            _ => {
                self.emit_logic_value(op);
                self.asm.bic_reg(true, R_FLAGS, R_FLAGS, R_MASK, 0);
                self.flags_szp_into(R_FLAGS, R_FR, size);
                self.flags = Flags::Live;
            }
        }
    }

    fn emit_arith_eager(&mut self, size: u8, sub: bool, keep_cf: bool) {
        match size {
            8 | 4 => {
                let sf = size == 8;
                if sub {
                    self.asm.subs_reg(sf, R_FR, R_FA, R_FB, 0);
                } else {
                    self.asm.adds_reg(sf, R_FR, R_FA, R_FB, 0);
                }
            }
            _ => {
                let sh = 64 - size as u32 * 8;
                self.asm.lsl_imm(true, T0, R_FA, sh);
                self.asm.lsl_imm(true, T1, R_FB, sh);
                if sub {
                    self.asm.subs_reg(true, R_FR, T0, T1, 0);
                } else {
                    self.asm.adds_reg(true, R_FR, T0, T1, 0);
                }
                self.asm.lsr_imm(true, R_FR, R_FR, sh);
            }
        }
        if keep_cf {
            self.asm.mov_imm64(T2, ARITH_MASK & !(1 << F_CF));
            self.asm.bic_reg(true, R_FLAGS, R_FLAGS, T2, 0);
        } else {
            self.asm.bic_reg(true, R_FLAGS, R_FLAGS, R_MASK, 0);
            self.asm.cset(true, T3, if sub { Cond::Cc } else { Cond::Cs });
            self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_CF);
        }
        self.asm.cset(true, T3, Cond::Vs);
        self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_OF);
        self.asm.eor_reg(true, T3, R_FA, R_FB, 0);
        self.asm.eor_reg(true, T3, T3, R_FR, 0);
        self.asm.ubfx(true, T3, T3, 4, 1);
        self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_AF);
        self.flags_szp_into(R_FLAGS, R_FR, size);
        self.flags = Flags::Live;
    }

    fn emit_logic_value(&mut self, op: Alu) {
        match op {
            Alu::And => self.asm.and_reg(true, R_FR, R_FA, R_FB, 0),
            Alu::Or => self.asm.orr_reg(true, R_FR, R_FA, R_FB, 0),
            _ => self.asm.eor_reg(true, R_FR, R_FA, R_FB, 0),
        }
    }

    fn branch_if_cond(&mut self, cc: u8) -> Label {
        match cc & 0xf {
            0x0 => self.asm.tbnz_forward(R_FLAGS, F_OF),
            0x1 => self.asm.tbz_forward(R_FLAGS, F_OF),
            0x2 => self.asm.tbnz_forward(R_FLAGS, F_CF),
            0x3 => self.asm.tbz_forward(R_FLAGS, F_CF),
            0x4 => self.asm.tbnz_forward(R_FLAGS, F_ZF),
            0x5 => self.asm.tbz_forward(R_FLAGS, F_ZF),
            0x8 => self.asm.tbnz_forward(R_FLAGS, F_SF),
            0x9 => self.asm.tbz_forward(R_FLAGS, F_SF),
            0xA => self.asm.tbnz_forward(R_FLAGS, F_PF),
            0xB => self.asm.tbz_forward(R_FLAGS, F_PF),
            other => {
                self.emit_cond_value(other, T0);
                self.asm.cbnz_forward(true, T0)
            }
        }
    }

    fn emit_cond_value(&mut self, cc: u8, dst: u32) {
        match cc & 0xf {
            0x0 => self.asm.ubfx(true, dst, R_FLAGS, F_OF, 1),
            0x1 => {
                self.asm.ubfx(true, dst, R_FLAGS, F_OF, 1);
                self.flip(dst);
            }
            0x2 => self.asm.ubfx(true, dst, R_FLAGS, F_CF, 1),
            0x3 => {
                self.asm.ubfx(true, dst, R_FLAGS, F_CF, 1);
                self.flip(dst);
            }
            0x4 => self.asm.ubfx(true, dst, R_FLAGS, F_ZF, 1),
            0x5 => {
                self.asm.ubfx(true, dst, R_FLAGS, F_ZF, 1);
                self.flip(dst);
            }
            0x6 | 0x7 => {
                self.asm.ubfx(true, dst, R_FLAGS, F_CF, 1);
                self.asm.ubfx(true, T3, R_FLAGS, F_ZF, 1);
                self.asm.orr_reg(true, dst, dst, T3, 0);
                if cc & 0xf == 0x7 {
                    self.flip(dst);
                }
            }
            0x8 => self.asm.ubfx(true, dst, R_FLAGS, F_SF, 1),
            0x9 => {
                self.asm.ubfx(true, dst, R_FLAGS, F_SF, 1);
                self.flip(dst);
            }
            0xA => self.asm.ubfx(true, dst, R_FLAGS, F_PF, 1),
            0xB => {
                self.asm.ubfx(true, dst, R_FLAGS, F_PF, 1);
                self.flip(dst);
            }
            0xC | 0xD => {
                self.asm.ubfx(true, dst, R_FLAGS, F_SF, 1);
                self.asm.ubfx(true, T3, R_FLAGS, F_OF, 1);
                self.asm.eor_reg(true, dst, dst, T3, 0);
                if cc & 0xf == 0xD {
                    self.flip(dst);
                }
            }
            _ => {
                self.asm.ubfx(true, dst, R_FLAGS, F_SF, 1);
                self.asm.ubfx(true, T3, R_FLAGS, F_OF, 1);
                self.asm.eor_reg(true, dst, dst, T3, 0);
                self.asm.ubfx(true, T3, R_FLAGS, F_ZF, 1);
                self.asm.orr_reg(true, dst, dst, T3, 0);
                if cc & 0xf == 0xF {
                    self.flip(dst);
                }
            }
        }
    }

    fn flip(&mut self, dst: u32) {
        let ok = self.asm.eor_imm(true, dst, dst, 1);
        debug_assert!(ok);
    }
}

enum Lowered {
    Ok,
    Terminated,
    Unsupported,
}

fn decode(window: &[u8], mode: Mode, rip: u64) -> Option<Insn> {
    let mut c = Cursor { buf: window, pos: 0 };
    let mut pfx = Pfx::default();
    let opcode = loop {
        let b = c.u8()?;
        match b {
            0x66 => pfx.p66 = true,
            0x2E | 0x36 | 0x3E | 0x26 => {}
            0x64 | 0x65 => pfx.seg = b,
            0xF0 | 0xF2 | 0xF3 | 0x67 => return None,
            0x40..=0x4F if mode.is64() => {
                pfx.rex = b;
                pfx.has_rex = true;
                break c.u8()?;
            }
            _ => break b,
        }
    };
    let (opcode, esc) = if opcode == 0x0F { (c.u8()?, true) } else { (opcode, false) };

    let opsize = |p: &Pfx| -> u8 {
        if mode.is64() && p.w() {
            8
        } else if p.p66 {
            2
        } else {
            4
        }
    };

    let has_modrm = if esc {
        matches!(opcode, 0x1F | 0x40..=0x4F | 0xAF | 0xB6 | 0xB7 | 0xBE | 0xBF)
    } else {
        match opcode {
            0x00..=0x3D if opcode & 7 < 4 => true,
            0x63 | 0x69 | 0x6B | 0x8D => true,
            0x80 | 0x81 | 0x83 | 0x84 | 0x85 | 0x88 | 0x89 | 0x8A | 0x8B => true,
            0xC0 | 0xC1 | 0xC6 | 0xC7 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => true,
            0xF6 | 0xF7 | 0xFE | 0xFF => true,
            _ => false,
        }
    };

    let mut reg = 0u8;
    let mut rm = Rm::Reg(0);
    let mut rip_rel_disp: Option<i64> = None;
    if has_modrm {
        let modrm = c.u8()?;
        let mod_ = modrm >> 6;
        reg = ((modrm >> 3) & 7) | (pfx.r() << 3);
        let rm_field = modrm & 7;
        if mod_ == 3 {
            rm = Rm::Reg(rm_field | (pfx.b() << 3));
        } else {
            let mut m = MemOp { seg: pfx.seg, ..Default::default() };
            if rm_field == 4 {
                let sib = c.u8()?;
                let scale = (sib >> 6) as u32;
                let index = ((sib >> 3) & 7) | (pfx.x() << 3);
                let base_reg = (sib & 7) | (pfx.b() << 3);
                if (sib >> 3) & 7 != 4 || pfx.x() != 0 {
                    m.index = Some(index);
                    m.scale = scale;
                }
                if sib & 7 == 5 && mod_ == 0 {
                    m.disp = c.u32()? as i32 as i64;
                } else {
                    m.base = Some(base_reg);
                    m.disp = match mod_ {
                        0 => 0,
                        1 => c.u8()? as i8 as i64,
                        _ => c.u32()? as i32 as i64,
                    };
                }
            } else if rm_field == 5 && mod_ == 0 {
                let disp = c.u32()? as i32 as i64;
                if mode.is64() {
                    rip_rel_disp = Some(disp);
                } else {
                    m.disp = disp;
                }
            } else {
                m.base = Some(rm_field | (pfx.b() << 3));
                m.disp = match mod_ {
                    0 => 0,
                    1 => c.u8()? as i8 as i64,
                    _ => c.u32()? as i32 as i64,
                };
            }
            rm = Rm::Mem(m);
        }
    }
    if mode.is64() {
        if let Rm::Mem(m) = rm {
            if m.seg == 0x64 {
                return None;
            }
        }
    }

    let mut imm = 0u64;
    if esc {
        if let 0x80..=0x8F = opcode {
            imm = c.u32()? as i32 as i64 as u64;
        }
    } else {
        match opcode {
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | 0xA8 => {
                imm = c.u8()? as u64;
            }
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0xA9 => {
                let size = opsize(&pfx);
                imm = if size == 2 { c.u16()? as u64 } else { sext(c.u32()? as u64, 4) } & mask_of(size);
            }
            0x6A => imm = c.u8()? as i8 as i64 as u64,
            0x68 => imm = c.u32()? as i32 as i64 as u64,
            0xA0..=0xA3 => imm = if mode.is64() { c.u64()? } else { c.u32()? as u64 },
            0x70..=0x7F | 0xEB => imm = c.u8()? as i8 as i64 as u64,
            0xE8 | 0xE9 => imm = c.u32()? as i32 as i64 as u64,
            0x80 => imm = c.u8()? as u64,
            0x81 => {
                let size = opsize(&pfx);
                imm = if size == 2 { c.u16()? as u64 } else { sext(c.u32()? as u64, 4) } & mask_of(size);
            }
            0x83 => {
                let size = opsize(&pfx);
                imm = sext(c.u8()? as u64, 1) & mask_of(size);
            }
            0x69 => {
                let size = opsize(&pfx);
                imm = if size == 2 { c.u16()? as u64 } else { sext(c.u32()? as u64, 4) } & mask_of(size);
            }
            0x6B => imm = sext(c.u8()? as u64, 1),
            0xB0..=0xB7 => imm = c.u8()? as u64,
            0xB8..=0xBF => {
                imm = if pfx.w() {
                    c.u64()?
                } else if pfx.p66 {
                    c.u16()? as u64
                } else {
                    c.u32()? as u64
                };
            }
            0xC0 | 0xC1 => imm = c.u8()? as u64,
            0xC2 => imm = c.u16()? as u64,
            0xC6 => imm = c.u8()? as u64,
            0xC7 => {
                let size = opsize(&pfx);
                imm = if size == 2 { c.u16()? as u64 } else { sext(c.u32()? as u64, 4) } & mask_of(size);
            }
            0xF6 if reg <= 1 => imm = c.u8()? as u64,
            0xF7 if reg <= 1 => {
                let size = opsize(&pfx);
                imm = if size == 2 { c.u16()? as u64 } else { sext(c.u32()? as u64, 4) } & mask_of(size);
            }
            _ => {}
        }
    }

    let len = c.pos as u8;
    if let Some(disp) = rip_rel_disp {
        if pfx.seg != 0 {
            return None;
        }
        let next = rip.wrapping_add(len as u64);
        let m = MemOp { abs: Some(next.wrapping_add(disp as u64)), ..Default::default() };
        rm = Rm::Mem(m);
    }
    Some(Insn { pfx, opcode, esc, reg, rm, imm, len })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlagEffect {
    Neutral,
    Overwrites,
    Reads,
}

fn flag_effect(insn: &Insn) -> FlagEffect {
    if insn.esc {
        return match insn.opcode {
            0x1F | 0xB6 | 0xB7 | 0xBE | 0xBF => FlagEffect::Neutral,
            _ => FlagEffect::Reads,
        };
    }
    match insn.opcode {
        0x00..=0x3D if insn.opcode & 7 < 6 => match Alu::from_op(insn.opcode >> 3) {
            Some(_) => FlagEffect::Overwrites,
            None => FlagEffect::Reads,
        },
        0x40..=0x4F => FlagEffect::Reads,
        0x50..=0x5F | 0x63 | 0x88..=0x8B | 0x8D | 0x90 | 0xB0..=0xBF => FlagEffect::Neutral,
        0x68 | 0x6A | 0xA0..=0xA3 | 0xC6 | 0xC7 | 0xC9 => FlagEffect::Neutral,
        0x80 | 0x81 | 0x83 => match Alu::from_op(insn.reg & 7) {
            Some(_) => FlagEffect::Overwrites,
            None => FlagEffect::Reads,
        },
        0x84 | 0x85 | 0xA8 | 0xA9 => FlagEffect::Overwrites,
        0xF6 | 0xF7 => match insn.reg & 7 {
            0 | 1 | 3 => FlagEffect::Overwrites,
            2 => FlagEffect::Neutral,
            _ => FlagEffect::Reads,
        },
        _ => FlagEffect::Reads,
    }
}

fn overwriter_settles(insn: &Insn) -> bool {
    if insn.esc || !matches!(insn.rm, Rm::Mem(_)) {
        return false;
    }
    match insn.opcode {
        0x00..=0x3D if insn.opcode & 7 < 2 => {
            Alu::from_op(insn.opcode >> 3).is_some_and(|o| o.writes_back())
        }
        0x80 | 0x81 | 0x83 => Alu::from_op(insn.reg & 7).is_some_and(|o| o.writes_back()),
        0xF6 | 0xF7 => insn.reg & 7 == 3,
        _ => false,
    }
}

const DEFER_SCAN: u32 = 12;

fn defer_pays<M: Memory + ?Sized>(mem: &M, mode: Mode, mut rip: u64, budget: u32) -> bool {
    for _ in 0..budget {
        let mut window = [0u8; 16];
        if mem.fetch(rip, &mut window).is_err() {
            return false;
        }
        let Some(insn) = decode(&window, mode, rip) else {
            return false;
        };
        match flag_effect(&insn) {
            FlagEffect::Overwrites => return !overwriter_settles(&insn),
            FlagEffect::Reads => return false,
            FlagEffect::Neutral => {}
        }
        rip = rip.wrapping_add(insn.len as u64) & mode.addr_mask();
    }
    false
}

impl Compiler {
    fn opsize(&self, p: &Pfx) -> u8 {
        if self.mode.is64() && p.w() {
            8
        } else if p.p66 {
            2
        } else {
            4
        }
    }

    fn lower(&mut self, insn: &Insn, next: u64) -> Lowered {
        let p = insn.pfx;
        let has_rex = p.has_rex;
        self.insn_flags = self.flags;
        if insn.esc {
            return self.lower_0f(insn, next);
        }
        match insn.opcode {
            0x00..=0x3D if insn.opcode & 7 < 6 => {
                let Some(op) = Alu::from_op(insn.opcode >> 3) else {
                    return Lowered::Unsupported;
                };
                let form = insn.opcode & 7;
                let size = if form % 2 == 0 && form != 5 { 1 } else { self.opsize(&p) };
                match form {
                    0 | 1 => {
                        self.settle_for_rm_dest(&insn.rm, op);
                        if let Rm::Mem(m) = insn.rm {
                            self.emit_addr(&m);
                        }
                        self.read_rm(&insn.rm, R_FA, size, has_rex);
                        self.load_gpr(R_FB, insn.reg, size, has_rex);
                        self.emit_alu(op, size);
                        self.finish_rm_dest(insn, op, size, has_rex, next)
                    }
                    2 | 3 => {
                        if let Rm::Mem(m) = insn.rm {
                            self.emit_addr(&m);
                        }
                        self.read_rm(&insn.rm, R_FB, size, has_rex);
                        self.load_gpr(R_FA, insn.reg, size, has_rex);
                        self.emit_alu(op, size);
                        if op.writes_back() {
                            self.store_gpr(R_FR, insn.reg, size, has_rex);
                        }
                        Lowered::Ok
                    }
                    _ => {
                        self.load_gpr(R_FA, 0, size, has_rex);
                        self.asm.mov_imm64(R_FB, insn.imm & mask_of(size));
                        self.emit_alu(op, size);
                        if op.writes_back() {
                            self.store_gpr(R_FR, 0, size, has_rex);
                        }
                        Lowered::Ok
                    }
                }
            }

            0x40..=0x4F if !self.mode.is64() => {
                let r = insn.opcode & 7;
                let size = self.opsize(&p);
                self.materialize();
                self.load_gpr(R_FA, r, size, has_rex);
                self.emit_incdec(size, insn.opcode < 0x48);
                self.store_gpr(R_FR, r, size, has_rex);
                Lowered::Ok
            }

            0x50..=0x57 => {
                let r = (insn.opcode & 7) | (p.b() << 3);
                let w = self.mode.stack_width();
                self.asm.ldr(8, R_VAL, R_STATE, gpr_off(r));
                self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_store_push(w, next, None);
                Lowered::Ok
            }
            0x58..=0x5F => {
                let r = (insn.opcode & 7) | (p.b() << 3);
                let w = self.mode.stack_width();
                self.asm.ldr(8, R_ADDR, R_STATE, gpr_off(4));
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_load(R_VAL, w);
                self.asm.add_imm(true, T0, R_ADDR, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, T0, T0, 0xffff_ffff);
                    debug_assert!(ok);
                    let ok = self.asm.and_imm(true, R_VAL, R_VAL, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.asm.str(8, T0, R_STATE, gpr_off(4));
                self.asm.str(8, R_VAL, R_STATE, gpr_off(r));
                Lowered::Ok
            }

            0x68 | 0x6A if !p.p66 => {
                let w = self.mode.stack_width();
                self.asm.mov_imm64(R_VAL, insn.imm);
                self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_store_push(w, next, None);
                Lowered::Ok
            }

            0x63 if self.mode.is64() => {
                let size = self.opsize(&p);
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_VAL, 4, has_rex);
                self.asm.sbfx(true, R_VAL, R_VAL, 0, 32);
                self.mask_to(R_VAL, size);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }

            0x69 | 0x6B => {
                let size = self.opsize(&p);
                self.materialize();
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.asm.mov_imm64(R_FB, insn.imm & mask_of(size));
                self.emit_imul(size);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }

            0x70..=0x7F => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                self.emit_jcc(insn.opcode & 0xF, target, next)
            }

            0x80 | 0x81 | 0x83 => {
                let size = if insn.opcode == 0x80 { 1 } else { self.opsize(&p) };
                let Some(op) = Alu::from_op(insn.reg & 7) else {
                    return Lowered::Unsupported;
                };
                self.settle_for_rm_dest(&insn.rm, op);
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.asm.mov_imm64(R_FB, insn.imm & mask_of(size));
                self.emit_alu(op, size);
                self.finish_rm_dest(insn, op, size, has_rex, next)
            }

            0x84 | 0x85 => {
                let size = if insn.opcode == 0x84 { 1 } else { self.opsize(&p) };
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.load_gpr(R_FB, insn.reg, size, has_rex);
                self.emit_alu(Alu::And, size);
                Lowered::Ok
            }

            0x88 | 0x89 => {
                let size = if insn.opcode == 0x88 { 1 } else { self.opsize(&p) };
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.load_gpr(R_VAL, insn.reg, size, has_rex);
                match insn.rm {
                    Rm::Reg(i) => {
                        self.store_gpr(R_VAL, i, size, has_rex);
                        Lowered::Ok
                    }
                    Rm::Mem(_) => {
                        self.emit_store(R_VAL, size, Commit::None, next);
                        Lowered::Ok
                    }
                }
            }
            0x8A | 0x8B => {
                let size = if insn.opcode == 0x8A { 1 } else { self.opsize(&p) };
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_VAL, size, has_rex);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }

            0x8D => {
                let Rm::Mem(m) = insn.rm else {
                    return Lowered::Unsupported;
                };
                let size = self.opsize(&p);
                self.emit_addr(&m);
                self.asm.mov_reg(true, R_VAL, R_ADDR);
                self.mask_to(R_VAL, size);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }

            0x90 if p.b() == 0 => Lowered::Ok,

            0xA0..=0xA3 => {
                if self.mode.is64() && p.seg == 0x64 {
                    return Lowered::Unsupported;
                }
                let size = if insn.opcode & 1 == 0 { 1 } else { self.opsize(&p) };
                self.asm.mov_imm64(R_ADDR, insn.imm);
                match p.seg {
                    0x65 => {
                        self.asm.ldr(8, T0, R_STATE, st::GS_BASE);
                        self.asm.add_reg(true, R_ADDR, R_ADDR, T0, 0);
                    }
                    0x64 => {
                        self.asm.ldr(8, T0, R_STATE, st::FS_BASE);
                        self.asm.add_reg(true, R_ADDR, R_ADDR, T0, 0);
                    }
                    _ => {}
                }
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                match insn.opcode {
                    0xA0 | 0xA1 => {
                        self.emit_load(R_VAL, size);
                        self.store_gpr(R_VAL, 0, size, has_rex);
                    }
                    _ => {
                        self.load_gpr(R_VAL, 0, size, has_rex);
                        self.emit_store(R_VAL, size, Commit::None, next);
                    }
                }
                Lowered::Ok
            }

            0xA8 | 0xA9 => {
                let size = if insn.opcode == 0xA8 { 1 } else { self.opsize(&p) };
                self.load_gpr(R_FA, 0, size, has_rex);
                self.asm.mov_imm64(R_FB, insn.imm & mask_of(size));
                self.emit_alu(Alu::And, size);
                Lowered::Ok
            }

            0xB0..=0xB7 => {
                let r = (insn.opcode & 7) | (p.b() << 3);
                self.asm.mov_imm64(R_VAL, insn.imm & 0xff);
                self.store_gpr(R_VAL, r, 1, has_rex);
                Lowered::Ok
            }
            0xB8..=0xBF => {
                let r = (insn.opcode & 7) | (p.b() << 3);
                let size = self.opsize(&p);
                self.asm.mov_imm64(R_VAL, insn.imm & mask_of(size));
                self.store_gpr(R_VAL, r, size, has_rex);
                Lowered::Ok
            }

            0xC0 | 0xC1 | 0xD0 | 0xD1 => {
                let size = if insn.opcode & 1 == 0 { 1 } else { self.opsize(&p) };
                let count = if insn.opcode < 0xD0 { insn.imm } else { 1 };
                self.emit_shift(insn, size, count, next, has_rex)
            }

            0xC6 | 0xC7 => {
                if insn.reg & 7 != 0 {
                    return Lowered::Unsupported;
                }
                let size = if insn.opcode == 0xC6 { 1 } else { self.opsize(&p) };
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.asm.mov_imm64(R_VAL, insn.imm & mask_of(size));
                match insn.rm {
                    Rm::Reg(i) => {
                        self.store_gpr(R_VAL, i, size, has_rex);
                        Lowered::Ok
                    }
                    Rm::Mem(_) => {
                        self.emit_store(R_VAL, size, Commit::None, next);
                        Lowered::Ok
                    }
                }
            }

            0xC2 | 0xC3 if !p.p66 => {
                self.materialize();
                let w = self.mode.stack_width();
                self.asm.ldr(8, R_ADDR, R_STATE, gpr_off(4));
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_load(R_FA, w);
                let released = w as u64 + if insn.opcode == 0xC2 { insn.imm } else { 0 };
                if released < 4096 {
                    self.asm.add_imm(true, T0, R_ADDR, released as u32, false);
                } else {
                    self.asm.mov_imm64(T0, released);
                    self.asm.add_reg(true, T0, R_ADDR, T0, 0);
                }
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, T0, T0, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.asm.str(8, T0, R_STATE, gpr_off(4));
                self.exit_indirect(Flags::Live, R_FA, self.insns + 1);
                Lowered::Terminated
            }

            0xC9 => {
                let w = self.mode.stack_width();
                self.asm.ldr(8, R_ADDR, R_STATE, gpr_off(5));
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_load(R_VAL, w);
                self.asm.add_imm(true, T0, R_ADDR, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, T0, T0, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.asm.str(8, T0, R_STATE, gpr_off(4));
                self.asm.str(8, R_VAL, R_STATE, gpr_off(5));
                Lowered::Ok
            }

            0xE8 if !p.p66 => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                let w = self.mode.stack_width();
                self.asm.mov_imm64(R_VAL, next);
                self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_store_push(w, target, None);
                let f = self.flags;
                self.exit_to(f, target, self.insns + 1, ExitKind::Link);
                Lowered::Terminated
            }

            0xE9 | 0xEB => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                let f = self.flags;
                self.exit_to(f, target, self.insns + 1, ExitKind::Link);
                Lowered::Terminated
            }

            0xF6 | 0xF7 => {
                let size = if insn.opcode == 0xF6 { 1 } else { self.opsize(&p) };
                match insn.reg & 7 {
                    2 => {
                        if let Rm::Mem(m) = insn.rm {
                            self.emit_addr(&m);
                        }
                        self.read_rm(&insn.rm, R_VAL, size, has_rex);
                        self.asm.mvn(true, R_VAL, R_VAL);
                        self.mask_to(R_VAL, size);
                        match insn.rm {
                            Rm::Reg(i) => {
                                self.store_gpr(R_VAL, i, size, has_rex);
                                Lowered::Ok
                            }
                            Rm::Mem(_) => {
                                self.emit_store(R_VAL, size, Commit::None, next);
                                Lowered::Ok
                            }
                        }
                    }
                    3 => {
                        self.settle_for_rm_dest(&insn.rm, Alu::Sub);
                        if let Rm::Mem(m) = insn.rm {
                            self.emit_addr(&m);
                        }
                        self.read_rm(&insn.rm, R_FB, size, has_rex);
                        self.asm.mov_imm64(R_FA, 0);
                        self.emit_alu(Alu::Sub, size);
                        self.finish_rm_dest(insn, Alu::Sub, size, has_rex, next)
                    }
                    _ => Lowered::Unsupported,
                }
            }

            0xFF if matches!(insn.reg & 7, 2 | 4) && !p.p66 => {
                self.materialize();
                let size = if self.mode.is64() { 8 } else { 4 };
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                    self.emit_load(R_FA, size);
                } else if let Rm::Reg(i) = insn.rm {
                    self.load_gpr(R_FA, i, size, has_rex);
                }
                if insn.reg & 7 == 2 {
                    let w = self.mode.stack_width();
                    self.asm.mov_imm64(R_VAL, next);
                    self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                    self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                    if !self.mode.is64() {
                        let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                        debug_assert!(ok);
                    }
                    self.emit_store_push(w, next, Some(R_FA));
                }
                self.exit_indirect(Flags::Live, R_FA, self.insns + 1);
                Lowered::Terminated
            }

            0xFE | 0xFF => {
                let sub = insn.reg & 7;
                if sub > 1 {
                    return Lowered::Unsupported;
                }
                let size = if insn.opcode == 0xFE { 1 } else { self.opsize(&p) };
                self.materialize();
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.emit_incdec(size, sub == 0);
                match insn.rm {
                    Rm::Reg(i) => {
                        self.store_gpr(R_FR, i, size, has_rex);
                        Lowered::Ok
                    }
                    Rm::Mem(_) => {
                        self.emit_store(R_FR, size, Commit::None, next);
                        Lowered::Ok
                    }
                }
            }

            _ => Lowered::Unsupported,
        }
    }

    fn lower_0f(&mut self, insn: &Insn, next: u64) -> Lowered {
        let p = insn.pfx;
        let has_rex = p.has_rex;
        match insn.opcode {
            0x1F => Lowered::Ok,
            0x40..=0x4F => {
                let size = self.opsize(&p);
                self.materialize();
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.load_gpr(R_VAL, insn.reg, size, has_rex);
                self.emit_cond_value(insn.opcode & 0xF, T0);
                self.asm.subs_imm(true, ZR, T0, 0, false);
                self.asm.csel(true, R_VAL, R_FA, R_VAL, Cond::Ne);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }
            0x80..=0x8F => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                self.emit_jcc(insn.opcode & 0xF, target, next)
            }
            0xAF => {
                let size = self.opsize(&p);
                self.materialize();
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_FB, size, has_rex);
                self.load_gpr(R_FA, insn.reg, size, has_rex);
                self.emit_imul(size);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }
            0xB6 | 0xB7 | 0xBE | 0xBF => {
                let src = if insn.opcode & 1 == 0 { 1u8 } else { 2 };
                let size = self.opsize(&p);
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                self.read_rm(&insn.rm, R_VAL, src, has_rex);
                if insn.opcode >= 0xBE {
                    self.asm.sbfx(true, R_VAL, R_VAL, 0, src as u32 * 8);
                    self.mask_to(R_VAL, size);
                }
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }
            _ => Lowered::Unsupported,
        }
    }

    fn mask_to(&mut self, r: u32, size: u8) {
        if size == 8 {
            return;
        }
        let ok = self.asm.and_imm(true, r, r, mask_of(size));
        debug_assert!(ok);
    }

    fn settle_for_rm_dest(&mut self, rm: &Rm, op: Alu) {
        if matches!(rm, Rm::Mem(_)) && op.writes_back() {
            self.materialize();
        }
    }

    fn finish_rm_dest(
        &mut self,
        insn: &Insn,
        op: Alu,
        size: u8,
        has_rex: bool,
        next: u64,
    ) -> Lowered {
        match insn.rm {
            Rm::Reg(i) => {
                if op.writes_back() {
                    self.store_gpr(R_FR, i, size, has_rex);
                }
                Lowered::Ok
            }
            Rm::Mem(_) => {
                if op.writes_back() {
                    self.emit_store(R_FR, size, Commit::None, next);
                }
                Lowered::Ok
            }
        }
    }

    fn emit_incdec(&mut self, size: u8, is_inc: bool) {
        self.asm.mov_imm64(R_FB, 1);
        if self.defer {
            self.emit_arith_value(size, !is_inc);
            self.flags = Flags::Arith { size, sub: !is_inc, keep_cf: true };
        } else {
            self.emit_arith_eager(size, !is_inc, true);
        }
    }

    fn emit_imul(&mut self, size: u8) {
        let bits = size as u32 * 8;
        if size == 8 {
            self.asm.mul(true, R_VAL, R_FA, R_FB);
            self.asm.smulh(T1, R_FA, R_FB);
            self.asm.cmp_reg_asr(true, T1, R_VAL, 63);
            self.asm.cset(true, T3, Cond::Ne);
        } else {
            self.asm.sbfx(true, T0, R_FA, 0, bits);
            self.asm.sbfx(true, T1, R_FB, 0, bits);
            self.asm.mul(true, T2, T0, T1);
            self.asm.mov_reg(true, R_VAL, T2);
            self.mask_to(R_VAL, size);
            self.asm.sbfx(true, T0, R_VAL, 0, bits);
            self.asm.subs_reg(true, ZR, T0, T2, 0);
            self.asm.cset(true, T3, Cond::Ne);
        }
        self.asm.mov_imm64(T0, (1 << F_CF) | (1 << F_OF));
        self.asm.bic_reg(true, R_FLAGS, R_FLAGS, T0, 0);
        self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_CF);
        self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_OF);
    }

    fn emit_shift(&mut self, insn: &Insn, size: u8, count: u64, next: u64, has_rex: bool) -> Lowered {
        let kind = insn.reg & 7;
        let (is_shl, is_sar) = match kind {
            4 | 6 => (true, false),
            5 => (false, false),
            7 => (false, true),
            _ => return Lowered::Unsupported,
        };
        let bits = size as u32 * 8;
        let count = (count & if size == 8 { 0x3f } else { 0x1f }) as u32;
        if count == 0 {
            if let Rm::Mem(m) = insn.rm {
                self.emit_addr(&m);
            }
            self.read_rm(&insn.rm, R_VAL, size, has_rex);
            return match insn.rm {
                Rm::Reg(i) => {
                    self.store_gpr(R_VAL, i, size, has_rex);
                    Lowered::Ok
                }
                Rm::Mem(_) => {
                    self.emit_store(R_VAL, size, Commit::None, next);
                    Lowered::Ok
                }
            };
        }
        self.materialize();
        if let Rm::Mem(m) = insn.rm {
            self.emit_addr(&m);
        }
        self.read_rm(&insn.rm, R_FB, size, has_rex);
        if is_shl {
            if count <= bits {
                self.asm.ubfx(true, T3, R_FB, bits - count, 1);
            } else {
                self.asm.mov_imm64(T3, 0);
            }
            self.asm.lsl_imm(true, R_VAL, R_FB, count.min(63));
            self.mask_to(R_VAL, size);
        } else if is_sar {
            self.asm.sbfx(true, T0, R_FB, 0, bits);
            self.asm.ubfx(true, T3, T0, count - 1, 1);
            self.asm.asr_imm(true, R_VAL, T0, count.min(63));
            self.mask_to(R_VAL, size);
        } else {
            self.asm.ubfx(true, T3, R_FB, count - 1, 1);
            self.asm.lsr_imm(true, R_VAL, R_FB, count.min(63));
        }
        let clear = (1u64 << F_CF) | (1 << F_SF) | (1 << F_ZF) | (1 << F_PF) | if count == 1 { 1 << F_OF } else { 0 };
        self.asm.mov_imm64(T0, clear);
        self.asm.bic_reg(true, R_FA, R_FLAGS, T0, 0);
        self.asm.orr_reg(true, R_FA, R_FA, T3, F_CF);
        if count == 1 {
            if is_shl {
                self.asm.ubfx(true, T0, R_VAL, bits - 1, 1);
                self.asm.eor_reg(true, T0, T0, T3, 0);
                self.asm.orr_reg(true, R_FA, R_FA, T0, F_OF);
            } else if !is_sar {
                self.asm.ubfx(true, T0, R_FB, bits - 1, 1);
                self.asm.orr_reg(true, R_FA, R_FA, T0, F_OF);
            }
        }
        self.flags_szp_into(R_FA, R_VAL, size);
        match insn.rm {
            Rm::Reg(i) => {
                self.asm.mov_reg(true, R_FLAGS, R_FA);
                self.store_gpr(R_VAL, i, size, has_rex);
                Lowered::Ok
            }
            Rm::Mem(_) => {
                self.emit_store(R_VAL, size, Commit::Flags, next);
                Lowered::Ok
            }
        }
    }

    fn emit_store_push(&mut self, w: u8, next: u64, next_reg: Option<u32>) {
        let miss = self.emit_tlb_probe(tlb_off::WRITE, w);
        self.asm.str_reg(w, R_VAL, T3, R_ADDR);
        self.asm.mov_reg(true, R_VAL, R_ADDR);
        let done = self.asm.b_forward();
        self.asm.bind(miss);
        self.asm.mov_reg(true, 0, R_CTX);
        self.asm.mov_reg(true, 1, R_ADDR);
        self.asm.mov_imm64(2, w as u64);
        self.asm.mov_reg(true, 3, R_VAL);
        self.asm.mov_reg(true, R_VAL, R_ADDR);
        self.asm.ldr(8, T0, R_CTX, ctx_off::WRITE);
        self.asm.blr(T0);
        let l = self.asm.cbnz_forward(true, 0);
        self.store_stubs.push(StoreStub {
            label: l,
            retired: self.insns,
            rip: self.rip,
            next_rip: next,
            next_reg,
            commit: Commit::Gpr { idx: 4, size: 8, has_rex: true },
            before: self.insn_flags,
            after: self.flags,
            spilled: self.spilled,
        });
        self.asm.bind(done);
        self.store_gpr(R_VAL, 4, 8, true);
    }

    fn emit_jcc(&mut self, cc: u8, target: u64, fallthrough: u64) -> Lowered {
        self.materialize();
        let taken = self.branch_if_cond(cc);
        self.exit_to(Flags::Live, fallthrough, self.insns + 1, ExitKind::Link);
        self.asm.bind(taken);
        self.exit_to(Flags::Live, target, self.insns + 1, ExitKind::Link);
        Lowered::Terminated
    }
}
