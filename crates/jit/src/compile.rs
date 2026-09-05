//! The basic-block compiler: guest x86/x86-64 → ARM64 (roadmap W8.3).
//!
//! # What is compiled, and what is not
//!
//! The set below was chosen by *measuring* (`exemu run --opcode-profile`), not
//! by guessing: on the 7-Zip reference run (496M instructions, Wine's DLLs
//! included) these shapes are ~99% of the stream. Everything else — every rare
//! opcode, every SSE/x87/VEX instruction, `syscall`, `call`/`ret`, the string
//! ops, `adc`/`sbb`, rotates, the `LOCK`/`REP` prefixes — **ends the block**, and
//! the interpreter executes that instruction. Deferring is always safe;
//! compiling something whose flag semantics are not proven is not.
//!
//! Compiled today:
//!
//! | Shape | Notes |
//! | ----- | ----- |
//! | `add`/`or`/`and`/`sub`/`xor`/`cmp`, all six operand forms | sizes 1/2/4/8; `adc`/`sbb` deliberately excluded (the carry-in makes the sub-64-bit flag lowering a different problem) |
//! | group 1 (`80`/`81`/`83`) | same six operations |
//! | `test` (`84`/`85`/`a8`/`a9`) | |
//! | `mov` (`88`/`89`/`8a`/`8b`/`b0`–`bf`/`c6`/`c7`) | |
//! | `lea`, `movzx`, `movsx`, `movsxd` | |
//! | `imul` (`0f af`, `69`, `6b`) | CF/OF only, exactly like the interpreter |
//! | `shl`/`shr`/`sar` with a **constant** count (`c0`/`c1`/`d0`/`d1`) | `d2`/`d3` (CL count) and the rotates side-exit |
//! | `inc`/`dec`, `neg`, `not` | |
//! | `cmov<cc>` | including the "write the destination even when not taken" rule |
//! | `push r`/`pop r` | |
//! | `j<cc>`/`jmp` rel8/rel32 | **block terminators**: the branch is compiled and `rip` is left correct, so the hot loop never returns to the interpreter |
//! | `nop` | |
//!
//! # The two rules that make faults exact
//!
//! 1. **Nothing is committed before a faulting access.** Results live in scratch
//!    registers; the guest register file and the live `rflags` are updated only
//!    after every access of that instruction has succeeded.
//! 2. **A fault rewinds.** `rip` is set back to the start of the faulting
//!    instruction and the block returns with the fault bit set. The caller
//!    re-executes that one instruction on the interpreter, which raises the real
//!    error — including whatever partial state the interpreter itself would
//!    leave behind. The JIT never constructs an `EmuError`.
//!
//! Self-modifying code is handled by the same mechanism from the other side: the
//! store helper reports (via [`crate::rt::status::WROTE_CODE`]) when a store
//! landed in executable memory, and the block commits that instruction and stops
//! rather than running instructions that may have just been rewritten.

use crate::a64::{Asm, Cond, Label, ZR};
use crate::rt::{ctx_off, status};
use exemu_core::cpu::CpuState;
use exemu_core::Memory;

/// Guest CPU mode. Mirrors `exemu_cpu::Bits` without depending on it (the JIT
/// stays a sibling of the interpreter, both pointing inward at `exemu-core`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// 32-bit protected mode.
    Protected,
    /// 64-bit long mode.
    Long,
}

impl Mode {
    #[inline]
    fn is64(self) -> bool {
        self == Mode::Long
    }
    /// Address mask: 32-bit mode truncates every effective address.
    #[inline]
    fn addr_mask(self) -> u64 {
        match self {
            Mode::Long => u64::MAX,
            Mode::Protected => 0xFFFF_FFFF,
        }
    }
    /// Stack slot width in bytes.
    #[inline]
    fn stack_width(self) -> u8 {
        match self {
            Mode::Long => 8,
            Mode::Protected => 4,
        }
    }
}

// --- ARM64 register roles inside a block ------------------------------------

const R_STATE: u32 = 19; // *mut CpuState
const R_CTX: u32 = 20; // *mut BlockCtx
const R_FLAGS: u32 = 21; // rflags — as of *before* any pending flag operation
const R_PARITY: u32 = 22; // parity table base
const R_FA: u32 = 23; // pending flag operand a (survives helper calls)
const R_FB: u32 = 24; // pending flag operand b (survives helper calls)
const R_FR: u32 = 25; // pending flag result — also the ALU result
const R_VAL: u32 = 26; // value to store / commit (survives helper calls)
const R_ADDR: u32 = 27; // effective address (survives helper calls)
const R_MASK: u32 = 28; // 0x8D5 = CF|PF|AF|ZF|SF|OF

/// Scratch registers, dead across any helper call.
const T0: u32 = 9;
const T1: u32 = 10;
const T2: u32 = 11;
const T3: u32 = 12;

/// x86 flag bit positions.
const F_CF: u32 = 0;
const F_PF: u32 = 2;
const F_AF: u32 = 4;
const F_ZF: u32 = 6;
const F_SF: u32 = 7;
const F_OF: u32 = 11;
/// The six status flags a normal arithmetic instruction defines.
const ARITH_MASK: u64 = (1 << F_CF) | (1 << F_PF) | (1 << F_AF) | (1 << F_ZF) | (1 << F_SF) | (1 << F_OF);

/// Byte offsets into [`CpuState`], taken from the real layout rather than
/// assumed: `offset_of!` is evaluated by the compiler against the same type
/// definition the interpreter uses.
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

/// Why the block stopped growing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// An instruction the compiler does not implement. The interpreter runs it,
    /// then the next block starts after it. `esc` distinguishes the `0F` map, so
    /// `0F B1` (cmpxchg) is not reported as `B1` (mov r8, imm8).
    Unsupported { rip: u64, opcode: u8, esc: bool },
    /// The instruction bytes could not be fetched — the interpreter will raise
    /// the fetch fault.
    FetchFailed { rip: u64 },
    /// The block hit the instruction cap.
    Full,
    /// The block ended on a compiled branch; `rip` is left correct by the code.
    Terminator,
    /// The last instruction ended on the top of the address space, so the next
    /// one is at a *lower* address than the block's first. A block is a
    /// contiguous byte range — that is what the store helper's two-compare
    /// self-modification check and the engine's two-page generation check are
    /// built on — so the block stops here rather than becoming two ranges.
    Wrapped,
}

/// A compiled block, before it is written into the code buffer.
pub struct BlockPlan {
    /// Guest address of the first instruction.
    pub start: u64,
    /// Number of guest instructions compiled.
    pub insns: u32,
    /// Guest address just past the last compiled instruction.
    pub end_rip: u64,
    /// Total guest instruction bytes covered.
    pub bytes: u64,
    /// The ARM64 words.
    pub code: Vec<u32>,
    pub stop: StopReason,
}

/// Maximum guest instructions in one block.
pub const MAX_INSNS: u32 = 64;

// --- decode -----------------------------------------------------------------

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

/// A decoded memory operand. `abs` is `Some` when the address is a compile-time
/// constant (RIP-relative, or a bare `disp32` in 32-bit mode).
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
    /// Length in bytes.
    len: u8,
}

/// A tiny byte cursor over the prefetched instruction window.
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

/// The x86 operations of the regular ALU family, by opcode `>> 3`.
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
            // 2 = adc, 3 = sbb: the carry-in makes the <64-bit flag lowering a
            // separate problem, so they are not compiled (yet).
            _ => None,
        }
    }
    fn writes_back(self) -> bool {
        self != Alu::Cmp
    }
}

/// What has to be written to guest state once every access of an instruction has
/// succeeded. Emitted twice (hot path and the "store hit code" stub), so it is
/// kept to one or two instructions.
#[derive(Clone, Copy)]
enum Commit {
    None,
    /// `rflags = R_FA` — the eagerly-computed flags of a shift, which have to
    /// survive the store call before they may be committed.
    Flags,
    Gpr { idx: u8, size: u8, has_rex: bool },
}

/// The flag state at a point in the emitted code (roadmap W8.4).
///
/// Computing x86's six status flags eagerly costs ~16 ARM64 instructions per ALU
/// operation, and the overwhelming majority of those results are dead: pointer
/// arithmetic, index updates and the `add`/`sub` inside an addressing sequence
/// have their flags overwritten by the *next* flag-writing instruction without
/// anything ever reading them. So an ALU instruction emits only its **result**
/// and records here how its flags could be derived; the derivation is emitted at
/// the first point that can observe them, and never at all when a later
/// instruction supersedes it first.
///
/// The invariant that makes this exact: while a state other than [`Flags::Live`]
/// is outstanding, `R_FLAGS` holds the architectural `rflags` from *before* that
/// operation, and `R_FA`/`R_FB`/`R_FR` hold its masked operands and result. So
/// materialising is always `R_FLAGS = (R_FLAGS & !defined) | computed` — which
/// is also why the flags an operation leaves *undefined* (INC/DEC's CF) come out
/// right for free.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flags {
    /// `R_FLAGS` is the architectural `rflags`; nothing is pending.
    Live,
    /// An ADD/SUB-shaped result is pending. `keep_cf` marks INC/DEC, which
    /// define every status flag except CF.
    Arith { size: u8, sub: bool, keep_cf: bool },
    /// AND/OR/XOR/TEST: CF, OF and AF are cleared, SF/ZF/PF come from `R_FR`.
    Logic { size: u8 },
}

/// A deferred fault exit (rewind to the start of instruction `retired`).
struct FaultStub {
    label: Label,
    retired: u32,
    rip: u64,
    /// The flag state as of the *start* of the faulting instruction — what the
    /// rewound state must show.
    flags: Flags,
}

/// A deferred "the store completed but landed in code" exit.
struct StoreStub {
    label: Label,
    retired: u32,
    rip: u64,
    next_rip: u64,
    commit: Commit,
    /// Flag state as of the start of this instruction (the rewind path) …
    before: Flags,
    /// … and as of after it (the "committed, now stop" path).
    after: Flags,
}

/// The block being built.
pub struct Compiler {
    asm: Asm,
    mode: Mode,
    /// Instructions compiled so far.
    insns: u32,
    /// Guest address of the instruction being compiled.
    rip: u64,
    /// Flag state right here in the emitted stream.
    flags: Flags,
    /// Flag state as of the start of the instruction being lowered. A faulting
    /// access rewinds to exactly that point, so its stub must restore this one
    /// rather than whatever the instruction has computed so far.
    insn_flags: Flags,
    /// Whether the instruction being lowered should leave its flags pending.
    /// Purely a cost decision — either answer is correct.
    defer: bool,
    fault_stubs: Vec<FaultStub>,
    store_stubs: Vec<StoreStub>,
    /// Branches to the shared epilogue.
    exits: Vec<Label>,
}

/// Bit set in the block's return value when it exited by rewinding to a
/// faulting instruction.
pub const RET_FAULT: u64 = 1 << 32;

impl Compiler {
    /// Compile a straight-line block starting at `start`. A plan with
    /// `insns == 0` means nothing here could be compiled and the caller must
    /// interpret.
    pub fn compile(mem: &dyn Memory, mode: Mode, start: u64, max_insns: u32) -> BlockPlan {
        let mut c = Compiler {
            asm: Asm::new(),
            mode,
            insns: 0,
            rip: start,
            flags: Flags::Live,
            insn_flags: Flags::Live,
            defer: false,
            fault_stubs: Vec::new(),
            store_stubs: Vec::new(),
            exits: Vec::new(),
        };
        c.prologue();
        let mut stop = StopReason::Full;
        let mut rip = start;
        while c.insns < max_insns {
            c.rip = rip;
            let mut window = [0u8; 16];
            // How many bytes of `window` are really guest memory. The rest are
            // zeros this function put there, and **decoding them would fabricate
            // an instruction**: at the tail of an executable region the
            // interpreter faults fetching the byte after the last mapped one,
            // so a compiler that read its own padding would run something the
            // reference CPU never reaches. `decode` is therefore handed only the
            // prefix that was fetched, and refuses anything longer.
            let mut valid = window.len();
            if mem.fetch(rip, &mut window).is_err() {
                // Short window near a region's tail: fetch what we can, byte by
                // byte, so an instruction that fits still compiles.
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
            // Deferring this instruction's flags only pays when a later one
            // overwrites them first (roadmap W8.4); either answer is correct.
            c.defer = flag_effect(&insn) != FlagEffect::Neutral
                && defer_pays(mem, mode, next, DEFER_SCAN);
            match c.lower(&insn, next) {
                Lowered::Ok => {
                    c.insns += 1;
                    rip = next;
                    // Addresses only ever rise from `start`, so `next < start`
                    // can only mean this instruction ended on the top of the
                    // address space and the next one is back at the bottom.
                    // Carrying on would make the block two disjoint byte
                    // ranges, and everything downstream — the store helper's
                    // `code_lo..code_hi` self-modification test, the engine's
                    // two-page generation check — assumes exactly one.
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
        // Fallthrough exit: rip = end of the block, no fault.
        if stop != StopReason::Terminator {
            c.exit_to(c.flags, end_rip, insns as u64);
        }
        c.emit_stubs();
        c.epilogue();
        BlockPlan {
            start,
            insns,
            end_rip,
            // Masked, because `end_rip` is: a 32-bit block that ends on the
            // 4 GiB boundary has `end_rip == 0`, and a plain 64-bit subtraction
            // would call that a 2^64-sized block instead of the handful of
            // bytes it is.
            bytes: end_rip.wrapping_sub(start) & mode.addr_mask(),
            code: c.asm.into_words(),
            stop,
        }
    }

    // ---- frame -----------------------------------------------------------

    fn prologue(&mut self) {
        let a = &mut self.asm;
        a.stp_pre(19, 20, crate::a64::SP, -96);
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
        // Every exit branches here with x0 already holding the return value.
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
        a.ldp_post(19, 20, crate::a64::SP, 96);
        a.ret();
    }

    /// Leave the block: settle `flags`, store `rip`, set the return value, jump
    /// to the epilogue. The flag state is passed in rather than taken from
    /// `self` because a stub exits with the state of the point it rewinds to,
    /// not the state of the emission cursor.
    fn exit_to(&mut self, flags: Flags, rip: u64, ret: u64) {
        self.emit_flags(flags);
        self.asm.mov_imm64(T0, rip);
        self.asm.str(8, T0, R_STATE, st::RIP);
        self.asm.mov_imm64(0, ret);
        let l = self.asm.b_forward();
        self.exits.push(l);
    }

    fn emit_stubs(&mut self) {
        let stores = std::mem::take(&mut self.store_stubs);
        for s in stores {
            self.asm.bind(s.label);
            // status 1 = fault (rewind), status 2 = store completed into code.
            self.asm.subs_imm(true, ZR, 0, status::FAULT as u32, false);
            let is_fault = self.asm.b_cond_forward(Cond::Eq);
            self.emit_commit(s.commit);
            self.exit_to(s.after, s.next_rip, (s.retired + 1) as u64);
            self.asm.bind(is_fault);
            self.exit_to(s.before, s.rip, s.retired as u64 | RET_FAULT);
        }
        let faults = std::mem::take(&mut self.fault_stubs);
        for f in faults {
            self.asm.bind(f.label);
            self.exit_to(f.flags, f.rip, f.retired as u64 | RET_FAULT);
        }
    }

    // ---- guest register access -------------------------------------------

    /// Is this a legacy high-byte register access (AH/CH/DH/BH)?
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

    /// Store `src` (already masked to `size`) into guest register `idx`,
    /// reproducing `CpuState::gpr_write`: a 4-byte write zero-extends, 1- and
    /// 2-byte writes preserve the upper bits.
    fn store_gpr(&mut self, src: u32, idx: u8, size: u8, has_rex: bool) {
        if Self::high8(size, has_rex, idx) {
            self.asm.str(1, src, R_STATE, gpr_off(idx & 3) + 1);
        } else if size == 4 {
            // The value is masked, so a full 8-byte store *is* the zero-extend.
            self.asm.str(8, src, R_STATE, gpr_off(idx));
        } else {
            self.asm.str(size, src, R_STATE, gpr_off(idx));
        }
    }

    // ---- memory operands --------------------------------------------------

    /// Emit the effective-address computation for `m` into [`R_ADDR`].
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
        // Segment base (fs:/gs:). The 64-bit `fs` base is a fixed constant the
        // interpreter keeps outside CpuState, so that form is not compiled.
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

    /// Emit a guest load of `size` bytes from [`R_ADDR`] into `dst`.
    /// Clobbers x0..x8; `dst` must be a callee-saved role register.
    fn emit_load(&mut self, dst: u32, size: u8) {
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
        // The fault branch is taken *before* this write, so `dst` may be one of
        // the pending flag registers without disturbing the rewind path.
        self.asm.mov_reg(true, dst, 0);
    }

    /// Emit a guest store of `size` bytes from `src` to [`R_ADDR`], then the
    /// instruction's commit. Clobbers x0..x8.
    fn emit_store(&mut self, src: u32, size: u8, commit: Commit, next_rip: u64) {
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
            commit,
            before: self.insn_flags,
            after: self.flags,
        });
        self.emit_commit(commit);
    }

    fn emit_commit(&mut self, c: Commit) {
        match c {
            Commit::None => {}
            Commit::Flags => self.asm.mov_reg(true, R_FLAGS, R_FA),
            Commit::Gpr { idx, size, has_rex } => self.store_gpr(R_VAL, idx, size, has_rex),
        }
    }

    /// Read the r/m operand into `dst` (memory operands go through the helper;
    /// the address is left in [`R_ADDR`] for a later store).
    fn read_rm(&mut self, rm: &Rm, dst: u32, size: u8, has_rex: bool) {
        match rm {
            Rm::Reg(i) => self.load_gpr(dst, *i, size, has_rex),
            Rm::Mem(_) => self.emit_load(dst, size),
        }
    }

    // ---- flags ------------------------------------------------------------

    /// SF/ZF/PF from the masked result in `res`, ORed into `dst`.
    fn flags_szp_into(&mut self, dst: u32, res: u32, size: u8) {
        let bits = size as u32 * 8;
        self.asm.subs_imm(true, ZR, res, 0, false); // cmp res, #0
        self.asm.cset(true, T3, Cond::Eq);
        self.asm.orr_reg(true, dst, dst, T3, F_ZF);
        self.asm.ubfx(true, T3, res, bits - 1, 1);
        self.asm.orr_reg(true, dst, dst, T3, F_SF);
        let ok = self.asm.and_imm(true, T3, res, 0xff);
        debug_assert!(ok);
        self.asm.ldrb_reg(T3, R_PARITY, T3);
        self.asm.orr_reg(true, dst, dst, T3, F_PF);
    }

    /// Fold `flags` into [`R_FLAGS`], leaving it architecturally correct.
    /// Emits nothing for [`Flags::Live`] — which is the whole point: most
    /// pending states are superseded before any of this is ever reached.
    fn emit_flags(&mut self, flags: Flags) {
        match flags {
            Flags::Live => {}
            Flags::Logic { size } => {
                // CF, OF and AF are all cleared by a logic operation.
                self.asm.bic_reg(true, R_FLAGS, R_FLAGS, R_MASK, 0);
                self.flags_szp_into(R_FLAGS, R_FR, size);
            }
            Flags::Arith { size, sub, keep_cf } => {
                // Re-derive NZCV with one compare of the saved operands: then
                // ARM's C and V *are* x86's CF and OF for this width. Widths
                // below 32 bits are shifted up so the sign bit lands in bit 63.
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
                // NZCV is live from here to the last `cset`; `mov`, `bic`,
                // `orr`, `eor` and `ubfx` do not disturb it.
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
                // AF = (a ^ b ^ result) bit 4, from the masked operands.
                self.asm.eor_reg(true, T3, R_FA, R_FB, 0);
                self.asm.eor_reg(true, T3, T3, R_FR, 0);
                self.asm.ubfx(true, T3, T3, 4, 1);
                self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_AF);
                self.flags_szp_into(R_FLAGS, R_FR, size);
            }
        }
    }

    /// Settle whatever is pending, so `R_FLAGS` may be read (or the pending
    /// registers reused).
    ///
    /// Only ever called **before** the current instruction's memory accesses —
    /// which is what lets it also declare the instruction-start state settled,
    /// and therefore what lets that instruction's fault stubs emit nothing.
    fn materialize(&mut self) {
        if self.flags != Flags::Live {
            self.emit_flags(self.flags);
            self.flags = Flags::Live;
        }
        self.insn_flags = Flags::Live;
    }

    /// `R_FR = R_FA ∓ R_FB`, masked to `size`. Flags are only *recorded*.
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

    /// One of the six compiled ALU operations, `R_FA` op `R_FB` → `R_FR`.
    ///
    /// Deferring is only *free* when a later instruction in this block
    /// overwrites the flags first — settling later costs one instruction more
    /// than computing now, because the operation has to be repeated to get
    /// NZCV back. `self.defer` carries that decision, taken by scanning
    /// forward from the next instruction ([`defer_pays`]).
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

    /// `R_FR = R_FA ∓ R_FB` **and** the flags it defines, straight into
    /// `R_FLAGS` — NZCV comes from the operation itself rather than from a
    /// repeat of it, which is what makes this one instruction cheaper than
    /// deferring plus settling. `keep_cf` is INC/DEC.
    fn emit_arith_eager(&mut self, size: u8, sub: bool, keep_cf: bool) {
        // Sub-64-bit widths are handled by shifting both operands up so the
        // sign bit lands in bit 63: then ARM's N/Z/C/V are exactly x86's
        // SF/ZF/CF/OF for that width, with no extra masking.
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
        // NZCV is live here; `mov`, `bic`, `orr`, `eor` and `ubfx` leave it be.
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
        // AF = (a ^ b ^ result) bit 4, from the *unshifted* masked operands.
        self.asm.eor_reg(true, T3, R_FA, R_FB, 0);
        self.asm.eor_reg(true, T3, T3, R_FR, 0);
        self.asm.ubfx(true, T3, T3, 4, 1);
        self.asm.orr_reg(true, R_FLAGS, R_FLAGS, T3, F_AF);
        self.flags_szp_into(R_FLAGS, R_FR, size);
        self.flags = Flags::Live;
    }

    /// `R_FR = R_FA op R_FB` for AND/OR/XOR. The operands are already masked,
    /// so a 64-bit operation leaves a result that is masked too.
    fn emit_logic_value(&mut self, op: Alu) {
        match op {
            Alu::And => self.asm.and_reg(true, R_FR, R_FA, R_FB, 0),
            Alu::Or => self.asm.orr_reg(true, R_FR, R_FA, R_FB, 0),
            _ => self.asm.eor_reg(true, R_FR, R_FA, R_FB, 0),
        }
    }

    /// Branch when the x86 condition `cc` holds.
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
                // Two-flag conditions: build the boolean, then branch on it.
                self.emit_cond_value(other, T0);
                self.asm.cbnz_forward(true, T0)
            }
        }
    }

    /// Materialise the x86 condition `cc` as 0/1 in `dst`.
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
            // BE = CF | ZF
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
            // L = SF != OF ; GE = SF == OF
            0xC | 0xD => {
                self.asm.ubfx(true, dst, R_FLAGS, F_SF, 1);
                self.asm.ubfx(true, T3, R_FLAGS, F_OF, 1);
                self.asm.eor_reg(true, dst, dst, T3, 0);
                if cc & 0xf == 0xD {
                    self.flip(dst);
                }
            }
            // LE = ZF | (SF != OF) ; G = !ZF & (SF == OF)
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

// --- decoding ---------------------------------------------------------------

/// Decode one instruction from `window`. `None` means "this compiler does not
/// handle it" — which includes prefixes it refuses (LOCK, REP, address-size
/// override) and any instruction whose encoding runs past the window.
fn decode(window: &[u8], mode: Mode, rip: u64) -> Option<Insn> {
    let mut c = Cursor { buf: window, pos: 0 };
    let mut pfx = Pfx::default();
    let opcode = loop {
        let b = c.u8()?;
        match b {
            0x66 => pfx.p66 = true,
            0x2E | 0x36 | 0x3E | 0x26 => {}
            0x64 | 0x65 => pfx.seg = b,
            // Refused: LOCK, REP/REPNE (and the SSE mandatory prefixes), and the
            // address-size override.
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

    // Which instructions take a ModRM byte.
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
    // In 64-bit mode the interpreter resolves `fs:` against a fixed constant
    // that does not live in `CpuState` (Windows guests use `gs:` for the TEB and
    // never touch the 64-bit `fs` base), so compiled code has nothing correct to
    // read. Refuse rather than reach for the 32-bit TEB base sitting in
    // `CpuState::fs_base`, which is what a naive lowering would do.
    if mode.is64() {
        if let Rm::Mem(m) = rm {
            if m.seg == 0x64 {
                return None;
            }
        }
    }

    // Immediates, read *after* the ModRM/SIB/disp so RIP-relative resolves past
    // the whole instruction (the same ordering rule the interpreter follows).
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
            // MOV AL/eAX <-> moffs: the offset is an *address*-size immediate,
            // not an operand-size one (and the address-size override is refused
            // above, so the mode alone decides its width).
            0xA0..=0xA3 => imm = if mode.is64() { c.u64()? } else { c.u32()? as u64 },
            0x70..=0x7F | 0xEB => imm = c.u8()? as i8 as i64 as u64,
            0xE9 => imm = c.u32()? as i32 as i64 as u64,
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
    // Resolve RIP-relative now that the length is known.
    if let Some(disp) = rip_rel_disp {
        // RIP-relative *with* a segment override is rare enough that refusing it
        // is cheaper than getting it subtly wrong.
        if pfx.seg != 0 {
            return None;
        }
        let next = rip.wrapping_add(len as u64);
        let m = MemOp { abs: Some(next.wrapping_add(disp as u64)), ..Default::default() };
        rm = Rm::Mem(m);
    }
    Some(Insn { pfx, opcode, esc, reg, rm, imm, len })
}

/// What an instruction does to the six status flags, as far as the deferral
/// decision cares.
///
/// Only ever consulted to choose between two *equally correct* lowerings, so a
/// misclassification costs instructions and never meaning. Everything the
/// classifier does not recognise — including every instruction the compiler
/// declines, which ends the block — answers [`FlagEffect::Reads`], the
/// conservative side.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlagEffect {
    /// Leaves every status flag alone, and reads none of them.
    Neutral,
    /// Defines all six from its own operands, reading none — this is what makes
    /// an earlier flag computation dead.
    Overwrites,
    /// Reads them, or defines only some of them (which amounts to the same
    /// thing: the bits it does not define have to be there already).
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
        // The regular ALU family; `adc`/`sbb` (forms 2 and 3) read CF.
        0x00..=0x3D if insn.opcode & 7 < 6 => match Alu::from_op(insn.opcode >> 3) {
            Some(_) => FlagEffect::Overwrites,
            None => FlagEffect::Reads,
        },
        // 32-bit INC/DEC preserve CF (and in 64-bit mode these bytes are a REX
        // prefix followed by something this compiler declines).
        0x40..=0x4F => FlagEffect::Reads,
        0x50..=0x5F | 0x63 | 0x88..=0x8B | 0x8D | 0x90 | 0xB0..=0xBF => FlagEffect::Neutral,
        0x68 | 0x6A | 0xA0..=0xA3 | 0xC6 | 0xC7 | 0xC9 => FlagEffect::Neutral,
        0x80 | 0x81 | 0x83 => match Alu::from_op(insn.reg & 7) {
            Some(_) => FlagEffect::Overwrites,
            None => FlagEffect::Reads,
        },
        0x84 | 0x85 | 0xA8 | 0xA9 => FlagEffect::Overwrites,
        // group 3: /0,/1 test → overwrites; /2 not → neutral; /3 neg →
        // overwrites; mul/div are not compiled at all.
        0xF6 | 0xF7 => match insn.reg & 7 {
            0 | 1 | 3 => FlagEffect::Overwrites,
            2 => FlagEffect::Neutral,
            _ => FlagEffect::Reads,
        },
        _ => FlagEffect::Reads,
    }
}

/// Would an [`FlagEffect::Overwrites`] instruction have to settle a pending
/// state before it could run? A memory *destination* would: by the time its
/// store can fault, the pending registers hold its own operands.
fn overwriter_settles(insn: &Insn) -> bool {
    if insn.esc || !matches!(insn.rm, Rm::Mem(_)) {
        return false;
    }
    match insn.opcode {
        0x00..=0x3D if insn.opcode & 7 < 2 => {
            Alu::from_op(insn.opcode >> 3).is_some_and(|o| o.writes_back())
        }
        0x80 | 0x81 | 0x83 => Alu::from_op(insn.reg & 7).is_some_and(|o| o.writes_back()),
        0xF6 | 0xF7 => insn.reg & 7 == 3, // neg
        _ => false,
    }
}

/// How far ahead the deferral scan looks. Long enough to see across an
/// addressing sequence, short enough that compiling stays cheap.
const DEFER_SCAN: u32 = 12;

/// Does leaving this instruction's flags pending actually pay?
///
/// It does exactly when some later instruction in this block overwrites all six
/// status flags before anything can read them — then the computation is skipped
/// outright. Otherwise settling later costs one instruction *more* than
/// computing now (the operation has to be repeated to recover NZCV), so the
/// answer is no.
fn defer_pays(mem: &dyn Memory, mode: Mode, mut rip: u64, budget: u32) -> bool {
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

    /// Lower one decoded instruction. `next` is the guest address after it.
    fn lower(&mut self, insn: &Insn, next: u64) -> Lowered {
        let p = insn.pfx;
        let has_rex = p.has_rex;
        // A faulting access rewinds to here, so this is the flag state every
        // stub of this instruction has to restore.
        self.insn_flags = self.flags;
        if insn.esc {
            return self.lower_0f(insn, next);
        }
        match insn.opcode {
            // ---- regular ALU family ------------------------------------
            0x00..=0x3D if insn.opcode & 7 < 6 => {
                let Some(op) = Alu::from_op(insn.opcode >> 3) else {
                    return Lowered::Unsupported;
                };
                let form = insn.opcode & 7;
                let size = if form % 2 == 0 && form != 5 { 1 } else { self.opsize(&p) };
                match form {
                    0 | 1 => {
                        // dst = r/m, src = reg
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
                        // dst = reg, src = r/m
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
                        // dst = al/eax, src = imm
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

            // ---- INC/DEC r32 (32-bit mode only) -------------------------
            0x40..=0x4F if !self.mode.is64() => {
                let r = insn.opcode & 7;
                let size = self.opsize(&p);
                self.materialize();
                self.load_gpr(R_FA, r, size, has_rex);
                self.emit_incdec(size, insn.opcode < 0x48);
                self.store_gpr(R_FR, r, size, has_rex);
                Lowered::Ok
            }

            // ---- PUSH/POP r ---------------------------------------------
            0x50..=0x57 => {
                let r = (insn.opcode & 7) | (p.b() << 3);
                let w = self.mode.stack_width();
                // Value first (a `push rsp` pushes the *old* rsp), then the new
                // stack pointer; rsp is only committed once the store succeeds.
                self.asm.ldr(8, R_VAL, R_STATE, gpr_off(r));
                self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_store_push(w, next);
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
                // rsp += w (masked), then the destination — in that order, so
                // `pop rsp` ends up holding the popped value.
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

            // ---- PUSH imm8 / imm32 --------------------------------------
            //
            // The 0x66 form pushes two bytes and adjusts rsp by two, which is
            // a different shape; it is not compiled.
            0x68 | 0x6A if !p.p66 => {
                let w = self.mode.stack_width();
                self.asm.mov_imm64(R_VAL, insn.imm);
                self.asm.ldr(8, T0, R_STATE, gpr_off(4));
                self.asm.sub_imm(true, R_ADDR, T0, w as u32, false);
                if !self.mode.is64() {
                    let ok = self.asm.and_imm(true, R_ADDR, R_ADDR, 0xffff_ffff);
                    debug_assert!(ok);
                }
                self.emit_store_push(w, next);
                Lowered::Ok
            }

            // ---- MOVSXD r64, r/m32 --------------------------------------
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

            // ---- IMUL r, r/m, imm ---------------------------------------
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

            // ---- Jcc rel8 -----------------------------------------------
            0x70..=0x7F => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                self.emit_jcc(insn.opcode & 0xF, target, next)
            }

            // ---- group 1: r/m, imm --------------------------------------
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

            // ---- TEST r/m, r --------------------------------------------
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

            // ---- MOV r/m <-> r ------------------------------------------
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

            // ---- LEA -----------------------------------------------------
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

            // ---- NOP -----------------------------------------------------
            0x90 if p.b() == 0 => Lowered::Ok,

            // ---- MOV AL/eAX <-> moffs (absolute address) ----------------
            0xA0..=0xA3 => {
                // In 64-bit mode the interpreter resolves `fs:` against a fixed
                // constant that does not live in `CpuState`, so compiled code
                // has nothing correct to read — the same refusal the ModRM path
                // makes.
                if self.mode.is64() && p.seg == 0x64 {
                    return Lowered::Unsupported;
                }
                let size = if insn.opcode & 1 == 0 { 1 } else { self.opsize(&p) };
                self.asm.mov_imm64(R_ADDR, insn.imm);
                // The **live** per-thread segment bases, in the interpreter's
                // order: base first, then the address mask (roadmap W5.7).
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

            // ---- TEST al/eax, imm ---------------------------------------
            0xA8 | 0xA9 => {
                let size = if insn.opcode == 0xA8 { 1 } else { self.opsize(&p) };
                self.load_gpr(R_FA, 0, size, has_rex);
                self.asm.mov_imm64(R_FB, insn.imm & mask_of(size));
                self.emit_alu(Alu::And, size);
                Lowered::Ok
            }

            // ---- MOV r, imm ---------------------------------------------
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

            // ---- shifts with a constant count ---------------------------
            0xC0 | 0xC1 | 0xD0 | 0xD1 => {
                let size = if insn.opcode & 1 == 0 { 1 } else { self.opsize(&p) };
                let count = if insn.opcode < 0xD0 { insn.imm } else { 1 };
                self.emit_shift(insn, size, count, next, has_rex)
            }

            // ---- MOV r/m, imm -------------------------------------------
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

            // ---- LEAVE ---------------------------------------------------
            //
            // `mov rsp, rbp ; pop rbp`, in the interpreter's exact order: the
            // transient `rsp = rbp` is masked by the pop's own read, and the
            // committed rsp is `(rbp + width)` masked.
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

            // ---- JMP rel -------------------------------------------------
            0xE9 | 0xEB => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                let f = self.flags;
                self.exit_to(f, target, (self.insns + 1) as u64);
                Lowered::Terminated
            }

            // ---- group 3: NOT / NEG --------------------------------------
            0xF6 | 0xF7 => {
                let size = if insn.opcode == 0xF6 { 1 } else { self.opsize(&p) };
                match insn.reg & 7 {
                    2 => {
                        // NOT — no flags.
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
                        // NEG — 0 - v, full arithmetic flags.
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

            // ---- group 4/5: INC/DEC r/m ---------------------------------
            0xFE | 0xFF => {
                let sub = insn.reg & 7;
                if sub > 1 {
                    return Lowered::Unsupported; // call/jmp/push r/m
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
            // multi-byte NOP
            0x1F => Lowered::Ok,
            // CMOVcc
            0x40..=0x4F => {
                let size = self.opsize(&p);
                self.materialize();
                if let Rm::Mem(m) = insn.rm {
                    self.emit_addr(&m);
                }
                // `R_FA` is free once the pending state is settled above.
                self.read_rm(&insn.rm, R_FA, size, has_rex);
                self.load_gpr(R_VAL, insn.reg, size, has_rex);
                self.emit_cond_value(insn.opcode & 0xF, T0);
                self.asm.subs_imm(true, ZR, T0, 0, false);
                // The destination is written unconditionally — that is what
                // zero-extends a 32-bit CMOV even when the condition is false.
                self.asm.csel(true, R_VAL, R_FA, R_VAL, Cond::Ne);
                self.store_gpr(R_VAL, insn.reg, size, has_rex);
                Lowered::Ok
            }
            // Jcc rel32
            0x80..=0x8F => {
                let target = next.wrapping_add(insn.imm) & self.mode.addr_mask();
                self.emit_jcc(insn.opcode & 0xF, target, next)
            }
            // IMUL r, r/m
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
            // MOVZX / MOVSX
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

    /// Mask a value in `r` down to `size` bytes.
    fn mask_to(&mut self, r: u32, size: u8) {
        if size == 8 {
            return;
        }
        let ok = self.asm.and_imm(true, r, r, mask_of(size));
        debug_assert!(ok);
    }

    /// An instruction whose destination is a **memory** operand and which also
    /// defines flags has to settle anything pending before it starts: by the
    /// time its store can fault, the pending registers hold *this*
    /// instruction's operands, so the rewind path could no longer reconstruct
    /// the previous instruction's flags. (A `cmp`/`test` against memory writes
    /// nothing back, so it keeps the deferral.)
    fn settle_for_rm_dest(&mut self, rm: &Rm, op: Alu) {
        if matches!(rm, Rm::Mem(_)) && op.writes_back() {
            self.materialize();
        }
    }

    /// Commit an instruction whose destination is the r/m operand. The flags
    /// stay pending: on the store's rewind path `R_FLAGS` is still the
    /// pre-instruction value, which is exactly what a rewind wants.
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

    /// INC/DEC: add/sub 1 with CF preserved. The operand is in [`R_FA`], and
    /// the caller has already settled any pending flags — so `R_FLAGS` holds
    /// the incoming CF that materialising will keep.
    fn emit_incdec(&mut self, size: u8, is_inc: bool) {
        self.asm.mov_imm64(R_FB, 1);
        if self.defer {
            self.emit_arith_value(size, !is_inc);
            self.flags = Flags::Arith { size, sub: !is_inc, keep_cf: true };
        } else {
            self.emit_arith_eager(size, !is_inc, true);
        }
    }

    /// Two-operand signed multiply truncated to `size`; CF = OF = "the full
    /// product did not fit", every other flag untouched (exactly the
    /// interpreter's `imul_trunc`). Operands in [`R_FA`]/[`R_FB`], result in
    /// [`R_VAL`]; the caller has settled the flags, so this writes them directly.
    fn emit_imul(&mut self, size: u8) {
        let bits = size as u32 * 8;
        if size == 8 {
            self.asm.mul(true, R_VAL, R_FA, R_FB);
            self.asm.smulh(T1, R_FA, R_FB);
            // Overflow iff the high half is not the sign extension of the low.
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

    /// SHL/SHR/SAR with a compile-time count. The rotates and the CL-count
    /// forms are not compiled.
    ///
    /// A shift *preserves* AF (and OF unless the count is 1), so it reads the
    /// incoming flags and computes eagerly rather than deferring — into
    /// [`R_FA`], which is free once the pending state is settled and which
    /// survives the store of a memory destination.
    fn emit_shift(&mut self, insn: &Insn, size: u8, count: u64, next: u64, has_rex: bool) -> Lowered {
        let kind = insn.reg & 7;
        // 0=rol 1=ror 2=rcl 3=rcr 4=shl 5=shr 6=shl(alias) 7=sar
        let (is_shl, is_sar) = match kind {
            4 | 6 => (true, false),
            5 => (false, false),
            7 => (false, true),
            _ => return Lowered::Unsupported,
        };
        let bits = size as u32 * 8;
        let count = (count & if size == 8 { 0x3f } else { 0x1f }) as u32;
        if count == 0 {
            // Identity, and — crucially — flags are left completely untouched,
            // including anything still pending, so nothing is settled here.
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
        // `R_FB` is free once the pending state is settled, and it survives the
        // store of a memory destination.
        self.read_rm(&insn.rm, R_FB, size, has_rex);
        // CF, then the result; both from the pre-shift value.
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
        // Clear CF/SF/ZF/PF (plus OF when the count is 1, the only case in which
        // the architecture defines it), then rebuild them.
        let clear = (1u64 << F_CF) | (1 << F_SF) | (1 << F_ZF) | (1 << F_PF) | if count == 1 { 1 << F_OF } else { 0 };
        self.asm.mov_imm64(T0, clear);
        self.asm.bic_reg(true, R_FA, R_FLAGS, T0, 0);
        self.asm.orr_reg(true, R_FA, R_FA, T3, F_CF);
        if count == 1 {
            if is_shl {
                // OF = MSB(result) XOR CF
                self.asm.ubfx(true, T0, R_VAL, bits - 1, 1);
                self.asm.eor_reg(true, T0, T0, T3, 0);
                self.asm.orr_reg(true, R_FA, R_FA, T0, F_OF);
            } else if !is_sar {
                // SHR: OF = MSB(original)
                self.asm.ubfx(true, T0, R_FB, bits - 1, 1);
                self.asm.orr_reg(true, R_FA, R_FA, T0, F_OF);
            }
            // SAR: OF = 0, already cleared.
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

    /// The store half of `push`: the address in [`R_ADDR`] *is* the new rsp and
    /// the value is in [`R_VAL`]; rsp is committed only after the store
    /// succeeds.
    fn emit_store_push(&mut self, w: u8, next: u64) {
        self.asm.mov_reg(true, 0, R_CTX);
        self.asm.mov_reg(true, 1, R_ADDR);
        self.asm.mov_imm64(2, w as u64);
        self.asm.mov_reg(true, 3, R_VAL); // the value being pushed
        // The pending commit is the *new rsp*, so move it into R_VAL now that
        // the pushed value is safely in an argument register — both the hot path
        // and the "store hit code" stub then commit the same register.
        self.asm.mov_reg(true, R_VAL, R_ADDR);
        self.asm.ldr(8, T0, R_CTX, ctx_off::WRITE);
        self.asm.blr(T0);
        let l = self.asm.cbnz_forward(true, 0);
        self.store_stubs.push(StoreStub {
            label: l,
            retired: self.insns,
            rip: self.rip,
            next_rip: next,
            commit: Commit::Gpr { idx: 4, size: 8, has_rex: true },
            before: self.insn_flags,
            after: self.flags,
        });
        self.store_gpr(R_VAL, 4, 8, true);
    }

    /// A conditional branch: both edges are compiled, so the block leaves with
    /// `rip` already correct and never returns to the interpreter for the jump.
    fn emit_jcc(&mut self, cc: u8, target: u64, fallthrough: u64) -> Lowered {
        // The condition reads `R_FLAGS`, and both edges leave the block.
        self.materialize();
        let taken = self.branch_if_cond(cc);
        self.exit_to(Flags::Live, fallthrough, (self.insns + 1) as u64);
        self.asm.bind(taken);
        self.exit_to(Flags::Live, target, (self.insns + 1) as u64);
        Lowered::Terminated
    }
}
