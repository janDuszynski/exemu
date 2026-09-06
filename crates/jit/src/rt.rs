//! The runtime a compiled block calls back into, and the context it reads.
//!
//! Compiled code never touches guest memory directly. Every load and store is a
//! call to one of the two helpers here, which go through the same
//! [`exemu_core::Memory`] implementation — and therefore the same bounds checks,
//! permission checks and region lookups — as the interpreter. That costs a call
//! per access, and buys two things worth more than the cycles: a JIT block
//! cannot reach a host address the interpreter could not, and a faulting access
//! produces *exactly* the interpreter's fault, because the interpreter is the
//! thing that ends up raising it (see [`status`]).
//!
//! [`BlockCtx`] is also where **native block linking** (roadmap W8.5) keeps its
//! state, because a linked chain of blocks never returns to Rust between links:
//! the running instruction total, the budget it is measured against, the
//! link-slot array, the block trail and the self-modification report all live
//! here so that compiled code can maintain them itself.

use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::{Memory, Perm};

/// Entries in the block-entry ring [`BlockCtx::trail`] points at. A power of two
/// so compiled code can wrap the index with a single `and`.
pub const TRAIL: usize = 32;

/// Bits of the page-hash table in [`BlockCtx::code_pages`] — one bit per hashed
/// guest code page, `1 << CODE_PAGE_BITS` bits in all (16 KiB at 17).
pub const CODE_PAGE_BITS: u32 = 17;

/// Words in that table.
pub const CODE_PAGE_WORDS: usize = 1 << (CODE_PAGE_BITS - 6);

/// [`BlockCtx::pending`] when the last exit had no link slot to fill.
pub const NO_SLOT: u64 = u64::MAX;

/// [`BlockCtx::smc`] when no store has hit a page that may hold compiled code.
pub const NO_SMC: u64 = u64::MAX;

/// The one epoch value no [`LinkSlot`] ever carries, so writing it into
/// [`BlockCtx::link_epoch`] takes every link out of service *for the rest of the
/// running chain* — which is how a store into guest code stops a chain from
/// jumping into a block it may have just invalidated, without unwinding to Rust
/// first. The engine's own epochs run `1 ..= u64::MAX - 1`; a never-filled slot
/// carries 0, which is why 0 could not be used for this (an empty slot and a
/// dead epoch would have compared equal, and the block would have branched to a
/// null pointer — which is exactly what the first version of this did).
pub const LINK_EPOCH_DEAD: u64 = u64::MAX;

/// Which bit of the [`BlockCtx::code_pages`] table stands for `addr`'s page.
///
/// A hash rather than a direct index, because guest code pages are scattered
/// across a 64-bit address space: a *set* bit means "a compiled block may live
/// on this page" and is confirmed exactly, on the rare path, against the
/// engine's real page set. A clear bit is definitive.
#[inline]
pub fn code_page_bit(addr: u64) -> u64 {
    (addr / exemu_core::CODE_PAGE_SIZE).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - CODE_PAGE_BITS)
}

/// Status word returned by the store helper (and the `fault` half of
/// [`ReadResult`]).
pub mod status {
    /// The access completed normally.
    pub const OK: u64 = 0;
    /// The access faulted. Compiled code must rewind: `rip` goes back to the
    /// start of the faulting instruction, nothing that instruction would have
    /// changed has been changed, and the caller re-executes it on the
    /// interpreter, which raises the real `EmuError`.
    pub const FAULT: u64 = 1;
    /// The store completed **and** landed on a page some compiled block was
    /// built from. The block must commit this instruction and then stop, because
    /// any instruction after it — in this block, or in any block the chain is
    /// natively linked to — may have just been rewritten underneath the compiled
    /// code.
    pub const WROTE_CODE: u64 = 2;
}

/// A guest load's result: the value in `x0`, the status in `x1` (AAPCS64 returns
/// a 16-byte struct in the first two result registers, so the emitted check is a
/// single `cbnz x1`).
#[repr(C)]
pub struct ReadResult {
    pub value: u64,
    pub status: u64,
}

/// One entry of the link array: a compiled block's successor, cached.
///
/// `epoch` is what makes the pointer safe to jump to. Every slot is stamped with
/// the engine's link epoch when it is filled, and compiled code takes the link
/// only while the stamp still matches [`BlockCtx::link_epoch`] — so **unlinking
/// everything is a single increment**, with no walk over the array, no patching
/// of emitted code and no instruction-cache maintenance. Every event that can
/// make a cached pointer wrong bumps the epoch: a code-cache flush, guest code
/// overwritten under a cached block, and (when it arrives) a debugger attaching.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkSlot {
    pub epoch: u64,
    /// The guest address this slot caches a block for. A **direct** exit knows
    /// its target at compile time and does not read this; an **indirect** one —
    /// a computed `jmp`/`call` — compares the address the guest just produced
    /// against it, and takes the link only if they agree. That comparison is the
    /// inline cache: one load and one compare buys the whole chain when the
    /// branch keeps going to the same place, and costs nothing but a return to
    /// Rust when it does not.
    pub key: u64,
    /// Address of the successor block's *chain entry* — its body, past the
    /// frame-building prologue the chain has already executed once.
    pub code: u64,
}

// ---------------------------------------------------------------------------
// The guest-memory TLB (roadmap W8.6)
// ---------------------------------------------------------------------------
//
// A direct-mapped cache of *host* addresses, so the common guest load or store
// is a handful of emitted instructions instead of a call into [`jit_read`] /
// [`jit_write`] and a region lookup. Compiled code only ever **reads** it; every
// entry is written here, on the slow path, from a span the backend handed out —
// and the backend refuses to hand one out in exactly the cases where a direct
// access would not be equivalent (see `Memory::host_span`).

/// Slots, a power of two so the index is a mask. 512 × 32 B = 16 KiB, which
/// covers 2 MiB of contiguous guest space and sits well inside L1D.
pub const TLB_SLOTS: usize = 512;

/// `log2(TLB_SLOTS)`, as the emitter's `ubfx` width.
pub const TLB_SLOT_BITS: u32 = 9;

/// Guest page shift. The same 4 KiB page the SMC seam uses.
pub const TLB_PAGE_BITS: u32 = 12;

/// Bytes an entry must cover for the page it caches: **the whole page plus the
/// widest access minus one**.
///
/// This is what makes the emitted fast path a single tag compare with no
/// end-of-access check. An 8-byte load at the page's last byte reaches 7 bytes
/// into the next page — and because the span was resolved as one contiguous run
/// inside *one* region, those bytes are at the same host offset and under the
/// same permission, so the cached base is right for them too. A page whose
/// region ends less than 7 bytes past it simply never gets an entry and stays
/// on the helper.
pub const TLB_SPAN: usize = (1 << TLB_PAGE_BITS) + 7;

/// The tag of a slot that caches nothing. A real tag is a guest address shifted
/// right by [`TLB_PAGE_BITS`], so it can never reach `u64::MAX` — which matters,
/// because a *zeroed* table would otherwise claim to cache guest page 0, and the
/// differential's edge layout maps page 0 on purpose.
pub const TLB_EMPTY: u64 = u64::MAX;

/// One direct-mapped entry: a page's host base for reading and for writing,
/// kept apart so a store can never take an entry a load filled.
///
/// `base` is `host_address_of_page - guest_page_base`, so compiled code forms
/// the host address as `base + guest_addr` with one add folded into the load's
/// addressing mode.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlbEntry {
    pub read_tag: u64,
    pub read_base: u64,
    pub write_tag: u64,
    pub write_base: u64,
}

impl TlbEntry {
    /// An entry that caches nothing.
    pub const EMPTY: TlbEntry =
        TlbEntry { read_tag: TLB_EMPTY, read_base: 0, write_tag: TLB_EMPTY, write_base: 0 };
}

impl Default for TlbEntry {
    fn default() -> Self {
        TlbEntry::EMPTY
    }
}

/// Byte offsets inside a [`TlbEntry`], for the emitter's `ldp`.
pub mod tlb_off {
    use super::TlbEntry;
    pub const READ: u32 = std::mem::offset_of!(TlbEntry, read_tag) as u32;
    pub const WRITE: u32 = std::mem::offset_of!(TlbEntry, write_tag) as u32;
    pub const SIZE: u32 = std::mem::size_of::<TlbEntry>() as u32;
}

/// The tag compiled code compares against: `addr`'s guest page number.
#[inline]
pub fn tlb_tag(addr: u64) -> u64 {
    addr >> TLB_PAGE_BITS
}

/// The slot compiled code indexes: the low bits of that page number.
#[inline]
pub fn tlb_slot(addr: u64) -> usize {
    (tlb_tag(addr) as usize) & (TLB_SLOTS - 1)
}

/// Base of the page `addr` is on.
#[inline]
fn tlb_page_base(addr: u64) -> u64 {
    addr & !((1u64 << TLB_PAGE_BITS) - 1)
}

/// The load helper's type, as compiled code calls it.
pub type ReadFn<M> = unsafe extern "C" fn(*mut BlockCtx<'_, M>, u64, u32) -> ReadResult;

/// The store helper's type.
pub type WriteFn<M> = unsafe extern "C" fn(*mut BlockCtx<'_, M>, u64, u32, u64) -> u64;

/// Everything a compiled block needs that is not the register file.
///
/// The emitted code loads and stores this struct at fixed offsets ([`ctx_off`])
/// and passes its address to the helpers; it never interprets the `mem` field,
/// which is why that field can stay an ordinary Rust reference.
///
/// `M` is the guest-memory backend, **by value rather than as `dyn Memory`**
/// (roadmap W8.6). It buys nothing structurally — the helpers still go through
/// the same [`Memory`] impl, in the same order, with the same checks — but it
/// takes the vtable dispatch out of the single hottest path in the JIT: with
/// the backend's type known, `read_uint`/`write_uint` are direct calls that
/// ThinLTO can inline into [`jit_read`]/[`jit_write`], which also collapses the
/// 40-byte `Result<u64, EmuError>` those methods return through memory. Guest
/// loads and stores were **40% of the whole 7-Zip run** when this was measured.
#[repr(C)]
pub struct BlockCtx<'a, M: Memory + ?Sized> {
    /// 256-byte table: `parity[b]` is the x86 PF for a result whose low byte is
    /// `b` (1 when the byte has an even number of set bits). Compiled code
    /// computes PF with an `and`+`ldrb` instead of a five-instruction fold.
    pub parity: *const u8,
    /// The guest address range the **currently running** block was compiled
    /// from. A store inside it has rewritten instructions this block is about to
    /// execute, so the block must commit that store and stop — and since a
    /// natively linked chain never returns to Rust between blocks, the block
    /// writes this pair itself, at its chain entry, rather than being handed it.
    pub code_lo: u64,
    pub code_hi: u64,
    /// Address of [`jit_read`], loaded and `blr`-ed by compiled code.
    pub read: ReadFn<M>,
    /// Address of [`jit_write`].
    pub write: WriteFn<M>,
    /// Guest instructions retired since [`crate::Jit::run`] was entered — kept
    /// here rather than in a register because a chain of natively linked blocks
    /// carries it across block boundaries without returning to Rust.
    pub retired: u64,
    /// The chain stops at the first block boundary at which `retired` has
    /// reached this. It is a **correctness** parameter, not a tuning knob:
    /// preemption, the `KUSER_SHARED_DATA` refresh and the step cap all happen
    /// between blocks in the caller's loop, so a chain that ran past the budget
    /// would move them.
    pub budget: u64,
    /// Base of the engine's [`LinkSlot`] array.
    pub links: *const LinkSlot,
    /// The epoch a slot must carry to be taken (see [`LinkSlot`]).
    pub link_epoch: u64,
    /// Slot index the last returning exit wanted to link and could not, or
    /// [`NO_SLOT`]. The engine fills exactly that slot once it has compiled and
    /// validated the block the chain landed on — the link is created from the
    /// side that knows both of its ends.
    pub pending: u64,
    /// Ring of guest addresses of the blocks a chain linked into, and the
    /// monotonic index into it. The fault reporter prints this trail, and a
    /// natively linked chain is invisible to the caller's loop, so compiled code
    /// writes it.
    pub trail: *mut u64,
    pub trail_at: u64,
    /// Address of the **first** store that landed on a page the page-hash table
    /// says may hold compiled code, or [`NO_SMC`], and how many such stores there
    /// were. The engine confirms one address against its exact page set — a hash
    /// has false positives and unlinking on every one of them would be a real
    /// cost — but it can only do that for a single address, so more than one hit
    /// in the same block is treated as the real thing rather than guessed at.
    pub smc: u64,
    pub smc_hits: u64,
    /// `1 << CODE_PAGE_BITS` bits: which guest pages compiled blocks were built
    /// from. Read by [`jit_write`] on every store, so it is a table lookup and
    /// not a set-membership test.
    pub code_pages: *const u64,
    /// Base of the engine's [`TlbEntry`] array — [`TLB_SLOTS`] entries, read by
    /// compiled code on every guest access and written only here.
    pub tlb: *mut TlbEntry,
    /// Non-zero while the helpers may fill that array. Zero is not a
    /// correctness requirement — `Memory::host_span` refuses on its own in every
    /// case that matters — it is how the engine stops paying for fills it knows
    /// will be refused, and how a test can force every access onto the helper.
    pub tlb_on: u64,
    /// Entries filled, and fills the backend refused, since [`crate::Jit::run`]
    /// was entered. Reported, not acted on: a refusal is a store into
    /// executable memory or a page at the tail of its region, and how often
    /// those happen is the thing worth knowing rather than guessing at.
    pub tlb_fills: u64,
    pub tlb_denied: u64,
    /// Accesses [`jit_read_watched`] / [`jit_write_watched`] refused because
    /// they land in an armed watchpoint. Reported, like the two above.
    pub watch_stops: u64,
    /// The process's shared debug handle, when one is attached (roadmap W9.3).
    ///
    /// Read **only** by [`jit_read_watched`] / [`jit_write_watched`], which are
    /// installed in `read`/`write` above only while a watchpoint is actually
    /// armed — so on every ordinary run this field is `None`, nothing loads it,
    /// and the emitted code does not know it exists. Emitted code never reads
    /// it at all: it has no offset in [`ctx_off`].
    pub debug: Option<&'a DebugControl>,
    /// Guest memory. Only the helpers below dereference it.
    ///
    /// **Last on purpose.** `M` is a type parameter (roadmap W8.6), so this is
    /// a thin pointer for a concrete backend and a fat one for `dyn Memory`;
    /// putting it last means every offset above it is the same either way, and
    /// the emitter's [`ctx_off`] constants hold for every instantiation.
    /// `ctx_offsets_do_not_depend_on_the_memory_type` pins that.
    pub mem: &'a mut M,
}

impl<M: Memory + ?Sized> BlockCtx<'_, M> {
    /// Cache the host base of `addr`'s page for **reading**, if the backend
    /// will hand one out.
    ///
    /// Called from the slow path after an access has already succeeded, so the
    /// page is known to be mapped; what is being asked here is the stronger
    /// question the fast path needs — is the *whole* page, plus the seven bytes
    /// an 8-byte access at its last byte reaches, inside one region with this
    /// permission, and is there nothing armed that must observe the access.
    /// Every one of those is the backend's judgement, not this crate's.
    #[cold]
    #[inline(never)]
    fn tlb_fill_read(&mut self, addr: u64) {
        let page = tlb_page_base(addr);
        let Some(span) = self.mem.host_span(page, TLB_SPAN, Perm::READ) else {
            self.tlb_denied += 1;
            return;
        };
        let base = (span.as_ptr() as u64).wrapping_sub(page);
        self.tlb_fills += 1;
        // SAFETY: `tlb` is the engine's array, `TLB_SLOTS` entries long and
        // alive for the whole call; `tlb_slot` masks to exactly that many. The
        // base is written before the tag so a slot is never momentarily
        // readable with a stale base.
        unsafe {
            let e = self.tlb.add(tlb_slot(addr));
            (*e).read_base = base;
            (*e).read_tag = tlb_tag(addr);
        }
    }

    /// As [`tlb_fill_read`](Self::tlb_fill_read), for **writing**.
    ///
    /// The backend additionally refuses executable memory here, which is what
    /// keeps every store that could rewrite compiled code on [`jit_write`] —
    /// and therefore keeps the self-modification range test, the code-page hash
    /// and `Memory::code_generation` in the path of every such store.
    #[cold]
    #[inline(never)]
    fn tlb_fill_write(&mut self, addr: u64) {
        let page = tlb_page_base(addr);
        let Some(span) = self.mem.host_span_mut(page, TLB_SPAN, Perm::WRITE) else {
            self.tlb_denied += 1;
            return;
        };
        let base = (span.as_mut_ptr() as u64).wrapping_sub(page);
        self.tlb_fills += 1;
        // SAFETY: as `tlb_fill_read`.
        unsafe {
            let e = self.tlb.add(tlb_slot(addr));
            (*e).write_base = base;
            (*e).write_tag = tlb_tag(addr);
        }
    }

    /// Might a compiled block live on `addr`'s page? A clear bit is a definitive
    /// no; a set bit is confirmed against the engine's exact page set on the
    /// rare path (see [`crate::Jit`]).
    #[inline]
    pub fn code_page_hit(&self, addr: u64) -> bool {
        let bit = code_page_bit(addr);
        // SAFETY: `code_pages` is the engine's table, which is
        // `CODE_PAGE_WORDS` words long and outlives every block call; `bit` is a
        // hash shifted down to exactly `CODE_PAGE_BITS` bits, so `bit >> 6` is
        // inside it.
        let word = unsafe { *self.code_pages.add((bit >> 6) as usize) };
        word & (1u64 << (bit & 63)) != 0
    }
}

/// Byte offsets of the [`BlockCtx`] fields the emitter loads and stores.
///
/// Taken against `dyn Memory`, and identical for every other backend: `mem` is
/// the struct's last field, so the type parameter cannot move anything the
/// emitter addresses (see [`BlockCtx::mem`]).
pub mod ctx_off {
    use super::BlockCtx;
    use exemu_core::Memory;
    type Ctx = BlockCtx<'static, dyn Memory>;
    pub const PARITY: u32 = std::mem::offset_of!(Ctx, parity) as u32;
    pub const CODE_LO: u32 = std::mem::offset_of!(Ctx, code_lo) as u32;
    pub const READ: u32 = std::mem::offset_of!(Ctx, read) as u32;
    pub const WRITE: u32 = std::mem::offset_of!(Ctx, write) as u32;
    pub const RETIRED: u32 = std::mem::offset_of!(Ctx, retired) as u32;
    pub const BUDGET: u32 = std::mem::offset_of!(Ctx, budget) as u32;
    pub const LINKS: u32 = std::mem::offset_of!(Ctx, links) as u32;
    pub const LINK_EPOCH: u32 = std::mem::offset_of!(Ctx, link_epoch) as u32;
    pub const PENDING: u32 = std::mem::offset_of!(Ctx, pending) as u32;
    pub const TRAIL: u32 = std::mem::offset_of!(Ctx, trail) as u32;
    pub const TRAIL_AT: u32 = std::mem::offset_of!(Ctx, trail_at) as u32;
    pub const TLB: u32 = std::mem::offset_of!(Ctx, tlb) as u32;
}

/// The parity table (`PF` = 1 when the low byte has an even population count).
pub static PARITY: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = ((i as u8).count_ones() % 2 == 0) as u8;
        i += 1;
    }
    t
};

/// Guest load. Called from compiled code with the block's `BlockCtx`.
///
/// # Safety
/// `ctx` must be the pointer the engine passed into the block: a live,
/// exclusively-borrowed `BlockCtx` for the duration of the call.
pub unsafe extern "C" fn jit_read<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
) -> ReadResult {
    // SAFETY: the engine builds the `BlockCtx` on its own stack, hands the block
    // a raw pointer to it, and holds no reference to it while the block runs —
    // so this is the only live borrow for the duration of the call.
    let ctx = unsafe { &mut *ctx };
    match ctx.mem.read_uint(addr, size as u8) {
        Ok(value) => {
            // The access succeeded, so this is a page worth caching — and this
            // is the only moment the helper runs for it, because once the entry
            // is in, compiled code stops calling here for that page.
            if ctx.tlb_on != 0 {
                ctx.tlb_fill_read(addr);
            }
            ReadResult { value, status: status::OK }
        }
        Err(_) => ReadResult { value: 0, status: status::FAULT },
    }
}

/// Guest load, with the debug handle's data watchpoints honoured
/// (roadmap W9.3, step S6).
///
/// Installed in [`BlockCtx::read`] by [`crate::Jit::run`] **only** while a
/// watchpoint is actually armed, so the disarmed cost is not "a cheap check per
/// access" but no check and no different code at all — the emitted block is
/// byte-identical either way, because the helper is reached through a pointer.
///
/// The check is made **before** the access and a hit returns [`status::FAULT`]
/// *without performing it*. That is deliberate and it is the only status that
/// works:
///
/// * `FAULT` is the one answer that returns control to the engine's caller at
///   the instruction in question — the block rewinds to the start of that
///   instruction having changed nothing, and the caller's run loop hands
///   exactly that instruction to the **interpreter**, which performs the access,
///   records the hit on the shared handle, and lets the run-loop head report it
///   *after* the instruction completes (trap-after, matching x86 data
///   breakpoints).
/// * A "commit, then stop" status would end the *block*, but the chain loop
///   would simply go round to the next one, so the stop would surface a whole
///   chain late and against the wrong instruction count.
///
/// The access therefore happens exactly **once**, on the interpreter, and this
/// crate reports nothing about it: the reported address, kind and count all come
/// from the reference engine.
///
/// # Safety
/// As [`jit_read`].
pub unsafe extern "C" fn jit_read_watched<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
) -> ReadResult {
    // SAFETY: as `jit_read` — and this reads two `Copy` fields before handing
    // the same pointer on, so no borrow of `*ctx` is live across the call.
    let watched = unsafe {
        (*ctx).debug.is_some_and(|d| d.is_watched(addr, u64::from(size), WatchKind::Read))
    };
    if watched {
        // SAFETY: as above.
        unsafe { (*ctx).watch_stops += 1 };
        return ReadResult { value: 0, status: status::FAULT };
    }
    // SAFETY: the caller's contract, unchanged.
    unsafe { jit_read(ctx, addr, size) }
}

/// Guest store, with the debug handle's data watchpoints honoured
/// (roadmap W9.3, step S6). See [`jit_read_watched`] — the rule is the same one,
/// and the store is refused *before* it lands, so the interpreter is the only
/// thing that ever performs it.
///
/// # Safety
/// As [`jit_read`].
pub unsafe extern "C" fn jit_write_watched<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
    value: u64,
) -> u64 {
    // SAFETY: as `jit_read_watched`.
    let watched = unsafe {
        (*ctx).debug.is_some_and(|d| d.is_watched(addr, u64::from(size), WatchKind::Write))
    };
    if watched {
        // SAFETY: as above.
        unsafe { (*ctx).watch_stops += 1 };
        return status::FAULT;
    }
    // SAFETY: the caller's contract, unchanged.
    unsafe { jit_write(ctx, addr, size, value) }
}

/// Guest store. Returns a [`status`] word.
///
/// # Safety
/// As [`jit_read`].
pub unsafe extern "C" fn jit_write<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
    value: u64,
) -> u64 {
    // SAFETY: see `jit_read`.
    let ctx = unsafe { &mut *ctx };
    // Two questions, because they have two different answers.
    //
    // **Does this store rewrite the running block's own instructions?** Then the
    // block must commit it and stop, because what comes after it in this block
    // may no longer be what was compiled. Byte-precise, two compares — the same
    // test this helper has always made, on a range the block now publishes for
    // itself (a linked chain enters blocks Rust never sees).
    //
    // **Does it land on a page *any* compiled block was built from?** Then some
    // block further along this chain's links may be stale, and the chain must
    // not jump into one. Zeroing the context's copy of the link epoch does
    // exactly that and no more: no slot carries epoch 0, so every remaining exit
    // in this chain returns to Rust instead of linking, and the engine — told
    // where the store went — confirms the page against its exact set before
    // deciding whether to unlink for real. One shift, one multiply and one load,
    // on a path a store takes ~10% of guest instructions.
    let own = addr < ctx.code_hi && addr.saturating_add(size as u64) > ctx.code_lo;
    // The second probe is only worth making when the access really does span two
    // pages. `code_page_bit` depends on nothing but `addr / CODE_PAGE_SIZE`
    // (pinned by `the_page_hash_puts_one_page_in_exactly_one_bit`), so within a
    // page the two probes are the same probe — and every store was paying for it.
    // The offset test also covers the address-space wrap that made the old form
    // use `wrapping_add`: an `addr` high enough to wrap has a page offset high
    // enough to take the branch.
    let spans_two_pages =
        (addr & (exemu_core::CODE_PAGE_SIZE - 1)) + size as u64 > exemu_core::CODE_PAGE_SIZE;
    let page = ctx.code_page_hit(addr)
        || (spans_two_pages && ctx.code_page_hit(addr.wrapping_add(size as u64 - 1)));
    match ctx.mem.write_uint(addr, size as u8, value) {
        Err(_) => status::FAULT,
        Ok(()) => {
            if page {
                if ctx.smc_hits == 0 {
                    ctx.smc = addr;
                }
                ctx.smc_hits += 1;
                ctx.link_epoch = LINK_EPOCH_DEAD;
            }
            if ctx.tlb_on != 0 {
                ctx.tlb_fill_write(addr);
            }
            if own {
                status::WROTE_CODE
            } else {
                status::OK
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `BlockCtx` over `mem` with `pages` marked as holding compiled code and
    /// `tlb` as its guest-memory TLB.
    fn ctx_with_tlb<'a>(
        mem: &'a mut exemu_memory::VirtualMemory,
        table: &'a mut [u64],
        pages: &[u64],
        tlb: &'a mut [TlbEntry],
        tlb_on: u64,
    ) -> BlockCtx<'a, exemu_memory::VirtualMemory> {
        for &p in pages {
            let bit = code_page_bit(p);
            table[(bit >> 6) as usize] |= 1 << (bit & 63);
        }
        BlockCtx {
            parity: PARITY.as_ptr(),
            code_lo: 0,
            code_hi: 0,
            read: jit_read,
            write: jit_write,
            retired: 0,
            budget: 0,
            links: std::ptr::null(),
            link_epoch: 7,
            pending: NO_SLOT,
            trail: std::ptr::null_mut(),
            trail_at: 0,
            smc: NO_SMC,
            smc_hits: 0,
            code_pages: table.as_ptr(),
            tlb: tlb.as_mut_ptr(),
            tlb_on,
            tlb_fills: 0,
            tlb_denied: 0,
            watch_stops: 0,
            debug: None,
            mem,
        }
    }

    /// A fresh TLB, as the engine hands one over.
    fn empty_tlb() -> Vec<TlbEntry> {
        vec![TlbEntry::EMPTY; TLB_SLOTS]
    }

    /// The entry `addr` maps to, read back the way compiled code would — through
    /// the context's own pointer, so the backing array stays borrowed by it.
    fn slot_of<M: Memory + ?Sized>(ctx: &BlockCtx<'_, M>, addr: u64) -> TlbEntry {
        // SAFETY: `ctx.tlb` is the array the caller handed over, `TLB_SLOTS`
        // entries long and alive for the whole test; `tlb_slot` masks into it.
        unsafe { *ctx.tlb.add(tlb_slot(addr)) }
    }

    /// Is every slot still empty?
    fn all_empty<M: Memory + ?Sized>(ctx: &BlockCtx<'_, M>) -> bool {
        // SAFETY: as `slot_of`.
        (0..TLB_SLOTS).all(|i| unsafe { *ctx.tlb.add(i) } == TlbEntry::EMPTY)
    }

    /// The two page-hash tests below do not exercise the TLB, so they get one
    /// that is switched off.
    fn ctx_over<'a>(
        mem: &'a mut exemu_memory::VirtualMemory,
        table: &'a mut [u64],
        pages: &[u64],
        tlb: &'a mut [TlbEntry],
    ) -> BlockCtx<'a, exemu_memory::VirtualMemory> {
        ctx_with_tlb(mem, table, pages, tlb, 0)
    }

    /// The store helper probes the page-hash table for the access's **last**
    /// byte only when the access really spans two pages (roadmap W8.6). Within a
    /// page the two probes are the same probe, so skipping the second is free;
    /// across one it is not, and this is the case that would go silently
    /// unnoticed if the test were dropped. Reported the same either way.
    #[test]
    fn a_store_straddling_into_a_code_page_is_still_reported() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        // Only the *second* page is one a compiled block was built from.
        let mut tlb = empty_tlb();
        let mut ctx = ctx_over(&mut mem, &mut table, &[0x9000], &mut tlb);
        // A 4-byte store whose first byte is on 0x8000 and whose last is on
        // 0x9000. The first probe misses; only the second can catch it.
        // SAFETY: `ctx` is a live, exclusively borrowed context, which is
        // exactly what the helper's contract asks for.
        let st = unsafe { jit_write(&mut ctx as *mut _, 0x8ffe, 4, 0x1122_3344) };
        assert_eq!(st, status::OK, "not the running block's own code");
        assert_eq!(ctx.smc_hits, 1, "the straddling store must be reported");
        assert_eq!(ctx.smc, 0x8ffe);
        assert_eq!(ctx.link_epoch, LINK_EPOCH_DEAD, "the chain's links must die");
        // ...and the store itself happened, unchanged.
        assert_eq!(mem.read_u32(0x8ffe).unwrap(), 0x1122_3344);
    }

    #[test]
    fn a_store_inside_a_page_no_block_was_built_from_is_not_reported() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        let mut tlb = empty_tlb();
        let mut ctx = ctx_over(&mut mem, &mut table, &[0x9000], &mut tlb);
        // Wholly inside 0x8000, including the 8-byte store that ends on the
        // page's last byte — the boundary the offset test is written against.
        for (addr, size) in [(0x8000u64, 8u32), (0x8ff8, 8), (0x8fff, 1)] {
            // SAFETY: as above.
            let st = unsafe { jit_write(&mut ctx as *mut _, addr, size, 0) };
            assert_eq!(st, status::OK, "{addr:#x}");
        }
        assert_eq!(ctx.smc_hits, 0);
        assert_eq!(ctx.link_epoch, 7, "the links must stay live");
    }

    // ---- the guest-memory TLB's fill side (roadmap W8.6) ------------------
    //
    // Compiled code only ever *reads* the table, and reading it is a tag compare
    // it cannot get wrong. Everything that could be wrong is here, in what the
    // helpers put into it — so these are the tests that matter.

    /// The entry a hit uses: the right slot, the right tag, and a base that
    /// turns a guest address into the host address of that guest byte.
    #[test]
    fn a_successful_read_caches_its_page() {
        use exemu_core::{Memory as _, Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        mem.write_u64(0x9100, 0x0123_4567_89ab_cdef).unwrap();
        let host = mem.host_span(0x9100, 8, Perm::READ).unwrap().as_ptr() as u64;

        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: `ctx` is a live, exclusively borrowed context.
        let r = unsafe { jit_read(&mut ctx as *mut _, 0x9100, 8) };
        assert_eq!(r.status, status::OK);
        assert_eq!(r.value, 0x0123_4567_89ab_cdef);
        assert_eq!(ctx.tlb_fills, 1);
        assert_eq!(ctx.tlb_denied, 0);

        let e = slot_of(&ctx, 0x9100);
        assert_eq!(e.read_tag, tlb_tag(0x9100), "tagged with its own page");
        assert_eq!(e.read_base.wrapping_add(0x9100), host, "base + addr is the host byte");
        assert_eq!(e.write_tag, TLB_EMPTY, "a read must not fill the write half");
    }

    /// `tlb_on = 0` is the engine saying "do not bother", and nothing may appear.
    #[test]
    fn nothing_is_cached_while_the_table_is_switched_off() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 0);
        // SAFETY: as above.
        unsafe {
            jit_read(&mut ctx as *mut _, 0x9100, 8);
            jit_write(&mut ctx as *mut _, 0x9100, 8, 1);
        }
        assert_eq!(ctx.tlb_fills, 0);
        assert!(all_empty(&ctx));
    }

    /// **The self-modifying-code guarantee.** PE sections are mapped RWX, so a
    /// store into an image must stay on the helper, where the code-page hash and
    /// the running block's own range are tested. Reads of the same page are
    /// fine — a read changes nothing.
    #[test]
    fn a_store_into_executable_memory_is_never_cached() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("image", 0x40_0000, 0x3000, Perm::RWX)).unwrap();
        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: as above.
        let st = unsafe { jit_write(&mut ctx as *mut _, 0x40_1000, 4, 0x9090_9090) };
        assert_eq!(st, status::OK);
        assert_eq!(ctx.tlb_denied, 1, "the backend refused, and it was asked once");
        assert_eq!(slot_of(&ctx, 0x40_1000).write_tag, TLB_EMPTY);
        // ...and the store did reach the SMC seam it would have bypassed.
        assert_eq!(ctx.mem.code_generation(), 1);
        // A read of the same page caches normally.
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0x40_1000, 4) };
        assert_eq!(slot_of(&ctx, 0x40_1000).read_tag, tlb_tag(0x40_1000));
    }

    /// **The watchpoint guarantee.** Nothing is cached while one is armed, so
    /// every access keeps going through the backend that reports it.
    #[test]
    fn nothing_is_cached_while_a_watchpoint_is_armed() {
        use exemu_core::debug::{DebugControl, WatchKind};
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        let d = DebugControl::attached();
        mem.set_debug(d.clone());
        // Armed on a completely different address: the refusal is global,
        // because an entry makes *every* access to its page unobservable.
        d.arm_watch(0x8f00, 4, WatchKind::Write);

        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: as above.
        unsafe {
            jit_read(&mut ctx as *mut _, 0x9100, 8);
            jit_write(&mut ctx as *mut _, 0x9100, 8, 1);
        }
        assert_eq!(ctx.tlb_fills, 0);
        assert!(all_empty(&ctx));
        // The access that was armed for was seen.
        // SAFETY: as above.
        unsafe { jit_write(&mut ctx as *mut _, 0x8f00, 4, 7) };
        assert!(d.take_watch_hit().is_some(), "the watchpoint must still fire");
    }

    /// A page whose region ends inside the span an entry has to cover is left
    /// alone, which is what lets the emitted probe be a single tag compare with
    /// no end-of-access check: an 8-byte load at the page's last byte reaches
    /// seven bytes past it, and those bytes have to be in the same region.
    #[test]
    fn a_page_at_the_tail_of_its_region_is_not_cached() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        // Exactly one page: the last byte's 8-byte access would leave it.
        mem.map(Region::new("tight", 0x8000, 0x1000, Perm::RW)).unwrap();
        // One page plus the slack: cacheable.
        mem.map(Region::new("loose", 0xa000, 0x1000 + 8, Perm::RW)).unwrap();
        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0x8010, 4) };
        assert_eq!(slot_of(&ctx, 0x8010).read_tag, TLB_EMPTY, "tight region");
        assert_eq!(ctx.tlb_denied, 1);
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0xa010, 4) };
        assert_eq!(slot_of(&ctx, 0xa010).read_tag, tlb_tag(0xa010), "loose region");

        // The property that buys: every access of every width, anywhere on a
        // cached page, lands inside the span the entry was filled from.
        let e = slot_of(&ctx, 0xa010);
        let span = ctx.mem.host_span(0xa000, TLB_SPAN, Perm::READ).unwrap();
        let lo = span.as_ptr() as u64;
        for off in [0u64, 1, 0xffe, 0xfff] {
            for width in [1u64, 2, 4, 8] {
                let host = e.read_base.wrapping_add(0xa000 + off);
                assert!(host >= lo, "{off:#x}/{width} before the span");
                assert!(host + width <= lo + TLB_SPAN as u64, "{off:#x}/{width} past the span");
            }
        }
    }

    /// A tag is a guest address shifted right by the page bits, so it can never
    /// be the empty marker — which is what stops a *zeroed* table from claiming
    /// to cache guest page 0. The differential's edge layout maps page 0.
    #[test]
    fn no_real_tag_can_collide_with_the_empty_marker() {
        for addr in [0u64, 1, 0xfff, 0x1000, u64::MAX, u64::MAX - 1] {
            assert_ne!(tlb_tag(addr), TLB_EMPTY, "{addr:#x}");
            assert!(tlb_slot(addr) < TLB_SLOTS);
        }
        assert_eq!(TlbEntry::EMPTY.read_tag, TLB_EMPTY);
        assert_eq!(TlbEntry::EMPTY.write_tag, TLB_EMPTY);
        assert_ne!(TlbEntry::EMPTY, TlbEntry { read_tag: 0, ..TlbEntry::EMPTY });
        // The emitter folds the entry size into a shift.
        assert_eq!(tlb_off::SIZE, 32);
        assert_eq!(tlb_off::READ, 0);
        assert_eq!(tlb_off::WRITE, 16);
        assert_eq!(1usize << TLB_SLOT_BITS, TLB_SLOTS);
    }

    #[test]
    fn parity_table_matches_the_interpreters_definition() {
        for (i, p) in PARITY.iter().enumerate() {
            assert_eq!(*p == 1, (i as u8).count_ones() % 2 == 0, "byte {i}");
        }
    }

    #[test]
    fn ctx_offsets_are_what_the_emitter_assumes() {
        // The emitter reaches these with 8-byte-scaled `ldr`/`str`s, so they must
        // be 8-aligned and inside the 12-bit scaled immediate.
        for off in [
            ctx_off::PARITY,
            ctx_off::READ,
            ctx_off::WRITE,
            ctx_off::RETIRED,
            ctx_off::BUDGET,
            ctx_off::LINKS,
            ctx_off::LINK_EPOCH,
            ctx_off::PENDING,
            ctx_off::TRAIL,
            ctx_off::TRAIL_AT,
        ] {
            assert_eq!(off % 8, 0, "offset {off} is not 8-aligned");
            assert!(off < 4096 * 8, "offset {off} is past the scaled immediate");
            assert!((off as usize) < std::mem::size_of::<BlockCtx<'static, dyn Memory>>());
        }
    }

    /// The emitter's offsets are compile-time constants taken against one
    /// instantiation, but a block runs with whatever backend the caller passed
    /// (roadmap W8.6). `mem` is last precisely so that cannot matter: a thin
    /// `&mut VirtualMemory` and a fat `&mut dyn Memory` must put every field the
    /// emitter addresses in the same place.
    #[test]
    fn ctx_offsets_do_not_depend_on_the_memory_type() {
        macro_rules! offs {
            ($t:ty) => {
                [
                    std::mem::offset_of!(BlockCtx<'static, $t>, parity),
                    std::mem::offset_of!(BlockCtx<'static, $t>, code_lo),
                    std::mem::offset_of!(BlockCtx<'static, $t>, code_hi),
                    std::mem::offset_of!(BlockCtx<'static, $t>, read),
                    std::mem::offset_of!(BlockCtx<'static, $t>, write),
                    std::mem::offset_of!(BlockCtx<'static, $t>, retired),
                    std::mem::offset_of!(BlockCtx<'static, $t>, budget),
                    std::mem::offset_of!(BlockCtx<'static, $t>, links),
                    std::mem::offset_of!(BlockCtx<'static, $t>, link_epoch),
                    std::mem::offset_of!(BlockCtx<'static, $t>, pending),
                    std::mem::offset_of!(BlockCtx<'static, $t>, trail),
                    std::mem::offset_of!(BlockCtx<'static, $t>, trail_at),
                    std::mem::offset_of!(BlockCtx<'static, $t>, smc),
                    std::mem::offset_of!(BlockCtx<'static, $t>, smc_hits),
                    std::mem::offset_of!(BlockCtx<'static, $t>, code_pages),
                ]
            };
        }
        // A stand-in for any concrete backend: what matters is that it is
        // `Sized`, so `&mut M` is a thin pointer where `&mut dyn Memory` is fat.
        struct Thin;
        impl Memory for Thin {
            fn read(&self, _: u64, _: &mut [u8]) -> exemu_core::Result<()> {
                unreachable!()
            }
            fn write(&mut self, _: u64, _: &[u8]) -> exemu_core::Result<()> {
                unreachable!()
            }
        }
        assert_eq!(offs!(Thin), offs!(dyn Memory));
        assert_eq!(offs!(Thin)[0], 0, "the emitter's first field must be at 0");
    }

    #[test]
    fn every_code_page_bit_is_inside_the_table() {
        // The hash is shifted down to exactly `CODE_PAGE_BITS`, which is what
        // makes the unchecked load in `code_page_hit` sound.
        for page in [0u64, 1, 0x1000, 0x7fff_ffff_f000, u64::MAX, 0x1_0000_0000] {
            let bit = code_page_bit(page);
            assert!(bit < (1 << CODE_PAGE_BITS), "{page:#x} hashed out of range");
            assert!((bit >> 6) < CODE_PAGE_WORDS as u64);
        }
    }

    #[test]
    fn the_page_hash_puts_one_page_in_exactly_one_bit() {
        // Same page in, same bit out — and addresses inside one page all agree,
        // which is what lets the store helper test only the first and last byte.
        let base = 0x1_4000_1000u64;
        let bit = code_page_bit(base);
        for off in [0u64, 1, 0x800, 0xfff] {
            assert_eq!(code_page_bit(base + off), bit);
        }
        assert_ne!(code_page_bit(base + 0x1000), bit, "the next page shares a bit");
    }
}
