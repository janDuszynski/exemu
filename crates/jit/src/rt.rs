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

use exemu_core::Memory;

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

/// Everything a compiled block needs that is not the register file.
///
/// The emitted code loads and stores this struct at fixed offsets ([`ctx_off`])
/// and passes its address to the helpers; it never interprets the `mem` field,
/// which is why that field can stay an ordinary Rust trait object.
#[repr(C)]
pub struct BlockCtx<'a> {
    /// Guest memory. Only the helpers below dereference it.
    pub mem: &'a mut dyn Memory,
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
    pub read: unsafe extern "C" fn(*mut BlockCtx<'_>, u64, u32) -> ReadResult,
    /// Address of [`jit_write`].
    pub write: unsafe extern "C" fn(*mut BlockCtx<'_>, u64, u32, u64) -> u64,
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
}

impl BlockCtx<'_> {
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
pub mod ctx_off {
    use super::BlockCtx;
    pub const PARITY: u32 = std::mem::offset_of!(BlockCtx<'static>, parity) as u32;
    pub const CODE_LO: u32 = std::mem::offset_of!(BlockCtx<'static>, code_lo) as u32;
    pub const READ: u32 = std::mem::offset_of!(BlockCtx<'static>, read) as u32;
    pub const WRITE: u32 = std::mem::offset_of!(BlockCtx<'static>, write) as u32;
    pub const RETIRED: u32 = std::mem::offset_of!(BlockCtx<'static>, retired) as u32;
    pub const BUDGET: u32 = std::mem::offset_of!(BlockCtx<'static>, budget) as u32;
    pub const LINKS: u32 = std::mem::offset_of!(BlockCtx<'static>, links) as u32;
    pub const LINK_EPOCH: u32 = std::mem::offset_of!(BlockCtx<'static>, link_epoch) as u32;
    pub const PENDING: u32 = std::mem::offset_of!(BlockCtx<'static>, pending) as u32;
    pub const TRAIL: u32 = std::mem::offset_of!(BlockCtx<'static>, trail) as u32;
    pub const TRAIL_AT: u32 = std::mem::offset_of!(BlockCtx<'static>, trail_at) as u32;
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
pub unsafe extern "C" fn jit_read(ctx: *mut BlockCtx<'_>, addr: u64, size: u32) -> ReadResult {
    // SAFETY: the engine builds the `BlockCtx` on its own stack, hands the block
    // a raw pointer to it, and holds no reference to it while the block runs —
    // so this is the only live borrow for the duration of the call.
    let ctx = unsafe { &mut *ctx };
    match ctx.mem.read_uint(addr, size as u8) {
        Ok(value) => ReadResult { value, status: status::OK },
        Err(_) => ReadResult { value: 0, status: status::FAULT },
    }
}

/// Guest store. Returns a [`status`] word.
///
/// # Safety
/// As [`jit_read`].
pub unsafe extern "C" fn jit_write(ctx: *mut BlockCtx<'_>, addr: u64, size: u32, value: u64) -> u64 {
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
    let page = ctx.code_page_hit(addr)
        || (size > 1 && ctx.code_page_hit(addr.wrapping_add(size as u64 - 1)));
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
            assert!((off as usize) < std::mem::size_of::<BlockCtx<'static>>());
        }
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
