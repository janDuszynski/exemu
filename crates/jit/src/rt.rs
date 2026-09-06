use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::{Memory, Perm};

pub const TRAIL: usize = 32;

pub const CODE_PAGE_BITS: u32 = 17;

pub const CODE_PAGE_WORDS: usize = 1 << (CODE_PAGE_BITS - 6);

pub const NO_SLOT: u64 = u64::MAX;

pub const NO_SMC: u64 = u64::MAX;

pub const LINK_EPOCH_DEAD: u64 = u64::MAX;

#[inline]
pub fn code_page_bit(addr: u64) -> u64 {
    (addr / exemu_core::CODE_PAGE_SIZE).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - CODE_PAGE_BITS)
}

pub mod status {
    pub const OK: u64 = 0;
    pub const FAULT: u64 = 1;
    pub const WROTE_CODE: u64 = 2;
}

#[repr(C)]
pub struct ReadResult {
    pub value: u64,
    pub status: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkSlot {
    pub epoch: u64,
    pub key: u64,
    pub code: u64,
}

pub const TLB_SLOTS: usize = 512;

pub const TLB_SLOT_BITS: u32 = 9;

pub const TLB_PAGE_BITS: u32 = 12;

pub const TLB_SPAN: usize = 1 << TLB_PAGE_BITS;

pub const TLB_EMPTY: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlbEntry {
    pub read_tag: u64,
    pub read_base: u64,
    pub write_tag: u64,
    pub write_base: u64,
}

impl TlbEntry {
    pub const EMPTY: TlbEntry =
        TlbEntry { read_tag: TLB_EMPTY, read_base: 0, write_tag: TLB_EMPTY, write_base: 0 };
}

impl Default for TlbEntry {
    fn default() -> Self {
        TlbEntry::EMPTY
    }
}

pub mod tlb_off {
    use super::TlbEntry;
    pub const READ: u32 = std::mem::offset_of!(TlbEntry, read_tag) as u32;
    pub const WRITE: u32 = std::mem::offset_of!(TlbEntry, write_tag) as u32;
    pub const SIZE: u32 = std::mem::size_of::<TlbEntry>() as u32;
}

#[inline]
pub fn tlb_tag(addr: u64) -> u64 {
    addr >> TLB_PAGE_BITS
}

#[inline]
pub fn tlb_slot(addr: u64) -> usize {
    (tlb_tag(addr) as usize) & (TLB_SLOTS - 1)
}

#[inline]
fn tlb_page_base(addr: u64) -> u64 {
    addr & !((1u64 << TLB_PAGE_BITS) - 1)
}

pub type ReadFn<M> = unsafe extern "C" fn(*mut BlockCtx<'_, M>, u64, u32) -> ReadResult;

pub type WriteFn<M> = unsafe extern "C" fn(*mut BlockCtx<'_, M>, u64, u32, u64) -> u64;

#[repr(C)]
pub struct BlockCtx<'a, M: Memory + ?Sized> {
    pub parity: *const u8,
    pub code_lo: u64,
    pub code_hi: u64,
    pub read: ReadFn<M>,
    pub write: WriteFn<M>,
    pub retired: u64,
    pub budget: u64,
    pub links: *const LinkSlot,
    pub link_epoch: u64,
    pub pending: u64,
    pub trail: *mut u64,
    pub trail_at: u64,
    pub smc: u64,
    pub smc_hits: u64,
    pub code_pages: *const u64,
    pub tlb: *mut TlbEntry,
    pub tlb_on: u64,
    pub tlb_fills: u64,
    pub tlb_denied: u64,
    pub watch_stops: u64,
    pub debug: Option<&'a DebugControl>,
    pub mem: &'a mut M,
}

impl<M: Memory + ?Sized> BlockCtx<'_, M> {
    fn tlb_has(&self, addr: u64, half: u32) -> bool {
        // SAFETY: `tlb` is the engine's array, `TLB_SLOTS` entries long and
        let tag = unsafe {
            let e = self.tlb.add(tlb_slot(addr));
            if half == tlb_off::READ { (*e).read_tag } else { (*e).write_tag }
        };
        tag == tlb_tag(addr)
    }

    #[cold]
    #[inline(never)]
    fn tlb_fill_read(&mut self, addr: u64) {
        if self.tlb_has(addr, tlb_off::READ) {
            return;
        }
        let page = tlb_page_base(addr);
        let Some(span) = self.mem.host_span(page, TLB_SPAN, Perm::READ) else {
            self.tlb_denied += 1;
            return;
        };
        let base = (span.as_ptr() as u64).wrapping_sub(page);
        self.tlb_fills += 1;
        // SAFETY: `tlb` is the engine's array, `TLB_SLOTS` entries long and
        unsafe {
            let e = self.tlb.add(tlb_slot(addr));
            (*e).read_base = base;
            (*e).read_tag = tlb_tag(addr);
        }
    }

    #[cold]
    #[inline(never)]
    fn tlb_fill_write(&mut self, addr: u64) {
        if self.tlb_has(addr, tlb_off::WRITE) {
            return;
        }
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

    #[inline]
    pub fn code_page_hit(&self, addr: u64) -> bool {
        let bit = code_page_bit(addr);
        // SAFETY: `code_pages` is the engine's table, which is
        let word = unsafe { *self.code_pages.add((bit >> 6) as usize) };
        word & (1u64 << (bit & 63)) != 0
    }
}

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

pub static PARITY: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = ((i as u8).count_ones() % 2 == 0) as u8;
        i += 1;
    }
    t
};

/// # Safety
/// `ctx` must be a live `BlockCtx` from the engine.
pub unsafe extern "C" fn jit_read<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
) -> ReadResult {
    // SAFETY: the engine builds the `BlockCtx` on its own stack, hands the block
    let ctx = unsafe { &mut *ctx };
    match ctx.mem.read_uint(addr, size as u8) {
        Ok(value) => {
            if ctx.tlb_on != 0 {
                ctx.tlb_fill_read(addr);
            }
            ReadResult { value, status: status::OK }
        }
        Err(_) => ReadResult { value: 0, status: status::FAULT },
    }
}

/// # Safety
/// `ctx` must be a live `BlockCtx` from the engine.
pub unsafe extern "C" fn jit_read_watched<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
) -> ReadResult {
    // SAFETY: as `jit_read` — and this reads two `Copy` fields before handing
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

/// # Safety
/// `ctx` must be a live `BlockCtx` from the engine.
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

/// # Safety
/// `ctx` must be a live `BlockCtx` from the engine.
pub unsafe extern "C" fn jit_write<M: Memory + ?Sized>(
    ctx: *mut BlockCtx<'_, M>,
    addr: u64,
    size: u32,
    value: u64,
) -> u64 {
    // SAFETY: see `jit_read`.
    let ctx = unsafe { &mut *ctx };
    let own = addr < ctx.code_hi && addr.saturating_add(size as u64) > ctx.code_lo;
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

    fn empty_tlb() -> Vec<TlbEntry> {
        vec![TlbEntry::EMPTY; TLB_SLOTS]
    }

    fn slot_of<M: Memory + ?Sized>(ctx: &BlockCtx<'_, M>, addr: u64) -> TlbEntry {
        // SAFETY: `ctx.tlb` is the array the caller handed over, `TLB_SLOTS`
        unsafe { *ctx.tlb.add(tlb_slot(addr)) }
    }

    fn all_empty<M: Memory + ?Sized>(ctx: &BlockCtx<'_, M>) -> bool {
        // SAFETY: as `slot_of`.
        (0..TLB_SLOTS).all(|i| unsafe { *ctx.tlb.add(i) } == TlbEntry::EMPTY)
    }

    fn ctx_over<'a>(
        mem: &'a mut exemu_memory::VirtualMemory,
        table: &'a mut [u64],
        pages: &[u64],
        tlb: &'a mut [TlbEntry],
    ) -> BlockCtx<'a, exemu_memory::VirtualMemory> {
        ctx_with_tlb(mem, table, pages, tlb, 0)
    }

    #[test]
    fn a_store_straddling_into_a_code_page_is_still_reported() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        let mut tlb = empty_tlb();
        let mut ctx = ctx_over(&mut mem, &mut table, &[0x9000], &mut tlb);
        // SAFETY: `ctx` is a live, exclusively borrowed context, which is
        let st = unsafe { jit_write(&mut ctx as *mut _, 0x8ffe, 4, 0x1122_3344) };
        assert_eq!(st, status::OK, "not the running block's own code");
        assert_eq!(ctx.smc_hits, 1, "the straddling store must be reported");
        assert_eq!(ctx.smc, 0x8ffe);
        assert_eq!(ctx.link_epoch, LINK_EPOCH_DEAD, "the chain's links must die");
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
        for (addr, size) in [(0x8000u64, 8u32), (0x8ff8, 8), (0x8fff, 1)] {
            // SAFETY: as above.
            let st = unsafe { jit_write(&mut ctx as *mut _, addr, size, 0) };
            assert_eq!(st, status::OK, "{addr:#x}");
        }
        assert_eq!(ctx.smc_hits, 0);
        assert_eq!(ctx.link_epoch, 7, "the links must stay live");
    }

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
        assert_eq!(ctx.mem.code_generation(), 1);
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0x40_1000, 4) };
        assert_eq!(slot_of(&ctx, 0x40_1000).read_tag, tlb_tag(0x40_1000));
    }

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
        d.arm_watch(0x8f00, 4, WatchKind::Write);

        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: as above.
        unsafe {
            jit_read(&mut ctx as *mut _, 0x9100, 8);
            jit_write(&mut ctx as *mut _, 0x9100, 8, 1);
        }
        assert_eq!(ctx.tlb_fills, 0);
        assert!(all_empty(&ctx));
        // SAFETY: as above.
        unsafe { jit_write(&mut ctx as *mut _, 0x8f00, 4, 7) };
        assert!(d.take_watch_hit().is_some(), "the watchpoint must still fire");
    }

    #[test]
    fn the_last_page_of_a_region_is_cached_when_the_region_ends_on_a_page() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("tight", 0x8000, 0x1000, Perm::RW)).unwrap();
        mem.map(Region::new("ragged", 0xa000, 0x1010, Perm::RW)).unwrap();
        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0x8010, 4) };
        assert_eq!(slot_of(&ctx, 0x8010).read_tag, tlb_tag(0x8010), "one-page region");
        assert_eq!(ctx.tlb_denied, 0);
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0xa010, 4) };
        assert_eq!(slot_of(&ctx, 0xa010).read_tag, tlb_tag(0xa010), "its full first page");
        // SAFETY: as above.
        unsafe { jit_read(&mut ctx as *mut _, 0xb008, 4) };
        assert_eq!(slot_of(&ctx, 0xb008).read_tag, TLB_EMPTY, "its ragged last page");
        assert_eq!(ctx.tlb_denied, 1);

        let e = slot_of(&ctx, 0x8010);
        let span = ctx.mem.host_span(0x8000, TLB_SPAN, Perm::READ).unwrap();
        let lo = span.as_ptr() as u64;
        for off in [0u64, 1, 0xff8, 0xffe, 0xfff] {
            for width in [1u64, 2, 4, 8] {
                if off + width > TLB_SPAN as u64 {
                    continue;
                }
                let host = e.read_base.wrapping_add(0x8000 + off);
                assert!(host >= lo, "{off:#x}/{width} before the span");
                assert!(host + width <= lo + TLB_SPAN as u64, "{off:#x}/{width} past the span");
            }
        }
    }

    #[test]
    fn a_straddling_access_does_not_refill_the_entry_it_cannot_use() {
        use exemu_core::{Perm, Region};
        let mut table = vec![0u64; CODE_PAGE_WORDS];
        let mut tlb = empty_tlb();
        let mut mem = exemu_memory::VirtualMemory::new();
        mem.map(Region::new("data", 0x8000, 0x3000, Perm::RW)).unwrap();
        let mut ctx = ctx_with_tlb(&mut mem, &mut table, &[], &mut tlb, 1);
        for _ in 0..4 {
            // SAFETY: as above.
            unsafe { jit_read(&mut ctx as *mut _, 0x8ffe, 8) };
        }
        assert_eq!(ctx.tlb_fills, 1, "one fill for the page it starts on, then nothing");
        assert_eq!(ctx.tlb_denied, 0);
        assert_eq!(slot_of(&ctx, 0x8ffe).read_tag, tlb_tag(0x8ffe));
    }

    #[test]
    fn no_real_tag_can_collide_with_the_empty_marker() {
        for addr in [0u64, 1, 0xfff, 0x1000, u64::MAX, u64::MAX - 1] {
            assert_ne!(tlb_tag(addr), TLB_EMPTY, "{addr:#x}");
            assert!(tlb_slot(addr) < TLB_SLOTS);
        }
        assert_eq!(TlbEntry::EMPTY.read_tag, TLB_EMPTY);
        assert_eq!(TlbEntry::EMPTY.write_tag, TLB_EMPTY);
        assert_ne!(TlbEntry::EMPTY, TlbEntry { read_tag: 0, ..TlbEntry::EMPTY });
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
        for page in [0u64, 1, 0x1000, 0x7fff_ffff_f000, u64::MAX, 0x1_0000_0000] {
            let bit = code_page_bit(page);
            assert!(bit < (1 << CODE_PAGE_BITS), "{page:#x} hashed out of range");
            assert!((bit >> 6) < CODE_PAGE_WORDS as u64);
        }
    }

    #[test]
    fn the_page_hash_puts_one_page_in_exactly_one_bit() {
        let base = 0x1_4000_1000u64;
        let bit = code_page_bit(base);
        for off in [0u64, 1, 0x800, 0xfff] {
            assert_eq!(code_page_bit(base + off), bit);
        }
        assert_ne!(code_page_bit(base + 0x1000), bit, "the next page shares a bit");
    }
}
