//! Host spans and the layout generation — the seam a JIT keeps a cache of host
//! addresses on (roadmap W8.6).
//!
//! Everything here is about one question: **when is it a use-after-free?** A
//! caller resolves a span once and then reads and writes those bytes directly,
//! hundreds of millions of times, without asking again — so the only things
//! standing between that and a wild pointer are
//!
//! * `layout_generation` moving for every mutation that can move or free the
//!   bytes, or change the permission under them; and
//! * `host_span` refusing, up front, every case where a direct access would not
//!   be equivalent to the same access made the ordinary way — a fault, an armed
//!   watchpoint, or a write into executable memory.
//!
//! The tests are written as an enumeration of `VirtualMemory`'s mutators rather
//! than as a sample of them, because "we covered every site" is the actual
//! claim.

use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::{Memory, Perm, Region};
use exemu_memory::VirtualMemory;

const PAGE: u64 = 0x1000;

fn mem() -> VirtualMemory {
    let mut m = VirtualMemory::new();
    m.map(Region::new("data", 0x1000, 0x4000, Perm::RW)).unwrap();
    m.map(Region::new("image", 0x40_0000, 0x4000, Perm::RWX)).unwrap();
    m.map(Region::new("ro", 0x50_0000, 0x1000, Perm::READ)).unwrap();
    m
}

/// The host address of the first byte of a span, as a caller would keep it.
fn span_ptr(m: &VirtualMemory, addr: u64) -> Option<usize> {
    m.host_span(addr, 8, Perm::READ).map(|s| s.as_ptr() as usize)
}

// ---------------------------------------------------------------------------
// The generation: every mutation that can invalidate a span, and no others.
// ---------------------------------------------------------------------------

/// `VirtualMemory`'s complete set of `&mut self` entry points, split into the
/// ones that can invalidate a span and the ones that cannot. If a new mutator
/// is added and this test is not updated, it is the one that should fail.
#[test]
fn layout_generation_moves_for_every_mutation_that_can_invalidate_a_span() {
    // --- moves it -----------------------------------------------------
    // `map`, `map_with_data` and `map_fixed` all funnel through `insert`,
    // which may reallocate the region vector and shifts every `Mapped` above
    // the insertion point.
    let mut m = VirtualMemory::new();
    let g0 = m.layout_generation();
    m.map(Region::new("a", 0x1000, PAGE, Perm::RW)).unwrap();
    let g1 = m.layout_generation();
    assert_ne!(g1, g0, "map");

    m.map_with_data("b", 0x2000, PAGE, &[1, 2, 3], Perm::RW).unwrap();
    let g2 = m.layout_generation();
    assert_ne!(g2, g1, "map_with_data");

    m.map_fixed(0x3000, PAGE, Perm::RW, "c").unwrap();
    let g3 = m.layout_generation();
    assert_ne!(g3, g2, "map_fixed");

    // `protect` leaves the bytes where they are but changes what may be done
    // with them — a writable span handed out under the old permission, or
    // withheld under it, must not survive.
    m.protect(0x1000, PAGE, Perm::RX).unwrap();
    let g4 = m.layout_generation();
    assert_ne!(g4, g3, "protect");

    // `unmap` frees the buffer outright: the one mutation where a missed bump
    // is a dangling pointer rather than a stale permission.
    m.unmap(0x3000, 0).unwrap();
    let g5 = m.layout_generation();
    assert_ne!(g5, g4, "unmap (MEM_RELEASE)");

    m.unmap(0x2000, PAGE).unwrap();
    let g6 = m.layout_generation();
    assert_ne!(g6, g5, "unmap (range)");

    // --- does not move it ---------------------------------------------
    // Everything else `VirtualMemory` exposes writes *into* an existing buffer
    // or touches state a span does not depend on. None of these may cost a
    // cache flush.
    let mut m = mem();
    let g = m.layout_generation();
    m.write_u64(0x1100, 0xdead_beef).unwrap();
    m.write_uint(0x1108, 4, 0x1234).unwrap();
    m.write(0x1110, &[1, 2, 3, 4]).unwrap();
    m.poke(0x40_0000, &[0x90; 8]).unwrap(); // into executable memory
    m.poke(0x1200, &[0x11]).unwrap();
    m.read_u64(0x1100).unwrap();
    m.read_uint(0x1108, 4).unwrap();
    let mut buf = [0u8; 4];
    m.fetch(0x40_0000, &mut buf).unwrap();
    m.set_debug(DebugControl::detached());
    // A failed mutation changes nothing either.
    assert!(m.map(Region::new("dup", 0x1000, PAGE, Perm::RW)).is_err());
    assert!(m.protect(0x9999_0000, PAGE, Perm::RW).is_err());
    assert_eq!(m.layout_generation(), g, "a non-structural operation moved it");
}

/// The property the generation is a proxy for, stated directly: while it does
/// not move, the host address of a region's bytes does not move either — no
/// matter how much is written through the ordinary path. This is what makes it
/// sound to resolve a span once and keep using it.
#[test]
fn a_host_pointer_is_stable_while_the_generation_is() {
    let mut m = mem();
    let g = m.layout_generation();
    let p = span_ptr(&m, 0x1100).expect("mapped and readable");

    for i in 0..64u64 {
        m.write_u64(0x1100 + i * 8, i).unwrap();
        m.write_uint(0x2000 + i, 1, i).unwrap();
        m.poke(0x40_0000 + i, &[0xcc]).unwrap();
    }
    assert_eq!(m.layout_generation(), g, "writes moved the generation");
    assert_eq!(span_ptr(&m, 0x1100), Some(p), "the bytes moved under a live span");
    // ...and the span still sees what the ordinary path wrote.
    assert_eq!(m.host_span(0x1100, 8, Perm::READ).unwrap(), 0u64.to_le_bytes());
}

/// The region vector really does reallocate, and every reallocation is caught.
/// Mapping regions one at a time past `Vec`'s growth points is the closest this
/// backend has to "growing a region", and it is the case where a cached
/// `Mapped` *reference* would dangle.
#[test]
fn every_region_vector_reallocation_moves_the_generation() {
    let mut m = VirtualMemory::new();
    let mut seen = m.layout_generation();
    let mut ptrs = Vec::new();
    for i in 0..64u64 {
        let base = 0x10_0000 + i * PAGE * 2;
        m.map(Region::new(format!("r{i}"), base, PAGE, Perm::RW)).unwrap();
        let g = m.layout_generation();
        assert_ne!(g, seen, "mapping region {i} did not move the generation");
        seen = g;
        ptrs.push((base, span_ptr(&m, base).unwrap()));
    }
    // The backing buffers themselves never moved — only the vector of headers
    // did — so re-resolving after all that growth gives the same addresses.
    // (Which is *why* the generation, not the pointer, is the invalidation
    // signal: a caller cannot tell these two apart from outside.)
    for (base, p) in ptrs {
        assert_eq!(span_ptr(&m, base), Some(p), "region at {base:#x} moved");
    }
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

/// Anything that would fault is refused, so a fast path built on spans cannot
/// serve an access the ordinary path would have refused — and therefore cannot
/// move where a fault happens.
#[test]
fn a_span_is_refused_for_everything_that_would_fault() {
    let mut m = mem();
    // Unmapped.
    assert!(m.host_span(0x9999_0000, 8, Perm::READ).is_none());
    assert!(m.host_span_mut(0x9999_0000, 8, Perm::WRITE).is_none());
    // Off the end of a region — the whole range must be inside one region.
    assert!(m.host_span(0x1000 + 0x4000 - 4, 8, Perm::READ).is_none());
    assert!(m.host_span(0x1000, 0x4001, Perm::READ).is_none());
    // Spanning two adjacent-but-separate regions is still two regions.
    let mut split = VirtualMemory::new();
    split.map(Region::new("lo", 0x1000, PAGE, Perm::RW)).unwrap();
    split.map(Region::new("hi", 0x2000, PAGE, Perm::RW)).unwrap();
    assert!(split.host_span(0x1ffc, 8, Perm::READ).is_none());
    // Permission.
    assert!(m.host_span_mut(0x50_0000, 8, Perm::WRITE).is_none(), "read-only");
    assert!(m.host_span(0x50_0000, 8, Perm::READ).is_some(), "read-only is readable");
    // Degenerate length.
    assert!(m.host_span(0x1000, 0, Perm::READ).is_none());
    // The exact fit is allowed — the boundary the refusals are written against.
    assert!(m.host_span(0x1000, 0x4000, Perm::READ).is_some());
}

/// **No writable span over executable memory.** A write through one could not
/// reach `note_code_write`, so a guest rewriting its own code through it would
/// be invisible to a JIT's invalidation. Reads are fine — they change nothing.
#[test]
fn no_writable_span_for_executable_memory() {
    let mut m = mem();
    assert!(m.host_span(0x40_0000, 8, Perm::READ).is_some(), "RWX is readable");
    assert!(m.host_span_mut(0x40_0000, 8, Perm::WRITE).is_none(), "RWX is not span-writable");
    // ...and the ordinary write path still works there, still bumping the seam.
    let before = m.code_generation();
    m.write_u32(0x40_0000, 0x9090_9090).unwrap();
    assert_eq!(m.code_generation(), before + 1);

    // The refusal tracks `protect`, not the permission the region was born with.
    m.protect(0x1000, PAGE * 4, Perm::RWX).unwrap();
    assert!(m.host_span_mut(0x1100, 8, Perm::WRITE).is_none(), "now executable");
    m.protect(0x1000, PAGE * 4, Perm::RW).unwrap();
    assert!(m.host_span_mut(0x1100, 8, Perm::WRITE).is_some(), "executable again removed");
}

/// **No spans at all while a watchpoint is armed.** An armed watchpoint has to
/// see every guest access, and an access served from a span reports nothing —
/// so the refusal is expressed here, in the backend that owns the reporting,
/// rather than as a rule a caller has to remember.
#[test]
fn no_span_at_all_while_a_watchpoint_is_armed() {
    let d = DebugControl::attached();
    let mut m = mem();
    m.set_debug(d.clone());

    // Attached but unarmed is not a debugger doing anything: spans are fine.
    assert!(!m.watchpoints_armed());
    assert!(m.host_span(0x1100, 8, Perm::READ).is_some());
    assert!(m.host_span_mut(0x1100, 8, Perm::WRITE).is_some());

    // Armed anywhere at all — not just over the range being asked for — and
    // everything is refused. A watchpoint on one address must not be silently
    // skipped because a *different* page was resolved before it was armed;
    // catching that is the caller's job via `watchpoints_armed`, and this is
    // the half that stops any *new* span being handed out.
    d.arm_watch(0x3000, 4, WatchKind::Write);
    assert!(m.watchpoints_armed());
    assert!(m.host_span(0x1100, 8, Perm::READ).is_none());
    assert!(m.host_span_mut(0x1100, 8, Perm::WRITE).is_none());

    d.disarm_watch(0x3000);
    assert!(!m.watchpoints_armed());
    assert!(m.host_span(0x1100, 8, Perm::READ).is_some());

    // A detached handle is not a debugger at all.
    let mut plain = mem();
    plain.set_debug(DebugControl::detached());
    assert!(!plain.watchpoints_armed());
    assert!(plain.host_span(0x1100, 8, Perm::READ).is_some());
    // ...and so is no handle.
    assert!(!mem().watchpoints_armed());
}

// ---------------------------------------------------------------------------
// Equivalence with the ordinary path.
// ---------------------------------------------------------------------------

/// A span is the *same bytes*, in the same order, as the typed accessors — so a
/// fast path built on it is a pure shortcut, not a second implementation.
#[test]
fn a_span_sees_exactly_what_the_typed_accessors_do() {
    let mut m = mem();
    m.write_u64(0x1100, 0x0123_4567_89ab_cdef).unwrap();
    assert_eq!(m.host_span(0x1100, 8, Perm::READ).unwrap(), 0x0123_4567_89ab_cdefu64.to_le_bytes());
    // Little-endian, so a 2-byte read at +0 is the low half.
    assert_eq!(m.read_uint(0x1100, 2).unwrap(), 0xcdef);
    assert_eq!(m.host_span(0x1100, 2, Perm::READ).unwrap(), [0xef, 0xcd]);

    // Written through the span, read back the ordinary way.
    m.host_span_mut(0x1200, 4, Perm::WRITE).unwrap().copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(m.read_uint(0x1200, 4).unwrap(), 0x0403_0201);

    // The span starts at `addr`, not at the region base.
    let base = m.host_span(0x1000, 1, Perm::READ).unwrap().as_ptr() as usize;
    let at = m.host_span(0x1234, 1, Perm::READ).unwrap().as_ptr() as usize;
    assert_eq!(at - base, 0x234);
}

/// The default is "no host mapping", so a backend that does not opt in — every
/// test double in the workspace — is untouched by all of this.
#[test]
fn the_default_implementation_hands_out_nothing() {
    struct Bare(Vec<u8>);
    impl Memory for Bare {
        fn read(&self, addr: u64, buf: &mut [u8]) -> exemu_core::Result<()> {
            buf.copy_from_slice(&self.0[addr as usize..][..buf.len()]);
            Ok(())
        }
        fn write(&mut self, addr: u64, data: &[u8]) -> exemu_core::Result<()> {
            self.0[addr as usize..][..data.len()].copy_from_slice(data);
            Ok(())
        }
    }
    let mut b = Bare(vec![0; 64]);
    assert!(b.host_span(0, 8, Perm::READ).is_none());
    assert!(b.host_span_mut(0, 8, Perm::WRITE).is_none());
    assert_eq!(b.layout_generation(), 0);
    assert!(!b.watchpoints_armed());
}
