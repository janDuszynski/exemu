//! The runtime a compiled block calls back into.
//!
//! Compiled code never touches guest memory directly. Every load and store is a
//! call to one of the two helpers here, which go through the same
//! [`exemu_core::Memory`] implementation — and therefore the same bounds checks,
//! permission checks and region lookups — as the interpreter. That costs a call
//! per access, and buys two things worth more than the cycles: a JIT block
//! cannot reach a host address the interpreter could not, and a faulting access
//! produces *exactly* the interpreter's fault, because the interpreter is the
//! thing that ends up raising it (see [`Status`]).

use exemu_core::Memory;

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
    /// The store completed **and** landed in executable memory (roadmap W1.7's
    /// code-generation counter moved). The block must commit this instruction
    /// and then stop, because any instruction after it in the same block may
    /// have just been rewritten underneath the compiled code.
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

/// Everything a compiled block needs that is not the register file.
///
/// The emitted code only ever *loads* from this struct at fixed offsets
/// ([`ctx_off`]) and passes its address to the helpers; it never interprets the
/// `mem` field, which is why that field can stay an ordinary Rust trait object.
#[repr(C)]
pub struct BlockCtx<'a> {
    /// Guest memory. Only the helpers below dereference it.
    pub mem: &'a mut dyn Memory,
    /// 256-byte table: `parity[b]` is the x86 PF for a result whose low byte is
    /// `b` (1 when the byte has an even number of set bits). Compiled code
    /// computes PF with an `and`+`ldrb` instead of a five-instruction fold.
    pub parity: *const u8,
    /// The guest address range of the code the running block was compiled from.
    /// The store helper compares against it to detect a store that rewrites the
    /// block's own instructions — the only self-modification that can affect
    /// code already executing. (Stores that hit *other* code pages are caught
    /// between blocks, by the engine's per-page generation check.)
    pub code_lo: u64,
    pub code_hi: u64,
    /// Address of [`jit_read`], loaded and `blr`-ed by compiled code.
    pub read: unsafe extern "C" fn(*mut BlockCtx<'_>, u64, u32) -> ReadResult,
    /// Address of [`jit_write`].
    pub write: unsafe extern "C" fn(*mut BlockCtx<'_>, u64, u32, u64) -> u64,
}

/// Byte offsets of the [`BlockCtx`] fields the emitter loads.
pub mod ctx_off {
    use super::BlockCtx;
    pub const PARITY: u32 = std::mem::offset_of!(BlockCtx<'static>, parity) as u32;
    pub const READ: u32 = std::mem::offset_of!(BlockCtx<'static>, read) as u32;
    pub const WRITE: u32 = std::mem::offset_of!(BlockCtx<'static>, write) as u32;
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
    // Does this store overlap the bytes the running block was compiled from? If
    // so the instructions after it may have just changed, so the block must
    // commit this one and stop. Two compares, no call into the memory
    // implementation — the check has to be cheap, because a store is ~10% of a
    // real instruction stream.
    let hits_own_code = addr < ctx.code_hi && addr.saturating_add(size as u64) > ctx.code_lo;
    match ctx.mem.write_uint(addr, size as u8, value) {
        Err(_) => status::FAULT,
        Ok(()) => {
            if hits_own_code {
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
        // The emitter loads these with 8-byte-scaled `ldr`s, so they must be
        // 8-aligned and inside the struct.
        assert_eq!(ctx_off::PARITY % 8, 0);
        assert_eq!(ctx_off::READ % 8, 0);
        assert_eq!(ctx_off::WRITE % 8, 0);
        assert!((ctx_off::WRITE as usize) < std::mem::size_of::<BlockCtx<'static>>());
    }
}
