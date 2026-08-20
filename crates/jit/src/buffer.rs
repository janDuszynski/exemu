//! The W^X code buffer (roadmap W8.2).
//!
//! Apple Silicon enforces W^X for executable mappings: a page may be writable
//! **or** executable for a given thread, never both at once. The supported way
//! to host a JIT is:
//!
//! 1. `mmap` the region `PROT_READ|PROT_WRITE|PROT_EXEC` with `MAP_JIT`;
//! 2. call `pthread_jit_write_protect_np(0)` to put *this thread* in
//!    "JIT pages are writable" mode, write the code, then
//!    `pthread_jit_write_protect_np(1)` to switch back to executable;
//! 3. call `sys_icache_invalidate` over the bytes just written, because the
//!    instruction cache is not coherent with the data cache on ARM.
//!
//! Step 2 is **per thread**, not per page: the mapping stays `RX` for every
//! other thread the whole time, and this thread only ever holds `W` across the
//! `copy` in [`CodeBuffer::push`]. Executing while the toggle is in the
//! writable state would fault, so `push` restores it on every path.
//!
//! ## Packaging requirement (roadmap W9.7)
//!
//! `MAP_JIT` works out of the box for an ad-hoc-signed binary (`cargo test`,
//! `cargo run`, the `exemu` CLI as built here). The moment exemu ships as a
//! **notarized `.app` with the hardened runtime**, the same call fails with
//! `EPERM` unless the bundle is signed with:
//!
//! ```text
//! <key>com.apple.security.cs.allow-jit</key><true/>
//! ```
//!
//! That entitlement — and only that one; `allow-unsigned-executable-memory` and
//! `disable-executable-page-protection` are *weaker* alternatives that should
//! not be used — is a hard requirement on the W9.7 packaging step.
//!
//! ## Why the `unsafe` here is small
//!
//! Every foreign function this crate calls is declared in this file (four of
//! them), and each `unsafe` block below is a single call whose preconditions are
//! stated immediately above it. Nothing outside this module ever sees a raw
//! pointer into the mapping except as an opaque [`BlockCode`] handle.

use std::ffi::{c_int, c_void};

/// Errors the code buffer can report. A JIT that cannot allocate is never a
/// correctness problem — the caller falls back to the interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    /// `mmap` refused the mapping (on a hardened-runtime build, the missing
    /// `com.apple.security.cs.allow-jit` entitlement lands here).
    MapFailed,
    /// The buffer is full. Blocks are never freed individually; the engine
    /// flushes and recompiles instead.
    OutOfSpace,
    /// This platform has no W^X JIT backend compiled in.
    Unsupported,
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::MapFailed => write!(
                f,
                "MAP_JIT mmap failed (a hardened-runtime build needs the \
                 com.apple.security.cs.allow-jit entitlement)"
            ),
            BufferError::OutOfSpace => write!(f, "JIT code buffer is full"),
            BufferError::Unsupported => write!(f, "no W^X JIT backend on this platform"),
        }
    }
}

/// A compiled block's entry point, as handed back by [`CodeBuffer::push`].
///
/// The ABI is fixed by the emitter (see `compile.rs`):
/// `extern "C" fn(state: *mut CpuState, ctx: *mut BlockCtx) -> u64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockCode {
    entry: *const u8,
}

impl BlockCode {
    /// The raw entry address (for disassembly/debugging).
    pub fn addr(self) -> usize {
        self.entry as usize
    }

    /// Reinterpret the entry point as the block ABI's function pointer.
    ///
    /// # Safety
    /// The caller must guarantee that the bytes at this address were produced by
    /// this crate's emitter for exactly that ABI, and that the buffer they live
    /// in has not been reset since.
    pub unsafe fn as_fn<F: Copy>(self) -> F {
        debug_assert_eq!(std::mem::size_of::<F>(), std::mem::size_of::<*const u8>());
        // SAFETY: `F` is checked to be pointer-sized above, and the caller
        // asserts it is the emitter's ABI for this entry point.
        unsafe { std::mem::transmute_copy::<*const u8, F>(&self.entry) }
    }
}

// ---------------------------------------------------------------------------
// macOS / Apple Silicon backend
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sys {
    use super::{c_int, c_void};

    // The crate's entire foreign-function surface. Declared here rather than
    // taken from a crates.io binding so an auditor can check four lines against
    // `mmap(2)`, `munmap(2)`, `pthread_jit_write_protect_np(3)` and
    // `sys_icache_invalidate(3)` without leaving this file.
    extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64, // off_t is 64-bit on macOS
        ) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, len: usize) -> c_int;
        pub fn pthread_jit_write_protect_np(enabled: c_int);
        pub fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }

    pub const PROT_READ: c_int = 0x01;
    pub const PROT_WRITE: c_int = 0x02;
    pub const PROT_EXEC: c_int = 0x04;
    pub const MAP_PRIVATE: c_int = 0x0002;
    pub const MAP_ANON: c_int = 0x1000;
    /// `MAP_JIT` — the flag that makes a mapping eligible for the per-thread
    /// write-protect toggle below.
    pub const MAP_JIT: c_int = 0x0800;
}

/// A bump-allocated block of `MAP_JIT` memory that compiled code is written into.
///
/// Not `Send`/`Sync` (it holds a raw pointer and the write toggle is per
/// thread): one buffer belongs to one JIT engine on one thread.
pub struct CodeBuffer {
    base: *mut u8,
    capacity: usize,
    used: usize,
    /// Number of blocks written since the last [`CodeBuffer::reset`].
    blocks: usize,
}

impl CodeBuffer {
    /// Reserve `capacity` bytes (rounded up to a page) of JIT memory.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn with_capacity(capacity: usize) -> Result<CodeBuffer, BufferError> {
        let page = 16 * 1024; // Apple Silicon's page size; rounding up is enough
        let capacity = capacity.max(page).div_ceil(page) * page;
        // SAFETY: a fresh anonymous mapping with a non-zero length and no fixed
        // address; `mmap` either returns a valid mapping of `capacity` bytes or
        // MAP_FAILED, which is checked immediately.
        let p = unsafe {
            sys::mmap(
                std::ptr::null_mut(),
                capacity,
                sys::PROT_READ | sys::PROT_WRITE | sys::PROT_EXEC,
                sys::MAP_PRIVATE | sys::MAP_ANON | sys::MAP_JIT,
                -1,
                0,
            )
        };
        if p.is_null() || p as isize == -1 {
            return Err(BufferError::MapFailed);
        }
        Ok(CodeBuffer { base: p as *mut u8, capacity, used: 0, blocks: 0 })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn with_capacity(_capacity: usize) -> Result<CodeBuffer, BufferError> {
        Err(BufferError::Unsupported)
    }

    /// Copy one compiled block (a slice of ARM64 instruction words) into the
    /// buffer and return its entry point.
    ///
    /// The write window — the only moment this thread can write JIT memory — is
    /// exactly the `copy_nonoverlapping` between the two toggle calls.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn push(&mut self, code: &[u32]) -> Result<BlockCode, BufferError> {
        let bytes = std::mem::size_of_val(code);
        // Keep every entry point 4-byte aligned (ARM64 requires it). `used` only
        // ever grows by whole instruction words, so it already is; assert rather
        // than assume.
        debug_assert_eq!(self.used % 4, 0);
        if bytes > self.capacity - self.used {
            return Err(BufferError::OutOfSpace);
        }
        // SAFETY: `self.used <= self.capacity` is the invariant maintained here
        // and `bytes <= capacity - used` was just checked, so `dst` and the
        // `bytes` after it are inside the mapping. `code` is a live slice of at
        // least `bytes` bytes and cannot alias the mapping (it is a Vec on the
        // Rust heap). The write is legal only while the per-thread JIT write
        // toggle is off, which is why the two calls bracket the copy — and why
        // nothing between them can panic (a raw `copy_nonoverlapping` of
        // `Copy` data cannot unwind, so the toggle is always restored).
        unsafe {
            let dst = self.base.add(self.used);
            sys::pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(code.as_ptr() as *const u8, dst, bytes);
            sys::pthread_jit_write_protect_np(1);
            // ARM's I-cache is not coherent with the D-cache: without this the
            // CPU may execute stale bytes at an address a previous block used.
            sys::sys_icache_invalidate(dst as *mut c_void, bytes);
        }
        // SAFETY-relevant bookkeeping happens after the write so a failure above
        // cannot leave `used` claiming space that holds nothing.
        let entry = {
            // SAFETY: `used <= capacity`, so this is a pointer within (or one
            // past the end of) the mapping — and it is within, since `bytes > 0`
            // for every block the emitter produces.
            unsafe { self.base.add(self.used) as *const u8 }
        };
        self.used += bytes;
        self.blocks += 1;
        Ok(BlockCode { entry })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn push(&mut self, _code: &[u32]) -> Result<BlockCode, BufferError> {
        Err(BufferError::Unsupported)
    }

    /// Forget every block and reuse the memory from the start.
    ///
    /// # Panics / soundness
    /// Callers must not do this while any block from this buffer is executing —
    /// the engine only resets between block calls (it is not re-entrant), which
    /// is why this is a plain `&mut self` method rather than an `unsafe` one:
    /// holding `&mut` on the buffer already excludes a live borrow of the
    /// engine that would be needed to run a block.
    pub fn reset(&mut self) {
        self.used = 0;
        self.blocks = 0;
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn blocks(&self) -> usize {
        self.blocks
    }

    /// Bytes still available for compiled code.
    pub fn remaining(&self) -> usize {
        self.capacity - self.used
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for CodeBuffer {
    fn drop(&mut self) {
        // SAFETY: `base`/`capacity` are exactly what `mmap` returned and this
        // type is the sole owner of the mapping (no `Clone`, not `Copy`).
        unsafe {
            sys::munmap(self.base as *mut c_void, self.capacity);
        }
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;

    /// `mov x0, #imm16; ret` — the smallest possible proof that a page written
    /// through the W^X toggle really executes.
    fn movz_ret(imm: u16) -> Vec<u32> {
        vec![0xD280_0000 | ((imm as u32) << 5), 0xD65F_03C0]
    }

    #[test]
    fn writes_then_executes() {
        let mut buf = CodeBuffer::with_capacity(4096).expect("MAP_JIT mapping");
        let code = buf.push(&movz_ret(0x1234)).unwrap();
        // SAFETY: the bytes at `code` are the two instructions above, which take
        // no arguments and return a u64 in x0 per AAPCS64.
        let f: extern "C" fn() -> u64 = unsafe { code.as_fn() };
        assert_eq!(f(), 0x1234);
    }

    #[test]
    fn many_blocks_stay_independent() {
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let mut fns = Vec::new();
        for i in 0..64u16 {
            fns.push(buf.push(&movz_ret(i * 7)).unwrap());
        }
        for (i, code) in fns.iter().enumerate() {
            // SAFETY: as above — each entry is its own `movz`/`ret` pair.
            let f: extern "C" fn() -> u64 = unsafe { code.as_fn() };
            assert_eq!(f(), i as u64 * 7, "block {i}");
        }
        assert_eq!(buf.blocks(), 64);
        assert_eq!(buf.used(), 64 * 8);
    }

    #[test]
    fn rejects_overflow_instead_of_scribbling() {
        let mut buf = CodeBuffer::with_capacity(1).unwrap(); // rounds up to a page
        let big = vec![0xD503_201Fu32; buf.capacity() / 4]; // NOPs, exactly full
        assert!(buf.push(&big).is_ok());
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.push(&movz_ret(1)), Err(BufferError::OutOfSpace));
    }

    #[test]
    fn reset_reuses_the_mapping() {
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let a = buf.push(&movz_ret(11)).unwrap();
        buf.reset();
        assert_eq!(buf.used(), 0);
        let b = buf.push(&movz_ret(22)).unwrap();
        assert_eq!(a.addr(), b.addr(), "reset rewinds the bump pointer");
        // SAFETY: `b` is the freshly written block at that address; `a` is dead.
        let f: extern "C" fn() -> u64 = unsafe { b.as_fn() };
        // Proves the i-cache invalidation actually happened: without it this
        // could still return the *old* block's 11.
        assert_eq!(f(), 22);
    }

    #[test]
    fn code_that_calls_back_into_rust_works() {
        // `br x1`-style call-out: the block ABI depends on being able to `blr`
        // to a Rust `extern "C"` helper, so prove that shape executes.
        extern "C" fn helper(a: u64) -> u64 {
            a * 3
        }
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let code = buf
            .push(&[
                0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
                0xD63F_0020, // blr x1
                0xA8C1_7BFD, // ldp x29, x30, [sp], #16
                0xD65F_03C0, // ret
            ])
            .unwrap();
        // SAFETY: the block takes (x0, x1) and returns x0, exactly as declared.
        let f: extern "C" fn(u64, extern "C" fn(u64) -> u64) -> u64 = unsafe { code.as_fn() };
        assert_eq!(f(14, helper), 42);
    }
}
