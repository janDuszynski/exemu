use std::ffi::{c_int, c_void};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    MapFailed,
    OutOfSpace,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockCode {
    entry: *const u8,
}

impl BlockCode {
    pub fn addr(self) -> usize {
        self.entry as usize
    }

    /// # Safety
    /// The buffer must hold a valid function of type `F`.
    pub unsafe fn as_fn<F: Copy>(self) -> F {
        debug_assert_eq!(std::mem::size_of::<F>(), std::mem::size_of::<*const u8>());
        // SAFETY: `F` is checked to be pointer-sized above, and the caller
        unsafe { std::mem::transmute_copy::<*const u8, F>(&self.entry) }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sys {
    use super::{c_int, c_void};

    extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
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
    pub const MAP_JIT: c_int = 0x0800;
}

pub struct CodeBuffer {
    base: *mut u8,
    capacity: usize,
    used: usize,
    blocks: usize,
}

impl CodeBuffer {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn with_capacity(capacity: usize) -> Result<CodeBuffer, BufferError> {
        let page = 16 * 1024;
        let capacity = capacity.max(page).div_ceil(page) * page;
        // SAFETY: a fresh anonymous mapping with a non-zero length and no fixed
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn push(&mut self, code: &[u32]) -> Result<BlockCode, BufferError> {
        let bytes = std::mem::size_of_val(code);
        debug_assert_eq!(self.used % 4, 0);
        if bytes > self.capacity - self.used {
            return Err(BufferError::OutOfSpace);
        }
        // SAFETY: `self.used <= self.capacity` is the invariant maintained here
        unsafe {
            let dst = self.base.add(self.used);
            sys::pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(code.as_ptr() as *const u8, dst, bytes);
            sys::pthread_jit_write_protect_np(1);
            sys::sys_icache_invalidate(dst as *mut c_void, bytes);
        }
        // SAFETY-relevant bookkeeping happens after the write so a failure above
        let entry = {
            // SAFETY: `used <= capacity`, so this is a pointer within (or one
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

    pub fn remaining(&self) -> usize {
        self.capacity - self.used
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for CodeBuffer {
    fn drop(&mut self) {
        // SAFETY: `base`/`capacity` are exactly what `mmap` returned and this
        unsafe {
            sys::munmap(self.base as *mut c_void, self.capacity);
        }
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;

    fn movz_ret(imm: u16) -> Vec<u32> {
        vec![0xD280_0000 | ((imm as u32) << 5), 0xD65F_03C0]
    }

    #[test]
    fn writes_then_executes() {
        let mut buf = CodeBuffer::with_capacity(4096).expect("MAP_JIT mapping");
        let code = buf.push(&movz_ret(0x1234)).unwrap();
        // SAFETY: the bytes at `code` are the two instructions above, which take
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
        let mut buf = CodeBuffer::with_capacity(1).unwrap();
        let big = vec![0xD503_201Fu32; buf.capacity() / 4];
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
        assert_eq!(f(), 22);
    }

    #[test]
    fn code_that_calls_back_into_rust_works() {
        extern "C" fn helper(a: u64) -> u64 {
            a * 3
        }
        let mut buf = CodeBuffer::with_capacity(4096).unwrap();
        let code = buf
            .push(&[
                0xA9BF_7BFD,
                0xD63F_0020,
                0xA8C1_7BFD,
                0xD65F_03C0,
            ])
            .unwrap();
        // SAFETY: the block takes (x0, x1) and returns x0, exactly as declared.
        let f: extern "C" fn(u64, extern "C" fn(u64) -> u64) -> u64 = unsafe { code.as_fn() };
        assert_eq!(f(14, helper), 42);
    }
}
