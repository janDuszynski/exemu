//! A tiny bounds-checked little-endian cursor over a byte slice.
//!
//! PE files are little-endian on every target we care about, and Rust's
//! `from_le_bytes` makes the reads trivial; this wrapper just adds bounds
//! checks so a truncated or malicious file yields a clean `InvalidPe` error
//! instead of a panic.

use exemu_core::{EmuError, Result};

pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        self.data
            .get(off..off + len)
            .ok_or_else(|| EmuError::InvalidPe(format!("read of {len} bytes at {off:#x} out of bounds")))
    }

    #[allow(dead_code)] // part of a complete reader API; not every field is 1 byte
    pub fn u8(&self, off: usize) -> Result<u8> {
        Ok(self.slice(off, 1)?[0])
    }

    pub fn u16(&self, off: usize) -> Result<u16> {
        let b = self.slice(off, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&self, off: usize) -> Result<u32> {
        let b = self.slice(off, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&self, off: usize) -> Result<u64> {
        let b = self.slice(off, 8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    /// Copy `len` raw bytes out at `off`.
    pub fn bytes(&self, off: usize, len: usize) -> Result<Vec<u8>> {
        Ok(self.slice(off, len)?.to_vec())
    }

    /// Read a NUL-terminated ASCII string starting at `off`.
    #[allow(dead_code)] // used by string tables the parser may grow into
    pub fn cstr(&self, off: usize) -> Result<String> {
        let mut end = off;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        Ok(String::from_utf8_lossy(&self.data[off..end]).into_owned())
    }
}
