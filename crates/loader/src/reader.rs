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
        off.checked_add(len)
            .and_then(|end| self.data.get(off..end))
            .ok_or_else(|| EmuError::InvalidPe(format!("read of {len} bytes at {off:#x} out of bounds")))
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

    pub fn bytes(&self, off: usize, len: usize) -> Result<Vec<u8>> {
        Ok(self.slice(off, len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_whose_end_overflows_are_errors() {
        let r = Reader::new(&[0u8; 8]);
        assert!(r.bytes(usize::MAX, 2).is_err());
        assert!(r.u32(usize::MAX - 1).is_err());
    }
}
