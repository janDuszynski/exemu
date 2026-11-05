use crate::error::{EmuError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perm(pub u8);

impl Perm {
    pub const NONE: Perm = Perm(0);
    pub const READ: Perm = Perm(1 << 0);
    pub const WRITE: Perm = Perm(1 << 1);
    pub const EXEC: Perm = Perm(1 << 2);

    pub const RW: Perm = Perm(0b011);
    pub const RX: Perm = Perm(0b101);
    pub const RWX: Perm = Perm(0b111);

    #[inline]
    pub const fn contains(self, other: Perm) -> bool {
        self.0 & other.0 == other.0
    }

    #[inline]
    pub const fn union(self, other: Perm) -> Perm {
        Perm(self.0 | other.0)
    }
}

#[derive(Debug, Clone)]
pub struct Region {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub perm: Perm,
}

impl Region {
    pub fn new(name: impl Into<String>, base: u64, size: u64, perm: Perm) -> Self {
        Region { name: name.into(), base, size, perm }
    }

    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }

    #[inline]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

pub fn guest_addr(base: u64, off: u64, len: usize) -> Result<u64> {
    base.checked_add(off)
        .ok_or(EmuError::Unmapped { addr: base.wrapping_add(off), len })
}

pub trait Memory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()>;

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.read(addr, buf)
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        let mut b = [0u8; 1];
        self.read(addr, &mut b)?;
        Ok(b[0])
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn write_u8(&mut self, addr: u64, v: u8) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn read_u8_at(&self, base: u64, off: u64) -> Result<u8> {
        self.read_u8(guest_addr(base, off, 1)?)
    }

    fn write_u8_at(&mut self, base: u64, off: u64, v: u8) -> Result<()> {
        self.write_u8(guest_addr(base, off, 1)?, v)
    }

    fn write_u16(&mut self, addr: u64, v: u16) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn read_u16_at(&self, base: u64, off: u64) -> Result<u16> {
        self.read_u16(guest_addr(base, off, 2)?)
    }

    fn write_u16_at(&mut self, base: u64, off: u64, v: u16) -> Result<()> {
        self.write_u16(guest_addr(base, off, 2)?, v)
    }

    fn write_u32(&mut self, addr: u64, v: u32) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn read_u32_at(&self, base: u64, off: u64) -> Result<u32> {
        self.read_u32(guest_addr(base, off, 4)?)
    }

    fn write_u32_at(&mut self, base: u64, off: u64, v: u32) -> Result<()> {
        self.write_u32(guest_addr(base, off, 4)?, v)
    }

    fn write_u64(&mut self, addr: u64, v: u64) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn read_u64_at(&self, base: u64, off: u64) -> Result<u64> {
        self.read_u64(guest_addr(base, off, 8)?)
    }

    fn write_u64_at(&mut self, base: u64, off: u64, v: u64) -> Result<()> {
        self.write_u64(guest_addr(base, off, 8)?, v)
    }

    fn read_uint(&self, addr: u64, size: u8) -> Result<u64> {
        Ok(match size {
            1 => self.read_u8(addr)? as u64,
            2 => self.read_u16(addr)? as u64,
            4 => self.read_u32(addr)? as u64,
            8 => self.read_u64(addr)?,
            _ => return Err(EmuError::Unsupported(format!("memory read of {size} bytes"))),
        })
    }

    fn read_at(&self, base: u64, off: u64, buf: &mut [u8]) -> Result<()> {
        self.read(guest_addr(base, off, buf.len())?, buf)
    }

    fn write_at(&mut self, base: u64, off: u64, data: &[u8]) -> Result<()> {
        self.write(guest_addr(base, off, data.len())?, data)
    }

    fn write_uint(&mut self, addr: u64, size: u8, v: u64) -> Result<()> {
        match size {
            1 => self.write_u8(addr, v as u8),
            2 => self.write_u16(addr, v as u16),
            4 => self.write_u32(addr, v as u32),
            8 => self.write_u64(addr, v),
            _ => Err(EmuError::Unsupported(format!("memory write of {size} bytes"))),
        }
    }

    fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for i in 0..max as u64 {
            let b = self.read_u8_at(addr, i)?;
            if b == 0 {
                break;
            }
            out.push(b);
        }
        Ok(out)
    }

    fn map_fixed(&mut self, base: u64, size: u64, perm: Perm, name: &str) -> Result<()> {
        let _ = (base, size, perm, name);
        Err(EmuError::Unsupported("dynamic mapping".into()))
    }

    fn protect(&mut self, base: u64, size: u64, perm: Perm) -> Result<Perm> {
        let _ = (base, size, perm);
        Err(EmuError::Unsupported("protect".into()))
    }

    fn unmap(&mut self, base: u64, size: u64) -> Result<()> {
        let _ = (base, size);
        Err(EmuError::Unsupported("unmap".into()))
    }

    fn next_region(&self, addr: u64) -> Option<(u64, u64, Perm)> {
        let _ = addr;
        None
    }

    fn host_span(&self, addr: u64, len: usize, needed: Perm) -> Option<&[u8]> {
        let _ = (addr, len, needed);
        None
    }

    fn host_span_mut(&mut self, addr: u64, len: usize, needed: Perm) -> Option<&mut [u8]> {
        let _ = (addr, len, needed);
        None
    }

    fn layout_generation(&self) -> u64 {
        0
    }

    fn watchpoints_armed(&self) -> bool {
        false
    }

    fn code_generation(&self) -> u64 {
        0
    }

    fn code_page_generation(&self, addr: u64) -> u64 {
        let _ = addr;
        0
    }
}

pub const CODE_PAGE_SIZE: u64 = 0x1000;

#[cfg(test)]
mod tests {
    use super::*;

    struct Flat(Vec<u8>);

    impl Memory for Flat {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let start = usize::try_from(addr).map_err(|_| EmuError::Unmapped { addr, len: buf.len() })?;
            let src = start
                .checked_add(buf.len())
                .and_then(|end| self.0.get(start..end))
                .ok_or(EmuError::Unmapped { addr, len: buf.len() })?;
            buf.copy_from_slice(src);
            Ok(())
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let start = usize::try_from(addr).map_err(|_| EmuError::Unmapped { addr, len: data.len() })?;
            let dst = start
                .checked_add(data.len())
                .and_then(|end| self.0.get_mut(start..end))
                .ok_or(EmuError::Unmapped { addr, len: data.len() })?;
            dst.copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn offset_access_matches_plain_access_in_range() {
        let mut m = Flat(vec![0; 64]);
        m.write_u32_at(8, 4, 0xdead_beef).unwrap();
        assert_eq!(m.read_u32(12).unwrap(), 0xdead_beef);
        assert_eq!(m.read_u32_at(8, 4).unwrap(), 0xdead_beef);
    }

    #[test]
    fn overflowing_offset_is_an_unmapped_error() {
        let mut m = Flat(vec![0; 64]);
        assert_eq!(
            m.read_u32_at(u64::MAX - 2, 8),
            Err(EmuError::Unmapped { addr: 5, len: 4 })
        );
        assert_eq!(
            m.write_u64_at(u64::MAX, 1, 0),
            Err(EmuError::Unmapped { addr: 0, len: 8 })
        );
        assert!(m.read_at(u64::MAX, 2, &mut [0u8; 2]).is_err());
        assert!(m.read_cstr(u64::MAX, 4).is_err());
    }
}
