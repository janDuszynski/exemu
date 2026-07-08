//! The guest memory abstraction.
//!
//! The domain only cares that *something* can store and retrieve bytes at
//! 64-bit guest addresses and knows about permissions. The concrete paged
//! implementation lives in the `exemu-memory` crate.

use crate::error::{EmuError, Result};

/// Access permission bits for a mapped region. Combine with `|`.
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

/// A contiguous span of guest address space with a name and permissions.
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

/// Guest physical/virtual memory as the interpreter sees it.
///
/// Only [`read`](Memory::read) and [`write`](Memory::write) are required;
/// the typed little-endian accessors are provided on top of them so every
/// implementation gets them for free and behaves identically.
pub trait Memory {
    /// Fill `buf` with bytes starting at `addr`. Fails if any byte is
    /// unmapped or unreadable.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;

    /// Store `data` starting at `addr`. Fails if any byte is unmapped or
    /// unwritable.
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()>;

    /// Fetch bytes for execution. Defaults to [`read`](Memory::read) but a
    /// backend may enforce the executable bit here.
    fn fetch(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.read(addr, buf)
    }

    // ---- little-endian typed helpers -------------------------------------

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

    fn write_u16(&mut self, addr: u64, v: u16) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn write_u32(&mut self, addr: u64, v: u32) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    fn write_u64(&mut self, addr: u64, v: u64) -> Result<()> {
        self.write(addr, &v.to_le_bytes())
    }

    /// Read an integer of `size` (1/2/4/8) bytes, zero-extended into a u64.
    fn read_uint(&self, addr: u64, size: u8) -> Result<u64> {
        Ok(match size {
            1 => self.read_u8(addr)? as u64,
            2 => self.read_u16(addr)? as u64,
            4 => self.read_u32(addr)? as u64,
            8 => self.read_u64(addr)?,
            _ => return Err(EmuError::Unsupported(format!("memory read of {size} bytes"))),
        })
    }

    /// Write the low `size` (1/2/4/8) bytes of `v`.
    fn write_uint(&mut self, addr: u64, size: u8, v: u64) -> Result<()> {
        match size {
            1 => self.write_u8(addr, v as u8),
            2 => self.write_u16(addr, v as u16),
            4 => self.write_u32(addr, v as u32),
            8 => self.write_u64(addr, v),
            _ => Err(EmuError::Unsupported(format!("memory write of {size} bytes"))),
        }
    }

    /// Read a NUL-terminated ASCII/UTF-8 string (without the terminator).
    fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for i in 0..max as u64 {
            let b = self.read_u8(addr + i)?;
            if b == 0 {
                break;
            }
            out.push(b);
        }
        Ok(out)
    }

    // ---- dynamic mapping (VirtualAlloc/Free/Protect/Query support) --------
    //
    // The domain exposes just enough of the concrete address space for the OS
    // layer's virtual-memory manager to reserve, release, re-protect and probe
    // regions at runtime. Backends that are fixed-size (test doubles) inherit
    // the defaults below and simply refuse dynamic mapping.

    /// Map a fresh zero-filled region of `size` bytes at the fixed address
    /// `base` with permission `perm`. Fails on overlap with an existing region
    /// (which the caller uses to detect a taken address). Default: unsupported.
    fn map_fixed(&mut self, base: u64, size: u64, perm: Perm, name: &str) -> Result<()> {
        let _ = (base, size, perm, name);
        Err(EmuError::Unsupported("dynamic mapping".into()))
    }

    /// Change the protection of the region containing `base` to `perm`,
    /// returning that region's previous permission. Page-granular splitting is
    /// not modelled — the whole covering region is re-protected. Default:
    /// unsupported.
    fn protect(&mut self, base: u64, size: u64, perm: Perm) -> Result<Perm> {
        let _ = (base, size, perm);
        Err(EmuError::Unsupported("protect".into()))
    }

    /// Release mapped memory. `size == 0` releases the single region that
    /// starts exactly at `base` (VirtualFree/MEM_RELEASE); otherwise every
    /// region fully inside `[base, base+size)` is released. Default:
    /// unsupported.
    fn unmap(&mut self, base: u64, size: u64) -> Result<()> {
        let _ = (base, size);
        Err(EmuError::Unsupported("unmap".into()))
    }

    /// The first mapped region whose end is above `addr`, as
    /// `(base, size, perm)`. If its base is `<= addr`, then `addr` is inside
    /// that region; otherwise `addr` lies in a free gap that ends at the
    /// returned base. `None` means everything at/above `addr` is free.
    /// Default: `None`.
    fn next_region(&self, addr: u64) -> Option<(u64, u64, Perm)> {
        let _ = addr;
        None
    }
}
