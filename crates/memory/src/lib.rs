//! # exemu-memory — the guest address space
//!
//! A straightforward region-based implementation of [`exemu_core::Memory`].
//! Guest memory is a set of non-overlapping [`Region`]s, each backed by an
//! owned byte buffer and carrying read/write/execute permissions. Regions
//! are kept sorted by base address so lookups are a binary search rather
//! than a linear scan — the hot path for every instruction fetch and every
//! memory operand.
//!
//! Accesses must fall entirely within a single region; an access that spans
//! a gap (or two separate regions) is reported as [`EmuError::Unmapped`],
//! which is exactly what a real page fault would do.

#![forbid(unsafe_code)]

use exemu_core::{EmuError, Memory, Perm, Region, Result};

struct Mapped {
    region: Region,
    bytes: Vec<u8>,
}

impl Mapped {
    #[inline]
    fn end(&self) -> u64 {
        self.region.end()
    }
}

/// The whole guest virtual address space.
#[derive(Default)]
pub struct VirtualMemory {
    /// Regions, invariant: sorted by `region.base`, non-overlapping.
    regions: Vec<Mapped>,
}

impl VirtualMemory {
    pub fn new() -> Self {
        VirtualMemory { regions: Vec::new() }
    }

    /// Map a zero-filled region.
    pub fn map(&mut self, region: Region) -> Result<()> {
        let bytes = vec![0u8; region.size as usize];
        self.insert(region, bytes)
    }

    /// Map a region and populate its start with `data`; the remainder up to
    /// `size` is zero-filled. Handy for PE sections where the virtual size
    /// exceeds the on-disk data (e.g. `.data`/`.bss`).
    pub fn map_with_data(
        &mut self,
        name: impl Into<String>,
        base: u64,
        size: u64,
        data: &[u8],
        perm: Perm,
    ) -> Result<()> {
        let size = size.max(data.len() as u64);
        let mut bytes = vec![0u8; size as usize];
        bytes[..data.len()].copy_from_slice(data);
        self.insert(Region::new(name, base, size, perm), bytes)
    }

    /// A privileged write that bypasses permission checks, modelling what the
    /// loader/kernel does when it patches an image (e.g. filling the Import
    /// Address Table, which usually lives in a read-only section). Still
    /// bounds-checked against a single region.
    pub fn poke(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let m = self.find_mut(addr).ok_or(EmuError::Unmapped { addr, len: data.len() })?;
        let start = (addr - m.region.base) as usize;
        let end = start
            .checked_add(data.len())
            .filter(|&e| e as u64 <= m.region.size)
            .ok_or(EmuError::Unmapped { addr, len: data.len() })?;
        m.bytes[start..end].copy_from_slice(data);
        Ok(())
    }

    /// The list of mapped regions (for diagnostics / a memory map dump).
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.iter().map(|m| &m.region)
    }

    /// Total number of bytes currently mapped.
    pub fn mapped_bytes(&self) -> u64 {
        self.regions.iter().map(|m| m.region.size).sum()
    }

    // ---- internals -------------------------------------------------------

    fn insert(&mut self, region: Region, bytes: Vec<u8>) -> Result<()> {
        if region.size == 0 {
            return Ok(());
        }
        // Reject overlaps with any existing region.
        for m in &self.regions {
            let overlaps = region.base < m.end() && m.region.base < region.end();
            if overlaps {
                return Err(EmuError::Overlap { addr: region.base, len: region.size });
            }
        }
        let pos = self.regions.partition_point(|m| m.region.base < region.base);
        self.regions.insert(pos, Mapped { region, bytes });
        Ok(())
    }

    /// Find the region containing `addr` via binary search.
    #[inline]
    fn find(&self, addr: u64) -> Option<&Mapped> {
        // The candidate is the last region whose base <= addr.
        let idx = self.regions.partition_point(|m| m.region.base <= addr);
        if idx == 0 {
            return None;
        }
        let m = &self.regions[idx - 1];
        if m.region.contains(addr) {
            Some(m)
        } else {
            None
        }
    }

    #[inline]
    fn find_mut(&mut self, addr: u64) -> Option<&mut Mapped> {
        let idx = self.regions.partition_point(|m| m.region.base <= addr);
        if idx == 0 {
            return None;
        }
        let m = &mut self.regions[idx - 1];
        if m.region.contains(addr) {
            Some(m)
        } else {
            None
        }
    }

    /// Resolve `[addr, addr+len)` to a slice inside one region, checking that
    /// the whole range is contained and that `needed` permission is present.
    fn locate(&self, addr: u64, len: usize, needed: Perm, what: &'static str) -> Result<(usize, usize)> {
        let m = self.find(addr).ok_or(EmuError::Unmapped { addr, len })?;
        let start = (addr - m.region.base) as usize;
        let end = start
            .checked_add(len)
            .filter(|&e| e as u64 <= m.region.size)
            .ok_or(EmuError::Unmapped { addr, len })?;
        if !m.region.perm.contains(needed) {
            return Err(EmuError::Permission { addr, needed: what });
        }
        Ok((start, end))
    }
}

impl Memory for VirtualMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let (start, end) = self.locate(addr, buf.len(), Perm::READ, "read")?;
        let m = self.find(addr).expect("located above");
        buf.copy_from_slice(&m.bytes[start..end]);
        Ok(())
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let (start, end) = self.locate(addr, buf.len(), Perm::EXEC, "execute")?;
        let m = self.find(addr).expect("located above");
        buf.copy_from_slice(&m.bytes[start..end]);
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let (start, end) = self.locate(addr, data.len(), Perm::WRITE, "write")?;
        let m = self.find_mut(addr).expect("located above");
        m.bytes[start..end].copy_from_slice(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> VirtualMemory {
        let mut m = VirtualMemory::new();
        m.map(Region::new("stack", 0x1000, 0x1000, Perm::RW)).unwrap();
        m.map(Region::new("code", 0x400000, 0x1000, Perm::RX)).unwrap();
        m
    }

    #[test]
    fn roundtrip_typed() {
        let mut m = mem();
        m.write_u64(0x1100, 0xdead_beef_cafe_babe).unwrap();
        assert_eq!(m.read_u64(0x1100).unwrap(), 0xdead_beef_cafe_babe);
        assert_eq!(m.read_u32(0x1100).unwrap(), 0xcafe_babe);
        assert_eq!(m.read_u8(0x1100).unwrap(), 0xbe);
    }

    #[test]
    fn unmapped_faults() {
        let m = mem();
        assert!(matches!(m.read_u8(0x9999_9999), Err(EmuError::Unmapped { .. })));
    }

    #[test]
    fn permission_enforced() {
        let mut m = mem();
        // code region is read+execute, not writable
        assert!(matches!(m.write_u8(0x400000, 1), Err(EmuError::Permission { .. })));
        // and data region is not executable
        let mut b = [0u8; 1];
        assert!(matches!(m.fetch(0x1000, &mut b), Err(EmuError::Permission { .. })));
    }

    #[test]
    fn overlap_rejected() {
        let mut m = mem();
        assert!(matches!(
            m.map(Region::new("dup", 0x1800, 0x1000, Perm::RW)),
            Err(EmuError::Overlap { .. })
        ));
    }

    #[test]
    fn access_spanning_region_end_faults() {
        let m = mem();
        // 8-byte read starting 4 bytes before the region end overruns it.
        assert!(m.read_u64(0x1000 + 0x1000 - 4).is_err());
    }
}
