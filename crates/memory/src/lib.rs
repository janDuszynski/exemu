#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::HashMap;

use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::{EmuError, Memory, Perm, Region, Result, CODE_PAGE_SIZE};

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

#[derive(Default)]
pub struct VirtualMemory {
    regions: Vec<Mapped>,
    code_gen: u64,
    page_gen: HashMap<u64, u64>,
    hints: [Cell<usize>; HINT_SLOTS],
    layout_gen: u64,
    debug: Option<DebugControl>,
}

const HINT_SLOTS: usize = 8;

impl VirtualMemory {
    pub fn new() -> Self {
        VirtualMemory::default()
    }

    pub fn map(&mut self, region: Region) -> Result<()> {
        let bytes = vec![0u8; region.size as usize];
        self.insert(region, bytes)
    }

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
        let is_exec = m.region.perm.contains(Perm::EXEC);
        m.bytes[start..end].copy_from_slice(data);
        if is_exec {
            self.note_code_write(addr, data.len());
        }
        Ok(())
    }

    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.iter().map(|m| &m.region)
    }

    pub fn mapped_bytes(&self) -> u64 {
        self.regions.iter().map(|m| m.region.size).sum()
    }

    pub fn set_debug(&mut self, debug: DebugControl) {
        self.debug = debug.is_attached().then_some(debug);
    }

    pub fn debug(&self) -> Option<&DebugControl> {
        self.debug.as_ref()
    }

    #[inline]
    fn note_watched_access(&self, addr: u64, len: usize, kind: WatchKind) {
        let Some(d) = self.debug.as_ref() else { return };
        if !d.any_watchpoints() {
            return;
        }
        Self::record_watch_hit(d, addr, len, kind);
    }

    #[cold]
    #[inline(never)]
    fn record_watch_hit(d: &DebugControl, addr: u64, len: usize, kind: WatchKind) {
        if d.is_watched(addr, len as u64, kind) {
            d.note_watch_hit(addr, kind);
        }
    }

    #[cold]
    #[inline(never)]
    fn note_code_write(&mut self, addr: u64, len: usize) {
        self.code_gen = self.code_gen.wrapping_add(1);
        let first = addr / CODE_PAGE_SIZE;
        let last = (addr + (len as u64 - 1)) / CODE_PAGE_SIZE;
        for page in first..=last {
            let g = self.page_gen.entry(page * CODE_PAGE_SIZE).or_insert(0);
            *g = g.wrapping_add(1);
        }
    }

    fn insert(&mut self, region: Region, bytes: Vec<u8>) -> Result<()> {
        if region.size == 0 {
            return Ok(());
        }
        for m in &self.regions {
            let overlaps = region.base < m.end() && m.region.base < region.end();
            if overlaps {
                return Err(EmuError::Overlap { addr: region.base, len: region.size });
            }
        }
        let pos = self.regions.partition_point(|m| m.region.base < region.base);
        self.regions.insert(pos, Mapped { region, bytes });
        self.layout_gen = self.layout_gen.wrapping_add(1);
        Ok(())
    }

    #[inline]
    fn find_idx(&self, addr: u64) -> Option<usize> {
        let slot = ((addr >> 12) as usize) & (HINT_SLOTS - 1);
        let hint = self.hints[slot].get();
        if let Some(m) = self.regions.get(hint) {
            if m.region.contains(addr) {
                return Some(hint);
            }
        }
        self.find_idx_slow(addr, slot)
    }

    #[inline(never)]
    fn find_idx_slow(&self, addr: u64, slot: usize) -> Option<usize> {
        let idx = self.regions.partition_point(|m| m.region.base <= addr);
        if idx == 0 {
            return None;
        }
        if self.regions[idx - 1].region.contains(addr) {
            self.hints[slot].set(idx - 1);
            Some(idx - 1)
        } else {
            None
        }
    }

    #[inline]
    fn find_mut(&mut self, addr: u64) -> Option<&mut Mapped> {
        let i = self.find_idx(addr)?;
        Some(&mut self.regions[i])
    }

    #[inline]
    fn locate(
        &self,
        addr: u64,
        len: usize,
        needed: Perm,
        what: &'static str,
    ) -> Result<(usize, usize, usize)> {
        let idx = match self.find_idx(addr) {
            Some(i) => i,
            None => return Err(EmuError::Unmapped { addr, len }),
        };
        let m = &self.regions[idx];
        let start = (addr - m.region.base) as usize;
        let end = match start.checked_add(len) {
            Some(e) if e as u64 <= m.region.size => e,
            _ => return Err(EmuError::Unmapped { addr, len }),
        };
        if !m.region.perm.contains(needed) {
            return Err(EmuError::Permission { addr, needed: what });
        }
        Ok((idx, start, end))
    }
}

impl Memory for VirtualMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let (idx, start, end) = self.locate(addr, buf.len(), Perm::READ, "read")?;
        buf.copy_from_slice(&self.regions[idx].bytes[start..end]);
        self.note_watched_access(addr, buf.len(), WatchKind::Read);
        Ok(())
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let (idx, start, end) = self.locate(addr, buf.len(), Perm::EXEC, "execute")?;
        buf.copy_from_slice(&self.regions[idx].bytes[start..end]);
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let (idx, start, end) = self.locate(addr, data.len(), Perm::WRITE, "write")?;
        let m = &mut self.regions[idx];
        let is_exec = m.region.perm.contains(Perm::EXEC);
        m.bytes[start..end].copy_from_slice(data);
        if is_exec {
            self.note_code_write(addr, data.len());
        }
        self.note_watched_access(addr, data.len(), WatchKind::Write);
        Ok(())
    }

    fn read_uint(&self, addr: u64, size: u8) -> Result<u64> {
        let len = match size {
            1 => 1usize,
            2 => 2,
            4 => 4,
            8 => 8,
            _ => return Err(EmuError::Unsupported(format!("memory read of {size} bytes"))),
        };
        let (idx, start, end) = self.locate(addr, len, Perm::READ, "read")?;
        let b = &self.regions[idx].bytes[start..end];
        self.note_watched_access(addr, len, WatchKind::Read);
        Ok(match size {
            1 => b[0] as u64,
            2 => u16::from_le_bytes([b[0], b[1]]) as u64,
            4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64,
            _ => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        })
    }

    fn write_uint(&mut self, addr: u64, size: u8, v: u64) -> Result<()> {
        let len = match size {
            1 => 1usize,
            2 => 2,
            4 => 4,
            8 => 8,
            _ => return Err(EmuError::Unsupported(format!("memory write of {size} bytes"))),
        };
        let (idx, start, end) = self.locate(addr, len, Perm::WRITE, "write")?;
        let m = &mut self.regions[idx];
        let is_exec = m.region.perm.contains(Perm::EXEC);
        let dst = &mut m.bytes[start..end];
        match size {
            1 => dst[0] = v as u8,
            2 => dst.copy_from_slice(&(v as u16).to_le_bytes()),
            4 => dst.copy_from_slice(&(v as u32).to_le_bytes()),
            _ => dst.copy_from_slice(&v.to_le_bytes()),
        }
        if is_exec {
            self.note_code_write(addr, len);
        }
        self.note_watched_access(addr, len, WatchKind::Write);
        Ok(())
    }

    fn map_fixed(&mut self, base: u64, size: u64, perm: Perm, name: &str) -> Result<()> {
        self.map(Region::new(name, base, size, perm))
    }

    fn protect(&mut self, base: u64, size: u64, perm: Perm) -> Result<Perm> {
        let m = self.find_mut(base).ok_or(EmuError::Unmapped { addr: base, len: size as usize })?;
        let old = m.region.perm;
        m.region.perm = perm;
        self.layout_gen = self.layout_gen.wrapping_add(1);
        Ok(old)
    }

    fn unmap(&mut self, base: u64, size: u64) -> Result<()> {
        self.layout_gen = self.layout_gen.wrapping_add(1);
        if size == 0 {
            if let Some(pos) = self.regions.iter().position(|m| m.region.base == base) {
                self.regions.remove(pos);
            }
        } else {
            let end = base.saturating_add(size);
            self.regions.retain(|m| !(m.region.base >= base && m.end() <= end));
        }
        Ok(())
    }

    fn next_region(&self, addr: u64) -> Option<(u64, u64, Perm)> {
        self.regions
            .iter()
            .find(|m| m.end() > addr)
            .map(|m| (m.region.base, m.region.size, m.region.perm))
    }

    fn host_span(&self, addr: u64, len: usize, needed: Perm) -> Option<&[u8]> {
        if len == 0 || self.watchpoints_armed() {
            return None;
        }
        let (idx, start, end) = self.locate(addr, len, needed, "read").ok()?;
        Some(&self.regions[idx].bytes[start..end])
    }

    fn host_span_mut(&mut self, addr: u64, len: usize, needed: Perm) -> Option<&mut [u8]> {
        if len == 0 || self.watchpoints_armed() {
            return None;
        }
        let (idx, start, end) = self.locate(addr, len, needed, "write").ok()?;
        if self.regions[idx].region.perm.contains(Perm::EXEC) {
            return None;
        }
        Some(&mut self.regions[idx].bytes[start..end])
    }

    #[inline]
    fn layout_generation(&self) -> u64 {
        self.layout_gen
    }

    #[inline]
    fn watchpoints_armed(&self) -> bool {
        self.debug.as_ref().is_some_and(|d| d.any_watchpoints())
    }

    #[inline]
    fn code_generation(&self) -> u64 {
        self.code_gen
    }

    #[inline]
    fn code_page_generation(&self, addr: u64) -> u64 {
        let page = (addr / CODE_PAGE_SIZE) * CODE_PAGE_SIZE;
        self.page_gen.get(&page).copied().unwrap_or(0)
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
        assert!(matches!(m.write_u8(0x400000, 1), Err(EmuError::Permission { .. })));
        let mut b = [0u8; 1];
        assert!(matches!(m.fetch(0x1000, &mut b), Err(EmuError::Permission { .. })));
    }

    #[test]
    fn lookup_cache_survives_a_map_that_shifts_the_region_vector() {
        let mut m = mem();
        m.write_u8(0x400010, 0x11).ok();
        assert_eq!(m.read_u8(0x400010).unwrap(), 0x00);
        assert_eq!(m.read_u32(0x400000).unwrap(), 0);

        m.map(Region::new("low", 0x100, 0x100, Perm::RW)).unwrap();
        m.write_u8(0x180, 0x5A).unwrap();

        assert_eq!(m.read_u8(0x180).unwrap(), 0x5A, "new low region");
        assert_eq!(m.read_u32(0x400000).unwrap(), 0, "code region after the shift");
        m.write_u64(0x1100, 0xFEED).unwrap();
        assert_eq!(m.read_u64(0x1100).unwrap(), 0xFEED, "stack region after the shift");
    }

    #[test]
    fn lookup_cache_does_not_resurrect_an_unmapped_region() {
        let mut m = mem();
        m.map_fixed(0x5000_0000, 0x1000, Perm::RW, "valloc").unwrap();
        m.write_u32(0x5000_0010, 0xABCD).unwrap();
        assert_eq!(m.read_u32(0x5000_0010).unwrap(), 0xABCD);

        m.unmap(0x5000_0000, 0).unwrap();
        assert!(matches!(m.read_u32(0x5000_0010), Err(EmuError::Unmapped { .. })));
        assert!(matches!(m.write_u32(0x5000_0010, 1), Err(EmuError::Unmapped { .. })));
        m.write_u64(0x1100, 7).unwrap();
        assert_eq!(m.read_u64(0x1100).unwrap(), 7);
    }

    #[test]
    fn lookup_cache_sees_a_protection_change() {
        let mut m = mem();
        m.write_u8(0x1000, 1).unwrap();
        m.protect(0x1000, 0x1000, Perm::READ).unwrap();
        assert!(matches!(m.write_u8(0x1000, 2), Err(EmuError::Permission { .. })));
        assert_eq!(m.read_u8(0x1000).unwrap(), 1);
    }

    #[test]
    fn typed_accessors_match_the_default_semantics() {
        let mut m = mem();
        for (size, v) in [(1u8, 0xAAu64), (2, 0xBBBB), (4, 0xCCCC_CCCC), (8, 0xDDDD_DDDD_DDDD_DDDD)] {
            m.write_uint(0x1200, size, v).unwrap();
            assert_eq!(m.read_uint(0x1200, size).unwrap(), v, "width {size}");
        }
        m.write_u64(0x1300, 0).unwrap();
        m.write_uint(0x1300, 4, 0x1122_3344).unwrap();
        assert_eq!(m.read_u64(0x1300).unwrap(), 0x1122_3344);

        assert!(matches!(m.read_uint(0x9999_9999, 3), Err(EmuError::Unsupported(_))));
        assert!(matches!(m.write_uint(0x9999_9999, 3, 0), Err(EmuError::Unsupported(_))));
        assert!(matches!(m.write_uint(0x400000, 4, 0), Err(EmuError::Permission { .. })));
        assert!(matches!(m.read_uint(0x9999_9999, 4), Err(EmuError::Unmapped { .. })));
        let mut rwx = rwx_mem();
        let before = rwx.code_generation();
        rwx.write_uint(0x400040, 4, 0x9090_9090).unwrap();
        assert_eq!(rwx.code_generation() - before, 1);
        assert_eq!(rwx.code_page_generation(0x400000), 1);
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
        assert!(m.read_u64(0x1000 + 0x1000 - 4).is_err());
    }

    #[test]
    fn dynamic_map_protect_unmap() {
        let mut m = mem();
        m.map_fixed(0x5000_0000, 0x2000, Perm::RW, "valloc").unwrap();
        let (base, size, perm) = m.next_region(0x5000_0000).unwrap();
        assert_eq!((base, size), (0x5000_0000, 0x2000));
        assert_eq!(perm, Perm::RW);
        assert!(m.map_fixed(0x5000_0000, 0x1000, Perm::RW, "dup").is_err());
        let old = m.protect(0x5000_0000, 0x2000, Perm::RX).unwrap();
        assert_eq!(old, Perm::RW);
        assert_eq!(m.next_region(0x5000_0000).unwrap().2, Perm::RX);
        m.unmap(0x5000_0000, 0).unwrap();
        assert!(m.read_u8(0x5000_0000).is_err());
    }

    #[test]
    fn next_region_reports_free_gap() {
        let m = mem();
        let (base, _, _) = m.next_region(0x9000).unwrap();
        assert_eq!(base, 0x400000);
        assert!(m.next_region(0x9000_0000).is_none());
    }

    fn rwx_mem() -> VirtualMemory {
        let mut m = VirtualMemory::new();
        m.map(Region::new("data", 0x1000, 0x1000, Perm::RW)).unwrap();
        m.map(Region::new("code", 0x400000, 0x4000, Perm::RWX)).unwrap();
        m
    }

    #[test]
    fn data_writes_never_bump_the_code_generation() {
        let mut m = rwx_mem();
        assert_eq!(m.code_generation(), 0);
        m.write_u64(0x1100, 0xdead_beef).unwrap();
        m.write_u8(0x1200, 0xff).unwrap();
        assert_eq!(m.code_generation(), 0);
        assert_eq!(m.code_page_generation(0x1000), 0);
    }

    #[test]
    fn write_into_executable_region_bumps_global_and_page_gen() {
        let mut m = rwx_mem();
        let before = m.code_page_generation(0x400000);
        assert_eq!((m.code_generation(), before), (0, 0));
        m.write_u8(0x400010, 0x90).unwrap();
        assert_eq!(m.code_generation(), 1);
        assert_eq!(m.code_page_generation(0x400000), 1);
        m.write_u8(0x400020, 0x90).unwrap();
        assert_eq!(m.code_generation(), 2);
        assert_eq!(m.code_page_generation(0x400000), 2);
        assert_eq!(m.code_page_generation(0x401000), 0);
    }

    #[test]
    fn per_page_generations_are_independent() {
        let mut m = rwx_mem();
        m.write_u8(0x400000, 0x90).unwrap();
        m.write_u8(0x402000, 0x90).unwrap();
        m.write_u8(0x402008, 0x90).unwrap();
        assert_eq!(m.code_page_generation(0x400000), 1);
        assert_eq!(m.code_page_generation(0x401000), 0);
        assert_eq!(m.code_page_generation(0x402000), 2);
        assert_eq!(m.code_generation(), 3);
    }

    #[test]
    fn write_spanning_a_page_boundary_bumps_both_pages() {
        let mut m = rwx_mem();
        m.write_u64(0x401000 - 4, 0).unwrap();
        assert_eq!(m.code_generation(), 1);
        assert_eq!(m.code_page_generation(0x400ffc), 1);
        assert_eq!(m.code_page_generation(0x401000), 1);
    }

    #[test]
    fn loader_poke_into_code_also_bumps_the_seam() {
        let mut m = rwx_mem();
        m.poke(0x400100, &[0xcc]).unwrap();
        assert_eq!(m.code_generation(), 1);
        assert_eq!(m.code_page_generation(0x400000), 1);
        m.poke(0x1000, &[0x00]).unwrap();
        assert_eq!(m.code_generation(), 1);
    }
}
