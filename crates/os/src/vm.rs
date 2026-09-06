use exemu_core::{CpuState, Memory, Perm, Result};

use crate::api::Outcome;
use crate::WinOs;

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_DECOMMIT: u32 = 0x0000_4000;
const MEM_RELEASE: u32 = 0x0000_8000;
const MEM_STATE_COMMIT: u32 = 0x0000_1000;
const MEM_STATE_RESERVE: u32 = 0x0000_2000;
const MEM_STATE_FREE: u32 = 0x0001_0000;
const MEM_PRIVATE: u32 = 0x0002_0000;
#[allow(dead_code)]
pub(crate) const MEM_MAPPED: u32 = 0x0004_0000;
#[allow(dead_code)]
pub(crate) const MEM_IMAGE: u32 = 0x0100_0000;

const PAGE: u64 = 0x1000;
const GRAN: u64 = 0x1_0000;

const LOW_ARENA_BASE: u64 = 0x1_0000;

fn zero_bits_ceiling(zero_bits: u64) -> u64 {
    match zero_bits {
        0 => u64::MAX,
        n if n < 32 => (1u64 << (64 - n)) - 1,
        mask => mask,
    }
}

pub(crate) struct VmAlloc {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub committed: bool,
    pub mtype: u32,
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn protect_from_perm(p: Perm) -> u32 {
    match (p.contains(Perm::EXEC), p.contains(Perm::WRITE), p.contains(Perm::READ)) {
        (true, true, _) => 0x40,
        (true, false, true) => 0x20,
        (true, false, false) => 0x10,
        (false, true, _) => 0x04,
        (false, false, true) => 0x02,
        (false, false, false) => 0x01,
    }
}

impl WinOs {
    pub(crate) fn virtual_alloc(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr_req = self.arg(cpu, mem, 0)?;
        let size_req = self.arg(cpu, mem, 1)?;
        let alloc_type = self.arg(cpu, mem, 2)? as u32;
        let protect = self.arg(cpu, mem, 3)? as u32;
        let base = self.vm_alloc_region(mem, addr_req, size_req, alloc_type, protect)?;
        Ok(Outcome::Return(base))
    }

    pub(crate) fn virtual_free(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let free_type = self.arg(cpu, mem, 2)? as u32;
        self.vm_free_region(mem, addr, free_type);
        Ok(Outcome::Return(1))
    }

    pub(crate) fn virtual_protect(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let new_protect = self.arg(cpu, mem, 2)? as u32;
        let old_ptr = self.arg(cpu, mem, 3)?;
        let old = self.vm_protect_region(addr, new_protect);
        if old_ptr != 0 {
            mem.write_u32(old_ptr, old)?;
        }
        Ok(Outcome::Return(1))
    }

    pub(crate) fn virtual_query(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let buf = self.arg(cpu, mem, 1)?;
        self.vm_query_region(mem, addr, buf)
    }

    pub(crate) fn vm_alloc_region(
        &mut self,
        mem: &mut dyn Memory,
        addr_req: u64,
        size_req: u64,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64> {
        self.vm_alloc_region_below(mem, addr_req, size_req, alloc_type, protect, u64::MAX)
    }

    pub(crate) fn vm_alloc_region_below(
        &mut self,
        mem: &mut dyn Memory,
        addr_req: u64,
        size_req: u64,
        alloc_type: u32,
        protect: u32,
        max_addr: u64,
    ) -> Result<u64> {
        let committed = alloc_type & MEM_COMMIT != 0;
        let size = align_up(size_req.max(1), PAGE);

        if addr_req == 0 {
            let Some(base) = self.vm_find_free_below(mem, size, max_addr) else {
                self.last_error = 8;
                return Ok(0);
            };
            if mem.map_fixed(base, size, Perm::RWX, "valloc").is_err() {
                self.last_error = 8;
                return Ok(0);
            }
            self.vm_insert(VmAlloc { base, size, protect, committed, mtype: MEM_PRIVATE });
            return Ok(base);
        }

        let base = addr_req & !(PAGE - 1);
        if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
            a.committed = a.committed || committed;
            if protect != 0 {
                a.protect = protect;
            }
            return Ok(base);
        }
        let free_here = mem.next_region(base).map_or(true, |(rb, _, _)| rb >= base + size);
        if free_here && mem.map_fixed(base, size, Perm::RWX, "valloc").is_ok() {
            self.vm_insert(VmAlloc { base, size, protect, committed, mtype: MEM_PRIVATE });
        }
        Ok(base)
    }

    pub(crate) fn vm_free_region(&mut self, mem: &mut dyn Memory, addr: u64, free_type: u32) {
        let base = addr & !(PAGE - 1);
        if free_type & MEM_RELEASE != 0 {
            if let Some(pos) = self.vm_allocs.iter().position(|a| a.base == base) {
                let a = self.vm_allocs.remove(pos);
                let _ = mem.unmap(a.base, 0);
            }
        } else if free_type & MEM_DECOMMIT != 0 {
            if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
                a.committed = false;
            }
        }
    }

    pub(crate) fn vm_protect_region(&mut self, addr: u64, new_protect: u32) -> u32 {
        let base = addr & !(PAGE - 1);
        let old = self
            .vm_allocs
            .iter()
            .find(|a| base >= a.base && base < a.base + a.size)
            .map_or(0x40, |a| a.protect);
        if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
            a.protect = new_protect;
        }
        old
    }

    pub(crate) fn vm_query_region(&mut self, mem: &mut dyn Memory, addr: u64, buf: u64) -> Result<Outcome> {
        let page_base = addr & !(PAGE - 1);

        if let Some(a) = self.vm_allocs.iter().find(|a| addr >= a.base && addr < a.base + a.size) {
            let (base, size, prot, comm, mtype) = (a.base, a.size, a.protect, a.committed, a.mtype);
            let region_size = base + size - page_base;
            let state = if comm { MEM_STATE_COMMIT } else { MEM_STATE_RESERVE };
            let prot_out = if comm { prot } else { 0 };
            return self.write_mbi(mem, buf, page_base, base, prot, region_size, state, prot_out, mtype);
        }

        match mem.next_region(addr) {
            Some((rb, rsize, rperm)) if rb <= addr => {
                let prot = protect_from_perm(rperm);
                let region_size = rb + rsize - page_base;
                self.write_mbi(mem, buf, page_base, rb, prot, region_size, MEM_STATE_COMMIT, prot, MEM_PRIVATE)
            }
            Some((rb, _, _)) => self.write_mbi(mem, buf, page_base, 0, 0, rb - page_base, MEM_STATE_FREE, 0, 0),
            None => self.write_mbi(mem, buf, page_base, 0, 0, 0x1000_0000, MEM_STATE_FREE, 0, 0),
        }
    }

    pub(crate) fn map_anywhere(&mut self, mem: &mut dyn Memory, size: u64, perm: exemu_core::Perm, name: &str) -> Option<u64> {
        let base = self.vm_find_free(mem, size);
        mem.map_fixed(base, size, perm, name).ok().map(|()| base)
    }

    pub(crate) fn map_anywhere_low(
        &mut self,
        mem: &mut dyn Memory,
        size: u64,
        perm: exemu_core::Perm,
        name: &str,
    ) -> Option<u64> {
        let base = self.vm_find_free_below(mem, size, u32::MAX as u64)?;
        mem.map_fixed(base, size, perm, name).ok().map(|()| base)
    }

    fn vm_find_free_below(&mut self, mem: &dyn Memory, size: u64, max_addr: u64) -> Option<u64> {
        if max_addr == u64::MAX {
            return Some(self.vm_find_free(mem, size));
        }
        let mut base = LOW_ARENA_BASE;
        loop {
            if base.checked_add(size)? - 1 > max_addr {
                return None;
            }
            match mem.next_region(base) {
                None => return Some(base),
                Some((rb, rsize, _)) => {
                    if rb >= base + size {
                        return Some(base);
                    }
                    base = align_up(rb + rsize, GRAN);
                }
            }
        }
    }

    fn vm_find_free(&mut self, mem: &dyn Memory, size: u64) -> u64 {
        let mut base = align_up(self.valloc_next, GRAN);
        loop {
            match mem.next_region(base) {
                None => break,
                Some((rb, rsize, _)) => {
                    if rb >= base.saturating_add(size) {
                        break;
                    }
                    base = align_up(rb + rsize, GRAN);
                }
            }
        }
        self.valloc_next = base + align_up(size, GRAN);
        base
    }

    fn vm_insert(&mut self, a: VmAlloc) {
        let pos = self.vm_allocs.partition_point(|x| x.base < a.base);
        self.vm_allocs.insert(pos, a);
    }

    pub(crate) fn vm_insert_view(&mut self, a: VmAlloc) {
        self.vm_insert(a);
    }

    pub(crate) fn vm_view_base(&self, addr: u64) -> Option<u64> {
        self.vm_allocs.iter().find(|a| a.base == addr).map(|a| a.base)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_mbi(
        &self,
        mem: &mut dyn Memory,
        buf: u64,
        base: u64,
        alloc_base: u64,
        alloc_protect: u32,
        region_size: u64,
        state: u32,
        protect: u32,
        mtype: u32,
    ) -> Result<Outcome> {
        if buf == 0 {
            return Ok(Outcome::Return(0));
        }
        if self.cfg.is_64bit {
            mem.write_u64(buf, base)?;
            mem.write_u64(buf + 0x08, alloc_base)?;
            mem.write_u32(buf + 0x10, alloc_protect)?;
            mem.write_u32(buf + 0x14, 0)?;
            mem.write_u64(buf + 0x18, region_size)?;
            mem.write_u32(buf + 0x20, state)?;
            mem.write_u32(buf + 0x24, protect)?;
            mem.write_u32(buf + 0x28, mtype)?;
            mem.write_u32(buf + 0x2C, 0)?;
            Ok(Outcome::Return(0x30))
        } else {
            mem.write_u32(buf, base as u32)?;
            mem.write_u32(buf + 0x04, alloc_base as u32)?;
            mem.write_u32(buf + 0x08, alloc_protect)?;
            mem.write_u32(buf + 0x0C, region_size as u32)?;
            mem.write_u32(buf + 0x10, state)?;
            mem.write_u32(buf + 0x14, protect)?;
            mem.write_u32(buf + 0x18, mtype)?;
            Ok(Outcome::Return(0x1C))
        }
    }
}

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

pub(crate) const MEMORY_BASIC_INFORMATION: u32 = 0;

impl WinOs {
    pub(crate) fn nt_allocate_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_ptr = self.syscall_arg(cpu, mem, 1)?;
        let zero_bits = self.syscall_arg(cpu, mem, 2)?;
        let size_ptr = self.syscall_arg(cpu, mem, 3)?;
        let alloc_type = self.syscall_arg(cpu, mem, 4)? as u32;
        let protect = self.syscall_arg(cpu, mem, 5)? as u32;
        if base_ptr == 0 || size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let addr_req = mem.read_u64(base_ptr)?;
        let size_req = mem.read_u64(size_ptr)?;
        let max_addr = zero_bits_ceiling(zero_bits);
        let base =
            self.vm_alloc_region_below(mem, addr_req, size_req, alloc_type, protect, max_addr)?;
        if base == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        mem.write_u64(base_ptr, base)?;
        mem.write_u64(size_ptr, align_up(size_req.max(1), PAGE))?;
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_free_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_ptr = self.syscall_arg(cpu, mem, 1)?;
        let size_ptr = self.syscall_arg(cpu, mem, 2)?;
        let free_type = self.syscall_arg(cpu, mem, 3)? as u32;
        if base_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let addr = mem.read_u64(base_ptr)?;
        let region = self.vm_region_bounds(addr);
        self.vm_free_region(mem, addr, free_type);
        if let Some((base, size)) = region {
            mem.write_u64(base_ptr, base)?;
            if size_ptr != 0 {
                mem.write_u64(size_ptr, size)?;
            }
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_protect_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_ptr = self.syscall_arg(cpu, mem, 1)?;
        let new_protect = self.syscall_arg(cpu, mem, 3)? as u32;
        let old_ptr = self.syscall_arg(cpu, mem, 4)?;
        if base_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let addr = mem.read_u64(base_ptr)?;
        let old = self.vm_protect_region(addr, new_protect);
        if old_ptr != 0 {
            mem.write_u32(old_ptr, old)?;
        }
        Ok(STATUS_SUCCESS)
    }

    pub(crate) fn nt_query_virtual_memory_basic(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_address = self.syscall_arg(cpu, mem, 1)?;
        let buffer = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let return_length = self.syscall_arg(cpu, mem, 5)?;

        let need = if self.cfg.is_64bit { 0x30 } else { 0x1C };
        if buffer == 0 || length < need {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Outcome::Return(written) = self.vm_query_region(mem, base_address, buffer)? else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        if return_length != 0 {
            mem.write_u64(return_length, written)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn vm_region_bounds(&self, addr: u64) -> Option<(u64, u64)> {
        self.vm_allocs
            .iter()
            .find(|a| addr >= a.base && addr < a.base + a.size)
            .map(|a| (a.base, a.size))
    }
}

pub(crate) fn ssdt_nt_allocate_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_allocate_virtual_memory(cpu, mem)
}

pub(crate) fn ssdt_nt_free_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_free_virtual_memory(cpu, mem)
}

pub(crate) fn ssdt_nt_protect_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_protect_virtual_memory(cpu, mem)
}

pub(crate) const SSDT_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
pub(crate) const SSDT_NT_FREE_VIRTUAL_MEMORY: u32 = 0x1e;
pub(crate) const SSDT_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x50;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_memory::VirtualMemory;

    #[test]
    fn zero_bits_ceiling_covers_both_documented_forms() {
        assert_eq!(zero_bits_ceiling(0), u64::MAX, "0 = unconstrained");
        assert_eq!(zero_bits_ceiling(32), 32, "≥32 is a highest-address mask, not a bit count");
        assert_eq!(zero_bits_ceiling(0x7fff_ffff), 0x7fff_ffff, "the WoW64 low-2 GiB ceiling");
        assert_eq!(zero_bits_ceiling(33) >> 31, 0, "33 leading zero bits ⇒ a 31-bit address");
        assert_eq!(zero_bits_ceiling(1), u64::MAX >> 1, "1 leading zero bit");
    }

    #[test]
    fn zero_bits_ceiling_places_the_allocation_low() {
        let mut mem = VirtualMemory::new();
        let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });

        let high = os.vm_alloc_region(&mut mem, 0, 0x2000, MEM_COMMIT, 0x04).unwrap();
        assert!(high > u32::MAX as u64, "the default arena is above 4 GiB (got {high:#x})");

        let low = os
            .vm_alloc_region_below(&mut mem, 0, 0x2000, MEM_COMMIT, 0x04, 0x7fff_ffff)
            .unwrap();
        assert_ne!(low, 0, "the constrained allocation succeeded");
        assert!(low >= LOW_ARENA_BASE, "clear of the null-guard window");
        assert!(low + 0x2000 - 1 <= 0x7fff_ffff, "the whole region is under the ceiling");
        assert_eq!(low & (GRAN - 1), 0, "64 KiB aligned");
        mem.write_u32(low, 0xC0FFEE).unwrap();

        let low2 = os
            .vm_alloc_region_below(&mut mem, 0, 0x2000, MEM_COMMIT, 0x04, 0x7fff_ffff)
            .unwrap();
        assert!(low2 >= low + 0x2000 || low2 + 0x2000 <= low, "the two regions are disjoint");
        assert_eq!(mem.read_u32(low).unwrap(), 0xC0FFEE, "the first region survived");

        assert_eq!(
            os.vm_alloc_region_below(&mut mem, 0, 0x2000, MEM_COMMIT, 0x04, 0x1000).unwrap(),
            0,
            "an impossible ceiling reports out-of-memory",
        );
    }
}
