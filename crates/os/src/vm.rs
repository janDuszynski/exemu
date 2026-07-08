//! The `VirtualAlloc` family: a small user-space virtual-memory manager.
//!
//! `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/`VirtualQuery` back real,
//! distinct regions in the guest address space (via the [`Memory`] mapping
//! primitives added for this purpose) while tracking each reservation's nominal
//! `PAGE_*` protection and commit state here. That lets `VirtualQuery` and
//! `VirtualProtect` report honest values even though the backing pages are
//! mapped permissively (RWX) — the emulator's deliberate DEP-relaxed stance
//! that lets packers/JITs execute pages they allocated writable.

use exemu_core::{CpuState, Memory, Perm, Result};

use crate::api::Outcome;
use crate::WinOs;

// flAllocationType bits.
const MEM_COMMIT: u32 = 0x0000_1000;
// dwFreeType bits.
const MEM_DECOMMIT: u32 = 0x0000_4000;
const MEM_RELEASE: u32 = 0x0000_8000;
// MEMORY_BASIC_INFORMATION.State values.
const MEM_STATE_COMMIT: u32 = 0x0000_1000;
const MEM_STATE_RESERVE: u32 = 0x0000_2000;
const MEM_STATE_FREE: u32 = 0x0001_0000;
// MEMORY_BASIC_INFORMATION.Type values.
const MEM_PRIVATE: u32 = 0x0002_0000;

const PAGE: u64 = 0x1000; // 4 KiB page
const GRAN: u64 = 0x1_0000; // 64 KiB allocation granularity

/// One `VirtualAlloc` reservation.
pub(crate) struct VmAlloc {
    /// 64 KiB-aligned allocation base (the `AllocationBase` for every page).
    pub base: u64,
    /// Reserved size in bytes (page-aligned).
    pub size: u64,
    /// Nominal `PAGE_*` protection last requested for the region.
    pub protect: u32,
    /// Committed (MEM_COMMIT) vs reserve-only.
    pub committed: bool,
}

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// Map a coarse access permission to the `PAGE_*` constant that best describes
/// it (used only to report protection for pre-existing, non-VirtualAlloc
/// regions such as the image, stack and heap).
fn protect_from_perm(p: Perm) -> u32 {
    match (p.contains(Perm::EXEC), p.contains(Perm::WRITE), p.contains(Perm::READ)) {
        (true, true, _) => 0x40,      // PAGE_EXECUTE_READWRITE
        (true, false, true) => 0x20,  // PAGE_EXECUTE_READ
        (true, false, false) => 0x10, // PAGE_EXECUTE
        (false, true, _) => 0x04,     // PAGE_READWRITE
        (false, false, true) => 0x02, // PAGE_READONLY
        (false, false, false) => 0x01, // PAGE_NOACCESS
    }
}

impl WinOs {
    /// VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect).
    pub(crate) fn virtual_alloc(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr_req = self.arg(cpu, mem, 0)?;
        let size_req = self.arg(cpu, mem, 1)?;
        let alloc_type = self.arg(cpu, mem, 2)? as u32;
        let protect = self.arg(cpu, mem, 3)? as u32;
        let committed = alloc_type & MEM_COMMIT != 0;
        let size = align_up(size_req.max(1), PAGE);

        if addr_req == 0 {
            // Fresh reservation: find a free, 64 KiB-aligned window and back it
            // permissively (the tracked `protect` carries the nominal value).
            let base = self.vm_find_free(mem, size);
            if mem.map_fixed(base, size, Perm::RWX, "valloc").is_err() {
                self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                return Ok(Outcome::Return(0));
            }
            self.vm_insert(VmAlloc { base, size, protect, committed });
            return Ok(Outcome::Return(base));
        }

        // Explicit address: committing inside a prior reservation, or a new
        // fixed map.
        let base = addr_req & !(PAGE - 1);
        if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
            a.committed = a.committed || committed;
            if protect != 0 {
                a.protect = protect;
            }
            return Ok(Outcome::Return(base));
        }
        // Not ours: map it fixed if the range is free, else treat the commit as
        // already satisfied (the address falls inside image/stack/heap).
        let free_here = mem.next_region(base).map_or(true, |(rb, _, _)| rb >= base + size);
        if free_here && mem.map_fixed(base, size, Perm::RWX, "valloc").is_ok() {
            self.vm_insert(VmAlloc { base, size, protect, committed });
            return Ok(Outcome::Return(base));
        }
        Ok(Outcome::Return(base))
    }

    /// VirtualFree(lpAddress, dwSize, dwFreeType).
    pub(crate) fn virtual_free(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let free_type = self.arg(cpu, mem, 2)? as u32;
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
        Ok(Outcome::Return(1))
    }

    /// VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect).
    pub(crate) fn virtual_protect(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let new_protect = self.arg(cpu, mem, 2)? as u32;
        let old_ptr = self.arg(cpu, mem, 3)?;
        let base = addr & !(PAGE - 1);
        // Report the previous nominal protection (RWX for pre-existing regions).
        let old = self
            .vm_allocs
            .iter()
            .find(|a| base >= a.base && base < a.base + a.size)
            .map_or(0x40, |a| a.protect);
        if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
            a.protect = new_protect;
        }
        if old_ptr != 0 {
            mem.write_u32(old_ptr, old)?;
        }
        Ok(Outcome::Return(1))
    }

    /// VirtualQuery(lpAddress, lpBuffer, dwLength) → bytes written (0 on fail).
    pub(crate) fn virtual_query(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let buf = self.arg(cpu, mem, 1)?;
        let page_base = addr & !(PAGE - 1);

        // 1) One of our own reservations: report its tracked protection/state.
        if let Some(a) = self.vm_allocs.iter().find(|a| addr >= a.base && addr < a.base + a.size) {
            let (base, size, prot, comm) = (a.base, a.size, a.protect, a.committed);
            let region_size = base + size - page_base;
            let state = if comm { MEM_STATE_COMMIT } else { MEM_STATE_RESERVE };
            let prot_out = if comm { prot } else { 0 };
            return self.write_mbi(mem, buf, page_base, base, prot, region_size, state, prot_out, MEM_PRIVATE);
        }

        // 2) Another mapped region (image/stack/heap/teb/…): committed.
        // 3) Otherwise a free gap up to the next region (or the top of space).
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

    /// Find a free, 64 KiB-aligned base for at least `size` bytes at/above the
    /// bump hint, then advance the hint past it.
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

    /// Insert a reservation, keeping `vm_allocs` sorted by base.
    fn vm_insert(&mut self, a: VmAlloc) {
        let pos = self.vm_allocs.partition_point(|x| x.base < a.base);
        self.vm_allocs.insert(pos, a);
    }

    /// Write a `MEMORY_BASIC_INFORMATION` (32- or 64-bit layout) into guest
    /// memory and return the number of bytes written.
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
