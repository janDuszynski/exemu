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
// MEM_MAPPED (data/file-backed) and MEM_IMAGE (SEC_IMAGE) label a section view's
// `VmAlloc.mtype`; the section code (roadmap W2.7) sets them. Defined here so the
// type-value vocabulary lives beside MEM_PRIVATE and `write_mbi` reports them.
#[allow(dead_code)] // first setter is the W2.7 section code.
pub(crate) const MEM_MAPPED: u32 = 0x0004_0000;
#[allow(dead_code)] // first setter is the W2.7 section code.
pub(crate) const MEM_IMAGE: u32 = 0x0100_0000;

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
    /// `MEMORY_BASIC_INFORMATION.Type` reported for the region: `MEM_PRIVATE`
    /// for an ordinary `VirtualAlloc`/`NtAllocateVirtualMemory` reservation,
    /// `MEM_IMAGE` for a `SEC_IMAGE` section view, `MEM_MAPPED` for a
    /// data/file-backed section view (both filled in by the section code, W2.7).
    pub mtype: u32,
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
        let base = self.vm_alloc_region(mem, addr_req, size_req, alloc_type, protect)?;
        Ok(Outcome::Return(base))
    }

    /// VirtualFree(lpAddress, dwSize, dwFreeType).
    pub(crate) fn virtual_free(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let free_type = self.arg(cpu, mem, 2)? as u32;
        self.vm_free_region(mem, addr, free_type);
        Ok(Outcome::Return(1))
    }

    /// VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect).
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

    /// VirtualQuery(lpAddress, lpBuffer, dwLength) → bytes written (0 on fail).
    pub(crate) fn virtual_query(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let addr = self.arg(cpu, mem, 0)?;
        let buf = self.arg(cpu, mem, 1)?;
        self.vm_query_region(mem, addr, buf)
    }

    // --- Shared region-mutation core (the Win32 `Virtual*` and the NT
    // `Nt*VirtualMemory` syscalls, W2.6, both drive these). Plain-argument
    // helpers that own the `vm_allocs`/mapping logic; the outer wrappers only
    // marshal the ABI (registers / `Outcome` vs NTSTATUS + IN/OUT pointers). ---

    /// Reserve and/or commit a region, returning its page-aligned base (0 on
    /// out-of-memory, with `last_error` set). Shared by `VirtualAlloc` and
    /// `NtAllocateVirtualMemory`. `addr_req == 0` picks a free window; a nonzero
    /// address commits inside a prior reservation or fixes a fresh map there.
    pub(crate) fn vm_alloc_region(
        &mut self,
        mem: &mut dyn Memory,
        addr_req: u64,
        size_req: u64,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64> {
        let committed = alloc_type & MEM_COMMIT != 0;
        let size = align_up(size_req.max(1), PAGE);

        if addr_req == 0 {
            // Fresh reservation: find a free, 64 KiB-aligned window and back it
            // permissively (the tracked `protect` carries the nominal value).
            let base = self.vm_find_free(mem, size);
            if mem.map_fixed(base, size, Perm::RWX, "valloc").is_err() {
                self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                return Ok(0);
            }
            self.vm_insert(VmAlloc { base, size, protect, committed, mtype: MEM_PRIVATE });
            return Ok(base);
        }

        // Explicit address: committing inside a prior reservation, or a new
        // fixed map.
        let base = addr_req & !(PAGE - 1);
        if let Some(a) = self.vm_allocs.iter_mut().find(|a| base >= a.base && base < a.base + a.size) {
            a.committed = a.committed || committed;
            if protect != 0 {
                a.protect = protect;
            }
            return Ok(base);
        }
        // Not ours: map it fixed if the range is free, else treat the commit as
        // already satisfied (the address falls inside image/stack/heap).
        let free_here = mem.next_region(base).map_or(true, |(rb, _, _)| rb >= base + size);
        if free_here && mem.map_fixed(base, size, Perm::RWX, "valloc").is_ok() {
            self.vm_insert(VmAlloc { base, size, protect, committed, mtype: MEM_PRIVATE });
        }
        Ok(base)
    }

    /// Release (unmap) or decommit a region. Shared by `VirtualFree` and
    /// `NtFreeVirtualMemory`. `MEM_RELEASE` unmaps the whole reservation;
    /// `MEM_DECOMMIT` just clears its commit state.
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

    /// Set a region's nominal protection and return the previous value (0x40 /
    /// PAGE_EXECUTE_READWRITE for a pre-existing non-`VirtualAlloc` region).
    /// Shared by `VirtualProtect` and `NtProtectVirtualMemory`.
    pub(crate) fn vm_protect_region(&mut self, addr: u64, new_protect: u32) -> u32 {
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
        old
    }

    /// Resolve the region containing `addr` and write a `MEMORY_BASIC_INFORMATION`
    /// into `buf`, returning the bytes written (0 on a null buffer). Shared by
    /// `VirtualQuery` and `NtQueryVirtualMemory(MemoryBasicInformation)`.
    pub(crate) fn vm_query_region(&mut self, mem: &mut dyn Memory, addr: u64, buf: u64) -> Result<Outcome> {
        let page_base = addr & !(PAGE - 1);

        // 1) One of our own reservations: report its tracked protection/state.
        if let Some(a) = self.vm_allocs.iter().find(|a| addr >= a.base && addr < a.base + a.size) {
            let (base, size, prot, comm, mtype) = (a.base, a.size, a.protect, a.committed, a.mtype);
            let region_size = base + size - page_base;
            let state = if comm { MEM_STATE_COMMIT } else { MEM_STATE_RESERVE };
            let prot_out = if comm { prot } else { 0 };
            return self.write_mbi(mem, buf, page_base, base, prot, region_size, state, prot_out, mtype);
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

    /// Reserve and back a fresh region of `size` bytes somewhere free in the
    /// VirtualAlloc arena, returning its base — used for thread stacks (P3.4)
    /// as well as `VirtualAlloc(NULL, …)`. `None` if the mapping fails.
    pub(crate) fn map_anywhere(&mut self, mem: &mut dyn Memory, size: u64, perm: exemu_core::Perm, name: &str) -> Option<u64> {
        let base = self.vm_find_free(mem, size);
        mem.map_fixed(base, size, perm, name).ok().map(|()| base)
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

// ---------------------------------------------------------------------------
// NT memory syscalls (roadmap W2.6) — the NTSTATUS / IN-OUT-pointer face of the
// same VM manager the Win32 `Virtual*` APIs drive.
//
// Wine's PE `ntdll.dll` reaches these through a raw `SYSCALL` (the SSDT index in
// EAX, recovered from the pinned guest stubs' `mov eax,N`): NtAllocateVirtualMemory
// = 0x18, NtFreeVirtualMemory = 0x1e, NtProtectVirtualMemory = 0x50,
// NtQueryVirtualMemory = 0x23. The W2.3 dispatcher has already saved the context
// and switched to the unix stack; each handler reads its arguments via
// [`WinOs::syscall_arg`] (arg0=R10, arg1=RDX, arg2=R8, arg3=R9, args 5+ on the
// guest stack) and returns an NTSTATUS the dispatcher places in RAX.
//
// The IN/OUT pointer contract (public `winternl.h` / ntifs.h): `*BaseAddress`
// and `*RegionSize` are read on entry and written back with the actual base /
// size; `NtProtect` writes `*OldProtect`; `NtQuery` writes the buffer and the
// optional `*ReturnLength`. Clean-room Class B: signatures from the public NT
// headers, indices from the pinned guest binary — no Wine `.c` was read.

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_INVALID_PARAMETER` — a required pointer argument was NULL, or an
/// unsupported memory-information class was requested.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_NO_MEMORY` — the reservation could not be backed.
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// `MEMORY_INFORMATION_CLASS::MemoryBasicInformation` (value 0) — the class
/// backing `VirtualQuery`. `MemoryWineUnixFuncs` (1000) is handled separately in
/// [`crate::unixlib`].
pub(crate) const MEMORY_BASIC_INFORMATION: u32 = 0;

impl WinOs {
    /// `NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
    /// *RegionSize, AllocationType, Protect)`. arg0=process (ignored — the
    /// current-process pseudo-handle at the gate), arg1=&BaseAddress,
    /// arg2=ZeroBits, arg3=&RegionSize, arg4=AllocationType, arg5=Protect.
    pub(crate) fn nt_allocate_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base_ptr = self.syscall_arg(cpu, mem, 1)?;
        let size_ptr = self.syscall_arg(cpu, mem, 3)?;
        let alloc_type = self.syscall_arg(cpu, mem, 4)? as u32;
        let protect = self.syscall_arg(cpu, mem, 5)? as u32;
        if base_ptr == 0 || size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // IN/OUT: the caller's requested base (may be 0 = "you pick") and size.
        let addr_req = mem.read_u64(base_ptr)?;
        let size_req = mem.read_u64(size_ptr)?;
        let base = self.vm_alloc_region(mem, addr_req, size_req, alloc_type, protect)?;
        if base == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        // Write back the actual base and the page-rounded size.
        mem.write_u64(base_ptr, base)?;
        mem.write_u64(size_ptr, align_up(size_req.max(1), PAGE))?;
        Ok(STATUS_SUCCESS)
    }

    /// `NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType)`.
    /// arg0=process, arg1=&BaseAddress, arg2=&RegionSize, arg3=FreeType.
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
        // On a full release the actual base/size freed are the reservation's;
        // fall back to the page-aligned request otherwise.
        if let Some((base, size)) = region {
            mem.write_u64(base_ptr, base)?;
            if size_ptr != 0 {
                mem.write_u64(size_ptr, size)?;
            }
        }
        Ok(STATUS_SUCCESS)
    }

    /// `NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize,
    /// NewProtect, *OldProtect)`. arg0=process, arg1=&BaseAddress,
    /// arg2=&RegionSize, arg3=NewProtect, arg4=&OldProtect.
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

    /// `NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
    /// Buffer, Length, *ReturnLength)`. The `MemoryWineUnixFuncs` class is served
    /// in [`crate::unixlib`]; W2.6 adds `MemoryBasicInformation` (the
    /// `VirtualQuery` payload). arg0=process, arg1=base, arg2=class, arg3=buffer,
    /// arg4=length, arg5=&ReturnLength.
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

    /// The reservation bounds (`base`, `size`) containing `addr`, if it is one of
    /// our own `vm_allocs` regions. Used by `NtFreeVirtualMemory` to report the
    /// actual base/size freed before the reservation is dropped.
    fn vm_region_bounds(&self, addr: u64) -> Option<(u64, u64)> {
        self.vm_allocs
            .iter()
            .find(|a| addr >= a.base && addr < a.base + a.size)
            .map(|a| (a.base, a.size))
    }
}

/// SSDT thunk for `NtAllocateVirtualMemory` (index 0x18).
pub(crate) fn ssdt_nt_allocate_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_allocate_virtual_memory(cpu, mem)
}

/// SSDT thunk for `NtFreeVirtualMemory` (index 0x1e).
pub(crate) fn ssdt_nt_free_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_free_virtual_memory(cpu, mem)
}

/// SSDT thunk for `NtProtectVirtualMemory` (index 0x50).
pub(crate) fn ssdt_nt_protect_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_protect_virtual_memory(cpu, mem)
}

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
pub(crate) const SSDT_NT_FREE_VIRTUAL_MEMORY: u32 = 0x1e;
pub(crate) const SSDT_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x50;
