//! Section objects — the file-backed / pagefile-backed shared-memory primitive
//! Wine's PE loader (`LdrLoadDll`) drives to map a DLL image (roadmap W2.7).
//!
//! Wine's PE `ntdll.dll` loads a module by opening the `.dll` file, creating a
//! **`SEC_IMAGE`** section over that file handle, mapping a view of it, and then
//! reading the PE headers/sections back through the mapped view. exemu models
//! the three syscalls that path issues:
//!
//! * `NtCreateSection` — create a section object over an (optional) file handle,
//!   snapshotting its bytes as the section's backing store. `SEC_IMAGE` in
//!   `AllocationAttributes` marks the view's [`vm::VmAlloc::mtype`] `MEM_IMAGE`
//!   (`VirtualQuery`/`NtQueryVirtualMemory` then reports the region as image);
//!   otherwise it is `MEM_MAPPED`. A NULL file handle is a pagefile-backed
//!   (zero-filled) section.
//! * `NtMapViewOfSection` — reserve a region (the caller's `BaseAddress` if
//!   non-NULL, else picked from the VirtualAlloc arena), copy the section's
//!   backing bytes into it, and register a `VmAlloc` so the view queries as a
//!   real committed region of the right `Type`.
//! * `NtUnmapViewOfSection` — release the view (unmap the backing, drop the
//!   `VmAlloc`).
//!
//! **Clean-room note (Class B).** The three signatures come from the public NT
//! headers (`ntifs.h` `NtCreateSection`, `wdm.h` `ZwMapViewOfSection`); the SSDT
//! indices (`NtCreateSection`=0x4a, `NtMapViewOfSection`=0x28,
//! `NtUnmapViewOfSection`=0x2a) were recovered from the pinned guest
//! `ntdll.dll` stubs' `mov eax,N` immediates — no Wine `.c` was read.

use std::io::{Read, Seek, SeekFrom};

use exemu_core::{CpuState, Memory, Perm, Result};

use crate::vm::{VmAlloc, MEM_IMAGE, MEM_MAPPED};
use crate::WinOs;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_INVALID_PARAMETER` — a required OUT pointer was NULL.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_INVALID_HANDLE` — the section handle names no live section.
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// `STATUS_NO_MEMORY` — the view's backing region could not be mapped.
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// `SEC_IMAGE` (in `AllocationAttributes`): map the section as an executable
/// image, so its view reports `MEM_IMAGE`. Public `winnt.h` value.
const SEC_IMAGE: u32 = 0x0100_0000;

const PAGE: u64 = 0x1000;

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_CREATE_SECTION: u32 = 0x4a;
pub(crate) const SSDT_NT_MAP_VIEW_OF_SECTION: u32 = 0x28;
pub(crate) const SSDT_NT_UNMAP_VIEW_OF_SECTION: u32 = 0x2a;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// One section object: a snapshot of its backing bytes plus the memory `Type`
/// (`MEM_IMAGE`/`MEM_MAPPED`) and nominal protection a view of it reports.
pub(crate) struct Section {
    /// Backing bytes (a snapshot of the file at create time, or empty for a
    /// zero-filled pagefile-backed section). A mapped view is `data`, then zero
    /// fill out to the (page-rounded) view size.
    pub data: Vec<u8>,
    /// Page-rounded section size in bytes.
    pub size: u64,
    /// The view's reported `MEMORY_BASIC_INFORMATION.Type`
    /// (`MEM_IMAGE` for `SEC_IMAGE`, else `MEM_MAPPED`).
    pub mtype: u32,
    /// Nominal `PAGE_*` protection recorded for a view of the section.
    pub protect: u32,
}

impl WinOs {
    /// Read the whole content of an open guest file handle (rewinding first, and
    /// restoring the cursor afterwards) as the section's backing snapshot.
    fn read_file_backing(&mut self, file_handle: u64) -> Option<Vec<u8>> {
        let of = self.files.get_mut(&file_handle)?;
        let saved = of.file.stream_position().ok();
        of.file.seek(SeekFrom::Start(0)).ok()?;
        let mut buf = Vec::new();
        of.file.read_to_end(&mut buf).ok()?;
        if let Some(pos) = saved {
            let _ = of.file.seek(SeekFrom::Start(pos));
        }
        Some(buf)
    }

    /// `NtCreateSection(*SectionHandle, DesiredAccess, *ObjectAttributes,
    /// *MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)`.
    /// arg0=&SectionHandle, arg1=DesiredAccess, arg2=&ObjectAttributes,
    /// arg3=&MaximumSize, arg4=SectionPageProtection, arg5=AllocationAttributes,
    /// arg6=FileHandle.
    pub(crate) fn nt_create_section(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle_ptr = self.syscall_arg(cpu, mem, 0)?;
        let max_size_ptr = self.syscall_arg(cpu, mem, 3)?;
        let page_protect = self.syscall_arg(cpu, mem, 4)? as u32;
        let alloc_attrs = self.syscall_arg(cpu, mem, 5)? as u32;
        let file_handle = self.syscall_arg(cpu, mem, 6)?;
        if handle_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }

        // Snapshot the backing file (NULL FileHandle = pagefile-backed = empty).
        let data = if file_handle != 0 {
            match self.read_file_backing(file_handle) {
                Some(d) => d,
                None => return Ok(STATUS_INVALID_HANDLE),
            }
        } else {
            Vec::new()
        };

        // The section size is `MaximumSize` if given, else the backing length;
        // rounded up to a page.
        let requested = if max_size_ptr != 0 { mem.read_u64(max_size_ptr)? } else { 0 };
        let size = align_up(requested.max(data.len() as u64).max(1), PAGE);

        let mtype = if alloc_attrs & SEC_IMAGE != 0 { MEM_IMAGE } else { MEM_MAPPED };
        let handle = self.next_handle;
        self.next_handle += 4;
        self.sections.insert(handle, Section { data, size, mtype, protect: page_protect });
        mem.write_u64(handle_ptr, handle)?;
        Ok(STATUS_SUCCESS)
    }

    /// `NtMapViewOfSection(SectionHandle, ProcessHandle, *BaseAddress, ZeroBits,
    /// CommitSize, *SectionOffset, *ViewSize, InheritDisposition, AllocationType,
    /// Win32Protect)`. arg0=SectionHandle, arg1=ProcessHandle(ignored),
    /// arg2=&BaseAddress, arg3=ZeroBits, arg4=CommitSize, arg5=&SectionOffset,
    /// arg6=&ViewSize, arg7=InheritDisposition, arg8=AllocationType,
    /// arg9=Win32Protect.
    pub(crate) fn nt_map_view_of_section(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let section_handle = self.syscall_arg(cpu, mem, 0)?;
        let base_ptr = self.syscall_arg(cpu, mem, 2)?;
        let offset_ptr = self.syscall_arg(cpu, mem, 5)?;
        let size_ptr = self.syscall_arg(cpu, mem, 6)?;
        if base_ptr == 0 || size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let Some(section) = self.sections.get(&section_handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        let (data, sec_size, mtype, protect) =
            (section.data.clone(), section.size, section.mtype, section.protect);

        // View parameters (all optional). SectionOffset and ViewSize default to
        // "the whole section from the start"; a nonzero ViewSize is honoured,
        // page-rounded.
        let offset = if offset_ptr != 0 { mem.read_u64(offset_ptr)? } else { 0 };
        let want = if size_ptr != 0 { mem.read_u64(size_ptr)? } else { 0 };
        let view_size = if want != 0 {
            align_up(want, PAGE)
        } else {
            align_up(sec_size.saturating_sub(offset).max(1), PAGE)
        };

        // Reserve the region: honour a caller-supplied BaseAddress (64 KiB
        // rounded down), else pick a free window from the VirtualAlloc arena.
        let req_base = mem.read_u64(base_ptr)?;
        let base = if req_base != 0 {
            let base = req_base & !(0x1_0000 - 1);
            if mem.map_fixed(base, view_size, Perm::RWX, "section-view").is_err() {
                return Ok(STATUS_NO_MEMORY);
            }
            base
        } else {
            match self.map_anywhere(mem, view_size, Perm::RWX, "section-view") {
                Some(b) => b,
                None => return Ok(STATUS_NO_MEMORY),
            }
        };

        // Copy the section's backing bytes (from `offset`) into the view; the
        // tail past the backing stays zero (the region is mapped zero-filled).
        let start = (offset as usize).min(data.len());
        let copy_len = ((view_size as usize).min(data.len().saturating_sub(start))) as u64;
        if copy_len != 0 {
            mem.write(base, &data[start..start + copy_len as usize])?;
        }

        // Register the view as a committed reservation so `NtQueryVirtualMemory`
        // reports it with the section's `Type` (MEM_IMAGE / MEM_MAPPED).
        self.vm_insert_view(VmAlloc { base, size: view_size, protect, committed: true, mtype });

        mem.write_u64(base_ptr, base)?;
        mem.write_u64(size_ptr, view_size)?;
        if offset_ptr != 0 {
            mem.write_u64(offset_ptr, offset)?;
        }
        Ok(STATUS_SUCCESS)
    }

    /// `NtUnmapViewOfSection(ProcessHandle, BaseAddress)`. arg0=ProcessHandle
    /// (ignored), arg1=BaseAddress. Releases the view's backing region.
    pub(crate) fn nt_unmap_view_of_section(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let base = self.syscall_arg(cpu, mem, 1)?;
        const MEM_RELEASE: u32 = 0x0000_8000;
        if self.vm_view_base(base).is_none() {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        self.vm_free_region(mem, base, MEM_RELEASE);
        Ok(STATUS_SUCCESS)
    }
}

/// SSDT thunk for `NtCreateSection` (index 0x4a).
pub(crate) fn ssdt_nt_create_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_create_section(cpu, mem)
}

/// SSDT thunk for `NtMapViewOfSection` (index 0x28).
pub(crate) fn ssdt_nt_map_view_of_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_map_view_of_section(cpu, mem)
}

/// SSDT thunk for `NtUnmapViewOfSection` (index 0x2a).
pub(crate) fn ssdt_nt_unmap_view_of_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_unmap_view_of_section(cpu, mem)
}
