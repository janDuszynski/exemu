//! Section objects — the file-backed / pagefile-backed shared-memory primitive
//! Wine's PE loader drives to map a DLL image (roadmap W2.7 / W3.2).
//!
//! Wine's PE `ntdll.dll` `loader_init` loads kernel32/kernelbase/ucrtbase by
//! opening the `.dll` file, creating a **`SEC_IMAGE`** section over that file
//! handle, querying its image information, mapping a view of it, and then
//! letting `build_module` relocate/fix-up the mapped image itself. exemu models
//! the syscalls that path issues:
//!
//! * `NtCreateSection` — create a section object over an (optional) file handle.
//!   For a **non-image** (MEM_MAPPED / pagefile) section it snapshots the file's
//!   bytes as a flat backing store (the W2.7 path, unchanged). For a **`SEC_IMAGE`**
//!   section it additionally parses the backing file as a PE and stores the parsed
//!   per-section RVA layout (base, size-of-image, entry, stack, machine…) so the
//!   view can be laid out in memory the way the real image loader would.
//! * `NtQuerySection` — answer `SectionImageInformation` (class 1): a 0x40-byte
//!   `SECTION_IMAGE_INFORMATION` (`TransferAddress`, stack sizes, subsystem,
//!   `Machine`, image flags) that Wine's `open_dll_file` reads back after
//!   `ZwCreateSection` to sanity-check the image before mapping it.
//! * `NtMapViewOfSection` — reserve a region and populate it. For an image
//!   section it reserves `SizeOfImage`, lays valid PE headers at the base and
//!   each section's raw bytes at `base + VirtualAddress` **un-relocated** (the
//!   guest's `build_module` applies the base relocations itself), zero-filling
//!   section tails / `.bss`, and writes the chosen base back to `*BaseAddress`.
//!   For a non-image section it flat-copies the backing (the W2.7 path).
//! * `NtUnmapViewOfSection` — release the view (unmap the backing, drop the
//!   `VmAlloc`).
//!
//! **No relocation (confirmed against the pinned ntdll, roadmap W3.2).** The
//! image is mapped with absolute addresses still pointing at the preferred
//! `ImageBase` (0x170000000). Guest ntdll's `build_module` @0x44b70 relocates
//! the mapped image itself (bias = actual_base − preferred_ImageBase, added
//! additively via `LdrProcessRelocationBlock`), bracketed by
//! `NtProtectVirtualMemory`. Applying relocations here would double-relocate and
//! corrupt the image, so `NtMapViewOfSection` MUST NOT touch the fixup sites.
//!
//! **Clean-room note (Class B).** The three signatures come from the public NT
//! headers (`ntifs.h` `NtCreateSection`, `wdm.h` `ZwMapViewOfSection`); the SSDT
//! indices (`NtCreateSection`=0x4a, `NtMapViewOfSection`=0x28,
//! `NtUnmapViewOfSection`=0x2a, `NtQuerySection`=0x51) were recovered from the
//! pinned guest `ntdll.dll` stubs' `mov eax,N` immediates. The
//! `SECTION_IMAGE_INFORMATION` field offsets used are the public winternl-family
//! layout, cross-checked against the pinned `open_dll_file` @0x56b40 consumer's
//! `cmp word [rbp+0x30],0x8664` / `cmp byte [rbp+0x32],0` / `test byte [rbp+0x33],1`.

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
/// `STATUS_INVALID_INFO_CLASS` — an unsupported `NtQuerySection` class.
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
/// `STATUS_INFO_LENGTH_MISMATCH` — the query buffer is too small.
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// `SEC_IMAGE` (in `AllocationAttributes`): map the section as an executable
/// image, so its view reports `MEM_IMAGE`. Public `winnt.h` value.
const SEC_IMAGE: u32 = 0x0100_0000;

/// `SectionImageInformation` — the `NtQuerySection` class Wine reads back after
/// creating a `SEC_IMAGE` section. Public `winternl.h` `SECTION_INFORMATION_CLASS`.
const SECTION_IMAGE_INFORMATION: u64 = 1;
/// Byte length of a `SECTION_IMAGE_INFORMATION` (x64). Wine passes exactly this
/// as the query length (`mov r9d,0x40` at `open_dll_file+0x290`).
const SECTION_IMAGE_INFORMATION_LEN: u64 = 0x40;

/// `IMAGE_FILE_MACHINE_AMD64`. `open_dll_file` gates on `[info+0x30] == 0x8664`.
const MACHINE_AMD64: u16 = 0x8664;

const PAGE: u64 = 0x1000;

/// SSDT indices, recovered from the pinned guest `ntdll.dll` stubs' `mov eax,N`.
pub(crate) const SSDT_NT_CREATE_SECTION: u32 = 0x4a;
pub(crate) const SSDT_NT_MAP_VIEW_OF_SECTION: u32 = 0x28;
pub(crate) const SSDT_NT_UNMAP_VIEW_OF_SECTION: u32 = 0x2a;
/// `NtQuerySection` — `ZwQuerySection` @ ntdll RVA 0xf350 (`mov eax,0x51`). Free
/// index; `NtResumeThread` is 0x52 (no collision).
pub(crate) const SSDT_NT_QUERY_SECTION: u32 = 0x51;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// The per-section pieces of a parsed PE image needed to lay it out in memory
/// image-mode and to answer `NtQuerySection(SectionImageInformation)`.
///
/// Stored on a `SEC_IMAGE` `Section` at create time (parsed once, from the
/// backing file) so `NtQuerySection` and `NtMapViewOfSection` never re-read the
/// file. Absolute addresses in the section bytes are left **at the preferred
/// `ImageBase`** — the guest relocates the mapped copy itself.
pub(crate) struct SectionImage {
    /// Preferred load address (`OptionalHeader.ImageBase`). The mapped image is
    /// laid out un-relocated relative to this base.
    pub image_base: u64,
    /// Total virtual size of the image (page/section-aligned), the reservation
    /// size for a view.
    pub size_of_image: u64,
    /// Entry point RVA; `TransferAddress = image_base + entry_rva`.
    pub entry_rva: u32,
    /// Windows subsystem (2 = GUI, 3 = console) → `SubSystemType`.
    pub subsystem: u16,
    /// Amount of stack the image asks the loader to reserve → `MaximumStackSize`.
    pub stack_reserve: u64,
    /// The raw PE header bytes (mapped at the image base so `RtlImageNtHeader`
    /// finds MZ/PE at `base` / `base+e_lfanew`).
    pub headers: Vec<u8>,
    /// Per-section placement: `(rva, virtual_size, raw_data, r, w, x)`.
    pub sections: Vec<ImageSection>,
}

/// One section's in-memory placement, straight from `exemu_loader::parse`.
///
/// Only the `(rva, virtual_size, data)` placement is retained: the reservation
/// is backed RWX (exemu's deliberate DEP-relaxed stance, matching the rest of
/// the loader) and the guest's `build_module` reprotects individual pages via
/// `NtProtectVirtualMemory` as it relocates, so the per-section characteristic
/// bits are not needed for the in-memory copy.
pub(crate) struct ImageSection {
    pub rva: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
}

/// One section object: a snapshot of its backing bytes plus the memory `Type`
/// (`MEM_IMAGE`/`MEM_MAPPED`) and nominal protection a view of it reports. When
/// `image` is `Some`, the section is a `SEC_IMAGE` image section whose view is
/// laid out per-section (see [`WinOs::nt_map_view_of_section`]); otherwise a
/// view is `data` flat-copied then zero-filled to the view size (W2.7).
pub(crate) struct Section {
    /// Backing bytes (a snapshot of the file at create time, or empty for a
    /// zero-filled pagefile-backed section). A mapped **non-image** view is
    /// `data`, then zero fill out to the (page-rounded) view size.
    pub data: Vec<u8>,
    /// Page-rounded section size in bytes (non-image view size).
    pub size: u64,
    /// The view's reported `MEMORY_BASIC_INFORMATION.Type`
    /// (`MEM_IMAGE` for `SEC_IMAGE`, else `MEM_MAPPED`).
    pub mtype: u32,
    /// Nominal `PAGE_*` protection recorded for a view of the section.
    pub protect: u32,
    /// The parsed PE layout for a `SEC_IMAGE` section (`None` for a plain
    /// MEM_MAPPED / pagefile section — the W2.7 flat path).
    pub image: Option<SectionImage>,
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

        let is_image = alloc_attrs & SEC_IMAGE != 0;

        // For a SEC_IMAGE section backed by a real file, parse the PE now and
        // store the per-section RVA layout so the view can be laid out image-mode
        // (per-section RVAs, un-relocated). A file that does not parse as a PE
        // keeps `image = None` and falls back to the flat W2.7 copy — still typed
        // MEM_IMAGE — which is the correct behaviour for the W2.7 "fake image"
        // test and harmless for a real (non-PE) mapping. Non-image and
        // pagefile-backed sections are always flat (image = None).
        let image = if is_image && !data.is_empty() {
            exemu_loader::parse(&data).ok().map(|pe| SectionImage {
                image_base: pe.image_base,
                size_of_image: pe.size_of_image as u64,
                entry_rva: pe.entry_rva,
                subsystem: pe.subsystem,
                stack_reserve: pe.stack_reserve,
                headers: pe.headers,
                sections: pe
                    .sections
                    .into_iter()
                    .map(|s| ImageSection {
                        rva: s.rva,
                        virtual_size: s.virtual_size,
                        data: s.data,
                    })
                    .collect(),
            })
        } else {
            None
        };

        // The section size is `MaximumSize` if given, else (for an image) the
        // whole SizeOfImage, else the backing length; rounded up to a page.
        let requested = if max_size_ptr != 0 { mem.read_u64(max_size_ptr)? } else { 0 };
        let image_size = image.as_ref().map(|i| i.size_of_image).unwrap_or(0);
        let size = align_up(requested.max(image_size).max(data.len() as u64).max(1), PAGE);

        let mtype = if is_image { MEM_IMAGE } else { MEM_MAPPED };
        let handle = self.next_handle;
        self.next_handle += 4;
        self.sections.insert(handle, Section { data, size, mtype, protect: page_protect, image });
        mem.write_u64(handle_ptr, handle)?;
        Ok(STATUS_SUCCESS)
    }

    /// `NtQuerySection(SectionHandle, SectionInformationClass, *SectionInformation,
    /// SectionInformationLength, *ReturnLength)`. arg0=SectionHandle,
    /// arg1=SectionInformationClass, arg2=&SectionInformation, arg3=Length,
    /// arg4=&ReturnLength.
    ///
    /// Only `SectionImageInformation` (class 1) is served — the class Wine's
    /// `open_dll_file` issues after `ZwCreateSection(SEC_IMAGE)`. It fills a
    /// 0x40-byte `SECTION_IMAGE_INFORMATION` from the section's parsed PE:
    ///
    /// | off  | field                | value                              |
    /// | ---- | -------------------- | ---------------------------------- |
    /// | 0x00 | TransferAddress      | `image_base + entry_rva`           |
    /// | 0x10 | MaximumStackSize     | `stack_reserve`                    |
    /// | 0x18 | CommittedStackSize   | one page (nonzero, ≤ maximum)      |
    /// | 0x20 | SubSystemType        | `subsystem`                        |
    /// | 0x30 | Machine (u16)        | 0x8664 (AMD64)                     |
    /// | 0x32 | ImageContainsCode    | 1                                  |
    /// | 0x33 | ImageFlags           | 0 (bit0 clear)                     |
    ///
    /// The consumer gates on `Machine == 0x8664` (→ accept, close file, return
    /// SUCCESS). The 0x32/0x33 bytes are only reached on the *non*-AMD64 branch,
    /// but are filled correctly regardless: `[+0x32] != 0` (has code) so the
    /// `cmp byte [rbp+0x32],0; je accept` is not taken purely on emptiness, and
    /// `[+0x33] bit0 == 0` so `test byte [rbp+0x33],1; jne accept` is likewise a
    /// no-op — the AMD64 machine check is the sole gate for our images.
    pub(crate) fn nt_query_section(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let section_handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)?;
        let info_ptr = self.syscall_arg(cpu, mem, 2)?;
        let info_len = self.syscall_arg(cpu, mem, 3)?;
        let ret_len_ptr = self.syscall_arg(cpu, mem, 4)?;

        let Some(section) = self.sections.get(&section_handle) else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        if class != SECTION_IMAGE_INFORMATION {
            return Ok(STATUS_INVALID_INFO_CLASS);
        }
        if info_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if info_len < SECTION_IMAGE_INFORMATION_LEN {
            if ret_len_ptr != 0 {
                mem.write_u64(ret_len_ptr, SECTION_IMAGE_INFORMATION_LEN)?;
            }
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }

        // Derive the image info. A SEC_IMAGE section always parsed the PE at
        // create time; a non-image section has no image information to report.
        let Some(img) = section.image.as_ref() else {
            return Ok(STATUS_INVALID_INFO_CLASS);
        };
        let transfer_address = img.image_base.wrapping_add(img.entry_rva as u64);
        let max_stack = img.stack_reserve.max(PAGE);
        let committed_stack = PAGE.min(max_stack);
        let subsystem = img.subsystem as u32;

        // Zero the whole 0x40-byte struct, then fill the fields Wine reads.
        let mut buf = [0u8; SECTION_IMAGE_INFORMATION_LEN as usize];
        buf[0x00..0x08].copy_from_slice(&transfer_address.to_le_bytes()); // TransferAddress
        buf[0x10..0x18].copy_from_slice(&max_stack.to_le_bytes()); // MaximumStackSize
        buf[0x18..0x20].copy_from_slice(&committed_stack.to_le_bytes()); // CommittedStackSize
        buf[0x20..0x24].copy_from_slice(&subsystem.to_le_bytes()); // SubSystemType
        buf[0x30..0x32].copy_from_slice(&MACHINE_AMD64.to_le_bytes()); // Machine
        buf[0x32] = 1; // ImageContainsCode
        buf[0x33] = 0; // ImageFlags (bit0 clear)
        mem.write(info_ptr, &buf)?;

        if ret_len_ptr != 0 {
            mem.write_u64(ret_len_ptr, SECTION_IMAGE_INFORMATION_LEN)?;
        }
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
        if !self.sections.contains_key(&section_handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        // Image sections take the per-section layout path; everything else keeps
        // the W2.7 flat copy.
        if self.sections[&section_handle].image.is_some() {
            return self.map_image_view(mem, section_handle, base_ptr, size_ptr, offset_ptr);
        }
        self.map_flat_view(mem, section_handle, base_ptr, offset_ptr, size_ptr)
    }

    /// Non-image (`MEM_MAPPED` / pagefile) view: reserve the region and flat-copy
    /// the backing bytes, zero-filling the tail (the unchanged W2.7 path).
    fn map_flat_view(
        &mut self,
        mem: &mut dyn Memory,
        section_handle: u64,
        base_ptr: u64,
        offset_ptr: u64,
        size_ptr: u64,
    ) -> Result<u32> {
        let section = &self.sections[&section_handle];
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

    /// Image (`SEC_IMAGE`) view: reserve `SizeOfImage`, lay valid PE headers at
    /// the chosen base and each section's raw bytes at `base + VirtualAddress`
    /// **un-relocated**, zero-fill section tails / `.bss`, and write the chosen
    /// base back to `*BaseAddress`. Wine passes `BaseAddress = 0` (the map picks
    /// the base and writes it back); a caller-provided base is honoured.
    ///
    /// **Does NOT apply base relocations** — the guest's `build_module` relocates
    /// the mapped copy itself; double-relocating would corrupt the image.
    fn map_image_view(
        &mut self,
        mem: &mut dyn Memory,
        section_handle: u64,
        base_ptr: u64,
        size_ptr: u64,
        offset_ptr: u64,
    ) -> Result<u32> {
        // Snapshot everything the layout needs before any &mut self borrow
        // (map_anywhere) so the immutable section borrow can end here.
        let section = &self.sections[&section_handle];
        let protect = section.protect;
        let img = section.image.as_ref().expect("image view requires parsed PE");
        let view_size = align_up(img.size_of_image.max(PAGE), PAGE);
        let headers = img.headers.clone();
        let sections: Vec<(u32, u32, Vec<u8>)> = img
            .sections
            .iter()
            .map(|s| (s.rva, s.virtual_size, s.data.clone()))
            .collect();

        // Reserve SizeOfImage: honour a caller base (64 KiB rounded down), else
        // pick a free window. Back it RWX so the guest's NtProtectVirtualMemory
        // bracket around relocation can flip protections freely.
        let req_base = mem.read_u64(base_ptr)?;
        let base = if req_base != 0 {
            let base = req_base & !(0x1_0000 - 1);
            if mem.map_fixed(base, view_size, Perm::RWX, "image-view").is_err() {
                return Ok(STATUS_NO_MEMORY);
            }
            base
        } else {
            match self.map_anywhere(mem, view_size, Perm::RWX, "image-view") {
                Some(b) => b,
                None => return Ok(STATUS_NO_MEMORY),
            }
        };

        // 1) PE headers at base (RtlImageNtHeader checks MZ @base, PE\0\0
        //    @base+e_lfanew). The reservation is zero-filled, so writing just
        //    the header bytes leaves the rest of the header page zero.
        if !headers.is_empty() {
            let hlen = (headers.len() as u64).min(view_size) as usize;
            mem.write(base, &headers[..hlen])?;
        }

        // 2) Each section's raw bytes at base + VirtualAddress, un-relocated.
        //    The backing region is zero-filled, so a section whose raw data is
        //    shorter than its VirtualSize (tail / .bss) is already zero past the
        //    copied bytes — no explicit zeroing needed beyond clamping the copy.
        for (rva, vsize, data) in &sections {
            let seg_base = base.wrapping_add(*rva as u64);
            // Clamp the write into the reservation and to the section's virtual
            // size (never spill initialized bytes past VirtualSize).
            let end_off = (*rva as u64).saturating_add(*vsize as u64).min(view_size);
            let avail = end_off.saturating_sub(*rva as u64) as usize;
            let n = data.len().min(avail);
            if n != 0 {
                mem.write(seg_base, &data[..n])?;
            }
        }

        // Register the view so NtQueryVirtualMemory reports it as MEM_IMAGE.
        self.vm_insert_view(VmAlloc {
            base,
            size: view_size,
            protect,
            committed: true,
            mtype: MEM_IMAGE,
        });

        mem.write_u64(base_ptr, base)?;
        // Report the full image size back through *ViewSize, and echo the (zero)
        // section offset if the caller passed a SectionOffset cell.
        mem.write_u64(size_ptr, view_size)?;
        if offset_ptr != 0 {
            mem.write_u64(offset_ptr, 0)?;
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

/// SSDT thunk for `NtQuerySection` (index 0x51).
pub(crate) fn ssdt_nt_query_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_section(cpu, mem)
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
