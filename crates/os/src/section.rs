use std::io::{Read, Seek, SeekFrom};

use exemu_core::{CpuState, Memory, Perm, Result};

use crate::vm::{VmAlloc, MEM_IMAGE, MEM_MAPPED};
use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

const SEC_IMAGE: u32 = 0x0100_0000;

const SECTION_IMAGE_INFORMATION: u64 = 1;
const SECTION_IMAGE_INFORMATION_LEN: u64 = 0x40;

const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_I386: u16 = 0x014c;

const PAGE: u64 = 0x1000;

pub(crate) const SSDT_NT_CREATE_SECTION: u32 = 0x4a;
pub(crate) const SSDT_NT_MAP_VIEW_OF_SECTION: u32 = 0x28;
pub(crate) const SSDT_NT_UNMAP_VIEW_OF_SECTION: u32 = 0x2a;
pub(crate) const SSDT_NT_QUERY_SECTION: u32 = 0x51;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

pub(crate) struct SectionImage {
    pub image_base: u64,
    pub size_of_image: u64,
    pub entry_rva: u32,
    pub subsystem: u16,
    pub stack_reserve: u64,
    pub is_64bit: bool,
    pub headers: Vec<u8>,
    pub sections: Vec<ImageSection>,
    pub dll_name: Option<String>,
}

pub(crate) struct ImageSection {
    pub rva: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
}

pub(crate) struct Section {
    pub data: Vec<u8>,
    pub size: u64,
    pub mtype: u32,
    pub protect: u32,
    pub image: Option<SectionImage>,
}

impl WinOs {
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

        let data = if file_handle != 0 {
            match self.read_file_backing(file_handle) {
                Some(d) => d,
                None => return Ok(STATUS_INVALID_HANDLE),
            }
        } else {
            Vec::new()
        };

        let is_image = alloc_attrs & SEC_IMAGE != 0;

        let image = if is_image && !data.is_empty() {
            self.images.parse(&data).ok().map(|pe| SectionImage {
                image_base: pe.image_base,
                size_of_image: pe.size_of_image as u64,
                entry_rva: pe.entry_rva,
                subsystem: pe.subsystem,
                stack_reserve: pe.stack_reserve,
                is_64bit: pe.is_64bit,
                headers: pe.headers,
                dll_name: pe.dll_name.clone(),
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

        let Some(img) = section.image.as_ref() else {
            return Ok(STATUS_INVALID_INFO_CLASS);
        };
        let transfer_address = img.image_base.wrapping_add(img.entry_rva as u64);
        let max_stack = img.stack_reserve.max(PAGE);
        let committed_stack = PAGE.min(max_stack);
        let subsystem = img.subsystem as u32;
        let machine = if img.is_64bit { MACHINE_AMD64 } else { MACHINE_I386 };

        let mut buf = [0u8; SECTION_IMAGE_INFORMATION_LEN as usize];
        buf[0x00..0x08].copy_from_slice(&transfer_address.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&max_stack.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&committed_stack.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(&subsystem.to_le_bytes());
        buf[0x30..0x32].copy_from_slice(&machine.to_le_bytes());
        buf[0x32] = 1;
        buf[0x33] = 0;
        mem.write(info_ptr, &buf)?;

        if ret_len_ptr != 0 {
            mem.write_u64(ret_len_ptr, SECTION_IMAGE_INFORMATION_LEN)?;
        }
        Ok(STATUS_SUCCESS)
    }

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
        if self.sections[&section_handle].image.is_some() {
            return self.map_image_view(mem, section_handle, base_ptr, size_ptr, offset_ptr);
        }
        self.map_flat_view(mem, section_handle, base_ptr, offset_ptr, size_ptr)
    }

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

        let offset = if offset_ptr != 0 { mem.read_u64(offset_ptr)? } else { 0 };
        let want = if size_ptr != 0 { mem.read_u64(size_ptr)? } else { 0 };
        let view_size = if want != 0 {
            align_up(want, PAGE)
        } else {
            align_up(sec_size.saturating_sub(offset).max(1), PAGE)
        };

        let req_base = mem.read_u64(base_ptr)?;
        let base = if req_base != 0 {
            let base = req_base & !(0x1_0000 - 1);
            if mem.map_fixed(base, view_size, Perm::RWX, "section-view").is_err() {
                return Ok(STATUS_NO_MEMORY);
            }
            base
        } else {
            let placed = if self.wow64_peb32 != 0 {
                self.map_anywhere_low(mem, view_size, Perm::RWX, "section-view")
            } else {
                self.map_anywhere(mem, view_size, Perm::RWX, "section-view")
            };
            match placed {
                Some(b) => b,
                None => return Ok(STATUS_NO_MEMORY),
            }
        };

        let start = (offset as usize).min(data.len());
        let copy_len = ((view_size as usize).min(data.len().saturating_sub(start))) as u64;
        if copy_len != 0 {
            mem.write(base, &data[start..start + copy_len as usize])?;
        }

        self.vm_insert_view(VmAlloc { base, size: view_size, protect, committed: true, mtype });

        mem.write_u64(base_ptr, base)?;
        mem.write_u64(size_ptr, view_size)?;
        if offset_ptr != 0 {
            mem.write_u64(offset_ptr, offset)?;
        }
        Ok(STATUS_SUCCESS)
    }

    fn map_image_view(
        &mut self,
        mem: &mut dyn Memory,
        section_handle: u64,
        base_ptr: u64,
        size_ptr: u64,
        offset_ptr: u64,
    ) -> Result<u32> {
        let section = &self.sections[&section_handle];
        let protect = section.protect;
        let img = section.image.as_ref().expect("image view requires parsed PE");
        let view_size = align_up(img.size_of_image.max(PAGE), PAGE);
        let headers = img.headers.clone();
        let dll_name = img.dll_name.clone();
        let sections: Vec<(u32, u32, Vec<u8>)> = img
            .sections
            .iter()
            .map(|s| (s.rva, s.virtual_size, s.data.clone()))
            .collect();
        let is_64bit = img.is_64bit;

        let req_base = mem.read_u64(base_ptr)?;
        let base = if req_base != 0 {
            let base = req_base & !(0x1_0000 - 1);
            if mem.map_fixed(base, view_size, Perm::RWX, "image-view").is_err() {
                return Ok(STATUS_NO_MEMORY);
            }
            base
        } else {
            let placed = if is_64bit {
                self.map_anywhere(mem, view_size, Perm::RWX, "image-view")
            } else {
                self.map_anywhere_low(mem, view_size, Perm::RWX, "image-view")
            };
            match placed {
                Some(b) => b,
                None => return Ok(STATUS_NO_MEMORY),
            }
        };

        if !headers.is_empty() {
            let hlen = (headers.len() as u64).min(view_size) as usize;
            mem.write(base, &headers[..hlen])?;
        }

        for (rva, vsize, data) in &sections {
            let seg_base = base.wrapping_add(*rva as u64);
            let end_off = (*rva as u64).saturating_add(*vsize as u64).min(view_size);
            let avail = end_off.saturating_sub(*rva as u64) as usize;
            let n = data.len().min(avail);
            if n != 0 {
                mem.write(seg_base, &data[..n])?;
            }
        }

        self.vm_insert_view(VmAlloc {
            base,
            size: view_size,
            protect,
            committed: true,
            mtype: MEM_IMAGE,
        });
        if self.cfg.trace {
            if let Some(n) = &dll_name {
                if let Some((prev, pbase, _)) =
                    self.loaded_modules().into_iter().find(|(m, _, _)| m.eq_ignore_ascii_case(n))
                {
                    eprintln!("[exemu] warning: duplicate image map {n} at {base:#x} (already {prev} at {pbase:#x})");
                }
            }
        }
        self.record_image_view(base, view_size, dll_name);

        mem.write_u64(base_ptr, base)?;
        mem.write_u64(size_ptr, view_size)?;
        if offset_ptr != 0 {
            mem.write_u64(offset_ptr, 0)?;
        }
        Ok(STATUS_SUCCESS)
    }

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
        self.forget_image_view(base);
        Ok(STATUS_SUCCESS)
    }
}

pub(crate) fn ssdt_nt_create_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_create_section(cpu, mem)
}

pub(crate) fn ssdt_nt_query_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_section(cpu, mem)
}

pub(crate) fn ssdt_nt_map_view_of_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_map_view_of_section(cpu, mem)
}

pub(crate) fn ssdt_nt_unmap_view_of_section(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_unmap_view_of_section(cpu, mem)
}
