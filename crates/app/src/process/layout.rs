use std::path::PathBuf;

use exemu_core::PeImage;
use exemu_cpu::{FS_BASE_32, GS_BASE};

use crate::wow64_boot;

pub(super) struct Layout {
    pub(super) stack_base: u64,
    pub(super) stack_size: u64,
    pub(super) heap_base: u64,
    pub(super) heap_size: u64,
    pub(super) api_base: u64,
    pub(super) dll_base: u64,
    pub(super) dll_size: u64,
    pub(super) env_base: u64,
    pub(super) teb_base: u64,
    pub(super) peb_addr: u64,
    pub(super) teb_self: u64,
    pub(super) teb_peb: u64,
    pub(super) teb_stack_base: u64,
    pub(super) teb_stack_limit: u64,
    pub(super) peb_image_base: u64,
    pub(super) peb_ldr_off: u64,
    pub(super) peb_loaderlock_off: u64,
    pub(super) valloc_base: u64,
}

impl Layout {
    pub(super) fn for_bits(is_64bit: bool) -> Layout {
        if is_64bit {
            Layout {
                stack_base: 0x0000_0010_0000_0000,
                stack_size: 0x0020_0000,
                heap_base: 0x0000_0002_0000_0000,
                heap_size: 0x0400_0000,
                api_base: 0x0000_7EFF_0000_0000,
                dll_base: 0x0000_0006_0000_0000,
                dll_size: 0x0800_0000,
                env_base: 0x0000_0000_5000_0000,
                teb_base: GS_BASE,
                peb_addr: GS_BASE + 0x2000,
                teb_self: 0x30,
                teb_peb: 0x60,
                teb_stack_base: 0x08,
                teb_stack_limit: 0x10,
                peb_image_base: 0x10,
                peb_ldr_off: 0x18,
                peb_loaderlock_off: 0x110,
                valloc_base: 0x0000_0040_0000_0000,
            }
        } else {
            Layout {
                stack_base: 0x0018_0000,
                stack_size: 0x0020_0000,
                heap_base: 0x1000_0000,
                heap_size: 0x0400_0000,
                api_base: 0x7000_0000,
                dll_base: 0x2000_0000,
                dll_size: 0x0400_0000,
                env_base: 0x0010_0000,
                teb_base: FS_BASE_32,
                peb_addr: FS_BASE_32 + 0x2000,
                teb_self: 0x18,
                teb_peb: 0x30,
                teb_stack_base: 0x04,
                teb_stack_limit: 0x08,
                peb_image_base: 0x08,
                peb_ldr_off: 0x0c,
                peb_loaderlock_off: 0xa0,
                valloc_base: 0x3000_0000,
            }
        }
    }

    pub(super) fn for_wow64() -> Layout {
        Layout {
            teb_base: wow64_boot::WOW64_TEB64,
            peb_addr: wow64_boot::WOW64_PEB64,
            ..Layout::for_bits(true)
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct BootCtx<'a> {
    pub(super) lay: &'a Layout,
    pub(super) image: &'a PeImage,
    pub(super) base: u64,
    pub(super) stack_top: u64,
    pub(super) wine_dll_dir: &'a Option<String>,
    pub(super) wow64_dir32: &'a Option<PathBuf>,
}
