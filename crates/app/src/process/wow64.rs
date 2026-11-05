use exemu_core::{EmuError, Memory, Result};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;
use exemu_os::WinOs;

use crate::config::RunConfig;
use crate::kuser::{KUSER_SHARED_DATA_BASE, KUSER_SYSTEM_CALL};
use crate::{wow64_boot, wow64_image};

use super::layout::BootCtx;
use super::wine::map_wine_debug_pages;

pub(super) fn bring_up(
    os: &mut WinOs,
    cpu: &mut Interpreter,
    mem: &mut VirtualMemory,
    cfg: &RunConfig,
    ctx: &BootCtx,
) -> Result<wow64_boot::Wow64Boot> {
    let BootCtx { lay, image, base, stack_top, wine_dll_dir, wow64_dir32 } = *ctx;
    let Some(ntdll_base) = os.load_wine_core(mem)? else {
        return Err(EmuError::Os(
            "WoW64 boot: the 64-bit Wine core would not load from the pinned prefix".into(),
        ));
    };
    map_wine_debug_pages(mem, lay.teb_base, lay.peb_addr)?;
    mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &0u32.to_le_bytes())?;

    let dir64 = wine_dll_dir.clone().unwrap_or_default();
    let dir32 = wow64_dir32.clone().unwrap_or_default();
    let dirs = wow64_boot::Wow64Dirs {
        dir64: std::path::Path::new(&dir64),
        dir32: &dir32,
    };
    let ntdll64_bytes = std::fs::read(dirs.dir64.join("ntdll.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot re-read ntdll.dll: {e}")))?;
    let ntdll64 = wow64_image::image_view(&ntdll64_bytes, ntdll_base)?;

    let boot = wow64_boot::build(mem, &dirs, &ntdll64, base)?;
    if cfg.wow64_bringup == wow64_boot::Bringup::Direct {
        let (bound, missing) =
            wow64_boot::bind_guest_imports(mem, base, &image.imports, &boot)?;
        if !missing.is_empty() {
            return Err(EmuError::Os(format!(
                "WoW64 boot (direct bring-up): {} guest import(s) unresolved against the \
                 32-bit Wine set — this program needs the Wine-loader bring-up: {}",
                missing.len(),
                missing.join(", ")
            )));
        }
        let _ = bound;
    }

    let pp32 = os
        .build_wow64_process_parameters(mem, wow64_boot::WOW64_PARAMS, wow64_boot::WOW64_PARAMS_SIZE)?
        .ok_or_else(|| {
            EmuError::Os("WoW64 boot: the 32-bit process-parameter arena is too small".into())
        })?;
    mem.write_u32(boot.peb32 + exemu_os::wow64::peb32::PROCESS_PARAMETERS, pp32 as u32)?;

    os.set_wow64_peb32(boot.peb32);
    os.register_wow64_module("wow64cpu.dll", boot.wow64cpu.base);
    os.register_wow64_module("wow64win.dll", boot.wow64win.base);

    let dispatcher = ntdll64.export("KiUserCallbackDispatcher").ok_or_else(|| {
        EmuError::Os("WoW64 boot: the 64-bit ntdll exports no KiUserCallbackDispatcher".into())
    })?;
    os.set_client_callback_dispatcher(dispatcher);

    os.set_wow64_threading(exemu_os::wow64::Wow64Threading {
        ldrp_initialize: boot.wow64.export("Wow64LdrpInitialize").ok_or_else(|| {
            EmuError::Os("WoW64 boot: wow64.dll does not export Wow64LdrpInitialize".into())
        })?,
        rtl_user_thread_start32: boot
            .ntdll32
            .export("RtlUserThreadStart")
            .ok_or_else(|| EmuError::Os("WoW64 boot: ntdll32 exports no RtlUserThreadStart".into()))?,
    });

    let h32 = os.register_ntdll32_unixlib(boot.ntdll32.base);
    if let Some(slot) = boot.ntdll32.export("__wine_unixlib_handle") {
        mem.write_u64(slot, h32)?;
    }

    let native = |os: &mut exemu_os::WinOs, sym: &str| {
        os.resolve_import("ntdll.dll", &exemu_core::ImportSymbol::Named(sym.into()))
    };
    let (ldr_get, ldr_load) = (native(os, "LdrGetDllHandle"), native(os, "LdrLoadDll"));
    for img in [&boot.wow64cpu, &boot.wow64] {
        for (iat_rva, _dll, sym) in &img.imports {
            let addr = match sym.as_str() {
                "LdrGetDllHandle" => ldr_get,
                "LdrLoadDll" => ldr_load,
                _ => continue,
            };
            mem.write_u64(img.base + *iat_rva as u64, addr)?;
        }
    }

    match cfg.wow64_bringup {
        wow64_boot::Bringup::Direct => {
            wow64_boot::seat_direct(cpu, mem, &boot, image.entry_va(), stack_top)?
        }
        wow64_boot::Bringup::WineLoader => wow64_boot::seat_wine_loader(
            cpu,
            mem,
            &boot,
            &ntdll64,
            lay.peb_addr,
            image.entry_va(),
            stack_top,
        )?,
    }

    Ok(boot)
}
