use exemu_core::{Cpu, EmuError, Perm, Region, Result};
use exemu_cpu::Interpreter;
use exemu_memory::VirtualMemory;
use exemu_os::{winedebug, WinOs};

use crate::config::RunConfig;
use crate::kuser::{KUSER_SHARED_DATA_BASE, KUSER_SYSTEM_CALL};
use crate::PAGE;

use super::layout::BootCtx;

pub(super) fn dll_dir(cfg: &RunConfig) -> Option<String> {
    if let Some(dir) = cfg.wine_boot_dir.clone() {
        if std::path::Path::new(&dir).is_dir() {
            Some(dir)
        } else {
            None
        }
    } else if std::env::var_os("EXEMU_WINE_BOOT").is_some() {
        let dir = std::env::var("EXEMU_WINE_DLLS")
            .unwrap_or_else(|_| "example_exe/wine-dlls/x86_64-windows".to_string());
        if std::path::Path::new(&dir).is_dir() {
            Some(dir)
        } else {
            None
        }
    } else {
        None
    }
}

pub(super) fn bring_up(
    os: &mut WinOs,
    cpu: &mut Interpreter,
    mem: &mut VirtualMemory,
    ctx: &BootCtx,
) -> Result<()> {
    let BootCtx { lay, image, stack_top, .. } = *ctx;
    if image.is_64bit {
        if let Some(ntdll_base) = os.load_wine_core(mem)? {
            map_wine_debug_pages(mem, lay.teb_base, lay.peb_addr)?;
            mem.poke(
                KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL,
                &0u32.to_le_bytes(),
            )?;
            if let Some(ldr_init_va) = os.ntdll_export("LdrInitializeThunk") {
                let seated = ntdll_base + exemu_os::RVA_LDR_INITIALIZE_THUNK;
                if ldr_init_va != seated {
                    return Err(EmuError::Os(format!(
                        "ntdll LdrInitializeThunk export {ldr_init_va:#x} != \
                         bootstrap-seated {seated:#x} (pinned-binary RVA drift)"
                    )));
                }
            }
            let entry = image.entry_va();
            os.bootstrap_via_ldr_init(
                cpu.state_mut(),
                mem,
                ntdll_base,
                entry,
                0,
                stack_top,
            )?;
        }
    }
    Ok(())
}

pub(super) fn map_wine_debug_pages(mem: &mut VirtualMemory, teb_base: u64, peb_addr: u64) -> Result<()> {
    mem.map(Region::new("wine-dbgstr", teb_base + winedebug::STRDUP_RING_OFF_64, PAGE, Perm::RW))?;
    mem.map(Region::new("wine-dbgopts", peb_addr + winedebug::OPTIONS_OFF_64, PAGE, Perm::RW))?;
    winedebug::write_options(
        mem,
        peb_addr,
        winedebug::OPTIONS_OFF_64,
        PAGE,
        &winedebug::Options::from_env(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::Memory;
    use exemu_cpu::GS_BASE;

    #[test]
    fn wine_debug_pages_are_mapped_and_writable() {
        let teb_base = GS_BASE;
        let peb_addr = GS_BASE + 0x2000;
        let mut mem = VirtualMemory::new();
        map_wine_debug_pages(&mut mem, teb_base, peb_addr).expect("map wine debug pages");

        mem.poke(teb_base + 0x3000, &7u32.to_le_bytes())
            .expect("write ring position");
        assert_eq!(
            mem.read_u32(teb_base + 0x3000).expect("read ring position"),
            7
        );
        mem.poke(teb_base + 0x3008, b"x").expect("write ring byte");
        mem.read_u8(teb_base + 0x3008 + 0x3fc)
            .expect("ring tail is mapped");

        let opts = peb_addr + winedebug::OPTIONS_OFF_64;
        assert_eq!(
            mem.read_u8(opts).expect("read debug-options page"),
            winedebug::DEFAULT_FLAGS,
            "the default record carries err+fixme, as a real Wine process does"
        );
        assert_eq!(mem.read_u8(opts + 1).expect("read the name"), 0, "the terminator's name is empty");
        mem.read_u8(opts + PAGE - 1).expect("the options page tail is mapped");
    }
}
