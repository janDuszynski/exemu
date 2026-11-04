use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, EmuError, Memory, Perm, Result};
use exemu_memory::VirtualMemory;
use exemu_os::winedebug;
use exemu_os::wow64;

use crate::wow64_image::{self, Wow64Image};

pub const WOW64_LOW_ARENA: u64 = 0x6000_0000;
pub const WOW64_LOW_ARENA_SIZE: u64 = 0x0800_0000;

pub const WOW64_TEB64: u64 = 0x7F00_0000;
pub const WOW64_PEB64: u64 = WOW64_TEB64 + 0x2000;
pub const WOW64_EXTRA: u64 = WOW64_TEB64 + 0x8000;
pub const WOW64_EXTRA_SIZE: u64 = 0x2_0000;
pub const WOW64_TEB32: u64 = WOW64_EXTRA;
pub const WOW64_PEB32: u64 = WOW64_EXTRA + 0x2000;
pub const WOW64_CPU_AREA: u64 = WOW64_EXTRA + 0x4000;
pub const WOW64_INFO: u64 = WOW64_EXTRA + 0x5000;
pub const WOW64_PARAMS: u64 = WOW64_EXTRA + 0x6000;
pub const WOW64_PARAMS_SIZE: u64 = WOW64_EXTRA_SIZE - 0x6000;

pub const WOW64_STACK32_BASE: u64 = 0x0018_0000;
pub const WOW64_STACK32_SIZE: u64 = 0x0020_0000;

pub struct Wow64Boot {
    pub ntdll32: Wow64Image,
    pub wow64cpu: Wow64Image,
    pub wow64: Wow64Image,
    pub wow64win: Wow64Image,
    pub win32u: Wow64Image,
    pub teb64: u64,
    pub teb32: u64,
    pub peb64: u64,
    pub peb32: u64,
    pub cpu_area: u64,
    pub stack32_top: u64,
}

pub struct Wow64Dirs<'a> {
    pub dir64: &'a Path,
    pub dir32: &'a Path,
}

impl Wow64Dirs<'_> {
    pub fn complete(&self) -> bool {
        self.dir64.join("ntdll.dll").is_file()
            && self.dir64.join("wow64.dll").is_file()
            && self.dir64.join("wow64cpu.dll").is_file()
            && self.dir64.join("wow64win.dll").is_file()
            && self.dir64.join("win32u.dll").is_file()
            && self.dir32.join("ntdll.dll").is_file()
    }
}

pub fn sibling_i386_dir(dir64: &Path) -> std::path::PathBuf {
    match dir64.parent() {
        Some(p) => p.join("i386-windows"),
        None => std::path::PathBuf::from("i386-windows"),
    }
}

pub fn build(
    mem: &mut VirtualMemory,
    dirs: &Wow64Dirs<'_>,
    ntdll64: &Wow64Image,
    guest_image_base: u64,
) -> Result<Wow64Boot> {
    let mut low = WOW64_LOW_ARENA;
    let mut place = |mem: &mut VirtualMemory, host: std::path::PathBuf, name: &'static str| -> Result<Wow64Image> {
        let bytes = std::fs::read(&host)
            .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read {}: {e}", host.display())))?;
        let img = wow64_image::map_image(mem, &bytes, low, name)?;
        low += img.size;
        low = (low + 0xffff) & !0xffff;
        if low > WOW64_LOW_ARENA + WOW64_LOW_ARENA_SIZE {
            return Err(EmuError::Os("WoW64 boot: the sub-4 GiB image arena is exhausted".into()));
        }
        Ok(img)
    };
    let ntdll32 = place(mem, dirs.dir32.join("ntdll.dll"), "ntdll32")?;
    let wow64cpu = place(mem, dirs.dir64.join("wow64cpu.dll"), "wow64cpu")?;
    debug_assert!(wow64cpu.base + wow64cpu.size <= u32::MAX as u64);

    const HIGH: u64 = 0x0000_0007_0000_0000;
    let wow64_bytes = std::fs::read(dirs.dir64.join("wow64.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read wow64.dll: {e}")))?;
    let wow64_img = wow64_image::map_image(mem, &wow64_bytes, HIGH, "wow64")?;
    let win_bytes = std::fs::read(dirs.dir64.join("wow64win.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read wow64win.dll: {e}")))?;
    let wow64win = wow64_image::map_image(mem, &win_bytes, HIGH + 0x0400_0000, "wow64win")?;
    let win32u_bytes = std::fs::read(dirs.dir64.join("win32u.dll"))
        .map_err(|e| EmuError::Os(format!("WoW64 boot: cannot read win32u.dll: {e}")))?;
    let win32u = wow64_image::map_image(mem, &win32u_bytes, HIGH + 0x0800_0000, "win32u64")?;

    let bound = wow64_image::bind_imports(mem, &wow64_img, &[ntdll64], 8)?;
    if bound < 200 {
        return Err(EmuError::Os(format!(
            "WoW64 boot: wow64.dll bound only {bound} ntdll imports (expected 200+) — wrong pinned set?"
        )));
    }
    wow64_image::bind_imports(mem, &wow64cpu, &[&wow64_img, ntdll64], 8)?;
    wow64_image::bind_imports(mem, &win32u, &[ntdll64], 8)?;
    let win_bound = wow64_image::bind_imports(mem, &wow64win, &[ntdll64, &wow64_img, &win32u], 8)?;
    if win_bound < 450 {
        return Err(EmuError::Os(format!(
            "WoW64 boot: wow64win.dll bound only {win_bound} imports (expected 480+) — wrong pinned set?"
        )));
    }

    mem.map(exemu_core::Region::new("wow64_extra", WOW64_EXTRA, WOW64_EXTRA_SIZE, Perm::RW))?;
    let teb64 = WOW64_TEB64;
    let teb32 = WOW64_TEB32;
    wow64::link_teb32(mem, teb64, teb32)?;

    mem.map(exemu_core::Region::new(
        "stack32",
        WOW64_STACK32_BASE,
        WOW64_STACK32_SIZE,
        Perm::RW,
    ))?;
    let stack32_top = WOW64_STACK32_BASE + WOW64_STACK32_SIZE;

    wow64::seed_teb32(mem, teb32, WOW64_PEB32, WOW64_STACK32_BASE, stack32_top)?;
    mem.write_u32(teb32 + wow64::TEB32_CLIENT_ID, 0x1000)?;
    mem.write_u32(teb32 + wow64::TEB32_CLIENT_ID + 4, 0x1001)?;

    mem.write_u32(WOW64_PEB32 + wow64::peb32::IMAGE_BASE, guest_image_base as u32)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_MAJOR_VERSION, 10)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_MINOR_VERSION, 0)?;
    mem.write_u16(WOW64_PEB32 + wow64::peb32::OS_BUILD_NUMBER, 19043)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::OS_PLATFORM_ID, 2)?;
    mem.write_u32(WOW64_PEB32 + wow64::peb32::SESSION_ID, 1)?;

    winedebug::write_options(
        mem,
        WOW64_PEB32,
        winedebug::OPTIONS_OFF_32,
        WOW64_CPU_AREA - (WOW64_PEB32 + winedebug::OPTIONS_OFF_32),
        &winedebug::Options::from_env(),
    )?;

    mem.write_u64(teb64 + WOW64_INFO_TEB_SLOT, WOW64_INFO)?;

    let block = ntdll64.export("LdrSystemDllInitBlock").ok_or_else(|| {
        EmuError::Os("WoW64 boot: the 64-bit ntdll exports no LdrSystemDllInitBlock".into())
    })?;
    let sysdll = wow64::SystemDllInitBlock {
        ntdll32_base: ntdll32.base,
        ldr_initialize_thunk: ntdll32_export(&ntdll32, "LdrInitializeThunk")?,
        exception_dispatcher: ntdll32_export(&ntdll32, "KiUserExceptionDispatcher")?,
        apc_dispatcher: ntdll32_export(&ntdll32, "KiUserApcDispatcher")?,
        callback_dispatcher: ntdll32_export(&ntdll32, "KiUserCallbackDispatcher")?,
    };
    wow64::publish_system_dll_init_block(mem, block, &sysdll)?;

    let prepare = wow64_img.export("Wow64PrepareForException").ok_or_else(|| {
        EmuError::Os("WoW64 boot: wow64.dll does not export Wow64PrepareForException".into())
    })?;
    wow64::publish_wow64_exception_hook(mem, ntdll64.base, prepare)?;

    wow64::publish_kernel_callback_table(mem, wow64win.base, wow64win.entry, WOW64_PEB64)?;

    Ok(Wow64Boot {
        ntdll32,
        wow64cpu,
        wow64: wow64_img,
        wow64win,
        win32u,
        teb64,
        teb32,
        peb64: WOW64_PEB64,
        peb32: WOW64_PEB32,
        cpu_area: WOW64_CPU_AREA,
        stack32_top,
    })
}

pub const PEB64_PROCESS_HEAP: u64 = 0x30;

fn ntdll32_export(img: &Wow64Image, name: &str) -> Result<u64> {
    img.export(name)
        .ok_or_else(|| EmuError::Os(format!("WoW64 boot: the 32-bit ntdll exports no {name}")))
}

pub const WOW64_INFO_TEB_SLOT: u64 = 0x14d0;

pub const WOW64_BOOTSTRAP: u64 = WOW64_EXTRA + WOW64_EXTRA_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Bringup {
    Direct,
    #[default]
    WineLoader,
}

pub fn seat_direct(
    cpu: &mut exemu_cpu::Interpreter,
    mem: &mut VirtualMemory,
    boot: &Wow64Boot,
    guest_entry: u64,
    stack64_top: u64,
) -> Result<()> {
    let sym = |img: &Wow64Image, n: &str| -> Result<u64> {
        img.export(n)
            .ok_or_else(|| EmuError::Os(format!("WoW64 boot: wow64cpu.dll does not export {n}")))
    };
    let process_init = sym(&boot.wow64cpu, "BTCpuProcessInit")?;
    let get_bop = sym(&boot.wow64cpu, "BTCpuGetBopCode")?;
    let simulate = sym(&boot.wow64cpu, "BTCpuSimulate")?;
    let slots = wow64::BopSlots {
        transition: boot
            .ntdll32
            .export("Wow64Transition")
            .ok_or_else(|| EmuError::Os("WoW64 boot: 32-bit ntdll exports no Wow64Transition".into()))?,
        syscall_dispatcher: boot.ntdll32.export("__wine_syscall_dispatcher").ok_or_else(|| {
            EmuError::Os("WoW64 boot: 32-bit ntdll exports no __wine_syscall_dispatcher".into())
        })?,
        wow32_reserved: boot.teb32 + wow64::TEB32_WOW32_RESERVED,
    };

    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    let call_abs = |code: &mut Vec<u8>, target: u64| {
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&target.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]);
    };
    call_abs(&mut code, process_init);
    call_abs(&mut code, get_bop);
    for slot in [slots.transition, slots.syscall_dispatcher, slots.wow32_reserved] {
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&slot.to_le_bytes());
        code.extend_from_slice(&[0x89, 0x01]);
    }
    call_abs(&mut code, simulate);
    code.push(0xF4);

    mem.map(exemu_core::Region::new("wow64_bootstrap", WOW64_BOOTSTRAP, 0x1000, Perm::RWX))?;
    mem.write(WOW64_BOOTSTRAP, &code)?;

    let esp32 = (boot.stack32_top - 0x100) & !0xf;
    let start = wow64::Start32 { eip: guest_entry as u32, esp: esp32 as u32, eax: 0, ebx: 0 };
    wow64::init_cpu_area(mem, boot.teb64, boot.cpu_area, start)?;
    seat_cpu(cpu, boot, stack64_top);
    Ok(())
}

fn seat_cpu(cpu: &mut exemu_cpu::Interpreter, boot: &Wow64Boot, stack64_top: u64) {
    let s = cpu.state_mut();
    s.rip = WOW64_BOOTSTRAP;
    s.set_rsp((stack64_top - 0x100) & !0xf);
    s.gs_base = boot.teb64;
    s.fs_base = boot.teb32;
    cpu.set_bits(exemu_cpu::Bits::B64);
}

pub fn seat_wine_loader(
    cpu: &mut exemu_cpu::Interpreter,
    mem: &mut VirtualMemory,
    boot: &Wow64Boot,
    ntdll64: &Wow64Image,
    peb64: u64,
    guest_entry: u64,
    stack64_top: u64,
) -> Result<()> {
    let ldrp_init = boot
        .wow64
        .export("Wow64LdrpInitialize")
        .ok_or_else(|| EmuError::Os("WoW64 boot: wow64.dll does not export Wow64LdrpInitialize".into()))?;
    let create_heap = ntdll64
        .export("RtlCreateHeap")
        .ok_or_else(|| EmuError::Os("WoW64 boot: the 64-bit ntdll exports no RtlCreateHeap".into()))?;

    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);
    code.extend_from_slice(&[0xB9, 0x02, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x31, 0xD2]);
    code.extend_from_slice(&[0x45, 0x31, 0xC0]);
    code.extend_from_slice(&[0x45, 0x31, 0xC9]);
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&create_heap.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]);
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&(peb64 + PEB64_PROCESS_HEAP).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x01]);
    code.extend_from_slice(&[0x31, 0xC9]);
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&ldrp_init.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]);
    code.push(0xF4);

    mem.map(exemu_core::Region::new("wow64_bootstrap", WOW64_BOOTSTRAP, 0x1000, Perm::RWX))?;
    mem.write(WOW64_BOOTSTRAP, &code)?;

    let esp32 = (boot.stack32_top - 0x100) & !0xf;
    let start = wow64::Start32 {
        eip: ntdll32_export(&boot.ntdll32, "RtlUserThreadStart")? as u32,
        esp: esp32 as u32,
        eax: guest_entry as u32,
        ebx: 0,
    };
    wow64::init_cpu_area(mem, boot.teb64, boot.cpu_area, start)?;
    seat_cpu(cpu, boot, stack64_top);
    Ok(())
}

pub fn bind_guest_imports(
    mem: &mut VirtualMemory,
    guest_base: u64,
    imports: &[exemu_core::Import],
    boot: &Wow64Boot,
) -> Result<(usize, Vec<String>)> {
    let mut by_dll: HashMap<&str, &Wow64Image> = HashMap::new();
    by_dll.insert("ntdll.dll", &boot.ntdll32);
    let mut bound = 0usize;
    let mut missing = Vec::new();
    for imp in imports {
        let exemu_core::ImportSymbol::Named(name) = &imp.symbol else {
            missing.push(format!("{}#<ordinal>", imp.dll));
            continue;
        };
        match by_dll.get(imp.dll.as_str()).and_then(|m| m.export(name)) {
            Some(addr) if addr <= u32::MAX as u64 => {
                mem.write_u32(guest_base + imp.iat_rva as u64, addr as u32)?;
                bound += 1;
            }
            _ => missing.push(format!("{}!{name}", imp.dll)),
        }
    }
    Ok((bound, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wow64_block_leaves_wines_debug_scratch_alone() {
        let ring = WOW64_TEB32 + winedebug::STRDUP_RING_OFF_32 + winedebug::STRDUP_RING_SIZE;
        assert!(ring <= WOW64_PEB32, "the 32-bit debug-string ring runs into PEB32");
        const {
            assert!(
                winedebug::STRDUP_RING_OFF_32 + winedebug::STRDUP_RING_SIZE
                    <= wow64::TEB32_ACTIVATION_CONTEXT_STACK,
                "the ring overlaps TEB32's activation-context stack"
            )
        };
        let opts = WOW64_PEB32 + winedebug::OPTIONS_OFF_32;
        assert!(
            opts + winedebug::OPTION_SIZE <= WOW64_CPU_AREA,
            "the option array overlaps the CPU-reserved area — the W6.4 bug"
        );
        let blocks = [WOW64_TEB32, WOW64_PEB32, WOW64_CPU_AREA, WOW64_INFO, WOW64_PARAMS];
        for w in blocks.windows(2) {
            assert!(w[0] < w[1], "the WoW64 block is laid out in order: {w:#x?}");
        }
        assert_eq!(
            WOW64_PARAMS + WOW64_PARAMS_SIZE,
            WOW64_EXTRA + WOW64_EXTRA_SIZE,
            "the parameter arena runs to the end of the block and no further"
        );
        const {
            assert!(
                WOW64_PEB64 + winedebug::OPTIONS_OFF_64 + 0x1000 <= WOW64_EXTRA,
                "the 64-bit option page runs into the WoW64 block"
            )
        };
        let ring64 = WOW64_TEB64 + winedebug::STRDUP_RING_OFF_64;
        assert!(WOW64_PEB64 + 0x1000 <= ring64, "the 64-bit ring overlaps the PEB page");
        assert!(
            ring64 + winedebug::STRDUP_RING_SIZE <= WOW64_PEB64 + winedebug::OPTIONS_OFF_64,
            "the 64-bit ring runs into the 64-bit option page"
        );
    }
}
