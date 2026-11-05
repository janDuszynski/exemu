use exemu_core::debug::DebugControl;
use exemu_core::{Cpu, EmuError, GuestClock, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32, GS_BASE};
use exemu_loader as loader;
use exemu_memory::VirtualMemory;
use exemu_os::{winedebug, WinConfig, WinOs};

use crate::cmdline::{build_cmdline, truncate_cmdline};
use crate::config::RunConfig;
use crate::kuser::{map_kuser_shared_data, KUSER_SHARED_DATA_BASE, KUSER_SYSTEM_CALL};
use crate::{image_loader, prefix_dirs, spawn, winsxs, wow64_boot, wow64_image, PAGE};

use super::Process;

const TEB_SIZE: u64 = 0x2000;
const ENV_SIZE: u64 = 0x1000;
const API_SIZE: u64 = 0x0010_0000;
const JIT_CODE_BYTES: usize = 32 << 20;

struct Layout {
    stack_base: u64,
    stack_size: u64,
    heap_base: u64,
    heap_size: u64,
    api_base: u64,
    dll_base: u64,
    dll_size: u64,
    env_base: u64,
    teb_base: u64,
    peb_addr: u64,
    teb_self: u64,
    teb_peb: u64,
    teb_stack_base: u64,
    teb_stack_limit: u64,
    peb_image_base: u64,
    peb_ldr_off: u64,
    peb_loaderlock_off: u64,
    valloc_base: u64,
}

impl Layout {
    fn for_bits(is_64bit: bool) -> Layout {
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

    fn for_wow64() -> Layout {
        Layout {
            teb_base: wow64_boot::WOW64_TEB64,
            peb_addr: wow64_boot::WOW64_PEB64,
            ..Layout::for_bits(true)
        }
    }
}

impl Process {
    pub fn load(pe_bytes: &[u8], cfg: &mut RunConfig) -> Result<Process> {
        let mut image = loader::parse(pe_bytes)?;
        let mut mem = VirtualMemory::new();

        let clock = GuestClock::new(cfg.virtual_clock || env_opt_in("EXEMU_VIRTUAL_CLOCK"));

        let preferred_base = image.image_base;
        let base = cfg.load_base.unwrap_or(preferred_base);
        if base != preferred_base {
            if image.relocations.is_empty() {
                return Err(EmuError::InvalidPe(format!(
                    "cannot load image at non-preferred base {base:#x}: no relocation table \
                     (preferred base {preferred_base:#x})"
                )));
            }
            loader::apply_relocations(&mut image.sections, &image.relocations, preferred_base, base)?;
            patch_header_image_base(&mut image.headers, image.is_64bit, base);
            image.image_base = base;
        }

        let hdr_len = align_up(image.size_of_headers as u64, PAGE).max(PAGE);
        mem.map_with_data("headers", base, hdr_len, &image.headers, Perm::RW)?;

        for s in &image.sections {
            let addr = base + s.rva as u64;
            let size = align_up((s.virtual_size as u64).max(s.data.len() as u64), PAGE).max(PAGE);
            let mut perm = section_perm(s);
            let end = s.rva as u64 + size;
            let carries_iat = image
                .imports
                .iter()
                .any(|i| (i.iat_rva as u64) >= s.rva as u64 && (i.iat_rva as u64) < end);
            if carries_iat {
                perm = perm.union(Perm::WRITE);
            }
            mem.map_with_data(section_name(&s.name), addr, size, &s.data, perm)?;
        }

        let wine_dll_dir = if let Some(dir) = cfg.wine_boot_dir.clone() {
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
        };

        let wow64_dir32 = wine_dll_dir
            .as_ref()
            .map(|d| wow64_boot::sibling_i386_dir(std::path::Path::new(d)));
        let is_wow64 = !image.is_64bit
            && match (&wine_dll_dir, &wow64_dir32) {
                (Some(d64), Some(d32)) => wow64_boot::Wow64Dirs {
                    dir64: std::path::Path::new(d64),
                    dir32: d32,
                }
                .complete(),
                _ => false,
            };

        let lay = if is_wow64 {
            Layout::for_wow64()
        } else {
            Layout::for_bits(image.is_64bit)
        };
        let ptr_size = if image.is_64bit { 8 } else { 4 };
        let proc_is_64 = image.is_64bit || is_wow64;
        let proc_ptr_size = if proc_is_64 { 8 } else { 4 };

        mem.map(Region::new("stack", lay.stack_base, lay.stack_size, Perm::RW))?;

        mem.map(Region::new("heap", lay.heap_base, lay.heap_size, Perm::RW))?;

        mem.map(Region::new("dlls", lay.dll_base, lay.dll_size, Perm::RWX))?;

        mem.map(Region::new("teb", lay.teb_base, TEB_SIZE, Perm::RW))?;
        mem.map(Region::new("peb", align_down(lay.peb_addr, PAGE), PAGE, Perm::RW))?;
        let stack_top = lay.stack_base + lay.stack_size;
        let write_ptr = |mem: &mut VirtualMemory, addr: u64, val: u64| -> Result<()> {
            mem.poke(addr, &val.to_le_bytes()[..proc_ptr_size])
        };
        write_ptr(&mut mem, lay.teb_base + lay.teb_self, lay.teb_base)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_peb, lay.peb_addr)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_base, stack_top)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_limit, lay.stack_base)?;
        write_ptr(&mut mem, lay.peb_addr + lay.peb_image_base, base)?;

        map_kuser_shared_data(&mut mem, &clock)?;

        mem.map(Region::new("env", lay.env_base, ENV_SIZE, Perm::RW))?;
        let cmdline = truncate_cmdline(
            cfg.command_line.clone().unwrap_or_else(|| build_cmdline(&cfg.args)),
        );
        let cmd_a = lay.env_base;
        let mut ascii = cmdline.clone().into_bytes();
        ascii.push(0);
        mem.poke(cmd_a, &ascii)?;
        let cmd_w = lay.env_base + 0x400;
        let mut wide: Vec<u8> = Vec::new();
        for u in cmdline.encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        mem.poke(cmd_w, &wide)?;

        let sandbox = cfg
            .sandbox_root
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("exemu-sandbox"));
        let _ = std::fs::create_dir_all(&sandbox);
        let _ = std::fs::create_dir_all(sandbox.join("C").join("windows").join("system32"));
        for guest in exemu_os::folders::all_guest_dirs() {
            let mut host = sandbox.clone();
            for comp in guest.split('\\') {
                match comp {
                    "" | "." | ".." => {}
                    c if c.ends_with(':') => host.push(&c[..c.len() - 1]),
                    c => host.push(c),
                }
            }
            let _ = std::fs::create_dir_all(&host);
        }
        let module_name = cfg
            .args
            .first()
            .map(|s| s.rsplit(['/', '\\']).next().unwrap_or(s).to_string())
            .unwrap_or_else(|| "program.exe".into());
        let module_path_w = format!("C:\\{module_name}");
        let host_exe = sandbox.join("C").join(&module_name);
        if let Some(p) = host_exe.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&host_exe, pe_bytes);

        if wine_dll_dir.is_some() {
            let drv = sandbox
                .join("C")
                .join("windows")
                .join("system32")
                .join(exemu_os::audio::DRIVER_MODULE);
            let _ = std::fs::write(drv, exemu_os::audio::driver_stub_pe());
        }

        if let Some(dir) = &wine_dll_dir {
            let prefix = match (image.is_64bit, &wow64_dir32) {
                (false, Some(d32)) => d32.clone(),
                _ => std::path::PathBuf::from(dir),
            };
            prefix_dirs::stage_prefix_dirs(&sandbox);
            let _ = winsxs::stage_comctl6(&sandbox, &prefix, winsxs::arch_for(image.is_64bit));
        }

        let mut os = WinOs::new(WinConfig {
            api_base: lay.api_base,
            heap_base: lay.heap_base,
            heap_size: lay.heap_size,
            image_base: base,
            cmdline_ptr_a: cmd_a,
            cmdline_ptr_w: cmd_w,
            echo: cfg.echo,
            trace: cfg.trace,
            is_64bit: proc_is_64,
            sandbox: sandbox.to_string_lossy().into_owned(),
            module_path_w,
            dll_base: lay.dll_base,
            dll_size: lay.dll_size,
            valloc_base: lay.valloc_base,
            peb_addr: lay.peb_addr,
            teb_base: lay.teb_base,
            peb_ldr_off: lay.peb_ldr_off,
            peb_loaderlock_off: lay.peb_loaderlock_off,
            image_size: align_up(image.size_of_image as u64, PAGE).max(PAGE),
            image_entry: image.entry_va(),
            image_name: module_name.clone(),
            wine_dll_dir: wine_dll_dir.clone(),
            dpi: cfg.dpi,
            file_dialog_pick: cfg.file_dialog_pick.clone(),
        });

        os.set_image_loader(Box::new(image_loader::PeImageLoader));
        os.set_unwind_table(image.function_table.clone());

        os.set_environment(cfg.environment.clone());
        os.set_spawn_depth(cfg.spawn_depth);
        os.set_process_spawner(Box::new(spawn::AppSpawner::new(cfg, sandbox.clone())));

        os.seed_main_teb(&mut mem, lay.stack_base, stack_top)?;

        mem.map(Region::new("imports", lay.api_base, API_SIZE, Perm::RW))?;

        for imp in image.imports.iter().filter(|_| !is_wow64) {
            let addr = os.resolve_import_addr(&imp.dll, &imp.symbol);
            mem.poke(base + imp.iat_rva as u64, &addr.to_le_bytes()[..ptr_size])?;
            if let exemu_core::ImportSymbol::Named(name) = &imp.symbol {
                if let Some(value) = data_import_seed(name, cmd_a, cmd_w) {
                    mem.poke(addr, &value.to_le_bytes()[..ptr_size])?;
                }
            }
        }

        let mut tls_callbacks: Vec<u64> = Vec::new();
        if let Some(tls) = &image.tls {
            let delta = base.wrapping_sub(preferred_base);
            if tls.address_of_index != 0 {
                let idx = os.alloc_tls_index();
                let index_va = tls.address_of_index.wrapping_add(delta);
                mem.poke(index_va, &idx.to_le_bytes()[..4])?;
            }
            if !tls.raw_template.is_empty() {
                let start_va = tls.start_address_of_raw_data.wrapping_add(delta);
                mem.poke(start_va, &tls.raw_template)?;
            }
            tls_callbacks = tls.callback_rvas.iter().map(|&rva| base + rva as u64).collect();
        }
        os.set_tls_callbacks(tls_callbacks);

        os.init_ldr(&mut mem)?;

        if cfg.gui {
            let dialogs = loader::parse_dialogs(pe_bytes);
            let gui: Box<dyn exemu_core::Gui> = match std::env::var_os("EXEMU_GUI_SHOT") {
                Some(dir) => Box::new(exemu_gui::OffscreenGui::new(std::path::PathBuf::from(dir))),
                None => Box::new(exemu_gui::MinifbGui::new()),
            };
            os.set_gui(gui, dialogs);
        }

        if let Some(d) = cfg.driver.take() {
            os.set_driver(d);
        }
        if let Some(sink) = cfg.audio_sink.take() {
            os.set_audio_sink(sink);
        }
        if let Some(rx) = cfg.input.take() {
            os.set_input(rx);
        }

        let mut cpu = Interpreter::with_bits(if image.is_64bit { Bits::B64 } else { Bits::B32 });
        let want_jit = cfg.jit || std::env::var("EXEMU_JIT").is_ok_and(|v| v != "0");
        let mut jit = if want_jit {
            match exemu_jit::Jit::new(JIT_CODE_BYTES) {
                Ok(j) => Some(j),
                Err(e) => {
                    eprintln!("[exemu] JIT unavailable, running on the interpreter: {e}");
                    None
                }
            }
        } else {
            None
        };
        cpu.set_clock(clock.clone());
        os.set_clock(clock.clone());
        let exit_thunk = os.exit_thunk();
        let rsp = if image.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 8;
            mem.write_u64(sp, exit_thunk)?;
            sp
        } else {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 4;
            mem.write_u32(sp, exit_thunk as u32)?;
            sp
        };
        cpu.state_mut().set_rsp(rsp);
        os.start_process(cpu.state_mut(), &mut mem, image.entry_va())?;

        if image.is_64bit {
            if let Some(ntdll_base) = os.load_wine_core(&mut mem)? {
                map_wine_debug_pages(&mut mem, lay.teb_base, lay.peb_addr)?;
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
                    &mut mem,
                    ntdll_base,
                    entry,
                    0,
                    stack_top,
                )?;
            }
        }

        let mut wow64 = None;
        if is_wow64 {
            let Some(ntdll_base) = os.load_wine_core(&mut mem)? else {
                return Err(EmuError::Os(
                    "WoW64 boot: the 64-bit Wine core would not load from the pinned prefix".into(),
                ));
            };
            map_wine_debug_pages(&mut mem, lay.teb_base, lay.peb_addr)?;
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

            let boot = wow64_boot::build(&mut mem, &dirs, &ntdll64, base)?;
            if cfg.wow64_bringup == wow64_boot::Bringup::Direct {
                let (bound, missing) =
                    wow64_boot::bind_guest_imports(&mut mem, base, &image.imports, &boot)?;
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
                .build_wow64_process_parameters(&mut mem, wow64_boot::WOW64_PARAMS, wow64_boot::WOW64_PARAMS_SIZE)?
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
            let (ldr_get, ldr_load) = (native(&mut os, "LdrGetDllHandle"), native(&mut os, "LdrLoadDll"));
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
                    wow64_boot::seat_direct(&mut cpu, &mut mem, &boot, image.entry_va(), stack_top)?
                }
                wow64_boot::Bringup::WineLoader => wow64_boot::seat_wine_loader(
                    &mut cpu,
                    &mut mem,
                    &boot,
                    &ntdll64,
                    lay.peb_addr,
                    image.entry_va(),
                    stack_top,
                )?,
            }
            wow64 = Some(boot);
        }

        let idle = cfg.debug.is_none()
            && std::env::var("EXEMU_DEBUG_IDLE").is_ok_and(|v| !v.is_empty() && v != "0");
        if idle {
            let (session, _front) = exemu_core::DebugSession::pair(DebugControl::attached());
            cfg.debug = Some(session);
        }
        let (dbg, dbg_cmds, dbg_events) = match cfg.debug.take() {
            Some(s) => (s.control, Some(s.commands), Some(s.events)),
            None => (DebugControl::detached(), None, None),
        };
        mem.set_debug(dbg.clone());
        if let Some(j) = jit.as_mut() {
            j.set_debug(dbg.clone());
        }

        Ok(Process {
            mem,
            cpu,
            os,
            clock,
            sandbox: sandbox.to_string_lossy().into_owned(),
            entry: image.entry_va(),
            max_steps: cfg.max_steps,
            image_base: base,
            exc_depth: 0,
            wow64,
            jit,
            dbg,
            dbg_cmds,
            dbg_events,
        })
    }
}

fn env_opt_in(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !v.is_empty() && v != "0",
        Err(_) => false,
    }
}

fn map_wine_debug_pages(mem: &mut VirtualMemory, teb_base: u64, peb_addr: u64) -> Result<()> {
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

#[inline]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

#[inline]
fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

fn patch_header_image_base(headers: &mut [u8], is_64bit: bool, base: u64) {
    let read_u32 = |h: &[u8], at: usize| -> Option<u32> {
        h.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(pe_off) = read_u32(headers, 0x3C).map(|v| v as usize) else { return };
    let opt = pe_off + 4 + 20;
    if is_64bit {
        if let Some(dst) = headers.get_mut(opt + 24..opt + 32) {
            dst.copy_from_slice(&base.to_le_bytes());
        }
    } else if let Some(dst) = headers.get_mut(opt + 28..opt + 32) {
        dst.copy_from_slice(&(base as u32).to_le_bytes());
    }
}

fn section_name(raw: &str) -> String {
    if raw.is_empty() {
        "section".to_string()
    } else {
        raw.to_string()
    }
}

fn section_perm(s: &exemu_core::pe::Section) -> Perm {
    let bits = Perm::NONE
        .union(if s.writable { Perm::WRITE } else { Perm::NONE })
        .union(if s.executable { Perm::EXEC } else { Perm::NONE });
    bits.union(Perm::READ)
}

fn data_import_seed(name: &str, cmd_a: u64, cmd_w: u64) -> Option<u64> {
    match name {
        "_acmdln" => Some(cmd_a),
        "_wcmdln" => Some(cmd_w),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
