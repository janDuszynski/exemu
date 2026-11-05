#![forbid(unsafe_code)]

pub mod audio_sample;
pub mod cab;
pub mod cab_sample;
pub mod comctl_sample;
pub mod comdlg_sample;
pub mod gui_sample;
mod memory_map;
pub mod sample;
pub mod shell_link_sample;
pub mod shell_sample;
pub mod socket_sample;
pub mod prefix_dirs;
pub mod winsxs;
pub mod wow64_boot;
pub mod wow64_gui_sample;
pub mod wow64_menu_sample;
pub mod wow64_sample;
pub mod spawn;
pub mod spawn_sample;

use std::time::{SystemTime, UNIX_EPOCH};

use exemu_core::debug::{DebugCommand, DebugControl, DebugEvent, DebugSnapshot, StopReason, StopRequest};
use exemu_core::{Cpu, EmuError, Exit, GuestClock, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32, GS_BASE};
use exemu_loader as loader;
use exemu_memory::VirtualMemory;
use exemu_os::{winedebug, WinConfig, WinOs};

const PAGE: u64 = 0x1000;
const TEB_SIZE: u64 = 0x2000;
const ENV_SIZE: u64 = 0x1000;
const API_SIZE: u64 = 0x0010_0000;

const NULL_GUARD: u64 = 0x1_0000;

const KUSER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
const KUSER_DISPATCHER_PAGE: u64 = 0x7ffe_1000;

const KUSER_TICK_COUNT_MULTIPLIER: u64 = 0x004;
const KUSER_INTERRUPT_TIME: u64 = 0x008;
const KUSER_SYSTEM_TIME: u64 = 0x014;
const KUSER_SYSTEM_CALL: u64 = 0x308;
const KUSER_TICK_COUNT: u64 = 0x320;

const KUSER_TICK_PERIOD_100NS: u64 = 156_250;

const KUSER_TICK_COUNT_MULTIPLIER_VALUE: u32 = 0x0FA0_0000;

const KUSER_REFRESH_INSTRUCTIONS: u64 = 65_536;

const JIT_CODE_BYTES: usize = 32 << 20;

const CHAIN_MAX_INSTRUCTIONS: u64 = 65_536;

const JIT_EXACT_STOP_WINDOW: u64 = 128;

const DEBUG_READ_MAX: u64 = 1 << 20;

enum DebugAction {
    Continue,
    Step,
    Detach,
    Kill,
}

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

pub struct RunConfig {
    pub args: Vec<String>,
    pub echo: bool,
    pub trace: bool,
    pub driver: Option<Box<dyn exemu_core::UserDriver>>,
    pub audio_sink: Option<Box<dyn exemu_core::AudioSink>>,
    pub max_steps: u64,
    pub gui: bool,
    pub load_base: Option<u64>,
    pub wine_boot_dir: Option<String>,
    pub wow64_bringup: wow64_boot::Bringup,
    pub input: Option<std::sync::mpsc::Receiver<exemu_core::InputEvent>>,
    pub sandbox_root: Option<std::path::PathBuf>,
    pub virtual_clock: bool,
    pub command_line: Option<String>,
    pub environment: Vec<(String, String)>,
    pub spawn_depth: u32,
    pub jit: bool,
    pub dpi: u32,
    pub file_dialog_pick: Option<String>,
    pub debug: Option<exemu_core::DebugSession>,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            args: vec!["program.exe".into()],
            echo: true,
            trace: false,
            max_steps: 2_000_000_000,
            gui: false,
            load_base: None,
            wine_boot_dir: None,
            wow64_bringup: wow64_boot::Bringup::default(),
            driver: None,
            audio_sink: None,
            input: None,
            sandbox_root: None,
            virtual_clock: false,
            command_line: None,
            environment: Vec::new(),
            spawn_depth: 0,
            jit: false,
            dpi: 96,
            file_dialog_pick: std::env::var("EXEMU_FILE_DIALOG_PICK").ok().filter(|s| !s.is_empty()),
            debug: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct JitReport {
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub chains: u64,
    pub insns_executed: u64,
    pub faults: u64,
    pub not_compiled: u64,
    pub flushes: u64,
    pub code_bytes: usize,
    pub declined: Vec<(u16, u64)>,
}

pub struct RunResult {
    pub exit_code: i32,
    pub steps: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub sandbox: String,
    pub children_created: u32,
    pub jit: Option<JitReport>,
}

enum ExcSource<'a> {
    Interrupt(u8),
    Error(&'a EmuError),
}

pub struct Process {
    mem: VirtualMemory,
    cpu: Interpreter,
    os: WinOs,
    clock: GuestClock,
    sandbox: String,
    entry: u64,
    max_steps: u64,
    image_base: u64,
    exc_depth: u32,
    wow64: Option<wow64_boot::Wow64Boot>,
    jit: Option<exemu_jit::Jit>,
    dbg: DebugControl,
    dbg_cmds: Option<std::sync::mpsc::Receiver<DebugCommand>>,
    dbg_events: Option<std::sync::mpsc::Sender<DebugEvent>>,
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
            let ntdll64 = exemu_os::wow64::image_view(&ntdll64_bytes, ntdll_base)?;

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

    pub fn wow64(&self) -> Option<&wow64_boot::Wow64Boot> {
        self.wow64.as_ref()
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn peek_u8(&self, addr: u64) -> Result<u8> {
        self.mem.read_u8(addr)
    }

    pub fn peek_u32(&self, addr: u64) -> Result<u32> {
        self.mem.read_u32(addr)
    }

    pub fn peek_u64(&self, addr: u64) -> Result<u64> {
        self.mem.read_u64(addr)
    }

    pub fn memory(&self) -> &dyn Memory {
        &self.mem
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn run_until_rip(&mut self, target: u64, max_steps: u64) -> Result<u64> {
        let mut steps = 0u64;
        while self.cpu.state().rip != target {
            if steps >= max_steps {
                return Err(EmuError::Os(format!(
                    "run_until_rip({target:#x}): not reached within {max_steps} steps (rip {:#x})",
                    self.cpu.state().rip
                )));
            }
            match self.cpu.step(&mut self.mem, &mut self.os)? {
                Exit::Continue => steps += 1,
                other => {
                    return Err(EmuError::Os(format!(
                        "run_until_rip({target:#x}): process left the run loop with {other:?} after {steps} steps"
                    )))
                }
            }
        }
        Ok(steps)
    }

    pub fn run(mut self) -> Result<RunResult> {
        self.run_borrowed()
    }

    pub fn run_borrowed(&mut self) -> Result<RunResult> {
        let mut steps: u64 = 0;
        let refresh_kuser = self.clock.is_virtual();
        let mut next_kuser_refresh = KUSER_REFRESH_INSTRUCTIONS;
        const TAIL: usize = 24;
        let mut recent: std::collections::VecDeque<u64> = std::collections::VecDeque::with_capacity(TAIL + 1);
        let mut debugging = self.dbg.is_attached();
        let mut stepping = false;
        let mut step_target = u64::MAX;
        let exit_code = loop {
            if self.max_steps != 0 && steps >= self.max_steps {
                let tail = self.rip_trail(&recent);
                let e = EmuError::Os(format!("instruction budget exhausted after {steps} steps"));
                return Err(self.fault_debugged(debugging, e, steps, &tail));
            }
            recent.push_back(self.cpu.state().rip);
            if recent.len() > TAIL {
                recent.pop_front();
            }

            let step_rip = self.cpu.state().rip;
            self.os.set_guest_mode32(self.cpu.bits() == Bits::B32);
            if debugging {
                let mut reason = self.debug_pending_stop(steps, step_target);
                if reason.is_none() {
                    match self.dbg.take_request() {
                        StopRequest::Pause => reason = Some(StopReason::Paused),
                        StopRequest::Step => {
                            step_target = steps + 1;
                            stepping = true;
                        }
                        StopRequest::Run => {}
                    }
                }
                if reason.is_none() && self.dbg.is_break(step_rip) {
                    reason = Some(StopReason::Breakpoint { rip: step_rip });
                }
                if let Some(reason) = reason {
                    let trail = self.rip_trail(&recent);
                    match self.debug_stop(reason, steps, &trail) {
                        DebugAction::Continue => {
                            stepping = false;
                            step_target = u64::MAX;
                        }
                        DebugAction::Step => {
                            stepping = true;
                            step_target = steps + 1;
                        }
                        DebugAction::Detach => {
                            debugging = false;
                            stepping = false;
                            step_target = u64::MAX;
                        }
                        DebugAction::Kill => {
                            return Err(EmuError::Os(format!(
                                "the debugger abandoned the run after {steps} instructions"
                            )));
                        }
                    }
                }
            }
            let interpret_only = debugging && self.debug_needs_interpreter(stepping, steps);
            if let Some(jit) = self.jit.as_mut().filter(|_| !interpret_only) {
                let mode = match self.cpu.bits() {
                    Bits::B64 => exemu_jit::Mode::Long,
                    Bits::B32 => exemu_jit::Mode::Protected,
                };
                let budget = if self.exc_depth != 0 {
                    0
                } else {
                    let mut b = CHAIN_MAX_INSTRUCTIONS;
                    b = b.min(exemu_core::Hooks::retire_budget(&self.os));
                    if refresh_kuser {
                        b = b.min(next_kuser_refresh.saturating_sub(steps));
                    }
                    if self.max_steps != 0 {
                        b = b.min(self.max_steps.saturating_sub(steps));
                    }
                    if debugging {
                        b = b.min(self.dbg.break_at_step().saturating_sub(steps));
                    }
                    b
                };
                let ran = jit.run(self.cpu.state_mut(), &mut self.mem, mode, budget);
                let insns = ran.insns();
                if insns != 0 {
                    self.clock.retire(insns as u64);
                    steps += insns as u64;
                    exemu_core::Hooks::retire(
                        &mut self.os,
                        insns as u64,
                        self.cpu.state_mut(),
                        &mut self.mem,
                    )?;
                    self.apply_thread_mode_switch();
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                if matches!(ran, exemu_jit::Run::Executed { .. }) {
                    continue;
                }
            }
            let outcome = self.cpu.step(&mut self.mem, &mut self.os);
            self.apply_thread_mode_switch();
            let tail = || self.rip_trail(&recent);
            match outcome {
                Ok(Exit::Continue) => {
                    steps += 1;
                    if refresh_kuser && steps >= next_kuser_refresh {
                        refresh_kuser_time(&mut self.mem, &self.clock)?;
                        next_kuser_refresh =
                            (steps / KUSER_REFRESH_INSTRUCTIONS + 1) * KUSER_REFRESH_INSTRUCTIONS;
                    }
                    if self.exc_depth != 0 && !self.at_exc_dispatcher(step_rip) {
                        self.exc_depth = 0;
                    }
                }
                Ok(Exit::ProcessExit(code)) => {
                    if let Some(u) = self.os.take_unhandled_exception() {
                        let t = self.rip_trail(&recent);
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    break code;
                }
                Ok(Exit::Halted) => break 0,
                Ok(Exit::Interrupt(n)) => {
                    let t = tail();
                    if self.try_deliver_hw_exception(ExcSource::Interrupt(n), steps, &t)? {
                        continue;
                    }
                    if let Some(u) = self.os.take_unhandled_exception() {
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    let e = EmuError::Os(format!("unhandled interrupt {n:#x}"));
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
                Ok(Exit::Syscall(index)) => {
                    let t = tail();
                    let e = EmuError::Os(format!("SYSCALL {index:#x} escaped the dispatcher"));
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
                Err(e) => {
                    let t = tail();
                    if self.try_deliver_hw_exception(ExcSource::Error(&e), steps, &t)? {
                        continue;
                    }
                    if let Some(u) = self.os.take_unhandled_exception() {
                        return Err(self.unhandled_fault(debugging, u, steps, &t));
                    }
                    return Err(self.fault_debugged(debugging, e, steps, &t));
                }
            }
        };

        if let Some(tx) = self.dbg_events.as_ref() {
            let _ = tx.send(DebugEvent::Exited { code: exit_code, steps });
        }

        Ok(RunResult {
            exit_code,
            steps,
            stdout: self.os.captured_stdout().to_vec(),
            stderr: self.os.captured_stderr().to_vec(),
            sandbox: self.sandbox.clone(),
            children_created: self.os.children_created(),
            jit: self.jit_report(),
        })
    }

    fn rip_trail(&self, recent: &std::collections::VecDeque<u64>) -> Vec<u64> {
        match self.jit.as_ref() {
            Some(jit) => jit.recent_blocks(),
            None => recent.iter().copied().collect(),
        }
    }

    pub fn debug(&self) -> &DebugControl {
        &self.dbg
    }

    fn debug_pending_stop(&self, steps: u64, step_target: u64) -> Option<StopReason> {
        if let Some((addr, kind)) = self.dbg.take_watch_hit() {
            return Some(StopReason::Watch { addr, kind });
        }
        if steps >= step_target {
            return Some(StopReason::StepComplete);
        }
        if steps >= self.dbg.break_at_step() {
            self.dbg.set_break_at_step(None);
            return Some(StopReason::StepCount { steps });
        }
        None
    }

    fn debug_needs_interpreter(&self, stepping: bool, steps: u64) -> bool {
        stepping
            || self.dbg.break_at_step().saturating_sub(steps) <= JIT_EXACT_STOP_WINDOW
    }

    fn debug_stop(&mut self, reason: StopReason, steps: u64, trail: &[u64]) -> DebugAction {
        let Some(cmds) = self.dbg_cmds.take() else { return DebugAction::Continue };
        let events = self.dbg_events.take();
        let action = self.debug_serve(&cmds, events.as_ref(), reason, steps, trail);
        if matches!(action, DebugAction::Detach) {
            self.debug_disarm_all();
        } else {
            self.dbg_cmds = Some(cmds);
            self.dbg_events = events;
        }
        action
    }

    fn debug_serve(
        &mut self,
        cmds: &std::sync::mpsc::Receiver<DebugCommand>,
        events: Option<&std::sync::mpsc::Sender<DebugEvent>>,
        reason: StopReason,
        steps: u64,
        trail: &[u64],
    ) -> DebugAction {
        let snapshot = self.debug_snapshot(reason, steps, trail);
        if let Some(tx) = events {
            let _ = tx.send(DebugEvent::Stopped(Box::new(snapshot)));
        }
        loop {
            let Ok(cmd) = cmds.recv() else {
                return DebugAction::Detach;
            };
            match cmd {
                DebugCommand::Resume => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Resumed);
                    }
                    return DebugAction::Continue;
                }
                DebugCommand::Step => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Resumed);
                    }
                    return DebugAction::Step;
                }
                DebugCommand::Pause => {}
                DebugCommand::ArmBreak(addr) => self.dbg.arm_break(addr),
                DebugCommand::DisarmBreak(addr) => self.dbg.disarm_break(addr),
                DebugCommand::ArmWatch { base, len, kind } => self.dbg.arm_watch(base, len, kind),
                DebugCommand::DisarmWatch(base) => self.dbg.disarm_watch(base),
                DebugCommand::BreakAtStep(n) => self.dbg.set_break_at_step(n),
                DebugCommand::ReadMemory { addr, len } => {
                    let bytes = self.debug_read(addr, len);
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Memory { addr, bytes });
                    }
                }
                DebugCommand::Disassemble { addr, .. } => {
                    if let Some(tx) = events {
                        let _ = tx.send(DebugEvent::Error(format!(
                            "cannot disassemble at {addr:#x}: the decoder is not a public seam yet \
                             (roadmap W9.2). Read the bytes with ReadMemory instead."
                        )));
                    }
                }
                DebugCommand::Detach => return DebugAction::Detach,
                DebugCommand::Kill => return DebugAction::Kill,
            }
        }
    }

    fn debug_snapshot(&self, stop: StopReason, steps: u64, trail: &[u64]) -> DebugSnapshot {
        let regs = self.cpu.state().clone();
        let table = self.os.unwind_table();
        let backtrace = if table.is_empty() {
            Vec::new()
        } else {
            exemu_core::unwind::backtrace(table, self.image_base, &regs, &self.mem, 24)
        };
        DebugSnapshot {
            stop,
            steps,
            bits: match self.cpu.bits() {
                Bits::B64 => 64,
                Bits::B32 => 32,
            },
            rip_note: self.os.describe_addr(regs.rip),
            trail: trail.to_vec(),
            backtrace,
            modules: self
                .os
                .loaded_modules()
                .into_iter()
                .map(|(name, base, size)| exemu_core::ModuleInfo { name, base, size })
                .collect(),
            threads: Vec::new(),
            handles: Vec::new(),
            regions: self.mem.regions().cloned().collect(),
            regs,
        }
    }

    fn debug_read(&self, addr: u64, len: u64) -> Vec<u8> {
        let len = len.min(DEBUG_READ_MAX) as usize;
        let mut buf = vec![0u8; len];
        if self.mem.read(addr, &mut buf).is_ok() {
            return buf;
        }
        buf.clear();
        for i in 0..len as u64 {
            let mut b = [0u8; 1];
            if self.mem.read(addr.wrapping_add(i), &mut b).is_err() {
                break;
            }
            buf.push(b[0]);
        }
        buf
    }

    fn fault_debugged(
        &mut self,
        debugging: bool,
        err: EmuError,
        steps: u64,
        recent: &[u64],
    ) -> EmuError {
        let err = self.fault(err, steps, recent);
        if debugging {
            if let EmuError::Fault { report, .. } = &err {
                let report = report.clone();
                self.debug_stop(StopReason::Faulted { report }, steps, recent);
            }
        }
        err
    }

    fn unhandled_fault(
        &mut self,
        debugging: bool,
        u: exemu_os::UnhandledException,
        steps: u64,
        recent: &[u64],
    ) -> EmuError {
        let exemu_os::UnhandledException { code, address, how } = u;
        let e = EmuError::Os(format!(
            "unhandled guest exception {code:#010x} at {} — {how}",
            self.addr_note(address)
        ));
        self.fault_debugged(debugging, e, steps, recent)
    }

    fn debug_disarm_all(&self) {
        for addr in self.dbg.breakpoints() {
            self.dbg.disarm_break(addr);
        }
        for w in self.dbg.watchpoints() {
            self.dbg.disarm_watch(w.base);
        }
        self.dbg.set_break_at_step(None);
        self.dbg.request(StopRequest::Run);
    }

    pub fn jit_report(&self) -> Option<JitReport> {
        let jit = self.jit.as_ref()?;
        let s = jit.stats();
        Some(JitReport {
            blocks_compiled: s.blocks_compiled,
            blocks_executed: s.blocks_executed,
            chains: s.chains,
            insns_executed: s.insns_executed,
            faults: s.faults,
            not_compiled: s.not_compiled,
            flushes: s.flushes,
            code_bytes: s.peak_code_bytes.max(jit.code_bytes()),
            declined: s.top_declined(16),
        })
    }

    fn at_exc_dispatcher(&self, rip: u64) -> bool {
        self.os
            .module_base("ntdll.dll")
            .is_some_and(|b| rip == b + exemu_os::RVA_KI_USER_EXCEPTION_DISPATCHER)
    }

    fn try_deliver_hw_exception(&mut self, src: ExcSource<'_>, steps: u64, recent: &[u64]) -> Result<bool> {
        let Some(ntdll_base) = self.os.module_base("ntdll.dll") else {
            return Ok(false);
        };
        let mode = if self.wow64.is_some() && self.cpu.bits() == Bits::B32 {
            exemu_os::TrapMode::Compat32
        } else {
            exemu_os::TrapMode::Long
        };
        const MAX_EXC_DEPTH: u32 = 8;
        if self.exc_depth >= MAX_EXC_DEPTH {
            return Ok(false);
        }

        let cpu = self.cpu.state();
        let (code, address, info): (u32, u64, Vec<u64>) = match src {
            ExcSource::Interrupt(0) => (0xC000_0094, cpu.rip, Vec::new()),
            ExcSource::Interrupt(3) => (0x8000_0003, cpu.rip.wrapping_add(1), Vec::new()),
            ExcSource::Error(e) => match e.cause() {
                EmuError::Permission { addr, needed } => {
                    let rw = match *needed {
                        "write" => 1u64,
                        "execute" => 8u64,
                        _ => 0u64,
                    };
                    (0xC000_0005, *addr, vec![rw, *addr])
                }
                EmuError::Unmapped { addr, .. } => (0xC000_0005, *addr, vec![0, *addr]),
                _ => return Ok(false),
            },
            ExcSource::Interrupt(_) => return Ok(false),
        };

        if self.os.note_exception_delivery(code, address, cpu.rip).is_err() {
            return Ok(false);
        }

        if std::env::var_os("EXEMU_FAULT_TRACE").is_some() {
            let rip = self.cpu.state().rip;
            let mut bytes = [0u8; 16];
            let _ = self.mem.read(rip, &mut bytes);
            eprintln!(
                "[exc] code={code:#x} at={address:#x} rip={rip:#x} {} bytes={bytes:02x?}",
                self.os.module_for_addr(rip).unwrap_or_default()
            );
        }

        if std::env::var_os("EXEMU_DBG").is_some() {
            eprintln!(
                "[exemu] delivering exception {code:#010x} to the guest, faulting address {} ({})
{}",
                self.addr_note(address),
                memory_map::locate(self.mem.regions(), address),
                self.fault_report(
                    &format!("guest exception {code:#010x} (address {address:#x})"),
                    None,
                    steps,
                    recent,
                ),
            );
        }

        let rip_before = self.cpu.state().rip;
        if let ExcSource::Interrupt(3) = src {
            self.cpu.state_mut().rip = rip_before.wrapping_add(1);
        }

        if let Err(why) = self.os.deliver_hw_exception(
            self.cpu.state_mut(),
            &mut self.mem,
            ntdll_base,
            exemu_os::Trap { code, address, info: &info, mode },
        ) {
            self.cpu.state_mut().rip = rip_before;
            if std::env::var_os("EXEMU_DBG").is_some() {
                eprintln!("[exemu] could not deliver exception {code:#010x} to the guest: {why}");
            }
            return Ok(false);
        }
        if mode == exemu_os::TrapMode::Compat32 {
            self.cpu.set_bits(Bits::B64);
        }
        self.exc_depth += 1;
        Ok(true)
    }

    fn apply_thread_mode_switch(&mut self) {
        if let Some(mode32) = self.os.take_thread_mode_switch() {
            self.cpu.set_bits(if mode32 { Bits::B32 } else { Bits::B64 });
        }
    }

    fn fault(&self, err: EmuError, steps: u64, recent: &[u64]) -> EmuError {
        let report = self.fault_report(&err.to_string(), Some(&err), steps, recent);
        EmuError::Fault { report, cause: Box::new(err) }
    }

    fn addr_note(&self, addr: u64) -> String {
        match self.os.module_at(addr) {
            Some((name, rva)) => format!("{addr:#x} ({name}+{rva:#x})"),
            None => format!("{addr:#x}"),
        }
    }

    fn fault_report(&self, headline: &str, err: Option<&EmuError>, steps: u64, recent: &[u64]) -> String {
        use std::fmt::Write;
        let s = self.cpu.state();
        let mut o = String::new();
        let _ = writeln!(o, "{headline}");

        if let Some(EmuError::Unmapped { addr, .. }) = &err {
            let (lo, hi) = self.os.thunk_range();
            if *addr >= lo && *addr < hi {
                let sym = self.os.symbol_for_thunk(*addr).unwrap_or_else(|| "<unknown import>".into());
                let _ = writeln!(
                    o,
                    "  note: {addr:#018x} is the import thunk for {sym}.\n\
                     \x20       the guest is dereferencing it as data, so {sym} is a *data* export,\n\
                     \x20       not a function. exemu resolves imports as call targets only; data\n\
                     \x20       imports (common in msvcrt/UCRT startup) are not supported."
                );
            }
        }

        let null_deref = s.rip < NULL_GUARD
            || matches!(
                err,
                Some(EmuError::Unmapped { addr, .. } | EmuError::Permission { addr, .. }) if *addr < NULL_GUARD
            );
        if null_deref {
            let suspects = self.os.zero_returning_stubs();
            let _ = writeln!(
                o,
                "  note: this is a NULL dereference (address below {NULL_GUARD:#x} — a null pointer\n\
                 \x20       plus at most a struct-field offset), which in exemu almost always means\n\
                 \x20       an unimplemented API returned 0 and the guest kept it as a pointer."
            );
            if suspects.is_empty() {
                let _ = writeln!(
                    o,
                    "  note: no unimplemented Win32 stub has returned 0 in this run, so the NULL\n\
                     \x20       came from somewhere else — guest logic, or a *implemented* API\n\
                     \x20       returning the wrong thing."
                );
            } else {
                let _ = writeln!(
                    o,
                    "  suspects (unimplemented stubs that returned 0, most recent first): {}",
                    suspects.join(", ")
                );
            }
        }

        if let Some(EmuError::Unmapped { addr, .. } | EmuError::Permission { addr, .. }) = err {
            let _ = writeln!(o, "  faulting address {addr:#x}: {}", memory_map::locate(self.mem.regions(), *addr));
        }

        let _ = writeln!(o, "  faulted after {steps} instructions");
        let _ = writeln!(
            o,
            "  rip={:#018x}  rsp={:#018x}  rbp={:#018x}  rflags={:#06x}",
            s.rip,
            s.rsp(),
            s.reg(exemu_core::Reg::Rbp),
            s.rflags
        );
        if self.os.module_at(s.rip).is_some() {
            let _ = writeln!(o, "  rip is {}", self.addr_note(s.rip));
        }
        for row in s.gpr.chunks(4).enumerate() {
            let (r, regs) = row;
            let _ = write!(o, "  ");
            for (i, v) in regs.iter().enumerate() {
                let name = exemu_core::Reg::NAMES[r * 4 + i];
                let _ = write!(o, "{name:>3}={v:#018x}  ");
            }
            o.push('\n');
        }
        let mut buf = [0u8; 16];
        match self.mem.fetch(s.rip, &mut buf) {
            Ok(()) => {
                let _ = write!(o, "  bytes @ rip:");
                for b in buf {
                    let _ = write!(o, " {b:02x}");
                }
            }
            Err(_) => {
                let _ = write!(o, "  (cannot fetch instruction bytes at rip — page not mapped/executable)");
            }
        }
        if !recent.is_empty() {
            let _ = write!(o, "\n  recent rip trail (oldest→newest):");
            for r in recent {
                let _ = write!(o, " {r:#x}");
            }
            if recent.iter().any(|r| self.os.module_at(*r).is_some()) {
                let _ = write!(o, "\n  recent rip trail (named):");
                for r in recent {
                    let _ = write!(o, " {}", self.os.describe_addr(*r));
                }
            }
        }
        let function_table = self.os.unwind_table();
        if !function_table.is_empty() {
            let frames = exemu_core::unwind::backtrace(
                function_table,
                self.image_base,
                s,
                &self.mem,
                24,
            );
            if !frames.is_empty() {
                let _ = write!(o, "\n  call stack (virtual unwind, innermost first): {}", self.addr_note(s.rip));
                for f in &frames {
                    let _ = write!(o, " ← {}", self.addr_note(*f));
                }
            }
        }
        if std::env::var_os("EXEMU_DBG").is_some() {
            let _ = write!(o, "\n{}", memory_map::dump(self.mem.regions()));
        }
        let modules = self.os.loaded_modules();
        if !modules.is_empty() {
            let _ = write!(o, "\n  loaded modules:");
            for (name, base, size) in &modules {
                let _ = write!(o, " {name}@{base:#x}+{size:#x}");
            }
        }
        o.push('\n');
        o
    }
}

pub fn load_and_run(pe_bytes: &[u8], cfg: RunConfig) -> Result<RunResult> {
    let mut cfg = cfg;
    Process::load(pe_bytes, &mut cfg)?.run()
}

fn map_kuser_shared_data(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
    mem.map(Region::new(
        "kuser_shared_data",
        KUSER_SHARED_DATA_BASE,
        PAGE,
        Perm::READ,
    ))?;
    mem.map(Region::new(
        "kuser_dispatcher",
        KUSER_DISPATCHER_PAGE,
        PAGE,
        Perm::RWX,
    ))?;

    if clock.is_virtual() {
        refresh_kuser_time(mem, clock)?;
    } else {
        let now_100ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let system_time = (now_100ns.as_secs() + KUSER_FILETIME_EPOCH_DIFF_SECS) * 10_000_000
            + now_100ns.subsec_nanos() as u64 / 100;
        write_ksystem_time(mem, KUSER_SYSTEM_TIME, system_time)?;
        write_ksystem_time(mem, KUSER_INTERRUPT_TIME, 0)?;
        write_ksystem_time(mem, KUSER_TICK_COUNT, 0)?;
    }

    mem.poke(
        KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER,
        &KUSER_TICK_COUNT_MULTIPLIER_VALUE.to_le_bytes(),
    )?;
    mem.poke(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL, &1u32.to_le_bytes())?;
    Ok(())
}

fn write_ksystem_time(mem: &mut VirtualMemory, off: u64, val: u64) -> Result<()> {
    let low = (val & 0xFFFF_FFFF) as u32;
    let high = (val >> 32) as u32;
    mem.poke(KUSER_SHARED_DATA_BASE + off, &low.to_le_bytes())?;
    mem.poke(KUSER_SHARED_DATA_BASE + off + 4, &high.to_le_bytes())?;
    mem.poke(KUSER_SHARED_DATA_BASE + off + 8, &high.to_le_bytes())
}

fn refresh_kuser_time(mem: &mut VirtualMemory, clock: &GuestClock) -> Result<()> {
    let Some(monotonic) = clock.monotonic_100ns() else { return Ok(()) };
    let Some(filetime) = clock.filetime() else { return Ok(()) };
    write_ksystem_time(mem, KUSER_SYSTEM_TIME, filetime)?;
    write_ksystem_time(mem, KUSER_INTERRUPT_TIME, monotonic)?;
    write_ksystem_time(mem, KUSER_TICK_COUNT, monotonic / KUSER_TICK_PERIOD_100NS)
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

const KUSER_FILETIME_EPOCH_DIFF_SECS: u64 = 11_644_473_600;

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

const CMDLINE_MAX_BYTES: usize = 0x3F0;

fn truncate_cmdline(mut cmdline: String) -> String {
    if cmdline.len() > CMDLINE_MAX_BYTES {
        let mut end = CMDLINE_MAX_BYTES;
        while end > 0 && !cmdline.is_char_boundary(end) {
            end -= 1;
        }
        cmdline.truncate(end);
    }
    cmdline
}

fn build_cmdline(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kuser_shared_data_fields_readable() {
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem, &GuestClock::host()).expect("map KUSER_SHARED_DATA");

        assert_eq!(KUSER_SHARED_DATA_BASE, 0x7ffe_0000);

        let system_call = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_CALL)
            .expect("read SystemCall");
        assert_ne!(system_call, 0, "SystemCall selector must be nonzero");

        let system_time_high = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 4)
            .expect("read SystemTime.High1Time");
        assert_ne!(system_time_high, 0, "SystemTime should be a real clock value");
        let system_time_high2 = mem
            .read_u32(KUSER_SHARED_DATA_BASE + KUSER_SYSTEM_TIME + 8)
            .expect("read SystemTime.High2Time");
        assert_eq!(system_time_high, system_time_high2);

        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_INTERRUPT_TIME)
                .expect("read InterruptTime"),
            0
        );
        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT)
                .expect("read TickCount"),
            0
        );

        assert_eq!(KUSER_DISPATCHER_PAGE, KUSER_SHARED_DATA_BASE + PAGE);
        mem.read_u8(KUSER_DISPATCHER_PAGE)
            .expect("dispatcher landing page is mapped");

        assert_eq!(
            mem.read_u32(KUSER_SHARED_DATA_BASE + KUSER_TICK_COUNT_MULTIPLIER)
                .expect("read TickCountMultiplier"),
            KUSER_TICK_COUNT_MULTIPLIER_VALUE
        );
    }

    #[test]
    fn kuser_time_fields_track_the_virtual_clock() {
        let read_ksystem_time = |mem: &VirtualMemory, off: u64| -> u64 {
            let lo = mem.read_u32(KUSER_SHARED_DATA_BASE + off).unwrap() as u64;
            let hi = mem.read_u32(KUSER_SHARED_DATA_BASE + off + 4).unwrap() as u64;
            (hi << 32) | lo
        };

        let clock = GuestClock::virtualized();
        let mut mem = VirtualMemory::new();
        map_kuser_shared_data(&mut mem, &clock).expect("map KUSER_SHARED_DATA");

        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 0);
        assert_eq!(read_ksystem_time(&mem, KUSER_TICK_COUNT), 0);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME,
            "the wall clock starts at the fixed virtual epoch, not at the host's now"
        );

        for _ in 0..exemu_core::VIRTUAL_INSTRUCTIONS_PER_SECOND {
            clock.retire_one();
        }
        refresh_kuser_time(&mut mem, &clock).expect("refresh");
        assert_eq!(read_ksystem_time(&mem, KUSER_INTERRUPT_TIME), 10_000_000);
        assert_eq!(
            read_ksystem_time(&mem, KUSER_SYSTEM_TIME),
            exemu_core::VIRTUAL_EPOCH_FILETIME + 10_000_000
        );
        let ticks = read_ksystem_time(&mem, KUSER_TICK_COUNT);
        assert_eq!(ticks, 64);
        let ms = (ticks * u64::from(KUSER_TICK_COUNT_MULTIPLIER_VALUE)) >> 24;
        assert_eq!(ms, 1_000, "the guest's own tick→ms conversion agrees");
    }

    #[test]
    fn a_long_command_line_is_clamped_to_the_env_region() {
        assert_eq!(truncate_cmdline("short".into()), "short");

        let long = "a".repeat(CMDLINE_MAX_BYTES * 3);
        let cut = truncate_cmdline(long);
        assert_eq!(cut.len(), CMDLINE_MAX_BYTES);

        let wide = "é".repeat(CMDLINE_MAX_BYTES);
        let cut = truncate_cmdline(wide);
        assert!(cut.len() <= CMDLINE_MAX_BYTES, "{} bytes", cut.len());
        assert!(cut.chars().all(|c| c == 'é'), "cut on a character boundary");
        let utf16_bytes = cut.encode_utf16().count() * 2 + 2;
        assert!(utf16_bytes <= 0xC00, "{utf16_bytes} UTF-16 bytes");
        assert!(cut.len() < 0x400, "{} bytes + NUL", cut.len());
    }

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
