use exemu_core::{CpuState, Memory, Reg, Result};

use crate::WinOs;

pub(crate) const MEMORY_WINE_UNIX_FUNCS: u32 = 1000;
pub(crate) const MEMORY_WINE_UNIX_WOW64_FUNCS: u32 = 1001;

const PE32_MAGIC: u16 = 0x10B;
const PE32_PLUS_MAGIC: u16 = 0x20B;
const PE32_EXPORT_DIR: u64 = 96;
const PE32_PLUS_EXPORT_DIR: u64 = 112;

pub(crate) const SSDT_NT_QUERY_VIRTUAL_MEMORY: u32 = 0x23;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
use crate::syscall::STATUS_NOT_IMPLEMENTED;

pub type UnixEntry = fn(&mut WinOs, &mut CpuState, &mut dyn Memory, args: u64) -> Result<u32>;

pub struct Unixlib {
    pub name: &'static str,
    pub table: &'static [UnixEntry],
    pub wow64: bool,
}

static NTDLL_UNIXLIB: &[UnixEntry] = &[
    load_so_dll,
    unwind_builtin_dll,
    wine_dbg_write,
    wine_server_call,
    server_fd_to_handle,
    server_handle_to_fd,
    spawnvp,
    system_time_precise,
];

#[allow(dead_code)]
pub(crate) const NTDLL_WINE_SERVER_CALL: u32 = 3;

fn load_so_dll(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_DLL_NOT_FOUND)
}

fn unwind_builtin_dll(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_UNSUCCESSFUL)
}

fn wine_dbg_write(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args == 0 {
        return Ok(0);
    }
    let (str_ptr, len) = if os.unix_call_wow64 {
        (mem.read_u32(args)? as u64, mem.read_u32(args + 4)? as usize)
    } else {
        (mem.read_u64(args)?, mem.read_u32(args + 8)? as usize)
    };
    if str_ptr == 0 || len == 0 {
        return Ok(0);
    }
    let n = len.min(0x1_0000);
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = mem.read_u8(str_ptr + i as u64)?;
    }
    os.wine_dbg_sink(&buf);
    Ok(n as u32)
}

fn wine_server_call(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.wine_server_call(args, cpu, mem)
}

fn server_fd_to_handle(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

fn server_handle_to_fd(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

fn spawnvp(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NOT_IMPLEMENTED)
}

fn system_time_precise(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        mem.write_u64(args, os.filetime_now())?;
    }
    Ok(STATUS_SUCCESS)
}

impl WinOs {
    pub fn register_unixlib(&mut self, module_base: u64, lib: Unixlib) -> u64 {
        if let Some(&h) = self.unixlib_of_module.get(&module_base) {
            return h;
        }
        let handle = self.unixlibs.len() as u64;
        self.unixlibs.push(lib);
        self.unixlib_of_module.insert(module_base, handle);
        handle
    }

    pub fn register_ntdll_unixlib(&mut self, ntdll_base: u64) -> u64 {
        self.register_unixlib(
            ntdll_base,
            Unixlib { name: "ntdll", table: NTDLL_UNIXLIB, wow64: false },
        )
    }

    pub fn register_ntdll32_unixlib(&mut self, ntdll32_base: u64) -> u64 {
        self.register_unixlib(
            ntdll32_base,
            Unixlib { name: "ntdll32", table: NTDLL_UNIXLIB, wow64: true },
        )
    }

    pub(crate) fn unixlib_handle_of(&self, module_base: u64) -> Option<u64> {
        self.unixlib_of_module.get(&module_base).copied()
    }

    fn register_builtin_unixlib(&mut self, mem: &dyn Memory, base: u64, wow64: bool) -> Option<u64> {
        let name = module_name_at(mem, base)?;
        if self.cfg.trace {
            let side = if wow64 { "wow64 " } else { "" };
            eprintln!("[unixlib] {name} at {base:#x} asks for its {side}unix side");
        }
        let lib = match (name.to_ascii_lowercase().as_str(), wow64) {
            ("ws2_32.dll", false) => crate::net::ws2_32_unixlib(),
            ("ws2_32.dll", true) => crate::net::ws2_32_wow64_unixlib(),
            (crate::crypt32::CRYPT32_MODULE, false) => crate::crypt32::crypt32_unixlib(),
            (crate::audio::DRIVER_MODULE, false) => crate::audio::coreaudio_unixlib(),
            _ => return None,
        };
        Some(self.register_unixlib(base, lib))
    }

    pub(crate) fn wine_dbg_sink(&mut self, bytes: &[u8]) {
        if self.cfg.trace || std::env::var_os("EXEMU_WINE_DBG").is_some() {
            eprint!("[wine] {}", String::from_utf8_lossy(bytes));
        }
    }

    pub(crate) fn dispatch_unix_call(
        &mut self,
        handle: u64,
        code: u32,
        args: u64,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        self.unix_call_blocked = false;
        if self.cfg.trace {
            let name = self.unixlibs.get(handle as usize).map(|l| l.name).unwrap_or("?");
            eprintln!("[unixlib] {name}[{code}] args {args:#x}");
        }
        let Some(lib) = self.unixlibs.get(handle as usize) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        let wow64 = lib.wow64;
        let Some(entry) = lib.table.get(code as usize).copied() else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        self.unix_call_wow64 = wow64;
        entry(self, cpu, mem, args)
    }

    pub(crate) fn wine_unix_call(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = cpu.reg(Reg::Rcx);
        let code = cpu.reg(Reg::Rdx) as u32;
        let args = cpu.reg(Reg::R8);
        self.dispatch_unix_call(handle, code, args, cpu, mem)
    }

    pub(crate) fn nt_query_virtual_memory(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let info_class = self.syscall_arg(cpu, mem, 2)? as u32;

        let wow64 = match info_class {
            MEMORY_WINE_UNIX_FUNCS => false,
            MEMORY_WINE_UNIX_WOW64_FUNCS => true,
            crate::vm::MEMORY_BASIC_INFORMATION => return self.nt_query_virtual_memory_basic(cpu, mem),
            _ => return Ok(STATUS_INVALID_PARAMETER),
        };

        let base_address = self.syscall_arg(cpu, mem, 1)?;
        let buffer = self.syscall_arg(cpu, mem, 3)?;
        let length = self.syscall_arg(cpu, mem, 4)?;
        let return_length = self.syscall_arg(cpu, mem, 5)?;

        if buffer == 0 || length < 8 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let handle = match self.unixlib_handle_of(base_address) {
            Some(h) if self.unixlibs.get(h as usize).is_some_and(|l| l.wow64 == wow64) => h,
            Some(_) => return Ok(STATUS_INVALID_ADDRESS),
            None => match self.register_builtin_unixlib(mem, base_address, wow64) {
                Some(h) => h,
                None => return Ok(STATUS_INVALID_ADDRESS),
            },
        };
        mem.write_u64(buffer, handle)?;
        if return_length != 0 {
            mem.write_u64(return_length, 8)?;
        }
        Ok(STATUS_SUCCESS)
    }
}

fn module_name_at(mem: &dyn Memory, base: u64) -> Option<String> {
    if mem.read_u16(base).ok()? != 0x5A4D {
        return None;
    }
    let e_lfanew = mem.read_u32(base + 0x3C).ok()? as u64;
    if mem.read_u32(base + e_lfanew).ok()? != 0x0000_4550 {
        return None;
    }
    let opt = base + e_lfanew + 24;
    let export_dir = match mem.read_u16(opt).ok()? {
        PE32_PLUS_MAGIC => PE32_PLUS_EXPORT_DIR,
        PE32_MAGIC => PE32_EXPORT_DIR,
        _ => return None,
    };
    let export_rva = mem.read_u32(opt + export_dir).ok()? as u64;
    if export_rva == 0 {
        return None;
    }
    let name_rva = mem.read_u32(base + export_rva + 12).ok()? as u64;
    if name_rva == 0 {
        return None;
    }
    let raw = mem.read_cstr(base + name_rva, 64).ok()?;
    Some(String::from_utf8_lossy(&raw).into_owned())
}

pub(crate) fn ssdt_nt_query_virtual_memory(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_virtual_memory(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::Exit;
    use exemu_memory::VirtualMemory;

    fn os64() -> WinOs {
        WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() })
    }

    #[test]
    fn query_then_call_system_time_precise() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();

        let mut os = os64();
        let ntdll_base = 0x7f00_0000;
        let expected_handle = os.register_ntdll_unixlib(ntdll_base);

        let out_buf = 0x2_0100;
        let ret_len = 0x2_0108;
        cpu_query(&mut os, &mut mem, ntdll_base, out_buf, ret_len);
        let handle = mem.read_u64(out_buf).unwrap();
        assert_eq!(handle, expected_handle, "query returns the registered handle");
        assert_eq!(mem.read_u64(ret_len).unwrap(), 8, "return_length written");

        let host_before = crate::time::filetime_now();
        let args = 0x2_0200;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rcx, handle);
        cpu.set_reg(Reg::Rdx, 7);
        cpu.set_reg(Reg::R8, args);
        let status = os.wine_unix_call(&mut cpu, &mut mem).unwrap();
        let host_after = crate::time::filetime_now();
        assert_eq!(status, STATUS_SUCCESS, "system_time_precise succeeded");
        let precise = mem.read_u64(args).unwrap();
        assert!(
            (host_before..=host_after).contains(&precise),
            "system_time_precise {precise} within host clock bracket [{host_before}, {host_after}]",
        );
    }

    fn cpu_query(os: &mut WinOs, mem: &mut VirtualMemory, base: u64, out_buf: u64, ret_len: u64) {
        let gsp = 0x2_0800;
        mem.write_u64(gsp + 0x28, 8).unwrap();
        mem.write_u64(gsp + 0x30, ret_len).unwrap();
        os.set_syscall_guest_rsp_for_test(gsp);

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, 0xFFFF_FFFF_FFFF_FFFF);
        cpu.set_reg(Reg::Rdx, base);
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64);
        cpu.set_reg(Reg::R9, out_buf);
        let status = os.nt_query_virtual_memory(&mut cpu, mem).unwrap();
        assert_eq!(status, STATUS_SUCCESS);
    }

    #[test]
    fn bad_handle_or_code_is_invalid_parameter() {
        let mut mem = VirtualMemory::new();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        let mut cpu = CpuState::default();
        assert_eq!(os.dispatch_unix_call(h + 99, 0, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
        assert_eq!(os.dispatch_unix_call(h, 8, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
        assert_eq!(os.dispatch_unix_call(h, 999, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn all_eight_entries_walk_without_faulting() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x3_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        let mut cpu = CpuState::default();

        let msg = 0x3_0100;
        mem.write(msg, b"hi").unwrap();
        let dbg_args = 0x3_0200;
        mem.write_u64(dbg_args, msg).unwrap();
        mem.write_u64(dbg_args + 8, 2).unwrap();
        let time_args = 0x3_0300;
        let srv_req = 0x3_0400;

        let expected = [
            (0u32, STATUS_DLL_NOT_FOUND, 0u64),
            (1, STATUS_UNSUCCESSFUL, 0),
            (2, 2, dbg_args),
            (3, STATUS_NOT_IMPLEMENTED, srv_req),
            (4, STATUS_NOT_IMPLEMENTED, 0),
            (5, STATUS_NOT_IMPLEMENTED, 0),
            (6, STATUS_NOT_IMPLEMENTED, 0),
            (7, STATUS_SUCCESS, time_args),
        ];
        for (code, want, args) in expected {
            let got = os.dispatch_unix_call(h, code, args, &mut cpu, &mut mem).unwrap();
            assert_eq!(got, want, "entry {code} returned an unexpected NTSTATUS");
        }
        assert!(mem.read_u64(time_args).unwrap() > 0, "system_time_precise wrote a nonzero FILETIME");
        assert_eq!(os.dispatch_unix_call(h, 8, 0, &mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn query_rejects_bad_base_and_class() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.register_ntdll_unixlib(0x7f00_0000);
        os.set_syscall_guest_rsp_for_test(0x2_0800);

        let mut cpu = CpuState::default();
        mem.write_u64(0x2_0800 + 0x28, 8).unwrap();
        mem.write_u64(0x2_0800 + 0x30, 0).unwrap();
        cpu.set_reg(Reg::Rdx, 0xdead_0000);
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64);
        cpu.set_reg(Reg::R9, 0x2_0100);
        assert_eq!(os.nt_query_virtual_memory(&mut cpu, &mut mem).unwrap(), STATUS_INVALID_ADDRESS);

        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::Rdx, 0x7f00_0000);
        cpu.set_reg(Reg::R8, 0);
        cpu.set_reg(Reg::R9, 0x2_0100);
        assert_eq!(os.nt_query_virtual_memory(&mut cpu, &mut mem).unwrap(), STATUS_INVALID_PARAMETER);
    }

    fn map_named_image(mem: &mut VirtualMemory, base: u64, magic: u16, name: &str) {
        mem.map_fixed(base, 0x1000, exemu_core::Perm::RW, "image").unwrap();
        let e_lfanew = 0x80u64;
        let opt = base + e_lfanew + 24;
        let export_dir = if magic == PE32_MAGIC { PE32_EXPORT_DIR } else { PE32_PLUS_EXPORT_DIR };
        let (export_rva, name_rva) = (0x400u64, 0x500u64);
        mem.write_u16(base, 0x5A4D).unwrap();
        mem.write_u32(base + 0x3C, e_lfanew as u32).unwrap();
        mem.write_u32(base + e_lfanew, 0x0000_4550).unwrap();
        mem.write_u16(opt, magic).unwrap();
        mem.write_u32(opt + export_dir, export_rva as u32).unwrap();
        mem.write_u32(base + export_rva + 12, name_rva as u32).unwrap();
        mem.write(base + name_rva, name.as_bytes()).unwrap();
    }

    fn query_class(os: &mut WinOs, mem: &mut VirtualMemory, base: u64, class: u32) -> (u32, u64) {
        let gsp = 0x2_0800;
        mem.write_u64(gsp + 0x28, 8).unwrap();
        mem.write_u64(gsp + 0x30, 0).unwrap();
        mem.write_u64(0x2_0100, 0xA5A5_A5A5_A5A5_A5A5).unwrap();
        os.set_syscall_guest_rsp_for_test(gsp);
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, 0xFFFF_FFFF_FFFF_FFFF);
        cpu.set_reg(Reg::Rdx, base);
        cpu.set_reg(Reg::R8, class as u64);
        cpu.set_reg(Reg::R9, 0x2_0100);
        let status = os.nt_query_virtual_memory(&mut cpu, mem).unwrap();
        (status, mem.read_u64(0x2_0100).unwrap())
    }

    #[test]
    fn a_32bit_ws2_32_gets_its_unix_side_through_the_wow64_funcs_class() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x0050_0000;
        map_named_image(&mut mem, base, PE32_MAGIC, "ws2_32.dll");

        let (status, handle) = query_class(&mut os, &mut mem, base, MEMORY_WINE_UNIX_WOW64_FUNCS);
        assert_eq!(
            status, STATUS_SUCCESS,
            "wow64.dll turns a 32-bit DLL's MemoryWineUnixFuncs into MemoryWineUnixWow64Funcs; \
             refusing it makes ws2_32's DllMain return FALSE"
        );
        assert_ne!(handle, 0xA5A5_A5A5_A5A5_A5A5, "the handle is written to the caller's buffer");

        let mut cpu = CpuState::default();
        let status = os.dispatch_unix_call(handle, 0, 0x2_0200, &mut cpu, &mut mem).unwrap();
        assert!(os.unix_call_wow64, "a call through the wow64 handle is marked as carrying 32-bit args");
        assert_eq!(status, 11001, "and answers what the 64-bit side answers: no resolver");

        let (again, same) = query_class(&mut os, &mut mem, base, MEMORY_WINE_UNIX_WOW64_FUNCS);
        assert_eq!((again, same), (STATUS_SUCCESS, handle), "one module, one handle");
        let (native, _) = query_class(&mut os, &mut mem, base, MEMORY_WINE_UNIX_FUNCS);
        assert_eq!(native, STATUS_INVALID_ADDRESS, "the wow64 side is not handed out as the native one");
    }

    #[test]
    fn the_wow64_funcs_class_is_refused_for_a_library_without_a_wow64_side() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x0060_0000;
        map_named_image(&mut mem, base, PE32_MAGIC, crate::audio::DRIVER_MODULE);
        let (status, untouched) = query_class(&mut os, &mut mem, base, MEMORY_WINE_UNIX_WOW64_FUNCS);
        assert_eq!(status, STATUS_INVALID_ADDRESS, "its unix side reads 64-bit argument structs only");
        assert_eq!(untouched, 0xA5A5_A5A5_A5A5_A5A5);

        let base64 = 0x0070_0000;
        map_named_image(&mut mem, base64, PE32_PLUS_MAGIC, crate::audio::DRIVER_MODULE);
        let (status, _) = query_class(&mut os, &mut mem, base64, MEMORY_WINE_UNIX_FUNCS);
        assert_eq!(status, STATUS_SUCCESS, "the native class still answers the 64-bit driver");
    }

    #[test]
    fn ssdt_slot_answers_query() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, exemu_core::Perm::RW, "scratch").unwrap();
        let mut os = os64();
        let base = 0x7f00_0000;
        let h = os.register_ntdll_unixlib(base);
        os.set_syscall_handler(SSDT_NT_QUERY_VIRTUAL_MEMORY, ssdt_nt_query_virtual_memory);

        let gsp = 0x2_0800;
        mem.write_u64(gsp + 0x28, 8).unwrap();
        mem.write_u64(gsp + 0x30, 0).unwrap();

        let mut cpu = CpuState::default();
        cpu.set_rsp(gsp);
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_reg(Reg::R10, 0xFFFF_FFFF_FFFF_FFFF);
        cpu.set_reg(Reg::Rdx, base);
        cpu.set_reg(Reg::R8, MEMORY_WINE_UNIX_FUNCS as u64);
        cpu.set_reg(Reg::R9, 0x2_0100);

        let exit = os.dispatch_syscall(SSDT_NT_QUERY_VIRTUAL_MEMORY, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64, "NTSTATUS in RAX");
        assert_eq!(mem.read_u64(0x2_0100).unwrap(), h, "handle written to out-buffer");
    }
}
