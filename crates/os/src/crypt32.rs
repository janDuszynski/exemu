use exemu_core::{CpuState, Memory, Result};

use crate::unixlib::{UnixEntry, Unixlib};
use crate::WinOs;

pub(crate) const CRYPT32_MODULE: &str = "crypt32.dll";

const UNIX_FUNCS_COUNT: usize = 7;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;

fn process_attach(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_DLL_NOT_FOUND)
}

fn process_detach(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn open_cert_store(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_DLL_NOT_FOUND)
}

fn import_store_key(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_INVALID_PARAMETER)
}

fn import_store_cert(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_INVALID_PARAMETER)
}

fn close_cert_store(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn enum_root_certs(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_NO_MORE_ENTRIES)
}

static CRYPT32_UNIXLIB: [UnixEntry; UNIX_FUNCS_COUNT] = [
    process_attach,
    process_detach,
    open_cert_store,
    import_store_key,
    import_store_cert,
    close_cert_store,
    enum_root_certs,
];

pub(crate) fn crypt32_unixlib() -> Unixlib {
    Unixlib { name: "crypt32", table: &CRYPT32_UNIXLIB, wow64: false }
}

pub(crate) fn crypt32_wow64_unixlib() -> Unixlib {
    Unixlib { name: "crypt32 (wow64)", table: &CRYPT32_UNIXLIB, wow64: true }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unixlib::{MEMORY_WINE_UNIX_FUNCS, MEMORY_WINE_UNIX_WOW64_FUNCS};
    use crate::WinConfig;
    use exemu_core::{Perm, Reg};
    use exemu_memory::VirtualMemory;

    const SCRATCH: u64 = 0x2_0000;
    const GUEST_RSP: u64 = SCRATCH + 0x800;
    const HANDLE_OUT: u64 = SCRATCH + 0x100;
    const PARAMS: u64 = SCRATCH + 0x200;
    const CERT_BUF: u64 = SCRATCH + 0x300;
    const NEEDED: u64 = SCRATCH + 0x400;
    const IMAGE_BASE: u64 = 0x0000_0040_0216_0000;
    const E_LFANEW: u64 = 0x80;
    const PE32_PLUS_MAGIC: u16 = 0x20B;
    const OPTIONAL_HEADER: u64 = E_LFANEW + 24;
    const EXPORT_DIR_ENTRY: u64 = OPTIONAL_HEADER + 112;
    const EXPORT_DIR_RVA: u64 = 0x400;
    const EXPORT_NAME_RVA: u64 = 0x500;
    const POISON: u64 = 0xA5A5_A5A5_A5A5_A5A5;

    const CODE_PROCESS_ATTACH: u32 = 0;
    const CODE_PROCESS_DETACH: u32 = 1;
    const CODE_OPEN_CERT_STORE: u32 = 2;
    const CODE_IMPORT_STORE_KEY: u32 = 3;
    const CODE_IMPORT_STORE_CERT: u32 = 4;
    const CODE_CLOSE_CERT_STORE: u32 = 5;
    const CODE_ENUM_ROOT_CERTS: u32 = 6;

    fn map_crypt32_image(mem: &mut VirtualMemory) {
        mem.map_fixed(IMAGE_BASE, 0x1000, Perm::RW, "crypt32").unwrap();
        mem.write_u16(IMAGE_BASE, 0x5A4D).unwrap();
        mem.write_u32(IMAGE_BASE + 0x3C, E_LFANEW as u32).unwrap();
        mem.write_u32(IMAGE_BASE + E_LFANEW, 0x0000_4550).unwrap();
        mem.write_u16(IMAGE_BASE + OPTIONAL_HEADER, PE32_PLUS_MAGIC).unwrap();
        mem.write_u32(IMAGE_BASE + EXPORT_DIR_ENTRY, EXPORT_DIR_RVA as u32).unwrap();
        mem.write_u32(IMAGE_BASE + EXPORT_DIR_RVA + 12, EXPORT_NAME_RVA as u32).unwrap();
        mem.write(IMAGE_BASE + EXPORT_NAME_RVA, b"CRYPT32.dll\0").unwrap();
    }

    fn init_unix_call(os: &mut WinOs, mem: &mut VirtualMemory) -> (u32, u64) {
        mem.write_u64(HANDLE_OUT, POISON).unwrap();
        mem.write_u64(GUEST_RSP + 0x28, 8).unwrap();
        mem.write_u64(GUEST_RSP + 0x30, 0).unwrap();
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, u64::MAX);
        cpu.set_reg(Reg::Rdx, IMAGE_BASE);
        cpu.set_reg(Reg::R8, u64::from(MEMORY_WINE_UNIX_FUNCS));
        cpu.set_reg(Reg::R9, HANDLE_OUT);
        let status = os.nt_query_virtual_memory(&mut cpu, mem).unwrap();
        (status, mem.read_u64(HANDLE_OUT).unwrap())
    }

    fn booted() -> (WinOs, VirtualMemory, u64) {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(SCRATCH, 0x1000, Perm::RW, "scratch").unwrap();
        map_crypt32_image(&mut mem);
        let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });
        let (status, handle) = init_unix_call(&mut os, &mut mem);
        assert_eq!(
            status, STATUS_SUCCESS,
            "crypt32's DllMain returns FALSE when __wine_init_unix_call fails, and loader_init aborts the process"
        );
        assert_ne!(handle, POISON, "__wine_unixlib_handle is written to the caller's buffer");
        (os, mem, handle)
    }

    fn call(os: &mut WinOs, mem: &mut VirtualMemory, handle: u64, code: u32, args: u64) -> u32 {
        let mut cpu = CpuState::default();
        os.dispatch_unix_call(handle, code, args, &mut cpu, mem).unwrap()
    }

    #[test]
    fn crypt32_gets_its_unix_side_and_one_handle_per_module() {
        let (mut os, mut mem, handle) = booted();
        let (status, again) = init_unix_call(&mut os, &mut mem);
        assert_eq!((status, again), (STATUS_SUCCESS, handle));
    }

    #[test]
    fn dll_main_attach_and_detach_calls_answer_the_no_pkcs12_backend_state() {
        let (mut os, mut mem, handle) = booted();
        assert_eq!(
            call(&mut os, &mut mem, handle, CODE_PROCESS_ATTACH, 0),
            STATUS_DLL_NOT_FOUND,
            "Wine's unix process_attach answers STATUS_DLL_NOT_FOUND when it has no PKCS#12 library"
        );
        assert_eq!(call(&mut os, &mut mem, handle, CODE_PROCESS_DETACH, 0), STATUS_SUCCESS);
    }

    #[test]
    fn the_host_root_store_is_empty_and_the_buffer_is_untouched() {
        let (mut os, mut mem, handle) = booted();
        mem.write_u64(PARAMS, CERT_BUF).unwrap();
        mem.write_u32(PARAMS + 8, 2048).unwrap();
        mem.write_u64(PARAMS + 0x10, NEEDED).unwrap();
        mem.write_u64(CERT_BUF, POISON).unwrap();
        mem.write_u32(NEEDED, 0x5A5A_5A5A).unwrap();
        assert_eq!(
            call(&mut os, &mut mem, handle, CODE_ENUM_ROOT_CERTS, PARAMS),
            STATUS_NO_MORE_ENTRIES,
            "rootstore.c loops while enum_root_certs answers 0; an empty store is STATUS_NO_MORE_ENTRIES"
        );
        assert_eq!(mem.read_u64(CERT_BUF).unwrap(), POISON);
        assert_eq!(mem.read_u32(NEEDED).unwrap(), 0x5A5A_5A5A);
    }

    #[test]
    fn pfx_import_fails_the_way_wine_does_without_a_pkcs12_backend() {
        let (mut os, mut mem, handle) = booted();
        assert_eq!(call(&mut os, &mut mem, handle, CODE_OPEN_CERT_STORE, PARAMS), STATUS_DLL_NOT_FOUND);
        assert_eq!(call(&mut os, &mut mem, handle, CODE_IMPORT_STORE_KEY, PARAMS), STATUS_INVALID_PARAMETER);
        assert_eq!(call(&mut os, &mut mem, handle, CODE_IMPORT_STORE_CERT, PARAMS), STATUS_INVALID_PARAMETER);
        assert_eq!(call(&mut os, &mut mem, handle, CODE_CLOSE_CERT_STORE, PARAMS), STATUS_SUCCESS);
    }

    #[test]
    fn a_32bit_crypt32_gets_its_unix_side_through_the_wow64_funcs_class() {
        const PE32_MAGIC: u16 = 0x10B;
        const PE32_EXPORT_DIR_ENTRY: u64 = OPTIONAL_HEADER + 96;
        let mut mem = VirtualMemory::new();
        mem.map_fixed(SCRATCH, 0x1000, Perm::RW, "scratch").unwrap();
        map_crypt32_image(&mut mem);
        mem.write_u16(IMAGE_BASE + OPTIONAL_HEADER, PE32_MAGIC).unwrap();
        mem.write_u32(IMAGE_BASE + EXPORT_DIR_ENTRY, 0).unwrap();
        mem.write_u32(IMAGE_BASE + PE32_EXPORT_DIR_ENTRY, EXPORT_DIR_RVA as u32).unwrap();
        let mut os = WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() });

        mem.write_u64(HANDLE_OUT, POISON).unwrap();
        mem.write_u64(GUEST_RSP + 0x28, 8).unwrap();
        mem.write_u64(GUEST_RSP + 0x30, 0).unwrap();
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, u64::MAX);
        cpu.set_reg(Reg::Rdx, IMAGE_BASE);
        cpu.set_reg(Reg::R8, u64::from(MEMORY_WINE_UNIX_WOW64_FUNCS));
        cpu.set_reg(Reg::R9, HANDLE_OUT);
        assert_eq!(
            os.nt_query_virtual_memory(&mut cpu, &mut mem).unwrap(),
            STATUS_SUCCESS,
            "wow64.dll rewrites a 32-bit crypt32's MemoryWineUnixFuncs to the wow64 class; refusing it fails DllMain"
        );
        let handle = mem.read_u64(HANDLE_OUT).unwrap();
        assert_ne!(handle, POISON);
        assert_eq!(call(&mut os, &mut mem, handle, CODE_PROCESS_ATTACH, PARAMS), STATUS_DLL_NOT_FOUND);
        assert!(os.unix_call_wow64);
        assert_eq!(call(&mut os, &mut mem, handle, CODE_ENUM_ROOT_CERTS, PARAMS), STATUS_NO_MORE_ENTRIES);
    }

    #[test]
    fn a_code_past_unix_funcs_count_is_refused() {
        let (mut os, mut mem, handle) = booted();
        assert_eq!(
            call(&mut os, &mut mem, handle, UNIX_FUNCS_COUNT as u32, 0),
            STATUS_INVALID_PARAMETER
        );
    }
}
