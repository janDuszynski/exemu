use exemu_core::{EmuError, Memory, Result};

pub const TEB_CPU_AREA_PTR_OFF: u64 = 0x1488;

pub const CPU_AREA_HEADER_LEN: u64 = 4;

pub const CPU_AREA_RELOAD_BIT: u32 = 1;

pub const CTX_EDI: u64 = 0x9c;
pub const CTX_ESI: u64 = 0xa0;
pub const CTX_EBX: u64 = 0xa4;
pub const CTX_EDX: u64 = 0xa8;
pub const CTX_ECX: u64 = 0xac;
pub const CTX_EAX: u64 = 0xb0;
pub const CTX_EBP: u64 = 0xb4;
pub const CTX_EIP: u64 = 0xb8;
pub const CTX_SEGCS: u64 = 0xbc;
pub const CTX_EFLAGS: u64 = 0xc0;
pub const CTX_ESP: u64 = 0xc4;
pub const CTX_SEGSS: u64 = 0xc8;

pub const SEL_CS32: u32 = exemu_core::cpu::SEL_CS32 as u32;
pub const SEL_SS32: u32 = exemu_core::cpu::SEL_DATA as u32;
pub const SEL_CS64: u32 = exemu_core::cpu::SEL_CS64 as u32;

pub const TEB64_WOW_TEB_OFFSET: u64 = 0x180c;

pub const TEB32_WOW32_RESERVED: u64 = 0xc0;

pub const THREAD_WOW64_CONTEXT: u32 = 0x1d;
pub const WOW64_CONTEXT_SIZE: u64 = 0x2cc;

pub const SYSDLL_LDR_INITIALIZE_THUNK: u64 = 0x18;
pub const SYSDLL_KI_USER_EXCEPTION_DISPATCHER: u64 = 0x20;
pub const SYSDLL_KI_USER_APC_DISPATCHER: u64 = 0x28;
pub const SYSDLL_KI_USER_CALLBACK_DISPATCHER: u64 = 0x30;
pub const SYSDLL_NTDLL32_BASE: u64 = 0x48;
pub const SYSDLL_BLOCK_SIZE: u64 = 0x50;

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDllInitBlock {
    pub ntdll32_base: u64,
    pub ldr_initialize_thunk: u64,
    pub exception_dispatcher: u64,
    pub apc_dispatcher: u64,
    pub callback_dispatcher: u64,
}

pub fn publish_system_dll_init_block(mem: &mut dyn Memory, block: u64, v: &SystemDllInitBlock) -> Result<()> {
    for (name, addr) in [
        ("ntdll32 base", v.ntdll32_base),
        ("LdrInitializeThunk", v.ldr_initialize_thunk),
        ("KiUserExceptionDispatcher", v.exception_dispatcher),
        ("KiUserApcDispatcher", v.apc_dispatcher),
        ("KiUserCallbackDispatcher", v.callback_dispatcher),
    ] {
        if addr > u32::MAX as u64 {
            return Err(EmuError::Os(format!(
                "LdrSystemDllInitBlock: 32-bit ntdll {name} at {addr:#x} is above 4 GiB — \
                 wow64.dll narrows it into a 32-bit CONTEXT"
            )));
        }
    }
    mem.write_u32(block, SYSDLL_BLOCK_SIZE as u32)?;
    mem.write_u64_at(block, SYSDLL_LDR_INITIALIZE_THUNK, v.ldr_initialize_thunk)?;
    mem.write_u64_at(block, SYSDLL_KI_USER_EXCEPTION_DISPATCHER, v.exception_dispatcher)?;
    mem.write_u64_at(block, SYSDLL_KI_USER_APC_DISPATCHER, v.apc_dispatcher)?;
    mem.write_u64_at(block, SYSDLL_KI_USER_CALLBACK_DISPATCHER, v.callback_dispatcher)?;
    mem.write_u64_at(block, SYSDLL_NTDLL32_BASE, v.ntdll32_base)?;
    Ok(())
}

pub fn publish_wow64_exception_hook(mem: &mut dyn Memory, ntdll64_base: u64, prepare: u64) -> Result<u64> {
    let entry = ntdll64_base + crate::RVA_KI_USER_EXCEPTION_DISPATCHER;
    let mut b = [0u8; 8];
    mem.read(entry, &mut b)?;
    if b[0] != 0xFC || b[1..4] != [0x48, 0x8B, 0x05] {
        return Err(EmuError::Os(format!(
            "WoW64 boot: the 64-bit KiUserExceptionDispatcher at {entry:#x} does not open with \
             `cld; mov rax,[rip+disp32]` (saw {b:02x?}) — its WoW64 hook cell cannot be located"
        )));
    }
    let disp = i32::from_le_bytes(b[4..8].try_into().unwrap());
    let slot = (entry + 8).wrapping_add(disp as i64 as u64);
    mem.write_u64(slot, prepare)?;
    Ok(slot)
}

pub const PROCESS_WOW64_INFORMATION: u32 = 0x1a;

pub const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES: u32 = 0xb5;

pub mod arch_entry {
    pub const KERNEL_MODE: u32 = 1 << 16;
    pub const USER_MODE: u32 = 1 << 17;
    pub const NATIVE: u32 = 1 << 18;
    pub const PROCESS: u32 = 1 << 19;

    pub const fn entry(machine: u16, flags: u32) -> u32 {
        machine as u32 | flags
    }
}

pub const MACHINE_I386: u16 = 0x014c;
pub const MACHINE_AMD64: u16 = 0x8664;

pub const TEB32_SELF: u64 = 0x18;
pub const TEB32_PEB: u64 = 0x30;
pub const TEB32_STACK_BASE: u64 = 0x04;
pub const TEB32_STACK_LIMIT: u64 = 0x08;
pub const TEB32_EXCEPTION_LIST: u64 = 0x00;
pub const TEB32_CLIENT_ID: u64 = 0x20;
pub const TEB32_ACTIVATION_CONTEXT_STACK_POINTER: u64 = 0x1a8;
pub const TEB32_ACTIVATION_CONTEXT_STACK: u64 = 0x1800;

pub fn seed_teb32(mem: &mut dyn Memory, teb32: u64, peb32: u64, stack_base: u64, stack_top: u64) -> Result<()> {
    mem.write_u32_at(teb32, TEB32_EXCEPTION_LIST, u32::MAX)?;
    mem.write_u32_at(teb32, TEB32_STACK_BASE, stack_top as u32)?;
    mem.write_u32_at(teb32, TEB32_STACK_LIMIT, stack_base as u32)?;
    mem.write_u32_at(teb32, TEB32_SELF, teb32 as u32)?;
    mem.write_u32_at(teb32, TEB32_PEB, peb32 as u32)?;
    let actx = teb32 + TEB32_ACTIVATION_CONTEXT_STACK;
    mem.write_u32_at(teb32, TEB32_ACTIVATION_CONTEXT_STACK_POINTER, actx as u32)?;
    mem.write_u32_at(actx, 0x04, actx as u32 + 0x04)?;
    mem.write_u32_at(actx, 0x08, actx as u32 + 0x04)?;
    Ok(())
}

pub mod peb32 {
    pub const BEING_DEBUGGED: u64 = 0x02;
    pub const IMAGE_BASE: u64 = 0x08;
    pub const LDR: u64 = 0x0c;
    pub const PROCESS_PARAMETERS: u64 = 0x10;
    pub const NT_GLOBAL_FLAG: u64 = 0x68;
    pub const OS_MAJOR_VERSION: u64 = 0xa4;
    pub const OS_MINOR_VERSION: u64 = 0xa8;
    pub const OS_BUILD_NUMBER: u64 = 0xac;
    pub const OS_PLATFORM_ID: u64 = 0xb0;
    pub const SESSION_ID: u64 = 0x1d4;
}

const EFLAGS_INIT: u32 = 0x0000_0202;

#[derive(Debug, Clone, Copy, Default)]
pub struct Start32 {
    pub eip: u32,
    pub esp: u32,
    pub eax: u32,
    pub ebx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Wow64Threading {
    pub ldrp_initialize: u64,
    pub rtl_user_thread_start32: u64,
}

pub fn init_cpu_area(mem: &mut dyn Memory, teb_base: u64, area: u64, start: Start32) -> Result<()> {
    mem.write_u64_at(teb_base, TEB_CPU_AREA_PTR_OFF, area)?;
    mem.write_u32(area, 0)?;
    let ctx = area + CPU_AREA_HEADER_LEN;
    mem.write_u32_at(ctx, CTX_EIP, start.eip)?;
    mem.write_u32_at(ctx, CTX_ESP, start.esp)?;
    mem.write_u32_at(ctx, CTX_EAX, start.eax)?;
    mem.write_u32_at(ctx, CTX_EBX, start.ebx)?;
    mem.write_u32_at(ctx, CTX_EFLAGS, EFLAGS_INIT)?;
    mem.write_u32_at(ctx, CTX_SEGCS, SEL_CS32)?;
    mem.write_u32_at(ctx, CTX_SEGSS, SEL_SS32)?;
    Ok(())
}

pub fn publish_wow64_transition(mem: &mut dyn Memory, transition_slot: u64, bop: u64) -> Result<()> {
    if bop > u32::MAX as u64 {
        return Err(EmuError::Os(format!(
            "WoW64 BOP at {bop:#x} is above 4 GiB — a 32-bit `jmp dword ptr [Wow64Transition]` cannot reach it"
        )));
    }
    mem.write_u32(transition_slot, bop as u32)
}

pub fn link_teb32(mem: &mut dyn Memory, teb64: u64, teb32: u64) -> Result<()> {
    if teb32 > u32::MAX as u64 {
        return Err(EmuError::Os(format!(
            "WoW64 TEB32 at {teb32:#x} is above 4 GiB — 32-bit guest code could not address it"
        )));
    }
    let delta = teb32 as i64 - teb64 as i64;
    let delta = i32::try_from(delta).map_err(|_| {
        EmuError::Os(format!(
            "WoW64 TEB32 {teb32:#x} is more than 2 GiB from TEB64 {teb64:#x} — \
             TEB64.WowTebOffset is a signed 32-bit field"
        ))
    })?;
    mem.write_u32_at(teb64, TEB64_WOW_TEB_OFFSET, delta as u32)?;
    mem.write_u32_at(teb32, TEB32_SELF, teb32 as u32)?;
    Ok(())
}

pub fn teb32_of(mem: &dyn Memory, teb64: u64) -> Result<Option<u64>> {
    let off = mem.read_u32_at(teb64, TEB64_WOW_TEB_OFFSET)? as i32;
    if off == 0 {
        return Ok(None);
    }
    Ok(Some(teb64.wrapping_add(off as i64 as u64)))
}

#[derive(Debug, Clone, Copy)]
pub struct BopSlots {
    pub transition: u64,
    pub syscall_dispatcher: u64,
    pub wow32_reserved: u64,
}

pub fn publish_bop(mem: &mut dyn Memory, slots: BopSlots, bop: u64) -> Result<()> {
    for slot in [slots.transition, slots.syscall_dispatcher, slots.wow32_reserved] {
        if slot != 0 {
            publish_wow64_transition(mem, slot, bop)?;
        }
    }
    Ok(())
}

pub const PEB64_KERNEL_CALLBACK_TABLE: u64 = 0x58;

pub mod cb_frame {
    pub const ARGS: u64 = 0x20;
    pub const LEN: u64 = 0x28;
    pub const ID: u64 = 0x2c;
    pub const SIZE: u64 = 0x30;
}

pub const SSDT_NT_CALLBACK_RETURN: u32 = 5;

pub const NT_USER_CALL_WIN_PROC: u32 = 4;

pub const NTUSER_DPI_UNAWARE: u32 = 0x6010;

pub mod win_proc_params {
    pub const FUNC: u64 = 0x00;
    pub const HWND: u64 = 0x08;
    pub const MSG: u64 = 0x10;
    pub const WPARAM: u64 = 0x18;
    pub const LPARAM: u64 = 0x20;
    pub const SIZE: u64 = 0x28;
    pub const ANSI: u64 = 0x2c;
    pub const MAPPING: u64 = 0x30;
    pub const DPI_CONTEXT: u64 = 0x34;
    pub const PROC_A: u64 = 0x38;
    pub const PROC_W: u64 = 0x40;
    pub const RESULT: u64 = 0x48;
    pub const SIZE_OF: u64 = 0x50;
    pub const CALL_LEN: u32 = 0x48;
}

pub fn publish_kernel_callback_table(mem: &mut dyn Memory, wow64win_base: u64, entry: u64, peb64: u64) -> Result<u64> {
    const TAIL: [u8; 17] = [
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x40, 0x60,
        0x48, 0x89, 0x50, 0x58,
    ];
    let mut head = [0u8; 5];
    mem.read(entry, &mut head)?;
    let body = if head[0] == 0xE9 {
        let rel = i32::from_le_bytes(head[1..5].try_into().unwrap());
        (entry + 5).wrapping_add(rel as i64 as u64)
    } else {
        entry
    };
    let mut win = vec![0u8; 0x100];
    mem.read(body, &mut win)?;
    for i in 0..win.len() - (7 + TAIL.len()) {
        if win[i] != 0x48 || win[i + 1] != 0x8D || win[i + 2] != 0x15 {
            continue;
        }
        if win[i + 7..i + 7 + TAIL.len()] != TAIL {
            continue;
        }
        let disp = i32::from_le_bytes(win[i + 3..i + 7].try_into().unwrap());
        let table = (body + i as u64 + 7).wrapping_add(disp as i64 as u64);
        if table < wow64win_base {
            break;
        }
        mem.write_u64_at(peb64, PEB64_KERNEL_CALLBACK_TABLE, table)?;
        return Ok(table);
    }
    Err(EmuError::Os(format!(
        "WoW64 boot: wow64win.dll's DllMain at {body:#x} does not publish PEB.KernelCallbackTable in \
         the recovered shape (lea rdx,[rip+d32]; mov rax,gs:[0x30]; mov rax,[rax+0x60]; mov [rax+0x58],rdx) \
         — the user-callback table cannot be located"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{Perm, Region};
    use exemu_memory::VirtualMemory;

    #[test]
    fn init_cpu_area_lays_out_the_wow64_context() {
        let mut mem = VirtualMemory::new();
        let teb = 0x1_0000u64;
        let area = 0x2_0000u64;
        mem.map(Region::new("teb", teb, 0x2000, Perm::RW)).unwrap();
        mem.map(Region::new("cpu", area, 0x1000, Perm::RW)).unwrap();

        init_cpu_area(
            &mut mem,
            teb,
            area,
            Start32 { eip: 0x0040_1234, esp: 0x0041_0000, eax: 0x0040_5678, ebx: 0 },
        )
        .unwrap();

        assert_eq!(mem.read_u64_at(teb, TEB_CPU_AREA_PTR_OFF).unwrap(), area, "area ptr at TEB+0x1488");
        assert_eq!(mem.read_u32(area).unwrap(), 0, "header cleared → forward path");
        let ctx = area + CPU_AREA_HEADER_LEN;
        assert_eq!(mem.read_u32_at(ctx, CTX_EIP).unwrap(), 0x0040_1234, "Eip");
        assert_eq!(mem.read_u32_at(ctx, CTX_ESP).unwrap(), 0x0041_0000, "Esp");
        assert_eq!(mem.read_u32_at(ctx, CTX_EAX).unwrap(), 0x0040_5678, "Eax = the thread entry point");
        assert_eq!(mem.read_u32_at(ctx, CTX_SEGCS).unwrap(), SEL_CS32, "SegCs = 0x23");
        assert_eq!(mem.read_u32_at(ctx, CTX_SEGSS).unwrap(), SEL_SS32, "SegSs = 0x2b");
        assert_eq!(mem.read_u32_at(ctx, CTX_EFLAGS).unwrap(), EFLAGS_INIT, "EFlags");
        assert_eq!(CTX_SEGCS - CTX_EIP, 4, "SegCs directly follows Eip");
    }

    #[test]
    fn publish_wow64_transition_writes_a_32bit_bop_pointer() {
        let mut mem = VirtualMemory::new();
        let slot = 0x50_0000u64;
        mem.map(Region::new("ntdll32", slot, 0x1000, Perm::RW)).unwrap();

        publish_wow64_transition(&mut mem, slot, 0x6A40_7000).unwrap();
        assert_eq!(mem.read_u32(slot).unwrap(), 0x6A40_7000, "BOP VA published as a 32-bit cell");
        assert_eq!(mem.read_u32_at(slot, 4).unwrap(), 0, "only the 32-bit slot is written");

        let err = publish_wow64_transition(&mut mem, slot, 0x1_0000_7000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "a BOP above 4 GiB is rejected, not truncated: {err}");
        assert_eq!(mem.read_u32(slot).unwrap(), 0x6A40_7000, "the rejected publish left the slot intact");
    }

    #[test]
    fn teb32_link_round_trips_through_the_signed_wow_teb_offset() {
        let mut mem = VirtualMemory::new();
        let teb64 = 0x7F00_0000u64;
        let teb32 = teb64 + 0x8000;
        mem.map(Region::new("tebs", teb64, 0x1_0000, Perm::RW)).unwrap();

        assert_eq!(teb32_of(&mem, teb64).unwrap(), None, "a zero field means: not a WoW64 thread");
        link_teb32(&mut mem, teb64, teb32).unwrap();
        assert_eq!(teb32_of(&mem, teb64).unwrap(), Some(teb32), "TEB64 + (i32)WowTebOffset = TEB32");
        assert_eq!(mem.read_u32_at(teb32, TEB32_SELF).unwrap() as u64, teb32, "TEB32.NtTib.Self");

        let below = teb64 - 0x8000;
        mem.map(Region::new("below", below, 0x1000, Perm::RW)).unwrap();
        link_teb32(&mut mem, teb64, below).unwrap();
        assert_eq!(mem.read_u32_at(teb64, TEB64_WOW_TEB_OFFSET).unwrap() as i32, -0x8000);
        assert_eq!(teb32_of(&mem, teb64).unwrap(), Some(below), "a negative WowTebOffset resolves too");

        let err = link_teb32(&mut mem, teb64, 0x1_0000_0000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "TEB32 above 4 GiB is refused: {err}");
        let err = link_teb32(&mut mem, 0x10_0000_0000, 0x1000).unwrap_err();
        assert!(matches!(err, EmuError::Os(_)), "a >2 GiB TEB64→TEB32 distance is refused: {err}");
    }

    #[test]
    fn publish_bop_fills_all_three_cells() {
        let mut mem = VirtualMemory::new();
        let page = 0x50_0000u64;
        mem.map(Region::new("cells", page, 0x1000, Perm::RW)).unwrap();
        let slots = BopSlots {
            transition: page,
            syscall_dispatcher: page + 0x10,
            wow32_reserved: page + 0x20,
        };
        publish_bop(&mut mem, slots, 0x6A40_7000).unwrap();
        for (name, at) in [
            ("Wow64Transition", slots.transition),
            ("__wine_syscall_dispatcher", slots.syscall_dispatcher),
            ("TEB32.WOW32Reserved", slots.wow32_reserved),
        ] {
            assert_eq!(mem.read_u32(at).unwrap(), 0x6A40_7000, "{name} holds the BOP");
        }
        publish_bop(&mut mem, BopSlots { transition: 0, ..slots }, 0x6A40_8000).unwrap();
        assert_eq!(mem.read_u32(slots.syscall_dispatcher).unwrap(), 0x6A40_8000);
    }
}
