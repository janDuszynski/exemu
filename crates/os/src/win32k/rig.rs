use exemu_core::{CpuState, Memory, Perm, Reg};
use exemu_memory::VirtualMemory;

use super::{alloc_handle, Window};
use crate::syscall::SyscallHandler;
use crate::WinOs;

pub(super) const SCRATCH: u64 = 0x2_0000;
pub(super) const SCRATCH_SIZE: u64 = 0x4000;
const STACK: u64 = SCRATCH + 0x3000;
const REGISTER_ARGS: usize = 4;
const STACK_ARGS_OFFSET: u64 = 0x28;

pub(super) struct Rig {
    pub os: WinOs,
    pub mem: VirtualMemory,
}

impl Rig {
    pub(super) fn new() -> Rig {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(SCRATCH, SCRATCH_SIZE, Perm::RW, "scratch").unwrap();
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, ..Default::default() });
        os.set_syscall_guest_rsp_for_test(STACK);
        Rig { os, mem }
    }

    pub(super) fn call(&mut self, handler: SyscallHandler, args: &[u64]) -> u32 {
        let mut cpu = CpuState::default();
        cpu.set_rsp(STACK);
        let regs = [Reg::R10, Reg::Rdx, Reg::R8, Reg::R9];
        for (reg, value) in regs.iter().zip(args) {
            cpu.set_reg(*reg, *value);
        }
        for (i, value) in args.iter().enumerate().skip(REGISTER_ARGS) {
            let at = STACK + STACK_ARGS_OFFSET + (i - REGISTER_ARGS) as u64 * 8;
            self.mem.write_u64(at, *value).unwrap();
        }
        handler(&mut self.os, &mut cpu, &mut self.mem).unwrap()
    }

    pub(super) fn wide(&mut self, at: u64, text: &str) {
        let mut bytes = Vec::new();
        for u in text.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        self.mem.write(at, &bytes).unwrap();
    }

    pub(super) fn window(&mut self, style: u32) -> u32 {
        let hwnd = alloc_handle(&mut self.os);
        self.os.win32k_state.windows.push((
            hwnd,
            Window {
                class_atom: 0,
                class_name: "C".into(),
                title: String::new(),
                rect: [0, 0, 100, 100],
                style,
                ex_style: 0,
                parent: 0,
                shown: true,
                wndproc: 0,
                needs_paint: false,
                surface: None,
                extra: vec![0u8; 16],
                user_data: 0,
                id: 0,
                instance: 0,
                props: Vec::new(),
                dialog_info: 0,
                dialog_cancelled: false,
            },
        ));
        hwnd
    }
}
