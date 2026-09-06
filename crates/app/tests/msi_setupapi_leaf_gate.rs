use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000;
const GS_BASE: u64 = 0x0000_7FFF_0000_0000;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

struct Dll {
    base: u64,
    exports: HashMap<String, u64>,
    imports: Vec<exemu_core::Import>,
}

impl Dll {
    fn export(&self, name: &str) -> u64 {
        *self
            .exports
            .get(name)
            .unwrap_or_else(|| panic!("{name} not exported as local (non-forwarder) code"))
    }

    fn iat_slot(&self, dll: &str, symbol: &str) -> u64 {
        self.imports
            .iter()
            .find(|i| {
                i.dll.eq_ignore_ascii_case(dll)
                    && matches!(&i.symbol, exemu_core::ImportSymbol::Named(n) if n == symbol)
            })
            .unwrap_or_else(|| panic!("no import of {dll}!{symbol} in this image"))
            .iat_rva as u64
            + self.base
    }
}

fn load_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> Dll {
    let mut image = exemu_loader::parse(bytes).expect("DLL should parse as PE32+");
    assert!(image.is_64bit, "an x86_64-windows DLL must be PE32+");
    assert!(!image.relocations.is_empty(), "a Wine PE DLL carries a .reloc table");

    exemu_loader::apply_relocations(&mut image.sections, &image.relocations, image.image_base, base)
        .expect("apply base relocations");

    let hdr_len = align_up(image.headers.len() as u64, 0x1000).max(0x1000);
    mem.map(Region::new("dll_headers", base, hdr_len, Perm::RWX)).unwrap();
    mem.write(base, &image.headers).unwrap();
    for s in &image.sections {
        let vsize = (s.virtual_size as u64).max(s.data.len() as u64);
        let map_len = align_up(vsize, 0x1000).max(0x1000);
        let addr = base + s.rva as u64;
        if mem.map(Region::new("dll_section", addr, map_len, Perm::RWX)).is_ok() && !s.data.is_empty() {
            mem.write(addr, &s.data).unwrap();
        } else if !s.data.is_empty() {
            mem.poke(addr, &s.data).unwrap();
        }
    }

    let mut exports = HashMap::new();
    for e in &image.exports {
        if e.forwarder.is_some() {
            continue;
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Dll { base, exports, imports: image.imports }
}

fn disable_debug_channel(mem: &mut VirtualMemory, entry: u64) {
    let mut window = [0u8; 32];
    if mem.read(entry, &mut window).is_err() {
        return;
    }
    for i in 0..window.len().saturating_sub(7) {
        if window[i] == 0xF6 && window[i + 1] == 0x05 {
            let disp = i32::from_le_bytes(window[i + 2..i + 6].try_into().unwrap()) as i64;
            let next_insn = entry + (i as u64) + 7;
            let flag_addr = (next_insn as i64 + disp) as u64;
            mem.poke(flag_addr, &[0u8]).expect("the flag byte lands inside the mapped image");
            return;
        }
    }
}

fn call_export(mem: &mut VirtualMemory, entry: u64, args: &[u64]) -> u64 {
    disable_debug_channel(mem, entry);
    let mut os = exemu_core::hooks::NoHooks;
    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = entry;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE;
        let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().take(4).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    mem.write_u64(rsp, SENTINEL).unwrap();
    let mut steps = 0u64;
    loop {
        match cpu.step(mem, &mut os).expect("the DLL's own bytes faulted") {
            Exit::Continue => steps += 1,
            Exit::Halted => break,
            other => panic!("unexpected exit driving the export: {other:?}"),
        }
        assert!(steps < 100_000, "leaf export ran away");
    }
    cpu.state().reg(Reg::Rax)
}

fn fresh_mem() -> VirtualMemory {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("stack", STACK_TOP - 0x4000, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x2000, Perm::RW)).unwrap();
    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    mem
}

#[test]
fn msi_close_handle_and_record_is_null_on_wine() {
    let msi = Path::new(WINE_DLLS).join("msi.dll");
    if !msi.exists() {
        eprintln!("SKIP: {} not present (Wine DLL set is git-ignored)", msi.display());
        return;
    }
    const BASE: u64 = 0x0000_0007_0000_0000;
    let bytes = std::fs::read(&msi).expect("read msi.dll");
    let mut mem = fresh_mem();
    let dll = load_dll(&mut mem, &bytes, BASE);

    let msi_close_handle = dll.export("MsiCloseHandle");
    let rc = call_export(&mut mem, msi_close_handle, &[0]);
    assert_eq!(rc, 0, "MsiCloseHandle(0) should report ERROR_SUCCESS");

    const RET_STUB: u64 = SCRATCH + 0x1000;
    mem.write(RET_STUB, &[0xC3]).unwrap();
    for sym in ["EnterCriticalSection", "LeaveCriticalSection"] {
        let slot = dll.iat_slot("kernel32.dll", sym);
        mem.write_u64(slot, RET_STUB).unwrap();
    }

    const BOGUS_HANDLE: u64 = 0xDEAD_BEEF;
    let msi_record_is_null = dll.export("MsiRecordIsNull");
    let is_null = call_export(&mut mem, msi_record_is_null, &[BOGUS_HANDLE, 0]);
    assert_eq!(
        is_null, 0,
        "MsiRecordIsNull on an unrecognized handle should report FALSE (Wine's real handle-table \
         lookup fails silently for a handle nothing allocated, rather than treating \"not found\" as \"null\")"
    );
}

#[test]
fn setup_close_file_queue_rejects_a_bad_signature_handle_on_wine() {
    const ERROR_INVALID_HANDLE: u64 = 6;

    let setupapi = Path::new(WINE_DLLS).join("setupapi.dll");
    if !setupapi.exists() {
        eprintln!("SKIP: {} not present (Wine DLL set is git-ignored)", setupapi.display());
        return;
    }
    const BASE: u64 = 0x0000_0008_0000_0000;
    let bytes = std::fs::read(&setupapi).expect("read setupapi.dll");
    let mut mem = fresh_mem();
    let dll = load_dll(&mut mem, &bytes, BASE);

    let bad_handle = SCRATCH + 0x100;
    mem.write_u32(bad_handle, 0).unwrap();

    let setup_close_file_queue = dll.export("SetupCloseFileQueue");
    let ok = call_export(&mut mem, setup_close_file_queue, &[bad_handle]);
    assert_eq!(ok, 0, "SetupCloseFileQueue on a bad-signature handle should return FALSE");

    let last_error = mem.read_u32(GS_BASE + 0x68).unwrap() as u64;
    assert_eq!(
        last_error, ERROR_INVALID_HANDLE,
        "SetupCloseFileQueue should set GetLastError() = ERROR_INVALID_HANDLE for a bad handle"
    );
}
