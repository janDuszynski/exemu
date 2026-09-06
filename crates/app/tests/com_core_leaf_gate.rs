use std::collections::HashMap;
use std::path::Path;

use exemu_app::sample;
use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn load_dll(mem: &mut VirtualMemory, bytes: &[u8], base: u64) -> HashMap<String, u64> {
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
    exports
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
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap();
    mem
}

fn write_wstr(mem: &mut VirtualMemory, ptr: u64, s: &str) {
    let mut n = 0u64;
    for u in s.encode_utf16() {
        mem.write_u16(ptr + n * 2, u).unwrap();
        n += 1;
    }
    mem.write_u16(ptr + n * 2, 0).unwrap();
}

#[test]
fn combase_iid_from_string_parses_a_real_clsid_on_wine() {
    let combase = Path::new(WINE_DLLS).join("combase.dll");
    if !combase.exists() {
        eprintln!("SKIP: {} not present (Wine DLL set is git-ignored)", combase.display());
        return;
    }
    const BASE: u64 = 0x0000_0007_0000_0000;
    let bytes = std::fs::read(&combase).expect("read combase.dll");
    let mut mem = fresh_mem();
    let exports = load_dll(&mut mem, &bytes, BASE);

    let str_ptr = SCRATCH + 0x200;
    let iid_ptr = SCRATCH + 0x300;
    write_wstr(&mut mem, str_ptr, sample::COM_CLSID_STRING);
    mem.write(iid_ptr, &[0xAAu8; 16]).unwrap();

    let iid_from_string = *exports
        .get("IIDFromString")
        .expect("combase must export IIDFromString as local code");
    let hr = call_export(&mut mem, iid_from_string, &[str_ptr, iid_ptr]);
    assert_eq!(hr, 0, "IIDFromString(a well-formed CLSID string) should return S_OK");
    let mut parsed = [0u8; 16];
    mem.read(iid_ptr, &mut parsed).unwrap();
    assert_eq!(
        parsed, sample::COM_CLSID_BYTES,
        "IIDFromString should parse the formatted string into the exact CLSID bytes \
         the end-to-end COM gate hands CoCreateInstance"
    );
}

#[test]
fn oleaut32_variant_init_and_clear_round_trip_on_wine() {
    let oleaut32 = Path::new(WINE_DLLS).join("oleaut32.dll");
    if !oleaut32.exists() {
        eprintln!("SKIP: {} not present (Wine DLL set is git-ignored)", oleaut32.display());
        return;
    }
    const BASE: u64 = 0x0000_0009_0000_0000;
    let bytes = std::fs::read(&oleaut32).expect("read oleaut32.dll");
    let mut mem = fresh_mem();
    let exports = load_dll(&mut mem, &bytes, BASE);

    let variant_ptr = SCRATCH;
    mem.write(variant_ptr, &[0xAAu8; 24]).unwrap();

    let variant_init = *exports.get("VariantInit").expect("oleaut32 must export VariantInit");
    call_export(&mut mem, variant_init, &[variant_ptr]);
    let mut after_init = [0u8; 24];
    mem.read(variant_ptr, &mut after_init).unwrap();
    assert_eq!(after_init, [0u8; 24], "VariantInit should zero the whole VARIANT, not just vt");

    let variant_clear = *exports.get("VariantClear").expect("oleaut32 must export VariantClear");
    let hr = call_export(&mut mem, variant_clear, &[variant_ptr]);
    assert_eq!(hr, 0, "VariantClear(VT_EMPTY) should report S_OK");
    let mut after_clear = [0u8; 24];
    mem.read(variant_ptr, &mut after_clear).unwrap();
    assert_eq!(after_clear[0..2], [0, 0], "VariantClear should leave vt at VT_EMPTY");
}
