use std::path::Path;

use exemu_core::hooks::NoHooks;
use exemu_core::{Cpu, EmuError, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const NTDLL: &str = "../../example_exe/wine-dlls/x86_64-windows/ntdll.dll";

#[test]
fn ntdll_text_decode_sweep_has_no_family_gap() {
    let path = Path::new(NTDLL);
    if !path.exists() {
        eprintln!("SKIP: {NTDLL} not present (Wine DLL set is git-ignored) — deferred to a host with the DLLs");
        return;
    }

    let bytes = std::fs::read(path).expect("read ntdll.dll");
    let image = exemu_loader::parse(&bytes).expect("ntdll.dll should parse as PE32+");
    assert!(image.is_64bit, "ntdll.dll (x86_64-windows) must be PE32+");

    let text = image
        .sections
        .iter()
        .find(|s| s.name == ".text" && s.executable)
        .expect("ntdll.dll must have an executable .text");

    const BASE: u64 = 0x0001_0000_0000;
    const DATA: u64 = 0x0002_0000_0000;
    let text_len = text.data.len();
    let map_len = (text_len as u64 + 0xFFF) & !0xFFF;
    let mut mem = VirtualMemory::new();
    mem.map(Region::new(".text", BASE, map_len, Perm::RWX)).unwrap();
    mem.map(Region::new("data", DATA, 0x1_0000, Perm::RW)).unwrap();
    mem.write(BASE, &text.data).unwrap();

    let mut decodable = 0usize;
    let mut decode_gaps = 0usize;
    let mut offsets = 0usize;
    let mut by_opcode: std::collections::BTreeMap<String, usize> = Default::default();
    let mut first_gap_rvas: Vec<u64> = Vec::new();

    let mut prev_sequential = false;
    let mut seq_gap_opcodes: std::collections::BTreeMap<String, usize> = Default::default();
    let mut off = 0usize;
    while off < text_len {
        offsets += 1;
        let addr = BASE + off as u64;
        let mut cpu = Interpreter::with_bits(Bits::B64);
        {
            let s = cpu.state_mut();
            s.rip = addr;
            for r in s.gpr.iter_mut() {
                *r = DATA + 0x800;
            }
            s.gpr[4] = DATA + 0x8000;
        }
        cpu.set_mxcsr(0x1F80);
        let mut hooks = NoHooks;

        let mut advance = 1usize;
        let mut this_sequential = false;
        match cpu.step(&mut mem, &mut hooks) {
            Err(e) => match e.cause() {
                EmuError::Decode { opcode, .. } => {
                    decode_gaps += 1;
                    *by_opcode.entry(opcode.clone()).or_default() += 1;
                    if prev_sequential {
                        *seq_gap_opcodes.entry(opcode.clone()).or_default() += 1;
                    }
                    if first_gap_rvas.len() < 20 {
                        first_gap_rvas.push(text.rva as u64 + off as u64);
                    }
                }
                _ => {
                    decodable += 1;
                    this_sequential = true;
                }
            },
            Ok(_) => {
                decodable += 1;
                let new_rip = cpu.state().rip;
                if new_rip > addr && new_rip - addr <= 15 {
                    advance = (new_rip - addr) as usize;
                    this_sequential = true;
                }
            }
        }
        prev_sequential = this_sequential;
        off += advance;
    }

    let coverage = decodable as f64 / offsets as f64;
    eprintln!(
        "ntdll .text sweep: {offsets} decoded instructions, {decodable} decodable, {decode_gaps} decode-gaps ({:.4}% coverage)",
        coverage * 100.0
    );
    let mut ranked: Vec<_> = by_opcode.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1));
    eprintln!("top decode-gap opcodes (byte after prefixes):");
    for (op, n) in ranked.iter().take(25) {
        eprintln!("  {op}: {n}");
    }
    eprintln!("first gap RVAs: {first_gap_rvas:02x?}");
    eprintln!("SEQUENTIALLY-REACHED gap opcodes (real instruction-stream gaps): {seq_gap_opcodes:?}");

    fn is_implemented_family(op: &str) -> bool {
        if let Some(hex) = op.strip_prefix("0f ").and_then(|s| s.strip_prefix("0x")) {
            if let Ok(op2) = u8::from_str_radix(hex, 16) {
                return exemu_cpu::is_sse_opcode(op2)
                    || exemu_cpu::is_mmx_opcode(op2)
                    || matches!(op2, 0xA2 | 0x38 | 0x3A);
            }
            return false;
        }
        let byte = op.strip_prefix("0x").and_then(|h| u8::from_str_radix(h, 16).ok());
        matches!(byte, Some(0xC4 | 0xC5) | Some(0xD8..=0xDF))
    }
    let family_gaps: Vec<_> = seq_gap_opcodes
        .keys()
        .filter(|op| is_implemented_family(op))
        .collect();
    assert!(
        family_gaps.is_empty(),
        "ntdll .text has SEQUENTIAL decode gaps in IMPLEMENTED families (x87/VEX/SSE/MMX): {family_gaps:?} — a real W1 regression"
    );

    assert!(
        coverage > 0.95,
        "ntdll .text decode coverage {:.4}% below floor — a whole instruction family may be unimplemented",
        coverage * 100.0
    );
}
