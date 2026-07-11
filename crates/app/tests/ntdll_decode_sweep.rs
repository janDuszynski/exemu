//! W1 gate check (c): a decode sweep over Wine's PE `ntdll.dll` `.text`.
//!
//! The W1 gate asserts the interpreter can *decode* the ISA Wine's own builtin
//! ntdll is compiled with — x87, SSE/SSE4, VEX/AVX, BMI — with no fatal
//! decode-errors on the code it actually executes. A full "from
//! `LdrInitializeThunk`" trace needs the W2 PE/Unix boundary (not built yet),
//! so this is the *static* half: a linear recovering disassembly of the whole
//! `.text` section that classifies every byte offset as either
//!
//!   * decodable (the interpreter's decoder consumed a valid instruction, or
//!     rejected it only because the *operand* faulted — a semantic, not a
//!     decode, failure), or
//!   * a **decode gap** (`EmuError::Decode` — the decoder does not recognise the
//!     opcode).
//!
//! Linear disassembly over a whole section necessarily walks into jump tables,
//! literal pools, alignment padding and mid-instruction bytes, so isolated
//! decode gaps at data offsets are expected noise. The signal the gate cares
//! about is whether any gap is a *real, implemented* instruction family the
//! decoder wrongly rejects. This test fails only if the coverage of decodable
//! offsets falls below a high threshold, and it prints the ranked distinct
//! failing opcodes so a regression in a whole family (e.g. all VEX, all x87)
//! is impossible to miss.
//!
//! The test skips cleanly when the (git-ignored) Wine DLL set is absent, so it
//! never breaks a checkout that lacks `example_exe/wine-dlls/`.

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

    // Map the section's raw bytes at a fixed base as RWX so the decoder can
    // fetch instruction bytes; give it a scratch data page for operands.
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

    // Instruction-boundary-following linear disassembly. Decode at `off`; on a
    // clean decode advance by the number of bytes the decoder *consumed* (so the
    // walk stays on real instruction boundaries and does not re-decode
    // mid-instruction bytes or immediates as bogus opcodes). The consumed length
    // is the forward rip delta for a straight-line instruction; a branch/call
    // moves rip elsewhere, so we fall back to a conservative 1-byte resync (and
    // likewise on any fault or decode gap). This is the honest metric: coverage
    // of the actual decoded instruction stream, not of every byte offset.
    // Distinguish a gap reached *sequentially* (the previous instruction
    // decoded cleanly and advanced by its length straight into this offset — a
    // strong signal of a genuine instruction) from one only reached during a
    // 1-byte resync (which walks through data and synthesises plausible opcodes).
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
            // Point every GPR that a memory operand might use at the scratch
            // data page so an operand access does not itself fault the probe.
            for r in s.gpr.iter_mut() {
                *r = DATA + 0x800;
            }
            s.gpr[4] = DATA + 0x8000; // RSP: a valid stack slot for push/call probes
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
                // Any non-decode error (unmapped/permission operand fault,
                // unsupported semantics, etc.) means the bytes *decoded* fine —
                // the failure is downstream of the decoder. Count as decodable.
                _ => {
                    decodable += 1;
                    this_sequential = true; // decoded (semantic fault only)
                }
            },
            Ok(_) => {
                decodable += 1;
                let new_rip = cpu.state().rip;
                // Straight-line instruction: rip advanced 1..=15 bytes. Use that
                // as the consumed length so we land on the next instruction.
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
    // Rank the distinct failing opcodes so a family regression is obvious.
    let mut ranked: Vec<_> = by_opcode.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1));
    eprintln!("top decode-gap opcodes (byte after prefixes):");
    for (op, n) in ranked.iter().take(25) {
        eprintln!("  {op}: {n}");
    }
    eprintln!("first gap RVAs: {first_gap_rvas:02x?}");
    eprintln!("SEQUENTIALLY-REACHED gap opcodes (real instruction-stream gaps): {seq_gap_opcodes:?}");

    // Hard family-coverage assertion. A gap counts as a real instruction-stream
    // gap only when it is reached *sequentially* — the previous instruction
    // decoded cleanly and advanced by its own length straight into this offset.
    // Gaps reached only during a 1-byte resync walk through data (jump tables,
    // literals, relocations) are noise. Among the sequentially-reached gaps,
    // none may belong to an *implemented user-mode family*:
    //   * x87 (single-byte 0xD8..0xDF),
    //   * VEX/AVX (single-byte 0xC4/0xC5),
    //   * the two-byte 0x0F SSE/SSE2/SSSE3/SSE4/MMX opcodes exemu routes to its
    //     vector units (the `is_sse`/`is_mmx` opcode ranges), plus the specific
    //     scalar 0F ops the roadmap claims (CPUID 0F A2, the 0F 38/3A escapes).
    // Two-byte opcodes that are privileged/system or architecturally undefined —
    // 0F 00 (SLDT/LLDT/LTR group 6), 0F 01 (group 7), 0F 02/03 (LAR/LSL), 0F 04
    // (invalid), 0F 0F (obsolete 3DNow) — are NOT families a user-mode ntdll
    // emits; their appearance is data noise (the definitively-invalid 0F 04 in
    // this set is the proof that the sequential heuristic still admits data).
    fn is_implemented_family(op: &str) -> bool {
        if let Some(hex) = op.strip_prefix("0f ").and_then(|s| s.strip_prefix("0x")) {
            if let Ok(op2) = u8::from_str_radix(hex, 16) {
                // The 0F opcodes exemu's vector units + scalar handlers own.
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

    // And the aggregate coverage of the decoded instruction stream must stay
    // high; a whole unimplemented common family would crater it far below this.
    assert!(
        coverage > 0.95,
        "ntdll .text decode coverage {:.4}% below floor — a whole instruction family may be unimplemented",
        coverage * 100.0
    );
}
