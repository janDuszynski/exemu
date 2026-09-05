//! W6.7 — **growing the W6.3/W6.4 (ole32/oleaut32/combase) DLL-smoke case.**
//!
//! `com_gate.rs` already proves the headline W6.3/W6.4 claim end to end
//! (`CoCreateInstance` resolves a CLSID through exemu's registry and hands back
//! a live vtable) and drives one oleaut32 leaf (`SysStringLen`) directly. This
//! file adds two more leaves, each picked (from the pinned binaries'
//! disassembly, no Wine source read) because its *business logic* touches no
//! import at all:
//!
//! * [`combase_iid_from_string_parses_a_real_clsid_on_wine`] — combase's real
//!   `IIDFromString` parses the exact CLSID string
//!   [`exemu_app::sample::COM_CLSID_STRING`] the end-to-end COM gate already
//!   resolves through the registry, reproducing
//!   [`exemu_app::sample::COM_CLSID_BYTES`] exactly — a different piece of
//!   combase (its GUID *parser*) than the vtable-call path exercises.
//! * [`oleaut32_variant_init_and_clear_round_trip_on_wine`] — oleaut32's real
//!   `VariantInit`/`VariantClear` zero a `VARIANT` and report `S_OK` clearing
//!   it, proving Wine's own VARIANT-lifecycle code runs (distinct from the
//!   existing `SysStringLen` BSTR-only leaf).
//!
//! **A real trap found along the way, worth recording.** Every Wine PE
//! builtin opens hot functions with `test byte ptr [rip+d], N; jne <slow>` —
//! the compiled form of a `TRACE()`/`WARN()` guard reading that source file's
//! debug-channel flags. The instinctive assumption is "channels are off by
//! default, so the *fast* path is the one that runs" — **that assumption is
//! false on these binaries.** Reading the raw byte at oleaut32's own channel
//! flag (rva `0x5b6a0`, `VariantInit`'s guard target) out of the file shows
//! `0xff`, not `0` — Wine's debug channels start **lazily uninitialized**
//! (the sentinel is all-ones, resolved to real bits only on first use by
//! machinery this isolated harness doesn't run), so *any* bit test against
//! them reads as "on" and every one of these functions actually takes the
//! **logging** branch, which calls into further Wine machinery
//! (`vsnwprintf`-class formatting) this isolated, import-free harness cannot
//! service. The fix used here is the same kind of deliberate flag-poke
//! `dll_smoke.rs` already does to `KUSER_SHARED_DATA`'s `SystemCall` byte to
//! pick a code path: [`disable_debug_channel`] finds that function's own
//! `F6 05 <disp32> <imm8>` guard in its first bytes and pokes the byte it
//! tests to `0`, purely to skip Wine's *logging side effect* — it changes no
//! business logic, since the channel flag controls only whether a trace line
//! would be printed. `StringFromGUID2` was tried first and dropped: even past
//! its own channel guard, its *formatting* path itself calls
//! `ucrtbase!__stdio_common_vswprintf` — a real external dependency, not a
//! logging side effect — so it is not a self-contained case and is not landed
//! here.
//!
//! Both surviving cases are driven the same way as `com_gate.rs`'s
//! `SysStringLen` case: the DLL is mapped and relocated **alone** (no other
//! module, no imports bound), and the export runs through the real CPU from
//! its own relocated bytes with a `hlt` sentinel as the return address. Any
//! path that actually needs an import still faults here, exactly as intended.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::HashMap;
use std::path::Path;

use exemu_app::sample;
use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000; // one page whose first byte is `hlt`

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// Parse, relocate to `base` and map `bytes` into `mem`, returning the resolved
/// (non-forwarder) export map. Mirrors `com_gate.rs`'s `map_dll`.
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
            continue; // a re-export string, not a callable stub
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    exports
}

/// Find the first `test byte ptr [rip+disp32], imm8` (`F6 05 <disp32> <imm8>`)
/// in `entry`'s opening bytes — the compiled shape of a Wine `TRACE()`/`WARN()`
/// debug-channel guard — and poke the byte it tests to `0`, forcing that
/// function's *own* logging check to read "channel off". This changes no
/// business logic: the flag controls only whether Wine would print a trace
/// line, never what the function computes. A no-op when the pattern is absent.
fn disable_debug_channel(mem: &mut VirtualMemory, entry: u64) {
    let mut window = [0u8; 32];
    if mem.read(entry, &mut window).is_err() {
        return;
    }
    // `F6 05 <disp32> <imm8>` — opcode + ModRM + 4-byte displacement + 1-byte
    // immediate is always 7 bytes for this form (mod=00, rm=101 is RIP-relative
    // in 64-bit mode, and this addressing mode always carries a full disp32,
    // never a shorter encoding), so the next instruction — the RIP the
    // displacement is relative to — always starts 7 bytes past the opcode.
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

/// Drive a call to `entry` on the real interpreter with Win64 args in
/// RCX/RDX/R8/R9, a `hlt` sentinel as the return address, and return RAX. Any
/// unimplemented path (an unbound import, for instance) surfaces as a fault
/// that fails the test — that is the point: these exports were picked to need
/// none once their own debug-channel guard is neutralised.
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
    mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt
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

// ==========================================================================
// combase: IIDFromString.
// ==========================================================================

/// **New combase capability, distinct from the vtable-call path
/// `com_gate.rs` already proves.**
///
/// `IIDFromString` parses the exact CLSID string the end-to-end COM gate
/// resolves through the registry ([`sample::COM_CLSID_STRING`]) straight back
/// into 16 bytes, and must reproduce [`sample::COM_CLSID_BYTES`] exactly — so
/// a drift in either constant fails both tests. This exercises Wine's real
/// GUID-string *parser*, a different piece of combase than the vtable call.
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
    mem.write(iid_ptr, &[0xAAu8; 16]).unwrap(); // poison the out-param

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

// ==========================================================================
// oleaut32: VariantInit / VariantClear.
// ==========================================================================

/// **New oleaut32 capability, distinct from the existing `SysStringLen` leaf.**
///
/// `VariantInit` zeroes a full 24-byte `VARIANT` (confirmed from the
/// disassembly: `mov qword [rbx+0x10],0` then `movups xmmword [rbx],xmm0`
/// covers bytes 0..24 — `vt`, the reserved words and the 16-byte value union
/// all land at zero, i.e. `VT_EMPTY`). `VariantClear` on that same `VT_EMPTY`
/// variant takes the real leaf path (`vt & 0xFFF <= 0x17` classifies it as a
/// "nothing to free" type) and returns `S_OK` — proving Wine's real
/// variant-lifecycle code runs, not just its string helpers.
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
    // Poison the 24-byte VARIANT so a real zeroing is the only way to pass.
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
