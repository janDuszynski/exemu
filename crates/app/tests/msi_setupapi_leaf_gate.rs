//! W6.7 — **growing the W6.5 (cabinet/msi/setupapi) DLL-smoke case.**
//!
//! `cab_gate.rs` already proves cabinet.dll end to end (a real CAB extracts to
//! the expected bytes) and `breadth_gate.rs` proves msi.dll/setupapi.dll map,
//! relocate and satisfy their whole import closure from the pinned prefix —
//! but neither DLL had a single byte of its own code actually **executed**
//! before this file. Both new cases below run real msi.dll/setupapi.dll code
//! through the CPU, following the same "map the DLL alone, drive one export
//! through the interpreter" style as `com_gate.rs`/`com_core_leaf_gate.rs`,
//! reusing the debug-channel-guard poke documented there (`disable_debug_channel`).
//!
//! * [`msi_close_handle_and_record_is_null_on_wine`] — `MsiCloseHandle(0)`
//!   reports `ERROR_SUCCESS`, and — after binding msi's own two
//!   `EnterCriticalSection`/`LeaveCriticalSection` imports to no-op stubs, the
//!   only imports its handle table needs — `MsiRecordIsNull` on a handle that
//!   was never allocated runs Wine's real critical-section-guarded,
//!   bounds-checked handle-table lookup and reports `FALSE`, not a fault.
//! * [`setup_close_file_queue_rejects_a_bad_signature_handle_on_wine`] —
//!   `SetupCloseFileQueue` on a pointer whose first 4 bytes are not its magic
//!   signature (`0x21514653`) is real setupapi.dll code recognising a bad
//!   handle: it returns `FALSE` and reports `GetLastError() == ERROR_INVALID_HANDLE`
//!   through a real TEB, not a fake one.
//!
//! Both `MsiRecordIsNull`'s "found nothing" default and
//! `SetupCloseFileQueue`'s exact error code are genuinely non-obvious facts
//! about Wine's own implementation, recovered from the pinned binaries'
//! disassembly (no Wine source read) rather than assumed from documentation.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::HashMap;
use std::path::Path;

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const SENTINEL: u64 = 0x0000_0000_6000_0000; // one page whose first byte is `hlt`
/// The TEB's `gs`-segment base the interpreter defaults to
/// ([`exemu_core::cpu::DEFAULT_GS_BASE`]) — mapped so `SetupCloseFileQueue`'s
/// real `SetLastError`-equivalent write (`gs:[0x68]`) lands somewhere real.
const GS_BASE: u64 = 0x0000_7FFF_0000_0000;

#[inline]
fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// A mapped, relocated DLL image: its resolved (non-forwarder) export map plus
/// the parsed import list, so a caller can rebind specific IAT slots.
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

    /// The IAT slot address for `dll!symbol`, resolved from this image's own
    /// import table rather than a hardcoded offset.
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

/// Parse, relocate to `base` and map `bytes` into `mem`, returning the loaded
/// image. Mirrors `com_gate.rs`'s `map_dll`.
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
            continue; // a re-export string, not a callable stub
        }
        if let Some(name) = &e.name {
            exports.insert(name.clone(), base + e.rva as u64);
        }
    }
    Dll { base, exports, imports: image.imports }
}

/// See `com_core_leaf_gate.rs`'s doc comment for the full story: Wine's
/// `TRACE()`/`WARN()` debug-channel guards (`test byte ptr [rip+d], N` —
/// `F6 05 <disp32> <imm8>`, 7 bytes) read a channel-flags byte that is
/// lazily-uninitialized to `0xff` in these binaries, not `0`, so every guard
/// takes the **logging** branch unless neutralised. This pokes the byte the
/// *first* such guard in `entry`'s opening bytes tests to `0` — a pure
/// logging no-op, no business logic changes. No-op when the pattern is absent.
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

/// Drive a call to `entry` on the real interpreter with Win64 args in
/// RCX/RDX/R8/R9, a `hlt` sentinel as the return address, and return RAX. Any
/// unimplemented path (an unbound import, for instance) surfaces as a fault
/// that fails the test.
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
    // RWX: the msi.dll test also plants a tiny `ret` stub in here (the two
    // rebound imports must be executable, not just writable).
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RWX)).unwrap();
    mem.map(Region::new("sentinel", SENTINEL, 0x1000, Perm::RWX)).unwrap();
    mem.poke(SENTINEL, &[0xF4]).unwrap(); // hlt
    mem.map(Region::new("teb", GS_BASE, 0x2000, Perm::RW)).unwrap();
    // TEB self-pointer at gs:[0x30] — real Wine code reads this to find its
    // own TEB before indexing into it (e.g. LastErrorValue at +0x68).
    mem.write_u64(GS_BASE + 0x30, GS_BASE).unwrap();
    mem
}

// ==========================================================================
// msi.dll: MsiCloseHandle / MsiRecordIsNull.
// ==========================================================================

/// **New msi.dll capability: the first msi.dll code this suite has ever
/// actually executed** (`breadth_gate.rs` only maps and cross-checks imports).
///
/// `MsiCloseHandle(0)` is a genuine leaf (no imports, no debug guard on its
/// disassembled path) and reports `ERROR_SUCCESS` — real Wine code treating
/// closing a null handle as harmless.
///
/// `MsiRecordIsNull` needs one more thing: its handle-table lookup
/// (`msi_get_handle_object`, recovered by disassembling the pinned binary) is
/// guarded by a real Win32 `CRITICAL_SECTION`, so it imports
/// `kernel32!EnterCriticalSection`/`LeaveCriticalSection`. Both IAT slots are
/// resolved from msi.dll's **own** import table (never hardcoded) and rebound
/// to a two-byte `ret` stub — correct because a single-threaded direct call
/// needs no real mutual exclusion, only the two functions to return. With
/// that, `MsiRecordIsNull(0xDEADBEEF, 0)` — a handle nothing ever allocated —
/// runs Wine's real bounds-checked table lookup end to end and reports
/// `FALSE`: the lookup fails silently for an unrecognized handle rather than
/// treating "not found" as "null", a genuinely non-obvious real behaviour.
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

    // --- MsiCloseHandle(0) --------------------------------------------------
    let msi_close_handle = dll.export("MsiCloseHandle");
    let rc = call_export(&mut mem, msi_close_handle, &[0]);
    assert_eq!(rc, 0, "MsiCloseHandle(0) should report ERROR_SUCCESS");

    // --- Bind the two imports MsiRecordIsNull's handle lookup needs ---------
    const RET_STUB: u64 = SCRATCH + 0x1000;
    mem.write(RET_STUB, &[0xC3]).unwrap(); // ret
    for sym in ["EnterCriticalSection", "LeaveCriticalSection"] {
        let slot = dll.iat_slot("kernel32.dll", sym);
        mem.write_u64(slot, RET_STUB).unwrap();
    }

    // --- MsiRecordIsNull(0xDEADBEEF, 0) — a handle nobody allocated ---------
    const BOGUS_HANDLE: u64 = 0xDEAD_BEEF;
    let msi_record_is_null = dll.export("MsiRecordIsNull");
    let is_null = call_export(&mut mem, msi_record_is_null, &[BOGUS_HANDLE, 0]);
    assert_eq!(
        is_null, 0,
        "MsiRecordIsNull on an unrecognized handle should report FALSE (Wine's real handle-table \
         lookup fails silently for a handle nothing allocated, rather than treating \"not found\" as \"null\")"
    );
}

// ==========================================================================
// setupapi.dll: SetupCloseFileQueue.
// ==========================================================================

/// **New setupapi.dll capability: the first setupapi.dll code this suite has
/// ever actually executed.**
///
/// `SetupCloseFileQueue` checks its argument's first 4 bytes against a fixed
/// magic signature before trusting it as a real `FILEQUEUE` pointer — a
/// pattern Wine's `msi.dll` object headers use too (`0x4d434923`, seen while
/// investigating `MsiRecordIsNull`), just a different magic number
/// (`0x21514653`). A scratch page whose first bytes are zero is guaranteed not
/// to match, so real setupapi.dll code takes its "bad handle" path: it
/// returns `FALSE` and writes `ERROR_INVALID_HANDLE` (6) to the real TEB's
/// `LastErrorValue` field (`gs:[0x68]`) — the exact documented Win32 error for
/// an invalid handle, produced by Wine's own validation code, not asserted by
/// this test.
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

    // A scratch "handle" whose first 4 bytes are definitely not the real
    // FILEQUEUE signature.
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
