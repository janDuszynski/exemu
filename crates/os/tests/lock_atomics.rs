//! W2.15 — LOCK-prefix atomics under the cooperative scheduler.
//!
//! The interpreter is single-threaded and cooperatively scheduled: guest
//! threads switch only at explicit block/yield points (or the timeslice
//! preemption counter), never mid-instruction. A `lock cmpxchg`/`lock xadd`/
//! `lock inc` therefore reads memory once and writes it once with no thread
//! switch in between, so it is already one indivisible read-modify-write. This
//! is the de-risk pin the oracle cannot cover (it can't see cross-thread): it
//! must catch a *future* preemptive/JIT change that would split an RMW across a
//! thread switch and lose updates.
//!
//! The fixture spawns N cooperative guest threads (main + workers) that each run
//! a `lock cmpxchg` CAS-increment loop `K` times on ONE shared 64-bit counter,
//! driven end-to-end through the REAL interpreter + the `WinOs` scheduler. To
//! make interleaving real and adversarial, each CAS iteration deterministically
//! *yields to another thread between reading the counter and the compare-and-
//! swap* (via a `SwitchToThread()` call sitting between the load and the
//! `lock cmpxchg`). A racing thread bumps the counter during that window, so the
//! CAS's compare fails and the iteration must reload and retry. The only way the
//! final counter can equal `N * K` — with zero lost updates — is if every
//! `lock cmpxchg` is one atomic read-modify-write. A non-atomic CAS (read and
//! write split across the yield) would silently drop increments and the final
//! total would come up short.

use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// One RWX region holds all code + the IAT + the shared counter.
const REGION: u64 = 0x0000_0000_0040_0000;
const REGION_SIZE: u64 = 0x0001_0000;
const MAIN: u64 = REGION + 0x1000;
const WORKER: u64 = REGION + 0x1800;
const IAT_CREATE: u64 = REGION + 0x2000; // CreateThread thunk
const IAT_WFSO: u64 = REGION + 0x2008; // WaitForSingleObject thunk
const IAT_SWITCH: u64 = REGION + 0x2010; // SwitchToThread thunk
const COUNTER: u64 = REGION + 0x3000; // the shared 64-bit counter
const ITERS: u64 = REGION + 0x3008; // total CAS-loop iterations across all threads
const HANDLE0: u64 = REGION + 0x3100; // worker thread handles land here

const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const PEB: u64 = GS_BASE + 0x3000;

// Two spawned workers + the main thread all hammer the counter: 3 writers.
const N_WORKERS: usize = 2;
const N_THREADS: u64 = N_WORKERS as u64 + 1;
// CAS-increment iterations *per thread*. Kept modest so the test is fast but
// still forces many cross-thread interleavings (each iteration yields).
const K: u64 = 500;
const INFINITE: u64 = 0xFFFF_FFFF;

/// Emit the shared CAS-increment loop body that runs `K` times on `[COUNTER]`
/// and then a `ret`. On entry nothing is assumed about registers.
///
///   xor r15, r15                 ; iteration count
/// loop:
///   mov r14, [COUNTER]           ; read the counter (the "old" CAS witness)
///   call [IAT_SWITCH]            ; YIELD here — another thread may bump COUNTER
///   mov rax, r14                 ; the CAS witness must live in RAX; the API
///                                ;   call clobbered RAX (volatile), so restore
///                                ;   the value read *before* the yield
///   lea rdx, [r14+1]            ; new = old + 1
///   lock cmpxchg [COUNTER], rdx  ; atomic CAS: if [COUNTER]==rax → store rdx
///   jnz loop                    ; lost the race → reload and retry (no ++ yet)
///   inc r15
///   cmp r15, K
///   jb  loop
///   ret
///
/// The witness is read into the callee-saved `r14` *before* the yield and copied
/// into `rax` *after* it: the CAS therefore still compares the pre-yield value
/// against memory. The `call [IAT_SWITCH]` between the load and the
/// `lock cmpxchg` is what makes this adversarial — a racing thread bumps
/// `[COUNTER]` during the yield window, so the compare (pre-yield witness vs the
/// now-changed memory) fails and the loop retries. With an atomic CAS every
/// increment eventually lands exactly once; with a split (non-atomic) RMW,
/// increments would be lost. `r14`/`r15` are non-volatile, so the scheduler's
/// save/restore of this thread's full register state carries them across the
/// switch intact.
fn cas_loop_body(out: &mut Vec<u8>) {
    // xor r15, r15
    out.extend([0x4D, 0x31, 0xFF]);
    let loop_start = out.len();
    // lock inc qword [ITERS]  (F0 48 FF 04 25 <abs32>) — count EVERY iteration,
    // including CAS retries, into a shared cell. `ITERS > N*K` at the end proves
    // some CAS lost the race and retried, i.e. the threads actually interleaved
    // over the shared counter (a serial run would give exactly `ITERS == N*K`).
    // It is itself a `lock inc` RMW, exercising the FE/FF-group lockable path.
    out.extend([0xF0, 0x48, 0xFF, 0x04, 0x25]);
    out.extend((ITERS as u32).to_le_bytes());
    // mov r14, [COUNTER]  (4C 8B 34 25 <abs32>)
    out.extend([0x4C, 0x8B, 0x34, 0x25]);
    out.extend((COUNTER as u32).to_le_bytes());
    // call [IAT_SWITCH]   (FF 14 25 <abs32>)
    out.extend([0xFF, 0x14, 0x25]);
    out.extend((IAT_SWITCH as u32).to_le_bytes());
    // mov rax, r14        (4C 89 F0)
    out.extend([0x4C, 0x89, 0xF0]);
    // lea rdx, [r14+1]    (49 8D 56 01)
    out.extend([0x49, 0x8D, 0x56, 0x01]);
    // lock cmpxchg [COUNTER], rdx  (F0 48 0F B1 14 25 <abs32>)
    out.extend([0xF0, 0x48, 0x0F, 0xB1, 0x14, 0x25]);
    out.extend((COUNTER as u32).to_le_bytes());
    // jnz loop_start  (0F 85 rel32)
    out.extend([0x0F, 0x85]);
    let after = out.len() + 4;
    out.extend(((loop_start as i64 - after as i64) as i32).to_le_bytes());
    // inc r15  (49 FF C7)
    out.extend([0x49, 0xFF, 0xC7]);
    // cmp r15, K  (49 81 FF <imm32>)
    out.extend([0x49, 0x81, 0xFF]);
    out.extend((K as u32).to_le_bytes());
    // jb loop_start  (0F 82 rel32)
    out.extend([0x0F, 0x82]);
    let after2 = out.len() + 4;
    out.extend(((loop_start as i64 - after2 as i64) as i32).to_le_bytes());
    // ret
    out.push(0xC3);
}

#[test]
fn lock_cmpxchg_cas_increment_never_loses_an_update() {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("prog", REGION, REGION_SIZE, Perm::RWX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x4000, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, 0x3000, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();

    let mut os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        // Thread stacks + per-thread TEBs are mapped from here; keep it clear of
        // everything above.
        valloc_base: 0x0000_0040_0000_0000,
        ..WinConfig::default()
    });

    // Resolve the API thunks and seat them in the IAT the code calls through.
    let create = os.resolve_import("kernel32.dll", &ImportSymbol::Named("CreateThread".into()));
    let wfso = os.resolve_import("kernel32.dll", &ImportSymbol::Named("WaitForSingleObject".into()));
    let switch = os.resolve_import("kernel32.dll", &ImportSymbol::Named("SwitchToThread".into()));
    let exit_thunk = os.exit_thunk();
    mem.write_u64(IAT_CREATE, create).unwrap();
    mem.write_u64(IAT_WFSO, wfso).unwrap();
    mem.write_u64(IAT_SWITCH, switch).unwrap();
    mem.write_u64(COUNTER, 0).unwrap();
    mem.write_u64(ITERS, 0).unwrap();

    // --- worker thread: run the CAS loop, then ret (exit code 0) -----------
    let mut worker = Vec::new();
    cas_loop_body(&mut worker);
    mem.write(WORKER, &worker).unwrap();

    // --- main thread -------------------------------------------------------
    // Spawn N_WORKERS threads (storing each handle), run the CAS loop itself,
    // then join every worker, then ret. A generous fixed frame reserves the
    // shadow space + the two stack args (dwCreationFlags @ [rsp+0x20],
    // lpThreadId @ [rsp+0x28]) for every x64 call below.
    let mut main = Vec::new();
    // sub rsp, 0x40   (48 83 EC 40)
    main.extend([0x48, 0x83, 0xEC, 0x40]);
    for w in 0..N_WORKERS {
        // CreateThread(NULL, 0, WORKER, NULL, 0, NULL)
        // xor ecx,ecx / xor edx,edx  → attrs, stackSize
        main.extend([0x31, 0xC9]); // xor ecx, ecx
        main.extend([0x31, 0xD2]); // xor edx, edx
        // mov r8, WORKER  (49 B8 <imm64>)
        main.extend([0x49, 0xB8]);
        main.extend(WORKER.to_le_bytes());
        // xor r9d, r9d  (45 31 C9)
        main.extend([0x45, 0x31, 0xC9]);
        // mov qword [rsp+0x20], 0  (dwCreationFlags)  48 C7 44 24 20 00 00 00 00
        main.extend([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        // mov qword [rsp+0x28], 0  (lpThreadId)       48 C7 44 24 28 00 00 00 00
        main.extend([0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        // call [IAT_CREATE]  (FF 14 25 <abs32>)
        main.extend([0xFF, 0x14, 0x25]);
        main.extend((IAT_CREATE as u32).to_le_bytes());
        // mov [HANDLE0 + w*8], rax  (48 89 04 25 <abs32>)
        main.extend([0x48, 0x89, 0x04, 0x25]);
        main.extend(((HANDLE0 + w as u64 * 8) as u32).to_le_bytes());
    }
    // Main runs the CAS loop too (it is one of the N writers). Inline the body;
    // its trailing `ret` is replaced by falling through into the join phase, so
    // splice in everything up to (but not including) the final `ret`.
    let mut body = Vec::new();
    cas_loop_body(&mut body);
    body.pop(); // drop the trailing 0xC3 ret — fall through to the joins
    main.extend_from_slice(&body);
    // Join each worker: WaitForSingleObject([HANDLE], INFINITE)
    for w in 0..N_WORKERS {
        // mov rcx, [HANDLE0 + w*8]  (48 8B 0C 25 <abs32>)
        main.extend([0x48, 0x8B, 0x0C, 0x25]);
        main.extend(((HANDLE0 + w as u64 * 8) as u32).to_le_bytes());
        // mov edx, INFINITE  (BA <imm32>)
        main.extend([0xBA]);
        main.extend((INFINITE as u32).to_le_bytes());
        // call [IAT_WFSO]
        main.extend([0xFF, 0x14, 0x25]);
        main.extend((IAT_WFSO as u32).to_le_bytes());
    }
    // Return the final counter as the process exit code: mov rax, [COUNTER].
    main.extend([0x48, 0x8B, 0x04, 0x25]);
    main.extend((COUNTER as u32).to_le_bytes());
    // add rsp, 0x40  (48 83 C4 40)
    main.extend([0x48, 0x83, 0xC4, 0x40]);
    // ret → the process-exit sentinel
    main.push(0xC3);
    mem.write(MAIN, &main).unwrap();

    // --- run ---------------------------------------------------------------
    let mut cpu = Interpreter::with_bits(Bits::B64);
    // Seat the process-exit sentinel so main's final `ret` terminates cleanly.
    let rsp = (STACK_TOP - 0x100) & !0xf;
    let rsp = rsp - 8; // 16-byte alignment for the return address
    mem.write_u64(rsp, exit_thunk).unwrap();
    {
        let s = cpu.state_mut();
        s.rip = MAIN;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE; // main thread's TEB
        s.fs_base = GS_BASE;
    }

    let mut exit_code = None;
    for _ in 0..50_000_000u64 {
        match cpu.step(&mut mem, &mut os).unwrap() {
            Exit::Continue => {}
            Exit::ProcessExit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }

    let final_counter = mem.read_u64(COUNTER).unwrap();
    let expected = N_THREADS * K;
    assert_eq!(
        final_counter, expected,
        "lost an update: {N_THREADS} threads × {K} lock-cmpxchg increments should total {expected}, got {final_counter}",
    );
    // Main returns the counter it read as the process exit code (low 32 bits).
    assert_eq!(
        exit_code,
        Some(expected as i32),
        "main did not resume past the joins with the final counter",
    );
    // Prove the threads actually interleaved over the shared counter (so the
    // exact total is not a fluke of a serial run): with a yield between each
    // load and its CAS, a racing thread bumps the counter during the window and
    // the CAS retries. Total loop iterations therefore strictly exceed the
    // `N * K` successful ones. A serial (non-interleaved) run would retry never
    // and give exactly `N * K`.
    let total_iters = mem.read_u64(ITERS).unwrap();
    assert!(
        total_iters > expected,
        "threads did not interleave over the shared counter: {total_iters} iterations for {expected} increments (expected retries from contention)",
    );
}
