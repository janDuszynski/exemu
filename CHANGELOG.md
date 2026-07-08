# Changelog

exemu loads a Windows PE (32- or 64-bit) and runs it natively on Apple Silicon
— no Windows, no Rosetta, no VM. Versions before 1.0 track **capability**, not
API stability: `0.0.x` is the pre-GUI foundation, `0.1.0` will be the first real
interactive native window, and `1.0.0` is the notarized product. A version
advertises only what is actually implemented.

## v0.0.2 — trust the CPU

The CPU's correctness is now guarded by a **Unicorn differential oracle**: the
interpreter is lockstep-diffed against QEMU/Unicorn over tens of millions of
randomized instructions with zero divergence. Every instruction added below
lands only after the oracle is green for it.

### Oracle
- Fuzz the extended registers: the generator now exercises **R8–R15** (REX.R/B)
  and the engine seeds, runs and diffs **xmm8–15** in 64-bit mode (a harness bug
  left Unicorn's high XMM unseeded — fixed).

### CPU — SSE/SSE2 completion (each oracle-verified)
- `MOVMSKPS`/`MOVMSKPD` (previously a decode error).
- Saturating packed add/sub: `PADDS`/`PADDUS`/`PSUBS`/`PSUBUS` (byte + word).
- Packed multiply: `PMULLW`/`PMULHW`/`PMULHUW`, `PMULUDQ`, `PMADDWD`.
- `PAVGB`/`PAVGW`, `PSADBW`, `PACKSSWB`/`PACKSSDW`/`PACKUSWB`, `PEXTRW`
  (and routed `0F C5`, which the oracle flagged as unhandled).
- Packed int↔float: `CVTDQ2PS`/`CVTPS2DQ`/`CVTTPS2DQ`, and `LDDQU`.
- `LDMXCSR`/`STMXCSR` and `FXSAVE`/`FXRSTOR` (MXCSR + XMM), closing the CPUID
  FXSR honesty gap.

### Notes
- The cache-free interpreter runs self-modifying code correctly (pinned by a
  regression test).
- Deferred to later releases: the iced-x86 exhaustive-encoding oracle pass,
  control-flow oracle trials, the full MXCSR rounding-mode model (only
  round-nearest affects conversions today), and the approximate/rare
  `RSQRT`/`RCP`/`MASKMOVDQU`.

## v0.0.1 — foundation / bring-up

The substrate a Windows program needs before its window can exist: a software
CPU, a PE loader, a kernel-personality skeleton, and x64 exception handling.
Console apps run to completion; GUI installers reach and auto-drive their dialog
headlessly.

### CPU
- Software x86 / x86-64 interpreter (32- and 64-bit modes), integer + SSE/SSE2.
- Honest `CPUID` (advertises only implemented features), monotonic `RDTSC`,
  `POPCNT`/`TZCNT`/`LZCNT`, `MOVBE`, and the `0F 38` three-byte escape.
- Table-driven ALU flag-accuracy matrix (OF/CF/AF/PF/SF/ZF across all widths).

### Loader
- PE32 and PE32+ parsing: sections, imports (by name/ordinal), exports,
  base relocations, and the x64 `.pdata`/`.xdata` unwind function table.

### Windows userland (~200 APIs)
- kernel32/msvcrt/UCRT startup: CRT init (`_initterm`), TLS/FLS, environment,
  code-page conversion, heaps (`Heap*`/`Global*`/`Local*`), files in a host
  sandbox (`$TMPDIR/exemu-sandbox`).
- GUI installer path: dialog resource parsing, `CreateDialogParamW`/
  `DialogBoxParamW` driving the guest DLGPROC, a bounded message pump, and a
  solid-fill/text/line GDI subset rendered to a software framebuffer.

### Exceptions (x64)
- Parses `.pdata`/`.xdata`; virtual unwind (`RtlVirtualUnwind` equivalent)
  powers fault-report call stacks.
- Native `RtlCaptureContext` / `RtlLookupFunctionEntry` / `RtlVirtualUnwind` /
  `RtlPcToFileHeader`, and `RaiseException` / `RtlUnwindEx` driving a real
  search-then-unwind dispatch that calls the guest's own C++/SEH language
  handlers; an unmatched throw terminates like `std::terminate`.

### Tooling
- `exemu run|info|sample|opcodes`; a fault reporter with register dump, rip
  trail, import-thunk detection, and (x64) a virtually-unwound call stack;
  missing-opcode telemetry ranked by `exemu opcodes`.

### Verified
- Generated `hello.exe` runs and prints (incl. an SSE2 result), exit 0.
- 7-Zip installer runs end-to-end — extracts all 107 files + registry, exit 0
  (~496M instructions, headless).
- 117 tests pass; clippy clean at `-D warnings`.
