# Changelog

exemu loads a Windows PE (32- or 64-bit) and runs it natively on Apple Silicon
— no Windows, no Rosetta, no VM. Versions before 1.0 track **capability**, not
API stability: `0.0.x` is the pre-GUI foundation, `0.1.0` will be the first real
interactive native window, and `1.0.0` is the notarized product. A version
advertises only what is actually implemented.

## v0.0.4 — the windowing substrate

The last foundation layer *under* the GUI: a real USER32/GDI object model the
guest can drive — a message queue, real window objects, a painting model, input
state, and a typed GDI object model. There is still **no native window** (that is
the 0.1.0 headline); this hardens everything beneath it. It dismantles the
documented "GUI wall": guest code (and installer plugins like nsDialogs) can now
treat an HWND as a real, dereferenceable object with consistent per-window state.
199 tests, clippy clean; 7-Zip still installs end-to-end.

### Message queue (P5a.1)
- A real per-thread queue: `PostMessage`/`PostThreadMessage` enqueue,
  `GetMessage`/`PeekMessage` (PM_REMOVE vs PM_NOREMOVE) drain, `PostQuitMessage`
  delivers a synthetic `WM_QUIT` (carrying the exit code) once the queue drains,
  and a real `TranslateMessage` (WM_KEYDOWN→WM_CHAR).

### Window objects (P5a.2)
- `CreateWindowEx` allocates distinct, dereferenceable HWNDs holding per-window
  class/wndproc/style/rect/parent/title/userdata/props. `Get/SetWindowLong[Ptr]`
  (GWLP_WNDPROC subclassing, GWLP_USERDATA, GWL_STYLE/EXSTYLE, arbitrary
  cbWndExtra), `IsWindow`, `GetClientRect`/`GetWindowRect`, `GetClassName`,
  `ShowWindow`, `Get/Set/RemoveProp`, per-window `Get/SetWindowText`.
  `DispatchMessage` routes to the target HWND's WNDPROC.

### Painting model (P5a.4)
- Per-window invalidation: `InvalidateRect`/`ValidateRect`/`GetUpdateRect`,
  `BeginPaint` fills a real PAINTSTRUCT (rcPaint = update region) and services the
  paint, `EndPaint`, `GetDC`/`GetWindowDC`/`ReleaseDC`.

### Input & geometry (P5a.3)
- Focus (`Set/GetFocus`), mouse capture (`Set/Get/ReleaseCapture`),
  `GetKeyState`/`GetAsyncKeyState`, `GetCursorPos`; `MoveWindow`/`SetWindowPos`
  update the window rect and post `WM_MOVE`/`WM_SIZE`.

### GDI object model (P5b.1)
- **Typed** GDI objects (pen/brush/font). `SelectObject` installs into the
  matching device-context slot and returns the *previously selected* object of
  that kind; `CreateFontIndirect` parses a LOGFONT subset and `GetObject` marshals
  it back; `SaveDC`/`RestoreDC` (a real DC-state stack); `SetBkColor`/`SetBkMode`.

## v0.0.3 — a real process

The kernel personality underneath the (still-headless) GUI grew up: a program
can now spawn threads, allocate and probe virtual memory, wait on real
synchronization objects, read the clock, enumerate directories, and round-trip
the registry. The gate for this release: **a multithreaded console app runs;
`Reg*` round-trips; `VirtualAlloc/Protect/Query` behave; a self-extractor that
enumerates directories completes** (7-Zip still installs end-to-end, ~496M
instructions). 183 tests, clippy clean.

### Virtual memory (P3.2)
- Real `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/`VirtualQuery`: distinct,
  page-aligned regions from a dedicated 64 KiB-granular arena, reserve/commit
  tracking, `MEM_RELEASE` unmaps, and a true `MEMORY_BASIC_INFORMATION` (own
  regions, foreign mapped regions, and free gaps) in both 32- and 64-bit layout.
  Backing stays RWX (DEP-relaxed) while the *nominal* `PAGE_*` protection is
  tracked so `VirtualProtect`/`VirtualQuery` report honest values.

### Threads + cooperative scheduler (P3.4)
- A scheduler living entirely in the OS layer: a thread table with per-thread
  saved CPU state, its own `VirtualAlloc`-backed stack, and per-thread TLS/FLS.
- `CreateThread`/`_beginthreadex`, `ExitThread`/`_endthreadex`, start-routine
  return, `Resume`/`Suspend`/`TerminateThread`, `GetExitCodeThread`,
  `SwitchToThread`, `Sleep`/`SleepEx`. `GetCurrentThreadId` reports the running
  thread.
- Blocking `WaitForSingle/MultipleObjects` truly block and resume when the
  object signals (thread handles are waitable latches). A 50k-instruction
  timeslice preempts a CPU-bound thread so it can't starve the others.

### Synchronization objects (P3.6)
- Real signaling state for events (auto/manual-reset), mutexes (owner +
  recursion), semaphores (count/max) and waitable timers, with named-object
  sharing (`ERROR_ALREADY_EXISTS`) and `Open*` by name. `SetEvent`/`ResetEvent`/
  `PulseEvent`/`ReleaseMutex`/`ReleaseSemaphore` mutate state; waits consume it
  (auto-reset resets, semaphore decrements, mutex takes ownership).

### Time & date (P3.8)
- Host-clock-backed `GetTickCount(64)`, `QueryPerformanceCounter`/`Frequency`
  (10 MHz), `GetSystemTimeAsFileTime`, and `GetSystemTime`/`GetLocalTime` (a
  real `SYSTEMTIME` via a pure civil-from-days computation).

### Filesystem (P3.9)
- `FindFirstFile`/`FindNextFile` now have real **A-variants** (`WIN32_FIND_DATAA`)
  beside W; added `GetFullPathName`, `MoveFile`/`MoveFileEx`, `CopyFile`,
  `SetFileTime`, and A-variants of `CreateDirectory`/`DeleteFile`/
  `GetFileAttributes`.

### Registry (P3.12)
- The whole surface reworked with **W and A** variants: create/open/set/query/
  delete plus **enumeration** (`RegEnumKeyEx`/`RegEnumValue`/`RegQueryInfoKey`,
  treating the hive as a tree). Every `REG_*` value type round-trips; HKLM/HKCU
  are seeded with the version keys installers probe. (Cross-run persistence is
  still a TODO.)

### Installers
- **7-Zip** still installs end-to-end (~496M instructions, 107 files + registry,
  exit 0). **SteamSetup** now reaches ~93M instructions (more than double its
  pre-0.0.2 reach) before faulting deep in unpacked code; **Firefox** ~4.7M.

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
