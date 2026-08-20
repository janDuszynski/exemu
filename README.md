# exemu — a Windows `.exe` emulator for Apple Silicon

**Version 0.0.4** (the windowing substrate) — see [CHANGELOG.md](CHANGELOG.md).
Versions before 1.0 track capability, not API stability: `0.1.0` will be the
first real interactive native window, `1.0.0` the notarized product.

`exemu` loads a Windows **PE** (Portable Executable) `.exe` — either 32-bit
(`x86`) or 64-bit (`x86-64`) — and runs it on an Apple **M-series** (ARM64)
Mac, with no Windows, no Rosetta, and no virtual machine. It parses the
executable, maps it into a virtual address space, interprets the guest's
x86 instructions in software, and services the Windows API calls the program
makes by implementing them natively on the host.

It is written in **Rust** for speed and memory safety, and organized with
**Clean Architecture** so each concern (parsing, memory, CPU, OS) is an
independent, testable crate behind a trait.

> **Scope.** This is a from-scratch userland emulator built for clarity and
> extensibility. It implements a broad subset of the x86/x86-64 instruction
> set (through SSE4.2 plus AVX/AVX2, x87 and MMX), ~200 Win32 functions, a
> host-backed sandbox filesystem, and a lightweight **window + GDI renderer** —
> enough to run real console programs end to end and to drive real GUI apps
> (`--gui`) interactively, both dialog-template UIs and custom
> `CreateWindowEx` windows. On this default path the rendering is a software
> subset (solid fills, frames, text, lines) — **not** Windows' native theming,
> GDI+, or DirectX — so visually complex apps hit unimplemented drawing calls.
>
> **There is a second path.** exemu also implements the **NT syscall layer and
> the PE/Unix boundary Wine's own builtin DLLs call through**, so it can boot
> Wine's PE `ntdll`/`kernel32`/`user32`/`gdi32`/`win32u` as emulated guest code
> instead of re-implementing them — see
> [Running on Wine's PE personality](#running-on-wines-pe-personality---wine-boot).
> That path is opt-in and still under construction, but it is where the
> project is going: the Windows personality comes from Wine, and exemu supplies
> the CPU, the kernel, and a from-scratch macOS display driver.

## Architecture

Dependencies point strictly inward. The domain (`core`) has zero
dependencies and defines the abstractions; every outer crate implements or
orchestrates them.

```
        ┌─────────────────────────────────────────────┐
        │  cli   (presentation: argument parsing, UX)  │
        └───────────────────┬─────────────────────────┘
                            │
        ┌───────────────────▼─────────────────────────┐
        │  app   (use cases: load → map → run loop)    │
        └───┬───────────┬───────────┬─────────────┬────┘
            │           │           │             │
       ┌────▼───┐  ┌────▼────┐  ┌───▼───┐   ┌─────▼────┐
       │ loader │  │ memory  │  │cpu/jit│   │    os    │   (infrastructure)
       │  (PE)  │  │(regions)│  │(x86-64│   │(kernel32)│
       └────┬───┘  └────┬────┘  └───┬───┘   └─────┬────┘
            └───────────┴─────┬─────┴─────────────┘
                       ┌──────▼───────┐
                       │     core     │   (domain: types + traits,
                       │  no deps     │    Memory / Cpu / Hooks)
                       └──────────────┘
```

| Crate            | Layer          | Responsibility                                             |
| ---------------- | -------------- | ---------------------------------------------------------- |
| `exemu-core`     | Domain         | CPU state, PE model, errors; `Memory`/`Cpu`/`Hooks` traits |
| `exemu-loader`   | Infrastructure | Parse PE64 headers, sections and imports                   |
| `exemu-memory`   | Infrastructure | Region-based virtual memory with permissions               |
| `exemu-cpu`      | Infrastructure | x86-64 decoder + interpreter                               |
| `exemu-jit`      | Infrastructure | Block JIT: guest x86/x86-64 → native ARM64 (opt-in)        |
| `exemu-os`       | Infrastructure | PEB/TEB, import thunks, `kernel32` API implementations      |
| `exemu-app`      | Application    | Wire everything together and drive the fetch/exec loop     |
| `exemu-cli`      | Presentation   | `exemu run <file.exe>` and friends                         |

## Build & run

```sh
cargo build --release

# Generate a self-contained demo .exe (no Windows toolchain needed),
# inspect it, then run it:
./target/release/exemu sample hello.exe
./target/release/exemu info   hello.exe
./target/release/exemu run    hello.exe
```

Running the generated binary prints:

```
Hello from exemu! This Windows x64 .exe is running on Apple Silicon.

[exemu] process exited with code 0 after 13 instructions
```

`file(1)` confirms the generated `hello.exe` is a genuine
`PE32+ executable (console) x86-64, for MS Windows`.

### CLI

```
exemu run <file.exe> [--trace] [--no-echo] [--gui] [--wine-boot <dir>]
                     [--virtual-clock] [--jit] [--max-steps N] [--load-base <hex>]
                     [--telemetry <path>] [-- <args>...]
exemu info <file.exe>
exemu opcodes [--telemetry <path>] [--clear]
exemu corpus [--manifest <path>] [--only <substr>] [--quick] [--update]
exemu sample <out.exe>
exemu gui-sample <out.exe>
exemu cocoa-demo [--size WxH] [--hold SECS]
```

* `run` maps the image, resolves imports, and interprets it to completion,
  exiting with the guest's exit code. `--trace` logs calls to unimplemented
  Windows APIs; `--no-echo` suppresses mirroring guest output to the host.
  `--max-steps N` sets the instruction budget (0 = unlimited); `--load-base`
  maps the image away from its preferred `ImageBase` and applies its base
  relocations. `--wine-boot <dir>` selects the Wine PE personality
  ([below](#running-on-wines-pe-personality---wine-boot)); `--virtual-clock`
  (also `EXEMU_VIRTUAL_CLOCK=1`) replaces the host clock with a
  [deterministic one](#deterministic-guest-clock) driven by the instruction
  counter, so a run replays with the exact same instruction count. `--jit`
  (also `EXEMU_JIT=1`) runs guest code through the [block JIT](#block-jit---jit)
  where it can and reports how much of the run went native.
  If a run stops on an instruction the decoder doesn't implement, the opcode
  is appended to a telemetry log (`--telemetry <path>`, else the
  `EXEMU_TELEMETRY` env var, else `$TMPDIR/exemu-telemetry.log`).
  On a fault the report includes a register dump, the recent rip trail and —
  for 64-bit images with unwind data — a **call stack** recovered by virtually
  unwinding the guest's frames.
* `info` dumps headers, sections, imports and the x64 unwind data
  (`.pdata` runtime-function count).
* `opcodes` reads that telemetry log and prints a **most-wanted ranking** of
  the unimplemented opcodes that blocked past runs — so the highest-leverage
  instruction to add next is obvious. `--clear` resets the log.
* `corpus` runs the **per-exe regression pins** in `corpus.toml` and prints a
  pass/fail table with the instruction delta against each pin and where each
  binary stopped. Every binary runs in its own child process with a private
  `TMPDIR`, so its sandbox artifacts are counted in isolation. Exit status is 1
  on any drift; `--update` re-blesses the manifest so refreshing a pin is a
  deliberate, reviewable diff. See [Corpus regression gate](#corpus-regression-gate).
* `sample` writes the built-in Hello-World PE to disk; `gui-sample` writes a
  small real-window PE (run it with `--gui`).
* `cocoa-demo` opens a live macOS **NSWindow** whose contents are a `CAMetalLayer`
  and blits a BGRA test frame through the same Metal path the Wine GUI will use —
  the from-scratch display presenter (macOS only). `--size WxH` sets the window
  size, `--hold SECS` how long it stays up. This exercises the presenter's
  pixel/Metal path directly; driving it from a guest window is in progress.

## How it runs a `.exe`

1. **Load** — `exemu-loader` validates the DOS/PE/COFF/optional headers,
   reads the section table and walks the import directory.
2. **Map** — `exemu-app` maps headers and sections at the image base with
   per-section permissions, and sets up a stack, a heap arena, and a
   TEB/PEB pair reachable through the `gs:` segment.
3. **Bind imports** — each imported symbol is assigned a synthetic *thunk*
   address by `exemu-os`, which the loader writes into the Import Address
   Table. There are no real DLLs in the address space.
4. **Interpret** — `exemu-cpu` fetches, decodes and executes x86-64
   instructions one at a time.
5. **Service APIs** — before each instruction, the OS layer is asked whether
   `rip` is one of its thunks. If so it reads the arguments per the Windows
   x64 ABI, runs the call natively (e.g. `WriteFile` → host `stdout`), sets
   `rax`, and simulates the `ret`.

## What works today

* **Both bitnesses**: PE32 (32-bit `x86`) and PE32+ (64-bit `x86-64`),
  parsing headers, sections, and imports (by name or ordinal). The CPU has
  a 32-bit and a 64-bit mode (REX-vs-inc/dec, RIP-relative-vs-absolute
  addressing, 4-vs-8-byte stack, `fs:`-vs-`gs:` TEB).
* A broad instruction subset: the ALU family, `MOV`/`LEA`/`MOVZX`/`MOVSX`,
  `MOVBE`, stack ops, `CALL`/`RET`, the full `Jcc`/`SETcc`/`CMOVcc` condition
  set, shifts/rotates, `SHLD`/`SHRD`, `MUL`/`IMUL`/`DIV`/`IDIV`, the `BT`
  bit-test family, `BSF`/`BSR`/`BSWAP`, the bit-count instructions
  `POPCNT`/`TZCNT`/`LZCNT`, `XADD`/`CMPXCHG`, `LOOP`/`JECXZ`, the string ops
  (`MOVS`/`STOS`/`CMPS`/`LODS`/`SCAS` with `REP`/`REPE`/`REPNE`),
  `RDTSC`/`RDTSCP` (monotonic counter, or a 1 GHz ramp off the retired-
  instruction count under `--virtual-clock`; `RDTSCP` reports `TSC_AUX`=0 for the
  single-vCPU model), `PAUSE`, and a broad **SSE/SSE2** surface: moves,
  logical, scalar+packed float arithmetic, compares and conversions
  (incl. `CVTDQ2PS`/`CVTPS2DQ`/`CVTTPS2DQ`), the packed-integer family —
  add/sub (incl. **saturating** `PADD/PSUB S/US`), multiply (`PMULLW`/`HW`/
  `HUW`, `PMULUDQ`, `PMADDWD`), `PAVGB/W`, `PSADBW`, `PACK*`, `PEXTRW`,
  `MOVMSKPS/PD`, shifts, shuffles, pack/unpack — plus the **SSSE3/SSE4.1/
  SSE4.2** three-byte `0F 38`/`0F 3A` families: `PSHUFB`, `PALIGNR`, the
  horizontal add/subtract and sign/abs ops, `PTEST`, `ROUND*` (honoring `MXCSR`
  rounding), `PMULLD`/`PMULDQ`, the blends, `PMOVSX`/`PMOVZX`, `PEXTR*`/`PINSR*`,
  `INSERTPS`/`EXTRACTPS`, `DPPS`/`DPPD`, `MPSADBW`, the `PCMPESTR`/`PCMPISTR`
  string compares (full `imm8` semantics + flags), and `CRC32` — plus
  `LDMXCSR`/`STMXCSR`, the full 512-byte `FXSAVE`/`FXRSTOR` save area, and the
  extended-state
  `XSAVE`/`XRSTOR`/`XGETBV`/`XSETBV` (x87+SSE+AVX components) — all with faithful
  EFLAGS and cross-checked against a Unicorn differential oracle (byte-exact
  save-area diff). **AVX/AVX2** is implemented via the **VEX** prefixes
  (`0xC4`/`0xC5`): a 256-bit `YMM0`–`YMM15` register file with correct VEX.128
  zero-upper (vs legacy-SSE upper-preserve) semantics, the VEX forms of the SSE
  surface, the AVX2 lane-wise integer ops, and the broadcast/permute/blend/
  insert-extract family (`VPBROADCAST*`, `VPERMQ`/`VPERMD`, `VINSERTI128`/
  `VEXTRACTI128`, `VPBLEND*`, the per-element variable shifts), plus
  `VZEROUPPER`/`VZEROALL`. The **x87 FPU** is implemented too: the ST0–ST7
  register stack (with real 80-bit storage, so `long double` loads/stores are
  bit-exact), the control/status/tag words, `FLD`/`FST`/`FIST` and their integer
  and 80-bit forms, the arithmetic family (`FADD`/`FSUB(R)`/`FMUL`/`FDIV(R)`),
  compares (`FCOM`/`FCOMI`/`FUCOMI` + the `fnstsw ax`→`jcc` idiom),
  `FSQRT`/`FSCALE`/`FPREM`/`FRNDINT`, and the transcendentals
  (`FSIN`/`FCOS`/`FPATAN`/`F2XM1`/`FYL2X`, as documented host-math
  approximations). Arithmetic uses a double-precision core; the x87 category of
  the oracle diffs the whole stack + status/control words against Unicorn.
  `CPUID` reports an honest feature set (only the instructions actually
  implemented — through SSE4.2, AVX and AVX2), so CRTs dispatch onto code paths
  the interpreter can execute. **Self-modifying code** works because the
  interpreter re-decodes every instruction from live memory; writes into
  executable regions are tracked with per-page generation counters (the
  invalidation seam a future JIT code cache consumes).
* **~200 Win32 functions** across `kernel32`/`user32`/`gdi32`/`advapi32`/
  `shell32`/`ole32`/`comctl32`: console I/O, the `Heap*`/`Global*` allocators,
  the `lstr*` string family, `CharNext`/`CharPrev`, command line, module
  handles, and console stubs. Every function — even the unimplemented ones —
  carries its **stdcall argument count**, so 32-bit callee stack cleanup stays
  correct and stub calls don't corrupt the stack. Handle-returning stubs yield
  a non-null fake handle so setup proceeds.
* **A real process substrate** (the "a real process" milestone):
  - **Virtual memory:** `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/
    `VirtualQuery` map real, distinct, page-aligned regions with reserve/commit
    tracking; `VirtualQuery` fills a true `MEMORY_BASIC_INFORMATION`.
  - **Threads + a cooperative scheduler:** `CreateThread`/`_beginthreadex`,
    `ExitThread`, `Resume`/`Suspend`/`TerminateThread`, `GetExitCodeThread`,
    per-thread stacks and TLS. Threads yield at blocking points and on a
    timeslice, so a multithreaded console app runs and joins correctly.
  - **Real synchronization objects:** events (auto/manual-reset), mutexes
    (ownership + recursion), semaphores (counts), waitable timers, with
    named-object sharing; `WaitForSingle/MultipleObjects` truly block and wake.
  - **Time:** `GetTickCount(64)`, `QueryPerformanceCounter/Frequency`,
    `GetSystemTimeAsFileTime`, `GetSystemTime`/`GetLocalTime`, and the
    `NtQuerySystemTime`/`NtQueryPerformanceCounter` syscalls. Host-backed by
    default; `--virtual-clock` switches every one of them (plus `RDTSC` and
    `KUSER_SHARED_DATA`) onto a [deterministic clock](#deterministic-guest-clock)
    driven by the instruction counter.
  - **Registry:** an in-memory hive with W **and A** variants —
    create/open/set/query/delete, enumeration (`RegEnumKeyEx`/`RegEnumValue`/
    `RegQueryInfoKey`), every `REG_*` value type, and seeded HKLM/HKCU keys.
* **A real windowing substrate** (USER32/GDI object model — the layer *beneath*
  a native window; there is not yet a native window itself):
  - **Message queue:** a real per-thread queue behind `PostMessage`/
    `PostThreadMessage`/`GetMessage`/`PeekMessage`/`PostQuitMessage`/
    `TranslateMessage` (WM_KEYDOWN→WM_CHAR), with proper `WM_QUIT`.
  - **Window objects:** `CreateWindowEx` yields real, distinct, dereferenceable
    HWNDs; `Get/SetWindowLongPtr` (WNDPROC subclassing, user data, styles),
    `IsWindow`, `GetClientRect`/`GetWindowRect`, `GetClassName`, `ShowWindow`,
    `Get/Set/RemoveProp`, per-window text; `DispatchMessage` routes per-HWND.
  - **Painting:** per-window invalidation — `InvalidateRect`/`ValidateRect`/
    `GetUpdateRect`, `BeginPaint`/`EndPaint` (real PAINTSTRUCT), `GetDC`.
  - **Input & geometry:** focus/capture/key-state, `MoveWindow`/`SetWindowPos`
    (posting `WM_MOVE`/`WM_SIZE`).
  - **GDI objects:** typed pens/brushes/fonts, `SelectObject` returning the prior
    object, `CreateFontIndirect`/`GetObject`, `SaveDC`/`RestoreDC`.
* A **host-backed sandbox filesystem**: `CreateFileW`/`ReadFile`/`WriteFile`/
  `CloseHandle`, `CreateDirectory`, `GetTempPathW`/`GetTempFileNameW`,
  `GetFileSize`/`SetFilePointer`/`GetFileAttributes`/`DeleteFile`,
  `GetFullPathName`, `MoveFile`/`MoveFileEx`, `CopyFile`, `SetFileTime`,
  `GetModuleFileNameW`, and **directory enumeration**
  (`FindFirstFile`/`FindNextFile`/`FindClose`, in both **W and A** variants)
  with case-insensitive glob, `.`/`..` entries, and `WIN32_FIND_DATA` size/time
  fields. Guest paths map into a sandbox dir; the executable is copied in so a
  self-extractor can read its own appended archive.
* Data imports, `_initterm` static-constructor execution via re-entrant
  guest calls, and a slice of the `msvcrt` C runtime.
* **Data imports** (a DLL exporting a variable, not a function). The thunk
  region is mapped as real read/write memory, so the C runtime can
  dereference globals like `_fmode`/`_commode`; `_acmdln`/`_wcmdln` are
  seeded with the command line.
* A slice of the **`msvcrt` C runtime**: `malloc`/`calloc`/`realloc`/`free`,
  `memcpy`/`memmove`/`memset`/`memcmp`/`strlen`, the `exit` family,
  `__getmainargs`, and no-op startup hooks (`__set_app_type`, `_controlfp`,
  …). Enough that MSVCRT-linked binaries get through CRT startup and into
  their own `main`.
* **Re-entrant guest calls**: `_initterm` actually runs the initializer
  table (C/C++ static constructors) *as real guest calls*, in order, before
  returning. It does this with a driver-thunk state machine — an API handler
  seats a call frame pointing at a sentinel thunk, and each return advances
  to the next callback — so no nested interpreter loop is needed. This is
  the general mechanism any callback-taking API (`atexit`, `qsort`, window
  procedures) would build on.

### GUI (`--gui`)

`exemu run --gui <app.exe>` renders the program's UI in a real window and
lets you drive it. Two kinds of GUI are handled, both **generic** (keyed
only to what the loaded exe itself contains):

- **Dialog-template UIs** (installers, config dialogs). The window is built
  from the exe's `RT_DIALOG` resource — parsed control positions/classes/
  text, standard controls (button/edit/static/check/progress), and the
  default (`IDOK`)/cancel (`IDCANCEL`) buttons. Modeless (`CreateDialogParamW`)
  and modal (`DialogBoxParamW`) dialogs are both interactive; the dialog
  procedure receives `WM_INITDIALOG`, real `WM_COMMAND`s on clicks, control-
  text messages, and progress-bar updates (`PBM_*`).
- **Custom windows** (`RegisterClass` + `CreateWindowEx`). The window is
  bound to the app's own `WndProc`; the message loop delivers `WM_PAINT`
  then mouse input, `DispatchMessage` routes them to the `WndProc`, and a
  **GDI subset** (`BeginPaint`/`EndPaint`, `FillRect`, `Rectangle`,
  `TextOut`, `MoveTo`/`LineTo`, `SetPixel`, pens/brushes/colors) paints the
  client area. Try it: `exemu gui-sample /tmp/win.exe && exemu run --gui
  /tmp/win.exe`.

Without `--gui`, dialogs auto-drive headlessly (the default button is
"clicked" so batch runs proceed).

Limitations: the drawing is a plain software renderer (bitmap font, flat
fills), **not** Windows' native theme, GDI+, or DirectX; the GDI covers
solid fills/frames/text/lines, not bitmaps, regions, or advanced brushes.
Complex apps will hit unimplemented calls.

### Not implemented (yet)

AVX-512, FMA3, and AVX gather/mask-move instructions (AVX/AVX2 VEX-encoded ops
*are* implemented); native-themed / GDI+ / DirectX rendering (the
GDI is a solid-fill/text subset); **COM** object creation; **preemptive** threads
(the scheduler is cooperative — it yields at blocking points and on a timeslice,
not on true OS preemption); and **registry persistence to disk** (the `Reg*`
family round-trips through an in-memory hive with enumeration and seeded roots,
but the hive is not yet saved across runs).

**x64 exceptions work:** the `.pdata`/`.xdata` unwind tables are parsed,
`RtlCaptureContext`/`RtlLookupFunctionEntry`/`RtlVirtualUnwind`/`RtlUnwindEx`
are native, and `RaiseException` drives a real search-then-unwind dispatch that
walks the guest's frames and calls its own C++/SEH language handlers; a matching
catch resumes execution, an unmatched throw terminates like `std::terminate`.
(Still to come: the `_except_handler3`/`_except_handler4` dispatch step of 32-bit `fs:[0]` SEH — the `_EH_prolog` frame helper that builds the `EXCEPTION_REGISTRATION` frame is now native — and vectored exception handlers.)

### What real installers do today

These rows are not prose — they are the pins in `corpus.toml`, enforced by the
[corpus regression gate](#corpus-regression-gate). The numbers are what it
measures against a fresh sandbox with the
[deterministic clock](#deterministic-guest-clock) on, so they are exact rather
than approximate: the gate pins them with zero tolerance.

| Executable | Kind | Result |
| ---------- | ---- | ------ |
| **7-Zip installer** | 64-bit MSVC GUI | **installs end to end** — drives its dialog, "clicks" Install, decompresses its LZMA archive, writes all 107 files + registry, exits 0 (**496,505,572** instructions, 108 sandbox files) |
| **extracted `7z.exe`** | 64-bit console | **runs and prints its banner/usage** (`7-Zip 26.02 … Igor Pavlov`); `7z i` also runs |
| generated `hello.exe` | 64-bit console | **runs fully**, prints output incl. an SSE2 computation, exits 0 |
| Firefox Installer | 32-bit, UPX-packed | UPX self-decompresses, IAT reconstructed; the inner program runs CRT init + setup + SEH frame build + thread/sync init for **4,665,426** instructions, then calls through a NULL function pointer (`rip=0`) |
| SteamSetup | 32-bit NSIS | creates its temp dir, reads its own file, and decompresses/executes its archive for **92,865,377** instructions, then writes through a NULL pointer at `0x20001c2c` |
| tcc.exe | 32-bit console | dies after **728** instructions calling through a NULL returned by the `VerifyVersionInfoW`/`VerSetConditionMask` stub |

The last three are the *same* defect class, not three bugs: a stubbed Win32 API
returns NULL, the guest stores it as a pointer, and it faults far downstream —
728, 4.7M and 93M instructions later. They are pinned as **known-bad** so the
day the Wine path fixes them, the gate is what notices.

7-Zip is only an example — the same generic path drives any dialog-based
installer. With `--gui` you click Install in a real window (progress bar and
all); without it, the default button auto-drives so a self-extractor runs
its real extraction and writes its files to the host sandbox.

Extraction is compute-heavy (LZMA), so a real installer needs a raised step
budget: `exemu run --max-steps 800000000 installer.exe`. Files land under
`$TMPDIR/exemu-sandbox`.

> **Note on reproducing these numbers.** The sandbox **persists across runs**, and
> an installer enumerates and overwrites what is already there — so the
> instruction count genuinely shifts if you run the same binary twice without
> clearing `$TMPDIR/exemu-sandbox`. Clear it first if you want to reproduce a
> count exactly.

### Speed

The 7-Zip install above is ~4.97×10⁸ emulated instructions. Interpreted, that
takes **16–27 seconds** on an M-series Mac depending on the machine's load;
with `--jit` the *same run* — same instruction count, same output — takes about
**3 seconds**.

Interpreter speed was the next real wall, and the Wine path made it urgent
rather than academic: running Wine's own DLLs as guest code means every Win32
call is real PE code being interpreted, multiplying the instruction count per
app-visible action. The interpreter's measured hot spots (guest-memory region
lookup, per-byte instruction fetch, per-instruction hook dispatch) were removed
first; the block JIT below is the rest of the answer.

### Block JIT (`--jit`)

`exemu-jit` compiles guest **basic blocks** to native ARM64 and runs them
against the same register file and memory the interpreter uses. It is **opt-in**
(`--jit`, or `EXEMU_JIT=1`) and covers a deliberately small, measured slice of
the instruction set:

* integer ALU (`add`/`or`/`and`/`sub`/`xor`/`cmp`) in every operand form,
  group 1, `test`, `mov`, `lea`, `movzx`/`movsx`/`movsxd`, `imul`,
  constant-count `shl`/`shr`/`sar`, `inc`/`dec`, `neg`, `not`, `cmov<cc>`,
  `push`/`pop`, and `j<cc>`/`jmp` as compiled block terminators;
* **everything else side-exits to the interpreter** — every SSE/x87/AVX
  instruction, `syscall`, `call`/`ret`, the string ops, `adc`/`sbb`, the
  rotates, `mul`/`div`, the `LOCK`/`REP` prefixes. Deferring is always safe;
  compiling something whose flag semantics are not proven is not.

That slice was chosen by measuring, not guessing: an instrumented build
(`--opcode-profile`) counts every instruction shape a real run executes. On
7-Zip the top 20 shapes are 72% of the stream and the top 60 are 99.8%, and
they are almost entirely the shapes above — which is why a small compiler
covers **99.3%** of that run's instructions.

The JIT is required to be **bit-for-bit identical to the interpreter**, and
that is enforced two ways. A differential oracle
([below](#differential-cpu-oracle)) runs generated blocks through both engines
and compares the entire architectural state — every GPR, every `rflags` bit
including the ones x86 leaves undefined, `rip`, the vector file and every byte
of memory — at **0 divergences in 3.3M trials per bitness**. And every corpus
binary is run both ways: same exit code, same fault site, same artifacts, and
the same exact instruction count, with only the wall time different.

Two rules keep faults exact without any error plumbing in compiled code:
nothing is committed to guest state before a faulting access, and a faulting
access **rewinds** — `rip` goes back to the faulting instruction and the
*interpreter* re-executes it, raising the real error. Self-modifying code is
handled from the other side: a store into the running block's own bytes stops
the block, and between blocks the cache is validated against the per-page
code-generation counters, so an ordinary store into a PE section's data (which
exemu maps RWX) does not throw the cache away.

`crates/jit` is the **only** crate in the workspace that is not
`#![forbid(unsafe_code)]`, because a JIT cannot be. The relaxation is bounded:
four foreign declarations (`mmap`, `munmap`, `pthread_jit_write_protect_np`,
`sys_icache_invalidate`), an `unsafe` block per call with its precondition
stated above it, and `#![deny(clippy::undocumented_unsafe_blocks)]` to keep it
that way. The instruction encoder — where a codegen bug would actually live —
is ordinary safe Rust with no pointers in it. Compiled code reaches guest
memory only by calling back into the same `Memory` implementation the
interpreter uses, so a block cannot touch a host address the interpreter
could not.

**Packaging note:** the W^X code buffer uses `MAP_JIT`, which works for an
ad-hoc-signed binary but needs the `com.apple.security.cs.allow-jit`
entitlement once exemu ships as a notarized `.app` with the hardened runtime.

## Running on Wine's PE personality (`--wine-boot`)

Everything above is exemu's **hand-written** Windows personality — the default
path, and the one the corpus results describe. Alongside it exemu implements the
other half of the problem: the **NT kernel surface Wine's own builtin DLLs call
through**. Point `--wine-boot` at a directory of Wine's `x86_64-windows` PE
builtins and exemu boots *those* instead:

```sh
exemu run --wine-boot /path/to/wine/x86_64-windows hello.exe
exemu run --wine-boot /path/to/wine/x86_64-windows --gui app.exe   # native window
```

The division of labour is the point. Wine's `ntdll`, `kernelbase`, `kernel32`,
`ucrtbase`, `win32u`, `user32` and `gdi32` are **ordinary PE files that exemu
interprets as guest x86-64 code** — the same interpreter, no special-casing.
exemu supplies only what is genuinely below them:

* **The NT syscall boundary.** `KUSER_SHARED_DATA` at its fixed address, `SYSCALL`
  and the dispatcher page routed into a real **SSDT**: the dispatcher saves the
  Windows context into the TEB syscall frame, switches to a unix stack, calls the
  native handler, and restores. Memory, sections (`SEC_IMAGE`), files, threads,
  synchronization, registry and time are implemented as genuine `Nt*` services —
  including *real* blocking (a wait that cannot be satisfied rewinds the syscall
  and switches threads; there is no speculative `WAIT_OBJECT_0`).
* **ntdll's unixlib** — the 8-entry table reached via `__wine_unix_call`.
* **A wineserver-equivalent** — an in-process object manager speaking a
  `wine_server_call` protocol subset, with real cross-thread blocking.
* **A second SSDT for win32k** (`NtUser*`/`NtGdi*`) plus a display-driver seam, so
  Wine's user32/gdi32 render into a per-HWND BGRA surface exemu owns.
* **A from-scratch macOS display driver** — `NSWindow` + `CAMetalLayer`, an
  `NSEvent` tap feeding the guest's own `WndProc`, and a **CoreText** glyph
  rasterizer, with an interpreter/main-thread split so AppKit owns the window.

What is verified today:

| Capability | Status |
| ---------- | ------ |
| A console `.exe` runs to completion on Wine's real PE `kernel32`/`kernelbase`/`ucrtbase` | **works** — correct stdout, file-I/O round-trip, propagated exit code, none of exemu's emulated thunks used |
| A Win32 GUI app on Wine's `user32`/`gdi32`/`win32u` opens a **native macOS window** | **works** — real mouse/keyboard reach the guest `WndProc`; first frame pinned by a golden-PNG CI gate |
| Guest faults delivered as Windows exceptions | **works** — via `KiUserExceptionDispatcher`, resumed through `NtContinue` |
| **WoW64** (32-bit guests on the 64-bit Wine set) | **a 32-bit PE boots and reaches the NT layer through Wine's own thunks** — `exemu run --wine-boot <dir>` on a **PE32** builds a real WoW64 process (Wine's 32-bit `ntdll` + the 64-bit `ntdll`/`wow64`/`wow64cpu`/`wow64win`, dual PEB32/PEB64 and a TEB pair linked by `TEB64.WowTebOffset`), runs Wine's own `BTCpuProcessInit`, and enters the guest through `BTCpuSimulate`. A 32-bit `NtAllocateVirtualMemory` then travels Wine's own chain — the i386 ntdll's syscall stub → `__wine_syscall_dispatcher` → the `wow64cpu` BOP → `Wow64SystemServiceEx` → `wow64.dll`'s marshalling thunk → the 64-bit ntdll's `syscall` → exemu's SSDT — and the guest writes through the pointer it gets back. **exemu marshals nothing.** Gate: 1,292 instructions, exit code from the guest itself. **Not yet:** the win32k service table (`wow64win!sdwhwin32`) is unregistered, so a 32-bit **GUI** guest does not work; only `ntdll` imports are bound for the guest; Wine's own `Wow64LdrpInitialize`/32-bit `LdrInitializeThunk` are not run. Both gaps are pinned as tests |
| **comctl32 / uxtheme / comdlg32** | **arrive as guest code** — a sample that statically imports `comctl32!InitCommonControlsEx` runs to completion on the Wine boot, and Wine's own comctl32 registers `msctls_progress32` as a real window class. exemu implements no progress bar. user32's **built-in control classes** (`BUTTON`/`EDIT`/`STATIC`/…) are registered too: win32k recovers their WndProcs by following the `jmp qword [rip+disp32]` thunks in the client-PFN arrays user32 publishes at boot, so `CreateWindowExW(L"BUTTON", …)` reaches `NtUserCreateWindowEx`. One measured gap is pinned as a test: child windows do not paint yet |
| **COM** (`ole32` / `combase` / `oleaut32`) | **works** — `CoCreateInstance` genuinely succeeds: the CLSID resolves through exemu's registry to an `InprocServer32`, the in-proc server loads, and the guest calls a method through the returned vtable. No native COM in exemu; the emulated path is the control that proves it |
| **CAB extraction** (`cabinet`) | **works** — a guest extracts a real `.cab` through Wine's `FDICreate`/`FDICopy`, driven entirely by the guest's own FDI callbacks, and the bytes come back identical. exemu contributes a cabinet *writer* and no decoder, retiring the planned clean-room FDI |
| **shell32 / shlwapi** | **partly** — known folders resolve through Wine's own shell32, but the profile path comes back without its user component; the gap is pinned as a test |
| **TCP/UDP sockets** (`ws2_32`) | **works** — a guest exchanges bytes with a real host socket through Wine's `ws2_32`. A `SOCKET` is an NT file handle on `\Device\Afd`; every operation is one `NtDeviceIoControlFile`, serviced by exemu over real BSD sockets. Blocking is real: a receive against a silent peer waits and then delivers the actual bytes, never a premature zero-byte close. `AF_INET`/`AF_INET6` × `SOCK_STREAM`/`SOCK_DGRAM` only; name resolution (`getaddrinfo`) is still a stub |
| MSI / multimedia | **not yet** — `msi`/`setupapi` load and bind cleanly (their whole 33-module dependency closure is present), but nothing drives them end to end yet |

**exemu does not ship Wine's DLLs.** You point `--wine-boot` at a set you already
have. They are loaded as separate guest image files and are never linked or
transcribed into any exemu crate (Wine is LGPL-2.1-or-later); every native
backend here is written from public NT/PE specifications and Wine's published
architecture documentation.

## Testing

```sh
cargo test --workspace   # loader, memory, interpreter, and end-to-end
cargo clippy --workspace --all-targets
```

The interpreter has hand-assembled unit tests (arithmetic, loops, calls,
signed compares, division, `rep stos`, flags), and the app crate runs the
generated `.exe` through the entire pipeline and asserts on its output.

An NT-syscall **DLL-smoke** test (`crates/app/tests/dll_smoke.rs`) additionally
loads Wine's real PE `ntdll.dll` on its own and drives its own exported `Nt*`
stubs through the emulator's syscall dispatcher — proving a Wine-PE guest can
allocate memory, query the clock, open+write a file (bytes land on the host),
and create+wait an event, all via genuine `SYSCALL`s. It skips cleanly when the
(separately obtained, non-redistributed) Wine DLL set is absent.

### Corpus regression gate

`corpus.toml` at the repository root pins what each real installer in the test
corpus does — outcome, instruction count, where it stopped, and how many files
it wrote — and `exemu corpus` (or `crates/cli/tests/corpus_gate.rs`) runs them
and fails on drift. This is the harness that catches cross-thread / IPC /
integration regressions: the differential CPU oracle is single-stream and
structurally cannot see them.

```sh
cargo run  --release -p exemu-cli -- corpus            # the table
cargo run  --release -p exemu-cli -- corpus --update   # re-bless, reviewably
cargo test --release -p exemu-cli --test corpus_gate   # the gate (quick tier)
EXEMU_CORPUS=full cargo test --release -p exemu-cli --test corpus_gate
```

Three things make the counts reproducible, and all three are load-bearing:

* **A fresh sandbox per binary.** The guest filesystem sandbox
  (`$TMPDIR/exemu-sandbox`) persists and accumulates across runs, and an
  installer enumerates and overwrites what it finds there — so the same binary
  really does execute a different number of instructions against a dirty
  sandbox (7-Zip: 496,505,788 instructions/110 files against one, 496,505,786/115
  against another, 496,505,572/108 against a fresh one). Each entry therefore
  gets its own `TMPDIR`, deleted and recreated first. A count measured by a bare
  `exemu run` is not comparable to a pin.
* **A bare `argv[0]`.** The guest's command line is built into guest memory
  where the CRT parses it, so a longer path makes the guest execute more
  instructions (measured: 936 of them on Firefox Installer). Each binary is
  invoked by file name from its own directory, which keeps the counts a property
  of the emulator rather than of where the repo lives.
* **A virtual clock** (`virtual_clock = true` on an entry, below). Without it the
  emulator services the real host clock and a guest comparing two timestamps
  branches on host speed, so execution repeats only to about ±1 instruction —
  and, on the 93M-instruction SteamSetup run, to ±hundreds.

Tolerances follow from that. An entry on the **virtual clock** is pinned
*exactly* (`tolerance = 0`), because there is no host input left to jitter on.
An entry left on the host clock gets a noise floor instead of a change budget: a
clean **exit** is a completed trace and gets the bare 64-instruction floor, while
a **fault** pin's meaning is *where and why* it dies, so `rip` and the fault text
are compared exactly on both paths and only the "how far did we get" step count
gets ~0.1% slack. The corpus binaries are git-ignored third-party installers, so
a fresh checkout has none and the gate skips cleanly; it also skips on a debug
build, because the pins are release-measured.

**JIT twins.** Three entries (`jit = true`) run the same binary through the
[block JIT](#block-jit---jit) and are pinned to *exactly the interpreter
entry's numbers*, because the JIT is required to be bit-for-bit identical. Any
difference between a twin pair — one instruction, one artifact, a different
fault site — is a JIT bug, and catching it is the reason the pair exists. The
current table:

```
  PASS   7z2602-x64.exe                      exit 0            496,505,572     108   19.8s
  PASS   SteamSetup.exe                      fault @ 0x20001c2c 92,865,377       3    3.2s
  PASS   Firefox Installer.exe               fault @ 0x0         4,665,426       1    0.1s
  PASS   7z2602-x64.exe (jit)                exit 0            496,505,572     108    2.2s
  PASS   SteamSetup.exe (jit)                fault @ 0x20001c2c 92,865,377       3    1.4s
  PASS   Firefox Installer.exe (jit)         fault @ 0x0         4,665,426       1    0.1s
```

### Deterministic guest clock

`exemu run --virtual-clock` (or `EXEMU_VIRTUAL_CLOCK=1`) makes **every clock the
guest can read a function of the guest's own instruction stream**, so the same
binary executes the same number of instructions on every run and on every
machine. Off by default; the host-clock path is unchanged.

The model is one instruction = one 100-ns tick — a nominal **10M
instructions/second** machine — plus a fixed **2026-01-01T00:00:00Z** epoch. That
rate is not arbitrary: it is roughly what a release build actually interprets at,
so switching the clock on does not hand the guest a machine orders of magnitude
faster or slower than the one it was seeing, and it makes the units exact (the
performance counter already runs at 10 MHz, so *the QPC value is the instruction
count*, and a `FILETIME` is the epoch plus that count). A blocking `Sleep(ms)` is
credited the interval it asked for — it is a cooperative yield in exemu, so
without that a `Sleep`-paced timeout loop would have to grind out 10^4 iterations
per virtual millisecond to escape.

Everything guest-visible goes through it: `RDTSC`/`RDTSCP`, `GetTickCount(64)`,
`QueryPerformanceCounter`, `GetSystemTime(AsFileTime)`/`GetLocalTime`,
`NtQuerySystemTime`, `NtQueryPerformanceCounter`, the Wine-path
`RtlGetSystemTimePrecise` unix call, registry `LastWriteTime` stamps, and
`KUSER_SHARED_DATA`'s `SystemTime`/`InterruptTime`/`TickCount` — the last of
which the guest reads by *plain load* with no call to intercept, so the run loop
rewrites it every 65,536 instructions (6.55 ms of virtual time, finer than the
15.625 ms tick it is quantised to). **Not** virtualised: host filesystem
timestamps (`FindFirstFile`/`NtQueryDirectoryFile` report the real mtimes of real
files) and real socket timeouts, which are properties of the host world rather
than of the guest — both pinned as tests rather than left silent.

Measured through the corpus runner, the two binaries that used to wander:

| binary | host clock (3 runs) | virtual clock |
| --- | --- | --- |
| `Firefox Installer.exe` | 4,665,427 / 4,665,427 / 4,665,426 | 4,665,426 ×5 |
| `SteamSetup.exe` | 92,864,324 / 92,864,324 / 92,864,999 | 92,865,377 ×4 |

7-Zip still installs identically with it on (exit 0, 496,505,572 instructions,
108 artifacts — the same numbers as the host-clock pin). This is also the
prerequisite for the planned JIT-vs-interpreter differential, which can only diff
two engines instruction-for-instruction if a run replays exactly.

A **golden-image gate** (`gui_gate.rs`) pins the GUI sample's first painted frame
against a committed PNG so any pixel drift in the GDI paint path fails CI; it
renders headlessly through the deterministic offscreen presenter, and
`EXEMU_BLESS=1` re-blesses the golden after an intended rendering change.

**Running on Wine's real PE core (experimental, opt-in).** A **console `.exe`
runs to completion on Wine's own PE `ntdll` → `kernelbase` → `kernel32` →
`ucrtbase`**, running natively on the software CPU. With the Wine DLL set present
and the boot enabled (`RunConfig.wine_boot_dir`, or `EXEMU_WINE_BOOT=1` on the
CLI), the emulator maps ntdll + the exe, hands off through
`LdrInitializeThunk`, and Wine's own loader loads the rest as real image
sections, relocates them, and runs their `DllMain`s. The program's `WriteFile`
then runs Wine's kernel32 → `NtWriteFile` → the emulator's console bridge → host
stdout, and it exits 0 — none of the emulator's hand-written Win32 stubs are
used. The `crates/app/tests/wine_gate.rs` gate pins this end to end — including a
program that drives a full **file-I/O round-trip** (`CreateFileA` → `WriteFile` →
`ReadFile`) through Wine's kernel32 onto the host filesystem and then propagates a
**non-zero exit code** (`ExitProcess(42)` → Wine's `NtTerminateProcess`). GUI programs
now cross Wine's `win32u` syscall layer too: a generated Win32 sample runs its
`RegisterClass` → `CreateWindowEx` → `ShowWindow` → message loop to a clean exit
through Wine's **real `user32`/`gdi32`**, with the emulator's win32k backend
marshalling the actual class/title/geometry into real window objects and pushing
create/show/resize/destroy through a native display-driver seam
(`crates/app/tests/gui_gate.rs`). And the first pixels are real: the emulator
publishes the GDI shared handle table Wine's `gdi32` demands (at `PEB+0xF8`),
gives every window a guest-mapped BGRA backing surface, and services the
`NtGdiExtTextOutW`/`NtGdiRectangle` syscalls `gdi32` lowers `TextOutW`/
`Rectangle` into — so the sample's first frame (text + rectangle, drawn by
Wine's real GDI stack) renders headlessly to PNG. Text is rendered with **real
fonts**: `NtGdiExtTextOutW` asks the display driver to rasterize the run with
**CoreText** (proportional, anti-aliased Helvetica glyphs) and composites the
alpha coverage into the DIB, falling back to a built-in bitmap font only when no
CoreText backend is present (headless CI). Those pixels now reach a real
window: a from-scratch macOS presenter (`crates/gui/src/cocoa.rs`, `objc2`) gives
each top-level window an **NSWindow + CAMetalLayer** and blits the BGRA surface
into it via Metal — a real GPU round-trip verified pixel-lossless and byte-for-
byte at parity with the headless PNG path. And it is wired to *guest* windows:
`exemu run --gui --wine-boot <dir> <app.exe>` runs the interpreter on a spawned
thread while the main thread owns AppKit, so the window a Wine-hosted guest opens
with `CreateWindowEx` appears as a native `NSWindow` and shows what the guest
paints — no deadlock. And the window now **stays live**: the guest blocks in its
message loop (`GetMessage` parks the interpreter thread on a native input channel
instead of busy-spinning), the window stays on screen, and closing it delivers a
`WM_QUIT` so the guest exits cleanly. Messages now reach the guest's own
`WndProc`: `GetMessage` synthesizes the shown window's initial `WM_PAINT` and
`DispatchMessage` (Wine's real `user32` → `NtUserDispatchMessage`) invokes the
guest procedure, whose `WM_PAINT` arm repaints through `BeginPaint`/`Rectangle`/
`TextOutW`/`EndPaint` — a second, on-demand frame drawn by the app itself. And it
is now **interactive**: a main-thread `NSEvent` tap translates real mouse and
keyboard input into `WM_MOUSEMOVE`/`WM_LBUTTONDOWN`/`WM_KEYDOWN`/… and posts them
to the guest's message queue, which `DispatchMessage` (via `NtUserMessageCall`,
the syscall Wine actually lowers input messages into) routes to the `WndProc` —
so clicking the window makes the guest repaint. The cursor and display members
are serviced too: `GetCursorPos` reports the tracked pointer position (so the app
knows where it was clicked), `SetCursor`/`SetCursorPos`/`ClipCursor` are honoured,
and `EnumDisplaySettings`/`ChangeDisplaySettings` present a single 1920×1080
monitor. `exemu cocoa-demo` still opens the same presenter directly with a test
frame.

### Differential CPU oracle

The software CPU is validated against a reference x86 (Unicorn / QEMU TCG) by
the dev-only `exemu-oracle` crate. It seeds identical state into exemu and
Unicorn, single-steps one generated instruction in each, and diffs the
registers, defined status flags, and touched memory — across the integer ALU,
shift/rotate, multiply/divide, bit, and REP string families in both 32- and
64-bit mode. It runs millions of trials to `ZERO DIVERGENCE`:

```sh
# The `unicorn` feature builds a bundled C library (needs cmake); off by
# default, so the normal workspace build and CI never require it.
cargo run -p exemu-oracle --features unicorn --release -- fuzz --bits both --count 2M
```

A second differential answers the other question — **is the JIT the same
machine as the interpreter?** — and needs no reference emulator, so it runs in
the ordinary `cargo test --workspace` gate. Because the reference *is* the
interpreter there is no defined-flags policy: every bit of every GPR, `rflags`,
`rip`, the XMM/YMM/x87 files and every byte of guest memory must match exactly.
It also checks that a block the compiler declines leaves the state completely
untouched, and that a block which faults really did rewind onto an instruction
that faults on the interpreter (a *spurious* fault is invisible in a state diff
but means an address is being computed wrongly).

```sh
cargo run -p exemu-oracle --release -- jit --bits both --count 1M --chain 8
```

Current result: **0 divergences in 3.3M trials per bitness** across four
configurations (1, 8 and 32 instructions per block; four seeds).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). All
contributors sign the [Contributor License Agreement](CLA.md) (a one-comment
step handled automatically by a bot on your first pull request).

## License

exemu is licensed under the **PolyForm Noncommercial License 1.0.0** — see
[LICENSE.md](LICENSE.md).

- **Noncommercial use is free** — personal, research, hobby, education, and other
  noncommercial purposes.
- **Commercial/production use requires a separate license** from the owner.
  Enquiries: jan@janduszynski.pl

Contributions are accepted under the [Contributor License Agreement](CLA.md),
which keeps the owner as the sole rights-holder able to license, relicense, and
commercialize exemu (see [CONTRIBUTING.md](CONTRIBUTING.md)).

