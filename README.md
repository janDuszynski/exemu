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
> set (through SSE4.2 plus AVX/AVX2), ~200 Win32 functions, a host-backed sandbox
> filesystem, and a lightweight **window + GDI renderer** — enough to run
> real console programs end to end and to drive real GUI apps (`--gui`)
> interactively, both dialog-template UIs and custom `CreateWindowEx`
> windows. It is **not** a drop-in replacement for Wine: it does not emulate
> the NT kernel, COM, or the .NET CLR, and its rendering is a software
> subset (solid fills, frames, text, lines) — **not** Windows' native
> theming, GDI+, or DirectX — so visually complex apps hit unimplemented
> drawing calls.

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
       │ loader │  │ memory  │  │  cpu  │   │    os    │   (infrastructure)
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
exemu run <file.exe> [--trace] [--no-echo] [--telemetry <path>] [-- <args>...]
exemu info <file.exe>
exemu opcodes [--telemetry <path>] [--clear]
exemu sample <out.exe>
exemu gui-sample <out.exe>
exemu cocoa-demo [--size WxH] [--hold SECS]
```

* `run` maps the image, resolves imports, and interprets it to completion,
  exiting with the guest's exit code. `--trace` logs calls to unimplemented
  Windows APIs; `--no-echo` suppresses mirroring guest output to the host.
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
  `RDTSC`/`RDTSCP` (monotonic counter; `RDTSCP` reports `TSC_AUX`=0 for the
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
  - **Host-clock time:** `GetTickCount(64)`, `QueryPerformanceCounter/
    Frequency`, `GetSystemTimeAsFileTime`, `GetSystemTime`/`GetLocalTime`.
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

| Executable | Kind | Result |
| ---------- | ---- | ------ |
| **7-Zip installer** | 64-bit MSVC GUI | **installs end to end** — drives its dialog, "clicks" Install, decompresses its LZMA archive, writes all 107 files + registry, exits 0 (~496M instructions) |
| **extracted `7z.exe`** | 64-bit console | **runs and prints its banner/usage** (`7-Zip 26.02 … Igor Pavlov`); `7z i` also runs |
| generated `hello.exe` | 64-bit console | **runs fully**, prints output incl. an SSE2 computation, exits 0 |
| Firefox Installer | 32-bit, UPX-packed | UPX self-decompresses, IAT reconstructed; the inner program runs CRT init + setup + SEH frame build + thread/sync init for ~4.7M instructions before a fault deep in unpacked code |
| SteamSetup | 32-bit NSIS | creates its temp dir, reads its own file, and decompresses/executes its archive for **~93M instructions** (more than double the pre-0.0.2 reach) before a fault deep in unpacked code |

7-Zip is only an example — the same generic path drives any dialog-based
installer. With `--gui` you click Install in a real window (progress bar and
all); without it, the default button auto-drives so a self-extractor runs
its real extraction and writes its files to the host sandbox.

Extraction is compute-heavy (LZMA), so a real installer needs a raised step
budget: `exemu run --max-steps 800000000 installer.exe`. Files land under
`$TMPDIR/exemu-sandbox`.

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
Wine's real GDI stack) renders headlessly to PNG. Those pixels now reach a real
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
`TextOutW`/`EndPaint` — a second, on-demand frame drawn by the app itself. What's
left to make it fully interactive: native mouse/keyboard events (`NSEvent` → the
guest's message queue) so those `WndProc` dispatches carry real input (W4.6).
`exemu cocoa-demo` still opens the same presenter directly with a test frame.

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

