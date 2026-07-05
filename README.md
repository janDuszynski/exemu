# exemu — a Windows `.exe` emulator for Apple Silicon

**Version 0.0.1** (foundation / bring-up) — see [CHANGELOG.md](CHANGELOG.md).
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
> set (including SSE2), ~200 Win32 functions, a host-backed sandbox
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
* `sample` writes the built-in Hello-World PE to disk.

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
  (`MOVS`/`STOS`/`CMPS`/`LODS`/`SCAS` with `REP`/`REPE`/`REPNE`), and
  **SSE/SSE2** (moves, logical, scalar+packed float arithmetic, compares and
  conversions) — all with faithful EFLAGS. `CPUID` reports an honest feature
  set (only the instructions actually implemented), so CRTs dispatch onto code
  paths the interpreter can execute rather than into AVX it cannot.
* **~200 Win32 functions** across `kernel32`/`user32`/`gdi32`/`advapi32`/
  `shell32`/`ole32`/`comctl32`: console I/O, the `Heap*`/`Global*`/`Virtual*`
  allocators, the `lstr*` string family, `CharNext`/`CharPrev`, command
  line, module handles, and timing/console stubs. Every function — even the
  unimplemented ones — carries its **stdcall argument count**, so 32-bit
  callee stack cleanup stays correct and stub calls don't corrupt the stack.
  Handle-returning stubs yield a non-null fake handle so setup proceeds.
* A **host-backed sandbox filesystem**: `CreateFileW`/`ReadFile`/`WriteFile`/
  `CloseHandle`, `CreateDirectoryW`, `GetTempPathW`/`GetTempFileNameW`,
  `GetFileSize`/`SetFilePointer`/`GetFileAttributesW`/`DeleteFileW`, and
  `GetModuleFileNameW`. Guest paths map into a sandbox dir; the executable is
  copied in so a self-extractor can read its own appended archive.
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

AVX and x87 floating point; native-themed / GDI+ / DirectX rendering (the
GDI is a solid-fill/text subset); TLS callbacks and base relocations (images
load at their preferred base); real threads; **COM** object creation; and the
registry (Reg* calls are stubbed).

**x64 exceptions work:** the `.pdata`/`.xdata` unwind tables are parsed,
`RtlCaptureContext`/`RtlLookupFunctionEntry`/`RtlVirtualUnwind`/`RtlUnwindEx`
are native, and `RaiseException` drives a real search-then-unwind dispatch that
walks the guest's frames and calls its own C++/SEH language handlers; a matching
catch resumes execution, an unmatched throw terminates like `std::terminate`.
(Still to come: 32-bit `fs:[0]` SEH and vectored exception handlers.)

### What real installers do today

| Executable | Kind | Result |
| ---------- | ---- | ------ |
| **7-Zip installer** | 64-bit MSVC GUI | **installs end to end** — drives its dialog, "clicks" Install, decompresses its LZMA archive, writes all 107 files + registry, exits 0 (~496M instructions) |
| **extracted `7z.exe`** | 64-bit console | **runs and prints its banner/usage** (`7-Zip 26.02 … Igor Pavlov`); `7z i` also runs |
| generated `hello.exe` | 64-bit console | **runs fully**, prints output incl. an SSE2 computation, exits 0 |
| Firefox Installer | 32-bit, UPX-packed | runs its ~2.2M-instruction self-decompression stub to a clean exit |
| SteamSetup | 32-bit NSIS | creates its temp dir, reads its own file, and decompresses/executes its archive for ~45M instructions before a fault deep in unpacked code |

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

## License

MIT
