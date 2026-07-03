# exemu — a Windows `.exe` emulator for Apple Silicon

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
> set (including SSE2), ~200 Win32 functions, and a host-backed sandbox
> filesystem — enough to run real console programs end to end and to drive
> real installers a long way into their logic. It is **not** a drop-in
> replacement for Wine: it does not render a GUI, and it does not emulate
> the NT kernel, COM, or the .NET CLR, so graphical installers run their
> startup and extraction but cannot present their wizard.

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
exemu run <file.exe> [--trace] [--no-echo] [-- <args>...]
exemu info <file.exe>
exemu sample <out.exe>
```

* `run` maps the image, resolves imports, and interprets it to completion,
  exiting with the guest's exit code. `--trace` logs calls to unimplemented
  Windows APIs; `--no-echo` suppresses mirroring guest output to the host.
* `info` dumps headers, sections and imports.
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
  stack ops, `CALL`/`RET`, the full `Jcc`/`SETcc`/`CMOVcc` condition set,
  shifts/rotates, `SHLD`/`SHRD`, `MUL`/`IMUL`/`DIV`/`IDIV`, the `BT` bit-test
  family, `BSF`/`BSR`/`BSWAP`, `XADD`/`CMPXCHG`, `LOOP`/`JECXZ`, the string
  ops (`MOVS`/`STOS`/`CMPS`/`LODS`/`SCAS` with `REP`/`REPE`/`REPNE`), and
  **SSE/SSE2** (moves, logical, scalar+packed float arithmetic, compares and
  conversions) — all with faithful EFLAGS.
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

### Not implemented (yet)

AVX and x87 floating point; TLS callbacks and base relocations (images load
at their preferred base); table-based structured exception handling
(`.pdata`/`__C_specific_handler` is a no-op — fine unless an exception is
actually thrown); real threads; a **rendering GUI** and a real window
message loop; **COM** object creation; and the registry (Reg* calls are
stubbed).

### What real installers do today

| Executable | Kind | Result |
| ---------- | ---- | ------ |
| **7-Zip installer** | 64-bit MSVC GUI | **installs end to end** — drives its dialog, "clicks" Install, decompresses its LZMA archive, and writes all 107 files (validated: `7z.exe` is a real PE, `readme.txt` the genuine text) + registry, exits 0 (~496M instructions) |
| generated `hello.exe` | 64-bit console | **runs fully**, prints output incl. an SSE2 computation, exits 0 |
| Firefox Installer | 32-bit, UPX-packed | runs its ~2.2M-instruction self-decompression stub to a clean exit |
| SteamSetup | 32-bit NSIS | creates its temp dir, reads its own file, and decompresses/executes its archive for ~45M instructions before a fault deep in unpacked code |

exemu drives a real GUI installer's dialog procedure (via a re-entrant
guest-call mechanism) — invoking `WM_INITDIALOG` and a synthetic Install
click, round-tripping control text, and pumping a bounded message loop — so
a self-extracting installer runs its real extraction and writes its files to
a host sandbox. It still does **not render** a window or handle arbitrary
user interaction; the Install path is driven automatically.

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
