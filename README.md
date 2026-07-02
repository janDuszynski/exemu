# exemu — a Windows `.exe` emulator for Apple Silicon

`exemu` loads a Windows **PE** (Portable Executable) `.exe` built for
`x86-64` and runs it on an Apple **M-series** (ARM64) Mac — no Windows, no
Rosetta, no virtual machine. It parses the executable, maps it into a
virtual address space, interprets the guest's x86-64 instructions in
software, and services the Windows API calls the program makes by
implementing them natively on the host.

It is written in **Rust** for speed and memory safety, and organized with
**Clean Architecture** so each concern (parsing, memory, CPU, OS) is an
independent, testable crate behind a trait.

> **Scope.** This is a from-scratch userland emulator built for clarity and
> extensibility. It implements a practical subset of the x86-64 instruction
> set and a handful of `kernel32` APIs — enough to load and run real
> freestanding console programs end to end. It is not a drop-in replacement
> for Wine, and it does not emulate the NT kernel, the GUI, or the .NET CLR.

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

* PE32+ parsing: headers, sections, and imports (by name or ordinal).
* A practical subset of x86-64: the ALU family, `MOV`/`LEA`/`MOVZX`/`MOVSX`,
  stack ops, `CALL`/`RET`, the full `Jcc`/`SETcc`/`CMOVcc` condition set,
  shifts/rotates, `MUL`/`IMUL`/`DIV`/`IDIV`, `REP MOVS`/`STOS`, with
  faithful EFLAGS.
* `kernel32` essentials: `GetStdHandle`, `WriteFile`, `WriteConsoleA/W`,
  `ExitProcess`, the `Heap*`/`Virtual*` allocators, `GetCommandLine*`,
  `GetModuleHandle*`, plus last-error/console/timing stubs. Unknown imports
  return 0 (optionally traced) so a program keeps running.
* **Data imports** (a DLL exporting a variable, not a function). The thunk
  region is mapped as real read/write memory, so the C runtime can
  dereference globals like `_fmode`/`_commode`; `_acmdln`/`_wcmdln` are
  seeded with the command line.
* A slice of the **`msvcrt` C runtime**: `malloc`/`calloc`/`realloc`/`free`,
  `memcpy`/`memmove`/`memset`/`memcmp`/`strlen`, the `exit` family,
  `__getmainargs`, and no-op startup hooks (`__set_app_type`, `_initterm`,
  `_controlfp`, …). Enough that MSVCRT-linked binaries get through CRT
  startup and into their own `main`.

### Not implemented (yet)

SSE/AVX and x87 floating point; TLS callbacks and base relocations (images
load at their preferred base); table-based structured exception handling
(`.pdata`/`__C_specific_handler` is a no-op); C++ static initializers
(`_initterm` is skipped, since servicing it would require re-entrant guest
calls); threads; and the Win32 **GUI**, **COM**, registry and shell surfaces
(`user32`/`ole32`/`advapi32`/`shell32`).

As a concrete data point, the 7-Zip GUI installer (`7z…-x64.exe`, MSVC +
`msvcrt`) now executes ~49k instructions of real CRT and program code before
stopping at `user32!CreateDialogParamW` — i.e. at the GUI boundary rather
than in the C runtime. A **console** MSVCRT program that avoids SSE and SEH
stands a good chance of running; a GUI/COM application does not.

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
