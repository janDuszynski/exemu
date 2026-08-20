# Changelog

exemu loads a Windows PE (32- or 64-bit) and runs it natively on Apple Silicon
— no Windows, no Rosetta, no VM. Versions before 1.0 track **capability**, not
API stability: `0.0.x` is the pre-GUI foundation, `0.1.0` will be the first real
interactive native window, and `1.0.0` is the notarized product. A version
advertises only what is actually implemented.

## Unreleased — the Wine personality (W0–W5)

A change of *means*, not of goal. Up to v0.0.4 exemu re-implemented the Windows
personality by hand — kernel32, USER32, GDI, one function at a time. It now
**boots Wine's own PE builtin DLLs (`ntdll`, `kernelbase`, `kernel32`,
`ucrtbase`, `win32u`, `user32`, `gdi32`, …) as ordinary emulated x86-64 guest
code**, and implements natively in Rust only the small, well-defined *unix side*
of Wine's PE/Unix boundary: the NT syscall surface, ntdll's unixlib, a
wineserver-equivalent object manager, the win32u backend, and a from-scratch
macOS display driver.

The hand-written personality is **still the default path** and is unchanged; the
Wine path is opt-in via `exemu run --wine-boot <dir>` (or `EXEMU_WINE_BOOT`).
Wine's DLLs are loaded as separate guest image files, never linked or transcribed
into any exemu crate (LGPL-2.1-or-later invariant); every native backend is
written from public NT/PE specs and Wine's published architecture docs.

Tests grew 199 → 496, clippy clean at `-D warnings`; 7-Zip still installs
end-to-end on the default path.

### Interpreter performance (W8.1)
- **7-Zip installs in 27.5 s instead of ~65 s — 2.4× faster, with byte-identical
  behaviour.** Proven by A/B-ing the pre- and post-change binaries against the
  *same* sandbox state: both execute exactly 496,505,786 instructions. (That
  figure is a dirty-sandbox count; the fresh-sandbox pin is 496,505,572 — see
  the corpus-gate section. What matters here is that the two binaries agree.)
- Profile-driven, not guesswork: sampling the 496M-instruction run showed the
  **guest-memory path taking ~51% of the total**. Three fixes: every access was
  resolving its region *twice* (`locate` searched, discarded the reference, then
  `read`/`write` searched again); `EmuError::Unmapped` was constructed *eagerly*
  on every successful access via `ok_or`; and instruction decode issued one
  `Memory::fetch` **per byte** — a dynamic dispatch, region lookup and permission
  test each time. Decode now takes a single 16-byte window (x86-64 caps an
  instruction at 15 bytes), falling back to the per-byte path when the window
  cannot be fetched.
- **The boundaries the oracle structurally cannot see are pinned directly.** The
  differential fuzzer assembles every trial at the base of a 4 KiB page with one
  region per purpose, so the prefetch window always fits and the region cache is
  never stale. Explicit tests cover an instruction ending exactly at a region's
  last byte, an 11-byte `movabs` straddling the window-to-slow-path transition,
  an immediate lying in a readable-but-not-executable neighbour (which must still
  fault — the prefetch must not paper over a real fetch fault), and a `map` that
  shifts every region index under a warm cache entry.
- A separate win: `Hooks::intercept` runs before every guest instruction and led
  with a hash lookup on `rip`. Thunk addresses are allocated strictly linearly
  from a known base, so a range compare is *equivalent* to the lookup — turning
  ~5×10⁸ hashes into ~5×10⁸ predictable compares.
- `#![forbid(unsafe_code)]` is preserved throughout; relaxing it is a separate,
  later step scoped to a dedicated codegen crate.

### Licensing compliance is now mechanical (W9.1)
- **A CI licence gate**, deliberately split in two: `deny.toml` covers the
  *shipping closure* with **zero licence exceptions**, so "no copyleft in what we
  distribute" is a checked claim rather than a promise; `deny.dev.toml` covers the
  full graph and records the single exception — `unicorn-engine` is GPL-2.0 and is
  admissible only because it sits behind the differential oracle's off-by-default
  feature in a `publish = false` crate. If Unicorn ever leaks into the
  default-feature graph, the shipping policy fails with nothing to hide behind.
- **A reproducible SBOM** plus a mechanical **separability check** — the central
  diligence claim is that no Wine code is in exemu's compiled output, and that is
  now asserted by CI (verified against the real release binary: it links only
  Apple system frameworks plus `libSystem`/`libiconv`/`libobjc`).
- `docs/COMPLIANCE.md` — the LGPL redistribution checklist, explicitly marked as
  requiring review by counsel before any release.
- **Two findings recorded rather than smoothed over:** (1) `THIRD_PARTY_LICENSES`
  does not exist, so **any binary distribution of exemu today already fails its
  own permissive dependencies' notice requirements — independently of Wine**;
  (2) whether the project's chosen licence satisfies LGPL-2.1 §6 is a live
  question for counsel, not something the tooling can settle.

### CPU coverage for Wine's own binaries (W1)
- **x87 FPU**: ST0–ST7 with real 80-bit storage, control/status/tag words, the
  load/store/arithmetic/compare families, `FSQRT`/`FSCALE`/`FPREM`/`FRNDINT`, the
  transcendentals, and the `fnstsw ax`→`jcc` idiom.
- **`FXSAVE`/`FXRSTOR`** with the full 512-byte SDM layout (incl. abridged-FTW
  re-expansion) and **`XSAVE`/`XRSTOR`/`XGETBV`/`XSETBV`** over the x87+SSE+AVX
  state components.
- **`CPUID` honesty**: a machine-checked invariant that every advertised feature
  bit has a probe instruction the interpreter actually executes — so Wine never
  dispatches onto a path exemu cannot run.
- **SSSE3 / SSE4.1 / SSE4.2** (`0F 38`/`0F 3A`) incl. `PCMPESTR`/`PCMPISTR` with
  full `imm8` semantics, and `CRC32`.
- **AVX / AVX2 via VEX** (`0xC4`/`0xC5`): a 256-bit `YMM0`–`YMM15` file with
  correct VEX.128 zero-upper vs legacy-SSE preserve semantics.
- **BMI1/BMI2/ADX/F16C**, `CMPXCHG16B`, and the bare-form **MMX** register file
  aliased onto the physical x87 stack.
- **Self-modifying-code seam**: per-page generation counters on writes into
  executable memory — the invalidation hook a future JIT code cache consumes.
- Each family landed only after a **new differential-oracle category** diffed it
  against Unicorn; a Wine-`ntdll` `.text` decode sweep gates against whole-family
  decode regressions.

### The PE/Unix boundary (W2)
- `KUSER_SHARED_DATA` at its fixed `0x7ffe0000`, and `SYSCALL` / the fixed
  dispatcher page routed to an **NT syscall dispatcher**: save the Windows context
  into the TEB syscall frame, switch to a unix stack, index the SSDT, call the
  native handler, restore and return.
- **`__wine_unix_call`** fast path and ntdll's 8-entry **unixlib**
  (`load_so_dll`, `unwind_builtin_dll`, `wine_dbg_write`, `wine_server_call`,
  `server_fd_to_handle`, `server_handle_to_fd`, `spawnvp`, `system_time_precise`).
- Native `Nt*` services: **memory** (`NtAllocate/Free/Protect/QueryVirtualMemory`
  with `MEM_IMAGE`/`MEM_MAPPED`), **sections** (`SEC_IMAGE` file-backed images for
  Wine's own PE loader), **files** (`IO_STATUS_BLOCK` + `OBJECT_ATTRIBUTES` +
  `UNICODE_STRING` + the `\??\` namespace), **threads/process**, **synchronization**
  (with *real* blocking via syscall rewind — no speculative `WAIT_OBJECT_0`),
  **registry** (`\Registry\` namespace onto the existing hive, with the full
  buffer-too-small protocol), and **time**.
- A complete Wine-walkable **TEB (~0x1838) and PEB (~0x7C8)** per thread.
- A **wineserver-equivalent**: an in-process object manager speaking a
  `wine_server_call` protocol subset, with real cross-thread blocking.
- The `LOCK` prefix is honored, pinned by a cross-thread `lock cmpxchg` test.

### A real Wine process (W3)
- The **`LdrInitializeThunk` handoff** and `NtContinue`, the bootstrap Wine's
  ntdll expects; `PEB.ApiSetMap`, a full `RTL_USER_PROCESS_PARAMETERS`, the NLS
  data mapping, and the per-thread debug-string ring Wine's tracing writes to.
- A **console bridge** (`NtWriteFile` → host stdio) and a **hardware→software
  exception bridge** that delivers guest faults through
  `KiUserExceptionDispatcher` and resumes via `NtContinue`.
- **GATE:** a console `.exe` runs to completion on **Wine's real PE
  kernel32/kernelbase/ucrtbase** — correct stdout, file-I/O round-trip, and a
  propagated non-zero exit code — with none of exemu's emulated API thunks used.

### The first Wine-rendered window (W4)
- A **second SSDT** for win32k (`NtUser*`/`NtGdi*`) and a `UserDriver`/`Presenter`
  seam: Wine's user32/gdi32/win32u run as guest code and push real
  `CreateWindowEx`/`ShowWindow` calls through an injected display driver.
- A per-HWND **guest-mapped BGRA surface** plus the GDI handle table at `PEB+0xF8`,
  so Wine's own gdi32 renders into a DIB exemu owns.
- **`CocoaPresenter`**: a real `NSWindow` + `CAMetalLayer` blit path, with an
  interpreter/main-thread split so AppKit owns the window and the interpreter
  posts over a channel — guest windows appear as **native macOS windows**.
- An **`NSEvent` tap** feeding real mouse/keyboard into the guest's own `WndProc`,
  and a **CoreText glyph rasterizer** (real fonts in the DIB, not a bitmap font).
- **PNG golden-image CI gate**: pixel drift in the sample's first frame fails CI.

### WoW64 — 32-bit guests on the 64-bit Wine set (W5, in progress)
- The **CS-selector mode switch**: far indirect `jmp m16:32/m16:64` and `iretq`
  now switch the interpreter between 64-bit long mode and 32-bit compat mode —
  the primitive Wine's WoW64 is built on. PE32 loader coverage pinned.
- A **WoW64 process model** module: the CPU-reserved area at `TEB+0x1488` and the
  `WOW64_CONTEXT` layout `wow64cpu!BTCpuSimulate` reads.
- The pinned `wow64cpu.dll` is driven **through its own bytes**: the real
  `BTCpuProcessInit` builds the 32→64 return BOP (recovered by *running* it — the
  slot is `.bss`, zero-filled statically), and the real `BTCpuSimulate` switches
  into a 32-bit guest on both its forward paths.
- **Full WoW64 syscall round trip** on wow64cpu's own code: a 32-bit guest calls
  the init-built BOP → the 64-bit return handler saves the 32-bit context and
  dispatches → the guest resumes with the result.
- **A 32-bit guest reaches the real NT syscall table** through Wine's *own*
  `wow64.dll`: `Wow64Transition` → BOP → wow64cpu's return handler →
  `Wow64SystemServiceEx` → wow64.dll's per-service marshalling thunk →
  `ntdll` → exemu's SSDT → back. **exemu marshals nothing** — the 32→64
  argument conversion is Wine's job, done in guest code, which is the whole
  point of the new-WoW64 model. Verified for `NtQuerySystemTime` (a live
  FILETIME bracketed against the host clock) and `NtAllocateVirtualMemory`.
  The pinned Wine set contains no 32-bit `ntdll`, so the 32-bit caller is a
  synthesized stub of the documented shape: this pins the mechanism, not
  Wine's own 32-bit ntdll bytes.
- **Bug found by that work:** exemu ignored `NtAllocateVirtualMemory`'s
  `ZeroBits`, and its allocation arena starts well above 4 GiB — so a WoW64
  guest was handed a truncated, unmapped base. Now honoured.
- *Still to come:* loading wow64 into a real process boot.

### Sockets — Wine's ws2_32 reaches real BSD sockets (W7.1)
- **A guest exchanges bytes with a real host socket.** A generated program calls
  Wine's `ws2_32` to connect to a loopback listener the test itself creates,
  sends 61 bytes and receives a 52-byte reply byte for byte. Hermetic — the
  listener binds `127.0.0.1:0`, the port is baked in per run, no external host,
  passes offline. The emulated path is the control: `SOCKET=0`, `SENT=0`,
  `RECVD=0`.
- **The boundary was recovered from the binary before anything was implemented,**
  and `afd_abi.rs` re-derives every fact from the pinned `ws2_32.dll`/`ntdll.dll`
  on each run, so a wrong constant fails there rather than three layers down. A
  `SOCKET` is an NT file handle (`NtOpenFile` on `\Device\Afd`); every operation
  is one `NtDeviceIoControlFile` (SSDT 0x07).
- **The trap that pinning caught:** AFD control codes use *two* encodings — the
  operations Windows' own AFD defines shift `FILE_DEVICE_NETWORK` by 12
  (`0x0001_2xxx`), while the ones Wine adds for itself, all numbered above 200,
  use the ordinary `CTL_CODE`'s 16 (`0x0012_0xxx`). Neither formula produces the
  other block. The first draft used one shift for both, and the ABI test caught
  it before an implementation existed.
- **Blocking is real, not speculative.** A receive against a peer that stays
  silent for 300 ms waits and then delivers the actual bytes — never a premature
  zero-byte "graceful close". On would-block the handler rewinds the `SYSCALL`
  exactly as `NtWaitForSingleObject` does and yields.
- **Structural finding: Wine's PE builtins are *halves*.** `ws2_32`'s `DllMain`
  does nothing but `NtQueryVirtualMemory(MemoryWineUnixFuncs)` and returns that
  status as its `BOOL` — so without a registered unix side the DLL does not load
  at all, and the first end-to-end attempt died with `STATUS_DLL_INIT_FAILED`
  before a single socket call. Since every builtin except ntdll is mapped by
  Wine's own loader running as guest code, there is no load event to register
  against; exemu now pairs a builtin with its unix side at the moment the PE
  half asks, identifying the module from its mapped export directory.
- Scope is deliberate: `AF_INET`/`AF_INET6` × `SOCK_STREAM`/`SOCK_DGRAM` only,
  everything else refused with `STATUS_NOT_IMPLEMENTED`. Address policy has a
  single choke point for the future sandbox model. Name resolution is five
  honest stubs returning `WSAHOST_NOT_FOUND` — the pinned binary shows that
  handle is read by exactly five call sites, all name resolution, none on the
  socket path.

### COM arrives as guest code (W6.3 / W6.4)
- **`CoCreateInstance` genuinely succeeds on Wine's COM core.** A generated
  console program calls `CoInitializeEx` → `CoCreateInstance` → a method through
  the returned interface's vtable → `Release`, and gets back a real object with a
  real refcount. Wine's ole32 → combase → rpcrt4/advapi32/user32/gdi32 all boot
  as guest code; the CLSID resolves through exemu's registry to an
  `InprocServer32`, the in-proc server is loaded, and its `DllGetClassObject` is
  called. **There is no native COM anywhere in exemu** — and the emulated path is
  the control that proves it: exemu's own `CoCreateInstance` is an unsupported
  stub that leaves the out-pointer NULL, so the sample fails there and succeeds
  only under `--wine-boot`.
- **Registry fixes this required**, each a real bug: the hive was an exact-match
  map, but the Windows registry is case-insensitive/case-preserving, and Wine's
  kernelbase reaches `HKCR` as `\Registry\Machine\Software\Classes` while exemu
  seeded `HKLM\SOFTWARE\…` — so lookups silently missed. `HKEY_CLASSES_ROOT` is
  now a *view* onto `HKLM\SOFTWARE\Classes` rather than its own hive, so the
  Win32 seam, the NT syscalls and the seeds all meet on one subtree. Plus
  `NtOpenKeyEx`, `NtEnumerateValueKey`, `NtDeleteKey`, `NtDeleteValueKey`,
  `NtFlushKey`.
- Worth recording: **in Wine 11 the COM core is `combase.dll`, not `ole32`** —
  ole32 exports `CoInitializeEx`/`CoCreateInstance`/… as *forwarders* to combase
  and imports 67 more symbols from it.

### comctl32 / uxtheme / comdlg32 as guest code (W6.1)
- The pivot's central efficiency claim — that these DLLs cost exemu almost
  nothing because they are just guest PE code — is now **tested rather than
  asserted**. A generated sample that *statically* imports
  `comctl32!InitCommonControlsEx` (forcing the Wine loader to map, relocate,
  bind and run its DllMain before the entry point) runs to completion on the
  Wine boot, and the display driver observes **Wine's own comctl32 registering
  `msctls_progress32` as a real window class** with its own atom, instantiated
  at the requested geometry. exemu implements no progress bar.
- Each of the three DLLs is checked to relocate to a non-preferred base and to
  have **every named import it declares** (309 / 139 / 279 of them) resolve to
  a real export of the pinned DLL it names, forwarders included; one export per
  DLL is then executed through the interpreter from the DLL's own bytes.
- **The measured gaps were pinned as tests** so they stayed visible rather than
  being worked around: child windows did not paint — win32k allocated one surface
  per *top-level* window — and messaging a comctl32 control did not terminate.
  Both are closed in W4.8 below; the tests now assert the closed behaviour.

### user32's built-in control classes (W6.2)
- `CreateWindowExW(L"BUTTON", …)` now **reaches `NtUserCreateWindowEx`**. Wine's
  split leaves the built-in control classes (`BUTTON`/`EDIT`/`STATIC`/`LISTBOX`/
  `COMBOBOX`/`ScrollBar`/`MDIClient`/…) to the *kernel* side: user32 holds the
  WndProcs but registers no classes, so the lookup used to fail inside user32
  without ever crossing the syscall boundary.
- The WndProcs are **recovered at boot** from the one place they cross that
  boundary. `NtUserInitializeClientPfnArrays` is handed ntdll's `user_funcs`
  triple; each entry is a 7-byte `jmp qword [rip+disp32]` thunk whose slot holds
  the procedure user32 published through `RtlInitializeNtUserPfn`, index for
  index. win32k follows the thunks, checks each target really lands inside
  user32's mapped image (`SizeOfImage` read from the mapped PE header), and
  registers the 14 built-in classes against them. A target that resolves
  anywhere else is refused rather than registered.
- The whole chain is recovered by **disassembling the pinned binaries** (their
  own COFF symbol tables identify the per-index procs); no Wine source was read.
  The structure is pinned as a test against `ntdll.dll` itself — 17 entries per
  array, the exact thunk opcode, index-ordered slots, and the ANSI/Unicode arrays
  exactly one array apart — and end-to-end by the comctl gate, where the driver
  now observes the `BUTTON` child created at its requested geometry with its own
  atom, beside comctl32's `msctls_progress32`.

### `WM_NCCREATE` / `WM_CREATE` dispatch (W6.2)
- **A control finally runs its own creation handler.** `NtUserCreateWindowEx`
  now sends `WM_NCCREATE` then `WM_CREATE` to the class WndProc — user32's real
  `ButtonWndProc` and comctl32's real `ProgressWindowProc` included — so a
  control allocates its instance data instead of being an empty handle.
- The obstacle was structural, not a missing message. The existing WndProc
  dispatch *hijacks the syscall return*, which leaves the WndProc's LRESULT in
  the register `NtUserCreateWindowEx` must return the HWND in, and can only run
  one callback. The win32k callback frame now carries a **queue** of callbacks
  plus the handler's own result — the same re-entrant shape `_initterm`, the TLS
  callbacks and `DllMain` already use on the intercepted-import path — so both
  messages run and user32 still receives the handle.
- The `CREATESTRUCTW` the pair carries is built in a reservation *below* the
  interrupted syscall's stack pointer, with the callback frames seated below
  that, so a WndProc cannot overwrite the struct it was handed (and a window
  created from inside a WndProc nests naturally). The window and class names are
  **copied** NUL-terminated: the caller's `UNICODE_STRING` buffers carry a
  length, not a terminator. The `hInstance` / `lpParam` argument slots were
  pinned by probing the pinned user32 with distinctive values.
- The gate's proof is end-to-end and load-bearing: the sample's WndProc answers
  `WM_CREATE` by reading `CREATESTRUCTW.lpCreateParams` and only reports the
  creation — by setting the window text to `CREATESTRUCTW.lpszClass` — if the
  magic it was created with round-tripped.
- **A real boundary bug surfaced and is fixed.** The Wine boot ends up with
  *two* ntdll images: the one exemu pre-maps (the running image, the only copy
  whose `user_procs` user32 ever fills) and a second one Wine's own loader maps
  for the name `NTDLL.dll` while resolving forwarders. `user32!DefWindowProcW`
  is a forwarder to `NTDLL.NtdllDefWindowProc_W`, which is literally
  `jmp qword [user_procs+0xa8]` — so every module bound after that second map
  (the exe, comctl32) called `DefWindowProc` through a **NULL** slot and jumped
  to address 0. Worse, the fault never surfaced: ntdll's `call_seh_handlers`
  re-runs `virtual_unwind` until the frame reaches `TEB.StackBase`, and exemu's
  win32k callback-return thunk carries no `.pdata`, so the walk never terminated
  and the run spun instead of faulting. win32k now mirrors the recovered
  client-PFN procs into every mapped ntdll copy, making the table it recovered
  authoritative regardless of which image a module bound against. The duplicate
  load itself remains a loader-level gap, recorded in the comctl gate.

### Wine's own controls actually paint (W4.8)
- **A `BUTTON` and a `msctls_progress32` now appear as pixels, drawn by Wine's
  own code.** The golden frame at `crates/app/tests/goldens/comctl_painted_controls.png`
  shows user32's `ButtonWndProc` painting a bordered grey push button **with its
  own "Push me" label** and comctl32's `ProgressWindowProc` painting a chunked
  bar filled to the 60 % the guest set with `PBM_SETPOS`. exemu implements
  neither control. The gate reads those pixels back: dark glyph pixels strictly
  inside the button's border, and a fill fraction between 0.35 and 0.85 of the
  bar — a control that ignored the message would be empty, one that ignored the
  range would be full.
- **A control's label needed the two measuring calls, not just the drawing one.**
  `DrawTextW` asks for `NtGdiGetTextMetricsW` before it lays out and
  `NtGdiGetTextExtentExW` before it positions; with both answering the honest 0
  the button first drew no text at all, then drew it a million pixels
  off-surface. Both are serviced now, with the extent coming from the same
  rasterizer the draw uses so measure and draw agree.
- **Child windows have no surface of their own** — that is the model Wine's
  binaries dictate, not a shortcut. `NtUserGetDC`/`BeginPaint` bind a child's DC
  to its **top-level ancestor's** surface with an origin offset and a clip rect,
  and win32k applies both. That the *kernel* side must do it is recovered, not
  assumed: bounding every gdi32 primitive by its `.pdata` entry shows
  `Rectangle`, `PatBlt`, `BitBlt`, `LineTo`, `Ellipse`, `FillRgn`, `StretchBlt`
  and `SetPixel` performing **zero** non-stack arithmetic before their syscall —
  the app's raw logical coordinates cross the boundary untouched. The origin
  itself is published into the shared DC object at `+0x48`/`+0x4c`, the two
  dwords `gdi32!GetDCOrgEx` reads and nothing in gdi32 ever writes.
- **The `NtUserCall*` fan-in enums are recovered.** Three win32u indices carry
  whole families of tiny operations behind a call number that is public nowhere;
  they were left as honest stubs, and a control's WndProc consequently gave up on
  the first `IsWindow` that answered "no". Sweeping the pinned user32 for the
  selector immediate each public wrapper loads before its win32u thunk yields the
  lot — `IsWindow` = `NtUserCallHwnd(0xa)`, `GetClientRect` =
  `NtUserCallHwndParam(0xe)` over a `{ RECT*, dpi_ctx }` block,
  `GetSysColorBrush` = `NtUserCallOneParam(7)`, and so on. `user32!IsIconic`
  pins the meaning of the one ambiguous selector: it asks for `GWL_STYLE` with
  code `0xa` and tests bit 29, so `0xa` is `GetWindowLong`.
- **Per-window extra bytes exist.** A Wine control keeps its instance pointer in
  its class's `cbWndExtra` at offset 0 — `SetWindowLongPtr` on `WM_NCCREATE`,
  `GetWindowLongPtr` on every message after. With no storage behind those the
  progress bar re-read NULL forever. `NtUserSetWindowLong{,Ptr}` and the
  `GetWindowLong*` selectors now share one slot model (the documented negative
  offsets plus the extra block), and the syscall dispatcher grew a full-width
  result path so a returned *pointer* is not truncated to 32 bits.
- **The W4.8b brush wall is down, and the reason was a misread field.** The
  earlier attempt found gdi32 looping on a bare brush handle and concluded the
  handle needed an exotic client-side object. It does not: `gdi32!SelectObject`
  computes the object type as `(byte[entry+0x0C] & 0x7f) << 16` — **the low byte
  of the handle-table entry's generation word**, the very word that must already
  equal `handle >> 16` — and dispatches `0x100000` to `NtGdiSelectBrush`. So a
  GDI handle is simply `(type << 16) | slot`; the pre-existing HDC encoding was
  that rule all along with `type = 1`. Naming it makes brushes (`0x10`), pens
  (`0x30`), fonts (`0x0a`) and regions (`0x04`) fall straight out.
- **Stock objects had to be published, or Wine crashes.** `gdi32!GetStockObject`
  issues no syscall: it maps the index to a fixed table slot (`index + 0x20`,
  plus paired high/low-DPI slots for the four system fonts), reads the entry
  directly, and **executes `ud2` when the in-use byte is zero**. An unpopulated
  stock table therefore does not return NULL — it takes down the first control
  that asks for a stock brush mid-paint, which is exactly what happened.
- The primitive set the controls actually use, recovered by tracing the win32u
  boundary rather than guessed: `user32!FillRect` lowers to
  `SelectObject(brush)` + `PatBlt(PATCOPY)` + restore, so `NtGdiPatBlt`,
  `NtGdiSelectBrush`, `NtGdiCreateSolidBrush`, `NtGdiSelectPen/Font`,
  `NtGdiCreateRectRgn`, `NtGdiDeleteObjectApp` and a real
  `NtGdiIntersectClipRect` join the handler set. `SetTextColor`/`SetBkColor` are
  **not** client-side stores: they are `NtGdiGetAndSetDCDword(0x66/0x64)`, so
  text now renders in the DC's colour instead of always black.
- **Messaging a control terminates.** `SendMessageW(hProgress, PBM_SETRANGE)`
  then `PBM_SETPOS` returns and the guest runs on. The recorded diagnosis — "it
  spins on an unserviced `WineUnixCall` import thunk" — was wrong and is
  falsifiable straight from the binary: `comctl32.dll` imports no
  `__wine_unix_call` and no `NtQueryVirtualMemory` at all, so it has no unix half
  to pair. (That shape is real for `ws2_32`; it was never this.) The true cause
  was the NULL `DefWindowProcW` forwarder slot fixed in W6.2.
- **All of it is re-derived on every run.** `crates/app/tests/win32k_abi.rs` is
  the `afd_abi.rs` treatment for the GUI boundary: 9 tests that read the 26
  syscall indices, the three call-number enums, the `GetClientRect` parameter
  block, the GDI handle-type rule, the stock-slot arithmetic and the `ud2` trap,
  the DC_ATTR offsets and the `FillRect` lowering back out of the pinned
  `win32u`/`user32`/`gdi32` bytes and assert them against the constants the
  handlers use. A Wine bump that renumbers anything fails there, by name.
- New debug seams: `EXEMU_W32K_TRACE` logs every win32u index with its first
  three arguments (this is how the missing multiplexers were found), and
  `EXEMU_FAULT_TRACE` reports every exception handed to the guest's own
  dispatcher with the faulting instruction's bytes — without it, a Wine guest
  that catches its own access violation shows up only as an exit code.

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

### Corpus regression gate (W9.6)
- The per-exe regression pins stop being prose and become a **gate**.
  `corpus.toml` declares, per corpus binary, the expected outcome, instruction
  count and tolerance, fault site and reason, sandbox artifact count and step
  budget; `exemu corpus` runs them and prints a pass/fail table with the delta
  against each pin; `--update` re-blesses the manifest as a reviewable diff.
  `crates/cli/tests/corpus_gate.rs` is the same runner as a test, skip-guarded
  on the git-ignored corpus (a fresh checkout stays green) and on debug builds
  (the pins are release-measured).
- Each binary runs in its own child process with a private `TMPDIR`, so its
  guest-sandbox artifacts are counted in isolation, and is invoked by bare file
  name from its own directory — the guest command line lives in guest memory, so
  a longer `argv[0]` costs real instructions (measured: 936 of them on Firefox
  Installer). The pins are therefore a property of the emulator, not of the
  checkout path.
- **Reproducibility trap documented and fixed in the runner.** The guest sandbox
  `$TMPDIR/exemu-sandbox` persists and accumulates across runs, and an installer
  enumerates and overwrites what it finds there — so the same binary executes a
  different number of instructions against a dirty sandbox (7-Zip: 496,505,788
  instructions/110 files, 496,505,786/115, and 496,505,572/108 against a fresh
  one). Execution is deterministic *given* the sandbox state, not across a dirty
  one. The gate resets the sandbox per entry; even then, runs repeat only to
  about ±1 instruction because the emulator services the real host clock, which
  is why the tolerances are small noise floors rather than zero.

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
