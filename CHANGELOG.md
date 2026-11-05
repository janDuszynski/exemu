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

Tests grew 199 → 1059, clippy clean at `-D warnings`; 7-Zip still installs
end-to-end on the default path.

### `exemu-os` depends on `exemu-core` alone, and `exemu-app` is split by concern
- **The `os → cpu` edge is gone.** Its only use was the 32-bit TEB base, which
  was already `exemu_core::cpu::DEFAULT_FS_BASE`. The segment selectors
  (`0x33`, `0x23`, `0x2b`), defined once in `cpu` and twice more in `os`, now
  live once in `exemu_core::cpu`; `exemu_os::wow64::SEL_*` are `u32` views of
  them for the 32-bit `CONTEXT`.
- **The `os → loader` edge is gone.** Runtime PE loads (`LoadLibrary` plugins,
  the Wine core, `NtCreateSection(SEC_IMAGE)`) and api-set and forwarder
  resolution go through a new `exemu_core::ImageLoader` seam.
  `exemu-app` injects `image_loader::PeImageLoader`, which delegates to
  `exemu-loader`. A `WinOs` nobody injects gets `NoImageLoader` and loads no
  guest DLL at all. The WoW64 bring-up mapper (`Wow64Image`, `map_image`,
  `image_view`, `bind_imports`) moved from `exemu_os::wow64` to
  `exemu_app::wow64_image`, the only crate that called it.
- **`crates/app/src/lib.rs` went from 1,606 lines to 29.** It is now the crate
  root: `config.rs` (run config and results), `kuser.rs`
  (`KUSER_SHARED_DATA`), `cmdline.rs`, and `process/` with `load.rs` (bring-up),
  `run.rs` (the run loop), `debug.rs` (debugger serving), `exception.rs`
  (guest exception delivery) and `fault.rs` (fault reports). Every public path
  is unchanged.
- No behavior change: tests 1086 → 1088 (two new ones pin the adapter's
  forwarder and api-set paths, which no corpus pin can see), clippy clean, and
  all 11 corpus pins identical to the instruction.

### The JIT twin of a multithreaded Wine guest matches to the instruction (W8)
- **The Firefox installer's Wine run was 31,119 instructions shorter under
  `--jit`** (14,747,646 against the interpreter's 14,778,765). Every syscall, its
  arguments and the virtual clock agreed in both modes until the first
  preemptive thread switch, at instruction 11,030,780; there the interpreter
  switched away from `rip=0x600136de` and the JIT from `0x600136e0`, one
  instruction later, and from then on every switch drifted.
- **Two halves of one contract were wrong.** The JIT treated its budget as a
  floor: a chain stopped at the first block boundary *at or past* it, so the
  timeslice end, the `KUSER_SHARED_DATA` refresh and the step cap fired a few
  instructions late. It is now a ceiling: a call never retires more than it was
  allowed, links are taken only while the longest cached block still fits, and
  a block that would cross the ceiling is left to the interpreter. And the
  scheduler's retire budget let bulk retirement run *through* the slice's last
  step, which the interpreter spends on the switch itself without executing an
  instruction; it now stops one short, so the switch happens in that same
  interpreted step. Either half alone is not enough: the JIT ceiling alone gives
  14,778,753, the scheduler change alone 14,747,646, both together 14,778,765.
- **Why no test saw it.** The JIT differential let the JIT choose where to stop
  and then caught the interpreter up to that count, and the only budget it ever
  passed ended on a lap, which is a block boundary. Nothing could overshoot
  where it looked. `exemu-oracle jit --laps K --cut` now cuts every lapped
  trial at random budgets of 0..7 instructions against 3-instruction blocks and
  fails if a call retires one instruction past what it was given;
  `crates/jit/tests/budget.rs` stops a call/loop program at every instruction
  count in both bitnesses against the interpreter; and
  `crates/os/tests/thread.rs` runs two spinning threads for 230,017 steps in
  both modes and compares the counters each thread reached.
- The Firefox and SteamSetup Wine-path entries now have `--jit` twins in
  `corpus.toml`, pinned to the interpreter numbers.

### 32-bit GUI programs get their windows on the WoW64 path (W5)
- **`NtUserGetClassInfoEx` never filled the `WNDCLASSEXW` it was handed.**
  user32's `WIN_CreateWindowEx` reads `lpszMenuName` from that struct and passes
  it to `LoadMenuW`, so every window was created from uninitialised stack. Under
  WoW64 `wow64win` copied 64-bit stack garbage into the 32-bit struct, and
  Minesweeper and xmsol died in `kernelbase!get_res_nameW` reading `0x400c4bc`.
  The kernel now remembers the whole registered class, including the client's
  menu-name pointers, and answers with it. Minesweeper now creates its main
  window, shows it and paints it once; xmsol shows its window maximised.
- **A 32-bit `ws2_32.dll` can initialise.** `wow64.dll` rewrites a 32-bit DLL's
  `MemoryWineUnixFuncs` query into `MemoryWineUnixWow64Funcs`, which exemu
  refused, so `ws2_32`'s `DllMain` returned FALSE and anything importing it
  (xmplay through wininet) failed with `0xC0000142`. putty-32bit now gets as far
  as creating its windows.
- **`NtProtectVirtualMemory` now changes the main image's page protection.** It
  used to update bookkeeping only, so a packer that unprotects a read-only
  section before unpacking into it (xmplay's petite stub) faulted on its first
  write. The old protection reported is the section's own.

### curl runs completely on the Wine path: the first finished console program
- **A 64-bit mingw console program does its whole job.** `curl.exe` 8.21.0
  (LibreSSL, 20 Wine builtins) prints its 551-byte `--version` banner and exits
  0 after 3,951,927 instructions, and a `file://` fetch copies the loader's own
  3,848,296-byte `curl.exe` into `C:/Temp` and exits 0 after 4,499,611. Before,
  `--version` stopped at 2,552,459 instructions with `loader_init c0000142,
  CRYPT32.dll failed to initialize`.
- **crypt32 gets a unix side.** crypt32's `DllMain` fails when its
  `MemoryWineUnixFuncs` query finds nothing; `crates/os/src/crypt32.rs` now
  answers its seven unix calls as the pinned `crypt32.so` does on a host with
  no PKCS#12 library and an empty root store.
- **Corpus rows carry guest `args` and a `stdout` pin.** A row with a `stdout`
  pin runs with console echo on and fails unless the guest wrote exactly those
  bytes; `toml_lite` decodes `\n`, `\r` and `\t`. Exit code and artifact count
  alone could not tell a correct banner from silence, so console programs were
  a gate that could not fail. Mutation-checked: dropping the crypt32 arm, a
  wrong stdout byte, a muted console write, a mis-decoded `\r` and dropped
  `args` each turn the gate red.
- **Not yet:** `http://` fetches stop at the first socket option and `FIONBIO`
  ioctl (`STATUS_NOT_IMPLEMENTED`); secur32's schannel and dnsapi's libresolv
  unix sides are absent.

### The file dialog runs: `FileOpenDlgProc95` receives its first message (W6.2)
- **exemu's GDI handle table was the icon bug.** It held 128 slots, of which
  `0x20..=0x37` are the stock objects, so a guest had **72 GDI handles for its
  whole life** — and nothing ever came back: `NtGdiDeleteObjectApp` cleared the
  entry's in-use byte without returning the slot, while `NtUserReleaseDC` and
  `NtUserEndPaint` leaked it outright. By the time `shell32!SIC_Initialize`
  loaded its five shell icons the table was dry, which is why the 48x48, the
  *second* 16x16 and the 256x256 failed where the first two succeeded, and why
  two identical 16x16 loads disagreed. It was never the size and never the
  PNG-compressed resources. Slots are now recycled through a free list and the
  table holds 4096.
- **`NtUserGetIconInfo` now empties the two `UNICODE_STRING`s it is handed.**
  `GetIconInfoExW` writes its NUL terminators at `szModName[Length]` and
  `szResName[Length]`, indexing by `Length` as a character count; exemu left both
  fields untouched, so the terminator landed thousands of bytes past the struct.
  With an empty module name `CopyImage` takes its documented copy-and-scale path
  instead of reloading from a resource.
- **`GetDlgItem` returned 0 for every dialog in every guest.** `user32!GetDlgItem`
  starts with `GetWindow(hwndDlg, GW_CHILD)`, which is `NtUserCallHwndParam`
  selector `0x10` — unserviced, so it answered 0 and the search never began.
  `NtUserBuildHwndList` behind it had never been reached once. Both are serviced
  now, including the caller-writes-the-terminator convention its callers rely on.
- **`NtUserAllocWinProc` answers a real window-procedure handle.** It had
  answered 0, and `SetWindowLongPtrW` stores that answer, so `DWLP_DLGPROC` was 0
  for every dialog in the process and `DefDlgProcW` called nothing. exemu now
  keeps a `{procA, procW}` table and hands back an opaque handle that
  `GetDialogProc` resolves per flavour.
- **The result:** Wine's file dialog builds its controls, initialises its shell
  image lists, enumerates the folder through `IShellFolder`, fills its Look-in
  combo and delivers `CDN_INITDONE`/`CDN_FOLDERCHANGE`/`CDN_SELCHANGE` — 65.7M
  instructions where it used to spend 3M. `GetOpenFileNameW` still returns FALSE
  with `CommDlgExtendedError() == 0`, an honest cancel, and no access violation.
- **The next wall was fonts, and it is now behind us** — see the section below.
  A headless run can be told what a user would have typed
  (`RunConfig::file_dialog_pick`, `EXEMU_FILE_DIALOG_PICK`); it posts `WM_SETTEXT`
  into the file-name combo's edit and `WM_COMMAND(IDOK)` to the dialog. Off by
  default, so no existing run changes.

### GDI grows font objects, and the 32-bit half of the handle table (W6.2)
- **`NtGdiHfontCreate` (win32u 0x1233) answers a real `HFONT`.** Its first
  argument is an `ENUMLOGFONTEXDVW` (0x1a4 bytes) whose first member is the
  caller's `LOGFONTW` (0x5c bytes, `lfFaceName` at +0x1c) — read off
  `gdi32!CreateFontIndirectExW`, which passes `rdx = 0x1a4`, and off
  `CreateFontIndirectW`, which builds one on its own stack out of five `movdqu`
  copies of the caller's 0x5c bytes. exemu keeps those bytes verbatim and hands
  back an `NTGDI_OBJ_FONT` handle, which is the type `gdi32!SelectObject`
  dispatches on.
- **`NtGdiGetDCObject` (0x11f0) answers what a DC carries.** Its second argument
  is an `NTGDI_OBJ_*` value shifted left 16 — the same encoding as the high half
  of a GDI handle — recovered from `gdi32!GetCurrentObject`'s jump table, which
  turns `OBJ_FONT` into `0xa0000`, `OBJ_BRUSH` into `0x100000`, `OBJ_PEN` into
  `0x300000` and `OBJ_BITMAP` into `0x50000` (`NTGDI_OBJ_SURF`). A DC with
  nothing selected reports the stock `SYSTEM_FONT`, as Wine's own DC init does.
- **`NtGdiExtGetObjectW` fills a `LOGFONTW` for a font handle**, `NtGdiSelectFont`
  answers the font that was there before instead of echoing its argument,
  `NtGdiGetTextFaceW` answers the selected face, and `NtGdiGetFontData` answers
  `GDI_ERROR` — the honest answer for a font exemu has no file for, and the one
  that sends Uniscribe down its non-sfnt path.
- **`TEXTMETRICW` now follows the selected font.** It was a fixed 16x8 cell for
  every DC in every guest; it is now derived from the `LOGFONTW` — a negative
  `lfHeight` is an em size and the cell is `em + ceil(em/4)`, `tmAscent +
  tmDescent == tmHeight`, and weight, italic, underline, strike-out, charset and
  pitch/family come straight from the `LOGFONT`. Text extents ask the display
  driver to measure at that cell height rather than a hardcoded 16 px.
- **That is what gdi32's bundled Uniscribe was missing.** `init_script_cache`
  (gdi32 RVA 0x45e90) is `GetCurrentObject(hdc, OBJ_FONT)` →
  `GetObjectW(hfont, 0x5c, &lf)` → reject if `lf.lfFaceName[0] == 0` →
  `GetTextMetricsW(hdc, &sc->tm)`; every one of those steps used to fail at the
  first, so `analysis->glyphs[0].sc` stayed NULL and `ScriptString_pSize`
  dereferenced it at `gdi32+0x38819` (`sc->tm.tmHeight`, and `tm` sits at +0x70
  in `ScriptCache` because a 0x5c-byte `LOGFONTW` sits at +0x14 — which
  `init_script_cache`'s own `memcmp(entry+0x14, &lf, 0x5c)` confirms).
- **A WoW64 guest's `gdi32` reads the handle table out of its own PEB.** The
  32-bit `gdi32!GetObjectW` does `mov eax, fs:[0x18]` → `[eax+0x30]` (Peb) →
  `[eax+0x94]` (`GdiSharedHandleTable`) → `table + LOWORD(handle)*24`, and exemu
  published that pointer only at `PEB64+0xF8`. The first real `HFONT` therefore
  made the 32-bit half compute `0 + 0x38*24 + 0xe` and take an access violation
  at `0x54e`, which is what turned Firefox Installer's clean `exit 1` into a
  fault. exemu now publishes the pointer in the 32-bit PEB too and maps the
  table and its object arena below 4 GiB, since the 32-bit side reads both
  through 32-bit pointers.
- **Where the drive stops now.** It gets through shaping and stops one wall
  further on, in `comctl32!COMBOEX_ComboWndProc` (comboex.c:1950): the
  ComboBoxEx answers its edit's `EN_CHANGE` by asking the inner combo for
  `CB_GETCURSEL` and dereferencing `COMBOEX_FindItem`'s answer with no NULL
  check. `GetOpenFileNameW` still returns no path.
- **`NtUserGetProcessDpiAwarenessContext` (0x1435) answers.**
  `user32!GetThreadDpiAwarenessContext` reads the thread's context from
  `TEB+0x830` and, when that is 0, asks this syscall with `process == -1` and
  truncates the answer to 32 bits. The unserviced stub answered 0, which
  `GetAwarenessFromDpiAwarenessContext` rejects as `DPI_AWARENESS_INVALID`;
  exemu answers `NTUSER_DPI_UNAWARE` (0x6010), the context it already stamps
  into every `win_proc_params` and the one that goes with the 96 DPI
  `NtUserGetSystemDpiForProcess` reports.
  into the file-name combo's edit and `WM_COMMAND(IDOK)` to the dialog. That
  reaches gdi32's bundled Uniscribe and faults at `gdi32+0x38819`, because
  `NtGdiHfontCreate` is unserviced and no DC ever carries a font. Off by default,
  so no existing run changes.
### An input event names the window it came from (W4.6)
- **`exemu_core::InputEvent` carries an `hwnd`.** `MouseMove`, `MouseButton` and
  `Key` each gained one; `Close` did not, because the host only sends it when the
  last window has gone and it means "quit", not "this window closed". The host
  fills it in from the only identity it honestly has — an `NSEvent`'s
  `windowNumber` resolves to the guest **top-level** whose `NSWindow` received the
  event, and `event_client_pos` already converts through that same window's
  content view, so the hwnd and the coordinates come from one window.
- **win32k hit-tests down from that window instead of from `shown_window()`.**
  `route_raw_input` resolves the named window's surface owner and walks
  `window_from_point_in` from there; the `HTTRANSPARENT` re-walk uses the same
  root. `keyboard_target` takes the focus or the active window only when it lives
  under the named window, and otherwise the named window itself — a key typed
  into the second window can no longer land in the first window's focus. Capture
  still wins over everything, as on Windows.
- **What used to be the first shown window now routes per window.** Before this,
  a click in the second of two top-level windows reached the first one's
  controls; with several windows on screen there was no way to reach any but the
  first. An event naming a window win32k never made, or one the guest has hidden,
  is dropped rather than delivered to the wrong one, and an event with no hwnd
  (a test injector, the hostless path) keeps the old first-shown-window rule.
- **Pinned headlessly, and mutation-checked.** Two win32k unit tests build two
  top-level windows with a control each and route a click and a keystroke at the
  second; one `cocoa.rs` test resolves an `NSWindow` number to its guest hwnd
  through the pure `WindowModel`, with no AppKit window involved. Ignoring the
  event's hwnd in `route_raw_input`, in `keyboard_target` and in the host's
  lookup turns exactly those three red and leaves the other 126 win32k tests
  green; restored. Workspace 1079 → 1081, corpus 11/11 at delta 0.

### One host window per top-level, and input that goes only where it is routed (W4.6)
- **A real `NSWindow` was confirmed on screen, by looking at it.** `exemu run
  --gui --wine-boot <dir> <gui-sample.exe>` puts up a titled 480×260 window
  carrying the guest's CoreText text and GDI rectangles; `exemu cocoa-demo` puts
  up its test frame. Neither had ever been observed before — only inferred from
  exit codes. The window opens on the *default* Space, so with a full-screen app
  frontmost a plain `screencapture` of the screen shows nothing; the window is
  there, and `screencapture -l <windowNumber>` proves it. The presenter now
  prints the window's title, size and `windowNumber` when it opens, which is what
  makes that check possible.
- **Every window the guest created used to become its own `NSWindow`** — win32k
  calls `UserDriver::create_window` for children as well as top-levels, and the
  host opened one per call. A dialog with three controls meant four windows, and
  because a window vanishing was read as "the user closed it", the first one
  reaped killed the guest. The host now keeps a `WindowModel` (`crates/gui/src/
  host.rs`): a window whose parent is a window it already knows is a **control**,
  and a control shares its parent's `NSWindow` and client coordinate space, which
  is exactly the space win32k hit-tests in (`WM_NCHITTEST`, capture, the deepest
  topmost child). One top-level plus its controls opens one window.
- **A window created without `WS_VISIBLE` no longer pops up.** `Create` records
  the geometry, `ShowWindow` opens and fronts it, `SW_HIDE` orders it out without
  destroying it, a later `SW_SHOW` reuses it, and only a real `Destroy` closes it.
  Only the last visible window disappearing quits the guest.
- **Input is forwarded only from the window win32k will route it to.** An
  `NSEvent` belonging to any other window is dropped rather than delivered to the
  wrong one at the wrong coordinates.
- **A guest that redraws continuously no longer starves its own window.** The
  old loop pumped `NSEvent`s only when the command channel ran dry, so a stream
  of `Present`s meant no events at all; the pump now runs on a fixed 8 ms
  interval regardless.
- **The window now comes to the front and takes the keyboard**, and the reason it
  did not is an ordering AppKit does not document: `NSApplication::activate` must
  be called **before** `makeKeyAndOrderFront`, not after. Called after, the window
  is ordered in while the app is still inactive, so the window server puts it on
  the Space the app is assigned to rather than the one in front of the user, and
  it never becomes key — measured as `isOnActiveSpace=false` with a full-screen
  app frontmost, and visible as grey traffic lights in a window capture. Swapping
  the two lines gives `isOnActiveSpace=true`, coloured traffic lights, and
  `exemu` in the menu bar.
- **The live input chain was driven end to end and watched.**
  `EXEMU_COCOA_SYNTH_CLICK=x,y` posts one synthetic left click into the
  application's own `NSEvent` queue at that client point, so the click travels the
  real path — `nextEventMatchingMask` dequeues it, the window-number filter
  accepts it, `event_client_pos` converts it through the real `NSWindow`'s content
  view, the channel carries it, win32k routes it, Wine's `DispatchMessageW`
  lowers it through `NtUserMessageCall`, and the guest's `WndProc` handles it.
  On `gui-sample` the guest draws its click rectangle with the corner exactly at
  `x,y` (checked at two different points), and the run grows from 1,596,465 to
  1,597,073 instructions — the guest really executed its handler. This is the
  first time anything but an injected `InputEvent` has been shown to reach the
  guest; only the physical mouse itself is still unexercised.
- **Two AppKit correctness fixes.** `setReleasedWhenClosed(false)` — the host
  holds a `Retained<NSWindow>`, so letting AppKit release it on close left a
  dangling pointer for the next visibility check. And `finishLaunching`, which is
  the app's responsibility when it drives `nextEventMatchingMask` itself instead
  of calling `NSApplication::run`.
- Pinned headlessly by 12 new tests: nine in `crates/gui/tests/window_host.rs`
  over the pure `WindowModel`, three unit tests over the AppKit→Win32 mappings
  (the bottom-left→top-down client flip, the keyCode→VK table, the event filter).
  Each was mutation-checked: treating a control as a top-level, dropping the
  coordinate flip, forwarding every window's events, and routing to the newest
  window instead of the first each turn its test red.

### The JIT compiles `ret`, and the reason to compile it was not the one on record (W8)
- **`ret` and `ret imm16` now compile** — a stack pop reusing the software TLB
  plus an exit through the indirect-branch inline cache that W8.5 built for
  `jmp`/`call` through a register. `ret` was the last high-frequency opcode that
  ended a block by handing control back to the interpreter.
- **The measurement is a correction, and it is the point of the entry.** The
  plan said 7-Zip's 3.42 M returns to the interpreter were dominated by `ret`.
  They are not: 7-Zip executes **1,703** returns in its whole 496,505,572-instruction
  run, so side exits fall 3,419,597 → 3,417,894 (−0.05%) and retired host
  instructions do not move outside the run-to-run spread. The `c3×76` line in the
  JIT's declined-opcode report counts **distinct block addresses**, not
  executions; reading it as a frequency is what produced the wrong expectation.
- **On the Wine path it pays properly.** SteamSetup as a WoW64 process on Wine's
  PE builtins loses **40.9%** of its remaining side exits (206,174 → 121,869),
  runs 98.5% instead of 97.5% of its stream as native code, goes from 9.8 to
  **16.7** blocks per native chain, and retires **8.6% fewer host instructions**
  (1.2026 G → 1.0989 G, min user+sys over 5 interleaved reps, non-overlapping
  spreads). Every Win32 call on that path is a real `call` into a Wine DLL and a
  real `ret` back, which is exactly why the same opcode is worth 0.05% on one
  binary and 40.9% on the other.
- A fault in a compiled `ret` still rewinds to the interpreter's exact state: the
  return address is loaded before `rsp` moves, so a failed pop leaves `rsp`
  untouched and `rip` on the `ret` itself. A `66`-prefixed `ret` is declined
  rather than compiled, matching how the JIT already treats `66` on `call` and
  `jmp`.
- The JIT differential now **generates** returns — hostile-`esp` `ret` and
  `ret imm16` shapes whose pop straddles or runs off the end of a region, and a
  lapped `push <top> ; ret` shape that is the only way this harness can make a
  return's inline cache fill and then be taken. 0 divergences in 4.4 M trials
  across both bitnesses, both layouts, both debug modes and the lapped mode.
- A dozen JIT tests had used `ret` as *the opcode the compiler declines*, to end
  a block where they wanted it ended; they now use `hlt`, which the interpreter
  answers with a defined halt, which `crates/jit/tests/debug.rs` already used for
  the same purpose, and which is one byte with the same flag classification — so
  every block length, byte offset and emitted instruction those tests were
  exercising is unchanged.

### The file dialog tells the truth: an honest cancel instead of a hollow TRUE (W6.2)
- **`GetOpenFileNameW` had started returning TRUE with an untouched `lpstrFile`**,
  and the only visible sign was the comdlg sample's failure tally "improving"
  from 5 to 3 while every one of its seven reported tags stayed byte-identical.
  A hollow TRUE is worse than the FALSE it replaced: a real application takes an
  empty path for a valid selection. Read out of the pinned `user32.dll` rather
  than remembered — `DIALOG_DoDialogBox` (RVA 0x19930) answers a `WM_QUIT` by
  re-posting the quit and breaking out with `dlgInfo->idResult` untouched, and
  `DIALOG_get_info` (RVA 0x19eb0) pre-initialises exactly that field to `IDOK`.
  That is genuinely what Wine does; the defect was exemu **manufacturing** a
  `WM_QUIT` for a run with no window host and aiming it at a modal dialog.
- **A run nobody is sitting in front of now closes a modal dialog rather than
  quitting at it**, in the two stages a window server uses: `WM_CLOSE` first —
  the message a click on the close box sends, and the one user32's `DEFDLG_Proc`
  answers by posting the Cancel button's command — and, if the dialog does
  nothing with it, the window is destroyed, which is what makes the loop's
  `IsWindow` check fail and its answer an honest 0. exemu writes no byte of
  user32's private `DIALOGINFO`. Only windows user32 attached a `DIALOGINFO` to
  are touched; an ordinary main window still just gets the `WM_QUIT` its pump is
  documented to stop on. `GetOpenFileNameW` and `GetSaveFileNameW` now both
  answer FALSE with `CommDlgExtendedError() == 0` — a plain cancel.
- **`NtUserPostMessage` (win32u 0x14d0) had no handler at all**, so every
  `PostMessage` a Wine DLL made was silently dropped — nothing says so, because
  the return value is almost never checked. Found because `DEFDLG_Proc`'s
  `WM_CLOSE` arm *posts* `WM_COMMAND(IDCANCEL)` rather than destroying the
  window, so closing any Wine dialog did nothing whatsoever.
- **Correction: icons never worked.** `NtUserSetCursorIconData` rejected every
  descriptor whose `num_frames` was zero, and user32 leaves it zero for every
  ordinary icon (`num_steps`/`num_frames` count an *animated* cursor's steps and
  frames). user32 answers a FALSE there by destroying the object it had just
  allocated and returning NULL, so **no `LoadIcon` in a Wine guest had ever
  produced an icon** — including after the icon-object work above. The earlier
  evidence was about reaching the call, not about it succeeding; the
  `NtUserDestroyCursor` immediately after it in the same trace is what said
  otherwise. Only a non-NULL frame pointer was ever required.
- **The sample now prints each dialog's raw `BOOL`** (`OPENRET`/`SAVERET`) out of
  a scratch dword of its own, and the gate ties the tally to the observables that
  explain it: a leg that reports TRUE must have produced a path, and with no path
  the count is exactly five, itemised. A lower number is not progress.

### Icons exist: the object every `LoadIcon` in a Wine guest was failing on (W6.2)
- **Every `LoadIcon`/`LoadCursor`/`CreateIconFromResourceEx` in a Wine-path guest
  returned NULL**, and the cause was a single unserviced multiplexer arm.
  `user32!create_cursoricon_object` allocates the icon object *first* —
  `NtUserCallOneParam(is_icon, NtUserCallOneParam_CreateCursorIcon)` — and gives
  up the moment that answers 0. It always did. The enumeration is recovered from
  the pinned `user32.dll`'s own DWARF (`CreateCursorIcon = 0`, `GetSysColor = 6`,
  `GetSysColorBrush = 7`, `GetSystemMetrics = 9`), the last three of which exemu
  had already recovered by disassembly — so the numbering is cross-checked, not
  taken on faith.
- **The GDI bitmap object model** an icon frame is built out of: memory DCs
  (`NtGdiCreateCompatibleDC`, whose surface *is* the bitmap selected into it),
  `NtGdiCreateBitmap` / `CreateCompatibleBitmap` / `CreateDIBSection` /
  `SelectBitmap` / `GetDeviceCaps`, and `GetObjectW` for bitmaps. Every bitmap
  gets a real guest-mapped store at the depth asked for with the DWORD-aligned
  DIB stride, because `CreateDIBSection` hands that address back to the caller.
- **Icon/cursor objects**: `NtUserSetCursorIconData`, `NtUserGetIconInfo`,
  `NtUserGetIconSize`, `NtUserFindExistingCursorIcon`, `NtUserDestroyCursor`.
  Two constants a guess gets silently wrong, recovered and pinned against the
  binaries: `NtUserGetIconSize` reports the height **doubled** (its only caller,
  `user32!get_icon_size`, halves it back out), and `GetIconInfo` hands back
  **copies** of `hbmMask`/`hbmColor` because its caller deletes them.
- **The icon system metrics.** `shell32!SIC_Initialize` sizes the system image
  list from `SM_CXICON`/`SM_CYICON` and `SM_CXSMICON`/`SM_CYSMICON`; exemu
  answered 0 for all four, so the list came out 0×0, comctl32 destroyed it, and
  comdlg32's file dialog dereferenced the resulting NULL `HIMAGELIST`.
- `EXEMU_WINE_DBG=1` forces Wine's own `WINEDEBUG` channels to host stderr for a
  run whose trace flag is off — which is every gate test, i.e. exactly the runs
  whose diagnostics one needs while debugging.
- Corpus unchanged, 11/11, to the instruction.

### The win32u trace says which index is *unserviced* (W6.2)
- win32k fills its **whole** syscall-index range with an honest-zero stub before
  overriding the slots it really services, so an `EXEMU_W32K_TRACE` transcript
  could not tell "serviced" from "answered zero" — every index looked identical.
- The service table now records which slots something actually **wrote** a
  handler for, as opposed to which the blanket fill covered, and the trace marks
  the rest `<UNSERVICED>`. Nothing about how a guest runs changes; this is a
  diagnostic, and it is what turns "the dialog stops somewhere" into a named
  list of missing primitives in one run.

### A guest finally gets comctl32 **v6**: the WinSxS store is materialised (W6.1)
- **Every Wine-path guest silently got comctl32 v5.** Wine ships two builds —
  `comctl32.dll` (`__WINE_COMCTL32_VERSION=5`) and `comctl32_v6.dll` (`=6`) —
  and only v6 compiles the themed replacements for the user32 built-ins
  (`Button`, `ComboBox`, `Edit`, `ListBox`, `Static`) plus `SysLink` and
  `TaskDialog`, and only it delay-imports `uxtheme`. Choosing v6 is not a flag:
  the guest's manifest declares a dependency on the
  `Microsoft.Windows.Common-Controls` 6.0.0.0 **side-by-side assembly**, and the
  loader resolves it through the activation context.
- **The assembly was in the prefix all along** — embedded in `comctl32_v6.dll`
  as an `RT_MANIFEST` resource *named* `WINE_MANIFEST`. What was missing was
  Wine's **prefix-creation** step, which turns those resources into a store:
  `%WINDIR%\winsxs\manifests\<key>.manifest` plus a private copy of the DLL
  under `%WINDIR%\winsxs\<key>\`, keyed
  `<arch>_<name>_<publicKeyToken>_<version>_<lang>_deadbeef`. exemu had never run
  it, so `ntdll!lookup_winsxs` opened an empty directory and Wine logged
  `fixme:actctx:parse_depend_manifests Could not find dependent assembly`.
- exemu now runs it (`crates/app/src/winsxs.rs`, staged from `Process::load`
  next to the `winecoreaudio.drv` staging), for the architecture the process's
  own loader will ask for — `x86` inside a WoW64 process, `amd64` for a native
  64-bit one. It is idempotent and only ever writes into the run's sandbox.
- **Proven guest-side, not by file existence.** The gate boots `SteamSetup.exe`
  as a WoW64 process, walks its own `PEB32.Ldr`, and asserts (a) the
  `LDR_DATA_TABLE_ENTRY` for `comctl32.dll` carries a `FullDllName` under
  `C:\windows\winsxs\<key>\` and (b) the image at that entry's `DllBase`
  exports `TaskDialogIndirect`, read out of the **mapped** export directory —
  an export the v5 build does not have at all. Mutation-checked: with the
  staging call removed the same run reports
  `FullDllName = "C:\windows\system32\COMCTL32.dll"` and the test fails.
- Corpus: both Wine WoW64 rows move, deterministic across three runs, and the
  attribution is exact — reverting only the staging call reproduces the old pins
  to the instruction. `SteamSetup.exe (wine wow64)` 7,683,013 → **8,169,827**
  (+486,814), 4 → 6 artifacts (the two new files *are* the store);
  `Firefox Installer.exe (wine wow64)` 14,466,773 → **14,775,399** (+308,626),
  3 → 5. The Firefox delta is the activation-context work alone — its inner
  7-Zip SFX declares the same dependency but exits before it loads comctl32.

### An exception nothing handles ends the process, instead of spinning (W5.12)
- **An unhandled guest fault used to run for ever** — measured as one
  `0xC0000005`, then `0x80000003` at `ntdll+0x10a5b` without end until the step
  budget. The cost was not the hang itself but what it did to every other change:
  anything that let a guest reach a *new* fault turned a clean stop into a
  300M-instruction one, and a GDI change was once bisected out for a hang that
  had nothing to do with GDI.
- The cause was one unserviced syscall. Wine's `KiUserExceptionDispatcher` is
  `call dispatch_exception; int3`, and that `int3` is unreachable in a working
  system because `dispatch_exception` never returns: it tail-calls
  `NtRaiseException(rec, ctx, FirstChance = FALSE)` when nothing handled the
  exception. exemu answered that with `STATUS_NOT_IMPLEMENTED`, so the call
  returned, the `int3` ran, and exemu delivered the resulting `STATUS_BREAKPOINT`
  back to the same dispatcher.
- `NtRaiseException` is now serviced. A last-resort raise **ends the process with
  the exception code**, which is what the NT kernel does — and exemu ends the run
  through its fault reporter, naming the *original* exception with its module
  attribution and rip trail rather than the `int3` that followed it. Behind that,
  a bound on re-delivery keyed on `NtContinue`, so no other shape of the same
  loop can come back.

### Wine can read a directory: `FILE_BOTH_DIR_INFORMATION.FileName` is at +0x5E (W6.1)
- **Every filename Wine read back from `NtQueryDirectoryFile` was empty.** The
  field follows `ShortName[12]` at 0x46 and so begins at 0x5E; `sizeof` is 0x60
  only because the struct is padded past its trailing `WCHAR FileName[1]`.
- **`FileInformationClass` was ignored outright.** Wine's own `FindFirstFileW`
  asks for `FileIdExtdBothDirectoryInformation`, whose name is at 0x72, and got
  the other class's layout. Both are now written in their own shape and anything
  else is refused rather than answered with a struct of the wrong kind. A third
  bug behind those: `Length`, `FileInformationClass` and `RestartScan` are 32-bit
  parameters in 8-byte stack slots, and exemu was reading the caller's stale
  upper halves along with them.
- What that turns on: **a real start-menu shortcut now records its shell-namespace
  target**. `IShellLink::SetPath` builds the `.lnk`'s PIDL by walking the
  namespace, which enumerates every directory on the way down — impossible while
  the names came back empty. Wine's shell32 now writes a shortcut carrying
  `C:\` → `windows` → `system32` → `notepad.exe`.

### A WoW64 process's section views are 32-bit addressable (W5.7)
- `wow64.dll` narrows the base `NtMapViewOfSection` returns into the 32-bit
  guest's pointer cell **without checking**, so a view placed above 4 GiB is not
  refused — it is truncated into a pointer to nothing and the guest faults
  somewhere else entirely on its first read. Image views and the NLS blob already
  allowed for that; ordinary file views did not.
### The JIT's memory cache stops skipping the last page of every region (W8.6)
- **A guest access cache entry used to need its page *plus seven bytes*** — the
  reach of an 8-byte access at the page's last byte — so that the emitted check
  could be a bare tag compare with no end-of-access test. That bought a small
  fast path and cost almost all of its coverage: the probe ran seven bytes past
  the region's end, so **the last page of every region could never be cached**,
  and a stack is used from the top down, which makes that page the hottest one in
  the process. Attributed over the first 1,000,000 declined fills: **998,205 of
  7-Zip's (99.8%) were one region's final page**, and **69% of the Wine WoW64
  path's were the 32-bit stack's** — none of them permission refusals.
- **The end-of-access check is now free rather than absent.** The probe compares
  the cached page number against the page of the access's *last* byte, while
  indexing the slot by the page of its *first*. An access that leaves the page
  therefore looks for a tag one page above the one that chose the slot, and only
  pages congruent modulo the slot count ever share a slot — so it cannot match,
  and falls back to the helper. The same argument covers an address that wraps at
  2^64 or at 2^32. Folding the shift into the compare pays for the add, so the
  fast path is still seven instructions (six for a byte access).
- **Measured on the same build, before and after** (`EXEMU_JIT_TLB_STATS`):
  7-Zip `--jit` **1,141,330 declined fills → 0**; SteamSetup on the Wine WoW64
  path **1,090,698 → 217,225 (−80%)**. What is left on the Wine path is the RWX
  image and `VirtualAlloc` regions — the executable-memory rule doing its job.
- **Retired host instructions, interleaved in one session, 5 reps, min user+sys:**
  7-Zip **10.443 G → 10.176 G (−2.6%)**, spread 10.443–10.489 vs 10.176–10.189;
  SteamSetup on Wine **1.3336 G → 1.1181 G (−16.2%)**, spread 1.334–1.375 vs
  1.118–1.124, CPU 0.06 s → 0.05 s. The two differ by an order of magnitude
  because the declined fills were 0.2% of 7-Zip's guest instructions and 14.5% of
  the Wine path's.
- **The blind spot this had created in the differential is gone the other way
  too.** Every region that harness maps is one page — all of it final page — so
  the fast path was reached only in the trials given deliberate extra slack. On
  identical trials the harness now goes from **18,390 entries filled and 28,989
  fills declined to 41,911 filled and 195 declined**, which is the region-final
  page becoming reachable, measured where it can be seen.
- Corpus 11/11 at drift 0 with every count unchanged to the instruction (7-Zip
  496,505,572 interpreted, debug-attached and JIT-compiled alike); 0 divergences
  in 4.0 M differential trials — 2 M across `mixed` and `edge` at both bitnesses,
  1.6 M more with a breakpoint or a watchpoint armed, and 400 k lapped — with
  **zero** cache entries filled in every watchpoint-armed run, which is the
  invariant that keeps an armed watchpoint seeing every access. Workspace tests
  1004 → 1009, clippy clean at `-D warnings`.

### Window properties, and the handle every window procedure is given (W6.2)
- **`SetProp`/`GetProp`/`RemoveProp` had no implementation at all.** `GetProp`
  answered NULL for something that had just been set — and window properties are
  where a large part of Wine's own USER layer keeps per-window state. The visible
  symptom was `err:commctrl:COMCTL32_SubclassProc Our sub classing stack got
  erased` on *every* control comctl32 subclasses; it is gone. Properties are
  keyed by name, with the documented integer-atom overload, and the stored value
  comes back at full 64-bit width because what callers park there is a pointer to
  their own allocation, not a BOOL.
- **Every dialog procedure in the process was being called with `hwnd = 0`.**
  `user32!WIN_GetFullHandle` — the handle widener each user32 entry point runs
  its `HWND` through — is one `NtUserCallHwnd` selector, and exemu answered it
  with 0. `user32!call_dialog_proc` widens the handle and passes the result to
  the dialog procedure *as its window*, so a dialog procedure could not name its
  own window: comdlg32's file-dialog procedure could not even store its own
  state. exemu's handles are already full, so the answer is the validated
  identity.
- Both are re-derived from the pinned binaries on every test run
  (`crates/os/tests/user_abi.rs`), so a Wine-prefix refresh that renumbers the
  SSDT fails a test instead of silently bringing the bug back.

### A real codepage table, and an honest codepage surface (W6.x)
- **msvcrt was running with empty multibyte tables on every Wine-booted guest.**
  `NtGetNlsSectionPtr(type 0xb, id)` answered *every* codepage with the same
  `CP_UTF8`-marked stub — and cached it by section type alone, so a second
  distinct codepage would have got the first one's view. `RtlInitCodePageTable`
  short-paths on that marker, so the conversion ran as UTF-8 under whatever
  codepage the guest had named. The C runtime asks for **20127** (US-ASCII, its
  default single-byte locale), round-trips all 256 byte values through
  `MultiByteToWideChar`/`WideCharToMultiByte` into 256-byte buffers, and UTF-8
  needs 384 bytes for the return leg — hence
  `err:msvcrt:create_mbcinfo … ret=0 (exp 256), error=122`, and hence empty
  `mbctype` tables in every guest that touches the CRT.
- **The surface was measured, not guessed.** A new `EXEMU_NLS_TRACE` seam logs
  every `NtGetNlsSectionPtr(type, id)`. Over a full Wine boot of both WoW64
  corpus binaries the complete request set is four calls: sort, case,
  normalisation, and codepage **20127** (six times) — nothing else. On the
  emulated path the two conversion APIs are reached 11,311 times, every one of
  them with `CP_ACP`, which is UTF-8 there because `GetACP` reports 65001.
- **What is supported, and what is refused.** exemu now builds a real
  `C_#####.nls` image for **20127**, **28591** (ISO 8859-1) and **1252**
  (Windows ANSI) — one generator, all three bijections on their defined range,
  so the reverse direction needs no best-fit guessing. Every other codepage is
  refused with `STATUS_OBJECT_NAME_NOT_FOUND`, exactly as a missing `.nls` file
  would be, and surfaces to the guest as `ERROR_INVALID_PARAMETER`. The DBCS
  codepages (932, 936, 949, 950, 1361) are deliberately out of scope: their
  tables are real `.nls` data the pinned prefix does not ship, and an
  approximation would corrupt text silently. **A wrong conversion is worse than
  a refused one, and a silently-empty table is worse than both.**
- The table format was recovered from the pinned `ntdll.dll` itself —
  `RtlInitCodePageTable`, `RtlCustomCPToUnicodeN` and `RtlUnicodeToCustomCPN` —
  and `crates/os/tests/nls_abi.rs` re-derives every offset from the binaries on
  each run, so a prefix refresh that reshapes the table fails a test instead of
  quietly mis-converting text.
- exemu's own `WideCharToMultiByte`/`MultiByteToWideChar` thunks now convert
  through the same tables, so the emulated and the Wine path cannot disagree,
  and `lpUsedDefaultChar` is answered honestly.
- Corpus: 7-Zip byte-identical; the two Wine rows *fall* — SteamSetup
  −29,799 and Firefox −14,762 instructions — because the failed conversions,
  their `err:`-channel formatting and msvcrt's fallback no longer happen.
### Where the comctl6 side-by-side assembly actually is (W6.1, diagnosis)
- With Wine's own debug channels on, a WoW64 guest that asks for themed controls
  reports `fixme:actctx:parse_depend_manifests Could not find dependent assembly
  "Microsoft.Windows.Common-Controls" (6.0.0.0)`, and the process ends up with no
  activation context at all. **The fallback is material:** Wine 11.0 ships two
  comctl32 builds, and the pinned prefix has both — only `comctl32_v6.dll`
  compiles the themed replacements for the user32 built-ins (Button, ComboBox,
  Edit, ListBox, Static) plus SysLink and TaskDialog, and only it delay-imports
  `uxtheme`. Without the assembly a guest gets the v5 build.
- **The prefix does ship the assembly**; it is simply never materialised. Wine
  embeds it in the v6 DLL as an `RT_MANIFEST` resource *named* `WINE_MANIFEST`,
  and writes the WinSxS store from it at prefix-creation time. exemu has never
  run that step. `crates/app/tests/sxs_assembly.rs` pins the recovery half — the
  resource is there, exemu's loader already reads and parses it, the v5 build
  publishes none, and the exact WinSxS key Wine would look for.
- Staging that store by hand surfaced a **real bug one layer down**:
  `FILE_BOTH_DIR_INFORMATION.FileName` sits at +0x5E (after `ShortName[12]`),
  not at the +0x60 struct size, so every filename Wine reads back from
  `NtQueryDirectoryFile` is empty. Not fixed here — it is in `crates/os` — but
  recorded with its reproduction. No lookup was faked and no half-working store
  was landed.

### PE sections are mapped from their real characteristics, not RWX (W9.5)
- **The loader used to map every section — and the PE header page —
  read/write/execute**, on the recorded theory that "running arbitrary binaries
  matters more than reproducing page-permission enforcement". It maps each one
  from its own `IMAGE_SECTION_HEADER.Characteristics` now: code is not writable,
  data is not executable, resources and `.pdata` are read-only, and the header
  page is writable (packers rebuild import tables there) but never executable.
- **The theory it replaces was wrong about its own counter-example.** The
  corpus's self-modifying guest is the UPX-packed Firefox stub, which
  decompresses over its own image and jumps into it — and UPX *marks* `UPX0` and
  `UPX1` `MEM_READ|MEM_WRITE|MEM_EXECUTE`. An honest mapping hands a packer
  exactly the pages it asked for; it is only the ordinary MSVC image that stops
  being a `W^X` hole. Pinned both ways in `crates/app/tests/section_perms.rs`.
- **One documented departure, because a real gap sits under it.** The section
  carrying the **import address table** is mapped writable even when the linker
  marked it read-only. exemu's own binder does not need that (it patches IAT
  slots with the privileged `Memory::poke`), but on the `--wine-boot` path the
  loader binding those slots is *guest* code — Wine's i386 `loader_init` —
  which brackets the write with `NtProtectVirtualMemory(PAGE_READWRITE)`.
  exemu's implementation of that syscall is **nominal**: it records the
  requested `PAGE_*` for `VirtualQuery` to report and never changes a real
  permission (nothing in the tree calls `Memory::protect`). Without the
  carve-out, Wine's loader dies on its first IAT store — measured on
  `SteamSetup.exe`, one 4-byte write to `0x408070` in its read-only `.rdata`,
  after which the 32-bit loader never gets past kernel32/kernelbase.
- **This supersedes the "exemu maps PE sections RWX" justification** recorded
  under the block-JIT work below. The per-*page* code-generation counter is
  still the right precision, but for the narrower reason that a genuinely
  writable-and-executable section (a UPX stub) exists at all.
- Corpus **11/11** with every count unchanged to the instruction, 7-Zip's three
  rows included; **981 tests** (976 + 5), clippy clean at `-D warnings`.

### Breakpoints and watchpoints are honoured in compiled code (W9.3)
- **The JIT's whole contribution to the debugger is a negative guarantee** —
  never run past an armed address — not a second breakpoint implementation. It
  still cannot report a hit, get the reported `rip` wrong, or disagree with the
  interpreter about which instruction was reached, because it never decides:
  every stop is decided at the run loop's head, the one point the interpreter
  path and the compiled chain converge at.
- **Arming a breakpoint splits a block; it does not de-optimise one.** The
  compiler is handed the next armed address and ends the block *before* it, so
  the instructions in front of a breakpoint still run as native code and the one
  at it is interpreted. A breakpoint at a block entry compiles to nothing, which
  already means "the caller interprets this one". The block cache is keyed on the
  debug handle's generation, so arming or disarming costs a flush at human speed
  and nothing per block.
- **A compiled block refuses a watched access rather than performing it.** Two
  memory helpers are swapped in behind the function pointers a block already
  calls through — no emitted-code change at all — and they return a fault
  *before* the access, so the block rewinds having changed nothing and the
  interpreter performs it, records the hit and reports it. The access happens
  exactly once, on the reference engine. The guest-memory fast path is disabled
  while anything is watched, so it cannot cache a page and thereby hide a later
  access on it.
- **Attaching is still free.** With nothing armed the emitted code is
  byte-identical and the block count, the link count, the cache-fill count and
  the emitted-byte count are all asserted equal to a detached run. The corpus is
  unmoved: 11 of 11 pins at Δ = 0, with 7-Zip at exactly 496,505,572
  instructions on all three of its rows.
- **A store-only fault used to lose its flags.** A store is the last thing a
  read-modify-write instruction does, so by the time it can fault the flags are
  already computed — and the rewind restored a state that means "emit nothing".
  `inc byte [rdi]` into a read-only page came back with `rflags = 0x2` instead of
  what it went in with, and that value lands in the `CONTEXT` an access-violation
  handler is given. Every data region the differential maps is writable, so a
  faulting store there is always one whose load would have faulted too — and a
  load faults before anything has been computed. An armed data watchpoint is the
  first thing that can fault a store whose load succeeded, which is how this
  surfaced. Fixed; the block frame now carries a small flag-state spill for it.
- **The differential grew a debugger dimension.** Every trial can arm one
  breakpoint or one watchpoint, and the expected instruction count is computed
  from the *interpreter's* trace, so a JIT that "honoured" a breakpoint by
  refusing to compile would fail rather than pass. Zero divergences over 500,000
  trials per bitness in each of the plain, breakpoint and watchpoint modes, on
  both the low and the address-boundary layouts.

### Wine's debug channels resolve through Wine's own mechanism (W6.4)
- **What a `TRACE()` costs in a Wine builtin is decided by a per-process array
  exemu never wrote.** Every channel is a 16-byte `{ unsigned char flags;
  char name[15]; }` object in the DLL's `.data`, shipped with `flags = 0xff` —
  bit 7 is a "not resolved yet" sentinel, and bits 0–3 are the classes
  `fixme, err, warn, trace`. A guard is a bare `test byte [chan], 1<<class`, so
  an unresolved channel reads as *every class on* and takes the logging branch.
  The branch calls `ntdll!__wine_dbg_get_channel_flags`, which looks the channel
  up in the array and **caches the answer back into the object**, after which
  every guard on it is one failing `testb`. exemu is what stands in for
  `ntdll.so`, so exemu has to write that array.
- **The array's address differs between the two bitnesses**, and that had gone
  unnoticed: `ntdll.dll` x86-64 computes it as `lea rdi,[peb+0x2000]` and
  `ntdll.dll` i386 as `lea ecx,[peb+0x1000]`. exemu wrote a zeroed page at
  `PEB64+0x2000` and nothing at all at `PEB32+0x1000` — where the **WoW64
  CPU-reserved area** happened to sit, so every 32-bit builtin resolved its
  channel flags out of the live 32-bit register save area. Measured: the byte
  read as `0x00` most of the time and `0x01` after a mode switch had left the
  reset-state flag set. The WoW64 block now spaces `PEB32` the way it spaces
  `TEB32` (whose `+0x1000` is `__wine_dbg_strdup`'s per-thread ring), and
  `wow64_boot.rs` carries a layout test that fails if anything is placed on
  either region again.
- **The default is `err+fixme`, not "all off"** — recovered, not assumed. Each
  builtin carries a fallback resolver for the case where ntdll's export is
  unreachable (i386 `user32!fallback__wine_dbg_get_channel_flags`); it parses
  `WINEDEBUG` against its own `fixme,err,warn,trace` table and falls back to a
  `default_flags` byte that **ships as `0x03`**. That is the documented
  `wine(1)` default. exemu's zeroed page meant `0x00`, i.e. Wine's own
  diagnostics were silently suppressed; `exemu run --trace` now shows them.
- **`WINEDEBUG` works.** `exemu_os::winedebug` parses the documented syntax
  (`[class][+|-]channel,…`, `all` for the default) and publishes the array for
  both PEBs, sorted by name because ntdll binary-searches it and always
  terminated so ntdll cannot walk past it.
- **New `crates/app/tests/wine_debug_abi.rs`** re-derives all of it from the
  pinned binaries on every run: the sign test that makes `0x80` the sentinel,
  both PEB offsets and the `shl 4` stride, the `{0xff, name}` shape of every
  `__wine_dbch_*` in user32's data, the class bit order, the shipped `0x03`
  default, and both `__wine_dbg_strdup` ring offsets.
- **Turning them on found a latent marshalling bug.** With `err` live, the
  64-bit Wine boot started faulting *inside* the unixlib: `wine_dbg_write`'s
  params block is `{ const char *str; unsigned int len; }`, and both pinned
  producers fill it with a `movq` for the pointer and a **`movl`** for the
  length (`ntdll!__wine_dbg_write` rva 0x3f440, `__wine_dbg_output` rva
  0x3f300), leaving the slot's upper half as whatever the frame's uninitialised
  stack held. exemu read it as a qword, so a stale upper half made the copy walk
  off the mapped page — the same 32/64 slot trap as `NtUserMessageCall`'s
  `type`. Invisible until now only because nothing ever emitted. Fixed, and
  pinned from the producer's own bytes.
- **Corpus:** the two Wine WoW64 entries move and nothing else does —
  SteamSetup 7,692,064 → **7,712,812** (+20,748), Firefox 14,466,327 →
  **14,480,727** (+14,400), deterministic across three runs. The attribution is
  exact rather than inferred: on the same build `WINEDEBUG=-all` reproduces both
  old pins to the instruction, so the whole delta is Wine's `err`/`fixme`
  channels doing work a real Wine process does, and the layout move contributes
  nothing. The eight non-Wine entries, 7-Zip's 496,505,572 included, are Δ0.

### `NtUserMessageCall` dispatches on an allow-list (W6.3)
- **`NtUserMessageCall` is not a family of sends.** The `type` argument in its
  6th slot selects one of 19 members, and only nine of them deliver a message to
  a window procedure. exemu used to dispatch every *unrecognised* type to the
  target window's WndProc, which is a self-feeding loop rather than a
  conservative default: `user32!DefWindowProcW` brackets every message with
  `SPY_EnterMessage`/`SPY_ExitMessage`, and each of those is another
  `NtUserMessageCall` — so answering one of them with a send re-delivers the
  message that is already being handled. Measured on `SteamSetup.exe` for the
  one member that was already named (`SpyGetMsgName`): 461 nested callbacks in
  ~200k instructions, into a 2 MiB stack overflow.
- **The whole type space was recovered from the pinned Wine 11.0 PE set**, not
  from a header. Every caller fills the slot with a `mov dword ptr [rsp+0x28],
  imm32` (i386: `[esp+0x14]`) right before the win32u thunk, so sweeping each PE
  that imports `NtUserMessageCall` enumerates it; the 64-bit and 32-bit builds
  agree entry for entry. The members and the routine that issues each:
  `0x29a` `USER_ScrollBarProc`, `0x29c` `PopupMenuWndProc`, `0x29d`
  `DesktopWndProc`, `0x29e` `DefWindowProc`/`NC_HandleSysCommand`, `0x2ab`
  `CallWindowProc`, `0x2b1` `SendMessage`, `0x2b3` `SendMessageTimeout`, `0x2b7`
  `SendNotifyMessage`, `0x2b8` `SendMessageCallback`, `0x300`
  `explorer!clipboard_wndproc`, `0x303`/`0x304` `SPY_Enter`/`ExitMessage`,
  `0x305` `imm32!ImeProcessKey`, `0x306` explorer's systray, `0x308`
  `post_dde_message`, `0x309` `wintab32!WTInfoW`, `0x3001` `dispatch_message`,
  `0x3002` `SPY_GetMsgName`. `0x307` has **no caller in the pinned set** and is
  recovered from `wow64win!wow64_NtUserMessageCall`'s own switch instead.
- **Three dispositions, no fall-through to a WndProc.** The five kernel-side
  window procedures (`DefWindowProc` and the scroll-bar / menu / desktop /
  clipboard procedures) run exemu's own `def_window_proc`; the four sends plus
  `dispatch_message` and `CallWindowProc` reach a procedure; everything else —
  the spy hooks, the IME / systray / tablet driver calls, the DDE post, and any
  type this build has never seen — answers the module's honest zero, the same
  clean "no object" `honest_stub` gives.
- **Two new pins in `crates/app/tests/win32k_abi.rs`**: one asserts each named
  type against the routine that issues it, the other sweeps every `.pdata`
  function of all five pinned PEs that import the syscall and fails if any of
  them issues a type exemu does not name. Three unit tests in
  `crates/os/src/win32k.rs` pin the behaviour itself, including that an unknown
  type installs no callback frame. Corpus Δ0 on all ten entries.

### comdlg32's file dialog, measured and root-caused (W6.2)
- **A guest actually calls `GetOpenFileNameW`** now — `crates/app/src/
  comdlg_sample.rs` generates a console PE that statically imports
  `comdlg32!GetOpenFileNameW`/`GetSaveFileNameW`/`CommDlgExtendedError`, fills a
  real x64 `OPENFILENAMEW`, and then **opens the path it is handed** with
  `CreateFileW`/`ReadFile`, so a bridge returning a string the guest's own
  filesystem view cannot resolve would fail visibly rather than silently pass.
- **The call reaches Wine's own comdlg32**, proven positively rather than
  assumed: a third leg repeats the call with a deliberately invalid
  `lStructSize` and gets back `CDERR_STRUCTSIZE`. exemu implements no
  `OPENFILENAMEW` validator anywhere, and the emulated path — where the import
  is a recognised-but-unimplemented thunk — answers 0 for the same call.
- **The dialog does not open, and `crates/app/tests/comdlg_gate.rs` pins exactly
  where it stops.** The healthy call passes validation *and* finds, loads and
  locks comdlg32's own dialog template (`CommDlgExtendedError() == 0`, i.e.
  neither `CDERR_FINDRESFAILURE` nor `CDERR_LOADRESFAILURE`), then
  `DialogBoxIndirectParamW` fails **with not one window reaching the driver**.
- **Root cause**, from a `EXEMU_W32K_TRACE` transcript of the failing call:
  user32's dialog manager names the dialog class the way Windows does — by its
  well-known integer atom `MAKEINTATOM(32770)` = 0x8002 — resolves it with
  `NtUserGetAtomName` and hands the resulting string to `NtUserGetClassInfoEx`.
  exemu's win32k SSDT has no `NtUserGetAtomName` handler, so the name comes back
  empty, the class lookup fails client-side, and creation aborts before
  `NtUserCreateWindowEx`. The gate recovers the three syscall indices involved
  from `win32u.dll`'s own export stubs, so a prefix refresh that renumbers the
  SSDT fails the test instead of quietly invalidating the analysis.
- **Fidelity decision for W6.2: let Wine render its own dialog**, not a native
  `NSOpenPanel`. Verified experimentally that the gap is one SSDT handler wide —
  with an `NtUserGetAtomName` that answers the documented integer-atom rule,
  Wine builds its real `#32770` "Open" window with its own `Static` "Look &in:"
  and `ComboBox` children (and then meets a separate guest-stack-depth problem
  in the nested creation callbacks). A native panel would need a new intercept
  seam and would discard every `OPENFILENAMEW` semantic — filters, `OFN_*`
  flags, hook procs, custom templates, `nFileOffset`/`nFileExtension` — that
  Wine's dialog implements for free.

### Per-exe profiles (W9.4)
- **`exemu run --profile <path>`** loads a TOML `[profile]` table of run
  settings — `max_steps`, `sandbox_root`, `wine_boot` (Wine prefix), `dpi`,
  `backend` (`headless`/`window`), `jit`, `virtual_clock`, `trace`, `audio`,
  extra guest `args`, and the exe's own `path` — so a known-good binary runs
  without remembering flags. Extends `corpus.toml`'s existing idea rather than
  inventing a second mechanism: a new shared module (`crates/cli/src/
  toml_lite.rs`) carries the tiny hand-rolled value parser both `corpus.rs`
  and the new `profile.rs` use, so a profile is a second **vocabulary**
  (settings only, no pinned outcome), not a second parser. Merge order is
  built-in default < profile file < explicit CLI flag/positional argument, so
  any flag typed on the command line still wins. `profiles/7z2602-x64.toml`
  is a worked example mirroring the corpus's own known-good settings for the
  one binary that installs end to end.
- **Two settings that did not exist as CLI-observable knobs before this**, now
  added alongside the profile mechanism: `--sandbox-root <path>` (previously
  only settable in-process via `RunConfig::sandbox_root`, e.g. by tests and
  the corpus runner's private-`TMPDIR` isolation) and `--dpi <n>` (new
  `WinConfig::dpi` field, wired to exactly `NtUserGetSystemDpiForProcess` and
  `NtUserCallHwnd`'s `GetDpiForWindow` selector — **not** to the
  `EnumDisplaySettings`/`DEVMODE` device mode, which still reports a fixed 96
  from the display driver's `DisplayMode`; the two can disagree, and the
  profile module docs say so).
- Fixed a latent bug this surfaced: `cmd_run`'s "files created" report computed
  its own sandbox path independently of `RunConfig::sandbox_root`, so setting
  a custom sandbox root would have made the end-of-run file listing silently
  report the wrong (empty) directory. Now derived from the same
  `cfg.sandbox_root` the run itself used.
- Drag-and-drop groundwork for the W9.7 `.app` (see below): `exemu` invoked
  with a bare file path and no subcommand — exactly how macOS delivers a
  Finder drag-onto-the-icon or double-click to a bundled, non-AppKit
  executable — now dispatches as `exemu run <path>` instead of erroring
  "unknown command".

### The JIT's guest memory path, inlined (W8.6)
- **7-Zip `--jit` goes from 22.0 G to 10.4 G retired host instructions — −53% —
  and from 0.79 s to 0.44 s of CPU**, on exactly the same 496,505,572 guest
  instructions. Measured interleaved in one session, 5 reps, min user+sys, with
  every binary built and alternated; the same binary spans 0.79–0.84 s (and one
  arm 0.76–0.98 s) depending on machine load, while the instruction count varies
  by under 0.15%, which is why that is the number quoted.
- **Profiled rather than guessed.** Sampling put 249 of 614 main-thread samples —
  **40% of the whole process** — in the guest memory helpers. Afterwards it is
  2–3 of 126, with the bulk of the run in emitted code.
- **A guest load or store no longer calls into Rust.** Emitted code carries a
  direct-mapped cache of host addresses and does the access itself in seven
  instructions with no call, no spill and no `Result` returned through memory. A
  miss falls into exactly the helper sequence that was there before.
- **The seam that made it possible did not weaken anything.** `exemu-core` and
  `exemu-memory` both keep `#![forbid(unsafe_code)]`, untouched: the new
  `Memory::host_span` / `host_span_mut` return **safe slices**, so the backend
  writes no `unsafe` and the compiler checks the bounds of what it exposes.
  Turning one into a pointer that outlives the borrow is the JIT's explicit
  `unsafe`, in the one crate that has ever been allowed it.
- **Four invariants, each enforced where it cannot be forgotten.** A span is
  refused for anything that would fault, so a fault still lands on exactly the
  instruction it did before; a *writable* span is never handed out over
  executable memory, so every store that could rewrite compiled code keeps going
  through the self-modification checks; nothing is handed out at all while a data
  watchpoint is armed, so an armed watchpoint still sees every access; and
  `Memory::layout_generation` moves for every map, unmap and re-protect, so a
  cached host address cannot outlive the bytes it points at. The JIT checks all
  of that **once per `Jit::run`, never per access** — detached, that is a field
  load and a null test per chain.
- **The differential could not execute the new fast path at all, and now can.**
  Every region the JIT-vs-interpreter harness mapped was exactly one page, and a
  page was then only cached when its whole page plus seven bytes was inside one
  region — so 3,000 trials filled **zero** cache entries. The "zero divergences" that
  first accompanied the fast path was true and worth nothing. Region roominess is
  now drawn per trial, so half the trials keep the tight one-page regions the
  fault shapes depend on and half have the slack the fast path needs: 1,203
  entries filled in the same 3,000 trials.
- 0 divergences in 2M differential trials across both address-space layouts and
  both bitnesses with the fast path engaged; corpus 11/11 at drift 0; workspace
  tests 940 → 960, clippy clean at `-D warnings`.

### Native block linking and indirect-branch inline caches (W8.5)
- **7-Zip `--jit` goes from 0.95 s to 0.76 s of CPU — 28.5 G to 21.7 G retired
  host instructions — on exactly the same 496,505,572 guest instructions and the
  same 108 artifacts.** A compiled block's exit no longer returns to Rust to be
  told where to go next: when the target is a compile-time constant (a
  fallthrough, a `jmp rel`, either edge of a `j<cc>`, or a `call rel32`) it reads
  a cached pointer to the successor's body and branches straight into it, so a
  run of blocks executes as one straight line of native code — **95.8% of block
  entries (78.0 M of 81.4 M) on that run**, out of only 1,501 distinct filled
  slots. Measured interleaved — both binaries built, alternated in one session, min user+sys over
  five runs each — because the same binary spans a wide range depending on what
  else the machine is doing.
- **Indirect branches get an inline cache.** `call r/m` and `jmp r/m` — every
  import-table call, every virtual call, every jump table — read the same slot,
  which also records *which* guest address it cached a block for, and take the
  link only if the address the guest just produced matches. On the Wine WoW64
  path that removes **31%** of the returns to the interpreter (247,909 → 171,618)
  and takes blocks-per-chain from 7.5 to 10.8. On 7-Zip, whose hot path is an
  LZMA loop with almost no calls in it, it removes only 3,354 of 3.42 M and costs
  ~1% in emitted-code size — recorded rather than buried, because the cost is
  fixed per call site compiled and the benefit scales with how often that site
  runs.
- **The budget moved into the emitted exit, and that is a correctness property.**
  A chain adds each block's instructions to a running total and stops at the
  first block boundary at which the total has reached what the caller allowed —
  the same boundary the block-at-a-time loop stopped at. Timeslice preemption,
  the `KUSER_SHARED_DATA` clock refresh and the step cap therefore still fire at
  the identical guest instruction, and the corpus stays **10 of 10 with zero
  drift**, SteamSetup's exact fault address and count included.
- **Unlinking is one increment.** Every slot carries the engine's link epoch and
  is taken only while it still matches, so retiring every link at once is a
  single `+= 1` — no walk over the array, no patching of emitted code, no
  instruction-cache maintenance. A code-cache flush does it; so does a store the
  guest makes into a page a compiled block was built from, which is checked on
  every store against a page-hash table because a linked chain has no Rust
  between blocks to notice. Without that a chain could store into a block further
  down its own links and then execute the stale copy.
- **The differential learned to run round a loop** (`exemu-oracle jit --laps K`),
  because every trial it had ever generated walked each of its blocks exactly
  once — the one case in which a link is never *taken*. 0 divergences in 800 k
  lapped trials with 1.42 M block entries reached by a native link, plus 2 M
  straight trials across both bitnesses and both layout mixes.

### The block JIT (W8.2 / W8.3 / W8.7)
- **7-Zip installs in ~2.4 s instead of ~16.6 s — 7× faster — executing exactly
  the same 496,505,572 instructions and producing the same 108 artifacts.**
  `exemu run --jit` (or `EXEMU_JIT=1`) compiles guest basic blocks to native
  ARM64; it is **off by default** and every corpus pin is still measured on the
  interpreter. Whole-corpus A/B, same binary, virtual clock, two passes each:
  7-Zip 19.7/16.6 s → 3.5/2.4 s, SteamSetup 3.3/3.4 s → 1.44/1.46 s, Firefox
  Installer 0.19/0.17 s → 0.16/0.16 s. Every run matched the interpreter's exit
  code, instruction count, fault site, register dump and artifact count exactly.
- **The A/B is now a standing gate, not a one-off measurement.** `corpus.toml`
  gains a `jit` field and three **twin entries** — the same binaries through the
  JIT, pinned to exactly the interpreter entries' numbers. `exemu corpus` runs
  8 of 8 green: 7-Zip `exit 0` @ 496,505,572 / 108 artifacts on both engines
  (19.8 s vs 2.2 s), SteamSetup `fault @ 0x20001c2c` @ 92,865,377 / 3 on both
  (3.2 s vs 1.4 s), Firefox `fault @ 0x0` @ 4,665,426 / 1 on both. A difference
  between a twin pair — one instruction, one artifact, a moved fault — fails the
  gate.
- **The opcode slice was measured, not guessed.** A new feature-gated build
  (`--features opcode-profile`, `exemu run --opcode-profile`) counts every
  instruction *shape* — opcode, `0F` escape, `REX.W`/`66`, group sub-opcode —
  that a real run executes. 7-Zip: 161 distinct shapes, top 20 = 72% of the
  stream, top 60 = 99.8%; `mov r,r/m` alone is 12%, `shr imm` 7%, `jae rel8` 6%.
  No SSE, no x87 and no push/pop in the top 60. The JIT compiles that head of
  the distribution and **side-exits to the interpreter for everything else** —
  which is why ~20 opcode families cover **99.3%** of the 7-Zip run.
- Compiled: the integer ALU in all six operand forms, group 1, `test`, `mov`,
  `lea`, `movzx`/`movsx`/`movsxd`, `imul`, constant-count `shl`/`shr`/`sar`,
  `inc`/`dec`, `neg`, `not`, `cmov<cc>`, `push`/`pop`, and `j<cc>`/`jmp` as
  compiled block terminators (so the hot loop never returns to the interpreter
  for a branch). Deliberately **not** compiled: SSE/x87/AVX, `syscall`,
  `call`/`ret`, string ops, `adc`/`sbb`, rotates, `mul`/`div`, `LOCK`/`REP`,
  and `fs:` in 64-bit mode.
- **Bit-for-bit or nothing.** A second differential oracle
  (`exemu-oracle jit`, and in the ordinary test gate) runs generated blocks
  through the JIT and the interpreter and compares the *entire* architectural
  state — every GPR, every `rflags` bit **including the ones x86 leaves
  undefined**, `rip`, XMM/YMM/x87, and every byte of guest memory. There is no
  defined-flags policy because the reference is the interpreter, not another
  CPU. **0 divergences in 8.3M trials per bitness** across ten configurations
  (1, 8, 24 and 32 instructions per block; ten seeds).
  It also proves that a declined block changes nothing, and that a block which
  faults rewound onto an instruction that really does fault. The harness was
  validated by injecting a one-bit AF bug, which it caught in 2,000 trials.
- **Two JIT bugs at the edge of the address space (W8.7).** Both were found by
  auditing the JIT's address masking against the interpreter's, and neither was
  a masking bug: the masking turned out to be right everywhere, and is now
  pinned in both directions (32-bit must truncate, 64-bit must not) by
  `crates/jit/tests/address_width.rs`.
  - **The compiler decoded its own padding.** Where a 16-byte instruction fetch
    overruns the region, the window is refilled byte by byte — but `decode` was
    handed the whole window, zeros included. At the tail of an executable region
    that *fabricates* an instruction the guest does not have: `8B 05` plus four
    bytes of padding compiled as `mov eax, [0]` and succeeded, where the
    interpreter faults fetching the third byte. `decode` now sees only the bytes
    that were really fetched, so an over-long encoding is simply declined.
  - **A block ending on the 4 GiB boundary reported an empty byte range.** The
    store helper decides "this store rewrote an instruction I have not run yet"
    by comparing against the block's `code_lo..code_hi`, and `hi` came from the
    address the block *ends* at — which for such a block has wrapped round below
    its own start. Clamped, the range collapsed to nothing, no store could ever
    hit it, and the block carried on executing instructions the guest had just
    overwritten. The range is now derived from the block's *length*, and the
    compiler stops a block at the wrap (`StopReason::Wrapped`) so a block stays
    one contiguous range — which is what both that check and the two-page code
    generation check assume.
- **Where a trial is assembled is now part of the trial (W8.7).** Every trial
  used to be built at the base of a low page, which made the differential
  *structurally* blind to the address-width rule: in 32-bit mode every
  architectural address is masked to 32 bits (`rip` after any instruction, a
  branch target, an effective address, `esp` across a push or pop) and in
  64-bit mode none of them is, so a trial that never computes an address near
  2^32 cannot tell a CPU that masks from one that does not. A trial now also
  picks a **layout** — `edge-code` (32-bit code flush against 2^32 with page
  zero mapped, or 64-bit code above 4 GiB where the rule is the opposite),
  `edge-data` (low code, but `esp` and the base pointer on the boundary), or
  the historical `low` — selected by `--layout low|edge|mixed`. The generator
  also emits **push/pop/leave, `push imm`, near branches and `[rbp+disp]`
  accesses**, none of which the single-instruction stream shared with the
  Unicorn oracle contains: it has no control flow and never touches the stack.
  This is what surfaced the two JIT bugs above; neither was reachable before.
- **The trials were not as independent as their count suggested.** They were
  seeded `Rng::new(base ^ index * GOLDEN)`, and `Rng` is itself counter-based,
  so trial *i*'s draw sequence was trial *i+1*'s **shifted by one** — a whole
  run sampled one shared sequence at different offsets, and nearby indices could
  assemble byte-for-byte identical trials. `Rng::for_trial` runs the mixing
  finalizer over the counter first; pinned by a test that asserts the old
  derivation really was a shift and the new one shares no draw.
- Volume after the fixes: **0 divergences in 1.25M trials per bitness** — 500k
  mixed-layout, 500k boundary-layouts-only, and 250k single-instruction blocks,
  across three seeds (2.5M trials in all) — and 7-Zip still retires exactly
  496,505,572 instructions under `--jit`, so neither fix moved the pin.
- Two rules make faults exact with no error plumbing in compiled code: nothing
  is committed to guest state before a faulting access, and a fault **rewinds**
  — `rip` returns to the faulting instruction and the *interpreter* re-executes
  it, raising the real `EmuError` with the same message, address and partial
  state the fault reporter expects. SteamSetup's known fault reproduces through
  this path exactly, register for register.
- **First consumer of the W1.7 self-modifying-code seam.** A store into the
  running block's own bytes commits that instruction and stops the block; between
  blocks, cached blocks are validated against the *per-page* code generations.
  The page precision is not an optimisation but a necessity: exemu maps PE
  sections RWX, so an ordinary store into `.data` moves the global counter — and
  treating that as "code changed" measured **40× slower than the interpreter**
  on SteamSetup before the fix. Pinned by three tests.
- **Two traps found by reading rather than by a failing test**, both fixed with
  a pin. (1) The block cache is keyed by `(address, CPU mode)`, not by address:
  a 32-bit guest on Wine's 64-bit PE set starts on a *64-bit* trampoline and
  switches modes at every transition, so a mode fixed at load time would have
  decoded 64-bit code as 32-bit, silently. (2) `Hooks::intercept` is not only
  the API-thunk seam — the OS layer uses "called once per instruction" as its
  **timeslice clock**, so a JIT-compiled spin loop would never yield and a
  compute-bound guest thread would starve the others. New `Hooks::retire(n)`
  (default no-op) reports what a block ran; the JIT variant of the preemption
  test fails without it.
- **`crates/jit` is the only crate in the workspace that is not
  `#![forbid(unsafe_code)]`**, and the relaxation is bounded on purpose: the
  whole foreign surface is four declarations (`mmap`, `munmap`,
  `pthread_jit_write_protect_np`, `sys_icache_invalidate`), each `unsafe` block
  is one call with its precondition stated above it, every one is covered by a
  test that *executes* the result, and `#![deny(clippy::undocumented_unsafe_blocks)]`
  keeps it that way. The instruction encoder — where a codegen bug would live —
  is ordinary safe Rust. Compiled code reaches guest memory only through the same
  `Memory` implementation the interpreter uses, so it cannot touch a host address
  the interpreter could not. `MAP_JIT` needs the
  `com.apple.security.cs.allow-jit` entitlement once exemu ships as a notarized
  `.app` (W9.7).

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

#### Child processes (W3.5)
- **`CreateProcessW` works, through Wine's own kernel32/kernelbase.** The guest
  path is entirely Wine's: `CreateProcessInternalW` →
  `RtlCreateProcessParametersEx` → `create_nt_process` →
  **`NtCreateUserProcess`** → `NtResumeThread`; exemu supplies the syscalls and
  the run. `GetExitCodeProcess` is likewise Wine's, over exemu's new
  `NtQueryInformationProcess(ProcessBasicInformation)`.
- **A child is a second complete emulator instance** — its own address space,
  `WinOs` and interpreter — *prepared* by `NtCreateUserProcess` and *started*
  when its initial thread is resumed. That is the seam Wine actually uses:
  kernelbase creates every child with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` and
  resumes it as the last step, so `CREATE_SUSPENDED` and the plain case are both
  correct without exemu guessing.
- **The handle semantics are the real ones**: a process/thread handle pair from
  the same space `CloseHandle` routes, `WaitForSingleObject` that is unsignaled
  until the child exits, `PROCESS_INFORMATION.dwProcessId` from the output
  `PsAttributeClientId`, and the child's own exit code read back. The child
  inherits the parent's console and environment block.
- **The honest limit:** the run is **synchronous**, so parent and child are never
  alive at once — a pipe handshake or a cross-process event cannot work, and no
  code pretends otherwise. Out-of-scope requests return a real NTSTATUS rather
  than a plausible success: a debug port, a job list, a token
  (`CreateProcessAsUser`), a foreign parent, a non-AMD64 machine type, an
  explicit handle list, and std handles that are not the console sentinels a
  fresh address space can honour. A child the *emulator* fails to run reports
  `STATUS_UNSUCCESSFUL` plus a verbatim report on the parent's stderr — never an
  invented exit code.
- **GATE:** a generated parent PE calls `CreateProcessW` on a generated child PE,
  waits on the handle and reads back the child's exit code (91, a value only the
  child knows) — 563,877 instructions on the Wine boot, 1,654 on the emulated
  path as the control, both `SPAWN OK`. Every offset, index and flag bit is
  re-derived from the pinned binaries on every run by `process_abi.rs`.
- **Measured, and honest about it: neither corpus installer is unblocked.**
  Total Commander still exits 1 after ~4.06M instructions on the Wine boot
  (~22k emulated) having created **zero** processes — the same numbers W6.5
  pinned. SteamSetup is a PE32, so the x64-only Wine boot cannot reach Wine's
  `CreateProcessW` for it at all, and on the emulated path it faults at the same
  known site ~92.86M instructions in, with `CreateProcess` never called (verified
  by tracing every intercepted API). The corpus gate is 4/4 after this change,
  7-Zip byte-identical at 496,505,572.

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

### A WoW64 process creates real 32-bit threads (W5.11)

`NtCreateThreadEx` used to answer `STATUS_NOT_IMPLEMENTED` in a WoW64 process,
because a 32-bit thread is not a thread with a smaller stack: it is a *64-bit*
thread that enters `wow64!Wow64LdrpInitialize`, which builds that thread's own
BOP and `WOW64INFO` links and then runs `for(;;) BTCpuSimulate()`. exemu now does
that per thread and supplies what a kernel owes each one — a **sub-4 GiB** 32-bit
stack (one from the 64-bit `VirtualAlloc` arena reaches the guest as its low half,
which is how `Firefox Installer.exe`'s worker died on its own `push ebp` at
`0x12fef8`), a TEB64/TEB32 pair in one low block so the signed 32-bit
`WowTebOffset` spans it, and its own CPU-reserved area seeded with the i386
start convention (`Eax` = entry, `Ebx` = argument).

- **The scheduler now carries the CPU mode across a switch.** `CpuState` has no
  `bits` field — the mode lives in the interpreter — so a context switch swapped
  registers and left the incoming thread running the *outgoing* one's mode. In a
  WoW64 process that is fatal in one instruction: a fresh thread's entry is
  `Wow64LdrpInitialize` at `0x7_0000_2ce0`, which a 32-bit CPU truncates to
  `0x2ce0`. This was latent for any multithreaded WoW64 process.
- **`Firefox Installer.exe` on `--wine-boot`: 12,467,176 → 14,466,116**
  instructions, still a clean exit 1 with zero exceptions delivered. Corpus pin
  re-blessed at zero tolerance over three identical runs; 7-Zip unchanged at
  exactly 496,505,572, corpus 10 of 10.
- The negative pin flips with its control kept:
  `a_wow64_process_refuses_to_create_a_thread` becomes
  `a_wow64_process_creates_a_real_32bit_thread`, plus
  `a_thread_switch_carries_the_cpu_mode` for the scheduler half.

### A 32-bit guest's own window procedure runs (W5.10)

The W5 GUI wall. exemu's win32k *is* the kernel, so every `WM_NCCREATE` it owes
a window it has just created has to leave the kernel the way a kernel leaves it.
In a WoW64 process it could not — it called the 32-bit procedure directly, in
long mode, under the Win64 register ABI, through a return thunk a 32-bit `ret`
cannot reach — so the callback was declined and the window heard nothing. It now
takes the real route, and every hop below the first belongs to Wine:

```
exemu's win32k
  → ntdll!KiUserCallbackDispatcher      (id = NtUserCallWinProc)
  → wow64win!user_callbacks[4]          → wow64!Wow64KiUserCallbackDispatcher
  → BTCpuSimulate                       → ntdll32!KiUserCallbackDispatcher
  → user32(i386)!User32CallWinProc      → the guest's own 32-bit WndProc
  → NtCallbackReturn (SSDT index 5)     → exemu resumes the interrupted syscall
```

exemu contributes exactly three things: `PEB.KernelCallbackTable`, which
`wow64win!DllMain` would publish and this boot never runs (the array is decoded
out of that `DllMain`'s own bytes, not hardcoded); the callback frame and the
`win_proc_params` block; and `NtCallbackReturn`, which restores the non-volatile
registers and `XMM6`–`XMM15` captured when the callback was seated — the chain
unwinds by `longjmp`, so what is live at the return belongs to `wow64win`, not
to the `win32u` frame the syscall must resume into.

- **Gate**: a new PE32 sample registers a class whose `lpfnWndProc` is its own
  32-bit code, creates the window, and checks that `WM_NCCREATE` **and**
  `WM_CREATE` arrived, that the `CREATESTRUCTW` it was handed is 32-bit (its
  `style` at offset `0x20`) and at an address a 32-bit pointer can hold, that a
  `SendMessageW` returned what the procedure returned — the *return* half of the
  round trip — and that `esp` came back unchanged. Exit 71, 3,312,593
  instructions.
- **Every constant is re-derived from the pinned Wine binaries on each run**
  (`wow64_callback_abi.rs`, 8 tests): the dispatcher's frame layout and the
  `PEB+0x58` table, the 25-entry `user_callbacks` array and its publish site,
  `NtUserCallWinProc = 4` (named by `wow64win`'s own COFF symbol table, not
  counted), the 32-bit frame `Wow64KiUserCallbackDispatcher` builds at
  `(Esp − 0x1c − len) & ~15`, the frame `wow64.dll`'s slot 5 fills at
  `TEB64+0x14a8`, and `struct win_proc_params`, whose layout three independent
  consumers have to agree on.
- **Two defects this surfaced.** A `CREATESTRUCTW` parked on the process's
  *64-bit* stack (`0x10_0000_0000`) reached the 32-bit procedure as a truncated
  pointer, and its handles are 4 bytes wide, not 8 — so it now goes in a
  sub-4 GiB scratch in a 32-bit layout. And `NtUserMessageCall` type `0x3002` is
  `SpyGetMsgName`, a *query* for a message's printable name that
  `user32!DefWindowProcW` issues on every message; dispatching it as a send is a
  self-feeding loop that went 461 callbacks deep and overflowed a 2 MiB stack.
- **`SteamSetup.exe` on `--wine-boot` now unpacks its NSIS archive** —
  `Temp/nsa1.tmp`, `nsa2.tmp` — running **30,803,716** instructions, up from
  7,363,620. Its `corpus.toml` pin adds `--virtual-clock`, which sends NSIS down
  a shorter path, and is re-blessed **7,363,620 → 7,692,851** (zero tolerance,
  three identical runs). 7-Zip is unchanged at exactly 496,505,572; the corpus
  stays 10 of 10.
- The negative pin flips: `a_wow64_process_gets_no_creation_pair` becomes
  `a_wow64_process_gets_its_creation_pair_through_a_client_callback`, keeping
  the 64-bit control in the same test.

### Both 32-bit installers stop asking, not crashing (W5.10 / W5.11)

Two WoW64 defects of the same shape — code that decided a guest's *bitness*
from `cfg.is_64bit`, which is `true` in a WoW64 process because the process
genuinely is 64-bit. Neither is fixed by making it 32-bit; both need machinery
that is Wine's, so both are now honest refusals with the faithful path named.

- **A 32-bit client callback is no longer made in long mode.** A 32-bit guest's
  `CreateWindowEx` reaches exemu's win32k correctly, and exemu then seated the
  class WndProc — 32-bit code — with the CPU still in 64-bit mode. On
  `SteamSetup.exe` that was combase's `OleMainThreadWndClass` procedure, whose
  `ff 25 fc d4 e4 02` is `jmp dword ptr [<its own IAT>]` in 32-bit mode and
  `jmp qword ptr [rip+0x2e4d4fc]` in 64-bit: an access violation at `0x5c67b73`
  and a 145-deep exception cascade. Two more defects sit in the same call — the
  Win64 register ABI handed to a `stdcall` procedure, and a return thunk at
  `0x7EFF_0000_0000` that a 32-bit `ret` cannot reach. The faithful route is
  `ntdll64!KiUserCallbackDispatcher` → `wow64!Wow64KiUserCallbackDispatcher` →
  `ntdll32!KiUserCallbackDispatcher`; until exemu speaks that protocol the
  callback is **declined**, so a window is created but hears no `WM_NCCREATE`/
  `WM_CREATE`. **SteamSetup goes from a fault at 6,605,667 instructions to a
  clean exit 2 at 7,363,620, with zero exceptions delivered.**
- **A 32-bit thread is refused rather than mis-spawned.** `Firefox Installer.exe`
  died on `msvcrt!__beginthreadex_trampoline`'s own `push ebp`: the spawned
  thread's stack came from the **64-bit** `VirtualAlloc` arena at
  `0x40_0000_0000`, and 32-bit code sees only its low half (`0x0012_fef8`),
  where nothing is mapped. A 32-bit thread is a 64-bit thread entering
  `wow64!Wow64LdrpInitialize` with its own CPU-reserved area, so
  `NtCreateThreadEx` now answers `STATUS_NOT_IMPLEMENTED` in a WoW64 process
  and the guest's `_beginthreadex` takes its error path. **Firefox goes from a
  fault at 10,950,022 to a clean exit 1 at 12,467,176** — 2.7× the emulated
  path, with all the extra work being Wine's own code.
- **Both are pinned in `corpus.toml`** via a new per-entry `wine_boot = "<Wine
  prefix>"`, which runs an entry with `--wine-boot`. They are separate entries
  from the emulated ones on the same binaries, because the two paths are not the
  same program — and keeping both is what stops an improvement on one from
  masking a regression on the other. Zero tolerance, three identical
  virtual-clock runs each. The corpus is now **10 of 10**, 7-Zip unchanged at
  exactly 496,505,572.
- Both walls are also pinned as unit tests with a passing **control** in the
  same test (`a_wow64_process_gets_no_creation_pair`,
  `a_wow64_process_refuses_to_create_a_thread`), so each fails the day the real
  protocol lands — which is when these claims have to be rewritten.

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
- **The real process boot (W5.4/W5.1/W5.3/W5.5).** `exemu run --wine-boot <dir>`
  pointed at a **PE32** now builds a genuine WoW64 process: Wine's 32-bit
  `ntdll` from the prefix's `i386-windows` half plus the 64-bit
  `ntdll`/`wow64`/`wow64cpu`/`wow64win`, a dual **PEB32/PEB64**, a **TEB pair**
  linked by `TEB64.WowTebOffset`, and the WoW64 CPU-reserved area. exemu then
  hands off to Wine: a 64-bit bring-up trampoline calls the real
  `BTCpuProcessInit`, the real `BTCpuGetBopCode`, publishes the result, and
  enters `BTCpuSimulate`. **Gate: a 32-bit guest allocates memory through the
  entire real chain and writes through the pointer it gets back** — 1,292
  instructions, exit code produced by the guest itself. The synthesized 32-bit
  caller is gone: the stub that runs is Wine's own i386 `ntdll`.
- **The recovery that made it work — and would have been invisible if guessed.**
  Wine's 32-bit `ntdll` does *not* route its syscall stubs through
  `Wow64Transition`. All 526 of them are
  `mov eax,<index>; mov edx,<helper>; call edx; ret <argbytes>`, and that one
  shared helper is `jmp dword ptr [__wine_syscall_dispatcher]`; `wow64.dll`
  publishes `BTCpuGetBopCode()` into **both** names *and* into
  `TEB32.WOW32Reserved` (which the single `call dword ptr fs:[0xc0]` stub —
  `NtQueryInformationProcess` — reads). Publishing only the famous name leaves
  every stub jumping through a null pointer. Every fact here is re-derived from
  the pinned binaries on each test run (`crates/app/tests/wow64_abi.rs`, in the
  `afd_abi.rs` style), including `TEB64+0x180c` = the signed 32-bit
  `WowTebOffset` and the shared 32-/64-bit SSDT index space (258 services
  cross-checked).
- `mov r/m16, Sreg` now reports the flat WoW64 selectors instead of zero.
  `ntdll!RtlCaptureContext` fills `CONTEXT.SegCs` with `mov [rcx+0x38], cs` and
  `BTCpuProcessInit` bakes that word into the return BOP — reporting `0` sent the
  32→64 transition back into 32-bit mode. Mutation-checked: forcing the wrong
  64-bit CS fails the gate.
- New NT services behind the boot: `NtQueryInformationThread(ThreadWow64Context)`
  (class `0x1d` and length `0x2cc` read out of `RtlWow64GetThreadContext`'s own
  bytes) and a native `LdrGetDllHandle`.
- Hardened: delivering a guest exception on a stack pointer below the
  dispatcher-frame size used to *panic* (debug) or build the frame at a wild
  address (release); it is now a reported error.
- *Measured gaps, pinned as tests:* `wow64.dll`'s **table 1** (win32k) is never
  registered because exemu does not run `Wow64LdrpInitialize`, so a 32-bit **GUI**
  guest is not yet supported; only `ntdll` imports are bound for the 32-bit
  guest; and `BTCpuProcessInit`'s `LdrGetDllHandle` is serviced by exemu's own
  loader query rather than Wine's `LdrGetDllHandleEx`.
- **Wine's own 32-bit loader now runs, and `Wow64LdrpInitialize` with it
  (W5.6/W5.7/W5.8).** The default WoW64 bring-up no longer hand-assembles the
  process's own setup: it calls `wow64!Wow64LdrpInitialize`, so Wine's process
  init loads `wow64cpu`/`wow64win`, **`movdqu`-copies the win32k service
  descriptor out of `wow64win!sdwhwin32` into its table 1** (the gap that was
  pinned as failing-by-design), publishes the BOP into all three 32-bit cells
  itself, and its per-thread init seats the 32-bit thread on
  **`ntdll32!LdrInitializeThunk`**. Wine's i386 `loader_init` then maps 32-bit
  DLLs off disk and binds the guest's whole import graph — exemu binds nothing.
  Gate: the WoW64 sample exits with its own code after **841,235** instructions
  (1,292 on the shorter `Bringup::Direct` path, which is kept and still pinned).
- **The 32-bit bootstrap contract was recovered from the i386 binary, not
  mirrored from the 64-bit one — and it differs.** `ntdll32!RtlUserThreadStart`
  is `mov [esp+8],ebx; mov [esp+4],eax; jmp …`: a fresh 32-bit thread carries its
  entry point in **`Eax`** and its argument in **`Ebx`**, where the 64-bit one
  uses `Rcx`/`Rdx`; `LdrInitializeThunk` takes its `CONTEXT` as a *stack*
  argument and hands `loader_init` a pointer to `context->Eax`.
- **`ntdll!LdrSystemDllInitBlock` is the hand-off** the kernel/Unix side owes
  `wow64.dll`: `+0x18` is the 32-bit `LdrInitializeThunk` (its per-thread init
  stores it straight into the new thread's `Eip`), `+0x20`/`+0x28`/`+0x30` the
  32-bit exception/APC/callback dispatchers, and `+0x48` the **ntdll32 image
  base** (it is passed to `RtlFindExportedRoutineByName`, which is what proves it
  is a module handle and not a routine). exemu fills it; every offset is
  re-derived from `wow64.dll`'s own use sites on each test run.
- **`__wine_unix_call` from a 32-bit guest arrives with a 32-bit `args` block.**
  `wow64cpu`'s BOP handler zero-extends the guest's pointer into `r8d` and calls
  the *same* 64-bit dispatcher the 64-bit ntdll uses — nothing on the PE side
  widens it — so the unix side reads it in 32-bit width, keyed off the 32-bit
  ntdll's own `__wine_unixlib_handle`. That is Wine's
  `__wine_unix_call_wow64_funcs` contract, and the phase plan had it backwards.
- **A real CPU bug, found by Wine's 32-bit ntdll:** the `moffs` form of `MOV`
  (`A0`–`A3`) added a *fixed* segment base instead of the live, per-thread one,
  so `mov fs:[0], eax` — how the i386 ntdll installs an SEH frame — stored
  through the process-default FS base rather than the guest's TEB32.
- New NT services behind the boot, each class/index read out of the caller's own
  bytes: `NtQueryInformationProcess(ProcessWow64Information / Basic)`,
  `NtQuerySystemInformationEx(SystemSupportedProcessorArchitectures)` (behind
  `RtlWow64GetProcessMachines`), `NtQuerySystemInformation(SystemEmulation-
  BasicInformation)` — whose single interesting field, `MaximumUserModeAddress`,
  is what `wow64.dll` bounds-checks every 32-bit pointer against — and
  `NtSetInformationThread(ThreadWow64Context)`, which also arms `BTCpuSimulate`'s
  full-context reload bit.
- **The WoW64 file-system redirector**: in a WoW64 process `\windows\system32`
  resolves to the *32-bit* half of the pinned prefix (and `\windows\syswow64`
  always does), so Wine's i386 loader is handed i386 PEs. Alongside it,
  `NtQuerySection` now reports the image's **own** machine instead of a hardcoded
  AMD64 (a PE32 was rejected with `STATUS_INVALID_IMAGE_FORMAT` before it was
  ever mapped), and both PE32 section views and the NLS view are placed below
  4 GiB, because `wow64.dll` narrows whatever base the kernel returns into a
  32-bit cell.
- `PEB32.ProcessParameters` is built too — Wine's i386
  `init_user_process_params` reads `EnvironmentSize` at **`+0x290`**, mirroring
  the 64-bit `+0x3f0` this project already pins, so the 32-bit header runs past
  the public 0x290-byte stub.
- *Measured, pinned as probes (W5.8):* on the WoW64 path `SteamSetup.exe` is
  still running at a 60M-instruction budget and `Firefox Installer.exe` reaches
  **11,462,340** instructions — past its UPX stub, into the inner program —
  before an unmapped read. Neither completes; both numbers are floors with the
  identity assertions (`PEB32.Ldr` published by Wine's own loader) that make
  them attributable.
- *Still open:* a 32-bit guest exception is not routed through
  `wow64.dll!Wow64PassExceptionToGuest` to `ntdll32!KiUserExceptionDispatcher`
  (exemu declines to deliver it and reports the fault instead, pinned as a
  comment on the delivery path); the process is single-threaded; and
  `LdrGetDllHandle`/`LdrLoadDll` for the WoW64 module set are serviced by
  exemu's own loader query rather than Wine's.

### Audio — a buffer plays through Wine's own mmdevapi (W7.2)
- **A guest plays PCM through Wine's audio stack.** A generated program that
  imports nothing but `ole32` calls `CoCreateInstance(CLSID_MMDeviceEnumerator)`
  and walks the ordinary WASAPI chain — `IMMDeviceEnumerator` → `IMMDevice` →
  `IAudioClient` → `IAudioRenderClient` — writes 240 frames into the buffer
  `GetBuffer` hands it, and the host backend receives those bytes **byte for
  byte**. The mix format travels the other way: `GetMixFormat` reports exemu's
  48 kHz / 2ch / 32-bit float back up through Wine's `IAudioClient`. The
  emulated path is the control: `CoCreateInstance` leaves the out-pointer NULL
  and the sample stops before it has an enumerator.
- **The finding that shaped the whole item: Wine's `*.drv` audio drivers ship no
  PE half worth the name.** The pinned `winealsa.drv` and `winepulse.drv` are
  **byte-identical** — a 0x70-byte `.text`, *no export directory*, one import
  (`kernel32!DisableThreadLibraryCalls`). Nothing about the interface is ALSA- or
  PulseAudio-specific because nothing about the interface is in them at all. The
  PE half of the whole audio stack is **`mmdevapi.dll`**, the only audio DLL that
  imports the unixlib bootstrap trio, and every code number and argument struct
  is compiled into *it*.
- **So exemu ships its own driver PE.** `mmdevapi!load_driver` builds
  `L"wine%s.drv"` from a registry list and asks the loaded module for its unixlib
  handle; its own default list is `"pulse,alsa,oss,coreaudio"`. Since exemu
  identifies a builtin by its **export directory** and the `.drv` stubs have
  none, they can never be paired. exemu generates a `winecoreaudio.drv` of its
  own — a stub PE that names itself — drops it in the sandbox's `system32` and
  seeds `HKCU\Software\Wine\Drivers\Audio = "coreaudio"`. No Wine bytes are
  copied, linked or transcribed; the licensing invariant is untouched.
- **The unixlib table is a dense 0..=36, recovered exhaustively** — all 46
  `call [__wine_unix_call_dispatcher]` sites in mmdevapi's `.text`, the
  `mov edx, imm` in each argument slot, and the enclosing function's name from
  mmdevapi's own **COFF symbol table** (3 114 symbols survive in the shipped
  binary). `audio_abi.rs` re-derives all of it on every run, plus the argument
  offsets, the `WAVEFORMATEXTENSIBLE` reply size, the endpoint-table shape, and
  the `ERROR_INSUFFICIENT_BUFFER` retry protocol.
- **A contract invisible until it hangs, also recovered:** `main_loop_start`
  blocks in `WaitForSingleObject(event, INFINITE)` until the *driver* signals the
  event it was handed, so the `main_loop` entry has to signal it before returning
  or `stream_init` deadlocks.
- **Bug found by that work:** `NtQueryInformationToken` accepted only exemu's own
  token pseudo-handle, but ntdll's `RtlFormatCurrentUserKeyPath` asks for
  `TokenUser` on `(HANDLE)-6` (`NtCurrentThreadEffectiveToken`). Rejecting it
  made `RtlOpenCurrentUser` fail, and its caller then proceeded with an
  **uninitialised root handle** — silently costing the guest the whole of
  `HKEY_CURRENT_USER`. The symptom here was every `IMMDevice::Activate` failing
  with `AUDCLNT_E_DEVICE_INVALIDATED`, because mmdevapi registers each endpoint's
  GUID under HKCU.
- **That one-line token fix also closed both W6.6 shell32 gaps** — every known
  folder now resolves to `C:\Users\exemu\…`, user component and all, and all
  six `SHGetFolderPathW` calls succeed (they were 5 of 6 failing). The gaps had
  looked like shell32 gaps for three rounds of work; the tell was that the
  `Shell Folders` seeds, the HKCU namespace fix and the whole token surface each
  left the run **byte-identical** in instruction count. A change that moves
  nothing has fixed nothing.
- **The host side is real CoreAudio.** A new `exemu-audio` crate implements the
  sink over AudioToolbox's `AudioQueue` — the push-shaped output API, which is
  the exact shape the `AudioSink` contract has — with a three-buffer ring and a
  staging queue the refill callback drains, zero-padding on underrun so a starved
  stream is silence rather than stale audio. Two new dependencies
  (`objc2-audio-toolbox`, `objc2-core-audio-types`), both `Zlib OR Apache-2.0 OR
  MIT`, from the objc2 family already in the shipping closure: no new licence
  family. `exemu run --audio` opts in; `exemu audio-sample` writes a PE that
  plays a 100 ms tone through the whole chain.
- Scope is deliberate: one render endpoint, shared mode, a fixed 48 kHz stereo
  float mix format. Capture, exclusive mode, MIDI, aux, loopback, the property
  store and event-driven mode are refused with a real HRESULT, never a silent
  success. Host audio leaves through a new `exemu_core::AudioSink` seam whose
  default is accept-and-drop, so a machine with no audio device is unaffected —
  which is also what makes the gate CI-safe.

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

### The GUI is interactive — input routing, capture and focus (W4.8)
- **A click reaches Wine's own `ButtonWndProc`, and the button behaves like a
  button.** W4.8 had painted the controls but routed input only to the first
  shown top-level window, so a click never got near a child. Now a press at the
  `BUTTON`'s coordinates is hit-tested onto that child, and user32's own
  procedure runs the whole documented sequence: `NtUserSetCapture`, push itself,
  `NtUserSetFocus`, `BM_SETSTATE` (which repaints on the spot through
  `NtUserGetDC`); then on the release it un-pushes, checks the point against
  `GetClientRect`, `NtUserReleaseCapture`, reads its id from `GWLP_ID`, asks
  `GetParent` and sends the parent a genuine `WM_COMMAND`/`BN_CLICKED`. The gate
  observes the notification by having the sample's WndProc set the window text
  of the HWND it was handed in **lParam** — so the recorded driver call naming
  the *button* is proof the message carried its real handle.
- **The pressed repaint is proven in pixels.** 1926 of the button rect's 17,920
  bytes change while it is down, and specifically the Win95 edge swap: the
  top-left inner edge goes `COLOR_BTNHIGHLIGHT` white → `COLOR_BTNSHADOW` grey
  and the black `COLOR_3DDKSHADOW` bottom-right lifts to grey. exemu supplies
  the palette; which colour goes on which edge in which state is Wine's
  `UITOOLS95_DFC_ButtonPush`. Pinned as
  `crates/app/tests/goldens/comctl_button_pressed.png`.
- **Which side hit-tests is recovered, not chosen.** `user32!WindowFromPoint` is
  sixteen bytes — unpack the by-value `POINT` (`shr rax, 0x20`) and tail-jump
  `NtUserWindowFromPoint`, which is the function's last instruction — and
  `SetCapture`/`ReleaseCapture`/`SetFocus` are bare thunks, while
  `GetFocus`/`GetActiveWindow`/`GetCapture` are indices 0/1/2 of
  `NtUserGetThreadState`. So native events are queued **raw** and given a target
  at retrieval: the capture holder first (in its own client coordinates, no hit
  test — which is what lets a pushed button see the button-up after the pointer
  leaves its rect), else the deepest visible window under the point, which is
  then asked `WM_NCHITTEST` and gets to answer. `HTCLIENT` delivers the client
  message with the point rebased; `HTTRANSPARENT` retries with that window
  excluded (Wine's `ButtonWndProc` answers exactly that for a `BS_GROUPBOX`);
  anything else delivers the `WM_NC*` twin. Honouring a callback's *return
  value* needed a continuation on the win32k callback frame.
- **`NtUserMessageCall` turned out to be a whole family behind one index**,
  selected by the `type` immediate each user32 wrapper stores at `[rsp+0x28]`:
  `SendMessage` 0x2b1, `SendMessageTimeout` 0x2b3, `SendNotifyMessage` 0x2b7,
  `SendMessageCallback` 0x2b8, `CallWindowProc` 0x2ab, `DefWindowProc` 0x29e and
  0x3001 for the internal `dispatch_message` behind `DispatchMessage`. Two of
  those matter a great deal. 0x3001 must answer **zero**, or user32 walks a
  `win_proc_params` block its caller never initialized. And 0x29e must run a
  **kernel-side `DefWindowProc`**, because `user32!DefWindowProcW` is nothing but
  this syscall — it handles five IME/syscommand messages and forwards the rest,
  `WM_NCHITTEST` included; there is no `NC_HandleNCHitTest` anywhere in user32.
- **Two long-standing marshalling bugs fell out.** `NtUserCallHwnd` code 0x10
  returns the **HWND**, not a boolean: `user32!WIN_IsCurrentProcess` is
  `mov edx,0x10; call NtUserCallHwnd; mov eax,eax` and `DefWindowProcW` uses what
  comes back *as the window handle* (`mov rbx, rax`) — answering 1 sent every
  `DefWindowProc` in the process to window number 1, which is why the recursion
  above had never been observed. And `NtUserMessageCall`'s `type`/`ansi` are
  **DWORD** stack slots, written with `mov dword ptr [rsp+…], imm`; reading the
  full qword picked up the previous frame's bytes, so the same `SetWindowTextW`
  came out Unicode on one call and ANSI on the next.
- **Keyboard follows the focus.** `NtUserSetFocus` sends `WM_KILLFOCUS`/
  `WM_SETFOCUS` and key messages go to the focus window (falling back to the
  active top-level), `NtUserTranslateMessage` produces the `WM_CHAR` after a
  key-down instead of returning 0, and `NtUserPeekMessage` is a real
  non-blocking pump rather than a permanent "nothing available". Gate:
  after a click the `BUTTON` holds the focus, and `VK_SPACE` makes Wine's button
  notify its parent a second time.
- Gates: `comctl_gate` 8 → 12 (`clicking_the_button_reaches_wine_button_wndproc_on_wine`,
  `a_click_that_misses_the_button_notifies_nobody_on_wine`,
  `space_activates_the_focused_button_on_wine`,
  `the_pressed_button_matches_golden_on_wine`), `win32k_abi` 9 → 13 with the
  re-derived index table 26 → 36, and +7 win32k unit tests. Both existing
  goldens stay byte-identical. `comctl_sample`: 1,758,795 instructions plain,
  1,789,659 pumped, 1,819,519 with the click.

### Known folders through Wine's shell32 (W6.6)
- **`SHGetFolderPathW`/`SHGetKnownFolderPath` now resolve correctly** — a console
  sample that statically imports `shell32!SHGetFolderPathW` runs to completion on
  the Wine boot at **exit 0** (was exit 6: every one of 6 requested `CSIDL`s
  failing), e.g. `APPDATA=C:\Users\exemu\AppData\Roaming` (was
  `C:\users\AppData\Roaming` — lowercase `users`, empty user component). exemu
  hand-writes no shell32; Wine's own resolves the paths.
- **Root cause, found by disassembling the pinned `shell32.dll` and then tracing
  the live syscalls it issues:** the per-CSIDL resolver's registry helper calls
  `NtQueryInformationToken` on `NtCurrentThreadEffectiveToken()` — `(HANDLE)-6`,
  a **public, documented** NT pseudo-handle (`winternl.h`/`processthreadsapi.h`)
  a caller may use to reach "my own token" without ever calling
  `NtOpenProcessToken` first. exemu's token surface (added chasing this same bug)
  recognised only the real handle it hands out itself, so this always failed with
  `STATUS_INVALID_HANDLE`; `HKEY_CURRENT_USER` never resolved, every registry
  read fell back to `HKLM` (visible live in the syscall trace — never `HKCU`),
  and shell32 landed on a purely computed default with no user name in it. Three
  earlier, plausible fixes (the `Shell Folders` registry keys, the HKCU/NT
  namespace fold, the token surface's first cut) had each left the instruction
  count **byte-identical**, proving Wine never executed those paths — the
  decisive clue that pointed at the token seam instead of the registry seam.
- The second, previously-downstream gap (5 of 6 folders reporting failure because
  the named directory didn't exist) **closed for free**: exemu has materialised
  the full `C:\Users\exemu\…` profile tree since the earlier W6.6 sandbox-seeding
  commit, so once Wine resolves the *same* path exemu actually creates, every
  directory is already there.
- Fix: `crates/os/src/token.rs` now accepts `NtCurrentProcessToken()` (-4),
  `NtCurrentThreadToken()` (-5) and `NtCurrentThreadEffectiveToken()` (-6)
  everywhere the real opened pseudo-handle is accepted — correct for exemu's
  single-user, no-impersonation model, where all four name the same token.
  `crates/app/tests/shell_gate.rs` now pins the *fixed* paths (cross-checked
  against `exemu_os::folders::csidl_path`, so the two can't silently drift) and a
  zero exit code, with an explicit trap for the old bug's signature
  (`\users\` with no name) so a regression reads immediately as "the old bug is
  back".

### Start-menu shortcuts, and the zero that broke case-insensitivity (W6.6)
- **A guest writes a real `.lnk` into `CSIDL_PROGRAMS` through Wine's own
  shell32** — the whole installer sequence: `CoCreateInstance(CLSID_ShellLink)`
  → `IShellLinkW::SetPath` → `GetPath` (which hands the target back) →
  `QueryInterface(IID_IPersistFile)` → `IPersistFile::Save`. The gate reads the
  file back out of the sandbox and walks it as the format Microsoft publishes
  (MS-SHLLINK): the 0x4C header, `LinkCLSID = CLSID_ShellLink`,
  `LinkFlags.HasLinkInfo`, `ShowCommand = SW_SHOWNORMAL`, and a `LinkInfo` whose
  `LocalBasePath` is exactly the target `SetPath` was given. exemu implements no
  COM, no shell namespace and no `.lnk` serializer; the emulated path is the
  control (its `CoCreateInstance` cannot produce an object at all). Exit 0 after
  2,616,308 guest instructions.
- **Root cause of the `SetPath` fault: a stubbed API returned a *plausible
  zero*, and four subsystems later the guest dereferenced NULL.** exemu answered
  `NtGetNlsSectionPtr(type 0xA)` — ntdll's **case-mapping** section — with the
  same zero-filled codepage stub it used for every other section type. ntdll's
  `locale_init` installed it as the process upcase/downcase tables
  (`section+4`, and `section+4+2*word[section+2]`), and *because the pointer was
  non-NULL* every case-insensitive comparison in the process took the table path
  instead of its ASCII fallback — with a table that maps every character to
  itself. **Case-insensitive comparison silently became case-sensitive.** So
  `LdrpFindLoadedDllByName(L"NTDLL.dll")` — reached while resolving a forwarder,
  the pinned kernel32/user32 spell it uppercase — failed to match the already
  loaded `ntdll.dll`, and Wine's loader mapped a **second, uninitialised copy of
  ntdll**. shell32's delay-load stub bound to that copy, and the first
  delay-load resolution walked its never-initialised `LdrpHashTable`, found a
  bucket whose `LIST_ENTRY.Flink` was `NULL`, and read a field at `+0xBC` off
  it — the reported `page fault on read access to 00000000000000BC`, two million
  instructions and four subsystems away from the stub.
- **Fix: real case tables** (`crates/os/src/nls.rs`). The three-level 8/4/4
  sparse delta format was recovered from the pinned `ntdll.dll`
  (`RtlCompareUnicodeStrings` @ RVA 0x1c9c0 and `RtlHashUnicodeString` @ 0x27ea0
  index it identically: `ch += T[T[T[ch>>8] + ((ch>>4)&0xF)] + (ch&0xF)]`), and
  the deltas come from Rust's own Unicode data — simple 1:1 mappings only, which
  is exactly what a per-character delta table can express. Identical blocks are
  shared, so the whole BMP costs a few KiB. A unit test walks the emitted table
  with the guest's own indexing across all 65,536 code points and checks it
  against `char::to_uppercase`/`to_lowercase`, with a floor on how many
  characters must actually map so a degenerate table cannot pass. The duplicate
  ntdll load — a loader-level gap pinned in `comctl_gate.rs` since W6.2 — is
  gone with it.
- **Every address in a fault report is now module-attributed.** `WinOs::module_at`
  / `describe_addr` / `loaded_modules` resolve a guest address to
  `shell32.dll+0x39600`, consulting both exemu's own loader **and** the image
  views the *guest* loader maps through `NtCreateSection(SEC_IMAGE)` /
  `NtMapViewOfSection` — which matters because on the Wine boot exemu maps only
  ntdll and everything else arrives that way, so previously every faulting
  address in Wine's code was an unattributable number. The report gains the
  named rip, a named rip trail, a named call stack and a loaded-module list; a
  duplicate image map is warned about under `--trace`. `EXEMU_DBG=1` prints the
  whole report for an exception that is *delivered to the guest* rather than
  fatal — without it, an access violation Wine then swallows leaves no trace at
  all. This is what turned the hunt above from hours into minutes.
- **A NULL-dereference fault now names the stubs that returned the NULL.** The
  commonest failure shape in exemu is an unimplemented API returning 0 that the
  guest keeps as a pointer and faults on an arbitrary distance later — 728
  instructions for `tcc.exe`, 4.7M for the Firefox installer, 93M for
  SteamSetup — and the fault itself carried no trace of where the zero came
  from, which is why those read as three unrelated bugs. The OS layer now
  remembers every unimplemented stub that hands the guest a 0 (newest first,
  deduplicated, capped), and the report recognises the *shape* of the fault (an
  address inside the never-mapped 64 KiB null-guard region — a null pointer plus
  at most a struct-field offset) and prints the suspects. On `tcc.exe` it names
  `kernel32.dll!VerifyVersionInfoW` and `kernel32.dll!VerSetConditionMask` —
  exactly the pair `knowledge/known-issues.know` records as its cause, now
  produced automatically rather than by hand. Pinned as a test against the real
  binary. **Finding worth recording:** on the Firefox installer the same
  diagnostic reports that *no* unimplemented stub returned 0 in the whole run —
  so despite being filed in the same class, its NULL comes from somewhere else
  (guest logic, or an *implemented* API returning the wrong thing).
- **PINNED GAP:** the saved `.lnk` carries no `LinkTargetIDList`. Real Windows
  also stores the target as a PIDL, which `SetPath` builds by walking the shell
  namespace (`SHGetDesktopFolder` → `IShellFolder::ParseDisplayName`); that walk
  does not produce one here, so the shortcut resolves by path only. Asserted, so
  closing it fails the test and forces this note to be updated.

### IShellLink through COM (W6.6 stretch, partial — superseded above)
- **`CoCreateInstance(CLSID_ShellLink, IID_IShellLinkW)` resolves through
  exemu's registry to shell32's own `IShellLinkW`** — the same
  in-proc-server mechanism W6.3/W6.4 proved for the ole32 moniker classes,
  now proved for a shell32-hosted one. A real vtable call through the
  returned interface (`GetPath`, on a pristine link) returns **exactly**
  `S_FALSE` — Microsoft's documented HRESULT for "successful call, no path
  retrieved" — which is strong evidence the call reached Wine's *real*
  `IShellLinkW::GetPath`, not coincidence: a wrong vtable slot would not
  reproduce a specific documented result. `crates/os/src/reg.rs` seeds
  `HKCR\CLSID\{CLSID_ShellLink}\InprocServer32 = shell32.dll`; new sample
  `crates/app/src/shell_link_sample.rs` + gate
  `crates/app/tests/shell_link_gate.rs`.
- **`SetPath` crashes — a genuine, separate gap, deliberately left out of the
  shipped sample rather than worked around.** Wine's own crash reporter names
  it exactly: `Unhandled page fault on read access to 00000000000000BC` — a
  NULL pointer plus a small struct-field offset, the same failure class
  `knowledge/known-issues.know` already documents (a stubbed Win32 API
  returns 0/NULL, real Wine code dereferences it later). Isolated
  methodically: the `GetPath` slot (vtable+0x18) was proven correct and
  callable first; a sweep of neighbouring slots showed vtable+0xA0
  ("SetPath", correctly the last of `IShellLinkW`'s 21 documented slots)
  holds a plausible, same-image function pointer immediately followed by the
  vtable's true end (+0xA8/+0xB0 both `NULL`) — confirming the *offset* is
  right; the `pszFile` argument was echoed back byte-for-byte correct before
  the call. The fault is therefore inside Wine's real `SetPath`, hitting
  some *other*, not-yet-identified stub — worth its own investigation.
  **(Resolved: it was the all-zero NLS case table — see the section above. The
  isolation recorded here was correct and is what made the search tractable.)**

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
  one. The gate resets the sandbox per entry.

### Deterministic guest clock (W9.6 follow-up)
- **A corpus binary now executes the exact same number of instructions on every
  run.** With the sandbox reset and `argv[0]` pinned, one source of drift was
  left: exemu serviced the *real host clock*, so a guest comparing two timestamps
  branched on how fast the host happened to be. `exemu run --virtual-clock` (or
  `EXEMU_VIRTUAL_CLOCK=1`, or `RunConfig::virtual_clock`) replaces it with a
  clock derived from the guest's own retired-instruction count. Measured through
  the corpus runner:

  | binary | host clock (3 runs) | virtual clock |
  | --- | --- | --- |
  | `Firefox Installer.exe` | 4,665,427 / 4,665,427 / 4,665,426 | **4,665,426 ×5** |
  | `SteamSetup.exe` | 92,864,324 / 92,864,324 / 92,864,999 | **92,865,377 ×4** |
  | `7z2602-x64.exe` | 496,505,572 | **496,505,572 ×3** (exit 0, 108 artifacts) |

- **The model**: one retired instruction = one 100-ns tick, i.e. a nominal 10M
  instructions/second machine, from a fixed 2026-01-01T00:00:00Z epoch. That rate
  is roughly what a release build actually interprets at, so a guest is not
  handed a machine orders of magnitude faster or slower than the one it was
  seeing, and the units come out exact: the performance counter already runs at
  10 MHz, so *the QPC value is the instruction count* and a `FILETIME` is the
  epoch plus that count. `RDTSC` is a fixed 1 GHz multiple of the same time, so a
  guest calibrating TSC against QPC gets a self-consistent answer instead of two
  unrelated ramps. `Sleep(ms)` — a cooperative yield costing one instruction — is
  credited the interval it asked for, so `Sleep`-paced timeout loops still
  terminate in about as many iterations as on real hardware.
- **Everything guest-visible goes through it**: `RDTSC`/`RDTSCP`,
  `GetTickCount(64)`, `QueryPerformanceCounter`, `GetSystemTime(AsFileTime)` /
  `GetLocalTime`, `NtQuerySystemTime`, `NtQueryPerformanceCounter`, the Wine-path
  `RtlGetSystemTimePrecise` unix call, and registry `LastWriteTime` stamps.
- **`KUSER_SHARED_DATA` too — the one with nothing to intercept.** A guest reads
  `SystemTime`/`InterruptTime`/`TickCount` from that page with a *plain load*, so
  the run loop rewrites them every 65,536 instructions (6.55 ms of virtual time,
  finer than the 15.625 ms tick they are quantised to). A cadence keyed to the
  instruction count, not to host time — anything else would reintroduce the
  nondeterminism. `TickCountMultiplier` is also seeded now (0x0FA00000, the real
  Windows value) on both paths: it was 0, which made a guest's inline
  `GetTickCount` compute 0 forever.
- **Not virtualised, said so explicitly and pinned as tests**: host filesystem
  timestamps (`FindFirstFile`/`NtQueryDirectoryFile` report the real mtimes of
  real files — making that deterministic *and* order-preserving needs a virtual-FS
  metadata overlay) and real socket timeouts.
- **The corpus tolerances tightened accordingly.** A `virtual_clock = true` entry
  is pinned as an *equality* (`tolerance = 0`) — for the clean exit and for the
  faults alike — so the gate now resolves a single instruction across a
  496-million-instruction run. A noise floor that is no longer needed does not
  stay in place. One entry deliberately stays on the host clock, on the same
  binary as a virtual-clock entry, so the default path keeps being tested and a
  behavioural difference between the two clocks would show up as a fault-identity
  mismatch rather than as silence.
- Off by default; the host-clock path is byte-identical to what shipped. This is
  also the prerequisite for the planned JIT-vs-interpreter differential (W8.7),
  which can only diff two engines instruction-for-instruction if a run replays
  exactly.

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
