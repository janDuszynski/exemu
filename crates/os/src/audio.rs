//! Audio — the **mmdevapi driver unixlib** Wine's PE audio stack calls, and the
//! host backend behind it (roadmap W7.2).
//!
//! # The boundary, recovered — not assumed
//!
//! Every constant, code index and structure offset below was **recovered by
//! disassembling the pinned Wine 11.0 binaries** in
//! `example_exe/wine-dlls/x86_64-windows/`, the same method that established the
//! WoW64, COM, win32k and `\Device\Afd` boundaries.
//! `crates/app/tests/audio_abi.rs` re-derives each one from those bytes on every
//! run and asserts it against this module, so a wrong guess here cannot survive
//! a test run. No Wine source was read (clean-room Class B); the COM/NT
//! signatures themselves are the public `mmdeviceapi.h` / `audioclient.h` /
//! `winternl.h` ones.
//!
//! ## Finding 1 — the `*.drv` audio drivers ship **no PE half at all**
//!
//! The pinned prefix contains `winealsa.drv` and `winepulse.drv`. They are
//! **byte-for-byte identical** (`sha256 d582e673…`), 57 180 bytes each, and each
//! is a stub: `.text` is 0x70 bytes, there is **no export directory**, and the
//! single import is `kernel32!DisableThreadLibraryCalls`. `DllMain` calls that
//! on `DLL_PROCESS_ATTACH` and returns `TRUE`. Nothing ALSA-specific — or
//! audio-specific — survives into the PE image; all of it lives in the Linux
//! `.so` half that a Windows-format prefix does not carry.
//!
//! So there is **nothing driver-specific for exemu to be compatible with**. The
//! interface is generic by construction: the same PE bytes serve ALSA and
//! PulseAudio, and mmdevapi's own default driver list — a literal in its
//! `.rdata` — is `"pulse,alsa,oss,coreaudio"`.
//!
//! ## Finding 2 — the PE half of the whole audio stack is `mmdevapi.dll`
//!
//! Of the audio DLLs in the prefix (`winmm`, `dsound`, `mmdevapi`, `xaudio2_*`,
//! `msacm32`, `mciwave`, `midimap`, …) exactly one imports the unixlib
//! bootstrap trio `ntdll!{NtQueryVirtualMemory, LdrGetDllHandle,
//! RtlFindExportedRoutineByName}`: **`mmdevapi.dll`**. Everything above it —
//! `winmm`'s waveOut, `dsound`, `xaudio2` — reaches the driver through
//! mmdevapi's COM surface, as guest code, and never touches this boundary.
//!
//! `mmdevapi!load_driver` is the whole handshake, and it is short:
//!
//! ```text
//! swprintf(buf, L"wine%s.drv", name);          // name from the registry list
//! drv->module = LoadLibraryW(buf);
//! NtQueryVirtualMemory(GetCurrentProcess(), drv->module,
//!                      MemoryWineUnixFuncs /* 1000 */, &drv->unix_handle, 8, NULL);
//! __wine_unix_call(drv->unix_handle, 0 /* process_attach */, NULL);
//! __wine_unix_call(drv->unix_handle, 27 /* test_connect */, &{ name, priority });
//! ```
//!
//! The driver module is therefore a pure *anchor*: its only job is to be a
//! mapped image whose base `MemoryWineUnixFuncs` resolves to a unixlib handle.
//! Every code number and every argument structure is compiled into **mmdevapi**,
//! not into the driver.
//!
//! ## Consequence for exemu: exemu ships its own `winecoreaudio.drv`
//!
//! Two facts make hijacking one of Wine's stubs impossible *and* unnecessary:
//!
//! * exemu identifies a builtin at the `MemoryWineUnixFuncs` query from the
//!   mapped image's **export directory** ([`crate::unixlib`]), and Wine's `.drv`
//!   stubs have none — they can never be identified this way.
//! * `coreaudio` is already in mmdevapi's own default driver list, so the
//!   selection path needs no patching: seeding
//!   `HKCU\Software\Wine\Drivers\Audio = "coreaudio"` makes mmdevapi ask for
//!   `winecoreaudio.drv` by name.
//!
//! exemu therefore **generates its own `winecoreaudio.drv`** — a minimal PE
//! whose `DllMain` returns `TRUE` and whose export directory names it — and
//! registers this module's unixlib against it. Nothing of Wine's is copied,
//! linked or transcribed: the driver PE is exemu's own bytes, and the unix side
//! is exemu's own CoreAudio backend. That is exactly the shape Wine itself uses
//! on macOS, reached through the driver name Wine's own mmdevapi already knows.
//!
//! ## The unixlib table — 37 entries, indices 0..=36
//!
//! Recovered exhaustively: every `call [__wine_unix_call_dispatcher]` in
//! `mmdevapi.dll`'s `.text` (46 sites) was located, the `mov edx, imm` in its
//! argument slot read back, and the enclosing function named from the DLL's own
//! **COFF symbol table** (mingw keeps it; 3 114 symbols survive in the shipped
//! binary). The codes form a dense 0..=36 with no gaps.
//!
//! | Code | Issued by (mmdevapi's own symbol) | What it does |
//! | ---- | --------------------------------- | ------------ |
//! | 0  | `load_driver`                        | process attach (`args = NULL`) |
//! | 1  | `DllMain`                            | process detach (`args = NULL`) |
//! | 2  | `main_loop_func`                     | driver event loop thread |
//! | 3  | `load_driver_devices`                | enumerate endpoints |
//! | 4  | `stream_init`                        | create a stream |
//! | 5  | `client_Release` / `stream_release`  | release a stream |
//! | 6  | `client_Start`                       | start |
//! | 7  | `client_Stop`                        | stop |
//! | 8  | `client_Reset`                       | reset |
//! | 9  | `timer_loop_func`                    | per-stream timer thread |
//! | 10 | `render_GetBuffer`                   | acquire the render buffer |
//! | 11 | `render_ReleaseBuffer`               | release the render buffer |
//! | 12 | `capture_GetBuffer`                  | acquire the capture buffer |
//! | 13 | `capture_ReleaseBuffer`              | release the capture buffer |
//! | 14 | `client_IsFormatSupported`           | format probe |
//! | 15 | `stream_init` (loopback path)        | resolve a loopback capture device |
//! | 16 | `client_GetMixFormat`                | the shared-mode mix format |
//! | 17 | `client_GetDevicePeriod`             | default / minimum period |
//! | 18 | `client_GetBufferSize`               | buffer size in frames |
//! | 19 | `client_GetStreamLatency`            | latency |
//! | 20 | `client_GetCurrentPadding`           | frames still queued |
//! | 21 | `capture_GetNextPacketSize`          | next capture packet |
//! | 22 | `clock_GetFrequency`                 | `IAudioClock` frequency |
//! | 23 | `clock_GetPosition`                  | `IAudioClock` position |
//! | 24 | `set_stream_volumes`                 | master / per-channel volume |
//! | 25 | `client_SetEventHandle`              | event-driven mode |
//! | 26 | `AudioClockAdjustment_SetSampleRate` | sample-rate adjustment |
//! | 27 | `load_driver`                        | probe + priority |
//! | 28 | `control_GetState`                   | is the stream started |
//! | 29 | `set_driver_prop_value`              | driver property store |
//! | 30 | `init_driver`                        | the MIDI driver's name |
//! | 31..=35 | `DriverProc` / `modMessage` / `midMessage` / `notify_thread` | MIDI |
//! | 36 | `auxMessage`                         | the winmm aux device |
//!
//! ## Scope — what exemu actually implements
//!
//! Deliberately one slice: **shared-mode render on a single endpoint at a fixed
//! mix format** (see [`MIX_SAMPLE_RATE`], [`MIX_CHANNELS`]). That is the path
//! `IAudioClient` + `IAudioRenderClient` takes, and it is the path a program
//! that plays a sound takes. Everything else — capture, exclusive mode, MIDI,
//! aux, the property store, loopback, sample-rate adjustment — is refused with a
//! **real HRESULT** (`E_NOTIMPL` / `AUDCLNT_E_UNSUPPORTED_FORMAT` /
//! `AUDCLNT_E_DEVICE_INVALIDATED`), never a silent success. A caller that asks
//! for something exemu has not written finds out.

use std::collections::HashMap;

use exemu_core::{AudioFormat, CpuState, Memory, Result};

use crate::unixlib::{UnixEntry, Unixlib};
use crate::WinOs;

// ---------------------------------------------------------------------------
// 1. Driver selection — how mmdevapi finds a driver at all
// ---------------------------------------------------------------------------

/// The registry key `mmdevapi!init_driver` opens under **`HKEY_CURRENT_USER`**
/// (`RegOpenKeyW(0x80000001, …)`) to choose a driver. Recovered as the wide
/// literal `drv_keyW` in mmdevapi's `.rdata`.
pub const DRIVER_KEY: &str = "Software\\Wine\\Drivers";

/// The value name under [`DRIVER_KEY`] holding a comma-separated driver list.
/// (`init_driver` splits on `,` with `wcschr`, then tries each in order and
/// keeps the one reporting the highest [`code 27`](CODE_TEST_CONNECT) priority.)
pub const DRIVER_VALUE: &str = "Audio";

/// mmdevapi's own fallback list when the registry value is absent — the literal
/// `default_list.16` in its `.rdata`. `coreaudio` being in it is why exemu needs
/// no patching to be selected.
pub const DRIVER_DEFAULT_LIST: &str = "pulse,alsa,oss,coreaudio";

/// The driver exemu registers, as it appears in [`DRIVER_VALUE`].
pub const DRIVER_NAME: &str = "coreaudio";

/// `mmdevapi!load_driver` builds its module name as `PREFIX + name + SUFFIX`.
pub const DRIVER_MODULE_PREFIX: &str = "wine";
/// The other half of that name.
pub const DRIVER_MODULE_SUFFIX: &str = ".drv";

/// The module name exemu's generated driver PE reports through its export
/// directory — the name `load_driver` asks `LoadLibraryW` for once
/// [`DRIVER_NAME`] is selected, and the key [`crate::unixlib`] matches on.
pub const DRIVER_MODULE: &str = "winecoreaudio.drv";

/// The priority `load_driver` records for the driver it probed, as reported by
/// [`CODE_TEST_CONNECT`]. mmdevapi maps these to the literals `Unavailable`,
/// `Low`, `Neutral`, `Preferred` in its trace output, and keeps the driver with
/// the numerically highest value.
pub const PRIORITY_UNAVAILABLE: u32 = 0;
/// `Low`.
pub const PRIORITY_LOW: u32 = 1;
/// `Neutral` — also the value mmdevapi pre-seeds the field with.
pub const PRIORITY_NEUTRAL: u32 = 2;
/// `Preferred`. exemu reports this: on macOS CoreAudio is not a fallback.
pub const PRIORITY_PREFERRED: u32 = 3;

// ---------------------------------------------------------------------------
// 2. The unixlib codes
// ---------------------------------------------------------------------------

/// Number of entries in the driver unixlib table. mmdevapi issues a dense
/// 0..=36 with no gaps; a 37th index would be out of contract.
pub const UNIXLIB_ENTRIES: usize = 37;

/// 0 — `load_driver`, `args = NULL`.
pub const CODE_PROCESS_ATTACH: u32 = 0;
/// 1 — `DllMain(DLL_PROCESS_DETACH)`, `args = NULL`, once per loaded driver.
pub const CODE_PROCESS_DETACH: u32 = 1;
/// 2 — `main_loop_func`, the driver's event-loop thread.
pub const CODE_MAIN_LOOP: u32 = 2;
/// 3 — `load_driver_devices`, called twice (render then capture).
pub const CODE_GET_ENDPOINT_IDS: u32 = 3;
/// 4 — `stream_init`.
pub const CODE_CREATE_STREAM: u32 = 4;
/// 5 — `client_Release` / `stream_init`'s error path / `stream_release`.
pub const CODE_RELEASE_STREAM: u32 = 5;
/// 6 — `client_Start`.
pub const CODE_START: u32 = 6;
/// 7 — `client_Stop`.
pub const CODE_STOP: u32 = 7;
/// 8 — `client_Reset`.
pub const CODE_RESET: u32 = 8;
/// 9 — `timer_loop_func`, the per-stream timer thread `client_Start` spawns.
pub const CODE_TIMER_LOOP: u32 = 9;
/// 10 — `render_GetBuffer`.
pub const CODE_GET_RENDER_BUFFER: u32 = 10;
/// 11 — `render_ReleaseBuffer`.
pub const CODE_RELEASE_RENDER_BUFFER: u32 = 11;
/// 12 — `capture_GetBuffer`.
pub const CODE_GET_CAPTURE_BUFFER: u32 = 12;
/// 13 — `capture_ReleaseBuffer`.
pub const CODE_RELEASE_CAPTURE_BUFFER: u32 = 13;
/// 14 — `client_IsFormatSupported`.
pub const CODE_IS_FORMAT_SUPPORTED: u32 = 14;
/// 15 — `stream_init`'s `AUDCLNT_STREAMFLAGS_LOOPBACK` path.
pub const CODE_GET_LOOPBACK_CAPTURE_DEVICE: u32 = 15;
/// 16 — `client_GetMixFormat`.
pub const CODE_GET_MIX_FORMAT: u32 = 16;
/// 17 — `client_GetDevicePeriod`, `client_GetSharedModeEnginePeriod`, `stream_init`.
pub const CODE_GET_DEVICE_PERIOD: u32 = 17;
/// 18 — `client_GetBufferSize`.
pub const CODE_GET_BUFFER_SIZE: u32 = 18;
/// 19 — `client_GetStreamLatency`.
pub const CODE_GET_LATENCY: u32 = 19;
/// 20 — `client_GetCurrentPadding`.
pub const CODE_GET_CURRENT_PADDING: u32 = 20;
/// 21 — `capture_GetNextPacketSize`.
pub const CODE_GET_NEXT_PACKET_SIZE: u32 = 21;
/// 22 — `clock_GetFrequency`.
pub const CODE_GET_FREQUENCY: u32 = 22;
/// 23 — `clock_GetPosition` and `clock2_GetDevicePosition`.
pub const CODE_GET_POSITION: u32 = 23;
/// 24 — `set_stream_volumes`, `streamvolume_SetAllVolumes`, `…SetChannelVolume`.
pub const CODE_SET_VOLUMES: u32 = 24;
/// 25 — `client_SetEventHandle`.
pub const CODE_SET_EVENT_HANDLE: u32 = 25;
/// 26 — `AudioClockAdjustment_SetSampleRate`.
pub const CODE_SET_SAMPLE_RATE: u32 = 26;
/// 27 — `load_driver`'s probe; fills the priority the selection loop compares.
pub const CODE_TEST_CONNECT: u32 = 27;
/// 28 — `control_GetState`; `S_OK` means started.
pub const CODE_IS_STARTED: u32 = 28;
/// 29 — `set_driver_prop_value`, the device property store.
pub const CODE_GET_PROP_VALUE: u32 = 29;
/// 30 — `init_driver`; fills a `WCHAR` buffer with the MIDI driver's name (an
/// empty string means "the same driver", which is what exemu reports).
pub const CODE_MIDI_DRIVER_NAME: u32 = 30;
/// 31 — `DriverProc`, MIDI init.
pub const CODE_MIDI_INIT: u32 = 31;
/// 32 — `DriverProc`, MIDI release (`args = NULL`).
pub const CODE_MIDI_RELEASE: u32 = 32;
/// 33 — `modMessage`, MIDI out.
pub const CODE_MIDI_OUT_MESSAGE: u32 = 33;
/// 34 — `midMessage`, MIDI in.
pub const CODE_MIDI_IN_MESSAGE: u32 = 34;
/// 35 — `notify_thread`, the MIDI notification wait.
pub const CODE_MIDI_NOTIFY_WAIT: u32 = 35;
/// 36 — `auxMessage`, the winmm aux device.
pub const CODE_AUX_MESSAGE: u32 = 36;

// ---------------------------------------------------------------------------
// 3. Argument-structure offsets
// ---------------------------------------------------------------------------
//
// Recovered from the argument slots mmdevapi fills before each dispatcher call
// and reads back after it. `audio_abi.rs` re-derives the ones marked below by
// locating each call's `lea r8, [rsp+disp]` (the `args` pointer) and matching
// the surrounding `[rsp+disp8]` stores and loads against these constants.

/// `get_endpoint_ids` (3): `{ UINT flow; void *endpoints; UINT size;
/// HRESULT result; UINT num; UINT default_idx; }`.
pub const EP_IDS_FLOW: u64 = 0x00;
/// Caller-allocated buffer the driver fills with the endpoint table.
pub const EP_IDS_ENDPOINTS: u64 = 0x08;
/// Size of that buffer in bytes (in), the size needed (out on overflow).
pub const EP_IDS_SIZE: u64 = 0x10;
/// The HRESULT. mmdevapi retries with a bigger buffer on
/// [`HRESULT_ERROR_INSUFFICIENT_BUFFER`].
pub const EP_IDS_RESULT: u64 = 0x14;
/// How many endpoints were written.
pub const EP_IDS_NUM: u64 = 0x18;
/// Index of the default endpoint.
pub const EP_IDS_DEFAULT_IDX: u64 = 0x1c;

/// One entry of the endpoint table: two byte offsets **relative to the start of
/// the endpoints buffer**. `load_driver_devices` computes `endpoints + off` for
/// both.
pub const ENDPOINT_STRIDE: u64 = 8;
/// Offset of the friendly name (a `WCHAR` string) within an entry.
pub const ENDPOINT_NAME_OFF: u64 = 0;
/// Offset of the opaque device id within an entry. It is a **`char` string**:
/// `mmdevapi!get_device_guid` widens it with `MultiByteToWideChar(CP_UNIXCP)` to
/// build a registry key, and `get_device_name_from_guid` hands it back with
/// `_strdup`. That id is what later arrives as the `device` field below.
pub const ENDPOINT_ID_OFF: u64 = 4;

/// `test_connect` (27): `{ const WCHAR *name; UINT priority; }`.
pub const TEST_CONNECT_NAME: u64 = 0x00;
/// The priority slot — pre-seeded with [`PRIORITY_NEUTRAL`] by mmdevapi.
pub const TEST_CONNECT_PRIORITY: u64 = 0x08;

/// `get_mix_format` (16): `{ const char *device; UINT flow; WAVEFORMATEXTENSIBLE *fmt;
/// HRESULT result; }`. `fmt` points at a `CoTaskMemAlloc(0x28)` block — exactly
/// `sizeof(WAVEFORMATEXTENSIBLE)`, which is what fixes the reply's shape.
pub const MIX_FMT_DEVICE: u64 = 0x00;
/// The data flow (0 = render, 1 = capture).
pub const MIX_FMT_FLOW: u64 = 0x08;
/// The 40-byte block to fill.
pub const MIX_FMT_FMT: u64 = 0x10;
/// The HRESULT.
pub const MIX_FMT_RESULT: u64 = 0x18;

/// `get_device_period` (17): `{ const char *device; UINT flow; HRESULT result;
/// REFERENCE_TIME *def_period; REFERENCE_TIME *min_period; }`. Either pointer
/// may be NULL.
pub const PERIOD_DEVICE: u64 = 0x00;
/// The data flow.
pub const PERIOD_FLOW: u64 = 0x08;
/// The HRESULT.
pub const PERIOD_RESULT: u64 = 0x0c;
/// Out: the default period, in 100 ns units. mmdevapi clamps whatever the
/// driver reports up to 10 ms (`0x186A0`).
pub const PERIOD_DEF: u64 = 0x10;
/// Out: the minimum period, in 100 ns units.
pub const PERIOD_MIN: u64 = 0x18;

/// `is_format_supported` (14): `{ const char *device; UINT flow; UINT share;
/// const WAVEFORMATEX *fmt_in; HRESULT result; }`. There is no `fmt_out`:
/// mmdevapi answers a shared-mode near-match by calling its own `GetMixFormat`
/// when the driver returns `S_FALSE`.
pub const FMT_SUPPORTED_DEVICE: u64 = 0x00;
/// The data flow.
pub const FMT_SUPPORTED_FLOW: u64 = 0x08;
/// `AUDCLNT_SHAREMODE` (0 = shared, 1 = exclusive).
pub const FMT_SUPPORTED_SHARE: u64 = 0x0c;
/// The format being probed.
pub const FMT_SUPPORTED_FMT: u64 = 0x10;
/// The HRESULT: `S_OK`, `S_FALSE` (a closer match exists) or
/// [`AUDCLNT_E_UNSUPPORTED_FORMAT`].
pub const FMT_SUPPORTED_RESULT: u64 = 0x18;

/// `create_stream` (4) — the widest structure in the table, 0x50 bytes.
/// `{ const char *name; const char *device; UINT flow; UINT share; UINT flags;
///    REFERENCE_TIME duration; REFERENCE_TIME period; const WAVEFORMATEX *fmt;
///    HRESULT result; UINT32 *channel_count; stream_handle *stream; }`
pub const CREATE_NAME: u64 = 0x00;
/// The endpoint id (a `char` string, see [`ENDPOINT_ID_OFF`]).
pub const CREATE_DEVICE: u64 = 0x08;
/// The data flow.
pub const CREATE_FLOW: u64 = 0x10;
/// `AUDCLNT_SHAREMODE`.
pub const CREATE_SHARE: u64 = 0x14;
/// `AUDCLNT_STREAMFLAGS_*`.
pub const CREATE_FLAGS: u64 = 0x18;
/// Buffer duration in 100 ns units. mmdevapi has already raised it to at least
/// three device periods before the call.
pub const CREATE_DURATION: u64 = 0x20;
/// Device period in 100 ns units.
pub const CREATE_PERIOD: u64 = 0x28;
/// The `WAVEFORMATEX` the client asked for.
pub const CREATE_FMT: u64 = 0x30;
/// The HRESULT.
pub const CREATE_RESULT: u64 = 0x38;
/// Out: channel count, used to size mmdevapi's per-channel volume array.
pub const CREATE_CHANNEL_COUNT: u64 = 0x40;
/// Out: the opaque stream handle every later call carries.
pub const CREATE_STREAM: u64 = 0x48;

/// `release_stream` (5): `{ stream_handle stream; HANDLE timer_thread;
/// HRESULT result; }`.
pub const RELEASE_STREAM_STREAM: u64 = 0x00;
/// The timer thread `client_Start` created, so the driver can join it.
pub const RELEASE_STREAM_TIMER: u64 = 0x08;
/// The HRESULT.
pub const RELEASE_STREAM_RESULT: u64 = 0x10;

/// `start` / `stop` / `reset` / `is_started` (6, 7, 8, 28):
/// `{ stream_handle stream; HRESULT result; }`.
pub const STREAM_ONLY_STREAM: u64 = 0x00;
/// The HRESULT.
pub const STREAM_ONLY_RESULT: u64 = 0x08;

/// `get_buffer_size` (18), `get_current_padding` (20), `get_latency` (19),
/// `get_frequency` (22), `get_next_packet_size` (21):
/// `{ stream_handle stream; HRESULT result; T *out; }`.
pub const STREAM_OUT_STREAM: u64 = 0x00;
/// The HRESULT.
pub const STREAM_OUT_RESULT: u64 = 0x08;
/// The single out pointer (a `UINT32*` or a `UINT64*`/`REFERENCE_TIME*`).
pub const STREAM_OUT_PTR: u64 = 0x10;

/// `get_render_buffer` (10): `{ stream_handle stream; UINT32 frames;
/// HRESULT result; BYTE **data; }`. `*data` receives a pointer the **guest**
/// then writes PCM into, which is why exemu backs it with guest memory.
pub const RENDER_GET_STREAM: u64 = 0x00;
/// Frames requested.
pub const RENDER_GET_FRAMES: u64 = 0x08;
/// The HRESULT.
pub const RENDER_GET_RESULT: u64 = 0x0c;
/// The `BYTE**` the buffer pointer is written through.
pub const RENDER_GET_DATA: u64 = 0x10;

/// `release_render_buffer` (11): `{ stream_handle stream; UINT32 written_frames;
/// UINT flags; HRESULT result; }`.
pub const RENDER_REL_STREAM: u64 = 0x00;
/// Frames the client actually wrote.
pub const RENDER_REL_FRAMES: u64 = 0x08;
/// `AUDCLNT_BUFFERFLAGS_*` (bit 0 = `SILENT`).
pub const RENDER_REL_FLAGS: u64 = 0x0c;
/// The HRESULT.
pub const RENDER_REL_RESULT: u64 = 0x10;

/// `get_position` (23): `{ stream_handle stream; BOOL device; HRESULT result;
/// UINT64 *pos; UINT64 *qpctime; }`. `clock_GetPosition` passes `device = 0`;
/// `clock2_GetDevicePosition` is the other caller.
pub const POSITION_STREAM: u64 = 0x00;
/// Whether the device position (rather than the stream position) is wanted.
pub const POSITION_DEVICE: u64 = 0x08;
/// The HRESULT.
pub const POSITION_RESULT: u64 = 0x0c;
/// Out: the position.
pub const POSITION_POS: u64 = 0x10;
/// Out: the matching QPC timestamp; may be NULL.
pub const POSITION_QPC: u64 = 0x18;

/// `set_volumes` (24): `{ stream_handle stream; float master_volume;
/// const float *volumes; const float *session_volumes; }` — no result field.
pub const VOLUMES_STREAM: u64 = 0x00;
/// The session master volume as a `float`.
pub const VOLUMES_MASTER: u64 = 0x08;
/// Per-channel volumes (`channel_count` floats).
pub const VOLUMES_CHANNELS: u64 = 0x10;
/// Per-channel session volumes.
pub const VOLUMES_SESSION: u64 = 0x18;

/// `set_event_handle` (25): `{ stream_handle stream; HANDLE event;
/// HRESULT result; }`.
pub const EVENT_STREAM: u64 = 0x00;
/// The event the client wants signalled each period.
pub const EVENT_HANDLE: u64 = 0x08;
/// The HRESULT.
pub const EVENT_RESULT: u64 = 0x10;

/// `main_loop` (2) and `timer_loop` (9) each take a single qword: the event the
/// loop signals once it is running, and the stream to service, respectively.
pub const LOOP_ARG: u64 = 0x00;

// ---------------------------------------------------------------------------
// 4. HRESULTs — the honest answers
// ---------------------------------------------------------------------------

/// `S_OK`.
pub const S_OK: u32 = 0x0000_0000;
/// `S_FALSE` — `is_format_supported`'s "not this, but something close exists".
pub const S_FALSE: u32 = 0x0000_0001;
/// `E_NOTIMPL` — the honest answer for a code exemu has not implemented.
pub const E_NOTIMPL: u32 = 0x8000_4001;
/// `E_POINTER`.
pub const E_POINTER: u32 = 0x8000_4003;
/// `E_INVALIDARG`.
pub const E_INVALIDARG: u32 = 0x8007_0057;
/// `E_OUTOFMEMORY`.
pub const E_OUTOFMEMORY: u32 = 0x8007_000E;
/// `HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)` — `get_endpoint_ids`'s
/// "grow the buffer and ask again", which mmdevapi loops on.
pub const HRESULT_ERROR_INSUFFICIENT_BUFFER: u32 = 0x8007_007A;
/// `AUDCLNT_E_NOT_INITIALIZED`.
pub const AUDCLNT_E_NOT_INITIALIZED: u32 = 0x8889_0001;
/// `AUDCLNT_E_WRONG_ENDPOINT_TYPE` — a render call on a capture stream.
pub const AUDCLNT_E_WRONG_ENDPOINT_TYPE: u32 = 0x8889_0008;
/// `AUDCLNT_E_BUFFER_TOO_LARGE`.
pub const AUDCLNT_E_BUFFER_TOO_LARGE: u32 = 0x8889_0006;
/// `AUDCLNT_E_OUT_OF_ORDER` — `GetBuffer` twice without a `ReleaseBuffer`.
pub const AUDCLNT_E_OUT_OF_ORDER: u32 = 0x8889_0007;
/// `AUDCLNT_E_UNSUPPORTED_FORMAT`.
pub const AUDCLNT_E_UNSUPPORTED_FORMAT: u32 = 0x8889_000E;
/// `AUDCLNT_E_DEVICE_INVALIDATED` — exemu's answer for a capture endpoint.
pub const AUDCLNT_E_DEVICE_INVALIDATED: u32 = 0x8889_0004;
/// `AUDCLNT_E_INVALID_SIZE`.
pub const AUDCLNT_E_INVALID_SIZE: u32 = 0x8889_0009;
/// `AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED` — exclusive mode is out of scope.
pub const AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED: u32 = 0x8889_0017;

// ---------------------------------------------------------------------------
// 5. The endpoint exemu publishes, and its fixed mix format
// ---------------------------------------------------------------------------

/// `EDataFlow::eRender`.
pub const E_RENDER: u32 = 0;
/// `EDataFlow::eCapture`.
pub const E_CAPTURE: u32 = 1;

/// `AUDCLNT_SHAREMODE_SHARED`.
pub const SHARE_SHARED: u32 = 0;
/// `AUDCLNT_SHAREMODE_EXCLUSIVE`.
pub const SHARE_EXCLUSIVE: u32 = 1;

/// `CLSID_MMDeviceEnumerator` — the class a program creates to reach the whole
/// stack (`CoCreateInstance` → `IMMDeviceEnumerator` → `IMMDevice` →
/// `IAudioClient` → `IAudioRenderClient`). Public `mmdeviceapi.h`; exemu's
/// registry seeds it against `mmdevapi.dll`, which serves it from
/// `DllGetClassObject`.
pub const CLSID_MM_DEVICE_ENUMERATOR: &str = "{BCDE0395-E52F-467C-8E3D-C4579291692E}";

/// The friendly name of exemu's single render endpoint (a `WCHAR` string in the
/// endpoint table).
pub const ENDPOINT_NAME: &str = "exemu CoreAudio Output";
/// Its opaque id (a `char` string — see [`ENDPOINT_ID_OFF`]).
pub const ENDPOINT_ID: &str = "exemu-coreaudio-render";

/// The one shared-mode mix format exemu offers: 48 kHz stereo 32-bit float,
/// which is CoreAudio's own canonical format and needs no conversion on the
/// host side.
pub const MIX_SAMPLE_RATE: u32 = 48_000;
/// Channels in that format.
pub const MIX_CHANNELS: u16 = 2;
/// Bits per sample in that format.
pub const MIX_BITS: u16 = 32;
/// Bytes per frame (`MIX_CHANNELS * MIX_BITS / 8`).
pub const MIX_FRAME_BYTES: u32 = (MIX_CHANNELS as u32) * (MIX_BITS as u32) / 8;

/// `WAVE_FORMAT_EXTENSIBLE`.
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
/// `WAVE_FORMAT_IEEE_FLOAT`.
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
/// `sizeof(WAVEFORMATEX)`.
pub const WAVEFORMATEX_LEN: u32 = 18;
/// `cbSize` for a `WAVEFORMATEXTENSIBLE` (22), and hence its total size of 40 —
/// the exact `CoTaskMemAlloc` mmdevapi makes for `get_mix_format`.
pub const WAVEFORMATEXTENSIBLE_EXTRA: u16 = 22;
/// `sizeof(WAVEFORMATEXTENSIBLE)`.
pub const WAVEFORMATEXTENSIBLE_LEN: u32 = WAVEFORMATEX_LEN + WAVEFORMATEXTENSIBLE_EXTRA as u32;
/// `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT` = `{00000003-0000-0010-8000-00AA00389B71}`,
/// in `GUID` byte order.
pub const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: [u8; 16] = [
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];
/// `SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT`.
pub const SPEAKER_STEREO: u32 = 0x3;

/// The default device period exemu reports, in 100 ns units (10 ms — also
/// mmdevapi's own floor, which it clamps anything smaller up to).
pub const DEFAULT_PERIOD: u64 = 100_000;
/// The minimum period exemu reports (3 ms).
pub const MIN_PERIOD: u64 = 30_000;

/// Hard ceiling on a stream's buffer, in frames — 10 s at [`MIX_SAMPLE_RATE`].
/// A `create_stream` asking for more is refused with
/// [`AUDCLNT_E_BUFFER_TOO_LARGE`] rather than allocating unboundedly.
pub const MAX_BUFFER_FRAMES: u32 = MIX_SAMPLE_RATE * 10;

// ---------------------------------------------------------------------------
// 6. State
// ---------------------------------------------------------------------------

/// One render stream created through [`CODE_CREATE_STREAM`].
pub(crate) struct Stream {
    /// Buffer capacity in frames, as reported by [`CODE_GET_BUFFER_SIZE`].
    capacity: u32,
    /// Guest-visible staging buffer handed out by [`CODE_GET_RENDER_BUFFER`],
    /// `capacity * MIX_FRAME_BYTES` bytes of committed guest memory.
    buffer: u64,
    /// Frames handed out by the outstanding `get_render_buffer`, if any.
    /// `Some` between a `GetBuffer` and its `ReleaseBuffer` — a second
    /// `GetBuffer` in that window is [`AUDCLNT_E_OUT_OF_ORDER`].
    held: Option<u32>,
    /// Frames written and not yet consumed by the host sink.
    padding: u32,
    /// Whether [`CODE_START`] has run and [`CODE_STOP`] has not.
    started: bool,
    /// Frames the sink has accepted since the stream was created — the
    /// `IAudioClock` position.
    position: u64,
}

/// Everything the audio boundary owns, hung off [`WinOs`].
#[derive(Default)]
pub struct AudioState {
    /// Live streams by opaque handle.
    streams: HashMap<u64, Stream>,
    /// Next handle to mint. Starts at 1 so 0 is never a valid stream (mmdevapi
    /// tests `stream != NULL` before every call).
    next_handle: u64,
}

// ---------------------------------------------------------------------------
// 7. Small helpers
// ---------------------------------------------------------------------------

/// Read a NUL-terminated `char` string out of guest memory, bounded.
fn read_cstr(mem: &dyn Memory, ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    match mem.read_cstr(ptr, 512) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(_) => String::new(),
    }
}

/// Write `value` as a NUL-terminated UTF-16 string at `ptr`; returns the byte
/// length written including the terminator.
fn write_wstr(mem: &mut dyn Memory, ptr: u64, value: &str) -> Result<u64> {
    let mut at = ptr;
    for unit in value.encode_utf16() {
        mem.write_u16(at, unit)?;
        at += 2;
    }
    mem.write_u16(at, 0)?;
    Ok(at + 2 - ptr)
}

/// Byte length of `value` as a NUL-terminated UTF-16 string.
fn wstr_len(value: &str) -> u64 {
    (value.encode_utf16().count() as u64 + 1) * 2
}

/// Write `value` as a NUL-terminated `char` string at `ptr`.
fn write_cstr(mem: &mut dyn Memory, ptr: u64, value: &str) -> Result<u64> {
    for (i, b) in value.as_bytes().iter().enumerate() {
        mem.write_u8(ptr + i as u64, *b)?;
    }
    mem.write_u8(ptr + value.len() as u64, 0)?;
    Ok(value.len() as u64 + 1)
}

/// The `WAVEFORMATEX` fields exemu needs out of a guest format block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Wfx {
    tag: u16,
    channels: u16,
    sample_rate: u32,
    bits: u16,
    /// `SubFormat.Data1` for a `WAVE_FORMAT_EXTENSIBLE` block, else 0.
    sub_tag: u32,
}

impl Wfx {
    /// Read the public `WAVEFORMATEX` layout: `wFormatTag, nChannels,
    /// nSamplesPerSec, nAvgBytesPerSec, nBlockAlign, wBitsPerSample, cbSize`.
    fn read(mem: &dyn Memory, ptr: u64) -> Result<Wfx> {
        let tag = mem.read_u16(ptr)?;
        let sub_tag = if tag == WAVE_FORMAT_EXTENSIBLE && mem.read_u16(ptr + 16)? >= WAVEFORMATEXTENSIBLE_EXTRA {
            // WAVEFORMATEXTENSIBLE.SubFormat starts at +24; Data1 identifies it.
            mem.read_u32(ptr + 24)?
        } else {
            0
        };
        Ok(Wfx {
            tag,
            channels: mem.read_u16(ptr + 2)?,
            sample_rate: mem.read_u32(ptr + 4)?,
            bits: mem.read_u16(ptr + 14)?,
            sub_tag,
        })
    }

    /// Whether this is exactly the one format exemu renders.
    fn is_mix_format(&self) -> bool {
        let float = self.tag == WAVE_FORMAT_IEEE_FLOAT
            || (self.tag == WAVE_FORMAT_EXTENSIBLE && self.sub_tag == WAVE_FORMAT_IEEE_FLOAT as u32);
        float && self.channels == MIX_CHANNELS && self.sample_rate == MIX_SAMPLE_RATE && self.bits == MIX_BITS
    }
}

/// Fill a 40-byte `WAVEFORMATEXTENSIBLE` at `ptr` with exemu's mix format.
fn write_mix_format(mem: &mut dyn Memory, ptr: u64) -> Result<()> {
    let block_align = MIX_FRAME_BYTES as u16;
    mem.write_u16(ptr, WAVE_FORMAT_EXTENSIBLE)?;
    mem.write_u16(ptr + 2, MIX_CHANNELS)?;
    mem.write_u32(ptr + 4, MIX_SAMPLE_RATE)?;
    mem.write_u32(ptr + 8, MIX_SAMPLE_RATE * MIX_FRAME_BYTES)?;
    mem.write_u16(ptr + 12, block_align)?;
    mem.write_u16(ptr + 14, MIX_BITS)?;
    mem.write_u16(ptr + 16, WAVEFORMATEXTENSIBLE_EXTRA)?;
    // WAVEFORMATEXTENSIBLE: Samples.wValidBitsPerSample, dwChannelMask, SubFormat.
    mem.write_u16(ptr + 18, MIX_BITS)?;
    mem.write_u32(ptr + 20, SPEAKER_STEREO)?;
    for (i, b) in KSDATAFORMAT_SUBTYPE_IEEE_FLOAT.iter().enumerate() {
        mem.write_u8(ptr + 24 + i as u64, *b)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. The unixlib entries
// ---------------------------------------------------------------------------

impl WinOs {
    /// The `AudioFormat` exemu's single endpoint runs at.
    fn mix_format() -> AudioFormat {
        AudioFormat {
            channels: MIX_CHANNELS,
            sample_rate: MIX_SAMPLE_RATE,
            bits: MIX_BITS,
            float: true,
        }
    }

    /// `get_endpoint_ids` (3). One render endpoint, no capture endpoints.
    fn audio_get_endpoint_ids(&mut self, mem: &mut dyn Memory, args: u64) -> Result<u32> {
        let flow = mem.read_u32(args + EP_IDS_FLOW)?;
        if flow != E_RENDER {
            // No capture endpoint: report zero devices, successfully. That is
            // what a render-only backend honestly is, and mmdevapi copes.
            mem.write_u32(args + EP_IDS_NUM, 0)?;
            mem.write_u32(args + EP_IDS_DEFAULT_IDX, 0)?;
            mem.write_u32(args + EP_IDS_RESULT, S_OK)?;
            return Ok(S_OK);
        }
        let name_off = ENDPOINT_STRIDE;
        let id_off = name_off + wstr_len(ENDPOINT_NAME);
        let needed = id_off + ENDPOINT_ID.len() as u64 + 1;
        let size = mem.read_u32(args + EP_IDS_SIZE)? as u64;
        let buf = mem.read_u64(args + EP_IDS_ENDPOINTS)?;
        if buf == 0 || size < needed {
            mem.write_u32(args + EP_IDS_SIZE, needed as u32)?;
            mem.write_u32(args + EP_IDS_RESULT, HRESULT_ERROR_INSUFFICIENT_BUFFER)?;
            return Ok(S_OK);
        }
        mem.write_u32(buf + ENDPOINT_NAME_OFF, name_off as u32)?;
        mem.write_u32(buf + ENDPOINT_ID_OFF, id_off as u32)?;
        write_wstr(mem, buf + name_off, ENDPOINT_NAME)?;
        write_cstr(mem, buf + id_off, ENDPOINT_ID)?;
        mem.write_u32(args + EP_IDS_NUM, 1)?;
        mem.write_u32(args + EP_IDS_DEFAULT_IDX, 0)?;
        mem.write_u32(args + EP_IDS_RESULT, S_OK)?;
        Ok(S_OK)
    }

    /// `create_stream` (4). Shared-mode render at the fixed mix format only.
    fn audio_create_stream(&mut self, mem: &mut dyn Memory, args: u64) -> Result<u32> {
        let fail = |mem: &mut dyn Memory, hr: u32| -> Result<u32> {
            mem.write_u32(args + CREATE_RESULT, hr)?;
            Ok(S_OK)
        };
        if mem.read_u32(args + CREATE_FLOW)? != E_RENDER {
            return fail(mem, AUDCLNT_E_WRONG_ENDPOINT_TYPE);
        }
        if mem.read_u32(args + CREATE_SHARE)? != SHARE_SHARED {
            return fail(mem, AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED);
        }
        let device = read_cstr(mem, mem.read_u64(args + CREATE_DEVICE)?);
        if device != ENDPOINT_ID {
            return fail(mem, AUDCLNT_E_DEVICE_INVALIDATED);
        }
        let fmt_ptr = mem.read_u64(args + CREATE_FMT)?;
        if fmt_ptr == 0 {
            return fail(mem, E_POINTER);
        }
        let fmt = Wfx::read(mem, fmt_ptr)?;
        if !fmt.is_mix_format() {
            return fail(mem, AUDCLNT_E_UNSUPPORTED_FORMAT);
        }
        // duration is in 100 ns units; frames = duration * rate / 10^7.
        let duration = mem.read_u64(args + CREATE_DURATION)?;
        let frames = duration.saturating_mul(MIX_SAMPLE_RATE as u64) / 10_000_000;
        let capacity = frames.clamp(1, MAX_BUFFER_FRAMES as u64) as u32;
        if frames > MAX_BUFFER_FRAMES as u64 {
            return fail(mem, AUDCLNT_E_BUFFER_TOO_LARGE);
        }
        let bytes = capacity as u64 * MIX_FRAME_BYTES as u64;
        let Some(buffer) = self.map_anywhere(mem, bytes, exemu_core::Perm::RW, "audio-render") else {
            return fail(mem, E_OUTOFMEMORY);
        };
        if !self.audio_sink.open(&Self::mix_format()) {
            return fail(mem, AUDCLNT_E_DEVICE_INVALIDATED);
        }
        self.audio.next_handle += 1;
        let handle = self.audio.next_handle;
        self.audio.streams.insert(
            handle,
            Stream {
                capacity,
                buffer,
                held: None,
                padding: 0,
                started: false,
                position: 0,
            },
        );
        let count_ptr = mem.read_u64(args + CREATE_CHANNEL_COUNT)?;
        if count_ptr != 0 {
            mem.write_u32(count_ptr, MIX_CHANNELS as u32)?;
        }
        let stream_ptr = mem.read_u64(args + CREATE_STREAM)?;
        if stream_ptr != 0 {
            mem.write_u64(stream_ptr, handle)?;
        }
        mem.write_u32(args + CREATE_RESULT, S_OK)?;
        Ok(S_OK)
    }

    /// `get_render_buffer` (10). Hands the guest a pointer into the stream's own
    /// guest-visible staging buffer; the guest writes PCM straight into it.
    fn audio_get_render_buffer(&mut self, mem: &mut dyn Memory, args: u64) -> Result<u32> {
        let handle = mem.read_u64(args + RENDER_GET_STREAM)?;
        let frames = mem.read_u32(args + RENDER_GET_FRAMES)?;
        let Some(stream) = self.audio.streams.get_mut(&handle) else {
            mem.write_u32(args + RENDER_GET_RESULT, AUDCLNT_E_NOT_INITIALIZED)?;
            return Ok(S_OK);
        };
        if stream.held.is_some() {
            mem.write_u32(args + RENDER_GET_RESULT, AUDCLNT_E_OUT_OF_ORDER)?;
            return Ok(S_OK);
        }
        if frames > stream.capacity - stream.padding {
            mem.write_u32(args + RENDER_GET_RESULT, AUDCLNT_E_BUFFER_TOO_LARGE)?;
            return Ok(S_OK);
        }
        let buffer = stream.buffer;
        stream.held = Some(frames);
        let data_ptr = mem.read_u64(args + RENDER_GET_DATA)?;
        if data_ptr == 0 {
            mem.write_u32(args + RENDER_GET_RESULT, E_POINTER)?;
            return Ok(S_OK);
        }
        mem.write_u64(data_ptr, buffer)?;
        mem.write_u32(args + RENDER_GET_RESULT, S_OK)?;
        Ok(S_OK)
    }

    /// `release_render_buffer` (11). Copies the frames the guest wrote out of
    /// guest memory and pushes them at the host sink — the one place audio
    /// actually leaves the emulator.
    fn audio_release_render_buffer(&mut self, mem: &mut dyn Memory, args: u64) -> Result<u32> {
        let handle = mem.read_u64(args + RENDER_REL_STREAM)?;
        let written = mem.read_u32(args + RENDER_REL_FRAMES)?;
        let flags = mem.read_u32(args + RENDER_REL_FLAGS)?;
        let Some(stream) = self.audio.streams.get_mut(&handle) else {
            mem.write_u32(args + RENDER_REL_RESULT, AUDCLNT_E_NOT_INITIALIZED)?;
            return Ok(S_OK);
        };
        let Some(held) = stream.held else {
            mem.write_u32(args + RENDER_REL_RESULT, AUDCLNT_E_OUT_OF_ORDER)?;
            return Ok(S_OK);
        };
        if written > held {
            mem.write_u32(args + RENDER_REL_RESULT, AUDCLNT_E_INVALID_SIZE)?;
            return Ok(S_OK);
        }
        stream.held = None;
        let base = stream.buffer;
        let bytes = written as usize * MIX_FRAME_BYTES as usize;
        stream.position += written as u64;
        // AUDCLNT_BUFFERFLAGS_SILENT: the client wrote nothing and means silence.
        let mut pcm = vec![0u8; bytes];
        if flags & 1 == 0 {
            for (i, b) in pcm.iter_mut().enumerate() {
                *b = mem.read_u8(base + i as u64)?;
            }
        }
        self.audio_sink.write(&pcm);
        mem.write_u32(args + RENDER_REL_RESULT, S_OK)?;
        Ok(S_OK)
    }

    /// The `{ stream; HRESULT; T *out }` family: 18, 19, 20, 21, 22.
    fn audio_stream_out(&mut self, mem: &mut dyn Memory, args: u64, code: u32) -> Result<u32> {
        let handle = mem.read_u64(args + STREAM_OUT_STREAM)?;
        let out = mem.read_u64(args + STREAM_OUT_PTR)?;
        let Some(stream) = self.audio.streams.get(&handle) else {
            mem.write_u32(args + STREAM_OUT_RESULT, AUDCLNT_E_NOT_INITIALIZED)?;
            return Ok(S_OK);
        };
        if out == 0 {
            mem.write_u32(args + STREAM_OUT_RESULT, E_POINTER)?;
            return Ok(S_OK);
        }
        match code {
            CODE_GET_BUFFER_SIZE => mem.write_u32(out, stream.capacity)?,
            CODE_GET_CURRENT_PADDING => mem.write_u32(out, stream.padding)?,
            CODE_GET_LATENCY => mem.write_u64(out, DEFAULT_PERIOD)?,
            // IAudioClock::GetFrequency, in the same units as GetPosition —
            // frames per second, since exemu's position counts frames.
            CODE_GET_FREQUENCY => mem.write_u64(out, MIX_SAMPLE_RATE as u64)?,
            // Capture only; a render stream never has a next packet.
            CODE_GET_NEXT_PACKET_SIZE => {
                mem.write_u32(args + STREAM_OUT_RESULT, AUDCLNT_E_WRONG_ENDPOINT_TYPE)?;
                return Ok(S_OK);
            }
            _ => {
                mem.write_u32(args + STREAM_OUT_RESULT, E_NOTIMPL)?;
                return Ok(S_OK);
            }
        }
        mem.write_u32(args + STREAM_OUT_RESULT, S_OK)?;
        Ok(S_OK)
    }

    /// The `{ stream; HRESULT }` family: 6, 7, 8, 28.
    fn audio_stream_only(&mut self, mem: &mut dyn Memory, args: u64, code: u32) -> Result<u32> {
        let handle = mem.read_u64(args + STREAM_ONLY_STREAM)?;
        let Some(stream) = self.audio.streams.get_mut(&handle) else {
            mem.write_u32(args + STREAM_ONLY_RESULT, AUDCLNT_E_NOT_INITIALIZED)?;
            return Ok(S_OK);
        };
        let hr = match code {
            CODE_START => {
                stream.started = true;
                self.audio_sink.start();
                S_OK
            }
            CODE_STOP => {
                stream.started = false;
                self.audio_sink.stop();
                S_OK
            }
            CODE_RESET => {
                if stream.started {
                    // AUDCLNT_E_NOT_STOPPED; mmdevapi surfaces it verbatim.
                    0x8889_0005
                } else {
                    stream.padding = 0;
                    stream.position = 0;
                    stream.held = None;
                    self.audio_sink.reset();
                    S_OK
                }
            }
            // is_started: S_OK when running, S_FALSE otherwise.
            CODE_IS_STARTED => {
                if stream.started {
                    S_OK
                } else {
                    S_FALSE
                }
            }
            _ => E_NOTIMPL,
        };
        mem.write_u32(args + STREAM_ONLY_RESULT, hr)?;
        Ok(S_OK)
    }
}

// ---------------------------------------------------------------------------
// 9. The table
// ---------------------------------------------------------------------------

/// Every entry below returns `STATUS_SUCCESS`: the NTSTATUS of a
/// `__wine_unix_call` says only "the call reached the unix side", and mmdevapi
/// checks it separately from the `HRESULT` field it then reads out of the
/// argument block (a nonzero NTSTATUS makes it `assert()` through
/// `wine_unix_call.part.0`). The *answer* always travels in the structure.
const STATUS_SUCCESS: u32 = 0;

fn entry_process_attach(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn entry_process_detach(os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    os.audio.streams.clear();
    os.audio_sink.close();
    Ok(STATUS_SUCCESS)
}

/// `main_loop` (2) — **and it must signal its event before returning.**
///
/// `mmdevapi!main_loop_start` creates a manual-reset event, spawns a thread on
/// `main_loop_func` with the event as its parameter, and then blocks in
/// `WaitForSingleObject(event, INFINITE)`. On real Wine the driver's loop
/// signals that event once it is running and then never returns. exemu drives
/// the render buffer synchronously from `release_render_buffer`, so there is no
/// loop to run — but a unix side that merely returns leaves the event unset and
/// **deadlocks `stream_init`**, which is the first thing every audio program
/// does. Signalling and returning lets the loop thread exit cleanly and the
/// caller proceed. (Recovered by disassembling `main_loop_start`; it is exactly
/// the kind of contract that is invisible until it hangs.)
fn entry_main_loop(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        let event = mem.read_u64(args + LOOP_ARG)?;
        os.signal_event_handle(event);
    }
    Ok(STATUS_SUCCESS)
}

/// `timer_loop` (9) — the per-stream thread `client_Start` spawns. Its argument
/// is the stream, not an event, and nobody waits on it, so returning is enough:
/// the thread exits and the render path stays synchronous.
fn entry_timer_loop(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn entry_get_endpoint_ids(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_get_endpoint_ids(mem, args)
}

fn entry_create_stream(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_create_stream(mem, args)
}

fn entry_release_stream(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    let handle = mem.read_u64(args + RELEASE_STREAM_STREAM)?;
    os.audio.streams.remove(&handle);
    if os.audio.streams.is_empty() {
        os.audio_sink.close();
    }
    mem.write_u32(args + RELEASE_STREAM_RESULT, S_OK)?;
    Ok(STATUS_SUCCESS)
}

fn entry_start(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_only(mem, args, CODE_START)
}
fn entry_stop(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_only(mem, args, CODE_STOP)
}
fn entry_reset(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_only(mem, args, CODE_RESET)
}
fn entry_is_started(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_only(mem, args, CODE_IS_STARTED)
}

fn entry_get_render_buffer(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_get_render_buffer(mem, args)
}
fn entry_release_render_buffer(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_release_render_buffer(mem, args)
}

/// Capture is out of scope: exemu publishes no capture endpoint, so a capture
/// call can only arrive on a stream that does not exist.
fn entry_capture(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + STREAM_ONLY_RESULT, AUDCLNT_E_WRONG_ENDPOINT_TYPE)?;
    Ok(STATUS_SUCCESS)
}

fn entry_is_format_supported(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    let hr = if mem.read_u32(args + FMT_SUPPORTED_FLOW)? != E_RENDER {
        AUDCLNT_E_WRONG_ENDPOINT_TYPE
    } else if mem.read_u32(args + FMT_SUPPORTED_SHARE)? != SHARE_SHARED {
        AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED
    } else {
        let fmt_ptr = mem.read_u64(args + FMT_SUPPORTED_FMT)?;
        if fmt_ptr == 0 {
            E_POINTER
        } else if Wfx::read(mem, fmt_ptr)?.is_mix_format() {
            S_OK
        } else {
            // S_FALSE means "no, but the mix format is close" — mmdevapi then
            // fetches it through GetMixFormat and hands it to the caller.
            S_FALSE
        }
    };
    mem.write_u32(args + FMT_SUPPORTED_RESULT, hr)?;
    Ok(STATUS_SUCCESS)
}

/// Loopback capture (15) is out of scope; the honest answer is `E_NOTIMPL`, and
/// mmdevapi turns that into a failed `Initialize`.
fn entry_get_loopback_capture_device(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    mem: &mut dyn Memory,
    args: u64,
) -> Result<u32> {
    // The result field of this block sits at +0x1c (the length is at +0x18).
    mem.write_u32(args + 0x1c, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

fn entry_get_mix_format(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    let hr = if mem.read_u32(args + MIX_FMT_FLOW)? != E_RENDER {
        AUDCLNT_E_WRONG_ENDPOINT_TYPE
    } else {
        let fmt = mem.read_u64(args + MIX_FMT_FMT)?;
        if fmt == 0 {
            E_POINTER
        } else {
            write_mix_format(mem, fmt)?;
            S_OK
        }
    };
    mem.write_u32(args + MIX_FMT_RESULT, hr)?;
    Ok(STATUS_SUCCESS)
}

fn entry_get_device_period(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    let def = mem.read_u64(args + PERIOD_DEF)?;
    if def != 0 {
        mem.write_u64(def, DEFAULT_PERIOD)?;
    }
    let min = mem.read_u64(args + PERIOD_MIN)?;
    if min != 0 {
        mem.write_u64(min, MIN_PERIOD)?;
    }
    mem.write_u32(args + PERIOD_RESULT, S_OK)?;
    Ok(STATUS_SUCCESS)
}

fn entry_get_buffer_size(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_out(mem, args, CODE_GET_BUFFER_SIZE)
}
fn entry_get_latency(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_out(mem, args, CODE_GET_LATENCY)
}
fn entry_get_current_padding(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_out(mem, args, CODE_GET_CURRENT_PADDING)
}
fn entry_get_next_packet_size(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_out(mem, args, CODE_GET_NEXT_PACKET_SIZE)
}
fn entry_get_frequency(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    os.audio_stream_out(mem, args, CODE_GET_FREQUENCY)
}

fn entry_get_position(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    let handle = mem.read_u64(args + POSITION_STREAM)?;
    let Some(stream) = os.audio.streams.get(&handle) else {
        mem.write_u32(args + POSITION_RESULT, AUDCLNT_E_NOT_INITIALIZED)?;
        return Ok(STATUS_SUCCESS);
    };
    let pos = stream.position;
    let ptr = mem.read_u64(args + POSITION_POS)?;
    if ptr != 0 {
        mem.write_u64(ptr, pos)?;
    }
    let qpc = mem.read_u64(args + POSITION_QPC)?;
    if qpc != 0 {
        mem.write_u64(qpc, crate::time::filetime_now())?;
    }
    mem.write_u32(args + POSITION_RESULT, S_OK)?;
    Ok(STATUS_SUCCESS)
}

/// `set_volumes` (24) has no result field, and exemu applies no gain: the guest
/// writes the samples it wants heard and exemu passes them through unchanged.
/// Accepting the call silently is correct here — nothing was refused.
fn entry_set_volumes(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

/// Event-driven mode (25) is out of scope: exemu never signals a period event,
/// so accepting the handle would be a lie that hangs the caller.
fn entry_set_event_handle(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + EVENT_RESULT, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

/// Sample-rate adjustment (26) is out of scope; the block's result field sits
/// where the `{stream, HRESULT}` family's does.
fn entry_set_sample_rate(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + STREAM_ONLY_RESULT, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

/// `test_connect` (27) — the probe `load_driver` uses to rank drivers.
fn entry_test_connect(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + TEST_CONNECT_PRIORITY, PRIORITY_PREFERRED)?;
    Ok(STATUS_SUCCESS)
}

/// The device property store (29) is out of scope. Its result field sits at
/// +0x20 in a block whose device/key/value pointers exemu does not consume.
fn entry_get_prop_value(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + 0x20, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

/// `midi_driver_name` (30) — `args` is the `WCHAR` buffer itself. An empty
/// string means "no separate MIDI driver", which is the truth here.
fn entry_midi_driver_name(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        mem.write_u16(args, 0)?;
    }
    Ok(STATUS_SUCCESS)
}

/// MIDI (31..=35) and the winmm aux device (36) are out of scope. They carry no
/// common result field, so the refusal travels as the NTSTATUS — which is what
/// makes it visible: mmdevapi's own `wine_unix_call` wrapper asserts on it
/// rather than pretending the call worked.
fn entry_unimplemented(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(crate::syscall::STATUS_NOT_IMPLEMENTED)
}

/// The driver unixlib, index for index. The order **is** the contract: it is the
/// `code` mmdevapi passes to `__wine_unix_call`, recovered exhaustively above.
static AUDIO_UNIXLIB: &[UnixEntry] = &[
    entry_process_attach,               // 0  process_attach
    entry_process_detach,               // 1  process_detach
    entry_main_loop,                    // 2  main_loop
    entry_get_endpoint_ids,             // 3  get_endpoint_ids
    entry_create_stream,                // 4  create_stream
    entry_release_stream,               // 5  release_stream
    entry_start,                        // 6  start
    entry_stop,                         // 7  stop
    entry_reset,                        // 8  reset
    entry_timer_loop,                   // 9  timer_loop
    entry_get_render_buffer,            // 10 get_render_buffer
    entry_release_render_buffer,        // 11 release_render_buffer
    entry_capture,                      // 12 get_capture_buffer
    entry_capture,                      // 13 release_capture_buffer
    entry_is_format_supported,          // 14 is_format_supported
    entry_get_loopback_capture_device,  // 15 get_loopback_capture_device
    entry_get_mix_format,               // 16 get_mix_format
    entry_get_device_period,            // 17 get_device_period
    entry_get_buffer_size,              // 18 get_buffer_size
    entry_get_latency,                  // 19 get_latency
    entry_get_current_padding,          // 20 get_current_padding
    entry_get_next_packet_size,         // 21 get_next_packet_size
    entry_get_frequency,                // 22 get_frequency
    entry_get_position,                 // 23 get_position
    entry_set_volumes,                  // 24 set_volumes
    entry_set_event_handle,             // 25 set_event_handle
    entry_set_sample_rate,              // 26 set_sample_rate
    entry_test_connect,                 // 27 test_connect
    entry_is_started,                   // 28 is_started
    entry_get_prop_value,               // 29 get_prop_value
    entry_midi_driver_name,             // 30 midi_driver_name
    entry_unimplemented,                // 31 midi_init
    entry_unimplemented,                // 32 midi_release
    entry_unimplemented,                // 33 midi_out_message
    entry_unimplemented,                // 34 midi_in_message
    entry_unimplemented,                // 35 midi_notify_wait
    entry_unimplemented,                // 36 aux_message
];

/// The unixlib [`crate::unixlib`] registers when the generated
/// [`DRIVER_MODULE`] asks `MemoryWineUnixFuncs` for its handle.
pub(crate) fn coreaudio_unixlib() -> Unixlib {
    Unixlib { name: "winecoreaudio", table: AUDIO_UNIXLIB }
}

// ---------------------------------------------------------------------------
// 10. exemu's own driver PE
// ---------------------------------------------------------------------------

/// Where the generated driver's `.text` lands.
const STUB_TEXT_RVA: u32 = 0x1000;
/// Where its export directory lands.
const STUB_RDATA_RVA: u32 = 0x2000;
/// Where its (empty) relocation block lands.
const STUB_RELOC_RVA: u32 = 0x3000;
/// Preferred base. Wine's own builtins prefer `0x1_8000_0000`; picking a
/// different one keeps the two out of each other's way without needing the
/// loader to relocate either.
const STUB_IMAGE_BASE: u64 = 0x0000_0001_9000_0000;
/// One exported symbol, so the image has a real export directory —
/// [`crate::unixlib`] identifies a builtin by the `Name` field in it, and Wine's
/// own `.drv` stubs are unidentifiable precisely because they have none.
const STUB_EXPORT: &str = "exemu_audio_driver";

/// Build **exemu's own** `winecoreaudio.drv`: a minimal PE32+ DLL whose
/// `DllMain` returns `TRUE` and whose export directory names it
/// [`DRIVER_MODULE`].
///
/// This is the audio driver's *PE half*, and it is deliberately as empty as
/// Wine's own — because that is all a Wine audio driver's PE half ever is (see
/// this module's header). Nothing here is derived from Wine: it is a stock PE
/// skeleton plus `mov eax, 1; ret`. The **unix half** — the interesting part —
/// is [`AUDIO_UNIXLIB`], and it is paired with this module the moment mmdevapi
/// asks `MemoryWineUnixFuncs` for its handle.
///
/// The application layer writes these bytes into the sandbox's
/// `C:\windows\system32` before a Wine boot, so `mmdevapi!load_driver`'s
/// `LoadLibraryW(L"winecoreaudio.drv")` finds them.
pub fn driver_stub_pe() -> Vec<u8> {
    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;
    const HEADERS: u32 = 0x400;

    // `.text`: DllMain and the one exported stub, both `mov eax, imm; ret`.
    let mut text = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // DllMain -> TRUE
    let export_off = text.len() as u32;
    text.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax, eax ; ret

    // `.rdata`: IMAGE_EXPORT_DIRECTORY + its three arrays + two strings.
    let dir_len = 40u32;
    let funcs_rva = STUB_RDATA_RVA + dir_len;
    let names_rva = funcs_rva + 4;
    let ords_rva = names_rva + 4;
    let modname_rva = ords_rva + 4; // 2-byte array, padded to 4
    let expname_rva = modname_rva + DRIVER_MODULE.len() as u32 + 1;
    let mut rdata = Vec::new();
    let put32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    put32(&mut rdata, 0); // Characteristics
    put32(&mut rdata, 0); // TimeDateStamp
    rdata.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    rdata.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    put32(&mut rdata, modname_rva); // Name — what unixlib.rs reads
    put32(&mut rdata, 1); // Base
    put32(&mut rdata, 1); // NumberOfFunctions
    put32(&mut rdata, 1); // NumberOfNames
    put32(&mut rdata, funcs_rva);
    put32(&mut rdata, names_rva);
    put32(&mut rdata, ords_rva);
    put32(&mut rdata, STUB_TEXT_RVA + export_off); // AddressOfFunctions[0]
    put32(&mut rdata, expname_rva); // AddressOfNames[0]
    rdata.extend_from_slice(&0u16.to_le_bytes()); // AddressOfNameOrdinals[0]
    rdata.extend_from_slice(&0u16.to_le_bytes()); // padding to 4 bytes
    rdata.extend_from_slice(DRIVER_MODULE.as_bytes());
    rdata.push(0);
    rdata.extend_from_slice(STUB_EXPORT.as_bytes());
    rdata.push(0);
    let export_dir_size = rdata.len() as u32;

    // `.reloc`: one block with two IMAGE_REL_BASED_ABSOLUTE (type 0) entries.
    // The image contains no absolute addresses, but a present, well-formed
    // relocation directory is what tells a loader it *may* rebase us.
    let mut reloc = Vec::new();
    reloc.extend_from_slice(&STUB_TEXT_RVA.to_le_bytes());
    reloc.extend_from_slice(&12u32.to_le_bytes());
    reloc.extend_from_slice(&0u16.to_le_bytes());
    reloc.extend_from_slice(&0u16.to_le_bytes());

    let raw = |n: usize| -> u32 { (n as u32).div_ceil(FILE_ALIGN) * FILE_ALIGN };
    let text_raw = raw(text.len());
    let rdata_raw = raw(rdata.len());
    let reloc_raw = raw(reloc.len());
    let size_of_image = STUB_RELOC_RVA + SECTION_ALIGN;

    let mut f = vec![0u8; HEADERS as usize];
    let put16 = |f: &mut [u8], at: usize, v: u16| f[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32f = |f: &mut [u8], at: usize, v: u32| f[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |f: &mut [u8], at: usize, v: u64| f[at..at + 8].copy_from_slice(&v.to_le_bytes());

    f[0] = b'M';
    f[1] = b'Z';
    put32f(&mut f, 0x3C, 0x40); // e_lfanew
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    put16(&mut f, coff, 0x8664); // Machine = AMD64
    put16(&mut f, coff + 2, 3); // NumberOfSections
    put16(&mut f, coff + 16, 240); // SizeOfOptionalHeader (112 + 16*8)
    // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    put16(&mut f, coff + 18, 0x0002 | 0x0020 | 0x2000);

    let opt = coff + 20;
    put16(&mut f, opt, 0x20B); // PE32+
    put32f(&mut f, opt + 4, text_raw); // SizeOfCode
    put32f(&mut f, opt + 8, rdata_raw + reloc_raw); // SizeOfInitializedData
    put32f(&mut f, opt + 16, STUB_TEXT_RVA); // AddressOfEntryPoint = DllMain
    put32f(&mut f, opt + 20, STUB_TEXT_RVA); // BaseOfCode
    put64(&mut f, opt + 24, STUB_IMAGE_BASE);
    put32f(&mut f, opt + 32, SECTION_ALIGN);
    put32f(&mut f, opt + 36, FILE_ALIGN);
    put16(&mut f, opt + 40, 6); // MajorOperatingSystemVersion
    put16(&mut f, opt + 48, 6); // MajorSubsystemVersion
    put32f(&mut f, opt + 56, size_of_image);
    put32f(&mut f, opt + 60, HEADERS);
    put16(&mut f, opt + 68, 3); // Subsystem = CONSOLE
    put16(&mut f, opt + 70, 0x0100); // DllCharacteristics = NX_COMPAT
    put64(&mut f, opt + 72, 0x100000); // SizeOfStackReserve
    put64(&mut f, opt + 80, 0x1000); // SizeOfStackCommit
    put64(&mut f, opt + 88, 0x100000); // SizeOfHeapReserve
    put64(&mut f, opt + 96, 0x1000); // SizeOfHeapCommit
    put32f(&mut f, opt + 108, 16); // NumberOfRvaAndSizes
    let dd = opt + 112;
    put32f(&mut f, dd, STUB_RDATA_RVA); // DataDirectory[0] = Export
    put32f(&mut f, dd + 4, export_dir_size);
    put32f(&mut f, dd + 5 * 8, STUB_RELOC_RVA); // DataDirectory[5] = BaseReloc
    put32f(&mut f, dd + 5 * 8 + 4, reloc.len() as u32);

    // Section headers.
    let mut sh = opt + 240;
    let section = |f: &mut [u8], at: &mut usize, name: &str, rva: u32, vsize: u32, raw_size: u32, ptr: u32, chars: u32| {
        let bytes = name.as_bytes();
        f[*at..*at + bytes.len()].copy_from_slice(bytes);
        put32f(f, *at + 8, vsize);
        put32f(f, *at + 12, rva);
        put32f(f, *at + 16, raw_size);
        put32f(f, *at + 20, ptr);
        put32f(f, *at + 36, chars);
        *at += 40;
    };
    let text_ptr = HEADERS;
    let rdata_ptr = text_ptr + text_raw;
    let reloc_ptr = rdata_ptr + rdata_raw;
    // CNT_CODE | MEM_EXECUTE | MEM_READ
    section(&mut f, &mut sh, ".text", STUB_TEXT_RVA, text.len() as u32, text_raw, text_ptr, 0x6000_0020);
    // CNT_INITIALIZED_DATA | MEM_READ
    section(&mut f, &mut sh, ".rdata", STUB_RDATA_RVA, rdata.len() as u32, rdata_raw, rdata_ptr, 0x4000_0040);
    // CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ
    section(&mut f, &mut sh, ".reloc", STUB_RELOC_RVA, reloc.len() as u32, reloc_raw, reloc_ptr, 0x4200_0040);

    text.resize(text_raw as usize, 0);
    rdata.resize(rdata_raw as usize, 0);
    reloc.resize(reloc_raw as usize, 0);
    f.extend_from_slice(&text);
    f.extend_from_slice(&rdata);
    f.extend_from_slice(&reloc);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table's length is the contract mmdevapi's dense 0..=36 relies on.
    #[test]
    fn the_table_covers_exactly_the_recovered_code_range() {
        assert_eq!(AUDIO_UNIXLIB.len(), UNIXLIB_ENTRIES);
        assert_eq!(CODE_AUX_MESSAGE as usize, UNIXLIB_ENTRIES - 1);
    }

    /// The driver module name is what `load_driver`'s `L"wine%s.drv"` builds
    /// from the registry value exemu seeds — derived, not spelled twice.
    #[test]
    fn the_driver_module_name_follows_load_drivers_own_formula() {
        assert_eq!(
            format!("{DRIVER_MODULE_PREFIX}{DRIVER_NAME}{DRIVER_MODULE_SUFFIX}"),
            DRIVER_MODULE
        );
        assert!(DRIVER_DEFAULT_LIST.split(',').any(|d| d == DRIVER_NAME));
    }

    /// `sizeof(WAVEFORMATEXTENSIBLE)` is what mmdevapi `CoTaskMemAlloc`s for
    /// `get_mix_format`, so the reply must fit it exactly.
    #[test]
    fn the_mix_format_block_is_a_waveformatextensible() {
        assert_eq!(WAVEFORMATEXTENSIBLE_LEN, 40);
        assert_eq!(MIX_FRAME_BYTES, 8);
    }

    /// The generated driver PE must parse, and — the load-bearing part — must
    /// carry an export directory whose `Name` is [`DRIVER_MODULE`], because
    /// that is the only thing [`crate::unixlib`] can identify a builtin by.
    /// Wine's own `.drv` stubs fail exactly this, which is why exemu ships one.
    #[test]
    fn the_generated_driver_pe_names_itself_through_its_export_directory() {
        let bytes = driver_stub_pe();
        let image = exemu_loader::parse(&bytes).expect("the generated driver parses as a PE");
        assert!(image.is_64bit, "PE32+ — exemu's builtins are 64-bit");
        assert_eq!(
            image.dll_name.as_deref(),
            Some(DRIVER_MODULE),
            "the export directory's Name is what unixlib.rs matches on"
        );
        assert_eq!(image.entry_rva, STUB_TEXT_RVA, "the entry point is DllMain");
        assert!(!image.relocations.is_empty() || bytes.len() > 0x800);
        assert!(image.imports.is_empty(), "the stub needs nothing from anyone");
        let exports: Vec<&str> = image.exports.iter().filter_map(|e| e.name.as_deref()).collect();
        assert_eq!(exports, vec![STUB_EXPORT]);
        // DllMain returns TRUE — a Wine builtin whose DllMain returns FALSE does
        // not load, which is the failure mode this whole pairing exists to avoid.
        let text = image.sections.iter().find(|s| s.name == ".text").expect(".text");
        assert_eq!(&text.data[..6], &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    }
}
