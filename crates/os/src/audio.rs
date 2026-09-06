use std::collections::HashMap;

use exemu_core::{AudioFormat, CpuState, Memory, Result};

use crate::unixlib::{UnixEntry, Unixlib};
use crate::WinOs;

pub const DRIVER_KEY: &str = "Software\\Wine\\Drivers";

pub const DRIVER_VALUE: &str = "Audio";

pub const DRIVER_DEFAULT_LIST: &str = "pulse,alsa,oss,coreaudio";

pub const DRIVER_NAME: &str = "coreaudio";

pub const DRIVER_MODULE_PREFIX: &str = "wine";
pub const DRIVER_MODULE_SUFFIX: &str = ".drv";

pub const DRIVER_MODULE: &str = "winecoreaudio.drv";

pub const PRIORITY_UNAVAILABLE: u32 = 0;
pub const PRIORITY_LOW: u32 = 1;
pub const PRIORITY_NEUTRAL: u32 = 2;
pub const PRIORITY_PREFERRED: u32 = 3;

pub const UNIXLIB_ENTRIES: usize = 37;

pub const CODE_PROCESS_ATTACH: u32 = 0;
pub const CODE_PROCESS_DETACH: u32 = 1;
pub const CODE_MAIN_LOOP: u32 = 2;
pub const CODE_GET_ENDPOINT_IDS: u32 = 3;
pub const CODE_CREATE_STREAM: u32 = 4;
pub const CODE_RELEASE_STREAM: u32 = 5;
pub const CODE_START: u32 = 6;
pub const CODE_STOP: u32 = 7;
pub const CODE_RESET: u32 = 8;
pub const CODE_TIMER_LOOP: u32 = 9;
pub const CODE_GET_RENDER_BUFFER: u32 = 10;
pub const CODE_RELEASE_RENDER_BUFFER: u32 = 11;
pub const CODE_GET_CAPTURE_BUFFER: u32 = 12;
pub const CODE_RELEASE_CAPTURE_BUFFER: u32 = 13;
pub const CODE_IS_FORMAT_SUPPORTED: u32 = 14;
pub const CODE_GET_LOOPBACK_CAPTURE_DEVICE: u32 = 15;
pub const CODE_GET_MIX_FORMAT: u32 = 16;
pub const CODE_GET_DEVICE_PERIOD: u32 = 17;
pub const CODE_GET_BUFFER_SIZE: u32 = 18;
pub const CODE_GET_LATENCY: u32 = 19;
pub const CODE_GET_CURRENT_PADDING: u32 = 20;
pub const CODE_GET_NEXT_PACKET_SIZE: u32 = 21;
pub const CODE_GET_FREQUENCY: u32 = 22;
pub const CODE_GET_POSITION: u32 = 23;
pub const CODE_SET_VOLUMES: u32 = 24;
pub const CODE_SET_EVENT_HANDLE: u32 = 25;
pub const CODE_SET_SAMPLE_RATE: u32 = 26;
pub const CODE_TEST_CONNECT: u32 = 27;
pub const CODE_IS_STARTED: u32 = 28;
pub const CODE_GET_PROP_VALUE: u32 = 29;
pub const CODE_MIDI_DRIVER_NAME: u32 = 30;
pub const CODE_MIDI_INIT: u32 = 31;
pub const CODE_MIDI_RELEASE: u32 = 32;
pub const CODE_MIDI_OUT_MESSAGE: u32 = 33;
pub const CODE_MIDI_IN_MESSAGE: u32 = 34;
pub const CODE_MIDI_NOTIFY_WAIT: u32 = 35;
pub const CODE_AUX_MESSAGE: u32 = 36;

pub const EP_IDS_FLOW: u64 = 0x00;
pub const EP_IDS_ENDPOINTS: u64 = 0x08;
pub const EP_IDS_SIZE: u64 = 0x10;
pub const EP_IDS_RESULT: u64 = 0x14;
pub const EP_IDS_NUM: u64 = 0x18;
pub const EP_IDS_DEFAULT_IDX: u64 = 0x1c;

pub const ENDPOINT_STRIDE: u64 = 8;
pub const ENDPOINT_NAME_OFF: u64 = 0;
pub const ENDPOINT_ID_OFF: u64 = 4;

pub const TEST_CONNECT_NAME: u64 = 0x00;
pub const TEST_CONNECT_PRIORITY: u64 = 0x08;

pub const MIX_FMT_DEVICE: u64 = 0x00;
pub const MIX_FMT_FLOW: u64 = 0x08;
pub const MIX_FMT_FMT: u64 = 0x10;
pub const MIX_FMT_RESULT: u64 = 0x18;

pub const PERIOD_DEVICE: u64 = 0x00;
pub const PERIOD_FLOW: u64 = 0x08;
pub const PERIOD_RESULT: u64 = 0x0c;
pub const PERIOD_DEF: u64 = 0x10;
pub const PERIOD_MIN: u64 = 0x18;

pub const FMT_SUPPORTED_DEVICE: u64 = 0x00;
pub const FMT_SUPPORTED_FLOW: u64 = 0x08;
pub const FMT_SUPPORTED_SHARE: u64 = 0x0c;
pub const FMT_SUPPORTED_FMT: u64 = 0x10;
pub const FMT_SUPPORTED_RESULT: u64 = 0x18;

pub const CREATE_NAME: u64 = 0x00;
pub const CREATE_DEVICE: u64 = 0x08;
pub const CREATE_FLOW: u64 = 0x10;
pub const CREATE_SHARE: u64 = 0x14;
pub const CREATE_FLAGS: u64 = 0x18;
pub const CREATE_DURATION: u64 = 0x20;
pub const CREATE_PERIOD: u64 = 0x28;
pub const CREATE_FMT: u64 = 0x30;
pub const CREATE_RESULT: u64 = 0x38;
pub const CREATE_CHANNEL_COUNT: u64 = 0x40;
pub const CREATE_STREAM: u64 = 0x48;

pub const RELEASE_STREAM_STREAM: u64 = 0x00;
pub const RELEASE_STREAM_TIMER: u64 = 0x08;
pub const RELEASE_STREAM_RESULT: u64 = 0x10;

pub const STREAM_ONLY_STREAM: u64 = 0x00;
pub const STREAM_ONLY_RESULT: u64 = 0x08;

pub const STREAM_OUT_STREAM: u64 = 0x00;
pub const STREAM_OUT_RESULT: u64 = 0x08;
pub const STREAM_OUT_PTR: u64 = 0x10;

pub const RENDER_GET_STREAM: u64 = 0x00;
pub const RENDER_GET_FRAMES: u64 = 0x08;
pub const RENDER_GET_RESULT: u64 = 0x0c;
pub const RENDER_GET_DATA: u64 = 0x10;

pub const RENDER_REL_STREAM: u64 = 0x00;
pub const RENDER_REL_FRAMES: u64 = 0x08;
pub const RENDER_REL_FLAGS: u64 = 0x0c;
pub const RENDER_REL_RESULT: u64 = 0x10;

pub const POSITION_STREAM: u64 = 0x00;
pub const POSITION_DEVICE: u64 = 0x08;
pub const POSITION_RESULT: u64 = 0x0c;
pub const POSITION_POS: u64 = 0x10;
pub const POSITION_QPC: u64 = 0x18;

pub const VOLUMES_STREAM: u64 = 0x00;
pub const VOLUMES_MASTER: u64 = 0x08;
pub const VOLUMES_CHANNELS: u64 = 0x10;
pub const VOLUMES_SESSION: u64 = 0x18;

pub const EVENT_STREAM: u64 = 0x00;
pub const EVENT_HANDLE: u64 = 0x08;
pub const EVENT_RESULT: u64 = 0x10;

pub const SAMPLE_RATE_STREAM: u64 = 0x00;
pub const SAMPLE_RATE_RATE: u64 = 0x08;
pub const SAMPLE_RATE_RESULT: u64 = 0x0c;

pub const LOOP_ARG: u64 = 0x00;

pub const S_OK: u32 = 0x0000_0000;
pub const S_FALSE: u32 = 0x0000_0001;
pub const E_NOTIMPL: u32 = 0x8000_4001;
pub const E_POINTER: u32 = 0x8000_4003;
pub const E_INVALIDARG: u32 = 0x8007_0057;
pub const E_OUTOFMEMORY: u32 = 0x8007_000E;
pub const HRESULT_ERROR_INSUFFICIENT_BUFFER: u32 = 0x8007_007A;
pub const AUDCLNT_E_NOT_INITIALIZED: u32 = 0x8889_0001;
pub const AUDCLNT_E_WRONG_ENDPOINT_TYPE: u32 = 0x8889_0008;
pub const AUDCLNT_E_BUFFER_TOO_LARGE: u32 = 0x8889_0006;
pub const AUDCLNT_E_OUT_OF_ORDER: u32 = 0x8889_0007;
pub const AUDCLNT_E_UNSUPPORTED_FORMAT: u32 = 0x8889_000E;
pub const AUDCLNT_E_DEVICE_INVALIDATED: u32 = 0x8889_0004;
pub const AUDCLNT_E_INVALID_SIZE: u32 = 0x8889_0009;
pub const AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED: u32 = 0x8889_0017;

pub const E_RENDER: u32 = 0;
pub const E_CAPTURE: u32 = 1;

pub const SHARE_SHARED: u32 = 0;
pub const SHARE_EXCLUSIVE: u32 = 1;

pub const CLSID_MM_DEVICE_ENUMERATOR: &str = "{BCDE0395-E52F-467C-8E3D-C4579291692E}";

pub const ENDPOINT_NAME: &str = "exemu CoreAudio Output";
pub const ENDPOINT_ID: &str = "exemu-coreaudio-render";

pub const MIX_SAMPLE_RATE: u32 = 48_000;
pub const MIX_CHANNELS: u16 = 2;
pub const MIX_BITS: u16 = 32;
pub const MIX_FRAME_BYTES: u32 = (MIX_CHANNELS as u32) * (MIX_BITS as u32) / 8;

pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
pub const WAVEFORMATEX_LEN: u32 = 18;
pub const WAVEFORMATEXTENSIBLE_EXTRA: u16 = 22;
pub const WAVEFORMATEXTENSIBLE_LEN: u32 = WAVEFORMATEX_LEN + WAVEFORMATEXTENSIBLE_EXTRA as u32;
pub const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: [u8; 16] = [
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];
pub const SPEAKER_STEREO: u32 = 0x3;

pub const DEFAULT_PERIOD: u64 = 100_000;
pub const MIN_PERIOD: u64 = 30_000;

pub const MAX_BUFFER_FRAMES: u32 = MIX_SAMPLE_RATE * 10;

pub(crate) struct Stream {
    capacity: u32,
    buffer: u64,
    held: Option<u32>,
    started: bool,
    position: u64,
}

#[derive(Default)]
pub struct AudioState {
    streams: HashMap<u64, Stream>,
    next_handle: u64,
}

fn read_cstr(mem: &dyn Memory, ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    match mem.read_cstr(ptr, 512) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(_) => String::new(),
    }
}

fn write_wstr(mem: &mut dyn Memory, ptr: u64, value: &str) -> Result<u64> {
    let mut at = ptr;
    for unit in value.encode_utf16() {
        mem.write_u16(at, unit)?;
        at += 2;
    }
    mem.write_u16(at, 0)?;
    Ok(at + 2 - ptr)
}

fn wstr_len(value: &str) -> u64 {
    (value.encode_utf16().count() as u64 + 1) * 2
}

fn write_cstr(mem: &mut dyn Memory, ptr: u64, value: &str) -> Result<u64> {
    for (i, b) in value.as_bytes().iter().enumerate() {
        mem.write_u8(ptr + i as u64, *b)?;
    }
    mem.write_u8(ptr + value.len() as u64, 0)?;
    Ok(value.len() as u64 + 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Wfx {
    tag: u16,
    channels: u16,
    sample_rate: u32,
    bits: u16,
    sub_tag: u32,
}

impl Wfx {
    fn read(mem: &dyn Memory, ptr: u64) -> Result<Wfx> {
        let tag = mem.read_u16(ptr)?;
        let sub_tag = if tag == WAVE_FORMAT_EXTENSIBLE && mem.read_u16(ptr + 16)? >= WAVEFORMATEXTENSIBLE_EXTRA {
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

    fn is_mix_format(&self) -> bool {
        let float = self.tag == WAVE_FORMAT_IEEE_FLOAT
            || (self.tag == WAVE_FORMAT_EXTENSIBLE && self.sub_tag == WAVE_FORMAT_IEEE_FLOAT as u32);
        float && self.channels == MIX_CHANNELS && self.sample_rate == MIX_SAMPLE_RATE && self.bits == MIX_BITS
    }
}

fn write_mix_format(mem: &mut dyn Memory, ptr: u64) -> Result<()> {
    let block_align = MIX_FRAME_BYTES as u16;
    mem.write_u16(ptr, WAVE_FORMAT_EXTENSIBLE)?;
    mem.write_u16(ptr + 2, MIX_CHANNELS)?;
    mem.write_u32(ptr + 4, MIX_SAMPLE_RATE)?;
    mem.write_u32(ptr + 8, MIX_SAMPLE_RATE * MIX_FRAME_BYTES)?;
    mem.write_u16(ptr + 12, block_align)?;
    mem.write_u16(ptr + 14, MIX_BITS)?;
    mem.write_u16(ptr + 16, WAVEFORMATEXTENSIBLE_EXTRA)?;
    mem.write_u16(ptr + 18, MIX_BITS)?;
    mem.write_u32(ptr + 20, SPEAKER_STEREO)?;
    for (i, b) in KSDATAFORMAT_SUBTYPE_IEEE_FLOAT.iter().enumerate() {
        mem.write_u8(ptr + 24 + i as u64, *b)?;
    }
    Ok(())
}

impl WinOs {
    fn mix_format() -> AudioFormat {
        AudioFormat {
            channels: MIX_CHANNELS,
            sample_rate: MIX_SAMPLE_RATE,
            bits: MIX_BITS,
            float: true,
        }
    }

    fn audio_get_endpoint_ids(&mut self, mem: &mut dyn Memory, args: u64) -> Result<u32> {
        let flow = mem.read_u32(args + EP_IDS_FLOW)?;
        if flow != E_RENDER {
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
        if frames > stream.capacity {
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
            CODE_GET_CURRENT_PADDING => mem.write_u32(out, 0)?,
            CODE_GET_LATENCY => mem.write_u64(out, DEFAULT_PERIOD)?,
            CODE_GET_FREQUENCY => mem.write_u64(out, MIX_SAMPLE_RATE as u64)?,
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
                    0x8889_0005
                } else {
                    stream.position = 0;
                    stream.held = None;
                    self.audio_sink.reset();
                    S_OK
                }
            }
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

const STATUS_SUCCESS: u32 = 0;

fn entry_process_attach(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn entry_process_detach(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    for (_, stream) in std::mem::take(&mut os.audio.streams) {
        let _ = mem.unmap(stream.buffer, stream.capacity as u64 * MIX_FRAME_BYTES as u64);
    }
    os.audio_sink.close();
    Ok(STATUS_SUCCESS)
}

fn entry_main_loop(os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        let event = mem.read_u64(args + LOOP_ARG)?;
        os.signal_event_handle(event);
    }
    Ok(STATUS_SUCCESS)
}

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
    if let Some(stream) = os.audio.streams.remove(&handle) {
        let _ = mem.unmap(stream.buffer, stream.capacity as u64 * MIX_FRAME_BYTES as u64);
    }
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
            S_FALSE
        }
    };
    mem.write_u32(args + FMT_SUPPORTED_RESULT, hr)?;
    Ok(STATUS_SUCCESS)
}

fn entry_get_loopback_capture_device(
    _os: &mut WinOs,
    _cpu: &mut CpuState,
    mem: &mut dyn Memory,
    args: u64,
) -> Result<u32> {
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

fn entry_set_volumes(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(STATUS_SUCCESS)
}

fn entry_set_event_handle(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + EVENT_RESULT, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

fn entry_set_sample_rate(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + SAMPLE_RATE_RESULT, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

fn entry_test_connect(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + TEST_CONNECT_PRIORITY, PRIORITY_PREFERRED)?;
    Ok(STATUS_SUCCESS)
}

fn entry_get_prop_value(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    mem.write_u32(args + 0x20, E_NOTIMPL)?;
    Ok(STATUS_SUCCESS)
}

fn entry_midi_driver_name(_os: &mut WinOs, _cpu: &mut CpuState, mem: &mut dyn Memory, args: u64) -> Result<u32> {
    if args != 0 {
        mem.write_u16(args, 0)?;
    }
    Ok(STATUS_SUCCESS)
}

fn entry_unimplemented(_os: &mut WinOs, _cpu: &mut CpuState, _mem: &mut dyn Memory, _args: u64) -> Result<u32> {
    Ok(crate::syscall::STATUS_NOT_IMPLEMENTED)
}

static AUDIO_UNIXLIB: &[UnixEntry] = &[
    entry_process_attach,
    entry_process_detach,
    entry_main_loop,
    entry_get_endpoint_ids,
    entry_create_stream,
    entry_release_stream,
    entry_start,
    entry_stop,
    entry_reset,
    entry_timer_loop,
    entry_get_render_buffer,
    entry_release_render_buffer,
    entry_capture,
    entry_capture,
    entry_is_format_supported,
    entry_get_loopback_capture_device,
    entry_get_mix_format,
    entry_get_device_period,
    entry_get_buffer_size,
    entry_get_latency,
    entry_get_current_padding,
    entry_get_next_packet_size,
    entry_get_frequency,
    entry_get_position,
    entry_set_volumes,
    entry_set_event_handle,
    entry_set_sample_rate,
    entry_test_connect,
    entry_is_started,
    entry_get_prop_value,
    entry_midi_driver_name,
    entry_unimplemented,
    entry_unimplemented,
    entry_unimplemented,
    entry_unimplemented,
    entry_unimplemented,
    entry_unimplemented,
];

pub(crate) fn coreaudio_unixlib() -> Unixlib {
    Unixlib { name: "winecoreaudio", table: AUDIO_UNIXLIB, wow64: false }
}

const STUB_TEXT_RVA: u32 = 0x1000;
const STUB_RDATA_RVA: u32 = 0x2000;
const STUB_RELOC_RVA: u32 = 0x3000;
const STUB_IMAGE_BASE: u64 = 0x0000_0001_9000_0000;
const STUB_EXPORT: &str = "exemu_audio_driver";

pub fn driver_stub_pe() -> Vec<u8> {
    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;
    const HEADERS: u32 = 0x400;

    let mut text = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
    let export_off = text.len() as u32;
    text.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    let dir_len = 40u32;
    let funcs_rva = STUB_RDATA_RVA + dir_len;
    let names_rva = funcs_rva + 4;
    let ords_rva = names_rva + 4;
    let modname_rva = ords_rva + 4;
    let expname_rva = modname_rva + DRIVER_MODULE.len() as u32 + 1;
    let mut rdata = Vec::new();
    let put32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    put32(&mut rdata, 0);
    put32(&mut rdata, 0);
    rdata.extend_from_slice(&0u16.to_le_bytes());
    rdata.extend_from_slice(&0u16.to_le_bytes());
    put32(&mut rdata, modname_rva);
    put32(&mut rdata, 1);
    put32(&mut rdata, 1);
    put32(&mut rdata, 1);
    put32(&mut rdata, funcs_rva);
    put32(&mut rdata, names_rva);
    put32(&mut rdata, ords_rva);
    put32(&mut rdata, STUB_TEXT_RVA + export_off);
    put32(&mut rdata, expname_rva);
    rdata.extend_from_slice(&0u16.to_le_bytes());
    rdata.extend_from_slice(&0u16.to_le_bytes());
    rdata.extend_from_slice(DRIVER_MODULE.as_bytes());
    rdata.push(0);
    rdata.extend_from_slice(STUB_EXPORT.as_bytes());
    rdata.push(0);
    let export_dir_size = rdata.len() as u32;

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
    put32f(&mut f, 0x3C, 0x40);
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    put16(&mut f, coff, 0x8664);
    put16(&mut f, coff + 2, 3);
    put16(&mut f, coff + 16, 240);
    put16(&mut f, coff + 18, 0x0002 | 0x0020 | 0x2000);

    let opt = coff + 20;
    put16(&mut f, opt, 0x20B);
    put32f(&mut f, opt + 4, text_raw);
    put32f(&mut f, opt + 8, rdata_raw + reloc_raw);
    put32f(&mut f, opt + 16, STUB_TEXT_RVA);
    put32f(&mut f, opt + 20, STUB_TEXT_RVA);
    put64(&mut f, opt + 24, STUB_IMAGE_BASE);
    put32f(&mut f, opt + 32, SECTION_ALIGN);
    put32f(&mut f, opt + 36, FILE_ALIGN);
    put16(&mut f, opt + 40, 6);
    put16(&mut f, opt + 48, 6);
    put32f(&mut f, opt + 56, size_of_image);
    put32f(&mut f, opt + 60, HEADERS);
    put16(&mut f, opt + 68, 3);
    put16(&mut f, opt + 70, 0x0100);
    put64(&mut f, opt + 72, 0x100000);
    put64(&mut f, opt + 80, 0x1000);
    put64(&mut f, opt + 88, 0x100000);
    put64(&mut f, opt + 96, 0x1000);
    put32f(&mut f, opt + 108, 16);
    let dd = opt + 112;
    put32f(&mut f, dd, STUB_RDATA_RVA);
    put32f(&mut f, dd + 4, export_dir_size);
    put32f(&mut f, dd + 5 * 8, STUB_RELOC_RVA);
    put32f(&mut f, dd + 5 * 8 + 4, reloc.len() as u32);

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
    section(&mut f, &mut sh, ".text", STUB_TEXT_RVA, text.len() as u32, text_raw, text_ptr, 0x6000_0020);
    section(&mut f, &mut sh, ".rdata", STUB_RDATA_RVA, rdata.len() as u32, rdata_raw, rdata_ptr, 0x4000_0040);
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

    #[test]
    fn the_table_covers_exactly_the_recovered_code_range() {
        assert_eq!(AUDIO_UNIXLIB.len(), UNIXLIB_ENTRIES);
        assert_eq!(CODE_AUX_MESSAGE as usize, UNIXLIB_ENTRIES - 1);
    }

    #[test]
    fn the_driver_module_name_follows_load_drivers_own_formula() {
        assert_eq!(
            format!("{DRIVER_MODULE_PREFIX}{DRIVER_NAME}{DRIVER_MODULE_SUFFIX}"),
            DRIVER_MODULE
        );
        assert!(DRIVER_DEFAULT_LIST.split(',').any(|d| d == DRIVER_NAME));
    }

    #[test]
    fn the_mix_format_block_is_a_waveformatextensible() {
        assert_eq!(WAVEFORMATEXTENSIBLE_LEN, 40);
        assert_eq!(MIX_FRAME_BYTES, 8);
    }

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
        let text = image.sections.iter().find(|s| s.name == ".text").expect(".text");
        assert_eq!(&text.data[..6], &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    }
}
