//! The audio-backend abstraction (roadmap W7.2).
//!
//! The domain only knows that *some* host backend can be handed PCM frames. The
//! OS layer's mmdevapi driver unixlib ([`exemu-os`'s `audio` module]) marshals
//! everything out of guest memory and then calls through [`AudioSink`], so it
//! stays free of any platform audio dependency — the same shape [`crate::driver`]
//! uses for the display.
//!
//! This is the Rust-native moral equivalent of the unix half of a Wine audio
//! driver, except that the *whole* interface Wine's `mmdevapi` speaks lives in
//! the OS layer and only the last hop — "here are N frames, play them" — crosses
//! this boundary. That keeps the CoreAudio implementation small enough to be
//! obviously correct, and lets tests substitute a recording sink.
//!
//! **Every method has a default no-op** so a backend implements only what it
//! supports and so [`NoAudio`] is one empty impl.

/// The PCM format a stream runs at. exemu drives a single fixed format
/// (48 kHz stereo 32-bit float), but the shape is general so a future backend
/// can refuse one it cannot open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    /// Channels per frame.
    pub channels: u16,
    /// Frames per second.
    pub sample_rate: u32,
    /// Bits per sample.
    pub bits: u16,
    /// Whether samples are IEEE floats (as opposed to signed integers).
    pub float: bool,
}

impl AudioFormat {
    /// Bytes per frame — `channels * bits / 8`.
    pub fn frame_bytes(&self) -> u32 {
        u32::from(self.channels) * u32::from(self.bits) / 8
    }
}

/// A host audio backend. Implemented by `exemu-audio` (CoreAudio) and by test
/// doubles; the OS layer holds a `Box<dyn AudioSink>`.
///
/// The contract is deliberately push-only and synchronous: [`write`](Self::write)
/// is called from the guest's `IAudioRenderClient::ReleaseBuffer`, with the
/// frames the guest just wrote, and must not block for longer than a device
/// period. A backend that buffers internally (CoreAudio's AudioQueue does)
/// simply enqueues them.
pub trait AudioSink: Send {
    /// Open the device at `format`. Returns `false` if the backend cannot serve
    /// it — the OS layer then fails the guest's `Initialize` with a real
    /// HRESULT rather than pretending. Called once per stream creation.
    fn open(&mut self, format: &AudioFormat) -> bool {
        let _ = format;
        true
    }

    /// Begin playback (the guest called `IAudioClient::Start`).
    fn start(&mut self) {}

    /// Pause playback (`IAudioClient::Stop`).
    fn stop(&mut self) {}

    /// Discard anything queued (`IAudioClient::Reset`).
    fn reset(&mut self) {}

    /// Accept `frames` of PCM in the format [`open`](Self::open) was given.
    /// The slice is a whole number of frames and is not retained.
    fn write(&mut self, frames: &[u8]) {
        let _ = frames;
    }

    /// Release the device (the last stream went away, or the process detached).
    fn close(&mut self) {}
}

/// The default backend: audio is accepted and dropped. This is what a headless
/// run and a machine with no audio device get, and it is deliberately *not* an
/// error — a program that plays a sound should still run.
pub struct NoAudio;

impl AudioSink for NoAudio {}
