//! # exemu-audio — the host audio backend
//!
//! The outermost ring on the audio path. The OS layer's mmdevapi driver unixlib
//! (`exemu_os::audio`) does all the guest-memory marshalling and then hands
//! plain PCM to an [`exemu_core::AudioSink`]; this crate implements that trait
//! over **CoreAudio**, the same way `exemu-gui` implements `UserDriver` over
//! AppKit. Nothing here knows what a `WAVEFORMATEX` is, and nothing in the inner
//! layers knows what an `AudioQueue` is.
//!
//! ## Why AudioQueue
//!
//! `AudioSink` is a **push** contract: the guest's
//! `IAudioRenderClient::ReleaseBuffer` produces N frames and they must go
//! somewhere. AudioToolbox's `AudioQueue` is CoreAudio's push-shaped output API
//! — you hand it buffers and it plays them — so the mapping is direct and the
//! unsafe surface is six C calls. The lower-level `AudioUnit`/AUHAL render
//! callback would need the same staging buffer plus a pull adapter on top.
//!
//! ## Shape
//!
//! [`CoreAudioSink::write`] appends into a staging queue. A fixed ring of three
//! AudioQueue buffers is enqueued at [`open`](CoreAudioSink::open); each time
//! CoreAudio finishes one it calls back, the callback refills it from the
//! staging queue (zero-padding on underrun, so a starved stream is *silence*,
//! never stale audio) and re-enqueues it.
//!
//! The callback takes a `Mutex` on the staging queue. That is not what a
//! hard-real-time backend would do, and it is recorded here rather than hidden:
//! for exemu's current purpose — an emulated guest producing audio far slower
//! than real time — the lock is never contended for long, and the honest
//! failure mode (a glitch) is preferable to the complexity of a lock-free ring
//! before anything needs it.
//!
//! ## Not the default, deliberately
//!
//! `exemu_core::NoAudio` (accept and drop) remains the default everywhere. This
//! backend is opted into by the application layer, so a headless run, a CI
//! machine with no audio device and every test keep working untouched — which is
//! also why the W7.2 gate drives a recording sink rather than this.

#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]

/// Frames per AudioQueue buffer. At 48 kHz, 1024 frames is ~21 ms — short
/// enough that `Stop` is responsive, long enough that the callback rate is
/// modest.
const FRAMES_PER_BUFFER: u32 = 1024;

/// How many buffers stay in flight. Three is the usual minimum that keeps the
/// device fed while one is being refilled.
const BUFFER_COUNT: usize = 3;

/// Ceiling on the staging queue, in frames. A guest that produces faster than
/// real time (an emulator can, in bursts) must not grow this without bound; past
/// the cap the **oldest** audio is dropped, because for playback the newest is
/// the audio anyone would want to hear.
const MAX_STAGED_FRAMES: usize = 48_000 * 2; // 2 s at 48 kHz

#[cfg(target_os = "macos")]
mod imp {
    use std::collections::VecDeque;
    use std::ffi::c_void;
    use std::ptr::NonNull;
    use std::sync::{Arc, Mutex};

    use objc2_audio_toolbox::{
        AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
        AudioQueueNewOutput, AudioQueueRef, AudioQueueStart, AudioQueueStop,
    };
    use objc2_core_audio_types::{
        kAudioFormatFlagIsFloat, kAudioFormatFlagIsPacked, kAudioFormatFlagIsSignedInteger,
        kAudioFormatLinearPCM, AudioStreamBasicDescription,
    };

    use exemu_core::{AudioFormat, AudioSink};

    use super::{BUFFER_COUNT, FRAMES_PER_BUFFER, MAX_STAGED_FRAMES};

    /// What the render callback and the guest thread share. Held by an `Arc`
    /// whose raw pointer is CoreAudio's `inUserData`, so it outlives the queue.
    struct Staging {
        /// PCM waiting to be played, in the opened format.
        pcm: Mutex<VecDeque<u8>>,
        /// Bytes per frame, for the [`MAX_STAGED_FRAMES`] cap.
        frame_bytes: usize,
    }

    /// The `AudioQueueRef` a live stream owns.
    ///
    /// `AudioQueueRef` is a raw pointer, so it is not `Send` by inference, but
    /// `AudioSink: Send` and exemu moves the sink onto the interpreter thread
    /// once at startup. AudioQueue's own API is documented as callable from any
    /// thread, and exemu only ever touches it from that one — so the marker is
    /// sound and the confinement is what makes it so.
    struct Queue(AudioQueueRef);
    // SAFETY: see the doc comment — single-threaded confinement plus AudioQueue's
    // own thread-safety guarantee.
    unsafe impl Send for Queue {}

    /// An opened stream.
    struct Live {
        queue: Queue,
        staging: Arc<Staging>,
        /// The `Arc` handed to CoreAudio as `inUserData`, reclaimed on close.
        raw_user_data: *const Staging,
        started: bool,
    }
    // SAFETY: `raw_user_data` is only ever read (as an `Arc` refcount to reclaim)
    // on the same thread that created it; the pointee is `Sync` by construction
    // (a `Mutex` and a `usize`).
    unsafe impl Send for Live {}

    /// CoreAudio's "this buffer is played out, refill it" callback.
    ///
    /// # Safety
    ///
    /// Invoked by CoreAudio with the `inUserData` given to `AudioQueueNewOutput`
    /// (a live `Arc<Staging>` raw pointer) and a buffer belonging to `queue`.
    unsafe extern "C-unwind" fn refill(
        user: *mut c_void,
        queue: AudioQueueRef,
        buffer: AudioQueueBufferRef,
    ) {
        if user.is_null() || buffer.is_null() {
            return;
        }
        // SAFETY: `user` is the pointer `open` handed to AudioQueueNewOutput,
        // and the `Arc` is kept alive until after AudioQueueDispose.
        let staging = unsafe { &*(user as *const Staging) };
        // SAFETY: CoreAudio owns this buffer and has just handed it back to us.
        let buf = unsafe { &mut *buffer };
        let capacity = buf.mAudioDataBytesCapacity as usize;
        // SAFETY: `mAudioData` points at `mAudioDataBytesCapacity` writable bytes.
        let dst = unsafe { std::slice::from_raw_parts_mut(buf.mAudioData.as_ptr().cast::<u8>(), capacity) };

        {
            // A poisoned lock must not stop playback: take the data anyway.
            let mut pcm = staging.pcm.lock().unwrap_or_else(|e| e.into_inner());
            let n = capacity.min(pcm.len());
            for slot in dst.iter_mut().take(n) {
                *slot = pcm.pop_front().unwrap_or(0);
            }
            // Underrun is silence, never whatever the buffer held last time.
            dst[n..].fill(0);
        }
        buf.mAudioDataByteSize = capacity as u32;
        // SAFETY: re-enqueueing the buffer we were just given, with no packet
        // descriptions (linear PCM).
        unsafe { AudioQueueEnqueueBuffer(queue, buffer, 0, std::ptr::null()) };
    }

    /// Translate an [`AudioFormat`] into CoreAudio's interleaved linear-PCM
    /// description. Returns `None` for a format this backend will not claim to
    /// support, so the OS layer can fail the guest's `Initialize` honestly.
    fn describe(format: &AudioFormat) -> Option<AudioStreamBasicDescription> {
        if format.channels == 0 || format.sample_rate == 0 {
            return None;
        }
        let flags = if format.float {
            if format.bits != 32 && format.bits != 64 {
                return None;
            }
            kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked
        } else {
            if format.bits != 16 && format.bits != 24 && format.bits != 32 {
                return None;
            }
            kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked
        };
        let frame_bytes = format.frame_bytes();
        Some(AudioStreamBasicDescription {
            mSampleRate: f64::from(format.sample_rate),
            mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: flags,
            mBytesPerPacket: frame_bytes,
            mFramesPerPacket: 1,
            mBytesPerFrame: frame_bytes,
            mChannelsPerFrame: u32::from(format.channels),
            mBitsPerChannel: u32::from(format.bits),
            mReserved: 0,
        })
    }

    /// A CoreAudio output stream behind the [`AudioSink`] seam.
    #[derive(Default)]
    pub struct CoreAudioSink {
        live: Option<Live>,
    }

    impl CoreAudioSink {
        /// A closed sink. It opens on the first stream the guest creates.
        pub fn new() -> CoreAudioSink {
            CoreAudioSink { live: None }
        }
    }

    impl AudioSink for CoreAudioSink {
        fn open(&mut self, format: &AudioFormat) -> bool {
            self.close();
            let Some(mut asbd) = describe(format) else {
                return false;
            };
            let frame_bytes = format.frame_bytes() as usize;
            let staging = Arc::new(Staging {
                pcm: Mutex::new(VecDeque::new()),
                frame_bytes,
            });
            let raw_user_data = Arc::into_raw(Arc::clone(&staging));

            let mut queue: AudioQueueRef = std::ptr::null_mut();
            // SAFETY: `asbd` and `queue` are live locals; the callback matches
            // the required signature; `raw_user_data` is a live `Arc` pointer
            // that outlives the queue (reclaimed only after Dispose).
            let status = unsafe {
                AudioQueueNewOutput(
                    NonNull::from(&mut asbd),
                    Some(refill),
                    raw_user_data as *mut c_void,
                    None,
                    None,
                    0,
                    NonNull::from(&mut queue),
                )
            };
            if status != 0 || queue.is_null() {
                // SAFETY: nothing took ownership of the pointer.
                drop(unsafe { Arc::from_raw(raw_user_data) });
                return false;
            }

            let bytes = FRAMES_PER_BUFFER as usize * frame_bytes;
            for _ in 0..BUFFER_COUNT {
                let mut buffer: AudioQueueBufferRef = std::ptr::null_mut();
                // SAFETY: `queue` is live; `buffer` is a live local.
                let ok = unsafe { AudioQueueAllocateBuffer(queue, bytes as u32, NonNull::from(&mut buffer)) };
                if ok != 0 || buffer.is_null() {
                    continue;
                }
                // Prime it with silence and hand it straight to the queue: the
                // refill callback takes over from here.
                // SAFETY: the buffer was just allocated by `queue` with `bytes`
                // writable bytes at `mAudioData`.
                unsafe {
                    let b = &mut *buffer;
                    std::slice::from_raw_parts_mut(b.mAudioData.as_ptr().cast::<u8>(), bytes).fill(0);
                    b.mAudioDataByteSize = bytes as u32;
                    AudioQueueEnqueueBuffer(queue, buffer, 0, std::ptr::null());
                }
            }

            self.live = Some(Live {
                queue: Queue(queue),
                staging,
                raw_user_data,
                started: false,
            });
            true
        }

        fn start(&mut self) {
            if let Some(live) = self.live.as_mut() {
                if !live.started {
                    // SAFETY: `queue` is live and owned by this sink.
                    unsafe { AudioQueueStart(live.queue.0, std::ptr::null()) };
                    live.started = true;
                }
            }
        }

        /// `IAudioClient::Stop` means "stop the stream", not "throw away what I
        /// already wrote". `AudioQueueStop(inImmediate: false)` matches that: it
        /// plays out what is already enqueued and *then* returns, and it stops
        /// accepting new buffers first, so the refill callback cannot keep it
        /// alive. It therefore blocks for up to one ring of buffers
        /// (`BUFFER_COUNT * FRAMES_PER_BUFFER`, ~64 ms at 48 kHz) — deliberate:
        /// a guest that writes a sound and immediately stops should hear it.
        fn stop(&mut self) {
            if let Some(live) = self.live.as_mut() {
                if live.started {
                    // SAFETY: `queue` is live and owned by this sink.
                    unsafe { AudioQueueStop(live.queue.0, false) };
                    live.started = false;
                }
            }
        }

        fn reset(&mut self) {
            if let Some(live) = self.live.as_ref() {
                live.staging.pcm.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
        }

        fn write(&mut self, frames: &[u8]) {
            let Some(live) = self.live.as_ref() else {
                return;
            };
            let cap = MAX_STAGED_FRAMES * live.staging.frame_bytes;
            let mut pcm = live.staging.pcm.lock().unwrap_or_else(|e| e.into_inner());
            pcm.extend(frames.iter().copied());
            // Drop the oldest audio past the ceiling — see MAX_STAGED_FRAMES.
            while pcm.len() > cap {
                pcm.pop_front();
            }
        }

        fn close(&mut self) {
            let Some(live) = self.live.take() else {
                return;
            };
            // A guest that never called `Stop` still wrote audio it meant to be
            // heard, so drain once (bounded by the ring, as in `stop`) before
            // tearing down. Then the immediate forms: after
            // `Dispose(immediate: true)` no further callback can run, which is
            // what makes dropping the `Arc` below sound.
            // SAFETY: `queue` is live and owned by this sink.
            unsafe {
                if live.started {
                    AudioQueueStop(live.queue.0, false);
                }
                AudioQueueStop(live.queue.0, true);
                AudioQueueDispose(live.queue.0, true);
            }
            // SAFETY: this reclaims the reference handed to AudioQueueNewOutput,
            // after the queue that held it is gone.
            drop(unsafe { Arc::from_raw(live.raw_user_data) });
        }
    }

    impl Drop for CoreAudioSink {
        fn drop(&mut self) {
            self.close();
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use exemu_core::{AudioFormat, AudioSink};

    /// Off macOS there is no CoreAudio. The type still exists so the application
    /// layer needs no `cfg`, and it refuses to open rather than pretending: a
    /// guest asking for a stream gets a real failure, not silence it might mistake
    /// for a working device.
    #[derive(Default)]
    pub struct CoreAudioSink;

    impl CoreAudioSink {
        /// A sink that opens nothing.
        pub fn new() -> CoreAudioSink {
            CoreAudioSink
        }
    }

    impl AudioSink for CoreAudioSink {
        fn open(&mut self, _format: &AudioFormat) -> bool {
            false
        }
    }
}

pub use imp::CoreAudioSink;

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{AudioFormat, AudioSink};

    /// A sink that was never opened must be inert: `write` before `open` is what
    /// a guest that ignored a failed `Initialize` would do, and it must not
    /// fault. (On a CI machine with no audio device `open` itself may fail, so
    /// this is deliberately the only behaviour asserted unconditionally.)
    #[test]
    fn an_unopened_sink_swallows_writes() {
        let mut sink = CoreAudioSink::new();
        sink.write(&[0u8; 64]);
        sink.start();
        sink.stop();
        sink.reset();
        sink.close();
    }

    /// The formats the backend refuses, refused for the right reason — a zero
    /// channel count or a bit depth CoreAudio's linear-PCM description cannot
    /// express. `open` returning `false` is what lets `exemu_os::audio` fail the
    /// guest's `Initialize` with a real HRESULT instead of going quiet.
    #[test]
    fn a_nonsense_format_is_refused_rather_than_opened() {
        for bad in [
            AudioFormat { channels: 0, sample_rate: 48_000, bits: 32, float: true },
            AudioFormat { channels: 2, sample_rate: 0, bits: 32, float: true },
            AudioFormat { channels: 2, sample_rate: 48_000, bits: 12, float: false },
            AudioFormat { channels: 2, sample_rate: 48_000, bits: 8, float: true },
        ] {
            let mut sink = CoreAudioSink::new();
            assert!(!sink.open(&bad), "{bad:?} should be refused");
        }
    }
}
