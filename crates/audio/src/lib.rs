#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]

const FRAMES_PER_BUFFER: u32 = 1024;

const BUFFER_COUNT: usize = 3;

const MAX_STAGED_FRAMES: usize = 48_000 * 2;

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

    struct Staging {
        pcm: Mutex<VecDeque<u8>>,
        frame_bytes: usize,
    }

    struct Queue(AudioQueueRef);
    unsafe impl Send for Queue {}

    struct Live {
        queue: Queue,
        staging: Arc<Staging>,
        raw_user_data: *const Staging,
        started: bool,
    }
    unsafe impl Send for Live {}

    unsafe extern "C-unwind" fn refill(
        user: *mut c_void,
        queue: AudioQueueRef,
        buffer: AudioQueueBufferRef,
    ) {
        if user.is_null() || buffer.is_null() {
            return;
        }
        let staging = unsafe { &*(user as *const Staging) };
        let buf = unsafe { &mut *buffer };
        let capacity = buf.mAudioDataBytesCapacity as usize;
        let dst = unsafe { std::slice::from_raw_parts_mut(buf.mAudioData.as_ptr().cast::<u8>(), capacity) };

        {
            let mut pcm = staging.pcm.lock().unwrap_or_else(|e| e.into_inner());
            let n = capacity.min(pcm.len());
            for slot in dst.iter_mut().take(n) {
                *slot = pcm.pop_front().unwrap_or(0);
            }
            dst[n..].fill(0);
        }
        buf.mAudioDataByteSize = capacity as u32;
        unsafe { AudioQueueEnqueueBuffer(queue, buffer, 0, std::ptr::null()) };
    }

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

    #[derive(Default)]
    pub struct CoreAudioSink {
        live: Option<Live>,
    }

    impl CoreAudioSink {
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
                drop(unsafe { Arc::from_raw(raw_user_data) });
                return false;
            }

            let bytes = FRAMES_PER_BUFFER as usize * frame_bytes;
            for _ in 0..BUFFER_COUNT {
                let mut buffer: AudioQueueBufferRef = std::ptr::null_mut();
                let ok = unsafe { AudioQueueAllocateBuffer(queue, bytes as u32, NonNull::from(&mut buffer)) };
                if ok != 0 || buffer.is_null() {
                    continue;
                }
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
                    unsafe { AudioQueueStart(live.queue.0, std::ptr::null()) };
                    live.started = true;
                }
            }
        }

        fn stop(&mut self) {
            if let Some(live) = self.live.as_mut() {
                if live.started {
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
            while pcm.len() > cap {
                pcm.pop_front();
            }
        }

        fn close(&mut self) {
            let Some(live) = self.live.take() else {
                return;
            };
            unsafe {
                if live.started {
                    AudioQueueStop(live.queue.0, false);
                }
                AudioQueueStop(live.queue.0, true);
                AudioQueueDispose(live.queue.0, true);
            }
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

    #[derive(Default)]
    pub struct CoreAudioSink;

    impl CoreAudioSink {
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

    #[test]
    fn an_unopened_sink_swallows_writes() {
        let mut sink = CoreAudioSink::new();
        sink.write(&[0u8; 64]);
        sink.start();
        sink.stop();
        sink.reset();
        sink.close();
    }

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
