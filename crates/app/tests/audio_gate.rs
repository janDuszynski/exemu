//! W7.2 — **a buffer played through Wine's `mmdevapi.dll` as guest code**.
//!
//! The proof binary ([`exemu_app::audio_sample`]) imports nothing but
//! `ole32` and the console primitives. It calls
//! `CoCreateInstance(CLSID_MMDeviceEnumerator)` and walks the ordinary WASAPI
//! chain — `IMMDeviceEnumerator` → `IMMDevice` → `IAudioClient` →
//! `IAudioRenderClient` — writes PCM into the buffer `GetBuffer` hands it, and
//! releases it. Every one of those interfaces is **Wine's own mmdevapi running
//! as guest code**, loaded as the in-proc server exemu's registry names for that
//! CLSID.
//!
//! exemu contributes exactly one thing: the driver unix side mmdevapi asks for
//! (`exemu_os::audio`), reached through the boundary `audio_abi.rs` recovers.
//! Three things make the result attributable to that path and nothing else:
//!
//! 1. **exemu implements no audio API at all**, native or emulated. On the
//!    emulated path `CoCreateInstance` is an unsupported stub that leaves the
//!    out-pointer NULL, so the sample stops before it has an enumerator. That is
//!    the control below.
//! 2. **The bytes are checked at the far end.** The gate injects a recording
//!    [`AudioSink`] and compares what it received against the pattern baked into
//!    the guest image, byte for byte. The PCM provably crossed the whole COM
//!    stack and the unixlib — nothing in between could have synthesised it.
//! 3. **The format came back the other way.** The sample prints the
//!    `WAVEFORMATEX` fields `GetMixFormat` returned, and they are exemu's mix
//!    format — so the reply travelled up through Wine's `IAudioClient` too.
//!
//! **Hermetic and CI-safe.** The sink is a plain `Vec<u8>` behind a mutex; no
//! audio device is opened, nothing is played, and the test passes on a machine
//! with no sound hardware. The CoreAudio backend is a *different* `AudioSink`
//! and is never used here.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::path::Path;
use std::sync::{Arc, Mutex};

use exemu_app::{audio_sample, load_and_run, RunConfig};
use exemu_core::{AudioFormat, AudioSink};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// What the sink saw, shared with the test thread.
#[derive(Default)]
struct Recorded {
    /// The format `open` was called with, if it was.
    format: Option<AudioFormat>,
    /// Every byte handed to `write`, concatenated.
    pcm: Vec<u8>,
    /// How many times `start` was called.
    starts: u32,
    /// How many times `stop` was called.
    stops: u32,
}

/// A recording backend. This is the whole "device": no host audio API is
/// touched, which is what keeps the gate runnable anywhere.
struct CaptureSink(Arc<Mutex<Recorded>>);

impl AudioSink for CaptureSink {
    fn open(&mut self, format: &AudioFormat) -> bool {
        self.0.lock().unwrap().format = Some(*format);
        true
    }
    fn write(&mut self, frames: &[u8]) {
        self.0.lock().unwrap().pcm.extend_from_slice(frames);
    }
    fn start(&mut self) {
        self.0.lock().unwrap().starts += 1;
    }
    fn stop(&mut self) {
        self.0.lock().unwrap().stops += 1;
    }
}

/// Read a `LABEL=` line out of the sample's stdout.
fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

/// A `LABEL=` line parsed as the 16-hex-digit value the sample prints.
fn value(stdout: &str, label: &str) -> u64 {
    let raw = line(stdout, label);
    u64::from_str_radix(raw, 16).unwrap_or_else(|_| panic!("{label} is not hex: {raw:?}"))
}

/// A private sandbox per run, so nothing a previous run left behind can change
/// what this one observes (see `RunConfig::sandbox_root`).
fn private_sandbox(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-w72-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The control: exemu implements no audio stack, and its `CoCreateInstance` is
/// an unsupported stub, so the sample cannot even obtain an enumerator. Without
/// this, a pass on the Wine path could just be an exemu thunk being helpful.
#[test]
fn emulated_path_has_no_audio_stack_at_all() {
    let heard = Arc::new(Mutex::new(Recorded::default()));
    let exe = audio_sample::build();
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 4_000_000,
            sandbox_root: Some(private_sandbox("emulated")),
            audio_sink: Some(Box::new(CaptureSink(Arc::clone(&heard)))),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_ne!(run.exit_code, audio_sample::AUDIO_OK_EXIT, "stdout:\n{stdout}");
    assert!(
        stdout.contains(audio_sample::FAIL_MESSAGE.trim_end()),
        "the sample should report failure without an audio stack; stdout:\n{stdout}"
    );
    // Specifically: no enumerator, so nothing downstream could have run.
    let recorded = heard.lock().unwrap();
    assert!(recorded.pcm.is_empty(), "nothing should have reached the sink");
    assert!(recorded.format.is_none(), "…and no stream should have been opened");
}

/// The W7.2 gate: Wine's `mmdevapi.dll`, running as guest code, plays a buffer
/// through exemu's driver unix side.
#[test]
fn audio_sample_plays_a_buffer_through_wine_mmdevapi() {
    if !Path::new(WINE_DLLS).join("mmdevapi.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/mmdevapi.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let heard = Arc::new(Mutex::new(Recorded::default()));
    let exe = audio_sample::build();
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 800_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(private_sandbox("wine")),
            audio_sink: Some(Box::new(CaptureSink(Arc::clone(&heard)))),
            ..RunConfig::default()
        },
    )
    .expect("the audio sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("audio sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    // Wine's audio stack really booted: mmdevapi pulls in ole32/combase plus the
    // whole kernel32/kernelbase/ntdll/ucrtbase set, which the emulated control
    // cannot approach.
    assert!(run.steps > 1_000_000, "expected a real Wine boot, got {} steps", run.steps);

    // COM produced the enumerator through exemu's registry, and the chain held.
    assert_eq!(value(&stdout, audio_sample::LABEL_COINIT), 0, "CoInitializeEx; stdout:\n{stdout}");
    for label in [
        audio_sample::LABEL_ENUM,
        audio_sample::LABEL_DEVICE,
        audio_sample::LABEL_CLIENT,
        audio_sample::LABEL_MIXFMT,
        audio_sample::LABEL_INIT,
        audio_sample::LABEL_BUFFER,
        audio_sample::LABEL_RENDER,
        audio_sample::LABEL_GETBUF,
        audio_sample::LABEL_RELBUF,
        audio_sample::LABEL_START,
        audio_sample::LABEL_STOP,
    ] {
        let hr = value(&stdout, label);
        assert!(
            hr & 0x8000_0000 == 0,
            "{label}{hr:016x} is a failure HRESULT; stdout:\n{stdout}"
        );
    }

    // THE CLAIM, downward: the mix format exemu's driver reported travelled back
    // up through Wine's IAudioClient to the guest.
    assert_eq!(
        value(&stdout, audio_sample::LABEL_CHANNELS),
        u64::from(exemu_os::audio::MIX_CHANNELS),
        "GetMixFormat's nChannels; stdout:\n{stdout}"
    );
    assert_eq!(
        value(&stdout, audio_sample::LABEL_RATE),
        u64::from(exemu_os::audio::MIX_SAMPLE_RATE),
        "GetMixFormat's nSamplesPerSec; stdout:\n{stdout}"
    );
    assert_eq!(
        value(&stdout, audio_sample::LABEL_BITS),
        u64::from(exemu_os::audio::MIX_BITS),
        "GetMixFormat's wBitsPerSample; stdout:\n{stdout}"
    );

    // The stream mmdevapi created is the one exemu sized: 200 ms at 48 kHz.
    assert_eq!(
        value(&stdout, audio_sample::LABEL_FRAMES),
        9_600,
        "GetBufferSize; stdout:\n{stdout}"
    );

    // The guest said so itself, with its distinguishing exit code.
    assert!(stdout.contains(audio_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(run.exit_code, audio_sample::AUDIO_OK_EXIT, "stdout:\n{stdout}");

    // THE CLAIM, upward: the host sink received exactly the PCM the guest wrote.
    let recorded = heard.lock().unwrap();
    assert_eq!(
        recorded.format,
        Some(AudioFormat {
            channels: exemu_os::audio::MIX_CHANNELS,
            sample_rate: exemu_os::audio::MIX_SAMPLE_RATE,
            bits: exemu_os::audio::MIX_BITS,
            float: true,
        }),
        "the sink was opened at the mix format"
    );
    assert_eq!(recorded.starts, 1, "IAudioClient::Start reached the backend");
    assert_eq!(recorded.stops, 1, "…and so did Stop");
    assert_eq!(
        recorded.pcm.len(),
        audio_sample::PATTERN_LEN as usize,
        "the sink received {} bytes, expected {}",
        recorded.pcm.len(),
        audio_sample::PATTERN_LEN
    );
    assert_eq!(
        recorded.pcm,
        audio_sample::pattern(),
        "the PCM the sink received is not the PCM the guest wrote"
    );
}
