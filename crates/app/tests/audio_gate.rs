use std::path::Path;
use std::sync::{Arc, Mutex};

use exemu_app::{audio_sample, load_and_run, RunConfig};
use exemu_core::{AudioFormat, AudioSink};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

#[derive(Default)]
struct Recorded {
    format: Option<AudioFormat>,
    pcm: Vec<u8>,
    starts: u32,
    stops: u32,
}

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

fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

fn value(stdout: &str, label: &str) -> u64 {
    let raw = line(stdout, label);
    u64::from_str_radix(raw, 16).unwrap_or_else(|_| panic!("{label} is not hex: {raw:?}"))
}

fn private_sandbox(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-w72-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

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
    let recorded = heard.lock().unwrap();
    assert!(recorded.pcm.is_empty(), "nothing should have reached the sink");
    assert!(recorded.format.is_none(), "…and no stream should have been opened");
}

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

    assert!(run.steps > 1_000_000, "expected a real Wine boot, got {} steps", run.steps);

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

    assert_eq!(
        value(&stdout, audio_sample::LABEL_FRAMES),
        9_600,
        "GetBufferSize; stdout:\n{stdout}"
    );

    assert!(stdout.contains(audio_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(run.exit_code, audio_sample::AUDIO_OK_EXIT, "stdout:\n{stdout}");

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
