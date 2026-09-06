#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    pub channels: u16,
    pub sample_rate: u32,
    pub bits: u16,
    pub float: bool,
}

impl AudioFormat {
    pub fn frame_bytes(&self) -> u32 {
        u32::from(self.channels) * u32::from(self.bits) / 8
    }
}

pub trait AudioSink: Send {
    fn open(&mut self, format: &AudioFormat) -> bool {
        let _ = format;
        true
    }

    fn start(&mut self) {}

    fn stop(&mut self) {}

    fn reset(&mut self) {}

    fn write(&mut self, frames: &[u8]) {
        let _ = frames;
    }

    fn close(&mut self) {}
}

pub struct NoAudio;

impl AudioSink for NoAudio {}
