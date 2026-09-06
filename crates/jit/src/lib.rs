#![deny(clippy::undocumented_unsafe_blocks)]

pub mod a64;
pub mod buffer;
pub mod compile;
pub mod engine;
pub mod rt;

pub use buffer::{BlockCode, BufferError, CodeBuffer};
pub use compile::{BlockPlan, Mode, StopReason};
pub use engine::{Jit, JitStats, Run};
