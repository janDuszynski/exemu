//! # exemu-core — the domain layer
//!
//! This crate is the innermost ring of the architecture. It contains the
//! vocabulary of the emulator (CPU state, memory model, the loaded-image
//! model) and the *abstractions* — [`Memory`], [`Cpu`], and [`Hooks`] —
//! that the outer infrastructure crates implement.
//!
//! It has **no dependencies** and performs **no I/O**. Everything here is
//! plain data and traits, which keeps the core testable in isolation and
//! keeps the dependency arrows pointing inward.

#![forbid(unsafe_code)]

pub mod clock;
pub mod audio;
pub mod cpu;
pub mod debug;
pub mod driver;
pub mod error;
pub mod gui;
pub mod hooks;
pub mod memory;
pub mod pe;
pub mod spawn;
pub mod telemetry;
pub mod unwind;

pub use clock::{
    GuestClock, QPC_FREQUENCY, TSC_TICKS_PER_100NS, VIRTUAL_EPOCH_FILETIME,
    VIRTUAL_INSTRUCTIONS_PER_SECOND,
};
pub use audio::{AudioFormat, AudioSink, NoAudio};
pub use cpu::{Cpu, CpuState, Exit, Reg, X87, flags};
pub use debug::{
    DebugCommand, DebugControl, DebugEvent, DebugFrontEnd, DebugSession, DebugSnapshot,
    DisasmLine, HandleInfo, ModuleInfo, NoTrace, StopReason, StopRequest, SyscallTable,
    ThreadInfo, TraceSink, WatchKind, Watchpoint, BREAK_AT_STEP_DISABLED,
};
pub use driver::{
    DisplayMode, InputEvent, MouseButton, NoDriver, TextBitmap, UserDriver, WindowParams,
};
pub use error::{EmuError, Result};
pub use gui::{Control, ControlKind, DialogTemplate, DrawOp, Gui, GuiEvent, NoGui};
pub use hooks::Hooks;
pub use memory::{Memory, Perm, Region, CODE_PAGE_SIZE};
pub use pe::{
    ActivationContext, AssemblyIdentity, Export, Import, ImportSymbol, ManifestInfo, PeImage,
    Reloc, Section, Tls,
};
pub use spawn::{
    ChildProcessOutcome, ChildProcessRequest, NoSpawner, ProcessSpawner, SpawnError,
};
pub use telemetry::{rank as rank_opcode_misses, MissRecord, OpcodeRank};
pub use unwind::{FrameUnwind, HandlerType, UnwindCode, UnwindEntry, UnwindInfo, UnwindOp};
