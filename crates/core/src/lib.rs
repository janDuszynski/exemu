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

pub mod cpu;
pub mod error;
pub mod gui;
pub mod hooks;
pub mod memory;
pub mod pe;
pub mod telemetry;
pub mod unwind;

pub use cpu::{Cpu, CpuState, Exit, Reg, flags};
pub use error::{EmuError, Result};
pub use gui::{Control, ControlKind, DialogTemplate, DrawOp, Gui, GuiEvent, NoGui};
pub use hooks::Hooks;
pub use memory::{Memory, Perm, Region};
pub use pe::{
    ActivationContext, AssemblyIdentity, Export, Import, ImportSymbol, ManifestInfo, PeImage,
    Reloc, Section, Tls,
};
pub use telemetry::{rank as rank_opcode_misses, MissRecord, OpcodeRank};
pub use unwind::{FrameUnwind, HandlerType, UnwindCode, UnwindEntry, UnwindInfo, UnwindOp};
