//! # exemu-oracle — differential CPU oracles (roadmap P0.1 / P0.2 / W8.7)
//!
//! Two differentials live here, answering two different questions:
//!
//! * **vs Unicorn** (`engine`, feature `unicorn`) — "is the interpreter a real
//!   x86?" Steps exemu and Unicorn (QEMU TCG) through the same generated
//!   instruction from identical state and reports the first divergence. Gated
//!   behind the `unicorn` feature so the default workspace build (the CI gate)
//!   never needs Unicorn's native toolchain — and never pulls its GPL-2.0
//!   licence into the shipping closure.
//! * **vs the interpreter** ([`jitdiff`], always built) — "is the JIT the same
//!   machine as the interpreter, bit for bit?" No reference emulator, so no
//!   defined-flags policy: every bit must match. Runs in the ordinary test gate.
//!
//! Both drive the same generator (`gen`), so the JIT is exercised by exactly the
//! instruction stream the interpreter was validated on.

// Public so that a build *without* the `unicorn` feature (where only the JIT
// differential consumes the generator) does not report every unused category
// builder as dead code.
pub mod gen;
pub mod rng;

#[cfg(feature = "unicorn")]
mod engine;

pub mod jitdiff;

#[cfg(feature = "unicorn")]
pub use engine::{debug_index, fuzz, render, Divergence, FuzzConfig, Summary};
