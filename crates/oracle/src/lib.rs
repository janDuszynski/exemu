//! # exemu-oracle — differential CPU oracle (roadmap P0.1 / P0.2)
//!
//! Steps the exemu interpreter and Unicorn (QEMU TCG) through the same
//! generated instruction from identical state and reports the first
//! divergence. The whole harness is gated behind the `unicorn` feature so the
//! default workspace build (the CI gate) never needs Unicorn's native
//! toolchain.

#[cfg(feature = "unicorn")]
mod engine;
#[cfg(feature = "unicorn")]
mod gen;
#[cfg(feature = "unicorn")]
mod rng;

#[cfg(feature = "unicorn")]
pub use engine::{fuzz, render, Divergence, FuzzConfig, Summary};
