//! # exemu-jit — the block JIT (roadmap W8)
//!
//! Compiles guest x86/x86-64 **basic blocks** to native ARM64 and runs them
//! against the same [`exemu_core::CpuState`] and [`exemu_core::Memory`] the
//! interpreter uses. Anything the emitter has not *proven* it can reproduce
//! bit-for-bit — a rare opcode, a syscall, the `__wine_unix_call` boundary, an
//! instruction whose flag semantics are not settled — is not compiled: the block
//! simply ends there and the interpreter executes that instruction. A JIT that
//! covers twenty opcodes exactly is worth more than one that covers two hundred
//! approximately, because a silent divergence costs more than it saves (see the
//! SteamSetup fault: one wrong flag, 45M instructions of debugging).
//!
//! This commit is the substrate only (roadmap W8.2): the W^X code buffer the
//! emitter will write into. The emitter itself is W8.3.
//!
//! ## Why this crate is allowed `unsafe`, and only this crate
//!
//! Every other crate in the workspace declares `unsafe_code = "forbid"`, and
//! that is a load-bearing property of the project, not a style preference. A JIT
//! cannot be written under it: generating machine code at runtime means
//! `mmap`-ing memory, toggling its write protection, and jumping to bytes the
//! type system knows nothing about. Rather than weaken the invariant everywhere,
//! it is relaxed **here alone**, and the relaxation is bounded:
//!
//! * The **entire** foreign-function surface is four declarations in
//!   [`buffer`] (`mmap`, `munmap`, `pthread_jit_write_protect_np`,
//!   `sys_icache_invalidate`).
//! * Emitting code will be *safe* code: an encoder from instruction descriptions
//!   to `u32` words, with no pointers in sight. The part of a JIT where a
//!   correctness bug actually lives is ordinary safe Rust and is tested as such.
//! * `unsafe` appears in exactly three roles: allocating/writing the W^X buffer,
//!   calling a compiled block, and the `extern "C"` helpers a block calls back
//!   into. Each block is individually commented with the precondition it relies
//!   on, and covered by a test that executes it.
//! * The guest will never be trusted with a host pointer: compiled code
//!   addresses guest memory only by calling back into the Rust
//!   [`exemu_core::Memory`] implementation, which performs the same bounds and
//!   permission checks the interpreter does.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod buffer;

pub use buffer::{BlockCode, BufferError, CodeBuffer};
