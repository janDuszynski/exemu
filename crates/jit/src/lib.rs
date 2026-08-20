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
//! * Emitting code is *safe* code: [`a64`] is a pure encoder from instruction
//!   descriptions to `u32` words with no pointers in sight, and [`compile`]
//!   turns guest instructions into those words. The overwhelming majority of the
//!   crate — the part where a correctness bug would actually live — is ordinary
//!   safe Rust, and is tested as such.
//! * `unsafe` appears in exactly four places: allocating and writing the W^X
//!   buffer, reinterpreting a block's entry point as a function pointer, calling
//!   it ([`engine`]), and the two `extern "C"` helpers a block calls back into
//!   ([`rt`]). Each is commented with the precondition it relies on, and
//!   `#![deny(clippy::undocumented_unsafe_blocks)]` keeps it that way.
//! * The guest is never trusted with a host pointer. Compiled code addresses
//!   guest memory only by calling back into the Rust [`exemu_core::Memory`]
//!   implementation, which performs the same bounds and permission checks the
//!   interpreter does. A JIT block cannot read or write a host address the
//!   interpreter could not.
//!
//! ## The correctness contract
//!
//! For any guest state *S* and any block the compiler accepts, running the block
//! must leave *exactly* the state the interpreter would leave after the same
//! number of instructions — all sixteen GPRs, `rflags` (every bit, including AF
//! and PF), `rip`, and every byte of guest memory. That is not an aspiration; it
//! is checked by the differential in `crates/oracle` (roadmap W8.7) over the
//! same generated trials the Unicorn oracle uses, and by this crate's own tests.
//!
//! Two rules make faults exact without any error plumbing in compiled code:
//!
//! 1. **Nothing is committed before a faulting access.** Within one guest
//!    instruction, results live in scratch registers; the guest register file
//!    and the live `rflags` are updated only once every access has succeeded.
//! 2. **A fault rewinds.** `rip` goes back to the start of the faulting
//!    instruction and the block returns [`Run::Faulted`]; the caller re-executes
//!    that one instruction on the interpreter, which raises the real
//!    [`exemu_core::EmuError`] — with the message, the address and even the
//!    partial state the fault reporter expects. The JIT never constructs an
//!    error of its own.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod a64;
pub mod buffer;
pub mod compile;
pub mod engine;
pub mod rt;

pub use buffer::{BlockCode, BufferError, CodeBuffer};
pub use compile::{BlockPlan, Mode, StopReason};
pub use engine::{Jit, JitStats, Run};
