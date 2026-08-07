//! Library half of the `exemu` command-line front-end.
//!
//! The binary (`src/main.rs`) is a thin presentation shell; anything a test or
//! another tool needs to drive lives here. Today that is the corpus regression
//! gate (roadmap W9.6): the `exemu corpus` subcommand and the integration test
//! in `tests/corpus_gate.rs` are two front-ends over the same
//! [`corpus::run_manifest`], so the gate CI enforces and the table a developer
//! reads can never disagree.

#![forbid(unsafe_code)]

pub mod corpus;
