//! Library half of the `exemu` command-line front-end.
//!
//! The binary (`src/main.rs`) is a thin presentation shell; anything a test or
//! another tool needs to drive lives here. That includes:
//!
//! * the corpus regression gate (roadmap W9.6): the `exemu corpus` subcommand
//!   and the integration test in `tests/corpus_gate.rs` are two front-ends over
//!   the same [`corpus::run_manifest`], so the gate CI enforces and the table a
//!   developer reads can never disagree.
//! * per-exe run profiles (roadmap W9.4): [`profile::Profile`] is the
//!   settings-only sibling of [`corpus::Entry`] — "this binary wants these
//!   settings" without the pinned-outcome assertions a regression gate needs —
//!   over the same [`toml_lite`] parser.

#![forbid(unsafe_code)]

pub mod corpus;
pub mod profile;
pub mod toml_lite;
