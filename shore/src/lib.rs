//! Shore daemon library.
//!
//! Stages live in their own modules; `main.rs` is a thin binary over them.

pub mod cloudflare;
pub mod dedup;
pub mod server;
pub mod session;
