//! Vessel daemon library.
//!
//! Each pipeline stage lives in its own module; `main.rs` is a thin binary over
//! them.

pub mod chunker;
pub mod crypto;
pub mod disk_buffer;
pub mod dumpcap;
pub mod fifo;
pub mod kek;
pub mod pipeline;
pub mod ring_buffer;
pub mod sender;
pub mod status;
