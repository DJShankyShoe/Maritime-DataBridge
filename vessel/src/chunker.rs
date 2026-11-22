//! Accumulates whole pcapng blocks into a chunk, closing it when the size threshold
//! is reached or `max_wait` elapses since the first block, whichever comes first.
//!
//! The threshold is soft. A block is never split, so a chunk overshoots by whatever
//! block tipped it over. 64 KB is the largest size that still fills by size rather
//! than falling back on the timer across sparse OT traffic, down to around
//! 0.26 Mbps, while producing half the chunks and ACKs of a 32 KB chunk.
//!
//! The 2 s window is long because OT protocols are sparse; a short one would close
//! chunks nearly empty and waste framing overhead.
//!
//! Assembly and sending are decoupled through a bounded queue, which is what lets
//! replay traffic fill the gaps while a live chunk is still accumulating.
//!
//! The same assembler serves both streams, parameterised by [`StreamType`].

// Imports StreamType, which identifies the type of traffic.
// For example, the code uses StreamType::Live in its tests.
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// How often a paused live assembler checks whether the link is back.
const LINK_POLL: Duration = Duration::from_millis(100);

// Imports mpsc, which lets one part of the program send
// completed chunks to another part through a channel.
use noc_common::framing::StreamType;

// Imports 2 tools for handling time.
// sleep_until waits until a given deadline.
// Instant::now() gets the current point in time.
use tokio::sync::mpsc;

// Imports the shared ring buffer.
// This is where the chunk assembler retrieves incoming blocks.
use tokio::time::{sleep_until, Instant};


// Documentation explaining what ReadyChunk represents.
// It contains whole pcapng blocks joined together.
// The sender will assign a sequence number later.
/// An assembled chunk: whole pcapng blocks concatenated. The sender assigns the
/// sequence number at send time, since that counter belongs to the transport layer.

// Allows Rust to automatically provide useful functions:
// Debug: display the value for debugging.
// Clone: make a copy.
// PartialEq and Eq: compare values for equality.
use crate::ring_buffer::SharedRingBuffer;

/// An assembled chunk: whole pcapng blocks concatenated. The sender assigns the
/// sequence number at send time, since that counter belongs to the transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]

// Creates a public structure called ReadyChunk.
// A structure groups related information together.
pub struct ReadyChunk {
    // Stores which traffic stream this chunk belongs to.
    pub stream: StreamType,

    // Stores the actual bytes inside the completed chunk.
    // Vec<u8> is a list of bytes that can grow in size.
    pub payload: Vec<u8>,
}




/// Assemble chunks until the output channel closes. `out` is bounded, so a slow
/// sender back-pressures assembly.

/// Assemble chunks until the output channel closes.
/// The channel has limited capacity.
/// If the sender is slow, the assembler may need to wait.

// pub: Other parts of the program can use this function.
// async: The function can wait for operations without
// blocking the entire asynchronous runtime.
pub async fn run_chunker(
    // The shared ring buffer containing incoming blocks.
    ring: SharedRingBuffer,
    // Identifies the traffic stream being processed.
    stream: StreamType,
    // Minimum target size for completing a chunk, in bytes.
    chunk_threshold_bytes: usize,
    // Maximum amount of time to collect blocks into a chunk.
    max_wait: Duration,
    // Channel used to send completed chunks.
    // The channel carries ReadyChunk values.
    out: mpsc::Sender<ReadyChunk>,
    // The live stream passes the link state: while the link is down nothing is packed,
    // so unsent data stays in the ring where an outage spill can take it. The replay
    // stream passes None; its data is already safe on disk.
    link_up: Option<Arc<AtomicBool>>,
) {
    // Repeats the chunk assembly process.
    // After finishing one chunk, it starts another.
    loop {
        // Live stream with the link down: wait for it to come back before packing more.
        if let Some(up) = &link_up {
            while !up.load(Ordering::Relaxed) {
                tokio::time::sleep(LINK_POLL).await;
            }
        }

        // Wait indefinitely for the first block; never emit an empty chunk.
        // Waits for the first available block in the ring buffer.
        // .await means the function waits until a block is available.
        // It does not start a timer while waiting here.
        let first = ring.take_block().await;

        // Creates a new payload using the first block.
        // 'mut' means the payload can be modified later.
        // More blocks can be added to this payload.
        let mut payload = first;

        // The window runs from the first block, not from the last.
        // The timer starts AFTER the first block is retrieved.

        // Instant::now() gets the current point in time.
        // max_wait adds the allowed waiting duration.
        // deadline stores the time when the chunk should close.
        let deadline = Instant::now() + max_wait;



        // Keep pulling until the threshold is met or the window expires. A first
        // block already over the threshold skips the loop entirely.

        // Keep collecting blocks while the payload size
        // is smaller than the configured threshold.

        // payload.len() returns the current payload size in bytes.
        // If it is smaller than chunk_threshold_bytes,
        // the assembler continues waiting for more blocks.
        while payload.len() < chunk_threshold_bytes {

            // tokio::select! waits for multiple asynchronous operations.
            // Here, it waits for either:
            // 1. Another block to become available.
            // 2. The deadline to be reached.
            tokio::select! {

                // Try to retrieve another block from the ring buffer.
                // Once a block arrives, store it in 'block'.
                block = ring.take_block() => {

                    // Adds the entire block to the current payload.
                    // Existing data stays in the payload.
                    // The new block is appended to the end.
                    payload.extend_from_slice(&block);
                }

                // Wait until the previously calculated deadline.
                _ = sleep_until(deadline) => {

                    // Exit the while loop when the timer expires.
                    // The current payload is kept.
                    break;
                }
            }
        }



        // Create a completed ReadyChunk containing:
        // 1. The current stream type.
        // 2. The payload collected so far.
        
        // out.send(...) sends the chunk to the output channel.
        // .await waits if the channel cannot accept it immediately.
        
        // .is_err() checks whether sending failed.
        // Sending fails if the receiver has been dropped.
        // The link went down while this chunk was being packed: give its blocks back to
        // the ring instead of queueing them, so the outage spill can take them.
        if let Some(up) = &link_up {
            if !up.load(Ordering::Relaxed) {
                ring.return_unsent(vec![payload]).await;
                continue;
            }
        }
        crate::status::STATS.stream(stream).packed.fetch_add(1, Ordering::Relaxed);
        if out.send(ReadyChunk { stream, payload }).await.is_err() {
            
            
            // Receiver gone, so the sender has shut down.

            // Stop running the chunk assembler when
            // the receiver is no longer available.
            break;
        }
    }
}


// Only compile this section when running tests.
// This is not part of the normal application execution.
