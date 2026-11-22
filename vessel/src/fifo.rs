//! # FIFO Reader (Capture Ingestion Boundary)
//!
//! Reads the merged pcapng stream from dumpcap's named pipe, parses out complete
//! blocks, caches the Section Header Block (SHB), and forwards each block to the 
//! ring buffer. dumpcap writes to the FIFO unaware that it is a pipe rather than 
//! a regular file.
//!
//! [`run_reader`] is generic over `AsyncRead` to allow in-memory testing, while 
//! production deployment feeds it the pipe from [`open_fifo`]. Raw-capture privileges 
//! are handled on the dumpcap binary via `setcap`, keeping this daemon unprivileged.


use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use noc_common::pcapng::{BlockParser, HeaderEvent, SessionHeader};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{watch, Mutex};

use crate::ring_buffer::{PushOutcome, SharedRingBuffer};

/// Minimum gap between drop warnings, so sustained overload does not spam the log.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(1);

/// Read size. Unrelated to block size; the parser reassembles across reads.
const READ_CHUNK: usize = 64 * 1024;

/// Why the reader loop returned.
#[derive(Debug, PartialEq, Eq)]
pub enum ReaderExit {
    /// The writer closed the pipe. On the fresh stream a new SHB re-establishes
    /// the header.
    Eof,
}

/// Reads blocks until EOF, forwards them to `ring`, and updates `header`.
///
/// A parse error indicates that the stream has desynchronised. This most plausibly 
/// happens if dumpcap dies midway through writing a block, causing the next instance's 
/// fresh header to be swallowed as the corrupted block's tail. 
///
/// This error is not fatal: the reader recovers by skipping to the next section 
/// header and bumping `restart` so the supervisor can replace dumpcap. Returning 
/// here instead would stop capture silently until the daemon restarts: the pipe would
/// fill up and dumpcap would block.

pub async fn run_reader<R>(
    mut reader: R,
    ring: SharedRingBuffer,
    header: Arc<Mutex<SessionHeader>>,
    restart: watch::Sender<u64>,
) -> anyhow::Result<ReaderExit>
where
    R: AsyncRead + Unpin,
{
    let mut parser = BlockParser::new();
    let mut buf = vec![0u8; READ_CHUNK];
    // True while skipping to the next section header, so one desync asks for one
    // dumpcap restart however many feeds the resync spans.
    let mut desynced = false;

    // Drop accounting, logged on a throttle.
    let mut dropped_blocks: u64 = 0;
    let mut dropped_bytes: u64 = 0;
    let mut last_drop_log = tokio::time::Instant::now()
        .checked_sub(DROP_LOG_INTERVAL)
        .unwrap_or_else(tokio::time::Instant::now);

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(ReaderExit::Eof);
        }
        parser.feed(&buf[..n]);

        // Drain every block the feed made available.
        loop {
            let block = match parser.next_block() {
                Ok(Some(block)) => {
                    desynced = false;
                    block
                }
                Ok(None) => break,
                Err(e) => {
                    if !desynced {
                        desynced = true;
                        tracing::error!(
                            error = %e,
                            "capture stream desynchronised; skipping to the next section \
                             header and restarting dumpcap"
                        );
                        // A desync leaves no way to find block boundaries again until a
                        // new section starts, and only a fresh dumpcap emits one.
                        restart.send_modify(|n| *n += 1);
                    }
                    if parser.resync_to_next_section() {
                        continue;
                    }
                    break; // no header buffered yet, read more and try again
                }
            };
            match header.lock().await.observe(&block) {
                HeaderEvent::NewSection => {
                    tracing::info!("new pcapng section header (interface list changed?)");
                }
                HeaderEvent::Extended | HeaderEvent::Passthrough => {}
            }
            match ring
                .push_block(block.data)
                .await
                .map_err(|e| anyhow::anyhow!("ring buffer rejected a block: {e}"))?
            {
                PushOutcome::Dropped { bytes } => {
                    dropped_blocks += 1;
                    crate::status::STATS.dropped_blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    dropped_bytes += bytes as u64;
                    if last_drop_log.elapsed() >= DROP_LOG_INTERVAL {
                        tracing::warn!(
                            dropped_blocks,
                            dropped_bytes,
                            "ring buffer full in spill_to_disk mode, dropping captured \
                             blocks (disk cannot keep up)"
                        );
                        last_drop_log = tokio::time::Instant::now();
                    }
                }
                PushOutcome::Stored => {}
            }
        }
    }
}

/// Creates the FIFO if missing, increases its kernel buffer, and opens both ends.
///
/// Returns a reader for [`run_reader`] and a second handle for dumpcap to
/// inherit. Passing the file descriptor instead of the path prevents dumpcap
/// from unlinking the FIFO if startup fails, which would leave the reader
/// stranded on a deleted pipe while subsequent dumpcap instances write to a new one.
///
/// Both ends are opened with `O_RDWR` so the open does not block waiting for a
/// writer, preventing spurious EOFs between dumpcap restarts. Increasing the buffer
/// size beyond the default 1 MB limit requires `fs.pipe-max-size` to be provisioned 
/// on the host; if this configuration is missing, the `fcntl` call fails and the error 
/// is surfaced rather than running with an undersized pipe.

pub fn open_fifo(
    path: impl AsRef<Path>,
    pipe_size_bytes: u32,
) -> io::Result<(tokio::fs::File, std::fs::File)> {
    let path = path.as_ref();
    ensure_fifo(path)?;

    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true) // O_RDWR: keep a writer end open, never block on open
        .open(path)?;

    set_pipe_size(&std_file, pipe_size_bytes)?;

    let child_end = std_file.try_clone()?;

    // tokio::fs reads on its blocking pool, so the fd stays blocking. Parking one
    // pool thread on the pipe is fine, and O_RDWR keeps a writer end open.
    Ok((tokio::fs::File::from_std(std_file), child_end))
}

/// Creates the FIFO if it does not exist. An existing path is left unchanged,
/// but opening it fails loudly if the path is not a FIFO.

fn ensure_fifo(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pipe path contains NUL"))?;
    // Owner and group rw: dumpcap writes, the daemon reads.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o660) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_pipe_size(file: &std::fs::File, size: u32) -> io::Result<()> {
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETPIPE_SZ, size as libc::c_int) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
