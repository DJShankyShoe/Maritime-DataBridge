//! Shore server: accept vessels, verify them, receive chunks
//!
//! One task per connection. Combine everything together. Each runs the handshake to derive a verified vessel id,
//! reads the fresh header, fetches the persistent session from the registry so dedup
//! survives reconnects, then loops receiving chunks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use noc_common::config::FlushMode;
use noc_common::identity::{read_session_header, read_session_id, server_handshake, DeviceDirectory};
use noc_common::wire::{read_chunk, write_ack, write_keepalive};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::session::Registry;

/// Upper bound on a chunk payload. The soft threshold plus one block sits far below
/// this; the block-size cap makes a comfortable ceiling.
pub const MAX_CHUNK_PAYLOAD: u32 = 64 * 1024 * 1024;

/// Accept vessel connections forever, one task each.
///
/// `mode` selects the flush scheduling. In size mode the per-connection downtime
/// watchdog flushes on link-drop detection; in time mode the shore-wide sweep drives
/// everything and connections do no downtime flush of their own.
pub async fn serve(
    listener: TcpListener,
    directory: Arc<dyn DeviceDirectory>,
    registry: Arc<Registry>,
    downtime: Duration,
    keepalive: Duration,
    mode: FlushMode,
) -> anyhow::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        // Nagle would hold our tiny ACKs and keepalives, which are often the last
        // thing sent before the link goes idle. The vessel reads that delay as silence
        // and eventually as an outage.
        sock.set_nodelay(true).ok();
        let directory = directory.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_connection(sock, &*directory, &registry, downtime, keepalive, mode).await
            {
                tracing::warn!(%peer, error = %e, "vessel connection ended with error");
            }
        });
    }
}

/// Drive one connection: handshake, header, receive loop, keepalive writer.
pub async fn run_connection<S>(
    mut io: S,
    directory: &dyn DeviceDirectory,
    registry: &Registry,
    downtime: Duration,
    keepalive: Duration,
    mode: FlushMode,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Handshake, then the session id and header, all before the socket is split.
    let vessel_id = server_handshake(&mut io, directory).await?;
    let session_id = read_session_id(&mut io).await?;
    let header = read_session_header(&mut io).await?;
    tracing::info!(vessel = %vessel_id, %session_id, header_len = header.len(), "vessel authenticated");

    // A new session id means a reboot and supersedes the old session; the same one is
    // a reconnect and reuses it, so the watermark still dedups resends.
    let vessel = registry.get_or_create(&vessel_id, &session_id).await;
    let stats = {
        let mut v = vessel.lock().await;
        v.set_header(header);
        v.stats()
    };
    // Counted while this connection lasts, however it ends.
    stats.connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    struct Open(std::sync::Arc<crate::session::VesselStats>);
    impl Drop for Open {
        fn drop(&mut self) {
            self.0.connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _open = Open(stats);

    // Split so the keepalive task can write while the read loop reads. A select! on
    // the same stream would cancel an in-progress chunk read instead.
    let (mut rd, wr) = tokio::io::split(io);
    let wr = Arc::new(Mutex::new(wr));
    let ka_handle = {
        let wr = wr.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(keepalive);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                if write_keepalive(&mut *wr.lock().await).await.is_err() {
                    break; // socket gone; the read loop will also end
                }
            }
        })
    };

    let result = receive_loop(&mut rd, &wr, &vessel, downtime, mode).await;
    ka_handle.abort();
    // An error is logged by the caller; a clean close (the vessel, or a tunnel in between,
    // closed the socket) would otherwise leave no trace.
    if result.is_ok() {
        tracing::info!(vessel = %vessel_id, "vessel connection closed");
    }
    result
}

async fn receive_loop<R, W>(
    rd: &mut R,
    wr: &Arc<Mutex<W>>,
    vessel: &Arc<Mutex<crate::session::Vessel>>,
    downtime: Duration,
    mode: FlushMode,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Link-drop detection runs on its own timer rather than as a timeout wrapped around
    // the read. Cancelling `read_chunk` part-way through a payload would throw away the
    // bytes already taken, leaving the next header to be parsed from the middle of a
    // payload, which is the same problem the split above avoids for keepalives. In size mode the
    // watchdog flushes what has accumulated instead of waiting on a threshold that may
    // never be met while the link is down; time mode leaves flushing to its sweep, and
    // either way the connection stays open.
    let last_chunk = Arc::new(Mutex::new(Instant::now()));
    let watchdog = (mode == FlushMode::Size).then(|| {
        let vessel = vessel.clone();
        let last = last_chunk.clone();
        let tick = (downtime / 4).max(Duration::from_millis(100));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tick).await;
                if last.lock().await.elapsed() < downtime {
                    continue;
                }
                if let Err(e) = vessel.lock().await.flush_all().await {
                    tracing::warn!(error = %e, "downtime flush failed");
                }
                // Restart the window so one idle stretch flushes once, not every tick.
                *last.lock().await = Instant::now();
            }
        })
    });

    let result: anyhow::Result<()> = loop {
        match read_chunk(rd, MAX_CHUNK_PAYLOAD).await {
            // Clean close between frames.
            Ok(None) => break Ok(()),
            // Dedup, append, ACK. New or duplicate both get an ACK; only a truncated
            // chunk does not.
            Ok(Some(chunk)) => {
                *last_chunk.lock().await = Instant::now();
                let stream = chunk.header.stream;
                let seq = chunk.header.seq;
                // Errors here `break` rather than `?`: returning early would skip the
                // teardown below and leave the watchdog running forever, still flushing a
                // vessel that is gone, one leaked task per disconnect.
                let flush_due = match vessel.lock().await.accept(stream, seq, &chunk.payload).await {
                    Ok((_, due)) => due,
                    Err(e) => break Err(anyhow::Error::from(e)),
                };
                if let Err(e) = write_ack(&mut *wr.lock().await, stream, seq).await {
                    break Err(anyhow::Error::from(e));
                }
                if flush_due {
                    if let Err(e) = vessel.lock().await.flush_stream(stream).await {
                        break Err(anyhow::Error::from(e));
                    }
                }
            }
            // Truncated chunk or socket error: discard it, send no ACK, and end the
            // connection. The vessel resends once its own timer fires.
            Err(_) => break Ok(()),
        }
    };

    if let Some(h) = watchdog {
        h.abort();
    }
    // Flush whatever this connection left behind, whether it ended cleanly or not, and
    // report the connection's own error ahead of any flush error.
    let flushed = vessel.lock().await.flush_all().await.map_err(anyhow::Error::from);
    result.and(flushed)
}
