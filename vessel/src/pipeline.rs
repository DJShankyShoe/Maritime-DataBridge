//! Starts every part of the vessel daemon as background tasks, then connects to shore
//! and reconnects whenever the link drops.

// Standard library: file paths, a shared on/off flag, and timing.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Error handling. Context adds a readable message to an error.
use anyhow::{Context, Result};

// From the common crate: the signing key and config, the stream type, the handshake,
// and pcapng parsing.
use noc_common::identity::VesselSigningKey;
use noc_common::config::VesselConfig;
use noc_common::framing::StreamType;
use noc_common::identity::{client_handshake, write_session_header};
use noc_common::pcapng::{BlockParser, Endianness, SessionHeader};

// Tokio: the TCP connection to shore, channels between tasks, and an async lock.
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};

// The other parts of the vessel daemon that this file starts and connects together.
use crate::chunker::{run_chunker, ReadyChunk};
use crate::disk_buffer::{
    free_bytes, kek_ids_in_use, list_segments, quarantine_segment, replay_segment, DiskBuffer,
    ReplayError,
};
use crate::dumpcap;
use crate::fifo::{open_fifo, run_reader};
use crate::kek::{KekManager, Rotation, TpmBackend, HANDLE_BASE};
use crate::ring_buffer::{FullPolicy, SharedRingBuffer};
use crate::sender::{run_sender, SenderExit, SenderParams, SeqCounters};

/// One megabyte in bytes.
const MB: usize = 1024 * 1024;
/// How long to wait before reconnecting to shore.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
/// How long to wait before restarting the FIFO reader after it stops.
const READER_RETRY: Duration = Duration::from_secs(1);

/// Starts every part of the vessel daemon, then connects to shore and reconnects whenever
/// the link drops.
pub async fn run_vessel(cfg: VesselConfig, key: VesselSigningKey) -> Result<()> {
    // Shutdown signal for the background tasks. Nothing sends on it at the moment.
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    // The live buffer drops new data when it's full. The replay buffer waits for space
    // instead, so decrypted data is never thrown away.
    let live_buf = SharedRingBuffer::new(cfg.ring_buffer.size_mb as usize * MB, FullPolicy::Drop);
    let replay_buf = SharedRingBuffer::new(cfg.replay_buffer_size_bytes() as usize, FullPolicy::Block);
    let header = Arc::new(Mutex::new(SessionHeader::new()));
    // Open the TPM keys. There's no fallback: if the TPM can't be reached, the vessel
    // won't start.
    let backend = TpmBackend::new(&cfg.tpm.tcti, HANDLE_BASE)
        .with_context(|| format!("TPM transport {:?}", cfg.tpm.tcti))?;
    let keks = Arc::new(
        KekManager::open(Arc::new(backend), unix_now())
            .await
            .with_context(|| format!("opening the TPM KEKs via {}", cfg.tpm.tcti))?,
    );
    tracing::info!(
        tcti = %cfg.tpm.tcti,
        current = %format_args!("{:016x}", keks.current().id),
        resident = keks.ids().len(),
        "TPM KEKs ready"
    );

    // Stops segment writing and the KEK clean-up scan from running at the same time.
    let spill_lock = Arc::new(Mutex::new(()));

    // Whether we're connected to shore. The spill monitor uses it to pick its mode.
    let link_up = Arc::new(AtomicBool::new(false));

    // Open the FIFO before starting dumpcap, so the pipe is ready when dumpcap starts.
    let (fifo, fifo_child_end) = open_fifo(
        &cfg.capture.pipe_path,
        cfg.capture.fifo_buffer_size_kb.saturating_mul(1024),
    )
    .with_context(|| format!("opening FIFO {}", cfg.capture.pipe_path.display()))?;

    // The FIFO reader bumps this counter to ask for a dumpcap restart. We keep the
    // sending end here so the channel stays open for the whole run.
    let (restart_capture, restart_capture_rx) = watch::channel(0u64);

    // Background task: keep dumpcap running. It gets the FIFO as an open file, not a path.
    {
        let capture = cfg.capture.clone();
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            dumpcap::supervise(&capture, fifo_child_end, sd, restart_capture_rx).await
        });
    }

    // Background task: read the FIFO into the live ring buffer. If the reader ever stops,
    // ask for a fresh dumpcap, wait a second and start it again, so capture never stops
    // without anyone noticing.
    {
        let lb = live_buf.clone();
        let hdr = header.clone();
        let restart = restart_capture.clone();
        let mut fifo = Some(fifo);
        let pipe_path = cfg.capture.pipe_path.clone();
        let fifo_bytes = cfg.capture.fifo_buffer_size_kb.saturating_mul(1024);
        tokio::spawn(async move {
            loop {
                // First time round, use the FIFO opened above. After that, reopen it.
                let reader = match fifo.take() {
                    Some(f) => f,
                    None => match open_fifo(&pipe_path, fifo_bytes) {
                        // dumpcap already has its own end of the pipe.
                        Ok((r, _child)) => r,
                        Err(e) => {
                            tracing::error!(error = %e, "reopening the capture FIFO failed");
                            tokio::time::sleep(READER_RETRY).await;
                            continue;
                        }
                    },
                };
                match run_reader(reader, lb.clone(), hdr.clone(), restart.clone()).await {
                    Ok(exit) => tracing::warn!(?exit, "FIFO reader stopped; restarting it"),
                    Err(e) => tracing::error!(error = %e, "FIFO reader failed; restarting it"),
                }
                restart.send_modify(|n| *n += 1);
                tokio::time::sleep(READER_RETRY).await;
            }
        });
    }

    let chunk_bytes = cfg.chunking.chunk_size_kb as usize * 1024;
    let max_wait = Duration::from_millis(cfg.chunking.max_wait_ms);

    // Background task: group live blocks into chunks.
    // It packs only while the link is up: during an outage unsent data must stay in the ring,
    // where the spill can take it, not sit in this queue in RAM.
    let (live_tx, mut live_rx) = mpsc::channel::<ReadyChunk>(64);
    {
        let lb = live_buf.clone();
        let up = link_up.clone();
        tokio::spawn(async move {
            run_chunker(lb, StreamType::Live, chunk_bytes, max_wait, live_tx, Some(up)).await;
        });
    }
    // Background task: same for replayed blocks, tagged REPLAY.
    let (replay_tx, mut replay_rx) = mpsc::channel::<ReadyChunk>(64);
    {
        let rb = replay_buf.clone();
        tokio::spawn(async move {
            run_chunker(rb, StreamType::Replay, chunk_bytes, max_wait, replay_tx, None).await;
        });
    }

    // Background task: send any encrypted segments on disk back to shore.
    {
        let spill_dir = cfg.disk_buffer.spill_dir.clone();
        let keks = keks.clone();
        let rb = replay_buf.clone();
        tokio::fs::create_dir_all(&spill_dir).await.ok();
        tokio::spawn(async move { run_replay_driver(&spill_dir, &keks, &rb).await });
    }

    // Sender settings, from the config.
    let params = SenderParams {
        max_in_flight: cfg.transport.max_in_flight_chunks as usize,
        ack_timeout: Duration::from_millis(cfg.transport.ack_timeout_ms),
        live_replay_ratio: cfg.transport.live_replay_send_ratio,
        link_timeout: Duration::from_secs(cfg.disk_buffer.link_down_timeout_s),
    };
    let seg_size = cfg.disk_buffer.segment_size_mb as usize * MB;

    // Background task: move data from RAM to encrypted disk when needed. With the link up
    // it spills everything unsent once the buffer is 95% full. With the link down it
    // writes whole segments only and keeps the rest in RAM.
    {
        let cap = cfg.ring_buffer.size_mb as usize * MB;
        let threshold = cap / 100 * cfg.ring_buffer.spill_high_watermark_pct as usize;
        let ctx = SpillCtx {
            spill_dir: cfg.disk_buffer.spill_dir.clone(),
            seg_size,
            keks: keks.clone(),
            header: header.clone(),
        };
        let lb = live_buf.clone();
        let lock = spill_lock.clone();
        let up = link_up.clone();
        tokio::spawn(async move {
            run_spill_monitor(&lb, threshold, &ctx, &lock, &up).await;
        });
    }

    // Background task: remove TPM keys no segment needs, and rotate the key every 24 hours.
    {
        let keks = keks.clone();
        let spill_dir = cfg.disk_buffer.spill_dir.clone();
        let lock = spill_lock.clone();
        tokio::spawn(async move { run_kek_maintenance(&keks, &spill_dir, &lock).await });
    }

    // One session id per boot, kept across reconnects, so shore can tell a reconnect
    // from a reboot.
    let session_id = noc_common::identity::generate_session_id();
    tracing::info!(%session_id, "vessel session id");

    // Background task: the status snapshot noc-console reads (counters and levels, no keys).
    {
        let fixed = crate::status::Fixed {
            path: crate::status::path(&cfg.capture.pipe_path),
            session: session_id.clone(),
            shore: cfg.transport.shore_addr.clone(),
            interfaces: cfg.capture.interfaces.clone(),
            live_cap: (cfg.ring_buffer.size_mb as usize * MB) as u64,
            replay_cap: cfg.replay_buffer_size_bytes(),
            spill_dir: cfg.disk_buffer.spill_dir.clone(),
            pipe: cfg.capture.pipe_path.clone(),
        };
        tokio::spawn(crate::status::run(fixed, live_buf.clone(), replay_buf.clone(), keks.clone()));
    }
    // These carry over from one connection to the next.
    let mut counters = SeqCounters::default();
    let mut carryover: Vec<ReadyChunk> = Vec::new();

    // Time limit for each setup step. When the link is blackholed, connect and writes
    // just hang instead of failing, so without a limit this loop could get stuck.
    let setup_timeout = Duration::from_secs(cfg.disk_buffer.link_down_timeout_s);

    // Connect, set up the session, then run the sender until the link drops. Repeat.
    loop {
        // Not connected: any live chunk still queued goes back to the ring so an outage
        // spill can take it (one may have been packed just as the link went down).
        return_queued_live(&mut live_rx, &live_buf, Vec::new()).await;
        crate::status::STATS.set_link(crate::status::Link::Connecting);
        let mut sock = match tokio::time::timeout(
            setup_timeout,
            TcpStream::connect(&cfg.transport.shore_addr),
        )
        .await
        {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                s
            }
            Ok(Err(e)) => {
                // Couldn't connect. The spill monitor looks after the data meanwhile,
                // so wait a bit and try again.
                tracing::warn!(addr = %cfg.transport.shore_addr, error = %e, "connect failed; retrying");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            }
            Err(_) => {
                // Timed out. We've already waited the full time, so retry straight away.
                tracing::warn!(
                    addr = %cfg.transport.shore_addr,
                    timeout_s = cfg.disk_buffer.link_down_timeout_s,
                    "connect timed out (link blackholed); retrying"
                );
                continue;
            }
        };

        // Handshake, with the same time limit.
        match tokio::time::timeout(setup_timeout, client_handshake(&mut sock, &key)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "handshake failed; retrying");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            }
            Err(_) => {
                tracing::warn!(
                    timeout_s = cfg.disk_buffer.link_down_timeout_s,
                    "handshake timed out (link blackholed); retrying"
                );
                continue;
            }
        }
        // Then the session id and the pcapng header, same time limit.
        match tokio::time::timeout(
            setup_timeout,
            noc_common::identity::write_session_id(&mut sock, &session_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "sending session id failed; retrying");
                continue;
            }
            Err(_) => {
                tracing::warn!("sending session id timed out (link blackholed); retrying");
                continue;
            }
        }
        // No time limit here on purpose. On a fresh start dumpcap may not have written
        // its header yet, and that's not an error.
        let header_bytes = wait_for_header(&header).await;
        match tokio::time::timeout(setup_timeout, write_session_header(&mut sock, &header_bytes))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "sending header failed; retrying");
                continue;
            }
            Err(_) => {
                tracing::warn!("sending header timed out (link blackholed); retrying");
                continue;
            }
        }
        tracing::info!("connected to shore; streaming");
        link_up.store(true, Ordering::Relaxed);
        crate::status::STATS.set_link(crate::status::Link::Streaming);

        let outcome = run_sender(
            sock,
            &mut live_rx,
            &mut replay_rx,
            live_buf.clone(),
            replay_buf.clone(),
            &mut counters,
            params,
            std::mem::take(&mut carryover),
        )
        .await?;
        // The connection is over, however it ended. Switch the spill monitor to outage
        // mode and keep any unsent chunks for next time.
        link_up.store(false, Ordering::Relaxed);
        crate::status::STATS.set_link(crate::status::Link::Down);
        // Unsent live chunks (the one the sender had taken, then the queue) go back to the
        // ring; an unsent replay chunk is kept, its data is safe on disk already.
        let (live_unsent, replay_unsent): (Vec<_>, Vec<_>) =
            outcome.unsent.into_iter().partition(|c| c.stream == StreamType::Live);
        carryover = replay_unsent;
        return_queued_live(&mut live_rx, &live_buf, live_unsent).await;

        match outcome.exit {
            SenderExit::QueuesClosed => {
                tracing::info!("all queues closed; vessel pipeline done");
                return Ok(());
            }
            SenderExit::PeerClosed => {
                tracing::warn!("shore closed connection; reconnecting");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
            SenderExit::LinkDown => {
                // The spill monitor deals with the outage, so just reconnect.
                tracing::warn!("link down (15s); reconnecting, the spill manager takes care of the outage");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
    }
}

/// Give live chunks that were packed but never sent back to the ring, oldest first:
/// `first` (taken from the queue earlier), then whatever is still queued. They have no
/// sequence number yet, so nothing on shore has seen them and they cannot become duplicates.
async fn return_queued_live(
    live_rx: &mut mpsc::Receiver<ReadyChunk>,
    live_buf: &SharedRingBuffer,
    first: Vec<ReadyChunk>,
) {
    let mut chunks: Vec<Vec<u8>> = first.into_iter().map(|c| c.payload).collect();
    while let Ok(c) = live_rx.try_recv() {
        chunks.push(c.payload);
    }
    if chunks.is_empty() {
        return;
    }
    let bytes: usize = chunks.iter().map(Vec::len).sum();
    tracing::info!(chunks = chunks.len(), bytes, "unsent live chunks returned to the ring for the outage spill");
    live_buf.return_unsent(chunks).await;
}

/// How many segments are sealed at once. We keep it at 1 because the disk is the slow part
/// (about 17 MB/s on our 2-CPU test vessel, while AES-GCM does about 4 GB/s). When we tried 2,
/// it was no faster, and the FIFO reader fell behind so dumpcap dropped packets.
const SEAL_WORKERS: usize = 1;
/// Most segments one spill run seals before it lets go of the spill lock, so the KEK
/// maintenance task is not shut out by a long overload. The next check carries on.
const MAX_SEGMENTS_PER_RUN: usize = 8;
/// Room kept free on the spill disk beyond the segments about to be written.
const DISK_MARGIN: u64 = 8 * MB as u64;
/// Waits after a spill fails for any reason other than a full disk: 1 s, doubling to 10 s.
const SPILL_BACKOFF_MIN: Duration = Duration::from_secs(1);
const SPILL_BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Checks every 200 ms whether data in RAM should be moved to encrypted disk.
async fn run_spill_monitor(
    live_buf: &SharedRingBuffer,
    high_watermark_bytes: usize,
    ctx: &SpillCtx,
    spill_lock: &Arc<Mutex<()>>,
    link_up: &AtomicBool,
) {
    const POLL: Duration = Duration::from_millis(200);
    let mut pacing = SpillPacing::default();
    loop {
        tokio::time::sleep(POLL).await;
        if pacing.backing_off() {
            continue;
        }
        let up = link_up.load(Ordering::Relaxed);
        // Link up: spill once the buffer is 95% full, then everything unsent.
        // Link down: spill whole segments as soon as one is pending, and keep the rest in RAM.
        let due = if up {
            live_buf.used_bytes().await >= high_watermark_bytes
        } else {
            live_buf.pending_bytes().await >= ctx.seg_size
        };
        // With no room on disk, nothing is taken out of the ring: no encryption that would
        // only be thrown away. The data waits in RAM, and the ring tail-drops if it fills.
        if !due || !pacing.disk_has_room(&ctx.spill_dir, ctx.seg_size) {
            continue;
        }
        if up {
            tracing::warn!(
                high_watermark_bytes,
                "ring buffer reached spill high-watermark; draining pending to disk"
            );
        }
        let _g = spill_lock.lock().await;
        spill_run(live_buf, ctx, up, &mut pacing).await;
    }
}

/// The settings the spill functions share.
struct SpillCtx {
    spill_dir: PathBuf,
    seg_size: usize,
    keks: Arc<KekManager>,
    header: Arc<Mutex<SessionHeader>>,
}

/// When the spill may next try, and what it has already said about it. A full disk pauses
/// it until there is room again; any other failure backs it off. Each state change is
/// logged once, not every 200 ms.
#[derive(Default)]
struct SpillPacing {
    /// Paused because the spill disk has no room for a segment.
    disk_full: bool,
    /// Current wait after a failure; zero while spills succeed.
    backoff: Duration,
    /// No attempt before this.
    retry_at: Option<tokio::time::Instant>,
}

impl SpillPacing {
    fn backing_off(&self) -> bool {
        self.retry_at.is_some_and(|t| tokio::time::Instant::now() < t)
    }

    /// Whether the spill disk can take one more segment, logging when that changes. A
    /// failed check counts as room: the spill directory may not exist yet, and a real
    /// problem will show up as a failed write instead.
    fn disk_has_room(&mut self, dir: &Path, seg_size: usize) -> bool {
        match free_bytes(dir) {
            Ok(free) => self.note_free_space(free, seg_size),
            Err(_) => true,
        }
    }

    /// Records how much the spill disk has free, and whether a segment fits in it.
    fn note_free_space(&mut self, free: u64, seg_size: usize) -> bool {
        let room = fits(free, 1, seg_size);
        if !room && !self.disk_full {
            tracing::warn!(
                free_bytes = free,
                "spill disk has no room for a segment; spilling paused, data stays in RAM and the \
                 ring tail-drops if it fills"
            );
        } else if room && self.disk_full {
            tracing::info!(free_bytes = free, "spill disk has room again; spilling resumed");
        }
        self.disk_full = !room;
        room
    }

    fn succeeded(&mut self) {
        if !self.backoff.is_zero() {
            tracing::info!("spilling works again");
        }
        self.backoff = Duration::ZERO;
        self.retry_at = None;
    }

    fn failed(&mut self) -> Duration {
        self.backoff = (self.backoff * 2).clamp(SPILL_BACKOFF_MIN, SPILL_BACKOFF_MAX);
        self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
        self.backoff
    }
}

/// Whether `segments` more segments of `seg_size`, plus the margin, fit in `free` bytes.
fn fits(free: u64, segments: usize, seg_size: usize) -> bool {
    free >= segments as u64 * (seg_size as u64 + DISK_MARGIN)
}

/// One spill: takes the oldest pending segment out of the ring and seals it, up to
/// SEAL_WORKERS at a time, until less than a segment is pending. With the link up the
/// rest goes too, as one last short segment, so everything unsent is on disk. With the
/// link down the rest stays in RAM and is sent on LIVE when the link comes back.
///
/// Only pending blocks are taken, never in-flight ones, and only one segment per worker
/// is out of the ring at a time, so a spill holds at most SEAL_WORKERS segments (and their
/// sealing buffers) in memory besides the ring. A segment that fails to seal stops the run; once the others finish, every
/// failed group goes back to the front of the ring, newest first, so the ring keeps
/// capture order.
async fn spill_run(live_buf: &SharedRingBuffer, ctx: &SpillCtx, link_up: bool, pacing: &mut SpillPacing) {
    // Need the byte order to write segments. Check it before taking anything out of RAM.
    let Some(endian) = current_endianness(&ctx.header).await else {
        tracing::error!("cannot spill: pcapng header/endianness not yet known");
        return;
    };
    // Open the spill folder first too, so if it's missing or read-only nothing is lost.
    let Some(mut db) = open_disk_buffer(ctx, endian).await else {
        pacing.failed();
        return;
    };
    let mut sealing = tokio::task::JoinSet::new();
    let mut failed: Vec<(u64, Vec<Vec<u8>>, std::io::Error)> = Vec::new();
    let (mut handed_out, mut written, mut bytes) = (0usize, 0usize, 0usize);
    let mut rest_taken = false;
    loop {
        // Hand out the next segment while a worker is free, nothing has failed, and the
        // disk has room for it on top of those still being written.
        let more = failed.is_empty()
            && sealing.len() < SEAL_WORKERS
            && handed_out < MAX_SEGMENTS_PER_RUN
            && free_bytes(&ctx.spill_dir).map_or(true, |f| fits(f, sealing.len() + 1, ctx.seg_size));
        if more {
            let mut blocks = live_buf.drain_segment(ctx.seg_size).await;
            if blocks.is_empty() && link_up && !rest_taken {
                blocks = live_buf.drain_pending().await;
                rest_taken = true;
            }
            if !blocks.is_empty() {
                tracing::info!(
                    blocks = blocks.len(),
                    bytes = blocks.iter().map(|b| b.len()).sum::<usize>(),
                    reason = if link_up { "high watermark" } else { "link down" },
                    "sealing a segment"
                );
                let slot = db.reserve();
                let keks = ctx.keks.clone();
                // Sealing and fsyncing takes seconds. On an async worker that stalls the
                // FIFO reader (a 2-vCPU vessel has two workers), and dumpcap then drops.
                sealing.spawn_blocking(move || {
                    let result = slot.seal(&blocks, &keks);
                    (slot.index(), blocks, result)
                });
                handed_out += 1;
                continue;
            }
        }
        match sealing.join_next().await {
            None => break,
            Some(Ok((_, blocks, Ok(_)))) => {
                written += 1;
                bytes += blocks.iter().map(|b| b.len()).sum::<usize>();
            }
            Some(Ok((index, blocks, Err(e)))) => failed.push((index, blocks, e)),
            Some(Err(e)) => tracing::error!(error = %e, "a sealing task failed; the blocks it held are lost"),
        }
    }
    if written > 0 {
        let path = if link_up { "link-up high-watermark" } else { "outage" };
        tracing::info!(bytes, segments = written, path, "spilled to encrypted segments");
    }
    if failed.is_empty() {
        pacing.succeeded();
        return;
    }
    // Back to the ring, newest first: each group goes to the front, so the oldest ends
    // up first, ahead of whatever is still pending.
    failed.sort_by_key(|(index, _, _)| std::cmp::Reverse(*index));
    let (mut returned, mut dropped) = (0usize, 0usize);
    let error = failed[0].2.to_string();
    for (_, blocks, _) in failed {
        let held = blocks.len();
        let lost = live_buf.return_blocks(blocks).await;
        returned += held - lost;
        dropped += lost;
    }
    let retry_in = pacing.failed();
    tracing::error!(
        error,
        segments = written,
        returned,
        dropped,
        retry_in_s = retry_in.as_secs(),
        "spill failed; unwritten blocks returned to the ring"
    );
}

/// Opens the spill directory on the blocking pool: it creates the directory, sweeps stale
/// staging files and lists the segments already there. `None` if that fails, in which
/// case the caller drains nothing and the data stays in RAM.
async fn open_disk_buffer(ctx: &SpillCtx, endian: Endianness) -> Option<DiskBuffer> {
    let dir = ctx.spill_dir.clone();
    match tokio::task::spawn_blocking(move || DiskBuffer::new(&dir, endian)).await {
        Ok(Ok(db)) => Some(db),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "cannot open the spill directory; leaving data in RAM");
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "opening the spill directory failed; leaving data in RAM");
            None
        }
    }
}

/// Gets the capture's byte order from the cached header.
async fn current_endianness(header: &Arc<Mutex<SessionHeader>>) -> Option<Endianness> {
    let h = header.lock().await;
    header_endianness(h.bytes())
}

/// Keeps sending encrypted segment files back to shore, oldest first.
async fn run_replay_driver(
    spill_dir: &Path,
    keks: &Arc<KekManager>,
    replay_buf: &SharedRingBuffer,
) {
    /// How many times a segment may be rejected before it is set aside as .corrupt.
    const MAX_ATTEMPTS: u32 = 3;
    /// Wait after a segment is unavailable (the TPM did not answer), doubling to the cap.
    const RETRY_INITIAL: Duration = Duration::from_secs(1);
    const RETRY_MAX: Duration = Duration::from_secs(30);
    let mut failures: std::collections::HashMap<PathBuf, u32> = std::collections::HashMap::new();
    let mut retry = RETRY_INITIAL;
    // Set while replay is waiting out an unavailable TPM, so its recovery is logged once.
    let mut waiting = false;

    loop {
        // Look for segment files. If there are none, check again in half a second.
        let segments = match list_segments(spill_dir) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "listing spill segments failed");
                Vec::new()
            }
        };
        if segments.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        for seg in segments {
            match replay_segment(&seg, keks, replay_buf).await {
                Ok(()) => {
                    failures.remove(&seg);
                    retry = RETRY_INITIAL;
                    if waiting {
                        tracing::info!("replay resumed: segments are opening again");
                        waiting = false;
                    }
                }
                Err(e @ ReplayError::Unavailable(..)) => {
                    // Not the file's fault, so it does not count towards setting it aside:
                    // a TPM that is briefly unreachable must not cost the segments waiting
                    // on it. Every segment needs the TPM, so stop this pass and wait.
                    tracing::warn!(error = %e, retry_in_s = retry.as_secs(), "segment unavailable; keeping it and retrying");
                    waiting = true;
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(RETRY_MAX);
                    break;
                }
                Err(e @ ReplayError::Rejected(..)) => {
                    // Count the failure. After 3, rename the file so it stops blocking the rest.
                    let attempts = failures.entry(seg.clone()).or_insert(0);
                    *attempts += 1;
                    tracing::error!(segment = %seg.display(), attempt = *attempts, error = %e, "replay of segment failed");
                    if *attempts >= MAX_ATTEMPTS {
                        match quarantine_segment(&seg) {
                            Ok(dest) => {
                                tracing::error!(
                                    segment = %seg.display(),
                                    set_aside = %dest.display(),
                                    "segment failed to replay repeatedly; set aside so it stops blocking replay and releases its KEK"
                                );
                                failures.remove(&seg);
                            }
                            Err(e) => tracing::error!(segment = %seg.display(), error = %e, "could not set the failing segment aside"),
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}

/// Every 5 minutes, removes unneeded TPM keys and rotates the current key when due.
async fn run_kek_maintenance(keks: &KekManager, spill_dir: &Path, spill_lock: &Mutex<()>) {
    const CHECK_EVERY: Duration = Duration::from_secs(300);
    // So the "rotation deferred" warning is logged once, not every 5 minutes.
    let mut deferral_logged = false;
    loop {
        if let Err(e) = evict_unused_keks(keks, spill_dir, spill_lock).await {
            tracing::error!(error = %e, "KEK eviction failed; will retry");
        }
        match keks.rotate_if_due(unix_now()).await {
            Ok(Rotation::NotDue) => deferral_logged = false,
            Ok(Rotation::Rotated { new }) => {
                deferral_logged = false;
                tracing::info!(kek = %format_args!("{new:016x}"), "rotated to a new KEK");
            }
            Ok(Rotation::Deferred) => {
                if !deferral_logged {
                    tracing::warn!("KEK rotation is due but every TPM slot holds a KEK still in use; deferring");
                    deferral_logged = true;
                }
            }
            Err(e) => tracing::error!(error = %e, "KEK rotation failed; will retry"),
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// Removes TPM keys that no segment on disk needs any more.
async fn evict_unused_keks(keks: &KekManager, spill_dir: &Path, spill_lock: &Mutex<()>) -> Result<()> {
    // Hold the spill lock so no segment is written while we check. Otherwise a file still
    // being sealed with an old key could be missed, and that key removed.
    let _no_sealing = spill_lock.lock().await;
    let dir = spill_dir.to_path_buf();
    // Listing the folder blocks, so do it on the blocking thread pool.
    let in_use = tokio::task::spawn_blocking(move || kek_ids_in_use(&dir)).await??;
    for id in keks.evict_unused(&in_use).await? {
        tracing::info!(kek = %format_args!("{id:016x}"), "evicted KEK: no segment on disk needs it");
    }
    Ok(())
}

/// Returns the current time in seconds since 1970 (epoch).
fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Waits until dumpcap's pcapng header has been captured, then returns a copy.
async fn wait_for_header(header: &Arc<Mutex<SessionHeader>>) -> Vec<u8> {
    loop {
        {
            let h = header.lock().await;
            if h.has_header() {
                return h.bytes().to_vec();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Reads the byte order out of a cached pcapng header.
fn header_endianness(header: &[u8]) -> Option<Endianness> {
    if header.is_empty() {
        return None;
    }
    let mut parser = BlockParser::new();
    parser.feed(header);
    match parser.next_block() {
        Ok(Some(block)) => Some(block.endianness),
        _ => None,
    }
}
