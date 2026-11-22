//! Sends chunks to shore over one connection: picks LIVE or REPLAY, waits for each
//! chunk's ACK, resends late ones and notices when the link has gone down.

// Standard library: a hash map and durations.
use std::collections::HashMap;
use std::time::Duration;

// Frame types and socket helpers from the common crate, plus Tokio's I/O, channels and timers.
use noc_common::framing::StreamType;
use noc_common::wire::{write_chunk, ServerMsg, ServerMsgReader};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

// The chunk type and ring buffer from this crate.
use crate::chunker::ReadyChunk;
use crate::ring_buffer::SharedRingBuffer;
use crate::status::STATS;
use std::sync::atomic::Ordering::Relaxed;

/// The next sequence number for each stream, LIVE and REPLAY.
#[derive(Debug, Default)]
pub struct SeqCounters {
    live: u64,
    replay: u64,
}

// Reading and bumping the sequence counters.
impl SeqCounters {
    /// Returns the next sequence number for a stream without using it up.
    fn peek(&self, stream: StreamType) -> u64 {
        match stream {
            StreamType::Live => self.live,
            StreamType::Replay => self.replay,
        }
    }

    /// Moves a stream's counter on by one.
    fn advance(&mut self, stream: StreamType) {
        match stream {
            StreamType::Live => self.live += 1,
            StreamType::Replay => self.replay += 1,
        }
    }
}

/// The four settings the sender runs with.
#[derive(Debug, Clone, Copy)]
pub struct SenderParams {
    /// How many chunks can be waiting for an ACK at once.
    pub max_in_flight: usize,
    /// How long to wait for an ACK before resending a chunk.
    pub ack_timeout: Duration,
    /// 0 = LIVE always goes first. N = N LIVE chunks, then one REPLAY.
    pub live_replay_ratio: u32,
    /// How long shore can stay silent (with chunks outstanding) before the link counts as down.
    pub link_timeout: Duration,
}

/// Reason for run_sender stopping.
#[derive(Debug, PartialEq, Eq)]
pub enum SenderExit {
    /// Shore closed the connection cleanly.
    PeerClosed,
    /// Both chunk queues closed with nothing left to send.
    QueuesClosed,
    /// A write failed or stalled, or shore went silent for too long.
    LinkDown,
}

/// Decides whether the next chunk sent is LIVE or REPLAY.
fn choose_stream(
    live_ready: bool,
    replay_ready: bool,
    consecutive_live: &mut u32,
    ratio: u32,
) -> Option<StreamType> {
    match (live_ready, replay_ready) {
        (true, true) => {
            if ratio == 0 {
                // Ratio 0: LIVE always wins while it has data.
                *consecutive_live += 1;
                Some(StreamType::Live)
            } else if *consecutive_live >= ratio {
                *consecutive_live = 0;
                Some(StreamType::Replay)
            } else {
                *consecutive_live += 1;
                Some(StreamType::Live)
            }
        }
        (true, false) => {
            *consecutive_live += 1;
            Some(StreamType::Live)
        }
        (false, true) => {
            *consecutive_live = 0;
            Some(StreamType::Replay)
        }
        (false, false) => None,
    }
}

/// Writes a chunk, and treats a write that takes longer than link_timeout as a dead link.
/// Returns false if the write failed or timed out.
async fn timed_write<W>(
    wr: &mut W,
    stream: StreamType,
    seq: u64,
    payload: &[u8],
    link_timeout: Duration,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    matches!(
        tokio::time::timeout(link_timeout, write_chunk(wr, stream, seq, payload)).await,
        Ok(Ok(()))
    )
}

/// What run_sender hands back: the exit reason and any unsent chunks.
#[derive(Debug)]
pub struct SenderOutcome {
    pub exit: SenderExit,
    /// Chunks taken from a queue but never written (at most one per stream).
    pub unsent: Vec<ReadyChunk>,
}

/// Sends chunks to shore over one connection, and handles ACKs, resends and link-down.
#[allow(clippy::too_many_arguments)]
pub async fn run_sender<S>(
    io: S,
    live_rx: &mut mpsc::Receiver<ReadyChunk>,
    replay_rx: &mut mpsc::Receiver<ReadyChunk>,
    live_buf: SharedRingBuffer,
    replay_buf: SharedRingBuffer,
    counters: &mut SeqCounters,
    params: SenderParams,
    carryover: Vec<ReadyChunk>,
) -> anyhow::Result<SenderOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Separate read and write halves, so we can wait for ACKs while writing chunks.
    let (mut rd, mut wr) = tokio::io::split(io);

    // Returns the buffer that matches a stream.
    let buf_for = |stream: StreamType| match stream {
        StreamType::Live => &live_buf,
        StreamType::Replay => &replay_buf,
    };

    // Chunks waiting for an ACK, keyed by (stream, seq), with the time each is due a resend.
    // The payload itself stays in the ring buffer.
    let mut inflight: HashMap<(StreamType, u64), Instant> = HashMap::new();
    STATS.max_inflight.store(params.max_in_flight as u64, Relaxed);
    let mut live_slot: Option<ReadyChunk> = None;
    let mut replay_slot: Option<ReadyChunk> = None;
    let mut consecutive_live: u32 = 0;
    let mut live_open = true;
    let mut replay_open = true;
    // Last time we heard anything from shore (ACK or keepalive).
    let mut last_progress = Instant::now();
    let mut server_msgs = ServerMsgReader::new();

    // Put back any chunks the last connection took but never sent.
    for c in carryover {
        match c.stream {
            StreamType::Live => live_slot = Some(c),
            StreamType::Replay => replay_slot = Some(c),
        }
    }

    // Resend chunks still waiting for an ACK from the last connection, with the same
    // stream and seq, so shore can spot the ones it already has.
    let mut startup_link_down = false;
    'resend: for (stream, buf) in [
        (StreamType::Live, &live_buf),
        (StreamType::Replay, &replay_buf),
    ] {
        for (seq, payload) in buf.inflight_entries().await {
            STATS.stream(stream).resent_reconnect.fetch_add(1, Relaxed);
            if !timed_write(&mut wr, stream, seq, &payload, params.link_timeout).await {
                startup_link_down = true;
                break 'resend;
            }
            inflight.insert((stream, seq), Instant::now() + params.ack_timeout);
            STATS.inflight.store(inflight.len() as u64, Relaxed);
        }
    }

    let exit = if startup_link_down {
        SenderExit::LinkDown
    } else {
        loop {
            // First, resend anything whose ACK is overdue.
            let now = Instant::now();
            let mut expired: Vec<(StreamType, u64)> = inflight
                .iter()
                .filter(|(_, &deadline)| deadline <= now)
                .map(|(&k, _)| k)
                .collect();
            // Lowest seq first. The map has no order, and shore expects the lower ones first.
            expired.sort_unstable_by_key(|&(_, seq)| seq);
            let mut write_failed = false;
            for (stream, seq) in expired {
                match buf_for(stream).inflight_payload_cloned(seq).await {
                    Some(payload) => {
                        STATS.stream(stream).resent_timeout.fetch_add(1, Relaxed);
                        if !timed_write(&mut wr, stream, seq, &payload, params.link_timeout).await {
                            write_failed = true;
                            break;
                        }
                        inflight.insert((stream, seq), Instant::now() + params.ack_timeout);
                    }
                    None => {
                        // Its ACK already arrived, so just drop the timer.
                        inflight.remove(&(stream, seq));
                    }
                }
            }
            if write_failed {
                break SenderExit::LinkDown;
            }

            // Then send new chunks while there's room in the window.
            let mut write_failed = false;
            loop {
                // Top up the slots from the queues without waiting.
                if live_slot.is_none() {
                    if let Ok(c) = live_rx.try_recv() {
                        live_slot = Some(c);
                    }
                }
                if replay_slot.is_none() {
                    if let Ok(c) = replay_rx.try_recv() {
                        replay_slot = Some(c);
                    }
                }
                if inflight.len() >= params.max_in_flight {
                    break;
                }
                let Some(stream) = choose_stream(
                    live_slot.is_some(),
                    replay_slot.is_some(),
                    &mut consecutive_live,
                    params.live_replay_ratio,
                ) else {
                    break;
                };
                let chunk = match stream {
                    StreamType::Live => live_slot.take().unwrap(),
                    StreamType::Replay => replay_slot.take().unwrap(),
                };
                // Only peek the seq here. If the write fails, the same number is used next
                // time, so shore never sees a gap.
                let seq = counters.peek(stream);
                if !timed_write(&mut wr, stream, seq, &chunk.payload, params.link_timeout).await {
                    // Link is down. Put the chunk back so the next connection sends it.
                    match stream {
                        StreamType::Live => live_slot = Some(chunk),
                        StreamType::Replay => replay_slot = Some(chunk),
                    }
                    write_failed = true;
                    break;
                }
                counters.advance(stream);
                let st = STATS.stream(stream);
                st.sent.fetch_add(1, Relaxed);
                st.sent_bytes.fetch_add(chunk.payload.len() as u64, Relaxed);
                st.last_seq.store(seq, Relaxed);
                // Mark it as sent in the buffer. It stays there until its ACK.
                buf_for(stream).commit_chunk(seq, chunk.payload).await;
                inflight.insert((stream, seq), Instant::now() + params.ack_timeout);
                STATS.inflight.store(inflight.len() as u64, Relaxed);
            }
            if write_failed {
                break SenderExit::LinkDown;
            }

            // Nothing left to send and both queues closed, so we're done.
            if inflight.is_empty()
                && live_slot.is_none()
                && replay_slot.is_none()
                && !live_open
                && !replay_open
            {
                break SenderExit::QueuesClosed;
            }

            // Nothing more to do for now, so wait for whatever happens next.
            let next_deadline = inflight.values().min().copied();
            let window_open = inflight.len() < params.max_in_flight;
            let link_deadline = last_progress + params.link_timeout;

            tokio::select! {
                // Message from shore. An ACK frees its chunk. A keepalive just tells us
                // the link is still up. Both reset the link-down timer.
                msg = server_msgs.next(&mut rd) => {
                    match msg {
                        Ok(Some(ServerMsg::Ack(ack))) => {
                            if let Some(due) = inflight.remove(&(ack.stream, ack.seq)) {
                                buf_for(ack.stream).release_chunk(ack.seq).await;
                                // Sent at (due - ack_timeout), so the round trip is what is
                                // left of the timer subtracted from its length.
                                STATS.rtt_sample(params.ack_timeout.saturating_sub(due.saturating_duration_since(Instant::now())));
                                STATS.stream(ack.stream).acked.fetch_add(1, Relaxed);
                                STATS.inflight.store(inflight.len() as u64, Relaxed);
                            }
                            last_progress = Instant::now();
                        }
                        Ok(Some(ServerMsg::Keepalive)) => {
                            STATS.keepalives.fetch_add(1, Relaxed);
                            last_progress = Instant::now();
                        }
                        Ok(None) => break SenderExit::PeerClosed,
                        Err(_) => break SenderExit::LinkDown, // socket read error
                    }
                }
                // A resend timer is due.
                _ = async {
                    match next_deadline {
                        Some(d) => sleep_until(d).await,
                        None => std::future::pending::<()>().await,
                    }
                } => { /* the resend happens at the top of the loop */ }
                // Shore has been silent too long: no ACK and no keepalive. Armed whether or
                // not chunks are in flight, because shore sends a keepalive every few
                // seconds; an idle vessel whose connection has quietly died (a tunnel that
                // closed shore's end but not ours) would otherwise sit "connected" until
                // it next had data to send.
                _ = sleep_until(link_deadline) => {
                    break SenderExit::LinkDown;
                }
                // New LIVE chunk. Only wait for one if there's room to send it.
                c = live_rx.recv(), if window_open && live_slot.is_none() && live_open => {
                    match c {
                        Some(c) => live_slot = Some(c),
                        None => live_open = false,
                    }
                }
                // New REPLAY chunk.
                c = replay_rx.recv(), if window_open && replay_slot.is_none() && replay_open => {
                    match c {
                        Some(c) => replay_slot = Some(c),
                        None => replay_open = false,
                    }
                }
            }
        }
    };

    // Hand back anything still sitting in a slot, for the next connection.
    let mut unsent = Vec::new();
    if let Some(c) = live_slot.take() {
        unsent.push(c);
    }
    if let Some(c) = replay_slot.take() {
        unsent.push(c);
    }
    // This connection's window is gone; its unACKed chunks go out again on the next one.
    STATS.inflight.store(0, Relaxed);
    Ok(SenderOutcome { exit, unsent })
}
