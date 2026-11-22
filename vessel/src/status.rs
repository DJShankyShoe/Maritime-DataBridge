//! Status snapshot for `noc-console`.
//!
//! The sender, chunker, FIFO reader and replay driver update these counters as they work.
//! Every 250 ms a task writes them, with the buffer and FIFO levels, to `status.json` in the
//! service's runtime directory (temp file, then rename, so the console never reads half a
//! file). Only counters and levels, no keys. The console works out rates from two snapshots.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noc_common::framing::StreamType;

/// How often the snapshot is rewritten.
pub const INTERVAL: Duration = Duration::from_millis(250);

/// Per-stream counters (LIVE and REPLAY have their own).
pub struct StreamStats {
    /// Chunks closed by the chunker.
    pub packed: AtomicU64,
    /// Chunks sent for the first time, and their payload bytes.
    pub sent: AtomicU64,
    pub sent_bytes: AtomicU64,
    /// Chunks whose ACK arrived.
    pub acked: AtomicU64,
    /// Resends: no ACK in time, or still unACKed when a new connection started.
    pub resent_timeout: AtomicU64,
    pub resent_reconnect: AtomicU64,
    /// Sequence number of the last chunk sent for the first time.
    pub last_seq: AtomicU64,
}

impl StreamStats {
    const fn new() -> Self {
        Self {
            packed: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            resent_timeout: AtomicU64::new(0),
            resent_reconnect: AtomicU64::new(0),
            last_seq: AtomicU64::new(0),
        }
    }
}

/// Link states, as the console shows them.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Link {
    Starting = 0,
    Connecting = 1,
    Streaming = 2,
    Down = 3,
}

pub struct Stats {
    pub live: StreamStats,
    pub replay: StreamStats,
    /// Chunks sent and awaiting their ACK, and the window's size.
    pub inflight: AtomicU64,
    pub max_inflight: AtomicU64,
    /// Smoothed round trip from send to ACK, in microseconds (0 until the first ACK).
    pub rtt_us: AtomicU64,
    pub keepalives: AtomicU64,
    link: AtomicU8,
    link_since_ms: AtomicU64,
    /// Captured blocks the full ring buffer had to drop.
    pub dropped_blocks: AtomicU64,
    /// The segment being replayed, if any.
    replaying: Mutex<String>,
}

pub static STATS: Stats = Stats {
    live: StreamStats::new(),
    replay: StreamStats::new(),
    inflight: AtomicU64::new(0),
    max_inflight: AtomicU64::new(0),
    rtt_us: AtomicU64::new(0),
    keepalives: AtomicU64::new(0),
    link: AtomicU8::new(Link::Starting as u8),
    link_since_ms: AtomicU64::new(0),
    dropped_blocks: AtomicU64::new(0),
    replaying: Mutex::new(String::new()),
};

impl Stats {
    pub fn stream(&self, s: StreamType) -> &StreamStats {
        match s {
            StreamType::Live => &self.live,
            StreamType::Replay => &self.replay,
        }
    }

    /// Record a link state change, and when it happened.
    pub fn set_link(&self, l: Link) {
        if self.link.swap(l as u8, Relaxed) != l as u8 {
            self.link_since_ms.store(now_ms(), Relaxed);
        }
    }

    /// Fold one send-to-ACK time into the smoothed round trip (weight 1/8, as TCP does).
    pub fn rtt_sample(&self, d: Duration) {
        let us = d.as_micros().min(u64::MAX as u128) as u64;
        let old = self.rtt_us.load(Relaxed);
        self.rtt_us.store(if old == 0 { us } else { old - old / 8 + us / 8 }, Relaxed);
    }

    pub fn set_replaying(&self, name: &str) {
        if let Ok(mut r) = self.replaying.lock() {
            r.clear();
            r.push_str(name);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Where the snapshot goes: the service's runtime directory (systemd sets
/// `$RUNTIME_DIRECTORY`), else next to the capture FIFO.
pub fn path(pipe_path: &Path) -> PathBuf {
    std::env::var_os("RUNTIME_DIRECTORY")
        .map(PathBuf::from)
        .or_else(|| pipe_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir)
        .join("status.json")
}

/// What the writer needs that is not a counter.
pub struct Fixed {
    pub path: PathBuf,
    pub session: String,
    pub shore: String,
    pub interfaces: Vec<String>,
    pub live_cap: u64,
    pub replay_cap: u64,
    pub spill_dir: PathBuf,
    pub pipe: PathBuf,
}

/// Rewrite the snapshot every [`INTERVAL`] for the life of the daemon.
pub async fn run(
    fixed: Fixed,
    live: crate::ring_buffer::SharedRingBuffer,
    replay: crate::ring_buffer::SharedRingBuffer,
    keks: Arc<crate::kek::KekManager>,
) {
    let mut tick = tokio::time::interval(INTERVAL);
    let (mut n, mut segs, mut seg_bytes) = (0u64, 0u64, 0u64);
    loop {
        tick.tick().await;
        // The spill directory costs a stat per segment, so look once a second.
        if n % 4 == 0 {
            (segs, seg_bytes) = spill_usage(&fixed.spill_dir);
        }
        n += 1;
        let (lu, lp) = (live.used_bytes().await as u64, live.pending_bytes().await as u64);
        let (ru, rp) = (replay.used_bytes().await as u64, replay.pending_bytes().await as u64);
        let (cap_bytes, cap_packets) = capture_counters(&fixed.interfaces);
        let json = render(&fixed, Levels {
            live_used: lu,
            live_pending: lp,
            replay_used: ru,
            replay_pending: rp,
            fifo: fifo_bytes(&fixed.pipe),
            segments: segs,
            segment_bytes: seg_bytes,
            cap_bytes,
            cap_packets,
            kek: keks.current().id,
        });
        let tmp = fixed.path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            std::fs::rename(&tmp, &fixed.path).ok();
        }
    }
}

struct Levels {
    live_used: u64,
    live_pending: u64,
    replay_used: u64,
    replay_pending: u64,
    fifo: u64,
    segments: u64,
    segment_bytes: u64,
    cap_bytes: u64,
    cap_packets: u64,
    kek: u64,
}

fn render(f: &Fixed, l: Levels) -> String {
    let s = &STATS;
    let stream = |x: &StreamStats| {
        format!(
            r#"{{"packed":{},"sent":{},"sent_bytes":{},"acked":{},"resent_timeout":{},"resent_reconnect":{},"last_seq":{}}}"#,
            x.packed.load(Relaxed),
            x.sent.load(Relaxed),
            x.sent_bytes.load(Relaxed),
            x.acked.load(Relaxed),
            x.resent_timeout.load(Relaxed),
            x.resent_reconnect.load(Relaxed),
            x.last_seq.load(Relaxed),
        )
    };
    let link = match s.link.load(Relaxed) {
        1 => "connecting",
        2 => "streaming",
        3 => "down",
        _ => "starting",
    };
    let replaying = s.replaying.lock().map(|r| r.clone()).unwrap_or_default();
    let ifaces: Vec<String> = f.interfaces.iter().map(|i| format!("\"{}\"", esc(i))).collect();
    format!(
        concat!(
            r#"{{"role":"vessel","time_ms":{},"session":"{}","shore":"{}","link":"{}","link_since_ms":{},"#,
            r#""inflight":{},"max_inflight":{},"rtt_us":{},"keepalives":{},"#,
            r#""live":{},"replay":{},"#,
            r#""live_used":{},"live_pending":{},"live_cap":{},"replay_used":{},"replay_pending":{},"replay_cap":{},"#,
            r#""fifo":{},"segments":{},"segment_bytes":{},"replaying":"{}","kek":"{:016x}","dropped_blocks":{},"#,
            r#""interfaces":[{}],"cap_bytes":{},"cap_packets":{}}}"#,
        ),
        now_ms(),
        esc(&f.session),
        esc(&f.shore),
        link,
        s.link_since_ms.load(Relaxed),
        s.inflight.load(Relaxed),
        s.max_inflight.load(Relaxed),
        s.rtt_us.load(Relaxed),
        s.keepalives.load(Relaxed),
        stream(&s.live),
        stream(&s.replay),
        l.live_used,
        l.live_pending,
        f.live_cap,
        l.replay_used,
        l.replay_pending,
        f.replay_cap,
        l.fifo,
        l.segments,
        l.segment_bytes,
        esc(&replaying),
        l.kek,
        s.dropped_blocks.load(Relaxed),
        ifaces.join(","),
        l.cap_bytes,
        l.cap_packets,
    )
}

/// JSON string escaping for the few strings in the snapshot.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn spill_usage(dir: &Path) -> (u64, u64) {
    let (mut n, mut b) = (0, 0);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".seg") {
                n += 1;
                b += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    (n, b)
}

/// Bytes and packets seen on the capture interfaces, from the kernel's counters: received
/// plus sent, since dumpcap captures both directions.
fn capture_counters(ifaces: &[String]) -> (u64, u64) {
    let read = |i: &str, what: &str| -> u64 {
        std::fs::read_to_string(format!("/sys/class/net/{i}/statistics/{what}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    ifaces.iter().fold((0, 0), |(b, p), i| {
        (b + read(i, "rx_bytes") + read(i, "tx_bytes"), p + read(i, "rx_packets") + read(i, "tx_packets"))
    })
}

/// Bytes waiting in the capture FIFO, read with FIONREAD on a second, never-reading,
/// non-blocking read end.
fn fifo_bytes(pipe: &Path) -> u64 {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(pipe)
        .ok()
        .and_then(|f| {
            let mut n: libc::c_int = 0;
            // SAFETY: FIONREAD writes one c_int through a valid pointer to a local.
            (unsafe { libc::ioctl(f.as_raw_fd(), libc::FIONREAD, &mut n) } == 0).then_some(n as u64)
        })
        .unwrap_or(0)
}
