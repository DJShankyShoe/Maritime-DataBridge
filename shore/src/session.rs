//! Per-vessel session state and flush
//!
//! When vessel receive the packet from shore, after checking if the byte stream is duplicated (via the dedup.rs), it will then append the data into a temp file and flushed to the OS
//! The flush will happen before the shore server ACK closes the process level host, to prevent data loss as the data is already "backup" into the kernel.
//! After all the "supposed" byte stream is flushed into the temp file, it will then prep the temp file to be pcapng
//! When preping the temp file, it will put the pcapng Filename: {vessel_id}_{session_id}_{shore_start}_{label}_{seq:06}.pcapng
//! And because pcap file is a sequence of blocks and the file needs to begin with SHB (Section Header Block) and IDB (Interface Description Block), so will need to check if the packet already consist of the SHB and IDB block, so that the packet does not generate a new file eevery single time it is received
//! Ensure that the file receive on Malcolm side is complete and that any file that is partially done is being left out and Malcolm does not have access to it

//! It will also check the registry - Map session ID to vessel ID
//! If session ID is already existing for this specific vessel, just reconnect it
//! If session ID is a new one for this vessel, flush out all the old data and update the session ID for this specific vessel, before putting the data inside the pcap file
//!

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noc_common::framing::StreamType;
use noc_common::pcapng::starts_with_section_header;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::dedup::{Classification, DedupTracker};

/// The temp subdirectory and the ingest filename label for a stream. These differ:
/// REPLAY accumulates under `replay/` but ships as `backfill`. Keeping both in one
/// match stops them drifting apart.
fn stream_names(stream: StreamType) -> (&'static str, &'static str) {
    match stream {
        StreamType::Live => ("live", "live"),
        StreamType::Replay => ("replay", "backfill"),
    }
}

/// Counters for one vessel session, for the status snapshot noc-console reads. Atomics in
/// their own allocation, shared by the session and the registry, so the snapshot never has
/// to take the session's lock (held across file writes and flushes).
#[derive(Default)]
pub struct VesselStats {
    pub live_chunks: AtomicU64,
    pub replay_chunks: AtomicU64,
    pub duplicates: AtomicU64,
    pub bytes: AtomicU64,
    pub files: AtomicU64,
    /// Wall-clock milliseconds of the last chunk received.
    pub last_chunk_ms: AtomicU64,
    /// Connections from this vessel open right now (normally 0 or 1).
    pub connections: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Per-stream accumulation state.
struct StreamState {
    dedup: DedupTracker,
    file: tokio::fs::File,
    bytes_written: u64,
}

/// State for one vessel boot. Survives reconnects within that boot, so the dedup
/// watermark persists and resent chunks are recognised. A new boot gets a fresh one.
pub struct Vessel {
    vessel_id: String,
    session_id: String,
    /// Cached SHB/IDB, refreshed on reconnect and prepended on flush.
    header: Vec<u8>,
    temp_dir: PathBuf,
    ingest_dir: PathBuf,
    flush_size_bytes: u64,
    expected_window: usize,
    live: Option<StreamState>,
    replay: Option<StreamState>,
    /// When this shore process started, as fixed-width hex milliseconds. Part of every
    /// ingest filename, so a restarted shore resuming the same session can never reuse a
    /// name its previous run already wrote.
    start_stamp: String,
    /// Monotonic counter for flush output filenames within this shore run.
    flush_seq: u64,
    stats: Arc<VesselStats>,
}

impl Vessel {
    fn new(
        vessel_id: String,
        session_id: String,
        temp_dir: PathBuf,
        ingest_dir: PathBuf,
        flush_size_bytes: u64,
        expected_window: usize,
        start_stamp: String,
    ) -> Self {
        Self {
            stats: Arc::new(VesselStats::default()),
            vessel_id,
            session_id,
            start_stamp,
            header: Vec::new(),
            temp_dir,
            ingest_dir,
            flush_size_bytes,
            expected_window,
            live: None,
            replay: None,
            flush_seq: 0,
        }
    }

    /// This session's counters.
    pub fn stats(&self) -> Arc<VesselStats> {
        self.stats.clone()
    }

    /// Refresh the cached pcapng header.
    pub fn set_header(&mut self, header: Vec<u8>) {
        self.header = header;
    }

    fn temp_path(&self, stream: StreamType) -> PathBuf {
        self.temp_dir
            .join(&self.vessel_id)
            .join(stream_names(stream).0)
            .join("current.pcapng.tmp")
    }

    async fn stream_mut(&mut self, stream: StreamType) -> std::io::Result<&mut StreamState> {
        let exists = match stream {
            StreamType::Live => self.live.is_some(),
            StreamType::Replay => self.replay.is_some(),
        };
        if !exists {
            let temp_path = self.temp_path(stream);
            if let Some(parent) = temp_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&temp_path)
                .await?;
            let st = StreamState {
                dedup: DedupTracker::new(self.expected_window),
                file,
                bytes_written: 0,
            };
            match stream {
                StreamType::Live => self.live = Some(st),
                StreamType::Replay => self.replay = Some(st),
            }
        }
        Ok(match stream {
            StreamType::Live => self.live.as_mut().unwrap(),
            StreamType::Replay => self.replay.as_mut().unwrap(),
        })
    }

    /// Append a new chunk, or discard a duplicate. The caller ACKs either way.
    /// Returns whether a size-flush is now due.
    pub async fn accept(
        &mut self,
        stream: StreamType,
        seq: u64,
        payload: &[u8],
    ) -> std::io::Result<(Classification, bool)> {
        let flush_size = self.flush_size_bytes;
        let stats = self.stats.clone();
        let st = self.stream_mut(stream).await?;
        let cls = st.dedup.observe(seq);
        match stream {
            StreamType::Live => stats.live_chunks.fetch_add(1, Relaxed),
            StreamType::Replay => stats.replay_chunks.fetch_add(1, Relaxed),
        };
        if cls == Classification::New {
            stats.bytes.fetch_add(payload.len() as u64, Relaxed);
        } else {
            stats.duplicates.fetch_add(1, Relaxed);
        }
        stats.last_chunk_ms.store(now_ms(), Relaxed);
        if cls == Classification::New {
            st.file.write_all(payload).await?;
            // Hand it to the OS before the caller ACKs. tokio's File buffers writes, so
            // without this an ACK could promise data that a shore crash would lose,
            // which is the gap the ACK layer is there to close. Full durability
            // against host loss would need sync_all per chunk; that cost is not paid
            // here, so a host crash can still lose the un-fsynced tail.
            st.file.flush().await?;
            st.bytes_written += payload.len() as u64;
        }
        let flush_due = flush_size > 0 && st.bytes_written >= flush_size;
        Ok((cls, flush_due))
    }

    /// Finalise a stream's temp file into a standalone pcapng in the ingest dir and
    /// reset it. No-op if nothing has accumulated.
    pub async fn flush_stream(&mut self, stream: StreamType) -> std::io::Result<Option<PathBuf>> {
        let has_data = match stream {
            StreamType::Live => self.live.as_ref().map(|s| s.bytes_written > 0),
            StreamType::Replay => self.replay.as_ref().map(|s| s.bytes_written > 0),
        }
        .unwrap_or(false);
        if !has_data {
            return Ok(None);
        }

        let temp_path = self.temp_path(stream);
        let label = stream_names(stream).1;
        // The session id stops a rebooted vessel's fresh counter from overwriting the
        // previous boot's files; the shore start stamp does the same for a restarted
        // shore, whose counter also starts again from zero.
        let stem = format!("{}_{}_{}_{}", self.vessel_id, self.session_id, self.start_stamp, label);

        // Flush buffered writes before reading the accumulated blocks back.
        if let Some(st) = self.stream_state_mut(stream) {
            st.file.flush().await?;
        }
        tokio::fs::create_dir_all(&self.ingest_dir).await?;
        let body = tokio::fs::read(&temp_path).await?;

        // The capture's own SHB/IDB travel down the data path as ordinary blocks, so the
        // first file of a session already opens with a section header; prepending the
        // cached one there would make a two-section file, which not every pcapng reader
        // handles. Later files start mid-section and do need it.
        let prepend: &[u8] = if starts_with_section_header(&body) {
            &[]
        } else {
            &self.header
        };

        // Write to a staging name and publish it complete, so a partial file is never
        // visible.
        let staging = self.ingest_dir.join(format!("{stem}.pcapng.partial"));
        {
            let mut out = tokio::fs::File::create(&staging).await?;
            out.write_all(prepend).await?;
            out.write_all(&body).await?;
            out.flush().await?;
        }
        let file_bytes = prepend.len() + body.len();
        let out_path = publish_without_replacing(&staging, &self.ingest_dir, &mut self.flush_seq, |n| {
            format!("{stem}_{n:06}.pcapng")
        })
        .await?;

        // Truncate the temp file and reset its counter. The dedup watermark stays,
        // so resent chunks are still recognised after a flush.
        let fresh = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await?;
        if let Some(st) = self.stream_state_mut(stream) {
            st.file = fresh;
            st.bytes_written = 0;
        }
        self.stats.files.fetch_add(1, Relaxed);
        tracing::info!(vessel = %self.vessel_id, stream = label, bytes = file_bytes, ingest = %out_path.display(), "flushed stream to Malcolm ingest");
        Ok(Some(out_path))
    }

    fn stream_state_mut(&mut self, stream: StreamType) -> Option<&mut StreamState> {
        match stream {
            StreamType::Live => self.live.as_mut(),
            StreamType::Replay => self.replay.as_mut(),
        }
    }

    /// Flush both streams, on downtime or session end.
    pub async fn flush_all(&mut self) -> std::io::Result<()> {
        self.flush_stream(StreamType::Live).await?;
        self.flush_stream(StreamType::Replay).await?;
        Ok(())
    }

}

/// Publish `staging` in `dir` under `name(seq)`, moving on to the next number if that
/// name is already taken, and return the path it landed at. `seq` is left one past it.
///
/// A rename would silently replace an existing file, which is how a restarted shore once
/// destroyed ingest files it had already written. A hard link fails instead when the name
/// exists, so whatever else goes wrong, a finished ingest file is never overwritten.
async fn publish_without_replacing(
    staging: &Path,
    dir: &Path,
    seq: &mut u64,
    name: impl Fn(u64) -> String,
) -> std::io::Result<PathBuf> {
    loop {
        let path = dir.join(name(*seq));
        *seq += 1;
        match tokio::fs::hard_link(staging, &path).await {
            Ok(()) => {
                // The file is published; a staging name left behind is only clutter, and
                // failing here would make the caller flush the same data again.
                if let Err(e) = tokio::fs::remove_file(staging).await {
                    tracing::warn!(staging = %staging.display(), error = %e, "could not remove the staging file");
                }
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                tracing::warn!(taken = %path.display(), "ingest file name already exists; using the next number instead of replacing it");
            }
            Err(e) => return Err(e),
        }
    }
}

/// The live session for one vessel, tagged with its session id.
struct SessionEntry {
    session_id: String,
    vessel: Arc<Mutex<Vessel>>,
    stats: Arc<VesselStats>,
}

/// Escape a string for the JSON status snapshot.
fn esc(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

/// Per-vessel sessions, keyed by verified vessel id. Each vessel has at most one
/// live session. A connect carrying a new session id means a reboot: the previous
/// session's buffered data is flushed, its state dropped, and dedup starts fresh.
/// The same session id is a reconnect and reuses the existing state.
pub struct Registry {
    vessels: Mutex<HashMap<String, SessionEntry>>,
    temp_dir: PathBuf,
    ingest_dir: PathBuf,
    flush_size_bytes: u64,
    expected_window: usize,
    /// This shore run's start time, stamped into every ingest filename.
    start_stamp: String,
}

impl Registry {
    pub fn new(
        temp_dir: impl AsRef<Path>,
        ingest_dir: impl AsRef<Path>,
        flush_size_bytes: u64,
        expected_window: usize,
    ) -> Self {
        Self {
            vessels: Mutex::new(HashMap::new()),
            temp_dir: temp_dir.as_ref().to_path_buf(),
            ingest_dir: ingest_dir.as_ref().to_path_buf(),
            flush_size_bytes,
            expected_window,
            start_stamp: start_stamp(),
        }
    }

    /// The status snapshot noc-console reads: this shore run, and each vessel's session and
    /// counters. Reads atomics only, never a session's lock.
    pub async fn status_json(&self) -> String {
        let map = self.vessels.lock().await;
        let mut ids: Vec<&String> = map.keys().collect();
        ids.sort();
        let vessels: Vec<String> = ids
            .into_iter()
            .map(|id| {
                let e = &map[id];
                let st = &e.stats;
                format!(
                    concat!(
                        r#"{{"id":"{}","session":"{}","connections":{},"live_chunks":{},"replay_chunks":{},"#,
                        r#""duplicates":{},"bytes":{},"files":{},"last_chunk_ms":{}}}"#
                    ),
                    esc(id),
                    esc(&e.session_id),
                    st.connections.load(Relaxed),
                    st.live_chunks.load(Relaxed),
                    st.replay_chunks.load(Relaxed),
                    st.duplicates.load(Relaxed),
                    st.bytes.load(Relaxed),
                    st.files.load(Relaxed),
                    st.last_chunk_ms.load(Relaxed),
                )
            })
            .collect();
        format!(
            r#"{{"role":"shore","time_ms":{},"start":"{}","vessels":[{}]}}"#,
            now_ms(),
            esc(&self.start_stamp),
            vessels.join(",")
        )
    }

    /// Fetch the session for this vessel and boot, superseding any prior boot's.
    pub async fn get_or_create(&self, vessel_id: &str, session_id: &str) -> Arc<Mutex<Vessel>> {
        // Decide under the lock, then flush any superseded session after releasing
        // it, so no file I/O happens while holding it.
        let superseded: Option<Arc<Mutex<Vessel>>>;
        let vessel: Arc<Mutex<Vessel>>;
        {
            let mut map = self.vessels.lock().await;
            match map.get(vessel_id) {
                Some(entry) if entry.session_id == session_id => {
                    tracing::info!(vessel = %vessel_id, %session_id, "reconnect: same session, dedup state kept");
                    return entry.vessel.clone();
                }
                existing => {
                    tracing::info!(vessel = %vessel_id, %session_id, supersedes = existing.is_some(), "new session");
                    superseded = existing.map(|e| e.vessel.clone());
                    let v = Vessel::new(
                        vessel_id.to_string(),
                        session_id.to_string(),
                        self.temp_dir.clone(),
                        self.ingest_dir.clone(),
                        self.flush_size_bytes,
                        self.expected_window,
                        self.start_stamp.clone(),
                    );
                    let stats = v.stats();
                    vessel = Arc::new(Mutex::new(v));
                    map.insert(
                        vessel_id.to_string(),
                        SessionEntry {
                            session_id: session_id.to_string(),
                            vessel: vessel.clone(),
                            stats,
                        },
                    );
                }
            }
        }
        if let Some(old) = superseded {
            // Salvage whatever the prior boot buffered, best effort.
            if let Err(e) = old.lock().await.flush_all().await {
                tracing::warn!(vessel = %vessel_id, error = %e, "flush of superseded session failed");
            } else {
                tracing::info!(vessel = %vessel_id, new_session = %session_id, "new vessel session superseded the previous one");
            }
        }
        vessel
    }

    /// Flush every live session on both streams, whatever its link state. Returns how
    /// many ingest files were written. A failure on one vessel is logged and skipped so
    /// it cannot stall the sweep for the rest of the fleet.
    pub async fn flush_all_sessions(&self) -> usize {
        // Snapshot the handles under the lock, then do file I/O with it released.
        let sessions: Vec<(String, Arc<Mutex<Vessel>>)> = {
            let map = self.vessels.lock().await;
            map.iter()
                .map(|(id, entry)| (id.clone(), entry.vessel.clone()))
                .collect()
        };

        let mut flushed = 0;
        for (vessel_id, vessel) in sessions {
            let mut v = vessel.lock().await;
            for stream in [StreamType::Live, StreamType::Replay] {
                match v.flush_stream(stream).await {
                    Ok(Some(_)) => flushed += 1,
                    Ok(None) => {} // nothing accumulated for this stream
                    Err(e) => {
                        tracing::warn!(vessel = %vessel_id, ?stream, error = %e, "periodic flush failed")
                    }
                }
            }
        }
        flushed
    }
}

/// The current time as fixed-width hex milliseconds, so names sort in start order.
fn start_stamp() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    format!("{ms:012x}")
}

/// The time-mode flush scheduler: every `interval`, flush every live session.
///
/// This sweep is all of time mode's scheduling. Being link-state-agnostic it covers
/// the outage case for free, which is why time mode needs no downtime rule of its
/// own. It runs shore-wide rather than per connection, so a session that has since
/// disconnected still gets its buffered data out.
pub async fn run_flush_sweep(registry: Arc<Registry>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // consume the immediate first tick
    loop {
        tick.tick().await;
        let n = registry.flush_all_sessions().await;
        if n > 0 {
            tracing::info!(files = n, "periodic flush sweep moved files to Malcolm ingest");
        }
    }
}
