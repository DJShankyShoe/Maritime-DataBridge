//! Configuration for both vessel and shore. (might needa split them up?)

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Types of errors that may occur
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

// ---------------------------------------------------------------------------
// Vessel config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VesselConfig {
    pub capture: CaptureConfig,
    pub ring_buffer: RingBufferConfig,
    pub chunking: ChunkingConfig,
    pub disk_buffer: DiskBufferConfig,
    pub replay_buffer: ReplayBufferConfig,
    pub transport: TransportConfig,
    pub identity: IdentityConfig,
    /// Optional, see TpmConfig.
    #[serde(default)]
    pub tpm: TpmConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Path to private signing key, it is to authenticate vessel's identity.
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmConfig {
    /// Configuration specifying the TPM connection interface. (either `device:/dev/tpmrm0` or 
    /// [for dev because it uses software TPM] `swtpm:host=127.0.0.1,port=2321`)
    #[serde(default = "default_tpm_tcti")]
    pub tcti: String,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self { tcti: default_tpm_tcti() }
    }
}

/// Configuration for capturing packets
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    /// Interfaces to capture on.
    pub interfaces: Vec<String>,
    /// Path the FIFO dumpcap writes to.
    pub pipe_path: PathBuf,
    /// Kernel pipe buffer size. Size might exceeds the 1 MB ceiling, so `fs.pipe-max-size` needs to be raised first.
    #[serde(default = "default_fifo_buffer_size_kb")]
    pub fifo_buffer_size_kb: u32,
    /// Capture buffer for each interface, passed to dumpcap as `-B`.
    #[serde(default = "default_libpcap_buffer_size_mb")]
    pub libpcap_buffer_size_mb: u32,
}

/// In-RAM ring buffer sizing and disk spill watermark.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingBufferConfig {
    /// Ring buffer size in MB.
    #[serde(default = "default_ring_buffer_size_mb")]
    pub size_mb: u32,
    /// Percentage where unsent data starts spilling to encrypted disk segments.
    #[serde(default = "default_spill_high_watermark_pct")]
    pub spill_high_watermark_pct: u8,
}

/// Settings for batching captured blocks into network chunks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkingConfig {
    /// Chunk size for sending in KB. Packets are never split, so size might exceed.
    #[serde(default = "default_chunk_size_kb")]
    pub chunk_size_kb: u32,
    /// Maximum time in ms to wait before sending a chunk that is not filled up.
    #[serde(default = "default_max_wait_ms")]
    pub max_wait_ms: u64,
}

/// Settings for writing encrypted segments to disk during network outages.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskBufferConfig {
    /// Target size in MB for encrypted disk segments. 
    /// Cut at packet boundaries, so segment size might exceed the default.
    #[serde(default = "default_segment_size_mb")]
    pub segment_size_mb: u32,
    /// Seconds before the connection counts as down. Matches shore's downtime timeout.
    #[serde(default = "default_link_down_timeout_s")]
    pub link_down_timeout_s: u64,
    /// Directory where encrypted disk segments are stored during outages.
    #[serde(default = "default_spill_dir")]
    pub spill_dir: PathBuf,
}

/// Margin for reading encrypted disk segments back into memory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBufferConfig {
    /// Extra MB added to segment_size_mb so the replay buffer can fit oversized segments.
    #[serde(default = "default_replay_margin_mb")]
    pub margin_mb: u32,
}

/// Settings for sending chunks to shore over the network.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// How many chunks can be waiting for an ACK at once.
    #[serde(default = "default_max_in_flight_chunks")]
    pub max_in_flight_chunks: u32,
    /// How long to wait in milliseconds for an ACK before resending a chunk.
    #[serde(default = "default_ack_timeout_ms")]
    pub ack_timeout_ms: u64,
    /// How LIVE and REPLAY share the link: 0 gives LIVE strict priority; N >= 1 sends N live chunks per 1 replay chunk.
    #[serde(default = "default_live_replay_send_ratio")]
    pub live_replay_send_ratio: u32,
    /// Shore server address (host:port) to connect to, routed over WARP in production.
    pub shore_addr: String,
}

// Loading, buffer size calculation, and validation for vessel configuration.
impl VesselConfig {
    /// Loads and validates a vessel config from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let cfg: VesselConfig = load_toml(path.as_ref())?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Replay buffer size in bytes, calculated from segment size plus margin.
    pub fn replay_buffer_size_bytes(&self) -> u64 {
        (self.disk_buffer.segment_size_mb as u64 + self.replay_buffer.margin_mb as u64)
            * 1024
            * 1024
    }

    /// Checks that all vessel settings are within valid operational limits.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.capture.interfaces.is_empty() {
            return Err(ConfigError::Invalid(
                "capture.interfaces must list at least one interface".into(),
            ));
        }
        if self.transport.max_in_flight_chunks == 0 {
            return Err(ConfigError::Invalid(
                "transport.max_in_flight_chunks must be >= 1".into(),
            ));
        }
        // Ratio 0 means strict live priority: REPLAY chunks are only sent when no LIVE chunks are waiting.
        if self.chunking.chunk_size_kb == 0 {
            return Err(ConfigError::Invalid(
                "chunking.chunk_size_kb must be > 0".into(),
            ));
        }
        if self.ring_buffer.size_mb == 0 {
            return Err(ConfigError::Invalid("ring_buffer.size_mb must be > 0".into()));
        }
        if !(1..=99).contains(&self.ring_buffer.spill_high_watermark_pct) {
            return Err(ConfigError::Invalid(
                "ring_buffer.spill_high_watermark_pct must be between 1 and 99".into(),
            ));
        }
        // A whole segment must be able to form inside the ring buffer, or the outage spill can never write one.
        if self.disk_buffer.segment_size_mb == 0 {
            return Err(ConfigError::Invalid(
                "disk_buffer.segment_size_mb must be > 0".into(),
            ));
        }
        if self.disk_buffer.segment_size_mb >= self.ring_buffer.size_mb {
            return Err(ConfigError::Invalid(format!(
                "disk_buffer.segment_size_mb ({}) must be < ring_buffer.size_mb ({})",
                self.disk_buffer.segment_size_mb, self.ring_buffer.size_mb
            )));
        }
        if self.tpm.tcti.trim().is_empty() {
            return Err(ConfigError::Invalid("tpm.tcti must not be empty".into()));
        }
        // The at-rest guarantee needs a real TPM: a software TPM keeps the KEK in a file.
        if !ALLOW_SOFTWARE_TPM && !self.tpm.tcti.trim().starts_with("device:") {
            return Err(ConfigError::Invalid(format!(
                "tpm.tcti must be a TPM device such as \"device:/dev/tpmrm0\" (got {:?}): this build does not run on a software TPM",
                self.tpm.tcti
            )));
        }
        // host:port with a numeric port; the host may be a name, so it is resolved at connect time.
        let addr = self.transport.shore_addr.trim();
        let port_ok = addr
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0));
        if !port_ok {
            return Err(ConfigError::Invalid(format!(
                "transport.shore_addr must be the shore's host:port (got {addr:?})"
            )));
        }
        if self.identity.key_file.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "identity.key_file must name this vessel's signing key".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shore config
// ---------------------------------------------------------------------------

/// Whether `[tpm] tcti` may name something other than a TPM device (the swtpm emulator).
/// The dev tree allows it for hosts without a chip; tools/make-prod-tree.sh sets it to
/// false, so a production vessel refuses to start on anything but a real TPM.
pub const ALLOW_SOFTWARE_TPM: bool = false;

/// Top-level shore daemon configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoreConfig {
    pub shore: ShoreSection,
}

/// Settings for the shore daemon: ingest, identity, network address, and keepalives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoreSection {
    pub ingest: IngestConfig,
    pub identity: ShoreIdentityConfig,
    /// Local address (host:port) to listen on. Sits behind WARP with no public IP in production.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Seconds between keepalive frames sent to vessels. Kept below vessel link timeout so connections stay alive.
    #[serde(default = "default_keepalive_interval_s")]
    pub keepalive_interval_s: u64,
}

/// Identity and device verification settings for shore.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoreIdentityConfig {
    /// Path to a static key-to-vessel table, the offline alternative to the Cloudflare lookup.
    #[serde(default)]
    pub devices_file: Option<PathBuf>,

    /// Optional Cloudflare account ID. Setting this selects live lookup via Cloudflare Devices API.
    #[serde(default)]
    pub cloudflare_account_id: Option<String>,

    /// Path to a file holding the read-only Cloudflare API token. NOC_CF_API_TOKEN environment variable works too.
    #[serde(default)]
    pub api_token_file: Option<PathBuf>,

    /// Seconds between refreshing the device table from Cloudflare.
    #[serde(default = "default_vessel_lookup_refresh_s")]
    pub vessel_lookup_refresh_s: u64,
}

/// Ingest directory and flush settings for Malcolm.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestConfig {
    #[serde(default)]
    pub mode: FlushMode,

    /// Flushes incoming capture files once they reach this size in MB (used in size mode).
    #[serde(default = "default_flush_size_mb")]
    pub flush_size_mb: u32,

    /// Seconds between periodic flush sweeps (used in time mode).
    #[serde(default = "default_flush_interval_s")]
    pub flush_interval_s: u64,
    /// Seconds of inactivity before treating the link as dropped, forcing a flush in size mode.
    #[serde(default = "default_downtime_timeout_s")]
    pub downtime_timeout_s: u64,
    /// Temporary staging directory for active captures.
    #[serde(default = "default_temp_dir")]
    pub temp_dir: PathBuf,
    /// Final directory where completed captures are handed off to Malcolm.
    #[serde(default = "default_ingest_dir")]
    pub ingest_dir: PathBuf,
}

/// How shore decides when to write out pcapng files: by size or on a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FlushMode {
    /// Flushes when a file reaches flush_size_mb, or when the link drops.
    #[default]
    Size,
    /// Flushes on a fixed timer every flush_interval_s, regardless of connection state.
    Time,
}

// Loading and validation for shore configuration.
impl ShoreConfig {
    /// Loads and validates a shore config from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let cfg: ShoreConfig = load_toml(path.as_ref())?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks that the settings required by the chosen flush mode are valid.
    fn validate(&self) -> Result<(), ConfigError> {
        // Vessels are resolved through Cloudflare when an account is set, else a static table.
        let id = &self.shore.identity;
        match &id.cloudflare_account_id {
            Some(a) if a.trim().is_empty() => {
                return Err(ConfigError::Invalid(
                    "shore.identity.cloudflare_account_id is empty: set the Zero Trust account id (or comment it out and set devices_file)".into(),
                ))
            }
            Some(_) => {}
            None if id.devices_file.is_none() => {
                return Err(ConfigError::Invalid(
                    "shore.identity needs cloudflare_account_id (live lookup) or devices_file (static table)".into(),
                ))
            }
            None => {}
        }
        let ingest = &self.shore.ingest;
        if ingest.mode == FlushMode::Size && ingest.flush_size_mb == 0 {
            return Err(ConfigError::Invalid(
                "shore.ingest.flush_size_mb must be > 0 in size mode".into(),
            ));
        }
        if ingest.mode == FlushMode::Time && ingest.flush_interval_s == 0 {
            return Err(ConfigError::Invalid(
                "shore.ingest.flush_interval_s must be > 0 in time mode".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared helpers + defaults
// ---------------------------------------------------------------------------

/// Reads and parses a TOML file into the requested type.
fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Default capture FIFO buffer size: 16 MB (16384 KB).
fn default_fifo_buffer_size_kb() -> u32 {
    16384
}
/// Default capture buffer per interface: 64 MB. With the old 4 MB default dumpcap started
/// dropping packets from about 75 Mbps; with 64 MB nothing was lost up to 100 Mbps.
fn default_libpcap_buffer_size_mb() -> u32 {
    64
}
/// Default RAM ring buffer size: 128 MB.
fn default_ring_buffer_size_mb() -> u32 {
    128
}
/// Default spill high watermark trigger: 95% full.
fn default_spill_high_watermark_pct() -> u8 {
    95
}
/// Default network chunk send batch size: 64 KB.
fn default_chunk_size_kb() -> u32 {
    64
}
/// Default maximum wait time before closing a chunk: 2000 ms.
fn default_max_wait_ms() -> u64 {
    2000
}
/// Default encrypted disk segment size: 32 MB.
fn default_segment_size_mb() -> u32 {
    32
}
/// Default link outage detection timeout: 15 seconds.
fn default_link_down_timeout_s() -> u64 {
    15
}
/// Default replay buffer safety margin: 5 MB.
fn default_replay_margin_mb() -> u32 {
    5
}
/// Default maximum unacknowledged chunks in flight: 8.
fn default_max_in_flight_chunks() -> u32 {
    8
}
/// Default chunk ACK timeout before resending: 2000 ms.
fn default_ack_timeout_ms() -> u64 {
    2000
}
/// Default stream priority ratio: 0 (strict LIVE priority).
fn default_live_replay_send_ratio() -> u32 {
    0
}
/// Default file flush size in size mode: 10 MB.
fn default_flush_size_mb() -> u32 {
    10
}
/// Default flush sweep interval in time mode: 30 seconds.
fn default_flush_interval_s() -> u64 {
    30
}
/// Default shore link downtime timeout: 15 seconds.
fn default_downtime_timeout_s() -> u64 {
    15
}
/// Default directory for encrypted disk spill segments.
fn default_spill_dir() -> PathBuf {
    PathBuf::from("/var/noc/spill/")
}
/// Default shore TCP bind address.
fn default_listen_addr() -> String {
    "0.0.0.0:9600".to_string()
}
/// Default Cloudflare device list refresh interval: 600 seconds (10 minutes).
fn default_vessel_lookup_refresh_s() -> u64 {
    600
}
/// Default keepalive ping interval: 5 seconds.
fn default_keepalive_interval_s() -> u64 {
    5
}
/// Default TPM transport interface string.
fn default_tpm_tcti() -> String {
    "device:/dev/tpmrm0".to_string()
}
/// Default temporary directory for staging captures on shore.
fn default_temp_dir() -> PathBuf {
    PathBuf::from("/var/shore/tmp/")
}
/// Default directory for Malcolm ingest on shore.
fn default_ingest_dir() -> PathBuf {
    PathBuf::from("/var/shore/malcolm_ingest/")
}
