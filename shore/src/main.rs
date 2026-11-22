//! Shore daemon entry point.
//!
//! Build the dependencies and call server.rs
//! Loads config, builds the device directory, then serves vessel connections with one
//! task each.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use noc_common::config::ShoreConfig;
use base64::Engine;
use noc_common::identity::{DeviceDirectory, StaticDirectory};
use noc_shore::cloudflare::CloudflareDirectory;
use noc_shore::session::Registry;
use tokio::net::TcpListener;

const MB: u64 = 1024 * 1024;
/// Dedup window size, sized around the vessel's in-flight window.
const EXPECTED_WINDOW: usize = 64;

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}

fn config_path() -> PathBuf {
    if let Some(arg) = std::env::args().nth(1) {
        return PathBuf::from(arg);
    }
    if let Ok(env) = std::env::var("NOC_SHORE_CONFIG") {
        return PathBuf::from(env);
    }
    PathBuf::from("/etc/noc/shore.toml")
}

/// Load the static device table. Keys use the same base64 the Devices API returns,
/// so entries can be pasted straight from it.
fn load_devices(path: &Path) -> Result<StaticDirectory> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading devices file {}", path.display()))?;
    let table: HashMap<String, String> =
        toml::from_str(&text).with_context(|| format!("parsing devices file {}", path.display()))?;
    let table_is_empty = table.is_empty();
    let mut dir = StaticDirectory::new();
    for (b64_key, vessel_id) in table {
        let spki = base64::engine::general_purpose::STANDARD
            .decode(b64_key.trim())
            .with_context(|| format!("device key for {vessel_id} is not valid base64"))?;
        dir.enroll(spki, vessel_id);
    }
    // An empty table would turn every vessel away, so refuse to start rather than run idle.
    if table_is_empty {
        anyhow::bail!(
            "devices file {} lists no vessels: add a line \"<public key>\" = \"<vessel id>\" per vessel",
            path.display()
        );
    }
    Ok(dir)
}

/// Read the API token from its file or the environment, never from the config.
fn load_cf_token(id: &noc_common::config::ShoreIdentityConfig) -> Result<String> {
    if let Some(path) = &id.api_token_file {
        let tok = std::fs::read_to_string(path)
            .with_context(|| format!("reading Cloudflare API token file {}", path.display()))?;
        return Ok(tok.trim().to_string());
    }
    if let Ok(tok) = std::env::var("NOC_CF_API_TOKEN") {
        return Ok(tok.trim().to_string());
    }
    anyhow::bail!(
        "cloudflare_account_id is set but no API token found: set api_token_file or NOC_CF_API_TOKEN"
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let path = config_path();
    let config = ShoreConfig::load(&path)
        .with_context(|| format!("loading shore config from {}", path.display()))?;
    let ingest = &config.shore.ingest;

    // Live lookup when an account is configured, otherwise the static table.
    let id = &config.shore.identity;
    let directory: Arc<dyn DeviceDirectory> = if let Some(account) = &id.cloudflare_account_id {
        let token = load_cf_token(id)?;
        let cf = CloudflareDirectory::connect(account.clone(), token)
            .await
            .context("initialising Cloudflare Devices directory")?;
        cf.spawn_refresh(Duration::from_secs(id.vessel_lookup_refresh_s));
        tracing::info!(
            account = %account,
            refresh_s = id.vessel_lookup_refresh_s,
            "vessel identity via live Cloudflare Devices API"
        );
        cf
    } else {
        // Validated: with no account id, devices_file is set.
        let devices = id.devices_file.as_deref().context("no devices_file")?;
        tracing::info!(devices_file = %devices.display(), "vessel identity via static devices file");
        Arc::new(load_devices(devices)?)
    };

    // Size mode flushes at the threshold; time mode has no size trigger at all.
    let flush_size_bytes = match ingest.mode {
        noc_common::config::FlushMode::Size => ingest.flush_size_mb as u64 * MB,
        noc_common::config::FlushMode::Time => 0,
    };
    let registry = Arc::new(Registry::new(
        &ingest.temp_dir,
        &ingest.ingest_dir,
        flush_size_bytes,
        EXPECTED_WINDOW,
    ));

    // In time mode one shore-wide sweep drives all flushing, outages included, so
    // connections do no downtime flush. Size mode has no sweep.
    if ingest.mode == noc_common::config::FlushMode::Time {
        let interval = Duration::from_secs(ingest.flush_interval_s);
        tokio::spawn(noc_shore::session::run_flush_sweep(
            registry.clone(),
            interval,
        ));
        tracing::info!(
            flush_interval_s = ingest.flush_interval_s,
            "time-mode periodic flush sweep started"
        );
    }

    // The status snapshot noc-console reads, in the service's runtime directory (systemd
    // sets $RUNTIME_DIRECTORY), rewritten every 250 ms via a temp file and a rename.
    {
        let dir = std::env::var_os("RUNTIME_DIRECTORY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| ingest.temp_dir.clone());
        let path = dir.join("status.json");
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tick.tick().await;
                let tmp = path.with_extension("json.tmp");
                if tokio::fs::write(&tmp, registry.status_json().await).await.is_ok() {
                    tokio::fs::rename(&tmp, &path).await.ok();
                }
            }
        });
    }

    let listener = TcpListener::bind(&config.shore.listen_addr)
        .await
        .with_context(|| format!("binding {}", config.shore.listen_addr))?;
    tracing::info!(
        listen = %config.shore.listen_addr,
        ingest_dir = %ingest.ingest_dir.display(),
        mode = ?ingest.mode,
        "shore daemon listening"
    );

    let downtime = Duration::from_secs(ingest.downtime_timeout_s);
    let keepalive = Duration::from_secs(config.shore.keepalive_interval_s);
    noc_shore::server::serve(
        listener,
        directory,
        registry,
        downtime,
        keepalive,
        ingest.mode,
    )
    .await
}
