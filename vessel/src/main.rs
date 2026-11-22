//! The vessel daemon's entry point: loads the config and signing key, then starts
//! the pipeline.

// Standard library: file paths.
use std::path::PathBuf;

// Error handling, plus the config and signing-key helpers from the common crate.
use anyhow::{Context, Result};
use noc_common::config::VesselConfig;
use noc_common::identity::{load_signing_key_pkcs8_der, VesselSigningKey};

/// Sets up logging for the vessel daemon.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Log level comes from RUST_LOG, and defaults to "info" if it isn't set.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}

/// Works out where the vessel config file is.
fn config_path() -> PathBuf {
    // 1. First command-line argument.
    if let Some(arg) = std::env::args().nth(1) {
        return PathBuf::from(arg);
    }
    // 2. The NOC_VESSEL_CONFIG environment variable.
    if let Ok(env) = std::env::var("NOC_VESSEL_CONFIG") {
        return PathBuf::from(env);
    }
    // 3. The default location.
    PathBuf::from("/etc/noc/vessel.toml")
}

/// Loads the vessel's P-256 signing key from the key file.
fn load_key(path: &std::path::Path) -> Result<VesselSigningKey> {
    let der = std::fs::read(path)
        .with_context(|| format!("reading identity key {}", path.display()))?;
    load_signing_key_pkcs8_der(&der)
        .with_context(|| format!("parsing PKCS#8 P-256 key from {}", path.display()))
}

/// The vessel daemon's entry point: loads config and key, then starts the pipeline.
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // Load the config (it gets checked as it loads), then the signing key.
    let path = config_path();
    let config = VesselConfig::load(&path)
        .with_context(|| format!("loading vessel config from {}", path.display()))?;
    let key = load_key(&config.identity.key_file)?;

    tracing::info!(
        interfaces = ?config.capture.interfaces,
        shore = %config.transport.shore_addr,
        ring_buffer_mb = config.ring_buffer.size_mb,
        "vessel daemon starting"
    );

    // Hand over to the pipeline. In practice this only returns if something goes wrong.
    noc_vessel::pipeline::run_vessel(config, key).await
}
