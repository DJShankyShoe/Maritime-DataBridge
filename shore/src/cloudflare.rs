//! Vessel identity via the Cloudflare Zero Trust Devices API 
//!
//! Device generate a keypair locally. 
//! Device enroll itself into  cloudflared 
//! Cloudflare will not know the private key of the device, but will know the public key instead.
//! Cloudflare will store the device public key as SPKI (SubjectPublicKeyInfo) blob, in base64 encoding 
//! Cloudflare now have the device record, {key: "AAAA...", deviceID: "Vessel_01"}
//! This script will then be used by shore when the vessel sends its public key over and shore have to check who the public key belongs to
//!

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use noc_common::identity::DeviceDirectory;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const DEVICES_API_BASE: &str = "https://api.cloudflare.com/client/v4/accounts";

/// Cached directory, keyed on the device's SPKI bytes. The device name is used
/// directly as the vessel id.
pub struct CloudflareDirectory {
    account_id: String,
    token: String,
    http: reqwest::Client,
    map: RwLock<HashMap<Vec<u8>, String>>,
    /// When the miss path last called the API. Behind a mutex so concurrent misses
    /// serialise into one fetch instead of one each.
    last_miss_fetch: Mutex<Option<Instant>>,
}

/// Shortest gap between two miss-driven API calls. A miss happens before the vessel
/// has proved anything, so an unknown key must not be a lever on the Devices API: a
/// burst of connections with made-up keys costs one request, not one each. A genuinely
/// new vessel still resolves on its next connect, and the periodic refresh picks it up
/// regardless.
const MISS_FETCH_MIN_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct DevicesResponse {
    result: Vec<Device>,
    success: bool,
}

#[derive(Deserialize)]
struct Device {
    /// base64 SPKI of the device's P-256 public key.
    key: String,
    /// Device name, used as the vessel_id.
    name: String,
}

impl CloudflareDirectory {
    /// Build the directory, warming the cache before any vessel connects.
    pub async fn connect(account_id: String, token: String) -> Result<Arc<Self>> {
        let dir = Arc::new(Self {
            account_id,
            token,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("building Cloudflare HTTP client")?,
            map: RwLock::new(HashMap::new()),
            last_miss_fetch: Mutex::new(None),
        });
        let n = dir.refresh().await.context("initial Cloudflare devices refresh")?;
        tracing::info!(devices = n, "loaded vessel identities from Cloudflare Devices API");
        Ok(dir)
    }

    /// Fetch the full device list.
    async fn fetch(&self) -> Result<HashMap<Vec<u8>, String>> {
        let url = format!("{DEVICES_API_BASE}/{}/devices", self.account_id);
        let resp: DevicesResponse = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("Cloudflare Devices API request failed")?
            .error_for_status()
            .context("Cloudflare Devices API returned an error status")?
            .json()
            .await
            .context("parsing Cloudflare Devices API response")?;
        if !resp.success {
            anyhow::bail!("Cloudflare Devices API reported success=false");
        }
        let mut map = HashMap::new();
        for d in resp.result {
            match base64::engine::general_purpose::STANDARD.decode(d.key.trim()) {
                Ok(spki) => {
                    map.insert(spki, d.name);
                }
                Err(e) => tracing::warn!(device = %d.name, error = %e, "skipping device with unparseable key"),
            }
        }
        Ok(map)
    }

    /// Refresh the cache. Returns the device count.
    async fn refresh(&self) -> Result<usize> {
        let map = self.fetch().await?;
        let n = map.len();
        *self.map.write().await = map;
        // A full refresh is as good as a miss fetch, so it resets the throttle too.
        *self.last_miss_fetch.lock().await = Some(Instant::now());
        Ok(n)
    }

    /// Spawn the periodic refresh. Errors are logged and retried next tick, so a
    /// transient API outage never tears down a still-valid cache.
    pub fn spawn_refresh(self: &Arc<Self>, interval: Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await; // consume immediate tick (initial refresh already ran)
            loop {
                tick.tick().await;
                match this.refresh().await {
                    Ok(n) => tracing::debug!(devices = n, "refreshed Cloudflare devices cache"),
                    Err(e) => tracing::warn!(error = %e, "Cloudflare devices refresh failed; keeping cached table"),
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl DeviceDirectory for CloudflareDirectory {
    async fn lookup(&self, pubkey_spki: &[u8]) -> Option<String> {
        // The common case: a vessel we already know.
        if let Some(id) = self.map.read().await.get(pubkey_spki).cloned() {
            return Some(id);
        }
        // A miss may mean a vessel enrolled since the last refresh, so refresh and
        // re-check. If the API is unreachable we report unknown.
        let mut last = self.last_miss_fetch.lock().await;
        // Another miss may have fetched while we waited on the lock; that fetch would
        // have filled the cache, so look again before spending a request.
        if let Some(id) = self.map.read().await.get(pubkey_spki).cloned() {
            return Some(id);
        }
        if let Some(at) = *last {
            if at.elapsed() < MISS_FETCH_MIN_INTERVAL {
                tracing::debug!("unknown vessel key; miss-path lookup throttled");
                return None;
            }
        }
        *last = Some(Instant::now());
        match self.fetch().await {
            Ok(map) => {
                let hit = map.get(pubkey_spki).cloned();
                *self.map.write().await = map;
                if hit.is_some() {
                    tracing::info!("resolved a new vessel via live Cloudflare fallback");
                }
                hit
            }
            Err(e) => {
                tracing::warn!(error = %e, "Cloudflare cache-miss fallback lookup failed");
                None
            }
        }
    }
}
