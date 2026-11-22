//! Identity handshake 
//! Vessel sends public key to shore
//! shore receive the public key and check the public key against its directory to find the "owner" of this public key
//! shore verified that public key exist and send a random nonce to the vessel
//! vessel then signs the nonce and shore verifies it against the key it solve
//! this then help to ensure that Integrity is achieved
//!
//! Signing is ECDSA P-256 with SHA-256, the same key the WARP client registers with
//! Cloudflare. 
//!

use std::collections::HashMap;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// Re-exported so downstream crates name the vessel key type without depending on
/// `p256` directly.
pub use p256::ecdsa::SigningKey as VesselSigningKey;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Fixed signature length: r and s, 32 bytes each.
pub const SIG_LEN: usize = 64;
pub const NONCE_LEN: usize = 32;
/// Upper bound on a public key read off the wire. P-256 SPKI is 91 bytes; this
/// bounds allocation against a hostile length prefix.
pub const MAX_PUBKEY_LEN: usize = 256;

const STATUS_OK: u8 = 1;
const STATUS_REJECT: u8 = 0;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("vessel public key is not enrolled")]
    NotEnrolled,
    #[error("shore rejected the vessel: not enrolled")]
    RejectedNotEnrolled,
    #[error("nonce signature verification failed")]
    BadSignature,
    #[error("shore rejected the vessel: bad signature")]
    RejectedBadSignature,
    #[error("malformed public key")]
    BadPublicKey,
    #[error("public key too large: {0} bytes")]
    PublicKeyTooLarge(u16),
    #[error("session id too large: {0} bytes")]
    SessionIdTooLarge(u16),
    #[error("session id is not valid UTF-8")]
    BadSessionId,
    #[error("session id has characters that are not allowed: {0:?}")]
    UnsafeSessionId(String),
    #[error("the directory resolved a vessel id that is not a safe name: {0:?}")]
    UnsafeVesselId(String),
    #[error("session header too large: {0} bytes")]
    HeaderTooLarge(u32),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Maps a device public key to a vessel id. [`StaticDirectory`] serves tests and
/// offline runs; production uses a cached table refreshed from the Cloudflare Devices
/// API with a live fallback on a miss.
#[async_trait::async_trait]
pub trait DeviceDirectory: Send + Sync {
    /// The vessel id enrolled for this key, or `None`. Async because a cache miss
    /// may trigger a live lookup; a hit returns immediately.
    async fn lookup(&self, pubkey_spki: &[u8]) -> Option<String>;
}

/// In-memory directory keyed on SPKI bytes, standing in for the Devices API.
#[derive(Debug, Default, Clone)]
pub struct StaticDirectory {
    map: HashMap<Vec<u8>, String>,
}

impl StaticDirectory {
    pub fn new() -> Self {
        Self::default()
    }
    /// Enroll an SPKI public key → vessel_id.
    pub fn enroll(&mut self, pubkey_spki: Vec<u8>, vessel_id: impl Into<String>) {
        self.map.insert(pubkey_spki, vessel_id.into());
    }
}

#[async_trait::async_trait]
impl DeviceDirectory for StaticDirectory {
    async fn lookup(&self, pubkey_spki: &[u8]) -> Option<String> {
        self.map.get(pubkey_spki).cloned()
    }
}

/// The SPKI public key bytes, as sent on the wire and keyed in the directory.
pub fn signing_key_spki(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_public_key_der()
        .expect("P-256 verifying key always encodes to SPKI")
        .as_bytes()
        .to_vec()
}

/// Load a signing key from PKCS#8 DER: the staged WARP key, or a generated one.
pub fn load_signing_key_pkcs8_der(der: &[u8]) -> Result<SigningKey, HandshakeError> {
    SigningKey::from_pkcs8_der(der).map_err(|_| HandshakeError::BadPublicKey)
}

/// Generate a fresh keypair. Provisioning helper.
pub fn generate_keypair() -> SigningKey {
    SigningKey::random(&mut rand_core::OsRng)
}

/// Serialise a signing key to PKCS#8 DER.
pub fn signing_key_to_pkcs8_der(key: &SigningKey) -> Vec<u8> {
    key.to_pkcs8_der()
        .expect("P-256 signing key always encodes to PKCS#8")
        .as_bytes()
        .to_vec()
}

async fn write_pubkey<S: AsyncWrite + Unpin>(io: &mut S, spki: &[u8]) -> Result<(), HandshakeError> {
    io.write_all(&(spki.len() as u16).to_be_bytes()).await?;
    io.write_all(spki).await?;
    Ok(())
}

async fn read_pubkey<S: AsyncRead + Unpin>(io: &mut S) -> Result<Vec<u8>, HandshakeError> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf);
    if len as usize > MAX_PUBKEY_LEN {
        return Err(HandshakeError::PublicKeyTooLarge(len));
    }
    let mut spki = vec![0u8; len as usize];
    io.read_exact(&mut spki).await?;
    Ok(spki)
}

/// Prove this vessel's identity to shore.
pub async fn client_handshake<S>(io: &mut S, key: &SigningKey) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Send public key (SPKI).
    write_pubkey(io, &signing_key_spki(key)).await?;
    io.flush().await?;

    // 2/3. Enrollment result + nonce.
    let mut status = [0u8; 1];
    io.read_exact(&mut status).await?;
    if status[0] != STATUS_OK {
        return Err(HandshakeError::RejectedNotEnrolled);
    }
    let mut nonce = [0u8; NONCE_LEN];
    io.read_exact(&mut nonce).await?;

    // 4. Sign the nonce (ECDSA P-256 / SHA-256).
    let sig: Signature = key.sign(&nonce);
    io.write_all(sig.to_bytes().as_slice()).await?;
    io.flush().await?;

    // 5. Verification result.
    io.read_exact(&mut status).await?;
    if status[0] != STATUS_OK {
        return Err(HandshakeError::RejectedBadSignature);
    }
    Ok(())
}

/// Verify a vessel and return the id the directory gave, never anything the vessel
/// claimed for itself.
pub async fn server_handshake<S>(
    io: &mut S,
    directory: &dyn DeviceDirectory,
) -> Result<String, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Receive the vessel's public key (SPKI).
    let spki = read_pubkey(io).await?;

    // 2. Directory lookup (by SPKI bytes).
    let vessel_id = match directory.lookup(&spki).await {
        Some(id) => id,
        None => {
            io.write_all(&[STATUS_REJECT]).await?;
            io.flush().await?;
            return Err(HandshakeError::NotEnrolled);
        }
    };
    // The id becomes a directory name and part of an ingest filename, so a
    // device named with a slash or `..` would write outside the intended tree. It
    // comes from Cloudflare or devices.toml rather than the vessel, so this is a
    // misconfiguration rather than an attack, but it is still rejected here.
    if !is_safe_name(&vessel_id) {
        io.write_all(&[STATUS_REJECT]).await?;
        io.flush().await?;
        return Err(HandshakeError::UnsafeVesselId(vessel_id));
    }
    let verifying_key =
        VerifyingKey::from_public_key_der(&spki).map_err(|_| HandshakeError::BadPublicKey)?;

    // 3. Send a fresh random nonce.
    io.write_all(&[STATUS_OK]).await?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    io.write_all(&nonce).await?;
    io.flush().await?;

    // 4/5. Receive and verify the signature (proof of private-key possession).
    let mut sig_bytes = [0u8; SIG_LEN];
    io.read_exact(&mut sig_bytes).await?;
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            io.write_all(&[STATUS_REJECT]).await?;
            io.flush().await?;
            return Err(HandshakeError::BadSignature);
        }
    };
    match verifying_key.verify(&nonce, &sig) {
        Ok(()) => {
            io.write_all(&[STATUS_OK]).await?;
            io.flush().await?;
            Ok(vessel_id)
        }
        Err(_) => {
            io.write_all(&[STATUS_REJECT]).await?;
            io.flush().await?;
            Err(HandshakeError::BadSignature)
        }
    }
}

/// Max session id accepted on the wire. Real ones are around 21 characters.
pub const MAX_SESSION_ID_LEN: usize = 64;

/// A per-boot session id. The random suffix keeps it unique even if the clock is
/// unsynced at boot, which happens when a vessel comes up before NTP.
///
/// This is metadata the vessel asserts, not an identity claim; identity is proven by
/// the handshake. It lets shore tell a reconnect from a reboot.
pub fn generate_session_id() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{ms:x}-{:08x}", rand::random::<u32>())
}

/// Send the session id, length-prefixed. Goes after the handshake, before the
/// header.
pub async fn write_session_id<S>(io: &mut S, session_id: &str) -> Result<(), HandshakeError>
where
    S: AsyncWrite + Unpin,
{
    let bytes = session_id.as_bytes();
    io.write_all(&(bytes.len() as u16).to_be_bytes()).await?;
    io.write_all(bytes).await?;
    io.flush().await?;
    Ok(())
}

/// Read the vessel's session id.
pub async fn read_session_id<S>(io: &mut S) -> Result<String, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_SESSION_ID_LEN {
        return Err(HandshakeError::SessionIdTooLarge(len as u16));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    let id = String::from_utf8(buf).map_err(|_| HandshakeError::BadSessionId)?;
    // Unlike the vessel id this is asserted by the vessel, and it too lands in an
    // ingest filename. Anything outside the safe set is refused rather than
    // rewritten, so two vessels can never be folded onto one name.
    if !is_safe_name(&id) {
        return Err(HandshakeError::UnsafeSessionId(id));
    }
    Ok(id)
}

/// Upper bound on a name used as a path component. Longer than any session id
/// (bounded separately on the wire) and generous for a device name.
pub const MAX_NAME_LEN: usize = 128;

/// Whether a string is safe to use as a single filesystem path component.
///
/// Deliberately narrow: ASCII letters, digits, `-`, `_` and `.`, non-empty, and never
/// `.` or `..` on their own. Real ids are hex with a dash, and vessel names in
/// the device list are short identifiers, so nothing legitimate is excluded.
pub fn is_safe_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.len() <= MAX_NAME_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Max header size accepted. Generous, but bounds allocation.
pub const MAX_SESSION_HEADER: u32 = 1024 * 1024;

/// Send the cached pcapng header, length-prefixed.
pub async fn write_session_header<S>(io: &mut S, header: &[u8]) -> Result<(), HandshakeError>
where
    S: AsyncWrite + Unpin,
{
    io.write_all(&(header.len() as u32).to_be_bytes()).await?;
    io.write_all(header).await?;
    io.flush().await?;
    Ok(())
}

/// Read the header the vessel sent.
pub async fn read_session_header<S>(io: &mut S) -> Result<Vec<u8>, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_SESSION_HEADER {
        return Err(HandshakeError::HeaderTooLarge(len));
    }
    let mut header = vec![0u8; len as usize];
    io.read_exact(&mut header).await?;
    Ok(header)
}
