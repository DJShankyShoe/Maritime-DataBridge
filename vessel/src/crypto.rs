//! Encrypts captured vessel data before saving it to disk.
//! Each segment gets its own DEK to encrypt the data.
//! The DEK is protected using ECDH with a KEK kept inside the TPM.
//! During replay, the TPM helps recover the DEK so the data can be decrypted.
//! It also checks that the encrypted file has not been changed or damaged.

// AES-256-GCM encrypts the data, P-256/ECDH helps protect the DEK, rand creates fresh values, and SHA-256
// create the wrapping key.
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NonZeroScalar, ProjectivePoint, PublicKey};
use rand::RngCore;
use sha2::{Digest as _, Sha256};
// Imports the KEK type and KEK ID from kek.rs for use in crypto.rs
use crate::kek::{Kek, KekId};

// Create a fixed 4 byte label called MAGIC, with the value NOCS
const MAGIC: &[u8; 4] = b"NOCS";

// These constants tell the program the fixed sizes of the different part inside the encrypted segment format.
const VERSION: u8 = 1;
const KEK_ID_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
// Wrapped DEK = 32-byte key ciphertext + 16-byte GCM tag.
const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
// Leading bytes needed to learn which KEK a segment used: magic, version, KEK id.
pub const KEK_ID_PREFIX_LEN: usize = 4 + 1 + KEK_ID_LEN;
// Uncompressed SEC1 P-256 point, as the TPM wants it for the exchange.
const EPH_PUB_LEN: usize = 65;
// Header: prefix(13) + eph_pub(65) + dek_nonce(12) + wrapped_dek(48) + seg_nonce(12).
const HEADER_LEN: usize =
    KEK_ID_PREFIX_LEN + EPH_PUB_LEN + NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN;

// Use the text NOCS-ecdh-wrap as a fixed label when making the wrapping key
const KDF_LABEL: &[u8] = b"NOCS-ecdh-wrap";
// Error handling
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("segment file too short or missing header")]
    TooShort,
    #[error("bad magic: not a NOC encrypted segment")]
    BadMagic,
    #[error("unsupported segment envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("authentication failed (truncated, corrupted, or wrong key)")]
    AuthFailed,
    #[error("the KEK's public key is not a valid P-256 point")]
    BadKekPublic,
    #[error("the ephemeral public key in the header is not a valid P-256 point")]
    BadEphemeralKey,
    #[error("KEK {0:016x} is not resident, so this segment can never be unwrapped")]
    UnknownKek(KekId),
    /// The TPM could not be reached or did not answer. Unlike every other variant this
    /// says nothing about the file: the same segment may open fine a moment later.
    #[error("the TPM could not complete the key exchange: {0}")]
    KekUnavailable(String),
}

impl CryptoError {
    /// Whether retrying the same segment later could succeed. Only an unreachable TPM
    /// qualifies; everything else is a property of the file or of which KEKs exist.
    pub fn is_transient(&self) -> bool {
        matches!(self, CryptoError::KekUnavailable(_))
    }
}

/// Why a KEK could not complete an exchange.
#[derive(Debug)]
pub enum KekFailure {
    /// No KEK with this id is resident. Permanent: nothing can open the segment.
    Missing,
    /// The TPM could not be reached or refused the request. Possibly transient.
    Unreachable(String),
}

/// Connects crypto.rs to the key manager in kek.rs
/// id: KekId --> tells the key manager which KEK to use.
/// eph_public: &[u8] --> gives it the temporary public key from the encrypted file
/// Result<[u8; 32], KekFailure> --> returns either the 32 byte shared secret or why not
pub trait KekStore {
    fn ecdh_z(&self, id: KekId, eph_public: &[u8]) -> Result<[u8; 32], KekFailure>;
}

// Makes a key to protect the DEK
// It takes the ECDH shared secret, the temporary public key, and the KEK ID, 
// mixes them together with SHA 256 and gets the new 32 bytes key
fn wrap_key_from(z: &[u8; 32], eph_public: &[u8], kek_id: KekId) -> [u8; KEY_LEN] {
    let mut h = Sha256::new();
    h.update(KDF_LABEL);
    h.update(z);
    h.update(eph_public);
    h.update(kek_id.to_be_bytes());
    let digest = h.finalize();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&digest);
    key
}

/// Bytes a sealed segment adds to its plaintext: the header in front and the GCM tag
/// behind. A caller that allocates the plaintext with this much spare capacity lets
/// [`seal`] build the file without reallocating.
pub const ENVELOPE_OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// Encrypts the segment and package.
/// Creates a new DEK, use it to encrypt the captured segment, then protects the DEK using the wrapping key.
/// It saves the encrypted data together with the info needed to decrypt it later.
/// The plaintext is taken by value and encrypted in place, and the header is put in front
/// of it in the same allocation, so a 32 MB segment is held once rather than once as
/// plaintext and twice more on its way to becoming the file.
pub fn seal(kek: &Kek, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mut rng = rand::thread_rng();
    // Check the KEK before doing any work on the data.
    let their = PublicKey::from_sec1_bytes(kek.public()).map_err(|_| CryptoError::BadKekPublic)?;

    // One data key per file, never reused.
    let mut dek = [0u8; KEY_LEN];
    rng.fill_bytes(&mut dek);

    // The whole file under one nonce and tag.
    let mut seg_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut seg_nonce);
    let mut body = plaintext;
    let t_enc = std::time::Instant::now();
    let tag = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek))
        .encrypt_in_place_detached(Nonce::from_slice(&seg_nonce), b"", &mut body)
        .expect("AES-GCM encryption is infallible for valid inputs");

    let enc_ms = t_enc.elapsed().as_millis() as u64;
    // Derive the key that wraps the data key, and the header bytes that go with it.
    let eph_secret = NonZeroScalar::random(&mut rng);
    let eph_public = PublicKey::from_secret_scalar(&eph_secret)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    // x of the shared point, as ECDH is defined. The ephemeral secret goes out of scope
    // here and is never written down.
    let shared = (ProjectivePoint::from(*their.as_affine()) * *eph_secret).to_affine();
    let mut z = [0u8; 32];
    z.copy_from_slice(&shared.x());
    let mut wrapping_key = wrap_key_from(&z, &eph_public, kek.id);
    z.fill(0);

    let mut dek_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut dek_nonce);
    let wrapped_dek = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key))
        .encrypt(Nonce::from_slice(&dek_nonce), dek.as_slice())
        .expect("AES-GCM encryption is infallible for valid inputs");
    debug_assert_eq!(wrapped_dek.len(), WRAPPED_DEK_LEN);
    // The DEK id is the first bytes of the wrapped DEK, which is in the segment header
    // anyway. It lets us match a segment's sealing to its replay without saying anything
    // about the key itself.
    tracing::info!(
        bytes = body.len(),
        aes_ms = enc_ms,
        dek = %dek_id(&wrapped_dek),
        kek = %format_args!("{:016x}", kek.id),
        eph = %format_args!("{:02x}{:02x}{:02x}{:02x}", eph_public[1], eph_public[2], eph_public[3], eph_public[4]),
        "segment encrypted: fresh DEK, AES-256-GCM, DEK wrapped by ephemeral ECDH"
    );
    dek.fill(0);
    wrapping_key.fill(0);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&kek.id.to_be_bytes());
    header.extend_from_slice(&eph_public);
    header.extend_from_slice(&dek_nonce);
    header.extend_from_slice(&wrapped_dek);
    header.extend_from_slice(&seg_nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);

    // The same allocation becomes the file: header in front, ciphertext, tag behind.
    // Reserving is free when the caller left ENVELOPE_OVERHEAD spare.
    body.reserve_exact(ENVELOPE_OVERHEAD);
    body.splice(0..0, header);
    body.extend_from_slice(&tag);
    Ok(body)
}

/// Decrypts the segment and recover
/// Reads the encrypted file, finds which KEK is needed, rebuild the wrapping key,
/// use it to recover the DEK, then uses the DEK to decrypt the original captured data.
pub fn open(keks: &dyn KekStore, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < KEK_ID_PREFIX_LEN {
        return Err(CryptoError::TooShort);
    }
    if &blob[0..4] != MAGIC {
        return Err(CryptoError::BadMagic);
    }
    let version = blob[4];
    // Read the id straight from the header, without gating on the version first: an
    // unsupported version has to be reported as such rather than as a bad header.
    let kek_id = u64::from_be_bytes(blob[5..13].try_into().expect("checked the length"));

    if version != VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    if blob.len() < HEADER_LEN {
        return Err(CryptoError::TooShort);
    }
    let mut off = KEK_ID_PREFIX_LEN;
    let eph_public = &blob[off..off + EPH_PUB_LEN];
    off += EPH_PUB_LEN;
    // A malformed point is the file's fault, so catch it here rather than let the TPM
    // refuse it and have that mistaken for the TPM being unavailable.
    PublicKey::from_sec1_bytes(eph_public).map_err(|_| CryptoError::BadEphemeralKey)?;
    // The only step that needs the chip: the KEK's private half never left it.
    let t_tpm = std::time::Instant::now();
    let mut z = keks.ecdh_z(kek_id, eph_public).map_err(|f| match f {
        KekFailure::Missing => CryptoError::UnknownKek(kek_id),
        KekFailure::Unreachable(msg) => CryptoError::KekUnavailable(msg),
    })?;
    let mut wrapping_key = wrap_key_from(&z, eph_public, kek_id);
    z.fill(0);
    let tpm_ms = t_tpm.elapsed().as_millis() as u64;

    let dek_nonce = &blob[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let wrapped_dek = &blob[off..off + WRAPPED_DEK_LEN];
    off += WRAPPED_DEK_LEN;
    let seg_nonce = &blob[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let ciphertext = &blob[off..];

    let unwrapped = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key))
        .decrypt(Nonce::from_slice(dek_nonce), wrapped_dek)
        .map_err(|_| CryptoError::AuthFailed);
    wrapping_key.fill(0);
    let mut dek = unwrapped?;
    if dek.len() != KEY_LEN {
        return Err(CryptoError::AuthFailed);
    }
    let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek))
        .decrypt(Nonce::from_slice(seg_nonce), ciphertext)
        .map_err(|_| CryptoError::AuthFailed);
    dek.fill(0);
    if plaintext.is_ok() {
        tracing::info!(
            bytes = ciphertext.len(),
            tpm_ms,
            dek = %dek_id(wrapped_dek),
            kek = %format_args!("{kek_id:016x}"),
            "segment decrypted: DEK unwrapped by the TPM, whole-file GCM tag verified"
        );
    }
    plaintext
}

/// A short, non-secret name for a segment's DEK: the first 4 bytes of its wrapped form.
fn dek_id(wrapped: &[u8]) -> String {
    wrapped.iter().take(4).map(|b| format!("{b:02x}")).collect()
}


