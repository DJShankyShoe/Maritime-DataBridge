//! Manages the KEKs used by crypto.rs.
//! The KEK private key stay inside the TPM.
//! This file creates, loads, rotates, uses and removes KEKs when needed.

// Standard library tools for sets, formatting, string parsing, and shared thread-safe data
// HashSets -> unique IDs
// fmt -> debug output
// FromStr -> parse strings
// Arc -> shared ownership
// RwLock -> Safe shared reading/writing
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

// imports SHA 256 hashing, async locking and TPM types needed to create,
// read, use and remove KEKs and TPM Non volatile date
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use tss_esapi::attributes::{NvIndexAttributesBuilder, ObjectAttributesBuilder};
use tss_esapi::constants::{CapabilityType, NvIndexType};
use tss_esapi::handles::{KeyHandle, NvIndexTpmHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::structures::{
    CapabilityData, EccParameter, EccPoint, EccScheme, HashScheme,
    KeyDerivationFunctionScheme, MaxNvBuffer, NvPublicBuilder, Public, PublicBuilder,
    PublicEccParametersBuilder, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;
/// ID used to identify each KEK
pub type KekId = u64;

/// KEKs the TPM may hold at once, the current one included.
pub const SLOTS: u32 = 3;
/// Persistent handle of slot 0. The other slots follow it.
pub const HANDLE_BASE: u32 = 0x810A_0000;
/// Age at which the current KEK is replaced.
pub const ROTATE_AFTER_S: u64 = 24 * 60 * 60;

/// NV index holding slot 0's creation time; the other slots follow it. An ordinary
/// 8-byte index, owner-written and owner-readable, defined with its key and undefined
/// with it.
pub const NV_BASE: u32 = 0x0181_0A00;
// Bytes of creation time kept in an NV index.
const NV_TIME_LEN: usize = 8;

/// Uncompressed SEC1 point: 0x04 ‖ x(32) ‖ y(32).
pub const PUBLIC_LEN: usize = 65;
/// Lists of possible KEK related errors
/// Tpm(String) -> Something went wrong when communicating with the TPM
/// NoFreeSlot -> There is no empty TPM slot available for a new KEK
/// NotResident(KekId) -> The requested KEK is not currently stored in the TPM
/// Task(String) -> The background TPM worker task failed
#[derive(Debug, thiserror::Error)]
pub enum KekError {
    #[error("TPM {0}")]
    Tpm(String),
    #[error("no free TPM slot for a KEK: every slot holds an object that is not a vessel KEK")]
    NoFreeSlot,
    #[error("KEK {0:016x} is not resident in the TPM, so no segment of it can be unwrapped")]
    NotResident(KekId),
    #[error("TPM worker task failed: {0}")]
    Task(String),
}
// If a TPM operation fails, this function creates a readable KekError::Tpm message
fn tpm_err(op: &str, e: tss_esapi::Error) -> KekError {
    KekError::Tpm(format!("{op} failed: {e}"))
}

/// Kek stores the ID, creation time, TPM slot, and public key for one KEK. The private key never leaves the TPM
pub struct Kek {
    pub id: KekId,
    pub created_unix: u64,
    pub slot: u32,
    // The point to wrap against. The matching private half exists only in the chip.
    public: [u8; PUBLIC_LEN],
}

impl Kek {
 
    // Creates a KEK object from its public key, creation time and TPM slot
    fn from_public(slot: u32, created_unix: u64, public: [u8; PUBLIC_LEN]) -> Self {
        Self { id: id_from_public(&public), created_unix, slot, public }
    }

    /// Returns the KEK public key
    pub fn public(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }
}
// Control how kek is shown in debug output
impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only ever public material, but keep the shape of the output stable.
        f.debug_struct("Kek")
            .field("id", &format_args!("{:016x}", self.id))
            .field("created_unix", &self.created_unix)
            .field("slot", &self.slot)
            .finish()
    }
}

/// generates a unique KEK ID based on the KEK public key
pub fn id_from_public(public: &[u8]) -> KekId {
    let digest = Sha256::digest(public);
    u64::from_be_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
}

/// Says what is inside a TPM slot (Empty, ECDH and Foreign (something unrelated)
pub enum SlotRead {
    Empty,
    /// One of ours: its public point, and the creation time from the NV index beside it.
    Ecdh {
        public: [u8; PUBLIC_LEN],
        created_unix: u64,
    },
    /// Occupied by an object that is not ours, and is left alone.
    Foreign,
}

/// KekBackend is the interface used to read, create, use, and delete KEKs in the TPM
pub trait KekBackend: Send + Sync + 'static {
    /// Every slot, in order.
    fn read_slots(&self) -> Result<Vec<SlotRead>, KekError>;
    /// Create an ECDH KEK in an empty slot and record its creation time. Returns the
    /// public point; the private half stays inside the store.
    fn create_ecdh(&self, slot: u32, created_unix: u64) -> Result<[u8; PUBLIC_LEN], KekError>;
    /// Complete an ECDH exchange with the slot's private half, returning the shared
    /// x-coordinate. `eph_public` is an uncompressed SEC1 point.
    fn ecdh_z(&self, slot: u32, eph_public: &[u8]) -> Result<[u8; 32], KekError>;
    fn evict(&self, slot: u32) -> Result<(), KekError>;
}

/// TPMBackend stores the TPM connection settings and the base locations used for KEKs and Non volatile data
pub struct TpmBackend {
    tcti: TctiNameConf,
    base: u32,
    nv_base: u32,
}
// TpmBackend sets up the TPM connection, maps KEK slots to TPM handles, and store/removes each KEK's creation time in TPM NV storage.
impl TpmBackend {
    
    /// Creates a TPM backend using the normal Non volatile location
    pub fn new(tcti: &str, base: u32) -> Result<Self, KekError> {
        Self::with_nv_base(tcti, base, NV_BASE)
    }

    /// Creates a TPM backend with a custom non volatile location
    pub fn with_nv_base(tcti: &str, base: u32, nv_base: u32) -> Result<Self, KekError> {
        let tcti = TctiNameConf::from_str(tcti).map_err(|e| tpm_err("transport parse", e))?;
        Ok(Self { tcti, base, nv_base })
    }

    // Saves when a kek was created 
    fn write_nv_time(&self, index: u32, created_unix: u64) -> Result<(), KekError> {
        self.with_context("KEK time write", |ctx| ctx.execute_with_nullauth_session(|ctx| {
            let nv_index = NvIndexTpmHandle::new(index)?;
            let attrs = NvIndexAttributesBuilder::new()
                .with_owner_write(true)
                .with_owner_read(true)
                .with_nv_index_type(NvIndexType::Ordinary)
                .with_no_da(true)
                .build()?;
            let nv_public = NvPublicBuilder::new()
                .with_nv_index(nv_index)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attrs)
                .with_data_area_size(NV_TIME_LEN)
                .build()?;
            // An index left behind by an earlier key is reused rather than redefined, so
            // a half-finished eviction cannot block a mint.
            let nv_handle = if nv_present(ctx, index) {
                ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index))?.into()
            } else {
                ctx.nv_define_space(Provision::Owner, None, nv_public)?
            };
            let data = MaxNvBuffer::try_from(created_unix.to_be_bytes().to_vec())?;
            ctx.nv_write(NvAuth::Owner, nv_handle, data, 0)
        }))
    }
    // Removes the saved creation time
    fn undefine_nv(&self, index: u32) -> Result<(), KekError> {
        self.with_context("KEK time remove", |ctx| {
            if !nv_present(ctx, index) {
                return Ok(());
            }
            ctx.execute_with_nullauth_session(|ctx| {
            let nv_index = NvIndexTpmHandle::new(index)?;
            let handle = ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index))?;
            ctx.nv_undefine_space(Provision::Owner, handle.into())
            })
        })
    }
// Finds the real tpm handle for a slot
// Converts a simple slot number like 0,1,2 into actual tpm handles address
    fn handle(&self, slot: u32) -> Result<PersistentTpmHandle, KekError> {
        PersistentTpmHandle::new(self.base + slot).map_err(|e| tpm_err("handle", e))
    }
// Connects to the TPM, runs an operation and converts TPM errors into KekError
    fn with_context<T>(
        &self,
        op: &str,
        f: impl FnOnce(&mut Context) -> tss_esapi::Result<T>,
    ) -> Result<T, KekError> {
        let mut ctx = Context::new(self.tcti.clone()).map_err(|e| tpm_err("connect", e))?;
        f(&mut ctx).map_err(|e| tpm_err(op, e))
    }
}
// This is the real TPM implementation for reading KEK slots, creating KEKs, performing ECDH, and deleting KEKs
impl KekBackend for TpmBackend {
    // Checks what is in the TPM slots (Empty, ECDH, Foreign)
    fn read_slots(&self) -> Result<Vec<SlotRead>, KekError> {
        let base = self.base;
        let nv_base = self.nv_base;
        self.with_context("KEK slot read", |ctx| {
            // Handles come back in ascending order from `base`, so any in our range are
            // among the first SLOTS returned.
            // Queries go without a session: the null-auth session asks for parameter
            // encryption, which commands like GetCapability reject.
            let (caps, _) = ctx.execute_without_session(|ctx| ctx.get_capability(CapabilityType::Handles, base, SLOTS))?;
            let present: Vec<u32> = match caps {
                CapabilityData::Handles(list) => list.into_inner().into_iter().map(u32::from).collect(),
                _ => Vec::new(),
            };
            let mut slots = Vec::with_capacity(SLOTS as usize);
            for handle in base..base + SLOTS {
                if !present.contains(&handle) {
                    slots.push(SlotRead::Empty);
                    continue;
                }
                let slot = handle - base;
                let obj = ctx.tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(handle)?))?;
                let (public, _, _) = ctx.execute_without_session(|ctx| ctx.read_public(KeyHandle::from(obj)))?;
                match &public {
                    // A KEK of the current design: an unrestricted ECC decryption key.
                    Public::Ecc { parameters, unique, .. }
                        if public.object_attributes().decrypt()
                            && !public.object_attributes().restricted()
                            && public.object_attributes().no_da()
                            && parameters.ecc_curve() == EccCurve::NistP256 =>
                    {
                        match sec1_from_point(unique) {
                            Some(point) => {
                                // A missing time reads as 0, which only makes the KEK look
                                // old enough to rotate out, never unusable.
                                let created_unix = read_nv_time(ctx, nv_base + slot).unwrap_or(0);
                                slots.push(SlotRead::Ecdh { public: point, created_unix });
                            }
                            None => slots.push(SlotRead::Foreign),
                        }
                    }
                    _ => slots.push(SlotRead::Foreign),
                }
            }
            Ok(slots)
        })
    }
// Creates a new P-256 ECDH KEK inside the TPM, makes it persistent, stores its creation time, and returns only the public key.
    fn create_ecdh(&self, slot: u32, created_unix: u64) -> Result<[u8; PUBLIC_LEN], KekError> {
        let handle = self.handle(slot)?;
        let nv_index = self.nv_base + slot;
        let public = self.with_context("KEK create", |ctx| ctx.execute_with_nullauth_session(|ctx| {
            let parent = ctx
                .create_primary(Hierarchy::Owner, storage_parent_template()?, None, None, None, None)?
                .key_handle;
            // Nothing else flushes transient objects when there is no resource manager,
            // so flush them on every path.
            let created = (|| {
                let created = ctx.create(parent, ecdh_kek_template()?, None, None, None, None)?;
                let point = match &created.out_public {
                    Public::Ecc { unique, .. } => sec1_from_point(unique),
                    _ => None,
                };
                let loaded = ctx.load(parent, created.out_private, created.out_public)?;
                let persisted = ctx.evict_control(Provision::Owner, loaded.into(), Persistent::Persistent(handle));
                // The persistent copy is what counts; a failed flush of the loaded one
                // must not report a KEK that was created as lost.
                if let Err(e) = ctx.flush_context(loaded.into()) {
                    tracing::warn!(error = %e, "could not flush the loaded KEK object");
                }
                persisted?;
                Ok(point)
            })();
            if let Err(e) = ctx.flush_context(parent.into()) {
                tracing::warn!(error = %e, "could not flush the TPM storage parent");
            }
            created
        }))?;
        let public = public.ok_or_else(|| {
            KekError::Tpm("KEK create failed: the TPM returned no public point".into())
        })?;
        // The key is what matters; a creation time we fail to record only makes the KEK
        // look old, so it is logged rather than unwinding a key that already exists.
        if let Err(e) = self.write_nv_time(nv_index, created_unix) {
            tracing::warn!(slot, error = %e, "could not record the KEK's creation time in NV");
        }
        Ok(public)
    }
// Uses the private KEK inside the TPM together with the ephemeral public key to calculate the ECDH shared secret as 32 bytes.
    fn ecdh_z(&self, slot: u32, eph_public: &[u8]) -> Result<[u8; 32], KekError> {
        let handle = self.handle(slot)?;
        let point = point_from_sec1(eph_public).ok_or_else(|| {
            KekError::Tpm("KEK ecdh failed: ephemeral key is not an uncompressed P-256 point".into())
        })?;
        let z = self.with_context("KEK ecdh", |ctx| ctx.execute_with_nullauth_session(|ctx| {
            let obj = ctx.tr_from_tpm_public(TpmHandle::Persistent(handle))?;
            ctx.ecdh_z_gen(KeyHandle::from(obj), point)
        }))?;
        let x = z.x().value();
        // The TPM may drop leading zero bytes, so right-align into a fixed 32.
        if x.len() > 32 {
            return Err(KekError::Tpm(format!("KEK ecdh failed: shared x is {} bytes", x.len())));
        }
        let mut out = [0u8; 32];
        out[32 - x.len()..].copy_from_slice(x);
        Ok(out)
    }
// Deletes a KEK from its persistent TPM slot and removes its saved creation time from Non volatile storage
    fn evict(&self, slot: u32) -> Result<(), KekError> {
        let handle = self.handle(slot)?;
        let nv_index = self.nv_base + slot;
        self.with_context("KEK evict", |ctx| ctx.execute_with_nullauth_session(|ctx| {
            let obj = ctx.tr_from_tpm_public(TpmHandle::Persistent(handle))?;
            ctx.evict_control(Provision::Owner, obj, Persistent::Persistent(handle))?;
            Ok(())
        }))?;
        // The key is gone, so a leftover time is harmless; a slot that is reused will
        // overwrite it. Still worth clearing, and worth knowing when it fails.
        if let Err(e) = self.undefine_nv(nv_index) {
            tracing::warn!(slot, error = %e, "could not remove the KEK's creation-time NV index");
        }
        Ok(())
    }
}

// Checks if that non volatile storage location exists without causing unnecessary TPM error messages.
fn nv_present(ctx: &mut Context, index: u32) -> bool {
    let found = ctx.execute_without_session(|ctx| {
        ctx.get_capability(CapabilityType::Handles, index, 1)
    });
    match found {
        Ok((CapabilityData::Handles(list), _)) => {
            list.into_inner().into_iter().any(|h| u32::from(h) == index)
        }
        _ => false,
    }
}

// Looks for the Non volatile entry and if it exists and contain 8 bytes, converts those bytes back into the KEK creation time.
fn read_nv_time(ctx: &mut Context, index: u32) -> Option<u64> {
    if !nv_present(ctx, index) {
        return None;
    }
    let nv_index = NvIndexTpmHandle::new(index).ok()?;
    let handle = ctx
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index)))
        .ok()?;
    let data = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.nv_read(NvAuth::Owner, handle.into(), NV_TIME_LEN as u16, 0)
        })
        .ok()?;
    let bytes: [u8; NV_TIME_LEN] = data.value().try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

// Converts a TPM ECC public point into a 65 byte SEC1 format
fn sec1_from_point(point: &EccPoint) -> Option<[u8; PUBLIC_LEN]> {
    let (x, y) = (point.x().value(), point.y().value());
    if x.len() > 32 || y.len() > 32 || x.is_empty() || y.is_empty() {
        return None;
    }
    let mut out = [0u8; PUBLIC_LEN];
    out[0] = 0x04;
    out[1 + (32 - x.len())..33].copy_from_slice(x);
    out[33 + (32 - y.len())..65].copy_from_slice(y);
    Some(out)
}

// Converts a 65 byte SEC1 public key data back into a TPM ECC point
fn point_from_sec1(bytes: &[u8]) -> Option<EccPoint> {
    if bytes.len() != PUBLIC_LEN || bytes[0] != 0x04 {
        return None;
    }
    let x = EccParameter::try_from(bytes[1..33].to_vec()).ok()?;
    let y = EccParameter::try_from(bytes[33..65].to_vec()).ok()?;
    Some(EccPoint::new(x, y))
}

// Defines the TPM settings used to create the temporary storage-parent key.
fn storage_parent_template() -> tss_esapi::Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

// Defines the TPM settings used to create the ECDH key
// The private key is generated inside the TPM and cannot be exported
fn ecdh_kek_template() -> tss_esapi::Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(false)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Rotation tells the program whether ( no rotation was needed , a new KEK was created or rotation had to wait)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    NotDue,
    Rotated { new: KekId },
    /// Due, but no slot is free.
    Deferred,
}
// Resident stores all active KEKs and remembers which one is the current KEKs
struct Resident {
    keks: Vec<Arc<Kek>>,
    current: Arc<Kek>,
}

/// KekManager keeps track of the current KEK, all known KEKs, and handles changes like rotation and deletion
pub struct KekManager {
    backend: Arc<dyn KekBackend>,
    resident: RwLock<Resident>,
    // Held across anything that changes what the TPM holds.
    changes: Mutex<()>,
}

impl KekManager {
    /// Load the KEKs from the TPM/backend. If none exist, creates the first KEK
    pub async fn open(backend: Arc<dyn KekBackend>, now_unix: u64) -> Result<Self, KekError> {
        let b = backend.clone();
        let keks = blocking(move || load_or_mint(&*b, now_unix)).await?;
        Ok(Self::from_keks(backend, keks))
    }

    // Chooses the current kek
    fn from_keks(backend: Arc<dyn KekBackend>, keks: Vec<Kek>) -> Self {
        let keks: Vec<Arc<Kek>> = keks.into_iter().map(Arc::new).collect();
        // The newest is current; the slot number settles a tie, which only an unwritten
        // creation time can produce.
        let current = keks
            .iter()
            .max_by_key(|k| (k.created_unix, k.slot))
            .expect("at least one KEK")
            .clone();
        Self {
            backend,
            resident: RwLock::new(Resident { keks, current }),
            changes: Mutex::new(()),
        }
    }

    /// Returns the KEK used for new encrypted segments
    pub fn current(&self) -> Arc<Kek> {
        self.resident.read().unwrap().current.clone()
    }
    /// Finds a KEK by its ID
    pub fn get(&self, id: KekId) -> Option<Arc<Kek>> {
        self.resident.read().unwrap().keks.iter().find(|k| k.id == id).cloned()
    }
    /// Returns the IDs of all currently known KEKs
    pub fn ids(&self) -> Vec<KekId> {
        self.resident.read().unwrap().keks.iter().map(|k| k.id).collect()
    }

    /// Finds the correct KEK and ask the backend/TPM to perform ECDH
    pub fn ecdh_z_blocking(&self, id: KekId, eph_public: &[u8]) -> Result<[u8; 32], KekError> {
        let slot = self
            .resident
            .read()
            .unwrap()
            .keks
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.slot)
            .ok_or(KekError::NotResident(id))?;
        self.backend.ecdh_z(slot, eph_public)
    }

    /// Deletes old KEKs that are no longer needed by any stored segment
    pub async fn evict_unused(&self, in_use: &HashSet<KekId>) -> Result<Vec<KekId>, KekError> {
        let _changing = self.changes.lock().await;
        let unused: Vec<Arc<Kek>> = {
            let r = self.resident.read().unwrap();
            r.keks
                .iter()
                .filter(|k| k.id != r.current.id && !in_use.contains(&k.id))
                .cloned()
                .collect()
        };
        let mut evicted = Vec::with_capacity(unused.len());
        for kek in unused {
            let b = self.backend.clone();
            let slot = kek.slot;
            blocking(move || b.evict(slot)).await?;
            self.resident.write().unwrap().keks.retain(|k| k.id != kek.id);
            evicted.push(kek.id);
        }
        Ok(evicted)
    }

    /// Creates a new KEK when the current KEK is old enough and a slot is free
    pub async fn rotate_if_due(&self, now_unix: u64) -> Result<Rotation, KekError> {
        let _changing = self.changes.lock().await;
        let current_created = self.resident.read().unwrap().current.created_unix;
        if now_unix.saturating_sub(current_created) < ROTATE_AFTER_S {
            return Ok(Rotation::NotDue);
        }
        let b = self.backend.clone();
        let minted = blocking(move || {
            // Re-read rather than trust what we loaded at startup, in case another
            // object has since taken a slot.
            match free_slot(&b.read_slots()?) {
                Some(slot) => mint(&*b, slot, now_unix).map(Some),
                None => Ok(None),
            }
        })
        .await?;
        let Some(kek) = minted else {
            return Ok(Rotation::Deferred);
        };
        let kek = Arc::new(kek);
        let mut r = self.resident.write().unwrap();
        r.keks.push(kek.clone());
        r.current = kek.clone();
        Ok(Rotation::Rotated { new: kek.id })
    }
}
// It lets crypto.rs use KekManager to perform the ECDH operation wihtout needing to known the TPM details
impl crate::crypto::KekStore for KekManager {
    fn ecdh_z(&self, id: KekId, eph_public: &[u8]) -> Result<[u8; 32], crate::crypto::KekFailure> {
        use crate::crypto::KekFailure;
        self.ecdh_z_blocking(id, eph_public).map_err(|e| match e {
            // Not resident means the key is gone, which no retry can fix.
            KekError::NotResident(_) => KekFailure::Missing,
            // Anything else came from reaching the TPM, which may work next time.
            other => KekFailure::Unreachable(other.to_string()),
        })
    }
}
// blocking() runs a slow/blocking TPM task on a separate worker thread, waits for it to finish, and converts task failure into KekError
async fn blocking<T, F>(f: F) -> Result<T, KekError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, KekError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| KekError::Task(e.to_string()))?
}
// Finds the first empty TPM KEK slot
fn free_slot(slots: &[SlotRead]) -> Option<u32> {
    slots.iter().position(|s| matches!(s, SlotRead::Empty)).map(|i| i as u32)
}
// Creates a new ECDH KEK in the selected TPM slot
fn mint(backend: &dyn KekBackend, slot: u32, created_unix: u64) -> Result<Kek, KekError> {
    let public = backend.create_ecdh(slot, created_unix)?;
    Ok(Kek::from_public(slot, created_unix, public))
}
// Loads existing KEKs from the TPM
// If none exist , creates the first KEK in a free slot.
fn load_or_mint(backend: &dyn KekBackend, now_unix: u64) -> Result<Vec<Kek>, KekError> {
    let slots = backend.read_slots()?;
    let free = free_slot(&slots);
    let mut keks = Vec::new();
    for (slot, read) in slots.iter().enumerate() {
        let slot = slot as u32;
        match read {
            SlotRead::Empty => {}
            SlotRead::Ecdh { public, created_unix } => {
                keks.push(Kek::from_public(slot, *created_unix, *public))
            }
            SlotRead::Foreign => {
                tracing::warn!(slot, "TPM KEK slot holds an object that is not a vessel KEK; leaving it alone")
            }
        }
    }
    // If no vessel KEK exists, create the firest one in free slot
    // The program cannot start encryption without a TPM held KEK
    if keks.is_empty() {
        let slot = free.ok_or(KekError::NoFreeSlot)?;
        keks.push(mint(backend, slot, now_unix)?);
    }
    Ok(keks)
}
