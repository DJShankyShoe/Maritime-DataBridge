//! On link-down, never-sent ring-buffer contents drain into segment files cut at
//! whole block boundaries, each sealed as a single AES-256-GCM envelope. The size is
//! a soft target: a file lands slightly above it, by whatever block tipped it over
//! plus the envelope overhead.
//!
//! On recovery each segment is decrypted and verified in one pass, then released
//! block by block into the replay buffer to be re-chunked and sent on REPLAY. A file
//! is deleted only once every chunk derived from it has been ACKed, which is enforced
//! by handling one segment at a time and waiting for the buffer to drain first.
//!
//! Segments carry packet blocks with no section header of their own, so a one-byte
//! endianness marker precedes the plaintext to let replay find block boundaries.


// Bring in HashSet, a collection that keeps each key ID only once.
use std::collections::HashSet;

// Bring in tools for input and output, plus reading and writing files.
use std::io::{self, Write};

// Bring in Path for a path reference and PathBuf for a path we can store.
use std::path::{Path, PathBuf};

// Bring in Arc so different tasks can share the same key manager safely.
use std::sync::Arc;

// Bring in the pcapng block reader and the setting for byte order.
use noc_common::pcapng::{BlockParser, Endianness};

//Use this project's encryption and decryption functions.
use crate::crypto;

//Use the types that identify and manage encryption keys.
use crate::kek::{KekId, KekManager};

//Use the shared ring buffer that holds blocks waiting for replay.
use crate::ring_buffer::SharedRingBuffer;

//Use .seg as the filename ending for completed segment files.
const SEGMENT_EXT: &str = "seg";


/// Extension for a segment set aside after repeated replay failures.
// Use .corrupt as the ending for files set aside for inspection.
const CORRUPT_EXT: &str = "corrupt";


/// Suffix of a segment still being written. Never listed and never replayed.
// Use .tmp to identify files that are still being written.
const STAGING_SUFFIX: &str = "tmp";

//Represent little endian byte order with the number 0.
const ENDIAN_LE: u8 = 0;

//Represent big endian byte order with the number 1.
const ENDIAN_BE: u8 = 1;

/// Manages segment files under a spill directory.
// Start defining the DiskBuffer structure that manages files on disk.
pub struct DiskBuffer { 
    
    // Store the directory where encrypted segments will be saved.
    spill_dir: PathBuf, 
    
    // Store the byte order used by the original packet blocks.
    endianness: Endianness, 
    
    /// Counter for segment filenames, so lexical order matches creation order.
    //Store the next number to include in a segment filename.
    next_index: u64, 
    
}
//Start defining what DiskBuffer can do.
impl DiskBuffer { 
    // Begin the constructor that creates a DiskBuffer.
    pub fn new(
        // Receive a folder path in any supported path-like form.
        spill_dir: impl AsRef<Path>, 
        // Receive the byte order to use when replaying these blocks later.
        endianness: Endianness, 
    // Return either a newly made DiskBuffer or a file-related error.
    ) -> io::Result<Self> { 
        // Convert the given folder path into a path value we can keep.
        let spill_dir = spill_dir.as_ref().to_path_buf(); 
        // Create the spill folder if needed, including parent folders; stop on error.
        std::fs::create_dir_all(&spill_dir)?; 
        // Sweep staging files a crash left behind. They are never published (only the
        // rename below does that) and never replayed, so they would otherwise sit in the
        // spill directory for good.
        //  Try deleting old unfinished files from an earlier run.
        match remove_stale_staging(&spill_dir) { 
            //If no old temporary files were removed, do nothing.
            Ok(0) => {} 
            // If some were removed, record their number in the log.
            Ok(n) => tracing::info!(files = n, "removed stale segment staging files"), 
            // If cleanup fails, log a warning but continue starting up.
            Err(e) => tracing::warn!(error = %e, "could not sweep stale segment staging files"), 
        
        }
        // Resume past anything a prior run left on disk.
        // Work out the next filename number by looking at existing segments.
        let next_index = list_segments(&spill_dir)? 
            // Go through the list of existing segment paths.
            .iter() 
            // Try extracting a number from each filename and ignore ones without one.
            .filter_map(|p| segment_index(p)) 
            // Find the largest valid segment number.
            .max() 
            // Make the next number one higher than that largest number.
            .map(|m| m + 1) 
            // If there are no valid numbers, start from 0.
            .unwrap_or(0); 
        //Start building the DiskBuffer object to return.
        Ok(Self { 
            // Save the folder path into the object.
            spill_dir, 
            // Save the byte order into the object.
            endianness, 
            // Save the next filename number into the object.
            next_index, 

        })

    }
    // Create a helper that turns byte order into a single marker byte.
    fn endian_byte(&self) -> u8 { 
        // Check which byte order was configured.
        match self.endianness { 
            // For little endian, return the marker 0.
            Endianness::Little => ENDIAN_LE, 
            // For big endian, return the marker 1.
            Endianness::Big => ENDIAN_BE, 
        } 
    } 





    /// Reserve the next segment number. Numbers follow the order data left the ring, so
    /// replay keeps that order even when two segments finish sealing out of order. A
    /// segment that then fails to write leaves a gap in the numbering, which is harmless.
    // Start a function that hands out the place on disk for the next segment.
    pub fn reserve(&mut self) -> SegmentSlot {
        // Build the slot with this buffer's folder, the next number and the byte order.
        let slot = SegmentSlot {
            // Copy the folder the segment will be written into.
            spill_dir: self.spill_dir.clone(),
            // Give the slot the next filename number.
            index: self.next_index,
            // Give the slot the byte-order marker its plaintext starts with.
            endian: self.endian_byte(),
        };
        // Move the counter on so the next slot gets the following number.
        self.next_index += 1;
        // Return the reserved slot.
        slot
    }

}




/// The place on disk for one segment: its folder, its number and the byte order of the
/// blocks it holds. It owns everything sealing needs, so sealing can run on the blocking
/// pool, two segments at a time, without borrowing the [`DiskBuffer`].
//  Start a structure describing where one segment will be written.
pub struct SegmentSlot {
    //  Store the folder the segment is written into.
    spill_dir: PathBuf,
    //  Store this segment's filename number.
    index: u64,
    //  Store the byte-order marker that starts the plaintext.
    endian: u8,
}

//  Start defining what a SegmentSlot can do.
impl SegmentSlot {
    /// This segment's number, which orders it for replay.
    //  Return the slot's filename number.
    pub fn index(&self) -> u64 {
        //  Give back the stored number.
        self.index
    }

    /// Encrypt a group of whole blocks into one segment file and publish it. Blocking
    /// (encryption, write and fsync): run it on the blocking pool.
    ///
    /// The group is copied once, behind the endianness marker, into a buffer with room
    /// for the envelope, which is then encrypted in place. On failure nothing is
    /// published and no staging file is left; the caller still holds the blocks.
    //  Start the function that turns one group of blocks into one encrypted file.
    pub fn seal(&self, blocks: &[Vec<u8>], keks: &KekManager) -> io::Result<PathBuf> {
        //  Work out how many bytes the plaintext needs: the marker plus every block.
        let len = 1 + blocks.iter().map(|b| b.len()).sum::<usize>();
        //  Make one buffer with room for the plaintext and the envelope around it.
        let mut plaintext = Vec::with_capacity(len + crypto::ENVELOPE_OVERHEAD);
        //  Start the plaintext with the byte-order marker.
        plaintext.push(self.endian);
        //  Copy each block in, in order.
        for b in blocks {
            //  Add this block's bytes to the end of the plaintext.
            plaintext.extend_from_slice(b);
        }
        //  Use the KEK that is current right now.
        let kek = keks.current();
        //  Encrypt the plaintext in place and wrap its data key under the KEK.
        let sealed = crypto::seal(&kek, plaintext)
            //  Turn a sealing error into a file error the caller can report.
            .map_err(|e| io::Error::other(format!("sealing a segment failed: {e}")))?;
        // The KEK id goes in the name so the retention scan can read it from a listing, and
        // the same rename that publishes the file applies it.
        //  Build the final segment filename from the number and the KEK id.
        let path = self
            //  Start from the spill folder.
            .spill_dir
            //  Add the filename.
            .join(format!("segment_{:012}_{:016x}.{SEGMENT_EXT}", self.index, kek.id));
        //  Build the staging name the file is written under first.
        let tmp = path.with_extension(format!("{SEGMENT_EXT}.{STAGING_SUFFIX}"));
        //  Write and sync the staging file, collecting any error.
        let staged = (|| -> io::Result<()> {
            //  Create the staging file.
            let mut f = std::fs::File::create(&tmp)?;
            //  Write every encrypted byte.
            f.write_all(&sealed)?;
            //  Make sure the bytes are on storage before the file is published.
            f.sync_all()
        })();
        //  Check whether writing the staging file failed.
        if let Err(e) = staged {
            // Leave nothing half-written behind for the next run to sweep.
            //  Try removing the incomplete staging file; ignore cleanup errors.
            let _ = std::fs::remove_file(&tmp);
            //  Return the original writing or syncing error.
            return Err(e);
        }
        //  Publish the file under its final name.
        std::fs::rename(&tmp, &path)?;
        tracing::info!(segment = self.index, bytes = sealed.len(), kek = %format_args!("{:016x}", kek.id), "segment written");
        // Persist the rename too, or a crash could leave the entry missing.
        //  Try opening the folder itself so its updated filename list can be synced.
        if let Ok(dir) = std::fs::File::open(&self.spill_dir) {
            //  Try syncing the folder to storage; ignore errors here.
            let _ = dir.sync_all();
        }
        //  Return the final path of the new segment.
        Ok(path)
    }
}

/// Bytes free for an unprivileged writer on the filesystem holding `dir`. The spill
/// checks this before taking a segment out of the ring, so a full disk costs nothing:
/// no encryption, no partial write that is deleted again.
//  Start a function that asks the filesystem how much space is left.
pub fn free_bytes(dir: &Path) -> io::Result<u64> {
    //  Bring in the helper that turns a path into raw bytes.
    use std::os::unix::ffi::OsStrExt;
    //  Make a C string of the path for the system call.
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: statvfs only writes into the struct we pass, which is plain data.
    //  Make an empty statvfs record for the system call to fill in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    //  Ask the kernel about the filesystem, and check for failure.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        //  Return the operating system's error.
        return Err(io::Error::last_os_error());
    }
    //  Free blocks available to non-root users times the block size.
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

/// Move a segment that will not decrypt out of the replay path, keeping its bytes for
/// inspection under a `.corrupt` name.
///
/// A segment that fails verification is rejected. If it stayed in place it would be
/// retried forever, and because [`kek_ids_in_use`] would still see it, its KEK would stay
/// in the TPM and could block key rotation.
//  Start a function to move a bad segment out of the normal replay list.
pub fn quarantine_segment(path: &Path) -> io::Result<PathBuf> {
    // Segment numbering restarts at 0 once the directory empties, and set-aside files are
    // invisible to that scan, so a fixed name would overwrite an earlier one's evidence.
    //  Prepare a new filename ending in .corrupt.
    let mut out = path.with_extension(CORRUPT_EXT);
    //  Start an extra filename number at 1 if there is a clash.
    let mut n = 1;
    //  Keep checking while that new filename already exists.
    while out.exists() {
        //  Use a numbered .corrupt filename to avoid overwriting an earlier file.
        out = path.with_extension(format!("{n}.{CORRUPT_EXT}"));
        //  Increase the extra number for the next attempt.
        n += 1;
    }
    //  Rename the segment to the chosen .corrupt filename.
    std::fs::rename(path, &out)?;
    //  Return the new path so the caller knows where the file went.
    Ok(out)

}



/// Delete leftover segment staging files under `dir`, returning how many went.
//  Start a helper that deletes abandoned .seg.tmp files.
fn remove_stale_staging(dir: &Path) -> io::Result<usize> {
    //  Start counting the files successfully deleted.
    let mut removed = 0;
    //  Visit each item in the given directory; stop if reading the directory fails.
    for entry in std::fs::read_dir(dir)? {
        //  Get the path of this directory item; stop if reading it fails.
        let path = entry?.path();
        //  First check whether its final extension is .tmp.
        let is_staging = path.extension().and_then(|e| e.to_str()) == Some(STAGING_SUFFIX)
            //  Also examine the path without that final .tmp ending.
            && path
                //  Get that shortened filename.
                .file_stem()
                //  Read the extension of that shortened filename.
                .and_then(|s| Path::new(s).extension())
                //  Convert the extension into readable text when possible.
                .and_then(|e| e.to_str())
                //  Require that extension to be .seg, making this a .seg.tmp file.
                == Some(SEGMENT_EXT);
        //  If it matches and deletion succeeds, count it as removed.
        if is_staging && std::fs::remove_file(&path).is_ok() {
            //  Increase the number of files that were deleted.
            removed += 1;
        }

    }
    //  Return the number of stale staging files that were deleted.
    Ok(removed)

}



/// Segment files under `dir`, oldest first.
//  Start a function that lists completed .seg files in a folder.
pub fn list_segments(dir: &Path) -> io::Result<Vec<PathBuf>> {
    //  Start an empty list for the segment file paths.
    let mut out = Vec::new();
    //  Check whether the folder does not exist.
    if !dir.exists() {
        //  If it does not exist, return an empty list without an error.
        return Ok(out);

    }
    //  Visit every item in the directory.
    for entry in std::fs::read_dir(dir)? {
        //  Get the current item's file path.
        let path = entry?.path();
        //  Check whether the item's file extension is exactly .seg.
        if path.extension().and_then(|e| e.to_str()) == Some(SEGMENT_EXT) {
            //  If so, add that path to the segment list.
            out.push(path);
  
        }

    }
    //  Sort file paths alphabetically, which matches order for numbered names.
    out.sort();
    //  Return the sorted list of segment paths.
    Ok(out)

}



/// Ids of the KEKs that segments on disk were sealed under. A KEK in this set must stay
/// in the TPM; any other KEK can be evicted.
///
/// The id comes from the filename (`segment_<index>_<kek id>.seg`), so the whole scan
/// is one directory read and opens nothing. The caller holds the spill lock during the
/// scan, and on a slow SD card opening every segment would hold up sealing for a while. The name is
/// applied by the same rename that publishes the file, so it can never disagree with the
/// envelope inside: a crash leaves either an unpublished `.seg.tmp` (swept at startup,
/// never scanned) or a complete file under its final name.
///
/// A `.seg` whose name carries no id is not something this daemon wrote. It is logged and
/// pins nothing: we cannot make up an id for it, and one unexplained file holding a TPM
/// slot for good would block key rotation. Replay still
/// reads such a file's own header, so if its KEK happens to still be resident it opens;
/// the warning is there because nothing guarantees that.
//  Start a function that discovers which encryption keys saved files still need.
pub fn kek_ids_in_use(dir: &Path) -> io::Result<HashSet<KekId>> {
    //  Start an empty set of key IDs, with no duplicates allowed.
    let mut ids = HashSet::new();
    //  Visit each completed segment found in the folder.
    for path in list_segments(dir)? {
        //  Read the sealing key's id straight out of the filename.
        match segment_kek_id(&path) {
            //  Remember the ID so the key can be kept for future decryption.
            Some(id) => {
                //  Add it to the set, which ignores a key already listed.
                ids.insert(id);

            }
            //  A name without an id is unexpected, so say so and hold no key for it.
            None => tracing::warn!(
                //  Name the file that could not be accounted for.
                segment = %path.display(),
                //  Explain what was wrong with it and what follows from that.
                "segment filename carries no KEK id; it pins no KEK, so the key it needs may be evicted before it replays"
            ),

        }

    }
    //  Return the set of key IDs the segments on disk need.
    Ok(ids)

}



/// The number and the KEK id in a segment filename, as text: `segment_<index>_<kek id>`
/// gives both, and a name this daemon did not write may give only the number.
//  Start a helper that splits a segment filename into its two parts.
fn segment_name_parts(path: &Path) -> Option<(&str, Option<&str>)> {
    //  Get the filename without its extension, or stop with None.
    let stem = path
        //  Take the part of the name before the final .seg.
        .file_stem()?
        //  Convert the filename to text, or stop with None if it cannot.
        .to_str()?
        //  Remove the required segment_ prefix, or stop with None if absent.
        .strip_prefix("segment_")?;
    //  Split at the underscore that separates the number from the key id.
    Some(match stem.split_once('_') {
        //  One of our names yields the number and the key id after it.
        Some((index, kek)) => (index, Some(kek)),
        //  A name with no underscore is the number alone, with no key id to report.
        None => (stem, None),

    })

}



//  Start a helper that tries to find the number inside a segment filename.
fn segment_index(path: &Path) -> Option<u64> {
    //  Split the name up, keeping only the number before any key id.
    let (index, _) = segment_name_parts(path)?;
    //  Try converting that text into a number, giving None if it is not one.
    index.parse().ok()

}



/// The id of the KEK a segment was sealed under, taken from its filename. `None` if the
/// name has no id, or one that is not 16 hex digits, since this daemon never writes
/// names like that.
//  Start a helper that reads the sealing key's id out of a segment filename.
fn segment_kek_id(path: &Path) -> Option<KekId> {
    //  Split the name up and require the key-id part to be present.
    let (_, kek) = segment_name_parts(path)?;
    //  Take that part, or stop with None if the name has no key id.
    let kek = kek?;
    //  Insist on exactly the 16 hex digits a 64-bit id is written as, so a name that
    //  merely happens to contain an underscore is not read as an id.
    if kek.len() != 16 || !kek.bytes().all(|b| b.is_ascii_hexdigit()) {
        //  Report no id, so the caller holds no key on this file's behalf.
        return None;

    }
    //  Read those digits as a hexadecimal number, giving None if they do not parse.
    KekId::from_str_radix(kek, 16).ok()

}



/// Why a segment could not be replayed, which decides what the replay driver does next.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The segment cannot be processed right now: the TPM did not answer, or the file
    /// could not be read. Its data is intact, so it is kept and tried again later.
    #[error("segment {0} is unavailable for now: {1}")]
    Unavailable(PathBuf, String),
    /// The segment itself is unusable: it failed verification, is malformed, or names a
    /// KEK that no longer exists. Retrying cannot help.
    #[error("segment {0} was rejected: {1}")]
    Rejected(PathBuf, String),
}

/// Replay one segment: decrypt, verify, release its blocks, wait for shore to ACK
/// everything derived from it, then delete it.
///
/// Only one segment is in flight at a time, so an empty replay buffer means this
/// segment's chunks have all been ACKed and it is safe to unlink.
//  Start an async function that replays one segment and deletes it after drain.
pub async fn replay_segment(
    //  Receive the path of the encrypted segment file.
    path: &Path,
    //  Receive the shared manager that can decrypt the segment.
    keks: &Arc<KekManager>,
    //  Receive the shared buffer that will hold replayed blocks.
    replay_buf: &SharedRingBuffer,
//  Return success, or whether the failure is worth retrying.
) -> Result<(), ReplayError> {
    //  Errors that leave the file intact and may clear up by themselves.
    let unavailable = |why: String| ReplayError::Unavailable(path.to_path_buf(), why);
    //  Errors that say the file itself can never be replayed.
    let rejected = |why: String| ReplayError::Rejected(path.to_path_buf(), why);
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    tracing::info!(segment = %name, "replaying segment");
    crate::status::STATS.set_replaying(&name);
    //  Read the whole encrypted file into memory; a read failure is not the file's fault.
    let blob = tokio::fs::read(path).await.map_err(|e| unavailable(e.to_string()))?;
    // Both halves of this block: a v3 unwrap is a TPM round trip, and the bulk decrypt
    // of a 32 MB segment is itself too long to sit on an async worker.
    //  Clone the shared manager so a background worker can use it.
    let keks = keks.clone();
    //  Decrypt and verify the whole file on a worker for blocking work.
    let plaintext = tokio::task::spawn_blocking(move || crypto::open(&*keks, &blob))
        //  Wait for the worker; a worker that died says nothing about the file.
        .await
        .map_err(|e| unavailable(format!("decrypt task failed: {e}")))?
        //  Only an unreachable TPM is worth waiting for; any other failure is the file's.
        .map_err(|e| {
            if e.is_transient() {
                unavailable(e.to_string())
            } else {
                rejected(format!("failed to decrypt/verify: {e}"))
            }
        })?;
    //  Check whether decryption returned zero bytes.
    if plaintext.is_empty() {
        //  Stop with an error if the decrypted data is empty.
        return Err(rejected("decrypted to empty plaintext".into()));
    }
    //  Read the first byte and decide which byte order the blocks use.
    let endianness = match plaintext[0] {
        //  Marker 0 means little endian.
        ENDIAN_LE => Endianness::Little,
        //  Marker 1 means big endian.
        ENDIAN_BE => Endianness::Big,
        //  Any other marker is invalid, so stop with an error.
        other => return Err(rejected(format!("bad endianness marker {other}"))),
    };
    // Re-parse the headerless stream and release whole blocks. push_block
    // back-pressures; the buffer is sized above one segment plus its overshoot.
    //  Make a block parser that uses the correct byte order.
    let mut parser = BlockParser::with_endianness(endianness);
    //  Give it everything except the first marker byte.
    parser.feed(&plaintext[1..]);
    //  Keep asking the parser for complete blocks until none remain.
    while let Some(block) = parser.next_block().map_err(|e| rejected(e.to_string()))? {
        //  Add this whole parsed block into the replay buffer, waiting if it is full.
        replay_buf
            .push_block(block.data)
            .await
            .map_err(|e| rejected(format!("replay buffer rejected a block: {e}")))?;
    }
    //  Check whether the parser still has leftover bytes.
    if parser.pending_bytes() != 0 {
        //  An incomplete final block means the segment is damaged.
        return Err(rejected(format!(
            "trailing partial block ({} bytes), corrupt",
            parser.pending_bytes()
        )));
    }

    tracing::info!(bytes = plaintext.len(), "segment queued on REPLAY");
    // Delete only once every derived chunk has been ACKed.
    //  Wait until the shared replay buffer is completely drained.
    replay_buf.wait_until_empty().await;
    //  Only then delete the encrypted segment file from disk.
    tokio::fs::remove_file(path).await.map_err(|e| unavailable(e.to_string()))?;
    //  Log that the segment finished replaying and was deleted.
    tracing::info!(segment = %path.display(), "replay segment fully ACKed and deleted");
    crate::status::STATS.set_replaying("");
    //  Return success.
    Ok(())
}







//  Compile the following test module only when running tests.
