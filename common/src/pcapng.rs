//! Parses pcapng blocks and validates them before passing them on.
//!
//! The ring buffer, chunking, storage and encryption layers all rely on
//! receiving complete blocks. This parser checks each block before passing
//! it to the next stage.
//!
//! Each block has the following structure:
//!
//! ```text
//! [Block Type: 4B][Block Total Length: 4B][Body ...][Block Total Length: 4B]
//! ```
//!
//! The total length appears at both the beginning and end of the block.
//! Both values must match and include the entire block. The length must
//! be at least 12 bytes and a multiple of 4.
//!
//! pcapng supports both little-endian and big-endian byte order. Each
//! section specifies its byte order in the Section Header Block (SHB),
//! using the Byte-Order Magic. This applies to all fields in the section,
//! including the SHB's own length.
//!
//! The parser checks the Byte-Order Magic to determine the correct byte
//! order. When a new SHB appears, it checks again to handle the new
//! section, which may use a different byte order.

/// SHB magic bytes are designed to work in either byte order.
pub const BLOCK_TYPE_SHB: u32 = 0x0A0D_0D0A;
/// Interface Description Block type.
pub const BLOCK_TYPE_IDB: u32 = 0x0000_0001;

/// Byte-order magic stored as a big-endian byte sequence.
const BOM_BE: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];
/// Byte-Order Magic stored as a little-endian byte sequence.
const BOM_LE: [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];

/// Smallest valid block: 4 bytes each for the type, length and trailing length.
const MIN_BLOCK_LEN: u32 = 12;

/// Maximum allowed block size. This prevents invalid or malicious length fields
/// from triggering large memory allocations before the full block is available.
pub const DEFAULT_MAX_BLOCK_LEN: u32 = 64 * 1024 * 1024;

/// Byte order used by the current pcapng section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Big,
    Little,
}

impl Endianness {
    fn read_u32(self, b: &[u8]) -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        match self {
            Endianness::Big => u32::from_be_bytes(arr),
            Endianness::Little => u32::from_le_bytes(arr),
        }
    }
}

/// A complete block stored as-is, including both length fields, so the original
/// bytes can be written back without serialising the block again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub block_type: u32,
    pub endianness: Endianness,
    pub data: Vec<u8>,
}

impl Block {
    pub fn is_section_header(&self) -> bool {
        self.block_type == BLOCK_TYPE_SHB
    }
    pub fn is_interface_description(&self) -> bool {
        self.block_type == BLOCK_TYPE_IDB
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// A block was received before the SHB, so its byte order is unknown.
    /// Every valid stream must begin with an SHB.
    #[error("data block encountered before any Section Header Block")]
    NoSectionHeader,
    /// The SHB contains an invalid byte-order magic value.
    #[error("invalid pcapng byte-order magic in section header block")]
    BadByteOrderMagic,
    /// The block length is below 12 bytes or is not a multiple of 4.
    #[error("invalid block total length {0} (must be >= 12 and a multiple of 4)")]
    InvalidLength(u32),
    /// The declared block length exceeds the configured limit.
    #[error("block total length {len} exceeds maximum {max}")]
    BlockTooLarge { len: u32, max: u32 },
    /// The leading and trailing block lengths do not match, indicating corruption.
    #[error("block total length fields disagree (leading {leading}, trailing {trailing})")]
    TrailingLengthMismatch { leading: u32, trailing: u32 },
}

/// Extracts complete blocks from a data stream.
///
/// Each read may contain part of a block, multiple blocks, or a block split
/// across several reads. `next_block` returns only complete, validated blocks,
/// while any remaining data is buffered until more bytes arrive.
#[derive(Debug)]
pub struct BlockParser {
    buf: Vec<u8>,
    /// Tracks the bytes already processed in `buf`. Using a cursor avoids
    /// shifting the buffer after each block, keeping compaction to a minimum.
    pos: usize,
    endianness: Option<Endianness>,
    max_block_len: u32,
}

impl Default for BlockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockParser {
    pub fn new() -> Self {
        Self::with_max_block_len(DEFAULT_MAX_BLOCK_LEN)
    }

    pub fn with_max_block_len(max_block_len: u32) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            endianness: None,
            max_block_len,
        }
    }

    /// Parses a block stream without a section header when the byte order is
    /// already known, such as when replaying a decrypted spill segment.
    pub fn with_endianness(endianness: Endianness) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            endianness: Some(endianness),
            max_block_len: DEFAULT_MAX_BLOCK_LEN,
        }
    }

    /// Byte order set by the most recent SHB, if one has been received.
    pub fn endianness(&self) -> Option<Endianness> {
        self.endianness
    }

    /// Number of buffered bytes still waiting to form a complete block.
    pub fn pending_bytes(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Add the newly received bytes to the internal buffer.
    pub fn feed(&mut self, data: &[u8]) {
        // Drop the consumed prefix before growing, so the buffer stays bounded by the
        // largest incomplete block rather than by total throughput.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Returns the next complete block. `Ok(None)` means more data is needed.
    pub fn next_block(&mut self) -> Result<Option<Block>, ParseError> {
        let avail = &self.buf[self.pos..];
        if avail.len() < 8 {
            return Ok(None);
        }

        // Check the byte order of the current block.
        let is_shb = avail[0..4] == BLOCK_TYPE_SHB.to_be_bytes()
            || avail[0..4] == BLOCK_TYPE_SHB.to_le_bytes();
        let endian = if is_shb {
            if avail.len() < 12 {
                return Ok(None); // Wait until the Byte-Order Magic is available.
            }
            if avail[8..12] == BOM_BE {
                Endianness::Big
            } else if avail[8..12] == BOM_LE {
                Endianness::Little
            } else {
                return Err(ParseError::BadByteOrderMagic);
            }
        } else {
            self.endianness.ok_or(ParseError::NoSectionHeader)?
        };

        let total_len = endian.read_u32(&avail[4..8]);
        if total_len < MIN_BLOCK_LEN || !total_len.is_multiple_of(4) {
            return Err(ParseError::InvalidLength(total_len));
        }
        if total_len > self.max_block_len {
            return Err(ParseError::BlockTooLarge {
                len: total_len,
                max: self.max_block_len,
            });
        }

        let total_len = total_len as usize;
        if avail.len() < total_len {
            return Ok(None); // Wait until the full block has arrived.
        }

        // The trailing length must match the leading one.
        let trailing = endian.read_u32(&avail[total_len - 4..total_len]);
        if trailing as usize != total_len {
            return Err(ParseError::TrailingLengthMismatch {
                leading: total_len as u32,
                trailing,
            });
        }

        let block_type = endian.read_u32(&avail[0..4]);
        let data = avail[..total_len].to_vec();

        // Update the parser state only after validation, allowing it to retry
        // when more data arrives if an earlier check fails.
        if is_shb {
            self.endianness = Some(endian);
        }
        self.pos += total_len;

        Ok(Some(Block {
            block_type,
            endianness: endian,
            data,
        }))
    }

    /// Discards buffered bytes until a possible Section Header Block (SHB) is found,
    /// allowing the reader to resume processing after a stream becomes misaligned.
    ///
    /// After a parsing error, the original byte positions can no longer be trusted.
    /// The SHB is the only block that can be identified independently because its
    /// type magic is the same in both byte orders. The following Byte-Order Magic
    /// and a valid block length provide additional checks to help locate the header.
    /// The search starts one byte after the beginning of the buffer to skip the block
    /// that caused the error.
    ///
    /// Returns `true` when a potential SHB is found at the start of the buffer.
    /// If no complete candidate is available, the buffer is reduced to a possible
    /// header prefix that could continue with the next feed. Call this method again
    /// after more data arrives.
    pub fn resync_to_next_section(&mut self) -> bool {
        // Byte order is set by the next section header, so parsing must wait until then.
        self.endianness = None;
        let avail = self.buf.len() - self.pos;
        for i in 1..avail {
            if section_header_at(&self.buf[self.pos + i..], self.max_block_len) {
                self.buf.drain(..self.pos + i);
                self.pos = 0;
                return true;
            }
        }
        // Retain only bytes that could form the start of a signature across reads.
        let keep = avail.min(SHB_SIGNATURE_LEN - 1);
        let cut = self.buf.len() - keep;
        self.buf.drain(..cut);
        self.pos = 0;
        false
    }
}

/// Minimum bytes needed to identify an SHB: type, length and Byte-Order Magic.
const SHB_SIGNATURE_LEN: usize = 12;

/// Checks whether `bytes` starts with a possible Section Header Block by
/// verifying its type magic, Byte-Order Magic and declared length.
fn section_header_at(bytes: &[u8], max_block_len: u32) -> bool {
    if bytes.len() < SHB_SIGNATURE_LEN {
        return false;
    }
    if bytes[0..4] != BLOCK_TYPE_SHB.to_be_bytes() && bytes[0..4] != BLOCK_TYPE_SHB.to_le_bytes() {
        return false;
    }
    let endian = if bytes[8..12] == BOM_BE {
        Endianness::Big
    } else if bytes[8..12] == BOM_LE {
        Endianness::Little
    } else {
        return false;
    };
    let len = endian.read_u32(&bytes[4..8]);
    len >= MIN_BLOCK_LEN && len.is_multiple_of(4) && len <= max_block_len
}

/// Checks whether the byte stream starts with an SHB, meaning it contains
/// its own section header rather than requiring one to be added.
pub fn starts_with_section_header(bytes: &[u8]) -> bool {
    section_header_at(bytes, DEFAULT_MAX_BLOCK_LEN)
}

/// Describes how a block affects a [`SessionHeader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderEvent {
    /// A fresh SHB opened a new section, resetting the cached header. On the vessel
    /// this means the interface list changed mid-session.
    NewSection,
    /// A header block (SHB or IDB) was appended to the current header.
    Extended,
    /// A non-header (data) block; the header is considered complete. Not stored.
    Passthrough,
}

/// Collects the section header (the SHB and its IDBs) for later reuse or
/// insertion at the start of a stream. It includes all header blocks at the
/// beginning of a section. The first data block marks the end of the header,
/// while a new SHB begins a new one.
#[derive(Debug, Default, Clone)]
pub struct SessionHeader {
    bytes: Vec<u8>,
    complete: bool,
}

impl SessionHeader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes the next parsed block. Header blocks are added to the cache
    /// until the first data block arrives. A new SHB starts a fresh cache.
    pub fn observe(&mut self, block: &Block) -> HeaderEvent {
        if block.is_section_header() {
            let had_content = !self.bytes.is_empty();
            self.bytes.clear();
            self.bytes.extend_from_slice(&block.data);
            self.complete = false;
            return if had_content {
                HeaderEvent::NewSection
            } else {
                HeaderEvent::Extended
            };
        }
        if block.is_interface_description() && !self.complete {
            self.bytes.extend_from_slice(&block.data);
            return HeaderEvent::Extended;
        }
        // A data block freezes the header.
        self.complete = true;
        HeaderEvent::Passthrough
    }

    /// Cached SHB and IDBs, ready to be added to a file or sent when a connection opens.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether an SHB has been captured yet.
    pub fn has_header(&self) -> bool {
        !self.bytes.is_empty()
    }
}
