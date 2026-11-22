//! Byte layouts for the vessel-to-shore wire protocol, with functions to encode and decode them.
//! Chunk (vessel to shore): [1B stream][4B payload length][8B seq][payload]
//! ACK (shore to vessel): [1B 0xAC][1B stream][8B seq]. Keepalive: [1B 0xCA]

// For the io::Error wrapped in FrameError::Io.
use std::io;

/// Size of a chunk header in bytes: stream (1) + length (4) + seq (8).
pub const CHUNK_HEADER_LEN: usize = 13;

/// Size of an ACK frame in bytes: message type (1) + stream (1) + seq (8).
pub const ACK_FRAME_LEN: usize = 10;

/// First byte of an ACK frame (shore to vessel).
pub const MSG_TYPE_ACK: u8 = 0xAC;

/// Keepalive frame (shore to vessel). Just this one byte, no body.
pub const MSG_TYPE_KEEPALIVE: u8 = 0xCA;

/// Which lane a chunk belongs to: Live or Replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    Live,
    Replay,
}

// Converting a StreamType to and from its wire byte.
impl StreamType {
    /// Converts a StreamType into its byte for sending: Live is 0, Replay is 1.
    pub fn as_byte(self) -> u8 {
        match self {
            StreamType::Live => 0,
            StreamType::Replay => 1,
        }
    }

    /// Converts a received byte back into a StreamType.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(StreamType::Live),
            1 => Some(StreamType::Replay),
            _ => None,
        }
    }
}

/// The three fields at the front of every chunk: stream, payload length and sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub stream: StreamType,
    pub seq: u64,
    /// Payload length in bytes.
    pub len: u32,
}

// Encoding and decoding the 13-byte chunk header.
impl ChunkHeader {
    /// Turns the header into its 13-byte wire form.
    pub fn encode(&self) -> [u8; CHUNK_HEADER_LEN] {
        let mut buf = [0u8; CHUNK_HEADER_LEN];
        buf[0] = self.stream.as_byte();
        buf[1..5].copy_from_slice(&self.len.to_be_bytes());
        buf[5..13].copy_from_slice(&self.seq.to_be_bytes());
        buf
    }

    /// Turns 13 received bytes back into a ChunkHeader.
    pub fn decode(buf: &[u8; CHUNK_HEADER_LEN]) -> Result<Self, FrameError> {
        let stream = StreamType::from_byte(buf[0]).ok_or(FrameError::UnknownStreamType(buf[0]))?;
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let seq = u64::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        Ok(ChunkHeader { stream, seq, len })
    }
}

/// A shore acknowledgement for one chunk: its stream and sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFrame {
    pub stream: StreamType,
    pub seq: u64,
}

// Encoding and decoding the 10-byte ACK frame.
impl AckFrame {
    /// Turns the ACK into its 10-byte wire form.
    pub fn encode(&self) -> [u8; ACK_FRAME_LEN] {
        let mut buf = [0u8; ACK_FRAME_LEN];
        buf[0] = MSG_TYPE_ACK;
        buf[1] = self.stream.as_byte();
        buf[2..10].copy_from_slice(&self.seq.to_be_bytes());
        buf
    }

    /// Turns 10 received bytes back into an AckFrame.
    pub fn decode(buf: &[u8; ACK_FRAME_LEN]) -> Result<Self, FrameError> {
        if buf[0] != MSG_TYPE_ACK {
            return Err(FrameError::UnknownMessageType(buf[0]));
        }
        let stream = StreamType::from_byte(buf[1]).ok_or(FrameError::UnknownStreamType(buf[1]))?;
        let seq = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        Ok(AckFrame { stream, seq })
    }
}

/// Every error that can happen while reading or writing a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("unknown stream-type byte {0}")]
    UnknownStreamType(u8),
    #[error("unknown message-type byte {0}")]
    UnknownMessageType(u8),
    #[error("chunk payload length {len} exceeds maximum {max}")]
    ChunkTooLarge { len: u32, max: u32 },
    #[error(transparent)]
    Io(#[from] io::Error),
}
