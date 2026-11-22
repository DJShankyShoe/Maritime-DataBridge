//! Reading and writing the frames from framing.rs over a socket.
//! Shared by the vessel and shore so both sides use the same code.

// Tokio's async read and write helpers.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// The frame types and sizes from framing.rs.
use crate::framing::{
    AckFrame, ChunkHeader, FrameError, StreamType, ACK_FRAME_LEN, CHUNK_HEADER_LEN,
    MSG_TYPE_ACK, MSG_TYPE_KEEPALIVE,
};

/// Writes one chunk to the socket: the 13-byte header, then its payload.
pub async fn write_chunk<W>(
    w: &mut W,
    stream: StreamType,
    seq: u64,
    payload: &[u8],
) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    let header = ChunkHeader {
        stream,
        seq,
        len: payload.len() as u32,
    };
    w.write_all(&header.encode()).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// One fully received chunk: its header and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub header: ChunkHeader,
    pub payload: Vec<u8>,
}

/// Reads one complete chunk from the socket: the 13-byte header, then its payload.
/// Returns None if the other side closed cleanly between chunks.
pub async fn read_chunk<R>(r: &mut R, max_payload: u32) -> Result<Option<Chunk>, FrameError>
where
    R: AsyncRead + Unpin,
{
    // Read the 13-byte header first.
    let mut header_buf = [0u8; CHUNK_HEADER_LEN];
    match read_full_or_eof(r, &mut header_buf).await? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Filled => {}
    }
    let header = ChunkHeader::decode(&header_buf)?;

    // Check the length before allocating, so a bad header can't ask for gigabytes.
    if header.len > max_payload {
        return Err(FrameError::ChunkTooLarge {
            len: header.len,
            max: max_payload,
        });
    }

    // Then read exactly that many payload bytes.
    let mut payload = vec![0u8; header.len as usize];
    r.read_exact(&mut payload).await?; // errors if the connection closes mid-payload
    Ok(Some(Chunk { header, payload }))
}

/// Writes one 10-byte ACK frame to tell the vessel a chunk was received.
pub async fn write_ack<W>(w: &mut W, stream: StreamType, seq: u64) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&AckFrame { stream, seq }.encode()).await?;
    Ok(())
}


/// Writes a single keepalive byte to the vessel.
pub async fn write_keepalive<W>(w: &mut W) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&[MSG_TYPE_KEEPALIVE]).await?;
    Ok(())
}

/// A message from shore, either an ACK or a keepalive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMsg {
    Ack(AckFrame),
    Keepalive,
}

/// Holds a partly read message from shore between calls, so a read cancelled
/// inside select! can carry on where it stopped.
#[derive(Debug, Default)]
pub struct ServerMsgReader {
    buf: [u8; ACK_FRAME_LEN],
    filled: usize,
}

// Reading ACKs and keepalives from shore.
impl ServerMsgReader {
    /// Creates an empty reader.
    pub fn new() -> Self {
        Self {
            buf: [0u8; ACK_FRAME_LEN],
            filled: 0,
        }
    }

    /// Reads the next message from shore, either a keepalive or an ACK.
    pub async fn next<R>(&mut self, r: &mut R) -> Result<Option<ServerMsg>, FrameError>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            // Need the type byte first to know how long the message is.
            let need = if self.filled == 0 {
                1
            } else {
                match self.buf[0] {
                    MSG_TYPE_KEEPALIVE => 1,
                    MSG_TYPE_ACK => ACK_FRAME_LEN,
                    other => {
                        self.filled = 0;
                        return Err(FrameError::UnknownMessageType(other));
                    }
                }
            };

            // Have the whole message: decode it and reset for the next one.
            if self.filled >= need {
                let msg = match self.buf[0] {
                    MSG_TYPE_KEEPALIVE => ServerMsg::Keepalive,
                    _ => ServerMsg::Ack(AckFrame::decode(&self.buf)?),
                };
                self.filled = 0;
                return Ok(Some(msg));
            }

            // Not enough yet. Read only up to the end of this message, so we never
            // take bytes that belong to the next one.
            let n = r.read(&mut self.buf[self.filled..need]).await?;
            if n == 0 {
                if self.filled == 0 {
                    return Ok(None); // clean close between frames
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            self.filled += n;
        }
    }
}

/// How read_full_or_eof ended: the buffer was filled, or the connection closed cleanly.
enum ReadOutcome {
    Filled,
    Eof,
}

/// Fills a buffer completely, and reports whether the connection closed cleanly or mid-frame.
async fn read_full_or_eof<R>(r: &mut R, buf: &mut [u8]) -> Result<ReadOutcome, FrameError>
where
    R: AsyncRead + Unpin,
{
    // A read can return fewer bytes than asked for, so keep going until the buffer is full.
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;

        // 0 bytes means the other side closed. Fine if nothing was read yet,
        // an error if we were partway through a frame.
        if n == 0 {
            if filled == 0 {
                return Ok(ReadOutcome::Eof);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        filled += n;
    }
    Ok(ReadOutcome::Filled)
}
