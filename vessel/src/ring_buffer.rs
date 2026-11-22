
// Imports HashMap and VecDeque. HashMap stores chunks by sequence number. 
// VecDeque is a queue that keeps blocks in first in first out order.
use std::collections::{HashMap, VecDeque};

//Imports Arc, which lets multiple async tasks safely share ownership of the same buffer and notification objects.
use std::sync::Arc;

//Imports Tokio Notify, which lets one async task wake another task that is waiting.
use tokio::sync::Notify;

// Imports Tokio Mutex, which makes sure only one async task changes the RingBuffer at a time.
use tokio::sync::Mutex;

// Creates FullPolicy, which decides what the buffer should do when there is not enough space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullPolicy {


    // Block mode means wait until space becomes available instead of losing the incoming data.
    Block,


    // Drop mode means discard the new block if there is not enough space.
    Drop,

}



/// Result of a successful [`RingBuffer::push_block`].

// Automatically adds useful Rust abilities such as printing for debugging, copying and comparing values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

// Creates a type that tells the caller what happened after trying to add a block.
pub enum PushOutcome {

    // Means the block was successfully stored in the buffer.
    Stored,

    /// Buffer was full under `FullPolicy::Drop`, so the block was discarded rather
    /// than stored. Means the disk spill could not keep up; the loss is accepted.

    // Means the block was dropped. It also records how many bytes were dropped.
    Dropped { bytes: usize },

}



// Makes PushError printable, comparable and usable as a normal Rust error type.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]

// Creates the possible errors that can happen when pushing a block.
pub enum PushError {

    /// Not enough free space. The async wrapper turns this into an await.

    // Sets the human readable error message for the WouldBlock error.
    #[error("ring buffer full, would block")]

    // Means Block mode has no free space right now, so the caller must wait.
    WouldBlock,

    /// A single block larger than the entire buffer can never be stored.

    // Sets the error message when one block is bigger than the whole buffer.
    #[error("block of {block} bytes exceeds ring buffer capacity {capacity}")]

    //   Stores the oversized block size and the total buffer capacity inside the error.
    BlockTooLarge { block: usize, capacity: usize },

}



/// Synchronous core. Wrap in [`SharedRingBuffer`] for concurrent use.

// Lets the RingBuffer be printed in debugging output.
#[derive(Debug)]

// Defines the main in memory ring buffer and all the values it needs to track.
pub struct RingBuffer {

    // Queue of complete network blocks that are waiting to be assembled into a chunk.
    pending: VecDeque<Vec<u8>>,

    // Tracks how many bytes are currently inside the pending queue.
    pending_bytes: usize,

    /// Bytes taken by the chunk assembler but not yet committed to a chunk.

    // Tracks bytes already removed from pending for chunk assembly but not yet committed as sent.
    checked_out_bytes: usize,

    /// Sent chunks awaiting their individual ACK, keyed by sequence number. The

    /// payload is retained verbatim so a timed-out chunk can be resent as-is.

    // Stores sent chunks that are still waiting for an ACK. The key is the chunk sequence number.
    inflight: HashMap<u64, Vec<u8>>,

    // Tracks the total number of bytes currently waiting for ACKs.
    inflight_bytes: usize,

    // Stores the maximum amount of memory this buffer is allowed to use.
    capacity_bytes: usize,

    // Stores whether this buffer should wait or drop when full.
    policy: FullPolicy,

}



// Starts the functions that belong to RingBuffer.
impl RingBuffer {

    // Constructor. Creates a new RingBuffer with the chosen capacity and full buffer policy.
    pub fn new(capacity_bytes: usize, policy: FullPolicy) -> Self {

        //  Starts filling in the fields of the new RingBuffer.
        Self {

            //  Starts with an empty pending queue.
            pending: VecDeque::new(),

            //  Starts with 0 pending bytes.
            pending_bytes: 0,

            //  Starts with 0 bytes being assembled.
            checked_out_bytes: 0,

            //  Starts with no sent chunks waiting for ACKs.
            inflight: HashMap::new(),

            //  Starts with 0 in flight bytes.
            inflight_bytes: 0,

            //  Stores the capacity value passed into new().
            capacity_bytes,

            //  Stores the full buffer policy passed into new().
            policy,

        
        }

    }



    /// Total bytes currently counted against the budget (all three states).

    //   Returns the total memory currently being used by all 3 buffer stages.
    pub fn used_bytes(&self) -> usize {

        //   Adds pending, checked out and in flight bytes together.
        self.pending_bytes + self.checked_out_bytes + self.inflight_bytes

    
    }

    //   Returns how many bytes are still available in the buffer.
    pub fn free_bytes(&self) -> usize {

        //   Subtracts used memory from capacity. saturating_sub prevents the number from going below 0.
        self.capacity_bytes.saturating_sub(self.used_bytes())

    
    }

    //   Returns the current number of pending bytes.
    pub fn pending_bytes(&self) -> usize {

        //   Gives back the pending_bytes value.
        self.pending_bytes

    
    }

    //   Returns the current number of bytes waiting for ACKs.
    pub fn inflight_bytes(&self) -> usize {

        //   Gives back the inflight_bytes value.
        self.inflight_bytes

    
    }




    /// Whether a `need`-byte push would have to wait for space.

    ///

    /// Lets the async wrapper check before handing over the block, so the common path

    /// moves it rather than cloning. False when waiting could not help anyway: an

    /// oversized block is unstorable, and a Drop-policy buffer never blocks.

    //   Checks whether a block of size need would have to wait before it can be stored.
    fn would_block(&self, need: usize) -> bool {

        //   First condition: this buffer must be using Block mode.
        self.policy == FullPolicy::Block

            //   Second condition: the block must be small enough to fit in the buffer eventually.
            && need <= self.capacity_bytes

            //   Third condition: the block is bigger than the free space available right now.
            && need > self.free_bytes()

    
    }



    /// Push one complete pcapng block. Honors this buffer's [`FullPolicy`] when full.

    //   Tries to add one complete block into the buffer and returns either an outcome or an error.
    pub fn push_block(&mut self, block: Vec<u8>) -> Result<PushOutcome, PushError> {

        //   Finds the size of the incoming block in bytes.
        let need = block.len();

        //   Checks whether this one block is bigger than the entire buffer.
        if need > self.capacity_bytes {

            //   Immediately returns a BlockTooLarge error.
            return Err(PushError::BlockTooLarge {

                //   Records the size of the block that was too large.
                block: need,

                //   Records the total capacity of the buffer.
                capacity: self.capacity_bytes,

            //   Finishes and returns that error value.
            });

        
        }



        //   Checks whether there is enough free memory for the block right now.
        if need <= self.free_bytes() {

            //   Adds the block size to the pending byte counter.
            self.pending_bytes += need;

            //   Places the block at the back of the pending queue so FIFO order is preserved.
            self.pending.push_back(block);

            //   Returns success and says the block was stored.
            return Ok(PushOutcome::Stored);

        
        }



        //   If there is not enough space, choose what to do based on the buffer policy.
        match self.policy {

            //   In Block mode, report WouldBlock so the async wrapper can wait for space.
            FullPolicy::Block => Err(PushError::WouldBlock),

            // Dropping beats back-pressuring dumpcap: the spill monitor should have

            // relieved the pressure already, so reaching here means the disk is behind.

            // In-flight data is untouched, so nothing gets duplicated across streams.

            //   In Drop mode, discard the new block and report how many bytes were dropped.
            FullPolicy::Drop => Ok(PushOutcome::Dropped { bytes: need }),

        
        }

    
    }



    /// Take the next pending block for chunk assembly. It stays counted against the

    /// budget as checked-out until it is committed into a chunk.

    //   Takes the oldest pending block for chunk assembly. Returns None if there is no block.
    pub fn take_block(&mut self) -> Option<Vec<u8>> {

        //   Removes the oldest block from the front. The ? returns None immediately if the queue is empty.
        let block = self.pending.pop_front()?;

        //   Removes this block size from the pending byte counter.
        self.pending_bytes -= block.len();

        //   Adds the same size to checked out bytes because the data is still using memory.
        self.checked_out_bytes += block.len();

        //   Returns the block to the chunk assembler.
        Some(block)

    
    }



    /// Move an assembled chunk into the in-flight set under `seq`. The payload stays

    /// resident for resend until its ACK arrives.

    //   Marks an assembled chunk as sent and waiting for its ACK.
    pub fn commit_chunk(&mut self, seq: u64, payload: Vec<u8>) {

        //   Runs a safety check in debug builds.
        debug_assert!(

            //   Checks that the committed payload is not larger than the amount that was checked out.
            payload.len() <= self.checked_out_bytes,

            //   Message shown if that debug safety check fails.
            "committing more bytes than were checked out"

        //   Ends the debug assertion.
        );

        //   Moves the payload size out of the checked out counter without allowing a negative value.
        self.checked_out_bytes = self.checked_out_bytes.saturating_sub(payload.len());

        //   Adds the payload size to the in flight counter.
        self.inflight_bytes += payload.len();

        //   Stores the sent payload using its sequence number so it can be ACKed or resent later.
        self.inflight.insert(seq, payload);

    
    }



    /// Borrow an in-flight chunk's payload for retransmission.

    //   Looks up an in flight chunk by sequence number without removing it.
    pub fn inflight_payload(&self, seq: u64) -> Option<&[u8]> {

        //   If the sequence exists, returns a read only byte slice of its payload. Otherwise returns None.
        self.inflight.get(&seq).map(|v| v.as_slice())

    
    }



    /// Release an in-flight chunk on its ACK. Returns bytes reclaimed, or `None` for

    /// an unknown seq (a duplicate ACK for an already-released chunk).

    //   Removes a sent chunk after its ACK arrives and returns the number of bytes freed.
    pub fn release_chunk(&mut self, seq: u64) -> Option<usize> {

        //   Removes the chunk with this sequence number. If it does not exist, return None.
        let payload = self.inflight.remove(&seq)?;

        //   Stores the size of the removed chunk in n.
        let n = payload.len();

        //   Subtracts the ACKed chunk size from in flight memory usage.
        self.inflight_bytes -= n;

        //   Returns the number of bytes that were freed.
        Some(n)

    
    }



    /// Drain one segment: the oldest pending blocks, whole, summing to at least

    /// `segment_size` (cut at a block boundary, so it may overshoot slightly). Empty if

    /// less than one full segment is pending, which leaves that remainder in the ring.


    /// The spill takes one segment at a time and seals it before (or while) taking the

    /// next, so only what is being sealed is ever out of the ring. Taking every segment

    /// at once held all of them in memory until the last was on disk.

    //   Removes the oldest pending blocks that make up one spill segment of at least segment_size bytes.
    pub fn drain_segment(&mut self, segment_size: usize) -> Vec<Vec<u8>> {

        //   Debug check that prevents an invalid segment size of 0.
        debug_assert!(segment_size > 0, "segment_size must be > 0");

        //   Creates an empty segment.
        let mut seg = Vec::new();

        //   Leaves everything in place unless a whole segment is pending.
        if self.pending_bytes < segment_size {

            //   Returns the empty segment.
            return seg;

        }

        //   Starts a counter for how many bytes have been added to this segment.
        let mut acc = 0usize;

        //   Keeps adding whole blocks until this segment reaches the required size.
        while acc < segment_size {

            // The guard above guarantees at least `segment_size` bytes remain.

            //   Removes the oldest pending block.
            let b = self
                .pending
                .pop_front()
                .expect("pending_bytes >= segment_size guarantees a block");

            //   Subtracts the removed block size from pending bytes.
            self.pending_bytes -= b.len();

            //   Adds this block size to the segment total.
            acc += b.len();

            //   Adds the whole block into the segment.
            seg.push(b);

        }

        //   Returns the segment.
        seg

    }



    /// Drain only the never-sent blocks.

    ///

    /// In-flight chunks are retained on purpose. They have already been sent, so on

    /// reconnect they go out again on their original stream and seq, where shore's

    /// watermark recognises them as duplicates. Replaying them cross-stream instead

    /// would defeat that per-stream watermark and duplicate data in Malcolm. This is

    /// what keeps a non-crash outage exactly 1:1.

    //   Removes and returns every block that has never been sent yet.
    pub fn drain_pending(&mut self) -> Vec<Vec<u8>> {

        //   Drains the whole pending queue and collects the blocks into a new vector.
        let out: Vec<Vec<u8>> = self.pending.drain(..).collect();

        //   Resets pending byte usage to 0 because all pending blocks were removed.
        self.pending_bytes = 0;

        //   Returns the drained blocks.
        out

    
    }



    /// Put blocks back at the front, in order, after a spill failed to write them.

    /// Returns how many would not fit and were dropped.

    ///

    /// Without this a failed write loses the data outright: the spill takes it out of

    /// the ring before writing, so an `ENOSPC` would discard everything it drained.

    /// Dropping what no longer fits is the ordinary tail-drop of a full ring,

    /// applied to the oldest data instead of the newest, which beats losing all of it.

    //   Tries to put previously drained blocks back at the front if a disk spill failed.
    pub fn return_blocks(&mut self, blocks: Vec<Vec<u8>>) -> usize {

        //   Starts a counter for blocks that cannot be returned because there is no space.
        let mut dropped = 0;

        //   Processes the drained blocks in reverse so push_front restores their original order.
        for block in blocks.into_iter().rev() {

            //   Checks whether this block can still fit in the available memory.
            if block.len() > self.free_bytes() {

                //   Counts this block as dropped because it no longer fits.
                dropped += 1;

                //   Skips the rest of this loop and moves to the next block.
                continue;

            
            }

            //   Adds the returned block size back to the pending byte counter.
            self.pending_bytes += block.len();

            //   Puts the block at the front of the pending queue.
            self.pending.push_front(block);

        
        }

        //   Returns how many blocks could not be restored.
        dropped

    
    }



    /// Puts chunks that were packed but never sent back at the front of the pending queue,
    /// oldest first, so an outage spill saves them too. A chunk is just whole blocks one
    /// after another, so it goes back as one entry and no block gets cut. Its bytes were
    /// counted as checked out, so they only move back to pending and nothing is dropped.
    /// Only use this for chunks that were never sent. A chunk with a sequence number is
    /// already in flight, and replaying it would give shore a duplicate.
    pub fn return_unsent(&mut self, chunks: Vec<Vec<u8>>) {
        for payload in chunks.into_iter().rev() {
            self.checked_out_bytes = self.checked_out_bytes.saturating_sub(payload.len());
            self.pending_bytes += payload.len();
            self.pending.push_front(payload);
        }
    }



    /// In-flight chunks for retransmission, in ascending sequence order. The order

    /// matters: shore takes the first sequence it sees on a fresh

    /// tracker as its lower bound, so resending out of order could strand the lower

    /// ones. The backing map has no order of its own, hence the explicit sort.

    //   Returns copies of all in flight chunks together with their sequence numbers.
    pub fn inflight_entries(&self) -> Vec<(u64, Vec<u8>)> {

        //   Starts building a new list from the current RingBuffer.
        let mut out: Vec<(u64, Vec<u8>)> = self

            //   Uses the in flight HashMap.
            .inflight

            //   Loops through each sequence number and payload without removing them.
            .iter()

            //   Turns each map entry into a tuple and clones the payload so the original stays in the buffer.
            .map(|(&seq, payload)| (seq, payload.clone()))

            //   Collects all those tuples into the output vector.
            .collect();

        // Sorts the output by sequence number from smallest to largest.
        out.sort_unstable_by_key(|(seq, _)| *seq);

        // Returns the drained blocks.
        out

    }

}



/// Async wrapper. Producers await space in Block mode, consumers await new blocks.


// Lets SharedRingBuffer be cheaply cloned. The clones still point to the same underlying buffer.
#[derive(Clone)]

// Defines the async safe wrapper around RingBuffer.
pub struct SharedRingBuffer {

    // Stores the RingBuffer behind Arc and Mutex so multiple async tasks can safely share it.
    inner: Arc<Mutex<RingBuffer>>,

    /// Signalled when space frees up, waking a blocked producer.

    // Notification used to wake producers when memory space becomes available.
    space: Arc<Notify>,

    /// Signalled when a block arrives, waking a waiting consumer.

    // Notification used to wake consumers when new pending data arrives.
    data: Arc<Notify>,


}



//  Starts the functions that belong to SharedRingBuffer.
impl SharedRingBuffer {

    //  Constructor. Creates a new RingBuffer with the chosen capacity and full buffer policy.
    pub fn new(capacity_bytes: usize, policy: FullPolicy) -> Self {

        //  Starts filling in the fields of the new RingBuffer.
        Self {

            //   Creates the RingBuffer and wraps it so it can be shared and locked safely.
            inner: Arc::new(Mutex::new(RingBuffer::new(capacity_bytes, policy))),

            //   Creates the notification object for free space.
            space: Arc::new(Notify::new()),

            //   Creates the notification object for newly available data.
            data: Arc::new(Notify::new()),

        //   Ends the current Rust block such as a function, enum, struct, loop or module.
        }

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// Push a block, awaiting space if the buffer is full in Block mode.

    /// `BlockTooLarge` returns immediately since waiting cannot help.

    ///

    /// The block is moved rather than cloned: `would_block` is checked under the same

    /// lock first, so we only hand it over once it is certain to be consumed. Every

    /// captured block passes through here, and the live buffer never blocks anyway, so

    /// a clone-then-retry structure would copy every block for a retry that can't

    /// happen.

    //   Async version of push_block. In Block mode it can wait until space is available.
    pub async fn push_block(&self, block: Vec<u8>) -> Result<PushOutcome, PushError> {

        //   Keeps retrying until the operation can finish.
        loop {

            // Register for the wakeup before checking, or we could miss a

            // notification that fires between the check and the await.

            //   Registers interest in the next free space notification before checking the buffer.
            let notified = self.space.notified();

            //   Starts a smaller scope so the Mutex lock can be released before waiting.
            {

                //   Waits for exclusive access to the inner RingBuffer and then locks it.
                let mut rb = self.inner.lock().await;

                //   If this block does not need to wait, try to push it now.
                if !rb.would_block(block.len()) {

                    //   Calls the normal RingBuffer push function and stores the result.
                    let outcome = rb.push_block(block);

                    //   Releases the Mutex lock early so other tasks can use the buffer.
                    drop(rb);

                    // Only wake consumers if something was actually stored; a

                    // tail-drop added nothing to take.

                    //   Checks whether the block was actually stored rather than dropped or rejected.
                    if matches!(outcome, Ok(PushOutcome::Stored)) {

                        //   Wakes tasks waiting for new data because a block is now available.
                        self.data.notify_waiters();

                    //   Ends the current Rust block such as a function, enum, struct, loop or module.
                    }

                    //   Returns the push result and ends this async function.
                    return outcome;

                //   Ends the current Rust block such as a function, enum, struct, loop or module.
                }

            //   Ends the current Rust block such as a function, enum, struct, loop or module.
            }

            //   If the buffer would block, sleep here until another task says space was freed.
            notified.await;

        //   Ends the current Rust block such as a function, enum, struct, loop or module.
        }

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// Take the next pending block, awaiting one if none are available.

    //   Async version of take_block. It waits if there is currently no pending block.
    pub async fn take_block(&self) -> Vec<u8> {

        //   Keeps retrying until the operation can finish.
        loop {

            //   Registers interest in the next new data notification.
            let notified = self.data.notified();

            //   Starts a smaller scope so the Mutex lock can be released before waiting.
            {

                //   Waits for exclusive access to the inner RingBuffer and then locks it.
                let mut rb = self.inner.lock().await;

                //   Tries to take a block. This branch runs only when a block exists.
                if let Some(block) = rb.take_block() {

                    //   Releases the Mutex lock early so other tasks can use the buffer.
                    drop(rb);

                    //   Wakes producers because moving a block may allow buffer work to continue.
                    self.space.notify_waiters();

                    //   Returns the block and ends the function.
                    return block;

                //   Ends the current Rust block such as a function, enum, struct, loop or module.
                }

            //   Ends the current Rust block such as a function, enum, struct, loop or module.
            }

            //   If the buffer would block, sleep here until another task says space was freed.
            notified.await;

        //   Ends the current Rust block such as a function, enum, struct, loop or module.
        }

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    //   Async safe wrapper that commits a chunk as in flight.
    pub async fn commit_chunk(&self, seq: u64, payload: Vec<u8>) {

        //   Locks the RingBuffer and calls its commit_chunk function.
        self.inner.lock().await.commit_chunk(seq, payload);

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// Release an in-flight chunk on ACK, waking anyone blocked on space.

    //   Async safe wrapper that releases an ACKed in flight chunk.
    pub async fn release_chunk(&self, seq: u64) -> Option<usize> {

        //   Locks the buffer, releases the sequence and stores how many bytes were freed.
        let freed = self.inner.lock().await.release_chunk(seq);

        //   Checks whether a chunk was actually found and removed.
        if freed.is_some() {

            //   Wakes producers because moving a block may allow buffer work to continue.
            self.space.notify_waiters();

        //   Ends the current Rust block such as a function, enum, struct, loop or module.
        }

        //   Returns Some(bytes) when memory was freed or None when that sequence was unknown.
        freed

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    //   Async safe function that returns total used memory.
    pub async fn used_bytes(&self) -> usize {

        //   Locks the inner buffer and reads used_bytes.
        self.inner.lock().await.used_bytes()

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    //   Async safe function that returns pending memory usage.
    pub async fn pending_bytes(&self) -> usize {

        //   Locks the inner buffer and reads pending_bytes.
        self.inner.lock().await.pending_bytes()

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// See [`RingBuffer::drain_segment`].

    //   Async safe version of draining one spill segment.
    pub async fn drain_segment(&self, segment_size: usize) -> Vec<Vec<u8>> {

        //   Locks the buffer and drains one segment.
        let out = self.inner.lock().await.drain_segment(segment_size);

        //   Checks whether any data was actually removed from the buffer.
        if !out.is_empty() {

            //   Wakes producers because moving a block may allow buffer work to continue.
            self.space.notify_waiters();

        //   Ends the current Rust block such as a function, enum, struct, loop or module.
        }

        //   Returns the drained blocks.
        out

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// Copy an in-flight chunk's payload for a resend, or `None` if its ACK already

    /// released it. The buffer owns the only copy, so this is the sole source.

    //   Gets a copy of an in flight payload so it can be resent.
    pub async fn inflight_payload_cloned(&self, seq: u64) -> Option<Vec<u8>> {

        //   Locks the buffer, finds the payload and copies it into a new Vec.
        self.inner.lock().await.inflight_payload(seq).map(|p| p.to_vec())

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// See [`RingBuffer::drain_pending`].

    //   Async safe version of removing all never sent pending blocks.
    pub async fn drain_pending(&self) -> Vec<Vec<u8>> {

        //   Locks the buffer and drains the pending queue.
        let out = self.inner.lock().await.drain_pending();

        //   Wakes producers because moving a block may allow buffer work to continue.
        self.space.notify_waiters();

        //   Returns the drained blocks.
        out

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// See [`RingBuffer::return_blocks`].

    /// The returned blocks are pending again, so this wakes [`take_block`](Self::take_block)
    /// like a push does. The chunk assembler can find the ring empty while a spill holds
    /// its blocks, and it then sleeps until data arrives; if capture has gone quiet, a
    /// return that did not wake it would leave those blocks unsent for good.

    //   Async safe version of putting failed spill blocks back into the buffer.
    pub async fn return_blocks(&self, blocks: Vec<Vec<u8>>) -> usize {

        //   Remembers how many blocks were handed back, to tell whether any were restored.
        let total = blocks.len();

        //   Locks the buffer and calls return_blocks.
        let dropped = self.inner.lock().await.return_blocks(blocks);

        //   Wakes tasks waiting for data if at least one block is pending again.
        if dropped < total {
            self.data.notify_waiters();
        }

        //   Returns how many blocks could not be restored.
        dropped

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// See [`RingBuffer::return_unsent`]. Wakes the chunk assembler, as a push does.
    pub async fn return_unsent(&self, chunks: Vec<Vec<u8>>) {
        if chunks.is_empty() {
            return;
        }
        self.inner.lock().await.return_unsent(chunks);
        self.data.notify_waiters();
    }



    /// See [`RingBuffer::inflight_entries`].

    //   Async safe function that returns sorted copies of all in flight chunks.
    pub async fn inflight_entries(&self) -> Vec<(u64, Vec<u8>)> {

        //   Locks the buffer and gets the in flight entries.
        self.inner.lock().await.inflight_entries()

    //   Ends the current Rust block such as a function, enum, struct, loop or module.
    }



    /// Wait until nothing is pending, checked-out or in-flight. The replay path uses

    /// this to know every chunk from a segment has been ACKed before deleting it.

    //   Waits until pending, checked out and in flight usage all become 0.
    pub async fn wait_until_empty(&self) {

        //   Keeps retrying until the operation can finish.
        loop {

            // Registers interest in the next free space notification before checking the buffer.
            let notified = self.space.notified();

            // Checks whether the entire buffer budget is now empty.
            if self.inner.lock().await.used_bytes() == 0 {

                // Ends the wait because there is no buffered data left.
                return;

            
            }

            // If the buffer would block, sleep here until another task says space was freed.
            notified.await;

        
        }

    
    }


}




//   Compiles the following test module only when Rust tests are being run.
