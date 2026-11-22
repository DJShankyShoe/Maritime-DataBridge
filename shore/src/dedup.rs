//! Per-stream duplicate detection
//!
//! When vessel sends data over to the shore, the data stream is splitted up into bytes of equal size and a tracker is placed at the shore side.
//! For every data stream that is received by the shore, the tracker will put in the SEQ value to ensure that the data stream bytes are received in the order of the original message.
//! The highest seq number will be placed as the watermark, such that if the tracker receive the same number as the watermark or any seq number lesser that the watermark, it will just drop the packet
//! If the tracker receive a packet that is not in sequence, but the seq number is higher than the watermark value, it will place the packet in window (a placeholder)
//! When the tracker find the missing seq number, the watermark value will then be updated to the highest value in the stream.
//!
//! Connection is TCP stream, so chunks arrive in send order
//!

use std::collections::BTreeSet;

/// Cap on remembered pre-baseline sequences. A vessel can only have
/// `max_in_flight_chunks` outstanding, so this is orders of magnitude more than a
/// well-behaved one needs, while keeping the tracker's memory bounded.
const MAX_BELOW_BASELINE: usize = 1024;

/// Whether a sequence is new (write it) or a duplicate (discard, but still ACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    New,
    Duplicate,
}

#[derive(Debug)]
pub struct DedupTracker {
    /// Highest contiguously-received sequence. `None` until the first chunk sets the
    /// baseline.
    watermark: Option<u64>,
    /// First sequence this tracker ever saw. The watermark only speaks for sequences
    /// at or above it.
    baseline: u64,
    /// Sequences seen below `baseline` (resends of chunks sent before this tracker
    /// started), so a second copy is still recognised. Capped, so memory stays flat.
    below: BTreeSet<u64>,
    /// Sequences above the watermark that are not yet contiguous.
    window: BTreeSet<u64>,
    /// Steady-state window size. Exceeding it is logged, not enforced.
    expected_window: usize,
}

impl DedupTracker {
    pub fn new(expected_window: usize) -> Self {
        Self {
            watermark: None,
            baseline: 0,
            below: BTreeSet::new(),
            window: BTreeSet::new(),
            expected_window,
        }
    }



    /// Classify and record `seq`, advancing the watermark as far as the window
    /// allows.
    pub fn observe(&mut self, seq: u64) -> Classification {
        match self.watermark {
            None => {
                // The first chunk sets the baseline.
                self.watermark = Some(seq);
                self.baseline = seq;
                Classification::New
            }
            Some(wm) => {
                if seq < self.baseline {
                    // Predates this tracker, so the watermark says nothing about it:
                    // judge it only on whether we have seen this exact sequence since.
                    if self.below.contains(&seq) {
                        return Classification::Duplicate;
                    }
                    if self.below.len() < MAX_BELOW_BASELINE {
                        self.below.insert(seq);
                    } else {
                        // Far more pre-baseline resends than any in-flight window can
                        // explain. Keep accepting (a duplicate beats a loss) but say so.
                        tracing::warn!(
                            seq,
                            baseline = self.baseline,
                            "pre-baseline sequence record is full; accepting without dedup"
                        );
                    }
                    return Classification::New;
                }
                if seq <= wm || self.window.contains(&seq) {
                    return Classification::Duplicate;
                }
                self.window.insert(seq);
                // Absorb any run that just became contiguous.
                while self.window.remove(&(self.watermark.unwrap() + 1)) {
                    self.watermark = Some(self.watermark.unwrap() + 1);
                }
                if self.window.len() > self.expected_window {
                    tracing::warn!(
                        window = self.window.len(),
                        expected = self.expected_window,
                        "dedup window larger than expected, many outstanding gaps"
                    );
                }
                Classification::New
            }
        }
    }
}
