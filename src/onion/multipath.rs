use std::collections::BTreeMap;

/// Payload size for our multi-path cells.
/// We reserve 8 bytes for the 64-bit multi-path sequence number,
/// leaving the rest for the actual payload.
pub const MULTIPATH_HEADER_SIZE: usize = 8;

pub struct MultiPathSlicer {
    next_seq: u64,
}

impl Default for MultiPathSlicer {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiPathSlicer {
    pub fn new() -> Self {
        Self { next_seq: 0 }
    }

    /// Takes a chunk of data, assigns it the next multi-path sequence number,
    /// and returns the sequence number and the encapsulated payload.
    pub fn slice(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        let seq = self.next_seq;
        self.next_seq += 1;

        out[0..8].copy_from_slice(&seq.to_be_bytes());
        let len = data.len();
        out[8..8 + len].copy_from_slice(data);
        8 + len
    }
}

pub struct MultiPathReassembler {
    next_expected_seq: u64,
    // Buffer for out-of-order packets. Maps sequence number to data.
    buffer: BTreeMap<u64, Vec<u8>>,
}

impl Default for MultiPathReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiPathReassembler {
    pub fn new() -> Self {
        Self {
            next_expected_seq: 0,
            buffer: BTreeMap::new(),
        }
    }

    /// Receives a packet with a multi-path header.
    /// Returns the data if it is the next expected packet in sequence,
    /// or None if we are waiting for an earlier packet.
    pub fn receive(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < MULTIPATH_HEADER_SIZE {
            return None; // Drop invalid
        }

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&payload[0..8]);
        let seq = u64::from_be_bytes(seq_bytes);

        // --- F5: DoS Defense (Bound the Reassembly Buffer) ---
        if seq < self.next_expected_seq {
            return None; // Drop replayed or too-old packets
        }

        const MAX_SEQ_GAP: u64 = 100_000;
        if seq - self.next_expected_seq > MAX_SEQ_GAP {
            return None; // Drop aggressively out-of-bound sequences
        }

        const MAX_BUFFERED_ENTRIES: usize = 10_000;
        if self.buffer.len() >= MAX_BUFFERED_ENTRIES && !self.buffer.contains_key(&seq) {
            return None; // Drop new packets if the buffer is full
        }

        let data = payload[8..].to_vec();

        if seq == self.next_expected_seq {
            self.next_expected_seq += 1;
            Some(data)
        } else if seq > self.next_expected_seq {
            self.buffer.insert(seq, data);
            None
        } else {
            // Duplicate or deeply delayed packet. We can just drop it.
            None
        }
    }

    /// Checks if there are buffered packets that can now be yielded.
    pub fn pop_next_buffered(&mut self) -> Option<Vec<u8>> {
        if let Some(data) = self.buffer.remove(&self.next_expected_seq) {
            self.next_expected_seq += 1;
            Some(data)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_slice_and_reassemble() {
        let mut slicer = MultiPathSlicer::new();
        let mut reassembler = MultiPathReassembler::new();

        let mut out1 = [0u8; 100];
        let len1 = slicer.slice(b"hello", &mut out1);

        let mut out2 = [0u8; 100];
        let len2 = slicer.slice(b"world", &mut out2);

        let mut out3 = [0u8; 100];
        let len3 = slicer.slice(b"multipath", &mut out3);

        // Receive out of order: 1, 3, 2
        assert_eq!(reassembler.receive(&out1[..len1]).unwrap(), b"hello");

        assert_eq!(reassembler.receive(&out3[..len3]), None); // Buffered
        assert_eq!(reassembler.pop_next_buffered(), None);

        assert_eq!(reassembler.receive(&out2[..len2]).unwrap(), b"world"); // Completes gap
        assert_eq!(reassembler.pop_next_buffered().unwrap(), b"multipath"); // Unlocks buffered
        assert_eq!(reassembler.pop_next_buffered(), None);
    }
}
