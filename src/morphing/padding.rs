//! MTU packet padding and length normalization.

pub struct PacketPadder {
    block_size: usize,
}

impl PacketPadder {
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size: if block_size == 0 { 512 } else { block_size },
        }
    }

    /// Pads data up to the nearest multiple of `block_size` using deterministic length-prefixed framing.
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        let original_len = data.len();
        // Overhead: 4 bytes for original length prefix
        let total_needed = original_len + 4;
        let padding_needed = (self.block_size - (total_needed % self.block_size)) % self.block_size;
        let final_len = total_needed + padding_needed;

        let mut out = Vec::with_capacity(final_len);
        out.extend_from_slice(&(original_len as u32).to_be_bytes());
        out.extend_from_slice(data);
        out.resize(final_len, 0x00);
        out
    }

    /// Strips padding from a padded buffer, returning the original slice.
    pub fn unpad<'a>(&self, padded: &'a [u8]) -> Result<&'a [u8], &'static str> {
        if padded.len() < 4 {
            return Err("Buffer too short for length prefix");
        }
        let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
        if padded.len() < 4 + len {
            return Err("Corrupted padding frame: payload truncated");
        }
        Ok(&padded[4..4 + len])
    }
}
