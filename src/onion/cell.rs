//! Fixed-size 1024-byte OnionCell protocol for layered encryption.

use std::convert::TryInto;

pub const ONION_CELL_SIZE: usize = 1024;
pub const HEADER_SIZE: usize = 13;
pub const PAYLOAD_SIZE: usize = ONION_CELL_SIZE - HEADER_SIZE; // 1011 bytes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    Extend = 5,
    Extended = 6,
    Data = 7,
    DataAck = 8,
}

impl CellCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Create),
            2 => Some(Self::Created),
            3 => Some(Self::Relay),
            4 => Some(Self::Destroy),
            5 => Some(Self::Extend),
            6 => Some(Self::Extended),
            7 => Some(Self::Data),
            8 => Some(Self::DataAck),
            _ => None,
        }
    }
}

/// A constant-size 1024-byte cell preventing packet-length side channels.
#[derive(Clone)]
pub struct OnionCell {
    pub circuit_id: u32,
    pub command: CellCommand,
    pub stream_id: u16,
    pub length: u16,
    pub digest: [u8; 4],
    pub payload: [u8; PAYLOAD_SIZE],
}

impl OnionCell {
    pub fn new(circuit_id: u32, command: CellCommand, stream_id: u16, data: &[u8]) -> Self {
        let mut payload = [0u8; PAYLOAD_SIZE];
        let len = data.len().min(PAYLOAD_SIZE);
        payload[..len].copy_from_slice(&data[..len]);

        let digest = Self::calculate_digest(circuit_id, command as u8, stream_id, len as u16, &payload[..len]);

        Self {
            circuit_id,
            command,
            stream_id,
            length: len as u16,
            digest,
            payload,
        }
    }

    pub fn calculate_digest(circuit_id: u32, command: u8, stream_id: u16, len: u16, data: &[u8]) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(circuit_id.to_be_bytes());
        hasher.update([command]);
        hasher.update(stream_id.to_be_bytes());
        hasher.update(len.to_be_bytes());
        hasher.update(data);
        let result = hasher.finalize();
        let mut d = [0u8; 4];
        d.copy_from_slice(&result[..4]);
        d
    }

    pub fn is_digest_valid(&self) -> bool {
        let len = self.length as usize;
        if len > PAYLOAD_SIZE {
            return false;
        }
        let expected = Self::calculate_digest(
            self.circuit_id,
            self.command as u8,
            self.stream_id,
            self.length,
            &self.payload[..len],
        );
        self.digest == expected
    }

    pub fn serialize(&self) -> [u8; ONION_CELL_SIZE] {
        let mut buf = [0u8; ONION_CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4] = self.command as u8;
        buf[5..7].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[7..9].copy_from_slice(&self.length.to_be_bytes());
        buf[9..13].copy_from_slice(&self.digest);
        buf[13..ONION_CELL_SIZE].copy_from_slice(&self.payload);
        buf
    }

    pub fn parse(buf: &[u8; ONION_CELL_SIZE]) -> Result<Self, String> {
        let circuit_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let command = CellCommand::from_u8(buf[4])
            .ok_or_else(|| format!("Unknown cell command: {}", buf[4]))?;
        let stream_id = u16::from_be_bytes(buf[5..7].try_into().unwrap());
        let length = u16::from_be_bytes(buf[7..9].try_into().unwrap());
        let mut digest = [0u8; 4];
        digest.copy_from_slice(&buf[9..13]);
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[13..ONION_CELL_SIZE]);

        Ok(Self {
            circuit_id,
            command,
            stream_id,
            length,
            digest,
            payload,
        })
    }
}
