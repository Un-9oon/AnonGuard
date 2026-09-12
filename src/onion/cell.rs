//! Fixed-size 1024-byte OnionCell protocol with HMAC-SHA256 Authenticated MAC.

use std::convert::TryInto;

pub const ONION_CELL_SIZE: usize = 1024;
pub const HEADER_SIZE: usize = 25;
pub const PAYLOAD_SIZE: usize = ONION_CELL_SIZE - HEADER_SIZE; // 999 bytes

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

/// A constant-size 1024-byte cell with a 16-byte Poly1305 MAC tag preventing bit-flipping/tagging.
#[derive(Clone)]
pub struct OnionCell {
    pub circuit_id: u32,
    pub command: CellCommand,
    pub stream_id: u16,
    pub length: u16,
    pub mac: [u8; 16],
    pub payload: [u8; PAYLOAD_SIZE],
}

impl OnionCell {
    pub fn new(
        circuit_id: u32,
        command: CellCommand,
        stream_id: u16,
        data: &[u8],
        mac_key: &[u8; 32],
    ) -> Result<Self, String> {
        if data.len() > PAYLOAD_SIZE {
            return Err(format!(
                "Payload length {} exceeds maximum cell payload size {}",
                data.len(),
                PAYLOAD_SIZE
            ));
        }

        let mut payload = [0u8; PAYLOAD_SIZE];
        let len = data.len();
        payload[..len].copy_from_slice(data);

        let mac = Self::calculate_mac(
            mac_key,
            circuit_id,
            command as u8,
            stream_id,
            len as u16,
            &payload[..len],
        );

        Ok(Self {
            circuit_id,
            command,
            stream_id,
            length: len as u16,
            mac,
            payload,
        })
    }

    pub fn calculate_mac(
        mac_key: &[u8; 32],
        circuit_id: u32,
        command: u8,
        stream_id: u16,
        len: u16,
        data: &[u8],
    ) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(mac_key)
            .expect("HMAC supports 32-byte keys");
        mac.update(&circuit_id.to_be_bytes());
        mac.update(&[command]);
        mac.update(&stream_id.to_be_bytes());
        mac.update(&len.to_be_bytes());
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag[..16]);
        out
    }

    pub fn is_mac_valid(&self, mac_key: &[u8; 32]) -> bool {
        let len = self.length as usize;
        if len > PAYLOAD_SIZE {
            return false;
        }
        let expected = Self::calculate_mac(
            mac_key,
            self.circuit_id,
            self.command as u8,
            self.stream_id,
            self.length,
            &self.payload[..len],
        );
        // Constant-time tag comparison
        subtle::ConstantTimeEq::ct_eq(&self.mac[..], &expected[..]).into()
    }

    pub fn serialize(&self) -> [u8; ONION_CELL_SIZE] {
        let mut buf = [0u8; ONION_CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4] = self.command as u8;
        buf[5..7].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[7..9].copy_from_slice(&self.length.to_be_bytes());
        buf[9..25].copy_from_slice(&self.mac);
        buf[25..ONION_CELL_SIZE].copy_from_slice(&self.payload);
        buf
    }

    pub fn parse(buf: &[u8; ONION_CELL_SIZE]) -> Result<Self, String> {
        let circuit_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let command = CellCommand::from_u8(buf[4])
            .ok_or_else(|| format!("Unknown cell command: {}", buf[4]))?;
        let stream_id = u16::from_be_bytes(buf[5..7].try_into().unwrap());
        let length = u16::from_be_bytes(buf[7..9].try_into().unwrap());
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&buf[9..25]);
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[25..ONION_CELL_SIZE]);

        Ok(Self {
            circuit_id,
            command,
            stream_id,
            length,
            mac,
            payload,
        })
    }
}
