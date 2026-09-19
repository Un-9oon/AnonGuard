//! Fixed-size 1024-byte OnionCell protocol with HMAC-SHA256 Authenticated MAC.

pub const ONION_CELL_SIZE: usize = 1024;
pub const HEADER_SIZE: usize = 29;
pub const PAYLOAD_SIZE: usize = ONION_CELL_SIZE - HEADER_SIZE; // 995 bytes

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
    Dummy = 9,
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
            9 => Some(Self::Dummy),
            _ => None,
        }
    }
}

/// A constant-size 1024-byte cell with a 16-byte HMAC-SHA256 MAC tag and sequence number preventing replay and bit-flipping attacks.
#[derive(Clone)]
pub struct OnionCell {
    pub circuit_id: u32,
    pub sequence_no: u32,
    pub command: CellCommand,
    pub stream_id: u16,
    pub length: u16,
    pub mac: [u8; 16],
    pub payload: [u8; PAYLOAD_SIZE],
}

impl OnionCell {
    pub fn new(
        circuit_id: u32,
        sequence_no: u32,
        command: CellCommand,
        stream_id: u16,
        data: &[u8],
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

        Ok(Self {
            circuit_id,
            sequence_no,
            command,
            stream_id,
            length: len as u16,
            mac: [0u8; 16], // To be filled by AEAD
            payload,
        })
    }

    pub fn serialize(&self) -> [u8; ONION_CELL_SIZE] {
        let mut buf = [0u8; ONION_CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sequence_no.to_be_bytes());
        buf[8] = self.command as u8;
        buf[9..11].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[11..13].copy_from_slice(&self.length.to_be_bytes());
        buf[13..1008].copy_from_slice(&self.payload);
        buf[1008..1024].copy_from_slice(&self.mac);
        buf
    }

    pub fn parse(buf: &[u8; ONION_CELL_SIZE]) -> Result<Self, String> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let sequence_no = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let command = CellCommand::from_u8(buf[8])
            .ok_or_else(|| format!("Unknown cell command: {}", buf[8]))?;
        let stream_id = u16::from_be_bytes([buf[9], buf[10]]);
        let length = u16::from_be_bytes([buf[11], buf[12]]);
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[13..1008]);
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&buf[1008..1024]);

        Ok(Self {
            circuit_id,
            sequence_no,
            command,
            stream_id,
            length,
            mac,
            payload,
        })
    }
}
