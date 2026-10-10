//! Version 6 fixed-size 8192-byte protocol cells carried inside authenticated TLS links.

use rand::Rng;

pub const ONION_CELL_SIZE: usize = 8192;
pub const HEADER_SIZE: usize = 61; // Includes 32 random padding bytes; not a Sphinx header.
pub const PAYLOAD_SIZE: usize = ONION_CELL_SIZE - HEADER_SIZE; // 8131 bytes

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
    /// End the upload direction while preserving downstream responses.
    End = 10,
    Session = 11,
    SessionAccepted = 12,
    SessionOpen = 13,
    SessionOpened = 14,
    SessionRefused = 15,
    SessionFinish = 16,
    SessionFinished = 17,
    SessionReset = 18,
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
            10 => Some(Self::End),
            11 => Some(Self::Session),
            12 => Some(Self::SessionAccepted),
            13 => Some(Self::SessionOpen),
            14 => Some(Self::SessionOpened),
            15 => Some(Self::SessionRefused),
            16 => Some(Self::SessionFinish),
            17 => Some(Self::SessionFinished),
            18 => Some(Self::SessionReset),
            _ => None,
        }
    }
}

/// A fixed-size cell with a 16-byte AEAD tag and a sequence number.
#[derive(Clone)]
pub struct OnionCell {
    pub circuit_id: u32,
    pub sequence_no: u32,
    pub command: CellCommand,
    pub stream_id: u16,
    pub length: u16,
    pub ephemeral_key: [u8; 32], // Random padding, not an X25519 public key.
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

        // Randomize padding at creation; this does not establish unlinkability.
        let mut rng = rand::thread_rng();
        let mut ephemeral_key = [0u8; 32];
        rng.fill(&mut ephemeral_key);

        Ok(Self {
            circuit_id,
            sequence_no,
            command,
            stream_id,
            length: len as u16,
            ephemeral_key,
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
        buf[13..45].copy_from_slice(&self.ephemeral_key);
        buf[45..45 + PAYLOAD_SIZE].copy_from_slice(&self.payload);
        buf[ONION_CELL_SIZE - 16..ONION_CELL_SIZE].copy_from_slice(&self.mac);
        buf
    }

    pub fn parse(buf: &[u8; ONION_CELL_SIZE]) -> Result<Self, String> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let sequence_no = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let command = CellCommand::from_u8(buf[8])
            .ok_or_else(|| format!("Unknown cell command: {}", buf[8]))?;
        let stream_id = u16::from_be_bytes([buf[9], buf[10]]);
        let length = u16::from_be_bytes([buf[11], buf[12]]);
        if length as usize > PAYLOAD_SIZE {
            return Err(format!(
                "Parsed cell length {} exceeds maximum {}",
                length, PAYLOAD_SIZE
            ));
        }

        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&buf[13..45]);

        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[45..45 + PAYLOAD_SIZE]);

        let mut mac = [0u8; 16];
        mac.copy_from_slice(&buf[ONION_CELL_SIZE - 16..ONION_CELL_SIZE]);

        Ok(Self {
            circuit_id,
            sequence_no,
            command,
            stream_id,
            length,
            ephemeral_key,
            mac,
            payload,
        })
    }
}
