//! Layered Onion Circuit Routing, Multi-hop Key Agreement, and HMAC-SHA256 Authenticated Peeling.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};

/// Per-hop cryptographic session state containing forward and backward ciphers plus HMAC-SHA256 MAC key.
pub struct HopCryptState {
    pub forward_cipher: ChaCha20,
    pub backward_cipher: ChaCha20,
    pub mac_key: [u8; 32],
}

impl HopCryptState {
    pub fn new(forward_key: &[u8; 32], backward_key: &[u8; 32], mac_key: &[u8; 32]) -> Self {
        let nonce = [0u8; 12];
        let forward_cipher = ChaCha20::new(forward_key.into(), &nonce.into());
        let backward_cipher = ChaCha20::new(backward_key.into(), &nonce.into());

        Self {
            forward_cipher,
            backward_cipher,
            mac_key: *mac_key,
        }
    }

    /// Encrypts/decrypts in-place for forward stream traffic.
    pub fn encrypt_forward(&mut self, data: &mut [u8]) {
        self.forward_cipher.apply_keystream(data);
    }

    /// Encrypts/decrypts in-place for backward (return) stream traffic.
    pub fn encrypt_backward(&mut self, data: &mut [u8]) {
        self.backward_cipher.apply_keystream(data);
    }
}

/// Key derivation function turning an X25519 shared secret into forward, backward, and MAC keys.
pub fn derive_hop_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut hasher_f = Sha256::new();
    hasher_f.update(shared_secret);
    hasher_f.update(b"AnonGuard-Forward-Key-v2");
    let f_hash = hasher_f.finalize();

    let mut hasher_b = Sha256::new();
    hasher_b.update(shared_secret);
    hasher_b.update(b"AnonGuard-Backward-Key-v2");
    let b_hash = hasher_b.finalize();

    let mut hasher_m = Sha256::new();
    hasher_m.update(shared_secret);
    hasher_m.update(b"AnonGuard-HMAC-SHA256-Key-v3");
    let m_hash = hasher_m.finalize();

    let mut forward_key = [0u8; 32];
    let mut backward_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    forward_key.copy_from_slice(&f_hash);
    backward_key.copy_from_slice(&b_hash);
    mac_key.copy_from_slice(&m_hash);

    (forward_key, backward_key, mac_key)
}

/// Represents a client-side 3-hop onion circuit (Guard -> Middle -> Exit).
pub struct OnionCircuit {
    pub circuit_id: u32,
    hops: Vec<HopCryptState>,
}

impl OnionCircuit {
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            hops: Vec::new(),
        }
    }

    /// Adds a negotiated hop state to the circuit.
    pub fn add_hop(&mut self, forward_key: [u8; 32], backward_key: [u8; 32], mac_key: [u8; 32]) {
        self.hops
            .push(HopCryptState::new(&forward_key, &backward_key, &mac_key));
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn get_hop_mac_key(&self, index: usize) -> Option<[u8; 32]> {
        self.hops.get(index).map(|h| h.mac_key)
    }

    /// Forward Onion Encryption:
    /// Wraps a cell from innermost layer (Exit) to outermost layer (Guard).
    pub fn wrap_forward(&mut self, cell: &OnionCell) -> [u8; ONION_CELL_SIZE] {
        let mut raw = cell.serialize();

        // Encrypt in reverse order: Exit first, then Middle, then Guard
        for hop in self.hops.iter_mut().rev() {
            hop.encrypt_forward(&mut raw[4..]);
        }

        raw
    }

    /// Backward Onion Decryption (Client receives return traffic):
    /// Removes Guard layer (Hop 0), then Middle (Hop 1), then Exit (Hop 2).
    pub fn unwrap_backward(
        &mut self,
        raw: &mut [u8; ONION_CELL_SIZE],
    ) -> Result<OnionCell, String> {
        for hop in self.hops.iter_mut() {
            hop.encrypt_backward(&mut raw[4..]);
        }
        OnionCell::parse(raw)
    }
}

/// Represents the relay's view of an onion circuit with anti-replay state.
pub struct RelayCircuitHop {
    pub circuit_id: u32,
    pub crypt: HopCryptState,
    pub expected_recv_seq: u32,
    pub next_send_seq: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeelResult {
    /// This cell is addressed directly to this relay with verified HMAC-SHA256 MAC.
    AddressedToThisRelay(CellCommand, Vec<u8>),
    /// This cell belongs to downstream hops; forward the peeled raw buffer.
    ForwardDownstream(Box<[u8; ONION_CELL_SIZE]>),
}

impl RelayCircuitHop {
    pub fn new(
        circuit_id: u32,
        forward_key: [u8; 32],
        backward_key: [u8; 32],
        mac_key: [u8; 32],
    ) -> Self {
        Self {
            circuit_id,
            crypt: HopCryptState::new(&forward_key, &backward_key, &mac_key),
            expected_recv_seq: 1, // Handshake cells use sequence 0
            next_send_seq: 1,
        }
    }

    /// Peels one layer of forward onion encryption, verifies the HMAC-SHA256 MAC,
    /// and enforces anti-replay sequence number progression.
    pub fn peel_forward(&mut self, raw: &mut [u8; ONION_CELL_SIZE]) -> Result<PeelResult, String> {
        self.crypt.encrypt_forward(&mut raw[4..]);

        if let Ok(cell) = OnionCell::parse(raw) {
            // Cryptographic HMAC-SHA256 MAC verification
            if cell.is_mac_valid(&self.crypt.mac_key) {
                // Anti-replay check: prevent replay, duplication, or reordering of cells
                if cell.sequence_no < self.expected_recv_seq {
                    return Err(format!(
                        "Anti-replay rejection on circuit {}: received stale sequence {} (expected >= {})",
                        self.circuit_id, cell.sequence_no, self.expected_recv_seq
                    ));
                }
                self.expected_recv_seq = cell.sequence_no + 1;

                let len = (cell.length as usize).min(cell.payload.len());
                return Ok(PeelResult::AddressedToThisRelay(
                    cell.command,
                    cell.payload[..len].to_vec(),
                ));
            }
        }

        Ok(PeelResult::ForwardDownstream(Box::new(*raw)))
    }

    /// Wraps return payload in backward encryption before passing upstream towards client.
    pub fn wrap_backward(&mut self, raw: &mut [u8; ONION_CELL_SIZE]) {
        self.crypt.encrypt_backward(&mut raw[4..]);
    }
}

/// Builds a CREATE cell carrying the client's ephemeral X25519 public key.
pub fn build_create_cell(
    circuit_id: u32,
    client_pub: &X25519PublicKey,
) -> Result<OnionCell, String> {
    let initial_mac_key = [0u8; 32];
    OnionCell::new(
        circuit_id,
        0,
        CellCommand::Create,
        0,
        client_pub.as_bytes(),
        &initial_mac_key,
    )
}

/// Relay processes a CREATE cell, performs X25519 Diffie-Hellman, and returns the established hop state and CREATED cell.
pub fn handle_create_cell(create_cell: &OnionCell) -> Result<(RelayCircuitHop, OnionCell), String> {
    if create_cell.command != CellCommand::Create {
        return Err(format!(
            "Expected CREATE cell, got {:?}",
            create_cell.command
        ));
    }
    if create_cell.length < 32 {
        return Err("CREATE cell payload too short for X25519 public key".to_string());
    }

    let client_pub_bytes: [u8; 32] = create_cell.payload[..32]
        .try_into()
        .map_err(|_| "Failed to extract client public key".to_string())?;
    let client_pub = X25519PublicKey::from(client_pub_bytes);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_pub = X25519PublicKey::from(&relay_secret);

    let shared = relay_secret.diffie_hellman(&client_pub);
    let (forward_key, backward_key, mac_key) = derive_hop_keys(shared.as_bytes());

    let created_cell = OnionCell::new(
        create_cell.circuit_id,
        0,
        CellCommand::Created,
        0,
        relay_pub.as_bytes(),
        &mac_key,
    )?;

    let relay_hop =
        RelayCircuitHop::new(create_cell.circuit_id, forward_key, backward_key, mac_key);
    Ok((relay_hop, created_cell))
}

/// Client processes a CREATED or EXTENDED cell from a relay, deriving the hop keys and confirming HMAC-SHA256 authentication.
pub fn process_created_cell(
    created_cell: &OnionCell,
    client_secret: EphemeralSecret,
) -> Result<HandshakeKeys, String> {
    if created_cell.command != CellCommand::Created && created_cell.command != CellCommand::Extended
    {
        return Err(format!(
            "Expected CREATED or EXTENDED cell, got {:?}",
            created_cell.command
        ));
    }
    if created_cell.length < 32 {
        return Err("CREATED/EXTENDED cell payload too short for X25519 public key".to_string());
    }

    let relay_pub_bytes: [u8; 32] = created_cell.payload[..32]
        .try_into()
        .map_err(|_| "Failed to extract relay public key".to_string())?;
    let relay_pub = X25519PublicKey::from(relay_pub_bytes);

    let shared = client_secret.diffie_hellman(&relay_pub);
    let (forward_key, backward_key, mac_key) = derive_hop_keys(shared.as_bytes());

    if !created_cell.is_mac_valid(&mac_key) {
        return Err("Cell HMAC-SHA256 authentication verification failed".to_string());
    }

    Ok((forward_key, backward_key, mac_key))
}

/// Encodes an EXTEND payload containing the next hop address and the client's ephemeral public key for that hop.
pub fn encode_extend_payload(
    next_host: &str,
    next_port: u16,
    client_pub: &X25519PublicKey,
) -> Result<Vec<u8>, String> {
    let host_bytes = next_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("Host string exceeds 255 bytes limit".to_string());
    }

    let mut payload = Vec::with_capacity(1 + host_bytes.len() + 2 + 32);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&next_port.to_be_bytes());
    payload.extend_from_slice(client_pub.as_bytes());
    Ok(payload)
}

/// Decodes an EXTEND payload received by an intermediate relay.
pub fn decode_extend_payload(payload: &[u8]) -> Result<(String, u16, X25519PublicKey), String> {
    if payload.len() < 1 + 2 + 32 {
        return Err("EXTEND payload too short".to_string());
    }
    let host_len = payload[0] as usize;
    if payload.len() < 1 + host_len + 2 + 32 {
        return Err("EXTEND payload truncated".to_string());
    }

    let host = String::from_utf8(payload[1..1 + host_len].to_vec())
        .map_err(|_| "Invalid UTF-8 in EXTEND host".to_string())?;
    let port_bytes: [u8; 2] = payload[1 + host_len..1 + host_len + 2]
        .try_into()
        .map_err(|_| "Failed to read port".to_string())?;
    let port = u16::from_be_bytes(port_bytes);

    let pub_bytes: [u8; 32] = payload[1 + host_len + 2..1 + host_len + 2 + 32]
        .try_into()
        .map_err(|_| "Failed to read public key".to_string())?;
    let client_pub = X25519PublicKey::from(pub_bytes);

    Ok((host, port, client_pub))
}

/// Encodes a RELAY payload instructing the exit relay to connect to target_host:target_port.
pub fn encode_relay_target(target_host: &str, target_port: u16) -> Result<Vec<u8>, String> {
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("Target host string exceeds 255 bytes limit".to_string());
    }
    let mut payload = Vec::with_capacity(1 + host_bytes.len() + 2);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&target_port.to_be_bytes());
    Ok(payload)
}

/// Decodes a RELAY payload received by an exit relay.
pub fn decode_relay_target(payload: &[u8]) -> Result<(String, u16), String> {
    if payload.len() < 1 + 2 {
        return Err("RELAY target payload too short".to_string());
    }
    let host_len = payload[0] as usize;
    if payload.len() < 1 + host_len + 2 {
        return Err("RELAY target payload truncated".to_string());
    }
    let host = String::from_utf8(payload[1..1 + host_len].to_vec())
        .map_err(|_| "Invalid UTF-8 in RELAY target host".to_string())?;
    let port_bytes: [u8; 2] = payload[1 + host_len..1 + host_len + 2]
        .try_into()
        .map_err(|_| "Failed to read port".to_string())?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((host, port))
}

pub type HandshakeKeys = ([u8; 32], [u8; 32], [u8; 32]);

/// Simulates an X25519 key exchange between client and a relay.
pub fn perform_client_relay_handshake() -> (HandshakeKeys, HandshakeKeys) {
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = X25519PublicKey::from(&client_secret);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_public = X25519PublicKey::from(&relay_secret);

    let client_shared = client_secret.diffie_hellman(&relay_public);
    let relay_shared = relay_secret.diffie_hellman(&client_public);

    let client_keys = derive_hop_keys(client_shared.as_bytes());
    let relay_keys = derive_hop_keys(relay_shared.as_bytes());

    (client_keys, relay_keys)
}
