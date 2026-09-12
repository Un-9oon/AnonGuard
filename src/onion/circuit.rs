//! Layered Onion Circuit Routing, Multi-hop Key Agreement, and Poly1305 Authenticated Peeling.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};

/// Per-hop cryptographic session state containing forward and backward ciphers plus Poly1305 MAC key.
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
pub fn derive_hop_keys(shared_secret: &[u8; 32], hop_index: u8) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut hasher_f = Sha256::new();
    hasher_f.update(shared_secret);
    hasher_f.update(b"AnonGuard-Forward-Key-v2");
    hasher_f.update([hop_index]);
    let f_hash = hasher_f.finalize();

    let mut hasher_b = Sha256::new();
    hasher_b.update(shared_secret);
    hasher_b.update(b"AnonGuard-Backward-Key-v2");
    hasher_b.update([hop_index]);
    let b_hash = hasher_b.finalize();

    let mut hasher_m = Sha256::new();
    hasher_m.update(shared_secret);
    hasher_m.update(b"AnonGuard-Poly1305-MAC-Key-v2");
    hasher_m.update([hop_index]);
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
    pub fn unwrap_backward(&mut self, raw: &mut [u8; ONION_CELL_SIZE]) -> Result<OnionCell, String> {
        for hop in self.hops.iter_mut() {
            hop.encrypt_backward(&mut raw[4..]);
        }
        OnionCell::parse(raw)
    }
}

/// Represents the relay's view of an onion circuit.
pub struct RelayCircuitHop {
    pub circuit_id: u32,
    pub crypt: HopCryptState,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeelResult {
    /// This cell is addressed directly to this relay with verified Poly1305 MAC.
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
        }
    }

    /// Peels one layer of forward onion encryption and verifies the Poly1305 MAC.
    pub fn peel_forward(&mut self, raw: &mut [u8; ONION_CELL_SIZE]) -> Result<PeelResult, String> {
        self.crypt.encrypt_forward(&mut raw[4..]);

        if let Ok(cell) = OnionCell::parse(raw) {
            // Cryptographic Poly1305 MAC verification
            if cell.is_mac_valid(&self.crypt.mac_key) {
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

pub type HandshakeKeys = ([u8; 32], [u8; 32], [u8; 32]);

/// Simulates an X25519 key exchange between client and a relay.
pub fn perform_client_relay_handshake(hop_index: u8) -> (HandshakeKeys, HandshakeKeys) {
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = X25519PublicKey::from(&client_secret);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_public = X25519PublicKey::from(&relay_secret);

    let client_shared = client_secret.diffie_hellman(&relay_public);
    let relay_shared = relay_secret.diffie_hellman(&client_public);

    let client_keys = derive_hop_keys(client_shared.as_bytes(), hop_index);
    let relay_keys = derive_hop_keys(relay_shared.as_bytes(), hop_index);

    (client_keys, relay_keys)
}
